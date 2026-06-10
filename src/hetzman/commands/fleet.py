"""Fleet health: per-node heartbeat reports and the fleet-status view.

``health-report`` runs local checks and writes a heartbeat to
``/hetzman/health/{node}`` under a 300s lease — if a node stops reporting,
the key expires and its absence IS the down-signal. ``fleet-status`` renders
all heartbeats; with no alerting infra (by choice), this plus the MOTD
snippet is how degradation surfaces.
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
from typing import Dict, Optional

import typer

from ..apps import app
from ..config import get_etcd_client, get_settings
from ..console import console
from ..etcd_kv import get_all_with_prefix, get_key, put_with_lease
from ..logging import log_message
from ..registry import load_registry
from ..render import DOMAIN
from .system import compute_audit

HEALTH_PREFIX = "/hetzman/health/"
HEALTH_TTL_SECONDS = 300
STATE_DIR = "/var/lib/hetzman"
SUMMARY_FILE = f"{STATE_DIR}/last-health-summary.txt"
LAST_SYNC_FILE = f"{STATE_DIR}/last-node-sync.json"
INCUS_POOL_MOUNT = "/var/lib/incus/storage-pools/default"


def _run(cmd, timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _is_active(unit: str) -> bool:
    return _run(["systemctl", "is-active", unit]).stdout.strip() == "active"


def _pct(path: str) -> Optional[int]:
    try:
        usage = shutil.disk_usage(path)
        return round(usage.used / usage.total * 100)
    except OSError:
        return None


def _versions() -> Dict[str, str]:
    try:
        from importlib.metadata import version

        hetzman_version = version("hetzman")
    except Exception:
        hetzman_version = "unknown"
    incus = _run(["incus", "--version"])
    return {
        "hetzman_version": hetzman_version,
        "incus_version": incus.stdout.strip() or "unknown",
    }


@app.command(name="health-report")
def health_report():
    """Run local health checks and heartbeat them into etcd"""
    settings = get_settings()
    nodes = load_registry()
    checks: Dict[str, object] = {}

    checks["etcd"] = "ok" if get_key("/hetzman/version") else "fail"
    checks["dnsmasq"] = "ok" if _is_active("dnsmasq") else "fail"
    checks["incus"] = "ok" if _is_active("incus") else "fail"
    checks["watcher"] = "ok" if _is_active("hetzman-instance-watcher") else "fail"

    dig = _run(["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1",
                f"{settings.current_server}.{DOMAIN}"])
    checks["dns_resolve"] = "ok" if dig.returncode == 0 and dig.stdout.strip() else "fail"

    try:
        missing, orphaned, _correct = compute_audit()
        checks["audit"] = "drift" if (missing or orphaned) else "ok"
    except Exception:
        checks["audit"] = "error"

    peers: Dict[str, str] = {}
    for name, node in sorted(nodes.items()):
        if name == settings.current_server:
            continue
        alive = _run(["ping", "-c1", "-W2", node["vswitch_ip"]]).returncode == 0
        peers[name] = "ok" if alive else "fail"
    checks["peers"] = peers

    checks["disk_root_pct"] = _pct("/")
    checks["btrfs_pool_pct"] = _pct(INCUS_POOL_MOUNT)

    node_sync_state = None
    try:
        with open(LAST_SYNC_FILE) as f:
            node_sync_state = json.load(f)
    except (OSError, json.JSONDecodeError):
        pass

    payload = {
        "node": settings.current_server,
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        **_versions(),
        "checks": checks,
        "endpoints_configured": len(settings.etcd_endpoints),
        "node_sync": node_sync_state,
    }

    wrote = put_with_lease(
        HEALTH_PREFIX + settings.current_server, json.dumps(payload), HEALTH_TTL_SECONDS
    )

    flat = {k: v for k, v in checks.items() if not isinstance(v, dict)}
    failed = [k for k, v in flat.items() if v == "fail" or v == "error"]
    failed += [f"peer:{k}" for k, v in peers.items() if v != "ok"]

    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(SUMMARY_FILE, "w") as f:
            f.write(
                f"  {settings.current_server}: "
                + ("ALL OK" if not failed else f"FAILING: {', '.join(failed)}")
                + f" | disk {checks['disk_root_pct']}% pool {checks['btrfs_pool_pct']}%"
                + f" | heartbeat {'written' if wrote else 'WRITE FAILED'}\n"
            )
    except OSError:
        pass

    if failed or not wrote:
        console.print(f"[red]health: FAILING {failed} (heartbeat written: {wrote})[/red]")
        log_message(f"health-report failing: {failed} wrote={wrote}", "WARNING")
        raise typer.Exit(code=1)
    console.print("[green]health: all checks ok[/green]")


@app.command(name="fleet-status")
def fleet_status():
    """Show health of every node in the fleet (from etcd heartbeats)"""
    from rich.table import Table

    nodes = load_registry()
    health = {
        key[len(HEALTH_PREFIX):]: value
        for key, value in get_all_with_prefix(HEALTH_PREFIX).items()
        if isinstance(value, dict)
    }

    try:
        members = {m.name for m in get_etcd_client().members}
    except Exception:
        members = set()

    now = datetime.datetime.now()
    degraded = False
    table = Table(title=f"Fleet status ({len(nodes)} registered nodes)")
    for column in ("Node", "Heartbeat", "Checks", "Peers", "Versions", "Sync", "Disk/Pool"):
        table.add_column(column)

    for name in sorted(set(nodes) | set(health)):
        beat = health.get(name)
        if not beat:
            table.add_row(name, "[red]DOWN (no heartbeat)[/red]", "-", "-", "-", "-", "-")
            degraded = True
            continue

        age = "?"
        try:
            delta = now - datetime.datetime.fromisoformat(beat["ts"])
            age = f"{int(delta.total_seconds())}s ago"
        except (KeyError, ValueError):
            pass

        checks = beat.get("checks", {})
        flat = {k: v for k, v in checks.items() if isinstance(v, str)}
        bad = [k for k, v in flat.items() if v not in ("ok",)]
        peers = checks.get("peers", {})
        bad_peers = [k for k, v in peers.items() if v != "ok"]
        if bad or bad_peers:
            degraded = True

        version = beat.get("hetzman_version", "?")
        incus = beat.get("incus_version", "?")
        endpoints = beat.get("endpoints_configured")
        if nodes and endpoints != len(nodes):
            degraded = True
            version += f" [red](endpoints={endpoints}!={len(nodes)})[/red]"

        sync = (beat.get("node_sync") or {}).get("result", "-")
        table.add_row(
            name,
            f"[green]{age}[/green]",
            "[green]ok[/green]" if not bad else f"[red]{','.join(bad)}[/red]",
            "[green]ok[/green]" if not bad_peers else f"[red]{','.join(bad_peers)}[/red]",
            f"{version} / incus {incus}",
            sync if sync != "error" else "[red]error[/red]",
            f"{checks.get('disk_root_pct', '?')}% / {checks.get('btrfs_pool_pct', '?')}%",
        )
        if name in nodes and nodes[name].get("etcd_name") not in members and members:
            degraded = True

    console.print(table)
    if degraded:
        console.print("[red]Fleet DEGRADED[/red]")
        raise typer.Exit(code=1)
    console.print("[green]Fleet healthy[/green]")
