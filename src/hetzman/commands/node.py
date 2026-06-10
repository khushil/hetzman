"""Node registry commands and the node-sync engine.

``node register/list/show/remove`` manage /hetzman/nodes/ entries (always
through validation — never write the registry with raw etcdctl).

``node-sync`` renders this node's config from the registry and either
reports drift (``--check``) or converges it (``--apply``). Every apply step
is individually guarded and the whole run is fail-closed: any registry
validation/guard failure means nothing is touched.
"""
from __future__ import annotations

import configparser
import datetime
import importlib.resources
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Tuple

import typer
import yaml

from ..apps import app, node_app
from ..config import CONFIG_FILE, get_settings, write_config
from ..console import console
from ..etcd_kv import delete_key, get_all_with_prefix, put_key
from ..locking import sync_lock
from ..logging import log_message
from ..registry import (
    NODES_PREFIX,
    SCHEMA_VERSION,
    load_registry,
    registry_guard,
    validate_registry,
)
from ..render import (
    RenderError,
    base_ensure_rules,
    base_policies,
    dnsmasq_conf_lines_to_remove,
    iptables_cleanup_plan,
    netplan_semantically_equal,
    render_dnsmasq_include,
    render_iptables_base,
    render_iptables_base_v6,
    render_netplan_vswitch,
    DOMAIN,
)
from .system import do_sync_apply

DNSMASQ_CONF = "/etc/dnsmasq.conf"
DNSMASQ_INCLUDE = "/etc/dnsmasq.d/hetzman-nodes.conf"
NETPLAN_VSWITCH = "/etc/netplan/60-vswitch.yaml"
NETPLAN_BRIDGE = "/etc/netplan/61-incus-bridge.yaml"
RULES_V4_BASE = "/etc/iptables/rules.v4.hetzman-base"
RULES_V6_BASE = "/etc/iptables/rules.v6.hetzman-base"
ETCD_CONF = "/etc/etcd.conf"
STATE_DIR = "/var/lib/hetzman"
LAST_SYNC_FILE = f"{STATE_DIR}/last-node-sync.json"
SYNC_LOG = "/var/log/hetzman-tooling/node-sync.log"

# package-data file -> (destination, mode)
DATA_INSTALL_MAP = {
    "hetzman-instance-watcher.service": ("/etc/systemd/system/hetzman-instance-watcher.service", 0o644),
    "hetzman-iptables-restore.service": ("/etc/systemd/system/hetzman-iptables-restore.service", 0o644),
    "hetzman-health.service": ("/etc/systemd/system/hetzman-health.service", 0o644),
    "hetzman-health.timer": ("/etc/systemd/system/hetzman-health.timer", 0o644),
    "hetzman-node-sync.service": ("/etc/systemd/system/hetzman-node-sync.service", 0o644),
    "hetzman-node-sync.timer": ("/etc/systemd/system/hetzman-node-sync.timer", 0o644),
    "hetzman-etcd-backup.service": ("/etc/systemd/system/hetzman-etcd-backup.service", 0o644),
    "hetzman-etcd-backup.timer": ("/etc/systemd/system/hetzman-etcd-backup.timer", 0o644),
    "dnsmasq-override.conf": ("/etc/systemd/system/dnsmasq.service.d/hetzman.conf", 0o644),
    "99-hetzman-pin-base": ("/usr/share/netfilter-persistent/plugins.d/99-hetzman-pin-base", 0o755),
    "95-hetzman-motd": ("/etc/update-motd.d/95-hetzman", 0o755),
}
ENABLE_UNITS = [
    "hetzman-instance-watcher.service",
    "hetzman-iptables-restore.service",
    "hetzman-health.timer",
    "hetzman-node-sync.timer",
    "hetzman-etcd-backup.timer",
]


def _read(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _write(path: str, content: str, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _data_text(name: str) -> str:
    return (importlib.resources.files("hetzman") / "data" / name).read_text()


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _sync_log(lines: List[str]) -> None:
    try:
        os.makedirs(os.path.dirname(SYNC_LOG), exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(SYNC_LOG, "a") as f:
            for line in lines:
                f.write(f"[{stamp}] {line}\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Registry commands

def _etcd_name_from_conf() -> Optional[str]:
    text = _read(ETCD_CONF) or ""
    match = re.search(r"^ETCD_NAME=(\S+)$", text, re.MULTILINE)
    return match.group(1).strip('"') if match else None


def _mtu_from_netplan(vlan_interface: str) -> int:
    text = _read(NETPLAN_VSWITCH)
    if text:
        try:
            doc = yaml.safe_load(text)
            return int(doc["network"]["vlans"][vlan_interface]["mtu"])
        except Exception:
            pass
    return 1400


def _infer_public_block(current_server: str) -> Optional[str]:
    pool = get_all_with_prefix("/hetzman/ip-pool/")
    blocks = {
        row["block"]
        for row in pool.values()
        if isinstance(row, dict) and row.get("server") == current_server and row.get("block")
    }
    return blocks.pop() if len(blocks) == 1 else None


@node_app.command("register")
def node_register(
    from_config: bool = typer.Option(False, "--from-config", help="Seed the entry from this node's local config"),
    public_block: Optional[str] = typer.Option(None, help="Routed public block CIDR (inferred from ip-pool if omitted)"),
):
    """Register (or refresh) this node in the fleet registry"""
    if not from_config:
        console.print("[red]Only --from-config registration is supported[/red]")
        raise typer.Exit(code=1)

    settings = get_settings()
    if not settings.vswitch_ip or not settings.vlan_interface:
        console.print(f"[red]config.ini is missing vswitch_ip/vlan_interface[/red]")
        raise typer.Exit(code=1)

    etcd_name = _etcd_name_from_conf()
    if not etcd_name:
        console.print(f"[red]Could not read ETCD_NAME from {ETCD_CONF}[/red]")
        raise typer.Exit(code=1)

    block = public_block or _infer_public_block(settings.current_server)
    if not block:
        console.print("[red]Could not infer public block from ip-pool; pass --public-block[/red]")
        raise typer.Exit(code=1)

    try:
        vlan_id = int(settings.vlan_interface.rsplit(".", 1)[1])
    except (IndexError, ValueError):
        console.print(f"[red]Cannot parse VLAN id from {settings.vlan_interface!r}[/red]")
        raise typer.Exit(code=1)

    entry = {
        "schema": SCHEMA_VERSION,
        "name": settings.current_server,
        "vswitch_ip": settings.vswitch_ip,
        "bridge_ip": settings.bridge_ip,
        "bridge_subnet": str(ipaddress.ip_network(f"{settings.bridge_ip}/24", strict=False)),
        "public_block": block,
        "primary_interface": settings.primary_iface,
        "vlan_interface": settings.vlan_interface,
        "vlan_id": vlan_id,
        "mtu": _mtu_from_netplan(settings.vlan_interface),
        "etcd_name": etcd_name,
        "etcd_client_port": 2379,
        "updated_at": datetime.datetime.now().isoformat(),
    }

    merged = load_registry()
    merged[settings.current_server] = entry
    errors = validate_registry(merged)
    if errors:
        console.print("[red]Refusing to register; registry would be invalid:[/red]")
        for error in errors:
            console.print(f"  [red]- {error}[/red]")
        raise typer.Exit(code=1)

    if not put_key(NODES_PREFIX + settings.current_server, json.dumps(entry)):
        console.print("[red]etcd write failed[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Registered {settings.current_server}[/green]")
    console.print(json.dumps(entry, indent=2))


@node_app.command("list")
def node_list():
    """List registry entries"""
    from rich.table import Table

    nodes = load_registry()
    errors = validate_registry(nodes) if nodes else ["registry is empty"]

    table = Table(title=f"Fleet registry ({len(nodes)} nodes)")
    for column in ("Node", "vSwitch IP", "Bridge", "Public block", "etcd name", "Updated"):
        table.add_column(column)
    for name in sorted(nodes):
        node = nodes[name]
        table.add_row(
            name, node.get("vswitch_ip", "?"),
            f"{node.get('bridge_ip', '?')} ({node.get('bridge_subnet', '?')})",
            node.get("public_block", "?"), node.get("etcd_name", "?"),
            (node.get("updated_at") or "?")[:19],
        )
    console.print(table)
    if errors:
        for error in errors:
            console.print(f"[red]invalid: {error}[/red]")
        raise typer.Exit(code=1)


@node_app.command("show")
def node_show(name: str = typer.Argument(..., help="Node name")):
    """Show one registry entry as JSON"""
    nodes = load_registry()
    if name not in nodes:
        console.print(f"[red]{name} not in registry[/red]")
        raise typer.Exit(code=1)
    console.print(json.dumps(nodes[name], indent=2))


@node_app.command("remove")
def node_remove(
    name: str = typer.Argument(..., help="Node name"),
    force: bool = typer.Option(False, "--force", help="Remove even with referencing NAT/pool/DNS rows"),
):
    """Remove a node from the registry (pair with `etcdctl member remove`)"""
    nodes = load_registry()
    if name not in nodes:
        console.print(f"[red]{name} not in registry[/red]")
        raise typer.Exit(code=1)

    refs: List[str] = []
    if get_all_with_prefix(f"/hetzman/nat/{name}/"):
        refs.append("NAT rules")
    if any(r.get("server") == name for r in get_all_with_prefix("/hetzman/ip-pool/").values() if isinstance(r, dict)):
        refs.append("ip-pool rows")
    if any(r.get("server") == name for r in get_all_with_prefix("/hetzman/dns/").values() if isinstance(r, dict)):
        refs.append("DNS records")
    if refs and not force:
        console.print(f"[red]{name} is still referenced by: {', '.join(refs)} (use --force to override)[/red]")
        raise typer.Exit(code=1)

    if not delete_key(NODES_PREFIX + name):
        console.print("[red]etcd delete failed[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Removed {name} from the registry[/green]")
    console.print(
        "[yellow]Reminder: node-sync is now inert fleet-wide until the etcd member "
        "is also removed (registry must 1:1 match members). This fail-closed freeze "
        "is intended.[/yellow]"
    )


# ---------------------------------------------------------------------------
# node-sync

def _config_ini_differs(self_node: dict, all_ips: List[str]) -> bool:
    desired = configparser.ConfigParser()
    desired["server"] = {
        "name": self_node["name"],
        "bridge_ip": self_node["bridge_ip"],
        "vswitch_ip": self_node["vswitch_ip"],
        "primary_interface": self_node["primary_interface"],
        "vlan_interface": self_node["vlan_interface"],
    }
    desired["etcd"] = {"endpoints": ",".join(f"{ip}:2379" for ip in sorted(all_ips))}

    on_disk = configparser.ConfigParser()
    on_disk.read(CONFIG_FILE)
    for section in desired.sections():
        if not on_disk.has_section(section):
            return True
        for option, value in desired[section].items():
            if on_disk.get(section, option, fallback=None) != value:
                return True
    return False


def _iptables_live_missing(self_node: dict, nodes: Dict[str, dict]) -> List[Tuple[str, str, List[str]]]:
    missing = []
    for table, chain, args in base_ensure_rules(self_node, nodes):
        if _run(["iptables", "-w", "5", "-t", table, "-C", chain, *args], timeout=10).returncode != 0:
            missing.append((table, chain, args))
    return missing


def _systemd_changes() -> List[str]:
    changed = []
    for data_name, (dest, _mode) in DATA_INSTALL_MAP.items():
        if _read(dest) != _data_text(data_name):
            changed.append(data_name)
    return changed


def _post_check_network(self_node: dict, nodes: Dict[str, dict]) -> bool:
    peers = [n["vswitch_ip"] for name, n in sorted(nodes.items()) if name != self_node["name"]]
    ping_ok = any(
        _run(["ping", "-c1", "-W2", ip], timeout=10).returncode == 0 for ip in peers[:2]
    )
    from ..etcd_kv import get_key

    return ping_ok and get_key("/hetzman/version") is not None


@app.command(name="node-sync")
def node_sync(
    check: bool = typer.Option(False, "--check", help="Report drift without changing anything"),
    apply: bool = typer.Option(False, "--apply", help="Converge this node to the registry"),
):
    """Render and reconcile this node's config from the fleet registry"""
    if check == apply:
        console.print("[red]Pass exactly one of --check or --apply[/red]")
        raise typer.Exit(code=2)

    with sync_lock() as acquired:
        if not acquired:
            console.print("[yellow]Another sync is in progress; skipping[/yellow]")
            raise typer.Exit(code=0)
        raise typer.Exit(code=_node_sync_run(apply))


def _node_sync_run(apply: bool) -> int:
    settings = get_settings()
    changed: List[str] = []
    warnings: List[str] = []
    errors: List[str] = []

    # ---- Preflight (fail-closed) ----
    nodes = load_registry()
    problems = validate_registry(nodes)
    if not problems:
        problems = registry_guard(nodes, settings.current_server)
    if problems:
        for problem in problems:
            console.print(f"[red]preflight: {problem}[/red]")
        _sync_log([f"preflight failed: {p}" for p in problems])
        _write_state("error", changed, errors=problems)
        return 3

    self_node = nodes[settings.current_server]
    all_ips = [n["vswitch_ip"] for n in nodes.values()]

    # ---- Compute drift ----
    pending: List[str] = []

    config_drift = _config_ini_differs(self_node, all_ips)
    if config_drift:
        pending.append("config.ini")

    desired_include = render_dnsmasq_include(nodes)
    include_drift = _read(DNSMASQ_INCLUDE) != desired_include
    if include_drift:
        pending.append("dnsmasq-include")

    conf_text = _read(DNSMASQ_CONF) or ""
    doomed_lines = dnsmasq_conf_lines_to_remove(conf_text, nodes)
    if doomed_lines:
        pending.append(f"dnsmasq.conf-migration({len(doomed_lines)} lines)")

    desired_netplan = render_netplan_vswitch(self_node, nodes)
    netplan_on_disk = _read(NETPLAN_VSWITCH) or ""
    netplan_drift = not netplan_semantically_equal(netplan_on_disk, desired_netplan)
    if netplan_drift:
        pending.append("netplan-vswitch")

    # 61-incus-bridge.yaml: warn-only.
    bridge_text = _read(NETPLAN_BRIDGE) or ""
    if self_node["bridge_ip"] not in bridge_text:
        warnings.append(
            f"{NETPLAN_BRIDGE} does not contain bridge_ip {self_node['bridge_ip']} (not auto-managed)"
        )

    try:
        desired_base_v4 = render_iptables_base(self_node, nodes)
        desired_base_v6 = render_iptables_base_v6()
    except RenderError as e:
        console.print(f"[red]render: {e}[/red]")
        _write_state("error", changed, errors=[str(e)])
        return 3

    base_drift = _read(RULES_V4_BASE) != desired_base_v4
    base_v6_drift = _read(RULES_V6_BASE) != desired_base_v6
    if base_drift or base_v6_drift:
        pending.append("iptables-base")

    live_missing = _iptables_live_missing(self_node, nodes)
    live_save = _run(["iptables-save"], timeout=15).stdout or ""
    deletions, cleanup_warnings = iptables_cleanup_plan(live_save, nodes)
    warnings.extend(cleanup_warnings)
    if live_missing:
        pending.append(f"iptables-live(+{len(live_missing)})")
    if deletions:
        pending.append(f"iptables-cleanup(-{len(deletions)})")

    systemd_changed = _systemd_changes()
    if systemd_changed:
        pending.append(f"systemd({','.join(systemd_changed)})")

    # ---- --check: report only ----
    if not apply:
        for warning in warnings:
            console.print(f"[yellow]warn: {warning}[/yellow]")
        if pending:
            console.print(f"[yellow]Drift detected: {', '.join(pending)}[/yellow]")
            return 1
        console.print("[green]Clean: node matches the registry[/green]")
        return 0

    # ---- --apply ----
    if config_drift:
        if write_config(self_node, all_ips):
            changed.append("config.ini")
        else:
            errors.append("config.ini write failed")

    dnsmasq_needs_restart = False
    if include_drift:
        try:
            _write(DNSMASQ_INCLUDE, desired_include)
            changed.append("dnsmasq-include")
            dnsmasq_needs_restart = True
        except OSError as e:
            errors.append(f"dnsmasq include: {e}")

    if doomed_lines:
        backup = DNSMASQ_CONF + ".bak-hetzman-migration"
        try:
            if not os.path.exists(backup):
                shutil.copy2(DNSMASQ_CONF, backup)
            kept = [l for l in conf_text.splitlines() if l not in doomed_lines]
            _write(DNSMASQ_CONF, "\n".join(kept) + "\n")
            changed.append("dnsmasq.conf-migration")
            dnsmasq_needs_restart = True
        except OSError as e:
            errors.append(f"dnsmasq.conf migration: {e}")

    if dnsmasq_needs_restart:
        test = _run(["dnsmasq", "--test", f"--conf-file={DNSMASQ_CONF}",
                     "--conf-dir=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new"])
        if test.returncode != 0:
            errors.append(f"dnsmasq --test failed: {test.stderr.strip()}")
        else:
            _run(["systemctl", "restart", "dnsmasq"])
            time.sleep(1)
            dig = _run(["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1",
                        f"{self_node['name']}.{DOMAIN}"])
            if not dig.stdout.strip():
                errors.append("post-restart dig check failed")

    if netplan_drift:
        backup = f"{NETPLAN_VSWITCH}.bak-{int(time.time())}"
        try:
            if os.path.exists(NETPLAN_VSWITCH):
                shutil.copy2(NETPLAN_VSWITCH, backup)
            _write(NETPLAN_VSWITCH, desired_netplan, mode=0o600)
            generate = _run(["netplan", "generate"])
            if generate.returncode != 0:
                raise RuntimeError(f"netplan generate: {generate.stderr.strip()}")
            _run(["netplan", "apply"], timeout=60)
            time.sleep(3)
            if not _post_check_network(self_node, nodes):
                raise RuntimeError("post-apply network check failed")
            changed.append("netplan-vswitch")
        except Exception as e:
            errors.append(f"netplan: {e}; restoring backup")
            if os.path.exists(backup):
                shutil.copy2(backup, NETPLAN_VSWITCH)
                _run(["netplan", "apply"], timeout=60)

    # iptables: live ensure first (additive), then deletions, then base files.
    for table, _chain, _args in base_policies():
        _run(["iptables", "-w", "5", "-t", table, "-P", _chain, _args], timeout=10)
    for table, chain, args in live_missing:
        result = _run(["iptables", "-w", "5", "-t", table, "-A", chain, *args], timeout=10)
        if result.returncode != 0:
            errors.append(f"iptables ensure {table}/{chain} failed: {result.stderr.strip()}")
    if live_missing:
        changed.append("iptables-live")

    for table, args in deletions:
        result = _run(["iptables", "-w", "5", "-t", table, "-D", *args], timeout=10)
        if result.returncode != 0:
            warnings.append(f"cleanup deletion failed ({table}): {' '.join(args)}")
    if deletions:
        changed.append("iptables-cleanup")

    for path, desired, drift in (
        (RULES_V4_BASE, desired_base_v4, base_drift),
        (RULES_V6_BASE, desired_base_v6, base_v6_drift),
    ):
        if not drift:
            continue
        try:
            if os.path.exists(path):
                shutil.copy2(path, path + ".prev")
            _write(path, desired, mode=0o640)
            restore_bin = "iptables-restore" if path == RULES_V4_BASE else "ip6tables-restore"
            test = _run([restore_bin, "--test", path])
            if test.returncode != 0:
                raise RuntimeError(f"{restore_bin} --test: {test.stderr.strip()}")
            changed.append(os.path.basename(path))
        except Exception as e:
            errors.append(f"{path}: {e}")
            if os.path.exists(path + ".prev"):
                shutil.copy2(path + ".prev", path)

    if systemd_changed:
        for data_name in systemd_changed:
            dest, mode = DATA_INSTALL_MAP[data_name]
            try:
                _write(dest, _data_text(data_name), mode=mode)
            except OSError as e:
                errors.append(f"{dest}: {e}")
        _run(["systemctl", "daemon-reload"])
        for unit in ENABLE_UNITS:
            _run(["systemctl", "enable", unit])
        if "hetzman-instance-watcher.service" in systemd_changed:
            _run(["systemctl", "restart", "hetzman-instance-watcher"])
        changed.append("systemd")

    # Anti-entropy NAT/DNS reconcile (netfilter-persistent save inside is
    # re-pinned to the base by the just-installed plugin).
    if not do_sync_apply(restart_watcher=False):
        errors.append("sync-apply reported failures")

    for warning in warnings:
        console.print(f"[yellow]warn: {warning}[/yellow]")
    result = "error" if errors else ("changed" if changed else "clean")
    for error in errors:
        console.print(f"[red]error: {error}[/red]")
    console.print(f"[{'green' if result != 'error' else 'red'}]node-sync result: {result} "
                  f"(changed: {', '.join(changed) or 'nothing'})[/]")

    _sync_log(
        [f"result={result} changed={changed} errors={errors} warnings={len(warnings)}"]
        + [f"  warn: {w}" for w in warnings]
    )
    _write_state(result, changed, errors=errors)
    return 0 if result != "error" else 4


def _write_state(result: str, changed: List[str], errors: Optional[List[str]] = None) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LAST_SYNC_FILE, "w") as f:
            json.dump(
                {
                    "ts": datetime.datetime.now().isoformat(timespec="seconds"),
                    "result": result,
                    "changed": changed,
                    "errors": (errors or [])[:5],
                },
                f,
            )
    except OSError as e:
        log_message(f"could not write {LAST_SYNC_FILE}: {e}", "WARNING")
