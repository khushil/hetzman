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
import difflib
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
    DNS_LEASEFILE,
    FILTER_CUSTOM_CHAINS,
    HOSTPORTS_CHAIN,
    MANAGED_HEADER,
    NAT_CUSTOM_CHAINS,
    RenderError,
    TRUSTED_DNS_CLIENTS,
    _host_port_argv,
    base_ensure_rules,
    base_policies,
    dns_acl_source_ok,
    host_port_ok,
    iptables_cleanup_plan,
    netplan_semantically_equal,
    render_dnsmasq_conf,
    render_dnsmasq_include,
    render_iptables_base,
    render_iptables_base_v6,
    render_netplan_vswitch,
    DOMAIN,
)
from ._render import drive
from .system import do_sync_apply

DNSMASQ_CONF = "/etc/dnsmasq.conf"
DNSMASQ_INCLUDE = "/etc/dnsmasq.d/hetzman-nodes.conf"
NETPLAN_VSWITCH = "/etc/netplan/60-vswitch.yaml"
NETPLAN_BRIDGE = "/etc/netplan/61-incus-bridge.yaml"
RULES_V4_BASE = "/etc/iptables/rules.v4.hetzman-base"
RULES_V6_BASE = "/etc/iptables/rules.v6.hetzman-base"
ETCD_CONF = "/etc/etcd.conf"
STATE_DIR = "/var/lib/hetzman"
DNSMASQ_DOWN_SENTINEL = "/var/lib/hetzman/dnsmasq-down"
TRUSTED_DNS_CLIENTS_KEY = "/hetzman/config/trusted-dns-clients"
# One etcd key PER host-port entry, not a JSON list in a single key:
# add is a put, close is a delete, and two operators editing different ports
# cannot clobber each other - so no read-modify-write and no CAS. Mirrors the
# existing /hetzman/port-forward/<server>/<instance>-<port>-<proto> shape.
# Per-NODE, so opening a port here never opens it on the peer.
HOST_PORTS_PREFIX = "/hetzman/host-ports"
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
# dnsmasq (DNS + DHCP) — managed serving config, safe apply

def _vswitch_addr_up(self_node: dict) -> bool:
    """True iff this node's vSwitch IP is live on its VLAN interface.

    node-sync only adds the vSwitch listener to dnsmasq.conf when this is True,
    so a down/not-yet-configured VLAN iface can never make dnsmasq fail to bind
    on restart (a failure ``dnsmasq --test`` cannot catch)."""
    res = _run(["ip", "-o", "addr", "show", "dev", self_node["vlan_interface"]], timeout=10)
    if res.returncode != 0:
        return False
    return self_node["vswitch_ip"] in (res.stdout or "")


def _systemctl_active(unit: str) -> bool:
    return (_run(["systemctl", "is-active", unit], timeout=10).stdout or "").strip() == "active"


def _leasefile_size() -> int:
    """Bytes in the DHCP leasefile; -1 when it does not exist."""
    try:
        return os.path.getsize(DNS_LEASEFILE)
    except OSError:
        return -1


def _dnsmasq_serving(
    self_node: dict, *, check_dhcp: bool, require_leases: bool = True
) -> Tuple[bool, str]:
    """Poll up to ~8s (> dnsmasq.service RestartSec=5) for dnsmasq to be fully
    serving. Returns (ok, reason). ``--test`` + a forward dig can both pass while
    DHCP is dead, so we additionally check the :67 listener and the leasefile.

    ``require_leases`` makes the leasefile check *differential*: the caller
    passes whether leases existed BEFORE the apply. A node that has never handed
    out a lease — a freshly bootstrapped one with no instances yet, or any node
    whose last instance was removed — legitimately has an empty leasefile, and
    treating that as failure would roll back a perfectly good conf and then
    escalate (the rollback is equally lease-less), leaving node-sync permanently
    erroring. The :67 listener check still runs either way, so DHCP liveness is
    verified on a fresh node too; only the "we lost the leases we had" signal is
    conditional."""
    last = "unknown"
    for _ in range(8):
        if not _systemctl_active("dnsmasq"):
            last = "service not active"
            time.sleep(1)
            continue
        fwd = _run(["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1",
                    f"{self_node['name']}.{DOMAIN}"], timeout=10)
        if not (fwd.stdout or "").strip():
            last = "forward dig empty"
            time.sleep(1)
            continue
        rev = _run(["dig", "+short", "+time=2", "+tries=1", "-x", self_node["vswitch_ip"],
                    "@127.0.0.1"], timeout=10)
        if self_node["name"] not in (rev.stdout or ""):
            last = "reverse dig mismatch"
            time.sleep(1)
            continue
        if check_dhcp:
            ss = _run(["ss", "-ulnp", "sport = :67"], timeout=10)
            if "dnsmasq" not in (ss.stdout or ""):
                last = "DHCP :67 listener gone"
                time.sleep(1)
                continue
            if require_leases:
                size = _leasefile_size()
                if size < 0:
                    last = "leasefile missing"
                    time.sleep(1)
                    continue
                if size == 0:
                    last = "leasefile empty"
                    time.sleep(1)
                    continue
        return True, "ok"
    return False, last


def _clear_dnsmasq_sentinel() -> None:
    try:
        os.unlink(DNSMASQ_DOWN_SENTINEL)
    except OSError:
        pass


def _trusted_dns_clients() -> List[str]:
    """Trusted :53 source CIDRs: always the vSwitch, plus any operator-configured
    VPN CIDRs from etcd. Fail-closed (narrower) — a malformed/oversized value is
    logged and dropped, never widening the ACL and never aborting node-sync."""
    trusted = list(TRUSTED_DNS_CLIENTS)
    try:
        raw = get_all_with_prefix(TRUSTED_DNS_CLIENTS_KEY).get(TRUSTED_DNS_CLIENTS_KEY)
        cidrs = raw if isinstance(raw, list) else (raw.get("cidrs") if isinstance(raw, dict) else [])
        for cidr in cidrs or []:
            if dns_acl_source_ok(str(cidr)):
                if cidr not in trusted:
                    trusted.append(str(cidr))
            else:
                _sync_log([f"trusted-dns-clients: rejected unsafe CIDR {cidr!r} (not RFC1918/too broad)"])
    except Exception as e:  # noqa: BLE001 — must never break node-sync
        _sync_log([f"trusted-dns-clients: read/parse failed, using vSwitch only: {e}"])
    return trusted


def _host_ports(node_name: str) -> List[dict]:
    """Operator-opened host ports for THIS node, from etcd.

    Fail-closed the same way :func:`_trusted_dns_clients` is: a malformed entry
    is logged and dropped, a read failure yields an empty list, and nothing in
    here may raise. The renderer's ``_assert_host_ports_safe`` would abort the
    entire node-sync run (no DNS, no netplan, no firewall, no systemd) on bad
    operator data, so this filter is what keeps that backstop unreachable.

    Exact-key lookup per entry under the node's own prefix - deliberately NOT a
    scan of ``/hetzman/host-ports/`` as a whole, which would open every node's
    ports on every node.
    """
    prefix = f"{HOST_PORTS_PREFIX}/{node_name}/"
    entries: List[dict] = []
    try:
        for key, raw in sorted((get_all_with_prefix(prefix) or {}).items()):
            if not key.startswith(prefix):
                continue
            if host_port_ok(raw):
                entries.append(raw)
            else:
                _sync_log([f"host-ports: rejected malformed entry at {key}: {raw!r}"])
    except Exception as e:  # noqa: BLE001 — must never break node-sync
        _sync_log([f"host-ports: read/parse failed, opening none: {e}"])
    return entries


def _desired_host_port_rules(host_ports: List[dict]) -> List[List[str]]:
    """Deduplicated argv for the HETZMAN_HOSTPORTS chain, in rendered order."""
    seen, out = set(), []
    for entry in host_ports:
        argv = _host_port_argv(entry)
        if tuple(argv) in seen:
            continue
        seen.add(tuple(argv))
        out.append(argv)
    return out


def _live_host_port_rules() -> List[List[str]]:
    """What the HETZMAN_HOSTPORTS chain currently holds, as argv lists."""
    result = _run(["iptables", "-w", "5", "-S", HOSTPORTS_CHAIN], timeout=10)
    if result.returncode != 0:
        return []
    rules = []
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        if len(parts) > 2 and parts[0] == "-A" and parts[1] == HOSTPORTS_CHAIN:
            rules.append(parts[2:])
    return rules


def _apply_dnsmasq(
    self_node: dict,
    *,
    include_drift: bool,
    desired_include: str,
    conf_drift: bool,
    conf_is_managed: bool,
    desired_conf: str,
) -> Tuple[List[str], List[str]]:
    """Write the dnsmasq include + full conf, then ONE restart + verify, with a
    test-before-write and an escalating rollback. Returns (changed, errors).

    Safety properties (each unit-tested):
    * the candidate conf is ``dnsmasq --test``ed BEFORE the live file is touched;
    * a ``.rollback`` snapshot is taken every apply and restored on ANY failed
      post-apply check (active + forward + reverse + DHCP :67 + leasefile);
    * if even the rollback isn't serving, escalate (CRITICAL log + a
      ``dnsmasq-down`` sentinel) instead of leaving DHCP silently dead;
    * the leasefile arm of that check is only armed when leases existed BEFORE
      the apply, so a node with no instances yet is not mistaken for a dead one.
    """
    changed: List[str] = []
    errors: List[str] = []
    needs_restart = False
    # Sampled before anything is written: "did this node have leases to lose?"
    had_leases = _leasefile_size() > 0

    if include_drift:
        try:
            _write(DNSMASQ_INCLUDE, desired_include)
            changed.append("dnsmasq-include")
            needs_restart = True
        except OSError as e:
            errors.append(f"dnsmasq include: {e}")

    conf_rollback = None
    if conf_drift:
        try:
            # one-time pre-management backup of the hand-rolled conf
            if not conf_is_managed and os.path.exists(DNSMASQ_CONF):
                premanage = DNSMASQ_CONF + ".bak-hetzman-premanage"
                if not os.path.exists(premanage):
                    shutil.copy2(DNSMASQ_CONF, premanage)
            # rollback snapshot every apply (exact prior bytes to restore to)
            if os.path.exists(DNSMASQ_CONF):
                conf_rollback = DNSMASQ_CONF + ".rollback"
                shutil.copy2(DNSMASQ_CONF, conf_rollback)
            # TEST the candidate BEFORE the live file is ever touched
            candidate = DNSMASQ_CONF + ".candidate"
            _write(candidate, desired_conf)
            test = _run(["dnsmasq", "--test", f"--conf-file={candidate}",
                         "--conf-dir=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new"])
            try:
                os.unlink(candidate)
            except OSError:
                pass
            if test.returncode != 0:
                errors.append(f"dnsmasq.conf --test failed (not applied): {test.stderr.strip()}")
            else:
                _write(DNSMASQ_CONF, desired_conf)
                changed.append("dnsmasq.conf" if conf_is_managed else "dnsmasq.conf-adopt")
                needs_restart = True
        except OSError as e:
            errors.append(f"dnsmasq.conf write: {e}")

    if not needs_restart:
        return changed, errors

    _run(["systemctl", "restart", "dnsmasq"])
    ok, reason = _dnsmasq_serving(self_node, check_dhcp=True, require_leases=had_leases)
    if ok:
        _clear_dnsmasq_sentinel()
        return changed, errors

    # roll the conf back to the known-good bytes and restart
    errors.append(f"dnsmasq post-apply check failed ({reason}); rolling back")
    _sync_log([f"dnsmasq post-apply failed ({reason}); rolling back dnsmasq.conf"])
    if conf_rollback and os.path.exists(conf_rollback):
        try:
            shutil.copy2(conf_rollback, DNSMASQ_CONF)
        except OSError as e:
            errors.append(f"dnsmasq.conf rollback copy failed: {e}")
    _run(["systemctl", "restart", "dnsmasq"])
    ok2, reason2 = _dnsmasq_serving(self_node, check_dhcp=True, require_leases=had_leases)
    if ok2:
        _clear_dnsmasq_sentinel()
        return changed, errors

    # ESCALATE: even the rollback isn't serving — DHCP/DNS is down.
    msg = f"CRITICAL: dnsmasq down after rollback ({reason2})"
    log_message(msg, "ERROR")
    _sync_log([msg])
    try:
        _write(DNSMASQ_DOWN_SENTINEL, f"{reason2}\n")
    except OSError:
        pass
    errors.append(msg)
    return changed, errors


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

    from ..core.reads import list_nodes

    nodes, errors = list_nodes()

    table = Table(title=f"Fleet registry ({len(nodes)} nodes)")
    for column in ("Node", "vSwitch IP", "Bridge", "Public block", "etcd name", "Updated"):
        table.add_column(column)
    for node in nodes:
        table.add_row(
            node.name, node.vswitch_ip or "?",
            f"{node.bridge_ip or '?'} ({node.bridge_subnet or '?'})",
            node.public_block or "?", node.etcd_name or "?",
            (node.updated_at or "?")[:19],
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


@node_app.command("add")
def node_add(
    name: str = typer.Argument(..., help="Node (server) name"),
    vswitch_ip: str = typer.Option(..., help="Internal vSwitch IP (e.g. 10.0.0.5)"),
    bridge_ip: str = typer.Option(..., help="Incus bridge IP (e.g. 10.100.5.1)"),
    public_block: str = typer.Option(..., help="Routed public block CIDR"),
    primary_interface: str = typer.Option(..., help="Physical interface (e.g. enp5s0)"),
    vlan_interface: str = typer.Option(..., help="VLAN interface (e.g. enp5s0.4000)"),
    vlan_id: int = typer.Option(..., help="VLAN id (e.g. 4000)"),
    mtu: int = typer.Option(1400, help="vSwitch MTU"),
    etcd_name: str = typer.Option(..., help="The node's etcd member name (ETCD_NAME)"),
):
    """Register a node's topology in the fleet registry (registry-only).

    NOTE: this does NOT add the etcd cluster member. The new box must be
    provisioned (etcd installed + joined as a member, hetzman installed) before
    node-sync will converge — full remote provisioning is a separate command.
    """
    from ..core import nodes as core_nodes

    drive(core_nodes.register_node(
        name=name, vswitch_ip=vswitch_ip, bridge_ip=bridge_ip, public_block=public_block,
        primary_interface=primary_interface, vlan_interface=vlan_interface,
        vlan_id=vlan_id, mtu=mtu, etcd_name=etcd_name,
    ))


@node_app.command("remove")
def node_remove(
    name: str = typer.Argument(..., help="Node name"),
    remove_member: bool = typer.Option(
        False, "--remove-member", help="Also remove the node's etcd cluster member (guarded)"
    ),
    force: bool = typer.Option(False, "--force", help="Remove even with referencing NAT/pool/DNS rows"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the typed confirmation"),
):
    """Remove a node from the registry (and optionally its etcd cluster member)."""
    from ..core import nodes as core_nodes

    if remove_member and not yes:
        # Typed confirmation: a wrong target can break the production quorum.
        console.print(
            f"[bold red]This will remove etcd cluster member for '{name}'.[/bold red]\n"
            "[yellow]Re-type the node name to confirm:[/yellow]"
        )
        typed = typer.prompt("node name")
        if typed != name:
            console.print("[red]Name mismatch; aborting.[/red]")
            raise typer.Exit(code=1)

    drive(core_nodes.remove_node(name, remove_member=remove_member, force=force))


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


def _rule_variants(args: List[str]) -> List[List[str]]:
    """A rule and its live-equivalent spellings.

    The fleet's persisted rulesets predate this tool and use the legacy
    ``-m state --state`` alias in places; it is functionally identical to
    ``-m conntrack --ctstate`` but does not ``-C``-match it. Accept either
    so we never stack a duplicate-equivalent rule; the canonical base file
    stays modern and live state converges at the next boot restore.
    """
    variants = [args]
    if "conntrack" in args:
        legacy = list(args)
        for old, new in (("-m", "-m"), ("conntrack", "state"), ("--ctstate", "--state")):
            legacy = [new if a == old else a for a in legacy]
        variants.append(legacy)
    return variants


def _iptables_live_missing(
    self_node: dict, nodes: Dict[str, dict], trusted_dns_clients: Optional[List[str]] = None
) -> List[Tuple[str, str, List[str]]]:
    missing = []
    for table, chain, args in base_ensure_rules(self_node, nodes, trusted_dns_clients):
        present = any(
            _run(["iptables", "-w", "5", "-t", table, "-C", chain, *variant], timeout=10).returncode == 0
            for variant in _rule_variants(args)
        )
        if not present:
            missing.append((table, chain, args))
    return missing


def _ensure_custom_chains() -> None:
    """Create the custom nat AND filter chains if they do not exist yet.

    The base ruleset jumps PREROUTING/POSTROUTING into HETZMAN_NAT and
    HETZMAN_NAT_POST. On a freshly provisioned node neither chain exists, so the
    live-ensure step below fails every one of those jumps with
    ``Chain 'HETZMAN_NAT' does not exist``. ``do_sync_apply`` does create them —
    but it runs at the END of node-sync, so the FIRST run on any new node always
    reported errors and only the second run came back clean.

    The same applies to the filter table: the base ruleset jumps INPUT into
    HETZMAN_HOSTPORTS, and that jump fails identically if the chain is absent.

    Creating a chain that already exists is an error we deliberately ignore;
    this is idempotent and additive, and never touches rules.
    """
    for table, chains in (("nat", NAT_CUSTOM_CHAINS), ("filter", FILTER_CUSTOM_CHAINS)):
        for chain in chains:
            exists = _run(
                ["iptables", "-w", "5", "-t", table, "-L", chain, "-n"], timeout=10
            ).returncode == 0
            if not exists:
                _run(["iptables", "-w", "5", "-t", table, "-N", chain], timeout=10)


def _apply_host_ports(desired: List[List[str]]) -> List[str]:
    """Flush and rebuild HETZMAN_HOSTPORTS from etcd. Returns error strings.

    Flush-and-rebuild rather than incremental add, because the ensure path
    (iptables -C || -A) cannot express removal: without this, closing a port
    would leave it open until the next reboot while --check reported clean.
    """
    errors: List[str] = []
    flush = _run(["iptables", "-w", "5", "-t", "filter", "-F", HOSTPORTS_CHAIN], timeout=10)
    if flush.returncode != 0:
        return [f"host-ports: flush failed: {flush.stderr.strip()}"]
    for argv in desired:
        result = _run(
            ["iptables", "-w", "5", "-t", "filter", "-A", HOSTPORTS_CHAIN, *argv], timeout=10
        )
        if result.returncode != 0:
            errors.append(f"host-ports: add {' '.join(argv)} failed: {result.stderr.strip()}")
    return errors


def _systemd_changes() -> List[str]:
    changed = []
    for data_name, (dest, _mode) in DATA_INSTALL_MAP.items():
        if _read(dest) != _data_text(data_name):
            changed.append(data_name)
    return changed


def _post_check_network(self_node: dict, nodes: Dict[str, dict]) -> bool:
    """Did the netplan apply leave this node able to talk to the fleet?

    The peer-ping arm is only meaningful when there IS a peer. On a single-node
    fleet ``peers`` is empty and ``any([])`` is False, which would fail every
    netplan apply, roll it straight back, and leave node-sync reporting an error
    on every run forever — with the drift never clearing. So require a peer to
    answer only when one exists; etcd reachability is the arm that still means
    something either way.
    """
    peers = [n["vswitch_ip"] for name, n in sorted(nodes.items()) if name != self_node["name"]]
    ping_ok = not peers or any(
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

    # Full managed dnsmasq.conf (DNS + DHCP). The render supersedes the legacy
    # host-record migration (it never emits host-record lines). vlan_listen is
    # gated on the vSwitch address being live so the candidate can always bind.
    conf_text = _read(DNSMASQ_CONF) or ""
    conf_is_managed = conf_text.startswith(MANAGED_HEADER)
    vlan_listen = _vswitch_addr_up(self_node)
    try:
        desired_conf = render_dnsmasq_conf(self_node, vlan_listen=vlan_listen)
    except RenderError as e:
        console.print(f"[red]render dnsmasq.conf: {e}[/red]")
        _sync_log([f"render dnsmasq.conf failed: {e}"])
        _write_state("error", changed, errors=[str(e)])
        return 3
    conf_drift = conf_text != desired_conf
    if conf_drift:
        pending.append("dnsmasq.conf" if conf_is_managed else "dnsmasq.conf-adopt")

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

    trusted_dns = _trusted_dns_clients()
    host_ports = _host_ports(settings.current_server)
    desired_hostport_rules = _desired_host_port_rules(host_ports)
    try:
        desired_base_v4 = render_iptables_base(
            self_node, nodes, trusted_dns_clients=trusted_dns, host_ports=host_ports
        )
        desired_base_v6 = render_iptables_base_v6()
    except RenderError as e:
        console.print(f"[red]render: {e}[/red]")
        _write_state("error", changed, errors=[str(e)])
        return 3

    base_drift = _read(RULES_V4_BASE) != desired_base_v4
    base_v6_drift = _read(RULES_V6_BASE) != desired_base_v6
    if base_drift or base_v6_drift:
        pending.append("iptables-base")

    live_missing = _iptables_live_missing(self_node, nodes, trusted_dns)
    live_save = _run(["iptables-save"], timeout=15).stdout or ""
    deletions, cleanup_warnings = iptables_cleanup_plan(live_save, nodes)
    warnings.extend(cleanup_warnings)
    # Host-port drift is computed as desired-vs-live in BOTH directions. The
    # generic live_missing path only ever reports additions, so without this a
    # closed port would linger in the live chain and --check would say "clean".
    hostport_drift = _live_host_port_rules() != desired_hostport_rules
    if hostport_drift:
        pending.append(f"host-ports({len(desired_hostport_rules)} desired)")
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
        if conf_drift:
            # Surface exactly what a (safety-critical) dnsmasq.conf apply would change.
            diff = list(difflib.unified_diff(
                conf_text.splitlines(), desired_conf.splitlines(),
                fromfile="dnsmasq.conf (live)", tofile="dnsmasq.conf (desired)", lineterm="",
            ))
            if diff:
                console.print("[cyan]dnsmasq.conf diff:[/cyan]")
                for line in diff[:80]:
                    color = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim"
                    console.print(f"[{color}]{line}[/{color}]")
        if base_drift:
            # Same treatment dnsmasq.conf gets: on a box with no console, seeing
            # exactly which firewall lines would change before applying them is
            # the difference between a safe apply and a guess.
            diff = list(difflib.unified_diff(
                (_read(RULES_V4_BASE) or "").splitlines(), desired_base_v4.splitlines(),
                fromfile="rules.v4.hetzman-base (live)",
                tofile="rules.v4.hetzman-base (desired)", lineterm="",
            ))
            if diff:
                console.print("[cyan]iptables base diff:[/cyan]")
                for line in diff[:80]:
                    color = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim"
                    console.print(f"[{color}]{line}[/{color}]")
        if hostport_drift:
            console.print("[cyan]host-ports (live -> desired):[/cyan]")
            for argv in _live_host_port_rules():
                console.print(f"[red]- {' '.join(argv)}[/red]")
            for argv in desired_hostport_rules:
                console.print(f"[green]+ {' '.join(argv)}[/green]")
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

    d_changed, d_errors = _apply_dnsmasq(
        self_node,
        include_drift=include_drift, desired_include=desired_include,
        conf_drift=conf_drift, conf_is_managed=conf_is_managed, desired_conf=desired_conf,
    )
    changed.extend(d_changed)
    errors.extend(d_errors)

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
    _ensure_custom_chains()
    for table, _chain, _args in base_policies():
        _run(["iptables", "-w", "5", "-t", table, "-P", _chain, _args], timeout=10)
    for table, chain, args in live_missing:
        result = _run(["iptables", "-w", "5", "-t", table, "-A", chain, *args], timeout=10)
        if result.returncode != 0:
            errors.append(f"iptables ensure {table}/{chain} failed: {result.stderr.strip()}")
    if live_missing:
        changed.append("iptables-live")

    if hostport_drift:
        hp_errors = _apply_host_ports(desired_hostport_rules)
        errors.extend(hp_errors)
        if not hp_errors:
            changed.append("host-ports")

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
            # --now also starts timers; for already-active services it's a no-op.
            _run(["systemctl", "enable", "--now", unit])
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
