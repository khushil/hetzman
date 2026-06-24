"""Console-free read layer: data gathering for the list/status views.

This module performs the etcd reads and pure-data shaping that the Rich
``*_list`` / ``status`` / ``fleet-status`` CLI commands previously did inline,
and returns frozen value objects from :mod:`hetzman.core.models`.  No Rich
markup appears in any returned field — rendering is the presentation layer's
job.

HARD INVARIANT: this module may import ONLY console-free modules
(``hetzman.etcd_kv``, ``hetzman.registry``, ``hetzman.config``,
``hetzman.core.models``, ``hetzman.core.exec``) plus the standard library.  It
must NOT import any ``hetzman.commands.*`` module nor ``hetzman.network`` (both
pull in the Rich console).  The console tripwire in
``tests/test_core_import_isolation.py`` enforces this.
"""
from __future__ import annotations

import datetime

from ..config import get_etcd_client, get_settings
from ..etcd_kv import get_all_with_prefix
from ..registry import load_registry, validate_registry
from . import exec as host_exec
from .errors import CoreError, HostUnreachable
from .models import (
    DNSRecord,
    DnsServerStatus,
    FleetNodeStatus,
    FleetStatus,
    Instance,
    IPAllocation,
    NodeInfo,
    PortForward,
    SystemStatus,
    UpdateStatus,
)

IP_POOL_PREFIX = "/hetzman/ip-pool/"
DNS_PREFIX = "/hetzman/dns/"
HEALTH_PREFIX = "/hetzman/health/"


# ---------------------------------------------------------------------------
# IP pool
# ---------------------------------------------------------------------------


def list_ips(
    server: str | None = None, available_only: bool = False
) -> list[IPAllocation]:
    """Public IP pool, mirroring ``ip_list`` filtering/sorting.

    From ``/hetzman/ip-pool/``; sorted by key (== IP-keyed), filtered by
    ``server`` and (when ``available_only``) by ``status == "available"``.
    """
    ip_pool = get_all_with_prefix(IP_POOL_PREFIX)
    result: list[IPAllocation] = []
    for key, data in sorted(ip_pool.items()):
        if not isinstance(data, dict):
            continue
        if server and data.get("server") != server:
            continue
        if available_only and data.get("status") != "available":
            continue
        result.append(IPAllocation.from_etcd(key, data))
    return result


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def list_dns(server: str | None = None) -> list[DNSRecord]:
    """DNS A-records, mirroring ``dns_list``.

    From ``/hetzman/dns/``; sorted by key, filtered by ``server``.
    """
    dns_records = get_all_with_prefix(DNS_PREFIX)
    result: list[DNSRecord] = []
    for key, record in sorted(dns_records.items()):
        if not isinstance(record, dict):
            continue
        if server and record.get("server") != server:
            continue
        result.append(DNSRecord.from_etcd(key, record))
    return result


# ---------------------------------------------------------------------------
# Port forwards
# ---------------------------------------------------------------------------


def list_ports(instance: str | None = None) -> list[PortForward]:
    """Port-forward rules for the current server, mirroring ``port_list``.

    From ``/hetzman/port-forward/{current_server}/``; sorted by key, filtered
    by ``instance`` (matched against ``instance_name``).
    """
    current_server = get_settings().current_server
    port_forwards = get_all_with_prefix(f"/hetzman/port-forward/{current_server}/")
    result: list[PortForward] = []
    for _key, rule in sorted(port_forwards.items()):
        if not isinstance(rule, dict):
            continue
        if instance and rule.get("instance_name") != instance:
            continue
        result.append(PortForward.from_etcd(_key, rule))
    return result


# ---------------------------------------------------------------------------
# Node registry
# ---------------------------------------------------------------------------


def list_nodes() -> tuple[list[NodeInfo], list[str]]:
    """Registry entries plus validation errors, mirroring ``node_list``.

    Returns ``(nodes, errors)`` where ``nodes`` is sorted by name and
    ``errors`` matches ``node_list``: ``validate_registry(nodes)`` when the
    registry is non-empty, else ``["registry is empty"]``.
    """
    raw = load_registry()
    errors = validate_registry(raw) if raw else ["registry is empty"]
    nodes = [
        NodeInfo.from_etcd(name, raw[name]) for name in sorted(raw)
    ]
    return nodes, errors


# ---------------------------------------------------------------------------
# System status
# ---------------------------------------------------------------------------


def get_system_status() -> SystemStatus:
    """Snapshot of the counters shown by ``system.status``.

    Replicates ``status()`` exactly as data.  ``etcd_members`` is the live
    member count, or ``None`` if listing members raises (matching the CLI's
    "Unknown").  No other exception is swallowed here.
    """
    current_server = get_settings().current_server

    dns_records = get_all_with_prefix(DNS_PREFIX)
    dns_mine = sum(
        1 for v in dns_records.values()
        if isinstance(v, dict) and v.get("server") == current_server
    )

    dns_types: dict = {}
    for record in dns_records.values():
        if not isinstance(record, dict):
            continue
        if record.get("server") == current_server and record.get("type"):
            dns_types[record["type"]] = dns_types.get(record["type"], 0) + 1

    ip_pool = get_all_with_prefix(IP_POOL_PREFIX)
    ips_available = sum(
        1 for v in ip_pool.values()
        if isinstance(v, dict)
        and v.get("server") == current_server
        and v.get("status") == "available"
    )
    ips_total = sum(
        1 for v in ip_pool.values()
        if isinstance(v, dict) and v.get("server") == current_server
    )

    nat_rules = get_all_with_prefix(f"/hetzman/nat/{current_server}/")
    active_nat = sum(
        1 for v in nat_rules.values()
        if isinstance(v, dict) and v.get("enabled", True)
    )

    port_forwards = get_all_with_prefix(f"/hetzman/port-forward/{current_server}/")
    active_ports = sum(
        1 for v in port_forwards.values()
        if isinstance(v, dict) and v.get("enabled", True)
    )

    try:
        etcd_members: int | None = len(list(get_etcd_client().members))
    except Exception:
        etcd_members = None

    return SystemStatus(
        server=current_server,
        dns_total=len(dns_records),
        dns_mine=dns_mine,
        dns_types=dns_types,
        ips_available=ips_available,
        ips_total=ips_total,
        active_nat=active_nat,
        active_ports=active_ports,
        etcd_members=etcd_members,
    )


# ---------------------------------------------------------------------------
# Fleet status (keystone)
# ---------------------------------------------------------------------------


def get_fleet_status() -> FleetStatus:
    """Fleet health as pure data, ported from ``fleet.fleet_status``.

    Per node (over ``sorted(set(nodes) | set(health))``) build a
    :class:`FleetNodeStatus`.  The ``degraded`` flag reproduces the CLI's
    exactly:

    * a registered/known node with no heartbeat -> down -> degraded;
    * any bad check or bad peer -> degraded;
    * ``endpoints_configured != len(nodes)`` (registry size) when the registry
      is non-empty -> degraded;
    * a registered node whose ``etcd_name`` is absent from the live etcd
      members (when members are known) -> degraded.
    """
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
    node_statuses: list[FleetNodeStatus] = []

    for name in sorted(set(nodes) | set(health)):
        beat = health.get(name)
        if not beat:
            degraded = True
            node_statuses.append(
                FleetNodeStatus(
                    name=name,
                    heartbeat_age_s=None,
                    alive=False,
                    checks_bad=(),
                    peers_bad=(),
                    hetzman_version="?",
                    incus_version="?",
                    sync_result="-",
                    disk_root_pct=None,
                    pool_pct=None,
                    endpoint_count_ok=True,
                    etcd_member_present=False,
                    endpoints_configured=None,
                )
            )
            continue

        heartbeat_age_s: int | None = None
        try:
            delta = now - datetime.datetime.fromisoformat(beat["ts"])
            heartbeat_age_s = int(delta.total_seconds())
        except (KeyError, ValueError):
            pass

        checks = beat.get("checks", {})
        flat = {k: v for k, v in checks.items() if isinstance(v, str)}
        bad = tuple(k for k, v in flat.items() if v not in ("ok",))
        peers = checks.get("peers", {})
        bad_peers = tuple(k for k, v in peers.items() if v != "ok")
        if bad or bad_peers:
            degraded = True

        endpoints = beat.get("endpoints_configured")
        endpoint_count_ok = True
        if nodes and endpoints != len(nodes):
            degraded = True
            endpoint_count_ok = False

        sync = (beat.get("node_sync") or {}).get("result", "-")

        disk_root_pct = _as_int(checks.get("disk_root_pct"))
        pool_pct = _as_int(checks.get("btrfs_pool_pct"))

        registered = name in nodes
        etcd_name = nodes[name].get("etcd_name") if registered else None
        etcd_member_present = bool(members) and etcd_name in members
        if registered and etcd_name not in members and members:
            degraded = True

        node_statuses.append(
            FleetNodeStatus(
                name=name,
                heartbeat_age_s=heartbeat_age_s,
                alive=True,
                checks_bad=bad,
                peers_bad=bad_peers,
                hetzman_version=beat.get("hetzman_version", "?"),
                incus_version=beat.get("incus_version", "?"),
                sync_result=sync,
                disk_root_pct=disk_root_pct,
                pool_pct=pool_pct,
                endpoint_count_ok=endpoint_count_ok,
                etcd_member_present=etcd_member_present,
                endpoints_configured=endpoints
                if isinstance(endpoints, int)
                else None,
            )
        )

    return FleetStatus(
        nodes=tuple(node_statuses),
        degraded=degraded,
        member_names=frozenset(members),
        registered_node_count=len(nodes),
    )


def _as_int(value: object) -> int | None:
    """Best-effort int coercion for check values; ``None`` when not numeric."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


# ---------------------------------------------------------------------------
# Instances (VMs + containers) — live, via the host executor
# ---------------------------------------------------------------------------


def list_instances(host: str | None = None) -> tuple[list[Instance], list[str]]:
    """List Incus instances on ``host``, or fleet-wide when ``host is None``.

    Incus is standalone per host, so the fleet view fans out across every
    registry node (sequentially — one dead node + an SSH ConnectTimeout would
    otherwise stall a parallel list). Returns ``(instances, unreachable_hosts)``
    so a single down/failing node degrades to a partial result instead of
    failing the whole listing.
    """
    if host is not None:
        data = host_exec.incus_json(host, ["list"])
        return [Instance.from_incus(host, d) for d in data], []

    registry = load_registry()
    instances: list[Instance] = []
    unreachable: list[str] = []
    for name in sorted(registry):
        try:
            data = host_exec.incus_json(name, ["list"], timeout=30)
        except (HostUnreachable, CoreError):
            unreachable.append(name)
            continue
        instances.extend(Instance.from_incus(name, d) for d in data)
    return instances, unreachable


def check_updates(host: str | None = None) -> UpdateStatus:
    """Available apt upgrades on ``host`` (read-only — uses the existing cache,
    never runs ``apt update``)."""
    res = host_exec.run_on(
        host, ["apt", "list", "--upgradable"], root=True, check=False, timeout=60
    )
    packages: list[str] = []
    security = 0
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Listing"):
            continue
        packages.append(line.split("/", 1)[0])
        if "-security" in line:
            security += 1
    target = host or get_settings().current_server or "?"
    return UpdateStatus(
        host=target, count=len(packages), packages=tuple(packages), security_count=security
    )


def reboot_required(host: str | None = None) -> bool:
    """Whether ``host`` is flagged as needing a reboot (``/var/run/reboot-required``)."""
    res = host_exec.run_on(
        host, ["test", "-f", "/var/run/reboot-required"], root=True, check=False, timeout=15
    )
    return res.returncode == 0


TRUSTED_DNS_CLIENTS_KEY = "/hetzman/config/trusted-dns-clients"

_DNS_PROBE = r"""
echo "ACTIVE=$(systemctl is-active dnsmasq 2>/dev/null)"
echo "LISTEN=$(ss -ulnH 'sport = :53' 2>/dev/null | awk '{print $4}' | sed -E 's/:53$//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | paste -sd,)"
echo "DHCP67=$(ss -ulnp 'sport = :67' 2>/dev/null | grep -c dnsmasq)"
echo "FWD=$(dig +short +time=2 +tries=1 @127.0.0.1 %(fwd)s 2>/dev/null | head -1)"
echo "REV=$(dig +short +time=2 +tries=1 -x %(vswitch)s @127.0.0.1 2>/dev/null | head -1)"
echo "FORWARDERS=$(grep -E '^server=' /etc/dnsmasq.conf 2>/dev/null | sed 's/server=//' | paste -sd,)"
echo "REVZONES=$(grep -E '^local=/.*in-addr\.arpa' /etc/dnsmasq.conf 2>/dev/null | sed -E 's#^local=/(.*)/#\1#' | paste -sd,)"
echo "DHCPRANGE=$(grep -E '^dhcp-range=' /etc/dnsmasq.conf 2>/dev/null | head -1 | sed 's/dhcp-range=//')"
"""


def _external_acl() -> tuple[str, ...]:
    """Trusted :53 source CIDRs (DESIRED state, from the render): the vSwitch plus
    any valid operator VPN CIDRs in etcd. Mirrors node-sync's fail-closed read."""
    from .. import render

    acl = list(render.TRUSTED_DNS_CLIENTS)
    try:
        raw = get_all_with_prefix(TRUSTED_DNS_CLIENTS_KEY).get(TRUSTED_DNS_CLIENTS_KEY)
        cidrs = raw if isinstance(raw, list) else (raw.get("cidrs") if isinstance(raw, dict) else [])
        for cidr in cidrs or []:
            if render.dns_acl_source_ok(str(cidr)) and cidr not in acl:
                acl.append(str(cidr))
    except Exception:  # noqa: BLE001 — a status read must never raise on a bad doc
        pass
    return tuple(acl)


def get_dns_server_status(host: str | None = None) -> DnsServerStatus:
    """Live serving state of one node's managed dnsmasq (DNS + DHCP).

    One batched probe per node (systemctl/ss/dig + a read of dnsmasq.conf) so the
    fleet view never fans out into ~6 sequential SSH round-trips per host.
    """
    from ..render import DOMAIN

    registry = load_registry()
    target = host or get_settings().current_server
    node = registry.get(target, {})
    vswitch = node.get("vswitch_ip", "127.0.0.1")
    fwd_name = f"{target}.{DOMAIN}" if target else "localhost"
    script = _DNS_PROBE % {"fwd": fwd_name, "vswitch": vswitch}
    res = host_exec.run_on(host, ["bash", "-c", script], root=True, check=False, timeout=30)

    fields: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            fields[key] = val.strip()

    def _csv(key: str) -> tuple[str, ...]:
        return tuple(p for p in fields.get(key, "").split(",") if p)

    return DnsServerStatus(
        host=target or "?",
        active=fields.get("ACTIVE") == "active",
        listen_addrs=_csv("LISTEN"),
        forwarders=_csv("FORWARDERS"),
        reverse_zones=_csv("REVZONES"),
        dhcp_range=fields.get("DHCPRANGE") or None,
        forward_ok=bool(fields.get("FWD")),
        reverse_ok=bool(target and target in fields.get("REV", "")),
        dhcp_listener=fields.get("DHCP67", "0") not in ("0", ""),
        external_acl=_external_acl(),
    )
