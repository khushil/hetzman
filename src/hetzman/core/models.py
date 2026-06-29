"""Read-side frozen dataclass models for the hetzman core layer.

Each model is a pure value object constructed from etcd data.  No console,
no Rich, no other hetzman modules are imported here.

etcd key prefixes referenced by each model are noted in the class docstring.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# IP pool / NAT
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IPAllocation:
    """A single public-IP entry.

    etcd key: ``/hetzman/ip-pool/{ip}``
    """

    ip: str
    server: str
    status: str
    assigned_to: str | None
    block: str | None

    @classmethod
    def from_etcd(cls, key: str, data: dict[str, Any]) -> "IPAllocation":
        ip = key.rsplit("/", 1)[-1]
        return cls(
            ip=ip,
            server=data.get("server", ""),
            status=data.get("status", "unknown"),
            assigned_to=data.get("assigned_to"),
            block=data.get("block"),
        )


@dataclass(frozen=True)
class NatRule:
    """NAT mapping for one instance.

    etcd key: ``/hetzman/nat/{server}/{instance}``

    Fields match the payload written by ``ip_assign``:
    ``public_ip``, ``private_ip``, ``instance_name``, ``enabled``.
    """

    instance: str
    public_ip: str
    private_ip: str
    enabled: bool

    @classmethod
    def from_etcd(cls, key: str, data: dict[str, Any]) -> "NatRule":
        # key ends with /{server}/{instance}
        instance = key.rsplit("/", 1)[-1]
        return cls(
            instance=data.get("instance_name", instance),
            public_ip=data.get("public_ip", ""),
            private_ip=data.get("private_ip", ""),
            enabled=bool(data.get("enabled", True)),
        )


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DNSRecord:
    """A DNS A-record managed by hetzman.

    etcd key: ``/hetzman/dns/{hostname}``
    """

    hostname: str
    ip: str
    server: str
    instance: str | None
    type: str | None
    auto: bool
    updated: str | None

    @classmethod
    def from_etcd(cls, key: str, data: dict[str, Any]) -> "DNSRecord":
        hostname = key[len("/hetzman/dns/"):]
        return cls(
            hostname=hostname,
            ip=data.get("ip", ""),
            server=data.get("server", ""),
            instance=data.get("instance"),
            type=data.get("type"),
            auto=bool(data.get("auto", False)),
            updated=data.get("updated"),
        )


# ---------------------------------------------------------------------------
# Port forwards
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortForward:
    """A DNAT port-forward rule.

    etcd key: ``/hetzman/port-forward/{server}/{instance}-{port}-{proto}``

    Field names match the payload written by ``port_add``:
    ``public_ip``, ``public_port``, ``private_ip``, ``private_port``,
    ``protocol``, ``instance_name``, ``description``, ``enabled``.
    """

    public_ip: str
    public_port: int
    private_ip: str
    private_port: int
    protocol: str
    instance: str
    description: str | None
    enabled: bool

    @classmethod
    def from_etcd(cls, key: str, data: dict[str, Any]) -> "PortForward":
        return cls(
            public_ip=data.get("public_ip", ""),
            public_port=int(data.get("public_port", 0)),
            private_ip=data.get("private_ip", ""),
            private_port=int(data.get("private_port", 0)),
            protocol=data.get("protocol", "tcp"),
            instance=data.get("instance_name", ""),
            description=data.get("description"),
            enabled=bool(data.get("enabled", True)),
        )


# ---------------------------------------------------------------------------
# Node registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodeInfo:
    """Fleet node registry entry.

    etcd key: ``/hetzman/nodes/{name}``

    Fields sourced from the entry written by ``node_register``.
    The ``raw`` dict holds the full payload for fields not promoted here
    (``primary_interface``, ``vlan_interface``, ``vlan_id``, ``mtu``, …).
    """

    name: str
    vswitch_ip: str
    bridge_ip: str
    bridge_subnet: str
    public_block: str
    etcd_name: str
    updated_at: str | None
    raw: dict  # full etcd payload; required, not defaulted

    @classmethod
    def from_etcd(cls, key: str, data: dict[str, Any]) -> "NodeInfo":
        name = key.rsplit("/", 1)[-1]
        return cls(
            name=data.get("name", name),
            vswitch_ip=data.get("vswitch_ip", ""),
            bridge_ip=data.get("bridge_ip", ""),
            bridge_subnet=data.get("bridge_subnet", ""),
            public_block=data.get("public_block", ""),
            etcd_name=data.get("etcd_name", ""),
            updated_at=data.get("updated_at"),
            raw=dict(data),
        )


# ---------------------------------------------------------------------------
# Fleet / health
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FleetNodeStatus:
    """Per-node status derived from ``/hetzman/health/{node}`` heartbeats.

    Fields contain plain text only — no Rich markup; rendering is the
    caller's responsibility.

    etcd key: ``/hetzman/health/{node}`` (300 s lease; absence == down)

    Source fields from the payload written by ``health_report``:
    ``ts``, ``hetzman_version``, ``incus_version``, ``checks``,
    ``endpoints_configured``, ``node_sync``.
    """

    name: str
    heartbeat_age_s: int | None
    alive: bool
    checks_bad: tuple[str, ...]
    peers_bad: tuple[str, ...]
    hetzman_version: str
    incus_version: str
    sync_result: str
    disk_root_pct: int | None
    pool_pct: int | None
    endpoint_count_ok: bool
    etcd_member_present: bool
    # Raw endpoint count from the heartbeat (``endpoints_configured``); kept so
    # the CLI can faithfully render the ``(endpoints=X!=Y)`` annotation where
    # X is this value and Y is ``FleetStatus.registered_node_count``.  ``None``
    # when the node has no heartbeat or the field is absent.
    endpoints_configured: int | None = None


@dataclass(frozen=True)
class FleetStatus:
    """Aggregate fleet health view.

    Composed from :class:`FleetNodeStatus` objects and the live etcd member
    list; not stored directly in etcd.
    """

    nodes: tuple[FleetNodeStatus, ...]
    degraded: bool
    member_names: frozenset[str]
    # Number of nodes in the registry (``len(load_registry())``).  Distinct
    # from ``len(nodes)`` because ``nodes`` is the union of registered nodes
    # and nodes that have a heartbeat but no registry entry.  This is the ``Y``
    # in the CLI's ``(endpoints=X!=Y)`` annotation and the title's
    # "(N registered nodes)".
    registered_node_count: int = 0


# ---------------------------------------------------------------------------
# Audit / system
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditResult:
    """Outcome of comparing desired IP state (etcd) with the host interface.

    Mirrors the return value of ``compute_audit()`` in ``system.py``.
    ``missing`` and ``correct`` are ``{ip: instance_name}`` dicts;
    ``orphaned`` is a tuple of IPs present on the interface but not in etcd.
    """

    missing: dict  # {ip: instance_name} — required, not defaulted
    orphaned: tuple[str, ...]
    correct: dict  # {ip: instance_name} — required, not defaulted

    @property
    def clean(self) -> bool:
        """True when there are no missing and no orphaned IPs."""
        return not self.missing and not self.orphaned


@dataclass(frozen=True)
class SystemStatus:
    """Snapshot of key system counters shown by the ``status`` command.

    Composed from several etcd prefixes on a single node:
    ``/hetzman/dns/``, ``/hetzman/ip-pool/``,
    ``/hetzman/nat/{server}/``, ``/hetzman/port-forward/{server}/``,
    and the etcd member list.
    """

    server: str
    dns_total: int
    dns_mine: int
    dns_types: dict  # {type_name: count} — required, not defaulted
    ips_available: int
    ips_total: int
    active_nat: int
    active_ports: int
    etcd_members: int | None


# ---------------------------------------------------------------------------
# Node-sync drift
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftStatus:
    """Drift report produced by ``node-sync --check``.

    ``pending`` holds the names of config artefacts that are out of date
    (e.g. ``"config.ini"``, ``"dnsmasq-include"``).  ``warnings`` and
    ``errors`` carry diagnostic text from the sync run.

    Source: ``_node_sync_run()`` in ``commands/node.py``; not stored in
    etcd directly (persisted locally to ``/var/lib/hetzman/last-node-sync.json``).
    """

    clean: bool
    pending: tuple[str, ...]
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


# ---------------------------------------------------------------------------
# Instances (VMs + containers) — live host state, not etcd
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Instance:
    """An Incus VM or container on a fleet host.

    Source: ``incus list --format json`` on ``host`` (incus is standalone per
    host, so each node is queried separately). ``disk`` is the root device size
    and may be ``None`` (some containers carry no explicit root-size quota).
    """

    name: str
    host: str
    type: str           # "virtual-machine" | "container"
    status: str         # "Running" | "Stopped" | ...
    cpus: int | None
    memory: str | None  # e.g. "32GB"
    disk: str | None    # root device size, e.g. "250GB"; None if unset
    private_ip: str | None

    @staticmethod
    def _private_ip(data: dict) -> str | None:
        net = (data.get("state") or {}).get("network") or {}
        for iface in ("eth0", "enp5s0"):
            for addr in (net.get(iface) or {}).get("addresses", []) or []:
                if addr.get("family") == "inet" and not str(addr.get("address", "")).startswith("127."):
                    return addr.get("address")
        return None

    @staticmethod
    def _root_size(data: dict) -> str | None:
        # prefer the instance-local device, fall through to profile-expanded
        for key in ("devices", "expanded_devices"):
            size = ((data.get(key) or {}).get("root") or {}).get("size")
            if size:
                return size
        return None

    @classmethod
    def from_incus(cls, host: str, data: dict) -> "Instance":
        cfg = data.get("config") or {}
        ecfg = data.get("expanded_config") or {}
        raw_cpu = cfg.get("limits.cpu") or ecfg.get("limits.cpu")
        try:
            cpus = int(raw_cpu) if raw_cpu is not None else None
        except (TypeError, ValueError):
            cpus = None
        return cls(
            name=data.get("name", ""),
            host=host,
            type=data.get("type", ""),
            status=data.get("status", ""),
            cpus=cpus,
            memory=cfg.get("limits.memory") or ecfg.get("limits.memory"),
            disk=cls._root_size(data),
            private_ip=cls._private_ip(data),
        )


@dataclass(frozen=True)
class UpdateStatus:
    """Available apt updates on a host (read-only; from ``apt list --upgradable``)."""

    host: str
    count: int
    packages: tuple[str, ...]
    security_count: int


@dataclass(frozen=True)
class UserAccount:
    """A login account on a VM or host (uid>=1000 plus root).

    Source: a batched probe (getent/passwd -S/sudoers/authorized_keys). ``locked``
    means the account is suspended (password + login disabled); ``sudo`` reflects a
    hetzman-managed passwordless-sudo drop-in."""

    name: str
    uid: int | None
    sudo: bool
    locked: bool
    key_count: int
    home: str | None


@dataclass(frozen=True)
class DnsServerStatus:
    """Live serving state of a node's managed dnsmasq (DNS + DHCP).

    Source: a single batched probe on the host (systemctl/ss/dig + a read of the
    managed ``/etc/dnsmasq.conf``). ``external_acl`` is DERIVED from the desired
    iptables render (the trusted :53 source CIDRs), not from the live host.
    """

    host: str
    active: bool
    listen_addrs: tuple[str, ...]   # e.g. ("127.0.0.1", "10.100.4.1", "10.0.0.4")
    forwarders: tuple[str, ...]     # upstream servers, e.g. ("1.1.1.1", "8.8.8.8")
    reverse_zones: tuple[str, ...]  # authoritative in-addr.arpa zones served
    dhcp_range: str | None          # e.g. "10.100.4.10,10.100.4.250,..."; None if no DHCP
    forward_ok: bool                # self-test: a known forward name resolves
    reverse_ok: bool                # self-test: this node's vswitch IP reverse-resolves
    dhcp_listener: bool             # a dnsmasq :67 listener is present
    external_acl: tuple[str, ...]   # trusted :53 source CIDRs (vSwitch + opt VPN)
