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
