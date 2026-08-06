"""Fleet node registry stored in etcd under /hetzman/nodes/.

The registry is the source of truth for fleet topology. ``node-sync``
renders per-node config (dnsmasq host-records, vswitch routes, firewall
accepts, config.ini endpoints) from it, so every mutation MUST go through
the validating CLI commands — never raw etcdctl puts.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List

from .etcd_kv import get_all_with_prefix
# render.py is stdlib+yaml only (no console, no etcd), so importing its
# addressing constants here is safe and keeps a single source of truth.
from .render import CONTAINER_SUPERNET, VSWITCH_SUBNET

NODES_PREFIX = "/hetzman/nodes/"
SCHEMA_VERSION = 1

REQUIRED_FIELDS = (
    "schema",
    "name",
    "vswitch_ip",
    "bridge_ip",
    "bridge_subnet",
    "public_block",
    "primary_interface",
    "vlan_interface",
    "vlan_id",
    "mtu",
    "etcd_name",
)


def load_registry() -> Dict[str, dict]:
    """Return {node_name: entry} for every registry entry."""
    raw = get_all_with_prefix(NODES_PREFIX)
    nodes: Dict[str, dict] = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            nodes[key[len(NODES_PREFIX):]] = value
    return nodes


def validate_registry(nodes: Dict[str, dict]) -> List[str]:
    """Structural validation. Returns a list of human-readable errors."""
    errors: List[str] = []
    if not nodes:
        return ["registry is empty"]

    seen: Dict[str, Dict[Any, str]] = {
        "vswitch_ip": {}, "bridge_ip": {}, "public_block": {},
    }
    subnets: Dict[ipaddress.IPv4Network, str] = {}

    for name, node in nodes.items():
        for field in REQUIRED_FIELDS:
            if field not in node or node[field] in (None, ""):
                errors.append(f"{name}: missing field {field!r}")
        if errors and any(e.startswith(f"{name}:") for e in errors):
            continue

        if node["schema"] != SCHEMA_VERSION:
            errors.append(f"{name}: unsupported schema {node['schema']!r}")
        if node["name"] != name:
            errors.append(f"{name}: name field {node['name']!r} != key")

        try:
            vswitch = ipaddress.ip_address(node["vswitch_ip"])
            bridge = ipaddress.ip_address(node["bridge_ip"])
            subnet = ipaddress.ip_network(node["bridge_subnet"], strict=True)
            ipaddress.ip_network(node["public_block"], strict=True)
        except ValueError as e:
            errors.append(f"{name}: bad address/network: {e}")
            continue

        if bridge not in subnet:
            errors.append(f"{name}: bridge_ip {bridge} not in {subnet}")

        # The addressing plan is load-bearing, not a convention: the NAT
        # masquerade rules and the authoritative reverse zone are rendered
        # against the whole supernet (render.py:CONTAINER_SUPERNET,
        # DNS_REVERSE_ZONES), and the vSwitch accepts against VSWITCH_SUBNET.
        # A node addressed outside them registers and validates happily, then
        # silently gets no outbound NAT and no reverse DNS — so reject it here.
        supernet = ipaddress.ip_network(CONTAINER_SUPERNET)
        if not subnet.subnet_of(supernet):
            errors.append(
                f"{name}: bridge_subnet {subnet} is outside {supernet} — it would "
                "get no NAT and no reverse DNS"
            )
        vswitch_net = ipaddress.ip_network(VSWITCH_SUBNET)
        if vswitch not in vswitch_net:
            errors.append(f"{name}: vswitch_ip {vswitch} is outside {vswitch_net}")
        if not isinstance(node["vlan_id"], int) or not isinstance(node["mtu"], int):
            errors.append(f"{name}: vlan_id/mtu must be integers")

        for field in ("vswitch_ip", "bridge_ip", "public_block"):
            value = node[field]
            if value in seen[field]:
                errors.append(
                    f"{name}: duplicate {field} {value} (also {seen[field][value]})"
                )
            seen[field][value] = name

        for other_subnet, other_name in subnets.items():
            if subnet.overlaps(other_subnet):
                errors.append(
                    f"{name}: bridge_subnet {subnet} overlaps {other_subnet} ({other_name})"
                )
        subnets[subnet] = name

    return errors


def registry_guard(nodes: Dict[str, dict], current_server: str) -> List[str]:
    """Cross-check the registry against live etcd membership.

    A 1:1 match is required: every registry node's vswitch_ip must appear as
    exactly one member's peer-URL host with the matching member name, and
    vice versa. Counting alone is NOT enough — a typo'd-but-valid entry must
    fail here rather than propagate wrong routes/accepts fleet-wide. While
    the guard fails (e.g. mid node-add/remove) node-sync is intentionally
    inert on every node: fail-closed.
    """
    errors: List[str] = []
    if current_server not in nodes:
        errors.append(f"this node ({current_server}) is not in the registry")

    from .config import get_etcd_client

    try:
        members = list(get_etcd_client().members)
    except Exception as e:
        return errors + [f"cannot list etcd members: {e}"]

    member_by_ip: Dict[str, str] = {}
    for member in members:
        for url in member.peer_urls:
            host = url.split("//", 1)[-1].rsplit(":", 1)[0]
            member_by_ip[host] = member.name

    registry_ips = {n["vswitch_ip"]: name for name, n in nodes.items()}

    for ip, name in registry_ips.items():
        if ip not in member_by_ip:
            errors.append(f"registry node {name} ({ip}) has no etcd member")
        elif member_by_ip[ip] != nodes[name].get("etcd_name"):
            errors.append(
                f"{name}: etcd_name {nodes[name].get('etcd_name')!r} != "
                f"member name {member_by_ip[ip]!r} at {ip}"
            )

    for ip, member_name in member_by_ip.items():
        if ip not in registry_ips:
            errors.append(f"etcd member {member_name} ({ip}) is not in the registry")

    return errors
