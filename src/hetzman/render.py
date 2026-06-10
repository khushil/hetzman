"""Pure renderers for node-local config, driven by the etcd node registry.

Everything here is side-effect free and unit-testable: functions take
registry entries and return text/rule lists. ``node-sync`` diffs the output
against disk and applies. Two hard safety properties live here:

* ``render_iptables_base`` raises ``RenderError`` unless the produced
  ruleset provably contains the SSH, loopback, established and ICMP accepts
  plus an etcd accept for every registry node — ``iptables-restore --test``
  only validates *syntax*, so a semantically-lockout base must be impossible
  to render.
* ``iptables_cleanup_plan`` uses DENY-LIST semantics: it only ever proposes
  deleting explicitly known-cruft patterns. Anything unrecognized is
  reported, never deleted — on dc3, docker's egress NAT consists of plain
  POSTROUTING MASQUERADE rules (not DOCKER-chain jumps) and deleting
  "unrecognized" rules would destroy Kubernetes networking.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

import yaml

DOMAIN = "daemondreams.home.arpa"
VSWITCH_SUBNET = "10.0.0.0/24"
CONTAINER_SUPERNET = "10.100.0.0/16"
INCUS_BRIDGE = "incusbr0"
ROUTE_METRIC = 100

MANAGED_HEADER = "# Managed by hetzman node-sync - do not edit by hand\n"


class RenderError(Exception):
    """A renderer produced provably unsafe output."""


# --------------------------------------------------------------------------
# dnsmasq

def render_dnsmasq_include(nodes: Dict[str, dict]) -> str:
    lines = [MANAGED_HEADER]
    for name in sorted(nodes):
        lines.append(f"host-record={name}.{DOMAIN},{nodes[name]['vswitch_ip']}\n")
    return "".join(lines)


def dnsmasq_conf_lines_to_remove(conf_text: str, nodes: Dict[str, dict]) -> List[str]:
    """host-record lines in dnsmasq.conf superseded by the managed include."""
    hostnames = {f"{name}.{DOMAIN}" for name in nodes}
    doomed = []
    for line in conf_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("host-record="):
            record = stripped[len("host-record="):].split(",")[0]
            if record in hostnames:
                doomed.append(line)
    return doomed


# --------------------------------------------------------------------------
# netplan

def render_netplan_vswitch(self_node: dict, nodes: Dict[str, dict]) -> str:
    routes = [
        {
            "to": node["bridge_subnet"],
            "via": node["vswitch_ip"],
            "metric": ROUTE_METRIC,
        }
        for node in nodes.values()
        if node["name"] != self_node["name"]
    ]
    routes.sort(key=lambda r: r["to"])
    doc = {
        "network": {
            "version": 2,
            "vlans": {
                self_node["vlan_interface"]: {
                    "id": self_node["vlan_id"],
                    "link": self_node["primary_interface"],
                    "addresses": [f"{self_node['vswitch_ip']}/24"],
                    "mtu": self_node["mtu"],
                    "routes": routes,
                },
            },
        },
    }
    return yaml.safe_dump(doc, default_flow_style=False, sort_keys=False)


def _normalize_netplan(doc):
    """Sort route lists so list-order alone never reads as drift."""
    if isinstance(doc, dict):
        return {
            key: (
                sorted(value, key=lambda r: str(r.get("to", "")))
                if key == "routes" and isinstance(value, list)
                else _normalize_netplan(value)
            )
            for key, value in doc.items()
        }
    return doc


def netplan_semantically_equal(text_a: str, text_b: str) -> bool:
    """Formatting/order-insensitive comparison so a reformat never triggers
    a needless fleet-wide ``netplan apply``."""
    try:
        return _normalize_netplan(yaml.safe_load(text_a)) == _normalize_netplan(
            yaml.safe_load(text_b)
        )
    except yaml.YAMLError:
        return False


# --------------------------------------------------------------------------
# iptables

def _etcd_accepts(nodes: Dict[str, dict]) -> List[str]:
    return [
        f"-A INPUT -s {nodes[name]['vswitch_ip']}/32 -p tcp -m tcp --dport 2379:2380 -j ACCEPT"
        for name in sorted(nodes)
    ]


def render_iptables_base(self_node: dict, nodes: Dict[str, dict]) -> str:
    subnet = self_node["bridge_subnet"]
    accepts = _etcd_accepts(nodes)
    text = "\n".join(
        [
            "# Managed by hetzman node-sync (canonical base; per-instance NAT is",
            "# rebuilt from etcd by sync-apply at boot - do not edit by hand)",
            "*mangle",
            ":PREROUTING ACCEPT [0:0]",
            ":INPUT ACCEPT [0:0]",
            ":FORWARD ACCEPT [0:0]",
            ":OUTPUT ACCEPT [0:0]",
            ":POSTROUTING ACCEPT [0:0]",
            "-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
            "COMMIT",
            "*filter",
            ":INPUT DROP [0:0]",
            ":FORWARD ACCEPT [0:0]",
            ":OUTPUT ACCEPT [0:0]",
            f"-A INPUT -i {INCUS_BRIDGE} -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -i lo -j ACCEPT",
            "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
            f"-A INPUT -s {VSWITCH_SUBNET} -p tcp -m tcp --dport 8443 -j ACCEPT",
            *accepts,
            "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            f"-A FORWARD -s {subnet} -j ACCEPT",
            f"-A FORWARD -d {subnet} -j ACCEPT",
            "COMMIT",
            "*nat",
            ":PREROUTING ACCEPT [0:0]",
            ":INPUT ACCEPT [0:0]",
            ":OUTPUT ACCEPT [0:0]",
            ":POSTROUTING ACCEPT [0:0]",
            ":HETZMAN_NAT - [0:0]",
            ":HETZMAN_NAT_POST - [0:0]",
            "-A PREROUTING -j HETZMAN_NAT",
            "-A POSTROUTING -j HETZMAN_NAT_POST",
            f"-A HETZMAN_NAT_POST -s {CONTAINER_SUPERNET} -d {CONTAINER_SUPERNET} -j MASQUERADE",
            "COMMIT",
            "",
        ]
    )

    required = [
        "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
        "-A INPUT -i lo -j ACCEPT",
        "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT",
        *accepts,
    ]
    for snippet in required:
        if snippet not in text:
            raise RenderError(f"unsafe iptables base: missing {snippet!r}")
    if not nodes:
        raise RenderError("unsafe iptables base: empty registry")
    return text


def render_iptables_base_v6() -> str:
    return "\n".join(
        [
            "# Managed by hetzman node-sync",
            "*filter",
            ":INPUT ACCEPT [0:0]",
            ":FORWARD ACCEPT [0:0]",
            ":OUTPUT ACCEPT [0:0]",
            "COMMIT",
            "",
        ]
    )


def base_policies() -> List[Tuple[str, str, str]]:
    return [
        ("filter", "INPUT", "DROP"),
        ("filter", "FORWARD", "ACCEPT"),
        ("filter", "OUTPUT", "ACCEPT"),
    ]


def base_ensure_rules(self_node: dict, nodes: Dict[str, dict]) -> List[Tuple[str, str, List[str]]]:
    """(table, chain, args) tuples to ensure live, via ``iptables -C || -A``."""
    subnet = self_node["bridge_subnet"]
    rules: List[Tuple[str, str, List[str]]] = [
        ("mangle", "FORWARD", ["-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                               "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
        ("filter", "INPUT", ["-i", INCUS_BRIDGE, "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-i", "lo", "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-s", VSWITCH_SUBNET, "-p", "tcp", "-m", "tcp",
                             "--dport", "8443", "-j", "ACCEPT"]),
    ]
    for name in sorted(nodes):
        rules.append(("filter", "INPUT", ["-s", f"{nodes[name]['vswitch_ip']}/32", "-p", "tcp",
                                          "-m", "tcp", "--dport", "2379:2380", "-j", "ACCEPT"]))
    rules += [
        ("filter", "INPUT", ["-p", "icmp", "-m", "icmp", "--icmp-type", "8", "-j", "ACCEPT"]),
        ("filter", "FORWARD", ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
        ("filter", "FORWARD", ["-s", subnet, "-j", "ACCEPT"]),
        ("filter", "FORWARD", ["-d", subnet, "-j", "ACCEPT"]),
        ("nat", "PREROUTING", ["-j", "HETZMAN_NAT"]),
        ("nat", "POSTROUTING", ["-j", "HETZMAN_NAT_POST"]),
        ("nat", "HETZMAN_NAT_POST", ["-s", CONTAINER_SUPERNET, "-d", CONTAINER_SUPERNET,
                                     "-j", "MASQUERADE"]),
    ]
    return rules


_RE_ETCD_ACCEPT = re.compile(
    r"^-A INPUT -s (\d+\.\d+\.\d+\.\d+)/32 -p tcp -m tcp --dport 2379:2380 -j ACCEPT$"
)
_RE_NAT_LOG = re.compile(
    r'^-A (?:PREROUTING|POSTROUTING) -s [\d./]+ -j LOG --log-prefix "NAT-(?:PRE|POST): "\s*$'
)
_RE_BLANKET_MASQ = re.compile(
    r"^-A POSTROUTING -s 10\.100\.\d+\.0/24 ! -d 10\.0\.0\.0/8 -j MASQUERADE$"
)
_RE_DOCKER_ISH = re.compile(r"DOCKER|docker0|br-[0-9a-f]+|-s 172\.1[6-9]\.|-s 172\.2\d\.|-s 172\.3[01]\.")


def iptables_cleanup_plan(
    live_save_text: str, nodes: Dict[str, dict]
) -> Tuple[List[Tuple[str, List[str]]], List[str]]:
    """Deny-list cleanup: (deletions, warnings).

    Deletions are (table, args-without-"-A") suitable for ``iptables -t T -D``.
    Only three explicitly known-cruft patterns are ever deleted; everything
    else unrecognized in the nat top-level chains is warned about only.
    """
    registry_ips = {n["vswitch_ip"] for n in nodes.values()}
    deletions: List[Tuple[str, List[str]]] = []
    warnings: List[str] = []
    table = ""

    for line in live_save_text.splitlines():
        line = line.rstrip()
        if line.startswith("*"):
            table = line[1:]
            continue
        if not line.startswith("-A"):
            continue
        if "--dport 22" in line:  # absolute no-touch
            continue

        if table == "filter":
            match = _RE_ETCD_ACCEPT.match(line)
            if match and match.group(1) not in registry_ips:
                deletions.append((table, line[3:].split(" ")))
            continue

        if table == "nat" and (line.startswith("-A PREROUTING") or line.startswith("-A POSTROUTING")):
            if _RE_NAT_LOG.match(line):
                deletions.append((table, _split_save_rule(line[3:])))
                continue
            if _RE_BLANKET_MASQ.match(line):
                deletions.append((table, line[3:].split(" ")))
                continue
            if line in ("-A PREROUTING -j HETZMAN_NAT", "-A POSTROUTING -j HETZMAN_NAT_POST"):
                continue
            if _RE_DOCKER_ISH.search(line):
                continue  # docker-owned; docker manages its own lifecycle
            warnings.append(f"unrecognized {table} rule (left untouched): {line}")

    return deletions, warnings


def _split_save_rule(rule: str) -> List[str]:
    """Split an iptables-save rule into argv, respecting quoted strings."""
    args: List[str] = []
    current = ""
    in_quotes = False
    for ch in rule:
        if ch == '"':
            in_quotes = not in_quotes
            continue
        if ch == " " and not in_quotes:
            if current:
                args.append(current)
                current = ""
            continue
        current += ch
    if current:
        args.append(current)
    return args
