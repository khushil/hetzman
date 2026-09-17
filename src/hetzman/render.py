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

import ipaddress
import re
from typing import Dict, List, Optional, Sequence, Tuple

import yaml

DOMAIN = "daemondreams.home.arpa"
VSWITCH_SUBNET = "10.0.0.0/24"
CONTAINER_SUPERNET = "10.100.0.0/16"
INCUS_BRIDGE = "incusbr0"
# Fleet PostgreSQL. Rendered on every node (like 8443) rather than only the node
# that happens to run it: the base is identical fleet-wide, and the rule is inert
# where nothing listens. postgresql's own pg_hba.conf already admits the vSwitch
# (hostssl all all 10.0.0.0/24 scram-sha-256) — without this the firewall
# contradicted it, so only containers could reach the DB and hosts could not.
POSTGRES_PORT = "5432"
ROUTE_METRIC = 100
# The custom nat-table chains the base ruleset jumps into. They must EXIST
# before those jumps can be added, which is not true on a freshly provisioned
# node — see commands/node.py:_ensure_nat_chains. Kept in step with the rendered
# ruleset by test_node_iptables.py.
NAT_CUSTOM_CHAINS: Tuple[str, ...] = ("HETZMAN_NAT", "HETZMAN_NAT_POST")
# Operator-opened host ports live in their OWN filter chain, not appended to
# INPUT. The live-ensure path (iptables -C || -A) can only ADD rules, so a port
# removed from etcd would stay open until the next reboot while node-sync
# happily reported "clean". An owned chain is flushed and rebuilt from etcd on
# every apply, which makes removal correct by construction and the rule order
# deterministic. Mirrors network.py:apply_nat_rules, the same pattern for NAT.
HOSTPORTS_CHAIN = "HETZMAN_HOSTPORTS"
FILTER_CUSTOM_CHAINS: Tuple[str, ...] = (HOSTPORTS_CHAIN,)
# Ports an operator may NOT open through this mechanism. Two kinds: ports the
# renderer already manages (opening them again is a second source of truth that
# will drift), and ports whose service must never face the public internet even
# by accident (OpenBao). Derived from the constants above so this cannot rot
# independently of the rules it guards.
OPENBAO_PORTS: Tuple[str, ...] = ("8200", "8201")

MANAGED_HEADER = "# Managed by hetzman node-sync - do not edit by hand\n"

# --- managed dnsmasq.conf knobs (pinned to the live, captured config) --------
# DNS_ADDN_HOSTS must equal config.ADDITIONAL_HOSTS (asserted in test_render);
# kept as a literal here so render.py stays free of the etcd-importing config.
DNS_ADDN_HOSTS = "/opt/hetzman-tooling/configs/additional-hosts"
DNS_LEASEFILE = "/var/lib/misc/dnsmasq.leases"
DNS_LOG_FACILITY = "/var/log/hetzman-tooling/dnsmasq.log"
DNS_FORWARDERS: Tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
DNS_FORWARD_MAX = 150
DNS_CACHE_SIZE = 1000
# Authoritative reverse zones (answered locally, NEVER forwarded upstream).
# Safe to make the whole 10.100.0.0/16 authoritative on every node because the
# hetzman addn-hosts file carries EVERY fleet instance on EVERY node (global),
# so cross-node instance PTRs resolve; unknown private reverse -> local NXDOMAIN.
#   0.0.10.in-addr.arpa   == 10.0.0.0/24   (vSwitch)
#   100.10.in-addr.arpa   == 10.100.0.0/16 (all per-node bridges)
DNS_REVERSE_ZONES: Tuple[str, ...] = ("0.0.10.in-addr.arpa", "100.10.in-addr.arpa")

# Trusted source ranges allowed to reach :53 (default: the vSwitch only). An
# operator may add a VPN CIDR via /hetzman/config/trusted-dns-clients; node-sync
# validates + passes it in. NEVER public — enforced by _assert_dns_acl_safe.
TRUSTED_DNS_CLIENTS: Tuple[str, ...] = (VSWITCH_SUBNET,)
_RFC1918 = tuple(
    ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def dns_acl_source_ok(cidr: str) -> bool:
    """True iff ``cidr`` is a private (RFC1918) subnet narrow enough to be a
    safe :53 ACL source: rejects public ranges, ``0.0.0.0/0`` and anything
    broader than /16 (e.g. a 10.0.0.0/8 blanket)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if net.version != 4 or net.prefixlen < 16:
        return False
    return any(net.subnet_of(s) for s in _RFC1918)


def reserved_host_ports() -> frozenset:
    """Ports an operator may not open via the host-port mechanism.

    Derived from the constants the renderer already emits rules for, plus
    OpenBao. Never hardcode a second copy of this list: a literal would drift
    the moment a new managed rule is added, and the failure mode is silent.
    """
    return frozenset(
        {"22", "53", "2379", "2380", "8443", POSTGRES_PORT} | set(OPENBAO_PORTS)
    )


def host_port_ok(entry: dict) -> bool:
    """True iff ``entry`` is a well-formed host-port record.

    Deliberately NOT modelled on :func:`dns_acl_source_ok`. That predicate
    demands a private, narrow CIDR because a public resolver is a hazard. A
    host port's whole purpose may be to face the internet, so ``0.0.0.0/0`` is
    VALID here. This checks shape only; policy (reserved ports) is enforced at
    CLI write time, where an operator can see the error.
    """
    if not isinstance(entry, dict):
        return False
    try:
        port = int(entry["port"])
    except (KeyError, TypeError, ValueError):
        return False
    if not 1 <= port <= 65535:
        return False
    if entry.get("protocol", "tcp") not in ("tcp", "udp"):
        return False
    try:
        ipaddress.ip_network(str(entry.get("source", "0.0.0.0/0")), strict=False)
    except ValueError:
        return False
    return True


def _host_port_argv(entry: dict) -> List[str]:
    """Canonical argv for one host-port ACCEPT, without the chain name.

    ``0.0.0.0/0`` is emitted as NO ``-s`` at all, because that is how
    ``iptables-save`` renders a match-anything source. Emitting it literally
    would differ from what the kernel reports and drift forever.
    """
    proto = entry.get("protocol", "tcp")
    source = str(entry.get("source", "0.0.0.0/0"))
    args: List[str] = []
    if ipaddress.ip_network(source, strict=False).prefixlen != 0:
        args += ["-s", source]
    args += ["-p", proto, "-m", proto, "--dport", str(int(entry["port"])), "-j", "ACCEPT"]
    return args


def _host_port_accepts(host_ports: Sequence[dict]) -> List[str]:
    """Rendered ``-A HETZMAN_HOSTPORTS ...`` lines, deduplicated, stable order."""
    seen = set()
    lines: List[str] = []
    for entry in host_ports:
        argv = tuple(_host_port_argv(entry))
        if argv in seen:
            continue
        seen.add(argv)
        lines.append(f"-A {HOSTPORTS_CHAIN} " + " ".join(argv))
    return lines


def _assert_host_ports_safe(host_ports: Sequence[dict]) -> None:
    """Unreachable backstop for a programming error.

    Operator data is filtered and logged upstream in
    ``commands/node.py:_host_ports`` - malformed etcd content must degrade to
    an empty list, never abort node-sync. If a malformed entry reaches here it
    means the filter was bypassed in code, which is a bug worth failing on.
    """
    for entry in host_ports:
        if not host_port_ok(entry):
            raise RenderError(f"malformed host-port entry reached renderer: {entry!r}")


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
    """host-record lines in dnsmasq.conf superseded by the managed include.

    Superseded once the conf is fully hetzman-managed: ``render_dnsmasq_conf``
    never emits node host-record lines (they live only in the include), so
    node-sync short-circuits this legacy migration for a managed conf.
    """
    hostnames = {f"{name}.{DOMAIN}" for name in nodes}
    doomed = []
    for line in conf_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("host-record="):
            record = stripped[len("host-record="):].split(",")[0]
            if record in hostnames:
                doomed.append(line)
    return doomed


def render_dnsmasq_conf(self_node: dict, *, vlan_listen: bool) -> str:
    """The full managed ``/etc/dnsmasq.conf`` for one node (DNS **and** DHCP).

    Reproduces the captured hand-rolled config exactly, plus three deliberate
    hardenings: (1) explicit interface scoping that never binds the public
    interface (``except-interface`` + named ifaces only); (2) DHCP confined to
    the bridge (``no-dhcp-interface`` on lo and the vSwitch) so it can't hand
    bridge-pool leases to vSwitch hosts; (3) authoritative reverse zones. When
    ``vlan_listen`` is True the vSwitch iface is added for trusted external
    clients — node-sync passes True only after a live address-up probe so the
    candidate can always bind (a down vSwitch iface would otherwise fail the
    restart that ``dnsmasq --test`` cannot catch).
    """
    bridge_ip = self_node["bridge_ip"]
    vlan_iface = self_node["vlan_interface"]
    primary_iface = self_node["primary_interface"]
    net = ipaddress.ip_network(self_node["bridge_subnet"])
    dhcp_start = net.network_address + 10
    dhcp_end = net.network_address + 250
    netmask = net.netmask

    lines: List[str] = [MANAGED_HEADER.rstrip("\n")]
    # --- listening: explicit ifaces; DHCP on the bridge only, never public ---
    lines += ["interface=lo", f"interface={INCUS_BRIDGE}"]
    if vlan_listen:
        lines.append(f"interface={vlan_iface}")
    lines += [f"except-interface={primary_iface}", "bind-dynamic", "no-dhcp-interface=lo"]
    if vlan_listen:
        lines.append(f"no-dhcp-interface={vlan_iface}")
    # --- forward zone + recursion (trusted clients only; see iptables ACL) ---
    lines += [
        f"domain={DOMAIN}",
        f"local=/{DOMAIN}/",
        "expand-hosts",
        "domain-needed",
        "bogus-priv",
        "no-negcache",
        "stop-dns-rebind",
        "rebind-localhost-ok",
        f"dns-forward-max={DNS_FORWARD_MAX}",
        "no-resolv",
    ]
    lines += [f"server={fwd}" for fwd in DNS_FORWARDERS]
    lines.append(f"cache-size={DNS_CACHE_SIZE}")
    # --- authoritative reverse zones (never forwarded upstream) ---
    lines += [f"local=/{zone}/" for zone in DNS_REVERSE_ZONES]
    # --- DHCP (bridge only) ---
    lines += [
        f"dhcp-range={dhcp_start},{dhcp_end},{netmask},12h",
        f"dhcp-option=option:router,{bridge_ip}",
        f"dhcp-option=option:dns-server,{bridge_ip}",
        f"dhcp-option=option:domain-name,{DOMAIN}",
        "dhcp-authoritative",
        "dhcp-rapid-commit",
        f"dhcp-leasefile={DNS_LEASEFILE}",
    ]
    # --- records + logging ---
    lines += [
        f"addn-hosts={DNS_ADDN_HOSTS}",
        f"log-facility={DNS_LOG_FACILITY}",
        "log-queries=extra",
        "log-dhcp",
    ]
    text = "\n".join(lines) + "\n"

    # Safety: the public interface must be excepted and never bound (a public
    # listener + recursion = an open resolver). dnsmasq --test cannot catch this.
    if f"\nexcept-interface={primary_iface}\n" not in text:
        raise RenderError("unsafe dnsmasq.conf: public interface not excepted")
    # line-anchored so 'except-interface=eth0' doesn't read as 'interface=eth0'
    if f"\ninterface={primary_iface}\n" in text:
        raise RenderError(f"unsafe dnsmasq.conf: binds public interface {primary_iface}")
    return text


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


def _dns_accepts(trusted: Sequence[str]) -> List[str]:
    """udp+tcp :53 ACCEPTs, one source per trusted CIDR (validated by caller)."""
    rules: List[str] = []
    for cidr in trusted:
        rules.append(f"-A INPUT -s {cidr} -p udp -m udp --dport 53 -j ACCEPT")
        rules.append(f"-A INPUT -s {cidr} -p tcp -m tcp --dport 53 -j ACCEPT")
    return rules


def _assert_dns_acl_safe(text_lines: Sequence[str]) -> None:
    """Refuse to ship any :53 ACCEPT that isn't scoped to a safe private source.

    The inverse of the must-contain-SSH lifeline: ``iptables-restore --test``
    proves syntax, never that we didn't just open a public resolver. Scans the
    actual rendered/applied rules, so an ``-i``-only or public ``-s`` is caught.
    """
    for line in text_lines:
        # Token match, NOT substring: "--dport 53" is a prefix of "--dport 5353"
        # (and 530, 53000, ...), so a substring test would drag an unrelated
        # high port into the :53 ACL check and raise RenderError on it. A
        # RenderError here aborts the WHOLE node-sync run - no DNS, no netplan,
        # no firewall, no systemd - silently, every 15 minutes.
        if not re.search(r"--dport 53(?![\d:])", line):
            continue
        match = re.search(r"-s (\S+)", line)
        if not match or not dns_acl_source_ok(match.group(1)):
            raise RenderError(f"unsafe :53 accept (unscoped/public source): {line!r}")


def render_iptables_base(
    self_node: dict,
    nodes: Dict[str, dict],
    trusted_dns_clients: Optional[Sequence[str]] = None,
    host_ports: Optional[Sequence[dict]] = None,
) -> str:
    subnet = self_node["bridge_subnet"]
    accepts = _etcd_accepts(nodes)
    trusted = list(TRUSTED_DNS_CLIENTS if trusted_dns_clients is None else trusted_dns_clients)
    dns_accepts = _dns_accepts(trusted)
    hostports = list(host_ports or [])
    _assert_host_ports_safe(hostports)
    hostport_accepts = _host_port_accepts(hostports)
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
            # iptables-restore requires every chain to be declared before any
            # rule references it, so this must stay above the jump below.
            f":{HOSTPORTS_CHAIN} - [0:0]",
            f"-A INPUT -i {INCUS_BRIDGE} -j ACCEPT",
            # Instances on PEER nodes, reaching this host's services.
            #
            # The rule above already gives a container unrestricted access to
            # its OWN host — every port, including etcd and the Incus API.
            # Without this line the same container can reach a peer host's
            # *instances* but none of that host's *services*, which is an
            # inconsistency rather than a security boundary. Container traffic
            # to a 10.0.0.0/8 destination is deliberately not masqueraded, so it
            # arrives sourced from CONTAINER_SUPERNET and is matched here.
            f"-A INPUT -s {CONTAINER_SUPERNET} -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -i lo -j ACCEPT",
            "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
            f"-A INPUT -s {VSWITCH_SUBNET} -p tcp -m tcp --dport 8443 -j ACCEPT",
            f"-A INPUT -s {VSWITCH_SUBNET} -p tcp -m tcp --dport {POSTGRES_PORT} -j ACCEPT",
            *dns_accepts,
            *accepts,
            "-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT",
            # Operator-opened ports. Placement is cosmetic: INPUT is ACCEPT-only
            # under policy DROP, so there is no earlier DROP/REJECT/RETURN for
            # ordering to interact with. What must match exactly is the argv
            # SPELLING shared with base_ensure_rules.
            f"-A INPUT -j {HOSTPORTS_CHAIN}",
            *hostport_accepts,
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
    _assert_dns_acl_safe(text.splitlines())
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


def base_ensure_rules(
    self_node: dict,
    nodes: Dict[str, dict],
    trusted_dns_clients: Optional[Sequence[str]] = None,
) -> List[Tuple[str, str, List[str]]]:
    """(table, chain, args) tuples to ensure live, via ``iptables -C || -A``."""
    subnet = self_node["bridge_subnet"]
    trusted = list(TRUSTED_DNS_CLIENTS if trusted_dns_clients is None else trusted_dns_clients)
    rules: List[Tuple[str, str, List[str]]] = [
        ("mangle", "FORWARD", ["-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                               "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
        ("filter", "INPUT", ["-i", INCUS_BRIDGE, "-j", "ACCEPT"]),
        # Mirrors render_iptables_base — the two MUST agree or node-sync reports
        # drift on every run.
        ("filter", "INPUT", ["-s", CONTAINER_SUPERNET, "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-i", "lo", "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-s", VSWITCH_SUBNET, "-p", "tcp", "-m", "tcp",
                             "--dport", "8443", "-j", "ACCEPT"]),
        ("filter", "INPUT", ["-s", VSWITCH_SUBNET, "-p", "tcp", "-m", "tcp",
                             "--dport", POSTGRES_PORT, "-j", "ACCEPT"]),
        # The JUMP is ensured here; the chain's CONTENTS deliberately are not.
        # This path is iptables -C || -A, which can only add - it has no way to
        # express "this rule should no longer be present", which is exactly what
        # closing a port requires. The contents are reconciled instead by
        # flush-and-rebuild in commands/node.py:_apply_host_ports, so a port
        # removed from etcd actually closes. The chain itself is created by
        # _ensure_custom_chains before this list is applied; without it every
        # jump would fail with "Chain does not exist" on a fresh node.
        ("filter", "INPUT", ["-j", HOSTPORTS_CHAIN]),
    ]
    for cidr in trusted:
        rules.append(("filter", "INPUT", ["-s", cidr, "-p", "udp", "-m", "udp",
                                          "--dport", "53", "-j", "ACCEPT"]))
        rules.append(("filter", "INPUT", ["-s", cidr, "-p", "tcp", "-m", "tcp",
                                          "--dport", "53", "-j", "ACCEPT"]))
    # Same fail-closed guard as the rendered base: the live -A path is otherwise
    # ungated, so a bad trusted CIDR could open :53 to the world.
    _assert_dns_acl_safe([" ".join(args) for _, _, args in rules])
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
