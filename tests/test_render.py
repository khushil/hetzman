"""Unit tests for the pure renderers — the safety-critical core of node-sync."""
import copy

import pytest
import yaml

from hetzman.render import (
    DNS_ADDN_HOSTS,
    DNS_REVERSE_ZONES,
    RenderError,
    base_ensure_rules,
    dns_acl_source_ok,
    dnsmasq_conf_lines_to_remove,
    iptables_cleanup_plan,
    netplan_semantically_equal,
    render_dnsmasq_conf,
    render_dnsmasq_include,
    render_iptables_base,
    render_netplan_vswitch,
    _split_save_rule,
)


def make_fleet():
    def node(name, n):
        return {
            "schema": 1,
            "name": name,
            "vswitch_ip": f"10.0.0.{n}",
            "bridge_ip": f"10.100.{n}.1",
            "bridge_subnet": f"10.100.{n}.0/24",
            "public_block": f"203.0.113.{8 * n}/29",
            "primary_interface": "enp5s0",
            "vlan_interface": "enp5s0.4000",
            "vlan_id": 4000,
            "mtu": 1400,
            "etcd_name": f"etcd-{name.split('-')[2]}",
            "etcd_client_port": 2379,
        }

    return {
        f"htz-hel1-dc{dc}-bm-01": node(f"htz-hel1-dc{dc}-bm-01", n)
        for n, dc in ((1, 7), (2, 4), (3, 3), (4, 12))
    }


FLEET = make_fleet()
SELF = FLEET["htz-hel1-dc4-bm-01"]


def test_dnsmasq_include_has_all_nodes_sorted():
    text = render_dnsmasq_include(FLEET)
    assert text.count("host-record=") == 4
    assert "host-record=htz-hel1-dc12-bm-01.daemondreams.home.arpa,10.0.0.4" in text
    lines = [l for l in text.splitlines() if l.startswith("host-record=")]
    assert lines == sorted(lines)


def test_dnsmasq_migration_only_removes_registry_hosts():
    conf = (
        "interface=incusbr0\n"
        "host-record=htz-hel1-dc7-bm-01.daemondreams.home.arpa,10.0.0.1\n"
        "host-record=something-else.example.com,1.2.3.4\n"
    )
    doomed = dnsmasq_conf_lines_to_remove(conf, FLEET)
    assert len(doomed) == 1
    assert "dc7" in doomed[0]


# The live, hand-rolled dnsmasq.conf captured from dc12 in Phase 0 (the golden
# source of truth). render_dnsmasq_conf must reproduce EVERY directive here or a
# VM loses its lease/router/DNS. dc12 == FLEET["htz-hel1-dc12-bm-01"] (n=4).
CAPTURED_DC12 = """\
interface=lo
interface=incusbr0
bind-dynamic
domain=daemondreams.home.arpa
local=/daemondreams.home.arpa/
expand-hosts
domain-needed
bogus-priv
no-negcache
stop-dns-rebind
rebind-localhost-ok
dns-forward-max=150
no-resolv
server=1.1.1.1
server=8.8.8.8
cache-size=1000
dhcp-range=10.100.4.10,10.100.4.250,255.255.255.0,12h
dhcp-option=option:router,10.100.4.1
dhcp-option=option:dns-server,10.100.4.1
dhcp-option=option:domain-name,daemondreams.home.arpa
dhcp-authoritative
dhcp-rapid-commit
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
addn-hosts=/opt/hetzman-tooling/configs/additional-hosts
log-facility=/var/log/hetzman-tooling/dnsmasq.log
log-queries=extra
"""

DC12 = FLEET["htz-hel1-dc12-bm-01"]


def test_dnsmasq_conf_reproduces_every_captured_directive():
    """The single most important safety test: nothing in the live config is
    silently dropped by the render (would break DHCP/DNS for every VM)."""
    rendered = render_dnsmasq_conf(DC12, vlan_listen=True).splitlines()
    for directive in CAPTURED_DC12.splitlines():
        assert directive in rendered, f"render DROPPED live directive: {directive!r}"


def test_dnsmasq_conf_pinned_paths_match_config():
    from hetzman import config
    assert DNS_ADDN_HOSTS == config.ADDITIONAL_HOSTS


def test_dnsmasq_conf_self_substitution():
    # DHCP range/router derive from THIS node's bridge_subnet (dc4 -> n=2).
    conf = render_dnsmasq_conf(SELF, vlan_listen=True)
    assert "dhcp-range=10.100.2.10,10.100.2.250,255.255.255.0,12h" in conf
    assert "dhcp-option=option:router,10.100.2.1" in conf
    assert "dhcp-option=option:dns-server,10.100.2.1" in conf
    # A node with a DISTINCT vlan/primary iface proves the iface is self-derived
    # (not a hardcoded constant), per the review.
    odd = dict(SELF, vlan_interface="bond0.99", primary_interface="bond0")
    odd_conf = render_dnsmasq_conf(odd, vlan_listen=True)
    assert "interface=bond0.99" in odd_conf
    assert "except-interface=bond0" in odd_conf
    assert "no-dhcp-interface=bond0.99" in odd_conf


def test_dnsmasq_conf_vlan_listen_toggle():
    on = render_dnsmasq_conf(SELF, vlan_listen=True)
    off = render_dnsmasq_conf(SELF, vlan_listen=False)
    # vSwitch iface added only when the address is up.
    assert "interface=enp5s0.4000" in on
    assert "interface=enp5s0.4000" not in off
    assert "no-dhcp-interface=enp5s0.4000" in on
    assert "no-dhcp-interface=enp5s0.4000" not in off
    # Public iface NEVER bound; always excepted; lo never serves DHCP.
    for conf in (on, off):
        assert "except-interface=enp5s0" in conf
        assert "\ninterface=enp5s0\n" not in conf  # line-anchored: not the public iface
        assert "no-dhcp-interface=lo" in conf


def test_dnsmasq_conf_reverse_zones_scoped():
    conf = render_dnsmasq_conf(SELF, vlan_listen=True)
    assert "local=/0.0.10.in-addr.arpa/" in conf
    assert "local=/100.10.in-addr.arpa/" in conf
    # NEVER the whole-10/8 reverse zone.
    assert "local=/10.in-addr.arpa/" not in conf
    assert DNS_REVERSE_ZONES == ("0.0.10.in-addr.arpa", "100.10.in-addr.arpa")


def test_dnsmasq_conf_refuses_to_bind_public_iface():
    # Misconfig where the vSwitch iface == the public iface must NOT silently
    # produce an internet-facing resolver.
    bad = dict(SELF, vlan_interface="enp5s0", primary_interface="enp5s0")
    with pytest.raises(RenderError):
        render_dnsmasq_conf(bad, vlan_listen=True)


def test_dns_acl_source_predicate():
    assert dns_acl_source_ok("10.0.0.0/24")
    assert dns_acl_source_ok("192.168.1.0/24")
    assert dns_acl_source_ok("10.8.0.5/24")        # host bits ok (strict=False)
    assert not dns_acl_source_ok("0.0.0.0/0")      # world
    assert not dns_acl_source_ok("10.0.0.0/8")     # too broad
    assert not dns_acl_source_ok("1.2.3.0/24")     # public
    assert not dns_acl_source_ok("not-a-cidr")


def test_iptables_dns_acl_scoped_to_vswitch_by_default():
    text = render_iptables_base(SELF, FLEET)
    assert "-A INPUT -s 10.0.0.0/24 -p udp -m udp --dport 53 -j ACCEPT" in text
    assert "-A INPUT -s 10.0.0.0/24 -p tcp -m tcp --dport 53 -j ACCEPT" in text


def test_iptables_dns_acl_rejects_unsafe_trusted_cidrs():
    for bad in ("0.0.0.0/0", "10.0.0.0/8", "1.2.3.0/24"):
        with pytest.raises(RenderError):
            render_iptables_base(SELF, FLEET, trusted_dns_clients=[bad])
        with pytest.raises(RenderError):
            base_ensure_rules(SELF, FLEET, trusted_dns_clients=[bad])


def test_iptables_dns_acl_allows_extra_vpn_cidr():
    text = render_iptables_base(SELF, FLEET, trusted_dns_clients=["10.0.0.0/24", "192.168.50.0/24"])
    assert "-s 192.168.50.0/24 -p udp -m udp --dport 53 -j ACCEPT" in text


def test_base_ensure_rules_include_scoped_dns_accepts():
    rules = base_ensure_rules(SELF, FLEET)
    dns_rules = [r for r in rules if "53" in " ".join(r[2])]
    assert len(dns_rules) == 2  # udp + tcp for the one default vswitch CIDR
    for _t, _c, args in dns_rules:
        assert "10.0.0.0/24" in args


def test_netplan_routes_exclude_self():
    doc = yaml.safe_load(render_netplan_vswitch(SELF, FLEET))
    vlan = doc["network"]["vlans"]["enp5s0.4000"]
    assert vlan["addresses"] == ["10.0.0.2/24"]
    assert vlan["mtu"] == 1400
    routes = {r["to"]: r["via"] for r in vlan["routes"]}
    assert routes == {
        "10.100.1.0/24": "10.0.0.1",
        "10.100.3.0/24": "10.0.0.3",
        "10.100.4.0/24": "10.0.0.4",
    }


def test_netplan_semantic_equality_ignores_formatting():
    a = render_netplan_vswitch(SELF, FLEET)
    doc = yaml.safe_load(a)
    b = yaml.safe_dump(doc, sort_keys=True, indent=4)  # different formatting
    assert netplan_semantically_equal(a, b)
    doc["network"]["vlans"]["enp5s0.4000"]["mtu"] = 1500
    assert not netplan_semantically_equal(a, yaml.safe_dump(doc))


def test_iptables_base_contains_lifeline_rules():
    text = render_iptables_base(SELF, FLEET)
    assert ":INPUT DROP" in text
    assert "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT" in text
    assert "-A INPUT -i lo -j ACCEPT" in text
    assert "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" in text
    for n in (1, 2, 3, 4):
        assert f"-A INPUT -s 10.0.0.{n}/32 -p tcp -m tcp --dport 2379:2380 -j ACCEPT" in text
    assert "-A FORWARD -s 10.100.2.0/24 -j ACCEPT" in text
    assert "-A HETZMAN_NAT_POST -s 10.100.0.0/16 -d 10.100.0.0/16 -j MASQUERADE" in text
    # Skeleton only: no per-instance NAT frozen into the base.
    assert "SNAT" not in text and "DNAT" not in text


def test_iptables_base_refuses_empty_registry():
    with pytest.raises(RenderError):
        render_iptables_base(SELF, {})


def test_ensure_rules_match_base_accepts():
    rules = base_ensure_rules(SELF, FLEET)
    etcd_rules = [r for r in rules if "2379:2380" in " ".join(r[2])]
    assert len(etcd_rules) == 4


SAMPLE_LIVE = """\
*filter
:INPUT DROP [0:0]
-A INPUT -i incusbr0 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -s 10.0.0.1/32 -p tcp -m tcp --dport 2379:2380 -j ACCEPT
-A INPUT -s 10.0.0.9/32 -p tcp -m tcp --dport 2379:2380 -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -s 10.100.2.216/32 -j LOG --log-prefix "NAT-PRE: "
-A PREROUTING -j HETZMAN_NAT
-A POSTROUTING -s 10.100.2.216/32 -j LOG --log-prefix "NAT-POST: "
-A POSTROUTING -s 10.100.1.0/24 ! -d 10.0.0.0/8 -j MASQUERADE
-A POSTROUTING -s 172.18.0.0/16 ! -o br-bf01543d24ba -j MASQUERADE
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -o wg0 -j SNAT --to-source 192.0.2.1
-A POSTROUTING -j HETZMAN_NAT_POST
COMMIT
"""


def test_cleanup_plan_deletes_only_known_cruft():
    deletions, warnings = iptables_cleanup_plan(SAMPLE_LIVE, FLEET)
    flat = [(t, " ".join(args)) for t, args in deletions]

    # Stale etcd accept (10.0.0.9 not in registry) deleted; registry one kept.
    assert ("filter", "INPUT -s 10.0.0.9/32 -p tcp -m tcp --dport 2379:2380 -j ACCEPT") in flat
    assert not any("10.0.0.1/32" in d for _t, d in flat)

    # LOG cruft and the blanket MASQUERADE deleted.
    assert any("NAT-PRE:" in d for _t, d in flat)
    assert any("NAT-POST:" in d for _t, d in flat)
    assert ("nat", "POSTROUTING -s 10.100.1.0/24 ! -d 10.0.0.0/8 -j MASQUERADE") in flat

    # Docker's plain MASQUERADE rules are NEVER deleted (would break KIND).
    assert not any("172.1" in d for _t, d in flat)

    # The unknown wireguard-ish rule is warned about, not deleted.
    assert not any("wg0" in d for _t, d in flat)
    assert any("wg0" in w for w in warnings)


def test_cleanup_never_touches_ssh():
    live = "*filter\n-A INPUT -s 10.0.0.9/32 -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"
    deletions, _ = iptables_cleanup_plan(live, FLEET)
    assert deletions == []


def test_split_save_rule_preserves_quoted_log_prefix():
    args = _split_save_rule('POSTROUTING -s 10.100.2.216/32 -j LOG --log-prefix "NAT-POST: "')
    assert args[-1] == "NAT-POST: "
    assert args[0] == "POSTROUTING"


def test_netplan_routes_sorted_and_order_insensitive():
    text = render_netplan_vswitch(SELF, FLEET)
    doc = yaml.safe_load(text)
    routes = doc["network"]["vlans"]["enp5s0.4000"]["routes"]
    assert [r["to"] for r in routes] == sorted(r["to"] for r in routes)
    reversed_doc = copy.deepcopy(doc)
    reversed_doc["network"]["vlans"]["enp5s0.4000"]["routes"] = list(reversed(routes))
    assert netplan_semantically_equal(text, yaml.safe_dump(reversed_doc))


# --------------------------------------------------------------------------
# Cross-node reachability: instances -> a PEER host's services

def _self_and_fleet():
    fleet = make_fleet()
    return fleet["htz-hel1-dc12-bm-01"], fleet


def test_peer_instances_may_reach_this_host():
    """A container already has unrestricted access to its OWN host via the
    bridge rule; peer hosts must match, or instances can reach a peer's
    instances but none of its services."""
    from hetzman.render import CONTAINER_SUPERNET, INCUS_BRIDGE, render_iptables_base

    self_node, nodes = _self_and_fleet()
    text = render_iptables_base(self_node, nodes)
    assert f"-A INPUT -i {INCUS_BRIDGE} -j ACCEPT" in text
    assert f"-A INPUT -s {CONTAINER_SUPERNET} -j ACCEPT" in text


def test_supernet_accept_is_in_both_the_base_and_the_live_ensure():
    """Drift tripwire: the rendered base and the live-ensure list must agree,
    otherwise node-sync reports drift on every single run."""
    from hetzman.render import CONTAINER_SUPERNET, base_ensure_rules, render_iptables_base

    self_node, nodes = _self_and_fleet()
    assert f"-A INPUT -s {CONTAINER_SUPERNET} -j ACCEPT" in render_iptables_base(self_node, nodes)
    assert ("filter", "INPUT", ["-s", CONTAINER_SUPERNET, "-j", "ACCEPT"]) in \
        base_ensure_rules(self_node, nodes)


def test_supernet_accept_does_not_widen_the_dns_acl():
    """The :53 ACL guard must still pass — this rule is not a DNS widening."""
    from hetzman.render import base_ensure_rules

    self_node, nodes = _self_and_fleet()
    base_ensure_rules(self_node, nodes)   # raises RenderError if the guard trips
