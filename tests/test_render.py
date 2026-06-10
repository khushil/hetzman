"""Unit tests for the pure renderers — the safety-critical core of node-sync."""
import copy

import pytest
import yaml

from hetzman.render import (
    RenderError,
    base_ensure_rules,
    dnsmasq_conf_lines_to_remove,
    iptables_cleanup_plan,
    netplan_semantically_equal,
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
