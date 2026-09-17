"""Tests for node-sync's iptables chain handling.

The base ruleset jumps into custom nat chains, and into the custom filter chain
that carries operator-opened host ports. Those jumps cannot be added before the
chains exist, and on a freshly provisioned node they do not — which made the
FIRST node-sync run on every new node report errors.
"""
from types import SimpleNamespace
from unittest.mock import patch

import hetzman.commands.node as node
from hetzman.render import (
    FILTER_CUSTOM_CHAINS,
    NAT_CUSTOM_CHAINS,
    render_iptables_base,
)

ALL_CUSTOM_CHAINS = tuple(NAT_CUSTOM_CHAINS) + tuple(FILTER_CUSTOM_CHAINS)


def _ok(rc=0):
    return SimpleNamespace(returncode=rc, stdout="", stderr="")


def _fleet():
    n = {
        "name": "n1", "vswitch_ip": "10.0.0.4", "bridge_ip": "10.100.4.1",
        "bridge_subnet": "10.100.4.0/24", "vlan_interface": "enp5s0.4000",
    }
    return n, {"n1": n}


def test_constant_matches_the_chains_the_base_ruleset_declares():
    """Tripwire: if a chain is added to the rendered base but not to the
    constant, node-sync would fail to pre-create it on a fresh node again."""
    self_node, nodes = _fleet()
    text = render_iptables_base(self_node, nodes)
    declared = {
        line[1:].split()[0]
        for line in text.splitlines()
        if line.startswith(":HETZMAN")
    }
    assert declared == set(ALL_CUSTOM_CHAINS)


def test_missing_chains_are_created():
    calls = []

    def fake_run(cmd, timeout=30):
        calls.append(cmd)
        if "-L" in cmd:
            return _ok(1)          # chain does not exist
        return _ok()

    with patch.object(node, "_run", side_effect=fake_run):
        node._ensure_custom_chains()

    created = [c for c in calls if "-N" in c]
    assert [c[c.index("-N") + 1] for c in created] == list(ALL_CUSTOM_CHAINS)
    # ...and each in the right table, or the chain is created where no rule
    # jumps into it and the jump still fails.
    tables = {c[c.index("-N") + 1]: c[c.index("-t") + 1] for c in created}
    for chain in NAT_CUSTOM_CHAINS:
        assert tables[chain] == "nat"
    for chain in FILTER_CUSTOM_CHAINS:
        assert tables[chain] == "filter"


def test_existing_chains_are_left_alone():
    """Idempotent: creating a chain that exists is an error we must not provoke."""
    calls = []

    def fake_run(cmd, timeout=30):
        calls.append(cmd)
        return _ok(0)              # every chain already exists

    with patch.object(node, "_run", side_effect=fake_run):
        node._ensure_custom_chains()

    assert not any("-N" in c for c in calls)


def test_chains_are_ensured_before_the_jumps_are_appended():
    """Ordering is the whole point: -N must precede the -A that jumps into it."""
    order = []

    def fake_run(cmd, timeout=30):
        if "-N" in cmd:
            order.append(("create", cmd[cmd.index("-N") + 1]))
        elif "-A" in cmd:
            order.append(("append", cmd[cmd.index("-A") + 1]))
        return _ok(1) if "-L" in cmd else _ok(0)

    with patch.object(node, "_run", side_effect=fake_run):
        node._ensure_custom_chains()
        # simulate the live-ensure step that follows
        node._run(["iptables", "-w", "5", "-t", "nat", "-A", "PREROUTING", "-j", "HETZMAN_NAT"])

    assert order[0][0] == "create"
    assert order[-1] == ("append", "PREROUTING")
