"""Tests for node-sync's netplan post-apply check.

A failed check rolls the netplan back, so a check that is wrong in the *pessimistic*
direction is not harmless: it makes the drift unclearable and node-sync error on
every run. These pin the fleet-size edge cases.
"""
from types import SimpleNamespace
from unittest.mock import patch

import hetzman.commands.node as node


def _ok(rc=0):
    return SimpleNamespace(returncode=rc, stdout="", stderr="")


def _fleet(*ips):
    return {
        f"node-{ip.replace('.', '-')}": {"name": f"node-{ip.replace('.', '-')}", "vswitch_ip": ip}
        for ip in ips
    }


def test_single_node_fleet_passes_without_any_peer_to_ping():
    """The regression: with no peers, `any([])` is False and every netplan apply
    would be rolled back, so the drift could never clear."""
    nodes = _fleet("10.0.0.4")
    self_node = nodes["node-10-0-0-4"]
    with patch.object(node, "_run", return_value=_ok(1)) as run, \
         patch("hetzman.etcd_kv.get_key", return_value="3.1"):
        assert node._post_check_network(self_node, nodes) is True
    # no ping was attempted — there was nothing to ping
    assert not any(c.args[0][0] == "ping" for c in run.call_args_list)


def test_single_node_fleet_still_fails_when_etcd_is_unreachable():
    """Relaxing the ping arm must not relax the arm that still means something."""
    nodes = _fleet("10.0.0.4")
    with patch.object(node, "_run", return_value=_ok()), \
         patch("hetzman.etcd_kv.get_key", return_value=None):
        assert node._post_check_network(nodes["node-10-0-0-4"], nodes) is False


def test_multi_node_fleet_still_requires_a_peer_to_answer():
    """With peers present the ping arm is real and must still be enforced."""
    nodes = _fleet("10.0.0.4", "10.0.0.1", "10.0.0.2")
    self_node = nodes["node-10-0-0-4"]
    with patch.object(node, "_run", return_value=_ok(1)), \
         patch("hetzman.etcd_kv.get_key", return_value="3.1"):
        assert node._post_check_network(self_node, nodes) is False

    with patch.object(node, "_run", return_value=_ok(0)), \
         patch("hetzman.etcd_kv.get_key", return_value="3.1"):
        assert node._post_check_network(self_node, nodes) is True
