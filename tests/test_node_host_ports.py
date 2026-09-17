"""Unit tests for the operator-opened host-port reader and reconciliation.

The load-bearing properties: malformed operator data must NEVER abort
node-sync (a RenderError there takes down DNS, netplan, firewall and systemd
on a 15-minute timer), the reader must be scoped to THIS node, and closing a
port must actually close it rather than waiting for a reboot.
subprocess + etcd are mocked - never touches a live firewall.
"""
from types import SimpleNamespace
from unittest.mock import patch

import hetzman.commands.node as node

NODE = "htz-fsn1-dc1-bm-01"
PEER = "htz-hel1-dc12-bm-01"


def _entry(port=1666, protocol="tcp", source="0.0.0.0/0"):
    return {"port": port, "protocol": protocol, "source": source, "description": "p4d"}


def _ok(rc=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


# --- reader: fail-closed trio, mirroring _trusted_dns_clients ---------------

def test_host_ports_default_is_empty():
    with patch.object(node, "get_all_with_prefix", return_value={}):
        assert node._host_ports(NODE) == []


def test_host_ports_drops_malformed_entries_but_keeps_good_ones():
    doc = {
        f"/hetzman/host-ports/{NODE}/1666-tcp": _entry(),
        f"/hetzman/host-ports/{NODE}/0-tcp": _entry(port=0),          # invalid port
        f"/hetzman/host-ports/{NODE}/443-sctp": _entry(protocol="sctp"),  # bad proto
        f"/hetzman/host-ports/{NODE}/8080-tcp": _entry(port=8080, source="nonsense"),
    }
    with patch.object(node, "get_all_with_prefix", return_value=doc), \
         patch.object(node, "_sync_log"):
        entries = node._host_ports(NODE)
    assert [e["port"] for e in entries] == [1666]


def test_host_ports_bad_doc_is_fail_closed_not_raising():
    """A read failure must degrade to 'open nothing', never propagate."""
    with patch.object(node, "get_all_with_prefix", side_effect=RuntimeError("etcd down")), \
         patch.object(node, "_sync_log"):
        assert node._host_ports(NODE) == []


def test_host_ports_reader_is_scoped_to_this_node_not_the_whole_prefix():
    """A prefix scan over /hetzman/host-ports/ would open EVERY node's ports on
    EVERY node. The reader must query this node's subtree only."""
    captured = {}

    def fake(prefix):
        captured["prefix"] = prefix
        return {f"/hetzman/host-ports/{PEER}/9999-tcp": _entry(port=9999)}

    with patch.object(node, "get_all_with_prefix", side_effect=fake), \
         patch.object(node, "_sync_log"):
        entries = node._host_ports(NODE)
    assert captured["prefix"] == f"/hetzman/host-ports/{NODE}/"
    # Even if the backend over-returns, keys outside this node are ignored.
    assert entries == []


# --- reconciliation: removal must actually remove ---------------------------

def test_live_rules_are_parsed_from_the_chain():
    listing = (
        "-N HETZMAN_HOSTPORTS\n"
        "-A HETZMAN_HOSTPORTS -p tcp -m tcp --dport 1666 -j ACCEPT\n"
    )
    with patch.object(node, "_run", return_value=_ok(stdout=listing)):
        assert node._live_host_port_rules() == [
            ["-p", "tcp", "-m", "tcp", "--dport", "1666", "-j", "ACCEPT"]
        ]


def test_missing_chain_reads_as_no_rules():
    with patch.object(node, "_run", return_value=_ok(rc=1, stderr="No chain/target/match")):
        assert node._live_host_port_rules() == []


def test_apply_flushes_before_rebuilding():
    """Flush-first is what makes a close take effect. Without it the ensure
    path could only ever ADD, so a removed port stayed open until reboot."""
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return _ok()

    with patch.object(node, "_run", side_effect=fake_run):
        errors = node._apply_host_ports(
            [["-p", "tcp", "-m", "tcp", "--dport", "1666", "-j", "ACCEPT"]]
        )
    assert errors == []
    assert "-F" in calls[0] and node.HOSTPORTS_CHAIN in calls[0]
    assert "-A" in calls[1] and "1666" in calls[1]


def test_apply_with_no_desired_rules_leaves_an_empty_chain():
    """Closing the last port must flush and add nothing - not skip the flush."""
    calls = []
    with patch.object(node, "_run", side_effect=lambda argv, **kw: (calls.append(argv), _ok())[1]):
        assert node._apply_host_ports([]) == []
    assert len(calls) == 1 and "-F" in calls[0]


def test_failed_flush_reports_and_does_not_rebuild():
    with patch.object(node, "_run", return_value=_ok(rc=1, stderr="permission denied")):
        errors = node._apply_host_ports(
            [["-p", "tcp", "-m", "tcp", "--dport", "1666", "-j", "ACCEPT"]]
        )
    assert len(errors) == 1 and "flush failed" in errors[0]


def test_desired_rules_are_deduplicated():
    entries = [_entry(), dict(_entry()), _entry(port=443)]
    assert len(node._desired_host_port_rules(entries)) == 2
