"""Unit tests for the safety-critical dnsmasq apply in node-sync.

The managed /etc/dnsmasq.conf serves DHCP for every VM on the bridge, so a bad
apply is a bridge-wide outage. These tests pin the load-bearing properties:
test-before-write, rollback on any failed post-check, and escalation when even
the rollback is dead. subprocess + filesystem are mocked — never touches a live
dnsmasq.
"""
from types import SimpleNamespace
from unittest.mock import patch

import hetzman.commands.node as node


def _node():
    return {
        "name": "htz-hel1-dc12-bm-01",
        "vswitch_ip": "10.0.0.4",
        "bridge_ip": "10.100.4.1",
        "vlan_interface": "enp5s0.4000",
    }


def _ok(stdout="", rc=0, stderr=""):
    return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


# --------------------------------------------------------------------------
# _apply_dnsmasq — the apply state machine

def test_apply_writes_conf_and_clears_sentinel_on_success():
    runs = []

    def fake_run(cmd, timeout=30):
        runs.append(cmd)
        return _ok()

    with patch.object(node, "_run", side_effect=fake_run), \
         patch.object(node, "_write") as wr, \
         patch.object(node, "_dnsmasq_serving", return_value=(True, "ok")), \
         patch.object(node, "_clear_dnsmasq_sentinel") as clear, \
         patch("os.path.exists", return_value=True), \
         patch("shutil.copy2"), patch("os.unlink"):
        changed, errors = node._apply_dnsmasq(
            _node(), include_drift=False, desired_include="",
            conf_drift=True, conf_is_managed=True, desired_conf="# Managed\nx\n")
    assert errors == []
    assert "dnsmasq.conf" in changed
    # live conf written exactly once with the desired content
    assert any(c.args[0] == node.DNSMASQ_CONF and c.args[1] == "# Managed\nx\n"
               for c in wr.call_args_list)
    clear.assert_called_once()
    assert ["systemctl", "restart", "dnsmasq"] in runs


def test_apply_candidate_test_failure_never_touches_live_conf():
    def fake_run(cmd, timeout=30):
        if "--test" in cmd:
            return _ok(rc=1, stderr="bad config")
        return _ok()

    written = []
    with patch.object(node, "_run", side_effect=fake_run), \
         patch.object(node, "_write", side_effect=lambda p, c, **k: written.append(p)), \
         patch.object(node, "_dnsmasq_serving", return_value=(True, "ok")) as serving, \
         patch("os.path.exists", return_value=True), \
         patch("shutil.copy2"), patch("os.unlink"):
        changed, errors = node._apply_dnsmasq(
            _node(), include_drift=False, desired_include="",
            conf_drift=True, conf_is_managed=False, desired_conf="# Managed\nbad\n")
    assert any("--test failed" in e for e in errors)
    # the live conf must NOT be written; only the candidate was
    assert node.DNSMASQ_CONF not in written
    assert node.DNSMASQ_CONF + ".candidate" in written
    serving.assert_not_called()  # no restart attempted


def test_apply_rolls_back_on_failed_post_check():
    restarts = []

    def fake_run(cmd, timeout=30):
        if cmd[:2] == ["systemctl", "restart"]:
            restarts.append(cmd)
        return _ok()

    copies = []
    with patch.object(node, "_run", side_effect=fake_run), \
         patch.object(node, "_write"), \
         patch.object(node, "_dnsmasq_serving", side_effect=[(False, "forward dig empty"), (True, "ok")]), \
         patch.object(node, "_clear_dnsmasq_sentinel") as clear, \
         patch("os.path.exists", return_value=True), \
         patch("shutil.copy2", side_effect=lambda s, d: copies.append((s, d))), \
         patch("os.unlink"):
        changed, errors = node._apply_dnsmasq(
            _node(), include_drift=False, desired_include="",
            conf_drift=True, conf_is_managed=True, desired_conf="# Managed\nx\n")
    assert any("rolling back" in e for e in errors)
    # restored from the .rollback snapshot
    assert any(src.endswith(".rollback") and dst == node.DNSMASQ_CONF for src, dst in copies)
    assert len(restarts) == 2          # apply restart + rollback restart
    clear.assert_called_once()         # rollback recovered → sentinel cleared


def test_apply_escalates_when_rollback_also_dead():
    with patch.object(node, "_run", return_value=_ok()), \
         patch.object(node, "_write") as wr, \
         patch.object(node, "_dnsmasq_serving", return_value=(False, "service not active")), \
         patch.object(node, "log_message") as logm, \
         patch("os.path.exists", return_value=True), \
         patch("shutil.copy2"), patch("os.unlink"):
        changed, errors = node._apply_dnsmasq(
            _node(), include_drift=False, desired_include="",
            conf_drift=True, conf_is_managed=True, desired_conf="# Managed\nx\n")
    assert any("CRITICAL" in e for e in errors)
    logm.assert_called()                # CRITICAL logged
    # the down-sentinel was written
    assert any(c.args[0] == node.DNSMASQ_DOWN_SENTINEL for c in wr.call_args_list)


# --------------------------------------------------------------------------
# _dnsmasq_serving — the liveness poll

def test_serving_requires_active_forward_reverse_dhcp_lease():
    self_node = _node()

    def fake_run(cmd, timeout=30):
        if cmd[:2] == ["dig", "+short"] and "-x" in cmd:
            return _ok(stdout="htz-hel1-dc12-bm-01.daemondreams.home.arpa.\n")
        if cmd[:2] == ["dig", "+short"]:
            return _ok(stdout="10.0.0.4\n")
        if cmd[0] == "ss":
            return _ok(stdout='UNCONN 0 0 0.0.0.0:67 ... users:(("dnsmasq",pid=1))')
        return _ok()

    with patch.object(node, "_systemctl_active", return_value=True), \
         patch.object(node, "_run", side_effect=fake_run), \
         patch("os.path.getsize", return_value=521):
        ok, reason = node._dnsmasq_serving(self_node, check_dhcp=True)
    assert ok and reason == "ok"


def test_serving_fails_when_dhcp_listener_gone():
    self_node = _node()

    def fake_run(cmd, timeout=30):
        if cmd[:2] == ["dig", "+short"] and "-x" in cmd:
            return _ok(stdout="htz-hel1-dc12-bm-01.daemondreams.home.arpa.\n")
        if cmd[:2] == ["dig", "+short"]:
            return _ok(stdout="10.0.0.4\n")
        if cmd[0] == "ss":
            return _ok(stdout="(no dhcp listener bound)")   # DHCP died
        return _ok()

    with patch.object(node, "_systemctl_active", return_value=True), \
         patch.object(node, "_run", side_effect=fake_run), \
         patch.object(node, "time", SimpleNamespace(sleep=lambda *_: None)), \
         patch("os.path.getsize", return_value=521):
        ok, reason = node._dnsmasq_serving(self_node, check_dhcp=True)
    assert not ok and "DHCP" in reason


# --------------------------------------------------------------------------
# _trusted_dns_clients — fail-closed

def test_trusted_clients_default_is_vswitch_only():
    with patch.object(node, "get_all_with_prefix", return_value={}):
        assert node._trusted_dns_clients() == ["10.0.0.0/24"]


def test_trusted_clients_accepts_valid_vpn_rejects_public():
    doc = {node.TRUSTED_DNS_CLIENTS_KEY: ["192.168.9.0/24", "1.2.3.0/24", "0.0.0.0/0"]}
    with patch.object(node, "get_all_with_prefix", return_value=doc), \
         patch.object(node, "_sync_log"):
        trusted = node._trusted_dns_clients()
    assert "192.168.9.0/24" in trusted       # valid private VPN CIDR added
    assert "1.2.3.0/24" not in trusted        # public rejected
    assert "0.0.0.0/0" not in trusted         # world rejected


def test_trusted_clients_bad_doc_is_fail_closed_not_raising():
    with patch.object(node, "get_all_with_prefix", side_effect=RuntimeError("boom")), \
         patch.object(node, "_sync_log"):
        # must NOT raise out of node-sync; falls back to vSwitch only
        assert node._trusted_dns_clients() == ["10.0.0.0/24"]


def test_vswitch_addr_up_detects_live_address():
    with patch.object(node, "_run", return_value=_ok(stdout="3: enp5s0.4000 inet 10.0.0.4/24 ...")):
        assert node._vswitch_addr_up(_node()) is True
    with patch.object(node, "_run", return_value=_ok(stdout="3: enp5s0.4000 inet ...")):
        assert node._vswitch_addr_up(_node()) is False
    with patch.object(node, "_run", return_value=_ok(rc=1)):
        assert node._vswitch_addr_up(_node()) is False
