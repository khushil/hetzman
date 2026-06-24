"""Tests for core/ops.py (reboot quorum guard, apply-updates) + host users +
assess_reboot boundaries. exec/nodes/reads mocked — no real fleet."""
import unittest
from unittest import mock

from hetzman.core import ops, users
from hetzman.core.errors import CoreError, NotFoundError, ValidationError
from hetzman.core.events import Severity
from hetzman.core.nodes import MemberView, assess_reboot


def _mv(id, name="m", healthy=True):
    return MemberView(id=id, name=name, peer_hosts=("10.0.0.1",), healthy=healthy, is_leader=False)


def _drain(gen):
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


class AssessRebootTests(unittest.TestCase):
    """A reboot drops a voter transiently — quorum stays at the FULL cluster n."""

    def test_n3_reboot_one_with_two_healthy_ok(self):
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c")]
        assess_reboot(members, 1)  # 2 healthy others >= quorum 2 of 3

    def test_n3_reboot_refused_when_another_down(self):
        members = [_mv(1, "a"), _mv(2, "b", healthy=False), _mv(3, "c")]
        with self.assertRaises(CoreError):
            assess_reboot(members, 1)  # only 1 healthy other < quorum 2

    def test_n4_reboot_one_with_three_healthy_ok(self):
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c"), _mv(4, "d")]
        assess_reboot(members, 1)  # 3 healthy others >= quorum 3 of 4

    def test_n4_reboot_refused_when_one_other_down(self):
        members = [_mv(1, "a"), _mv(2, "b", healthy=False), _mv(3, "c"), _mv(4, "d")]
        with self.assertRaises(CoreError):
            assess_reboot(members, 1)  # 2 healthy others < quorum 3 of 4

    def test_refuses_while_unstarted_member(self):
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, ""), _mv(4, "d")]
        with self.assertRaises(CoreError):
            assess_reboot(members, 1)


class RebootHostTests(unittest.TestCase):
    @mock.patch("hetzman.core.ops._running_instances", return_value=["vm1"])
    @mock.patch("hetzman.core.ops.host_exec")
    @mock.patch("hetzman.core.ops.nodes")
    def test_reboot_member_safe(self, nd, hx, ri):
        hx.resolve_host.return_value = "node-a"
        nd.lookup_member.return_value = (_mv(1, "etcd-a"),
                                         [_mv(1, "etcd-a"), _mv(2, "b"), _mv(3, "c")])
        nd.assess_reboot.return_value = None  # safe
        events, result = _drain(ops.reboot_host("node-a"))
        self.assertTrue(result.ok)
        # warned about the running VM + issued the reboot
        self.assertTrue(any(e.severity == Severity.WARNING for e in events))
        hx.run_on.assert_called_once()
        self.assertIn("reboot", hx.run_on.call_args[0][1])

    @mock.patch("hetzman.core.ops._running_instances", return_value=[])
    @mock.patch("hetzman.core.ops.host_exec")
    @mock.patch("hetzman.core.ops.nodes")
    def test_reboot_refused_breaks_quorum(self, nd, hx, ri):
        hx.resolve_host.return_value = "node-a"
        nd.lookup_member.return_value = (_mv(1, "etcd-a"), [_mv(1), _mv(2)])
        nd.assess_reboot.side_effect = CoreError("would lose quorum")
        with self.assertRaises(CoreError):
            _drain(ops.reboot_host("node-a"))
        hx.run_on.assert_not_called()  # never issued the reboot

    @mock.patch("hetzman.core.ops._running_instances", return_value=[])
    @mock.patch("hetzman.core.ops.host_exec")
    @mock.patch("hetzman.core.ops.nodes")
    def test_reboot_non_member_host_skips_quorum(self, nd, hx, ri):
        hx.resolve_host.return_value = "edge-1"
        nd.lookup_member.return_value = (None, [])  # not an etcd member
        events, result = _drain(ops.reboot_host("edge-1"))
        self.assertTrue(result.ok)
        nd.assess_reboot.assert_not_called()
        hx.run_on.assert_called_once()


class ApplyUpdatesTests(unittest.TestCase):
    @mock.patch("hetzman.core.ops._running_instances", return_value=[])
    @mock.patch("hetzman.core.ops.host_exec")
    def test_apply_streams_apt_output(self, hx, ri):
        hx.resolve_host.return_value = "node-a"
        hx.stream_on.return_value = iter(["Reading package lists...", "0 upgraded"])
        events, result = _drain(ops.apply_updates("node-a"))
        self.assertTrue(result.ok)
        # apt output appeared as INFO events
        self.assertTrue(any("upgraded" in e.message for e in events))


class HostUserTests(unittest.TestCase):
    @mock.patch("hetzman.core.users._read_pubkey", return_value="ssh-ed25519 AAAA...")
    @mock.patch("hetzman.core.users.host_exec")
    @mock.patch("hetzman.core.users.check_host_user_exists", return_value=False)
    def test_add_host_user(self, exists, hx, rk):
        events, result = _drain(users.add_host_user("node-a", "alice", "/k.pub", sudo=True))
        self.assertTrue(result.ok)
        argv0 = [c.args[1][0] for c in hx.run_on.call_args_list]
        self.assertIn("useradd", argv0)
        # the key is written private (umask 077 + tee) with the pubkey on stdin
        tee = [c for c in hx.run_on.call_args_list if "tee" in " ".join(c.args[1])]
        self.assertTrue(tee)
        self.assertEqual(tee[0].kwargs["input"], "ssh-ed25519 AAAA...")
        self.assertIn("umask 077", tee[0].args[1][-1])

    @mock.patch("hetzman.core.users._read_pubkey", return_value="k")
    @mock.patch("hetzman.core.users.host_exec")
    @mock.patch("hetzman.core.users.check_host_user_exists", return_value=False)
    def test_add_host_user_key_push_failure_rolls_back(self, exists, hx, rk):
        # useradd/mkdir succeed, but the key write (bash tee) raises -> userdel rollback
        def run_on(host, argv, **kw):
            if "tee" in " ".join(argv):
                raise CoreError("disk full")
            return mock.Mock(returncode=0)
        hx.run_on.side_effect = run_on
        with self.assertRaises(CoreError):
            _drain(users.add_host_user("node-a", "alice", "/k.pub"))
        argv0 = [c.args[1][0] for c in hx.run_on.call_args_list]
        self.assertIn("userdel", argv0)  # rollback

    @mock.patch("hetzman.core.users._read_pubkey", return_value="k")
    @mock.patch("hetzman.core.users.host_exec")
    @mock.patch("hetzman.core.users.check_host_user_exists", return_value=False)
    def test_add_host_user_chown_failure_rolls_back(self, exists, hx, rk):
        # a failed chown (would let sshd ignore the key) must abort + roll back,
        # not report success.
        def run_on(host, argv, **kw):
            if argv[0] == "chown":
                raise CoreError("chown failed")
            return mock.Mock(returncode=0)
        hx.run_on.side_effect = run_on
        with self.assertRaises(CoreError):
            _drain(users.add_host_user("node-a", "alice", "/k.pub"))
        argv0 = [c.args[1][0] for c in hx.run_on.call_args_list]
        self.assertIn("userdel", argv0)

    @mock.patch("hetzman.core.users._read_pubkey", return_value="newkey")
    @mock.patch("hetzman.core.users.host_exec")
    @mock.patch("hetzman.core.users.check_host_user_exists", return_value=True)
    def test_change_host_keys_is_atomic(self, exists, hx, rk):
        events, result = _drain(users.change_host_keys("node-a", "alice", "/new.pub"))
        self.assertTrue(result.ok)
        # one atomic bash op: temp -> chmod -> mv, key content on stdin
        call = hx.run_on.call_args_list[0]
        script = call.args[1][-1]
        self.assertIn("mv ", script)
        self.assertIn(".hetzman.tmp", script)
        self.assertEqual(call.kwargs["input"], "newkey")

    @mock.patch("hetzman.core.users.host_exec")
    @mock.patch("hetzman.core.users.check_host_user_exists", return_value=True)
    def test_remove_host_root_refused(self, exists, hx):
        with self.assertRaises(ValidationError):
            _drain(users.remove_host_user("node-a", "root"))


if __name__ == "__main__":
    unittest.main()
