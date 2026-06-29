"""Tests for core/users.py: add (with key-push rollback), remove, change-keys."""
import unittest
from unittest import mock

from hetzman.core import users as core_users
from hetzman.core.errors import CoreError, NotFoundError, ValidationError
from hetzman.core.events import Severity


def _drain(gen):
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


class _Res:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ""


class UserCrudTests(unittest.TestCase):
    PROBE = (
        "root|0|no|no|7|/root\n"
        "kdep|1000|no|yes|7|/home/kdep\n"
        "alice|1001|yes|no|1|/home/alice\n"        # suspended + sudo
    )

    def test_list_users_parses_probe(self):
        with mock.patch.object(core_users, "_user_run", return_value=_Res(self.PROBE)):
            accounts = core_users.list_users("host", "h")
        by = {a.name: a for a in accounts}
        self.assertFalse(by["kdep"].locked)
        self.assertTrue(by["kdep"].sudo)
        self.assertTrue(by["alice"].locked)        # susp == "yes"
        self.assertEqual(by["alice"].key_count, 1)
        self.assertEqual(by["root"].uid, 0)

    def test_suspend_refuses_root(self):
        with self.assertRaises(ValidationError):
            _drain(core_users.suspend_user("host", "h", "root"))

    def test_set_sudo_refuses_root(self):
        with self.assertRaises(ValidationError):
            _drain(core_users.set_user_sudo("host", "h", "root", True))

    def test_suspend_locks_and_expires(self):
        calls = []
        with mock.patch.object(core_users, "_user_exists", return_value=True), \
             mock.patch.object(core_users, "_user_run",
                               side_effect=lambda *a, **k: calls.append(a[2]) or _Res()):
            events, result = _drain(core_users.suspend_user("host", "h", "alice"))
        self.assertTrue(result.ok)
        self.assertIn(["usermod", "--lock", "--expiredate", "1", "alice"], calls)

    def test_suspend_missing_user_raises(self):
        with mock.patch.object(core_users, "_user_exists", return_value=False):
            with self.assertRaises(NotFoundError):
                _drain(core_users.suspend_user("vm", "v", "ghost", host="node-a"))

    def test_grant_sudo_validates_with_visudo(self):
        seen = {}
        with mock.patch.object(core_users, "_user_exists", return_value=True), \
             mock.patch.object(core_users, "_user_run",
                               side_effect=lambda *a, **k: seen.update(argv=a[2]) or _Res()):
            _drain(core_users.set_user_sudo("vm", "v", "bob", True, host="node-a"))
        self.assertIn("visudo -cf", " ".join(seen["argv"]))

    def test_revoke_sudo_removes_dropin_and_groups(self):
        cmds = []
        with mock.patch.object(core_users, "_user_exists", return_value=True), \
             mock.patch.object(core_users, "_user_run",
                               side_effect=lambda *a, **k: cmds.append(a[2]) or _Res()):
            _drain(core_users.set_user_sudo("host", "h", "alice", False))
        flat = " ".join(" ".join(c) for c in cmds)
        self.assertIn("rm -f /etc/sudoers.d/90-hetzman-alice", flat)
        self.assertIn("gpasswd -d alice", flat)        # group sudo stripped too
        self.assertIn("sudo admin wheel", flat)

    def test_vm_scope_routes_incus_through_host(self):
        seen = {}

        def fake_run_on(host, argv, **kw):
            seen.update(host=host, argv=list(argv))
            return _Res()
        with mock.patch("hetzman.core.users.host_exec.run_on", side_effect=fake_run_on):
            core_users._user_run("vm", "myvm", ["id", "bob"], host="node-b", check=False)
        self.assertEqual(seen["host"], "node-b")
        self.assertEqual(seen["argv"][:4], ["incus", "exec", "myvm", "--"])


class AddUserTests(unittest.TestCase):
    @mock.patch("hetzman.core.users._push_key")
    @mock.patch("hetzman.core.users.run_vm_exec", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_user_exists", return_value=False)
    @mock.patch("hetzman.core.users.check_vm_exists", return_value=True)
    @mock.patch("hetzman.core.users.require_root")
    def test_add_success(self, root, exists, uexists, run, push):
        events, result = _drain(core_users.add_user("vm", "alice", "ssh-ed25519 AAAAk alice@h"))
        self.assertTrue(result.ok)
        self.assertTrue(any(e.severity == Severity.SUCCESS for e in events))
        push.assert_called_once()

    @mock.patch("hetzman.core.users._push_key", side_effect=CoreError("push failed"))
    @mock.patch("hetzman.core.users.run_vm_exec", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_user_exists", return_value=False)
    @mock.patch("hetzman.core.users.check_vm_exists", return_value=True)
    @mock.patch("hetzman.core.users.require_root")
    def test_add_key_push_failure_rolls_back_user(self, root, exists, uexists, run, push):
        with self.assertRaises(CoreError):
            _drain(core_users.add_user("vm", "alice", "ssh-ed25519 AAAAk alice@h"))
        # userdel cleanup must have run
        self.assertTrue(
            any(c.args[1][0] == "userdel" for c in run.call_args_list),
            "expected userdel rollback after key push failure",
        )

    @mock.patch("hetzman.core.users.check_vm_user_exists", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_exists", return_value=True)
    @mock.patch("hetzman.core.users.require_root")
    def test_add_existing_user_raises(self, root, exists, uexists):
        with self.assertRaises(ValidationError):
            _drain(core_users.add_user("vm", "alice", "ssh-ed25519 AAAAk alice@h"))


class RemoveUserTests(unittest.TestCase):
    @mock.patch("hetzman.core.users.run_vm_exec", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_user_exists", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_exists", return_value=True)
    @mock.patch("hetzman.core.users.require_root")
    def test_remove_success(self, root, exists, uexists, run):
        events, result = _drain(core_users.remove_user("vm", "alice"))
        self.assertTrue(result.ok)

    @mock.patch("hetzman.core.users.check_vm_user_exists", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_exists", return_value=True)
    @mock.patch("hetzman.core.users.require_root")
    def test_remove_root_refused(self, root, exists, uexists):
        with self.assertRaises(ValidationError):
            _drain(core_users.remove_user("vm", "root"))

    @mock.patch("hetzman.core.users.check_vm_user_exists", return_value=False)
    @mock.patch("hetzman.core.users.check_vm_exists", return_value=True)
    @mock.patch("hetzman.core.users.require_root")
    def test_remove_missing_user_raises(self, root, exists, uexists):
        with self.assertRaises(NotFoundError):
            _drain(core_users.remove_user("vm", "ghost"))


class ChangeKeysTests(unittest.TestCase):
    @mock.patch("hetzman.core.users._push_key")
    @mock.patch("hetzman.core.users.run_vm_exec", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_user_exists", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_exists", return_value=True)
    @mock.patch("hetzman.core.users.require_root")
    def test_change_keys_success(self, root, exists, uexists, run, push):
        events, result = _drain(core_users.change_keys("vm", "alice", "/new.pub"))
        self.assertTrue(result.ok)
        push.assert_called_once()


if __name__ == "__main__":
    unittest.main()
