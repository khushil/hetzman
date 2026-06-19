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


class AddUserTests(unittest.TestCase):
    @mock.patch("hetzman.core.users._push_key")
    @mock.patch("hetzman.core.users.run_vm_exec", return_value=True)
    @mock.patch("hetzman.core.users.check_vm_user_exists", return_value=False)
    @mock.patch("hetzman.core.users.check_vm_exists", return_value=True)
    @mock.patch("hetzman.core.users.require_root")
    def test_add_success(self, root, exists, uexists, run, push):
        events, result = _drain(core_users.add_user("vm", "alice", "/k.pub"))
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
            _drain(core_users.add_user("vm", "alice", "/k.pub"))
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
            _drain(core_users.add_user("vm", "alice", "/k.pub"))


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
