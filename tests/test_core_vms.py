"""Tests for core/vms.py: composition, rollback/compensation, cancellation.

stdlib unittest + mock; no real incus/etcd/root. The leaf generators
(assign_ip/add_dns/add_port/release_ip/remove_dns) are patched so we test the
compose + undo logic, which is the high-risk part.
"""
import unittest
from contextlib import contextmanager
from unittest import mock

from hetzman.core import vms as core_vms
from hetzman.core.errors import CoreError, ValidationError
from hetzman.core.events import OpResult, ProgressEvent, Severity


def _drain(gen):
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


@contextmanager
def _lock(acquired=True):
    yield acquired


def _leaf(summary=None, events=()):
    """Build a leaf-style sub-generator yielding *events*, returning an OpResult."""
    def gen(*a, **k):
        for e in events:
            yield e
        return OpResult(ok=True, summary=summary or {})
    return gen


class CreateVmTests(unittest.TestCase):
    BASE = dict(
        require_root=mock.DEFAULT,
        check_vm_exists=mock.DEFAULT,
    )

    def _patches(self):
        return mock.patch.multiple(
            "hetzman.core.vms",
            require_root=mock.DEFAULT,
            check_vm_exists=mock.DEFAULT,
            get_settings=mock.DEFAULT,
            _incus_launch=mock.DEFAULT,
            _wait_private_ip=mock.DEFAULT,
            _incus_stop_delete=mock.DEFAULT,
            secure_vm_instance=mock.DEFAULT,
            restart_instance_watcher=mock.DEFAULT,
            network=mock.DEFAULT,
            sync_lock=mock.DEFAULT,
            assign_ip=mock.DEFAULT,
            add_dns=mock.DEFAULT,
            add_port=mock.DEFAULT,
            release_ip=mock.DEFAULT,
            remove_dns=mock.DEFAULT,
        )

    def test_create_public_success_composes_and_reconciles_once(self):
        with self._patches() as m:
            m["check_vm_exists"].return_value = False
            m["get_settings"].return_value = mock.Mock(current_server="srv1")
            m["_wait_private_ip"].return_value = "10.0.0.5"
            m["secure_vm_instance"].return_value = True
            m["sync_lock"].side_effect = lambda: _lock(True)
            m["assign_ip"].side_effect = _leaf(summary={"public_ip": "1.1.1.1"})
            m["add_dns"].side_effect = _leaf()
            events, result = _drain(core_vms.create_vm("vm1", network_type="public"))

        self.assertTrue(result.ok)
        self.assertEqual(result.summary["public_ip"], "1.1.1.1")
        self.assertEqual(result.summary["private_ip"], "10.0.0.5")
        # reconcile hoisted: apply_nat_rules called exactly once by create_vm
        self.assertEqual(m["network"].apply_nat_rules.call_count, 1)
        # 5 STEP events
        steps = [e for e in events if e.severity == Severity.STEP]
        self.assertEqual(len(steps), 5)

    def test_create_container_passes_type_through(self):
        with self._patches() as m:
            m["check_vm_exists"].return_value = False
            m["get_settings"].return_value = mock.Mock(current_server="srv1")
            m["_wait_private_ip"].return_value = "10.100.1.5"
            m["secure_vm_instance"].return_value = True
            m["sync_lock"].side_effect = lambda: _lock(True)
            m["add_dns"].side_effect = _leaf()
            events, result = _drain(
                core_vms.create_vm("ct1", network_type="private", instance_type="container")
            )
        self.assertTrue(result.ok)
        self.assertEqual(result.summary["type"], "container")
        # the type reached _incus_launch
        _args, kwargs = m["_incus_launch"].call_args
        passed = kwargs.get("instance_type", _args[-1] if _args else None)
        self.assertEqual(passed, "container")

    def test_create_rejects_bad_instance_type(self):
        with self._patches() as m:
            m["check_vm_exists"].return_value = False
            with self.assertRaises(ValidationError):
                _drain(core_vms.create_vm("x", instance_type="lxc"))

    def test_create_failure_rolls_back_ip_dns_and_instance(self):
        with self._patches() as m:
            m["check_vm_exists"].return_value = False
            m["get_settings"].return_value = mock.Mock(current_server="srv1")
            m["_wait_private_ip"].return_value = "10.0.0.5"
            m["sync_lock"].side_effect = lambda: _lock(True)
            m["assign_ip"].side_effect = _leaf(summary={"public_ip": "1.1.1.1"})
            m["add_dns"].side_effect = _leaf()
            m["release_ip"].side_effect = _leaf()
            m["remove_dns"].side_effect = _leaf()
            # secure step raises -> triggers rollback
            m["secure_vm_instance"].side_effect = RuntimeError("boom")

            with self.assertRaises(CoreError):
                _drain(core_vms.create_vm("vm1", network_type="public"))

            # compensation ran in reverse: dns removed, ip released, instance deleted
            m["remove_dns"].assert_called()
            m["release_ip"].assert_called()
            m["_incus_stop_delete"].assert_called_once_with("vm1")

    def test_create_cancellation_rolls_back_silently(self):
        with self._patches() as m:
            m["check_vm_exists"].return_value = False
            m["get_settings"].return_value = mock.Mock(current_server="srv1")
            m["_wait_private_ip"].return_value = "10.0.0.5"
            m["sync_lock"].side_effect = lambda: _lock(True)
            m["assign_ip"].side_effect = _leaf(summary={"public_ip": "1.1.1.1"})
            m["add_dns"].side_effect = _leaf()
            m["release_ip"].side_effect = _leaf()
            m["remove_dns"].side_effect = _leaf()
            m["secure_vm_instance"].return_value = True

            gen = core_vms.create_vm("vm1", network_type="public")
            # 1st next: suspended at the "Launching" yield (launch not run yet).
            next(gen)
            # 2nd next: runs _incus_launch + pushes the undo, suspends at SUCCESS.
            next(gen)
            gen.close()  # GeneratorExit -> silent rollback of the launched instance
            m["_incus_stop_delete"].assert_called_once_with("vm1")

    def test_create_existing_vm_raises_before_launch(self):
        with self._patches() as m:
            m["check_vm_exists"].return_value = True
            with self.assertRaises(ValidationError):
                _drain(core_vms.create_vm("vm1"))
            m["_incus_launch"].assert_not_called()

    def test_create_aborts_on_lock_contention(self):
        with self._patches() as m:
            m["check_vm_exists"].return_value = False
            m["get_settings"].return_value = mock.Mock(current_server="srv1")
            m["_wait_private_ip"].return_value = "10.0.0.5"
            m["sync_lock"].side_effect = lambda: _lock(False)  # watcher holds it
            with self.assertRaises(CoreError):
                _drain(core_vms.create_vm("vm1", network_type="public"))
            # launched instance is rolled back
            m["_incus_stop_delete"].assert_called_once_with("vm1")


class ChangeVmTests(unittest.TestCase):
    @mock.patch("hetzman.core.instances.require_root")
    def test_change_vm_shim_requires_a_field(self, root):
        # change_vm now shims to change_instance, which validates after require_root.
        with self.assertRaises(ValidationError):
            _drain(core_vms.change_vm("vm1"))


if __name__ == "__main__":
    unittest.main()
