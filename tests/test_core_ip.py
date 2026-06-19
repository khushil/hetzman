"""Tests for core/ip.py: atomic pool claim (CAS), sync_lock, and rollback.

stdlib unittest + mock; no real etcd/incus/root.
"""
import unittest
from contextlib import contextmanager
from unittest import mock

from hetzman.core import ip as core_ip
from hetzman.core.errors import CoreError, ValidationError
from hetzman.core.events import Severity


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


class ClaimPoolIpTests(unittest.TestCase):
    """The CAS claim is the correctness-critical piece."""

    def _pool(self):
        return {
            "/hetzman/ip-pool/1.1.1.1": {"server": "srv1", "status": "available"},
            "/hetzman/ip-pool/1.1.1.2": {"server": "srv1", "status": "assigned"},
            "/hetzman/ip-pool/2.2.2.2": {"server": "srv2", "status": "available"},
        }

    @mock.patch("hetzman.core.ip.etcd_kv.replace_if_value", return_value=True)
    @mock.patch("hetzman.core.ip.etcd_kv.get_key")
    @mock.patch("hetzman.core.ip.etcd_kv.get_all_with_prefix")
    def test_auto_claims_first_available_for_server(self, prefix, get_key, cas):
        prefix.return_value = self._pool()
        get_key.return_value = '{"server": "srv1", "status": "available"}'
        chosen = core_ip._claim_pool_ip("srv1", "vm", None)
        self.assertEqual(chosen, "1.1.1.1")  # not the assigned .2, not srv2's
        cas.assert_called_once()  # claimed via compare-and-swap, not a bare put

    @mock.patch("hetzman.core.ip.etcd_kv.replace_if_value", return_value=False)
    @mock.patch("hetzman.core.ip.etcd_kv.get_key")
    @mock.patch("hetzman.core.ip.etcd_kv.get_all_with_prefix")
    def test_cas_loss_on_only_candidate_raises(self, prefix, get_key, cas):
        # One available IP, but the CAS keeps losing (a concurrent claimant won).
        prefix.return_value = {"/hetzman/ip-pool/1.1.1.1": {"server": "srv1", "status": "available"}}
        get_key.return_value = '{"server": "srv1", "status": "available"}'
        with self.assertRaises(ValidationError):
            core_ip._claim_pool_ip("srv1", "vm", None)

    @mock.patch("hetzman.core.ip.etcd_kv.get_all_with_prefix", return_value={})
    def test_no_ips_raises(self, prefix):
        with self.assertRaises(ValidationError):
            core_ip._claim_pool_ip("srv1", "vm", None)

    @mock.patch("hetzman.core.ip.etcd_kv.get_all_with_prefix")
    def test_specific_ip_not_available_raises(self, prefix):
        prefix.return_value = {"/hetzman/ip-pool/1.1.1.2": {"server": "srv1", "status": "assigned"}}
        with self.assertRaises(ValidationError):
            core_ip._claim_pool_ip("srv1", "vm", "1.1.1.2")


class AssignIpTests(unittest.TestCase):
    @mock.patch("hetzman.core.ip.restart_instance_watcher")
    @mock.patch("hetzman.core.ip.network")
    @mock.patch("hetzman.core.ip.sync_lock", lambda: _lock(True))
    @mock.patch("hetzman.core.ip._claim_pool_ip", return_value="1.1.1.1")
    @mock.patch("hetzman.core.ip._wait_for_private_ip")
    @mock.patch("hetzman.core.ip.etcd_kv")
    @mock.patch("hetzman.core.ip.get_settings")
    def test_assign_success(self, gs, kv, wait, claim, net, watcher):
        gs.return_value = mock.Mock(current_server="srv1")
        kv.get_key.return_value = None  # no existing NAT
        wait.side_effect = lambda instance: _mk_wait("10.0.0.5")
        net.add_ip_to_interface.return_value = True

        events, result = _drain(core_ip.assign_ip("vm"))
        self.assertTrue(result.ok)
        self.assertEqual(result.summary["public_ip"], "1.1.1.1")
        self.assertEqual(result.summary["private_ip"], "10.0.0.5")
        self.assertTrue(any(e.severity == Severity.SUCCESS for e in events))
        net.apply_nat_rules.assert_called_once()

    @mock.patch("hetzman.core.ip._release_pool_ip")
    @mock.patch("hetzman.core.ip.network")
    @mock.patch("hetzman.core.ip.sync_lock", lambda: _lock(True))
    @mock.patch("hetzman.core.ip._claim_pool_ip", return_value="1.1.1.1")
    @mock.patch("hetzman.core.ip._wait_for_private_ip")
    @mock.patch("hetzman.core.ip.etcd_kv")
    @mock.patch("hetzman.core.ip.get_settings")
    def test_assign_interface_failure_rolls_back_claim(self, gs, kv, wait, claim, net, release):
        gs.return_value = mock.Mock(current_server="srv1")
        kv.get_key.return_value = None
        wait.side_effect = lambda instance: _mk_wait("10.0.0.5")
        net.add_ip_to_interface.return_value = False  # interface add fails

        with self.assertRaises(CoreError):
            _drain(core_ip.assign_ip("vm"))
        # the claimed pool IP must be reverted so it is not orphaned
        release.assert_called_once_with("1.1.1.1")

    @mock.patch("hetzman.core.ip.network")
    @mock.patch("hetzman.core.ip.sync_lock", lambda: _lock(False))  # watcher holds lock
    @mock.patch("hetzman.core.ip._wait_for_private_ip")
    @mock.patch("hetzman.core.ip.etcd_kv")
    @mock.patch("hetzman.core.ip.get_settings")
    def test_assign_aborts_on_lock_contention(self, gs, kv, wait, net):
        gs.return_value = mock.Mock(current_server="srv1")
        kv.get_key.return_value = None
        wait.side_effect = lambda instance: _mk_wait("10.0.0.5")
        with self.assertRaises(CoreError):
            _drain(core_ip.assign_ip("vm"))

    @mock.patch("hetzman.core.ip.etcd_kv")
    @mock.patch("hetzman.core.ip.get_settings")
    def test_assign_already_assigned_raises(self, gs, kv):
        gs.return_value = mock.Mock(current_server="srv1")
        kv.get_key.return_value = '{"public_ip": "1.1.1.1"}'
        with self.assertRaises(ValidationError):
            _drain(core_ip.assign_ip("vm"))


class ReleaseIpTests(unittest.TestCase):
    @mock.patch("hetzman.core.ip.etcd_kv")
    @mock.patch("hetzman.core.ip.get_settings")
    def test_release_no_nat_soft_fails(self, gs, kv):
        gs.return_value = mock.Mock(current_server="srv1")
        kv.get_key.return_value = None
        events, result = _drain(core_ip.release_ip("vm"))
        self.assertFalse(result.ok)
        self.assertEqual([e.severity for e in events], [Severity.WARNING])

    @mock.patch("hetzman.core.ip.restart_instance_watcher")
    @mock.patch("hetzman.core.ip.network")
    @mock.patch("hetzman.core.ip.sync_lock", lambda: _lock(True))
    @mock.patch("hetzman.core.ip.etcd_kv")
    @mock.patch("hetzman.core.ip.get_settings")
    def test_release_success_clears_nat_ports_pool(self, gs, kv, net, watcher):
        gs.return_value = mock.Mock(current_server="srv1")
        kv.get_key.side_effect = [
            '{"public_ip": "1.1.1.1"}',                       # nat lookup
            '{"status": "assigned", "assigned_to": "vm"}',    # pool lookup
        ]
        kv.get_all_with_prefix.return_value = {
            "/hetzman/port-forward/srv1/vm-80-tcp": {"instance_name": "vm"},
            "/hetzman/port-forward/srv1/other-80-tcp": {"instance_name": "other"},
        }
        net.remove_ip_from_interface.return_value = True
        events, result = _drain(core_ip.release_ip("vm"))
        self.assertTrue(result.ok)
        # NAT deleted + the vm's port forward deleted (not other's)
        deleted = [c.args[0] for c in kv.delete_key.call_args_list]
        self.assertIn("/hetzman/nat/srv1/vm", deleted)
        self.assertIn("/hetzman/port-forward/srv1/vm-80-tcp", deleted)
        self.assertNotIn("/hetzman/port-forward/srv1/other-80-tcp", deleted)
        net.apply_nat_rules.assert_called_once()


def _mk_wait(ip):
    """Build a _wait_for_private_ip-style sub-generator that returns *ip*."""
    def gen():
        return ip
        yield  # pragma: no cover - make it a generator
    return gen()


if __name__ == "__main__":
    unittest.main()
