"""Tests for the Phase-1 cross-host reads: list_instances fan-out (+unreachable),
check_updates parsing, reboot_required. exec + registry mocked."""
import unittest
from unittest import mock

from hetzman.core import reads
from hetzman.core.errors import HostUnreachable
from hetzman.core.exec import ExecResult

_VM = {
    "name": "web1", "type": "virtual-machine", "status": "Running",
    "config": {"limits.cpu": "4", "limits.memory": "8GB"},
    "devices": {"root": {"size": "50GB", "type": "disk"}},
    "state": {"network": {"eth0": {"addresses": [{"family": "inet", "address": "10.0.5.2"}]}}},
}
_CT = {  # a container with NO root size (real on the live fleet) + profile-inherited cpu
    "name": "ci-1", "type": "container", "status": "Running",
    "config": {}, "expanded_config": {"limits.cpu": "2"},
    "devices": {}, "expanded_devices": {"root": {"type": "disk"}},  # no size
}


class ListInstancesTests(unittest.TestCase):
    @mock.patch("hetzman.core.reads.host_exec.incus_json")
    def test_single_host(self, incus_json):
        incus_json.return_value = [_VM, _CT]
        items, unreachable = reads.list_instances("node-a")
        self.assertEqual(unreachable, [])
        self.assertEqual([i.name for i in items], ["web1", "ci-1"])
        vm = items[0]
        self.assertEqual((vm.host, vm.type, vm.cpus, vm.memory, vm.disk, vm.private_ip),
                         ("node-a", "virtual-machine", 4, "8GB", "50GB", "10.0.5.2"))
        ct = items[1]
        self.assertEqual((ct.cpus, ct.disk), (2, None))  # expanded cpu; no disk baseline

    @mock.patch("hetzman.core.reads.load_registry", return_value={"node-a": {}, "node-b": {}})
    @mock.patch("hetzman.core.reads.host_exec.incus_json")
    def test_fleet_fanout_partial_on_unreachable(self, incus_json, reg):
        def side(host, args, **kw):
            if host == "node-b":
                raise HostUnreachable("node-b down")
            return [_VM]
        incus_json.side_effect = side
        items, unreachable = reads.list_instances(None)
        self.assertEqual([i.name for i in items], ["web1"])
        self.assertEqual(unreachable, ["node-b"])  # partial result, not a crash


class UpdatesTests(unittest.TestCase):
    @mock.patch("hetzman.core.reads.host_exec.run_on")
    def test_check_updates_parses_and_counts_security(self, run_on):
        run_on.return_value = ExecResult(
            0,
            "Listing...\n"
            "bash/now 5.1 amd64 [upgradable from: 5.0]\n"
            "openssl/focal-security 1.1 amd64 [upgradable from: 1.0]\n",
            "WARNING: apt does not have a stable CLI\n",
        )
        st = reads.check_updates("node-a")
        self.assertEqual(st.count, 2)
        self.assertEqual(st.security_count, 1)
        self.assertEqual(st.packages, ("bash", "openssl"))

    @mock.patch("hetzman.core.reads.host_exec.run_on")
    def test_reboot_required_true_false(self, run_on):
        run_on.return_value = ExecResult(0, "", "")
        self.assertTrue(reads.reboot_required("node-a"))
        run_on.return_value = ExecResult(1, "", "")
        self.assertFalse(reads.reboot_required("node-a"))


if __name__ == "__main__":
    unittest.main()
