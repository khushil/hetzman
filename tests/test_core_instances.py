"""Tests for core/instances.py: live resize, disk grow-only, restart fallback,
the size parser, and reboot. exec mocked (runs on the target via delegation)."""
import unittest
from unittest import mock

from hetzman.core import instances as ci
from hetzman.core.errors import CoreError, NotFoundError, ValidationError
from hetzman.core.events import Severity


def _drain(gen):
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


def _inst(status="Running", disk="50GB"):
    d = {"name": "vm1", "type": "virtual-machine", "status": status,
         "config": {}, "devices": {}}
    if disk is not None:
        d["devices"]["root"] = {"size": disk, "type": "disk"}
    return d


class SizeParserTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(ci._to_bytes("1GB"), 10**9)
        self.assertEqual(ci._to_bytes("1GiB"), 2**30)
        self.assertEqual(ci._to_bytes("250GB"), 250 * 10**9)
        self.assertGreater(ci._to_bytes("1GiB"), ci._to_bytes("1GB"))  # GiB > GB
        with self.assertRaises(ValidationError):
            ci._to_bytes("lots")


class ChangeInstanceTests(unittest.TestCase):
    @mock.patch("hetzman.core.instances.require_root")
    def test_requires_a_field(self, root):
        with self.assertRaises(ValidationError):
            _drain(ci.change_instance("vm1"))

    @mock.patch("hetzman.core.instances.host_exec")
    @mock.patch("hetzman.core.instances.require_root")
    def test_cpu_memory_live_no_restart(self, root, hx):
        hx.incus_json.return_value = [_inst()]
        events, result = _drain(ci.change_instance("vm1", cpus=8, memory="16GB"))
        self.assertTrue(result.ok)
        # two config sets, NO stop/start (live)
        calls = [c.args[1] for c in hx.incus.call_args_list]
        self.assertIn(["config", "set", "vm1", "limits.cpu=8"], calls)
        self.assertIn(["config", "set", "vm1", "limits.memory=16GB"], calls)
        self.assertFalse(any("stop" in c or "start" in c for c in calls))

    @mock.patch("hetzman.core.instances.host_exec")
    @mock.patch("hetzman.core.instances.require_root")
    def test_disk_grow_ok(self, root, hx):
        hx.incus_json.return_value = [_inst(disk="50GB")]
        events, result = _drain(ci.change_instance("vm1", disk="100GB"))
        self.assertTrue(result.ok)
        calls = [c.args[1] for c in hx.incus.call_args_list]
        self.assertIn(["config", "device", "set", "vm1", "root", "size=100GB"], calls)

    @mock.patch("hetzman.core.instances.host_exec")
    @mock.patch("hetzman.core.instances.require_root")
    def test_disk_shrink_refused(self, root, hx):
        hx.incus_json.return_value = [_inst(disk="100GB")]
        with self.assertRaises(ValidationError):
            _drain(ci.change_instance("vm1", disk="50GB"))
        hx.incus.assert_not_called()

    @mock.patch("hetzman.core.instances.host_exec")
    @mock.patch("hetzman.core.instances.require_root")
    def test_disk_no_baseline_refused(self, root, hx):
        # container with no root size (real on the live btrfs CI containers)
        hx.incus_json.return_value = [_inst(disk=None)]
        with self.assertRaises(ValidationError):
            _drain(ci.change_instance("vm1", disk="100GB"))

    @mock.patch("hetzman.core.instances.host_exec")
    @mock.patch("hetzman.core.instances.require_root")
    def test_live_failure_falls_back_to_restart(self, root, hx):
        hx.incus_json.return_value = [_inst(status="Running")]
        # first config set fails -> stop, re-apply, start
        calls = {"n": 0}

        def incus(host, argv, **kw):
            if argv[:2] == ["config", "set"] and calls["n"] == 0:
                calls["n"] += 1
                raise CoreError("needs restart")
            return mock.Mock()
        hx.incus.side_effect = incus
        events, result = _drain(ci.change_instance("vm1", cpus=8))
        self.assertTrue(result.ok)
        argvs = [c.args[1][0] for c in hx.incus.call_args_list]
        self.assertIn("stop", argvs)
        self.assertIn("start", argvs)
        self.assertTrue(any(e.severity == Severity.WARNING for e in events))

    @mock.patch("hetzman.core.instances.host_exec")
    @mock.patch("hetzman.core.instances.require_root")
    def test_not_found(self, root, hx):
        hx.incus_json.return_value = []
        with self.assertRaises(NotFoundError):
            _drain(ci.change_instance("ghost", cpus=2))


class RebootTests(unittest.TestCase):
    @mock.patch("hetzman.core.instances.host_exec")
    @mock.patch("hetzman.core.instances.require_root")
    def test_reboot(self, root, hx):
        hx.incus_json.return_value = [_inst()]
        events, result = _drain(ci.reboot_instance("vm1"))
        self.assertTrue(result.ok)
        self.assertEqual(hx.incus.call_args.args[1], ["restart", "vm1"])


if __name__ == "__main__":
    unittest.main()
