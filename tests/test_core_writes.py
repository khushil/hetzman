"""Tests for P3b write generators (dns, ports) and the drive() CLI adapter.

stdlib unittest + mock; no real etcd/network/root. We patch etcd_kv and the
reconcile side-effects so only the generator's logic and event stream are
exercised.
"""
import unittest
from unittest import mock

from hetzman.core import dns as core_dns
from hetzman.core import ports as core_ports
from hetzman.core.errors import CoreError, ValidationError
from hetzman.core.events import OpResult, ProgressEvent, Severity


def _drain(gen):
    """Run a ProgressGen to completion; return (events, OpResult)."""
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


class DnsWriteTests(unittest.TestCase):
    @mock.patch("hetzman.core.dns._reconcile")
    @mock.patch("hetzman.core.dns.get_settings")
    @mock.patch("hetzman.core.dns.etcd_kv.put_key", return_value=True)
    def test_add_dns_success_qualifies_and_reconciles(self, put_key, get_settings, reconcile):
        get_settings.return_value = mock.Mock(current_server="srv1")
        events, result = _drain(core_dns.add_dns("web", "1.2.3.4"))
        # key was qualified with the default domain
        key = put_key.call_args[0][0]
        self.assertEqual(key, "/hetzman/dns/web.daemondreams.home.arpa")
        self.assertEqual([e.severity for e in events], [Severity.SUCCESS])
        self.assertTrue(result.ok)
        self.assertEqual(result.summary["hostname"], "web.daemondreams.home.arpa")
        reconcile.assert_called_once()

    @mock.patch("hetzman.core.dns._reconcile")
    @mock.patch("hetzman.core.dns.get_settings")
    @mock.patch("hetzman.core.dns.etcd_kv.put_key", return_value=True)
    def test_add_dns_reconcile_false_skips_side_effects(self, put_key, get_settings, reconcile):
        get_settings.return_value = mock.Mock(current_server="srv1")
        _drain(core_dns.add_dns("web.example.com", "1.2.3.4", reconcile=False))
        reconcile.assert_not_called()

    @mock.patch("hetzman.core.dns.get_settings")
    @mock.patch("hetzman.core.dns.etcd_kv.put_key", return_value=False)
    def test_add_dns_put_failure_raises(self, put_key, get_settings):
        get_settings.return_value = mock.Mock(current_server="srv1")
        with self.assertRaises(CoreError):
            _drain(core_dns.add_dns("web", "1.2.3.4"))

    @mock.patch("hetzman.core.dns._reconcile")
    @mock.patch("hetzman.core.dns.etcd_kv.delete_key", return_value=True)
    def test_remove_dns_success(self, delete_key, reconcile):
        events, result = _drain(core_dns.remove_dns("web"))
        self.assertEqual([e.severity for e in events], [Severity.SUCCESS])
        self.assertTrue(result.ok)
        reconcile.assert_called_once()

    @mock.patch("hetzman.core.dns._reconcile")
    @mock.patch("hetzman.core.dns.etcd_kv.delete_key", return_value=False)
    def test_remove_dns_not_found_soft_fails(self, delete_key, reconcile):
        events, result = _drain(core_dns.remove_dns("web"))
        self.assertEqual([e.severity for e in events], [Severity.WARNING])
        self.assertFalse(result.ok)
        reconcile.assert_not_called()


class PortWriteTests(unittest.TestCase):
    def test_add_port_invalid_inputs_raise(self):
        with self.assertRaises(ValidationError):
            _drain(core_ports.add_port("vm", 0, 80))
        with self.assertRaises(ValidationError):
            _drain(core_ports.add_port("vm", 80, 99999))
        with self.assertRaises(ValidationError):
            _drain(core_ports.add_port("vm", 80, 80, protocol="sctp"))

    @mock.patch("hetzman.core.ports.get_settings")
    @mock.patch("hetzman.core.ports.etcd_kv.get_key", return_value=None)
    def test_add_port_no_public_ip_raises(self, get_key, get_settings):
        get_settings.return_value = mock.Mock(current_server="srv1")
        with self.assertRaises(ValidationError):
            _drain(core_ports.add_port("vm", 80, 8080))

    @mock.patch("hetzman.core.ports._reconcile")
    @mock.patch("hetzman.core.ports.get_settings")
    @mock.patch("hetzman.core.ports.etcd_kv.put_key", return_value=True)
    @mock.patch("hetzman.core.ports.etcd_kv.get_key")
    def test_add_port_success(self, get_key, put_key, get_settings, reconcile):
        get_settings.return_value = mock.Mock(current_server="srv1")
        get_key.return_value = '{"public_ip": "1.2.3.4", "private_ip": "10.0.0.5"}'
        events, result = _drain(core_ports.add_port("vm", 80, 8080, "tcp", "web"))
        self.assertEqual([e.severity for e in events], [Severity.SUCCESS])
        self.assertTrue(result.ok)
        self.assertEqual(result.summary["public_ip"], "1.2.3.4")
        self.assertEqual(result.summary["private_ip"], "10.0.0.5")
        reconcile.assert_called_once()
        # key shape: instance-publicport-protocol
        self.assertIn("vm-80-tcp", put_key.call_args[0][0])

    @mock.patch("hetzman.core.ports._reconcile")
    @mock.patch("hetzman.core.ports.get_settings")
    @mock.patch("hetzman.core.ports.etcd_kv.delete_key", return_value=False)
    def test_remove_port_not_found_soft_fails(self, delete_key, get_settings, reconcile):
        get_settings.return_value = mock.Mock(current_server="srv1")
        events, result = _drain(core_ports.remove_port("vm", 80))
        self.assertEqual([e.severity for e in events], [Severity.WARNING])
        self.assertFalse(result.ok)
        reconcile.assert_not_called()


class DriveAdapterTests(unittest.TestCase):
    def _drive(self, gen, **kw):
        from hetzman.commands._render import drive
        return drive(gen, **kw)

    def test_drive_returns_opresult_and_prints(self):
        def gen():
            yield ProgressEvent(Severity.STEP, "doing", step=1, total=2)
            yield ProgressEvent(Severity.SUCCESS, "done")
            return OpResult(ok=True, summary={"x": 1})

        with mock.patch("hetzman.commands._render.console") as con:
            result = self._drive(gen())
        self.assertTrue(result.ok)
        # printed once per event
        self.assertEqual(con.print.call_count, 2)

    def test_drive_maps_coreerror_to_exit1_and_closes(self):
        import typer

        closed = {"v": False}

        def gen():
            try:
                yield ProgressEvent(Severity.STEP, "start")
                raise CoreError("boom")
            finally:
                closed["v"] = True

        with mock.patch("hetzman.commands._render.console"):
            with self.assertRaises(typer.Exit) as ctx:
                self._drive(gen())
        self.assertEqual(ctx.exception.exit_code, 1)
        self.assertTrue(closed["v"])  # generator finally ran (compensation hook)

    def test_drive_exit_on_failure_flag(self):
        import typer

        def gen():
            yield ProgressEvent(Severity.WARNING, "not found")
            return OpResult(ok=False)

        with mock.patch("hetzman.commands._render.console"):
            # default: soft failure does NOT exit
            r = self._drive(gen())
            self.assertFalse(r.ok)
            # with flag: exits 1
            with self.assertRaises(typer.Exit):
                self._drive(gen(), exit_on_failure=True)


if __name__ == "__main__":
    unittest.main()
