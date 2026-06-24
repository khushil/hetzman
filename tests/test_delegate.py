"""Tests for commands/_delegate.run_or_delegate: local drives the generator;
remote streams the target's hetzman over SSH."""
import unittest
from unittest import mock

from hetzman.commands._delegate import run_or_delegate
from hetzman.core.events import OpResult, ProgressEvent, Severity


class DelegateTests(unittest.TestCase):
    @mock.patch("hetzman.commands._delegate.host_exec")
    def test_local_drives_generator(self, hx):
        hx.resolve_host.return_value = "node-a"
        hx.is_local.return_value = True

        def gen():
            yield ProgressEvent(Severity.SUCCESS, "done locally")
            return OpResult(ok=True)

        with mock.patch("hetzman.commands._delegate.drive") as drive:
            run_or_delegate("node-a", ["vm", "reboot", "x", "--yes"], gen)
            drive.assert_called_once()
        # never streamed remotely
        hx.stream_on.assert_not_called()

    @mock.patch("hetzman.commands._delegate.host_exec")
    def test_remote_streams_target_hetzman(self, hx):
        hx.resolve_host.return_value = "node-b"
        hx.is_local.return_value = False

        def fake_stream(host, argv, **kw):
            assert argv[0] == "hetzman"
            assert argv[1:] == ["vm", "reboot", "x", "--yes"]
            yield "Step 1/1: Rebooting x"
            yield "Rebooted x"
            return OpResult(ok=True)

        hx.stream_on.side_effect = fake_stream
        with mock.patch("hetzman.commands._delegate.console") as con:
            run_or_delegate("node-b", ["vm", "reboot", "x", "--yes"], lambda: None)
        printed = " ".join(str(c.args[0]) for c in con.print.call_args_list)
        self.assertIn("Rebooted x", printed)


if __name__ == "__main__":
    unittest.main()
