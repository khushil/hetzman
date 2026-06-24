"""Tests for core/exec.py: local-vs-ssh argv, remote quoting, error mapping,
external-mode resolution, and stream_on (no stderr deadlock).

No real fleet/ssh: subprocess.run/Popen and the registry are mocked.
"""
import subprocess
import unittest
from unittest import mock

from hetzman.core import exec as ex
from hetzman.core.errors import CoreError, HostUnreachable, NotFoundError, ValidationError

_REGISTRY = {
    "node-a": {"vswitch_ip": "10.0.0.1"},
    "node-b": {"vswitch_ip": "10.0.0.2"},
}


def _settings(current):
    return mock.Mock(current_server=current)


def _completed(rc=0, out="", err=""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=out, stderr=err)


class ResolveAndLocalTests(unittest.TestCase):
    @mock.patch("hetzman.core.exec.get_settings")
    def test_is_local(self, gs):
        gs.return_value = _settings("node-a")
        self.assertTrue(ex.is_local("node-a"))
        self.assertFalse(ex.is_local("node-b"))
        gs.return_value = _settings(None)  # external box
        self.assertFalse(ex.is_local("node-a"))

    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_resolve_host(self, gs, reg):
        gs.return_value = _settings("node-a")
        self.assertEqual(ex.resolve_host(None), "node-a")        # on-node default
        self.assertEqual(ex.resolve_host("node-b"), "node-b")    # explicit, in registry
        with self.assertRaises(NotFoundError):
            ex.resolve_host("ghost")
        gs.return_value = _settings(None)  # external + no host -> must raise
        with self.assertRaises(ValidationError):
            ex.resolve_host(None)


class RunOnArgvTests(unittest.TestCase):
    """The local path must reproduce today's exact argv; remote must ssh+quote."""

    @mock.patch("hetzman.core.exec.subprocess.run")
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_local_incus_is_byte_identical_to_legacy(self, gs, reg, run):
        gs.return_value = _settings("node-a")
        run.return_value = _completed(out="[]")
        ex.incus("node-a", ["list"])
        # legacy callers ran exactly ["sudo", "incus", "list"]
        self.assertEqual(run.call_args[0][0], ["sudo", "incus", "list"])

    @mock.patch("hetzman.core.exec.subprocess.run")
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_remote_uses_ssh_no_sudo_and_quotes(self, gs, reg, run):
        gs.return_value = _settings("node-a")  # target node-b is remote
        run.return_value = _completed(out="[]")
        ex.incus("node-b", ["list"])
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("StrictHostKeyChecking=yes", cmd)
        self.assertEqual(cmd[-2], "root@10.0.0.2")
        # remote command is a single shell-quoted string, no sudo
        self.assertEqual(cmd[-1], "incus list")
        self.assertNotIn("sudo", cmd[-1])

    @mock.patch("hetzman.core.exec.subprocess.run")
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_remote_shell_quotes_special_args(self, gs, reg, run):
        gs.return_value = _settings(None)  # external -> everything remote
        run.return_value = _completed(out="")
        ex.run_on("node-a", ["sh", "-c", "echo a b; rm -rf /"])
        remote = run.call_args[0][0][-1]
        # the dangerous arg must be a single quoted token, not split/executed
        self.assertIn("'echo a b; rm -rf /'", remote)

    @mock.patch("hetzman.core.exec.subprocess.run")
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_ssh_255_maps_to_hostunreachable(self, gs, reg, run):
        gs.return_value = _settings("node-a")
        run.return_value = _completed(rc=255, err="connection refused")
        with self.assertRaises(HostUnreachable):
            ex.run_on("node-b", ["true"])

    @mock.patch("hetzman.core.exec.subprocess.run")
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_nonzero_local_maps_to_coreerror(self, gs, reg, run):
        gs.return_value = _settings("node-a")
        run.return_value = _completed(rc=1, err="boom")
        with self.assertRaises(CoreError):
            ex.run_on("node-a", ["false"])

    @mock.patch("hetzman.core.exec.subprocess.run", side_effect=subprocess.TimeoutExpired("x", 5))
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_timeout_maps_to_coreerror(self, gs, reg, run):
        gs.return_value = _settings("node-a")
        with self.assertRaises(CoreError):
            ex.run_on("node-a", ["sleep"])

    @mock.patch("hetzman.core.exec.subprocess.run")
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_input_is_forwarded_to_subprocess(self, gs, reg, run):
        # the host-user 'tee' key-push relies on input= reaching the ssh subprocess.
        gs.return_value = _settings(None)  # external -> remote ssh path
        run.return_value = _completed()
        ex.run_on("node-a", ["tee", "/x"], input="ssh-ed25519 KEY")
        self.assertEqual(run.call_args.kwargs["input"], "ssh-ed25519 KEY")

    @mock.patch("hetzman.core.exec.subprocess.run")
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_incus_json_parses(self, gs, reg, run):
        gs.return_value = _settings("node-a")
        run.return_value = _completed(out='[{"name":"vm1"}]')
        data = ex.incus_json("node-a", ["list"])
        self.assertEqual(data[0]["name"], "vm1")
        self.assertIn("--format", run.call_args[0][0])


class StreamOnTests(unittest.TestCase):
    @mock.patch("hetzman.core.exec.subprocess.Popen")
    @mock.patch("hetzman.core.exec.load_registry", return_value=_REGISTRY)
    @mock.patch("hetzman.core.exec.get_settings")
    def test_stream_yields_lines_and_merges_stderr(self, gs, reg, popen):
        gs.return_value = _settings("node-a")
        fake = mock.Mock()
        stdout = mock.MagicMock()
        stdout.__iter__.return_value = iter(["line1\n", "line2\n"])
        fake.stdout = stdout  # MagicMock supports .close()
        fake.wait.return_value = 0
        fake.returncode = 0
        popen.return_value = fake
        lines = []
        gen = ex.stream_on("node-a", ["apt-get", "upgrade"])
        try:
            while True:
                lines.append(next(gen))
        except StopIteration as stop:
            result = stop.value
        self.assertEqual(lines, ["line1", "line2"])
        self.assertEqual(result.returncode, 0)
        # stderr must be merged into stdout to avoid pipe-buffer deadlock
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.STDOUT)


if __name__ == "__main__":
    unittest.main()
