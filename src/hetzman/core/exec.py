"""Host executor — run a command on a fleet host, locally or over SSH.

The single seam for reaching ANY fleet host. Used for two things:

* **fleet-wide reads** (``incus list`` / ``apt list`` on each node), and
* **delegation** of a host-touching mutation: the command layer runs the
  TARGET node's own ``hetzman`` over SSH (see ``commands/_delegate.py``) rather
  than orchestrating incus/etcd/iptables step-by-step from the centre.

It is NEVER used to remote individual incus/etcd/network steps — that path was
rejected in review (broken reconcile, lock-skip-as-success).

Console-free. Decision: a host is *local* iff it equals this node's
``current_server`` (so on an external command-centre box, where
``current_server is None``, everything is remote). Remote = ``ssh root@<vswitch_ip>``
with strict host-key checking against a pinned ``known_hosts`` (vswitch IPs come
from the registry this tool can write, so TOFU would be unsafe). The remote
login is already root, so no ``sudo``; argv is shell-quoted into a single command
string because ssh re-tokenizes through the remote shell.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass
from typing import Any, Generator, Optional, Sequence

from ..config import SSH_KNOWN_HOSTS, get_settings
from ..logging import log_message
from ..registry import load_registry
from .errors import CoreError, HostUnreachable, NotFoundError, ValidationError

_SSH_OPTS = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-o", "StrictHostKeyChecking=yes",
    "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
]


@dataclass(frozen=True)
class ExecResult:
    returncode: int
    stdout: str
    stderr: str


def is_local(host: Optional[str]) -> bool:
    """True iff *host* is this node (so we run the command directly)."""
    current = get_settings().current_server
    return current is not None and host == current


def resolve_host(explicit: Optional[str]) -> str:
    """Resolve the target host: an explicit name (validated against the registry),
    else this node, else raise (external mode must name a host)."""
    if explicit:
        if explicit not in load_registry():
            raise NotFoundError(f"host {explicit!r} is not in the fleet registry")
        return explicit
    current = get_settings().current_server
    if current:
        return current
    raise ValidationError(
        "no target host: pass an explicit --host (external mode has no local node)"
    )


def _vswitch_ip(host: str, registry: Optional[dict] = None) -> str:
    nodes = registry if registry is not None else load_registry()
    entry = nodes.get(host)
    if not entry or not entry.get("vswitch_ip"):
        raise NotFoundError(f"host {host!r} has no vswitch_ip in the registry")
    return str(entry["vswitch_ip"])


def _resolve_target(host: Optional[str]) -> str:
    target = host if host is not None else get_settings().current_server
    if target is None:
        raise ValidationError("no target host (external mode requires an explicit host)")
    return target


def _local_cmd(argv: list[str], root: bool) -> list[str]:
    # On a node we are already root (ops call require_root), but prepend sudo when
    # asked, matching the historical argv exactly (sudo is a no-op when euid 0).
    return (["sudo", *argv] if root else list(argv))


def _ssh_cmd(host: str, argv: list[str], registry: Optional[dict]) -> list[str]:
    ip = _vswitch_ip(host, registry)
    # ssh concatenates remote args and re-parses them through the remote shell,
    # so send ONE shell-quoted command string (never rely on argv separation).
    remote = " ".join(shlex.quote(a) for a in argv)
    return ["ssh", *_SSH_OPTS, f"root@{ip}", remote]


def run_on(
    host: Optional[str],
    argv: Sequence[Any],
    *,
    root: bool = False,
    timeout: int = 120,
    check: bool = True,
    input: Optional[str] = None,
    registry: Optional[dict] = None,
) -> ExecResult:
    """Run *argv* on *host* (local or via SSH). Remote runs as root (no sudo)."""
    target = _resolve_target(host)
    argv = [str(a) for a in argv]
    local = is_local(target)
    cmd = _local_cmd(argv, root) if local else _ssh_cmd(target, argv, registry)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input=input
        )
    except subprocess.TimeoutExpired:
        raise CoreError(f"{target}: '{argv[0]}' timed out after {timeout}s")
    except OSError as exc:
        raise CoreError(f"{target}: could not run '{argv[0]}': {exc}")

    log_message(f"exec {'local' if local else 'ssh:' + target}: {argv[0]} rc={proc.returncode}")
    if not local and proc.returncode == 255:
        raise HostUnreachable(f"{target}: SSH failed: {proc.stderr.strip()[:300]}")
    if check and proc.returncode != 0:
        raise CoreError(
            f"{target}: '{argv[0]}' failed (rc={proc.returncode}): {proc.stderr.strip()[:400]}"
        )
    return ExecResult(proc.returncode, proc.stdout, proc.stderr)


def stream_on(
    host: Optional[str],
    argv: Sequence[Any],
    *,
    root: bool = False,
    timeout: int = 600,
    check: bool = True,
    registry: Optional[dict] = None,
) -> Generator[str, None, ExecResult]:
    """Run a long command and yield its output line by line; return ExecResult.

    stderr is merged into stdout so the unbounded output of apt/incus can never
    deadlock against a tight consumer loop on a full stderr pipe.
    """
    target = _resolve_target(host)
    argv = [str(a) for a in argv]
    local = is_local(target)
    cmd = _local_cmd(argv, root) if local else _ssh_cmd(target, argv, registry)
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except OSError as exc:
        raise CoreError(f"{target}: could not start '{argv[0]}': {exc}")

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line.rstrip("\n")
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise CoreError(f"{target}: '{argv[0]}' timed out after {timeout}s")
    finally:
        if proc.stdout is not None:
            proc.stdout.close()

    rc = proc.returncode
    log_message(f"exec-stream {'local' if local else 'ssh:' + target}: {argv[0]} rc={rc}")
    if not local and rc == 255:
        raise HostUnreachable(f"{target}: SSH failed")
    if check and rc != 0:
        raise CoreError(f"{target}: '{argv[0]}' failed (rc={rc})")
    return ExecResult(rc, "", "")


def incus(host: Optional[str], args: Sequence[Any], **kw) -> ExecResult:
    """Run ``incus <args>`` on *host* (root)."""
    return run_on(host, ["incus", *args], root=True, **kw)


def incus_json(host: Optional[str], args: Sequence[Any], *, timeout: int = 30) -> Any:
    """Run ``incus <args> --format json`` on *host* and parse the result."""
    res = incus(host, [*args, "--format", "json"], timeout=timeout)
    return json.loads(res.stdout)
