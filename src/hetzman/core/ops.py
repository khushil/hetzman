"""Host operations: apply updates, reboot — guarded (CHECK done in reads.py).

These run on the target host via the executor. ``reboot_host`` reuses the
voter-health quorum guard (a reboot transiently drops an etcd voter) and warns
about hosted running instances. ``rolling_reboot`` serializes, re-checks quorum
before each, and aborts the remainder if a host does not come back.
"""
from __future__ import annotations

import time
from typing import Optional, Sequence

from . import exec as host_exec
from . import nodes, reads
from .errors import CoreError, HostUnreachable
from .events import OpResult, ProgressEvent, ProgressGen, Severity

# apt, non-interactively, keeping existing config files on conflict.
_APT_UPGRADE = [
    "env", "DEBIAN_FRONTEND=noninteractive",
    "apt-get", "-y",
    "-o", "Dpkg::Options::=--force-confdef",
    "-o", "Dpkg::Options::=--force-confold",
    "upgrade",
]


def _running_instances(host: str) -> list[str]:
    """Running instance names on *host*. Raises (HostUnreachable/CoreError) on a
    real read failure so the caller can warn instead of silently reporting none."""
    items, _ = reads.list_instances(host)
    return [i.name for i in items if i.status.lower() in ("running", "started")]


def _warn_running(host: str) -> ProgressGen:
    """Yield a blast-radius warning for hosted running instances; if the read
    itself fails, warn that we are proceeding blind rather than assume none."""
    try:
        running = _running_instances(host)
    except (HostUnreachable, CoreError) as exc:
        yield ProgressEvent(
            Severity.WARNING,
            f"could not enumerate instances on {host} ({exc}); proceeding blind",
        )
        return
    if running:
        yield ProgressEvent(
            Severity.WARNING,
            f"{len(running)} running instance(s) on {host} will go down: {', '.join(running)}",
        )


def apply_updates(host: Optional[str] = None) -> ProgressGen:
    """Run apt-get update + upgrade on a host, streaming output."""
    target = host_exec.resolve_host(host)

    yield ProgressEvent(Severity.STEP, f"apt-get update on {target}", 1, 2)
    index_failed = False
    for line in host_exec.stream_on(target, ["apt-get", "update"], root=True, timeout=300):
        yield ProgressEvent(Severity.INFO, line)
        # apt-get update often exits 0 even when some mirrors failed.
        if "Failed to fetch" in line or "Some index files failed to download" in line:
            index_failed = True
    if index_failed:
        yield ProgressEvent(
            Severity.WARNING,
            "apt index only partially refreshed; upgrading against a possibly-stale index",
        )

    yield ProgressEvent(Severity.STEP, f"apt-get upgrade on {target}", 2, 2)
    for line in host_exec.stream_on(target, _APT_UPGRADE, root=True, timeout=1800):
        yield ProgressEvent(Severity.INFO, line)
    yield ProgressEvent(Severity.SUCCESS, f"updates applied on {target}")
    return OpResult(ok=True, summary={"host": target})


def reboot_host(host: Optional[str] = None) -> ProgressGen:
    """Reboot a host. If it is an etcd member, refuse unless the cluster keeps
    quorum while it is down; warn about hosted running instances."""
    target = host_exec.resolve_host(host)

    member, members = nodes.lookup_member(target)
    if member is not None:
        nodes.assess_reboot(members, member.id)  # raises CoreError if unsafe
        healthy = sum(1 for m in members if m.healthy)
        yield ProgressEvent(
            Severity.INFO,
            f"etcd: {len(members)} members, {healthy} healthy — quorum holds while "
            f"{target} reboots",
        )
        if member.is_leader:
            yield ProgressEvent(
                Severity.WARNING,
                "rebooting the current raft leader — expect a brief election / write stall",
            )
        if len(members) <= 3:
            yield ProgressEvent(
                Severity.WARNING,
                f"cluster runs at bare quorum (no fault tolerance) while {target} reboots",
            )

    yield from _warn_running(target)

    yield ProgressEvent(Severity.STEP, f"Rebooting {target}", 1, 1)
    # The reboot tears down our SSH session, so ssh exits 255 (HostUnreachable)
    # even though the reboot succeeded — that is expected. A real failure (polkit
    # denial, hung job: a non-255 nonzero) must surface, so use check=True and
    # only swallow the connection teardown.
    try:
        host_exec.run_on(target, ["systemctl", "reboot"], root=True, check=True, timeout=20)
    except HostUnreachable:
        pass
    yield ProgressEvent(Severity.SUCCESS, f"Reboot initiated on {target}")
    return OpResult(ok=True, summary={"host": target})


def _came_back(host: str, *, tries: int = 20, delay: int = 15) -> bool:
    """Poll until the host answers SSH AND (if it is an etcd member) its member is
    healthy again — so a rolling reboot never moves on while a voter is still
    down/catching up."""
    is_member, _ = nodes.lookup_member(host)
    for _ in range(tries):
        time.sleep(delay)
        try:
            host_exec.run_on(host, ["true"], root=True, check=False, timeout=10)
        except (HostUnreachable, CoreError):
            continue
        if is_member is None:
            return True  # not an etcd member; SSH back is enough
        # An etcd member must have genuinely REJOINED and caught its raft log up
        # (it answers Status while still replaying), else taking the next host
        # down could drop quorum. Re-read fresh cluster state each poll.
        member, members = nodes.lookup_member(host)
        if member is not None and nodes.member_caught_up(member.id, members):
            return True
    return False


def rolling_reboot(hosts: Sequence[str]) -> ProgressGen:
    """Reboot hosts one at a time, re-checking quorum before each and aborting the
    remainder if a host fails to come back."""
    done = []
    for raw in hosts:
        target = host_exec.resolve_host(raw)
        yield ProgressEvent(Severity.STEP, f"Rolling reboot: {target}", len(done) + 1, len(hosts))
        # reboot_host re-runs the quorum guard for the CURRENT cluster state.
        yield from reboot_host(target)
        yield ProgressEvent(Severity.INFO, f"waiting for {target} to come back…")
        if not _came_back(target):
            yield ProgressEvent(
                Severity.ERROR,
                f"{target} did not come back; aborting the remaining reboots",
            )
            raise CoreError(f"{target} did not return after reboot ({len(done)} done)")
        done.append(target)
        yield ProgressEvent(Severity.SUCCESS, f"{target} is back")
    return OpResult(ok=True, summary={"rebooted": tuple(done)})
