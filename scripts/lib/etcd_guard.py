#!/usr/bin/env python3
"""Quorum guards for the bash provisioning scripts.

Thin CLI over the already-tested safety math in ``hetzman.core.nodes`` — the
bash scripts must never reimplement quorum arithmetic. Run with the installed
hetzman interpreter so the package and its etcd client are importable:

    /opt/pipx/venvs/hetzman/bin/python scripts/lib/etcd_guard.py <cmd> [args]

Commands:
  registry-json                 dump the fleet registry as JSON
  can-restart <node>            exit 0 iff etcd on <node> can go down safely
  can-add                       exit 0 iff a voting member can be added now
  wait-caught-up <node> [tries] poll until <node>'s member has rejoined
  members                       one "name<TAB>peer<TAB>healthy<TAB>leader" per line

Every command is fail-closed: any error exits non-zero with a message on stderr.
"""
from __future__ import annotations

import json
import os
import sys
import time

# config.py retries the etcd connect 6x30s for non-tty callers, to ride out a
# cold-boot race against quorum formation. A provisioning script should not hang
# three minutes on an unreachable cluster, so shorten it unless the caller has
# already chosen a value. Must be set before hetzman.config is imported.
os.environ.setdefault("HETZMAN_ETCD_CONNECT_RETRIES", "2")

from hetzman.core import nodes as core_nodes  # noqa: E402
from hetzman.core.errors import CoreError  # noqa: E402
from hetzman.registry import load_registry  # noqa: E402


def _die(msg: str) -> None:
    print(f"guard: {msg}", file=sys.stderr)
    sys.exit(1)


def cmd_registry_json(_argv: list[str]) -> None:
    print(json.dumps(load_registry(), indent=2, sort_keys=True))


def cmd_members(_argv: list[str]) -> None:
    for m in core_nodes._member_views():
        peer = m.peer_hosts[0] if m.peer_hosts else "?"
        print(f"{m.name or '<unstarted>'}\t{peer}\t{m.healthy}\t{m.is_leader}")


def cmd_can_restart(argv: list[str]) -> None:
    """Safe to take <node>'s etcd down? Same guard as a reboot: the cluster must
    keep a quorum of healthy voters while this one is away."""
    if not argv:
        _die("can-restart needs a node name")
    node = argv[0]
    member, members = core_nodes.lookup_member(node)
    if member is None:
        _die(f"{node} maps to no current etcd member")
    try:
        core_nodes.assess_reboot(members, member.id)
    except CoreError as e:
        _die(str(e))
    healthy = sum(1 for m in members if m.healthy)
    print(f"ok: {len(members)} members, {healthy} healthy — quorum holds while {node} restarts")
    if member.is_leader:
        print(f"warning: {node} is the current raft leader; expect a brief election", file=sys.stderr)


def cmd_can_add(_argv: list[str]) -> None:
    """Safe to promote the learner to a VOTING member right now?

    Delegates to the unit-tested ``assess_addition``; the margin rule lives in
    the package, not here.
    """
    members = core_nodes._member_views()
    try:
        core_nodes.assess_addition(members)
    except CoreError as e:
        _die(str(e))
    n_after = len(members) + 1
    quorum_after = n_after // 2 + 1
    healthy = sum(1 for m in members if m.healthy)
    print(f"ok: {len(members)} members, {healthy} healthy — "
          f"quorum {quorum_after} of {n_after} after the change, margin {healthy - quorum_after}")


def cmd_wait_caught_up(argv: list[str]) -> None:
    """Poll until <node>'s member is healthy AND its raft log has caught up.

    Answering Status is not enough — a member replies while still replaying its
    log, and moving on then could drop quorum at the next step.
    """
    if not argv:
        _die("wait-caught-up needs a node name")
    node = argv[0]
    tries = int(argv[1]) if len(argv) > 1 else 40
    delay = int(argv[2]) if len(argv) > 2 else 5

    for attempt in range(1, tries + 1):
        try:
            member, members = core_nodes.lookup_member(node)
            if member is not None and core_nodes.member_caught_up(member.id, members):
                print(f"ok: {node} has rejoined and caught up (after {attempt} polls)")
                return
        except Exception as e:  # noqa: BLE001 — keep polling through transient errors
            if attempt == tries:
                _die(f"{node} never caught up: {e}")
        time.sleep(delay)
    _die(f"{node} did not catch up within {tries * delay}s")


COMMANDS = {
    "registry-json": cmd_registry_json,
    "members": cmd_members,
    "can-restart": cmd_can_restart,
    "can-add": cmd_can_add,
    "wait-caught-up": cmd_wait_caught_up,
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    try:
        COMMANDS[sys.argv[1]](sys.argv[2:])
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 — a guard must fail closed, not traceback
        _die(f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
