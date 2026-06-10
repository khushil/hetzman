"""Process-level mutual exclusion for operations that mutate firewall/DNS.

node-sync, sync-apply, and the instance watcher's reconcile can all rebuild
the HETZMAN nat chains; the lock keeps them from interleaving. The lock is
non-blocking — a contender skips (timers retry on their own schedule) — and
re-entrant within a process so node-sync can call sync-apply while holding it.
"""
from __future__ import annotations

import fcntl
from contextlib import contextmanager

LOCK_PATH = "/run/hetzman-sync.lock"

_holder_depth = 0
_lock_file = None


@contextmanager
def sync_lock():
    """Yield True if the lock is held (acquired or re-entered), else False."""
    global _holder_depth, _lock_file

    if _holder_depth > 0:
        _holder_depth += 1
        try:
            yield True
        finally:
            _holder_depth -= 1
        return

    try:
        lock_file = open(LOCK_PATH, "w")
    except OSError:
        # Can't even open the lock file (not root?) — proceed unlocked rather
        # than deadlock; mutations will fail loudly on their own if unprivileged.
        yield True
        return

    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_file.close()
        yield False
        return

    _lock_file = lock_file
    _holder_depth = 1
    try:
        yield True
    finally:
        _holder_depth = 0
        _lock_file = None
        try:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
        except OSError:
            pass
        lock_file.close()
