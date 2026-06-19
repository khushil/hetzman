"""Process-level mutual exclusion for operations that mutate firewall/DNS.

node-sync, sync-apply, and the instance watcher's reconcile can all rebuild
the HETZMAN nat chains; the lock keeps them from interleaving. The lock is
non-blocking — a contender skips (timers retry on their own schedule) — and
re-entrant within a process so node-sync can call sync-apply while holding it.
"""
from __future__ import annotations

import fcntl
import threading
from contextlib import contextmanager

LOCK_PATH = "/run/hetzman-sync.lock"

_holder_depth = 0
_lock_file = None
# Guards the read-modify-write of the module globals so two threads can't race
# _holder_depth; reentrant so a nested sync_lock() in the same thread (which
# already holds it during the bookkeeping window) does not deadlock.
_STATE_LOCK = threading.RLock()


@contextmanager
def sync_lock():
    """Yield True if the lock is held (acquired or re-entered), else False."""
    global _holder_depth, _lock_file

    with _STATE_LOCK:
        if _holder_depth > 0:
            _holder_depth += 1
            reentered = True
        else:
            reentered = False

    if reentered:
        try:
            yield True
        finally:
            with _STATE_LOCK:
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

    with _STATE_LOCK:
        _lock_file = lock_file
        _holder_depth = 1
    try:
        yield True
    finally:
        with _STATE_LOCK:
            _holder_depth = 0
            _lock_file = None
        try:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
        except OSError:
            pass
        lock_file.close()
