"""Thread-safety shim serializing all etcd client access.

A long-lived TUI runs many thread workers hitting etcd concurrently, but the
underlying client accessor (``config.get_etcd_client``) caches a single client
and ``reset_etcd_client`` clears that cache mid-flight on auth recovery. Without
serialization two workers could rebuild/observe the client at once.

A single module-level :class:`threading.RLock` is the primary defense: callers
hold it for the whole get+call so no other thread can swap the client underneath
them. The lock is *reentrant* so an auth-recovery reset nested inside an
in-flight operation already holding the lock does not deadlock.
"""
from __future__ import annotations

import threading

from .. import config

_ETCD_LOCK = threading.RLock()


def etcd_lock() -> threading.RLock:
    """Return the shared etcd lock for compound operations (e.g. CAS)."""
    return _ETCD_LOCK


def get_client():
    """Thread-safe accessor for the cached etcd client."""
    with _ETCD_LOCK:
        return config.get_etcd_client()


def reset_client() -> None:
    """Thread-safe drop of the cached client so the next call re-authenticates."""
    with _ETCD_LOCK:
        config.reset_etcd_client()
