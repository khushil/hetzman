"""Thin retry wrappers around the etcd client.

All helpers transparently recover from expired RBAC auth tokens: etcd
invalidates tokens server-side after a TTL, and the etcd3 library never
refreshes them, so a long-running process (the instance watcher, a timer
unit) would otherwise fail every write with UNAUTHENTICATED until restart.
On such an error the cached client is dropped and rebuilt, which
re-authenticates, and the call is retried within the normal retry budget.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

from .config import get_etcd_client, reset_etcd_client
from .logging import log_message

_RETRIES = 3
_BACKOFF = 0.5


def _recover_if_auth_error(error: Exception) -> bool:
    """If *error* is an expired/invalid-token failure, rebuild the client."""
    message = str(error)
    is_auth = "invalid auth token" in message or "UNAUTHENTICATED" in message
    if not is_auth:
        try:
            import grpc

            is_auth = (
                isinstance(error, grpc.RpcError)
                and error.code() == grpc.StatusCode.UNAUTHENTICATED
            )
        except Exception:
            is_auth = False
    if is_auth:
        log_message("etcd auth token expired; re-authenticating", "WARNING")
        reset_etcd_client()
    return is_auth


def get_key(key: str) -> Optional[str]:
    for i in range(_RETRIES):
        try:
            value, _ = get_etcd_client().get(key)
            return value.decode("utf-8") if value else None
        except Exception as e:
            recovered = _recover_if_auth_error(e)
            if i < _RETRIES - 1:
                if not recovered:
                    time.sleep(_BACKOFF)
                continue
            log_message(f"Error getting etcd key {key}: {e}", "ERROR")
            return None
    return None


def put_key(key: str, value: str) -> bool:
    for i in range(_RETRIES):
        try:
            get_etcd_client().put(key, value)
            return True
        except Exception as e:
            recovered = _recover_if_auth_error(e)
            if i < _RETRIES - 1:
                if not recovered:
                    time.sleep(_BACKOFF)
                continue
            log_message(f"Error putting etcd key {key}: {e}", "ERROR")
            return False
    return False


def put_with_lease(key: str, value: str, ttl: int) -> bool:
    """Put *key* attached to a fresh lease of *ttl* seconds.

    Used for heartbeats: if the writer stops, the key expires and its
    absence is the down-signal.
    """
    for i in range(_RETRIES):
        try:
            client = get_etcd_client()
            lease = client.lease(ttl)
            client.put(key, value, lease=lease)
            return True
        except Exception as e:
            recovered = _recover_if_auth_error(e)
            if i < _RETRIES - 1:
                if not recovered:
                    time.sleep(_BACKOFF)
                continue
            log_message(f"Error putting leased etcd key {key}: {e}", "ERROR")
            return False
    return False


def delete_key(key: str) -> bool:
    for i in range(_RETRIES):
        try:
            get_etcd_client().delete(key)
            return True
        except Exception as e:
            recovered = _recover_if_auth_error(e)
            if i < _RETRIES - 1:
                if not recovered:
                    time.sleep(_BACKOFF)
                continue
            log_message(f"Error deleting etcd key {key}: {e}", "ERROR")
            return False
    return False


def get_all_with_prefix(prefix: str) -> Dict[str, Any]:
    for i in range(_RETRIES):
        try:
            results: Dict[str, Any] = {}
            for value, metadata in get_etcd_client().get_prefix(prefix):
                key = metadata.key.decode("utf-8")
                val = value.decode("utf-8")
                try:
                    results[key] = json.loads(val)
                except json.JSONDecodeError:
                    results[key] = val
            return results
        except Exception as e:
            recovered = _recover_if_auth_error(e)
            if i < _RETRIES - 1:
                if not recovered:
                    time.sleep(_BACKOFF)
                continue
            log_message(f"Error getting prefix {prefix}: {e}", "ERROR")
            return {}
    return {}
