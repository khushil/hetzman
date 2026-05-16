"""Thin retry wrappers around the etcd client."""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

from .config import get_etcd_client
from .logging import log_message

_RETRIES = 3
_BACKOFF = 0.5


def get_key(key: str) -> Optional[str]:
    client = get_etcd_client()
    for i in range(_RETRIES):
        try:
            value, _ = client.get(key)
            return value.decode("utf-8") if value else None
        except Exception as e:
            if i < _RETRIES - 1:
                time.sleep(_BACKOFF)
                continue
            log_message(f"Error getting etcd key {key}: {e}", "ERROR")
            return None
    return None


def put_key(key: str, value: str) -> bool:
    client = get_etcd_client()
    for i in range(_RETRIES):
        try:
            client.put(key, value)
            return True
        except Exception as e:
            if i < _RETRIES - 1:
                time.sleep(_BACKOFF)
                continue
            log_message(f"Error putting etcd key {key}: {e}", "ERROR")
            return False
    return False


def delete_key(key: str) -> bool:
    client = get_etcd_client()
    for i in range(_RETRIES):
        try:
            client.delete(key)
            return True
        except Exception as e:
            if i < _RETRIES - 1:
                time.sleep(_BACKOFF)
                continue
            log_message(f"Error deleting etcd key {key}: {e}", "ERROR")
            return False
    return False


def get_all_with_prefix(prefix: str) -> Dict[str, Any]:
    client = get_etcd_client()
    try:
        results: Dict[str, Any] = {}
        for value, metadata in client.get_prefix(prefix):
            key = metadata.key.decode("utf-8")
            val = value.decode("utf-8")
            try:
                results[key] = json.loads(val)
            except json.JSONDecodeError:
                results[key] = val
        return results
    except Exception as e:
        log_message(f"Error getting prefix {prefix}: {e}", "ERROR")
        return {}
