"""DNS record mutations as core operation generators.

Leaf ops (see :mod:`hetzman.core.events`): raise :class:`CoreError` on hard
failure, return their product in ``OpResult.summary``. Pass ``reconcile=False``
when composing inside a larger op (e.g. ``create_vm``) so the dnsmasq/hosts
reconcile + watcher restart run once at the end rather than per record.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from .. import etcd_kv, network
from ..config import get_settings
from ..logging import log_message
from ..services import restart_instance_watcher
from .errors import CoreError
from .events import OpResult, ProgressEvent, ProgressGen, Severity

DOMAIN_SUFFIX = ".daemondreams.home.arpa"


def qualify(hostname: str) -> str:
    """Append the default domain to a short hostname (mirrors the CLI)."""
    return hostname if "." in hostname else f"{hostname}{DOMAIN_SUFFIX}"


def _reconcile() -> None:
    """Regenerate hosts + reload dnsmasq + restart the watcher (idempotent)."""
    network.regenerate_hosts_file()
    network.reload_dnsmasq()
    restart_instance_watcher()


def add_dns(
    hostname: str,
    ip: str,
    instance: Optional[str] = None,
    *,
    reconcile: bool = True,
) -> ProgressGen:
    """Add a DNS record. Raises :class:`CoreError` if the etcd write fails."""
    hostname = qualify(hostname)
    record = {
        "ip": ip,
        "server": get_settings().current_server,
        "instance": instance,
        "type": None,
        "auto": False,
        "updated": datetime.now().isoformat(),
    }
    if not etcd_kv.put_key(f"/hetzman/dns/{hostname}", json.dumps(record)):
        raise CoreError("Failed to add DNS record")
    log_message(f"Added DNS record: {hostname} -> {ip}")
    yield ProgressEvent(Severity.SUCCESS, f"Added DNS record: {hostname} -> {ip}")
    if reconcile:
        _reconcile()
    return OpResult(ok=True, summary={"hostname": hostname, "ip": ip})


def remove_dns(hostname: str, *, reconcile: bool = True) -> ProgressGen:
    """Remove a DNS record. Soft-fails (``ok=False``) when not found."""
    hostname = qualify(hostname)
    if not etcd_kv.delete_key(f"/hetzman/dns/{hostname}"):
        yield ProgressEvent(Severity.WARNING, f"DNS record not found: {hostname}")
        return OpResult(ok=False, summary={"hostname": hostname})
    log_message(f"Removed DNS record: {hostname}")
    yield ProgressEvent(Severity.SUCCESS, f"Removed DNS record: {hostname}")
    if reconcile:
        _reconcile()
    return OpResult(ok=True, summary={"hostname": hostname})
