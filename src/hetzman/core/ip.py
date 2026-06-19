"""Public-IP pool assignment/release as core operation generators.

Two correctness properties the short-lived CLI got away without but a
long-lived TUI needs:

* The pool claim is an **etcd compare-and-swap** (``etcd_kv.replace_if_value``),
  so two concurrent assignments can never transition the same IP from
  "available" to "assigned".
* The host-mutating steps (interface + NAT apply) run under ``sync_lock`` so
  they never interleave with the instance watcher's reconcile. On lock
  contention the op aborts cleanly rather than racing.
"""
from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime
from typing import Optional

from .. import etcd_kv, network
from ..config import get_settings
from ..locking import sync_lock
from ..logging import log_message
from ..services import restart_instance_watcher
from .errors import CoreError, NotFoundError, ValidationError
from .events import OpResult, ProgressEvent, ProgressGen, Severity

_PRIVATE_IFACES = ("eth0", "enp5s0")


def _incus_list(instance: str) -> list:
    """Return ``incus list <instance> --format json`` parsed, or raise CoreError."""
    try:
        proc = subprocess.run(
            ["sudo", "incus", "list", instance, "--format", "json"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return json.loads(proc.stdout)
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as exc:
        raise CoreError(f"Error querying instance '{instance}': {exc}")


def _extract_private_ip(instance_data: dict) -> Optional[str]:
    network_state = instance_data.get("state", {}).get("network", {})
    for iface in _PRIVATE_IFACES:
        if iface in network_state:
            for addr in network_state[iface].get("addresses", []):
                if addr["family"] == "inet" and not addr["address"].startswith("127."):
                    return addr["address"]
    return None


def _wait_for_private_ip(instance: str) -> ProgressGen:
    """Yield progress while waiting for the guest's private IP; return it.

    Internal sub-generator: returns the IP string (not an OpResult). Raises
    NotFoundError if the instance is missing, CoreError if no IP appears.
    """
    instances = _incus_list(instance)
    if not instances:
        raise NotFoundError(f"Instance '{instance}' not found")
    instance_data = instances[0]

    retries = 6
    while retries > 0:
        private_ip = _extract_private_ip(instance_data)
        if private_ip:
            return private_ip
        if retries <= 1:
            break
        yield ProgressEvent(
            Severity.INFO,
            f"Waiting for instance to get IP... ({retries * 5}s remaining)",
        )
        time.sleep(5)
        retries -= 1
        instances = _incus_list(instance)
        if instances:
            instance_data = instances[0]
    raise CoreError(f"Instance '{instance}' has no IP address after 30s")


def _claim_pool_ip(current_server: str, instance: str, specific_ip: Optional[str]) -> str:
    """Atomically claim an available pool IP for *instance*; return it.

    Uses compare-and-swap so a concurrent assignment cannot grab the same IP.
    Raises ValidationError if no IP can be claimed.
    """
    pool = etcd_kv.get_all_with_prefix("/hetzman/ip-pool/")
    if specific_ip:
        key = f"/hetzman/ip-pool/{specific_ip}"
        if key not in pool:
            raise ValidationError(f"IP {specific_ip} not found in pool")
        if pool[key].get("server") != current_server:
            raise ValidationError(f"IP {specific_ip} belongs to different server")
        if pool[key].get("status") != "available":
            raise ValidationError(f"IP {specific_ip} is not available")
        candidates = [specific_ip]
    else:
        candidates = [
            key.replace("/hetzman/ip-pool/", "")
            for key, data in sorted(pool.items())
            if data.get("server") == current_server and data.get("status") == "available"
        ]
        if not candidates:
            raise ValidationError(f"No available IPs in pool for {current_server}")

    for public_ip in candidates:
        pool_key = f"/hetzman/ip-pool/{public_ip}"
        raw = etcd_kv.get_key(pool_key)
        if not raw:
            continue
        entry = json.loads(raw)
        if entry.get("status") != "available":
            continue
        entry["status"] = "assigned"
        entry["assigned_to"] = instance
        entry["assigned_at"] = datetime.now().isoformat()
        if etcd_kv.replace_if_value(pool_key, raw, json.dumps(entry)):
            return public_ip
        # Lost the race for this IP; try the next candidate.
    if specific_ip:
        raise ValidationError(f"IP {specific_ip} is not available")
    raise ValidationError(f"No available IPs in pool for {current_server}")


def _release_pool_ip(public_ip: str) -> None:
    """Best-effort revert of a pool claim back to available (compensation)."""
    raw = etcd_kv.get_key(f"/hetzman/ip-pool/{public_ip}")
    if not raw:
        return
    entry = json.loads(raw)
    entry["status"] = "available"
    entry["assigned_to"] = None
    entry["assigned_at"] = None
    etcd_kv.put_key(f"/hetzman/ip-pool/{public_ip}", json.dumps(entry))


def assign_ip(
    instance: str,
    ip: Optional[str] = None,
    *,
    reconcile: bool = True,
) -> ProgressGen:
    """Assign a public IP from the pool to *instance*."""
    current_server = get_settings().current_server

    existing = etcd_kv.get_key(f"/hetzman/nat/{current_server}/{instance}")
    if existing:
        nat = json.loads(existing)
        raise ValidationError(
            f"Instance '{instance}' already has public IP {nat['public_ip']}; "
            f"release it first with: sudo hetzman ip-release {instance}"
        )

    private_ip = yield from _wait_for_private_ip(instance)

    with sync_lock() as acquired:
        if not acquired:
            yield ProgressEvent(Severity.WARNING, "Another sync is in progress")
            raise CoreError("Another sync is in progress; try again")

        public_ip = _claim_pool_ip(current_server, instance, ip)
        try:
            if not network.add_ip_to_interface(public_ip):
                raise CoreError(f"Failed to add IP {public_ip} to host interface")
            nat_data = {
                "public_ip": public_ip,
                "private_ip": private_ip,
                "instance_name": instance,
                "enabled": True,
                "created": datetime.now().isoformat(),
            }
            etcd_kv.put_key(
                f"/hetzman/nat/{current_server}/{instance}", json.dumps(nat_data)
            )
        except Exception:
            # Compensation: undo the pool claim so the IP isn't orphaned.
            _release_pool_ip(public_ip)
            raise

        log_message(f"Assigned {public_ip} to {instance} ({private_ip})")
        yield ProgressEvent(
            Severity.SUCCESS, f"Assigned {public_ip} to {instance} ({private_ip})"
        )
        if reconcile:
            network.apply_nat_rules()
            restart_instance_watcher()

    return OpResult(
        ok=True,
        summary={"instance": instance, "public_ip": public_ip, "private_ip": private_ip},
    )


def release_ip(instance: str, *, reconcile: bool = True) -> ProgressGen:
    """Release the public IP assigned to *instance* (and its port forwards)."""
    current_server = get_settings().current_server

    nat_data = etcd_kv.get_key(f"/hetzman/nat/{current_server}/{instance}")
    if not nat_data:
        yield ProgressEvent(Severity.WARNING, f"No NAT rule found for instance '{instance}'")
        return OpResult(ok=False, summary={"instance": instance})

    public_ip = json.loads(nat_data)["public_ip"]

    with sync_lock() as acquired:
        if not acquired:
            yield ProgressEvent(Severity.WARNING, "Another sync is in progress")
            raise CoreError("Another sync is in progress; try again")

        etcd_kv.delete_key(f"/hetzman/nat/{current_server}/{instance}")

        port_forwards = etcd_kv.get_all_with_prefix(
            f"/hetzman/port-forward/{current_server}/"
        )
        for key, data in port_forwards.items():
            if data.get("instance_name") == instance:
                etcd_kv.delete_key(key)

        raw = etcd_kv.get_key(f"/hetzman/ip-pool/{public_ip}")
        if raw:
            entry = json.loads(raw)
            entry["status"] = "available"
            entry["assigned_to"] = None
            entry["assigned_at"] = None
            etcd_kv.put_key(f"/hetzman/ip-pool/{public_ip}", json.dumps(entry))

        if not network.remove_ip_from_interface(public_ip):
            yield ProgressEvent(
                Severity.WARNING,
                f"Failed to remove IP {public_ip} from host interface",
            )

        log_message(f"Released {public_ip} from {instance}")
        yield ProgressEvent(Severity.SUCCESS, f"Released {public_ip} from {instance}")
        if reconcile:
            network.apply_nat_rules()
            restart_instance_watcher()

    return OpResult(ok=True, summary={"instance": instance, "public_ip": public_ip})
