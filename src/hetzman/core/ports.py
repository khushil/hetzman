"""Port-forward mutations as core operation generators.

Leaf ops: raise :class:`ValidationError`/:class:`CoreError` on failure, return
the rule in ``OpResult.summary``. ``reconcile=False`` defers the NAT apply +
watcher restart to a composing op.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from .. import etcd_kv, network
from ..config import get_settings
from ..logging import log_message
from ..services import restart_instance_watcher
from .errors import CoreError, ValidationError
from .events import OpResult, ProgressEvent, ProgressGen, Severity


def _reconcile() -> None:
    network.apply_nat_rules()
    restart_instance_watcher()


def add_port(
    instance: str,
    public_port: int,
    private_port: int,
    protocol: str = "tcp",
    description: Optional[str] = None,
    *,
    reconcile: bool = True,
) -> ProgressGen:
    """Add a port-forward rule for an instance that already has a public IP."""
    if not (1 <= public_port <= 65535):
        raise ValidationError(f"Invalid public port: {public_port}")
    if not (1 <= private_port <= 65535):
        raise ValidationError(f"Invalid private port: {private_port}")
    if protocol not in ("tcp", "udp"):
        raise ValidationError(f"Invalid protocol: {protocol}")

    current_server = get_settings().current_server
    nat_data = etcd_kv.get_key(f"/hetzman/nat/{current_server}/{instance}")
    if not nat_data:
        raise ValidationError(
            f"Instance '{instance}' does not have a public IP assigned; "
            "use 'hetzman ip-assign' first"
        )
    nat_rule = json.loads(nat_data)

    port_key = (
        f"/hetzman/port-forward/{current_server}/{instance}-{public_port}-{protocol}"
    )
    port_data = {
        "public_ip": nat_rule["public_ip"],
        "public_port": public_port,
        "private_ip": nat_rule["private_ip"],
        "private_port": private_port,
        "protocol": protocol,
        "instance_name": instance,
        "description": description,
        "enabled": True,
        "created": datetime.now().isoformat(),
    }
    if not etcd_kv.put_key(port_key, json.dumps(port_data)):
        raise CoreError("Failed to add port forward")
    log_message(f"Added port forward for {instance}")
    yield ProgressEvent(
        Severity.SUCCESS,
        f"Added port forward: {nat_rule['public_ip']}:{public_port} -> "
        f"{nat_rule['private_ip']}:{private_port} ({protocol})",
    )
    if reconcile:
        _reconcile()
    return OpResult(
        ok=True,
        summary={
            "instance": instance,
            "public_port": public_port,
            "private_port": private_port,
            "protocol": protocol,
            "public_ip": nat_rule["public_ip"],
            "private_ip": nat_rule["private_ip"],
        },
    )


def remove_port(
    instance: str,
    public_port: int,
    protocol: str = "tcp",
    *,
    reconcile: bool = True,
) -> ProgressGen:
    """Remove a port-forward rule. Soft-fails (``ok=False``) when not found."""
    current_server = get_settings().current_server
    port_key = (
        f"/hetzman/port-forward/{current_server}/{instance}-{public_port}-{protocol}"
    )
    if not etcd_kv.delete_key(port_key):
        yield ProgressEvent(Severity.WARNING, "Port forward rule not found")
        return OpResult(ok=False, summary={"instance": instance})
    log_message(f"Removed port forward: {instance}:{public_port}/{protocol}")
    yield ProgressEvent(Severity.SUCCESS, "Removed port forward rule")
    if reconcile:
        _reconcile()
    return OpResult(ok=True, summary={"instance": instance})
