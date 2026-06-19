"""VM lifecycle (create/delete/change) as core operation generators.

``create_vm`` composes the ip/dns/port leaf generators with ``reconcile=False``
and reconciles once at the end (so the watcher restart + NAT/dnsmasq apply run a
single time, not per sub-op). It also tracks an undo stack: on any failure — or
on cancellation (``GeneratorExit``) from the TUI — it rolls back the resources
it created (release IP, remove DNS, delete the instance) so a half-built VM
never orphans pool/DNS/NAT state, which the old delete-only cleanup did.
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Sequence

from .. import etcd_kv, network
from ..config import get_settings
from ..locking import sync_lock
from ..logging import log_message
from ..services import restart_instance_watcher
from ..vm_helpers import check_vm_exists, secure_vm_instance
from .dns import add_dns, remove_dns
from .errors import CoreError, NotFoundError, ValidationError
from .events import OpResult, ProgressEvent, ProgressGen, Severity
from .ip import _extract_private_ip, assign_ip, release_ip
from .ports import add_port
from .privilege import require_root
from .templates import apply_template_gen

DOMAIN_SUFFIX = ".daemondreams.home.arpa"


@dataclass(frozen=True)
class PortForwardSpec:
    """A port forward to create during ``create_vm`` (collected by the caller)."""

    public_port: int
    private_port: int
    protocol: str = "tcp"
    description: Optional[str] = None


def _drain_silent(gen) -> None:
    """Run a generator to completion, ignoring its events and any error."""
    try:
        for _ in gen:
            pass
    except Exception:
        pass


def _incus_launch(vm_name: str, image: str, cpus: int, memory: str, disk: str) -> None:
    cmd = [
        "sudo", "incus", "launch", image, vm_name, "--vm",
        "-c", f"limits.cpu={cpus}",
        "-c", f"limits.memory={memory}",
        "-d", f"root,size={disk}",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
    except subprocess.CalledProcessError as exc:
        raise CoreError(f"Failed to launch instance: {exc.stderr}")
    except (subprocess.SubprocessError, OSError) as exc:
        raise CoreError(f"Failed to launch instance: {exc}")


def _wait_private_ip(vm_name: str, tries: int = 12) -> Optional[str]:
    """Poll incus up to ``tries`` * 5s for the guest's private IP."""
    for _ in range(tries):
        try:
            result = subprocess.run(
                ["sudo", "incus", "list", vm_name, "--format", "json"],
                capture_output=True, text=True, check=True, timeout=10,
            )
            data = json.loads(result.stdout)
            if data:
                ip = _extract_private_ip(data[0])
                if ip:
                    return ip
        except Exception:
            pass
        time.sleep(5)
    return None


def _incus_stop_delete(vm_name: str) -> None:
    """Best-effort stop+delete (used for rollback; never raises)."""
    for cmd in (
        ["sudo", "incus", "stop", vm_name, "--force"],
        ["sudo", "incus", "delete", vm_name],
    ):
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception:
            pass


def create_vm(
    vm_name: str,
    *,
    image: str = "images:ubuntu/24.04/cloud",
    cpus: int = 1,
    memory: str = "2048MB",
    disk: str = "20GB",
    network_type: str = "public",
    port_forwards: Sequence[PortForwardSpec] = (),
    template: Optional[str] = None,
) -> ProgressGen:
    """Create, configure, secure, and optionally provision a new Incus VM."""
    require_root()
    if check_vm_exists(vm_name):
        raise ValidationError(f"VM or container '{vm_name}' already exists")
    if network_type not in ("public", "private"):
        raise ValidationError("Network must be 'public' or 'private'")

    current_server = get_settings().current_server
    dns_name = f"{vm_name}{DOMAIN_SUFFIX}"
    # (label, undo callable) pushed as each resource is created; run in reverse.
    undo: list[tuple[str, callable]] = []

    try:
        yield ProgressEvent(Severity.STEP, "Launching instance", 1, 5)
        _incus_launch(vm_name, image, cpus, memory, disk)
        undo.append(("instance", lambda: _incus_stop_delete(vm_name)))
        yield ProgressEvent(Severity.SUCCESS, f"VM {vm_name} launched")

        yield ProgressEvent(Severity.STEP, "Waiting for private IP", 2, 5)
        private_ip = _wait_private_ip(vm_name)
        if not private_ip:
            raise CoreError(f"Could not get private IP for {vm_name} after 60s")
        yield ProgressEvent(Severity.SUCCESS, f"Got private IP: {private_ip}")

        yield ProgressEvent(Severity.STEP, "Configuring networking", 3, 5)
        public_ip = None
        with sync_lock() as acquired:
            if not acquired:
                raise CoreError("Another sync is in progress; try again")
            if network_type == "public":
                res = yield from assign_ip(vm_name, None, reconcile=False)
                public_ip = res.summary["public_ip"]
                undo.append(
                    ("public IP", lambda: _drain_silent(release_ip(vm_name, reconcile=False)))
                )
                yield from add_dns(dns_name, public_ip, vm_name, reconcile=False)
                undo.append(
                    ("DNS record", lambda: _drain_silent(remove_dns(dns_name, reconcile=False)))
                )
                for pf in port_forwards:
                    yield from add_port(
                        vm_name, pf.public_port, pf.private_port,
                        pf.protocol, pf.description, reconcile=False,
                    )
            else:
                yield from add_dns(dns_name, private_ip, vm_name, reconcile=False)
                undo.append(
                    ("DNS record", lambda: _drain_silent(remove_dns(dns_name, reconcile=False)))
                )
            # Reconcile the host once for all the networking changes above.
            network.regenerate_hosts_file()
            network.reload_dnsmasq()
            network.apply_nat_rules()
        yield ProgressEvent(Severity.SUCCESS, "Networking configured")

        yield ProgressEvent(Severity.STEP, "Securing VM", 4, 5)
        if secure_vm_instance(vm_name):
            yield ProgressEvent(Severity.SUCCESS, "VM security hardened")
        else:
            yield ProgressEvent(
                Severity.ERROR, "VM was created but security hardening failed"
            )

        if template:
            try:
                yield from apply_template_gen(vm_name, template, check=False)
            except (NotFoundError, ValidationError) as exc:
                yield ProgressEvent(
                    Severity.WARNING, f"{exc}; VM created without the template"
                )

        yield ProgressEvent(Severity.STEP, "Done", 5, 5)
        restart_instance_watcher()
        log_message(f"Created VM {vm_name}")
        return OpResult(
            ok=True,
            summary={
                "name": vm_name,
                "image": image,
                "cpus": cpus,
                "memory": memory,
                "disk": disk,
                "hostname": dns_name,
                "private_ip": private_ip,
                "public_ip": public_ip,
            },
        )
    except GeneratorExit:
        # Cancelled by the consumer (e.g. TUI worker closing the generator):
        # roll back silently, then let the cancellation propagate.
        for _label, fn in reversed(undo):
            try:
                fn()
            except Exception:
                pass
        raise
    except Exception as exc:
        yield ProgressEvent(Severity.ERROR, f"Error during VM creation: {exc}")
        for label, fn in reversed(undo):
            yield ProgressEvent(Severity.WARNING, f"Rolling back {label}...")
            try:
                fn()
            except Exception:
                pass
        if isinstance(exc, (CoreError, ValidationError, NotFoundError)):
            raise
        raise CoreError(f"VM creation failed: {exc}")


def delete_vm(vm_name: str) -> ProgressGen:
    """Delete a VM and clean up its IP, port forwards, and DNS records.

    Confirmation is the caller's responsibility (the CLI/TUI), not core's.
    """
    require_root()
    if not check_vm_exists(vm_name):
        raise NotFoundError(f"VM or container '{vm_name}' not found")

    yield ProgressEvent(Severity.STEP, "Releasing public IP and port forwards", 1, 3)
    yield from release_ip(vm_name, reconcile=False)

    yield ProgressEvent(Severity.STEP, "Removing DNS records", 2, 3)
    dns_records = etcd_kv.get_all_with_prefix("/hetzman/dns/")
    removed = 0
    for key, data in dns_records.items():
        if data.get("instance") == vm_name:
            hostname = key.replace("/hetzman/dns/", "")
            if etcd_kv.delete_key(key):
                yield ProgressEvent(Severity.SUCCESS, f"Removed DNS: {hostname}")
                removed += 1
            else:
                yield ProgressEvent(Severity.ERROR, f"Failed to remove DNS: {hostname}")
    if removed:
        network.regenerate_hosts_file()
        network.reload_dnsmasq()
    else:
        yield ProgressEvent(Severity.WARNING, f"No DNS records found for {vm_name}")

    yield ProgressEvent(Severity.STEP, "Stopping and deleting instance", 3, 3)
    try:
        subprocess.run(
            ["sudo", "incus", "stop", vm_name, "--force"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        yield ProgressEvent(Severity.SUCCESS, "Instance stopped")
        subprocess.run(
            ["sudo", "incus", "delete", vm_name],
            check=True, capture_output=True, text=True, timeout=30,
        )
        yield ProgressEvent(Severity.SUCCESS, "Instance deleted")
    except (subprocess.SubprocessError, OSError) as exc:
        raise CoreError(f"Error deleting instance: {getattr(exc, 'stderr', exc)}")

    network.apply_nat_rules()
    restart_instance_watcher()
    log_message(f"Deleted VM {vm_name}")
    return OpResult(ok=True, summary={"name": vm_name})


def change_vm(
    vm_name: str,
    *,
    cpus: Optional[int] = None,
    memory: Optional[str] = None,
) -> ProgressGen:
    """Change CPU/memory for a VM (stops, reconfigures, restarts)."""
    require_root()
    if cpus is None and memory is None:
        raise ValidationError("You must specify cpus or memory")
    if not check_vm_exists(vm_name):
        raise NotFoundError(f"VM or container '{vm_name}' not found")

    started = False
    try:
        yield ProgressEvent(Severity.INFO, f"Stopping {vm_name}...")
        subprocess.run(
            ["sudo", "incus", "stop", vm_name],
            check=True, capture_output=True, text=True, timeout=60,
        )
        if cpus is not None:
            yield ProgressEvent(Severity.INFO, f"Applying new CPU limit: {cpus}")
            subprocess.run(
                ["sudo", "incus", "config", "set", vm_name, f"limits.cpu={cpus}"],
                check=True, capture_output=True, text=True, timeout=10,
            )
        if memory is not None:
            yield ProgressEvent(Severity.INFO, f"Applying new memory limit: {memory}")
            subprocess.run(
                ["sudo", "incus", "config", "set", vm_name, f"limits.memory={memory}"],
                check=True, capture_output=True, text=True, timeout=10,
            )
        yield ProgressEvent(Severity.INFO, f"Starting {vm_name}...")
        subprocess.run(
            ["sudo", "incus", "start", vm_name],
            check=True, capture_output=True, text=True, timeout=30,
        )
        started = True
        yield ProgressEvent(Severity.SUCCESS, f"Successfully changed limits for {vm_name}")
        restart_instance_watcher()
        log_message(f"Changed limits for {vm_name}")
        return OpResult(ok=True, summary={"name": vm_name})
    except (subprocess.SubprocessError, OSError) as exc:
        if not started:
            # Best-effort: bring the VM back up in its previous state.
            yield ProgressEvent(Severity.WARNING, "Attempting to restart VM in its previous state...")
            try:
                subprocess.run(
                    ["sudo", "incus", "start", vm_name], capture_output=True, timeout=30
                )
            except Exception:
                pass
        raise CoreError(f"Error during VM change: {getattr(exc, 'stderr', exc)}")
