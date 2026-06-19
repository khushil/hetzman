"""Role-based VM provisioning templates (idempotent software install).

A *template* is a YAML file shipped as package data under ``hetzman/templates/<name>.yaml``
with these optional keys:

  description: one-line summary (shown by ``hetzman vm cfg list``).
  apt:         list of apt package names, installed in one ``apt-get install -y`` pass.
  scripts:     ordered list of ``{name, run, [timeout], [required]}`` steps. Each ``run`` is a
               bash snippet executed in the VM as root via ``incus exec``. Steps MUST be
               idempotent (guard with ``command -v``/``test -e`` checks) so re-applying a
               template is always safe. ``required`` defaults to ``true`` (a failed required
               step aborts the apply); set ``required: false`` for best-effort steps.

SECURITY: templates are trusted, version-controlled package data shipped WITH hetzman. They
are NEVER read from etcd, the network, or user input — their ``scripts`` run as root inside
the guest, so a mutable source would be a root RCE in the VM. The only runtime input is the
template *name* (resolved against the shipped files; a missing name is a hard error).
"""

from __future__ import annotations

import importlib.resources as _resources
import subprocess

import yaml

from .logging import log_message
from .vm_helpers import run_vm_exec


def _templates_root():
    """Return a Traversable for the shipped ``hetzman/templates`` directory."""
    return _resources.files("hetzman").joinpath("templates")


def list_templates() -> list[tuple[str, str]]:
    """Return ``(name, description)`` for every shipped template, name-sorted."""
    out: list[tuple[str, str]] = []
    root = _templates_root()
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name)
    except (FileNotFoundError, NotADirectoryError, OSError):
        return out
    for entry in entries:
        if not entry.name.endswith(".yaml"):
            continue
        try:
            data = yaml.safe_load(entry.read_text()) or {}
        except (yaml.YAMLError, OSError):  # a malformed template still lists (no desc)
            data = {}
        desc = str(data.get("description", "")) if isinstance(data, dict) else ""
        out.append((entry.name[: -len(".yaml")], desc))
    return out


def load_template(name: str) -> dict:
    """Load and parse template *name*. Raises ``FileNotFoundError`` / ``ValueError``."""
    path = _templates_root().joinpath(f"{name}.yaml")
    if not path.is_file():
        raise FileNotFoundError(name)
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"template '{name}' is not a YAML mapping")
    return data


def _set_role_label(vm_name: str, template: str) -> None:
    """Record the applied template as an Incus instance label (host side, best-effort).

    The VM->role mapping lives as ``user.hetzman.template`` on the Incus instance, NOT in
    etcd: hetzman's etcd holds only network state (dns/nat/ip-pool/port-forward/nodes) and
    the instance-watcher reconciles network only — it must never auto-provision software.
    """
    try:
        subprocess.run(
            ["sudo", "incus", "config", "set", vm_name, f"user.hetzman.template={template}"],
            check=True,
            capture_output=True,
            timeout=15,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        log_message(f"Warning: could not label {vm_name} with template: {exc}", "WARNING")


def apply_template(vm_name: str, name: str) -> bool:
    """Apply template *name* to *vm_name*. Returns ``True`` only on full success.

    A failed ``required`` step (or the apt pass) aborts immediately and returns ``False``;
    a failed ``required: false`` step logs a warning, continues, and downgrades the result.
    """
    data = load_template(name)
    log_message(f"Applying template '{name}' to {vm_name}...")

    apt_packages = data.get("apt") or []
    if apt_packages:
        run_vm_exec(vm_name, ["apt-get", "update", "-y"], "apt update", timeout=300)
        if not run_vm_exec(
            vm_name,
            ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", *apt_packages],
            f"apt install ({len(apt_packages)} packages)",
            timeout=1800,
        ):
            log_message("apt install failed — aborting template apply.", "ERROR")
            return False

    ok = True
    for step in data.get("scripts") or []:
        step_name = str(step.get("name", "script"))
        run = step.get("run", "")
        if not run:
            continue
        required = bool(step.get("required", True))
        timeout = int(step.get("timeout", 600))
        if not run_vm_exec(vm_name, ["bash", "-c", run], f"step: {step_name}", timeout=timeout):
            if required:
                log_message(f"Required step '{step_name}' failed — aborting.", "ERROR")
                return False
            log_message(f"Optional step '{step_name}' failed — continuing.", "WARNING")
            ok = False

    _set_role_label(vm_name, name)
    return ok
