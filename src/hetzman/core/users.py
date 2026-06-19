"""VM user management (add / remove / change-keys) as core generators.

These drive ``incus exec`` via :func:`hetzman.vm_helpers.run_vm_exec` (which
returns bool and logs its own step detail). Confirmation for the destructive
``remove`` is the caller's responsibility.
"""
from __future__ import annotations

import subprocess

from ..vm_helpers import check_vm_exists, check_vm_user_exists, run_vm_exec
from .errors import CoreError, NotFoundError, ValidationError
from .events import OpResult, ProgressEvent, ProgressGen, Severity
from .privilege import require_root


def _push_key(vm_name: str, key_file: str, auth_keys: str) -> None:
    """incus file push the public key, or raise CoreError."""
    try:
        subprocess.run(
            ["sudo", "incus", "file", "push", key_file, f"{vm_name}{auth_keys}"],
            check=True, capture_output=True, text=True, timeout=10,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise CoreError(f"Could not push SSH key: {getattr(exc, 'stderr', exc)}")


def add_user(
    vm_name: str,
    username: str,
    key_file: str,
    *,
    sudo: bool = False,
) -> ProgressGen:
    """Create a user on a VM with an SSH key and optional passwordless sudo."""
    require_root()
    if not check_vm_exists(vm_name):
        raise NotFoundError(f"VM '{vm_name}' not found")
    if check_vm_user_exists(vm_name, username):
        raise ValidationError(f"User '{username}' already exists on {vm_name}")

    yield ProgressEvent(Severity.INFO, f"Creating user '{username}' on {vm_name}...")
    user_home = f"/home/{username}"
    ssh_dir = f"{user_home}/.ssh"
    auth_keys = f"{ssh_dir}/authorized_keys"

    if not run_vm_exec(vm_name, ["useradd", "-m", "-s", "/bin/bash", username], f"Creating user {username}"):
        raise CoreError(f"Failed to create user {username}")
    if not run_vm_exec(vm_name, ["passwd", "-l", username], f"Locking password for {username}"):
        yield ProgressEvent(Severity.WARNING, f"Could not lock password for {username}")
    if not run_vm_exec(vm_name, ["mkdir", "-p", ssh_dir], "Creating .ssh directory"):
        raise CoreError("Failed to create .ssh directory")

    try:
        _push_key(vm_name, key_file, auth_keys)
    except CoreError:
        # Compensation: roll back the half-created user.
        run_vm_exec(vm_name, ["userdel", "-r", username], f"Cleaning up failed user {username}")
        raise

    if not run_vm_exec(vm_name, ["chown", "-R", f"{username}:{username}", ssh_dir], "Setting .ssh owner"):
        yield ProgressEvent(Severity.WARNING, f"Could not set owner on {ssh_dir}")
    if not run_vm_exec(vm_name, ["chmod", "700", ssh_dir], "Setting .ssh permissions"):
        yield ProgressEvent(Severity.WARNING, f"Could not set permissions on {ssh_dir}")
    if not run_vm_exec(vm_name, ["chmod", "600", auth_keys], "Setting authorized_keys permissions"):
        yield ProgressEvent(Severity.WARNING, f"Could not set permissions on {auth_keys}")

    if sudo:
        sudo_file = f"/etc/sudoers.d/90-hetzman-{username}"
        sudo_cmd = f"echo '{username} ALL=(ALL) NOPASSWD: ALL' > {sudo_file}"
        if not run_vm_exec(vm_name, ["bash", "-c", sudo_cmd], "Applying sudo rule"):
            yield ProgressEvent(Severity.WARNING, "Could not apply sudo rule")
        if not run_vm_exec(vm_name, ["chmod", "440", sudo_file], "Setting sudo permissions"):
            yield ProgressEvent(Severity.WARNING, "Could not set sudo file permissions")

    yield ProgressEvent(Severity.SUCCESS, f"Successfully created user '{username}' on {vm_name}")
    return OpResult(ok=True, summary={"vm": vm_name, "username": username, "sudo": sudo})


def remove_user(vm_name: str, username: str) -> ProgressGen:
    """Remove a user and their home directory from a VM."""
    require_root()
    if not check_vm_exists(vm_name):
        raise NotFoundError(f"VM '{vm_name}' not found")
    if not check_vm_user_exists(vm_name, username):
        raise NotFoundError(f"User '{username}' not found on {vm_name}")
    if username == "root":
        raise ValidationError("Cannot remove root user")

    if not run_vm_exec(vm_name, ["userdel", "-r", username], f"Removing user {username} and home dir"):
        yield ProgressEvent(Severity.ERROR, "Failed to remove user. See log.")

    sudo_file = f"/etc/sudoers.d/90-hetzman-{username}"
    run_vm_exec(vm_name, ["rm", "-f", sudo_file], "Cleaning up sudo rule")

    yield ProgressEvent(Severity.SUCCESS, f"Successfully removed user '{username}' from {vm_name}")
    return OpResult(ok=True, summary={"vm": vm_name, "username": username})


def change_keys(vm_name: str, username: str, key_file: str) -> ProgressGen:
    """Replace a user's authorized_keys file on a VM."""
    require_root()
    if not check_vm_exists(vm_name):
        raise NotFoundError(f"VM '{vm_name}' not found")
    if not check_vm_user_exists(vm_name, username):
        raise NotFoundError(f"User '{username}' not found on {vm_name}")

    yield ProgressEvent(Severity.INFO, f"Changing SSH key for '{username}' on {vm_name}...")
    auth_keys = f"/home/{username}/.ssh/authorized_keys"
    _push_key(vm_name, key_file, auth_keys)

    if not run_vm_exec(vm_name, ["chown", f"{username}:{username}", auth_keys], "Setting key owner"):
        yield ProgressEvent(Severity.WARNING, f"Could not set owner on {auth_keys}")
    if not run_vm_exec(vm_name, ["chmod", "600", auth_keys], "Setting key permissions"):
        yield ProgressEvent(Severity.WARNING, f"Could not set permissions on {auth_keys}")

    yield ProgressEvent(Severity.SUCCESS, f"Successfully changed keys for user '{username}' on {vm_name}")
    return OpResult(ok=True, summary={"vm": vm_name, "username": username})
