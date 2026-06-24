"""VM user management (add / remove / change-keys) as core generators.

These drive ``incus exec`` via :func:`hetzman.vm_helpers.run_vm_exec` (which
returns bool and logs its own step detail). Confirmation for the destructive
``remove`` is the caller's responsibility.
"""
from __future__ import annotations

import os
import subprocess
import tempfile

from ..logging import log_message
from ..vm_helpers import check_vm_exists, check_vm_user_exists, run_vm_exec
from . import exec as host_exec
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

    pubkey = _read_pubkey(key_file)  # accepts inline content or a path
    fd, tmp_key = tempfile.mkstemp(suffix=".pub")
    try:
        with os.fdopen(fd, "w") as tf:
            tf.write(pubkey)
        _push_key(vm_name, tmp_key, auth_keys)
    except CoreError:
        # Compensation: roll back the half-created user.
        run_vm_exec(vm_name, ["userdel", "-r", username], f"Cleaning up failed user {username}")
        raise
    finally:
        try:
            os.unlink(tmp_key)
        except OSError:
            pass

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


# --------------------------------------------------------------------------- #
# Host users — useradd on the bare-metal node itself, via the executor
# --------------------------------------------------------------------------- #
def _read_pubkey(key: str) -> str:
    """Resolve a public key from either inline content or a file path.

    The TUI (and cross-host delegation) pass the key text directly; the CLI
    passes a path. An ``ssh-…``/``ecdsa-…``/``sk-…`` string with a space is
    treated as content, anything else as a file to read."""
    stripped = key.strip()
    if stripped.startswith(("ssh-", "ecdsa-", "sk-", "ssh-ed25519")) and " " in stripped:
        return stripped + "\n"
    try:
        with open(key) as f:
            return f.read()
    except OSError as exc:
        raise ValidationError(f"cannot read key file {key}: {exc}")


def _host_step(host: str, argv: list[str], label: str) -> bool:
    """Run a host command via the executor; False (logged) on failure."""
    try:
        host_exec.run_on(host, argv, root=True, timeout=60)
        return True
    except CoreError as exc:
        log_message(f"host user step '{label}' failed on {host}: {exc}", "ERROR")
        return False


def check_host_user_exists(host: str, username: str) -> bool:
    res = host_exec.run_on(host, ["id", username], root=True, check=False, timeout=15)
    return res.returncode == 0


def add_host_user(host: str, username: str, key_file: str, *, sudo: bool = False) -> ProgressGen:
    """Create a user on a fleet HOST (not an instance) with an SSH key + sudo."""
    pubkey = _read_pubkey(key_file)
    if check_host_user_exists(host, username):
        raise ValidationError(f"user '{username}' already exists on host {host}")

    yield ProgressEvent(Severity.INFO, f"Creating user '{username}' on host {host}...")
    ssh_dir = f"/home/{username}/.ssh"
    auth_keys = f"{ssh_dir}/authorized_keys"

    if not _host_step(host, ["useradd", "-m", "-s", "/bin/bash", username], "useradd"):
        raise CoreError(f"failed to create user {username} on {host}")
    # Every post-useradd step is mandatory: a wrong owner/mode makes sshd silently
    # ignore the key (lockout). On ANY failure, roll the half-made user back.
    try:
        if not _host_step(host, ["passwd", "-l", username], "lock password"):
            yield ProgressEvent(Severity.WARNING, f"could not lock password for {username}")
        if not _host_step(host, ["mkdir", "-p", ssh_dir], "mkdir .ssh"):
            raise CoreError("failed to create .ssh directory")
        # Write the key already-private (umask 077 => 600); no world-readable window.
        host_exec.run_on(
            host, ["bash", "-c", f"umask 077 && tee {auth_keys} >/dev/null"],
            input=pubkey, root=True, timeout=30,
        )
        if not _host_step(host, ["chown", "-R", f"{username}:{username}", ssh_dir], "chown"):
            raise CoreError(f"failed to set owner on {ssh_dir} (sshd would ignore the key)")
        if not _host_step(host, ["chmod", "700", ssh_dir], "chmod .ssh"):
            raise CoreError(f"failed to set permissions on {ssh_dir}")
    except CoreError:
        _host_step(host, ["userdel", "-r", username], "rollback")  # compensation
        raise

    if sudo:
        sudo_file = f"/etc/sudoers.d/90-hetzman-{username}"
        rule = f"{username} ALL=(ALL) NOPASSWD: ALL"
        if not _host_step(host, ["bash", "-c", f"echo {rule!r} > {sudo_file}"], "sudo rule"):
            yield ProgressEvent(Severity.WARNING, "could not apply sudo rule")
        _host_step(host, ["chmod", "440", sudo_file], "chmod sudoers")

    yield ProgressEvent(Severity.SUCCESS, f"created user '{username}' on host {host}")
    return OpResult(ok=True, summary={"host": host, "username": username, "sudo": sudo})


def remove_host_user(host: str, username: str) -> ProgressGen:
    """Remove a user (and home dir) from a fleet host."""
    if username == "root":
        raise ValidationError("cannot remove root user")
    if not check_host_user_exists(host, username):
        raise NotFoundError(f"user '{username}' not found on host {host}")
    if not _host_step(host, ["userdel", "-r", username], "userdel"):
        yield ProgressEvent(Severity.ERROR, "failed to remove user; see log")
    _host_step(host, ["rm", "-f", f"/etc/sudoers.d/90-hetzman-{username}"], "rm sudoers")
    yield ProgressEvent(Severity.SUCCESS, f"removed user '{username}' from host {host}")
    return OpResult(ok=True, summary={"host": host, "username": username})


def change_host_keys(host: str, username: str, key_file: str) -> ProgressGen:
    """Replace a host user's authorized_keys ATOMICALLY — a mid-write failure
    (dropped pipe, full disk, timeout) leaves the original key intact rather than
    truncating it and locking the user out."""
    pubkey = _read_pubkey(key_file)
    if not check_host_user_exists(host, username):
        raise NotFoundError(f"user '{username}' not found on host {host}")
    yield ProgressEvent(Severity.INFO, f"Changing SSH key for '{username}' on host {host}...")
    auth_keys = f"/home/{username}/.ssh/authorized_keys"
    tmp = f"{auth_keys}.hetzman.tmp"
    # write temp (private) -> set owner/mode -> rename over the original, only on full success.
    script = (
        f"umask 077 && tee {tmp} >/dev/null "
        f"&& chown {username}:{username} {tmp} && chmod 600 {tmp} && mv {tmp} {auth_keys}"
    )
    try:
        host_exec.run_on(host, ["bash", "-c", script], input=pubkey, root=True, timeout=30)
    except CoreError:
        _host_step(host, ["rm", "-f", tmp], "cleanup temp")
        raise CoreError(
            f"failed to update keys for {username} on {host}; original key left intact"
        )
    yield ProgressEvent(Severity.SUCCESS, f"changed keys for '{username}' on host {host}")
    return OpResult(ok=True, summary={"host": host, "username": username})
