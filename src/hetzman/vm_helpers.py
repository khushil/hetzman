"""Helpers for ``incus exec`` calls and VM hardening."""
from __future__ import annotations

import os
import subprocess
from typing import List, Optional, Tuple

from .config import HOST_ROOT_KEYS
from .logging import log_message


def run_vm_exec(
    vm_name: str,
    cmd_list: List[str],
    step_msg: str,
    timeout: int = 120,
    user_id: Optional[str] = None,
) -> bool:
    """Run an ``incus exec`` command, log on failure."""
    log_message(f"  {step_msg}...")
    base_cmd = ["sudo", "incus", "exec", vm_name]
    if user_id:
        base_cmd.extend(["--user", user_id])
    base_cmd.append("--")
    try:
        subprocess.run(
            base_cmd + cmd_list,
            check=True, capture_output=True, text=True, timeout=timeout,
        )
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"  FAILED: {e.stderr[:200]}...", "ERROR")
        log_message(f"Failed to {step_msg.lower()} on {vm_name}: {e.stderr}", "ERROR")
        return False
    except Exception as e:
        log_message(f"  FAILED: {e}", "ERROR")
        log_message(f"Failed to {step_msg.lower()} on {vm_name}: {e}", "ERROR")
        return False


def check_vm_exists(vm_name: str) -> bool:
    try:
        subprocess.run(
            ["sudo", "incus", "info", vm_name],
            check=True, text=True, timeout=5,
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False


def check_vm_user_exists(vm_name: str, username: str) -> bool:
    try:
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "id", username],
            check=True, capture_output=True, text=True, timeout=5,
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False


def get_vm_users(vm_name: str) -> List[Tuple[str, str]]:
    """Return ``(username, home_dir)`` for root + real users (UID >= 1000, /home/*)."""
    users: List[Tuple[str, str]] = [("root", "/root")]
    try:
        result = subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "cat", "/etc/passwd"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.split(":")
            if len(parts) < 6:
                continue
            username, _, uid_str, _, _, home_dir = parts[:6]
            try:
                uid = int(uid_str)
            except ValueError:
                continue
            if uid >= 1000 and home_dir.startswith("/home/"):
                users.append((username, home_dir))
        return users
    except Exception as e:
        log_message(f"Could not get users from {vm_name}: {e}", "ERROR")
        return users


def secure_vm_instance(vm_name: str) -> bool:
    """Install/harden SSH + fail2ban on a single VM."""
    if not check_vm_exists(vm_name):
        log_message(f"Skipping {vm_name} (does not exist or not running).")
        return False

    log_message(f"--- Processing VM: {vm_name} ---")

    if not os.path.exists(HOST_ROOT_KEYS):
        log_message(f"Error: Host key file not found at {HOST_ROOT_KEYS}", "ERROR")
        return False

    try:
        log_message("Step 1/8: Installing/Enabling openssh-server...")
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "apt-get", "update", "-y"],
            capture_output=True, text=True, timeout=120,
        )
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "apt-get", "install", "openssh-server", "-y"],
            check=True, capture_output=True, text=True, timeout=120,
        )
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "systemctl", "enable", "--now", "ssh"],
            check=True, capture_output=True, text=True, timeout=30,
        )

        log_message("Step 2/8: Ensuring /root/.ssh directory...")
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "mkdir", "-p", "/root/.ssh"],
            check=True, capture_output=True, text=True, timeout=10,
        )

        log_message("Step 3/8: Pushing authorized_keys...")
        subprocess.run(
            ["sudo", "incus", "file", "push", HOST_ROOT_KEYS, f"{vm_name}/root/.ssh/authorized_keys"],
            check=True, capture_output=True, text=True, timeout=10,
        )

        log_message("Step 4/8: Setting permissions...")
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "chmod", "700", "/root/.ssh"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "chmod", "600", "/root/.ssh/authorized_keys"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "chown", "-R", "root:root", "/root/.ssh"],
            check=True, capture_output=True, text=True, timeout=10,
        )

        log_message("Step 5/8: Hardening sshd_config (key-only)...")
        sed_command = (
            "sed -i -e 's/^#*PermitRootLogin .*/PermitRootLogin prohibit-password/' "
            "-e 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' "
            "-e 's/^#*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' "
            "/etc/ssh/sshd_config"
        )
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "bash", "-c", sed_command],
            check=True, capture_output=True, text=True, timeout=10,
        )

        log_message("Step 6/8: Restarting sshd service...")
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "systemctl", "restart", "ssh"],
            check=True, capture_output=True, text=True, timeout=10,
        )

        log_message("Step 7/8: Installing fail2ban...")
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "apt-get", "install", "fail2ban", "-y"],
            check=True, capture_output=True, text=True, timeout=120,
        )

        log_message("Step 8/8: Configuring fail2ban...")
        jail_local_content = (
            "[sshd]\n"
            "enabled = true\n"
            "port    = ssh\n"
            "logpath = %(sshd_log)s\n"
            "backend = %(sshd_backend)s\n"
        )
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "bash", "-c",
             f"echo -e '{jail_local_content}' > /etc/fail2ban/jail.local"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "incus", "exec", vm_name, "--", "systemctl", "enable", "--now", "fail2ban"],
            check=True, capture_output=True, text=True, timeout=30,
        )

        log_message(f"Successfully secured {vm_name}", "INFO")
        return True

    except subprocess.CalledProcessError as e:
        log_message(f"Failed to secure {vm_name}: {e.stderr}", "ERROR")
        return False
    except Exception as e:
        log_message(f"An unexpected error occurred while securing {vm_name}: {e}", "ERROR")
        return False
