import subprocess

from .logging import log_message


def restart_instance_watcher() -> None:
    log_message("Restarting hetzman-instance-watcher service...")
    try:
        subprocess.run(
            ["sudo", "systemctl", "restart", "hetzman-instance-watcher"],
            check=True, capture_output=True, timeout=10,
        )
        log_message("Restarted hetzman-instance-watcher service")
    except Exception as e:
        log_message(f"Failed to restart hetzman-instance-watcher: {e}", "WARNING")
