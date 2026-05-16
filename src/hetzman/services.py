import subprocess

from .console import console
from .logging import log_message


def restart_instance_watcher() -> None:
    console.print("[cyan]Restarting hetzman-instance-watcher service...[/cyan]")
    try:
        subprocess.run(
            ["sudo", "systemctl", "restart", "hetzman-instance-watcher"],
            check=True, capture_output=True, timeout=10,
        )
        log_message("Restarted hetzman-instance-watcher service")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not restart hetzman-instance-watcher: {e}[/yellow]")
        log_message(f"Failed to restart hetzman-instance-watcher: {e}", "WARNING")
