import json
import os
import subprocess
from pathlib import Path
from typing import Optional

import typer

from ..apps import users_app
from ..console import console
from ..vm_helpers import (
    check_vm_exists,
    check_vm_user_exists,
    get_vm_users,
    run_vm_exec,
)


def _require_root():
    if os.geteuid() != 0:
        console.print("[red]Error: This command must be run as root (or with sudo).[/red]")
        raise typer.Exit(code=1)


@users_app.command("add")
def vm_users_add(
    vm_name: str = typer.Argument(..., help="Name of the VM"),
    username: str = typer.Argument(..., help="Username to create"),
    key_file: Path = typer.Option(
        ..., "--key", help="Path to the user's public SSH key file on the host",
        exists=True, file_okay=True, dir_okay=False, readable=True,
    ),
    sudo: bool = typer.Option(False, "--sudo", help="Grant passwordless sudo privileges"),
):
    """Add a new user to a VM with SSH key and optional sudo."""
    _require_root()

    if not check_vm_exists(vm_name):
        console.print(f"[red]Error: VM '{vm_name}' not found.[/red]")
        raise typer.Exit(code=1)

    if check_vm_user_exists(vm_name, username):
        console.print(f"[red]Error: User '{username}' already exists on {vm_name}.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Creating user '{username}' on {vm_name}...[/cyan]")

    user_home = f"/home/{username}"
    ssh_dir = f"{user_home}/.ssh"
    auth_keys = f"{ssh_dir}/authorized_keys"

    if not run_vm_exec(vm_name, ["useradd", "-m", "-s", "/bin/bash", username], f"Creating user {username}"):
        raise typer.Exit(code=1)

    if not run_vm_exec(vm_name, ["passwd", "-l", username], f"Locking password for {username}"):
        console.print(f"[yellow]Warning: Could not lock password for {username}.[/yellow]")

    if not run_vm_exec(vm_name, ["mkdir", "-p", ssh_dir], "Creating .ssh directory"):
        raise typer.Exit(code=1)

    console.print("  Pushing SSH key...")
    try:
        subprocess.run(
            ["sudo", "incus", "file", "push", str(key_file), f"{vm_name}{auth_keys}"],
            check=True, capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        console.print(f"[red]FAILED: Could not push SSH key: {e}[/red]")
        run_vm_exec(vm_name, ["userdel", "-r", username], f"Cleaning up failed user {username}")
        raise typer.Exit(code=1)

    if not run_vm_exec(vm_name, ["chown", "-R", f"{username}:{username}", ssh_dir], "Setting .ssh owner"):
        console.print(f"[yellow]Warning: Could not set owner on {ssh_dir}[/yellow]")
    if not run_vm_exec(vm_name, ["chmod", "700", ssh_dir], "Setting .ssh permissions"):
        console.print(f"[yellow]Warning: Could not set permissions on {ssh_dir}[/yellow]")
    if not run_vm_exec(vm_name, ["chmod", "600", auth_keys], "Setting authorized_keys permissions"):
        console.print(f"[yellow]Warning: Could not set permissions on {auth_keys}[/yellow]")

    if sudo:
        console.print("  Granting passwordless sudo...")
        sudo_file = f"/etc/sudoers.d/90-hetzman-{username}"
        sudo_cmd = f"echo '{username} ALL=(ALL) NOPASSWD: ALL' > {sudo_file}"
        if not run_vm_exec(vm_name, ["bash", "-c", sudo_cmd], "Applying sudo rule"):
            console.print("[yellow]Warning: Could not apply sudo rule.[/yellow]")
        if not run_vm_exec(vm_name, ["chmod", "440", sudo_file], "Setting sudo permissions"):
            console.print("[yellow]Warning: Could not set sudo file permissions.[/yellow]")

    console.print(f"[green]✓ Successfully created user '{username}' on {vm_name}.[/green]")


@users_app.command("remove")
def vm_users_remove(
    vm_name: str = typer.Argument(..., help="Name of the VM"),
    username: str = typer.Argument(..., help="Username to remove"),
):
    """Remove a user and their home directory from a VM."""
    _require_root()

    if not check_vm_exists(vm_name):
        console.print(f"[red]Error: VM '{vm_name}' not found.[/red]")
        raise typer.Exit(code=1)

    if not check_vm_user_exists(vm_name, username):
        console.print(f"[red]Error: User '{username}' not found on {vm_name}.[/red]")
        raise typer.Exit(code=1)

    if username == "root":
        console.print("[red]Error: Cannot remove root user.[/red]")
        raise typer.Exit(code=1)

    if not typer.confirm(
        f"Are you sure you want to remove user '{username}' and their home directory from {vm_name}?"
    ):
        console.print("[red]Remove cancelled.[/red]")
        raise typer.Exit(code=1)

    if not run_vm_exec(vm_name, ["userdel", "-r", username], f"Removing user {username} and home dir"):
        console.print("[red]Error: Failed to remove user. See log.[/red]")

    sudo_file = f"/etc/sudoers.d/90-hetzman-{username}"
    run_vm_exec(vm_name, ["rm", "-f", sudo_file], "Cleaning up sudo rule")

    console.print(f"[green]✓ Successfully removed user '{username}' from {vm_name}.[/green]")


@users_app.command("change-keys")
def vm_users_change_keys(
    vm_name: str = typer.Argument(..., help="Name of the VM"),
    username: str = typer.Argument(..., help="Username to update"),
    key_file: Path = typer.Option(
        ..., "--key", help="Path to the user's *new* public SSH key file",
        exists=True, file_okay=True, dir_okay=False, readable=True,
    ),
):
    """Replace a user's authorized_keys file on a VM."""
    _require_root()

    if not check_vm_exists(vm_name):
        console.print(f"[red]Error: VM '{vm_name}' not found.[/red]")
        raise typer.Exit(code=1)

    if not check_vm_user_exists(vm_name, username):
        console.print(f"[red]Error: User '{username}' not found on {vm_name}.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Changing SSH key for '{username}' on {vm_name}...[/cyan]")

    auth_keys = f"/home/{username}/.ssh/authorized_keys"

    console.print("  Pushing new key...")
    try:
        subprocess.run(
            ["sudo", "incus", "file", "push", str(key_file), f"{vm_name}{auth_keys}"],
            check=True, capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        console.print(f"[red]FAILED: Could not push new SSH key: {e}[/red]")
        raise typer.Exit(code=1)

    if not run_vm_exec(vm_name, ["chown", f"{username}:{username}", auth_keys], "Setting key owner"):
        console.print(f"[yellow]Warning: Could not set owner on {auth_keys}[/yellow]")
    if not run_vm_exec(vm_name, ["chmod", "600", auth_keys], "Setting key permissions"):
        console.print(f"[yellow]Warning: Could not set permissions on {auth_keys}[/yellow]")

    console.print(f"[green]✓ Successfully changed keys for user '{username}' on {vm_name}.[/green]")


@users_app.command("audit")
def vm_users_audit(
    vm_name: Optional[str] = typer.Argument(None, help="The name of the VM to audit."),
    all_vms: bool = typer.Option(False, "--all", help="Audit all running Incus VMs."),
):
    """Audit users, SSH keys, and fail2ban status on VMs."""
    _require_root()

    if not vm_name and not all_vms:
        console.print("[red]Error: You must provide a VM name or use --all.[/red]")
        raise typer.Exit(code=1)

    vm_list = []
    if all_vms:
        console.print("[cyan]Targeting all RUNNING Incus VMs...[/cyan]")
        try:
            result = subprocess.run(
                ["sudo", "incus", "list", "--format", "json"],
                capture_output=True, text=True, check=True, timeout=10,
            )
            vms = json.loads(result.stdout)
            vm_list = [vm["name"] for vm in vms if vm["status"].lower() == "running"]
            if not vm_list:
                console.print("[yellow]No running VMs found.[/yellow]")
                return
        except Exception as e:
            console.print(f"[red]Error listing VMs: {e}[/red]")
            raise typer.Exit(code=1)
    else:
        vm_list.append(vm_name)

    total = len(vm_list)
    for i, vm in enumerate(vm_list):
        if not check_vm_exists(vm):
            console.print(f"\n[yellow]Skipping {i+1} of {total}: {vm} (does not exist or not running).[/yellow]")
            continue

        console.print(f"\n[bold cyan]--- Audit for {vm} ---[/bold cyan]")

        users = get_vm_users(vm)
        if not users:
            console.print(f"  [red]Could not retrieve users from {vm}.[/red]")
            continue

        for username, home_dir in users:
            console.print(f"  [green]User: {username}[/green] (home: {home_dir})")

            auth_keys_file = f"{home_dir}/.ssh/authorized_keys"

            try:
                cat_proc = subprocess.run(
                    ["sudo", "incus", "exec", vm, "--", "cat", auth_keys_file],
                    capture_output=True, text=True, timeout=5,
                )

                if cat_proc.returncode != 0:
                    if "No such file" in cat_proc.stderr:
                        console.print("    - [yellow]No authorized_keys file.[/yellow]")
                    else:
                        console.print(f"    - [red]Could not read keys: {cat_proc.stderr[:100].strip()}[/red]")
                    continue

                keys_content = cat_proc.stdout
                if not keys_content.strip():
                    console.print("    - [yellow]authorized_keys file is empty.[/yellow]")
                    continue

                keygen_proc = subprocess.run(
                    ["ssh-keygen", "-lf", "-"],
                    input=keys_content,
                    capture_output=True, text=True, check=True,
                )

                for line in keygen_proc.stdout.strip().split("\n"):
                    console.print(f"    - [default]{line.strip()}[/default]")

            except Exception as e:
                console.print(f"    - [red]Error processing keys: {e}[/red]")

        console.print("  [green]Fail2Ban Status (sshd):[/green]")
        try:
            f2b_proc = subprocess.run(
                ["sudo", "incus", "exec", vm, "--", "fail2ban-client", "status", "sshd"],
                capture_output=True, text=True, timeout=10, check=True,
            )

            status_output = f2b_proc.stdout.strip()
            if not status_output:
                console.print("    - [yellow]No output from fail2ban-client.[/yellow]")
            else:
                for line in status_output.split("\n"):
                    console.print(f"    [default]{line.strip()}[/default]")

        except subprocess.CalledProcessError as e:
            if "No such file" in e.stderr or "not found" in e.stderr:
                console.print("    - [yellow]fail2ban-client not found or not running.[/yellow]")
            else:
                console.print(f"    - [red]Error getting status: {e.stderr[:100].strip()}[/red]")
        except Exception as e:
            console.print(f"    - [red]Error processing fail2ban: {e}[/red]")
