import json
import os
import subprocess
import time
from typing import Optional

import typer
from rich.table import Table

from ..apps import cfg_app, vm_app
from ..config import get_settings
from ..console import console
from ..etcd_kv import delete_key, get_all_with_prefix, get_key
from ..network import regenerate_hosts_file, reload_dnsmasq
from ..services import restart_instance_watcher
from ..vm_helpers import check_vm_exists, run_vm_exec, secure_vm_instance
from . import dns as dns_cmds
from . import ip as ip_cmds
from . import port as port_cmds


@vm_app.command("create")
def vm_create(
    vm_name: str = typer.Argument(..., help="Name for the new VM"),
    image: str = typer.Option("images:ubuntu/24.04/cloud", help="Incus image to use"),
    cpus: int = typer.Option(1, help="Number of vCPUs"),
    memory: str = typer.Option("2048MB", help="Memory (e.g., 512MB, 2GB)"),
    disk: str = typer.Option("20GB", help="Disk size (e.g., 10GB)"),
    network: str = typer.Option("public", help="Network type: 'public' or 'private'"),
    port_forward: bool = typer.Option(False, "--port-forward", help="Add port forwards (for public IPs)"),
):
    """Create, configure, and secure a new Incus VM"""
    if os.geteuid() != 0:
        console.print("[red]Error: This command must be run as root (or with sudo).[/red]")
        raise typer.Exit(code=1)

    if check_vm_exists(vm_name):
        console.print(f"[red]Error: VM or container '{vm_name}' already exists.[/red]")
        raise typer.Exit(code=1)

    if network not in ("public", "private"):
        console.print("[red]Error: Network must be 'public' or 'private'.[/red]")
        raise typer.Exit(code=1)

    current_server = get_settings().current_server

    console.print(f"[cyan]Starting to create VM: {vm_name}...[/cyan]")

    try:
        console.print("Step 1/5: Launching instance...")
        launch_cmd = [
            "sudo", "incus", "launch", image, vm_name,
            "--vm",
            "-c", f"limits.cpu={cpus}",
            "-c", f"limits.memory={memory}",
            "-d", f"root,size={disk}",
        ]
        subprocess.run(launch_cmd, check=True, capture_output=True, text=True, timeout=300)
        console.print(f"[green]✓ VM {vm_name} launched.[/green]")

        console.print("Step 2/5: Waiting for private IP...")
        private_ip = None
        for _ in range(12):  # up to 60s
            try:
                result = subprocess.run(
                    ["sudo", "incus", "list", vm_name, "--format", "json"],
                    capture_output=True, text=True, check=True, timeout=10,
                )
                vm_data = json.loads(result.stdout)
                if vm_data and "state" in vm_data[0] and "network" in vm_data[0]["state"]:
                    net = vm_data[0]["state"]["network"]
                    for iface in ("eth0", "enp5s0"):
                        if iface in net and net[iface].get("addresses"):
                            for addr in net[iface]["addresses"]:
                                if addr["family"] == "inet" and not addr["address"].startswith("127."):
                                    private_ip = addr["address"]
                                    break
                        if private_ip:
                            break
                if private_ip:
                    break
            except Exception:
                pass
            time.sleep(5)

        if not private_ip:
            console.print(f"[red]Error: Could not get private IP for {vm_name} after 60s.[/red]")
            raise typer.Exit(code=1)

        console.print(f"[green]✓ Got private IP: {private_ip}[/green]")

        console.print("Step 3/5: Configuring networking...")
        public_ip = None
        dns_name = f"{vm_name}.daemondreams.home.arpa"

        if network == "public":
            ip_cmds.ip_assign(instance=vm_name, ip=None)

            nat_data = get_key(f"/hetzman/nat/{current_server}/{vm_name}")
            if nat_data:
                public_ip = json.loads(nat_data).get("public_ip")
                dns_cmds.dns_add(hostname=dns_name, ip=public_ip, instance=vm_name)

            if port_forward:
                console.print(f"[cyan]Adding port forwards for {vm_name} ({public_ip}).[/cyan]")
                while True:
                    try:
                        proto = typer.prompt("Protocol (tcp/udp, 'done' to finish)", default="tcp")
                        if proto == "done":
                            break
                        pub_port = typer.prompt("Public port", type=int)
                        priv_port = typer.prompt("Private port", type=int, default=pub_port)
                        desc = typer.prompt("Description", default="")
                        port_cmds.port_add(
                            instance=vm_name,
                            public_port=pub_port,
                            private_port=priv_port,
                            protocol=proto,
                            description=desc,
                        )
                    except Exception as e:
                        console.print(f"[red]Invalid input: {e}[/red]")
        else:
            dns_cmds.dns_add(hostname=dns_name, ip=private_ip, instance=vm_name)

        console.print("[green]✓ Networking configured.[/green]")

        console.print("Step 4/5: Securing VM...")
        if not secure_vm_instance(vm_name):
            console.print("[red]Error: VM was created but security hardening failed.[/red]")
        else:
            console.print("[green]✓ VM security hardened.[/green]")

        console.print("Step 5/5: Done!")
        table = Table(title=f"New VM Summary: {vm_name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Name", vm_name)
        table.add_row("Image", image)
        table.add_row("vCPUs", str(cpus))
        table.add_row("Memory", memory)
        table.add_row("Disk", disk)
        table.add_row("Hostname", dns_name)
        table.add_row("Private IP", private_ip)
        table.add_row("Public IP", public_ip if public_ip else "N/A (Private)")
        console.print(table)

        restart_instance_watcher()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"\n[red]Error during VM creation: {e}[/red]")
        console.print(f"[yellow]Attempting to clean up failed VM: {vm_name}...[/yellow]")
        try:
            subprocess.run(
                ["sudo", "incus", "stop", vm_name, "--force"],
                capture_output=True, text=True, timeout=30,
            )
            subprocess.run(
                ["sudo", "incus", "delete", vm_name],
                capture_output=True, text=True, timeout=30,
            )
            console.print("[green]✓ Cleanup successful.[/green]")
        except Exception:
            console.print(f"[red]✗ Cleanup failed. Manual removal of {vm_name} may be required.[/red]")
        raise typer.Exit(code=1)


@vm_app.command("delete")
def vm_delete(
    vm_name: str = typer.Argument(..., help="Name of the VM to delete"),
):
    """Delete a VM and clean up all associated DNS and network rules"""
    if os.geteuid() != 0:
        console.print("[red]Error: This command must be run as root (or with sudo).[/red]")
        raise typer.Exit(code=1)

    if not check_vm_exists(vm_name):
        console.print(f"[red]Error: VM or container '{vm_name}' not found.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[yellow]This will permanently delete '{vm_name}' and all associated data.[/yellow]")
    if not typer.confirm("Are you sure you want to continue?"):
        console.print("[red]Delete cancelled.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Deleting {vm_name}...[/cyan]")

    try:
        console.print("Step 1/3: Releasing public IP and port forwards...")
        ip_cmds.ip_release(instance=vm_name)

        console.print("Step 2/3: Removing DNS records...")
        dns_records = get_all_with_prefix("/hetzman/dns/")
        records_removed = 0
        for key, data in dns_records.items():
            if data.get("instance") == vm_name:
                hostname = key.replace("/hetzman/dns/", "")
                if delete_key(key):
                    console.print(f"  [green]✓ Removed DNS: {hostname}[/green]")
                    records_removed += 1
                else:
                    console.print(f"  [red]✗ Failed to remove DNS: {hostname}[/red]")

        if records_removed > 0:
            regenerate_hosts_file()
            reload_dnsmasq()
        else:
            console.print(f"  [yellow]No DNS records found for {vm_name}[/yellow]")

        console.print("Step 3/3: Stopping and deleting instance...")
        subprocess.run(
            ["sudo", "incus", "stop", vm_name, "--force"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        console.print("  [green]✓ Instance stopped.[/green]")

        subprocess.run(
            ["sudo", "incus", "delete", vm_name],
            check=True, capture_output=True, text=True, timeout=30,
        )
        console.print("  [green]✓ Instance deleted.[/green]")

        console.print(f"\n[green]Successfully deleted {vm_name} and all related rules.[/green]")
        restart_instance_watcher()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"\n[red]Error during VM deletion: {e}[/red]")
        console.print("[yellow]Some cleanup steps may have failed. Check 'incus list' and 'hetzman status'.[/yellow]")
        raise typer.Exit(code=1)


@vm_app.command("change")
def vm_change(
    vm_name: str = typer.Argument(..., help="Name of the VM to modify"),
    cpus: Optional[int] = typer.Option(None, help="New number of vCPUs"),
    memory: Optional[str] = typer.Option(None, help="New memory amount (e.g., 4GB)"),
):
    """Change CPU or memory for a VM (requires restart)"""
    if os.geteuid() != 0:
        console.print("[red]Error: This command must be run as root (or with sudo).[/red]")
        raise typer.Exit(code=1)

    if not cpus and not memory:
        console.print("[red]Error: You must specify --cpus or --memory.[/red]")
        raise typer.Exit(code=1)

    if not check_vm_exists(vm_name):
        console.print(f"[red]Error: VM or container '{vm_name}' not found.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[yellow]This will stop and restart {vm_name} to apply changes.[/yellow]")
    if not typer.confirm("Are you sure you want to continue?"):
        console.print("[red]Change cancelled.[/red]")
        raise typer.Exit(code=1)

    try:
        console.print(f"Stopping {vm_name}...")
        subprocess.run(
            ["sudo", "incus", "stop", vm_name],
            check=True, capture_output=True, text=True, timeout=60,
        )

        if cpus:
            console.print(f"Applying new CPU limit: {cpus}")
            subprocess.run(
                ["sudo", "incus", "config", "set", vm_name, f"limits.cpu={cpus}"],
                check=True, capture_output=True, text=True, timeout=10,
            )

        if memory:
            console.print(f"Applying new memory limit: {memory}")
            subprocess.run(
                ["sudo", "incus", "config", "set", vm_name, f"limits.memory={memory}"],
                check=True, capture_output=True, text=True, timeout=10,
            )

        console.print(f"Starting {vm_name}...")
        subprocess.run(
            ["sudo", "incus", "start", vm_name],
            check=True, capture_output=True, text=True, timeout=30,
        )

        console.print(f"[green]✓ Successfully changed limits for {vm_name}[/green]")
        restart_instance_watcher()

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"\n[red]Error during VM change: {e}[/red]")
        console.print("[yellow]Attempting to restart VM in its previous state...[/yellow]")
        try:
            subprocess.run(["sudo", "incus", "start", vm_name], capture_output=True, timeout=30)
        except Exception:
            pass
        raise typer.Exit(code=1)


@cfg_app.command("install-defaults")
def vm_cfg_defaults(
    vm_name: str = typer.Argument(..., help="Name of the VM to configure"),
):
    """Install default tools (btop, iftop, git, gh)"""
    if os.geteuid() != 0:
        console.print("[red]Error: This command must be run as root (or with sudo).[/red]")
        raise typer.Exit(code=1)

    if not check_vm_exists(vm_name):
        console.print(f"[red]Error: VM or container '{vm_name}' not found.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Installing default software on {vm_name}...[/cyan]")

    if not run_vm_exec(vm_name, ["apt-get", "update", "-y"], "Updating apt cache"):
        raise typer.Exit(code=1)

    if not run_vm_exec(
        vm_name,
        ["apt-get", "install", "-y", "iftop", "btop", "git", "curl", "ca-certificates"],
        "Installing apt-utils (iftop, btop, git, curl)",
    ):
        console.print("[yellow]Warning: could not install all apt packages. Continuing...[/yellow]")

    console.print("[bold]Installing GitHub CLI (gh) system-wide...[/bold]")
    gh_install_script = (
        "curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg "
        "| dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg && "
        "chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg && "
        "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] "
        "https://cli.github.com/packages stable main\" > /etc/apt/sources.list.d/github-cli.list && "
        "apt-get update -y && "
        "apt-get install gh -y"
    )
    if not run_vm_exec(vm_name, ["bash", "-c", gh_install_script], "Running gh install script", timeout=300):
        console.print("[yellow]Warning: Could not install GitHub CLI (gh).[/yellow]")

    console.print(f"[green]✓ Default software installation complete for {vm_name}[/green]")
