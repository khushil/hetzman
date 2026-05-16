import json
import subprocess
import time
from datetime import datetime
from typing import Optional

import typer
from rich.table import Table

from ..apps import app
from ..config import get_settings
from ..console import console
from ..etcd_kv import delete_key, get_all_with_prefix, get_key, put_key
from ..logging import log_message
from ..network import (
    add_ip_to_interface,
    apply_nat_rules,
    remove_ip_from_interface,
)
from ..services import restart_instance_watcher


@app.command()
def ip_list(
    server: Optional[str] = typer.Option(None, help="Filter by server"),
    available_only: bool = typer.Option(False, "--available", help="Show only available IPs"),
):
    """List public IP pool"""
    ip_pool = get_all_with_prefix("/hetzman/ip-pool/")

    if not ip_pool:
        console.print("[yellow]No IPs found[/yellow]")
        return

    table = Table(title="Public IP Pool")
    table.add_column("IP Address", style="cyan")
    table.add_column("Server", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Assigned To", style="yellow")

    for key, data in sorted(ip_pool.items()):
        ip_address = key.replace("/hetzman/ip-pool/", "")

        if server and data.get("server") != server:
            continue
        if available_only and data.get("status") != "available":
            continue

        status = data.get("status", "unknown")
        status_color = "green" if status == "available" else "red"

        table.add_row(
            ip_address,
            data.get("server", ""),
            f"[{status_color}]{status}[/{status_color}]",
            data.get("assigned_to", "-"),
        )

    console.print(table)


@app.command()
def ip_assign(
    instance: str = typer.Argument(..., help="Instance name"),
    ip: Optional[str] = typer.Option(None, help="Specific IP to assign"),
):
    """Assign a public IP from the pool to an instance"""
    settings = get_settings()
    current_server = settings.current_server

    existing_nat = get_key(f"/hetzman/nat/{current_server}/{instance}")
    if existing_nat:
        nat_data = json.loads(existing_nat)
        console.print(f"[yellow]Instance '{instance}' already has public IP {nat_data['public_ip']}[/yellow]")
        console.print(f"[yellow]Release it first with: sudo hetzman ip-release {instance}[/yellow]")
        return

    try:
        result = subprocess.run(
            ["sudo", "incus", "list", instance, "--format", "json"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        instances = json.loads(result.stdout)
        if not instances:
            console.print(f"[red]Instance '{instance}' not found[/red]")
            return

        instance_data = instances[0]

        retries = 6
        private_ip: Optional[str] = None

        while retries > 0 and not private_ip:
            network_state = instance_data.get("state", {}).get("network", {})
            has_addresses = any(
                iface in network_state and network_state[iface].get("addresses")
                for iface in ("eth0", "enp5s0")
            )

            if not has_addresses:
                if retries > 1:
                    console.print(f"[yellow]Waiting for instance to get IP... ({retries*5}s remaining)[/yellow]")
                    time.sleep(5)
                    result = subprocess.run(
                        ["sudo", "incus", "list", instance, "--format", "json"],
                        capture_output=True, text=True, check=True, timeout=10,
                    )
                    instances = json.loads(result.stdout)
                    if instances:
                        instance_data = instances[0]
                    retries -= 1
                    continue
                else:
                    console.print(f"[red]Instance '{instance}' has no IP address after 30s[/red]")
                    return

            for iface in ("eth0", "enp5s0"):
                if iface in network_state:
                    for addr in network_state[iface].get("addresses", []):
                        if addr["family"] == "inet" and not addr["address"].startswith("127."):
                            private_ip = addr["address"]
                            break
                if private_ip:
                    break

            if not private_ip and retries > 1:
                time.sleep(5)
                retries -= 1

        if not private_ip:
            console.print(f"[red]Could not determine private IP for instance '{instance}'[/red]")
            return

        ip_pool = get_all_with_prefix("/hetzman/ip-pool/")

        if ip:
            ip_key = f"/hetzman/ip-pool/{ip}"
            if ip_key not in ip_pool:
                console.print(f"[red]IP {ip} not found in pool[/red]")
                return

            ip_data = ip_pool[ip_key]
            if ip_data["server"] != current_server:
                console.print(f"[red]IP {ip} belongs to different server[/red]")
                return

            if ip_data["status"] != "available":
                console.print(f"[red]IP {ip} is not available[/red]")
                return

            public_ip = ip
        else:
            public_ip = None
            for ip_key, ip_data in sorted(ip_pool.items()):
                if ip_data["server"] == current_server and ip_data["status"] == "available":
                    public_ip = ip_key.replace("/hetzman/ip-pool/", "")
                    break

            if not public_ip:
                console.print(f"[red]No available IPs in pool for {current_server}[/red]")
                return

        if not add_ip_to_interface(public_ip):
            console.print(f"[red]Failed to add IP {public_ip} to host interface[/red]")
            return

        ip_data = ip_pool[f"/hetzman/ip-pool/{public_ip}"]
        ip_data["status"] = "assigned"
        ip_data["assigned_to"] = instance
        ip_data["assigned_at"] = datetime.now().isoformat()
        put_key(f"/hetzman/ip-pool/{public_ip}", json.dumps(ip_data))

        nat_data = {
            "public_ip": public_ip,
            "private_ip": private_ip,
            "instance_name": instance,
            "enabled": True,
            "created": datetime.now().isoformat(),
        }
        put_key(f"/hetzman/nat/{current_server}/{instance}", json.dumps(nat_data))

        console.print(f"[green]Assigned {public_ip} to {instance} ({private_ip})[/green]")
        log_message(f"Assigned {public_ip} to {instance} ({private_ip})")

        apply_nat_rules()
        restart_instance_watcher()

    except Exception as e:
        console.print(f"[red]Error assigning IP: {e}[/red]")
        log_message(f"Error assigning IP: {e}", "ERROR")


@app.command()
def ip_release(
    instance: str = typer.Argument(..., help="Instance name"),
):
    """Release public IP from an instance"""
    current_server = get_settings().current_server

    nat_data = get_key(f"/hetzman/nat/{current_server}/{instance}")
    if not nat_data:
        console.print(f"[yellow]No NAT rule found for instance '{instance}'[/yellow]")
        return

    nat_rule = json.loads(nat_data)
    public_ip = nat_rule["public_ip"]

    delete_key(f"/hetzman/nat/{current_server}/{instance}")

    port_forwards = get_all_with_prefix(f"/hetzman/port-forward/{current_server}/")
    for key, data in port_forwards.items():
        if data.get("instance_name") == instance:
            delete_key(key)

    ip_data = get_key(f"/hetzman/ip-pool/{public_ip}")
    if ip_data:
        pool_entry = json.loads(ip_data)
        pool_entry["status"] = "available"
        pool_entry["assigned_to"] = None
        pool_entry["assigned_at"] = None
        put_key(f"/hetzman/ip-pool/{public_ip}", json.dumps(pool_entry))

    if not remove_ip_from_interface(public_ip):
        console.print(f"[yellow]Warning: Failed to remove IP {public_ip} from host interface[/yellow]")

    console.print(f"[green]Released {public_ip} from {instance}[/green]")
    log_message(f"Released {public_ip} from {instance}")

    apply_nat_rules()
    restart_instance_watcher()
