import json
from datetime import datetime
from typing import Optional

import typer
from rich.table import Table

from ..apps import app
from ..config import get_settings
from ..console import console
from ..etcd_kv import delete_key, get_all_with_prefix, get_key, put_key
from ..logging import log_message
from ..network import apply_nat_rules
from ..services import restart_instance_watcher


@app.command()
def port_add(
    instance: str = typer.Argument(..., help="Instance name"),
    public_port: int = typer.Argument(..., help="Public port"),
    private_port: int = typer.Argument(..., help="Private port"),
    protocol: str = typer.Option("tcp", help="Protocol (tcp/udp)"),
    description: Optional[str] = typer.Option(None, help="Description"),
):
    """Add a port forward rule"""
    if not (1 <= public_port <= 65535):
        console.print(f"[red]Invalid public port: {public_port}[/red]")
        return
    if not (1 <= private_port <= 65535):
        console.print(f"[red]Invalid private port: {private_port}[/red]")
        return
    if protocol not in ("tcp", "udp"):
        console.print(f"[red]Invalid protocol: {protocol}[/red]")
        return

    current_server = get_settings().current_server

    nat_data = get_key(f"/hetzman/nat/{current_server}/{instance}")
    if not nat_data:
        console.print(f"[red]Instance '{instance}' does not have a public IP assigned[/red]")
        console.print("[yellow]Use 'hetzman ip-assign' first[/yellow]")
        return

    nat_rule = json.loads(nat_data)

    port_key = f"/hetzman/port-forward/{current_server}/{instance}-{public_port}-{protocol}"
    port_data = {
        "public_ip": nat_rule["public_ip"],
        "public_port": public_port,
        "private_ip": nat_rule["private_ip"],
        "private_port": private_port,
        "protocol": protocol,
        "instance_name": instance,
        "description": description,
        "enabled": True,
        "created": datetime.now().isoformat(),
    }

    if put_key(port_key, json.dumps(port_data)):
        console.print(
            f"[green]Added port forward: {nat_rule['public_ip']}:{public_port} -> "
            f"{nat_rule['private_ip']}:{private_port} ({protocol})[/green]"
        )
        log_message(f"Added port forward for {instance}")
        apply_nat_rules()
        restart_instance_watcher()
    else:
        console.print("[red]Failed to add port forward[/red]")


@app.command()
def port_remove(
    instance: str = typer.Argument(..., help="Instance name"),
    public_port: int = typer.Argument(..., help="Public port"),
    protocol: str = typer.Option("tcp", help="Protocol (tcp/udp)"),
):
    """Remove a port forward rule"""
    current_server = get_settings().current_server
    port_key = f"/hetzman/port-forward/{current_server}/{instance}-{public_port}-{protocol}"

    if delete_key(port_key):
        console.print("[green]Removed port forward rule[/green]")
        log_message(f"Removed port forward: {instance}:{public_port}/{protocol}")
        apply_nat_rules()
        restart_instance_watcher()
    else:
        console.print("[yellow]Port forward rule not found[/yellow]")


@app.command()
def port_list(
    instance: Optional[str] = typer.Option(None, help="Filter by instance"),
):
    """List port forward rules"""
    current_server = get_settings().current_server
    port_forwards = get_all_with_prefix(f"/hetzman/port-forward/{current_server}/")

    if not port_forwards:
        console.print("[yellow]No port forward rules found[/yellow]")
        return

    table = Table(title="Port Forward Rules")
    table.add_column("Public", style="cyan")
    table.add_column("Private", style="green")
    table.add_column("Protocol", style="magenta")
    table.add_column("Instance", style="yellow")
    table.add_column("Description", style="white")
    table.add_column("Enabled", style="blue")

    for _, rule in sorted(port_forwards.items()):
        if instance and rule.get("instance_name") != instance:
            continue
        table.add_row(
            f"{rule['public_ip']}:{rule['public_port']}",
            f"{rule['private_ip']}:{rule['private_port']}",
            rule["protocol"],
            rule["instance_name"],
            rule.get("description", "-"),
            "Yes" if rule.get("enabled", True) else "No",
        )

    console.print(table)
