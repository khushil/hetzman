from typing import Optional

import typer
from rich.table import Table

from ..apps import app
from ..console import console
from ..core import ports as core_ports
from ..core.reads import list_ports
from ._render import drive


@app.command()
def port_add(
    instance: str = typer.Argument(..., help="Instance name"),
    public_port: int = typer.Argument(..., help="Public port"),
    private_port: int = typer.Argument(..., help="Private port"),
    protocol: str = typer.Option("tcp", help="Protocol (tcp/udp)"),
    description: Optional[str] = typer.Option(None, help="Description"),
):
    """Add a port forward rule"""
    drive(core_ports.add_port(instance, public_port, private_port, protocol, description))


@app.command()
def port_remove(
    instance: str = typer.Argument(..., help="Instance name"),
    public_port: int = typer.Argument(..., help="Public port"),
    protocol: str = typer.Option("tcp", help="Protocol (tcp/udp)"),
):
    """Remove a port forward rule"""
    drive(core_ports.remove_port(instance, public_port, protocol))


@app.command()
def port_list(
    instance: Optional[str] = typer.Option(None, help="Filter by instance"),
):
    """List port forward rules"""
    rules = list_ports(instance=instance)

    if not rules:
        console.print("[yellow]No port forward rules found[/yellow]")
        return

    table = Table(title="Port Forward Rules")
    table.add_column("Public", style="cyan")
    table.add_column("Private", style="green")
    table.add_column("Protocol", style="magenta")
    table.add_column("Instance", style="yellow")
    table.add_column("Description", style="white")
    table.add_column("Enabled", style="blue")

    for rule in rules:
        table.add_row(
            f"{rule.public_ip}:{rule.public_port}",
            f"{rule.private_ip}:{rule.private_port}",
            rule.protocol,
            rule.instance,
            rule.description if rule.description is not None else "-",
            "Yes" if rule.enabled else "No",
        )

    console.print(table)
