from typing import Optional

import typer
from rich.table import Table

from ..apps import app
from ..console import console
from ..core import ip as core_ip
from ..core.reads import list_ips
from ._render import drive


@app.command()
def ip_list(
    server: Optional[str] = typer.Option(None, help="Filter by server"),
    available_only: bool = typer.Option(False, "--available", help="Show only available IPs"),
):
    """List public IP pool"""
    all_ips = list_ips()

    if not all_ips:
        console.print("[yellow]No IPs found[/yellow]")
        return

    allocations = list_ips(server=server, available_only=available_only)

    table = Table(title="Public IP Pool")
    table.add_column("IP Address", style="cyan")
    table.add_column("Server", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Assigned To", style="yellow")

    for alloc in allocations:
        status_color = "green" if alloc.status == "available" else "red"

        table.add_row(
            alloc.ip,
            alloc.server,
            f"[{status_color}]{alloc.status}[/{status_color}]",
            alloc.assigned_to if alloc.assigned_to is not None else "-",
        )

    console.print(table)


@app.command()
def ip_assign(
    instance: str = typer.Argument(..., help="Instance name"),
    ip: Optional[str] = typer.Option(None, help="Specific IP to assign"),
):
    """Assign a public IP from the pool to an instance"""
    drive(core_ip.assign_ip(instance, ip))


@app.command()
def ip_release(
    instance: str = typer.Argument(..., help="Instance name"),
):
    """Release public IP from an instance"""
    drive(core_ip.release_ip(instance))
