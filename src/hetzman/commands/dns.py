from typing import Optional

import typer
from rich.table import Table

from ..apps import app
from ..console import console
from ..core import dns as core_dns
from ..core.reads import list_dns
from ._render import drive


@app.command()
def dns_add(
    hostname: str = typer.Argument(..., help="Hostname (FQDN or short name)"),
    ip: str = typer.Argument(..., help="IP address"),
    instance: Optional[str] = typer.Option(None, help="Instance name"),
):
    """Add a DNS record manually"""
    drive(core_dns.add_dns(hostname, ip, instance))


@app.command()
def dns_remove(
    hostname: str = typer.Argument(..., help="Hostname to remove"),
):
    """Remove a DNS record"""
    drive(core_dns.remove_dns(hostname))


@app.command()
def dns_list(
    server: Optional[str] = typer.Option(None, help="Filter by server"),
):
    """List all DNS records"""
    records = list_dns(server=server)

    if not records:
        console.print("[yellow]No DNS records found[/yellow]")
        return

    table = Table(title="DNS Records")
    table.add_column("Hostname", style="cyan")
    table.add_column("IP Address", style="green")
    table.add_column("Server", style="magenta")
    table.add_column("Instance", style="yellow")
    table.add_column("Type", style="blue")
    table.add_column("Auto", style="white")

    for rec in records:
        table.add_row(
            rec.hostname,
            rec.ip,
            rec.server,
            rec.instance or "-",
            rec.type or "-",
            "Yes" if rec.auto else "No",
        )

    console.print(table)
