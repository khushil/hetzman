"""`hetzman instances` — list all VMs and containers, fleet-wide or per host."""
from typing import Optional

import typer
from rich.table import Table

from ..apps import app
from ..console import console
from ..core import reads


@app.command("instances")
def instances(
    host: Optional[str] = typer.Option(
        None, "--host", "-H", help="Only this host (default: every fleet node)"
    ),
):
    """List Incus VMs and containers across the fleet (or a single host)."""
    items, unreachable = reads.list_instances(host)

    if unreachable:
        console.print(f"[yellow]Unreachable hosts (skipped): {', '.join(unreachable)}[/yellow]")

    if not items:
        console.print("[yellow]No instances found.[/yellow]")
        return

    table = Table(title="Instances")
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="magenta")
    table.add_column("Type", style="blue")
    table.add_column("Status", style="green")
    table.add_column("CPU", style="white", justify="right")
    table.add_column("Memory", style="white", justify="right")
    table.add_column("Disk", style="white", justify="right")
    table.add_column("Private IP", style="yellow")

    for i in sorted(items, key=lambda x: (x.host, x.name)):
        status_style = "green" if i.status.lower() in ("running", "started") else "red"
        type_short = "vm" if i.type == "virtual-machine" else (i.type or "?")
        table.add_row(
            i.name,
            i.host,
            type_short,
            f"[{status_style}]{i.status}[/{status_style}]",
            "-" if i.cpus is None else str(i.cpus),
            i.memory or "-",
            i.disk or "-",
            i.private_ip or "-",
        )
    console.print(table)
