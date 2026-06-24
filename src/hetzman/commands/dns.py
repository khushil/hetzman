from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from ..apps import app
from ..console import console
from ..core import exec as host_exec
from ..core.errors import CoreError, HostUnreachable
from ..core.reads import get_dns_server_status, list_dns
from ..registry import load_registry
from ..core import dns as core_dns
from ._render import drive


def _tick(ok: bool) -> str:
    return "[green]✓[/green]" if ok else "[red]✗[/red]"


def _render_dns_status_panel(s) -> Panel:
    lines = [
        f"active: {_tick(s.active)}   forward: {_tick(s.forward_ok)}   "
        f"reverse: {_tick(s.reverse_ok)}   dhcp: {_tick(s.dhcp_listener)}",
        f"listen:    {', '.join(s.listen_addrs) or '-'}",
        f"forwarders:{' ' + ', '.join(s.forwarders) if s.forwarders else ' -'}",
        f"reverse:   {', '.join(s.reverse_zones) or '-'}",
        f"dhcp:      {s.dhcp_range or '-'}",
        f"ext ACL:   {', '.join(s.external_acl) or '-'}",
    ]
    healthy = s.active and s.forward_ok and s.reverse_ok and s.dhcp_listener
    border = "green" if healthy else "red"
    return Panel("\n".join(lines), title=f"dnsmasq @ {s.host}", border_style=border)


@app.command()
def dns_status(
    host: Optional[str] = typer.Option(None, help="A single host (default: whole fleet)"),
):
    """Show the managed dnsmasq serving status (per host or fleet-wide)."""
    targets = [host] if host else sorted(load_registry())
    for target in targets:
        try:
            console.print(_render_dns_status_panel(get_dns_server_status(target)))
        except (HostUnreachable, CoreError) as e:
            console.print(Panel(f"[red]{e}[/red]", title=f"dnsmasq @ {target}", border_style="red"))


@app.command()
def dns_config_show(
    host: Optional[str] = typer.Option(None, help="Host to read (default: this node)"),
):
    """Print the live managed /etc/dnsmasq.conf for a host."""
    res = host_exec.run_on(host, ["cat", "/etc/dnsmasq.conf"], root=True, check=False, timeout=20)
    console.print(res.stdout or "[yellow](empty / unreadable)[/yellow]")


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
