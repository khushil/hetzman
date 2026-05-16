import json
from datetime import datetime
from typing import Optional

import typer
from rich.table import Table

from ..apps import app
from ..config import get_settings
from ..console import console
from ..etcd_kv import delete_key, get_all_with_prefix, put_key
from ..logging import log_message
from ..network import regenerate_hosts_file, reload_dnsmasq
from ..services import restart_instance_watcher


@app.command()
def dns_add(
    hostname: str = typer.Argument(..., help="Hostname (FQDN or short name)"),
    ip: str = typer.Argument(..., help="IP address"),
    instance: Optional[str] = typer.Option(None, help="Instance name"),
):
    """Add a DNS record manually"""
    if "." not in hostname:
        hostname = f"{hostname}.daemondreams.home.arpa"

    record = {
        "ip": ip,
        "server": get_settings().current_server,
        "instance": instance,
        "type": None,
        "auto": False,
        "updated": datetime.now().isoformat(),
    }

    if put_key(f"/hetzman/dns/{hostname}", json.dumps(record)):
        console.print(f"[green]Added DNS record: {hostname} -> {ip}[/green]")
        log_message(f"Added DNS record: {hostname} -> {ip}")
        regenerate_hosts_file()
        reload_dnsmasq()
        restart_instance_watcher()
    else:
        console.print("[red]Failed to add DNS record[/red]")


@app.command()
def dns_remove(
    hostname: str = typer.Argument(..., help="Hostname to remove"),
):
    """Remove a DNS record"""
    if "." not in hostname:
        hostname = f"{hostname}.daemondreams.home.arpa"

    if delete_key(f"/hetzman/dns/{hostname}"):
        console.print(f"[green]Removed DNS record: {hostname}[/green]")
        log_message(f"Removed DNS record: {hostname}")
        regenerate_hosts_file()
        reload_dnsmasq()
        restart_instance_watcher()
    else:
        console.print(f"[yellow]DNS record not found: {hostname}[/yellow]")


@app.command()
def dns_list(
    server: Optional[str] = typer.Option(None, help="Filter by server"),
):
    """List all DNS records"""
    dns_records = get_all_with_prefix("/hetzman/dns/")

    if not dns_records:
        console.print("[yellow]No DNS records found[/yellow]")
        return

    table = Table(title="DNS Records")
    table.add_column("Hostname", style="cyan")
    table.add_column("IP Address", style="green")
    table.add_column("Server", style="magenta")
    table.add_column("Instance", style="yellow")
    table.add_column("Type", style="blue")
    table.add_column("Auto", style="white")

    for key, record in sorted(dns_records.items()):
        hostname = key.replace("/hetzman/dns/", "")
        if server and record.get("server") != server:
            continue
        table.add_row(
            hostname,
            record.get("ip", ""),
            record.get("server", ""),
            record.get("instance", "-"),
            record.get("type", "-"),
            "Yes" if record.get("auto", False) else "No",
        )

    console.print(table)
