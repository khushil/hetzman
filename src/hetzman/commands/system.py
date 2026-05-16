import json
import os
import subprocess
from typing import Optional

import typer

from ..apps import app
from ..config import get_etcd_client, get_settings
from ..console import console
from ..etcd_kv import get_all_with_prefix
from ..logging import log_message
from ..network import (
    apply_nat_rules,
    get_public_ip_from_interface,
    regenerate_hosts_file,
    reload_dnsmasq,
    remove_ip_from_interface,
)
from ..services import restart_instance_watcher
from ..vm_helpers import secure_vm_instance


@app.command()
def sync_apply():
    """Regenerate configuration files and apply all rules"""
    console.print("[cyan]Regenerating configuration and applying rules...[/cyan]")
    success = True
    current_server = get_settings().current_server

    # Clean up orphaned IPs.
    try:
        nat_rules = get_all_with_prefix(f"/hetzman/nat/{current_server}/")
        active_ips = {
            rule["public_ip"]
            for rule in nat_rules.values()
            if rule.get("enabled", True)
        }

        ip_pool = get_all_with_prefix("/hetzman/ip-pool/")
        pool_ips = [
            key.replace("/hetzman/ip-pool/", "")
            for key, data in ip_pool.items()
            if data.get("server") == current_server
        ]

        for pool_ip in pool_ips:
            if get_public_ip_from_interface(pool_ip) and pool_ip not in active_ips:
                console.print(f"[yellow]Removing orphaned IP {pool_ip} from interface[/yellow]")
                remove_ip_from_interface(pool_ip)

    except Exception as e:
        console.print(f"[yellow]Warning: Could not clean orphaned IPs: {e}[/yellow]")

    if not regenerate_hosts_file():
        success = False

    if not reload_dnsmasq():
        success = False

    if not apply_nat_rules():
        success = False

    try:
        subprocess.run(
            ["sudo", "netfilter-persistent", "save"],
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        console.print("[yellow]Warning: Could not save iptables rules[/yellow]")

    if success:
        console.print("[green]Configuration applied successfully[/green]")
    else:
        console.print("[red]Some operations failed. Check logs.[/red]")

    restart_instance_watcher()


@app.command()
def status():
    """Show system status"""
    current_server = get_settings().current_server
    console.print(f"\n[bold cyan]HetzMan Status - {current_server}[/bold cyan]\n")

    try:
        dns_records = get_all_with_prefix("/hetzman/dns/")
        my_dns = sum(1 for v in dns_records.values() if v.get("server") == current_server)
        console.print(f"DNS Records: [green]{my_dns}[/green] (total: {len(dns_records)})")

        types: dict = {}
        for record in dns_records.values():
            if record.get("server") == current_server and record.get("type"):
                types[record["type"]] = types.get(record["type"], 0) + 1

        for t, count in types.items():
            console.print(f"  - {t}: {count}")

        ip_pool = get_all_with_prefix("/hetzman/ip-pool/")
        my_available = sum(
            1 for v in ip_pool.values()
            if v.get("server") == current_server and v.get("status") == "available"
        )
        my_total = sum(1 for v in ip_pool.values() if v.get("server") == current_server)
        console.print(f"Available IPs: [green]{my_available}[/green] / {my_total}")

        nat_rules = get_all_with_prefix(f"/hetzman/nat/{current_server}/")
        active_nat = sum(1 for v in nat_rules.values() if v.get("enabled", True))
        console.print(f"Active NAT Rules: [green]{active_nat}[/green]")

        port_forwards = get_all_with_prefix(f"/hetzman/port-forward/{current_server}/")
        active_ports = sum(1 for v in port_forwards.values() if v.get("enabled", True))
        console.print(f"Active Port Forwards: [green]{active_ports}[/green]")

        try:
            members = get_etcd_client().members
            console.print(f"ETCD Cluster: [green]{len(list(members))} members[/green]")
        except Exception:
            console.print("ETCD Cluster: [yellow]Unknown[/yellow]")

        console.print()

    except Exception as e:
        console.print(f"[red]Error getting status: {e}[/red]")


@app.command()
def audit():
    """Audit IP interface state vs etcd"""
    current_server = get_settings().current_server
    console.print(f"\n[bold cyan]IP Interface Audit - {current_server}[/bold cyan]\n")

    try:
        nat_rules = get_all_with_prefix(f"/hetzman/nat/{current_server}/")
        should_be_active = {
            rule["public_ip"]: rule["instance_name"]
            for rule in nat_rules.values()
            if rule.get("enabled", True)
        }

        ip_pool = get_all_with_prefix("/hetzman/ip-pool/")
        pool_ips = [
            key.replace("/hetzman/ip-pool/", "")
            for key, data in ip_pool.items()
            if data.get("server") == current_server
        ]

        currently_active = {pool_ip for pool_ip in pool_ips if get_public_ip_from_interface(pool_ip)}

        missing = set(should_be_active.keys()) - currently_active
        orphaned = currently_active - set(should_be_active.keys())
        correct = set(should_be_active.keys()) & currently_active

        console.print(f"[green]✓ Correct IPs on interface: {len(correct)}[/green]")
        for ip in sorted(correct):
            console.print(f"  {ip} → {should_be_active[ip]}")

        if missing:
            console.print(f"\n[red]✗ Missing IPs: {len(missing)}[/red]")
            for ip in sorted(missing):
                console.print(f"  {ip} → {should_be_active[ip]} [red]MISSING[/red]")
            console.print("\n[yellow]Run 'sudo hetzman sync-apply' to fix[/yellow]")

        if orphaned:
            console.print(f"\n[yellow]⚠ Orphaned IPs: {len(orphaned)}[/yellow]")
            for ip in sorted(orphaned):
                console.print(f"  {ip} [yellow]ORPHANED[/yellow]")
            console.print("\n[yellow]Run 'sudo hetzman sync-apply' to clean[/yellow]")

        if not missing and not orphaned:
            console.print("\n[green]✓ All checks passed[/green]")

        console.print()

        if missing or orphaned:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error during audit: {e}[/red]")
        log_message(f"Error during audit: {e}", "ERROR")
        raise typer.Exit(code=2)


@app.command()
def secure_vm(
    vm_name: Optional[str] = typer.Argument(None, help="The name of the VM to secure."),
    all_vms: bool = typer.Option(False, "--all", help="Secure all running Incus VMs."),
):
    """Secure a VM with key-only SSH and fail2ban"""
    if os.geteuid() != 0:
        console.print("[red]Error: This command must be run as root (or with sudo).[/red]")
        raise typer.Exit(code=1)

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
    success = 0
    for i, vm in enumerate(vm_list):
        console.print(f"\n[bold]Processing {i+1} of {total}: {vm}[/bold]")
        if secure_vm_instance(vm):
            success += 1

    console.print(f"\n[green]VM Security Summary: {success} secured, {total - success} failed.[/green]")
