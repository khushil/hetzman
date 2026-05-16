import os
import subprocess
from datetime import datetime
from typing import Optional

import typer

from ..apps import app
from ..console import console
from ..logging import log_message

ETCD_CONF = "/etc/etcd.conf"


def _read_etcd_conf() -> dict[str, str]:
    """Parse /etc/etcd.conf (KEY=VALUE per line) into a dict.

    This is the single source of truth for *this* member's identity in
    the cluster: who am I, what are my peers, what's the cluster token.
    Reading it lets cluster admin commands work for any N-node cluster
    without hard-coding member names or IPs.
    """
    result: dict[str, str] = {}
    with open(ETCD_CONF) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


@app.command()
def etcd_backup(
    output_file: Optional[str] = typer.Option(None, help="Output file for backup"),
):
    """Create a backup of etcd data"""
    if not output_file:
        output_file = f"/var/lib/hetzman/etcd-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"

    try:
        subprocess.run([
            "sudo", "etcdctl",
            "--endpoints=https://127.0.0.1:2379",
            "--cacert=/etc/etcd/certs/ca.pem",
            "--cert=/opt/hetzman-tooling/certs/client.pem",
            "--key=/opt/hetzman-tooling/certs/client-key.pem",
            "snapshot", "save", output_file,
        ], check=True, capture_output=True, timeout=30)

        console.print(f"[green]ETCD backup saved to: {output_file}[/green]")
        log_message(f"ETCD backup created: {output_file}")
        return True
    except Exception as e:
        console.print(f"[red]Failed to backup etcd: {e}[/red]")
        log_message(f"Failed to backup etcd: {e}", "ERROR")
        return False


@app.command()
def etcd_restore(
    backup_file: str = typer.Argument(..., help="Backup file to restore from"),
):
    """Restore etcd data from backup"""
    if not os.path.exists(backup_file):
        console.print(f"[red]Backup file not found: {backup_file}[/red]")
        return

    console.print("[yellow]WARNING: This will overwrite ALL etcd data![/yellow]")
    if not typer.confirm("Are you sure you want to continue?"):
        console.print("[red]Restore cancelled[/red]")
        return

    try:
        etcd_conf = _read_etcd_conf()
    except OSError as e:
        console.print(f"[red]Could not read {ETCD_CONF}: {e}[/red]")
        return

    member_name = etcd_conf.get("ETCD_NAME")
    initial_cluster = etcd_conf.get("ETCD_INITIAL_CLUSTER")
    cluster_token = etcd_conf.get("ETCD_INITIAL_CLUSTER_TOKEN")
    peer_url = etcd_conf.get("ETCD_INITIAL_ADVERTISE_PEER_URLS")

    missing = [
        k for k, v in {
            "ETCD_NAME": member_name,
            "ETCD_INITIAL_CLUSTER": initial_cluster,
            "ETCD_INITIAL_CLUSTER_TOKEN": cluster_token,
            "ETCD_INITIAL_ADVERTISE_PEER_URLS": peer_url,
        }.items() if not v
    ]
    if missing:
        console.print(f"[red]{ETCD_CONF} is missing required keys: {', '.join(missing)}[/red]")
        return

    try:
        subprocess.run(["sudo", "systemctl", "stop", "etcd"], check=True)

        subprocess.run(["sudo", "rm", "-rf", "/var/lib/etcd"], check=True)

        subprocess.run([
            "sudo", "etcdctl", "snapshot", "restore", backup_file,
            "--data-dir=/var/lib/etcd",
            "--name", member_name,
            "--initial-cluster", initial_cluster,
            "--initial-cluster-token", cluster_token,
            "--initial-advertise-peer-urls", peer_url,
        ], check=True)

        subprocess.run(["sudo", "chown", "-R", "etcd:etcd", "/var/lib/etcd"], check=True)

        subprocess.run(["sudo", "systemctl", "start", "etcd"], check=True)

        console.print(f"[green]ETCD restored from: {backup_file}[/green]")
        log_message(f"ETCD restored from: {backup_file}")
    except Exception as e:
        console.print(f"[red]Failed to restore etcd: {e}[/red]")
        log_message(f"Failed to restore etcd: {e}", "ERROR")
