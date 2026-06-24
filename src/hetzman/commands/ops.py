"""`hetzman ops` — host operational commands: read-only checks (updates,
reboot-required) plus guarded apply-updates and reboot."""
from typing import Optional

import typer
from rich.table import Table

from ..apps import ops_app
from ..console import console
from ..core import ops as core_ops
from ..core import reads
from ..registry import load_registry
from ._render import drive


def _hosts(host: Optional[str]) -> list[str]:
    return [host] if host else sorted(load_registry())


@ops_app.command("updates")
def ops_updates(
    host: Optional[str] = typer.Option(None, "--host", "-H", help="One host (default: all)"),
):
    """Show available apt updates per host (read-only)."""
    table = Table(title="Available updates")
    table.add_column("Host", style="cyan")
    table.add_column("Updates", style="green", justify="right")
    table.add_column("Security", style="red", justify="right")
    table.add_column("Reboot?", style="yellow")
    for h in _hosts(host):
        try:
            st = reads.check_updates(h)
            rr = reads.reboot_required(h)
        except Exception as exc:  # surface per-host, keep going
            table.add_row(h, "[red]unreachable[/red]", "-", f"[dim]{type(exc).__name__}[/dim]")
            continue
        table.add_row(
            h,
            str(st.count),
            str(st.security_count),
            "[red]yes[/red]" if rr else "no",
        )
    console.print(table)


@ops_app.command("reboot-required")
def ops_reboot_required(
    host: Optional[str] = typer.Option(None, "--host", "-H", help="One host (default: all)"),
):
    """Show which hosts are flagged as needing a reboot."""
    for h in _hosts(host):
        try:
            flagged = reads.reboot_required(h)
        except Exception as exc:
            console.print(f"{h}: [red]unreachable[/red] ([dim]{type(exc).__name__}[/dim])")
            continue
        console.print(f"{h}: " + ("[red]reboot required[/red]" if flagged else "[green]ok[/green]"))


@ops_app.command("apply-updates")
def ops_apply_updates(
    host: str = typer.Option(..., "--host", "-H", help="Host to update"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Apply apt updates on a host (streams apt output)."""
    if not yes:
        console.print(f"[yellow]This will run apt-get upgrade on {host}.[/yellow]")
        if not typer.confirm("Continue?"):
            raise typer.Exit(code=1)
    drive(core_ops.apply_updates(host))


@ops_app.command("reboot")
def ops_reboot(
    host: str = typer.Option(..., "--host", "-H", help="Host to reboot"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the typed confirmation"),
):
    """Reboot a host (guarded: refuses if it would break etcd quorum)."""
    if not yes:
        console.print(
            f"[bold red]This will REBOOT host {host}[/bold red] (its VMs/containers go down)."
        )
        typed = typer.prompt("Re-type the host name to confirm")
        if typed != host:
            console.print("[red]Name mismatch; aborting.[/red]")
            raise typer.Exit(code=1)
    drive(core_ops.reboot_host(host))


@ops_app.command("rolling-reboot")
def ops_rolling_reboot(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Reboot every fleet host one at a time (quorum re-checked before each)."""
    hosts = sorted(load_registry())
    console.print(f"[bold red]Rolling reboot of {len(hosts)} hosts:[/bold red] {', '.join(hosts)}")
    if not yes:
        typed = typer.prompt("Type 'rolling-reboot' to confirm")
        if typed != "rolling-reboot":
            console.print("[red]Aborted.[/red]")
            raise typer.Exit(code=1)
    drive(core_ops.rolling_reboot(hosts))
