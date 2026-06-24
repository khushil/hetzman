"""`hetzman ops` — host operational commands. Phase 1 ships the read-only
checks (available updates, reboot-required); apply/reboot land in Phase 4."""
from typing import Optional

import typer
from rich.table import Table

from ..apps import ops_app
from ..console import console
from ..core import reads
from ..registry import load_registry


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
