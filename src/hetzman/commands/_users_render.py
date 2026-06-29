"""Shared rendering for `vm users list` / `host users list`."""
from rich.table import Table

from ..console import console


def render_users(scope: str, target: str, accounts) -> None:
    if not accounts:
        console.print(f"[yellow]No login accounts found on {scope} {target}[/yellow]")
        return
    table = Table(title=f"Users on {scope} {target}")
    table.add_column("User", style="cyan")
    table.add_column("UID", style="white")
    table.add_column("Sudo", style="magenta")
    table.add_column("Status", style="white")
    table.add_column("Keys", style="green")
    for a in accounts:
        table.add_row(
            a.name,
            "-" if a.uid is None else str(a.uid),
            "yes" if a.sudo else "-",
            "[red]SUSPENDED[/red]" if a.locked else "[green]active[/green]",
            str(a.key_count),
        )
    console.print(table)
