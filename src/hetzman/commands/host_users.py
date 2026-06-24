"""`hetzman host users` — manage users on the bare-metal fleet hosts."""
from pathlib import Path

import typer

from ..apps import host_users_app
from ..console import console
from ..core import users as core_users
from ._render import drive


@host_users_app.command("add")
def host_users_add(
    host: str = typer.Argument(..., help="Fleet host name"),
    username: str = typer.Argument(..., help="Username to create"),
    key_file: Path = typer.Option(
        ..., "--key", help="Path to the user's public SSH key (on this box)",
        exists=True, file_okay=True, dir_okay=False, readable=True,
    ),
    sudo: bool = typer.Option(False, "--sudo", help="Grant passwordless sudo"),
):
    """Add a user to a fleet host with an SSH key and optional sudo."""
    drive(core_users.add_host_user(host, username, str(key_file), sudo=sudo))


@host_users_app.command("remove")
def host_users_remove(
    host: str = typer.Argument(..., help="Fleet host name"),
    username: str = typer.Argument(..., help="Username to remove"),
):
    """Remove a user (and home dir) from a fleet host."""
    if not typer.confirm(f"Remove user '{username}' and home dir from host {host}?"):
        console.print("[red]Cancelled.[/red]")
        raise typer.Exit(code=1)
    drive(core_users.remove_host_user(host, username))


@host_users_app.command("change-keys")
def host_users_change_keys(
    host: str = typer.Argument(..., help="Fleet host name"),
    username: str = typer.Argument(..., help="Username to update"),
    key_file: Path = typer.Option(
        ..., "--key", help="Path to the user's *new* public SSH key",
        exists=True, file_okay=True, dir_okay=False, readable=True,
    ),
):
    """Replace a host user's authorized_keys."""
    drive(core_users.change_host_keys(host, username, str(key_file)))
