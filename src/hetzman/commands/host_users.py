"""`hetzman host users` — manage users on the bare-metal fleet hosts."""
from pathlib import Path
from typing import Optional

import typer

from ..apps import host_users_app
from ..console import console
from ..core import users as core_users
from ._render import drive


@host_users_app.command("add")
def host_users_add(
    host: str = typer.Argument(..., help="Fleet host name"),
    username: str = typer.Argument(..., help="Username to create"),
    key_file: Optional[Path] = typer.Option(
        None, "--key", help="Path to the user's public SSH key (on this box)",
        exists=True, file_okay=True, dir_okay=False, readable=True,
    ),
    key_content: Optional[str] = typer.Option(
        None, "--key-content", help="The public SSH key inline (alternative to --key)",
    ),
    sudo: bool = typer.Option(False, "--sudo", help="Grant passwordless sudo"),
):
    """Add a user to a fleet host with an SSH key and optional sudo."""
    key = key_content if key_content else (str(key_file) if key_file else None)
    if not key:
        console.print("[red]Provide --key <file> or --key-content <key>[/red]")
        raise typer.Exit(code=2)
    drive(core_users.add_host_user(host, username, key, sudo=sudo))


@host_users_app.command("list")
def host_users_list(
    host: str = typer.Argument(..., help="Fleet host name"),
):
    """List login accounts on a host (uid + sudo + suspended status + key count)."""
    from ._users_render import render_users
    render_users("host", host, core_users.list_users("host", host))


@host_users_app.command("suspend")
def host_users_suspend(
    host: str = typer.Argument(..., help="Fleet host name"),
    username: str = typer.Argument(..., help="Username to suspend"),
):
    """Suspend an account on a host (locks + expires it; blocks all login incl. keys)."""
    drive(core_users.suspend_user("host", host, username))


@host_users_app.command("unsuspend")
def host_users_unsuspend(
    host: str = typer.Argument(..., help="Fleet host name"),
    username: str = typer.Argument(..., help="Username to re-enable"),
):
    """Re-enable a suspended account on a host."""
    drive(core_users.unsuspend_user("host", host, username))


@host_users_app.command("sudo")
def host_users_sudo(
    host: str = typer.Argument(..., help="Fleet host name"),
    username: str = typer.Argument(..., help="Username"),
    revoke: bool = typer.Option(False, "--revoke", help="Revoke sudo instead of granting"),
):
    """Grant (default) or --revoke sudo for a user on a host.

    Grant adds a passwordless sudoers drop-in; --revoke removes it AND strips
    sudo/admin/wheel group membership (fully de-sudos the user)."""
    drive(core_users.set_user_sudo("host", host, username, grant=not revoke))


@host_users_app.command("remove")
def host_users_remove(
    host: str = typer.Argument(..., help="Fleet host name"),
    username: str = typer.Argument(..., help="Username to remove"),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt"),
):
    """Remove a user (and home dir) from a fleet host."""
    if not yes and not typer.confirm(f"Remove user '{username}' and home dir from host {host}?"):
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
