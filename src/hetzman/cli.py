"""Top-level entry point. Importing this module wires every command into the
Typer apps defined in :mod:`hetzman.apps`.
"""
from .apps import app

# Import command modules so their @app.command decorators register.
from .commands import dns  # noqa: F401
from .commands import etcd_admin  # noqa: F401
from .commands import fleet  # noqa: F401
from .commands import ip  # noqa: F401
from .commands import node  # noqa: F401
from .commands import port  # noqa: F401
from .commands import system  # noqa: F401
from .commands import tui  # noqa: F401
from .commands import vm  # noqa: F401
from .commands import vm_users  # noqa: F401

__all__ = ["app", "main"]


def main() -> None:
    """Console-script entry point.

    Runs the Typer app and maps the core layer's lazy-etcd failure to a clean
    ``exit 1`` (the lazy client now raises :class:`EtcdUnavailable` instead of
    calling ``sys.exit`` directly, so read commands that don't yet route through
    the core ``drive()`` adapter would otherwise surface a traceback).
    """
    from .console import console
    from .core.errors import EtcdUnavailable, PrivilegeError

    try:
        app()
    except (EtcdUnavailable, PrivilegeError) as e:
        console.print(f"[red]ERROR: {e}[/red]")
        raise SystemExit(1)
