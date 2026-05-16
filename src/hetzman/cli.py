"""Top-level entry point. Importing this module wires every command into the
Typer apps defined in :mod:`hetzman.apps`.
"""
from .apps import app

# Import command modules so their @app.command decorators register.
from .commands import dns  # noqa: F401
from .commands import etcd_admin  # noqa: F401
from .commands import ip  # noqa: F401
from .commands import port  # noqa: F401
from .commands import system  # noqa: F401
from .commands import vm  # noqa: F401
from .commands import vm_users  # noqa: F401

__all__ = ["app"]
