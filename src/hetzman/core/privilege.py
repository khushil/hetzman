"""Privilege helpers for the core layer.

Dependency-light by design: no console, no logging, just :mod:`os` and the
typed error hierarchy.
"""

from __future__ import annotations

import os

from .errors import PrivilegeError


def require_root(action: str | None = None) -> None:
    """Raise :class:`PrivilegeError` unless the effective UID is 0 (root).

    :param action: optional label describing the operation that needs root,
        woven into the error message for context.
    """
    if os.geteuid() != 0:
        if action:
            raise PrivilegeError(f"{action} requires root privileges (run as root).")
        raise PrivilegeError("This operation requires root privileges (run as root).")
