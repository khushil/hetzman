"""Typed error hierarchy for the core layer.

Pure module: it imports nothing from ``hetzman`` (or anywhere else) so it can be
depended on freely without dragging in side effects. Leaf operations raise one
of these typed errors on failure; front-ends map them to exit codes / messages.
"""

from __future__ import annotations


class CoreError(Exception):
    """Base class for all errors raised by the core layer."""


class ValidationError(CoreError):
    """Bad input or an unmet precondition."""


class NotFoundError(CoreError):
    """A requested resource does not exist."""


class PrivilegeError(CoreError):
    """The current process lacks the required privilege (e.g. not root)."""


class EtcdUnavailable(CoreError):
    """The etcd cluster was unreachable after retries."""
