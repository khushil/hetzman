"""Progress and result contract for core operations.

Operations are written as generators that *yield* :class:`ProgressEvent` values
to report progress and *return* an :class:`OpResult` describing the outcome::

    ProgressGen = Generator[ProgressEvent, None, OpResult]

Contract:

* A **leaf** op RAISES a typed :class:`~hetzman.core.errors.CoreError` on
  failure. On success it returns its product inside ``OpResult.summary``.
* A **composing** op delegates to a leaf with ``res = yield from leaf(...)`` and
  reads ``res.summary`` to obtain that leaf's product, re-yielding the leaf's
  progress events transparently to the front-end.

Note: :class:`ProgressEvent` and :class:`OpResult` are ``frozen`` dataclasses.
Mutable defaults on a frozen dataclass raise ``ValueError`` at import time on
Python 3.12, so collection-typed fields use immutable defaults
(``default_factory=dict``, empty tuples).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Generator, Mapping


class Severity(Enum):
    """Severity / kind of a progress event."""

    INFO = "info"
    STEP = "step"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class ProgressEvent:
    """A single progress update yielded by an operation generator."""

    severity: Severity
    message: str
    step: int | None = None
    total: int | None = None
    detail: str | None = None
    # Labels nested-op steps so a child "Step n/m" does not collide with the
    # parent's step counter when events are re-yielded by a composing op.
    scope: str | None = None


@dataclass(frozen=True)
class OpResult:
    """The outcome of an operation, returned (not yielded) by its generator."""

    ok: bool
    summary: Mapping[str, object] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


# The generator protocol implemented by core operations: yields ProgressEvent,
# sends nothing, returns an OpResult.
ProgressGen = Generator[ProgressEvent, None, OpResult]
