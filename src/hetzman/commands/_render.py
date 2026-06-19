"""CLI adapter that drives a core operation generator to the console.

A core write op is a ``ProgressGen`` — a generator that yields
:class:`~hetzman.core.events.ProgressEvent`s and returns an
:class:`~hetzman.core.events.OpResult`. :func:`drive` is the single place the
CLI renders those events (with the project's Rich conventions) and maps the
typed core errors to a clean ``typer.Exit(1)``. The Textual front-end consumes
the same generators a different way (a worker streaming events into the log
panel), so this rendering logic lives only here, on the CLI side.
"""
from __future__ import annotations

from typing import Optional

import typer

from ..console import console
from ..core.errors import (
    CoreError,
    EtcdUnavailable,
    NotFoundError,
    PrivilegeError,
    ValidationError,
)
from ..core.events import OpResult, ProgressEvent, Severity

# Severity -> Rich style. INFO is intentionally unstyled to match the plain
# progress lines the original commands printed; STEP is cyan ("Step n/m: ...").
_STYLE: dict[Severity, str] = {
    Severity.INFO: "",
    Severity.STEP: "cyan",
    Severity.SUCCESS: "green",
    Severity.WARNING: "yellow",
    Severity.ERROR: "red",
}


def _format(event: ProgressEvent) -> str:
    text = event.message
    if event.step is not None and event.total is not None:
        text = f"Step {event.step}/{event.total}: {text}"
    if event.scope:
        text = f"[{event.scope}] {text}"
    style = _STYLE.get(event.severity, "")
    return f"[{style}]{text}[/{style}]" if style else text


def drive(gen, *, exit_on_failure: bool = False) -> Optional[OpResult]:
    """Render *gen* to the console and return its :class:`OpResult`.

    * Prints each ``ProgressEvent`` as it is yielded.
    * Maps a raised :class:`~hetzman.core.errors.CoreError` (and subclasses) to
      ``typer.Exit(1)`` after printing it.
    * Always ``close()``s the generator so its ``finally``/compensation runs even
      on an error or early exit.
    * With ``exit_on_failure=True``, also exits 1 when the op completes with
      ``OpResult(ok=False)`` (used by commands where a soft failure is still an
      error exit; the default keeps the original "not found -> exit 0" behavior).
    """
    result: Optional[OpResult] = None
    try:
        while True:
            try:
                event = next(gen)
            except StopIteration as stop:
                result = stop.value
                break
            console.print(_format(event))
    except PrivilegeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    except (ValidationError, NotFoundError, EtcdUnavailable, CoreError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)
    finally:
        gen.close()

    if result is not None:
        for warning in result.warnings:
            console.print(f"[yellow]{warning}[/yellow]")
        for error in result.errors:
            console.print(f"[red]{error}[/red]")
        if exit_on_failure and not result.ok:
            raise typer.Exit(1)
    return result
