"""Cross-host mutation = run the WHOLE op on the target node.

A host-touching mutation targeting node X is executed by invoking X's own
``hetzman`` over SSH (streaming it back), so X runs its complete local logic,
locks, and reconcile — the centre never orchestrates incus/etcd/iptables
step-by-step remotely. On the local node it just drives the core generator.

The caller passes the remote argv it would run on the target (already including
any ``--yes`` so the target never re-prompts) AND a factory for the local
generator. Confirmation happens once, on the orchestrator, BEFORE calling this.
"""
from __future__ import annotations

from typing import Callable, Optional

import typer

from ..console import console
from ..core import exec as host_exec
from ..core.errors import CoreError, HostUnreachable
from ._render import drive


def run_or_delegate(host: Optional[str], remote_argv: list[str], gen_factory: Callable):
    """Run on the target: locally drive ``gen_factory()``, else stream the
    target's ``hetzman remote_argv`` over SSH."""
    target = host_exec.resolve_host(host)
    if host_exec.is_local(target):
        return drive(gen_factory())

    console.print(f"[cyan]→ delegating to {target} (running its hetzman over SSH)…[/cyan]")
    gen = host_exec.stream_on(target, ["hetzman", *remote_argv], root=True, timeout=1800)
    try:
        while True:
            try:
                line = next(gen)
            except StopIteration:
                break
            console.print(line)
    except HostUnreachable as exc:
        console.print(f"[red]Host unreachable: {exc}[/red]")
        raise typer.Exit(1)
    except CoreError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)
    finally:
        gen.close()
