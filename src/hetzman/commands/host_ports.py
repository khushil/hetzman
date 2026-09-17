"""Operator-opened ports on a fleet HOST, under etcd /hetzman/host-ports/<node>/.

Distinct from ``hetzman port-add``, which DNATs a public port to an *instance*.
This opens a port on the host's own INPUT chain, for a service running on the
host itself. The two are deliberately named apart: ``port-add`` vs
``host port-open``.

One key per entry, per node. Adding is a put and closing is a delete, so there
is no read-modify-write and no CAS window; two operators editing different
ports cannot clobber one another. Per-node, so opening a port here never opens
it on the peer.

Policy (reserved ports) is enforced HERE rather than in the renderer. A
RenderError during node-sync aborts the whole run - no DNS, no netplan, no
firewall, no systemd - silently, on a 15-minute timer. Rejecting at write time
puts the error in front of the operator who typed the command instead.
"""
import json
from typing import Optional

import typer

from ..apps import host_app
from ..config import get_settings
from ..console import console
from ..etcd_kv import delete_key, get_all_with_prefix, put_key
from ..render import host_port_ok, reserved_host_ports

HOST_PORTS_PREFIX = "/hetzman/host-ports"


def _node(node: Optional[str]) -> str:
    return node or get_settings().current_server


def _key(node: str, port: int, protocol: str) -> str:
    return f"{HOST_PORTS_PREFIX}/{node}/{port}-{protocol}"


@host_app.command("port-open")
def port_open(
    port: int = typer.Argument(..., help="TCP/UDP port to open on the host itself"),
    protocol: str = typer.Option("tcp", help="tcp or udp"),
    source: str = typer.Option("0.0.0.0/0", help="Source CIDR allowed to reach it"),
    description: str = typer.Option("", help="What this port is for"),
    node: Optional[str] = typer.Option(None, help="Target node (default: this host)"),
):
    """Open a port on a fleet host's own firewall.

    Unlike the :53 ACL, a public source is legitimate here - that is often the
    entire point - so 0.0.0.0/0 is accepted. Reserved ports are not: those are
    either already rendered by node-sync (a second source of truth would drift)
    or must never face the internet by accident.
    """
    target = _node(node)
    entry = {
        "port": port, "protocol": protocol, "source": source,
        "description": description or None,
    }
    if protocol not in ("tcp", "udp"):
        console.print(f"[red]Invalid protocol {protocol!r} (want tcp or udp)[/red]")
        raise typer.Exit(code=2)
    if str(port) in reserved_host_ports():
        console.print(
            f"[red]Port {port} is reserved[/red] - it is either already managed by "
            f"node-sync or must not be exposed. Reserved: "
            f"{', '.join(sorted(reserved_host_ports(), key=int))}"
        )
        raise typer.Exit(code=2)
    if not host_port_ok(entry):
        console.print(f"[red]Invalid host-port entry:[/red] {entry!r}")
        raise typer.Exit(code=2)

    if not put_key(_key(target, port, protocol), json.dumps(entry)):
        console.print("[red]Failed to write host-port to etcd[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Opened {protocol}/{port} from {source} on[/green] {target}")
    console.print(f"[dim]Applies on the next node-sync on {target} "
                  f"(or run: sudo hetzman node-sync --apply).[/dim]")


@host_app.command("port-close")
def port_close(
    port: int = typer.Argument(..., help="Port to close"),
    protocol: str = typer.Option("tcp", help="tcp or udp"),
    node: Optional[str] = typer.Option(None, help="Target node (default: this host)"),
):
    """Close a previously opened host port.

    The live rule is removed by node-sync's flush-and-rebuild of the
    HETZMAN_HOSTPORTS chain, so this genuinely closes rather than waiting for a
    reboot.
    """
    target = _node(node)
    key = _key(target, port, protocol)
    if not get_all_with_prefix(key).get(key):
        console.print(f"[yellow]No such host-port on {target}: {protocol}/{port}[/yellow]")
        raise typer.Exit(code=1)
    if not delete_key(key):
        console.print("[red]Failed to delete host-port from etcd[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Closed {protocol}/{port} on[/green] {target}")
    console.print(f"[dim]Run: sudo hetzman node-sync --apply on {target} to take effect now.[/dim]")


@host_app.command("port-list")
def port_list(
    node: Optional[str] = typer.Option(None, help="Target node (default: this host)"),
    all_nodes: bool = typer.Option(False, "--all", help="List every node's host ports"),
):
    """List operator-opened host ports."""
    prefix = HOST_PORTS_PREFIX + "/" if all_nodes else f"{HOST_PORTS_PREFIX}/{_node(node)}/"
    rows = sorted((get_all_with_prefix(prefix) or {}).items())
    if not rows:
        console.print(f"[yellow]No host ports open[/yellow] ({prefix})")
        return
    for key, raw in rows:
        who = key[len(HOST_PORTS_PREFIX) + 1:].rsplit("/", 1)[0]
        if isinstance(raw, dict):
            console.print(
                f"[cyan]{who}[/cyan]  {raw.get('protocol', '?')}/{raw.get('port', '?')}  "
                f"from {raw.get('source', '?')}  {raw.get('description') or ''}"
            )
        else:
            console.print(f"[red]{key}: malformed ({raw!r}) - node-sync will drop it[/red]")
