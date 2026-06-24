"""Fleet-wide config under etcd /hetzman/config/.

Currently: the trusted :53 source CIDRs that may reach the local resolver from
off-bridge (the vSwitch is always trusted; this adds operator VPN ranges).
Mutations go through this validating CLI — never raw etcdctl — so a typo can
never widen an open-resolver-sensitive ACL.
"""
import json
from typing import List

import typer

from ..apps import config_app
from ..console import console
from ..etcd_kv import get_all_with_prefix, put_key
from ..render import TRUSTED_DNS_CLIENTS, dns_acl_source_ok

TRUSTED_DNS_CLIENTS_KEY = "/hetzman/config/trusted-dns-clients"


def _read_trusted() -> List[str]:
    raw = get_all_with_prefix(TRUSTED_DNS_CLIENTS_KEY).get(TRUSTED_DNS_CLIENTS_KEY)
    if isinstance(raw, list):
        return [str(c) for c in raw]
    if isinstance(raw, dict):
        return [str(c) for c in raw.get("cidrs", [])]
    return []


@config_app.command("show-trusted-dns-clients")
def show_trusted_dns_clients():
    """Show the trusted :53 source CIDRs (vSwitch is always trusted implicitly)."""
    console.print(f"[cyan]Always trusted:[/cyan] {', '.join(TRUSTED_DNS_CLIENTS)}")
    extra = _read_trusted()
    console.print(f"[cyan]Configured extra:[/cyan] {', '.join(extra) if extra else '(none)'}")


@config_app.command("set-trusted-dns-clients")
def set_trusted_dns_clients(
    cidrs: List[str] = typer.Argument(
        None, help="Private (RFC1918) CIDRs allowed to reach :53, e.g. 10.8.0.0/24. "
                   "Pass none to clear."),
):
    """Set the operator VPN CIDR(s) allowed to query the resolver.

    Each must be a private, /16-or-narrower range — public/oversized values are
    rejected so the resolver can never be opened to the internet. Takes effect on
    the next node-sync on each host.
    """
    cidrs = cidrs or []
    bad = [c for c in cidrs if not dns_acl_source_ok(c)]
    if bad:
        console.print(f"[red]Rejected (not private / too broad / invalid):[/red] {', '.join(bad)}")
        raise typer.Exit(code=2)
    if not put_key(TRUSTED_DNS_CLIENTS_KEY, json.dumps(cidrs)):
        console.print("[red]Failed to write trusted-dns-clients to etcd[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Set trusted-dns-clients:[/green] {', '.join(cidrs) if cidrs else '(cleared)'}")
    console.print("[dim]Applies on the next node-sync per host (adds an iptables :53 accept).[/dim]")
