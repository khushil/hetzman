from typing import Optional

import typer
from rich.table import Table

from ..apps import cfg_app, vm_app
from ..console import console
from ..core import instances as core_instances
from ..core import vms as core_vms
from ..core.templates import apply_template_gen
from ..core.vms import PortForwardSpec
from ._delegate import run_or_delegate
from ._render import drive


@vm_app.command("create")
def vm_create(
    vm_name: str = typer.Argument(..., help="Name for the new VM or container"),
    type: str = typer.Option("vm", "--type", help="Instance type: 'vm' or 'container'"),
    image: str = typer.Option("images:ubuntu/24.04/cloud", help="Incus image to use"),
    cpus: int = typer.Option(1, help="Number of vCPUs"),
    memory: str = typer.Option("2048MB", help="Memory (e.g., 512MB, 2GB)"),
    disk: str = typer.Option("20GB", help="Disk size (e.g., 10GB)"),
    network: str = typer.Option("public", help="Network type: 'public' or 'private'"),
    port_forward: bool = typer.Option(False, "--port-forward", help="Add port forwards (for public IPs)"),
    template: Optional[str] = typer.Option(
        None, "--template", help="Provisioning template to apply (see 'hetzman vm cfg list')"
    ),
):
    """Create, configure, and secure a new Incus VM or container (--type)."""
    # Interactive port-forward collection is a CLI concern (the TUI uses a form).
    port_forwards: list[PortForwardSpec] = []
    if port_forward and network == "public":
        console.print("[cyan]Adding port forwards.[/cyan]")
        while True:
            proto = typer.prompt("Protocol (tcp/udp, 'done' to finish)", default="tcp")
            if proto == "done":
                break
            pub_port = typer.prompt("Public port", type=int)
            priv_port = typer.prompt("Private port", type=int, default=pub_port)
            desc = typer.prompt("Description", default="")
            port_forwards.append(
                PortForwardSpec(pub_port, priv_port, proto, desc or None)
            )

    result = drive(
        core_vms.create_vm(
            vm_name,
            image=image,
            cpus=cpus,
            memory=memory,
            disk=disk,
            network_type=network,
            port_forwards=port_forwards,
            template=template,
            instance_type=type,
        )
    )

    if result and result.ok:
        s = result.summary
        table = Table(title=f"New VM Summary: {vm_name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Name", str(s["name"]))
        table.add_row("Type", str(s.get("type", "vm")))
        table.add_row("Image", str(s["image"]))
        table.add_row("vCPUs", str(s["cpus"]))
        table.add_row("Memory", str(s["memory"]))
        table.add_row("Disk", str(s["disk"]))
        table.add_row("Hostname", str(s["hostname"]))
        table.add_row("Private IP", str(s["private_ip"]))
        table.add_row("Public IP", s["public_ip"] if s["public_ip"] else "N/A (Private)")
        console.print(table)


@vm_app.command("delete")
def vm_delete(
    vm_name: str = typer.Argument(..., help="Name of the VM to delete"),
):
    """Delete a VM and clean up all associated DNS and network rules"""
    console.print(
        f"[yellow]This will permanently delete '{vm_name}' and all associated data.[/yellow]"
    )
    if not typer.confirm("Are you sure you want to continue?"):
        console.print("[red]Delete cancelled.[/red]")
        raise typer.Exit(code=1)
    drive(core_vms.delete_vm(vm_name))


@vm_app.command("change")
def vm_change(
    vm_name: str = typer.Argument(..., help="Name of the VM/container to modify"),
    cpus: Optional[int] = typer.Option(None, help="New number of vCPUs"),
    memory: Optional[str] = typer.Option(None, help="New memory amount (e.g., 4GB)"),
    disk: Optional[str] = typer.Option(None, help="New root disk size (grow-only, e.g. 100GB)"),
    host: Optional[str] = typer.Option(None, "--host", "-H", help="Target host (default: this node)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt"),
):
    """Change CPU / memory / disk for a VM or container (live where possible)."""
    if cpus is None and memory is None and disk is None:
        console.print("[red]Error: specify at least one of --cpus, --memory, --disk.[/red]")
        raise typer.Exit(code=1)
    if not yes:
        console.print(f"[yellow]This will change {vm_name} (it may restart to apply).[/yellow]")
        if not typer.confirm("Continue?"):
            console.print("[red]Change cancelled.[/red]")
            raise typer.Exit(code=1)
    remote = ["vm", "change", vm_name, "--yes"]
    if cpus is not None:
        remote += ["--cpus", str(cpus)]
    if memory is not None:
        remote += ["--memory", memory]
    if disk is not None:
        remote += ["--disk", disk]
    run_or_delegate(
        host, remote,
        lambda: core_instances.change_instance(vm_name, cpus=cpus, memory=memory, disk=disk),
    )


@vm_app.command("reboot")
def vm_reboot(
    vm_name: str = typer.Argument(..., help="Name of the VM/container to reboot"),
    host: Optional[str] = typer.Option(None, "--host", "-H", help="Target host (default: this node)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt"),
):
    """Reboot a VM or container (incus restart)."""
    if not yes:
        console.print(f"[yellow]This will reboot {vm_name}.[/yellow]")
        if not typer.confirm("Continue?"):
            console.print("[red]Reboot cancelled.[/red]")
            raise typer.Exit(code=1)
    run_or_delegate(
        host, ["vm", "reboot", vm_name, "--yes"],
        lambda: core_instances.reboot_instance(vm_name),
    )


@cfg_app.command("list")
def vm_cfg_list():
    """List the available VM provisioning templates."""
    from ..templates import list_templates

    table = Table(title="VM templates")
    table.add_column("Template", style="cyan")
    table.add_column("Description", style="green")
    templates = list_templates()
    if not templates:
        console.print("[yellow]No templates found.[/yellow]")
        return
    for name, desc in templates:
        table.add_row(name, desc)
    console.print(table)


@cfg_app.command("apply")
def vm_cfg_apply(
    template: str = typer.Argument(..., help="Template name (see 'hetzman vm cfg list')"),
    vm_name: str = typer.Argument(..., help="Name of the VM to configure"),
):
    """Apply a provisioning template's software to a VM (idempotent)."""
    # exit_on_failure: a template applied "with warnings" (optional steps failed)
    # exits non-zero, matching the original command.
    drive(apply_template_gen(vm_name, template), exit_on_failure=True)


@cfg_app.command("install-defaults")
def vm_cfg_defaults(
    vm_name: str = typer.Argument(..., help="Name of the VM to configure"),
):
    """Install default tools (btop, iftop, git, curl, gh) — alias for the 'defaults' template."""
    drive(apply_template_gen(vm_name, "defaults"), exit_on_failure=True)
