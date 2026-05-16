"""Typer app instances. Lives in its own module so command modules can import
the apps without depending on (and triggering) the full ``cli`` module.
"""
import typer

app = typer.Typer(help="HetzMan - Hetzner Infrastructure Management Tool v3.1")
vm_app = typer.Typer(help="Manage Incus VMs (create, delete, change)")
app.add_typer(vm_app, name="vm")
cfg_app = typer.Typer(help="Configure default software on a VM")
vm_app.add_typer(cfg_app, name="cfg")
users_app = typer.Typer(help="Manage users and SSH keys on a VM")
vm_app.add_typer(users_app, name="users")
