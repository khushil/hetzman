"""Modal screens for the hetzman control center: confirmation + input forms.

Each input modal ``dismiss``es with a plain dict of field values (or ``None``
if cancelled); the caller turns that into the core-op call. ConfirmModal
dismisses with a bool. Keeping the modals dumb (no core calls) means the
mutation logic lives in one place — the app's mutation worker.
"""
from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Grid, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Select


class ConfirmModal(ModalScreen[bool]):
    """A yes/no confirmation. Dismisses True (confirm) or False (cancel)."""

    DEFAULT_CSS = """
    ConfirmModal { align: center middle; }
    ConfirmModal > Vertical {
        width: 60; height: auto; padding: 1 2;
        border: thick $warning; background: $surface;
    }
    ConfirmModal Label { width: 100%; padding-bottom: 1; }
    ConfirmModal Horizontal { height: auto; align: center middle; }
    ConfirmModal Button { margin: 0 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._message)
            with Horizontal():
                yield Button("Confirm", variant="error", id="confirm")
                yield Button("Cancel", variant="primary", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class _FormModal(ModalScreen[Optional[dict]]):
    """Base for input forms. Subclasses fill ``fields`` and ``title``."""

    DEFAULT_CSS = """
    _FormModal { align: center middle; }
    _FormModal > Vertical {
        width: 70; height: auto; max-height: 90%; padding: 1 2;
        border: thick $accent; background: $surface;
    }
    _FormModal Label.title { text-style: bold; color: $accent; padding-bottom: 1; }
    _FormModal Label.field { padding-top: 1; }
    _FormModal Horizontal { height: auto; align: center middle; padding-top: 1; }
    _FormModal Button { margin: 0 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]
    title_text = "Form"

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.title_text, classes="title")
            yield from self.compose_fields()
            with Horizontal():
                yield Button("OK", variant="success", id="ok")
                yield Button("Cancel", variant="primary", id="cancel")

    def compose_fields(self) -> ComposeResult:  # pragma: no cover - overridden
        return iter(())

    def collect(self) -> Optional[dict]:  # pragma: no cover - overridden
        return {}

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.dismiss(self.collect())
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _val(self, widget_id: str) -> str:
        return self.query_one(f"#{widget_id}", Input).value.strip()


class DnsAddModal(_FormModal):
    title_text = "Add DNS record"

    def compose_fields(self) -> ComposeResult:
        yield Label("Hostname (FQDN or short)", classes="field")
        yield Input(id="hostname", placeholder="web")
        yield Label("IP address", classes="field")
        yield Input(id="ip", placeholder="10.0.0.5")
        yield Label("Instance (optional)", classes="field")
        yield Input(id="instance")

    def collect(self) -> Optional[dict]:
        hostname, ip = self._val("hostname"), self._val("ip")
        if not hostname or not ip:
            return None
        return {"hostname": hostname, "ip": ip, "instance": self._val("instance") or None}


class IpAssignModal(_FormModal):
    title_text = "Assign public IP"

    def compose_fields(self) -> ComposeResult:
        yield Label("Instance name", classes="field")
        yield Input(id="instance")
        yield Label("Specific IP (optional, blank = next available)", classes="field")
        yield Input(id="ip")

    def collect(self) -> Optional[dict]:
        instance = self._val("instance")
        if not instance:
            return None
        return {"instance": instance, "ip": self._val("ip") or None}


class PortAddModal(_FormModal):
    title_text = "Add port forward"

    def compose_fields(self) -> ComposeResult:
        yield Label("Instance name", classes="field")
        yield Input(id="instance")
        yield Label("Public port", classes="field")
        yield Input(id="public_port", type="integer")
        yield Label("Private port", classes="field")
        yield Input(id="private_port", type="integer")
        yield Label("Protocol", classes="field")
        yield Select([("tcp", "tcp"), ("udp", "udp")], id="protocol", value="tcp", allow_blank=False)
        yield Label("Description (optional)", classes="field")
        yield Input(id="description")

    def collect(self) -> Optional[dict]:
        instance = self._val("instance")
        pub, priv = self._val("public_port"), self._val("private_port")
        if not instance or not pub or not priv:
            return None
        return {
            "instance": instance,
            "public_port": int(pub),
            "private_port": int(priv),
            "protocol": self.query_one("#protocol", Select).value,
            "description": self._val("description") or None,
        }


class HostPickerModal(ModalScreen[Optional[str]]):
    """Pick the target fleet host for subsequent mutations. Dismisses the chosen
    host name, or None if cancelled."""

    DEFAULT_CSS = """
    HostPickerModal { align: center middle; }
    HostPickerModal > Vertical {
        width: 60; height: auto; max-height: 80%; padding: 1 2;
        border: thick $accent; background: $surface;
    }
    HostPickerModal Label.title { text-style: bold; color: $accent; padding-bottom: 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, hosts: list[str], current: Optional[str] = None) -> None:
        super().__init__()
        self._hosts = hosts
        self._current = current

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Select target host", classes="title")
            options = [(h + (" (current)" if h == self._current else ""), h) for h in self._hosts]
            yield Select(options, id="host", value=self._current or Select.BLANK, allow_blank=True)
            with Horizontal():
                yield Button("OK", variant="success", id="ok")
                yield Button("Cancel", variant="primary", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            value = self.query_one("#host", Select).value
            self.dismiss(None if value is Select.BLANK else value)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class InstanceNameModal(_FormModal):
    """Single field: an instance/VM name (for delete-by-name actions)."""

    title_text = "Instance name"

    def __init__(self, title: str = "Instance name") -> None:
        super().__init__()
        self.title_text = title

    def compose_fields(self) -> ComposeResult:
        yield Label("VM / instance name", classes="field")
        yield Input(id="name")

    def collect(self) -> Optional[dict]:
        name = self._val("name")
        return {"name": name} if name else None


class InstanceChangeModal(_FormModal):
    """Resize an instance: any of cpu / memory / disk (blank = leave unchanged)."""

    title_text = "Change instance"

    def __init__(self, name: str, host: str) -> None:
        super().__init__()
        self.title_text = f"Change {name} (on {host})"

    def compose_fields(self) -> ComposeResult:
        yield Label("vCPUs (blank = unchanged)", classes="field")
        yield Input(id="cpus", type="integer")
        yield Label("Memory (e.g. 8GB, blank = unchanged)", classes="field")
        yield Input(id="memory")
        yield Label("Root disk (grow-only, e.g. 100GB, blank = unchanged)", classes="field")
        yield Input(id="disk")

    def collect(self) -> Optional[dict]:
        cpus = self._val("cpus")
        out = {
            "cpus": int(cpus) if cpus else None,
            "memory": self._val("memory") or None,
            "disk": self._val("disk") or None,
        }
        if not any(out.values()):
            return None
        return out


class TypedConfirmModal(ModalScreen[bool]):
    """A destructive confirmation that requires re-typing an exact phrase
    (the node/host name). Dismisses True only on an exact match."""

    DEFAULT_CSS = """
    TypedConfirmModal { align: center middle; }
    TypedConfirmModal > Vertical {
        width: 70; height: auto; padding: 1 2;
        border: thick $error; background: $surface;
    }
    TypedConfirmModal Label { width: 100%; }
    TypedConfirmModal Label.warn { color: $error; text-style: bold; padding-bottom: 1; }
    TypedConfirmModal Horizontal { height: auto; align: center middle; padding-top: 1; }
    TypedConfirmModal Button { margin: 0 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, message: str, phrase: str) -> None:
        super().__init__()
        self._message = message
        self._phrase = phrase

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._message, classes="warn")
            yield Label(f"Type '{self._phrase}' to confirm:")
            yield Input(id="phrase")
            with Horizontal():
                yield Button("Confirm", variant="error", id="confirm")
                yield Button("Cancel", variant="primary", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            self.dismiss(self.query_one("#phrase", Input).value.strip() == self._phrase)
        else:
            self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


class ManageUsersModal(ModalScreen[Optional[dict]]):
    """Full-CRUD user management for a VM or host. Lists accounts and dismisses
    {"action": add|suspend|unsuspend|sudo_grant|sudo_revoke|remove, "username": <name>}
    (username omitted for "add"), or None on close."""

    DEFAULT_CSS = """
    ManageUsersModal { align: center middle; }
    ManageUsersModal > Vertical {
        width: 96; height: auto; max-height: 90%; padding: 1 2;
        border: thick $accent; background: $surface;
    }
    ManageUsersModal Label.title { text-style: bold; color: $accent; padding-bottom: 1; }
    ManageUsersModal DataTable { height: auto; max-height: 16; }
    ManageUsersModal Horizontal { height: auto; align: center middle; padding-top: 1; }
    ManageUsersModal Button { margin: 0 1; }
    """

    BINDINGS = [("escape", "cancel", "Close")]

    def __init__(self, scope: str, target: str, accounts) -> None:
        super().__init__()
        self._scope = scope
        self._target = target
        self._accounts = accounts

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"Users on {self._scope} {self._target}  —  select a row, then act",
                        classes="title")
            yield DataTable(id="users", cursor_type="row", zebra_stripes=True)
            with Horizontal():
                yield Button("Add", variant="success", id="add")
                yield Button("Suspend", id="suspend")
                yield Button("Unsuspend", id="unsuspend")
                yield Button("Grant sudo", id="sudo_grant")
                yield Button("Revoke sudo", id="sudo_revoke")
                yield Button("Remove", variant="error", id="remove")
                yield Button("Close", id="cancel")

    def on_mount(self) -> None:
        table = self.query_one("#users", DataTable)
        table.add_columns("User", "UID", "Sudo", "Status", "Keys")
        for a in self._accounts:
            table.add_row(
                a.name, "-" if a.uid is None else str(a.uid),
                "yes" if a.sudo else "-",
                "SUSPENDED" if a.locked else "active", str(a.key_count),
            )

    def _selected_user(self) -> Optional[str]:
        table = self.query_one("#users", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        return str(table.get_row_at(table.cursor_row)[0])

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "cancel":
            self.dismiss(None)
            return
        if bid == "add":
            self.dismiss({"action": "add"})
            return
        user = self._selected_user()
        if user is None:
            return
        self.dismiss({"action": bid, "username": user})


class AddUserModal(_FormModal):
    """Add a user (with SSH key + optional sudo) to a host or a VM/container."""

    def __init__(self, scope: str, target: str, host: str):
        super().__init__()
        self._scope = scope        # "host" | "vm"
        self._target = target
        self._host = host
        where = f"host {target}" if scope == "host" else f"{scope} {target} (on {host})"
        self.title_text = f"Add user to {where}"

    def compose_fields(self) -> ComposeResult:
        yield Label("Username", classes="field")
        yield Input(id="username", placeholder="alice")
        yield Label("SSH public key", classes="field")
        yield Input(id="key", placeholder="ssh-ed25519 AAAA... user@host")
        yield Checkbox("Grant passwordless sudo", id="sudo")

    def collect(self) -> Optional[dict]:
        user = self._val("username")
        key = self._val("key")
        if not user or not key:
            return None
        return {
            "scope": self._scope, "target": self._target, "host": self._host,
            "username": user, "key": key,
            "sudo": self.query_one("#sudo", Checkbox).value,
        }


class VmCreateModal(_FormModal):
    title_text = "Create VM / container"

    def compose_fields(self) -> ComposeResult:
        yield Label("Name", classes="field")
        yield Input(id="name")
        yield Label("Type", classes="field")
        yield Select(
            [("vm", "vm"), ("container", "container")],
            id="type", value="vm", allow_blank=False,
        )
        yield Label("Image", classes="field")
        yield Input(id="image", value="images:ubuntu/24.04/cloud")
        yield Label("vCPUs", classes="field")
        yield Input(id="cpus", value="1", type="integer")
        yield Label("Memory", classes="field")
        yield Input(id="memory", value="2048MB")
        yield Label("Disk", classes="field")
        yield Input(id="disk", value="20GB")
        yield Label("Network", classes="field")
        yield Select(
            [("public", "public"), ("private", "private")],
            id="network", value="public", allow_blank=False,
        )
        yield Label("Template (optional)", classes="field")
        yield Input(id="template")

    def collect(self) -> Optional[dict]:
        name = self._val("name")
        if not name:
            return None
        return {
            "name": name,
            "type": self.query_one("#type", Select).value,
            "image": self._val("image") or "images:ubuntu/24.04/cloud",
            "cpus": int(self._val("cpus") or "1"),
            "memory": self._val("memory") or "2048MB",
            "disk": self._val("disk") or "20GB",
            "network": self.query_one("#network", Select).value,
            "template": self._val("template") or None,
        }
