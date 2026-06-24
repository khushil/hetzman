"""The hetzman Textual application — full control center (P4).

Read-only dashboards (P2) plus interactive mutations: the etcd-backed domains
(IPs / DNS / Ports) are CRUD tabs, and VM/IP/DNS/Port operations are also on the
command palette (ctrl+\\). Every mutation runs in a thread worker that drives a
``core`` generator and streams its ``ProgressEvent``s into the shared LogPanel;
destructive actions route through a ConfirmModal first.

Architecture invariants (reused by every screen):
* data + mutations touch the blocking, etcd-backed ``core`` layer ONLY inside
  ``@work(thread=True)`` workers; ``core.concurrency`` serialises etcd access.
* workers marshal back via ``call_from_thread`` — widgets are never touched off
  the UI thread.
* ``EtcdUnavailable`` / errors degrade to a banner or a log line, never a crash.
"""
from __future__ import annotations

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.command import Hit, Hits, Provider
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Static,
    TabbedContent,
    TabPane,
)

from ..core import dns as core_dns
from ..core import exec as host_exec
from ..core import instances as core_instances
from ..core import ip as core_ip
from ..core import nodes as core_nodes
from ..core import ops as core_ops
from ..core import ports as core_ports
from ..core import reads
from ..core import vms as core_vms
from ..core.errors import CoreError, EtcdUnavailable
from ..core.events import ProgressEvent, Severity
from ..core.models import FleetStatus, SystemStatus
from .modals import (
    ConfirmModal,
    DnsAddModal,
    HostPickerModal,
    InstanceChangeModal,
    InstanceNameModal,
    IpAssignModal,
    PortAddModal,
    TypedConfirmModal,
    VmCreateModal,
)
from .widgets import Banner, LogPanel

_FLEET_COLUMNS = ("Node", "Heartbeat", "Checks", "Peers", "Versions", "Sync", "Disk/Pool")
_IP_COLUMNS = ("IP Address", "Server", "Status", "Assigned To")
_DNS_COLUMNS = ("Hostname", "IP", "Server", "Instance", "Type", "Auto")
_PORT_COLUMNS = ("Public", "Private", "Protocol", "Instance", "Description", "Enabled")
_INSTANCE_COLUMNS = ("Name", "Host", "Type", "Status", "CPU", "Mem", "Disk", "Private IP")
_NODE_COLUMNS = ("Node", "vSwitch IP", "Bridge", "Public block", "etcd name")

# active tab id -> the DataTable id holding that domain's rows
_DOMAIN_TABLE = {
    "tab-ips": "#ip-table",
    "tab-dns": "#dns-table",
    "tab-ports": "#port-table",
}


def _ok_or(values: tuple[str, ...]) -> Text:
    return Text("ok", style="green") if not values else Text(",".join(values), style="red")


class HetzmanCommands(Provider):
    """Command-palette entries for every control-center action."""

    @property
    def _commands(self):
        app = self.app
        return [
            ("Create VM", app.action_create_vm),
            ("Delete VM", app.action_delete_vm),
            ("Assign public IP", lambda: app.push_add("tab-ips")),
            ("Add DNS record", lambda: app.push_add("tab-dns")),
            ("Add port forward", lambda: app.push_add("tab-ports")),
            ("Change instance (cpu/mem/disk)", app.action_change_instance),
            ("Reboot instance", app.action_reboot_instance),
            ("Apply updates on a host", app.action_apply_updates),
            ("Reboot a host", app.action_reboot_host),
            ("Remove node from fleet", app.action_remove_node),
            ("Select target host", app.action_pick_host),
            ("Refresh all", app.action_refresh),
            ("Go to: Dashboard", lambda: app.goto("tab-dashboard")),
            ("Go to: Fleet", lambda: app.goto("tab-fleet")),
            ("Go to: Instances", lambda: app.goto("tab-instances")),
            ("Go to: Nodes", lambda: app.goto("tab-nodes")),
            ("Go to: IPs", lambda: app.goto("tab-ips")),
            ("Go to: DNS", lambda: app.goto("tab-dns")),
            ("Go to: Ports", lambda: app.goto("tab-ports")),
        ]

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for name, callback in self._commands:
            score = matcher.match(name)
            if score > 0:
                yield Hit(score, matcher.highlight(name), callback, help=name)


class HetzmanApp(App):
    """Interactive control center."""

    TITLE = "hetzman"
    SUB_TITLE = "control center"
    COMMANDS = App.COMMANDS | {HetzmanCommands}

    CSS = """
    #banner { dock: top; }
    #system-card { padding: 1 2; height: auto; }
    #fleet-summary { padding: 0 2 1 2; height: auto; }
    DataTable { height: 1fr; }
    #log {
        dock: bottom; height: 10;
        border-top: solid $accent; background: $surface; padding: 0 1;
    }
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("n", "create_vm", "New VM/ctr"),
        ("a", "add", "Add"),
        ("c", "change_instance", "Change"),
        ("b", "reboot_instance", "Reboot"),
        ("d", "delete", "Delete"),
        ("ctrl+p", "command_palette", "More…"),
        ("q", "quit", "Quit"),
    ]

    FLEET_INTERVAL = 10.0
    SYSTEM_INTERVAL = 30.0
    DOMAIN_INTERVAL = 30.0
    INSTANCE_INTERVAL = 30.0

    # Target host for mutations (None until picked; defaults to current node on
    # a fleet node, required on the external command-centre box).
    target_host: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Banner(id="banner")
        with TabbedContent(initial="tab-dashboard"):
            with TabPane("Dashboard", id="tab-dashboard"):
                yield Static("Loading system status…", id="system-card")
                yield Static("", id="fleet-summary")
            with TabPane("Fleet", id="tab-fleet"):
                yield DataTable(id="fleet-table", zebra_stripes=True, cursor_type="row")
            with TabPane("IPs", id="tab-ips"):
                yield DataTable(id="ip-table", zebra_stripes=True, cursor_type="row")
            with TabPane("DNS", id="tab-dns"):
                yield Static("Loading resolver status…", id="dns-server-card")
                yield DataTable(id="dns-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Instances", id="tab-instances"):
                yield DataTable(id="instance-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Nodes", id="tab-nodes"):
                yield DataTable(id="node-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Ports", id="tab-ports"):
                yield DataTable(id="port-table", zebra_stripes=True, cursor_type="row")
        yield LogPanel(id="log", max_lines=1000, wrap=True, highlight=False, markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#fleet-table", DataTable).add_columns(*_FLEET_COLUMNS)
        self.query_one("#ip-table", DataTable).add_columns(*_IP_COLUMNS)
        self.query_one("#dns-table", DataTable).add_columns(*_DNS_COLUMNS)
        self.query_one("#port-table", DataTable).add_columns(*_PORT_COLUMNS)
        self.query_one("#instance-table", DataTable).add_columns(*_INSTANCE_COLUMNS)
        self.query_one("#node-table", DataTable).add_columns(*_NODE_COLUMNS)
        self.query_one(LogPanel).info("hetzman control center started")
        self.action_refresh()
        self.set_interval(self.FLEET_INTERVAL, self._load_fleet)
        self.set_interval(self.SYSTEM_INTERVAL, self._load_system)
        self.set_interval(self.DOMAIN_INTERVAL, self._load_domains)
        self.set_interval(self.INSTANCE_INTERVAL, self._load_instances)

    # ------------------------------------------------------------------ #
    # Navigation helpers
    # ------------------------------------------------------------------ #
    def goto(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    @property
    def _active_tab(self) -> str:
        return self.query_one(TabbedContent).active

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #
    def action_refresh(self) -> None:
        self._load_fleet()
        self._load_system()
        self._load_domains()
        self._load_instances()
        self._load_nodes()

    # ---- instance / node / ops actions (selected row drives the target) ----
    def _selected(self, table_id: str):
        table = self.query_one(table_id, DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        return [str(c) for c in table.get_row_at(table.cursor_row)]

    def action_change_instance(self) -> None:
        row = self._selected("#instance-table")
        if not row:
            self.query_one(LogPanel).info("Select an instance row first (Instances tab).")
            return
        name, host = row[0], row[1]

        def _then(data):
            if not data:
                return
            remote = ["vm", "change", name, "--yes"]
            if data["cpus"] is not None:
                remote += ["--cpus", str(data["cpus"])]
            if data["memory"]:
                remote += ["--memory", data["memory"]]
            if data["disk"]:
                remote += ["--disk", data["disk"]]
            self._delegate(host, remote,
                           lambda: core_instances.change_instance(
                               name, cpus=data["cpus"], memory=data["memory"], disk=data["disk"]),
                           f"change {name}")

        self.push_screen(InstanceChangeModal(name, host), _then)

    def action_reboot_instance(self) -> None:
        row = self._selected("#instance-table")
        if not row:
            self.query_one(LogPanel).info("Select an instance row first (Instances tab).")
            return
        name, host = row[0], row[1]
        self._confirm(
            f"Reboot instance {name} on {host}?",
            None,
            f"reboot {name}",
            delegate=(host, ["vm", "reboot", name, "--yes"],
                      lambda: core_instances.reboot_instance(name)),
        )

    def action_apply_updates(self) -> None:
        self._pick_then(lambda host: self._delegate(
            host, ["ops", "apply-updates", "--host", host, "--yes"],
            lambda: core_ops.apply_updates(host), f"apply-updates {host}"))

    def action_reboot_host(self) -> None:
        def _picked(host):
            def _confirmed(ok):
                if ok:
                    self._delegate(host, ["ops", "reboot", "--host", host, "--yes"],
                                   lambda: core_ops.reboot_host(host), f"reboot host {host}")
            self.push_screen(
                TypedConfirmModal(f"REBOOT host {host} (its VMs/containers go down)", host),
                _confirmed,
            )
        self._pick_then(_picked)

    def action_remove_node(self) -> None:
        row = self._selected("#node-table")
        if not row:
            self.query_one(LogPanel).info("Select a node row first (Nodes tab).")
            return
        name = row[0]

        def _confirmed(ok):
            if ok:
                self._run_mutation(
                    lambda: core_nodes.remove_node(name, remove_member=True), f"remove node {name}")
        self.push_screen(
            TypedConfirmModal(f"Remove node {name} + its etcd member (guarded)", name),
            _confirmed,
        )

    def _pick_then(self, callback) -> None:
        """Open the host picker, then call back with the chosen host."""
        self._open_host_picker(callback)

    def action_pick_host(self) -> None:
        def _then(host):
            if host:
                self.target_host = host
                self.sub_title = f"target: {host}"
                self.query_one(LogPanel).info(f"target host set to {host}")
        self._open_host_picker(_then)

    @work(thread=True, group="hostpicker", exclusive=True)
    def _open_host_picker(self, callback) -> None:
        from ..registry import load_registry
        try:
            hosts = sorted(load_registry())
        except Exception as exc:  # pragma: no cover - defensive
            self.call_from_thread(self.query_one(LogPanel).error, f"host list failed: {exc}")
            return
        self.call_from_thread(self.push_screen, HostPickerModal(hosts, self.target_host), callback)

    def action_add(self) -> None:
        self.push_add(self._active_tab)

    def push_add(self, tab_id: str) -> None:
        if tab_id == "tab-dns":
            self.push_screen(DnsAddModal(), self._on_dns_add)
        elif tab_id == "tab-ips":
            self.push_screen(IpAssignModal(), self._on_ip_assign)
        elif tab_id == "tab-ports":
            self.push_screen(PortAddModal(), self._on_port_add)
        # Dashboard/Fleet have no "add" action.

    def action_delete(self) -> None:
        tab = self._active_tab
        table_sel = _DOMAIN_TABLE.get(tab)
        if not table_sel:
            return
        table = self.query_one(table_sel, DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return
        row = [str(c) for c in table.get_row_at(table.cursor_row)]
        if tab == "tab-dns":
            hostname = row[0]
            self._confirm(
                f"Remove DNS record {hostname}?",
                lambda: core_dns.remove_dns(hostname),
                f"remove dns {hostname}",
            )
        elif tab == "tab-ports":
            public_port = row[0].rsplit(":", 1)[-1]
            instance, protocol = row[3], row[2]
            self._confirm(
                f"Remove port forward {instance} {public_port}/{protocol}?",
                lambda: core_ports.remove_port(instance, int(public_port), protocol),
                f"remove port {instance}:{public_port}",
            )
        elif tab == "tab-ips":
            assigned_to = row[3]
            if not assigned_to or assigned_to == "-":
                self.query_one(LogPanel).info("Selected IP is not assigned; nothing to release.")
                return
            self._confirm(
                f"Release IP from {assigned_to}?",
                lambda: core_ip.release_ip(assigned_to),
                f"release ip {assigned_to}",
            )

    def action_create_vm(self) -> None:
        self.push_screen(VmCreateModal(), self._on_vm_create)

    def action_delete_vm(self) -> None:
        def _then(data):
            if not data:
                return
            name = data["name"]
            self._confirm(
                f"Permanently delete VM {name} and all its rules?",
                lambda: core_vms.delete_vm(name),
                f"delete vm {name}",
            )

        self.push_screen(InstanceNameModal("Delete VM"), _then)

    # ------------------------------------------------------------------ #
    # Modal result handlers -> mutations
    # ------------------------------------------------------------------ #
    def _on_dns_add(self, data) -> None:
        if not data:
            return
        self._run_mutation(
            lambda: core_dns.add_dns(data["hostname"], data["ip"], data["instance"]),
            f"add dns {data['hostname']}",
        )

    def _on_ip_assign(self, data) -> None:
        if not data:
            return
        self._run_mutation(
            lambda: core_ip.assign_ip(data["instance"], data["ip"]),
            f"assign ip {data['instance']}",
        )

    def _on_port_add(self, data) -> None:
        if not data:
            return
        self._run_mutation(
            lambda: core_ports.add_port(
                data["instance"], data["public_port"], data["private_port"],
                data["protocol"], data["description"],
            ),
            f"add port {data['instance']}:{data['public_port']}",
        )

    def _on_vm_create(self, data) -> None:
        if not data:
            return
        itype = data.get("type", "vm")
        self._run_mutation(
            lambda: core_vms.create_vm(
                data["name"], image=data["image"], cpus=data["cpus"],
                memory=data["memory"], disk=data["disk"],
                network_type=data["network"], template=data["template"],
                instance_type=itype,
            ),
            f"create {itype} {data['name']}",
        )

    def _confirm(self, message: str, factory, label: str, *, delegate=None) -> None:
        def _then(confirmed: bool) -> None:
            if not confirmed:
                return
            if delegate is not None:
                self._delegate(*delegate, label)
            else:
                self._run_mutation(factory, label)

        self.push_screen(ConfirmModal(message), _then)

    def _delegate(self, host: str, remote_argv, gen_factory, label: str) -> None:
        self._run_delegated(host, remote_argv, gen_factory, label)

    # ------------------------------------------------------------------ #
    # Mutation workers: drive a core generator (local) or delegate to the
    # target node's hetzman over SSH, streaming events into the log.
    # ------------------------------------------------------------------ #
    @work(thread=True, exclusive=False)
    def _run_mutation(self, factory, label: str) -> None:
        log = self.query_one(LogPanel)
        self.call_from_thread(log.info, f"▶ {label}")
        gen = factory()
        try:
            while True:
                try:
                    event = next(gen)
                except StopIteration:
                    break
                self.call_from_thread(log.write_event, event)
        except (CoreError, Exception) as exc:  # noqa: BLE001 - surface, never crash
            self.call_from_thread(log.error, f"{label}: {type(exc).__name__}: {exc}")
        finally:
            gen.close()
        self.call_from_thread(self._load_domains)
        self.call_from_thread(self._load_system)
        self.call_from_thread(self._load_instances)

    @work(thread=True, exclusive=False)
    def _run_delegated(self, host: str, remote_argv, gen_factory, label: str) -> None:
        log = self.query_one(LogPanel)
        self.call_from_thread(log.info, f"▶ {label} @ {host}")
        try:
            if host_exec.is_local(host):
                gen = gen_factory()
                try:
                    while True:
                        try:
                            event = next(gen)
                        except StopIteration:
                            break
                        self.call_from_thread(log.write_event, event)
                finally:
                    gen.close()
            else:
                for line in host_exec.stream_on(host, ["hetzman", *remote_argv], root=True, timeout=1800):
                    self.call_from_thread(log.info, line)
        except (CoreError, Exception) as exc:  # noqa: BLE001 - surface, never crash
            self.call_from_thread(log.error, f"{label}: {type(exc).__name__}: {exc}")
        self.call_from_thread(self._load_instances)

    # ------------------------------------------------------------------ #
    # Read workers (thread; etcd is blocking)
    # ------------------------------------------------------------------ #
    @work(thread=True, group="fleet", exclusive=True)
    def _load_fleet(self) -> None:
        self._load_into(reads.get_fleet_status, self._render_fleet, "fleet")

    @work(thread=True, group="system", exclusive=True)
    def _load_system(self) -> None:
        self._load_into(reads.get_system_status, self._render_system, "system")

    @work(thread=True, group="domains", exclusive=True)
    def _load_domains(self) -> None:
        try:
            ips = reads.list_ips()
            dns = reads.list_dns()
            ports = reads.list_ports()
        except EtcdUnavailable as exc:
            self.call_from_thread(self._on_etcd_error, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self.call_from_thread(self._on_load_error, "domains", exc)
            return
        try:  # resolver status is best-effort; never blocks the domain tables
            dns_status = reads.get_dns_server_status()
        except Exception:  # noqa: BLE001
            dns_status = None
        self.call_from_thread(self._render_domains, ips, dns, ports, dns_status)

    @work(thread=True, group="instances", exclusive=True)
    def _load_instances(self) -> None:
        try:
            items, unreachable = reads.list_instances(None)
        except EtcdUnavailable as exc:
            self.call_from_thread(self._on_etcd_error, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self.call_from_thread(self._on_load_error, "instances", exc)
            return
        self.call_from_thread(self._render_instances, items, unreachable)

    @work(thread=True, group="nodes", exclusive=True)
    def _load_nodes(self) -> None:
        try:
            nodes, errors = reads.list_nodes()
        except EtcdUnavailable as exc:
            self.call_from_thread(self._on_etcd_error, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self.call_from_thread(self._on_load_error, "nodes", exc)
            return
        self.call_from_thread(self._render_nodes, nodes, errors)

    def _load_into(self, read_fn, render_fn, what: str) -> None:
        try:
            data = read_fn()
        except EtcdUnavailable as exc:
            self.call_from_thread(self._on_etcd_error, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self.call_from_thread(self._on_load_error, what, exc)
            return
        self.call_from_thread(render_fn, data)

    # ------------------------------------------------------------------ #
    # Render (UI thread)
    # ------------------------------------------------------------------ #
    def _overlay_active(self) -> bool:
        """True when a modal or the command palette is on top. Background
        refreshes must not repaint (or query) through it — ``query_one`` would
        search the overlay screen and raise ``NoMatches``."""
        return len(self.screen_stack) > 1

    def _base_query(self, selector):
        """query_one against the base screen, regardless of any active overlay."""
        return self.screen_stack[0].query_one(selector)

    def _render_fleet(self, fleet: FleetStatus) -> None:
        if self._overlay_active():
            return
        self.query_one(Banner).clear()
        table = self.query_one("#fleet-table", DataTable)
        table.clear()
        for node in fleet.nodes:
            if not node.alive:
                table.add_row(node.name, Text("DOWN (no heartbeat)", style="red"), "-", "-", "-", "-", "-")
                continue
            age = "?" if node.heartbeat_age_s is None else f"{node.heartbeat_age_s}s ago"
            versions = Text(f"{node.hetzman_version} / incus {node.incus_version}")
            if fleet.registered_node_count and node.endpoints_configured != fleet.registered_node_count:
                versions.append(
                    f" (endpoints={node.endpoints_configured}!={fleet.registered_node_count})",
                    style="red",
                )
            sync = Text("error", style="red") if node.sync_result == "error" else Text(node.sync_result)
            disk = "?" if node.disk_root_pct is None else str(node.disk_root_pct)
            pool = "?" if node.pool_pct is None else str(node.pool_pct)
            table.add_row(
                node.name, Text(age, style="green"),
                _ok_or(node.checks_bad), _ok_or(node.peers_bad),
                versions, sync, f"{disk}% / {pool}%",
            )
        summary = self.query_one("#fleet-summary", Static)
        summary.update(
            Text("● Fleet DEGRADED", style="bold red")
            if fleet.degraded
            else Text("● Fleet healthy", style="bold green")
        )

    def _render_system(self, status: SystemStatus) -> None:
        if self._overlay_active():
            return
        self.query_one(Banner).clear()
        text = Text()
        text.append(f"HetzMan Status — {status.server}\n\n", style="bold cyan")
        text.append("DNS Records: ")
        text.append(str(status.dns_mine), style="green")
        text.append(f"  (total {status.dns_total})\n")
        for type_name, count in status.dns_types.items():
            text.append(f"  - {type_name}: {count}\n", style="dim")
        text.append("Available IPs: ")
        text.append(str(status.ips_available), style="green")
        text.append(f" / {status.ips_total}\n")
        text.append("Active NAT Rules: ")
        text.append(f"{status.active_nat}\n", style="green")
        text.append("Active Port Forwards: ")
        text.append(f"{status.active_ports}\n", style="green")
        text.append("ETCD Cluster: ")
        if status.etcd_members is None:
            text.append("Unknown", style="yellow")
        else:
            text.append(f"{status.etcd_members} members", style="green")
        self.query_one("#system-card", Static).update(text)

    def _render_domains(self, ips, dns, ports, dns_status=None) -> None:
        if self._overlay_active():
            return
        self.query_one(Banner).clear()

        card = self.query_one("#dns-server-card", Static)
        if dns_status is None:
            card.update("[dim]resolver status unavailable[/dim]")
        else:
            s = dns_status

            def tick(ok):
                return "[green]✓[/green]" if ok else "[red]✗[/red]"

            card.update(
                f"resolver @ {s.host}   active {tick(s.active)}  forward {tick(s.forward_ok)}  "
                f"reverse {tick(s.reverse_ok)}  dhcp {tick(s.dhcp_listener)}\n"
                f"listen {', '.join(s.listen_addrs) or '-'}   "
                f"fwd {', '.join(s.forwarders) or '-'}   acl {', '.join(s.external_acl) or '-'}"
            )

        ip_table = self.query_one("#ip-table", DataTable)
        ip_table.clear()
        for a in ips:
            ip_table.add_row(
                a.ip, a.server,
                Text(a.status, style="green" if a.status == "available" else "red"),
                a.assigned_to if a.assigned_to is not None else "-",
            )

        dns_table = self.query_one("#dns-table", DataTable)
        dns_table.clear()
        for r in dns:
            dns_table.add_row(
                r.hostname, r.ip, r.server, r.instance or "-", r.type or "-",
                "Yes" if r.auto else "No",
            )

        port_table = self.query_one("#port-table", DataTable)
        port_table.clear()
        for p in ports:
            port_table.add_row(
                f"{p.public_ip}:{p.public_port}", f"{p.private_ip}:{p.private_port}",
                p.protocol, p.instance,
                p.description if p.description is not None else "-",
                "Yes" if p.enabled else "No",
            )

    def _render_instances(self, items, unreachable) -> None:
        if self._overlay_active():
            return
        table = self.query_one("#instance-table", DataTable)
        table.clear()
        for i in sorted(items, key=lambda x: (x.host, x.name)):
            running = i.status.lower() in ("running", "started")
            table.add_row(
                i.name, i.host,
                "vm" if i.type == "virtual-machine" else (i.type or "?"),
                Text(i.status, style="green" if running else "red"),
                "-" if i.cpus is None else str(i.cpus),
                i.memory or "-", i.disk or "-", i.private_ip or "-",
            )
        if unreachable:
            self.query_one(LogPanel).write_event(
                ProgressEvent(Severity.WARNING,
                              f"instances: unreachable hosts skipped: {', '.join(unreachable)}")
            )

    def _render_nodes(self, nodes, errors) -> None:
        if self._overlay_active():
            return
        table = self.query_one("#node-table", DataTable)
        table.clear()
        for n in nodes:
            table.add_row(
                n.name, n.vswitch_ip,
                f"{n.bridge_ip} ({n.bridge_subnet})",
                n.public_block or "-", n.etcd_name or "-",
            )
        if errors:
            self.query_one(LogPanel).write_event(
                ProgressEvent(Severity.WARNING, f"registry: {'; '.join(errors)}")
            )

    # ------------------------------------------------------------------ #
    # Error handling (UI thread)
    # ------------------------------------------------------------------ #
    def _on_etcd_error(self, message: str) -> None:
        # base-screen queries so an error during a modal/palette still surfaces
        self._base_query(Banner).show(f"etcd unavailable: {message}")
        self._base_query(LogPanel).error(f"etcd unavailable: {message}")

    def _on_load_error(self, what: str, exc: Exception) -> None:
        self._base_query(LogPanel).error(f"{what} refresh failed: {type(exc).__name__}: {exc}")


def run() -> None:
    """Entry point used by the ``hetzman tui`` command."""
    HetzmanApp().run()
