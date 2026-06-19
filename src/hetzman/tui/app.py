"""The hetzman Textual application — read-only Dashboard + Fleet (P2).

Architecture notes (the pattern every later screen reuses):

* Data is read from the synchronous, blocking etcd-backed ``core.reads`` only
  inside **thread workers** (``@work(thread=True)``); the UI event loop is
  never blocked. ``core.concurrency`` serialises the underlying etcd access, so
  concurrent refresh workers are safe.
* Workers marshal results back onto the UI thread with ``call_from_thread``;
  widgets are never touched from a worker thread.
* ``EtcdUnavailable`` (and any load error) degrades to a visible banner + a log
  line, never a crash or a blank screen.
* The :class:`~hetzman.tui.widgets.LogPanel` is the shared activity sink that
  later phases stream mutation ``ProgressEvent``s into.
"""
from __future__ import annotations

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Static,
    TabbedContent,
    TabPane,
)

from ..core import reads
from ..core.errors import EtcdUnavailable
from ..core.models import FleetStatus, SystemStatus
from .widgets import Banner, LogPanel

_FLEET_COLUMNS = ("Node", "Heartbeat", "Checks", "Peers", "Versions", "Sync", "Disk/Pool")


def _ok_or(values: tuple[str, ...]) -> Text:
    """Render the fleet 'Checks'/'Peers' cell: green ok, or red bad keys."""
    if not values:
        return Text("ok", style="green")
    return Text(",".join(values), style="red")


class HetzmanApp(App):
    """Interactive control center. Read-only in P2."""

    TITLE = "hetzman"
    SUB_TITLE = "control center"

    CSS = """
    #banner { dock: top; }
    #system-card { padding: 1 2; height: auto; }
    #fleet-summary { padding: 0 2 1 2; height: auto; }
    #fleet-table { height: 1fr; }
    #log {
        dock: bottom;
        height: 10;
        border-top: solid $accent;
        background: $surface;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
    ]

    # Refresh cadences. Fleet heartbeats carry a 300s TTL, so 10s is plenty
    # fresh; the cross-prefix system counters change less and poll slower.
    FLEET_INTERVAL = 10.0
    SYSTEM_INTERVAL = 30.0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Banner(id="banner")
        with TabbedContent(initial="tab-dashboard"):
            with TabPane("Dashboard", id="tab-dashboard"):
                yield Static("Loading system status…", id="system-card")
                yield Static("", id="fleet-summary")
            with TabPane("Fleet", id="tab-fleet"):
                yield DataTable(id="fleet-table", zebra_stripes=True, cursor_type="row")
        yield LogPanel(id="log", max_lines=1000, wrap=True, highlight=False, markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#fleet-table", DataTable).add_columns(*_FLEET_COLUMNS)
        self.query_one(LogPanel).info("hetzman control center started")
        self.action_refresh()
        self.set_interval(self.FLEET_INTERVAL, self._load_fleet)
        self.set_interval(self.SYSTEM_INTERVAL, self._load_system)

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #
    def action_refresh(self) -> None:
        self._load_fleet()
        self._load_system()

    # ------------------------------------------------------------------ #
    # Workers (thread; etcd is blocking)
    # ------------------------------------------------------------------ #
    @work(thread=True, group="fleet", exclusive=True)
    def _load_fleet(self) -> None:
        try:
            fleet = reads.get_fleet_status()
        except EtcdUnavailable as exc:
            self.call_from_thread(self._on_etcd_error, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self.call_from_thread(self._on_load_error, "fleet", exc)
            return
        self.call_from_thread(self._render_fleet, fleet)

    @work(thread=True, group="system", exclusive=True)
    def _load_system(self) -> None:
        try:
            status = reads.get_system_status()
        except EtcdUnavailable as exc:
            self.call_from_thread(self._on_etcd_error, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self.call_from_thread(self._on_load_error, "system", exc)
            return
        self.call_from_thread(self._render_system, status)

    # ------------------------------------------------------------------ #
    # Render (UI thread)
    # ------------------------------------------------------------------ #
    def _render_fleet(self, fleet: FleetStatus) -> None:
        self.query_one(Banner).clear()
        table = self.query_one("#fleet-table", DataTable)
        table.clear()
        for node in fleet.nodes:
            if not node.alive:
                table.add_row(
                    node.name,
                    Text("DOWN (no heartbeat)", style="red"),
                    "-", "-", "-", "-", "-",
                )
                continue
            age = "?" if node.heartbeat_age_s is None else f"{node.heartbeat_age_s}s ago"
            versions = Text(f"{node.hetzman_version} / incus {node.incus_version}")
            if (
                fleet.registered_node_count
                and node.endpoints_configured != fleet.registered_node_count
            ):
                versions.append(
                    f" (endpoints={node.endpoints_configured}"
                    f"!={fleet.registered_node_count})",
                    style="red",
                )
            sync = (
                Text("error", style="red")
                if node.sync_result == "error"
                else Text(node.sync_result)
            )
            disk = "?" if node.disk_root_pct is None else str(node.disk_root_pct)
            pool = "?" if node.pool_pct is None else str(node.pool_pct)
            table.add_row(
                node.name,
                Text(age, style="green"),
                _ok_or(node.checks_bad),
                _ok_or(node.peers_bad),
                versions,
                sync,
                f"{disk}% / {pool}%",
            )

        summary = self.query_one("#fleet-summary", Static)
        if fleet.degraded:
            summary.update(Text("● Fleet DEGRADED", style="bold red"))
        else:
            summary.update(Text("● Fleet healthy", style="bold green"))

    def _render_system(self, status: SystemStatus) -> None:
        self.query_one(Banner).clear()
        text = Text()
        text.append(f"HetzMan Status — {status.server}\n\n", style="bold cyan")
        text.append("DNS Records: ", style="")
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

    # ------------------------------------------------------------------ #
    # Error handling (UI thread)
    # ------------------------------------------------------------------ #
    def _on_etcd_error(self, message: str) -> None:
        self.query_one(Banner).show(f"etcd unavailable: {message}")
        self.query_one(LogPanel).error(f"etcd unavailable: {message}")

    def _on_load_error(self, what: str, exc: Exception) -> None:
        self.query_one(LogPanel).error(f"{what} refresh failed: {type(exc).__name__}: {exc}")


def run() -> None:
    """Entry point used by the ``hetzman tui`` command."""
    HetzmanApp().run()
