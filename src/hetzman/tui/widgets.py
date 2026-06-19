"""Reusable Textual widgets for the hetzman control center."""
from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog, Static

from ..core.events import ProgressEvent, Severity

# Severity -> (Rich style, prefix glyph) for log lines.
_SEVERITY_STYLE: dict[Severity, tuple[str, str]] = {
    Severity.INFO: ("dim", "·"),
    Severity.STEP: ("cyan", "▶"),
    Severity.SUCCESS: ("green", "✓"),
    Severity.WARNING: ("yellow", "!"),
    Severity.ERROR: ("red", "✗"),
}


class LogPanel(RichLog):
    """Shared activity log. The single sink for streamed ``ProgressEvent``s.

    In P2 it records refresh activity and errors; later phases stream the step
    events of every mutation here, giving one unified activity log across all
    screens.
    """

    def write_event(self, event: ProgressEvent) -> None:
        """Render a :class:`ProgressEvent` as one styled line."""
        style, glyph = _SEVERITY_STYLE.get(event.severity, ("", "·"))
        line = Text()
        line.append(f"{glyph} ", style=style)
        if event.step is not None and event.total is not None:
            line.append(f"[{event.step}/{event.total}] ", style="bold")
        if event.scope:
            line.append(f"({event.scope}) ", style="dim")
        line.append(event.message, style=style)
        if event.detail:
            line.append(f"  — {event.detail}", style="dim")
        self.write(line)

    def info(self, message: str) -> None:
        self.write_event(ProgressEvent(Severity.INFO, message))

    def error(self, message: str) -> None:
        self.write_event(ProgressEvent(Severity.ERROR, message))


class Banner(Static):
    """A dismissable status banner, hidden until there is something to say.

    Used for connection problems (etcd unavailable) so the dashboard degrades
    to a visible message instead of a blank screen or a crash.
    """

    DEFAULT_CSS = """
    Banner {
        display: none;
        width: 100%;
        padding: 0 1;
        background: $error;
        color: $text;
    }
    Banner.visible { display: block; }
    """

    def show(self, message: str) -> None:
        self.update(Text(message, style="bold"))
        self.add_class("visible")

    def clear(self) -> None:
        self.update("")
        self.remove_class("visible")
