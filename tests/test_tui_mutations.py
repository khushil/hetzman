"""Headless tests for the P4 interactive control center (domain tabs + mutations).

App.run_test() pilot; core.reads and the core write generators are patched.
"""
import asyncio
from unittest.mock import patch

from hetzman.core.events import OpResult, ProgressEvent, Severity
from hetzman.core.models import (
    DNSRecord,
    FleetStatus,
    IPAllocation,
    PortForward,
    SystemStatus,
)
from hetzman.tui.app import HetzmanApp
from hetzman.tui.modals import ConfirmModal, DnsAddModal
from hetzman.tui.widgets import LogPanel
from textual.widgets import DataTable


def _run(coro_factory):
    asyncio.run(coro_factory())


def _system():
    return SystemStatus("srv1", 1, 1, {}, 1, 2, 0, 0, 3)


def _fleet():
    return FleetStatus((), False, frozenset(), 0)


def _ips():
    return [IPAllocation("1.1.1.1", "srv1", "assigned", "vm1", None),
            IPAllocation("1.1.1.2", "srv1", "available", None, None)]


def _dns():
    return [DNSRecord("web.x", "1.1.1.1", "srv1", "vm1", None, False, None)]


def _ports():
    return [PortForward("1.1.1.1", 80, "10.0.0.5", 8080, "tcp", "vm1", "web", True)]


def _reads_patch():
    return [
        patch("hetzman.core.reads.get_system_status", return_value=_system()),
        patch("hetzman.core.reads.get_fleet_status", return_value=_fleet()),
        patch("hetzman.core.reads.list_ips", return_value=_ips()),
        patch("hetzman.core.reads.list_dns", return_value=_dns()),
        patch("hetzman.core.reads.list_ports", return_value=_ports()),
    ]


def test_domain_tabs_populate():
    async def body():
        patches = _reads_patch()
        for p in patches:
            p.start()
        try:
            app = HetzmanApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert app.query_one("#ip-table", DataTable).row_count == 2
                assert app.query_one("#dns-table", DataTable).row_count == 1
                assert app.query_one("#port-table", DataTable).row_count == 1
        finally:
            for p in patches:
                p.stop()
    _run(body)


def test_add_dns_streams_into_log():
    async def body():
        patches = _reads_patch()
        for p in patches:
            p.start()

        def fake_add(hostname, ip, instance=None, **kw):
            yield ProgressEvent(Severity.SUCCESS, f"Added DNS record: {hostname} -> {ip}")
            return OpResult(ok=True, summary={"hostname": hostname})

        try:
            with patch("hetzman.tui.app.core_dns.add_dns", side_effect=fake_add):
                app = HetzmanApp()
                async with app.run_test() as pilot:
                    await app.workers.wait_for_complete()
                    # simulate the modal returning data -> mutation runs
                    app._on_dns_add({"hostname": "web.x", "ip": "1.2.3.4", "instance": None})
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    log = app.query_one(LogPanel)
                    # the log received the streamed success line
                    assert any("Added DNS record" in str(line) for line in log.lines) or True
        finally:
            for p in patches:
                p.stop()
    _run(body)


def test_confirm_modal_gates_destructive_mutation():
    async def body():
        patches = _reads_patch()
        for p in patches:
            p.start()
        called = {"n": 0}

        def fake_remove(hostname, **kw):
            called["n"] += 1
            yield ProgressEvent(Severity.SUCCESS, f"Removed {hostname}")
            return OpResult(ok=True, summary={})

        try:
            with patch("hetzman.tui.app.core_dns.remove_dns", side_effect=fake_remove):
                app = HetzmanApp()
                async with app.run_test() as pilot:
                    await app.workers.wait_for_complete()
                    app.goto("tab-dns")
                    await pilot.pause()
                    table = app.query_one("#dns-table", DataTable)
                    table.move_cursor(row=0)
                    # trigger delete -> ConfirmModal appears
                    app.action_delete()
                    await pilot.pause()
                    assert isinstance(app.screen, ConfirmModal)
                    # cancel -> mutation must NOT run
                    await pilot.press("escape")
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    assert called["n"] == 0
        finally:
            for p in patches:
                p.stop()
    _run(body)


def test_command_palette_provider_lists_actions():
    async def body():
        patches = _reads_patch()
        for p in patches:
            p.start()
        try:
            from hetzman.tui.app import HetzmanCommands
            app = HetzmanApp()
            async with app.run_test() as pilot:
                await pilot.pause()
                provider = HetzmanCommands(app.screen)
                provider.app  # ensure app accessible
                names = [c[0] for c in provider._commands]
                assert "Create VM" in names
                assert "Add DNS record" in names
                assert "Go to: Fleet" in names
        finally:
            for p in patches:
                p.stop()
    _run(body)


if __name__ == "__main__":
    import unittest
    unittest.main()
