"""Headless tests for the Textual control center via App.run_test().

These run without a TTY and without etcd: core.reads is patched. Tests are
plain functions wrapping asyncio.run so they execute under pytest without
needing pytest-asyncio.
"""
import asyncio
from unittest.mock import patch

from hetzman.core.errors import EtcdUnavailable
from hetzman.core.models import FleetNodeStatus, FleetStatus, SystemStatus
from hetzman.tui.app import HetzmanApp
from hetzman.tui.widgets import Banner, LogPanel
from textual.widgets import DataTable, Static


def _run(coro_factory):
    asyncio.run(coro_factory())


def _healthy_fleet():
    node = FleetNodeStatus(
        name="htz-hel1-dc12-bm-01",
        alive=True,
        heartbeat_age_s=12,
        checks_bad=(),
        peers_bad=(),
        hetzman_version="3.2.0",
        incus_version="6.0",
        endpoints_configured=2,
        sync_result="ok",
        disk_root_pct=41,
        pool_pct=12,
        endpoint_count_ok=True,
        etcd_member_present=True,
    )
    return FleetStatus(
        nodes=(node,),
        degraded=False,
        member_names=frozenset({"htz-hel1-dc12-bm-01"}),
        registered_node_count=2,
    )


def _degraded_fleet():
    down = FleetNodeStatus(
        name="htz-hel1-dc12-bm-02",
        alive=False,
        heartbeat_age_s=None,
        checks_bad=(),
        peers_bad=(),
        hetzman_version="?",
        incus_version="?",
        endpoints_configured=None,
        sync_result="-",
        disk_root_pct=None,
        pool_pct=None,
        endpoint_count_ok=False,
        etcd_member_present=False,
    )
    return FleetStatus(
        nodes=(down,),
        degraded=True,
        member_names=frozenset(),
        registered_node_count=2,
    )


def _system():
    return SystemStatus(
        server="htz-hel1-dc12-bm-01",
        dns_total=10,
        dns_mine=7,
        dns_types={"A": 5, "CNAME": 2},
        ips_available=3,
        ips_total=8,
        active_nat=4,
        active_ports=2,
        etcd_members=3,
    )


def test_dashboard_renders_system_and_fleet():
    async def body():
        with patch("hetzman.core.reads.get_fleet_status", return_value=_healthy_fleet()), \
             patch("hetzman.core.reads.get_system_status", return_value=_system()):
            app = HetzmanApp()
            async with app.run_test() as pilot:
                await pilot.pause()
                # workers are threads; let them complete and post back
                await app.workers.wait_for_complete()
                await pilot.pause()

                card = app.query_one("#system-card", Static)
                rendered = card.renderable.plain if hasattr(card.renderable, "plain") else str(card.renderable)
                assert "HetzMan Status" in rendered
                assert "htz-hel1-dc12-bm-01" in rendered

                table = app.query_one("#fleet-table", DataTable)
                assert table.row_count == 1

                summary = app.query_one("#fleet-summary", Static)
                assert "healthy" in summary.renderable.plain.lower()

                # Banner stays hidden on success.
                assert not app.query_one(Banner).has_class("visible")
    _run(body)


def test_degraded_fleet_marks_down_node():
    async def body():
        with patch("hetzman.core.reads.get_fleet_status", return_value=_degraded_fleet()), \
             patch("hetzman.core.reads.get_system_status", return_value=_system()):
            app = HetzmanApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                await pilot.pause()
                table = app.query_one("#fleet-table", DataTable)
                assert table.row_count == 1
                summary = app.query_one("#fleet-summary", Static)
                assert "degraded" in summary.renderable.plain.lower()
    _run(body)


def test_etcd_unavailable_shows_banner_not_crash():
    async def body():
        boom = EtcdUnavailable("Could not connect to etcd cluster")
        with patch("hetzman.core.reads.get_fleet_status", side_effect=boom), \
             patch("hetzman.core.reads.get_system_status", side_effect=boom):
            app = HetzmanApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                await pilot.pause()
                banner = app.query_one(Banner)
                assert banner.has_class("visible")
                assert "etcd unavailable" in banner.renderable.plain.lower()
                # The app is still alive and the fleet table simply has no rows.
                assert app.query_one("#fleet-table", DataTable).row_count == 0
    _run(body)


def test_refresh_action_reloads():
    async def body():
        with patch("hetzman.core.reads.get_fleet_status", return_value=_healthy_fleet()) as gf, \
             patch("hetzman.core.reads.get_system_status", return_value=_system()):
            app = HetzmanApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                await pilot.pause()
                calls_before = gf.call_count
                await pilot.press("r")
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert gf.call_count > calls_before
    _run(body)
