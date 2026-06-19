"""Unit tests for the console-free read layer ``hetzman.core.reads``.

All etcd / registry / config access is mocked; no real etcd or incus is
touched.  Tests assert the returned frozen models and, for the fleet view, the
exact ``degraded`` semantics ported from the CLI.  They also assert that no
returned text field carries Rich markup (a literal ``[``).
"""
from __future__ import annotations

import datetime
import unittest
from unittest import mock

from hetzman.core import reads
from hetzman.core.models import (
    DNSRecord,
    FleetStatus,
    IPAllocation,
    NodeInfo,
    PortForward,
    SystemStatus,
)


def _no_markup(*values) -> bool:
    """True when none of *values* (recursively over str/tuple) contains '['."""
    for v in values:
        if isinstance(v, str):
            if "[" in v:
                return False
        elif isinstance(v, (tuple, list, frozenset)):
            if not _no_markup(*v):
                return False
    return True


class TestListIps(unittest.TestCase):
    def test_filter_and_sort(self) -> None:
        pool = {
            "/hetzman/ip-pool/10.0.0.2": {"server": "srvB", "status": "available"},
            "/hetzman/ip-pool/10.0.0.1": {
                "server": "srvA", "status": "assigned", "assigned_to": "web",
            },
            "/hetzman/ip-pool/10.0.0.3": {"server": "srvA", "status": "available"},
        }
        with mock.patch.object(reads, "get_all_with_prefix", return_value=pool):
            all_ips = reads.list_ips()
        self.assertEqual([i.ip for i in all_ips], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertIsInstance(all_ips[0], IPAllocation)

        with mock.patch.object(reads, "get_all_with_prefix", return_value=pool):
            srva = reads.list_ips(server="srvA")
        self.assertEqual([i.ip for i in srva], ["10.0.0.1", "10.0.0.3"])

        with mock.patch.object(reads, "get_all_with_prefix", return_value=pool):
            avail = reads.list_ips(server="srvA", available_only=True)
        self.assertEqual([i.ip for i in avail], ["10.0.0.3"])
        self.assertTrue(all(_no_markup(i.ip, i.server, i.status) for i in srva))


class TestListDns(unittest.TestCase):
    def test_filter_and_sort(self) -> None:
        records = {
            "/hetzman/dns/b.example": {"ip": "1.1.1.2", "server": "srvB", "type": "A"},
            "/hetzman/dns/a.example": {
                "ip": "1.1.1.1", "server": "srvA", "auto": True,
            },
        }
        with mock.patch.object(reads, "get_all_with_prefix", return_value=records):
            out = reads.list_dns()
        self.assertEqual([d.hostname for d in out], ["a.example", "b.example"])
        self.assertIsInstance(out[0], DNSRecord)
        self.assertTrue(out[0].auto)

        with mock.patch.object(reads, "get_all_with_prefix", return_value=records):
            srvb = reads.list_dns(server="srvB")
        self.assertEqual([d.hostname for d in srvb], ["b.example"])


class TestListPorts(unittest.TestCase):
    def test_uses_current_server_and_filters(self) -> None:
        pf = {
            "/hetzman/port-forward/srv1/web-80-tcp": {
                "public_ip": "1.2.3.4", "public_port": 80,
                "private_ip": "10.0.0.5", "private_port": 8080,
                "protocol": "tcp", "instance_name": "web", "enabled": True,
            },
            "/hetzman/port-forward/srv1/db-5432-tcp": {
                "public_ip": "1.2.3.5", "public_port": 5432,
                "private_ip": "10.0.0.6", "private_port": 5432,
                "protocol": "tcp", "instance_name": "db", "enabled": False,
            },
        }
        settings = mock.Mock(current_server="srv1")
        with mock.patch.object(reads, "get_settings", return_value=settings), \
                mock.patch.object(reads, "get_all_with_prefix", return_value=pf) as gp:
            out = reads.list_ports()
        gp.assert_called_once_with("/hetzman/port-forward/srv1/")
        self.assertEqual([p.instance for p in out], ["db", "web"])
        self.assertIsInstance(out[0], PortForward)

        with mock.patch.object(reads, "get_settings", return_value=settings), \
                mock.patch.object(reads, "get_all_with_prefix", return_value=pf):
            web = reads.list_ports(instance="web")
        self.assertEqual([p.instance for p in web], ["web"])
        self.assertEqual(web[0].public_port, 80)


class TestListNodes(unittest.TestCase):
    def test_empty_registry(self) -> None:
        with mock.patch.object(reads, "load_registry", return_value={}):
            nodes, errors = reads.list_nodes()
        self.assertEqual(nodes, [])
        self.assertEqual(errors, ["registry is empty"])

    def test_nodes_sorted_and_validated(self) -> None:
        registry = {
            "b": {"name": "b", "vswitch_ip": "10.0.0.2", "etcd_name": "b"},
            "a": {"name": "a", "vswitch_ip": "10.0.0.1", "etcd_name": "a"},
        }
        with mock.patch.object(reads, "load_registry", return_value=registry), \
                mock.patch.object(reads, "validate_registry", return_value=["boom"]):
            nodes, errors = reads.list_nodes()
        self.assertEqual([n.name for n in nodes], ["a", "b"])
        self.assertIsInstance(nodes[0], NodeInfo)
        self.assertEqual(errors, ["boom"])


class TestSystemStatus(unittest.TestCase):
    def test_counts_and_members(self) -> None:
        def fake_prefix(prefix: str):
            if prefix == "/hetzman/dns/":
                return {
                    "/hetzman/dns/a": {"server": "me", "type": "A"},
                    "/hetzman/dns/b": {"server": "me", "type": "A"},
                    "/hetzman/dns/c": {"server": "other", "type": "CNAME"},
                }
            if prefix == "/hetzman/ip-pool/":
                return {
                    "/hetzman/ip-pool/1": {"server": "me", "status": "available"},
                    "/hetzman/ip-pool/2": {"server": "me", "status": "assigned"},
                    "/hetzman/ip-pool/3": {"server": "other", "status": "available"},
                }
            if prefix == "/hetzman/nat/me/":
                return {"x": {"enabled": True}, "y": {"enabled": False}}
            if prefix == "/hetzman/port-forward/me/":
                return {"p": {"enabled": True}}
            return {}

        settings = mock.Mock(current_server="me")
        client = mock.Mock(members=[mock.Mock(), mock.Mock(), mock.Mock()])
        with mock.patch.object(reads, "get_settings", return_value=settings), \
                mock.patch.object(reads, "get_all_with_prefix", side_effect=fake_prefix), \
                mock.patch.object(reads, "get_etcd_client", return_value=client):
            st = reads.get_system_status()
        self.assertIsInstance(st, SystemStatus)
        self.assertEqual(st.server, "me")
        self.assertEqual(st.dns_total, 3)
        self.assertEqual(st.dns_mine, 2)
        self.assertEqual(st.dns_types, {"A": 2})
        self.assertEqual(st.ips_available, 1)
        self.assertEqual(st.ips_total, 2)
        self.assertEqual(st.active_nat, 1)
        self.assertEqual(st.active_ports, 1)
        self.assertEqual(st.etcd_members, 3)

    def test_members_unknown_on_exception(self) -> None:
        settings = mock.Mock(current_server="me")
        with mock.patch.object(reads, "get_settings", return_value=settings), \
                mock.patch.object(reads, "get_all_with_prefix", return_value={}), \
                mock.patch.object(reads, "get_etcd_client", side_effect=RuntimeError("boom")):
            st = reads.get_system_status()
        self.assertIsNone(st.etcd_members)
        self.assertEqual(st.dns_total, 0)


def _beat(ts: str | None = "now", **over):
    if ts == "now":
        ts = datetime.datetime.now().isoformat(timespec="seconds")
    base = {
        "ts": ts,
        "hetzman_version": "1.0.0",
        "incus_version": "6.0",
        "checks": {
            "etcd": "ok", "dnsmasq": "ok",
            "disk_root_pct": 42, "btrfs_pool_pct": 7,
            "peers": {},
        },
        "endpoints_configured": 2,
        "node_sync": {"result": "applied"},
    }
    base.update(over)
    return base


def _registry(*names):
    return {n: {"name": n, "etcd_name": n, "vswitch_ip": f"10.0.0.{i}"}
            for i, n in enumerate(names, start=1)}


class _FleetHarness:
    """Context-manager style patcher for get_fleet_status dependencies."""

    def __init__(self, registry, health, member_names=("a", "b"), raise_members=False):
        self.registry = registry
        self.health = {f"/hetzman/health/{k}": v for k, v in health.items()}
        self.member_names = member_names
        self.raise_members = raise_members

    def run(self) -> FleetStatus:
        if self.raise_members:
            client = mock.Mock()
            type(client).members = mock.PropertyMock(side_effect=RuntimeError())
        else:
            client = mock.Mock(members=[mock.Mock(name=n) for n in self.member_names])
            # mock.Mock(name=...) sets the mock's repr name, NOT a .name attr;
            # set .name explicitly.
            client.members = []
            for n in self.member_names:
                m = mock.Mock()
                m.name = n
                client.members.append(m)
        with mock.patch.object(reads, "load_registry", return_value=self.registry), \
                mock.patch.object(reads, "get_all_with_prefix", return_value=self.health), \
                mock.patch.object(reads, "get_etcd_client", return_value=client):
            return reads.get_fleet_status()


class TestFleetStatus(unittest.TestCase):
    def test_healthy_not_degraded(self) -> None:
        registry = _registry("a", "b")
        health = {"a": _beat(), "b": _beat()}
        fs = _FleetHarness(registry, health, member_names=("a", "b")).run()
        self.assertIsInstance(fs, FleetStatus)
        self.assertFalse(fs.degraded)
        self.assertEqual(fs.registered_node_count, 2)
        self.assertEqual(fs.member_names, frozenset({"a", "b"}))
        self.assertEqual([n.name for n in fs.nodes], ["a", "b"])
        a = fs.nodes[0]
        self.assertTrue(a.alive)
        self.assertEqual(a.checks_bad, ())
        self.assertEqual(a.peers_bad, ())
        self.assertEqual(a.disk_root_pct, 42)
        self.assertEqual(a.pool_pct, 7)
        self.assertEqual(a.sync_result, "applied")
        self.assertEqual(a.endpoints_configured, 2)
        self.assertTrue(a.endpoint_count_ok)
        self.assertTrue(a.etcd_member_present)
        self.assertIsInstance(a.heartbeat_age_s, int)

    def test_no_heartbeat_is_down_and_degraded(self) -> None:
        registry = _registry("a", "b")
        health = {"a": _beat()}  # b missing
        fs = _FleetHarness(registry, health, member_names=("a", "b")).run()
        self.assertTrue(fs.degraded)
        b = next(n for n in fs.nodes if n.name == "b")
        self.assertFalse(b.alive)
        self.assertIsNone(b.heartbeat_age_s)
        self.assertIsNone(b.endpoints_configured)
        self.assertFalse(b.etcd_member_present)

    def test_bad_check_degrades(self) -> None:
        registry = _registry("a", "b")
        bad = _beat()
        bad["checks"] = {**bad["checks"], "dnsmasq": "fail"}
        health = {"a": bad, "b": _beat()}
        fs = _FleetHarness(registry, health, member_names=("a", "b")).run()
        self.assertTrue(fs.degraded)
        a = next(n for n in fs.nodes if n.name == "a")
        self.assertIn("dnsmasq", a.checks_bad)

    def test_bad_peer_degrades(self) -> None:
        registry = _registry("a", "b")
        beat_a = _beat()
        beat_a["checks"] = {**beat_a["checks"], "peers": {"b": "fail"}}
        health = {"a": beat_a, "b": _beat()}
        fs = _FleetHarness(registry, health, member_names=("a", "b")).run()
        self.assertTrue(fs.degraded)
        a = next(n for n in fs.nodes if n.name == "a")
        self.assertEqual(a.peers_bad, ("b",))

    def test_endpoints_mismatch_degrades(self) -> None:
        registry = _registry("a", "b")  # len 2
        beat = _beat(endpoints_configured=1)  # != 2
        health = {"a": beat, "b": _beat()}
        fs = _FleetHarness(registry, health, member_names=("a", "b")).run()
        self.assertTrue(fs.degraded)
        a = next(n for n in fs.nodes if n.name == "a")
        self.assertFalse(a.endpoint_count_ok)
        self.assertEqual(a.endpoints_configured, 1)
        # The CLI renders (endpoints=X!=Y); X and Y must be available.
        self.assertEqual(fs.registered_node_count, 2)

    def test_registered_node_missing_from_members_degrades(self) -> None:
        registry = _registry("a", "b")
        health = {"a": _beat(), "b": _beat()}
        # member list lacks "b" -> b's etcd_name absent from members
        fs = _FleetHarness(registry, health, member_names=("a",)).run()
        self.assertTrue(fs.degraded)
        b = next(n for n in fs.nodes if n.name == "b")
        self.assertFalse(b.etcd_member_present)
        a = next(n for n in fs.nodes if n.name == "a")
        self.assertTrue(a.etcd_member_present)

    def test_members_unknown_does_not_degrade_on_membership(self) -> None:
        # When members can't be listed, the etcd-membership rule must NOT fire.
        registry = _registry("a")
        health = {"a": _beat(endpoints_configured=1)}  # len(registry)==1 -> ok
        fs = _FleetHarness(registry, health, raise_members=True).run()
        self.assertEqual(fs.member_names, frozenset())
        self.assertFalse(fs.degraded)
        a = fs.nodes[0]
        self.assertFalse(a.etcd_member_present)

    def test_no_rich_markup_anywhere(self) -> None:
        registry = _registry("a", "b")
        bad = _beat(endpoints_configured=1)
        bad["checks"] = {**bad["checks"], "dnsmasq": "fail", "peers": {"b": "fail"}}
        health = {"a": bad}  # b down
        fs = _FleetHarness(registry, health, member_names=("a",)).run()
        self.assertTrue(fs.degraded)
        for n in fs.nodes:
            self.assertTrue(
                _no_markup(
                    n.name, n.hetzman_version, n.incus_version, n.sync_result,
                    n.checks_bad, n.peers_bad,
                ),
                msg=f"Rich markup leaked into {n!r}",
            )
        self.assertTrue(_no_markup(*fs.member_names))


if __name__ == "__main__":
    unittest.main()
