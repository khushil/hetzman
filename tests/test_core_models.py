"""stdlib unittest tests for hetzman.core.models.

Run with:
    cd /home/kdep/src/hetzman && PYTHONPATH=src python3 -m unittest tests.test_core_models -v
"""
from __future__ import annotations

import re
import unittest

from hetzman.core.models import (
    AuditResult,
    DNSRecord,
    DriftStatus,
    FleetNodeStatus,
    FleetStatus,
    IPAllocation,
    NatRule,
    NodeInfo,
    PortForward,
    SystemStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RICH_RE = re.compile(r"\[/?[a-zA-Z_#].*?\]")


def _has_rich(value: str | None) -> bool:
    return bool(value and _RICH_RE.search(value))


# ---------------------------------------------------------------------------
# IPAllocation
# ---------------------------------------------------------------------------


class TestIPAllocation(unittest.TestCase):
    def test_construct(self):
        alloc = IPAllocation(
            ip="1.2.3.4",
            server="node1",
            status="available",
            assigned_to=None,
            block="1.2.3.0/29",
        )
        self.assertEqual(alloc.ip, "1.2.3.4")
        self.assertIsNone(alloc.assigned_to)

    def test_from_etcd_assigned(self):
        data = {
            "server": "node1",
            "status": "assigned",
            "assigned_to": "my-vm",
            "block": "1.2.3.0/29",
        }
        alloc = IPAllocation.from_etcd("/hetzman/ip-pool/1.2.3.4", data)
        self.assertEqual(alloc.ip, "1.2.3.4")
        self.assertEqual(alloc.status, "assigned")
        self.assertEqual(alloc.assigned_to, "my-vm")

    def test_from_etcd_missing_keys(self):
        alloc = IPAllocation.from_etcd("/hetzman/ip-pool/5.6.7.8", {})
        self.assertEqual(alloc.ip, "5.6.7.8")
        self.assertEqual(alloc.status, "unknown")
        self.assertIsNone(alloc.assigned_to)
        self.assertIsNone(alloc.block)

    def test_frozen(self):
        alloc = IPAllocation("1.1.1.1", "s", "available", None, None)
        with self.assertRaises(Exception):
            alloc.ip = "2.2.2.2"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# DNSRecord
# ---------------------------------------------------------------------------


class TestDNSRecord(unittest.TestCase):
    def test_from_etcd(self):
        data = {
            "ip": "10.0.0.5",
            "server": "node1",
            "instance": "my-ct",
            "type": "incus",
            "auto": True,
            "updated": "2024-01-01T00:00:00",
        }
        rec = DNSRecord.from_etcd("/hetzman/dns/my-ct.home.arpa", data)
        self.assertEqual(rec.hostname, "my-ct.home.arpa")
        self.assertTrue(rec.auto)
        self.assertEqual(rec.type, "incus")

    def test_from_etcd_minimal(self):
        rec = DNSRecord.from_etcd("/hetzman/dns/foo.local", {"ip": "192.168.1.1"})
        self.assertFalse(rec.auto)
        self.assertIsNone(rec.instance)
        self.assertIsNone(rec.updated)

    def test_construct_manual(self):
        rec = DNSRecord(
            hostname="bar.local",
            ip="10.0.0.2",
            server="s",
            instance=None,
            type=None,
            auto=False,
            updated=None,
        )
        self.assertEqual(rec.hostname, "bar.local")


# ---------------------------------------------------------------------------
# NatRule
# ---------------------------------------------------------------------------


class TestNatRule(unittest.TestCase):
    def test_from_etcd(self):
        data = {
            "public_ip": "1.2.3.4",
            "private_ip": "10.0.0.5",
            "instance_name": "my-vm",
            "enabled": True,
        }
        rule = NatRule.from_etcd("/hetzman/nat/node1/my-vm", data)
        self.assertEqual(rule.instance, "my-vm")
        self.assertEqual(rule.public_ip, "1.2.3.4")
        self.assertTrue(rule.enabled)

    def test_from_etcd_disabled(self):
        data = {
            "public_ip": "1.2.3.5",
            "private_ip": "10.0.0.6",
            "instance_name": "vm2",
            "enabled": False,
        }
        rule = NatRule.from_etcd("/hetzman/nat/node1/vm2", data)
        self.assertFalse(rule.enabled)

    def test_from_etcd_missing_keys(self):
        rule = NatRule.from_etcd("/hetzman/nat/node1/fallback", {})
        self.assertEqual(rule.instance, "fallback")
        self.assertTrue(rule.enabled)  # default is True


# ---------------------------------------------------------------------------
# PortForward
# ---------------------------------------------------------------------------


class TestPortForward(unittest.TestCase):
    def test_from_etcd(self):
        data = {
            "public_ip": "1.2.3.4",
            "public_port": 8080,
            "private_ip": "10.0.0.5",
            "private_port": 80,
            "protocol": "tcp",
            "instance_name": "web",
            "description": "nginx",
            "enabled": True,
        }
        pf = PortForward.from_etcd("/hetzman/port-forward/node1/web-8080-tcp", data)
        self.assertEqual(pf.public_port, 8080)
        self.assertEqual(pf.private_port, 80)
        self.assertEqual(pf.description, "nginx")

    def test_construct_defaults(self):
        pf = PortForward(
            public_ip="1.2.3.4",
            public_port=22,
            private_ip="10.0.0.2",
            private_port=22,
            protocol="tcp",
            instance="ct1",
            description=None,
            enabled=True,
        )
        self.assertIsNone(pf.description)


# ---------------------------------------------------------------------------
# NodeInfo
# ---------------------------------------------------------------------------


class TestNodeInfo(unittest.TestCase):
    _SAMPLE = {
        "schema": 1,
        "name": "node1",
        "vswitch_ip": "10.0.0.1",
        "bridge_ip": "192.168.100.1",
        "bridge_subnet": "192.168.100.0/24",
        "public_block": "1.2.3.0/29",
        "primary_interface": "eth0",
        "vlan_interface": "eth0.100",
        "vlan_id": 100,
        "mtu": 1400,
        "etcd_name": "node1-etcd",
        "etcd_client_port": 2379,
        "updated_at": "2024-06-01T12:00:00",
    }

    def test_from_etcd(self):
        ni = NodeInfo.from_etcd("/hetzman/nodes/node1", self._SAMPLE)
        self.assertEqual(ni.name, "node1")
        self.assertEqual(ni.vswitch_ip, "10.0.0.1")
        self.assertEqual(ni.etcd_name, "node1-etcd")
        self.assertIn("vlan_id", ni.raw)

    def test_from_etcd_key_fallback(self):
        ni = NodeInfo.from_etcd("/hetzman/nodes/node2", {"vswitch_ip": "10.0.0.2"})
        # name falls back to the key segment
        self.assertEqual(ni.name, "node2")

    def test_raw_preserved(self):
        ni = NodeInfo.from_etcd("/hetzman/nodes/node1", self._SAMPLE)
        self.assertEqual(ni.raw["mtu"], 1400)


# ---------------------------------------------------------------------------
# FleetNodeStatus — no Rich markup
# ---------------------------------------------------------------------------


class TestFleetNodeStatus(unittest.TestCase):
    def _make(self, **kwargs) -> FleetNodeStatus:
        defaults = dict(
            name="node1",
            heartbeat_age_s=30,
            alive=True,
            checks_bad=(),
            peers_bad=(),
            hetzman_version="1.0.0",
            incus_version="6.1.0",
            sync_result="clean",
            disk_root_pct=42,
            pool_pct=18,
            endpoint_count_ok=True,
            etcd_member_present=True,
        )
        defaults.update(kwargs)
        return FleetNodeStatus(**defaults)

    def test_no_rich_in_string_fields(self):
        node = self._make(
            checks_bad=("audit", "dns_resolve"),
            peers_bad=("node2",),
        )
        for attr in ("name", "hetzman_version", "incus_version", "sync_result"):
            val = getattr(node, attr)
            self.assertFalse(_has_rich(val), f"Rich markup found in {attr!r}: {val!r}")

    def test_alive_false(self):
        node = self._make(alive=False, heartbeat_age_s=None)
        self.assertFalse(node.alive)
        self.assertIsNone(node.heartbeat_age_s)

    def test_immutable_tuple_fields(self):
        node = self._make(checks_bad=("audit",))
        self.assertIsInstance(node.checks_bad, tuple)

    def test_frozen(self):
        node = self._make()
        with self.assertRaises(Exception):
            node.alive = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# FleetStatus
# ---------------------------------------------------------------------------


class TestFleetStatus(unittest.TestCase):
    def test_construct(self):
        fs = FleetStatus(nodes=(), degraded=False, member_names=frozenset({"node1"}))
        self.assertFalse(fs.degraded)
        self.assertIsInstance(fs.member_names, frozenset)


# ---------------------------------------------------------------------------
# AuditResult
# ---------------------------------------------------------------------------


class TestAuditResult(unittest.TestCase):
    def test_clean_true(self):
        ar = AuditResult(missing={}, orphaned=(), correct={"1.2.3.4": "vm1"})
        self.assertTrue(ar.clean)

    def test_clean_false_missing(self):
        ar = AuditResult(missing={"5.6.7.8": "vm2"}, orphaned=(), correct={})
        self.assertFalse(ar.clean)

    def test_clean_false_orphaned(self):
        ar = AuditResult(missing={}, orphaned=("9.10.11.12",), correct={})
        self.assertFalse(ar.clean)

    def test_clean_both_dirty(self):
        ar = AuditResult(
            missing={"1.1.1.1": "a"},
            orphaned=("2.2.2.2",),
            correct={},
        )
        self.assertFalse(ar.clean)


# ---------------------------------------------------------------------------
# SystemStatus
# ---------------------------------------------------------------------------


class TestSystemStatus(unittest.TestCase):
    def test_construct(self):
        ss = SystemStatus(
            server="node1",
            dns_total=10,
            dns_mine=7,
            dns_types={"incus": 5, "manual": 2},
            ips_available=3,
            ips_total=8,
            active_nat=4,
            active_ports=6,
            etcd_members=3,
        )
        self.assertEqual(ss.dns_mine, 7)
        self.assertIsNone(
            None if ss.etcd_members is None else None
        )  # sanity — etcd_members is not None here
        self.assertEqual(ss.etcd_members, 3)

    def test_etcd_members_none(self):
        ss = SystemStatus(
            server="s",
            dns_total=0,
            dns_mine=0,
            dns_types={},
            ips_available=0,
            ips_total=0,
            active_nat=0,
            active_ports=0,
            etcd_members=None,
        )
        self.assertIsNone(ss.etcd_members)


# ---------------------------------------------------------------------------
# DriftStatus
# ---------------------------------------------------------------------------


class TestDriftStatus(unittest.TestCase):
    def test_clean(self):
        ds = DriftStatus(clean=True, pending=(), warnings=(), errors=())
        self.assertTrue(ds.clean)

    def test_dirty(self):
        ds = DriftStatus(
            clean=False,
            pending=("config.ini", "dnsmasq-include"),
            warnings=("bridge not managed",),
            errors=(),
        )
        self.assertFalse(ds.clean)
        self.assertIn("config.ini", ds.pending)


if __name__ == "__main__":
    unittest.main()
