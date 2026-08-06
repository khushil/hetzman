"""SAFETY-CRITICAL tests for core/nodes.py.

The quorum/removal safety math (assess_removal) is exercised exhaustively at the
n=2 / n=3->2 / n=4->3 / n=5->4 boundaries in isolation from etcd I/O. The live
probe paths (_probe_member / _member_views), member mapping, and the
register/remove generators are covered with etcd mocked.
"""
import unittest
from unittest import mock

from hetzman.core import nodes
from hetzman.core.errors import CoreError, NotFoundError, ValidationError
from hetzman.core.nodes import (
    MemberView,
    assess_addition,
    assess_removal,
    map_to_member,
)


def _mv(id, name="m", healthy=True, leader=False, peer="10.0.0.1"):
    return MemberView(id=id, name=name, peer_hosts=(peer,), healthy=healthy, is_leader=leader)


def _drain(gen):
    events = []
    try:
        while True:
            events.append(next(gen))
    except StopIteration as stop:
        return events, stop.value


class AssessAdditionTests(unittest.TestCase):
    """Growing the cluster raises quorum immediately while the newcomer is not
    yet healthy, so the margin must come from the existing members."""

    def test_empty_membership_refused(self):
        with self.assertRaises(CoreError):
            assess_addition([])

    def test_unstarted_member_refused(self):
        # A joining/unstarted member means the topology is mid-transition.
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, ""), _mv(4, "d")]
        with self.assertRaises(CoreError):
            assess_addition(members)

    def test_n4_to_5_requires_all_four_healthy(self):
        # 4->5: quorum after is 3. All 4 healthy -> margin 1 -> safe.
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c"), _mv(4, "d", leader=True)]
        assess_addition(members)

    def test_n4_to_5_refused_at_three_healthy(self):
        # The case a bare quorum check would wrongly allow: 3 healthy of 4 IS a
        # quorum, but the resulting 5-member cluster has quorum 3 and exactly 3
        # healthy — zero margin, one more fault stops writes.
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c", healthy=False), _mv(4, "d")]
        with self.assertRaises(CoreError) as ctx:
            assess_addition(members)
        self.assertIn("margin", str(ctx.exception))

    def test_n3_to_4_requires_all_three_healthy(self):
        # 3->4: quorum after is 3, so all 3 healthy gives zero margin -> refused.
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c")]
        with self.assertRaises(CoreError):
            assess_addition(members)

    def test_n5_to_6_allows_one_unhealthy(self):
        # 5->6: quorum after is 4, so 5 healthy gives margin 1 -> safe.
        members = [_mv(i, f"m{i}") for i in range(1, 6)]
        assess_addition(members)
        # ...but 4 healthy of 5 lands exactly at quorum -> refused.
        degraded = [_mv(1, "a", healthy=False)] + [_mv(i, f"m{i}") for i in range(2, 6)]
        with self.assertRaises(CoreError):
            assess_addition(degraded)


class AssessRemovalTests(unittest.TestCase):
    """The pure safety decision — fail-closed, requires a spare healthy voter."""

    def test_n2_always_refused(self):
        with self.assertRaises(CoreError):
            assess_removal([_mv(1), _mv(2)], 1)

    def test_n3_to_2_refused_no_margin(self):
        # 3 all healthy: removing one lands at 2 voters (quorum 2) with no spare.
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c", leader=True)]
        with self.assertRaises(CoreError):
            assess_removal(members, 1)

    def test_n4_all_healthy_remove_nonleader_is_safe(self):
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c"), _mv(4, "d", leader=True)]
        assess_removal(members, 1)  # remaining 3, quorum 2, healthy_after 3 > 2 -> safe

    def test_n4_refuses_when_two_others_unhealthy(self):
        members = [
            _mv(1, "a"),
            _mv(2, "b", healthy=False),
            _mv(3, "c", healthy=False),
            _mv(4, "d", leader=True),
        ]
        with self.assertRaises(CoreError):
            assess_removal(members, 1)  # healthy_after = {4} = 1 <= quorum 2

    def test_n5_remove_with_margin_safe(self):
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c"), _mv(4, "d"), _mv(5, "e", leader=True)]
        assess_removal(members, 1)  # remaining 4, quorum 3, healthy_after 4 > 3 -> safe

    def test_refuses_removing_a_healthy_leader(self):
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c"), _mv(4, "d", leader=True)]
        with self.assertRaises(CoreError):
            assess_removal(members, 4)

    def test_dead_leader_is_removable(self):
        # target is still reported leader but is DOWN — must be removable.
        members = [
            _mv(1, "a", leader=True, healthy=False),  # dead old leader = target
            _mv(2, "b"), _mv(3, "c"), _mv(4, "d"),
        ]
        assess_removal(members, 1)  # remaining 3 healthy, quorum 2, 3 > 2 -> safe

    def test_refuses_while_an_unstarted_member_exists(self):
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, ""), _mv(4, "d", leader=True), _mv(5, "e")]
        with self.assertRaises(CoreError):
            assess_removal(members, 1)

    def test_unknown_target_refused(self):
        members = [_mv(1, "a"), _mv(2, "b"), _mv(3, "c"), _mv(4, "d", leader=True)]
        with self.assertRaises(CoreError):
            assess_removal(members, 999)


class ProbeAndViewsTests(unittest.TestCase):
    """The live probe paths the mocks used to hide."""

    def _raw_member(self, id, name, urls):
        m = mock.Mock()
        m.id = id
        m.name = name
        m.peer_urls = [f"https://{u.split('//')[1].split(':')[0]}:2380" for u in urls]
        m.client_urls = urls
        return m

    def _status(self, leader_id):
        st = mock.Mock()
        st.leader = mock.Mock(id=leader_id) if leader_id is not None else None
        return st

    @mock.patch("hetzman.core.nodes._client_for")
    @mock.patch("hetzman.core.nodes.get_etcd_client")
    def test_responsive_voter_mid_election_is_healthy(self, gc, cf):
        # every member responds, but leader is None (mid-election) -> all HEALTHY
        raw = [self._raw_member(i, f"m{i}", [f"https://10.0.0.{i}:2379"]) for i in (1, 2, 3)]
        gc.return_value.members = raw
        client = mock.Mock()
        client.status.return_value = self._status(None)  # no leader yet
        cf.return_value = client
        views = nodes._member_views()
        self.assertTrue(all(v.healthy for v in views))     # liveness != leader-present
        self.assertFalse(any(v.is_leader for v in views))  # nobody flagged leader

    @mock.patch("hetzman.core.nodes._client_for")
    @mock.patch("hetzman.core.nodes.get_etcd_client")
    def test_dead_member_is_unhealthy_not_hang(self, gc, cf):
        raw = [self._raw_member(i, f"m{i}", [f"https://10.0.0.{i}:2379"]) for i in (1, 2, 3)]
        gc.return_value.members = raw

        def client_for(host, port):
            c = mock.Mock()
            if host == "10.0.0.2":
                c.status.side_effect = Exception("timeout")  # dead member
            else:
                c.status.return_value = self._status(1)  # leader = 1
            return c
        cf.side_effect = client_for
        views = {v.id: v for v in nodes._member_views()}
        self.assertFalse(views[2].healthy)   # dead -> unhealthy (would have hung w/o timeout)
        self.assertTrue(views[1].healthy and views[3].healthy)
        self.assertTrue(views[1].is_leader)  # majority (2 of 2 responders) agree leader=1


class CaughtUpTests(unittest.TestCase):
    """member_caught_up gates the rolling reboot — a member answering Status while
    still replaying its raft log must NOT count as caught up."""

    def _m(self, id, healthy=True, leader=False, raft=100):
        return MemberView(id=id, name=f"m{id}", peer_hosts=("10.0.0.1",),
                          healthy=healthy, is_leader=leader, raft_index=raft)

    def test_caught_up_within_lag(self):
        members = [self._m(1, raft=100), self._m(2, leader=True, raft=110), self._m(3, raft=109)]
        self.assertTrue(nodes.member_caught_up(1, members))

    def test_lagging_member_not_caught_up(self):
        members = [self._m(1, raft=10), self._m(2, leader=True, raft=5000), self._m(3, raft=4999)]
        self.assertFalse(nodes.member_caught_up(1, members))

    def test_no_leader_means_not_caught_up(self):
        members = [self._m(1, raft=100), self._m(2, raft=110), self._m(3, raft=109)]  # none leader
        self.assertFalse(nodes.member_caught_up(1, members))

    def test_unhealthy_or_no_raft_index_not_caught_up(self):
        members = [self._m(1, healthy=False, raft=100), self._m(2, leader=True, raft=110)]
        self.assertFalse(nodes.member_caught_up(1, members))
        members = [self._m(1, raft=None), self._m(2, leader=True, raft=110)]
        self.assertFalse(nodes.member_caught_up(1, members))


class MapToMemberTests(unittest.TestCase):
    def test_match_by_etcd_name(self):
        members = [_mv(1, "etcd-a", peer="10.0.0.1"), _mv(2, "etcd-b", peer="10.0.0.2")]
        m = map_to_member("nodeB", {"etcd_name": "etcd-b", "vswitch_ip": "10.0.0.2"}, members)
        self.assertEqual(m.id, 2)

    def test_fallback_by_vswitch(self):
        members = [_mv(1, "x", peer="10.0.0.1"), _mv(2, "y", peer="10.0.0.2")]
        m = map_to_member("nodeB", {"etcd_name": "nomatch", "vswitch_ip": "10.0.0.2"}, members)
        self.assertEqual(m.id, 2)

    def test_ambiguous_name_refused(self):
        members = [_mv(1, "dup", peer="10.0.0.1"), _mv(2, "dup", peer="10.0.0.2")]
        with self.assertRaises(CoreError):
            map_to_member("n", {"etcd_name": "dup", "vswitch_ip": "9.9.9.9"}, members)

    def test_try_map_returns_none_when_absent_but_raises_on_ambiguous(self):
        members = [_mv(1, "a", peer="10.0.0.1")]
        self.assertIsNone(nodes._try_map("n", {"etcd_name": "z", "vswitch_ip": "9.9"}, members))
        dup = [_mv(1, "dup", peer="10.0.0.1"), _mv(2, "dup", peer="10.0.0.2")]
        with self.assertRaises(CoreError):
            nodes._try_map("n", {"etcd_name": "dup", "vswitch_ip": "9.9"}, dup)


class RegisterNodeTests(unittest.TestCase):
    @mock.patch("hetzman.core.nodes.etcd_kv.put_key", return_value=True)
    @mock.patch("hetzman.core.nodes.validate_registry", return_value=[])
    @mock.patch("hetzman.core.nodes.load_registry", return_value={})
    def test_register_writes_validated_entry(self, lr, vr, put):
        events, result = _drain(nodes.register_node(
            name="n1", vswitch_ip="10.0.0.9", bridge_ip="10.100.9.1",
            public_block="203.0.113.0/29", primary_interface="enp5s0",
            vlan_interface="enp5s0.4000", vlan_id=4000, mtu=1400, etcd_name="etcd-n1",
        ))
        self.assertTrue(result.ok)
        self.assertEqual(put.call_args[0][0], "/hetzman/nodes/n1")

    @mock.patch("hetzman.core.nodes.validate_registry", return_value=["duplicate vswitch_ip"])
    @mock.patch("hetzman.core.nodes.load_registry", return_value={})
    def test_register_refuses_invalid_registry(self, lr, vr):
        with self.assertRaises(ValidationError):
            _drain(nodes.register_node(
                name="n1", vswitch_ip="10.0.0.9", bridge_ip="10.100.9.1",
                public_block="203.0.113.0/29", primary_interface="enp5s0",
                vlan_interface="enp5s0.4000", vlan_id=4000, mtu=1400, etcd_name="etcd-n1",
            ))


class RemoveNodeTests(unittest.TestCase):
    @mock.patch("hetzman.core.nodes.get_settings")
    @mock.patch("hetzman.core.nodes.load_registry", return_value={})
    def test_not_in_registry(self, lr, gs):
        gs.return_value = mock.Mock(current_server="me")
        with self.assertRaises(NotFoundError):
            _drain(nodes.remove_node("ghost"))

    @mock.patch("hetzman.core.nodes.get_settings")
    @mock.patch("hetzman.core.nodes.load_registry", return_value={"me": {}})
    def test_refuses_self(self, lr, gs):
        gs.return_value = mock.Mock(current_server="me")
        with self.assertRaises(ValidationError):
            _drain(nodes.remove_node("me"))

    @mock.patch("hetzman.core.nodes._references", return_value=["NAT rules"])
    @mock.patch("hetzman.core.nodes.get_settings")
    @mock.patch("hetzman.core.nodes.load_registry", return_value={"n2": {}})
    def test_refuses_referenced_without_force(self, lr, gs, refs):
        gs.return_value = mock.Mock(current_server="me")
        with self.assertRaises(ValidationError):
            _drain(nodes.remove_node("n2"))

    @mock.patch("hetzman.core.nodes.etcd_kv.delete_key", return_value=True)
    @mock.patch("hetzman.core.nodes._references", return_value=[])
    @mock.patch("hetzman.core.nodes.get_settings")
    @mock.patch("hetzman.core.nodes.load_registry", return_value={"n2": {}})
    def test_registry_only_remove(self, lr, gs, refs, dk):
        gs.return_value = mock.Mock(current_server="me")
        events, result = _drain(nodes.remove_node("n2"))
        self.assertTrue(result.ok)
        self.assertFalse(result.summary["member_removed"])
        dk.assert_called_once_with("/hetzman/nodes/n2")

    @mock.patch("hetzman.core.nodes._remove_member_via_other")
    @mock.patch("hetzman.core.nodes.etcd_kv.delete_key", return_value=True)
    @mock.patch("hetzman.core.nodes._member_views")
    @mock.patch("hetzman.core.nodes._references", return_value=[])
    @mock.patch("hetzman.core.nodes.get_settings")
    @mock.patch("hetzman.core.nodes.load_registry",
                return_value={"n2": {"etcd_name": "etcd-b", "vswitch_ip": "10.0.0.2"}})
    def test_member_remove_safe_path(self, lr, gs, refs, mv, dk, rm):
        gs.return_value = mock.Mock(current_server="me")
        # 4 healthy members so the margin permits removal
        mv.return_value = [_mv(1, "etcd-a"), _mv(2, "etcd-b", peer="10.0.0.2"),
                           _mv(3, "etcd-c"), _mv(4, "etcd-d", leader=True)]
        events, result = _drain(nodes.remove_node("n2", remove_member=True))
        self.assertTrue(result.ok and result.summary["member_removed"])
        self.assertEqual(rm.call_args[0][0].id, 2)  # removed via-other for member id 2

    @mock.patch("hetzman.core.nodes._remove_member_via_other")
    @mock.patch("hetzman.core.nodes._member_views")
    @mock.patch("hetzman.core.nodes._references", return_value=[])
    @mock.patch("hetzman.core.nodes.get_settings")
    @mock.patch("hetzman.core.nodes.load_registry",
                return_value={"n2": {"etcd_name": "etcd-b", "vswitch_ip": "10.0.0.2"}})
    def test_member_remove_refused_breaks_quorum(self, lr, gs, refs, mv, rm):
        gs.return_value = mock.Mock(current_server="me")
        mv.return_value = [_mv(1, "etcd-a", healthy=False),
                           _mv(2, "etcd-b", healthy=True, peer="10.0.0.2"),
                           _mv(3, "etcd-c", healthy=True, leader=True)]
        with self.assertRaises(CoreError):
            _drain(nodes.remove_node("n2", remove_member=True))
        rm.assert_not_called()  # never touched the cluster

    @mock.patch("hetzman.core.nodes._remove_member_via_other")
    @mock.patch("hetzman.core.nodes.etcd_kv.delete_key", return_value=True)
    @mock.patch("hetzman.core.nodes._member_views", return_value=[_mv(1, "etcd-a"), _mv(2, "etcd-b")])
    @mock.patch("hetzman.core.nodes._references", return_value=[])
    @mock.patch("hetzman.core.nodes.get_settings")
    @mock.patch("hetzman.core.nodes.load_registry",
                return_value={"n2": {"etcd_name": "gone", "vswitch_ip": "10.9.9.9"}})
    def test_idempotent_member_already_absent(self, lr, gs, refs, mv, dk, rm):
        # member already removed (unmappable) -> skip etcd phase, just delete registry
        gs.return_value = mock.Mock(current_server="me")
        events, result = _drain(nodes.remove_node("n2", remove_member=True))
        self.assertTrue(result.ok)
        rm.assert_not_called()
        dk.assert_called_once_with("/hetzman/nodes/n2")


if __name__ == "__main__":
    unittest.main()


class ProbeCredentialsTests(unittest.TestCase):
    """Member probes issue Maintenance RPCs, which etcd RBAC limits to root.

    Regression: connecting as the ordinary user made every Status probe fail
    PERMISSION_DENIED, so every member read as unhealthy and every quorum guard
    refused forever — a fail-closed guard that could never open.
    """

    def test_client_for_uses_root_credentials(self):
        with mock.patch("hetzman.config.load_etcd_admin_credentials",
                        return_value=("root", "s3cret")), \
             mock.patch("etcd3.client") as client:
            nodes._client_for("10.0.0.4", 2379)
        kwargs = client.call_args.kwargs
        self.assertEqual(kwargs["user"], "root")
        self.assertEqual(kwargs["password"], "s3cret")

    def test_admin_credentials_prefer_root_file(self):
        from hetzman import config

        with mock.patch.object(config, "_read_credentials",
                               side_effect=lambda p: ("root", "r") if "root" in p else ("hetzman", "h")):
            self.assertEqual(config.load_etcd_admin_credentials(), ("root", "r"))

    def test_admin_credentials_fall_back_when_no_root_file(self):
        from hetzman import config

        with mock.patch.object(config, "_read_credentials",
                               side_effect=lambda p: (None, None) if "root" in p else ("hetzman", "h")):
            self.assertEqual(config.load_etcd_admin_credentials(), ("hetzman", "h"))
