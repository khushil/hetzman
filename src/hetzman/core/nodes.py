"""Fleet node registry + etcd cluster-membership operations (SAFETY-CRITICAL).

Two generators:

* ``register_node`` — validated **registry write only**. It does NOT add an etcd
  member (this etcd3 build has no learner support and nothing here provisions
  etcd on a new box; auto-adding a voting member would erode quorum). Full
  remote provisioning is a separate, separately-reviewed phase.
* ``remove_node`` — removes the registry entry and, with ``remove_member=True``,
  the etcd cluster member, behind a **voter-health quorum guard** derived from
  etcd's own per-member Status (NOT the /hetzman/health heartbeats, which do not
  measure raft voter health).

The safety decision is the pure function :func:`assess_removal`, unit-tested at
the n=2 / n=3->2 / n=4->3 boundaries in isolation from all etcd I/O.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
from collections import Counter
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import etcd3

from .. import config, etcd_kv
from ..config import get_etcd_client, get_settings
from ..registry import NODES_PREFIX, SCHEMA_VERSION, load_registry, validate_registry
from .errors import CoreError, NotFoundError, ValidationError
from .events import OpResult, ProgressEvent, ProgressGen, Severity


# --------------------------------------------------------------------------- #
# Pure value objects + safety math (no etcd I/O — exhaustively unit-tested)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MemberView:
    """A minimal, test-friendly view of an etcd member."""

    id: int
    name: str            # empty string => unstarted / still joining
    peer_hosts: tuple[str, ...]
    healthy: bool        # responded to a Status RPC (liveness only)
    is_leader: bool
    raft_index: Optional[int] = None  # raft log position (for catch-up checks)


# A just-rebooted etcd answers Status the instant its socket is up, while its
# raft log is still replaying. A member within this many entries of the
# furthest-ahead voter is considered "caught up" enough to count.
_MAX_RAFT_LAG = 128


def member_caught_up(target_id: int, members: list[MemberView]) -> bool:
    """True iff the target member is healthy, a stable leader is agreed, and the
    target's raft log is within _MAX_RAFT_LAG of the furthest-ahead voter.

    Used to gate a rolling reboot: never take the NEXT voter down until the one
    we just rebooted has genuinely rejoined and caught up (answering Status is
    NOT enough — it can reply while still replaying its log).
    """
    target = next((m for m in members if m.id == target_id), None)
    if target is None or not target.healthy or target.raft_index is None:
        return False
    if not any(m.is_leader for m in members):  # no agreed leader => mid-election
        return False
    indices = [m.raft_index for m in members if m.healthy and m.raft_index is not None]
    if not indices:
        return False
    return (max(indices) - target.raft_index) <= _MAX_RAFT_LAG


def assess_removal(members: list[MemberView], target_id: int) -> None:
    """Raise CoreError if removing ``target_id`` is unsafe; return None if safe.

    Rules (fail-closed):
      * cluster must have >= 3 members (a 2-node shrink is never safe to automate);
      * refuse while ANY member is unstarted (empty name => topology mid-transition);
      * refuse only if the target is a *healthy* current raft leader (transfer
        leadership first); a DEAD member merely still reported as the old leader
        is removable — etcd will/has elect(ed) a new leader among survivors;
      * the count of HEALTHY voters remaining after removal must EXCEED the
        post-removal quorum (i.e. leave at least one spare healthy voter), so an
        automated removal never lands the cluster at a zero-margin 2-voter state
        or removes a voter while the rest are already one fault from quorum.
    """
    n = len(members)
    if n <= 2:
        raise CoreError(
            f"refusing etcd member removal: cluster too small (n={n}); "
            "a 2-node shrink leaves no fault tolerance"
        )
    if any(not m.name for m in members):
        raise CoreError(
            "refusing: an etcd member is unstarted/joining (topology mid-transition)"
        )
    target = next((m for m in members if m.id == target_id), None)
    if target is None:
        raise CoreError(f"target member id {target_id} is not in the cluster")
    if target.is_leader and target.healthy:
        raise CoreError(
            "refusing: target is the current healthy raft leader (transfer leadership first)"
        )
    remaining = n - 1
    quorum = remaining // 2 + 1
    healthy_after = sum(1 for m in members if m.id != target_id and m.healthy)
    if healthy_after <= quorum:
        raise CoreError(
            f"refusing: removal would leave no spare healthy voter "
            f"({healthy_after} healthy after vs quorum {quorum} of {remaining}); "
            "need a margin of at least one"
        )


def assess_reboot(members: list[MemberView], target_id: int) -> None:
    """Raise CoreError if rebooting ``target_id`` would risk etcd quorum.

    A reboot takes the member DOWN transiently but does NOT remove it, so quorum
    stays that of the FULL cluster (n). The remaining members must keep a quorum
    of HEALTHY voters while the target is down. (Distinct from assess_removal,
    which recomputes quorum for the n-1 cluster.)
    """
    n = len(members)
    if any(not m.name for m in members):
        raise CoreError(
            "refusing: an etcd member is unstarted/joining (topology mid-transition)"
        )
    if not any(m.id == target_id for m in members):
        raise CoreError(f"target member id {target_id} is not in the cluster")
    quorum = n // 2 + 1
    healthy_without = sum(1 for m in members if m.id != target_id and m.healthy)
    if healthy_without < quorum:
        raise CoreError(
            f"refusing reboot: the cluster would lose quorum while this node is down "
            f"({healthy_without} healthy others < {quorum} quorum of {n})"
        )


def lookup_member(name: str) -> tuple[Optional[MemberView], list[MemberView]]:
    """Return (this node's etcd member or None, all members) — None when the node
    is not in the registry or maps to no current member."""
    entry = load_registry().get(name)
    if not entry:
        return None, []
    members = _member_views()
    return _try_map(name, entry, members), members


def _peer_host(url: str) -> str:
    # https://10.0.0.1:2380 -> 10.0.0.1  (mirrors registry_guard's parse)
    return url.split("//", 1)[-1].rsplit(":", 1)[0]


def map_to_member(name: str, entry: dict, members: list[MemberView]) -> MemberView:
    """Map a registry node to its etcd member; refuse on ambiguity/none."""
    etcd_name = entry.get("etcd_name")
    by_name = [m for m in members if m.name and m.name == etcd_name]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        raise CoreError(f"ambiguous: multiple etcd members named {etcd_name!r}")
    vswitch_ip = entry.get("vswitch_ip")
    by_ip = [m for m in members if vswitch_ip and vswitch_ip in m.peer_hosts]
    if len(by_ip) == 1:
        return by_ip[0]
    if len(by_ip) > 1:
        raise CoreError(f"ambiguous: multiple etcd members with peer {vswitch_ip}")
    raise CoreError(
        f"could not map node {name!r} to an etcd member "
        f"(etcd_name={etcd_name!r}, vswitch_ip={vswitch_ip!r})"
    )


def _try_map(name: str, entry: dict, members: list[MemberView]) -> Optional[MemberView]:
    """Like :func:`map_to_member` but returns None when the member is simply
    absent (idempotent re-run after a partial removal). Still raises on
    ambiguity — we never guess which member to remove."""
    try:
        return map_to_member(name, entry, members)
    except CoreError as exc:
        if "ambiguous" in str(exc):
            raise
        return None


# --------------------------------------------------------------------------- #
# etcd I/O (mocked in tests)
# --------------------------------------------------------------------------- #
_PROBE_TIMEOUT = 2  # seconds — a black-holed dead member must not hang the op


def _url_hostport(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    return parts.hostname or _peer_host(url), parts.port or 2379


def _client_for(host: str, port: int):
    import os
    return etcd3.client(
        host=host, port=port, timeout=_PROBE_TIMEOUT,
        ca_cert=config.ETCD_CA_CERT if os.path.exists(config.ETCD_CA_CERT) else None,
        cert_cert=config.ETCD_CLIENT_CERT if os.path.exists(config.ETCD_CLIENT_CERT) else None,
        cert_key=config.ETCD_CLIENT_KEY if os.path.exists(config.ETCD_CLIENT_KEY) else None,
    )


@dataclass(frozen=True)
class _Probe:
    healthy: bool                 # a Status RPC succeeded (liveness, independent of leader)
    leader_id: Optional[int]      # leader this member reported (None mid-election)
    raft_index: Optional[int]     # this member's raft log position


def _probe_member(member) -> _Probe:
    """Probe a member's Status with a bounded timeout. A successful RPC means
    HEALTHY regardless of whether a leader is currently elected."""
    for url in (member.client_urls or []):
        host, port = _url_hostport(url)
        client = None
        try:
            client = _client_for(host, port)
            st = client.status()
            leader = getattr(st, "leader", None)
            lid = leader.id if hasattr(leader, "id") else leader
            return _Probe(healthy=True, leader_id=lid, raft_index=getattr(st, "raft_index", None))
        except Exception:
            continue
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
    return _Probe(healthy=False, leader_id=None, raft_index=None)


def _member_views() -> list[MemberView]:
    """Build MemberViews from the live cluster + bounded per-member Status probes.

    Liveness = a successful Status RPC. The leader is taken by MAJORITY agreement
    among responders (not last-writer-wins); if responders disagree the leader is
    treated as unknown (no member flagged leader) — fail-closed.
    """
    raw = list(get_etcd_client().members)
    probes = {m.id: _probe_member(m) for m in raw}

    responders = [p for p in probes.values() if p.healthy]
    votes = Counter(p.leader_id for p in responders if p.leader_id is not None)
    leader_id: Optional[int] = None
    if votes:
        top_id, top_count = votes.most_common(1)[0]
        if top_count * 2 > len(responders):  # strict majority of responders agree
            leader_id = top_id

    return [
        MemberView(
            id=m.id,
            name=m.name or "",
            peer_hosts=tuple(_peer_host(u) for u in (m.peer_urls or [])),
            healthy=probes[m.id].healthy,
            is_leader=leader_id is not None and m.id == leader_id,
            raft_index=probes[m.id].raft_index,
        )
        for m in raw
    ]


def _remove_member_via_other(target: MemberView, members: list[MemberView]) -> None:
    """Issue the remove RPC from a HEALTHY member that is NOT the target, so we
    never tear down the very endpoint the request travels through (which would
    fail the request and could freeze the fleet)."""
    raw = {m.id: m for m in get_etcd_client().members}
    for view in members:
        if view.id == target.id or not view.healthy:
            continue
        member = raw.get(view.id)
        if member is None or not member.client_urls:
            continue
        host, port = _url_hostport(member.client_urls[0])
        client = None
        try:
            client = _client_for(host, port)
            client.remove_member(target.id)
            return
        except Exception:
            continue
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
    raise CoreError("could not reach any healthy non-target member to perform the removal")


def _references(name: str) -> list[str]:
    """NAT / ip-pool / DNS rows still referencing this node (block removal)."""
    refs = []
    if etcd_kv.get_all_with_prefix(f"/hetzman/nat/{name}/"):
        refs.append("NAT rules")
    pool = etcd_kv.get_all_with_prefix("/hetzman/ip-pool/")
    if any(isinstance(v, dict) and v.get("server") == name for v in pool.values()):
        refs.append("IP pool")
    dns = etcd_kv.get_all_with_prefix("/hetzman/dns/")
    if any(isinstance(v, dict) and v.get("server") == name for v in dns.values()):
        refs.append("DNS records")
    return refs


# --------------------------------------------------------------------------- #
# Generators
# --------------------------------------------------------------------------- #
def register_node(
    *,
    name: str,
    vswitch_ip: str,
    bridge_ip: str,
    public_block: str,
    primary_interface: str,
    vlan_interface: str,
    vlan_id: int,
    mtu: int,
    etcd_name: str,
) -> ProgressGen:
    """Write (or refresh) a node's registry entry. Registry-only — etcd
    membership is a separate, deliberate step (see module docstring)."""
    entry = {
        "schema": SCHEMA_VERSION,
        "name": name,
        "vswitch_ip": vswitch_ip,
        "bridge_ip": bridge_ip,
        "bridge_subnet": str(ipaddress.ip_network(f"{bridge_ip}/24", strict=False)),
        "public_block": public_block,
        "primary_interface": primary_interface,
        "vlan_interface": vlan_interface,
        "vlan_id": vlan_id,
        "mtu": mtu,
        "etcd_name": etcd_name,
        "etcd_client_port": 2379,
        "updated_at": datetime.datetime.now().isoformat(),
    }
    merged = load_registry()
    merged[name] = entry
    errors = validate_registry(merged)
    if errors:
        raise ValidationError("registry would be invalid: " + "; ".join(errors))

    yield ProgressEvent(Severity.STEP, f"Registering node {name}", 1, 1)
    if not etcd_kv.put_key(NODES_PREFIX + name, json.dumps(entry)):
        raise CoreError("etcd write failed")
    yield ProgressEvent(Severity.SUCCESS, f"Registered {name} in the fleet registry")
    yield ProgressEvent(
        Severity.WARNING,
        "node-sync stays fail-closed fleet-wide until this node's etcd member is "
        "started and the registry 1:1-matches members (intended).",
    )
    return OpResult(ok=True, summary={"name": name})


def remove_node(
    name: str,
    *,
    remove_member: bool = False,
    force: bool = False,
) -> ProgressGen:
    """Remove a node from the registry and (optionally) the etcd cluster."""
    registry = load_registry()
    if name not in registry:
        raise NotFoundError(f"node {name!r} is not in the registry")
    if get_settings().current_server == name:
        raise ValidationError("refusing to remove the node you are running on")

    refs = _references(name)
    if refs and not force:
        raise ValidationError(
            f"node {name!r} is still referenced by {', '.join(refs)}; "
            "release those first or pass force=True"
        )

    if remove_member:
        members = _member_views()
        target = _try_map(name, registry[name], members)
        if target is None:
            # Idempotent re-run: the etcd member is already gone — just converge
            # the registry so a prior partial removal (member removed, registry
            # delete failed) doesn't leave node-sync frozen.
            yield ProgressEvent(
                Severity.WARNING,
                f"etcd member for {name} already absent; removing registry entry only",
            )
        else:
            healthy = sum(1 for m in members if m.healthy)
            yield ProgressEvent(
                Severity.INFO,
                f"etcd: {len(members)} members, {healthy} healthy; "
                f"removing {target.name} ({target.id})",
            )
            assess_removal(members, target.id)  # raises CoreError if unsafe
            yield ProgressEvent(Severity.STEP, f"Removing etcd member {target.name}", 1, 1)
            _remove_member_via_other(target, members)
            yield ProgressEvent(Severity.SUCCESS, f"Removed etcd member {target.name}")

    if not etcd_kv.delete_key(NODES_PREFIX + name):
        raise CoreError(
            "etcd registry delete failed"
            + (" (etcd member was already removed — re-run to retry the registry delete)"
               if remove_member else "")
        )
    yield ProgressEvent(Severity.SUCCESS, f"Removed {name} from the fleet registry")
    yield ProgressEvent(
        Severity.WARNING,
        "node-sync stays fail-closed until the registry 1:1-matches members again.",
    )
    return OpResult(ok=True, summary={"name": name, "member_removed": remove_member})
