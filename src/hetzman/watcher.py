"""Incus instance watcher (packaged successor of scripts/instance-watcher.py).

Watches Incus instances and manages DNS entries in etcd. Differences from
the legacy standalone script, by design:

* Uses the shared :mod:`hetzman.etcd_kv` helpers, so expired etcd auth
  tokens are transparently re-authenticated (the legacy script failed every
  write after token TTL until its unit was restarted).
* Calls :func:`hetzman.commands.system.do_sync_apply` in-process with
  ``restart_watcher=False`` — the legacy script shelled out to the monolith,
  whose path was an empty file on one node, and a packaged equivalent that
  restarted the watcher unit would kill this very process mid-loop.

Semantics (proven on the fleet): a stopped instance keeps its DNS; only an
instance actually deleted from Incus is unregistered. State is seeded from
etcd at startup so restarts/reboots cannot orphan records.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime
from typing import Dict, Optional

from .config import get_settings
from .etcd_kv import delete_key, get_all_with_prefix, get_key, put_key
from .network import regenerate_hosts_file, reload_dnsmasq
from .render import DOMAIN

WATCHER_LOG = "/var/log/hetzman-tooling/instance-watcher.log"
POLL_SECONDS = 10
VM_IP_GRACE_SECONDS = 120


def _log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(os.path.dirname(WATCHER_LOG), exist_ok=True)
        with open(WATCHER_LOG, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except OSError:
        pass


def get_current_instances() -> Optional[Dict[str, dict]]:
    """All instances (any state) with their IPs, or None if the query failed.

    None means "unknown" — callers must skip reconciliation entirely so a
    transient incus error never prunes live DNS/NAT records. Stopped
    instances stay in the map (ip=None) and keep their DNS; only deleted
    instances drop out.
    """
    try:
        result = subprocess.run(
            ["incus", "list", "--format", "json"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        instances = json.loads(result.stdout)
    except Exception as e:
        _log(f"Error querying incus instances: {e}")
        return None

    instance_map: Dict[str, dict] = {}
    for instance in instances:
        name = instance["name"]
        status = instance.get("status", "Unknown")
        ip_address = None
        network = (instance.get("state") or {}).get("network") or {}
        for iface in ("eth0", "enp5s0"):
            if iface not in network:
                continue
            for addr in network[iface].get("addresses") or []:
                if addr.get("family") == "inet" and not addr.get("address", "").startswith("127."):
                    ip_address = addr["address"]
                    break
        instance_map[name] = {
            "ip": ip_address,
            "type": instance.get("type", "unknown"),
            "status": status,
        }
    return instance_map


def get_registered_instances() -> Dict[str, dict]:
    """Seed state from etcd: DNS records this server owns."""
    current_server = get_settings().current_server
    registered: Dict[str, dict] = {}
    for record in get_all_with_prefix("/hetzman/dns/").values():
        if not isinstance(record, dict):
            continue
        if record.get("server") == current_server and record.get("instance"):
            registered[record["instance"]] = {
                "ip": record.get("ip"),
                "type": record.get("type", "unknown"),
                "status": "Running",
            }
    return registered


def register_dns(instance_name: str, ip_address: str, instance_type: str) -> bool:
    if not ip_address:
        return False
    hostname = f"{instance_name}.{DOMAIN}"
    record = {
        "ip": ip_address,
        "server": get_settings().current_server,
        "instance": instance_name,
        "type": instance_type,
        "auto": True,
        "updated": datetime.now().isoformat(),
    }
    if put_key(f"/hetzman/dns/{hostname}", json.dumps(record)):
        _log(f"Registered DNS: {hostname} -> {ip_address} ({instance_type})")
        return True
    _log(f"Error registering DNS for {hostname}")
    return False


def unregister_dns(instance_name: str) -> bool:
    """Remove an instance's DNS, NAT, pool assignment and port-forwards."""
    current_server = get_settings().current_server
    nat_changed = False
    try:
        hostname = f"{instance_name}.{DOMAIN}"

        nat_value = get_key(f"/hetzman/nat/{current_server}/{instance_name}")
        public_ip = None
        if nat_value:
            try:
                public_ip = json.loads(nat_value).get("public_ip")
            except json.JSONDecodeError:
                public_ip = None
            delete_key(f"/hetzman/nat/{current_server}/{instance_name}")
            nat_changed = True

            if public_ip:
                pool_value = get_key(f"/hetzman/ip-pool/{public_ip}")
                if pool_value:
                    try:
                        pool_entry = json.loads(pool_value)
                        pool_entry.update(
                            status="available", assigned_to=None, assigned_at=None
                        )
                        put_key(f"/hetzman/ip-pool/{public_ip}", json.dumps(pool_entry))
                    except json.JSONDecodeError:
                        pass

        delete_key(f"/hetzman/dns/{hostname}")

        for key, data in get_all_with_prefix(f"/hetzman/port-forward/{current_server}/").items():
            if isinstance(data, dict) and data.get("instance_name") == instance_name:
                delete_key(key)
                nat_changed = True

        if public_ip:
            _log(f"Unregistered {instance_name}: DNS, NAT, public IP {public_ip} released")
        else:
            _log(f"Unregistered {instance_name}: DNS cleaned up")

        if nat_changed:
            from .commands.system import do_sync_apply

            do_sync_apply(restart_watcher=False)
            _log(f"Reconciled NAT rules after unregistering {instance_name}")

        return True
    except Exception as e:
        _log(f"Error unregistering {instance_name}: {e}")
        return False


def main() -> None:
    current_server = get_settings().current_server
    _log(f"Instance watcher (hetzman package) started on {current_server}")

    vms_pending_ip: Dict[str, float] = {}
    previous_instances = get_registered_instances()
    if previous_instances:
        _log(
            f"Seeded {len(previous_instances)} previously-registered instance(s) "
            f"from etcd for reconciliation"
        )

    while True:
        try:
            current_instances = get_current_instances()
            if current_instances is None:
                time.sleep(POLL_SECONDS)
                continue
            changed = False

            for name, info in current_instances.items():
                if info["status"] not in ("Running", "Started"):
                    vms_pending_ip.pop(name, None)
                    continue

                if info["ip"] is None:
                    if info["type"] == "virtual-machine":
                        if name not in vms_pending_ip:
                            vms_pending_ip[name] = time.time()
                            _log(f"VM {name} detected without IP, waiting...")
                        elif time.time() - vms_pending_ip[name] > VM_IP_GRACE_SECONDS:
                            _log(f"VM {name} still has no IP after 2 minutes, skipping")
                            vms_pending_ip.pop(name, None)
                    continue

                vms_pending_ip.pop(name, None)

                if (
                    name not in previous_instances
                    or previous_instances.get(name, {}).get("ip") != info["ip"]
                ):
                    if register_dns(name, info["ip"], info["type"]):
                        changed = True

            for name in previous_instances:
                if name not in current_instances:
                    if unregister_dns(name):
                        changed = True
                    vms_pending_ip.pop(name, None)

            if changed:
                regenerate_hosts_file()
                reload_dnsmasq()

            previous_instances = current_instances
            time.sleep(POLL_SECONDS)

        except KeyboardInterrupt:
            _log("Instance watcher stopped by user")
            break
        except Exception as e:
            _log(f"Error in main loop: {e}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
