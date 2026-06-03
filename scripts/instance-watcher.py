#!/usr/bin/env python3
"""
Incus Instance Watcher - ETCD Version 3.2
Watches for Incus instances and manages DNS entries in etcd with TLS
"""

import subprocess
import json
import os
import sys
import time
import configparser
import re
import etcd3
from datetime import datetime

CONFIG_FILE = "/opt/hetzman-tooling/config.ini"
ADDITIONAL_HOSTS = "/opt/hetzman-tooling/configs/additional-hosts"
LOG_FILE = "/var/log/hetzman-tooling/instance-watcher.log"
ETCD_CREDS_FILE = "/opt/hetzman-tooling/etcd-credentials"
ETCD_CA_CERT = "/opt/hetzman-tooling/certs/ca.pem"
ETCD_CLIENT_CERT = "/opt/hetzman-tooling/certs/client.pem"
ETCD_CLIENT_KEY = "/opt/hetzman-tooling/certs/client-key.pem"

# Load config
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

CURRENT_SERVER = config.get('server', 'name')
BRIDGE_IP = config.get('server', 'bridge_ip')
PRIMARY_IFACE = config.get('server', 'primary_interface')

# Load etcd credentials if available
etcd_username = None
etcd_password = None
if os.path.exists(ETCD_CREDS_FILE):
    try:
        with open(ETCD_CREDS_FILE, 'r') as f:
            creds = f.read().strip()
            if ':' in creds:
                etcd_username, etcd_password = creds.split(':', 1)
    except:
        pass

# ETCD connection with TLS and retry
ETCD_ENDPOINTS = config.get('etcd', 'endpoints').split(',')
etcd_hosts = []
for endpoint in ETCD_ENDPOINTS:
    host, port = endpoint.split(':')
    etcd_hosts.append((host, int(port)))

# Connect with TLS
etcd_client = None
for host, port in etcd_hosts:
    try:
        # Try secure connection first
        etcd_client = etcd3.client(
            host=host,
            port=port,
            ca_cert=ETCD_CA_CERT if os.path.exists(ETCD_CA_CERT) else None,
            cert_cert=ETCD_CLIENT_CERT if os.path.exists(ETCD_CLIENT_CERT) else None,
            cert_key=ETCD_CLIENT_KEY if os.path.exists(ETCD_CLIENT_KEY) else None,
            user=etcd_username,
            password=etcd_password
        )
        break
    except:
        continue

if not etcd_client:
    print("ERROR: Could not connect to etcd cluster")
    sys.exit(1)


def log_message(message):
    """Log message to file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except:
        pass


def get_public_ip_from_interface(ip_address):
    """Check if IP is on interface using regex"""
    try:
        result = subprocess.run(
            ["ip", "addr", "show", PRIMARY_IFACE],
            capture_output=True, text=True, timeout=5
        )
        ip_pattern = re.compile(r'\b' + re.escape(ip_address) + r'/\d+\b')
        return bool(ip_pattern.search(result.stdout))
    except:
        return False


def remove_ip_from_interface(ip_address):
    """Remove IP address from host interface"""
    try:
        if not get_public_ip_from_interface(ip_address):
            return True

        subprocess.run([
            "ip", "addr", "del", f"{ip_address}/32",
            "dev", PRIMARY_IFACE
        ], check=True, capture_output=True, timeout=5)

        log_message(f"Removed IP {ip_address} from interface {PRIMARY_IFACE}")
        return True
    except:
        return False


def get_current_instances():
    """Get all instances (any state) with their IPs.

    Returns a dict {name: {ip, type, status}} on success (empty if there are
    genuinely no instances), or None if the incus query itself failed. Callers
    MUST treat None as "unknown" and skip reconciliation so a transient incus
    error never prunes live DNS/NAT records. Instances in EVERY state are
    included (ip is None when not running / no address yet) so a stopped
    instance still counts as "existing" and keeps its DNS; only instances
    actually deleted from Incus drop out of the map and have their DNS pruned.
    """
    try:
        result = subprocess.run(
            ["incus", "list", "--format", "json"],
            capture_output=True, text=True, check=True, timeout=10
        )

        instances = json.loads(result.stdout)
        instance_map = {}

        for instance in instances:
            name = instance['name']
            status = instance.get('status', 'Unknown')
            instance_type = instance.get('type', 'unknown')

            # Get IP address (None when not running or no address yet).
            # Stopped instances are intentionally kept in the map (see docstring).
            ip_address = None
            state = instance.get('state') or {}
            network = state.get('network') or {}
            # Check both eth0 (containers) and enp5s0 (VMs)
            for iface in ['eth0', 'enp5s0']:
                if iface not in network:
                    continue
                for addr in (network[iface].get('addresses') or []):
                    if addr.get('family') == 'inet' and not addr.get('address', '').startswith('127.'):
                        ip_address = addr['address']
                        break

            instance_map[name] = {
                'ip': ip_address,
                'type': instance_type,
                'status': status
            }

        return instance_map

    except Exception as e:
        # Distinct from {} (no instances): signal an error so the caller skips
        # this cycle instead of treating every instance as removed.
        log_message(f"Error querying incus instances: {e}")
        return None


def get_registered_instances():
    """Seed watcher state from etcd: DNS records this server already owns.

    The watcher only remembers instances within a single process lifetime, so
    after a restart/reboot it would otherwise forget everything it had
    registered and never prune records for instances deleted while it was down.
    Seeding previous_instances from etcd lets the normal removed-instance
    reconciliation clean up those orphans on the first successful loop. Only
    records owned by CURRENT_SERVER are seeded so we never touch other nodes'
    records.
    """
    registered = {}
    try:
        for value, metadata in etcd_client.get_prefix("/hetzman/dns/"):
            try:
                data = json.loads(value.decode('utf-8'))
            except Exception:
                continue
            if data.get('server') == CURRENT_SERVER and data.get('instance'):
                registered[data['instance']] = {
                    'ip': data.get('ip'),
                    'type': data.get('type', 'unknown'),
                    'status': 'Running',
                }
    except Exception as e:
        log_message(f"Error seeding registered instances from etcd: {e}")
    return registered


def register_dns(instance_name, ip_address, instance_type):
    """Register instance in etcd DNS"""
    if not ip_address:
        return False

    try:
        hostname = f"{instance_name}.daemondreams.home.arpa"

        record = {
            "ip": ip_address,
            "server": CURRENT_SERVER,
            "instance": instance_name,
            "type": instance_type,
            "auto": True,
            "updated": datetime.now().isoformat()
        }

        etcd_client.put(f"/hetzman/dns/{hostname}", json.dumps(record))
        log_message(f"Registered DNS: {hostname} -> {ip_address} ({instance_type})")
        return True

    except Exception as e:
        log_message(f"Error registering DNS: {e}")
        return False


def unregister_dns(instance_name):
    """Unregister instance from etcd and clean up"""
    nat_changed = False
    try:
        hostname = f"{instance_name}.daemondreams.home.arpa"

        # Get NAT rule if exists
        nat_value, _ = etcd_client.get(f"/hetzman/nat/{CURRENT_SERVER}/{instance_name}")
        public_ip = None
        if nat_value:
            nat_data = json.loads(nat_value.decode('utf-8'))
            public_ip = nat_data.get('public_ip')

            # Delete NAT rule
            etcd_client.delete(f"/hetzman/nat/{CURRENT_SERVER}/{instance_name}")
            nat_changed = True

            # Release public IP
            ip_value, _ = etcd_client.get(f"/hetzman/ip-pool/{public_ip}")
            if ip_value:
                ip_data = json.loads(ip_value.decode('utf-8'))
                ip_data['status'] = 'available'
                ip_data['assigned_to'] = None
                ip_data['assigned_at'] = None
                etcd_client.put(f"/hetzman/ip-pool/{public_ip}", json.dumps(ip_data))

        # Delete DNS record
        etcd_client.delete(f"/hetzman/dns/{hostname}")

        # Delete port forwards
        for value, metadata in etcd_client.get_prefix(f"/hetzman/port-forward/{CURRENT_SERVER}/"):
            key = metadata.key.decode('utf-8')
            data = json.loads(value.decode('utf-8'))
            if data.get('instance_name') == instance_name:
                etcd_client.delete(key)
                nat_changed = True

        # Remove public IP from interface (handled by sync-apply)
        if public_ip:
            log_message(f"Unregistered {instance_name}: DNS, NAT, public IP {public_ip} marked for removal")
        else:
            log_message(f"Unregistered {instance_name}: DNS cleaned up")

        # Reconcile NAT rules if any changes were made
        if nat_changed:
            try:
                subprocess.run(["/usr/bin/python3", "/opt/hetzman-tooling/scripts/hetzman.py", "sync-apply"],
                              capture_output=True, timeout=30, check=False)
                log_message(f"Reconciled NAT rules after unregistering {instance_name}")
            except Exception as e:
                log_message(f"Failed to reconcile NAT rules: {e}")

        return True

    except Exception as e:
        log_message(f"Error unregistering {instance_name}: {e}")
        return False


def regenerate_hosts_file():
    """Regenerate hosts file from etcd"""
    try:
        dns_records = {}
        for value, metadata in etcd_client.get_prefix("/hetzman/dns/"):
            key = metadata.key.decode('utf-8')
            hostname = key.replace("/hetzman/dns/", "")
            data = json.loads(value.decode('utf-8'))
            dns_records[hostname] = data['ip']

        os.makedirs(os.path.dirname(ADDITIONAL_HOSTS), exist_ok=True)
        with open(ADDITIONAL_HOSTS, "w") as f:
            for hostname, ip in sorted(dns_records.items()):
                f.write(f"{ip} {hostname}\n")

        return True

    except:
        return False


def reload_dnsmasq():
    """Reload dnsmasq"""
    try:
        subprocess.run(["systemctl", "reload", "dnsmasq"],
                      check=True, capture_output=True, timeout=10)
        return True
    except:
        return False


def main():
    """Main watcher loop"""
    log_message(f"Instance watcher v3.2 started on {CURRENT_SERVER}")

    # Track VMs waiting for IP
    vms_pending_ip = {}

    # Seed from etcd so a restart/reboot doesn't lose memory of instances we
    # previously registered; the removed-instance pass below then prunes any
    # that no longer exist (the cause of orphaned DNS records after a reboot).
    previous_instances = get_registered_instances()
    if previous_instances:
        log_message(
            f"Seeded {len(previous_instances)} previously-registered instance(s) "
            f"from etcd for reconciliation"
        )

    while True:
        try:
            current_instances = get_current_instances()
            if current_instances is None:
                # incus query failed: state is unknown this cycle. Skip
                # reconciliation entirely so a transient error never deletes
                # DNS/NAT for instances that are actually still running.
                time.sleep(10)
                continue
            changed = False

            # Check for new or changed instances
            for name, info in current_instances.items():
                # Stopped/frozen/etc.: keep its existing DNS untouched (don't
                # register and don't treat as pending). DNS is removed only when
                # the instance is actually deleted (handled below).
                if info['status'] not in ('Running', 'Started'):
                    vms_pending_ip.pop(name, None)
                    continue

                # Handle running instances without an IP yet
                if info['ip'] is None:
                    if info['type'] == 'virtual-machine':
                        if name not in vms_pending_ip:
                            vms_pending_ip[name] = time.time()
                            log_message(f"VM {name} detected without IP, waiting...")
                        elif time.time() - vms_pending_ip[name] > 120:
                            log_message(f"VM {name} still has no IP after 2 minutes, skipping")
                            vms_pending_ip.pop(name, None)
                    continue

                # Remove from pending if it has IP now
                vms_pending_ip.pop(name, None)

                # New instance or IP changed
                if name not in previous_instances or previous_instances.get(name, {}).get('ip') != info['ip']:
                    if register_dns(name, info['ip'], info['type']):
                        changed = True

            # Check for removed instances
            for name in previous_instances:
                if name not in current_instances:
                    if unregister_dns(name):
                        changed = True
                    vms_pending_ip.pop(name, None)

            # Regenerate hosts file if changed
            if changed:
                regenerate_hosts_file()
                reload_dnsmasq()

            previous_instances = current_instances

            time.sleep(10)

        except KeyboardInterrupt:
            log_message("Instance watcher stopped by user")
            break
        except Exception as e:
            log_message(f"Error in main loop: {e}")
            time.sleep(10)


if __name__ == "__main__":
    main()
