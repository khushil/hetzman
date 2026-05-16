"""Host network mutations: IP-on-interface, dnsmasq, hosts file, NAT rules."""
from __future__ import annotations

import os
import re
import subprocess

from .config import ADDITIONAL_HOSTS, get_settings
from .console import console
from .etcd_kv import get_all_with_prefix
from .logging import log_message


def get_public_ip_from_interface(ip_address: str) -> bool:
    iface = get_settings().primary_iface
    try:
        result = subprocess.run(
            ["ip", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        return bool(re.search(r"\b" + re.escape(ip_address) + r"/\d+\b", result.stdout))
    except Exception as e:
        log_message(f"Error checking IP {ip_address} on interface: {e}", "ERROR")
        return False


def add_ip_to_interface(ip_address: str) -> bool:
    iface = get_settings().primary_iface
    if get_public_ip_from_interface(ip_address):
        log_message(f"IP {ip_address} already on interface {iface}")
        return True
    try:
        subprocess.run(
            ["sudo", "ip", "addr", "add", f"{ip_address}/32", "dev", iface],
            check=True, capture_output=True, timeout=5,
        )
        log_message(f"Added IP {ip_address} to interface {iface}")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to add IP {ip_address} to interface: {e}", "ERROR")
        return False
    except subprocess.TimeoutExpired:
        log_message(f"Timeout adding IP {ip_address} to interface", "ERROR")
        return False


def remove_ip_from_interface(ip_address: str) -> bool:
    iface = get_settings().primary_iface
    if not get_public_ip_from_interface(ip_address):
        log_message(f"IP {ip_address} not on interface {iface}")
        return True
    try:
        subprocess.run(
            ["sudo", "ip", "addr", "del", f"{ip_address}/32", "dev", iface],
            check=True, capture_output=True, timeout=5,
        )
        log_message(f"Removed IP {ip_address} from interface {iface}")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"Failed to remove IP {ip_address} from interface: {e}", "ERROR")
        return False
    except subprocess.TimeoutExpired:
        log_message(f"Timeout removing IP {ip_address} from interface", "ERROR")
        return False


def reload_dnsmasq() -> bool:
    try:
        subprocess.run(
            ["sudo", "systemctl", "reload", "dnsmasq"],
            check=True, capture_output=True, timeout=10,
        )
        log_message("dnsmasq reloaded successfully")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to reload dnsmasq: {e}[/red]")
        log_message(f"Failed to reload dnsmasq: {e}", "ERROR")
        return False
    except subprocess.TimeoutExpired:
        console.print("[red]Timeout reloading dnsmasq[/red]")
        log_message("Timeout reloading dnsmasq", "ERROR")
        return False


def regenerate_hosts_file() -> bool:
    try:
        dns_records = get_all_with_prefix("/hetzman/dns/")
        os.makedirs(os.path.dirname(ADDITIONAL_HOSTS), exist_ok=True)
        with open(ADDITIONAL_HOSTS, "w") as f:
            for key, record in dns_records.items():
                if isinstance(record, dict):
                    hostname = key.replace("/hetzman/dns/", "")
                    f.write(f"{record['ip']} {hostname}\n")
        log_message(f"Regenerated hosts file with {len(dns_records)} records")
        return True
    except Exception as e:
        console.print(f"[red]Error regenerating hosts file: {e}[/red]")
        log_message(f"Error regenerating hosts file: {e}", "ERROR")
        return False


def _ensure_nat_chain(chain: str, parent: str) -> None:
    """Idempotently create ``chain`` (in nat table) and a jump from ``parent``."""
    subprocess.run(
        ["sudo", "iptables", "-w", "5", "-t", "nat", "-N", chain],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
    )
    check = subprocess.run(
        ["sudo", "iptables", "-w", "5", "-t", "nat", "-C", parent, "-j", chain],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
    )
    if check.returncode != 0:
        subprocess.run(
            ["sudo", "iptables", "-w", "5", "-t", "nat", "-I", parent, "-j", chain],
            check=True, capture_output=True, timeout=10,
        )


def apply_nat_rules() -> bool:
    """Apply all enabled NAT rules from etcd with idempotency and proper exclusions."""
    settings = get_settings()
    try:
        _ensure_nat_chain("HETZMAN_NAT", "PREROUTING")
        _ensure_nat_chain("HETZMAN_NAT_POST", "POSTROUTING")

        # Clear existing NAT rules.
        subprocess.run(
            ["sudo", "iptables", "-w", "5", "-t", "nat", "-F", "HETZMAN_NAT"],
            capture_output=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "iptables", "-w", "5", "-t", "nat", "-F", "HETZMAN_NAT_POST"],
            capture_output=True, timeout=10,
        )

        nat_rules = get_all_with_prefix(f"/hetzman/nat/{settings.current_server}/")

        for _, rule in nat_rules.items():
            if not isinstance(rule, dict) or not rule.get("enabled", True):
                continue

            public_ip = rule["public_ip"]
            private_ip = rule["private_ip"]
            instance_name = rule["instance_name"]

            add_ip_to_interface(public_ip)

            # DNAT for external traffic.
            subprocess.run([
                "sudo", "iptables", "-w", "5", "-t", "nat", "-A", "HETZMAN_NAT",
                "-d", public_ip,
                "-j", "DNAT",
                "--to-destination", private_ip,
            ], check=True, capture_output=True, timeout=10)

            # Hairpin NAT for internal traffic accessing public IP.
            subprocess.run([
                "sudo", "iptables", "-w", "5", "-t", "nat", "-A", "HETZMAN_NAT",
                "-i", "incusbr0",
                "-d", public_ip,
                "-j", "DNAT",
                "--to-destination", private_ip,
            ], check=True, capture_output=True, timeout=10)

            # SNAT with internal-network exclusions.
            subprocess.run([
                "sudo", "iptables", "-w", "5", "-t", "nat", "-A", "HETZMAN_NAT_POST",
                "-s", private_ip,
                "!", "-d", "10.0.0.0/8",
                "-j", "SNAT",
                "--to-source", public_ip,
            ], check=True, capture_output=True, timeout=10)

            log_message(f"Applied 1:1 NAT with hairpin: {public_ip} <-> {private_ip} ({instance_name})")

        # Masquerade for hairpin return traffic.
        masq_check = subprocess.run([
            "sudo", "iptables", "-w", "5", "-t", "nat", "-C", "HETZMAN_NAT_POST",
            "-s", "10.100.0.0/16",
            "-d", "10.100.0.0/16",
            "-j", "MASQUERADE",
        ], capture_output=True, timeout=10)
        if masq_check.returncode != 0:
            subprocess.run([
                "sudo", "iptables", "-w", "5", "-t", "nat", "-A", "HETZMAN_NAT_POST",
                "-s", "10.100.0.0/16",
                "-d", "10.100.0.0/16",
                "-j", "MASQUERADE",
            ], check=True, capture_output=True, timeout=10)

        port_rules = get_all_with_prefix(f"/hetzman/port-forward/{settings.current_server}/")

        for _, rule in port_rules.items():
            if not isinstance(rule, dict) or not rule.get("enabled", True):
                continue
            subprocess.run([
                "sudo", "iptables", "-w", "5", "-t", "nat", "-A", "HETZMAN_NAT",
                "-d", rule["public_ip"],
                "-p", rule["protocol"],
                "--dport", str(rule["public_port"]),
                "-j", "DNAT",
                "--to-destination", f"{rule['private_ip']}:{rule['private_port']}",
            ], check=True, capture_output=True, timeout=10)
            log_message(
                f"Applied port forward: {rule['public_ip']}:{rule['public_port']} -> "
                f"{rule['private_ip']}:{rule['private_port']} ({rule['protocol']})"
            )

        console.print(f"[green]Applied {len(nat_rules)} NAT rules and {len(port_rules)} port forwards[/green]")
        return True

    except Exception as e:
        console.print(f"[red]Error applying NAT rules: {e}[/red]")
        log_message(f"Error applying NAT rules: {e}", "ERROR")
        return False
