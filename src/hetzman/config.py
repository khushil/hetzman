"""Configuration paths, lazy settings, and lazy etcd client.

Importing this module has no side effects: settings are read on first call
to ``get_settings()`` and the etcd client is built on first call to
``get_etcd_client()``. This lets ``hetzman --help`` (and any unit test)
work without etcd, certs, or ``/opt/hetzman-tooling/config.ini``.
"""
from __future__ import annotations

import configparser
import os
import sys
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

import etcd3

from .core.errors import EtcdUnavailable

# Paths are env-overridable so the external (non-fleet) command centre can point
# at its own config/certs/known_hosts without the on-node defaults.
CONFIG_FILE = os.environ.get("HETZMAN_CONFIG_FILE", "/opt/hetzman-tooling/config.ini")
ADDITIONAL_HOSTS = "/opt/hetzman-tooling/configs/additional-hosts"
LOG_FILE = "/var/log/hetzman-tooling/hetzman.log"
ETCD_CREDS_FILE = os.environ.get("HETZMAN_ETCD_CREDS_FILE", "/opt/hetzman-tooling/etcd-credentials")
ETCD_CA_CERT = os.environ.get("HETZMAN_ETCD_CA_CERT", "/opt/hetzman-tooling/certs/ca.pem")
ETCD_CLIENT_CERT = os.environ.get("HETZMAN_ETCD_CLIENT_CERT", "/opt/hetzman-tooling/certs/client.pem")
ETCD_CLIENT_KEY = os.environ.get("HETZMAN_ETCD_CLIENT_KEY", "/opt/hetzman-tooling/certs/client-key.pem")
HOST_ROOT_KEYS = "/root/.ssh/authorized_keys"
# Pinned known_hosts for the SSH executor (host-key checking is strict — vswitch
# IPs come from the registry this tool can write, so TOFU would be unsafe).
SSH_KNOWN_HOSTS = os.environ.get("HETZMAN_KNOWN_HOSTS", "/opt/hetzman-tooling/known_hosts")

# Bounded connect-retry: a systemd unit at cold boot may race quorum formation,
# so non-interactive invocations retry; interactive ones fail fast.
_RETRY_SLEEP_SECONDS = 30


@dataclass(frozen=True)
class Settings:
    # ``current_server`` is None in EXTERNAL mode (a command-centre box with no
    # ``[server]`` identity). Node-only code paths must refuse when it is None;
    # targeting ops must resolve an explicit host (see core.exec.resolve_host).
    current_server: Optional[str]
    bridge_ip: str
    primary_iface: str
    etcd_endpoints: tuple[tuple[str, int], ...]
    vswitch_ip: str = ""
    vlan_interface: str = ""


def _parse_endpoints(raw: str) -> list[tuple[str, int]]:
    endpoints = []
    for endpoint in raw.split(","):
        endpoint = endpoint.strip()
        if not endpoint:
            continue
        host, port = endpoint.rsplit(":", 1)
        endpoints.append((host.strip(), int(port)))
    return endpoints


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    # etcd endpoints: from [etcd] or, for an external box bootstrap, the env.
    raw_eps = config.get("etcd", "endpoints", fallback="") or os.environ.get(
        "HETZMAN_ETCD_ENDPOINTS", ""
    )
    return Settings(
        current_server=config.get("server", "name", fallback=None),
        bridge_ip=config.get("server", "bridge_ip", fallback=""),
        primary_iface=config.get("server", "primary_interface", fallback=""),
        etcd_endpoints=tuple(_parse_endpoints(raw_eps)),
        vswitch_ip=config.get("server", "vswitch_ip", fallback=""),
        vlan_interface=config.get("server", "vlan_interface", fallback=""),
    )


def is_external() -> bool:
    """True when this box has no fleet-node identity (no ``[server]`` section).

    External mode = a command centre that reaches the fleet over etcd + SSH; it
    has no local ``current_server`` and no local incus, so every targeting op
    must name an explicit host.
    """
    return get_settings().current_server is None


def _load_etcd_credentials() -> tuple[Optional[str], Optional[str]]:
    if not os.path.exists(ETCD_CREDS_FILE):
        return None, None
    try:
        with open(ETCD_CREDS_FILE) as f:
            creds = f.read().strip()
    except OSError:
        return None, None
    if ":" not in creds:
        return None, None
    user, password = creds.split(":", 1)
    return user, password


def _connect_passes() -> int:
    env = os.environ.get("HETZMAN_ETCD_CONNECT_RETRIES")
    if env is not None:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    # systemd units have no tty; humans do.
    return 1 if sys.stdin.isatty() else 6


@lru_cache(maxsize=1)
def get_etcd_client():
    settings = get_settings()
    user, password = _load_etcd_credentials()

    passes = _connect_passes()
    for attempt in range(passes):
        for host, port in settings.etcd_endpoints:
            try:
                client = etcd3.client(
                    host=host,
                    port=port,
                    ca_cert=ETCD_CA_CERT if os.path.exists(ETCD_CA_CERT) else None,
                    cert_cert=ETCD_CLIENT_CERT if os.path.exists(ETCD_CLIENT_CERT) else None,
                    cert_key=ETCD_CLIENT_KEY if os.path.exists(ETCD_CLIENT_KEY) else None,
                    user=user,
                    password=password,
                )
                client.get("/hetzman/version")
                return client
            except Exception:
                continue
        if attempt < passes - 1:
            time.sleep(_RETRY_SLEEP_SECONDS)

    raise EtcdUnavailable("Could not connect to etcd cluster")


def reset_etcd_client() -> None:
    """Drop the cached client so the next call re-authenticates.

    etcd RBAC auth tokens expire server-side; the etcd3 library does not
    refresh them, so long-running processes must rebuild the client when a
    call fails with UNAUTHENTICATED.
    """
    get_etcd_client.cache_clear()


def write_config(server: dict, all_vswitch_ips: list[str]) -> bool:
    """Atomically rewrite config.ini from a registry self-entry.

    Never affects the running process: ``get_settings()`` is cached.
    """
    config = configparser.ConfigParser()
    config["server"] = {
        "name": server["name"],
        "bridge_ip": server["bridge_ip"],
        "vswitch_ip": server["vswitch_ip"],
        "primary_interface": server["primary_interface"],
        "vlan_interface": server["vlan_interface"],
    }
    config["etcd"] = {
        "endpoints": ",".join(f"{ip}:2379" for ip in sorted(all_vswitch_ips)),
    }
    tmp = CONFIG_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            config.write(f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, CONFIG_FILE)
        return True
    except OSError as e:
        from .logging import log_message

        log_message(f"Error writing {CONFIG_FILE}: {e}", "ERROR")
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
