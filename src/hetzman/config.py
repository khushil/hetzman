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
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

import etcd3

from .console import console

CONFIG_FILE = "/opt/hetzman-tooling/config.ini"
ADDITIONAL_HOSTS = "/opt/hetzman-tooling/configs/additional-hosts"
LOG_FILE = "/var/log/hetzman-tooling/hetzman.log"
ETCD_CREDS_FILE = "/opt/hetzman-tooling/etcd-credentials"
ETCD_CA_CERT = "/opt/hetzman-tooling/certs/ca.pem"
ETCD_CLIENT_CERT = "/opt/hetzman-tooling/certs/client.pem"
ETCD_CLIENT_KEY = "/opt/hetzman-tooling/certs/client-key.pem"
HOST_ROOT_KEYS = "/root/.ssh/authorized_keys"


@dataclass(frozen=True)
class Settings:
    current_server: str
    bridge_ip: str
    primary_iface: str
    etcd_endpoints: tuple[tuple[str, int], ...]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    endpoints = []
    for endpoint in config.get("etcd", "endpoints").split(","):
        host, port = endpoint.split(":")
        endpoints.append((host, int(port)))
    return Settings(
        current_server=config.get("server", "name"),
        bridge_ip=config.get("server", "bridge_ip"),
        primary_iface=config.get("server", "primary_interface"),
        etcd_endpoints=tuple(endpoints),
    )


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


@lru_cache(maxsize=1)
def get_etcd_client():
    settings = get_settings()
    user, password = _load_etcd_credentials()

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

    console.print("[red]ERROR: Could not connect to etcd cluster[/red]")
    sys.exit(1)
