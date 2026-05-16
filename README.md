# hetzman

Hetzner Infrastructure Management Tool — DNS, NAT, IP pools, and Incus VMs over an etcd cluster.

## Install

`hetzman` runs as root (touches `/root/.ssh`, `/var/log/hetzman-tooling/`, and uses `sudo` for `iptables`/`incus`/`systemctl`). Install system-wide with pipx so the entry point lands at `/usr/local/bin/hetzman`.

### Prerequisites (one-time)

```sh
sudo apt install pipx python3-venv
```

### Install / update / uninstall

```sh
./scripts/install.sh     # first time
./scripts/update.sh      # after `git pull`
./scripts/uninstall.sh   # remove
```

The scripts self-elevate with `sudo` and set `PIPX_HOME=/opt/pipx` + `PIPX_BIN_DIR=/usr/local/bin`, so the venv lives at `/opt/pipx/venvs/hetzman/` and the entry point lands at `/usr/local/bin/hetzman` (matching the previous setup). On systems with pipx ≥ 1.5 the equivalent one-liner is `sudo pipx install --global .`.

## Layout

```
src/hetzman/
├── cli.py              # Typer app + sub-app wiring
├── config.py           # paths, lazy settings + lazy etcd client
├── console.py          # shared Rich Console
├── logging.py          # log_message
├── etcd_kv.py          # KV helpers (get/put/delete/prefix)
├── network.py          # IP-on-interface, dnsmasq, hosts file, NAT rules
├── services.py         # systemd helpers
├── vm_helpers.py       # incus exec helpers + secure_vm_instance
└── commands/
    ├── dns.py          # dns add/remove/list
    ├── ip.py           # ip list/assign/release
    ├── port.py         # port add/remove/list
    ├── etcd_admin.py   # etcd backup/restore
    ├── system.py       # sync-apply, status, audit, secure-vm
    ├── vm.py           # vm create/delete/change + cfg install-defaults
    └── vm_users.py     # vm users add/remove/change-keys/audit
```

## Runtime requirements

`/opt/hetzman-tooling/config.ini` with:

```ini
[server]
name = ...
bridge_ip = ...
primary_interface = ...

[etcd]
endpoints = host1:port,host2:port
```

Optional:
- `/opt/hetzman-tooling/etcd-credentials` — `user:password`
- `/opt/hetzman-tooling/certs/{ca,client,client-key}.pem` — etcd TLS

`hetzman --help` works without any of these (etcd is connected lazily).
