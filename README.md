# hetzman

Hetzner Infrastructure Management Tool — DNS, NAT, IP pools, and Incus VMs over an etcd cluster.

Available as a scriptable CLI **and** an interactive TUI control center
(`hetzman tui`). Both share one UI-agnostic core layer (`src/hetzman/core/`):
reads return dataclasses, writes are progress-streaming generators, so the CLI
and the TUI consume identical logic.

## Interactive control center

```sh
hetzman tui
```

A Textual app (runs locally or over SSH) with:

- **Dashboard** — live system status + fleet-health summary.
- **Fleet / IPs / DNS / Ports** tabs — auto-refreshing tables.
- **Mutations** — `a` add, `d` delete on a domain tab; destructive actions
  confirm first; every operation streams its progress into a shared log panel.
- **Command palette** (`ctrl+\`) — Create/Delete VM, Assign IP, Add DNS, Add
  port forward, refresh, and jump-to-tab.

Data is read from the (blocking) etcd-backed core only inside Textual thread
workers, so the UI never blocks; an etcd outage degrades to a banner, not a
crash.

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
├── cli.py              # Typer app + sub-app wiring (incl. `tui` command)
├── config.py           # paths, lazy settings + lazy etcd client
├── console.py          # shared Rich Console (CLI only — never imported by core/)
├── logging.py          # log_message
├── etcd_kv.py          # KV helpers (get/put/delete/prefix/compare-and-swap)
├── network.py          # IP-on-interface, dnsmasq, hosts file, NAT rules
├── services.py         # systemd helpers
├── vm_helpers.py       # incus exec helpers + secure_vm_instance
├── core/               # UI-agnostic service layer (CLI + TUI both consume it)
│   ├── events.py       # ProgressEvent / OpResult / ProgressGen contract
│   ├── errors.py       # CoreError hierarchy (Validation/NotFound/Privilege/EtcdUnavailable)
│   ├── models.py       # frozen read-side dataclasses
│   ├── reads.py        # side-effect-free reads -> models (no console)
│   ├── concurrency.py  # serialises etcd access for the multi-worker TUI
│   ├── dns.py / ip.py / ports.py / vms.py / users.py / templates.py  # write generators
│   └── privilege.py    # require_root()
├── tui/                # Textual control center (a core consumer)
│   ├── app.py          # HetzmanApp: tabs, workers, mutation streaming, palette
│   ├── widgets.py      # LogPanel, Banner
│   └── modals.py       # ConfirmModal + input forms
└── commands/
    ├── _render.py      # drive(): renders a core generator to the console
    ├── dns.py          # dns add/remove/list
    ├── ip.py           # ip list/assign/release
    ├── port.py         # port add/remove/list
    ├── etcd_admin.py   # etcd backup/restore
    ├── system.py       # sync-apply, status, audit, secure-vm
    ├── tui.py          # `hetzman tui`
    ├── vm.py           # vm create/delete/change + cfg install-defaults
    └── vm_users.py     # vm users add/remove/change-keys/audit
```

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'   # editable + pytest, pytest-mock, textual-dev
.venv/bin/python -m pytest          # run the suite
```

The `core/` layer is console-free by construction — `tests/test_core_import_isolation.py`
is a tripwire that fails if any core (or low-level) module imports the Rich
console, which would corrupt the Textual compositor from a worker thread.

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
