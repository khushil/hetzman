# Host ports

Opens a port on a fleet **host's own** firewall, for a service running on the
host itself.

Not to be confused with `hetzman port-add`, which DNATs a public port through to
an **instance**. The two are named apart deliberately:

| command | opens | for |
|---|---|---|
| `hetzman port-add <instance> <pub> <priv>` | a DNAT in `HETZMAN_NAT` | a service in an Incus instance |
| `hetzman host port-open <port>` | an ACCEPT in `HETZMAN_HOSTPORTS` | a service on the host |

## Usage

```sh
sudo hetzman host port-open 1666 --protocol tcp --description "Perforce p4d (SSL)"
sudo hetzman host port-open 8080 --source 10.0.0.0/24        # scoped to the vSwitch
sudo hetzman host port-list [--all]
sudo hetzman host port-close 1666
sudo hetzman node-sync --apply        # or wait for the 15-minute timer
```

`--node` targets another host; it defaults to the host you run it on and the
resolved name is echoed back, because opening a port on the wrong node is a
quiet mistake.

## Why a dedicated chain

Rules live in an owned `HETZMAN_HOSTPORTS` chain that node-sync **flushes and
rebuilds from etcd** on every apply, rather than being appended to `INPUT`.

The live-ensure path is `iptables -C || -A`. It can only *add*. If host ports
were appended to `INPUT`, closing one would remove the etcd key, report success,
and leave the port **open until the next reboot** - while `node-sync --check`
printed "Clean", because nothing in the drift computation looks for rules that
are present but no longer wanted. `iptables_cleanup_plan` would not catch it
either: its `filter` branch matches only stale etcd accepts and skips everything
else.

Flush-and-rebuild makes removal correct by construction. `--check` reports
host-port drift in both directions (`-` live-but-unwanted, `+` wanted-but-absent).

This mirrors `network.py:apply_nat_rules`, which reconciles the NAT chains the
same way.

## etcd shape

One key per entry, per node:

```
/hetzman/host-ports/<node>/<port>-<proto>  ->  {port, protocol, source, description}
```

Per-key rather than a JSON list in one key, so add is a `put`, close is a
`delete`, and two operators editing different ports cannot clobber each other -
no read-modify-write, no CAS window. Per-**node**, so opening a port on one host
never opens it on the peer. A node with no keys renders exactly what it rendered
before this feature existed (asserted by
`test_host_ports_absent_is_byte_identical_to_empty`).

## Where validation happens

**Renderer narrows, CLI shouts.**

Malformed operator data must never reach the renderer: a `RenderError` inside
`render_iptables_base` aborts the *entire* node-sync run - no DNS, no netplan, no
firewall, no systemd - silently, on a 15-minute timer. So
`commands/node.py:_host_ports` filters and logs bad entries and returns `[]` on
any read failure, exactly as `_trusted_dns_clients` does.
`render._assert_host_ports_safe` remains only as a backstop for a code bug.

Policy lives in the CLI, where the operator sees the error:

- **Reserved ports** (`22, 53, 2379, 2380, 5432, 8443, 8200, 8201`) are refused
  with exit 2. They are either already rendered by node-sync - a second source of
  truth would drift - or must never face the internet by accident (OpenBao). The
  set is derived from the renderer's own constants so it cannot rot separately.
- Duplicates are **de-duplicated** in the renderer, never raised. A duplicate
  must not be a one-command way to wedge node-sync on a remote box.

`0.0.0.0/0` is a **valid** source here. Unlike the `:53` ACL - where
`dns_acl_source_ok` demands a private, narrow CIDR because an open resolver is a
hazard - a host port facing the internet is frequently the entire point. Do not
reuse that predicate; `host_port_ok` checks shape only.

## Note on the `:53` guard

`_assert_dns_acl_safe` previously tested `"--dport 53" in line` as a substring.
`--dport 53` is a prefix of `--dport 5353` (and `530`, `53000`), so opening any
such port would have dragged it into the `:53` ACL check and raised
`RenderError` - wedging node-sync entirely. It is now a token match. Regression:
`test_dns_acl_guard_is_token_matched_not_substring`.
