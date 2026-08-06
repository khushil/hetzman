#!/usr/bin/env bash
# Bring a new Hetzner dedicated server into the HetzMan fleet: attach it to the
# vSwitch, stand up its Incus bridge, join etcd, install hetzman and register it
# so node-sync converges the rest.
#
# This is the "full remote provisioning is a separate command" referenced by
# src/hetzman/commands/node.py:node_add. Run it as root ON THE NEW BOX.
#
#   sudo ./scripts/bootstrap-node.sh \
#       --name         htz-hel1-dc9-bm-01 \
#       --vswitch-ip   10.0.0.5 \
#       --bridge-ip    10.100.5.1 \
#       --public-block 1.2.3.4/32 \
#       --etcd-name    etcd-dc9 \
#       --ca-dir       /root/etcd-ca \
#       --join-peer    10.0.0.1
#
# Prerequisites:
#   * the server is already attached to the vSwitch in Hetzner Robot with the
#     right VLAN id (this script configures the OS only, never Robot);
#   * <ca-dir> holds ca.pem + ca-key.pem and a ca-bundle.pem the fleet already
#     trusts — see scripts/etcd-ca-rollout.sh;
#   * the fleet's etcd is healthy.
#
# Design notes:
#   * The node joins etcd as a LEARNER. Learners do not count toward quorum, so
#     the join and catch-up window carries no quorum risk at all; promotion to a
#     voter is the last step and is gated by core/nodes.py:assess_addition.
#   * Nothing that node-sync manages is hand-written here — not the iptables
#     base, not dnsmasq, not the systemd units. A partial base ruleset with
#     INPUT DROP and no etcd accepts would lock this box out of the cluster it
#     just joined.
#   * Every stage detects its own completion, so a failed run is re-runnable.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/etcd-pki.sh
source "$REPO_DIR/scripts/lib/etcd-pki.sh"

GUARD="$REPO_DIR/scripts/lib/etcd_guard.py"
HETZMAN_PY=/opt/pipx/venvs/hetzman/bin/python
HETZMAN_BIN=/usr/local/bin/hetzman

NETPLAN_VSWITCH=/etc/netplan/60-vswitch.yaml
NETPLAN_BRIDGE=/etc/netplan/61-incus-bridge.yaml
ETCD_CERT_DIR=/etc/etcd/certs
ETCD_CONF=/etc/etcd.conf
ETCD_DATA_DIR=/var/lib/etcd
TOOLING_DIR=/opt/hetzman-tooling
TOOLING_CERTS="$TOOLING_DIR/certs"
CONFIG_INI="$TOOLING_DIR/config.ini"
CLUSTER_TOKEN=hetzman-cluster-token
ROUTE_METRIC=100          # must match render.py:ROUTE_METRIC

NAME=""; VSWITCH_IP=""; BRIDGE_IP=""; PUBLIC_BLOCK=""; ETCD_NAME=""
CA_DIR=""; CA_BUNDLE=""; JOIN_PEER=""; ETCD_CREDS=""; PEER_HOST_KEYS=""
VLAN_ID=4000; PRIMARY_IFACE=""; MTU=1400; POOL_SIZE=""
DRY_RUN=0; PROMOTE=0; RECONCILE_INCUS=0; CERTS_PRESTAGED=0

die()  { echo "error: $*" >&2; exit 1; }
info() { echo; echo "==> $*"; }
step() { echo "  - $*"; }
warn() { echo "  ! $*" >&2; }
run()  { if (( DRY_RUN )); then echo "  [dry-run] $*"; else "$@"; fi; }

usage() { sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --name)              NAME=$2; shift 2 ;;
        --vswitch-ip)        VSWITCH_IP=$2; shift 2 ;;
        --bridge-ip)         BRIDGE_IP=$2; shift 2 ;;
        --public-block)      PUBLIC_BLOCK=$2; shift 2 ;;
        --etcd-name)         ETCD_NAME=$2; shift 2 ;;
        --ca-dir)            CA_DIR=$2; shift 2 ;;
        --ca-bundle)         CA_BUNDLE=$2; shift 2 ;;
        --join-peer)         JOIN_PEER=$2; shift 2 ;;
        --etcd-credentials)  ETCD_CREDS=$2; shift 2 ;;
        --peer-host-keys)    PEER_HOST_KEYS=$2; shift 2 ;;
        --vlan-id)           VLAN_ID=$2; shift 2 ;;
        --primary-interface) PRIMARY_IFACE=$2; shift 2 ;;
        --mtu)               MTU=$2; shift 2 ;;
        --pool-size)         POOL_SIZE=$2; shift 2 ;;
        --promote)           PROMOTE=1; shift ;;
        --reconcile-incus)   RECONCILE_INCUS=1; shift ;;
        --dry-run)           DRY_RUN=1; shift ;;
        -h|--help)           usage 0 ;;
        *)                   die "unknown argument: $1 (try --help)" ;;
    esac
done

# ==========================================================================
# Stage 1 — preflight. Refuse early; change nothing.
# ==========================================================================
stage_preflight() {
    info "Stage 1: preflight"

    for var in NAME VSWITCH_IP BRIDGE_IP PUBLIC_BLOCK ETCD_NAME CA_DIR JOIN_PEER; do
        local flag=${var,,}
        [[ -n ${!var} ]] || die "--${flag//_/-} is required"
    done
    [[ $EUID -eq 0 ]] || die "must run as root"

    CA_BUNDLE=${CA_BUNDLE:-$CA_DIR/ca-bundle.pem}
    for f in "$CA_DIR/ca.pem" "$CA_BUNDLE"; do
        [[ -r $f ]] || die "not readable: $f (see scripts/etcd-ca-rollout.sh)"
    done
    # The CA *private* key is only needed to mint leaves. When they have been
    # pre-staged (minted on the box that holds the CA and copied in), the key
    # should NOT travel here at all — a CA key that exists in one place is a CA
    # key that can't be leaked from two.
    if [[ -r $ETCD_CERT_DIR/etcd-peer.pem && -r $ETCD_CERT_DIR/etcd-server.pem ]]; then
        step "leaf certificates pre-staged; CA private key not required on this box"
        CERTS_PRESTAGED=1
    else
        [[ -r $CA_DIR/ca-key.pem ]] \
            || die "no leaves pre-staged and no CA key at $CA_DIR/ca-key.pem — cannot mint"
        CERTS_PRESTAGED=0
    fi

    grep -q "24.04" /etc/os-release || warn "not Ubuntu 24.04 — the fleet runs 24.04"
    command -v netplan >/dev/null || die "netplan not found"

    if [[ -z $PRIMARY_IFACE ]]; then
        PRIMARY_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
        [[ -n $PRIMARY_IFACE ]] || die "could not auto-detect the primary interface; pass --primary-interface"
        step "auto-detected primary interface: $PRIMARY_IFACE"
    fi
    ip link show "$PRIMARY_IFACE" >/dev/null 2>&1 || die "no such interface: $PRIMARY_IFACE"

    # netplan resolves a VLAN's `link:` against a DEFINED ethernet, not merely a
    # kernel interface — if the primary is not declared under `ethernets:` in
    # some /etc/netplan file, `netplan generate` rejects our VLAN with
    # "interface '<iface>' is not defined". Catch it here rather than at apply.
    if ! python3 - "$PRIMARY_IFACE" <<'PY'
import glob, sys, yaml
iface = sys.argv[1]
for path in glob.glob("/etc/netplan/*.yaml") + glob.glob("/etc/netplan/*.yml"):
    try:
        with open(path) as f:
            doc = yaml.safe_load(f) or {}
    except Exception:
        continue
    if iface in ((doc.get("network") or {}).get("ethernets") or {}):
        sys.exit(0)
sys.exit(1)
PY
    then
        die "$PRIMARY_IFACE is not declared under 'ethernets:' in /etc/netplan — netplan would reject the VLAN"
    fi
    step "$PRIMARY_IFACE is declared in netplan"

    VLAN_IFACE="$PRIMARY_IFACE.$VLAN_ID"

    # The registry derives vlan_id by splitting the interface name, so the name
    # must actually end in the VLAN id (commands/node.py:node_register).
    [[ ${VLAN_IFACE##*.} == "$VLAN_ID" ]] || die "vlan interface name must end in .$VLAN_ID"

    [[ $BRIDGE_IP =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]] \
        || die "--bridge-ip must be a plain IPv4 address"
    BRIDGE_SUBNET="${BASH_REMATCH[1]}.0/24"

    # A public block that is already routed here would collide in the registry.
    if ip -o addr show | grep -qw "${PUBLIC_BLOCK%%/*}"; then
        step "public block base ${PUBLIC_BLOCK%%/*} is live on this box"
    fi

    DEFAULT_ROUTE=$(ip route show default | head -1)
    [[ -n $DEFAULT_ROUTE ]] || die "no default route — refusing to touch networking"

    cat <<EOF
    node            : $NAME
    vSwitch         : $VSWITCH_IP/24 on $VLAN_IFACE (VLAN $VLAN_ID, MTU $MTU)
    Incus bridge    : $BRIDGE_IP  ($BRIDGE_SUBNET)
    public block    : $PUBLIC_BLOCK
    etcd member     : $ETCD_NAME (learner first)
    join peer       : $JOIN_PEER
    CA              : $CA_DIR/ca.pem  bundle: $CA_BUNDLE
EOF
}

# ==========================================================================
# Stage 1b — reconcile a box already set up as a STANDALONE Incus host.
#
# bootstrap-fsn1.sh leaves a working single-box platform whose networking model
# is the opposite of the fleet's in three load-bearing ways:
#
#   standalone (bootstrap-fsn1)        fleet (hetzman)
#   ---------------------------        ---------------------------------------
#   incus network create incusbr0      netplan 61-incus-bridge.yaml, UNMANAGED
#     -> Incus runs its own dnsmasq       -> the host's dnsmasq serves DHCP/DNS,
#        on the bridge                       rendered by node-sync
#   ipv4.nat=true on the network       HETZMAN_NAT_POST masquerade from etcd
#   10.60.0.0/24                       10.100.<n>.0/24 inside 10.100.0.0/16
#
# Two dnsmasqs cannot both own :53/:67 on the bridge, two NAT sources fight, and
# a bridge outside 10.100.0.0/16 gets neither masquerade nor reverse DNS (see
# render.py:CONTAINER_SUPERNET / DNS_REVERSE_ZONES — now enforced by
# registry.py:validate_registry). So this must be resolved BEFORE anything else.
# ==========================================================================
stage_reconcile_standalone() {
    info "Stage 1b: checking for a standalone Incus setup"

    if ! command -v incus >/dev/null 2>&1; then
        step "incus not installed — nothing to reconcile"
        return 0
    fi
    if ! incus info >/dev/null 2>&1; then
        step "incus not initialised — nothing to reconcile"
        return 0
    fi

    local conflicts=0 managed="" net_v4="" net_nat="" instances=""

    if incus network show incusbr0 >/dev/null 2>&1; then
        managed=$(incus network list --format csv 2>/dev/null \
                  | awk -F, '$1=="incusbr0" {print $3}')
        net_v4=$(incus network get incusbr0 ipv4.address 2>/dev/null || true)
        net_nat=$(incus network get incusbr0 ipv4.nat 2>/dev/null || true)

        if [[ $managed == "YES" ]]; then
            warn "incusbr0 is an INCUS-MANAGED network (${net_v4:-no ipv4}, ipv4.nat=${net_nat:-unset})"
            warn "  the fleet needs an UNMANAGED netplan bridge; Incus's own dnsmasq would"
            warn "  fight the host dnsmasq that node-sync manages for :53 and :67"
            conflicts=1
        fi
        if [[ $net_nat == "true" ]]; then
            warn "ipv4.nat=true on incusbr0 duplicates hetzman's HETZMAN_NAT_POST masquerade"
            conflicts=1
        fi
        if [[ -n $net_v4 && $net_v4 != "$BRIDGE_IP/24" ]]; then
            warn "incusbr0 is $net_v4, but this node is registering $BRIDGE_IP/24"
            conflicts=1
        fi
    fi

    # Proxy devices are the standalone port-forward model; the fleet forwards via
    # hetzman port-add (DNAT in HETZMAN_NAT). They do not coexist meaningfully.
    instances=$(incus list -c n --format csv 2>/dev/null || true)
    local proxies=""
    local inst
    for inst in $instances; do
        if incus config device show "$inst" 2>/dev/null | grep -q "type: proxy"; then
            proxies+="$inst "
        fi
    done
    if [[ -n $proxies ]]; then
        warn "instances with Incus proxy devices: $proxies"
        warn "  migrate these to 'hetzman port-add' after joining; they are not managed by the fleet"
    fi

    # Informational only — hetzman does not hardcode a pool name, but a fleet
    # mismatch complicates 'incus copy' migrations between nodes.
    local pools
    pools=$(incus storage list --format csv 2>/dev/null | cut -d, -f1,2 | tr '\n' ' ')
    [[ -n $pools ]] && step "storage pools: $pools (dc12 uses 'default' btrfs)"

    if (( conflicts == 0 )); then
        step "no standalone/fleet conflicts found"
        return 0
    fi

    if ! (( RECONCILE_INCUS )); then
        cat >&2 <<EOF

  This box is configured as a STANDALONE Incus host and cannot join the fleet
  as-is. Re-run with --reconcile-incus to fix it automatically (only possible
  while there are no instances), or resolve it by hand:

      incus profile device remove default eth0
      incus network delete incusbr0
      # then re-run this script; stage 7 creates the unmanaged netplan bridge
      # at $BRIDGE_IP/24 and stage 10 re-attaches the default profile.

EOF
        die "refusing to continue over a conflicting standalone Incus setup"
    fi

    if [[ -n $instances ]]; then
        die "--reconcile-incus refuses while instances exist ($(wc -w <<<"$instances") found): \
deleting incusbr0 would disconnect them. Move or delete them first."
    fi

    step "reconciling: removing the managed incusbr0 and its profile attachment"
    run bash -c "incus profile device remove default eth0 2>/dev/null || true"
    run incus network delete incusbr0
    step "incusbr0 removed; the unmanaged netplan bridge is created in stage 7"
}

# ==========================================================================
# Netplan helper — every apply must be survivable over the PUBLIC path.
# ==========================================================================
apply_netplan_guarded() {
    local path=$1 content=$2 what=$3
    local backup="$path.bak-$(date +%s)"

    if (( DRY_RUN )); then
        echo "  [dry-run] would write $path:"
        printf '%s\n' "$content" | sed 's/^/      /'
        return 0
    fi

    [[ -e $path ]] && cp -a "$path" "$backup"
    umask 077
    printf '%s' "$content" >"$path.tmp"
    chmod 0600 "$path.tmp"
    mv "$path.tmp" "$path"

    if ! netplan generate 2>&1 | sed 's/^/      /'; then
        [[ -e $backup ]] && cp -a "$backup" "$path" || rm -f "$path"
        die "$what: netplan generate rejected the config (restored)"
    fi
    netplan apply || true
    sleep 3

    # The ONLY way back into this box is the public path, so prove it survived
    # before believing the apply worked.
    if ! ip route show default | grep -q .; then
        warn "$what: default route disappeared — restoring"
        [[ -e $backup ]] && cp -a "$backup" "$path" || rm -f "$path"
        netplan apply || true
        die "$what: apply removed the default route (restored)"
    fi
    step "$what applied; public default route intact"
}

# ==========================================================================
# Stage 2 — vSwitch attach, pass A: address only.
# ==========================================================================
stage_vswitch_pass_a() {
    info "Stage 2: vSwitch attach (pass A — address only)"
    if ip -o addr show dev "$VLAN_IFACE" 2>/dev/null | grep -qw "$VSWITCH_IP"; then
        step "$VSWITCH_IP already live on $VLAN_IFACE — skipping"
        return 0
    fi
    # Routes to the other nodes' bridges come in pass B, once the registry is
    # readable. The kernel's connected route for the /24 is enough to reach every
    # peer's etcd, which is all pass B needs.
    apply_netplan_guarded "$NETPLAN_VSWITCH" "$(cat <<EOF
network:
  version: 2
  vlans:
    $VLAN_IFACE:
      id: $VLAN_ID
      link: $PRIMARY_IFACE
      addresses:
      - $VSWITCH_IP/24
      mtu: $MTU
EOF
)" "vSwitch pass A"
}

# ==========================================================================
# Stage 3 — hard gate: does the vSwitch actually carry traffic?
# ==========================================================================
stage_verify_vswitch() {
    info "Stage 3: verifying the vSwitch carries traffic"
    if (( DRY_RUN )); then echo "  [dry-run] ping $JOIN_PEER"; return 0; fi

    local tries=10 pinged=0
    for ((i = 1; i <= tries; i++)); do
        if ping -c1 -W2 "$JOIN_PEER" >/dev/null 2>&1; then
            step "peer $JOIN_PEER reachable over $VLAN_IFACE"
            pinged=1
            break
        fi
        sleep 2
    done

    if (( pinged )); then
        # A successful ping proves the vSwitch carries traffic and NOTHING MORE.
        # hetzman's base ruleset accepts ICMP from anywhere but opens 2379:2380
        # only to nodes ALREADY in the registry — so a brand-new node pings fine
        # and still cannot reach etcd. Discovering that at stage 6, after netplan
        # and package changes have landed, is far worse than discovering it here.
        if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$JOIN_PEER/2379" 2>/dev/null; then
            step "join peer's etcd client port (2379) reachable"
            return 0
        fi
        cat >&2 <<EOF

  $JOIN_PEER answers ICMP over the vSwitch, but TCP/2379 is CLOSED.

  This is expected for a node that is not registered yet: node-sync renders
  "-A INPUT -s <ip>/32 --dport 2379:2380 -j ACCEPT" only for registry members.
  Open it on $JOIN_PEER before re-running (pause the timer first, or the
  cleanup pass will reap the rule mid-bootstrap):

      systemctl stop hetzman-node-sync.timer
      iptables -I INPUT 5 -s $VSWITCH_IP/32 -p tcp -m tcp --dport 2379:2380 -j ACCEPT

  After this node registers, node-sync renders that rule permanently; then:

      systemctl start hetzman-node-sync.timer

EOF
        die "join peer's etcd port is unreachable — cannot read the registry or join"
    fi
    cat >&2 <<EOF

  The vSwitch is not passing traffic to $JOIN_PEER.

  This is exactly the failure that has had dc12 offline since 2026-08-03, so
  check it rather than working around it:
    * Robot: is this server attached to the vSwitch, with VLAN $VLAN_ID?
    * ip -d link show $VLAN_IFACE   — VLAN configured and LOWER_UP?
    * ip neigh show dev $VLAN_IFACE — any ARP resolution at all?
    * can the existing nodes still reach each other?

EOF
    die "vSwitch verification failed — refusing to continue"
}

# ==========================================================================
# Stage 5 — etcd PKI (needed before pass B: etcdctl must talk to the cluster).
# ==========================================================================
stage_etcd_pki() {
    info "Stage 5: etcd PKI"
    run install -d -m 0755 "$ETCD_CERT_DIR"
    run install -d -m 0755 "$TOOLING_CERTS"

    if (( CERTS_PRESTAGED )) || { [[ -r $ETCD_CERT_DIR/etcd-peer.pem ]] && ! (( DRY_RUN )); }; then
        step "leaf certificates already present — skipping mint"
    else
        run pki_mint_server "$CA_DIR" "$ETCD_CERT_DIR" "$VSWITCH_IP"
        run pki_mint_peer   "$CA_DIR" "$ETCD_CERT_DIR" "$VSWITCH_IP" "$ETCD_NAME" "$NAME"
        run pki_mint_client "$CA_DIR" "$TOOLING_CERTS"
    fi

    run install -m 0644 "$CA_BUNDLE" "$ETCD_CERT_DIR/ca.pem"
    run install -m 0644 "$CA_BUNDLE" "$TOOLING_CERTS/ca.pem"

    if ! (( DRY_RUN )); then
        pki_verify "$ETCD_CERT_DIR/ca.pem" \
            "$ETCD_CERT_DIR/etcd-server.pem" "$ETCD_CERT_DIR/etcd-peer.pem" \
            "$TOOLING_CERTS/client.pem" \
            || die "freshly minted certificates do not verify against the bundle"
        step "SANs: $(pki_cert_sans "$ETCD_CERT_DIR/etcd-peer.pem")"
    fi

    if [[ -n $ETCD_CREDS ]]; then
        run install -m 0600 "$ETCD_CREDS" "$TOOLING_DIR/etcd-credentials"
    fi
}

# etcdctl wrapper against the existing cluster
ETCDCTL=/usr/local/bin/etcdctl
_peer_etcdctl_as() {
    local creds_file=$1; shift
    local args=(--endpoints="https://$JOIN_PEER:2379"
                --cacert="$ETCD_CERT_DIR/ca.pem"
                --cert="$TOOLING_CERTS/client.pem"
                --key="$TOOLING_CERTS/client-key.pem")
    if [[ -r $creds_file ]]; then
        args+=(--user="$(cat "$creds_file")")
    fi
    "$ETCDCTL" "${args[@]}" "$@"
}

# Ordinary role — enough for KV reads (the registry).
peer_etcdctl() { _peer_etcdctl_as "$TOOLING_DIR/etcd-credentials" "$@"; }

# Root role — REQUIRED for Cluster RPCs (member add/promote) and Maintenance
# (endpoint status). etcd RBAC denies these to the ordinary `hetzman` user, and
# the denial surfaces only as a bare "permission denied" at the point of use.
peer_etcdctl_admin() {
    [[ -r $TOOLING_DIR/etcd-root-credentials ]] \
        || die "cluster operations need $TOOLING_DIR/etcd-root-credentials (root etcd role)"
    _peer_etcdctl_as "$TOOLING_DIR/etcd-root-credentials" "$@"
}

# ==========================================================================
# Stage 4 — packages and system objects.
# ==========================================================================
stage_packages() {
    info "Stage 4: packages and system objects"

    # bind9-dnsutils is NOT optional: node-sync shells out to `dig` in its
    # dnsmasq post-apply check, and a missing dig makes it roll back a good conf.
    local pkgs=(incus dnsmasq iptables-persistent pipx python3-venv bind9-dnsutils
                openssl rsync)
    local missing=()
    for p in "${pkgs[@]}"; do
        dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if (( ${#missing[@]} )); then
        step "installing: ${missing[*]}"
        run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
    else
        step "all packages already present"
    fi

    if ! command -v "$ETCDCTL" >/dev/null; then
        die "etcd binaries missing: install etcd/etcdctl/etcdutl 3.6.11 into /usr/local/bin first"
    fi

    # etcd.service runs User=etcd with ProtectSystem=strict + ReadWritePaths.
    if ! getent passwd etcd >/dev/null; then
        step "creating the etcd system user"
        run useradd --system --home-dir /home/etcd --shell /usr/sbin/nologin etcd
    fi
    run install -d -o etcd -g etcd -m 0700 "$ETCD_DATA_DIR"
    run chown -R etcd:etcd "$ETCD_CERT_DIR"
    run install -d -m 0755 "$TOOLING_DIR" /var/log/hetzman-tooling /var/lib/hetzman
}

# ==========================================================================
# Stage 6 — vSwitch pass B: peer routes, rendered from the registry.
# ==========================================================================
stage_vswitch_pass_b() {
    info "Stage 6: vSwitch routes (pass B — from the registry)"
    if (( DRY_RUN )); then echo "  [dry-run] read registry, rewrite $NETPLAN_VSWITCH with peer routes"; return 0; fi

    local registry
    registry=$(peer_etcdctl get --prefix /hetzman/nodes/ --print-value-only) \
        || die "could not read the registry from $JOIN_PEER"
    [[ -n $registry ]] || die "registry came back empty"

    # Routes must match render.py:render_netplan_vswitch — every OTHER node's
    # bridge_subnet via its vswitch_ip, metric 100, sorted by destination.
    local routes
    routes=$(printf '%s' "$registry" | python3 -c '
import json, sys
me = sys.argv[1]
rows = []
for line in sys.stdin.read().splitlines():
    line = line.strip()
    if not line:
        continue
    n = json.loads(line)
    if n["name"] == me:
        continue
    rows.append((n["bridge_subnet"], n["vswitch_ip"]))
for to, via in sorted(rows):
    print(f"      - to: {to}\n        via: {via}\n        metric: '"$ROUTE_METRIC"'")
' "$NAME") || die "could not parse the registry"

    [[ -n $routes ]] || die "no peer routes derived from the registry"
    step "$(grep -c 'to:' <<<"$routes") peer route(s) from the registry"

    apply_netplan_guarded "$NETPLAN_VSWITCH" "$(cat <<EOF
network:
  version: 2
  vlans:
    $VLAN_IFACE:
      id: $VLAN_ID
      link: $PRIMARY_IFACE
      addresses:
      - $VSWITCH_IP/24
      mtu: $MTU
      routes:
$routes
EOF
)" "vSwitch pass B"
}

# ==========================================================================
# Stage 7 — Incus bridge (node-sync treats this file as warn-only).
# ==========================================================================
stage_bridge() {
    info "Stage 7: Incus bridge"
    if ip -o addr show dev incusbr0 2>/dev/null | grep -qw "$BRIDGE_IP"; then
        step "incusbr0 already carries $BRIDGE_IP — skipping"
        return 0
    fi
    apply_netplan_guarded "$NETPLAN_BRIDGE" "$(cat <<EOF
network:
  version: 2
  bridges:
    incusbr0:
      addresses:
      - $BRIDGE_IP/24
      mtu: $MTU
      dhcp4: false
      dhcp6: false
      accept-ra: false
      parameters:
        stp: false
        forward-delay: 0
EOF
)" "Incus bridge"
}

# ==========================================================================
# Stage 8 — etcd config + join as a LEARNER.
# ==========================================================================
stage_etcd_join() {
    info "Stage 8: etcd configuration and learner join"

    if (( DRY_RUN )); then
        echo "  [dry-run] write $ETCD_CONF, member add --learner, start etcd"
        return 0
    fi

    # Every current peer plus ourselves, for ETCD_INITIAL_CLUSTER.
    local initial
    initial=$(peer_etcdctl_admin member list -w json | python3 -c '
import json, sys
ms = json.load(sys.stdin)["members"]
parts = []
for m in ms:
    if m.get("isLearner"):
        continue
    name = m.get("name")
    urls = m.get("peerURLs") or []
    if name and urls:
        parts.append(f"{name}={urls[0]}")
print(",".join(parts))
') || die "could not enumerate current members"
    initial="$initial,$ETCD_NAME=https://$VSWITCH_IP:2380"
    step "initial cluster: $initial"

    cat >"$ETCD_CONF" <<EOF
# $NAME etcd configuration (joined as a learner by bootstrap-node.sh)
ETCD_NAME=$ETCD_NAME
ETCD_DATA_DIR=$ETCD_DATA_DIR
ETCD_LISTEN_CLIENT_URLS=https://$VSWITCH_IP:2379,https://127.0.0.1:2379
ETCD_ADVERTISE_CLIENT_URLS=https://$VSWITCH_IP:2379
ETCD_LISTEN_PEER_URLS=https://$VSWITCH_IP:2380
ETCD_INITIAL_ADVERTISE_PEER_URLS=https://$VSWITCH_IP:2380
ETCD_INITIAL_CLUSTER=$initial
ETCD_INITIAL_CLUSTER_STATE=existing
ETCD_INITIAL_CLUSTER_TOKEN=$CLUSTER_TOKEN

# TLS for client connections
ETCD_CERT_FILE=$ETCD_CERT_DIR/etcd-server.pem
ETCD_KEY_FILE=$ETCD_CERT_DIR/etcd-server-key.pem
ETCD_TRUSTED_CA_FILE=$ETCD_CERT_DIR/ca.pem
ETCD_CLIENT_CERT_AUTH=true

# TLS for peer connections
ETCD_PEER_CERT_FILE=$ETCD_CERT_DIR/etcd-peer.pem
ETCD_PEER_KEY_FILE=$ETCD_CERT_DIR/etcd-peer-key.pem
ETCD_PEER_TRUSTED_CA_FILE=$ETCD_CERT_DIR/ca.pem
ETCD_PEER_CLIENT_CERT_AUTH=true

# Compaction and performance
ETCD_SNAPSHOT_COUNT=10000
ETCD_AUTO_COMPACTION_MODE=periodic
ETCD_AUTO_COMPACTION_RETENTION=1
EOF
    chmod 0644 "$ETCD_CONF"

    cat >/etc/systemd/system/etcd.service <<EOF
[Unit]
Description=etcd key-value store
After=network-online.target
Wants=network-online.target
Before=hetzman-instance-watcher.service

[Service]
Type=notify
User=etcd
Group=etcd
EnvironmentFile=$ETCD_CONF
ExecStartPre=/bin/sh -c 'until ip addr show | grep -q "$VSWITCH_IP/"; do sleep 1; done'
ExecStart=/usr/local/bin/etcd
Restart=always
RestartSec=10
LimitNOFILE=40000

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$ETCD_DATA_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

    install -d -m 0755 /etc/systemd/system/etcd.service.d
    cat >/etc/systemd/system/etcd.service.d/priority.conf <<'EOF'
# etcd fsync-latency priority (matches the rest of the fleet)
[Service]
Nice=-10
CPUWeight=10000
IOSchedulingClass=best-effort
IOSchedulingPriority=0
EOF
    systemctl daemon-reload

    # Join as a LEARNER: no quorum impact while it catches up.
    if peer_etcdctl_admin member list | grep -q "$VSWITCH_IP:2380"; then
        step "member for $VSWITCH_IP already exists — skipping member add"
    else
        step "adding $ETCD_NAME as a learner"
        peer_etcdctl_admin member add "$ETCD_NAME" --learner \
            --peer-urls="https://$VSWITCH_IP:2380" \
            || die "member add failed"
    fi

    step "starting etcd"
    systemctl enable --now etcd
    sleep 5
    # A learner REJECTS client RPCs ("etcdserver: rpc not supported for learner"),
    # so querying its own endpoint for health can NEVER succeed. Ask the join peer
    # instead: a member only acquires a name in the cluster's member list once it
    # has actually started and published itself, which is the real liveness signal.
    for ((i = 1; i <= 30; i++)); do
        if peer_etcdctl_admin member list -w json 2>/dev/null | python3 -c '
import json, sys
ip = sys.argv[1]
try:
    ms = json.load(sys.stdin)["members"]
except Exception:
    sys.exit(1)
for m in ms:
    if any(u.split("//", 1)[-1].rsplit(":", 1)[0] == ip for u in (m.get("peerURLs") or [])):
        sys.exit(0 if m.get("name") else 1)
sys.exit(1)
' "$VSWITCH_IP"; then
            step "etcd is up and published as a started cluster member"
            return 0
        fi
        sleep 5
    done
    die "local etcd did not join the cluster; check: journalctl -u etcd"
}

# ==========================================================================
# Stage 9 — SSH trust. Deliberately NOT automatic host-key acceptance.
# ==========================================================================
stage_ssh_trust() {
    info "Stage 9: SSH trust"

    if [[ ! -f /root/.ssh/id_rsa ]]; then
        step "generating a root keypair"
        run install -d -m 0700 /root/.ssh
        run ssh-keygen -q -t rsa -b 4096 -N "" -f /root/.ssh/id_rsa -C "root@$NAME"
    else
        step "root keypair already present"
    fi

    if [[ -n $PEER_HOST_KEYS ]]; then
        step "pinning peer host keys from $PEER_HOST_KEYS"
        run bash -c "cat '$PEER_HOST_KEYS' >>/root/.ssh/known_hosts && sort -u -o /root/.ssh/known_hosts /root/.ssh/known_hosts"
        run chmod 0600 /root/.ssh/known_hosts
    else
        # hetzman's executor uses StrictHostKeyChecking=yes against a pinned
        # known_hosts precisely so vswitch IPs cannot be spoofed. Scanning keys
        # here would be TOFU and would quietly undo that, so it is the operator's
        # step, not ours.
        warn "no --peer-host-keys given; hetzman's SSH executor will not reach peers from this node"
        warn "supply the peers' host keys and re-run this stage, or run fleet commands from an existing node"
    fi

    if ! (( DRY_RUN )); then
        cat <<EOF

    Distribute this node's public key to each existing node (run from one of them):

      echo '$(cat /root/.ssh/id_rsa.pub 2>/dev/null || echo "<generated on first real run>")' \\
          >> /root/.ssh/authorized_keys

    And pin THIS node's host key on each existing node:

      ssh-keyscan -H $VSWITCH_IP >> /root/.ssh/known_hosts

EOF
    fi
}

# ==========================================================================
# Stage 10 — hetzman + Incus.
# ==========================================================================
stage_hetzman() {
    info "Stage 10: hetzman and Incus"

    if [[ ! -x $HETZMAN_BIN ]]; then
        step "installing hetzman via scripts/install.sh"
        run "$REPO_DIR/scripts/install.sh"
    else
        step "hetzman already installed"
    fi

    # A minimal config.ini; node-sync rewrites it from the registry afterwards
    # (config.py:write_config).
    if (( DRY_RUN )); then
        echo "  [dry-run] write $CONFIG_INI"
    else
        local endpoints
        endpoints=$(peer_etcdctl_admin member list -w json | python3 -c '
import json, sys
hosts = []
for m in json.load(sys.stdin)["members"]:
    for u in (m.get("clientURLs") or []):
        hosts.append(u.split("//",1)[-1].rsplit(":",1)[0])
print(",".join(f"{h}:2379" for h in sorted(set(hosts))))
')
        [[ -n $endpoints ]] || endpoints="$JOIN_PEER:2379"
        endpoints="$endpoints,$VSWITCH_IP:2379"
        cat >"$CONFIG_INI" <<EOF
[server]
name = $NAME
bridge_ip = $BRIDGE_IP
vswitch_ip = $VSWITCH_IP
primary_interface = $PRIMARY_IFACE
vlan_interface = $VLAN_IFACE

[etcd]
endpoints = $endpoints
EOF
        chmod 0644 "$CONFIG_INI"
        step "wrote $CONFIG_INI"
    fi

    if ! incus info >/dev/null 2>&1; then
        # Sized from --pool-size, NOT from /root/dc12-preseed.yaml: that preseed
        # claims 300GB while dc12's live pool image is 560GB, so it has drifted.
        local size_gb=${POOL_SIZE:-100}
        size_gb=${size_gb//[^0-9]/}          # accept 500, 500GB or 500GiB
        [[ -n $size_gb ]] || die "--pool-size must contain a number of GiB"
        step "initialising Incus with a ${size_gb}GiB btrfs pool"
        run incus admin init --auto --storage-backend btrfs --storage-create-loop "$size_gb"
    fi
    run incus config set core.https_address "$VSWITCH_IP:8443"

    # `device set` FAILS on a device that does not exist, and after
    # --reconcile-incus removed the managed network's NIC there is none.
    # Swallowing that error would leave the default profile with no NIC at all,
    # so every container created later would come up with no network.
    if incus profile device get default eth0 nictype >/dev/null 2>&1; then
        step "updating eth0 on the default profile"
        run incus profile device set default eth0 parent incusbr0
        run incus profile device set default eth0 mtu "$MTU"
    else
        step "adding eth0 to the default profile (bridged to incusbr0, mtu $MTU)"
        run incus profile device add default eth0 nic \
            nictype=bridged parent=incusbr0 mtu="$MTU"
    fi
}

# ==========================================================================
# Stage 11 — register in the fleet registry, then converge.
# ==========================================================================
stage_register() {
    info "Stage 11: registering in the fleet registry"
    # node register --from-config runs validate_registry (but NOT registry_guard),
    # so it can close the very registry/membership mismatch the join opened.
    run "$HETZMAN_BIN" node register --from-config --public-block "$PUBLIC_BLOCK"
}

stage_converge() {
    info "Stage 12: convergence"
    step "node-sync on this node"
    run "$HETZMAN_BIN" node-sync --apply

    if (( DRY_RUN )); then return 0; fi

    local peers
    peers=$("$HETZMAN_PY" "$GUARD" registry-json | python3 -c '
import json, sys
me = sys.argv[1]
for name, n in sorted(json.load(sys.stdin).items()):
    if name != me:
        print(n["vswitch_ip"])
' "$NAME")

    echo
    echo "    Run node-sync on the existing nodes so they learn the route to"
    echo "    $BRIDGE_SUBNET and open 2379:2380 to $VSWITCH_IP."
    echo "    node-sync is local-only (no delegation), so drive it from an"
    echo "    existing node, which already has the keys and pinned host keys:"
    echo
    for ip in $peers; do
        echo "      ssh root@$ip hetzman node-sync --apply"
    done
    echo
    echo "    (Their hetzman-node-sync.timer would also pick this up within ~13 min.)"
}

# ==========================================================================
# Stage 13 — promote the learner. Last, and guarded.
# ==========================================================================
stage_promote() {
    info "Stage 13: promoting the learner to a voting member"
    if ! (( PROMOTE )); then
        cat <<EOF
    Skipped (no --promote). The node is a healthy LEARNER: it replicates but
    does not vote, so the cluster's fault tolerance is unchanged.

    Promote once the fleet has converged and every existing member is healthy:

      $HETZMAN_PY $GUARD can-add        # margin guard (assess_addition)
      $ETCDCTL member list              # find the learner's id
      $ETCDCTL member promote <id>

EOF
        return 0
    fi

    if (( DRY_RUN )); then echo "  [dry-run] can-add guard, then member promote"; return 0; fi

    "$HETZMAN_PY" "$GUARD" can-add \
        || die "refusing to promote: the cluster has no spare healthy voter"

    # Match on the parsed peer URL, not a text grep — an IP is a regex that would
    # also match unrelated members, and promoting the wrong one is unrecoverable.
    local id
    id=$(peer_etcdctl_admin member list -w json | python3 -c '
import json, sys
ip = sys.argv[1]
for m in json.load(sys.stdin)["members"]:
    if any(u.split("//", 1)[-1].rsplit(":", 1)[0] == ip for u in (m.get("peerURLs") or [])):
        print(format(m["ID"], "x"))
        break
' "$VSWITCH_IP")
    [[ -n $id ]] || die "could not find the learner's member id for $VSWITCH_IP"
    step "promoting member $id"
    peer_etcdctl_admin member promote "$id" || die "promote failed"
    "$HETZMAN_PY" "$GUARD" wait-caught-up "$NAME"
}

# ==========================================================================
main() {
    stage_preflight
    stage_reconcile_standalone
    stage_vswitch_pass_a
    stage_verify_vswitch
    stage_packages
    stage_etcd_pki
    stage_vswitch_pass_b
    stage_bridge
    stage_etcd_join
    stage_ssh_trust
    stage_hetzman
    stage_register
    stage_converge
    stage_promote

    info "Bootstrap complete for $NAME"
    cat <<EOF
    Verify:
      hetzman node list
      hetzman node-sync --check                 # on all nodes; expect clean
      $ETCDCTL member list                      # learner (or voter if promoted)
      ping $JOIN_PEER
      test ! -e /var/lib/hetzman/dnsmasq-down
EOF
}

main "$@"
