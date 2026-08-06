#!/usr/bin/env bash
# Extend the fleet's etcd trust to a SECOND CA, without re-minting a single
# existing leaf certificate.
#
# Why additive rather than a full rotation: etcd loads ETCD_TRUSTED_CA_FILE and
# ETCD_PEER_TRUSTED_CA_FILE into a Go CertPool, which accepts a concatenated PEM
# bundle. Trusting {old CA, new CA} everywhere lets a NEW node present new-CA
# certs while every existing node keeps its old-CA certs untouched — one rolling
# restart instead of the three a real rotation needs.
#
# Run this from an existing fleet node (it needs the root SSH key and the pinned
# known_hosts). It is a prerequisite for scripts/bootstrap-node.sh whenever the
# original CA key is unavailable.
#
#   sudo ./scripts/etcd-ca-rollout.sh --ca-dir /root/etcd-ca --create-ca
#   sudo ./scripts/etcd-ca-rollout.sh --ca-dir /root/etcd-ca --dry-run
#
# Safety properties:
#   * every existing leaf is verified against the bundle BEFORE any etcd is
#     restarted — a bad bundle would otherwise cost one voter per restart;
#   * nodes are done ONE AT A TIME, each gated by the same quorum guard used for
#     reboots (core/nodes.py:assess_reboot) and not left until the member has
#     genuinely rejoined and caught its raft log up (member_caught_up);
#   * every remote edit keeps a timestamped backup and is rolled back if etcd
#     fails to come back.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/etcd-pki.sh
source "$REPO_DIR/scripts/lib/etcd-pki.sh"

GUARD="$REPO_DIR/scripts/lib/etcd_guard.py"
HETZMAN_PY=/opt/pipx/venvs/hetzman/bin/python

ETCD_CERT_DIR=/etc/etcd/certs
ETCD_CONF=/etc/etcd.conf
TOOLING_CERTS=/opt/hetzman-tooling/certs
BUNDLE_NAME=ca-bundle.pem

CA_DIR=""
CREATE_CA=0
DRY_RUN=0
ACCEPT_DOWNTIME=0
NEW_CA_CN="etcd-ca-$(date +%Y)"

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "warning: $*" >&2; }
run()  { if (( DRY_RUN )); then echo "  [dry-run] $*"; else "$@"; fi; }

usage() {
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --ca-dir)    CA_DIR=$2; shift 2 ;;
        --ca-cn)     NEW_CA_CN=$2; shift 2 ;;
        --create-ca) CREATE_CA=1; shift ;;
        --dry-run)   DRY_RUN=1; shift ;;
        --accept-downtime) ACCEPT_DOWNTIME=1; shift ;;
        -h|--help)   usage 0 ;;
        *)           die "unknown argument: $1 (try --help)" ;;
    esac
done

[[ -n $CA_DIR ]] || die "--ca-dir is required"
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"
[[ -x $HETZMAN_PY ]] || die "hetzman interpreter not found at $HETZMAN_PY"

# --------------------------------------------------------------------------
# Fleet topology, straight from the registry (never hand-maintained here)

info "Reading the fleet registry"
REGISTRY_JSON=$("$HETZMAN_PY" "$GUARD" registry-json) \
    || die "could not read the registry (is etcd reachable?)"

mapfile -t NODES < <(
    printf '%s' "$REGISTRY_JSON" | "$HETZMAN_PY" -c '
import json, sys
# NB: no f-string subscripting here — this source is embedded in a
# single-quoted bash string, so an escaped inner quote never reaches Python.
for name, n in sorted(json.load(sys.stdin).items()):
    print(name + "\t" + n["vswitch_ip"])
'
)
(( ${#NODES[@]} > 0 )) || die "registry is empty"
info "Fleet: ${#NODES[@]} nodes"
printf '    %s\n' "${NODES[@]}"

THIS_NODE=$(hostname)

# Count VOTING members only. etcdctl's json carries isLearner; the python etcd3
# library this tool otherwise uses does not expose it, so ask etcdctl directly.
voting_member_count() {
    /usr/local/bin/etcdctl \
        --endpoints="https://127.0.0.1:2379" \
        --cacert="$ETCD_CERT_DIR/ca.pem" \
        --cert="$TOOLING_CERTS/client.pem" \
        --key="$TOOLING_CERTS/client-key.pem" \
        member list -w json 2>/dev/null \
    | "$HETZMAN_PY" -c '
import json, sys
try:
    ms = json.load(sys.stdin)["members"]
except Exception:
    print(0); raise SystemExit
print(sum(1 for m in ms if not m.get("isLearner")))
' 2>/dev/null || echo 0
}

# on_node <ip> <cmd...> — run locally when the target is this box, else over SSH
# with the same strict host-key policy hetzman's own executor uses.
on_node() {
    local ip=$1; shift
    if ip -o addr show | grep -qw "$ip"; then
        "$@"
    else
        ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
            "root@$ip" "$(printf '%q ' "$@")"
    fi
}

copy_to_node() {
    local ip=$1 src=$2 dst=$3
    if ip -o addr show | grep -qw "$ip"; then
        install -m 0644 "$src" "$dst"
    else
        scp -q -o BatchMode=yes -o StrictHostKeyChecking=yes "$src" "root@$ip:$dst"
    fi
}

# --------------------------------------------------------------------------
# 1. New CA + bundle

if (( CREATE_CA )); then
    info "Creating a new CA in $CA_DIR (CN=$NEW_CA_CN)"
    if (( DRY_RUN )); then
        echo "  [dry-run] pki_new_ca $CA_DIR $NEW_CA_CN"
    else
        pki_new_ca "$CA_DIR" "$NEW_CA_CN"
        cat <<EOF

  *** BACK UP $CA_DIR/ca-key.pem NOW, OFF THIS MACHINE. ***
  Losing the previous CA key is what made this rollout necessary.

EOF
    fi
fi

# In a dry run --create-ca has not actually made the CA yet, so its absence
# is expected rather than an error.
if ! (( DRY_RUN && CREATE_CA )); then
    [[ -r $CA_DIR/ca.pem ]] || die "no CA cert at $CA_DIR/ca.pem (use --create-ca?)"
fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
BUNDLE="$WORK/$BUNDLE_NAME"

info "Building the trust bundle (old CA + new CA)"
if (( DRY_RUN )) && [[ ! -r $CA_DIR/ca.pem ]]; then
    echo "  [dry-run] would bundle $ETCD_CERT_DIR/ca.pem + $CA_DIR/ca.pem"
else
    pki_bundle "$BUNDLE" "$ETCD_CERT_DIR/ca.pem" "$CA_DIR/ca.pem" >/dev/null
    echo "    $(grep -c 'BEGIN CERTIFICATE' "$BUNDLE") certificates in the bundle"
fi

# --------------------------------------------------------------------------
# 2. Pre-flight: EVERY existing leaf must verify against the bundle first

info "Pre-flight: verifying every existing leaf against the new bundle"
preflight_failed=0
for entry in "${NODES[@]}"; do
    name=${entry%%$'\t'*}; ip=${entry##*$'\t'}
    echo "  --- $name ($ip)"
    node_tmp="$WORK/$name"; mkdir -p "$node_tmp"
    fetched=()
    for leaf in etcd-server.pem etcd-peer.pem; do
        if on_node "$ip" cat "$ETCD_CERT_DIR/$leaf" >"$node_tmp/$leaf" 2>/dev/null \
           && [[ -s $node_tmp/$leaf ]]; then
            fetched+=("$node_tmp/$leaf")
        else
            echo "    MISSING  $ETCD_CERT_DIR/$leaf" >&2
            preflight_failed=1
        fi
    done
    if on_node "$ip" cat "$TOOLING_CERTS/client.pem" >"$node_tmp/client.pem" 2>/dev/null \
       && [[ -s $node_tmp/client.pem ]]; then
        fetched+=("$node_tmp/client.pem")
    fi
    if (( ${#fetched[@]} )); then
        pki_verify "$BUNDLE" "${fetched[@]}" || preflight_failed=1
    fi
done

(( preflight_failed == 0 )) \
    || die "pre-flight failed: the bundle does not validate every current leaf — NOT restarting anything"
info "Pre-flight passed: the bundle validates every current certificate"

# --------------------------------------------------------------------------
# 3. Rolling install, one node at a time

install_bundle_on() {
    local name=$1 ip=$2
    local stamp; stamp=$(date +%s)

    info "[$name] quorum guard"
    if (( DRY_RUN )); then
        echo "  [dry-run] $HETZMAN_PY $GUARD can-restart $name"
    elif ! "$HETZMAN_PY" "$GUARD" can-restart "$name"; then
        # A single-VOTER cluster (learners excluded — they never vote) always
        # fails this guard: there is no other voter to hold quorum while the only
        # one restarts. That is a true statement, not a reason to refuse forever
        # — restarting etcd on a one-voter fleet simply means brief downtime.
        # Anywhere else, a refusal means real danger, so only this specific case
        # is overridable, and only with an explicit acknowledgement.
        if [[ $(voting_member_count) -eq 1 ]] && (( ACCEPT_DOWNTIME )); then
            warn "[$name] single-voter cluster: etcd will be UNAVAILABLE during the restart"
            warn "[$name] proceeding because --accept-downtime was given"
        else
            [[ $(voting_member_count) -eq 1 ]] && \
                warn "single-voter cluster: re-run with --accept-downtime to accept the outage"
            die "[$name] refused by the quorum guard; fix cluster health first"
        fi
    fi

    info "[$name] installing $BUNDLE_NAME"
    run copy_to_node "$ip" "$BUNDLE" "$ETCD_CERT_DIR/$BUNDLE_NAME"
    run on_node "$ip" chown etcd:etcd "$ETCD_CERT_DIR/$BUNDLE_NAME"
    run on_node "$ip" chmod 0644 "$ETCD_CERT_DIR/$BUNDLE_NAME"
    # hetzman's own client reads this path (config.py:ETCD_CA_CERT)
    run copy_to_node "$ip" "$BUNDLE" "$TOOLING_CERTS/$BUNDLE_NAME"

    info "[$name] repointing trusted-CA settings in $ETCD_CONF"
    run on_node "$ip" cp -a "$ETCD_CONF" "$ETCD_CONF.bak-$stamp"
    run on_node "$ip" sed -i -E \
        "s#^(ETCD_TRUSTED_CA_FILE|ETCD_PEER_TRUSTED_CA_FILE)=.*#\\1=$ETCD_CERT_DIR/$BUNDLE_NAME#" \
        "$ETCD_CONF"

    if ! (( DRY_RUN )); then
        local applied
        applied=$(on_node "$ip" grep -c "TRUSTED_CA_FILE=$ETCD_CERT_DIR/$BUNDLE_NAME" "$ETCD_CONF" || true)
        [[ $applied == 2 ]] \
            || die "[$name] expected 2 trusted-CA lines to point at the bundle, got ${applied:-0}"
    fi

    info "[$name] restarting etcd"
    run on_node "$ip" systemctl restart etcd

    info "[$name] waiting for the member to rejoin and catch up"
    if (( DRY_RUN )); then
        echo "  [dry-run] $HETZMAN_PY $GUARD wait-caught-up $name"
    elif ! "$HETZMAN_PY" "$GUARD" wait-caught-up "$name"; then
        warn "[$name] did not come back — rolling $ETCD_CONF back and restarting"
        on_node "$ip" cp -a "$ETCD_CONF.bak-$stamp" "$ETCD_CONF" || true
        on_node "$ip" systemctl restart etcd || true
        die "[$name] failed to rejoin after the trust change; remaining nodes untouched"
    fi
    info "[$name] done"
}

for entry in "${NODES[@]}"; do
    install_bundle_on "${entry%%$'\t'*}" "${entry##*$'\t'}"
done

# --------------------------------------------------------------------------
# 4. New client cert from the new CA (also clears the old one's expiry)

info "Minting a new hetzman client certificate from the new CA"
if (( DRY_RUN )); then
    echo "  [dry-run] pki_mint_client $CA_DIR $WORK/client"
else
    mkdir -p "$WORK/client"
    pki_mint_client "$CA_DIR" "$WORK/client" >/dev/null
    pki_verify "$BUNDLE" "$WORK/client/client.pem" >/dev/null \
        || die "the new client cert does not verify against the bundle"
fi

for entry in "${NODES[@]}"; do
    name=${entry%%$'\t'*}; ip=${entry##*$'\t'}
    info "[$name] installing the new client certificate"
    stamp=$(date +%s)
    run on_node "$ip" cp -a "$TOOLING_CERTS/client.pem"     "$TOOLING_CERTS/client.pem.bak-$stamp"
    run on_node "$ip" cp -a "$TOOLING_CERTS/client-key.pem" "$TOOLING_CERTS/client-key.pem.bak-$stamp"
    run copy_to_node "$ip" "$WORK/client/client.pem"     "$TOOLING_CERTS/client.pem"
    run copy_to_node "$ip" "$WORK/client/client-key.pem" "$TOOLING_CERTS/client-key.pem"
    run on_node "$ip" chmod 0600 "$TOOLING_CERTS/client-key.pem"

    # Prove the new client cert actually authenticates before moving on.
    if ! (( DRY_RUN )); then
        on_node "$ip" hetzman node list >/dev/null \
            || die "[$name] hetzman cannot reach etcd with the new client cert; backups are at *.bak-$stamp"
    fi
done

cat <<EOF

==> Rollout complete.

    Trusted CAs now: old etcd-ca + $NEW_CA_CN (bundle at $ETCD_CERT_DIR/$BUNDLE_NAME)
    Existing leaves are untouched and still valid.
    New nodes can now be minted from $CA_DIR and will be trusted fleet-wide.

    Verify with:
      hetzman node-sync --check          # on each node
      $HETZMAN_PY $GUARD members

    Reminder: back up $CA_DIR/ca-key.pem off-machine.
EOF
