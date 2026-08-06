#!/usr/bin/env bash
# Shared openssl helpers for the fleet's etcd PKI.
#
# Sourced by scripts/etcd-ca-rollout.sh and scripts/bootstrap-node.sh; never run
# directly. Every function is idempotent-safe in the sense that it writes to a
# temp file and moves it into place only on success, so a failed mint never
# leaves a half-written key or cert behind.
#
# Shape matches the fleet's existing certs: RSA 2048, SHA-256, CN-only subject.
# The one deliberate difference is that new leaves carry explicit keyUsage /
# extendedKeyUsage extensions. The originals carry none, which Go's TLS stack
# treats as "valid for any usage" — the new ones are strictly narrower and
# interoperate with the old ones unchanged.
#
#   ca dir layout:   <ca-dir>/ca.pem, <ca-dir>/ca-key.pem
#   leaf output:     <out-dir>/<name>.pem, <out-dir>/<name>-key.pem

set -euo pipefail

PKI_KEY_BITS="${PKI_KEY_BITS:-2048}"
PKI_CA_DAYS="${PKI_CA_DAYS:-3650}"
PKI_LEAF_DAYS="${PKI_LEAF_DAYS:-3650}"

pki_die() { echo "pki: $*" >&2; exit 1; }

# _pki_mint <ca-dir> <out-dir> <name> <CN> <ext-block>
# Generates a key + CSR and signs it with the CA using <ext-block> as the x509
# extension section. Private keys are created under umask 077 and land at 0600.
_pki_mint() {
    local ca_dir=$1 out_dir=$2 name=$3 cn=$4 exts=$5
    local ca_cert="$ca_dir/ca.pem" ca_key="$ca_dir/ca-key.pem"

    [[ -r $ca_cert ]] || pki_die "CA cert not readable: $ca_cert"
    [[ -r $ca_key  ]] || pki_die "CA key not readable: $ca_key"

    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064  # expand $tmp now, not at trap time
    trap "rm -rf '$tmp'" RETURN

    cat >"$tmp/ext.cnf" <<EOF
[ req ]
distinguished_name = dn
prompt             = no
[ dn ]
CN = $cn
[ v3 ]
$exts
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical,CA:FALSE
EOF

    ( umask 077; openssl genrsa -out "$tmp/key.pem" "$PKI_KEY_BITS" 2>/dev/null )
    openssl req -new -key "$tmp/key.pem" -out "$tmp/csr.pem" \
        -config "$tmp/ext.cnf" >/dev/null 2>&1
    openssl x509 -req -in "$tmp/csr.pem" -out "$tmp/cert.pem" \
        -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
        -days "$PKI_LEAF_DAYS" -sha256 \
        -extfile "$tmp/ext.cnf" -extensions v3 >/dev/null 2>&1

    # Prove the result before publishing it: a cert that does not chain to its
    # own CA must never reach /etc/etcd/certs.
    openssl verify -CAfile "$ca_cert" "$tmp/cert.pem" >/dev/null \
        || pki_die "freshly minted $name does not verify against $ca_cert"

    mkdir -p "$out_dir"
    install -m 0600 "$tmp/key.pem"  "$out_dir/$name-key.pem"
    install -m 0644 "$tmp/cert.pem" "$out_dir/$name.pem"
    echo "$out_dir/$name.pem"
}

# pki_new_ca <ca-dir> [CN]
# Creates a self-signed CA. Refuses to overwrite an existing one — losing a CA
# key is what necessitated this tooling; silently clobbering one would repeat it.
pki_new_ca() {
    local ca_dir=$1 cn=${2:-etcd-ca}
    [[ -e $ca_dir/ca-key.pem ]] && pki_die "CA key already exists: $ca_dir/ca-key.pem (refusing to overwrite)"

    mkdir -p "$ca_dir"
    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    cat >"$tmp/ca.cnf" <<EOF
[ req ]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ca
[ dn ]
CN = $cn
[ v3_ca ]
basicConstraints       = critical,CA:TRUE
keyUsage               = critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
EOF

    ( umask 077; openssl genrsa -out "$tmp/ca-key.pem" "$PKI_KEY_BITS" 2>/dev/null )
    openssl req -x509 -new -key "$tmp/ca-key.pem" -out "$tmp/ca.pem" \
        -days "$PKI_CA_DAYS" -sha256 -config "$tmp/ca.cnf" -extensions v3_ca >/dev/null 2>&1

    install -m 0600 "$tmp/ca-key.pem" "$ca_dir/ca-key.pem"
    install -m 0644 "$tmp/ca.pem"     "$ca_dir/ca.pem"
    echo "$ca_dir/ca.pem"
}

# pki_mint_server <ca-dir> <out-dir> <vswitch-ip>
# etcd's client-facing cert. SANs match the fleet's existing server certs.
pki_mint_server() {
    local ca_dir=$1 out_dir=$2 ip=$3
    _pki_mint "$ca_dir" "$out_dir" etcd-server "etcd-server" "\
keyUsage         = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName   = IP:$ip,IP:127.0.0.1"
}

# pki_mint_peer <ca-dir> <out-dir> <vswitch-ip> <etcd-name> <node-name>
# Peer certs are presented in BOTH directions of a peer connection, so they need
# serverAuth and clientAuth — ETCD_PEER_CLIENT_CERT_AUTH=true means the receiving
# peer validates them as client certs.
pki_mint_peer() {
    local ca_dir=$1 out_dir=$2 ip=$3 etcd_name=$4 node_name=$5
    _pki_mint "$ca_dir" "$out_dir" etcd-peer "etcd-peer" "\
keyUsage         = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName   = IP:$ip,IP:127.0.0.1,DNS:$etcd_name,DNS:$node_name"
}

# pki_mint_client <ca-dir> <out-dir> [CN]
# The hetzman client cert (config.py:ETCD_CLIENT_CERT).
pki_mint_client() {
    local ca_dir=$1 out_dir=$2 cn=${3:-hetzman-client}
    _pki_mint "$ca_dir" "$out_dir" client "$cn" "\
keyUsage         = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth"
}

# pki_bundle <out-file> <ca.pem>...
# Concatenates CA certs into a trust bundle. etcd loads this into a Go CertPool,
# which accepts multiple roots — that is what lets a new CA be trusted alongside
# the old one without re-minting a single existing leaf.
pki_bundle() {
    local out=$1; shift
    [[ $# -ge 1 ]] || pki_die "pki_bundle needs at least one CA cert"

    local tmp
    tmp=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN

    local ca
    for ca in "$@"; do
        [[ -r $ca ]] || pki_die "CA cert not readable: $ca"
        openssl x509 -in "$ca" -noout >/dev/null 2>&1 \
            || pki_die "not a valid PEM certificate: $ca"
        openssl x509 -in "$ca" >>"$tmp"      # normalise: strip any junk around the PEM
    done

    install -m 0644 "$tmp" "$out"
    echo "$out"
}

# pki_verify <bundle> <cert>...
# Every cert must chain to the bundle. Used as the pre-flight before any etcd
# restart: a bundle that fails to validate the CURRENT leaves would cost one
# voter per restart, so this must pass before the rollout touches anything.
pki_verify() {
    local bundle=$1; shift
    [[ -r $bundle ]] || pki_die "bundle not readable: $bundle"

    local rc=0 cert
    for cert in "$@"; do
        if [[ ! -r $cert ]]; then
            echo "  MISSING  $cert" >&2
            rc=1
            continue
        fi
        if openssl verify -CAfile "$bundle" "$cert" >/dev/null 2>&1; then
            echo "  ok       $cert"
        else
            echo "  FAILED   $cert" >&2
            rc=1
        fi
    done
    return $rc
}

# pki_cert_sans <cert> — print the SANs, for post-install assertions.
pki_cert_sans() {
    openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null \
        | tail -n +2 | tr -d ' '
}
