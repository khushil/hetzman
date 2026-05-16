#!/usr/bin/env bash
# Remove hetzman.
set -euo pipefail

export PIPX_HOME=/opt/pipx
export PIPX_BIN_DIR=/usr/local/bin

if [[ $EUID -ne 0 ]]; then
    exec sudo --preserve-env=PIPX_HOME,PIPX_BIN_DIR "$0" "$@"
fi

if ! command -v pipx >/dev/null; then
    echo "pipx not found." >&2
    exit 1
fi

pipx uninstall hetzman
echo "Done."
