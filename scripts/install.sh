#!/usr/bin/env bash
# Install hetzman system-wide via pipx (pre-1.5 compatible).
# Venv: /opt/pipx/venvs/hetzman   Entry point: /usr/local/bin/hetzman
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PIPX_HOME=/opt/pipx
export PIPX_BIN_DIR=/usr/local/bin

if [[ $EUID -ne 0 ]]; then
    exec sudo --preserve-env=PIPX_HOME,PIPX_BIN_DIR "$0" "$@"
fi

if ! command -v pipx >/dev/null; then
    echo "pipx not found. Install it first: sudo apt install pipx python3-venv" >&2
    exit 1
fi

TARGET="$PIPX_BIN_DIR/hetzman"
if [[ -e "$TARGET" && ! -L "$TARGET" ]]; then
    BACKUP="$TARGET.pre-pipx.$(date +%s)"
    echo "Backing up pre-existing standalone $TARGET -> $BACKUP"
    mv "$TARGET" "$BACKUP"
fi

echo "Installing hetzman from $REPO_DIR"
pipx install "$REPO_DIR"
echo "Done. Run: hetzman --help"
