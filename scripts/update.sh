#!/usr/bin/env bash
# Reinstall hetzman from the current repo (typically after `git pull`).
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

echo "Reinstalling hetzman from $REPO_DIR"
pipx install --force "$REPO_DIR"
echo "Done. Installed: $(hetzman --help 2>&1 | head -1 || echo 'hetzman')"
