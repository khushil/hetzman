"""Instance (VM + container) mutations: live resize and reboot.

These run ON the target host (the command layer delegates a cross-host request
to the target node's own ``hetzman`` — see ``commands/_delegate.py``), so the
generators here always operate against the LOCAL incus via the executor's
local fast-path (``host=None`` → current node).

Resize is **live where possible**: ``incus config set`` is applied directly and
only falls back to stop→apply→start if the live apply fails on a running
instance. Disk is **grow-only** and refused when the instance has no root-size
baseline (real on the live btrfs CI containers — there is nothing to prove a
grow against).
"""
from __future__ import annotations

import re
from typing import Optional

from . import exec as host_exec
from .errors import CoreError, NotFoundError, ValidationError
from .events import OpResult, ProgressEvent, ProgressGen, Severity
from .privilege import require_root

# Size suffixes incus accepts. GB = 10^9, GiB = 2^30, etc.
_UNITS = {
    "": 1, "B": 1,
    "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12,
    "KIB": 2**10, "MIB": 2**20, "GIB": 2**30, "TIB": 2**40,
}


def _to_bytes(size: str) -> int:
    """Parse an incus size string (e.g. '250GB', '8GiB') to bytes."""
    m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)\s*$", size or "")
    if not m:
        raise ValidationError(f"unparseable size {size!r}")
    unit = m.group(2).upper()
    if unit not in _UNITS:
        raise ValidationError(f"unknown size unit in {size!r}")
    return int(float(m.group(1)) * _UNITS[unit])


def _root_size(inst: dict) -> Optional[str]:
    for key in ("devices", "expanded_devices"):
        size = ((inst.get(key) or {}).get("root") or {}).get("size")
        if size:
            return size
    return None


def _fetch(name: str) -> dict:
    data = host_exec.incus_json(None, ["list", name])
    if not data:
        raise NotFoundError(f"instance '{name}' not found")
    return data[0]


def change_instance(
    name: str,
    *,
    cpus: Optional[int] = None,
    memory: Optional[str] = None,
    disk: Optional[str] = None,
) -> ProgressGen:
    """Change cpu/memory/disk on a VM or container (live where possible)."""
    require_root()
    if cpus is None and memory is None and disk is None:
        raise ValidationError("specify at least one of cpus, memory, or disk")

    inst = _fetch(name)
    running = str(inst.get("status", "")).lower() in ("running", "started")

    ops: list[tuple[str, list[str]]] = []
    if cpus is not None:
        ops.append((f"limits.cpu={cpus}", ["config", "set", name, f"limits.cpu={cpus}"]))
    if memory is not None:
        ops.append((f"limits.memory={memory}", ["config", "set", name, f"limits.memory={memory}"]))
    if disk is not None:
        current = _root_size(inst)
        if not current:
            raise ValidationError(
                f"{name} has no root-disk size baseline; cannot grow safely "
                "(set the quota manually first)"
            )
        if _to_bytes(disk) < _to_bytes(current):
            raise ValidationError(f"disk shrink refused: {current} -> {disk}")
        if _to_bytes(disk) == _to_bytes(current):
            yield ProgressEvent(Severity.INFO, f"disk already {current}; skipping")
        else:
            ops.append(
                (f"root size={disk}", ["config", "device", "set", name, "root", f"size={disk}"])
            )

    if not ops:
        return OpResult(ok=True, summary={"name": name, "changed": ()})

    def _apply_all() -> None:
        for _label, argv in ops:
            host_exec.incus(None, argv, timeout=60)

    yield ProgressEvent(Severity.STEP, f"Applying {len(ops)} change(s) to {name}", 1, 1)
    try:
        _apply_all()
    except CoreError as exc:
        if not running:
            raise
        # Live apply failed on a running instance — fall back to a restart.
        yield ProgressEvent(
            Severity.WARNING, f"live apply failed ({exc}); restarting {name} to apply"
        )
        host_exec.incus(None, ["stop", name], timeout=180)
        try:
            _apply_all()
        finally:
            # Always bring it back up, even if re-apply fails.
            host_exec.incus(None, ["start", name], check=False, timeout=180)

    changed = tuple(label for label, _ in ops)
    yield ProgressEvent(Severity.SUCCESS, f"Changed {name}: {', '.join(changed)}")
    return OpResult(ok=True, summary={"name": name, "changed": changed})


def reboot_instance(name: str) -> ProgressGen:
    """Reboot (incus restart) a VM or container."""
    require_root()
    _fetch(name)  # NotFoundError if missing
    yield ProgressEvent(Severity.STEP, f"Rebooting {name}", 1, 1)
    host_exec.incus(None, ["restart", name], timeout=180)
    yield ProgressEvent(Severity.SUCCESS, f"Rebooted {name}")
    return OpResult(ok=True, summary={"name": name})
