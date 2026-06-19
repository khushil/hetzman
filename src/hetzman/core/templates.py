"""Provisioning-template application as a core operation generator."""
from __future__ import annotations

from ..vm_helpers import check_vm_exists
from .errors import NotFoundError, ValidationError
from .events import OpResult, ProgressEvent, ProgressGen, Severity
from .privilege import require_root


def apply_template_gen(vm_name: str, name: str, *, check: bool = True) -> ProgressGen:
    """Apply a provisioning template to a VM.

    Raises NotFoundError if the template doesn't exist and ValidationError on a
    malformed template (so a standalone ``cfg apply`` exits non-zero); a
    composing op like ``create_vm`` catches those to downgrade to a warning.
    A non-fatal "optional step failed" outcome returns ``OpResult(ok=False)``
    with a warning event rather than raising.
    """
    from ..templates import apply_template

    if check:
        require_root()
        if not check_vm_exists(vm_name):
            raise NotFoundError(f"VM or container '{vm_name}' not found")

    yield ProgressEvent(Severity.INFO, f"Applying template '{name}'...")
    try:
        ok = apply_template(vm_name, name)
    except FileNotFoundError:
        raise NotFoundError(
            f"template '{name}' not found (see 'hetzman vm cfg list')"
        )
    except ValueError as exc:
        raise ValidationError(str(exc))

    if ok:
        yield ProgressEvent(Severity.SUCCESS, f"Template '{name}' applied to {vm_name}")
        return OpResult(ok=True, summary={"template": name})
    yield ProgressEvent(
        Severity.WARNING,
        f"Template '{name}' applied to {vm_name} with warnings "
        "(one or more optional steps failed)",
    )
    return OpResult(ok=False, summary={"template": name})
