"""Import-isolation tripwire: core must never pull in hetzman.console (Rich).

Each test spawns a FRESH subprocess per module so there is zero cross-test
import bleed.  The subprocess imports the target module, then exits with code 0
if hetzman.console is absent from sys.modules or code 1 if it is present.

WHY THIS EXISTS
---------------
The core layer (hetzman.core.*) and the decoupled low-level utilities
(hetzman.config, hetzman.logging, hetzman.etcd_kv, hetzman.locking) must not
drag in the Rich console at import time — that belongs exclusively in the
presentation layer (P3 and above).

This guard fires the instant a future agent imports an un-decoupled utility
(network.py, vm_helpers.py, render.py, …) into core or into a low-level
module, because those utilities currently import hetzman.console at module
level.  Catching it here — before the change is merged — is exactly the right
moment.
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_MODULES_UNDER_TEST: list[str] = [
    # core sub-modules
    "hetzman.core.events",
    "hetzman.core.errors",
    "hetzman.core.privilege",
    "hetzman.core.models",
    "hetzman.core.concurrency",
    "hetzman.core.reads",
    # decoupled low-level modules
    "hetzman.config",
    "hetzman.logging",
    "hetzman.etcd_kv",
    "hetzman.locking",
    # console-free utilities (decoupled in this phase)
    "hetzman.network",
    "hetzman.services",
    "hetzman.templates",
    "hetzman.vm_helpers",
]

_PROBE = (
    "import {mod}; import sys; "
    "sys.exit(0 if 'hetzman.console' not in sys.modules else 1)"
)


def _make_test(module_name: str):
    def test_method(self: unittest.TestCase) -> None:
        env = {**os.environ, "PYTHONPATH": "src"}
        result = subprocess.run(
            [sys.executable, "-c", _PROBE.format(mod=module_name)],
            env=env,
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=(
                f"Module '{module_name}' pulled in hetzman.console (Rich) at "
                f"import time.\n"
                f"stdout: {result.stdout!r}\n"
                f"stderr: {result.stderr!r}"
            ),
        )

    test_method.__name__ = f"test_no_console_{module_name.replace('.', '_')}"
    test_method.__doc__ = (
        f"'{module_name}' must not import hetzman.console (Rich) at module level."
    )
    return test_method


class TestCoreImportIsolation(unittest.TestCase):
    """Verify that no core / low-level module drags in hetzman.console."""


# Dynamically attach one test method per module so failures are reported
# individually (easy to spot which module broke the rule).
for _mod in _MODULES_UNDER_TEST:
    _method = _make_test(_mod)
    setattr(TestCoreImportIsolation, _method.__name__, _method)


if __name__ == "__main__":
    unittest.main()
