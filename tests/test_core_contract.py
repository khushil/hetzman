"""Contract tests for the UI-agnostic core layer (stdlib unittest)."""

from __future__ import annotations

import unittest
from unittest import mock

from hetzman.core.errors import (
    CoreError,
    EtcdUnavailable,
    NotFoundError,
    PrivilegeError,
    ValidationError,
)
from hetzman.core.events import OpResult, ProgressEvent, Severity
from hetzman.core.privilege import require_root


class TestEventsConstruct(unittest.TestCase):
    def test_progress_event_constructs(self):
        # Proves the frozen dataclass has no mutable-default import bug.
        ev = ProgressEvent(severity=Severity.STEP, message="hi")
        self.assertEqual(ev.severity, Severity.STEP)
        self.assertEqual(ev.message, "hi")
        self.assertIsNone(ev.step)
        self.assertIsNone(ev.scope)

    def test_op_result_constructs(self):
        res = OpResult(ok=True)
        self.assertTrue(res.ok)

    def test_op_result_defaults_empty_and_immutable(self):
        res = OpResult(ok=True)
        self.assertEqual(dict(res.summary), {})
        self.assertEqual(res.warnings, ())
        self.assertEqual(res.errors, ())
        # frozen dataclass: assignment must fail.
        with self.assertRaises(Exception):
            res.ok = False  # type: ignore[misc]

    def test_op_result_defaults_not_shared(self):
        a = OpResult(ok=True)
        b = OpResult(ok=True)
        self.assertIsNot(a.summary, b.summary)


class TestSeverity(unittest.TestCase):
    def test_members(self):
        self.assertEqual(
            {s.value for s in Severity},
            {"info", "step", "success", "warning", "error"},
        )


class TestRequireRoot(unittest.TestCase):
    def test_raises_when_not_root(self):
        with mock.patch("os.geteuid", return_value=1000):
            with self.assertRaises(PrivilegeError):
                require_root()

    def test_raises_includes_action_label(self):
        with mock.patch("os.geteuid", return_value=1000):
            with self.assertRaises(PrivilegeError) as ctx:
                require_root("create VM")
            self.assertIn("create VM", str(ctx.exception))

    def test_returns_none_when_root(self):
        with mock.patch("os.geteuid", return_value=0):
            self.assertIsNone(require_root())


class TestErrorHierarchy(unittest.TestCase):
    def test_all_derive_from_core_error(self):
        for exc in (ValidationError, NotFoundError, PrivilegeError, EtcdUnavailable):
            self.assertTrue(issubclass(exc, CoreError))


if __name__ == "__main__":
    unittest.main()
