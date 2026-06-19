"""Thread-safety + etcd-availability tests for the low-level modules.

Stdlib unittest + unittest.mock only (no pytest, no real etcd/network/root).
"""
from __future__ import annotations

import unittest
from unittest import mock

from hetzman import config, etcd_kv, locking
from hetzman.core import concurrency
from hetzman.core.errors import EtcdUnavailable


class GetEtcdClientRaisesTest(unittest.TestCase):
    def test_raises_etcd_unavailable_not_systemexit(self):
        """A total connect failure surfaces EtcdUnavailable, never sys.exit."""
        settings = config.Settings(
            current_server="s",
            bridge_ip="10.0.0.1",
            primary_iface="eth0",
            etcd_endpoints=(("127.0.0.1", 2379),),
        )
        config.get_etcd_client.cache_clear()
        with mock.patch.object(config, "get_settings", return_value=settings), \
             mock.patch.object(config, "_load_etcd_credentials", return_value=(None, None)), \
             mock.patch.object(config, "_connect_passes", return_value=1), \
             mock.patch.object(config, "etcd3") as m_etcd3:
            m_etcd3.client.side_effect = RuntimeError("connection refused")
            with self.assertRaises(EtcdUnavailable):
                config.get_etcd_client()
        config.get_etcd_client.cache_clear()


class EtcdUnavailablePropagatesTest(unittest.TestCase):
    def test_get_key_reraises_etcd_unavailable(self):
        with mock.patch.object(
            concurrency, "get_client", side_effect=EtcdUnavailable("down")
        ):
            with self.assertRaises(EtcdUnavailable):
                etcd_kv.get_key("/k")

    def test_get_all_with_prefix_reraises_etcd_unavailable(self):
        with mock.patch.object(
            concurrency, "get_client", side_effect=EtcdUnavailable("down")
        ):
            with self.assertRaises(EtcdUnavailable):
                etcd_kv.get_all_with_prefix("/p")

    def test_put_key_reraises_etcd_unavailable(self):
        with mock.patch.object(
            concurrency, "get_client", side_effect=EtcdUnavailable("down")
        ):
            with self.assertRaises(EtcdUnavailable):
                etcd_kv.put_key("/k", "v")


class GenericErrorReturnsNoneTest(unittest.TestCase):
    def test_get_key_returns_none_after_retries_on_generic_error(self):
        """A non-auth, non-EtcdUnavailable error exhausts retries and yields None."""
        client = mock.Mock()
        client.get.side_effect = RuntimeError("boom")
        with mock.patch.object(concurrency, "get_client", return_value=client), \
             mock.patch.object(etcd_kv.time, "sleep"), \
             mock.patch.object(etcd_kv, "log_message"):
            self.assertIsNone(etcd_kv.get_key("/k"))
        self.assertEqual(client.get.call_count, etcd_kv._RETRIES)

    def test_get_all_with_prefix_returns_empty_on_generic_error(self):
        client = mock.Mock()
        client.get_prefix.side_effect = RuntimeError("boom")
        with mock.patch.object(concurrency, "get_client", return_value=client), \
             mock.patch.object(etcd_kv.time, "sleep"), \
             mock.patch.object(etcd_kv, "log_message"):
            self.assertEqual(etcd_kv.get_all_with_prefix("/p"), {})


class SyncLockReentrantTest(unittest.TestCase):
    def test_nested_sync_lock_yields_true_twice(self):
        # Force the open() path to take the "proceed unlocked" branch so this
        # test needs no root / real lock file, while still exercising reentry.
        with mock.patch.object(locking, "open", side_effect=OSError, create=True):
            with locking.sync_lock() as outer:
                self.assertTrue(outer)
                with locking.sync_lock() as inner:
                    self.assertTrue(inner)

    def test_nested_sync_lock_reentry_with_lockfile(self):
        fake = mock.Mock()
        with mock.patch.object(locking, "open", return_value=fake, create=True), \
             mock.patch.object(locking.fcntl, "flock"):
            with locking.sync_lock() as outer:
                self.assertTrue(outer)
                self.assertEqual(locking._holder_depth, 1)
                with locking.sync_lock() as inner:
                    self.assertTrue(inner)
                    self.assertEqual(locking._holder_depth, 2)
                self.assertEqual(locking._holder_depth, 1)
        self.assertEqual(locking._holder_depth, 0)


if __name__ == "__main__":
    unittest.main()
