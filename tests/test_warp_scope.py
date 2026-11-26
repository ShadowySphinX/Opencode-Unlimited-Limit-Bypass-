"""Regression tests for WARP mode/protocol pairing and worker liveness."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import ouc_common
import warp_keeper


class ScopeProtocolTests(unittest.TestCase):
    def test_app_only_scope_selects_masque(self) -> None:
        self.assertEqual(ouc_common.warp_protocol_for_scope("isolated"), "masque")

    def test_full_tunnel_scope_selects_wireguard(self) -> None:
        self.assertEqual(ouc_common.warp_protocol_for_scope("tun"), "wireguard")

    def _apply(self, scope: str, current: str) -> list[tuple[str, object]]:
        trace: list[tuple[str, object]] = []

        def fake_protocol(desired, warp_bin=None):
            trace.append(("protocol", desired))
            return True

        def fake_run(args, **_kwargs):
            trace.append(("run", list(args)))
            return 0, ""

        with mock.patch.object(
            ouc_common, "warp_mode", return_value=current
        ), mock.patch.object(
            ouc_common, "run_warp", side_effect=fake_run
        ), mock.patch.object(
            ouc_common, "ensure_warp_protocol", side_effect=fake_protocol
        ):
            ouc_common.ensure_warp_mode("warp-cli", scope)
        return trace

    def test_app_only_sets_masque_before_switching_to_proxy(self) -> None:
        # Switching the mode first would leave a WireGuard client in proxy
        # mode, which Cloudflare refuses, so the protocol has to land first.
        self.assertEqual(
            self._apply("isolated", "warp"),
            [
                ("protocol", "masque"),
                ("run", ["proxy", "port", "40000"]),
                ("run", ["mode", "proxy"]),
            ],
        )

    def test_a_proxy_tunnel_is_not_rebound_on_every_tick(self) -> None:
        self.assertEqual(
            self._apply("isolated", "proxy"),
            [("protocol", "masque")],
        )

    def test_full_tunnel_switches_mode_before_wireguard(self) -> None:
        self.assertEqual(
            self._apply("tun", "proxy"),
            [("run", ["mode", "warp"]), ("protocol", "wireguard")],
        )


class KeeperConnectTests(unittest.TestCase):
    def test_app_only_reconnect_leaves_the_protocol_to_the_scope(self) -> None:
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            calls.append(list(args))
            return 0, ""

        with mock.patch.object(warp_keeper, "ensure_warp_mode") as mode, mock.patch.object(
            warp_keeper, "run_warp", side_effect=fake_run
        ), mock.patch.object(warp_keeper, "_wait_connected", return_value=True):
            self.assertTrue(warp_keeper._connect("warp-cli", "isolated"))

        mode.assert_called_once_with("warp-cli", "isolated")
        self.assertEqual(calls, [["connect"]])


class MutexNamespaceTests(unittest.TestCase):
    def test_worker_liveness_checks_both_namespaces(self) -> None:
        self.assertEqual(
            ouc_common._mutex_names("OpencodeUnlimitedKeeper"),
            ("Global\\OpencodeUnlimitedKeeper", "Local\\OpencodeUnlimitedKeeper"),
        )


if __name__ == "__main__":
    unittest.main()
