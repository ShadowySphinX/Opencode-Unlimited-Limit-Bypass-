"""Endpoint switching keeps the selected WARP mode and survives a dead candidate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import clean_endpoint
import ouc_common


class SetCustomEndpointTests(unittest.TestCase):
    def test_switch_applies_the_selected_scope_mode(self) -> None:
        calls: list[list[str]] = []

        def fake_run_warp(args, warp_bin=None, timeout=15.0):
            calls.append(list(args))
            return 0, ""

        with mock.patch.object(clean_endpoint, "find_warp_cli", return_value="warp-cli"), \
                mock.patch.object(clean_endpoint, "_active_warp_scope", return_value="isolated"), \
                mock.patch.object(clean_endpoint, "run_warp", side_effect=fake_run_warp), \
                mock.patch.object(
                    clean_endpoint,
                    "warp_status",
                    return_value=(True, "proxy", "Connected"),
                ), \
                mock.patch.object(clean_endpoint.time, "sleep"), \
                mock.patch.object(ouc_common, "ensure_warp_mode") as ensure:
            ok, _message = clean_endpoint.set_custom_endpoint("162.159.192.1:2408")

        self.assertTrue(ok)
        ensure.assert_called_once_with("warp-cli", "isolated")
        self.assertIn(["tunnel", "endpoint", "set", "162.159.192.1:2408"], calls)


class AutoHealTests(unittest.TestCase):
    def test_moves_past_an_endpoint_that_cannot_connect(self) -> None:
        attempts: list[str] = []
        latency = {"fast-but-dead": 5.0, "slow-but-working": 30.0}

        def fake_set(endpoint: str):
            attempts.append(endpoint)
            if endpoint == "slow-but-working":
                return True, "connected"
            return False, "did not connect"

        with mock.patch.object(
            clean_endpoint,
            "KNOWN_CLEAN_ENDPOINTS",
            ("fast-but-dead", "slow-but-working"),
        ), mock.patch.object(
            clean_endpoint,
            "test_endpoint_latency",
            side_effect=lambda endpoint, _timeout: latency.get(endpoint),
        ), mock.patch.object(
            clean_endpoint, "set_custom_endpoint", side_effect=fake_set
        ):
            ok, message = clean_endpoint.auto_heal_warp_endpoint()

        self.assertTrue(ok)
        self.assertIn("slow-but-working", message)
        self.assertEqual(attempts, ["fast-but-dead", "slow-but-working"])

    def test_tries_endpoints_even_when_icmp_and_tcp_are_filtered(self) -> None:
        attempts: list[str] = []

        def fake_set(endpoint: str):
            attempts.append(endpoint)
            return (endpoint == "second"), "result"

        with mock.patch.object(
            clean_endpoint,
            "KNOWN_CLEAN_ENDPOINTS",
            ("first", "second"),
        ), mock.patch.object(
            clean_endpoint,
            "test_endpoint_latency",
            return_value=None,
        ), mock.patch.object(
            clean_endpoint, "set_custom_endpoint", side_effect=fake_set
        ):
            ok, message = clean_endpoint.auto_heal_warp_endpoint()

        self.assertTrue(ok)
        self.assertIn("second", message)
        self.assertIn("latency unknown", message)
        self.assertEqual(attempts, ["first", "second"])


if __name__ == "__main__":
    unittest.main()
