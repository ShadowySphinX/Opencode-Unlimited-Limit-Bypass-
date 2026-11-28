import io
import sys
import threading
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import avatar_ui
import zen_guard


class ProviderOverloadTests(unittest.TestCase):
    def test_exact_overload_advances_log_without_queueing_quota_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "opencode.log"
            log.write_text(
                "sessionID=ses_overloaded AI.Error.RateLimit The inference service is overloaded\n",
                encoding="utf-8",
            )
            state = {}
            with mock.patch.object(zen_guard, "OPENCODE_LOG_FILE", log), mock.patch.object(zen_guard, "_save_state"):
                wall, sessions = zen_guard._read_new_log_bytes(state)
            self.assertFalse(wall)
            self.assertEqual(sessions, [])
            self.assertFalse(state.get("wall_pending", False))
            self.assertEqual(state["offset"], log.stat().st_size)

    def test_provider_overload_does_not_trigger_automatic_hop(self):
        api = avatar_ui.AvatarControlApi.__new__(avatar_ui.AvatarControlApi)
        api._repair_lock = threading.Lock()
        api._action_lock = threading.Lock()
        api._repair_actions = []
        api._repair_last = {}
        api.get_state = lambda: {
            "services": {"keeper_running": True, "keeper_heartbeat": 1, "proxy_listening": True},
            "warp": {"connected": True, "rotating": False},
            "proxy": {"fallback_active": False},
            "probe": {"ok": True, "code": "overloaded"},
            "egress": {"mode": "warp"},
            "lane": {"desktop_service_wired": True, "path_wired": True},
        }
        with mock.patch.object(api, "_run_repair_action") as repair:
            api._auto_repair_tick()
        repair.assert_not_called()

    def test_overload_and_real_quota_in_same_chunk_only_queue_quota_session(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "opencode.log"
            log.write_text(
                "sessionID=ses_overloaded AI.Error.RateLimit The inference service is overloaded\n"
                "sessionID=ses_quota AI.Error.QuotaExceeded Free usage limit reached\n",
                encoding="utf-8",
            )
            state = {}
            with mock.patch.object(zen_guard, "OPENCODE_LOG_FILE", log), mock.patch.object(zen_guard, "_save_state"):
                wall, sessions = zen_guard._read_new_log_bytes(state)
            self.assertTrue(wall)
            self.assertEqual(sessions, ["ses_quota"])
            self.assertEqual(state["offset"], log.stat().st_size)

    def test_free_usage_limit_error_alone_counts_as_a_free_wall(self) -> None:
        # OpenCode sometimes logs only the error class name, without the
        # "Free usage limit" sentence the guard used to look for.
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "opencode.log"
            log.write_text(
                "sessionID=ses_free AI_APICallError: FreeUsageLimitError\n",
                encoding="utf-8",
            )
            state = {}
            with mock.patch.object(
                zen_guard, "OPENCODE_LOG_FILE", log
            ), mock.patch.object(zen_guard, "_save_state"):
                wall, sessions = zen_guard._read_new_log_bytes(state)
            self.assertTrue(wall)
            self.assertEqual(sessions, ["ses_free"])
            self.assertGreater(state["last_free_wall"], 0)

    def test_async_probe_preserves_overload_status_without_marking_route_down(self):
        api = avatar_ui.AvatarControlApi.__new__(avatar_ui.AvatarControlApi)
        api._probe_lock = threading.Lock()
        api._probe_checking = False
        api._probe = {}
        api._probe_ts = 0
        with mock.patch.object(avatar_ui, "_port_open", return_value=True), mock.patch.object(
            avatar_ui, "_probe_http", return_value=(True, "overloaded")
        ), mock.patch.object(avatar_ui.threading, "Thread") as thread:
            thread.side_effect = lambda **kwargs: mock.Mock(start=kwargs["target"])
            api._refresh_probe_async(force=True)
        self.assertEqual(api._probe["code"], "overloaded")
        self.assertTrue(api._probe["ok"])

    def test_http_503_is_reachable_provider_not_a_failed_route(self):
        error = urllib.error.HTTPError("https://opencode.ai", 503, "Busy", {}, io.BytesIO(b'The inference service is overloaded. Please try again later.'))
        with mock.patch.object(avatar_ui.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            self.assertEqual(avatar_ui._probe_http("https://opencode.ai", None), (True, "overloaded"))

    def test_inference_overload_is_not_a_transport_error(self):
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        lines = [f'timestamp={stamp}.000Z level=ERROR message="AI_APICallError: The inference service is overloaded. Please try again later. statusCode=503"']
        self.assertEqual(avatar_ui._recent_network_errors(lines), [])
        self.assertEqual(len(avatar_ui._recent_overload_errors(lines)), 1)

    def test_generic_503_still_reports_a_route_failure(self):
        error = urllib.error.HTTPError("https://opencode.ai", 503, "Unavailable", {}, io.BytesIO(b"Proxy server is overloaded"))
        with mock.patch.object(avatar_ui.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            self.assertEqual(avatar_ui._probe_http("https://opencode.ai", None), (False, "upstream"))

    def test_bare_api_error_is_not_proof_of_a_network_failure(self):
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        self.assertEqual(avatar_ui._recent_network_errors([f'timestamp={stamp} level=ERROR AI_APICallError invalid request']), [])

    def test_stale_overload_is_not_shown(self):
        self.assertEqual(avatar_ui._recent_overload_errors([
            'timestamp=2020-01-01T00:00:00 level=ERROR The inference service is overloaded'
        ]), [])

    def test_overload_health_does_not_offer_network_repair(self):
        api = avatar_ui.AvatarControlApi.__new__(avatar_ui.AvatarControlApi)
        health = api._build_health(
            warp_installed=True, warp_connected=True, rotating=False,
            egress={"mode": "warp"}, keeper_running=True, guard_running=True,
            proxy_listening=True, svc_wired=True, installed=True,
            probe={"ok": True, "code": "ok"},
            overload_errors=["The inference service is overloaded"],
        )
        issues = [issue for issue in health["issues"] if "overload" in issue["title"].lower()]
        self.assertEqual(len(issues), 1)
        self.assertIsNone(issues[0]["fix"])
