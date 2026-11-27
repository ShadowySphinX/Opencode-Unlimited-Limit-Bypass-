"""Focused regression tests for route failover, diagnostics, and health parsing."""

from __future__ import annotations

import errno
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import avatar_ui
import ouc_common
import proxy_chain
import zen_guard
import zen_proxy


class DataRootTests(unittest.TestCase):
    def test_windows_uses_local_appdata(self) -> None:
        with mock.patch.object(ouc_common.sys, "platform", "win32"), mock.patch.dict(
            os.environ, {"LOCALAPPDATA": r"C:\Users\tester\AppData\Local"}, clear=False
        ):
            self.assertEqual(
                ouc_common._default_data_root(),
                Path(r"C:\Users\tester\AppData\Local"),
            )

    def test_linux_uses_xdg_data_home(self) -> None:
        with mock.patch.object(ouc_common.sys, "platform", "linux"), mock.patch.dict(
            os.environ, {"XDG_DATA_HOME": "/srv/tester/.local/share"}, clear=False
        ):
            self.assertEqual(
                ouc_common._default_data_root(), Path("/srv/tester/.local/share")
            )

    def test_linux_falls_back_to_local_share(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "XDG_DATA_HOME"}
        with mock.patch.object(ouc_common.sys, "platform", "linux"), mock.patch.dict(
            os.environ, env, clear=True
        ), mock.patch.object(
            ouc_common.Path, "home", return_value=Path("/home/tester")
        ):
            self.assertEqual(
                ouc_common._default_data_root(), Path("/home/tester/.local/share")
            )


class RunHiddenTests(unittest.TestCase):
    def test_windows_suppresses_the_console_window(self) -> None:
        completed = mock.Mock()
        with mock.patch.object(
            ouc_common.sys, "platform", "win32"
        ), mock.patch.object(
            ouc_common.subprocess, "run", return_value=completed
        ) as run:
            result = ouc_common.run_hidden(["warp-cli", "status"], timeout=3.0)

        self.assertIs(result, completed)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["warp-cli", "status"])
        self.assertEqual(kwargs["creationflags"], ouc_common.CREATE_NO_WINDOW)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertEqual(kwargs["timeout"], 3.0)

    def test_non_ascii_output_is_decoded_as_utf8(self) -> None:
        # A Windows console defaults to a legacy code page; decoding warp-cli or
        # opencode output with it would raise instead of returning the text.
        result = ouc_common.run_hidden(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write('\u00e9'.encode())",
            ],
            timeout=30.0,
        )

        self.assertEqual(result.stdout, "\u00e9")

    def test_linux_does_not_pass_windows_creation_flags(self) -> None:
        with mock.patch.object(
            ouc_common.sys, "platform", "linux"
        ), mock.patch.object(ouc_common.subprocess, "run") as run:
            ouc_common.run_hidden(["warp-cli", "status"])

        _, kwargs = run.call_args
        self.assertNotIn("creationflags", kwargs)


class RecentNetworkErrorTests(unittest.TestCase):
    def _line(self, when: datetime, message: str) -> str:
        return (
            f"timestamp={when.strftime('%Y-%m-%dT%H:%M:%S')}.123Z "
            f'level=ERROR run=test message="{message}"'
        )

    def test_only_recent_upstream_failures_are_reported(self) -> None:
        now = datetime.now(timezone.utc)
        old = self._line(now - timedelta(hours=2), "ECONNRESET while contacting provider")
        recent = self._line(now - timedelta(seconds=30), "AI.Error: ECONNRESET")
        own_503 = (
            f"timestamp={now.strftime('%Y-%m-%dT%H:%M:%S')}.123Z level=INFO "
            'message="Sent HTTP response" http.method=GET http.url=/api/info http.status=503'
        )
        upstream_503 = self._line(
            now - timedelta(seconds=20), "AI_APICallError statusCode=503"
        )

        found = avatar_ui._recent_network_errors(
            [old, recent, own_503, upstream_503]
        )

        self.assertEqual(len(found), 2)
        self.assertTrue(any("ECONNRESET" in line for line in found))
        self.assertTrue(any("AI_APICallError" in line for line in found))
        self.assertFalse(any("api/info" in line for line in found))

    def test_lines_without_a_timestamp_are_ignored(self) -> None:
        self.assertEqual(
            avatar_ui._recent_network_errors(["stack trace: ECONNRESET"]), []
        )

    def test_local_cli_broken_pipe_is_not_a_network_error(self) -> None:
        now = datetime.now(timezone.utc)
        line = (
            f"timestamp={now.strftime('%Y-%m-%dT%H:%M:%S')}.507Z level=ERROR "
            'run=5aa107ed message="unhandled rejection" '
            'cause="Error: EPIPE: broken pipe, write" role=cli'
        )
        self.assertEqual(avatar_ui._recent_network_errors([line]), [])


class EdgeFailoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._saved = (
            zen_proxy.LANE_DIR,
            zen_proxy.PROXY_STATUS_FILE,
            zen_proxy.FALLBACK_FLAG,
            zen_proxy.PROXY_LOG_FILE,
        )
        zen_proxy.LANE_DIR = self.dir
        zen_proxy.PROXY_STATUS_FILE = self.dir / "proxy_status.json"
        zen_proxy.FALLBACK_FLAG = self.dir / "fallback.flag"
        zen_proxy.PROXY_LOG_FILE = self.dir / "proxy.log"
        zen_proxy._LAST_STREAM_RESET_NOTE = 0.0

    def tearDown(self) -> None:
        (
            zen_proxy.LANE_DIR,
            zen_proxy.PROXY_STATUS_FILE,
            zen_proxy.FALLBACK_FLAG,
            zen_proxy.PROXY_LOG_FILE,
        ) = self._saved
        self.tmp.cleanup()

    def test_bracketed_ipv6_localhost_is_connected_without_brackets(self) -> None:
        state = zen_proxy._WarpState([], "")
        sock = mock.Mock()

        with mock.patch.object(
            zen_proxy.socket, "create_connection", return_value=sock
        ) as connect:
            self.assertIs(zen_proxy._open_upstream("[::1]", 443, state), sock)

        connect.assert_called_once_with(("::1", 443), timeout=10.0)

    def test_stale_warp_address_is_refreshed_once(self) -> None:
        state = zen_proxy._WarpState(["edge-a"], "edge-a")
        calls: list[tuple[str, str]] = []
        fresh = object()

        def fake_open(edge, port, local_v6, timeout=0.0):
            calls.append((edge, local_v6))
            if local_v6 == "2001:db8::1":
                raise OSError(errno.EADDRNOTAVAIL, "address not available")
            return fresh

        with mock.patch.object(
            zen_proxy, "get_warp_local_v6", side_effect=["2001:db8::1", "2001:db8::2"]
        ), mock.patch.object(zen_proxy, "_open_pinned_v6", side_effect=fake_open):
            sock, edge = zen_proxy._open_pinned_any("opencode.ai", 443, state)

        self.assertIs(sock, fresh)
        self.assertEqual(edge, "edge-a")
        self.assertEqual(
            calls, [("edge-a", "2001:db8::1"), ("edge-a", "2001:db8::2")]
        )

    def test_new_warp_address_is_polled_until_the_adapter_publishes_it(self) -> None:
        state = zen_proxy._WarpState(["edge-a"], "edge-a")
        reported = ["2001:db8::1", "2001:db8::1", "2001:db8::2"]

        with mock.patch.object(zen_proxy, "get_warp_local_v6", side_effect=reported):
            fresh = zen_proxy._wait_for_new_local_v6(
                state, "2001:db8::1", time.monotonic() + 5.0
            )

        self.assertEqual(fresh, "2001:db8::2")

    def test_stale_address_wait_gives_up_at_the_deadline(self) -> None:
        state = zen_proxy._WarpState(["edge-a"], "edge-a")

        with mock.patch.object(zen_proxy, "get_warp_local_v6", return_value="2001:db8::1"):
            fresh = zen_proxy._wait_for_new_local_v6(
                state, "2001:db8::1", time.monotonic() - 1.0
            )

        self.assertEqual(fresh, "")

    def test_primary_edge_is_first_and_failed_edge_is_skipped(self) -> None:
        state = zen_proxy._WarpState(["edge-a", "edge-b", "edge-c"], "edge-a")
        self.assertEqual(state.edges_to_try()[0], "edge-a")

        state.mark_edge_failed("edge-a")
        choices = state.edges_to_try()

        self.assertNotIn("edge-a", choices)
        self.assertLessEqual(len(choices), zen_proxy.EDGE_TRY_LIMIT)
        self.assertNotEqual(state.get(wait_if_rotating=False)[1], "edge-a")

    def test_success_clears_fallback_and_switches_primary(self) -> None:
        state = zen_proxy._WarpState(["edge-a", "edge-b"], "edge-a")
        zen_proxy.FALLBACK_FLAG.write_text("1", encoding="utf-8")

        state.mark_edge_ok("edge-b")

        self.assertFalse(zen_proxy.FALLBACK_FLAG.exists())
        self.assertEqual(state.get(wait_if_rotating=False)[1], "edge-b")
        self.assertEqual(
            (self.dir / "last_edge.txt").read_text(encoding="utf-8").strip(),
            "edge-b",
        )

    def test_status_counts_errors_and_fallbacks(self) -> None:
        zen_proxy._record_event("reset", "ConnectionResetError", "opencode.ai", "edge-a")
        zen_proxy._record_event("fallback", "direct route used", "opencode.ai")
        status = zen_proxy.proxy_status()

        self.assertEqual(status["errors_5m"], 1)
        self.assertEqual(status["fallbacks_5m"], 1)
        self.assertIsNotNone(status["fallback_age"])
        self.assertLessEqual(status["fallback_age"], 2)
        log = (self.dir / "proxy.log").read_text(encoding="utf-8")
        self.assertIn("reset:", log)
        self.assertIn("fallback:", log)

    def test_mid_stream_reset_retires_edge_only_after_a_second_cut(self) -> None:
        state = zen_proxy._WarpState(["edge-a", "edge-b"], "edge-a")

        zen_proxy._note_stream_reset(
            "opencode.ai", "ConnectionResetError after response", state, "edge-a"
        )
        self.assertEqual(state.current_edge(), "edge-a")
        self.assertEqual(zen_proxy.proxy_status()["stream_resets_5m"], 1)

        zen_proxy._LAST_STREAM_RESET_NOTE = 0.0
        zen_proxy._note_stream_reset(
            "opencode.ai", "ConnectionResetError after response", state, "edge-a"
        )
        self.assertEqual(state.current_edge(), "edge-b")
        self.assertEqual(zen_proxy.proxy_status()["stream_resets_5m"], 2)
        log = (self.dir / "proxy.log").read_text(encoding="utf-8")
        self.assertIn("stream_reset:", log)
        self.assertIn("moved to edge-b", log)

    def test_isolated_start_skips_the_pinned_edge_pool_fetch(self) -> None:
        with mock.patch.object(
            zen_proxy, "_active_warp_scope", return_value="isolated"
        ), mock.patch.object(
            zen_proxy,
            "fetch_opencode_aaaa_pool",
            side_effect=AssertionError("isolated startup must not resolve edges"),
        ), mock.patch.object(
            zen_proxy, "ensure_dirs", lambda: None
        ):
            server, port, edge = zen_proxy.start_proxy_server(0)

        try:
            self.assertGreater(port, 0)
            self.assertEqual(edge, "")
            self.assertEqual(zen_proxy.proxy_status()["last_event"]["kind"], "start")
        finally:
            server.shutdown()
            server.server_close()


class DoorHoldTests(unittest.TestCase):
    """A request that arrives during a rotation waits instead of failing."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._saved = (
            zen_proxy.LANE_DIR,
            zen_proxy.PROXY_STATUS_FILE,
            zen_proxy.FALLBACK_FLAG,
            zen_proxy.PROXY_LOG_FILE,
        )
        zen_proxy.LANE_DIR = self.dir
        zen_proxy.PROXY_STATUS_FILE = self.dir / "proxy_status.json"
        zen_proxy.FALLBACK_FLAG = self.dir / "fallback.flag"
        zen_proxy.PROXY_LOG_FILE = self.dir / "proxy.log"

    def tearDown(self) -> None:
        (
            zen_proxy.LANE_DIR,
            zen_proxy.PROXY_STATUS_FILE,
            zen_proxy.FALLBACK_FLAG,
            zen_proxy.PROXY_LOG_FILE,
        ) = self._saved
        self.tmp.cleanup()

    def test_connect_waits_while_the_guard_rotates(self) -> None:
        sock = object()
        paused = [True, True, False]
        attempts: list[int] = []

        def fake_open(host, port, state):
            attempts.append(len(attempts))
            if len(attempts) < 3:
                raise ConnectionRefusedError("tunnel is down for the rotation")
            return sock

        with mock.patch.object(zen_proxy, "_open_upstream", side_effect=fake_open), mock.patch.object(
            zen_proxy, "_rotation_in_progress", side_effect=lambda: paused.pop(0) if paused else False
        ), mock.patch.object(zen_proxy, "time") as fake_time:
            fake_time.monotonic.side_effect = lambda: 0.0
            fake_time.sleep.return_value = None
            result = zen_proxy._connect_upstream("opencode.ai", 443, mock.Mock())

        self.assertIs(result, sock)
        self.assertEqual(len(attempts), 3)
        log = (self.dir / "proxy.log").read_text(encoding="utf-8")
        self.assertIn("hold:", log)
        self.assertNotIn("connect_fail:", log)

    def test_connect_gives_up_when_the_rotation_never_ends(self) -> None:
        with mock.patch.object(
            zen_proxy,
            "_open_upstream",
            side_effect=ConnectionRefusedError("tunnel is down"),
        ), mock.patch.object(zen_proxy, "_rotation_in_progress", return_value=True), mock.patch.object(
            zen_proxy, "_active_tunnels", return_value=1
        ), mock.patch.object(zen_proxy, "ROTATION_HOLD_SECONDS", 0.0):
            with self.assertRaises(ConnectionRefusedError):
                zen_proxy._connect_upstream("opencode.ai", 443, mock.Mock())

        log = (self.dir / "proxy.log").read_text(encoding="utf-8")
        self.assertIn("connect_fail:", log)

    def test_a_fresh_pause_file_means_a_rotation_is_running(self) -> None:
        pause = self.dir / "keeper.pause"
        pause.write_text(json.dumps({"until": time.time() + 600}), encoding="utf-8")

        with mock.patch.object(zen_proxy, "PAUSE_FILE", pause), mock.patch.object(
            zen_proxy, "is_keeper_paused", return_value=True
        ):
            self.assertTrue(zen_proxy._rotation_in_progress())

    def test_a_pause_left_by_a_killed_guard_does_not_hold_requests(self) -> None:
        pause = self.dir / "keeper.pause"
        pause.write_text(json.dumps({"until": time.time() + 600}), encoding="utf-8")
        old = time.time() - zen_proxy.ROTATION_FRESH_SECONDS - 30
        os.utime(pause, (old, old))

        with mock.patch.object(zen_proxy, "PAUSE_FILE", pause), mock.patch.object(
            zen_proxy, "is_keeper_paused", return_value=True
        ):
            self.assertFalse(zen_proxy._rotation_in_progress())

    def test_connect_repairs_once_when_no_tunnel_is_streaming(self) -> None:
        sock = object()
        attempts: list[int] = []

        def fake_open(host, port, state):
            attempts.append(len(attempts))
            if len(attempts) < 2:
                raise ConnectionRefusedError("edge is dead")
            return sock

        with mock.patch.object(zen_proxy, "_open_upstream", side_effect=fake_open), mock.patch.object(
            zen_proxy, "_rotation_in_progress", return_value=False
        ), mock.patch.object(zen_proxy, "_active_tunnels", return_value=0), mock.patch.object(
            zen_proxy, "_repair_warp_tunnel", return_value=True
        ) as repair:
            result = zen_proxy._connect_upstream("opencode.ai", 443, mock.Mock())

        self.assertIs(result, sock)
        repair.assert_called_once()

    def test_connect_does_not_repair_while_another_stream_is_open(self) -> None:
        with mock.patch.object(
            zen_proxy,
            "_open_upstream",
            side_effect=ConnectionRefusedError("edge is dead"),
        ), mock.patch.object(zen_proxy, "_rotation_in_progress", return_value=False), mock.patch.object(
            zen_proxy, "_active_tunnels", return_value=2
        ), mock.patch.object(zen_proxy, "_repair_warp_tunnel") as repair:
            with self.assertRaises(ConnectionRefusedError):
                zen_proxy._connect_upstream("opencode.ai", 443, mock.Mock())

        repair.assert_not_called()


class TunnelByteActivityTests(unittest.TestCase):
    """The proxy publishes byte activity so an idle socket is not 'streaming'."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._saved = (zen_proxy.LANE_DIR, zen_proxy.PROXY_STATUS_FILE)
        zen_proxy.LANE_DIR = self.dir
        zen_proxy.PROXY_STATUS_FILE = self.dir / "proxy_status.json"
        zen_proxy._reset_tunnel_activity()

    def tearDown(self) -> None:
        zen_proxy._reset_tunnel_activity()
        zen_proxy.LANE_DIR, zen_proxy.PROXY_STATUS_FILE = self._saved
        self.tmp.cleanup()

    def status(self) -> dict:
        return json.loads(zen_proxy.PROXY_STATUS_FILE.read_text(encoding="utf-8"))

    def test_an_idle_tunnel_publishes_no_byte_stamp(self) -> None:
        zen_proxy._enter_tunnel()

        status = self.status()
        self.assertEqual(status["active_tunnels"], 1)
        self.assertEqual(status["last_byte_ts"], 0)

    def test_a_relayed_byte_updates_the_published_stamp(self) -> None:
        zen_proxy._enter_tunnel()
        try:
            zen_proxy._note_tunnel_bytes()
        finally:
            zen_proxy._leave_tunnel()

        status = self.status()
        self.assertGreater(status["last_byte_ts"], 0)
        self.assertLessEqual(status["last_byte_ts"], int(time.time()))


class RegistrationBackoffTests(unittest.TestCase):
    def test_retries_wait_longer_each_time(self) -> None:
        sleeps: list[float] = []

        def fake_run_warp(args, **kwargs):
            return 1, "registration failed"

        with mock.patch.object(
            ouc_common, "warp_registration_healthy", return_value=False
        ), mock.patch.object(ouc_common, "run_warp", side_effect=fake_run_warp), mock.patch.object(
            ouc_common.time, "sleep", side_effect=sleeps.append
        ):
            ok = ouc_common.repair_warp_registration("warp-cli", max_tries=4)

        self.assertFalse(ok)
        self.assertEqual(sleeps, [2.0, 4.0, 8.0])

    def test_success_stops_the_backoff(self) -> None:
        sleeps: list[float] = []
        results = [(1, "failed"), (0, "ok")]

        with mock.patch.object(
            ouc_common, "warp_registration_healthy", return_value=False
        ), mock.patch.object(
            ouc_common, "run_warp", side_effect=lambda *a, **k: results.pop(0)
        ), mock.patch.object(ouc_common.time, "sleep", side_effect=sleeps.append):
            ok = ouc_common.repair_warp_registration("warp-cli", max_tries=4)

        self.assertTrue(ok)
        self.assertEqual(sleeps, [2.0])

    def test_healthy_registration_skips_every_retry(self) -> None:
        with mock.patch.object(
            ouc_common, "warp_registration_healthy", return_value=True
        ), mock.patch.object(ouc_common, "run_warp") as run:
            self.assertTrue(ouc_common.repair_warp_registration("warp-cli"))

        run.assert_not_called()


class BodyReadTests(unittest.TestCase):
    def test_unbuffered_short_reads_are_reassembled(self) -> None:
        class ShortReadStream:
            def __init__(self, data: bytes) -> None:
                self.data = data

            def read(self, size: int) -> bytes:
                chunk = self.data[: min(size, 3)]
                self.data = self.data[len(chunk) :]
                return chunk

        payload = b'{"model":"deepseek-v4.1","stream":true}'
        self.assertEqual(
            zen_proxy._read_exact(ShortReadStream(payload), len(payload)), payload
        )

    def test_eof_before_the_declared_length_returns_what_arrived(self) -> None:
        class TruncatedStream:
            def __init__(self) -> None:
                self.calls = 0

            def read(self, size: int) -> bytes:
                self.calls += 1
                return b"abc" if self.calls == 1 else b""

        self.assertEqual(zen_proxy._read_exact(TruncatedStream(), 10), b"abc")


class StreamResetReportingTests(unittest.TestCase):
    class _FakeSocket:
        def __init__(self, recv_events: list[object]) -> None:
            self.recv_events = list(recv_events)
            self.sent: list[bytes] = []
            self.shutdowns: list[int] = []

        def setsockopt(self, *args) -> None:
            pass

        def ioctl(self, *args) -> None:
            pass

        def recv(self, size: int, flags: int = 0) -> bytes:
            event = self.recv_events.pop(0)
            if isinstance(event, Exception):
                raise event
            return event

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

        def shutdown(self, how: int) -> None:
            self.shutdowns.append(how)

    def test_reset_after_the_client_closed_is_not_a_cut_stream(self) -> None:
        client = self._FakeSocket([b""])
        upstream = self._FakeSocket(
            [b"HTTP/1.1 200 OK\r\n\r\n", ConnectionResetError("cut")]
        )
        with mock.patch.object(
            zen_proxy.select,
            "select",
            side_effect=[
                ([upstream], [], []),
                ([client], [], []),
                ([upstream], [], []),
            ],
        ), mock.patch.object(
            zen_proxy, "_drain_client"
        ), mock.patch.object(
            zen_proxy, "_note_stream_reset"
        ) as note, mock.patch.object(
            zen_proxy, "_record_reset"
        ) as reset:
            zen_proxy._relay(client, upstream, "opencode.ai", None, "edge-a")

        self.assertFalse(note.called)
        self.assertFalse(reset.called)

    def test_reset_while_the_client_waits_is_reported(self) -> None:
        client = self._FakeSocket([])
        upstream = self._FakeSocket(
            [b"HTTP/1.1 200 OK\r\n\r\n", ConnectionResetError("cut")]
        )
        with mock.patch.object(
            zen_proxy.select,
            "select",
            side_effect=[
                ([upstream], [], []),
                ([upstream], [], []),
                ([], [], []),
            ],
        ), mock.patch.object(
            zen_proxy, "_drain_client"
        ), mock.patch.object(
            zen_proxy, "_note_stream_reset"
        ) as note:
            zen_proxy._relay(client, upstream, "opencode.ai", None, "edge-a")

        note.assert_called_once()
        host, detail, state, edge = note.call_args.args
        self.assertEqual(host, "opencode.ai")
        self.assertIn("after response", detail)
        self.assertIsNone(state)
        self.assertEqual(edge, "edge-a")

    def test_client_gone_detects_a_pending_close(self) -> None:
        left, right = socket.socketpair()
        try:
            self.assertFalse(zen_proxy._client_gone(left, set(), seconds=0.02))
            right.close()
            self.assertTrue(zen_proxy._client_gone(left, set(), seconds=0.5))
        finally:
            left.close()


class TaskEnabledParseTests(unittest.TestCase):
    def _enabled_with(self, xml: str) -> bool:
        res = mock.Mock(returncode=0, stdout=xml)
        with mock.patch.object(ouc_common, "run_hidden", return_value=res):
            return ouc_common.task_enabled("Example-Task")

    def test_enabled_tasks_omit_the_element(self) -> None:
        self.assertTrue(self._enabled_with("<Task><Settings></Settings></Task>"))

    def test_disabled_task_is_detected(self) -> None:
        self.assertFalse(
            self._enabled_with("<Task><Settings><Enabled>false</Enabled></Settings></Task>")
        )

    def test_utf16_text_decoded_as_single_bytes_still_parses(self) -> None:
        xml = "<Task><Settings><Enabled>false</Enabled></Settings></Task>"
        interleaved = "".join(char + "\x00" for char in xml)
        self.assertFalse(self._enabled_with(interleaved))

    def test_missing_task_is_not_enabled(self) -> None:
        res = mock.Mock(returncode=1, stdout="")
        with mock.patch.object(ouc_common, "run_hidden", return_value=res):
            self.assertFalse(ouc_common.task_enabled("Missing-Task"))


class AutoRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._saved_log = avatar_ui.AUTO_REPAIR_LOG
        avatar_ui.AUTO_REPAIR_LOG = Path(self.tmp.name) / "auto_repair.log"

    def tearDown(self) -> None:
        avatar_ui.AUTO_REPAIR_LOG = self._saved_log
        self.tmp.cleanup()

    def _api(self, state: dict) -> avatar_ui.AvatarControlApi:
        api = object.__new__(avatar_ui.AvatarControlApi)
        api._repair_lock = threading.Lock()
        api._repair_last = {}
        api._repair_actions = []
        api._repair_status = ""
        api._repair_enabled = True
        api._action_lock = threading.Lock()
        api.get_state = lambda force_egress=False: state
        api._repair_performed = []
        api._run_repair_action = lambda action: (
            api._repair_performed.append(action) or {"ok": True, "message": "done"}
        )
        return api

    def _state(self, *, wired: bool, listening: bool, keeper_running: bool) -> dict:
        return {
            "services": {
                "proxy_listening": listening,
                "keeper_running": keeper_running,
                "keeper_heartbeat": 1.0,
            },
            "warp": {"connected": True, "rotating": False},
            "proxy": {"fallback_active": False, "errors_5m": 0},
            "probe": {"code": "ok"},
            "egress": {"mode": "warp"},
            "lane": {"desktop_service_wired": wired, "path_wired": False},
        }

    def test_repairs_proxy_only_when_the_task_was_not_disabled(self) -> None:
        state = self._state(wired=True, listening=False, keeper_running=False)
        api = self._api(state)

        with mock.patch.object(avatar_ui, "task_enabled", return_value=True):
            api._auto_repair_tick()
        self.assertEqual(api._repair_performed, ["start_keeper"])

        api2 = self._api(state)
        with mock.patch.object(avatar_ui, "task_enabled", return_value=False):
            api2._auto_repair_tick()
        self.assertEqual(api2._repair_performed, [])

    def test_fallback_changes_edge_instead_of_restarting_a_healthy_route(self) -> None:
        state = self._state(wired=True, listening=True, keeper_running=True)
        state["proxy"] = {"fallback_active": True, "errors_5m": 1}
        api = self._api(state)

        api._auto_repair_tick()

        self.assertEqual(api._repair_performed, ["hop"])

    def test_a_freshly_booted_clock_still_allows_the_first_repair(self) -> None:
        # time.monotonic() counts from boot, so a machine that started seconds
        # ago must not be read as "a repair just ran".
        state = self._state(wired=True, listening=True, keeper_running=True)
        state["proxy"] = {"fallback_active": True, "errors_5m": 1}
        api = self._api(state)

        with mock.patch.object(avatar_ui.time, "monotonic", return_value=5.0):
            api._auto_repair_tick()

        self.assertEqual(api._repair_performed, ["hop"])

    def test_repeated_repairs_respect_the_cooldown(self) -> None:
        state = self._state(wired=True, listening=False, keeper_running=False)
        api = self._api(state)

        with mock.patch.object(avatar_ui, "task_enabled", return_value=True):
            api._auto_repair_tick()
            api._auto_repair_tick()

        self.assertEqual(api._repair_performed, ["start_keeper"])


class HealthTests(unittest.TestCase):
    def _health(
        self,
        *,
        proxy: dict,
        net_errors: list[str],
        guard_free_wall: int = 0,
        guard_backoff: int = 0,
    ) -> dict:
        api = object.__new__(avatar_ui.AvatarControlApi)
        return api._build_health(
            warp_installed=True,
            warp_connected=True,
            rotating=False,
            egress={"mode": "warp"},
            keeper_running=True,
            guard_running=True,
            proxy_listening=True,
            svc_wired=True,
            installed=True,
            probe={"ok": True, "code": "ok", "ms": 120},
            proxy=proxy,
            net_errors=net_errors,
            desktop_installed=True,
            cli_installed=True,
            path_wired=True,
            guard_free_wall=guard_free_wall,
            guard_backoff=guard_backoff,
        )

    def test_direct_fallback_is_visible_and_actionable(self) -> None:
        health = self._health(
            proxy={"fallback_active": True, "fallback_age": 120}, net_errors=[]
        )
        issue = next(i for i in health["issues"] if i["title"] == "Using a direct connection")

        self.assertEqual(issue["level"], "warn")
        self.assertEqual(issue["fix"], "repair_warp")
        self.assertIn("2 minutes ago", issue["detail"])

    def test_recent_transport_errors_are_reported_without_duplicate_fallback(self) -> None:
        health = self._health(
            proxy={"fallback_active": False}, net_errors=["ECONNRESET while reading"]
        )
        titles = [i["title"] for i in health["issues"]]
        self.assertIn("OpenCode hit a network error", titles)

        duplicate = self._health(
            proxy={"fallback_active": True, "fallback_age": 120},
            net_errors=["ECONNRESET while reading"],
        )
        duplicate_titles = [i["title"] for i in duplicate["issues"]]
        self.assertIn("Using a direct connection", duplicate_titles)
        self.assertNotIn("OpenCode hit a network error", duplicate_titles)

    def test_free_limit_that_ignores_new_ips_is_explained(self) -> None:
        future = int(time.time()) + 3600
        health = self._health(
            proxy={"fallback_active": False},
            net_errors=[],
            guard_free_wall=future,
        )
        issue = next(
            i
            for i in health["issues"]
            if i["title"] == "The free limit is not following the IP"
        )

        self.assertEqual(issue["level"], "warn")
        self.assertEqual(issue["fix"], "hop")
        self.assertIn("refills around", issue["detail"])
        self.assertIn("continue by themselves", issue["detail"])
        self.assertNotIn(
            "Auto-rotation is taking a break",
            [i["title"] for i in health["issues"]],
        )

    def test_repeated_stream_resets_are_surfaced_with_a_rotation_action(self) -> None:
        health = self._health(
            proxy={"fallback_active": False, "stream_resets_5m": 2}, net_errors=[]
        )
        issue = next(
            i for i in health["issues"] if i["title"] == "Response streams keep dropping"
        )

        self.assertEqual(issue["level"], "warn")
        self.assertEqual(issue["fix"], "hop")

        single = self._health(
            proxy={"fallback_active": False, "stream_resets_5m": 1}, net_errors=[]
        )
        self.assertNotIn(
            "Response streams keep dropping",
            [i["title"] for i in single["issues"]],
        )


class PublicEgressTests(unittest.TestCase):
    def test_local_warp_address_is_not_accepted_as_public_egress(self) -> None:
        with mock.patch.object(
            ouc_common, "get_egress_ip", return_value="203.0.113.7"
        ), mock.patch.object(
            ouc_common, "get_warp_local_v6", return_value="2606:4700:110:8a1e::1"
        ), mock.patch.object(
            proxy_chain, "get_egress_config", return_value={"mode": "warp", "warp_scope": "tun"}
        ):
            self.assertEqual(
                ouc_common.get_egress_v6(timeout=0.1), "2606:4700:110:8a1e::1"
            )
            self.assertEqual(ouc_common.get_public_v6(timeout=0.1), "")

    def test_public_ipv6_is_returned(self) -> None:
        with mock.patch.object(
            ouc_common, "get_egress_ip", return_value="2606:4700:110:8a1e::2"
        ):
            self.assertEqual(
                ouc_common.get_public_v6(timeout=0.1), "2606:4700:110:8a1e::2"
            )

    def test_the_egress_probe_measures_the_inference_host_first(self) -> None:
        # A trace from another Cloudflare host can report an address the model
        # traffic never uses, which makes a rotation that changed nothing look
        # successful.
        self.assertTrue(
            ouc_common._EGRESS_ENDPOINTS[0].startswith("https://opencode.ai/")
        )

    def test_a_trace_body_is_parsed_to_its_address(self) -> None:
        body = "fl=abc\nh=opencode.ai\nip=2a09:bac5:48e9:682::a6:d\nts=1\nwarp=on\n"

        self.assertEqual(
            ouc_common._parse_egress_body(body), "2a09:bac5:48e9:682::a6:d"
        )


class HopGuardTests(unittest.TestCase):
    def test_a_disconnected_tunnel_is_not_rotated_in_a_loop(self) -> None:
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            calls.append(list(args))
            return (0, "")

        with mock.patch.object(
            ouc_common, "warp_status", return_value=(False, "warp", "Disconnected")
        ), mock.patch.object(
            ouc_common, "run_warp", side_effect=fake_run
        ), mock.patch.object(
            ouc_common, "ensure_warp_mode"
        ), mock.patch.object(
            ouc_common, "ensure_warp_protocol"
        ), mock.patch.object(
            ouc_common.time, "sleep"
        ):
            self.assertEqual(ouc_common.hop_once("warp-cli"), "")

        self.assertEqual(calls, [["connect"]])


class HopReportTests(unittest.TestCase):
    """hop_report distinguishes the four ways a rotation can end."""

    def _run(self, status, rotated, observed, reset=False):
        with mock.patch.object(
            ouc_common, "ensure_warp_mode", return_value=True
        ), mock.patch.object(
            ouc_common, "ensure_warp_protocol", return_value=True
        ), mock.patch.object(
            ouc_common, "warp_status", return_value=status
        ), mock.patch.object(
            ouc_common, "run_warp", return_value=(0, "")
        ), mock.patch.object(
            ouc_common, "time"
        ) as fake_time, mock.patch.object(
            ouc_common, "_rotated_egress", return_value=rotated
        ), mock.patch.object(
            ouc_common, "get_public_v6", return_value=observed
        ), mock.patch.object(
            ouc_common, "_full_registration_reset", return_value=reset
        ):
            fake_time.sleep.return_value = None
            fake_time.time.return_value = 1_800_000_000.0
            return ouc_common.hop_report("warp-cli", previous="2606:4700:1::")

    def test_a_new_block_is_reported_as_fresh_with_its_address(self) -> None:
        report = self._run((True, "warp", ""), "2606:4700:2::7", "")

        self.assertEqual(report["status"], "fresh")
        self.assertEqual(report["address"], "2606:4700:2::7")
        self.assertEqual(report["block"], "2606:4700:2::")
        self.assertEqual(report["previous_block"], "2606:4700:1::")

    def test_a_reused_block_is_reported_without_an_address(self) -> None:
        report = self._run((True, "warp", ""), "", "2606:4700:1::5")

        self.assertEqual(report["status"], "reused")
        self.assertEqual(report["address"], "")
        self.assertEqual(report["block"], "2606:4700:1::")
        self.assertIn("already", report["detail"])

    def test_a_tunnel_that_never_returns_is_reported_as_down(self) -> None:
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            calls.append(list(args))
            return (0, "")

        with mock.patch.object(
            ouc_common, "warp_status", return_value=(False, "warp", "Disconnected")
        ), mock.patch.object(
            ouc_common, "run_warp", side_effect=fake_run
        ), mock.patch.object(
            ouc_common, "ensure_warp_mode"
        ), mock.patch.object(
            ouc_common, "ensure_warp_protocol"
        ), mock.patch.object(
            ouc_common.time, "sleep"
        ):
            report = ouc_common.hop_report("warp-cli")

        self.assertEqual(report["status"], "down")
        self.assertEqual(report["address"], "")
        self.assertEqual(calls, [["connect"]])

    def test_a_connected_tunnel_without_a_probe_is_not_called_fresh(self) -> None:
        report = self._run((True, "warp", ""), "", "")

        self.assertEqual(report["status"], "unreachable")
        self.assertEqual(report["address"], "")
        self.assertIn("never answered", report["detail"])

    def test_hop_once_keeps_its_contract_of_an_address_or_nothing(self) -> None:
        with mock.patch.object(
            ouc_common, "hop_report", return_value={"status": "reused", "address": ""}
        ):
            self.assertEqual(ouc_common.hop_once("warp-cli"), "")


class FreeWallTests(unittest.TestCase):
    def test_reset_is_the_next_utc_midnight(self) -> None:
        now = int(datetime(2026, 11, 17, 12, 29, tzinfo=timezone.utc).timestamp())
        reset = datetime.fromtimestamp(
            zen_guard._next_utc_midnight(now), timezone.utc
        )
        self.assertEqual(reset, datetime(2026, 11, 18, 0, 0, tzinfo=timezone.utc))

    def test_two_fresh_addresses_that_hit_the_free_wall_pause_until_reset(self) -> None:
        now = int(datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc).timestamp())
        state = zen_guard._default_state()
        state["last_ok_hop"] = now - 30
        state["last_free_wall"] = now - 5

        with mock.patch.object(zen_guard, "_save_state"), mock.patch.object(
            zen_guard, "append_log"
        ), mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            self.assertFalse(zen_guard._note_wall(state, now))
            self.assertEqual(state["free_wall_hops"], 1)

            state["last_ok_hop"] = now + 100
            state["last_free_wall"] = now + 105
            self.assertTrue(zen_guard._note_wall(state, now + 110))

        self.assertEqual(
            state["free_wall_until"], zen_guard._next_utc_midnight(now + 110)
        )
        self.assertEqual(state["backoff_until"], state["free_wall_until"])


class CurlEgressTests(unittest.TestCase):
    def test_a_direct_probe_ignores_environment_proxies(self) -> None:
        completed = mock.Mock(stdout="ip=1.2.3.4\n")
        with mock.patch.object(ouc_common, "run_hidden", return_value=completed) as run:
            found = ouc_common._curl_egress("curl", "", True, 2.0)

        self.assertEqual(found, "1.2.3.4")
        args = run.call_args[0][0]
        self.assertIn("--noproxy", args)
        self.assertIn("-6", args)

    def test_a_proxy_probe_uses_only_the_configured_proxy(self) -> None:
        completed = mock.Mock(stdout="ip=1.2.3.4\n")
        with mock.patch.object(ouc_common, "run_hidden", return_value=completed) as run:
            ouc_common._curl_egress("curl", "socks5h://127.0.0.1:1080", False, 2.0)

        args = run.call_args[0][0]
        self.assertIn("-x", args)
        self.assertNotIn("--noproxy", args)


class CustomProxyFailoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._saved = (
            proxy_chain.EGRESS_CONFIG_FILE,
            proxy_chain.PROXY_INDEX_FILE,
            proxy_chain.ensure_dirs,
        )
        proxy_chain.EGRESS_CONFIG_FILE = self.dir / "egress_mode.json"
        proxy_chain.PROXY_INDEX_FILE = self.dir / "custom_proxy_index.txt"
        proxy_chain.ensure_dirs = lambda: None
        proxy_chain.EGRESS_CONFIG_FILE.write_text(
            json.dumps(
                {
                    "mode": "custom",
                    "warp_scope": "tun",
                    "custom_proxy": "10.0.0.1:1080,10.0.0.2:1080",
                    "custom_type": "socks5",
                }
            ),
            encoding="utf-8",
        )
        proxy_chain.PROXY_INDEX_FILE.write_text("0", encoding="utf-8")

    def tearDown(self) -> None:
        (
            proxy_chain.EGRESS_CONFIG_FILE,
            proxy_chain.PROXY_INDEX_FILE,
            proxy_chain.ensure_dirs,
        ) = self._saved
        self.tmp.cleanup()

    def test_failover_advances_without_blocking_verification(self) -> None:
        def warp_down(host: str, port: int):
            raise ConnectionError("warp down")

        with mock.patch.object(
            proxy_chain, "open_socks5_tunnel", side_effect=OSError("node down")
        ), mock.patch.object(
            proxy_chain, "open_http_proxy_tunnel", side_effect=OSError("node down")
        ), mock.patch.object(
            proxy_chain,
            "rotate_custom_proxy",
            side_effect=AssertionError("request path must not verify proxy nodes"),
        ), mock.patch.object(
            proxy_chain, "advance_custom_proxy", wraps=proxy_chain.advance_custom_proxy
        ) as advance:
            with self.assertRaises(ConnectionError):
                proxy_chain.open_multi_egress_upstream("opencode.ai", 443, warp_down)

        self.assertGreaterEqual(advance.call_count, 1)
        self.assertEqual(proxy_chain.PROXY_INDEX_FILE.read_text(encoding="utf-8"), "0")


class CmdWrapperEncodingTests(unittest.TestCase):
    def test_non_ascii_path_switches_the_shim_to_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "opencode.cmd"
            content = (
                "@echo off\r\n"
                '"C:\\Users\\\u043f\u0440\u043e\u0444\u0438\u043b\u044c\\python.exe" '
                '"C:\\Users\\\u043f\u0440\u043e\u0444\u0438\u043b\u044c\\zen_lane.py" %*\r\n'
                "exit /b %ERRORLEVEL%\r\n"
            )
            avatar_ui._write_cmd_wrapper(target, content)
            data = target.read_bytes()
            self.assertIn(b"chcp 65001 >nul", data)
            self.assertEqual(
                data.decode("utf-8"),
                content.replace("@echo off\r\n", "@echo off\r\nchcp 65001 >nul\r\n", 1),
            )

    def test_ascii_path_keeps_the_shim_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "opencode.cmd"
            content = (
                '@echo off\r\n"C:\\Python310\\python.exe" '
                '"C:\\ouc\\zen_lane.py" %*\r\nexit /b %ERRORLEVEL%\r\n'
            )
            avatar_ui._write_cmd_wrapper(target, content)
            self.assertEqual(target.read_bytes(), content.encode("ascii"))
            self.assertNotIn(b"chcp", target.read_bytes())

    def test_deploy_handles_a_non_ascii_install_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "\u043f\u0440\u043e\u0444\u0438\u043b\u044c"
            bin_dir = base / "bin"
            scripts_dir = base / "scripts"
            bin_dir.mkdir(parents=True)
            scripts_dir.mkdir(parents=True)
            with mock.patch.object(avatar_ui, "BIN_DIR", bin_dir), mock.patch.object(
                avatar_ui, "SCRIPTS_DIR", scripts_dir
            ), mock.patch.object(avatar_ui, "ensure_dirs"), mock.patch.object(
                avatar_ui.sys, "frozen", True, create=True
            ):
                avatar_ui._deploy_scripts_and_shims()

            shim = bin_dir / "opencode.cmd"
            self.assertTrue(shim.is_file())
            self.assertIn(b"chcp 65001 >nul", shim.read_bytes())


class RegistrationResetTests(unittest.TestCase):
    def setUp(self) -> None:
        ouc_common._LAST_REG_RESET = 0.0

    def tearDown(self) -> None:
        ouc_common._LAST_REG_RESET = 0.0

    def test_a_second_reset_inside_the_cooldown_is_refused(self) -> None:
        with mock.patch.object(ouc_common, "run_warp", return_value=(0, "")), mock.patch.object(
            ouc_common, "warp_registration_healthy", return_value=False
        ), mock.patch.object(
            ouc_common, "repair_warp_registration", return_value=True
        ), mock.patch.object(
            ouc_common, "ensure_warp_mode", return_value=True
        ):
            self.assertTrue(ouc_common._full_registration_reset("warp-cli", "warp"))
            self.assertFalse(ouc_common._full_registration_reset("warp-cli", "warp"))

    def test_a_refused_registration_leaves_warp_alone(self) -> None:
        calls: list[str] = []

        def fake_run(args, **kwargs):
            calls.append(args[0])
            return 0, ""

        with mock.patch.object(ouc_common, "run_warp", side_effect=fake_run), mock.patch.object(
            ouc_common, "warp_registration_healthy", return_value=False
        ), mock.patch.object(
            ouc_common, "repair_warp_registration", return_value=False
        ), mock.patch.object(ouc_common, "time") as fake_time:
            fake_time.sleep.return_value = None
            fake_time.time.return_value = 1_800_000_000.0
            self.assertFalse(ouc_common._full_registration_reset("warp-cli", "warp"))

        self.assertIn("registration", calls)
        self.assertNotIn("connect", calls)

    def test_hop_falls_back_to_a_registration_reset(self) -> None:
        with mock.patch.object(
            ouc_common, "ensure_warp_mode", return_value=True
        ), mock.patch.object(
            ouc_common, "ensure_warp_protocol", return_value=True
        ), mock.patch.object(
            ouc_common, "warp_status", return_value=(True, "warp", "")
        ), mock.patch.object(
            ouc_common, "run_warp", return_value=(0, "")
        ), mock.patch.object(
            ouc_common, "time"
        ) as fake_time, mock.patch.object(
            ouc_common, "_rotated_egress", return_value=""
        ), mock.patch.object(
            ouc_common, "_full_registration_reset", return_value=False
        ) as reset:
            fake_time.sleep.return_value = None
            fake_time.time.return_value = 1_800_000_000.0
            ouc_common.hop_once("warp-cli", previous="2606:4700:1::")

        reset.assert_called_once()


class ServiceWiringTests(unittest.TestCase):
    """The dashboard and doctor agree with OpenCode about the proxy env."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.file = Path(self.tmp.name) / "service.json"
        self._saved = ouc_common.SERVICE_FILE
        ouc_common.SERVICE_FILE = self.file

    def tearDown(self) -> None:
        ouc_common.SERVICE_FILE = self._saved
        self.tmp.cleanup()

    def _write(self, env) -> None:
        self.file.write_text(json.dumps({"env": env}), encoding="utf-8")

    def test_lowercase_keys_written_by_opencode_still_count(self) -> None:
        self._write({"https_proxy": "http://127.0.0.1:41987"})

        self.assertTrue(ouc_common.service_proxy_wired(41987))

    def test_uppercase_keys_count(self) -> None:
        self._write({"HTTPS_PROXY": "http://127.0.0.1:41987"})

        self.assertTrue(ouc_common.service_proxy_wired(41987))

    def test_a_port_mismatch_is_not_wired(self) -> None:
        self._write({"HTTPS_PROXY": "http://127.0.0.1:1080"})

        self.assertFalse(ouc_common.service_proxy_wired(41987))

    def test_a_missing_file_is_not_wired(self) -> None:
        self.assertFalse(ouc_common.service_proxy_wired(41987))

    def test_a_service_file_without_env_is_not_wired(self) -> None:
        self.file.write_text(json.dumps({"password": "x", "env": None}), encoding="utf-8")

        self.assertFalse(ouc_common.service_proxy_wired(41987))


if __name__ == "__main__":
    unittest.main()
