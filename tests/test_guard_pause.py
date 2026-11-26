"""Guard rotation gating: a reconnect must never land on a live response."""

from __future__ import annotations

import contextlib
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "relay"))

import zen_guard


class GuardGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.state_file = base / "state.json"
        self.log_file = base / "guard.log"
        self.opencode_log = base / "opencode.log"
        self.opencode_log.write_text("boot\n", encoding="utf-8")
        self.lane = base / "lane"
        self.lane.mkdir()
        self.db_file = base / "opencode.db"
        self._patches = [
            mock.patch.object(zen_guard, "GUARD_STATE_FILE", self.state_file),
            mock.patch.object(zen_guard, "GUARD_LOG_FILE", self.log_file),
            mock.patch.object(zen_guard, "OPENCODE_LOG_FILE", self.opencode_log),
            mock.patch.object(zen_guard, "LANE_DIR", self.lane),
            mock.patch.object(zen_guard, "OPENCODE_DB_FILE", self.db_file),
        ]
        for p in self._patches:
            p.start()
        self.now = 1_800_000_000

    def tearDown(self) -> None:
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def write_state(self, **fields) -> dict:
        state = dict(zen_guard._default_state())
        state.update(fields)
        self.state_file.write_text(json.dumps(state), encoding="utf-8")
        return state

    def read_state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    # -- pause ---------------------------------------------------------

    def test_active_pause_reports_remaining_and_leaves_state_alone(self) -> None:
        self.write_state(backoff_until=self.now + 600)
        state = self.read_state()

        self.assertEqual(zen_guard._pause_left(state, self.now), 600)
        self.assertEqual(state["backoff_until"], self.now + 600)
        self.assertFalse(self.log_file.exists())

    def test_expired_pause_is_cleared_once(self) -> None:
        self.write_state(
            backoff_until=self.now - 5,
            failed_hops=2,
            free_wall_hops=3,
            free_wall_until=self.now - 5,
            defer_since=self.now - 90,
        )
        state = self.read_state()

        self.assertEqual(zen_guard._pause_left(state, self.now), 0)
        saved = self.read_state()
        self.assertEqual(saved["backoff_until"], 0)
        self.assertEqual(saved["failed_hops"], 0)
        self.assertEqual(saved["free_wall_hops"], 0)
        self.assertEqual(saved["defer_since"], 0)

    def test_expired_free_wall_pause_resumes_the_waiting_chat(self) -> None:
        self.write_state(
            backoff_until=self.now - 5,
            free_wall_until=self.now - 5,
            pending={"ses_a": self.now - 3600},
            resumed={"ses_a": 0},
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_dispatch_auto_resume") as resume, \
                mock.patch.object(zen_guard, "time") as fake_time:
            fake_time.time.return_value = float(self.now)
            self.assertEqual(zen_guard._pause_left(state, self.now), 0)

        resume.assert_called_once()
        self.assertIn("allowance window reopened", self.log_file.read_text(encoding="utf-8"))

    def test_an_ordinary_pause_does_not_send_continue(self) -> None:
        self.write_state(backoff_until=self.now - 5, pending={"ses_a": self.now - 60})
        state = self.read_state()

        with mock.patch.object(zen_guard, "_dispatch_auto_resume") as resume:
            self.assertEqual(zen_guard._pause_left(state, self.now), 0)

        resume.assert_not_called()

    def test_pause_blocks_rotation_even_while_a_request_is_live(self) -> None:
        self.write_state(backoff_until=self.now + 3600)
        state = self.read_state()

        self.assertEqual(zen_guard._rotation_blocked(state, self.now, live=True), "paused")

    def test_new_wall_does_not_rotate_while_paused(self) -> None:
        self.write_state(
            backoff_until=self.now + 3600,
            last_ok_hop=self.now - 30,
            wall_pending=True,
        )
        state = self.read_state()

        self.assertTrue(zen_guard._note_wall(state, self.now))

    def test_a_wall_measured_on_the_fallback_route_is_not_counted(self) -> None:
        # The request never used the new address, so this wall proves nothing
        # about it and must not trip the "allowance ignores the IP" latch.
        self.write_state(last_ok_hop=self.now - 60, last_free_wall=self.now - 30)
        flag = self.lane / "fallback.flag"
        flag.write_text("x", encoding="utf-8")
        import os

        os.utime(flag, (self.now - 45, self.now - 45))
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now)

        self.assertEqual(self.read_state()["free_wall_hops"], 0)
        self.assertIn("not counted", self.log_file.read_text(encoding="utf-8"))

    def test_a_wall_measured_after_a_confirmed_hop_is_counted(self) -> None:
        self.write_state(last_ok_hop=self.now - 60, last_free_wall=self.now - 30)
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now)

        self.assertEqual(self.read_state()["free_wall_hops"], 1)

    def test_a_shared_tor_exit_cannot_trip_the_allowance_latch(self) -> None:
        self.write_state(
            last_ok_hop=self.now - 60,
            last_free_wall=self.now - 30,
            free_wall_hops=1,
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="tor"):
            zen_guard._note_wall(state, self.now)

        self.assertEqual(self.read_state()["free_wall_hops"], 0)

    # -- quiet window --------------------------------------------------

    def test_live_log_holds_rotation_and_starts_the_defer_clock(self) -> None:
        self.write_state()
        state = self.read_state()

        self.assertEqual(zen_guard._rotation_blocked(state, self.now, live=True), "busy")
        self.assertEqual(self.read_state()["defer_since"], self.now)

    def test_defer_clock_is_reused_across_polls(self) -> None:
        self.write_state(defer_since=self.now - 30)
        state = self.read_state()

        self.assertEqual(zen_guard._rotation_blocked(state, self.now, live=True), "busy")
        self.assertEqual(self.read_state()["defer_since"], self.now - 30)

    def test_busy_session_cannot_block_rotation_forever(self) -> None:
        self.write_state(defer_since=self.now - zen_guard.QUIET_MAX_WAIT - 1)
        state = self.read_state()

        self.assertEqual(zen_guard._rotation_blocked(state, self.now, live=True), "")
        self.assertEqual(self.read_state()["defer_since"], 0)

    def test_quiet_session_rotates_immediately(self) -> None:
        self.write_state(defer_since=self.now - 5)
        state = self.read_state()

        self.assertEqual(zen_guard._rotation_blocked(state, self.now, live=False), "")
        self.assertEqual(self.read_state()["defer_since"], 0)

    # -- liveness ------------------------------------------------------

    def test_log_written_seconds_ago_counts_as_live(self) -> None:
        stamp = time.time() - 5
        self.opencode_log.touch()
        import os

        os.utime(self.opencode_log, (stamp, stamp))

        self.assertTrue(zen_guard._work_is_live())

    def test_log_written_long_ago_counts_as_quiet(self) -> None:
        stamp = time.time() - zen_guard.QUIET_SECONDS - 5
        import os

        os.utime(self.opencode_log, (stamp, stamp))

        self.assertFalse(zen_guard._work_is_live())

    def test_missing_log_is_not_live(self) -> None:
        self.opencode_log.unlink()

        self.assertFalse(zen_guard._work_is_live())

    def _write_tunnels(
        self, count: int, age: float = 0.0, byte_age: float | None = None
    ) -> None:
        stamp = int(time.time() - age)
        data = {"active_tunnels": count, "active_tunnels_ts": stamp}
        if byte_age is not None:
            data["last_byte_ts"] = int(time.time() - byte_age)
        (self.lane / "proxy_status.json").write_text(
            json.dumps(data), encoding="utf-8"
        )

    def test_idle_tunnel_with_a_quiet_log_is_not_live(self) -> None:
        # An open keep-alive socket used to hold rotations back for the whole
        # cap even though nothing was being generated.
        stamp = time.time() - zen_guard.QUIET_SECONDS - 30
        import os

        os.utime(self.opencode_log, (stamp, stamp))
        self._write_tunnels(1, byte_age=zen_guard.QUIET_SECONDS + 5)

        self.assertFalse(zen_guard._work_is_live())

    def test_tunnel_that_relayed_bytes_counts_as_live(self) -> None:
        stamp = time.time() - zen_guard.QUIET_SECONDS - 30
        import os

        os.utime(self.opencode_log, (stamp, stamp))
        self._write_tunnels(1, byte_age=2)

        self.assertTrue(zen_guard._work_is_live())

    def test_old_proxy_tunnel_count_still_counts_as_live(self) -> None:
        stamp = time.time() - zen_guard.QUIET_SECONDS - 30
        import os

        os.utime(self.opencode_log, (stamp, stamp))
        self._write_tunnels(1)

        self.assertTrue(zen_guard._work_is_live())

    def test_closed_tunnel_with_a_quiet_log_is_not_live(self) -> None:
        stamp = time.time() - zen_guard.QUIET_SECONDS - 30
        import os

        os.utime(self.opencode_log, (stamp, stamp))
        self._write_tunnels(0)

        self.assertFalse(zen_guard._work_is_live())

    def test_stale_tunnel_snapshot_is_ignored(self) -> None:
        stamp = time.time() - zen_guard.QUIET_SECONDS - 30
        import os

        os.utime(self.opencode_log, (stamp, stamp))
        self._write_tunnels(1, age=zen_guard.TUNNEL_STATUS_MAX_AGE + 5)

        self.assertFalse(zen_guard._work_is_live())

    def test_a_landed_rotation_cannot_lift_a_free_wall_pause(self) -> None:
        pause = self.now + 7200
        state = self.write_state(backoff_until=pause, free_wall_until=pause, free_wall_hops=2)

        @contextlib.contextmanager
        def _ctx(*_args, **_kwargs):
            yield

        with mock.patch.object(
            zen_guard,
            "hop_report",
            return_value={"status": "fresh", "address": "2a09:bac5:777:1::1", "detail": ""},
        ), \
                mock.patch.object(zen_guard, "get_egress_v6", return_value="2a09:bac5:555:1::1"), \
                mock.patch.object(zen_guard, "keeper_pause_ctx", _ctx), \
                mock.patch.object(zen_guard, "_dispatch_auto_resume"), \
                mock.patch.object(zen_guard, "time") as fake_time:
            fake_time.time.return_value = float(self.now)
            zen_guard._rotate(state, "warp-cli")

        saved = self.read_state()
        self.assertEqual(saved["backoff_until"], pause)
        self.assertEqual(saved["free_wall_until"], pause)


    # -- chats left on the wall ----------------------------------------

    def test_a_chat_resumed_into_the_same_wall_waits_before_another_continue(self) -> None:
        # Sending 'continue' again straight away only adds another failed turn
        # to a chat that is standing on the same wall.
        state = dict(zen_guard._default_state())
        state["pending"] = {"ses_a": self.now - 900}
        state["resumed"] = {"ses_a": self.now - 30}

        self.assertEqual(zen_guard._resumable(state, self.now), [])

        later = self.now + zen_guard.STUCK_RETRY_SECONDS
        self.assertEqual(zen_guard._resumable(state, later), ["ses_a"])

    def test_a_wall_arriving_after_a_continue_is_queued_straight_away(self) -> None:
        state = dict(zen_guard._default_state())
        state["pending"] = {"ses_a": self.now - 5, "ses_b": self.now - 5}
        state["resumed"] = {"ses_a": self.now - 3600}

        self.assertEqual(zen_guard._resumable(state, self.now), ["ses_a", "ses_b"])

    def test_a_turned_off_resume_sends_nothing_and_says_so(self) -> None:
        state = dict(zen_guard._default_state())
        state["pending"] = {"ses_a": self.now - 60}

        import auto_resume

        with mock.patch.object(auto_resume, "is_auto_resume_enabled", return_value=False), \
                mock.patch.object(auto_resume, "clear_opencode_free_limit", return_value=0), \
                mock.patch.object(auto_resume, "resume_active_session") as resume:
            zen_guard._dispatch_auto_resume(state)

        resume.assert_not_called()
        self.assertIn(
            "resume is turned off", self.log_file.read_text(encoding="utf-8")
        )

    def test_a_failed_hop_holds_the_next_rotation_for_longer(self) -> None:
        state = dict(zen_guard._default_state())
        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            self.assertEqual(zen_guard._rotation_wait(state), zen_guard.COOLDOWN_SECONDS)

            state["failed_hops"] = 1
            self.assertEqual(
                zen_guard._rotation_wait(state), zen_guard.ROTATION_RETRY_SECONDS
            )

    def test_a_tor_circuit_is_swapped_on_the_short_cooldown(self) -> None:
        state = dict(zen_guard._default_state())
        state["failed_hops"] = 3

        with mock.patch.object(zen_guard, "_egress_mode", return_value="tor"):
            self.assertEqual(zen_guard._rotation_wait(state), zen_guard.COOLDOWN_SECONDS)

    def make_db(self, rows) -> None:
        import sqlite3

        con = sqlite3.connect(self.db_file)
        con.execute("CREATE TABLE session_v2 (id TEXT PRIMARY KEY, time_archived INTEGER)")
        con.execute("CREATE TABLE session_message (session_id TEXT, time_created INTEGER, data TEXT)")
        for session_id, created_ms, finish, archived in rows:
            con.execute("INSERT OR IGNORE INTO session_v2 VALUES (?, ?)", (session_id, archived))
            con.execute(
                "INSERT INTO session_message VALUES (?, ?, ?)",
                (session_id, created_ms, json.dumps({"finish": finish, "text": "FreeUsageLimitError"})),
            )
        con.commit()
        con.close()

    def test_only_a_chat_whose_newest_message_is_the_wall_is_stuck(self) -> None:
        now_ms = self.now * 1000
        self.make_db(
            [
                ("ses_stuck", now_ms - 120_000, "error", None),
                ("ses_typed", now_ms - 120_000, "error", None),
                ("ses_typed", now_ms - 60_000, "stop", None),
                ("ses_mention", now_ms - 60_000, "tool-calls", None),
                ("ses_archived", now_ms - 60_000, "error", now_ms),
                ("ses_old", now_ms - (zen_guard.STUCK_LOOKBACK + 60) * 1000, "error", None),
            ]
        )

        self.assertEqual(zen_guard._sessions_stuck_on_wall(self.now), ["ses_stuck"])

    def test_rescue_queues_the_chat_and_sends_continue(self) -> None:
        state = self.write_state()

        with mock.patch.object(zen_guard, "_sessions_stuck_on_wall", return_value=["ses_stuck"]), \
                mock.patch.object(zen_guard, "_dispatch_auto_resume") as resume:
            queued = zen_guard._rescue_stuck_sessions(state, self.now)

        self.assertEqual(queued, 1)
        resume.assert_called_once()
        saved = self.read_state()
        self.assertEqual(saved["pending"], {"ses_stuck": self.now})
        self.assertTrue(saved["wall_pending"])

    def test_a_chat_handled_a_moment_ago_is_not_rescued_again(self) -> None:
        state = self.write_state(resumed={"ses_stuck": self.now - 60})

        with mock.patch.object(zen_guard, "_sessions_stuck_on_wall", return_value=["ses_stuck"]), \
                mock.patch.object(zen_guard, "_dispatch_auto_resume") as resume:
            self.assertEqual(zen_guard._rescue_stuck_sessions(state, self.now), 0)

        resume.assert_not_called()


class BurnListTests(unittest.TestCase):
    """A /64 that ran out yesterday is a fresh block today."""

    def test_a_block_burned_today_is_skipped(self) -> None:
        state = dict(zen_guard._default_state())
        zen_guard._blacklist_add(state, "2606:4700:110:81b7::1")

        self.assertTrue(zen_guard._is_burnt(state, "2606:4700:110:81b7:aaaa::2"))

    def test_a_block_burned_yesterday_is_available_again(self) -> None:
        state = dict(zen_guard._default_state())
        zen_guard._blacklist_add(state, "2606:4700:110:81b7::1")
        state["blacklist_day"]["2606:4700:110:81b7::"] = zen_guard._utc_day() - 1

        self.assertFalse(zen_guard._is_burnt(state, "2606:4700:110:81b7::1"))
        self.assertEqual(state["blacklist"], [])

    def test_entries_written_before_the_day_field_existed_still_count(self) -> None:
        state = dict(zen_guard._default_state())
        state["blacklist"] = ["2606:4700:110:81b7::"]

        self.assertTrue(zen_guard._is_burnt(state, "2606:4700:110:81b7::9"))
        self.assertEqual(
            state["blacklist_day"]["2606:4700:110:81b7::"], zen_guard._utc_day()
        )

    def test_adding_the_same_block_twice_keeps_one_entry(self) -> None:
        state = dict(zen_guard._default_state())
        zen_guard._blacklist_add(state, "2606:4700:110:81b7::1")
        zen_guard._blacklist_add(state, "2606:4700:110:81b7::99")

        self.assertEqual(state["blacklist"], ["2606:4700:110:81b7::"])

    def test_the_list_stays_capped(self) -> None:
        state = dict(zen_guard._default_state())
        for i in range(zen_guard.BLACKLIST_MAX + 25):
            zen_guard._blacklist_add(state, f"2606:4700:{i:x}:81b7::1")

        self.assertEqual(len(state["blacklist"]), zen_guard.BLACKLIST_MAX)


if __name__ == "__main__":
    unittest.main()
