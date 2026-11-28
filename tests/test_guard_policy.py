"""Detection, retry policy, audit and manual-rotation handling."""

from __future__ import annotations

import contextlib
import json
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
sys.path.insert(0, str(ROOT / "relay"))

import avatar_ui
import zen_guard


def _stamp(seconds_ago: float) -> str:
    when = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class GuardBase(unittest.TestCase):
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
        self.audit_file = base / "guard_audit.jsonl"
        self._patches = [
            mock.patch.object(zen_guard, "GUARD_STATE_FILE", self.state_file),
            mock.patch.object(zen_guard, "GUARD_LOG_FILE", self.log_file),
            mock.patch.object(zen_guard, "OPENCODE_LOG_FILE", self.opencode_log),
            mock.patch.object(zen_guard, "LANE_DIR", self.lane),
            mock.patch.object(zen_guard, "OPENCODE_DB_FILE", self.db_file),
            mock.patch.object(zen_guard, "AUDIT_FILE", self.audit_file),
            mock.patch.object(avatar_ui, "GUARD_STATE_FILE", self.state_file),
        ]
        for patch in self._patches:
            patch.start()
        self.now = 1_800_000_000

    def tearDown(self) -> None:
        for patch in self._patches:
            patch.stop()
        self._tmp.cleanup()

    def write_state(self, **fields) -> dict:
        state = dict(zen_guard._default_state())
        state.update(fields)
        self.state_file.write_text(json.dumps(state), encoding="utf-8")
        return state

    def read_state(self) -> dict:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def audit_lines(self) -> list[dict]:
        if not self.audit_file.is_file():
            return []
        return [
            json.loads(line)
            for line in self.audit_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def append_log(self, text: str) -> None:
        with self.opencode_log.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")


class WallDetectionTests(GuardBase):
    def test_the_free_limit_error_marker_counts(self) -> None:
        self.assertEqual(
            zen_guard._classify_wall_line("INFO FreeUsageLimitError: free tier", 10_000),
            "wall",
        )

    def test_a_healthy_mention_of_rate_limits_is_not_a_wall(self) -> None:
        # Configuration and docs talk about limits too; only error records count.
        self.assertEqual(
            zen_guard._classify_wall_line("INFO rate limit exceeded handler installed", 10_000),
            "",
        )

    def test_a_429_inside_an_error_record_counts(self) -> None:
        self.assertEqual(
            zen_guard._classify_wall_line(
                "ERROR level=error sessionID=ses_abc fetch failed status=429", 10_000
            ),
            "wall",
        )

    def test_a_line_older_than_the_window_is_stale(self) -> None:
        line = f"ERROR timestamp={_stamp(600)} FreeUsageLimitError"
        self.assertEqual(
            zen_guard._classify_wall_line(line, int(time.time())), "stale"
        )

    def test_a_recent_timestamp_is_still_fresh(self) -> None:
        line = f"ERROR timestamp={_stamp(5)} FreeUsageLimitError"
        self.assertEqual(
            zen_guard._classify_wall_line(line, int(time.time())), "wall"
        )

    def test_a_truncated_log_does_not_replay_the_old_tail(self) -> None:
        self.opencode_log.write_text(
            "ERROR FreeUsageLimitError: old wall\n", encoding="utf-8"
        )
        size = self.opencode_log.stat().st_size
        state = self.write_state(offset=size + 5_000)

        wall, sessions = zen_guard._read_new_log_bytes(state, self.now)

        self.assertFalse(wall)
        self.assertEqual(sessions, [])
        self.assertEqual(self.read_state()["offset"], size)
        self.assertEqual(self.audit_lines()[-1]["decision"], "stale-wall")

    def test_a_fresh_wall_line_is_read_and_audited(self) -> None:
        self.append_log("ERROR sessionID=ses_a FreeUsageLimitError: free usage limit")
        state = self.write_state()

        wall, sessions = zen_guard._read_new_log_bytes(state, int(time.time()))

        self.assertTrue(wall)
        self.assertEqual(sessions, ["ses_a"])
        events = [item["event"] for item in self.audit_lines()]
        self.assertIn("wall", events)


class PolicyTests(GuardBase):
    def test_a_wall_after_the_guards_own_continue_is_not_counted(self) -> None:
        state = self.write_state(
            last_ok_hop=self.now - 40,
            last_free_wall=self.now - 5,
            resumed={"ses_a": self.now - 20},
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            self.assertFalse(zen_guard._note_wall(state, self.now, ["ses_a"]))

        self.assertEqual(state["free_wall_hops"], 0)
        self.assertEqual(state["failed_hops"], 0)
        # It still slows the reconnect cadence down, once per hop.
        self.assertEqual(state["retry_level"], 1)
        self.assertEqual(zen_guard._rotation_wait(state), 2 * 60)
        self.assertIn("own 'continue'", self.log_file.read_text(encoding="utf-8"))

    def test_the_same_hop_cannot_escalate_the_ladder_twice(self) -> None:
        state = self.write_state(
            last_ok_hop=self.now - 40,
            last_free_wall=self.now - 5,
            resumed={"ses_a": self.now - 20},
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now, ["ses_a"])
            zen_guard._note_wall(state, self.now + 5, ["ses_a"])

        self.assertEqual(state["retry_level"], 1)

    def test_the_retry_ladder_grows_and_stops_at_ten_minutes(self) -> None:
        waits = [
            zen_guard._retry_wait({"retry_level": level}) for level in range(6)
        ]
        self.assertEqual(waits, [75, 120, 300, 600, 600, 600])

    def test_a_second_wall_for_the_same_hop_does_not_escalate_again(self) -> None:
        state = self.write_state(
            last_ok_hop=self.now - 60,
            last_free_wall=self.now - 30,
            free_wall_hops=2,
            retry_level=1,
            ladder_marked_hop=self.now - 60,
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now)

        self.assertEqual(state["retry_level"], 1)

    def test_an_old_all_day_pause_is_shortened_after_an_upgrade(self) -> None:
        midnight = self.now + 6 * 3600
        state = self.write_state(free_wall_until=midnight, backoff_until=midnight, free_wall_hops=2)

        with mock.patch.object(zen_guard, "FREE_WALL_LATCH", False):
            zen_guard._shorten_old_latch(state, self.now)

        self.assertEqual(state["free_wall_until"], 0)
        self.assertEqual(state["free_wall_hops"], 0)
        self.assertEqual(state["backoff_until"], self.now + zen_guard.RETRY_STEPS[-1])
        self.assertIn("shortened", self.log_file.read_text(encoding="utf-8"))

    def test_a_hop_that_held_resets_the_ladder(self) -> None:
        state = self.write_state(
            retry_level=2,
            last_ok_hop=self.now - zen_guard.REWALL_SECONDS - 10,
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now)

        self.assertEqual(state["retry_level"], 0)
        self.assertEqual(zen_guard._retry_wait(state), 75)

    def test_a_wall_from_an_already_blacklisted_block_is_not_counted(self) -> None:
        current = "2a09:bac5:1111:1::1"
        prefix = zen_guard.normalize_v6_64(current)
        state = self.write_state(
            last_ok_hop=self.now - 60,
            last_free_wall=self.now - 30,
            current=current,
            blacklist=[prefix],
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now)

        self.assertEqual(state["free_wall_hops"], 0)
        self.assertIn("already blacklisted", self.log_file.read_text(encoding="utf-8"))

    def test_a_wall_is_never_counted_twice_for_the_same_hop(self) -> None:
        state = self.write_state(last_ok_hop=self.now - 60, last_free_wall=self.now - 30)
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now)
            zen_guard._note_wall(state, self.now + 5)

        self.assertEqual(state["free_wall_hops"], 1)

    def test_an_expired_pause_asks_the_database_for_chats_still_on_the_wall(self) -> None:
        state = self.write_state(backoff_until=self.now - 5, free_wall_until=self.now - 5)
        state = self.read_state()

        with mock.patch.object(
            zen_guard, "_sessions_stuck_on_wall", return_value=["ses_db"]
        ), mock.patch.object(zen_guard, "_dispatch_auto_resume") as resume:
            self.assertEqual(zen_guard._pause_left(state, self.now), 0)

        self.assertIn("ses_db", state["pending"])
        resume.assert_called_once()

    def test_a_spent_account_is_only_marked_after_a_wall_follows_the_switch(self) -> None:
        state = self.write_state(
            switch_pending={"account": "cred_a", "at": self.now - 30},
            last_ok_hop=self.now - 40,
            last_free_wall=self.now - 20,
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now, [])

        self.assertTrue(self.read_state()["accounts_burned"]["cred_a"])
        self.assertEqual(self.read_state()["switch_pending"], {})

    def test_an_account_that_kept_working_is_not_marked_spent(self) -> None:
        state = self.write_state(
            switch_pending={"account": "cred_a", "at": self.now - 3600},
            last_ok_hop=self.now - 40,
            last_free_wall=self.now - 20,
        )
        state = self.read_state()

        with mock.patch.object(zen_guard, "_egress_mode", return_value="warp"):
            zen_guard._note_wall(state, self.now, [])

        self.assertEqual(self.read_state()["accounts_burned"], {})
        self.assertEqual(self.read_state()["switch_pending"], {})


class DecisionAuditTests(GuardBase):
    def test_a_decision_updates_the_state_and_the_file(self) -> None:
        state = self.write_state()
        state = self.read_state()

        zen_guard._audit(
            state,
            "decision",
            decision="defer:live",
            reason="a request is still streaming",
        )

        self.assertEqual(state["last_decision"], "defer:live - a request is still streaming")
        self.assertTrue(state["last_decision_at"])
        self.assertEqual(self.audit_lines()[-1]["decision"], "defer:live")

    def test_the_audit_file_rolls_instead_of_growing_forever(self) -> None:
        state = self.write_state()
        state = self.read_state()
        self.audit_file.write_text("x" * (zen_guard.AUDIT_ROLL_BYTES + 10), encoding="utf-8")

        zen_guard._audit(state, "decision", decision="rotate")

        rolled = self.audit_file.with_name(self.audit_file.name + ".1")
        self.assertTrue(rolled.is_file())
        self.assertEqual(self.audit_lines()[-1]["decision"], "rotate")


class _StopPoll(Exception):
    pass


class MainLoopTests(GuardBase):
    """One poll of the guard loop, stopped by raising from time.sleep."""

    def _run_one_poll(self, state_fields: dict) -> mock.Mock:
        self.write_state(**state_fields)
        switch = mock.Mock(return_value=True)
        polls = {"n": 0}

        def _sleep(_seconds: float) -> None:
            # The sleep is the first statement of each poll: let the first body
            # run, then stop the loop.
            polls["n"] += 1
            if polls["n"] >= 2:
                raise _StopPoll

        with mock.patch.object(zen_guard, "acquire_mutex", return_value=object()), \
                mock.patch.object(zen_guard, "find_warp_cli", return_value="warp-cli"), \
                mock.patch.object(zen_guard, "_heartbeat"), \
                mock.patch.object(zen_guard, "_rescue_stuck_sessions"), \
                mock.patch.object(
                    zen_guard, "_read_new_log_bytes", return_value=(True, ["ses_a"])
                ), \
                mock.patch.object(zen_guard, "_note_wall", return_value=True), \
                mock.patch.object(zen_guard, "_switch_account", switch), \
                mock.patch.object(zen_guard.time, "sleep", side_effect=_sleep):
            with self.assertRaises(_StopPoll):
                zen_guard.main()
        return switch

    def test_the_first_wall_of_the_day_does_not_spend_an_account(self) -> None:
        switch = self._run_one_poll({"free_wall_hops": 0})

        switch.assert_not_called()

    def test_an_account_is_tried_once_a_confirmed_hop_hit_the_wall(self) -> None:
        switch = self._run_one_poll({"free_wall_hops": 1})

        switch.assert_called_once()


class ManualRotationTests(GuardBase):
    def _api(self) -> avatar_ui.AvatarControlApi:
        api = object.__new__(avatar_ui.AvatarControlApi)
        api._action_lock = threading.Lock()
        api._egress_lock = threading.Lock()
        api._egress_v6 = ""
        api._last_egress_ts = 0.0
        api._refresh_egress_async = lambda force=False: None
        return api

    def test_a_manual_hop_sets_last_ok_hop_and_clears_the_pause(self) -> None:
        self.write_state(
            backoff_until=self.now + 3600,
            free_wall_until=self.now + 3600,
            free_wall_hops=2,
            retry_level=3,
        )
        api = self._api()

        @contextlib.contextmanager
        def _ctx(*_args, **_kwargs):
            yield

        with mock.patch.object(
            avatar_ui, "find_warp_cli", return_value="warp-cli"
        ), mock.patch.object(avatar_ui, "get_warp_local_v6", return_value=""), \
                mock.patch.object(avatar_ui, "keeper_pause_ctx", _ctx), \
                mock.patch.object(
                    avatar_ui,
                    "hop_report",
                    return_value={"status": "fresh", "address": "2a09:bac5:1:2::9", "detail": ""},
                ), mock.patch.object(
                    avatar_ui.AvatarControlApi, "_unlock_after_rotation", return_value="unlocked"
                ):
            result = api.hop_now()

        self.assertTrue(result["ok"])
        self.assertIn("unlocked", result["message"])
        saved = self.read_state()
        self.assertTrue(saved["last_ok_hop"])
        self.assertEqual(saved["backoff_until"], 0)
        self.assertEqual(saved["free_wall_until"], 0)
        self.assertEqual(saved["free_wall_hops"], 0)
        self.assertEqual(saved["retry_level"], 0)
        self.assertEqual(saved["current"], "2a09:bac5:1:2::9")
        self.assertEqual(self.audit_lines()[-1]["event"], "hop")
        self.assertEqual(self.audit_lines()[-1]["source"], "manual")

    def test_clear_blacklist_drops_the_day_map_too(self) -> None:
        self.write_state(blacklist=["2a09:bac5:1:2::"], blacklist_day={"2a09:bac5:1:2::": 99})
        api = object.__new__(avatar_ui.AvatarControlApi)

        result = api.clear_blacklist()

        self.assertTrue(result["ok"])
        saved = self.read_state()
        self.assertEqual(saved["blacklist"], [])
        self.assertEqual(saved["blacklist_day"], {})


if __name__ == "__main__":
    unittest.main()
