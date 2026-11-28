"""The client countdown is a hint: read it, clear it, try the chat, then hop."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "relay"))

import auto_resume
import avatar_ui
import zen_guard


class SoftRetryBase(unittest.TestCase):
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
        self.drafts = base / "drafts.sqlite"
        self._patches = [
            mock.patch.object(zen_guard, "GUARD_STATE_FILE", self.state_file),
            mock.patch.object(zen_guard, "GUARD_LOG_FILE", self.log_file),
            mock.patch.object(zen_guard, "OPENCODE_LOG_FILE", self.opencode_log),
            mock.patch.object(zen_guard, "LANE_DIR", self.lane),
            mock.patch.object(zen_guard, "OPENCODE_DB_FILE", self.db_file),
            mock.patch.object(zen_guard, "AUDIT_FILE", self.audit_file),
            mock.patch.object(avatar_ui, "GUARD_STATE_FILE", self.state_file),
            mock.patch.object(auto_resume, "drafts_databases", return_value=[self.drafts]),
        ]
        for patch in self._patches:
            patch.start()
        self.now = int(time.time())

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

    def audit(self) -> list[dict]:
        if not self.audit_file.is_file():
            return []
        return [
            json.loads(line)
            for line in self.audit_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def write_drafts(self, rows: dict[str, object]) -> None:
        con = sqlite3.connect(self.drafts)
        try:
            con.execute("CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB)")
            con.executemany(
                "INSERT INTO state (key, value) VALUES (?, ?)",
                [(key, value) for key, value in rows.items()],
            )
            con.commit()
        finally:
            con.close()

    def write_chat(
        self,
        *,
        newest_is_error: bool,
        session_id: str = "ses_a",
        age_seconds: int = 0,
    ) -> None:
        con = sqlite3.connect(self.db_file)
        try:
            con.execute(
                "CREATE TABLE session_v2 (id TEXT, time_archived INTEGER, "
                "time_updated INTEGER, directory TEXT, title TEXT)"
            )
            con.execute(
                "CREATE TABLE session_message (session_id TEXT, time_created INTEGER, data TEXT)"
            )
            con.execute(
                "INSERT INTO session_v2 VALUES (?, NULL, 1, '', '')", (session_id,)
            )
            payload = (
                {"finish": "error", "text": "FreeUsageLimitError: free usage limit"}
                if newest_is_error
                else {"finish": "stop", "text": "here is the answer"}
            )
            con.execute(
                "INSERT INTO session_message VALUES (?, ?, ?)",
                (session_id, int((time.time() - age_seconds) * 1000), json.dumps(payload)),
            )
            con.commit()
        finally:
            con.close()


class LockParsingTests(SoftRetryBase):
    def test_epoch_milliseconds_and_seconds_both_normalise(self) -> None:
        deadline = int(time.time()) + 3600

        self.assertEqual(auto_resume._lock_epoch(deadline * 1000), deadline)
        self.assertEqual(auto_resume._lock_epoch(deadline), deadline)
        self.assertEqual(auto_resume._lock_epoch(str(deadline)), deadline)

    def test_iso_text_is_accepted(self) -> None:
        stamp = datetime.now(timezone.utc) + timedelta(hours=5)
        got = auto_resume._lock_epoch(stamp.strftime("%Y-%m-%dT%H:%M:%SZ"))

        self.assertLessEqual(abs(got - int(stamp.timestamp())), 1)

    def test_junk_and_implausible_values_are_ignored(self) -> None:
        self.assertEqual(auto_resume._lock_epoch("not a time"), 0)
        self.assertEqual(auto_resume._lock_epoch(7), 0)
        self.assertEqual(auto_resume._lock_epoch(None), 0)
        self.assertEqual(auto_resume._lock_epoch(b""), 0)

    def test_read_opencode_lock_keeps_the_latest_deadline_and_no_values(self) -> None:
        now = int(time.time())
        self.write_drafts(
            {
                "free-limit": str((now + 3600) * 1000),
                "go-upsell": now + 7200,
                "unrelated-counter": 42,
                "some-text": "hello",
            }
        )

        info = auto_resume.read_opencode_lock()

        self.assertEqual(info["until"], now + 7200)
        self.assertEqual(info["keys"]["free-limit"], now + 3600)
        self.assertNotIn("unrelated-counter", info["keys"])
        self.assertNotIn("some-text", info["keys"])

    def test_read_opencode_lock_returns_zero_when_nothing_is_stored(self) -> None:
        self.write_drafts({"some-text": "hello"})

        self.assertEqual(auto_resume.read_opencode_lock()["until"], 0)


class ClientLockTests(SoftRetryBase):
    def test_the_guard_records_the_advertised_time_for_display_only(self) -> None:
        state = self.write_state()
        until = self.now + 6 * 3600

        with mock.patch.object(
            auto_resume, "read_opencode_lock", return_value={"until": until, "keys": {"free-limit": until}}
        ):
            zen_guard._refresh_client_lock(state, self.now)

        self.assertEqual(state["client_lock_until"], until)
        self.assertEqual(state["client_lock_keys"], {"free-limit": until})
        events = [item for item in self.audit() if item["event"] == "lock"]
        self.assertEqual(events[-1]["client_lock_until"], until)
        # A hint never becomes a decision, and never rotates anything.
        self.assertEqual(state["last_decision"], "")

    def test_the_lock_is_only_read_once_a_minute(self) -> None:
        state = self.write_state(client_lock_at=self.now - 5)

        with mock.patch.object(auto_resume, "read_opencode_lock") as reader:
            zen_guard._refresh_client_lock(state, self.now)

        reader.assert_not_called()

    def test_a_passed_wait_time_is_cleared_immediately(self) -> None:
        state = self.write_state(client_lock_until=self.now - 60, backoff_until=self.now + 600)

        with mock.patch.object(auto_resume, "clear_opencode_free_limit", return_value=2) as clear:
            cleared = zen_guard._clear_stale_lock(state, self.now)

        self.assertTrue(cleared)
        clear.assert_called_once()
        self.assertEqual(state["client_lock_until"], 0)
        self.assertEqual(self.audit()[-1]["decision"], "lock-expired")
        # The rotation pause is untouched: only the client row was dropped.
        self.assertEqual(state["backoff_until"], self.now + 600)

    def test_a_future_wait_time_is_left_alone(self) -> None:
        state = self.write_state(client_lock_until=self.now + 600)

        with mock.patch.object(auto_resume, "clear_opencode_free_limit") as clear:
            cleared = zen_guard._clear_stale_lock(state, self.now)

        self.assertFalse(cleared)
        clear.assert_not_called()
        self.assertEqual(state["client_lock_until"], self.now + 600)

    def test_the_stale_clear_is_throttled(self) -> None:
        state = self.write_state(
            client_lock_until=self.now - 60, lock_cleared_at=self.now - 10
        )

        with mock.patch.object(auto_resume, "clear_opencode_free_limit") as clear:
            cleared = zen_guard._clear_stale_lock(state, self.now)

        self.assertFalse(cleared)
        clear.assert_not_called()


class WallFallbackTests(SoftRetryBase):
    def test_a_fresh_answer_without_a_session_id_cancels_the_wall(self) -> None:
        self.write_chat(newest_is_error=False, age_seconds=5)

        with mock.patch.object(
            auto_resume, "get_latest_session_info", return_value=("ses_a", "", "")
        ):
            self.assertTrue(zen_guard._wall_already_over([]))

    def test_an_old_answer_without_a_session_id_does_not_cancel_the_wall(self) -> None:
        self.write_chat(newest_is_error=False, age_seconds=2 * 3600)

        with mock.patch.object(
            auto_resume, "get_latest_session_info", return_value=("ses_a", "", "")
        ):
            self.assertFalse(zen_guard._wall_already_over([]))

    def test_no_session_and_no_database_leaves_the_wall_alone(self) -> None:
        with mock.patch.object(auto_resume, "get_latest_session_info", return_value=None):
            self.assertFalse(zen_guard._wall_already_over([]))


class SoftRetryTests(SoftRetryBase):
    def test_a_wall_tries_the_chat_before_any_hop(self) -> None:
        state = self.write_state(pending={"ses_a": self.now})

        with mock.patch.object(
            auto_resume, "resume_active_session", return_value=(True, "sent")
        ) as resume:
            started = zen_guard._soft_retry(state, self.now, ["ses_a"])

        self.assertTrue(started)
        resume.assert_called_once_with(["ses_a"])
        self.assertEqual(state["soft_pending"], {"ses_a": self.now})
        self.assertEqual(state["resumed"]["ses_a"], self.now)
        self.assertEqual(self.audit()[-1]["decision"], "soft-retry")

    def test_one_soft_retry_per_chat(self) -> None:
        state = self.write_state(pending={"ses_a": self.now}, soft_pending={"ses_a": self.now})

        with mock.patch.object(auto_resume, "resume_active_session") as resume:
            self.assertFalse(zen_guard._soft_retry(state, self.now, ["ses_a"]))
            state["soft_pending"] = {}
            state["soft_retry"] = {"ses_a": 1}
            self.assertFalse(zen_guard._soft_retry(state, self.now, ["ses_a"]))

        resume.assert_not_called()

    def test_a_wall_after_the_guards_own_continue_is_not_retried_again(self) -> None:
        state = self.write_state(pending={"ses_a": self.now}, resumed={"ses_a": self.now - 20})

        with mock.patch.object(auto_resume, "resume_active_session") as resume:
            self.assertFalse(zen_guard._soft_retry(state, self.now, ["ses_a"]))

        resume.assert_not_called()

    def test_the_kill_switch_disables_the_attempt(self) -> None:
        state = self.write_state(pending={"ses_a": self.now})

        with mock.patch.object(zen_guard, "SOFT_RETRY_ENABLED", False), mock.patch.object(
            auto_resume, "resume_active_session"
        ) as resume:
            self.assertFalse(zen_guard._soft_retry(state, self.now, ["ses_a"]))

        resume.assert_not_called()

    def test_a_pending_retry_inside_its_window_only_waits(self) -> None:
        state = self.write_state(soft_pending={"ses_a": self.now - 10})

        self.assertEqual(zen_guard._check_soft_retry(state, self.now), "waiting")
        self.assertEqual(state["soft_pending"], {"ses_a": self.now - 10})

    def test_a_chat_that_answered_ends_the_wall_without_a_hop(self) -> None:
        self.write_chat(newest_is_error=False)
        state = self.write_state(
            soft_pending={"ses_a": self.now - 100}, retry_level=2, free_wall_hops=2
        )

        status = zen_guard._check_soft_retry(state, self.now)

        self.assertEqual(status, "ok")
        self.assertEqual(state["soft_pending"], {})
        self.assertEqual(state["last_verdict"], "resumed")
        self.assertEqual(state["retry_level"], 0)
        self.assertEqual(state["free_wall_hops"], 0)
        self.assertEqual(self.audit()[-1]["decision"], "soft-retry ok")

    def test_a_chat_back_on_the_wall_falls_through_to_the_hop(self) -> None:
        self.write_chat(newest_is_error=True)
        state = self.write_state(soft_pending={"ses_a": self.now - 100})

        status = zen_guard._check_soft_retry(state, self.now)

        self.assertEqual(status, "walled")
        self.assertEqual(state["soft_pending"], {})
        self.assertEqual(state["soft_retry"], {"ses_a": 1})
        self.assertEqual(state["last_verdict"], "still walled")
        self.assertEqual(self.audit()[-1]["decision"], "soft-retry failed")

    def test_silence_after_the_attempt_eventually_counts_as_a_failure(self) -> None:
        state = self.write_state(soft_pending={"ses_a": self.now - zen_guard.SOFT_RETRY_MAX_WAIT - 1})

        self.assertEqual(zen_guard._check_soft_retry(state, self.now), "walled")


class ResumeVerdictTests(SoftRetryBase):
    def test_a_chat_that_answered_is_recorded_as_resumed(self) -> None:
        self.write_chat(newest_is_error=False)
        state = self.write_state(
            resume_verify={"ses_a": {"at": self.now - 61, "verdict": "pending"}},
            retry_level=2,
            free_wall_hops=1,
        )

        zen_guard._verify_resume(state, self.now)

        self.assertEqual(state["resume_verify"]["ses_a"]["verdict"], "resumed")
        self.assertEqual(state["last_verdict"], "resumed")
        self.assertEqual(state["retry_level"], 0)
        self.assertEqual(state["free_wall_hops"], 0)

    def test_a_chat_still_on_the_wall_is_reported_honestly(self) -> None:
        self.write_chat(newest_is_error=True)
        state = self.write_state(resume_verify={"ses_a": {"at": self.now - 61, "verdict": "pending"}})

        zen_guard._verify_resume(state, self.now)

        self.assertEqual(state["resume_verify"]["ses_a"]["verdict"], "still walled")
        self.assertEqual(state["last_verdict"], "still walled")
        self.assertEqual(self.audit()[-1]["decision"], "resume-walled")

    def test_a_fresh_attempt_is_not_judged_early(self) -> None:
        state = self.write_state(resume_verify={"ses_a": {"at": self.now - 5, "verdict": "pending"}})

        with mock.patch.object(zen_guard, "_session_verdict") as verdict:
            zen_guard._verify_resume(state, self.now)

        verdict.assert_not_called()
        self.assertEqual(state["resume_verify"]["ses_a"]["verdict"], "pending")

    def test_dispatch_remembers_what_has_to_be_checked(self) -> None:
        state = self.write_state(pending={"ses_a": self.now})

        with mock.patch.object(auto_resume, "is_auto_resume_enabled", return_value=True), \
                mock.patch.object(auto_resume, "clear_opencode_free_limit", return_value=0), \
                mock.patch.object(auto_resume, "resume_active_session", return_value=(True, "sent")), \
                mock.patch.object(zen_guard, "_fallback_is_fresh", return_value=False), \
                mock.patch.object(zen_guard.time, "sleep"), \
                mock.patch.object(zen_guard.time, "time", return_value=float(self.now)):
            zen_guard._dispatch_auto_resume(state)

        self.assertEqual(state["resume_verify"]["ses_a"]["verdict"], "pending")

    def test_a_resume_sent_over_the_fallback_is_marked_unconfirmed(self) -> None:
        state = self.write_state(pending={"ses_a": self.now})

        with mock.patch.object(auto_resume, "is_auto_resume_enabled", return_value=True), \
                mock.patch.object(auto_resume, "clear_opencode_free_limit", return_value=0), \
                mock.patch.object(auto_resume, "resume_active_session", return_value=(True, "sent")), \
                mock.patch.object(zen_guard, "_fallback_is_fresh", return_value=True), \
                mock.patch.object(zen_guard.time, "sleep"), \
                mock.patch.object(zen_guard.time, "time", return_value=float(self.now)):
            zen_guard._dispatch_auto_resume(state)

        decisions = [item.get("decision") for item in self.audit()]
        self.assertIn("unlock-unconfirmed", decisions)


class WallDbCheckTests(SoftRetryBase):
    def test_a_chat_still_on_the_wall_keeps_the_wall(self) -> None:
        self.write_chat(newest_is_error=True)

        self.assertFalse(zen_guard._wall_already_over(["ses_a"]))
        self.assertEqual(zen_guard._sessions_still_walled(["ses_a"]), ["ses_a"])

    def test_a_chat_that_moved_on_cancels_the_wall(self) -> None:
        self.write_chat(newest_is_error=False)

        self.assertTrue(zen_guard._wall_already_over(["ses_a"]))
        self.assertEqual(zen_guard._sessions_still_walled(["ses_a"]), [])

    def test_an_unreadable_database_leaves_the_wall_alone(self) -> None:
        self.assertFalse(zen_guard._wall_already_over(["ses_a"]))
        self.assertFalse(zen_guard._wall_already_over([]))

    def test_old_soft_entries_are_pruned(self) -> None:
        state = self.write_state(
            soft_retry={"ses_old": time.time() - 4000, "ses_new": time.time()},
            soft_pending={"ses_old": time.time() - 4000},
            resume_verify={
                "ses_old": {"at": time.time() - 4000, "verdict": "pending"},
                "ses_new": {"at": time.time(), "verdict": "pending"},
            },
        )

        zen_guard._prune(state)

        self.assertEqual(list(state["soft_retry"]), ["ses_new"])
        self.assertEqual(state["soft_pending"], {})
        self.assertEqual(list(state["resume_verify"]), ["ses_new"])


class DashboardActionTests(SoftRetryBase):
    def _api(self) -> avatar_ui.AvatarControlApi:
        return object.__new__(avatar_ui.AvatarControlApi)

    def test_retry_chat_clears_the_lock_and_sends_one_continue(self) -> None:
        self.write_state(soft_retry={"ses_a": 1}, client_lock_until=self.now + 600)

        with mock.patch.object(auto_resume, "clear_opencode_free_limit", return_value=3), \
                mock.patch.object(auto_resume, "send_continue_keystroke", return_value=True):
            result = self._api().fix_issue("retry-chat")

        self.assertTrue(result["ok"])
        self.assertIn("No IP was spent", result["message"])
        saved = self.read_state()
        self.assertEqual(saved["soft_retry"], {})
        self.assertEqual(saved["client_lock_until"], 0)

    def test_retry_chat_says_when_no_window_took_the_keystroke(self) -> None:
        with mock.patch.object(auto_resume, "clear_opencode_free_limit", return_value=0), \
                mock.patch.object(auto_resume, "send_continue_keystroke", return_value=False):
            result = self._api().fix_issue("retry-chat")

        self.assertFalse(result["ok"])
        self.assertIn("no opencode window", result["message"].lower())

    def test_reload_chat_types_nothing(self) -> None:
        with mock.patch.object(auto_resume, "reload_opencode_window", return_value=True):
            result = self._api().fix_issue("reload-chat")

        self.assertTrue(result["ok"])
        self.assertIn("reloaded", result["message"])

    def test_the_health_panel_offers_both_cheap_actions(self) -> None:
        api = self._api()
        health = api._build_health(
            warp_installed=True,
            warp_connected=True,
            rotating=False,
            egress={"mode": "warp"},
            keeper_running=True,
            guard_running=True,
            proxy_listening=True,
            svc_wired=True,
            installed=True,
            probe={"code": "ok"},
            client_lock_until=self.now + 3600,
            retry_level=0,
        )

        issue = next(
            item for item in health["issues"] if "wait until" in item["title"]
        )
        fixes = [action["fix"] for action in issue["actions"]]
        self.assertEqual(fixes, ["retry-chat", "reload-chat"])

    def test_the_health_panel_names_the_account_wall_at_the_cap(self) -> None:
        api = self._api()
        health = api._build_health(
            warp_installed=True,
            warp_connected=True,
            rotating=False,
            egress={"mode": "warp"},
            keeper_running=True,
            guard_running=True,
            proxy_listening=True,
            svc_wired=True,
            installed=True,
            probe={"code": "ok"},
            last_verdict="still walled",
            retry_level=zen_guard.RETRY_STEPS.index(zen_guard.RETRY_STEPS[-1]),
        )

        titles = [item["title"] for item in health["issues"]]
        self.assertTrue(any("following your account" in title for title in titles))

    def test_deep_reset_style_state_clear_forgets_the_hint(self) -> None:
        self.write_state(
            client_lock_until=self.now + 600,
            soft_pending={"ses_a": self.now},
            soft_retry={"ses_a": 1},
            resume_verify={"ses_a": {"at": self.now, "verdict": "still walled"}},
            last_verdict="still walled",
        )

        self._api()._clear_soft_state()

        saved = self.read_state()
        self.assertEqual(saved["client_lock_until"], 0)
        self.assertEqual(saved["soft_pending"], {})
        self.assertEqual(saved["soft_retry"], {})
        self.assertEqual(saved["resume_verify"], {})
        self.assertEqual(saved["last_verdict"], "")


if __name__ == "__main__":
    unittest.main()
