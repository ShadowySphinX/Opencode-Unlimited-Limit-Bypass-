"""A wall can be answered with another signed-in account, not only a new IP."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import account_pool
import zen_guard


EXPORT = [
    {
        "id": "cred_a",
        "integrationID": "opencode",
        "label": "Personal",
        "active": True,
        "value": {"type": "oauth", "access": "SECRET-ACCESS", "refresh": "SECRET-REFRESH"},
    },
    {
        "id": "cred_b",
        "integrationID": "opencode",
        "label": "Work",
        "active": False,
        "value": {"type": "oauth", "access": "OTHER-SECRET", "refresh": "OTHER-REFRESH"},
    },
    {"id": "cred_c", "integrationID": "anthropic", "label": "Claude", "active": False},
]


class AccountListTests(unittest.TestCase):
    def test_the_cli_runs_through_the_cross_platform_helper(self) -> None:
        # The old path passed creationflags directly, which raises ValueError on
        # Linux and turned every wall into "guard error" instead of a switch.
        completed = mock.Mock(returncode=0, stdout="[]")

        with mock.patch.object(
            account_pool, "find_opencode_cli", return_value="/usr/bin/opencode"
        ), mock.patch.object(
            account_pool, "run_hidden", return_value=completed
        ) as run:
            result = account_pool._run(["export"], 5.0)

        self.assertIs(result, completed)
        run.assert_called_once_with(
            ["/usr/bin/opencode", "auth", "export"], timeout=5.0
        )

    def test_a_cmd_shim_is_run_through_cmd_exe(self) -> None:
        completed = mock.Mock(returncode=0, stdout="[]")
        shim = r"C:\Users\user\AppData\Roaming\npm\opencode.cmd"

        with mock.patch.object(
            account_pool, "find_opencode_cli", return_value=shim
        ), mock.patch.object(
            account_pool, "run_hidden", return_value=completed
        ) as run:
            account_pool._run(["switch", "opencode", "cred_b"], 5.0)

        command = run.call_args.args[0]
        # COMSPEC is an absolute path on Windows, so compare the name only.
        self.assertIn("cmd.exe", command[0].lower())
        self.assertEqual(command[1], "/c")
        self.assertEqual(command[2], shim)
        self.assertEqual(command[3:], ["auth", "switch", "opencode", "cred_b"])

    def test_a_missing_cli_is_not_an_error(self) -> None:
        with mock.patch.object(account_pool, "find_opencode_cli", return_value=None):
            self.assertIsNone(account_pool._run(["export"], 5.0))

    def test_a_spawn_failure_is_not_an_error(self) -> None:
        with mock.patch.object(
            account_pool, "find_opencode_cli", return_value="/usr/bin/opencode"
        ), mock.patch.object(
            account_pool, "run_hidden", side_effect=OSError("boom")
        ):
            self.assertIsNone(account_pool._run(["export"], 5.0))

    def test_only_gateway_accounts_are_listed(self) -> None:
        proc = mock.Mock(returncode=0, stdout=json.dumps(EXPORT))

        with mock.patch.object(account_pool, "_run", return_value=proc):
            listed = account_pool.accounts()

        self.assertEqual([item["id"] for item in listed], ["cred_a", "cred_b"])
        self.assertEqual(listed[0]["label"], "Personal")
        self.assertTrue(listed[0]["active"])
        self.assertFalse(listed[1]["active"])

    def test_no_secret_ever_leaves_the_cli(self) -> None:
        proc = mock.Mock(returncode=0, stdout=json.dumps(EXPORT))

        with mock.patch.object(account_pool, "_run", return_value=proc):
            listed = account_pool.accounts()

        rendered = json.dumps(listed)
        self.assertNotIn("SECRET", rendered)
        self.assertEqual(sorted(listed[0]), ["active", "id", "label"])

    def test_a_failed_export_lists_nothing(self) -> None:
        with mock.patch.object(account_pool, "_run", return_value=None):
            self.assertEqual(account_pool.accounts(), [])

        broken = mock.Mock(returncode=1, stdout="boom")
        with mock.patch.object(account_pool, "_run", return_value=broken):
            self.assertEqual(account_pool.accounts(), [])

    def test_switch_reports_the_cli_verdict(self) -> None:
        with mock.patch.object(account_pool, "_run", return_value=mock.Mock(returncode=0)):
            self.assertTrue(account_pool.switch("cred_b"))

        with mock.patch.object(account_pool, "_run", return_value=mock.Mock(returncode=1)):
            self.assertFalse(account_pool.switch("cred_b"))

        self.assertFalse(account_pool.switch(""))


class GuardAccountSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.state_file = base / "state.json"
        self.log_file = base / "guard.log"
        self._patches = [
            mock.patch.object(zen_guard, "GUARD_STATE_FILE", self.state_file),
            mock.patch.object(zen_guard, "GUARD_LOG_FILE", self.log_file),
        ]
        for patch in self._patches:
            patch.start()
        self.now = 1_800_000_000

    def tearDown(self) -> None:
        for patch in self._patches:
            patch.stop()
        self._tmp.cleanup()

    def state(self, **fields) -> dict:
        state = dict(zen_guard._default_state())
        state.update(fields)
        self.state_file.write_text(json.dumps(state), encoding="utf-8")
        return state

    def test_a_fresh_account_replaces_the_burned_one(self) -> None:
        state = self.state(
            backoff_until=self.now + 3600,
            free_wall_until=self.now + 3600,
            free_wall_hops=2,
            pending={"ses_a": self.now - 30},
        )
        accounts = [
            {"id": "cred_a", "label": "Personal", "active": True},
            {"id": "cred_b", "label": "Work", "active": False},
        ]

        with mock.patch.object(zen_guard.account_pool, "accounts", return_value=accounts), \
                mock.patch.object(zen_guard.account_pool, "switch", return_value=True) as switch, \
                mock.patch.object(zen_guard, "_dispatch_auto_resume") as resume, \
                mock.patch.object(zen_guard, "time") as fake_time:
            fake_time.time.return_value = float(self.now)
            switched = zen_guard._switch_account(state, self.now)
            expected_day = zen_guard._utc_day()

        self.assertTrue(switched)
        switch.assert_called_once_with("cred_b")
        resume.assert_called_once()
        saved = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(saved["accounts_burned"], {"cred_a": expected_day})
        self.assertEqual(saved["backoff_until"], 0)
        self.assertEqual(saved["free_wall_until"], 0)
        self.assertEqual(saved["last_ok_hop"], self.now)
        self.assertEqual(saved["account_switches"], 1)

    def test_every_account_burned_leaves_the_ip_path_alone(self) -> None:
        today = zen_guard._utc_day()
        state = self.state(accounts_burned={"cred_b": today})
        accounts = [
            {"id": "cred_a", "label": "Personal", "active": True},
            {"id": "cred_b", "label": "Work", "active": False},
        ]

        with mock.patch.object(zen_guard.account_pool, "accounts", return_value=accounts), \
                mock.patch.object(zen_guard.account_pool, "switch") as switch:
            self.assertFalse(zen_guard._switch_account(state, self.now))

        switch.assert_not_called()
        self.assertIn("every signed-in account", self.log_file.read_text(encoding="utf-8"))

    def test_yesterdays_burn_does_not_block_today(self) -> None:
        state = self.state(accounts_burned={"cred_b": zen_guard._utc_day() - 1})
        accounts = [
            {"id": "cred_a", "label": "Personal", "active": True},
            {"id": "cred_b", "label": "Work", "active": False},
        ]

        with mock.patch.object(zen_guard.account_pool, "accounts", return_value=accounts), \
                mock.patch.object(zen_guard.account_pool, "switch", return_value=True), \
                mock.patch.object(zen_guard, "_dispatch_auto_resume"):
            state["accounts_burned"] = {"cred_b": zen_guard._utc_day() - 1}
            self.assertTrue(zen_guard._switch_account(state, self.now))

    def test_corrupt_burn_state_does_not_stop_the_switch(self) -> None:
        state = self.state(accounts_burned={"cred_b": "yesterday-ish", "junk": None})
        accounts = [
            {"id": "cred_a", "label": "Personal", "active": True},
            {"id": "cred_b", "label": "Work", "active": False},
        ]

        with mock.patch.object(zen_guard.account_pool, "accounts", return_value=accounts), \
                mock.patch.object(zen_guard.account_pool, "switch", return_value=True) as switch, \
                mock.patch.object(zen_guard, "_dispatch_auto_resume"):
            self.assertTrue(zen_guard._switch_account(state, self.now))

        switch.assert_called_once_with("cred_b")

    def test_one_account_is_not_a_pool(self) -> None:
        state = self.state()

        with mock.patch.object(
            zen_guard.account_pool,
            "accounts",
            return_value=[{"id": "cred_a", "label": "Personal", "active": True}],
        ), mock.patch.object(zen_guard.account_pool, "switch") as switch:
            self.assertFalse(zen_guard._switch_account(state, self.now))

        switch.assert_not_called()

    def test_a_refused_switch_keeps_the_account_marked_fresh(self) -> None:
        state = self.state()
        accounts = [
            {"id": "cred_a", "label": "Personal", "active": True},
            {"id": "cred_b", "label": "Work", "active": False},
        ]

        with mock.patch.object(zen_guard.account_pool, "accounts", return_value=accounts), \
                mock.patch.object(zen_guard.account_pool, "switch", return_value=False), \
                mock.patch.object(zen_guard, "_dispatch_auto_resume") as resume:
            self.assertFalse(zen_guard._switch_account(state, self.now))

        resume.assert_not_called()
        self.assertEqual(state["accounts_burned"], {})


if __name__ == "__main__":
    unittest.main()
