"""Watches OpenCode's log for quota walls and rotates the active egress."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

# Ensure local script and bundled directories are resolvable
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
_SCRIPTS = Path(os.environ.get("LOCALAPPDATA", "")) / "opencode-unlimited" / "scripts"
if _SCRIPTS.is_dir() and str(_SCRIPTS) not in sys.path:
    # Appended, not prepended: the deployed copy must never shadow a module
    # sitting next to this file, which is what the repo and tests import.
    sys.path.append(str(_SCRIPTS))

from ouc_common import (
    GUARD_AUDIT_FILE as GUARD_DIR_AUDIT,
    GUARD_LOG_FILE,
    GUARD_STATE_FILE,
    LANE_DIR,
    OPENCODE_LOG_FILE,
    acquire_mutex,
    append_log,
    ensure_dirs,
    find_warp_cli,
    get_egress_v6,
    get_warp_local_v6,
    hop_report,
    keeper_pause_ctx,
    normalize_v6_64,
)
import account_pool

# Markers that name the free allowance itself: these are a wall on their own.
PRIMARY_WALL_MARKERS = (
    "freeusagelimiterror",
    "free usage limit error",
    "free usage limit",
    "free usage exceeded",
    "free-tier usage limit",
)
# Generic markers: only a wall when the line also looks like an error record,
# because a healthy log mentions "rate limit" in config and error text.
SECONDARY_WALL_MARKERS = (
    "quotaexceeded",
    "quota exceeded",
    "quota_exceeded",
    "usage limit reached",
    "exceeded your current quota",
    "credits exhausted",
    "rate limit exceeded",
    "rate_limit_exceeded",
    "rate limited",
    "ratelimited",
    "resource_exhausted",
    "429 too many requests",
    "status=429",
    "status: 429",
    "status 429",
    "code=429",
)
ERROR_RECORD_MARKERS = ("level=error", "level: error", '"level":"error"', "ai_apicallerror", "sessionid=ses_")
_LOG_TIMESTAMP_RE = re.compile(r"timestamp=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

POLL_SECONDS = 10
COOLDOWN_SECONDS = 75
MAX_HOP_TRIES = 4
BLACKLIST_MAX = 200
MAX_READ_BYTES = 4_000_000
# Loop protection: if the limit comes back this soon after a new IP, that IP
# didn't help. The pause is short because WARP's /64 blocks are shared and the
# next one is often fine.
REWALL_SECONDS = 180
# How close a fallback has to sit to the hop and the wall before the wall is
# treated as having measured the old route instead of the new address.
FALLBACK_WINDOW = 5
FAILED_HOPS_MAX = 2
BACKOFF_SECONDS = 2 * 60
# A hop that could not be confirmed is not worth retrying every cooldown:
# each attempt reconnects WARP and cuts live streams.
ROTATION_RETRY_SECONDS = 10 * 60
# Confirmed new IPv6 addresses that still hit the free wall mean the allowance
# is probably not following the IP. That is worth a longer wait, never a stop
# for the rest of the day: the wait escalates and is capped below.
FREE_WALL_HOPS_MAX = 2
# Retry ladder after a wall the last rotation did not fix. The first step is the
# normal cooldown; each repeat doubles the wait up to the cap, and a hop that
# survives REWALL_SECONDS resets the ladder.
RETRY_STEPS = (COOLDOWN_SECONDS, 2 * 60, 5 * 60, 10 * 60)
# Set OUC_FREE_WALL_LATCH=1 to restore the old "stop until 00:00 UTC" behaviour.
FREE_WALL_LATCH = os.environ.get("OUC_FREE_WALL_LATCH", "").strip() == "1"
# A wall this soon after the guard's own 'continue' measures that prompt, not
# the address, so it must not count as proof that the new /64 is spent.
SELF_INFLICTED_SECONDS = 120
# Every wall, gate decision, hop and unlock leaves one line here so "it did
# nothing" can always be explained afterwards.
AUDIT_FILE = GUARD_DIR_AUDIT
AUDIT_ROLL_BYTES = 1_000_000
# A log line older than this is history. Without the check, a guard restart or
# a log truncation replays old walls as if they had just happened.
WALL_LINE_MAX_AGE = 120
# The log reader is the fast path; the database is asked less often so a wall
# whose log line never matched still triggers a rotation.
DB_WALL_SCAN_SECONDS = 60
HEARTBEAT_FILE = GUARD_LOG_FILE.parent / "heartbeat.txt"
PENDING_MAX_AGE = 30 * 60
# The guard learns about walls from the log, so a session that hit the limit
# while it was stopped has nothing to trigger a resume when the allowance comes
# back. Those are found in OpenCode's database on start. Only recent walls are
# worth reopening, and a rescue that failed is not repeated every poll.
STUCK_LOOKBACK = 12 * 3600
STUCK_RETRY_SECONDS = 15 * 60
OPENCODE_DB_FILE = Path.home() / ".local" / "share" / "opencode" / "opencode.db"
# Reconnecting WARP tears the tunnel adapter down, which resets every live
# socket. A rotation therefore waits for a quiet window: no bytes relayed and
# no OpenCode log writes for this long means no request is mid-stream. The wait
# is capped so a busy session cannot block rotation forever.
QUIET_SECONDS = 45
QUIET_MAX_WAIT = 180
# A proxy from before byte tracking publishes only its live tunnel count, and
# only when a tunnel opens or closes. That snapshot stays trusted for longer
# than the rotation wait it feeds, and a restarted proxy republishes zero.
TUNNEL_STATUS_MAX_AGE = QUIET_MAX_WAIT + 60


def _heartbeat() -> None:
    """Cheap liveness signal the app checks; a running but hung guard stops writing this."""
    try:
        HEARTBEAT_FILE.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        pass


def _default_state(offset: int = 0) -> dict:
    return {
        "blacklist": [],
        "offset": offset,
        "last_hop": 0,
        "hops": 0,
        "current": "",
        "wall_pending": False,
        "wall_seen": 0,
        "last_ok_hop": 0,
        "last_wait_log": 0,
        "pending": {},
        "resumed": {},
        "failed_hops": 0,
        "backoff_until": 0,
        "hop_counted": 0,
        "backoff_logged": 0,
        "last_free_wall": 0,
        "free_wall_hops": 0,
        "free_wall_counted": 0,
        "free_wall_until": 0,
        "accounts_burned": {},
        "account_switches": 0,
        "account_switch_day": 0,
        "retry_level": 0,
        "retry_marked_hop": 0,
        "ladder_marked_hop": 0,
        "switch_pending": {},
        "db_scan_at": 0,
        "last_decision": "",
        "last_decision_at": 0,
    }


def _load_state() -> dict:
    if not GUARD_STATE_FILE.is_file():
        offset = OPENCODE_LOG_FILE.stat().st_size if OPENCODE_LOG_FILE.is_file() else 0
        state = _default_state(offset)
        _save_state(state)
        return state
    try:
        data = json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {**_default_state(), **data}
    except Exception:
        pass
    # A truncated or hand-edited state file must not replay the whole log: the
    # walls it holds were already handled before the write was lost.
    offset = OPENCODE_LOG_FILE.stat().st_size if OPENCODE_LOG_FILE.is_file() else 0
    return _default_state(offset)


def _save_state(state: dict) -> None:
    try:
        tmp = GUARD_STATE_FILE.with_name(GUARD_STATE_FILE.name + ".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, GUARD_STATE_FILE)
    except Exception:
        pass


def _audit(state: dict, event: str, **fields) -> dict:
    """Append one machine-readable line so any silent poll can be explained later."""
    record: dict = {"ts": int(time.time()), "event": event, "mode": _egress_mode()}
    for key, value in fields.items():
        if value is not None:
            record[key] = value
    try:
        path = AUDIT_FILE
        try:
            if path.stat().st_size > AUDIT_ROLL_BYTES:
                path.replace(path.with_name(path.name + ".1"))
        except OSError:
            pass
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception:
        pass
    decision = str(fields.get("decision") or "")
    if decision:
        reason = str(fields.get("reason") or "")
        state["last_decision"] = f"{decision} - {reason}" if reason else decision
        state["last_decision_at"] = record["ts"]
    return record


def _decision_text(decision: str, reason: str = "") -> str:
    return f"{decision} - {reason}" if reason else decision


def _resumable(state: dict, now: float | None = None) -> list[str]:
    """Chats that hit the limit and have no recent 'continue' against them.

    A chat that was already continued waits out ``STUCK_RETRY_SECONDS`` before
    another one: sending 'continue' again straight away only adds another failed
    turn to a chat that is standing on the same wall.
    """
    now = time.time() if now is None else now
    resumed = state.get("resumed") or {}
    waiting: list[str] = []
    for sid in state.get("pending") or {}:
        last = float(resumed.get(sid, 0) or 0)
        # A chat that was already continued waits out the retry window before
        # another 'continue'; sending one every poll only adds a failed turn to
        # a chat that is standing on the same wall.
        if last and now - last < STUCK_RETRY_SECONDS:
            continue
        waiting.append(sid)
    return waiting


def _prune(state: dict) -> None:
    cutoff = time.time() - PENDING_MAX_AGE
    for key in ("pending", "resumed"):
        state[key] = {k: v for k, v in (state.get(key) or {}).items() if float(v or 0) >= cutoff}


def _dispatch_auto_resume(state: dict) -> None:
    """After a new IP: send 'continue' to every chat that hit the limit, not just the latest one."""
    try:
        from auto_resume import resume_active_session, is_auto_resume_enabled, clear_opencode_free_limit

        # Always clear client-side free-limit locks immediately upon rotation
        clear_opencode_free_limit()

        sids = _resumable(state)
        ok = False
        if is_auto_resume_enabled():
            time.sleep(1.5)
            ok, res_msg = resume_active_session(sids or None)
            outcome = "sent" if ok else "not sent"
            append_log(GUARD_LOG_FILE, f"[auto-resume] {outcome} -> {res_msg}")
        else:
            append_log(
                GUARD_LOG_FILE,
                "[auto-resume] resume is turned off in the dashboard - no 'continue' was sent",
            )
        now = time.time()
        for sid in sids:
            # Remember the attempt even when nothing was sent, so a missing
            # window is retried after the retry window instead of every poll;
            # the chat stays pending until a 'continue' actually goes out.
            state.setdefault("resumed", {})[sid] = now
            if ok:
                (state.get("pending") or {}).pop(sid, None)
        _prune(state)
        _save_state(state)
    except Exception as exc:
        append_log(GUARD_LOG_FILE, f"[auto-resume] note: {exc}")


def _sessions_stuck_on_wall(now: float | None = None) -> list[str]:
    """Chats whose newest message is the free-limit error itself.

    OpenCode stores a failed request as a message with ``finish`` set to
    ``error``, so that field is what separates a real wall from a chat that
    merely mentions one. Only the session's newest message counts: if the user
    typed again afterwards, the chat is not stuck, it is waiting for an answer.
    """
    now = time.time() if now is None else now
    if not OPENCODE_DB_FILE.is_file():
        return []
    cutoff_ms = int((now - STUCK_LOOKBACK) * 1000)
    stuck: list[str] = []
    try:
        import sqlite3

        con = sqlite3.connect(f"file:{OPENCODE_DB_FILE.as_posix()}?mode=ro", uri=True, timeout=3.0)
    except Exception:
        return []
    try:
        rows = con.execute(
            "SELECT DISTINCT m.session_id FROM session_message AS m "
            "JOIN session_v2 AS s ON s.id = m.session_id "
            "WHERE s.time_archived IS NULL AND m.time_created >= ? "
            "AND json_extract(m.data, '$.finish') = 'error' "
            "AND m.data LIKE '%FreeUsageLimitError%'",
            (cutoff_ms,),
        ).fetchall()
        for (session_id,) in rows:
            newest = con.execute(
                "SELECT json_extract(data, '$.finish'), data FROM session_message "
                "WHERE session_id = ? ORDER BY time_created DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            if (
                newest
                and newest[0] == "error"
                and "FreeUsageLimitError" in str(newest[1] or "")
            ):
                stuck.append(str(session_id))
    except Exception:
        return []
    finally:
        try:
            con.close()
        except Exception:
            pass
    return stuck


def _rescue_stuck_sessions(state: dict, now: int | None = None) -> int:
    """Queue chats left on the wall before this start and resume them.

    A reboot, an update or a manual stop all leave the guard blind to a wall
    that already happened, and the user would sit in front of a chat that never
    continues. Returns how many were queued.
    """
    now = int(time.time()) if now is None else now
    pending = state.setdefault("pending", {})
    resumed = state.get("resumed") or {}
    queued = 0
    for sid in _sessions_stuck_on_wall(now):
        handled = max(float(resumed.get(sid, 0) or 0), float(pending.get(sid, 0) or 0))
        if handled and now - handled < STUCK_RETRY_SECONDS:
            continue
        pending[sid] = now
        queued += 1
    if not queued:
        return 0
    state["wall_pending"] = True
    _save_state(state)
    append_log(
        GUARD_LOG_FILE,
        f"{queued} chat(s) were left on the free limit before this start - resuming them",
    )
    _audit(state, "wall", source="db", sessions=queued, decision="resume-only",
           reason="chats left on the wall before this start")
    _dispatch_auto_resume(state)
    return queued


def _switch_account(state: dict, now: int) -> bool:
    """Answer a wall by asking as another signed-in account.

    A credential carries its own daily allowance, so this handles the wall that
    a tunnel reconnect cannot: the one that follows the wallet rather than the
    address the wallet is asked from.
    """
    accounts = account_pool.accounts()
    if len(accounts) < 2:
        return False
    today = _utc_day()
    raw_burned = state.get("accounts_burned")
    burned: dict[str, int] = {}
    if isinstance(raw_burned, dict):
        # A hand-edited or half-written state must not stop the guard loop.
        for key, value in raw_burned.items():
            try:
                stamp = int(value or 0)
            except (TypeError, ValueError):
                continue
            if stamp >= today:
                burned[str(key)] = stamp
    state["accounts_burned"] = burned
    active = next((item for item in accounts if item.get("active")), None)
    fresh = [
        item
        for item in accounts
        if not item.get("active") and burned.get(str(item["id"]), 0) < today
    ]
    if not fresh:
        if active:
            append_log(
                GUARD_LOG_FILE,
                "every signed-in account has hit the free limit today - waiting for 00:00 UTC",
            )
        return False
    target = fresh[0]
    if not account_pool.switch(str(target["id"])):
        append_log(
            GUARD_LOG_FILE,
            f"account switch to '{target['label']}' failed - staying on the current one",
        )
        _audit(state, "decision", decision="switch-failed", reason="the switch command failed")
        return False
    # Only a switch the client really took is worth anything.
    try:
        current = next((item for item in account_pool.accounts() if item.get("active")), None)
    except Exception:
        current = None
    if not current or str(current.get("id")) != str(target["id"]):
        append_log(
            GUARD_LOG_FILE,
            f"account switch to '{target['label']}' did not take effect - staying on the current one",
        )
        _audit(
            state,
            "decision",
            decision="switch-failed",
            reason="the account pool still reports another account as active",
        )
        return False
    if active:
        # Debts are settled by evidence: the previous account is only marked
        # spent when a wall follows inside the switch window.
        state["switch_pending"] = {"account": str(active["id"]), "at": now}
    for key in (
        "backoff_until",
        "free_wall_until",
        "free_wall_hops",
        "free_wall_counted",
        "failed_hops",
        "defer_since",
        "retry_level",
    ):
        state[key] = 0
    state["last_ok_hop"] = now
    state["hop_counted"] = now
    try:
        switch_day = int(state.get("account_switch_day", 0) or 0)
        switches = int(state.get("account_switches", 0) or 0)
    except (TypeError, ValueError):
        switch_day, switches = 0, 0
    if switch_day != today:
        state["account_switch_day"] = today
        switches = 0
    state["account_switches"] = switches + 1
    _save_state(state)
    append_log(
        GUARD_LOG_FILE,
        f"free limit answered with a fresh account: '{target['label']}' "
        f"(switch {state['account_switches']} today) - no tunnel reconnect needed",
    )
    _audit(
        state,
        "decision",
        decision="switch-account",
        reason=f"'{target['label']}' is now the active account",
        cleared_rows=None,
    )
    _dispatch_auto_resume(state)
    return True


def _next_utc_midnight(now: int) -> int:
    """Return the next 00:00 UTC, when the gateway's free allowance resets."""
    stamp = datetime.fromtimestamp(now, timezone.utc)
    reset = (stamp + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(reset.timestamp())


def _pause_left(state: dict, now: int) -> int:
    """Seconds of an active auto-rotation pause, clearing one that has expired.

    Every rotation reconnects WARP and resets live sockets, so a pause has to be
    a single gate in front of the whole loop rather than a check inside one
    branch. An expired pause is cleared here once.
    """
    until = int(state.get("backoff_until", 0) or 0)
    if not until:
        return 0
    if now >= until:
        was_free_wall = bool(int(state.get("free_wall_until", 0) or 0))
        # pending is pruned after 30 minutes, so a long pause can expire with
        # nothing left to resume. Ask the database instead of trusting it.
        for sid in _sessions_stuck_on_wall(now):
            state.setdefault("pending", {}).setdefault(sid, now)
        waiting = _resumable(state, float(now))
        state["backoff_until"] = 0
        state["failed_hops"] = 0
        state["free_wall_hops"] = 0
        state["free_wall_until"] = 0
        state["defer_since"] = 0
        _save_state(state)
        if was_free_wall and waiting:
            # The pause was the allowance window. Reopening it is the moment the
            # chat can work again, so the "continue" is sent here instead of
            # waiting for the user to type something first.
            append_log(
                GUARD_LOG_FILE,
                f"allowance window reopened - resuming {len(waiting)} waiting chat(s)",
            )
            _dispatch_auto_resume(state)
        else:
            append_log(GUARD_LOG_FILE, "rotation pause is over - trying again on the next limit")
        _audit(state, "decision", decision="pause-over", reason=f"resumed {len(waiting)} chat(s)")
        return 0
    return until - now


def _proxy_status() -> dict:
    """The local proxy's published status, or an empty dict when unreadable."""
    try:
        data = json.loads((LANE_DIR / "proxy_status.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _proxy_has_tunnels(data: dict, now: float) -> bool:
    """True while the local proxy reports an open upstream tunnel."""
    try:
        count = int(data.get("active_tunnels", 0) or 0)
        stamp = float(data.get("active_tunnels_ts", 0) or 0)
    except (TypeError, ValueError):
        return False
    return count > 0 and now - stamp <= TUNNEL_STATUS_MAX_AGE


def _proxy_moved_bytes(data: dict, now: float) -> bool:
    """True while the proxy relayed bytes within the quiet window.

    An open tunnel is not proof of work: OpenCode keeps idle keep-alive
    sockets, and one of those used to hold every rotation back for the whole
    cap. The proxy stamps the last byte it relayed, so a tunnel only counts as
    live while data is actually moving.
    """
    try:
        stamp = float(data.get("last_byte_ts", 0) or 0)
    except (TypeError, ValueError):
        return False
    return stamp > 0 and now - stamp < QUIET_SECONDS


def _work_is_live(now: float | None = None) -> bool:
    """True while a response may be streaming.

    A long stream writes its log line when it starts and when it finishes, so
    the log's mtime says nothing about the middle of one. The proxy's last byte
    stamp is the direct signal; the recent log write also covers the moment
    before the proxy accepts the CONNECT. A proxy from before byte tracking
    publishes no stamp, and its tunnel count is all that can be trusted there.
    """
    now = time.time() if now is None else now
    status = _proxy_status()
    if "last_byte_ts" in status:
        if _proxy_moved_bytes(status, now):
            return True
    elif _proxy_has_tunnels(status, now):
        return True
    try:
        age = now - OPENCODE_LOG_FILE.stat().st_mtime
    except OSError:
        return False
    return age < QUIET_SECONDS


def _egress_mode() -> str:
    """Active egress mode, defaulting to WARP when the config cannot be read."""
    try:
        from proxy_chain import get_egress_config

        return str(get_egress_config().get("mode", "warp"))
    except Exception:
        return "warp"


def _retry_wait(state: dict) -> int:
    """The current rung of the retry ladder: 75s, then 2, 5, 10 minutes."""
    try:
        level = int(state.get("retry_level", 0) or 0)
    except (TypeError, ValueError):
        level = 0
    level = max(0, min(level, len(RETRY_STEPS) - 1))
    return RETRY_STEPS[level]


def _wall_is_self_inflicted(state: dict, sessions: list[str] | None, now: int) -> bool:
    """True when the guard sent the 'continue' that produced this wall.

    A wall that lands moments after the guard's own prompt measures that prompt,
    not the new address: counting it as a spent block used to stop rotation for
    the rest of the day.
    """
    if not sessions:
        return False
    resumed = state.get("resumed") or {}
    for sid in sessions:
        try:
            stamp = float(resumed.get(sid, 0) or 0)
        except (TypeError, ValueError):
            return False
        if not stamp or not (0 <= now - stamp <= SELF_INFLICTED_SECONDS):
            return False
    return True


def _rotation_wait(state: dict) -> int:
    """Seconds to wait after the last hop before reconnecting WARP again.

    A hop that could not be confirmed, or a wall that came back right after a
    confirmed new address, is not worth retrying on the normal cooldown: every
    attempt reconnects WARP and drops live sockets, and that churn is what makes
    the tunnel look unstable. A Tor circuit or a proxy node costs nothing to
    swap, so those keep the short cooldown.
    """
    if _egress_mode() in ("tor", "custom"):
        return COOLDOWN_SECONDS
    if int(state.get("failed_hops", 0) or 0) > 0:
        return max(COOLDOWN_SECONDS, ROTATION_RETRY_SECONDS)
    return _retry_wait(state)


def _rotation_blocked(state: dict, now: int, live: bool) -> str:
    """Reason to hold a rotation back, or '' when reconnecting WARP is safe."""
    if _pause_left(state, now) > 0:
        return "paused"
    if live:
        started = int(state.get("defer_since", 0) or 0)
        if not started:
            state["defer_since"] = now
            _save_state(state)
            return "busy"
        if now - started < QUIET_MAX_WAIT:
            return "busy"
    if state.get("defer_since"):
        state["defer_since"] = 0
        _save_state(state)
    return ""


def _rode_the_fallback(last_hop: int, wall_at: int) -> bool:
    """True when a request left through the normal network around this wall.

    A request that fell back never used the new address, so the wall says
    nothing about that address and must not be counted as proof that the
    allowance ignores the IP.
    """
    try:
        stamp = (LANE_DIR / "fallback.flag").stat().st_mtime
    except OSError:
        return False
    return last_hop - FALLBACK_WINDOW <= stamp <= wall_at + FALLBACK_WINDOW


def _resolve_pending_burn(state: dict, now: int) -> None:
    """Decide whether the account we switched away from was really spent.

    A credential is only marked burnt when the wall lands inside the same short
    window as the switch. Otherwise that account was fine and stays usable.
    """
    pending = state.get("switch_pending")
    if not isinstance(pending, dict) or not pending:
        return
    account = str(pending.get("account") or "")
    try:
        at = int(pending.get("at", 0) or 0)
    except (TypeError, ValueError):
        at = 0
    state["switch_pending"] = {}
    if not account or not at:
        return
    if now - at <= SELF_INFLICTED_SECONDS:
        burned = state.setdefault("accounts_burned", {})
        if isinstance(burned, dict):
            burned[account] = _utc_day()
        append_log(
            GUARD_LOG_FILE,
            f"the limit followed the account switch {now - at}s later - "
            f"the previous account is spent for today",
        )
        _audit(
            state,
            "decision",
            decision="account-burned",
            reason=f"wall {now - at}s after the switch",
        )
    else:
        _audit(
            state,
            "decision",
            decision="account-ok",
            reason="the new account held past the switch window",
        )


def record_hop(
    state: dict,
    old_addr: str,
    new_addr: str,
    source: str = "guard",
    clear_pauses: bool = False,
) -> None:
    """Write one confirmed hop into the guard state.

    Every path that lands a new exit (guard, Try now, deep reset, zen-hop) goes
    through here so the state, the audit and the dashboard always agree.
    ``clear_pauses`` is for a manual rotation, which is an explicit "try again
    now"; the automatic path leaves the policy counters to ``_note_wall``.
    """
    now = int(time.time())
    state["current"] = new_addr or state.get("current", "")
    state["hops"] = int(state.get("hops", 0) or 0) + 1
    state["last_hop"] = now
    state["last_ok_hop"] = now
    state["hop_counted"] = 0
    state["failed_hops"] = 0
    state["defer_since"] = 0
    if clear_pauses:
        state["backoff_until"] = 0
        state["backoff_logged"] = 0
        state["free_wall_until"] = 0
        state["free_wall_hops"] = 0
        state["free_wall_counted"] = 0
        state["retry_level"] = 0
        state["retry_marked_hop"] = 0
        state["ladder_marked_hop"] = 0
        state["switch_pending"] = {}
    _audit(
        state,
        "hop",
        source=source,
        old_prefix=normalize_v6_64(old_addr),
        new_prefix=normalize_v6_64(new_addr),
        old_address=old_addr,
        new_address=new_addr,
    )
    _save_state(state)


def _note_wall(state: dict, now: int, sessions: list[str] | None = None) -> bool:
    """Track walls that return right after a new IP and size the next wait.

    Returns True while auto-rotation must not run now: either a pause is active,
    or the retry ladder has moved the next attempt further out.
    """
    _pause_left(state, now)
    _resolve_pending_burn(state, now)
    paused_until = int(state.get("backoff_until", 0) or 0)
    if now < paused_until:
        if now - int(state.get("backoff_logged", 0) or 0) >= 60:
            state["backoff_logged"] = now
            left = max(0, (paused_until - now) // 60)
            append_log(
                GUARD_LOG_FILE,
                f"limit seen again, but auto-rotation is paused for ~{left} more min "
                f"(new IPs kept hitting the limit immediately)",
            )
            _audit(
                state,
                "decision",
                decision=f"paused:{paused_until}",
                reason=f"{left} min left in the pause",
            )
            _save_state(state)
        return True

    last_hop = int(state.get("last_ok_hop", 0) or 0)
    if _wall_is_self_inflicted(state, sessions, now):
        # The guard asked this chat to continue moments ago. That wall measures
        # the prompt, not the new address, so it is not proof the block is
        # spent - but it should still slow the reconnect cadence down once per
        # hop, so a wall the guard keeps causing cannot churn the tunnel.
        if int(state.get("retry_marked_hop", 0) or 0) != last_hop:
            state["retry_marked_hop"] = last_hop
            state["retry_level"] = min(
                int(state.get("retry_level", 0) or 0) + 1, len(RETRY_STEPS) - 1
            )
        if now - int(state.get("own_wall_logged", 0) or 0) >= 60:
            state["own_wall_logged"] = now
            append_log(
                GUARD_LOG_FILE,
                "limit came back seconds after the guard's own 'continue' - "
                "not counted against the new address",
            )
            _audit(
                state,
                "decision",
                decision="wall-own",
                reason="limit followed the guard's own continue",
            )
        _save_state(state)
        return False

    if last_hop and now - last_hop <= REWALL_SECONDS:
        # A wall this soon after a confirmed hop means that address did not
        # help. It is not a failed rotation (the hop itself landed), so the
        # wait is sized by the free-wall ladder below, not by failed_hops.
        if int(state.get("hop_counted", 0) or 0) != last_hop:
            state["hop_counted"] = last_hop
            append_log(
                GUARD_LOG_FILE,
                f"limit came back {now - last_hop}s after the last IP change",
            )
    elif last_hop:
        # The previous IP lasted long enough: this isn't a rotation loop, and
        # the retry ladder starts from the shortest step again.
        state["failed_hops"] = 0
        state["retry_marked_hop"] = 0
        state["ladder_marked_hop"] = 0
        if int(state.get("retry_level", 0) or 0):
            state["retry_level"] = 0
            _audit(
                state,
                "decision",
                decision="retry-reset",
                reason="the last new address held past the rewall window",
            )

    free_wall = int(state.get("last_free_wall", 0) or 0)
    fresh_free = bool(last_hop) and bool(free_wall) and 0 <= free_wall - last_hop <= REWALL_SECONDS
    if fresh_free and _egress_mode() not in ("warp", "clean"):
        # The allowance follows a WARP /64 well enough to prove something about
        # it. A shared Tor exit or one proxy node proves nothing, so the latch
        # stays out of the way and lets the next rotation through.
        fresh_free = False
        state["free_wall_hops"] = 0
    if fresh_free and _rode_the_fallback(last_hop, free_wall):
        fresh_free = False
        if int(state.get("fallback_noted", 0) or 0) != last_hop:
            state["fallback_noted"] = last_hop
            append_log(
                GUARD_LOG_FILE,
                f"limit came back {free_wall - last_hop}s after the last IP change, but the "
                f"request had left through the fallback route - that wall says nothing about "
                f"the new address, so it is not counted",
            )
            _audit(
                state,
                "decision",
                decision="wall-fallback",
                reason="the request left through the fallback route",
            )
    if fresh_free:
        active_prefix = normalize_v6_64(str(state.get("current", "")))
        if active_prefix and active_prefix in (state.get("blacklist") or []):
            # The address that hit the wall is a block the guard already burnt,
            # so this wall says nothing about a genuinely new address.
            fresh_free = False
            state["free_wall_hops"] = 0
            append_log(
                GUARD_LOG_FILE,
                "the wall came from a /64 that is already blacklisted - "
                "not counted as a fresh address hitting the limit",
            )
            _audit(
                state,
                "decision",
                decision="wall-blacklisted",
                reason="the active /64 was already blacklisted",
            )
    if fresh_free:
        if int(state.get("free_wall_counted", 0) or 0) != last_hop:
            state["free_wall_counted"] = last_hop
            state["free_wall_hops"] = int(state.get("free_wall_hops", 0) or 0) + 1
            append_log(
                GUARD_LOG_FILE,
                f"free limit came back {free_wall - last_hop}s after a confirmed new IPv6 "
                f"address ({state['free_wall_hops']} of {FREE_WALL_HOPS_MAX})",
            )
    else:
        state["free_wall_hops"] = 0

    if (
        int(state.get("free_wall_hops", 0) or 0) >= FREE_WALL_HOPS_MAX
        and int(state.get("ladder_marked_hop", 0) or 0) != last_hop
    ):
        if FREE_WALL_LATCH:
            until = _next_utc_midnight(now)
            state["free_wall_until"] = until
            state["backoff_until"] = until
            state["backoff_logged"] = now
            state["hop_counted"] = last_hop
            reset_at = datetime.fromtimestamp(until, timezone.utc).strftime("%H:%M UTC")
            append_log(
                GUARD_LOG_FILE,
                f"free limit is not following the IP: {FREE_WALL_HOPS_MAX} confirmed new IPv6 "
                f"addresses hit it again. Pausing rotation until {reset_at} (OUC_FREE_WALL_LATCH).",
            )
            _audit(
                state,
                "decision",
                decision=f"paused:{until}",
                reason="free-wall latch enabled by OUC_FREE_WALL_LATCH",
            )
            _save_state(state)
            return True
        # Escalate instead of stopping for the day: the wait grows to a cap and
        # is tried again, so a block that was simply unlucky still gets a chance.
        level = min(int(state.get("retry_level", 0) or 0) + 1, len(RETRY_STEPS) - 1)
        state["retry_level"] = level
        state["ladder_marked_hop"] = last_hop
        wait = _retry_wait(state)
        append_log(
            GUARD_LOG_FILE,
            f"free limit is not following the IP: {FREE_WALL_HOPS_MAX} confirmed new IPv6 "
            f"addresses hit it again. Next attempt in {wait}s, capped at "
            f"{RETRY_STEPS[-1] // 60} min - Rotate /64 Now still works.",
        )
        _audit(
            state,
            "decision",
            decision=f"cooldown:{wait}",
            reason="free limit kept following confirmed new /64s",
        )
        _save_state(state)
        return False

    _save_state(state)
    return now < int(state.get("backoff_until", 0) or 0)


def _utc_day(stamp: float | None = None) -> int:
    """The day number the free allowance is counted in; Cloudflare resets at 00:00 UTC."""
    return int((time.time() if stamp is None else stamp) // 86_400)


def _prune_blacklist(state: dict) -> list[str]:
    """Drop burned /64s from earlier allowance days.

    A block that ran out yesterday is a fresh block today, so keeping it on the
    list would skip the cheapest addresses the next wall has available. Entries
    written before this field existed have no day yet and start counting now.
    """
    today = _utc_day()
    seen = state.setdefault("blacklist_day", {})
    if not isinstance(seen, dict):
        seen = {}
        state["blacklist_day"] = seen
    live: list[str] = []
    for entry in state.get("blacklist", []):
        prefix = normalize_v6_64(entry) if entry else ""
        if not prefix:
            continue
        day = seen.get(prefix)
        if day is None:
            seen[prefix] = today
            day = today
        if int(day) >= today:
            live.append(prefix)
        else:
            seen.pop(prefix, None)
    state["blacklist"] = live[-BLACKLIST_MAX:]
    return state["blacklist"]


def _blacklist_add(state: dict, addr: str) -> None:
    prefix = normalize_v6_64(addr)
    if not prefix:
        return
    bl = [x for x in _prune_blacklist(state) if x != prefix]
    bl.append(prefix)
    state["blacklist"] = bl[-BLACKLIST_MAX:]
    state.setdefault("blacklist_day", {})[prefix] = _utc_day()


def _is_burnt(state: dict, addr: str) -> bool:
    prefix = normalize_v6_64(addr)
    if not prefix:
        return False
    return prefix in _prune_blacklist(state)


def _line_is_fresh(line: str, now: int) -> bool:
    """True when a log line is news. A line without a timestamp keeps its old meaning."""
    match = _LOG_TIMESTAMP_RE.search(line or "")
    if not match:
        return True
    try:
        stamp = (
            datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
            .replace(tzinfo=timezone.utc)
            .timestamp()
        )
    except ValueError:
        return True
    return now - stamp <= WALL_LINE_MAX_AGE


def _classify_wall_line(line: str, now: int) -> str:
    """'wall', 'stale', or '' - is this line a limit, and is it current?

    The free-limit markers name the allowance itself and stand alone. The
    generic markers (429, "rate limited") also appear in config and in text
    about limits, so they only count inside an error record.
    """
    low = (line or "").lower()
    if not any(marker in low for marker in PRIMARY_WALL_MARKERS):
        if not any(marker in low for marker in SECONDARY_WALL_MARKERS):
            return ""
        if not any(marker in low for marker in ERROR_RECORD_MARKERS):
            return ""
    return "wall" if _line_is_fresh(line, now) else "stale"


def _read_new_log_bytes(state: dict, now: int | None = None) -> tuple[bool, list[str]]:
    """(wall seen since the last offset?, session IDs of the chats that hit it)."""
    now = int(time.time()) if now is None else now
    if not OPENCODE_LOG_FILE.is_file():
        return False, []
    try:
        size = OPENCODE_LOG_FILE.stat().st_size
    except OSError:
        return False, []

    offset = int(state.get("offset", 0) or 0)
    if size < offset:
        # The log was truncated or replaced. Everything before the new end has
        # already been handled, so only the new bytes are worth reading; the old
        # tail must not be replayed as a fresh wall.
        state["offset"] = size
        _audit(
            state,
            "log-truncated",
            source="log",
            offset=offset,
            size=size,
            decision="stale-wall",
            reason="log shrank - old tail skipped",
        )
        _save_state(state)
        return False, []

    start = max(offset, size - MAX_READ_BYTES)
    delta = size - start
    wall = False
    stale = 0
    free_wall_line = False
    sessions: list[str] = []
    sid_reader: Callable[[str], str] | None = None
    if delta > 0:
        try:
            with OPENCODE_LOG_FILE.open("rb") as fh:
                fh.seek(start)
                chunk = fh.read(delta).decode("utf-8", errors="replace")
            for line in chunk.splitlines():
                verdict = _classify_wall_line(line, now)
                if verdict == "stale":
                    stale += 1
                    continue
                if verdict != "wall":
                    continue
                wall = True
                if "free usage limit" in line.lower() or "freeusagelimiterror" in line.lower():
                    free_wall_line = True
                if sid_reader is None:
                    try:
                        from auto_resume import session_id_in

                        sid_reader = session_id_in
                    except Exception:
                        sid_reader = False  # type: ignore[assignment]
                if sid_reader:
                    sid = sid_reader(line)
                    if sid and sid not in sessions:
                        sessions.append(sid)
        except OSError:
            pass

    state["offset"] = size
    if wall:
        state["wall_pending"] = True
        state["wall_seen"] = now
        if free_wall_line:
            state["last_free_wall"] = now
        _audit(state, "wall", source="log", sessions=len(sessions), free=free_wall_line)
    elif stale:
        _audit(
            state,
            "wall",
            source="log",
            decision="stale-wall",
            reason=f"{stale} old limit line(s) ignored",
        )
    _save_state(state)
    return wall, sessions


def _rotate(state: dict, warp_bin: str | None) -> bool:
    now = int(time.time())

    # Detect active egress mode
    mode = "warp"
    try:
        from proxy_chain import get_egress_config
        mode = get_egress_config().get("mode", "warp")
    except Exception:
        pass

    # 1. Tor Network mode: rotate Tor circuit to get a new exit node IP
    if mode == "tor":
        append_log(GUARD_LOG_FILE, "wall detected in Tor mode - rotating circuit for fresh exit identity")
        try:
            from tor_manager import rotate_tor_circuit
            ok, msg = rotate_tor_circuit()
            if ok:
                record_hop(state, "", "", source="guard-tor")
            else:
                state["last_hop"] = now
                state["failed_hops"] = int(state.get("failed_hops", 0) or 0) + 1
                _save_state(state)
            append_log(GUARD_LOG_FILE, f"Tor rotated #{state['hops']}: {msg}")
            if ok:
                _dispatch_auto_resume(state)
            return ok
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"Tor rotation error: {exc}")
            _audit(state, "decision", decision="rotate-failed", reason=f"tor: {exc}")
            return False

    # 2. Custom Proxy mode: cycle proxy node in pool
    if mode == "custom":
        append_log(GUARD_LOG_FILE, "wall detected in Custom Proxy mode - cycling proxy node")
        try:
            from proxy_chain import rotate_custom_proxy
            ok, msg = rotate_custom_proxy()
            if ok:
                record_hop(state, "", "", source="guard-custom")
            else:
                state["last_hop"] = now
                state["failed_hops"] = int(state.get("failed_hops", 0) or 0) + 1
                _save_state(state)
            append_log(GUARD_LOG_FILE, f"Custom proxy rotated #{state['hops']}: {msg}")
            if ok:
                _dispatch_auto_resume(state)
            return ok
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"Custom proxy rotation error: {exc}")
            _audit(state, "decision", decision="rotate-failed", reason=f"proxy: {exc}")
            state["last_hop"] = now
            state["hops"] = int(state.get("hops", 0) or 0) + 1
            _save_state(state)
            return False

    # 3. WARP / Clean Endpoint mode: rotate IPv6 /64 subnet
    if not warp_bin:
        append_log(GUARD_LOG_FILE, "wall detected but warp-cli is not installed for WARP rotation")
        _audit(
            state,
            "decision",
            decision="rotate-failed",
            reason="warp-cli is not installed",
        )
        return False

    old_v6 = (
        get_egress_v6(timeout=8.0)
        or (get_warp_local_v6() or "")
        or str(state.get("current", ""))
    )
    old_prefix = normalize_v6_64(old_v6)
    append_log(GUARD_LOG_FILE, f"wall detected - rotating WARP /64 (was: {old_v6 or '?'})")
    _blacklist_add(state, old_v6)
    _save_state(state)

    new_v6 = ""
    with keeper_pause_ctx("zen-guard", seconds=600):
        avoid = {str(x) for x in state.get("blacklist", []) if x}
        for attempt in range(1, MAX_HOP_TRIES + 1):
            report = hop_report(
                warp_bin,
                avoid_prefixes=avoid,
                previous=old_v6,
            )
            cand = report["address"]
            if not cand:
                # Name the real outcome: a tunnel that stayed down is a different
                # problem from a provider handing back a block we already burnt.
                append_log(
                    GUARD_LOG_FILE,
                    f"try {attempt}: no new block ({report['status']}: {report['detail']})",
                )
                continue
            new_v6 = cand
            break

        if not new_v6:
            append_log(GUARD_LOG_FILE, "everything blacklisted - recycling oldest block")
            leftover = hop_report(
                warp_bin,
                avoid_prefixes=set(),
                previous=old_v6,
            )
            if leftover["address"]:
                new_v6 = leftover["address"]

    state["last_hop"] = now
    same_address = bool(old_prefix) and bool(new_v6) and normalize_v6_64(new_v6) == old_prefix
    if new_v6 and not same_address:
        # A landed hop never lifts a pause: _pause_left owns that, so a wall the
        # guard already proved follows the IP cannot be undone by a rotation that
        # slipped past the gate.
        record_hop(state, old_v6, new_v6, source="guard", clear_pauses=False)
        append_log(GUARD_LOG_FILE, f"rotated #{state['hops']}: {old_v6} -> {new_v6}")
        try:
            from ouc_common import LANE_DIR
            (LANE_DIR / "edge_reroll").write_text(str(time.time()), encoding="utf-8")
        except Exception:
            pass
        _dispatch_auto_resume(state)
        return True

    if same_address:
        # Don't send "continue" on the same limited IP: that is exactly the loop users saw.
        # last_ok_hop is deliberately left alone so the next wall is not treated as
        # a fresh IP (and so no resume is sent here).
        state["failed_hops"] = int(state.get("failed_hops", 0) or 0) + 1
        if state["failed_hops"] >= FAILED_HOPS_MAX:
            state["backoff_until"] = now + BACKOFF_SECONDS
            state["backoff_logged"] = now
            append_log(
                GUARD_LOG_FILE,
                f"pausing auto-rotation for {BACKOFF_SECONDS // 60} min: WARP kept "
                f"returning the same /64 ({new_v6}). It will try again by itself after that.",
            )
        else:
            append_log(
                GUARD_LOG_FILE,
                f"rotation ended on the same /64 ({new_v6}) - chat left paused instead of looping",
            )
        _audit(
            state,
            "decision",
            decision="rotate-failed",
            reason=f"WARP came back on the same /64 ({new_v6})",
        )
        _save_state(state)
        return False

    state["backoff_until"] = now + ROTATION_RETRY_SECONDS
    state["backoff_logged"] = now
    _save_state(state)
    append_log(
        GUARD_LOG_FILE,
        f"rotation failed - no confirmed new IPv6 egress. Pausing retries for "
        f"{ROTATION_RETRY_SECONDS // 60} min so the tunnel is not reconnected in a loop.",
    )
    _audit(
        state,
        "decision",
        decision="rotate-failed",
        reason=f"no confirmed new IPv6 egress ({new_v6 or 'no address'})",
    )
    return False


def _shorten_old_latch(state: dict, now: int) -> None:
    """Convert an all-day pause written by an older version into a bounded one.

    Without this an upgrade during the day would inherit a pause until 00:00
    UTC, which is exactly the behaviour this version removes.
    """
    if FREE_WALL_LATCH:
        return
    until = int(state.get("free_wall_until", 0) or 0)
    if until <= now:
        return
    capped = now + RETRY_STEPS[-1]
    state["free_wall_until"] = 0
    state["free_wall_hops"] = 0
    state["retry_level"] = len(RETRY_STEPS) - 1
    state["retry_marked_hop"] = 0
    state["ladder_marked_hop"] = 0
    state["backoff_until"] = min(until, capped)
    _save_state(state)
    append_log(
        GUARD_LOG_FILE,
        "an all-day pause left by an older version was shortened to "
        f"{RETRY_STEPS[-1] // 60} min - rotation keeps trying",
    )
    _audit(
        state,
        "decision",
        decision=f"paused:{state['backoff_until']}",
        reason="old all-day latch shortened after an upgrade",
    )


def main() -> int:
    ensure_dirs()
    mutex = acquire_mutex("OpencodeUnlimitedGuard")
    if mutex is None:
        return 0

    warp_bin = find_warp_cli()
    state = _load_state()
    _shorten_old_latch(state, int(time.time()))
    append_log(
        GUARD_LOG_FILE,
        f"guard up (poll {POLL_SECONDS}s, cooldown {COOLDOWN_SECONDS}s, warp={'found' if warp_bin else 'none'})",
    )
    _heartbeat()
    # A wall that happened while the guard was stopped is invisible to the log
    # reader, so anything still sitting on it is picked up here.
    if _pause_left(state, int(time.time())) <= 0:
        _rescue_stuck_sessions(state)

    while True:
        time.sleep(POLL_SECONDS)
        try:
            _heartbeat()
            state = _load_state()
            now = int(time.time())
            paused = _pause_left(state, now) > 0
            wall, sessions = _read_new_log_bytes(state, now)
            pending = state.setdefault("pending", {})
            if wall:
                for sid in sessions:
                    pending.setdefault(sid, now)
                _save_state(state)
                # IP rotation comes first. A different account is only worth
                # asking once a confirmed new /64 has already hit the wall;
                # otherwise the first limit of the day silently spends it.
                if int(state.get("free_wall_hops", 0) or 0) >= 1 and _switch_account(state, now):
                    continue
            elif now - int(state.get("db_scan_at", 0) or 0) >= DB_WALL_SCAN_SECONDS:
                # The log is the fast path; the database is the safety net for a
                # wall whose log line never matched the markers.
                state["db_scan_at"] = now
                resumed = state.get("resumed") or {}
                fresh_stuck = [
                    sid
                    for sid in _sessions_stuck_on_wall(now)
                    if sid not in pending
                    and now - float(resumed.get(sid, 0) or 0) >= STUCK_RETRY_SECONDS
                ]
                if fresh_stuck:
                    wall = True
                    state["wall_seen"] = now
                    state["wall_pending"] = True
                    for sid in fresh_stuck:
                        pending.setdefault(sid, now)
                    _audit(state, "wall", source="db", sessions=len(fresh_stuck))
                    _save_state(state)
            if paused:
                # Single gate in front of the IP work: while auto-rotation is
                # paused this process neither reconnects WARP nor sends "continue".
                continue
            if not wall and not state.get("wall_pending"):
                continue

            if wall:
                if _note_wall(state, now, sessions):
                    continue

            last_hop = int(state.get("last_hop", 0) or 0)
            last_ok = int(state.get("last_ok_hop", 0) or 0)
            seen = int(state.get("wall_seen", 0) or 0)
            if seen and seen <= last_ok:
                # The wall came from the session that was already rotated.
                for sid in list(state.get("pending") or {}):
                    state.setdefault("resumed", {})[sid] = last_ok
                    (state.get("pending") or {}).pop(sid, None)
                _prune(state)
                state["wall_pending"] = False
                _audit(
                    state,
                    "decision",
                    decision="stale-wall",
                    reason="this wall belongs to the session that was already rotated",
                )
                _save_state(state)
                continue

            # A hop that already failed, or a wall that came back right after a
            # confirmed new address, holds the next rotation longer than the
            # normal cooldown.
            hold = _rotation_wait(state)
            age = now - last_hop
            if age >= hold:
                blocked = _rotation_blocked(state, now, _work_is_live())
                if blocked:
                    # Reconnecting WARP resets every live socket, so a rotation
                    # never lands on top of a streaming response.
                    last_log = int(state.get("last_defer_log", 0) or 0)
                    if now - last_log >= 60:
                        state["last_defer_log"] = now
                        append_log(
                            GUARD_LOG_FILE,
                            "rotation held back - a request is still streaming; "
                            "the route is swapped once the session goes quiet",
                        )
                        _audit(
                            state,
                            "decision",
                            decision="defer:live",
                            reason="a request is still streaming",
                        )
                    state["wall_pending"] = True
                    _save_state(state)
                    continue
                state["wall_pending"] = False
                _save_state(state)
                if not _rotate(state, warp_bin):
                    state["wall_pending"] = True
                    _save_state(state)
            else:
                # Only continue other tabs when the last hop really produced a
                # new IP. A failed hop or one that stayed on the same /64 must
                # not send 'continue' on the old, limited address.
                fresh_ip = wall and last_ok >= last_hop
                resumable = _resumable(state) if fresh_ip else []
                if resumable:
                    # Other tabs that were cut off by the same wall arrived after
                    # the IP change; the new IP is fresh, so continue them too.
                    append_log(
                        GUARD_LOG_FILE,
                        f"{len(resumable)} more chat(s) hit the limit around the last IP change "
                        f"({age}s ago) - sending them 'continue'",
                    )
                    _audit(
                        state,
                        "decision",
                        decision="resume-only",
                        reason=f"{len(resumable)} chat(s) cut off by the same wall",
                    )
                    _dispatch_auto_resume(state)
                else:
                    last_log = int(state.get("last_wait_log", 0) or 0)
                    if now - last_log >= 60:
                        append_log(
                            GUARD_LOG_FILE,
                            f"wall queued - waiting out cooldown ({age}s < {hold}s)",
                        )
                        _audit(
                            state,
                            "decision",
                            decision=f"cooldown:{max(0, hold - age)}",
                            reason=f"waiting {hold}s after the last rotation",
                        )
                        state["last_wait_log"] = now
                        _save_state(state)
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"guard error: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
