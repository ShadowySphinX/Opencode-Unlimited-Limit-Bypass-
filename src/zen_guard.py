"""Watches OpenCode's log for quota walls and rotates the active egress."""

from __future__ import annotations

import json
import os
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
# is not following the IP. Stop rotating until it resets at 00:00 UTC.
FREE_WALL_HOPS_MAX = 2
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
        return False
    if active:
        burned[str(active["id"])] = today
    for key in ("backoff_until", "free_wall_until", "free_wall_hops", "failed_hops", "defer_since"):
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
        waiting = _resumable(state)
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
    return COOLDOWN_SECONDS


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


def _note_wall(state: dict, now: int) -> bool:
    """Track walls that return right after a new IP and pause rotation when it's clearly a loop.

    Returns True while auto-rotation is paused (the caller should not rotate or resume).
    """
    _pause_left(state, now)
    if now < int(state.get("backoff_until", 0) or 0):
        if now - int(state.get("backoff_logged", 0) or 0) >= 60:
            state["backoff_logged"] = now
            _save_state(state)
            left = max(0, (int(state["backoff_until"]) - now) // 60)
            append_log(
                GUARD_LOG_FILE,
                f"limit seen again, but auto-rotation is paused for ~{left} more min "
                f"(new IPs kept hitting the limit immediately)",
            )
        return True

    last_hop = int(state.get("last_ok_hop", 0) or 0)
    if last_hop and now - last_hop <= REWALL_SECONDS:
        if int(state.get("hop_counted", 0) or 0) != last_hop:
            state["hop_counted"] = last_hop
            state["failed_hops"] = int(state.get("failed_hops", 0) or 0) + 1
            append_log(
                GUARD_LOG_FILE,
                f"limit came back {now - last_hop}s after the last IP change "
                f"(failed attempt {state['failed_hops']} of {FAILED_HOPS_MAX})",
            )
    elif last_hop:
        # The previous IP lasted long enough: this isn't a rotation loop.
        state["failed_hops"] = 0

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

    if int(state.get("free_wall_hops", 0) or 0) >= FREE_WALL_HOPS_MAX:
        until = _next_utc_midnight(now)
        state["free_wall_until"] = until
        state["backoff_until"] = until
        state["backoff_logged"] = now
        state["hop_counted"] = last_hop
        reset_at = datetime.fromtimestamp(until, timezone.utc).strftime("%H:%M UTC")
        append_log(
            GUARD_LOG_FILE,
            f"free limit is not following the IP: {FREE_WALL_HOPS_MAX} confirmed new IPv6 "
            f"addresses hit it again. Pausing rotation until {reset_at}. Another provider, "
            f"OpenCode Go, or pressing Try now is the way forward.",
        )
        _save_state(state)
        return True

    if int(state.get("failed_hops", 0) or 0) >= FAILED_HOPS_MAX:
        state["backoff_until"] = now + BACKOFF_SECONDS
        state["backoff_logged"] = now
        append_log(
            GUARD_LOG_FILE,
            f"pausing auto-rotation for {BACKOFF_SECONDS // 60} min: the last "
            f"{FAILED_HOPS_MAX} new addresses hit the limit again immediately. "
            f"It will try one more address by itself after that, or press Rotate /64 Now.",
        )
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


def _read_new_log_bytes(state: dict) -> tuple[bool, list[str]]:
    """(wall seen since the last offset?, session IDs of the chats that hit it)."""
    if not OPENCODE_LOG_FILE.is_file():
        return False, []
    try:
        size = OPENCODE_LOG_FILE.stat().st_size
    except OSError:
        return False, []

    offset = int(state.get("offset", 0) or 0)
    if size < offset:
        offset = 0

    start = max(offset, size - MAX_READ_BYTES)
    delta = size - start
    wall = False
    sessions: list[str] = []
    if delta > 0:
        try:
            with OPENCODE_LOG_FILE.open("rb") as fh:
                fh.seek(start)
                chunk = fh.read(delta).decode("utf-8", errors="replace")
            chunk_lower = chunk.lower()
            wall_patterns = (
                "quotaexceeded",
                "quota exceeded",
                "quota_exceeded",
                "free usage limit",
                "freeusagelimiterror",
                "free usage exceeded",
                "free-tier usage limit",
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
            if any(p in chunk_lower for p in wall_patterns):
                wall = True
                sid_reader: Callable[[str], str] | None = None
                try:
                    from auto_resume import session_id_in

                    sid_reader = session_id_in
                except Exception:
                    pass
                if sid_reader is not None:
                    for line in chunk.splitlines():
                        low = line.lower()
                        if any(p in low for p in wall_patterns):
                            sid = sid_reader(line)
                            if sid and sid not in sessions:
                                sessions.append(sid)
        except OSError:
            pass

    state["offset"] = size
    if wall:
        state["wall_pending"] = True
        state["wall_seen"] = int(time.time())
        if "free usage limit" in chunk_lower or "freeusagelimiterror" in chunk_lower:
            state["last_free_wall"] = state["wall_seen"]
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
            state["last_hop"] = now
            state["hops"] = int(state.get("hops", 0) or 0) + 1
            if ok:
                state["last_ok_hop"] = now
            _save_state(state)
            append_log(GUARD_LOG_FILE, f"Tor rotated #{state['hops']}: {msg}")
            if ok:
                _dispatch_auto_resume(state)
            return ok
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"Tor rotation error: {exc}")
            return False

    # 2. Custom Proxy mode: cycle proxy node in pool
    if mode == "custom":
        append_log(GUARD_LOG_FILE, "wall detected in Custom Proxy mode - cycling proxy node")
        try:
            from proxy_chain import rotate_custom_proxy
            ok, msg = rotate_custom_proxy()
            state["last_hop"] = now
            state["hops"] = int(state.get("hops", 0) or 0) + 1
            if ok:
                state["last_ok_hop"] = now
            _save_state(state)
            append_log(GUARD_LOG_FILE, f"Custom proxy rotated #{state['hops']}: {msg}")
            if ok:
                _dispatch_auto_resume(state)
            return ok
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"Custom proxy rotation error: {exc}")
            state["last_hop"] = now
            state["hops"] = int(state.get("hops", 0) or 0) + 1
            _save_state(state)
            return False

    # 3. WARP / Clean Endpoint mode: rotate IPv6 /64 subnet
    if not warp_bin:
        append_log(GUARD_LOG_FILE, "wall detected but warp-cli is not installed for WARP rotation")
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
        state["current"] = new_v6
        state["hops"] = int(state.get("hops", 0) or 0) + 1
        state["last_ok_hop"] = now
        state["failed_hops"] = 0
        # A landed hop never lifts a pause: _pause_left owns that, so a wall the
        # guard already proved follows the IP cannot be undone by a rotation that
        # slipped past the gate.
        if not int(state.get("free_wall_until", 0) or 0):
            state["backoff_until"] = 0
            state["backoff_logged"] = 0
        state["hop_counted"] = 0
        _save_state(state)
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
    return False


def main() -> int:
    ensure_dirs()
    mutex = acquire_mutex("OpencodeUnlimitedGuard")
    if mutex is None:
        return 0

    warp_bin = find_warp_cli()
    state = _load_state()
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
            wall, sessions = _read_new_log_bytes(state)
            if wall:
                pending = state.setdefault("pending", {})
                for sid in sessions:
                    pending.setdefault(sid, now)
                _save_state(state)
                # A fresh account is the cheapest answer to a wall and the only
                # one a free-tier pause does not cover: the pause is about
                # reconnecting the tunnel, not about who is asking.
                if _switch_account(state, now):
                    continue
            if paused:
                # Single gate in front of the IP work: while auto-rotation is
                # paused this process neither reconnects WARP nor sends "continue".
                continue
            if not wall and not state.get("wall_pending"):
                continue

            if wall:
                if _note_wall(state, now):
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
                    _dispatch_auto_resume(state)
                else:
                    last_log = int(state.get("last_wait_log", 0) or 0)
                    if now - last_log >= 60:
                        append_log(
                            GUARD_LOG_FILE,
                            f"wall queued - waiting out cooldown ({age}s < {hold}s)",
                        )
                        state["last_wait_log"] = now
                        _save_state(state)
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"guard error: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
