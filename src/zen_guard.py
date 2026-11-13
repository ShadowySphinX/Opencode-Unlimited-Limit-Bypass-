"""Zen Guard for Windows: watches OpenCode's log for quota walls and rotates /64."""

from __future__ import annotations

import json
import time

from ouc_common import (
    GUARD_LOG_FILE,
    GUARD_STATE_FILE,
    OPENCODE_LOG_FILE,
    acquire_mutex,
    append_log,
    ensure_dirs,
    find_warp_cli,
    get_egress_v6,
    get_warp_local_v6,
    hop_once,
    keeper_pause_ctx,
    normalize_v6_64,
)

POLL_SECONDS = 10
COOLDOWN_SECONDS = 75
MAX_HOP_TRIES = 8
BLACKLIST_MAX = 200
MAX_READ_BYTES = 50_000_000


def _default_state(offset: int = 0) -> dict:
    return {
        "blacklist": [],
        "offset": offset,
        "last_hop": 0,
        "hops": 0,
        "current": "",
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
    return _default_state()


def _save_state(state: dict) -> None:
    try:
        GUARD_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
    except Exception:
        pass


def _blacklist_add(state: dict, addr: str) -> None:
    prefix = normalize_v6_64(addr)
    if not prefix:
        return
    bl = [x for x in state.get("blacklist", []) if x and normalize_v6_64(x) != prefix]
    bl.append(prefix)
    state["blacklist"] = bl[-BLACKLIST_MAX:]


def _is_burnt(state: dict, addr: str) -> bool:
    prefix = normalize_v6_64(addr)
    if not prefix:
        return False
    return any(x and normalize_v6_64(x) == prefix for x in state.get("blacklist", []))


def _read_new_log_bytes(state: dict) -> bool:
    """Return True if a QuotaExceeded wall error appeared since the last offset."""
    if not OPENCODE_LOG_FILE.is_file():
        return False
    try:
        size = OPENCODE_LOG_FILE.stat().st_size
    except OSError:
        return False

    offset = int(state.get("offset", 0) or 0)
    if size < offset:
        offset = 0

    delta = size - offset
    wall = False
    if 0 < delta < MAX_READ_BYTES:
        try:
            with OPENCODE_LOG_FILE.open("rb") as fh:
                fh.seek(offset)
                chunk = fh.read(delta).decode("utf-8", errors="replace")
            if "QuotaExceeded" in chunk or "Free usage limit reached" in chunk:
                wall = True
        except OSError:
            pass

    state["offset"] = size
    _save_state(state)
    return wall


def _rotate(state: dict, warp_bin: str | None) -> None:
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
        append_log(GUARD_LOG_FILE, "wall detected in Tor mode — rotating circuit for fresh exit identity")
        try:
            from tor_manager import rotate_tor_circuit
            ok, msg = rotate_tor_circuit()
            state["last_hop"] = now
            state["hops"] = int(state.get("hops", 0) or 0) + 1
            _save_state(state)
            append_log(GUARD_LOG_FILE, f"Tor rotated #{state['hops']}: {msg}")
            return
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"Tor rotation error: {exc}")
            return

    # 2. Custom Proxy mode: record quota event
    if mode == "custom":
        append_log(GUARD_LOG_FILE, "wall detected in Custom Proxy mode — node quota limit reached")
        state["last_hop"] = now
        state["hops"] = int(state.get("hops", 0) or 0) + 1
        _save_state(state)
        return

    # 3. WARP / Clean Endpoint mode: rotate IPv6 /64 subnet
    if not warp_bin:
        append_log(GUARD_LOG_FILE, "wall detected but warp-cli is not installed for WARP rotation")
        return

    old_v6 = get_egress_v6(timeout=8.0) or (get_warp_local_v6() or "")
    append_log(GUARD_LOG_FILE, f"wall detected — rotating WARP /64 (was: {old_v6 or '?'})")
    _blacklist_add(state, old_v6)
    _save_state(state)

    new_v6 = ""
    with keeper_pause_ctx("zen-guard", seconds=300):
        for attempt in range(1, MAX_HOP_TRIES + 1):
            cand = hop_once(warp_bin)
            if not cand:
                append_log(GUARD_LOG_FILE, f"try {attempt}: tunnel repair failed")
                continue
            if _is_burnt(state, cand):
                append_log(
                    GUARD_LOG_FILE,
                    f"try {attempt}: cloudflare returned a blacklisted /64 ({cand}) — again",
                )
                continue
            new_v6 = cand
            break

        if not new_v6:
            append_log(GUARD_LOG_FILE, "everything blacklisted — recycling oldest block")
            cand = hop_once(warp_bin)
            if cand:
                new_v6 = cand

    state["last_hop"] = now
    if new_v6:
        state["current"] = new_v6
        state["hops"] = int(state.get("hops", 0) or 0) + 1
        _save_state(state)
        append_log(GUARD_LOG_FILE, f"rotated #{state['hops']}: {old_v6} -> {new_v6} ✓")
        try:
            from ouc_common import LANE_DIR
            (LANE_DIR / "edge_reroll").write_text(str(time.time()), encoding="utf-8")
        except Exception:
            pass
    else:
        _save_state(state)
        append_log(
            GUARD_LOG_FILE,
            "rotation failed — keeper will keep the tunnel alive, retrying next wall",
        )


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

    while True:
        time.sleep(POLL_SECONDS)
        try:
            wall = _read_new_log_bytes(state)
            if not wall:
                continue
            now = int(time.time())
            last_hop = int(state.get("last_hop", 0) or 0)
            age = now - last_hop
            if age >= COOLDOWN_SECONDS:
                _rotate(state, warp_bin)
            else:
                append_log(
                    GUARD_LOG_FILE,
                    f"wall seen but in cooldown ({age}s < {COOLDOWN_SECONDS}s) — waiting",
                )
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"guard error: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
