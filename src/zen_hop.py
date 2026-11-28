"""Zen Hop for Windows: manual WARP /64 identity rotation."""

from __future__ import annotations

import json
import sys

from ouc_common import (
    GUARD_STATE_FILE,
    find_warp_cli,
    get_egress_v6,
    get_warp_local_v6,
    hop_once,
    keeper_pause_ctx,
    normalize_v6_64,
)


def main() -> int:
    warp_bin = find_warp_cli()
    if not warp_bin:
        print("warp-cli.exe not found", file=sys.stderr)
        return 1

    old_v6 = get_egress_v6(timeout=8.0) or (get_warp_local_v6() or "")
    print(f"old /64: {old_v6 or '?'}")
    print("-- rotating (keeper paused) --")

    avoid: set[str] = set()
    if GUARD_STATE_FILE.is_file():
        try:
            state = json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8"))
            avoid = {str(x) for x in state.get("blacklist", []) if x}
        except Exception:
            pass

    with keeper_pause_ctx("zen-hop", seconds=300):
        new_v6 = hop_once(
            warp_bin,
            max_reg_tries=4,
            avoid_prefixes=avoid,
            previous=old_v6,
        )

    if not new_v6:
        print("-- rotation failed; the keeper will keep the tunnel alive and retry --")
        return 1

    # Use the guard's recorder so a manual hop leaves last_ok_hop and the pauses
    # in the same shape the guard expects; a bare clear left the guard paused.
    try:
        from zen_guard import record_hop

        state: dict = {}
        if GUARD_STATE_FILE.is_file():
            try:
                state = json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                state = {}
        record_hop(state, old_v6, new_v6, source="manual-cli", clear_pauses=True)
    except Exception as exc:
        print(f"-- could not update the guard state: {exc} --")

    try:
        from auto_resume import resume_active_session

        _ok, msg = resume_active_session(None)
        print(f"-- unlock: {msg} --")
    except Exception as exc:
        print(f"-- unlock note: {exc} --")

    print(f"new /64: {new_v6}")
    old_prefix = normalize_v6_64(old_v6)
    new_prefix = normalize_v6_64(new_v6)
    if new_prefix and new_prefix != old_prefix:
        print("new /64 prefix accepted; re-send your message.")
        return 0
    if new_v6 != old_v6:
        print("new address accepted; re-send your message.")
        return 0

    print("Cloudflare returned the same /64 block; run the command again.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
