"""Zen Hop for Windows: manual WARP /64 identity rotation."""

from __future__ import annotations

import sys

from ouc_common import (
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

    with keeper_pause_ctx("zen-hop", seconds=180):
        new_v6 = hop_once(warp_bin, max_reg_tries=5)

    if not new_v6:
        print("-- registration/tunnel failed — keeper will keep retrying --")
        return 1

    print(f"new /64: {new_v6}")
    old_prefix = normalize_v6_64(old_v6)
    new_prefix = normalize_v6_64(new_v6)
    if new_prefix and new_prefix != old_prefix:
        print("== FRESH /64 ✓ — re-send your message ==")
        return 0
    if new_v6 != old_v6:
        print("== FRESH /64 ✓ — re-send your message ==")
        return 0

    print("== cloudflare handed back the same block — run me again ==")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
