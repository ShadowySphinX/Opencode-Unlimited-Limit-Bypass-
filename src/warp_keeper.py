"""Windows WARP keeper: enforces TUN mode and auto-repairs WARP connections."""

from __future__ import annotations

import os
import sys
import time

from ouc_common import (
    KEEPER_LOG_FILE,
    SERVICE_PROXY_PORT,
    acquire_mutex,
    append_log,
    ensure_dirs,
    find_warp_cli,
    get_warp_local_v6,
    is_admin,
    is_keeper_paused,
    run_warp,
    warp_status,
)
from ouc_firewall import install_killswitch, is_killswitch_installed
from zen_proxy import start_proxy_server

TICK_SECONDS = 45


def ensure_connected(warp_bin: str) -> bool:
    """Verify WARP connection based on active scope (isolated proxy or full TUN)."""
    scope = "isolated"
    try:
        from proxy_chain import get_egress_config
        scope = get_egress_config().get("warp_scope", "isolated")
    except Exception:
        pass

    connected, mode, _ = warp_status(warp_bin)
    if scope == "isolated":
        run_warp(["proxy", "port", "40000"], warp_bin=warp_bin)
        if mode and "proxy" not in mode.lower():
            run_warp(["mode", "proxy"], warp_bin=warp_bin)
        elif not mode:
            run_warp(["mode", "proxy"], warp_bin=warp_bin)

        if connected:
            return True
        run_warp(["connect"], warp_bin=warp_bin)
        time.sleep(3)
        connected, _, _ = warp_status(warp_bin)
        return connected

    # Full System TUN mode
    if mode and "warp" not in mode.lower():
        run_warp(["mode", "warp"], warp_bin=warp_bin)
    elif not mode:
        run_warp(["mode", "warp"], warp_bin=warp_bin)

    if connected and get_warp_local_v6():
        return True

    run_warp(["connect"], warp_bin=warp_bin)
    time.sleep(4)
    connected, _, _ = warp_status(warp_bin)
    if connected and get_warp_local_v6():
        append_log(KEEPER_LOG_FILE, "reconnected existing registration")
        return True

    append_log(KEEPER_LOG_FILE, "tunnel dead — rotating registration to repair")
    run_warp(["disconnect"], warp_bin=warp_bin)
    run_warp(["registration", "delete"], warp_bin=warp_bin)
    rc, msg = run_warp(["registration", "new"], warp_bin=warp_bin)
    if rc != 0:
        append_log(KEEPER_LOG_FILE, f"registration new failed: {msg}")
        return False

    run_warp(["mode", "warp"], warp_bin=warp_bin)
    run_warp(["connect"], warp_bin=warp_bin)
    time.sleep(5)
    connected, _, _ = warp_status(warp_bin)
    ok = connected and bool(get_warp_local_v6())
    append_log(KEEPER_LOG_FILE, "tunnel repaired ✓" if ok else "repair still waiting for IPv6")
    return ok


def main() -> int:
    ensure_dirs()
    mutex = acquire_mutex("OpencodeUnlimitedKeeper")
    if mutex is None:
        return 0

    warp_bin = find_warp_cli()
    append_log(KEEPER_LOG_FILE, f"keeper up (tick={TICK_SECONDS}s, warp={'found' if warp_bin else 'none'})")

    # 1. ALWAYS start the desktop/service proxy on port 41987 first so OpenCode can route in all modes
    proxy_srv = None
    try:
        proxy_srv, bound_port, edge = start_proxy_server(SERVICE_PROXY_PORT)
        append_log(KEEPER_LOG_FILE, f"desktop/service proxy listening on 127.0.0.1:{bound_port} (edge={edge})")
    except Exception as exc:
        append_log(KEEPER_LOG_FILE, f"service proxy bind failed on port {SERVICE_PROXY_PORT}: {exc}")

    # On startup, allow network interface initialization if booting and warp is installed
    if warp_bin:
        for _ in range(6):
            rc, _ = run_warp(["status"], warp_bin=warp_bin, timeout=8.0)
            if rc == 0:
                break
            time.sleep(8)

    while True:
        try:
            mode = "warp"
            try:
                from proxy_chain import get_egress_config
                mode = get_egress_config().get("mode", "warp")
            except Exception:
                pass

            if mode in ("warp", "clean"):
                if warp_bin and not is_keeper_paused():
                    ensure_connected(warp_bin)
                    if is_admin() and (
                        os.environ.get("OUC_FIREWALL_KILLSWITCH") == "1"
                        or is_killswitch_installed()
                    ):
                        if not is_killswitch_installed():
                            install_killswitch()
            elif mode == "tor":
                # Ensure Tor daemon is healthy if managed
                try:
                    from tor_manager import get_active_tor_target, is_portable_tor_running, start_portable_tor
                    if not get_active_tor_target() and is_portable_tor_running():
                        start_portable_tor()
                except Exception:
                    pass
        except Exception as exc:
            append_log(KEEPER_LOG_FILE, f"keeper error: {exc}")
        time.sleep(TICK_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
