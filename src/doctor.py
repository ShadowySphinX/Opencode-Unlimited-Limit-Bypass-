"""Doctor for Windows: health check for WARP tunnel, background tasks, and lane shim."""

from __future__ import annotations

import json
import shutil
import socket
import sys
from datetime import datetime, timezone

from ouc_common import (
    BIN_DIR,
    GUARD_STATE_FILE,
    SERVICE_PROXY_PORT,
    TASK_GUARD,
    TASK_KEEPER,
    find_opencode_cli,
    find_warp_cli,
    get_egress_ip,
    get_warp_local_v6,
    is_cloudflare_v6,
    normalize_v6_64,
    run_hidden,
    service_proxy_wired,
    warp_status,
)
from ouc_common import is_mutex_held
from ouc_firewall import is_killswitch_installed


def _ok(msg: str) -> None:
    print(f"  [OK] {msg}")


def _warn(msg: str) -> None:
    print(f"  [!]  {msg}")


def _bad(msg: str) -> None:
    print(f"  [X]  {msg}")


def _is_mutex_held(name: str) -> bool:
    """Same liveness check the dashboard uses, across both namespaces."""
    return is_mutex_held(name)


def _task_exists(task_name: str) -> bool:
    try:
        res = run_hidden(["schtasks", "/Query", "/TN", task_name], timeout=6.0)
        return res.returncode == 0
    except Exception:
        return False


def main() -> int:
    # Force UTF-8 output safely on Windows consoles
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    print("")
    print("  =============================")
    print("  Opencode Unlimited - doctor")
    print("  =============================")
    print("")

    # 1. Keeper status
    if _is_mutex_held("OpencodeUnlimitedKeeper"):
        _ok("warp-keeper process: running")
    elif _task_exists(TASK_KEEPER):
        _bad(f"warp-keeper down (task installed) - run: schtasks /Run /TN {TASK_KEEPER}")
    else:
        _bad("warp-keeper not running & scheduled task missing - re-run install.ps1")

    # 2. Egress Mode Check (WARP, Tor, or Custom Proxy)
    mode = "warp"
    default_scope = "tun" if sys.platform == "win32" else "isolated"
    warp_scope = default_scope
    try:
        from proxy_chain import get_egress_config
        cfg = get_egress_config()
        mode = cfg.get("mode", "warp")
        warp_scope = cfg.get("warp_scope", default_scope)
    except Exception:
        pass

    print(f"  [i]  active egress mode: {mode.upper()} (scope: {warp_scope})")

    if mode == "tor":
        try:
            from tor_manager import get_active_tor_target, is_portable_tor_running, test_socks5_alive
            tor_target = get_active_tor_target()
            if tor_target:
                alive = test_socks5_alive(tor_target[1], host=tor_target[0])
                if alive:
                    _ok(f"Tor SOCKS5 listening on {tor_target[0]}:{tor_target[1]}")
                else:
                    _warn(f"Tor process detected on {tor_target[0]}:{tor_target[1]}, but SOCKS5 probe failed")
            elif is_portable_tor_running():
                _warn("Tor is starting up - establishing circuit...")
            else:
                _bad("Tor daemon not running - click 'Start Portable Tor' in app")
        except Exception as exc:
            _bad(f"Tor check error: {exc}")

    elif mode == "custom":
        try:
            from proxy_chain import get_current_proxy_spec, relay_state

            spec = get_current_proxy_spec()
            phost, pport = spec["host"], int(spec["port"])
            _ok(f"custom proxy pool active: {phost}:{pport}")
            if spec.get("type") == "relay":
                state = relay_state(spec, timeout=8.0)
                if state.get("ok"):
                    resets = int(state.get("resets_at") or 0)
                    when = ""
                    if resets:
                        when = datetime.fromtimestamp(
                            resets, timezone.utc
                        ).strftime("%Y-%m-%d %H:%M UTC")
                    lane = str(state.get("lane") or "prefix")
                    _ok(
                        f"relay lane {lane} · block {state.get('block') or 'unassigned'} · "
                        f"requests today {state.get('requests', 0)} · resets {when or '?'}"
                    )
                    if state.get("instance"):
                        _ok(
                            f"relay exit {state['instance']} via "
                            f"{state.get('endpoint', '?')} (warp registration)"
                        )
                    elif state.get("source"):
                        _ok(f"relay source address {state['source']}")
                    stats = state.get("stats") or {}
                    if stats:
                        parts = [f"lane {stats.get('lane', '?')}"]
                        if stats.get("prefix_blocks"):
                            parts.append(
                                f"prefix {stats['prefix_blocks']} blocks, "
                                f"{stats.get('prefix_free', '?')} free"
                            )
                        if stats.get("warpgate_instances") is not None:
                            reachable = stats.get("warpgate_reachable")
                            parts.append(
                                f"warpgate {stats['warpgate_instances']} instances"
                                + ("" if reachable else " (unreachable)")
                            )
                        parts.append(f"burnt {stats.get('burnt_blocks', '?')}")
                        _ok("relay capacity: " + " · ".join(parts))
                        if stats.get("warpgate_reachable") is False:
                            _warn(
                                "relay cannot reach its WarpGate host - rotation will "
                                "fall back to the prefix lane only"
                            )
                        if stats.get("free_blocks") == 0:
                            _warn("relay has no spare blocks - add a prefix or WarpGate instances")
                else:
                    _bad(f"relay control API: {state.get('error', 'unreachable')}")
        except Exception as exc:
            _bad(f"custom proxy configuration error: {exc}")

    else:
        # WARP Mode Check
        warp_bin = find_warp_cli()
        if not warp_bin:
            _warn("warp-cli.exe not found - install Cloudflare WARP, or switch to Tor / Custom Proxy mode")
        else:
            connected, warp_m, raw = warp_status(warp_bin)
            if connected:
                mode_tag = f" (mode: {warp_m})" if warp_m else ""
                _ok(f"warp tunnel: connected{mode_tag}")
            else:
                _bad(f"warp not connected ({raw or 'unknown'}) - run opencode-unlimited-hop, or reconnect WARP from the dashboard")

        if warp_scope == "isolated":
            try:
                from tor_manager import test_socks5_alive
                if test_socks5_alive(40000, host="127.0.0.1"):
                    _ok("WARP isolated SOCKS5 proxy: active on 127.0.0.1:40000 (app-only mode)")
                else:
                    _warn("WARP isolated port 40000 not responding - reconnect WARP or switch the scope to Full TUN")
            except Exception:
                pass
        else:
            local_v6 = get_warp_local_v6()
            if local_v6:
                _ok(f"WARP adapter IPv6: {local_v6}")
            else:
                _warn("CloudflareWARP adapter IPv6 missing - switch to App-Only (Isolated) mode or check WARP TUN adapter")

    # 4. External egress check
    egress = get_egress_ip(timeout=8.0)
    if egress:
        if ":" in egress:
            prefix = normalize_v6_64(egress)
            if is_cloudflare_v6(egress):
                _ok(f"egress is cloudflare (warp): {prefix}/64")
            else:
                _ok(f"egress IPv6 verified: {egress}")
        else:
            # An IPv4 egress cannot be cleared by a /64 rotation: the address
            # the bucket follows never changes. Name it instead of passing.
            _warn(
                f"egress is IPv4 ({egress}) - rotating a /64 cannot move this "
                "address; check WARP mode and any IPv4 pin on the inference route"
            )
    else:
        _warn("no external egress check response (offline, tunnel still connecting, or proxy unavailable)")

    # 5. Guard status
    if _is_mutex_held("OpencodeUnlimitedGuard"):
        _ok("zen-guard process: running")
    elif _task_exists(TASK_GUARD):
        _bad(f"zen-guard down (task installed) - run: schtasks /Run /TN {TASK_GUARD}")
    else:
        _bad("zen-guard not running & scheduled task missing - re-run install.ps1")

    if GUARD_STATE_FILE.is_file():
        try:
            data = json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8"))
            hops = data.get("hops", 0)
            bl_count = len([x for x in data.get("blacklist", []) if x])
            print(f"       rotations so far: {hops} · blacklisted /64s: {bl_count}")
        except Exception as exc:
            print(f"       guard state unreadable: {exc}")

    # 6. Firewall kill-switch (optional admin rule)
    if is_killswitch_installed():
        _ok("firewall kill-switch (OUC_LEAKGUARD_CLI): installed")
    else:
        _warn("firewall kill-switch not installed (proxy still fails closed via WARP IPv6 bind; run install.bat as Admin to add firewall rule)")

    # 7. Real opencode binary + PATH shim check
    real_oc = find_opencode_cli()
    if real_oc:
        _ok(f"real opencode CLI: {real_oc}")
    else:
        _bad("real opencode CLI not found")

    # 8. OpenCode Desktop / background service proxy integration
    proxy_up = False
    try:
        with socket.create_connection(("127.0.0.1", SERVICE_PROXY_PORT), timeout=1.5):
            proxy_up = True
    except OSError:
        pass
    svc_proxied = service_proxy_wired()
    if proxy_up and svc_proxied:
        _ok(f"OpenCode Desktop & background service -> WARP lane (127.0.0.1:{SERVICE_PROXY_PORT})")
    elif proxy_up:
        _warn(f"service proxy listening on 127.0.0.1:{SERVICE_PROXY_PORT}, but service.json not wired - re-run install.bat")
    else:
        _warn(f"Desktop/service proxy not listening on 127.0.0.1:{SERVICE_PROXY_PORT} - restart OpencodeUnlimited-Keeper")

    which_oc = shutil.which("opencode")
    expected_shim = str(BIN_DIR / "opencode.cmd").lower()
    if which_oc and which_oc.lower() == expected_shim:
        _ok(f"opencode on PATH -> lane ({which_oc})")
    elif which_oc:
        _warn(f"opencode on PATH resolves to {which_oc} instead of {BIN_DIR / 'opencode.cmd'} - open a new terminal or move {BIN_DIR} earlier in PATH")
    else:
        _warn(f"opencode not on PATH - add {BIN_DIR} to User PATH")

    # 9. Client-side lock rows (names and parsed times only - never the values)
    try:
        from auto_resume import list_limit_state_keys, read_opencode_lock

        def _when(stamp: int) -> str:
            return datetime.fromtimestamp(stamp).strftime("%d %b %H:%M")

        lock_rows = list_limit_state_keys()
        info = read_opencode_lock()
        times = dict(info.get("keys") or {})
        if lock_rows:
            parts = []
            for name in sorted({name for _db, name in lock_rows}):
                stamp = int(times.get(name, 0) or 0)
                parts.append(f"{name} -> wait until {_when(stamp)}" if stamp else f"{name} -> no time stored")
            _warn(
                "client lock rows present: "
                + "; ".join(parts)
                + " - that time is a client hint: the guard clears it, tries the chat once, "
                "and only rotates if that attempt fails"
            )
        elif int(info.get("until", 0) or 0):
            _ok(f"client lock says wait until {_when(int(info['until']))} (a hint, not a wall)")
        else:
            _ok("no client-side limit lock rows")
    except Exception as exc:
        _warn(f"client lock check skipped: {exc}")

    print("")
    print("  all [OK] = ready. run `opencode` from a fresh terminal.")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
