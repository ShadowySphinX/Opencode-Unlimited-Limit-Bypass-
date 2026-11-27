"""Windows WARP keeper: keeps the selected WARP mode connected and repairs dropped tunnels."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time

from ouc_common import (
    KEEPER_LOG_FILE,
    LANE_DIR,
    SERVICE_PROXY_PORT,
    acquire_mutex,
    append_log,
    ensure_dirs,
    ensure_warp_mode,
    find_warp_cli,
    is_admin,
    is_keeper_paused,
    repair_warp_registration,
    run_warp,
    warp_mode,
    warp_status,
)
from ouc_firewall import install_killswitch, is_killswitch_installed
from zen_proxy import start_proxy_server

TICK_SECONDS = 45
REPAIR_COOLDOWN_SECONDS = 120.0
WARP_PROXY_PORT = 40000
PROXY_WATCH_SECONDS = 3.0
# A tunnel that cannot connect on one tick may still be mid-reconnect on the
# next, so the hand-over needs a second bad tick before it acts.
WARP_DOWN_TICKS = 2
HEARTBEAT_FILE = KEEPER_LOG_FILE.parent / "heartbeat.txt"
_PROXY_LOCK = threading.Lock()
_last_repair = 0.0
_warp_down_ticks = 0


def _hand_over_to_tor(mode: str) -> bool:
    """Run the lane on Tor when WARP will not connect.

    Requests already fall back to Tor in that state, and rotation follows the
    configured mode, so staying on WARP would rotate a tunnel that is not
    carrying the traffic. A strict proxy is a deliberate choice and is left
    alone.
    """
    if mode not in ("warp", "clean"):
        return False
    if os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file():
        return False
    try:
        from proxy_chain import get_egress_config, set_egress_config
        from tor_manager import get_active_tor_target, start_portable_tor
    except Exception:
        return False
    if not get_active_tor_target():
        ok, _ = start_portable_tor()
        if not ok:
            return False
    cfg = get_egress_config()
    set_egress_config(
        "tor",
        custom_proxy=str(cfg.get("custom_proxy", "127.0.0.1:10808")),
        custom_type=str(cfg.get("custom_type", "socks5")),
        warp_scope=str(cfg.get("warp_scope", "")),
    )
    append_log(
        KEEPER_LOG_FILE,
        "WARP will not connect and Tor is up - the lane switched to Tor; pick WARP "
        "in the dashboard once it recovers",
    )
    return True


def _heartbeat() -> None:
    """Cheap liveness signal the app checks; a running but hung keeper stops writing this."""
    try:
        HEARTBEAT_FILE.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        pass


def _active_scope() -> str:
    default_scope = "tun" if sys.platform == "win32" else "isolated"
    try:
        from proxy_chain import get_egress_config

        return str(get_egress_config().get("warp_scope", default_scope))
    except Exception:
        return default_scope


def _wait_connected(warp_bin: str, attempts: int = 10) -> bool:
    for _ in range(attempts):
        time.sleep(1.0)
        connected, _, _ = warp_status(warp_bin=warp_bin, force=True)
        if connected:
            return True
    return False


def _connect(warp_bin: str, scope: str) -> bool:
    # ensure_warp_mode also applies the protocol the scope needs, so an app-only
    # reconnect stays on MASQUE instead of being pushed back to WireGuard.
    ensure_warp_mode(warp_bin, scope)
    run_warp(["connect"], warp_bin=warp_bin, timeout=12.0)
    return _wait_connected(warp_bin)


def _registration_missing(raw: str) -> bool:
    low = (raw or "").lower()
    return any(
        marker in low
        for marker in ("registration missing", "not registered", "no registration")
    )


def ensure_connected(warp_bin: str | None = None) -> bool:
    """Keep the WARP tunnel connected without resetting a healthy session."""
    global _last_repair

    if not warp_bin:
        warp_bin = find_warp_cli()
    if not warp_bin:
        return False

    scope = _active_scope()
    desired_mode = "proxy" if scope == "isolated" else "warp"
    connected, _mode, raw = warp_status(warp_bin=warp_bin, force=True)
    if connected:
        current_mode = warp_mode(warp_bin=warp_bin)
        if current_mode == desired_mode or (
            # An unreadable mode is only healthy when the port the scope needs
            # is actually listening; otherwise the tunnel is drift too.
            not current_mode
            and (desired_mode != "proxy" or _port_open(WARP_PROXY_PORT))
        ):
            return True
        # The selected scope changed while the tunnel stayed up. Apply the
        # mode before returning so the isolated proxy port is actually bound.
        append_log(
            KEEPER_LOG_FILE,
            f"operation mode drift ({current_mode} -> {desired_mode}) - applying selected scope",
        )
        ensure_warp_mode(warp_bin, scope)
        if _wait_connected(warp_bin, 8):
            return True
        _, _, raw = warp_status(warp_bin=warp_bin, force=True)

    low = (raw or "").lower()
    if "connecting" in low or "reconnecting" in low:
        if _wait_connected(warp_bin, 8):
            return True
        _, _, raw = warp_status(warp_bin=warp_bin, force=True)

    if _registration_missing(raw):
        append_log(KEEPER_LOG_FILE, "registration missing - creating a new one")
        if not repair_warp_registration(warp_bin, 3):
            return False
        raw = ""

    if _connect(warp_bin, scope):
        return True

    if time.monotonic() - _last_repair < REPAIR_COOLDOWN_SECONDS:
        return False
    _last_repair = time.monotonic()

    append_log(KEEPER_LOG_FILE, "tunnel disconnected - renewing keys and reconnecting")
    run_warp(["tunnel", "rotate-keys"], warp_bin=warp_bin, timeout=15.0)
    if _connect(warp_bin, scope):
        return True

    _, _, raw = warp_status(warp_bin=warp_bin, force=True)
    if _registration_missing(raw):
        if repair_warp_registration(warp_bin, 3) and _connect(warp_bin, scope):
            return True
    return False


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.6):
            return True
    except OSError:
        return False


def _start_service_proxy(quiet: bool = False) -> object | None:
    with _PROXY_LOCK:
        if _port_open(SERVICE_PROXY_PORT):
            return None
        try:
            srv, bound_port, edge = start_proxy_server(SERVICE_PROXY_PORT)
            if not quiet:
                append_log(
                    KEEPER_LOG_FILE,
                    f"service proxy listening on 127.0.0.1:{bound_port} (edge={edge})",
                )
            return srv
        except Exception as exc:
            if not quiet:
                append_log(
                    KEEPER_LOG_FILE,
                    f"service proxy bind failed on port {SERVICE_PROXY_PORT}: {exc}",
                )
            return None


def _desktop_brand_once(state: dict) -> dict:
    """Keep the desktop copy patch in place after an app update.

    One ``stat`` when the archive has not moved, which is every tick on a normal
    day. The result is logged when it changes rather than every tick, so the
    keeper log still reads like a history instead of a pulse.
    """
    try:
        import desktop_brand

        result = desktop_brand.sync_copy()
    except Exception as exc:
        result = f"error: {exc}"
    if result != state.get("desktop_brand"):
        state["desktop_brand"] = result
        if result not in ("ok", "off"):
            append_log(KEEPER_LOG_FILE, f"desktop copy: {result}")
    return state


def _proxy_watchdog() -> None:
    """Keep the local proxy served; rebind it within seconds if it disappears."""
    servers = []  # keep references so the servers are not garbage collected
    bind_failing = False
    while True:
        try:
            if not _port_open(SERVICE_PROXY_PORT):
                srv = _start_service_proxy(quiet=True)
                if srv is not None:
                    servers.append(srv)
                    bind_failing = False
                elif not bind_failing:
                    append_log(
                        KEEPER_LOG_FILE,
                        f"service proxy is not listening on port {SERVICE_PROXY_PORT}; retrying every "
                        f"{int(PROXY_WATCH_SECONDS)}s",
                    )
                    bind_failing = True
        except Exception:
            pass
        time.sleep(PROXY_WATCH_SECONDS)


def main() -> int:
    global _warp_down_ticks
    ensure_dirs()
    mutex = acquire_mutex("OpencodeUnlimitedKeeper")
    if mutex is None:
        return 0

    warp_bin = find_warp_cli()
    append_log(KEEPER_LOG_FILE, f"keeper up (tick={TICK_SECONDS}s, warp={'found' if warp_bin else 'none'})")
    _heartbeat()

    # Start the desktop/service proxy on 41987 so every egress mode is routable.
    proxy_srv = _start_service_proxy()
    reported_external = proxy_srv is None and _port_open(SERVICE_PROXY_PORT)
    threading.Thread(target=_proxy_watchdog, daemon=True).start()
    brand_state: dict = {}

    # On startup, allow network interface initialization if booting and warp is installed
    if warp_bin:
        for _ in range(6):
            rc, _ = run_warp(["status"], warp_bin=warp_bin, timeout=8.0)
            if rc == 0:
                break
            time.sleep(8)

    while True:
        try:
            _heartbeat()
            brand_state = _desktop_brand_once(brand_state)
            if proxy_srv is None and not _port_open(SERVICE_PROXY_PORT):
                proxy_srv = _start_service_proxy()
            elif proxy_srv is None and not reported_external:
                append_log(KEEPER_LOG_FILE, "service proxy is already listening")
                reported_external = True

            if warp_bin is None:
                warp_bin = find_warp_cli()

            mode = "warp"
            try:
                from proxy_chain import get_egress_config
                mode = get_egress_config().get("mode", "warp")
            except Exception:
                pass

            if mode in ("warp", "clean"):
                if warp_bin and not is_keeper_paused():
                    if ensure_connected(warp_bin):
                        _warp_down_ticks = 0
                    else:
                        _warp_down_ticks += 1
                        if _warp_down_ticks >= WARP_DOWN_TICKS and _hand_over_to_tor(mode):
                            _warp_down_ticks = 0
                    if is_admin() and (
                        os.environ.get("OUC_FIREWALL_KILLSWITCH") == "1"
                        or is_killswitch_installed()
                    ):
                        if not is_killswitch_installed():
                            install_killswitch()
            elif mode == "tor":
                # Restart the managed Tor daemon only when its process is gone,
                # or when a live process has not opened its SOCKS port after a
                # generous bootstrap window. Restarting on every tick would kill
                # a slow first bootstrap before it completes.
                try:
                    from tor_manager import (
                        TOR_PID_FILE,
                        get_active_tor_target,
                        is_portable_tor_running,
                        start_portable_tor,
                        stop_portable_tor,
                    )
                    if not get_active_tor_target():
                        if not is_portable_tor_running():
                            start_portable_tor()
                        else:
                            try:
                                age = time.time() - TOR_PID_FILE.stat().st_mtime
                            except OSError:
                                age = 0.0
                            if age > 240.0:
                                append_log(
                                    KEEPER_LOG_FILE,
                                    "Tor SOCKS port did not open within 240s - restarting Tor",
                                )
                                stop_portable_tor()
                                start_portable_tor()
                except Exception:
                    pass
        except Exception as exc:
            append_log(KEEPER_LOG_FILE, f"keeper error: {exc}")
        time.sleep(TICK_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
