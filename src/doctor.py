"""Doctor for Windows: health check for WARP tunnel, background tasks, and lane shim."""

from __future__ import annotations

import ctypes
import json
import shutil
import socket
import sys
from pathlib import Path

from ouc_common import (
    BIN_DIR,
    GUARD_STATE_FILE,
    SERVICE_PROXY_PORT,
    TASK_GUARD,
    TASK_KEEPER,
    find_opencode_cli,
    find_warp_cli,
    get_egress_v6,
    get_warp_local_v6,
    is_cloudflare_v6,
    normalize_v6_64,
    run_hidden,
    warp_status,
)
from ouc_firewall import is_killswitch_installed


def _ok(msg: str) -> None:
    print(f"  [OK] {msg}")


def _warn(msg: str) -> None:
    print(f"  [!]  {msg}")


def _bad(msg: str) -> None:
    print(f"  [X]  {msg}")


def _is_mutex_held(name: str) -> bool:
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenMutexW.restype = ctypes.c_void_p
    SYNCHRONIZE = 0x00100000
    handle = kernel32.OpenMutexW(SYNCHRONIZE, False, f"Local\\{name}")
    if handle:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return True
    return False


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
    print("  Opencode Unlimited — doctor")
    print("  =============================")
    print("")

    # 1. Keeper status
    if _is_mutex_held("OpencodeUnlimitedKeeper"):
        _ok("warp-keeper process: running")
    elif _task_exists(TASK_KEEPER):
        _bad(f"warp-keeper down (task installed) — run: schtasks /Run /TN {TASK_KEEPER}")
    else:
        _bad("warp-keeper not running & scheduled task missing — re-run install.ps1")

    # 2. WARP CLI & Tunnel
    warp_bin = find_warp_cli()
    if not warp_bin:
        _bad("warp-cli.exe not found — install Cloudflare WARP")
    else:
        connected, mode, raw = warp_status(warp_bin)
        if connected:
            mode_tag = f" (mode: {mode})" if mode else ""
            _ok(f"warp tunnel: connected{mode_tag}")
        else:
            _bad(f"warp not connected ({raw or 'unknown'}) — run: opencode-unlimited-hop")

    # 3. Local CloudflareWARP IPv6 adapter address
    local_v6 = get_warp_local_v6()
    if local_v6:
        _ok(f"WARP adapter IPv6: {local_v6}")
    else:
        _bad("CloudflareWARP adapter IPv6 missing — ensure WARP is in TUN (warp) mode")

    # 4. External IPv6 egress check
    egress = get_egress_v6(timeout=8.0)
    if egress:
        prefix = normalize_v6_64(egress)
        if is_cloudflare_v6(egress):
            _ok(f"egress is cloudflare (warp): {prefix}/64")
        else:
            _bad(f"egress is NOT warp ({egress}) — check WARP mode/tunnel")
    else:
        _warn("no IPv6 egress check response (offline or tunnel still connecting)")

    # 5. Guard status
    if _is_mutex_held("OpencodeUnlimitedGuard"):
        _ok("zen-guard process: running")
    elif _task_exists(TASK_GUARD):
        _bad(f"zen-guard down (task installed) — run: schtasks /Run /TN {TASK_GUARD}")
    else:
        _bad("zen-guard not running & scheduled task missing — re-run install.ps1")

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
    svc_cfg = Path.home() / ".config" / "opencode" / "service.json"
    svc_proxied = False
    if svc_cfg.is_file():
        try:
            cfg = json.loads(svc_cfg.read_text(encoding="utf-8"))
            env_map = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
            svc_proxied = f"127.0.0.1:{SERVICE_PROXY_PORT}" in str(env_map.get("HTTPS_PROXY", ""))
        except Exception:
            pass
    if proxy_up and svc_proxied:
        _ok(f"OpenCode Desktop & background service -> WARP lane (127.0.0.1:{SERVICE_PROXY_PORT})")
    elif proxy_up:
        _warn(f"service proxy listening on 127.0.0.1:{SERVICE_PROXY_PORT}, but service.json not wired — re-run install.bat")
    else:
        _warn(f"Desktop/service proxy not listening on 127.0.0.1:{SERVICE_PROXY_PORT} — restart OpencodeUnlimited-Keeper")

    which_oc = shutil.which("opencode")
    expected_shim = str(BIN_DIR / "opencode.cmd").lower()
    if which_oc and which_oc.lower() == expected_shim:
        _ok(f"opencode on PATH -> lane ({which_oc})")
    elif which_oc:
        _warn(f"opencode on PATH resolves to {which_oc} instead of {BIN_DIR / 'opencode.cmd'} — open a new terminal or move {BIN_DIR} earlier in PATH")
    else:
        _warn(f"opencode not on PATH — add {BIN_DIR} to User PATH")

    print("")
    print("  all [OK] = ready. run `opencode` from a fresh terminal.")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
