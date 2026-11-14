"""Opencode Unlimited — Control Center GUI (Made by Avatar)."""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Support frozen PyInstaller bundle as well as direct execution from windows/
def _bundle_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


_BUNDLE = _bundle_dir()
if str(_BUNDLE) not in sys.path:
    sys.path.insert(0, str(_BUNDLE))

import psutil
import webview

from ouc_common import (
    BIN_DIR,
    BRAND,
    CREATE_NO_WINDOW,
    DEST_DIR,
    GUARD_LOG_FILE,
    GUARD_STATE_FILE,
    KEEPER_LOG_FILE,
    LANE_DIR,
    OPENCODE_LOG_FILE,
    SCRIPTS_DIR,
    SERVICE_PROXY_PORT,
    TASK_GUARD,
    TASK_KEEPER,
    ensure_dirs,
    fetch_opencode_aaaa_pool,
    find_opencode_cli,
    find_opencode_desktop,
    find_warp_cli,
    get_egress_v6,
    get_warp_local_v6,
    hop_once,
    is_admin,
    is_cloudflare_v6,
    is_keeper_paused,
    keeper_pause_ctx,
    normalize_v6_64,
    run_hidden,
    run_warp,
    warp_status,
)
from ouc_firewall import install_killswitch, is_killswitch_installed, remove_killswitch

WINDOW_TITLE = "Opencode Unlimited v2.4.0 — Made by Avatar"
DETACHED_PROCESS = 0x00000008
_WORKER_FILES = (
    "ouc_common.py",
    "ouc_firewall.py",
    "zen_proxy.py",
    "zen_lane.py",
    "warp_keeper.py",
    "zen_guard.py",
    "zen_hop.py",
    "doctor.py",
    "tor_manager.py",
    "proxy_chain.py",
    "clean_endpoint.py",
)
_SERVICE_ENV_KEYS = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "https_proxy",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
)


def _enable_dark_titlebar() -> None:
    """Apply native Windows 10/11 dark mode to the PyWebView window frame."""
    try:
        hwnd = ctypes.windll.user32.FindWindowW(None, WINDOW_TITLE)
        if not hwnd:
            return
        val = ctypes.c_int(1)
        for attr in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                ctypes.c_void_p(hwnd),
                ctypes.c_uint(attr),
                ctypes.byref(val),
                ctypes.sizeof(val),
            )
    except Exception:
        pass


def _is_mutex_held(name: str) -> bool:
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenMutexW.restype = ctypes.c_void_p
    handle = kernel32.OpenMutexW(0x00100000, False, f"Local\\{name}")
    if handle:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return True
    return False


def _task_exists(task_name: str) -> bool:
    try:
        res = run_hidden(["schtasks", "/Query", "/TN", task_name], timeout=5.0)
        return res.returncode == 0
    except Exception:
        return False


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.6):
            return True
    except OSError:
        return False


def _tail_lines(path: Path, count: int = 75) -> list[str]:
    if not path.is_file():
        return []
    try:
        size = path.stat().st_size
        read_bytes = min(size, 131_072)
        with path.open("rb") as fh:
            if size > read_bytes:
                fh.seek(size - read_bytes)
            text = fh.read(read_bytes).decode("utf-8", errors="replace")
        lines = text.splitlines()
        return lines[-count:]
    except Exception:
        return []


def _read_db_stats() -> dict[str, int]:
    db_path = Path.home() / ".local" / "share" / "opencode" / "opencode.db"
    out = {"projects": 0, "sessions": 0, "messages": 0}
    if not db_path.is_file():
        return out
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
        try:
            for key, table in (("projects", "project"), ("sessions", "session_v2"), ("messages", "session_message")):
                row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()
                if row:
                    out[key] = int(row[0])
        finally:
            conn.close()
    except Exception:
        pass
    return out


def _find_pythonw() -> str | None:
    if not getattr(sys, "frozen", False):
        exe = Path(sys.executable)
        pw = exe.with_name("pythonw.exe")
        return str(pw if pw.is_file() else exe)
    for cmd in ("pythonw.exe", "python.exe"):
        found = shutil.which(cmd)
        if found and "WindowsApps" not in found:
            return found
    return None


def _deploy_scripts_and_shims() -> dict[str, str]:
    ensure_dirs()
    src_dir = _BUNDLE
    for candidate in (_BUNDLE / "src", _BUNDLE / "windows", _BUNDLE, Path(__file__).resolve().parent):
        if (candidate / "ouc_common.py").is_file():
            src_dir = candidate
            break
    for fname in _WORKER_FILES:
        src = src_dir / fname
        if src.is_file():
            shutil.copy2(src, SCRIPTS_DIR / fname)

    py_exe = shutil.which("python.exe")
    if py_exe and "WindowsApps" in py_exe:
        py_exe = None
    if not getattr(sys, "frozen", False):
        py_exe = sys.executable

    if py_exe:
        pyw_exe = str(Path(py_exe).with_name("pythonw.exe"))
        if not Path(pyw_exe).is_file():
            pyw_exe = py_exe
        wrappers = {
            "opencode.cmd": f'@echo off\r\n"{py_exe}" "{SCRIPTS_DIR / "zen_lane.py"}" %*\r\nexit /b %ERRORLEVEL%\r\n',
            "opencode-desktop.cmd": f'@echo off\r\nstart "" "{pyw_exe}" "{SCRIPTS_DIR / "zen_lane.py"}" --ouc-desktop %*\r\n',
            "opencode-unlimited-hop.cmd": f'@echo off\r\n"{py_exe}" "{SCRIPTS_DIR / "zen_hop.py"}" %*\r\nexit /b %ERRORLEVEL%\r\n',
            "opencode-unlimited-doctor.cmd": f'@echo off\r\n"{py_exe}" "{SCRIPTS_DIR / "doctor.py"}" %*\r\nexit /b %ERRORLEVEL%\r\n',
            "opencode-unlimited-keeper.cmd": f'@echo off\r\n"{py_exe}" "{SCRIPTS_DIR / "warp_keeper.py"}" %*\r\nexit /b %ERRORLEVEL%\r\n',
            "opencode-unlimited-guard.cmd": f'@echo off\r\n"{py_exe}" "{SCRIPTS_DIR / "zen_guard.py"}" %*\r\nexit /b %ERRORLEVEL%\r\n',
        }
        for name, content in wrappers.items():
            (BIN_DIR / name).write_text(content, encoding="ascii")
    elif getattr(sys, "frozen", False):
        exe = sys.executable
        wrappers = {
            "opencode.cmd": f'@echo off\r\n"{exe}" --lane %*\r\nexit /b %ERRORLEVEL%\r\n',
            "opencode-desktop.cmd": f'@echo off\r\nstart "" "{exe}" --lane --ouc-desktop %*\r\n',
            "opencode-unlimited-hop.cmd": f'@echo off\r\n"{exe}" --hop %*\r\nexit /b %ERRORLEVEL%\r\n',
            "opencode-unlimited-doctor.cmd": f'@echo off\r\n"{exe}" --doctor %*\r\nexit /b %ERRORLEVEL%\r\n',
            "opencode-unlimited-keeper.cmd": f'@echo off\r\n"{exe}" --worker keeper\r\nexit /b %ERRORLEVEL%\r\n',
            "opencode-unlimited-guard.cmd": f'@echo off\r\n"{exe}" --worker guard\r\nexit /b %ERRORLEVEL%\r\n',
        }
        for name, content in wrappers.items():
            (BIN_DIR / name).write_text(content, encoding="ascii")

    return {"scripts_dir": str(SCRIPTS_DIR), "bin_dir": str(BIN_DIR)}


def _update_user_path(add: bool) -> bool:
    import winreg

    target = str(BIN_DIR).rstrip("\\")
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                cur, reg_type = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                cur, reg_type = "", winreg.REG_EXPAND_SZ
            parts = [p for p in str(cur).split(";") if p and p.rstrip("\\").lower() != target.lower()]
            if add:
                new_parts = [target, *parts]
            else:
                new_parts = parts
            winreg.SetValueEx(key, "Path", 0, reg_type, ";".join(new_parts))
        return True
    except Exception:
        return False


def _user_path_has_bin() -> bool:
    import winreg

    target = str(BIN_DIR).rstrip("\\").lower()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
            cur, _ = winreg.QueryValueEx(key, "Path")
            parts = [p.rstrip("\\").lower() for p in str(cur).split(";") if p]
            return bool(parts and parts[0] == target)
    except Exception:
        return False


class AvatarControlApi:
    """Backend controller exposed to the Avatar WebView2 UI."""

    def __init__(self) -> None:
        ensure_dirs()
        self._egress_lock = threading.Lock()
        self._egress_v6 = ""
        self._egress_checking = False
        self._last_egress_ts = 0.0
        self._last_local_v6 = ""
        self._edge_pool: list[str] = []
        self._action_lock = threading.Lock()
        self._ensure_proxy_active()
        self._refresh_egress_async(force=True)
        self._refresh_pool_async()
        self._auto_heal_warp_startup()

    def _ensure_proxy_active(self) -> None:
        """Guarantee that local HTTP/CONNECT proxy on SERVICE_PROXY_PORT (41987) is always running."""
        if not _port_open(SERVICE_PROXY_PORT):
            def _serve() -> None:
                try:
                    from zen_proxy import start_proxy_server
                    start_proxy_server(SERVICE_PROXY_PORT)
                except Exception:
                    pass
            threading.Thread(target=_serve, daemon=True).start()

    def _auto_heal_warp_startup(self) -> None:
        def _check_and_heal() -> None:
            time.sleep(2.5)
            wb = find_warp_cli()
            if not wb:
                return
            try:
                conn, mode, raw = warp_status(wb)
                raw_lower = raw.lower()
                # If WARP has handshake block, MITM error, or unstable connection on launch, self-heal automatically
                if (not conn) or ("unstable" in raw_lower) or ("mitm" in raw_lower) or ("unable" in raw_lower):
                    self.repair_warp_connection()
            except Exception:
                pass

        threading.Thread(target=_check_and_heal, daemon=True).start()

    def _refresh_pool_async(self) -> None:
        def _run() -> None:
            pool = fetch_opencode_aaaa_pool()
            if pool:
                self._edge_pool = pool

        threading.Thread(target=_run, daemon=True).start()

    def _refresh_egress_async(self, force: bool = False) -> None:
        with self._egress_lock:
            if self._egress_checking:
                return
            if not force and (time.time() - self._last_egress_ts) < 25.0:
                return
            self._egress_checking = True

        def _run() -> None:
            try:
                v6 = get_egress_v6(timeout=6.0)
                with self._egress_lock:
                    self._egress_v6 = v6
                    self._last_egress_ts = time.time()
            finally:
                with self._egress_lock:
                    self._egress_checking = False

        threading.Thread(target=_run, daemon=True).start()

    def get_state(self, force_egress: bool = False) -> dict:
        warp_bin = find_warp_cli()
        connected, mode, status_text = warp_status(warp_bin) if warp_bin else (False, "", "Not Installed")
        local_v6 = get_warp_local_v6() or ""

        if local_v6 != self._last_local_v6:
            self._last_local_v6 = local_v6
            if local_v6:
                self._refresh_egress_async(force=True)
            else:
                with self._egress_lock:
                    self._egress_v6 = ""
        elif force_egress:
            self._refresh_egress_async(force=True)

        with self._egress_lock:
            egress_v6 = self._egress_v6
            checking_egress = self._egress_checking

        guard_state = {"blacklist": [], "hops": 0, "last_hop": 0, "current": ""}
        if GUARD_STATE_FILE.is_file():
            try:
                guard_state.update(json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8")))
            except Exception:
                pass

        blacklist = [x for x in guard_state.get("blacklist", []) if x]
        pinned_edge = ""
        last_edge_file = LANE_DIR / "last_edge.txt"
        if last_edge_file.is_file():
            pinned_edge = last_edge_file.read_text(encoding="utf-8").strip()

        edge_override = "auto"
        override_file = LANE_DIR / "edge_override.txt"
        if override_file.is_file():
            val = override_file.read_text(encoding="utf-8").strip()
            if val:
                edge_override = val

        svc_cfg = Path.home() / ".config" / "opencode" / "service.json"
        svc_wired = False
        if svc_cfg.is_file():
            try:
                cfg = json.loads(svc_cfg.read_text(encoding="utf-8"))
                env_map = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
                svc_wired = f"127.0.0.1:{SERVICE_PROXY_PORT}" in str(env_map.get("HTTPS_PROXY", ""))
            except Exception:
                pass

        cli_path = find_opencode_cli() or ""
        desktop_path = find_opencode_desktop() or ""
        log_size = OPENCODE_LOG_FILE.stat().st_size if OPENCODE_LOG_FILE.is_file() else 0

        return {
            "warp": {
                "installed": bool(warp_bin),
                "bin": warp_bin or "",
                "connected": connected,
                "mode": mode or "unknown",
                "status_text": status_text or ("Connected" if connected else "Disconnected"),
                "adapter_v6": local_v6,
                "egress_v6": egress_v6,
                "egress_prefix": normalize_v6_64(egress_v6) if egress_v6 else "",
                "is_cf": is_cloudflare_v6(egress_v6) if egress_v6 else False,
                "checking_egress": checking_egress,
                "rotating": is_keeper_paused(),
            },
            "services": {
                "keeper_running": _is_mutex_held("OpencodeUnlimitedKeeper"),
                "guard_running": _is_mutex_held("OpencodeUnlimitedGuard"),
                "keeper_task": _task_exists(TASK_KEEPER),
                "guard_task": _task_exists(TASK_GUARD),
                "proxy_listening": _port_open(SERVICE_PROXY_PORT),
                "proxy_port": SERVICE_PROXY_PORT,
                "firewall_installed": is_killswitch_installed(),
                "is_admin": is_admin(),
                "auto_resume": self._is_auto_resume_active(),
            },
            "lane": {
                "pinned_edge": pinned_edge,
                "edge_override": edge_override,
                "edge_pool": self._edge_pool,
                "strict_mode": (LANE_DIR / "strict_proxy.flag").is_file(),
                "cli_path": cli_path,
                "desktop_path": desktop_path,
                "path_wired": _user_path_has_bin(),
                "desktop_service_wired": svc_wired,
                "scripts_installed": (SCRIPTS_DIR / "warp_keeper.py").is_file(),
            },
            "stats": {
                "hops": int(guard_state.get("hops", 0) or 0),
                "blacklist_count": len(blacklist),
                "blacklist": list(reversed(blacklist)),
                "last_hop": int(guard_state.get("last_hop", 0) or 0),
                "db": _read_db_stats(),
                "log_size_bytes": log_size,
            },
            "logs": {
                "guard": _tail_lines(GUARD_LOG_FILE, 75),
                "keeper": _tail_lines(KEEPER_LOG_FILE, 75),
                "opencode": _tail_lines(OPENCODE_LOG_FILE, 55),
            },
            "egress": self._get_egress_state(),
        }

    def _get_egress_state(self) -> dict:
        try:
            from proxy_chain import get_egress_config
            from tor_manager import get_active_tor_target, is_portable_tor_running
            from clean_endpoint import KNOWN_CLEAN_ENDPOINTS
            cfg = get_egress_config()
            target = get_active_tor_target()
            from proxy_chain import get_current_custom_proxy
            cur_h, cur_p, cur_i, cur_total = get_current_custom_proxy()
            return {
                "mode": cfg.get("mode", "warp"),
                "warp_scope": cfg.get("warp_scope", "isolated"),
                "custom_proxy": cfg.get("custom_proxy", "127.0.0.1:10808"),
                "custom_type": cfg.get("custom_type", "socks5"),
                "custom_pool_count": cur_total,
                "custom_current_node": f"{cur_h}:{cur_p} (#{cur_i + 1}/{cur_total})",
                "tor_active": bool(target),
                "tor_target": f"{target[0]}:{target[1]}" if target else "Not running",
                "tor_running": is_portable_tor_running(),
                "clean_endpoints": list(KNOWN_CLEAN_ENDPOINTS),
            }
        except Exception as exc:
            return {"mode": "warp", "warp_scope": "isolated", "error": str(exc), "clean_endpoints": []}

    def set_warp_scope(self, scope: str) -> dict:
        from proxy_chain import get_egress_config, set_egress_config
        cfg = get_egress_config()
        clean_scope = "tun" if scope.lower().strip() == "tun" else "isolated"
        new_cfg = set_egress_config(
            mode=cfg.get("mode", "warp"),
            custom_proxy=cfg.get("custom_proxy", "127.0.0.1:10808"),
            custom_type=cfg.get("custom_type", "socks5"),
            warp_scope=clean_scope,
        )
        warp = find_warp_cli()
        if warp:
            if clean_scope == "isolated":
                run_warp(["proxy", "port", "40000"], warp_bin=warp)
                run_warp(["mode", "proxy"], warp_bin=warp)
            else:
                run_warp(["mode", "warp"], warp_bin=warp)
            run_warp(["connect"], warp_bin=warp)
        self._refresh_egress_async(force=True)
        label = "App-Only (Isolated Proxy)" if clean_scope == "isolated" else "Full System TUN"
        return {"ok": True, "scope": clean_scope, "message": f"WARP scope set to: {label}"}

    def set_egress_mode(self, mode: str, custom_proxy: str = "127.0.0.1:10808", custom_type: str = "socks5") -> dict:
        from proxy_chain import set_egress_config
        cfg = set_egress_config(mode, custom_proxy, custom_type)
        if mode == "tor":
            from tor_manager import get_active_tor_target, start_portable_tor
            if not get_active_tor_target():
                threading.Thread(target=start_portable_tor, daemon=True).start()
        return {"ok": True, "config": cfg, "message": f"Active egress switched to: {mode.upper()}"}

    def rotate_tor_circuit(self) -> dict:
        from tor_manager import rotate_tor_circuit
        ok, msg = rotate_tor_circuit()
        return {"ok": ok, "message": msg}

    def toggle_tor_service(self, enable: bool) -> dict:
        from tor_manager import start_portable_tor, stop_portable_tor
        ok, msg = start_portable_tor() if enable else stop_portable_tor()
        return {"ok": ok, "message": msg}

    def rotate_custom_proxy(self) -> dict:
        from proxy_chain import rotate_custom_proxy
        ok, msg = rotate_custom_proxy()
        return {"ok": ok, "message": msg}

    def set_clean_endpoint(self, endpoint: str) -> dict:
        from clean_endpoint import set_custom_endpoint
        ok, msg = set_custom_endpoint(endpoint)
        if ok:
            self._refresh_egress_async(force=True)
        return {"ok": ok, "message": msg}

    def reset_clean_endpoint(self) -> dict:
        from clean_endpoint import reset_custom_endpoint
        ok, msg = reset_custom_endpoint()
        if ok:
            self._refresh_egress_async(force=True)
        return {"ok": ok, "message": msg}

    def test_clean_endpoints(self, timeout: float = 1.2) -> dict:
        import concurrent.futures
        from clean_endpoint import KNOWN_CLEAN_ENDPOINTS, test_endpoint_latency

        def _check(ep: str) -> dict:
            lat = test_endpoint_latency(ep, timeout=timeout)
            return {"endpoint": ep, "latency": lat}

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            res = list(ex.map(_check, KNOWN_CLEAN_ENDPOINTS))
        return {"ok": True, "endpoints": res}

    def warp_connect(self) -> dict:
        warp = find_warp_cli()
        if not warp:
            return {"ok": False, "message": "warp-cli.exe not found."}
        scope = "isolated"
        try:
            from proxy_chain import get_egress_config
            scope = get_egress_config().get("warp_scope", "isolated")
        except Exception:
            pass

        run_warp(["registration", "new"], warp_bin=warp)
        if scope == "isolated":
            run_warp(["mode", "proxy"], warp_bin=warp)
            run_warp(["proxy", "port", "40000"], warp_bin=warp)
        else:
            run_warp(["mode", "warp"], warp_bin=warp)

        rc, msg = run_warp(["connect"], warp_bin=warp)
        for _ in range(8):
            time.sleep(1.0)
            conn, _, raw = warp_status(warp)
            if conn:
                self._refresh_egress_async(force=True)
                return {"ok": True, "message": f"WARP connected ({'App-Only proxy' if scope == 'isolated' else 'Full TUN'})."}
            if "unable" in raw.lower() or "mitm" in raw.lower():
                break

        # Auto-repair CF_HAPPY_EYEBALLS_MITM_FAILURE or broken endpoint
        run_warp(["disconnect"], warp_bin=warp)
        run_warp(["tunnel", "endpoint", "reset"], warp_bin=warp)
        run_warp(["registration", "delete"], warp_bin=warp)
        run_warp(["registration", "new"], warp_bin=warp)
        if scope == "isolated":
            run_warp(["mode", "proxy"], warp_bin=warp)
            run_warp(["proxy", "port", "40000"], warp_bin=warp)
        else:
            run_warp(["mode", "warp"], warp_bin=warp)
        run_warp(["connect"], warp_bin=warp)

        for _ in range(6):
            time.sleep(1.0)
            conn, _, _ = warp_status(warp)
            if conn:
                self._refresh_egress_async(force=True)
                return {"ok": True, "message": f"WARP auto-repaired and connected ({'App-Only proxy' if scope == 'isolated' else 'Full TUN'})."}

        return {"ok": False, "message": "WARP connect in progress; please refresh in a moment."}

    def warp_disconnect(self) -> dict:
        warp = find_warp_cli()
        if not warp:
            return {"ok": False, "message": "warp-cli.exe not found."}
        rc, msg = run_warp(["disconnect"], warp_bin=warp)
        with self._egress_lock:
            self._egress_v6 = ""
        return {"ok": rc == 0, "message": "WARP disconnected." if rc == 0 else msg}

    def hop_now(self) -> dict:
        if not self._action_lock.acquire(blocking=False):
            return {"ok": False, "message": "Another rotation or setup action is already running."}
        try:
            warp = find_warp_cli()
            if not warp:
                return {"ok": False, "message": "warp-cli.exe not found."}
            old_v6 = self._egress_v6 or (get_warp_local_v6() or "")
            with keeper_pause_ctx("avatar-ui-hop", seconds=180):
                new_v6 = hop_once(warp, max_reg_tries=5)
            if not new_v6:
                return {"ok": False, "message": "Rotation failed — keeper will retry automatically."}
            with self._egress_lock:
                self._egress_v6 = new_v6
                self._last_egress_ts = time.time()
            # Trigger edge re-roll on persistent proxy
            if (LANE_DIR / "edge_override.txt").is_file():
                ov = (LANE_DIR / "edge_override.txt").read_text(encoding="utf-8").strip().lower()
            else:
                ov = "auto"
            if ov == "auto":
                (LANE_DIR / "edge_reroll").write_text(str(time.time()), encoding="utf-8")
            # Record hop in state.json
            if GUARD_STATE_FILE.is_file():
                try:
                    st = json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8"))
                except Exception:
                    st = {}
            else:
                st = {}
            st["hops"] = int(st.get("hops", 0) or 0) + 1
            st["last_hop"] = int(time.time())
            st["current"] = new_v6
            GUARD_STATE_FILE.write_text(json.dumps(st), encoding="utf-8")
            old_p = normalize_v6_64(old_v6) or "?"
            new_p = normalize_v6_64(new_v6) or new_v6
            return {"ok": True, "message": f"Rotated /64: {old_p} -> {new_p}"}
        finally:
            self._action_lock.release()

    def toggle_worker(self, name: str, enable: bool) -> dict:
        if name not in ("keeper", "guard"):
            return {"ok": False, "message": "Unknown worker."}
        script_name = "warp_keeper.py" if name == "keeper" else "zen_guard.py"
        task_name = TASK_KEEPER if name == "keeper" else TASK_GUARD
        worker_flag = name

        if not enable:
            killed = 0
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    pname = (proc.info.get("name") or "").lower()
                    cmd = " ".join(proc.info.get("cmdline") or []).lower()
                    if pname in ("python.exe", "pythonw.exe") and script_name in cmd:
                        proc.kill()
                        killed += 1
                    elif f"--worker {worker_flag}" in cmd and proc.info["pid"] != os.getpid():
                        proc.kill()
                        killed += 1
                except Exception:
                    pass
            return {"ok": True, "message": f"Stopped {name} ({killed} process{'es' if killed != 1 else ''})."}

        _deploy_scripts_and_shims()
        if _task_exists(task_name):
            res = run_hidden(["schtasks", "/Run", "/TN", task_name], timeout=8.0)
            if res.returncode == 0:
                time.sleep(1.0)
                return {"ok": True, "message": f"Started {name} via Scheduled Task."}

        pyw = _find_pythonw()
        if pyw and (SCRIPTS_DIR / script_name).is_file():
            subprocess.Popen(
                [pyw, str(SCRIPTS_DIR / script_name)],
                creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                close_fds=True,
            )
            time.sleep(1.0)
            return {"ok": True, "message": f"Started {name} background daemon."}

        if getattr(sys, "frozen", False):
            subprocess.Popen(
                [sys.executable, "--worker", worker_flag],
                creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                close_fds=True,
            )
            time.sleep(1.0)
            return {"ok": True, "message": f"Started bundled {name} daemon."}

        return {"ok": False, "message": f"Could not launch {name}."}

    def toggle_desktop_service_proxy(self, enable: bool) -> dict:
        proxy_url = f"http://127.0.0.1:{SERVICE_PROXY_PORT}"
        cfg_file = Path.home() / ".config" / "opencode" / "service.json"

        # 1. If enabling, ensure keeper is running to host port 41987
        if enable:
            if not _port_open(SERVICE_PROXY_PORT):
                self.toggle_worker("keeper", True)
                for _ in range(12):
                    if _port_open(SERVICE_PROXY_PORT):
                        break
                    time.sleep(0.3)

        # 2. Update service.json directly in Python (100% reliable, zero CLI dependencies)
        try:
            cfg = {}
            if cfg_file.is_file():
                try:
                    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
                except Exception:
                    pass
            if not isinstance(cfg.get("env"), dict):
                cfg["env"] = {}

            if enable:
                for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
                    cfg["env"][k] = proxy_url
                for k in ("NO_PROXY", "no_proxy"):
                    cfg["env"][k] = "127.0.0.1,localhost,::1"
            else:
                for k in _SERVICE_ENV_KEYS:
                    cfg["env"].pop(k, None)
                if not cfg["env"]:
                    cfg.pop("env", None)

            cfg_file.parent.mkdir(parents=True, exist_ok=True)
            cfg_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        except Exception as exc:
            return {"ok": False, "message": f"Failed updating service.json: {exc}"}

        # 3. If opencode CLI is present, run official commands as well
        oc = find_opencode_cli()
        if oc:
            try:
                if enable:
                    run_hidden([oc, "service", "set", "env", "HTTPS_PROXY", proxy_url], timeout=4.0)
                    run_hidden([oc, "service", "set", "env", "HTTP_PROXY", proxy_url], timeout=4.0)
                    run_hidden([oc, "service", "set", "env", "NO_PROXY", "127.0.0.1,localhost,::1"], timeout=4.0)
                else:
                    for k in _SERVICE_ENV_KEYS:
                        run_hidden([oc, "service", "unset", "env", k], timeout=4.0)
                run_hidden([oc, "service", "restart"], timeout=5.0)
            except Exception:
                pass

        # 4. Kill active opencode-cli background daemons so OpenCode restarts them with fresh settings
        try:
            import psutil
            for p in psutil.process_iter(["name", "exe"]):
                try:
                    pname = (p.info["name"] or "").lower()
                    pexe = p.info["exe"] or ""
                    if "opencode-cli" in pname and BRAND not in pexe.lower():
                        p.kill()
                except Exception:
                    pass
        except Exception:
            pass

        return {
            "ok": True,
            "message": (
                f"OpenCode Desktop service wired to {proxy_url}."
                if enable
                else "OpenCode Desktop service restored to direct egress."
            ),
        }

    def toggle_autostart(self, enable: bool) -> dict:
        if not enable:
            for tn in (TASK_KEEPER, TASK_GUARD):
                run_hidden(["schtasks", "/Delete", "/TN", tn, "/F"], timeout=8.0)
            return {"ok": True, "message": "Removed logon Scheduled Tasks."}

        _deploy_scripts_and_shims()
        pyw = _find_pythonw()
        for tn, script_name, flag in (
            (TASK_KEEPER, "warp_keeper.py", "keeper"),
            (TASK_GUARD, "zen_guard.py", "guard"),
        ):
            if pyw and (SCRIPTS_DIR / script_name).is_file():
                exe, ps_arg = pyw, f"'\"{SCRIPTS_DIR / script_name}\"'"
            else:
                exe, ps_arg = sys.executable, f"'--worker {flag}'"
            ps = (
                f"$a=New-ScheduledTaskAction -Execute '{exe}' -Argument {ps_arg};"
                f"$t=New-ScheduledTaskTrigger -AtLogOn -User \"$env:USERDOMAIN\\$env:USERNAME\";"
                f"$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
                f"-StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 3 "
                f"-RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew;"
                f"Unregister-ScheduledTask -TaskName '{tn}' -Confirm:$false -ErrorAction SilentlyContinue;"
                f"Register-ScheduledTask -TaskName '{tn}' -Action $a -Trigger $t -Settings $s | Out-Null"
            )
            res = run_hidden(["powershell.exe", "-NoProfile", "-Command", ps], timeout=12.0)
            if res.returncode != 0:
                return {"ok": False, "message": f"Task registration failed: {res.stderr.strip()}"}
        return {"ok": True, "message": "Registered logon auto-start tasks for Keeper & Guard."}

    def toggle_firewall(self, enable: bool) -> dict:
        action = "install" if enable else "remove"
        if is_admin():
            ok, msg = install_killswitch() if enable else remove_killswitch()
            return {"ok": ok, "message": msg}

        py = shutil.which("python.exe")
        if py and "WindowsApps" not in py and (SCRIPTS_DIR / "ouc_firewall.py").is_file():
            exe, params = py, f'"{SCRIPTS_DIR / "ouc_firewall.py"}" {action}'
        else:
            exe, params = sys.executable, f"--firewall {action}"

        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 0)
        if rc <= 32:
            return {"ok": False, "message": "UAC prompt was declined or failed."}
        for _ in range(12):
            time.sleep(0.35)
            if is_killswitch_installed() == enable:
                break
        state_ok = is_killswitch_installed() == enable
        return {
            "ok": state_ok,
            "message": (
                "Firewall kill-switch rule OUC_LEAKGUARD_CLI installed."
                if enable and state_ok
                else "Firewall kill-switch rule removed."
                if not enable and state_ok
                else "Firewall update sent; refresh status in a moment."
            ),
        }

    def _is_auto_resume_active(self) -> bool:
        try:
            from auto_resume import is_auto_resume_enabled
            return is_auto_resume_enabled()
        except Exception:
            return True

    def toggle_auto_resume(self, enable: bool) -> dict:
        try:
            from auto_resume import set_auto_resume
            set_auto_resume(enable)
            return {
                "ok": True,
                "message": (
                    "Auto-resume enabled — OpenCode Unlimited will automatically send 'continue' when limits are bypassed."
                    if enable
                    else "Auto-resume disabled."
                ),
            }
        except Exception as exc:
            return {"ok": False, "message": f"Failed setting auto-resume: {exc}"}

    def toggle_strict_mode(self, enable: bool) -> dict:
        ensure_dirs()
        flag = LANE_DIR / "strict_proxy.flag"
        if enable:
            flag.write_text("1\n", encoding="utf-8")
            return {"ok": True, "message": "Strict fail-closed mode enabled (all requests require active WARP tunnel)."}
        flag.unlink(missing_ok=True)
        return {"ok": True, "message": "Resilient fallback mode enabled (automatic bypass prevents 503 errors if WARP drops)."}

    def auto_heal_endpoint(self) -> dict:
        try:
            from clean_endpoint import auto_heal_warp_endpoint
            ok, msg = auto_heal_warp_endpoint()
            if ok:
                self._refresh_egress_async(force=True)
            return {"ok": ok, "message": msg}
        except Exception as exc:
            return {"ok": False, "message": f"Auto-heal failed: {exc}"}

    def repair_warp_connection(self) -> dict:
        """Purges stale cryptographic keys, resets endpoint overrides, and auto-repairs MITM errors."""
        wb = find_warp_cli()
        if not wb:
            return {"ok": False, "message": "warp-cli.exe not found."}
        try:
            scope = "isolated"
            try:
                from proxy_chain import get_egress_config
                scope = get_egress_config().get("warp_scope", "isolated")
            except Exception:
                pass

            # Phase 1: Rapid key rotation and endpoint reset (preserves active client registration)
            run_warp(["tunnel", "endpoint", "reset"], warp_bin=wb)
            run_warp(["tunnel", "protocol", "set", "WireGuard"], warp_bin=wb)
            run_warp(["tunnel", "rotate-keys"], warp_bin=wb)
            if scope == "isolated":
                run_warp(["mode", "proxy"], warp_bin=wb)
                run_warp(["proxy", "port", "40000"], warp_bin=wb)
            else:
                run_warp(["mode", "warp"], warp_bin=wb)
            run_warp(["connect"], warp_bin=wb)

            for _ in range(3):
                time.sleep(1.0)
                conn, _, raw = warp_status(wb)
                raw_low = raw.lower()
                if conn and "unstable" not in raw_low and "mitm" not in raw_low and "unable" not in raw_low:
                    self._refresh_egress_async(force=True)
                    return {"ok": True, "message": f"WARP encryption keys rotated successfully. Connected ({'App-Only proxy' if scope == 'isolated' else 'TUN'})!"}

            # Phase 2: Full re-registration if key rotation alone did not resolve the handshake block
            run_warp(["disconnect"], warp_bin=wb)
            run_warp(["registration", "delete"], warp_bin=wb)
            run_warp(["registration", "new"], warp_bin=wb)
            run_warp(["tunnel", "protocol", "set", "WireGuard"], warp_bin=wb)
            if scope == "isolated":
                run_warp(["mode", "proxy"], warp_bin=wb)
                run_warp(["proxy", "port", "40000"], warp_bin=wb)
            else:
                run_warp(["mode", "warp"], warp_bin=wb)
            run_warp(["connect"], warp_bin=wb)

            for _ in range(6):
                time.sleep(1.0)
                conn, _, _ = warp_status(wb)
                if conn:
                    self._refresh_egress_async(force=True)
                    return {"ok": True, "message": f"WARP keys & endpoints reset successfully. Connected ({'App-Only proxy' if scope == 'isolated' else 'TUN'})!"}

            return {"ok": True, "message": "WARP reset executed. Reconnecting in background..."}
        except Exception as exc:
            return {"ok": False, "message": f"Repair failed: {exc}"}

    def reroll_edge(self) -> dict:
        ensure_dirs()
        (LANE_DIR / "edge_override.txt").write_text("auto\n", encoding="utf-8")
        (LANE_DIR / "edge_reroll").write_text(str(time.time()), encoding="utf-8")
        time.sleep(1.7)
        edge = ""
        if (LANE_DIR / "last_edge.txt").is_file():
            edge = (LANE_DIR / "last_edge.txt").read_text(encoding="utf-8").strip()
        return {"ok": True, "message": f"Re-rolled Cloudflare edge: {edge or 'pending next request'}"}

    def set_edge_override(self, edge: str) -> dict:
        ensure_dirs()
        clean = edge.strip() or "auto"
        (LANE_DIR / "edge_override.txt").write_text(clean + "\n", encoding="utf-8")
        time.sleep(1.6)
        return {"ok": True, "message": f"Edge pinning set to: {clean}"}

    def refresh_edge_pool(self) -> dict:
        pool = fetch_opencode_aaaa_pool()
        self._edge_pool = pool
        return {"ok": True, "pool": pool, "message": f"Found {len(pool)} live opencode.ai IPv6 edges."}

    def deep_reset_identity(self) -> dict:
        """Deep clean transient caches & rotate network identity without touching user chats/sessions."""
        import shutil, tempfile

        cleared: list[str] = []

        # Clear transient client caches only (never touch opencode.db or user chat sessions!)
        base_dir = Path.home() / ".local" / "share" / "opencode"
        if base_dir.is_dir():
            for item_name in ("storage", "olliecode-fingerprint.json"):
                target = base_dir / item_name
                if target.is_file():
                    try:
                        target.unlink(missing_ok=True)
                        cleared.append(item_name)
                    except Exception:
                        pass
                elif target.is_dir():
                    try:
                        shutil.rmtree(target, ignore_errors=True)
                        cleared.append(item_name)
                    except Exception:
                        pass

        for extra_cache in [
            Path.home() / ".cache" / "opencode",
            Path.home() / ".local" / "state" / "opencode",
            Path(os.environ.get("LOCALAPPDATA", "")) / "opencode" / "cache" if os.environ.get("LOCALAPPDATA") else None,
            Path(tempfile.gettempdir()) / "opencode",
        ]:
            if extra_cache and extra_cache.is_dir():
                try:
                    shutil.rmtree(extra_cache, ignore_errors=True)
                    cleared.append(extra_cache.name)
                except Exception:
                    pass

        # Clear guard blacklist and reset edge override
        self.clear_blacklist()
        self.set_edge_override("auto")
        self.repair_warp_connection()

        rot_msg = ""
        try:
            from proxy_chain import get_egress_config
            mode = get_egress_config().get("mode", "warp")
            if mode == "tor":
                from tor_manager import rotate_tor_circuit
                _, rot_msg = rotate_tor_circuit()
            elif mode == "custom":
                from proxy_chain import rotate_custom_proxy
                _, rot_msg = rotate_custom_proxy()
            else:
                from ouc_common import find_warp_cli, hop_once
                wbin = find_warp_cli()
                if wbin:
                    new_ip = hop_once(wbin)
                    rot_msg = f"Rotated WARP IP: {new_ip}" if new_ip else "WARP reconnected"
        except Exception as exc:
            rot_msg = f"Rotation note: {exc}"

        return {
            "ok": True,
            "message": f"Deep reset complete. Cleared cache: {', '.join(cleared) or 'clean'}. Sessions preserved. {rot_msg}",
        }

    def clear_blacklist(self) -> dict:
        if not GUARD_STATE_FILE.is_file():
            return {"ok": True, "message": "Blacklist already empty."}
        try:
            st = json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            st = {}
        st["blacklist"] = []
        GUARD_STATE_FILE.write_text(json.dumps(st), encoding="utf-8")
        return {"ok": True, "message": "Cleared /64 blacklist."}

    def launch_desktop(self) -> dict:
        desktop = find_opencode_desktop()
        if not desktop:
            return {"ok": False, "message": "OpenCode.exe Desktop app not found."}

        # Clean up any orphaned/zombie opencode-cli.exe daemon processes that hold stale ports (e.g. 42914)
        try:
            import psutil
            desktop_running = any("opencode.exe" in p.name().lower() for p in psutil.process_iter(["name"]))
            if not desktop_running:
                for p in psutil.process_iter(["name"]):
                    if "opencode-cli" in p.name().lower():
                        try:
                            p.terminate()
                        except Exception:
                            pass
            # Free port 42914 if held by stale daemon to prevent "Managed service port 42914 is already in use" IPC crash
            for conn in psutil.net_connections(kind="tcp"):
                if conn.laddr and conn.laddr.port == 42914 and conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        p.terminate()
                    except Exception:
                        pass
        except Exception:
            pass

        if not _port_open(SERVICE_PROXY_PORT):
            self.toggle_worker("keeper", True)
        svc_cfg = Path.home() / ".config" / "opencode" / "service.json"
        already_wired = False
        if svc_cfg.is_file():
            try:
                cfg = json.loads(svc_cfg.read_text(encoding="utf-8"))
                env_map = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
                already_wired = f"127.0.0.1:{SERVICE_PROXY_PORT}" in str(env_map.get("HTTPS_PROXY", ""))
            except Exception:
                pass
        if not already_wired:
            self.toggle_desktop_service_proxy(True)
        env = os.environ.copy()
        proxy_url = f"http://127.0.0.1:{SERVICE_PROXY_PORT}"
        env["HTTPS_PROXY"] = proxy_url
        env["HTTP_PROXY"] = proxy_url
        env["NO_PROXY"] = "127.0.0.1,localhost,::1"
        subprocess.Popen(
            [
                desktop,
                f"--proxy-server={proxy_url}",
                "--proxy-bypass-list=<-loopback>;127.0.0.1;localhost;::1;*.local",
            ],
            env=env,
            close_fds=True,
        )
        return {"ok": True, "message": "Launched OpenCode Desktop through WARP IPv6 lane."}

    def fix_opencode_service(self) -> dict:
        """Terminate orphaned daemons, unblock busy service ports, and restart clean."""
        killed = 0
        try:
            import psutil
            for p in psutil.process_iter(["name"]):
                name = p.name().lower()
                if "opencode-cli" in name or "opencode.exe" in name:
                    try:
                        p.kill()
                        killed += 1
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            import psutil
            for conn in psutil.net_connections(kind="tcp"):
                if conn.laddr and conn.laddr.port == 42914 and conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        p.kill()
                        killed += 1
                    except Exception:
                        pass
        except Exception:
            pass

        # Stop service via CLI if installed
        cli = find_opencode_cli()
        if cli:
            try:
                subprocess.run([cli, "service", "stop"], capture_output=True, timeout=5.0)
            except Exception:
                pass

        # Reset service.json proxy env to ensure clean state
        self.toggle_desktop_service_proxy(True)
        return {"ok": True, "message": f"Service ports unblocked (terminated {killed} stale processes). Ready to launch!"}

    def launch_cli(self) -> dict:
        _deploy_scripts_and_shims()
        shim = BIN_DIR / "opencode.cmd"
        if not shim.is_file():
            return {"ok": False, "message": "opencode CLI shim not ready; run Install / Repair first."}
        wt = shutil.which("wt.exe")
        if wt:
            subprocess.Popen([wt, "cmd.exe", "/k", str(shim)], close_fds=True)
        else:
            subprocess.Popen(
                ["cmd.exe", "/c", "start", "OpenCode Unlimited CLI", "cmd.exe", "/k", str(shim)],
                shell=False,
                close_fds=True,
            )
        return {"ok": True, "message": "Opened OpenCode CLI terminal via Zen Lane."}

    def install_or_repair(self) -> dict:
        if not self._action_lock.acquire(blocking=False):
            return {"ok": False, "message": "Another setup action is in progress."}
        try:
            if not find_warp_cli():
                return {"ok": False, "message": "Cloudflare WARP (warp-cli.exe) not found. Install WARP from https://1.1.1.1/ or run install.bat first."}
            if not find_opencode_cli():
                return {"ok": False, "message": "OpenCode CLI not found. Install OpenCode from https://opencode.ai or run install.bat first."}
            _deploy_scripts_and_shims()
            _update_user_path(True)
            self.toggle_autostart(True)
            self.toggle_worker("keeper", True)
            self.toggle_worker("guard", True)
            self.warp_connect()
            self.toggle_desktop_service_proxy(True)
            self._refresh_egress_async(force=True)
            return {"ok": True, "message": "Installed/repaired shims, PATH, tasks, WARP TUN, and Desktop service."}
        finally:
            self._action_lock.release()

    def uninstall_all(self) -> dict:
        if not self._action_lock.acquire(blocking=False):
            return {"ok": False, "message": "Another setup action is in progress."}
        try:
            self.toggle_autostart(False)
            self.toggle_worker("guard", False)
            self.toggle_worker("keeper", False)
            self.toggle_desktop_service_proxy(False)
            if is_killswitch_installed():
                self.toggle_firewall(False)
            _update_user_path(False)
            warp = find_warp_cli()
            if warp:
                run_warp(["disconnect"], warp_bin=warp)
            if DEST_DIR.is_dir():
                shutil.rmtree(DEST_DIR, ignore_errors=True)
            with self._egress_lock:
                self._egress_v6 = ""
            return {"ok": True, "message": "Uninstalled background tasks, shims, proxy overrides, and state."}
        finally:
            self._action_lock.release()

    def open_logs_folder(self) -> dict:
        ensure_dirs()
        os.startfile(str(DEST_DIR))  # type: ignore[attr-defined]
        return {"ok": True, "message": f"Opened {DEST_DIR}"}

    def copy_text(self, text: str) -> dict:
        try:
            subprocess.run(["clip.exe"], input=text, text=True, creationflags=CREATE_NO_WINDOW, timeout=3.0)
            return {"ok": True, "message": f"Copied: {text}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def open_external_url(self, url: str) -> dict:
        try:
            webbrowser.open(url)
            return {"ok": True, "url": url}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}


def _attach_parent_console() -> None:
    try:
        if ctypes.windll.kernel32.AttachConsole(-1):
            sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
            sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
    except Exception:
        pass


def _run_cli_mode(argv: list[str]) -> int | None:
    if len(argv) >= 2 and argv[0] == "--worker":
        role = argv[1].lower()
        if role == "keeper":
            import warp_keeper
            return warp_keeper.main()
        if role == "guard":
            import zen_guard
            return zen_guard.main()
    if len(argv) >= 2 and argv[0] == "--firewall":
        ok, msg = install_killswitch() if argv[1] == "install" else remove_killswitch()
        print(msg)
        return 0 if ok else 1
    if argv and argv[0] == "--lane":
        _attach_parent_console()
        import zen_lane
        sys.argv = ["zen_lane.py", *argv[1:]]
        return zen_lane.main()
    if argv and argv[0] == "--hop":
        _attach_parent_console()
        import zen_hop
        return zen_hop.main()
    if argv and argv[0] == "--doctor":
        _attach_parent_console()
        import doctor
        return doctor.main()
    return None


def _is_webview2_available() -> bool:
    """Check registry for installed Microsoft Edge WebView2 Runtime or Edge Canary/Beta/Dev."""
    try:
        import winreg
        keys = (
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"),
        )
        for hive, subkey in keys:
            try:
                with winreg.OpenKey(hive, subkey) as k:
                    val, _ = winreg.QueryValueEx(k, "pv")
                    if val and str(val).strip() not in ("0.0.0.0", "0"):
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _prompt_webview2_install() -> None:
    """Prompt user to download official Microsoft Edge WebView2 runtime if missing."""
    import webbrowser
    MB_YESNO = 0x00000004
    MB_ICONEXCLAMATION = 0x00000030
    IDYES = 6
    msg = (
        "Microsoft Edge WebView2 Runtime is required to run the Opencode Unlimited UI.\n\n"
        "It was not detected on this Windows installation (this commonly occurs on "
        "older Windows 10 versions or stripped/lite/gaming Windows editions).\n\n"
        "Would you like to open the official Microsoft WebView2 installer download page now?"
    )
    ans = ctypes.windll.user32.MessageBoxW(
        None,
        msg,
        "Opencode Unlimited — WebView2 Required",
        MB_YESNO | MB_ICONEXCLAMATION,
    )
    if ans == IDYES:
        webbrowser.open("https://go.microsoft.com/fwlink/p/?LinkId=2124703")


def _load_ui_html() -> str:
    """Load index.html from bundle or adjacent filesystem paths."""
    candidates = (
        _BUNDLE / "src" / "ui" / "index.html",
        _BUNDLE / "windows" / "ui" / "index.html",
        _BUNDLE / "ui" / "index.html",
        Path(__file__).resolve().parent / "ui" / "index.html",
        Path(__file__).resolve().parent / "src" / "ui" / "index.html",
        Path(__file__).resolve().parent / "windows" / "ui" / "index.html",
        DEST_DIR / "ui" / "index.html",
    )
    for p in candidates:
        if p.is_file():
            try:
                txt = p.read_text(encoding="utf-8")
                if txt.strip():
                    return txt
            except Exception:
                pass
    raise FileNotFoundError("Could not find index.html in application bundle or local folders.")


def _log_startup_error(exc: Exception) -> None:
    """Log startup exceptions to disk and present an informative dialog."""
    import traceback
    err_text = traceback.format_exc()
    try:
        log_dir = DEST_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "avatar_ui_error.log").write_text(err_text, encoding="utf-8")
    except Exception:
        pass
    MB_OK = 0x00000000
    MB_ICONERROR = 0x00000010
    ctypes.windll.user32.MessageBoxW(
        None,
        f"Failed to initialize Opencode Unlimited UI:\n\n{exc}\n\n"
        f"Details have been written to:\n{DEST_DIR}\\logs\\avatar_ui_error.log",
        "Opencode Unlimited — Startup Error",
        MB_OK | MB_ICONERROR,
    )


def _kill_previous_instances() -> int:
    """Terminate any lingering previous versions of Opencode Unlimited or orphaned background workers."""
    current_pid = os.getpid()
    count = 0
    try:
        import psutil
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = p.info["pid"]
                if pid == current_pid:
                    continue
                name = (p.info["name"] or "").lower()
                cmd = " ".join(p.info.get("cmdline") or []).lower()
                # Terminate any duplicate/old OpencodeUnlimited executable
                if "opencodeunlimited" in name:
                    p.kill()
                    count += 1
                # Terminate any orphaned python process running old keeper/guard/ui scripts
                elif "python" in name and any(x in cmd for x in ("warp_keeper.py", "zen_guard.py", "avatar_ui.py")):
                    p.kill()
                    count += 1
            except Exception:
                pass
        if count > 0:
            time.sleep(0.4)
    except Exception:
        pass
    return count


def main() -> int:
    cli_rc = _run_cli_mode(sys.argv[1:])
    if cli_rc is not None:
        return cli_rc

    # Auto-kill previous versions or orphaned background tasks so only one clean instance runs
    _kill_previous_instances()

    # Guarantee local proxy on 41987 is immediately active
    if not _port_open(SERVICE_PROXY_PORT):
        try:
            from zen_proxy import start_proxy_server
            start_proxy_server(SERVICE_PROXY_PORT)
        except Exception:
            pass

    existing = ctypes.windll.user32.FindWindowW(None, WINDOW_TITLE)
    if existing:
        ctypes.windll.user32.ShowWindow(ctypes.c_void_p(existing), 9)  # SW_RESTORE
        ctypes.windll.user32.SetForegroundWindow(ctypes.c_void_p(existing))
        return 0

    if not _is_webview2_available():
        _prompt_webview2_install()
        return 1

    try:
        html_content = _load_ui_html()
    except Exception as exc:
        _log_startup_error(exc)
        return 1

    ico_path = Path()
    for candidate_ico in (
        _BUNDLE / "src" / "assets" / "avatar.ico",
        _BUNDLE / "windows" / "assets" / "avatar.ico",
        _BUNDLE / "assets" / "avatar.ico",
        Path(__file__).resolve().parent / "assets" / "avatar.ico",
    ):
        if candidate_ico.is_file():
            ico_path = candidate_ico
            break

    cache_dir = DEST_DIR / "webview_cache"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    api = AvatarControlApi()
    window = webview.create_window(
        WINDOW_TITLE,
        html=html_content,
        js_api=api,
        width=1180,
        height=790,
        min_size=(980, 680),
        background_color="#070b14",
        text_select=True,
    )
    window.events.shown += _enable_dark_titlebar
    start_kwargs: dict = {
        "gui": "edgechromium",
        "debug": False,
        "storage_path": str(cache_dir),
        "private_mode": False,
    }
    if ico_path.is_file():
        start_kwargs["icon"] = str(ico_path)

    try:
        webview.start(**start_kwargs)
    except Exception as exc:
        _log_startup_error(exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
