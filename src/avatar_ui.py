"""Opencode Unlimited - Control Center GUI (Made by Avatar)."""

from __future__ import annotations

import ctypes
import datetime
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
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
    append_log,
    ensure_dirs,
    ensure_warp_mode,
    fetch_opencode_aaaa_pool,
    find_opencode_cli,
    find_opencode_desktop,
    find_warp_cli,
    get_egress_ip,
    get_warp_local_v6,
    hop_report,
    is_admin,
    is_cloudflare_v6,
    is_keeper_paused,
    is_mutex_held,
    keeper_pause_ctx,
    normalize_v6_64,
    opencode_command,
    repair_warp_registration,
    run_hidden,
    run_warp,
    service_proxy_wired,
    task_enabled,
    task_exists,
    warp_registration_healthy,
    warp_status,
)
from ouc_firewall import install_killswitch, is_killswitch_installed, remove_killswitch

WINDOW_TITLE = "Opencode Unlimited v4.0 - Made by Avatar"
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
    "auto_resume.py",
    "account_pool.py",
    "desktop_brand.py",
    "ouc_watchdog.py",
)
_SERVICE_ENV_KEYS = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "https_proxy",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
)
# A real request through the local proxy is the only check that proves traffic
# gets in and out; a listening port alone can hide a dead tunnel.
PROBE_URL = "https://opencode.ai/"
PROBE_DIRECT_URL = "https://cloudflare.com/cdn-cgi/trace"
PROBE_EVERY = 120.0
PROBE_TIMEOUT = 8.0
HEARTBEAT_STALE = 240.0

# Auto-repair only touches connectivity, never the user's selected route or
# OpenCode itself. Cooldowns keep a permanent outage from becoming a loop.
AUTO_REPAIR_FILE = LANE_DIR / "auto_repair.json"
AUTO_REPAIR_LOG = LANE_DIR / "auto_repair.log"
AUTO_REPAIR_TICK = 25.0
AUTO_REPAIR_MAX_PER_HOUR = 6
AUTO_REPAIR_COOLDOWNS = {
    "start_keeper": 120.0,
    "restart_keeper": 600.0,
    "connect_warp": 180.0,
    "hop": 300.0,
    "repair_warp": 900.0,
}


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


def clear_opencode_free_limit() -> int:
    """Delete client-side free-limit and go-upsell lockout rows from drafts.sqlite."""
    try:
        from auto_resume import clear_opencode_free_limit as clear

        return clear()
    except Exception:
        return 0


_BRAND_CACHE: tuple[float, dict] = (0.0, {})
# Reading an archive is not free; the answer changes about once per app update,
# so the health panel holds it for five minutes instead of re-reading on every
# refresh. A press of Apply clears it immediately.
BRAND_CACHE_SECONDS = 300.0


def _desktop_brand_state() -> dict:
    """The desktop copy patch, cached: reading an archive on every refresh is noise."""
    global _BRAND_CACHE
    stamp, cached = _BRAND_CACHE
    if cached and time.time() - stamp < BRAND_CACHE_SECONDS:
        return cached
    try:
        import desktop_brand

        state = desktop_brand.copy_status()
    except Exception:
        state = {}
    _BRAND_CACHE = (time.time(), state)
    return state


def _forget_desktop_brand() -> None:
    global _BRAND_CACHE
    _BRAND_CACHE = (0.0, {})


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.6):
            return True
    except OSError:
        return False


def _heartbeat_age(path: Path) -> float | None:
    """Seconds since the worker last wrote its heartbeat, or None if it never did."""
    try:
        return max(0.0, time.time() - path.stat().st_mtime)
    except OSError:
        return None


def _probe_http(url: str, proxy: str | None, timeout: float = PROBE_TIMEOUT) -> tuple[bool, str]:
    """Make one real HTTPS request. Returns (reached, stage).

    Explicit inference overload proves reachability, unlike a generic gateway
    failure. Stage is one of: ok, overloaded, proxy, timeout, upstream.
    """
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "opencode-unlimited-probe/4.0",
            "Cache-Control": "no-cache",
            "Accept": "*/*",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            resp.read(64)
        return True, "ok"
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(4096).decode("utf-8", errors="replace")
            if exc.code in (429, 503) and _OVERLOAD_RE.search(body):
                return True, "overloaded"
        except Exception:
            pass
        finally:
            exc.close()
        return (False, "upstream") if exc.code in (407, 502, 503, 504) else (True, "ok")
    except Exception as exc:
        text = str(getattr(exc, "reason", exc)).lower()
        if "connection refused" in text or "errno 10061" in text or "actively refused" in text:
            return False, "proxy"
        if "timed out" in text or "timeout" in text:
            return False, "timeout"
        return False, "upstream"


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


# EPIPE is deliberately absent: OpenCode reports a closed stdout/stderr pipe as
# "Error: EPIPE: broken pipe, write" with role=cli, which is local and must not
# raise the network banner. Upstream write failures still carry fetch failed,
# UND_ERR_*, or ECONNRESET.
_NET_ERROR_RE = re.compile(
    r"ECONNRESET|ECONNREFUSED|ECONNABORTED|ETIMEDOUT|ENETUNREACH|"
    r"EHOSTUNREACH|ENOTFOUND|EAI_AGAIN|CF_HAPPY_EYEBALLS|UND_ERR_|"
    r"Transport error|fetch failed",
    re.IGNORECASE,
)
_UPSTREAM_503_RE = re.compile(
    r"statusCode[=:\s]+503|Request failed with status 503",
    re.IGNORECASE,
)
_OVERLOAD_RE = re.compile(r"inference service is overloaded", re.IGNORECASE)
_LOG_TS_RE = re.compile(r"^timestamp=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")


def _recent_network_errors(lines: list[str], max_age: float = 600.0) -> list[str]:
    """Upstream connection failures OpenCode logged in the last few minutes.

    OpenCode's own ``http.status=503`` replies are not upstream failures, so
    the match list is limited to transport errors and provider 503s.
    """
    return _recent_matching_errors(
        [line for line in lines if not _OVERLOAD_RE.search(line)],
        re.compile(f"{_NET_ERROR_RE.pattern}|{_UPSTREAM_503_RE.pattern}", re.IGNORECASE),
        max_age,
    )


def _recent_overload_errors(lines: list[str], max_age: float = 600.0) -> list[str]:
    return _recent_matching_errors(lines, _OVERLOAD_RE, max_age)


def _recent_matching_errors(lines: list[str], pattern: re.Pattern, max_age: float) -> list[str]:
    cutoff = time.time() - max_age
    found: list[str] = []
    for line in lines:
        if not pattern.search(line):
            continue
        stamp = _LOG_TS_RE.match(line)
        if not stamp:
            continue
        try:
            when = datetime.datetime.strptime(
                stamp.group(1), "%Y-%m-%dT%H:%M:%S"
            ).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
        if when.timestamp() < cutoff:
            continue
        text = _LOG_TS_RE.sub("", line).replace("\\n", " ").strip()
        for marker in ("level=ERROR ", "level=WARN "):
            if text.startswith(marker):
                text = text[len(marker):]
                break
        found.append(text[:260])
    return found[-3:]


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


def _is_ascii(text: str) -> bool:
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        return False
    return True


def _write_cmd_wrapper(path: Path, content: str) -> None:
    """Write a .cmd shim, switching to UTF-8 when a path holds non-ASCII text.

    cmd.exe reads batch files in the active console code page, so a shim whose
    content or install path holds non-ASCII text needs ``chcp 65001`` before the
    first non-ASCII line. ASCII shims keep the plain fast path and leave the
    console code page alone.
    """
    if _is_ascii(content) and _is_ascii(str(path)):
        path.write_bytes(content.encode("ascii"))
        return

    lines = content.split("\r\n")
    if lines and lines[0].lower().startswith("@echo off"):
        lines.insert(1, "chcp 65001 >nul")
    path.write_bytes("\r\n".join(lines).encode("utf-8"))


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
            _write_cmd_wrapper(BIN_DIR / name, content)
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
            _write_cmd_wrapper(BIN_DIR / name, content)

    return {"scripts_dir": str(SCRIPTS_DIR), "bin_dir": str(BIN_DIR)}


def _stop_worker_processes(name: str) -> tuple[int, str]:
    """Stop the running keeper/guard process without touching tasks or service settings."""
    script_name = "warp_keeper.py" if name == "keeper" else "zen_guard.py"
    me = os.getpid()
    targets = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if proc.info["pid"] == me:
                continue
            pname = (proc.info.get("name") or "").lower()
            cmd = " ".join(proc.info.get("cmdline") or []).lower()
            if pname in ("python.exe", "pythonw.exe") and script_name in cmd:
                targets.append(proc)
            elif f"--worker {name}" in cmd:
                targets.append(proc)
        except Exception:
            pass

    killed = 0
    errors: list[str] = []
    for proc in targets:
        try:
            proc.kill()
            proc.wait(timeout=3.0)
            killed += 1
        except psutil.NoSuchProcess:
            killed += 1
        except psutil.AccessDenied:
            errors.append(f"permission denied for PID {proc.pid}")
        except Exception as exc:
            errors.append(f"PID {proc.pid}: {exc}")
    return killed, "; ".join(errors[:3])


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
        self._probe_lock = threading.Lock()
        self._probe: dict = {"ok": None, "code": "unknown", "ms": 0, "ts": 0}
        self._probe_checking = False
        self._probe_ts = 0.0
        self._repair_lock = threading.Lock()
        self._repair_last: dict[str, float] = {}
        self._repair_actions: list[dict] = []
        self._repair_status = "Watching for connection problems"
        self._repair_enabled = self._load_repair_setting()
        self._refresh_egress_async(force=True)
        self._refresh_pool_async()
        self._refresh_probe_async(force=True)
        self._auto_heal_warp_startup()
        threading.Thread(target=self._auto_repair_loop, daemon=True).start()

    def _load_repair_setting(self) -> bool:
        try:
            data = json.loads(AUTO_REPAIR_FILE.read_text(encoding="utf-8"))
            return bool(data.get("enabled", True))
        except Exception:
            return True

    def _save_repair_setting(self, enabled: bool) -> None:
        try:
            tmp = AUTO_REPAIR_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps({"enabled": enabled}), encoding="utf-8")
            tmp.replace(AUTO_REPAIR_FILE)
        except Exception:
            pass

    def _auto_repair_loop(self) -> None:
        # Let startup checks settle before watching; the first pass is cheap.
        time.sleep(20.0)
        while True:
            try:
                if self._repair_enabled:
                    self._auto_repair_tick()
            except Exception as exc:
                self._repair_status = f"Auto-repair hit an internal error: {exc}"
            time.sleep(AUTO_REPAIR_TICK)

    def _auto_repair_tick(self) -> None:
        now = time.monotonic()
        with self._repair_lock:
            recent = [a for a in self._repair_actions if now - a["mono"] < 3600.0]
            if len(recent) >= AUTO_REPAIR_MAX_PER_HOUR:
                self._repair_status = (
                    "Several repairs did not restore the route. Check the Connection tab; "
                    "auto-repair will try again later."
                )
                return

        if self._action_lock.locked():
            return  # a user action or rotation is running

        state = self.get_state()
        services = state["services"]
        warp = state["warp"]
        proxy = state.get("proxy") or {}
        probe = state.get("probe") or {}
        mode = state["egress"].get("mode", "warp")
        wired = state["lane"]["desktop_service_wired"] or state["lane"]["path_wired"]

        action = ""
        reason = ""
        keeper_allowed = services["keeper_running"] or task_enabled(TASK_KEEPER)
        if wired and not services["proxy_listening"] and keeper_allowed:
            action, reason = "start_keeper", "OpenCode is wired to the local proxy but it stopped"
        elif services["keeper_running"] and services["keeper_heartbeat"] is not None and services["keeper_heartbeat"] > HEARTBEAT_STALE:
            action, reason = "restart_keeper", "The background service stopped responding"
        elif mode in ("warp", "clean") and not warp["connected"] and not warp["rotating"]:
            action, reason = "connect_warp", "WARP is disconnected"
        elif mode in ("warp", "clean") and services["proxy_listening"] and not warp["rotating"]:
            code = probe.get("code", "")
            failing = proxy.get("fallback_active") or code in ("upstream", "timeout")
            if failing:
                last_hop = self._repair_last.get("hop", 0.0)
                if proxy.get("fallback_active") and now - last_hop > 600.0 and proxy.get("errors_5m", 0) >= 4:
                    action, reason = "repair_warp", "The tunnel kept failing after an edge change"
                else:
                    action, reason = "hop", "The local proxy could not reach opencode.ai"
        if not action:
            self._repair_status = "Watching for connection problems"
            return

        with self._repair_lock:
            last = self._repair_last.get(action, 0.0)
            if now - last < AUTO_REPAIR_COOLDOWNS.get(action, 300.0):
                return
            self._repair_last[action] = now

        self._repair_status = f"Repairing: {reason.lower()}..."
        result = self._run_repair_action(action)
        entry = {
            "ts": int(time.time()),
            "mono": time.monotonic(),
            "action": action,
            "reason": reason,
            "ok": bool(result.get("ok")),
            "message": str(result.get("message", ""))[:240],
        }
        with self._repair_lock:
            self._repair_actions = (self._repair_actions + [entry])[-20:]
        append_log(AUTO_REPAIR_LOG, f"{'ok' if entry['ok'] else 'failed'} {action}: {entry['message']}")
        self._repair_status = (
            f"Repaired: {reason}." if entry["ok"] else f"Could not repair automatically: {entry['message']}"
        )

    def _run_repair_action(self, action: str) -> dict:
        if action == "start_keeper":
            return self.fix_issue("start_keeper")
        if action == "restart_keeper":
            _stop_worker_processes("keeper")
            time.sleep(1.0)
            return self.toggle_worker("keeper", True)
        if action == "connect_warp":
            return self.warp_connect()
        if action == "hop":
            return self.hop_now()
        if action == "repair_warp":
            return self.repair_warp_connection()
        return {"ok": False, "message": f"Unknown repair action: {action}"}

    def get_auto_repair(self) -> dict:
        with self._repair_lock:
            actions = list(self._repair_actions[-6:])
        return {
            "enabled": self._repair_enabled,
            "status": self._repair_status,
            "actions": list(reversed(actions)),
            "max_per_hour": AUTO_REPAIR_MAX_PER_HOUR,
        }

    def toggle_auto_repair(self, enable: bool) -> dict:
        self._repair_enabled = bool(enable)
        self._save_repair_setting(self._repair_enabled)
        if not self._repair_enabled:
            self._repair_status = "Auto-repair is off"
        else:
            self._repair_status = "Watching for connection problems"
        return {
            "ok": True,
            "message": "Auto-repair is on. It only reconnects the proxy and route; your settings stay as chosen."
            if self._repair_enabled
            else "Auto-repair is off.",
        }

    def _auto_heal_warp_startup(self) -> None:
        def _check_and_heal() -> None:
            time.sleep(3.0)
            wb = find_warp_cli()
            if not wb:
                return
            try:
                conn, mode, raw = warp_status(wb)
                raw_lower = raw.lower()
                # Only auto-heal on an explicit handshake MITM or cryptographic failure.
                # A disconnected startup state alone does not justify deleting the registration.
                if ("mitm" in raw_lower) or ("cf_happy_eyeballs" in raw_lower):
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
                ip = get_egress_ip(timeout=6.0)
                with self._egress_lock:
                    self._egress_v6 = ip
                    self._last_egress_ts = time.time()
            finally:
                with self._egress_lock:
                    self._egress_checking = False

        threading.Thread(target=_run, daemon=True).start()

    def _refresh_probe_async(self, force: bool = False) -> None:
        """Ask opencode.ai through the local proxy whether traffic really gets in and out."""
        with self._probe_lock:
            if self._probe_checking:
                return
            # After a failure retry sooner (30 s), but don't hammer while the tunnel is fine (120 s).
            limit = 30.0 if self._probe.get("ok") is False else PROBE_EVERY
            if not force and (time.time() - self._probe_ts) < limit:
                return
            self._probe_checking = True

        def _run() -> None:
            started = time.time()
            code = "unknown"
            try:
                # On startup the keeper may still be binding the port: give it a few seconds.
                for _ in range(24):
                    if _port_open(SERVICE_PROXY_PORT):
                        break
                    time.sleep(0.25)
                proxy = f"http://127.0.0.1:{SERVICE_PROXY_PORT}"
                if not _port_open(SERVICE_PROXY_PORT):
                    code = "proxy_down"
                else:
                    reached, stage = _probe_http(PROBE_URL, proxy)
                    if reached:
                        code = stage
                    else:
                        direct_ok, _ = _probe_http(PROBE_DIRECT_URL, None, timeout=5.0)
                        code = stage if direct_ok else "offline"
            except Exception:
                code = "upstream"
            finally:
                with self._probe_lock:
                    self._probe = {
                        "ok": code in ("ok", "overloaded"),
                        "code": code,
                        "ms": int((time.time() - started) * 1000),
                        "ts": int(time.time()),
                    }
                    self._probe_ts = time.time()
                    self._probe_checking = False

        threading.Thread(target=_run, daemon=True).start()

    def get_state(self, force_egress: bool = False) -> dict:
        warp_bin = find_warp_cli()
        connected, mode, status_text = warp_status(warp_bin) if warp_bin else (False, "", "Not Installed")
        local_v6 = get_warp_local_v6() or ""

        egress_mode = "warp"
        try:
            from proxy_chain import get_egress_config
            cfg = get_egress_config()
            egress_mode = cfg.get("mode", "warp")
        except Exception:
            pass

        if egress_mode in ("warp", "clean"):
            if not connected:
                with self._egress_lock:
                    self._egress_v6 = ""
            elif local_v6 != self._last_local_v6:
                self._last_local_v6 = local_v6
                if local_v6:
                    self._refresh_egress_async(force=True)
                else:
                    with self._egress_lock:
                        self._egress_v6 = ""
            else:
                self._refresh_egress_async(force=force_egress)
        else:
            # Tor and custom routes have their own exit addresses; keep the
            # display fresh after guard-side circuit/node rotation as well.
            self._refresh_egress_async(force=force_egress)

        with self._egress_lock:
            egress_v6 = self._egress_v6
            checking_egress = self._egress_checking

        self._refresh_probe_async(force=force_egress)
        with self._probe_lock:
            probe = dict(self._probe)
            probe["checking"] = self._probe_checking

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

        svc_wired = service_proxy_wired()

        cli_path = find_opencode_cli() or ""
        desktop_path = find_opencode_desktop() or ""
        log_size = OPENCODE_LOG_FILE.stat().st_size if OPENCODE_LOG_FILE.is_file() else 0
        keeper_hb = _heartbeat_age(KEEPER_LOG_FILE.parent / "heartbeat.txt")
        guard_hb = _heartbeat_age(GUARD_LOG_FILE.parent / "heartbeat.txt")
        opencode_lines = _tail_lines(OPENCODE_LOG_FILE, 160)
        recent_errors = _recent_network_errors(opencode_lines)
        proxy: dict = {}
        try:
            from zen_proxy import proxy_status

            proxy = proxy_status()
        except Exception:
            proxy = {}
        proxy["fallback_active"] = (LANE_DIR / "fallback.flag").is_file()

        state = {
            "warp": {
                "installed": bool(warp_bin),
                "bin": warp_bin or "",
                "connected": connected,
                "mode": mode or "unknown",
                "egress_mode": egress_mode,
                "status_text": status_text or ("Connected" if connected else "Disconnected"),
                "adapter_v6": local_v6,
                "egress_v6": egress_v6,
                "egress_ip": egress_v6,
                "egress_prefix": normalize_v6_64(egress_v6) if egress_v6 else "",
                "is_cf": is_cloudflare_v6(egress_v6) if ":" in egress_v6 else False,
                "checking_egress": checking_egress,
                "rotating": is_keeper_paused(),
            },
            "services": {
                "keeper_running": is_mutex_held("OpencodeUnlimitedKeeper"),
                "guard_running": is_mutex_held("OpencodeUnlimitedGuard"),
                "keeper_task": task_exists(TASK_KEEPER),
                "guard_task": task_exists(TASK_GUARD),
                "proxy_listening": _port_open(SERVICE_PROXY_PORT),
                "proxy_port": SERVICE_PROXY_PORT,
                "firewall_installed": is_killswitch_installed(),
                "is_admin": is_admin(),
                "auto_resume": self._is_auto_resume_active(),
                "keeper_heartbeat": keeper_hb,
                "guard_heartbeat": guard_hb,
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
                "failed_hops": int(guard_state.get("failed_hops", 0) or 0),
                "backoff_until": int(guard_state.get("backoff_until", 0) or 0),
                "db": _read_db_stats(),
                "log_size_bytes": log_size,
            },
            "logs": {
                "guard": _tail_lines(GUARD_LOG_FILE, 75),
                "keeper": _tail_lines(KEEPER_LOG_FILE, 75),
                "opencode": opencode_lines[-55:],
                "proxy": _tail_lines(LANE_DIR / "proxy.log", 75),
            },
            "egress": self._get_egress_state(),
            "proxy": proxy,
            "auto_repair": self.get_auto_repair(),
        }

        state["probe"] = probe
        state["health"] = self._build_health(
            warp_installed=state["warp"]["installed"],
            warp_connected=connected,
            rotating=state["warp"]["rotating"],
            egress=state["egress"],
            keeper_running=state["services"]["keeper_running"],
            guard_running=state["services"]["guard_running"],
            proxy_listening=state["services"]["proxy_listening"],
            svc_wired=svc_wired,
            installed=state["lane"]["scripts_installed"],
            probe=probe,
            guard_backoff=int(guard_state.get("backoff_until", 0) or 0),
            guard_free_wall=int(guard_state.get("free_wall_until", 0) or 0),
            keeper_heartbeat=keeper_hb,
            guard_heartbeat=guard_hb,
            desktop_installed=bool(desktop_path),
            cli_installed=bool(cli_path),
            path_wired=state["lane"]["path_wired"],
            proxy=proxy,
            net_errors=recent_errors,
            overload_errors=_recent_overload_errors(opencode_lines),
        )
        return state

    def _build_health(
        self,
        *,
        warp_installed: bool,
        warp_connected: bool,
        rotating: bool,
        egress: dict,
        keeper_running: bool,
        guard_running: bool,
        proxy_listening: bool,
        svc_wired: bool,
        installed: bool,
        probe: dict | None = None,
        guard_backoff: int = 0,
        guard_free_wall: int = 0,
        keeper_heartbeat: float | None = None,
        guard_heartbeat: float | None = None,
        desktop_installed: bool = False,
        cli_installed: bool = False,
        path_wired: bool = False,
        proxy: dict | None = None,
        net_errors: list[str] | None = None,
        overload_errors: list[str] | None = None,
    ) -> dict:
        """Summarise the live state as a short list of plain-language problems with one-click fixes."""
        issues: list[dict] = []
        proxy = proxy or {}
        net_errors = net_errors or []

        def add(level: str, title: str, detail: str, fix: str | None = None, fix_label: str = "Fix it") -> None:
            issues.append({"level": level, "title": title, "detail": detail, "fix": fix, "fix_label": fix_label})

        mode = egress.get("mode", "warp")
        if not installed:
            add(
                "warn",
                "Setup isn't finished",
                "The background service isn't installed yet, so OpenCode isn't protected or auto-rotated.",
                "install",
                "Install",
            )
        if installed and (desktop_installed or cli_installed) and not svc_wired and not path_wired:
            add(
                "warn",
                "OpenCode isn't using Opencode Unlimited",
                "OpenCode is installed but it's connecting directly, so it will hit the free limit and nothing "
                "will rotate. Press Connect, then reopen OpenCode.",
                "connect_opencode",
                "Connect",
            )
        if (svc_wired or path_wired) and not proxy_listening:
            add(
                "bad",
                "OpenCode can't connect right now",
                "OpenCode is set to go through the local proxy on port 41987, but it isn't running. "
                "Messages fail with ECONNREFUSED until it's back.",
                "start_keeper",
                "Start it",
            )
        elif installed and not keeper_running:
            add(
                "warn",
                "Background protection is off",
                "WARP Keeper isn't running. This window is covering for it, but OpenCode will lose "
                "its connection when you close the app.",
                "start_keeper",
                "Turn on",
            )
        if keeper_running and keeper_heartbeat is not None and keeper_heartbeat > HEARTBEAT_STALE:
            add(
                "bad",
                "Background protection stopped responding",
                f"WARP Keeper is still running but hasn't checked in for {int(keeper_heartbeat // 60)} minutes, "
                "so OpenCode may lose its connection. Press Restart.",
                "restart_workers",
                "Restart",
            )
        if guard_running and guard_heartbeat is not None and guard_heartbeat > HEARTBEAT_STALE:
            add(
                "warn",
                "Auto-rotation stopped responding",
                f"Zen Guard is still running but hasn't checked in for {int(guard_heartbeat // 60)} minutes, "
                "so the free limit won't rotate. Press Restart.",
                "restart_workers",
                "Restart",
            )
        if mode in ("warp", "clean"):
            if not warp_installed:
                add(
                    "bad",
                    "Cloudflare WARP isn't installed",
                    "WARP mode needs the free Cloudflare WARP app (1.1.1.1).",
                    "install_warp",
                    "Download WARP",
                )
            elif not warp_connected and not rotating:
                add("bad", "WARP is disconnected", "Traffic can't go through Cloudflare right now.", "connect_warp", "Connect")
        elif mode == "tor" and not egress.get("tor_active"):
            add("bad", "Tor isn't running", "Tor mode is selected but no Tor proxy is reachable.", "start_tor", "Start Tor")
        if installed and not guard_running:
            add(
                "warn",
                "Auto-rotation is off",
                "Zen Guard isn't running, so when you hit the free limit you'll have to rotate manually.",
                "start_guard",
                "Turn on",
            )

        code = (probe or {}).get("code", "")
        if overload_errors or code == "overloaded":
            add(
                "warn",
                "The inference provider reports overload",
                "Allow OpenCode's existing retry to finish, retry later, or select another model/provider. "
                "Rotating WARP or repairing the route does not increase provider capacity.",
            )
        fallback_active = bool(proxy.get("fallback_active"))
        if proxy_listening and fallback_active:
            route = {
                "warp": "Cloudflare WARP",
                "clean": "the clean endpoint",
                "tor": "Tor",
                "custom": "your proxy",
            }.get(mode, "the selected route")
            age = proxy.get("fallback_age")
            when = (
                f"{max(1, int(age // 60))} minute{'s' if int(age // 60) != 1 else ''} ago"
                if isinstance(age, int) and age >= 60
                else "in the last few minutes"
            )
            add(
                "warn",
                "Using a direct connection",
                f"The route through {route} dropped {when}, so OpenCode was sent straight out to stay usable. "
                "It keeps working, but the free limit may not rotate until this is repaired.",
                "start_tor" if mode == "tor" else "hop" if mode == "custom" else "repair_warp",
                "Repair route",
            )
        if proxy_listening and code in ("upstream", "timeout", "offline"):
            if code == "offline":
                add(
                    "bad",
                    "This PC has no internet",
                    "Neither the direct connection nor the local proxy could reach the internet. "
                    "Check Wi-Fi or the network cable, then press Refresh.",
                )
            elif (
                (mode in ("warp", "clean") and warp_connected)
                or (mode == "tor" and egress.get("tor_active"))
                or mode == "custom"
            ):
                hint = {
                    "tor": "Press Start Tor, or pick another connection type in the mode bar.",
                    "custom": "Press Next Node to try another proxy node, or pick another connection type in the mode bar.",
                }.get(mode, "Press Fix WARP, or pick another connection type in the mode bar.")
                add(
                    "bad",
                    "OpenCode can't get through the local proxy",
                    "The local proxy is running, but nothing comes back from opencode.ai. " + hint,
                    "start_tor" if mode == "tor" else "hop" if mode == "custom" else "repair_warp",
                    "Try" if mode in ("tor", "custom") else "Repair",
                )

        stream_resets = int(proxy.get("stream_resets_5m", 0) or 0)
        if proxy_listening and stream_resets >= 2 and not fallback_active:
            fix = "start_tor" if mode == "tor" else "hop"
            label = "Restart Tor" if mode == "tor" else "Rotate route"
            add(
                "warn",
                "Response streams keep dropping",
                f"{stream_resets} live response stream{'s' if stream_resets != 1 else ''} "
                "were cut in the last five minutes. A flaky edge or a provider-side idle "
                "timeout can do this; the route itself is still up. Rotate to move to a "
                "fresh exit, or switch to Tor if it keeps happening.",
                fix,
                label,
            )

        if net_errors and proxy_listening and not fallback_active and code not in (
            "upstream",
            "timeout",
            "offline",
        ):
            sample = net_errors[-1]
            fix = "start_tor" if mode == "tor" else "hop" if mode == "custom" else "repair_warp"
            label = "Restart Tor" if mode == "tor" else "Next node" if mode == "custom" else "Repair"
            add(
                "bad",
                "OpenCode hit a network error",
                f"OpenCode logged a connection failure in the last few minutes: {sample} "
                "Press Repair to rebuild the route; the Proxy tab shows which edge dropped it.",
                fix,
                label,
            )

        if guard_free_wall and guard_free_wall > time.time():
            reset = time.strftime("%H:%M", time.localtime(guard_free_wall))
            add(
                "warn",
                "The free limit is not following the IP",
                f"Two confirmed new IPv6 addresses still hit the free limit, so the allowance is no "
                f"longer tied to your address. Rotation is paused until it refills around {reset} "
                f"(your time); the chats waiting on it continue by themselves then, without you typing "
                f"anything. Use another provider, subscribe to OpenCode Go, or press Try now to force "
                f"another address.",
                "hop",
                "Try now",
            )
        elif guard_backoff and guard_backoff > time.time():
            mins = max(1, int((guard_backoff - time.time()) // 60))
            add(
                "warn",
                "Auto-rotation is taking a break",
                f"New addresses kept hitting the free limit right away, so rotation paused for about "
                f"{mins} more minute{'s' if mins != 1 else ''} to avoid a loop. It tries again by itself after "
                "that, or press Try now to get a new IP immediately.",
                "hop",
                "Try now",
            )

        brand_state = _desktop_brand_state()
        if brand_state.get("supported") and not brand_state.get("patched"):
            add(
                "warn",
                "The desktop app still pushes a subscription",
                "OpenCode Desktop replaces the chat box with a card that asks you to subscribe, even "
                "after the free allowance is about to refill by itself. Press Apply and the app is "
                "rewritten with wording that matches what actually happens. Nothing else in the app "
                "changes, and it can be put back the same way.",
                "brand_desktop",
                "Apply",
            )

        bad = any(i["level"] == "bad" for i in issues)
        wired = svc_wired or path_wired
        if rotating:
            status, title, sub = (
                "busy",
                "Rotating to a fresh IP...",
                "This takes about 10-15 seconds. OpenCode will continue automatically.",
            )
        elif bad:
            status, title, sub = "bad", "OpenCode needs attention", "Fix the problem below and OpenCode will work again."
        elif issues:
            status, title, sub = "warn", "Working, with warnings", "OpenCode works, but something below should be turned on."
        elif wired and probe is not None and probe.get("ok") is not True:
            if probe.get("ok") is None:
                status, title, sub = (
                    "warn",
                    "Checking the connection...",
                    "Making sure traffic really gets through the local proxy. This takes a few seconds.",
                )
            else:
                status, title, sub = (
                    "warn",
                    "Couldn't confirm the connection",
                    "The last real test didn't finish. Press Refresh to try again.",
                )
        else:
            status, title = "ok", "Everything is working"
            sub = {
                "tor": "OpenCode is connected through the Tor network.",
                "custom": "OpenCode is connected through your custom proxy.",
            }.get(mode, "OpenCode is connected through Cloudflare WARP and auto-rotates when you hit the limit.")
        return {"status": status, "title": title, "sub": sub, "issues": issues}

    def fix_issue(self, action: str) -> dict:
        """One-click fixes for the problems listed in the health panel."""
        if action == "brand_desktop":
            try:
                import desktop_brand

                ok, message = desktop_brand.apply_copy()
            except Exception as exc:
                return {"ok": False, "message": f"The desktop patch could not run ({exc})."}
            _forget_desktop_brand()
            return {"ok": ok, "message": message}
        if action == "start_keeper":
            res = self.toggle_worker("keeper", True)
            for _ in range(20):
                if _port_open(SERVICE_PROXY_PORT):
                    break
                time.sleep(0.3)
            if _port_open(SERVICE_PROXY_PORT):
                return {
                    "ok": True,
                    "message": "Background service is running. OpenCode can connect again - send 'continue'.",
                }
            return res
        if action == "start_guard":
            return self.toggle_worker("guard", True)
        if action == "restart_workers":
            return self.restart_workers()
        if action == "connect_warp":
            return self.warp_connect()
        if action == "repair_warp":
            return self.repair_warp_connection()
        if action == "hop":
            return self.hop_now()
        if action == "fix_port":
            return self.fix_opencode_service()
        if action == "start_tor":
            return self.toggle_tor_service(True)
        if action == "install":
            return self.install_or_repair()
        if action == "connect_opencode":
            res = self.toggle_desktop_service_proxy(True)
            if res.get("ok"):
                try:
                    _deploy_scripts_and_shims()
                    _update_user_path(True)
                except Exception:
                    pass
                res["message"] = (
                    "OpenCode is connected to the local proxy. Close and reopen OpenCode so it picks up the change."
                )
            return res
        if action == "install_warp":
            webbrowser.open("https://one.one.one.one/")
            return {"ok": True, "message": "Opened the Cloudflare WARP download page. Install it, then press Refresh."}
        return {"ok": False, "message": "Unknown fix."}

    def fix_everything(self) -> dict:
        """Run every one-click fix the health check suggests, most serious first."""
        order = [
            "install",
            "connect_opencode",
            "start_keeper",
            "restart_workers",
            "connect_warp",
            "start_tor",
            "start_guard",
            "fix_port",
        ]
        done: list[str] = []
        failed: list[str] = []
        manual: list[str] = []
        tried: set[str] = set()
        for _round in range(2):
            health = self.get_state().get("health") or {}
            issues = sorted(health.get("issues", []), key=lambda i: 0 if i.get("level") == "bad" else 1)
            todo = [i for i in issues if i.get("fix") and i["fix"] not in tried]
            if not todo:
                break
            for issue in sorted(todo, key=lambda i: order.index(i["fix"]) if i["fix"] in order else 99):
                fix = issue["fix"]
                tried.add(fix)
                if fix == "install_warp":
                    manual.append("Install Cloudflare WARP (free) from one.one.one.one, then press Fix everything again.")
                    continue
                try:
                    res = self.fix_issue(fix)
                except Exception as exc:
                    res = {"ok": False, "message": str(exc)}
                (done if res.get("ok") else failed).append(issue.get("title", fix))
        final = self.get_state().get("health") or {}
        left = [i.get("title", "") for i in final.get("issues", []) if i.get("level") == "bad"]
        if not left and not manual:
            msg = "Everything is working." if not done else f"Fixed: {', '.join(done)}. Everything is working."
            return {"ok": True, "message": msg, "fixed": done, "remaining": []}
        parts = []
        if done:
            parts.append(f"Fixed: {', '.join(done)}.")
        if failed:
            parts.append(f"Couldn't fix: {', '.join(failed)}.")
        if left:
            parts.append(f"Still not working: {', '.join(left)}.")
        parts += manual
        return {"ok": False, "message": " ".join(parts), "fixed": done, "remaining": left + manual}

    def restart_workers(self) -> dict:
        """Restart the keeper and guard with the code currently deployed, without changing service wiring."""
        if not self._action_lock.acquire(blocking=False):
            return {"ok": False, "message": "Another rotation or setup action is already running."}
        try:
            _deploy_scripts_and_shims()
            for name in ("guard", "keeper"):
                _stop_worker_processes(name)
            time.sleep(1.0)
            for name in ("guard", "keeper"):
                self.toggle_worker(name, True)
            for _ in range(20):
                if _port_open(SERVICE_PROXY_PORT):
                    break
                time.sleep(0.3)
            if _port_open(SERVICE_PROXY_PORT):
                return {"ok": True, "message": "Background service restarted with the current code."}
            return {
                "ok": False,
                "message": "Workers restarted, but the local proxy is not listening yet. Check the Keeper log.",
            }
        finally:
            self._action_lock.release()

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
            fallback_scope = "tun" if sys.platform == "win32" else "isolated"
            return {"mode": "warp", "warp_scope": fallback_scope, "error": str(exc), "clean_endpoints": []}

    def set_warp_scope(self, scope: str) -> dict:
        from proxy_chain import get_egress_config, set_egress_config
        cfg = get_egress_config()
        clean_scope = "tun" if scope.lower().strip() == "tun" else "isolated"
        changed = str(cfg.get("warp_scope", "")) != clean_scope
        set_egress_config(
            mode=cfg.get("mode", "warp"),
            custom_proxy=cfg.get("custom_proxy", "127.0.0.1:10808"),
            custom_type=cfg.get("custom_type", "socks5"),
            warp_scope=clean_scope,
        )
        warp = find_warp_cli()
        if warp and changed:
            if not warp_registration_healthy(warp):
                repair_warp_registration(warp, 3)
            ensure_warp_mode(warp, clean_scope)
            run_warp(["connect"], warp_bin=warp)
            connected = False
            for _ in range(8):
                time.sleep(0.8)
                connected, _, raw = warp_status(warp, force=True)
                if connected:
                    break
            self._refresh_egress_async(force=True)
            if not connected:
                detail = (raw or "").strip()
                return {
                    "ok": False,
                    "scope": clean_scope,
                    "message": (
                        f"Scope saved as {clean_scope}, but WARP did not reconnect"
                        + (f": {detail}" if detail else ".")
                    ),
                }
        label = "App-Only (Isolated Proxy)" if clean_scope == "isolated" else "Full System TUN"
        return {"ok": True, "scope": clean_scope, "message": f"WARP scope set to: {label}"}

    def set_egress_mode(self, mode: str, custom_proxy: str = "127.0.0.1:10808", custom_type: str = "socks5") -> dict:
        from proxy_chain import get_egress_config, set_egress_config
        chosen = str(mode).lower().strip()
        if chosen not in ("warp", "tor", "custom", "clean"):
            return {"ok": False, "message": f"Unknown egress mode: {mode}"}
        current = get_egress_config()
        cfg = set_egress_config(
            chosen,
            custom_proxy,
            custom_type,
            warp_scope=current.get("warp_scope"),
        )
        if chosen == "tor":
            from tor_manager import get_active_tor_target, start_portable_tor
            if not get_active_tor_target():
                threading.Thread(target=start_portable_tor, daemon=True).start()
        elif chosen in ("warp", "clean"):
            warp = find_warp_cli()
            if warp:
                default_scope = "tun" if sys.platform == "win32" else "isolated"
                scope = current.get("warp_scope", default_scope)
                if not warp_registration_healthy(warp):
                    repair_warp_registration(warp, 3)
                ensure_warp_mode(warp, scope)
                run_warp(["connect"], warp_bin=warp)
                connected = False
                raw = ""
                for _ in range(8):
                    time.sleep(0.8)
                    connected, _, raw = warp_status(warp, force=True)
                    if connected:
                        break
                if not connected:
                    detail = (raw or "").strip()
                    return {
                        "ok": False,
                        "config": cfg,
                        "message": (
                            f"Egress saved as {chosen.upper()}, but WARP did not connect"
                            + (f": {detail}" if detail else ".")
                        ),
                    }
        self._refresh_egress_async(force=True)
        return {"ok": True, "config": cfg, "message": f"Active egress switched to: {chosen.upper()}"}

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
        default_scope = "tun" if sys.platform == "win32" else "isolated"
        scope = default_scope
        try:
            from proxy_chain import get_egress_config
            scope = get_egress_config().get("warp_scope", default_scope)
        except Exception:
            pass

        if not warp_registration_healthy(warp):
            if not repair_warp_registration(warp, 3):
                return {
                    "ok": False,
                    "message": "WARP registration could not be created. Check the WARP client and retry.",
                }

        ensure_warp_mode(warp, scope)
        run_warp(["connect"], warp_bin=warp)
        raw = ""
        for _ in range(10):
            time.sleep(1.0)
            conn, _, raw = warp_status(warp, force=True)
            if conn:
                self._refresh_egress_async(force=True)
                return {
                    "ok": True,
                    "message": f"WARP connected ({'App-Only proxy' if scope == 'isolated' else 'Full TUN'}).",
                }

        # Renew the session keys once; the endpoint and registration stay intact.
        run_warp(["tunnel", "rotate-keys"], warp_bin=warp)
        run_warp(["connect"], warp_bin=warp)
        for _ in range(8):
            time.sleep(1.0)
            conn, _, raw = warp_status(warp, force=True)
            if conn:
                self._refresh_egress_async(force=True)
                return {
                    "ok": True,
                    "message": f"WARP session renewed and connected ({'App-Only proxy' if scope == 'isolated' else 'Full TUN'}).",
                }

        detail = (raw or "").strip()
        return {
            "ok": False,
            "message": (
                "WARP could not connect. Restart the Cloudflare WARP client "
                + (f"({detail})" if detail else "and retry.")
            ),
        }

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
            try:
                from proxy_chain import get_egress_config
                mode = get_egress_config().get("mode", "warp")
            except Exception:
                mode = "warp"
            if mode == "tor":
                from tor_manager import rotate_tor_circuit
                ok, msg = rotate_tor_circuit()
                self._refresh_egress_async(force=True)
                return {"ok": ok, "message": msg}
            if mode == "custom":
                from proxy_chain import rotate_custom_proxy
                ok, msg = rotate_custom_proxy()
                self._refresh_egress_async(force=True)
                return {"ok": ok, "message": msg}

            warp = find_warp_cli()
            if not warp:
                return {"ok": False, "message": "warp-cli.exe not found."}
            old_v6 = self._egress_v6 or (get_warp_local_v6() or "")
            avoid: set[str] = set()
            if GUARD_STATE_FILE.is_file():
                try:
                    st = json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8"))
                    avoid = {str(x) for x in st.get("blacklist", []) if x}
                except Exception:
                    pass
            with keeper_pause_ctx("avatar-ui-hop", seconds=300):
                report = hop_report(
                    warp,
                    max_reg_tries=5,
                    avoid_prefixes=avoid,
                    previous=old_v6,
                )
            new_v6 = report["address"]
            if not new_v6:
                why = {
                    "reused": "WARP came back on the same block",
                    "down": "the tunnel would not come back up",
                    "unreachable": "the tunnel is up but the address probe did not answer",
                }.get(report.get("status", ""), "no fresh block was observed")
                return {
                    "ok": False,
                    "message": f"Rotation failed - {why}. Keeper will retry automatically.",
                }
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
            # A manual rotation is an explicit request to try again now.
            st["failed_hops"] = 0
            st["backoff_until"] = 0
            st["hop_counted"] = 0
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
            # Disable the logon task first so its restart-on-failure policy
            # cannot bring the worker back after the kill below.
            if task_exists(task_name):
                run_hidden(
                    ["schtasks", "/Change", "/TN", task_name, "/DISABLE"], timeout=8.0
                )
            killed, error = _stop_worker_processes(name)
            if name == "keeper":
                self.toggle_desktop_service_proxy(False)
            if error:
                return {
                    "ok": False,
                    "message": f"Stopped {killed} {name} process{'es' if killed != 1 else ''}, but {error}. "
                    "Close OpenCode or run this app as administrator, then try again.",
                }
            return {"ok": True, "message": f"Stopped {name} ({killed} process{'es' if killed != 1 else ''})."}

        _deploy_scripts_and_shims()
        if task_exists(task_name):
            run_hidden(
                ["schtasks", "/Change", "/TN", task_name, "/ENABLE"], timeout=8.0
            )
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
                for _ in range(20):
                    if _port_open(SERVICE_PROXY_PORT):
                        break
                    time.sleep(0.3)
            if not _port_open(SERVICE_PROXY_PORT):
                return {"ok": False, "message": f"Proxy port {SERVICE_PROXY_PORT} is not listening. Check WARP Keeper."}

        # 2. Update service.json directly so unrelated keys such as the
        #    service password are preserved.
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

        # 3. Ask the OpenCode CLI to apply the same settings and restart.
        oc = find_opencode_cli()
        if oc:
            try:
                if enable:
                    for key in ("HTTPS_PROXY", "HTTP_PROXY"):
                        run_hidden(
                            opencode_command(
                                oc, ["service", "set", "env", key, proxy_url]
                            ),
                            timeout=4.0,
                        )
                    run_hidden(
                        opencode_command(
                            oc,
                            [
                                "service",
                                "set",
                                "env",
                                "NO_PROXY",
                                "127.0.0.1,localhost,::1",
                            ],
                        ),
                        timeout=4.0,
                    )
                else:
                    for key in _SERVICE_ENV_KEYS:
                        run_hidden(
                            opencode_command(oc, ["service", "unset", "env", key]),
                            timeout=4.0,
                        )
                run_hidden(
                    opencode_command(oc, ["service", "restart"]), timeout=15.0
                )
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
                    "Auto-resume enabled. A 'continue' prompt is sent after a rotation."
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
            return {"ok": True, "message": "Strict fail-closed mode enabled: requests fail when the configured egress is unavailable."}
        flag.unlink(missing_ok=True)
        return {"ok": True, "message": "Resilient fallback enabled: when WARP drops, requests fall back to a direct connection instead of returning 503."}

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
        """Renew the WARP session without deleting a healthy registration."""
        wb = find_warp_cli()
        if not wb:
            return {"ok": False, "message": "warp-cli.exe not found."}
        try:
            default_scope = "tun" if sys.platform == "win32" else "isolated"
            scope = default_scope
            try:
                from proxy_chain import get_egress_config
                scope = get_egress_config().get("warp_scope", default_scope)
            except Exception:
                pass

            if not warp_registration_healthy(wb):
                if not repair_warp_registration(wb, 3):
                    return {
                        "ok": False,
                        "message": "WARP registration could not be created. Check the WARP client and retry.",
                    }

            run_warp(["tunnel", "rotate-keys"], warp_bin=wb)
            ensure_warp_mode(wb, scope)
            run_warp(["connect"], warp_bin=wb)

            raw = ""
            for _ in range(8):
                time.sleep(1.0)
                conn, _, raw = warp_status(wb, force=True)
                if conn:
                    self._refresh_egress_async(force=True)
                    return {
                        "ok": True,
                        "message": f"WARP session renewed and connected ({'App-Only proxy' if scope == 'isolated' else 'Full TUN'}).",
                    }

            raw_low = (raw or "").lower()
            if "registration missing" in raw_low or "not registered" in raw_low:
                if repair_warp_registration(wb, 3):
                    run_warp(["connect"], warp_bin=wb)
                    for _ in range(6):
                        time.sleep(1.0)
                        conn, _, _ = warp_status(wb, force=True)
                        if conn:
                            self._refresh_egress_async(force=True)
                            return {
                                "ok": True,
                                "message": "WARP registration recreated and connected.",
                            }

            detail = (raw or "").strip()
            return {
                "ok": False,
                "message": (
                    "WARP still cannot connect. Restart the Cloudflare WARP client"
                    + (f" ({detail})." if detail else " and retry.")
                ),
            }
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
            for item_name in ("olliecode-fingerprint.json",):
                target = base_dir / item_name
                if target.is_file():
                    try:
                        target.unlink(missing_ok=True)
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

        # Clear client-side rate limit lockouts from drafts.sqlite
        fl_cleared = clear_opencode_free_limit()
        if fl_cleared > 0:
            cleared.append(f"{fl_cleared} limit entries")

        # Clear guard blacklist and reset edge override
        self.clear_blacklist()
        self.set_edge_override("auto")

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
                    with keeper_pause_ctx("avatar-ui-deep-reset", seconds=300):
                        new_ip = hop_once(wbin, previous=self._egress_v6)
                    rot_msg = (
                        f"Rotated WARP IP: {new_ip}"
                        if new_ip
                        else "WARP reconnect failed"
                    )
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

        # Clear any client-side rate limit lockouts
        clear_opencode_free_limit()

        if not _port_open(SERVICE_PROXY_PORT):
            self.toggle_worker("keeper", True)
        already_wired = service_proxy_wired()
        if not already_wired:
            self.toggle_desktop_service_proxy(True)
        env = os.environ.copy()
        proxy_url = f"http://127.0.0.1:{SERVICE_PROXY_PORT}"
        env["HTTPS_PROXY"] = proxy_url
        env["HTTP_PROXY"] = proxy_url
        env["NO_PROXY"] = "127.0.0.1,localhost,::1"
        args_str = f"--proxy-server={proxy_url} --proxy-bypass-list=127.0.0.1;localhost;::1;*.local"
        launched = False
        if sys.platform == "win32" and hasattr(os, "startfile"):
            try:
                os.startfile(desktop, arguments=args_str)
                launched = True
            except Exception:
                pass
        if not launched:
            flags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) if sys.platform == "win32" else 0
            subprocess.Popen(
                [desktop, f"--proxy-server={proxy_url}", "--proxy-bypass-list=127.0.0.1;localhost;::1;*.local"],
                env=env,
                creationflags=flags,
                close_fds=False if sys.platform == "win32" else True,
            )
        return {"ok": True, "message": "Launched OpenCode Desktop through WARP IPv6 lane."}

    def fix_opencode_service(self) -> dict:
        """Restart the OpenCode background service without killing the Desktop app."""
        cli = find_opencode_cli()
        if not cli:
            return {
                "ok": False,
                "message": "OpenCode CLI not found. Install OpenCode or run install.bat first.",
            }

        fl_cleared = clear_opencode_free_limit()

        try:
            run_hidden(opencode_command(cli, ["service", "stop"]), timeout=10.0)
            time.sleep(0.5)
        except Exception:
            pass

        status = run_hidden(opencode_command(cli, ["service", "status"]), timeout=8.0)
        status_text = (status.stdout or "") + (status.stderr or "")
        healthy = status.returncode == 0 and "127.0.0.1:" in status_text

        if not healthy:
            result = run_hidden(
                opencode_command(cli, ["service", "restart"]), timeout=20.0
            )
            if result.returncode != 0:
                result = run_hidden(
                    opencode_command(cli, ["service", "start"]), timeout=15.0
                )
            time.sleep(1.0)
        else:
            run_hidden(opencode_command(cli, ["service", "restart"]), timeout=20.0)
            time.sleep(1.0)

        status = run_hidden(opencode_command(cli, ["service", "status"]), timeout=8.0)
        status_text = ((status.stdout or "") + (status.stderr or "")).strip()
        healthy = status.returncode == 0 and "127.0.0.1:" in status_text

        if not _port_open(SERVICE_PROXY_PORT):
            self.toggle_worker("keeper", True)
            for _ in range(20):
                if _port_open(SERVICE_PROXY_PORT):
                    break
                time.sleep(0.3)

        if _port_open(SERVICE_PROXY_PORT):
            self.toggle_desktop_service_proxy(True)
        else:
            self.toggle_desktop_service_proxy(False)

        extra = f" Cleared {fl_cleared} limit rows." if fl_cleared > 0 else ""
        if healthy:
            return {
                "ok": True,
                "message": f"OpenCode service restarted at {status_text}.{extra}",
            }
        return {
            "ok": False,
            "message": (
                "OpenCode service did not report a listening address. "
                f"Close OpenCode, then retry.{extra}"
            ),
        }

    def launch_cli(self) -> dict:
        _deploy_scripts_and_shims()
        shim = BIN_DIR / "opencode.cmd"
        if not shim.is_file():
            return {"ok": False, "message": "opencode CLI shim not ready; run Install / Repair first."}
        wt = shutil.which("wt.exe")
        use_close_fds = False if sys.platform == "win32" else True
        if wt:
            subprocess.Popen([wt, "cmd.exe", "/k", str(shim)], close_fds=use_close_fds)
        else:
            subprocess.Popen(
                ["cmd.exe", "/c", "start", "OpenCode Unlimited CLI", "cmd.exe", "/k", str(shim)],
                shell=False,
                close_fds=use_close_fds,
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
            return {"ok": True, "message": "Installed/repaired shims, PATH, tasks, WARP in the selected scope, and Desktop service."}
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
        "Opencode Unlimited - WebView2 Required",
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
        "Opencode Unlimited - Startup Error",
        MB_OK | MB_ICONERROR,
    )


def main() -> int:
    cli_rc = _run_cli_mode(sys.argv[1:])
    if cli_rc is not None:
        return cli_rc

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
    except TypeError:
        # pywebview 5.x does not accept an icon argument.
        start_kwargs.pop("icon", None)
        try:
            webview.start(**start_kwargs)
        except Exception as exc:
            _log_startup_error(exc)
            return 1
    except Exception as exc:
        _log_startup_error(exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
