"""Auto-Resume module for OpenCode Unlimited.

Automatically detects when a rate limit is bypassed, clears client-side database
lockouts (free-limit / go-upsell), reloads the OpenCode interface, and sends
a 'continue' action to the active OpenCode session.
"""

from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ouc_common import LANE_DIR, find_opencode_cli, opencode_command

AUTO_RESUME_FLAG = LANE_DIR / "auto_resume.flag"


def is_auto_resume_enabled() -> bool:
    """Return True if auto-resume is enabled (default is enabled)."""
    if AUTO_RESUME_FLAG.is_file():
        try:
            return AUTO_RESUME_FLAG.read_text(encoding="utf-8").strip() != "0"
        except Exception:
            return True
    return True


def set_auto_resume(enable: bool) -> None:
    """Enable or disable the auto-resume feature."""
    LANE_DIR.mkdir(parents=True, exist_ok=True)
    AUTO_RESUME_FLAG.write_text("1\n" if enable else "0\n", encoding="utf-8")


# The keys OpenCode Desktop uses for the client-side lockout. Only names that
# were confirmed are deleted: a blanket "anything containing 'limit'" would also
# remove usage counters and model settings.
LOCK_KEYS = (
    "free-limit",
    "go-upsell",
    "free_usage_limit",
    "usage_limit",
    "quota_exceeded",
)


def drafts_databases() -> list[Path]:
    """Every drafts.sqlite location the Desktop app has used."""
    candidates = [
        Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "ai.opencode.desktop" / "drafts.sqlite",
        Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ai.opencode.desktop" / "drafts.sqlite",
        Path.home() / ".config" / "ai.opencode.desktop" / "drafts.sqlite",
        Path.home() / ".local" / "share" / "opencode" / "drafts.sqlite",
    ]
    seen: list[Path] = []
    for path in candidates:
        if path not in seen:
            seen.append(path)
    return seen


# Names that suggest a stored wait time rather than a counter. Used only to
# decide which rows to parse; nothing is ever printed or logged as a value.
LOCK_KEY_HINTS = ("limit", "upsell", "quota", "reset")


def _lock_epoch(value) -> int:
    """Normalise a stored lock value to an epoch second, or 0 when it is not a time.

    The Desktop has written this row as epoch milliseconds, epoch seconds and
    ISO text across versions, so all three are accepted and then sanity checked
    against the present before anything treats it as a deadline.
    """
    if value is None:
        return 0
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8", "ignore").strip()
        except Exception:
            return 0
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value).strip().strip('"')
        if not text:
            return 0
        try:
            number = float(text)
        except ValueError:
            try:
                stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return 0
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            number = stamp.timestamp()
    # A millisecond stamp is ~1.7e12; anything that large is not seconds.
    if number > 1e11:
        number /= 1000.0
    now = time.time()
    if not (now - 30 * 86400 <= number <= now + 60 * 86400):
        return 0
    return int(number)


def read_opencode_lock() -> dict:
    """The wait time OpenCode Desktop stored client-side, normalised.

    Returns ``{"until": epoch, "keys": {name: epoch}, "detail": [(db, key, epoch)]}``.
    ``until`` is the latest advertised time across the databases the app has
    used, or 0 when nothing that looks like a deadline is stored. This is a
    client hint only: the guard displays it and clears it once it has passed,
    never rotates because of it.
    """
    found: dict[str, int] = {}
    detail: list[tuple[str, str, int]] = []
    for db_path in drafts_databases():
        if not db_path.is_file():
            continue
        try:
            conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=3.0)
        except Exception:
            continue
        try:
            rows = conn.execute("SELECT key, value FROM state").fetchall()
            for key, value in rows:
                name = str(key)
                low = name.lower()
                if not any(hint in low for hint in LOCK_KEY_HINTS):
                    continue
                stamp = _lock_epoch(value)
                if not stamp:
                    continue
                detail.append((str(db_path), name, stamp))
                found[name] = max(found.get(name, 0), stamp)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return {
        "until": max(found.values()) if found else 0,
        "keys": found,
        "detail": detail,
    }


def list_limit_state_keys() -> list[tuple[str, str]]:
    """(database, key) for every state row that looks like a limit lockout.

    Diagnostic only: it reads names, never values, so a report can name the real
    keys without exposing the user's state.
    """
    found: list[tuple[str, str]] = []
    for db_path in drafts_databases():
        if not db_path.is_file():
            continue
        try:
            conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=3.0)
        except Exception:
            continue
        try:
            rows = conn.execute("SELECT key FROM state").fetchall()
            for (key,) in rows:
                name = str(key)
                low = name.lower()
                if "limit" in low or "upsell" in low or "quota" in low:
                    found.append((str(db_path), name))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return found


def clear_opencode_free_limit(detail: list[str] | None = None) -> int:
    """Delete client-side free-limit and go-upsell lockout rows from drafts.sqlite.

    OpenCode Desktop stores rate limit timestamps in drafts.sqlite (table 'state').
    Even after IP rotation, the UI blocks user prompts until this timestamp is purged.
    """
    candidates = drafts_databases()
    deleted = 0
    for db_path in candidates:
        if not db_path.is_file():
            continue
        try:
            conn = sqlite3.connect(
                f"file:{db_path.as_posix()}?mode=rw",
                uri=True,
                timeout=5.0,
            )
            try:
                conn.execute("PRAGMA busy_timeout=5000")
                cur = conn.cursor()
                placeholders = ", ".join("?" for _ in LOCK_KEYS)
                cur.execute(
                    f"DELETE FROM state WHERE key IN ({placeholders})",
                    LOCK_KEYS,
                )
                rows = max(0, cur.rowcount)
                deleted += rows
                conn.commit()
                if detail is not None and rows:
                    detail.append(f"{db_path.name}: cleared {rows} lock row(s)")
            finally:
                conn.close()
        except Exception:
            pass
    return deleted


def get_latest_session_info() -> tuple[str, str, str] | None:
    """Query opencode.db for the most recently active non-archived session.

    Returns (session_id, directory, title) or None.
    """
    db_path = Path.home() / ".local" / "share" / "opencode" / "opencode.db"
    if not db_path.is_file():
        return None
    try:
        conn = sqlite3.connect(str(db_path), timeout=3.0)
    except Exception:
        return None
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, directory, title FROM session_v2 "
            "WHERE time_archived IS NULL "
            "ORDER BY time_updated DESC LIMIT 1"
        )
        row = cur.fetchone()
        if row and row[0]:
            return str(row[0]), str(row[1] or ""), str(row[2] or "")
    except Exception:
        pass
    finally:
        conn.close()
    return None


def _deliver_keystrokes(reload_first: bool = True, text: str | None = "continue{ENTER}") -> bool:
    """Focus OpenCode and send a reload and/or text.

    ``text`` is Windows SendKeys syntax; None means "reload only", which is what
    clears a stale limit banner without adding a turn to the chat.
    """
    if sys.platform != "win32":
        try:
            import shutil
            if shutil.which("xdotool"):
                reload_ok = False
                if reload_first:
                    reload = subprocess.run(["xdotool", "search", "--onlyvisible", "--class", "opencode", "key", "--clearmodifiers", "ctrl+r"], capture_output=True, timeout=2.0)
                    reload_ok = reload.returncode == 0
                    time.sleep(1.2)
                if text is None:
                    return reload_ok
                typed = subprocess.run(["xdotool", "search", "--onlyvisible", "--class", "opencode", "type", "--clearmodifiers", "continue"], capture_output=True, timeout=2.0)
                sent = subprocess.run(["xdotool", "search", "--onlyvisible", "--class", "opencode", "key", "--clearmodifiers", "Return"], capture_output=True, timeout=2.0)
                # xdotool exits non-zero when no matching window exists, so a
                # silent no-op must not be reported as a delivered keystroke.
                return typed.returncode == 0 and sent.returncode == 0
        except Exception:
            pass
        return False

    # 1. Native Windows Win32 API window focus and key dispatch
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.restype = wintypes.BOOL
        user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user32.GetWindowTextW.restype = ctypes.c_int
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL
        target_hwnds = []

        def _enum_cb(hwnd, _):
            if user32.IsWindowVisible(hwnd):
                length = user32.GetWindowTextLengthW(hwnd)
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value.lower()
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value == os.getpid():
                    return True
                pname = ""
                try:
                    import psutil
                    pname = psutil.Process(pid.value).name().lower()
                except Exception:
                    pass
                if "unlimited" in pname:
                    return True
                if pname in ("opencode.exe", "opencode-cli.exe"):
                    target_hwnds.append((hwnd, buf.value, pname))
                elif pname in (
                    "windowsterminal.exe",
                    "cmd.exe",
                    "powershell.exe",
                    "pwsh.exe",
                    "conhost.exe",
                    "mintty.exe",
                    "wezterm-gui.exe",
                    "alacritty.exe",
                ) and "opencode" in title:
                    target_hwnds.append((hwnd, buf.value, pname))
            return True

        CB_TYPE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows.argtypes = [CB_TYPE, wintypes.LPARAM]
        user32.EnumWindows.restype = wintypes.BOOL
        user32.EnumWindows(CB_TYPE(_enum_cb), 0)

        for hwnd, title, pname in target_hwnds:
            # SW_RESTORE = 9
            user32.ShowWindow(hwnd, 9)
            user32.SetForegroundWindow(hwnd)
            time.sleep(0.4)
            if user32.GetForegroundWindow() != hwnd:
                # Windows refused the focus change; never type into another app.
                continue
            # If requested, send Ctrl+R to reload UI (reloading drops the free-limit block screen)
            reloaded = False
            if reload_first and pname == "opencode.exe":
                ps_reload = """
                Add-Type -AssemblyName System.Windows.Forms
                [System.Windows.Forms.SendKeys]::SendWait("^r")
                """
                subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_reload],
                    capture_output=True,
                    creationflags=0x08000000,
                    timeout=3.0,
                )
                time.sleep(1.2)
                if user32.GetForegroundWindow() != hwnd:
                    user32.ShowWindow(hwnd, 9)
                    user32.SetForegroundWindow(hwnd)
                    time.sleep(0.4)
                    if user32.GetForegroundWindow() != hwnd:
                        continue
                reloaded = True

            if text is None:
                # Reload only. A terminal window has no reload to deliver.
                if reloaded:
                    return True
                continue

            ps_send = f"""
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.SendKeys]::SendWait("{text}")
            """
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_send],
                capture_output=True,
                creationflags=0x08000000,
                timeout=4.0,
            )
            return True
    except Exception:
        pass

    return False


def send_continue_keystroke(reload_first: bool = True) -> bool:
    """Send reload (^r) and 'continue{ENTER}' to the OpenCode window."""
    return _deliver_keystrokes(reload_first=reload_first, text="continue{ENTER}")


def reload_opencode_window() -> bool:
    """Reload the Desktop window only: drops a stale limit banner, types nothing."""
    return _deliver_keystrokes(reload_first=True, text=None)


_SESSION_ID_RE = re.compile(r"\bsessionID=(ses_[A-Za-z0-9]+)")


def session_id_in(line: str) -> str:
    """The OpenCode session a log line belongs to ('' if none). Wall errors carry 'sessionID=ses_...'."""
    match = _SESSION_ID_RE.search(line or "")
    return match.group(1) if match else ""


def _session_directory(session_id: str) -> str:
    db_path = Path.home() / ".local" / "share" / "opencode" / "opencode.db"
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=3.0)
        try:
            row = conn.execute("SELECT directory FROM session_v2 WHERE id = ?", (session_id,)).fetchone()
        finally:
            conn.close()
        return str(row[0] or "") if row else ""
    except Exception:
        return ""


def _stop_stale_continue(oc: str, session_id: str) -> None:
    """End an earlier 'continue' we sent to this session if it is still hanging around."""
    try:
        import psutil

        exe_name = Path(oc).name.lower()
        for proc in psutil.process_iter(["name", "cmdline"]):
            try:
                cmd = proc.info.get("cmdline") or []
                if (
                    (proc.info.get("name") or "").lower() == exe_name
                    and "run" in cmd
                    and session_id in cmd
                    and cmd[-1:] == ["continue"]
                ):
                    proc.kill()
            except Exception:
                pass
    except Exception:
        pass


def resume_sessions(session_ids: list[str]) -> tuple[int, list[str]]:
    """Send 'continue' to each listed session through OpenCode's background service."""
    oc = find_opencode_cli()
    if not oc:
        return 0, ["OpenCode CLI not found"]
    sent, notes = 0, []
    for sid in dict.fromkeys(s for s in session_ids if s):
        directory = _session_directory(sid)
        cwd = directory if (directory and os.path.isdir(directory)) else None
        _stop_stale_continue(oc, sid)
        try:
            kwargs: dict = {"cwd": cwd, "close_fds": True}
            if sys.platform == "win32":
                kwargs["creationflags"] = 0x08000000 | 0x00000008
            else:
                kwargs["start_new_session"] = True
            subprocess.Popen(opencode_command(oc, ["run", "--session", sid, "continue"]), **kwargs)
            sent += 1
        except Exception as exc:
            notes.append(f"{sid[:12]}: {exc}")
    return sent, notes


def _dispatch_cli_resume(oc: str, sess: tuple[str, str, str] | None) -> bool:
    """Start one CLI run that continues the newest session."""
    if sess:
        sess_id, directory, _title = sess
        cmd = opencode_command(oc, ["run", "--session", sess_id, "continue"])
        cwd = directory if (directory and os.path.isdir(directory)) else None
    else:
        cmd = opencode_command(oc, ["run", "--continue", "continue"])
        cwd = None

    try:
        kwargs: dict = {"cwd": cwd, "close_fds": True}
        if sys.platform == "win32":
            kwargs["creationflags"] = 0x08000000 | 0x00000008
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen(cmd, **kwargs)
        return True
    except Exception:
        return False


RELOAD_HINT = "hint: chat still locked - press Reload"


def resume_active_session(session_ids: list[str] | None = None) -> tuple[bool, str]:
    """Resume OpenCode after a new IP: clear the lock, reload the window, then continue.

    The reload is not optional. The Desktop banner and the disabled composer are
    drawn from client state, so a CLI 'continue' alone leaves the user looking at
    the error until they press Ctrl+R themselves.
    """
    if not is_auto_resume_enabled():
        return False, "Auto-resume is disabled."

    details: list[str] = []
    cleared = clear_opencode_free_limit(details)
    if cleared > 0:
        details.append(f"cleared {cleared} rate limit entries from database")

    reloaded = reload_opencode_window()
    details.append(
        "reloaded the OpenCode window" if reloaded else "could not reload the OpenCode window"
    )

    if session_ids:
        sent, notes = resume_sessions(session_ids)
        details.append(f"sent 'continue' to {sent} of {len(set(session_ids))} chat(s) that hit the limit")
        details.extend(notes)
        if sent:
            if not reloaded:
                details.append(RELOAD_HINT)
            return True, " | ".join(details)
        # Nothing could be sent that way: fall through to the active window.

    # Prefer the open Desktop window so the user sees the resumed session.
    # Only fall back to a detached CLI run when no window is available; running
    # both at once creates duplicate turns in the same session.
    if send_continue_keystroke(reload_first=not reloaded):
        details.append("sent reload and 'continue' to the OpenCode window")
        return True, " | ".join(details)

    oc = find_opencode_cli()
    if oc:
        sess = get_latest_session_info()
        if _dispatch_cli_resume(oc, sess):
            target = f"session {sess[0][:8]}..." if sess else "last session"
            details.append(f"dispatched CLI continue to {target}")
            return True, " | ".join(details)

    if cleared > 0 or reloaded:
        return False, (
            " | ".join(details) + " but no OpenCode window or session was available | " + RELOAD_HINT
        )
    return False, "No active session or window found to resume."
