"""Auto-Resume module for OpenCode Unlimited.

Automatically detects when a rate limit is bypassed, and dispatches a 'continue'
action to the active OpenCode session (via OpenCode CLI or keystroke to Desktop/Terminal),
so the model continues generating autonomously while the user is away from their PC.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import time
from pathlib import Path

from ouc_common import LANE_DIR, find_opencode_cli

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


def get_latest_session_info() -> tuple[str, str, str] | None:
    """Query opencode.db for the most recently active non-archived session.

    Returns (session_id, directory, title) or None.
    """
    db_path = Path.home() / ".local" / "share" / "opencode" / "opencode.db"
    if not db_path.is_file():
        return None
    try:
        conn = sqlite3.connect(str(db_path), timeout=3.0)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, directory, title FROM session_v2 "
            "WHERE time_archived IS NULL "
            "ORDER BY time_updated DESC LIMIT 1"
        )
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            return str(row[0]), str(row[1] or ""), str(row[2] or "")
    except Exception:
        pass
    return None


def send_continue_keystroke() -> bool:
    """Send 'continue{ENTER}' to any active OpenCode Desktop or Terminal window."""
    # 1. Native Windows Win32 API window focus and key dispatch
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        target_hwnds = []

        def _enum_cb(hwnd, _):
            if user32.IsWindowVisible(hwnd):
                length = user32.GetWindowTextLengthW(hwnd)
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value.lower()
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                pname = ""
                try:
                    import psutil
                    pname = psutil.Process(pid.value).name().lower()
                except Exception:
                    pass
                if "opencode" in pname or "opencode" in title or "terminal" in pname or "terminal" in title:
                    target_hwnds.append((hwnd, buf.value, pname))
            return True

        CB_TYPE = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows(CB_TYPE(_enum_cb), 0)

        for hwnd, title, pname in target_hwnds:
            # SW_RESTORE = 9
            user32.ShowWindow(hwnd, 9)
            user32.SetForegroundWindow(hwnd)
            time.sleep(0.3)
            ps_send = """
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.SendKeys]::SendWait("continue{ENTER}")
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

    # 2. PowerShell WScript.Shell AppActivate fallback
    ps = """
    $ws = New-Object -ComObject WScript.Shell
    $targets = @("OpenCode", "opencode", "ai.opencode", "Terminal", "PowerShell", "Command Prompt", "Alacritty")
    $sent = $false
    foreach ($t in $targets) {
        if ($ws.AppActivate($t)) {
            Start-Sleep -Milliseconds 300
            $ws.SendKeys("continue{ENTER}")
            $sent = $true
            break
        }
    }
    if ($sent) { Write-Output "SENT" } else { Write-Output "NOT_FOUND" }
    """
    try:
        CREATE_NO_WINDOW = 0x08000000
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=5.0,
            creationflags=CREATE_NO_WINDOW,
        )
        return "SENT" in res.stdout
    except Exception:
        return False


def resume_active_session() -> tuple[bool, str]:
    """Resume the active OpenCode session with a 'continue' prompt."""
    if not is_auto_resume_enabled():
        return False, "Auto-resume is disabled."

    oc = find_opencode_cli()
    sess = get_latest_session_info()
    cli_dispatched = False
    details = []

    # 1. Attempt CLI session resume if a session exists
    if oc and sess:
        sess_id, directory, title = sess
        cmd = [oc, "run", "--session", sess_id, "continue"]
        cwd = directory if (directory and os.path.isdir(directory)) else None
        try:
            CREATE_NO_WINDOW = 0x08000000
            DETACHED_PROCESS = 0x00000008
            subprocess.Popen(
                cmd,
                cwd=cwd,
                creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                close_fds=True,
            )
            cli_dispatched = True
            details.append(f"dispatched CLI resume to session {sess_id[:8]}... ({title or 'active'})")
        except Exception as exc:
            details.append(f"CLI resume attempt failed: {exc}")
    elif oc:
        try:
            CREATE_NO_WINDOW = 0x08000000
            DETACHED_PROCESS = 0x00000008
            subprocess.Popen(
                [oc, "run", "--continue", "continue"],
                creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                close_fds=True,
            )
            cli_dispatched = True
            details.append("dispatched generic CLI continue")
        except Exception:
            pass

    # 2. Also send keystroke to any interactive OpenCode GUI or terminal window
    win_sent = send_continue_keystroke()
    if win_sent:
        details.append("sent keystroke 'continue' to active OpenCode window")

    if cli_dispatched or win_sent:
        return True, " ✓ ".join(details)
    return False, "No active session or window found to resume."
