"""Shared paths, process helpers, WARP controls, and IPv6 utilities for Windows."""

from __future__ import annotations

import contextlib
import ctypes
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Iterator

BRAND = "opencode-unlimited"
CREATE_NO_WINDOW = 0x08000000

LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
DEST_DIR = LOCAL_APPDATA / BRAND
SCRIPTS_DIR = DEST_DIR / "scripts"
BIN_DIR = DEST_DIR / "bin"
GUARD_DIR = DEST_DIR / "guard"
KEEPER_DIR = DEST_DIR / "keeper"
LANE_DIR = DEST_DIR / "lane"

PAUSE_FILE = DEST_DIR / "keeper.pause"
GUARD_STATE_FILE = GUARD_DIR / "state.json"
GUARD_LOG_FILE = GUARD_DIR / "guard.log"
KEEPER_LOG_FILE = KEEPER_DIR / "keeper.log"
OPENCODE_LOG_FILE = Path.home() / ".local" / "share" / "opencode" / "log" / "opencode.log"

TASK_KEEPER = "OpencodeUnlimited-Keeper"
TASK_GUARD = "OpencodeUnlimited-Guard"
FW_RULE_PREFIX = "OUC_LEAKGUARD_"
SERVICE_PROXY_PORT = int(os.environ.get("OUC_SERVICE_PROXY_PORT", "41987"))

_WARP_CANDIDATES = (
    Path(r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"),
    Path(r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe"),
    LOCAL_APPDATA / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe",
)

_OPENCODE_CANDIDATES = (
    LOCAL_APPDATA / "Programs" / "ai.opencode.desktop" / "resources" / "opencode-cli.exe",
    Path.home() / ".opencode" / "bin" / "opencode.exe",
    LOCAL_APPDATA / "opencode" / "opencode.exe",
    Path.home() / ".bun" / "bin" / "opencode.exe",
    Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "npm" / "opencode.cmd",
)

_FALLBACK_OPENCODE_AAAA = (
    "2606:4700::6810:7f60",
    "2606:4700::6810:8060",
    "2606:4700::6810:84e5",
    "2606:4700::6810:85e5",
    "2606:4700::6811:d209",
    "2606:4700::6812:a42",
    "2606:4700::6812:b42",
    "2606:4700:10::6814:2011",
    "2606:4700:10::6814:2111",
    "2606:4700:10::6814:2211",
    "2606:4700:10::6814:2311",
    "2606:4700:10::ac42:ad95",
    "2606:4700:10::ac42:ad96",
    "2606:4700:10::ac42:ad97",
    "2606:4700:10::ac42:ad98",
    "2606:4700:20::681a:641",
    "2606:4700:20::681a:741",
    "2606:4700:20::681a:841",
    "2606:4700:20::681a:941",
    "2606:4700:30::6818:101",
    "2606:4700:30::6818:201",
    "2606:4700:30::6818:301",
    "2606:4700:30::6818:401",
    "2606:4700:30::ac43:8001",
    "2606:4700:30::ac43:8002",
    "2606:4700:30::ac43:9001",
    "2606:4700:30::ac43:9002",
    "2606:4700:30::ac43:a001",
    "2606:4700:30::ac43:a002",
    "2606:4700:31::a29f:8001",
    "2606:4700:31::a29f:8002",
    "2606:4700:31::a29f:9001",
    "2606:4700:31::a29f:9002",
    "2606:4700:e0::ac40:9001",
    "2606:4700:e0::ac40:9002",
)

_IPV6_RE = re.compile(r"\b([0-9a-fA-F:]+:[0-9a-fA-F:]+)\b")


def ensure_dirs() -> None:
    """Create state and log directories if missing."""
    for d in (DEST_DIR, SCRIPTS_DIR, BIN_DIR, GUARD_DIR, KEEPER_DIR, LANE_DIR):
        d.mkdir(parents=True, exist_ok=True)


def run_hidden(
    args: list[str],
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess without spawning a visible Windows console window."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )


def find_warp_cli() -> str | None:
    """Locate Cloudflare warp-cli.exe."""
    env_bin = os.environ.get("OUC_WARP_BIN", "").strip()
    if env_bin and Path(env_bin).is_file():
        return env_bin
    on_path = shutil.which("warp-cli")
    if on_path:
        return on_path
    for candidate in _WARP_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    return None


def find_opencode_cli() -> str | None:
    """Locate the real opencode CLI binary, skipping wrapper shims."""
    env_bin = os.environ.get("OUC_REAL_BIN", "").strip()
    if env_bin and Path(env_bin).is_file():
        return env_bin

    # 1. Check running processes first
    try:
        import psutil
        for p in psutil.process_iter(["name", "exe"]):
            try:
                name = (p.info["name"] or "").lower()
                exe = p.info["exe"] or ""
                if ("opencode-cli" in name or name == "opencode.exe") and BRAND not in exe.lower():
                    if Path(exe).is_file():
                        return str(exe)
            except Exception:
                pass
    except Exception:
        pass

    # 2. Check standard candidate paths
    for candidate in _OPENCODE_CANDIDATES:
        if candidate.is_file():
            return str(candidate)

    # 3. Check AppData Roaming CLI versions
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    cli_dir = appdata / "ai.opencode.desktop" / "cli"
    if cli_dir.is_dir():
        for p in sorted(cli_dir.rglob("opencode-cli.exe"), reverse=True):
            if p.is_file():
                return str(p)

    # 4. PATH lookup
    for name in ("opencode.exe", "opencode"):
        found = shutil.which(name)
        if not found:
            continue
        low = found.lower()
        if BRAND in low or "opencode-infinite" in low:
            continue
        return found
    return None


def find_opencode_desktop() -> str | None:
    """Locate OpenCode Desktop GUI executable if installed."""
    # 1. Check running processes first
    try:
        import psutil
        for p in psutil.process_iter(["name", "exe"]):
            try:
                name = (p.info["name"] or "").lower()
                exe = p.info["exe"] or ""
                if name == "opencode.exe" and BRAND not in exe.lower():
                    if Path(exe).is_file():
                        return str(exe)
            except Exception:
                pass
    except Exception:
        pass

    candidates = (
        LOCAL_APPDATA / "Programs" / "ai.opencode.desktop" / "OpenCode.exe",
        LOCAL_APPDATA / "Programs" / "OpenCode" / "OpenCode.exe",
        LOCAL_APPDATA / "OpenCode" / "OpenCode.exe",
        Path(r"C:\Program Files\OpenCode\OpenCode.exe"),
        Path(r"C:\Program Files\ai.opencode.desktop\OpenCode.exe"),
        Path(r"C:\Program Files (x86)\OpenCode\OpenCode.exe"),
        Path(r"C:\Program Files (x86)\ai.opencode.desktop\OpenCode.exe"),
    )
    for c in candidates:
        if c.is_file():
            return str(c)

    # 3. Check Desktop and Start Menu shortcuts (.lnk)
    try:
        import win32com.client
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut_dirs = (
            Path.home() / "Desktop",
            Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
        )
        for sdir in shortcut_dirs:
            if sdir.is_dir():
                for lnk in sdir.rglob("*opencode*.lnk"):
                    if "unlimited" in lnk.name.lower() or "infinite" in lnk.name.lower():
                        continue
                    try:
                        sc = shell.CreateShortCut(str(lnk))
                        target_path = sc.Targetpath
                        if target_path and Path(target_path).is_file() and target_path.lower().endswith("opencode.exe"):
                            return str(target_path)
                    except Exception:
                        pass
    except Exception:
        pass

    return None


def run_warp(
    args: list[str],
    warp_bin: str | None = None,
    timeout: float = 15.0,
) -> tuple[int, str]:
    """Invoke warp-cli.exe, probing --accept-tos first then falling back."""
    exe = warp_bin or find_warp_cli()
    if not exe:
        return 1, "warp-cli.exe not found"

    for attempt in ([exe, "--accept-tos", *args], [exe, *args]):
        try:
            res = run_hidden(attempt, timeout=timeout)
            out = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
            if res.returncode == 0:
                return 0, out.strip()
        except Exception as exc:
            out = str(exc)
    return 1, out.strip()


def warp_mode(warp_bin: str | None = None) -> str:
    """Return current WARP operation_mode from settings JSON (e.g. 'warp')."""
    rc, out = run_warp(["-j", "settings", "list"], warp_bin=warp_bin, timeout=6.0)
    if rc == 0 and out.startswith("{"):
        try:
            data = json.loads(out)
            op = data.get("settings", {}).get("operation_mode") or data.get("operation_mode")
            if isinstance(op, str):
                return op
            if isinstance(op, dict):
                return ",".join(op.keys())
        except Exception:
            pass
    return ""


def warp_status(warp_bin: str | None = None) -> tuple[bool, str, str]:
    """Return (is_connected, mode_name, raw_text) for WARP."""
    rc, out = run_warp(["-j", "status"], warp_bin=warp_bin, timeout=8.0)
    if rc == 0 and out.startswith("{"):
        try:
            data = json.loads(out)
            status = str(data.get("status", ""))
            connected = status.lower() == "connected"
            mode = ""
            reason = data.get("reason")
            if isinstance(reason, dict):
                cur = (
                    reason.get("SettingsChanged", {}).get("current", {})
                    if isinstance(reason.get("SettingsChanged"), dict)
                    else {}
                )
                op_mode = cur.get("operation_mode")
                if isinstance(op_mode, str):
                    mode = op_mode
                elif isinstance(op_mode, dict):
                    mode = ",".join(op_mode.keys())
            if not mode:
                mode = warp_mode(warp_bin=warp_bin)
            return connected, mode, status
        except Exception:
            pass

    rc2, out2 = run_warp(["status"], warp_bin=warp_bin, timeout=8.0)
    first = out2.splitlines()[0] if out2 else ""
    connected = rc2 == 0 and "Connected" in first and "Disconnected" not in first
    return connected, "", first


def is_cloudflare_v6(addr: str) -> bool:
    """Return True if IPv6 address belongs to Cloudflare/WARP global ranges."""
    try:
        ip = ipaddress.IPv6Address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_private:
        return False
    low = ip.exploded.lower()
    return low.startswith(("2606:", "2a09:"))


def get_warp_local_v6() -> str | None:
    """Return the active CloudflareWARP adapter global IPv6 address, or None."""
    try:
        res = run_hidden(
            ["netsh", "interface", "ipv6", "show", "addresses", "CloudflareWARP"],
            timeout=5.0,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                m = _IPV6_RE.search(line)
                if not m:
                    continue
                cand = m.group(1).split("%", 1)[0]
                try:
                    ip = ipaddress.IPv6Address(cand)
                except ValueError:
                    continue
                if ip.is_link_local or ip.is_loopback or ip.is_multicast:
                    continue
                if is_cloudflare_v6(str(ip)) or ip.is_global:
                    return str(ip)
    except Exception:
        pass
    return None


def get_egress_v6(timeout: float = 8.0) -> str:
    """Query external IPv6 egress via curl.exe or urllib."""
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if curl:
        try:
            res = run_hidden(
                [curl, "-x", "socks5h://127.0.0.1:40000", "-s", "-m", str(int(timeout)), "https://api64.ipify.org"],
                timeout=timeout + 2.0,
            )
            ip = res.stdout.strip()
            if ip and ":" in ip:
                ipaddress.IPv6Address(ip)
                return ip
        except Exception:
            pass

        try:
            res = run_hidden(
                [curl, "-6", "-s", "-m", str(int(timeout)), "https://api64.ipify.org"],
                timeout=timeout + 2.0,
            )
            ip = res.stdout.strip()
            if ip and ":" in ip:
                ipaddress.IPv6Address(ip)
                return ip
        except Exception:
            pass

    try:
        req = urllib.request.Request("https://api64.ipify.org", headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ip = resp.read().decode("utf-8", errors="replace").strip()
            if ":" in ip:
                ipaddress.IPv6Address(ip)
                return ip
    except Exception:
        pass
    return ""


def normalize_v6_64(addr: str) -> str:
    """Normalize an IPv6 address to its /64 network prefix string."""
    clean = addr.strip().split("%", 1)[0]
    if not clean or ":" not in clean:
        return ""
    try:
        net = ipaddress.IPv6Network(f"{clean}/64", strict=False)
        return str(net.network_address)
    except ValueError:
        return ""


def is_keeper_paused() -> bool:
    """Check if zen-guard or zen-hop currently holds a valid pause lock."""
    if not PAUSE_FILE.is_file():
        return False
    try:
        data = json.loads(PAUSE_FILE.read_text(encoding="utf-8"))
        until = float(data.get("until", 0))
        if time.time() < until:
            return True
        PAUSE_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    return False


@contextlib.contextmanager
def keeper_pause_ctx(reason: str, seconds: int = 180) -> Iterator[None]:
    """Temporarily pause warp-keeper ticks while rotating WARP registration."""
    ensure_dirs()
    payload = {"until": time.time() + seconds, "reason": reason, "pid": os.getpid()}
    try:
        PAUSE_FILE.write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        pass
    try:
        yield
    finally:
        try:
            PAUSE_FILE.unlink(missing_ok=True)
        except Exception:
            pass


def acquire_mutex(name: str) -> int | None:
    """Acquire a named Windows mutex; returns handle if newly owned, else None."""
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    handle = kernel32.CreateMutexW(None, False, f"Local\\{name}")
    if not handle:
        return None
    err = kernel32.GetLastError()
    ERROR_ALREADY_EXISTS = 183
    if err == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return None
    return int(handle)


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def append_log(path: Path, message: str, max_bytes: int = 1_048_576) -> None:
    """Append timestamped log line with simple single-backup rotation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.is_file() and path.stat().st_size > max_bytes:
            bak = path.with_suffix(path.suffix + ".1")
            if bak.is_file():
                bak.unlink()
            path.rename(bak)
    except Exception:
        pass
    stamp = time.strftime("%m-%d %H:%M:%S")
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"{stamp} {message}\n")
    except Exception:
        pass


def fetch_opencode_aaaa_pool() -> list[str]:
    """Gather live IPv6 addresses for opencode.ai via DoH, system DNS, and fallback."""
    pool: set[str] = set()

    for doh_url in (
        "https://1.1.1.1/dns-query?name=opencode.ai&type=AAAA",
        "https://1.0.0.1/dns-query?name=opencode.ai&type=AAAA",
        "https://dns.google/resolve?name=opencode.ai&type=AAAA",
    ):
        try:
            req = urllib.request.Request(doh_url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            for ans in data.get("Answer", []):
                if ans.get("type") == 28:
                    ip = str(ans.get("data", "")).strip()
                    ipaddress.IPv6Address(ip)
                    pool.add(ip)
        except Exception:
            pass

    import socket

    for host in ("opencode.ai", "api.opencode.ai"):
        try:
            for info in socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM):
                ip = info[4][0].split("%", 1)[0]
                ipaddress.IPv6Address(ip)
                pool.add(ip)
        except Exception:
            pass

    pool.update(_FALLBACK_OPENCODE_AAAA)
    return sorted(pool)


def hop_once(warp_bin: str, max_reg_tries: int = 3) -> str:
    """Perform one WARP registration rotation and return the new external IPv6."""
    run_warp(["disconnect"], warp_bin=warp_bin)
    time.sleep(0.8)
    run_warp(["registration", "delete"], warp_bin=warp_bin)
    time.sleep(0.8)

    registered = False
    for attempt in range(max_reg_tries):
        rc, _ = run_warp(["registration", "new"], warp_bin=warp_bin)
        if rc == 0:
            registered = True
            break
        if attempt + 1 < max_reg_tries:
            time.sleep(6)

    if not registered:
        return ""

    scope = "isolated"
    try:
        from proxy_chain import get_egress_config
        scope = get_egress_config().get("warp_scope", "isolated")
    except Exception:
        pass

    time.sleep(1.2)
    if scope == "isolated":
        run_warp(["proxy", "port", "40000"], warp_bin=warp_bin)
        run_warp(["mode", "proxy"], warp_bin=warp_bin)
    else:
        run_warp(["mode", "warp"], warp_bin=warp_bin)
    time.sleep(0.5)
    run_warp(["connect"], warp_bin=warp_bin)

    for idx in range(12):
        time.sleep(3)
        connected, _, _ = warp_status(warp_bin)
        if not connected:
            if idx in (2, 5):
                run_warp(["connect"], warp_bin=warp_bin)
            continue
        v6 = get_egress_v6(timeout=5.0)
        if v6:
            return v6
        local_v6 = get_warp_local_v6()
        if local_v6 and is_cloudflare_v6(local_v6):
            return local_v6
    return ""
