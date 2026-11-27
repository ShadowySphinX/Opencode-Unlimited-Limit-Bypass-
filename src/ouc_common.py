"""Shared paths, process helpers, WARP controls, and IPv6 utilities."""

from __future__ import annotations

import contextlib
import ctypes
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Any
from pathlib import Path
from typing import Iterator

BRAND = "opencode-unlimited"
CREATE_NO_WINDOW = 0x08000000


def _default_data_root() -> Path:
    """Return the per-user state root for this platform."""
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))


LOCAL_APPDATA = _default_data_root()
DEST_DIR = LOCAL_APPDATA / BRAND
SCRIPTS_DIR = DEST_DIR / "scripts"
BIN_DIR = (
    DEST_DIR / "bin"
    if sys.platform == "win32"
    else Path(os.environ.get("XDG_BIN_HOME", Path.home() / ".local" / "bin"))
)
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
# The OpenCode background service reads its proxy from this file and rewrites
# it on its own, so either spelling of a key can be in there.
SERVICE_FILE = Path.home() / ".config" / "opencode" / "service.json"
SERVICE_PROXY_KEYS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")

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


def service_proxy_wired(port: int | None = None) -> bool:
    """True when OpenCode's service env sends HTTPS through the local proxy."""
    port = SERVICE_PROXY_PORT if port is None else port
    try:
        cfg = json.loads(SERVICE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    env = cfg.get("env") if isinstance(cfg, dict) else None
    if not isinstance(env, dict):
        return False
    needle = f"127.0.0.1:{port}"
    return any(needle in str(env.get(key, "")) for key in SERVICE_PROXY_KEYS)


def ensure_dirs() -> None:
    """Create state and log directories if missing."""
    for d in (DEST_DIR, SCRIPTS_DIR, BIN_DIR, GUARD_DIR, KEEPER_DIR, LANE_DIR):
        d.mkdir(parents=True, exist_ok=True)


def run_hidden(
    args: list[str],
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess without spawning a visible console window on Windows."""
    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = CREATE_NO_WINDOW
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        # warp-cli and opencode print UTF-8 while a Windows console defaults to
        # a legacy code page; a strict locale decode would raise on non-ASCII.
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        **kwargs,
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
    """Locate the OpenCode CLI binary, skipping the Desktop GUI executable."""
    env_bin = os.environ.get("OUC_REAL_BIN", "").strip()
    if env_bin and Path(env_bin).is_file():
        return env_bin

    # The Desktop GUI also runs as OpenCode.exe. Only accept a running
    # opencode-cli/host CLI process, or an opencode.exe outside the Desktop
    # installation directory.
    try:
        import psutil
        for p in psutil.process_iter(["name", "exe"]):
            try:
                name = (p.info["name"] or "").lower()
                exe = p.info["exe"] or ""
                low = exe.lower()
                if not exe or BRAND in low:
                    continue
                if "opencode-cli" in name:
                    if Path(exe).is_file():
                        return str(exe)
                elif name == "opencode.exe" and "ai.opencode.desktop" not in low:
                    if Path(exe).is_file():
                        return str(exe)
            except Exception:
                pass
    except Exception:
        pass

    # Desktop-managed CLI versions live under Roaming\ai.opencode.desktop\cli.
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    cli_dir = appdata / "ai.opencode.desktop" / "cli"
    if cli_dir.is_dir():
        paths: list[Path] = []
        for p in cli_dir.rglob("opencode-cli.exe"):
            try:
                if p.is_file():
                    paths.append(p)
            except OSError:
                pass
        if paths:
            return str(max(paths, key=lambda p: p.stat().st_mtime))

    for candidate in _OPENCODE_CANDIDATES:
        if candidate.is_file():
            return str(candidate)

    for name in ("opencode.exe", "opencode"):
        hit = shutil.which(name)
        if not hit:
            continue
        low = hit.lower()
        if BRAND in low or "opencode-infinite" in low or "unlimited" in low:
            continue
        if "ai.opencode.desktop" in low and not low.endswith("opencode-cli.exe"):
            continue
        return hit
    return None


def opencode_command(exe: str, args: list[str]) -> list[str]:
    """Return an executable argument list that also works for .cmd shims."""
    if exe.lower().endswith((".cmd", ".bat")):
        return [os.environ.get("COMSPEC", "cmd.exe"), "/c", exe, *args]
    return [exe, *args]


def find_opencode_service_port() -> int | None:
    """Return the port of the running OpenCode background service, if any."""
    exe = find_opencode_cli()
    if not exe:
        return None
    try:
        res = run_hidden(opencode_command(exe, ["service", "status"]), timeout=6.0)
        text = (res.stdout or "") + (res.stderr or "")
        match = re.search(r"127\.0\.0\.1:(\d{2,5})", text)
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return None


def find_opencode_desktop() -> str | None:
    """Locate the OpenCode Desktop GUI executable if installed."""
    try:
        import psutil
        for p in psutil.process_iter(["name", "exe"]):
            try:
                name = (p.info["name"] or "").lower()
                exe = p.info["exe"] or ""
                if name == "opencode.exe" and "ai.opencode.desktop" in exe.lower():
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


_WARP_STATUS_CACHE: dict[str, tuple[float, tuple[bool, str, str]]] = {}
_WARP_STATUS_LOCK = threading.Lock()
_WARP_MODE_CACHE: dict[str, tuple[float, str]] = {}

_WARP_STATE_ARGS = {
    "connect",
    "disconnect",
    "registration",
    "mode",
    "tunnel",
    "proxy",
    "settings",
}


def run_warp(
    args: list[str],
    warp_bin: str | None = None,
    timeout: float = 15.0,
) -> tuple[int, str]:
    """Invoke warp-cli.exe, probing --accept-tos first then falling back."""
    exe = warp_bin or find_warp_cli()
    if not exe:
        return 1, "warp-cli.exe not found"

    out = ""
    rc = 1
    for attempt in ([exe, "--accept-tos", *args], [exe, *args]):
        try:
            res = run_hidden(attempt, timeout=timeout)
            out = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
            rc = res.returncode
            if rc == 0:
                break
        except Exception as exc:
            out = str(exc)
            rc = 1

    if rc == 0 and any(a in _WARP_STATE_ARGS for a in args):
        with _WARP_STATUS_LOCK:
            _WARP_STATUS_CACHE.clear()
            _WARP_MODE_CACHE.clear()
    return rc, out.strip()


def warp_mode(warp_bin: str | None = None) -> str:
    """Return the current WARP operation mode (warp or proxy)."""
    exe = warp_bin or find_warp_cli() or ""
    now = time.monotonic()
    with _WARP_STATUS_LOCK:
        cached = _WARP_MODE_CACHE.get(exe)
        if cached and now - cached[0] < 5.0:
            return cached[1]

    mode = ""
    rc, out = run_warp(["-j", "settings"], warp_bin=warp_bin, timeout=6.0)
    if rc == 0 and "{" in out:
        try:
            data = json.loads(out[out.find("{"): out.rfind("}") + 1])
            settings = data.get("settings")
            if not isinstance(settings, dict):
                settings = data
            op = settings.get("operation_mode")
            if isinstance(op, str):
                mode = op
            elif isinstance(op, dict):
                mode = ",".join(op.keys())
        except Exception:
            pass
    if not mode:
        rc2, out2 = run_warp(["settings"], warp_bin=warp_bin, timeout=5.0)
        if rc2 == 0:
            for line in out2.splitlines():
                if "mode" in line.lower() and ":" in line:
                    value = line.rsplit(":", 1)[1].strip().lower()
                    if value in ("warp", "proxy", "dns_only", "tunnel_only"):
                        mode = value
                        break
    with _WARP_STATUS_LOCK:
        _WARP_MODE_CACHE[exe] = (time.monotonic(), mode)
    return mode


def get_warp_protocol(warp_bin: str | None = None) -> str:
    """Return current WARP protocol (e.g. 'wireguard' or 'masque') in lowercase."""
    rc, out = run_warp(["-j", "settings"], warp_bin=warp_bin, timeout=5.0)
    if rc == 0 and "{" in out:
        try:
            data = json.loads(out[out.find("{"): out.rfind("}") + 1])
            settings = data.get("settings")
            if not isinstance(settings, dict):
                settings = data
            proto = str(settings.get("warp_tunnel_protocol", "")).lower().strip()
            if proto:
                return proto
        except Exception:
            pass
    rc2, out2 = run_warp(["settings"], warp_bin=warp_bin, timeout=5.0)
    if rc2 == 0 and out2:
        for line in out2.splitlines():
            if "protocol" in line.lower():
                if "wireguard" in line.lower():
                    return "wireguard"
                if "masque" in line.lower():
                    return "masque"
    return ""


def ensure_warp_protocol(desired: str = "wireguard", warp_bin: str | None = None) -> bool:
    """Set the WARP tunnel protocol only when it differs from the requested one."""
    want = desired.strip().lower()
    if want not in ("wireguard", "masque"):
        return False
    current = get_warp_protocol(warp_bin=warp_bin)
    if current == want:
        return True
    label = "WireGuard" if want == "wireguard" else "MASQUE"
    rc, _ = run_warp(["tunnel", "protocol", "set", label], warp_bin=warp_bin, timeout=10.0)
    if rc == 0:
        with _WARP_STATUS_LOCK:
            _WARP_MODE_CACHE.clear()
    return rc == 0


def warp_protocol_for_scope(scope: str) -> str:
    """Return the tunnel protocol the selected scope can actually use.

    Cloudflare's client refuses proxy mode on WireGuard with "Proxy mode only
    supports MASQUE", so app-only has to run MASQUE. Full TUN keeps the
    WireGuard path the endpoint and rotation code expect.
    """
    return "masque" if str(scope).strip().lower() == "isolated" else "wireguard"


def warp_status(warp_bin: str | None = None, force: bool = False) -> tuple[bool, str, str]:
    """Return (is_connected, mode_name, status_text) for WARP."""
    exe = warp_bin or find_warp_cli() or ""
    now = time.monotonic()
    if not force:
        with _WARP_STATUS_LOCK:
            cached = _WARP_STATUS_CACHE.get(exe)
            if cached and now - cached[0] < 1.0:
                return cached[1]

    connected = False
    mode = ""
    status_text = "Disconnected"
    rc, out = run_warp(["-j", "status"], warp_bin=warp_bin, timeout=6.0)
    if rc == 0 and "{" in out:
        try:
            data = json.loads(out[out.find("{"): out.rfind("}") + 1])
            status_text = str(data.get("status", "")).strip() or status_text
            connected = status_text.lower() == "connected"
            reason = data.get("reason")
            if isinstance(reason, dict):
                current = reason.get("SettingsChanged")
                if isinstance(current, dict) and isinstance(current.get("current"), dict):
                    op_mode = current["current"].get("operation_mode")
                    if isinstance(op_mode, str):
                        mode = op_mode
                    elif isinstance(op_mode, dict):
                        mode = ",".join(op_mode.keys())
            if not mode:
                mode = warp_mode(warp_bin=warp_bin)
            if not connected and reason:
                detail = reason if isinstance(reason, str) else json.dumps(reason, ensure_ascii=True)
                status_text = f"{status_text}: {detail}"
        except Exception:
            pass
    else:
        rc2, out2 = run_warp(["status"], warp_bin=warp_bin, timeout=6.0)
        first = ""
        for line in (out2 or "").splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            low = line_s.lower()
            if "status" in low or "connected" in low:
                if not first:
                    first = line_s
                if "connected" in low and "disconnected" not in low:
                    connected = True
                    first = line_s
                    break
        if first:
            status_text = first
        mode = warp_mode(warp_bin=warp_bin)

    result = (connected, mode, status_text)
    with _WARP_STATUS_LOCK:
        _WARP_STATUS_CACHE[exe] = (time.monotonic(), result)
    return result


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
    """Return the active WARP adapter global IPv6 address, or None."""
    # Adapter names are localized on some Windows installs; match the
    # interface by its owner (Cloudflare/WARP) instead of a fixed label.
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            low = name.lower()
            if "warp" not in low and "cloudflare" not in low:
                continue
            for addr in addrs:
                if addr.family != socket.AF_INET6:
                    continue
                cand = str(addr.address).split("%", 1)[0]
                try:
                    ip = ipaddress.IPv6Address(cand)
                except ValueError:
                    continue
                if ip.is_link_local or ip.is_loopback or ip.is_multicast:
                    continue
                return str(ip)
    except Exception:
        pass

    # Fallback for systems without psutil or with a renamed adapter.
    try:
        res = run_hidden(
            ["netsh", "interface", "ipv6", "show", "addresses"],
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
                if is_cloudflare_v6(str(ip)):
                    return str(ip)
    except Exception:
        pass
    return None


_EGRESS_ENDPOINTS = (
    # Measured first because it is the host the model traffic goes to. A trace
    # from another Cloudflare host can take a different route and report an
    # address that the inference path never uses.
    "https://opencode.ai/cdn-cgi/trace",
    "https://api64.ipify.org",
    "https://cloudflare.com/cdn-cgi/trace",
    "https://1.1.1.1/cdn-cgi/trace",
)


def _valid_public_ip(text: str) -> str:
    """Return a normalized public IP address from text, or an empty string."""
    cand = text.strip().split("%", 1)[0]
    if not cand or len(cand) > 64 or any(ch in cand for ch in " <>\"'"):
        return ""
    try:
        ip = ipaddress.ip_address(cand)
    except ValueError:
        return ""
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return ""
    return str(ip)


def _parse_egress_body(text: str) -> str:
    """Extract an address from ipify output or a Cloudflare trace body."""
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("ip="):
            found = _valid_public_ip(line.split("=", 1)[1])
            if found:
                return found
    return _valid_public_ip(text or "")


def _curl_egress(curl: str, proxy: str, ipv6: bool, timeout: float, insecure: bool = False) -> str:
    """Probe a public IP echo service, optionally through a proxy."""
    for endpoint in _EGRESS_ENDPOINTS:
        args = [curl, "-sS", "--max-time", str(max(2, int(timeout)))]
        if ipv6:
            args.append("-6")
        if proxy:
            args.extend(["-x", proxy])
            if insecure and proxy.lower().startswith("https://"):
                args.append("--proxy-insecure")
        else:
            # curl honours http(s)_proxy from the environment, which would send
            # a "direct" probe through a proxy and report the wrong exit.
            args.extend(["--noproxy", "*"])
        args.append(endpoint)
        try:
            res = run_hidden(args, timeout=timeout + 1.5)
        except Exception:
            continue
        found = _parse_egress_body(res.stdout)
        if found:
            return found
    return ""


def _proxy_url(
    host: str,
    port: int,
    proxy_type: str = "socks5",
    username: str = "",
    password: str = "",
    use_tls: bool = False,
) -> str:
    """Build a curl proxy URL, including credentials when configured."""
    from urllib.parse import quote

    if proxy_type.lower().startswith("socks"):
        scheme = "socks5h"
    else:
        scheme = "https" if use_tls else "http"
    auth = ""
    if username:
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return f"{scheme}://{auth}{host}:{port}"


def probe_proxy_egress(proxy_url: str, timeout: float = 6.0, insecure: bool = False) -> str:
    """Return the public address seen through ``proxy_url``, or an empty string.

    Used when the exit has to be confirmed against a specific pool node, not
    whichever node the persisted index happens to point at.
    """
    if not proxy_url:
        return ""
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        return ""
    return _curl_egress(curl, proxy_url, False, timeout, insecure)


def get_egress_ip(timeout: float = 6.0) -> str:
    """Return the public egress IP of the active route, or an empty string."""
    mode = "warp"
    scope = "tun" if sys.platform == "win32" else "isolated"
    try:
        from proxy_chain import get_egress_config

        cfg = get_egress_config()
        mode = str(cfg.get("mode", "warp"))
        scope = str(cfg.get("warp_scope", scope))
    except Exception:
        pass

    curl = shutil.which("curl.exe") or shutil.which("curl")
    if curl:
        if mode == "tor":
            ports: list[int] = []
            try:
                from tor_manager import get_active_tor_target

                target = get_active_tor_target()
                if target:
                    ports.append(int(target[1]))
            except Exception:
                pass
            for port in [*ports, 9050, 9150]:
                found = _curl_egress(
                    curl, f"socks5h://127.0.0.1:{port}", False, timeout
                )
                if found:
                    return found
        elif mode == "custom":
            proxy = ""
            insecure = False
            try:
                from proxy_chain import get_current_proxy_spec, relay_tls_insecure

                spec = get_current_proxy_spec()
                proxy = _proxy_url(
                    spec.get("host", "127.0.0.1"),
                    int(spec.get("port", 10808)),
                    str(spec.get("type", "socks5")),
                    str(spec.get("username", "")),
                    str(spec.get("password", "")),
                    bool(spec.get("tls")),
                )
                insecure = bool(spec.get("tls")) and relay_tls_insecure()
            except Exception:
                proxy = ""
            if proxy:
                found = _curl_egress(curl, proxy, False, timeout, insecure)
                if found:
                    return found
        else:
            if scope == "isolated":
                found = _curl_egress(
                    curl, "socks5h://127.0.0.1:40000", False, timeout
                )
                if found:
                    return found
            found = _curl_egress(curl, "", True, timeout)
            if found:
                return found

    # Direct HTTP fallback is only valid for a native WARP tunnel.
    if mode in ("warp", "clean") and scope != "isolated":
        for endpoint in _EGRESS_ENDPOINTS:
            try:
                req = urllib.request.Request(
                    endpoint, headers={"User-Agent": "curl/8.0"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    found = _parse_egress_body(
                        resp.read().decode("utf-8", errors="replace")
                    )
                if found:
                    return found
            except Exception:
                pass
    return ""


def get_egress_v6(timeout: float = 6.0) -> str:
    """Return the public IPv6 egress address for WARP, or an empty string."""
    mode = "warp"
    try:
        from proxy_chain import get_egress_config

        mode = str(get_egress_config().get("mode", "warp"))
    except Exception:
        pass
    if mode not in ("warp", "clean"):
        return ""

    egress = get_egress_ip(timeout=timeout)
    if ":" in egress:
        return egress

    local = get_warp_local_v6()
    if local and is_cloudflare_v6(local):
        return local
    return ""


def get_public_v6(timeout: float = 6.0) -> str:
    """Return the public IPv6 address the far side sees, or an empty string.

    The WARP adapter keeps its IPv6 address when the tunnel stops carrying
    traffic, so the adapter address is not proof that IPv6 works. Rotation must
    be confirmed with the address observed from outside; otherwise a failed hop
    looks successful while every request quietly leaves over IPv4.
    """
    egress = get_egress_ip(timeout=timeout)
    return egress if ":" in egress else ""


def normalize_v6_64(addr: str) -> str:
    """Normalize an IPv6 address or prefix to its /64 network prefix string."""
    clean = addr.strip().split("%", 1)[0].split("/", 1)[0]
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


_MUTEX_SYNCHRONIZE = 0x00100000
_MUTEX_ERROR_ALREADY_EXISTS = 183


def _mutex_names(name: str) -> tuple[str, str]:
    """Return both namespaces a worker mutex can live in.

    A Local\\ mutex only exists inside the session that created it, so a worker
    started by a scheduled task can be invisible to the dashboard that asks
    about it. The Global\\ spelling is machine wide, but creating it needs a
    privilege a standard user lacks, so both are tried.
    """
    return f"Global\\{name}", f"Local\\{name}"


def _open_mutex(path: str) -> int | None:
    """Return a handle to an existing mutex, or None when it does not exist."""
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenMutexW.restype = ctypes.c_void_p
    kernel32.OpenMutexW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_int32,
        ctypes.c_wchar_p,
    ]
    handle = kernel32.OpenMutexW(_MUTEX_SYNCHRONIZE, False, path)
    return int(handle) if handle else None


def acquire_mutex(name: str) -> int | None:
    """Acquire a named Windows mutex; returns handle if newly owned, else None."""
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int32,
        ctypes.c_wchar_p,
    ]
    global_name, local_name = _mutex_names(name)
    for path, other in ((global_name, local_name), (local_name, global_name)):
        # Another worker may hold the other spelling of the name; only one
        # keeper (or guard) may run at a time.
        held = _open_mutex(other)
        if held:
            kernel32.CloseHandle(ctypes.c_void_p(held))
            return None
        handle = kernel32.CreateMutexW(None, False, path)
        if not handle:
            continue  # Global\ needs a privilege a standard user lacks
        if kernel32.GetLastError() == _MUTEX_ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return None
        return int(handle)
    return None


def is_mutex_held(name: str) -> bool:
    """True while another process owns a worker mutex, in either namespace.

    Liveness of the keeper and guard is defined by their named mutex: the
    process takes it on start and Windows drops it when the process ends, so it
    cannot go stale the way a heartbeat file can.
    """
    kernel32 = ctypes.windll.kernel32
    for path in _mutex_names(name):
        handle = _open_mutex(path)
        if handle:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return True
    return False


def task_exists(task_name: str) -> bool:
    """True when a scheduled task with this name is registered."""
    try:
        res = run_hidden(["schtasks", "/Query", "/TN", task_name], timeout=5.0)
        return res.returncode == 0
    except Exception:
        return False


def task_enabled(task_name: str) -> bool:
    """True only for a registered task that is not disabled.

    Auto-repair and the watchdog use this so a worker the user deliberately
    turned off is never started behind their back.
    """
    try:
        res = run_hidden(["schtasks", "/Query", "/TN", task_name, "/XML"], timeout=5.0)
    except Exception:
        return False
    if res.returncode != 0:
        return False
    # schtasks writes UTF-16, which run_hidden may decode as single-byte text.
    # Removing NULs recovers the ASCII XML we need on every Windows locale.
    text = (res.stdout or "").replace("\x00", "")
    return not re.search(r"<enabled>\s*false\s*</enabled>", text, re.IGNORECASE)


def is_admin() -> bool:
    """Return True if the current process has administrator/root privileges."""
    if sys.platform != "win32":
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
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

    for host in ("opencode.ai", "api.opencode.ai"):
        try:
            for info in socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM):
                ip = str(info[4][0]).split("%", 1)[0]
                ipaddress.IPv6Address(ip)
                pool.add(ip)
        except Exception:
            pass

    pool.update(_FALLBACK_OPENCODE_AAAA)
    return sorted(pool)


def _current_warp_scope() -> str:
    default_scope = "tun" if sys.platform == "win32" else "isolated"
    try:
        from proxy_chain import get_egress_config

        return str(get_egress_config().get("warp_scope", default_scope))
    except Exception:
        return default_scope


def ensure_warp_mode(warp_bin: str, scope: str) -> None:
    """Put warp-cli into the operation mode required by the selected scope.

    The protocol always travels with the mode. Moving to proxy mode sets MASQUE
    first, because a proxy client still on WireGuard refuses the connection and
    drops the machine off the tunnel. Moving back to TUN flips the mode first,
    because the proxy client rejects a protocol change while it serves proxy.
    """
    desired = "proxy" if str(scope).strip().lower() == "isolated" else "warp"
    current = warp_mode(warp_bin=warp_bin)
    if desired == "proxy":
        protocol = get_warp_protocol(warp_bin=warp_bin)
        if current == "proxy" and protocol and not protocol.startswith("masque"):
            # A serving proxy client rejects a protocol change, so the tunnel
            # has to come down before the drift can be corrected.
            run_warp(["disconnect"], warp_bin=warp_bin, timeout=10.0)
        if not ensure_warp_protocol("masque", warp_bin=warp_bin):
            # Switching mode now would leave a proxy on a protocol it cannot
            # serve; keep the working tunnel and let the keeper retry.
            return
        if current != "proxy":
            run_warp(["proxy", "port", "40000"], warp_bin=warp_bin, timeout=10.0)
            run_warp(["mode", "proxy"], warp_bin=warp_bin, timeout=10.0)
        return
    if current != "warp":
        run_warp(["mode", "warp"], warp_bin=warp_bin, timeout=10.0)
    ensure_warp_protocol("wireguard", warp_bin=warp_bin)


def warp_registration_healthy(warp_bin: str) -> bool:
    """Return True when warp-cli reports an existing device registration."""
    rc, _ = run_warp(["registration", "show"], warp_bin=warp_bin, timeout=8.0)
    return rc == 0


# Cloudflare refuses new registrations in bursts, typically for a few seconds.
# Waiting the same two seconds every try burns the whole budget inside one
# refusal window, so each retry waits longer than the one before it.
REGISTRATION_BACKOFF = (0.0, 2.0, 4.0, 8.0, 12.0, 16.0)
# Deleting the device registration is the only rotation that cannot reuse the
# old /64, and the only one that can leave WARP unregistered for a while. One
# reset every ten minutes is enough to unstick a rotation without turning a
# Cloudflare refusal into an outage.
REG_RESET_COOLDOWN = 600.0
_LAST_REG_RESET = 0.0


def repair_warp_registration(warp_bin: str, max_tries: int = 3) -> bool:
    """Recreate a broken registration without touching a healthy one."""
    if warp_registration_healthy(warp_bin):
        return True
    for attempt in range(max(1, max_tries)):
        wait = REGISTRATION_BACKOFF[min(attempt, len(REGISTRATION_BACKOFF) - 1)]
        if wait:
            time.sleep(wait)
        rc, out = run_warp(["registration", "new"], warp_bin=warp_bin, timeout=30.0)
        if rc == 0:
            return True
        if "old registration" in out.lower():
            run_warp(["registration", "delete"], warp_bin=warp_bin, timeout=20.0)
    return False


def _rotated_egress(
    warp_bin: str, avoid: set[str], timeout: float = 2.5
) -> str:
    """Return the observed IPv6 egress when it is outside every avoided /64."""
    connected, _, _ = warp_status(warp_bin=warp_bin, force=True)
    if not connected:
        return ""
    candidate = get_public_v6(timeout=timeout)
    prefix = normalize_v6_64(candidate)
    if not candidate or not prefix or prefix in avoid:
        return ""
    return candidate


def _full_registration_reset(warp_bin: str, scope: str) -> bool:
    """Last resort when key rotation keeps landing on the same /64.

    Deleting the registration is the one rotation that cannot reuse the old
    block, but it is also the one that can leave WARP without a device if
    Cloudflare refuses the new one. A long cooldown keeps a stuck guard from
    repeating it on every attempt.
    """
    global _LAST_REG_RESET
    now = time.time()
    if now - _LAST_REG_RESET < REG_RESET_COOLDOWN:
        return False
    _LAST_REG_RESET = now

    run_warp(["disconnect"], warp_bin=warp_bin, timeout=10.0)
    run_warp(["registration", "delete"], warp_bin=warp_bin, timeout=20.0)
    # The delete returns before the daemon lets go of the old registration.
    for _ in range(15):
        if not warp_registration_healthy(warp_bin):
            break
        time.sleep(0.3)
    if not repair_warp_registration(warp_bin, 4):
        return False
    ensure_warp_mode(warp_bin, scope)
    run_warp(["connect"], warp_bin=warp_bin, timeout=15.0)
    return True


def hop_report(
    warp_bin: str,
    max_reg_tries: int = 3,
    avoid_prefixes: set[str] | None = None,
    previous: str = "",
) -> dict:
    """Rotate the WARP session and return the outcome of the attempt.

    Four outcomes are possible:

    ``fresh``       a block outside every avoided /64 was observed;
    ``reused``      the tunnel stayed up but came back on a block already in
                    use, which a caller must not treat as a rotation;
    ``down``        the tunnel did not come back up;
    ``unreachable`` the tunnel reports connected but the probe did not return.

    ``address`` holds the observed egress on ``fresh`` and is empty otherwise.
    """
    avoid: set[str] = set()
    for value in avoid_prefixes or ():
        prefix = normalize_v6_64(value)
        if prefix:
            avoid.add(prefix)
    old_prefix = normalize_v6_64(previous)
    if old_prefix:
        avoid.add(old_prefix)

    scope = _current_warp_scope()
    ensure_warp_mode(warp_bin, scope)

    seen = ""
    # A disconnected tunnel cannot produce a /64. Reconnecting a few times is
    # fine, but rotate-keys/disconnect/connect in a loop only cuts live
    # sessions without changing anything.
    connected, _, _ = warp_status(warp_bin=warp_bin, force=True)
    if not connected:
        run_warp(["connect"], warp_bin=warp_bin, timeout=15.0)
        for _ in range(4):
            time.sleep(1.5)
            connected, _, _ = warp_status(warp_bin=warp_bin, force=True)
            if connected:
                break
        if not connected:
            return {
                "status": "down",
                "address": "",
                "block": "",
                "previous_block": old_prefix,
                "detail": "the tunnel would not come back up",
            }

    for _rotation in range(3):
        # rotate-keys keeps the device registration and only renews the
        # WireGuard session, so Cloudflare assigns a new client /64.
        run_warp(["tunnel", "rotate-keys"], warp_bin=warp_bin, timeout=15.0)
        run_warp(["disconnect"], warp_bin=warp_bin, timeout=10.0)
        time.sleep(0.8)
        run_warp(["connect"], warp_bin=warp_bin, timeout=15.0)

        for _ in range(6):
            time.sleep(1.5)
            candidate = _rotated_egress(warp_bin, avoid)
            if candidate:
                return {
                    "status": "fresh",
                    "address": candidate,
                    "block": normalize_v6_64(candidate),
                    "previous_block": old_prefix,
                    "detail": "",
                }
        # Record the block the tunnel came back on. Read once per rotation:
        # polling it every second only makes a failing path slower.
        observed = get_public_v6(timeout=2.5)
        if observed:
            seen = observed

        connected, _, _raw = warp_status(warp_bin=warp_bin, force=True)
        if not connected:
            if repair_warp_registration(warp_bin, max_reg_tries):
                ensure_warp_mode(warp_bin, scope)
                run_warp(["connect"], warp_bin=warp_bin, timeout=15.0)

    # Key rotation reused its block every time. A full registration reset is the
    # only step left that cannot hand back the same /64.
    if _full_registration_reset(warp_bin, scope):
        for _ in range(6):
            time.sleep(1.5)
            candidate = _rotated_egress(warp_bin, avoid)
            if candidate:
                return {
                    "status": "fresh",
                    "address": candidate,
                    "block": normalize_v6_64(candidate),
                    "previous_block": old_prefix,
                    "detail": "",
                }
            observed = get_public_v6(timeout=2.5)
            if observed:
                seen = observed

    connected, _, _ = warp_status(warp_bin=warp_bin, force=True)
    if not connected:
        return {
            "status": "down",
            "address": "",
            "block": "",
            "previous_block": old_prefix,
            "detail": "the tunnel dropped and would not reconnect",
        }
    if seen:
        return {
            "status": "reused",
            "address": "",
            "block": normalize_v6_64(seen),
            "previous_block": old_prefix,
            "detail": "the tunnel came back on the block it was already using",
        }
    return {
        "status": "unreachable",
        "address": "",
        "block": "",
        "previous_block": old_prefix,
        "detail": "the tunnel is connected but the address probe never answered",
    }


def hop_once(
    warp_bin: str,
    max_reg_tries: int = 3,
    avoid_prefixes: set[str] | None = None,
    previous: str = "",
) -> str:
    """Rotate the WARP session until an unused public /64 is observed.

    Returns an address whose /64 differs from the previous egress and from
    every prefix in ``avoid_prefixes``. Returns an empty string when the
    tunnel cannot produce a fresh block; use :func:`hop_report` to learn which
    of the four ways it happened.
    """
    return hop_report(
        warp_bin,
        max_reg_tries=max_reg_tries,
        avoid_prefixes=avoid_prefixes,
        previous=previous,
    )["address"]
