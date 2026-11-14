"""Tor portable manager and SOCKS5 client for OpenCode Unlimited."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from pathlib import Path

from ouc_common import (
    CREATE_NO_WINDOW,
    DEST_DIR,
    append_log,
    ensure_dirs,
    run_hidden,
)

TOR_DIR = DEST_DIR / "tor"
TOR_DATA_DIR = TOR_DIR / "data"
TOR_PID_FILE = TOR_DIR / "tor.pid"
TOR_LOG_FILE = DEST_DIR / "logs" / "tor.log"
TOR_DEFAULT_SOCKS_PORT = 9050
TOR_BROWSER_SOCKS_PORT = 9150

DETACHED_PROCESS = 0x00000008


def is_port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.8) -> bool:
    """Check whether a local TCP port is answering."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.error):
        return False


def test_socks5_alive(port: int, host: str = "127.0.0.1", timeout: float = 1.2) -> bool:
    """Verify that a given port responds to a standard SOCKS5 handshake."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            return len(resp) == 2 and resp[0] == 5 and resp[1] == 0
    except Exception:
        return False


def find_tor_exe() -> Path | None:
    """Locate portable or installed tor.exe across system and portable paths."""
    candidates = [
        TOR_DIR / "tor" / "tor.exe",
        TOR_DIR / "Tor" / "tor.exe",
        TOR_DIR / "tor.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path.home() / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path.home() / "OneDrive" / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c

    # System PATH lookup
    system_tor = shutil.which("tor.exe") or shutil.which("tor")
    if system_tor and os.path.isfile(system_tor):
        return Path(system_tor)

    # Recursive search if unzipped in custom subfolder
    if TOR_DIR.is_dir():
        for p in TOR_DIR.rglob("tor.exe"):
            if p.is_file():
                return p
    return None


def get_active_tor_target() -> tuple[str, int] | None:
    """Return (host, port) of the first live Tor SOCKS service (portable, Tor Browser, or daemon)."""
    # Prefer Tor Browser if user already has it running
    for p in (TOR_BROWSER_SOCKS_PORT, TOR_DEFAULT_SOCKS_PORT):
        if test_socks5_alive(p):
            return ("127.0.0.1", p)
    return None


def fetch_tor_bundle_url() -> list[str]:
    """Get list of mirror download URLs for Tor Expert Bundle."""
    urls = []
    api_url = "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json"
    req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            version = data.get("version")
            if version:
                urls.append(f"https://dist.torproject.org/torbrowser/{version}/tor-expert-bundle-windows-x86_64-{version}.tar.gz")
                urls.append(f"https://archive.org/download/tor-expert-bundle-{version}/tor-expert-bundle-windows-x86_64-{version}.tar.gz")
    except Exception:
        pass

    urls.extend([
        "https://dist.torproject.org/torbrowser/14.0.7/tor-expert-bundle-windows-x86_64-14.0.7.tar.gz",
        "https://archive.org/download/tor-expert-bundle-14.0.7/tor-expert-bundle-windows-x86_64-14.0.7.tar.gz",
    ])
    return urls


def download_and_extract_tor() -> tuple[bool, str]:
    """Download portable Tor Expert Bundle with multi-mirror support and extract."""
    ensure_dirs()
    TOR_DIR.mkdir(parents=True, exist_ok=True)
    TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)

    existing_exe = find_tor_exe()
    if existing_exe:
        return True, f"Tor already installed at {existing_exe}"

    bundle_urls = fetch_tor_bundle_url()
    tar_path = TOR_DIR / "tor-expert-bundle.tar.gz"

    downloaded = False
    last_err = ""
    for url in bundle_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=60) as src, open(tar_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            if tar_path.is_file() and tar_path.stat().st_size > 1024 * 1024:
                downloaded = True
                break
        except Exception as exc:
            last_err = str(exc)
            continue

    if not downloaded:
        return False, f"Tor download failed across all mirrors: {last_err or 'Network timeout'}"

    # Extract using system tar.exe or python tarfile fallback
    extracted = False
    tar_exe = shutil.which("tar.exe") or shutil.which("tar")
    if tar_exe:
        res = run_hidden([tar_exe, "-xf", str(tar_path), "-C", str(TOR_DIR)], timeout=30.0)
        if res.returncode == 0:
            extracted = True

    if not extracted:
        try:
            with tarfile.open(tar_path, "r:gz") as t:
                t.extractall(TOR_DIR)
            extracted = True
        except Exception as exc:
            return False, f"Failed to extract Tor archive: {exc}"

    try:
        tar_path.unlink(missing_ok=True)
    except Exception:
        pass

    exe = find_tor_exe()
    if exe and exe.is_file():
        return True, f"Tor portable installed successfully at {exe}"
    return False, "Tor archive extracted but tor.exe was not found."


def is_portable_tor_running() -> bool:
    """Check if our managed portable tor.exe process is alive."""
    if not TOR_PID_FILE.is_file():
        return False
    try:
        pid = int(TOR_PID_FILE.read_text(encoding="utf-8").strip())
        import psutil
        proc = psutil.Process(pid)
        return proc.is_running() and "tor" in proc.name().lower()
    except Exception:
        return False


def start_portable_tor() -> tuple[bool, str]:
    """Start the portable Tor process in the background."""
    if test_socks5_alive(TOR_DEFAULT_SOCKS_PORT) or test_socks5_alive(TOR_BROWSER_SOCKS_PORT):
        target = get_active_tor_target()
        return True, f"Tor SOCKS already running on {target[0]}:{target[1]}"

    exe = find_tor_exe()
    if not exe:
        ok, msg = download_and_extract_tor()
        if not ok:
            return False, msg
        exe = find_tor_exe()
        if not exe:
            return False, "Tor executable missing after install."

    TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
    TOR_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    args = [
        str(exe),
        "--SocksPort",
        f"127.0.0.1:{TOR_DEFAULT_SOCKS_PORT}",
        "--ControlPort",
        "127.0.0.1:9051",
        "--CookieAuthentication",
        "0",
        "--DataDirectory",
        str(TOR_DATA_DIR),
        "--Log",
        f"notice file {TOR_LOG_FILE}",
    ]

    try:
        proc = subprocess.Popen(
            args,
            creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
            close_fds=True,
        )
        TOR_PID_FILE.write_text(str(proc.pid), encoding="utf-8")
    except Exception as exc:
        return False, f"Failed to spawn tor.exe: {exc}"

    # Wait for SOCKS port to open (up to 25s for first bootstrap)
    for _ in range(25):
        if test_socks5_alive(TOR_DEFAULT_SOCKS_PORT):
            return True, f"Portable Tor started on 127.0.0.1:{TOR_DEFAULT_SOCKS_PORT}"
        time.sleep(1.0)

    return False, f"Tor process started (PID {proc.pid}) but SOCKS port 9050 did not respond in time."


def stop_portable_tor() -> tuple[bool, str]:
    """Terminate the managed portable Tor process."""
    if not TOR_PID_FILE.is_file():
        return True, "Portable Tor is not running."
    try:
        pid = int(TOR_PID_FILE.read_text(encoding="utf-8").strip())
        import psutil
        proc = psutil.Process(pid)
        if "tor" in proc.name().lower():
            proc.kill()
        TOR_PID_FILE.unlink(missing_ok=True)
        return True, f"Stopped portable Tor (PID {pid})."
    except Exception as exc:
        TOR_PID_FILE.unlink(missing_ok=True)
        return True, f"Tor process cleanup: {exc}"


def signal_tor_newnym(control_port: int = 9051) -> bool:
    """Send SIGNAL NEWNYM to Tor control port to build a fresh circuit and exit node."""
    try:
        with socket.create_connection(("127.0.0.1", control_port), timeout=1.2) as s:
            s.sendall(b'AUTHENTICATE ""\r\n')
            resp = s.recv(512)
            if b"250" in resp:
                s.sendall(b"SIGNAL NEWNYM\r\n")
                resp2 = s.recv(512)
                return b"250" in resp2
    except Exception:
        pass
    return False


def rotate_tor_circuit() -> tuple[bool, str]:
    """Rotate Tor circuit for a fresh exit node IP and reset quota."""
    # 1. Try Tor control port SIGNAL NEWNYM first (Tor Browser: 9151, System Tor: 9051)
    for port in (9051, 9151):
        if signal_tor_newnym(port):
            time.sleep(1.2)
            return True, f"Tor circuit rotated via control port {port} (new exit identity assigned)."

    # 2. If control port not active, cycle portable Tor daemon if running
    if is_portable_tor_running():
        stop_portable_tor()
        time.sleep(1.0)
        return start_portable_tor()

    active = get_active_tor_target()
    if active:
        return True, f"External Tor active on {active[0]}:{active[1]} (circuit cycle requested)."
    return start_portable_tor()


def open_socks5_tunnel(
    dest_host: str,
    dest_port: int,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
    timeout: float = 12.0,
) -> socket.socket:
    """Establish an upstream TCP tunnel through a SOCKS5 proxy server."""
    sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
    # SOCKS5 greeting
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
        sock.close()
        raise ConnectionError("SOCKS5 proxy authentication failed or invalid protocol")

    # Connect command: support IPv4 (ATYP=1), IPv6 (ATYP=4), and Domain (ATYP=3)
    port_bytes = dest_port.to_bytes(2, "big")
    try:
        ip_v4 = socket.inet_aton(dest_host)
        req = b"\x05\x01\x00\x01" + ip_v4 + port_bytes
    except OSError:
        try:
            ip_v6 = socket.inet_pton(socket.AF_INET6, dest_host)
            req = b"\x05\x01\x00\x04" + ip_v6 + port_bytes
        except (OSError, AttributeError):
            host_bytes = dest_host.encode("idna")
            req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port_bytes
    sock.sendall(req)

    reply = sock.recv(4)
    if len(reply) < 4 or reply[1] != 0:
        sock.close()
        code = reply[1] if len(reply) >= 2 else -1
        raise ConnectionError(f"SOCKS5 proxy connection failed (error code {code})")

    atyp = reply[3]
    if atyp == 1:
        sock.recv(4 + 2)
    elif atyp == 3:
        dlen = sock.recv(1)[0]
        sock.recv(dlen + 2)
    elif atyp == 4:
        sock.recv(16 + 2)

    sock.settimeout(None)
    return sock
