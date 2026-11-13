"""Multi-egress proxy router: supports Cloudflare WARP, Tor Network, and Custom SOCKS5/HTTP."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Literal

from ouc_common import LANE_DIR, ensure_dirs
from tor_manager import (
    get_active_tor_target,
    open_socks5_tunnel,
    start_portable_tor,
)

EgressType = Literal["warp", "tor", "custom"]
EGRESS_CONFIG_FILE = LANE_DIR / "egress_mode.json"


def get_egress_config() -> dict:
    """Read the active egress routing configuration."""
    if EGRESS_CONFIG_FILE.is_file():
        try:
            cfg = json.loads(EGRESS_CONFIG_FILE.read_text(encoding="utf-8"))
            if "warp_scope" not in cfg:
                cfg["warp_scope"] = "isolated"
            return cfg
        except Exception:
            pass
    return {
        "mode": "warp",
        "warp_scope": "isolated",
        "custom_proxy": "127.0.0.1:10808",
        "custom_type": "socks5",
    }


def set_egress_config(
    mode: EgressType,
    custom_proxy: str = "127.0.0.1:10808",
    custom_type: str = "socks5",
    warp_scope: str = "isolated",
) -> dict:
    """Save the active egress configuration."""
    ensure_dirs()
    cfg = {
        "mode": mode,
        "warp_scope": "tun" if warp_scope.lower().strip() == "tun" else "isolated",
        "custom_proxy": custom_proxy.strip(),
        "custom_type": custom_type.lower().strip(),
    }
    EGRESS_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg


def open_http_proxy_tunnel(dest_host: str, dest_port: int, proxy_host: str, proxy_port: int, timeout: float = 12.0) -> socket.socket:
    """Connect to an upstream HTTP proxy and negotiate CONNECT tunnel."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    req = (
        f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
        f"Host: {dest_host}:{dest_port}\r\n"
        f"Proxy-Connection: Keep-Alive\r\n\r\n"
    )
    s.sendall(req.encode("ascii"))
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            s.close()
            raise ConnectionError("Upstream HTTP proxy closed connection.")
        resp += chunk
    status_line = resp.split(b"\r\n", 1)[0].decode("latin-1")
    if " 200 " not in status_line:
        s.close()
        raise ConnectionError(f"Upstream HTTP proxy rejected CONNECT: {status_line}")
    return s


def open_multi_egress_upstream(host: str, port: int, warp_fallback_fn) -> socket.socket:
    """Route an outbound connection according to the active egress mode."""
    cfg = get_egress_config()
    mode = cfg.get("mode", "warp")

    if mode == "tor":
        target = get_active_tor_target()
        if not target:
            ok, msg = start_portable_tor()
            if not ok:
                raise ConnectionError(f"Could not connect via Tor: {msg}")
            target = get_active_tor_target() or ("127.0.0.1", 9050)
        return open_socks5_tunnel(host, port, socks_host=target[0], socks_port=target[1])

    if mode == "custom":
        raw = cfg.get("custom_proxy", "127.0.0.1:10808").strip()
        # Clean protocol prefixes if user pasted them
        for prefix in ("socks5://", "socks5h://", "http://", "https://"):
            if raw.lower().startswith(prefix):
                raw = raw[len(prefix):]
        raw = raw.strip("/ ")
        phost, sep, pport_s = raw.rpartition(":")
        if sep:
            pport = int(pport_s) if pport_s.isdigit() else 10808
            phost = phost.strip("[] ") or "127.0.0.1"
        else:
            pport = int(raw) if raw.isdigit() else 10808
            phost = "127.0.0.1"

        ptype = cfg.get("custom_type", "socks5").lower()
        if ptype == "http":
            return open_http_proxy_tunnel(host, port, phost, pport)
        return open_socks5_tunnel(host, port, socks_host=phost, socks_port=pport)

    # Default: Cloudflare WARP IPv6 socket binding
    return warp_fallback_fn(host, port)
