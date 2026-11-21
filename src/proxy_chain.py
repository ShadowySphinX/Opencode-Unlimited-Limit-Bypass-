"""Multi-egress proxy router: WARP, Tor, Custom SOCKS5/HTTP, and block relays.

A ``relay://`` entry points at a ``blockrelay`` server: an authenticated CONNECT
tunnel that gives this machine a sticky IPv6 /64 and rotates it on demand.  The
tunnel is blind, so the OpenCode client keeps its own TLS session and its own
fingerprint; only the source address changes.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
from typing import Literal

from ouc_common import LANE_DIR, ensure_dirs
from tor_manager import (
    get_active_tor_target,
    open_socks5_tunnel,
    start_portable_tor,
)

import sys

EgressType = Literal["warp", "tor", "custom", "clean"]
EGRESS_CONFIG_FILE = LANE_DIR / "egress_mode.json"
# Self-signed relays are the normal case on a fresh VPS.  Opting out of
# certificate verification is explicit and never on by default.
RELAY_INSECURE_FLAG = LANE_DIR / "relay_insecure.flag"


def relay_tls_insecure() -> bool:
    """True when the operator opted into unverified relay certificates."""
    return os.environ.get("OUC_RELAY_INSECURE") == "1" or RELAY_INSECURE_FLAG.is_file()


def _relay_ssl_context() -> ssl.SSLContext:
    if relay_tls_insecure():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def get_default_warp_scope() -> str:
    # App-only by default: WARP must never take over the whole PC
    return "isolated"


def get_egress_config() -> dict:
    """Read the active egress routing configuration."""
    default_scope = get_default_warp_scope()
    if EGRESS_CONFIG_FILE.is_file():
        try:
            cfg = json.loads(EGRESS_CONFIG_FILE.read_text(encoding="utf-8"))
            if "warp_scope" not in cfg:
                cfg["warp_scope"] = default_scope
            return cfg
        except Exception:
            pass
    return {
        "mode": "warp",
        "warp_scope": default_scope,
        "custom_proxy": "127.0.0.1:10808",
        "custom_type": "socks5",
    }


def set_egress_config(
    mode: EgressType,
    custom_proxy: str = "127.0.0.1:10808",
    custom_type: str = "socks5",
    warp_scope: str | None = None,
) -> dict:
    """Save the active egress configuration."""
    ensure_dirs()
    if warp_scope is None or not warp_scope.strip():
        chosen_scope = get_default_warp_scope()
    else:
        # Hard clamp: WARP is app-only (proxy mode). Full-tunnel would route the
        # entire PC (and ZCode) through WARP and drop on every rotation.
        chosen_scope = "isolated"
    cfg = {
        "mode": mode,
        "warp_scope": chosen_scope,
        "custom_proxy": custom_proxy.strip(),
        "custom_type": custom_type.lower().strip(),
    }
    EGRESS_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        (LANE_DIR / "custom_proxy_index.txt").write_text("0", encoding="utf-8")
    except Exception:
        pass
    return cfg


PROXY_INDEX_FILE = LANE_DIR / "custom_proxy_index.txt"


def _parse_proxy_entry(raw: str, default_type: str = "socks5") -> dict | None:
    """Parse one ``[scheme://][user:pass@]host:port`` proxy entry."""
    from urllib.parse import unquote

    text = raw.strip()
    if not text:
        return None
    scheme = ""
    if "://" in text:
        scheme, text = text.split("://", 1)
        scheme = scheme.lower().strip()
    text = text.strip().rstrip("/")
    username = ""
    password = ""
    if "@" in text:
        userinfo, text = text.rsplit("@", 1)
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo
        username = unquote(username)
        password = unquote(password)

    host = ""
    port = 0
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            host = text[1:end]
            rest = text[end + 1 :].lstrip(":")
            if rest.isdigit():
                port = int(rest)
    else:
        phost, sep, pport = text.rpartition(":")
        if sep and pport.isdigit():
            host = phost.strip("[] ")
            port = int(pport)
        elif text.isdigit():
            host, port = "127.0.0.1", int(text)
    if not host or not 0 < port < 65536:
        return None
    tls = False
    if scheme in ("relay", "relaytls", "relay+tls"):
        proxy_type = "relay"
        tls = True
    elif scheme in ("relayplain", "relay+tcp", "relay-insecure"):
        proxy_type = "relay"
    elif scheme == "https":
        # Legacy: `https://` has always meant "plaintext CONNECT to an HTTP
        # proxy" here.  Relay users spell the scheme `relay://` instead, so
        # existing configs keep working untouched.
        proxy_type = "http"
    else:
        if scheme in ("socks5", "socks5h"):
            proxy_type = "socks5"
        elif scheme in ("http", "relay"):
            proxy_type = scheme
        else:
            proxy_type = default_type
            if proxy_type == "https":
                proxy_type = "http"
            if proxy_type not in ("socks5", "http", "relay"):
                proxy_type = "socks5"
    return {
        "host": host,
        "port": port,
        "type": proxy_type,
        "tls": tls,
        "username": username,
        "password": password,
    }


def parse_proxy_specs(raw: str, default_type: str = "socks5") -> list[dict]:
    """Parse a comma/semicolon/space/newline delimited proxy pool."""
    import re

    entries = re.split(r"[,;\s\n\r]+", (raw or "").strip())
    specs = []
    for item in entries:
        spec = _parse_proxy_entry(item, default_type)
        if spec:
            specs.append(spec)
    if not specs:
        specs = [
            {
                "host": "127.0.0.1",
                "port": 10808,
                "type": default_type if default_type in ("socks5", "http") else "socks5",
                "tls": False,
                "username": "",
                "password": "",
            }
        ]
    return specs


def parse_proxy_list(raw: str) -> list[tuple[str, int]]:
    """Parse comma, semicolon, space, or newline delimited proxies."""
    return [(s["host"], s["port"]) for s in parse_proxy_specs(raw)]


def _proxy_index(total: int) -> int:
    idx = 0
    if PROXY_INDEX_FILE.is_file():
        try:
            idx = int(PROXY_INDEX_FILE.read_text(encoding="utf-8").strip())
        except Exception:
            idx = 0
    return idx % max(1, total)


def get_current_proxy_spec() -> dict:
    """Return the active custom proxy entry with type and credentials."""
    cfg = get_egress_config()
    default_type = str(cfg.get("custom_type", "socks5")).lower()
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"), default_type
    )
    return specs[_proxy_index(len(specs))]


def get_current_custom_proxy() -> tuple[str, int, int, int]:
    """Return (host, port, current_index, total_count)."""
    cfg = get_egress_config()
    default_type = str(cfg.get("custom_type", "socks5")).lower()
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"), default_type
    )
    idx = _proxy_index(len(specs))
    spec = specs[idx]
    return spec["host"], spec["port"], idx, len(specs)


def rotate_custom_proxy() -> tuple[bool, str]:
    """Rotate the active exit: a fresh relay block, or the next pool node."""
    ensure_dirs()
    cfg = get_egress_config()
    default_type = str(cfg.get("custom_type", "socks5")).lower()
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"), default_type
    )
    original = _proxy_index(len(specs))
    current = specs[original]
    if len(specs) == 1 and current.get("type") != "relay":
        return False, (
            f"Only one proxy is configured ({current['host']}:{current['port']}); "
            "add another node to rotate exits."
        )

    from ouc_common import get_egress_ip

    failures: list[str] = []
    # A relay rotates its own block, so the same node is reused before the pool
    # advances; that is the whole point of the sticky assignment.
    for step in range(len(specs)):
        new_idx = (original + step) % len(specs)
        spec = specs[new_idx]
        if spec.get("type") == "relay":
            ok, msg = _rotate_relay_spec(spec)
            if ok:
                PROXY_INDEX_FILE.write_text(str(new_idx), encoding="utf-8")
                return True, msg
            failures.append(msg)
            continue
        if step == 0:
            continue
        PROXY_INDEX_FILE.write_text(str(new_idx), encoding="utf-8")
        exit_ip = get_egress_ip(timeout=5.0)
        if exit_ip:
            return True, (
                f"Switched to proxy #{new_idx + 1}/{len(specs)}: "
                f"{spec['host']}:{spec['port']} (exit {exit_ip})"
            )
        failures.append(f"{spec['host']}:{spec['port']} did not answer")

    PROXY_INDEX_FILE.write_text(str(original), encoding="utf-8")
    detail = failures[-1] if failures else "no candidate answered"
    return False, (
        f"Could not rotate away from {current['host']}:{current['port']} "
        f"(#{original + 1}/{len(specs)}): {detail}"
    )


def advance_custom_proxy() -> dict:
    """Move to the next proxy node without a blocking reachability test.

    Request-path failover has to stay fast. ``rotate_custom_proxy`` keeps the
    verification that the Next Node button needs; routers use this instead.
    """
    ensure_dirs()
    cfg = get_egress_config()
    default_type = str(cfg.get("custom_type", "socks5")).lower()
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"), default_type
    )
    idx = _proxy_index(len(specs))
    new_idx = (idx + 1) % len(specs)
    try:
        PROXY_INDEX_FILE.write_text(str(new_idx), encoding="utf-8")
    except Exception:
        pass
    return specs[new_idx]


def _basic_auth_header(username: str, password: str) -> str:
    import base64

    token = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"


def open_http_proxy_tunnel(
    dest_host: str,
    dest_port: int,
    proxy_host: str,
    proxy_port: int,
    timeout: float = 12.0,
    username: str = "",
    password: str = "",
    use_tls: bool = False,
) -> socket.socket:
    """Connect to an upstream HTTP proxy and negotiate CONNECT tunnel.

    ``use_tls`` wraps the hop to the proxy itself in TLS (that is what a
    ``relay://`` entry asks for); the tunnel payload stays untouched, so the
    client's own TLS session to the destination is end-to-end.
    """
    raw = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s = raw
    try:
        if use_tls:
            s = _relay_ssl_context().wrap_socket(raw, server_hostname=proxy_host)
            s.settimeout(timeout)
        auth = _basic_auth_header(username, password) if username else ""
        req = (
            f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
            f"Host: {dest_host}:{dest_port}\r\n"
            f"{auth}"
            f"Proxy-Connection: Keep-Alive\r\n\r\n"
        )
        s.sendall(req.encode("utf-8"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                raise ConnectionError("Upstream HTTP proxy closed connection.")
            resp += chunk
            if len(resp) > 65536:
                raise ConnectionError("Upstream HTTP proxy reply is too large.")
        status_line = resp.split(b"\r\n", 1)[0].decode("latin-1")
        if " 200 " not in status_line:
            raise ConnectionError(
                f"Upstream HTTP proxy rejected CONNECT: {status_line}"
            )
        s.settimeout(None)
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        if s is not raw:
            try:
                raw.close()
            except Exception:
                pass
        raise


def relay_api_request(
    spec: dict,
    method: str,
    path: str,
    payload: dict | None = None,
    timeout: float = 20.0,
) -> dict:
    """Call the relay control API (``/api/state``, ``/api/rotate``).

    The control API is separate from the tunnel: same port, no CONNECT.  It is
    reached directly, not through the proxy pool, because a broken tunnel must
    not take the rotation endpoint down with it.
    """
    host = spec["host"]
    port = int(spec["port"])
    if spec.get("tls"):
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=_relay_ssl_context()
        )
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    token = str(spec.get("password", ""))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        conn.request(method.upper(), path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(65536)
        status = resp.status
    finally:
        try:
            conn.close()
        except Exception:
            pass
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        data = {"ok": False, "error": f"relay returned {status} with a non-JSON body"}
    if not isinstance(data, dict):
        data = {"ok": False, "error": "relay returned an unexpected payload"}
    data.setdefault("ok", False)
    data["status"] = status
    return data


def relay_state(spec: dict, timeout: float = 10.0) -> dict:
    """Return the relay's view of this client's block, or an error payload."""
    if spec.get("type") != "relay":
        return {"ok": False, "error": "not a relay entry"}
    try:
        return relay_api_request(spec, "GET", "/api/state", timeout=timeout)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _probe_relay_spec(spec: dict, timeout: float = 8.0) -> str:
    """Confirm the exit address of one specific relay entry."""
    from ouc_common import probe_proxy_egress, _proxy_url

    url = _proxy_url(
        spec["host"],
        int(spec["port"]),
        "relay",
        str(spec.get("username", "")),
        str(spec.get("password", "")),
        bool(spec.get("tls")),
    )
    return probe_proxy_egress(
        url, timeout=timeout, insecure=bool(spec.get("tls")) and relay_tls_insecure()
    )


def _rotate_relay_spec(spec: dict) -> tuple[bool, str]:
    """Ask the relay for a fresh /64 and report the block it handed back."""
    where = f"{spec['host']}:{spec['port']}"
    try:
        data = relay_api_request(spec, "POST", "/api/rotate")
    except Exception as exc:
        return False, f"relay {where} unreachable for rotation ({type(exc).__name__}: {exc})"

    if not data.get("ok"):
        return False, f"relay {where} could not rotate: {data.get('error', 'unknown error')}"

    block = str(data.get("block", ""))
    relay_egress = str(data.get("egress_ip", ""))
    verified = bool(data.get("verified"))
    if not verified and relay_egress:
        return False, (
            f"relay rotated to {block or '?'} but its own probe saw {relay_egress}, "
            "outside that block"
        )
    exit_ip = _probe_relay_spec(spec)
    if not exit_ip and verified and relay_egress:
        # The relay proved the block dials out; the local probe can fail on a
        # cold tunnel and still be healthy.
        exit_ip = relay_egress
    if not exit_ip:
        return False, (
            f"relay rotated to {block or '?'} but no egress could be confirmed; "
            "check the relay host allowlist and TLS certificate"
        )
    suffix = "" if relay_egress else " (relay-side probe unavailable)"
    return True, f"relay {where} -> {block} (exit {exit_ip}){suffix}"


def is_relay_mode(cfg: dict | None = None) -> bool:
    """True when the active custom pool is a block relay.

    The relay is a device-hygiene lane, not a privacy lane: if it is selected
    and unavailable, traffic must fail loudly instead of leaking out over the
    burnt WARP address.
    """
    if cfg is None:
        cfg = get_egress_config()
    if str(cfg.get("mode", "warp")) != "custom":
        return False
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"),
        str(cfg.get("custom_type", "socks5")).lower(),
    )
    return all(s.get("type") == "relay" for s in specs)


def open_multi_egress_upstream(host: str, port: int, warp_fallback_fn) -> socket.socket:
    """Route an outbound connection according to the active egress mode with auto-healing and failover."""
    cfg = get_egress_config()
    mode = cfg.get("mode", "warp")

    if mode == "tor":
        target = get_active_tor_target()
        if not target:
            ok, msg = start_portable_tor()
            if not ok:
                if warp_fallback_fn and not (os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()):
                    return warp_fallback_fn(host, port)
                raise ConnectionError(f"Could not connect via Tor: {msg}")
            target = get_active_tor_target() or ("127.0.0.1", 9050)
        try:
            return open_socks5_tunnel(host, port, socks_host=target[0], socks_port=target[1], timeout=10.0)
        except Exception:
            if warp_fallback_fn and not (os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()):
                return warp_fallback_fn(host, port)
            raise

    if mode == "custom":
        specs = parse_proxy_specs(
            cfg.get("custom_proxy", "127.0.0.1:10808"),
            str(cfg.get("custom_type", "socks5")).lower(),
        )
        tries = max(1, len(specs))
        last_err = None

        for _ in range(tries):
            spec = get_current_proxy_spec()
            phost = spec["host"]
            pport = int(spec["port"])
            ptype = spec["type"]
            puser = spec.get("username", "")
            ppass = spec.get("password", "")
            if ptype == "relay":
                # Blind tunnel to the block relay.  No plaintext retry and no
                # WARP fallback: falling back would spend the address the relay
                # exists to replace, and would hide a dead relay.
                return open_http_proxy_tunnel(
                    host,
                    port,
                    phost,
                    pport,
                    timeout=12.0,
                    username=puser,
                    password=ppass,
                    use_tls=bool(spec.get("tls")),
                )
            if ptype == "http":
                try:
                    return open_http_proxy_tunnel(
                        host,
                        port,
                        phost,
                        pport,
                        timeout=8.0,
                        username=puser,
                        password=ppass,
                    )
                except Exception as e:
                    last_err = e
            else:
                try:
                    return open_socks5_tunnel(
                        host,
                        port,
                        socks_host=phost,
                        socks_port=pport,
                        timeout=6.0,
                        username=puser,
                        password=ppass,
                    )
                except Exception as e:
                    last_err = e
                    # Some proxies are configured with the wrong scheme.
                    try:
                        return open_http_proxy_tunnel(
                            host,
                            port,
                            phost,
                            pport,
                            timeout=5.0,
                            username=puser,
                            password=ppass,
                        )
                    except Exception:
                        pass
            # If current node failed and we have more nodes, advance pool to next node
            if len(specs) > 1:
                advance_custom_proxy()

        if warp_fallback_fn and not (
            os.environ.get("OUC_STRICT_PROXY") == "1"
            or (LANE_DIR / "strict_proxy.flag").is_file()
        ):
            try:
                return warp_fallback_fn(host, port)
            except Exception:
                pass
        raise ConnectionError(f"All proxies in pool failed (last error: {last_err})")

    # Default: Cloudflare WARP IPv6 socket binding
    return warp_fallback_fn(host, port)
