"""Local IPv6-pinning HTTP/CONNECT proxy bound to Cloudflare WARP on Windows."""

from __future__ import annotations

import os
import random
import select
import socket
import socketserver
import threading
import time
import urllib.parse

from ouc_common import (
    LANE_DIR,
    ensure_dirs,
    fetch_opencode_aaaa_pool,
    get_warp_local_v6,
    is_keeper_paused,
    normalize_v6_64,
)

PINNED_HOSTS = {
    "opencode.ai",
    "www.opencode.ai",
    "api.opencode.ai",
    "opencode.com",
    "www.opencode.com",
    "api.opencode.com",
    "inference.opencode.ai",
}


class _WarpState:
    """Thread-safe cache for active WARP IPv6 and auto-rotated pinned edge."""

    def __init__(self, pool: list[str], initial_edge: str, ttl: float = 1.5) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._ts = 0.0
        self._v6: str | None = None
        self._last_prefix: str = ""
        self._pool = pool
        self._edge = initial_edge
        self._reroll_mtime = 0.0

    def _apply_edge_controls(self) -> None:
        override_file = LANE_DIR / "edge_override.txt"
        reroll_file = LANE_DIR / "edge_reroll"
        if not os.environ.get("OUC_PIN_EDGE") and override_file.is_file():
            try:
                val = override_file.read_text(encoding="utf-8").strip()
                if val and val.lower() != "auto" and ":" in val:
                    self._edge = val
                    (LANE_DIR / "last_edge.txt").write_text(val + "\n", encoding="utf-8")
                    return
            except Exception:
                pass
        if reroll_file.is_file():
            try:
                mtime = reroll_file.stat().st_mtime
                if mtime > self._reroll_mtime:
                    self._reroll_mtime = mtime
                    fresh_pool = fetch_opencode_aaaa_pool() or self._pool
                    self._pool = fresh_pool
                    choices = [c for c in fresh_pool if c != self._edge] or fresh_pool
                    self._edge = random.choice(choices)
                    (LANE_DIR / "last_edge.txt").write_text(self._edge + "\n", encoding="utf-8")
            except Exception:
                pass

    def poll_controls(self) -> None:
        """Refresh edge override / reroll state immediately without waiting for traffic."""
        with self._lock:
            self._apply_edge_controls()

    def get(self, wait_if_rotating: bool = True) -> tuple[str | None, str]:
        deadline = time.monotonic() + (18.0 if wait_if_rotating else 0.0)
        while True:
            now = time.monotonic()
            with self._lock:
                if now - self._ts < self._ttl and self._v6:
                    return self._v6, self._edge
            v6 = get_warp_local_v6()
            with self._lock:
                self._ts = time.monotonic()
                self._v6 = v6
                if v6:
                    prefix = normalize_v6_64(v6)
                    if prefix and self._last_prefix and prefix != self._last_prefix:
                        if not os.environ.get("OUC_PIN_EDGE"):
                            fresh_pool = fetch_opencode_aaaa_pool() or self._pool
                            self._pool = fresh_pool
                            self._edge = random.choice(fresh_pool)
                            try:
                                (LANE_DIR / "last_edge.txt").write_text(
                                    self._edge + "\n", encoding="utf-8"
                                )
                            except Exception:
                                pass
                    if prefix:
                        self._last_prefix = prefix
                self._apply_edge_controls()
                edge = self._edge
            if v6:
                return v6, edge
            if not wait_if_rotating or not is_keeper_paused() or time.monotonic() >= deadline:
                return None, edge
            time.sleep(0.75)


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _relay(a: socket.socket, b: socket.socket) -> None:
    """Bidirectionally forward bytes between two sockets with TCP keepalive and resilient streaming."""
    sockets = [a, b]
    closed = set()
    for s in (a, b):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Windows TCP keepalive parameters: idle 15s, interval 5s
            if hasattr(socket, "SIO_KEEPALIVE_VALS"):
                s.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 15000, 5000))
        except Exception:
            pass

    last_active = time.monotonic()
    try:
        while sockets:
            readable, _, exceptional = select.select(sockets, [], sockets, 5.0)
            if exceptional:
                break
            if not readable:
                # Generous 15-minute idle ceiling for long-thinking models (DeepSeek V4.1 reasoning)
                if time.monotonic() - last_active > 900.0:
                    break
                continue

            last_active = time.monotonic()
            for src in readable:
                dst = b if src is a else a
                try:
                    data = src.recv(65536)
                except (OSError, ConnectionResetError):
                    data = b""

                if data:
                    try:
                        dst.sendall(data)
                    except (OSError, ConnectionResetError):
                        return
                else:
                    # EOF from src -> send TCP FIN to dst (half-close)
                    closed.add(src)
                    if src in sockets:
                        sockets.remove(src)
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    if len(closed) >= 2:
                        return
    except Exception:
        pass


def _open_pinned_v6(dest_ip: str, port: int, local_v6: str, timeout: float = 12.0) -> socket.socket:
    """Open an IPv6 TCP socket explicitly bound to the WARP tunnel IPv6 address."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.bind((local_v6, 0))
        sock.connect((dest_ip, port))
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def _open_warp_direct(
    clean_host: str,
    port: int,
    warp_state: _WarpState,
) -> socket.socket:
    scope = "isolated"
    try:
        from proxy_chain import get_egress_config
        scope = get_egress_config().get("warp_scope", "isolated")
    except Exception:
        pass

    is_strict = os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()
    is_opencode_host = (
        clean_host in PINNED_HOSTS
        or clean_host.endswith(".opencode.ai")
        or clean_host.endswith(".opencode.com")
    )

    # 1. Isolated (App-Only) mode: tunnel via local WARP SOCKS5 proxy (port 40000) if listening
    if scope == "isolated":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_chk:
                s_chk.settimeout(0.2)
                if s_chk.connect_ex(("127.0.0.1", 40000)) == 0:
                    from tor_manager import open_socks5_tunnel
                    return open_socks5_tunnel(clean_host, port, socks_host="127.0.0.1", socks_port=40000, timeout=8.0)
        except Exception:
            pass

    # 2. TUN mode or fallback: bind explicitly to the WARP adapter's IPv6
    if is_opencode_host:
        local_v6, pinned_edge = warp_state.get(wait_if_rotating=True)
        if local_v6:
            try:
                return _open_pinned_v6(pinned_edge, port, local_v6)
            except Exception:
                pass

        # Try local WARP SOCKS5 if TUN socket bind failed and port 40000 is open
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_chk:
                s_chk.settimeout(0.2)
                if s_chk.connect_ex(("127.0.0.1", 40000)) == 0:
                    from tor_manager import open_socks5_tunnel
                    return open_socks5_tunnel(clean_host, port, socks_host="127.0.0.1", socks_port=40000, timeout=8.0)
        except Exception:
            pass

    local_v6, _ = warp_state.get(wait_if_rotating=False)
    if local_v6:
        try:
            infos = socket.getaddrinfo(clean_host, port, socket.AF_INET6, socket.SOCK_STREAM)
            if infos:
                return _open_pinned_v6(infos[0][4][0], port, local_v6)
        except Exception:
            pass

    # 3. Resilient failover: If WARP is down, try active Tor before failing
    try:
        from tor_manager import get_active_tor_target, open_socks5_tunnel
        tor_target = get_active_tor_target()
        if tor_target:
            return open_socks5_tunnel(clean_host, port, socks_host=tor_target[0], socks_port=tor_target[1], timeout=6.0)
    except Exception:
        pass

    # 4. Strict fail-closed privacy mode: only fail if explicitly enabled by user
    if is_strict:
        raise ConnectionRefusedError("Cloudflare WARP tunnel unavailable (fail-closed strict mode)")

    # 5. Resilient Direct Fallback:
    # If WARP is unavailable or dropped, route directly so OpenCode NEVER throws 502/503 errors!
    if is_opencode_host:
        try:
            _, pinned_edge = warp_state.get(wait_if_rotating=False)
            if pinned_edge and ":" in pinned_edge:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((pinned_edge, port))
                sock.settimeout(None)
                return sock
        except Exception:
            pass

    # Direct standard dual-stack connection (IPv4/IPv6)
    sock = socket.create_connection((clean_host, port), timeout=8.0)
    sock.settimeout(None)
    return sock


def _open_upstream(
    host: str,
    port: int,
    warp_state: _WarpState,
) -> socket.socket:
    """Connect upstream: supports WARP IPv6, Tor, and Custom SOCKS5/HTTP with resilient fallback."""
    clean_host = host.strip("[]").lower()
    if clean_host in ("127.0.0.1", "localhost", "::1"):
        sock = socket.create_connection((clean_host, port), timeout=10.0)
        sock.settimeout(None)
        return sock

    try:
        from proxy_chain import get_egress_config, open_multi_egress_upstream
        cfg = get_egress_config()
        if cfg.get("mode") in ("tor", "custom"):
            try:
                return open_multi_egress_upstream(
                    host,
                    port,
                    lambda h, p: _open_warp_direct(h, p, warp_state),
                )
            except Exception as exc:
                is_strict = os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()
                if is_strict:
                    raise ConnectionRefusedError(f"Multi-egress ({cfg.get('mode')}) upstream error: {exc}")
                # Fall back to resilient direct path if upstream proxy dropped
                return _open_warp_direct(clean_host, port, warp_state)
    except Exception:
        pass

    return _open_warp_direct(clean_host, port, warp_state)


def _make_handler(warp_state: _WarpState):
    class ProxyHandler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            try:
                raw_line = self.rfile.readline(65536)
            except OSError:
                return
            if not raw_line:
                return
            parts = raw_line.decode("latin-1").strip().split()
            if len(parts) < 3:
                return
            method, target, proto = parts[0].upper(), parts[1], parts[2]

            headers: list[bytes] = []
            content_len = 0
            while True:
                line = self.rfile.readline(65536)
                if not line or line in (b"\r\n", b"\n"):
                    break
                low = line.decode("latin-1").lower()
                if low.startswith("proxy-connection:"):
                    continue
                if low.startswith("content-length:"):
                    try:
                        content_len = int(low.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                headers.append(line)

            if method == "CONNECT":
                host, _, port_s = target.rpartition(":")
                if not host:
                    host, port = target, 443
                else:
                    try:
                        port = int(port_s)
                    except ValueError:
                        self._send_err(400, "Bad Request")
                        return
                try:
                    upstream = _open_upstream(host, port, warp_state)
                except Exception as exc:
                    is_strict = os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()
                    if is_strict:
                        self._send_err(503, f"Service Unavailable: {exc}")
                        return
                    # Seamless direct fallback so user never gets 502/503 errors
                    try:
                        upstream = socket.create_connection((host, port), timeout=8.0)
                        upstream.settimeout(None)
                    except Exception as exc2:
                        self._send_err(503, f"Service Unavailable: {exc2}")
                        return

                try:
                    self.wfile.write(f"{proto} 200 Connection Established\r\n\r\n".encode("ascii"))
                    self.wfile.flush()
                    _relay(self.connection, upstream)
                finally:
                    upstream.close()
                return

            parsed = urllib.parse.urlsplit(target)
            host = parsed.hostname or ""
            if not host:
                self._send_err(400, "Bad Request")
                return
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            try:
                upstream = _open_upstream(host, port, warp_state)
            except Exception as exc:
                is_strict = os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()
                if is_strict:
                    self._send_err(503, f"Service Unavailable: {exc}")
                    return
                # Seamless direct fallback so user never gets 502/503 errors
                try:
                    upstream = socket.create_connection((host, port), timeout=8.0)
                    upstream.settimeout(None)
                except Exception as exc2:
                    self._send_err(503, f"Service Unavailable: {exc2}")
                    return

            try:
                req_head = f"{method} {path} {proto}\r\n".encode("latin-1")
                upstream.sendall(req_head)
                for h in headers:
                    upstream.sendall(h)
                upstream.sendall(b"\r\n")
                if content_len > 0:
                    body = self.rfile.read(content_len)
                    if body:
                        upstream.sendall(body)
                _relay(self.connection, upstream)
            finally:
                upstream.close()

        def _send_err(self, code: int, reason: str) -> None:
            try:
                msg = f"HTTP/1.1 {code} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                self.wfile.write(msg.encode("ascii", errors="replace"))
                self.wfile.flush()
            except OSError:
                pass

    return ProxyHandler


def start_proxy_server(port: int = 0) -> tuple[_ThreadedTCPServer, int, str]:
    """Start the local CONNECT proxy in a background thread and return (server, port, edge)."""
    pool = fetch_opencode_aaaa_pool()
    chosen_edge = os.environ.get("OUC_PIN_EDGE", "").strip() or random.choice(pool)
    try:
        ensure_dirs()
        (LANE_DIR / "last_edge.txt").write_text(chosen_edge + "\n", encoding="utf-8")
    except Exception:
        pass

    warp_state = _WarpState(pool=pool, initial_edge=chosen_edge, ttl=1.5)
    handler = _make_handler(warp_state)
    srv = _ThreadedTCPServer(("127.0.0.1", port), handler)
    actual_port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    def _watch_controls() -> None:
        while True:
            time.sleep(1.0)
            try:
                warp_state.poll_controls()
            except Exception:
                pass

    threading.Thread(target=_watch_controls, daemon=True).start()
    return srv, actual_port, chosen_edge


if __name__ == "__main__":
    import sys

    bind_port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server, listening_port, edge = start_proxy_server(bind_port)
    print(f"zen-proxy listening on 127.0.0.1:{listening_port} (edge={edge})", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
