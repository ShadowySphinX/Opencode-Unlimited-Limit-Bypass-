"""Local HTTP/CONNECT proxy that routes through the selected egress route."""

from __future__ import annotations

import errno
import json
import os
import random
import select
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
from pathlib import Path

from ouc_common import (
    LANE_DIR,
    PAUSE_FILE,
    append_log,
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

PROXY_LOG_FILE = LANE_DIR / "proxy.log"
PROXY_STATUS_FILE = LANE_DIR / "proxy_status.json"
FALLBACK_FLAG = LANE_DIR / "fallback.flag"

# Three quick attempts beat one long stall: OpenCode shows a network error long
# before a 12-second connect timeout per address finishes.
EDGE_CONNECT_TIMEOUT = 3.0
EDGE_TRY_LIMIT = 3
EDGE_FAILURE_COOLDOWN = 120.0
# A WARP reconnect replaces the tunnel address; give the adapter a short,
# bounded window to publish the new one before declaring the route dead.
STALE_ADDRESS_WAIT = 6.0
STALE_ADDRESS_POLL = 0.25
# A rotation closes the tunnel for a few seconds. Holding the request beats
# handing OpenCode a connection error it cannot retry, but the wait is capped so
# a wedged rotation cannot pin a request open forever.
ROTATION_HOLD_SECONDS = 30.0
ROTATION_POLL_SECONDS = 0.4
# The keeper pause file is created before a rotation and deleted after it. A
# guard killed mid-rotation leaves it behind until its own lease runs out, which
# can be minutes, so only a freshly written pause is trusted as "rotating now".
ROTATION_FRESH_SECONDS = 120.0
STATUS_LOCK = threading.Lock()
_LAST_FALLBACK_NOTE = 0.0
_RESET_LOCK = threading.Lock()
_LAST_RESET_NOTE = 0.0
_STREAM_RESET_LOCK = threading.Lock()
_LAST_STREAM_RESET_NOTE = 0.0
_TUNNEL_LOCK = threading.Lock()
_ACTIVE_TUNNELS = 0
_BYTE_LOCK = threading.Lock()
_LAST_BYTE_TS = 0.0
_LAST_BYTE_PUBLISH = 0.0
# A stream relays chunks continuously, so the guard only needs a stamp that is
# a few seconds old. Rewriting the status file on every chunk would put a disk
# write in the middle of the data path.
BYTE_PUBLISH_INTERVAL = 2.0

# Kinds that describe a failed route rather than a lifecycle note.
ERROR_KINDS = {
    "error",
    "reset",
    "stream_reset",
    "connect_fail",
    "edge_fail",
    "fallback",
    "bind_fail",
}
LOG_KINDS = ERROR_KINDS | {"repair", "start", "hold"}


def _read_proxy_status() -> dict:
    try:
        data = json.loads(PROXY_STATUS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_proxy_status(data: dict) -> None:
    try:
        tmp = PROXY_STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        tmp.replace(PROXY_STATUS_FILE)
    except Exception:
        pass


def _record_event(kind: str, detail: str, host: str = "", edge: str = "") -> None:
    """Keep a small, bounded trail of route failures for health checks and logs."""
    now = int(time.time())
    entry = {
        "ts": now,
        "kind": kind,
        "detail": str(detail)[:400],
        "host": host[:120],
        "edge": edge[:120],
    }
    try:
        with STATUS_LOCK:
            data = _read_proxy_status()
            recent = [e for e in data.get("recent", []) if now - int(e.get("ts", 0)) <= 900]
            recent.append(entry)
            data["recent"] = recent[-30:]
            data["last_event"] = entry
            if kind in ERROR_KINDS:
                data["last_error"] = entry["detail"]
                data["last_error_ts"] = now
            if edge:
                data["edge"] = edge
            if kind == "fallback":
                data["fallback_ts"] = now
            if kind == "edge_fail" and edge:
                data["last_bad_edge"] = edge
            _write_proxy_status(data)
    except Exception:
        pass
    if kind in LOG_KINDS:
        append_log(
            PROXY_LOG_FILE,
            f"{kind}: {entry['detail']}"
            + (f" host={entry['host']}" if entry["host"] else "")
            + (f" edge={entry['edge']}" if entry["edge"] else ""),
        )


def _mark_fallback(host: str, reason: str) -> None:
    """Record that a request left through the normal network instead of WARP."""
    global _LAST_FALLBACK_NOTE
    now = time.monotonic()
    if now - _LAST_FALLBACK_NOTE >= 30.0:
        _LAST_FALLBACK_NOTE = now
        try:
            FALLBACK_FLAG.write_text(str(int(time.time())), encoding="utf-8")
        except Exception:
            pass
        _record_event("fallback", reason, host)


def _record_reset(host: str, detail: str) -> None:
    """One line per ten seconds is enough; a dropped stream resets in bursts."""
    global _LAST_RESET_NOTE
    now = time.monotonic()
    with _RESET_LOCK:
        if now - _LAST_RESET_NOTE < 10.0:
            return
        _LAST_RESET_NOTE = now
    _record_event("reset", detail, host)


def _record_stream_reset(host: str, detail: str, edge: str = "") -> None:
    """Record a reset after response bytes started; those are visible to the user."""
    global _LAST_STREAM_RESET_NOTE
    now = time.monotonic()
    with _STREAM_RESET_LOCK:
        if now - _LAST_STREAM_RESET_NOTE < 5.0:
            return
        _LAST_STREAM_RESET_NOTE = now
    _record_event("stream_reset", detail, host, edge)


def _active_tunnels() -> int:
    with _TUNNEL_LOCK:
        return _ACTIVE_TUNNELS


def _last_byte_ts() -> float:
    with _BYTE_LOCK:
        return _LAST_BYTE_TS


def _publish_tunnel_count() -> None:
    """Mirror the tunnel count and byte activity into proxy_status.

    The guard uses these fields to tell a streaming response from an idle
    socket, so the last byte has to be published alongside the count.
    """
    try:
        with STATUS_LOCK:
            data = _read_proxy_status()
            data["active_tunnels"] = _active_tunnels()
            data["active_tunnels_ts"] = int(time.time())
            data["last_byte_ts"] = int(_last_byte_ts())
            _write_proxy_status(data)
    except Exception:
        pass


def _note_tunnel_bytes() -> None:
    """Record that a tunnel relayed bytes, throttled to one status write per interval."""
    global _LAST_BYTE_TS, _LAST_BYTE_PUBLISH
    now = time.time()
    publish = False
    with _BYTE_LOCK:
        _LAST_BYTE_TS = now
        if now - _LAST_BYTE_PUBLISH >= BYTE_PUBLISH_INTERVAL:
            _LAST_BYTE_PUBLISH = now
            publish = True
    if publish:
        _publish_tunnel_count()


def _enter_tunnel() -> None:
    global _ACTIVE_TUNNELS
    with _TUNNEL_LOCK:
        _ACTIVE_TUNNELS += 1
    _publish_tunnel_count()


def _leave_tunnel() -> None:
    global _ACTIVE_TUNNELS
    with _TUNNEL_LOCK:
        _ACTIVE_TUNNELS = max(0, _ACTIVE_TUNNELS - 1)
    _publish_tunnel_count()


def _reset_tunnel_activity() -> None:
    """Drop the counters a previous server left behind in this process."""
    global _ACTIVE_TUNNELS, _LAST_BYTE_TS, _LAST_BYTE_PUBLISH
    with _TUNNEL_LOCK:
        _ACTIVE_TUNNELS = 0
    with _BYTE_LOCK:
        _LAST_BYTE_TS = 0.0
        _LAST_BYTE_PUBLISH = 0.0


def _clear_fallback() -> None:
    try:
        if FALLBACK_FLAG.is_file():
            FALLBACK_FLAG.unlink()
    except Exception:
        pass


def proxy_status() -> dict:
    """Return a compact snapshot for the dashboard and doctor."""
    with STATUS_LOCK:
        data = _read_proxy_status()
    now = time.time()
    recent = [e for e in data.get("recent", []) if now - float(e.get("ts", 0)) <= 300]
    data["recent"] = recent
    data["errors_5m"] = sum(
        1
        for e in recent
        if e.get("kind")
        in ("error", "reset", "stream_reset", "connect_fail", "edge_fail")
    )
    data["stream_resets_5m"] = sum(1 for e in recent if e.get("kind") == "stream_reset")
    data["fallbacks_5m"] = sum(1 for e in recent if e.get("kind") == "fallback")
    fallback_ts = float(data.get("fallback_ts", 0) or 0)
    data["fallback_age"] = max(0, int(now - fallback_ts)) if fallback_ts else None
    data["active_tunnels"] = _active_tunnels()
    return data


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
        self._bad_edges: dict[str, float] = {}
        self._stream_fails: dict[str, list[float]] = {}

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

    def _pick_edge_locked(self, exclude: str = "") -> str:
        now = time.monotonic()
        bad = {
            edge
            for edge, failed_at in self._bad_edges.items()
            if now - failed_at < EDGE_FAILURE_COOLDOWN
        }
        choices = [e for e in self._pool if e != exclude and e not in bad]
        if not choices:
            choices = [e for e in self._pool if e != exclude]
        if not choices:
            choices = list(self._pool)
        return random.choice(choices) if choices else self._edge

    def edges_to_try(self) -> list[str]:
        """Current edge first, then healthy alternatives instead of one long stall."""
        with self._lock:
            now = time.monotonic()
            bad = {
                edge
                for edge, failed_at in self._bad_edges.items()
                if now - failed_at < EDGE_FAILURE_COOLDOWN
            }
            primary = self._edge
            healthy = [e for e in self._pool if e != primary and e not in bad]
            if primary in bad and healthy:
                choices = healthy
            else:
                choices = [primary, *healthy]
            if not healthy:
                # Every edge is cooling down: keep trying rather than failing
                # outright, but still don't repeat the same address first.
                choices = [e for e in self._pool if e != primary] or [primary]
            return choices[:EDGE_TRY_LIMIT]

    def mark_edge_ok(self, edge: str) -> None:
        with self._lock:
            self._bad_edges.pop(edge, None)
            if edge and edge != self._edge:
                self._edge = edge
                try:
                    (LANE_DIR / "last_edge.txt").write_text(edge + "\n", encoding="utf-8")
                except Exception:
                    pass
        _clear_fallback()

    def mark_edge_failed(self, edge: str) -> None:
        with self._lock:
            self._bad_edges[edge] = time.monotonic()
            if edge == self._edge:
                self._edge = self._pick_edge_locked(exclude=edge)
                try:
                    (LANE_DIR / "last_edge.txt").write_text(self._edge + "\n", encoding="utf-8")
                except Exception:
                    pass

    def current_edge(self) -> str:
        with self._lock:
            return self._edge

    def note_stream_reset(self, edge: str) -> str:
        """Move away from an edge that keeps cutting live response streams.

        A single reset can be the provider closing a finished stream, so the
        edge is only retired after a second reset inside five minutes.
        """
        if not edge:
            return ""
        now = time.monotonic()
        with self._lock:
            stamps = [
                t for t in self._stream_fails.get(edge, []) if now - t < 300.0
            ]
            stamps.append(now)
            self._stream_fails[edge] = stamps
            if len(stamps) < 2 or edge != self._edge:
                return ""
            replacement = self._pick_edge_locked(exclude=edge)
            if not replacement or replacement == edge:
                return ""
            self._edge = replacement
            self._bad_edges[edge] = now
            try:
                (LANE_DIR / "last_edge.txt").write_text(
                    replacement + "\n", encoding="utf-8"
                )
            except Exception:
                pass
            return replacement

    def invalidate(self) -> None:
        """Drop the cached tunnel address after WARP reconnects."""
        with self._lock:
            self._ts = 0.0
            self._v6 = None

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
    # SO_REUSEADDR on Windows lets a second process bind an active port.
    allow_reuse_address = sys.platform != "win32"
    daemon_threads = True


def _note_stream_reset(
    host: str,
    detail: str,
    warp_state: _WarpState | None,
    edge: str,
) -> None:
    """Report a mid-stream reset and retire a repeatedly failing pinned edge."""
    replacement = ""
    if warp_state is not None:
        replacement = warp_state.note_stream_reset(edge)
    if replacement:
        detail = f"{detail}; moved to {replacement}"
    _record_stream_reset(host, detail, edge)


def _client_gone(sock: socket.socket, closed: set, seconds: float = 0.15) -> bool:
    """Return True when the client already closed, including a pending EOF.

    A reset after the client stopped reading is not a cut stream the user can
    see. Waiting briefly for a pending EOF keeps completed responses from
    being reported as failures when the server closes with RST.
    """
    if sock in closed:
        return True
    try:
        readable, _, _ = select.select([sock], [], [], seconds)
        if not readable:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except OSError:
        return True


def _read_exact(stream, size: int) -> bytes:
    """Read exactly ``size`` bytes from an unbuffered socket stream."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _drain_client(sock: socket.socket, seconds: float = 0.25) -> None:
    """Consume trailing client bytes so Windows closes with FIN instead of RST."""
    try:
        sock.setblocking(False)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            readable, _, _ = select.select([sock], [], [], 0.05)
            if not readable:
                continue
            if not sock.recv(65536):
                break
    except OSError:
        pass


def _relay(
    a: socket.socket,
    b: socket.socket,
    host: str = "",
    warp_state: _WarpState | None = None,
    edge: str = "",
) -> None:
    """Bidirectionally forward bytes between two sockets with TCP keepalive and resilient streaming."""
    sockets = [a, b]
    closed = set()
    seen_data = set()
    for s in (a, b):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_NODELAY"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Windows TCP keepalive parameters: idle 15s, interval 5s
            if hasattr(socket, "SIO_KEEPALIVE_VALS"):
                s.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 15000, 5000))
            # Linux TCP keepalive parameters: idle 15s, interval 5s, 5 probes
            if hasattr(socket, "TCP_KEEPIDLE"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
            if hasattr(socket, "TCP_KEEPINTVL"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            if hasattr(socket, "TCP_KEEPCNT"):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except Exception:
            pass

    last_active = time.monotonic()
    try:
        while sockets:
            readable, _, exceptional = select.select(sockets, [], sockets, 5.0)
            if exceptional:
                break
            if not readable:
                # Generous 15-minute idle ceiling for long-thinking models.
                if time.monotonic() - last_active > 900.0:
                    break
                continue

            last_active = time.monotonic()
            for src in readable:
                dst = b if src is a else a
                try:
                    data = src.recv(65536)
                except (ConnectionResetError, ConnectionAbortedError) as exc:
                    # Many servers end a completed response with a reset instead
                    # of a clean FIN. A reset before the upstream sent anything
                    # is a route failure; one after data started is a cut stream.
                    if src is b and src in seen_data:
                        if not _client_gone(a, closed):
                            _note_stream_reset(
                                host,
                                f"{type(exc).__name__} after response",
                                warp_state,
                                edge,
                            )
                    elif not closed and src not in seen_data:
                        _record_reset(host, f"{type(exc).__name__} before response")
                    data = b""
                except OSError as exc:
                    # Windows reports a peer reset as plain OSError/WSAECONNRESET.
                    winerror = getattr(exc, "winerror", None)
                    if src is b and src in seen_data:
                        if not _client_gone(a, closed):
                            _note_stream_reset(
                                host,
                                f"winsock {winerror} after response"
                                if winerror
                                else f"{type(exc).__name__} after response",
                                warp_state,
                                edge,
                            )
                    elif not closed and src not in seen_data and winerror in (10053, 10054):
                        _record_reset(host, f"winsock {winerror} before response")
                    data = b""

                if data:
                    seen_data.add(src)
                    try:
                        dst.sendall(data)
                        _note_tunnel_bytes()
                    except (OSError, ConnectionResetError) as exc:
                        # A failed write toward the client means the client went
                        # away; only a write toward the upstream host says
                        # anything about the route.
                        if not closed and dst is b:
                            if b in seen_data:
                                _note_stream_reset(
                                    host,
                                    f"send failed after response: {type(exc).__name__}",
                                    warp_state,
                                    edge,
                                )
                            else:
                                _record_reset(
                                    host,
                                    f"send to upstream failed: {type(exc).__name__}",
                                )
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
                    if src is b:
                        # The upstream cannot send anything else on this tunnel.
                        # Drain the client briefly so Windows emits FIN, not RST.
                        _drain_client(a)
                        return
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


def _local_address_stale(exc: OSError) -> bool:
    """Return True when the bound WARP address disappeared mid-flight."""
    return getattr(exc, "winerror", None) == 10049 or exc.errno == errno.EADDRNOTAVAIL


def _wait_for_new_local_v6(
    warp_state: _WarpState, previous: str, deadline: float
) -> str:
    """Poll for the address WARP assigns after a reconnect.

    WARP drops the old tunnel address and adds the new one a moment later, so a
    single immediate re-read usually still sees the stale value and the proxy
    reports a dead route for a tunnel that is seconds from working again.
    """
    while True:
        warp_state.invalidate()
        fresh, _ = warp_state.get(wait_if_rotating=False)
        if fresh and fresh != previous:
            return fresh
        if time.monotonic() >= deadline:
            return ""
        time.sleep(STALE_ADDRESS_POLL)


def _open_pinned_any(
    label: str,
    port: int,
    warp_state: _WarpState,
) -> tuple[socket.socket, str]:
    """Try the current pinned address, then a few alternatives, before declaring the route dead.

    A WARP reconnect replaces the local IPv6 address. Binding the old one fails
    on every edge, so refresh the cached address once instead of reporting the
    whole route as dead.
    """
    local_v6, _ = warp_state.get(wait_if_rotating=True)
    if not local_v6:
        raise ConnectionRefusedError("WARP tunnel has no IPv6 address")

    last: Exception | None = None
    attempts = 0
    deadline = time.monotonic() + STALE_ADDRESS_WAIT
    while attempts < 2:
        attempts += 1
        stale_local = False
        for edge in warp_state.edges_to_try():
            try:
                sock = _open_pinned_v6(
                    edge, port, local_v6, timeout=EDGE_CONNECT_TIMEOUT
                )
                warp_state.mark_edge_ok(edge)
                return sock, edge
            except Exception as exc:
                last = exc
                if isinstance(exc, OSError) and _local_address_stale(exc):
                    stale_local = True
                    break
                warp_state.mark_edge_failed(edge)
                _record_event("edge_fail", f"{type(exc).__name__}: {exc}", label, edge)

        if not stale_local:
            break
        fresh = _wait_for_new_local_v6(warp_state, local_v6, deadline)
        if not fresh:
            break
        local_v6 = fresh
        _record_event("repair", "local WARP address changed; retrying", label)

    raise ConnectionRefusedError(f"No Cloudflare edge answered ({last})") from last


def _active_warp_scope() -> str:
    """Return the configured WARP scope, defaulting to the platform's safe mode."""
    default_scope = "tun" if sys.platform == "win32" else "isolated"
    try:
        from proxy_chain import get_egress_config

        return str(get_egress_config().get("warp_scope", default_scope))
    except Exception:
        return default_scope


def _open_warp_direct(
    clean_host: str,
    port: int,
    warp_state: _WarpState,
) -> socket.socket:
    scope = _active_warp_scope()

    is_strict = os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()
    is_opencode_host = (
        clean_host in PINNED_HOSTS
        or clean_host.endswith(".opencode.ai")
        or clean_host.endswith(".opencode.com")
    )

    # 1. Isolated (App-Only) mode: tunnel via local WARP SOCKS5 proxy (port 40000)
    if scope == "isolated":
        try:
            from tor_manager import open_socks5_tunnel
            return open_socks5_tunnel(clean_host, port, socks_host="127.0.0.1", socks_port=40000, timeout=2.0)
        except Exception:
            pass

    # 2. TUN mode or fallback: bind explicitly to the WARP adapter's IPv6
    if is_opencode_host:
        try:
            sock, _ = _open_pinned_any(clean_host, port, warp_state)
            return sock
        except Exception as exc:
            _record_event("connect_fail", f"pinned route failed: {exc}", clean_host)

        # Try local WARP SOCKS5 if TUN socket bind failed
        try:
            from tor_manager import open_socks5_tunnel
            return open_socks5_tunnel(clean_host, port, socks_host="127.0.0.1", socks_port=40000, timeout=2.0)
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

    # 3. Strict fail-closed privacy mode never silently uses Tor or a
    #    different route; the caller performs a repair attempt and retries.
    if is_strict:
        raise ConnectionRefusedError(
            "Cloudflare WARP tunnel unavailable (fail-closed strict mode)"
        )

    # 4. Resilient failover: if WARP is down, try an active Tor client.
    try:
        from tor_manager import get_active_tor_target, open_socks5_tunnel
        tor_target = get_active_tor_target()
        if tor_target:
            sock = open_socks5_tunnel(
                clean_host,
                port,
                socks_host=tor_target[0],
                socks_port=tor_target[1],
                timeout=6.0,
            )
            if is_opencode_host:
                _mark_fallback(clean_host, "WARP route unavailable; OpenCode used the Tor fallback")
            return sock
    except Exception:
        pass

    # 5. Direct fallback keeps OpenCode usable when the tunnel drops.
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

    # Direct standard dual-stack connection (IPv4/IPv6). This silently leaves
    # the WARP IPv6 route, so record it instead of changing the route unseen.
    if is_opencode_host:
        _mark_fallback(
            clean_host,
            f"pinned IPv6 edge unavailable; OpenCode used the fallback route ({scope})",
        )
    sock = socket.create_connection((clean_host, port), timeout=8.0)
    sock.settimeout(None)
    return sock


_REPAIR_LOCK = threading.Lock()
_LAST_REPAIR = 0.0
_REPAIR_INTERVAL = 20.0


def _strict_mode() -> bool:
    return os.environ.get("OUC_STRICT_PROXY") == "1" or (
        LANE_DIR / "strict_proxy.flag"
    ).is_file()


def _repair_warp_tunnel(warp_state: _WarpState) -> bool:
    """Reconnect a dropped WARP tunnel, at most once per interval.

    Only runs when the route is actually down; reconnecting a healthy tunnel
    resets its pin and can cause the drops this function exists to repair.
    """
    global _LAST_REPAIR
    try:
        from proxy_chain import get_egress_config

        cfg = get_egress_config()
    except Exception:
        return False
    mode = str(cfg.get("mode", "warp"))
    if mode not in ("warp", "clean"):
        return False
    scope = str(cfg.get("warp_scope", "tun"))
    if scope == "isolated":
        try:
            with socket.create_connection(("127.0.0.1", 40000), timeout=0.6):
                return False
        except OSError:
            pass
    elif get_warp_local_v6():
        return False

    with _REPAIR_LOCK:
        if time.monotonic() - _LAST_REPAIR < _REPAIR_INTERVAL:
            return False
        _LAST_REPAIR = time.monotonic()

    _record_event("repair", f"reconnecting WARP tunnel ({mode}/{scope})")
    try:
        from ouc_common import (
            ensure_warp_mode,
            find_warp_cli,
            repair_warp_registration,
            run_warp,
            warp_registration_healthy,
        )

        warp_bin = find_warp_cli()
        if not warp_bin:
            return False
        if not warp_registration_healthy(warp_bin):
            if not repair_warp_registration(warp_bin, 2):
                return False
        ensure_warp_mode(warp_bin, scope)
        run_warp(["connect"], warp_bin=warp_bin, timeout=12.0)
        for _ in range(8):
            time.sleep(0.75)
            if scope == "isolated":
                try:
                    with socket.create_connection(("127.0.0.1", 40000), timeout=0.6):
                        return True
                except OSError:
                    pass
            if get_warp_local_v6():
                warp_state.poll_controls()
                return True
    except Exception:
        pass
    return False


def _open_upstream(
    host: str,
    port: int,
    warp_state: _WarpState,
) -> socket.socket:
    """Connect upstream through the active WARP, Tor, or custom route."""
    clean_host = host.strip("[]").lower()
    if clean_host in ("127.0.0.1", "localhost", "::1"):
        sock = socket.create_connection((clean_host, port), timeout=10.0)
        sock.settimeout(None)
        return sock

    try:
        from proxy_chain import get_egress_config, is_relay_mode, open_multi_egress_upstream

        cfg = get_egress_config()
        if cfg.get("mode") in ("tor", "custom"):
            try:
                return open_multi_egress_upstream(
                    host,
                    port,
                    lambda h, p: _open_warp_direct(h, p, warp_state),
                )
            except Exception as exc:
                # A relay is selected on purpose; quietly spending the local
                # WARP address instead would burn it and mask a dead relay.
                if _strict_mode() or is_relay_mode(cfg):
                    raise ConnectionRefusedError(
                        f"Multi-egress ({cfg.get('mode')}) upstream error: {exc}"
                    ) from exc
                return _open_warp_direct(clean_host, port, warp_state)
    except ConnectionRefusedError:
        raise
    except Exception:
        pass

    return _open_warp_direct(clean_host, port, warp_state)


def _rotation_in_progress() -> bool:
    """True only while the guard is actively replacing the tunnel address."""
    if not is_keeper_paused():
        return False
    try:
        age = time.time() - PAUSE_FILE.stat().st_mtime
    except OSError:
        return False
    return age <= ROTATION_FRESH_SECONDS


def _connect_upstream(
    host: str,
    port: int,
    warp_state: _WarpState,
) -> socket.socket:
    """Open the configured route, holding through a rotation and then repairing.

    Reconnecting the tunnel is destructive to every live response stream, so the
    repair is deferred while another tunnel is active. While the guard is
    rotating, the route is down on purpose: waiting the rotation out turns a
    hard connection failure into a short delay the client never sees.
    """
    deadline = time.monotonic() + ROTATION_HOLD_SECONDS
    repaired = False
    held = False

    def hold() -> None:
        """Keep the request waiting while the tunnel is being replaced."""
        nonlocal held
        if not held:
            held = True
            _record_event("hold", "waiting for the tunnel rotation to finish", host)

    while True:
        try:
            sock = _open_upstream(host, port, warp_state)
        except Exception as exc:
            if _rotation_in_progress() and time.monotonic() < deadline:
                hold()
                time.sleep(ROTATION_POLL_SECONDS)
                continue
            if not repaired and _active_tunnels() == 0:
                repaired = True
                if _repair_warp_tunnel(warp_state):
                    hold()
                    continue
            _record_event("connect_fail", f"{type(exc).__name__}: {exc}", host)
            raise
        if _rotation_in_progress() and time.monotonic() < deadline:
            # The tunnel answered but is about to be replaced: a new socket now
            # would land on the old IP and be reset mid-response anyway.
            hold()
            sock.close()
            time.sleep(ROTATION_POLL_SECONDS)
            continue
        return sock


def _make_handler(warp_state: _WarpState):
    class ProxyHandler(socketserver.StreamRequestHandler):
        # StreamRequestHandler defaults to a buffered rfile. That can swallow
        # the first TLS bytes after CONNECT headers and leaves the tunnel
        # waiting forever. Header reads are tiny, so unbuffered is safer.
        rbufsize = 0
        wbufsize = 0
        disable_nagle_algorithm = True

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
                if low.startswith("proxy-authorization:"):
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
                    upstream = _connect_upstream(host, port, warp_state)
                except Exception as exc:
                    if _strict_mode():
                        _record_event("error", f"CONNECT {host}:{port}: {exc}", host)
                        self._send_err(503, "Service Unavailable", f"Strict mode blocked the route to {host}:{port}. {exc}")
                        return
                    # Direct fallback keeps OpenCode usable when the route drops.
                    try:
                        upstream = socket.create_connection((host, port), timeout=8.0)
                        upstream.settimeout(None)
                        _mark_fallback(host, f"CONNECT {host}:{port} used the direct route ({exc})")
                    except Exception as exc2:
                        _record_event("error", f"CONNECT {host}:{port}: {exc2}", host)
                        self._send_err(503, "Service Unavailable", f"Opencode Unlimited could not reach {host}:{port}. {exc2}")
                        return

                edge = warp_state.current_edge()
                _enter_tunnel()
                try:
                    self.wfile.write(f"{proto} 200 Connection Established\r\n\r\n".encode("ascii"))
                    self.wfile.flush()
                    _relay(self.connection, upstream, host, warp_state, edge)
                except OSError:
                    _record_reset(host, "client closed before tunnel reply")
                finally:
                    _leave_tunnel()
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
                upstream = _connect_upstream(host, port, warp_state)
            except Exception as exc:
                if _strict_mode():
                    _record_event("error", f"HTTP {host}:{port}: {exc}", host)
                    self._send_err(503, "Service Unavailable", f"Strict mode blocked the route to {host}:{port}. {exc}")
                    return
                # Direct fallback keeps OpenCode usable when the route drops.
                try:
                    upstream = socket.create_connection((host, port), timeout=8.0)
                    upstream.settimeout(None)
                    _mark_fallback(host, f"HTTP {host}:{port} used the direct route ({exc})")
                except Exception as exc2:
                    _record_event("error", f"HTTP {host}:{port}: {exc2}", host)
                    self._send_err(503, "Service Unavailable", f"Opencode Unlimited could not reach {host}:{port}. {exc2}")
                    return

            edge = warp_state.current_edge()
            _enter_tunnel()
            try:
                req_head = f"{method} {path} {proto}\r\n".encode("latin-1")
                upstream.sendall(req_head)
                for h in headers:
                    upstream.sendall(h)
                upstream.sendall(b"\r\n")
                if content_len > 0:
                    body = _read_exact(self.rfile, content_len)
                    if body:
                        upstream.sendall(body)
                _relay(self.connection, upstream, host, warp_state, edge)
            finally:
                _leave_tunnel()
                upstream.close()

        def _send_err(self, code: int, reason: str, detail: str = "") -> None:
            try:
                safe = reason.replace("\r", " ").replace("\n", " ")
                text = safe
                extra = detail.replace("\r", " ").replace("\n", " ").strip()
                if extra:
                    text = f"{safe}\n{extra}"
                payload = text.encode("utf-8", errors="replace")
                head = (
                    f"HTTP/1.1 {code} {safe}\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("latin-1", errors="replace")
                self.wfile.write(head + payload)
                self.wfile.flush()
            except OSError:
                pass

    return ProxyHandler


def start_proxy_server(port: int = 0) -> tuple[_ThreadedTCPServer, int, str]:
    """Start the local CONNECT proxy in a background thread and return (server, port, edge)."""
    pinned_edge = os.environ.get("OUC_PIN_EDGE", "").strip()
    scope = _active_warp_scope()

    # Isolated mode forwards through WARP's local SOCKS proxy; pinned IPv6 edge
    # discovery is only needed for a direct TUN route. Skipping it removes
    # several DNS timeouts from every Linux launch.
    if scope == "isolated" and not pinned_edge:
        pool: list[str] = []
        chosen_edge = ""
    else:
        pool = fetch_opencode_aaaa_pool()
        chosen_edge = pinned_edge or random.choice(pool)

    try:
        ensure_dirs()
        if chosen_edge:
            (LANE_DIR / "last_edge.txt").write_text(chosen_edge + "\n", encoding="utf-8")
    except Exception:
        pass

    warp_state = _WarpState(pool=pool, initial_edge=chosen_edge, ttl=1.5)
    handler = _make_handler(warp_state)
    try:
        srv = _ThreadedTCPServer(("127.0.0.1", port), handler)
    except OSError as exc:
        _record_event("bind_fail", f"127.0.0.1:{port}: {exc}")
        raise
    actual_port = srv.server_address[1]
    _clear_fallback()
    # A fresh proxy owns no tunnels; republishing zero clears the count and the
    # byte stamp left by the process it replaces so the guard does not wait on
    # a phantom stream.
    _reset_tunnel_activity()
    _publish_tunnel_count()
    _record_event(
        "start",
        f"listening on 127.0.0.1:{actual_port} (edge={chosen_edge or 'isolated'})",
    )
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


def _write_port_file(path: str, port: int) -> None:
    """Publish the bound port so a launcher can attach without guessing."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(str(port), encoding="utf-8")
    tmp.replace(target)


if __name__ == "__main__":
    cli = sys.argv[1:]
    port_file = ""
    if "--port-file" in cli:
        idx = cli.index("--port-file")
        if idx + 1 < len(cli):
            port_file = cli[idx + 1]
            del cli[idx : idx + 2]
    bind_port = int(cli[0]) if cli else 0
    server, listening_port, edge = start_proxy_server(bind_port)
    if port_file:
        _write_port_file(port_file, listening_port)
    print(
        f"zen-proxy listening on 127.0.0.1:{listening_port} "
        f"(edge={edge or 'isolated'})",
        flush=True,
    )
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
