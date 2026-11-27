#!/usr/bin/env python3
"""blockrelay - authenticated CONNECT relay with sticky IPv6 /64 blocks.

The OpenCode free tier meters requests per egress block: one IPv6 /64 (or one
IPv4 /32) per UTC day.  A routed IPv6 prefix therefore behaves like a pool of
independent daily budgets.  So does a WarpGate host, where every Cloudflare WARP
registration carries its own IPv6 exit.  This relay hands each client one block
from whichever lane the operator runs, dials the upstream from it, and rotates
the client to a different block when the client reports a quota wall.

Design constraints:

* The relay is a blind CONNECT tunnel.  It never terminates TLS and never edits
  the request, so the OpenCode client fingerprint reaches the gateway exactly as
  it left the app.
* Only a fixed host allowlist is tunneled.  The relay is not an open proxy.
* Blocks are sticky per client token so a user's whole session shares one
  budget, which is how the upstream limiter counts.
* The routed-prefix lane is Linux only (IP_FREEBIND / ip_nonlocal_bind).  The
  WarpGate lane has no such requirement, which is what makes it portable.

Run ``blockrelay.py --help`` for the CLI.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import secrets
import signal
import socket
import sqlite3
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import warpgate_pool
from warpgate_pool import Instance, WarpGateError, WarpGatePool

# Linux socket options.  Python may not expose IPV6_FREEBIND on every build, and
# the numeric values are stable in the kernel ABI.
IP_FREEBIND = 15
IPV6_FREEBIND = 78

BLOCK_PREFIX = 64
DAY_SECONDS = 86400
# The relay is token-authenticated per client, so it is not an open proxy even
# when every host is reachable.  Operators can narrow this to specific hosts;
# a narrow list has to cover every domain the OpenCode client contacts
# (models.dev, update checks), or those requests fail with 403.
DEFAULT_ALLOWED_HOSTS = ["*"]

# How long an instance→exit mapping is trusted before it is probed again.
EXIT_CACHE_SECONDS = 6 * 3600
# Attempts spent looking for an exit that is not already spent for the day.
ACQUIRE_ATTEMPTS = 12
# A retired instance is rebuilt by WarpGate in the background, so getting the
# same name back twice in a row is not a hard failure -- it is a rebuild that
# has not finished. Waiting briefly lets the replacement come up instead of
# spending every attempt in the same millisecond.
REBUILD_SETTLE_SECONDS = 0.4
REBUILD_SETTLE_BUDGET = 6.0
# Re-registrations allowed inside one assignment. A fresh registration normally
# yields a new block on the first try; a second covers a rebuild that has not
# finished. Anything beyond that means the pool has no unspent exits at all, and
# each attempt is two Cloudflare calls, so the loop stops re-registering and
# reports the shortage instead.
REISSUE_ATTEMPTS = 2
# A gate that has seen at least this many reports and answers 403 on this share
# of them is handing out a blocked exit. Mirrors WarpGate's own defaults so the
# relay and the pool agree on what "blocked" means.
CF_403_THRESHOLD = 50.0
CF_403_MIN_CHECKS = 3
# How long one per-instance health snapshot is trusted before re-reading it.
# Assignment is the hot path; a 30 s window keeps the extra call off it while
# still refusing an exit the gate has just condemned.
HEALTH_TTL_SECONDS = 30.0
# Backoff after the gate's per-source rate limiter refuses a control call.
RATE_LIMIT_BACKOFF = 0.5
RATE_LIMIT_BUDGET = 3.0


def log(message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{stamp} {message}", flush=True)


def utc_midnight(now: int | None = None) -> int:
    """The next 00:00 UTC, when the upstream free allowance resets."""
    stamp = datetime.fromtimestamp(int(now or time.time()), timezone.utc)
    nxt = (stamp + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(nxt.timestamp())


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_basic(value: str) -> str:
    """Return the password half of ``Basic user:password`` (the client token).

    Accepts the bare base64 payload as well as the full header value, because
    curl, Python and OpenCode all send the scheme prefix.
    """
    text = (value or "").strip()
    if " " in text:
        scheme, text = text.split(" ", 1)
        if scheme.lower() not in ("basic", "bearer"):
            return ""
        text = text.strip()
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8")
    except Exception:
        return ""
    return decoded.split(":", 1)[1] if ":" in decoded else ""


def parse_bearer(value: str) -> str:
    text = (value or "").strip()
    if text.lower().startswith("bearer "):
        return text[7:].strip()
    return ""


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.strip().strip("[]").lower().rstrip(".")
    for item in allowed:
        item = item.strip().lower().rstrip(".")
        if not item:
            continue
        if item == "*":
            return True
        if item.startswith("*."):
            if host.endswith(item[1:]):
                return True
        elif host == item:
            return True
    return False


def egress_in_block(egress: str, block: str) -> bool:
    """True when the address seen from outside really belongs to ``block``."""
    try:
        address = ipaddress.ip_address((egress or "").strip())
        return address.version == 6 and address in ipaddress.IPv6Network(
            block, strict=False
        )
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass
class Config:
    listen: str = "0.0.0.0"
    port: int = 4443
    database: str = "relay.db"
    prefixes: list[str] = field(default_factory=list)
    bind_suffix: str = "::1"
    allowed_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS))
    admin_token: str = ""
    enroll_secret: str = ""
    tls_cert: str = ""
    tls_key: str = ""
    max_tunnels_per_client: int = 8
    idle_timeout: float = 300.0
    connect_timeout: float = 15.0
    public_url: str = ""
    # prefix: routed IPv6 prefix only.  warpgate: WarpGate instances only.
    # hybrid: routed prefix first, WarpGate when the prefix has nothing left.
    upstream_mode: str = "prefix"
    warpgate_url: str = ""
    warpgate_username: str = ""
    warpgate_password: str = ""
    warpgate_proxy_host: str = ""
    warpgate_api_key: str = ""
    warpgate_sticky_minutes: int = 1440
    warpgate_verify_tls: bool = True
    warpgate_timeout: float = 10.0

    @property
    def blocks(self) -> list[ipaddress.IPv6Network]:
        nets: list[ipaddress.IPv6Network] = []
        for raw in self.prefixes:
            net = ipaddress.IPv6Network(str(raw).strip(), strict=False)
            if net.version != 6:
                raise ValueError(f"prefix {raw!r} is not IPv6")
            if net.prefixlen > BLOCK_PREFIX:
                net = ipaddress.IPv6Network(
                    f"{net.network_address}/{BLOCK_PREFIX}", strict=False
                )
            nets.append(net)
        return nets

    @property
    def uses_prefix(self) -> bool:
        return self.upstream_mode in ("prefix", "hybrid") and bool(self.prefixes)

    @property
    def uses_warpgate(self) -> bool:
        return self.upstream_mode in ("warpgate", "hybrid")

    @property
    def capacity(self) -> int:
        total = 0
        for net in self.blocks:
            total += 1 << (BLOCK_PREFIX - net.prefixlen)
        return total

    def pool(self) -> WarpGatePool | None:
        """Build the WarpGate client, or ``None`` when the lane is off."""
        if not self.uses_warpgate or not self.warpgate_url:
            return None
        return WarpGatePool(
            self.warpgate_url,
            self.warpgate_username,
            self.warpgate_password,
            proxy_host=self.warpgate_proxy_host,
            api_key=self.warpgate_api_key,
            sticky_minutes=self.warpgate_sticky_minutes,
            timeout=self.warpgate_timeout,
            verify_tls=self.warpgate_verify_tls,
        )

    @classmethod
    def load(cls, path: Path) -> "Config":
        data = json.loads(path.read_text(encoding="utf-8"))
        tls = data.get("tls") or {}
        upstream = data.get("upstream") or {}
        if not isinstance(upstream, dict):
            raise ValueError("upstream must be an object")
        gate = upstream.get("warpgate") or data.get("warpgate") or {}
        if not isinstance(gate, dict):
            raise ValueError("upstream.warpgate must be an object")
        mode = str(
            upstream.get("mode", data.get("upstream_mode", "prefix"))
        ).lower().strip()
        cfg = cls(
            listen=str(data.get("listen", "0.0.0.0")),
            port=int(data.get("port", 4443)),
            database=str(data.get("database", "relay.db")),
            prefixes=[str(x) for x in data.get("prefixes", [])],
            bind_suffix=str(data.get("bind_suffix", "::1")),
            allowed_hosts=[str(x) for x in data.get("allowed_hosts", DEFAULT_ALLOWED_HOSTS)],
            admin_token=str(data.get("admin_token", "")),
            enroll_secret=str(data.get("enroll_secret", "")),
            tls_cert=str(tls.get("cert", data.get("tls_cert", ""))),
            tls_key=str(tls.get("key", data.get("tls_key", ""))),
            max_tunnels_per_client=int(data.get("max_tunnels_per_client", 8)),
            idle_timeout=float(data.get("idle_timeout", 300)),
            connect_timeout=float(data.get("connect_timeout", 15)),
            public_url=str(data.get("public_url", "")),
            upstream_mode=mode,
            warpgate_url=str(gate.get("url", "")),
            warpgate_username=str(gate.get("username", "")),
            warpgate_password=str(gate.get("password", "")),
            warpgate_proxy_host=str(gate.get("proxy_host", "")),
            warpgate_api_key=str(gate.get("api_key", "")),
            warpgate_sticky_minutes=int(gate.get("sticky_minutes", 1440)),
            warpgate_verify_tls=bool(gate.get("verify_tls", True)),
            warpgate_timeout=float(gate.get("timeout", 10)),
        )
        if cfg.upstream_mode not in ("prefix", "warpgate", "hybrid"):
            raise ValueError(
                f"upstream.mode must be prefix, warpgate or hybrid (got {mode!r})"
            )
        if cfg.upstream_mode in ("prefix", "hybrid") and not cfg.prefixes:
            raise ValueError(
                "config needs at least one IPv6 prefix for the prefix lane"
            )
        if not cfg.uses_prefix and not cfg.uses_warpgate:
            raise ValueError("config has no usable egress lane")
        if cfg.uses_warpgate and not cfg.warpgate_url:
            raise ValueError("upstream.warpgate.url is required for the WarpGate lane")
        # Validate early so a bad prefix cannot fail at request time.
        _ = cfg.blocks
        if not cfg.admin_token:
            raise ValueError("config needs an admin_token")
        return cfg


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #


class Store:
    """Small SQLite ledger.

    Every websocket or HTTP request is handled on the asyncio thread, so a single
    connection with a short busy timeout is enough.  WAL keeps readers from
    blocking during tunnels.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        parent = Path(path).expanduser().resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=10.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                token_hash TEXT UNIQUE NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                block TEXT NOT NULL DEFAULT '',
                lane TEXT NOT NULL DEFAULT 'prefix',
                upstream TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL DEFAULT 0,
                requests INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS blocks (
                block TEXT PRIMARY KEY,
                client_id TEXT,
                requests INTEGER NOT NULL DEFAULT 0,
                last_used INTEGER NOT NULL DEFAULT 0,
                burnt_until INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS exits (
                name TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL DEFAULT '',
                block TEXT NOT NULL DEFAULT '',
                seen INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        # Databases created before the WarpGate lane existed need the extra
        # columns; sqlite has no "add column if not exists".
        for table, column, ddl in (
            ("clients", "lane", "TEXT NOT NULL DEFAULT 'prefix'"),
            ("clients", "upstream", "TEXT NOT NULL DEFAULT ''"),
        ):
            present = {
                row["name"]
                for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if column not in present:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        self.conn.commit()

    # -- settings ---------------------------------------------------------- #

    def get_setting(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    # -- blocks ------------------------------------------------------------ #

    def _iter_blocks(self, cfg: Config):
        offset_base = int(self.get_setting("cursor", "0"))
        candidates: list[tuple[ipaddress.IPv6Network, int]] = []
        for net in cfg.blocks:
            count = 1 << (BLOCK_PREFIX - net.prefixlen)
            candidates.append((net, count))
        total = sum(count for _, count in candidates)
        cursor = offset_base % max(1, total)
        remaining = total
        while remaining:
            seen = 0
            for net, count in candidates:
                if cursor >= seen + count:
                    seen += count
                    continue
                index = cursor - seen
                address = int(net.network_address) + (index << 64)
                yield str(ipaddress.IPv6Network((address, BLOCK_PREFIX)))
                remaining -= 1
                cursor += 1
                if cursor >= total:
                    cursor = 0
                break
            else:
                break

    def allocate_block(self, cfg: Config) -> str | None:
        """Return a free /64, rotating the scan cursor so blocks are spread out."""
        now = int(time.time())
        self.conn.execute(
            "UPDATE blocks SET burnt_until=0, client_id=NULL "
            "WHERE burnt_until<>0 AND burnt_until<=?",
            (now,),
        )
        self.conn.commit()
        for block in self._iter_blocks(cfg):
            row = self.conn.execute(
                "SELECT client_id, burnt_until FROM blocks "
                "WHERE block=? AND burnt_until<=?",
                (block, now),
            ).fetchone()
            if row is None:
                # Either brand new, or still burnt from an earlier rotation.
                exists = self.conn.execute(
                    "SELECT burnt_until FROM blocks WHERE block=?", (block,)
                ).fetchone()
                if exists is not None:
                    continue
                self.conn.execute("INSERT INTO blocks(block) VALUES(?)", (block,))
                self.conn.commit()
                return block
            if not row["client_id"]:
                return block
        return None

    def bind_block(self, block: str, client_id: str) -> None:
        self.conn.execute(
            "INSERT INTO blocks(block, client_id) VALUES(?, ?) "
            "ON CONFLICT(block) DO UPDATE SET client_id=excluded.client_id",
            (block, client_id),
        )
        self.conn.commit()

    def claim_block(self, block: str, client_id: str, now: int | None = None) -> bool:
        """Try to take ``block`` for ``client_id``.

        The WarpGate lane discovers blocks rather than slicing them out of a
        prefix, so two clients can be offered the same /64 by two paths.  This
        is the single arbiter: a block held by someone else, or burnt for the
        rest of the UTC day, is refused and the caller asks for another exit.
        """
        now = int(now or time.time())
        row = self.conn.execute(
            "SELECT client_id, burnt_until FROM blocks WHERE block=?", (block,)
        ).fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO blocks(block, client_id) VALUES(?, ?)", (block, client_id)
            )
            self.conn.commit()
            return True
        if row["client_id"] == client_id:
            return True
        if row["client_id"]:
            return False
        if row["burnt_until"] > now:
            return False
        self.conn.execute(
            "UPDATE blocks SET client_id=?, burnt_until=0 WHERE block=?",
            (client_id, block),
        )
        self.conn.commit()
        return True

    def release_block(self, block: str) -> None:
        """Give a block back without burning it."""
        self.conn.execute(
            "UPDATE blocks SET client_id=NULL WHERE block=?", (block,)
        )
        self.conn.commit()

    def set_route(self, client_id: str, block: str, lane: str, upstream: str = "") -> None:
        self.conn.execute(
            "UPDATE clients SET block=?, lane=?, upstream=? WHERE id=?",
            (block, lane, upstream, client_id),
        )
        self.conn.commit()

    def block_is_spent(self, block: str, now: int | None = None) -> bool:
        """True when nobody holds ``block`` and it is burnt for the day.

        This is the difference between an exit that is worth replacing and one
        that belongs to a live client: a spent block has no owner, so the
        WarpGate registration behind it can be re-registered without taking
        anyone offline.
        """
        now = int(now or time.time())
        row = self.conn.execute(
            "SELECT client_id, burnt_until FROM blocks WHERE block=?", (block,)
        ).fetchone()
        if row is None:
            return False
        return not row["client_id"] and int(row["burnt_until"] or 0) > now

    def burn_block(self, block: str, client_id: str) -> None:
        self.conn.execute(
            "UPDATE blocks SET client_id=NULL, burnt_until=?, last_used=? WHERE block=?",
            (utc_midnight(), int(time.time()), block),
        )
        self.conn.commit()

    # -- WarpGate exit cache ------------------------------------------------ #

    def exit_block(self, name: str, endpoint: str) -> str:
        """Cached /64 for a WarpGate instance, or ``""`` when it needs a probe."""
        row = self.conn.execute(
            "SELECT block, endpoint, seen FROM exits WHERE name=?", (name,)
        ).fetchone()
        if row is None:
            return ""
        if row["endpoint"] and row["endpoint"] != endpoint:
            return ""
        if int(row["seen"]) + EXIT_CACHE_SECONDS < int(time.time()):
            return ""
        return str(row["block"] or "")

    def put_exit(self, name: str, endpoint: str, block: str) -> None:
        self.conn.execute(
            "INSERT INTO exits(name, endpoint, block, seen) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET endpoint=excluded.endpoint, "
            "block=excluded.block, seen=excluded.seen",
            (name, endpoint, block, int(time.time())),
        )
        self.conn.commit()

    def forget_exit(self, name: str) -> None:
        """Drop a cached /64 for an instance WarpGate is about to rebuild.

        A rebuilt instance keeps its name and port but answers from a brand new
        WARP account, so the cached row would keep pointing the router at a
        block that is already spent.
        """
        self.conn.execute("DELETE FROM exits WHERE name=?", (name,))
        self.conn.commit()

    # -- clients ----------------------------------------------------------- #

    def create_client(
        self,
        cfg: Config,
        label: str = "",
        assign_block: bool | None = None,
    ) -> tuple[str, str, str]:
        """Create a client, return (client_id, token, block).

        ``block`` is empty when the client will be routed by the WarpGate lane
        on its first request.  Pre-assigning a routed block is skipped when the
        prefix has nothing left but WarpGate capacity remains, so a full prefix
        does not stop new users from enrolling.
        """
        if assign_block is None:
            assign_block = cfg.uses_prefix
        last_error: Exception | None = None
        for _ in range(8):
            block = self.allocate_block(cfg) if assign_block else None
            if not block and not cfg.uses_warpgate:
                raise RuntimeError("no free blocks left; add another prefix or relay")
            token = secrets.token_urlsafe(32)
            client_id = "cl_" + secrets.token_hex(8)
            lane = "prefix" if block else "warpgate"
            try:
                self.conn.execute(
                    "INSERT INTO clients(id, token_hash, label, block, lane, created_at) "
                    "VALUES(?, ?, ?, ?, ?, ?)",
                    (
                        client_id,
                        hash_token(token),
                        label,
                        block or "",
                        lane,
                        int(time.time()),
                    ),
                )
                self.conn.commit()
                if block:
                    self.bind_block(block, client_id)
                return client_id, token, block or ""
            except sqlite3.IntegrityError as exc:  # extremely unlikely
                last_error = exc
                self.conn.rollback()
                if block:
                    self.release_block(block)
                continue
        raise RuntimeError(f"could not allocate a client: {last_error}")

    def client_by_token(self, token: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM clients WHERE token_hash=? AND enabled=1",
            (hash_token(token),),
        ).fetchone()

    def client_by_id(self, client_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()

    def rotate_client(self, cfg: Config, client_id: str) -> tuple[str, str]:
        row = self.client_by_id(client_id)
        if not row:
            raise LookupError("unknown client")
        old = str(row["block"])
        if old:
            self.burn_block(old, client_id)
        block = self.allocate_block(cfg)
        if not block:
            # Put the old block back if it was not actually burnt; the caller
            # should add capacity instead of leaving the client without a route.
            if old:
                self.bind_block(old, client_id)
                self.conn.execute(
                    "UPDATE blocks SET burnt_until=0 WHERE block=?", (old,)
                )
                self.conn.commit()
            raise RuntimeError("no free blocks left; add another prefix or relay")
        # A rotated block always comes from the prefix lane, so the client must
        # leave any WarpGate lease behind; keeping the old lane would route the
        # prefix block through an instance that never answers from it.
        self.conn.execute(
            "UPDATE clients SET block=?, lane='prefix', upstream='' WHERE id=?",
            (block, client_id),
        )
        self.conn.commit()
        self.bind_block(block, client_id)
        return old, block

    def touch(self, client_id: str, block: str, requests: int = 1) -> None:
        now = int(time.time())
        self.conn.execute(
            "UPDATE clients SET last_seen=?, requests=requests+? WHERE id=?",
            (now, requests, client_id),
        )
        self.conn.execute(
            "UPDATE blocks SET last_used=?, requests=requests+? WHERE block=?",
            (now, requests, block),
        )
        self.conn.commit()

    def stats(
        self,
        cfg: Config,
        gate: "warpgate_pool.PoolStats | None" = None,
        capacity: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time())
        clients = self.conn.execute(
            "SELECT COUNT(*) AS n FROM clients WHERE enabled=1"
        ).fetchone()["n"]
        burnt = self.conn.execute(
            "SELECT COUNT(*) AS n FROM blocks WHERE burnt_until>?", (now,)
        ).fetchone()["n"]
        assigned = self.conn.execute(
            "SELECT COUNT(*) AS n FROM blocks WHERE client_id IS NOT NULL"
        ).fetchone()["n"]
        per_lane = {"prefix": 0, "warpgate": 0}
        for row in self.conn.execute(
            "SELECT lane, COUNT(*) AS n FROM clients WHERE enabled=1 GROUP BY lane"
        ):
            per_lane[str(row["lane"] or "prefix")] = int(row["n"])

        prefix_capacity = cfg.capacity if cfg.uses_prefix else 0
        prefix_assigned = 0
        if cfg.uses_prefix:
            nets = cfg.blocks
            for row in self.conn.execute(
                "SELECT block FROM blocks WHERE client_id IS NOT NULL"
            ):
                try:
                    net = ipaddress.IPv6Network(str(row["block"]), strict=False)
                except ValueError:
                    continue
                if any(net.subnet_of(item) for item in nets):
                    prefix_assigned += 1
        gate_free = None if gate is None else max(0, gate.available)
        return {
            "lane": cfg.upstream_mode,
            "capacity": (capacity if capacity is not None else prefix_capacity) or None,
            "prefix_blocks": prefix_capacity,
            "prefix_assigned": prefix_assigned,
            "prefix_free": max(0, prefix_capacity - prefix_assigned),
            "warpgate_instances": None if gate is None else gate.instances,
            "warpgate_available": gate_free,
            "warpgate_reachable": None if gate is None else gate.reachable,
            "warpgate_detail": "" if gate is None else gate.detail,
            "clients": clients,
            "clients_prefix": per_lane.get("prefix", 0),
            "clients_warpgate": per_lane.get("warpgate", 0),
            "assigned_blocks": assigned,
            "burnt_blocks": burnt,
            "free_blocks": (
                max(0, prefix_capacity - prefix_assigned)
                if cfg.uses_prefix
                else gate_free
            ),
            "requests": self.conn.execute(
                "SELECT COALESCE(SUM(requests), 0) AS n FROM clients"
            ).fetchone()["n"],
            "resets_at": utc_midnight(),
        }


# --------------------------------------------------------------------------- #
# Outbound
# --------------------------------------------------------------------------- #


def _set_freebind(sock: socket.socket) -> None:
    """Allow binding an address that is routed to this host but not assigned."""
    for level, option in ((socket.IPPROTO_IPV6, IPV6_FREEBIND), (socket.IPPROTO_IP, IP_FREEBIND)):
        try:
            sock.setsockopt(level, option, 1)
        except OSError:
            # Some kernels only accept one of the two; ip_nonlocal_bind covers
            # the rest.  A real bind failure is reported by bind() below.
            pass


def source_for(cfg: Config, block: str) -> str:
    net = ipaddress.IPv6Network(block, strict=False)
    suffix = (cfg.bind_suffix or "::1").strip()
    if suffix.startswith("::"):
        return str(net.network_address + int(ipaddress.IPv6Address(suffix)))
    # A full address or a partial suffix that already names the low bits.
    return str(ipaddress.IPv6Address(suffix))


def resolve_aaaa(host: str, port: int, timeout: float = 8.0) -> list[tuple]:
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
    except socket.gaierror:
        infos = []
    if infos:
        return infos
    # Some resolvers return only A records for hosts that do have AAAA.  Ask
    # Cloudflare's DoH resolver directly as a fallback, then connect by address.
    import urllib.parse
    import urllib.request

    query = urllib.parse.quote(host, safe="")
    url = f"https://cloudflare-dns.com/dns-query?name={query}&type=AAAA"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []
    answers = [
        item.get("data", "")
        for item in payload.get("Answer", [])
        if item.get("type") == 28 and item.get("data")
    ]
    result = []
    for address in answers:
        try:
            ip = ipaddress.IPv6Address(address)
        except ValueError:
            continue
        result.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(ip), port, 0, 0)))
    return result


async def open_bound(
    cfg: Config,
    host: str,
    port: int,
    block: str,
    timeout: float | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection from the client's block to ``host:port``."""
    loop = asyncio.get_running_loop()
    infos = await asyncio.to_thread(resolve_aaaa, host, port)
    if not infos:
        raise ConnectionError(f"no IPv6 address for {host}")
    source = source_for(cfg, block)
    last: Exception | None = None
    for info in infos:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setblocking(False)
        _set_freebind(sock)
        try:
            sock.bind((source, 0, 0, 0))
            await asyncio.wait_for(
                loop.sock_connect(sock, info[4]), timeout or cfg.connect_timeout
            )
            return await asyncio.open_connection(sock=sock)
        except Exception as exc:
            last = exc
            sock.close()
            continue
    raise ConnectionError(f"{host}:{port} unreachable from {source}: {last}")


def verify_block_sync(cfg: Config, block: str, timeout: float = 10.0) -> str:
    """Dial a Cloudflare trace endpoint from ``block`` and return the seen IP."""
    host = "www.cloudflare.com"
    infos = resolve_aaaa(host, 443)
    if not infos:
        return ""
    source = source_for(cfg, block)
    for info in infos:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        _set_freebind(sock)
        try:
            sock.bind((source, 0, 0, 0))
            sock.connect(info[4])
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(
                    b"GET /cdn-cgi/trace HTTP/1.1\r\n"
                    b"Host: www.cloudflare.com\r\n"
                    b"User-Agent: blockrelay\r\n"
                    b"Connection: close\r\n\r\n"
                )
                data = b""
                while len(data) < 65536:
                    chunk = tls.recv(8192)
                    if not chunk:
                        break
                    data += chunk
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            continue
        for line in data.decode("utf-8", "replace").splitlines():
            if line.startswith("ip="):
                return line.split("=", 1)[1].strip()
    return ""


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #


class NoCapacity(RuntimeError):
    """Every lane is out of unspent blocks."""


@dataclass
class Route:
    """Where a client's bytes leave from."""

    lane: str
    block: str
    source: str
    instance: Instance | None = None

    @property
    def label(self) -> str:
        if self.instance is None:
            return f"prefix:{self.source}"
        return f"warpgate:{self.instance.name}@{self.instance.endpoint}"

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "lane": self.lane,
            "block": self.block,
            "source": self.source,
        }
        if self.instance is not None:
            payload["instance"] = self.instance.name
            payload["endpoint"] = self.instance.endpoint
        return payload


def _instance_to_json(instance: Instance) -> str:
    return json.dumps(
        {
            "name": instance.name,
            "host": instance.host,
            "port": instance.port,
            "username": instance.username,
            "password": instance.password,
            "session_id": instance.session_id,
        },
        separators=(",", ":"),
    )


def _instance_from_json(raw: str) -> Instance | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return Instance(
            name=str(data["name"]),
            host=str(data["host"]),
            port=int(data["port"]),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            session_id=str(data.get("session_id", "")),
        )
    except Exception:
        return None


class Router:
    """Chooses and drives the egress lane for each client.

    Two lanes exist.  The prefix lane slices a routed IPv6 prefix into /64s and
    binds a source address inside each one, which is exact but needs a Linux
    host with a real prefix.  The WarpGate lane leases a WARP registration per
    client and reads its exit back, which needs no prefix and no Linux
    privileges but caps out at the number of registrations.

    Running both (``hybrid``) spends prefix blocks first, because they are
    free and unlimited, and falls back to WarpGate when the prefix is used up.
    """

    def __init__(self, cfg: Config, store: Store, pool: WarpGatePool | None = None) -> None:
        self.cfg = cfg
        self.store = store
        self.pool = pool if pool is not None else cfg.pool()
        self._stats: tuple[float, warpgate_pool.PoolStats] | None = None
        self._health: tuple[float, dict[str, warpgate_pool.InstanceHealth]] | None = None

    # -- capacity ----------------------------------------------------------- #

    async def gate_health(self, ttl: float = 30.0) -> dict[str, warpgate_pool.InstanceHealth]:
        """Cached per-instance view; empty when the gate cannot be asked.

        Empty means "nothing known", never "everything is fine": callers fail
        open so a missing endpoint cannot block assignment, and a gate that has
        never seen a report simply has no 403 number to judge.
        """
        if not self.pool:
            return {}
        cached = self._health
        if cached and cached[0] + ttl > time.time():
            return cached[1]
        try:
            items = await asyncio.to_thread(self.pool.instances)
        except Exception:
            items = []
        view = {item.name: item for item in items}
        self._health = (time.time(), view)
        return view

    def _may_use(self, view: dict[str, warpgate_pool.InstanceHealth], name: str) -> str:
        """Why an offer is unusable, or ``""`` when it is fine.

        Only facts the gate states are used. ``unknown`` health is left alone:
        an instance that was just rebuilt has no probe yet and excluding it
        would shrink the pool exactly when it is needed.
        """
        item = view.get(name)
        if item is None:
            return ""
        if item.health == "unhealthy":
            return "is not running"
        if (
            item.cf_403_rate is not None
            and item.cf_checks >= CF_403_MIN_CHECKS
            and item.cf_403_rate >= CF_403_THRESHOLD
        ):
            return f"is answering Cloudflare 403 on {item.cf_403_rate:.0f}% of checks"
        return ""

    def _is_pinned(self, view: dict[str, warpgate_pool.InstanceHealth], name: str) -> bool:
        item = view.get(name)
        return bool(item and item.dedicated)

    async def gate_stats(self, ttl: float = 30.0) -> warpgate_pool.PoolStats | None:
        """Cached WarpGate capacity read; never raises."""
        if not self.pool:
            return None
        cached = self._stats
        if cached and cached[0] + ttl > time.time():
            return cached[1]
        try:
            stats = await asyncio.to_thread(self.pool.stats)
        except Exception as exc:
            stats = warpgate_pool.PoolStats(reachable=False, detail=str(exc))
        self._stats = (time.time(), stats)
        return stats

    def capacity(self, gate: warpgate_pool.PoolStats | None = None) -> int | None:
        total = self.cfg.capacity if self.cfg.uses_prefix else 0
        if self.cfg.uses_warpgate:
            if gate is None or not gate.instances:
                # An unreachable WarpGate is unknown capacity, not zero.
                return total or None
            total += gate.instances
        return total

    # -- assignment --------------------------------------------------------- #

    async def ensure(self, client: sqlite3.Row) -> Route:
        """Return the client's route, acquiring one on first use."""
        block = str(client["block"] or "")
        lane = str(client["lane"] or "prefix")
        if block and lane == "prefix":
            return Route("prefix", block, source_for(self.cfg, block))

        instance = _instance_from_json(str(client["upstream"] or ""))
        if block and lane == "warpgate" and instance is not None:
            # The lease is still the client's; no control-plane round trip on
            # the request path.
            return Route("warpgate", block, instance.endpoint, instance)
        return await self.assign(str(client["id"]))

    async def assign(self, client_id: str) -> Route:
        if self.cfg.uses_prefix:
            block = self.store.allocate_block(self.cfg)
            if block:
                self.store.set_route(client_id, block, "prefix", "")
                return Route("prefix", block, source_for(self.cfg, block))
            if not self.cfg.uses_warpgate:
                raise NoCapacity(
                    "no free blocks left; add another prefix or relay"
                )
        return await self._assign_warpgate(client_id)

    async def _assign_warpgate(self, client_id: str) -> Route:
        if not self.pool:
            raise NoCapacity(
                "the prefix lane is exhausted and no WarpGate pool is configured"
            )
        session = self.pool.session_id_for(client_id)
        tried: set[str] = set()
        settled = 0.0
        reissues = 0
        backoff = 0.0
        view = await self.gate_health(HEALTH_TTL_SECONDS)
        detail = "no instance answered"
        for _ in range(ACQUIRE_ATTEMPTS):
            try:
                instance = await asyncio.to_thread(self.pool.acquire, session)
            except WarpGateError as exc:
                if exc.rate_limited and backoff + RATE_LIMIT_BACKOFF <= RATE_LIMIT_BUDGET:
                    # The gate limits control calls per source address, so a
                    # burst of enrolments must not turn into a burst of 429s
                    # that the clients read as "no capacity".
                    backoff += RATE_LIMIT_BACKOFF
                    await asyncio.sleep(RATE_LIMIT_BACKOFF)
                    continue
                raise NoCapacity(f"WarpGate could not hand out an instance: {exc}")
            if instance.name in tried:
                # The same name twice means the lease is sticky or the instance
                # is mid-rebuild. Wait a beat instead of spending every
                # remaining attempt inside the same millisecond.
                if settled < REBUILD_SETTLE_BUDGET:
                    await asyncio.sleep(REBUILD_SETTLE_SECONDS)
                    settled += REBUILD_SETTLE_SECONDS
                await asyncio.to_thread(self._quiet_release, session)
                continue
            tried.add(instance.name)

            why = self._may_use(view, instance.name)
            if why:
                # The gate already knows this one is down or blocked. Leave it
                # to the gate's own repair loop and ask for another exit.
                detail = f"{instance.name} {why}"
                await asyncio.to_thread(self._quiet_release, session)
                continue

            block = self.store.exit_block(instance.name, instance.endpoint)
            if not block:
                egress, block = await asyncio.to_thread(
                    warpgate_pool.probe_block, instance
                )
                if egress and block:
                    self.store.put_exit(instance.name, instance.endpoint, block)
            if not block:
                detail = f"{instance.endpoint} reported no IPv6 exit"
                await self._retire(instance, session, reissue=False)
                continue
            if not self.store.claim_block(block, client_id):
                if not self.store.block_is_spent(block):
                    detail = f"{block} is already assigned to another client"
                elif self._is_pinned(await self.gate_health(0.0), instance.name):
                    detail = f"{block} is spent and {instance.name} is pinned by the operator"
                elif reissues < REISSUE_ATTEMPTS:
                    # Nobody owns this /64 and the day's quota is gone, so the
                    # registration behind it is dead weight until tomorrow.
                    # Replace the account instead of handing it out again.
                    reissues += 1
                    detail = f"{block} is spent for today"
                    await self._retire(instance, session, reissue=True)
                    continue
                else:
                    # Re-registration already failed to move the exit; stop
                    # spending registrations on an exhausted pool.
                    detail = f"{block} is spent for today"
                await asyncio.to_thread(self._quiet_release, session)
                continue
            self.store.set_route(
                client_id, block, "warpgate", _instance_to_json(instance)
            )
            return Route("warpgate", block, instance.endpoint, instance)
        raise NoCapacity(f"no unspent exit after {ACQUIRE_ATTEMPTS} tries ({detail})")

    def _quiet_release(self, session: str) -> None:
        if not self.pool:
            return
        try:
            self.pool.release(session)
        except Exception:
            pass

    def _quiet_report(self, session: str, status: int, failure_type: str) -> None:
        if not self.pool:
            return
        try:
            self.pool.report(session, status, failure_type)
        except Exception:
            pass

    def _quiet_rotate(self, instance: Instance) -> None:
        if not self.pool:
            return
        try:
            self.pool.rotate_instance(instance)
        except Exception:
            pass

    async def _retire(
        self, instance: Instance | None, session: str, *, reissue: bool
    ) -> None:
        """Hand an instance back, and replace it when its block is spent.

        ``reissue`` is the difference between the two failures worth telling
        WarpGate about:

        * a spent block needs a **new** registration, because Cloudflare meters
          the quota per exit block and the old account cannot move.  Only
          ``/api/pool/rotate`` does that -- it deletes the account and registers
          a fresh one.
        * a wedged tunnel needs only an engine restart on the same account, which
          ``/api/pool/report`` triggers after two consecutive failures and which
          deliberately keeps the exit address.

        The cached /64 is dropped either way: a rebuilt account answers from a
        different block, and a restarted tunnel must be probed again before the
        relay trusts its address.
        """
        if not self.pool:
            return
        if instance is not None and reissue:
            # Replacing an account is irreversible, so this check never trusts
            # the cached view: a pin added in the last half minute must still
            # stop the rotation.
            view = await self.gate_health(0.0)
            if self._is_pinned(view, instance.name):
                # An operator pinned this instance to its exit address. Its
                # account is not ours to replace, so hand the lease back and
                # let them decide when to rotate it.
                await asyncio.to_thread(self._quiet_release, session)
                return
        if instance is not None:
            if reissue:
                await asyncio.to_thread(self._quiet_rotate, instance)
            else:
                await asyncio.to_thread(self._quiet_report, session, 0, "proxy_dead")
            self.store.forget_exit(instance.name)
        await asyncio.to_thread(self._quiet_release, session)

    async def retire(self, instance: Instance | None, session: str) -> None:
        """Hand an instance back with a fresh registration.

        Used when a client leaves for good: its block is spent either way, so the
        account is only worth keeping if it is replaced.
        """
        await self._retire(instance, session, reissue=True)

    async def rotate(self, client_id: str) -> tuple[str, Route]:
        """Move a client onto a fresh block, keeping the old one if that fails."""
        row = self.store.client_by_id(client_id)
        if not row:
            raise LookupError("unknown client")
        old_block = str(row["block"] or "")
        old_lane = str(row["lane"] or "prefix")
        old_upstream = str(row["upstream"] or "")
        old_instance = _instance_from_json(old_upstream)

        # The old /64 is spent for the rest of the UTC day either way, so it is
        # burnt before the pool is touched and never offered again.
        if old_block:
            self.store.burn_block(old_block, client_id)

        retired = old_instance is not None and self.pool is not None
        if retired:
            session = old_instance.session_id or self.pool.session_id_for(client_id)
            await self._retire(old_instance, session, reissue=True)
        self.store.set_route(client_id, "", "", "")

        try:
            route = await self.assign(client_id)
        except Exception:
            # Only restore when the old instance is still untouched. Once its
            # account has been replaced its block no longer exists, and pointing
            # the client back at it would be a route to nowhere.
            if old_block and not retired:
                self.store.conn.execute(
                    "UPDATE blocks SET burnt_until=0 WHERE block=?", (old_block,)
                )
                self.store.conn.commit()
                self.store.claim_block(old_block, client_id)
                self.store.set_route(client_id, old_block, old_lane, old_upstream)
            raise
        return old_block, route

    # -- dialing ------------------------------------------------------------ #

    async def dial(self, route: Route, host: str, port: int):
        if route.lane == "prefix":
            return await open_bound(self.cfg, host, port, route.block)
        return await self._dial_warpgate(route, host, port)

    async def _dial_warpgate(self, route: Route, host: str, port: int):
        instance = route.instance
        if instance is None:
            raise ConnectionError("route has no WarpGate instance")
        infos = await asyncio.to_thread(resolve_aaaa, host, port)
        targets = [info[4][0] for info in infos] or [host]
        last: Exception | None = None
        for target in targets:
            try:
                sock = await warpgate_pool.open_socks5(
                    target,
                    port,
                    instance.host,
                    instance.port,
                    username=instance.username,
                    password=instance.password,
                    timeout=self.cfg.connect_timeout,
                )
                return await asyncio.open_connection(sock=sock)
            except Exception as exc:
                last = exc
                continue
        raise ConnectionError(f"{host}:{port} unreachable through {instance.endpoint}: {last}")

    async def verify(self, block: str, route: Route | None = None) -> tuple[str, bool]:
        """Ask the outside world which address this block really exits from."""
        if route is not None and route.lane == "warpgate" and route.instance:
            egress, _ = await asyncio.to_thread(
                warpgate_pool.probe_block, route.instance
            )
            return egress, bool(egress) and egress_in_block(egress, block)
        egress = await asyncio.to_thread(verify_block_sync, self.cfg, block)
        return egress, egress_in_block(egress, block)


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #


class Relay:
    def __init__(
        self,
        cfg: Config,
        store: Store,
        pool: WarpGatePool | None = None,
    ) -> None:
        self.cfg = cfg
        self.store = store
        self.router = Router(cfg, store, pool)
        self.semaphores: dict[str, asyncio.Semaphore] = {}

    async def stats(self) -> dict[str, Any]:
        gate = await self.router.gate_stats()
        return self.store.stats(self.cfg, gate, self.router.capacity(gate))

    def semaphore(self, client_id: str) -> asyncio.Semaphore:
        sem = self.semaphores.get(client_id)
        if sem is None:
            sem = asyncio.Semaphore(max(1, self.cfg.max_tunnels_per_client))
            self.semaphores[client_id] = sem
        return sem

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 20)
        except Exception:
            writer.close()
            return
        try:
            text = head.decode("latin-1")
            lines = text.split("\r\n")
            method, target, _version = lines[0].split(" ", 2)
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
        except Exception:
            await self._reply(writer, 400, {"ok": False, "error": "bad request"})
            return

        if method.upper() == "CONNECT":
            await self._connect(reader, writer, target, headers)
            return
        await self._api(reader, writer, method.upper(), target, headers)

    async def _connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
        headers: dict[str, str],
    ) -> None:
        token = parse_basic(headers.get("proxy-authorization", "")) or parse_bearer(
            headers.get("proxy-authorization", "")
        )
        client = self.store.client_by_token(token) if token else None
        if not client:
            await self._reply(writer, 407, {"ok": False, "error": "proxy authentication required"})
            return
        host, port = self._split_target(target)
        if not host or not host_allowed(host, self.cfg.allowed_hosts):
            await self._reply(writer, 403, {"ok": False, "error": "host not allowed"})
            return

        try:
            route = await self.router.ensure(client)
        except NoCapacity as exc:
            await self._reply(writer, 503, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:
            log(f"route_fail client={client['id']} err={exc}")
            await self._reply(writer, 503, {"ok": False, "error": f"routing failed: {exc}"})
            return

        sem = self.semaphore(str(client["id"]))
        if sem.locked():
            # Wait briefly instead of rejecting a burst; OpenCode opens several
            # short request tunnels per turn.
            try:
                await asyncio.wait_for(sem.acquire(), 5)
            except asyncio.TimeoutError:
                await self._reply(writer, 429, {"ok": False, "error": "too many tunnels"})
                return
        else:
            await sem.acquire()
        upstream_reader = upstream_writer = None
        try:
            upstream_reader, upstream_writer = await self.router.dial(route, host, port)
        except Exception as exc:
            log(
                f"connect_fail client={client['id']} lane={route.lane} "
                f"block={route.block} host={host} err={exc}"
            )
            await self._reply(writer, 502, {"ok": False, "error": str(exc)})
            sem.release()
            return

        try:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            try:
                await writer.drain()
            except Exception:
                pass
            self.store.touch(str(client["id"]), route.block)
            await asyncio.gather(
                self._pump(reader, upstream_writer),
                self._pump(upstream_reader, writer),
            )
        finally:
            sem.release()
            for stream in (upstream_writer, writer):
                try:
                    stream.close()
                except Exception:
                    pass

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while True:
                data = await asyncio.wait_for(reader.read(65536), self.cfg.idle_timeout)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except Exception:
                pass

    async def _api(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        headers: dict[str, str],
    ) -> None:
        path = target.split("?", 1)[0].rstrip("/") or "/"
        auth = headers.get("authorization", "")
        body = b""
        try:
            length = int(headers.get("content-length", "0") or "0")
            if not 0 <= length <= 1_048_576:
                raise ValueError("request body too large")
            if length:
                body = await asyncio.wait_for(reader.readexactly(length), 10)
        except Exception:
            body = b""
        payload: dict[str, Any] = {}
        if body:
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                payload = {}

        if path == "/healthz" and method == "GET":
            await self._reply(writer, 200, {"ok": True, "stats": await self.stats()})
            return

        if path == "/api/enroll" and method == "POST":
            if not self.cfg.enroll_secret:
                await self._reply(writer, 403, {"ok": False, "error": "enrollment is disabled"})
                return
            supplied = headers.get("x-enroll-secret", "")
            if not secrets.compare_digest(supplied, self.cfg.enroll_secret):
                await self._reply(writer, 403, {"ok": False, "error": "bad enrollment secret"})
                return
            label = str(payload.get("label", ""))[:120]
            try:
                client_id, token, block = self.store.create_client(self.cfg, label)
            except Exception as exc:
                await self._reply(writer, 503, {"ok": False, "error": str(exc)})
                return
            lane = "prefix" if block else "warpgate"
            await self._reply(
                writer,
                200,
                {
                    "ok": True,
                    "client_id": client_id,
                    "token": token,
                    "block": block,
                    "lane": lane,
                    "source": source_for(self.cfg, block) if block else "",
                    "relay": self.cfg.public_url,
                    "resets_at": utc_midnight(),
                },
            )
            return

        # Everything else needs a valid client or admin token.
        bearer = parse_bearer(auth) or headers.get("x-client-token", "")
        client = self.store.client_by_token(bearer) if bearer else None
        is_admin = bool(bearer) and bool(self.cfg.admin_token) and secrets.compare_digest(
            bearer, self.cfg.admin_token
        )

        if path == "/api/rotate" and method == "POST":
            if not client:
                await self._reply(writer, 403, {"ok": False, "error": "bad client token"})
                return
            try:
                old, route = await self.router.rotate(str(client["id"]))
            except Exception as exc:
                await self._reply(writer, 503, {"ok": False, "error": str(exc)})
                return
            egress, verified = await self.router.verify(route.block, route)
            payload = {
                "ok": True,
                "client_id": str(client["id"]),
                "old_block": old,
                "egress_ip": egress,
                "verified": verified,
                "resets_at": utc_midnight(),
            }
            payload.update(route.as_dict())
            await self._reply(writer, 200, payload)
            return

        if path == "/api/state" and method == "GET":
            if client:
                try:
                    route = await self.router.ensure(client)
                except NoCapacity as exc:
                    await self._reply(writer, 503, {"ok": False, "error": str(exc)})
                    return
                except Exception as exc:
                    await self._reply(
                        writer, 503, {"ok": False, "error": f"routing failed: {exc}"}
                    )
                    return
                payload = {
                    "ok": True,
                    "client_id": str(client["id"]),
                    "requests": client["requests"],
                    "resets_at": utc_midnight(),
                    "stats": await self.stats(),
                }
                payload.update(route.as_dict())
                await self._reply(writer, 200, payload)
                return
            if is_admin:
                await self._reply(writer, 200, {"ok": True, "stats": await self.stats()})
                return
            await self._reply(writer, 403, {"ok": False, "error": "bad token"})
            return

        if path == "/api/clients" and method == "POST":
            if not is_admin:
                await self._reply(writer, 403, {"ok": False, "error": "admin token required"})
                return
            label = str(payload.get("label", ""))[:120]
            try:
                client_id, token, block = self.store.create_client(self.cfg, label)
            except Exception as exc:
                await self._reply(writer, 503, {"ok": False, "error": str(exc)})
                return
            await self._reply(
                writer,
                200,
                {
                    "ok": True,
                    "client_id": client_id,
                    "token": token,
                    "block": block,
                    "lane": "prefix" if block else "warpgate",
                },
            )
            return

        if path == "/api/clients" and method == "GET":
            if not is_admin:
                await self._reply(writer, 403, {"ok": False, "error": "admin token required"})
                return
            rows = self.store.conn.execute(
                "SELECT id, label, block, lane, created_at, last_seen, requests, enabled "
                "FROM clients ORDER BY created_at"
            ).fetchall()
            await self._reply(
                writer,
                200,
                {"ok": True, "clients": [dict(row) for row in rows]},
            )
            return

        await self._reply(writer, 404, {"ok": False, "error": "not found"})

    @staticmethod
    def _split_target(target: str) -> tuple[str, int]:
        text = target.strip()
        if text.startswith("["):
            end = text.find("]")
            if end == -1:
                return "", 0
            host = text[1:end]
            rest = text[end + 1 :].lstrip(":")
            port = int(rest) if rest.isdigit() else 443
            return host, port
        host, _, raw_port = text.rpartition(":")
        if not host or not raw_port.isdigit():
            return text, 443
        return host, int(raw_port)

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: int, payload: dict[str, Any]) -> None:
        reason = {
            200: "OK",
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            407: "Proxy Authentication Required",
            429: "Too Many Requests",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }.get(status, "Error")
        body = json.dumps(payload).encode("utf-8")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            writer.write(head + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_ssl(cfg: Config) -> ssl.SSLContext | None:
    if not cfg.tls_cert or not cfg.tls_key:
        return None
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


async def serve(cfg: Config, store: Store, pool: WarpGatePool | None = None) -> None:
    relay = Relay(cfg, store, pool)
    ssl_context = build_ssl(cfg)
    server = await asyncio.start_server(
        relay.handle,
        cfg.listen,
        cfg.port,
        ssl=ssl_context,
        backlog=256,
        limit=65536,
    )
    scheme = "https" if ssl_context else "http"
    lanes = cfg.upstream_mode
    detail = f"prefix_blocks={cfg.capacity}" if cfg.uses_prefix else ""
    if cfg.uses_warpgate:
        detail = (detail + " " if detail else "") + f"warpgate={cfg.warpgate_url}"
    log(
        f"blockrelay listening on {scheme}://{cfg.listen}:{cfg.port} "
        f"lane={lanes} {detail} bind_suffix={cfg.bind_suffix}"
    )
    stop = asyncio.Event()

    def _stop(*_: Any) -> None:
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    async with server:
        await stop.wait()
    log("blockrelay stopped")


def cmd_serve(args: argparse.Namespace) -> int:
    cfg = Config.load(Path(args.config))
    store = Store(cfg.database)
    try:
        asyncio.run(serve(cfg, store, cfg.pool()))
    except KeyboardInterrupt:
        pass
    return 0


def _pool_or_none(cfg: Config) -> WarpGatePool | None:
    try:
        return cfg.pool()
    except WarpGateError as exc:
        print(f"warpgate: unavailable ({exc})")
        return None


def cmd_client_new(args: argparse.Namespace) -> int:
    cfg = Config.load(Path(args.config))
    store = Store(cfg.database)
    client_id, token, block = store.create_client(cfg, args.label)
    relay_url = cfg.public_url or f"{cfg.listen}:{cfg.port}"
    lane = "prefix" if block else "warpgate"
    print(f"client_id: {client_id}")
    print(f"lane:      {lane}")
    print(f"block:     {block or '(assigned on first request)'}")
    if block:
        print(f"source:    {source_for(cfg, block)}")
    print(f"proxy:     relay://block:{token}@{relay_url}")
    return 0


def cmd_client_list(args: argparse.Namespace) -> int:
    cfg = Config.load(Path(args.config))
    store = Store(cfg.database)
    rows = store.conn.execute(
        "SELECT id, label, block, lane, created_at, last_seen, requests, enabled "
        "FROM clients ORDER BY created_at"
    ).fetchall()
    for row in rows:
        print(
            f"{row['id']}  {row['label']:<24} {str(row['lane']):<9} "
            f"{row['block'] or '-':<44} requests={row['requests']:<8} "
            f"last={row['last_seen']} enabled={row['enabled']}"
        )
    pool = _pool_or_none(cfg)
    gate = pool.stats() if pool else None
    print(f"stats: {json.dumps(store.stats(cfg, gate))}")
    return 0


def cmd_client_rotate(args: argparse.Namespace) -> int:
    cfg = Config.load(Path(args.config))
    store = Store(cfg.database)
    router = Router(cfg, store, cfg.pool())
    old, route = asyncio.run(router.rotate(args.id))
    print(f"{old or '(none)'} -> {route.block} ({route.label})")
    return 0


def cmd_client_revoke(args: argparse.Namespace) -> int:
    cfg = Config.load(Path(args.config))
    store = Store(cfg.database)
    row = store.client_by_id(args.id)
    if not row:
        print("unknown client")
        return 1
    store.conn.execute("UPDATE clients SET enabled=0 WHERE id=?", (args.id,))
    if row["block"]:
        store.burn_block(str(row["block"]), args.id)
    store.conn.commit()
    instance = _instance_from_json(str(row["upstream"] or ""))
    pool = _pool_or_none(cfg)
    if instance is not None and pool is not None:
        # The block this client used is spent for the rest of the day, so the
        # account behind it is only worth having if it is re-registered.
        router = Router(cfg, store, pool)
        session = instance.session_id or pool.session_id_for(args.id)
        asyncio.run(router.retire(instance, session))
    print(f"revoked {args.id}")
    return 0


def cmd_pool(args: argparse.Namespace) -> int:
    cfg = Config.load(Path(args.config))
    pool = _pool_or_none(cfg)
    if pool is None:
        print("the WarpGate lane is not configured")
        return 1
    stats = pool.stats()
    print(
        f"{cfg.warpgate_url}  reachable={stats.reachable}  "
        f"instances={stats.instances}  available={stats.available}  "
        f"in_use={stats.in_use}"
    )
    if stats.detail:
        print(f"detail: {stats.detail}")
    if args.probe <= 0:
        return 0 if stats.reachable else 1
    ok = stats.reachable
    seen: dict[str, str] = {}
    try:
        samples = pool.proxies(max(1, args.probe))[: args.probe]
    except WarpGateError as exc:
        print(f"extract failed: {exc}")
        return 1
    for instance in samples:
        egress, block = warpgate_pool.probe_block(instance)
        clone = seen.get(block or egress or instance.endpoint)
        state = "OK" if block and clone is None else ("DUP" if block else "FAIL")
        print(
            f"  {instance.endpoint:<24} egress={egress or '-':<40} "
            f"block={block or '-':<24} {state}"
        )
        seen[block or egress or instance.endpoint] = instance.endpoint
        ok = ok and bool(block) and clone is None
    return 0 if ok else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = Config.load(Path(args.config))
    store = Store(cfg.database)
    ok = True
    print(f"lane: {cfg.upstream_mode}")

    pool = _pool_or_none(cfg)
    gate = pool.stats() if pool else None
    if gate is not None:
        print(
            f"warpgate: {cfg.warpgate_url} reachable={gate.reachable} "
            f"instances={gate.instances} available={gate.available}"
            + (f" ({gate.detail})" if gate.detail else "")
        )
        ok = ok and gate.reachable
        if gate.reachable and args.samples > 0:
            try:
                samples = pool.proxies(args.samples)[: args.samples]
            except WarpGateError as exc:
                print(f"  extract failed: {exc}")
                samples = []
                ok = False
            seen: set[str] = set()
            for instance in samples:
                egress, block = warpgate_pool.probe_block(instance)
                fresh = bool(block) and block not in seen
                if block:
                    seen.add(block)
                print(
                    f"  {instance.endpoint:<24} egress={egress or '-':<40} "
                    f"block={block or '-':<24} "
                    f"{'OK' if fresh else 'FAIL'}"
                )
                ok = ok and fresh

    if cfg.uses_prefix:
        print(f"prefix lane: {cfg.capacity} blocks across {len(cfg.prefixes)} prefix(es)")
        for raw in cfg.prefixes:
            net = ipaddress.IPv6Network(raw, strict=False)
            block = str(ipaddress.IPv6Network((net.network_address, 64), strict=False))
            egress = verify_block_sync(cfg, block)
            inside = egress_in_block(egress, block)
            print(
                f"{block}  source={source_for(cfg, block)}  egress={egress or '-'}  "
                f"{'OK' if inside else 'FAIL'}"
            )
            ok = ok and inside

    stats = store.stats(cfg, gate)
    print(
        f"clients={stats['clients']} prefix={stats['clients_prefix']} "
        f"warpgate={stats['clients_warpgate']} burnt={stats['burnt_blocks']} "
        f"capacity={stats['capacity'] or '?'} resets_at={stats['resets_at']}"
    )
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.json")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("serve", help="run the relay")

    new = sub.add_parser("client-new", help="mint a client token")
    new.add_argument("--label", default="")

    sub.add_parser("client-list", help="list clients and capacity")

    rotate = sub.add_parser("client-rotate", help="move a client to a fresh block")
    rotate.add_argument("--id", required=True)

    revoke = sub.add_parser("client-revoke", help="disable a client")
    revoke.add_argument("--id", required=True)

    pool = sub.add_parser("pool", help="inspect the WarpGate lane")
    pool.add_argument(
        "--probe", type=int, default=3, help="instances to dial end to end (0 skips)"
    )

    doctor = sub.add_parser("doctor", help="verify every configured lane dials outbound")
    doctor.add_argument(
        "--samples", type=int, default=2, help="WarpGate instances to dial (0 skips)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "serve": cmd_serve,
        "client-new": cmd_client_new,
        "client-list": cmd_client_list,
        "client-rotate": cmd_client_rotate,
        "client-revoke": cmd_client_revoke,
        "pool": cmd_pool,
        "doctor": cmd_doctor,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
