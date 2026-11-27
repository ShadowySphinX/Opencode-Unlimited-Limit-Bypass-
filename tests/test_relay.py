"""Tests for the block relay: allocation, auth, rotation, and client wiring."""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "relay"))

import blockrelay
import ouc_common
import proxy_chain
import warpgate_pool


class RelayConfigTests(unittest.TestCase):
    def test_slash_48_expands_to_65536_blocks(self) -> None:
        cfg = blockrelay.Config(prefixes=["2001:db8:1::/48"], admin_token="x")
        self.assertEqual(cfg.capacity, 1 << 16)
        self.assertEqual(len(list(cfg.blocks)), 1)
        self.assertEqual(str(cfg.blocks[0]), "2001:db8:1::/48")

    def test_address_prefix_is_clamped_to_a_block(self) -> None:
        cfg = blockrelay.Config(prefixes=["2001:db8::1/128"], admin_token="x")
        self.assertEqual(str(cfg.blocks[0]), "2001:db8::/64")
        self.assertEqual(cfg.capacity, 1)

    def test_source_address_stays_inside_the_block(self) -> None:
        cfg = blockrelay.Config(
            prefixes=["2001:db8:aa::/48"], admin_token="x", bind_suffix="::1"
        )
        block = "2001:db8:aa:1234::/64"
        self.assertEqual(
            blockrelay.source_for(cfg, block), "2001:db8:aa:1234::1"
        )

    def test_non_ipv6_prefix_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            blockrelay.Config(prefixes=["10.0.0.0/8"], admin_token="x").blocks


class RelayHelperTests(unittest.TestCase):
    def test_wildcard_allowlist_allows_everything(self) -> None:
        self.assertTrue(blockrelay.host_allowed("anything.example", ["*"]))

    def test_allowlist_matches_exact_and_subdomain(self) -> None:
        allowed = ["opencode.ai", "*.opencode.ai"]
        self.assertTrue(blockrelay.host_allowed("opencode.ai", allowed))
        self.assertTrue(blockrelay.host_allowed("api.opencode.ai", allowed))
        self.assertFalse(blockrelay.host_allowed("evilopencode.ai", allowed))
        self.assertFalse(blockrelay.host_allowed("example.com", allowed))

    def test_egress_check_rejects_ipv4_and_foreign_blocks(self) -> None:
        self.assertTrue(blockrelay.egress_in_block("2001:db8::5", "2001:db8::/64"))
        self.assertFalse(blockrelay.egress_in_block("203.0.113.9", "2001:db8::/64"))
        self.assertFalse(blockrelay.egress_in_block("2001:db9::5", "2001:db8::/64"))
        self.assertFalse(blockrelay.egress_in_block("", "2001:db8::/64"))

    def test_basic_auth_parses_the_token_half(self) -> None:
        import base64

        header = base64.b64encode(b"block:s3cret").decode()
        self.assertEqual(blockrelay.parse_basic(header), "s3cret")
        self.assertEqual(blockrelay.parse_basic("not-base64!"), "")


class RelayStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = blockrelay.Config(
            prefixes=["2001:db8:1::/48"],
            admin_token="admin",
            database=str(Path(self.tmp.name) / "relay.db"),
        )
        self.store = blockrelay.Store(self.cfg.database)
        self.addCleanup(self.store.conn.close)

    def test_client_gets_a_sticky_block_inside_the_prefix(self) -> None:
        client_id, token, block = self.store.create_client(self.cfg, "alice")
        net = ipaddress.IPv6Network(block)
        self.assertTrue(net.subnet_of(ipaddress.IPv6Network("2001:db8:1::/48")))
        self.assertEqual(net.prefixlen, 64)
        row = self.store.client_by_token(token)
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], client_id)
        self.assertEqual(row["block"], block)

    def test_two_clients_never_share_a_block(self) -> None:
        _, _, first = self.store.create_client(self.cfg, "a")
        _, _, second = self.store.create_client(self.cfg, "b")
        self.assertNotEqual(first, second)

    def test_rotation_burns_the_old_block_until_midnight(self) -> None:
        client_id, token, old = self.store.create_client(self.cfg, "a")
        old_block, new_block = self.store.rotate_client(self.cfg, client_id)
        self.assertEqual(old_block, old)
        self.assertNotEqual(new_block, old)
        row = self.store.client_by_token(token)
        self.assertEqual(row["block"], new_block)
        burnt = self.store.conn.execute(
            "SELECT client_id, burnt_until FROM blocks WHERE block=?", (old,)
        ).fetchone()
        self.assertIsNone(burnt["client_id"])
        self.assertGreater(burnt["burnt_until"], 0)

        # A burnt block is never handed out again before the reset.
        _, _, third = self.store.create_client(self.cfg, "b")
        self.assertNotEqual(third, old)

    def test_rotation_moves_a_warpgate_client_back_to_the_prefix_lane(self) -> None:
        client_id, _, _ = self.store.create_client(self.cfg, "a")
        self.store.set_route(
            client_id, "", "warpgate", '{"name":"warp-1","host":"h","port":1}'
        )

        old, new = self.store.rotate_client(self.cfg, client_id)

        self.assertEqual(old, "")
        row = self.store.client_by_id(client_id)
        self.assertEqual(row["block"], new)
        self.assertEqual(row["lane"], "prefix")
        self.assertEqual(row["upstream"], "")

    def test_exhausted_capacity_refuses_to_rotate(self) -> None:
        cfg = blockrelay.Config(
            prefixes=["2001:db8:9::/64"],
            admin_token="admin",
            database=str(Path(self.tmp.name) / "one.db"),
        )
        store = blockrelay.Store(cfg.database)
        self.addCleanup(store.conn.close)
        client_id, _, block = store.create_client(cfg, "only")
        with self.assertRaises(RuntimeError):
            store.rotate_client(cfg, client_id)
        # The client keeps its original route instead of going dark.
        self.assertEqual(store.client_by_id(client_id)["block"], block)

    def test_revoked_client_cannot_authenticate(self) -> None:
        client_id, token, block = self.store.create_client(self.cfg, "gone")
        self.store.conn.execute("UPDATE clients SET enabled=0 WHERE id=?", (client_id,))
        self.store.conn.commit()
        self.assertIsNone(self.store.client_by_token(token))


class _RelayHarness:
    """Runs the real Relay handler on loopback for HTTP-level tests."""

    def __init__(self, cfg: blockrelay.Config, store: blockrelay.Store) -> None:
        self.cfg = cfg
        self.store = store
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.port = 0
        self.closed = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready.wait(10):
            raise RuntimeError("relay harness did not start")

    def _run(self) -> None:
        loop = self.loop
        asyncio.set_event_loop(loop)
        relay = blockrelay.Relay(self.cfg, self.store)
        server = loop.run_until_complete(
            asyncio.start_server(relay.handle, "127.0.0.1", 0, limit=65536)
        )
        self.port = server.sockets[0].getsockname()[1]
        self.ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                server.close()
                loop.run_until_complete(server.wait_closed())
            except Exception:
                pass
            loop.close()

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: dict | None = None,
    ) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        payload = json.dumps(body).encode() if body is not None else None
        head = {"Content-Type": "application/json"} if payload else {}
        head.update(headers or {})
        try:
            conn.request(method, path, body=payload, headers=head)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, json.loads(raw.decode() or "{}")
        finally:
            conn.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:
            pass
        self.thread.join(5)


class RelayHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = blockrelay.Config(
            listen="127.0.0.1",
            port=0,
            prefixes=["2001:db8:1::/48"],
            admin_token="admin-token",
            database=str(Path(self.tmp.name) / "relay.db"),
            allowed_hosts=["*.opencode.ai"],
        )
        self.store = blockrelay.Store(self.cfg.database)
        self.addCleanup(self.store.conn.close)
        self.harness = _RelayHarness(self.cfg, self.store)
        self.addCleanup(self.harness.close)
        self.client_id, self.token, self.block = self.store.create_client(
            self.cfg, "tester"
        )

    def test_health_reports_capacity(self) -> None:
        status, data = self.harness.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["stats"]["capacity"], 1 << 16)
        self.assertEqual(data["stats"]["clients"], 1)

    def test_connect_without_a_token_is_refused(self) -> None:
        status, _ = self.harness.request("CONNECT", "opencode.ai:443")
        self.assertEqual(status, 407)

    def test_connect_with_a_token_but_disallowed_host_is_refused(self) -> None:
        import base64

        auth = base64.b64encode(f"block:{self.token}".encode()).decode()
        status, _ = self.harness.request(
            "CONNECT", "example.com:443", {"Proxy-Authorization": f"Basic {auth}"}
        )
        self.assertEqual(status, 403)

    def test_rotation_moves_the_client_to_a_verified_block(self) -> None:
        with mock.patch.object(
            blockrelay,
            "verify_block_sync",
            side_effect=lambda cfg, block: str(
                ipaddress.IPv6Network(block).network_address + 2
            ),
        ):
            status, data = self.harness.request(
                "POST",
                "/api/rotate",
                {"Authorization": f"Bearer {self.token}"},
            )
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertTrue(data["verified"])
        self.assertNotEqual(data["block"], self.block)
        self.assertIn(
            ipaddress.IPv6Address(data["egress_ip"]),
            ipaddress.IPv6Network(data["block"]),
        )

    def test_rotation_without_a_token_is_refused(self) -> None:
        status, _ = self.harness.request("POST", "/api/rotate")
        self.assertEqual(status, 403)

    def test_state_reports_the_clients_block(self) -> None:
        status, data = self.harness.request(
            "GET", "/api/state", {"Authorization": f"Bearer {self.token}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["block"], self.block)
        self.assertTrue(data["source"].startswith(self.block.split("/")[0]))


class RelayClientParsingTests(unittest.TestCase):
    def test_relay_spec_carries_tls_and_the_token(self) -> None:
        spec = proxy_chain._parse_proxy_entry(
            "relay://block:abc123@relay.example.com:4443"
        )
        self.assertEqual(spec["type"], "relay")
        self.assertTrue(spec["tls"])
        self.assertEqual(spec["username"], "block")
        self.assertEqual(spec["password"], "abc123")
        self.assertEqual(spec["host"], "relay.example.com")
        self.assertEqual(spec["port"], 4443)

    def test_plain_relay_scheme_skips_tls(self) -> None:
        spec = proxy_chain._parse_proxy_entry("relayplain://block:t@10.0.0.5:4443")
        self.assertEqual(spec["type"], "relay")
        self.assertFalse(spec["tls"])

    def test_legacy_https_proxy_still_means_plaintext_connect(self) -> None:
        spec = proxy_chain._parse_proxy_entry("https://10.0.0.5:8080")
        self.assertEqual(spec["type"], "http")
        self.assertFalse(spec["tls"])

    def test_socks5_default_is_untouched(self) -> None:
        spec = proxy_chain._parse_proxy_entry("127.0.0.1:1080")
        self.assertEqual(spec["type"], "socks5")
        self.assertFalse(spec["tls"])

    def test_proxy_url_uses_https_only_for_tls_relays(self) -> None:
        url = ouc_common._proxy_url("relay.example.com", 4443, "relay", "block", "t", True)
        self.assertEqual(url, "https://block:t@relay.example.com:4443")
        url = ouc_common._proxy_url("10.0.0.5", 8080, "http", "", "", False)
        self.assertEqual(url, "http://10.0.0.5:8080")


class RelayRotationWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config_file = self.root / "egress_mode.json"
        self.index_file = self.root / "custom_proxy_index.txt"
        self.index_file.write_text("0", encoding="utf-8")
        self.config_file.write_text(
            json.dumps(
                {
                    "mode": "custom",
                    "warp_scope": "tun",
                    "custom_type": "socks5",
                    "custom_proxy": "relay://block:tok@relay.example.com:4443",
                }
            ),
            encoding="utf-8",
        )
        self.patches = [
            mock.patch.object(proxy_chain, "EGRESS_CONFIG_FILE", self.config_file),
            mock.patch.object(proxy_chain, "PROXY_INDEX_FILE", self.index_file),
            mock.patch.object(proxy_chain, "LANE_DIR", self.root),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_single_relay_node_is_still_rotatable(self) -> None:
        with mock.patch.object(
            proxy_chain,
            "relay_api_request",
            return_value={
                "ok": True,
                "block": "2001:db8:1:2::/64",
                "source": "2001:db8:1:2::1",
                "egress_ip": "2001:db8:1:2::1",
                "verified": True,
            },
        ), mock.patch.object(
            ouc_common, "probe_proxy_egress", return_value="2001:db8:1:2::1"
        ):
            ok, msg = proxy_chain.rotate_custom_proxy()
        self.assertTrue(ok)
        self.assertIn("2001:db8:1:2::/64", msg)
        self.assertIn("2001:db8:1:2::1", msg)

    def test_relay_error_is_reported_not_hidden(self) -> None:
        with mock.patch.object(
            proxy_chain,
            "relay_api_request",
            return_value={"ok": False, "error": "no free blocks left"},
        ):
            ok, msg = proxy_chain.rotate_custom_proxy()
        self.assertFalse(ok)
        self.assertIn("no free blocks left", msg)

    def test_unverified_rotation_is_not_reported_as_success(self) -> None:
        with mock.patch.object(
            proxy_chain,
            "relay_api_request",
            return_value={
                "ok": True,
                "block": "2001:db8:1:9::/64",
                "egress_ip": "2001:db8:ffff::1",
                "verified": False,
            },
        ):
            ok, msg = proxy_chain.rotate_custom_proxy()
        self.assertFalse(ok)
        self.assertIn("outside that block", msg)

    def test_a_local_exit_outside_the_reported_block_is_not_a_rotation(self) -> None:
        with mock.patch.object(
            proxy_chain,
            "relay_api_request",
            return_value={
                "ok": True,
                "block": "2001:db8:1:9::/64",
                "egress_ip": "2001:db8:1:9::1",
                "verified": True,
            },
        ), mock.patch.object(
            ouc_common, "probe_proxy_egress", return_value="2001:db8:1:2::1"
        ):
            ok, msg = proxy_chain.rotate_custom_proxy()
        self.assertFalse(ok)
        self.assertIn("did not change the route", msg)

    def test_relay_side_probe_covers_a_cold_local_tunnel(self) -> None:
        with mock.patch.object(
            proxy_chain,
            "relay_api_request",
            return_value={
                "ok": True,
                "block": "2001:db8:1:3::/64",
                "egress_ip": "2001:db8:1:3::1",
                "verified": True,
            },
        ), mock.patch.object(ouc_common, "probe_proxy_egress", return_value=""):
            ok, msg = proxy_chain.rotate_custom_proxy()
        self.assertTrue(ok)
        self.assertIn("2001:db8:1:3::1", msg)

    def test_relay_mode_refuses_silent_warp_fallback(self) -> None:
        self.assertTrue(proxy_chain.is_relay_mode())

    def test_plain_proxy_pool_is_not_relay_mode(self) -> None:
        self.config_file.write_text(
            json.dumps(
                {
                    "mode": "custom",
                    "warp_scope": "tun",
                    "custom_type": "socks5",
                    "custom_proxy": "127.0.0.1:1080",
                }
            ),
            encoding="utf-8",
        )
        self.assertFalse(proxy_chain.is_relay_mode())


class WarpGateParsingTests(unittest.TestCase):
    def test_control_plane_defaults_to_warpgates_documented_port(self) -> None:
        self.assertEqual(warpgate_pool.WarpGatePool("http://10.0.0.5").port, 4433)

    def test_acquire_requests_both_sticky_parameter_names(self) -> None:
        pool = warpgate_pool.WarpGatePool(
            "http://10.0.0.5:4433", sticky_minutes=1440
        )
        with mock.patch.object(
            pool,
            "request",
            return_value={"proxy": "socks5://10.0.0.5:10011", "name": "warp-1"},
        ) as request:
            pool.acquire("s-1")

        _method, _path = request.call_args.args[:2]
        query = request.call_args.kwargs["query"]
        self.assertEqual(query["session_id"], "s-1")
        self.assertEqual(query["time"], "1440")
        self.assertEqual(query["minutes"], "1440")

    def test_acquire_reads_the_ready_to_use_proxy_auth_url(self) -> None:
        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433")
        with mock.patch.object(
            pool,
            "request",
            return_value={
                "proxy_auth": "socks5://u%40x:p%3Aq@10.0.0.5:10011",
                "name": "warp-1",
            },
        ):
            instance = pool.acquire("s-1")

        self.assertEqual(instance.host, "10.0.0.5")
        self.assertEqual(instance.port, 10011)
        self.assertEqual(instance.username, "u@x")
        self.assertEqual(instance.password, "p:q")

    def test_report_uses_the_result_field_warpgate_meters(self) -> None:
        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433")
        with mock.patch.object(pool, "request", return_value={}) as request:
            self.assertTrue(pool.report("s-1", 403, "quota"))

        payload = request.call_args.kwargs["payload"]
        self.assertEqual(payload["result"], 403)
        self.assertEqual(payload["failure_type"], "quota")
        self.assertEqual(payload["status"], 403)

    def test_report_treats_a_zero_status_as_a_dead_tunnel(self) -> None:
        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433")
        with mock.patch.object(pool, "request", return_value={}) as request:
            pool.report("s-1", 0, "")

        payload = request.call_args.kwargs["payload"]
        self.assertEqual(payload["failure_type"], "proxy_dead")
        self.assertNotIn("result", payload)

    def test_rotate_names_the_instance_so_warpgate_can_replace_it(self) -> None:
        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433")
        instance = warpgate_pool.Instance(
            name="warp-7", host="10.0.0.5", port=10017
        )
        with mock.patch.object(pool, "request", return_value={}) as request:
            self.assertTrue(pool.rotate_instance(instance))

        method, path = request.call_args.args[:2]
        payload = request.call_args.kwargs["payload"]
        self.assertEqual((method, path), ("POST", "/api/pool/rotate"))
        self.assertEqual(payload["name"], "warp-7")
        self.assertEqual(payload["index"], 7)
        self.assertGreaterEqual(request.call_args.kwargs["timeout"], 60)

    def test_index_is_only_read_from_warpgates_own_naming(self) -> None:
        self.assertEqual(warpgate_pool.index_from_name("warp-12"), 12)
        self.assertIsNone(warpgate_pool.index_from_name("warp-12a"))
        self.assertIsNone(warpgate_pool.index_from_name("10.0.0.5:10011"))

    def test_proxy_url_is_split_into_host_and_port(self) -> None:
        host, port = warpgate_pool._split_proxy_url(
            "socks5://45.205.27.41:10011", "10.0.0.5"
        )
        self.assertEqual((host, port), ("45.205.27.41", 10011))

    def test_bare_address_is_accepted(self) -> None:
        self.assertEqual(
            warpgate_pool._split_proxy_url("10.0.0.5:11010", "x"), ("10.0.0.5", 11010)
        )

    def test_unparsable_address_is_rejected(self) -> None:
        with self.assertRaises(warpgate_pool.WarpGateError):
            warpgate_pool._split_proxy_url("nonsense", "x")

    def test_block_is_the_64_the_limiter_counts(self) -> None:
        self.assertEqual(
            warpgate_pool.block_of("2a09:bac1:1234:5678::1"),
            "2a09:bac1:1234:5678::/64",
        )
        self.assertEqual(warpgate_pool.block_of("45.205.27.41"), "")
        self.assertEqual(warpgate_pool.block_of(""), "")

    def test_instance_url_carries_credentials(self) -> None:
        instance = warpgate_pool.Instance(
            name="warp-1", host="10.0.0.5", port=10011, username="u", password="p"
        )
        self.assertEqual(instance.proxy_url, "socks5h://u:p@10.0.0.5:10011")

    def test_loopback_from_warpgate_is_rewritten_to_the_proxy_host(self) -> None:
        pool = warpgate_pool.WarpGatePool(
            "http://10.0.0.5:4433", proxy_host="10.0.0.5"
        )
        with mock.patch.object(
            pool,
            "request",
            return_value={"proxy": "socks5://127.0.0.1:10011", "name": "warp-1"},
        ):
            instance = pool.acquire("s-1")
        self.assertEqual(instance.host, "10.0.0.5")
        self.assertEqual(instance.port, 10011)

    def test_control_plane_error_is_typed(self) -> None:
        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433")
        response = mock.Mock()
        response.status = 429
        response.read.return_value = json.dumps(
            {"code": "A0002", "msg": "rate limited"}
        ).encode()
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(pool, "_connection", return_value=connection):
            with self.assertRaises(warpgate_pool.WarpGateError) as caught:
                pool.acquire("s-1")
        self.assertTrue(caught.exception.rate_limited)

    def test_stats_reads_the_rust_control_plane_vocabulary(self) -> None:
        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433")
        with mock.patch.object(
            pool,
            "request",
            return_value={
                "total_instances": 480,
                "running_containers": 470,
                "available": 461,
                "in_use": 9,
                "sticky_sessions": 9,
            },
        ):
            stats = pool.stats()

        self.assertTrue(stats.reachable)
        self.assertEqual(stats.instances, 480)
        self.assertEqual(stats.available, 461)
        self.assertEqual(stats.in_use, 9)
        self.assertEqual(stats.sessions, 9)

    def test_stats_falls_back_to_a_bare_instance_array(self) -> None:
        # /api/containers answers with the array itself on the Rust build; an
        # object-only reader used to raise AttributeError here and blind the
        # capacity read on a live host.
        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433")

        def fake_request(method, path, **kwargs):
            if path == "/api/stats":
                return {"running_containers": 2}
            return [
                {"name": "warp-1", "health": "healthy"},
                {"name": "warp-2", "health": "unhealthy"},
            ]

        with mock.patch.object(pool, "request", side_effect=fake_request):
            stats = pool.stats()

        self.assertEqual(stats.instances, 2)
        self.assertEqual(stats.available, 1)

    def test_stats_never_raises_on_a_dead_control_plane(self) -> None:
        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433")
        with mock.patch.object(
            pool,
            "request",
            side_effect=warpgate_pool.WarpGateError("down"),
        ):
            stats = pool.stats()
        self.assertFalse(stats.reachable)
        self.assertIn("down", stats.detail)


class _FakeGate:
    """Stands in for WarpGate without a network or a WARP registration."""

    def __init__(self, ports: list[int]) -> None:
        self.ports = ports
        self.index = 0
        self.acquired: list[str] = []
        self.released: list[str] = []
        self.reports: list[tuple[str, int, str]] = []
        self.rotated: list[str] = []
        self.view: list[warpgate_pool.InstanceHealth] = []

    def instances(self, timeout: float = 6.0) -> list[warpgate_pool.InstanceHealth]:
        return list(self.view)

    def session_id_for(self, client_id: str) -> str:
        return f"blockrelay-{client_id}"

    def acquire(self, session: str) -> warpgate_pool.Instance:
        self.acquired.append(session)
        port = self.ports[self.index % len(self.ports)]
        self.index += 1
        return warpgate_pool.Instance(
            name=f"warp-{port}",
            host="10.0.0.5",
            port=port,
            username="u",
            password="p",
            session_id=session,
        )

    def release(self, session: str) -> bool:
        self.released.append(session)
        return True

    def report(self, session: str, status: int = 0, failure_type: str = "") -> bool:
        self.reports.append((session, status, failure_type))
        return True

    def rotate_instance(self, instance: warpgate_pool.Instance, timeout: float = 180.0) -> bool:
        self.rotated.append(instance.name)
        return True

    def stats(self) -> warpgate_pool.PoolStats:
        return warpgate_pool.PoolStats(
            instances=len(self.ports), available=len(self.ports), reachable=True
        )


class RouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = blockrelay.Config(
            prefixes=[],
            admin_token="admin",
            database=str(Path(self.tmp.name) / "relay.db"),
            upstream_mode="warpgate",
            warpgate_url="http://10.0.0.5:4433",
        )
        self.store = blockrelay.Store(self.cfg.database)
        self.addCleanup(self.store.conn.close)

    def _block_for(self, port: int) -> str:
        return f"2a09:bac1:1234:{port}::/64"

    def test_first_request_leases_an_instance_and_claims_its_block(self) -> None:
        gate = _FakeGate([10011])
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, token, block = self.store.create_client(self.cfg, "alice")
        self.assertEqual(block, "")
        self.assertEqual(self.store.client_by_token(token)["lane"], "warpgate")

        self.store.put_exit("warp-10011", "10.0.0.5:10011", self._block_for(10011))
        route = asyncio.run(router.ensure(self.store.client_by_token(token)))

        self.assertEqual(route.lane, "warpgate")
        self.assertEqual(route.block, self._block_for(10011))
        self.assertEqual(route.instance.port, 10011)
        self.assertEqual(
            self.store.client_by_id(client_id)["block"], self._block_for(10011)
        )
        self.assertEqual(gate.acquired, [f"blockrelay-{client_id}"])

    def test_a_second_client_never_lands_on_the_same_block(self) -> None:
        # The pool offers 10011 twice, which is exactly what a small pool does
        # when its round-robin wraps.
        gate = _FakeGate([10011, 10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        first, _, _ = self.store.create_client(self.cfg, "alice")
        second, token, _ = self.store.create_client(self.cfg, "bob")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))

        route_a = asyncio.run(router.assign(first))
        route_b = asyncio.run(router.assign(second))
        self.assertNotEqual(route_a.block, route_b.block)
        self.assertEqual(route_b.block, self._block_for(10012))
        # The duplicate offer was handed back instead of being double-booked.
        self.assertTrue(gate.released)

    def test_rotation_leaves_the_burnt_block_behind(self) -> None:
        gate = _FakeGate([10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))

        self.store.set_route(client_id, "", "warpgate", "")
        first = asyncio.run(router.assign(client_id))
        old, second = asyncio.run(router.rotate(client_id))
        self.assertEqual(old, first.block)
        self.assertNotEqual(second.block, first.block)
        self.assertEqual(second.block, self._block_for(10012))
        row = self.store.conn.execute(
            "SELECT burnt_until FROM blocks WHERE block=?", (first.block,)
        ).fetchone()
        self.assertGreater(row["burnt_until"], 0)

    def test_a_spent_exit_is_replaced_instead_of_handed_out_again(self) -> None:
        # The first port is offered twice, which is what a wrapped
        # round-robin pool does: the second client is shown the same spent exit.
        gate = _FakeGate([10011, 10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        alice, _, _ = self.store.create_client(self.cfg, "alice")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))
        used = asyncio.run(router.assign(alice))

        # What a rotation leaves behind: nobody owns the /64 any more, but it
        # is burnt until midnight, so the account that answered from it cannot
        # serve anyone today.
        self.store.burn_block(used.block, alice)
        bob, _, _ = self.store.create_client(self.cfg, "bob")

        route = asyncio.run(router.assign(bob))

        self.assertEqual(gate.rotated, ["warp-10011"])
        self.assertEqual(gate.reports, [])
        self.assertEqual(route.block, self._block_for(10012))
        self.assertEqual(self.store.exit_block("warp-10011", "10.0.0.5:10011"), "")

    def test_an_exit_held_by_another_client_is_never_re_registered(self) -> None:
        gate = _FakeGate([10011, 10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        alice, _, _ = self.store.create_client(self.cfg, "alice")
        bob, _, _ = self.store.create_client(self.cfg, "bob")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))
        asyncio.run(router.assign(alice))

        route = asyncio.run(router.assign(bob))

        # Alice is still connected through warp-10011; replacing that account
        # would cut her off, so the duplicate offer is only handed back.
        self.assertEqual(gate.rotated, [])
        self.assertTrue(gate.released)
        self.assertEqual(route.block, self._block_for(10012))

    def test_an_exhausted_pool_stops_re_registering_and_reports_no_capacity(self) -> None:
        gate = _FakeGate([10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        alice, _, _ = self.store.create_client(self.cfg, "alice")
        # Both instances exit from the same /64, which is what a pool looks like
        # after every registration has been used up for the day.
        spent = self._block_for(10011)
        self.store.put_exit("warp-10011", "10.0.0.5:10011", spent)
        self.store.put_exit("warp-10012", "10.0.0.5:10012", spent)
        used = asyncio.run(router.assign(alice))
        self.store.burn_block(used.block, alice)

        bob, _, _ = self.store.create_client(self.cfg, "bob")
        with mock.patch.multiple(
            blockrelay, REBUILD_SETTLE_SECONDS=0.0, REBUILD_SETTLE_BUDGET=0.0
        ), self.assertRaises(blockrelay.NoCapacity) as caught:
            asyncio.run(router.assign(bob))

        # Every re-registration is two Cloudflare calls, so an exhausted pool
        # must not spend the whole attempt budget on them.
        self.assertEqual(len(gate.rotated), blockrelay.REISSUE_ATTEMPTS)
        self.assertIn("spent for today", str(caught.exception))

    def test_an_exit_the_gate_calls_unhealthy_is_passed_over(self) -> None:
        gate = _FakeGate([10011, 10012])
        gate.view = [
            warpgate_pool.InstanceHealth(name="warp-10011", health="unhealthy"),
        ]
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))

        route = asyncio.run(router.assign(client_id))

        self.assertEqual(route.block, self._block_for(10012))
        # Never routed to, never reported: the gate is already repairing it.
        self.assertEqual(gate.reports, [])
        self.assertEqual(gate.rotated, [])

    def test_an_exit_the_gate_says_is_403ing_is_passed_over(self) -> None:
        gate = _FakeGate([10011, 10012])
        gate.view = [
            warpgate_pool.InstanceHealth(
                name="warp-10011", health="healthy", cf_403_rate=80.0, cf_checks=10
            ),
        ]
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))

        route = asyncio.run(router.assign(client_id))

        self.assertEqual(route.block, self._block_for(10012))
        self.assertEqual(gate.rotated, [])

    def test_a_thin_403_sample_is_not_a_verdict(self) -> None:
        gate = _FakeGate([10011])
        # One blocked check out of one is a sample, not a rate; the gate's own
        # rule is that a verdict needs repeated evidence.
        gate.view = [
            warpgate_pool.InstanceHealth(
                name="warp-10011", health="healthy", cf_403_rate=100.0, cf_checks=1
            ),
        ]
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        self.store.put_exit("warp-10011", "10.0.0.5:10011", self._block_for(10011))

        route = asyncio.run(router.assign(client_id))

        self.assertEqual(route.block, self._block_for(10011))

    def test_a_pinned_instance_is_never_re_registered(self) -> None:
        gate = _FakeGate([10011, 10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        alice, _, _ = self.store.create_client(self.cfg, "alice")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))
        used = asyncio.run(router.assign(alice))
        self.store.burn_block(used.block, alice)
        gate.view = [
            warpgate_pool.InstanceHealth(name="warp-10011", dedicated=True),
        ]
        bob, _, _ = self.store.create_client(self.cfg, "bob")

        route = asyncio.run(router.assign(bob))

        self.assertEqual(gate.rotated, [])
        self.assertEqual(route.block, self._block_for(10012))

    def test_rotating_a_client_off_a_pinned_instance_keeps_the_pin(self) -> None:
        gate = _FakeGate([10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))
        asyncio.run(router.assign(client_id))
        gate.view = [
            warpgate_pool.InstanceHealth(name="warp-10011", dedicated=True),
        ]

        old, new = asyncio.run(router.rotate(client_id))

        self.assertEqual(gate.rotated, [])
        self.assertEqual(old, self._block_for(10011))
        self.assertEqual(new.block, self._block_for(10012))

    def test_a_rate_limited_gate_is_retried_after_a_pause(self) -> None:
        class SlowGate(_FakeGate):
            def __init__(self) -> None:
                super().__init__([10011])
                self.refused = 0

            def acquire(self, session: str) -> warpgate_pool.Instance:
                if not self.refused:
                    self.refused += 1
                    raise warpgate_pool.WarpGateError(
                        "请求频率超限", code=warpgate_pool.CODE_RATE_LIMITED, status=429
                    )
                return super().acquire(session)

        gate = SlowGate()
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        self.store.put_exit("warp-10011", "10.0.0.5:10011", self._block_for(10011))

        with mock.patch.object(blockrelay, "RATE_LIMIT_BACKOFF", 0.0):
            route = asyncio.run(router.assign(client_id))

        self.assertEqual(route.block, self._block_for(10011))
        self.assertEqual(gate.refused, 1)

    def test_rotation_replaces_the_spent_registration_and_forgets_its_exit(self) -> None:
        gate = _FakeGate([10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        for port in (10011, 10012):
            self.store.put_exit(f"warp-{port}", f"10.0.0.5:{port}", self._block_for(port))

        first = asyncio.run(router.assign(client_id))
        self.assertEqual(gate.rotated, [])

        old, second = asyncio.run(router.rotate(client_id))

        # Only /api/pool/rotate replaces the account; a report would restart the
        # tunnel and hand back the same spent block.
        self.assertEqual(gate.rotated, ["warp-10011"])
        self.assertEqual(self.store.exit_block("warp-10011", "10.0.0.5:10011"), "")
        self.assertEqual(old, first.block)
        self.assertEqual(second.block, self._block_for(10012))

    def test_a_dead_tunnel_is_reported_not_re_registered(self) -> None:
        gate = _FakeGate([10011, 10012])
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")

        def fake_probe(instance, timeout=10.0):
            if instance.port == 10011:
                return "", ""
            return "2a09:bac1:1234:10012::9", self._block_for(10012)

        with mock.patch.object(warpgate_pool, "probe_block", side_effect=fake_probe):
            route = asyncio.run(router.assign(client_id))

        self.assertEqual(route.block, self._block_for(10012))
        self.assertEqual([r[2] for r in gate.reports], ["proxy_dead"])
        self.assertEqual(gate.rotated, [])

    def test_failed_rotation_never_restores_a_reported_instance(self) -> None:
        gate = _FakeGate([10011])
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        self.store.put_exit("warp-10011", "10.0.0.5:10011", self._block_for(10011))
        asyncio.run(router.assign(client_id))

        # The settle pause is a production nicety; zeroing it keeps the test
        # about the rollback rule rather than about wall-clock time.
        with mock.patch.multiple(
            blockrelay, REBUILD_SETTLE_SECONDS=0.0, REBUILD_SETTLE_BUDGET=0.0
        ), mock.patch.object(warpgate_pool, "probe_block", return_value=("", "")):
            with self.assertRaises(blockrelay.NoCapacity):
                asyncio.run(router.rotate(client_id))

        row = self.store.client_by_id(client_id)
        self.assertEqual(row["block"], "")
        self.assertEqual(row["upstream"], "")

    def test_exhausted_pool_reports_no_capacity(self) -> None:
        gate = _FakeGate([10011])
        router = blockrelay.Router(self.cfg, self.store, gate)
        client_id, _, _ = self.store.create_client(self.cfg, "alice")
        self.store.put_exit("warp-10011", "10.0.0.5:10011", self._block_for(10011))
        asyncio.run(router.assign(client_id))

        other, _, _ = self.store.create_client(self.cfg, "bob")
        with mock.patch.multiple(
            blockrelay, REBUILD_SETTLE_SECONDS=0.0, REBUILD_SETTLE_BUDGET=0.0
        ):
            with self.assertRaises(blockrelay.NoCapacity):
                asyncio.run(router.assign(other))

    def test_hybrid_spends_the_prefix_before_the_pool(self) -> None:
        cfg = blockrelay.Config(
            prefixes=["2001:db8:1::/48"],
            admin_token="admin",
            database=str(Path(self.tmp.name) / "hybrid.db"),
            upstream_mode="hybrid",
            warpgate_url="http://10.0.0.5:4433",
        )
        store = blockrelay.Store(cfg.database)
        self.addCleanup(store.conn.close)
        gate = _FakeGate([10011])
        router = blockrelay.Router(cfg, store, gate)
        client_id, _, block = store.create_client(cfg, "alice")
        self.assertTrue(block.startswith("2001:db8:1:"))
        route = asyncio.run(router.ensure(store.client_by_id(client_id)))
        self.assertEqual(route.lane, "prefix")
        self.assertEqual(gate.acquired, [])


class RelayCapacityTests(unittest.TestCase):
    def test_warpgate_only_config_needs_no_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "admin_token": "a",
                        "upstream": {
                            "mode": "warpgate",
                            "warpgate": {"url": "http://10.0.0.5:4433"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            cfg = blockrelay.Config.load(path)
        self.assertTrue(cfg.uses_warpgate)
        self.assertFalse(cfg.uses_prefix)
        self.assertEqual(cfg.capacity, 0)

    def test_prefix_mode_without_a_prefix_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"admin_token": "a"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                blockrelay.Config.load(path)

    def test_unknown_lane_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "admin_token": "a",
                        "prefixes": ["2001:db8:1::/48"],
                        "upstream": {"mode": "magic"},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                blockrelay.Config.load(path)


if __name__ == "__main__":
    unittest.main()
