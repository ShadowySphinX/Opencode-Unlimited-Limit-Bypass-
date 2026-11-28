"""Tor lane: the SOCKS handshake has to match what Tor actually accepts."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import tor_manager


class _FakeSocks:
    """Records what the client sent and replays a scripted server reply."""

    def __init__(self, replies: list[bytes]) -> None:
        self.sent: list[bytes] = []
        self._replies = list(replies)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        return self._replies.pop(0)[:size] if self._replies else b""

    def settimeout(self, _value) -> None:
        pass

    def close(self) -> None:
        pass


class SocksGreetingTests(unittest.TestCase):
    def test_tor_is_not_offered_credentials_that_were_never_supplied(self) -> None:
        # Tor prefers method 2 whenever it is offered, so advertising it
        # without credentials makes every tunnel fail while the proxy itself
        # is perfectly healthy.
        server = _FakeSocks([b"\x05\x00"])

        with mock.patch.object(
            tor_manager.socket, "create_connection", return_value=server
        ):
            try:
                tor_manager.open_socks5_tunnel("example.com", 443, timeout=1.0)
            except Exception:
                pass

        self.assertEqual(server.sent[0], b"\x05\x01\x00")

    def test_credentials_are_offered_only_when_present(self) -> None:
        server = _FakeSocks([b"\x05\x02"])

        with mock.patch.object(
            tor_manager.socket, "create_connection", return_value=server
        ):
            try:
                tor_manager.open_socks5_tunnel(
                    "example.com", 443, timeout=1.0, username="u", password="p"
                )
            except Exception:
                pass

        self.assertEqual(server.sent[0], b"\x05\x02\x00\x02")


class SpawnTests(unittest.TestCase):
    """The portable daemon has to spawn on POSIX as well as Windows."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._saved = (
            tor_manager.TOR_PID_FILE,
            tor_manager.TOR_DATA_DIR,
            tor_manager.TOR_LOG_FILE,
        )
        tor_manager.TOR_PID_FILE = self.dir / "tor.pid"
        tor_manager.TOR_DATA_DIR = self.dir / "data"
        tor_manager.TOR_LOG_FILE = self.dir / "tor.log"

    def tearDown(self) -> None:
        (
            tor_manager.TOR_PID_FILE,
            tor_manager.TOR_DATA_DIR,
            tor_manager.TOR_LOG_FILE,
        ) = self._saved
        self.tmp.cleanup()

    def _start(self, platform: str) -> dict:
        proc = mock.Mock(pid=4321)
        with mock.patch.object(
            tor_manager.sys, "platform", platform
        ), mock.patch.object(
            tor_manager, "find_tor_exe", return_value=Path("/usr/bin/tor")
        ), mock.patch.object(
            tor_manager,
            "test_socks5_alive",
            side_effect=[False, False, True],
        ), mock.patch.object(
            tor_manager.subprocess, "Popen", return_value=proc
        ) as popen:
            ok, _ = tor_manager.start_portable_tor()

        self.assertTrue(ok)
        self.assertEqual(tor_manager.TOR_PID_FILE.read_text(encoding="utf-8"), "4321")
        return popen.call_args.kwargs

    def test_linux_spawns_without_windows_creation_flags(self) -> None:
        # creationflags is a Windows-only Popen argument; passing it on Linux
        # raises ValueError and Tor mode could never start.
        kwargs = self._start("linux")

        self.assertNotIn("creationflags", kwargs)
        self.assertTrue(kwargs["start_new_session"])

    def test_windows_keeps_the_hidden_detached_flags(self) -> None:
        kwargs = self._start("win32")

        self.assertEqual(
            kwargs["creationflags"],
            tor_manager.CREATE_NO_WINDOW | tor_manager.DETACHED_PROCESS,
        )
        self.assertNotIn("start_new_session", kwargs)

    def test_a_bootstrapping_tor_is_not_spawned_twice(self) -> None:
        with mock.patch.object(
            tor_manager, "test_socks5_alive", return_value=False
        ), mock.patch.object(
            tor_manager, "is_portable_tor_running", return_value=True
        ), mock.patch.object(
            tor_manager, "_portable_tor_age", return_value=5.0
        ), mock.patch.object(
            tor_manager.subprocess, "Popen"
        ) as popen:
            ok, message = tor_manager.start_portable_tor()

        self.assertFalse(ok)
        self.assertIn("still starting", message)
        popen.assert_not_called()

    def test_a_wedged_tor_is_replaced_after_the_grace_period(self) -> None:
        with mock.patch.object(
            tor_manager, "test_socks5_alive", side_effect=[False, False, True]
        ), mock.patch.object(
            tor_manager, "is_portable_tor_running", return_value=True
        ), mock.patch.object(
            tor_manager, "_portable_tor_age", return_value=600.0
        ), mock.patch.object(
            tor_manager, "stop_portable_tor"
        ) as stop, mock.patch.object(
            tor_manager, "find_tor_exe", return_value=Path("/usr/bin/tor")
        ), mock.patch.object(
            tor_manager.subprocess, "Popen", return_value=mock.Mock(pid=99)
        ) as popen:
            ok, _message = tor_manager.start_portable_tor()

        self.assertTrue(ok)
        stop.assert_called_once_with()
        popen.assert_called_once()
