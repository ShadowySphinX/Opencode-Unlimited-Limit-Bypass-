"""The desktop copy patch: what it rewrites, and what it refuses to touch.

Every test builds a small archive with the same layout the real one uses, so the
offset arithmetic, the read-back check and the byte-exact restore are exercised
without needing OpenCode Desktop installed.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import desktop_brand

BUNDLE = (
    'J({"dialog.usageExceeded.freeTier.title":`Free limit reached`,'
    '"dialog.usageExceeded.freeTier.description":`Subscribe to OpenCode Go for reliable access '
    'to the best open-source models for $10/month.`,'
    '"dialog.usageExceeded.freeTier.actionLabel":`Subscribe`,'
    '"ui.sessionTurn.error.freeUsageExceeded":`Free usage exceeded`,'
    '"desktop.menu.app":`OpenCode`});'
)
HTML = "<!doctype html><head><title data-sm>OpenCode</title></head><body></body></html>"
PACKAGE = b'{"name":"@opencode/desktop","version":"2.3.0"}'
OTHER_JS = "export const unrelated = 1;"


def nest(header: dict, path: tuple[str, ...], meta: dict) -> None:
    node = header
    for part in path[:-1]:
        node = node["files"].setdefault(part, {"files": {}})
    node["files"][path[-1]] = meta


def build_archive(root: Path, files: dict[tuple[str, ...], bytes] | None = None) -> Path:
    """A real archive layout: header with offsets, then the data section."""
    files = files or {
        ("out", "renderer", "assets", "main-TEST.js"): BUNDLE.encode(),
        ("out", "renderer", "index.html"): HTML.encode(),
        ("out", "renderer", "assets", "route-TEST.js"): OTHER_JS.encode(),
        ("package.json",): PACKAGE,
    }
    header: dict = {"files": {}}
    offset = 0
    for path, data in files.items():
        nest(header, path, {"size": len(data), "offset": str(offset)})
        offset += len(data)
    prelude = desktop_brand._archive_prelude(header)
    target = root / "resources" / "app.asar"
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as handle:
        handle.write(prelude)
        for data in files.values():
            handle.write(data)
    return target


def build_exe(root: Path, integrity: str) -> Path:
    exe = root / "OpenCode.exe"
    states = bytearray(b"0" * 9)
    states[desktop_brand.ASAR_INTEGRITY_FUSE] = ord(integrity)
    exe.write_bytes(b"MZ" + b"\0" * 64 + desktop_brand.FUSE_MAGIC + b"\x01\x09" + bytes(states))
    return exe


class DesktopBrandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.install = self.root / "install"
        self.install.mkdir()
        self.state_dir = self.root / "state"
        self.asar = build_archive(self.install)
        build_exe(self.install, "0")
        self.original = self.asar.read_bytes()
        self._patches = [
            mock.patch.object(desktop_brand, "install_dir", return_value=self.install),
            mock.patch.object(desktop_brand, "app_is_open", return_value=False),
            mock.patch.object(desktop_brand, "STATE_DIR", self.state_dir),
            mock.patch.object(desktop_brand, "STATE_FILE", self.state_dir / "state.json"),
            mock.patch.object(desktop_brand, "HEADER_COPY", self.state_dir / "header.bin"),
            mock.patch.object(desktop_brand, "INTENT_FILE", self.state_dir / "wanted.flag"),
            mock.patch.object(desktop_brand, "BRAND_LOG_FILE", self.state_dir / "brand.log"),
        ]
        for patch in self._patches:
            patch.start()
            self.addCleanup(patch.stop)

    def read_entry(self, path: tuple[str, ...]) -> bytes:
        with self.asar.open("rb") as handle:
            header, start = desktop_brand._archive_header(handle)
            return desktop_brand._entry_bytes(handle, start, desktop_brand._node_at(header, path))

    # -- the archive itself --------------------------------------------

    def test_the_header_round_trips_to_the_same_data_offset(self) -> None:
        with self.asar.open("rb") as handle:
            header, start = desktop_brand._archive_header(handle)
        encoded = desktop_brand._archive_prelude(header)

        self.assertEqual(len(encoded), start)
        self.assertEqual(encoded[: len(encoded) - 1], self.original[: start - 1])

    def test_offsets_are_strings_exactly_like_the_real_archive(self) -> None:
        with self.asar.open("rb") as handle:
            header, _start = desktop_brand._archive_header(handle)
        entry = desktop_brand._node_at(header, ("package.json",))

        self.assertIsInstance(entry["offset"], str)
        self.assertIsInstance(entry["size"], int)

    # -- apply ---------------------------------------------------------

    def test_apply_rewrites_the_copy_and_leaves_other_files_alone(self) -> None:
        ok, message = desktop_brand.apply_copy()

        self.assertTrue(ok, message)
        bundle = self.read_entry(("out", "renderer", "assets", "main-TEST.js")).decode()
        self.assertIn("Free allowance used up", bundle)
        self.assertIn("refills on a schedule of its own", bundle)
        self.assertIn("`Pricing`", bundle)
        self.assertIn("Opencode Unlimited", bundle)
        self.assertNotIn("Subscribe to OpenCode Go", bundle)
        self.assertEqual(self.read_entry(("package.json",)), PACKAGE)
        self.assertEqual(self.read_entry(("out", "renderer", "assets", "route-TEST.js")), OTHER_JS.encode())

    def test_apply_renames_the_window_title(self) -> None:
        desktop_brand.apply_copy()

        html = self.read_entry(("out", "renderer", "index.html")).decode()
        self.assertIn(">Opencode Unlimited</title>", html)

    def test_apply_reports_the_archive_as_patched(self) -> None:
        desktop_brand.apply_copy()

        state = desktop_brand.copy_status()
        self.assertTrue(state["patched"])
        self.assertTrue(state["supported"])
        self.assertEqual(state["integrity"], False)

    def test_second_apply_changes_nothing(self) -> None:
        desktop_brand.apply_copy()
        size = self.asar.stat().st_size

        ok, message = desktop_brand.apply_copy()

        self.assertTrue(ok)
        self.assertIn("already", message)
        self.assertEqual(self.asar.stat().st_size, size)

    def test_a_patched_archive_is_never_recorded_as_the_restore_baseline(self) -> None:
        desktop_brand.apply_copy()
        header = self.state_dir / "header.bin"
        header.unlink()

        with mock.patch.object(desktop_brand, "_is_patched", return_value=True), \
                mock.patch.object(
                    desktop_brand,
                    "_patched",
                    return_value=({("package.json",): PACKAGE}, ["window title"]),
                ):
            ok, message = desktop_brand.apply_copy()

        self.assertTrue(ok, message)
        self.assertFalse(header.is_file())
        self.assertFalse(desktop_brand.copy_status()["restorable"])

    def test_nothing_is_written_while_the_app_is_open(self) -> None:
        with mock.patch.object(desktop_brand, "app_is_open", return_value=True):
            ok, message = desktop_brand.apply_copy()

        self.assertFalse(ok)
        self.assertIn("is open", message)
        self.assertEqual(self.asar.read_bytes(), self.original)

    def test_a_build_that_checks_its_own_archive_is_left_alone(self) -> None:
        build_exe(self.install, "1")

        ok, message = desktop_brand.apply_copy()

        self.assertFalse(ok)
        self.assertIn("checks its own files", message)
        self.assertEqual(self.asar.read_bytes(), self.original)

    def test_a_build_without_the_copy_is_reported_not_guessed(self) -> None:
        self.asar.unlink()
        build_archive(
            self.install,
            files={("out", "renderer", "assets", "main-OTHER.js"): b"export const x = 1;"},
        )

        ok, message = desktop_brand.apply_copy()

        self.assertFalse(ok)
        self.assertIn("does not carry the copy", message)

    def test_a_failed_read_back_leaves_the_archive_untouched(self) -> None:
        with mock.patch.object(desktop_brand, "_entry_bytes", side_effect=ValueError("probe")):
            ok, _message = desktop_brand.apply_copy()

        self.assertFalse(ok)
        self.assertEqual(self.asar.read_bytes(), self.original)

    # -- restore -------------------------------------------------------

    def test_restore_returns_the_archive_byte_for_byte(self) -> None:
        desktop_brand.apply_copy()
        self.assertNotEqual(self.asar.read_bytes(), self.original)

        ok, message = desktop_brand.restore_copy()

        self.assertTrue(ok, message)
        self.assertEqual(self.asar.read_bytes(), self.original)
        self.assertFalse((self.state_dir / "header.bin").exists())

    def test_restore_on_an_untouched_install_is_a_no_op(self) -> None:
        ok, message = desktop_brand.restore_copy()

        self.assertTrue(ok)
        self.assertIn("already", message)
        self.assertEqual(self.asar.read_bytes(), self.original)

    def test_restore_waits_for_the_app_to_close(self) -> None:
        desktop_brand.apply_copy()
        patched = self.asar.read_bytes()

        with mock.patch.object(desktop_brand, "app_is_open", return_value=True):
            ok, _message = desktop_brand.restore_copy()

        self.assertFalse(ok)
        self.assertEqual(self.asar.read_bytes(), patched)

    # -- keeping it applied -------------------------------------------

    def test_sync_is_off_until_apply_was_used(self) -> None:
        self.assertEqual(desktop_brand.sync_copy(), "off")

    def test_sync_reports_ok_when_the_patch_is_current(self) -> None:
        desktop_brand.apply_copy()

        self.assertEqual(desktop_brand.sync_copy(), "ok")

    def test_sync_waits_while_the_app_is_open(self) -> None:
        desktop_brand.apply_copy()
        self.asar.touch()

        with mock.patch.object(desktop_brand, "app_is_open", return_value=True):
            self.assertEqual(desktop_brand.sync_copy(), "waiting")

    def test_an_update_over_the_patch_is_put_back(self) -> None:
        desktop_brand.apply_copy()
        self.asar.unlink()
        build_archive(self.install)

        self.assertEqual(desktop_brand.sync_copy(), "applied")
        bundle = self.read_entry(("out", "renderer", "assets", "main-TEST.js")).decode()
        self.assertIn("Free allowance used up", bundle)

    def test_a_request_made_while_the_app_is_open_lands_after_it_closes(self) -> None:
        with mock.patch.object(desktop_brand, "app_is_open", return_value=True):
            ok, message = desktop_brand.apply_copy()
            self.assertFalse(ok)
            self.assertIn("is open", message)
            self.assertTrue(desktop_brand.copy_status()["waiting"])
            self.assertEqual(desktop_brand.sync_copy(), "waiting")

        self.assertEqual(desktop_brand.sync_copy(), "applied")
        self.assertFalse(desktop_brand.copy_status()["waiting"])
        bundle = self.read_entry(("out", "renderer", "assets", "main-TEST.js")).decode()
        self.assertIn("Free allowance used up", bundle)


if __name__ == "__main__":
    unittest.main()
