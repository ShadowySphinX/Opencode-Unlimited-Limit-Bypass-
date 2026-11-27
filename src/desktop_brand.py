"""Desktop brand: the words the app itself uses about the free allowance.

OpenCode Desktop keeps every string it shows inside ``resources/app.asar``, and
the free-tier card that replaces the chat box is the one place it still sells a
subscription. Rewriting that copy in place is enough to stop the app arguing
with the tool that is already moving the chat forward, and it costs nothing at
runtime because the renderer simply loads different text.

How the archive is changed:

* The header JSON is parsed, the entries that hold the copy are read, and the
  rewritten files are appended to the end of the archive. Only their
  ``offset``/``size`` in the header change, so no other byte of the archive
  moves and an entry that is not patched keeps reading from its original place.
* The new archive is written beside the old one and read back before it is
  swapped in: every patched entry must return the exact bytes written, and an
  untouched entry must return the same bytes it did before. Any failure leaves
  the original archive alone.
* The header that came with the install is kept, so :func:`restore` rebuilds the
  original file byte for byte instead of storing a second copy of 230 MB. The
  header is only ever taken from an archive that is not already patched, so a
  restore can never come from a stale copy.
* Nothing is written while OpenCode is running, because it holds the archive
  open, and nothing is written at all when Electron's asar integrity fuse is
  enabled, because the app would then refuse to start.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import time
from pathlib import Path

from ouc_common import DEST_DIR, append_log, find_opencode_desktop

ASAR_RELATIVE = Path("resources") / "app.asar"
INDEX_ENTRY = ("out", "renderer", "index.html")
RENDERER_DIR = ("out", "renderer", "assets")

STATE_DIR = DEST_DIR / "desktop"
STATE_FILE = STATE_DIR / "state.json"
HEADER_COPY = STATE_DIR / "header.bin"
INTENT_FILE = STATE_DIR / "wanted.flag"
BRAND_LOG_FILE = STATE_DIR / "brand.log"

BRAND_NAME = "Opencode Unlimited"

# Electron writes a fixed marker into its executable and follows it with the
# version, the fuse count and one byte per fuse. Index 4 hashes the archive at
# load time, so a patched archive would make the app fail to start rather than
# run with different text.
FUSE_MAGIC = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
ASAR_INTEGRITY_FUSE = 4

MAX_HEADER_BYTES = 64 * 1024 * 1024
MAX_CHUNK_BYTES = 32 * 1024 * 1024
COPY_CHUNK = 8 * 1024 * 1024

# The copy table sits in one renderer bundle. Finding that string is what marks
# the chunk to read, so a pristine archive costs one chunk of I/O rather than
# every script in the archive.
COPY_ANCHOR = '"dialog.usageExceeded.freeTier.description":'

# Anchored on the key and its backtick quoting, so a value can never be replaced
# inside an unrelated message that happens to contain the same words.
REWRITES: tuple[tuple[str, str, str], ...] = (
    (
        "free-tier dialog title",
        '"dialog.usageExceeded.freeTier.title":`Free limit reached`',
        '"dialog.usageExceeded.freeTier.title":`Free allowance used up`',
    ),
    (
        "free-tier dialog body",
        '"dialog.usageExceeded.freeTier.description":`Subscribe to OpenCode Go for reliable access '
        "to the best open-source models for $10/month.`",
        '"dialog.usageExceeded.freeTier.description":`The free allowance refills on a schedule of its '
        "own. Nothing needs pressing: chats waiting on it continue by themselves once it reopens.`",
    ),
    (
        "free-tier dialog button",
        '"dialog.usageExceeded.freeTier.actionLabel":`Subscribe`',
        '"dialog.usageExceeded.freeTier.actionLabel":`Pricing`',
    ),
    (
        "inline limit message",
        '"ui.sessionTurn.error.freeUsageExceeded":`Free usage exceeded`',
        '"ui.sessionTurn.error.freeUsageExceeded":`Free allowance used up`',
    ),
    (
        "app menu label",
        '"desktop.menu.app":`OpenCode`',
        f'"desktop.menu.app":`{BRAND_NAME}`',
    ),
)

HTML_REWRITE = (">OpenCode</title>", f">{BRAND_NAME}</title>")

# What proves the archive still holds our copy.
_TITLE_MARK = "Free allowance used up"
_BODY_MARK = "refills on a schedule of its own"
_MENU_MARK = f'"desktop.menu.app":`{BRAND_NAME}`'


def _note(message: str) -> None:
    try:
        append_log(BRAND_LOG_FILE, message)
    except Exception:
        pass


# --------------------------------------------------------------------------- locating the install


def install_dir() -> Path | None:
    """The install that owns an archive, preferring the one the app runs from."""
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    roots: list[Path] = []
    exe = find_opencode_desktop()
    if exe:
        roots.append(Path(exe).parent)
    roots.extend(
        (
            local / "Programs" / "ai.opencode.desktop",
            local / "Programs" / "OpenCode",
            local / "OpenCode",
            Path(r"C:\Program Files\OpenCode"),
            Path(r"C:\Program Files\ai.opencode.desktop"),
        )
    )
    for root in roots:
        if (root / ASAR_RELATIVE).is_file():
            return root
    return None


def app_is_open() -> bool:
    """True when the app is open. An unknown answer counts as open: never patch under it."""
    install = install_dir()
    exe = str(install / "OpenCode.exe").lower() if install else ""
    try:
        import psutil

        for proc in psutil.process_iter(["name", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                path = (proc.info.get("exe") or "").lower()
            except Exception:
                continue
            if name != "opencode.exe":
                continue
            if not exe or not path or path == exe:
                return True
    except Exception:
        return True
    return False


def asar_integrity_enabled(exe: Path) -> bool | None:
    """Electron's fuse state for the archive hash: None when it cannot be read."""
    try:
        blob = exe.read_bytes()
    except OSError:
        return None
    at = blob.find(FUSE_MAGIC)
    if at < 0:
        return None
    count_at = at + len(FUSE_MAGIC) + 1
    if count_at >= len(blob):
        return None
    states = blob[count_at + 1 : count_at + 1 + blob[count_at]]
    if len(states) <= ASAR_INTEGRITY_FUSE:
        # The fuse is not part of this build, so nothing hashes the archive.
        return False
    return states[ASAR_INTEGRITY_FUSE : ASAR_INTEGRITY_FUSE + 1] == b"1"


# --------------------------------------------------------------------------- asar plumbing


def _archive_header(handle) -> tuple[dict, int]:
    """Parse the archive header; returns it with the offset its file data starts at."""
    handle.seek(0)
    prelude = handle.read(16)
    if len(prelude) < 16:
        raise ValueError("not an asar archive")
    marker, span, _inner, json_len = struct.unpack("<IIII", prelude)
    if marker != 4 or not 0 < json_len <= MAX_HEADER_BYTES:
        raise ValueError("unexpected asar header")
    if not 8 < span <= MAX_HEADER_BYTES:
        raise ValueError(f"unexpected header span ({span})")
    raw = handle.read(json_len)
    if len(raw) != json_len:
        raise ValueError("truncated asar header")
    header = json.loads(raw.decode("utf-8"))
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise ValueError("asar header has no file table")
    # `span` counts from byte 8 to the first file: the pickled string plus the
    # length prefixes that come before it.
    return header, 8 + span


def _archive_prelude(header: dict) -> bytes:
    """The header in the archive's own encoding: nested lengths, JSON, padding."""
    raw = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    pad = (4 - len(raw) % 4) % 4
    pickled = len(raw) + pad
    return struct.pack("<IIII", 4, pickled + 8, pickled + 4, len(raw)) + raw + b"\0" * pad


def _node_at(header: dict, path: tuple[str, ...]) -> dict:
    node = header
    for part in path:
        node = node["files"][part]
    return node


def _entry_bytes(handle, start: int, entry: dict) -> bytes:
    if entry.get("unpacked"):
        raise ValueError("entry is unpacked; its bytes live in app.asar.unpacked")
    size = int(entry["size"])
    if size < 0 or size > MAX_CHUNK_BYTES:
        raise ValueError(f"entry size out of range ({size})")
    handle.seek(start + int(entry["offset"]))
    data = handle.read(size)
    if len(data) != size:
        raise ValueError("truncated entry")
    return data


def _checksum_block(data: bytes) -> dict:
    """The per-file block the archive carries; kept honest for entries we move."""
    block = 4 * 1024 * 1024
    return {
        "algorithm": "SHA256",
        "hash": hashlib.sha256(data).hexdigest(),
        "blockSize": block,
        "blocks": [
            hashlib.sha256(data[i : i + block]).hexdigest()
            for i in range(0, max(len(data), 1), block)
        ],
    }


def _copy_exact(source, target, count: int) -> None:
    """Copy exactly ``count`` bytes, so a rebuild cannot run past the data section."""
    left = count
    while left > 0:
        block = source.read(min(COPY_CHUNK, left))
        if not block:
            raise ValueError("the data section ended early")
        target.write(block)
        left -= len(block)


def _list_files(node: dict, prefix: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], dict]]:
    found: list[tuple[tuple[str, ...], dict]] = []
    for name, meta in (node.get("files") or {}).items():
        if not isinstance(meta, dict):
            continue
        path = prefix + (name,)
        if isinstance(meta.get("files"), dict):
            found.extend(_list_files(meta, path))
        elif "offset" in meta:
            found.append((path, meta))
    return found


def _copy_candidates(header: dict) -> list[tuple[tuple[str, ...], dict]]:
    """Renderer scripts that could hold the copy, the bundle named main- first."""
    bundle: list[tuple[tuple[str, ...], dict]] = []
    others: list[tuple[tuple[str, ...], dict]] = []
    for path, meta in _list_files(header):
        if path[: len(RENDERER_DIR)] != RENDERER_DIR:
            continue
        name = path[-1]
        if not name.endswith(".js") or meta.get("unpacked"):
            continue
        if not 0 < int(meta.get("size", 0)) <= MAX_CHUNK_BYTES:
            continue
        (bundle if name.startswith("main-") else others).append((path, meta))
    return bundle + others


def _rewritten(text: str) -> tuple[str, list[str]]:
    """The text with every replacement that applies, plus the labels that moved."""
    applied: list[str] = []
    for label, before, after in REWRITES:
        if before in text:
            text = text.replace(before, after)
            applied.append(label)
    return text, applied


def _patched(handle, start: int, header: dict) -> tuple[dict[tuple[str, ...], bytes], list[str]]:
    """Every file that would change, as ``{path: new bytes}``, plus what moved."""
    changes: dict[tuple[str, ...], bytes] = {}
    labels: list[str] = []

    for path, meta in _copy_candidates(header):
        try:
            text = _entry_bytes(handle, start, meta).decode("utf-8")
        except (UnicodeDecodeError, ValueError, KeyError):
            continue
        new_text, applied = _rewritten(text)
        if applied:
            changes[path] = new_text.encode("utf-8")
            labels.extend(applied)
        if COPY_ANCHOR in text:
            # The string table is in this chunk; no other script repeats it.
            break

    try:
        html = _entry_bytes(handle, start, _node_at(header, INDEX_ENTRY)).decode("utf-8", errors="replace")
    except (KeyError, ValueError, TypeError):
        html = ""
    before, after = HTML_REWRITE
    if before in html:
        changes[INDEX_ENTRY] = html.replace(before, after).encode("utf-8")
        labels.append("window title")
    return changes, labels


def _is_patched(handle, start: int, header: dict) -> bool:
    """True when the copy in the archive is already ours."""
    try:
        html = _entry_bytes(handle, start, _node_at(header, INDEX_ENTRY)).decode("utf-8", errors="replace")
    except (KeyError, ValueError, TypeError):
        html = ""
    if f">{BRAND_NAME}</title>" in html:
        return True
    for path, meta in _copy_candidates(header):
        try:
            text = _entry_bytes(handle, start, meta).decode("utf-8", errors="replace")
        except (KeyError, ValueError, TypeError):
            continue
        if _TITLE_MARK in text or _MENU_MARK in text:
            return True
        if COPY_ANCHOR in text:
            # The string table is in this chunk, so the answer is already here.
            return False
    return False


# --------------------------------------------------------------------------- state


def _load_state() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(state: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=1), encoding="utf-8")
    except OSError as exc:
        _note(f"could not save state: {exc}")


def _clear_state() -> None:
    for path in (STATE_FILE, HEADER_COPY, INTENT_FILE):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _mark_wanted() -> None:
    """Remember that the copy was asked for, so a closed app gets it without asking twice."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        INTENT_FILE.write_text(str(int(time.time())), encoding="utf-8")
    except OSError as exc:
        _note(f"could not record the request: {exc}")


def _clear_wanted() -> None:
    try:
        INTENT_FILE.unlink(missing_ok=True)
    except OSError:
        pass


# --------------------------------------------------------------------------- public verbs


def copy_status() -> dict:
    """What is installed, what is patched, and what stands in the way."""
    install = install_dir()
    if install is None:
        return {
            "installed": False,
            "patched": False,
            "supported": False,
            "reason": "OpenCode Desktop is not installed",
        }
    asar = install / ASAR_RELATIVE
    out: dict = {
        "installed": True,
        "patched": False,
        "supported": False,
        "reason": "",
        "running": app_is_open(),
        "archive": str(asar),
        "archive_bytes": 0,
        "restorable": HEADER_COPY.is_file(),
        "waiting": INTENT_FILE.is_file(),
        "integrity": asar_integrity_enabled(install / "OpenCode.exe"),
        "labels": [],
    }
    try:
        out["archive_bytes"] = asar.stat().st_size
    except OSError:
        pass
    try:
        with asar.open("rb") as handle:
            header, start = _archive_header(handle)
            out["patched"] = _is_patched(handle, start, header)
            changes, labels = _patched(handle, start, header)
            out["supported"] = out["patched"] or bool(changes)
            out["labels"] = labels
    except (OSError, ValueError, KeyError) as exc:
        out["reason"] = f"unreadable: {exc}"
        return out
    if out["integrity"] is not False:
        out["reason"] = "this build checks its own files, so it is left alone"
    elif not out["supported"]:
        out["reason"] = "this build does not carry the copy to replace"
    elif _load_state() and not out["patched"]:
        out["reason"] = "the app was updated; apply again to restore the copy"
    return out


def apply_copy() -> tuple[bool, str]:
    """Rewrite the free-tier copy and the app name. Safe to call repeatedly."""
    install = install_dir()
    if install is None:
        return False, "OpenCode Desktop is not installed."
    if app_is_open():
        _mark_wanted()
        return False, "OpenCode Desktop is open; it will be done the next time it is closed."
    exe = install / "OpenCode.exe"
    if asar_integrity_enabled(exe) is not False:
        return False, "This build checks its own files, so it is left alone."

    asar = install / ASAR_RELATIVE
    temp = asar.with_name("app.asar.ouc-new")
    state = _load_state()
    try:
        with asar.open("rb") as handle:
            header, start = _archive_header(handle)
            already = _is_patched(handle, start, header)
            changes, labels = _patched(handle, start, header)
            if not changes:
                if already:
                    return True, "The app already shows this."
                return False, "This build does not carry the copy to replace."
            archive_bytes = asar.stat().st_size
            data_bytes = archive_bytes - start
            # The header of an untouched install is what `restore` puts back. A
            # patched archive never overwrites it with its own header; without
            # the original header a byte-exact restore is impossible, and
            # recording the patched one would silently keep the copy in place.
            if not already:
                handle.seek(0)
                prelude = handle.read(start)
                if len(prelude) != start:
                    raise ValueError("the header could not be read in full")
                STATE_DIR.mkdir(parents=True, exist_ok=True)
                HEADER_COPY.write_bytes(prelude)
                state = {
                    "asar": str(asar),
                    "exe": str(exe),
                    "brand": BRAND_NAME,
                    "data_bytes": data_bytes,
                    "baseline_bytes": archive_bytes,
                    "labels": [],
                }

        # Read the sentinel before the header is mutated; afterwards its offset
        # points into the appended copies and would no longer describe the
        # original archive.
        try:
            with asar.open("rb") as original:
                sentinel = _entry_bytes(
                    original, start, _node_at(header, ("package.json",))
                )
        except KeyError:
            sentinel = None

        # Point the changed entries at copies appended after the data section.
        # Only offsets move, so an entry that is not patched keeps reading its
        # own bytes from exactly where they already are.
        cursor = archive_bytes - start
        for path, data in changes.items():
            meta = _node_at(header, path)
            meta["offset"] = str(cursor)
            meta["size"] = len(data)
            meta["integrity"] = _checksum_block(data)
            cursor += len(data)
        added = cursor - (archive_bytes - start)

        with asar.open("rb") as source, temp.open("wb") as target:
            target.write(_archive_prelude(header))
            source.seek(start)
            shutil.copyfileobj(source, target, COPY_CHUNK)
            for data in changes.values():
                target.write(data)
            target.flush()
            os.fsync(target.fileno())

        # Read the result back before it is allowed to replace anything.
        with temp.open("rb") as check:
            new_header, new_start = _archive_header(check)
            for path, data in changes.items():
                if _entry_bytes(check, new_start, _node_at(new_header, path)) != data:
                    raise ValueError(f"{'/'.join(path)} did not read back")
            if sentinel is not None:
                after = _entry_bytes(
                    check, new_start, _node_at(new_header, ("package.json",))
                )
                if sentinel != after:
                    raise ValueError("an entry that was not patched moved")
        if temp.stat().st_size != new_start + data_bytes + added:
            raise ValueError("the archive came out the wrong size")

        if app_is_open():
            temp.unlink(missing_ok=True)
            return False, "OpenCode Desktop was opened; trying again later."
        os.replace(temp, asar)

        final = asar.stat()
        state.update(
            {
                "archive_bytes": final.st_size,
                "archive_mtime_ns": final.st_mtime_ns,
                "patched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "labels": sorted(set(labels)),
            }
        )
        _save_state(state)
        _clear_wanted()
        _note(f"patched {asar}: {', '.join(sorted(set(labels)))}")
        return True, "Done: OpenCode Desktop shows this the next time it opens."
    except (OSError, ValueError, KeyError) as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        _note(f"patch failed, the app was left as it was: {exc}")
        return False, f"Could not change OpenCode Desktop ({exc}); it was left as it was."


def restore_copy() -> tuple[bool, str]:
    """Put the archive back exactly as the install shipped it."""
    install = install_dir()
    if install is None:
        return True, "OpenCode Desktop is not installed."
    asar = install / ASAR_RELATIVE
    try:
        with asar.open("rb") as handle:
            header, start = _archive_header(handle)
            patched = _is_patched(handle, start, header)
    except (OSError, ValueError, KeyError) as exc:
        return False, f"The archive could not be read ({exc})."
    if not patched:
        _clear_state()
        return True, "OpenCode is already as it was."
    if app_is_open():
        return False, "OpenCode Desktop is open; it will be put back the next time it is closed."
    state = _load_state()
    if not HEADER_COPY.is_file() or not state:
        return False, "The original header was not kept, so a byte-exact restore is not possible."

    temp = asar.with_name("app.asar.ouc-restore")
    try:
        prelude = HEADER_COPY.read_bytes()
        data_bytes = int(state["data_bytes"])
        with asar.open("rb") as source, temp.open("wb") as target:
            target.write(prelude)
            source.seek(start)
            _copy_exact(source, target, data_bytes)
            target.flush()
            os.fsync(target.fileno())
        if temp.stat().st_size != len(prelude) + data_bytes:
            raise ValueError("the rebuilt archive is the wrong size")
        with temp.open("rb") as check:
            _archive_header(check)
        if app_is_open():
            temp.unlink(missing_ok=True)
            return False, "OpenCode Desktop was opened; trying again later."
        os.replace(temp, asar)
    except (OSError, ValueError, KeyError) as exc:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, f"Could not put the archive back ({exc})."
    _clear_state()
    _note(f"restored {asar}")
    return True, "OpenCode Desktop is back to how it was."


def sync_copy() -> str:
    """Keep the patch in place across app updates. One stat when nothing changed.

    Runs from the background service, so it is also the thing that finishes a
    request that was made while OpenCode was open: the request is remembered and
    the patch lands on the first tick after the app closes.
    """
    state = _load_state()
    wanted = INTENT_FILE.is_file()
    if not state and not wanted:
        return "off"
    install = install_dir()
    if install is None:
        return "gone"
    asar = install / ASAR_RELATIVE
    try:
        stat = asar.stat()
    except OSError:
        return "gone"
    if (
        state
        and stat.st_size == int(state.get("archive_bytes", 0) or 0)
        and stat.st_mtime_ns == int(state.get("archive_mtime_ns", 0) or 0)
    ):
        return "ok"
    if app_is_open():
        return "waiting"
    ok, message = apply_copy()
    if ok:
        return "applied"
    return f"failed: {message}"


def main(argv: list[str] | None = None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    command = args[0] if args else "status"
    if command == "apply":
        ok, message = apply_copy()
        print(message)
        return 0 if ok else 1
    if command == "restore":
        ok, message = restore_copy()
        print(message)
        return 0 if ok else 1
    if command == "sync":
        print(sync_copy())
        return 0
    print(json.dumps(copy_status(), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
