"""OpenCode accounts as a pool of free-tier budgets.

Every OpenCode Console account carries its own daily free allowance, while an
install with no credential falls back to the shared anonymous bucket that is
dry for most of the day.  ``opencode auth export`` lists the stored
credentials and ``opencode auth switch`` makes another one active, so a wall
can be answered by changing who is asking instead of reconnecting the tunnel.

Only identifiers and labels leave this module: tokens stay inside the CLI's own
output and are never parsed or logged.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from ouc_common import find_opencode_cli, opencode_command, run_hidden

INTEGRATION = "opencode"
EXPORT_TIMEOUT = 30.0
SWITCH_TIMEOUT = 45.0


def _run(args: list[str], timeout: float) -> subprocess.CompletedProcess[str] | None:
    cli = find_opencode_cli()
    if not cli:
        return None
    try:
        return run_hidden(opencode_command(cli, ["auth", *args]), timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _entries() -> list[dict[str, Any]]:
    proc = _run(["export"], EXPORT_TIMEOUT)
    if proc is None or proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout or "[]")
    except ValueError:
        return []
    return [entry for entry in data if isinstance(entry, dict)] if isinstance(data, list) else []


def accounts() -> list[dict[str, Any]]:
    """Stored gateway accounts, newest data first: ``[{id, label, active}]``."""
    out: list[dict[str, Any]] = []
    for entry in _entries():
        if str(entry.get("integrationID", "")) != INTEGRATION:
            continue
        credential_id = str(entry.get("id") or "")
        if not credential_id:
            continue
        out.append(
            {
                "id": credential_id,
                "label": str(entry.get("label") or credential_id),
                "active": bool(entry.get("active")),
            }
        )
    return out


def switch(credential_id: str) -> bool:
    """Make one stored account the active one. True when the CLI accepted it."""
    if not credential_id:
        return False
    proc = _run(["switch", INTEGRATION, credential_id], SWITCH_TIMEOUT)
    return bool(proc is not None and proc.returncode == 0)
