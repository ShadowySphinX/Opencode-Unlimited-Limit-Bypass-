"""Optional Windows Defender Firewall kill-switch rules for opencode-cli."""

from __future__ import annotations

import sys

from ouc_common import (
    FW_RULE_PREFIX,
    find_opencode_cli,
    is_admin,
    run_hidden,
)

CLI_RULE_NAME = f"{FW_RULE_PREFIX}CLI"
_PUBLIC_RANGES = (
    "0.0.0.0-9.255.255.255,"
    "11.0.0.0-126.255.255.255,"
    "128.0.0.0-172.15.255.255,"
    "172.32.0.0-192.167.255.255,"
    "192.169.0.0-255.255.255.255,"
    "2000::/3"
)


def is_killswitch_installed() -> bool:
    """Return True if the OUC_LEAKGUARD_CLI firewall rule exists."""
    try:
        res = run_hidden(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={CLI_RULE_NAME}"],
            timeout=6.0,
        )
        return res.returncode == 0 and CLI_RULE_NAME in res.stdout
    except Exception:
        return False


def install_killswitch() -> tuple[bool, str]:
    """Install outbound non-loopback/non-LAN block rule for opencode-cli.exe."""
    if not is_admin():
        return False, "administrator privileges required for firewall kill-switch"

    cli = find_opencode_cli()
    if not cli or not cli.lower().endswith(".exe"):
        return False, "opencode-cli.exe not found (skipping program firewall rule)"

    remove_killswitch()
    res = run_hidden(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={CLI_RULE_NAME}",
            "dir=out",
            "action=block",
            f"program={cli}",
            f"remoteip={_PUBLIC_RANGES}",
            "profile=any",
            "enable=yes",
            "description=Opencode Unlimited: force opencode-cli through localhost zen-proxy/WARP",
        ],
        timeout=10.0,
    )
    if res.returncode == 0:
        return True, f"installed rule {CLI_RULE_NAME} for {cli}"
    return False, (res.stderr or res.stdout).strip() or "netsh failed"


def remove_killswitch() -> tuple[bool, str]:
    """Remove any OUC_LEAKGUARD firewall rules."""
    if not is_admin():
        return False, "administrator privileges required to remove firewall rules"
    run_hidden(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={CLI_RULE_NAME}"],
        timeout=8.0,
    )
    return True, f"removed rule {CLI_RULE_NAME}"


def main() -> int:
    action = sys.argv[1].lower() if len(sys.argv) > 1 else "status"
    if action == "install":
        ok, msg = install_killswitch()
    elif action == "remove":
        ok, msg = remove_killswitch()
    elif action == "status":
        ok = is_killswitch_installed()
        msg = "installed" if ok else "not installed"
    else:
        print("Usage: ouc_firewall.py [install|remove|status]", file=sys.stderr)
        return 2
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
