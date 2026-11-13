"""Zen Lane for Windows: launches opencode through an ephemeral WARP IPv6-pinned proxy."""

from __future__ import annotations

import os
import subprocess
import sys
import time

from ouc_common import (
    find_opencode_cli,
    find_opencode_desktop,
    find_warp_cli,
    get_warp_local_v6,
    run_warp,
)
from zen_proxy import start_proxy_server

_NO_STANDALONE_CMDS = {
    "service",
    "upgrade",
    "update",
    "uninstall",
    "debug",
}
_INFO_FLAGS = {"--help", "-h", "--version", "-v", "--completions"}


def _needs_tunnel(args: list[str]) -> bool:
    if any(a in _INFO_FLAGS or a.startswith("--completions=") for a in args):
        return False
    for a in args:
        if not a.startswith("-"):
            return a not in _NO_STANDALONE_CMDS
    return True


def _should_add_standalone(args: list[str]) -> bool:
    if any(
        a in ("--standalone", "--server") or a.startswith("--server=")
        for a in args
    ):
        return False
    return _needs_tunnel(args)


def _ensure_warp_up() -> str | None:
    v6 = get_warp_local_v6()
    if v6:
        return v6

    warp = find_warp_cli()
    if not warp:
        return None

    run_warp(["mode", "warp"], warp_bin=warp)
    run_warp(["connect"], warp_bin=warp)
    for _ in range(10):
        time.sleep(1.0)
        v6 = get_warp_local_v6()
        if v6:
            return v6
    return None


def main() -> int:
    args = sys.argv[1:]

    desktop_mode = False
    if args and args[0] == "--ouc-desktop":
        desktop_mode = True
        args = args[1:]

    if desktop_mode:
        target = find_opencode_desktop()
        if not target:
            print("OpenCode.exe desktop app not found.", file=sys.stderr)
            return 1
    else:
        target = find_opencode_cli()
        if not target:
            print(
                "opencode CLI binary not found — set OUC_REAL_BIN or reinstall OpenCode.",
                file=sys.stderr,
            )
            return 1

    if not _needs_tunnel(args) and not desktop_mode:
        cmd = [target, *args]
        if target.lower().endswith((".cmd", ".bat")):
            cmd = [os.environ.get("COMSPEC", "cmd.exe"), "/c", *cmd]
        return subprocess.run(cmd).returncode

    if not _ensure_warp_up():
        print(
            "[zen-lane] Cloudflare WARP IPv6 tunnel is not up (fail-closed: blocking direct egress).\n"
            "Run: opencode-unlimited-doctor  or  opencode-unlimited-hop",
            file=sys.stderr,
        )
        return 1

    srv, port, _edge = start_proxy_server(0)
    proxy_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env["HTTPS_PROXY"] = proxy_url
    env["HTTP_PROXY"] = proxy_url
    env["https_proxy"] = proxy_url
    env["http_proxy"] = proxy_url
    env["NO_PROXY"] = "127.0.0.1,localhost,::1"
    env["no_proxy"] = "127.0.0.1,localhost,::1"

    launch_args = list(args)
    if desktop_mode:
        launch_args = [f"--proxy-server={proxy_url}", *launch_args]
    elif _should_add_standalone(launch_args):
        launch_args = ["--standalone", *launch_args]

    cmd = [target, *launch_args]
    if target.lower().endswith((".cmd", ".bat")):
        cmd = [os.environ.get("COMSPEC", "cmd.exe"), "/c", *cmd]

    try:
        proc = subprocess.run(cmd, env=env)
        return proc.returncode
    except KeyboardInterrupt:
        return 130
    finally:
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
