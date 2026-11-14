"""Clean Cloudflare WARP endpoint switcher for restricted countries."""

from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
from ouc_common import find_warp_cli, run_warp

KNOWN_CLEAN_ENDPOINTS = (
    "162.159.192.1:2408",  # Default Cloudflare Anycast (Primary)
    "162.159.192.2:2408",  # Anycast pool node 2
    "162.159.192.3:2408",  # Anycast pool node 3
    "162.159.192.4:2408",  # Anycast pool node 4
    "162.159.192.5:2408",  # Anycast pool node 5
    "162.159.193.1:2408",  # Clean pool 1 (common RU/IR/CN bypass)
    "162.159.193.2:2408",  # Clean pool 1 node 2
    "162.159.193.5:2408",  # Clean pool 2
    "162.159.193.9:2408",  # Clean pool 2 node 9
    "162.159.193.10:2408", # Clean pool 2 node 10
    "162.159.195.1:2408",  # Clean pool 3
    "162.159.195.2:2408",  # Clean pool 3 node 2
    "162.159.195.3:2408",  # Clean pool 3 node 3
    "162.159.195.4:2408",  # Clean pool 3 node 4
    "162.159.195.5:2408",  # Clean pool 3 node 5
    "188.114.96.1:2408",   # Cloudflare EU alternate 1
    "188.114.96.2:2408",   # Cloudflare EU alternate 1 node 2
    "188.114.96.3:2408",   # Cloudflare EU alternate 1 node 3
    "188.114.97.1:2408",   # Cloudflare EU alternate 2
    "188.114.97.2:2408",   # Cloudflare EU alternate 2 node 2
    "188.114.97.3:2408",   # Cloudflare EU alternate 2 node 3
    "188.114.98.1:2408",   # Cloudflare EU alternate 3
    "188.114.98.2:2408",   # Cloudflare EU alternate 3 node 2
    "188.114.98.3:2408",   # Cloudflare EU alternate 3 node 3
    "188.114.99.1:2408",   # Cloudflare EU alternate 4
    "188.114.99.2:2408",   # Cloudflare EU alternate 4 node 2
    "188.114.99.3:2408",   # Cloudflare EU alternate 4 node 3
)


def test_endpoint_latency(endpoint: str, timeout: float = 1.5) -> float | None:
    """Measure round-trip latency to a Cloudflare WireGuard endpoint in milliseconds."""
    host, _, _ = endpoint.rpartition(":")
    host = (host or endpoint).strip()
    is_win = platform.system().lower() == "windows"
    timeout_ms = max(500, int(timeout * 1000))
    cmd = (
        ["ping", "-n", "1", "-w", str(timeout_ms), host]
        if is_win
        else ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    )
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 0.5)
        if proc.returncode == 0:
            m = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", proc.stdout, re.IGNORECASE)
            if m:
                return round(float(m.group(1)), 1)
            return 1.0
    except Exception:
        pass

    # Fallback to TCP ping if ICMP is dropped by local policy
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, 80), timeout=timeout):
            return round((time.perf_counter() - t0) * 1000.0, 1)
    except Exception:
        return None


def set_custom_endpoint(endpoint: str) -> tuple[bool, str]:
    """Force Cloudflare WARP client to connect via a specific endpoint IP:PORT."""
    warp_bin = find_warp_cli()
    if not warp_bin:
        return False, "Cloudflare warp-cli.exe not found."

    # When setting custom endpoint (typically port 2408 WireGuard), switch protocol to WireGuard
    # to avoid MASQUE HTTP/3 TLS certificate mismatch (CF_HAPPY_EYEBALLS_MITM_FAILURE).
    run_warp(["tunnel", "protocol", "set", "WireGuard"], warp_bin=warp_bin)
    rc, msg = run_warp(["tunnel", "endpoint", "set", endpoint.strip()], warp_bin=warp_bin)
    if rc == 0:
        run_warp(["tunnel", "rotate-keys"], warp_bin=warp_bin)
        run_warp(["connect"], warp_bin=warp_bin)
        return True, f"Cloudflare WARP endpoint set to {endpoint} (WireGuard protocol)."
    return False, f"Failed to set endpoint: {msg}"


def reset_custom_endpoint() -> tuple[bool, str]:
    """Reset Cloudflare WARP endpoint to official default with WireGuard protocol."""
    warp_bin = find_warp_cli()
    if not warp_bin:
        return False, "Cloudflare warp-cli.exe not found."

    run_warp(["tunnel", "endpoint", "reset"], warp_bin=warp_bin)
    run_warp(["tunnel", "protocol", "set", "WireGuard"], warp_bin=warp_bin)
    run_warp(["tunnel", "rotate-keys"], warp_bin=warp_bin)
    run_warp(["connect"], warp_bin=warp_bin)
    return True, "Cloudflare WARP endpoint reset to official default (WireGuard protocol)."


def auto_heal_warp_endpoint(timeout: float = 1.0) -> tuple[bool, str]:
    """Benchmark clean endpoints concurrently and connect to the fastest available one."""
    from concurrent.futures import ThreadPoolExecutor

    results: list[tuple[float, str]] = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {
            executor.submit(test_endpoint_latency, ep, timeout): ep
            for ep in KNOWN_CLEAN_ENDPOINTS
        }
        for fut in future_map:
            ep = future_map[fut]
            try:
                lat = fut.result()
                if lat is not None:
                    results.append((lat, ep))
            except Exception:
                pass

    if not results:
        return False, "No responsive clean endpoints found."

    results.sort(key=lambda x: x[0])
    fastest_lat, fastest_ep = results[0]
    ok, msg = set_custom_endpoint(fastest_ep)
    if ok:
        return True, f"Auto-healed connection using {fastest_ep} ({fastest_lat}ms)"
    return False, msg
