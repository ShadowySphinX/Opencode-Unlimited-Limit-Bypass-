"""Clean Cloudflare WARP endpoint switcher for restricted countries."""

from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
from ouc_common import find_warp_cli, run_warp, warp_status

KNOWN_CLEAN_ENDPOINTS = (
    # Standard Cloudflare WireGuard (Port 2408)
    "162.159.192.1:2408",
    "162.159.192.2:2408",
    "162.159.193.1:2408",
    "162.159.193.5:2408",
    "162.159.195.1:2408",
    "188.114.96.1:2408",
    "188.114.97.1:2408",
    "188.114.98.1:2408",
    "188.114.99.1:2408",
    # Alternative Port 500 (IPsec IKE — universally unblocked by ISPs)
    "162.159.192.1:500",
    "162.159.193.1:500",
    "188.114.96.1:500",
    "188.114.97.1:500",
    # Alternative Port 4500 (IPsec NAT-T — bypasses UDP 2408 filtering)
    "162.159.192.1:4500",
    "162.159.193.1:4500",
    "188.114.96.1:4500",
    "188.114.97.1:4500",
    # Alternative Port 1701 (L2TP / Anycast bypass)
    "162.159.192.1:1701",
    "162.159.193.1:1701",
    # High-port Cloudflare WireGuard endpoints
    "162.159.192.1:854",
    "162.159.193.1:854",
    "162.159.192.1:880",
    "162.159.193.1:880",
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
        for _ in range(4):
            time.sleep(0.8)
            conn, _, raw = warp_status(warp_bin)
            raw_low = raw.lower()
            if conn and "unstable" not in raw_low and "unable" not in raw_low:
                return True, f"Cloudflare WARP endpoint connected to {endpoint} (WireGuard)."
        return True, f"Cloudflare WARP endpoint set to {endpoint} (handshake establishing...)."
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
