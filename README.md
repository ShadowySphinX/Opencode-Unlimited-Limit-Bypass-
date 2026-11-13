# Opencode-Unlimited-Limit-Bypass-

Automatic quota-wall rotator and multi-egress proxy router for **OpenCode Desktop** and **OpenCode CLI**.

OpenCode enforces free-tier message limits based on your inbound IP address (`/64` prefix on IPv6, `/32` on IPv4) and Cloudflare edge affinity. **Opencode Unlimited** monitors OpenCode logs in the background, automatically catches `QuotaExceeded` rate limits, and cycles your identity (fresh IPv6 `/64`, Tor circuit, or clean WireGuard endpoint) in ~12 seconds so you can continue generating without waiting for hourly limit resets.

---

## What's New in v2.3.0+ & Multi-Egress Edition

* **Full OpenCode 2.3.0+ Compatibility:** Recursively auto-detects internal and external CLI binaries across version folders (`cli\2.3.0-x64\opencode-cli.exe`), desktop apps, and custom drive installations.
* **Direct JSON Proxy Configuration:** Modifies `~/.config/opencode/service.json` directly in Python without requiring CLI shims. Eliminates `"opencode-cli.exe not found"` and `ECONNREFUSED` connection errors.
* **App-Only (Isolated Mode) by Default:** Only OpenCode's traffic routes through WARP/Tor/Proxy. The rest of your PC (Discord, Steam, online games, browsers) runs on your direct home internet. Zero game lag and zero PC network drops during IP rotation.
* **Full System TUN Mode Toggle:** One-click toggle retained for users who explicitly want their entire Windows system routed through the Cloudflare VPN.
* **Expanded Anycast Edge Pool (35 Verified Nodes):** Rotates across 35 live Cloudflare edge VIPs (`2606:4700::...`), increasing prompts per `/64` before an interface re-roll is needed.
* **Expanded Clean WireGuard Endpoints (27 Endpoints):** Built-in parallel latency tester (0.14s) across 27 verified clean endpoints (`162.159.192.x`–`195.x`, `188.114.96.x`–`99.x`) to bypass ISP WireGuard throttling (Russia, Iran, China, university/corporate networks).
* **Tor Control Port `SIGNAL NEWNYM`:** Instant sub-second exit node rotation via Tor control port (`9051`/`9151`) alongside automatic portable Tor daemon management.
* **Duplicate Process Guard:** Automatically terminates orphaned background workers on startup to prevent port `41987` binding collisions.

---

## Executables & Editions

| Executable | Routing Modes | Recommended For |
| :--- | :--- | :--- |
| **`OpencodeUnlimited-Multi.exe`** | **WARP (Isolated & TUN)**, **Tor Network**, **Custom Proxies**, **Clean Endpoints** | All users. Features live mode switcher, app-only isolation, and expanded node pools. |
| **`OpencodeUnlimited-Avatar.exe`** | Cloudflare WARP /64 rotator & fail-closed lane | Classic single-purpose binary for standard WARP setups. |

---

## How It Works Under the Hood

```
[ OpenCode Desktop / CLI ]
            │
            ▼ (HTTP / HTTPS)
   [ 127.0.0.1:41987 (Zen Proxy) ]
            │
   ─────────┴─────────────────────────────────────────────
   │ Mode Selection & Automated Fail-Closed Guard       │
   ───────────────────────────────────────────────────────
   ├── [1] WARP (Isolated Mode)   ──> 127.0.0.1:40000 (SOCKS5)  ──> Cloudflare Edge [2a09:... /64]
   ├── [2] WARP (Full TUN Mode)   ──> Virtual Adapter (Wintun)  ──> Whole-PC Cloudflare VPN
   ├── [3] Tor Network (Isolated) ──> 127.0.0.1:9050 / 9150     ──> Tor 3-Hop Exit Node
   ├── [4] Custom Proxy (Isolated)──> Clash / v2rayN / SOCKS5   ──> User Proxy Node
   └── [5] Clean Endpoint         ──> WireGuard Clean IP:2408   ──> Cloudflare Core Backbone
```

* **Zen Guard (Background Watchdog):** Polls `opencode.log` every 10 seconds. When `QuotaExceeded` or `"Free usage limit reached"` appears, it blacklists the current IP and rotates your identity automatically.
* **WARP Keeper (Proxy Host):** Keeps the local proxy on port `41987` alive and ensures the upstream route is healthy.

---

## How Usage Limits Reset per Mode

| Method | What Cloudflare Sees | Reset Mechanism | Tested Time |
| :--- | :--- | :--- | :---: |
| **WARP (Isolated)** | Cloudflare IPv6 `/64` prefix | Re-registers client on port 40000; Cloudflare assigns a new `/64` block. Normal PC traffic is not interrupted. | ~12s |
| **WARP (Full TUN)** | Cloudflare IPv6 `/64` prefix | Re-registers client on virtual adapter; assigns a new `/64` block across the full system. | ~12s |
| **Tor Network** | Global Tor Exit Node IP | Sends `SIGNAL NEWNYM` to Tor control port; establishes a fresh 3-hop circuit with a new exit IP. | ~1s |
| **Clean Endpoint** | Clean WireGuard IP + `/64` | Re-registers WireGuard keys through an unblocked endpoint to assign a fresh `/64`. | ~12s |
| **Custom Proxy** | Rotating residential / DC proxy | Outbound traffic cycles to the next proxy node in your pool. | Instant |

---

## Quick Setup (Windows)

### 1. Requirements
* Windows 10 or Windows 11 (64-bit)
* [OpenCode](https://opencode.ai) installed (Desktop or CLI)
* [Cloudflare WARP (1.1.1.1)](https://one.one.one.one/) (required for WARP modes; optional if using Tor or Custom Proxy)
* [Microsoft Edge WebView2 Runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703) (preinstalled on stock Windows 10/11; needed for lite/custom ISOs)
* *No Python installation required when running the `.exe`.*

### 2. Running the App
1. Launch **`OpencodeUnlimited-Multi.exe`**.
2. Click **Install / Repair System** at the bottom left (wires proxy entries, background watchdogs, and PATH entries).
3. Select your preferred egress mode on the top bar:
   * **⚡ WARP (IPv6):** Click **App-Only (Isolated)** so your games and Discord stay on normal internet.
   * **🧅 Tor Network:** Click **Start Tor Daemon** or use Tor Browser.
   * **🌐 Custom Proxy:** Enter your local proxy port (e.g. `127.0.0.1:10808`) and click **Apply & Route**.
   * **🛡️ Clean Endpoint:** Click **⚡ Ping Test**, select the lowest-latency endpoint, and click **Apply Endpoint**.
4. Confirm the control switches:
   * **WARP Keeper** $\rightarrow$ ON
   * **Zen Guard** $\rightarrow$ ON
   * **Desktop App Proxy** $\rightarrow$ ON
5. Click **Launch OpenCode Desktop** or open your terminal and run `opencode`.

---

## Running from Source / Building the Executables

### Setup Environment
```bash
git clone https://github.com/ShadowySphinX/Opencode-Unlimited-Limit-Bypass-.git
cd Opencode-Unlimited-Limit-Bypass-
pip install -r requirements.txt
```

### Build Standalone Executables
```powershell
# Build multi-egress release:
powershell -ExecutionPolicy Bypass -File .\build_multi_exe.ps1

# Build original Avatar release:
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
```

### Linux / WSL2 Headless Setup
```bash
bash install.sh
```
Compatible with Debian/Ubuntu (`apt`), Fedora (`dnf`), Arch (`pacman`), NixOS (`nix`), and openSUSE (`zypper`).

---

## Troubleshooting

* **`ECONNREFUSED: Unable to connect. Is the computer able to access the url?`**
  * **Cause:** OpenCode has `HTTPS_PROXY` set in `service.json`, but `OpencodeUnlimited` was closed, leaving port `41987` unbound.
  * **Fix:** Open `OpencodeUnlimited-Multi.exe` before using OpenCode. If you want to use OpenCode directly without any proxy, toggle off **Desktop App Proxy** in the app.
* **`opencode-cli.exe not found`**
  * **Cause:** Older versions looked only in fixed folders.
  * **Fix:** `OpencodeUnlimited-Multi.exe` automatically searches `%APPDATA%\ai.opencode.desktop\cli\*\opencode-cli.exe` (including `2.3.0-x64`) and configures `service.json` directly.
* **Game latency or Discord disconnects during IP rotation:**
  * **Cause:** Cloudflare WARP was running in Full System TUN mode.
  * **Fix:** Switch the WARP Scope in the UI to **🎯 App-Only (Isolated)**. Only OpenCode will route through the tunnel; gaming and streaming remain on direct home internet.
* **WARP stuck on "VERIFYING IPv6" / `CERT_NOT_YET_VALID`:**
  * **Cause:** Windows system clock is desynchronized.
  * **Fix:** Open Windows Settings $\rightarrow$ **Time & Language** $\rightarrow$ **Date & Time** $\rightarrow$ click **"Sync now"**.
* **App opens to a blank or black window:**
  * **Cause:** Missing Microsoft Edge WebView2 Evergreen Runtime.
  * **Fix:** Install the official [Microsoft Edge WebView2 Runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703).

---

## License

MIT License. Designed for automated quota management, fail-closed privacy, and multi-protocol network routing.
