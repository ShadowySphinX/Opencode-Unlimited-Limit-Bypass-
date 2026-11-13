# Opencode-Unlimited-Limit-Bypass-

Automatic quota-wall rotator and multi-egress proxy router for **OpenCode Desktop** and **OpenCode CLI**.

![OpenCode Unlimited Multi-Egress Dashboard](assets/ui-preview.png)

OpenCode enforces free-tier message limits based on your inbound IP address (`/64` prefix on IPv6, `/32` on IPv4) and Cloudflare edge affinity. **Opencode Unlimited** monitors OpenCode logs in real time, automatically intercepts `QuotaExceeded` rate limits, and cycles your identity (fresh IPv6 `/64`, Tor circuit, or proxy pool node) so you can continue generating without waiting for hourly limit resets.

---

## What's New in v2.3.0+ (Multi-Egress Edition)

* **Multi-Proxy Pool & Automatic Round-Robin Cycling:** Custom Proxy mode now supports pasting entire pools of SOCKS5/HTTP proxies (comma, semicolon, or newline separated). When an IP hits a rate wall, ZenGuard automatically rotates to the next node in the pool.
* **App-Only (Isolated Mode) by Default:** Only OpenCode's traffic routes through WARP/Tor/Proxy (`127.0.0.1:40000`). The rest of your PC (Discord, Steam, competitive games, browsers) runs on your direct home internet with zero lag spikes and zero network drops during rotations.
* **Full System TUN Mode Toggle:** One-click toggle retained for users who explicitly want their entire Windows system routed through the Cloudflare VPN.
* **Full OpenCode 2.3.0+ Compatibility:** Recursively auto-detects internal and external CLI binaries across version folders (`cli\2.3.0-x64\opencode-cli.exe`), desktop apps, and custom drive installations.
* **Direct JSON Proxy Configuration:** Modifies `~/.config/opencode/service.json` directly in Python without requiring CLI shims. Eliminates `"opencode-cli.exe not found"` and `ECONNREFUSED` connection errors.
* **Expanded Anycast Edge Pool (35 Verified Nodes):** Rotates across 35 live Cloudflare edge VIPs (`2606:4700::...`), increasing prompts per `/64` before an interface re-roll is needed.
* **Expanded Clean WireGuard Endpoints (27 Endpoints):** Built-in parallel latency tester (0.14s) across 27 verified clean endpoints (`162.159.192.x`–`195.x`, `188.114.96.x`–`99.x`) to bypass ISP WireGuard throttling (Russia, Iran, China, university/corporate networks).
* **Tor Control Port `SIGNAL NEWNYM`:** Instant sub-second exit node rotation via Tor control port (`9051`/`9151`) alongside automatic portable Tor daemon management.
* **Duplicate Process Guard:** Automatically terminates orphaned background workers on startup to prevent port `41987` binding collisions.

---

## Executables & Editions

| Executable | Routing Modes | Recommended For |
| :--- | :--- | :--- |
| **`OpencodeUnlimited-Multi.exe`** | **WARP (Isolated & TUN)**, **Tor Network**, **Custom Proxy Pool**, **Clean Endpoints** | All users. Features live mode switcher, app-only isolation, multi-proxy pool auto-cycling, and expanded node pools. |
| **`OpencodeUnlimited-Avatar.exe`** | Cloudflare WARP /64 rotator & fail-closed lane | Classic single-purpose binary for standard WARP setups. |

---

## How It Works Under the Hood

```
[ OpenCode Desktop / CLI ]
            │
            ▼ (HTTP / HTTPS via service.json)
   [ 127.0.0.1:41987 (Zen Proxy) ]
            │
   ─────────┴───────────────────────────────────────────────────────
   │ Mode Selection & Automated Fail-Closed Guard                 │
   ─────────────────────────────────────────────────────────────────
   ├── [1] WARP (Isolated Mode)    ──> 127.0.0.1:40000 (SOCKS5)    ──> Cloudflare Edge [2a09:... /64]
   ├── [2] WARP (Full TUN Mode)    ──> Virtual Adapter (Wintun)    ──> Whole-PC Cloudflare VPN
   ├── [3] Tor Network (Isolated)  ──> 127.0.0.1:9050 / 9150       ──> Tor 3-Hop Exit Node (IPv4)
   ├── [4] Custom Proxy Pool       ──> Node #1 -> Node #2 -> ...   ──> Multi-Proxy Round-Robin
   └── [5] Clean Endpoint          ──> WireGuard Clean IP:2408     ──> Cloudflare Core Backbone
```

* **Zen Guard (Background Watchdog):** Continuously tails `~/.local/share/opencode/log/opencode.log`. The instant `QuotaExceeded` or `"Free usage limit reached"` appears, it blacklists the burnt IP and triggers rotation automatically.
* **WARP Keeper (Proxy Host):** Keeps the local proxy on port `41987` alive and ensures the upstream route is healthy.

---

## Supported Egress Methods & Setup Guide

### 1. Cloudflare WARP (Recommended)
* **What it does:** Uses Cloudflare WARP to assign a unique `/64` IPv6 block per session.
* **App-Only (Isolated) Mode:** Sets WARP CLI to SOCKS5 proxy mode on `127.0.0.1:40000`. Only OpenCode traffic routes through WARP; your games, Discord, and streaming never drop or lag.
* **Full System TUN Mode:** Sets WARP to standard VPN mode where all system traffic goes through WARP.
* **How to use:**
  1. Install [Cloudflare WARP](https://one.one.one.one/).
  2. Select **⚡ WARP (IPv6)** tab in `OpencodeUnlimited-Multi.exe`.
  3. Choose **🎯 App-Only (Isolated)**.
  4. Click **⚡ Clean Hop** to test an instant rotation.

### 2. Tor Network Subsystem
* **What it does:** Routes requests through the decentralized Tor network, giving you a fresh public IPv4 exit relay on every rotation.
* **How to use:**
  1. Select **🧅 Tor Network** tab in `OpencodeUnlimited-Multi.exe`.
  2. If you don't have Tor Browser running, click **Start Portable Tor** (the app downloads and runs an isolated portable Tor daemon automatically).
  3. When limit is reached, Tor issues `SIGNAL NEWNYM` to control port `9051`, giving you a brand new identity in under 1 second.

### 3. Custom Multi-Proxy Pool
* **What it does:** Allows you to input one or more external HTTP or SOCKS5 proxies. Supports automatic round-robin cycling when limits are reached.
* **Format supported:** Enter single or multiple proxies separated by commas, semicolons, or newlines:
  ```text
  127.0.0.1:10808
  socks5://user:pass@proxy1.com:1080
  http://proxy2.com:8080
  ```
* **How to use:**
  1. Select **🌐 Custom Proxy** tab in `OpencodeUnlimited-Multi.exe`.
  2. Paste your proxy list into the text area.
  3. Select protocol (**SOCKS5** or **HTTP**).
  4. Click **Apply & Route**.
  5. The UI shows the active node count and index (e.g. `Active Node: #1/5 (proxy1.com:1080)`).
  6. Click **🔄 Next Node** to cycle manually, or let ZenGuard cycle automatically on quota hit.

### 4. Clean WireGuard Endpoints
* **What it does:** In regions where default Cloudflare endpoints are blocked or throttled by ISPs (Russia, Iran, China, school/enterprise firewalls), this connects directly to unblocked IP ranges.
* **How to use:**
  1. Select **🛡️ Clean Endpoint** tab.
  2. Click **⚡ Ping Test** (parallel test completes in 0.14 seconds).
  3. Select the endpoint with the lowest latency.
  4. Click **Apply Endpoint**.

---

## How Usage Limits Reset per Mode

| Method | What Cloudflare Sees | Reset Mechanism | Tested Time |
| :--- | :--- | :--- | :---: |
| **WARP (Isolated)** | Cloudflare IPv6 `/64` prefix | Re-registers client on port 40000; Cloudflare assigns a new `/64` block. Normal PC traffic is not interrupted. | ~10–12s |
| **WARP (Full TUN)** | Cloudflare IPv6 `/64` prefix | Re-registers client on virtual adapter; assigns a new `/64` block across the full system. | ~10–12s |
| **Tor Network** | Global Tor Exit Node IP | Sends `SIGNAL NEWNYM` to Tor control port; establishes a fresh 3-hop circuit with a new exit IP. | < 1s |
| **Custom Proxy Pool** | Proxy Server Public IP | Cycles round-robin to the next proxy server in your pool. | Instant (0s) |
| **Clean Endpoint** | Clean WireGuard IP + `/64` | Re-registers WireGuard keys through an unblocked endpoint to assign a fresh `/64`. | ~10–12s |

---

## Quick Setup (Windows)

### 1. Requirements
* Windows 10 or Windows 11 (64-bit)
* [OpenCode](https://opencode.ai) installed (Desktop or CLI)
* [Cloudflare WARP (1.1.1.1)](https://one.one.one.one/) (required for WARP modes; optional if using Tor or Custom Proxy)
* [Microsoft Edge WebView2 Runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703) (preinstalled on stock Windows 10/11)
* *No Python installation required when running the standalone `.exe`.*

### 2. Running the App
1. Launch **`OpencodeUnlimited-Multi.exe`**.
2. Click **Install / Repair System** at the bottom left (wires proxy entries, background watchdogs, and PATH entries).
3. Select your preferred egress mode on the top bar:
   * **⚡ WARP (IPv6):** Click **App-Only (Isolated)** so your games and Discord stay on normal internet.
   * **🧅 Tor Network:** Click **Start Tor Daemon** or use Tor Browser.
   * **🌐 Custom Proxy:** Paste your proxy or proxy pool and click **Apply & Route**.
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
# Build multi-egress release (recommended):
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
