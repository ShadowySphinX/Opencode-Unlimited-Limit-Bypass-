# PLEASE GIVE PROPER CREDITS. JUST DONT REBRAND AND LAUNCH IT AS YOURS.
# Opencode-Unlimited-Limit-Bypass

Automatic rate-limit rotator and multi-egress proxy router for OpenCode Desktop and OpenCode CLI.

![OpenCode Unlimited Dashboard](assets/ui-preview.png)

OpenCode enforces free-tier message limits based on your inbound IP address (`/64` prefix on IPv6, `/32` on IPv4) and Cloudflare edge affinity. This tool monitors OpenCode logs in real time, catches `QuotaExceeded` rate limit errors as soon as they are logged, and automatically cycles your identity (fresh IPv6 `/64`, Tor circuit, or proxy pool node) so you can keep working without waiting for limit resets.

---

## What's New in v2.3.0

* **Auto-Resume & Walk-Away Automation:** When OpenCode hits a rate limit and rotates your identity, Zen Guard automatically sends `continue` to your running session (via CLI session tracking and keystroke injection). You can start long tasks, walk away from your PC, and the model continues uninterrupted.
* **Multi-Proxy Pool & Round-Robin Cycling:** Custom Proxy mode now supports full proxy pools (comma, semicolon, or newline separated). When an IP hits a rate wall, the background watcher immediately switches to the next node in the pool.
* **App-Only (Isolated Mode) by Default:** Only OpenCode traffic routes through the local proxy (`127.0.0.1:40000`). Games, Discord, browsers, and other apps run on your direct internet connection without latency spikes or drops during IP rotations.
* **Full System TUN Mode Toggle:** An option remains to route the entire operating system through Cloudflare WARP for users who need system-wide routing.
* **OpenCode 2.3.0+ Compatibility:** Recursively auto-detects CLI binaries across versioned directories (`cli\2.3.0-x64\opencode-cli.exe`), desktop installations, and custom paths.
* **Direct JSON Configuration:** Writes proxy settings directly to `~/.config/opencode/service.json` in Python. Resolves `"opencode-cli.exe not found"` and `ECONNREFUSED` connection errors.
* **Expanded Anycast Edge Pool (35 Verified Nodes):** Rotates across 35 live Cloudflare edge VIPs (`2606:4700::...`) to prevent early rate limiting on single edge nodes.
* **Clean WireGuard Endpoints (27 Endpoints):** Built-in parallel latency tester (0.14s) across 27 verified endpoints (`162.159.192.x`–`195.x`, `188.114.96.x`–`99.x`) to bypass ISP WireGuard blocks in restricted regions.
* **Tor Subsystem with Control Port Support:** Sub-second exit node rotation via Tor control port (`SIGNAL NEWNYM` on `9051`/`9151`) with automatic portable Tor daemon management.
* **Linux Support:** Added headless installer (`install.sh`) supporting Debian, Ubuntu, Fedora, Arch, NixOS, and openSUSE.

---

## How It Works

```
[ OpenCode Desktop / CLI ]
            │
            ▼ (HTTP / HTTPS via service.json)
   [ 127.0.0.1:41987 (Zen Proxy) ]
            │
   ─────────┴───────────────────────────────────────────────────────
   │ Mode Selection & Fail-Closed Routing                          │
   ─────────────────────────────────────────────────────────────────
   ├── [1] WARP (Isolated Mode)    ──> 127.0.0.1:40000 (SOCKS5)    ──> Cloudflare Edge [2a09:... /64]
   ├── [2] WARP (Full TUN Mode)    ──> Virtual Adapter (Wintun)    ──> System-wide Cloudflare VPN
   ├── [3] Tor Network             ──> 127.0.0.1:9050 / 9150       ──> Tor 3-Hop Circuit
   ├── [4] Custom Proxy Pool       ──> Node #1 -> Node #2 -> ...   ──> Round-Robin Upstream
   └── [5] Clean Endpoint          ──> WireGuard Clean IP:2408     ──> Cloudflare Edge
```

* **Zen Guard:** Tails `~/.local/share/opencode/log/opencode.log`. When `AI.Error.QuotaExceeded` or `"Free usage limit reached"` appears, it blacklists the current IP and triggers identity rotation.
* **WARP Keeper:** Maintains the local listener on port `41987` and ensures upstream routes remain healthy.

---

## Supported Routing Modes

### 1. Cloudflare WARP
* Uses Cloudflare WARP to assign a new `/64` IPv6 prefix per session.
* **App-Only (Isolated) Mode:** Sets WARP CLI to proxy mode on `127.0.0.1:40000`. Only OpenCode uses WARP. Your normal network traffic is untouched.
* **Full System TUN Mode:** Standard VPN mode routing all system connections through WARP.
* **Usage:**
  1. Install [Cloudflare WARP](https://one.one.one.one/).
  2. Select the **WARP (IPv6)** tab.
  3. Select **App Only (Isolated)**.
  4. Use **Rotate /64 Now (Hop)** to test rotation.

### 2. Tor Network Subsystem
* Routes requests through the Tor network, assigning a new public IPv4 exit IP on each rotation.
* **Usage:**
  1. Select the **Tor Network** tab.
  2. Click **Start Portable Tor** (the app downloads and runs an isolated portable Tor daemon automatically if Tor is not already running).
  3. On rate limits, a `SIGNAL NEWNYM` command is sent to control port `9051`, rotating the circuit in under 1 second.

### 3. Custom Multi-Proxy Pool
* Supports one or more external HTTP or SOCKS5 proxies with automatic round-robin cycling on quota limits.
* **Input format:** Delimit proxies by commas, semicolons, or newlines:
  ```text
  127.0.0.1:10808
  socks5://user:pass@proxy1.com:1080
  http://proxy2.com:8080
  ```
* **Usage:**
  1. Select the **Custom Proxy** tab.
  2. Paste your proxy list into the input box.
  3. Choose protocol (**SOCKS5** or **HTTP**).
  4. Click **Apply & Route**.
  5. The interface displays the active node index and total pool size (e.g. `Active Node: #1/3`).
  6. Click **Next Node** to cycle manually, or let Zen Guard rotate automatically on rate limits.

### 4. Clean WireGuard Endpoints
* In regions where default Cloudflare endpoints are filtered or throttled by ISPs, this routes traffic through verified unblocked IP ranges.
* **Usage:**
  1. Select the **Clean Endpoint** tab.
  2. Click **Ping Test** to benchmark latency across the 27 endpoints.
  3. Select the lowest-latency endpoint.
  4. Click **Apply Endpoint**.

---

## Limit Reset Comparison

| Method | Public Identifier | Reset Mechanism | Typical Duration |
| :--- | :--- | :--- | :---: |
| **WARP (Isolated)** | Cloudflare IPv6 `/64` | Rotates SOCKS5 client on port 40000; assigns new `/64` prefix. No impact on system apps. | ~10–12s |
| **WARP (Full TUN)** | Cloudflare IPv6 `/64` | Re-registers client on virtual adapter; assigns new `/64` across the OS. | ~10–12s |
| **Tor Network** | Tor Exit Node IPv4 | Sends `SIGNAL NEWNYM` to control port; builds fresh 3-hop circuit. | < 1s |
| **Custom Proxy Pool** | Proxy Server Public IP | Advances to the next proxy node in the pool. | Instant |
| **Clean Endpoint** | Clean WireGuard IP + `/64` | Re-keys WireGuard through an unblocked endpoint to assign fresh `/64`. | ~10–12s |

---

## Setup (Windows)

### Requirements
* Windows 10 or Windows 11 (64-bit)
* [OpenCode](https://opencode.ai) (Desktop or CLI)
* [Cloudflare WARP (1.1.1.1)](https://one.one.one.one/) (required for WARP modes; optional for Tor and Custom Proxy)
* [Microsoft Edge WebView2 Runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703) (included by default on Windows 10/11)
* Python is not required when using the standalone binary.

### Quick Start
1. Run `OpencodeUnlimited-Multi.exe`.
2. Click **Install / Repair System** at the bottom left to initialize proxy paths and background services.
3. Choose your routing mode from the top bar:
   * **WARP (IPv6):** Click **App Only (Isolated)**.
   * **Tor Network:** Click **Start Portable Tor**.
   * **Custom Proxy:** Enter your proxy or proxy list and click **Apply & Route**.
   * **Clean Endpoint:** Click **Ping Test**, pick the fastest endpoint, and click **Apply Endpoint**.
4. Verify the switches on the left panel:
   * **WARP Keeper:** ON
   * **Zen Guard:** ON
   * **Desktop App Proxy:** ON
5. Launch OpenCode Desktop or run `opencode` in your terminal.

---

## Setup (Linux)

Run the automated installer:
```bash
bash install.sh
```
Compatible with Debian, Ubuntu, Fedora, Arch Linux, NixOS, and openSUSE. Configures the background services via systemd user units.

---

## Building from Source

```bash
git clone https://github.com/ShadowySphinX/Opencode-Unlimited-Limit-Bypass.git
cd Opencode-Unlimited-Limit-Bypass
pip install -r requirements.txt
```

To compile the standalone Windows binary:
```powershell
powershell -ExecutionPolicy Bypass -File .\build_multi_exe.ps1
```

---

## Troubleshooting

* **`ECONNREFUSED: Unable to connect. Is the computer able to access the url?`**
  * **Cause:** OpenCode has its proxy configured to `127.0.0.1:41987`, but `OpencodeUnlimited-Multi.exe` is not running.
  * **Fix:** Open `OpencodeUnlimited-Multi.exe` before using OpenCode. To run OpenCode directly without a proxy, toggle off **Desktop App Proxy** in the app.
* **`opencode-cli.exe not found`**
  * **Cause:** OpenCode CLI is installed in a versioned subfolder.
  * **Fix:** `OpencodeUnlimited-Multi.exe` scans `%APPDATA%\ai.opencode.desktop\cli\*\opencode-cli.exe` (including `2.3.0-x64`) and configures `service.json` directly.
* **Game latency or voice chat disconnects during rotation:**
  * **Cause:** WARP is running in Full System TUN mode.
  * **Fix:** Switch the WARP Scope in the interface to **App Only (Isolated)**.
* **WARP stuck on "VERIFYING IPv6" / `CERT_NOT_YET_VALID`:**
  * **Cause:** System clock drift.
  * **Fix:** Windows Settings -> **Time & Language** -> **Date & Time** -> click **Sync now**.
* **Blank or black window on launch:**
  * **Cause:** Missing Microsoft Edge WebView2 Evergreen Runtime.
  * **Fix:** Install the [WebView2 Runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703).
* **Cloudflare WARP shows `Connection blocked: CF_HAPPY_EYEBALLS_MITM_FAILURE`:**
  * **Cause:** Stale WARP encryption keys or MASQUE/WireGuard protocol handshake mismatch from custom endpoints.
  * **Fix:** The app self-heals this automatically on launch with zero clicks. You can also click **⚡ Fix WARP (Reset Keys)** at the top of the dashboard to instantly rotate your cryptographic keys and restore healthy status.

---

## License

MIT License.
