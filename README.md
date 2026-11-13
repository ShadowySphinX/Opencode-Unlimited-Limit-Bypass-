# Opencode-Unlimited-Limit-Bypass-

What it actually does - OpenCode's free limit tracks your IPv6 /64 block and which Cloudflare edge you hit. Opencode Unlimited puts traffic through WARP IPv6, picks random Cloudflare edges, watches `opencode.log` in the background, and automatically grabs a fresh WARP /64 in ~12 seconds when a limit hits. If WARP drops, it fails closed so your real IP doesn't leak.

---

## Requirements

### For Windows App (`OpencodeUnlimited-Avatar.exe`)
- **OS:** Windows 10 or Windows 11 (64-bit)
- **OpenCode:** Official OpenCode Desktop app or OpenCode CLI
- **Cloudflare WARP:** [Cloudflare WARP (1.1.1.1)](https://one.one.one.one/) installed and registered
- **WebView2:** [Microsoft Edge WebView2 Runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703) (preinstalled on standard Windows 10/11; required for debloated/lite Windows editions)
- *Note:* Python is **NOT required** if you are running the prebuilt `OpencodeUnlimited-Avatar.exe`.

### For Running / Building From Source (Python)
- **Python:** 3.8 to 3.12 (64-bit)
- Install Python dependencies:
  ```bash
  pip install -r requirements.txt
  ```
- Build the standalone executable anytime:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
  ```

### For Linux / WSL2 Users
- Linux x86_64 (native or WSL2)
- systemd & python3
- `sudo` privileges for initial systemd unit registration

---

## How to set it up

### 1. Make sure you have OpenCode & Cloudflare WARP
If you already have OpenCode and Cloudflare WARP (1.1.1.1) installed, you're good. If not:
- Download OpenCode: [opencode.ai](https://opencode.ai)
- Download Cloudflare WARP: [1.1.1.1](https://one.one.one.one/)

### 2. Open the app
1. Run `OpencodeUnlimited-Avatar.exe`.
2. Click **Install / Repair System** at the bottom left.
3. Give it a few seconds. It sets up the background tasks (WARP Keeper + Zen Guard), connects WARP in TUN mode, wires the OpenCode Desktop daemon, and sets up `opencode` in your system `PATH`.
4. *(Optional - not needed if everything works)* If you want the Windows Firewall rule that forces `opencode-cli.exe` to never touch your direct internet, toggle **Firewall Kill-Switch** on and accept the Windows UAC prompt.

### 3. Check that everything is green
- Top right badge should say `PROTECTED • WARP IPv6`.
- Public WARP /64 card should show `CF Verified`.
- **WARP Keeper**, **Zen Guard**, and **Desktop App Proxy** switches should all be **ON**.

---

## Daily use (how to actually run OpenCode)

- **Using the Desktop app:** Click **Launch OpenCode Desktop** in the app (your old chats and projects stay right where they are).
- **Using CLI:** Click **Launch OpenCode CLI**, or open any new terminal and type `opencode`.

### If you hit "Free usage limit reached":
1. Don't close anything. *(If it doesn't work while OpenCode is opened, close OpenCode and then try it).*
2. Wait ~10-15 seconds. Zen Guard catches the error in `opencode.log` and rotates WARP automatically - you'll see the top badge switch to `ROTATING /64...`.
3. Re-send your message.

### Want a new IP/edge manually anytime?
Hit **Rotate /64 Now (Hop)** or **Re-roll** on the Pinned Edge card.

---

## Troubleshooting

- **App opens to a blank / black screen:**
  Your Windows installation is missing the Microsoft Edge WebView2 Evergreen Runtime (common on stripped/custom Windows like AtlasOS, ReviOS, or LTSC).
  Download and install the official runtime: [Microsoft Edge WebView2 Installer](https://go.microsoft.com/fwlink/p/?LinkId=2124703), then re-open the app.
- **Can't connect to internet without the VPN:**
  If you turned on **Firewall Kill-Switch**, Windows blocks `opencode-cli.exe` unless it's routing through the local proxy. You can toggle the Firewall Kill-Switch **OFF** in the app, or use `btnWarpToggle` / disconnect in the UI.
- **Verify health from terminal:**
  You can run a diagnostic health check anytime:
  ```powershell
  .\OpencodeUnlimited-Avatar.exe --doctor
  ```

---

## License
MIT License. Built for seamless local development and automated Cloudflare WARP IPv6 rotation.
