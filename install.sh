#!/bin/bash
# Opencode Unlimited Usage - installer
#
# Installs OpenCode + Cloudflare WARP (via apt, dnf, pacman, nix, or zypper)
# in isolated proxy mode, then sets up the keeper, guard, lane shim,
# auto-resume router, and verification steps.
set -u

BRAND="opencode-unlimited"
DEST="${XDG_DATA_HOME:-$HOME/.local/share}/$BRAND"
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
UNIT_KEEPER="/etc/systemd/system/${BRAND}-keeper.service"
UNIT_GUARD="$HOME/.config/systemd/user/${BRAND}-guard.service"
SHIM="$BIN_DIR/opencode"
SUDOERS_FILE="/etc/sudoers.d/$BRAND"
RAW="https://raw.githubusercontent.com/ShadowySphinX/Opencode-Unlimited-Limit-Bypass-/main"

say(){ echo -e "  $*"; }
ok(){ echo -e "  \e[32m✓\e[0m $*"; }
bad(){ echo -e "  \e[31m✗\e[0m $*"; }
die(){ bad "$*"; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd)"
[ -n "$SRC" ] && [ -d "$SRC/scripts" ] || SRC=""   # piped-from-curl: fetch from github

echo ""
echo "  ==================================================="
echo "  Opencode Unlimited Usage (Linux v4.0)"
echo "  Created & Maintained by Avatar (ShadowySphinX)"
echo "  ==================================================="
echo ""

# ---------------------------------------------------------------- platform
[ "$(id -u)" = 0 ] && die "run me as your normal user, not root"
command -v systemctl >/dev/null 2>&1 || die "systemd not found - this build is linux+systemd only"
command -v python3 >/dev/null 2>&1 || die "python3 required (apt/dnf/pacman install python3)"
command -v curl    >/dev/null 2>&1 || die "curl required"
systemd-run --user --scope true >/dev/null 2>&1 || die "user systemd not running (are you inside a plain docker?)"
[ -e /dev/net/tun ] || die "/dev/net/tun missing - enable TUN in your VM/WSL settings first"

# ---------------------------------------------------------------- sudo
# order: cached (sudo -n) → password prompt from your terminal (curl | bash
# has no usable stdin - rustup and homebrew solve it the same way) →
# stdin fallback for people who download the script first.
if ! sudo -n true 2>/dev/null; then
  if bash -c 'sudo -v </dev/tty' 2>/dev/null; then
    ok "sudo authenticated"
  elif [ ! -t 0 ]; then
    sudo -S -v >/dev/null 2>&1 || die "sudo failed - password came wrong from stdin"
    ok "sudo authenticated (from stdin)"
  else
    die "sudo failed - run me from a real terminal"
  fi
fi

# ---------------------------------------------------------------- distro
PKR=""
command -v apt-get >/dev/null 2>&1 && PKR=apt
[ -z "$PKR" ] && command -v dnf >/dev/null 2>&1 && PKR=dnf
[ -z "$PKR" ] && command -v pacman >/dev/null 2>&1 && PKR=pacman
[ -z "$PKR" ] && command -v nix-env >/dev/null 2>&1 && PKR=nix
[ -z "$PKR" ] && command -v zypper >/dev/null 2>&1 && PKR=zypper

# If warp-cli is already present, we do not require a known package manager!
if ! command -v warp-cli >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/warp-cli" ] && [ -z "$PKR" ]; then
  die "no supported package manager found (apt/dnf/pacman/nix/zypper) - please install cloudflare-warp for your distro first, then re-run this script."
fi

# ---------------------------------------------------------------- opencode CLI
OC_REAL=""
if [ -x "$DEST/real-opencode" ]; then
  OC_REAL="$DEST/real-opencode"
elif [ -x "$HOME/.opencode/bin/opencode" ]; then
  OC_REAL="$HOME/.opencode/bin/opencode"
elif command -v opencode >/dev/null 2>&1; then
  CANDIDATE="$(command -v opencode)"
  # A reinstall must never copy our shim onto itself.
  if ! { [ "$(readlink -f "$CANDIDATE" 2>/dev/null)" = "$(readlink -f "$SHIM" 2>/dev/null)" ] && grep -qs "zen-lane" "$CANDIDATE"; }; then
    OC_REAL="$CANDIDATE"
  fi
fi
if [ -z "$OC_REAL" ]; then
  say "opencode CLI not found - installing (official installer)"
  if curl -fsSL https://opencode.ai/install 2>/dev/null | bash >/dev/null 2>&1; then
    [ -x "$HOME/.opencode/bin/opencode" ] && OC_REAL="$HOME/.opencode/bin/opencode"
  fi
  [ -n "$OC_REAL" ] || die "opencode install failed - install it manually from https://opencode.ai/install"
  ok "opencode installed"
else
  ok "opencode found: $OC_REAL"
fi

# ---------------------------------------------------------------- warp-cli
WARP=""
if command -v warp-cli >/dev/null 2>&1; then
  WARP="$(command -v warp-cli)"
elif [ -x "$HOME/.local/bin/warp-cli" ]; then
  WARP="$HOME/.local/bin/warp-cli"
fi
if [ -z "$WARP" ]; then
  say "warp-cli not found - installing cloudflare warp client"
  case "$PKR" in
    apt)
      sudo apt-get update -qq >/dev/null 2>&1
      sudo apt-get install -y -qq curl gpg lsb-release >/dev/null 2>&1
      curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
        | sudo gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg >/dev/null 2>&1
      echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" \
        | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null
      sudo apt-get update -qq >/dev/null 2>&1
      sudo apt-get install -y -qq cloudflare-warp >/dev/null 2>&1
      ;;
    dnf)
      # cloudflare doesn't ship official dnf repo bins for every fedora release;
      # the defvd route is their rpm. fall back to it.
      sudo dnf -y install gpg >/dev/null 2>&1
      REL=$(curl -fsSL https://api.github.com/repos/cloudflare-warp/cloudflare-warp-rpm/releases/latest 2>/dev/null \
        | python3 -c "import json,sys
try:
    a=json.load(sys.stdin)['assets']
    print(next(x['browser_download_url'] for x in a if 'x86_64.rpm' in x['name']))
except Exception:
    print('')" 2>/dev/null)
      if [ -n "$REL" ]; then
        curl -fsSL "$REL" -o /tmp/warp-install.rpm && sudo dnf -y install /tmp/warp-install.rpm >/dev/null 2>&1 && rm -f /tmp/warp-install.rpm
      else
        sudo dnf -y install cloudflare-warp >/dev/null 2>&1
      fi
      ;;
    pacman)
      if command -v yay >/dev/null 2>&1; then
        yay -S --noconfirm cloudflare-warp-bin >/dev/null 2>&1
      elif command -v paru >/dev/null 2>&1; then
        paru -S --noconfirm cloudflare-warp-bin >/dev/null 2>&1
      else
        die "arch needs yay or paru for cloudflare-warp-bin - install either, re-run me"
      fi
      ;;
    nix)
      if command -v nix-env >/dev/null 2>&1; then
        nix-env -iA nixpkgs.cloudflare-warp >/dev/null 2>&1 || die "NixOS: please add services.cloudflare-warp.enable = true to your configuration.nix or run 'nix-env -iA nixpkgs.cloudflare-warp'"
      fi
      ;;
    zypper)
      sudo zypper install -y cloudflare-warp >/dev/null 2>&1 || die "openSUSE: install cloudflare-warp from official repo"
      ;;
  esac
  command -v warp-cli >/dev/null 2>&1 && WARP="$(command -v warp-cli)"
  [ -n "$WARP" ] || die "warp-cli install failed - see https://pkg.cloudflareclient.com/"
  ok "cloudflare warp installed"
else
  ok "warp-cli found: $WARP"
fi

# warp-cli callers: some boxes wrap warp-cli with a shim that already passes
# --accept-tos, and passing it twice makes the CLI die. so: try with the
# flag first (fresh installs need it), fall back to without (shimmed boxes).
sw(){  sudo -n "$WARP" --accept-tos "$@" >/dev/null 2>&1 && return 0; sudo -n "$WARP" "$@" >/dev/null 2>&1; }
swo(){ sudo -n "$WARP" --accept-tos "$@" 2>/dev/null && return 0; sudo -n "$WARP" "$@" 2>/dev/null; }

# ---------------------------------------------------------------- scripts
mkdir -p "$DEST/scripts" "$DEST/python" "$BIN_DIR"
if [ -n "$SRC" ]; then
  cp "$SRC/scripts/"*.sh "$DEST/scripts/"
else
  say "fetching scripts from github"
  for f in warp-keeper.sh zen-lane.sh zen-guard.sh zen-hop.sh doctor.sh; do
    curl -fsSL "$RAW/scripts/$f" -o "$DEST/scripts/$f" || die "could not fetch $f"
  done
fi
chmod +x "$DEST/scripts/"*.sh

# The Linux lane runs the same hardened HTTP CONNECT proxy as Windows. Bun
# ignores socks5:// proxy variables, so this proxy is what actually carries
# OpenCode traffic through WARP's local SOCKS listener.
PY_MODULES="ouc_common.py zen_proxy.py proxy_chain.py tor_manager.py"
if [ -n "$SRC" ]; then
  for f in $PY_MODULES; do
    cp "$SRC/src/$f" "$DEST/python/$f" || die "could not install $f"
  done
else
  for f in $PY_MODULES; do
    curl -fsSL "$RAW/src/$f" -o "$DEST/python/$f" || die "could not fetch $f"
  done
fi
chmod 644 "$DEST/python/"*.py

# scripts pick the warp binary themselves (OUC_WARP_BIN env if the service
# provides one, else standard paths). no baking - sed-editing scripts after
# download is how you ship a broken script.
# hop + doctor on PATH
ln -sf "$DEST/scripts/zen-hop.sh" "$BIN_DIR/${BRAND}-hop"
ln -sf "$DEST/scripts/doctor.sh"  "$BIN_DIR/${BRAND}-doctor"
ok "scripts and lane proxy in $DEST"

# ---------------------------------------------------------------- sudoers (warp-cli for the unattended guard, exact keeper
# stop/start for rotation, read-only iptables verification for the doctor).
# Each entry is an exact-args match; sudoers will not accept anything else.
IPTABLES="$(command -v iptables 2>/dev/null || true)"
IP6TABLES="$(command -v ip6tables 2>/dev/null || true)"
SYSTEMCTL="$(command -v systemctl 2>/dev/null || echo /usr/bin/systemctl)"
SUDOERS_NEED="$USER ALL=(root) NOPASSWD: $WARP, $SYSTEMCTL stop $BRAND-keeper, $SYSTEMCTL start $BRAND-keeper"
[ -n "$IPTABLES" ]  && SUDOERS_NEED="$SUDOERS_NEED, $IPTABLES -nL OUC_LEAKGUARD"
[ -n "$IP6TABLES" ] && SUDOERS_NEED="$SUDOERS_NEED, $IP6TABLES -nL OUC_LEAKGUARD"
SUDOERS_NOW="$(sudo -n cat "$SUDOERS_FILE" 2>/dev/null || echo '')"
if [ "$SUDOERS_NOW" != "$SUDOERS_NEED" ]; then
  say "sudoers: passwordless warp-cli, keeper rotation, kill-switch verify"
  printf '%s\n' "$SUDOERS_NEED" | sudo tee "$SUDOERS_FILE" >/dev/null
  sudo chmod 440 "$SUDOERS_FILE"
  sudo visudo -c >/dev/null 2>&1 || { sudo rm -f "$SUDOERS_FILE"; die "sudoers validation failed - rerun the installer"; }
fi
sw status || die "passwordless warp-cli did not work - check $SUDOERS_FILE"
ok "passwordless warp-cli works"

# ---------------------------------------------------------------- warp: register + isolated proxy mode + connect
say "starting WARP in isolated proxy mode"
# Keep an existing device registration; only create one when missing.
if ! swo registration show >/dev/null 2>&1; then
  say "no WARP registration found - creating one"
  sw registration new >/dev/null 2>&1 || say "registration is not ready yet; the keeper will retry"
fi

# Detect VPS or SSH session to protect remote connectivity
if [ -n "${SSH_CLIENT:-}" ] || [ -n "${SSH_TTY:-}" ] || [ -n "${SSH_CONNECTION:-}" ] || [ -f /etc/cloud/cloud.cfg ] || [ -d /var/lib/cloud ]; then
  touch "$DEST/vps.flag" 2>/dev/null || true
  sudo touch /etc/opencode-unlimited-vps.flag 2>/dev/null || true
  say "VPS / SSH environment detected: enforcing isolated proxy mode (port 40000) to protect SSH access"
fi

# Proxy mode only carries MASQUE on current WARP clients; WireGuard there fails
# with "Proxy mode only supports MASQUE" and leaves port 40000 dead.
sw tunnel protocol set "${OUC_WARP_PROTOCOL:-MASQUE}" >/dev/null 2>&1 || true

sw mode proxy
sw proxy port 40000
sw connect
CONNECTED=0
for _ in $(seq 1 10); do
  sleep 3
  swo status | head -1 | grep -q Connected && { CONNECTED=1; break; }
done
[ "$CONNECTED" = 1 ] \
  && ok "warp tunnel: connected (isolated proxy mode on port 40000)" \
  || say "warp not up yet - the keeper will keep retrying every 45s"

# ---------------------------------------------------------------- keeper (root service)
cat > /tmp/ouc-keeper-unit <<EOF
[Unit]
Description=Opencode Unlimited - warp keeper (tunnel enforce + kill-switch)
After=network-online.target
Wants=network-online.target

[Service]
Environment=OUC_DEST=$DEST
Environment=OUC_WARP_MODE=proxy
Environment=OUC_PAUSE_FILE=$DEST/keeper.pause
ExecStart=/bin/bash $DEST/scripts/warp-keeper.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
sudo install -m 755 "$DEST/scripts/warp-keeper.sh" /usr/local/bin/${BRAND}-keeper
sudo install -m 644 /tmp/ouc-keeper-unit "$UNIT_KEEPER"
sudo systemctl daemon-reload
sudo systemctl enable --now ${BRAND}-keeper >/dev/null 2>&1
systemctl is-active ${BRAND}-keeper 2>/dev/null | grep -q active \
  && ok "keeper service (root): running" \
  || die "keeper did not start - check: systemctl status ${BRAND}-keeper"

# ---------------------------------------------------------------- guard (user service)
# Keep the user guard alive after SSH logs out; otherwise rotation stops on a
# headless VPS while the root keeper keeps running.
if command -v loginctl >/dev/null 2>&1; then
  sudo -n loginctl enable-linger "$USER" >/dev/null 2>&1 \
    || say "could not enable lingering - run: sudo loginctl enable-linger $USER"
fi

mkdir -p "$HOME/.config/systemd/user"
cat > "$UNIT_GUARD" <<EOF
[Unit]
Description=Opencode Unlimited - zen guard (wall watcher, auto /64 rotation)
After=network-online.target

[Service]
Environment=OUC_DEST=$DEST
Environment=OUC_WARP_MODE=proxy
Environment=OUC_PAUSE_FILE=$DEST/keeper.pause
Environment=OUC_KEEPER_UNIT=${BRAND}-keeper
Environment=OUC_WARP_BIN=$WARP
ExecStart=/bin/bash $DEST/scripts/zen-guard.sh
Restart=always
RestartSec=15

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now ${BRAND}-guard >/dev/null 2>&1
systemctl --user is-active ${BRAND}-guard 2>/dev/null | grep -q active \
  && ok "zen-guard service (user): running" \
  || die "guard did not start - check: systemctl --user status ${BRAND}-guard"

# ---------------------------------------------------------------- TUI shim (the lane)
if [ "$OC_REAL" = "$SHIM" ] || [ "$(readlink -f "$OC_REAL" 2>/dev/null)" = "$(readlink -f "$SHIM" 2>/dev/null)" ]; then
  if grep -qs "zen-lane" "$SHIM"; then
    [ -x "$DEST/real-opencode" ] \
      || die "opencode entry is already our shim but no real binary was found - set OUC_REAL_BIN or reinstall OpenCode"
    OC_REAL="$DEST/real-opencode"
  else
    cp "$SHIM" "$DEST/real-opencode" && chmod +x "$DEST/real-opencode"
    OC_REAL="$DEST/real-opencode"
  fi
fi
[ -n "$OC_REAL" ] || die "OpenCode CLI was not found - install it from https://opencode.ai/install"
printf '#!/usr/bin/env bash\nexport OUC_DEST="%s"\nexport OUC_REAL_BIN="%s"\nexec bash "%s/scripts/zen-lane.sh" "$@"\n' "$DEST" "$OC_REAL" "$DEST" > "$SHIM"
chmod +x "$SHIM"
ok "opencode entry → local proxy lane (WARP egress per launch)"

# ---------------------------------------------------------------- verify end to end (the installer doesn't lie)
say "verifying the lane end to end (this hits opencode once)..."
# The installer always leaves WARP in isolated proxy mode. Verify through that
# listener, not through the host's normal route (which would hide a dead WARP).
CF_TRACE=$(timeout 12 curl -x socks5h://127.0.0.1:40000 -s -m 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
V6=$(echo "$CF_TRACE" | grep "^ip=" | cut -d= -f2)
WARP_STATUS=$(echo "$CF_TRACE" | grep "^warp=" | cut -d= -f2)
if [ -z "$V6" ]; then
  V6=$(timeout 12 curl -x socks5h://127.0.0.1:40000 -s -m 10 https://api64.ipify.org 2>/dev/null || true)
fi

if [ "$WARP_STATUS" = "on" ] || [ "$WARP_STATUS" = "plus" ]; then
  ok "egress is cloudflare (warp verified): $V6"
elif [ -n "$V6" ]; then
  case "$V6" in
    2606:*|2a09:*|104.28.*|8.29.*) ok "egress is cloudflare (warp): $V6" ;;
    *) bad "egress is not Cloudflare WARP yet - the keeper will retry; run ${BRAND}-doctor if it persists" ;;
  esac
else
  bad "egress is not Cloudflare WARP yet - the keeper will retry; run ${BRAND}-doctor if it persists"
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ok "PATH has $BIN_DIR" ;;
  *) say "add this to your ~/.bashrc, then reopen the terminal:"
     say "    export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

echo ""
ok "DONE. close & reopen your terminal, then run:  opencode"
say "first launch: opencode sets up its device identity - if it asks you to log in, complete it once (free)"
echo ""
say "wall hits while you work? zen-guard rotates automatically - re-send your message if the automatic resume did not fire."
say "health check any time:  ${BRAND}-doctor   ·   fresh identity now:  ${BRAND}-hop"
echo ""
