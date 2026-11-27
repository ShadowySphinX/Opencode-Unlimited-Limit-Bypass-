#!/bin/bash
# zen hop - manual identity rotation. renews the WireGuard session keys and
# reconnects to obtain a new IPv6 /64. the device registration is kept.
#
# the keeper is paused during the hop so its tick cannot reconnect the tunnel
# in the middle of the rotation. The kill-switch chain stays installed the
# whole time, and the keeper resumes when the hop exits.
set -u

# warp binary: env → PATH → common fallbacks. probe with/without --accept-tos
# (shimmed boxes pass it twice = dead CLI).
WARP="${OUC_WARP_BIN:-}"
if [ -z "$WARP" ]; then
  if command -v warp-cli >/dev/null 2>&1; then WARP="$(command -v warp-cli)"
  elif [ -x /usr/bin/warp-cli ]; then WARP=/usr/bin/warp-cli
  elif [ -x "$HOME/.local/bin/warp-cli" ]; then WARP="$HOME/.local/bin/warp-cli"
  fi
fi
[ -n "$WARP" ] || { echo "warp-cli not found"; exit 1; }

KEEPER="${OUC_KEEPER_UNIT:-opencode-unlimited-keeper}"
DEST="${OUC_DEST:-${XDG_DATA_HOME:-$HOME/.local/share}/opencode-unlimited}"
PAUSE_FILE="${OUC_PAUSE_FILE:-$DEST/keeper.pause}"
MODE="${OUC_WARP_MODE:-proxy}"

w(){  sudo -n "$WARP" --accept-tos "$@" >/dev/null 2>&1 && return 0; sudo -n "$WARP" "$@" >/dev/null 2>&1; }
wo(){ sudo -n "$WARP" --accept-tos "$@" 2>/dev/null && return 0; sudo -n "$WARP" "$@" 2>/dev/null; }

set_mode(){
  # Proxy mode is MASQUE-only on current WARP clients; TUN uses WireGuard.
  if [ "$MODE" = "warp" ]; then
    # Leave proxy mode before changing the protocol: a proxy client rejects
    # the change while it is serving, so the order matters in this direction.
    w mode warp
    w tunnel protocol set "${OUC_WARP_PROTOCOL:-WireGuard}"
  else
    # A serving proxy client refuses a protocol change, so drop a proxy that
    # drifted onto the wrong protocol before correcting it.
    SETTINGS=$(wo settings 2>/dev/null || true)
    if echo "$SETTINGS" | grep -qiE "mode[^:]*:[[:space:]]*proxy" && ! echo "$SETTINGS" | grep -qi masque; then
      w disconnect
    fi
    w tunnel protocol set "${OUC_WARP_PROTOCOL:-MASQUE}"
    w mode proxy
    w proxy port 40000
  fi
}

restore(){
  rm -f "$PAUSE_FILE" 2>/dev/null || true
  sudo -n systemctl start "$KEEPER" >/dev/null 2>&1 || true
}
trap restore EXIT

USE_PROXY=0
if [ "$MODE" != "warp" ] || [ -f /etc/opencode-unlimited-vps.flag ] || [ -f "$DEST/vps.flag" ]; then
  USE_PROXY=1
fi

cur_v6(){
  local v ep
  # Same rule as the guard: measure the host the model traffic uses.
  if [ "$USE_PROXY" = "1" ]; then
    v=$(timeout 10 curl -x socks5h://127.0.0.1:40000 -s -m 8 https://opencode.ai/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' | head -n1)
    case "$v" in *:*) echo "$v"; return;; esac
    for ep in https://api6.ipify.org https://api64.ipify.org; do
      v=$(timeout 10 curl -x socks5h://127.0.0.1:40000 -s -m 8 "$ep" 2>/dev/null)
      case "$v" in *:*) echo "$v"; return;; esac
    done
  else
    v=$(timeout 10 curl -6 -s -m 8 https://opencode.ai/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' | head -n1)
    case "$v" in *:*) echo "$v"; return;; esac
    for ep in https://api6.ipify.org https://api64.ipify.org; do
      v=$(timeout 10 curl -6 -s -m 8 "$ep" 2>/dev/null)
      case "$v" in *:*) echo "$v"; return;; esac
    done
  fi
  echo ""
}

m64(){ python3 - "$1" <<'PY' 2>/dev/null
import ipaddress, sys
try:
    print(ipaddress.IPv6Network((ipaddress.IPv6Address(sys.argv[1]), 64), strict=False).network_address)
except Exception:
    print("")
PY
}

OLD_V6=$(cur_v6)
echo "old /64: ${OLD_V6:-?}"

touch "$PAUSE_FILE" 2>/dev/null || true
sudo -n systemctl stop "$KEEPER" >/dev/null 2>&1 || true
echo "-- rotating (keeper paused) --"
w disconnect

# Recreate a registration only when it is actually missing.
if ! wo registration show >/dev/null 2>&1; then
  for i in 1 2 3; do
    w registration new && break
    echo "  registration attempt $i failed"; sleep 6
  done
fi

w tunnel rotate-keys
set_mode
w connect

NEW_V6=""
for i in $(seq 1 20); do
  sleep 3
  wo status | head -1 | grep -q Connected || continue
  V=$(cur_v6)
  case "$V" in
    *:*)
      if [ -z "$OLD_V6" ] || [ "$(m64 "$V")" != "$(m64 "$OLD_V6")" ]; then
        NEW_V6="$V"
        break
      fi
      ;;
  esac
done

echo "new /64: ${NEW_V6:-?}"
if [ -n "$NEW_V6" ]; then
  # Clear client-side rate limit lockouts from drafts.sqlite. Python is a
  # hard installer dependency, so this does not need a separate sqlite3 CLI.
  for db in "$HOME/.config/ai.opencode.desktop/drafts.sqlite" "$HOME/.local/share/opencode/drafts.sqlite"; do
    [ -f "$db" ] || continue
    python3 - "$db" <<'PY' >/dev/null 2>&1 || true
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=5.0)
c.execute("DELETE FROM state WHERE key IN ('free-limit', 'go-upsell', 'free_usage_limit', 'usage_limit', 'quota_exceeded')")
c.commit()
c.close()
PY
  done
  echo "new /64 prefix accepted; re-send your message."
  exit 0
fi
echo "Cloudflare returned the same /64 block; run the command again."
exit 1
