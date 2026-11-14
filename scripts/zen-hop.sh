#!/bin/bash
# zen hop — manual identity rotation. deletes the current warp registration,
# registers fresh, reconnects. you land on a new IPv6 /64 (= new quota bucket).
#
# the keeper is paused during the hop — otherwise its 45s tick races us and
# "helpfully" repairs the tunnel mid-surgery. the kill-switch chain stays
# installed the whole time (keeper owns it but doesn't remove it on stop),
# so there is no leak window. keeper resumes on exit no matter what.
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
w(){  sudo -n "$WARP" --accept-tos "$@" >/dev/null 2>&1 && return 0; sudo -n "$WARP" "$@" >/dev/null 2>&1; }
wo(){ sudo -n "$WARP" --accept-tos "$@" 2>/dev/null && return 0; sudo -n "$WARP" "$@" 2>/dev/null; }

restore(){ sudo -n systemctl start "$KEEPER" >/dev/null 2>&1 || sudo systemctl start "$KEEPER" >/dev/null 2>&1; }
trap restore EXIT

IS_VPS=0
if [ -n "${SSH_CLIENT:-}" ] || [ -n "${SSH_TTY:-}" ] || [ -n "${SSH_CONNECTION:-}" ] || [ -f /etc/cloud/cloud.cfg ] || [ -d /var/lib/cloud ] || wo settings 2>/dev/null | grep -qi "proxy"; then
  IS_VPS=1
fi

cur_v6(){
  if [ "$IS_VPS" = "1" ]; then
    timeout 10 curl -x socks5h://127.0.0.1:40000 -s -m 8 https://api64.ipify.org 2>/dev/null || timeout 10 curl -x http://127.0.0.1:41987 -s -m 8 https://api64.ipify.org 2>/dev/null
  else
    timeout 10 curl -s -m 8 https://api64.ipify.org 2>/dev/null
  fi
}

OLD_V6=$(cur_v6)
echo "old /64: ${OLD_V6:-?}"

sudo systemctl stop "$KEEPER" >/dev/null 2>&1
echo "-- rotating (keeper paused) --"
w disconnect
w registration delete
NEW=0
for i in 1 2 3 4 5; do
  w registration new && { NEW=1; break; }
  echo "  attempt $i failed"; sleep 8
done
[ "$NEW" = 1 ] || { echo "-- registration failed — keeper will keep retrying --"; exit 1; }
if [ "$IS_VPS" = "1" ]; then
  w mode proxy
  w proxy port 40000
else
  w mode warp
fi
w connect

for i in $(seq 1 20); do
  sleep 3
  wo status | head -1 | grep -q Connected && break
done

NEW_V6=$(cur_v6)
echo "new /64: ${NEW_V6:-?}"
if [ "$NEW_V6" != "$OLD_V6" ] && [ -n "$NEW_V6" ]; then
  echo "== FRESH /64 ✓ — re-send your message =="
  exit 0
fi
echo "== cloudflare handed back the same block — run me again =="
exit 1
