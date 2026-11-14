#!/bin/bash
# doctor — tells you what's alive and what needs attention. no fixes, just
# the truth. run it whenever something feels off.
set -u

BRAND="opencode-unlimited"
DEST="$HOME/.local/share/$BRAND"

WARP="${OUC_WARP_BIN:-}"
if [ -z "$WARP" ]; then
  if command -v warp-cli >/dev/null 2>&1; then WARP="$(command -v warp-cli)"
  elif [ -x /usr/bin/warp-cli ]; then WARP=/usr/bin/warp-cli
  elif [ -x "$HOME/.local/bin/warp-cli" ]; then WARP="$HOME/.local/bin/warp-cli"
  fi
fi
wo(){ sudo -n "$WARP" --accept-tos "$@" 2>/dev/null && return 0; sudo -n "$WARP" "$@" 2>/dev/null; }

ok(){ echo -e "  \e[32m✓\e[0m $*"; }
warn(){ echo -e "  \e[33m!\e[0m $*"; }
bad(){ echo -e "  \e[31m✗\e[0m $*"; }

echo ""
echo "  ============================="
echo "  Opencode Unlimited — doctor"
echo "  ============================="
echo ""

# ---- keeper (root service)
systemctl is-active ${BRAND}-keeper >/dev/null 2>&1 \
  && ok "keeper service (root)" \
  || bad "keeper down — sudo systemctl restart ${BRAND}-keeper"

# ---- warp tunnel
ST=$(wo status | head -1)
echo "$ST" | grep -q Connected \
  && ok "warp tunnel: connected" \
  || bad "warp not connected — sudo systemctl restart ${BRAND}-keeper"

# ---- kill-switch chains & egress check
IS_PROXY=0
if wo settings 2>/dev/null | grep -qi "proxy"; then
  IS_PROXY=1
elif ss -tln 2>/dev/null | grep -q ":40000 "; then
  IS_PROXY=1
elif [ -n "${SSH_CLIENT:-}" ] || [ -n "${SSH_TTY:-}" ] || [ -n "${SSH_CONNECTION:-}" ] || [ -f /etc/cloud/cloud.cfg ] || [ -d /var/lib/cloud ]; then
  IS_PROXY=1
fi

if [ "$IS_PROXY" = "1" ]; then
  ok "isolated proxy mode active (port 40000 / SSH safe)"
  ok "kill-switch disabled in proxy mode (protects SSH connection)"
  # In isolated mode, query through proxy so we verify WARP egress without touching SSH eth0
  CF_TRACE=$(timeout 12 curl -x socks5h://127.0.0.1:40000 -s -m 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || timeout 12 curl -x http://127.0.0.1:41987 -s -m 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
  V6=$(echo "$CF_TRACE" | grep "^ip=" | cut -d= -f2)
  WARP_STATUS=$(echo "$CF_TRACE" | grep "^warp=" | cut -d= -f2)
  if [ -z "$V6" ]; then
    V6=$(timeout 12 curl -x socks5h://127.0.0.1:40000 -s -m 10 https://api64.ipify.org 2>/dev/null || true)
  fi
else
  sudo -n /usr/sbin/iptables  -nL OUC_LEAKGUARD >/dev/null 2>&1 \
    && ok "kill-switch v4 installed" \
    || bad "kill-switch v4 gone — keeper reinstalls it every 45s, or restart it"
  sudo -n /usr/sbin/ip6tables -nL OUC_LEAKGUARD >/dev/null 2>&1 \
    && ok "kill-switch v6 installed" \
    || bad "kill-switch v6 gone — keeper reinstalls it every 45s, or restart it"
  CF_TRACE=$(timeout 12 curl -s -m 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
  V6=$(echo "$CF_TRACE" | grep "^ip=" | cut -d= -f2)
  WARP_STATUS=$(echo "$CF_TRACE" | grep "^warp=" | cut -d= -f2)
  if [ -z "$V6" ]; then
    V6=$(timeout 12 curl -s -m 10 https://api64.ipify.org 2>/dev/null || true)
  fi
fi

if [ "$WARP_STATUS" = "on" ] || [ "$WARP_STATUS" = "plus" ]; then
  ok "egress is cloudflare (warp verified): $V6"
elif [ -n "$V6" ]; then
  FIRST=$(echo "$V6" | cut -d: -f1-4)
  case "$V6" in
    2606:*|2a09:*|104.28.*|8.29.*) ok "egress is cloudflare (warp): $V6" ;;
    *) bad "egress is NOT warp ($V6) — tunnel is lying, restart keeper" ;;
  esac
else
  bad "no egress through warp — tunnel down, restart keeper"
fi

# ---- guard (user service)
systemctl --user is-active ${BRAND}-guard >/dev/null 2>&1 \
  && ok "zen-guard service (user)" \
  || bad "zen-guard down — systemctl --user start ${BRAND}-guard"

# ---- guard state
if [ -f "$DEST/guard/state.json" ]; then
  python3 - "$DEST/guard/state.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(f"    rotations so far: {d.get('hops',0)} · blacklisted /64s: {len([x for x in d.get('blacklist',[]) if x])}")
except Exception as e:
    print(f"    guard state unreadable: {e}")
PY
fi

# ---- TUI shim
if [ -f "$HOME/.local/bin/opencode" ] && grep -q "zen-lane" "$HOME/.local/bin/opencode" 2>/dev/null; then
  ok "opencode entry → lane"
else
  warn "opencode entry doesn't point at the lane — reinstall or check ~/.local/bin/opencode"
fi

echo ""
echo "  all good = work. something red = run the command next to it."
echo ""
