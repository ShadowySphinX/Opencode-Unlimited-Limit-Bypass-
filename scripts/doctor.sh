#!/bin/bash
# doctor - prints which components are running and which need attention.
# It does not change anything; use it when diagnosing a problem.
set -u

BRAND="opencode-unlimited"
DEST="${OUC_DEST:-${XDG_DATA_HOME:-$HOME/.local/share}/$BRAND}"
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"

WARP="${OUC_WARP_BIN:-}"
if [ -z "$WARP" ]; then
  if command -v warp-cli >/dev/null 2>&1; then WARP="$(command -v warp-cli)"
  elif [ -x /usr/bin/warp-cli ]; then WARP=/usr/bin/warp-cli
  elif [ -x "$HOME/.local/bin/warp-cli" ]; then WARP="$HOME/.local/bin/warp-cli"
  fi
fi
wo(){ [ -n "$WARP" ] || return 1; sudo -n "$WARP" --accept-tos "$@" 2>/dev/null && return 0; sudo -n "$WARP" "$@" 2>/dev/null; }

ok(){ echo -e "  \e[32m✓\e[0m $*"; }
warn(){ echo -e "  \e[33m!\e[0m $*"; }
bad(){ echo -e "  \e[31m✗\e[0m $*"; }

port_open(){ (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }
IPT="$(command -v iptables 2>/dev/null || true)"
IP6T="$(command -v ip6tables 2>/dev/null || true)"

echo ""
echo "  ============================="
echo "  Opencode Unlimited - doctor"
echo "  ============================="
echo ""

# ---- keeper (root service)
systemctl is-active ${BRAND}-keeper >/dev/null 2>&1 \
  && ok "keeper service (root)" \
  || bad "keeper down - sudo systemctl restart ${BRAND}-keeper"

# ---- warp tunnel
ST=$(wo status | head -1)
echo "$ST" | grep -q Connected \
  && ok "warp tunnel: connected" \
  || bad "warp not connected - sudo systemctl restart ${BRAND}-keeper"

# ---- kill-switch chains & egress check
IS_PROXY=0
if [ -f /etc/opencode-unlimited-vps.flag ] || [ -f "$DEST/vps.flag" ]; then
  IS_PROXY=1
elif wo settings 2>/dev/null | grep -qiE "mode[^:]*:[[:space:]]*proxy"; then
  IS_PROXY=1
elif wo mode 2>/dev/null | grep -qi "proxy"; then
  IS_PROXY=1
elif ss -tln 2>/dev/null | grep -q ":40000"; then
  IS_PROXY=1
elif [ -n "${SSH_CLIENT:-}" ] || [ -n "${SSH_TTY:-}" ] || [ -n "${SSH_CONNECTION:-}" ] || [ -f /etc/cloud/cloud.cfg ] || [ -d /var/lib/cloud ]; then
  IS_PROXY=1
fi

if [ "$IS_PROXY" = "1" ]; then
  ok "isolated proxy mode active (port 40000 / SSH safe)"
  ok "kill-switch disabled in proxy mode (protects SSH connection)"
  port_open 40000 \
    && ok "WARP isolated SOCKS proxy: listening on 127.0.0.1:40000" \
    || bad "WARP proxy port 40000 is not listening - restart the keeper"
  # In isolated mode, query through proxy so we verify WARP egress without touching SSH eth0
  # Measured on the host the model traffic goes to: another Cloudflare host can
  # take a different route and hide a rotation that changed nothing.
  OC_TRACE=$(timeout 12 curl -x socks5h://127.0.0.1:40000 -s -m 10 https://opencode.ai/cdn-cgi/trace 2>/dev/null || true)
  OC_IP=$(echo "$OC_TRACE" | grep "^ip=" | cut -d= -f2)
  CF_TRACE=$(timeout 12 curl -x socks5h://127.0.0.1:40000 -s -m 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
  V6=$(echo "$CF_TRACE" | grep "^ip=" | cut -d= -f2)
  WARP_STATUS=$(echo "$CF_TRACE" | grep "^warp=" | cut -d= -f2)
  if [ -z "$V6" ]; then
    V6=$(timeout 12 curl -x socks5h://127.0.0.1:40000 -s -m 10 https://api64.ipify.org 2>/dev/null || true)
  fi
else
  if [ -n "$IPT" ]; then
    sudo -n "$IPT" -nL OUC_LEAKGUARD >/dev/null 2>&1 \
      && ok "kill-switch v4 installed" \
      || bad "kill-switch v4 gone - keeper reinstalls it every 45s, or restart it"
  else
    warn "iptables not installed - kill-switch check skipped"
  fi
  if [ -n "$IP6T" ]; then
    sudo -n "$IP6T" -nL OUC_LEAKGUARD >/dev/null 2>&1 \
      && ok "kill-switch v6 installed" \
      || bad "kill-switch v6 gone - keeper reinstalls it every 45s, or restart it"
  else
    warn "ip6tables not installed - kill-switch check skipped"
  fi
  CF_TRACE=$(timeout 12 curl -s -m 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
  V6=$(echo "$CF_TRACE" | grep "^ip=" | cut -d= -f2)
  WARP_STATUS=$(echo "$CF_TRACE" | grep "^warp=" | cut -d= -f2)
  OC_TRACE=$(timeout 12 curl -s -m 10 https://opencode.ai/cdn-cgi/trace 2>/dev/null || true)
  OC_IP=$(echo "$OC_TRACE" | grep "^ip=" | cut -d= -f2)
  if [ -z "$V6" ]; then
    V6=$(timeout 12 curl -s -m 10 https://api64.ipify.org 2>/dev/null || true)
  fi
fi

if [ "$WARP_STATUS" = "on" ] || [ "$WARP_STATUS" = "plus" ]; then
  ok "egress is cloudflare (warp verified): $V6"
elif [ -n "$V6" ]; then
  case "$V6" in
    2606:*|2a09:*|104.28.*|8.29.*) ok "egress is cloudflare (warp): $V6" ;;
    *) bad "egress is not Cloudflare WARP ($V6) - restart the keeper service" ;;
  esac
else
  bad "no egress through warp - tunnel down, restart keeper"
fi

# ---- inference route (the address the quota bucket follows)
if [ -n "$OC_IP" ]; then
  case "$OC_IP" in
    *:*)
      if [ -n "$V6" ] && [ "$OC_IP" != "$V6" ]; then
        warn "opencode.ai leaves from $OC_IP, the trace host from $V6 - different routes, so a rotation measures the wrong one"
      else
        ok "opencode.ai egress matches the measured route: $OC_IP"
      fi
      ;;
    *)
      bad "opencode.ai leaves over IPv4 ($OC_IP) - rotating a /64 cannot clear a wall that follows this address"
      ;;
  esac
else
  warn "could not read the opencode.ai egress - the model traffic route is unverified"
fi

# ---- Linux lane proxy modules
if PYTHONPATH="$DEST/python" python3 -c "import zen_proxy" >/dev/null 2>&1; then
  ok "Linux lane proxy: installed ($DEST/python)"
else
  bad "Linux lane proxy missing - rerun install.sh"
fi

# ---- guard (user service)
systemctl --user is-active ${BRAND}-guard >/dev/null 2>&1 \
  && ok "zen-guard service (user)" \
  || bad "zen-guard down - systemctl --user start ${BRAND}-guard"

if [ -f "$DEST/keeper.pause" ]; then
  warn "keeper pause file present - a rotation may still be running; remove $DEST/keeper.pause only if it is stuck"
fi

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
if [ -f "$BIN_DIR/opencode" ] && grep -q "zen-lane" "$BIN_DIR/opencode" 2>/dev/null; then
  ok "opencode entry → lane"
else
  warn "opencode entry doesn't point at the lane - reinstall or check $BIN_DIR/opencode"
fi

echo ""
echo "  all good = work. something red = run the command next to it."
echo ""
