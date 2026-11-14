#!/bin/bash
# warp keeper — keeps the cloudflare warp tunnel connected and healthy.
# runs as a systemd service.
#
# every tick (45s):
#   - maintains warp proxy mode (port 40000) or TUN mode
#   - reconnects if the tunnel died
#   - installs leakguard protection while strictly whitelisting SSH to prevent VPS lockouts
set -u

WARP="${OUC_WARP_BIN:-}"
if [ -z "$WARP" ]; then
  if command -v warp-cli >/dev/null 2>&1; then WARP="$(command -v warp-cli)"
  elif [ -x /usr/bin/warp-cli ]; then WARP=/usr/bin/warp-cli
  elif [ -x "$HOME/.local/bin/warp-cli" ]; then WARP="$HOME/.local/bin/warp-cli"
  fi
fi
[ -n "$WARP" ] || { echo "warp-cli not found"; exit 1; }

w(){  "$WARP" --accept-tos "$@" >/dev/null 2>&1 && return 0; "$WARP" "$@" >/dev/null 2>&1; }
wo(){ "$WARP" --accept-tos "$@" 2>/dev/null && return 0; "$WARP" "$@" 2>/dev/null; }

IFACE=CloudflareWARP
TICK=45

# Detect SSH session or cloud VPS environment
IS_VPS=0
if [ -n "${SSH_CLIENT:-}" ] || [ -n "${SSH_TTY:-}" ] || [ -n "${SSH_CONNECTION:-}" ] || [ -f /etc/cloud/cloud.cfg ] || [ -d /var/lib/cloud ]; then
  IS_VPS=1
fi

MODE="${OUC_WARP_MODE:-proxy}"

ensure_connected(){
  wo status | head -1 | grep -q Connected && return 0
  w connect; sleep 4
  wo status | head -1 | grep -q Connected && return 0
  # old registration is dead — burn it and make a fresh registration
  w disconnect
  w registration delete
  w registration new || return 1
  if [ "$MODE" = "warp" ] && [ "$IS_VPS" = "0" ]; then
    w mode warp
  else
    w mode proxy
    w proxy port 40000
  fi
  w connect
  sleep 5
  wo status | head -1 | grep -q Connected
}

ensure_guard(){
  # Only install iptables leakguard in TUN mode when NOT on a remote VPS
  if [ "$MODE" != "warp" ] || [ "$IS_VPS" = "1" ]; then
    # In proxy mode or VPS, remove old leakguard rule if present to ensure SSH is never blocked
    iptables  -D OUTPUT -j OUC_LEAKGUARD 2>/dev/null || true
    ip6tables -D OUTPUT -j OUC_LEAKGUARD 2>/dev/null || true
    return 0
  fi

  # ---- v4
  iptables  -N OUC_LEAKGUARD 2>/dev/null
  iptables  -F OUC_LEAKGUARD
  iptables  -A OUC_LEAKGUARD -o lo              -j ACCEPT
  iptables  -A OUC_LEAKGUARD -m state --state ESTABLISHED,RELATED -j ACCEPT

  # NEVER lock out SSH on port 22 or custom SSH ports
  iptables  -A OUC_LEAKGUARD -p tcp --dport 22 -j ACCEPT
  iptables  -A OUC_LEAKGUARD -p tcp --sport 22 -j ACCEPT
  SSH_PORTS="$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | sort -u)"
  for p in $SSH_PORTS; do
    if [ -n "$p" ] && [ "$p" -gt 0 ] 2>/dev/null && [ "$p" -ne 22 ]; then
      iptables -A OUC_LEAKGUARD -p tcp --dport "$p" -j ACCEPT
      iptables -A OUC_LEAKGUARD -p tcp --sport "$p" -j ACCEPT
    fi
  done

  iptables  -A OUC_LEAKGUARD -d 10.0.0.0/8      -j ACCEPT
  iptables  -A OUC_LEAKGUARD -d 172.16.0.0/12   -j ACCEPT
  iptables  -A OUC_LEAKGUARD -d 192.168.0.0/16  -j ACCEPT
  # cloudflare warp control/engage ranges
  iptables  -A OUC_LEAKGUARD -d 162.159.0.0/16  -j ACCEPT
  iptables  -A OUC_LEAKGUARD -d 188.114.0.0/16  -j ACCEPT
  iptables  -A OUC_LEAKGUARD -o $IFACE          -j ACCEPT
  iptables  -A OUC_LEAKGUARD -j DROP
  iptables  -C OUTPUT -j OUC_LEAKGUARD 2>/dev/null || iptables -I OUTPUT -j OUC_LEAKGUARD

  # ---- v6
  ip6tables -N OUC_LEAKGUARD 2>/dev/null
  ip6tables -F OUC_LEAKGUARD
  ip6tables -A OUC_LEAKGUARD -o lo   -j ACCEPT
  ip6tables -A OUC_LEAKGUARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A OUC_LEAKGUARD -p tcp --dport 22 -j ACCEPT
  ip6tables -A OUC_LEAKGUARD -p tcp --sport 22 -j ACCEPT
  for p in $SSH_PORTS; do
    if [ -n "$p" ] && [ "$p" -gt 0 ] 2>/dev/null && [ "$p" -ne 22 ]; then
      ip6tables -A OUC_LEAKGUARD -p tcp --dport "$p" -j ACCEPT
      ip6tables -A OUC_LEAKGUARD -p tcp --sport "$p" -j ACCEPT
    fi
  done
  ip6tables -A OUC_LEAKGUARD -d fe80::/10      -j ACCEPT
  ip6tables -A OUC_LEAKGUARD -d 2606:4700::/32 -j ACCEPT
  ip6tables -A OUC_LEAKGUARD -o $IFACE         -j ACCEPT
  ip6tables -A OUC_LEAKGUARD -j DROP
  ip6tables -C OUTPUT -j OUC_LEAKGUARD 2>/dev/null || ip6tables -I OUTPUT -j OUC_LEAKGUARD
}

# on initial boot wait for network
for i in 1 2 3 4 5 6; do
  w status >/dev/null 2>&1 && break
  sleep 10
done

while true; do
  if [ "$MODE" = "warp" ] && [ "$IS_VPS" = "0" ]; then
    w mode warp
  else
    w mode proxy
    w proxy port 40000
  fi
  ensure_connected || true
  ensure_guard
  sleep $TICK
done
