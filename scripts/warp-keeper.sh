#!/bin/bash
# warp keeper - keeps the cloudflare warp tunnel connected and healthy.
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
# Hosts with IPv6 disabled cannot hold the v6 chain; requiring it in the
# idempotence check would rebuild the rules (and briefly fail open) every tick.
IP6_OK=1
ip6tables -L -n >/dev/null 2>&1 || IP6_OK=0

DEST="${OUC_DEST:-${XDG_DATA_HOME:-$HOME/.local/share}/opencode-unlimited}"
PAUSE_FILE="${OUC_PAUSE_FILE:-$DEST/keeper.pause}"
mkdir -p "$(dirname "$PAUSE_FILE")" 2>/dev/null || true

# Detect SSH session or cloud VPS environment
IS_VPS=0
if [ -f /etc/opencode-unlimited-vps.flag ] || [ -n "${SSH_CLIENT:-}" ] || [ -n "${SSH_TTY:-}" ] || [ -n "${SSH_CONNECTION:-}" ] || [ -f /etc/cloud/cloud.cfg ] || [ -d /var/lib/cloud ]; then
  IS_VPS=1
fi

# The Linux installer selects isolated proxy mode. Users who deliberately
# choose TUN set OUC_WARP_MODE=warp in the unit or environment.
MODE="${OUC_WARP_MODE:-proxy}"
REPAIR_COOLDOWN=120
LAST_REPAIR=0

proxy_ready(){
  (exec 3<>/dev/tcp/127.0.0.1/40000) 2>/dev/null
}

set_mode(){
  # Current WARP clients only carry proxy mode over MASQUE; asking for
  # WireGuard there fails with "Proxy mode only supports MASQUE" and leaves
  # port 40000 dead. TUN keeps the WireGuard path.
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

ensure_connected(){
  # 1. Already connected in the right shape: do not touch anything.
  #    A stale "Connected" with no port 40000 listener is mode drift, not health.
  if wo status | head -1 | grep -q Connected; then
    if [ "$MODE" != "proxy" ] || proxy_ready; then
      return 0
    fi
    w disconnect
  fi

  # 2. In-flight handshake grace window
  if wo status | head -1 | grep -qi "connecting"; then
    for _ in $(seq 1 8); do
      sleep 1
      if wo status | head -1 | grep -q Connected; then
        if [ "$MODE" != "proxy" ] || proxy_ready; then return 0; fi
      fi
      wo status | head -1 | grep -qi "connecting" || break
    done
  fi

  # 3. Disconnected: ensure the selected mode and connect
  set_mode
  w connect

  for _ in $(seq 1 8); do
    sleep 1
    if wo status | head -1 | grep -q Connected; then
      if [ "$MODE" != "proxy" ] || proxy_ready; then return 0; fi
    fi
  done

  # 4. Gentle recovery: renew the session keys (registration is preserved).
  #    Rate-limit repairs so a flapping network is not churned every tick.
  NOW=$(date +%s)
  if [ $((NOW - LAST_REPAIR)) -lt "$REPAIR_COOLDOWN" ]; then
    return 1
  fi
  LAST_REPAIR=$NOW

  w tunnel rotate-keys
  set_mode
  w connect

  for _ in $(seq 1 6); do
    sleep 1
    if wo status | head -1 | grep -q Connected; then
      if [ "$MODE" != "proxy" ] || proxy_ready; then return 0; fi
    fi
  done

  # 5. Only register new if registration is explicitly missing
  STATUS="$(wo status 2>/dev/null)"
  if echo "$STATUS" | grep -qiE "registration missing|not registered"; then
    w registration new || return 1
    set_mode
    w connect
    sleep 4
    if wo status | head -1 | grep -q Connected; then
      [ "$MODE" != "proxy" ] || proxy_ready
      return $?
    fi
  fi

  wo status | head -1 | grep -q Connected || return 1
  [ "$MODE" != "proxy" ] || proxy_ready
}

ensure_guard(){
  # Only install iptables leakguard in TUN mode when NOT on a remote VPS
  if [ "$MODE" != "warp" ] || [ "$IS_VPS" = "1" ]; then
    # Remove any old leakguard rule in proxy mode or on a VPS so SSH stays reachable.
    iptables  -D OUTPUT -j OUC_LEAKGUARD 2>/dev/null || true
    ip6tables -D OUTPUT -j OUC_LEAKGUARD 2>/dev/null || true
    return 0
  fi

  SSH_PORTS="$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | sort -u)"

  # ---- v4
  # Flushing a live chain fails open until the DROP rule is back, so leave an
  # intact chain alone instead of rebuilding it on every tick. A new SSH port
  # still forces a rebuild so a changed sshd_config cannot lock the host out.
  intact=1
  iptables -C OUTPUT -j OUC_LEAKGUARD 2>/dev/null || intact=0
  iptables -C OUC_LEAKGUARD -j DROP 2>/dev/null || intact=0
  iptables -C OUC_LEAKGUARD -o lo -j ACCEPT 2>/dev/null || intact=0
  iptables -C OUC_LEAKGUARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || intact=0
  iptables -C OUC_LEAKGUARD -p tcp --dport 22 -j ACCEPT 2>/dev/null || intact=0
  iptables -C OUC_LEAKGUARD -p tcp --sport 22 -j ACCEPT 2>/dev/null || intact=0
  iptables -C OUC_LEAKGUARD -o "$IFACE" -j ACCEPT 2>/dev/null || intact=0
  if [ "$IP6_OK" = "1" ]; then
    ip6tables -C OUTPUT -j OUC_LEAKGUARD 2>/dev/null || intact=0
    ip6tables -C OUC_LEAKGUARD -j DROP 2>/dev/null || intact=0
    ip6tables -C OUC_LEAKGUARD -o lo -j ACCEPT 2>/dev/null || intact=0
    ip6tables -C OUC_LEAKGUARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || intact=0
    ip6tables -C OUC_LEAKGUARD -p tcp --dport 22 -j ACCEPT 2>/dev/null || intact=0
    ip6tables -C OUC_LEAKGUARD -p tcp --sport 22 -j ACCEPT 2>/dev/null || intact=0
    ip6tables -C OUC_LEAKGUARD -o "$IFACE" -j ACCEPT 2>/dev/null || intact=0
  fi
  if [ "$intact" = "1" ]; then
    for p in $SSH_PORTS; do
      if [ -n "$p" ] && [ "$p" -gt 0 ] 2>/dev/null; then
        iptables -C OUC_LEAKGUARD -p tcp --dport "$p" -j ACCEPT 2>/dev/null || intact=0
        iptables -C OUC_LEAKGUARD -p tcp --sport "$p" -j ACCEPT 2>/dev/null || intact=0
        if [ "$IP6_OK" = "1" ]; then
          ip6tables -C OUC_LEAKGUARD -p tcp --dport "$p" -j ACCEPT 2>/dev/null || intact=0
          ip6tables -C OUC_LEAKGUARD -p tcp --sport "$p" -j ACCEPT 2>/dev/null || intact=0
        fi
      fi
    done
  fi
  [ "$intact" = "1" ] && return 0

  iptables  -N OUC_LEAKGUARD 2>/dev/null
  iptables  -F OUC_LEAKGUARD
  iptables  -A OUC_LEAKGUARD -o lo              -j ACCEPT
  iptables  -A OUC_LEAKGUARD -m state --state ESTABLISHED,RELATED -j ACCEPT

  # NEVER lock out SSH on port 22 or custom SSH ports
  iptables  -A OUC_LEAKGUARD -p tcp --dport 22 -j ACCEPT
  iptables  -A OUC_LEAKGUARD -p tcp --sport 22 -j ACCEPT
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
  if [ "$IP6_OK" != "1" ]; then
    return 0
  fi
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
for _ in 1 2 3 4 5 6; do
  w status >/dev/null 2>&1 && break
  sleep 10
done

while true; do
  # Guard/hop touch this file before rotating so a keeper tick cannot
  # reconnect the tunnel underneath them.
  if [ -f "$PAUSE_FILE" ]; then
    sleep "$TICK"
    continue
  fi
  ensure_connected || true
  ensure_guard
  sleep "$TICK"
done
