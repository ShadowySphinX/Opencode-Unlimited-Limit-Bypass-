#!/bin/bash
# zen guard - watches OpenCode's error log for the free-usage wall and
# rotates your /64 automatically.
#
# opencode writes its errors to ~/.local/share/opencode/log/opencode.log -
# we tail it with a byte offset and only read new bytes. When a quota error
# appears:
#   1. current /64 goes on the blacklist
#   2. keeper pauses (its tick would race the rotation)
#   3. warp renews its WireGuard session keys → fresh /64 → keeper resumes
#   4. if cloudflare returns a blacklisted block, try again (up to 4)
#   5. if all retries return blacklisted blocks, recycle the oldest entry
# after a successful rotation, re-send your message.
set -u

LOGF="$HOME/.local/share/opencode/log/opencode.log"
DEST="${OUC_DEST:-${XDG_DATA_HOME:-$HOME/.local/share}/opencode-unlimited}"
STATE_DIR="$DEST/guard"
STATE="$STATE_DIR/state.json"
GUARD_LOG="$STATE_DIR/guard.log"
PAUSE_FILE="${OUC_PAUSE_FILE:-$DEST/keeper.pause}"

# warp binary: service env → PATH → common fallbacks. probe with/without
# --accept-tos (shimmed boxes pass it twice = dead CLI).
WARP="${OUC_WARP_BIN:-}"
if [ -z "$WARP" ]; then
  if command -v warp-cli >/dev/null 2>&1; then WARP="$(command -v warp-cli)"
  elif [ -x /usr/bin/warp-cli ]; then WARP=/usr/bin/warp-cli
  elif [ -x "$HOME/.local/bin/warp-cli" ]; then WARP="$HOME/.local/bin/warp-cli"
  fi
fi
[ -n "$WARP" ] || { echo "warp-cli not found"; exit 1; }
KEEPER="${OUC_KEEPER_UNIT:-opencode-unlimited-keeper}"

# Keep the installer's isolated proxy mode unless the user deliberately
# selected TUN. A wrong mode here can silently move traffic out of WARP.
MODE="${OUC_WARP_MODE:-proxy}"

COOLDOWN=75        # seconds between rotations (a rotation takes ~15s)
WALL_RE='QuotaExceeded|quota_exceeded|FreeUsageLimitError|Free usage limit|usage limit reached|Rate limit|rate_limit|too many requests|status=429|"status":429|credits exhausted|free-tier usage'
MAX_HOP_TRIES=4
BLACKLIST_MAX=200  # blacklist cap; oldest entries are recycled when full

mkdir -p "$STATE_DIR"

# The guard is an unprivileged user service. Never fall back to interactive
# sudo here: with no TTY it hangs and the keeper races the rotation.
svc(){ sudo -n systemctl "$@" >/dev/null 2>&1; }
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

glog(){ echo "$(date '+%m-%d %H:%M:%S') $*" >> "$GUARD_LOG"; }

state_get(){ python3 -c "
import json
try: d=json.load(open('$STATE'))
except: d={'blacklist':[],'offset':0,'last_hop':0,'hops':0,'current':''}
print(d.get('$1',''))" 2>/dev/null; }

state_set(){ python3 -c "
import ipaddress,json,sys
try: d=json.load(open('$STATE'))
except: d={'blacklist':[],'offset':0,'last_hop':0,'hops':0,'current':''}
d['$1']=sys.argv[1]
json.dump(d,open('$STATE','w'))" "$2" 2>/dev/null; }

USE_PROXY=0
if [ "$MODE" != "warp" ] || [ -f /etc/opencode-unlimited-vps.flag ] || [ -f "$DEST/vps.flag" ]; then
  USE_PROXY=1
fi

cur_v6(){
  local v ep
  # The address that matters is the one opencode.ai sees. Another Cloudflare
  # host can answer from a different address and make a rotation that changed
  # nothing look successful.
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

# blacklist entries are /64-normalized so the same block cannot return with
# a different interface ID (or compressed spelling) and pass the check.
blacklist_add(){
  [ -n "$1" ] || return 0
  python3 - "$1" "$STATE" <<'PY' 2>/dev/null
import ipaddress,json,sys
def m64(a):
    try: return str(ipaddress.IPv6Network((ipaddress.IPv6Address(a), 64), strict=False).network_address)
    except Exception: return ""
p=sys.argv[2]
try: d=json.load(open(p))
except: d={"blacklist":[],"offset":0,"last_hop":0,"hops":0,"current":""}
m=m64(sys.argv[1])
if m:
    d["blacklist"]=[x for x in d["blacklist"] if x and m64(x)!=m]+[m]
    d["blacklist"]=d["blacklist"][-200:]
json.dump(d,open(p,"w"))
PY
}

is_burnt(){
  python3 - "$1" "$STATE" <<'PY' 2>/dev/null
import ipaddress,json,sys
def m64(a):
    try: return str(ipaddress.IPv6Network((ipaddress.IPv6Address(a), 64), strict=False).network_address)
    except Exception: return ""
try: d=json.load(open(sys.argv[2]))
except: sys.exit(1)
m=m64(sys.argv[1])
sys.exit(0 if any(x and m64(x)==m for x in d.get("blacklist",[])) else 1)
PY
}

keeper_pause(){
  touch "$PAUSE_FILE" 2>/dev/null || true
  svc stop "$KEEPER" || glog "keeper stop not permitted; pause file holds the next tick"
}

keeper_resume(){
  rm -f "$PAUSE_FILE" 2>/dev/null || true
  svc start "$KEEPER" || true
}

hop_once(){
  # one non-destructive session rotation. prints the new IPv6 or empty.
  local old="$1" v=""
  keeper_pause
  w disconnect

  # Recreate a registration only when it is actually missing.
  if ! wo registration show >/dev/null 2>&1; then
    for _ in 1 2 3; do
      w registration new && break
      sleep 4
    done
  fi

  # rotate-keys keeps the device registration and renews the WireGuard
  # session, so Cloudflare assigns a new client /64.
  w tunnel rotate-keys
  set_mode
  w connect

  for _ in $(seq 1 10); do
    sleep 2
    v=$(cur_v6)
    case "$v" in
      *:*)
        if [ -z "$old" ] || [ "$(m64 "$v")" != "$(m64 "$old")" ]; then
          keeper_resume
          echo "$v"
          return
        fi
        ;;
    esac
    v=""
  done

  keeper_resume
  echo ""
}

# fresh state: start reading from the end of the current log
if [ ! -f "$STATE" ]; then
  OFF=0; [ -f "$LOGF" ] && OFF=$(wc -c < "$LOGF")
  printf '{"blacklist":[],"offset":%s,"last_hop":0,"hops":0,"current":""}' "$OFF" > "$STATE"
fi

glog "zen-guard up (cooldown ${COOLDOWN}s, blacklist cap ${BLACKLIST_MAX})"

while true; do
  sleep 20

  # ---- wall sniff (new bytes only) ----
  [ -f "$LOGF" ] || continue
  SIZE=$(wc -c < "$LOGF" 2>/dev/null || echo 0)
  OFF=$(state_get offset); OFF=${OFF:-0}
  PREV_OFF="$OFF"
  NEWBYTES=$((SIZE - OFF))
  WALL=0
  WALL_SID=""
  if [ "$NEWBYTES" -gt 0 ] && [ "$NEWBYTES" -lt 50000000 ]; then
    NEW_TEXT=$(tail -c +"$((OFF + 1))" "$LOGF" 2>/dev/null)
    if echo "$NEW_TEXT" | grep -E -aqi "$WALL_RE"; then
      WALL=1
      # Resume the exact chat that hit the wall: `run --continue` is scoped to
      # the guard's working directory and can land in a different project.
      # Only the wall lines carry the session that was refused; other lines in
      # the same chunk may name an unrelated session.
      WALL_SID=$(echo "$NEW_TEXT" | grep -aiE "$WALL_RE" | grep -aioE 'sessionID=ses_[A-Za-z0-9]+' | tail -n 1 | cut -d= -f2)
    fi
  fi
  state_set offset "$SIZE"

  NOW=$(date +%s)
  LASTHOP=$(state_get last_hop); LASTHOP=${LASTHOP:-0}
  AGE=$((NOW - LASTHOP))

  if [ "$WALL" = 1 ] && [ "$AGE" -ge "$COOLDOWN" ]; then
    OLD=$(cur_v6)
    glog "wall detected - rotating (was: ${OLD:-?})"
    blacklist_add "$OLD"
    NEW=""
    TRY=0
    while [ "$TRY" -lt "$MAX_HOP_TRIES" ]; do
      TRY=$((TRY + 1))
      V=$(hop_once "$OLD")
      if [ -z "$V" ]; then glog "try $TRY: rotation produced no fresh /64"; continue; fi
      if is_burnt "$V"; then glog "try $TRY: cloudflare returned a blacklisted /64 ($V) - again"; continue; fi
      NEW="$V"; break
    done
    # every block burned → recycle the oldest blacklist entry
    if [ -z "$NEW" ]; then
      glog "everything blacklisted - recycling oldest block"
      V=$(hop_once "$OLD")
      [ -n "$V" ] && NEW="$V"
    fi
    if [ -n "$NEW" ]; then
      state_set last_hop "$NOW"
      state_set current "$NEW"
      H=$(state_get hops); H=${H:-0}; H=$((H + 1))
      state_set hops "$H"
      glog "rotated #$H: $OLD → $NEW"
      python3 -c "
import sqlite3, os
from pathlib import Path
for db in [Path.home() / '.config' / 'ai.opencode.desktop' / 'drafts.sqlite', Path.home() / '.local' / 'share' / 'opencode' / 'drafts.sqlite']:
    if db.is_file():
        try:
            c = sqlite3.connect(str(db), timeout=5.0)
            c.execute(\"DELETE FROM state WHERE key IN ('free-limit', 'go-upsell', 'free_usage_limit', 'usage_limit', 'quota_exceeded')\")
            c.commit(); c.close()
        except: pass
" 2>/dev/null || true
      sleep 2
      if command -v opencode >/dev/null 2>&1; then
        RESUME_LOG="$STATE_DIR/auto-resume.log"
        if [ -n "$WALL_SID" ]; then
          nohup opencode run --session "$WALL_SID" "continue" >>"$RESUME_LOG" 2>&1 </dev/null &
          glog "[auto-resume] sent 'continue' to $WALL_SID (log: $RESUME_LOG)"
        else
          nohup opencode run --continue "continue" >>"$RESUME_LOG" 2>&1 </dev/null &
          glog "[auto-resume] sent 'continue' to the last session (no sessionID in wall line)"
        fi
      fi
    else
      # Keep the wall pending so the next tick retries instead of losing it.
      state_set offset "$PREV_OFF"
      glog "rotation failed - keeper will keep the tunnel alive, retrying next tick"
    fi
  elif [ "$WALL" = 1 ]; then
    state_set offset "$PREV_OFF"
    glog "wall seen but in cooldown (${AGE}s < ${COOLDOWN}s) - waiting"
  fi
done
