#!/bin/bash
# zen lane — the actual trick.
#
# opencode's free wall is keyed on what their server sees:
#   (your IPv6 /64 block) x (which cloudflare edge you land on)
# warp gives you a fresh /64 on every registration, and opencode.ai has
# several IPv6 edges. so:
#   - pin opencode.ai to ONE random edge from the live AAAA pool (per launch)
#   - force the request out over IPv6 (AAAA-only bind inside a namespace)
#   - fresh random machine-id for good measure
# every launch = fresh combo = fresh quota bucket.
#
# all of this happens inside a mount namespace (unshare). your real
# /etc/hosts and /etc/machine-id are never touched. process dies →
# namespace evaporates → no trace.
set -u

REAL="${OUC_REAL_BIN:-$HOME/.opencode/bin/opencode}"

if [ ! -x "$REAL" ]; then
  for c in "$HOME/.local/bin/opencode" /usr/local/bin/opencode /usr/bin/opencode; do
    [ -x "$c" ] && [ "$c" != "$(readlink -f "$0" 2>/dev/null)" ] && REAL="$c" && break
  done
fi
[ -x "$REAL" ] || { echo "opencode binary not found — set OUC_REAL_BIN or reinstall"; exit 1; }

# ---- pick a random edge from the live AAAA pool
# note: strict hex-colon regex on dig output — dig's error lines also contain
# colons and will happily poison the pool if you're lazy about the grep
AAAA_POOL=$(dig +short AAAA opencode.ai @1.1.1.1 2>/dev/null | grep -E '^[0-9A-Fa-f:]+$' | sort -u)
[ -z "$AAAA_POOL" ] && AAAA_POOL=$(python3 -c "
import socket
print('\n'.join({i[4][0] for i in socket.getaddrinfo('opencode.ai',443,socket.AF_INET6)}))" 2>/dev/null)
# last resort: known cloudflare literals (verified working at time of writing)
[ -z "$AAAA_POOL" ] && AAAA_POOL="2606:4700:10::ac42:ad95
2606:4700:10::ac42:ad96
2606:4700:10::6814:2011"
AAAA=$(echo "$AAAA_POOL" | shuf -n 1)

# namespace scratch space
TD=$(mktemp -d /tmp/ouc-lane.XXXXXX 2>/dev/null || { mkdir -p /tmp/opencode-unlimited; mktemp -d /tmp/opencode-unlimited/lane.XXXXXX; })
trap 'rm -rf "$TD"' EXIT

# opencode.ai → chosen edge, IPv6 only. if the host can't do v6 to that edge
# the request just fails — better a failure than a silent home-IP leak.
printf '%s opencode.ai\n%s www.opencode.ai\n%s api.opencode.ai\n' "$AAAA" "$AAAA" "$AAAA" > "$TD/hosts"

# random machine-id (some endpoints sniff it; fresh per launch costs nothing)
tr -dc 'a-f0-9' < /dev/urandom | head -c 32 > "$TD/machine-id"

# ---- launch the real binary inside the namespace
exec unshare -rm bash -c '
  mount --bind "$1/hosts"      /etc/hosts
  mount --bind "$1/machine-id" /etc/machine-id
  exec "$2" "${@:3}"
' _ "$TD" "$REAL" "$@"
