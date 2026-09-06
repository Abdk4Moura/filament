#!/usr/bin/env bash
# Does the WireGuard data plane actually carry overlay traffic?
#
# WHY A RIG AND NOT A UNIT TEST. wg.rs shells out to `wg` and `ip`, needs the
# kernel module and CAP_NET_ADMIN, and only means anything once two daemons have
# authenticated to each other and exchanged keys over their QUIC connection.
# None of that is reachable from a unit test, and the module sat in the tree with
# ZERO callers for exactly that reason: nothing could prove it worked, so nothing
# depended on it.
#
# Two network namespaces on one host, because each daemon needs its own kernel
# filament0 (l3::ifname() is a const) and its own WireGuard device.
set -uo pipefail
BIN=${FILAMENT_BIN:-/tmp/wg-bin/filament}
W=/tmp/wg-e2e
FAIL=0
say() { printf '\n=== %s\n' "$*"; }
ok()  { printf '  PASS  %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAIL=1; }

ns_setup() { # $1=ns $2=hostveth $3=subnet-third-octet
  ip netns del "$1" 2>/dev/null; ip link del "$2" 2>/dev/null
  ip netns add "$1"
  ip link add "$2" type veth peer name "$1-n" && ip link set "$1-n" netns "$1"
  ip addr add "10.90.$3.1/24" dev "$2" && ip link set "$2" up
  ip netns exec "$1" ip addr add "10.90.$3.2/24" dev "$1-n"
  ip netns exec "$1" ip link set "$1-n" up
  ip netns exec "$1" ip link set lo up
  ip netns exec "$1" ip route add default via "10.90.$3.1"
  mkdir -p "/etc/netns/$1" && echo "nameserver 1.1.1.1" > "/etc/netns/$1/resolv.conf"
  iptables -t nat -A POSTROUTING -s "10.90.$3.0/24" ! -o "$2" -j MASQUERADE
  iptables -I FORWARD 1 -i "$2" -j ACCEPT
  iptables -I FORWARD 1 -o "$2" -j ACCEPT
}
ns_teardown() { # $1=ns $2=hostveth $3=third octet
  for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$(readlink -f "$BIN")" ] && kill "$p" 2>/dev/null
  done
  ip netns del "$1" 2>/dev/null; ip link del "$2" 2>/dev/null
  iptables -t nat -D POSTROUTING -s "10.90.$3.0/24" ! -o "$2" -j MASQUERADE 2>/dev/null
  iptables -D FORWARD -i "$2" -j ACCEPT 2>/dev/null
  iptables -D FORWARD -o "$2" -j ACCEPT 2>/dev/null
  rm -rf "/etc/netns/$1"
}
cleanup() {
  say "cleanup"
  ns_teardown wga wga-h 1; ns_teardown wgb wgb-h 2
  ip link del filament-wg 2>/dev/null
  echo "  namespaces and interfaces removed"
}
[ "${KEEP:-0}" = "1" ] || trap cleanup EXIT

[ -x "$BIN" ] || { echo "SETUP: no binary at $BIN"; exit 2; }
command -v wg >/dev/null || { echo "SETUP: wireguard-tools missing"; exit 2; }
cleanup >/dev/null 2>&1
rm -rf "$W"; mkdir -p "$W/a" "$W/b"
sysctl -qw net.ipv4.ip_forward=1
say "binary: $("$BIN" --version)"

say "1. two namespaces, each with internet"
ns_setup wga wga-h 1; ns_setup wgb wgb-h 2
for n in wga wgb; do
  ip netns exec $n getent hosts api.filament.autumated.com >/dev/null 2>&1 \
    || { echo "SETUP: $n has no internet"; exit 2; }
done
ok "both namespaces resolve and route"

say "2. pair the two daemons, with the WireGuard plane enabled"
A="FILAMENT_CONFIG_DIR=$W/a"; B="FILAMENT_CONFIG_DIR=$W/b"
env $A "$BIN" init --yes --name wg-a --recovery-file "$W/a/rec" >/dev/null 2>&1
# NO init on B: `join` creates the identity, and running init first makes join
# refuse with "this device already has an identity". Same trap as the other rigs.
env $A "$BIN" set wireguard on >/dev/null 2>&1
env $B "$BIN" set wireguard on >/dev/null 2>&1
ip netns exec wga env $A FILAMENT_LOG=debug setsid nohup "$BIN" up --name-as wg-a >"$W/a.log" 2>&1 &
for i in $(seq 1 45); do grep -q "L3 overlay" "$W/a.log" 2>/dev/null && break; sleep 2; done
grep -q userspace "$W/a.log" && { echo "SETUP: A fell back to userspace (no kernel TUN)"; exit 2; }

rm -f "$W/inv.txt"
env $A "$BIN" add --for wg-b --allow transfer,mount --out "$W/inv.txt" --yes >/dev/null 2>&1
[ -s "$W/inv.txt" ] || { echo "SETUP: no invitation"; exit 2; }
# No --name-as on the JOIN: adding it stopped the enrolment dead at "invitation
# loaded". The device enrols under the machine hostname, which is why the
# assertion below counts a device rather than matching a name.
ip netns exec wgb env $B setsid nohup bash -c "\"$BIN\" join '$W/inv.txt' --yes; FILAMENT_LOG=debug \"$BIN\" up --name-as wg-b" >"$W/b.log" 2>&1 &
J=0
for i in $(seq 1 30); do
  J=$(grep -c "joined as" "$W/b.log" 2>/dev/null || echo 0)
  [ "${J:-0}" != "0" ] && break; sleep 4
done
# Assert on what the OWNER sees, not on a string in B's log: the log check
# passed once while B had not joined at all, because a substring matched in an
# error path. The device list is the fact.
# Count a device rather than match a name: the name depends on how the join was
# invoked, the FACT under test is that A gained a fleet member.
if [ "$(env $A "$BIN" devices 2>/dev/null | grep -cE '^\s+●')" -ge 1 ]; then
  ok "B joined A's fleet"
else
  bad "B never joined"; tail -8 "$W/b.log" | sed 's/^/    /'; exit 1
fi
# The reconcile runs on a 10s tick and both ends must rendezvous, so give it
# several ticks rather than one. Waiting is not the same as hoping: if it is not
# up after this, the check below says so.
sleep 70

say "3. did a WireGuard tunnel come up?"
for i in $(seq 1 10); do wg show filament-wg >/dev/null 2>&1 && break; sleep 6; done
grep -E "WireGuard" "$W/a.log" "$W/b.log" | tail -4 | sed 's/^/    /'
if wg show filament-wg >/dev/null 2>&1; then
  ok "filament-wg exists"
  PEERS=$(wg show filament-wg peers 2>/dev/null | wc -l)
  echo "  peers configured: $PEERS"
  wg show filament-wg 2>/dev/null | grep -E "peer|endpoint|allowed ips|transfer|handshake" | head -6 | sed "s/^/    /"
  [ "${PEERS:-0}" -ge 1 ] && ok "a peer is configured on the tunnel" || bad "interface exists but has no peer"
  # A tunnel with no handshake has carried nothing; this is the difference
  # between "configured" and "working".
  if wg show filament-wg latest-handshakes 2>/dev/null | awk '{exit ($2>0)?0:1}'; then
    ok "the tunnel completed a handshake (it is carrying traffic)"
  else
    bad "no WireGuard handshake: the interface is configured but dead"
  fi
else
  bad "no filament-wg interface; the plane did not come up"
fi

say "4. does overlay traffic still work?"
# The measurement that matters: whichever plane carried it, the mesh must work.
ADDR_B=$(env $B "$BIN" id --json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("overlay",""))' 2>/dev/null)
[ -n "$ADDR_B" ] || ADDR_B=$(grep -oE 'fdf1:[0-9a-f:]+' "$W/b.log" | head -1)
echo "  B overlay: ${ADDR_B:-<unknown>}"
if [ -n "$ADDR_B" ] && ip netns exec wga ping -c2 -W3 "$ADDR_B" >/dev/null 2>&1; then
  ok "A reaches B over the overlay"
else
  bad "A cannot reach B over the overlay"
fi

say "RESULT"
[ "$FAIL" = "0" ] && echo "  ALL CHECKS PASSED" || {
  echo "  SOME CHECKS FAILED"
  echo "  --- A log:"; tail -12 "$W/a.log" | sed 's/^/  /'
  echo "  --- B log:"; tail -12 "$W/b.log" | sed 's/^/  /'
}
exit "$FAIL"
