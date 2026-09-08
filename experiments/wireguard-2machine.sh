#!/usr/bin/env bash
# WIREGUARD DATA PLANE between two REAL machines, over the real internet.
#
# WHAT THIS PROVES. wg.rs sat in the tree with ZERO callers because nothing could
# exercise it: it needs the kernel module, CAP_NET_ADMIN, and two daemons that
# have already authenticated to each other and can exchange keys over their own
# QUIC connection. This builds exactly that across the internet and asks the only
# question that settles it: did a WireGuard HANDSHAKE complete? An interface that
# exists but never handshakes has carried nothing, so "the interface is there" is
# not the test.
#
# Each daemon runs in a network namespace because l3::ifname() is a const, so a
# second daemon on a host that already runs one cannot get its own kernel TUN.
#
# AND THE NAMESPACE'S WIREGUARD PORT IS FORWARDED IN. An earlier version of this
# rig gave the namespaces outbound NAT and nothing else, so WireGuard's port had
# no inbound mapping and kernel-to-kernel could never handshake. I read that as a
# property of the system and reported it as one; it was a property of this file.
# Both machines have PUBLIC IPs, and plain kernel WireGuard between them
# handshakes in seconds. The DNAT below restores that, so the namespace behaves
# like the host it stands in for instead of like a machine behind CGNAT.
set -uo pipefail
# PINNED OUT OF THE SHARED CARGO_TARGET_DIR: a concurrent build in another
# checkout has silently replaced a rig binary mid-run before, which makes every
# number after it a measurement of something else.
BIN=${FILAMENT_BIN:-/tmp/sr-bin/filament}
WANT_SHA=${WANT_SHA:-}
PEER=${PEER:-interserver-0x0}
LOCAL_BIN=${LOCAL_BIN:-$HOME/.local/bin/filament}   # drives the remote PTY
W=/tmp/wgx; MYNAME=wgx-owner
RBIN=/tmp/sr-peer-bin/filament; RDIR=/tmp/wgx-peer
FAIL=0

say()  { printf '\n=== %s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAIL=1; }

# Remote execution over filament's native PTY.
# SENTINEL-DELIMITED, not tail -1: a PTY echoes the command and the prompt, so
# positional extraction reads the prompt as the answer.
# CR STRIPPED: a PTY sends CRLF, so "UNREACHABLE\r" != "UNREACHABLE" and every
# string test silently inverts. Both of these actually happened here.
rsh() {
  local out
  out=$(printf 'echo __B__; %s; echo __E__\nexit\n' "$1" \
        | timeout "${2:-90}" "$LOCAL_BIN" shell "$PEER" 2>&1 \
        | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\x1b\]3008;[^\\]*\\//g; s/\r//g')
  printf '%s\n' "$out" | awk '/__B__/{f=1;next} /__E__/{f=0} f' | grep -vE '^\s*$'
}
# NEVER `export` FILAMENT_CONFIG_DIR: rsh drives the REAL local filament, the
# only thing that can reach the peer at all. Pointing it at the throwaway config
# breaks every remote step in a way that looks like a network fault.
own() { ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" "$BIN" "$@"; }

# Kill test daemons BY EXECUTABLE. FILAMENT_CONFIG_DIR is an env var and never
# appears in /proc/<pid>/cmdline, so matching on the config dir killed nothing
# and every aborted run leaked a live daemon; three had piled up before a
# "Text file busy" on rebuild gave it away. Matching the exe path also cannot
# hit either machine's real daemon, which runs a different binary.
kill_local()  { for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
                  [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$BIN" ] && kill "$p" 2>/dev/null
                done; return 0; }
KILL_REMOTE="for p in \$(ls /proc 2>/dev/null | grep -E '^[0-9]+\$'); do [ \"\$(readlink /proc/\$p/exe 2>/dev/null)\" = \"$RBIN\" ] && kill \$p 2>/dev/null; done"

cleanup() {
  say "cleanup"
  kill_local
  ip netns del srr 2>/dev/null; ip link del srr-h 2>/dev/null
  iptables -t nat -D POSTROUTING -s 10.77.0.0/24 ! -o srr-h -j MASQUERADE 2>/dev/null
  iptables -D FORWARD -i srr-h -j ACCEPT 2>/dev/null
  iptables -D FORWARD -o srr-h -j ACCEPT 2>/dev/null
  iptables -t nat -D PREROUTING -p udp --dport 51820 -j DNAT --to-destination 10.77.0.2:51820 2>/dev/null
  rm -rf /etc/netns/srr
  rsh "$KILL_REMOTE
       ip netns del srp 2>/dev/null; ip netns del srlan 2>/dev/null
       ip link del srp-h 2>/dev/null
       iptables -t nat -D POSTROUTING -s 10.88.0.0/24 ! -o srp-h -j MASQUERADE 2>/dev/null
       iptables -D FORWARD -i srp-h -j ACCEPT 2>/dev/null
       iptables -D FORWARD -o srp-h -j ACCEPT 2>/dev/null
       iptables -t nat -D PREROUTING -p udp --dport 51820 -j DNAT --to-destination 10.88.0.2:51820 2>/dev/null
       rm -rf $RDIR /etc/netns/srp; echo remote-clean" 120 >/dev/null 2>&1
  echo "  local and remote state removed"
}
[ "${KEEP:-0}" = "1" ] || trap cleanup EXIT

[ -x "$BIN" ] || { echo "SETUP: no binary at $BIN"; exit 2; }
GOT_SHA=$(sha256sum "$BIN" | cut -d' ' -f1)
if [ -n "$WANT_SHA" ] && [ "$GOT_SHA" != "$WANT_SHA" ]; then
  echo "SETUP: binary hash $GOT_SHA != expected $WANT_SHA"; exit 2
fi
cleanup >/dev/null 2>&1
rm -rf "$W"; mkdir -p "$W/rtr"
say "binary: $("$BIN" --version)  sha ${GOT_SHA:0:16}"


say "1. receiver namespace (owner side, its own filament0)"
sysctl -qw net.ipv4.ip_forward=1
ip netns add srr
ip link add srr-h type veth peer name srr-n && ip link set srr-n netns srr
ip addr add 10.77.0.1/24 dev srr-h && ip link set srr-h up
ip netns exec srr ip addr add 10.77.0.2/24 dev srr-n
ip netns exec srr ip link set srr-n up && ip netns exec srr ip link set lo up
ip netns exec srr ip route add default via 10.77.0.1
mkdir -p /etc/netns/srr && echo "nameserver 1.1.1.1" > /etc/netns/srr/resolv.conf
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o srr-h -j MASQUERADE
iptables -I FORWARD 1 -i srr-h -j ACCEPT
iptables -I FORWARD 1 -o srr-h -j ACCEPT
# WireGuard's registered port, forwarded into the namespace: this is what makes
# the endpoint reachable, as it would be on a host with a public IP.
iptables -t nat -A PREROUTING -p udp --dport 51820 -j DNAT --to-destination 10.77.0.2:51820
ip netns exec srr getent hosts api.filament.autumated.com >/dev/null 2>&1 \
  && ok "receiver namespace has internet" || { echo "SETUP: no internet in receiver ns"; exit 2; }

say "2. router namespace on the remote machine"
rsh "sysctl -qw net.ipv4.ip_forward=1
     ip netns add srp
     ip link add srp-h type veth peer name srp-n && ip link set srp-n netns srp
     ip addr add 10.88.0.1/24 dev srp-h && ip link set srp-h up
     ip netns exec srp ip addr add 10.88.0.2/24 dev srp-n
     ip netns exec srp ip link set srp-n up && ip netns exec srp ip link set lo up
     ip netns exec srp ip route add default via 10.88.0.1
     mkdir -p /etc/netns/srp && echo 'nameserver 1.1.1.1' > /etc/netns/srp/resolv.conf
     iptables -t nat -A POSTROUTING -s 10.88.0.0/24 ! -o srp-h -j MASQUERADE
     iptables -I FORWARD 1 -i srp-h -j ACCEPT
     iptables -I FORWARD 1 -o srp-h -j ACCEPT
     iptables -t nat -A PREROUTING -p udp --dport 51820 -j DNAT --to-destination 10.88.0.2:51820
     mkdir -p $RDIR" 180 >/dev/null
RNET=$(rsh "ip netns exec srp getent hosts api.filament.autumated.com >/dev/null 2>&1 && echo OK || echo FAIL" 90 | tail -1)
[ "$RNET" = "OK" ] && ok "router namespace has internet" || { echo "SETUP: no internet in router ns"; exit 2; }

say "1. namespaces on both machines"
sysctl -qw net.ipv4.ip_forward=1
ip netns add srr
ip link add srr-h type veth peer name srr-n && ip link set srr-n netns srr
ip addr add 10.77.0.1/24 dev srr-h && ip link set srr-h up
ip netns exec srr ip addr add 10.77.0.2/24 dev srr-n
ip netns exec srr ip link set srr-n up && ip netns exec srr ip link set lo up
ip netns exec srr ip route add default via 10.77.0.1
mkdir -p /etc/netns/srr && echo "nameserver 1.1.1.1" > /etc/netns/srr/resolv.conf
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o srr-h -j MASQUERADE
iptables -I FORWARD 1 -i srr-h -j ACCEPT
iptables -I FORWARD 1 -o srr-h -j ACCEPT
ip netns exec srr getent hosts api.filament.autumated.com >/dev/null 2>&1 \
  && ok "local namespace has internet" || { echo "SETUP: no internet locally"; exit 2; }
rsh "sysctl -qw net.ipv4.ip_forward=1
     ip netns add srp
     ip link add srp-h type veth peer name srp-n && ip link set srp-n netns srp
     ip addr add 10.88.0.1/24 dev srp-h && ip link set srp-h up
     ip netns exec srp ip addr add 10.88.0.2/24 dev srp-n
     ip netns exec srp ip link set srp-n up && ip netns exec srp ip link set lo up
     ip netns exec srp ip route add default via 10.88.0.1
     mkdir -p /etc/netns/srp && echo 'nameserver 1.1.1.1' > /etc/netns/srp/resolv.conf
     iptables -t nat -A POSTROUTING -s 10.88.0.0/24 ! -o srp-h -j MASQUERADE
     iptables -I FORWARD 1 -i srp-h -j ACCEPT
     iptables -I FORWARD 1 -o srp-h -j ACCEPT
     mkdir -p $RDIR" 200 >/dev/null
R=$(rsh "ip netns exec srp getent hosts api.filament.autumated.com >/dev/null 2>&1 && echo OK || echo FAIL" 90 | tail -1)
[ "$R" = "OK" ] && ok "remote namespace has internet" || { echo "SETUP: no internet remotely"; exit 2; }
RW=$(rsh "command -v wg >/dev/null && echo OK || echo FAIL" 90 | tail -1)
[ "$RW" = "OK" ] && ok "remote has wireguard-tools" || { echo "SETUP: remote lacks wireguard-tools"; exit 2; }

say "2. owner up, with the WireGuard plane on"
own init --yes --name "$MYNAME" --recovery-file "$W/rec" 2>&1 | tail -1
own set wireguard on 2>&1 | tail -1
ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" FILAMENT_LOG="${FLOG:-info}" setsid nohup "$BIN" up --name-as "$MYNAME" >"$W/rtr.log" 2>&1 &
for i in $(seq 1 45); do grep -q "L3 overlay" "$W/rtr.log" 2>/dev/null && break; sleep 2; done
grep -q userspace "$W/rtr.log" && { echo "SETUP: userspace overlay, no kernel TUN"; exit 2; }
ok "owner up with a kernel filament0"

say "3. peer joins, with the WireGuard plane on"
rm -f "$W/inv.txt"
own add --for "$PEER" --allow transfer,mount --out "$W/inv.txt" --yes 2>&1 | tail -1
[ -s "$W/inv.txt" ] || { echo "SETUP: no invitation"; exit 2; }
INV=$(cat "$W/inv.txt")
rsh "umask 077; printf '%s' '$INV' > $RDIR/inv.txt; chmod 600 $RDIR/inv.txt" 90 >/dev/null
rsh "setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN join $RDIR/inv.txt --yes; ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN set wireguard on; ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR FILAMENT_LOG=debug $RBIN up' >$RDIR/up.log 2>&1 & echo started" 90 >/dev/null
J=0
for i in $(seq 1 25); do
  J=$(rsh "grep -c 'joined as' $RDIR/up.log 2>/dev/null || echo 0" 60 | tail -1)
  [ "${J:-0}" != "0" ] && break; sleep 8
done
[ "${J:-0}" != "0" ] && ok "peer joined" || { bad "peer never joined"; rsh "tail -6 $RDIR/up.log" 90; exit 1; }

say "4. wait for the link to go direct and the reconcile to fire"
# The reconcile ticks every 10s and only acts on a DIRECT link, so allow several
# ticks plus the relay-to-direct upgrade.
for i in $(seq 1 30); do
  ip netns exec srr wg show filament-wg latest-handshakes 2>/dev/null | awk '$2>0' | grep -q . && break
  sleep 8
done
grep -E "WireGuard|DIRECT-CONNECT" "$W/rtr.log" | tail -3 | sed 's/^/    /'

say "5. is there a tunnel, and has it handshaken?"
if ip netns exec srr wg show filament-wg >/dev/null 2>&1; then
  ok "filament-wg exists on the owner"
  P=$(ip netns exec srr wg show filament-wg peers 2>/dev/null | wc -l)
  echo "  peers: $P"
  ip netns exec srr wg show filament-wg 2>/dev/null | grep -E "endpoint|allowed ips|handshake|transfer" | sed 's/^/    /'
  [ "${P:-0}" -ge 1 ] && ok "a peer is configured" || bad "no peer on the interface"
  # WHICH PATH won matters as much as whether one did: a 127.0.0.1 endpoint means
  # frames are taking a userspace hop through filament, which is the thing kernel
  # WireGuard is meant to avoid.
  EP=$(ip netns exec srr wg show filament-wg endpoints 2>/dev/null | awk '{print $2}' | head -1)
  case "$EP" in
    127.0.0.1:*) echo "  path: RELAY (via filament transport, one userspace hop)" ;;
    "")          echo "  path: unknown (no endpoint)" ;;
    *)           echo "  path: DIRECT kernel-to-kernel ($EP)" ;;
  esac
  # The difference between configured and WORKING.
  # Require a line AND a non-zero timestamp: with no peers this command prints
  # nothing, awk sees no input and exits 0, so the old check PASSED on an empty
  # interface. A vacuous assertion is worse than no assertion.
  if [ "$(ip netns exec srr wg show filament-wg latest-handshakes 2>/dev/null | awk '$2>0' | wc -l)" -ge 1 ]; then
    ok "WireGuard handshake completed: the tunnel is live"
  else
    bad "no handshake: configured but carrying nothing"
  fi
else
  bad "no filament-wg interface"
fi

say "RESULT"
if [ "$FAIL" = "0" ]; then
  echo "  ALL CHECKS PASSED"
  echo "  A WireGuard tunnel between two machines, keyed over filament's own"
  echo "  authenticated QUIC connection, with a completed handshake."
else
  echo "  SOME CHECKS FAILED"
  echo "  --- owner log:"; grep -E "WireGuard|DIRECT|L3 peer" "$W/rtr.log" | tail -8 | sed 's/^/  /'
  echo "  --- peer log:";  rsh "grep -E 'WireGuard|DIRECT|L3 peer' $RDIR/up.log | tail -8" 90 | sed 's/^/  /'
fi
exit "$FAIL"
