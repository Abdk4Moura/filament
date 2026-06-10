#!/usr/bin/env bash
# Robust-connection test driver. Rebuilds cleanly, resets state, runs scenarios,
# reports PASS/FAIL deterministically. Avoids the degraded one-off-command traps:
# explicit cwd for cargo, self-safe kill (excludes this script + app.py), lock clear.
set -u
ROOT=/root/wt-transport
BIN=/root/.local/bin/filament

kill_filament() {
  python3 - <<'PY'
import os, glob
me = os.getpid()
for c in glob.glob('/proc/[0-9]*/cmdline'):
    try: cmd = open(c, 'rb').read().decode('latin1')
    except Exception: continue
    pid = int(c.split('/')[2])
    if pid != me and '/.local/bin/filament' in cmd and 'app.py' not in cmd:
        try: os.kill(pid, 9)
        except Exception: pass
PY
  rm -f /root/.config/filament/*.lock /root/.config/filament/daemon.* 2>/dev/null
}

rebuild() {
  echo "== rebuild =="
  ( cd "$ROOT/cli" && cargo build --release 2>&1 | grep -E "Finished|error" | tail -1 )
  cp "$ROOT/cli/target/release/filament" "$BIN"
  echo "installed: $("$BIN" --version 2>/dev/null | head -1)"
}

start_up() {  # $1 = log file
  kill_filament; sleep 2
  rm -f "$1"
  nohup env FILAMENT_L2=1 "$BIN" up >"$1" 2>&1 & disown
  for i in $(seq 1 25); do grep -qiE "trusted devices" "$1" 2>/dev/null && return 0; sleep 1; done
  echo "!! up failed to start: $(grep -ivE '█|▀|▄' "$1" | tail -1)"; return 1
}

SELF_IP=165.22.207.231  # do-vm's own external IP: a tunnel whose remote is
                        # SELF is the #9 self-connect trap, not a success.

tunnel_ok() {  # $1 = log file
  grep -q "tunnel up\|SSH-2" "$1" && ! grep -q "remote=$SELF_IP\|remote=127\." "$1"
}

netcat_once() {  # returns 0 on connect
  echo | timeout 16 "$BIN" netcat pop2 22 >/tmp/rt-nc.log 2>&1
  tunnel_ok /tmp/rt-nc.log
}

scenario_repeat() {  # $1 = count — flakiness check
  echo "== scenario: $1x sequential netcat (flakiness) =="
  start_up /tmp/rt-up.log || return 1
  sleep 3
  local ok=0
  for n in $(seq 1 "$1"); do
    if netcat_once; then ok=$((ok+1)); printf "."; else printf "x"; fi
    sleep 1
  done
  echo ""
  echo "  RESULT single-connect: $ok/$1 $([ "$ok" -eq "$1" ] && echo PASS || echo FAIL)"
  kill_filament
  [ "$ok" -eq "$1" ]
}

POP="tailscale ssh agboola@pop-os"

# -x: match the process NAME only. A -f pattern would match the tailscale ssh
# wrapper's own embedded command line and kill the session mid-flight (255).
pop_up_restart() {
  $POP "bash -c 'pkill -9 -x filament; sleep 1; rm -f /tmp/fil-up.log \$HOME/.config/filament/*.lock; setsid nohup env FILAMENT_L2=1 \$HOME/.local/bin/filament up >/tmp/fil-up.log 2>&1 </dev/null & sleep 5; pgrep -x filament | wc -l'" 2>/dev/null | tail -1
}

pop_up_kill() {
  $POP "bash -c 'pkill -9 -x filament; sleep 1'" >/dev/null 2>&1
}

scenario_ghost() {  # connect with a freshly killed netcat's sid still on the channel
  echo "== scenario: ghost (SIGKILL'd netcat litters the channel, then connect) =="
  start_up /tmp/rt-up.log || return 1
  sleep 3
  local ok=0
  for n in 1 2 3; do
    timeout -s KILL 3 "$BIN" netcat pop2 22 >/dev/null 2>&1  # dies mid-handshake -> ghost sid
    if netcat_once; then ok=$((ok+1)); printf "."; else printf "x"; fi
  done
  echo ""
  echo "  RESULT ghost: $ok/3 $([ $ok -eq 3 ] && echo PASS || echo FAIL)"
  kill_filament
  [ $ok -eq 3 ]
}

scenario_multi() {  # two initiators at once; both must tunnel
  echo "== scenario: multi-client (2 simultaneous netcats) =="
  start_up /tmp/rt-up.log || return 1
  sleep 3
  ( echo | timeout 25 "$BIN" netcat pop2 22 >/tmp/rt-nc1.log 2>&1 ) &
  local p1=$!
  ( echo | timeout 25 "$BIN" netcat pop2 22 >/tmp/rt-nc2.log 2>&1 ) &
  local p2=$!
  wait $p1 $p2
  local ok=0
  tunnel_ok /tmp/rt-nc1.log && ok=$((ok+1))
  tunnel_ok /tmp/rt-nc2.log && ok=$((ok+1))
  echo "  RESULT multi: $ok/2 $([ $ok -eq 2 ] && echo PASS || echo FAIL)"
  kill_filament
  [ $ok -eq 2 ]
}

scenario_latejoin() {  # initiator first, acceptor comes up late
  echo "== scenario: late-join (netcat waits, pop-os up starts 6s later) =="
  start_up /tmp/rt-up.log || return 1
  pop_up_kill
  ( echo | timeout 40 "$BIN" netcat pop2 22 >/tmp/rt-nc.log 2>&1 ) &
  local ncpid=$!
  sleep 6
  pop_up_restart >/dev/null
  wait $ncpid
  if tunnel_ok /tmp/rt-nc.log; then
    echo "  RESULT late-join: PASS"; kill_filament; return 0
  fi
  echo "  RESULT late-join: FAIL"; kill_filament; return 1
}

scenario_suite() {
  local fails=0
  scenario_repeat "${1:-10}" || fails=$((fails+1))
  scenario_ghost   || fails=$((fails+1))
  scenario_multi   || fails=$((fails+1))
  scenario_latejoin || fails=$((fails+1))
  echo ""
  if [ $fails -eq 0 ]; then echo "== SUITE: ALL PASS =="; else echo "== SUITE: $fails scenario(s) FAILED =="; fi
  return $fails
}

case "${1:-all}" in
  rebuild) rebuild ;;
  repeat)  rebuild; scenario_repeat "${2:-10}" ;;
  noredeploy) scenario_repeat "${2:-10}" ;;  # skip rebuild, test current binary
  ghost)   scenario_ghost ;;
  multi)   scenario_multi ;;
  latejoin) scenario_latejoin ;;
  suite)   scenario_suite "${2:-10}" ;;      # full PASS/FAIL gate, current binary
  all)     rebuild; scenario_repeat "${2:-10}" ;;
esac
