#!/usr/bin/env bash
# Filament — rung-2 UDP HOLE-PUNCH gates (FILAMENT_HOLEPUNCH=1).
#
# Validates rung-2 against REAL NAT in the stress-lab netns topology (NOT
# loopback — loopback cannot exercise NAT, and the symmetric→relay step-down
# needs real coturn). Modeled on run-matrix.sh.
#
# TWO gates (the step-down is as important as the success):
#   1. CONE pair (port-restricted both sides, Endpoint-Independent Mapping):
#      hole-punch SUCCEEDS → route: holepunched, byte-exact, NO relay.
#   2. SYMMETRIC pair (random-fully, Endpoint-Dependent Mapping):
#      hole-punch correctly FAILS → steps down to relay → route: relayed,
#      byte-exact.
# Each gate FIRST proves the topology's NAT type with natprobe.py, so the route
# assertion is honest.
#
# SAFETY: all networking confined to filtest-* netns (see lib.sh). The fixture
# backend runs in filtest-rdv:8099; the test coturn runs in filtest-wan on a
# lab-private IP. A single EXIT trap reaps every netns/veth and process.
#
# Run from cli/:  ./tests/holepunch-gates.sh
set -uo pipefail

LAB="${FILAMENT_LAB_DIR:-/root/wt-stress/cli/tests/transport-lab}"
source "$LAB/lib.sh"

HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PY="${LAB_PY:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"
BACKEND_PORT=8099
TURN_PORT=3478
TURN_SECRET="hpsecret-$RANDOM"
PROBE_PORT=19998
REFL2="198.18.0.3"          # second STUN-probe reflector (cone vs symmetric)
PAYLOAD_BYTES="${PAYLOAD_BYTES:-2097152}"   # 2 MiB
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-90}"
WAN_DELAY_MS="${WAN_DELAY_MS:-25}"          # netem RTT for the zero-RTT race
WORK="$(mktemp -d /root/.claude/jobs/330c2366/tmp/hp-gates.XXXXXX)"

PASS=0; FAIL=0; FAILED=""
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }
hashof() { sha256sum "$1" | cut -d' ' -f1; }

declare -a SPAWNED=()
TURN_CT=""; R1=""; R2=""
reap() {
  for p in "${SPAWNED[@]:-}"; do kill "$p" 2>/dev/null || true; done
  [ -n "$TURN_CT" ] && kill "$TURN_CT" 2>/dev/null || true
  [ -n "$R1" ] && kill "$R1" 2>/dev/null || true
  [ -n "$R2" ] && kill "$R2" 2>/dev/null || true
  lab_cleanup
  [ -n "${KEEP_WORK:-}" ] && echo "logs kept in $WORK" || rm -rf "$WORK"
}
trap reap EXIT INT TERM

[ -x "$BIN" ] || { echo "build first: cargo build --release ($BIN)"; exit 2; }
[ -x "$PY" ] || { echo "no python venv at $PY"; exit 2; }

lab_cleanup
lab_assert_clean || { echo "pre-flight: host not clean, aborting"; exit 2; }

# ---- backend + STUN/TURN in the lab ----------------------------------------
start_backend() {
  local ice; ice=$("$PY" "$LAB/iceconfig.py" "$STUN_IP" "$TURN_PORT" "$TURN_SECRET")
  local turn_urls="turn:$STUN_IP:$TURN_PORT,turn:$STUN_IP:$TURN_PORT?transport=tcp"
  nse "$RDV_NS" env \
      PORT=$BACKEND_PORT \
      FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
      FIL_ICE_SERVERS="$ice" \
      FIL_TURN_HOST="$turn_urls" FIL_TURN_SECRET="$TURN_SECRET" \
      "$PY" "$CLI_DIR/../backend/app.py" >"$WORK/backend.log" 2>&1 &
  SPAWNED+=($!)
  for _ in $(seq 1 40); do
    nse "$RDV_NS" curl -fsS "http://127.0.0.1:$BACKEND_PORT/api/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "backend did not come up"; tail -5 "$WORK/backend.log"; return 1
}

start_turn() {
  nse "$WAN_NS" turnserver -n \
      --listening-ip="$STUN_IP" --relay-ip="$STUN_IP" \
      --listening-port="$TURN_PORT" \
      --static-auth-secret="$TURN_SECRET" --realm=filament.test \
      --no-tls --no-dtls --no-cli \
      --allow-loopback-peers \
      --min-port=49200 --max-port=49300 \
      >"$WORK/turn.log" 2>&1 &
  TURN_CT=$!
  sleep 1
  nse "$WAN_NS" ss -ulnp 2>/dev/null | grep -q ":$TURN_PORT" \
    || { echo "turnserver did not bind"; tail -5 "$WORK/turn.log"; return 1; }
}

# ---- NAT-type probe (proves the topology before asserting the route) -------
# Returns "EIM-cone" or "EDM-symmetric" for client side A|B.
probe_mapping() {
  local cli_ns="$1"
  nse "$WAN_NS" ip addr add "$REFL2/32" dev lo 2>/dev/null || true
  nse "$WAN_NS" "$PY" "$LAB/natprobe.py" server "$STUN_IP" "$PROBE_PORT" & R1=$!
  nse "$WAN_NS" "$PY" "$LAB/natprobe.py" server "$REFL2" "$PROBE_PORT" & R2=$!
  sleep 0.5
  local out; out=$(nse "$cli_ns" "$PY" "$LAB/natprobe.py" client "$STUN_IP" "$REFL2" "$PROBE_PORT")
  kill "$R1" "$R2" 2>/dev/null || true; R1=""; R2=""
  echo "$out" | grep -oE "MAPPING=[A-Za-z-]+" | head -1 | cut -d= -f2
}

# ---- pair A<->B as known devices (over WebRTC, flag off) --------------------
# Mirrors transport-gates.sh: A remembers boxB, B remembers boxA. The pair
# secret + rendezvous identity land in each side's devices.json. Returns config
# dirs via globals PAIR_CFGA / PAIR_CFGB.
pair_devices() {
  local server="http://$RDV_IP:$BACKEND_PORT"
  local cfgA="$WORK/cfgA" cfgB="$WORK/cfgB"
  rm -rf "$cfgA" "$cfgB"; mkdir -p "$cfgA" "$cfgB"
  local pf="$WORK/pairsmall.bin"; head -c 4096 /dev/urandom >"$pf"
  local W="hp-pair-$RANDOM"
  nse "${LAB_PREFIX}-cliA" env FILAMENT_CONFIG_DIR="$cfgA" \
      "$BIN" send "$pf" --word "$W" --remember boxB --server "$server" \
      >"$WORK/pair-send.log" 2>&1 &
  local sp=$!
  sleep 3
  nse "${LAB_PREFIX}-cliB" env FILAMENT_CONFIG_DIR="$cfgB" \
      timeout 60 "$BIN" recv "$W" -y --remember boxA --dir "$WORK/pairout" --server "$server" \
      >"$WORK/pair-recv.log" 2>&1 || true
  kill "$sp" 2>/dev/null || true; wait "$sp" 2>/dev/null || true
  PAIR_CFGA="$cfgA"; PAIR_CFGB="$cfgB"
  [ -s "$cfgA/devices.json" ] && [ -s "$cfgB/devices.json" ]
}

# ---- one known-device transfer trial, return "route|hashok" ----------------
# Mirrors transport-gates.sh GATE 1: B runs `up` (known-device daemon), A does
# `send --to boxB`. The known-device rendezvous triggers start_direct -> the
# rung-1 -> rung-2 -> WebRTC ladder.
# run_known_transfer <extra_env> <tag>
run_known_transfer() {
  local extra_env="$1" tag="$2"
  local server="http://$RDV_IP:$BACKEND_PORT"
  local payload="$WORK/payload-$tag.bin" outdir="$WORK/out-$tag"
  mkdir -p "$outdir"
  head -c "$PAYLOAD_BYTES" /dev/urandom > "$payload"
  local want_hash; want_hash=$(hashof "$payload")
  # B: known-device daemon, listening.
  nse "${LAB_PREFIX}-cliB" env $extra_env FILAMENT_CONFIG_DIR="$PAIR_CFGB" \
      timeout "$CONNECT_TIMEOUT" "$BIN" up --dir "$outdir" --server "$server" \
      >"$WORK/recv-$tag.log" 2>&1 &
  local up=$!
  sleep 3
  # A: send to the known device boxB.
  nse "${LAB_PREFIX}-cliA" env $extra_env FILAMENT_CONFIG_DIR="$PAIR_CFGA" \
      timeout "$CONNECT_TIMEOUT" "$BIN" send "$payload" --to boxB --server "$server" \
      >"$WORK/send-$tag.log" 2>&1 || true
  sleep 1
  kill "$up" 2>/dev/null || true; wait "$up" 2>/dev/null || true

  local got; got=$(find "$outdir" -type f ! -name '*.part' ! -name '*.meta' | head -1)
  # Prefer the AUTHORITATIVE connect marker (DIRECT-CONNECT ok (route: X)) over
  # the UI line, then fall back to the UI route line for the WebRTC/relay case.
  local route
  route=$(grep -hoE "DIRECT-CONNECT ok \(route: (direct-quic|holepunched)\)" \
            "$WORK/send-$tag.log" "$WORK/recv-$tag.log" 2>/dev/null \
            | grep -oE "(direct-quic|holepunched)" | head -1)
  if [ -z "$route" ]; then
    route=$(grep -hoE "route: (local|direct-quic|holepunched|relayed|direct)" \
              "$WORK/send-$tag.log" "$WORK/recv-$tag.log" 2>/dev/null | head -1 | awk '{print $2}')
  fi
  [ -z "$route" ] && route="-"
  local hashok=no
  if [ -n "$got" ] && [ "$(hashof "$got")" = "$want_hash" ]; then hashok=yes; fi
  echo "$route|$hashok"
}

build_pair() {
  local a_type="$1" b_type="$2"
  lab_build_core
  start_backend || return 1
  start_turn || return 1
  lab_add_nat_client A "$a_type"
  lab_add_nat_client B "$b_type"
  # netem RTT on both routers — the zero-RTT mapping race fix.
  sb_add_wan_latency A "$WAN_DELAY_MS"
  sb_add_wan_latency B "$WAN_DELAY_MS"
  nse "${LAB_PREFIX}-cliA" curl -fsS "http://$RDV_IP:$BACKEND_PORT/api/health" >/dev/null 2>&1 \
    && nse "${LAB_PREFIX}-cliB" curl -fsS "http://$RDV_IP:$BACKEND_PORT/api/health" >/dev/null 2>&1
}

GATES="${GATES:-cone sym}"

# ============================================================ GATE 1: CONE ====
if [[ " $GATES " == *" cone "* ]]; then
say "GATE 1 — cone NAT pair (port-restricted) -> hole-punch SUCCEEDS"
lab_cleanup
if build_pair port-restricted port-restricted; then
  mapA=$(probe_mapping "${LAB_PREFIX}-cliA")
  mapB=$(probe_mapping "${LAB_PREFIX}-cliB")
  echo "  NAT probe: A=$mapA B=$mapB (expect EIM-cone)"
  if [ "$mapA" = "EIM-cone" ] && [ "$mapB" = "EIM-cone" ]; then
    ok "topology is EIM-cone on both sides"
  else
    bad "topology NOT cone (A=$mapA B=$mapB) — cannot honestly assert punch"
  fi
  if pair_devices; then ok "paired (A knows boxB, B knows boxA)"; else bad "pairing failed"; fi
  res=$(run_known_transfer "FILAMENT_DIRECT=1 FILAMENT_HOLEPUNCH=1" "cone")
  IFS='|' read -r route hashok <<<"$res"
  echo "  result: route=$route hashok=$hashok"
  [ -n "$(grep -h "HOLEPUNCH ok" "$WORK"/send-cone.log "$WORK"/recv-cone.log 2>/dev/null)" ] \
    && echo "  (HOLEPUNCH ok marker present)"
  if [ "$route" = "holepunched" ]; then ok "route is holepunched"; else bad "route=$route (want holepunched)"; fi
  if [ "$hashok" = "yes" ]; then ok "cone transfer byte-exact"; else bad "cone transfer hash mismatch"; fi
  if [ "$route" != "relayed" ]; then ok "cone did NOT relay"; else bad "cone fell to relay"; fi
else
  bad "cone topology setup failed"
fi
lab_cleanup
fi  # GATE 1

# ========================================================= GATE 2: SYMMETRIC ==
if [[ " $GATES " == *" sym "* ]]; then
say "GATE 2 — symmetric NAT pair -> hole-punch FAILS, steps down to relay"
lab_cleanup
if build_pair symmetric symmetric; then
  mapA=$(probe_mapping "${LAB_PREFIX}-cliA")
  mapB=$(probe_mapping "${LAB_PREFIX}-cliB")
  echo "  NAT probe: A=$mapA B=$mapB (expect EDM-symmetric)"
  if [ "$mapA" = "EDM-symmetric" ] && [ "$mapB" = "EDM-symmetric" ]; then
    ok "topology is EDM-symmetric on both sides"
  else
    bad "topology NOT symmetric (A=$mapA B=$mapB) — cannot honestly assert step-down"
  fi
  if pair_devices; then ok "paired (A knows boxB, B knows boxA)"; else bad "pairing failed"; fi
  res=$(run_known_transfer "FILAMENT_DIRECT=1 FILAMENT_HOLEPUNCH=1" "sym")
  IFS='|' read -r route hashok <<<"$res"
  echo "  result: route=$route hashok=$hashok"
  [ -n "$(grep -h "HOLEPUNCH-FAIL" "$WORK"/send-sym.log "$WORK"/recv-sym.log 2>/dev/null)" ] \
    && echo "  (HOLEPUNCH-FAIL marker present — graceful step-down)"
  if [ "$route" = "relayed" ]; then ok "symmetric stepped down to relay"; else bad "route=$route (want relayed)"; fi
  if [ "$hashok" = "yes" ]; then ok "symmetric transfer byte-exact (via relay)"; else bad "symmetric transfer hash mismatch"; fi
  if [ "$route" != "holepunched" ]; then ok "symmetric did NOT falsely punch"; else bad "symmetric falsely reported holepunched"; fi
else
  bad "symmetric topology setup failed"
fi
lab_cleanup
fi  # GATE 2

# ---- summary ---------------------------------------------------------------
say "SUMMARY"
lab_assert_clean && echo "HOST CLEAN: no filtest-* remain" || echo "WARN: dirty after run"
echo "PASS=$PASS FAIL=$FAIL"
[ -n "$FAILED" ] && echo "FAILED:${FAILED}"
[ "$FAIL" -eq 0 ]
