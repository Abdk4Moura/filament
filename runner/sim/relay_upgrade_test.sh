#!/usr/bin/env bash
# Filament — P5 RELAY->DIRECT AUTO-UPGRADE gate (deterministic).
#
# SLO-measurement gate for transport-resilience §P5 (GAP-6). P1 makes a peer FALL
# to relay when direct stalls, and `relay_committed` deliberately stops the
# known-bad direct path from re-winning the race during cutover. But that makes
# relay a ONE-WAY TRAPDOOR: once on relay the peer STAYS on relay even after the
# network heals and direct would work again. P5 fixes that: a background prober
# keeps probing for a direct path while serving on relay, and SEAMLESSLY upgrades
# back to direct the moment one is confirmed STABLE (verify-before-upgrade). Relay
# becomes a way-station, not a destination.
#
# How the relay phase + the heal are forced deterministically:
#   - FILAMENT_TEST_FREEZE_PERSIST=1 + FILAMENT_TEST_FREEZE_AFTER_BYTES=N make
#     EVERY direct-QUIC transport go dark — so the direct ladder EXHAUSTS and the
#     session falls to the TURN relay (P1 rung d, `relay_committed`).
#   - FILAMENT_TEST_WEBRTC_RELAY_ONLY=1 + a local coturn make "relay" concretely
#     the TURN route (a real relay carries the session).
#   - FILAMENT_TEST_DIRECT_UNBLOCK_MS=M LIFTS the persistent freeze for any direct
#     transport born after M ms — i.e. the network HEALS mid-session. The prober's
#     fresh DIRECT standby (born after the lift) then carries data, so the
#     verify-before-upgrade confirms it and CUTS OVER back to direct.
#   - FILAMENT_TEST_DIRECT_FLAKY=1 (RUN F only) makes the post-lift standby connect
#     then RE-FREEZE immediately — a flaky direct path. The verify guard MUST catch
#     this and DISCARD it (stay on relay) — proving no flap.
#
# ASSERTS (deterministic; RUNS x):
#   RUN U (heal -> UPGRADE):
#     (a) the session FELL to the relay route (the trapdoor we're escaping),
#     (b) the prober DETECTED a direct path and UPGRADED back ("upgraded back to a
#         direct path") within the expected window,
#     (c) the session stayed intact + byte-EXACT across the upgrade (sha256),
#     (d) `relay_committed` was cleared — the upgrade banner is the ground truth
#         (it's printed only by perform_upgrade, which clears relay_committed).
#   RUN F (flaky direct -> NO FLAP):
#     (e) the session fell to relay, the prober found the (flaky) direct path and
#         entered VERIFY, but the verify guard DISCARDED it ("staying on relay (no
#         flap)") and NEVER upgraded — and still completed byte-exact on relay.
#
# Isolated: own backend on a private port, own coturn on private ports, own
# FILAMENT_CONFIG_DIRs, the BUILT --features test-hooks binary. Never the live
# daemon / installed CLI / production TURN.
#
# Usage (from repo root or anywhere):  runner/sim/relay_upgrade_test.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CLI_DIR="$ROOT/cli"
BIN="${FILJOB_BIN:-$CLI_DIR/target/release/filament}"
PORT="${FILAMENT_TEST_PORT:-8096}"
SERVER="http://127.0.0.1:$PORT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/relay-upgrade.XXXXXX")"
PYV="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"
[ -x "$PYV" ] || PYV="$(command -v python3)"

# coturn (local TURN) — private ports, loopback only.
TURN_PORT="${TURN_PORT:-34580}"
TURN_MINP="${TURN_MINP:-34600}"
TURN_MAXP="${TURN_MAXP:-34699}"
TURN_SECRET="${TURN_SECRET:-filament-sim-secret}"

# Knobs. Freeze early + detect fast so the fall-to-relay happens in seconds; a
# large payload keeps the transfer in flight on relay long enough for the prober
# to find direct and upgrade MID-SESSION; the heal (unblock) fires soon after the
# relay commit; the verify window is short so the upgrade lands inside the run.
#
# Timing budget that makes the upgrade land DETERMINISTICALLY (validated): the
# initial 700KB freezes the direct path at ~1-2s uptime → fall to relay. The heal
# (UNBLOCK_MS=4000) lifts the freeze for direct transports born after 4s uptime;
# until then every prober standby is born pre-heal and re-freezes at byte 0, which
# the verify-before-upgrade guard correctly DISCARDS ("no flap"). The FIRST
# post-heal standby (born >4s) holds through the verify window and UPGRADES — so
# the upgrade lands at ~uptime 5-6s. The 80MB payload over loopback-TURN takes
# ~10s+ (the pre-heal no-flap churn extends it further), so the transfer is still
# in flight when the upgrade lands. UNBLOCK_MS must stay ABOVE the ~2s initial-
# freeze moment (so we fall to relay first) and BELOW the relay-phase duration.
FREEZE_AT="${FREEZE_AT:-700000}"          # bytes before the direct data path goes dark
STALL_MS="${STALL_MS:-1500}"              # watchdog threshold (well under patience)
UNBLOCK_MS="${UNBLOCK_MS:-4000}"          # heal: direct transports born after this stream
UPGRADE_FIRST_MS="${UPGRADE_FIRST_MS:-1500}"   # first re-probe after falling to relay
UPGRADE_STEADY_MS="${UPGRADE_STEADY_MS:-4000}" # steady cadence cap
UPGRADE_VERIFY_MS="${UPGRADE_VERIFY_MS:-1200}" # sustained-progress window before cutover
UPGRADE_VERIFY_IDLE_MS="${UPGRADE_VERIFY_IDLE_MS:-900}"  # idle guard during verify
BIG_BYTES="${BIG_BYTES:-80000000}"        # 80MB — spans the relay phase + the upgrade
RUNS="${RUNS:-2}"                          # determinism: repeat the whole gate
RETRIES="${RETRIES:-10}"                   # re-seats for the independently-flaky initial dial

PASS=0; FAIL=0
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
hashof() { sha256sum "$1" | cut -d' ' -f1; }
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  [ -n "${OWN_BACKEND:-}" ] && kill "$OWN_BACKEND" 2>/dev/null
  [ -n "${OWN_TURN:-}" ] && kill "$OWN_TURN" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# Resilience gates drive the env-gated test hooks (FILAMENT_TEST_*), which ship
# ONLY in a `--features test-hooks` build (stripped from default/release).
if [ -z "${FILJOB_BIN:-}" ]; then
  ( cd "$CLI_DIR" && cargo build --release --features test-hooks ) || { echo "build failed"; exit 2; }
fi
[ -x "$BIN" ] || { echo "build first: (cd cli && cargo build --release --features test-hooks)"; exit 2; }
command -v turnserver >/dev/null || { echo "turnserver (coturn) not installed — skipping upgrade gate"; exit 2; }

# ---- local coturn (real TURN relay on loopback) -----------------------------
say "setup: local coturn (static-auth-secret) on 127.0.0.1:$TURN_PORT"
turnserver -n --no-tls --no-dtls --no-cli \
  --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
  --listening-port="$TURN_PORT" --min-port="$TURN_MINP" --max-port="$TURN_MAXP" \
  --realm=filament.sim --lt-cred-mech --fingerprint \
  --allow-loopback-peers \
  --static-auth-secret="$TURN_SECRET" \
  >"$WORK/turn.log" 2>&1 &
OWN_TURN=$!
sleep 2
if kill -0 "$OWN_TURN" 2>/dev/null; then
  ok "coturn up (relay candidates available on 127.0.0.1)"
else
  bad "coturn failed to start"; tail -n 20 "$WORK/turn.log"
  echo "RESULT: $PASS passed, $FAIL failed"; exit 1
fi

# ---- own fixture backend, pointed at the local TURN --------------------------
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$ROOT/backend" && PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    FIL_TURN_HOST="turn:127.0.0.1:$TURN_PORT?transport=udp" \
    FIL_TURN_SECRET="$TURN_SECRET" FIL_TURN_TTL=3600 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
OWN_BACKEND=$!
for _ in $(seq 1 40); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; tail "$WORK/backend.log"; exit 2; }
if curl -fsS "$SERVER/api/config" | grep -q '"turn:127.0.0.1'; then
  ok "backend hands out the local TURN relay (/api/config)"
else
  bad "backend not serving TURN — relay route can't form"
  curl -fsS "$SERVER/api/config" | head -c 400; echo
  echo "RESULT: $PASS passed, $FAIL failed"; exit 1
fi

# ---- payload (large: spans the relay phase + the upgrade) -------------------
BIG="$WORK/big.bin"; head -c "$BIG_BYTES" /dev/urandom >"$BIG"; H_BIG=$(hashof "$BIG")

# ---- pair A<->B (the known-device direct prerequisite) ----------------------
DA="$WORK/devA"; DB="$WORK/devB"; mkdir -p "$DA" "$DB"
PAIRFILE="$WORK/pair.bin"; head -c 1000000 /dev/urandom >"$PAIRFILE"
pair() {
  local W="pair-$$-$RANDOM"
  FILAMENT_CONFIG_DIR="$DA" "$BIN" send "$PAIRFILE" --word "$W" --remember boxB --server "$SERVER" >"$WORK/pair-a.log" 2>&1 &
  local SP=$!; sleep 3
  FILAMENT_CONFIG_DIR="$DB" timeout 60 "$BIN" recv "$W" -y --remember boxA --dir "$DB" --server "$SERVER" >"$WORK/pair-b.log" 2>&1
  wait $SP 2>/dev/null
}
say "setup: pairing A<->B (--remember over a code)"
pair
if [ -s "$DA/devices.json" ] && [ -s "$DB/devices.json" ]; then
  ok "paired (A knows boxB, B knows boxA)"
else
  bad "pairing setup"; tail -n 6 "$WORK/pair-a.log" "$WORK/pair-b.log"
  echo "RESULT: $PASS passed, $FAIL failed"; exit 1
fi

# ---- one upgrade attempt. flaky="0" -> heal to direct; flaky="1" -> flaky direct.
# Sets: A_RC A_FROZE A_RELAYED A_UPGRADED A_NOFLAP. Leaves logs.
one_attempt() {
  local tag="$1" flaky="$2"
  local DG="$WORK/$tag-drop"; rm -rf "$DG"; mkdir -p "$DG"
  local UPLOG="$WORK/$tag-up.log"; local SENDLOG="$WORK/$tag-send.log"
  local FLAKY_ENV=""
  [ "$flaky" = "1" ] && FLAKY_ENV="FILAMENT_TEST_DIRECT_FLAKY=1"
  # The `up` daemon is the canonical long-lived session (warm_standby + prober
  # default ON). Both ends carry the persistent freeze + the unblock heal so direct
  # first stalls (-> relay) then a FRESH direct standby (born after the heal)
  # carries data and the prober upgrades back. The prober knobs are tightened so the
  # detect->verify->upgrade lands inside the run.
  #
  # FILAMENT_WARM_STANDBY=1 on BOTH ends: this models an INTERACTIVE transfer
  # session (the case the upgrade prober serves). It makes the fall-to-relay
  # SYMMETRIC + fast — both ends do the P3 warm-relay instant failover and COMMIT
  # to relay — instead of the sender taking the slower cold WebRTC-fallback ladder,
  # which on this multi-homed loopback box often gets "stuck while connecting" and
  # drops the peer BEFORE ever reaching relay (so no symmetric probe could form).
  # It also makes BOTH ends prober-eligible, so the relay->direct probe is bilateral
  # (the QUIC simultaneous-open needs both sides dialing). The relay-fallback gate
  # pins WARM_STANDBY=0 to test the cold ladder; this gate pins it =1 to test the
  # warm path's upgrade-back, which is the P5 surface.
  FILAMENT_CONFIG_DIR="$DB" FILAMENT_DIRECT=1 FILAMENT_DIRECT_LOOPBACK_ONLY=1 \
    FILAMENT_STALL_MS="$STALL_MS" FILAMENT_WARM_STANDBY=1 \
    FILAMENT_UPGRADE_FIRST_MS="$UPGRADE_FIRST_MS" FILAMENT_UPGRADE_STEADY_MS="$UPGRADE_STEADY_MS" \
    FILAMENT_UPGRADE_VERIFY_MS="$UPGRADE_VERIFY_MS" FILAMENT_UPGRADE_VERIFY_IDLE_MS="$UPGRADE_VERIFY_IDLE_MS" \
    FILAMENT_TEST_FREEZE_PERSIST=1 FILAMENT_TEST_WEBRTC_RELAY_ONLY=1 \
    FILAMENT_TEST_FREEZE_AFTER_BYTES="$FREEZE_AT" FILAMENT_TEST_DIRECT_UNBLOCK_MS="$UNBLOCK_MS" \
    env $FLAKY_ENV timeout 90 "$BIN" up --dir "$DG" --server "$SERVER" >"$UPLOG" 2>&1 &
  local UP=$!; pids+=($UP); sleep 3
  A_RC=0
  FILAMENT_CONFIG_DIR="$DA" FILAMENT_DIRECT=1 FILAMENT_DIRECT_LOOPBACK_ONLY=1 \
    FILAMENT_STALL_MS="$STALL_MS" FILAMENT_WARM_STANDBY=1 \
    FILAMENT_UPGRADE_FIRST_MS="$UPGRADE_FIRST_MS" FILAMENT_UPGRADE_STEADY_MS="$UPGRADE_STEADY_MS" \
    FILAMENT_UPGRADE_VERIFY_MS="$UPGRADE_VERIFY_MS" FILAMENT_UPGRADE_VERIFY_IDLE_MS="$UPGRADE_VERIFY_IDLE_MS" \
    FILAMENT_TEST_FREEZE_PERSIST=1 FILAMENT_TEST_WEBRTC_RELAY_ONLY=1 \
    FILAMENT_TEST_FREEZE_AFTER_BYTES="$FREEZE_AT" FILAMENT_TEST_DIRECT_UNBLOCK_MS="$UNBLOCK_MS" \
    env $FLAKY_ENV timeout 90 "$BIN" send "$BIG" --to boxB --server "$SERVER" >"$SENDLOG" 2>&1 || A_RC=1
  sleep 1; kill $UP 2>/dev/null; wait $UP 2>/dev/null
  A_FROZE=0;  grep -hq "data-path FREEZE engaged" "$SENDLOG" "$UPLOG" 2>/dev/null && A_FROZE=1
  A_RELAYED=0; grep -hq "on relay — via a TURN server" "$SENDLOG" "$UPLOG" 2>/dev/null && A_RELAYED=1
  A_UPGRADED=0; grep -hq "upgraded back to a direct path" "$SENDLOG" "$UPLOG" 2>/dev/null && A_UPGRADED=1
  A_NOFLAP=0;  grep -hq "staying on relay (no flap)" "$SENDLOG" "$UPLOG" 2>/dev/null && A_NOFLAP=1
}

# RUN U: re-seat only when the setup (freeze + fall-to-relay) didn't materialize —
# the initial direct establishment under a persistent freeze on a multi-homed
# loopback box is independently flaky (orthogonal to the upgrade under test).
run_upgrade() {
  local tag="$1" try
  for try in $(seq 1 "$RETRIES"); do
    one_attempt "$tag" "0"
    local GOT="$WORK/$tag-drop/big.bin"
    if [ "$A_FROZE" = "1" ] && [ "$A_RELAYED" = "1" ] && [ "$A_UPGRADED" = "1" ] \
       && [ -f "$GOT" ] && [ "$(hashof "$GOT")" = "$H_BIG" ]; then
      return 0
    fi
    echo "    (upgrade attempt $try: froze=$A_FROZE relayed=$A_RELAYED upgraded=$A_UPGRADED — re-seating)" >&2
  done
  return 1
}

# RUN F: flaky direct. Re-seat only when the fall-to-relay setup didn't materialize.
run_flaky() {
  local tag="$1" try
  for try in $(seq 1 "$RETRIES"); do
    one_attempt "$tag" "1"
    local GOT="$WORK/$tag-drop/big.bin"
    # Need: fell to relay AND the verify guard fired (no-flap) AND it did NOT
    # upgrade AND the file still completed byte-exact on relay.
    if [ "$A_FROZE" = "1" ] && [ "$A_RELAYED" = "1" ] && [ "$A_NOFLAP" = "1" ] \
       && [ "$A_UPGRADED" = "0" ] && [ -f "$GOT" ] && [ "$(hashof "$GOT")" = "$H_BIG" ]; then
      return 0
    fi
    echo "    (flaky attempt $try: froze=$A_FROZE relayed=$A_RELAYED noflap=$A_NOFLAP upgraded=$A_UPGRADED — re-seating)" >&2
  done
  return 1
}

GATE_OK=1
for n in $(seq 1 "$RUNS"); do
  # ---------- RUN U: heal -> UPGRADE back to direct -------------------------
  say "RUN U $n/$RUNS: fall to relay, network heals, prober UPGRADES back to direct"
  tagU="upU$n"
  if run_upgrade "$tagU"; then :; fi
  GOT="$WORK/$tagU-drop/big.bin"
  if [ "$A_FROZE" = "1" ]; then
    ok "[$tagU] (a-pre) direct froze (the fall-to-relay setup is real)"
  else
    bad "[$tagU] (a-pre) freeze never engaged — not exercising the trapdoor"; GATE_OK=0
  fi
  if [ "$A_RELAYED" = "1" ]; then
    ok "[$tagU] (a) session FELL to the relay route (the one-way trapdoor)"
  else
    bad "[$tagU] (a) never reached relay — nothing to upgrade away from"; GATE_OK=0
  fi
  if [ "$A_UPGRADED" = "1" ]; then
    ok "[$tagU] (b) prober DETECTED direct + UPGRADED back ('upgraded back to a direct path')"
    grep -hE "probing for a direct path|direct path connected — verifying|upgraded back to a direct path" \
      "$WORK/$tagU-send.log" "$WORK/$tagU-up.log" 2>/dev/null | head -3 | sed 's/^/        /'
  else
    bad "[$tagU] (b) prober never upgraded back to direct"; GATE_OK=0
  fi
  if [ -f "$GOT" ] && [ "$(hashof "$GOT")" = "$H_BIG" ]; then
    ok "[$tagU] (c) session intact + byte-EXACT across the upgrade (sha256 match)"
  else
    bad "[$tagU] (c) file missing or corrupt across the upgrade"; GATE_OK=0
  fi
  # (d) relay_committed cleared — the upgrade banner is printed ONLY by
  # perform_upgrade, which clears relay_committed/relay_only as its first act, so
  # its presence IS the proof the commitment was released.
  if [ "$A_UPGRADED" = "1" ]; then
    ok "[$tagU] (d) relay_committed cleared (perform_upgrade ran — 'relay released')"
  else
    bad "[$tagU] (d) no upgrade => relay_committed still latched"; GATE_OK=0
  fi

  # ---------- RUN F: flaky direct -> NO FLAP (stay on relay) -----------------
  say "RUN F $n/$RUNS: fall to relay, direct comes up FLAKY — verify guard must NOT upgrade"
  tagF="flakyF$n"
  if run_flaky "$tagF"; then :; fi
  GOTF="$WORK/$tagF-drop/big.bin"
  if [ "$A_FROZE" = "1" ] && [ "$A_RELAYED" = "1" ]; then
    ok "[$tagF] (e-pre) fell to relay (same trapdoor setup)"
  else
    bad "[$tagF] (e-pre) didn't fall to relay"; GATE_OK=0
  fi
  if [ "$A_NOFLAP" = "1" ] && [ "$A_UPGRADED" = "0" ]; then
    ok "[$tagF] (e) flaky direct DISCARDED by the verify guard — stayed on relay (NO FLAP)"
    grep -hE "verifying it holds|staying on relay \(no flap\)" \
      "$WORK/$tagF-send.log" "$WORK/$tagF-up.log" 2>/dev/null | head -3 | sed 's/^/        /'
  else
    bad "[$tagF] (e) flaky direct was NOT correctly rejected (noflap=$A_NOFLAP upgraded=$A_UPGRADED)"; GATE_OK=0
  fi
  if [ -f "$GOTF" ] && [ "$(hashof "$GOTF")" = "$H_BIG" ]; then
    ok "[$tagF] (e2) still completed byte-EXACT on relay despite the flaky direct path"
  else
    bad "[$tagF] (e2) file missing/corrupt on relay under the flaky direct path"; GATE_OK=0
  fi
done

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$GATE_OK" = "1" ] && [ "$FAIL" = "0" ]
