#!/usr/bin/env bash
# Filament — P2 SIGNALING-DROP gate (the acceptor-zombie / "no peer connected",
# deterministic). This is the SLO-measurement gate for transport-resilience §P2
# (GAP-2): a long-lived `up`/`up --dir` acceptor must SELF-RECOVER natively after
# its signaling link is severed — reconnect, re-join its room(s), re-subscribe to
# its known-device channels, and re-announce presence — so a FRESH sender can
# rediscover it and a transfer completes, all WITHOUT an external supervisor.
#
# THE GAP it proves closed: the socket.io client is built reconnect(false) and the
# acceptor ran ONE signaling connection with no outer reconnect loop. On a flaky
# link, when the signaling TCP is severed the acceptor's socket died and it never
# re-announced — a ZOMBIE the sender can't rediscover. Historically this was
# patched OUTSIDE the binary by runner/up_supervisor.sh (proactive restart). P2
# fixes it IN-CORE; this gate runs the acceptor DIRECTLY (no supervisor).
#
# HOW THE DROP IS INDUCED: flaky_proxy.py sits between every filament client and
# the LOCAL backend. filament's discovery + SDP/ICE ride that socket.io TCP, so
# raising the down-flag severs the live signaling link (and refuses new conns)
# exactly like the WAN path dropping; lowering it heals.
#
# ASSERTS (each deterministic; run 2-3x):
#   (i)   ESTABLISHED : the acceptor connected + announced through the proxy.
#   (ii)  SEVERED     : the signaling link was cut mid-session (acceptor's socket
#                       died — the zombie condition is induced for real).
#   (iii) RECOVERED   : AFTER the link heals, the acceptor RE-ANNOUNCES in-core
#                       (a "signaling reconnected — re-announcing presence" line)
#                       and a FRESH sender rediscovers it + a transfer COMPLETES
#                       byte-exact (sha256), with NO supervisor.
#   A/B BASELINE      : with the in-core loop reverted
#                       (FILAMENT_TEST_NO_SIGNALING_RECONNECT=1) the SAME sever
#                       leaves the acceptor a ZOMBIE — the fresh sender CANNOT
#                       reach it (send fails) — proving the outer loop is
#                       load-bearing, not incidental.
#
# Isolated: own backend on a private port, own proxy port, own FILAMENT_CONFIG_DIRs,
# the BUILT release binary. NEVER touches the live `up --shell` daemon, the
# installed ~/.local/bin/filament, the live T4, or the production servers.
#
# Usage (from repo root or anywhere):  runner/sim/signaling_drop_test.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CLI_DIR="$ROOT/cli"
BIN="${FILJOB_BIN:-$CLI_DIR/target/release/filament}"
# PID-derived ports so overlapping runs never collide.
_BASE=$(( 8200 + ($$ % 1200) * 2 ))
PORT="${FILAMENT_TEST_PORT:-$_BASE}"             # backend (clients NEVER hit directly)
PROXY_PORT="${FILAMENT_TEST_PROXY_PORT:-$(( _BASE + 1 ))}"
BACKEND="http://127.0.0.1:$PORT"
SERVER="http://127.0.0.1:$PROXY_PORT"            # every client goes through the proxy
WORK="$(mktemp -d "${TMPDIR:-/tmp}/signaling-drop.XXXXXX")"
PYV="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"
[ -x "$PYV" ] || PYV="$(command -v python3)"

# P2 knobs: short silence threshold so the in-core loop re-dials in seconds.
SILENCE_MS="${SILENCE_MS:-3000}"     # signaling-silence watchdog threshold
RUNS="${RUNS:-2}"                    # determinism: repeat the whole gate
SEND_BUDGET="${SEND_BUDGET:-90}"     # post-heal send timeout (recovery must beat this)
BASELINE_BUDGET="${BASELINE_BUDGET:-45}"  # baseline send timeout (zombie must fail < this)

PASS=0; FAIL=0
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
hashof() { sha256sum "$1" | cut -d' ' -f1; }
DOWN_FLAG="$WORK/link_down"
link_down() { : > "$DOWN_FLAG"; }
link_up()   { rm -f "$DOWN_FLAG"; }

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; kill -- "-$p" 2>/dev/null; done
  pkill -9 -f "$WORK" 2>/dev/null || true
  [ -n "${OWN_BACKEND:-}" ] && kill "$OWN_BACKEND" 2>/dev/null
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd cli && cargo build --release)"; exit 2; }
say "binary: $BIN"
say "work:   $WORK"

# pre-flight: refuse to start on a taken port (stale leftovers).
for p in "$PORT" "$PROXY_PORT"; do
  if ss -ltn 2>/dev/null | grep -q ":$p "; then
    echo "ERROR: port $p already in use — a stale run is still alive. Free it first."; exit 2
  fi
done

# ---- own fixture backend ----------------------------------------------------
( cd "$ROOT/backend" && PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
OWN_BACKEND=$!
for _ in $(seq 1 40); do curl -fsS "$BACKEND/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$BACKEND/api/health" >/dev/null || { echo "no backend at $BACKEND"; tail "$WORK/backend.log"; exit 2; }
say "backend healthy on :$PORT"

# ---- the flaky proxy (severs the signaling link on the down-flag) -----------
"$PYV" "$HERE/flaky_proxy.py" --listen "127.0.0.1:$PROXY_PORT" --target "127.0.0.1:$PORT" \
  --down-flag "$DOWN_FLAG" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 1
say "flaky proxy up :$PROXY_PORT -> :$PORT"

# ---- payload + pairing A<->B (the known-device prerequisite) ----------------
BIG="$WORK/big.bin"; head -c 1500000 /dev/urandom >"$BIG"; H_BIG=$(hashof "$BIG")
DA="$WORK/devA"; DB="$WORK/devB"; mkdir -p "$DA" "$DB"
say "setup: pairing A<->B (--remember over a code, through the proxy)"
W="pair-$$-$RANDOM"
FILAMENT_CONFIG_DIR="$DA" "$BIN" send "$BIG" --word "$W" --remember boxB --server "$SERVER" >"$WORK/pair-a.log" 2>&1 &
SP=$!; sleep 3
FILAMENT_CONFIG_DIR="$DB" timeout 60 "$BIN" recv "$W" -y --remember boxA --dir "$DB" --server "$SERVER" >"$WORK/pair-b.log" 2>&1
wait $SP 2>/dev/null
if [ -s "$DA/devices.json" ] && [ -s "$DB/devices.json" ]; then
  ok "paired (A knows boxB, B knows boxA)"
else
  bad "pairing setup"; tail -n 6 "$WORK/pair-a.log" "$WORK/pair-b.log"
  echo "RESULT: $PASS passed, $FAIL failed"; exit 1
fi

# ---- one drop->heal->rediscover attempt -------------------------------------
# Starts a DIRECT (un-supervised) acceptor, lets it announce, severs signaling
# mid-session, heals it, then runs a FRESH sender and reports whether the
# transfer landed. Sets R_RC (sender rc) / R_GOT (received path).
#  $1 = tag   $2 = "heal" (self-heal ON) | "zombie" (baseline, loop reverted)
one_attempt() {
  local tag="$1"; local mode="$2"
  local DG="$WORK/$tag-drop"; rm -rf "$DG"; mkdir -p "$DG"
  local UPLOG="$WORK/$tag-up.log"; local SENDLOG="$WORK/$tag-send.log"
  local extra_env=""
  [ "$mode" = "zombie" ] && extra_env="FILAMENT_TEST_NO_SIGNALING_RECONNECT=1"

  # WebRTC route only (no direct-QUIC) so discovery rides the proxied signaling —
  # the path under test. The acceptor runs DIRECTLY: no up_supervisor.sh.
  link_up
  env FILAMENT_CONFIG_DIR="$DB" FILAMENT_SIGNALING_SILENCE_MS="$SILENCE_MS" $extra_env \
    timeout 130 "$BIN" up --dir "$DG" --server "$SERVER" >"$UPLOG" 2>&1 &
  local UP=$!; pids+=($UP)
  sleep 5   # let it connect + announce its channels (assert (i))

  # (ii) sever the signaling link mid-session — the acceptor's socket dies.
  say "[$tag] severing signaling link (down) ..."
  link_down
  sleep 4   # hold the outage so the live socket is truly gone

  # heal: the link is reachable again. The in-core loop must re-dial + re-announce.
  say "[$tag] restoring signaling link (up) ..."
  link_up
  sleep 8   # give the in-core outer loop time to reconnect + re-announce

  # (iii) a FRESH sender must rediscover the acceptor and complete the transfer.
  R_RC=0
  local budget="$SEND_BUDGET"; [ "$mode" = "zombie" ] && budget="$BASELINE_BUDGET"
  FILAMENT_CONFIG_DIR="$DA" \
    timeout "$budget" "$BIN" send "$BIG" --to boxB --server "$SERVER" >"$SENDLOG" 2>&1 || R_RC=1
  R_GOT="$DG/big.bin"
  sleep 1; kill $UP 2>/dev/null; wait $UP 2>/dev/null
}

GATE_OK=1
for n in $(seq 1 "$RUNS"); do
  say "RUN $n/$RUNS: sever signaling under a NO-SUPERVISOR acceptor; assert in-core re-announce + rediscovery"
  tag="run$n"
  one_attempt "$tag" "heal"
  UPLOG="$WORK/$tag-up.log"; SENDLOG="$WORK/$tag-send.log"; GOT="$WORK/$tag-drop/big.bin"

  # (i) the acceptor established + announced through the proxy.
  if grep -hqE "filament up|listening|known device" "$UPLOG"; then
    ok "[$tag] (i) acceptor ESTABLISHED + announced (no supervisor)"
  else
    bad "[$tag] (i) acceptor never announced"; tail -n 6 "$UPLOG"; GATE_OK=0
  fi

  # (ii) the sever actually happened (proxy severed a live connection).
  if grep -hqE "severed [1-9]|link DOWN" "$WORK/proxy.log"; then
    ok "[$tag] (ii) signaling link SEVERED mid-session (zombie condition induced)"
  else
    bad "[$tag] (ii) sever not observed — test not exercising the drop"; GATE_OK=0
  fi

  # (iii) the in-core loop RE-ANNOUNCED + the fresh sender landed the transfer.
  reannounced=0
  grep -hqE "signaling reconnected — re-announcing|signaling silent|signaling link closed" "$UPLOG" && reannounced=1
  if [ "$reannounced" = "1" ]; then
    ok "[$tag] (iii-a) in-core RE-ANNOUNCE fired (no external supervisor)"
    grep -hE "signaling reconnected|signaling silent|signaling link closed" "$UPLOG" | head -2 | sed 's/^/      /'
  else
    bad "[$tag] (iii-a) no in-core re-announce observed"; tail -n 8 "$UPLOG"; GATE_OK=0
  fi
  if [ "$R_RC" = "0" ] && [ -f "$GOT" ] && [ "$(hashof "$GOT")" = "$H_BIG" ]; then
    ok "[$tag] (iii-b) FRESH sender REDISCOVERED the acceptor + transfer byte-exact ($(stat -c%s "$GOT")B)"
  else
    bad "[$tag] (iii-b) sender could NOT reach the recovered acceptor (rc=$R_RC)"
    tail -n 8 "$SENDLOG"; GATE_OK=0
  fi
done

# ---- A/B BASELINE: in-core loop reverted => acceptor ZOMBIES ----------------
say "A/B BASELINE: in-core reconnect OFF (FILAMENT_TEST_NO_SIGNALING_RECONNECT=1) — the acceptor must ZOMBIE"
one_attempt "baseline" "zombie"
GOTB="$WORK/baseline-drop/big.bin"
# Zombie proof: the in-core re-announce must NOT have fired AND the fresh sender
# must NOT have reached the acceptor (no byte-exact delivery).
zombie_ok=1
if grep -hqE "signaling reconnected — re-announcing" "$WORK/baseline-up.log"; then
  zombie_ok=0   # the loop fired despite being disabled — the A/B knob is broken
fi
if [ "$R_RC" = "0" ] && [ -f "$GOTB" ] && [ "$(hashof "$GOTB" 2>/dev/null)" = "$H_BIG" ]; then
  zombie_ok=0   # the sender reached it — no zombie, the test isn't load-bearing
fi
if [ "$zombie_ok" = "1" ]; then
  ok "BASELINE zombies without the in-core loop (sender rc=$R_RC, no recovery) — the loop is load-bearing"
else
  bad "BASELINE recovered without the in-core loop — the A/B is not exercising the gap"
  tail -n 8 "$WORK/baseline-up.log" "$WORK/baseline-send.log"; GATE_OK=0
fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && [ "$GATE_OK" -eq 1 ] && { echo "SIGNALING-DROP GATE: GREEN"; exit 0; }
echo "SIGNALING-DROP GATE: RED"; exit 1
