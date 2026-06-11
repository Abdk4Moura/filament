#!/usr/bin/env bash
# DETERMINISTIC FLAKY-LINK SIMULATION for the file-driven filament job-runner.
#
# Reproduces — LOCALLY, with NO real remote box — the three failure modes that
# break the runner over the real Colab->do-vm WAN link, and proves the resilience
# fixes recover from each:
#
#   (a) discovery race  : the link is DOWN when the host first pushes the job, so a
#                         single `send` would hit "no peer connected within 60s".
#                         RETRY-UNTIL-PEER must keep trying and eventually land it.
#   (b) truncation      : the link DROPS mid result-transfer. The host's sha256
#                         INTEGRITY GATE must reject the partial and keep awaiting
#                         until a complete, byte-correct copy lands (resume-to-done).
#   (c) lost manifest   : the link is DOWN in the window the manifest would arrive.
#                         The box must RE-SHIP until the host ACKs, so the manifest
#                         is never permanently lost.
#
# HOW INSTABILITY IS INDUCED: a stdlib TCP proxy (flaky_proxy.py) sits between every
# filament CLI client and the LOCAL signaling backend. filament's discovery + SDP/ICE
# ride that socket.io link, so cutting it (toggle a control file) severs live
# connections and refuses new ones — the local equivalent of the WAN path dropping.
# A background "flapper" then keeps randomly dropping the link for the whole run, so
# the eventual success is "despite induced drops", not just one scripted outage.
#
# LOCAL ONLY: isolated FILAMENT_CONFIG_DIRs + the locally-built binary + a local
# backend on its own port. Never touches the user's daemon or ~/.local/bin/filament.
#
# Usage:  runner/sim/flaky_sim_test.sh            # full flaky run
#         FILJOB_KEEP=1 runner/sim/flaky_sim_test.sh   # keep work dir for inspection
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$RUNNER/.." && pwd)"
# PID-derived ports by default so overlapping/relaunched runs never collide on a
# port (a late cleanup of one run must not kill another run's backend). Override
# with FILJOB_SIM_PORT / FILJOB_SIM_PROXY_PORT.
_BASE=$(( 8100 + ($$ % 1500) * 2 ))
PORT="${FILJOB_SIM_PORT:-$_BASE}"
PROXY_PORT="${FILJOB_SIM_PROXY_PORT:-$(( _BASE + 1 ))}"
BACKEND="http://127.0.0.1:$PORT"          # clients NEVER hit this directly
SERVER="http://127.0.0.1:$PROXY_PORT"     # every client goes through the flaky proxy
BIN="${FILJOB_BIN:-$ROOT/cli/target/release/filament}"
SEED="${FILJOB_SIM_SEED:-1}"

# pick the python with signaling deps (reuse run_local_test's venv if present)
if [ -n "${FILJOB_VENV:-}" ] && [ -x "$FILJOB_VENV/bin/python" ]; then PY="$FILJOB_VENV/bin/python"
elif python3 -c "import flask_socketio, eventlet" >/dev/null 2>&1; then PY="$(command -v python3)"
elif [ -x "$RUNNER/.venv/bin/python" ]; then PY="$RUNNER/.venv/bin/python"
else echo "ERROR: need a python with flask_socketio+eventlet; run runner/run_local_test.sh once to build the venv"; exit 1; fi

SEC_DIN="aaaa1111bbbb2222cccc3333dddd4444aaaa1111bbbb2222cccc3333dddd4444"
SEC_DOUT="bbbb1111cccc2222dddd3333eeee4444bbbb1111cccc2222dddd3333eeee4444"

WORK="$(mktemp -d /tmp/filjob_sim.XXXXXX)"
HOST_CFG="$WORK/host"; HOST_DOUT_CFG="$WORK/host-dout"
BOX_DIN_CFG="$WORK/box-din"; BOX_DOUT_CFG="$WORK/box-dout"
BOX_JOBS="$WORK/box/filament-jobs"; BOX_INBOX="$BOX_JOBS/.inbox"
DOWN_FLAG="$WORK/link_down"
mkdir -p "$HOST_CFG" "$HOST_DOUT_CFG" "$BOX_DIN_CFG" "$BOX_DOUT_CFG" "$BOX_INBOX"

PIDS=()
cleanup() {
  # kill tracked PIDs AND their groups (the up-supervisor + filament children),
  # so a timeout-kill of the wrapper never leaks a backend/proxy/acceptor that
  # would hold a port and corrupt the next run.
  for p in "${PIDS[@]:-}"; do
    kill "$p" 2>/dev/null || true
    kill -- "-$p" 2>/dev/null || true
  done
  # belt-and-braces: anything still referencing OUR work dir (every client passes
  # a $WORK path in argv) + whatever still holds our two ports (the backend's argv
  # has no $WORK, so target it by port).
  pkill -9 -f "$WORK" 2>/dev/null || true
  for port in "$PORT" "$PROXY_PORT"; do
    holder="$(ss -ltnp 2>/dev/null | grep ":$port " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
    [ -n "$holder" ] && kill -9 "$holder" 2>/dev/null || true
  done
  [ "${FILJOB_KEEP:-0}" = "1" ] || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# pre-flight: refuse to start if our ports are already taken (stale leftovers)
for p in "$PORT" "$PROXY_PORT"; do
  if ss -ltn 2>/dev/null | grep -q ":$p "; then
    echo "ERROR: port $p already in use — a stale run is still alive. Free it first."; exit 1
  fi
done

say() { printf '\033[35m[sim]\033[0m %s\n' "$*"; }
link_down() { : > "$DOWN_FLAG"; }
link_up()   { rm -f "$DOWN_FLAG"; }

[ -x "$BIN" ] || { echo "ERROR: filament binary not found at $BIN"; exit 1; }
say "binary: $BIN"
say "work:   $WORK"

# --- devices.json -------------------------------------------------------------
"$PY" - "$HOST_CFG" "$HOST_DOUT_CFG" "$BOX_DIN_CFG" "$BOX_DOUT_CFG" "$SEC_DIN" "$SEC_DOUT" <<'PY'
import json,sys
host,hostdout,boxdin,boxdout,din,dout=sys.argv[1:7]
json.dump([{"name":"box-in","secret":din}],   open(f"{host}/devices.json","w"))
json.dump([{"name":"box-out","secret":dout}], open(f"{hostdout}/devices.json","w"))
json.dump([{"name":"host-in","secret":din}],  open(f"{boxdin}/devices.json","w"))
json.dump([{"name":"host-out","secret":dout}],open(f"{boxdout}/devices.json","w"))
PY

# --- local signaling backend (clients reach it ONLY via the proxy) ------------
say "starting local backend on :$PORT"
( cd "$ROOT/backend" && PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    "$PY" app.py >"$WORK/backend.log" 2>&1 & echo $! > "$WORK/backend.pid" )
PIDS+=("$(cat "$WORK/backend.pid")")
for _ in $(seq 1 50); do curl -sf "$BACKEND/api/health" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sf "$BACKEND/api/health" >/dev/null || { echo "ERROR: backend not healthy"; cat "$WORK/backend.log"; exit 1; }
say "backend healthy"

# --- the flaky proxy ----------------------------------------------------------
# Start with a background FLAPPER so the link keeps dropping for the whole run
# (mean 6s up / 2s down). The scripted outages below stack on top via the flag.
# The background flapper is AMBIENT realism (occasional drops); the DETERMINISTIC
# failure injection is the scripted forced outage at submit + the chaos bursts during
# result transfer (in flaky_e2e.py). Keep up-windows comfortably longer than a single
# establishment (~15s here) so the runner reliably converges despite the flapping.
FLAP_UP="${FILJOB_SIM_FLAP_UP:-90}"; FLAP_DOWN="${FILJOB_SIM_FLAP_DOWN:-1.5}"
say "starting flaky proxy :$PROXY_PORT -> :$PORT (seed=$SEED, flap ${FLAP_UP}s up / ${FLAP_DOWN}s down)"
"$PY" "$HERE/flaky_proxy.py" --listen "127.0.0.1:$PROXY_PORT" --target "127.0.0.1:$PORT" \
  --down-flag "$DOWN_FLAG" --flap-up "$FLAP_UP" --flap-down "$FLAP_DOWN" --seed "$SEED" \
  >"$WORK/proxy.log" 2>&1 &
PIDS+=("$!")
sleep 1

# --- box din acceptor + watcher (through the proxy) ---------------------------
cp "$RUNNER/box_executor.py" "$BOX_JOBS/box_executor.py"
cp "$RUNNER/watcher.py"      "$BOX_JOBS/watcher.py"

# SUPERVISED box-din acceptor: filament's socket.io is reconnect(false), so a
# severed `up` zombies out and the host can't rediscover it. up_supervisor.sh
# recycles it on a cadence so a fresh, re-announcing acceptor is always present.
FILAMENT_CONFIG_DIR="$BOX_DIN_CFG" HOME="$BOX_DIN_CFG" PATH="$(dirname "$BIN"):$PATH" \
  bash "$RUNNER/up_supervisor.sh" --cadence "${FILJOB_SIM_DIN_CADENCE:-30}" --log "$WORK/box_din.log" -- \
  "$BIN" up --server "$SERVER" --name-as filjob-box-din --dir "$BOX_INBOX" \
  >"$WORK/box_din_sup.log" 2>&1 &
PIDS+=("$!")

# watcher: short reship gap so re-ship reacts fast; long deadline; send waits for
# peer (FILJOB_SEND_TIMEOUT_S=0). DIRECT route (no TURN locally).
FILJOB_ROOT="$BOX_JOBS" FILJOB_SERVER="$SERVER" FILAMENT_BIN="$BIN" \
  FILJOB_BOX_DOUT_CFG="$BOX_DOUT_CFG" FILJOB_HOST_DOUT_PEER="host-out" \
  PATH="$(dirname "$BIN"):$PATH" \
  "$PY" "$BOX_JOBS/watcher.py" --no-relay --poll 1.0 --settle 0.5 \
  --reship-gap 3 --reship-deadline 600 --send-timeout 30 --send-retries 40 \
  --send-retry-gap 2 \
  >"$WORK/box_watcher.log" 2>&1 &
PIDS+=("$!")

sleep 3
say "box din + watcher up (through flaky proxy)"

# --- run the flaky e2e driver -------------------------------------------------
say "running flaky e2e (induced outages during submit + result transfer) ..."
set +e
FILJOB_SERVER="$SERVER" FILJOB_BIN="$BIN" \
  FILJOB_HOST_CFG="$HOST_CFG" FILJOB_HOST_DOUT_CFG="$HOST_DOUT_CFG" \
  FILJOB_DOWN_FLAG="$DOWN_FLAG" FILJOB_WORK="$WORK" \
  "$PY" "$HERE/flaky_e2e.py" &
E2E_PID=$!
PIDS+=("$E2E_PID")
wait "$E2E_PID"
RC=$?
set -e

if [ $RC -ne 0 ]; then
  say "FAILED (rc=$RC). Tail of logs:"
  echo "--- proxy ---";       tail -15 "$WORK/proxy.log"       2>/dev/null || true
  echo "--- box din ---";     tail -20 "$WORK/box_din.log"     2>/dev/null || true
  echo "--- box watcher ---"; tail -50 "$WORK/box_watcher.log" 2>/dev/null || true
else
  say "PASS — job succeeded + truncation recovered + manifest acked despite induced drops"
  echo "--- watcher ship/ack summary ---"
  grep -E "sent results|ACKed|stopping re-ship|GIVE UP" "$WORK/box_watcher.log" 2>/dev/null | tail -20 || true
  echo "--- proxy outage summary ---"
  grep -E "severed|DOWN" "$WORK/proxy.log" 2>/dev/null | tail -8 || true
fi
exit $RC
