#!/usr/bin/env bash
# Local loopback e2e for the FILE-DRIVEN filament job runner.
#
# Boots an ISOLATED filament topology on THIS host (separate built binary +
# separate FILAMENT_CONFIG_DIRs + a local signaling backend) and runs the full
# file-driven submit -> watcher-runs-job -> await(results) loop against it. Never
# touches the user's live `up --shell` daemon or the installed ~/.local/bin/filament.
#
# Topology (file-driven — see filament_runner.FileRunnerBox + watcher.py):
#   din  : box `up --dir <inbox>`  <- host `send`   (push job spec + inputs)
#   dout : host `up --dir <out>`   <- box  `send`   (manifest + outputs back)
#   (NO ctl PTY — the watcher is a local poll loop on the box.)
#
# RELAY: the WAN bring-up + host default to `--relay`; locally TURN may be
# unavailable, so this test uses the DIRECT route (--no-relay on both the watcher
# and the host). The relay path is exercised on the real T4.
#
# Usage:  runner/run_local_test.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PORT="${FILJOB_TEST_PORT:-8077}"
SERVER="http://127.0.0.1:$PORT"
BIN="${FILJOB_BIN:-$ROOT/cli/target/release/filament}"

# A python with the backend's signaling deps (flask-socketio + eventlet) is
# needed to run the LOCAL signaling backend. Prefer an explicit FILJOB_VENV;
# else use a repo-local venv (created + populated on first run); else fall back
# to system python3 if it already imports flask_socketio.
ensure_py() {
  if [ -n "${FILJOB_VENV:-}" ] && [ -x "$FILJOB_VENV/bin/python" ]; then
    PY="$FILJOB_VENV/bin/python"; return
  fi
  if python3 -c "import flask_socketio, eventlet" >/dev/null 2>&1; then
    PY="$(command -v python3)"; return
  fi
  local venv="$HERE/.venv"
  if [ ! -x "$venv/bin/python" ]; then
    echo "[test] creating venv at $venv (backend signaling deps)"
    python3 -m venv "$venv"
    "$venv/bin/pip" -q install --upgrade pip >/dev/null 2>&1 || true
    "$venv/bin/pip" -q install "flask>=3.0" "flask-cors>=4.0" "flask-socketio>=5.3" \
        "eventlet>=0.35" "python-socketio>=5" "websocket-client" >/dev/null
  fi
  PY="$venv/bin/python"
}
ensure_py

# distinct pair secrets (ctl planted for parity but UNUSED in the file-driven flow)
SEC_CTL="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
SEC_DIN="aaaa1111bbbb2222cccc3333dddd4444aaaa1111bbbb2222cccc3333dddd4444"
SEC_DOUT="bbbb1111cccc2222dddd3333eeee4444bbbb1111cccc2222dddd3333eeee4444"

WORK="$(mktemp -d /tmp/filjob_test.XXXXXX)"
HOST_CFG="$WORK/host"           # host: din sender (send) -> box-in
HOST_DOUT_CFG="$WORK/host-dout" # host: dout acceptor (up sink) <- box-out
BOX_DIN_CFG="$WORK/box-din"     # box:  din up --dir (knows host-in)
BOX_DOUT_CFG="$WORK/box-dout"   # box:  send on dout (knows host-out)
BOX_JOBS="$WORK/box/filament-jobs"
BOX_INBOX="$BOX_JOBS/.inbox"
mkdir -p "$HOST_CFG" "$HOST_DOUT_CFG" "$BOX_DIN_CFG" "$BOX_DOUT_CFG" "$BOX_INBOX"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  [ "${FILJOB_KEEP:-0}" = "1" ] || rm -rf "$WORK"
}
trap cleanup EXIT

echo "[test] binary:  $BIN"
echo "[test] work:    $WORK"
# The local test drives env-gated test hooks (FILAMENT_TEST_*), which now ship
# ONLY in a `--features test-hooks` build (stripped from default/release).
# Auto-build that binary unless an explicit FILJOB_BIN was provided.
if [ -z "${FILJOB_BIN:-}" ]; then
  ( cd "$ROOT/cli" && cargo build --release --features test-hooks ) || { echo "ERROR: build failed"; exit 1; }
fi
[ -x "$BIN" ] || { echo "ERROR: filament binary not found at $BIN (build: cd cli && cargo build --release --features test-hooks)"; exit 1; }

# --- devices.json on each side -------------------------------------------------
# host: din->"box-in" (send target). host-dout: dout->"box-out" (sink peer).
# box-din: knows host as "host-in". box-dout: knows host as "host-out".
"$PY" - "$HOST_CFG" "$HOST_DOUT_CFG" "$BOX_DIN_CFG" "$BOX_DOUT_CFG" \
       "$SEC_DIN" "$SEC_DOUT" <<'PY'
import json,sys
host,hostdout,boxdin,boxdout,din,dout=sys.argv[1:7]
json.dump([{"name":"box-in","secret":din}],   open(f"{host}/devices.json","w"))
json.dump([{"name":"box-out","secret":dout}], open(f"{hostdout}/devices.json","w"))
json.dump([{"name":"host-in","secret":din}],  open(f"{boxdin}/devices.json","w"))
json.dump([{"name":"host-out","secret":dout}],open(f"{boxdout}/devices.json","w"))
print("[test] planted devices.json on host/host-dout/box-din/box-dout")
PY

# --- local signaling backend ---------------------------------------------------
if ! curl -sf "$SERVER/api/health" >/dev/null 2>&1; then
  echo "[test] starting local signaling backend on :$PORT"
  ( cd "$ROOT/backend" && PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      "$PY" app.py >"$WORK/backend.log" 2>&1 & echo $! > "$WORK/backend.pid" )
  for _ in $(seq 1 40); do curl -sf "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.3; done
  PIDS+=("$(cat "$WORK/backend.pid")")
fi
curl -sf "$SERVER/api/health" >/dev/null || { echo "ERROR: backend not healthy"; cat "$WORK/backend.log"; exit 1; }
echo "[test] backend healthy"

# --- box din acceptor ----------------------------------------------------------
# din: a single `up` as the inbound file sink on the din channel (its own config
# dir so it subscribes to ONLY the din channel). DIRECT route locally.
FILAMENT_CONFIG_DIR="$BOX_DIN_CFG" HOME="$BOX_DIN_CFG" PATH="$(dirname "$BIN"):$PATH" \
  "$BIN" up --server "$SERVER" --name-as filjob-box-din --dir "$BOX_INBOX" \
  >"$WORK/box_din.log" 2>&1 &
PIDS+=("$!")

# --- box watcher (file-driven control plane), DIRECT route locally ------------
# stage the box-side python where the watcher expects to import box_executor.
cp "$HERE/box_executor.py" "$BOX_JOBS/box_executor.py"
cp "$HERE/watcher.py"      "$BOX_JOBS/watcher.py"
FILJOB_ROOT="$BOX_JOBS" FILJOB_SERVER="$SERVER" FILAMENT_BIN="$BIN" \
  FILJOB_BOX_DOUT_CFG="$BOX_DOUT_CFG" FILJOB_HOST_DOUT_PEER="host-out" \
  PATH="$(dirname "$BIN"):$PATH" \
  "$PY" "$BOX_JOBS/watcher.py" --no-relay --poll 1.0 --settle 0.5 \
  --reship-attempts 12 --reship-gap 3 \
  >"$WORK/box_watcher.log" 2>&1 &
PIDS+=("$!")

sleep 3
echo "[test] box din up + watcher up (direct route)"

# --- run the python e2e --------------------------------------------------------
echo "[test] running e2e ..."
set +e
FILJOB_SERVER="$SERVER" FILJOB_BIN="$BIN" \
  FILJOB_HOST_CFG="$HOST_CFG" FILJOB_HOST_DOUT_CFG="$HOST_DOUT_CFG" \
  "$PY" "$HERE/test_e2e.py"
RC=$?
set -e

if [ $RC -ne 0 ]; then
  echo "[test] FAILED (rc=$RC). Logs:"
  echo "--- box din ---";     tail -25 "$WORK/box_din.log"     2>/dev/null || true
  echo "--- box watcher ---"; tail -40 "$WORK/box_watcher.log" 2>/dev/null || true
fi
exit $RC
