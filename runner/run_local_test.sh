#!/usr/bin/env bash
# Local loopback e2e for the filament job runner.
#
# Boots an ISOLATED filament topology on THIS host (separate built binary +
# separate FILAMENT_CONFIG_DIRs + a local signaling backend) and runs the full
# submit -> stream -> fetch -> manifest loop against it. Never touches the user's
# live `up --shell` daemon or the installed ~/.local/bin/filament.
#
# Topology (three channels, one acceptor each — see filament_runner.py):
#   ctl  : box `up --shell`        <- host `pty`
#   din  : box `up --dir <inbox>`  <- host `send`   (push inputs)
#   dout : host `up --dir <out>`   <- box  `send`   (pull outputs)
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

# three distinct pair secrets
SEC_CTL="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
SEC_DIN="aaaa1111bbbb2222cccc3333dddd4444aaaa1111bbbb2222cccc3333dddd4444"
SEC_DOUT="bbbb1111cccc2222dddd3333eeee4444bbbb1111cccc2222dddd3333eeee4444"

WORK="$(mktemp -d /tmp/filjob_test.XXXXXX)"
HOST_CFG="$WORK/host"          # host: ctl initiator (pty) + din sender (send)
HOST_DOUT_CFG="$WORK/host-dout" # host: dout acceptor (up sink)
BOX_CFG="$WORK/box"            # box: ctl up --shell + din up
BOX_INBOX="$WORK/box/inbox"
BOX_JOBS="$WORK/box/jobs"
mkdir -p "$HOST_CFG" "$HOST_DOUT_CFG" "$BOX_CFG" "$BOX_INBOX" "$BOX_JOBS"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  # leave WORK for inspection unless KEEP unset
  [ "${FILJOB_KEEP:-0}" = "1" ] || rm -rf "$WORK"
}
trap cleanup EXIT

echo "[test] binary:  $BIN"
echo "[test] work:    $WORK"
[ -x "$BIN" ] || { echo "ERROR: filament binary not found at $BIN (build: cargo build --release -p filament-cli)"; exit 1; }

# --- devices.json on each side -------------------------------------------------
# host knows the box on all three channels; box knows the host on all three.
"$PY" - "$HOST_CFG" "$HOST_DOUT_CFG" "$BOX_CFG" "$SEC_CTL" "$SEC_DIN" "$SEC_DOUT" <<'PY'
import json,sys
host,hostdout,box,ctl,din,dout=sys.argv[1:8]
# host (initiator side): ctl->"box", din->"box-in", dout->"box-out".
# The host runs NO daemon here (only `pty`/`send` initiators), so co-locating
# all three secrets is fine — each command subscribes to its own channel.
json.dump([{"name":"box","secret":ctl},{"name":"box-in","secret":din},{"name":"box-out","secret":dout}],
          open(f"{host}/devices.json","w"))
# host-dout config: only the dout secret, known as "box-out"
json.dump([{"name":"box-out","secret":dout}], open(f"{hostdout}/devices.json","w"))
# box CTL daemon config: ONLY the ctl secret. It runs `up --shell`, so it must
# NOT know the din/dout secrets — otherwise this daemon would also subscribe to
# those channels and become a second acceptor (glare with the din sink).
json.dump([{"name":"host","secret":ctl}], open(f"{box}/devices.json","w"))
print("[test] planted devices.json on host/host-dout/box(ctl-only)")
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

# --- box acceptors -------------------------------------------------------------
# ctl: up --shell (PTY + control). FILAMENT_L2=1 so it serves PTYs.
FILAMENT_CONFIG_DIR="$BOX_CFG" HOME="$BOX_CFG" FILAMENT_L2=1 PATH="$(dirname "$BIN"):$PATH" \
  "$BIN" up --server "$SERVER" --shell --name-as filjob-box-ctl --dir "$BOX_CFG/ctldrop" \
  >"$WORK/box_ctl.log" 2>&1 &
PIDS+=("$!")
# din: a second `up` purely as the inbound file sink, on the din channel.
# It must be a SEPARATE config dir so it subscribes to ONLY the din channel
# (otherwise it'd also acquire ctl and glare with the ctl daemon).
DIN_CFG="$WORK/box-din"; mkdir -p "$DIN_CFG"
"$PY" - "$DIN_CFG" "$SEC_DIN" <<'PY'
import json,sys
cfg,din=sys.argv[1:3]; json.dump([{"name":"host-in","secret":din}], open(f"{cfg}/devices.json","w"))
PY
FILAMENT_CONFIG_DIR="$DIN_CFG" HOME="$DIN_CFG" PATH="$(dirname "$BIN"):$PATH" \
  "$BIN" up --server "$SERVER" --name-as filjob-box-din --dir "$BOX_INBOX" \
  >"$WORK/box_din.log" 2>&1 &
PIDS+=("$!")

# box dout config dir: ONLY the dout secret (known as "host-out"). The PTY-driven
# box-side `filament send` uses this via FILAMENT_CONFIG_DIR so it never shares a
# channel with the ctl daemon. No daemon runs here — it's initiator-only config.
BOX_DOUT_CFG="$WORK/box-dout"; mkdir -p "$BOX_DOUT_CFG"
"$PY" - "$BOX_DOUT_CFG" "$SEC_DOUT" <<'PY'
import json,sys
cfg,dout=sys.argv[1:3]; json.dump([{"name":"host-out","secret":dout}], open(f"{cfg}/devices.json","w"))
PY

sleep 3
echo "[test] box ctl up: $(grep -c 'filament up' "$WORK/box_ctl.log" 2>/dev/null || echo '?') ; din up started"

# --- run the python e2e --------------------------------------------------------
echo "[test] running e2e ..."
set +e
FILJOB_SERVER="$SERVER" FILJOB_BIN="$BIN" \
  FILJOB_HOST_CFG="$HOST_CFG" FILJOB_HOST_DOUT_CFG="$HOST_DOUT_CFG" \
  FILJOB_REMOTE_ROOT="$BOX_JOBS" FILJOB_REMOTE_INBOX="$BOX_INBOX" \
  FILJOB_BOX_DOUT_CFG="$BOX_DOUT_CFG" \
  "$PY" "$HERE/test_e2e.py"
RC=$?
set -e

if [ $RC -ne 0 ]; then
  echo "[test] FAILED (rc=$RC). Logs:"
  echo "--- box ctl ---"; tail -20 "$WORK/box_ctl.log" 2>/dev/null || true
  echo "--- box din ---"; tail -20 "$WORK/box_din.log" 2>/dev/null || true
fi
exit $RC
