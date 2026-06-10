#!/usr/bin/env bash
# Orchestrate a Python<->Rust control-plane interop run end to end:
#   1. start the fixture backend (if not already up),
#   2. plant a devices.json with a shared secret,
#   3. start the real `filament up` subscribed to channel_of(secret),
#   4. run a Python driver scenario as the (late) peer,
#   5. clean up.
#
# Usage:  ./run_interop.sh [discover|late-join|watch]   (default: discover)
set -euo pipefail

SCENARIO="${1:-discover}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VENV="${FIL_VENV:-/root/.claude/jobs/330c2366/tmp/venv}"
PY="$VENV/bin/python"
FILAMENT="$ROOT/cli/target/release/filament"
PORT="${PORT:-8099}"
SERVER="http://127.0.0.1:$PORT"
SECRET="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
CFG="$(mktemp -d)"

cleanup() { kill "${UP_PID:-}" 2>/dev/null || true; rm -rf "$CFG"; }
trap cleanup EXIT

# 1. backend
if ! curl -sf "$SERVER/api/health" >/dev/null 2>&1; then
  echo "[run_interop] starting fixture backend on :$PORT"
  ( cd "$ROOT/backend" && PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      "$PY" app.py >/tmp/fil_backend.log 2>&1 & )
  for _ in $(seq 1 20); do curl -sf "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.3; done
fi

# 2. plant devices.json
printf '[{"name":"pylab","secret":"%s"}]\n' "$SECRET" > "$CFG/devices.json"

# 3. real filament up (the already-present peer), L2 on so it emits offers
echo "[run_interop] starting real 'filament up' (channel $(${PY} -c "from filament_lab import crypto;print(crypto.channel_of('$SECRET')[:12])" ))"
FILAMENT_CONFIG_DIR="$CFG" HOME="$CFG" FILAMENT_L2=1 \
  "$FILAMENT" up --server "$SERVER" --name-as rust-up >/tmp/fil_up.log 2>&1 &
UP_PID=$!
sleep 3
echo "[run_interop] --- filament up log ---"; cat /tmp/fil_up.log

# 4. Python peer as the LATE subscriber
echo "[run_interop] --- python driver: $SCENARIO ---"
cd "$HERE"
timeout 20 "$PY" -m filament_lab.driver --secret "$SECRET" --name pylab "$SCENARIO" --seconds 12
