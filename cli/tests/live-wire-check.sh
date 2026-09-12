#!/usr/bin/env bash
# LIVE verification of the JS wire layer (frontend/src/net/protocol/wire.js):
# a real headless Chromium running the PRODUCTION frontend <-> a real `filament`
# CLI peer, both directions, over a real WebRTC data channel — REAL framing.
#
# This is the check the web-shell mock harness (?preview=webterm) canNOT give
# you: the mock uses a fake link and never builds/parses a single wire frame.
# Run this after ANY wire-touching frontend slice before promoting it.
#
#   ./live-wire-check.sh
#
# Two checks (mirror gates.sh gate 5 + gate 6, distilled):
#   5  CLI -> browser : CLI `send --room` ; a Chromium tab receives + verifies.
#   6  browser -> CLI : a Chromium tab sends two human-paced files ; CLI `recv`
#                       writes both byte-exact and stays alive between them.
# The file path and the PTY/shell path share the SAME wire.js functions
# (frame/parseFrame/encode/decodeControl/highHalfSid), so a green here covers the
# PTY framing too (the only PTY-unique pieces are MSG.PTY_* constants, pinned by
# wire.test.mjs). See docs/archive/plans/consolidation-plan-2026-06-15.md.
#
# Env (sensible defaults; override as needed):
#   FILAMENT_TEST_VENV  python with the backend deps (flask/eventlet/socketio)
#   PLAYWRIGHT_NODE_PATH NODE_PATH dir that resolves `require('playwright')`
#                        (a cached `npx playwright` install is fine)
#   PORT                 backend port (default 8077)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
REPO="$(dirname "$CLI_DIR")"
BIN="$CLI_DIR/target/release/filament"
PORT="${PORT:-8077}"
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
# Resolve playwright: prefer an installed cli/tests/node_modules, else env hint.
if [ -d "$HERE/node_modules/playwright" ]; then
  export NODE_PATH="$HERE/node_modules${NODE_PATH:+:$NODE_PATH}"
elif [ -n "${PLAYWRIGHT_NODE_PATH:-}" ]; then
  export NODE_PATH="$PLAYWRIGHT_NODE_PATH${NODE_PATH:+:$NODE_PATH}"
fi
node -e "require('playwright')" 2>/dev/null || {
  echo "playwright not resolvable. Either:"
  echo "  (cd $HERE && npm i playwright && npx playwright install chromium)"
  echo "  or set PLAYWRIGHT_NODE_PATH to a dir whose node_modules has playwright."
  exit 2
}
WORK="$(mktemp -d "${TMPDIR:-/tmp}/live-wire.XXXXXX")"
hashof() { sha256sum "$1" | cut -d' ' -f1; }
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

pids=(); OWN_BACKEND=""
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; [ -n "$OWN_BACKEND" ] && kill "$OWN_BACKEND" 2>/dev/null; }
trap cleanup EXIT

# --- backend (serves frontend/dist same-origin) ---
if ! curl -fsS "$SERVER/api/health" >/dev/null 2>&1; then
  for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
  sleep 1
  ( cd "$REPO/backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 FIL_CLAIM_LIMIT=1000000 \
      FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
  OWN_BACKEND=$!
  for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
fi
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log" 2>/dev/null; exit 2; }
[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

# dist must be SAME-ORIGIN (a prod-pointing bundle signals via prod and times out)
if grep -qs "api\.filament\.autumated\.com" "$REPO/frontend"/dist/assets/*.js 2>/dev/null; then
  echo "dist is prod-pointing — rebuilding same-origin…"
  ( cd "$REPO/frontend" && VITE_FILAMENT_API= npm run build >/dev/null 2>&1 ) || { echo "frontend rebuild failed"; exit 2; }
fi

# ============================================================ 5: CLI -> browser
printf '\n\033[1m== live 5: CLI -> browser ==\033[0m\n'
SMALL="$WORK/small.bin"; head -c $((5*1024*1024)) /dev/urandom > "$SMALL"
RM5="lw5room$$"
( cd "$HERE" && node browser-receiver.js "$SERVER/rooms/$RM5" >"$WORK/g5-pw.log" 2>&1 ) &
PW=$!; pids+=($PW); sleep 6
G5=0
timeout 120 "$BIN" send "$SMALL" --room "$RM5" --server "$SERVER" >"$WORK/g5-send.log" 2>&1 || G5=1
wait $PW || G5=1
if [ $G5 -eq 0 ] && grep -q "RECEIVE COMPLETE" "$WORK/g5-pw.log"; then
  ok "browser received from CLI (real framing)"
else
  echo "-- g5-pw.log --"; tail -n 8 "$WORK/g5-pw.log"; echo "-- g5-send.log --"; tail -n 8 "$WORK/g5-send.log"
  bad "CLI->browser"
fi

# ============================================================ 6: browser -> CLI x2
printf '\n\033[1m== live 6: browser -> CLI, two human-paced sends ==\033[0m\n'
D="$WORK/g6"; mkdir -p "$D"
FA="$WORK/g6-a.bin"; FB="$WORK/g6-b.bin"
head -c $((4*1024*1024)) /dev/urandom > "$FA"
head -c $((1024*1024))   /dev/urandom > "$FB"
RM6="lw6room$$"
timeout 240 "$BIN" receive -y --dir "$D" --room "$RM6" --server "$SERVER" >"$WORK/g6-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 2
G6=0
( cd "$HERE" && timeout 200 node browser-sender.js "$SERVER/rooms/$RM6" "$FA" "$FB" >"$WORK/g6-pw.log" 2>&1 ) || G6=1
wait $R || G6=1
if [ $G6 -eq 0 ] && [ "$(hashof "$D/g6-a.bin")" = "$(hashof "$FA")" ] \
   && [ "$(hashof "$D/g6-b.bin")" = "$(hashof "$FB")" ] \
   && grep -q "done (2 files)" "$WORK/g6-recv.log"; then
  ok "CLI received both browser sends byte-exact; link stayed alive between them"
else
  echo "-- g6-pw.log --"; tail -n 8 "$WORK/g6-pw.log"; echo "-- g6-recv.log --"; tail -n 8 "$WORK/g6-recv.log"
  bad "browser->CLI (note: a single failure may be the known G-i WebRTC glare under host contention — re-run)"
fi

echo
echo "==================================================="
echo "LIVE WIRE: $PASS passed, $FAIL failed"
echo "work: $WORK"
[ "$FAIL" = "0" ]
