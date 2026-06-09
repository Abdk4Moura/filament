#!/usr/bin/env bash
# Filament — rung-1 DIRECT CLI<->CLI transport gates (FILAMENT_DIRECT=1).
#
# OPT-IN. These exercise the additive QUIC transport (docs/design-direct-cli-
# transport.md realized over quinn). They are SEPARATE from gates.sh and never
# run by default — the direct path is gated behind FILAMENT_DIRECT.
#
# THREE gates (the negative-auth one is the security claim):
#   1. direct-connect : two known-device CLIs (FILAMENT_DIRECT=1) connect over
#                       QUIC (route: direct-quic, NOT relayed/webrtc) + byte-exact.
#   2. NEGATIVE auth   : a peer with the WRONG pair secret cannot establish —
#                       the keying-material MAC fails, peer rejected, ZERO bytes
#                       (and the WebRTC fallback also can't auto-accept it).
#   3. fallback        : direct blocked (FILAMENT_DIRECT_TEST_BLOCK=1) → WebRTC
#                       fallback still completes the transfer with the flag ON.
#
# Port 8098 ONLY for the fixture backend. Run from cli/:
#   ./tests/transport-gates.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="$CLI_DIR/target/release/filament"
PORT="${FILAMENT_TEST_PORT:-8098}"          # 8098 ONLY (task constraint)
SERVER="http://127.0.0.1:$PORT"
WORK="$(mktemp -d /root/.claude/jobs/330c2366/tmp/wt-transport-gates.XXXXXX)"
PYV="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"

PASS=0; FAIL=0; FAILED=""
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }
hashof() { sha256sum "$1" | cut -d' ' -f1; }
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  [ -n "${OWN_BACKEND:-}" ] && kill "$OWN_BACKEND" 2>/dev/null
}
trap cleanup EXIT

# ---- own fixture backend on 8098 -------------------------------------------
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
OWN_BACKEND=$!
for _ in $(seq 1 40); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; tail "$WORK/backend.log"; exit 2; }
# whoami must exist (we added it for candidate gathering)
curl -fsS "$SERVER/api/whoami" | grep -q '"ip"' || { echo "no /api/whoami"; exit 2; }

[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 2; }

# ---- payloads --------------------------------------------------------------
SMALL="$WORK/small.bin"; head -c 200000 /dev/urandom >"$SMALL"; H_SMALL=$(hashof "$SMALL")
BIG="$WORK/big.bin";     head -c 5000000 /dev/urandom >"$BIG";  H_BIG=$(hashof "$BIG")

# ---- pair two devices (A<->B), each stores the other's secret --------------
# Reuse the shipped --remember handshake over a code; this is the prerequisite
# for the known-device direct path. WebRTC (flag OFF) for the pairing itself.
DA="$WORK/devA"; DB="$WORK/devB"; DDROP="$WORK/drop"; mkdir -p "$DA" "$DB" "$DDROP"
pair() {
  local W="pair-$$-$RANDOM"
  FILAMENT_CONFIG_DIR="$DA" "$BIN" send "$SMALL" --word "$W" --remember boxB --server "$SERVER" >"$WORK/pair-a.log" 2>&1 &
  local SP=$!; sleep 3
  FILAMENT_CONFIG_DIR="$DB" timeout 60 "$BIN" recv "$W" -y --remember boxA --dir "$DB" --server "$SERVER" >"$WORK/pair-b.log" 2>&1
  wait $SP 2>/dev/null
}
say "setup: pairing A<->B (--remember over a code)"
pair
if [ -s "$DA/devices.json" ] && [ -s "$DB/devices.json" ]; then
  ok "paired (A knows boxB, B knows boxA)"
else
  bad "pairing setup"; tail -n 5 "$WORK/pair-a.log" "$WORK/pair-b.log"
  echo "RESULT: $PASS passed, $FAIL failed"; exit 1
fi

# ===========================================================================
say "GATE 1: direct-connect (FILAMENT_DIRECT=1) — route: direct-quic + byte-exact"
DG="$WORK/g1drop"; mkdir -p "$DG"
FILAMENT_CONFIG_DIR="$DB" FILAMENT_DIRECT=1 timeout 60 "$BIN" up --dir "$DG" --server "$SERVER" >"$WORK/g1-up.log" 2>&1 &
UP=$!; pids+=($UP); sleep 3
G1=0
FILAMENT_CONFIG_DIR="$DA" FILAMENT_DIRECT=1 timeout 60 "$BIN" send "$BIG" --to boxB --server "$SERVER" >"$WORK/g1-send.log" 2>&1 || G1=1
sleep 1; kill $UP 2>/dev/null; wait $UP 2>/dev/null
GOT="$DG/big.bin"
if [ $G1 -eq 0 ] \
   && [ -f "$GOT" ] && [ "$(hashof "$GOT")" = "$H_BIG" ] \
   && grep -hq "DIRECT-CONNECT ok (route: direct-quic)" "$WORK/g1-send.log" "$WORK/g1-up.log" \
   && ! grep -hq "route: relayed" "$WORK/g1-send.log" "$WORK/g1-up.log"; then
  echo "  marker: $(grep -h 'DIRECT-CONNECT ok' "$WORK/g1-send.log" "$WORK/g1-up.log" | head -1)"
  echo "  bytes:  $(stat -c%s "$GOT") / $(stat -c%s "$BIG")  hash-match"
  ok "GATE 1 direct-connect over QUIC, byte-exact"
else
  bad "GATE 1 direct-connect"
  echo "  G1=$G1 got=$([ -f "$GOT" ] && hashof "$GOT") want=$H_BIG"
  grep -h "DIRECT-\|route:" "$WORK/g1-send.log" "$WORK/g1-up.log" | head
  tail -n 4 "$WORK/g1-send.log" "$WORK/g1-up.log"
fi

# ===========================================================================
say "GATE 2: NEGATIVE auth — WRONG pair secret rejected, ZERO bytes"
# Corrupt B's stored secret for A so B holds the WRONG secret on BOTH transports:
#  - direct: keying-material MAC mismatch -> DIRECT-AUTH-FAIL, no QUIC link
#  - webrtc fallback: pair-proof fails -> B never trusts A; no -y + no tty -> declined
DBX="$WORK/devBwrong"; cp -r "$DB" "$DBX"
"$PYV" - "$DBX/devices.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
for e in d:
    if e.get("name")=="boxA":
        # flip every hex nibble -> a valid-length but WRONG 64-hex secret
        e["secret"]="".join("0" if c!="0" else "f" for c in e["secret"])[:64]
json.dump(d,open(p,"w"))
print("tampered boxA secret")
PY
DG2="$WORK/g2drop"; mkdir -p "$DG2"
# B (wrong secret) receives; no -y, stdin from /dev/null => untrusted offer declined.
FILAMENT_CONFIG_DIR="$DBX" FILAMENT_DIRECT=1 FILAMENT_REJOIN_SECS=4 timeout 45 \
  "$BIN" up --dir "$DG2" --server "$SERVER" </dev/null >"$WORK/g2-recv.log" 2>&1 &
RP=$!; pids+=($RP); sleep 3
# A (correct secret) tries to send.
FILAMENT_CONFIG_DIR="$DA" FILAMENT_DIRECT=1 timeout 25 \
  "$BIN" send "$SMALL" --to boxB --server "$SERVER" </dev/null >"$WORK/g2-send.log" 2>&1
sleep 2; kill $RP 2>/dev/null; wait $RP 2>/dev/null
# zero bytes: no completed file in the drop dir
BYTES=0; [ -f "$DG2/small.bin" ] && BYTES=$(stat -c%s "$DG2/small.bin" 2>/dev/null || echo 0)
if grep -hq "DIRECT-AUTH-FAIL" "$WORK/g2-send.log" "$WORK/g2-recv.log" \
   && [ "$BYTES" = "0" ] \
   && ! grep -hq "identity verified" "$WORK/g2-recv.log"; then
  echo "  marker: $(grep -h 'DIRECT-AUTH-FAIL' "$WORK/g2-send.log" "$WORK/g2-recv.log" | head -1)"
  echo "  bytes delivered: $BYTES (zero)"
  ok "GATE 2 negative-auth: MAC failed, rejected, zero bytes"
else
  bad "GATE 2 negative-auth"
  echo "  bytes=$BYTES (expected 0)"
  grep -h "DIRECT-\|identity\|verified\|MAC" "$WORK/g2-send.log" "$WORK/g2-recv.log" | head
fi

# ===========================================================================
say "GATE 3: fallback — direct blocked (flag ON) -> WebRTC still transfers"
DG3="$WORK/g3drop"; mkdir -p "$DG3"
FILAMENT_CONFIG_DIR="$DB" FILAMENT_DIRECT=1 FILAMENT_DIRECT_TEST_BLOCK=1 timeout 90 \
  "$BIN" up --dir "$DG3" --server "$SERVER" >"$WORK/g3-up.log" 2>&1 &
UP=$!; pids+=($UP); sleep 3
G3=0
FILAMENT_CONFIG_DIR="$DA" FILAMENT_DIRECT=1 FILAMENT_DIRECT_TEST_BLOCK=1 timeout 75 \
  "$BIN" send "$BIG" --to boxB --server "$SERVER" >"$WORK/g3-send.log" 2>&1 || G3=1
sleep 1; kill $UP 2>/dev/null; wait $UP 2>/dev/null
GOT3="$DG3/big.bin"
if [ $G3 -eq 0 ] && [ -f "$GOT3" ] && [ "$(hashof "$GOT3")" = "$H_BIG" ] \
   && grep -hq "DIRECT-FALLBACK\|DIRECT-BLOCKED" "$WORK/g3-send.log" "$WORK/g3-up.log" \
   && ! grep -hq "DIRECT-CONNECT ok" "$WORK/g3-send.log" "$WORK/g3-up.log"; then
  echo "  marker: $(grep -h 'DIRECT-FALLBACK\|DIRECT-BLOCKED' "$WORK/g3-send.log" "$WORK/g3-up.log" | head -1)"
  echo "  route:  $(grep -h 'route:' "$WORK/g3-up.log" "$WORK/g3-send.log" | head -1)"
  ok "GATE 3 fallback to WebRTC completed byte-exact"
else
  bad "GATE 3 fallback"
  echo "  G3=$G3 got=$([ -f "$GOT3" ] && hashof "$GOT3") want=$H_BIG"
  grep -h "DIRECT-\|route:" "$WORK/g3-send.log" "$WORK/g3-up.log" | head
  tail -n 4 "$WORK/g3-send.log" "$WORK/g3-up.log"
fi

echo
echo "================ RESULT: $PASS passed, $FAIL failed ================"
[ -n "$FAILED" ] && echo "failed:${FAILED//|/ }"
echo "logs + work dir: $WORK"
[ $FAIL -eq 0 ]
