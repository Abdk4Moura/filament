#!/usr/bin/env bash
# GATE 9 (ephemeral PAKE on the transfer path): `send --code` now mints a v2
# nameplate and runs the SAME SPAKE2 ceremony as `pair`, then DISCARDS the
# secret. A `recv <code>` claims the v2 nameplate and runs the ceremony too.
#
# Part A: a CLI->CLI `send --code` / `recv <code>` transfers a byte-exact file
#         WITH the ephemeral PAKE in the path, and stores NO secret (the secret
#         is discarded after auth).
# Part B (structural): the transfer path runs the shared ceremony and never
#         persists the ephemeral secret on a plain transfer.
#
# Configurable for any environment (defaults match the l1a fixture on 8093):
#   BIN     path to the release filament binary
#   SERVER  signaling backend URL (a LOCAL fixture, never prod)
set -uo pipefail
BIN=${BIN:-../../target/release/filament}
SERVER=${SERVER:-http://127.0.0.1:8093}
T=${T:-/tmp/l1a-gate9}
rm -rf "$T"; mkdir -p "$T/cfgS" "$T/cfgR" "$T/out"
SRC="$T/src.bin"; head -c 300000 /dev/urandom > "$SRC"
export FILAMENT_NONINTERACTIVE=1 RUST_LOG=

WORD="gigantic-element"
FILAMENT_CONFIG_DIR="$T/cfgS" FILAMENT_NAME=sender \
  "$BIN" --server "$SERVER" send "$SRC" --code --word "$WORD" </dev/null >"$T/send.log" 2>&1 &
S=$!
CODE=""
for i in $(seq 1 40); do
  CODE=$(grep -oiE "$WORD-[0-9]{3,5}" "$T/send.log" | head -1)
  [ -n "$CODE" ] && break; sleep 0.3
done
echo "minted v2 transfer code: ${CODE:-<none>}"
[ -z "$CODE" ] && { echo "GATE9 FAIL: no v2 code minted"; tail "$T/send.log"; kill $S 2>/dev/null; exit 1; }

FILAMENT_CONFIG_DIR="$T/cfgR" FILAMENT_NAME=receiver \
  "$BIN" --server "$SERVER" recv "$CODE" -y --dir "$T/out" </dev/null >"$T/recv.log" 2>&1 &
R=$!
for i in $(seq 1 120); do [ -f "$T/out/src.bin" ] && break; sleep 0.5; done
sleep 1
kill $S $R 2>/dev/null; wait $S 2>/dev/null; wait $R 2>/dev/null

PASS=1
if [ -f "$T/out/src.bin" ] && cmp -s "$SRC" "$T/out/src.bin"; then
  echo "GATE9.A PASS: byte-exact transfer WITH ephemeral PAKE"
else
  echo "GATE9.A FAIL: file not byte-exact"; echo "--send--"; tail -12 "$T/send.log"; echo "--recv--"; tail -12 "$T/recv.log"; PASS=0
fi

if [ -f "$T/cfgS/devices.json" ] || [ -f "$T/cfgR/devices.json" ]; then
  echo "GATE9.B FAIL: a plain transfer persisted a secret (must be discarded)"; PASS=0
else
  echo "GATE9.B PASS: no secret persisted by a plain transfer (ephemeral, discarded)"
fi

if grep -qi authenticat "$T/send.log" && grep -qi authenticat "$T/recv.log"; then
  echo "GATE9.C PASS: both sides ran the ephemeral SPAKE2 ceremony"
else
  echo "GATE9.C WARN: authentication line not found on both sides"
fi

[ "$PASS" = "1" ] && { echo "GATE9 PASS"; exit 0; }
echo "GATE9 FAIL"; exit 1
