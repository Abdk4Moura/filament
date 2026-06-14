#!/usr/bin/env bash
# GATE 9b (shared-auto-room multi-peer PAKE): the receiver runs an INDEPENDENT
# ephemeral SPAKE2 ceremony per candidate peer, so a decoy sharing the sender's
# auto-room can NOT make the receiver mis-latch and bail.
#
# Topology (the bug repro):
#   - SENDER:  `send <file> --code --word W`. A `send --code` joins the network
#              AUTO room (not a dedicated room) and pair-creates the nameplate.
#   - DECOY:   a plain `recv` (no code) on the SAME backend, so it resolves to the
#              SAME auto room and sits there. It NEVER runs the matching ceremony.
#   - RECEIVER: `recv <code>`. The claim matches it into the sender's CURRENT room
#              (the shared auto room), where it meets BOTH the real sender and the
#              decoy. It must authenticate the REAL sender (per-peer ceremonies)
#              and transfer byte-exact, ignoring the decoy.
#
# The decoy is started FIRST so it is present (and may appear / be driven) before
# the real sender's channel, exactly the ordering that latched the old single
# ceremony onto the wrong peer.
#
# Asserts:
#   A: the file arrives byte-exact at the receiver despite the decoy.
#   B: no secret is persisted by the plain transfer (ephemeral, discarded).
#   C: the decoy received NOTHING (it must not be handed the file).
#
# Configurable (defaults match the l1a fixture on 8093):
#   BIN     path to the release filament binary
#   SERVER  signaling backend URL (a LOCAL fixture, never prod)
set -uo pipefail
BIN=${BIN:-../../target/release/filament}
SERVER=${SERVER:-http://127.0.0.1:8093}
T=${T:-/tmp/l1a-gate9b}
rm -rf "$T"; mkdir -p "$T/cfgS" "$T/cfgD" "$T/cfgR" "$T/outR" "$T/outD"
SRC="$T/src.bin"; head -c 300000 /dev/urandom > "$SRC"
export FILAMENT_NONINTERACTIVE=1 RUST_LOG=

# DECOY first: a plain listener that joins the shared auto room and does nothing.
FILAMENT_CONFIG_DIR="$T/cfgD" FILAMENT_NAME=decoy \
  "$BIN" --server "$SERVER" recv -y --dir "$T/outD" </dev/null >"$T/decoy.log" 2>&1 &
D=$!
sleep 2  # let the decoy land in the auto room before the sender shows up

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
[ -z "$CODE" ] && { echo "GATE9b FAIL: no v2 code minted"; tail "$T/send.log"; kill $S $D 2>/dev/null; exit 1; }

FILAMENT_CONFIG_DIR="$T/cfgR" FILAMENT_NAME=receiver \
  "$BIN" --server "$SERVER" recv "$CODE" -y --dir "$T/outR" </dev/null >"$T/recv.log" 2>&1 &
R=$!
for i in $(seq 1 120); do [ -f "$T/outR/src.bin" ] && break; sleep 0.5; done
sleep 1
kill $S $D $R 2>/dev/null; wait $S 2>/dev/null; wait $D 2>/dev/null; wait $R 2>/dev/null

PASS=1
if [ -f "$T/outR/src.bin" ] && cmp -s "$SRC" "$T/outR/src.bin"; then
  echo "GATE9b.A PASS: receiver authenticated the real sender + got byte-exact file despite the decoy"
else
  echo "GATE9b.A FAIL: receiver did not get the byte-exact file"
  echo "--send--"; tail -15 "$T/send.log"
  echo "--recv--"; tail -20 "$T/recv.log"
  echo "--decoy--"; tail -10 "$T/decoy.log"
  PASS=0
fi

if [ -f "$T/cfgS/devices.json" ] || [ -f "$T/cfgR/devices.json" ]; then
  echo "GATE9b.B FAIL: a plain transfer persisted a secret (must be discarded)"; PASS=0
else
  echo "GATE9b.B PASS: no secret persisted (ephemeral PAKE secret discarded)"
fi

if [ -f "$T/outD/src.bin" ]; then
  echo "GATE9b.C FAIL: the DECOY received the file (it must never be handed bytes)"; PASS=0
else
  echo "GATE9b.C PASS: the decoy received nothing"
fi

[ "$PASS" = "1" ] && { echo "GATE9b PASS"; exit 0; }
echo "GATE9b FAIL"; exit 1
