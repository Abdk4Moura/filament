#!/usr/bin/env bash
# GATE 1 (mutual-key): two honest `filament pair` processes with the SAME spoken
# code derive the SAME pinned secret over the real wire (8093). Key confirmation
# passes; both write byte-identical devices.json secrets.
set -uo pipefail
BIN=/root/wt-l1a/cli/target/release/filament
SERVER=http://127.0.0.1:8093
T=/root/.claude/jobs/330c2366/tmp/wt-l1a-gates
CFG_A=$T/g1-cfgA; CFG_B=$T/g1-cfgB
rm -rf "$CFG_A" "$CFG_B"; mkdir -p "$CFG_A" "$CFG_B"

# Creator: mint a code, pair, store under name "bee".
FILAMENT_CONFIG_DIR=$CFG_A FILAMENT_PAIR_GRACE_SECS=30 \
  "$BIN" --server "$SERVER" pair --name bee </dev/null >"$T/g1-creator.log" 2>&1 &
CRE=$!

# Wait for the creator to print the full code (UPPERCASE on its own indented line).
CODE=""
for i in $(seq 1 50); do
  CODE=$(grep -oE '[A-Z]+-[A-Z]+-[A-Z]+-[0-9]{3,5}' "$T/g1-creator.log" | head -1)
  [ -n "$CODE" ] && break
  sleep 0.2
done
if [ -z "$CODE" ]; then echo "GATE1 FAIL: creator never printed a code"; cat "$T/g1-creator.log"; kill $CRE 2>/dev/null; exit 1; fi
echo "minted code: $CODE"

# Claimer types the code (lowercased — the CLI normalizes anyway).
FILAMENT_CONFIG_DIR=$CFG_B FILAMENT_PAIR_GRACE_SECS=30 \
  "$BIN" --server "$SERVER" pair "$(echo "$CODE" | tr 'A-Z' 'a-z')" --name ant </dev/null >"$T/g1-claimer.log" 2>&1 &
CLA=$!

# Wait for both to finish (bounded).
for i in $(seq 1 60); do
  kill -0 $CRE 2>/dev/null || kill -0 $CLA 2>/dev/null || break
  sleep 0.5
done
wait $CRE 2>/dev/null; wait $CLA 2>/dev/null

SEC_A=$(grep -oE '"secret": "[0-9a-f]{64}"' "$CFG_A/devices.json" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
SEC_B=$(grep -oE '"secret": "[0-9a-f]{64}"' "$CFG_B/devices.json" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
echo "creator secret: ${SEC_A:-<none>}"
echo "claimer secret: ${SEC_B:-<none>}"
echo "--- creator devices.json ---"; cat "$CFG_A/devices.json" 2>/dev/null
echo "--- claimer devices.json ---"; cat "$CFG_B/devices.json" 2>/dev/null

if [ -n "$SEC_A" ] && [ "$SEC_A" = "$SEC_B" ]; then
  echo "GATE1 PASS: both derived the SAME pinned secret (confirmation passed)"; exit 0
else
  echo "GATE1 FAIL: secrets differ or missing"; echo "--creator log--"; cat "$T/g1-creator.log"; echo "--claimer log--"; cat "$T/g1-claimer.log"; exit 1
fi
