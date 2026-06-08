#!/usr/bin/env bash
# GATE 3 (wrong-password-burns / no-retry): a claimer with the WRONG words but
# the right nameplate FAILS key confirmation AND consumes the nameplate. A
# second claim of the same nameplate finds nothing (burned). No silent same-code
# retry is possible — a failed pairing forces a FRESH code.
set -uo pipefail
BIN=/root/wt-l1a/cli/target/release/filament
SERVER=http://127.0.0.1:8093
T=/root/.claude/jobs/330c2366/tmp/wt-l1a-gates
rm -rf "$T/g3"; mkdir -p "$T/g3/cfgA" "$T/g3/cfgB" "$T/g3/cfgC"

# Creator mints a code.
FILAMENT_CONFIG_DIR=$T/g3/cfgA FILAMENT_PAIR_GRACE_SECS=20 \
  "$BIN" --server "$SERVER" pair --name x </dev/null >"$T/g3/creator.log" 2>&1 &
CRE=$!
CODE=""
for i in $(seq 1 50); do
  CODE=$(grep -oE '[A-Z]+-[A-Z]+-[A-Z]+-[0-9]{3,5}' "$T/g3/creator.log" | head -1)
  [ -n "$CODE" ] && break; sleep 0.2
done
[ -z "$CODE" ] && { echo "GATE3 FAIL: no code minted"; kill $CRE 2>/dev/null; exit 1; }
NAMEPLATE="${CODE##*-}"
echo "minted: $CODE  (nameplate $NAMEPLATE)"

# Claimer uses the right NAMEPLATE but WRONG words.
WRONG="tidy-walrus-violet-$NAMEPLATE"
FILAMENT_CONFIG_DIR=$T/g3/cfgB FILAMENT_PAIR_GRACE_SECS=20 \
  "$BIN" --server "$SERVER" pair "$WRONG" --name y </dev/null >"$T/g3/claimer.log" 2>&1 &
CLA=$!

# Wait for the ceremony to resolve (both should end — confirm fails on both).
for i in $(seq 1 50); do
  kill -0 $CLA 2>/dev/null || break; sleep 0.5
done
wait $CLA 2>/dev/null
# Creator may still be waiting on its grace; give it a moment then stop it.
sleep 2; kill $CRE 2>/dev/null; wait $CRE 2>/dev/null

echo "--- claimer log (tail) ---"; tail -6 "$T/g3/claimer.log"

# 1) Claimer must NOT have stored a secret.
STORED_B=$(cat "$T/g3/cfgB/devices.json" 2>/dev/null | grep -c '"secret"')
# 2) Claimer must REFUSE (confirmation failure), not silently agree.
REFUSED=$(grep -ciE 'REFUSED|confirmation failed|tamper|wrong code|disconnected|could not connect' "$T/g3/claimer.log")

# 3) Nameplate is BURNED: a fresh claim of the same nameplate finds nothing.
FILAMENT_CONFIG_DIR=$T/g3/cfgC \
  "$BIN" --server "$SERVER" pair "good-otter-ruby-$NAMEPLATE" --name z </dev/null >"$T/g3/reclaim.log" 2>&1 &
RC=$!
for i in $(seq 1 20); do kill -0 $RC 2>/dev/null || break; sleep 0.5; done
wait $RC 2>/dev/null
BURNED=$(grep -ciE 'rejected|invalid|burn|expire|never used' "$T/g3/reclaim.log")
echo "--- reclaim log (tail) ---"; tail -4 "$T/g3/reclaim.log"

echo "claimer stored secret count : $STORED_B (want 0)"
echo "claimer refused             : $REFUSED (want >=1)"
echo "nameplate burned on reclaim : $BURNED (want >=1)"

if [ "$STORED_B" = "0" ] && [ "$REFUSED" -ge 1 ] && [ "$BURNED" -ge 1 ]; then
  echo "GATE3 PASS: wrong password refused, nothing stored, nameplate burned (no silent retry)"
  exit 0
fi
echo "GATE3 FAIL"; exit 1
