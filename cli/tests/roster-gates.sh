#!/usr/bin/env bash
# Mesh roster v1: a spoke can SEE the mesh. Standalone, hermetic, fixture port
# 8120 ONLY. FILAMENT_BIN=/path/to/filament ./roster-gates.sh
#
#   A   each spoke's `devices` lists the sibling (from the owner-signed roster)
#   A2  `reach <sibling>` no longer says "no device named <sibling>"
#   B   the invariant: a revoked device is STILL refused by the acceptor even
#       though the roster still lists it (roster presence is evidence of nothing)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8120
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-roster.XXXXXX")"
DA="$WORK/A"
DB="$WORK/bravo"
DC="$WORK/charlie"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow shell
enroll_delegate charlie --allow shell

# Bring both spokes' daemons up so warm links to the owner form and the roster
# is pushed over them. The roster rides the control channel (no FILAMENT_L2
# needed on a spoke; L2 only gates the l2/pty/mount ACCEPTORS).
env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" up --dir "$WORK/bravo-drop" >"$WORK/upB.log" 2>&1 &
FIX_PIDS+=($!)
env FILAMENT_CONFIG_DIR="$DC" "$BIN" --server "$SERVER" up --dir "$WORK/charlie-drop" >"$WORK/upC.log" 2>&1 &
FIX_PIDS+=($!)
# Let warm links establish + the 5s roster tick fire + delivery land.
sleep 12

say "A: a spoke sees the mesh"
for name in bravo charlie; do
  local_cfg="$DB"; [ "$name" = "charlie" ] && local_cfg="$DC"
  other="charlie"; [ "$name" = "bravo" ] || other="bravo"
  out=$(env FILAMENT_CONFIG_DIR="$local_cfg" "$BIN" --server "$SERVER" devices 2>&1)
  echo "$out" | grep -q "MESH" && echo "$out" | grep -q "$other" \
    && ok "gateA: $name lists sibling $other under MESH" \
    || bad "gateA: $name did not list $other under MESH"
done

# The owner must stop reading as EXTERNAL on a spoke.
bravo_out=$(env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" devices 2>&1)
if echo "$bravo_out" | grep -q "FLEET" && echo "$bravo_out" | grep -q "alpha"; then
  ok "gateA-owner: bravo files the owner under FLEET, not EXTERNAL"
else
  bad "gateA-owner: bravo did not file the owner under FLEET (out: $bravo_out)"
fi

say "A2: reach <sibling> is a known name"
reach_out=$(timeout 40 env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" reach charlie 2>&1)
rc_reach=$?
# Positive proof of recognition (a pong, or the roster-only mesh narration),
# not mere absence of one error string: timeouts and crashes used to pass
# this gate for the wrong reason (any output without 'no device named').
echo "## (reach) rc=$rc_reach"
if [ "$rc_reach" = "0" ] && { echo "$reach_out" | grep -q "pong" || echo "$reach_out" | grep -q "in your mesh"; }; then
  ok "gateA2: reach charlie recognized the sibling (rc=0, positive proof)"
else
  bad "gateA2: reach charlie did not recognizably succeed (rc=$rc_reach out: $reach_out)"
fi

say "B: revoked device still refused even though the roster lists it"
# bravo can shell the owner BEFORE the revoke (positive control, owner-equivalent shell).
pre=$(env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" shell alpha -- 'echo PRE-OK' 2>&1)
echo "$pre" | grep -q "PRE-OK" \
  && ok "gateB-pre: bravo shells the owner before revoke" \
  || bad "gateB-pre: bravo could not shell before revoke (out: $pre)"
# Revoke bravo's certificate on the owner.
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke bravo --certificate --yes >/dev/null 2>&1
# Immediately: the acceptor refuses bravo on the tombstone. charlie's stored
# roster still lists bravo (the refresh has not re-pushed yet), so this is the
# sharp form of the invariant: roster presence is evidence of nothing.
post=$(env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" shell alpha -- 'echo POST-OK' 2>&1)
rc=$?
if [ "$rc" -ne 0 ]; then
  ok "gateB: revoked bravo is refused (exit $rc), roster presence did not resurrect it"
else
  bad "gateB: revoked bravo still got a shell (false success)"
fi

say "B2: after a roster refresh, the sibling no longer lists the revoked device, and it is still refused"
# Let the owner's 5s roster tick re-mint (bravo now filtered out of the snapshot,
# epoch bump) and push to charlie.
sleep 8
charlie_after=$(env FILAMENT_CONFIG_DIR="$DC" "$BIN" --server "$SERVER" devices 2>&1)
if echo "$charlie_after" | grep -q "bravo"; then
  bad "gateB2: charlie still lists revoked bravo after the refresh (out: $charlie_after)"
else
  ok "gateB2: charlie no longer lists revoked bravo after the roster refresh"
fi
# And the acceptor still refuses bravo if presented again (both halves).
again=$(env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" shell alpha -- 'echo AGAIN-OK' 2>&1)
rc2=$?
if [ "$rc2" -ne 0 ]; then
  ok "gateB2: revoked bravo is still refused after the refresh (exit $rc2)"
else
  bad "gateB2: revoked bravo got a shell after the refresh (false success)"
fi

echo
echo "roster gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
[ "$FAIL" -eq 0 ]
