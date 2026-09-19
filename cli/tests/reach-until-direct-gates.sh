#!/usr/bin/env bash
# `reach --until-direct`. Two daemons on one box are direct by nature, so this
# is the arm where the loop must stop at once and exit 0. Hermetic, fixture
# port 8122 ONLY. FILAMENT_BIN=/path/to/filament ./reach-until-direct-gates.sh
#
#   1  `reach <dev>` prints the one-line shape once ("pong via ...")
#   2  `reach <dev> --until-direct` names a direct route and exits 0
#   3  `--until-direct --json` emits the per-probe envelope, direct:true
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8122
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-reach.XXXXXX")"
DA="$WORK/A"
DB="$WORK/bravo"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow shell

# bravo's own daemon is what holds the link `--until-direct` watches.
env FILAMENT_CONFIG_DIR="$DB" FILAMENT_L2=1 "$BIN" --server "$SERVER" up --dir "$WORK/bravo-drop" >"$WORK/upB.log" 2>&1 &
FIX_PIDS+=($!)
sleep 12

say "1: plain reach prints the one-line shape"
out=$(timeout 60 env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" reach alpha 2>&1)
n=$(printf '%s\n' "$out" | grep -c "pong via ")
if [ "$n" = "1" ]; then ok "gate1: exactly one 'pong via' line"
else bad "gate1: expected one 'pong via' line, got $n (out: $out)"; fi

say "2: --until-direct stops on the direct path, exit 0"
out=$(timeout 60 env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" reach alpha --until-direct --timeout 20 2>&1)
rc=$?
echo "$out"
# The route label must come from the link, so assert a direct one by name
# rather than merely "not relay": a blank label would pass that.
if [ "$rc" = "0" ] && printf '%s\n' "$out" | grep -qE "pong via .*\((direct-quic|holepunched|direct[^)]*)\)"; then
  ok "gate2: direct route named, rc=0"
else
  bad "gate2: no direct line or rc=$rc (out: $out)"
fi

say "3: --until-direct --json emits the per-probe envelope"
js=$(timeout 60 env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" reach alpha --until-direct --timeout 20 --json 2>/dev/null | tail -1)
rc=$?
echo "$js"
if [ "$rc" = "0" ] && python3 -c "
import json,sys
v=json.loads('''$js''')
sys.exit(0 if v.get('verb')=='reach' and v.get('ok') and v['data']['direct'] is True and v['data']['addr'] else 1)
"; then ok "gate3: {verb:reach, direct:true, addr} on stdout"
else bad "gate3: envelope wrong or rc=$rc (line: $js)"; fi

echo; echo "==========================================="
echo "reach --until-direct gates: $PASS passed, $FAIL failed --$FAILED"
echo "work: $WORK"
[ "$FAIL" = "0" ]
