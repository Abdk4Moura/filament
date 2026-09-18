#!/usr/bin/env bash
# grant / revoke / devices honesty for delegated (ceiling-bounded) devices.
# Standalone, hermetic, fixture port 8104 ONLY.
#
#   FILAMENT_BIN=/path/to/filament ./cap-verbs-gates.sh
#
# A delegated device's authority comes from the enrollment ceiling on its fleet
# certificate, never from the grant store, so `grant`/`revoke` cannot bind for it.
# These gates prove the verbs refuse instead of reporting success, and that
# `devices` renders what enforcement honours (the ceiling), not an inert grant.
#
# Gates:
#   A  #226 grant refuses — a device enrolled with the default ceiling
#      (transfer, mount) cannot be granted shell; refusal names the ceiling.
#   B  #228 revoke refuses — a capability inside the ceiling cannot be revoked;
#      refusal names `revoke <device> --certificate`.
#   C  devices shows the ceiling — the row and the --json caps field list the
#      ceiling, never a shell the verb claimed to grant.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8104
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-cap-verbs.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== cap-verb gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

DA="$WORK/A"; mkdir -p "$DA"
env FILAMENT_CONFIG_DIR="$DA" "$BIN" init --name alpha --recovery-file "$DA/rec.txt" --yes >/dev/null 2>&1 \
  || { echo "init failed"; exit 2; }
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/up.log" 2>&1 &
pids+=($!)
sleep 2

# Enroll a delegated device with the default ceiling, then have it join.
enroll() {  # $1 = device name, $2 = extra add flags (e.g. "--allow shell")
  local name="$1"; shift
  local ddir="$WORK/$name"; mkdir -p "$ddir"
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" add --for "$name" "$@" --out "$WORK/$name-inv.txt" --yes >/dev/null 2>&1
  env FILAMENT_CONFIG_DIR="$ddir" "$BIN" --server "$SERVER" join --invite-file "$WORK/$name-inv.txt" --name "$name" --no-interactive >"$WORK/$name-join.log" 2>&1
  sleep 2
}

# ===================================================================== GATE A ==
# #226: grant a capability outside the ceiling must refuse.
say A
enroll foxtrot
OUTA=$(env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" grant foxtrot shell 2>&1)
rcA=$?
echo "## (grant shell) rc=$rcA"
echo "$OUTA" | sed 's/^/    /'
if [ "$rcA" != "0" ] && echo "$OUTA" | grep -q "outside foxtrot's invitation ceiling" \
   && echo "$OUTA" | grep -q "cannot widen"; then
  ok "gateA: grant outside the ceiling REFUSED (names ceiling + cannot widen)"
else
  bad "gateA: grant outside the ceiling NOT refused (rc=$rcA)"
fi

# ===================================================================== GATE B ==
# #228: revoke a capability inside the ceiling must refuse, naming --certificate.
say B
enroll golf --allow mount
OUTB=$(env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke golf mount --yes 2>&1)
rcB=$?
echo "## (revoke mount) rc=$rcB"
echo "$OUTB" | sed 's/^/    /'
if [ "$rcB" != "0" ] && echo "$OUTB" | grep -q "comes from the enrollment ceiling" \
   && echo "$OUTB" | grep -q -- "--certificate"; then
  ok "gateB: revoke inside the ceiling REFUSED (names --certificate)"
else
  bad "gateB: revoke inside the ceiling NOT refused (rc=$rcB)"
fi

# ===================================================================== GATE C ==
# devices renders the ceiling, never an inert grant.
say C
JSON=$(env FILAMENT_CONFIG_DIR="$DA" "$BIN" devices --json 2>/dev/null)
echo "$JSON" | python3 -c "
import sys, json
rows = {d['name']: d['caps'] for d in json.loads(sys.stdin.read())}
foxtrot = rows.get('foxtrot', [])
if 'shell' in foxtrot:
    print('## foxtrot caps include shell (WRONG):', foxtrot); sys.exit(1)
if set(['transfer','mount']) != set(foxtrot):
    print('## foxtrot caps not the ceiling:', foxtrot); sys.exit(1)
print('## foxtrot caps =', foxtrot)
" 2>/dev/null
rcC=$?
if [ "$rcC" = "0" ]; then
  ok "gateC: devices --json shows the ceiling (transfer, mount), no inert shell"
else
  bad "gateC: devices --json does NOT show the enforcement-honoured ceiling"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "cap-verb gates: $PASS passed, $FAIL failed${FAILED:+ — failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
