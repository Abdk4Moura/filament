#!/usr/bin/env bash
# `filament shell` (native PTY) denial + positive gates. Standalone, hermetic,
# fixture port 8103 ONLY. Proves that a shell refusal reaches the initiator as a
# nonzero exit + a reason, instead of an empty success (the #219/#223 defect).
#
#   FILAMENT_BIN=/path/to/filament ./shell-gates.sh
#
# Gates:
#   A  NEGATIVE no-cap — a paired device WITHOUT a shell grant is refused; exit
#      nonzero and the reason names the capability.
#   B  POSITIVE granted — `filament shell <peer> -- 'echo HELLO'` returns 0 with
#      HELLO on stdout.
#   C  NEIGHBOUR `-- true` — a legitimately fast-exiting remote command stays
#      exit 0 with no output; it must NOT be reported as a denial.
#   D  NEGATIVE revoked — after `revoke <peer> shell`, the shell is refused
#      (nonzero, reason).
#   E  NEGATIVE acceptor off — peer runs plain `up` (no --shell); the grant is
#      issued AFTER the daemon is already up (#219 repro order); the initiator
#      is told the acceptor is not serving, nonzero.
#
# Topology: side B = acceptor, side A = initiator, reciprocal pair secret
# (same-owner fleet, not a delegated device) so B trusts A. Gate E restarts the
# acceptor on plain `up`.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8103
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-shell-gates.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== shell gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

# --- own fixture backend on $PORT ---
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

DA="$WORK/A"; DB="$WORK/B"; mkdir -p "$DA" "$DB"
SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxB","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxA","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"

A_ENV=(env FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=boxA)

start_acceptor() {  # $1 = 1 (serve shell, grant-required) | 0 (plain up)
  local l2_env=""
  [ "$1" = "1" ] && l2_env="FILAMENT_L2=1"
  local drop="$WORK/Bdrop"; mkdir -p "$drop"
  env $l2_env FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB \
    "$BIN" up --dir "$drop" --server "$SERVER" >"$WORK/up.log" 2>&1 &
  pids+=($!)
  sleep 3
}

# ===================================================================== GATE A ==
# NEGATIVE: no shell grant yet, acceptor serving shell. Refused, nonzero, reason
# names the capability.
say A
start_acceptor 1
OUTA=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo SHOULD-NOT-RUN' 2>"$WORK/A.err" </dev/null)
rcA=$?
echo "## (no-cap) rc=$rcA out='$OUTA'"
if [ "$rcA" != "0" ] \
   && ! echo "$OUTA" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "refused\|not granted\|no shell cap" "$WORK/A.err"; then
  ok "gateA: no-cap device REFUSED a shell (nonzero + reason)"
else
  echo "-- A.err --"; cat "$WORK/A.err"; tail -5 "$WORK/up.log"
  bad "gateA: no-cap refusal NOT clean (rc=$rcA)"
fi

# ===================================================================== grant ===
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grant.log" 2>&1
grep -q '"shell"' "$DB/devices.json" || { echo "## grant did not persist"; cat "$DB/devices.json"; }

# ===================================================================== GATE B ==
# POSITIVE: granted, one-shot exec returns the command output, rc=0.
say B
OUTB=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo HELLO' 2>"$WORK/B.err" </dev/null)
rcB=$?
echo "## (granted) rc=$rcB out='$OUTB'"
if [ "$rcB" = "0" ] && echo "$OUTB" | grep -q "HELLO"; then
  ok "gateB: granted shell ran a remote command (rc=0, output)"
else
  echo "-- B.err --"; cat "$WORK/B.err"; tail -5 "$WORK/up.log"
  bad "gateB: granted shell FAILED (rc=$rcB)"
fi

# ===================================================================== GATE C ==
# NEIGHBOUR: `-- true` must stay exit 0, empty, NOT a denial.
say C
OUTC=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'true' 2>"$WORK/C.err" </dev/null)
rcC=$?
echo "## (-- true) rc=$rcC out='$OUTC'"
if [ "$rcC" = "0" ] && [ -z "$OUTC" ]; then
  ok "gateC: -- true stayed exit 0 with no output (not a false denial)"
else
  echo "-- C.err --"; cat "$WORK/C.err"
  bad "gateC: -- true mis-reported (rc=$rcC)"
fi

# ===================================================================== GATE D ==
# NEGATIVE: revoke the grant, then the same shell is refused.
say D
env FILAMENT_CONFIG_DIR="$DB" "$BIN" revoke boxA shell -y >"$WORK/revoke.log" 2>&1
OUTD=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo AFTER' 2>"$WORK/D.err" </dev/null)
rcD=$?
echo "## (revoked) rc=$rcD out='$OUTD'"
if [ "$rcD" != "0" ] \
   && ! echo "$OUTD" | grep -q "AFTER" \
   && grep -qi "refused\|not granted\|no shell cap" "$WORK/D.err"; then
  ok "gateD: revoked shell REFUSED (nonzero + reason)"
else
  echo "-- D.err --"; cat "$WORK/D.err"; tail -5 "$WORK/up.log"
  bad "gateD: revoked shell NOT refused (rc=$rcD)"
fi

# ===================================================================== GATE E ==
# NEGATIVE: acceptor OFF (plain `up`, no --shell), grant issued AFTER the daemon
# is up (#219 repro order). The initiator is told the acceptor is not serving.
say E
kill "${pids[-1]}" 2>/dev/null; sleep 1   # stop the --shell acceptor
start_acceptor 0                           # plain up
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grant2.log" 2>&1
OUTE=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo X' 2>"$WORK/E.err" </dev/null)
rcE=$?
echo "## (acceptor off) rc=$rcE out='$OUTE'"
# Message is "shell serving is off there..." since the acceptor wording change;
# match it alongside the older variants.
if [ "$rcE" != "0" ] && grep -qi "acceptor off\|not serving\|serving is off" "$WORK/E.err"; then
  ok "gateE: acceptor-off shell REFUSED with 'acceptor off' reason (nonzero)"
else
  echo "-- E.err --"; cat "$WORK/E.err"; tail -5 "$WORK/up.log"
  bad "gateE: acceptor-off refusal NOT clean (rc=$rcE)"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "shell gates: $PASS passed, $FAIL failed${FAILED:+ — failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
