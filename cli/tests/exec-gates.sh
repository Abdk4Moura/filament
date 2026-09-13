#!/usr/bin/env bash
# `filament exec` end-to-end gates. Standalone, hermetic, fixture port 8104 ONLY.
# Proves argv[] crosses EXACTLY (spaces/quotes/globs intact on both platforms by
# construction -- the vector is never joined, split, or re-parsed), stdout and
# stderr stay separate, exit codes surface, and real byte traffic works.
#
#   FILAMENT_BIN=/path/to/filament ./exec-gates.sh
#
# Gates:
#   A  NEGATIVE no-grant -- acceptor serving, initiator NOT granted: refused,
#      nonzero, reason names the capability (exercises authorize_exec live).
#   B  SPACES -- an argument with spaces arrives as ONE argv element.
#   C  QUOTES -- single and double quotes inside one argument survive byte-exact.
#   D  GLOB LITERAL -- `*.log` arrives literally (proves no shell expansion).
#   E  STDERR SPLIT -- bytes written to each stream land on the right local
#      descriptor, exit code intact.
#   F  EXIT CODES -- remote `exit 3` surfaces as our rc=3.
#   G  SIGNAL DEATH -- remote kill -9 surfaces as 137 (unix only: no portable
#      Windows equivalent exists; the 128+signal MAPPING is unit-tested).
#   H  BULK BYTES -- 1 MiB through `cat` matches local sha256 (binary-safe bulk).
#   I  RSYNC-OVER-EXEC -- real rsync across the link (skipped cleanly when rsync
#      is absent on PATH). `rsync -e '<filament> exec'` appends
#      `boxB rsync --server ...`, which our trailing-argv shape takes directly --
#      itself an argv-exactness proof under a real workload.
#   J  NEGATIVE revoked -- grant revoked, same command refused again.
#
# PLATFORM NOTE, stated honestly: executed here on Linux. The wire property
# under test (array preserved, never re-parsed) is platform-independent code --
# no cfg branches touch the argv path -- but the test BINARIES differ per
# platform (/bin/echo vs cmd builtins). The ECHO/SH/CAT variables below are the
# single porting point; the kill-137 gate is uname-guarded to unix.
#
# Topology: side B = acceptor, side A = initiator, reciprocal pair secret
# (same-owner fleet, not a delegated device) so B trusts A.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8104
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-exec-gates.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== exec gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

# --- platform command mapping (the single porting point) ---
if uname -s | grep -qiE "mingw|msys|cygwin|windows"; then
    PLATFORM="windows"
    ECHO_BIN="cmd"; ECHO_PREFIX="/c echo"
    SH_BIN="cmd"; SH_C="/C"
    CAT_BIN="cmd"; CAT_PREFIX="/C type"
else
    PLATFORM="unix"
    ECHO_BIN="/bin/echo"; ECHO_PREFIX=""
    SH_BIN="/bin/sh"; SH_C="-c"
    CAT_BIN="/bin/cat"; CAT_PREFIX=""
fi

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

start_acceptor() {
  local drop="$WORK/Bdrop"; mkdir -p "$drop"
  env FILAMENT_L2=1 FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB \
    "$BIN" up --dir "$drop" --server "$SERVER" >"$WORK/up.log" 2>&1 &
  pids+=($!)
  sleep 3
}

# ===================================================================== GATE A ==
# NEGATIVE: serving acceptor, initiator with NO grant. Refused, nonzero, reason.
say A
start_acceptor
OUTA=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" SHOULD-NOT-RUN 2>"$WORK/A.err" </dev/null)
rcA=$?
echo "## (no-grant) rc=$rcA out='$OUTA'"
if [ "$rcA" != "0" ] \
   && ! echo "$OUTA" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "refused\|not granted\|no shell cap" "$WORK/A.err"; then
  ok "gateA: ungranted exec REFUSED (nonzero + reason)"
else
  echo "-- A.err --"; cat "$WORK/A.err"; tail -5 "$WORK/up.log"
  bad "gateA: ungranted exec NOT refused cleanly (rc=$rcA)"
fi

# =================================================================== grant ====
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grant.log" 2>&1
grep -q '"shell"' "$DB/devices.json" || { echo "## grant did not persist"; cat "$DB/devices.json"; }

# ===================================================================== GATE B ==
# SPACES: one argv element with spaces arrives whole.
say B
OUTB=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" 'hello world' 2>"$WORK/B.err" </dev/null)
rcB=$?
echo "## (spaces) rc=$rcB out='$OUTB'"
if [ "$rcB" = "0" ] && [ "$OUTB" = "hello world" ]; then
  ok "gateB: spaced argument arrived as ONE argv element"
else
  echo "-- B.err --"; cat "$WORK/B.err"
  bad "gateB: spaces NOT preserved (rc=$rcB out='$OUTB')"
fi

# ===================================================================== GATE C ==
# QUOTES: single and double quotes inside one argument survive byte-exact.
say C
OUTC=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" 'say "hi" and '"'"'bye'"'" 2>"$WORK/C.err" </dev/null)
rcC=$?
echo "## (quotes) rc=$rcC out='$OUTC'"
if [ "$rcC" = "0" ] && [ "$OUTC" = 'say "hi" and '"'"'bye'"'" ]; then
  ok "gateC: quotes survived byte-exact (no shell re-parse)"
else
  echo "-- C.err --"; cat "$WORK/C.err"
  bad "gateC: quotes NOT preserved (rc=$rcC out='$OUTC')"
fi

# ===================================================================== GATE D ==
# GLOB LITERAL: `*.log` arrives literally -- proves no shell expansion.
say D
OUTD=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" '*.log' 2>"$WORK/D.err" </dev/null)
rcD=$?
echo "## (glob) rc=$rcD out='$OUTD'"
if [ "$rcD" = "0" ] && [ "$OUTD" = '*.log' ]; then
  ok "gateD: glob arrived literally (no shell expansion)"
else
  echo "-- D.err --"; cat "$WORK/D.err"
  bad "gateD: glob NOT literal (rc=$rcD out='$OUTD')"
fi

# ===================================================================== GATE E ==
# STDERR SPLIT: each stream lands on the right local descriptor.
say E
OUTE=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$SH_BIN" "$SH_C" 'echo out; echo err >&2' 2>"$WORK/E.err" </dev/null)
rcE=$?
echo "## (split) rc=$rcE out='$OUTE' err='$(cat "$WORK/E.err")'"
if [ "$rcE" = "0" ] && [ "$OUTE" = "out" ] && grep -qx "err" "$WORK/E.err"; then
  ok "gateE: stdout/stderr split correctly"
else
  echo "-- E.err --"; cat "$WORK/E.err"
  bad "gateE: streams NOT split (rc=$rcE out='$OUTE')"
fi

# ================================================================== GATE E2 ==
# STDIN ROUND-TRIP: bytes on our stdin reach the remote child's stdin and
# come back (the rsync gate's precondition, isolated -- every earlier gate
# uses empty stdin).
say E2
OUTE2=$(echo "STDIN-ROUNDTRIP-67890" | timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$CAT_BIN" 2>"$WORK/E2.err")
rcE2=$?
echo "## (stdin) rc=$rcE2 out='$OUTE2'"
if [ "$rcE2" = "0" ] && [ "$OUTE2" = "STDIN-ROUNDTRIP-67890" ]; then
  ok "gateE2: stdin bytes reached the remote child and returned"
else
  echo "-- E2.err --"; cat "$WORK/E2.err"
  bad "gateE2: stdin round-trip FAILED (rc=$rcE2 out='$OUTE2')"
fi

# ================================================================== GATE E3 ==
# EPIPE: a flooded stdin against an early-exiting child (`yes | head -1`)
# must end cleanly (output + rc 0), not hang: a write error to the dead
# child's stdin is treated as EOF and the loop still waits for its exit.
say E3
OUTE3=$(yes | timeout 20 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- head -n 1 2>"$WORK/E3.err")
rcE3=$?
echo "## (epipe) rc=$rcE3 out='$OUTE3'"
if [ "$rcE3" = "0" ] && [ "$OUTE3" = "y" ]; then
  ok "gateE3: flooded stdin vs early exit ended cleanly (output + rc 0)"
else
  echo "-- E3.err --"; cat "$WORK/E3.err"
  bad "gateE3: EPIPE case hung or mis-reported (rc=$rcE3 out='$OUTE3')"
fi

# ===================================================================== GATE F ==
# EXIT CODES: remote exit status becomes our exit code.
say F
timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$SH_BIN" "$SH_C" 'exit 3' 2>"$WORK/F.err" </dev/null
rcF=$?
echo "## (exit 3) rc=$rcF"
if [ "$rcF" = "3" ]; then
  ok "gateF: remote exit 3 surfaced as our rc=3"
else
  echo "-- F.err --"; cat "$WORK/F.err"
  bad "gateF: exit code NOT surfaced (rc=$rcF)"
fi

# ===================================================================== GATE G ==
# SIGNAL DEATH -> 137. Unix only: no portable Windows equivalent exists, and
# the 128+signal MAPPING itself is unit-tested (status_mapping_is_shell_convention).
say G
if [ "$PLATFORM" = "unix" ]; then
  timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$SH_BIN" "$SH_C" 'kill -9 $$' 2>"$WORK/G.err" </dev/null
  rcG=$?
  echo "## (kill -9) rc=$rcG"
  if [ "$rcG" = "137" ]; then
    ok "gateG: signal death surfaced as 137 (128+SIGKILL)"
  else
    echo "-- G.err --"; cat "$WORK/G.err"
    bad "gateG: signal death NOT 137 (rc=$rcG)"
  fi
else
  echo "SKIP gateG: signal-death has no portable Windows equivalent (mapping is unit-tested)"
fi

# ===================================================================== GATE H ==
# BULK BYTES: 1 MiB through `cat` matches local sha256 (binary-safe bulk).
say H
head -c 1048576 /dev/urandom > "$WORK/bulk.bin"
sha256sum "$WORK/bulk.bin" | awk '{print $1}' > "$WORK/bulk.want"
timeout 60 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$CAT_BIN" "$WORK/bulk.bin" 2>"$WORK/H.err" </dev/null | sha256sum | awk '{print $1}' > "$WORK/bulk.got"
rcH=${PIPESTATUS[0]}
echo "## (bulk) rc=$rcH"
if [ "$rcH" = "0" ] && cmp -s "$WORK/bulk.want" "$WORK/bulk.got"; then
  ok "gateH: 1 MiB bulk bytes match sha256"
else
  echo "-- H.err --"; cat "$WORK/H.err"
  bad "gateH: bulk bytes MISMATCH (rc=$rcH)"
fi

# ===================================================================== GATE I ==
# RSYNC-OVER-EXEC: real rsync across the link; skipped cleanly without rsync.
say I
if command -v rsync >/dev/null 2>&1; then
  mkdir -p "$WORK/rsrc" "$WORK/rdest"
  echo "rsync-payload-$(date +%s)" > "$WORK/rsrc/payload.txt"
  timeout 60 ${A_ENV[@]} rsync -av -e "$BIN --server $SERVER exec" "$WORK/rsrc/" "boxB:$WORK/rdest/" >"$WORK/I.log" 2>&1
  rcI=$?
  echo "## (rsync) rc=$rcI"
  if [ "$rcI" = "0" ] && cmp -s "$WORK/rsrc/payload.txt" "$WORK/rdest/payload.txt"; then
    ok "gateI: rsync-over-exec transferred byte-identical"
  else
    echo "-- I.log --"; cat "$WORK/I.log"
    bad "gateI: rsync-over-exec FAILED (rc=$rcI)"
  fi
else
  echo "SKIP gateI: no rsync on PATH"
fi

# ===================================================================== GATE J ==
# NEGATIVE revoked: same command refused again after revoke.
say J
env FILAMENT_CONFIG_DIR="$DB" "$BIN" revoke boxA shell -y >"$WORK/revoke.log" 2>&1
OUTJ=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" AFTER 2>"$WORK/J.err" </dev/null)
rcJ=$?
echo "## (revoked) rc=$rcJ out='$OUTJ'"
if [ "$rcJ" != "0" ] \
   && ! echo "$OUTJ" | grep -q "AFTER" \
   && grep -qi "refused\|not granted\|no shell cap" "$WORK/J.err"; then
  ok "gateJ: revoked exec REFUSED (nonzero + reason)"
else
  echo "-- J.err --"; cat "$WORK/J.err"
  bad "gateJ: revoked exec NOT refused (rc=$rcJ)"
fi

# ===================================================================== GATE K ==
# REVOKED MID-SESSION: a long exec dies (nonzero + revoked reason) when the
# shell grant is revoked underneath it -- the receiver ticker re-asks the
# gate instead of letting the child run out its clock.
say K
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grantK.log" 2>&1
timeout 40 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- /bin/sleep 30 2>"$WORK/K.err" </dev/null &
KPid=$!
sleep 5
env FILAMENT_CONFIG_DIR="$DB" "$BIN" revoke boxA shell -y >"$WORK/revokeK.log" 2>&1
wait "$KPid"
rcK=$?
echo "## (revoked mid-session) rc=$rcK"
if [ "$rcK" != "0" ] && [ "$rcK" != "124" ] && grep -qi "revoked" "$WORK/K.err"; then
  ok "gateK: mid-session revoke ended the exec (nonzero + reason)"
else
  echo "-- K.err --"; cat "$WORK/K.err"
  bad "gateK: revoked session NOT ended (rc=$rcK)"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "exec gates: $PASS passed, $FAIL failed${FAILED:+ — failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
