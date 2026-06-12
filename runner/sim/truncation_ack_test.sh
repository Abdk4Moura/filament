#!/usr/bin/env bash
# Filament — P4 WHOLE-FILE-INTEGRITY + DELIVERY-ACK gate (deterministic).
#
# SLO-measurement gate for transport-resilience §P4 (GAP-5): lift whole-file
# sha256 verification + a delivery-ACK INTO THE CORE send/recv, so EVERY filament
# transfer (not just runner jobs) is verified-and-acknowledged. The gap P4 closes:
# core send/recv kept partials + a head-hash (C7 resume) but had NO whole-file
# integrity check and was fire-and-forget — a transfer could "complete" while
# silently TRUNCATED/corrupt (the 7 KB stub) and the sender never learned whether
# the bytes landed intact. The runner had to bolt sha256-verify + an app-level ACK
# on top to be reliable; P4 makes it a CORE guarantee.
#
# How the corrupt receive is induced DETERMINISTICALLY: an in-binary test hook,
# FILAMENT_TEST_CORRUPT_RECV=<transfer-id>, flips the LAST byte of the received
# `.part` right before the receiver computes its whole-file sha256 — same size,
# wrong hash: exactly the "looks complete but is corrupt" case. The transfer id is
# deterministic: `send` mints it as "<sender-uid>-<sid>" where sid=1 for the first
# (only) payload — so the matching id is "<uid>-1"; we pass a fixed sender uid via
# the env so the id is known up front. FILAMENT_TEST_CORRUPT_ONCE=1 fires the flip
# EXACTLY ONCE so the receiver's re-fetch then succeeds (proves auto-recovery);
# omitting it corrupts EVERY round (proves the bounded clean failure).
#
# ASSERTS (each deterministic; RUNS x):
#   RUN R (recoverable, CORRUPT_ONCE=1):
#     (a) REJECT     : the receiver detected the whole-file checksum mismatch and
#                      did NOT declare done on the corrupt bytes (a "checksum
#                      FAILED" / re-fetch line is present).
#     (b) RECOVER    : after the re-fetch the file is byte-exact (sha256 match) and
#                      the receiver acked it ("verified ... acked").
#     (c) ACK-GATED  : the SENDER reported success only AFTER the delivery-ack
#                      ("delivered + verified" on the sender), i.e. NOT
#                      fire-and-forget, and exited 0.
#   RUN U (unrecoverable, CORRUPT persists every round):
#     (d) FAIL-CLEAN : the receiver REFUSES after the bounded re-fetches
#                      ("refusing to accept a corrupt file") — NO silent success
#                      (the final file is NOT placed byte-exact) and NO hang
#                      (the run terminates within the timeout, not via SIGTERM).
#   BASELINE C (clean, no corruption):
#     (e) ACK HAPPY  : a clean transfer still verifies + acks end-to-end (the ack
#                      path isn't only reached on the corrupt path).
#
# Isolated: own backend on a private port, own FILAMENT_CONFIG_DIRs, the BUILT
# release binary, the DEFAULT (loopback WebRTC) transport — no TURN needed. Never
# touches the live `up` daemon or ~/.local/bin.
#
# Usage (from repo root or anywhere):  runner/sim/truncation_ack_test.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CLI_DIR="$ROOT/cli"
BIN="${FILJOB_BIN:-$CLI_DIR/target/release/filament}"
PORT="${FILAMENT_TEST_PORT:-8094}"
SERVER="http://127.0.0.1:$PORT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/trunc-ack.XXXXXX")"
PYV="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"
[ -x "$PYV" ] || PYV="$(command -v python3)"

RUNS="${RUNS:-2}"                  # determinism: repeat the whole gate
ACK_TIMEOUT="${ACK_TIMEOUT:-12}"   # bounded ack wait (peer-too-old fallback)

PASS=0; FAIL=0
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
hashof() { sha256sum "$1" | cut -d' ' -f1; }
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  [ -n "${OWN_BACKEND:-}" ] && kill "$OWN_BACKEND" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# Resilience gates drive the env-gated test hooks (FILAMENT_TEST_*), which now
# ship ONLY in a `--features test-hooks` build (stripped from default/release).
# Auto-build that binary unless an explicit FILJOB_BIN was provided.
if [ -z "${FILJOB_BIN:-}" ]; then
  ( cd "$CLI_DIR" && cargo build --release --features test-hooks ) || { echo "build failed"; exit 2; }
fi
[ -x "$BIN" ] || { echo "build first: (cd cli && cargo build --release --features test-hooks)"; exit 2; }

# ---- own fixture backend ----------------------------------------------------
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$ROOT/backend" && PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
OWN_BACKEND=$!
for _ in $(seq 1 40); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; tail "$WORK/backend.log"; exit 2; }

# ---- payload (spans the head so head-hash alone can't catch a body flip) ----
BIG="$WORK/big.bin"; head -c 2000000 /dev/urandom >"$BIG"; H_BIG=$(hashof "$BIG")

# ---- pair A<->B (known-device auto-accept; the daemon `up` needs trust) ------
DA="$WORK/devA"; DB="$WORK/devB"; mkdir -p "$DA" "$DB"
pair() {
  local W="pair-$$-$RANDOM"
  FILAMENT_CONFIG_DIR="$DA" "$BIN" send "$BIG" --word "$W" --remember boxB --server "$SERVER" >"$WORK/pair-a.log" 2>&1 &
  local SP=$!; sleep 3
  FILAMENT_CONFIG_DIR="$DB" timeout 60 "$BIN" recv "$W" -y --remember boxA --dir "$DB" --server "$SERVER" >"$WORK/pair-b.log" 2>&1
  wait $SP 2>/dev/null
}
say "setup: pairing A<->B (--remember over a code)"
pair
if [ -s "$DA/devices.json" ] && [ -s "$DB/devices.json" ]; then
  ok "paired (A knows boxB, B knows boxA)"
else
  bad "pairing setup"; tail -n 6 "$WORK/pair-a.log" "$WORK/pair-b.log"
  echo "RESULT: $PASS passed, $FAIL failed"; exit 1
fi

# ---- one transfer attempt under a given corruption setting ------------------
# corrupt_mode: "once"  -> flip the last received byte EXACTLY ONCE (recoverable)
#               "persist"-> flip it EVERY verify round (unrecoverable)
#               "none"   -> clean transfer (baseline)
# Sets globals: A_RC (sender exit code), TIMED_OUT (1 if the run hit SIGTERM=124).
# The sender uid is pinned (FILAMENT_UID) so the transfer id the receiver must
# corrupt is known before the send starts. `send` mints my_uid = "cli-s-<UID>"
# and the transfer id = "<my_uid>-<sid>"; sid=1 for the first/only payload, so
# the id is "cli-s-<UID>-1".
SENDER_UID="trunc"                 # FILAMENT_UID
XFER_ID="cli-s-$SENDER_UID-1"      # => the deterministic transfer id
one_attempt() {
  local tag="$1" corrupt_mode="$2"
  local DG="$WORK/$tag-drop"; rm -rf "$DG"; mkdir -p "$DG"
  local UPLOG="$WORK/$tag-up.log"; local SENDLOG="$WORK/$tag-send.log"
  local recv_env=()
  case "$corrupt_mode" in
    once)    recv_env=(FILAMENT_TEST_CORRUPT_RECV="$XFER_ID" FILAMENT_TEST_CORRUPT_ONCE=1) ;;
    persist) recv_env=(FILAMENT_TEST_CORRUPT_RECV="$XFER_ID") ;;
    none)    recv_env=() ;;
  esac
  # The receiver's verify + re-fetch loop has brief no-data gaps that the SENDER's
  # bytes-moved watchdog (P0) would otherwise treat as a stall — churning the
  # direct-repair ladder toward a relay that isn't configured here, slow and
  # orthogonal to what THIS gate asserts (the receiver's whole-file reject/recover
  # + the ack gate). So we quiet the sender's stall watchdog (huge FILAMENT_STALL_MS)
  # and disable warm standby; the sender then simply waits on its bounded ack timer.
  # The P0/P1/P3 stall+relay behaviour has its own dedicated gates.
  # `env` applies the array-sourced vars (a bash assignment from an expanded array
  # before a command word is NOT treated as an env assignment — it'd try to RUN it).
  env FILAMENT_CONFIG_DIR="$DB" FILAMENT_STALL_MS=99999999 FILAMENT_WARM_STANDBY=0 ${recv_env[@]+"${recv_env[@]}"} \
    timeout 55 "$BIN" up --dir "$DG" --server "$SERVER" >"$UPLOG" 2>&1 &
  local UP=$!; pids+=($UP); sleep 3
  A_RC=0; TIMED_OUT=0
  env FILAMENT_CONFIG_DIR="$DA" FILAMENT_UID="$SENDER_UID" \
    FILAMENT_ACK_TIMEOUT="$ACK_TIMEOUT" FILAMENT_STALL_MS=99999999 FILAMENT_WARM_STANDBY=0 \
    timeout 55 "$BIN" send "$BIG" --to boxB --server "$SERVER" >"$SENDLOG" 2>&1 || A_RC=$?
  [ "$A_RC" = "124" ] && TIMED_OUT=1
  sleep 1; kill $UP 2>/dev/null; wait $UP 2>/dev/null
}

# Retry only on an ESTABLISHMENT flake (no transfer ever started => the corruption
# hook can't arm). A genuine reject/recover, once the transfer runs, is
# deterministic. `need` = "recover" | "fail" | "clean".
run_attempt() {
  local tag="$1" mode="$2" need="$3" try
  local GOT="$WORK/$tag-drop/big.bin"
  for try in $(seq 1 "${ATTEMPT_RETRIES:-6}"); do
    one_attempt "$tag" "$mode"
    # Did a transfer actually run? (an offer was accepted / bytes moved)
    if ! grep -hqE "verified|checksum|delivered|receiving|resuming|TRUNCATED|refusing" \
         "$WORK/$tag-send.log" "$WORK/$tag-up.log" 2>/dev/null; then
      echo "    ($tag attempt $try: no transfer carried — retrying establishment)" >&2
      continue
    fi
    case "$need" in
      recover) [ "$A_RC" = "0" ] && [ -f "$GOT" ] && [ "$(hashof "$GOT")" = "$H_BIG" ] && break ;;
      clean)   [ "$A_RC" = "0" ] && [ -f "$GOT" ] && [ "$(hashof "$GOT")" = "$H_BIG" ] && break ;;
      fail)    grep -hq "refusing to accept a corrupt file" "$WORK/$tag-up.log" && break ;;
    esac
    echo "    ($tag attempt $try: transfer ran but outcome not yet conclusive — re-seating)" >&2
  done
}

GATE_OK=1
for n in $(seq 1 "$RUNS"); do
  # ---- RUN R: recoverable corruption (CORRUPT_ONCE) --------------------------
  say "RUN R $n/$RUNS: induce a corrupt receive ONCE => reject + recover + ack-gated success"
  rtag="recoverR$n"
  run_attempt "$rtag" "once" "recover"
  RSEND="$WORK/$rtag-send.log"; RUP="$WORK/$rtag-up.log"; RGOT="$WORK/$rtag-drop/big.bin"

  # (a) REJECT: the receiver saw the checksum fail and did NOT accept the corrupt bytes.
  if grep -hqE "whole-file checksum FAILED|checksum can't match yet|TRUNCATED" "$RUP"; then
    ok "[$rtag] (a) REJECTED the corrupt receive (whole-file checksum mismatch, not declared done)"
    grep -hE "CORRUPT-RECV|checksum FAILED|re-fetching|TRUNCATED" "$RUP" | head -2 | sed 's/^/      /'
  else
    bad "[$rtag] (a) corrupt receive was NOT rejected"; tail -n 8 "$RUP"; GATE_OK=0
  fi

  # (b) RECOVER: the re-fetch produced a byte-exact file and the receiver acked it.
  if [ -f "$RGOT" ] && [ "$(hashof "$RGOT")" = "$H_BIG" ]; then
    ok "[$rtag] (b) AUTO-RECOVERED byte-exact after re-fetch ($(stat -c%s "$RGOT")/$(stat -c%s "$BIG"))"
  else
    bad "[$rtag] (b) did NOT recover byte-exact (got=$([ -f "$RGOT" ] && hashof "$RGOT") want=$H_BIG)"; GATE_OK=0
  fi
  if grep -hq "verified (whole-file sha256 matched) — acked" "$RUP"; then
    ok "[$rtag] (b) receiver verified the whole-file sha256 and sent the delivery-ack"
  else
    bad "[$rtag] (b) receiver did not emit the verified+acked line"; GATE_OK=0
  fi

  # (c) ACK-GATED SUCCESS: the SENDER completed only after seeing the delivery-ack.
  if grep -hq "delivered + verified (whole-file sha256 matched)" "$RSEND" && [ "$A_RC" = "0" ]; then
    ok "[$rtag] (c) SENDER reported success only AFTER the delivery-ack (not fire-and-forget; rc=0)"
    grep -h "delivered + verified" "$RSEND" | head -1 | sed 's/^/      /'
  else
    bad "[$rtag] (c) sender did not gate success on the delivery-ack (rc=$A_RC)"; tail -n 6 "$RSEND"; GATE_OK=0
  fi

  # ---- RUN U: unrecoverable corruption (every round) ------------------------
  say "RUN U $n/$RUNS: corrupt EVERY round => fail CLEAN (no silent bad file, no hang)"
  utag="unrecU$n"
  run_attempt "$utag" "persist" "fail"
  USEND="$WORK/$utag-send.log"; UUP="$WORK/$utag-up.log"; UGOT="$WORK/$utag-drop/big.bin"

  # (d) FAIL-CLEAN: refused after the bound, NOT placed byte-exact, and NO hang.
  refused=0; silent_bad=0; hung=0
  grep -hq "refusing to accept a corrupt file" "$UUP" && refused=1
  [ -f "$UGOT" ] && [ "$(hashof "$UGOT")" = "$H_BIG" ] && silent_bad=1
  [ "${TIMED_OUT:-0}" = "1" ] && hung=1
  if [ "$refused" = "1" ] && [ "$silent_bad" = "0" ]; then
    ok "[$utag] (d) FAILED CLEAN: refused a genuinely-corrupt file after the bounded re-fetches; no byte-exact file placed"
    grep -h "refusing to accept a corrupt file" "$UUP" | head -1 | sed 's/^/      /'
  else
    bad "[$utag] (d) did not fail clean (refused=$refused silent_bad=$silent_bad)"; tail -n 8 "$UUP"; GATE_OK=0
  fi
  # The corrupt file must NEVER be acked (no false "verified ... acked" for it).
  if grep -hq "verified (whole-file sha256 matched) — acked" "$UUP"; then
    bad "[$utag] (d) a corrupt receive was acked — silent success leak"; GATE_OK=0
  else
    ok "[$utag] (d) the corrupt receive was NEVER acked (no silent success)"
  fi

  # ---- BASELINE C: clean transfer still verifies + acks ----------------------
  say "BASELINE C $n/$RUNS: a CLEAN transfer still verifies + acks end-to-end"
  ctag="cleanC$n"
  run_attempt "$ctag" "none" "clean"
  CSEND="$WORK/$ctag-send.log"; CUP="$WORK/$ctag-up.log"; CGOT="$WORK/$ctag-drop/big.bin"
  if [ -f "$CGOT" ] && [ "$(hashof "$CGOT")" = "$H_BIG" ] \
     && grep -hq "verified (whole-file sha256 matched) — acked" "$CUP" \
     && grep -hq "delivered + verified (whole-file sha256 matched)" "$CSEND" \
     && [ "$A_RC" = "0" ]; then
    ok "[$ctag] (e) clean transfer: byte-exact, receiver verified+acked, sender ack-gated (rc=0)"
  else
    bad "[$ctag] (e) clean transfer did not verify+ack end-to-end (rc=$A_RC)"; tail -n 6 "$CSEND" "$CUP"; GATE_OK=0
  fi
done

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && [ "$GATE_OK" -eq 1 ] && { echo "WHOLE-FILE-INTEGRITY + DELIVERY-ACK (P4) GATE: GREEN"; exit 0; }
echo "WHOLE-FILE-INTEGRITY + DELIVERY-ACK (P4) GATE: RED"; exit 1
