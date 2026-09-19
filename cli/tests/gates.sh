#!/usr/bin/env bash
# Filament CLI — standing test gates (docs/cli-resilience.md Part 4).
#
# Every ledger item that claims VERIFIED is exercised here. Run against a
# local backend (default http://127.0.0.1:8077, started for you if absent
# when FILAMENT_TEST_AUTOSTART=1) or any FILAMENT_TEST_SERVER.
#
#   ./gates.sh              run gates 0-9 (no docker needed)
#   ./gates.sh --with-relay also run gate 10 (TURN relay via local coturn; docker)
#
# TWO TIERS (docs/cli-resilience.md Part 4):
#   SKIP_BROWSER=1 ./gates.sh --with-relay   the DETERMINISTIC CORE — every
#       gate here is deterministic BY CONSTRUCTION (CLI-only, seeded loss,
#       fixture-pinned). This is the commit/merge gate; it must be 100%.
#   ./gates.sh --with-relay                  core + the real-headless-browser
#       interop gates (5,6,12,13,16). Those exercise real Chromium + WebRTC
#       ICE/DTLS, timing-dependent BY NATURE; on a contended host they are
#       best-effort (run on a quiescent CI runner). The G-i glare under churn
#       is tracked as a product bug, not a test knob.
#
# Browser gates need playwright (npm i playwright in this dir; chromium is
# fetched on first run).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
# Correctness gates build DEBUG by default (~20s incremental) instead of the LTO
# release build (~4min) -- these gates verify BEHAVIOUR via the FILAMENT_TEST_*
# hooks, not throughput, so they don't need release codegen. Set
# FILAMENT_GATE_RELEASE=1 only when a gate is measuring MB/s.
if [ -n "${FILAMENT_GATE_RELEASE:-}" ]; then
  GATE_PROFILE_DIR=release; GATE_BUILD_FLAG=--release
else
  GATE_PROFILE_DIR=debug; GATE_BUILD_FLAG=
fi
# #249: this assumed cargo writes to cli/target, which is false on any machine
# that sets `target-dir` (this one shares /root/.cargo-target across worktrees,
# see ~/.cargo/config.toml). The build step below then SUCCEEDED while every gate
# tried to exec a path that does not exist: "1 passed, 31 failed", each failure
# reading `No such file or directory` rather than naming the cause. Ask cargo
# where it actually writes instead of assuming.
_target_dir() {
    ( cd "$CLI_DIR" && cargo metadata --format-version 1 --no-deps 2>/dev/null ) \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null \
      || echo "$CLI_DIR/target"
}
GATE_TARGET_DIR="${CARGO_TARGET_DIR:-$(_target_dir)}"
BIN="$GATE_TARGET_DIR/$GATE_PROFILE_DIR/filament"
SERVER="${FILAMENT_TEST_SERVER:-http://127.0.0.1:8077}"
WORK="${FILAMENT_TEST_WORK:-$(mktemp -d /tmp/filament-gates.XXXXXX)}"
WITH_RELAY=0
[ "${1:-}" = "--with-relay" ] && WITH_RELAY=1

# Hermetic: never let the operator's real config/devices leak into gates
# (a configured display name broke --to selection in gate 7 once).
export FILAMENT_CONFIG_DIR="$WORK/cfg"; mkdir -p "$WORK/cfg"
unset FILAMENT_NAME 2>/dev/null || true

PASS=0; FAIL=0; FAILED_GATES=""
say()  { printf '\n\033[1m== gate %s ==\033[0m\n' "$*"; }
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED_GATES="$FAILED_GATES $1"; }
hashof() { sha256sum "$1" | cut -d' ' -f1; }
# `kill -9 <pid>` on a `timeout`-wrapped background job kills only the wrapper.
# SIGKILL cannot be caught, so timeout never forwards it and the real process is
# ORPHANED. Measured: gate 11b's second receiver survived every run and was
# still resident hours later, twice. Send TERM first, which timeout DOES
# forward, give it a moment, then SIGKILL the wrapper and any surviving child.
kill_tree() {
  local pid
  for pid in "$@"; do
    [ -n "$pid" ] || continue
    kill -TERM "$pid" 2>/dev/null
  done
  sleep 0.5
  for pid in "$@"; do
    [ -n "$pid" ] || continue
    pkill -9 -P "$pid" 2>/dev/null
    kill -9 "$pid" 2>/dev/null
  done
}

wait_for_exit() {
  local pid="$1" seconds="$2" i
  for i in $(seq 1 $((seconds * 2))); do
    kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null; return; }
    sleep 0.5
  done
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 124
}
# L1-a: a `send --word <phrase>` now mints its OWN numeric nameplate (the phrase
# is only the SPAKE2 password), so the receiver must claim the FULL minted code,
# not the spoken phrase. CODE_WORD is a valid 2-word phrase (clears the >=2-word
# strength floor). wait_code <send.log> [phrase] echoes the minted `phrase-NNNN`
# code once the sender prints it (the same shape gate9 greps).
CODE_WORD="gigantic-element"
wait_code() {
  local log="$1" word="${2:-$CODE_WORD}" code="" i
  for i in $(seq 1 60); do
    code=$(grep -oiE "$word-[0-9]{3,5}" "$log" | head -1)
    [ -n "$code" ] && { echo "$code"; return 0; }
    sleep 0.3
  done
  return 1
}
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; [ -n "${OWN_BACKEND:-}" ] && kill "$OWN_BACKEND" 2>/dev/null; }
trap cleanup EXIT

# Determinism: the suite owns its OWN fixture backend with the claim
# rate-limit pinned sky-high (FIL_CLAIM_LIMIT) — the prod 5/min limit is a
# security control, but in a test it turns the suite's many rapid claims into
# a timing-window lottery ('slow-down' flakes). Pinning it makes the claim
# path deterministic. (Set FILAMENT_TEST_SERVER to point at an external
# server and skip the autostart — but then you own the claim limit.)
# #249: this used to default to a hardcoded venv inside a job directory
# (/root/.claude/jobs/330c2366/...) that no longer exists. The autostart below is
# gated on `-x "$PYV0"`, so a missing interpreter SKIPPED the backend silently
# and the run died two lines later on "no backend at ...", which reads as an
# environment problem rather than a stale path in this script. That is a large
# part of why the deterministic core has not been runnable, let alone wired into
# CI. Prefer the override, then a venv if one is present, then whatever python3
# is on PATH; the backend's deps are ordinary (flask, flask-socketio, eventlet).
_pick_python() {
    if [ -n "${FILAMENT_TEST_VENV:-}" ]; then echo "$FILAMENT_TEST_VENV"; return; fi
    for c in "$CLI_DIR/../backend/.venv/bin/python" "$CLI_DIR/../.venv/bin/python"; do
        [ -x "$c" ] && { echo "$c"; return; }
    done
    command -v python3 2>/dev/null || echo python3
}
PYV0="$(_pick_python)"
OWN_BACKEND=""
if [ -z "${FILAMENT_TEST_SERVER:-}" ] && [ -x "$PYV0" ]; then
  for pid in $(ss -tlnp 2>/dev/null | grep ":8077 " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
  sleep 1
  # FIL_PING_TIMEOUT high: a CPU-starved headless browser stays connected
  # instead of dropping → reconnecting → triggering the stale-answer glare.
  ( cd "$CLI_DIR/../backend" && PORT=8077 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 FIL_CLAIM_LIMIT=1000000 \
      FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 "$PYV0" app.py >"$WORK/fixture-backend.log" 2>&1 ) &
  OWN_BACKEND=$!
  for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
fi
curl -fsS "$SERVER/api/health" >/dev/null || {
  echo "no backend at $SERVER"
  echo "  interpreter tried: $PYV0"
  [ -n "$OWN_BACKEND" ] && { echo "  it was started; its log:"; sed 's/^/    /' "$WORK/fixture-backend.log" 2>/dev/null | tail -8; } \
                        || echo "  autostart was SKIPPED: that interpreter is not executable"
  exit 2
}
# These gates drive env-gated test hooks (FILAMENT_TEST_*), which now ship ONLY
# in a `--features test-hooks` build (stripped from default/release).
( cd "$CLI_DIR" && cargo build $GATE_BUILD_FLAG --features test-hooks -q ) || { echo "build failed"; exit 2; }
# Assert the binary the gates will EXEC exists, rather than discovering it 31
# failures later. A build that succeeded says nothing about where this script
# then looks.
[ -x "$BIN" ] || {
  echo "built, but no executable at the path the gates use:"
  echo "  BIN=$BIN"
  echo "  target dir resolved to: $GATE_TARGET_DIR"
  exit 2
}
echo "gates: using $BIN"

# The browser gates load frontend/dist via the LOCAL backend, so the bundle
# must be SAME-ORIGIN. `npm run build` bakes frontend/.env.production
# (the Cloudflare prod API base) — a dist built that way signals via PROD
# while the gate CLI sits on 127.0.0.1, and every Playwright gate times out
# (cost: a full suite of red herrings, 2026-06-07). Rebuild with the
# override if the poison marker is present.
FRONT="$CLI_DIR/../frontend"
if grep -qs "api\.filament\.autumated\.com" "$FRONT"/dist/assets/*.js 2>/dev/null; then
  echo "dist is prod-pointing — rebuilding same-origin for gates…"
  ( cd "$FRONT" && VITE_FILAMENT_API= npm run build >/dev/null 2>&1 ) || { echo "frontend rebuild failed"; exit 2; }
fi

# payloads
SMALL="$WORK/small.bin"; BIG="$WORK/big.bin"
head -c $((5 * 1024 * 1024))  /dev/urandom > "$SMALL"
head -c $((80 * 1024 * 1024)) /dev/urandom > "$BIG"
H_SMALL=$(hashof "$SMALL"); H_BIG=$(hashof "$BIG")

# ---------------------------------------------------------------- gate 0 ----
say "0: unit tests"
if ( cd "$CLI_DIR" && cargo test -q ) >"$WORK/g0.log" 2>&1; then ok "unit tests"; else bad "unit tests"; tail -n 5 "$WORK/g0.log"; fi
PYV="$PYV0"
if [ -x "$PYV" ]; then
  if ( cd "$CLI_DIR/.." && "$PYV" -m unittest backend.tests.test_pair_codes ) >"$WORK/g0b.log" 2>&1; then
    ok "pair-code variance/security tests"
  else bad "pair-code tests"; tail -n 5 "$WORK/g0b.log"; fi
fi

# ---------------------------------------------------------------- gate 1 ----
say "1: one-time code transfer + code burn"
D="$WORK/g1"; mkdir -p "$D"
"$BIN" send "$SMALL" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g1-send.log" 2>&1 &
SP=$!; pids+=($SP)
W=$(wait_code "$WORK/g1-send.log") || { bad "code transfer (no code minted)"; tail -n 3 "$WORK/g1-send.log"; }
if [ -n "${W:-}" ] && timeout 90 "$BIN" receive "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g1-recv.log" 2>&1 \
   && wait $SP && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ]; then
  ok "code transfer, hashes match, clean exits"
else bad "code transfer"; tail -n 3 "$WORK/g1-send.log" "$WORK/g1-recv.log"; fi
# C2: same-machine peers must BOTH report local (is_own_addr handles the
# multi-homed case), and nothing may misreport relayed.
if [ "$(grep -hc 'route: local' "$WORK/g1-send.log" "$WORK/g1-recv.log" | paste -sd+ | bc)" -ge 2 ] \
   && ! grep -hq "route: relayed" "$WORK/g1-send.log" "$WORK/g1-recv.log"; then
  ok "route detection: local on both ends, no false relayed"
else bad "route detection"; grep -h "route:" "$WORK/g1-send.log" "$WORK/g1-recv.log"; fi
if timeout 30 "$BIN" receive "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g1-burn.log" 2>&1; then
  bad "code burn (second claim was accepted!)"
else
  grep -q "code rejected" "$WORK/g1-burn.log" && ok "code burns on first use" || { bad "code burn (wrong error)"; tail -n 2 "$WORK/g1-burn.log"; }
fi

# ---------------------------------------------------------------- gate 2 ----
say "2: chaos — receiver killed mid-transfer, replacement resumes (C4/C6/C7)"
D="$WORK/g2"; mkdir -p "$D"
"$BIN" send "$BIG" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g2-send.log" 2>&1 &
SP=$!; pids+=($SP)
W=$(wait_code "$WORK/g2-send.log") || { bad "kill-resume (no code minted)"; tail -n 3 "$WORK/g2-send.log"; }
"$BIN" receive "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g2-recv1.log" 2>&1 &
R1=$!; pids+=($R1)
for _ in $(seq 1 60); do
  sz=$(stat -c %s "$D/big.bin.part" 2>/dev/null || echo 0)
  [ "$sz" -gt $((10 * 1024 * 1024)) ] && break
  sleep 0.5
done
# NOT kill_tree: this receiver is started WITHOUT a timeout wrapper, so $R1 is
# the real process and SIGKILL reaches it. kill_tree sends SIGTERM first, which
# `filament receive` handles gracefully and uses to clean up its partial file,
# leaving nothing for the resume half of this gate to resume from. The gate
# needs an abrupt death, which is the whole premise of "receiver killed
# mid-transfer". Regression from #287, whose commit message claimed it touched
# only timeout-wrapped sites; this one is not, and I did not check before
# changing it.
kill -9 $R1 2>/dev/null; wait $R1 2>/dev/null
# This used to render a missing .part as a bare `?` inside a success-path echo,
# and it fired for five consecutive runs while reading as cosmetic. If there is
# no partial file at the instant we have just killed a receiver mid-transfer,
# the gate's PREMISE has already failed and everything after it measures
# nothing. Fail here, loudly, instead of resuming from a file that is not there.
G2SZ=$(stat -c %s "$D/big.bin.part" 2>/dev/null || echo 0)
echo "(killed receiver at ${G2SZ} bytes)"
if [ "$G2SZ" -eq 0 ]; then
  bad "kill-resume: no partial file to resume from (receiver wrote nothing, or cleaned up on exit)"
  tail -n 3 "$WORK/g2-recv1.log" 2>/dev/null
fi
sleep 2
# The "resuming at" line is a DEBUG (resilience-internal) message, so the
# replacement receiver runs with -v to surface it for the assertion below. The
# resume itself is verbosity-independent (the sender re-offers from the saved
# offset); -v only makes the proof visible.
timeout 180 "$BIN" -v receive -y --dir "$D" --server "$SERVER" >"$WORK/g2-recv2.log" 2>&1
RC2=$?
wait $SP; RCS=$?
if [ $RC2 -eq 0 ] && [ $RCS -eq 0 ] && [ "$(hashof "$D/big.bin")" = "$H_BIG" ] \
   && grep -q "resuming at" "$WORK/g2-recv2.log"; then
  ok "kill-resume: replacement receiver resumed, hash matches"
else bad "kill-resume"; tail -n 4 "$WORK/g2-send.log" "$WORK/g2-recv2.log"; fi

# ---------------------------------------------------------------- gate 3 ----
say "3: corruption guard — same name+size, different content restarts (C7)"
D="$WORK/g3"; mkdir -p "$D"
head -c $((2 * 1024 * 1024)) /dev/zero > "$D/small.bin.part"
printf '{"size":%s,"head":"00deadbeef"}' "$(stat -c %s "$SMALL")" > "$D/small.bin.part.meta"
"$BIN" send "$SMALL" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g3-send.log" 2>&1 &
SP=$!; pids+=($SP)
W=$(wait_code "$WORK/g3-send.log") || { bad "corruption guard (no code minted)"; tail -n 3 "$WORK/g3-send.log"; }
# "different content" is a DEBUG (resilience-internal) line, so -v surfaces it.
if [ -n "${W:-}" ] && timeout 90 "$BIN" -v receive "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g3-recv.log" 2>&1 \
   && wait $SP && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ] \
   && grep -q "different content" "$WORK/g3-recv.log"; then
  ok "head mismatch detected, restarted from 0, hash matches"
else bad "corruption guard"; tail -n 3 "$WORK/g3-recv.log"; fi

# ---------------------------------------------------------------- gate 4 ----
say "4: directory tar + stdin pipe"
D="$WORK/g4"; mkdir -p "$D" "$WORK/srcdir/sub"
echo "hello" > "$WORK/srcdir/a.txt"; head -c 1048576 /dev/urandom > "$WORK/srcdir/sub/b.bin"
R4="g4room$$"
"$BIN" receive -y --dir "$D" --room "$R4" --server "$SERVER" >"$WORK/g4-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 3
G4=0
timeout 60 "$BIN" send "$WORK/srcdir" --room "$R4" --server "$SERVER" >"$WORK/g4-send.log" 2>&1 || G4=1
wait_for_exit $R 30 || G4=1
tar tf "$D/srcdir.tar" >/dev/null 2>&1 || G4=1
"$BIN" receive -y --dir "$D" --room "$R4" --server "$SERVER" >"$WORK/g4b-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 3
echo "pipe payload" | timeout 60 "$BIN" send - --name note.txt --room "$R4" --server "$SERVER" >"$WORK/g4b-send.log" 2>&1 || G4=1
wait_for_exit $R 30
[ "$(cat "$D/note.txt" 2>/dev/null)" = "pipe payload" ] || G4=1
[ $G4 -eq 0 ] && ok "dir tar + stdin round-trip" || bad "dir/stdin"

# ---------------------------------------------------------------- gate 5 ----
say "5: CLI -> browser (playwright)"
if [ -z "${SKIP_BROWSER:-}" ] && [ -d "$HERE/node_modules/playwright" ]; then
  RM5="g5room$$"
  ( cd "$HERE" && node browser-receiver.js "$SERVER/rooms/$RM5" >"$WORK/g5-pw.log" 2>&1 ) &
  PW=$!; pids+=($PW); sleep 6
  G5=0
  timeout 120 "$BIN" send "$SMALL" --room "$RM5" --server "$SERVER" >"$WORK/g5-send.log" 2>&1 || G5=1
  wait $PW || G5=1
  if [ $G5 -eq 0 ] && grep -q "RECEIVE COMPLETE" "$WORK/g5-pw.log"; then
    ok "browser received from CLI"
  else bad "CLI->browser"; tail -n 3 "$WORK/g5-pw.log" "$WORK/g5-send.log"; fi
else
  echo "SKIP (run: cd $HERE && npm i playwright && npx playwright install chromium)"
fi

# ---------------------------------------------------------------- gate 6 ----
say "6: browser -> CLI, two human-paced sends (C1 + C9, playwright)"
if [ -z "${SKIP_BROWSER:-}" ] && [ -d "$HERE/node_modules/playwright" ]; then
  D="$WORK/g6"; mkdir -p "$D"
  FA="$WORK/g6-a.bin"; FB="$WORK/g6-b.bin"
  head -c $((4 * 1024 * 1024)) /dev/urandom > "$FA"
  head -c $((1024 * 1024)) /dev/urandom > "$FB"
  RM6="g6room$$"
  timeout 240 "$BIN" receive -y --dir "$D" --room "$RM6" --server "$SERVER" >"$WORK/g6-recv.log" 2>&1 &
  R=$!; pids+=($R); sleep 2
  G6=0
  ( cd "$HERE" && timeout 200 node browser-sender.js "$SERVER/rooms/$RM6" "$FA" "$FB" >"$WORK/g6-pw.log" 2>&1 ) || G6=1
  wait $R || G6=1
  if [ $G6 -eq 0 ] && [ "$(hashof "$D/g6-a.bin")" = "$(hashof "$FA")" ] \
     && [ "$(hashof "$D/g6-b.bin")" = "$(hashof "$FB")" ] \
     && grep -q "done (2 files)" "$WORK/g6-recv.log"; then
    ok "CLI received both browser sends; stayed alive between them"
  else bad "browser->CLI"; tail -n 4 "$WORK/g6-pw.log" "$WORK/g6-recv.log"; fi
else
  echo "SKIP (playwright not installed)"
fi

# ---------------------------------------------------------------- gate 7 ----
say "7: --to peer selection (C13)"
DA="$WORK/g7-alice"; DB="$WORK/g7-bob"; mkdir -p "$DA" "$DB"
USER=alice "$BIN" receive -y --to charlie --dir "$DA" --server "$SERVER" >"$WORK/g7-alice.log" 2>&1 &
RA=$!; pids+=($RA)
USER=bob timeout 120 "$BIN" receive -y --dir "$DB" --server "$SERVER" >"$WORK/g7-bob.log" 2>&1 &
RB=$!; pids+=($RB); sleep 3
G7=0
timeout 60 "$BIN" send "$SMALL" --to bob --server "$SERVER" >"$WORK/g7-send.log" 2>&1 || G7=1
sleep 2; kill $RA 2>/dev/null; wait $RB 2>/dev/null
if [ $G7 -eq 0 ] && [ "$(hashof "$DB/small.bin" 2>/dev/null)" = "$H_SMALL" ] && [ ! -e "$DA/small.bin" ]; then
  ok "--to bob delivered to bob only"
else bad "--to selection"; tail -n 3 "$WORK/g7-send.log"; fi

# ---------------------------------------------------------------- gate 8 ----
say "8: consent — no tty, no -y declines (C14)"
D="$WORK/g8"; mkdir -p "$D"
R8="g8room$$"
"$BIN" receive --dir "$D" --room "$R8" --server "$SERVER" </dev/null >"$WORK/g8-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 3
G8=0
timeout 60 "$BIN" send "$SMALL" --room "$R8" --server "$SERVER" >"$WORK/g8-send.log" 2>&1; G8=$?
kill $R 2>/dev/null
# #274: a send whose every file was declined now exits NONZERO and suppresses
# the completion line. This gate used to require exit 0 while printing
# "declined", which is precisely the contract #274 called a bug: a script could
# not tell a delivered transfer from a refused one. Asserting 1 specifically,
# not merely nonzero, so a `timeout` kill (124) cannot satisfy this gate.
if [ $G8 -eq 1 ] && grep -q "declined" "$WORK/g8-send.log" \
   && grep -q "no files delivered" "$WORK/g8-send.log" && [ ! -e "$D/small.bin" ]; then
  ok "offer declined without consent; sender reported the decline and exited 1"
else bad "consent decline"; tail -n 3 "$WORK/g8-send.log" "$WORK/g8-recv.log"; fi

# ---------------------------------------------------------------- gate 9 ----
say "9: bulk transfer completes (C8a backpressure regression guard)"
# An absolute MB/s floor IS non-determinism — it encodes machine/load speed.
# The deterministic property is: 80 MB transfers correctly within a CEILING
# generous enough that only a genuine hang/backpressure-break trips it (240s
# = ~0.33 MB/s; a working transfer beats that by 20-50x even under heavy
# load). Speed is logged, never asserted.
D="$WORK/g9"; mkdir -p "$D"
R9="g9room$$"
"$BIN" receive -y --dir "$D" --room "$R9" --server "$SERVER" >"$WORK/g9-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 3
T0=$(date +%s.%N)
timeout 240 "$BIN" send "$BIG" --room "$R9" --server "$SERVER" >"$WORK/g9-send.log" 2>&1
RC=$?
T1=$(date +%s.%N)
wait_for_exit $R 30
RATE=$(python3 -c "print(f'{80/max(($T1-$T0)-4.5,0.1):.1f}')")
echo "(~${RATE} MB/s effective — informational, not asserted)"
if [ $RC -eq 0 ] && [ "$(hashof "$D/big.bin")" = "$H_BIG" ]; then
  ok "80 MB transferred + hash match within ceiling (${RATE} MB/s)"
else bad "bulk transfer (rc=$RC, ${RATE} MB/s — a hang/backpressure break, not slowness)"; fi

# --------------------------------------------------------------- gate 10 ----
kill_port() { # fixture backends (werkzeug reloader forks; kill by port)
  for pid in $(ss -tlnp 2>/dev/null | grep ":$1 " | grep -oP 'pid=\K[0-9]+' | sort -u); do
    kill "$pid" 2>/dev/null
  done
}
kill_8078() { kill_port 8078; }
VENV_PY="$PYV0"

# --------------------------------------------------------------- gate 12 ----
# C1 against PRODUCTION's config: a backend serving chunkSize 65536 makes the
# browser frame 64 KiB + 4 = 65540-byte messages. The CLI must advertise
# a=max-message-size and read with a >64K buffer (detached channel) or the
# first chunk kills the channel. This is the live-prod scenario, no deploy
# of the backend required.
say "12: browser with 64 KiB prod framing -> CLI (C1)"
if [ -z "${SKIP_BROWSER:-}" ] && [ -d "$HERE/node_modules/playwright" ] && [ -x "$VENV_PY" ]; then
  kill_port 8079; sleep 1
  ( cd "$CLI_DIR/../backend" && PORT=8079 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 FIL_CHUNK_SIZE=65536 FIL_CLAIM_LIMIT=1000000 \
      FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 "$VENV_PY" app.py >"$WORK/g12-backend.log" 2>&1 ) &
  BK12=$!; pids+=($BK12); sleep 4
  D="$WORK/g12"; mkdir -p "$D"
  FA="$WORK/g12-a.bin"; FB="$WORK/g12-b.bin"
  head -c $((4 * 1024 * 1024)) /dev/urandom > "$FA"; head -c $((1024 * 1024)) /dev/urandom > "$FB"
  RM="g12room$$"
  timeout 240 "$BIN" receive -y --dir "$D" --room "$RM" --server http://127.0.0.1:8079 >"$WORK/g12-recv.log" 2>&1 &
  R=$!; pids+=($R); sleep 2
  G12=0
  ( cd "$HERE" && timeout 200 node browser-sender.js "http://127.0.0.1:8079/rooms/$RM" "$FA" "$FB" >"$WORK/g12-pw.log" 2>&1 ) || G12=1
  wait $R || G12=1
  kill $BK12 2>/dev/null; kill_port 8079
  if [ $G12 -eq 0 ] && [ "$(hashof "$D/g12-a.bin")" = "$(hashof "$FA")" ] \
     && [ "$(hashof "$D/g12-b.bin")" = "$(hashof "$FB")" ]; then
    ok "CLI received 65540-byte browser frames (prod config, no backend deploy)"
  else bad "prod-framing browser->CLI"; tail -n 3 "$WORK/g12-pw.log" "$WORK/g12-recv.log"; fi
else
  echo "SKIP (needs playwright + backend venv)"
fi

if [ $WITH_RELAY -eq 1 ] && [ -x "$PYV0" ] && command -v docker >/dev/null 2>&1; then
  say "10: TURN relay path + route detection (C2/C17, docker coturn)"
  kill_8078; sleep 1
  TS=testsecret$RANDOM
  # --allow-loopback-peers: coturn 403s loopback peer addresses by default,
  # and in this hermetic setup BOTH peers are 127.0.0.1. Test-only flag.
  CT=$(docker run -d --rm --network host coturn/coturn -n \
        --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 --listening-port=3478 \
        --static-auth-secret="$TS" --realm=filament.test --no-tls --no-dtls \
        --allow-loopback-peers --cli-password=x 2>/dev/null)
  VENV_PY="$PYV0"
  ( cd "$CLI_DIR/../backend" && PORT=8078 FIL_TURN_HOST="turn:127.0.0.1:3478" FIL_TURN_SECRET="$TS" \
      "$VENV_PY" app.py >"$WORK/g10-backend.log" 2>&1 ) &
  BK=$!; pids+=($BK); sleep 4
  D="$WORK/g10"; mkdir -p "$D"
  "$BIN" send "$SMALL" --word "$CODE_WORD" --relay --server http://127.0.0.1:8078 >"$WORK/g10-send.log" 2>&1 &
  SP=$!; pids+=($SP)
  W=$(wait_code "$WORK/g10-send.log") || { bad "relay (no code minted)"; tail -n 3 "$WORK/g10-send.log"; }
  G10=0
  timeout 120 "$BIN" receive "$W" -y --relay --dir "$D" --server http://127.0.0.1:8078 >"$WORK/g10-recv.log" 2>&1 || G10=1
  wait $SP || G10=1
  kill $BK 2>/dev/null; kill_8078; docker stop "$CT" >/dev/null 2>&1
  # relay-only ICE policy guarantees the path; the route line is reporting.
  # Require it on at least one end (a very fast transfer can exit before the
  # sender's detector fires).
  if [ $G10 -eq 0 ] && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ] \
     && grep -hq "route: relayed" "$WORK/g10-send.log" "$WORK/g10-recv.log"; then
    ok "relayed transfer via coturn; route: relayed reported"
  else bad "relay"; tail -n 3 "$WORK/g10-send.log" "$WORK/g10-recv.log"; fi
elif [ $WITH_RELAY -eq 1 ]; then
  # Was a FAILURE, not a skip. The gate launched its backend with a hardcoded
  # interpreter path from a job directory that no longer exists, so it reported
  # "relay (no code minted)" and "relay" when the truth was that no python ever
  # ran. Gate 12 guarded on -x and skipped cleanly; this one did not, and three
  # of the fourteen failures in the first complete run were that one missing
  # file. A gate that cannot run must say so, not invent a product failure.
  say "10: TURN relay path + route detection (C2/C17, docker coturn)"
  echo "SKIP (needs a usable python and docker; set FILAMENT_TEST_VENV to point at one)"
fi

# --------------------------------------------------------------- gate 11 ----
say "11: same-uid rejoin supersede (C6) — frozen receiver replaced by same device"
D="$WORK/g11"; mkdir -p "$D"
# #28: the same-uid supersede now only fires for an IDLE link — an actively
# flowing one is preserved (a live signaling reconnect must not tear down a
# transfer). A frozen receiver goes idle, so it still supersedes; we pin the
# idle threshold low and sleep past it after the freeze to keep that
# deterministic regardless of how fast the replacement joins.
# -v on the sender: "superseding old link" is a DEBUG (resilience-internal) line.
FILAMENT_ADOPT_ACTIVE_MS=500 "$BIN" -v send "$BIG" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g11-send.log" 2>&1 &
SP=$!; pids+=($SP)
W=$(wait_code "$WORK/g11-send.log") || { bad "uid supersede (no code minted)"; tail -n 3 "$WORK/g11-send.log"; }
FILAMENT_UID="samedevice$$" "$BIN" receive "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g11-recv1.log" 2>&1 &
R1=$!; pids+=($R1)
for _ in $(seq 1 60); do
  sz=$(stat -c %s "$D/big.bin.part" 2>/dev/null || echo 0)
  [ "$sz" -gt $((10 * 1024 * 1024)) ] && break
  sleep 0.5
done
# Freeze (don't kill): the server lease stays alive, so when the replacement
# with the SAME uid joins, the sender must take the supersede path, not the
# peer-left path.
kill -STOP $R1 2>/dev/null
sleep 3   # > FILAMENT_ADOPT_ACTIVE_MS so the frozen link reads as idle (#28)
# -v on the replacement: "resuming at" is a DEBUG (resilience-internal) line.
FILAMENT_UID="samedevice$$" timeout 180 "$BIN" -v receive -y --dir "$D" --server "$SERVER" >"$WORK/g11-recv2.log" 2>&1
RC2=$?
# bounded wait: a hung sender must fail the gate, not the whole suite
RCS=99
for _ in $(seq 1 60); do kill -0 $SP 2>/dev/null || { wait $SP; RCS=$?; break; }; sleep 1; done
kill -9 $SP 2>/dev/null
kill -9 $R1 2>/dev/null
if [ $RC2 -eq 0 ] && [ $RCS -eq 0 ] && [ "$(hashof "$D/big.bin")" = "$H_BIG" ] \
   && grep -q "superseding old link" "$WORK/g11-send.log" \
   && grep -q "resuming at" "$WORK/g11-recv2.log"; then
  ok "same-uid supersede: sender swapped links, transfer resumed, hash matches"
else bad "uid supersede"; tail -n 4 "$WORK/g11-send.log" "$WORK/g11-recv2.log"; fi

# -------------------------------------------------------------- gate 11b ----
# The inverse of gate 11 (#28): when the same device reconnects its signaling
# socket (same uid, new sid) WHILE the original link is actively transferring,
# the sender must KEEP the flowing link — the data channel is independent of
# the socket. Pre-fix, the unconditional C6 supersede tore down the live
# transfer (issue #28). Same R2 wiring as gate 11, so if R2 ever failed to
# reach the sender, gate 11 would fail first — keeping this 'no supersede'
# assertion honest. Default idle threshold (3s) >> a healthy inter-frame gap.
say "11b: active same-uid link survives a live reconnect (#28)"
D1B="$WORK/g11b1"; D2B="$WORK/g11b2"; mkdir -p "$D1B" "$D2B"
# -v on the sender: "keeping active link" is a DEBUG (resilience-internal) line.
# The gate needs the transfer STILL FLOWING when R2 rejoins. Without a stall it
# raced the machine: 80 MB at the ~96 MB/s gate 9 measures is under a second, and
# the 8 MB threshold below is crossed in ~0.08s, inside the first poll. On a fast
# runner the transfer finished before the reconnect, "keeping active link" never
# printed, and the gate failed BECAUSE the machine was quick. Same problem, and
# the same remedy, as FILAMENT_TEST_PAIR_STALL in gate 17b.
#
# 3ms is chosen, not guessed: 80 MB in ~60 KiB chunks is ~1365 chunks, so 3ms
# each adds ~4.1s and the transfer lasts ~4.9s. R2 is spawned within ~0.6s (a
# 0.5s poll plus process start), so the reconnect lands mid-flight with about 8x
# margin, and the suite pays four seconds. 25ms would have added 34s.
FILAMENT_TEST_TRANSFER_STALL_MS=${FILAMENT_TEST_TRANSFER_STALL_MS:-3} \
  "$BIN" -v send "$BIG" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g11b-send.log" 2>&1 &
SP=$!; pids+=($SP)
W2=$(wait_code "$WORK/g11b-send.log") || { bad "flow-preserve (no code minted)"; tail -n 3 "$WORK/g11b-send.log"; }
FILAMENT_UID="livedev$$" "$BIN" receive "$W2" -y --dir "$D1B" --server "$SERVER" >"$WORK/g11b-recv1.log" 2>&1 &
R1=$!; pids+=($R1)
for _ in $(seq 1 60); do
  sz=$(stat -c %s "$D1B/big.bin.part" 2>/dev/null || echo 0)
  [ "$sz" -gt $((8 * 1024 * 1024)) ] && break
  sleep 0.5
done
# Same device rejoins (same uid, new sid) while R1 keeps flowing — must NOT
# supersede. R1 is left running; R2 is a never-adopted bystander we reap.
FILAMENT_UID="livedev$$" timeout 120 "$BIN" receive -y --dir "$D2B" --server "$SERVER" >"$WORK/g11b-recv2.log" 2>&1 &
R2B=$!; pids+=($R2B)
RCS=99
for _ in $(seq 1 120); do kill -0 $SP 2>/dev/null || { wait $SP; RCS=$?; break; }; sleep 1; done
# MIXED PAIR, deliberately. $R1 is unwrapped and $R2B is timeout-wrapped, so
# only the second needs kill_tree's TERM-first forwarding. SIGTERM on $R1 is
# safe HERE because this is teardown after the assertion loop has already waited
# out $SP: R1 is deliberately left running as the surviving link and R2 is a
# never-adopted bystander, so neither death is load-bearing. That is the fact
# that makes it safe, and it was unwritten until now. Contrast gate 2, where an
# abrupt kill IS the premise and TERM-first broke it.
kill_tree $R1 $R2B
# True positive: assert the sender SAW the reconnect and DELIBERATELY kept the
# link ("keeping active link") — not merely the absence of a supersede line,
# which a never-arriving R2 would also produce.
if [ $RCS -eq 0 ] && [ "$(hashof "$D1B/big.bin")" = "$H_BIG" ] \
   && grep -q "keeping active link" "$WORK/g11b-send.log" \
   && ! grep -q "superseding old link" "$WORK/g11b-send.log"; then
  ok "active link preserved across same-uid reconnect (kept deliberately, no supersede)"
else bad "flow-preserve (#28)"; tail -n 4 "$WORK/g11b-send.log" "$WORK/g11b-recv1.log"; fi

# -------------------------------------------------------------- gate 11c ----
# #28 second half (the socket-reconnect TRIGGER): when the server fires a
# peer-left for the ACTIVE link's old sid while its data channel is still
# alive (a signaling reconnect mid-transfer), the sender must NOT drop the
# link — it DEFERS the drop and the transfer completes on the same live
# channel. 11b covered the same-uid SUPERSEDE path (a new sid arrives); this
# covers the peer-left path, which used to drop unconditionally and kill the
# transfer. FILAMENT_TEST_INJECT_PEER_LEFT deterministically injects the
# synthetic peer-left for the active sid at a byte offset WITHOUT touching the
# data channel (a SIGSTOP/kill can't isolate the socket from the channel).
# A/B BY CONSTRUCTION: the same hook with FILAMENT_TEST_NO_DEFER reverts to the
# old unconditional drop and MUST fail to complete — so a regression that
# silently stops deferring is caught, not papered over. Pin the idle threshold
# default (3s) >> a healthy inter-frame gap so the live channel reads flowing.
say "11c: active link survives a peer-left on a still-flowing channel (#28 trigger)"
DC="$WORK/g11c"; mkdir -p "$DC"
INJC=$((8 * 1024 * 1024))
# Default idle threshold (3s) >> a healthy inter-frame gap, so the live channel
# reads flowing when the synthetic peer-left lands and the defer engages. (Don't
# pin it HIGH here: a high threshold keeps the sender's reaped-link alive ~30s
# after `done.`, which holds the receiver's socket open past its own clean exit
# and trips the recv timeout — measured 3/3 red. The reap never fires
# mid-transfer at the 3s default anyway: the channel stays busy throughout.)
# A) baseline: defer disabled — the injected peer-left drops the live link and
#    the transfer cannot complete on it.
DCA="$WORK/g11ca"; mkdir -p "$DCA"
# -v on the sender: "injecting synthetic peer-left" / "deferring drop" are DEBUG.
FILAMENT_TEST_INJECT_PEER_LEFT=$INJC FILAMENT_TEST_NO_DEFER=1 \
  "$BIN" -v send "$BIG" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g11ca-send.log" 2>&1 &
SPA=$!; pids+=($SPA)
WCA=$(wait_code "$WORK/g11ca-send.log") || { bad "deferred-drop (no code minted)"; tail -n 3 "$WORK/g11ca-send.log"; }
timeout 90 "$BIN" receive "$WCA" -y --dir "$DCA" --server "$SERVER" >"$WORK/g11ca-recv.log" 2>&1
RCA=$?
RCSA=99; for _ in $(seq 1 60); do kill -0 $SPA 2>/dev/null || { wait $SPA; RCSA=$?; break; }; sleep 1; done
kill -9 $SPA 2>/dev/null
HCA="x"; [ -f "$DCA/big.bin" ] && HCA=$(hashof "$DCA/big.bin")
base_ok=0; { [ $RCA -ne 0 ] || [ $RCSA -ne 0 ] || [ "$HCA" != "$H_BIG" ]; } \
  && grep -q "injecting synthetic peer-left" "$WORK/g11ca-send.log" && base_ok=1
# B) fix: defer active — the link is kept, transfer completes on it, no supersede.
FILAMENT_TEST_INJECT_PEER_LEFT=$INJC \
  "$BIN" -v send "$BIG" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g11c-send.log" 2>&1 &
SPB=$!; pids+=($SPB)
WC=$(wait_code "$WORK/g11c-send.log") || { bad "deferred-drop (no code minted)"; tail -n 3 "$WORK/g11c-send.log"; }
timeout 120 "$BIN" receive "$WC" -y --dir "$DC" --server "$SERVER" >"$WORK/g11c-recv.log" 2>&1
RCB=$?
RCSB=99; for _ in $(seq 1 150); do kill -0 $SPB 2>/dev/null || { wait $SPB; RCSB=$?; break; }; sleep 1; done
kill -9 $SPB 2>/dev/null
HCB="x"; [ -f "$DC/big.bin" ] && HCB=$(hashof "$DC/big.bin")
if [ "$base_ok" = "1" ] && [ $RCB -eq 0 ] && [ $RCSB -eq 0 ] && [ "$HCB" = "$H_BIG" ] \
   && grep -q "injecting synthetic peer-left" "$WORK/g11c-send.log" \
   && grep -q "deferring drop" "$WORK/g11c-send.log" \
   && ! grep -q "superseding old link" "$WORK/g11c-send.log"; then
  ok "deferred drop: flowing link survives its peer-left, transfer completes (A/B proven)"
else bad "deferred-drop (#28 trigger)"; tail -n 4 "$WORK/g11c-send.log" "$WORK/g11ca-send.log"; fi

# --------------------------------------------------------------- gate 13 ----
say "13: multi-link — CLI + two browsers, nobody wedges (C18)"
if [ -z "${SKIP_BROWSER:-}" ] && [ -d "$HERE/node_modules/playwright" ]; then
  RM13="g13room$$"
  ( cd "$HERE" && timeout 180 node two-browsers.js "$RM13" >"$WORK/g13-pw.log" 2>&1 ) &
  PW=$!; pids+=($PW); sleep 8
  G13=0
  timeout 120 "$BIN" send "$SMALL" --room "$RM13" --server "$SERVER" >"$WORK/g13-send.log" 2>&1 || G13=1
  wait $PW || G13=1
  if [ $G13 -eq 0 ] && grep -q "C18 PASS" "$WORK/g13-pw.log"; then
    ok "CLI answered both browsers; transfer completed with bystander"
  else bad "multi-link"; tail -n 3 "$WORK/g13-pw.log" "$WORK/g13-send.log"; fi
else
  echo "SKIP (playwright not installed)"
fi

# --------------------------------------------------------------- gate 14 ----
say "14: daemon — pair, introduce-grade trust, room-less up receives (C19/C20/C12)"
DA="$WORK/g14a"; DB="$WORK/g14b"; DD="$WORK/g14drop"; mkdir -p "$DA" "$DB" "$DD"
FILAMENT_CONFIG_DIR="$DA" "$BIN" send "$SMALL" --word "$CODE_WORD" --remember boxB --server "$SERVER" >"$WORK/g14-s1.log" 2>&1 &
SP=$!; pids+=($SP)
W=$(wait_code "$WORK/g14-s1.log") || { bad "daemon (no code minted)"; tail -n 3 "$WORK/g14-s1.log"; }
FILAMENT_CONFIG_DIR="$DB" timeout 60 "$BIN" receive "$W" -y --remember boxA --dir "$DB" --server "$SERVER" >"$WORK/g14-r1.log" 2>&1
wait $SP
FILAMENT_CONFIG_DIR="$DB" timeout 90 "$BIN" up --dir "$DD" --server "$SERVER" >"$WORK/g14-up.log" 2>&1 &
UP=$!; pids+=($UP); sleep 3
G14=0
FILAMENT_CONFIG_DIR="$DA" timeout 60 "$BIN" send "$BIG" --to boxB --server "$SERVER" >"$WORK/g14-s2.log" 2>&1 || G14=1
sleep 1; kill $UP 2>/dev/null
if [ $G14 -eq 0 ] && [ "$(hashof "$DD/big.bin")" = "$H_BIG" ] \
   && grep -q "identity verified" "$WORK/g14-up.log" \
   && ! grep -q "listening in room" "$WORK/g14-up.log"; then
  ok "daemon: verified identity, room-less, received + hash match"
else bad "daemon"; tail -n 3 "$WORK/g14-up.log" "$WORK/g14-s2.log"; fi

# --------------------------------------------------------------- gate 15 ----
say "15: paired recv holds the line when the sender vanishes (C21)"
D="$WORK/g15"; mkdir -p "$D"
"$BIN" send "$SMALL" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g15-send.log" 2>&1 &
SP=$!; pids+=($SP)
W=$(wait_code "$WORK/g15-send.log") || { bad "stepped-away wait (no code minted)"; tail -n 3 "$WORK/g15-send.log"; }
T0=$(date +%s)
# no -y and no tty -> the offer is declined -> sender exits -> peer-left with
# nothing received; the OLD behavior bailed instantly, C21 holds the line.
FILAMENT_REJOIN_SECS=8 timeout 60 "$BIN" receive "$W" --dir "$D" --server "$SERVER" </dev/null >"$WORK/g15-recv.log" 2>&1
RC=$?
T1=$(date +%s)
wait $SP 2>/dev/null
if [ $RC -ne 0 ] && grep -q "holding the line" "$WORK/g15-recv.log" \
   && grep -q "did not come back within 8s" "$WORK/g15-recv.log" \
   && [ $((T1 - T0)) -ge 8 ]; then
  ok "stepped-away sender: held ${FILAMENT_REJOIN_SECS:-8}s window, then failed honestly"
else bad "stepped-away wait"; tail -n 3 "$WORK/g15-recv.log"; fi

say "16: known-device rendezvous + remember consent (C12/C20/C27 web)"
if [ -z "${SKIP_BROWSER:-}" ] && [ -d "$HERE/node_modules/playwright" ]; then
  G16=0
  C16="$WORK/g16cfg"; mkdir -p "$C16"
  # phase 1 sender: mints the code (a valid 2-word phrase + machine nameplate),
  # offers a pair-keep secret (the browser must NOT store it until the human
  # clicks 'remember', C27). The browser must claim the FULL minted code.
  FILAMENT_CONFIG_DIR="$C16" "$BIN" send "$SMALL" --word "$CODE_WORD" --remember pwdev --server "$SERVER" >"$WORK/g16-s1.log" 2>&1 &
  S16=$!; pids+=($S16)
  W16=$(wait_code "$WORK/g16-s1.log") || { bad "known-device (no code minted)"; tail -n 3 "$WORK/g16-s1.log"; }
  # phase 3's decline sender is started later (below); the harness polls its log
  # for the minted code via the `@<logfile>` form once it reaches phase 3.
  ( cd "$HERE" && node known-device.js "$SERVER" "$W16" "@$WORK/g16-s3.log" >"$WORK/g16-pw.log" 2>&1 ) &
  PW16=$!; pids+=($PW16)
  wait $S16 || G16=1   # phase 1 transfer done; browser must now hold the secret
  # phase 2: fresh session, ISOLATED room, no code — only the secret-derived
  # channel can find the browser. The same config dir holds 'pwdev'.
  FILAMENT_CONFIG_DIR="$C16" timeout 120 "$BIN" send "$SMALL" --to pwdev --room "g16iso$$" --server "$SERVER" >"$WORK/g16-s2.log" 2>&1 || G16=1
  # phase 3 (C27 decline): a new sender offers; the browser clicks 'not now';
  # the ack must make this sender DISCARD its stored half.
  FILAMENT_CONFIG_DIR="$C16" timeout 60 "$BIN" send "$SMALL" --word "$CODE_WORD" --remember declinedev --server "$SERVER" >"$WORK/g16-s3.log" 2>&1 &
  S16B=$!; pids+=($S16B)
  wait $PW16 || G16=1
  kill $S16B 2>/dev/null; wait $S16B 2>/dev/null
  if [ $G16 -eq 0 ] && grep -q "SECRET STORED" "$WORK/g16-pw.log" \
     && grep -q "PHASE2 COMPLETE" "$WORK/g16-pw.log" \
     && grep -q "PHASE3 DECLINED" "$WORK/g16-pw.log" \
     && grep -q "declined to be remembered" "$WORK/g16-s3.log" \
     && ! grep -rq "declinedev" "$C16"; then
    ok "consent-gated store; --to found it cross-room; decline purged the sender's half"
  else bad "known-device"; tail -n 4 "$WORK/g16-pw.log" "$WORK/g16-s1.log" "$WORK/g16-s2.log" "$WORK/g16-s3.log"; fi
else
  echo "SKIP (run: cd $HERE && npm i playwright && npx playwright install chromium)"
fi

say "17: pair ceremony — no file, both stores hold the SAME secret (C29)"
DA17="$WORK/g17a"; DB17="$WORK/g17b"; mkdir -p "$DA17" "$DB17"
FILAMENT_CONFIG_DIR="$DA17" timeout 90 "$BIN" add --name boxB --server "$SERVER" >"$WORK/g17-a.log" 2>&1 &
P17=$!; pids+=($P17); sleep 4
C17=$(grep -oE '[A-Za-z]+-[A-Za-z]+-[0-9]+' "$WORK/g17-a.log" | head -1 | tr 'A-Z' 'a-z')
G17=0
FILAMENT_CONFIG_DIR="$DB17" timeout 90 "$BIN" join "$C17" --name boxA --server "$SERVER" >"$WORK/g17-b.log" 2>&1 || G17=1
wait $P17 || G17=1
CHA=$(FILAMENT_CONFIG_DIR="$DA17" "$BIN" devices | grep -oE 'channel [0-9a-f]+' | head -1)
CHB=$(FILAMENT_CONFIG_DIR="$DB17" "$BIN" devices | grep -oE 'channel [0-9a-f]+' | head -1)
if [ $G17 -eq 0 ] && [ -n "$CHA" ] && [ "$CHA" = "$CHB" ]; then
  ok "pair ceremony: both exited clean; channel ids match (one mutual secret)"
else bad "pair-ceremony"; tail -n 3 "$WORK/g17-a.log" "$WORK/g17-b.log"; fi

say "17b: pair ceremony fails FAST when it can't complete (no 10-min orphan)"
# The D3/D5 divergence the monitor kept catching: a claimer whose creator
# vanishes (or never connects) used to sit in the room for the full 600s TTL.
# The claimer here connects but STALLS (hook) so the ceremony can't finish;
# the budget (shortened to 5s) must bail it with a clear message — NOT the
# 600s code TTL, and well under the 90s timeout backstop.
DC="$WORK/g17c"; mkdir -p "$DC/a" "$DC/b"
FILAMENT_CONFIG_DIR="$DC/a" timeout 120 "$BIN" add --name gone --server "$SERVER" >"$WORK/g17c-a.log" 2>&1 &
CR=$!; pids+=($CR); sleep 4
CX=$(grep -oE '[A-Za-z]+-[A-Za-z]+-[0-9]+' "$WORK/g17c-a.log" | head -1 | tr 'A-Z' 'a-z')
T0=$(date +%s)
FILAMENT_TEST_PAIR_STALL=1 FILAMENT_PAIR_GRACE_SECS=5 FILAMENT_CONFIG_DIR="$DC/b" \
  timeout 90 "$BIN" join "$CX" --name orphan --server "$SERVER" >"$WORK/g17c-b.log" 2>&1
RC=$?; T1=$(date +%s)
kill $CR 2>/dev/null; wait $CR 2>/dev/null
if [ $RC -ne 0 ] && [ $((T1 - T0)) -lt 30 ] \
   && grep -q "could not connect before pairing finished" "$WORK/g17c-b.log"; then
  ok "ceremony bailed in $((T1 - T0))s with a clear message (was: 600s orphan)"
else bad "pair fail-fast"; echo "  rc=$RC walltime=$((T1-T0))s"; tail -n 3 "$WORK/g17c-b.log"; fi

# --------------------------------------------------------------- gate 18 ----
say "18: recv quiet-exit when peer-left never arrives (G-k)"
# The quiet-exit fallback: a transfer completes but the peer-left event is
# LOST (delivery is best-effort — observed live under load). recv must notice
# everything is done + nobody attached and exit 0 on its own.
#
# Simulating the loss: FILAMENT_TEST_DROP_PEER_LEFT makes recv drop incoming
# peer-left events at exactly the delivery boundary. (A SIGSTOP'd sender can't
# do it: engine.io's ping timeout reaps the frozen client in ~30 s and the
# legit peer-left wins the race against link teardown — measured.)
D="$WORK/g18"; mkdir -p "$D"
"$BIN" send "$SMALL" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g18-send.log" 2>&1 &
SP=$!; pids+=($SP)
W=$(wait_code "$WORK/g18-send.log") || { bad "quiet-exit (G-k) (no code minted)"; tail -n 3 "$WORK/g18-send.log"; }
# The test precondition is "the file arrived AND the sender is GONE, but the
# peer-left notification was LOST". So SIGKILL the sender the instant IT reports
# the delivery+ack (its own log, the earliest reliable "done" signal), so the
# receiver's post-delivery reconnect deterministically finds no live peer and the
# dropped peer-left forces the quiet-exit. Without this, under suite load the
# receiver reconnects to the still-lingering sender (a healthy link, which
# correctly BLOCKS quiet-exit), so the gate hung to the 120s timeout: a
# test-fidelity gap, not a product bug (the transfer always completed + verified).
( for _ in $(seq 1 600); do
    grep -q "delivered + verified\|^done\.\|delivered" "$WORK/g18-send.log" 2>/dev/null \
      && { kill -9 $SP 2>/dev/null; break; }
    sleep 0.1
  done ) &
T0=$(date +%s)
FILAMENT_TEST_DROP_PEER_LEFT=1 FILAMENT_QUIET_EXIT_SECS=3 \
  timeout 120 "$BIN" receive "$W" -y --dir "$D" --server "$SERVER" </dev/null >"$WORK/g18-recv.log" 2>&1
RC=$?
T1=$(date +%s)
kill -9 $SP 2>/dev/null; wait $SP 2>/dev/null
if [ $RC -eq 0 ] \
   && grep -q "peer-left never arrived" "$WORK/g18-recv.log" \
   && grep -F "done (1 file" "$WORK/g18-recv.log" >/dev/null \
   && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ] \
   && [ $((T1 - T0)) -lt 90 ]; then
  ok "quiet-exit fired (peer-left dropped), exited 0 in $((T1 - T0))s, hash matches"
else
  bad "quiet-exit (G-k)"; echo "  RC=$RC walltime=$((T1 - T0))s"; tail -n 6 "$WORK/g18-recv.log"
fi

# -------------------------------------------------------------- gate 18b ----
# Gate 18 Mode B (the contention flake #28 could not previously reproduce): a
# transfer COMPLETES, the sender's peer-left is LOST (as in gate 18), but the
# sender's departure also puts the receiver's now-pointless link into the C4
# reconnect loop. The link FLAPS (establish → connect → die → Stuck → establish
# …); each cycle RESETS attempts (so MAX_ATTEMPTS never caps it) and re-arms
# expected_secret (so digest_says_alone never holds) → conn.links never empties
# → the quiet-exit never fires → RC=124 hang to the timeout. Standalone it
# passes (no contention to trigger the flap); only under suite load did the
# departure-into-reconnect race fire — a heisenbug. This makes it DETERMINISTIC.
#
# FILAMENT_TEST_CHURN_AFTER_COMPLETE forces the post-completion flap from the
# recv loop (close + re-inject Ev::Stuck with attempts reset, mirroring the wild
# flap) ONCE the file is on disk. A/B with ONE binary via
# FILAMENT_TEST_DISABLE_MODEB_DROP:
#   A (baseline, drop disabled): on_stuck re-establishes → link persists → hang
#     → RC=124. This is the bug, reproduced on demand.
#   B (fix): on_stuck sees recv_done and DROPS the link (nothing left to fetch)
#     → conn.links empties → no link left to churn → quiet-exit fires fast.
# The fence is recv_done == (completed>0 && by_sid.is_empty() && !keep_open), so
# a MID-transfer link (by_sid non-empty) is never dropped — gate 2 (kill-resume)
# and gate 11c (deferred-drop) reconnect paths are untouched (unit-tested too).
say "18b: recv exits on post-completion link churn — Mode B (RC=124 flake, #28)"
H_DIR="$WORK/g18b"; mkdir -p "$H_DIR"
# A) baseline: Mode-B drop disabled → the post-completion flap hangs to timeout.
# -v on the receivers: the flap line ("connection stuck while connecting,
# retrying") and "nothing left to fetch" are DEBUG (resilience-internal) lines.
DA="$H_DIR/a"; mkdir -p "$DA"
"$BIN" send "$SMALL" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g18ba-send.log" 2>&1 &
SPA=$!; pids+=($SPA)
WA=$(wait_code "$WORK/g18ba-send.log") || { bad "gate-18b Mode B (no code minted)"; tail -n 3 "$WORK/g18ba-send.log"; }
( sleep 6; kill -9 $SPA 2>/dev/null ) &   # sender departs after delivering the file
FILAMENT_TEST_DISABLE_MODEB_DROP=1 FILAMENT_TEST_CHURN_AFTER_COMPLETE=1 \
  FILAMENT_TEST_DROP_PEER_LEFT=1 FILAMENT_QUIET_EXIT_SECS=2 \
  timeout 30 "$BIN" -v receive "$WA" -y --dir "$DA" --server "$SERVER" </dev/null >"$WORK/g18ba-recv.log" 2>&1
RCA=$?
kill -9 $SPA 2>/dev/null; wait $SPA 2>/dev/null
# Baseline MUST hang (RC=124) yet still have the bytes on disk (it's the EXIT
# that's broken, not the transfer) and show the flap, never a clean drop.
base_ok=0
{ [ $RCA -eq 124 ] && [ "$(hashof "$DA/small.bin" 2>/dev/null)" = "$H_SMALL" ] \
  && grep -q "stuck while connecting" "$WORK/g18ba-recv.log" \
  && ! grep -q "nothing left to fetch" "$WORK/g18ba-recv.log"; } && base_ok=1
# B) fix: Mode-B drop on → on_stuck drops the dead link, quiet-exit fires fast.
DB="$H_DIR/b"; mkdir -p "$DB"
"$BIN" send "$SMALL" --word "$CODE_WORD" --server "$SERVER" >"$WORK/g18bb-send.log" 2>&1 &
SPB=$!; pids+=($SPB)
WB=$(wait_code "$WORK/g18bb-send.log") || { bad "gate-18b Mode B (no code minted)"; tail -n 3 "$WORK/g18bb-send.log"; }
T0=$(date +%s)
( sleep 6; kill -9 $SPB 2>/dev/null ) &
FILAMENT_TEST_CHURN_AFTER_COMPLETE=1 FILAMENT_TEST_DROP_PEER_LEFT=1 FILAMENT_QUIET_EXIT_SECS=2 \
  timeout 30 "$BIN" -v receive "$WB" -y --dir "$DB" --server "$SERVER" </dev/null >"$WORK/g18bb-recv.log" 2>&1
RCB=$?
T1=$(date +%s)
kill -9 $SPB 2>/dev/null; wait $SPB 2>/dev/null
if [ "$base_ok" = "1" ] && [ $RCB -eq 0 ] \
   && [ "$(hashof "$DB/small.bin" 2>/dev/null)" = "$H_SMALL" ] \
   && grep -q "nothing left to fetch" "$WORK/g18bb-recv.log" \
   && grep -F "done (1 file" "$WORK/g18bb-recv.log" >/dev/null \
   && [ $((T1 - T0)) -lt 15 ]; then
  ok "Mode B: baseline hung (RC=$RCA), fix dropped dead link + exited in $((T1-T0))s (A/B proven)"
else
  bad "gate-18b Mode B"; echo "  base_ok=$base_ok RCA=$RCA RCB=$RCB fix_walltime=$((T1-T0))s"
  tail -n 6 "$WORK/g18bb-recv.log" "$WORK/g18ba-recv.log"
fi

# --------------------------------------------------------------- gate 19 ----
say "19: gate L — lossy session emits still converge (C30; loss=0.5 seed=16)"
# Seed 16's drop pattern is 'DD....': BOTH processes lose their first two
# session emits (join + subscribe). The rendezvous can then only happen via
# the convergent session's repair loop — which is exactly what's under test.
# Deterministic by seed; this exact choreography found two implementation
# bugs by hand before becoming a gate (a tick starved behind a blocking
# 600s read; see C30 in the ledger).
DA19="$WORK/g19a"; DB19="$WORK/g19b"; D19="$WORK/g19"; mkdir -p "$DA19" "$DB19" "$D19"
FILAMENT_CONFIG_DIR="$DA19" timeout 90 "$BIN" add --name boxB --server "$SERVER" >"$WORK/g19-pa.log" 2>&1 &
P19=$!; pids+=($P19); sleep 4
C19=$(grep -oE '[A-Za-z]+-[A-Za-z]+-[0-9]+' "$WORK/g19-pa.log" | head -1 | tr 'A-Z' 'a-z')
G19=0
FILAMENT_CONFIG_DIR="$DB19" timeout 90 "$BIN" join "$C19" --name boxA --server "$SERVER" >"$WORK/g19-pb.log" 2>&1 || G19=1
wait $P19 || G19=1
FILAMENT_TEST_EMIT_LOSS=0.5 FILAMENT_TEST_EMIT_SEED=16 FILAMENT_CONFIG_DIR="$DB19" \
  timeout 120 "$BIN" up --dir "$D19" --server "$SERVER" </dev/null >"$WORK/g19-up.log" 2>&1 &
U19=$!; pids+=($U19); sleep 2
T0=$(date +%s)
FILAMENT_TEST_EMIT_LOSS=0.5 FILAMENT_TEST_EMIT_SEED=16 FILAMENT_CONFIG_DIR="$DA19" \
  timeout 120 "$BIN" send "$SMALL" --to boxB --server "$SERVER" >"$WORK/g19-send.log" 2>&1 || G19=1
T1=$(date +%s)
kill $U19 2>/dev/null; wait $U19 2>/dev/null
if [ $G19 -eq 0 ] && [ "$(hashof "$D19/small.bin")" = "$H_SMALL" ] && [ $((T1 - T0)) -lt 60 ]; then
  ok "lossy rendezvous converged in $((T1 - T0))s (both sides dropped join+subscribe)"
else bad "gate-L convergence"; tail -n 4 "$WORK/g19-up.log" "$WORK/g19-send.log"; fi

# ============================================================================
# L1-a — PAKE first-pairing gates (spec docs/L1-pake-protocol.md §10)
# ----------------------------------------------------------------------------
# These SEVEN gates verify the SPAKE2 first-pairing change. They are validated
# by STANDALONE scripts under /root/.claude/jobs/330c2366/tmp/wt-l1a-gates/ on
# PORT 8093 (NOT 8077 — this suite's fixture), because the PAKE security
# properties want their own deterministic, two-tier harness:
#
#   gate L1a-1 mutual-key       gate1_mutual_key.sh  — two real `filament pair`
#       processes, same code → byte-identical pinned secret; confirmation passes.
#   gate L1a-2 adversarial      adversary (pake bin) — NEGATIVE security test:
#       a relay/MITM without the password cannot derive K nor substitute a key
#       (element-MITM, a=fingerprint-rewrite, caps-rewrite all DETECTED → abort,
#       zero secret). A/B numbers printed. *Required by the ledger NEGATIVE rule.*
#   gate L1a-3 wrongpw-burns    gate3_wrongpw_burn.sh — wrong password REFUSED,
#       nothing stored, nameplate BURNED (no silent same-code retry).
#   gate L1a-4 browser<->cli    gate4_interop.mjs — committed browser WASM and
#       native CLI derive the SAME secret + mutually confirm (deterministic).
#   gate L1a-5 caps deny-default cargo test capability_deny_by_default — empty
#       caps refuse a gated action; "transfer" is the L0 baseline; not escalatable.
#   gate L1a-6 downgrade-refused gate6_downgrade.sh — a v:2-stripping server
#       (FIL_FORCE_V1) is refused; no v2 path stores a server-readable secret.
#   gate L1a-7 no-regression    gate7_noregression.sh — vanilla send/recv still
#       transfers; remembered v2 devices reconnect via the unchanged proof path.
#       (Plus: existing gates 0/19 below still pass — pairing is additive.)
#
# Backend crypto: backend/tests/test_pair_codes.py::PakeV2Nameplate (incl. the
# relay-blind NEGATIVE assertion that words never reach the server). Shared
# SPAKE2 crate: `cargo test` in pake/ (10 unit tests incl. reflection-rejected).
# ============================================================================

say "20: U1 implicit identity: minted once on first use, never twice, inspect screens mint nothing"
# The config dir is NOT pre-created: the accessor makes it (0700) and the key
# (0600). Run 1 creates and says so once on stderr; run 2 says nothing and
# prints the same identity; `init` afterwards still refuses; `--json` never
# gets the prose line. Then the three that must NOT mint: the bare tour screen
# (an inspect surface, which must also not FAIL on a device that cannot mint),
# `id` under the opt-out (the pre-U1 answer, exit 0, nothing written), and a
# verb that must sign under the opt-out (still fails fast).
D20="$WORK/g20-cfg"; rm -rf "$D20"
FILAMENT_CONFIG_DIR="$D20" "$BIN" id >"$WORK/g20-1.out" 2>"$WORK/g20-1.err"; R20A=$?
FILAMENT_CONFIG_DIR="$D20" "$BIN" id >"$WORK/g20-2.out" 2>"$WORK/g20-2.err"; R20B=$?
N20A=$(grep -c "created your identity" "$WORK/g20-1.err"); N20B=$(grep -c "created your identity" "$WORK/g20-2.err")
M20K=$(stat -c %a "$D20/identity.ed25519" 2>/dev/null); M20D=$(stat -c %a "$D20" 2>/dev/null)
FILAMENT_CONFIG_DIR="$D20" "$BIN" init --yes --name g20 --recovery-file "$WORK/g20-rec" >"$WORK/g20-init.log" 2>&1; R20I=$?
D20J="$WORK/g20-json"; rm -rf "$D20J"
FILAMENT_CONFIG_DIR="$D20J" "$BIN" id --json >"$WORK/g20-j.out" 2>"$WORK/g20-j.err"; R20J=$?
D20T="$WORK/g20-tour"; rm -rf "$D20T"
FILAMENT_CONFIG_DIR="$D20T" "$BIN" >"$WORK/g20-t.log" 2>&1; R20T=$?
D20N="$WORK/g20-noimplicit"; rm -rf "$D20N"
FILAMENT_NO_IMPLICIT_INIT=1 FILAMENT_CONFIG_DIR="$D20N" "$BIN" id >"$WORK/g20-n.log" 2>&1; R20N=$?
FILAMENT_NO_IMPLICIT_INIT=1 FILAMENT_CONFIG_DIR="$D20N" "$BIN" grant g20peer route:10.66.0.0/24 >"$WORK/g20-g.log" 2>&1; R20G=$?
if [ $R20A -eq 0 ] && [ $R20B -eq 0 ] && [ "$N20A" = 1 ] && [ "$N20B" = 0 ] \
   && cmp -s "$WORK/g20-1.out" "$WORK/g20-2.out" && [ "$M20K" = 600 ] && [ "$M20D" = 700 ] \
   && [ $R20I -ne 0 ] && grep -q "already has identity" "$WORK/g20-init.log" \
   && [ $R20J -eq 0 ] && ! grep -q "created your identity" "$WORK/g20-j.err" && [ -f "$D20J/identity.ed25519" ] \
   && [ $R20T -eq 0 ] && grep -q "do this:" "$WORK/g20-t.log" && [ ! -e "$D20T/identity.ed25519" ] \
   && [ $R20N -eq 0 ] && grep -q "no identity yet" "$WORK/g20-n.log" \
   && [ $R20G -ne 0 ] && grep -q "filament init" "$WORK/g20-g.log" && [ ! -e "$D20N/identity.ed25519" ]; then
  ok "U1: created once ($N20A line, key $M20K, dir $M20D), second run silent, init refuses, --json silent, tour and opt-out mint nothing"
else
  bad "u1-implicit-init"
  echo "  rc: id=$R20A/$R20B lines=$N20A/$N20B key=$M20K dir=$M20D init=$R20I json=$R20J tour=$R20T optout-id=$R20N optout-grant=$R20G"
  tail -n 3 "$WORK/g20-1.err" "$WORK/g20-2.err" "$WORK/g20-init.log" "$WORK/g20-j.err" "$WORK/g20-t.log" "$WORK/g20-n.log" "$WORK/g20-g.log"
fi

# --------------------------------------------------------- L2 tunnel gates ---
# ssh / TCP over the data channel (docs/L2-tunnel-design.md). These run their
# OWN fixture backend on port 8097 (NOT this suite's 8077) and are OPT-IN:
# they are NOT part of the deterministic-core commit gate (single-stream scope;
# real sshd; longer-running). Run them standalone with `tests/l2-gates.sh`, or
# inline here with `L2_GATES=1 ./gates.sh`.
if [ "${L2_GATES:-0}" = "1" ]; then
  say "L2: ssh/TCP tunnel (port 8097 — delegates to l2-gates.sh)"
  if bash "$HERE/l2-gates.sh"; then
    ok "L2 tunnel gates (ssh round-trip, forward, half-close, cap/SSRF deny, teardown)"
  else
    bad "L2 tunnel gates"
  fi
fi

# ---------------------------------------------------------------- summary ---
printf '\n\033[1m%d passed, %d failed%s\033[0m\n' "$PASS" "$FAIL" "${FAILED_GATES:+ —$FAILED_GATES}"
echo "artifacts: $WORK"
[ $FAIL -eq 0 ]
