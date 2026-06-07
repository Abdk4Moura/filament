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
# Browser gates need playwright (npm i playwright in this dir; chromium is
# fetched on first run).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="$CLI_DIR/target/release/filament"
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
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; exit 2; }
( cd "$CLI_DIR" && cargo build --release -q ) || { echo "build failed"; exit 2; }

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
PYV="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"
if [ -x "$PYV" ]; then
  if ( cd "$CLI_DIR/.." && "$PYV" -m unittest backend.tests.test_pair_codes ) >"$WORK/g0b.log" 2>&1; then
    ok "pair-code variance/security tests"
  else bad "pair-code tests"; tail -n 5 "$WORK/g0b.log"; fi
fi

# ---------------------------------------------------------------- gate 1 ----
say "1: one-time code transfer + code burn"
W="g1-$$-$RANDOM"; D="$WORK/g1"; mkdir -p "$D"
"$BIN" send "$SMALL" --word "$W" --server "$SERVER" >"$WORK/g1-send.log" 2>&1 &
SP=$!; pids+=($SP); sleep 3
if timeout 90 "$BIN" recv "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g1-recv.log" 2>&1 \
   && wait $SP && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ]; then
  ok "code transfer, hashes match, clean exits"
else bad "code transfer"; tail -n 3 "$WORK/g1-send.log" "$WORK/g1-recv.log"; fi
# C2: same-machine peers must BOTH report local (is_own_addr handles the
# multi-homed case), and nothing may misreport relayed.
if [ "$(grep -hc 'route: local' "$WORK/g1-send.log" "$WORK/g1-recv.log" | paste -sd+ | bc)" -ge 2 ] \
   && ! grep -hq "route: relayed" "$WORK/g1-send.log" "$WORK/g1-recv.log"; then
  ok "route detection: local on both ends, no false relayed"
else bad "route detection"; grep -h "route:" "$WORK/g1-send.log" "$WORK/g1-recv.log"; fi
if timeout 30 "$BIN" recv "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g1-burn.log" 2>&1; then
  bad "code burn (second claim was accepted!)"
else
  grep -q "code rejected" "$WORK/g1-burn.log" && ok "code burns on first use" || { bad "code burn (wrong error)"; tail -n 2 "$WORK/g1-burn.log"; }
fi

# ---------------------------------------------------------------- gate 2 ----
say "2: chaos — receiver killed mid-transfer, replacement resumes (C4/C6/C7)"
W="g2-$$-$RANDOM"; D="$WORK/g2"; mkdir -p "$D"
"$BIN" send "$BIG" --word "$W" --server "$SERVER" >"$WORK/g2-send.log" 2>&1 &
SP=$!; pids+=($SP); sleep 3
"$BIN" recv "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g2-recv1.log" 2>&1 &
R1=$!; pids+=($R1)
for _ in $(seq 1 60); do
  sz=$(stat -c %s "$D/big.bin.part" 2>/dev/null || echo 0)
  [ "$sz" -gt $((10 * 1024 * 1024)) ] && break
  sleep 0.5
done
kill -9 $R1 2>/dev/null; wait $R1 2>/dev/null
echo "(killed receiver at $(stat -c %s "$D/big.bin.part" 2>/dev/null || echo '?') bytes)"
sleep 2
timeout 180 "$BIN" recv -y --dir "$D" --server "$SERVER" >"$WORK/g2-recv2.log" 2>&1
RC2=$?
wait $SP; RCS=$?
if [ $RC2 -eq 0 ] && [ $RCS -eq 0 ] && [ "$(hashof "$D/big.bin")" = "$H_BIG" ] \
   && grep -q "resuming at" "$WORK/g2-recv2.log"; then
  ok "kill-resume: replacement receiver resumed, hash matches"
else bad "kill-resume"; tail -n 4 "$WORK/g2-send.log" "$WORK/g2-recv2.log"; fi

# ---------------------------------------------------------------- gate 3 ----
say "3: corruption guard — same name+size, different content restarts (C7)"
W="g3-$$-$RANDOM"; D="$WORK/g3"; mkdir -p "$D"
head -c $((2 * 1024 * 1024)) /dev/zero > "$D/small.bin.part"
printf '{"size":%s,"head":"00deadbeef"}' "$(stat -c %s "$SMALL")" > "$D/small.bin.part.meta"
"$BIN" send "$SMALL" --word "$W" --server "$SERVER" >"$WORK/g3-send.log" 2>&1 &
SP=$!; pids+=($SP); sleep 3
if timeout 90 "$BIN" recv "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g3-recv.log" 2>&1 \
   && wait $SP && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ] \
   && grep -q "different content" "$WORK/g3-recv.log"; then
  ok "head mismatch detected, restarted from 0, hash matches"
else bad "corruption guard"; tail -n 3 "$WORK/g3-recv.log"; fi

# ---------------------------------------------------------------- gate 4 ----
say "4: directory tar + stdin pipe"
D="$WORK/g4"; mkdir -p "$D" "$WORK/srcdir/sub"
echo "hello" > "$WORK/srcdir/a.txt"; head -c 1048576 /dev/urandom > "$WORK/srcdir/sub/b.bin"
"$BIN" recv -y --dir "$D" --server "$SERVER" >"$WORK/g4-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 3
G4=0
timeout 60 "$BIN" send "$WORK/srcdir" --server "$SERVER" >"$WORK/g4-send.log" 2>&1 || G4=1
wait $R 2>/dev/null
tar tf "$D/srcdir.tar" >/dev/null 2>&1 || G4=1
"$BIN" recv -y --dir "$D" --server "$SERVER" >"$WORK/g4b-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 3
echo "pipe payload" | timeout 60 "$BIN" send - --name note.txt --server "$SERVER" >"$WORK/g4b-send.log" 2>&1 || G4=1
wait $R 2>/dev/null
[ "$(cat "$D/note.txt" 2>/dev/null)" = "pipe payload" ] || G4=1
[ $G4 -eq 0 ] && ok "dir tar + stdin round-trip" || bad "dir/stdin"

# ---------------------------------------------------------------- gate 5 ----
say "5: CLI -> browser (playwright)"
if [ -d "$HERE/node_modules/playwright" ]; then
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
if [ -d "$HERE/node_modules/playwright" ]; then
  D="$WORK/g6"; mkdir -p "$D"
  FA="$WORK/g6-a.bin"; FB="$WORK/g6-b.bin"
  head -c $((4 * 1024 * 1024)) /dev/urandom > "$FA"
  head -c $((1024 * 1024)) /dev/urandom > "$FB"
  RM6="g6room$$"
  timeout 240 "$BIN" recv -y --dir "$D" --room "$RM6" --server "$SERVER" >"$WORK/g6-recv.log" 2>&1 &
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
USER=alice "$BIN" recv -y --to charlie --dir "$DA" --server "$SERVER" >"$WORK/g7-alice.log" 2>&1 &
RA=$!; pids+=($RA)
USER=bob timeout 120 "$BIN" recv -y --dir "$DB" --server "$SERVER" >"$WORK/g7-bob.log" 2>&1 &
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
"$BIN" recv --dir "$D" --server "$SERVER" </dev/null >"$WORK/g8-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 3
G8=0
timeout 60 "$BIN" send "$SMALL" --server "$SERVER" >"$WORK/g8-send.log" 2>&1 || G8=1
kill $R 2>/dev/null
if [ $G8 -eq 0 ] && grep -q "declined" "$WORK/g8-send.log" && [ ! -e "$D/small.bin" ]; then
  ok "offer declined without consent; sender exited cleanly"
else bad "consent decline"; tail -n 3 "$WORK/g8-send.log" "$WORK/g8-recv.log"; fi

# ---------------------------------------------------------------- gate 9 ----
say "9: throughput floor (C8a regression guard)"
D="$WORK/g9"; mkdir -p "$D"
"$BIN" recv -y --dir "$D" --server "$SERVER" >"$WORK/g9-recv.log" 2>&1 &
R=$!; pids+=($R); sleep 3
T0=$(date +%s.%N)
timeout 120 "$BIN" send "$BIG" --server "$SERVER" >"$WORK/g9-send.log" 2>&1
RC=$?
T1=$(date +%s.%N)
wait $R 2>/dev/null
RATE=$(python3 -c "print(f'{80/max(($T1-$T0)-4.5,0.1):.1f}')")  # ~4.5s fixed overhead (join+route+grace)
echo "(~${RATE} MB/s effective)"
if [ $RC -eq 0 ] && [ "$(hashof "$D/big.bin")" = "$H_BIG" ] && python3 -c "exit(0 if $RATE >= 8 else 1)"; then
  ok "throughput >= 8 MB/s ($RATE MB/s)"
else bad "throughput ($RATE MB/s)"; fi

# --------------------------------------------------------------- gate 10 ----
kill_port() { # fixture backends (werkzeug reloader forks; kill by port)
  for pid in $(ss -tlnp 2>/dev/null | grep ":$1 " | grep -oP 'pid=\K[0-9]+' | sort -u); do
    kill "$pid" 2>/dev/null
  done
}
kill_8078() { kill_port 8078; }
VENV_PY="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"

# --------------------------------------------------------------- gate 12 ----
# C1 against PRODUCTION's config: a backend serving chunkSize 65536 makes the
# browser frame 64 KiB + 4 = 65540-byte messages. The CLI must advertise
# a=max-message-size and read with a >64K buffer (detached channel) or the
# first chunk kills the channel. This is the live-prod scenario, no deploy
# of the backend required.
say "12: browser with 64 KiB prod framing -> CLI (C1)"
if [ -d "$HERE/node_modules/playwright" ] && [ -x "$VENV_PY" ]; then
  kill_port 8079; sleep 1
  ( cd "$CLI_DIR/../backend" && PORT=8079 FIL_CHUNK_SIZE=65536 "$VENV_PY" app.py >"$WORK/g12-backend.log" 2>&1 ) &
  BK12=$!; pids+=($BK12); sleep 4
  D="$WORK/g12"; mkdir -p "$D"
  FA="$WORK/g12-a.bin"; FB="$WORK/g12-b.bin"
  head -c $((4 * 1024 * 1024)) /dev/urandom > "$FA"; head -c $((1024 * 1024)) /dev/urandom > "$FB"
  RM="g12room$$"
  timeout 240 "$BIN" recv -y --dir "$D" --room "$RM" --server http://127.0.0.1:8079 >"$WORK/g12-recv.log" 2>&1 &
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

if [ $WITH_RELAY -eq 1 ]; then
  say "10: TURN relay path + route detection (C2/C17, docker coturn)"
  kill_8078; sleep 1
  TS=testsecret$RANDOM
  # --allow-loopback-peers: coturn 403s loopback peer addresses by default,
  # and in this hermetic setup BOTH peers are 127.0.0.1. Test-only flag.
  CT=$(docker run -d --rm --network host coturn/coturn -n \
        --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 --listening-port=3478 \
        --static-auth-secret="$TS" --realm=filament.test --no-tls --no-dtls \
        --allow-loopback-peers --cli-password=x 2>/dev/null)
  VENV_PY="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"
  ( cd "$CLI_DIR/../backend" && PORT=8078 FIL_TURN_HOST="turn:127.0.0.1:3478" FIL_TURN_SECRET="$TS" \
      "$VENV_PY" app.py >"$WORK/g10-backend.log" 2>&1 ) &
  BK=$!; pids+=($BK); sleep 4
  W="g10-$$-$RANDOM"; D="$WORK/g10"; mkdir -p "$D"
  "$BIN" send "$SMALL" --word "$W" --relay --server http://127.0.0.1:8078 >"$WORK/g10-send.log" 2>&1 &
  SP=$!; pids+=($SP); sleep 3
  G10=0
  timeout 120 "$BIN" recv "$W" -y --relay --dir "$D" --server http://127.0.0.1:8078 >"$WORK/g10-recv.log" 2>&1 || G10=1
  wait $SP || G10=1
  kill $BK 2>/dev/null; kill_8078; docker stop "$CT" >/dev/null 2>&1
  # relay-only ICE policy guarantees the path; the route line is reporting.
  # Require it on at least one end (a very fast transfer can exit before the
  # sender's detector fires).
  if [ $G10 -eq 0 ] && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ] \
     && grep -hq "route: relayed" "$WORK/g10-send.log" "$WORK/g10-recv.log"; then
    ok "relayed transfer via coturn; route: relayed reported"
  else bad "relay"; tail -n 3 "$WORK/g10-send.log" "$WORK/g10-recv.log"; fi
fi

# --------------------------------------------------------------- gate 11 ----
say "11: same-uid rejoin supersede (C6) — frozen receiver replaced by same device"
W="g11-$$-$RANDOM"; D="$WORK/g11"; mkdir -p "$D"
"$BIN" send "$BIG" --word "$W" --server "$SERVER" >"$WORK/g11-send.log" 2>&1 &
SP=$!; pids+=($SP); sleep 3
FILAMENT_UID="samedevice$$" "$BIN" recv "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g11-recv1.log" 2>&1 &
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
sleep 1
FILAMENT_UID="samedevice$$" timeout 180 "$BIN" recv -y --dir "$D" --server "$SERVER" >"$WORK/g11-recv2.log" 2>&1
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

# --------------------------------------------------------------- gate 13 ----
say "13: multi-link — CLI + two browsers, nobody wedges (C18)"
if [ -d "$HERE/node_modules/playwright" ]; then
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
W="g14-$$-$RANDOM"
FILAMENT_CONFIG_DIR="$DA" "$BIN" send "$SMALL" --word "$W" --remember boxB --server "$SERVER" >"$WORK/g14-s1.log" 2>&1 &
SP=$!; pids+=($SP); sleep 3
FILAMENT_CONFIG_DIR="$DB" timeout 60 "$BIN" recv "$W" -y --remember boxA --dir "$DB" --server "$SERVER" >"$WORK/g14-r1.log" 2>&1
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
W="g15-$$-$RANDOM"; D="$WORK/g15"; mkdir -p "$D"
"$BIN" send "$SMALL" --word "$W" --server "$SERVER" >"$WORK/g15-send.log" 2>&1 &
SP=$!; pids+=($SP); sleep 3
T0=$(date +%s)
# no -y and no tty -> the offer is declined -> sender exits -> peer-left with
# nothing received; the OLD behavior bailed instantly, C21 holds the line.
FILAMENT_REJOIN_SECS=8 timeout 60 "$BIN" recv "$W" --dir "$D" --server "$SERVER" </dev/null >"$WORK/g15-recv.log" 2>&1
RC=$?
T1=$(date +%s)
wait $SP 2>/dev/null
if [ $RC -ne 0 ] && grep -q "holding the line" "$WORK/g15-recv.log" \
   && grep -q "did not come back within 8s" "$WORK/g15-recv.log" \
   && [ $((T1 - T0)) -ge 8 ]; then
  ok "stepped-away sender: held ${FILAMENT_REJOIN_SECS:-8}s window, then failed honestly"
else bad "stepped-away wait"; tail -n 3 "$WORK/g15-recv.log"; fi

say "16: known-device rendezvous + remember consent (C12/C20/C27 web)"
if [ -d "$HERE/node_modules/playwright" ]; then
  G16=0
  W16="g16-$$-$RANDOM"
  W16B="g16b-$$-$RANDOM"
  C16="$WORK/g16cfg"; mkdir -p "$C16"
  # phase 1 sender: mints the word code, offers a pair-keep secret (the
  # browser must NOT store it until the human clicks 'remember' — C27)
  FILAMENT_CONFIG_DIR="$C16" "$BIN" send "$SMALL" --word "$W16" --remember pwdev --server "$SERVER" >"$WORK/g16-s1.log" 2>&1 &
  S16=$!; pids+=($S16); sleep 3
  ( cd "$HERE" && node known-device.js "$SERVER" "$W16" "$W16B" >"$WORK/g16-pw.log" 2>&1 ) &
  PW16=$!; pids+=($PW16)
  wait $S16 || G16=1   # phase 1 transfer done; browser must now hold the secret
  # phase 2: fresh session, ISOLATED room, no code — only the secret-derived
  # channel can find the browser. The same config dir holds 'pwdev'.
  FILAMENT_CONFIG_DIR="$C16" timeout 120 "$BIN" send "$SMALL" --to pwdev --room "g16iso$$" --server "$SERVER" >"$WORK/g16-s2.log" 2>&1 || G16=1
  # phase 3 (C27 decline): a new sender offers; the browser clicks 'not now';
  # the ack must make this sender DISCARD its stored half.
  FILAMENT_CONFIG_DIR="$C16" timeout 60 "$BIN" send "$SMALL" --word "$W16B" --remember declinedev --server "$SERVER" >"$WORK/g16-s3.log" 2>&1 &
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
FILAMENT_CONFIG_DIR="$DA17" timeout 90 "$BIN" pair --name boxB --server "$SERVER" >"$WORK/g17-a.log" 2>&1 &
P17=$!; pids+=($P17); sleep 4
C17=$(grep -oE '[A-Za-z]+-[A-Za-z]+-[0-9]+' "$WORK/g17-a.log" | head -1 | tr 'A-Z' 'a-z')
G17=0
FILAMENT_CONFIG_DIR="$DB17" timeout 90 "$BIN" pair "$C17" --name boxA --server "$SERVER" >"$WORK/g17-b.log" 2>&1 || G17=1
wait $P17 || G17=1
CHA=$(FILAMENT_CONFIG_DIR="$DA17" "$BIN" devices | grep -oE 'channel [0-9a-f]+' | head -1)
CHB=$(FILAMENT_CONFIG_DIR="$DB17" "$BIN" devices | grep -oE 'channel [0-9a-f]+' | head -1)
if [ $G17 -eq 0 ] && [ -n "$CHA" ] && [ "$CHA" = "$CHB" ]; then
  ok "pair ceremony: both exited clean; channel ids match (one mutual secret)"
else bad "pair-ceremony"; tail -n 3 "$WORK/g17-a.log" "$WORK/g17-b.log"; fi

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
W="g18-$$-$RANDOM"; D="$WORK/g18"; mkdir -p "$D"
"$BIN" send "$SMALL" --word "$W" --server "$SERVER" >"$WORK/g18-send.log" 2>&1 &
SP=$!; pids+=($SP); sleep 3
# Drain the per-IP claim window (5/min): gates 16/17 claim several codes in
# the final minute; a fresh window makes the claim deterministic.
echo "(draining claim rate-limit window: 61s)"; sleep 61
T0=$(date +%s)
FILAMENT_TEST_DROP_PEER_LEFT=1 FILAMENT_QUIET_EXIT_SECS=3 \
  timeout 120 "$BIN" recv "$W" -y --dir "$D" --server "$SERVER" </dev/null >"$WORK/g18-recv.log" 2>&1
RC=$?
T1=$(date +%s)
kill $SP 2>/dev/null; wait $SP 2>/dev/null
if [ $RC -eq 0 ] \
   && grep -q "peer-left never arrived" "$WORK/g18-recv.log" \
   && grep -F "done (1 file" "$WORK/g18-recv.log" >/dev/null \
   && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ] \
   && [ $((T1 - T0)) -lt 90 ]; then
  ok "quiet-exit fired (peer-left dropped), exited 0 in $((T1 - T0))s, hash matches"
else
  bad "quiet-exit (G-k)"; echo "  RC=$RC walltime=$((T1 - T0))s"; tail -n 6 "$WORK/g18-recv.log"
fi

# ---------------------------------------------------------------- summary ---
printf '\n\033[1m%d passed, %d failed%s\033[0m\n' "$PASS" "$FAIL" "${FAILED_GATES:+ —$FAILED_GATES}"
echo "artifacts: $WORK"
[ $FAIL -eq 0 ]
