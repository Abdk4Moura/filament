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

# payloads
SMALL="$WORK/small.bin"; BIG="$WORK/big.bin"
head -c $((5 * 1024 * 1024))  /dev/urandom > "$SMALL"
head -c $((80 * 1024 * 1024)) /dev/urandom > "$BIG"
H_SMALL=$(hashof "$SMALL"); H_BIG=$(hashof "$BIG")

# ---------------------------------------------------------------- gate 0 ----
say "0: unit tests"
if ( cd "$CLI_DIR" && cargo test -q ) >"$WORK/g0.log" 2>&1; then ok "unit tests"; else bad "unit tests"; tail -n 5 "$WORK/g0.log"; fi

# ---------------------------------------------------------------- gate 1 ----
say "1: one-time code transfer + code burn"
W="g1-$$-$RANDOM"; D="$WORK/g1"; mkdir -p "$D"
"$BIN" send "$SMALL" --word "$W" --server "$SERVER" >"$WORK/g1-send.log" 2>&1 &
SP=$!; pids+=($SP); sleep 3
if timeout 90 "$BIN" recv "$W" -y --dir "$D" --server "$SERVER" >"$WORK/g1-recv.log" 2>&1 \
   && wait $SP && [ "$(hashof "$D/small.bin")" = "$H_SMALL" ]; then
  ok "code transfer, hashes match, clean exits"
else bad "code transfer"; tail -n 3 "$WORK/g1-send.log" "$WORK/g1-recv.log"; fi
# C2: no end may misreport a non-relayed path as relayed, and the loopback
# path must be detected as local by at least one end. (On a multi-homed host
# with a PUBLIC IP on the NIC — like a droplet running both test peers — ICE
# can legitimately select different interface addresses per side, so strict
# local/local symmetry only holds across two distinct machines.)
if grep -hq "route: local" "$WORK/g1-send.log" "$WORK/g1-recv.log" \
   && ! grep -hq "route: relayed" "$WORK/g1-send.log" "$WORK/g1-recv.log"; then
  ok "route detection: local seen, no false relayed"
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
  ( cd "$HERE" && node browser-receiver.js "$SERVER/" >"$WORK/g5-pw.log" 2>&1 ) &
  PW=$!; pids+=($PW); sleep 6
  G5=0
  timeout 120 "$BIN" send "$SMALL" --server "$SERVER" >"$WORK/g5-send.log" 2>&1 || G5=1
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
  timeout 240 "$BIN" recv -y --dir "$D" --server "$SERVER" >"$WORK/g6-recv.log" 2>&1 &
  R=$!; pids+=($R); sleep 2
  G6=0
  ( cd "$HERE" && timeout 200 node browser-sender.js "$SERVER/" "$FA" "$FB" >"$WORK/g6-pw.log" 2>&1 ) || G6=1
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
USER=bob "$BIN" recv -y --dir "$DB" --server "$SERVER" >"$WORK/g7-bob.log" 2>&1 &
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
kill_8078() { # the gate-10 backend (werkzeug reloader forks; kill by port)
  for pid in $(ss -tlnp 2>/dev/null | grep :8078 | grep -oP 'pid=\K[0-9]+' | sort -u); do
    kill "$pid" 2>/dev/null
  done
}

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

# ---------------------------------------------------------------- summary ---
printf '\n\033[1m%d passed, %d failed%s\033[0m\n' "$PASS" "$FAIL" "${FAILED_GATES:+ —$FAILED_GATES}"
echo "artifacts: $WORK"
[ $FAIL -eq 0 ]
