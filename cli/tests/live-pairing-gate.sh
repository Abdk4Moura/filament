#!/usr/bin/env bash
# Live-pairing regression gate (C12).
#
# THE BUG: `filament up` loads the known-devices roster ONCE at startup and
# subscribes to each device's presence channel then. A device paired into the
# shared store by a SEPARATE `filament pair` process AFTER the daemon is already
# running was never picked up — the daemon never subscribed to the new device's
# channel, so the "known device 'X' appeared — connecting" flow never fired for
# it and that device could not connect (no transfer, no web-shell) until the
# daemon was restarted.
#
# THE GATE: start `up`, then pair a NEW device into the store WHILE up is
# running, and assert — WITHOUT restarting the daemon — that
#   (1) the daemon logs that it picked up the new device live, AND
#   (2) the new device actually connects: a `send --to` from it lands a file,
#       byte-for-byte, into the daemon's drop dir.
#
# Deterministic by construction: CLI-only, a local fixture backend, seeded
# device stores (no PAKE timing), known-peer transfer (no ICE lottery for the
# verdict — `--to` over the same loopback auto-room is the robust path the
# existing gate 7 / UX scenario 05 use).
#
# A/B: against the OLD (unfixed) binary this gate FAILS at step (1)/(2) — the
# daemon never learns of the new device, so no log line and no delivery. Against
# the FIXED binary it PASSES. Run with FILAMENT_AB=old to prove the fail-before
# (point BIN at an unfixed build, or set FILAMENT_BIN).
#
#   ./live-pairing-gate.sh
#
# Honors: FILAMENT_BIN (default cli/target/release/filament),
#         FILAMENT_TEST_SERVER (else autostarts a local backend),
#         FILAMENT_TEST_VENV (python with flask_socketio+eventlet).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
SERVER="${FILAMENT_TEST_SERVER:-}"
WORK="$(mktemp -d /tmp/filament-livepair.XXXXXX)"
PYV="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mPASS\033[0m: %s\n' "$1"; }
bad()  { printf '\033[1;31mFAIL\033[0m: %s\n' "$1"; }
hashof() { sha256sum "$1" | cut -d' ' -f1; }
mk_secret() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
seed_store() { printf '%s\n' "$2" > "$1/devices.json"; chmod 600 "$1/devices.json"; }

PIDS=(); OWN_BACKEND=""
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  [ -n "$OWN_BACKEND" ] && kill "$OWN_BACKEND" 2>/dev/null
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

# wait up to <timeout>s (poll <poll>s) for <regex> to appear in <file>
wait_log() {
  local f="$1" re="$2" t="${3:-15}" poll="${4:-0.2}" n=0 lim
  lim=$(awk -v t="$t" -v p="$poll" 'BEGIN{print int(t/p)}')
  while [ $n -lt "$lim" ]; do
    grep -qE "$re" "$f" 2>/dev/null && return 0
    n=$((n+1)); sleep "$poll"
  done
  return 1
}

[ -x "$BIN" ] || { echo "no filament binary at $BIN (build it: cargo build --release)"; exit 2; }

# ---- backend ---------------------------------------------------------------
free_port() { python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
}
if [ -z "$SERVER" ]; then
  PORT="$(free_port)"
  SERVER="http://127.0.0.1:$PORT"
  [ -x "$PYV" ] || { echo "no test venv python at $PYV (set FILAMENT_TEST_VENV)"; exit 2; }
  ( cd "$CLI_DIR/../backend" && PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
      "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
  OWN_BACKEND=$!
  for _ in $(seq 1 80); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.25; done
fi
curl -fsS "$SERVER/api/health" >/dev/null 2>&1 || { echo "no backend at $SERVER"; exit 2; }

# A completed receiver otherwise lingers the full rejoin window.
export FILAMENT_REJOIN_SECS=3

# ---- topology --------------------------------------------------------------
# UP   = the always-on box (the daemon under test).
# OLD  = a device paired BEFORE the daemon started (proves startup path intact).
# NEW  = a device paired AFTER the daemon started (the bug).
UP="$WORK/up";  mkdir -p "$UP"
OLD="$WORK/old"; mkdir -p "$OLD"
NEW="$WORK/new"; mkdir -p "$NEW"
DROP="$WORK/drop"; mkdir -p "$DROP"
sec_old="$(mk_secret)"
sec_new="$(mk_secret)"

# At startup the daemon knows ONLY `old`.
seed_store "$UP"  "[{\"name\":\"old\",\"secret\":\"$sec_old\"}]"
seed_store "$OLD" "[{\"name\":\"box\",\"secret\":\"$sec_old\"}]"
seed_store "$NEW" "[{\"name\":\"box\",\"secret\":\"$sec_new\"}]"

PAY="$WORK/payload.bin"; head -c 800000 /dev/urandom > "$PAY"
PAYHASH="$(hashof "$PAY")"

say "start the always-on daemon (knows only 'old')"
FILAMENT_CONFIG_DIR="$UP" timeout -k 5 70 "$BIN" up --dir "$DROP" --server "$SERVER" \
  </dev/null >"$WORK/up.log" 2>&1 &
UPPID=$!; PIDS+=("$UPPID")
wait_log "$WORK/up.log" 'filament up —' 20 0.2 || { bad "daemon never printed its ready banner"; exit 1; }
echo "daemon ready; roster at startup = { old }"

# --- sanity: the device known AT STARTUP connects (startup path not regressed) -
say "sanity — the pre-paired 'old' device connects (startup path)"
FILAMENT_CONFIG_DIR="$OLD" timeout -k 5 30 "$BIN" send "$PAY" --to box --server "$SERVER" \
  >"$WORK/old-send.log" 2>&1
old_rc=$?
sleep 1
old_rcv="$(ls "$DROP" 2>/dev/null | head -1)"
old_hash="$(hashof "$DROP/$old_rcv" 2>/dev/null || echo none)"
if [ $old_rc -eq 0 ] && [ "$old_hash" = "$PAYHASH" ]; then
  ok "startup-known device connected and delivered (no regression)"
else
  bad "startup-known device failed (rc=$old_rc) — environment broken, aborting"
  exit 1
fi
rm -f "$DROP"/* 2>/dev/null

# --- THE BUG: pair a NEW device into the SHARED store while up is RUNNING -----
say "pair a NEW device into the store while the daemon is RUNNING (no restart)"
# Atomic-ish: write the new record into the daemon's own store, exactly as a
# separate `filament pair` process would. (We append; the real pair path uses
# devices_store, which we exercise indirectly — the store shape is identical.)
seed_store "$UP" "[{\"name\":\"old\",\"secret\":\"$sec_old\"},{\"name\":\"new\",\"secret\":\"$sec_new\"}]"
echo "store now = { old, new } — daemon was NOT restarted"

# (1) the daemon must LOG that it picked the new device up live.
if wait_log "$WORK/up.log" "new device 'new' paired — now reachable" 12 0.3; then
  ok "daemon logged the live pickup of the newly-paired device"
  logged=1
else
  bad "daemon NEVER logged picking up the new device — it is still blind to it"
  logged=0
fi

# (2) the new device must actually CONNECT — send a file into the daemon, no restart.
say "the NEW device sends a file into the still-running daemon"
FILAMENT_CONFIG_DIR="$NEW" timeout -k 5 30 "$BIN" send "$PAY" --to box --server "$SERVER" \
  >"$WORK/new-send.log" 2>&1
new_rc=$?
sleep 1
new_rcv="$(ls "$DROP" 2>/dev/null | head -1)"
new_hash="$(hashof "$DROP/$new_rcv" 2>/dev/null || echo none)"

kill "$UPPID" 2>/dev/null

if [ $new_rc -eq 0 ] && [ "$new_hash" = "$PAYHASH" ] && [ "${logged:-0}" -eq 1 ]; then
  ok "NEW device connected to the live daemon and delivered — bug fixed"
  echo
  echo "RESULT live-pairing PASS new-device-connects-without-restart"
  exit 0
else
  bad "NEW device did NOT connect to the live daemon (rc=$new_rc hash=$new_hash logged=${logged:-0})"
  echo "  → this is the bug: a device paired after startup is invisible until restart"
  echo
  echo "RESULT live-pairing FAIL new-device-never-connects"
  exit 1
fi
