#!/usr/bin/env bash
# GATE 6 (downgrade-refused): with both sides v2, a server that STRIPS the v:2
# flag (FIL_FORCE_V1) cannot force the legacy readable-secret path. A v2 client
# gets a legacy `pair-code` instead of `pair-ok` and ABORTS with a clear
# "update to pair securely" message — storing NOTHING.
#
# Part A (runtime): v2 creator vs a v:2-stripping server → refuse, no store.
# Part B (structural): the v2 pair_cmd never SENDS a pair-keep and its pair-keep
#         receive arm is a bail! — so no v2 code path stores a server-readable
#         secret. Together: the server can only DoS, never downgrade auth.
set -uo pipefail
BIN=/root/wt-l1a/cli/target/release/filament
T=/root/.claude/jobs/330c2366/tmp/wt-l1a-gates
PY=/root/.claude/jobs/330c2366/tmp/venv/bin/python
MAIN=/root/wt-l1a/cli/src/main.rs
rm -rf "$T/g6"; mkdir -p "$T/g6/cfg"

# Stop our own 8093 listener and restart it with the v2-stripping flag.
for pid in $(ss -tlnp 2>/dev/null | grep ":8093 " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd /root/wt-l1a/backend && PORT=8093 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_FORCE_V1=1 nohup "$PY" app.py >"$T/g6/backend-forcev1.log" 2>&1 & )
for i in $(seq 1 20); do curl -s http://127.0.0.1:8093/api/config >/dev/null 2>&1 && break; sleep 0.3; done

# A v2 creator against the stripping server.
FILAMENT_CONFIG_DIR=$T/g6/cfg FILAMENT_PAIR_GRACE_SECS=10 \
  "$BIN" --server http://127.0.0.1:8093 pair --name v </dev/null >"$T/g6/creator.log" 2>&1 &
CRE=$!
for i in $(seq 1 30); do kill -0 $CRE 2>/dev/null || break; sleep 0.3; done
wait $CRE 2>/dev/null
RC=$?

echo "--- creator log ---"; cat "$T/g6/creator.log"
REFUSED=$(grep -ciE 'pair securely|legacy|update' "$T/g6/creator.log")
STORED=$(cat "$T/g6/cfg/devices.json" 2>/dev/null | grep -c '"secret"')
echo "creator exit code     : $RC (want nonzero)"
echo "refused w/ message    : $REFUSED (want >=1)"
echo "secret stored         : $STORED (want 0)"

# Restore the normal 8093 backend for the remaining gates.
for pid in $(ss -tlnp 2>/dev/null | grep ":8093 " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd /root/wt-l1a/backend && PORT=8093 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 nohup "$PY" app.py >"$T/backend-8093.log" 2>&1 & )
for i in $(seq 1 20); do curl -s http://127.0.0.1:8093/api/config >/dev/null 2>&1 && break; sleep 0.3; done

# Part B: structural assertions on the v2 pair_cmd.
# 1) v2 ceremony never SENDS a pair-keep (no secret over the DataChannel).
KEEP_SENDS=$(awk '/^async fn pair_cmd/,/^}/' "$MAIN" | grep -c 'send_control.*pair-keep')
# 2) the pair-keep RECEIVE arm bails (refuses) — no store.
KEEP_BAILS=$(awk '/^async fn pair_cmd/,/^}/' "$MAIN" | grep -A2 '"pair-keep")' | grep -c 'bail!')
echo "v2 pair-keep sends    : $KEEP_SENDS (want 0)"
echo "v2 pair-keep bails    : $KEEP_BAILS (want >=1)"

if [ "$REFUSED" -ge 1 ] && [ "$STORED" = "0" ] && [ "$RC" -ne 0 ] && [ "$KEEP_SENDS" = "0" ] && [ "$KEEP_BAILS" -ge 1 ]; then
  echo "GATE6 PASS: v2-stripping server is refused; no v2 path stores a server-readable secret"
  exit 0
fi
echo "GATE6 FAIL"; exit 1
