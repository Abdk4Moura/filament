#!/usr/bin/env bash
# Self-safe rig primitives shared by the UX scenarios.
#
# HARD SAFETY RULES (see harness README):
#  - Never touch the user's real config (/root/.config/filament). Every filament
#    invocation in a scenario MUST set FILAMENT_CONFIG_DIR under $UX_ROOT/tmp.
#  - Never kill processes we did not start. We track our own PIDs in $UX_PIDS
#    and our own backend on $UX_PORT (a non-default port). We only kill a port
#    listener on $UX_PORT if WE are the ones who started it (recorded in
#    $UX_BACKEND_PID). The user's `filament up` daemon is a CLIENT (no listener),
#    so it is never matched.
set -uo pipefail
: "${ZSH_VERSION:=}"  # some interactive snapshots probe this under set -u

UX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UX_BIN="$UX_DIR/bin"
REPO="$(cd "$UX_DIR/../.." && pwd)"
FILAMENT="${FILAMENT_BIN:-/root/.local/bin/filament}"
PYV="${UX_PYV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"

UX_PORT="${UX_PORT:-8077}"
UX_SERVER="http://127.0.0.1:$UX_PORT"
UX_TMP="${UX_TMP:-/tmp/ux}"          # all throwaway config dirs live here
UX_WORK="${UX_WORK:-$UX_DIR/.work}"  # logs/payloads for this run

mkdir -p "$UX_TMP" "$UX_WORK"

UX_BACKEND_PID=""
declare -a UX_PIDS=()

# track a child we spawned
track() { UX_PIDS+=("$1"); }

backend_start() {
  # Reuse a backend WE started earlier in this run; otherwise spin one up.
  if [ -n "$UX_BACKEND_PID" ] && kill -0 "$UX_BACKEND_PID" 2>/dev/null; then return 0; fi
  # If something is already on the port and it answers health, reuse it.
  if curl -fsS "$UX_SERVER/api/health" >/dev/null 2>&1; then
    echo "[rig] reusing existing healthy backend on $UX_PORT"
    return 0
  fi
  echo "[rig] starting backend on $UX_PORT"
  ( cd "$REPO/backend" && PORT="$UX_PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
      "$PYV" app.py >"$UX_WORK/backend.log" 2>&1 ) &
  UX_BACKEND_PID=$!
  for _ in $(seq 1 40); do
    curl -fsS "$UX_SERVER/api/health" >/dev/null 2>&1 && break
    sleep 0.25
  done
  curl -fsS "$UX_SERVER/api/health" >/dev/null 2>&1 || { echo "[rig] backend failed"; cat "$UX_WORK/backend.log"; return 1; }
}

backend_stop() {
  [ -n "$UX_BACKEND_PID" ] && kill "$UX_BACKEND_PID" 2>/dev/null
  UX_BACKEND_PID=""
}

# Kill every child we tracked (and only those).
kill_ours() {
  for p in "${UX_PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  UX_PIDS=()
}

cleanup_all() {
  kill_ours
  backend_stop
}

# A throwaway config dir with a name pre-seeded (helper for direct-store rigs).
fresh_cfg() { local name="$1"; local d="$UX_TMP/$name"; rm -rf "$d"; mkdir -p "$d"; echo "$d"; }

# Seed a devices.json store directly (the gates' shortcut for known-device flows).
# usage: seed_store <cfgdir> <json-array-string>
seed_store() { printf '%s\n' "$2" > "$1/devices.json"; chmod 600 "$1/devices.json"; }

# A 32-byte hex pair secret.
mk_secret() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

hashof() { sha256sum "$1" | cut -d' ' -f1; }
