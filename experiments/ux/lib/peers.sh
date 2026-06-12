#!/usr/bin/env bash
# peers.sh — stand up / tear down REAL local filament peers for the e2e pipeline.
#
# CORE PRINCIPLE: these are GENUINE filament peers, not mocks. We use the
# LOCALLY-BUILT binary (cli/target/release/filament — built if missing), each
# with its OWN isolated FILAMENT_CONFIG_DIR under $PIPE_TMP, all signaling through
# a local backend we start on a free port. The CLI peer *is* a real peer; the
# browser pairs with it for real (see pairing.sh).
#
# HARD SAFETY (mirrors rig/lib.sh):
#  - Never touch the user's ~/.config/filament. Every filament call sets
#    FILAMENT_CONFIG_DIR under $PIPE_TMP.
#  - Never kill a process we did not start. We track our own PIDs and stamp every
#    backend with FIL_UX_RIG=1; cleanup matches only that marker + tracked PIDs.
#  - We never touch the installed ~/.local/bin/filament, the user's `up --shell`
#    daemon, the gallery server, or another agent's rig.
set -uo pipefail
: "${ZSH_VERSION:=}"

PEERS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UX_ROOT="$(cd "$PEERS_LIB_DIR/.." && pwd)"
REPO_ROOT="$(cd "$UX_ROOT/../.." && pwd)"

# The LOCALLY-BUILT binary (never the installed one). Override with FILAMENT_BIN.
# When provided externally it is trusted as-is (FILAMENT_BIN_EXPLICIT); otherwise
# pipe_ensure_binary rebuilds it WITH the test-hooks feature.
FILAMENT_BIN_EXPLICIT="${FILAMENT_BIN:+1}"
FILAMENT_BIN="${FILAMENT_BIN:-$REPO_ROOT/cli/target/release/filament}"

# A python that can run the signaling backend (flask-socketio + eventlet). Prefer
# an explicit PIPE_VENV; else the runner's venv; else a system python that imports
# the deps; else build a repo-local venv on first use.
pipe_ensure_py() {
  if [ -n "${PIPE_PY:-}" ] && [ -x "$PIPE_PY" ]; then return 0; fi
  if [ -n "${PIPE_VENV:-}" ] && [ -x "$PIPE_VENV/bin/python" ]; then PIPE_PY="$PIPE_VENV/bin/python"; return 0; fi
  if [ -x "$REPO_ROOT/runner/.venv/bin/python" ] && "$REPO_ROOT/runner/.venv/bin/python" -c "import flask_socketio, eventlet" >/dev/null 2>&1; then
    PIPE_PY="$REPO_ROOT/runner/.venv/bin/python"; return 0
  fi
  if python3 -c "import flask_socketio, eventlet" >/dev/null 2>&1; then PIPE_PY="$(command -v python3)"; return 0; fi
  local v="$UX_ROOT/.venv"
  if [ ! -x "$v/bin/python" ]; then
    echo "[peers] creating signaling venv at $v" >&2
    python3 -m venv "$v" && "$v/bin/pip" -q install --upgrade pip >/dev/null 2>&1
    "$v/bin/pip" -q install "flask>=3.0" "flask-cors>=4.0" "flask-socketio>=5.3" \
      "eventlet>=0.35" "python-socketio>=5" "websocket-client" >/dev/null 2>&1
  fi
  PIPE_PY="$v/bin/python"
}

# Scratch roots (the case runner overrides these per case for isolation).
PIPE_TMP="${PIPE_TMP:-/tmp/ux-pipeline}"   # throwaway FILAMENT_CONFIG_DIRs
PIPE_WORK="${PIPE_WORK:-$UX_ROOT/.pipe}"   # logs / payloads / videos
mkdir -p "$PIPE_TMP" "$PIPE_WORK"

export FIL_UX_RIG=1   # marker stamped on every backend we start

# ---- ports -----------------------------------------------------------------
PIPE_PORT_FORBIDDEN=" 5000 5077 5180 5181 8061 8077 8095 "
pipe_free_port() {
  local p="${1:-8200}"
  while :; do
    case "$PIPE_PORT_FORBIDDEN" in *" $p "*) p=$((p+1)); continue;; esac
    if ! ( exec 3<>"/dev/tcp/127.0.0.1/$p" ) 2>/dev/null; then echo "$p"; return 0; fi
    p=$((p+1))
  done
}

# ---- pid tracking ----------------------------------------------------------
declare -a PIPE_PIDS=()
pipe_track() { PIPE_PIDS+=("$1"); }
pipe_kill_tracked() {
  local p
  for p in "${PIPE_PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  # reap any filament peer that carries one of OUR config dirs under PIPE_TMP
  for p in $(pgrep -f "$FILAMENT_BIN" 2>/dev/null); do
    tr '\0' ' ' < "/proc/$p/environ" 2>/dev/null | grep -q "FILAMENT_CONFIG_DIR=$PIPE_TMP" && kill "$p" 2>/dev/null
  done
  PIPE_PIDS=()
}

# Reap ONLY backends we started (FIL_UX_RIG=1). Safe at suite end.
pipe_reap_backends() {
  local p
  for p in $(pgrep -f "app.py" 2>/dev/null); do
    tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -qx "FIL_UX_RIG=1" \
      && tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -qx "FIL_PIPELINE=1" \
      && kill "$p" 2>/dev/null
  done
}

# ---- ensure the built binary exists ----------------------------------------
# The UX journeys drive env-gated test hooks (FILAMENT_TEST_FREEZE_AFTER_BYTES,
# FILAMENT_DIRECT_LOOPBACK_ONLY), which now ship ONLY in a `--features test-hooks`
# build (stripped from default/release). Build WITH the feature; if an explicit
# FILAMENT_BIN was provided, trust it as-is.
pipe_ensure_binary() {
  if [ -n "${FILAMENT_BIN_EXPLICIT:-}" ] && [ -x "$FILAMENT_BIN" ]; then return 0; fi
  echo "[peers] building filament (cargo build --release --features test-hooks)…" >&2
  ( cd "$REPO_ROOT/cli" && cargo build --release --features test-hooks >"$PIPE_WORK/cargo-build.log" 2>&1 ) || {
    echo "[peers] cargo build FAILED — see $PIPE_WORK/cargo-build.log" >&2; return 1; }
  [ -x "$FILAMENT_BIN" ]
}

# ---- a fresh isolated config dir for a peer --------------------------------
# pipe_cfg <name> -> echoes the path
pipe_cfg() { local d="$PIPE_TMP/$1"; rm -rf "$d"; mkdir -p "$d"; echo "$d"; }

# ---- local signaling backend ----------------------------------------------
# pipe_backend_start -> sets PIPE_PORT / PIPE_SERVER, returns 0 on health.
PIPE_BACKEND_PID=""
pipe_backend_start() {
  pipe_ensure_py
  PIPE_PORT="${PIPE_PORT:-$(pipe_free_port 8200)}"
  PIPE_SERVER="http://127.0.0.1:$PIPE_PORT"
  if curl -fsS "$PIPE_SERVER/api/health" >/dev/null 2>&1; then return 0; fi
  local attempt
  for attempt in 1 2 3; do
    echo "[peers] starting local signaling backend on $PIPE_PORT (try $attempt)" >&2
    ( cd "$REPO_ROOT/backend" && PORT="$PIPE_PORT" FIL_UX_RIG=1 FIL_PIPELINE=1 \
        FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 FIL_CLAIM_LIMIT=1000000 \
        FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
        "$PIPE_PY" app.py >"$PIPE_WORK/backend-$PIPE_PORT.log" 2>&1 ) &
    PIPE_BACKEND_PID=$!
    local i
    for i in $(seq 1 160); do
      curl -fsS "$PIPE_SERVER/api/health" >/dev/null 2>&1 && return 0
      kill -0 "$PIPE_BACKEND_PID" 2>/dev/null || break
      sleep 0.25
    done
    kill -9 "$PIPE_BACKEND_PID" 2>/dev/null; PIPE_BACKEND_PID=""
    PIPE_PORT="$(pipe_free_port "$((PIPE_PORT + 1))")"; PIPE_SERVER="http://127.0.0.1:$PIPE_PORT"
  done
  echo "[peers] backend failed; last log:" >&2; tail -20 "$PIPE_WORK/backend-$PIPE_PORT.log" >&2
  return 1
}
pipe_backend_stop() { [ -n "$PIPE_BACKEND_PID" ] && kill "$PIPE_BACKEND_PID" 2>/dev/null; PIPE_BACKEND_PID=""; }

# ---- same-origin frontend (real app, served by our backend) ----------------
# Builds frontend/dist with VITE_FILAMENT_API= (empty => same-origin signaling)
# if it is missing or points at the prod API. The REAL built app, no mock seam.
pipe_ensure_frontend() {
  local dist="$REPO_ROOT/frontend/dist/index.html"
  if [ -f "$dist" ] && ! grep -ql "api.filament.autumated.com" "$REPO_ROOT"/frontend/dist/assets/*.js 2>/dev/null; then
    return 0
  fi
  echo "[peers] (re)building frontend same-origin…" >&2
  ( cd "$REPO_ROOT/frontend" && VITE_FILAMENT_API= npm run build >"$PIPE_WORK/frontbuild.log" 2>&1 ) || {
    echo "[peers] frontend build FAILED — see $PIPE_WORK/frontbuild.log" >&2; return 1; }
}

# ---- helpers ---------------------------------------------------------------
pipe_hashof() { sha256sum "$1" | cut -d' ' -f1; }
pipe_wait_log() {  # <file> <regex> [timeout_s=20] [poll_s=0.2]
  local f="$1" re="$2" to="${3:-20}" poll="${4:-0.2}" deadline
  deadline=$(( $(date +%s) + to ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    grep -qE "$re" "$f" 2>/dev/null && return 0
    sleep "$poll"
  done
  return 1
}
