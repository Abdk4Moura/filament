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

# Unique env marker stamped on EVERY backend this harness starts. Cleanup matches
# ONLY procs carrying it, so we never touch the user's daemon, the gallery server
# on 8095, the dev servers on 5180/5181, or another agent's rig (FIL_BUGFIX_RIG).
UX_MARKER="${UX_MARKER:-FIL_UX_RIG=1}"
export FIL_UX_RIG=1

# A free TCP port at/above $1 (default 8071), skipping ports another tenant owns.
# Avoids 5000/5077/5180/5181/8061/8077/8095 etc. (the user's + other agents').
UX_PORT_FORBIDDEN=" 5000 5077 5180 5181 8061 8077 8095 "
ux_free_port() {
  local p="${1:-8071}"
  while :; do
    case "$UX_PORT_FORBIDDEN" in *" $p "*) p=$((p+1)); continue;; esac
    # Probe in a SUBSHELL so no stray fd leaks into the caller. A successful
    # connect means the port is taken; a failed connect means it's free.
    if ! ( exec 3<>"/dev/tcp/127.0.0.1/$p" ) 2>/dev/null; then echo "$p"; return 0; fi
    p=$((p+1))
  done
}

# Port for THIS rig: caller may pin UX_PORT (parallel runner gives each scenario
# its own); otherwise grab a free one off the base. Default base moved off 8077
# (a leftover prior-run backend lives there) to 8071.
UX_PORT="${UX_PORT:-$(ux_free_port 8071)}"
UX_SERVER="http://127.0.0.1:$UX_PORT"
UX_TMP="${UX_TMP:-/tmp/ux}"          # all throwaway config dirs live here
UX_WORK="${UX_WORK:-$UX_DIR/.work}"  # logs/payloads for this run

mkdir -p "$UX_TMP" "$UX_WORK"

# ---- SPEED knob ------------------------------------------------------------
# Render speed is a tunable. SPEED selects a profile of agg --speed + asciinema
# --idle-time-limit; raw overrides (AGG_SPEED / IDLE_LIMIT) win; a scenario can
# request its own pace per-recording (see ux_speed / agg_speed in record.sh).
#   SPEED=normal  speed 1.3  idle 1.4   (default)
#   SPEED=fast    speed 2.5  idle 0.8
#   SPEED=slow    speed 1.0  idle 2.0
SPEED="${SPEED:-normal}"
case "$SPEED" in
  fast)   _UX_SPEED_DEF=2.5; _UX_IDLE_DEF=0.8 ;;
  slow)   _UX_SPEED_DEF=1.0; _UX_IDLE_DEF=2.0 ;;
  normal|*) _UX_SPEED_DEF=1.3; _UX_IDLE_DEF=1.4 ;;
esac
# Effective values (raw env override beats the profile).
UX_AGG_SPEED="${AGG_SPEED:-$_UX_SPEED_DEF}"
UX_IDLE_LIMIT="${IDLE_LIMIT:-$_UX_IDLE_DEF}"

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
  # The eventlet backend can occasionally wedge at boot under heavy concurrent
  # CPU load (sibling agg/ffmpeg/chromium starve its greenlet loop, so /api/health
  # never answers). Try a few times: each attempt boots on a FRESH free port and
  # waits generously; a stuck attempt is killed before the next.
  local attempt
  for attempt in 1 2 3; do
    echo "[rig] starting backend on $UX_PORT (attempt $attempt)"
    ( cd "$REPO/backend" && PORT="$UX_PORT" FIL_UX_RIG=1 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
        FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
        "$PYV" app.py >"$UX_WORK/backend-$UX_PORT.log" 2>&1 ) &
    UX_BACKEND_PID=$!
    # wait up to ~40s for health (generous: boot is slow under load)
    local i
    for i in $(seq 1 160); do
      curl -fsS "$UX_SERVER/api/health" >/dev/null 2>&1 && return 0
      kill -0 "$UX_BACKEND_PID" 2>/dev/null || break   # it died — retry
      sleep 0.25
    done
    echo "[rig] backend on $UX_PORT did not become healthy — killing + retrying"
    kill -9 "$UX_BACKEND_PID" 2>/dev/null; UX_BACKEND_PID=""
    UX_PORT="$(ux_free_port "$((UX_PORT + 1))")"; UX_SERVER="http://127.0.0.1:$UX_PORT"
  done
  echo "[rig] backend failed after retries"; cat "$UX_WORK/backend-$UX_PORT.log" 2>/dev/null
  return 1
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

# SUITE-WIDE safety net: reap any backend WE started (carrying FIL_UX_RIG=1) that
# outlived its worker shell. Matches ONLY our marker, so the user's daemon, the
# gallery server on 8095, the leftover 8077 backend, and another agent's
# FIL_BUGFIX_RIG are spared.
#
# DANGER: this kills ALL marked backends, including sibling scenarios' backends
# that are still in use. It must therefore run ONLY at the very END of the suite
# (top-level run.sh), NEVER inside a concurrent per-scenario worker — otherwise
# one finishing scenario would tear down another's live backend.
reap_marked_backends() {
  for p in $(pgrep -f "app.py" 2>/dev/null); do
    tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -qx "FIL_UX_RIG=1" && kill "$p" 2>/dev/null
  done
}

# Per-scenario teardown: kill ONLY this rig's own children + its own backend
# (tracked PIDs). Does NOT touch sibling rigs' marked backends.
cleanup_all() {
  kill_ours
  backend_stop
}

# A throwaway config dir with a name pre-seeded (helper for direct-store rigs).
fresh_cfg() { local name="$1"; local d="$UX_TMP/$name"; rm -rf "$d"; mkdir -p "$d"; echo "$d"; }

# Seed a devices.json store directly.
#
# DEPRECATED for anything that claims to test a user-facing flow. Writing the
# record ourselves asserts that we know the on-disk shape `add` produces, which
# is the assumption most likely to rot: the store gained an issuer fingerprint,
# packed capability fields and an expiry between 0.8.2 and 0.8.4, and a seeded
# scenario keeps passing across every one of those changes without ever
# exercising the code that writes them. Use pair_two below. seed_store stays only
# for negative cases that need a store no ceremony can legitimately produce
# (revoked, expired, corrupt).
# usage: seed_store <cfgdir> <json-array-string>
seed_store() { printf '%s\n' "$2" > "$1/devices.json"; chmod 600 "$1/devices.json"; }

# Poll a logfile for a minted 4-segment code. Defined here as well as in
# scenarios.sh so pair_two does not depend on its caller having defined it.
wait_code() { local f="$1" n=0 c=""; while [ $n -lt 80 ]; do
  c=$(grep -oE '[A-Za-z]+-[A-Za-z]+-[A-Za-z]+-[0-9]+' "$f" 2>/dev/null | head -1 | tr 'A-Z' 'a-z')
  [ -n "$c" ] && { echo "$c"; return 0; }; n=$((n+1)); sleep 0.2; done; return 1; }

# Pair two config dirs the way a person does: one side mints a code, the other
# claims it. No secrets are invented here and nothing is written by hand; both
# stores end up holding whatever the shipping ceremony actually writes.
#
#   pair_two <cfgA> <A-calls-B> <cfgB> <B-calls-A>   → 0 on success
#
# Both sides run to completion before returning, so a caller can immediately
# use `send --to <name>`.
pair_two() {
  local DA="$1" NB="$2" DB="$3" NA="$4"
  local log="$UX_WORK/pair-$(basename "$DA")-$(basename "$DB")"
  FILAMENT_CONFIG_DIR="$DA" timeout -k 5 45 "$FILAMENT" add --name "$NB" -y \
      --server "$UX_SERVER" </dev/null >"$log.a" 2>&1 &
  local PA=$!; track $PA
  local C
  C=$(wait_code "$log.a") || { echo "pair_two: $DA never minted a code" >&2; kill $PA 2>/dev/null; return 1; }
  FILAMENT_CONFIG_DIR="$DB" timeout -k 5 45 "$FILAMENT" add "$C" --name "$NA" -y \
      --server "$UX_SERVER" </dev/null >"$log.b" 2>&1
  local rcB=$?
  wait $PA 2>/dev/null; local rcA=$?
  # Assert on the stores, not on exit codes: the pairing is only real if each
  # side can now name the other.
  FILAMENT_CONFIG_DIR="$DA" "$FILAMENT" devices 2>/dev/null | grep -q "$NB" || {
    echo "pair_two: $DA does not list $NB (rcA=$rcA rcB=$rcB)" >&2; return 1; }
  FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" devices 2>/dev/null | grep -q "$NA" || {
    echo "pair_two: $DB does not list $NA (rcA=$rcA rcB=$rcB)" >&2; return 1; }
  return 0
}

# A 32-byte hex pair secret.
mk_secret() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

hashof() { sha256sum "$1" | cut -d' ' -f1; }

# ---- event waits (replace blind sleeps) ------------------------------------
# Poll a shell condition until it succeeds or a deadline passes.
#   wait_for <timeout_s> <poll_s> <cmd...>   → 0 if cmd ever succeeds, else 1
wait_for() {
  local timeout="$1" poll="$2"; shift 2
  local deadline=$(( $(date +%s) + timeout ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    "$@" >/dev/null 2>&1 && return 0
    sleep "$poll"
  done
  return 1
}

# Wait until a regex appears in a (possibly still-growing) logfile.
#   wait_log <file> <regex> [timeout_s=20] [poll_s=0.2]
wait_log() {
  local f="$1" re="$2" timeout="${3:-20}" poll="${4:-0.2}"
  wait_for "$timeout" "$poll" bash -c 'grep -qE "$2" "$1" 2>/dev/null' _ "$f" "$re"
}
