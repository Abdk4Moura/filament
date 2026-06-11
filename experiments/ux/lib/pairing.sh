#!/usr/bin/env bash
# pairing.sh — REAL pairing helpers. A genuine CLI peer mints a PAKE code; the
# browser (Playwright) types it into the real pair box. The CLI side is a real
# filament peer using the locally-built binary + an isolated config dir.
#
# These return the minted CODE on stdout (other diagnostics go to stderr/logs) so
# a case can: code=$(pipe_mint_code <cfg> <name>); then hand it to the browser.
set -uo pipefail
: "${ZSH_VERSION:=}"

# Extract a 4-segment pair code (word-word-word-NN) from a log/stream.
_pipe_grep_code() {
  grep -oE '[A-Za-z]+-[A-Za-z]+-[A-Za-z]+-[0-9]+' "$1" 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]'
}

# pipe_mint_code <cfgdir> <name> <logfile>  -> echoes the code; starts `pair`
# minting in the BACKGROUND (it blocks until the browser claims it). The pair
# PID is tracked for teardown; the caller drives the browser, then waits.
# Returns the PID via the global PIPE_LAST_PAIR_PID.
PIPE_LAST_PAIR_PID=""
pipe_mint_code() {
  local cfg="$1" name="$2" log="$3"
  : > "$log"
  FILAMENT_CONFIG_DIR="$cfg" timeout -k 5 120 "$FILAMENT_BIN" pair --name "$name" \
    --name-as "$name" --server "$PIPE_SERVER" >"$log" 2>&1 &
  PIPE_LAST_PAIR_PID=$!
  pipe_track "$PIPE_LAST_PAIR_PID"
  # poll the log until the 4-segment code is printed
  local code="" i
  for i in $(seq 1 80); do
    code=$(_pipe_grep_code "$log")
    [ -n "$code" ] && break
    kill -0 "$PIPE_LAST_PAIR_PID" 2>/dev/null || break
    sleep 0.25
  done
  echo "$code"
}

# pipe_seed_store <cfgdir> <json-array>  — write a real-shaped devices.json so an
# `up` daemon has a known device and stays alive (it refuses to start with none).
# A device the browser pairs in LATER is picked up live by the running daemon
# (the ~2s store rescan — the proven live-pairing path, see scenario 11).
pipe_seed_store() { printf '%s\n' "$2" > "$1/devices.json"; chmod 600 "$1/devices.json"; }
pipe_mk_secret() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# pipe_start_shell_peer <cfgdir> <name> <logfile> [extra up args...]
# Brings up a REAL `up --shell` peer (advertises a terminal). The store is seeded
# with one throwaway device so the daemon stays up; the browser pairs in live.
# Returns 0 once the ready banner is seen.
pipe_start_shell_peer() {
  local cfg="$1" name="$2" log="$3"; shift 3
  : > "$log"
  [ -f "$cfg/devices.json" ] || pipe_seed_store "$cfg" "[{\"name\":\"seed\",\"secret\":\"$(pipe_mk_secret)\"}]"
  FILAMENT_CONFIG_DIR="$cfg" "$FILAMENT_BIN" up --shell --name-as "$name" \
    --server "$PIPE_SERVER" "$@" </dev/null >"$log" 2>&1 &
  local pid=$!; pipe_track "$pid"
  PIPE_LAST_UP_PID="$pid"
  pipe_wait_log "$log" 'filament up —|known device|listening|ready' 20 0.2
}

# pipe_start_up_peer <cfgdir> <name> <dropdir> <logfile> [extra up args...]
# A plain always-on `up` (drop target), used by pair→device + transfer flows.
pipe_start_up_peer() {
  local cfg="$1" name="$2" dir="$3" log="$4"; shift 4
  mkdir -p "$dir"; : > "$log"
  FILAMENT_CONFIG_DIR="$cfg" "$FILAMENT_BIN" up --dir "$dir" --name-as "$name" \
    --server "$PIPE_SERVER" "$@" </dev/null >"$log" 2>&1 &
  local pid=$!; pipe_track "$pid"
  PIPE_LAST_UP_PID="$pid"
  pipe_wait_log "$log" 'filament up —|listening|ready' 20 0.2
}
