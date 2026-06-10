#!/usr/bin/env bash
# Record ONE scenario as an asciinema cast and render a GIF.
#   ./record.sh <id> [cols] [rows]
# Writes:  casts/<id>.cast  gallery/<id>.gif   and appends a RESULT line to
#          .work/results-<id>.txt (parsed by run.sh).
set -uo pipefail
: "${ZSH_VERSION:=}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/rig/lib.sh"
ID="$1"; COLS="${2:-100}"; ROWS="${3:-30}"
CAST="$HERE/casts/$ID.cast"
GIF="$HERE/gallery/$ID.gif"
RES="$UX_WORK/results-$ID.txt"
mkdir -p "$HERE/casts" "$HERE/gallery"

# ---- per-scenario render speed --------------------------------------------
# Base values come from the SPEED profile / raw override (resolved in lib.sh as
# UX_AGG_SPEED + UX_IDLE_LIMIT). A scenario may slow down a key moment by setting
# SCENARIO_SPEED_<id> / SCENARIO_IDLE_<id> (e.g. SCENARIO_SPEED_01=1.0 to dwell
# on the pairing handshake). Per-scenario beats profile; raw env still wins.
ps_var() { local v="$1"; echo "${!v:-}"; }
AGG_SPEED_EFF="$(ps_var "SCENARIO_SPEED_$ID")"; [ -n "$AGG_SPEED_EFF" ] || AGG_SPEED_EFF="$UX_AGG_SPEED"
IDLE_EFF="$(ps_var "SCENARIO_IDLE_$ID")";       [ -n "$IDLE_EFF" ]      || IDLE_EFF="$UX_IDLE_LIMIT"
[ -n "${AGG_SPEED:-}" ] && AGG_SPEED_EFF="$AGG_SPEED"   # raw override always wins
[ -n "${IDLE_LIMIT:-}" ] && IDLE_EFF="$IDLE_LIMIT"

# Scenarios that DECOUPLE the verdict from the recording. The single-host
# CLI<->CLI word-code transfer (03) and the ssh-over-tunnel handshake (06) are
# GREEN standalone but wedge reliably under asciinema recorder load (the same
# recording-contention class as web scenario 09). For these, get the
# AUTHORITATIVE verdict from a no-recorder verify pass, then record a time-boxed
# BEST-EFFORT cast purely for the illustrative GIF.
DECOUPLE_IDS=" 03 06 "

VERIFY_RES=""
if [[ "$DECOUPLE_IDS" == *" $ID "* ]]; then
  # (1) authoritative verify pass — NO recorder.
  bash "$HERE/scenarios.sh" "$ID" >"$UX_WORK/verify-$ID.log" 2>&1 || true
  VERIFY_RES=$(grep -h "^RESULT $ID " "$UX_WORK/verify-$ID.log" 2>/dev/null | tail -1)
  echo "[record] $ID verify pass: ${VERIFY_RES:-<none>}"
fi

# Record the cast (best-effort for decoupled scenarios, authoritative otherwise).
# Bound the recorded run so a recorder-induced wedge can't hang the suite. For
# decoupled scenarios the GIF is illustrative, so a short box is enough.
CAST_TIMEOUT=120; [ -n "$VERIFY_RES" ] && CAST_TIMEOUT=22
# -k forces SIGKILL 5s after SIGTERM in case asciinema waits on a wedged child
# (the ssh/transfer retry loops can otherwise outlive a plain SIGTERM).
timeout -k 5 "$CAST_TIMEOUT" "$UX_BIN/asciinema" rec -f asciicast-v2 --idle-time-limit "$IDLE_EFF" -q --overwrite \
  --cols "$COLS" --rows "$ROWS" \
  -c "bash '$HERE/scenarios.sh' '$ID'" "$CAST" >/dev/null 2>&1 || true
# kill any children the boxed (possibly-wedged) recorded run left behind:
# our filament procs (matched by cfg dir) AND scenario 06's throwaway sshd.
for p in $(pgrep -f "$FILAMENT" 2>/dev/null); do
  tr '\0' '\n' < /proc/$p/environ 2>/dev/null | grep -q "FILAMENT_CONFIG_DIR=$UX_TMP/s${ID}" && kill -9 "$p" 2>/dev/null
done
for p in $(pgrep -f "sshd_config" 2>/dev/null); do
  tr '\0' '\n' < /proc/$p/cmdline 2>/dev/null | grep -q "$UX_TMP/s${ID}" && kill -9 "$p" 2>/dev/null
done

# extract the RESULT line from the recorded output (strip ansi + cast json)
"$UX_BIN/agg" --cols "$COLS" --rows "$ROWS" --font-size 16 --speed "$AGG_SPEED_EFF" \
  --theme asciinema "$CAST" "$GIF" >/dev/null 2>&1 || echo "[record] agg failed for $ID" >&2

# pull RESULT out of the cast (it's embedded as terminal output)
CAST_RES=$(python3 - "$CAST" "$ID" <<'PY'
import json,sys,re
cast,idn=sys.argv[1],sys.argv[2]
out=[]
try:
  for i,line in enumerate(open(cast)):
    if i==0: continue
    try: ev=json.loads(line)
    except Exception: continue
    if len(ev)>=3 and ev[1]=="o": out.append(ev[2])
except Exception: pass
text=re.sub(r'\x1b\[[0-9;]*m','',''.join(out))
m=None
for L in text.splitlines():
    if L.startswith(f"RESULT {idn} "): m=L
print(m or "")
PY
)

# For decoupled scenarios the verify pass is authoritative; the cast is just the
# GIF. Otherwise the cast's RESULT line is the verdict.
if [ -n "$VERIFY_RES" ]; then
  echo "$VERIFY_RES" > "$RES"
elif [ -n "$CAST_RES" ]; then
  echo "$CAST_RES" > "$RES"
else
  echo "RESULT $ID FAIL no-result-line" > "$RES"
fi
cat "$RES"
