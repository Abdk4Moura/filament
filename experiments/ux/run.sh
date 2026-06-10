#!/usr/bin/env bash
# One command to run the whole UX suite: record every scenario (cli↔cli 01–07 as
# casts→GIFs, cli↔web 08–10 as side-by-side CLI+browser GIFs), build the gallery,
# and tear everything down.
#
#   ./run.sh                 run all 10 scenarios
#   ./run.sh 01 03 06        run a subset
#   SEQUENTIAL=1 ./run.sh    run one-at-a-time (debugging; old behaviour)
#   JOBS=3 ./run.sh          cap concurrency (default 4)
#   SPEED=fast ./run.sh      render faster (see README → SPEED knob)
#
# PARALLELISM: scenarios run CONCURRENTLY in ISOLATED rigs. Each scenario gets
#   - its own backend on its own FREE port (never 5000/5077/5180/5181/8061/8077/
#     8095 — the user's daemon, dev servers, gallery server, or another agent),
#   - its own throwaway config root  /tmp/ux/<id>,
#   - its own scratch/log dir        .work/<id>,
# so concurrent scenarios cannot interfere. A bounded job pool (JOBS, default 4)
# keeps load sane; wall-clock drops toward the slowest scenario.
#
# SAFETY: every filament call sets a throwaway FILAMENT_CONFIG_DIR under /tmp/ux;
# every backend we start carries the marker FIL_UX_RIG=1; teardown kills ONLY our
# tracked children and only backends carrying that marker. The user's real
# ~/.config/filament, their `filament up` daemon, the gallery server on 8095, and
# another agent's FIL_BUGFIX_RIG are never touched.
set -uo pipefail
: "${ZSH_VERSION:=}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# top-level rig (for shared work dir + the suite-wide cleanup of marked backends)
source "$HERE/rig/lib.sh"

ALL_CLI="01 02 03 04 05 06 07"
ALL_WEB="08 09 10"
SEL="${*:-$ALL_CLI $ALL_WEB}"
# Default concurrency scales to the box: single-host WebRTC/ssh ICE timing (03,
# 06, 08, 09) and eventlet backend boots get starved if we oversubscribe cores.
# Each scenario already uses ~2 cores (backend + two peers + a recorder), so cap
# at floor(nproc/2), clamped to 2..4. Override with JOBS=N.
_NPROC=$(nproc 2>/dev/null || echo 4); _DEFJOBS=$(( _NPROC / 2 ))
[ "$_DEFJOBS" -lt 2 ] && _DEFJOBS=2; [ "$_DEFJOBS" -gt 4 ] && _DEFJOBS=4
JOBS="${JOBS:-$_DEFJOBS}"
SEQUENTIAL="${SEQUENTIAL:-}"
# SOLO scenarios run ALONE, one at a time, after the parallel batch — each on a
# quiet host. These are the single-host ICE flows whose transfer/verify is
# contention-sensitive: 03 (word-code CLI↔CLI), 06 (ssh-over-tunnel), 08
# (CLI→browser WebRTC), 09 (browser→CLI WebRTC). On a small box their fragile
# ICE/data-channel timing wedges if other heavy scenarios share the cores, so we
# don't let them. Everything else (01 02 04 05 07 10) parallelizes freely.
SOLO_IDS="${SOLO_IDS:-03 06 08 09}"

echo "================ Filament UX harness ================"
echo "binary  : $FILAMENT"
echo "speed   : SPEED=$SPEED (agg --speed $UX_AGG_SPEED, idle $UX_IDLE_LIMIT)"
echo "mode    : ${SEQUENTIAL:+sequential}${SEQUENTIAL:-parallel (JOBS=$JOBS)}"
echo "tmp root: $UX_TMP   work root: $UX_WORK"
echo "scenarios: $SEL"
echo "====================================================="

SUITE_T0=$SECONDS

# Run ONE scenario in a fully isolated rig (own port + own tmp + own work dir).
# Writes its RESULT line to .work/results-<id>.txt and a timing to
# .work/time-<id>.txt. Self-cleans its backend on exit (own marker only).
run_one() {
  local id="$1" t0
  t0=$(date +%s)
  local stmp="$UX_TMP/$id" swork="$UX_WORK/$id"
  rm -rf "$stmp"; mkdir -p "$stmp" "$swork"
  # Isolated env for everything this scenario spawns. A FREE port per scenario
  # (base spaced out so the pool never collides), own tmp + work.
  # Per-id base with wide, non-overlapping windows so concurrent ux_free_port
  # calls never converge on the same port (id 01→8103, 02→8106, … 10→8130).
  local port; port=$(ux_free_port "$((8100 + 10#$id * 3))")
  (
    export UX_PORT="$port"
    export UX_TMP="$stmp"
    export UX_WORK="$swork"
    # bring up this scenario's own backend (carries FIL_UX_RIG=1)
    source "$HERE/rig/lib.sh"
    backend_start >>"$swork/rig.log" 2>&1 || { echo "RESULT $id FAIL backend"; exit 0; }
    case " $ALL_CLI " in
      *" $id "*) echo "--- recording cli↔cli $id (port $UX_PORT) ---"
                 bash "$HERE/record.sh" "$id" 100 28 >>"$swork/run.log" 2>&1 || true ;;
      *)         echo "--- recording cli↔web $id (port $UX_PORT) ---"
                 bash "$HERE/web-scenarios.sh" "$id" >>"$swork/run.log" 2>&1 || true ;;
    esac
    cleanup_all >>"$swork/rig.log" 2>&1
  )
  # The scenario writes results-<id>.txt into its OWN .work/<id>; lift it (and the
  # GIF/cast already land in the shared gallery/ and casts/) so gallery.py finds it.
  if [ -f "$swork/results-$id.txt" ]; then cp "$swork/results-$id.txt" "$UX_WORK/results-$id.txt"; fi
  grep -h "^RESULT $id " "$UX_WORK/results-$id.txt" 2>/dev/null || echo "RESULT $id BLOCKED no-result"
  echo "$id $(( $(date +%s) - t0 ))" > "$UX_WORK/time-$id.txt"
}

# clear stale per-scenario results so a BLOCKED never lingers from a past run
for id in $SEL; do rm -f "$UX_WORK/results-$id.txt" "$UX_WORK/time-$id.txt"; done

# Split the selection into a parallel batch and a solo tail (run alone, quiet host).
BATCH=""; SOLO=""
for id in $SEL; do
  case " $SOLO_IDS " in *" $id "*) SOLO="$SOLO $id";; *) BATCH="$BATCH $id";; esac
done

if [ -n "$SEQUENTIAL" ]; then
  for id in $BATCH $SOLO; do run_one "$id"; done
else
  # bounded job pool: at most JOBS scenarios in flight at once
  declare -A RUNNING=()
  for id in $BATCH; do
    while [ "${#RUNNING[@]}" -ge "$JOBS" ]; do
      for pid in "${!RUNNING[@]}"; do
        kill -0 "$pid" 2>/dev/null || unset "RUNNING[$pid]"
      done
      [ "${#RUNNING[@]}" -ge "$JOBS" ] && sleep 0.3
    done
    run_one "$id" &
    RUNNING[$!]="$id"
  done
  wait
  # solo tail: each on a fully quiet host (the parallel batch has drained)
  for id in $SOLO; do run_one "$id"; done
fi

SUITE_T=$((SECONDS-SUITE_T0))

# build gallery from the lifted results-*.txt
python3 "$HERE/gallery.py"

# write timing summary (collected from each scenario's time-<id>.txt)
declare -A TIMES
for id in $SEL; do TIMES[$id]=$(cut -d' ' -f2 "$UX_WORK/time-$id.txt" 2>/dev/null); done
{
  echo "# per-scenario wall-clock (record+render), isolated rigs"
  echo "# mode: ${SEQUENTIAL:+sequential}${SEQUENTIAL:-parallel JOBS=$JOBS}   SPEED=$SPEED"
  for id in $SEL; do echo "$id  ${TIMES[$id]:-?}s"; done
  echo "TOTAL  ${SUITE_T}s"
} | tee "$UX_WORK/timings.txt"

echo "===================================================="
echo "gallery: $HERE/gallery/index.html"
echo "total wall-clock: ${SUITE_T}s"
# suite-wide safety net: reap any of OUR marked backends still lingering
cleanup_all
echo "rig torn down (own backends + tracked children killed; /tmp/ux preserved for inspection)."
