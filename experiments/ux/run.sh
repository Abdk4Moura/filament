#!/usr/bin/env bash
# One command to run the whole UX suite: set up a self-safe local rig, record
# every scenario (cli↔cli 01–07 as casts→GIFs, cli↔web 08–10 as side-by-side
# CLI+browser GIFs), build the gallery, and tear everything down.
#
#   ./run.sh              run all 10 scenarios
#   ./run.sh 01 03 06     run a subset
#   PARALLEL_CLI=1 ./run.sh   record the cli↔cli scenarios concurrently (faster;
#                             they use independent config dirs + rooms)
#
# SAFETY: every filament call sets a throwaway FILAMENT_CONFIG_DIR under
# /tmp/ux; we run our OWN backend on $UX_PORT (default 8077); we kill only
# processes we started (tracked, or matched by their /tmp/ux config dir). The
# user's real ~/.config/filament and their running `filament up` daemon are
# never touched.
set -uo pipefail
: "${ZSH_VERSION:=}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/rig/lib.sh"

ALL_CLI="01 02 03 04 05 06 07"
ALL_WEB="08 09 10"
SEL="${*:-$ALL_CLI $ALL_WEB}"

echo "================ Filament UX harness ================"
echo "binary : $FILAMENT"
echo "backend: $UX_SERVER (ours; non-default port)"
echo "tmp    : $UX_TMP   work: $UX_WORK"
echo "scenarios: $SEL"
echo "====================================================="

backend_start || { echo "FATAL: backend failed"; exit 1; }
SUITE_T0=$SECONDS

declare -A TIMES
run_cli() {  # record.sh handles cast+gif+result
  local id="$1" t0=$SECONDS
  echo "--- recording cli↔cli $id ---"
  bash "$HERE/record.sh" "$id" 100 28 >>"$UX_WORK/run-$id.log" 2>&1 || true
  TIMES[$id]=$((SECONDS-t0))
  grep -h "^RESULT $id " "$UX_WORK/results-$id.txt" 2>/dev/null || echo "RESULT $id BLOCKED no-result"
}
run_web() {
  local id="$1" t0=$SECONDS
  echo "--- recording cli↔web $id ---"
  bash "$HERE/web-scenarios.sh" "$id" >>"$UX_WORK/run-$id.log" 2>&1 || true
  TIMES[$id]=$((SECONDS-t0))
  grep -h "^RESULT $id " "$UX_WORK/results-$id.txt" 2>/dev/null || echo "RESULT $id BLOCKED no-result"
}

for id in $SEL; do
  case " $ALL_CLI " in *" $id "*) run_cli "$id";; *) run_web "$id";; esac
done

SUITE_T=$((SECONDS-SUITE_T0))

# build gallery
python3 "$HERE/gallery.py"

# write timing summary
{
  echo "# per-scenario wall-clock (record+render)"
  for id in $SEL; do echo "$id  ${TIMES[$id]:-?}s"; done
  echo "TOTAL  ${SUITE_T}s"
} | tee "$UX_WORK/timings.txt"

echo "===================================================="
echo "gallery: $HERE/gallery/index.html"
echo "total wall-clock: ${SUITE_T}s"
cleanup_all
echo "rig torn down (backend + tracked children killed; /tmp/ux preserved for inspection)."
