#!/usr/bin/env bash
# pipeline.sh — flag-controlled, async, GPU-aware TEST + live-record pipeline that
# drives the REAL filament app against REAL local filament peers (no mock seams).
#
# It stands up genuine peers (locally-built binary, isolated FILAMENT_CONFIG_DIRs,
# a local signaling backend), PAIRS FOR REAL in the browser (a CLI peer mints a
# PAKE code; Playwright types it into the real pair box), drives the genuine UI,
# ASSERTS real DOM/store state, and (when recording) records the tab live to webm
# → transcodes to mp4 via a GPU-aware quality tier → updates the gallery.
#
# It is a TEST pipeline first: it exits NONZERO if any selected case fails.
#
#   ./pipeline.sh --help
#
set -uo pipefail
: "${ZSH_VERSION:=}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/peers.sh"
source "$HERE/lib/pairing.sh"
source "$HERE/lib/quality.sh"
# usecases suite is sourced AFTER the web-case helpers it builds on are defined
# (web_setup / finalize_reel / bg_run / emit) — see "source journeys.sh" below.

# ---------------------------------------------------------------- defaults ----
RECORD=1
ONLY=""           # csv of case ids to run (empty = all in suite)
SKIP=""           # csv of case ids to skip
SUITE="all"       # cli | web | runner | all
SPEED=1           # playback speed hint (passed to drivers where relevant)
PARALLEL=1        # web cases are single-host ICE-sensitive; default serial
QUALITY="auto"    # auto | high | min
ASYNC=1           # async by default: heavy encode/gallery runs in the background
OUT="$HERE/gallery"
UPDATE_GALLERY=1
GPU_NODE=""       # optional filament GPU node for encode offload (opt-in, guarded)

usage() {
  cat <<'EOF'
pipeline.sh — REAL-app + REAL-peer e2e TEST + live-record pipeline for filament.

USAGE
  experiments/ux/pipeline.sh [flags]

FLAGS
  --record / --no-record     record live Playwright video for each web case (default: record)
  --only <csv>               run only these case ids        (e.g. --only pair-device,web-shell)
  --skip <csv>               skip these case ids
  --suite <cli|web|runner|usecases|all>   which family of cases (default: all)
  --speed <x>                playback/gesture speed hint    (default: 1)
  --parallel <n>             max concurrent web cases       (default: 1 — single-host ICE-safe)
  --quality <auto|high|min>  encode tier (default: auto — GPU→high/NVENC, else CPU/min)
  --gpu-node <name>          OPT-IN: offload the final encode to a filament GPU node
                             (guarded; never contends with the live single-flight batch)
  --async / --sync           kick recording/encoding to the background (default) / wait
  --out <dir>                output dir for reels (default: experiments/ux/gallery)
  --update-gallery / --no-update-gallery   rebuild index.html + reels.html (default: update)
  --help                     this help

CASES (ids)
  cli:    cli-01 … cli-07, cli-11   (existing CLI scenarios via scenarios.sh — real cli↔cli peers)
  web:    pair-device, web-shell, device-sheet-mobile, device-sheet-desktop,
          sessions-dock, cmd-k, pwa-update   (REAL app + REAL peers, real PAKE pairing)
  runner: runner-local                (loopback file-driven runner via runner/run_local_test.sh)
  usecases: maya-send-big-file (HERO), maya-phone-to-laptop, maya-gpu-render,
            sam-phone-shell, sam-drag-build   (real user "journeys" — REAL peers,
            recorded + an ergonomics step-counter burned into each reel)

MODEL
  * Peers are REAL: locally-built cli/target/release/filament, isolated configs,
    a local signaling backend. No ?preview= mock seam is used for e2e (preview is
    reserved for the pure-visual reels only).
  * Pairing is REAL: a CLI peer mints a PAKE code; Playwright types it into the
    app's real pair box. Each case asserts genuine DOM / localStorage state.

EXIT
  Nonzero if any selected case FAILS. Reels land in --out; the gallery is updated.
EOF
}

# ---------------------------------------------------------------- arg parse ---
while [ $# -gt 0 ]; do
  case "$1" in
    --record) RECORD=1;;
    --no-record) RECORD=0;;
    --only) ONLY="$2"; shift;;
    --skip) SKIP="$2"; shift;;
    --suite) SUITE="$2"; shift;;
    --speed) SPEED="$2"; shift;;
    --parallel) PARALLEL="$2"; shift;;
    --quality) QUALITY="$2"; shift;;
    --gpu-node) GPU_NODE="$2"; shift;;
    --async) ASYNC=1;;
    --sync) ASYNC=0;;
    --out) OUT="$2"; shift;;
    --update-gallery) UPDATE_GALLERY=1;;
    --no-update-gallery) UPDATE_GALLERY=0;;
    --help|-h) usage; exit 0;;
    *) echo "unknown flag: $1" >&2; usage; exit 2;;
  esac
  shift
done

mkdir -p "$OUT" "$PIPE_WORK" "$PIPE_TMP"
RESULTS="$PIPE_WORK/pipe-results.txt"; : > "$RESULTS"
BG_DIR="$PIPE_WORK/bg"; mkdir -p "$BG_DIR"

# ---------------------------------------------------------------- registry ----
# Each case is: <id> <suite> <fn>. The fn RUNS + ASSERTS the real flow and (when
# recording) records live; it writes one line to $RESULTS: "RESULT <id> PASS|FAIL <detail>".
declare -A CASE_SUITE CASE_FN
register() { CASE_SUITE["$1"]="$2"; CASE_FN["$1"]="$3"; }

ALL_IDS=()
register pair-device          web    case_pair_device
register web-shell            web    case_web_shell
register device-sheet-mobile  web    case_device_sheet_mobile
register device-sheet-desktop web    case_device_sheet_desktop
register sessions-dock        web    case_sessions_dock
register cmd-k                web    case_cmd_k
register pwa-update           web    case_pwa_update
for n in 01 02 03 04 05 06 07 11; do register "cli-$n" cli "case_cli"; done
register runner-local         runner case_runner_local
# usecases "journey" suite — real user stories, real peers, recorded + annotated.
register maya-send-big-file    usecases case_maya_send_big_file
register maya-phone-to-laptop  usecases case_maya_phone_to_laptop
register maya-gpu-render       usecases case_maya_gpu_render
register sam-phone-shell       usecases case_sam_phone_shell
register sam-drag-build        usecases case_sam_drag_build
ALL_IDS=(pair-device web-shell device-sheet-mobile device-sheet-desktop sessions-dock cmd-k pwa-update \
         cli-01 cli-02 cli-03 cli-04 cli-05 cli-06 cli-07 cli-11 runner-local \
         maya-send-big-file maya-phone-to-laptop maya-gpu-render sam-phone-shell sam-drag-build)

in_csv() { case ",$1," in *",$2,"*) return 0;; esac; return 1; }

# selection: suite filter, then --only / --skip
SELECTED=()
for id in "${ALL_IDS[@]}"; do
  [ "$SUITE" != all ] && [ "${CASE_SUITE[$id]}" != "$SUITE" ] && continue
  [ -n "$ONLY" ] && ! in_csv "$ONLY" "$id" && continue
  [ -n "$SKIP" ] && in_csv "$SKIP" "$id" && continue
  SELECTED+=("$id")
done

emit() { echo "RESULT $1 $2 $3" >>"$RESULTS"; echo "[case] $1 -> $2: $3"; }

# ---------------------------------------------------------------- bg tracking -
declare -a BG_PIDS=()
bg_run() {  # bg_run <tag> <cmd...>  — run in background, track pid
  local tag="$1"; shift
  ( "$@" ) >"$BG_DIR/$tag.log" 2>&1 &
  local p=$!; BG_PIDS+=("$p"); echo "$p" >"$BG_DIR/$tag.pid"
  echo "[async] backgrounded $tag (pid $p) — log $BG_DIR/$tag.log"
}
bg_wait_all() {
  local p
  for p in "${BG_PIDS[@]:-}"; do wait "$p" 2>/dev/null; done
  BG_PIDS=()
}

# Transcode + place a recorded webm as a reel mp4 (the async-able heavy step).
# finalize_reel <webm-dir> <reel-name>
finalize_reel() {
  local viddir="$1" reel="$2"
  local webm; webm=$(ls -t "$viddir"/*.webm 2>/dev/null | head -1)
  [ -n "$webm" ] || { echo "[reel] no webm in $viddir for $reel"; return 1; }
  local tier; tier=$(pipe_quality_tier "$QUALITY")
  local mp4="$OUT/$reel.mp4"
  if pipe_transcode "$webm" "$mp4" "$tier" "$GPU_NODE"; then
    if pipe_ffprobe_ok "$mp4"; then
      echo "[reel] $reel.mp4 OK ($(stat -c%s "$mp4" 2>/dev/null) bytes, tier=$tier) ffprobe-valid"
      return 0
    fi
  fi
  echo "[reel] $reel.mp4 FAILED transcode/ffprobe"; return 1
}

# ---------------------------------------------------------------- web cases ---
# Common preamble for a web case: ensure binary+frontend+backend, return APP url.
web_setup() {
  pipe_ensure_binary || { emit "$1" FAIL "binary build failed"; return 1; }
  pipe_ensure_frontend || { emit "$1" FAIL "frontend build failed"; return 1; }
  pipe_backend_start || { emit "$1" FAIL "backend failed"; return 1; }
  APP="$PIPE_SERVER/"
  return 0
}

# Run a node driver, capture its PIPE_RESULT, finalize the reel (sync or async).
# run_web_driver <id> <reel> <node-driver> <args...>
run_web_driver() {
  local id="$1" reel="$2" drv="$3"; shift 3
  local viddir="$PIPE_WORK/vid-$id"; rm -rf "$viddir"; mkdir -p "$viddir"
  local rec=$([ "$RECORD" = 1 ] && echo "$viddir" || echo "")
  local log="$PIPE_WORK/$id-driver.log"
  ( cd "$HERE" && node "$drv" "$@" "$rec" ) >"$log" 2>&1
  local rc=$?
  local line; line=$(grep -m1 "^PIPE_RESULT " "$log" || echo "PIPE_RESULT FAIL no driver result")
  local verdict detail
  verdict=$(echo "$line" | awk '{print $2}'); detail=$(echo "$line" | cut -d' ' -f3-)
  # record/transcode only on a real pass with video
  if [ "$RECORD" = 1 ] && [ "$verdict" = PASS ]; then
    if [ "$ASYNC" = 1 ]; then bg_run "reel-$reel" finalize_reel "$viddir" "$reel"
    else finalize_reel "$viddir" "$reel" || true; fi
  fi
  emit "$id" "$verdict" "$detail"
  [ "$verdict" = PASS ]
}

case_pair_device() {
  local id=pair-device; web_setup "$id" || return 1
  local cfg; cfg=$(pipe_cfg "${id}-cli")
  local code; code=$(pipe_mint_code "$cfg" "browser" "$PIPE_WORK/$id-pair.log")
  [ -n "$code" ] || { emit "$id" FAIL "CLI did not mint a pair code"; return 1; }
  echo "[case] $id: CLI minted code $code"
  run_web_driver "$id" "reel-pair-device" web/e2e-pair-device.cjs "$APP" "$code"
}

case_web_shell() {
  local id=web-shell; web_setup "$id" || return 1
  local scfg; scfg=$(pipe_cfg "${id}-shell")
  pipe_start_shell_peer "$scfg" "box" "$PIPE_WORK/$id-up.log" || echo "[case] $id: up --shell banner not seen (continuing)"
  local code; code=$(pipe_mint_code "$scfg" "browser" "$PIPE_WORK/$id-pair.log")
  [ -n "$code" ] || { emit "$id" FAIL "shell peer did not mint a pair code"; return 1; }
  echo "[case] $id: shell peer minted code $code"
  run_web_driver "$id" "reel-webshell" web/e2e-webshell.cjs "$APP" "$code" "FILA_SHELL_$RANDOM"
}

_device_sheet() {
  local id="$1" mode="$2"; web_setup "$id" || return 1
  # The sheet/action-bar only renders for a LIVE (ready) remembered device, so we
  # pair against a real always-on shell peer (it stays connected after pairing).
  local cfg; cfg=$(pipe_cfg "${id}-shell")
  pipe_start_shell_peer "$cfg" "box" "$PIPE_WORK/$id-up.log" || true
  local code; code=$(pipe_mint_code "$cfg" "browser" "$PIPE_WORK/$id-pair.log")
  [ -n "$code" ] || { emit "$id" FAIL "peer did not mint a pair code"; return 1; }
  run_web_driver "$id" "reel-$id" web/e2e-device-sheet.cjs "$APP" "$code" "$mode"
}
case_device_sheet_mobile()  { _device_sheet device-sheet-mobile mobile; }
case_device_sheet_desktop() { _device_sheet device-sheet-desktop desktop; }

case_sessions_dock() {
  local id=sessions-dock; web_setup "$id" || return 1
  local scfg; scfg=$(pipe_cfg "${id}-shell")
  pipe_start_shell_peer "$scfg" "box" "$PIPE_WORK/$id-up.log" || true
  local code; code=$(pipe_mint_code "$scfg" "browser" "$PIPE_WORK/$id-pair.log")
  [ -n "$code" ] || { emit "$id" FAIL "shell peer did not mint a code"; return 1; }
  run_web_driver "$id" "reel-sessions-dock" web/e2e-sessions-dock.cjs "$APP" "$code"
}

case_cmd_k() {
  local id=cmd-k; web_setup "$id" || return 1
  local scfg; scfg=$(pipe_cfg "${id}-shell")
  pipe_start_shell_peer "$scfg" "box" "$PIPE_WORK/$id-up.log" || true
  local code; code=$(pipe_mint_code "$scfg" "browser" "$PIPE_WORK/$id-pair.log")
  [ -n "$code" ] || { emit "$id" FAIL "shell peer did not mint a code"; return 1; }
  run_web_driver "$id" "reel-cmd-k" web/e2e-cmdk.cjs "$APP" "$code"
}

case_pwa_update() {
  local id=pwa-update; web_setup "$id" || return 1
  # Build B: a second same-origin build with a fresh BUILD_ID (real "deploy").
  # We serve dist over the backend already (same-origin). For the SW swap we use a
  # tiny static http server with a swappable /sw.js (the backend doesn't hot-swap).
  bash "$HERE/lib/pwa-serve.sh" "$id" "$PIPE_WORK" || { emit "$id" FAIL "pwa static serve setup failed"; return 1; }
  local purl; purl=$(cat "$PIPE_WORK/$id-url.txt" 2>/dev/null)
  [ -n "$purl" ] || { emit "$id" FAIL "pwa server url missing"; return 1; }
  local swap="$PIPE_WORK/$id-swap.flag"; rm -f "$swap"
  run_web_driver "$id" "reel-pwa-update" web/e2e-pwa-update.cjs "$purl" "$swap" "buildB" || true
  bash "$HERE/lib/pwa-serve.sh" stop "$id" "$PIPE_WORK" 2>/dev/null || true
}

# ---------------------------------------------------------------- cli cases ---
# Reuse the existing scenarios.sh harness, but force the LOCALLY-BUILT binary so
# the CLI peers are the same code under test as the web flows.
case_cli() {
  local id="$1"; local n="${id#cli-}"
  pipe_ensure_binary || { emit "$id" FAIL "binary build failed"; return 1; }
  pipe_backend_start || { emit "$id" FAIL "backend failed"; return 1; }
  local cwork="$PIPE_TMP/cli-$n" wwork="$PIPE_WORK/cli-$n"
  mkdir -p "$cwork" "$wwork"
  local log="$PIPE_WORK/$id.log"
  # record.sh records a real cast→gif into gallery/<n>.gif AND writes
  # results-<n>.txt; rig/lib.sh honours FILAMENT_BIN (locally-built) + UX_PORT.
  if [ "$RECORD" = 1 ]; then
    FILAMENT_BIN="$FILAMENT_BIN" UX_PORT="$PIPE_PORT" UX_SERVER="$PIPE_SERVER" \
      UX_TMP="$cwork" UX_WORK="$wwork" \
      bash "$HERE/record.sh" "$n" 100 28 >"$log" 2>&1 || true
  else
    FILAMENT_BIN="$FILAMENT_BIN" UX_PORT="$PIPE_PORT" UX_SERVER="$PIPE_SERVER" \
      UX_TMP="$cwork" UX_WORK="$wwork" \
      bash "$HERE/scenarios.sh" "$n" >"$log" 2>&1 || true
  fi
  local rline
  rline=$(grep -hm1 "^RESULT $n " "$wwork/results-$n.txt" 2>/dev/null)
  [ -z "$rline" ] && rline=$(grep -hm1 "^RESULT $n " "$log" 2>/dev/null)
  local verdict detail
  verdict=$(echo "$rline" | awk '{print $3}'); detail=$(echo "$rline" | cut -d' ' -f4-)
  [ "$verdict" = PASS ] || [ "$verdict" = FAIL ] || { verdict=FAIL; detail="no RESULT line (see $log)"; }
  emit "$id" "$verdict" "${detail:-cli scenario $n}"
  [ "$verdict" = PASS ]
}

# ---------------------------------------------------------------- runner case -
case_runner_local() {
  local id=runner-local
  pipe_ensure_binary || { emit "$id" FAIL "binary build failed"; return 1; }
  local rl="$REPO_ROOT/runner/run_local_test.sh"
  [ -x "$rl" ] || { emit "$id" FAIL "run_local_test.sh missing"; return 1; }
  local log="$PIPE_WORK/$id.log"
  # loopback only — never touches the live T4 or the live single-flight batch.
  # Internally time-boxed so a single-host return-path stall can't hang the suite.
  FILJOB_BIN="$FILAMENT_BIN" timeout -k 10 "${RUNNER_TIMEOUT:-360}" bash "$rl" >"$log" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then
    emit "$id" PASS "file-driven runner loopback: submit→watcher-runs-job→results, sha-verified"; return 0
  fi
  # The job EXECUTING (ffmpeg exit=0, out.mp4 produced) is the runner correctness
  # signal; the box→host WebRTC RETURN path is the single-host-flaky part.
  if grep -q "done exit=0" "$PIPE_WORK"/cli-*/box_watcher.log 2>/dev/null || grep -q "job .* done exit=0" "$log" 2>/dev/null; then
    emit "$id" FAIL "runner job RAN (ffmpeg exit=0, out.mp4) but the single-host box→host return WebRTC didn't deliver in time (rc=$rc) — env ceiling, not a runner bug"
  else
    emit "$id" FAIL "runner loopback failed (rc=$rc) — see $log"
  fi
  return 1
}

# ---------------------------------------------------------------- usecases -----
# The journey suite builds ON the web-case helpers above (web_setup, finalize_reel,
# bg_run, emit, run_web_driver). Source it now that they're all defined.
source "$HERE/lib/journeys.sh"

# ---------------------------------------------------------------- run ----------
echo "================= filament e2e pipeline ================="
echo "binary  : $FILAMENT_BIN"
echo "suite   : $SUITE   record:$RECORD  quality:$QUALITY  async:$ASYNC  parallel:$PARALLEL"
echo "cases   : ${SELECTED[*]:-<none>}"
echo "out     : $OUT"
[ -n "$GPU_NODE" ] && echo "gpu-node: $GPU_NODE (offload encode, guarded)"
echo "========================================================="
[ "${#SELECTED[@]}" -eq 0 ] && { echo "no cases selected"; exit 2; }

T0=$SECONDS
# Web cases share one backend; cli/runner cases manage their own. Run web cases
# with bounded concurrency (default 1 — single-host ICE is contention-sensitive).
run_case() { local id="$1"; "${CASE_FN[$id]}" "$id" || true; }

if [ "$PARALLEL" -le 1 ]; then
  for id in "${SELECTED[@]}"; do run_case "$id"; done
else
  declare -A RUN=()
  for id in "${SELECTED[@]}"; do
    while [ "${#RUN[@]}" -ge "$PARALLEL" ]; do
      for pid in "${!RUN[@]}"; do kill -0 "$pid" 2>/dev/null || unset "RUN[$pid]"; done
      [ "${#RUN[@]}" -ge "$PARALLEL" ] && sleep 0.3
    done
    run_case "$id" & RUN[$!]="$id"
  done
  wait
fi

# wait for any async reel encodes to land before updating the gallery
if [ "$ASYNC" = 1 ] && [ "${#BG_PIDS[@]}" -gt 0 ]; then
  echo "[async] waiting for ${#BG_PIDS[@]} background encode job(s) to finish before gallery update…"
  bg_wait_all
fi

# ---------------------------------------------------------------- gallery -----
if [ "$UPDATE_GALLERY" = 1 ]; then
  python3 "$HERE/lib/update_gallery.py" "$RESULTS" "$OUT" || echo "[gallery] update failed (non-fatal)"
fi

# ---------------------------------------------------------------- teardown -----
pipe_kill_tracked
pipe_backend_stop
pipe_reap_backends

# ---------------------------------------------------------------- verdict ------
PASS=$(grep -c ' PASS ' "$RESULTS" 2>/dev/null); PASS=${PASS:-0}
FAIL=$(grep -c ' FAIL ' "$RESULTS" 2>/dev/null); FAIL=${FAIL:-0}
echo "========================================================="
echo "pipeline: $PASS pass, $FAIL fail  (wall $((SECONDS-T0))s)"
echo "results : $RESULTS"
echo "gallery : $OUT/index.html  +  $OUT/reels.html"
sed 's/^/  /' "$RESULTS"
[ "$FAIL" -eq 0 ]
