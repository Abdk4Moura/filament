#!/usr/bin/env bash
# quality.sh — GPU-aware video quality tiers + webm->mp4 transcode.
#
# Playwright records with chromium's built-in capture, which on the cached
# open-source build is VP8/webm (no H.264 in that chromium). We always transcode
# that webm to a real H.264 mp4 here, choosing a tier:
#
#   --quality auto  (default): detect a GPU.
#       * local `nvidia-smi`            -> high tier, NVENC (h264_nvenc)
#       * else --gpu-node configured    -> offload final encode to that node
#                                          (OPT-IN, GUARDED; falls back if busy)
#       * else                          -> min tier (CPU libx264, modest res/fps)
#   --quality high : force the high/NVENC tier (errors out clearly if no encoder)
#   --quality min  : force the bare-minimum CPU tier
#
# NVENC on our T4 uses the CPU-DECODE path (full-cuda decode is broken on the box
# per the runner gotcha): we decode the webm on CPU and only the ENCODE is NVENC.
set -uo pipefail
: "${ZSH_VERSION:=}"

# Resolve the effective tier given a requested quality + optional gpu node.
# echoes one of: high  min
# (gpu-node offload is handled in pipe_transcode, not here)
pipe_quality_tier() {
  local req="${1:-auto}"
  case "$req" in
    high) echo high; return;;
    min)  echo min;  return;;
  esac
  # auto: local GPU?
  if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
    # confirm ffmpeg actually has the nvenc encoder
    if ffmpeg -hide_banner -encoders 2>/dev/null | grep -q h264_nvenc; then echo high; return; fi
  fi
  # auto + a gpu node is opt-in: the offload path decides at transcode time.
  echo min
}

# Does a local NVENC encode path exist (GPU present AND encoder built in)?
pipe_have_nvenc() {
  command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1 \
    && ffmpeg -hide_banner -encoders 2>/dev/null | grep -q h264_nvenc
}

# pipe_transcode <in.webm> <out.mp4> <tier> [gpu_node]
# Transcodes; returns 0 on a valid mp4. The high tier prefers local NVENC, then
# (if a gpu_node is given and reachable) an offload, then falls back to CPU so a
# recording never fails just because the GPU is unavailable.
pipe_transcode() {
  local in="$1" out="$2" tier="$3" gpu_node="${4:-}"
  [ -f "$in" ] || { echo "[quality] no input webm: $in" >&2; return 1; }

  if [ "$tier" = high ]; then
    if pipe_have_nvenc; then
      echo "[quality] high tier: local NVENC (h264_nvenc, CPU-decode path)" >&2
      # CPU decode (no -hwaccel cuda — full-cuda decode broken on the T4), NVENC encode.
      ffmpeg -y -i "$in" -c:v h264_nvenc -preset p5 -rc vbr -cq 19 -b:v 6M -maxrate 12M \
        -pix_fmt yuv420p -movflags +faststart -an "$out" >/dev/null 2>&1 && _pipe_mp4_ok "$out" && return 0
      echo "[quality] local NVENC failed — falling back to CPU" >&2
    elif [ -n "$gpu_node" ]; then
      if pipe_gpu_offload "$in" "$out" "$gpu_node"; then return 0; fi
      echo "[quality] gpu-node offload unavailable — falling back to CPU min" >&2
    else
      echo "[quality] high requested but no NVENC + no gpu-node — using CPU (still high-ish settings)" >&2
      ffmpeg -y -i "$in" -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p \
        -movflags +faststart -an "$out" >/dev/null 2>&1 && _pipe_mp4_ok "$out" && return 0
    fi
  fi

  # min tier (and the universal fallback): functional CPU encode, low overhead.
  echo "[quality] min tier: CPU libx264 (modest res/fps, low overhead)" >&2
  ffmpeg -y -i "$in" -vf "fps=24,scale='min(1280,iw)':-2" -c:v libx264 -preset veryfast \
    -crf 26 -pix_fmt yuv420p -movflags +faststart -an "$out" >/dev/null 2>&1 && _pipe_mp4_ok "$out"
}

# Offload the final encode to a filament GPU node by SUBMITTING an NVENC ffmpeg
# job to the box via runner/runner_cli.py (the worked example from the runner
# docs), then fetching out.mp4.
#
# OPT-IN + GUARDED. The live T4 is single-flight: the separate agent's real batch
# holds a lock and this MUST NOT contend with it. We refuse to offload unless the
# caller explicitly points us at the host/box config (FILJOB_HOST_CFG etc.) AND a
# guard file ($FILJOB_BATCH_LOCK, default the box's batch lock) is absent. We use
# a SHORT submit-deadline so that if the box is busy the offload fails fast and we
# fall back to CPU instead of queuing behind the batch.
pipe_gpu_offload() {
  local in="$1" out="$2" node="$3"
  local rc="$REPO_ROOT/runner/runner_cli.py"
  [ -f "$rc" ] || { echo "[quality] runner_cli.py absent — cannot offload" >&2; return 1; }
  # Required config to reach the box (none baked in — never guess credentials).
  if [ -z "${FILJOB_HOST_CFG:-}" ] || [ -z "${FILJOB_HOST_DOUT_CFG:-}" ]; then
    echo "[quality] --gpu-node set but FILJOB_HOST_CFG/FILJOB_HOST_DOUT_CFG not provided — not offloading" >&2
    return 1
  fi
  # GUARD: never contend with the live single-flight batch.
  local lock="${FILJOB_BATCH_LOCK:-/tmp/filament-runner-batch.lock}"
  if [ -e "$lock" ]; then
    echo "[quality] live batch lock present ($lock) — NOT contending, falling back to CPU" >&2
    return 1
  fi
  local indir outdir; indir=$(mktemp -d); outdir=$(mktemp -d)
  cp "$in" "$indir/input.webm"
  echo "[quality] offloading NVENC encode to gpu-node $node (submit-deadline ${FILJOB_SUBMIT_DEADLINE:-30}s)" >&2
  "$PIPE_PY" "$rc" \
    --server "${FILJOB_SERVER:-https://api.filament.autumated.com}" \
    --host-cfg "$FILJOB_HOST_CFG" --dout-cfg "$FILJOB_HOST_DOUT_CFG" \
    --in "$indir" --out "$outdir" --input input.webm --output out.mp4 \
    --timeout 120 --submit-deadline "${FILJOB_SUBMIT_DEADLINE:-30}" \
    --await-timeout "${FILJOB_AWAIT_TIMEOUT:-180}" \
    -- ffmpeg -y -i input.webm -c:v h264_nvenc -preset p5 -cq 19 -b:v 6M \
       -pix_fmt yuv420p -movflags +faststart -an out.mp4 \
    >/dev/null 2>&1
  if [ -f "$outdir/out.mp4" ]; then cp "$outdir/out.mp4" "$out"; rm -rf "$indir" "$outdir"; _pipe_mp4_ok "$out" && return 0; fi
  rm -rf "$indir" "$outdir"; return 1
}

# Validate the produced mp4 with ffprobe (H.264 video stream, nonzero duration).
_pipe_mp4_ok() {
  local f="$1"
  [ -s "$f" ] || return 1
  local codec dur
  codec=$(ffprobe -v error -select_streams v:0 -show_entries stream=codec_name -of csv=p=0 "$f" 2>/dev/null)
  dur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$f" 2>/dev/null)
  [ "$codec" = h264 ] && awk "BEGIN{exit !($dur+0 > 0)}" 2>/dev/null
}

# Public: assert an mp4 is valid (used by the pipeline to gate reels).
pipe_ffprobe_ok() { _pipe_mp4_ok "$1"; }
