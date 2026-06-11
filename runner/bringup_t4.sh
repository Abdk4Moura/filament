#!/usr/bin/env bash
# filament job-runner — T4 BRING-UP (SSH-FREE).
#
# Paste this on a fresh, ephemeral Tesla T4 (Colab-style, glibc 2.35, no inbound
# SSH) to turn it into a filament job-runner NODE. It installs only what jobs
# need, drops the STATIC musl `filament` binary (a dynamic binary won't run on the
# T4's glibc), plants the pairing secrets, and starts the box-side din acceptor +
# the FILE-DRIVEN WATCHER. It NEVER installs openssh/sshd (that shuts the box down).
#
# CONTROL PLANE: file-driven (watcher.py), NOT an interactive PTY. The watcher
# polls the inbox for a job spec + its inputs, runs the job, and `filament send
# --relay`s the manifest + outputs back to the host on the dout channel. This
# survives the unstable Colab->do-vm WAN link that killed the v1 PTY control
# session (see docs/runner/jobrunner-challenges.md). The `ctl` PTY is DEPRECATED;
# this script no longer starts it (the secret is still planted so no re-pairing is
# needed — din/dout are reused unchanged).
#
# It does NOT drive the box; it just makes the box reachable as a job runner. The
# HOST then submits jobs with runner/runner_cli.py (file-driven, --relay default).
#
# ---------------------------------------------------------------------------
# WHAT YOU PROVIDE (env or edit the CONFIG block):
#   FILJOB_SERVER   signaling server (default: the public filament server)
#   SEC_CTL/SEC_DIN/SEC_DOUT   the three 64-hex pair secrets shared with the host
#       (generate with:  openssl rand -hex 32   — run THREE times on the host,
#        give the same three to both sides; keep them secret).
#   FILAMENT_URL    URL to fetch the static musl binary (or place ./filament next
#                   to this script / set FILAMENT_BIN to an existing path).
# ---------------------------------------------------------------------------
set -euo pipefail

# ===================== CONFIG (edit or pass via env) =======================
FILJOB_SERVER="${FILJOB_SERVER:-https://api.filament.autumated.com}"
SEC_CTL="${SEC_CTL:?set SEC_CTL (openssl rand -hex 32, shared with host)}"
SEC_DIN="${SEC_DIN:?set SEC_DIN (openssl rand -hex 32, shared with host)}"
SEC_DOUT="${SEC_DOUT:?set SEC_DOUT (openssl rand -hex 32, shared with host)}"

# How the BOX names the HOST on each channel (local aliases; must match how the
# host's bringup planted them on its side — see the host pairing helper).
HOST_CTL_NAME="${HOST_CTL_NAME:-host}"
HOST_DIN_NAME="${HOST_DIN_NAME:-host-in}"
HOST_DOUT_NAME="${HOST_DOUT_NAME:-host-out}"

ROOT_DIR="${FILJOB_ROOT:-$HOME/filament-jobs}"
INBOX="$ROOT_DIR/.inbox"
BIN="${FILAMENT_BIN:-$ROOT_DIR/filament}"
FILAMENT_URL="${FILAMENT_URL:-}"          # optional: fetch the static binary
INSTALL_RCLONE="${INSTALL_RCLONE:-0}"      # 1 to install rclone for R2 durability
# ===========================================================================

log() { printf '\033[36m[bringup]\033[0m %s\n' "$*"; }

mkdir -p "$ROOT_DIR" "$INBOX" \
         "$ROOT_DIR/cfg-ctl" "$ROOT_DIR/cfg-din" "$ROOT_DIR/cfg-dout" "$ROOT_DIR/ctldrop"

# --- 1. dependencies (jobs only; NO sshd) ----------------------------------
need() { command -v "$1" >/dev/null 2>&1; }

if ! need ffmpeg; then
  log "installing ffmpeg (NVENC build expected on the T4 CUDA image; apt ffmpeg links NVENC dynamically)"
  if need apt-get; then
    apt-get update -y && apt-get install -y ffmpeg
  elif need dnf; then dnf install -y ffmpeg || true
  elif need yum; then yum install -y ffmpeg || true
  fi
fi
need python3 || { log "installing python3"; (need apt-get && apt-get install -y python3) || true; }

if [ "$INSTALL_RCLONE" = "1" ] && ! need rclone; then
  log "installing rclone (R2 durability hook)"
  curl -fsSL https://rclone.org/install.sh | bash || log "rclone install failed (durability stays a no-op)"
fi

# sanity: confirm NVENC is actually present (informational — jobs may fall back)
if ffmpeg -hide_banner -encoders 2>/dev/null | grep -q h264_nvenc; then
  log "ffmpeg h264_nvenc encoder present"
  command -v nvidia-smi >/dev/null && nvidia-smi --query-gpu=name --format=csv,noheader | head -1 | sed 's/^/[bringup] GPU: /'
else
  log "WARNING: h264_nvenc not listed by ffmpeg — NVENC jobs will fail; CPU jobs still work"
fi

# --- 2. the static filament binary -----------------------------------------
if [ ! -x "$BIN" ]; then
  if [ -n "$FILAMENT_URL" ]; then
    log "fetching static filament binary from $FILAMENT_URL"
    dl="$ROOT_DIR/.filament.dl"
    curl -fsSL "$FILAMENT_URL" -o "$dl"
    # Standard release assets are .tar.gz; the one-off asset is a raw binary.
    # Detect and handle BOTH (tar -tzf succeeds only on a real gzip tarball).
    if tar -tzf "$dl" >/dev/null 2>&1; then
      log "  asset is a tarball — extracting the filament binary"
      tar -xzf "$dl" -C "$ROOT_DIR"
      f="$(find "$ROOT_DIR" -maxdepth 2 -type f -name filament 2>/dev/null | head -1)"
      [ -n "$f" ] || { log "ERROR: no 'filament' binary inside the tarball"; exit 1; }
      mv "$f" "$BIN"
    else
      mv "$dl" "$BIN"
    fi
    rm -f "$dl"
    chmod +x "$BIN"
  elif [ -x "$(dirname "$0")/filament" ]; then
    cp "$(dirname "$0")/filament" "$BIN"; chmod +x "$BIN"
  else
    log "ERROR: no filament binary. Build it on the host with:"
    log "  cargo build --release --features static --target x86_64-unknown-linux-musl"
    log "then host it (FILAMENT_URL) or copy it next to this script as ./filament"
    exit 1
  fi
fi
# verify it actually runs on this glibc (static-pie => should always run)
"$BIN" --version >/dev/null 2>&1 || { log "ERROR: filament binary does not run here (not static?)"; exit 1; }
log "filament binary OK: $("$BIN" --version 2>/dev/null | head -1)"

# put filament on PATH (the watcher invokes `filament send` for results)
ln -sf "$BIN" /usr/local/bin/filament 2>/dev/null || true

# --- 2b. deliver the box-side python (watcher + executor) -------------------
# The watcher runs the job and ships results; it imports box_executor for the
# job-execution logic. Get both onto the box: fetch from URL, else copy from the
# script's own dir (when run-as-file with the runner/ checkout present).
SRC_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo .)"
fetch_py() { # $1 = env URL value, $2 = local fallback name, $3 = dest
  if [ -n "${1:-}" ]; then
    log "fetching $(basename "$3") from $1"; curl -fsSL "$1" -o "$3"
  elif [ -f "$SRC_DIR/$2" ]; then
    cp "$SRC_DIR/$2" "$3"
  else
    log "ERROR: no source for $2 (set ${2%%.py}_URL or place it next to this script)"; exit 1
  fi
}
fetch_py "${WATCHER_URL:-}"   watcher.py       "$ROOT_DIR/watcher.py"
fetch_py "${EXECUTOR_URL:-}"  box_executor.py  "$ROOT_DIR/box_executor.py"
fetch_py "${SUPERVISOR_URL:-}" up_supervisor.sh "$ROOT_DIR/up_supervisor.sh"
chmod +x "$ROOT_DIR/up_supervisor.sh"
log "box-side files in place: watcher.py + box_executor.py + up_supervisor.sh"

# --- 3. plant the pairing secrets (isolated config dirs) --------------------
# Each role gets its OWN config dir holding exactly ONE secret, so no daemon ever
# subscribes to a channel it shouldn't (which would glare). The ctl secret is
# still planted (so din/dout pairing is UNCHANGED — no re-pairing needed), but
# the ctl PTY acceptor is no longer started (file-driven control plane).
python3 - "$ROOT_DIR" "$SEC_CTL" "$SEC_DIN" "$SEC_DOUT" \
         "$HOST_CTL_NAME" "$HOST_DIN_NAME" "$HOST_DOUT_NAME" <<'PY'
import json, sys
root, ctl, din, dout, n_ctl, n_din, n_dout = sys.argv[1:8]
json.dump([{"name": n_ctl,  "secret": ctl}],  open(f"{root}/cfg-ctl/devices.json",  "w"))
json.dump([{"name": n_din,  "secret": din}],  open(f"{root}/cfg-din/devices.json",  "w"))
json.dump([{"name": n_dout, "secret": dout}], open(f"{root}/cfg-dout/devices.json", "w"))
print("[bringup] planted ctl/din/dout device secrets (ctl unused; reused for no re-pair)")
PY

# --- 4. start the din acceptor + the FILE-DRIVEN WATCHER (NO sshd, NO PTY) ---
# din    : up --dir   -> receives the pushed job spec + inputs into the inbox.
# watcher: polls the inbox, runs jobs, `filament send --relay`s results on dout.
# The dout channel needs NO daemon on the box: the watcher only `send`s on it
# (the host stands up the dout sink transiently while awaiting results).
# Kill only PREVIOUSLY-tracked processes via their pid files — never pkill -f on
# a pattern that also appears in THIS script's own command line (when the script
# is run via `bash -c "$(curl …)"`, the whole script text is the process argv, so
# a `pkill -f "filament up …cfg-din"` would match and SIGTERM this very process).
for p in "$ROOT_DIR/ctl.pid" "$ROOT_DIR/din.pid" "$ROOT_DIR/watcher.pid"; do
  [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true
done
sleep 1

log "starting din acceptor (SUPERVISED, --relay -> $INBOX)"
# Wrap in up_supervisor.sh: filament's socket.io is reconnect(false), so a severed
# long-lived `up --dir` zombies out and the host can't rediscover it (the exact
# 'no peer connected' failure we hit on the real WAN). The supervisor recycles it on
# a cadence so a fresh, re-announcing acceptor is always present; partials resume.
# This is the pattern validated by runner/sim/flaky_sim_test.sh.
FILAMENT_CONFIG_DIR="$ROOT_DIR/cfg-din" HOME="$ROOT_DIR/cfg-din" \
  nohup bash "$ROOT_DIR/up_supervisor.sh" --cadence "${FILJOB_DIN_CADENCE:-90}" \
    --log "$ROOT_DIR/din.log" --pidfile "$ROOT_DIR/din.pid" -- \
    "$BIN" up --server "$FILJOB_SERVER" --name-as filjob-box-din --dir "$INBOX" --relay \
  >>"$ROOT_DIR/din.log" 2>&1 &

log "starting file-driven watcher (--relay results on dout)"
FILJOB_ROOT="$ROOT_DIR" FILJOB_SERVER="$FILJOB_SERVER" FILAMENT_BIN="$BIN" \
  FILJOB_BOX_DOUT_CFG="$ROOT_DIR/cfg-dout" FILJOB_HOST_DOUT_PEER="$HOST_DOUT_NAME" \
  nohup python3 "$ROOT_DIR/watcher.py" --relay >"$ROOT_DIR/watcher.log" 2>&1 &
echo $! > "$ROOT_DIR/watcher.pid"
log "watcher up — pid $(cat "$ROOT_DIR/watcher.pid"), log: $ROOT_DIR/watcher.log"

# --- 4b. OPS SHELL (debug/inspection ONLY — not the job control plane) -------
# A small `up --shell --relay` acceptor on the ctl channel so an operator can
# `filament pty box` into the node to inspect it (logs, manifests, nvidia-smi,
# disk). This is deliberately separate from job control — jobs still run over the
# robust file-driven watcher; this is just a human/ops door. `--relay` for
# stability over flaky NAT. Disable with FILJOB_OPS_SHELL=0.
if [ "${FILJOB_OPS_SHELL:-1}" != "0" ]; then
  log "starting ops shell (up --shell --relay on ctl — inspection only)"
  FILAMENT_CONFIG_DIR="$ROOT_DIR/cfg-ctl" HOME="$ROOT_DIR/cfg-ctl" FILAMENT_L2=1 \
    nohup "$BIN" up --server "$FILJOB_SERVER" --shell --relay --name-as filjob-box-ops \
    --dir "$ROOT_DIR/ctldrop" >"$ROOT_DIR/ctl.log" 2>&1 &
  echo $! > "$ROOT_DIR/ctl.pid"
  log "ops shell up — pid $(cat "$ROOT_DIR/ctl.pid")  (host: filament pty box --relay)"
fi

sleep 3
log "din acceptor + watcher up. logs: $ROOT_DIR/din.log  $ROOT_DIR/watcher.log"
log "node ready. On the HOST, point FileRunnerBox / runner_cli at:"
log "  remote_inbox = $INBOX     (host pushes job+inputs here via din)"
log "  host-cfg knows box-in (din); dout-cfg is the host results sink (box-out)"
log "DONE — this box is now a file-driven filament job-runner node (no SSH, no PTY)."

# --- 5. keep the launching cell alive (persistence) -------------------------
# Colab-style cells stay alive only while the foreground command runs. Tail the
# watcher + din logs so the cell blocks here, the backgrounded processes keep
# running, and the user sees live "job picked up / done / sent results" output.
# (Skip the tail when FILJOB_NO_TAIL=1, e.g. for scripted/non-interactive use.)
if [ "${FILJOB_NO_TAIL:-0}" != "1" ]; then
  log "tailing watcher + din logs (Ctrl-C / kill the cell to stop the node) ..."
  exec tail -n +1 -F "$ROOT_DIR/watcher.log" "$ROOT_DIR/din.log" "$ROOT_DIR/ctl.log"
fi
