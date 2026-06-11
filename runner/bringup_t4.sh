#!/usr/bin/env bash
# filament job-runner — T4 BRING-UP (SSH-FREE).
#
# Paste this on a fresh, ephemeral Tesla T4 (Colab-style, glibc 2.35, no inbound
# SSH) to turn it into a filament job-runner NODE. It installs only what jobs
# need, drops the STATIC musl `filament` binary (a dynamic binary won't run on the
# T4's glibc), plants the three pairing secrets, and starts the box-side
# acceptors. It NEVER installs openssh/sshd (that shuts the box down).
#
# It does NOT drive the box; it just makes the box reachable as a job runner. The
# HOST then submits jobs with runner/filament_runner.py.
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
    curl -fsSL "$FILAMENT_URL" -o "$BIN"
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

# put filament on PATH for the PTY login shell (host invokes `filament send` there)
ln -sf "$BIN" /usr/local/bin/filament 2>/dev/null || true

# --- 3. plant the three pairing secrets (isolated config dirs) --------------
# Each acceptor/initiator role gets its OWN config dir holding exactly ONE secret,
# so no daemon ever subscribes to a channel it shouldn't (which would glare).
python3 - "$ROOT_DIR" "$SEC_CTL" "$SEC_DIN" "$SEC_DOUT" \
         "$HOST_CTL_NAME" "$HOST_DIN_NAME" "$HOST_DOUT_NAME" <<'PY'
import json, sys
root, ctl, din, dout, n_ctl, n_din, n_dout = sys.argv[1:8]
json.dump([{"name": n_ctl,  "secret": ctl}],  open(f"{root}/cfg-ctl/devices.json",  "w"))
json.dump([{"name": n_din,  "secret": din}],  open(f"{root}/cfg-din/devices.json",  "w"))
json.dump([{"name": n_dout, "secret": dout}], open(f"{root}/cfg-dout/devices.json", "w"))
print("[bringup] planted ctl/din/dout device secrets")
PY

# --- 4. start the box-side acceptors (NO sshd) ------------------------------
# ctl : up --shell  -> serves the control PTY the host drives the executor over.
# din : up --dir    -> receives pushed inputs (host `send`) into the inbox.
# The dout channel needs NO daemon on the box: the box only `send`s on it (the
# host stands up the dout sink transiently during fetch).
# Kill only PREVIOUSLY-tracked acceptors via their pid files — never pkill -f on
# a pattern that also appears in THIS script's own command line (when the script
# is run via `bash -c "$(curl …)"`, the whole script text is the process argv, so
# a `pkill -f "filament up …cfg-ctl"` would match and SIGTERM this very process).
for p in "$ROOT_DIR/ctl.pid" "$ROOT_DIR/din.pid"; do
  [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true
done
sleep 1

log "starting ctl acceptor (up --shell)"
FILAMENT_CONFIG_DIR="$ROOT_DIR/cfg-ctl" HOME="$ROOT_DIR/cfg-ctl" FILAMENT_L2=1 \
  nohup "$BIN" up --server "$FILJOB_SERVER" --shell --name-as filjob-box-ctl \
  --dir "$ROOT_DIR/ctldrop" >"$ROOT_DIR/ctl.log" 2>&1 &
echo $! > "$ROOT_DIR/ctl.pid"

log "starting din acceptor (input sink -> $INBOX)"
FILAMENT_CONFIG_DIR="$ROOT_DIR/cfg-din" HOME="$ROOT_DIR/cfg-din" \
  nohup "$BIN" up --server "$FILJOB_SERVER" --name-as filjob-box-din \
  --dir "$INBOX" >"$ROOT_DIR/din.log" 2>&1 &
echo $! > "$ROOT_DIR/din.pid"

sleep 3
log "acceptors up. logs: $ROOT_DIR/ctl.log  $ROOT_DIR/din.log"
log "node ready. On the HOST, point RunnerBox at:"
log "  remote_jobs_root = $ROOT_DIR     remote_inbox = $INBOX"
log "  box_dout_config_dir = $ROOT_DIR/cfg-dout"
log "DONE — this box is now a filament job-runner node (no SSH, jobs only)."
