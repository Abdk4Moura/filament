# Filament e2e TEST + live-record pipeline (`pipeline.sh`)

A flag-controlled, async, GPU-aware pipeline that **tests** the filament UX by
driving the **REAL built app** against **REAL local filament peers** — and, when
recording, captures each flow live to an mp4 reel. It is a TEST first: it exits
**nonzero** if any selected case fails.

## The core principle — no mocks

There is **no `?preview=` mock seam** in the e2e path. Every case stands up
genuine peers and drives the genuine UI:

- **Real peers.** The locally-built binary `cli/target/release/filament` (built
  on demand if missing), each with its own isolated `FILAMENT_CONFIG_DIR` under
  `/tmp/ux-pipeline`, all signaling through a **local backend** we start on a free
  port. The CLI *is* a real peer (`filament up`, `filament up --shell`).
- **Real pairing.** A CLI peer mints a PAKE code (`filament pair`); Playwright
  **types it into the real pair box** ("pair with code" → `ENTER CODE` → `pair`) —
  the actual human gesture. Each case then asserts genuine DOM / `localStorage`
  state (e.g. the device landing in `filament-known-devices`, a live `ready` link,
  real PTY output rendered in xterm).
- `?preview=` stays ONLY for the pure-visual component reels (style switcher,
  annotator, mobile keys) — never the e2e seam.

## Run it

```bash
experiments/ux/pipeline.sh --help          # all flags
make -C experiments/ux e2e                 # full suite (or: make ux-e2e from repo root)
experiments/ux/pipeline.sh --suite web     # just the web e2e cases
experiments/ux/pipeline.sh --only pair-device,web-shell --sync
```

### Flags

| flag | meaning |
|------|---------|
| `--record` / `--no-record` | record a live Playwright reel per web case (default: record) |
| `--only <csv>` / `--skip <csv>` | select / deselect case ids |
| `--suite cli\|web\|runner\|all` | which family (default: all) |
| `--speed <x>` | gesture/playback speed hint |
| `--parallel <n>` | max concurrent web cases (default 1 — single-host ICE is contention-sensitive) |
| `--quality auto\|high\|min` | encode tier (default auto) |
| `--gpu-node <name>` | OPT-IN: offload the final encode to a filament GPU node (guarded) |
| `--async` / `--sync` | background the heavy encode/gallery (default) / wait |
| `--out <dir>` | reel output dir (default `gallery/`) |
| `--update-gallery` / `--no-update-gallery` | rebuild `index.html` + `reels.html` |

### Cases

- **web** (real app + real peers, real PAKE pairing):
  `pair-device`, `web-shell`, `device-sheet-mobile`, `device-sheet-desktop`,
  `sessions-dock`, `cmd-k`, `pwa-update`.
- **cli**: `cli-01 … cli-07`, `cli-11` — the existing `scenarios.sh` cli↔cli
  flows, forced onto the **locally-built** binary so the CLI peers are the same
  code under test as the web flows.
- **runner**: `runner-local` — the file-driven job runner over the **loopback**
  topology (`runner/run_local_test.sh`); isolated built binary + local backend.
  It never touches the live T4 or the live single-flight batch.

## Async

Recording/encoding is **async by default**: a case's heavy webm→mp4 transcode is
kicked into the **background** so the test loop doesn't block. Background jobs are
tracked (`.pipe/bg/<tag>.pid`) and **joined before the gallery is rebuilt**, so
reels always land before `index.html`/`reels.html` are written and no processes
leak. `--sync` runs the encode inline.

## GPU-aware quality tiers (`--quality auto`)

`lib/quality.sh` always transcodes the recorded VP8/webm (the cached chromium is
the open-source build with no H.264) to a real **H.264 mp4**, choosing a tier:

- **GPU present** (local `nvidia-smi` + `h264_nvenc` in ffmpeg) → **high** tier:
  high res/bitrate via **NVENC**. NVENC uses the **CPU-decode** path (full-cuda
  decode is broken on our T4) — only the encode is on the GPU.
- **`--gpu-node <name>`** (opt-in) → offload the final encode to a filament GPU
  node by **submitting an NVENC ffmpeg job** to the box via `runner/runner_cli.py`
  (the worked example from the runner docs) and fetching `out.mp4`. **Guarded**:
  it refuses unless you provide the box config (`FILJOB_HOST_CFG`,
  `FILJOB_HOST_DOUT_CFG`) AND the live-batch lock (`FILJOB_BATCH_LOCK`, default
  `/tmp/filament-runner-batch.lock`) is **absent**; it uses a short
  `--submit-deadline` so a busy box fails fast and falls back to CPU. It never
  contends with the live single-flight batch.
- **No GPU** → **min** tier: a functional CPU `libx264` encode (modest res/fps).
- `--quality high|min` force a tier.

Every produced mp4 is validated with **ffprobe** (H.264 stream, nonzero
duration) before it's accepted as a reel.

## What's robust vs environmental

- `pair-device`, `cli-*`, `runner-local`, and the GPU/async machinery work fully.
- `web-shell` / `sessions-dock` / `cmd-k` drive a **live browser↔`up --shell`
  WebRTC data channel** for a real PTY. That single-host browser↔CLI path is
  ICE/data-channel-timing-sensitive (the harness documents the same constraint for
  scenario 09); the drivers wait for a real `ready` link and retry, and pass when
  the channel stabilizes. On real cross-host hardware they are unconditional.

## After a change

Run `make -C experiments/ux e2e` (or `experiments/ux/pipeline.sh`). A nonzero exit
means a real flow regressed. Reels for the changed flows are refreshed in
`gallery/` and surfaced in `gallery/reels.html`.

### Optional pre-push / CI hook (documented, not installed)

```bash
# .git/hooks/pre-push (opt in by copying this in)
#!/usr/bin/env bash
exec experiments/ux/pipeline.sh --suite web --no-record --quality min || {
  echo "e2e regressed — push blocked"; exit 1; }
```
A CI job would do the same on a runner with a GPU and `--quality high`.
