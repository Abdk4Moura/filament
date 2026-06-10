# Filament CLI — visual UX test harness

A self-contained, human-watchable test harness for the Filament CLI's user-facing
flows. Each scenario drives the **real** `/root/.local/bin/filament` against a
**local** signaling backend, asserts the outcome (sha256 of transferred bytes,
derived channel ids, stored devices, remote command output), and records a GIF a
person can watch. Ten scenarios cover both `cli↔cli` and `cli↔web` directions.

The harness is **self-safe**: every `filament` call points at a throwaway
`FILAMENT_CONFIG_DIR` under `/tmp/ux`, the backend runs on a non-default port
(8077), and teardown kills **only** processes this harness started. The user's
real `~/.config/filament`, their running `filament up` daemon, and a Vite dev
server on port 5180 are never touched.

## Run it

```bash
./run.sh                 # all 10 scenarios, build gallery, tear down
./run.sh 01 03 06        # a subset
PARALLEL_CLI=1 ./run.sh  # (knob) run cli↔cli scenarios concurrently
```

Single scenario, manually:

```bash
bash record.sh 05 100 28          # cli↔cli: cast → GIF + RESULT
bash web-scenarios.sh 08          # cli↔web: CLI cast + browser webm → side-by-side GIF
bash scenarios.sh 07              # run a cli↔cli scenario WITHOUT recording (just assert)
python3 gallery.py                # rebuild gallery/index.html + results.json from results-*.txt
```

Open `gallery/index.html` to see every flow with its caption and PASS/FAIL badge.

## Tools + how they were installed

| Tool | Role | Install |
|---|---|---|
| **asciinema 3.0** | record the CLI terminal as `asciicast-v2` | prebuilt binary → `bin/asciinema` |
| **agg 1.5** | render an asciicast → GIF | prebuilt binary → `bin/agg` |
| **Playwright 1.52 + chromium** | drive the web app, record the tab as webm | `npm i` in this dir; `npx playwright install chromium` (cached under `~/.cache/ms-playwright`) |
| **ffmpeg** | webm → GIF (palette), side-by-side `hstack` compose | system package |
| **gifsicle 1.94** | final lossy + `-O3` optimize pass on the composed GIF | `apt-get install gifsicle` |
| **Filament backend** | local signaling server (eventlet) on port 8077 | repo `backend/app.py`, run from a venv python; frontend rebuilt same-origin with `VITE_FILAMENT_API=` |

## Scenarios

| # | Flow | What it proves |
|---|---|---|
| 01 | cli↔cli | `pair`: A mints a PAKE code, B claims it; both derive the same channel id (no key crosses the server) |
| 02 | cli↔cli | `devices` list / rename / forget — **and** the regression guard: forgetting one device must not wipe another's granted `shell` cap |
| 03 | cli↔cli | `send --word` one-time code → `recv`; bytes sha256-verified end-to-end |
| 04 | cli↔cli | `send --to` a known device: no code, identity proof-verified, auto-accepted; bytes verified |
| 05 | cli↔cli | always-on receiver `up` / `status` / `down`, with a paired send into it; bytes verified |
| 06 | cli↔cli | `grant shell` (deny-by-default consent) then `ssh peer -- echo OK` over the data-channel tunnel |
| 07 | cli↔cli | `introduce`: a hub that knows two devices vouches them to each other with a fresh mutual secret |
| 08 | cli↔web | CLI sends → the web app accepts the offer and reaches the download (save) affordance |
| 09 | cli↔web | the web app sends → CLI `recv` writes it, sha256-verified (see decoupling note below) |
| 10 | cli↔web | `pair` the web app with the CLI: CLI mints a PAKE code, the browser claims + stores the device |

## Measured runtimes

Wall-clock per scenario (record + render), local backend, sequential, on this VM:

<!-- TIMINGS:BEGIN -->
| # | flow | wall-clock | notes |
|---|---|---|---|
| 01 | cli↔cli | 2 s | pair |
| 02 | cli↔cli | 3 s | devices list/rename/forget + regression |
| 03 | cli↔cli | 27 s | **decoupled**: verify ~4 s + 22 s best-effort cast box |
| 04 | cli↔cli | 5 s | send --to known device |
| 05 | cli↔cli | 7 s | up / status / down |
| 06 | cli↔cli | 15 s | **decoupled**: verify ~6 s + best-effort cast box (ssh tunnel) |
| 07 | cli↔cli | 6 s | introduce |
| 08 | cli↔web | 7 s | CLI → web |
| 09 | cli↔web | 79 s | **decoupled**: no-recorder verify pass + best-effort visual + webm→GIF |
| 10 | cli↔web | 16 s | pair web ↔ CLI |
| | **TOTAL** | **~167 s** | sequential, clean slate |

> **Caveat measured the hard way:** scenario 06 clocked **549 s** in one pass —
> caused entirely by leftover throwaway `sshd` processes from earlier runs piling
> up and starving the single-host WebRTC/ssh handshakes. With self-cleaning sshd
> (the scenario now tears down its own `sshd`) and a clean slate, 06 is **15 s**.
> The decoupled scenarios' verdicts always come from their no-recorder verify
> passes, so a wedged cast never produces a wrong PASS/FAIL.
<!-- TIMINGS:END -->

**Dominant cost:** the `cli↔web` scenarios (08, 09, 10). The `cli↔cli` scenarios
are seconds each (pair ~2 s; a transfer + assert ~5–7 s). The web scenarios pay
for a headless chromium launch (~2–4 s), WebRTC establishment, a webm video
recording, and the webm→GIF + side-by-side `hstack` compose. Scenario 09 pays
twice over (a no-recorder verify pass **and** a best-effort visual pass).

### Mitigation knobs

- **Own local backend** on `127.0.0.1:8077` — no WAN/TURN latency; both peers on
  loopback share the same auto-room.
- **`PARALLEL_CLI=1`** — record the independent `cli↔cli` scenarios concurrently
  (each uses its own config dir + room).
- **`FILAMENT_REJOIN_SECS` low** (set to 2–3 in the scenarios) — a completed
  `recv -y` otherwise lingers the full rejoin window after the sender drops.
- **agg `--speed` / `--idle-time-limit`** and **ffmpeg `fps` + `scale` + palette**
  + **gifsicle `--lossy`** — trim idle time and quantize so GIFs are a few MB,
  not tens of MB (08 went from ~13 MB, 09 from ~29 MB down to single-digit MB).
- **mDNS-off chromium flags** (`--disable-features=WebRtcHideLocalIpsWithMdns
  --force-fieldtrials=WebRTC-Mdns/Disabled/`) — required for single-host
  CLI↔browser ICE to complete at all (see blockers).

## Blocked / decoupled flows and their precise blockers

### Scenario 09 (web → CLI) — decoupled verify + visual

Single-host **browser → CLI** WebRTC is the most contention-sensitive flow in the
suite. The transfer is GREEN standalone (sha256 matches, ~11 MB/s), but when a
Playwright **webm recorder** runs concurrently on the same host, the browser→CLI
ICE / data-channel timing reliably wedges (`recv` interrupts, no bytes land).
This is a **recording-contention** artifact, not a product break.

So scenario 09 is split:
1. **Verify pass (authoritative):** runs the real browser→CLI transfer with **no
   video recorder** and asserts the sha256. This produces the PASS/FAIL verdict.
   Retried up to 3×.
2. **Visual pass (best-effort):** separately records the browser tab for the GIF.
   Its outcome does **not** change the verdict; if recorder contention breaks the
   transfer, the GIF still shows the attempt. The gallery labels this.

### Single-host CLI↔browser ICE needs mDNS disabled

Headless chromium masks loopback host ICE candidates behind mDNS `.local` names
the CLI's WebRTC stack can't resolve, so single-host CLI↔browser ICE wedges with
an unhelpful `connection stuck while connecting — retrying`. The drivers launch
chromium with the two mDNS-off flags above to emit real `127.0.0.1` candidates.
(Real cross-host CLI↔browser uses real IPs and is fine; this is purely a
single-host test accommodation.)

### Single-host CLI↔CLI ICE under the recorder (03 and 06)

Two single-host CLI↔CLI flows wedge under asciinema recorder load even though
both are GREEN standalone:
- **03** — the anonymous `send --word` ↔ `recv` path opens ICE between two fresh
  ephemeral peers; the first `connecting…` attempt can wedge.
- **06** — the `ssh`-over-tunnel handshake can wedge after the data channel is up.

Both are **decoupled** the same way as 09: a no-recorder **verify pass** gives the
authoritative verdict, and a short time-boxed (`timeout -k 5 22`) **best-effort
cast** provides the GIF. (`--to`/`up` known-device transfers — 04/05 — don't show
this.) Scenario 06 also now tears down its own throwaway `sshd` so stale daemons
don't accumulate and starve later runs — that accumulation, not the product, was
behind a 549 s outlier (see timings).

## Product UX findings (punch-list)

These are real product behaviors the harness surfaced (not harness bugs):

1. **`send --name X` does not rename the received file.** The receiver (`recv`,
   `up`, and `--to`) always saves under the **sender's source basename**,
   silently ignoring `--name`. Confusing: the flag looks like it sets the saved
   name. (Worked around in the harness by hash-verifying bytes regardless of
   filename.)
2. **`recv -y` lingers** the full rejoin window after a completed transfer when
   the sender disconnects first — no prompt-exit on success. Slows demos; needs a
   low `FILAMENT_REJOIN_SECS` or an outer `timeout`.
3. **`filament devices` does not surface granted capabilities.** You can't see
   which devices hold `shell` without reading `devices.json` by hand.
4. **Two non-interchangeable "code" systems.** `filament pair` mints a 4-segment
   PAKE code; `filament send --word/--code` mints a 3-segment legacy
   file-transfer code. The browser's "pair with code" only consumes the PAKE
   code; it cannot claim a `send` code — confusing given both are called "codes."
   (So cli↔web file transfer uses the shared auto-room, not a code.)
5. **Single-host CLI↔browser WebRTC is unusable without disabling chromium mDNS,**
   and the failure mode (`connection stuck while connecting — retrying`) gives no
   hint that it's an ICE/mDNS issue.
6. **Single-host CLI↔CLI word-code ICE can wedge** on a first `connecting…`
   attempt under load, with the same unhelpful "stuck while connecting" message
   and (for `send`, which had no built-in timeout) an unbounded hang.

## Layout

```
run.sh             one-command suite (rig up → record all → gallery → teardown)
record.sh          record ONE cli↔cli scenario: cast → GIF + RESULT line
scenarios.sh       cli↔cli scenario bodies (01–07)
web-scenarios.sh   cli↔web scenario bodies (08–10): CLI cast + browser webm → GIF
web/*.js           Playwright browser halves (recv/send/pair, ±video)
rig/lib.sh         self-safe primitives: backend up/down, throwaway config dirs,
                   kill-only-ours
gallery.py         build gallery/index.html + results.json from .work/results-*.txt
bin/               asciinema + agg prebuilt binaries
casts/             recorded asciicasts
gallery/           the GIFs + index.html + results.json (the deliverable)
.work/             logs, payloads, raw webm, timings.txt (scratch)
```
