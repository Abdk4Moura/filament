# Filament CLI — visual UX test harness

A self-contained, human-watchable test harness for the Filament CLI's user-facing
flows. Each scenario drives the **real** `/root/.local/bin/filament` against a
**local** signaling backend, asserts the outcome (sha256 of transferred bytes,
derived channel ids, stored devices, remote command output), and records a GIF a
person can watch. Ten scenarios cover both `cli↔cli` and `cli↔web` directions.

The harness is **self-safe**: every `filament` call points at a throwaway
`FILAMENT_CONFIG_DIR` under `/tmp/ux`, each backend runs on a free loopback port
(base 8071+, skipping ports other tenants own) and carries the marker
`FIL_UX_RIG=1`, and teardown kills **only** processes this harness started
(tracked children + backends bearing that marker). The user's real
`~/.config/filament`, their running `filament up` daemon, the Vite dev servers on
5180/5181, and a gallery server on 8095 are never touched.

## Run it

```bash
./run.sh                 # all 10 scenarios (parallel), build gallery, tear down
./run.sh 01 03 06        # a subset
SEQUENTIAL=1 ./run.sh    # one-at-a-time (debugging / the old behaviour)
JOBS=3 ./run.sh          # cap concurrency (default 4)
SPEED=fast ./run.sh      # render faster (SPEED knob — see below)
```

### Parallelism

`run.sh` runs scenarios **concurrently in isolated rigs**. Each scenario gets its
own backend on its own **free port** (the runner skips 5000/5077/5180/5181/8061/
8077/8095 — the user's daemon, the dev servers, the gallery server, and another
agent's rig), its own throwaway config root `/tmp/ux/<id>`, and its own scratch
dir `.work/<id>`, so concurrent scenarios cannot interfere. A bounded job pool
(`JOBS`, default 4) keeps load sane; wall-clock drops toward the slowest
scenario. Every backend the harness starts carries the marker `FIL_UX_RIG=1`;
teardown kills **only** tracked children and backends bearing that marker.

Scenario **09** is a **solo tail**: its authoritative no-recorder verify pass of
single-host browser→CLI WebRTC wedges if *any* other recorder/chromium runs on
the same host (documented contention below), so it runs **alone after** the
parallel batch drains, on a quiet host. `SOLO_IDS="09"` controls this set.

### SPEED knob

Render speed (asciinema idle trim + agg playback speed) is a tunable:

```bash
SPEED=normal ./run.sh    # agg --speed 1.3, idle 1.4   (default)
SPEED=fast   ./run.sh    # agg --speed 2.5, idle 0.8   (snappier GIFs)
SPEED=slow   ./run.sh    # agg --speed 1.0, idle 2.0   (dwell on each step)
AGG_SPEED=2.0 IDLE_LIMIT=1.0 ./run.sh   # raw override (beats the profile)
```

A scenario can also request its own pace for a key moment via
`SCENARIO_SPEED_<id>` / `SCENARIO_IDLE_<id>` (e.g. `SCENARIO_SPEED_01=1.0` to
slow the pairing handshake). Precedence: raw `AGG_SPEED`/`IDLE_LIMIT` > per-
scenario > `SPEED` profile. The knob threads through both `record.sh` (cli↔cli
cast→GIF) and `web-scenarios.sh` (the cli cast + webm→GIF steps).

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

Wall-clock per scenario (record + render), isolated local backends, on this
4-core VM. The suite now runs **parallel** (light scenarios batched at `JOBS=2`,
then the four single-host ICE flows — 03/06/08/09 — as a sequential **solo tail**
on a quiet host so their fragile transfers don't wedge under contention). Old
fully-sequential total was **~167 s**.

<!-- TIMINGS:BEGIN -->
Parallel run (`JOBS=2` batch + sequential solo tail), all 10 PASS, 4-core VM:

| # | flow | phase | wall-clock | notes |
|---|---|---|---|---|
| 01 | cli↔cli | batch | 3 s | pair |
| 02 | cli↔cli | batch | 4 s | devices list/rename/forget + regression |
| 04 | cli↔cli | batch | 4 s | send --to known device |
| 05 | cli↔cli | batch | 5 s | up / status / down |
| 07 | cli↔cli | batch | 6 s | introduce |
| 10 | cli↔web | batch | 17 s | pair web ↔ CLI |
| 03 | cli↔cli | **solo** | 27 s | **decoupled**: verify ~4 s + 22 s best-effort cast box |
| 06 | cli↔cli | **solo** | 42 s | **decoupled** ssh tunnel: verify + best-effort cast + ssh retries |
| 08 | cli↔web | **solo** | 7 s | CLI → web (timeout-boxed cast + ≤2 attempts) |
| 09 | cli↔web | **solo** | 77 s | **decoupled**: no-recorder verify pass + best-effort visual + webm→GIF |
| | | | **~179 s** | parallel batch (~26 s) + sequential solo tail (03·06·08·09) |

The batch (six light scenarios) overlaps and finishes in ~26 s; the four
single-host ICE flows (03·06·08·09) then run **one at a time** on a quiet host —
that solo tail is the long pole. The old fully-sequential best case was ~167 s but
flaky under contention; this layout trades a little wall-clock for a **reliable,
deterministic 10/10** (no contention-induced failures, no leftover-process
starvation between runs). Raise `JOBS` / shrink `SOLO_IDS` on a bigger box.

> **Caveats measured the hard way:**
> - Scenario 06 once clocked **549 s** purely from leftover throwaway `sshd`
>   procs accumulating and starving the single-host handshakes; with self-cleaning
>   sshd + clean-slate isolated rigs it's ~40 s.
> - On this 4-core box, running >2 heavy scenarios at once (or any two recorder
>   scenarios together) saturates the cores and wedges single-host WebRTC/ssh ICE
>   and even eventlet backend boots — hence `JOBS` auto-caps at `nproc/2` and the
>   ICE flows are a sequential solo tail. `backend_start` also retries on a fresh
>   port if a boot gets starved.
> - The decoupled scenarios' verdicts always come from their no-recorder verify
>   passes, so a wedged cast never produces a wrong PASS/FAIL.
<!-- TIMINGS:END -->

**Dominant cost:** the `cli↔web` scenarios (08, 09, 10). The `cli↔cli` scenarios
are seconds each (pair ~2 s; a transfer + assert ~5–7 s). The web scenarios pay
for a headless chromium launch (~2–4 s), WebRTC establishment, a webm video
recording, and the webm→GIF + side-by-side `hstack` compose. Scenario 09 pays
twice over (a no-recorder verify pass **and** a best-effort visual pass).

### Mitigation knobs

- **Own local backend** on a free loopback port (per-scenario, base 8071+) — no
  WAN/TURN latency; both peers on loopback share the same auto-room.
- **Parallel isolated rigs** (default `JOBS=4`) — every scenario runs in its own
  backend + config root + room, so the suite finishes near the slowest scenario
  (09's solo tail) rather than the sum. `SEQUENTIAL=1` falls back to one-at-a-time.
- **Event waits, not blind sleeps** — scenarios now wait on deterministic signals
  (the `filament up —` ready banner, `recv`'s `● listening` line, the sender's
  `code <word>` line, the sshd port opening) via the `wait_for` / `wait_log`
  helpers in `rig/lib.sh`, instead of fixed `sleep 3/4`. Faster and less flaky.
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
