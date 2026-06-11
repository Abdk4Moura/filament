# Filament GPU Job-Runner — Challenges & Diagnosis

*Living engineering log. Started 2026-06-11. Context: offloading GPU work (NVENC
transcode, headless render) to an ephemeral, no-SSH Tesla T4 (Colab-style) reached
only over filament's P2P transport. See `docs/research/remote-accelerator-offload.md`
for why we build our own runner rather than adopt SkyPilot/Ray (no orchestrator can
attach to a box you can't `sshd` into).*

---

## Goal

Submit a named compute job to the T4, run it, and get the artifacts + a manifest
back — over filament, with **no SSH** on the box, and in a shape that reads as
"submit/await/fetch a job" (policy-clean) rather than "shell into a host."

## Architecture under test (v1 — three channels, interactive PTY control)

The first runner used **three filament channels**, one acceptor each, to dodge the
"two acceptors on one signaling channel glare" problem found during the local test:

| Channel | Box side | Host side | Purpose |
|---------|----------|-----------|---------|
| `ctl`   | `up --shell` (PTY acceptor) | `pty box` | host drives the box-side executor over an **interactive PTY**, streams progress |
| `din`   | `up --dir .inbox` | `send` | push the job spec + executor + inputs to the box |
| `dout`  | `send` (transient) | `up` sink | pull declared outputs back |

The local **loopback** test (host + box on one machine, localhost transport) passed
deterministically — real transcode byte-correct, timeout handled. **The WAN/Colab
run did not.** That gap is the subject of this doc.

---

## What works ✅

1. **Bring-up** (after the self-kill fix below) — fetches the static-musl binary,
   installs ffmpeg/NVENC, plants the three channel secrets, starts the acceptors.
2. **`din` input push is reliable enough** — over the real link, the box log shows all
   three inputs arriving in the inbox:
   ```
   ✓ box_executor.py  8.8 KB
   ✓ job.json  573 B
   ✓ input.mp4  956.6 KB → /root/filament-jobs/.inbox/
   ```
   It even **re-sent** the set on a retry (`job.json.1`, `input.mp4.1`), i.e. the
   transfer *recovers* from the link dropping. **The box already has everything it
   needs to run the job.**
3. **`ctl` PTY does open box-side** — `l2: pty granted to 'host' — 220x50`, `✓ host`,
   `route: direct-quic`. The control shell establishes.

## What fails ❌

**The WAN link is unstable; the long-lived PTY control session cannot survive it.**

Box-side evidence (Colab T4 → do-vm, direct-QUIC to 165.22.207.231):
```
ctl.log:  known device 'host' appeared — connecting   (x many)
          DIRECT-CONNECT ok (route: direct-quic) ... l2: pty granted to 'host'
          ... ✓ host ...                              (connects, grants PTY)
          known device 'host' appeared — connecting   (then re-dials, repeatedly)
          ! interrupted — partials kept

din.log:  ✓ root@do-vm ... ✓ input.mp4 ...            (transfer succeeds)
          ◌ root@do-vm reconnecting…
          connection stuck while connecting — retrying (2/3)
          connection stuck while connecting — retrying (3/3)
          dropping peer (connection stuck while connecting after 3 attempts)
```

Host-side symptom: `runner_cli.py` prints `submitting j-…` and then **hangs in
`open_session()`** for the entire timeout, producing no further output, because it is
waiting on a PTY control session that keeps dropping and re-dialing. It never gets a
stable shell to run the executor + read its sentinel-framed output, so it blocks.

## Root cause

- **Connection instability over the Colab→do-vm WAN path.** Direct-QUIC establishes
  and then drops within seconds (`connection stuck while connecting`, `dropping peer
  after 3 attempts`, `reconnecting…`). This is a NAT/path-stability problem, not a
  filament logic bug — and notably the **earlier successful T4 reel pipeline used the
  TURN *relay* route**, not direct-QUIC.
- **A long-lived interactive PTY is the wrong abstraction for a flaky link.** It needs
  one continuous, ordered, bidirectional stream to stay up for the whole job. Every
  drop kills it mid-run. By contrast, **discrete file transfers tolerate the drops** —
  they retry/resume and the bytes eventually land (proven by `din` above). We built the
  control plane on the one primitive that *can't* absorb the instability.

---

## Bugs found & fixed

1. **Bring-up self-kill (`Terminated` right after planting secrets).** `bringup_t4.sh`
   cleaned up prior runs with `pkill -f "filament up .*cfg-ctl"`. When the script is run
   via `bash -c "$(curl …)"`, the **entire script text is the process argv**, so that
   `pkill` pattern matched the bring-up's *own* process and SIGTERM'd it before the
   acceptors ever started. The local test ran it as a *file* (`bash bringup_t4.sh`),
   whose cmdline doesn't contain the pattern — so it never reproduced there.
   **Fix** (commit `e6b97da`): replace the `pkill -f` cleanup with pid-file-based kills
   (`kill $(cat ctl.pid)`), which can never match the script's own argv. Run-as-file
   also sidesteps it.
2. **Stale release binary.** The published `cli-v0.2.1-beta.4` musl asset was commit
   `35221d5` — it predated `up --shell`, so it couldn't serve the control channel.
   **Stop-gap (now superseded):** a one-off static-musl build was published as asset
   `filament-x86_64-unknown-linux-musl-shell` on the beta.4 release.
   **Fixed:** cut `cli-v0.2.1-beta.5` (commit `4d7406f`) via the CI release workflow.
   Its standard `filament-x86_64-unknown-linux-musl.tar.gz` asset is static-pie and has
   `--shell` + `--dir`. The one-off `…-musl-shell` asset is now retired; repoint the T4
   bring-up's `FILAMENT_URL` to the beta.5 standard musl asset:
   `https://github.com/Abdk4Moura/filament/releases/download/cli-v0.2.1-beta.5/filament-x86_64-unknown-linux-musl.tar.gz`

---

## Recommended path forward

### Primary: replace the interactive-PTY control plane with a **file-driven watcher**

Drop the `ctl` PTY entirely. The box runs a tiny **watcher loop** that polls its inbox
for a `job.json`, executes the declared job (the same fixed `box_executor.py` logic),
and drops `manifest.json` + the declared outputs into an **outbox** that flows back over
a file channel. The whole flow then uses **only file transfers** (push job → pull
results), which the logs prove survive the link instability. Benefits:

- **Robust to the exact failure we hit** — no long-lived stream to drop.
- **Even more policy-clean** — *no shell at all*; a job spec in, a manifest out.
- **The inputs already stage successfully**, so we're most of the way there: the box
  has `job.json` + `box_executor.py` + `input.mp4` in its inbox right now.

Sketch: box `watcher.py` (poll `.inbox/job-*.json` → run executor in a scratch dir →
write `.outbox/<id>/{manifest.json,outputs…}` → `filament send` the outbox dir to the
host, or host polls via a transient sink). Host `submit()` pushes a job and waits for
the manifest to arrive over the file channel.

### Secondary, stacks with the above: **force the TURN relay route**

The unstable path is direct-QUIC; the earlier working T4 pipeline used **relay**. Pass
`--relay` on the box/host transfers (or make the runner default to relay for WAN boxes).
Slower than direct, but stable — and for minutes-long transcode/render jobs, throughput
of the control path is irrelevant.

### Quick proof available now

The box already holds a complete job in `.inbox/`. Running the staged executor by hand
on the box (`python3 .inbox/box_executor.py …`) would prove NVENC + the 2× T4 works and
produce the output locally, which we then pull back over the file channel — a manual
dry run of exactly what the watcher will automate.

---

## Open items

- [x] Build the file-driven watcher control plane (box `watcher.py` + host submit/await).
      **Done** — `runner/watcher.py` (box poll loop: inbox → run via `box_executor.run_job`
      → ship manifest+outputs on dout) + `FileRunnerBox` in `runner/filament_runner.py`
      (host `submit`/`await_results`, no PTY). The `ctl` PTY is dropped from the control
      flow; din/dout secrets are reused unchanged (no re-pairing). Loopback e2e passes
      deterministically (real transcode byte-correct via sha256, timeout → exit 124),
      3/3 runs.
- [x] Default the runner to **relay** for WAN boxes. **Done** — `--relay` is the default
      on both the box watcher's result `send` and the host's `send`/`up` (the local
      loopback test passes `--no-relay` since TURN isn't available on localhost).
      *(Auto-fall-back on N direct drops is not implemented; relay is simply the default —
      a cleaner choice than racing direct first.)*
- [ ] Confirm the box actually exposes **2× T4** to `nvidia-smi -L` (bring-up logged a
      single "Tesla T4"); then add per-GPU dispatch (`-hwaccel_device 0/1`) for parallel
      jobs across both cards. *(Manifest now records ALL gpus via `nvidia-smi -L` as
      `gpus`; the watcher has a documented DISPATCH HOOK (`_claim_next`) — result-shipping
      already runs in a background thread so jobs pipeline; only per-GPU concurrent
      execution remains.)*
- [x] Cut a proper `beta.5` release so the public musl binary has `--shell` (done:
      `cli-v0.2.1-beta.5`, commit `4d7406f`; the one-off `…-musl-shell` asset is now
      superseded and can be retired).
- [ ] Add R2 durability (`rclone` is a no-op until creds are set) so artifacts survive
      the box dying even if the last-mile pull is mid-retry.

---

## Transport robustness pass (2026-06-11) — local flaky-link repro + runner resilience

The file-driven control plane removed the long-lived PTY, but the *file transfers
themselves* still failed intermittently over the real Colab→do-vm link in BOTH
directions: `send` couldn't always find the peer within 60s (`no peer connected`),
and the box→host result transfers truncated (a 7 KB partial of a multi-MB file,
`moov` missing) with the small `manifest.json` completion signal never arriving.
This pass makes the runner robust against that instability and adds a deterministic
LOCAL reproduction so the fix is validated without a real T4.

### Layer A — the core discovery race (investigated; already fixed in `main`'s CLI)

The chronic cross-machine discovery flakiness diagnosed in the Python signaling
harness (`experiments/`, memory `filament-signaling-harness.md`) was a **Rust client
discovery race**, with a fix set on `transport-direct-quic`:

| commit | fix |
|--------|-----|
| `a78de6a` | subscribe on `welcome` (don't subscribe before the socket.io connection is proven up — the original race) |
| `8f1ef99` | perfect-negotiation glare rules (impolite ignores colliding offers; polite rebuilds as responder) |
| `fcf13b1` | L2 candidate rotation (one attempt at a time; signals applied only for the current attempt) |
| `cc083a7` | server liveness (lease + alive-gates on roster/known-peer emission) |
| `a95f049` | self-connect refusal (#9 security) |

**Finding: ALL FIVE are already ancestors of `origin/main`** (verified with
`git merge-base --is-ancestor`), and of the exact binary the runner builds and runs
(`cli/target/release/filament`, commit `2d3cdd0`). So the runner already uses a CLI
with the discovery-race fixes; there is **no tractable, un-merged core fix left to make
in this pass**. The harness gate (`experiments/robust_test.sh suite`) is the regression
guard for that layer. The *residual* WAN intermittency is transport/path instability
(NAT, link drops, mid-stream resets) — not a signaling-logic bug — and is handled by
Layer B. We deliberately made **no speculative core changes** we couldn't validate here.

### Deliverable 1 — deterministic LOCAL flaky-link reproduction

`runner/sim/` reproduces the three failure modes with NO remote box:

- `flaky_proxy.py` — a stdlib TCP proxy between every filament CLI client and the
  LOCAL signaling backend. filament's discovery + SDP/ICE ride that socket.io link,
  so when a control file is present the proxy **severs live connections and refuses
  new ones** (the local equivalent of the WAN path dropping). A background *flapper*
  also drops the link on a randomised schedule for the whole run.
- `flaky_e2e.py` + `flaky_sim_test.sh` — boot an isolated topology (own backend port,
  isolated config dirs, the locally-built binary) with the proxy in the middle, then:
  - **(a) discovery race**: force the link DOWN at submit. A single `send` fails at
    `/api/room` / establishment; the host's retry-until-peer loop lands the push after
    healing.
  - **(b) truncation**: a chaos thread drops the link mid result-transfer; the host's
    sha256 integrity gate rejects the partial and keeps awaiting.
  - **(c) lost manifest**: drops land in the manifest's arrival window; the box re-ships
    until the host ACKs.
  - Run: `runner/sim/flaky_sim_test.sh` (`FILJOB_KEEP=1` to keep the work dir).

### Layer B — runner resilience (the guaranteed deliverable)

Per-file changes (`runner/filament_runner.py`, `runner/watcher.py`,
`runner/runner_cli.py`):

- **Retry-until-peer.** Host `FileRunnerBox._send` and box `Watcher._send` set
  `FILAMENT_SEND_TIMEOUT` to a *bounded* per-invocation value (default 45s) — a wedged
  establishment is abandoned and **re-invoked** (a fresh connect clears a stuck
  candidate pair), and the retry LOOP keeps re-invoking with backoff until the peer
  appears or a generous overall deadline (`submit_deadline_s` / `reship_deadline_s`,
  default 1800s). No more single-shot 60s give-ups. (0 = wait-forever is supported but
  discouraged: one hung send would stall the loop.)
- **Integrity + resume-to-completion.** `await_results` accepts a result set ONLY when
  a manifest for the job is present AND every declared non-missing output's sha256
  matches the manifest. A truncated/partial output fails verification, so the host
  never accepts it; it keeps awaiting while the box re-ships (filament keeps partials;
  `.N` resends are deduped by basename and the byte-correct copy is selected).
- **Result-ACK loop.** When the host has the full verified set it pushes a tiny
  `ack-<job_id>` back to the box over **din** (host→box, the direction that already
  works). The box watcher re-ships outputs+manifest each round and **stops the instant
  it sees the ack** in its inbox — bounded by `reship_deadline_s` and a safety cap of
  rounds, then it gives up cleanly and logs (the result stays on disk). A lost manifest
  is re-shipped until acked; a lost ack just costs one extra round.
- **No silent hangs.** `runner_cli` emits an unbuffered terminal outcome
  (`SUCCEEDED` / `FAILED <reason>` / `TIMED-OUT`); every wait has a deadline.
- `--relay` stays the default; all new knobs are env/flag-configurable with sane
  defaults.

**Validation:** two complementary tests.

- `runner/sim/test_resilience_unit.py` — **deterministic** (seconds, no transport): drives
  `FileRunnerBox` + `watcher.Watcher` against a scriptable fake `filament` CLI and pins all
  three guarantees exactly: (1) `submit` survives 3 forced `no peer connected` failures and
  lands (retry-until-peer); (2) a 7 KB truncated `out.bin` is **rejected** by the sha256
  integrity gate and only the byte-correct copy is accepted; (3) the host sends `ack-<id>`
  only after sha256 verification and the box reship loop **stops on the ack** (4 rounds, not
  the safety cap). Green 3/3.
- `runner/sim/flaky_sim_test.sh` — the **real-transport** flaky-link e2e (filament WebRTC
  through the dropping proxy). Confirmed end-to-end: submit recovered after a forced outage,
  result returned byte-correct + sha256-verified through induced result-transfer drops (the
  host out dir holds `out.mp4.1/.2` resend copies — truncation rejected, byte-correct copy
  selected), manifest re-shipped and `host ACKed … stopping re-ship` observed in the watcher
  log. Its wall-clock varies with WebRTC establishment timing under the proxy, so the unit
  test is the deterministic gate; the e2e is the integration proof.

`runner/run_local_test.sh` (clean link, real transport) stays green. Still pending:
live-T4 confirmation over the real WAN path.
