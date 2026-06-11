# filament-native job runner

A thin **compute-job orchestration layer** on top of filament's existing P2P
transport (file channel). It offloads a *declared* compute job — e.g. an NVENC
transcode or a headless render — to a remote filament-reachable box (an ephemeral
Tesla T4 we cannot SSH into), runs it, pulls the artifacts back, and records a
manifest.

It deliberately replaces the ad-hoc "open a shell and run commands, copy files
off" pattern with **"submit / await / fetch a named job"**: the host pushes a job
*spec* plus a *fixed* box-side executor, then a box-side **watcher** runs that
single executor — it never pipes arbitrary commands across a shell. This is the
structural reframing argued in
[`../docs/research/remote-accelerator-offload.md`](../docs/research/remote-accelerator-offload.md)
(see §3 for the *why* and §4 for the contract).

> **Control plane: FILE-DRIVEN (default).** The v1 runner drove the box over a
> long-lived interactive **PTY** (`ctl` channel); on the unstable Colab→do-vm WAN
> link that stream dropped every few seconds and the host hung forever in
> `open_session()` (see [`../docs/runner/jobrunner-challenges.md`](../docs/runner/jobrunner-challenges.md)).
> The runner now uses **only discrete file transfers** — which the diagnosis
> proved survive the drops (they retry/resume and the bytes land): the host
> **pushes** the job spec + inputs, a box-side **`watcher.py`** runs the job and
> **sends** the manifest + outputs back (manifest LAST = completion signal).
> **`--relay` (TURN) is the default** for WAN robustness. The PTY `ctl` channel is
> **deprecated** (the `RunnerBox` PTY class is kept only for reference/parity).

> Status: the file-driven runner **mechanics, manifest, artifact return, and
> timeout handling are validated end-to-end on a local loopback peer** (CPU
> `libx264` fallback, `--no-relay`), 3/3 deterministic runs. NVENC + the real
> `--relay` WAN path get validated on the real T4 (ephemeral; validated with the
> user). R2 durability is implemented but a no-op unless rclone + creds are set.

---

## Files

| file | what |
|------|------|
| `box_executor.py` | the **FIXED** box-side job-execution core. `run_job(job_dir)` reads `job.json`, runs the declared `cmd` in the scratch dir under a watchdog timeout, captures exit code + per-output sha256/size + wall-clock + **all** GPU names (`nvidia-smi -L`), writes `manifest.json`, and optionally `rclone`-copies outputs to R2 before the box dies. Shared by both the watcher and the legacy PTY path. Stdlib only. |
| `watcher.py` | **box-side file-driven control plane.** A local poll loop: watches `.inbox/` for a job spec + its inputs (dedups `.N` resends by basename, guards on input-presence + size-stability), runs the job via `box_executor.run_job`, writes an `.outbox/<id>/`, then **`filament send --relay`**s the manifest + outputs back on the dout channel (manifest LAST). Idempotent/crash-safe (retires the spec to `.inbox/done/`); ships results in a background thread so jobs pipeline. Stdlib only. |
| `filament_runner.py` | host-side library. **`FileRunnerBox`** (DEFAULT): `submit` (`send --relay` job+inputs on din) / `await_results` (stand up a `up --dir --relay` sink on dout, poll for the manifest + verify each output's sha256) / `run()`. **`RunnerBox`** (DEPRECATED): the legacy PTY `submit`/`stream`/`fetch`. Stdlib only. |
| `runner_cli.py` | host CLI to submit one job and fetch its artifacts (routes through `FileRunnerBox`; `--relay` default, `--no-relay` to opt out). |
| `bringup_t4.sh` | **SSH-FREE** T4 bring-up: install ffmpeg(NVENC)/python3/(rclone), drop the static musl binary + `watcher.py`/`box_executor.py`, plant pairing secrets, start the **din acceptor + the watcher** (no PTY, no sshd), and tail their logs to keep the cell alive. |
| `pair_host.sh` | host pairing helper: generates the secrets, plants host config, prints the env block to paste on the T4. (`ctl` is still planted but unused — din/dout are reused, so no re-pairing when moving off the PTY.) |
| `run_local_test.sh` + `test_e2e.py` | the loopback acceptance test (boots an isolated topology — din acceptor + watcher — and runs a real job through the file-driven flow, `--no-relay`). |

---

## The job spec

A job is JSON:

```json
{
  "id": "j-transcode-001",
  "inputs": ["input.mov"],
  "cmd": ["ffmpeg","-y","-hwaccel","cuda","-hwaccel_output_format","cuda",
          "-i","input.mov","-vf","scale_cuda=-2:720",
          "-c:v","h264_nvenc","-preset","p5","-b:v","5M","-c:a","aac",
          "-progress","pipe:1","-nostats","out_720p.mp4"],
  "outputs": ["out_720p.mp4"],
  "timeout_s": 1800,
  "rclone_dest": "r2:reel/"
}
```

- `inputs` — files pushed to the box (over the filament file channel) before the run.
- `cmd` — argv executed **in the scratch dir** by the fixed executor (not by a shell the host pipes into).
- `outputs` — declared artifacts; hashed (sha256), sized, and pulled back.
- `timeout_s` — wall-clock kill (whole process group; enforced by a watchdog even for jobs that emit no output).
- `rclone_dest` — **optional** durability target; no-op when unset or rclone absent.

The executor records a **manifest**:

```json
{
  "job_id": "j-transcode-001",
  "exit_code": 0,
  "timed_out": false,
  "outputs": [{"name": "out_720p.mp4", "sha256": "…", "bytes": 188683}],
  "duration_s": 0.231,
  "gpu": "Tesla T4",
  "gpus": ["Tesla T4", "Tesla T4"],
  "durability": {"ran": false, "reason": "no rclone_dest configured"},
  "executor_proto": "FILJOB v1"
}
```

---

## API (file-driven — default)

```python
from filament_runner import FileRunnerBox, Job

rb = FileRunnerBox(
    petname_box_din="box-in",                       # how the host names the box on din
    server="https://api.filament.autumated.com",
    host_config_dir="~/.filament-jobrunner/host",   # knows box-in (the `send` target)
    host_dout_config_dir="~/.filament-jobrunner/host-dout",  # the results sink (box-out)
    filament_bin="filament",
    relay=True,                                     # force TURN relay (WAN default)
)

job = Job.new(
    cmd=["ffmpeg","-y","-i","input.mov","-vf","scale=-2:720",
         "-c:v","h264_nvenc","-preset","p5","-b:v","5M","-c:a","aac",
         "-progress","pipe:1","-nostats","out_720p.mp4"],
    inputs=["input.mov"], outputs=["out_720p.mp4"], timeout_s=1800,
)

rb.submit(job, local_input_dir="./in")              # send --relay job-<id>.json + inputs on din
m = rb.await_results(job, "./out", overall_timeout_s=2400)  # sink up; poll for manifest+outputs; verify sha256
print(m)                                            # {exit_code, outputs:[{sha256,bytes}], duration_s, gpu, gpus, ...}

# or both in one call:
rb.run(job, "./in", "./out")
```

There is **no PTY and no shell**. The host pushes a spec + inputs; a box-side
`watcher.py` runs `box_executor.run_job(<scratch>)` (a fixed program that reads
`cmd` from `job.json` and runs it) and sends the manifest + outputs back. That is
the policy-clean property (§3): *submit a named job*, not *shell into a host* —
now with no interactive stream to drop on a flaky link.

### CLI

```bash
runner/runner_cli.py \
  --host-cfg ~/.filament-jobrunner/host --dout-cfg ~/.filament-jobrunner/host-dout \
  --in ./in --out ./out --input input.mov --output out_720p.mp4 \
  --relay \
  -- ffmpeg -y -hwaccel cuda -hwaccel_output_format cuda -i input.mov \
     -vf scale_cuda=-2:720 -c:v h264_nvenc -preset p5 -b:v 5M -c:a aac \
     -progress pipe:1 -nostats out_720p.mp4
```

`--relay` is the default; pass `--no-relay` for a good/local link.

---

## How it maps onto filament (transport model)

A filament "device" is a pair secret; a petname is a local alias. The file-driven
runner uses **two file channels** (the `ctl` PTY is dropped):

| channel | box side | host side | carries |
|---|---|---|---|
| `din`  | `up --dir <inbox>` (file acceptor) | `send --relay` (initiator) | push the job spec + inputs |
| `dout` | `send --relay` (initiator, run by the watcher) | `up --dir <out> --relay` (transient sink) | manifest + outputs back |

Everything is **discrete file transfers**, which retry/resume across the WAN link
drops (proven in the diagnosis). The box-side `dout` send runs under its own
dout-only config dir so it never co-subscribes the din channel. Resends collide
to `name.N` on each side; both ends normalise by basename. The box ships the
manifest LAST and re-ships the result set a few times (background thread) so a
send that lands in a host-side reconnect window is recovered — the host dedups by
`job_id`.

The legacy three-channel **PTY** model (`ctl`=`up --shell`/`pty`) is **deprecated**
(it hung on the flaky link); `RunnerBox` is retained for reference only.

---

## Bring up a fresh T4 as a job-runner node (SSH-FREE)

The T4 is glibc 2.35 and you must not install `sshd`. Build the **static musl**
binary on the host:

```bash
cargo build --release --features static --target x86_64-unknown-linux-musl
# -> cli/target/x86_64-unknown-linux-musl/release/filament   (static-pie; runs on the T4)
```

On the **host**, pair and get the secrets:

```bash
runner/pair_host.sh            # plants ~/.filament-jobrunner/{host,host-dout}, prints the T4 env block
```

On the **T4**, paste the printed `export SEC_CTL=… SEC_DIN=… SEC_DOUT=…` block,
make the static binary reachable (host it somewhere and set `FILAMENT_URL`, or
copy it next to the script as `./filament`), then:

```bash
# the binary + bringup_t4.sh on the box, secrets exported, then:
FILAMENT_URL="https://…/filament-musl"  bash bringup_t4.sh
```

`bringup_t4.sh` installs only ffmpeg(NVENC)/python3/(optional rclone), drops the
static binary + `watcher.py`/`box_executor.py`, plants the secrets in isolated
config dirs, and starts the **din acceptor + the file-driven watcher** (no PTY).
It then `tail -F`s the watcher + din logs so the launching cell stays alive (and
you see live "job picked up / done / sent results"); set `FILJOB_NO_TAIL=1` for
non-interactive use. **No openssh/sshd** (that shuts the box down). Deliver the
two python files by hosting them and setting `WATCHER_URL`/`EXECUTOR_URL`, or by
running the script from the `runner/` checkout (it copies them from alongside
itself). The box self-terminates when the ephemeral runtime ends; the watcher
ships artifacts first (and re-ships to survive link drops).

### R2 durability (optional)

Set `INSTALL_RCLONE=1` on the T4 and configure rclone creds (env / `rclone
config` / `~/secret_keys` piped in — never on the command line). Then pass
`rclone_dest="r2:bucket/path/"` in the job; the executor runs `rclone copy <out>
<dest>` before the box dies. With no creds it stays a clean no-op.

---

## Run the local acceptance test (no T4 needed)

```bash
runner/run_local_test.sh
```

Boots a SEPARATE filament topology on this host (locally-built binary + isolated
`FILAMENT_CONFIG_DIR`s + a local signaling backend — never the live daemon or the
installed binary): a box **din acceptor + watcher**, paired over din/dout, and
runs a **real** ffmpeg job through the file-driven `submit` → watcher → `await`
flow. It asserts: the manifest comes back **over the file channel** with a
matching `job_id`, each declared output is byte-correct (manifest sha256 ==
sha256 of the pulled file), `exit_code==0`, and a timeout job is killed and
reported (`exit 124`, `timed_out: true`). Uses NVENC if this host has a GPU, else
CPU `libx264`. **Relay note:** the test uses the **direct** route (`--no-relay`)
because TURN isn't available on localhost; the bring-up and host default to
`--relay` for the WAN. Validated 3/3 deterministic runs.

## Flaky-link simulation (prove the resilience without a T4)

```bash
runner/sim/flaky_sim_test.sh        # FILJOB_KEEP=1 to keep the work dir + logs
```

Reproduces the three failure modes that broke the runner over the real Colab→do-vm
WAN link and proves the resilience fixes recover from each — **all locally**. A
stdlib TCP proxy (`runner/sim/flaky_proxy.py`) sits between every filament client
and the local backend and severs the signaling link on command (plus a background
randomised flapper); `flaky_e2e.py` drives a real job through it while inducing
outages and asserts:

- **(a) discovery race** — link DOWN at submit; the single-shot `send` fails, but
  **retry-until-peer** lands the push after the link heals.
- **(b) truncation** — the link drops mid result-transfer; the host's **sha256
  integrity gate** rejects the partial and keeps awaiting until a byte-correct copy
  lands (resume-to-completion). The host never accepts a truncated output.
- **(c) lost manifest** — drops land in the manifest's arrival window; the box
  **re-ships until the host ACKs** (a tiny `ack-<job_id>` pushed back over din).

The job still returns complete + byte-correct (sha256 == manifest). See
`docs/runner/jobrunner-challenges.md` (Transport robustness pass) for the design.

For a **deterministic** check of the same three guarantees in seconds (no transport,
no WebRTC timing) — used as the regression gate:

```bash
runner/sim/test_resilience_unit.py
```

It drives `FileRunnerBox` + the watcher against a scriptable fake `filament` and
asserts: submit survives 3 forced `no peer connected` failures; a 7 KB truncated
output is rejected by the sha256 gate; the box stops re-shipping the instant the
host's `ack-<id>` lands.

---

## Not a dead end: lifting onto Modal / SkyPilot

The same **job spec is backend-swappable** (research §4). When the gift T4 stops
being enough or we want reproducibility, the identical `{id, inputs, cmd,
outputs, timeout_s}` lifts onto a serverless-GPU backend without changing
callers:

- **Modal** — wrap the `cmd` in `@app.function(gpu="T4")`; inputs as args / from
  R2; outputs returned or committed to a `modal.Volume`. ~$0.59/hr T4, scale to
  zero, reads as ML tooling.
- **SkyPilot** — a `sky.yaml` with `file_mounts` for `inputs`, a `run:` block
  calling `cmd`, `--use-spot`, and an autostop hook that pushes artifacts to R2.

The filament runner is the right tool for the *no-SSH gift box we have today*;
Modal/SkyPilot are the right tools the moment we'd rather rent.
