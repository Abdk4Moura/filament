# filament-native job runner

A thin **compute-job orchestration layer** on top of filament's existing P2P
transport (PTY + file channel). It offloads a *declared* compute job — e.g. an
NVENC transcode or a headless render — to a remote filament-reachable box (an
ephemeral Tesla T4 we cannot SSH into), streams structured progress, pulls the
artifacts back, and records a manifest.

It deliberately replaces the ad-hoc "open a shell and run commands, copy files
off" pattern with **"submit / await / fetch a named job"**: the host pushes a job
*spec* plus a *fixed* box-side executor, then invokes that single executor — it
never pipes arbitrary commands across a shell. This is the structural reframing
argued in [`../docs/research/remote-accelerator-offload.md`](../docs/research/remote-accelerator-offload.md)
(see §3 for the *why* and §4 for the contract).

> Status: the runner **mechanics, manifest, artifact return, and timeout
> handling are validated end-to-end on a local loopback peer** (CPU `libx264`
> fallback). NVENC specifically gets validated on the real T4 (the T4 is
> ephemeral and currently down). R2 durability is implemented but a no-op unless
> rclone + creds are configured.

---

## Files

| file | what |
|------|------|
| `box_executor.py` | the **FIXED** box-side program. Reads `job.json`, runs the declared `cmd` in the scratch dir under a timeout, captures exit code + per-output sha256/size + wall-clock + GPU name, writes `manifest.json`, streams `-progress`-style structured lines, and optionally `rclone`-copies outputs to R2 before the box dies. Stdlib only. |
| `filament_runner.py` | host-side library: `RunnerBox` with `submit` / `stream` / `fetch` / `manifest` (+ `run()` convenience). Drives the `filament` CLI (`pty`, `send`, `up`). Stdlib only. |
| `runner_cli.py` | host CLI to submit one job and fetch its artifacts. |
| `bringup_t4.sh` | **SSH-FREE** T4 bring-up: install ffmpeg(NVENC)/python3/(rclone), drop the static musl binary, plant pairing secrets, start the box acceptors. No sshd. |
| `pair_host.sh` | host pairing helper: generates the three secrets, plants host config, prints the env block to paste on the T4. |
| `run_local_test.sh` + `test_e2e.py` | the loopback acceptance test (boots an isolated topology + runs a real job). |

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
  "durability": {"ran": false, "reason": "no rclone_dest configured"},
  "executor_proto": "FILJOB v1"
}
```

---

## API

```python
from filament_runner import RunnerBox, Job

rb = RunnerBox(
    petname_ctl="box", petname_din="box-in", petname_dout="box-out",
    server="https://api.filament.autumated.com",
    host_config_dir="~/.filament-jobrunner/host",
    filament_bin="filament",
    remote_jobs_root="~/filament-jobs",
    remote_inbox="~/filament-jobs/.inbox",
    box_dout_config_dir="~/filament-jobs/cfg-dout",
)

job = Job.new(
    cmd=["ffmpeg","-y","-i","input.mov","-vf","scale=-2:720",
         "-c:v","h264_nvenc","-preset","p5","-b:v","5M","-c:a","aac",
         "-progress","pipe:1","-nostats","out_720p.mp4"],
    inputs=["input.mov"], outputs=["out_720p.mp4"], timeout_s=1800,
)

rb.submit(job, local_input_dir="./in")      # scratch dir + push inputs + push the fixed executor
for ev in rb.stream(job):                    # run the executor ONCE; parse frame=/out_time=/fps=
    if ev.kind == "progress":
        print(ev.data)                       # {'frame': 123, 'out_time': '00:00:04.1', 'fps': 58.0}
rb.fetch(job, local_output_dir="./out")      # pull declared outputs + manifest.json
print(rb.manifest(job))                      # {exit_code, outputs:[{sha256,bytes}], duration_s, gpu, ...}

# or all four in one persistent control session:
rb.run(job, "./in", "./out", on_progress=lambda e: ...)
```

The host **never** sends `cmd` over a shell. `submit` pushes a spec + the fixed
executor; `stream` invokes `python3 box_executor.py <scratch>` — a single fixed
program that reads `cmd` from `job.json` and runs it. That is the policy-clean
property (§3): *submit a named job*, not *shell into a host*.

### CLI

```bash
runner/runner_cli.py \
  --host-cfg ~/.filament-jobrunner/host --dout-cfg ~/.filament-jobrunner/host-dout \
  --remote-root '~/filament-jobs' --remote-inbox '~/filament-jobs/.inbox' \
  --box-dout-cfg '~/filament-jobs/cfg-dout' \
  --in ./in --out ./out --input input.mov --output out_720p.mp4 \
  -- ffmpeg -y -hwaccel cuda -hwaccel_output_format cuda -i input.mov \
     -vf scale_cuda=-2:720 -c:v h264_nvenc -preset p5 -b:v 5M -c:a aac \
     -progress pipe:1 -nostats out_720p.mp4
```

---

## How it maps onto filament (transport model)

A filament "device" is a pair secret; a petname is a local alias. To keep each
signaling channel to **exactly one acceptor** (two acceptors on one channel
glare), the runner uses **three channels**, each with a single fixed-role
acceptor:

| channel | box side | host side | carries |
|---|---|---|---|
| `ctl`  | `up --shell` (PTY acceptor) | `filament pty` (initiator) | control + the single executor invocation |
| `din`  | `up --dir <inbox>` (file acceptor) | `filament send` (initiator) | push inputs |
| `dout` | `filament send` (initiator, via the ctl PTY) | `up --dir <out>` (transient sink) | pull outputs + manifest |

Structured progress is sentinel-framed (`FILJOB v1 <id> progress {…}`) so the
host parses it out of the interactive PTY stream (which also carries shell
prompts/echo). The box-side `dout` send runs under its own dout-only config dir
so it never co-subscribes the ctl/din channels.

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
static binary, plants the three secrets in isolated config dirs, and starts
`up --shell` (ctl) + `up --dir` (din). **No openssh/sshd** (that shuts the box
down). The box self-terminates when the ephemeral runtime ends; the runner just
flushes artifacts first.

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

Boots a SEPARATE filament acceptor on this host (locally-built binary + isolated
`FILAMENT_CONFIG_DIR`s + a local signaling backend — never the live daemon or the
installed binary), pairs it over the three channels, and runs a **real** ffmpeg
job end-to-end. It asserts: outputs come back byte-correct (manifest sha256 ==
sha256 of the pulled file), `exit_code==0`, progress was parsed (non-empty
frame/out_time), and a timeout job is killed and reported (`exit 124`,
`timed_out: true`). Uses NVENC if this host has a GPU, else CPU `libx264`.

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
