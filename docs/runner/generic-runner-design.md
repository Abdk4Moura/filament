# Generic Remote-Compute Runner — Design Doc

*Decision-grade design. Date: 2026-06-11. Status: proposed. Doc-only (a parallel
agent owns the `runner/` code and the transport-reliability work). Grounded in the
current implementation under `runner/` and in
[`jobrunner-challenges.md`](jobrunner-challenges.md) +
[`../research/remote-accelerator-offload.md`](../research/remote-accelerator-offload.md).*

---

## TL;DR

**We are generalizing the T4-flavored filament job-runner into `filament-jobs`: a
portable "submit a named job to any paired filament box, get artifacts + a manifest
back" system that runs arbitrary compute — GPU or not — on any filament-reachable
machine, with no SSH and no interactive shell.**

The pitch: the current runner already has the right bones — a versioned **job spec**
(`{id, inputs, cmd, outputs, timeout_s, …}`), a **fixed box-side executor** that runs
the declared command in a scratch dir and emits a signed-by-hash **manifest**, and a
**file-driven control plane** (host pushes spec+inputs, a box-side `watcher.py` runs it
and ships results back over discrete file transfers). But everything is named, defaulted,
and documented for *one* use case: NVENC transcode on a gift T4. This doc specifies the
small set of renames, extractions, and contract clarifications that turn it into a
**reusable library + `filament-jobs` CLI** serving GPU render, ML inference/small
training, data/ETL batch, headless-browser/CI tasks, and periodic jobs — with the *same*
spec/manifest contract, the *same* file-driven reliability guarantees, and a clean
**backend-swap** boundary so the identical spec lifts onto Modal / SkyPilot / a rented
VM. It is **not** a cluster scheduler and **not** Kubernetes; it is a thin job
abstraction over a transport we already own.

---

## 1. Vision & scope

### What "generic" means here

A **job** is a named, declarative unit of compute: *here are some input files, here is a
command to run, here are the outputs I expect, here is how long it may take.* A **node**
is any filament-reachable box running the watcher. The system's whole job is to move the
spec+inputs to a node, run it in isolation, and move the artifacts+manifest back —
reliably, over a flaky WAN, with no shell.

"Generic" means three concrete properties the current code is *one specialization away*
from:

1. **Workload-agnostic.** The executor already runs an arbitrary `cmd` argv in a scratch
   dir (`box_executor.run_job`). Nothing about it is transcode-specific *except* the
   ffmpeg `-progress` parser and the NVENC-flavored docs/defaults. A render, a Python
   inference script, a `curl | jq` ETL step, or a headless-Chrome screenshot are all
   "an argv that reads inputs from cwd and writes outputs to cwd."
2. **Hardware-agnostic.** GPU is a *hint*, not a requirement. `nvidia-smi -L` is already
   best-effort (`_gpu_names()` returns `[]` on a CPU-only host); the loopback test runs
   CPU `libx264`. A node with no GPU is a perfectly good ETL/CI/browser node.
3. **Backend-agnostic.** The spec/manifest contract is the stable interface; "filament
   over a watcher" is one *backend* implementing it. Modal and SkyPilot are others
   (§8). Callers depend on the spec, not on filament.

### Non-goals (explicit)

- **Not a cluster scheduler.** No bin-packing across a fleet, no gang scheduling, no
  fair-share, no DAG/dependency engine. One job → one node. (Multiple concurrent jobs on
  *one* node is in scope — §5 — but cross-node placement is the caller's choice.)
- **Not Kubernetes / not Ray / not Slurm.** Those need a reachable daemon on the box
  (kubelet, Ray GCS, sshd). The entire reason this exists is the no-SSH ephemeral box;
  see research §2 ("no off-the-shelf orchestrator can adopt this box").
- **Not a general RPC/remote-shell.** The deliberate framing is *named job in, manifest
  out* — never "pipe arbitrary commands across a shell." This is both an ergonomics and a
  policy-optics decision (§7, research §3).
- **Not a data lake / artifact registry.** Durability is a single pluggable push step
  (`rclone` to object storage today); we don't own a catalog.

---

## 2. Use cases beyond the T4 transcode

The same spec/manifest contract serves each of these. The only things that vary are the
`cmd`, the `resources` hint, whether a container is requested, and (optionally) a
workload-specific progress parser. A concrete example spec per use case:

### 2a. GPU transcode (the existing case — baseline)

```json
{ "spec_version": 1, "id": "j-transcode-001",
  "inputs": ["input.mov"],
  "cmd": ["ffmpeg","-y","-hwaccel","cuda","-hwaccel_output_format","cuda",
          "-i","input.mov","-vf","scale_cuda=-2:720","-c:v","h264_nvenc",
          "-preset","p5","-b:v","5M","-c:a","aac","-progress","pipe:1","-nostats",
          "out_720p.mp4"],
  "outputs": ["out_720p.mp4"], "timeout_s": 1800,
  "resources": { "gpu": "required", "gpu_kind": "nvidia" },
  "progress": "ffmpeg", "durability": { "dest": "r2:reel/" } }
```

### 2b. GPU render (Blender / headless 3D)

A render is "run a renderer over a scene file, collect frames." Same shape; the outputs
are an image sequence (declare the directory or a glob — see `outputs` semantics, §3).

```json
{ "spec_version": 1, "id": "j-render-aurora-007",
  "inputs": ["scene.blend", "hdri.exr"],
  "cmd": ["blender","-b","scene.blend","-o","//frame_####","-F","PNG",
          "-f","1..120","--","--cycles-device","CUDA"],
  "outputs": ["frame_*.png"], "timeout_s": 7200,
  "resources": { "gpu": "required", "gpu_kind": "nvidia", "vram_gb": 8 },
  "progress": "blender", "retries": 1 }
```

### 2c. ML inference (batch)

```json
{ "spec_version": 1, "id": "j-infer-embed-204",
  "container": { "image": "ghcr.io/acme/embed:cu121", "gpus": "all" },
  "inputs": ["prompts.jsonl"],
  "cmd": ["python","run_embed.py","--in","prompts.jsonl","--out","embeddings.parquet"],
  "outputs": ["embeddings.parquet"], "timeout_s": 1800,
  "resources": { "gpu": "required", "vram_gb": 16 },
  "durability": { "dest": "r2:embeddings/204/" } }
```

### 2d. ML training (small / fine-tune; checkpointable)

Small/QLoRA-scale training, not multi-node. The key generic feature is **periodic
durability of checkpoints** so an ephemeral box dying mid-run doesn't lose everything
(research §H "checkpointing pattern").

```json
{ "spec_version": 1, "id": "j-train-lora-031",
  "container": { "image": "ghcr.io/acme/trl:latest", "gpus": "all" },
  "inputs": ["train.jsonl", "base_config.yaml"],
  "cmd": ["python","train_lora.py","--config","base_config.yaml",
          "--out","ckpt/","--save-every","500"],
  "outputs": ["ckpt/"], "timeout_s": 21600,
  "resources": { "gpu": "required", "vram_gb": 24 },
  "durability": { "dest": "r2:ckpts/031/", "interval_s": 600 } }
```

### 2e. Data / ETL batch (no GPU)

A CPU node is fine. Notice: same contract, `gpu: "forbidden"`, an arbitrary toolchain.

```json
{ "spec_version": 1, "id": "j-etl-rollup-2026w24",
  "inputs": ["events-2026w24.ndjson"],
  "cmd": ["bash","-lc","duckdb -c \"COPY (SELECT user,count(*) c FROM read_ndjson_auto('events-2026w24.ndjson') GROUP BY user) TO 'rollup.parquet'\""],
  "outputs": ["rollup.parquet"], "timeout_s": 600,
  "resources": { "gpu": "forbidden" },
  "durability": { "dest": "r2:rollups/" } }
```

### 2f. Headless browser / CI-style task (no GPU)

Screenshot/PDF/scrape, or a build+test. The runner doesn't care that it's a browser; it's
an argv with declared outputs.

```json
{ "spec_version": 1, "id": "j-shot-relay-landing",
  "container": { "image": "mcr.microsoft.com/playwright:v1.49.0" },
  "inputs": ["shot.js"],
  "cmd": ["node","shot.js","https://relay.autumated.com","shot.png"],
  "outputs": ["shot.png"], "timeout_s": 120,
  "resources": { "gpu": "forbidden" } }
```

### 2g. Periodic job

Periodicity is **not** a node-side concern — the node stays the same dumb watcher. A
periodic job is "the same spec, resubmitted on a schedule" by a host-side scheduler
(cron, the `loop`/`schedule` harness, or a thin `filament-jobs cron` wrapper). The spec
gains a stable `id` template so each run is distinguishable:

```json
{ "spec_version": 1, "id": "j-healthcheck-{{date}}",
  "cmd": ["bash","-lc","nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv > gpu.csv"],
  "outputs": ["gpu.csv"], "timeout_s": 60, "resources": { "gpu": "optional" } }
```

**The point:** every row above is the *same* `submit → run-in-scratch → manifest → fetch`
loop the code already implements. Generalization is removing transcode assumptions from
the *defaults and docs*, plus adding the `resources`/`container`/`progress`/durability
fields the spec is currently missing (§3), not rewriting the engine.

---

## 3. The job-spec contract

The spec is the **stable, versioned interface**. It must stay declarative (no host
callbacks, no code) and backend-agnostic (nothing filament-specific in it). The current
`Job` dataclass (`filament_runner.py`) is the v1 seed; this is the v2 superset.

### Schema (v2)

| field | type | req | meaning |
|---|---|---|---|
| `spec_version` | int | yes | contract version (currently `1`; bump on breaking change). The executor's `executor_proto` in the manifest mirrors it. |
| `id` | string | yes | caller-unique job id. Drives idempotency, dedup, scratch-dir name, manifest match. |
| `inputs` | string[] | no | files staged into the scratch dir before the run. Plain basenames; resends dedup by basename (already implemented). |
| `cmd` | string[] | yes\* | argv run **in the scratch dir** by the fixed executor — never a shell the host pipes into. |
| `entrypoint` | string | no | alternative to `cmd`: a named input script the node runs (`python <entrypoint>`); sugar over `cmd`, still no host-side shell. \*one of `cmd`/`entrypoint` required. |
| `env` | object | no | extra environment for the child process (allow-listed keys; see §7 — **never** secrets in the spec). |
| `outputs` | string[] | no | declared artifacts. Supports a plain name, a **directory** (shipped as a tarball + per-file hashes), or a **glob** (`frame_*.png`). Hashed (sha256), sized, shipped back, verified host-side. |
| `timeout_s` | int | yes | wall-clock kill of the whole process group (watchdog enforced even for silent jobs — already implemented). |
| `resources` | object | no | scheduling/placement **hints**: `{gpu: required\|optional\|forbidden, gpu_kind, vram_gb, cpu, mem_gb}`. Advisory on the filament backend (the node admits or rejects); authoritative on Modal/SkyPilot (becomes `gpu="T4"` etc.). |
| `container` | object | no | `{image, gpus, mounts}`. When present the node runs `cmd` *inside* the image via docker + nvidia-container-toolkit (`--gpus`); when absent it bare-execs. (§3 "container vs bare exec"). |
| `durability` | object | no | `{dest, interval_s?}`. Push outputs (and, if `interval_s`, periodic checkpoints) to object storage before/during the run. Pluggable; no-op when unset. Generalizes today's `rclone_dest`. |
| `retries` | int | no | node-side re-run count on non-zero exit / timeout (default 0). Idempotency is the caller's responsibility for non-pure jobs. |
| `progress` | string | no | named parser for live progress (`ffmpeg`, `blender`, `none`). Decouples progress from the transcode-only ffmpeg parser. |
| `labels` | object | no | free-form tags echoed into the manifest (`{pipeline: "reel", owner: "abdk"}`) for `ls`/filtering. |

### How it stays backend-agnostic

Nothing in the spec names filament, a peer, a channel, or a config dir. Those live in the
**runner/backend config**, not the job. A spec is a pure description of *what to run and
what comes back*; a backend decides *where*. This is what lets the identical JSON go to a
watcher node, a Modal function, or a SkyPilot task (§8). The current `Job.spec_dict()`
already serializes a clean, transport-free dict — we extend it, we don't entangle it.

### The manifest (return contract)

Unchanged in shape from today, extended for the new fields:

```json
{ "job_id": "j-render-aurora-007", "spec_version": 1, "executor_proto": "FILJOB v2",
  "exit_code": 0, "timed_out": false,
  "outputs": [{"name":"frame_001.png","sha256":"…","bytes":12345}, …],
  "duration_s": 412.7, "started_at": "…", "ended_at": "…",
  "node": {"gpu": "Tesla T4", "gpus": ["Tesla T4","Tesla T4"], "host":"…"},
  "durability": {"ran": true, "dest":"r2:…","results":[…]},
  "retries_used": 0, "labels": {"pipeline":"reel"} }
```

The manifest **is** the completion signal (shipped LAST over the file channel today;
that property is preserved). sha256 per output is the integrity proof the host verifies
(`_outputs_verified` already does this).

### Container option vs bare exec

- **Bare exec (default, today's behavior):** `cmd` runs directly in the scratch dir under
  the node's own toolchain. Lowest overhead; what the gift T4 uses (apt ffmpeg+NVENC).
  Correct when the node is pre-provisioned for the workload.
- **Container (`container.image` set):** the node wraps `cmd` in
  `docker run --rm -v <scratch>:/work -w /work [--gpus all] <image> <cmd>` with
  nvidia-container-toolkit for GPU passthrough. This is the **reproducibility** path
  (research §F) and the natural bridge to Modal/SkyPilot (which are "your container on
  their GPU"). The node advertises whether docker + the toolkit are available (bring-up
  probes it); a `container` job submitted to a node without docker is rejected cleanly,
  not silently bare-exec'd.

---

## 4. API + CLI surface

### Library API

A clean reusable package (proposed `filament_jobs/`), with a **backend interface** and
the filament implementation behind it. Illustrative pseudocode — *not* a real
implementation (the code agent owns that):

```python
from filament_jobs import JobSpec, Backend, FilamentBackend

# A backend knows WHERE; the spec knows WHAT.
backend = FilamentBackend(
    node="t4-box",                 # a named, paired node (resolves to din/dout secrets)
    server="https://api.filament.autumated.com",
    relay=True,                    # WAN default (§6)
)

spec = JobSpec(
    id="j-render-007",
    inputs=["scene.blend", "hdri.exr"],
    cmd=["blender","-b","scene.blend","-o","//frame_####","-F","PNG","-f","1..120"],
    outputs=["frame_*.png"],
    timeout_s=7200,
    resources={"gpu": "required", "vram_gb": 8},
    durability={"dest": "r2:renders/007/"},
)

handle = backend.submit(spec, input_dir="./in")      # returns a JobHandle (id, node)
for ev in backend.logs(handle, follow=True):         # structured progress events
    print(ev)
manifest = backend.await_result(handle, out_dir="./out", timeout_s=8000)  # verifies sha256
print(manifest.exit_code, [o.name for o in manifest.outputs])

# one-shot convenience (today's `run()`):
manifest = backend.run(spec, "./in", "./out")
```

The **`Backend` interface** is the abstraction boundary (§8): `submit`, `status`, `logs`,
`await_result`, `fetch`, `cancel`, `ls`. `FilamentBackend` wraps today's
`FileRunnerBox.submit`/`await_results`; `ModalBackend`/`SkyPilotBackend` are alternative
implementations of the same interface.

### `filament-jobs` CLI

One verb-per-operation CLI, replacing the single-shot `runner_cli.py`:

```text
filament-jobs node up [--name <n>] [--server …] [--ops-shell]   # turn THIS box into a runner
filament-jobs node pair <name>                                   # host-side: gen secrets, print bring-up block
filament-jobs node ls                                            # known/paired nodes + last-seen, GPU advertised

filament-jobs submit <spec.json|->  --node <n> [--in DIR]        # → prints job id
filament-jobs status <id>           [--node <n>]                 # queued|running|done|failed|timed_out
filament-jobs logs   <id>  [-f]     [--node <n>]                 # structured progress (ffmpeg/blender/…)
filament-jobs fetch  <id>  --out DIR[--node <n>]                 # pull declared outputs + manifest, verify sha256
filament-jobs cancel <id>           [--node <n>]                 # ask the node to kill the job (§5)
filament-jobs ls     [--node <n>] [--label k=v]                 # jobs on a node + state, from manifests/queue
```

Plus an inline-spec convenience that mirrors today's `runner_cli.py` ergonomics so simple
jobs need no JSON file:

```bash
filament-jobs submit --node t4-box --in ./in --out ./out \
  --input input.mov --output out_720p.mp4 --timeout 1800 --gpu required --relay \
  -- ffmpeg -y -hwaccel cuda -i input.mov -vf scale_cuda=-2:720 \
     -c:v h264_nvenc -preset p5 -b:v 5M -c:a aac out_720p.mp4
```

`node up` is the generalized, renamed `bringup_t4.sh` (§9): it no longer hard-assumes
ffmpeg/NVENC — it installs a *base* (python3 + filament binary + watcher/executor), and
workload deps are a node profile (`--profile ffmpeg|render|ml|browser|none`) or just
whatever the node already has. `node pair` is `pair_host.sh`.

---

## 5. Execution & concurrency model

### Today

`watcher.run_forever()` is a **single sequential loop**: `_claim_next()` returns one ready
job, `process_one()` runs it to completion, then results ship in a **background thread**
(so the next job's *compute* can start before the previous job's *upload* finishes — a
one-step pipeline). One job runs at a time.

The structure is already concurrency-ready: `_claim_next()` carries a documented
**DISPATCH HOOK**, a claimed spec is moved out of `.inbox/` immediately (so concurrent
claims can't double-run a job), and the manifest records **all** GPUs (`gpus` via
`nvidia-smi -L`) precisely so per-GPU dispatch can be added.

### The path to a queue + concurrency

1. **Explicit queue.** Promote the inbox scan into a small persistent **job queue** on the
   node (a `.queue/` dir of admitted specs with states `queued|running|done|failed`,
   each a file = the on-disk source of truth; no DB). `status`/`ls`/`cancel` read/write it.
   Crash-safe because it's just files (same discipline as `.inbox/done/` today).
2. **Bounded worker pool.** Replace the single loop with N workers (N = a configured
   concurrency, default = number of GPUs for GPU jobs, or a CPU-derived default for CPU
   jobs). Each worker `_claim_next()`s, runs `process_one()`, ships. The claim-then-move
   discipline already makes this safe.
3. **Per-resource dispatch.** A free-resource table (per-GPU index, CPU slots). A GPU job
   is assigned a free GPU index and the node injects it — the deferred
   `-hwaccel_device 0/1` parallelism for the 2× T4, and `CUDA_VISIBLE_DEVICES=<idx>` for
   container/ML jobs. `resources.gpu == forbidden` jobs run on CPU slots and never
   contend for a card. This is the concrete realization of the open item in
   [`jobrunner-challenges.md`](jobrunner-challenges.md) ("confirm 2× T4 … add per-GPU
   dispatch").

### Idempotency / crash-safety

Preserve and generalize today's guarantees:

- **A claimed spec is moved to `.queue/running/` (was `.inbox/done/`) before execution**,
  so a watcher restart never re-runs an in-flight job; on restart, `running/` entries
  with no manifest are either resumed-as-failed or re-queued per `retries`.
- **`_already_done(job_id)`** (manifest present in the outbox) makes resent specs no-ops —
  the host can safely resend on a flaky link.
- **The manifest is written atomically and shipped LAST**; partial output never reads as
  completion.
- **`retries`** re-runs on failure within the node, bounded; the manifest records
  `retries_used`. Callers must treat non-idempotent jobs (e.g. "append to a remote DB")
  with care — the contract is at-least-once delivery of *the run*, exactly-once delivery
  of *the artifact* (sha-verified).

`cancel` writes a tombstone the worker checks; the worker kills the process group
(`os.killpg`, already used by the watchdog) and marks the job `cancelled`.

---

## 6. Reliability requirements (contract for the transport-reliability agent)

The known failure (`jobrunner-challenges.md`) is **WAN link instability**: direct-QUIC
establishes and drops within seconds; a long-lived interactive PTY can't survive it, but
**discrete file transfers retry/resume and the bytes land**. The generic runner inherits
that lesson as **requirements**, not as something to re-derive here. The parallel agent is
implementing the fixes; this section states the contract the generic runner depends on.

**R1 — No long-lived control stream.** The control plane MUST be discrete file transfers
only (the file-driven design). No PTY/interactive session in the job path. (Met today by
`FileRunnerBox`/`watcher.py`; the deprecated PTY `RunnerBox` is out of the job path.)

**R2 — Retry-until-peer.** Every transfer (submit, result-ship) MUST retry/resume across
link drops until it lands or a bounded deadline elapses — and MUST NOT hang silently
forever (the exact `open_session()` hang we suffered). A stalled transfer MUST surface a
clear, time-bounded error.

**R3 — Integrity + resume.** Each output is sha256'd in the manifest and verified
host-side; a partial/corrupt transfer MUST be detectable and re-fetchable. (Met by
`_outputs_verified`; keep it.)

**R4 — Result-ACK / completion signal.** The manifest (shipped LAST) is the completion
signal; the host polls for a manifest matching `job_id` and then verifies outputs. The
node SHOULD re-ship the result set a bounded number of times (today's reship loop) so a
send that lands in a host-side reconnect window is recovered; the host dedups by
`job_id`. A future improvement: an explicit host→node ACK so the node can stop reshipping
early (today it reships a fixed count).

**R5 — Relay default for WAN.** `--relay` (TURN) is the default for WAN nodes (the
earlier working pipeline used relay; direct-QUIC was the unstable path). Local/loopback
may opt out (`--no-relay`).

**R6 — No silent hangs anywhere.** Every wait (submit, await, fetch, logs) MUST be
deadline-bounded and emit progress/heartbeat so a stuck job is observable, never an
indefinite block.

These are the generic runner's reliability SLOs. The runner's correctness (idempotency,
sha-verification) composes *on top of* them.

---

## 7. Pairing / security / ops

### Onboarding any box

`node pair` (host) generates pair secrets and prints the env block; `node up` (box) is the
generalized bring-up: fetch the static-musl `filament` binary, plant the secrets in
**isolated per-channel config dirs** (one secret per dir so no daemon co-subscribes a
channel it shouldn't — the existing `cfg-din`/`cfg-dout` discipline), drop
`watcher.py`+`box_executor.py`, start the din acceptor + the watcher. Today's three
secrets (`ctl`/`din`/`dout`) stay (din/dout carry jobs+results; `ctl` is reused only for
the optional ops-shell), so existing nodes don't re-pair.

### Deny-by-default, "named job, not a shell"

This is the load-bearing security and **policy-optics** posture (research §3):

- **No interactive shell in the job path.** The node runs a *fixed* program
  (`box_executor.run_job`) that reads a declared `cmd` from `job.json` and runs it in a
  scratch dir. The host never pipes commands across a shell. "Submit/await/fetch a named
  compute job with a spec + manifest" is a legitimate compute-orchestration sentence;
  "open a shell and run arbitrary commands, copy files off" is the prohibited silhouette.
  The whole abstraction exists partly *for the optics*, not only ergonomics.
- **The ops-shell is explicitly separate and opt-out.** `bringup_t4.sh` already gates a
  debug `up --shell` behind `FILJOB_OPS_SHELL` (default on; `=0` disables). In the generic
  runner this should default **off** and be flagged `--ops-shell` at `node up` time — an
  operator door for inspection (logs, nvidia-smi, disk), never the job control plane.
  Keeping it off-by-default keeps the node's surface "job runner," not "remote shell."
- **Spec hygiene = no shell injection surface.** `cmd` is an argv (no shell parsing); the
  staging step moves *named* files only (`shlex.quote`d in the legacy path). `env` is
  allow-listed; **secrets never travel in the spec** — durability creds come from the
  node's own rclone config/env (today's rule: "creds … never passed on the command line").

### Multi-tenant considerations

- **A node is single-tenant by default** (one pair-secret set = one trust domain). The
  pair secret *is* the authn; anyone with all three secrets can submit. For multiple
  callers sharing a node, issue distinct pair secrets per caller (distinct petnames) and
  optionally namespace the queue by `labels.owner`. Cross-tenant isolation beyond
  process+scratch-dir separation (e.g. cgroups, container-per-job) is a node-profile
  choice, not a core requirement (non-goal: full multi-tenant scheduler).
- **Resource caps** (`timeout_s`, optional per-node concurrency and disk quotas) bound a
  runaway or hostile job; the watchdog already kills the whole process group on timeout.

---

## 8. Backend-swappable

The spec/manifest contract is the abstraction boundary. The **`Backend` interface**
(§4) has exactly one filament-specific implementation today; the same interface admits
others. The identical `JobSpec` JSON lifts onto each:

| Backend | `submit` | run | `await_result` / fetch | teardown |
|---|---|---|---|---|
| **Filament** (have) | `send --relay` spec+inputs → node inbox (din) | box `watcher.py` → `box_executor.run_job` in scratch | poll dout sink for manifest+outputs, verify sha256 | node self-terminates (ephemeral); watcher flushes results first |
| **Modal** | wrap `cmd` in `@app.function(gpu=resources.gpu_kind)`; inputs as args / from R2 | Modal runs the container | return value / `modal.Volume` (`vol.commit()`) → mapped to manifest | scale-to-zero |
| **SkyPilot** | render `sky.yaml`: `file_mounts` = `inputs`, `run:` = `cmd`, `--use-spot`, `resources` = `accelerators` | provisions cheapest-spot VM | autostop hook pushes outputs to R2 → manifest | `autostop` / `sky down` |
| **Rented VM** (ThunderCompute/vast) | `tnr create` + `tnr scp` inputs | `tnr connect -- <cmd>` | `tnr scp` outputs → manifest | `tnr delete` |

**The abstraction boundary, precisely:** a `Backend` consumes a `JobSpec` (transport-free)
and produces a `Manifest` (transport-free), plus moving the declared `inputs`/`outputs`.
Everything backend-specific — petnames/secrets/relay for filament; image/gpu/volume for
Modal; `sky.yaml`/spot/autostop for SkyPilot — lives in the backend's *config*, never in
the spec. Because `container.image` already exists in the spec, the Modal/SkyPilot
backends (which are "your container on their GPU") map almost mechanically: the same
image + `cmd` runs there. **Filament-native is one backend among several** — the right one
for the no-SSH gift box we have today (research §2/§4); Modal/SkyPilot are the right ones
the moment we'd rather rent. Callers choose a backend and never change their spec. The
existing README already gestures at this ("Not a dead end: lifting onto Modal / SkyPilot");
this formalizes it as an interface.

---

## 9. Phased path from here

Honest about effort. Each phase is independently shippable; the system stays working
throughout. Sizes are rough engineering estimates.

### Phase 0 — Land the reliability contract (parallel agent; prerequisite)

The transport-reliability agent meets R1–R6 (§6). The generic work below assumes those
SLOs but doesn't block on them for the *non-transport* refactors. **Effort: owned
elsewhere.**

### Phase 1 — De-T4-ify in place (rename/generalize defaults; no behavior change) — **S**

- Generalize **docs/defaults**: README and `runner_cli.py` stop centering NVENC; "node"
  not "T4 box." Keep `box_executor.run_job` exactly as-is (it's already generic).
- Make the **progress parser pluggable**: factor the ffmpeg `-progress` parsing in
  `_run_with_progress` behind `spec.progress` (`ffmpeg`|`none`), default `none` for a
  generic argv. Transcode still gets live progress.
- Generalize **bring-up**: split `bringup_t4.sh` into a base bring-up (binary + python +
  secrets + watcher) and an optional **workload profile** (the ffmpeg/NVENC install
  becomes `--profile ffmpeg`). Rename to `node_up.sh`; keep a `bringup_t4.sh` shim that
  calls it with `--profile ffmpeg` so nothing breaks.
- **Keep:** the file-driven control plane, the manifest format, sha-verification, the
  reship loop, isolated config dirs, the ops-shell gate (flip default to off).

### Phase 2 — Spec v2 + CLI surface — **M**

- Extend `Job` → `JobSpec` with `spec_version`, `resources`, `container`, `env`,
  `entrypoint`, `progress`, `durability` (generalizing `rclone_dest`), `retries`,
  `labels`. Stay backward-compatible: a v1 spec (today's fields) parses as
  `spec_version: 1` with defaults.
- Build the `filament-jobs` CLI (§4) over the existing `FileRunnerBox`: `submit`/`status`/
  `logs`/`fetch`/`cancel`/`ls` + `node up`/`pair`/`ls`. `runner_cli.py` becomes a thin
  `filament-jobs submit` shim.
- Implement **container exec** in `box_executor.run_job` (docker + nvidia-container-toolkit
  when `spec.container` is set; bare exec otherwise). Node advertises docker availability
  at bring-up; `container` job to a docker-less node is rejected cleanly.
- Generalize **durability** to `{dest, interval_s}` with the periodic-checkpoint variant
  (for training); today's `_maybe_rclone` is the one-shot case.

### Phase 3 — Queue + concurrency + per-GPU dispatch — **M–L**

- Promote the inbox into a file-backed **queue** with explicit states; wire
  `status`/`ls`/`cancel` to it.
- Replace the single loop with a **bounded worker pool** and a **per-resource (per-GPU)
  dispatch table** (`-hwaccel_device`/`CUDA_VISIBLE_DEVICES`), realizing the deferred 2×T4
  parallelism. Preserve claim-then-move idempotency. **This is the largest behavior
  change; gate it behind a `--concurrency` default of 1 so it's opt-in until proven.**

### Phase 4 — Backend abstraction + a second backend — **M** (per backend)

- Extract the **`Backend` interface** (§8); `FilamentBackend` wraps the existing host
  code. No behavior change — pure refactor with the interface as the seam.
- Implement **one** alternative backend end-to-end (Modal recommended: lowest glue, best
  optics) as proof the spec truly lifts. SkyPilot/rented-VM follow the same interface
  later, on demand.

**Honest effort summary:** Phases 1–2 are mostly renames, doc work, and additive spec
fields over an engine that's already generic — low risk. Phase 3 (real concurrency +
per-GPU dispatch + a durable queue) is the genuinely hard, behavior-changing piece and
should be opt-in (`--concurrency 1` default) until validated on real 2×T4 hardware. Phase
4 is bounded per backend and only pays off once we're renting. None of it requires
touching the transport layer beyond consuming the R1–R6 guarantees.

---

## Open questions

1. **Queue durability granularity.** Is a `.queue/` dir of state-files enough, or do we
   want a tiny SQLite index for fast `ls`/filtering at scale? (Lean: files first;
   SQLite only if `ls` gets slow.)
2. **Container as default?** Should `node up --profile ml` default jobs to container exec
   for reproducibility, accepting the docker/toolkit dependency on the node? Or keep bare
   exec the default everywhere and make container strictly opt-in per spec? (Lean: bare
   default, container opt-in — matches the gift-T4 reality.)
3. **Explicit ACK vs fixed reship (R4).** Worth adding a host→node completion ACK so the
   node stops reshipping early, or is the bounded fixed-count reship (today) good enough?
   (Trades a little wasted bandwidth for protocol simplicity.)
4. **Output globs/dirs over the file channel.** Shipping a directory/glob as a tarball is
   clean, but loses per-file resume granularity on a flaky link. Tar the whole `outputs/`
   dir, or ship per-file and tar only on request? (Lean: per-file for small sets, tar for
   large image sequences — a spec flag.)
5. **Multi-tenant isolation depth.** Is process + scratch-dir separation sufficient, or do
   we need container-per-job / cgroup caps as a core feature rather than a node profile?
   (Depends on whether nodes are ever shared across trust domains.)
6. **Periodic-job ownership.** Host-side scheduler (cron / the `schedule` harness) vs a
   thin `filament-jobs cron` wrapper vs node-side timers. (Lean: host-side — keeps the
   node a dumb watcher; node-side timers would re-introduce state we don't want on an
   ephemeral box.)
