#!/usr/bin/env python3
"""filament job runner — box-side executor (the FIXED, single-invocation node program).

This is the ONLY thing the host ever runs on the remote box. It is a *fixed*
program: the host does not pipe arbitrary shell commands across the PTY. Instead
the host pushes a job spec + this script into a scratch dir and invokes:

    python3 box_executor.py <job_dir>

The executor reads `<job_dir>/job.json`, runs the declared `cmd` inside the
scratch dir under a timeout, captures exit code + per-output sha256/size +
wall-clock + GPU name, writes `<job_dir>/manifest.json`, and (optionally) runs a
durability step (`rclone copy` to R2) before the ephemeral box dies.

Structured progress is emitted on stdout as sentinel-framed lines so the host can
parse them out of an interactive PTY stream that also carries shell echo/prompts:

    FILJOB v1 <job_id> begin
    FILJOB v1 <job_id> progress {"frame":123,"fps":58.0,"out_time":"00:00:04.1",...}
    FILJOB v1 <job_id> manifest <one-line json>
    FILJOB v1 <job_id> done exit=<code>

The sentinel prefix (FILJOB) lets the host recover structure even though a login
shell, not a clean pipe, is on the other end of `filament pty`.

Job spec (job.json):
    {
      "id": "j-...",                # job id
      "inputs": ["a.mov", ...],     # files already pushed into job_dir
      "cmd": ["ffmpeg", "...", "-progress","pipe:1","-nostats","out.mp4"],
      "outputs": ["out.mp4", ...],  # declared artifacts to hash + (optionally) ship
      "timeout_s": 1800,
      "rclone_dest": "r2:reel/"     # OPTIONAL durability target; no-op if unset
    }

Stdlib-only. Targets the T4 stack: glibc 2.35 / python3.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

PROTO = "FILJOB v1"

# ffmpeg `-progress pipe:1` emits `key=value` lines; these are the ones worth
# surfacing as live progress. A `progress=end` line marks a flush boundary.
_PROGRESS_KEYS = ("frame", "fps", "out_time", "out_time_ms", "total_size", "speed", "bitrate")


def _emit(job_id, verb, payload=""):
    """Write one sentinel-framed line and flush (PTY buffering is unforgiving)."""
    line = f"{PROTO} {job_id} {verb}"
    if payload != "":
        line += f" {payload}"
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _sha256_and_size(path):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def _gpu_name():
    """`nvidia-smi --query-gpu=name` — the GPU the job actually ran on. Best-effort:
    on a CPU-only host (e.g. the local loopback test) there is no nvidia-smi, so we
    record None rather than failing the job."""
    smi = shutil.which("nvidia-smi")
    if not smi:
        return None
    try:
        out = subprocess.run(
            [smi, "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            name = out.stdout.strip().splitlines()
            return name[0].strip() if name else None
    except Exception:
        pass
    return None


def _run_with_progress(cmd, job_dir, job_id, timeout_s):
    """Run `cmd` in job_dir, parsing ffmpeg -progress lines off its stdout and
    re-emitting them as structured `progress` events. Returns (exit_code, timed_out).

    The child is started in its own process group so a timeout kills the whole
    tree (ffmpeg + any helpers), not just the parent. A dedicated watchdog thread
    enforces the timeout REGARDLESS of whether the child emits any output — a job
    like `sleep` produces no stdout, so a between-lines check alone would never
    fire."""
    import threading

    proc = subprocess.Popen(
        cmd,
        cwd=job_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,  # own process group for clean timeout kill
    )

    timed_out = {"v": False}
    cancel = threading.Event()

    def watchdog():
        if not timeout_s:
            return
        if cancel.wait(timeout=timeout_s):
            return  # job finished before the timeout
        # deadline hit: kill the whole process group (TERM, then KILL)
        timed_out["v"] = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        if not cancel.wait(timeout=5):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass

    wd = threading.Thread(target=watchdog, daemon=True)
    wd.start()

    acc = {}
    try:
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            # ffmpeg -progress pipe:1 lines look like `frame=123` / `out_time=...`
            m = re.match(r"^([A-Za-z_]+)=(.*)$", line.strip())
            if m and m.group(1) in _PROGRESS_KEYS:
                key, val = m.group(1), m.group(2).strip()
                if key in ("frame", "out_time_ms", "total_size"):
                    try:
                        acc[key] = int(val)
                    except ValueError:
                        acc[key] = val
                elif key == "fps":
                    try:
                        acc[key] = float(val)
                    except ValueError:
                        acc[key] = val
                else:
                    acc[key] = val
            elif line.strip() == "progress=end" or line.strip() == "progress=continue":
                # flush an accumulated progress frame at each ffmpeg boundary
                if acc:
                    _emit(job_id, "progress", json.dumps(acc, separators=(",", ":")))
                    acc = {}
    except Exception:
        pass

    rc = proc.wait()
    cancel.set()  # stop the watchdog
    wd.join(timeout=2)

    if timed_out["v"]:
        return (124, True)  # 124 == timeout, matching coreutils `timeout`
    if acc:
        _emit(job_id, "progress", json.dumps(acc, separators=(",", ":")))
    return (rc, False)


def _maybe_rclone(job_dir, dest, outputs, job_id):
    """Optional durability hook: push declared outputs to object storage before the
    box dies. PLUGGABLE / NO-OP when no dest configured or rclone is absent.
    Creds come from rclone's own config/env — never passed on the command line."""
    if not dest:
        return {"ran": False, "reason": "no rclone_dest configured"}
    rclone = shutil.which("rclone")
    if not rclone:
        return {"ran": False, "reason": "rclone not installed"}
    results = []
    for name in outputs:
        src = os.path.join(job_dir, name)
        if not os.path.exists(src):
            results.append({"name": name, "ok": False, "reason": "missing"})
            continue
        try:
            r = subprocess.run([rclone, "copy", src, dest], capture_output=True, text=True, timeout=600)
            results.append({"name": name, "ok": r.returncode == 0, "code": r.returncode})
        except Exception as e:
            results.append({"name": name, "ok": False, "reason": str(e)[:120]})
    return {"ran": True, "dest": dest, "results": results}


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: box_executor.py <job_dir>\n")
        return 2
    job_dir = os.path.abspath(argv[1])
    spec_path = os.path.join(job_dir, "job.json")
    with open(spec_path) as f:
        job = json.load(f)

    job_id = job["id"]
    cmd = job["cmd"]
    outputs = job.get("outputs", [])
    timeout_s = job.get("timeout_s", 0)
    rclone_dest = job.get("rclone_dest") or None

    _emit(job_id, "begin")
    wall_start = time.time()

    exit_code, timed_out = _run_with_progress(cmd, job_dir, job_id, timeout_s)

    duration_s = round(time.time() - wall_start, 3)
    gpu = _gpu_name()

    out_manifest = []
    for name in outputs:
        path = os.path.join(job_dir, name)
        if os.path.exists(path):
            sha, size = _sha256_and_size(path)
            out_manifest.append({"name": name, "sha256": sha, "bytes": size})
        else:
            out_manifest.append({"name": name, "sha256": None, "bytes": None, "missing": True})

    durability = _maybe_rclone(job_dir, rclone_dest, outputs, job_id)

    manifest = {
        "job_id": job_id,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "outputs": out_manifest,
        "duration_s": duration_s,
        "gpu": gpu,
        "durability": durability,
        "executor_proto": PROTO,
    }
    manifest_path = os.path.join(job_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # one-line manifest on the wire too, so the host has it even before fetch
    _emit(job_id, "manifest", json.dumps(manifest, separators=(",", ":")))
    _emit(job_id, "done", f"exit={exit_code}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
