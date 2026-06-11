#!/usr/bin/env python3
"""End-to-end test for the FILE-DRIVEN filament job runner — LOCAL loopback only.

Drives the file-driven control plane (FileRunnerBox + watcher.py) against an
isolated box on this host (isolated config dirs + the locally-built binary, NEVER
the user's live daemon or the installed ~/.local/bin/filament). The box-side
watcher + din acceptor are started by run_local_test.sh; this script is the HOST.

Flow per job:  host.submit(spec+inputs over din)  ->  watcher runs the job  ->
host.await_results(stand up dout sink, poll for manifest+outputs).  NO PTY.

Asserts:
  * the manifest comes back OVER THE FILE CHANNEL (dout), job_id matches
  * exit_code == 0
  * each declared output's sha256 in the manifest matches the PULLED bytes
  * a timeout job (sleep, small timeout_s) is killed and reported exit 124 / timed_out

NVENC is used if this host has a GPU; otherwise CPU libx264 (validates the RUNNER;
NVENC is validated on the real T4). Relay is DIRECT here (local TURN may be absent);
the bring-up + host default to --relay for the WAN.

Run:  runner/run_local_test.sh
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from filament_runner import FileRunnerBox, Job  # noqa: E402

SERVER = os.environ["FILJOB_SERVER"]
BIN = os.environ["FILJOB_BIN"]
HOST_CFG = os.environ["FILJOB_HOST_CFG"]
HOST_DOUT_CFG = os.environ["FILJOB_HOST_DOUT_CFG"]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def have_nvenc():
    try:
        out = subprocess.run(["ffmpeg", "-hide_banner", "-encoders"],
                             capture_output=True, text=True, timeout=20)
        if "h264_nvenc" not in out.stdout:
            return False
        return shutil.which("nvidia-smi") is not None
    except Exception:
        return False


def make_input(path):
    subprocess.run(
        ["ffmpeg", "-y", "-f", "lavfi", "-i", "testsrc=duration=4:size=640x480:rate=25",
         "-pix_fmt", "yuv420p", path],
        check=True, capture_output=True,
    )


def transcode_cmd(nvenc):
    if nvenc:
        return ["ffmpeg", "-y", "-hwaccel", "cuda", "-hwaccel_output_format", "cuda",
                "-i", "input.mp4", "-vf", "scale_cuda=-2:240",
                "-c:v", "h264_nvenc", "-preset", "p5", "-b:v", "1M",
                "-progress", "pipe:1", "-nostats", "out.mp4"]
    return ["ffmpeg", "-y", "-i", "input.mp4", "-vf", "scale=-2:240",
            "-c:v", "libx264", "-preset", "veryfast", "-b:v", "1M",
            "-progress", "pipe:1", "-nostats", "out.mp4"]


def new_box():
    # DIRECT route locally (relay=False); the WAN bring-up/host default to relay.
    return FileRunnerBox(
        petname_box_din="box-in",
        server=SERVER,
        host_config_dir=HOST_CFG,
        host_dout_config_dir=HOST_DOUT_CFG,
        filament_bin=BIN,
        relay=False,
    )


def test_real_transcode():
    print("\n=== TEST 1: real transcode (file-driven submit/await/manifest) ===")
    nvenc = have_nvenc()
    print(f"  encoder: {'NVENC (GPU present)' if nvenc else 'libx264 CPU fallback'}")
    work = tempfile.mkdtemp(prefix="filjob_in_")
    out_dir = tempfile.mkdtemp(prefix="filjob_out_")
    make_input(os.path.join(work, "input.mp4"))

    rb = new_box()
    job = Job.new(cmd=transcode_cmd(nvenc), inputs=["input.mp4"],
                  outputs=["out.mp4"], timeout_s=300, id="j-transcode-001")

    rb.submit(job, local_input_dir=work)
    print("  submit ok")
    m = rb.await_results(job, out_dir, overall_timeout_s=240)
    print(f"  manifest: {json.dumps(m, indent=2) if m else None}")

    # ---- assertions ----
    assert m is not None, "no manifest returned over the file channel"
    assert m["job_id"] == job.id, f"manifest job_id mismatch: {m['job_id']}"
    assert m["exit_code"] == 0, f"exit_code != 0: {m['exit_code']}"
    assert m["timed_out"] is False, "unexpected timeout"

    out_entry = next(o for o in m["outputs"] if o["name"] == "out.mp4")
    assert out_entry["sha256"] is not None and not out_entry.get("missing"), "out.mp4 missing in manifest"
    pulled = os.path.join(out_dir, "out.mp4")
    assert os.path.exists(pulled), "out.mp4 not pulled back over dout"
    local_sha = sha256_file(pulled)
    assert local_sha == out_entry["sha256"], (
        f"sha mismatch: manifest={out_entry['sha256']} pulled={local_sha}")
    assert os.path.getsize(pulled) == out_entry["bytes"], "byte-size mismatch"
    print(f"  ✓ byte-correct over file channel: sha256 {local_sha[:16]}… "
          f"({out_entry['bytes']} B) matches manifest")
    print(f"  ✓ gpu={m.get('gpu')!r}  gpus={m.get('gpus')!r}")
    print("  TEST 1 PASS")
    return True


def test_timeout():
    print("\n=== TEST 2: timeout job is killed and reported (file-driven) ===")
    work = tempfile.mkdtemp(prefix="filjob_to_in_")
    out_dir = tempfile.mkdtemp(prefix="filjob_to_out_")
    rb = new_box()
    job = Job.new(cmd=["sleep", "120"], inputs=[], outputs=[], timeout_s=4, id="j-timeout-001")

    rb.submit(job, local_input_dir=work)
    print("  submit ok")
    t0 = time.monotonic()
    # the watcher kills the job at timeout_s and ships the manifest; await it.
    m = rb.await_results(job, out_dir, overall_timeout_s=90)
    elapsed = time.monotonic() - t0
    print(f"  await finished in {elapsed:.1f}s")
    print(f"  manifest: {json.dumps(m, indent=2) if m else None}")

    assert m is not None, "no manifest for timeout job"
    assert m["job_id"] == job.id, "manifest job_id mismatch"
    assert m["timed_out"] is True, "timed_out flag not set"
    assert m["exit_code"] == 124, f"expected exit 124, got {m['exit_code']}"
    assert elapsed < 80, f"timeout took too long ({elapsed:.0f}s) — not actually killed"
    print("  ✓ timed out, killed, exit 124 reported over the file channel")
    print("  TEST 2 PASS")
    return True


if __name__ == "__main__":
    ok = True
    try:
        test_real_transcode()
    except Exception as e:
        ok = False
        print(f"  TEST 1 FAIL: {e}")
        import traceback; traceback.print_exc()
    try:
        test_timeout()
    except Exception as e:
        ok = False
        print(f"  TEST 2 FAIL: {e}")
        import traceback; traceback.print_exc()
    print("\n" + ("ALL TESTS PASSED" if ok else "TESTS FAILED"))
    sys.exit(0 if ok else 1)
