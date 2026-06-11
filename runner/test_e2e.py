#!/usr/bin/env python3
"""End-to-end test for the filament-native job runner — LOCAL loopback only.

Stands up a SEPARATE filament acceptor on this host (isolated config dirs + the
locally-built binary, NEVER the user's live daemon `bjndaw8bp` or the installed
~/.local/bin/filament), pairs it to a host identity over three channels
(ctl/din/dout), then runs a REAL ffmpeg transcode through the full
submit -> stream -> fetch -> manifest loop.

Asserts:
  * outputs come back byte-correct (manifest sha256 == sha256 of the pulled file)
  * exit_code == 0 and progress was parsed (non-empty frame/out_time stream)
  * a timeout job is killed and reported (exit 124, timed_out true)

NVENC is used if this host has a GPU; otherwise it falls back to CPU libx264.
The test validates RUNNER mechanics + manifest + artifact return; NVENC-specific
behavior is validated on the real T4 later.

Run:  runner/run_local_test.sh    (boots backend + box acceptors, then this file)
or:   FILJOB_SERVER=... FILJOB_BIN=... python3 runner/test_e2e.py
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
from filament_runner import RunnerBox, Job  # noqa: E402

SERVER = os.environ["FILJOB_SERVER"]
BIN = os.environ["FILJOB_BIN"]
HOST_CFG = os.environ["FILJOB_HOST_CFG"]
HOST_DOUT_CFG = os.environ["FILJOB_HOST_DOUT_CFG"]
REMOTE_ROOT = os.environ.get("FILJOB_REMOTE_ROOT")          # box jobs root
REMOTE_INBOX = os.environ.get("FILJOB_REMOTE_INBOX")        # box din drop dir
BOX_DOUT_CFG = os.environ.get("FILJOB_BOX_DOUT_CFG")        # box dout-only config dir


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
        # encoder listed != usable; a real GPU is needed. nvidia-smi present is our proxy.
        return shutil.which("nvidia-smi") is not None
    except Exception:
        return False


def make_input(path):
    """Generate a short, deterministic test clip with ffmpeg (testsrc)."""
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
    return RunnerBox(
        petname_ctl="box",
        petname_din="box-in",
        petname_dout="box-out",
        server=SERVER,
        host_config_dir=HOST_CFG,
        filament_bin=BIN,
        box_petname_for_host_dout="host-out",
        remote_jobs_root=REMOTE_ROOT,
        remote_inbox=REMOTE_INBOX,
        box_dout_config_dir=BOX_DOUT_CFG,
        connect_grace_s=4.0,
    )


def run_dout_with(rb, job, out_dir):
    # fetch() needs the dout config dir (with the dout secret) to run the host sink
    return rb.fetch(job, out_dir, dout_config_dir=HOST_DOUT_CFG)


def test_real_transcode():
    print("\n=== TEST 1: real transcode (submit/stream/fetch/manifest) ===")
    nvenc = have_nvenc()
    print(f"  encoder: {'NVENC (GPU present)' if nvenc else 'libx264 CPU fallback'}")
    work = tempfile.mkdtemp(prefix="filjob_in_")
    out_dir = tempfile.mkdtemp(prefix="filjob_out_")
    make_input(os.path.join(work, "input.mp4"))

    rb = new_box()
    job = Job.new(cmd=transcode_cmd(nvenc), inputs=["input.mp4"],
                  outputs=["out.mp4"], timeout_s=300, id="j-transcode-001")

    kinds = []
    progress_seen = {"frame": False, "out_time": False}
    try:
        rb.open_session()
        rb.submit(job, local_input_dir=work)
        print("  submit ok")
        for ev in rb.stream(job):
            kinds.append(ev.kind)
            if ev.kind == "progress":
                if "frame" in ev.data:
                    progress_seen["frame"] = True
                if "out_time" in ev.data:
                    progress_seen["out_time"] = True
            if ev.kind in ("begin", "done"):
                print(f"  event: {ev.kind} {ev.data if ev.data else ''}")
        print(f"  progress events: {kinds.count('progress')} ; frame seen={progress_seen['frame']} out_time seen={progress_seen['out_time']}")
        m = run_dout_with(rb, job, out_dir)
    finally:
        rb.close_session()
    print(f"  manifest: {json.dumps(m, indent=2) if m else None}")

    # ---- assertions ----
    assert m is not None, "no manifest returned"
    assert m["exit_code"] == 0, f"exit_code != 0: {m['exit_code']}"
    assert m["timed_out"] is False, "unexpected timeout"
    assert "begin" in kinds and "done" in kinds, f"missing lifecycle events: {set(kinds)}"
    assert kinds.count("progress") > 0, "no progress events parsed"
    assert progress_seen["frame"] or progress_seen["out_time"], "no frame/out_time in progress"

    out_entry = next(o for o in m["outputs"] if o["name"] == "out.mp4")
    assert out_entry["sha256"] is not None and not out_entry.get("missing"), "out.mp4 missing in manifest"
    pulled = os.path.join(out_dir, "out.mp4")
    assert os.path.exists(pulled), "out.mp4 not pulled back"
    local_sha = sha256_file(pulled)
    assert local_sha == out_entry["sha256"], (
        f"sha mismatch: manifest={out_entry['sha256']} pulled={local_sha}")
    assert os.path.getsize(pulled) == out_entry["bytes"], "byte-size mismatch"
    print(f"  ✓ byte-correct: sha256 {local_sha[:16]}… ({out_entry['bytes']} B) matches manifest")
    print(f"  ✓ gpu field: {m['gpu']!r}")
    print("  TEST 1 PASS")
    return True


def test_timeout():
    print("\n=== TEST 2: timeout job is killed and reported ===")
    work = tempfile.mkdtemp(prefix="filjob_to_in_")
    out_dir = tempfile.mkdtemp(prefix="filjob_to_out_")
    # a job that never finishes within the timeout: sleep well past timeout_s
    rb = new_box()
    job = Job.new(cmd=["sleep", "120"], inputs=[], outputs=[], timeout_s=4, id="j-timeout-001")
    try:
        rb.open_session()
        rb.submit(job, local_input_dir=work)
        print("  submit ok")
        t0 = time.monotonic()
        kinds = [ev.kind for ev in rb.stream(job)]
        elapsed = time.monotonic() - t0
        print(f"  stream finished in {elapsed:.1f}s; events: {kinds}")
        m = run_dout_with(rb, job, out_dir)
    finally:
        rb.close_session()
    print(f"  manifest: {json.dumps(m, indent=2) if m else None}")

    assert m is not None, "no manifest for timeout job"
    assert m["timed_out"] is True, "timed_out flag not set"
    assert m["exit_code"] == 124, f"expected exit 124, got {m['exit_code']}"
    assert elapsed < 60, f"timeout took too long ({elapsed:.0f}s) — not actually killed"
    print("  ✓ timed out, killed, exit 124 reported")
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
