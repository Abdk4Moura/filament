#!/usr/bin/env python3
"""Flaky-link e2e DRIVER (host side) — drives the runner while inducing outages.

Run by flaky_sim_test.sh. Every filament client (this host, the box din acceptor,
the box watcher) talks to the signaling backend THROUGH the flaky proxy; this
driver toggles the proxy's down-flag to choreograph the three failure modes, on
top of the proxy's background random flapper. It then asserts the runner recovered:

  TEST A (discovery race): force the link DOWN, then submit. A single `send` would
     give up with "no peer connected"; retry-until-peer must land the job anyway.

  TEST B+C (truncation + lost manifest): while awaiting results, a background
     "chaos" thread keeps dropping the link in short bursts. Result transfers
     truncate and manifests land in dead windows; the host's sha256 integrity gate
     must reject partials and keep awaiting, and the box must re-ship until acked.
     The job must STILL come back complete + byte-correct, and the box watcher must
     observe the host ack (verified from its log by the shell wrapper).

Asserts the SAME correctness bar as the clean test: manifest job_id matches,
exit_code 0, each declared output's sha256 == manifest == pulled bytes.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.dirname(HERE)
sys.path.insert(0, RUNNER)
from filament_runner import FileRunnerBox, Job  # noqa: E402

SERVER = os.environ["FILJOB_SERVER"]
BIN = os.environ["FILJOB_BIN"]
HOST_CFG = os.environ["FILJOB_HOST_CFG"]
HOST_DOUT_CFG = os.environ["FILJOB_HOST_DOUT_CFG"]
DOWN_FLAG = os.environ["FILJOB_DOWN_FLAG"]


def link_down():
    open(DOWN_FLAG, "w").close()


def link_up():
    try:
        os.remove(DOWN_FLAG)
    except FileNotFoundError:
        pass


def log(m):
    print(f"[flaky-e2e] {m}", flush=True)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def make_input(path):
    # a few MB so a mid-transfer drop produces a genuine partial (the real bug was
    # a 7 KB partial of a multi-MB file), but small enough that a transfer can
    # complete inside a flapper up-window (so the runner demonstrably recovers).
    subprocess.run(
        ["ffmpeg", "-y", "-f", "lavfi", "-i",
         "testsrc=duration=6:size=854x480:rate=25", "-pix_fmt", "yuv420p", path],
        check=True, capture_output=True,
    )


def transcode_cmd():
    # CPU libx264 (the local box has no GPU); validates the RUNNER transport, which
    # is what the flaky link breaks. NVENC is validated on the real T4.
    return ["ffmpeg", "-y", "-i", "input.mp4", "-vf", "scale=-2:360",
            "-c:v", "libx264", "-preset", "veryfast", "-b:v", "2M",
            "-progress", "pipe:1", "-nostats", "out.mp4"]


def new_box():
    return FileRunnerBox(
        petname_box_din="box-in", server=SERVER,
        host_config_dir=HOST_CFG, host_dout_config_dir=HOST_DOUT_CFG,
        filament_bin=BIN, relay=False,
        # retry-until-peer: each send bounded at 30s (abandon+re-invoke a wedge),
        # the loop retries up to the submit deadline.
        cli_send_timeout_s=30, submit_deadline_s=360, send_retry_gap_s=2.0,
        ack_attempts=20, sink_cadence_s=60.0,
    )


class Chaos:
    """Background thread that keeps dropping the link in short bursts while a
    transfer is in flight — truncating result sends and losing manifests."""

    def __init__(self, down_s=3.0, up_s=4.0):
        self.down_s, self.up_s = down_s, up_s
        self._stop = threading.Event()
        self._t = None
        self.bursts = 0

    def start(self):
        def loop():
            # let the first transfer attempt get going, then chop it
            self._stop.wait(self.up_s)
            while not self._stop.is_set():
                link_down()
                self.bursts += 1
                log(f"chaos: link DOWN (burst {self.bursts})")
                self._stop.wait(self.down_s)
                link_up()
                log("chaos: link UP")
                self._stop.wait(self.up_s)
        self._t = threading.Thread(target=loop, daemon=True)
        self._t.start()

    def stop(self):
        self._stop.set()
        if self._t:
            self._t.join(timeout=2)
        link_up()


def run():
    # root the scratch dirs under the wrapper's $WORK when provided, so the
    # wrapper's cleanup removes them and a killed run leaves nothing behind.
    base = os.environ.get("FILJOB_WORK") or tempfile.gettempdir()
    work = tempfile.mkdtemp(prefix="in_", dir=base)
    out_dir = tempfile.mkdtemp(prefix="out_", dir=base)
    log("building multi-MB input ...")
    make_input(os.path.join(work, "input.mp4"))
    in_sz = os.path.getsize(os.path.join(work, "input.mp4"))
    log(f"input.mp4 = {in_sz} bytes")

    rb = new_box()
    job = Job.new(cmd=transcode_cmd(), inputs=["input.mp4"], outputs=["out.mp4"],
                  timeout_s=120, id="j-flaky-001")

    chaos_on = os.environ.get("FILJOB_SIM_CHAOS", "1") != "0"

    # ---- TEST A: discovery race during submit --------------------------------
    if chaos_on:
        log("=== TEST A: link DOWN at submit — retry-until-peer must recover ===")
        link_down()
        log("link forced DOWN; starting submit (single-shot send would give up)")

        def _heal():
            # hold the forced outage ~6s: long enough that a single non-retrying
            # send fails (its /api/room and establishment hit a dead link), so the
            # recovery is demonstrably the retry-until-peer loop landing the push.
            time.sleep(6)
            link_up()
            log("forced outage cleared (retry-until-peer can now connect; flapper still flaps)")
        threading.Thread(target=_heal, daemon=True).start()
    else:
        log("=== BASELINE (FILJOB_SIM_CHAOS=0): no scripted outages; gentle flapper only ===")

    t0 = time.monotonic()
    rb.submit(job, local_input_dir=work)
    log(f"submit landed in {time.monotonic() - t0:.0f}s")

    # ---- TEST B+C: chaos during result transfer ------------------------------
    chaos = None
    if chaos_on:
        log("=== TEST B+C: chaos during results — truncation rejected + manifest re-shipped until acked ===")
        # drop for 2.5s every ~22s: long enough up-windows that a result transfer
        # eventually completes, but several early rounds get truncated / lost first
        # (so the integrity gate + reship-until-ack are genuinely exercised).
        chaos = Chaos(down_s=2.5, up_s=20.0)
        chaos.start()
    try:
        m = rb.await_results(job, out_dir, overall_timeout_s=420)
    finally:
        if chaos:
            chaos.stop()
    if chaos:
        log(f"await returned after {chaos.bursts} induced outage burst(s)")

    # ---- correctness assertions (same bar as the clean test) -----------------
    assert m is not None, "no manifest returned"
    assert m["job_id"] == job.id, f"manifest job_id mismatch: {m['job_id']}"
    assert m["exit_code"] == 0, f"exit_code != 0: {m['exit_code']}"
    assert m["timed_out"] is False, "unexpected timeout"
    out_entry = next(o for o in m["outputs"] if o["name"] == "out.mp4")
    assert out_entry["sha256"] and not out_entry.get("missing"), "out.mp4 missing in manifest"
    pulled = os.path.join(out_dir, "out.mp4")
    assert os.path.exists(pulled), "out.mp4 not pulled back"
    local_sha = sha256_file(pulled)
    assert local_sha == out_entry["sha256"], (
        f"SHA MISMATCH (truncation slipped through!): manifest={out_entry['sha256']} "
        f"pulled={local_sha}")
    assert os.path.getsize(pulled) == out_entry["bytes"], (
        f"byte-size mismatch: pulled={os.path.getsize(pulled)} manifest={out_entry['bytes']}")
    log(f"OK: out.mp4 byte-correct over flaky link — sha {local_sha[:16]}… "
        f"({out_entry['bytes']} B) == manifest")
    log("FLAKY E2E PASS")
    shutil.rmtree(work, ignore_errors=True)
    return True


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        log(f"FLAKY E2E FAIL: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    sys.exit(0)
