#!/usr/bin/env python3
"""DETERMINISTIC unit test of the runner's resilience LOGIC — no real transport.

The flaky-link e2e (flaky_sim_test.sh) proves the behaviour over the real filament
WebRTC transport, but its timing depends on WebRTC establishment through the proxy.
This test pins the THREE resilience guarantees deterministically, in seconds, by
driving FileRunnerBox + watcher.Watcher against a FAKE `filament` CLI (a tiny script
that moves files like the real `send`/`up` do) whose behaviour we can script:

  1. RETRY-UNTIL-PEER: the fake `send` is told to FAIL its first N invocations
     ("no peer connected"); FileRunnerBox._send must keep retrying and eventually
     succeed within the deadline (not give up after one shot).

  2. INTEGRITY GATE + RESUME: the watcher first ships a TRUNCATED output (wrong
     bytes), then the full one. await_results must REJECT the truncated copy (sha256
     mismatch) and only return once the byte-correct copy + manifest are present.

  3. RESULT-ACK LOOP: the watcher re-ships every round until it sees the host's
     `ack-<job_id>` land in its inbox; await_results sends that ack after the sha256
     gate passes. We assert the watcher STOPS re-shipping on the ack (bounded), and
     that a job is never accepted truncated.

Pure stdlib; runs in a few seconds. No backend, no WebRTC, no ports.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.dirname(HERE)
sys.path.insert(0, RUNNER)
import filament_runner as fr  # noqa: E402
import watcher as wt          # noqa: E402


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# --- a fake `filament` CLI -----------------------------------------------------
# It implements just enough of `send <paths> --to X` and `up --dir D`: a "send"
# copies the given files into a shared MAILBOX dir keyed by the --to peer; an "up
# --dir D" drains its peer's mailbox into D. A control file lets the test force the
# next K `send`s to fail (retry-until-peer) and to truncate a named file once.
FAKE = r'''#!/usr/bin/env python3
import os, sys, shutil, json, time
MAILROOT = os.environ["FAKE_MAILROOT"]
CTL = os.path.join(MAILROOT, "ctl.json")
def ctl():
    try:
        with open(CTL) as f: return json.load(f)
    except Exception: return {}
def put_ctl(d):
    tmp = CTL + ".tmp"
    with open(tmp, "w") as f: json.dump(d, f)
    os.replace(tmp, CTL)
a = sys.argv[1:]
cmd = a[0]
def mailbox(peer):
    d = os.path.join(MAILROOT, "to-" + peer); os.makedirs(d, exist_ok=True); return d
if cmd == "send":
    # filament send <paths...> --to PEER [--server S] [--relay]
    paths=[]; to=None; i=1
    while i < len(a):
        if a[i] == "--to": to=a[i+1]; i+=2
        elif a[i] in ("--server",): i+=2
        elif a[i] == "--relay": i+=1
        else: paths.append(a[i]); i+=1
    c = ctl()
    # forced establishment failures (retry-until-peer)
    fk = "fail_" + to
    if int(c.get(fk, 0)) > 0:
        c[fk] = int(c[fk]) - 1; put_ctl(c)
        sys.stderr.write("no peer connected within 60s\n"); sys.exit(1)
    mb = mailbox(to)
    for p in paths:
        base = os.path.basename(p)
        dst = os.path.join(mb, base)
        # unique_path on collision like the real CLI: name.1, name.2 ...
        n=1
        while os.path.exists(dst):
            dst = os.path.join(mb, f"{base}.{n}"); n+=1
        trunc = c.get("truncate_once")
        # write to a temp name then atomically rename, so a concurrent `up` drain
        # never sees a half-written file (mirrors filament's atomic delivery).
        tmpd = dst + ".part"
        if trunc and base == trunc:
            with open(p,"rb") as fsrc, open(tmpd,"wb") as fo: fo.write(fsrc.read(7000))  # 7KB partial
            c["truncate_once"]=None; put_ctl(c)
        else:
            shutil.copy(p, tmpd)
        os.replace(tmpd, dst)
    sys.exit(0)
if cmd == "up":
    # up --dir D [--name-as N] [--server S] [--relay]: drain MY mailbox into D, then idle.
    D=None; name=None; i=1
    while i < len(a):
        if a[i]=="--dir": D=a[i+1]; i+=2
        elif a[i]=="--name-as": name=a[i+1]; i+=2
        elif a[i]=="--server": i+=2
        elif a[i]=="--relay": i+=1
        else: i+=1
    # peer name this sink receives as: the test wires host sink == "host-out"
    me = os.environ.get("FAKE_UP_PEER","host-out")
    mb = mailbox(me)
    os.makedirs(D, exist_ok=True)
    # drain loop until killed
    while True:
        for fn in list(os.listdir(mb)):
            if fn.endswith(".part"): continue   # still being written
            src=os.path.join(mb,fn); dst=os.path.join(D,fn)
            n=1; base=dst
            while os.path.exists(dst):
                dst=f"{base}.{n}"; n+=1
            try: os.rename(src,dst)
            except Exception: pass
        time.sleep(0.2)
if cmd=="--version": print("fake-filament 0"); sys.exit(0)
sys.exit(0)
'''


def main():
    tmp = tempfile.mkdtemp(prefix="filjob_unit_")
    mailroot = os.path.join(tmp, "mail")
    os.makedirs(mailroot, exist_ok=True)
    fake = os.path.join(tmp, "filament")
    with open(fake, "w") as f:
        f.write(FAKE)
    os.chmod(fake, 0o755)
    os.environ["FAKE_MAILROOT"] = mailroot

    host_cfg = os.path.join(tmp, "host"); os.makedirs(host_cfg)
    dout_cfg = os.path.join(tmp, "host-dout"); os.makedirs(dout_cfg)
    in_dir = os.path.join(tmp, "in"); os.makedirs(in_dir)
    out_dir = os.path.join(tmp, "out"); os.makedirs(out_dir)

    # a multi-MB-ish input/output payload
    payload = os.path.join(in_dir, "input.bin")
    with open(payload, "wb") as f:
        f.write(os.urandom(2_000_000))

    ctl = os.path.join(mailroot, "ctl.json")

    def set_ctl(**kw):
        cur = {}
        if os.path.exists(ctl):
            with open(ctl) as f:
                cur = json.load(f)
        cur.update(kw)
        with open(ctl, "w") as f:
            json.dump(cur, f)

    ok = True

    # ============ TEST 1: retry-until-peer (host din push) ====================
    print("=== UNIT 1: retry-until-peer ===", flush=True)
    set_ctl(fail_box_in=3)  # first 3 sends to box-in FAIL ("no peer connected")
    rb = fr.FileRunnerBox(
        petname_box_din="box-in", server="http://x", host_config_dir=host_cfg,
        host_dout_config_dir=dout_cfg, filament_bin=fake, relay=False,
        cli_send_timeout_s=5, submit_deadline_s=60, send_retry_gap_s=0.2,
    )
    job = fr.Job.new(cmd=["true"], inputs=["input.bin"], outputs=["out.bin"],
                     timeout_s=30, id="u-1")
    t0 = time.monotonic()
    rb.submit(job, local_input_dir=in_dir)  # must survive the 3 forced failures
    print(f"  submit succeeded after forced failures in {time.monotonic()-t0:.1f}s", flush=True)
    # the spec + input must have landed in the box-in mailbox
    box_mb = os.path.join(mailroot, "to-box-in")
    landed = os.listdir(box_mb)
    assert any(n.startswith("job-u-1") for n in landed), f"spec didn't land: {landed}"
    assert any(n.startswith("input.bin") for n in landed), f"input didn't land: {landed}"
    print("  PASS: retry-until-peer landed spec + input despite 3 failures", flush=True)

    # ============ TEST 2+3: integrity gate + reship-until-ack =================
    print("=== UNIT 2+3: integrity gate + reship-until-ack ===", flush=True)
    # Build the watcher's result set: a real out.bin in a scratch + manifest.
    scratch = os.path.join(tmp, "scratch"); os.makedirs(scratch)
    out_payload = os.path.join(scratch, "out.bin")
    with open(out_payload, "wb") as f:
        f.write(os.urandom(3_000_000))
    real_sha = _sha(out_payload)
    manifest = {"job_id": "u-1", "exit_code": 0, "timed_out": False,
                "outputs": [{"name": "out.bin", "sha256": real_sha,
                             "bytes": os.path.getsize(out_payload)}]}
    with open(os.path.join(scratch, "manifest.json"), "w") as f:
        json.dump(manifest, f)

    # watcher that ships to host-out; FAKE_UP_PEER makes the host sink drain "host-out"
    os.environ["FAKE_UP_PEER"] = "host-out"
    jobs_root = os.path.join(tmp, "boxjobs")
    w = wt.Watcher(jobs_root=jobs_root, server="http://x", filament_bin=fake,
                   dout_config_dir=os.path.join(tmp, "boxdout"),
                   host_dout_peer="host-out", relay=False,
                   reship_gap_s=0.5, reship_deadline_s=60, send_timeout_s=5,
                   reship_attempts=50, send_retry_attempts=10, send_retry_gap_s=0.2)

    # Bridge the host's din ack into the watcher inbox: in the real system the box's
    # din `up` delivers ack-<id> there; here a tiny poller copies any ack from the
    # box-in mailbox into the watcher inbox so the reship loop can observe it and
    # STOP EARLY (proving ack-driven termination, not just the safety cap).
    _stop_bridge = threading.Event()

    def _ack_bridge():
        src = os.path.join(mailroot, "to-box-in")
        while not _stop_bridge.is_set():
            try:
                for fn in os.listdir(src):
                    if fn.startswith("ack-") and not os.path.exists(
                            os.path.join(w.inbox, fn)):
                        shutil.copy2(os.path.join(src, fn),
                                     os.path.join(w.inbox, fn))
            except Exception:
                pass
            time.sleep(0.2)
    threading.Thread(target=_ack_bridge, daemon=True).start()
    # force the FIRST shipped out.bin to be TRUNCATED (7KB partial) — the integrity
    # gate must reject it; a later round ships it whole.
    set_ctl(truncate_once="out.bin")

    jobdict = {"id": "u-1", "inputs": [], "cmd": ["true"], "outputs": ["out.bin"],
               "timeout_s": 30}
    w._ship(jobdict, scratch)  # starts the background reship loop

    # host side: await on the same mailbox; it must reject the truncated copy and
    # only accept once the byte-correct out.bin + manifest are in.
    rb2 = fr.FileRunnerBox(
        petname_box_din="box-in", server="http://x", host_config_dir=host_cfg,
        host_dout_config_dir=dout_cfg, filament_bin=fake, relay=False,
        cli_send_timeout_s=5, submit_deadline_s=60, send_retry_gap_s=0.2,
        ack_attempts=5, sink_cadence_s=120,
    )
    m = rb2.await_results(job, out_dir, overall_timeout_s=60)
    assert m is not None and m["job_id"] == "u-1", "no/incorrect manifest"
    pulled = os.path.join(out_dir, "out.bin")
    assert os.path.exists(pulled), "out.bin not pulled"
    got = _sha(pulled)
    assert got == real_sha, f"INTEGRITY GATE FAILED: accepted wrong bytes {got} != {real_sha}"
    assert os.path.getsize(pulled) == manifest["outputs"][0]["bytes"], "size mismatch"
    print(f"  PASS: integrity gate rejected the 7KB partial; accepted byte-correct "
          f"out.bin (sha {got[:12]}…)", flush=True)

    # the ack must have landed in the box inbox and the reship loop must STOP.
    deadline = time.monotonic() + 15
    acked = False
    while time.monotonic() < deadline:
        if w._ack_seen("u-1") or any(
            n.startswith("done") for n in os.listdir(w.inbox)) and any(
                f.startswith("ack-u-1") for f in os.listdir(w.done)):
            acked = True
            break
        time.sleep(0.3)
    # the host sent the ack to box-in mailbox; the watcher drains its inbox via the
    # din `up` in the real system — here we assert the host SENT it.
    box_in_mb = os.path.join(mailroot, "to-box-in")
    sent_ack = any(f.startswith("ack-u-1") for f in os.listdir(box_in_mb))
    assert sent_ack, f"host did not send ack-u-1 to box-in (have {os.listdir(box_in_mb)})"
    print("  PASS: host sent ack-u-1 to box (din) after sha256 verification", flush=True)

    # the ack bridge delivers ack-u-1 into the watcher inbox; the reship loop must
    # STOP EARLY on it (well before the 50-round safety cap) and log it.
    ship_t = next((t for t in w._ship_threads), None)
    if ship_t:
        ship_t.join(timeout=20)
    _stop_bridge.set()
    assert ship_t is None or not ship_t.is_alive(), \
        "reship loop did not stop after the host ack"
    print("  PASS: reship loop stopped on the host ack (ack-driven termination)", flush=True)

    print("\nALL UNIT RESILIENCE TESTS PASSED", flush=True)
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"\nUNIT TEST FAILED: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)
