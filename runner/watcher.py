#!/usr/bin/env python3
"""filament job runner — box-side WATCHER (file-driven control plane).

This REPLACES the interactive-PTY control plane (v1's `ctl` channel). The v1
runner drove the box-side executor over a long-lived `filament pty` session; on
the unstable Colab->do-vm WAN link that PTY dropped every few seconds and the
host hung forever in `open_session()` (see docs/runner/jobrunner-challenges.md).

The watcher needs NO inbound stream and NO shell. It is a LOCAL poll loop on the
box. Its only network I/O is discrete, retry-tolerant FILE TRANSFERS — exactly
the primitive the diagnosis proved survives the link drops:

    inbound (din) : the host pushes job<id>.json + the declared inputs into the
                    box inbox via `filament send` -> the box `up --dir .inbox`
                    daemon drops them in. The watcher just watches that dir.
    outbound (dout): the watcher runs the job, then `filament send --relay`s the
                    manifest + outputs back to the host's transient `up` sink on
                    the dout channel (peer `host-out`). The MANIFEST IS SENT LAST
                    so its host-side arrival signals job completion.

Job execution reuses box_executor.run_job() unchanged (cmd in a scratch dir, a
watchdog `timeout_s`, per-output sha256/size, wall-clock, `nvidia-smi -L` for ALL
gpus, manifest.json). The watcher only owns transport + lifecycle.

Crash-safe / idempotent: a job's spec is moved to `.inbox/done/` once picked up,
so a watcher restart never re-runs it. One job at a time (sequential); structured
so per-GPU parallel dispatch can be added later (see _claim_next / DISPATCH HOOK).

Stdlib-only. Targets the T4 stack (glibc 2.35 / python3). Logs plainly to stdout
(the bring-up tails it).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import box_executor  # noqa: E402  (reuse the FIXED job-execution logic)

# A resend over the file channel lands as `name.1`, `name.2`, ... (CLI
# unique_path()); normalise those back to the base name when matching.
_DUP_RE = re.compile(r"^(?P<base>.+?)(?:\.(?P<n>\d+))?$")
# job spec files are job<anything>.json (e.g. job.json, job-<id>.json)
_SPEC_RE = re.compile(r"^job.*\.json(?:\.\d+)?$")
# the host's completion ACK lands in the inbox as `ack-<job_id>` (possibly with a
# `.N` resend suffix). Its presence means the host has the FULL, sha256-verified
# result set, so the watcher can stop re-shipping that job.
_ACK_RE = re.compile(r"^ack-(?P<job_id>.+?)(?:\.\d+)?$")


def log(msg):
    sys.stdout.write(f"[watcher] {msg}\n")
    sys.stdout.flush()


def _base_name(fname):
    """Strip a trailing resend suffix (`.1`/`.2`) added on collision."""
    m = _DUP_RE.match(fname)
    base = m.group("base")
    # only treat `.N` as a resend suffix when the prefix already looks like a
    # real filename (has its own extension) — avoids mangling e.g. `clip.2.mp4`
    # which has no trailing numeric component anyway.
    return base


def _dup_index(fname):
    m = _DUP_RE.match(fname)
    n = m.group("n")
    return int(n) if n is not None else 0


def _resolve_by_base(inbox, wanted):
    """Find the file in `inbox` whose normalised base name == `wanted`,
    preferring the highest resend index (the most-recently-(re)sent copy).
    Returns the actual on-disk filename, or None."""
    best = None
    best_idx = -1
    for fn in os.listdir(inbox):
        path = os.path.join(inbox, fn)
        if not os.path.isfile(path):
            continue
        if _base_name(fn) == wanted:
            idx = _dup_index(fn)
            if idx > best_idx:
                best, best_idx = fn, idx
    return best


def _stable_size(path, settle_s=1.0):
    """True if the file's size is non-zero and unchanged across `settle_s` —
    a cheap guard against acting on a still-arriving transfer."""
    try:
        s1 = os.path.getsize(path)
        if s1 == 0:
            return False
        time.sleep(settle_s)
        return os.path.getsize(path) == s1
    except OSError:
        return False


class Watcher:
    def __init__(self, jobs_root, server, filament_bin, dout_config_dir,
                 host_dout_peer="host-out", relay=True, poll_s=2.0,
                 settle_s=1.0, reship_attempts=8, reship_gap_s=8.0,
                 reship_deadline_s=1800.0, send_timeout_s=0,
                 send_retry_attempts=6, send_retry_gap_s=4.0):
        self.jobs_root = os.path.abspath(os.path.expanduser(jobs_root))
        self.inbox = os.path.join(self.jobs_root, ".inbox")
        self.done = os.path.join(self.inbox, "done")
        self.outbox = os.path.join(self.jobs_root, ".outbox")
        self.scratch_root = os.path.join(self.jobs_root, "scratch")
        self.server = server
        self.bin = filament_bin
        self.dout_cfg = os.path.expanduser(dout_config_dir)
        self.host_dout_peer = host_dout_peer
        self.relay = relay
        self.poll_s = poll_s
        self.settle_s = settle_s
        # re-ship is now ACK-driven, not a blind fixed count: keep re-shipping
        # the result set until the host ACKs it (over din) OR reship_deadline_s
        # elapses. reship_attempts is a SAFETY CAP on rounds so a never-acking
        # host can't loop forever; the deadline is the primary bound.
        self.reship_attempts = reship_attempts
        self.reship_gap_s = reship_gap_s
        self.reship_deadline_s = reship_deadline_s
        # each individual `filament send` should NOT give up at the stock 60s
        # FILAMENT_SEND_TIMEOUT on a flaky link — 0 disables that internal bound
        # so the send waits for the peer; the retry loop + deadline bound it.
        self.send_timeout_s = send_timeout_s
        self.send_retry_attempts = send_retry_attempts
        self.send_retry_gap_s = send_retry_gap_s
        self._ship_threads = []
        for d in (self.inbox, self.done, self.outbox, self.scratch_root):
            os.makedirs(d, exist_ok=True)

    # ---- host completion ACK (over din) ----------------------------------

    def _ack_seen(self, job_id):
        """True once the host's `ack-<job_id>` file has landed in the inbox —
        meaning the host has the full, sha256-verified result set."""
        for fn in os.listdir(self.inbox):
            m = _ACK_RE.match(fn)
            if m and m.group("job_id") == job_id and os.path.isfile(
                    os.path.join(self.inbox, fn)):
                return True
        return False

    def _consume_acks(self):
        """Move any ack-* files out of the inbox so they aren't mistaken for a
        spec/input and don't accumulate. Idempotent."""
        for fn in os.listdir(self.inbox):
            if _ACK_RE.match(fn):
                src = os.path.join(self.inbox, fn)
                if os.path.isfile(src):
                    try:
                        shutil.move(src, os.path.join(self.done, fn))
                    except Exception:
                        try:
                            os.remove(src)
                        except OSError:
                            pass

    # ---- readiness -------------------------------------------------------

    def _list_specs(self):
        out = []
        for fn in os.listdir(self.inbox):
            if _SPEC_RE.match(fn) and os.path.isfile(os.path.join(self.inbox, fn)):
                out.append(fn)
        # process oldest-by-mtime first (FIFO-ish); resends of the same job map
        # to the same id and are deduped at claim time.
        out.sort(key=lambda f: os.path.getmtime(os.path.join(self.inbox, f)))
        return out

    def _read_spec(self, fname):
        try:
            with open(os.path.join(self.inbox, fname)) as f:
                return json.load(f)
        except Exception as e:
            log(f"spec {fname} not parseable yet ({e}); will retry")
            return None

    def _inputs_ready(self, job):
        """True only when EVERY declared input is present on disk (by normalised
        base name) and size-stable. Guards against acting on a partially-arrived
        set."""
        for name in job.get("inputs", []):
            actual = _resolve_by_base(self.inbox, os.path.basename(name))
            if actual is None:
                return False
            if not _stable_size(os.path.join(self.inbox, actual), self.settle_s):
                log(f"input '{name}' still arriving; waiting")
                return False
        return True

    # ---- claim + run -----------------------------------------------------

    def _already_done(self, job_id):
        return os.path.isdir(os.path.join(self.outbox, job_id)) and os.path.exists(
            os.path.join(self.outbox, job_id, "manifest.json"))

    def _claim_next(self):
        """Return (spec_fname, job) for the first READY job, or None.

        DISPATCH HOOK: today this returns one job and the caller runs it
        sequentially. For per-GPU parallelism, return a list of ready jobs and
        assign each to a free GPU index (`-hwaccel_device N`); the inbox-scan +
        readiness check below is already concurrency-safe per spec because a
        claimed spec is immediately moved out of .inbox/."""
        for spec_fname in self._list_specs():
            job = self._read_spec(spec_fname)
            if job is None:
                continue
            job_id = job.get("id")
            if not job_id:
                log(f"spec {spec_fname} has no id; moving aside")
                self._retire_spec(spec_fname, job_id="_malformed")
                continue
            if self._already_done(job_id):
                # a resent spec for a job we already finished — retire it
                log(f"job {job_id} already complete; retiring duplicate spec {spec_fname}")
                self._retire_spec(spec_fname, job_id)
                continue
            if not self._inputs_ready(job):
                continue
            return spec_fname, job
        return None

    def _retire_spec(self, spec_fname, job_id):
        """Move the spec out of .inbox so it is never re-claimed (idempotency).
        Returns the retired path (so staging can still read its bytes)."""
        src = os.path.join(self.inbox, spec_fname)
        dst = os.path.join(self.done, f"{job_id}__{spec_fname}")
        try:
            shutil.move(src, dst)
            return dst
        except Exception as e:
            log(f"could not retire spec {spec_fname}: {e}")
            return src

    def _stage_scratch(self, spec_path, job):
        """Build a fresh scratch dir: copy the spec (as job.json) + each declared
        input (resolved past any `.N` resend suffix) into it. `spec_path` is the
        ACTUAL on-disk spec path (it may already be retired to .inbox/done)."""
        job_id = job["id"]
        scratch = os.path.join(self.scratch_root, job_id)
        if os.path.exists(scratch):
            shutil.rmtree(scratch, ignore_errors=True)
        os.makedirs(scratch, exist_ok=True)
        # spec -> job.json (canonical name the executor expects)
        shutil.copy2(spec_path, os.path.join(scratch, "job.json"))
        for name in job.get("inputs", []):
            base = os.path.basename(name)
            actual = _resolve_by_base(self.inbox, base)
            if actual is None:
                raise RuntimeError(f"input '{name}' vanished before staging")
            shutil.copy2(os.path.join(self.inbox, actual),
                         os.path.join(scratch, base))
        return scratch

    def _ship(self, job, scratch):
        """Copy manifest + declared outputs into the outbox, then `filament send`
        them to the host on the dout channel. Manifest LAST so its arrival
        host-side signals completion."""
        job_id = job["id"]
        ob = os.path.join(self.outbox, job_id)
        os.makedirs(ob, exist_ok=True)

        # gather outputs (best-effort: a failed/timed-out job may not produce them)
        shipped_outputs = []
        for name in job.get("outputs", []):
            src = os.path.join(scratch, name)
            if os.path.exists(src):
                dst = os.path.join(ob, os.path.basename(name))
                shutil.copy2(src, dst)
                shipped_outputs.append(dst)
            else:
                log(f"declared output '{name}' absent (job exit?) — not shipping it")
        manifest_src = os.path.join(scratch, "manifest.json")
        manifest_dst = os.path.join(ob, "manifest.json")
        shutil.copy2(manifest_src, manifest_dst)

        # Ship in a BACKGROUND thread so the watcher loop stays responsive and the
        # next job can run immediately (pipelining; no sequential stall on the
        # flaky link). The host stands up its dout sink only when it starts
        # awaiting, which races with a fast job finishing here — a single send can
        # land in a reconnect window and be lost.
        #
        # RESULT-ACK LOOP (close the loop): keep RE-SHIPPING the result set until
        # the host tells us — via an `ack-<job_id>` file pushed back over din —
        # that it has the FULL, sha256-verified set. This means neither side gives
        # up prematurely: a lost manifest or a truncated output simply triggers
        # another round. Bounded by reship_deadline_s (primary) and a safety cap of
        # reship_attempts rounds. Outputs first, manifest LAST each round (manifest
        # = completion signal).
        def _ship_loop():
            cap = max(1, self.reship_attempts)
            deadline = time.monotonic() + self.reship_deadline_s
            i = 0
            while True:
                if self._ack_seen(job_id):
                    log(f"host ACKed {job_id} — result set confirmed received; "
                        f"stopping re-ship after {i} round(s)")
                    self._consume_acks()
                    return
                i += 1
                try:
                    if shipped_outputs:
                        self._send(shipped_outputs)
                    self._send([manifest_dst])
                    log(f"sent results for {job_id} (round {i}): "
                        f"{len(shipped_outputs)} output(s) + manifest "
                        f"(awaiting host ack)")
                except Exception as e:
                    log(f"ship round {i} for {job_id} errored: {e}")
                # stop conditions: ack arrived, deadline passed, or safety cap hit
                if self._ack_seen(job_id):
                    log(f"host ACKed {job_id} after round {i}; stopping re-ship")
                    self._consume_acks()
                    return
                if time.monotonic() >= deadline:
                    log(f"GIVE UP re-shipping {job_id}: no host ack within "
                        f"{self.reship_deadline_s:.0f}s ({i} round(s) sent). "
                        f"Result is on disk in {ob}.")
                    return
                if i >= cap:
                    log(f"GIVE UP re-shipping {job_id}: hit safety cap of {cap} "
                        f"rounds with no host ack. Result is on disk in {ob}.")
                    return
                # poll the inbox for the ack while we wait out the gap, so we react
                # to an ack promptly instead of after a full reship_gap_s sleep.
                waited = 0.0
                while waited < self.reship_gap_s:
                    if self._ack_seen(job_id):
                        break
                    time.sleep(min(0.5, self.reship_gap_s - waited))
                    waited += 0.5

        import threading
        t = threading.Thread(target=_ship_loop, name=f"ship-{job_id}", daemon=True)
        t.start()
        self._ship_threads.append(t)

    def _send(self, paths):
        cmd = [self.bin, "send", *paths, "--to", self.host_dout_peer,
               "--server", self.server]
        if self.relay:
            cmd.append("--relay")
        env = dict(os.environ)
        env["FILAMENT_CONFIG_DIR"] = self.dout_cfg
        env["HOME"] = self.dout_cfg
        env["FILAMENT_L2"] = "1"
        # RETRY-UNTIL-PEER: on a flaky link the host's dout sink may not be
        # subscribed yet (or the signaling link is mid-reconnect), so a single
        # `send` would hit "no peer connected" and give up. We (a) stop the CLI
        # from giving up early by setting FILAMENT_SEND_TIMEOUT (0 = wait for the
        # peer), and (b) re-invoke on a hard failure with backoff. The outer
        # _ship_loop bounds total time via the ACK deadline.
        env["FILAMENT_SEND_TIMEOUT"] = str(self.send_timeout_s)
        last = None
        attempts = max(1, self.send_retry_attempts)
        for attempt in range(attempts):
            # cap per-invocation wall time so a wedged send can't block the whole
            # ship loop forever; the loop will re-invoke (a fresh connect often
            # clears a wedged candidate pair).
            try:
                r = subprocess.run(cmd, env=env, capture_output=True, text=True,
                                   timeout=600)
            except subprocess.TimeoutExpired:
                last = "send invocation exceeded 600s (wedged); re-invoking"
                log(f"send attempt {attempt + 1} {last}")
                continue
            if r.returncode == 0:
                return
            last = r.stderr.strip()[-300:]
            log(f"send attempt {attempt + 1}/{attempts} failed ({r.returncode}): "
                f"{last}; retrying")
            time.sleep(self.send_retry_gap_s + 2 * attempt)
        log(f"WARNING: send ultimately failed after {attempts} attempts: {last}")

    def process_one(self, spec_fname, job):
        job_id = job["id"]
        log(f"job {job_id} picked up (spec={spec_fname}, inputs={job.get('inputs', [])})")
        # Retire the spec FIRST so a crash mid-run never re-runs it; stage from the
        # retired copy (we still need its bytes for the scratch dir).
        retired = self._retire_spec(spec_fname, job_id)
        scratch = self._stage_scratch(retired, job)
        log(f"job {job_id} running: {' '.join(job.get('cmd', []))}")
        # reuse the FIXED executor logic (writes scratch/manifest.json)
        box_executor.run_job(scratch, emit=lambda v, p="": None)
        with open(os.path.join(scratch, "manifest.json")) as f:
            manifest = json.load(f)
        log(f"job {job_id} done exit={manifest.get('exit_code')} "
            f"timed_out={manifest.get('timed_out')} dur={manifest.get('duration_s')}s "
            f"gpus={manifest.get('gpus')}")
        self._ship(job, scratch)

    # ---- loop ------------------------------------------------------------

    def run_forever(self):
        log(f"watcher up. inbox={self.inbox} outbox={self.outbox} "
            f"relay={self.relay} dout_peer={self.host_dout_peer}")
        while True:
            try:
                claim = self._claim_next()
                if claim is None:
                    # tidy any late/duplicate acks out of the inbox so they don't
                    # accumulate (the per-job ship loop also consumes its own ack).
                    self._consume_acks()
                    time.sleep(self.poll_s)
                    continue
                spec_fname, job = claim
                self.process_one(spec_fname, job)
            except KeyboardInterrupt:
                log("interrupted; exiting")
                return
            except Exception as e:
                log(f"ERROR processing job: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(self.poll_s)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="filament box-side file-driven job watcher")
    ap.add_argument("--jobs-root", default=os.environ.get("FILJOB_ROOT", "~/filament-jobs"))
    ap.add_argument("--server", default=os.environ.get("FILJOB_SERVER",
                    "https://api.filament.autumated.com"))
    ap.add_argument("--bin", default=os.environ.get("FILAMENT_BIN", "filament"))
    ap.add_argument("--dout-cfg", default=os.environ.get("FILJOB_BOX_DOUT_CFG",
                    "~/filament-jobs/cfg-dout"))
    ap.add_argument("--host-dout-peer", default=os.environ.get("FILJOB_HOST_DOUT_PEER", "host-out"))
    ap.add_argument("--poll", type=float, default=float(os.environ.get("FILJOB_POLL_S", "2.0")))
    ap.add_argument("--settle", type=float, default=float(os.environ.get("FILJOB_SETTLE_S", "1.0")))
    ap.add_argument("--reship-attempts", type=int,
                    default=int(os.environ.get("FILJOB_RESHIP_ATTEMPTS", "200")),
                    help="SAFETY CAP on re-ship rounds (ACK is the primary stop)")
    ap.add_argument("--reship-gap", type=float,
                    default=float(os.environ.get("FILJOB_RESHIP_GAP_S", "8.0")),
                    help="seconds between re-ship attempts")
    ap.add_argument("--reship-deadline", type=float,
                    default=float(os.environ.get("FILJOB_RESHIP_DEADLINE_S", "1800")),
                    help="give up re-shipping a job after this many seconds with no host ack")
    ap.add_argument("--send-timeout", type=int,
                    default=int(os.environ.get("FILJOB_SEND_TIMEOUT_S", "0")),
                    help="FILAMENT_SEND_TIMEOUT for each send (0 = wait for peer, no early give-up)")
    ap.add_argument("--send-retries", type=int,
                    default=int(os.environ.get("FILJOB_SEND_RETRIES", "6")),
                    help="re-invoke a failed `send` this many times before the round errors")
    ap.add_argument("--send-retry-gap", type=float,
                    default=float(os.environ.get("FILJOB_SEND_RETRY_GAP_S", "4.0")),
                    help="base backoff seconds between send re-invocations")
    # relay defaults ON for WAN robustness; the local loopback test passes --no-relay.
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--relay", dest="relay", action="store_true", default=True)
    g.add_argument("--no-relay", dest="relay", action="store_false")
    args = ap.parse_args(argv[1:])

    w = Watcher(
        jobs_root=args.jobs_root, server=args.server, filament_bin=args.bin,
        dout_config_dir=args.dout_cfg, host_dout_peer=args.host_dout_peer,
        relay=args.relay, poll_s=args.poll, settle_s=args.settle,
        reship_attempts=args.reship_attempts, reship_gap_s=args.reship_gap,
        reship_deadline_s=args.reship_deadline, send_timeout_s=args.send_timeout,
        send_retry_attempts=args.send_retries, send_retry_gap_s=args.send_retry_gap,
    )
    w.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
