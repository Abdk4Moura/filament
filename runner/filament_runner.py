#!/usr/bin/env python3
"""filament-native job runner — host side.

A thin compute-job orchestration layer on top of filament's existing P2P
transport (PTY + file channel). It lets us offload a declared compute job (e.g.
an NVENC transcode) to a remote filament-reachable box and get artifacts back —
WITHOUT the ad-hoc remote-shell pattern. The host pushes a job *spec* plus a
FIXED box-side executor, then invokes that single executor; it never pipes
arbitrary commands across a shell.

This is "submit / await / fetch a named job", not "shell into a host".
See docs/research/remote-accelerator-offload.md §3-§4.

------------------------------------------------------------------------------
Transport model
------------------------------------------------------------------------------
DEFAULT (file-driven, robust over an unstable WAN link) — use `FileRunnerBox`:

  din  : host `send --relay`               ; box `up --dir <inbox>`  (push job+inputs)
  dout : host `up --dir <results> --relay` ; box `send --relay`      (pull results)

Everything is discrete FILE TRANSFERS — no long-lived interactive stream to drop.
A box-side `watcher.py` picks the job up off the inbox, runs it, and sends the
manifest + outputs back (manifest LAST = completion signal). `--relay` is forced
on for stability. This replaces the v1 PTY control plane that hung on the flaky
Colab->do-vm link (docs/runner/jobrunner-challenges.md).

LEGACY (PTY control, DEPRECATED for WAN) — `RunnerBox`, kept for reference/local
parity. A filament "device" is a pair secret; a petname is a local alias. It used
THREE channels, each with exactly one acceptor:

  ctl  : box `up --shell`        ; host `filament pty`   (control — DROPS on a flaky link)
  din  : box `up --dir <inbox>`  ; host `filament send`  (push inputs)
  dout : host `up --dir <outbox>`; box  `filament send`  (pull outputs)

The file-driven path REUSES the same din/dout secrets — `ctl` is simply unused,
so no re-pairing is needed when moving off the PTY.

------------------------------------------------------------------------------
API
------------------------------------------------------------------------------
    rb = RunnerBox(petname_ctl="box", petname_din="box-in", petname_dout="box-out",
                   server=..., host_config_dir=..., filament_bin=...)
    job = Job(id="j-1", inputs=["input.mov"], cmd=[...], outputs=["out.mp4"],
              timeout_s=1800, rclone_dest=None)

    rb.submit(job, local_input_dir="/path/with/inputs")   # scratch + push inputs + push executor
    for ev in rb.stream(job):                               # run executor, parse progress
        ...
    rb.fetch(job, local_output_dir="/path/for/outputs")    # pull declared outputs + manifest.json
    manifest = rb.manifest(job)                             # the recorded manifest dict

Stdlib-only on the host side too (uses subprocess to drive the `filament` CLI).
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterator, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
EXECUTOR_SRC = os.path.join(HERE, "box_executor.py")
PROTO = "FILJOB v1"

# Match a sentinel-framed executor line *after* CR/escape stripping. The login
# shell echoes the command we typed and prints prompts; only genuine executor
# output begins with the protocol token at a clean line start.
_LINE_RE = re.compile(r"FILJOB v1 (\S+) (\w+)(?: (.*))?$")
# strip ANSI/control noise the PTY interleaves (prompts, bracketed-paste markers)
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


@dataclass
class Job:
    id: str
    inputs: list           # filenames (relative); must exist in local_input_dir at submit
    cmd: list              # argv run in the scratch dir on the box
    outputs: list          # declared artifact filenames to hash + pull back
    timeout_s: int = 1800
    rclone_dest: Optional[str] = None  # OPTIONAL durability target (no-op if unset)

    @staticmethod
    def new(cmd, inputs=None, outputs=None, timeout_s=1800, rclone_dest=None, id=None):
        return Job(
            id=id or f"j-{uuid.uuid4().hex[:8]}",
            inputs=list(inputs or []),
            cmd=list(cmd),
            outputs=list(outputs or []),
            timeout_s=int(timeout_s),
            rclone_dest=rclone_dest,
        )

    def spec_dict(self):
        return {
            "id": self.id,
            "inputs": self.inputs,
            "cmd": self.cmd,
            "outputs": self.outputs,
            "timeout_s": self.timeout_s,
            "rclone_dest": self.rclone_dest,
        }


@dataclass
class ProgressEvent:
    """One parsed structured line off the executor's stdout."""
    job_id: str
    kind: str               # begin | progress | manifest | done
    data: dict = field(default_factory=dict)
    raw: str = ""


class RunnerError(RuntimeError):
    pass


class RunnerBox:
    """Drives a single remote box that is already running the box-side acceptors
    (`up --shell` on ctl, `up --dir` on din). The host provides the dout acceptor
    transiently during fetch."""

    def __init__(
        self,
        petname_ctl: str,
        petname_din: str,
        petname_dout: str,
        server: str,
        host_config_dir: str,
        filament_bin: str = "filament",
        # petnames as the BOX knows them (for the box-side `send --to <host>`):
        box_petname_for_host_dout: str = "host-out",
        remote_jobs_root: str = "~/filament-jobs",
        remote_inbox: str = "~/filament-jobs/.inbox",
        # box-side config dir holding ONLY the dout secret — used by the PTY
        # `filament send` so it doesn't share a channel with the ctl daemon.
        box_dout_config_dir: str = "~/.filament-dout",
        remote_python: str = "python3",
        connect_grace_s: float = 4.0,
    ):
        self.ctl = petname_ctl
        self.din = petname_din
        self.dout = petname_dout
        self.server = server
        self.cfg = host_config_dir
        self.bin = filament_bin
        self.box_host_dout = box_petname_for_host_dout
        self.remote_root = remote_jobs_root
        self.remote_inbox = remote_inbox
        self.box_dout_config_dir = box_dout_config_dir
        self.remote_python = remote_python
        self.grace = connect_grace_s
        self._manifests = {}
        # persistent control-PTY session (opened once per job to avoid the
        # rapid open/close reconnect churn that wedges the ctl channel on a
        # single host). Set by open_session(); torn down by close_session().
        self._sess_p = None
        self._sess_t = None
        self._sess_get = None

    # ---- low-level filament invocations ----------------------------------

    def _env(self, extra=None, config_dir=None):
        env = dict(os.environ)
        env["FILAMENT_CONFIG_DIR"] = config_dir or self.cfg
        env["HOME"] = config_dir or self.cfg
        env["FILAMENT_L2"] = "1"
        # wide terminal so ffmpeg/`ls` output isn't wrapped in the PTY
        env["COLUMNS"] = "220"
        env["LINES"] = "50"
        if extra:
            env.update(extra)
        return env

    def _send(self, paths, to, timeout=300):
        """filament send <paths> --to <to> (host is initiator)."""
        cmd = [self.bin, "send", *paths, "--to", to, "--server", self.server]
        r = subprocess.run(cmd, env=self._env(), capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            raise RunnerError(f"send to {to} failed ({r.returncode}): {r.stderr.strip()[-400:]}")
        return r

    def remote_scratch(self, job: Job) -> str:
        # expanded on the box by the login shell ($HOME etc.)
        return f"{self.remote_root}/{job.id}"

    # ---- PTY control session --------------------------------------------

    def _open_pty(self):
        """Open a long-lived control PTY to the box (ctl channel). Returns the Popen.
        Caller feeds shell commands on stdin and reads framed output on stdout."""
        cmd = [self.bin, "pty", self.ctl, "--server", self.server]
        p = subprocess.Popen(
            cmd, env=self._env(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0,
        )
        return p

    @staticmethod
    def _safe_write(p, data: bytes) -> bool:
        try:
            p.stdin.write(data)
            p.stdin.flush()
            return True
        except (BrokenPipeError, ValueError, OSError):
            return False

    def _wait_ready(self, p, line_q, ready_timeout=40.0):
        """Block until the remote login shell is interactive, by probing it: send
        `echo <nonce>` and wait for the nonce to echo back on stdout. This replaces
        a fixed grace sleep — robust to slow/variable connection establishment.
        `line_q` is a callable returning the next cleaned line or None.
        Returns True if ready."""
        nonce = f"FILJOB_READY_{uuid.uuid4().hex[:8]}"
        deadline = time.monotonic() + ready_timeout
        sent = False
        last_send = 0.0
        while time.monotonic() < deadline:
            if p.poll() is not None:
                return False
            # (re)send the probe periodically until we see it echo
            now = time.monotonic()
            if not sent or (now - last_send) > 3.0:
                if not self._safe_write(p, (f"echo {nonce}\n").encode()):
                    return False
                sent = True
                last_send = now
            line = line_q(timeout=0.5)
            if line is not None and nonce in line and "echo" not in line:
                return True
        return False

    @staticmethod
    def _clean(line: str) -> str:
        return _ANSI_RE.sub("", line.replace("\r", "")).rstrip()

    # ---- public contract: submit / stream / fetch / manifest -------------

    def submit(self, job: Job, local_input_dir: str):
        """Create the scratch dir on the box, push input files + the fixed executor
        + the job spec over the file channel.

        Files land in the box `up --dir <inbox>` drop, then a single PTY command
        moves them into the per-job scratch dir. (No arbitrary command execution —
        just `mkdir`/`mv` of named files into the named job dir.)"""
        # 1. stage spec + executor locally alongside inputs to push them together
        stage = os.path.join(local_input_dir, f".__job_{job.id}")
        os.makedirs(stage, exist_ok=True)
        with open(os.path.join(stage, "job.json"), "w") as f:
            json.dump(job.spec_dict(), f, indent=2)
        # copy the fixed executor in
        with open(EXECUTOR_SRC) as src, open(os.path.join(stage, "box_executor.py"), "w") as dst:
            dst.write(src.read())

        # 2. push every input + the two control files to the box inbox (din channel)
        to_push = [os.path.join(stage, "job.json"), os.path.join(stage, "box_executor.py")]
        for name in job.inputs:
            ip = os.path.join(local_input_dir, name)
            if not os.path.exists(ip):
                raise RunnerError(f"declared input missing locally: {ip}")
            to_push.append(ip)
        self._send(to_push, self.din)

        # 3. assemble the scratch dir on the box from the inbox drop (one PTY command).
        # The box's din `up` daemon drops received files into self.remote_inbox
        # (the bring-up script points it there). Move the named files into the
        # per-job scratch dir. This is mkdir/mv of *named* files only.
        # Trusted, configured paths (remote_root/remote_inbox) may contain a
        # leading ~ that must stay shell-expandable, so they are NOT shlex-quoted;
        # only the (untrusted-shaped) filenames are quoted.
        scratch = self.remote_scratch(job)
        inbox = self.remote_inbox
        names = ["job.json", "box_executor.py"] + list(job.inputs)
        mv_cmd = (
            f"mkdir -p {scratch} && "
            + " && ".join(
                f"mv -f {inbox}/{shlex.quote(n)} {scratch}/{shlex.quote(n)}"
                for n in names
            )
            + " && echo FILJOB_SUBMIT_OK"
        )
        out = self._run_oneshot(mv_cmd, marker="FILJOB_SUBMIT_OK", timeout=60)
        if "FILJOB_SUBMIT_OK" not in out:
            raise RunnerError(f"submit assembly failed; box said:\n{out[-800:]}")

    def _spawn_line_reader(self, p):
        """Start a daemon thread that pushes cleaned non-empty stdout lines onto a
        Queue. Returns (queue, thread, get_fn) where get_fn(timeout) -> line|None.
        A sentinel `None` is enqueued when the stream ends."""
        import queue as _queue
        q = _queue.Queue()

        def reader():
            try:
                for raw in iter(p.stdout.readline, b""):
                    line = self._clean(raw.decode("utf-8", "replace"))
                    if line:
                        q.put(line)
            finally:
                q.put(None)  # EOF sentinel
        t = threading.Thread(target=reader, daemon=True)
        t.start()

        def get(timeout=0.5):
            try:
                return q.get(timeout=timeout)
            except _queue.Empty:
                return None
        return q, t, get

    def _close_pty(self, p, t):
        if self._safe_write(p, b"exit\n"):
            pass
        try:
            p.wait(timeout=10)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
        if t:
            t.join(timeout=2)

    # ---- persistent control session -------------------------------------

    def open_session(self, attempts: int = 4):
        """Open ONE control PTY to the box and wait for the shell to be ready.
        Reused by submit/stream/fetch so the ctl channel is connected exactly once
        per job (rapid open/close on a single host wedges the candidate race).

        Retries a few times: on a single host the WebRTC candidate pair can wedge
        ("connection stuck while connecting"), especially right after a previous
        session tore down; a fresh attempt after a short backoff clears it."""
        if self._sess_p is not None and self._sess_p.poll() is None:
            return
        last_err = None
        for i in range(attempts):
            p = self._open_pty()
            _, t, get = self._spawn_line_reader(p)
            if self._wait_ready(p, get):
                self._sess_p, self._sess_t, self._sess_get = p, t, get
                return
            self._close_pty(p, t)
            last_err = "shell not ready"
            time.sleep(3 + 2 * i)  # backoff lets a wedged candidate pair reset
        raise RunnerError(f"PTY shell did not become ready (ctl channel) after {attempts} attempts: {last_err}")

    def close_session(self):
        if self._sess_p is not None:
            self._close_pty(self._sess_p, self._sess_t)
        self._sess_p = self._sess_t = self._sess_get = None

    def _ensure_session(self):
        if self._sess_p is None or self._sess_p.poll() is not None:
            self.open_session()

    def _run_oneshot(self, shell_cmd: str, marker: str, timeout: float) -> str:
        """Run ONE compound command on the persistent control PTY, wait for a marker,
        and return the cleaned output seen since the command was sent. Used for the
        mkdir/mv assembly and the box-side fetch `send`."""
        self._ensure_session()
        p, get = self._sess_p, self._sess_get
        collected = []
        if not self._safe_write(p, (shell_cmd + "\n").encode()):
            raise RunnerError("PTY stdin closed before command could be sent")
        deadline = time.monotonic() + timeout
        seen = False
        while time.monotonic() < deadline:
            line = get(timeout=0.5)
            if line is None:
                if p.poll() is not None:
                    break
                continue
            collected.append(line)
            if marker in line:
                seen = True
                break
        if not seen:
            collected.append(f"[marker '{marker}' not seen within {timeout}s]")
        return "\n".join(collected)

    def stream(self, job: Job) -> Iterator[ProgressEvent]:
        """Invoke the FIXED executor ONCE on the box and yield parsed progress events.

        This is the single point where the box runs the job's `cmd`. The host
        does NOT pipe `cmd` over the shell — it invokes `python3 box_executor.py
        <scratch>`, and the executor reads cmd from job.json and runs it itself."""
        scratch = self.remote_scratch(job)
        invoke = (
            f"cd {scratch} && "
            f"{self.remote_python} box_executor.py {scratch}"
        )
        self._ensure_session()
        p, get = self._sess_p, self._sess_get
        if not self._safe_write(p, (invoke + "\n").encode()):
            raise RunnerError("PTY stdin closed before executor could be invoked")

        deadline = time.monotonic() + job.timeout_s + 120  # host-side safety margin
        done = False
        while time.monotonic() < deadline and not done:
            line = get(timeout=1.0)
            if line is None:
                if p.poll() is not None:
                    break
                continue
            m = _LINE_RE.search(line)
            if not m:
                continue
            jid, kind, payload = m.group(1), m.group(2), m.group(3)
            if jid != job.id:
                continue
            data = {}
            if payload:
                if kind in ("progress", "manifest"):
                    try:
                        data = json.loads(payload)
                    except Exception:
                        data = {"_raw": payload}
                else:
                    data = {"_raw": payload}
            if kind == "manifest":
                self._manifests[job.id] = data
            yield ProgressEvent(job_id=jid, kind=kind, data=data, raw=line)
            if kind == "done":
                done = True
        # session stays open for fetch — closed by close_session()

    def fetch(self, job: Job, local_output_dir: str, dout_config_dir: Optional[str] = None):
        """Pull declared outputs + manifest.json back over the dout file channel.

        The host stands up a transient `up` acceptor on the dout channel; the box
        (over the ctl PTY) runs `filament send <outputs> manifest.json --to <host>`."""
        os.makedirs(local_output_dir, exist_ok=True)
        dcfg = dout_config_dir or (self.cfg + "-dout")
        scratch = self.remote_scratch(job)
        files = list(job.outputs) + ["manifest.json"]
        quoted = " ".join(shlex.quote(f) for f in files)
        # Run the box-side `send` under the dout-only config dir + L2 enabled, so it
        # never co-subscribes the ctl/din channels (no acceptor glare).
        send_cmd = (
            f"cd {scratch} && "
            f"FILAMENT_CONFIG_DIR={self.box_dout_config_dir} FILAMENT_L2=1 "
            f"filament send {quoted} --to {shlex.quote(self.box_host_dout)} "
            f"--server {shlex.quote(self.server)} && echo FILJOB_FETCH_OK"
        )

        def _manifest_matches():
            mp = os.path.join(local_output_dir, "manifest.json")
            if not os.path.exists(mp):
                return False
            try:
                with open(mp) as f:
                    return json.load(f).get("job_id") == job.id
            except Exception:
                return False

        def _outputs_present():
            # the declared OUTPUTS are what must come back byte-correct; manifest.json
            # is best-effort over dout (we also have a wire copy from stream).
            return all(os.path.exists(os.path.join(local_output_dir, o)) for o in job.outputs)

        def _all_present():
            # declared outputs back AND a manifest for THIS job (pulled or, failing
            # that, the wire copy written locally below). Guards against a stray /
            # retried transfer of another job leaking onto the shared dout channel.
            return _outputs_present() and (_manifest_matches() or job.id in self._manifests)

        # Start clean so a pre-existing/stale manifest can't masquerade as success.
        for f in files:
            try:
                os.remove(os.path.join(local_output_dir, f))
            except FileNotFoundError:
                pass

        # The dout config dir must already contain the dout device secret (planted by
        # the bring-up script). Stand the sink `up` acceptor up, wait for it to be
        # subscribed, trigger the box-side send, and verify the files landed —
        # retrying if the acceptor/initiator raced or a cross-job transfer leaked in.
        last_out = ""
        for attempt in range(3):
            up = subprocess.Popen(
                [self.bin, "up", "--server", self.server, "--name-as", "filjob-host-sink",
                 "--dir", local_output_dir],
                env=self._env(config_dir=dcfg),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            # wait for the sink to announce it's up (subscribed) before sending
            ready_deadline = time.monotonic() + 20
            try:
                while time.monotonic() < ready_deadline:
                    line = up.stdout.readline()
                    if not line:
                        if up.poll() is not None:
                            break
                        continue
                    if b"filament up" in line or b"known device" in line:
                        break
                time.sleep(1.0)  # small settle margin after subscribe
                # the transfer time is independent of the job's compute timeout
                # (a 4s job can still produce a large artifact); floor it generously.
                send_timeout = max(job.timeout_s, 180)
                last_out = self._run_oneshot(send_cmd, marker="FILJOB_FETCH_OK", timeout=send_timeout)
            finally:
                up.terminate()
                try:
                    up.wait(timeout=8)
                except Exception:
                    up.kill()
            if _all_present():
                break
            time.sleep(2)
        if not _all_present():
            raise RunnerError(
                f"fetch did not return all outputs ({files}); last box output:\n{last_out[-800:]}"
            )

        # Authoritative manifest: prefer the pulled manifest.json (verified to be
        # ours); otherwise fall back to the wire copy received during stream and
        # write it locally so the output dir always has a manifest.json for the job.
        mpath = os.path.join(local_output_dir, "manifest.json")
        if _manifest_matches():
            with open(mpath) as f:
                self._manifests[job.id] = json.load(f)
        elif job.id in self._manifests:
            with open(mpath, "w") as f:
                json.dump(self._manifests[job.id], f, indent=2)
        return self._manifests.get(job.id)

    def manifest(self, job: Job) -> Optional[dict]:
        """Return the recorded manifest for the job (from stream's wire copy, or the
        pulled manifest.json after fetch — the latter is authoritative)."""
        return self._manifests.get(job.id)

    # ---- convenience -----------------------------------------------------

    def run(self, job: Job, local_input_dir: str, local_output_dir: str,
            dout_config_dir: Optional[str] = None, on_progress=None) -> Optional[dict]:
        """Full submit -> stream -> fetch -> manifest in one call, over a single
        persistent control session. `on_progress(ProgressEvent)` is called per event."""
        try:
            self.open_session()
            self.submit(job, local_input_dir)
            for ev in self.stream(job):
                if on_progress:
                    on_progress(ev)
            self.fetch(job, local_output_dir, dout_config_dir=dout_config_dir)
            return self.manifest(job)
        finally:
            self.close_session()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close_session()
        return False


# ============================================================================
# File-driven control plane (DEFAULT) — no PTY, robust over an unstable WAN link.
# ============================================================================
#
# The PTY-based RunnerBox above keeps ONE long-lived interactive stream up for the
# whole job; on the flaky Colab->do-vm link that stream drops every few seconds and
# the host hangs forever in open_session() (docs/runner/jobrunner-challenges.md).
#
# FileRunnerBox uses ONLY discrete file transfers, which the diagnosis proved
# survive the drops (they retry/resume and the bytes land):
#
#   submit : `filament send --relay` job<id>.json + inputs -> box inbox (din).
#            A box-side watcher.py picks the job up, runs it, and sends results.
#   await  : stand up a transient `up --dir <results> --relay` sink (host-dout
#            config) and POLL for manifest.json (which the box sends LAST) + the
#            declared outputs; verify each output's sha256 against the manifest.
#
# There is NO open_session / NO PTY here. `--relay` is forced on by default (set
# relay=False only for the local loopback test, where TURN may be unavailable).

class FileRunnerBox:
    """Host side of the file-driven runner. Pairs with the box-side watcher.py.

    Reuses the SAME din/dout pair secrets as the v1 runner (the `ctl` PTY secret
    is simply unused), so no re-pairing is needed.

      din  : host `send --relay`  -> box `up --dir <inbox>`   (push job + inputs)
      dout : host `up --dir <results> --relay` (transient sink) <- box `send`
             (results: manifest sent LAST, signalling completion)
    """

    def __init__(
        self,
        petname_box_din: str,        # how the host names the box on din (`box-in`)
        server: str,
        host_config_dir: str,        # host config (knows box-in for the `send`)
        host_dout_config_dir: str,   # host dout sink config (knows `box-out`)
        filament_bin: str = "filament",
        remote_inbox: str = "~/filament-jobs/.inbox",  # informational
        relay: bool = True,          # force TURN relay for WAN robustness
        send_timeout_s: int = 1800,
    ):
        self.box_din = petname_box_din
        self.server = server
        self.cfg = host_config_dir
        self.dout_cfg = host_dout_config_dir
        self.bin = filament_bin
        self.remote_inbox = remote_inbox
        self.relay = relay
        self.send_timeout_s = send_timeout_s
        self._manifests = {}

    def _env(self, config_dir):
        env = dict(os.environ)
        env["FILAMENT_CONFIG_DIR"] = config_dir
        env["HOME"] = config_dir
        env["FILAMENT_L2"] = "1"
        return env

    def _relay_args(self):
        return ["--relay"] if self.relay else []

    # ---- submit ----------------------------------------------------------

    def submit(self, job: Job, local_input_dir: str, stage_dir: Optional[str] = None):
        """Push the job spec (as job-<id>.json) + declared inputs to the box inbox
        over din. The watcher acts once the spec AND all inputs have landed.

        Files are sent with their plain basenames; resends collide to `.N` on the
        box and the watcher dedups them by basename (newest index wins)."""
        stage = stage_dir or os.path.join(local_input_dir, f".__job_{job.id}")
        os.makedirs(stage, exist_ok=True)
        spec_name = f"job-{job.id}.json"
        spec_path = os.path.join(stage, spec_name)
        with open(spec_path, "w") as f:
            json.dump(job.spec_dict(), f, indent=2)

        to_push = []
        for name in job.inputs:
            ip = os.path.join(local_input_dir, name)
            if not os.path.exists(ip):
                raise RunnerError(f"declared input missing locally: {ip}")
            to_push.append(ip)
        # send inputs FIRST, spec LAST, so when the watcher sees the spec the
        # inputs are already (mostly) there — the watcher still guards on
        # input-presence + size-stability, so order is an optimisation only.
        if to_push:
            self._send(to_push)
        self._send([spec_path])
        print(f"  submitted {job.id}: {len(job.inputs)} input(s) + spec "
              f"({'relay' if self.relay else 'direct'})", flush=True)

    def _send(self, paths, timeout=None):
        cmd = [self.bin, "send", *paths, "--to", self.box_din,
               "--server", self.server, *self._relay_args()]
        last = None
        for attempt in range(4):
            r = subprocess.run(cmd, env=self._env(self.cfg), capture_output=True,
                               text=True, timeout=timeout or self.send_timeout_s)
            if r.returncode == 0:
                return r
            last = r.stderr.strip()[-300:]
            print(f"  send attempt {attempt + 1} failed ({r.returncode}): {last}; "
                  f"retrying", flush=True)
            time.sleep(3 + 2 * attempt)
        raise RunnerError(f"send to {self.box_din} failed after retries: {last}")

    # ---- await -----------------------------------------------------------

    def await_results(self, job: Job, local_output_dir: str, overall_timeout_s: int):
        """Stand up the dout sink and POLL for this job's manifest.json + declared
        outputs to arrive, up to overall_timeout_s. Verifies each output's sha256
        against the manifest. Returns the manifest dict.

        The box sends the manifest LAST, so a manifest for THIS job id is the
        completion signal. Files may arrive with `.N` suffixes on resend; we match
        by basename and pick the byte-correct copy (sha256 == manifest)."""
        os.makedirs(local_output_dir, exist_ok=True)
        # start clean so a stale manifest/output can't masquerade as success
        for fn in list(os.listdir(local_output_dir)):
            try:
                os.remove(os.path.join(local_output_dir, fn))
            except (FileNotFoundError, IsADirectoryError, PermissionError):
                pass

        up = subprocess.Popen(
            [self.bin, "up", "--server", self.server, "--name-as", "filjob-host-sink",
             "--dir", local_output_dir, *self._relay_args()],
            env=self._env(self.dout_cfg),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        # drain the sink's stdout so it never blocks on a full pipe
        import threading as _threading

        def _drain():
            try:
                for _ in iter(up.stdout.readline, b""):
                    pass
            except Exception:
                pass
        _threading.Thread(target=_drain, daemon=True).start()

        try:
            deadline = time.monotonic() + overall_timeout_s
            printed_wait = False
            while time.monotonic() < deadline:
                m = self._scan_manifest(local_output_dir, job.id)
                if m is not None and self._outputs_verified(m, job, local_output_dir):
                    self._manifests[job.id] = m
                    print(f"  results complete for {job.id}: manifest + "
                          f"{len(job.outputs)} output(s) verified", flush=True)
                    return m
                if not printed_wait:
                    print(f"  awaiting results for {job.id} (sink up, "
                          f"{'relay' if self.relay else 'direct'}) ...", flush=True)
                    printed_wait = True
                time.sleep(2.0)
            raise RunnerError(
                f"await timed out after {overall_timeout_s}s; no complete result set "
                f"for {job.id} in {local_output_dir} "
                f"(have: {sorted(os.listdir(local_output_dir))})")
        finally:
            up.terminate()
            try:
                up.wait(timeout=8)
            except Exception:
                up.kill()

    def _scan_manifest(self, results_dir, job_id):
        """Return the manifest dict for job_id if a manifest.json (or a `.N`
        resend) for it has landed; else None."""
        for fn in os.listdir(results_dir):
            base = re.sub(r"\.\d+$", "", fn)
            if base != "manifest.json":
                continue
            try:
                with open(os.path.join(results_dir, fn)) as f:
                    m = json.load(f)
                if m.get("job_id") == job_id:
                    return m
            except Exception:
                continue
        return None

    @staticmethod
    def _sha256_file(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        return h.hexdigest()

    def _resolve_output(self, results_dir, name):
        """Find the landed file for declared output `name`, allowing for `.N`
        resend suffixes; return the path of the byte-correct copy if any sha
        matches later, else the highest-index copy."""
        base = os.path.basename(name)
        cands = []
        for fn in os.listdir(results_dir):
            stripped = re.sub(r"\.\d+$", "", fn)
            idx_m = re.search(r"\.(\d+)$", fn)
            idx = int(idx_m.group(1)) if idx_m else 0
            if stripped == base:
                cands.append((idx, os.path.join(results_dir, fn)))
        if not cands:
            return None
        cands.sort()  # ascending index; we'll check all for an sha match
        return cands

    def _outputs_verified(self, manifest, job, results_dir):
        """Every declared, non-missing output must have a landed copy whose sha256
        matches the manifest. Returns True only when ALL are present + correct."""
        by_name = {o["name"]: o for o in manifest.get("outputs", [])}
        for name in job.outputs:
            entry = by_name.get(name)
            if entry is None or entry.get("missing"):
                # the job didn't produce it (e.g. it failed/timed out); only
                # require presence of outputs the manifest says exist.
                continue
            cands = self._resolve_output(results_dir, name)
            if not cands:
                return False
            ok = False
            for _idx, path in cands:
                try:
                    if self._sha256_file(path) == entry.get("sha256"):
                        # canonicalise to the plain basename for the caller
                        final = os.path.join(results_dir, os.path.basename(name))
                        if os.path.abspath(path) != os.path.abspath(final):
                            try:
                                shutil.move(path, final)
                            except Exception:
                                pass
                        ok = True
                        break
                except OSError:
                    continue
            if not ok:
                return False
        return True

    def manifest(self, job: Job) -> Optional[dict]:
        return self._manifests.get(job.id)

    # ---- convenience -----------------------------------------------------

    def run(self, job: Job, local_input_dir: str, local_output_dir: str,
            overall_timeout_s: Optional[int] = None) -> Optional[dict]:
        """submit -> await -> manifest, file-driven, no PTY."""
        self.submit(job, local_input_dir)
        to = overall_timeout_s if overall_timeout_s is not None else (job.timeout_s + 600)
        return self.await_results(job, local_output_dir, overall_timeout_s=to)
