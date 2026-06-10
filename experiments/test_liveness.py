#!/usr/bin/env python3
"""Liveness test: the signaling server must never advertise dead peers.

Scenario (against a locally-started backend on a fresh port):
  a) probes A and B subscribe the same channel -> each sees the other via
     known-peer AND via the subscribe/sync rosters (peers + channel_peers);
  b) B's process is SIGKILL'd; probe C connects immediately -> C's roster must
     not contain B's sid (or B must vanish within <= 3s), while A still appears;
  c) A still receives known-peer for C (live-peer advertisement intact).

Run with the lab venv python:
  /root/.claude/jobs/330c2366/tmp/venv/bin/python experiments/test_liveness.py

The script starts/stops its own backend (port 8123) and spawns B as a child of
itself (--child mode) so it can be SIGKILL'd without cleanup handlers running.
Exit code 0 = pass.
"""
import os
import subprocess
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "py"))

from filament_lab.signaling import Signaling  # noqa: E402

PORT = int(os.environ.get("FIL_TEST_PORT", "8123"))
SERVER = f"http://127.0.0.1:{PORT}"
ROOM = "liveness-test-room"
CHANNEL = "ab" * 32  # any 64-hex channel id
PYTHON = sys.executable
BACKEND_DIR = os.path.join(HERE, "..", "backend")


def log(msg):
    print(f"[test] {msg}", flush=True)


# ----------------------------------------------------------------- child (B) --
def run_child():
    """Probe B: connect, sync into the room+channel, report sid and any peers
    seen, then idle until SIGKILL'd."""
    s = Signaling(SERVER, name="B", log=lambda *a: None)
    s.connect()
    done = threading.Event()

    def on_synced(d):
        print(f"SID {s.sio.get_sid()}", flush=True)
        done.set()

    s.on("synced", on_synced)
    s.on("known-peer", lambda d: print(f"PEER {d.get('id')}", flush=True))
    s.sync(ROOM, "uid-B", [CHANNEL])
    done.wait(10)
    time.sleep(3600)  # idle; the parent SIGKILLs us


# ------------------------------------------------------------------- helpers --
def wait_health(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{SERVER}/api/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except OSError:
            time.sleep(0.3)
    return False


def sync_roster(sig, uid, timeout=5.0):
    """Emit sync and return the digest (room peers + channel_peers)."""
    out, evt = {}, threading.Event()

    def ack(d):
        out.update(d or {})
        evt.set()

    sig.sync(ROOM, uid, [CHANNEL], callback=ack)
    if not evt.wait(timeout):
        raise AssertionError("sync ack timed out")
    return out


def roster_sids(digest):
    return ({p["id"] for p in digest.get("peers", [])}
            | {p["id"] for p in digest.get("channel_peers", [])})


def quiet(*_a):
    pass


# --------------------------------------------------------------------- test --
def run_test():
    failures = []
    env = dict(os.environ, PORT=str(PORT), FIL_ASYNC_MODE="eventlet",
               FIL_SELF_MONKEYPATCH="1")
    env.pop("FIL_REDIS_URL", None)  # in-proc dev mode: no Redis lease backend
    backend = subprocess.Popen([PYTHON, "app.py"], cwd=BACKEND_DIR, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    child = None
    a = c = None
    try:
        assert wait_health(), "backend never became healthy"

        # --- a) A and B see each other -----------------------------------
        a = Signaling(SERVER, name="A", log=quiet)
        a_known = {}  # sid -> event payload, from known-peer pushes
        a.on("known-peer", lambda d: a_known.__setitem__(d.get("id"), d))
        a.connect()
        sync_roster(a, "uid-A")
        a_sid = a.sio.get_sid()

        child = subprocess.Popen([PYTHON, os.path.abspath(__file__), "--child"],
                                 stdout=subprocess.PIPE, text=True, bufsize=1)
        b_sid, b_saw = [None], set()

        def read_child():
            for line in child.stdout:
                kind, _, val = line.strip().partition(" ")
                if kind == "SID":
                    b_sid[0] = val
                elif kind == "PEER":
                    b_saw.add(val)

        threading.Thread(target=read_child, daemon=True).start()
        deadline = time.time() + 10
        while b_sid[0] is None and time.time() < deadline:
            time.sleep(0.1)
        assert b_sid[0], "child B never reported its sid"

        deadline = time.time() + 5
        while b_sid[0] not in a_known and time.time() < deadline:
            time.sleep(0.1)
        if b_sid[0] not in a_known:
            failures.append("a) A never got known-peer for B")
        if b_sid[0] not in roster_sids(sync_roster(a, "uid-A")):
            failures.append("a) B missing from A's sync roster")
        deadline = time.time() + 5
        while a_sid not in b_saw and time.time() < deadline:
            time.sleep(0.1)
        if a_sid not in b_saw:
            failures.append("a) B never got known-peer for A")
        log(f"a) ok: A={a_sid} B={b_sid[0]} mutually visible")

        # --- b) SIGKILL B; C must not see it ------------------------------
        child.kill()
        t_kill = time.time()
        c = Signaling(SERVER, name="C", log=quiet)
        c_known, c_left = {}, set()
        c.on("known-peer", lambda d: c_known.__setitem__(d.get("id"), d))
        c.on("known-peer-left", lambda d: c_left.add(d.get("id")))
        c.connect()
        digest = sync_roster(c, "uid-C")
        sids = roster_sids(digest)
        ghost_for = 0.0
        while b_sid[0] in sids and time.time() - t_kill <= 3.0:
            time.sleep(0.25)
            sids = roster_sids(sync_roster(c, "uid-C"))
            ghost_for = time.time() - t_kill
        if b_sid[0] in sids:
            failures.append(f"b) DEAD B {b_sid[0]} still advertised after "
                            f"{time.time() - t_kill:.1f}s: {sids}")
        else:
            log(f"b) ok: dead B absent from C's roster "
                f"(gone after {ghost_for:.2f}s)")
        if a_sid not in sids:
            failures.append(f"b) live A {a_sid} missing from C's roster: {sids}")

        # --- c) A still advertised C (live-peer flow intact) ---------------
        c_sid = c.sio.get_sid()
        deadline = time.time() + 5
        while c_sid not in a_known and time.time() < deadline:
            time.sleep(0.1)
        if c_sid not in a_known:
            failures.append("c) A never got known-peer for C")
        else:
            log(f"c) ok: A got known-peer for C={c_sid}")
        # B may have been pushed to C inside the tiny FIN-propagation window
        # (C subscribed before the kernel surfaced B's close); if so, the
        # server must retract it with known-peer-left within the 3s budget.
        if b_sid[0] in c_known and b_sid[0] not in c_left:
            deadline = t_kill + 3.0
            while b_sid[0] not in c_left and time.time() < deadline:
                time.sleep(0.1)
            if b_sid[0] not in c_left:
                failures.append("c) dead B pushed to C as known-peer and "
                                "never retracted within 3s")
            else:
                log(f"c) ok: B's known-peer to C retracted by known-peer-left "
                    f"after {time.time() - t_kill:.2f}s")
    finally:
        for sig in (a, c):
            try:
                if sig:
                    sig.disconnect()
            except Exception:
                pass
        if child and child.poll() is None:
            child.kill()
        backend.terminate()
        try:
            backend.wait(5)
        except subprocess.TimeoutExpired:
            backend.kill()

    if failures:
        for f in failures:
            log("FAIL " + f)
        return False
    log("PASS")
    return True


if __name__ == "__main__":
    if "--child" in sys.argv:
        run_child()
    else:
        sys.exit(0 if run_test() else 1)
