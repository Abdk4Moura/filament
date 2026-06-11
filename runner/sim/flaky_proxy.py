#!/usr/bin/env python3
"""A deterministic flaky-link TCP proxy — the local stand-in for the unstable
Colab->do-vm WAN path that breaks the GPU job-runner.

It sits between the filament CLI clients and the LOCAL signaling backend and,
on command, severs every proxied connection (and refuses new ones) for a window,
then heals. Because filament's discovery + SDP/ICE exchange ride this socket.io
TCP link, cutting it reproduces the real failure signatures WITHOUT a remote box:

  * `send` can't find the peer within the timeout         (discovery race / "no peer connected")
  * an in-flight transfer's signaling drops mid-stream    (reconnect churn → truncation window)
  * a result/manifest send lands in a dead window         (lost manifest)

Control plane: a tiny HTTP-less control via a UNIX-signal-free file flag AND a
localhost control socket. The simplest robust knob is a CONTROL FILE the proxy
polls: if it exists, the link is DOWN (existing conns killed, new conns refused);
remove it and the link is UP again. A scripted sim toggles that file to choreograph
outages deterministically. Optionally a periodic flap (--flap-up / --flap-down)
induces randomised drops for a soak.

Stdlib-only. Usage:
  flaky_proxy.py --listen 127.0.0.1:9077 --target 127.0.0.1:8077 \
                 --down-flag /tmp/sim/down [--flap-up 4 --flap-down 2 --seed 1]
"""
import argparse
import os
import random
import socket
import sys
import threading
import time

_BUF = 1 << 16


def log(msg):
    sys.stderr.write(f"[flaky-proxy] {msg}\n")
    sys.stderr.flush()


class FlakyProxy:
    def __init__(self, listen, target, down_flag, flap_up=0.0, flap_down=0.0, seed=0):
        self.lhost, self.lport = listen
        self.thost, self.tport = target
        self.down_flag = down_flag
        self.flap_up = flap_up
        self.flap_down = flap_down
        self.rng = random.Random(seed)
        self._down = threading.Event()        # set => link is DOWN
        self._conns = set()                    # live (client,server) socket pairs
        self._conns_lock = threading.Lock()
        self._stop = threading.Event()
        self.opened = 0
        self.killed = 0

    # ---- outage state ----------------------------------------------------

    def is_down(self):
        # control-file presence OR an explicit flap window
        return self._down.is_set() or os.path.exists(self.down_flag)

    def _kill_all(self):
        with self._conns_lock:
            pairs = list(self._conns)
            self._conns.clear()
        for a, b in pairs:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass
            self.killed += 1
        if pairs:
            log(f"link DOWN — severed {len(pairs)} live connection(s)")

    # ---- pumps -----------------------------------------------------------

    def _pump(self, src, dst, pair):
        try:
            while not self._stop.is_set():
                # If the link drops mid-stream, stop pumping immediately so the
                # peer observes a truncated/closed stream (real drop behaviour).
                if self.is_down():
                    break
                src.settimeout(0.5)
                try:
                    data = src.recv(_BUF)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                try:
                    dst.sendall(data)
                except OSError:
                    break
        finally:
            with self._conns_lock:
                self._conns.discard(pair)
            for s in pair:
                try:
                    s.close()
                except OSError:
                    pass

    def _handle(self, client):
        if self.is_down():
            # refuse during an outage — exactly what an unreachable box looks like
            try:
                client.close()
            except OSError:
                pass
            return
        try:
            server = socket.create_connection((self.thost, self.tport), timeout=5)
        except OSError as e:
            log(f"upstream connect failed: {e}")
            try:
                client.close()
            except OSError:
                pass
            return
        client.setblocking(True)
        server.setblocking(True)
        pair = (client, server)
        with self._conns_lock:
            self._conns.add(pair)
        self.opened += 1
        t1 = threading.Thread(target=self._pump, args=(client, server, pair), daemon=True)
        t2 = threading.Thread(target=self._pump, args=(server, client, pair), daemon=True)
        t1.start()
        t2.start()

    # ---- outage choreography watcher ------------------------------------

    def _flag_watch(self):
        """Poll the control flag; the instant the link transitions to DOWN,
        sever all live connections (so an in-flight transfer truncates)."""
        was_down = False
        while not self._stop.is_set():
            down = self.is_down()
            if down and not was_down:
                self._kill_all()
            was_down = down
            time.sleep(0.1)

    def _flapper(self):
        if self.flap_up <= 0 and self.flap_down <= 0:
            return
        while not self._stop.is_set():
            up = self.rng.uniform(self.flap_up * 0.5, self.flap_up * 1.5) if self.flap_up else 1.0
            self._down.clear()
            self._wait(up)
            if self._stop.is_set():
                return
            down = self.rng.uniform(self.flap_down * 0.5, self.flap_down * 1.5) if self.flap_down else 1.0
            self._down.set()
            self._kill_all()
            self._wait(down)

    def _wait(self, secs):
        end = time.monotonic() + secs
        while not self._stop.is_set() and time.monotonic() < end:
            time.sleep(0.05)

    # ---- serve -----------------------------------------------------------

    def serve(self):
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((self.lhost, self.lport))
        ls.listen(128)
        ls.settimeout(0.5)
        log(f"listening on {self.lhost}:{self.lport} -> {self.thost}:{self.tport} "
            f"(down-flag={self.down_flag})")
        threading.Thread(target=self._flag_watch, daemon=True).start()
        threading.Thread(target=self._flapper, daemon=True).start()
        try:
            while not self._stop.is_set():
                try:
                    client, _ = ls.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
        finally:
            ls.close()
            self._kill_all()
            log(f"stopped (opened={self.opened}, severed={self.killed})")

    def stop(self):
        self._stop.set()


def _hostport(s):
    h, p = s.rsplit(":", 1)
    return (h, int(p))


def main(argv):
    ap = argparse.ArgumentParser(description="deterministic flaky-link TCP proxy")
    ap.add_argument("--listen", required=True, help="host:port to listen on")
    ap.add_argument("--target", required=True, help="host:port of the real backend")
    ap.add_argument("--down-flag", required=True,
                    help="control file; while it EXISTS the link is DOWN")
    ap.add_argument("--flap-up", type=float, default=0.0,
                    help="mean seconds UP between random outages (0 = no auto-flap)")
    ap.add_argument("--flap-down", type=float, default=0.0,
                    help="mean seconds DOWN per random outage")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv[1:])

    p = FlakyProxy(_hostport(args.listen), _hostport(args.target), args.down_flag,
                   flap_up=args.flap_up, flap_down=args.flap_down, seed=args.seed)
    try:
        p.serve()
    except KeyboardInterrupt:
        p.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
