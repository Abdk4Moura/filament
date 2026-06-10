#!/usr/bin/env python3
"""filament signaling probe — a controllable peer for EXPERIMENTS, not assertions.

The real `filament` binary is the "test object"; this is the other side, fully
under our control. Pair it with a real `filament up`/`send`/`netcat` and you can
construct exact adversarial timing (late join, withheld/duplicated/reordered
offers, malformed payloads) and watch how the real code reacts — deterministic,
and you can STEP IN interactively to inject anything.

It speaks the same Socket.IO signaling the CLI uses:
  emit join {room,uid,name}            -> recv welcome {id, peers}
  emit subscribe {channels:[chan]}     -> ack {ok,n} + recv known-peer {id,uid,name,channel}
  emit signal {to, data}               -> peer recv signal {from, data}
The pair channel is sha256("filament-pair:"+secret) (= the CLI's channel_of).

USAGE
  # passive watch: does a LATE subscriber see an already-present peer?
  #   (run `FILAMENT_L2=1 filament up` first, then:)
  probe.py --secret <hex> watch --seconds 15

  # interactive step-in REPL:
  probe.py --secret <hex> repl
  > peers                 # who's on my channel
  > offer <peer-id>       # send a transport-offer (optionally with ip:port candidates)
  > sig <peer-id> {json}  # send an arbitrary signal payload
  > raw subscribe {json}  # emit any event with any payload (fault injection)
  > quit

  --server defaults to the local fixture; pass a prod URL to probe live.
"""
import argparse, hashlib, json, sys, threading, time
import socketio

T0 = time.monotonic()
def ts(): return f"{time.monotonic()-T0:7.3f}s"
def log(kind, msg=""): print(f"[{ts()}] {kind:14} {msg}", flush=True)

def channel_of(secret: str) -> str:
    return hashlib.sha256(b"filament-pair:" + secret.encode()).hexdigest()

class Probe:
    def __init__(self, server, name):
        self.server, self.name = server, name
        self.sio = socketio.Client(reconnection=False, logger=False, engineio_logger=False)
        self.my_id = None
        self.peers = {}          # id -> {name, uid, channel}
        self.known_peer_seen = threading.Event()
        self.signals = []        # (from, data)
        self._wire()

    def _wire(self):
        s = self.sio
        @s.on("connect")
        def _c(): log("connect", f"transport={s.transport()}")
        @s.on("disconnect")
        def _d(): log("disconnect")
        @s.on("welcome")
        def _w(d): self.my_id = d.get("id"); log("welcome", f"id={self.my_id} peers={d.get('peers')}")
        @s.on("peer-joined")
        def _pj(d): log("peer-joined", json.dumps(d))
        @s.on("peer-left")
        def _pl(d): log("peer-left", json.dumps(d))
        @s.on("known-peer")
        def _kp(d):
            pid = d.get("id")
            self.peers[pid] = {k: d.get(k) for k in ("name", "uid", "channel")}
            self.known_peer_seen.set()
            log("KNOWN-PEER", f"id={pid} name={d.get('name')} uid={d.get('uid')} chan={d.get('channel','')[:12]}")
        @s.on("signal")
        def _sig(d):
            self.signals.append((d.get("from"), d.get("data")))
            dd = d.get("data") or {}
            t = dd.get("type") if isinstance(dd, dict) else "?"
            log("SIGNAL", f"from={d.get('from')} type={t} data={json.dumps(dd)[:140]}")

    def connect(self):
        log("connecting", self.server)
        self.sio.connect(self.server, wait_timeout=12)

    def join(self, room, uid):
        self.sio.emit("join", {"room": room, "uid": uid, "name": self.name})
        log("-> join", f"room={room} uid={uid}")

    def subscribe(self, channel):
        def ack(resp): log("subscribe-ack", json.dumps(resp))
        self.sio.emit("subscribe", {"channels": [channel]}, callback=ack)
        log("-> subscribe", f"chan={channel[:12]}…")

    def offer(self, to, addrs):
        data = {"type": "transport-offer", "v": 1, "addrs": addrs}
        self.sio.emit("signal", {"to": to, "data": data})
        log("-> OFFER", f"to={to} addrs={addrs}")

    def signal(self, to, data):
        self.sio.emit("signal", {"to": to, "data": data})
        log("-> signal", f"to={to} {json.dumps(data)[:140]}")

def repl(p):
    log("repl", "commands: peers | offer <id> [ip:port ...] | sig <id> <json> | raw <event> <json> | quit")
    for line in sys.stdin:
        parts = line.strip().split(None, 2)
        if not parts: continue
        cmd = parts[0]
        try:
            if cmd == "quit": break
            elif cmd == "peers":
                for pid, m in p.peers.items(): log("peer", f"{pid} {m}")
                if not p.peers: log("peer", "(none seen yet)")
            elif cmd == "offer":
                pid = parts[1]; addrs = parts[2].split() if len(parts) > 2 else ["127.0.0.1:59999"]
                p.offer(pid, addrs)
            elif cmd == "sig":
                p.signal(parts[1], json.loads(parts[2]))
            elif cmd == "raw":
                p.sio.emit(parts[1], json.loads(parts[2]) if len(parts) > 2 else {})
                log("-> raw", f"{parts[1]} {parts[2] if len(parts)>2 else '{}'}")
            else: log("?", f"unknown: {cmd}")
        except Exception as e:
            log("err", repr(e))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://127.0.0.1:8099")
    ap.add_argument("--secret", help="pair secret (hex) -> channel_of")
    ap.add_argument("--channel", help="raw 64-hex channel (overrides --secret)")
    ap.add_argument("--name", default="probe")
    ap.add_argument("mode", choices=["watch", "repl"], nargs="?", default="watch")
    ap.add_argument("--seconds", type=int, default=15)
    a = ap.parse_args()

    chan = a.channel or (channel_of(a.secret) if a.secret else None)
    p = Probe(a.server, a.name)
    p.connect()
    p.join(f"probe-{int(T0*1000)%100000}", f"probe-{a.name}")
    if chan:
        p.subscribe(chan)
        log("watching", f"channel {chan[:16]}… (the CLI's channel_of(secret))")

    if a.mode == "repl":
        repl(p)
    else:
        # passive: did we, the LATE subscriber, learn about an already-present peer?
        got = p.known_peer_seen.wait(timeout=a.seconds)
        log("VERDICT", "known-peer RECEIVED (late subscriber saw the existing peer) ✓"
                       if got else
                       f"NO known-peer in {a.seconds}s — late subscriber NEVER saw the existing peer ✗ (presence asymmetry reproduced)")
    p.sio.disconnect()

if __name__ == "__main__":
    main()
