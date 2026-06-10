"""Driver — scriptable scenarios + an interactive REPL over a Peer.

Scenarios are plain functions that drive a Peer (and optionally a real
`filament` subprocess) through a deterministic sequence, then report what was
observed. The REPL lets you step in by hand: peers, offer, sig, raw, faults.

Run:
  python -m filament_lab.driver --secret <hex> repl
  python -m filament_lab.driver --secret <hex> watch --seconds 15
  python -m filament_lab.driver --secret <hex> discover --seconds 15
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import crypto
from .peer import Peer
from .signaling import default_log


# --------------------------------------------------------------- scenarios ---

def scenario_watch(peer: Peer, seconds: int) -> dict:
    """Passive: subscribe and watch. Did a known-peer / offer appear?"""
    peer.subscribe_all()
    default_log("watching", f"channels={[c[:12] for c in peer.channels]}")
    got = peer.sig.wait_known_peer(seconds)
    return {"known_peer": got, "known": [repr(k) for k in peer.known.values()]}


def scenario_discover(peer: Peer, seconds: int) -> dict:
    """Subscribe, and when a known device appears, auto-send a transport-offer.
    Records discovery (both directions) and any offer the peer sends back."""
    peer.on_known_policy = "offer"
    peer.subscribe_all()
    default_log("discover", "subscribed; will offer on known-peer")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(0.2)
        if peer.known and all(k.offer_received for k in peer.known.values()):
            break
    return {
        "discovered": [repr(k) for k in peer.known.values()],
        "offers_received": {k.sid: k.offer_received for k in peer.known.values()
                            if k.offer_received},
        "offers_sent": [k.sid for k in peer.known.values() if k.offer_sent],
    }


def scenario_late_join(peer: Peer, seconds: int) -> dict:
    """The late-join experiment, from the PYTHON side: we are the LATE subscriber.

    Precondition (script externally): a real `filament up` is already subscribed
    to the shared channel BEFORE we run this. We subscribe second and observe:

      (a) Do WE receive a known-peer for the already-present Rust peer?
          (the server emits symmetrically in _do_subscribe — expected YES)
      (b) Does the Rust peer, on learning about us, fire its transport-offer —
          and do we catch it, or does its fire-once timing miss us?

    This separates the channel-presence layer (a) from the offer-timing layer
    (b), which is where the cited 'fire-once transport-offer' bug actually lives
    (l2.rs:437-505).
    """
    peer.subscribe_all()
    default_log("LATE-JOIN", "we subscribed AFTER the Rust peer (the late subscriber)")
    got_known = peer.sig.wait_known_peer(seconds)
    got_offer = peer.wait_offer(min(seconds, 8)) if got_known else False
    return {
        "a_known_peer_received": got_known,
        "b_offer_received": got_offer,
        "known": [repr(k) for k in peer.known.values()],
        "offers": {k.sid: k.offer_received for k in peer.known.values()
                   if k.offer_received},
        "verdict": _late_join_verdict(got_known, got_offer),
    }


def _late_join_verdict(got_known: bool, got_offer: bool) -> str:
    if not got_known:
        return ("PRESENCE MISS: late subscriber never got known-peer for the "
                "already-present peer (channel-layer asymmetry)")
    if not got_offer:
        return ("PRESENCE OK but OFFER MISS: we were discovered, yet no "
                "transport-offer arrived — the fire-once offer timing (l2.rs) "
                "did not reach the late peer")
    return "OK: known-peer AND transport-offer both reached the late subscriber"


# ------------------------------------------------------------------- REPL ----

REPL_HELP = (
    "commands:\n"
    "  peers                       list known-peers seen on our channels\n"
    "  offer <sid> [ip:port ...]   send a transport-offer (default 127.0.0.1:59999)\n"
    "  sig <sid> <json>            send an arbitrary signal payload to a peer\n"
    "  raw <event> <json>          emit any socket.io event (fault injection)\n"
    "  sub                         (re)subscribe to all our channels\n"
    "  fault <knob> <val>          withhold|delay|duplicate|reorder (e.g. fault delay 3)\n"
    "  tape                        dump the recorded event tape\n"
    "  policy offer|observe        auto-offer on discovery, or just watch\n"
    "  help | quit"
)


def repl(peer: Peer) -> None:
    default_log("repl", "type 'help' for commands")
    print(REPL_HELP, flush=True)
    for line in sys.stdin:
        parts = line.strip().split(None, 2)
        if not parts:
            continue
        cmd = parts[0]
        try:
            if cmd in ("quit", "exit"):
                break
            elif cmd == "help":
                print(REPL_HELP, flush=True)
            elif cmd == "peers":
                if not peer.known:
                    default_log("peer", "(none seen yet)")
                for k in peer.known.values():
                    default_log("peer", repr(k)
                                + (f" offer_in={bool(k.offer_received)}"))
            elif cmd == "sub":
                peer.subscribe_all()
            elif cmd == "offer":
                sid = parts[1]
                addrs = parts[2].split() if len(parts) > 2 else None
                peer.send_offer(sid, addrs)
            elif cmd == "sig":
                peer.sig.signal(parts[1], json.loads(parts[2]))
            elif cmd == "raw":
                peer.sig.raw(parts[1], json.loads(parts[2]) if len(parts) > 2 else {})
            elif cmd == "fault":
                _set_fault(peer, parts[1], parts[2] if len(parts) > 2 else "")
                default_log("faults", repr(peer.faults))
            elif cmd == "policy":
                peer.on_known_policy = parts[1]
                default_log("policy", peer.on_known_policy)
            elif cmd == "tape":
                for t, ev, payload in peer.sig.tape:
                    default_log(f"{t:7.3f}", f"{ev} {payload}")
            else:
                default_log("?", f"unknown: {cmd} (try 'help')")
        except Exception as e:
            default_log("err", repr(e))


def _set_fault(peer: Peer, knob: str, val: str) -> None:
    f = peer.faults
    if knob == "withhold":
        f.withhold_offer = val not in ("0", "false", "off", "")
    elif knob == "delay":
        f.delay_offer = float(val or 0)
    elif knob == "duplicate":
        f.duplicate_offer = int(val or 0)
    elif knob == "reorder":
        f.reorder = val not in ("0", "false", "off", "")
    else:
        raise ValueError(f"unknown fault knob: {knob}")


# ------------------------------------------------------------------- main ----

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Filament control-plane lab driver")
    ap.add_argument("--server", default="http://127.0.0.1:8099")
    ap.add_argument("--secret", action="append", default=[],
                    help="device secret (hex); repeatable. channel = channel_of(secret)")
    ap.add_argument("--channel", action="append", default=[],
                    help="raw 64-hex channel (skips channel_of); repeatable")
    ap.add_argument("--name", default="pylab")
    ap.add_argument("--uid", default=None)
    ap.add_argument("mode", choices=["watch", "discover", "late-join", "repl"],
                    nargs="?", default="watch")
    ap.add_argument("--seconds", type=int, default=15)
    a = ap.parse_args(argv)

    secrets = {f"dev{i}": s for i, s in enumerate(a.secret)}
    peer = Peer(a.server, secrets, name=a.name, uid=a.uid)
    # raw channels: inject directly so channel_of is bypassed
    for i, ch in enumerate(a.channel):
        peer.channels[ch] = f"chan{i}"
    if not peer.channels:
        default_log("warn", "no --secret/--channel given; nothing to subscribe to")

    peer.connect()
    try:
        if a.mode == "repl":
            repl(peer)
        elif a.mode == "watch":
            print(json.dumps(scenario_watch(peer, a.seconds), indent=2))
        elif a.mode == "discover":
            print(json.dumps(scenario_discover(peer, a.seconds), indent=2))
        elif a.mode == "late-join":
            print(json.dumps(scenario_late_join(peer, a.seconds), indent=2))
    finally:
        peer.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
