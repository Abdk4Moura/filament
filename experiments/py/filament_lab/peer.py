"""Peer — a known-device Filament peer (control plane only).

Wraps a Signaling connection with the device-pairing presence flow:
  * subscribe to channel_of(secret) for one or more known devices,
  * track known-peers that appear on those channels,
  * do the transport-offer exchange (emit/parse {type:"transport-offer", v:1,
    addrs:[...], srflx?}),
  * carry the fault knobs (withhold / delay / duplicate / reorder offers) so
    adversarial timing can be scripted deterministically.

The actual QUIC link (aioquic) is OUT OF SCOPE here — this is the control plane,
where the cross-machine bugs live (late-join presence, fire-once offers). When a
known-peer appears we can send a transport-offer exactly as cli/src/l2.rs:480 /
main.rs:1785 do, and we observe what the real binary sends back.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from . import crypto
from .signaling import Signaling


class FaultConfig:
    """Knobs for adversarial offer timing. Defaults = honest behavior."""

    def __init__(self):
        self.withhold_offer = False   # never send our transport-offer
        self.delay_offer = 0.0        # seconds to sleep before sending
        self.duplicate_offer = 0      # extra copies to send after the first
        self.reorder = False          # send candidates in reverse order

    def __repr__(self):
        return (f"FaultConfig(withhold={self.withhold_offer} delay={self.delay_offer} "
                f"dup={self.duplicate_offer} reorder={self.reorder})")


class KnownPeer:
    """A device that appeared on one of our subscribed channels."""

    def __init__(self, sid: str, name: str | None, uid: str | None, channel: str):
        self.sid = sid
        self.name = name
        self.uid = uid
        self.channel = channel
        self.first_seen = time.monotonic()
        self.offer_sent = False
        self.offer_received: dict | None = None  # their transport-offer payload

    def __repr__(self):
        return f"KnownPeer(sid={self.sid} name={self.name} uid={self.uid} chan={self.channel[:12]})"


class Peer:
    """A controllable known-device peer.

    secrets: name -> 64-hex device secret (as in devices.json). We subscribe to
    channel_of(secret) for each, so the real `filament up` holding the same
    secret discovers us (and we discover it) via the symmetric known-peer emit.
    """

    def __init__(self, server: str, secrets: dict[str, str], name: str = "pylab",
                 uid: str | None = None, log: Callable | None = None):
        self.sig = Signaling(server, name=name, log=log)
        self.secrets = dict(secrets)
        self.name = name
        self.uid = uid or f"pylab-{crypto.fresh_secret()[:8]}"
        self.faults = FaultConfig()
        self.log = self.sig.log

        # channel hex -> device name (reverse of channel_of)
        self.channels = {crypto.channel_of(s): n for n, s in self.secrets.items()}
        # sid -> KnownPeer
        self.known: dict[str, KnownPeer] = {}
        # what to do when a known-peer appears: "offer" (auto) or "observe"
        self.on_known_policy = "observe"

        self._offer_evt = threading.Event()
        self.sig.on("known-peer", self._on_known_peer)
        self.sig.on("signal", self._on_signal)

    # ------------------------------------------------------------ lifecycle --
    def connect(self, room: str | None = None) -> None:
        self.sig.connect()
        self.room = room or f"pylab-{crypto.fresh_secret()[:8]}"
        self.sig.join(self.room, self.uid)
        self.sig.wait_welcome(5)

    def subscribe_all(self) -> None:
        self.sig.subscribe(list(self.channels.keys()))

    def disconnect(self) -> None:
        self.sig.disconnect()

    # ------------------------------------------------------------- handlers --
    def _on_known_peer(self, d: dict) -> None:
        ch = d.get("channel") or ""
        if ch not in self.channels:
            return  # not one of ours
        sid = d.get("id")
        if not sid or sid in self.known:
            return
        kp = KnownPeer(sid, d.get("name"), d.get("uid"), ch)
        self.known[sid] = kp
        dev = self.channels.get(ch)
        self.log("DISCOVERED", f"device='{dev}' sid={sid} uid={kp.uid} via {ch[:12]}")
        if self.on_known_policy == "offer":
            self.send_offer(sid)

    def _on_signal(self, d: dict) -> None:
        data = d.get("data") or {}
        frm = d.get("from")
        if isinstance(data, dict) and data.get("type") == "transport-offer":
            kp = self.known.get(frm)
            if kp:
                kp.offer_received = data
            self._offer_evt.set()
            addrs = data.get("addrs") or []
            self.log("OFFER-IN", f"from={frm} v={data.get('v')} "
                                 f"addrs={addrs} srflx={data.get('srflx')}")

    # -------------------------------------------------------------- offers ---
    def make_offer(self, addrs: list[str], srflx: str | None = None) -> dict:
        """Build a transport-offer exactly as l2.rs:480 / main.rs:1785."""
        offer: dict[str, Any] = {"type": "transport-offer", "v": 1, "addrs": addrs}
        if srflx:
            offer["srflx"] = srflx
        return offer

    def send_offer(self, to_sid: str, addrs: list[str] | None = None,
                   srflx: str | None = None) -> None:
        """Send a transport-offer to a peer sid, applying the fault knobs."""
        f = self.faults
        addrs = addrs if addrs is not None else ["127.0.0.1:59999"]
        if f.reorder:
            addrs = list(reversed(addrs))
        if f.withhold_offer:
            self.log("OFFER-WITHHELD", f"to={to_sid} (fault: withhold)")
            return

        def _do():
            offer = self.make_offer(addrs, srflx)
            self.sig.signal(to_sid, offer)
            if to_sid in self.known:
                self.known[to_sid].offer_sent = True
            self.log("OFFER-OUT", f"to={to_sid} addrs={addrs}"
                                  + (f" srflx={srflx}" if srflx else ""))
            for i in range(f.duplicate_offer):
                self.sig.signal(to_sid, offer)
                self.log("OFFER-DUP", f"to={to_sid} copy#{i + 1} (fault: duplicate)")

        if f.delay_offer > 0:
            self.log("OFFER-DELAY", f"to={to_sid} sleeping {f.delay_offer}s (fault)")
            threading.Timer(f.delay_offer, _do).start()
        else:
            _do()

    def wait_offer(self, timeout: float = 10.0) -> bool:
        """Block until any transport-offer arrives."""
        return self._offer_evt.wait(timeout)

    # ------------------------------------------------------- trust proof -----
    def send_pair_proof(self, to_sid: str, device_name: str,
                        my_fp: str, their_fp: str) -> None:
        """Emit the pair-proof MAC that satisfies the Rust acceptor's trust gate
        (main.rs:3986). Reachable only once DTLS fingerprints exist (a real
        transport) — provided here so a future transport layer can call it."""
        secret = self.secrets[device_name]
        peer = self.known.get(to_sid)
        peer_uid = peer.uid if peer else ""
        mac = crypto.proof_for(secret, self.uid, self.uid, peer_uid, my_fp, their_fp)
        # In the real flow this rides the data channel (send_control); here we
        # expose it for whatever transport carries it.
        self.log("PAIR-PROOF", f"to={to_sid} device={device_name} mac={mac[:16]}…")
        return {"type": "pair-proof", "mac": mac}
