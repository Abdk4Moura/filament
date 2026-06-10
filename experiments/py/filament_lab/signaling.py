"""Filament signaling client — a reusable python-socketio wrapper.

Speaks the exact Socket.IO contract the Rust CLI (cli/src/net.rs) and the
backend (backend/signaling.py) use:

  emit join {room,uid,name}        -> recv welcome {id, peers}
  emit subscribe {channels:[...]}  -> ack {ok,n} + recv known-peer {...,channel}
  emit sync {room,uid,name,channels} -> ack/synced digest
  emit signal {to, data}           -> peer recv signal {from, data}
  pairing: pair-create/pair-ok/pair-code/pair-claim/pair-matched/pair-used/pair-error

THE HANDSHAKE FIX (the seed probe.py "namespaces failed to connect"): the
Flask-SocketIO fixture speaks Engine.IO v4 / Socket.IO v5, which python-socketio
5.x defaults to — so the protocol version is NOT the problem. The actual cause
is that probe.py forces transports=["websocket"] while the `websocket-client`
package is absent, leaving NO usable transport. We connect with BOTH transports
(polling upgrades to websocket if available); see requirements.txt.

This module is callback-driven and thread-safe enough for a REPL: register
handlers with .on(event, fn) or rely on the recorded state (peers, signals).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Callable

import socketio

# A process-wide monotonic clock so every log line in a scenario shares one T0.
_T0 = time.monotonic()


def ts() -> str:
    return f"{time.monotonic() - _T0:7.3f}s"


def default_log(kind: str, msg: str = "") -> None:
    print(f"[{ts()}] {kind:14} {msg}", flush=True)


class Signaling:
    """One Socket.IO connection to a filament signaling server.

    Records observed state (my_id, peers, signals, pair_state) AND fans events
    out to any callbacks registered via .on(event, fn). The peer/driver layers
    build on this; nothing here knows about crypto or transports.
    """

    # Events the server emits that we mirror into state + dispatch.
    SERVER_EVENTS = (
        "welcome", "peer-joined", "peer-left", "signal",
        "known-peer", "known-peer-left", "synced",
        "pair-code", "pair-ok", "pair-matched", "pair-used", "pair-error",
    )

    def __init__(self, server: str, name: str = "pylab", log: Callable | None = None):
        self.server = server
        self.name = name
        self.log = log or default_log
        self.sio = socketio.Client(reconnection=False, logger=False, engineio_logger=False)

        self.my_id: str | None = None
        # peer sid -> {name, uid, channel}
        self.peers: dict[str, dict] = {}
        # full event tape for after-the-fact inspection: (ts, event, payload)
        self.tape: list[tuple[float, str, Any]] = []
        # raw recorded signals: list of (from_sid, data)
        self.signals: list[tuple[str, Any]] = []
        self.pair_state: dict[str, Any] = {}

        self._cbs: dict[str, list[Callable]] = defaultdict(list)
        self._known_peer_evt = threading.Event()
        self._welcome_evt = threading.Event()
        self._wire()

    # ----------------------------------------------------------- callbacks --
    def on(self, event: str, fn: Callable) -> None:
        """Register an extra handler for an event. Called with the payload."""
        self._cbs[event].append(fn)

    def _dispatch(self, event: str, payload: Any) -> None:
        self.tape.append((time.monotonic() - _T0, event, payload))
        for fn in self._cbs.get(event, ()):
            try:
                fn(payload)
            except Exception as e:  # a buggy callback must not kill the socket
                self.log("cb-err", f"{event}: {e!r}")

    # --------------------------------------------------------------- wiring --
    def _wire(self) -> None:
        s = self.sio

        @s.on("connect")
        def _c():
            self.log("connect", f"transport={s.transport()}")
            self._dispatch("connect", None)

        @s.on("disconnect")
        def _d():
            self.log("disconnect")
            self._dispatch("disconnect", None)

        @s.on("welcome")
        def _w(d):
            self.my_id = d.get("id")
            self._welcome_evt.set()
            self.log("welcome", f"id={self.my_id} peers={d.get('peers')}")
            self._dispatch("welcome", d)

        @s.on("peer-joined")
        def _pj(d):
            self.log("peer-joined", _short(d))
            self._dispatch("peer-joined", d)

        @s.on("peer-left")
        def _pl(d):
            self.log("peer-left", _short(d))
            self._dispatch("peer-left", d)

        @s.on("known-peer")
        def _kp(d):
            pid = d.get("id")
            if pid:
                self.peers[pid] = {k: d.get(k) for k in ("name", "uid", "channel")}
            self._known_peer_evt.set()
            self.log("KNOWN-PEER",
                     f"id={pid} name={d.get('name')} uid={d.get('uid')} "
                     f"chan={(d.get('channel') or '')[:12]}")
            self._dispatch("known-peer", d)

        @s.on("known-peer-left")
        def _kpl(d):
            pid = d.get("id")
            self.peers.pop(pid, None)
            self.log("known-peer-left", _short(d))
            self._dispatch("known-peer-left", d)

        @s.on("signal")
        def _sig(d):
            self.signals.append((d.get("from"), d.get("data")))
            dd = d.get("data") or {}
            t = dd.get("type") if isinstance(dd, dict) else "?"
            self.log("SIGNAL", f"from={d.get('from')} type={t} {_short(dd)}")
            self._dispatch("signal", d)

        @s.on("synced")
        def _syn(d):
            self.log("synced", _short(d))
            self._dispatch("synced", d)

        for ev in ("pair-code", "pair-ok", "pair-matched", "pair-used", "pair-error"):
            self._wire_pair(ev)

    def _wire_pair(self, ev: str) -> None:
        @self.sio.on(ev)
        def _h(d=None):
            self.pair_state[ev] = d
            self.log(ev.upper(), _short(d))
            self._dispatch(ev, d)

    # ----------------------------------------------------------- transport --
    def connect(self, timeout: float = 10.0,
                transports: list[str] | None = None) -> None:
        self.log("connecting", self.server)
        # Default to websocket: it's what the Rust CLI uses and it delivers the
        # `welcome` immediately. The seed probe's "namespaces failed to connect"
        # was simply the `websocket-client` package being absent (so even the
        # websocket transport had no implementation) — install it (requirements.txt)
        # and websocket works. Under the eventlet fixture, long-poll delivery of
        # server-initiated emits (welcome) lags, so polling is a poor default here.
        self.sio.connect(self.server, transports=transports or ["websocket"],
                         wait_timeout=timeout)

    def disconnect(self) -> None:
        try:
            self.sio.disconnect()
        except Exception:
            pass

    def wait_welcome(self, timeout: float = 5.0) -> bool:
        return self._welcome_evt.wait(timeout)

    def wait_known_peer(self, timeout: float = 10.0) -> bool:
        return self._known_peer_evt.wait(timeout)

    # ------------------------------------------------------------- emitters --
    def join(self, room: str, uid: str, name: str | None = None) -> None:
        self.sio.emit("join", {"room": room, "uid": uid, "name": name or self.name})
        self.log("-> join", f"room={room} uid={uid}")

    def subscribe(self, channels: list[str], callback: Callable | None = None) -> None:
        def ack(resp):
            self.log("subscribe-ack", _short(resp))
            if callback:
                callback(resp)
        self.sio.emit("subscribe", {"channels": channels}, callback=ack)
        self.log("-> subscribe", f"n={len(channels)} [{','.join(c[:12] for c in channels)}]")

    def sync(self, room: str, uid: str, channels: list[str],
             name: str | None = None, callback: Callable | None = None) -> None:
        payload = {"room": room, "uid": uid, "name": name or self.name, "channels": channels}
        self.sio.emit("sync", payload, callback=callback)
        self.log("-> sync", f"room={room} chans={len(channels)}")

    def signal(self, to: str, data: Any) -> None:
        self.sio.emit("signal", {"to": to, "data": data})
        self.log("-> signal", f"to={to} {_short(data)}")

    def raw(self, event: str, payload: Any = None, callback: Callable | None = None) -> None:
        """Fault-injection seam: emit any event with any payload."""
        self.sio.emit(event, payload if payload is not None else {}, callback=callback)
        self.log("-> raw", f"{event} {_short(payload)}")


def _short(v: Any, n: int = 160) -> str:
    import json
    try:
        s = json.dumps(v)
    except (TypeError, ValueError):
        s = str(v)
    return s if len(s) <= n else s[:n] + "…"
