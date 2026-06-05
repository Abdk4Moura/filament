"""Socket.IO signaling relay.

A *dumb pipe*: it never sees file bytes. It tracks who is in which room and
forwards opaque WebRTC payloads (SDP/ICE) between peers, keyed by socket id.

Scaling: room membership lives behind a small Registry. With no Redis it's an
in-memory dict (single instance, the dev default). Set FIL_REDIS_URL and it
moves to Redis — combined with Socket.IO's Redis message queue (see app.py),
that lets you run many api replicas and scale them up/down on demand, because
every instance shares the same room state and can deliver to any peer.

Event contract (kept in sync with CONTRACT.md):
  client -> server   join {room,name} · signal {to,data} · leave {}
  server -> client   welcome {id,peers:[{id,name}]} · peer-joined {id,name}
                     peer-left {id} · signal {from,data}
"""
import re
import secrets as _secrets

from flask import request
from flask_socketio import emit, join_room, leave_room

# Speakable one-time codes: easy to say across a table, unique by NX semantics.
_ADJ = ["brave", "calm", "clever", "eager", "gentle", "jolly", "keen", "lucky", "mellow", "swift"]
_ANIMAL = ["otter", "panda", "falcon", "lynx", "koala", "heron", "fox", "ibex", "marten", "tapir"]


def _mint_pair_code():
    return f"{_secrets.choice(_ADJ)}-{_secrets.choice(_ANIMAL)}-{_secrets.randbelow(90) + 10}"


def _norm_code(raw):
    """Normalize a spoken keyword: lowercase, spaces→dashes, strip noise."""
    if not isinstance(raw, str):
        return ""
    return re.sub(r"[^a-z0-9-]", "", re.sub(r"\s+", "-", raw.strip().lower()))[:48]


class _MemRegistry:
    """Process-local membership (single instance)."""

    def __init__(self):
        self._m = {}  # sid -> {"room", "name", "uid"}

    def add(self, sid, room, name, uid=None):
        self._m[sid] = {"room": room, "name": name, "uid": uid}

    def room_of(self, sid):
        m = self._m.get(sid)
        return m["room"] if m else None

    def remove(self, sid):
        m = self._m.pop(sid, None)
        return m["room"] if m else None

    def peers_in(self, room, exclude=None):
        return [
            {"id": s, "name": v["name"], "uid": v.get("uid")}
            for s, v in self._m.items()
            if v["room"] == room and s != exclude
        ]

    # -- one-time pairing codes (#11) --
    def pair_create(self, code, sid, ttl=600):
        pairs = getattr(self, "_pairs", None)
        if pairs is None:
            pairs = self._pairs = {}
        if code in pairs:
            return False
        pairs[code] = sid
        return True

    def pair_claim(self, code):
        return getattr(self, "_pairs", {}).pop(code, None)


class _RedisRegistry:
    """Shared membership in Redis so api replicas see one another's peers.

    Liveness (#10): membership alone can't be trusted — an api restart kills
    sockets without running disconnect handlers, orphaning entries that then
    appear in every `welcome` as zombie peers. So every connection also holds a
    short LEASE, refreshed by its owning instance; `peers_in` only returns
    leased entries and lazily deletes the dead ones.
    """

    TTL = 86400  # room/sid bookkeeping
    LIVE_TTL = 120  # liveness lease; refreshed every ~45s while connected

    def __init__(self, url):
        import redis  # lazy: only needed when scaling with Redis

        self.r = redis.Redis.from_url(url, decode_responses=True)

    def _rk(self, room):
        return f"filament:room:{room}"

    def _sk(self, sid):
        return f"filament:sid:{sid}"

    def _lk(self, sid):
        return f"filament:live:{sid}"

    def add(self, sid, room, name, uid=None):
        import json

        p = self.r.pipeline()
        p.hset(self._rk(room), sid, json.dumps({"name": name, "uid": uid}))
        p.expire(self._rk(room), self.TTL)
        p.set(self._sk(sid), room, ex=self.TTL)
        p.set(self._lk(sid), 1, ex=self.LIVE_TTL)  # liveness lease (#10)
        p.execute()

    def refresh(self, sids):
        """Extend the liveness lease for locally-connected sids."""
        if not sids:
            return
        p = self.r.pipeline()
        for sid in sids:
            p.set(self._lk(sid), 1, ex=self.LIVE_TTL)
        p.execute()

    def room_of(self, sid):
        return self.r.get(self._sk(sid))

    def remove(self, sid):
        room = self.r.get(self._sk(sid))
        if room:
            p = self.r.pipeline()
            p.hdel(self._rk(room), sid)
            p.delete(self._sk(sid))
            p.delete(self._lk(sid))
            p.execute()
        return room

    # -- one-time pairing codes (#11): SET NX EX to create, GETDEL to consume
    # atomically — a code can be claimed exactly once, ever.
    def pair_create(self, code, sid, ttl=600):
        return bool(self.r.set(f"filament:pair:{code}", sid, nx=True, ex=ttl))

    def pair_claim(self, code):
        creator = self.r.getdel(f"filament:pair:{code}")
        # Don't match against a creator whose connection is already dead.
        if creator and not self.r.exists(self._lk(creator)):
            return None
        return creator

    def peers_in(self, room, exclude=None):
        import json

        entries = self.r.hgetall(self._rk(room))
        sids = [s for s in entries if s != exclude]
        if not sids:
            return []
        # Liveness check (#10): only entries holding a lease are real.
        p = self.r.pipeline()
        for s in sids:
            p.exists(self._lk(s))
        alive = dict(zip(sids, p.execute()))

        out, dead = [], []
        for s in sids:
            if not alive.get(s):
                dead.append(s)
                continue
            raw = entries[s]
            try:
                v = json.loads(raw)
                out.append({"id": s, "name": v.get("name"), "uid": v.get("uid")})
            except (json.JSONDecodeError, AttributeError):
                out.append({"id": s, "name": raw, "uid": None})  # pre-uid entry
        if dead:  # lazy cleanup: zombies vanish the first time anyone looks
            p = self.r.pipeline()
            p.hdel(self._rk(room), *dead)
            for s in dead:
                p.delete(self._sk(s))
            p.execute()
        return out


def make_registry(redis_url):
    return _RedisRegistry(redis_url) if redis_url else _MemRegistry()


def register(socketio, registry):
    local_sids = set()  # connections owned by THIS instance (for lease refresh)

    @socketio.on("connect")
    def on_connect():
        local_sids.add(request.sid)

    if hasattr(registry, "refresh"):
        def _lease_loop():
            while True:
                socketio.sleep(45)
                try:
                    registry.refresh(list(local_sids))
                except Exception:
                    pass

        socketio.start_background_task(_lease_loop)

    @socketio.on("join")
    def on_join(data):
        sid = request.sid
        room = (data or {}).get("room")
        name = (data or {}).get("name") or "anonymous"
        # uid: a stable per-tab identity that survives reconnects (sids don't).
        # It lets peers recognize "same device, new connection" — the basis for
        # transfer resume.
        uid = (data or {}).get("uid")
        if not room:
            return
        _do_leave(sid)  # if this socket was already in a room, clean it first

        join_room(room)
        registry.add(sid, room, name, uid)

        # Tell the joiner who's already here (they initiate offers); tell the
        # room someone arrived. With the Redis message queue these reach peers
        # on every instance.
        emit("welcome", {"id": sid, "peers": registry.peers_in(room, exclude=sid)})
        emit("peer-joined", {"id": sid, "name": name, "uid": uid}, room=room, include_self=False)

    # -- one-time pairing (#11): say the code aloud; it works exactly once. --
    PAIR_TTL = 600  # unclaimed codes evaporate after 10 minutes

    @socketio.on("pair-create")
    def on_pair_create(data=None):
        sid = request.sid
        keyword = _norm_code((data or {}).get("keyword"))
        for _ in range(4):
            code = keyword or _mint_pair_code()
            if registry.pair_create(code, sid, ttl=PAIR_TTL):
                emit("pair-code", {"code": code, "ttl": PAIR_TTL})
                return
            if keyword:  # a chosen keyword that's in use is an error, not a retry
                emit("pair-error", {"error": "taken"})
                return
        emit("pair-error", {"error": "exhausted"})

    @socketio.on("pair-claim")
    def on_pair_claim(data=None):
        code = _norm_code((data or {}).get("code"))
        creator = registry.pair_claim(code) if code else None
        room = registry.room_of(creator) if creator else None
        if not room:
            emit("pair-error", {"error": "invalid"})
            return
        # Code BURNED (atomic claim). Pairing is ADDITIVE: the claimer joins the
        # creator's CURRENT room — the creator never moves, keeps seeing nearby
        # devices, and can mint another code to admit another person.
        emit("pair-used", {"code": code}, to=creator)  # clear the displayed code
        emit("pair-matched", {"room": room})  # claimer crosses over

    @socketio.on("signal")
    def on_signal(data):
        sid = request.sid
        to = (data or {}).get("to")
        payload = (data or {}).get("data")
        if not to or not registry.room_of(sid):
            return
        emit("signal", {"from": sid, "data": payload}, to=to)  # routes cross-instance

    @socketio.on("leave")
    def on_leave(_data=None):
        _do_leave(request.sid)

    @socketio.on("disconnect")
    def on_disconnect():
        _do_leave(request.sid)

    def _do_leave(sid):
        local_sids.discard(sid)
        room = registry.remove(sid)
        if not room:
            return
        leave_room(room)
        emit("peer-left", {"id": sid}, room=room, include_self=False)
