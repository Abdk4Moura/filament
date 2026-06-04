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
from flask import request
from flask_socketio import emit, join_room, leave_room


class _MemRegistry:
    """Process-local membership (single instance)."""

    def __init__(self):
        self._m = {}  # sid -> {"room", "name"}

    def add(self, sid, room, name):
        self._m[sid] = {"room": room, "name": name}

    def room_of(self, sid):
        m = self._m.get(sid)
        return m["room"] if m else None

    def remove(self, sid):
        m = self._m.pop(sid, None)
        return m["room"] if m else None

    def peers_in(self, room, exclude=None):
        return [
            {"id": s, "name": v["name"]}
            for s, v in self._m.items()
            if v["room"] == room and s != exclude
        ]


class _RedisRegistry:
    """Shared membership in Redis so api replicas see one another's peers."""

    TTL = 86400  # self-heal: stale entries from unclean shutdowns expire

    def __init__(self, url):
        import redis  # lazy: only needed when scaling with Redis

        self.r = redis.Redis.from_url(url, decode_responses=True)

    def _rk(self, room):
        return f"filament:room:{room}"

    def _sk(self, sid):
        return f"filament:sid:{sid}"

    def add(self, sid, room, name):
        p = self.r.pipeline()
        p.hset(self._rk(room), sid, name)
        p.expire(self._rk(room), self.TTL)
        p.set(self._sk(sid), room, ex=self.TTL)
        p.execute()

    def room_of(self, sid):
        return self.r.get(self._sk(sid))

    def remove(self, sid):
        room = self.r.get(self._sk(sid))
        if room:
            p = self.r.pipeline()
            p.hdel(self._rk(room), sid)
            p.delete(self._sk(sid))
            p.execute()
        return room

    def peers_in(self, room, exclude=None):
        return [
            {"id": s, "name": n}
            for s, n in self.r.hgetall(self._rk(room)).items()
            if s != exclude
        ]


def make_registry(redis_url):
    return _RedisRegistry(redis_url) if redis_url else _MemRegistry()


def register(socketio, registry):
    @socketio.on("join")
    def on_join(data):
        sid = request.sid
        room = (data or {}).get("room")
        name = (data or {}).get("name") or "anonymous"
        if not room:
            return
        _do_leave(sid)  # if this socket was already in a room, clean it first

        join_room(room)
        registry.add(sid, room, name)

        # Tell the joiner who's already here (they initiate offers); tell the
        # room someone arrived. With the Redis message queue these reach peers
        # on every instance.
        emit("welcome", {"id": sid, "peers": registry.peers_in(room, exclude=sid)})
        emit("peer-joined", {"id": sid, "name": name}, room=room, include_self=False)

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
        room = registry.remove(sid)
        if not room:
            return
        leave_room(room)
        emit("peer-left", {"id": sid}, room=room, include_self=False)
