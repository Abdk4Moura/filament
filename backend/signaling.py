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
import os
import re
import secrets as _secrets
import time as _time
from collections import defaultdict, deque

from flask import request
from flask_socketio import emit, join_room, leave_room

# Speakable one-time codes: easy to say across a table, unique by NX semantics.
#
# Entropy budget (see the variance analysis repo): 64 adjectives x 64 animals
# x 900 numbers = 3,686,400 codes (~21.8 bits). Combined with the claim rate
# limit below, sweeping the space inside a code's 10-minute TTL is infeasible;
# the 10x10x90 = 9,000-code (~13.1 bit) original was not. Words are chosen to
# be short, common, and phonetically distinct so codes stay easy to SAY.
# Keep these lists in sync with frontend/src/lib/useFilament.js (peer names
# draw from the same vocabulary).
_ADJ = [
    "amber", "bold", "brave", "brisk", "calm", "cheery", "chill", "civil",
    "clever", "cosy", "crisp", "daring", "deft", "dewy", "eager", "early",
    "fancy", "fiery", "fleet", "fond", "frank", "free", "fresh", "gentle",
    "giddy", "glad", "golden", "grand", "happy", "hardy", "hasty", "honest",
    "humble", "jolly", "keen", "kind", "lively", "loyal", "lucky", "lunar",
    "mellow", "merry", "mighty", "misty", "neat", "noble", "perky", "plucky",
    "polar", "proud", "quick", "quiet", "rapid", "rosy", "royal", "shiny",
    "snappy", "solid", "spry", "stout", "sunny", "swift", "tidy", "witty",
]
_ANIMAL = [
    "otter", "panda", "falcon", "lynx", "koala", "heron", "fox", "ibex",
    "marten", "tapir", "badger", "beaver", "bison", "bongo", "camel", "civet",
    "condor", "crane", "dingo", "dove", "eland", "ermine", "ferret", "finch",
    "gecko", "gibbon", "hare", "hawk", "hyrax", "jackal", "kestrel", "kiwi",
    "lemur", "llama", "macaw", "magpie", "mole", "moose", "murre", "newt",
    "ocelot", "okapi", "oriole", "osprey", "owl", "pika", "plover", "puffin",
    "quokka", "rabbit", "raven", "robin", "seal", "shrew", "skink", "sparrow",
    "stoat", "swan", "tern", "toucan", "vole", "wombat", "wren", "zebra",
]
assert len(_ADJ) == 64 and len(set(_ADJ)) == 64, "adjective list must be 64 unique words"
assert len(_ANIMAL) == 64 and len(set(_ANIMAL)) == 64, "animal list must be 64 unique words"


def _mint_pair_code():
    """CSPRNG-minted speakable code: adj-animal-NNN, ~21.8 bits."""
    return f"{_secrets.choice(_ADJ)}-{_secrets.choice(_ANIMAL)}-{_secrets.randbelow(900) + 100}"


def _norm_code(raw):
    """Normalize a spoken keyword: lowercase, spaces→dashes, strip noise."""
    if not isinstance(raw, str):
        return ""
    return re.sub(r"[^a-z0-9-]", "", re.sub(r"\s+", "-", raw.strip().lower()))[:48]


class _MemRegistry:
    """Process-local membership (single instance).

    Liveness (#10, dev parity): same lease idea as _RedisRegistry, backed by a
    dict of monotonic expiries. Without it the in-proc backend advertised
    SIGKILL'd sids (ghosts) until the engine.io ping timeout fired disconnect.
    """

    LIVE_TTL = 60  # liveness lease; refreshed by the lease loop + on activity

    def __init__(self):
        self._m = {}  # sid -> {"room", "name", "uid"}
        self._live = {}  # sid -> lease expiry (monotonic)

    def refresh(self, sids):
        """Extend the liveness lease for connected sids."""
        exp = _time.monotonic() + self.LIVE_TTL
        for sid in sids:
            self._live[sid] = exp

    def _alive(self, sid):
        return self._live.get(sid, 0) > _time.monotonic()

    def add(self, sid, room, name, uid=None):
        self._m[sid] = {"room": room, "name": name, "uid": uid}
        self.refresh([sid])

    def room_of(self, sid):
        m = self._m.get(sid)
        return m["room"] if m else None

    def remove(self, sid):
        self._live.pop(sid, None)
        m = self._m.pop(sid, None)
        return m["room"] if m else None

    def peers_in(self, room, exclude=None):
        return [
            {"id": s, "name": v["name"], "uid": v.get("uid")}
            for s, v in self._m.items()
            if v["room"] == room and s != exclude and self._alive(s)
        ]

    def meta(self, sid):
        m = self._m.get(sid)
        return {"id": sid, "name": m["name"], "uid": m.get("uid")} if m else None

    # -- persistent-pair presence channels (C12): a channel id is a hash of an
    # E2E-shared secret; two sids in the same channel are mutually-trusted
    # devices and get told about each other regardless of room.
    def subscribe(self, sid, channels):
        chans = getattr(self, "_chan", None)
        if chans is None:
            chans = self._chan = {}
        bysid = getattr(self, "_sidchan", None)
        if bysid is None:
            bysid = self._sidchan = {}
        bysid.setdefault(sid, set()).update(channels)
        out = {}
        for ch in channels:
            members = chans.setdefault(ch, set())
            # lease-filter (#10) + lazy cleanup: dead sids vanish on first look
            members -= {s for s in members if s != sid and not self._alive(s)}
            out[ch] = [s for s in members if s != sid]
            members.add(sid)
        return out  # channel -> other live sids already present

    def unsubscribe_all(self, sid):
        affected = {}
        for ch in getattr(self, "_sidchan", {}).pop(sid, set()):
            members = getattr(self, "_chan", {}).get(ch, set())
            members.discard(sid)
            others = [s for s in members if self._alive(s)]
            if others:
                affected[ch] = others
        return affected  # channel -> remaining sids to notify

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

    def peek_pair(self, code):
        """Telemetry only: (exists, creator, creator_alive) without consuming."""
        creator = getattr(self, "_pairs", {}).get(code)
        return (creator is not None, creator, creator in self._m)


class _RedisRegistry:
    """Shared membership in Redis so api replicas see one another's peers.

    Liveness (#10): membership alone can't be trusted — an api restart kills
    sockets without running disconnect handlers, orphaning entries that then
    appear in every `welcome` as zombie peers. So every connection also holds a
    short LEASE, refreshed by its owning instance; `peers_in` only returns
    leased entries and lazily deletes the dead ones.
    """

    TTL = 86400  # room/sid bookkeeping
    LIVE_TTL = 120  # liveness lease; refreshed every ~15s while connected

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

    def meta(self, sid):
        import json

        room = self.r.get(self._sk(sid))
        if not room:
            return None
        raw = self.r.hget(self._rk(room), sid)
        try:
            v = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            v = {"name": raw}
        return {"id": sid, "name": v.get("name"), "uid": v.get("uid")}

    def _ck(self, channel):
        return f"filament:chan:{channel}"

    def _sck(self, sid):
        return f"filament:sidchan:{sid}"

    def subscribe(self, sid, channels):
        out = {}
        p = self.r.pipeline()
        for ch in channels:
            p.smembers(self._ck(ch))
        existing = p.execute()
        p = self.r.pipeline()
        for ch, members in zip(channels, existing):
            # lease-filter (#10): only live sids count
            live = [s for s in members if s != sid and self.r.exists(self._lk(s))]
            out[ch] = live
            p.sadd(self._ck(ch), sid)
            p.expire(self._ck(ch), self.TTL)
            p.sadd(self._sck(sid), ch)
            p.expire(self._sck(sid), self.TTL)
        p.execute()
        return out

    def unsubscribe_all(self, sid):
        affected = {}
        for ch in self.r.smembers(self._sck(sid)):
            self.r.srem(self._ck(ch), sid)
            others = [s for s in self.r.smembers(self._ck(ch)) if self.r.exists(self._lk(s))]
            if others:
                affected[ch] = others
        self.r.delete(self._sck(sid))
        return affected

    # -- one-time pairing codes (#11): SET NX EX to create, GETDEL to consume
    # atomically — a code can be claimed exactly once, ever.
    def pair_create(self, code, sid, ttl=600):
        return bool(self.r.set(f"filament:pair:{code}", sid, nx=True, ex=ttl))

    def peek_pair(self, code):
        """Telemetry only: (exists, creator, creator_alive) without consuming."""
        creator = self.r.get(f"filament:pair:{code}")
        return (creator is not None, creator, bool(creator and self.r.exists(self._lk(creator))))

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


def _tel(event, **kv):
    """Debugger-grade telemetry (C24): one JSON line per lifecycle event,
    prefixed TEL, to stdout -> docker logs. No file contents, no file names."""
    import json as _json
    import sys as _sys
    import time as _t

    try:
        print("TEL " + _json.dumps({"ts": round(_t.time(), 3), "ev": event, **kv}, separators=(",", ":")), flush=True)
    except Exception:
        _sys.stderr.write("TEL-fail\n")


def register(socketio, registry):
    local_sids = set()  # connections owned by THIS instance (for lease refresh)

    def _eio_alive(sid):
        """Ground truth for sids THIS instance owns: is the underlying
        engine.io socket still open? Catches a SIGKILL'd client the moment the
        transport sees FIN/RST — long before any lease lapses or the ping
        timeout fires."""
        try:
            eio_sid = socketio.server.manager.eio_sid_from_sid(sid, "/")
            sock = socketio.server.eio.sockets.get(eio_sid)
            return sock is not None and not sock.closed
        except Exception:
            return True  # never let introspection failure hide live peers

    def _sid_alive(sid):
        """Roster/known-peer gate (#10): a locally-owned sid must have a live
        socket; a remote sid (another instance) is vouched for by the lease the
        registry already filters on."""
        return sid not in local_sids or _eio_alive(sid)

    @socketio.on("connect")
    def on_connect():
        local_sids.add(request.sid)
        registry.refresh([request.sid])  # liveness lease from the first moment
        _tel("connect", sid=request.sid)

    def _lease_loop():
        # Refresh every 15s (TTL is 60s mem / 120s Redis) but ONLY for sids
        # whose engine.io socket is still open — a dead-but-undetected socket
        # stops being refreshed, so its lease lapses and every roster filter
        # stops advertising it even before disconnect fires.
        while True:
            socketio.sleep(15)
            try:
                registry.refresh([s for s in list(local_sids) if _eio_alive(s)])
            except Exception:
                pass

    socketio.start_background_task(_lease_loop)

    def _do_join(sid, room, name, uid):
        """The room-join effect: leave any prior room, join the new one, and
        announce in both directions. Factored so `sync` can reuse the EXACT
        same flow when (and only when) a sid's room actually changes."""
        _do_leave(sid)  # if this socket was already in a room, clean it first

        join_room(room)
        registry.add(sid, room, name, uid)
        peers = [p for p in registry.peers_in(room, exclude=sid) if _sid_alive(p["id"])]
        _tel("join", sid=sid, uid=uid, room=room, peers=len(peers))

        # Tell the joiner who's already here (they initiate offers); tell the
        # room someone arrived. With the Redis message queue these reach peers
        # on every instance.
        emit("welcome", {"id": sid, "peers": peers})
        emit("peer-joined", {"id": sid, "name": name, "uid": uid}, room=room, include_self=False)

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
        _do_join(sid, room, name, uid)

    # -- one-time pairing (#11): say the code aloud; it works exactly once. --
    PAIR_TTL = 600  # unclaimed codes evaporate after 10 minutes

    # L1-a (PAKE v2): a v:2 client mints the WORDS locally and asks the server
    # to allocate only the NAMEPLATE (the numeric routing suffix). The server
    # NEVER sees or generates the words — the entire MITM-resistance claim rests
    # on this (spec §2.0). A v2 nameplate is validated to be purely numeric so a
    # client can never smuggle words into it; the server stores ONLY that
    # nameplate and never echoes any code back (the creator displays its own
    # locally-assembled `words-nameplate`).
    _NAMEPLATE_RE = re.compile(r"^[0-9]{3,5}$")

    @socketio.on("pair-create")
    def on_pair_create(data=None):
        sid = request.sid
        # C24: this event proves the creator's socket is alive RIGHT NOW —
        # refresh its liveness lease so a code can never be minted by a
        # creator the claim-side lease check would call dead (the zombie-tab
        # failure observed live).
        if hasattr(registry, "refresh"):
            registry.refresh([sid])
        data = data or {}
        # GATE 6 fixture hook (downgrade-refused): FIL_FORCE_V1 makes the server
        # behave like a malicious/legacy relay that STRIPS the v:2 flag — it
        # ignores `v` and falls into the v1 word-minting branch. A v2 client must
        # REFUSE this (it gets a legacy `pair-code` instead of `pair-ok` and
        # aborts with "update to pair securely"). Pinned like FIL_CLAIM_LIMIT so
        # prod is untouched.
        force_v1 = os.environ.get("FIL_FORCE_V1") == "1"
        # --- v2 path: nameplate-only allocation, no words ever cross the wire.
        if data.get("v") == 2 and not force_v1:
            nameplate = _norm_code(data.get("nameplate"))
            if not _NAMEPLATE_RE.match(nameplate):
                # Defense-in-depth: reject anything that isn't a bare number so
                # a buggy/malicious v2 client can't park words server-side.
                emit("pair-error", {"error": "bad-nameplate"})
                return
            if registry.pair_create(nameplate, sid, ttl=PAIR_TTL):
                # NO words echoed; the creator shows its OWN minted full code.
                _tel("pair-create", sid=sid, nameplate=nameplate, v=2,
                     in_room=bool(registry.room_of(sid)), leased=registry.meta(sid) is not None)
                emit("pair-ok", {"nameplate": nameplate, "ttl": PAIR_TTL, "v": 2})
                return
            # Collision: the client re-mints a fresh nameplate and retries.
            emit("pair-error", {"error": "taken"})
            return
        # --- v1 path (unchanged): server mints the whole adj-animal-NNN code.
        keyword = _norm_code(data.get("keyword"))
        for _ in range(4):
            code = keyword or _mint_pair_code()
            if registry.pair_create(code, sid, ttl=PAIR_TTL):
                _tel("pair-create", sid=sid, code=code,
                     in_room=bool(registry.room_of(sid)), leased=registry.meta(sid) is not None)
                emit("pair-code", {"code": code, "ttl": PAIR_TTL})
                return
            if keyword:  # a chosen keyword that's in use is an error, not a retry
                emit("pair-error", {"error": "taken"})
                return
        emit("pair-error", {"error": "exhausted"})

    # Claim rate limit: 21.8 bits of code entropy only holds if nobody can
    # sweep the space. 5 attempts/min per connection (and per client IP, so
    # reconnecting doesn't reset it) makes an exhaustive sweep of 3.7M codes
    # take years instead of the minutes the unthrottled 9,000-code space took.
    # FIL_CLAIM_LIMIT overrides it: the gate fixture sets it sky-high so the
    # suite's many rapid claims never collide (the limit is a prod security
    # control, irrelevant to a local single-tester fixture — pinning it makes
    # the claim path DETERMINISTIC instead of timing-window-dependent).
    CLAIM_LIMIT = int(os.environ.get("FIL_CLAIM_LIMIT", "5"))
    CLAIM_WINDOW = 60.0
    _claim_log = defaultdict(deque)  # key -> recent claim timestamps

    def _claim_allowed(sid):
        ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or "?"
        now = _time.monotonic()
        for key in (f"sid:{sid}", f"ip:{ip}"):
            q = _claim_log[key]
            while q and now - q[0] > CLAIM_WINDOW:
                q.popleft()
            if len(q) >= CLAIM_LIMIT:
                return False
        for key in (f"sid:{sid}", f"ip:{ip}"):
            _claim_log[key].append(now)
        return True

    @socketio.on("pair-claim")
    def on_pair_claim(data=None):
        if not _claim_allowed(request.sid):
            emit("pair-error", {"error": "slow-down"})
            return
        data = data or {}
        # L1-a (PAKE v2): a v:2 claimer sends ONLY the nameplate — the password
        # (words) NEVER reaches the server (relay-blind, gate 2). The full typed
        # code is split CLIENT-SIDE; only the numeric nameplate is the rendezvous
        # selector here. For v1 clients the whole `code` is still the selector.
        if data.get("v") == 2:
            code = _norm_code(data.get("nameplate"))
            if not _NAMEPLATE_RE.match(code):
                emit("pair-error", {"error": "invalid", "why": "bad-nameplate"})
                return
        else:
            code = _norm_code(data.get("code"))
        existed, peek_creator, creator_alive = registry.peek_pair(code) if code else (False, None, False)
        creator = registry.pair_claim(code) if code else None
        room = registry.room_of(creator) if creator else None
        if not room:
            # The smoking-gun cases, now distinguishable: code never existed /
            # expired, vs creator known but its liveness lease lapsed (zombie
            # phone tab), vs creator alive but roomless.
            _tel("pair-claim-fail", sid=request.sid, code=code, existed=existed,
                 creator=peek_creator, creator_alive=creator_alive)
            # Tell the claimer WHICH failure this was (additive field — old
            # clients ignore it): a code whose creator is gone reads very
            # differently from a typo'd/expired one.
            why = "sender-gone" if existed and peek_creator else "unknown"
            emit("pair-error", {"error": "invalid", "why": why})
            return
        _tel("pair-claim-ok", sid=request.sid, code=code, creator=creator, room=room)
        # Code BURNED (atomic claim). Pairing is ADDITIVE: the claimer joins the
        # creator's CURRENT room — the creator never moves, keeps seeing nearby
        # devices, and can mint another code to admit another person.
        emit("pair-used", {"code": code}, to=creator)  # clear the displayed code
        emit("pair-matched", {"room": room})  # claimer crosses over

    # -- persistent-pair presence (C12). The client subscribes with channel
    # ids derived from E2E-shared pair secrets (sha256, hex). The server never
    # sees a secret — only meeting points. Mutual presence is symmetric:
    # both sides get `known-peer`. Trust is NOT asserted here; clients verify
    # each other with an HMAC proof over the secret after connecting.
    CHAN_RE = re.compile(r"^[0-9a-f]{64}$")
    MAX_CHANNELS = 64

    def _do_subscribe(sid, raw_channels):
        """Validate + apply a channel subscription (union, idempotent) and emit
        the symmetric known-peer pairs. Returns the count of accepted channels.
        Factored so both `subscribe` and `sync` share one code path — no
        duplicated validation, no duplicated emission loop."""
        chans = [c for c in (raw_channels or [])[:MAX_CHANNELS]
                 if isinstance(c, str) and CHAN_RE.match(c)]
        if not chans:
            return 0, []
        me = registry.meta(sid)
        roster = []  # live existing members on these channels — returned in the
        # ack so the subscriber discovers DETERMINISTICALLY, not dependent on the
        # async known-peer push landing (which is unreliable across prod workers).
        for ch, others in registry.subscribe(sid, chans).items():
            for other in others:
                if not _sid_alive(other):  # never advertise a dead sid (#10)
                    continue
                om = registry.meta(other)
                if om:
                    emit("known-peer", {**om, "channel": ch})
                    roster.append({**om, "channel": ch})
                if me:
                    emit("known-peer", {**me, "channel": ch}, to=other)
        return len(chans), roster

    @socketio.on("subscribe")
    def on_subscribe(data=None):
        registry.refresh([request.sid])  # any inbound event proves liveness
        n, roster = _do_subscribe(request.sid, (data or {}).get("channels"))
        # C28: the return value is the socket.io ACK — subscribers VERIFY the
        # emit landed instead of assuming (a subscribe that dies in a half-open
        # socket left devices mutually invisible until a page reload). `peers`
        # carries the live channel roster so discovery is deterministic.
        return {"ok": bool(n), "n": n, "peers": roster}

    # -- C30 convergent session: ONE idempotent, full-state event that ensures
    # membership + subscriptions + lease in a single ack'd round-trip. No emit
    # is load-bearing; only convergence is. The old join/subscribe events
    # remain for compat — new clients drive session state through `sync` alone.
    @socketio.on("sync")
    def on_sync(data=None):
        sid = request.sid
        data = data or {}
        room = data.get("room")
        name = data.get("name") or "anonymous"
        uid = data.get("uid")
        if not room:
            return {"v": 1, "ok": False, "room": None, "channels": 0, "lease": False}

        # Membership: re-announce ONLY when the room actually changes for this
        # sid (idempotent — a repeated sync to the same room is silent). When
        # the room is unchanged we deliberately do NOT re-add (a name/uid edit
        # without a room change is not re-broadcast); we only refresh the lease.
        room_changed = registry.room_of(sid) != room
        if room_changed:
            _do_join(sid, room, name, uid)
        elif hasattr(registry, "refresh"):
            registry.refresh([sid])  # lease refresh only (Redis); no emits

        # Subscriptions: union, idempotent, emits known-peer pairs as today AND
        # returns the live channel roster (deterministic discovery).
        n, chan_peers = _do_subscribe(sid, data.get("channels"))

        _tel("sync", sid=sid, room_changed=room_changed, channels=n)
        # Roster (C30 phase 2): the digest carries everyone the server holds in
        # the caller's room (welcome-shaped, self excluded). registry.peers_in
        # lease-filters; _sid_alive additionally drops locally-owned sids whose
        # socket just died (#10). Sort by sid THEN cap at 32 so an unchanged
        # room yields a byte-identical digest across repeated syncs (the
        # client's idempotency/reconciliation depends on it).
        peers = sorted((p for p in registry.peers_in(room, exclude=sid)
                        if _sid_alive(p["id"])), key=lambda p: p["id"])[:32]
        # Ack carries the server's resulting beliefs for this sid; the client
        # compares (digest) instead of assuming any single emit landed.
        digest = {"v": 1, "ok": True, "room": room, "channels": n, "lease": True,
                  "peers": peers, "channel_peers": chan_peers}
        # Also emit the digest as a plain event: the Rust client consumes
        # events through one channel (Ev enum) and skips ack plumbing.
        emit("synced", digest)
        return digest

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
        _tel("disconnect", sid=request.sid)
        _do_leave(request.sid)

    def _channel_goodbye(sid):
        for ch, others in registry.unsubscribe_all(sid).items():
            for other in others:
                emit("known-peer-left", {"id": sid, "channel": ch}, to=other)

    def _do_leave(sid):
        _channel_goodbye(sid)
        local_sids.discard(sid)
        room = registry.remove(sid)
        if not room:
            return
        leave_room(room)
        emit("peer-left", {"id": sid}, room=room, include_self=False)
