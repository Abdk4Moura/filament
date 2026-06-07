"""C30 convergent-session tests for the `sync` event.

`sync` is the one idempotent, full-state, ack'd round-trip that ensures a
sid's room membership + channel subscriptions + liveness lease. The whole
point of C30 is that no single emit is load-bearing — only convergence is —
so the properties guarded here are exactly the convergence properties:

  1. a valid sync acks the server's resulting beliefs in the agreed shape
  2. it is IDEMPOTENT: a second identical sync produces the same ack and NO
     duplicate announcements (no second peer-joined to the room)
  3. channels union across calls (idempotent add), count reflects accepted
  4. it ensures membership when the room changes, refreshes (silently) when not
  5. malformed/missing input is rejected without throwing

These run on a real Socket.IO test client (as ClaimRateLimit in
test_pair_codes.py does) so the emit/ack behavior is exercised end to end,
plus registry-level checks for the union/room_of primitives.

Run:  python -m unittest backend.tests.test_sync
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402

# A valid channel id is 64 lowercase hex chars (sha256 of an E2E secret).
C1 = "a" * 64
C2 = "b" * 64
BAD = "not-hex"


def _make():
    """A fresh app + socketio + Mem registry + drained test client."""
    from flask import Flask
    from flask_socketio import SocketIO

    app = Flask(__name__)
    sio = SocketIO(app, async_mode="threading")
    signaling.register(sio, signaling._MemRegistry())
    client = sio.test_client(app)
    client.get_received()  # drain the connect event
    return app, sio, client


def _ack(client, payload):
    """Emit sync with an ack callback and return the ack dict."""
    return client.emit("sync", payload, callback=True)


def _names(received):
    return [ev["name"] for ev in received]


class SyncAckShape(unittest.TestCase):
    def test_valid_sync_ack(self):
        _app, _sio, c = _make()
        ack = _ack(c, {"v": 1, "room": "r1", "name": "alice", "uid": "u1", "channels": [C1]})
        self.assertEqual(ack, {"v": 1, "ok": True, "room": "r1", "channels": 1,
                               "lease": True, "peers": []})

    def test_missing_room_rejected(self):
        _app, _sio, c = _make()
        ack = _ack(c, {"v": 1, "name": "alice"})
        self.assertEqual(ack, {"v": 1, "ok": False, "room": None, "channels": 0, "lease": False})

    def test_none_and_empty_payload_do_not_throw(self):
        _app, _sio, c = _make()
        self.assertFalse(_ack(c, None)["ok"])
        self.assertFalse(_ack(c, {})["ok"])

    def test_bad_channels_dropped_from_count(self):
        _app, _sio, c = _make()
        ack = _ack(c, {"room": "r1", "channels": [C1, BAD, 123, None, C2]})
        self.assertEqual(ack["channels"], 2)  # only the two valid hex ids count


class SyncIdempotent(unittest.TestCase):
    def test_identical_sync_same_ack_no_dup_announce(self):
        """Calling sync twice with identical payload yields the identical ack
        and emits NO duplicate peer-joined (the room did not change)."""
        _app, _sio, c = _make()
        payload = {"v": 1, "room": "r1", "name": "alice", "uid": "u1", "channels": [C1]}

        ack1 = _ack(c, payload)
        c.get_received()  # drain whatever the first sync produced
        ack2 = _ack(c, payload)
        self.assertEqual(ack1, ack2, "second identical sync must ack identically")

        # The second call changed nothing: no peer-joined (single client also
        # means no known-peer, the channel had no other member).
        self.assertNotIn("peer-joined", _names(c.get_received()))

    def test_resync_does_not_reannounce_to_room_peer(self):
        """A second sync from A must not deliver a fresh peer-joined for A to a
        peer B already in the room — membership is level-triggered, not edged."""
        app, sio, a = _make()
        b = sio.test_client(app)
        b.get_received()

        _ack(a, {"room": "r1", "name": "alice", "uid": "ua"})
        # B joins; drain both so we start from a clean slate.
        _ack(b, {"room": "r1", "name": "bob", "uid": "ub"})
        a.get_received()
        b.get_received()

        _ack(a, {"room": "r1", "name": "alice", "uid": "ua"})  # idempotent re-sync
        self.assertNotIn("peer-joined", _names(b.get_received()),
                         "re-syncing the same room must not re-announce A to B")


class SyncMembership(unittest.TestCase):
    def test_first_sync_announces(self):
        app, sio, a = _make()
        b = sio.test_client(app)
        b.get_received()
        _ack(b, {"room": "r1", "name": "bob", "uid": "ub"})
        b.get_received()

        ack = _ack(a, {"room": "r1", "name": "alice", "uid": "ua"})
        self.assertEqual(ack["room"], "r1")
        # The room learns A arrived; A learns B is already present via welcome.
        self.assertIn("peer-joined", _names(b.get_received()))
        self.assertIn("welcome", _names(a.get_received()))

    def test_room_change_reannounces(self):
        _app, _sio, c = _make()
        ack1 = _ack(c, {"room": "r1", "name": "alice"})
        c.get_received()
        ack2 = _ack(c, {"room": "r2", "name": "alice"})
        self.assertEqual(ack2["room"], "r2")
        self.assertNotEqual(ack1["room"], ack2["room"])
        # Moving rooms is a real join: A is announced in r2.
        self.assertIn("welcome", _names(c.get_received()))


class SyncChannelUnion(unittest.TestCase):
    def test_channels_union_across_calls(self):
        """sync [c1] then [c1,c2] -> the sid's subscription is the UNION, and
        each ack reports the count accepted on that call."""
        _app, _sio, c = _make()
        ack1 = _ack(c, {"room": "r1", "channels": [C1]})
        self.assertEqual(ack1["channels"], 1)
        ack2 = _ack(c, {"room": "r1", "channels": [C1, C2]})
        self.assertEqual(ack2["channels"], 2)

    def test_known_peer_emitted_to_channel_member(self):
        """Two sids in the same channel are told about each other."""
        app, sio, a = _make()
        b = sio.test_client(app)
        b.get_received()

        _ack(a, {"room": "r1", "name": "alice", "uid": "ua", "channels": [C1]})
        a.get_received()
        _ack(b, {"room": "r2", "name": "bob", "uid": "ub", "channels": [C1]})
        # B subscribing to C1 (where A already is) tells B about A, and A about B.
        self.assertIn("known-peer", _names(b.get_received()))
        self.assertIn("known-peer", _names(a.get_received()))


class SyncRoster(unittest.TestCase):
    """C30 phase 2: the digest GROWS a `peers` field — everyone in the
    caller's room (welcome-shaped {id,name,uid}, self excluded), capped at 32,
    deterministically ordered so repeated syncs are byte-identical."""

    def test_empty_room_yields_empty_peers(self):
        """A lone sid's digest lists no peers."""
        _app, _sio, c = _make()
        ack = _ack(c, {"room": "r1", "name": "alice", "uid": "ua"})
        self.assertEqual(ack["peers"], [])

    def test_digest_includes_co_roomed_peer(self):
        """A digest carries a co-roomed peer with id/name/uid, welcome-shaped."""
        app, sio, a = _make()
        b = sio.test_client(app)
        b.get_received()

        # B syncs in first so it is present when A syncs.
        _ack(b, {"room": "r1", "name": "bob", "uid": "ub"})
        b.get_received()
        ack = _ack(a, {"room": "r1", "name": "alice", "uid": "ua"})

        self.assertEqual(len(ack["peers"]), 1)
        peer = ack["peers"][0]
        self.assertEqual(peer["name"], "bob")
        self.assertEqual(peer["uid"], "ub")
        self.assertIn("id", peer)
        # welcome-shaped: exactly id/name/uid, nothing else.
        self.assertEqual(set(peer), {"id", "name", "uid"})

    def test_digest_excludes_self(self):
        """The caller never appears in its own roster."""
        app, sio, a = _make()
        b = sio.test_client(app)
        b.get_received()
        _ack(b, {"room": "r1", "name": "bob", "uid": "ua-other"})
        ack_a = _ack(a, {"room": "r1", "name": "alice", "uid": "ua"})

        # A's own name/uid must never appear in A's roster — only B does.
        self.assertEqual({p["name"] for p in ack_a["peers"]}, {"bob"})
        self.assertNotIn("ua", {p["uid"] for p in ack_a["peers"]})

    def test_peers_identical_across_repeated_syncs(self):
        """An unchanged room yields a byte-identical `peers` list every sync —
        with TWO peers, this also proves the order is stably sorted."""
        app, sio, a = _make()
        b = sio.test_client(app)
        c = sio.test_client(app)
        b.get_received()
        c.get_received()

        _ack(b, {"room": "r1", "name": "bob", "uid": "ub"})
        _ack(c, {"room": "r1", "name": "carol", "uid": "uc"})

        ack1 = _ack(a, {"room": "r1", "name": "alice", "uid": "ua"})
        a.get_received()
        ack2 = _ack(a, {"room": "r1", "name": "alice", "uid": "ua"})

        self.assertEqual(len(ack1["peers"]), 2)
        self.assertEqual(ack1["peers"], ack2["peers"],
                         "repeated sync of an unchanged room must be byte-identical")
        # Explicitly sorted by sid (deterministic cap).
        ids = [p["id"] for p in ack1["peers"]]
        self.assertEqual(ids, sorted(ids))


class RegistryLevelConvergence(unittest.TestCase):
    """The primitives sync relies on, exercised directly (mirrors the
    NormalizationAndBurn registry-level style in test_pair_codes.py)."""

    def test_subscribe_is_union_and_idempotent(self):
        reg = signaling._MemRegistry()
        reg.subscribe("sid-a", [C1])
        reg.subscribe("sid-a", [C1, C2])  # union; C1 re-added is a no-op
        self.assertEqual(reg._sidchan["sid-a"], {C1, C2})

    def test_room_of_after_readd_reflects_latest_room(self):
        reg = signaling._MemRegistry()
        reg.add("sid-a", "r1", "alice", "ua")
        self.assertEqual(reg.room_of("sid-a"), "r1")
        reg.add("sid-a", "r2", "alice", "ua")  # what a room-changing sync does
        self.assertEqual(reg.room_of("sid-a"), "r2")

    def test_subscribe_returns_existing_members(self):
        reg = signaling._MemRegistry()
        reg.subscribe("sid-a", [C1])
        out = reg.subscribe("sid-b", [C1])
        self.assertEqual(out[C1], ["sid-a"], "second subscriber sees the first")


if __name__ == "__main__":
    unittest.main()
