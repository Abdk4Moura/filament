#!/usr/bin/env python3
"""Allowlist telemetry monitor — flags DIVERGENCE from the legal session
state machine (docs/observability-state-machine.md), not predefined bad
patterns. A denylist can only catch failures already seen; this catches the
absence case too (a ceremony that fails by *not happening*).

Reads `docker logs -f deploy-api-1` (or a file via --replay), maintains a
per-sid / per-pair / per-room state machine, and prints ONE line per
divergence — that line is what the Monitor tool streams as a notification.

  live:    docker logs -f deploy-api-1 2>&1 | scripts/tel-watch.py
  replay:  docker logs deploy-api-1 --since 30m 2>&1 | scripts/tel-watch.py --replay

A background reader thread parses lines into shared state; the main loop
sweeps every 2s for dwell-timeout divergences (the ones no single event can
express). Tunables are the budgets from the divergence table.
"""
import sys
import json
import time
import threading

# --- budgets (seconds) — the divergence table -------------------------------
JOIN_BUDGET = 12      # D1: connect -> join
PAIR_BUDGET = 30      # D2: pair-claim-ok -> terminal-good
ORPHAN_BUDGET = 15    # D3: one party gone, other lingers
CONNECTING_BUDGET = 25  # D4: web connecting -> ready|failed
ROOM_SOLO_BUDGET = 600  # D5: ceremony room held by 1
SYNC_GAP_BUDGET = 90    # D6: live sid sync heartbeat gap

REPLAY = "--replay" in sys.argv

# wall clock comes from the TEL line's own ts (so replay is faithful); we
# track the max ts seen as "now".
class Clock:
    now = 0.0
clock = Clock()

lock = threading.Lock()
# sid -> {connect, join, room, kind, last_sync, disconnected}
sids = {}
# code -> {creator, claimer, claimed_ts, resolved}
pairs = {}
# room -> set(sid)
rooms = {}
# web session s -> {peer -> {state, since}}
web_peers = {}
fired = set()  # de-dupe divergence keys

def emit(key, msg):
    if key in fired:
        return
    fired.add(key)
    print(f"DIVERGE {msg}", flush=True)

def kind_of(uid):
    if not uid:
        return "web?"
    for k in ("cli-s", "cli-r", "cli-p"):
        if uid.startswith(k):
            return k
    return "web"

def terminal_good_for(sid):
    """Did this sid reach a good terminal? Best-effort from server view:
    a clean disconnect AFTER its pair resolved, or it's a web peer that went
    ready (tracked separately). Server-only clients: resolved pair == good."""
    s = sids.get(sid, {})
    return s.get("good", False)

def handle(ev, o):
    sid = o.get("sid")
    ts = o.get("ts") or clock.now
    clock.now = max(clock.now, ts)

    if ev == "connect":
        sids[sid] = {"connect": ts, "room": None, "kind": "?", "last_sync": ts, "disconnected": False, "good": False}
    elif ev == "join":
        s = sids.setdefault(sid, {"connect": ts, "last_sync": ts, "disconnected": False, "good": False})
        old = s.get("room")
        room = o.get("room")
        s["join"] = ts
        s["room"] = room
        s["kind"] = kind_of(o.get("uid"))
        if old and old in rooms:
            rooms[old].discard(sid)
        rooms.setdefault(room, set()).add(sid)
    elif ev == "sync":
        s = sids.setdefault(sid, {"connect": ts, "disconnected": False, "good": False})
        s["last_sync"] = ts
    elif ev == "pair-create":
        pairs.setdefault(o.get("code"), {})["creator"] = sid
    elif ev == "pair-claim-ok":
        p = pairs.setdefault(o.get("code"), {})
        p["claimer"] = sid
        p["creator"] = o.get("creator", p.get("creator"))
        p["claimed_ts"] = ts
        p["resolved"] = False
    elif ev == "pair-claim-fail":
        emit(f"claimfail:{sid}:{ts}", f"D7 pair-claim-fail sid={sid[-6:]} code={o.get('code')} existed={o.get('existed')} creator_alive={o.get('creator_alive')}")
    elif ev == "disconnect":
        s = sids.get(sid)
        if s:
            s["disconnected"] = ts
            r = s.get("room")
            if r and r in rooms:
                rooms[r].discard(sid)
    # ---- web (per session s) ----
    elif ev == "web:peer-status":
        s = o.get("s")
        peer = o.get("peer")
        to = o.get("to")
        wp = web_peers.setdefault(s, {})
        wp[peer] = {"state": to, "since": ts}
        if to == "ready":
            wp[peer]["resolved"] = True
        if o.get("from") == "connecting" and to == "failed":
            emit(f"connfail:{s}:{peer}:{ts}", f"D7 web peer connecting->failed s={s} peer={peer} dwell={o.get('dwellMs')}ms")
    elif ev in ("web:proof-fail", "web:proof-rejected"):
        emit(f"{ev}:{o.get('s')}:{ts}", f"D7 {ev} s={o.get('s')} peer={o.get('peer')}")
    elif ev == "web:subscribe-retry":
        emit(f"subretry:{o.get('s')}:{ts}", f"D7 subscribe-retry (emit loss caught) s={o.get('s')} attempt={o.get('attempt')}")
    elif ev == "web:state-diverged":
        emit(f"statediv:{o.get('s')}:{o.get('peer')}:{ts}", f"D7 state-diverged kind={o.get('kind')} s={o.get('s')} peer={o.get('peer')}")

def sweep():
    """Dwell-timeout divergences — the absence cases no event can express."""
    now = clock.now
    for sid, s in list(sids.items()):
        if s.get("disconnected"):
            continue
        # D1: connected, never joined
        if "join" not in s and now - s.get("connect", now) > JOIN_BUDGET:
            emit(f"D1:{sid}", f"D1 connected {int(now-s['connect'])}s, never joined sid={sid[-6:]}")
        # D6: live sid, sync heartbeat gone silent
        if s.get("join") and now - s.get("last_sync", now) > SYNC_GAP_BUDGET:
            emit(f"D6:{sid}:{int(s['last_sync'])}", f"D6 sync silent {int(now-s['last_sync'])}s while live sid={sid[-6:]} room={str(s.get('room'))[:14]}")
    # D2/D3: claimed pairs that never completed
    for code, p in list(pairs.items()):
        if not p.get("claimed_ts") or p.get("resolved"):
            continue
        creator, claimer = p.get("creator"), p.get("claimer")
        age = now - p["claimed_ts"]
        cs, ms = sids.get(creator, {}), sids.get(claimer, {})
        # mark resolved if either reached good OR both disconnected close together
        if cs.get("good") or ms.get("good"):
            p["resolved"] = True
            continue
        cd, md = cs.get("disconnected"), ms.get("disconnected")
        if cd and md and abs(cd - md) < 5:
            p["resolved"] = True   # clean co-exit ~ ceremony ended together
            continue
        # D3: one gone, other lingering
        if cd and not md and now - cd > ORPHAN_BUDGET:
            emit(f"D3:{code}", f"D3 pair '{code}' creator gone, claimer orphaned {int(now-cd)}s (sid={str(claimer)[-6:]})")
            p["resolved"] = True
        elif md and not cd and now - md > ORPHAN_BUDGET:
            emit(f"D3:{code}", f"D3 pair '{code}' claimer gone, creator orphaned {int(now-md)}s (sid={str(creator)[-6:]})")
            p["resolved"] = True
        # D2: claimed, nobody progressed, nobody left — stuck
        elif age > PAIR_BUDGET and not cd and not md:
            emit(f"D2:{code}", f"D2 pair '{code}' claimed {int(age)}s ago, NO completion (creator={str(creator)[-6:]} claimer={str(claimer)[-6:]} — handshake never finished)")
            p["resolved"] = True
    # D5: ceremony room solo too long
    for room, members in list(rooms.items()):
        live = {m for m in members if not sids.get(m, {}).get("disconnected")}
        if len(live) == 1 and room.split("-")[0] in ("pairc", "up", "intro"):
            m = next(iter(live))
            since = sids.get(m, {}).get("join", now)
            if now - since > ROOM_SOLO_BUDGET:
                emit(f"D5:{room}", f"D5 {room[:18]} held solo {int((now-since)/60)}min sid={m[-6:]}")
    # D4: web connecting that never resolved
    for s, peers in web_peers.items():
        for peer, st in peers.items():
            if st.get("state") == "connecting" and not st.get("resolved") and now - st["since"] > CONNECTING_BUDGET:
                emit(f"D4:{s}:{peer}:{int(st['since'])}", f"D4 web peer stuck 'connecting' {int(now-st['since'])}s (neither ready nor failed) s={s} peer={peer}")
                st["resolved"] = True  # one-shot

def feed(line):
    line = line.strip()
    i = line.find("TEL ")
    if i < 0:
        return
    payload = line[i+4:]
    # a TEL line may carry multiple JSON objects newline-joined upstream; the
    # docker stream gives one per line, but be defensive.
    try:
        o = json.loads(payload)
    except Exception:
        return
    ev = o.get("ev")
    if ev:
        with lock:
            handle(ev, o)

def main():
    if REPLAY:
        for line in sys.stdin:
            feed(line)
        with lock:
            # sweep at the real end-of-window time — honest durations. A
            # divergence whose budget hadn't elapsed by window-end won't show
            # (that's faithful to "as of now"); live mode catches those later.
            sweep()
        return
    # live: reader thread + sweep loop
    def reader():
        for line in sys.stdin:
            feed(line)
    t = threading.Thread(target=reader, daemon=True)
    t.start()
    while True:
        time.sleep(2)
        # in live mode TEL ts are real epoch; keep clock at wall time so dwell
        # timeouts fire even when the stream goes quiet.
        with lock:
            clock.now = max(clock.now, time.time())
            sweep()

if __name__ == "__main__":
    main()
