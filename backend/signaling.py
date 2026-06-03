"""Socket.IO signaling relay.

This is a *dumb pipe*: it never sees file bytes. It only keeps track of who is
in which room and forwards opaque WebRTC signaling payloads (SDP offers/answers
and ICE candidates) between peers. Each connected browser is identified by its
socket id (``sid``).

Event contract (kept in sync with frontend/src/lib/CONTRACT.md):

  client -> server
    join   {room, name}      join/create a room
    signal {to, data}        relay `data` to the peer whose id == `to`
    leave  {}                leave the current room

  server -> client
    welcome    {id, peers:[{id,name}]}   sent to the joiner: own id + who's here
    peer-joined{id, name}                a new peer arrived
    peer-left  {id}                       a peer disconnected/left
    signal     {from, data}               a relayed payload from peer `from`
"""
from flask import request
from flask_socketio import emit, join_room, leave_room


def register(socketio):
    # sid -> {"room": str, "name": str}
    members = {}

    def _peers_in(room, exclude=None):
        return [
            {"id": sid, "name": m["name"]}
            for sid, m in members.items()
            if m["room"] == room and sid != exclude
        ]

    @socketio.on("join")
    def on_join(data):
        sid = request.sid
        room = (data or {}).get("room")
        name = (data or {}).get("name") or "anonymous"
        if not room:
            return
        # If this socket was already in a room, clean that up first.
        _do_leave(sid)

        join_room(room)
        members[sid] = {"room": room, "name": name}

        # Tell the joiner who is already here (they will initiate offers).
        emit("welcome", {"id": sid, "peers": _peers_in(room, exclude=sid)})
        # Tell everyone else someone arrived.
        emit("peer-joined", {"id": sid, "name": name}, room=room, include_self=False)

    @socketio.on("signal")
    def on_signal(data):
        sid = request.sid
        to = (data or {}).get("to")
        payload = (data or {}).get("data")
        if not to or sid not in members:
            return
        # Relay only to the intended peer.
        emit("signal", {"from": sid, "data": payload}, to=to)

    @socketio.on("leave")
    def on_leave(_data=None):
        _do_leave(request.sid)

    @socketio.on("disconnect")
    def on_disconnect():
        _do_leave(request.sid)

    def _do_leave(sid):
        member = members.pop(sid, None)
        if not member:
            return
        room = member["room"]
        leave_room(room)
        emit("peer-left", {"id": sid}, room=room, include_self=False)
