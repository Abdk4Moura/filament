# Eleven ways WebRTC file transfer fails (and the fixes)

*Draft for Abdk4Moura.github.io. House style: no em dashes. Suggested slug:
`webrtc-file-transfer-failures`. Publishing notes at the bottom.*

---

Last year I dug up an abandoned repo from 2024. It was a peer-to-peer file
sharing app I had built while teaching myself how Flask and React fit
together, and it had quietly rotted. I decided to revive it properly. The
result is [Filament](https://filament.autumated.com), which sends files
directly between two browsers over WebRTC: no upload, no account, no size
limit.

Here is the thing nobody tells you about WebRTC file transfer: the demo takes
a weekend. Two laptops on your desk, same WiFi, fresh tabs, and it works on
the first try. Then you hand it to a real person with a phone that sleeps,
WiFi that flickers, and a second tab they forgot about, and you discover that
the demo was the easy 20 percent.

This post is the other 80 percent. Eleven concrete failure modes I hit while
making Filament reliable, each with the symptom, the actual cause, and the
fix. If you are building anything on RTCPeerConnection and DataChannels, I
suspect you will meet most of these too. The full engineering log lives in
the repo as [docs/resilience.md](https://github.com/Abdk4Moura/filament/blob/main/docs/resilience.md).

## The shape of the system

Filament is three interacting state machines:

1. **Room and signaling.** A small Flask-SocketIO server tracks who is in a
   room and relays opaque WebRTC payloads between peers. It never sees file
   bytes.
2. **Per-peer negotiation.** Each pair of browsers runs the classic dance:
   offer, answer, ICE candidates, connected. Maybe disconnected. Maybe
   failed.
3. **Per-file transfer.** Offered, transferring, complete. Or declined. Or
   stuck, which is the interesting case.

Almost none of the flakiness lived inside any single machine. It lived in
the seams between them, and reconnection stresses every seam at once. Keep
that in mind as a theme: most of what follows is two state machines
disagreeing about what just happened.

## 1. Glare: both peers offer at once and stick at "connecting"

**Symptom.** Two devices sometimes never connect. Both tiles sit at
"connecting" forever, especially right after a reconnect.

**Cause.** My original design picked the offerer by join order: the newer
peer initiates. That rule only holds if the server processes joins one at a
time. On reconnect both peers come back together, each gets a roster that
already lists the other, and both decide they are the newer one. Both call
`createOffer`, each receives the other's offer while in `have-local-offer`,
and `setRemoteDescription` throws. The error was swallowed, so nothing
retried. It got worse when I added Redis for scaling, because the eventlet
worker yields at every Redis call and the join handler stopped being atomic.

**Fix.** Perfect negotiation with a deterministic role. One peer per pair is
"impolite" based on a stable identity comparison, and only the impolite peer
owns the offer. On a true collision the impolite peer ignores the incoming
offer and the polite peer rolls back. No reliance on message ordering, so no
race. This is the documented pattern on MDN and you should reach for it on
day one, not after your first glare bug.

## 2. Unserialized signals silently drop ICE candidates

**Symptom.** Intermittent connection failures, or pairs falling back to the
relay when a direct path clearly existed.

**Cause.** My signal handler called `applySignal(data)` for each relayed
message but never awaited it, so an offer and the candidates following it
ran concurrently. A candidate that reached `addIceCandidate` before
`setRemoteDescription` resolved threw "remote description is null" and was
silently dropped. Losing host candidates is how you end up paying for TURN
bandwidth on two machines that sit on the same switch.

**Fix.** Two layers. A per-peer FIFO queue, so each signal is fully applied
before the next one starts. Plus a candidate buffer: candidates that arrive
before any remote description is set get parked and flushed right after
`setRemoteDescription` resolves. Order of arrival stops mattering.

## 3. Ghost peer tiles that come back from the dead

**Symptom.** A peer leaves, their tile disappears, and then a dead
"connecting" tile reappears a second later and lingers.

**Cause.** My state update was an upsert: update the peer if present, add it
if missing. But a closed connection's async callbacks still fire afterward.
A route-detection probe reschedules itself with `setTimeout`, and in-flight
`connectionstatechange` events arrive late. Each late callback re-upserted
(and therefore resurrected) the tile I had just removed.

**Fix.** Two parts. The connection object gets a closed guard: `close()`
sets a flag and replaces every callback with a no-op. And the upsert is
split into `addPeer`, used only on deliberate creation, and `updatePeer`,
which never adds. Late callbacks can update a tile that exists, but they can
no longer recreate one that does not. If your UI layer has a generic upsert
fed by async events, you have this bug; you just have not seen it yet.

## 4. Concurrent transfers corrupt each other

**Symptom.** Send two files at once, or accept two at once, and you get
corrupt output or a transfer frozen at "transferring".

**Cause.** The receiver had a single incoming slot, and binary chunks
carried no transfer id, so accepting a second file overwrote the slot and
interleaved two byte streams into one buffer. On the send side, two
streaming loops shared one DataChannel and each assigned
`channel.onbufferedamountlow`, clobbering the other's backpressure wakeup
and hanging it.

**Fix.** Frame every chunk: a 4-byte stream id in front of the payload, and
the receiver keys its buffers by that id. Any number of transfers can now
interleave on one channel safely. Backpressure became one persistent
`onbufferedamountlow` handler that resolves a shared list of waiting
senders, so nobody overwrites anybody. The lesson generalizes: a DataChannel
is a pipe, not a session. If two logical streams share it, you need framing,
exactly like you would on a raw TCP socket.

## 5. A drop mid-transfer leaves an unclearable row

**Symptom.** Lose the connection while a file is moving and the row is stuck
at "transferring" forever. The clear button only renders for terminal
states, so the user cannot even dismiss it.

**Cause.** The failure handler updated the peer's status but never walked
the transfers, so in-flight ones never reached a terminal state. Two state
machines, one event, only one of them notified.

**Fix.** A `failActive()` pass that runs on failure, on grace-timer expiry,
and on close: every transferring or offered transfer gets marked failed,
buffers are cleared, and parked sender loops are unblocked. Whenever one
state machine dies, ask which other machines were leaning on it.

## 6. Treating "disconnected" as fatal

**Symptom.** A brief network blip, like a phone hopping between WiFi and
cellular, killed an otherwise fine connection and forced a full re-pair.

**Cause.** I lumped the `disconnected` connection state in with `failed`.
But `disconnected` is frequently transient, and ICE can recover from it on
its own if you let it.

**Fix.** Treat it as soft. Show "connecting", have the impolite peer call
`restartIce()` to nudge recovery, and start a 6 second grace timer. Only if
the connection has not recovered by then do we declare failure for real.

## 7. The signal handler trusted any sender

**Symptom.** Stray "connecting" tiles for peers who had already left.

**Cause.** The handler's logic was: find the connection for this sender, or
create one. So any stale or duplicate message from a departed peer, even a
lone leftover ICE candidate, conjured a brand-new half-open connection and a
tile to go with it.

**Fix.** Only an incoming offer may create a new connection. Stray answers
and candidates from unknown senders are dropped. Signaling messages are
untrusted input from the network; validate the state transition they imply,
not just their shape.

## 8. Nothing watches the watchers: stuck at "connecting" with no timeout

**Symptom.** Two tiles sit at "connecting" indefinitely. Not failed.
Connecting. Forever.

**Cause.** ICE only times out once an offer and an answer have both been
exchanged. If a signaling message is lost, say the offer was relayed to a
connection that died a moment earlier, or the peer's tab got suspended mid
handshake, then nothing ever starts ICE, so nothing ever fails, so nothing
ever retries. WebRTC has no built-in timeout for "negotiation never got off
the ground". You have to bring your own.

**Fix.** Three layers. A 15 second establishment watchdog: if the connection
is not up in time, tear it down and recreate it with a fresh offer and fresh
ICE config, retry twice, then mark the peer failed honestly. Politeness
computed over stable per-tab identities instead of ephemeral socket ids, so
a peer holding a stale id cannot produce two polite peers waiting politely
on each other for eternity. And explicit `createOffer()` and
`createAnswer()` calls instead of the fashionable no-argument
`setLocalDescription()`, which throws on older Safari and was silently
killing the handshake inside the signal queue.

## 9. Stale TURN credentials in long-lived tabs

**Symptom.** Pairs that need the relay connect fine in a fresh tab but fail
in a tab that has been open for a few hours. This one is nasty because every
test you run with a freshly opened tab passes.

**Cause.** I fetched ICE server config once at page load. But TURN
credentials in the standard ephemeral scheme are expiry-stamped HMACs. A tab
older than the TTL hands dead credentials to every new connection, coturn
rejects the allocation, no relay candidates are gathered, and every
relay-dependent pair fails.

**Fix.** Refresh the config on every reconnect and every 10 minutes in the
background, so new connections always carry fresh credentials. I also raised
the server-side TTL to 6 hours so long-running relayed sessions can keep
refreshing their allocations. If you use ephemeral TURN credentials, the
question is not whether to re-fetch them, only how often.

## 10. Zombie presence: the same device appears twice

**Symptom.** One device shows up as two tiles with the same name, one of
which never connects.

**Cause.** Presence entries were only removed by the server's disconnect
handler. But a server restart or crash kills its sockets without running any
handlers, orphaning those entries in the Redis room registry. Every
subsequent roster handed the zombies out to clients as real peers. I
confirmed it live: the room hash held the same device under two socket ids,
one from a connection that died when the API container was recreated.

**Fix.** Two layers. Server side, liveness leases: every connection holds a
short-TTL key refreshed every 45 seconds by the instance that owns it, the
roster only returns leased entries, and dead ones are lazily deleted the
first time anyone looks. Orphans now vanish within two minutes of any crash.
Client side, identity supersede: a tab has exactly one live connection, so
when a connection arrives for a device identity we already display under an
older socket id, the old tile is replaced immediately. Disconnect handlers
are a courtesy, not a guarantee. Any presence system that relies on them
will accumulate ghosts.

## 11. Pairing codes that work forever are a bug, not a feature

This one is a design failure rather than a crash. Filament discovers devices
on the same network automatically, but sometimes the person across the table
is invisible to you: different carriers, AP isolation, CGNAT splitting what
looks like one network into many. For that case the original app had short
room codes, and they were persistent: anyone who overheard the code could
join the room later.

The fix was to make spoken codes one-time. Creating a code registers a
speakable phrase like `clever-lynx-63` for ten minutes. Claiming it is
atomic (a Redis `GETDEL`, so exactly one claim can ever succeed), and the
claimer joins the creator's current room while the creator never moves, so
nearby auto-discovery stays intact. Want to add a third person? Mint another
code. An overheard code is worthless the moment your real partner claims it,
and before that an attacker has to out-race the person physically sitting
next to you.

There was a bonus bug in here that I will admit to because someone else will
hit it: wiring `generateCode` straight to a button's `onClick` passes the
click event as the first argument. The event object sailed through as the
requested keyword and crashed the handler, so the button silently did
nothing. Type-guard your optional string parameters at both ends.

## Bonus: transfers that survive the connection

After all eleven fixes, drops re-paired automatically, but a half-sent video
still restarted from zero. On a flaky mobile path that can mean never
finishing. So Filament resumes:

1. **Stable identity.** Each tab mints a session-scoped id carried through
   the signaling protocol, so peers recognize "same device, new connection"
   after a drop. Socket ids change on every reconnect; you need something
   that does not.
2. **State that outlives the connection.** Partial receive buffers and
   unfinished outgoing files live in stores owned by the app layer, not by
   the per-connection object. A drop marks them paused, not failed.
3. **An offset handshake.** When a new channel opens to a device with a
   paused transfer, the sender re-offers with a resume flag, the receiver
   replies with how many bytes it already has, and the sender streams
   `file.slice(offset)` onward. The chunk framing from fix 4 keys everything
   by transfer id, so resumed bytes land in the right buffer.

One honest limit: resume requires the sender's tab to stay alive, because a
page reload revokes the browser's file handle and there is nothing left to
stream from. That is a platform boundary, not a design choice.

## What I actually learned

- **The seams are the product.** Every one of these bugs lived between two
  state machines, not inside one. When you draw your architecture, draw the
  seams and ask what happens at each one during a reconnect.
- **Silence is the enemy.** Almost every failure here was a swallowed
  exception or a missing timeout. WebRTC will happily sit in "connecting"
  until the heat death of the universe. Watchdog everything.
- **Test the old tab.** Fresh-tab testing hides credential expiry, zombie
  presence, and stale identity bugs. Leave a tab open overnight and try it
  in the morning.
- **Disconnect handlers are a courtesy.** Build presence on leases, not on
  goodbye messages.

Filament is open source and self-hostable: a React frontend, a small
Flask-SocketIO signaling server, Redis, and coturn, all wired together with
docker compose. Try it at
[filament.autumated.com](https://filament.autumated.com), read the code at
[github.com/Abdk4Moura/filament](https://github.com/Abdk4Moura/filament),
and if you find failure mode number twelve, the issue tracker is open.

---

## Publishing notes (not part of the post)

- Target: Abdk4Moura.github.io blog (markdown + posts.json index).
- Suggested posts.json entry:
  `{ "slug": "webrtc-file-transfer-failures", "title": "Eleven ways WebRTC file transfer fails (and the fixes)", "date": "2026-06-06", "summary": "Reviving an abandoned P2P file sharing app turned into a tour of every way WebRTC fails in the real world. Eleven failure modes, with causes and fixes." }`
- Style check: zero em dashes (house rule), verified.
- Good companion link for HN comments: docs/resilience.md in the repo.
