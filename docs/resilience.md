# Connection resilience & state machines

Filament has three interacting state machines:

1. **Room / signaling** — `signaling.py` (server) + `signaling.js` (client). Tracks
   who is in a room and relays opaque WebRTC payloads. Convention: roles are
   assigned by a deterministic tiebreaker (see #1), not by join order.
2. **Per-peer negotiation** — `webrtc.js` `PeerLink`: `new → offer/answer/ICE →
   connected → (disconnected) → failed/closed`.
3. **Per-file transfer** — `webrtc.js`: `offered → transferring → complete |
   declined | failed`.

Most flakiness lives in the *seams* between these, and reconnection stresses
every seam at once. This doc records each failure mode we found and fixed —
problem, then solution — so the reasoning isn't lost.

---

## 1. Glare: both peers offer at once → stuck "connecting"

**Symptom.** Sometimes two devices never connect (both tiles sit at
"connecting"), especially right after a reconnect.

**Problem.** The old design picked the offerer by join order ("the newer peer
initiates"). That only holds if the server's `welcome` reads are serialized.
Two ways it isn't:
- On reconnect both peers come back together; each `welcome` can already list
  the other, so **both** become initiators → both `createOffer` → each receives
  the other's offer while in `have-local-offer` → `setRemoteDescription` throws.
- We run the signaling with Redis for scaling; the eventlet worker **yields at
  every Redis I/O**, so the server's `join` handler is no longer atomic and two
  joins can interleave and each see the other.

The thrown error was swallowed, leaving the peer stuck.

**Solution.** Standard **perfect negotiation** with a deterministic role:
`polite = myId > peerId` (string compare), so exactly one peer per pair is
*impolite* and owns the offer. The impolite peer creates the data channel
(triggering `onnegotiationneeded` → offer); the polite peer answers. On a true
collision the impolite peer **ignores** the incoming offer and the polite peer
rolls back. No reliance on ordering, so it's race-proof.
*Files:* `webrtc.js` (constructor, `onnegotiationneeded`, `_handleSignal`),
`useFilament.js` (`makeLink` computes `polite` from `myIdRef`).

## 2. Unserialized signals drop ICE candidates

**Symptom.** Intermittent connect failures or needless relay (TURN) fallback.

**Problem.** The hook called `link.accept(data)` per relayed message but never
awaited it, so an `offer` and the `candidate`s that followed it ran
**concurrently**. A candidate that reached `addIceCandidate` before
`setRemoteDescription` resolved threw "remote description is null" and was
**silently dropped**. Lost host candidates hurt connectivity.

**Solution.** A **per-peer FIFO queue** (`enqueueSignal` chains onto
`this._signalQ`) so each signal is fully applied before the next, **plus** a
candidate buffer: candidates that arrive before a remote description is set are
held in `_pendingCandidates` and flushed by `_flushCandidates()` right after
`setRemoteDescription`.
*Files:* `webrtc.js` (`enqueueSignal`, `_handleSignal`, `_flushCandidates`),
`useFilament.js` (signal handler calls `enqueueSignal`).

## 3. Ghost peer tiles after teardown

**Symptom.** Dead "connecting"/"failed" tiles linger after a peer leaves or you
reconnect.

**Problem.** `upsertPeer` **added if missing**. But a closed `PeerLink`'s async
callbacks still fired afterward — `_detectRoute` reschedules via `setTimeout`
for ~2s, and in-flight `onconnectionstatechange` events arrive late — and each
late `onStatus`/`onRoute` re-`upsert`ed (re-created) the tile we'd just removed.

**Solution.** Two parts: (a) a `_closed` guard — `close()` sets it and replaces
`onStatus`/`onRoute`/`onTransfer` with no-ops, and `_detectRoute` bails when
closed; (b) split the hook's `upsertPeer` into `addPeer` (used only by
`makeLink`) and `updatePeer` (status/route — **never adds**). A late callback
can no longer resurrect a removed tile.
*Files:* `webrtc.js` (`close`, `_detectRoute`), `useFilament.js` (`addPeer` /
`updatePeer`).

## 4. Concurrent transfers corrupt each other

**Symptom.** Sending/accepting more than one file at once produced corrupt
files or a transfer stuck at "transferring".

**Problem.** The receiver had a **single** `_incoming` slot and binary chunks
carried **no transfer id**, so accepting a second file overwrote the slot and
mixed the byte streams. On the send side, two `_streamFile` loops interleaved
raw bytes on one channel and **clobbered each other's**
`channel.onbufferedamountlow`, hanging one of them.

**Solution.** **Frame every chunk** with a 4-byte stream id (`[uint32 sid]
[payload]`); the receiver keys buffers by `sid` in `_incomingBySid`, so any
number of transfers can interleave safely. Backpressure now uses **one
persistent** `onbufferedamountlow` that resolves a shared `_drainWaiters` list,
so concurrent senders never clobber it.
*Files:* `webrtc.js` (`sendFiles`, `acceptTransfer`, `_streamFile`, `_onMessage`,
`_onControl`, `_setChannel`).

## 5. A drop mid-transfer left an un-clearable "transferring" row

**Symptom.** Lose the connection while a file is moving and the row is stuck at
"transferring" forever — the **clear** button only shows for terminal states, so
it can't even be dismissed.

**Problem.** `onconnectionstatechange('failed')` updated the *peer* status but
nothing walked the transfers, so in-flight ones never reached a terminal state.

**Solution.** `_failActive()` marks any `transferring`/`offered` transfer as
`failed` (making it clearable), clears the incoming/outgoing maps, and unblocks
parked sender loops. It's called on `failed`, on the disconnect grace-timer
expiry, and in `close()`.
*Files:* `webrtc.js` (`_failActive`, `onconnectionstatechange`, `close`).

## 6. Transient `disconnected` was treated as terminal

**Symptom.** A brief network blip (e.g. Wi-Fi ↔ cellular) killed an otherwise
fine connection and forced a full re-pair.

**Problem.** `onconnectionstatechange` lumped `disconnected` in with `failed`.
But `disconnected` is frequently **transient** and ICE can recover on its own.

**Solution.** Treat `disconnected` as soft: show "connecting", have the impolite
peer call `restartIce()` to nudge recovery, and start a **6s grace timer** —
only if it hasn't returned to `connected` by then do we declare failure.
*Files:* `webrtc.js` (`onconnectionstatechange`, `_dcTimer`).

## 7. The signal handler trusted any sender

**Symptom.** Stray "connecting" tiles for peers that had already left.

**Problem.** `linksRef.get(from) || makeLink({ id: from })` created a brand-new
answerer link for **any** sid that sent **any** signal — including a stale or
duplicate message from a departed peer.

**Solution.** Only an incoming **offer** (`description` of type `offer`) may
create a new link; stray answers/candidates from unknown sids are ignored.
*Files:* `useFilament.js` (signal handler).

---

## Testing

`PeerLink`'s logic is exercised against a mock `RTCPeerConnection` (see the test
run in the PR that introduced these fixes): concurrent-transfer framing
roundtrip with interleaved chunks (#4), candidate buffering + ordering (#2),
impolite glare-ignore (#1), fail-on-drop (#5), and the closed-guard (#3). Full
end-to-end negotiation still needs two real browsers — these state-machine
fixes are unit-tested where they can be, and verified live by reconnect/transfer
testing on two devices.

## Known remaining limits (by design)

- **In-flight transfers are lost on a drop** — that's inherent to P2P; the data
  channel dies with the connection. Discovery/pairing recovers automatically so
  you can immediately re-send; chunk-level *resume* would be a larger feature.
- **Multi-instance API scaling** needs the Redis registry (already wired); the
  glare fix (#1) is what makes that safe.
