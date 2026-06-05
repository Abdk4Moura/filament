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

## 8. No negotiation watchdog → stuck at "connecting" forever

**Symptom.** Two tiles sit at "connecting" indefinitely (not even reaching
"failed").

**Problem.** ICE only times out (→ `failed`) once offer **and** answer have
been exchanged. If a signaling message is lost — the one offer relayed to a
just-died sid, the peer's tab suspended mid-handshake, an SDP error swallowed
by the signal queue, or a both-polite deadlock from politeness compared over
mismatched (stale) sids — nothing ever starts ICE, nothing ever fails, and
nothing retries. Infinite "connecting".

**Solution.** Three layers:
- A **15s establishment watchdog** in `PeerLink`: not `connected` in time →
  `onStuck` → the hook tears the link down and **recreates it** (fresh offer,
  fresh ICE config), twice, then marks the peer `failed` honestly.
- **Politeness by stable uid** (`politeRole`): roles are compared over the
  per-tab uids, which survive reconnects — so one side holding a stale sid can
  no longer produce two polite peers waiting on each other.
- **Explicit `createOffer()/createAnswer()`** instead of the no-arg
  `setLocalDescription()`, which throws on older Safari and silently killed
  the handshake.
*Files:* `webrtc.js` (`politeRole`, watchdog, `onnegotiationneeded`,
`_handleSignal`), `useFilament.js` (`onStuck` retry loop, `attemptsRef`).

## 9. Stale TURN credentials in long-lived tabs

**Symptom.** Pairs that need the relay (hard NATs, cellular) connect fine in a
fresh tab but fail in a tab that's been open a while.

**Problem.** `/api/config` was fetched **once at page load**, and TURN
credentials are expiry-stamped HMACs (`FIL_TURN_TTL`). A tab older than the
TTL hands dead credentials to every new connection → coturn rejects the
allocation → no relay candidates → relay-dependent pairs fail.

**Solution.** The hook now refreshes `/api/config` on **every reconnect** and
every **10 minutes** in the background, so new links always carry fresh
credentials; the server-side TTL was raised to 6h so long-running relayed
sessions can keep refreshing their allocations.
*Files:* `useFilament.js` (status-handler + interval refresh), droplet `.env`
(`FIL_TURN_TTL`).

## 10. Zombie registry entries → duplicate peer tiles

**Symptom.** The same device shows up twice in the peer grid (same name, two
tiles), one of them never connecting.

**Problem.** Registry entries were only removed by the disconnect handler. An
api **restart/crash kills its sockets without running handlers**, orphaning
those entries in the Redis room hash for up to 24h — and every subsequent
`welcome` hands the zombies to clients as roster entries. Confirmed live: the
room hash contained `gentle-fox` under **two sids with the same tab-uid**, one
from a connection that died in an api recreate. A second, transient variant:
during a reconnect, `peer-joined` (new sid) can arrive before `peer-left` (old
sid), briefly duplicating the tile.

**Solution.** Two layers:
- **Server — liveness leases:** every connection holds a `filament:live:{sid}`
  key (`EX 120`) refreshed every 45s by the instance that owns it; `peers_in`
  returns only leased entries and **lazily deletes** dead ones the first time
  anyone looks. Orphans now disappear ≤2 minutes after any crash/restart.
- **Client — uid supersede:** a tab has exactly one live connection, so when a
  link arrives for a uid we already display under an older sid, the old
  link/tile is replaced immediately. This also erases the transient
  reconnect-window duplicate.
*Files:* `backend/signaling.py` (`LIVE_TTL`, `refresh`, lease-aware
`peers_in`, `_lease_loop`), `useFilament.js` (`makeLink` supersede).

---

## Testing

`PeerLink`'s logic is exercised against a mock `RTCPeerConnection` (see the test
run in the PR that introduced these fixes): concurrent-transfer framing
roundtrip with interleaved chunks (#4), candidate buffering + ordering (#2),
impolite glare-ignore (#1), fail-on-drop (#5), and the closed-guard (#3). Full
end-to-end negotiation still needs two real browsers — these state-machine
fixes are unit-tested where they can be, and verified live by reconnect/transfer
testing on two devices.

## Transfer resume (feature, builds on the fixes above)

**Problem.** P2P transfers die with the connection. After the resilience fixes
a drop re-paired automatically, but a half-sent video still restarted from 0 —
on flaky mobile paths that can mean never finishing.

**Solution.** Three pieces:
1. **Stable identity** — each tab mints a session `uid` carried through
   `join`/`welcome`/`peer-joined`, so peers recognize "same device, new
   connection" after a drop (socket ids change every reconnect).
2. **State that outlives the link** — partial receive buffers and unfinished
   outgoing `File`s live in hook-owned stores (`partialsRef`/`outgoingRef`),
   not in the per-connection `PeerLink`. `_failActive` marks such transfers
   `paused` instead of `failed`.
3. **Offset handshake** — when a new channel opens to a peer whose `uid`
   matches a paused send, the sender re-offers with `resume: true`; the
   receiver (which already accepted once) auto-accepts with
   `offset: bytesReceived`; the sender streams `file.slice(offset…)`. Chunk
   framing (#4) keys everything by transfer id, so resumed bytes land in the
   same buffer.

**Limit:** resume requires the sender's *tab* to still be alive — a page reload
revokes the browser's file handle, and there is nothing to stream from. That's
a platform boundary (no filesystem access), not a design choice.

## Known remaining limits (by design)

- **In-flight transfers now pause + resume** across drops (above) when the
  sender's tab survives; a sender reload still loses the transfer — the browser
  revokes file handles on navigation.
- **Multi-instance API scaling** needs the Redis registry (already wired); the
  glare fix (#1) is what makes that safe.
