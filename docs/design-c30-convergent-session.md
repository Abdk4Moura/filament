# C30 — The convergent session: ending the lost-emit disease class

Status: DESIGN (approved direction 2026-06-07; implementation follows
cli-v0.2.1-beta.2). Companion to `cli-resilience.md` (the instances) — this
is the cure for the class.

## The disease, named precisely

Five incidents in one day of live multi-device testing, every one the same
shape — **session state held in N places, transitions edge-triggered, one
lost edge = permanent divergence**:

| Incident | Lost state | Bespoke belt that patched it |
|---|---|---|
| roomless ghost (Android reconnect, ignored by all) | room membership | rejoin belt (#14): re-join on every socket-up |
| zombie create-code (phone tab minted unclaimables) | creator lease | self-healing mint + lease refresh (C24) |
| invisible known device (`filament up` needed a page reload) | channel subscriptions | acked subscribe + 45 s reconcile (C28) |
| recv hung after a complete transfer | peer departure | quiet-exit fallback (G-k) |
| "never met a fella like you" (one-sided trust) | pairing belief | keep/proof acks (C27) |

Each fix rediscovered the same three moves: **assert → verify → reconcile**.
C28 wrote the slogan; C30 makes it the *only* mechanism instead of five
hand-rolled belts.

> **The rule.** No emit is ever load-bearing. Only convergence is.

## The model (level-triggered, anti-entropy)

Each client keeps two pure-data snapshots of its session:

```
desired   = { room, name, uid, channels: Set<hex>, lease: alive }
              ^ edited ONLY by app actions (join room, store device, …)
confirmed = the last server-ACKED snapshot + timestamp
              ^ edited ONLY by sync acks
```

One loop per client (browser `lib/session.js`, CLI `session.rs` module),
ticking on: every 5 s, every socket-up, every tab-visible:

```
if digest(desired) != digest(confirmed) or confirmed is stale (> 30 s):
    emit ONE `sync` { full desired state }            (idempotent)
    server ensures: membership(room), subscriptions(channels), lease refresh
    server ACKs with ITS resulting digest             (socket.io ack)
    confirmed = ack
```

Key properties:

- **Idempotent + full-state**: a sync can be applied twice, applied late, or
  applied after any number of losses — the result is the same. No ordering,
  no per-transition acks, no "did my join land?".
- **The digest closes the loop on the server's beliefs.** The ack carries
  what the server actually holds for this sid: `{room, channels: n, lease
  epoch}` — phase 2 adds a roster hash. The client never assumes; it
  compares.
- **The old events remain as fast-path hints** (`peer-joined`, `known-peer`,
  `pair-used` keep UX snappy). The sync loop is the guarantee underneath.
  Edge-triggered for latency, level-triggered for truth.

### What dissolves into this

| Today's belt | Fate under C30 |
|---|---|
| rejoin belt (#14) | deleted — room is in `desired`, every sync re-ensures it |
| subscribeKnown + ack-retry + 45 s reconcile + debounce (C28) | deleted — channels are in `desired` |
| pair-create lease refresh (C24 server half) | absorbed — every sync refreshes the lease |
| G-k quiet-exit | generalized — recv's exit reads the converged roster ("digest says alone"), not the absence of an event |
| `welcome`-handler re-subscribes (CLI ×3 call sites) | deleted |

### Phase 2 — roster digest

The sync ack adds `peers: hash(sorted sids in your room + your channel
matches)`. A client whose local roster hash disagrees re-fetches the roster
(one `who` request) and reconciles tiles/links. A missed `peer-left` or
`known-peer-left` now self-corrects within one tick — the entire G-k family,
structurally gone.

### Phase 3 — link-level mini-sync (peer ↔ peer)

The same model one level down, over the DataChannel, every ~10 s:

```
{ type: "state", transfers: { id: bytesReceived }, trusted: bool, away: bool }
```

Divergence detection between PEERS: a stalled transfer one side thinks is
moving, an accept that never arrived, one-sided trust, a stale `brb`. Each
is today an undiscovered field bug; under mini-sync each is detected and
corrected (re-offer, re-prove, re-ask) or surfaced honestly.

## The meta-gate (what makes it "forever")

**Gate L (lossy chaos): wrap the signaling client in a shim that drops 30 %
of outbound emits at random** (env `FILAMENT_TEST_EMIT_LOSS=0.3`, seeded for
reproducibility), then run the standard pair + transfer + reconnect
choreography and assert everything still converges: transfer completes,
hashes match, devices stay mutually visible, both exit clean.

Today every lost-emit bug was found by a human on a device in the field.
After gate L, **any future code path that secretly depends on a single emit
arriving fails in CI by construction.** That is the difference between
fixing five bugs and ending the class.

(The browser gets the same shim in `signaling.js` behind a query param for
Playwright runs: `?telLoss=0.3`.)

## Implementation order

1. Server `sync` handler (idempotent ensure + digest ack) — additive, old
   clients unaffected.
2. CLI `session` module; recv/up/send/pair loops swap their belts for it.
3. Browser `lib/session.js`; useFilament swaps its belts.
4. Gate L (CLI flavor), wired into the suite.
5. Phase 2 roster digest + recv exit generalization; gate L extended to
   assert tile/roster convergence.
6. Phase 3 mini-sync + its divergence telemetry.

Ledger discipline applies: C30 lands with gate L or it isn't VERIFIED.
