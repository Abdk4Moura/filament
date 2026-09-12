# Filament consolidation — layered decomposition plan (2026-06-15)

Goal: stop the "mangled" growth. Make the **filament protocol** and the
**resilience protocol** separate, named layers with one-way dependencies, so each
has one reason to change (SRP) and can be tested in isolation. `CONTRACT.md` stays
the cross-implementation wire spec; this doc is the *code-structure* spec that
mirrors it.

## Where the mess actually is (from a full concern-map pass)

The rot is concentrated in **three god-files**, not spread everywhere:

| File | LOC | Problem |
|------|-----|---------|
| `frontend/src/lib/webrtc.js` | 1741 | `PeerLink` mixes transport (WebRTC), protocol (framing/ceremonies), resilience (stall ladder, upgrade prober, watchdog, ack-fallback), and app (file streaming, PTY) in one class. |
| `frontend/src/lib/useFilament.js` | 1305 | One React hook mixes signaling, protocol orchestration, resilience recovery, and UI state. `makeLink()` (299–514) and the bootstrap effect (587–746) touch all four. |
| `cli/src/main.rs` | 8020 | God-file. `send_cmd` (1027 lines) and `recv_cmd` (2111 lines) are event loops that interleave PAKE + file protocol + chunk + ack + stall ladder. `Conn` struct mixes signaling/protocol/resilience state. |

**Already clean — keep as-is** (these are the model for the rest):
- Frontend: `pairing.js` (PAKE, pure state machine), `devices.js` (known-device store), `signaling.js` (relay glue), `session.js` (C30 convergence), `linkdiag.js` (diagnostics).
- CLI: `l2.rs`, `direct.rs`, `holepunch.rs`, `pake_ceremony.rs`, `session.rs`, `codeentry.rs`, `ui.rs`, `sshkeys.rs`.

## The division — five layers, one-way dependencies

Both the JS networking layer and the Rust CLI get the SAME shape. A layer may only
depend on layers **below** it. The wire contract (`CONTRACT.md`) is the seam
between the two implementations.

```
┌─────────────────────────────────────────────────────────────┐
│ 5. APPLICATION   file transfer UX · PTY/shell · L2 TUN · device list
│                  (JS: useFilament public API — FROZEN; web-shell)
│                  (Rust: send_cmd/recv_cmd as THIN drivers)
├─────────────────────────────────────────────────────────────┤
│ 4. ORCHESTRATION wires the 3 below per peer; connection state machine;
│                  signaling event handling; roster/presence
│                  (JS: slim PeerLink + signaling dispatcher)
│                  (Rust: Conn, split into signaling/roster vs. the rest)
├──────────────────────────────┬──────────────────────────────┤
│ 3. RESILIENCE                │ 2. PROTOCOL  (the filament protocol)
│   keep the link alive &      │   the wire contract: message types,
│   data delivered:            │   framing ([sid][payload]), encode/decode,
│   · stall detect + ladder    │   ceremonies:
│   · relay↔direct upgrade     │   · PAKE pairing / pair-keep / pair-proof
│   · idle/PTY liveness        │   · file-offer/accept/end/delivery-ack
│   · ack-fallback / replay    │   · pty-open/resize/close, l2-*, state ping
│   · reconnect budgets,       │   pure-ish: bytes⇄typed events; NO timers,
│     warm-standby, recovery   │   NO retries, NO reconnect
├──────────────────────────────┴──────────────────────────────┤
│ 1. TRANSPORT     the physical link ONLY. open/close, send(bytes),
│                  onBytes, onState, getStats/route. Knows nothing about
│                  message meaning or retries.
│                  (JS: RTCPeerConnection + data channel)
│                  (Rust: net.rs Transport trait + direct.rs/holepunch.rs)
└─────────────────────────────────────────────────────────────┘
```

### The SOLID discipline that makes it hold
- **SRP** — Protocol changes when the wire format changes; Resilience changes when
  the network-survival strategy changes. Today a single edit to `_streamFile` or
  `recv_cmd` risks both. After: separate files, separate reasons.
- **Dependency Inversion** — Resilience and Protocol depend on a **Transport
  interface**, not on concrete WebRTC/QUIC. This is what lets the `lab` (netns)
  drive resilience without real WebRTC, and lets Protocol be unit-tested with no
  network. The interface is the boundary; the concrete transport plugs in.
- **Protocol is timer-free and retry-free.** Every retry/timeout/reconnect lives in
  Resilience. That single rule is the un-mangling: if it has a `setTimeout` or a
  retry counter, it is Resilience, not Protocol.

## Seams that MUST NOT change (this keeps the refactor safe)
1. **The wire protocol** (`CONTRACT.md`) — byte-compatible across JS↔Rust, has
   gates/test-vectors (e.g. `proof_matches_browser`, gate 16). Frozen.
2. **`useFilament()` return shape** (`CONTRACT.md` UI contract) — the UI seam. Frozen.
3. **`PeerLink` public methods/callbacks** used by useFilament + WebTerminal
   (`sendFiles`, `openPty`, `onPtyData`, …). Kept or shimmed.

→ This is a **structural** refactor behind stable seams: behavior identical,
structure clean. That's what makes it verifiable (existing gates + the lab + the
web-shell harness all still pass) and reversible per-step.

## Sequencing — incremental, each step independently verifiable

**Phase 0 — name the seams (cheap, no behavior change).** Add the `Transport`,
`Protocol`, and `Resilience` interfaces as code + this doc. De-risks everything.

**Phase 1 — frontend `webrtc.js` split** (highest value, most verifiable — the lab
and web-shell harness exist):
- 1a. Extract **PROTOCOL**: `protocol/messages.js` (CTRL constants + framing +
  encode/decode), `protocol/transfer.js` (file-offer/accept/end/ack state machine).
  PeerLink delegates. (Targets the `_streamFile`/`_finishReceive`/`_onControl`
  tangles.)
- 1b. Extract **RESILIENCE**: `resilience/stall.js`, `resilience/upgrade.js`,
  `resilience/liveness.js`, `resilience/ackfallback.js` — controllers that take a
  Transport handle + progress signals. PeerLink delegates.
- 1c. PeerLink becomes a thin orchestrator (Transport + Protocol + Resilience +
  state). Verify against gates + lab.

**Phase 2 — frontend `useFilament.js` split** into signaling-dispatcher /
protocol-orchestrator / resilience-manager / state-reducer. Public API frozen.

**Phase 3 — CLI `main.rs` mirror** (biggest, riskiest, done last, behind the
gates): extract a `protocol` module (file-transfer state machine out of
send_cmd/recv_cmd) and a `resilience` module (ladder/upgrade/recovery out of Conn).
Keep the already-clean modules.

Each phase is shippable on its own and gated. Phases 1–2 don't touch Rust; Phase 3
doesn't touch the frontend.

## Other areas worth the same treatment (lower priority)
- **Frontend UI** (`Filament.jsx` and friends): theme/density/state vs. screens —
  separate presentation from the `useFilament` data it renders. Already partly OK.
- **Backend** (`signaling.py`, 654): the relay vs. the room/lease/known-channel
  bookkeeping could split, but it's small and stable — last.

## Decision (made 2026-06-16)
Full sweep including the Rust god-file; cleaner-slate interfaces. Hard constraint:
the **wire protocol stays byte-compatible** (cross-impl, gate-tested) even as
internal interfaces are redesigned. Verification net is thin (frontend had ZERO
unit tests; CLI gates partially red), so each step is landed behind a
characterization test and the existing gates, smallest verifiable slice first.

## Progress log
- **2026-06-16 — Phase 0 done; Phase 1 started.**
  - Verification convention chosen: plain-Node ESM characterization tests (like
    `cli/tests/l1a/gate8`), no new deps. Baseline `gate8` byte-identity = PASS.
  - `frontend/src/net/contracts.js` — the Transport / ProtocolCodec /
    ResilienceController interfaces (the cleaner-slate boundary).
  - `frontend/src/net/protocol/wire.js` — first extracted PROTOCOL module: the
    message-type registry (`MSG`), binary framing (`frame`/`parseFrame`/
    `isCloseFrame`/`highHalfSid`), and control codec (`encode/decodeControl`).
    Pulled out of `webrtc.js` (was inline at the old CTRL block + `_onMessage` +
    `sendPtyInput` + `openPty` + `_streamFile` + `_control`).
  - `webrtc.js` rewired to delegate to wire.js. Verified: `vite build` clean,
    `wire.test.mjs` PASS, `gate8` still PASS.
  - Residual not yet verified live: the PTY framing path and file-transfer
    receive assembly are exercised only by the heavier browser gates (need a
    running app + CLI + network), not by the web-shell mock harness. Equivalence
    was reasoned (Blob accepts Uint8Array; binaryType=arraybuffer) but a real
    browser↔CLI transfer should be run before promoting.

- **2026-06-16 (cont.) — gate baseline + LIVE wire verification + workstream D.**
  - Full gate baseline recorded in `consolidation-baseline-2026-06-16.md`.
    Today (quiescent host): vite build / wire.test / gate8 / cargo test (63/63) /
    transport-gates (4/4) / ssh-gates (4/4) all green; l2-gates 4/5; gates.sh
    core 20/21 (gate18 G-k is timing-flaky; 2 browser gates skip w/o playwright).
  - **Workstream D (red gate) FIXED**: l2-gates gate4 (non-loopback SSRF deny)
    was failing only because the refusal was logged at `ui::debug` (hidden at the
    default Info verbosity); the deny LOGIC was always correct. Promoted to
    `ui::say` to match the `shell-bootstrap-deny` convention → l2-gates 5/5.
    ssh-gates is 4/4 (charter's 1/4 was earlier WebRTC flakiness, not a bug).
  - **LIVE wire verification DONE** (the residual above is now retired). Ran a
    real Chromium (production frontend) ↔ real `filament` CLI over a real WebRTC
    data channel, both directions, via `cli/tests/live-wire-check.sh`:
    - CLI→browser file transfer (gate-5 shape): PASS (browser parses real CLI
      frames via wire.js `parseFrame`/`decodeControl`).
    - browser→CLI file transfer, two human-paced sends (gate-6 shape): PASS 2/2
      byte-exact (CLI parses real browser wire.js `frame`/`encodeControl` output).
      (One earlier failure under host contention = the known G-i WebRTC glare,
      not a framing bug; passes cleanly when not racing another browser.)
  - **PTY/shell path**: verified by equivalence, not a separate browser drive.
    The wire extraction is JS-only (the Rust PTY handler is untouched). The PTY
    path uses the IDENTICAL wire.js surface as file transfer — `_onMessage`
    decodes both via `decodeControl`/`parseFrame`; `_control` encodes all control
    (pty-open/resize/close AND file offer/accept/end/ack) via `encodeControl`;
    PTY input frames via the same `frame` (`wireFrame`) as file chunks; plus
    `highHalfSid`/`isCloseFrame`. Every one is exercised by the now-live file
    gates; the PTY-only constants (`MSG.PTY_*`) are pinned by `wire.test.mjs`. A
    full browser-shell Playwright drive (needs pairing + a `shell` grant against
    the explicitly-parked web-shell) would only re-test these same proven
    functions, so it was judged disproportionate — coverage is complete.

- **2026-06-16 (cont.) — Phase 1 slice: `net/protocol/transfer.js` extracted.**
  - The file-offer/accept/end/delivery-ack ceremony's MESSAGE VOCABULARY +
    PURE DECISIONS pulled out of `_streamFile`/`_finishReceive`/`_onControl`:
    `offerMsg`/`acceptMsg`/`declineMsg`/`endMsg`/`deliveryAckMsg` (exact frozen
    shapes, key order preserved), `decideOnOffer` (resume auto-accept vs
    surface), `decideAfterVerify` (the whole-file match→ack / mismatch→
    rerequest(truncated|corrupt) / over-bound→fail tree), `decideAckFallback`
    (MOVED here from webrtc.js; re-exported to keep the frozen surface), and
    `sendsToResume` (CTRL.STATE reconciliation). Pure: NO timers, NO state, NO
    transport, NO browser API — the un-mangling rule holds (the no-ack TIMER
    `_armAckFallback` stays in PeerLink, slated for resilience/ackfallback.js).
  - PeerLink delegates at every call site; the mutable stores, Blob assembly +
    sha256, channel sends, and timers stay put (orchestration). webrtc.js still
    re-exports `decideAckFallback`; `useFilament`/`WebTerminal` surfaces unchanged.
  - Verified: `transfer.test.mjs` (new characterization test, pins builders incl.
    key order + every decision) PASS; `vite build` clean; `wire.test.mjs` PASS;
    `gate8` byte-identity PASS; LIVE browser↔CLI both directions 2/2 byte-exact
    (`cli/tests/live-wire-check.sh`) — gate 6 exercises the send builders, gate 5
    the receive verify/ack decisions, over real WebRTC framing.

- **2026-06-16 (cont.) — Phase 1 resilience layer opened: `net/resilience/stall.js`.**
  - First RESILIENCE seam. Extracted the stall-correction LADDER SHAPE
    (`STALL_LADDER` + `nextStallRung`: none→a→b→c→fail) out of `_correctStall`'s
    nested ifs — a 1:1, logic-preserving control-flow refactor. The rung
    MECHANICS (ping+restartIce / re-offer+resume / onStall / failActive) and ALL
    timers + episode state stay in PeerLink (resilience owns the clock).
  - Verified: `stall.test.mjs` (new) PASS; vite build clean; wire/transfer/gate8
    PASS; LIVE browser↔CLI 2/2 (happy path intact). No behavior change (rung
    firing is byte-identical), so no lab run needed for THIS slice.

- **2026-06-16 (cont.) — stall DETECTOR reducer extracted (`stallTick`).**
  - The safety-critical watchdog decision (`_checkStall`'s idle / away-grace /
    progress / accumulate / episode-grace → correct) pulled into a PURE REDUCER
    `stallTick(state, obs) → {state, action, recovered}`. PeerLink keeps the
    STALL_TICK_MS timer + the mutable counters (idle/episode/lastMoved/
    lastBuffered) and just applies the returned next-counters and runs the ladder
    iff `action === 'correct'`. 1:1 extraction; every branch (incl. the
    idle-clears-episode vs away-keeps-episode distinction and the buffer-drain
    progress signal) preserved.
  - **Verified under real fault (per §6):**
    - `stall.test.mjs` extended — all 8 reducer branches pinned. PASS.
    - **netns lab**: `two-nodes --link filament`, `fault stall` → 100% loss
      (link up), `fault clear` → recovered 0% loss/1.6ms. Transport-resilience
      contract holds.
    - **browser freeze-shim** (`?test=freeze&log=debug`, console-captured): the
      detector tripped at exactly `idleMs 6000`, fired rung a (correctly
      polite-skipping restartIce), re-tripped at `14000` after the episode grace,
      then climbed to rung b (`re-offered/resumed … count 1`) — the EXACT
      original log strings, sequence, and thresholds. Proves the reducer is
      behavior-faithful. (The frozen transfer doesn't reach `complete` on THIS
      single host because the CLI's repair exhausts direct paths and falls to a
      dark TURN relay — an environment limit that hits the pre-refactor code
      identically, not a regression; the CLI fail-clean'd with the partial kept,
      never silent loss.)
    - LIVE happy-path browser↔CLI 2/2 (unchanged).
  - DEFERRED still: the timer-owning StallController (moving the
    setInterval+counters out of PeerLink), `upgrade.js`, `liveness.js`,
    `ackfallback.js`.

- **2026-06-16 (cont.) — `net/resilience/upgrade.js` (relay→direct prober policy).**
  - Extracted the prober's timer-free POLICY from `_upgradeProbe`/
    `_beginUpgradeVerify`/`_backoffUpgrade`: `decideProbeResult` (non-relay
    measurement → verify, else backoff), `decideUpgradeVerifyTick`
    (commit/discard/wait for the verify-before-commit window), `nextUpgradeDelay`
    (double-toward-cap backoff). PeerLink keeps the restartIce, the timers, and
    the verify-window bookkeeping (lastBytes/lastSeen).
  - Verified: `upgrade.test.mjs` (new, 15 cases) PASS; vite build clean;
    stall/wire/transfer/gate8 regression PASS; LIVE happy-path browser↔CLI 2/2.
  - **Verification caveat:** the relay→direct scenario is NOT reproducible on a
    single host (links are always `local`; the prober only runs on `relayed`), so
    neither the netns lab nor a single-host browser can exercise it live — unit
    tests are the floor. A true live check needs a two-machine / NAT'd-relay rig.

- **2026-06-16 (cont.) — `net/resilience/liveness.js` (idle-shell M1 detector + ladder).**
  - Extracted the consent-liveness detector from `_checkPtyLiveness` as a pure
    reducer `ptyLivenessTick(state, obs)` (seed / advance / accumulate-dead /
    correct, incl. the `?test=freezepty` frozen-seam handling), and the short
    shell recovery ladder from `_correctPtyDead` as `nextPtyStage` (ice → relay →
    exhausted). PeerLink keeps the timer (shares `_checkStall`'s tick), the
    `getStats` consent read, and the counters.
  - Verified: `liveness.test.mjs` (new, 15 cases incl. the frozen-seam) PASS;
    vite build clean; stall/upgrade/wire/transfer/gate8 regression PASS; LIVE
    happy-path browser↔CLI 2/2.
  - **Verification caveat:** the live idle-shell-death path needs `?test=freezepty`
    over a GRANTED browser PTY (trusted device + `shell` cap) — the heavier PTY
    harness — so unit tests are the floor for this slice.

  → Resilience POLICY is now fully extracted (stall detect+ladder, upgrade,
    liveness — all pure + tested). Remaining: move the TIMERS/counters into
    controller objects (StallController etc.), and `ackfallback` (its decision
    `decideAckFallback` already lives in protocol/transfer.js; only the
    `_armAckFallback` timer remains in PeerLink).

- **2026-06-16 (cont.) — first TIMER-OWNING controller: `StallController`.**
  - Moved the in-flight stall watchdog's mutable state (idle clock, episode
    latch, moved/buffered snapshots) AND the correction-ladder mechanics out of
    PeerLink into `net/resilience/stallController.js`. PeerLink keeps the single
    2s interval (it also ticks PTY liveness) and delegates: `this._stall.tick()`,
    `reset()` on channel-open, `clearState()` on teardown. The upgrade prober's
    glare-check now reads `this._stall.episode`. `_checkStall`/`_correctStall`
    deleted from PeerLink. Faithful relocation (pure decisions unchanged in
    stall.js).
  - Verified: vite build clean; stall/upgrade/liveness/wire/transfer/gate8 PASS;
    **browser `?test=freeze` console (2/2 clean runs)** showed the controller
    firing the ladder identically — stall detected at idleMs 6000 → rung a
    (ping-only when polite, ping+restartIce when impolite) → re-detect at 14000 →
    rung b (re-offered/resumed count 1).
  - **CROSS-MACHINE verified (pop-os over Tailscale)** — the real-network check.
    do-vm browser → pop-os `filament recv`: 1MB and 8MB transfers complete
    byte-exact (delivery-ack verified, route direct over Tailscale). Then a
    genuine injected stall: SIGSTOP the pop-os receiver mid-transfer (open-but-
    dark far end) → the do-vm StallController fired exactly as designed —
    `stall detected idleMs 6000` → rung a (ping+restartIce, impolite) →
    `idleMs 12000` → rung b (re-offered/resumed count 1); pop-os logged the
    mirror inbound-stall repair. It fail-cleaned (partials kept) only because no
    TURN is configured (relay fallback is dark) — orthogonal to the controller.
    StallController is now verified four ways: unit, local freeze-shim, netns
    lab, and cross-machine SIGSTOP.

- **2026-06-16 (cont.) — `AckFallbackController` (timer-owning, P4).**
  - Moved the delivery-ack no-ack WINDOW (`_armAckFallback` + the `_ackTimers`
    map + the "peer acks" memory `_markPeerAcks`/`_peerAcks`) out of PeerLink into
    `net/resilience/ackFallback.js`. PeerLink arms it after END+drain
    (`this._ack.arm`), cancels it on a genuine delivery-ack (`this._ack.onAck`),
    records the ack-capable peer (`this._ack.markPeerAcks`), and clears it on
    teardown (`this._ack.clear`). The pure verdict stays decideAckFallback
    (transfer.js). Faithful relocation.
  - Verified: vite build clean; all unit suites + gate8 PASS; LIVE happy-path
    browser↔CLI 2/2 (exercises arm → delivery-ack → onAck → complete + the
    peer-acks memory). The no-ack FAIL path is pinned by decideAckFallback's unit
    tests + the Rust `ack_fallback_never_completes_silently` test.

- **2026-06-16 (cont.) — `UpgradeProber` (timer-owning, P5).**
  - Moved the whole relay→direct prober (the `_upgradeTimer` chain: arm/disarm/
    schedule/probe/verify-before-commit/commit/backoff + the `_upgradeVerify`
    latch + cadence state) out of PeerLink into
    `net/resilience/upgradeProber.js`. PeerLink arms/disarms from `_detectRoute`
    (`this._upgrade.arm()/disarm()`), on `_failActive`/`close`, and keeps the
    frozen public `probeUpgradeNow()` delegating to `this._upgrade.probeNow()`.
    The pure decisions stay in upgrade.js. Faithful relocation.
  - Verified: vite build clean; all unit suites (incl. upgrade.js's 15 cases) +
    gate8 PASS; LIVE happy-path browser↔CLI 2/2. Live relay→direct still not
    reproducible here (no TURN/relay), so unit tests remain the floor for the
    prober's own logic.

- **2026-06-16 (cont.) — `LivenessController` (timer-owning, M1) — set complete.**
  - Moved the idle-shell consent-liveness detector (`_checkPtyLiveness` + the
    `getStats` read `_readConsentLiveness` + the counters + the `?test=freezepty`
    seam) and its short ladder (`_correctPtyDead`) out of PeerLink into
    `net/resilience/livenessController.js`. PeerLink's shared 2s interval now
    ticks `this._stall.tick()` + `this._liveness.tick()`; reset on open / teardown
    via `this._liveness.reset()`; the freeze seam set via
    `this._liveness.markFrozenForTest()` from `sendPtyInput`. Pure decisions stay
    in liveness.js. `_checkPtyLiveness`/`_correctPtyDead`/`_readConsentLiveness`
    deleted from PeerLink.
  - Verified: vite build clean; all unit suites + gate8 PASS; LIVE happy-path 2/2.

  → **TIMER-OWNING CONTROLLER EXTRACTION COMPLETE.** PeerLink no longer holds any
    resilience counters/episodes/per-concern timers; all four live in controller
    objects — `StallController` (cross-machine verified), `LivenessController`,
    `UpgradeProber`, `AckFallbackController`. PeerLink keeps only the shared 2s
    tick source (drives stall+liveness), the establishment watchdog, C4's
    disconnect timer, and the C30 state-ping interval (connection-state, not
    resilience). Remaining consolidation: slim PeerLink further if desired, then
    Phase 2 (useFilament.js) and Phase 3 (Rust main.rs).

## Phase 2 — useFilament.js split (started 2026-06-16)
The hook is a god-file mixing signaling, protocol orchestration, resilience
recovery, and UI state, behind a FROZEN return shape (CONTRACT.md UI contract).
Same discipline as Phase 1: extract the pure POLICY into node-testable modules
under `net/app/`, leave the React glue (state/refs/effects) in the hook delegating.
Verification: vite build + LIVE browser↔CLI (the hook is only exercisable in a
real browser; the return shape must stay identical).

- **2026-06-16 — resilience-MANAGER pure core: `net/app/recovery.js`.**
  - Extracted the recovery DECISIONS from `makeLink`/the network-recovery effect:
    `decideStallEscalation` (onStall: ignore / leave-to-p0 / already-spent /
    escalate-relay — bounded at-most-once relay), `decideStuckRecovery` (onStuck:
    retry up to maxRetries → second-wind → fail), `shouldRebuildLink` (rebuild
    failed/closed/disconnected links on a network change). The hook keeps the
    effects (makeLink, link.close, setTimeout, setState) and delegates.
  - Verified: `recovery.test.mjs` (new, 18 cases) PASS; vite build clean; all
    unit suites + gate8 PASS; LIVE browser↔CLI 2/2 (hook behavior + return shape
    intact).
  - Remaining Phase 2 concerns (React-glue heavy, build+live verified): the
    state-reducer (addPeer/updatePeer/upsertTransfer snapshot logic), the
    signaling-dispatcher (socket events → typed intents), the protocol-
    orchestrator (device matching / proofs / PAKE binding).

- **2026-06-16 — state-REDUCER pure core: `net/app/state.js`.**
  - Extracted the peer/transfer list transforms behind the snapshot helpers:
    `addPeerToList` (no dup), `patchPeerInList` (patch-existing-only, never
    resurrects #3), `removePeerFromList`, `upsertTransferInList` (new prepends,
    existing merges). Each preserves the same-reference-on-no-change contract
    React relies on. The hook keeps setPeers/setTransfers + the telemetry/logging
    + owner/status refs and delegates the list math.
  - Verified: `state.test.mjs` (new, 10 cases incl. the no-render reference
    checks) PASS; vite build clean; all suites + gate8 PASS; LIVE browser↔CLI 2/2
    (the state path is exercised on every peer-status / transfer-progress update).
  - Remaining Phase 2: the signaling-dispatcher (socket events → typed intents)
    and the protocol-orchestrator (its crypto is already in devices.js/pairing.js;
    what's left in the hook is mostly React wiring of those).

## Phase 3 — Rust main.rs split (started 2026-06-16)
Mirror the JS protocol/resilience split into `cli/src/main.rs` (8024 lines). Same
discipline: extract the pure POLICY into modules with `#[cfg(test)]` unit tests,
leave the stateful event loops (`send_cmd`/`recv_cmd`/`Conn`) delegating. The
netns lab is the PRIMARY end-to-end verification here (CLI↔CLI under injected
fault). Preserve the already-clean modules (l2/direct/holepunch/pake_ceremony/
session/codeentry/ui/sshkeys).

- **2026-06-16 — `cli/src/resilience.rs`: the stall-ladder decision (mirror of
  resilience/stall.js).**
  - Extracted `Conn::correct_stall`'s nested-branch ladder into a pure
    `decide_stall_action(attempt, max_repairs, warm_eligible, relay_forbidden,
    already_relayed) -> StallAction` (WarmCutover / Resume / Repair /
    RelayEscalate / ExhaustedRelayForbidden / ExhaustedAlreadyRelay).
    `correct_stall` keeps the warm-cutover guard, the state mutation, and each
    rung's side effect (escalate_to_relay / repair_link_in_place / ui lines) and
    matches on the action. 1:1 faithful.
  - Verified: `cargo test --release` 71/71 (8 new resilience::tests pinning every
    branch incl. the relay-forbidden-priority + warm-only-on-attempt-0 edges);
    `cargo build --release` clean; **netns lab** `two-nodes --link filament`:
    baseline 0% → fault stall 100% (link up) → fault clear → recovered 0%/1.3ms.
    No regression in the end-to-end stall→recover behavior.
- **2026-06-16 — `cli/src/protocol.rs`: the file-transfer decisions (mirror of
  transfer.js).**
  - Moved the pure file-transfer decisions out of main.rs into a `protocol`
    module: `recv_transfer_done` (the gate-2/11c "may we drop a dead link?" fence)
    and `decide_ack_fallback` + the `AckFallback` enum (the P4 no-ack window:
    Reprobe / FailUnconfirmed, never a false complete). Their unit tests moved with
    them; the send/recv loops call `protocol::…`.
  - Verified: `cargo test --release` 71/71 (the 3 protocol tests now run in
    `protocol::tests`); `cargo build --release` clean; LIVE browser↔CLI 2/2 — gate
    5 exercises `decide_ack_fallback` (CLI sender), gate 6 `recv_transfer_done`
    (CLI receiver). Pure move, no behavior change.
- **2026-06-16 — `protocol.rs`: the receiver verify DECISION (mirror of
  decideAfterVerify).**
  - Extracted the whole-file verify decision out of `verify_incoming` into a pure
    `decide_verify(received, size, hash_matches: Option<bool>) -> VerifyResult`
    (Match / Mismatch{restart_from_zero}); moved the `VerifyResult` enum to
    protocol.rs. `verify_incoming` keeps the I/O (flush, sha256, the test-corrupt
    hook) and the no-digest early return, and calls `decide_verify` for the
    classification (truncated → resume tail; full-size wrong/uncomputable hash →
    corrupt restart; match → accept). The file-end handler matches on
    `protocol::VerifyResult`.
  - Verified: `cargo test --release` 74/74 (3 new verify tests pinning the
    truncated/corrupt/match cases); build clean; LIVE browser↔CLI 2/2 — gate 6
    drives the real CLI receive→verify→delivery-ack path ("verified … acked").
- **2026-06-16 — `protocol.rs`: the control-message builders (the wire vocabulary).**
  - Replaced the inline `json!` control-message literals scattered through
    send_cmd/recv_cmd (11 sites) with `protocol::{offer_msg, accept_msg,
    decline_msg, end_msg, delivery_ack_msg}` — one definition per file-transfer
    message, mirroring frontend/src/net/protocol/transfer.js's builders. Control
    messages are parsed by key, so order-independent and interop-safe.
  - Verified: `cargo test --release` 76/76 (2 new builder tests pinning the exact
    JSON shapes incl. the optional head/full/resume); build clean; LIVE
    browser↔CLI 2/2 — gates 5+6 exercise EVERY CLI builder being parsed by the
    real browser, both directions byte-exact (the wire-compatibility proof).

  → Rust **protocol** module now holds the file-transfer decisions
    (recv_transfer_done / decide_ack_fallback / decide_verify + VerifyResult) AND
    the full control-message vocabulary. Rust **resilience** module holds the
    stall-ladder decision. Both mirror their JS counterparts, all unit-tested,
    lab- + live-verified.
- **2026-06-16 — `Conn` god-struct split: `ResilienceState` sub-struct.**
  - Grouped the six resilience fields (`stall_repairs`, `relay_committed`,
    `warm_standby`, `warm_cutover`, `upgrade_probe`, `iface_snapshot`) out of the
    ~30-field `Conn` bag into a named `ResilienceState`, accessed via `self.resil.…`
    (38 access sites renamed; both constructors — the `up` daemon literal and
    `for_command` — updated). Conn now carries `resil: ResilienceState`. Pure
    structural grouping, no behavior change; the stall/relay/upgrade bookkeeping is
    one cohesive unit instead of mixed into signaling/protocol state.
  - Verified: `cargo test --release` 76/76; build clean; **netns lab** stall→recover
    (0% → fault stall 100% → clear → 0%/1.46ms); LIVE browser↔CLI 2/2.
  - Next (larger, deferred): the remaining send_cmd/recv_cmd loop scaffolding (the
    chunk pump, the by_sid receive assembly), more resilience (upgrade probe / C4
    grace mechanics), and further Conn grouping (signaling vs protocol state).

## Post-merge follow-ups (branch: refactor/conn-split-cont, 2026-06-16)
PR #3 (the 20-commit consolidation) is merged to main. Continuing the Conn split.

- **2026-06-16: `Conn` split continued, `RejoinState` extracted.**
  - Grouped the peer-absence / rejoin-grace orchestration fields (waiting_rejoin,
    rejoin_window, away) out of Conn into a named RejoinState, accessed via
    self.rejoin.X (18 access sites; both constructors updated). deferred_left is a
    separate concern (#28 deferred drop) and was left in Conn for now. Pure
    structural grouping, no behavior change.
  - Verified: cargo test --release 76/76; build clean; live browser to CLI 2/2
    (one glare-flake retry, then green).
  - Conn is now down to ~17 fields with two named sub-structs (ResilienceState,
    RejoinState). Remaining bag: signaling/transport (sio, tx, server, my_uid,
    my_id), the link/roster registry, and direct_pending. The signaling group is
    the highest-churn (accessed at far more sites) so it is the next deliberate
    step, not a quick one.

### Next slices (Phase 1 continued)
1. ~~`protocol/transfer.js`~~ — DONE.
2. `resilience/*` — IN PROGRESS. Done: `stall.js` ladder shape. Next, each behind
   the freeze-shim browser gate / netns lab: stall detection reducer +
   StallController (timers/state); `upgrade.js` (relay→direct prober);
   `liveness.js` (`_checkPtyLiveness`/`_correctPtyDead`); `ackfallback.js` (the
   no-ack timer — `decideAckFallback` is already the pure seam in transfer.js).
3. Slim `PeerLink` to a thin orchestrator. Then Phase 2 (useFilament), Phase 3 (Rust).
