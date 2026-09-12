# Filament consolidation — GOAL / handoff charter

Historical consolidation brief. Read this only as an archive record; use the current documentation map for authoritative material. Its referenced wire spec is [`CONTRACT.md`](../../../CONTRACT.md), and its companion [`consolidation plan`](consolidation-plan-2026-06-15.md) is archived beside it.

design + progress log). You have full repo access at `/root/stunning-tribble`.

---

## 1. The goal (one paragraph)

Filament's networking has grown into three god-files where the **filament
protocol** (what bytes mean) and the **resilience protocol** (keeping a hostile
link alive) are mangled together with transport and UI. Separate them into clean,
SOLID layers with one-way dependencies, so each has one reason to change and can
be tested in isolation — **without changing observable behavior or the wire
format**. While in here, also fix the two gate suites that are currently red.

## 2. Definition of done (acceptance criteria — all must hold)

1. **`frontend/src/lib/webrtc.js`** decomposed into the layers: a Transport
   adapter, a `net/protocol/*` set (codec + ceremonies + transfer state machine),
   a `net/resilience/*` set (stall ladder, upgrade prober, liveness, ack-fallback),
   and a slim `PeerLink` that only orchestrates them.
2. **`frontend/src/lib/useFilament.js`** decomposed into a signaling-dispatcher,
   a protocol-orchestrator, a resilience-manager, and a state-reducer. The hook's
   **return shape is unchanged** (the UI contract — see `CONTRACT.md` §"UI contract").
3. **`cli/src/main.rs`** (8020 lines) has a `protocol` module (the file-transfer
   state machine extracted from `send_cmd`/`recv_cmd`) and a `resilience` module
   (stall ladder / upgrade / recovery extracted from `Conn`). Already-clean
   modules (below) are preserved, not rewritten.
4. **No gate regressions:** every gate green at the start of a slice is still green
   after it. (Establish the baseline first — see §6.)
5. **Red gates fixed:** `cli/tests/l2-gates.sh` → 5/5 and `cli/tests/ssh-gates.sh`
   → 4/4 green. (These were failing before this work — l2 3/5, ssh 1/4 — and may be
   a real bug in `filament ssh`/L2 or a test-env issue; diagnose first, see §5.D.)
6. **Wire compatibility intact:** `node cli/tests/l1a/gate8_byte_identity.mjs`
   passes, and a real browser↔CLI transfer + a browser↔CLI shell still work.

## 3. Hard constraints / non-goals

- **The wire protocol is frozen.** Byte-compatible across JS↔Rust at all times
  (`CONTRACT.md`). "Cleaner slate" applies to *internal* interfaces, never the
  bytes on the wire. If a change would alter a frame, control-message shape, or a
  ceremony, it is out of scope.
- **Frozen public seams:** the `useFilament()` return shape; `PeerLink`'s public
  methods/callbacks (used by `useFilament.js` and `WebTerminal.jsx`); the CLI
  subcommand surface. Keep or shim them.
- **The un-mangling rule:** if code has a timeout, a retry, or a reconnect, it
  belongs in RESILIENCE — never in PROTOCOL. PROTOCOL is pure codec + ceremony
  state and never owns a timer.
- **No behavior change, no new features.** This is structural only.
- **Do not touch the web shell** (`WebTerminal.jsx` etc.) — it's parked
  experimental. It only *consumes* `PeerLink`; don't break that surface.

## 4. Target architecture (five layers, one-way deps; same shape JS + Rust)

```
APPLICATION   file UX · PTY · L2 · device list   (useFilament public API — FROZEN)
ORCHESTRATION wires the three below per peer; connection state; signaling
RESILIENCE  ──────────────────┬── PROTOCOL  (the filament protocol)
 stall ladder, upgrade probe, │   message types, framing, encode/decode,
 liveness, ack-fallback/replay,│   ceremonies (PAKE, pair-keep/proof,
 reconnect budgets, recovery   │   file-offer/accept/end/ack, pty-*, l2-*, state)
 — OWNS every timer            │   — pure, NO timers, NO retries
TRANSPORT  the physical link only: send(bytes), onMessage, route, restartIce
```

Interfaces are already defined in `frontend/src/net/contracts.js` (Transport /
ProtocolCodec / ResilienceController). Dependency-invert: resilience & protocol
depend on the Transport *interface*, not concrete WebRTC/QUIC — that's what lets
the `lab` test resilience with no real WebRTC.

## 5. Work breakdown (per-slice recipe — do them in this order)

Each slice: extract → wire the old call sites to delegate → verify per §6 →
commit. Smallest verifiable slice first. Line refs below are **approximate /
pre-refactor — grep to confirm**, the file shifts as you go.

**A. Frontend `webrtc.js` (Phase 1)** — `frontend/src/lib/webrtc.js`
  - [DONE] `net/protocol/wire.js` — message registry + framing + control codec.
    (Already extracted + tested; `webrtc.js` already delegates.)
  - `net/protocol/transfer.js` — file-offer/accept/end/delivery-ack state machine.
    Worst tangles to pull from: `_streamFile` (~1242–1314), `_finishReceive`
    (~1097–1171), `_onControl` (~959–1095). Keep `decideAckFallback` (pure, ~62)
    as the seam; it's already unit-shaped.
  - `net/resilience/stall.js`, `upgrade.js`, `liveness.js`, `ackfallback.js` —
    pull `_checkStall`/`_correctStall` (~1437–1583), the upgrade prober
    (~643–801), `_checkPtyLiveness`/`_correctPtyDead` (~1585–1720), and the
    ack-fallback timers. These take a Transport handle + progress signals.
  - A Transport adapter wrapping the `RTCPeerConnection`/`RTCDataChannel` from the
    constructor (~326–531), `_setChannel` (~804–844), `_measureRoute`/`_detectRoute`
    (~584–641).
  - Slim `PeerLink` to orchestration only. Keep its public surface: callbacks
    `onStatus/onTransfer/onRoute/onChannelOpen/onStall/onPair*/onPtyData/onPtyClose/
    onPtyReady/onCaps`; methods `sendFiles/resumeSend/accept|declineTransfer/
    openPty/sendPtyInput/resizePty/closePty/sendBrb/sendBack/sendPair*/fingerprints/
    enqueueSignal/close/probeUpgradeNow`; exports `politeRole`, `PeerLink`,
    `decideAckFallback`.

**B. Frontend `useFilament.js` (Phase 2)** — `frontend/src/lib/useFilament.js`
  - Worst tangles: `makeLink()` (~299–514, all four concerns), the bootstrap
    signal handlers (~587–746), PAKE finalization (~814–885), `generateCode`
    (~956–1097), visibility/network recovery (~1124–1217).
  - Split into: signaling-dispatcher (socket events → typed intents),
    protocol-orchestrator (device matching, proofs, PAKE binding, ceremonies),
    resilience-manager (retry budgets, stall escalation, network-change recovery),
    state-reducer (the single place `setPeers/setTransfers/...` live).
  - **Return shape frozen.** Data flows one way: signaling → dispatcher →
    orchestrators → reducer → React.

**C. CLI `main.rs` (Phase 3)** — `cli/src/main.rs`
  - Extract `protocol` module: the file-transfer state machine out of `send_cmd`
    (~4381–5247) and `recv_cmd` (~5515–7418), plus verify/finalize.
  - Extract `resilience` module: `correct_stall`+`escalate_to_relay` (~3037–3282),
    `repair_link_in_place`, the upgrade probe, C4 grace/ICE-restart. Split the
    `Conn` struct (~1991–2198) so signaling/protocol/resilience state aren't one bag.
  - **Preserve** the already-clean modules: `l2.rs`, `direct.rs`, `holepunch.rs`,
    `pake_ceremony.rs`, `session.rs`, `codeentry.rs`, `ui.rs`, `sshkeys.rs`.
    (`net.rs` IS tangled — transport + signaling + Transport trait + Ev enum — and
    can be split too, lower priority.)

**D. Red-gate fix (can run in parallel; diagnose before fixing)**
  - `cli/tests/l2-gates.sh` (l2 3/5) and `cli/tests/ssh-gates.sh` (ssh 1/4).
  - First determine: real bug in `filament ssh`/L2, or test-environment flake?
    Read each gate script's header; run it; read its assertions. The L2/ssh paths
    live in `cli/src/l2.rs` + `main.rs` ssh subcommand. Fix the root cause; don't
    paper over a flaky test.

## 6. Verification protocol (per slice — the chosen bar)

- **Pure module** (no browser/network APIs) → add a plain-Node characterization
  test next to it (`*.test.mjs`, the `gate8` style) pinning current behavior.
  Model: `frontend/src/net/protocol/__tests__/wire.test.mjs`.
- **Any frontend slice** → `cd frontend && npx vite build` must be clean.
- **Any wire-touching slice** → `node cli/tests/l1a/gate8_byte_identity.mjs`.
- **Risky / non-pure slice** (transfer assembly, resilience timers, anything that
  moves real bytes) → run it LIVE before promoting:
  - Browser↔CLI gates: `cli/tests/browser-sender.js` / `browser-receiver.js`
    (Playwright; need a running app + a `filament` peer). Headers explain usage.
  - Resilience under fault: the `lab` skill (netns two-node; inject loss/latency/
    stall). Use for stall-ladder / upgrade / liveness slices.
- **CLI slices** → `cd cli && cargo build --release && cargo test`, then the
  shell gates: `cli/tests/gates.sh`, `transport-gates.sh`, `l2-gates.sh`,
  `ssh-gates.sh`, `holepunch-gates.sh`, `live-pairing-gate.sh`, `l1a/*`.
- **FIRST THING:** establish the full gate baseline (which pass / fail today) so
  "no regression" is measurable. The known-red ones are l2 (3/5) and ssh (1/4).

Run commands quick-ref:
```
cd frontend && npx vite build                                 # frontend compiles
node frontend/src/net/protocol/__tests__/wire.test.mjs        # wire char tests
node cli/tests/l1a/gate8_byte_identity.mjs                    # wire byte-identity
cd cli && cargo build --release && cargo test                 # CLI unit
bash cli/tests/gates.sh                                       # CLI gate suite (read header first)
cd frontend && npm run dev   # → http://localhost:5173/  (web-shell harness: ?preview=webterm&touch=1)
```

## 7. Current state (your starting point — 2026-06-16)

- Done + verified: `net/contracts.js` (layer interfaces); `net/protocol/wire.js`
  (extracted from `webrtc.js`, golden-tested); `webrtc.js` rewired to delegate.
  `vite build` clean, `wire.test.mjs` PASS, `gate8` PASS.
- Not yet re-verified live: the PTY framing path and file-transfer receive
  assembly after the wire extraction (the web-shell mock harness bypasses this).
  **Run a real browser↔CLI transfer + shell early** to confirm the wire extraction
  before building on it.
- Nothing committed yet by this effort — branch + commit per slice as you go.

## 8. Gotchas

- The web-shell mock harness (`?preview=webterm`) uses a fake link and does NOT
  exercise real framing/transport — don't mistake a green harness for a verified
  transport slice.
- `binaryType === 'arraybuffer'` on the data channel; `parseFrame` expects an
  ArrayBuffer. File buffers are assembled via `new Blob([...])`, which accepts
  `Uint8Array` — safe.
- Cross-impl crypto (`channelOf`/`proofFor` in `devices.js` ↔ Rust `channel_of`/
  `proof_for`) is pinned by `gate8` + the Rust `proof_matches_browser` test to the
  SAME external vectors. Touch with extreme care.
- CLI gates often need two nodes / network and can be flaky cross-machine (known).
  Prefer the `lab` for deterministic resilience repro.
