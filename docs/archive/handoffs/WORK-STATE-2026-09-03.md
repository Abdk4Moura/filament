# Work state and task list

> Living index of where filament + the product stand, written so context survives
> across sessions and compaction. The committed design docs are the source of
> truth; this file is the map and the ordering. Update status here as work lands.
> Last updated: 2026-08-25.

## One-paragraph state

filament's L3 data plane was moving to WireGuard, but only half of it landed:
`cli/src/wg.rs` is in main with `mod wg;` declared and ZERO callers, and
`feat/wireguard-l3` holds nothing main lacks, so the wiring has to be found or
rewritten (audit below). The identity/access/product design is complete and
committed. The trust root, L1 PAKE v2, is BUILT on the CLI side and running
today; what remains there is the server nameplate split, not the ceremony. Product thesis: a no-account pairwise mesh plus a secure
compute-pooling platform on top; the p2p send is the consumer wedge; enterprise
features are a demand-pulled compliance envelope built LAST.

## The core / product boundary (READ FIRST)

filament is the CORE/platform: pairing (L1), the transport ladder (L2), the overlay
(L3 = WireGuard), identity, capabilities, transfer, and `mount`, exposed through a
stable PRODUCT INTERFACE (the local control socket, `ctl.rs`). PRODUCTS -- the
compute/GPU product and any others -- are SEPARATE codebases that CONSUME that
interface. Nothing product-specific (GPU sandbox, job protocol, OpenAI routing)
lives in filament core. filament's job is to make itself usable for those purposes,
not to be them.

**NO BACKWARD COMPAT (2026-07-26).** No real users yet (owner + friends), so clean
breaks everywhere: no v1 paths, no fallback shims, no mixed-version negotiation, no
migration windows. Prioritize clean single-path implementations; everyone re-pairs
/ reconnects on the current format. (Applies to L1 gate #7 and the L2 per-sid v1
fallback, both dropped.)

## Master build order (and why this sequence)

THE TRUST ARC (sequential, one continuous code area, filament-professional):
1. **L1 PAKE v2** (trust root). CLI side BUILT (see the audit above); the server
   split remains. PAKE closes the first-pairing MITM gap; produces
   the per-device pinned secret + v2 device record. IN PROGRESS.
2. **Identity layer** (user-key over device-certs). The CONTINUATION of L1: extends
   the same pairing/device-record code; ADDITIVE on top of L1's device secret (user
   key vouches for device certs). SSH-CA shaped. filament-professional continues here.
3. **Capabilities / grant** (edge-local typed signed ops). Device-certs carry caps;
   generalizes L2's `filament grant`; the exposed authz primitive; meets the product
   interface at `open`.

PARALLEL CORE TRACKS (independent of the trust arc):
4. **L2 per-sid QUIC streams** (HoL-free multiplexing). NOT in main (see audit).
   Each sid its own QUIC
   stream. IN PROGRESS -> mimo-0x0 (`design-l2-perstream-quic.md`, single-path).
5. **Merge WireGuard L3 data plane** (`feat/wireguard-l3`). Built + measured, ready.
6. **Product interface** (`docs/design-product-interface.md`). Formalize `ctl.rs`
   into a stable local API + SDK. Exposes whatever identity/grant model exists, so
   it proceeds alongside the trust arc. Highest-leverage "make filament usable" move.

PRODUCTS (downstream, SEPARATE consumers of the interface):
7. **Compute product (lend-gpu).** GPU sandbox + consent + edge routing
   (OpenAI-compatible) + model distribution (`mount <cid>`). The p2p-send inverted.
   NOT filament core.
8. **Enterprise envelope** (org authority: SSO/audit/device-approval). LAST,
   demand-pulled, not a wedge.

REACHABILITY (a filament-core concern surfaced 2026-07-26, to spec): a public-IP
filament node doubles as the user's RENDEZVOUS + RELAY (not a coordinator; moves
ciphertext + brokers hole-punch, never authorizes). Multiple public nodes = an
interchangeable endpoint SET published in the DHT (introduce-gated, on top of the
pairwise core), TTL'd so a dead node drops and devices happy-eyeballs a live one
(failover without leader election). api.filament = opt-out-able hosted fallback.
Aligned with `design-mesh-network.md` (relay-peer doubles as rendezvous,
self-hostable, distinct services).

Fabric is the FOUNDATION we own standalone (Tailscale = compat bridge only). The
WEDGE is compute (govern USE, not reachability), built as a separate product ON the
core. Pitch: "secure compute pooling among trusted devices," never "a no-account
Tailscale."

## Build-order audit against `origin/main` (2026-08-28)

The WireGuard entry claimed "ready to merge" and turned out to be half-landed
dead code in main. That prompted checking the rest of the build order the same
way, against the tree rather than against memory. Each line below is what
`origin/main` actually contains, not what a section says.

| item | section claims | main actually has |
|---|---|---|
| 1. L1 PAKE v2 | "SPEC'D, to build; CLI/native side remaining" | `cli/src/pake_ceremony.rs`, 509 lines, using spake2, plus 9 `tests/l1a` gate scripts. The CLI side IS built and shipping: `add --word` runs the ceremony today. What IS still outstanding is the server split, `backend/signaling.py` still mints words. |
| 4. L2 per-sid QUIC | "IN PROGRESS -> mimo-0x0" | nothing. No per-sid wiring in `direct.rs`, and `origin/main..origin/feat/l2-perstream` is 0 commits, so the branch holds nothing main lacks. Not started, or lost the same way the WireGuard wiring was. |
| 5. WireGuard L3 | "Built + measured, ready to merge" | module + ADR present, `mod wg;` declared, ZERO callers. Half-landed, dead code. See the section below. |
| 6. Product interface | "CORE, to build" | `ctl.rs` is 849 lines with ~21 ops, no version field, no published contract. Accurate as written: the seam exists, the contract does not. |

So two of the four entries overstate what exists (L1 partly, WireGuard badly),
one understates it (L2 is not in progress, it is absent), and one is right.

THE PATTERN, and it is the same one that produced the stale path pointers and a
CI red misread as a regression: a status line is a claim about the tree that
nobody re-checks, and it ages badly precisely where the work was interrupted.
Anything here worth acting on should be re-verified against `main` first. It
takes one `git grep` per entry.

## Status by workstream

### WireGuard L3 data plane -- HALF-LANDED IN MAIN, and it is dead code there

> CORRECTION (2026-08-28). This section said "ready to merge" and named three
> commits: adr `6639d6d`, wg module `691a4be`, wiring `08f72a4`. Checked against
> `origin/main`, none of those three SHAs is an ancestor of main, so the numbers
> are stale (the work reached main through different commits). What IS true:
>
>   - `cli/src/wg.rs` (173 lines) is in main, via `ec5d400`.
>   - `docs/adr-0001-wireguard-as-l3-data-plane.md` is in main.
>   - `main.rs` declares `mod wg;`.
>   - NOTHING in main calls it. Zero `wg::` references anywhere under `cli/src`.
>
> So the carrier module is compiled into every shipped binary and reachable from
> nothing: the wiring that made `serve-tun --wireguard` real did not land with
> it. The measured numbers below were taken with that wiring in place, so they
> do not describe main today.
>
> `origin/main..origin/feat/wireguard-l3` is empty, so the branch cannot supply
> the missing piece either. Before this is called done, someone has to find where
> the wiring went, or write it again against the current `direct.rs`/`l3.rs`,
> which have both moved into `filament-transport` since.

### WireGuard L3 data plane -- the original entry (numbers predate the split)
- ADR: `docs/adr-0001-wireguard-as-l3-data-plane.md`
- Branch `feat/wireguard-l3`: adr `6639d6d`, wg module `691a4be`, wiring `08f72a4`.
- Numbers: loopback 0.48 -> 1.37 Gbps (0 retransmits vs 382); cross-machine
  do-vm<->other-do (~2 Gbps UDP policer) 396 -> 1256 Mbps (~99% of the UDP ceiling,
  near-clean). WG is env-bound here (shared CPU / policer), not its own ceiling.
- `serve-tun --wireguard`: filament brokers WG keys over its authed conn; kernel WG
  moves bytes. `cli/src/wg.rs` + `main.rs` wiring.
- NEXT: final review + rebase on main + merge. Bench scripts in the job tmp
  (`l3bench.sh`, `wgbench.sh`, `cross_wg_bench.sh`).

### L1 PAKE v2 (trust root) -- CLI SIDE BUILT; SERVER SPLIT OUTSTANDING

> Corrected 2026-08-28 against `origin/main`, see the audit above. The heading
> said "to build". The CLI/native side IS built and shipping:
> `cli/src/pake_ceremony.rs` is 509 lines using spake2, with 9 `tests/l1a` gate
> scripts, and `filament add --word` runs the ceremony today. What remains is
> the server nameplate-only split: `backend/signaling.py` still mints words.
- Spec: `docs/L1-pake-protocol.md` (decisions §13, 2026-07-26).
- Locked: v2-only cutover (no v1 fallback); auto-mint 16-bit (256x256);
  user-chosen gate = "2 distinct words, not a common phrase"; gate #3
  (burn-on-claim + no-retry) HARD + negatively tested; nameplate 900 + monitor;
  `spake2 = "=0.4.0"`.
- Browser PAKE v2 substantially built (`frontend/src/lib/words.js`, `pairing.js`,
  `PakePairing`, custom-code form). Remaining: CLI/native side, server
  nameplate-only split (remove word minting in `backend/signaling.py`), decisions
  2-4, and the §10 gates (esp. negative gates #2 server-can't-derive, #3 burn+no-retry).
- NEXT: contract to filament-professional.

### L2 per-sid QUIC streams -- NOT STARTED IN main (heading said IN PROGRESS)

> Corrected 2026-08-28. `origin/main` has no per-sid wiring in `direct.rs`, and
> `origin/main..origin/feat/l2-perstream` is 0 commits, so that branch holds
> nothing main lacks. Either the contracted work has not landed, or it went the
> way the WireGuard wiring did. Worth confirming with mimo-0x0 before anyone
> plans around it as in-flight.
- Spec: `docs/design-l2-perstream-quic.md` (PROPOSED). Each L2 `sid` gets its own
  QUIC bidi stream (QUIC gives per-stream flow control + no cross-stream HoL), so a
  stalled stream no longer blocks the others. App-credit (`feat/l2-credit`) was
  tried and FAILED validation. SINGLE PATH (no v1 fallback / no compat needed).
- File: `crates/filament-transport/src/direct.rs` (moved out of `cli/src` on
  2026-08-27; also touched by the WireGuard branch, merge ordering TBD).
- NEXT: mimo-0x0 returns a plan, then implements; money test = fast stream not
  blocked by a stalled slow stream over one link.

### Product interface -- CORE, to build
- The seam: `ctl.rs`, the local 0600 unix control socket (JSON line + reply +
  raw bytes; ~15 internal ops today: open/dial/pty/mount/...). Used only by the CLI
  talking to its own daemon; internal and unstable.
- The work: (1) stabilize + version + document it as a public contract; (2) fill
  gaps a product needs -- identity/pair, peers + an EVENTS subscription, open a
  stream to peer:action gated by the grant model, transfer, grants, mount; (3) a
  thin SDK (Python first for the compute MVP, then Rust/JS).
- Boundary: filament owns the API + primitives; products own compute-specific logic
  on the consumer side. Capabilities meet the interface at `open`.
- Spec: `docs/design-product-interface.md` (design 2026-07-26, stress-tested):
  versioned JSON-NDJSON over UDS, persistent-subscription events (2 lanes,
  replay), grants = authz + registration = service-discovery/consent, 0600 now +
  scope-able later. Build seq ends by porting the lend-gpu MVP onto the SDK.

### Identity + access UX -- DESIGNED + COMMITTED
- `docs/design-identity-access-ux.md`: onboarding, contact book, introduce,
  recovery presets, capabilities (edge-local typed-signed-op CRDT), postures +
  enterprise-as-envelope positioning.
- `docs/design-introduce-user-identity.md`: user-key over device-certs (SSH-CA
  shaped), introduce-to-one-device, privacy of the device set.
- Recovery: 2 dials -> 4 presets (Anonymous-purist / Consumer-default /
  High-availability / Trusted-circle); blind federated timestamping witness for the
  compromise race; 7-day pending + old-key freeze; duress PIN; private per-contact
  contacts.

### GPU / compute product -- FEASIBILITY + POSITIONING COMMITTED
- `docs/gpu-product-feasibility.md`: trusted-group edge inference is the feasible
  wedge; open marketplace gated on verifiable-compute + open-DHT Sybil;
  identity-continuity is the owed design.
- lend-gpu MVP: `runner/` Python (23 tests): sandbox (`--network none`, mem/cpu
  caps) + consent gate + send/borrow. Awaiting GPU-host validation + Rust subcommand.

### Mesh / discovery -- DECIDED (filament stays pairwise)
- `docs/design-mesh-network.md`: no mesh/DHT/coordinator in filament core. Any
  product discovery rides on top; closed-by-default, introduce-gated (Sybil research
  conclusion: introduce IS the Sybil defense).

## Pointers
- Memory: `gpu-product-mesh-wireguard.md` (durable summary of all of the above).
- Portfolio (public): "The Data Plane Underneath", "Who are you, really".
- Adversarial design reviews this session ran through xats agent `wise-agent`.


## 2026-08-25: fleet auto-mesh, L3 default-on, L3 over relay

Branch `work/fleet-automesh`, uncommitted. Design:
`docs/design-fleet-automesh.md`, `docs/design-l3-over-relay.md`, and the
amendment section in `docs/design-mesh-network.md`. Proof:
`proofs/fleet_automesh_model.py`, gated in `.github/workflows/proof.yml`.

### Landed and verified on real daemons

- **Fleet auto-mesh.** Devices holding a DeviceCert from the SAME owner key
  discover each other on one rendezvous channel and admit on the certificate,
  never on presence. Verified with three daemons where B and C never exchanged a
  code or secret and each ended up seeing the other.
- **L3 on by default.** `tun-addr` defaults to `auto`; `filament init` asks for
  the one-time CAP_NET_ADMIN grant. Verified: a fresh install brings up
  `filament0` dual-stack with a working `<name>.mesh`.
- **L3 over relay.** IP packets ride a reserved sid on the DataChannel, and the
  announce is bound by a per-link nonce challenge because webrtc-rs exposes no
  RFC-5705 exporter. Verified: with the direct ladder refused, `ping6` across the
  overlay returns 3/3 over a DataChannel-only link.
- **`expected_secret` sweep.** All 44 sites audited; two were wrong (the
  in-session pairing ceremony could be consumed by a fleet peer, and
  `digest_says_alone` mis-counted fleet links).
- Incidental: pidfile compat fix (`e76d6d6` wrote two lines, this branch parsed
  one), which had made `status` blind to a running daemon and would have let `up`
  start a second one on the same config.

### Next, in order, with the obligation attached

1. **Fleet peers: indexed (DONE), addressable (OPEN).** A verified sibling is now
   written to `devices.json` and listed under FLEET with an empty ceiling, with
   NO pair secret, so it can never become a channel subscription or dial target.
   Two related fixes went with it: the listing iterated `devices_load()` (which
   requires a secret, hiding the very records it should show), and the FLEET tier
   asked `load_owner_key()`, "do I hold the owner's PRIVATE key", so every joined
   device rendered its own siblings as EXTERNAL.
   CLOSED BY 1h FOR SEND, THEN FOR THE REST. `send --to <sibling>` was brokered
   first (58/58): the daemon mints a single-use secret over the cert-verified
   link, so there IS a secret to dial with.

   For a while only send had it, and that was found by call site rather than by
   assuming either way: `ctl::try_fleet_rendezvous` had exactly one caller,
   `send_cmd`. `shell`, `forward` and `mount` never asked for a ticket, so they
   still hit the no-secret wall this item was opened for. Generalising "send
   works now" to "the L2 verbs work now" would have been the narrow-view error
   this file keeps recording.

   NOW DONE (commit "l2: let every verb dial a sibling, not just send"). The
   broker call went into `bring_up_to_known` (cli/src/l2.rs), the ONE place an L2
   verb turns a name into a secret, so pty (shell), shell_bootstrap (ssh), netcat
   (forward), mount_cmd and establish_probe (doctor) all inherit it instead of
   five call sites each carrying a copy.

   Strictly additive: brokering is tried first and the fleet-secret fallback is
   untouched, so no daemon, no verified link, or a non-fleet name behaves exactly
   as before. `fleet_mode` is false for a brokered secret, matching send_cmd, and
   the 1h rule holds unchanged at the daemon end, which brokers only over a link
   with a Proven identity binding (`warm_link_for`), never on presence. Setting
   `fleet_mode` true would BREAK it: the fleet challenge waits for the crowded
   channel's hello, which a two-party brokered link never sends.

   STILL UNMEASURED, and this is the honest gap: the sibling dial itself. It
   needs three devices, two of them siblings not paired with each other, and the
   record below is that sibling numbers from an unvalidated rig are worse than no
   numbers. The mechanism is the one measured at 58/58 for send, but that is an
   argument for expecting it to work, not evidence that it does.
   **RESOLVED (2026-08-26): the obligation is discharged.** The negative test has
   now been RUN and PASSED. With `laptop`'s shell acceptor armed for a different
   device, a fleet sibling with zero grants is denied by the gate itself:

       l2: pty refused: phone: not in auth key caps

   while `reach` over the same link succeeds. Reachability and capability are
   demonstrably separate. Three bugs had to be fixed first, each of which stopped
   the request BEFORE the gate and each of which presented as "peer unreachable":
   the warm path is skipped for non-tty stdio (so redirected test runs never
   asked the daemon); fleet dial GLARE (both ends dialing, 1 verify / 10 drops,
   never settling, fixed with a deterministic `conn.my_id < pid` tiebreak, after
   which it is 1 verify / 0 drops); and `warm_link_for` gating on `l.trusted`,
   which a fleet link deliberately never sets.

   **UX DEFECT: FIXED.** A refusal used to present as a reachability failure.
   Measured from a real terminal:

       before:  45s   ->  "can't reach 'laptop' ... it may be offline"
       after:   28ms  ->  "the peer closed the shell request (capability not granted?)"

   Four layers, each hiding an answer the peer had already given:
   1. `l2-open` and `l2-close` shared the `l2_enabled` guard, which answers "will
      I ACCEPT inbound opens". Right for an open, wrong for a close, since a
      close is the peer answering a stream WE opened. So the client discarded the
      refusal it had just asked for. Split, and this was the load-bearing one:
      the close now reaches `Mux::on_close`, which drops the stream, which ends
      `verify_first_frame` with "closed before any frame" instead of a timeout,
      which is what lets a client tell a REFUSAL from a dead link.
   2. The daemon treated EVERY warm-pty failure as a zombie, tearing down a
      healthy link on every refusal. Only silence inside the verify window is a
      zombie now.
   3. `ctl::try_pty` collapsed every rejection to a bare `None`, losing the
      reason. `try_pty_reason` carries it.
   4. The client fell through to a COLD retry on refusal, and that retry died at
      name resolution, so ITS error is what surfaced. A `refused:` reason is now
      definitive and stops there.

   The identical hole had already been found and fixed once for MOUNT: see the
   #206 comment on `Mux::on_close`, which records that the reason "was dropped
   here and the initiator read a generic channel-closed". The pty path had it one
   layer up and nobody had walked it.

   **RELEASE-VERIFIED (2026-08-26).** Release build succeeded, installed, and
   re-verified on the release binary: three-node mesh forms with B and C never
   paired (A sees laptop+phone, B sees owner+phone, C sees laptop+owner), and the
   deny path reports "the peer closed the shell request (capability not
   granted?)" in ~2s rather than 45s of "may be offline". 410/410 tests green.
   The shipped binary carries no test hooks.

   **(historical note)** Everything from the `verified_name` binding onward is
   type-checked and exercised with a DEBUG build (release builds were killed
   externally three times, not OOM). Release-build, run the full suite, and
   install before relying on any of it. A `fleet-hello decision ...` debug line
   was left in the ChannelReady path deliberately; it is what made the glare
   diagnosable and is debug-level only.

   **Obligation, unchanged:** that step promotes the empty-ceiling capability
   gate from a second line of defence into the load-bearing one. A fleet peer is
   still stopped earlier, at name resolution and link establishment, so the gate
   has never been exercised live. Re-run the negative test (a fleet peer
   attempting `shell` and `send --to` against a sibling that granted it nothing)
   as PART of that change, not after it.
1a. **PRIVILEGE ESCALATION FOUND AND FIXED (2026-08-26).** Read this before
   touching fleet links. `adopt_direct` inferred the Fleet intent from the local
   `DirectPending`, which only the DIALER has, so every ACCEPTED fleet link was
   born `trusted: true` + OwnerDevice. Default-on, not limited to the opt-in send
   path. Caught live: a device whose `transfer` grant had been REVOKED still
   delivered a file (sha256 verified), because the acceptor granted it
   owner-equivalence at link birth, before capabilities were consulted. Fixed by
   failing safe with no pending: a peer we hold a PAIR secret for is that device;
   anything else, while a fleet secret exists, stays untrusted until
   `fleet-hello` names it. Re-verified: mesh still forms on all three nodes, and
   the revoked peer's file no longer lands. Full write-up in
   design-fleet-automesh.md.

1b. **`send --to` to a fleet sibling: MISDELIVERY FIXED. Opt-in, still OFF.**
   Root cause: `fleet_proven` was a single bool meaning "some peer proved", read
   everywhere as "THIS peer proved". With several siblings on the fleet channel,
   one peer verifying opened the offer guard for all of them. Measured: verified
   pid=8gNe as 'laptop', offered to pid=yNDj (the owner), which accepted.
   Fixed by making it a per-peer set. Re-verified in the same scenario: verified
   pid and offered pid now match, the offer is declined, and NO node receives
   anything.
   SECOND TOPOLOGY CONFIRMS (2026-08-26), with per-node inboxes:
     joined -> joined (C -> laptop): verify pid == OFFERING pid, declined,
                                     NO node received anything.
     joined -> owner  (C -> owner):  delivered to the owner's inbox only, which
                                     is correct (they are paired; the normal
                                     path, untouched by the fleet work).
   So the per-peer fix holds across sender/target roles and the ordinary paired
   send is unaffected. The warning was corrected from "KNOWN to deliver to the
   WRONG device" (no longer true) to "experimental, one topology".

   STAYS OPT-IN, deliberately. The path is now CORRECT but not USEFUL: a transfer
   to a sibling still cannot succeed, because a joined device has no owner-signed
   capability state to authorize it (item 2). Flipping the flag on today would
   replace a clear "not yet a send target" message with a decline, which is worse
   for the user. Enable it when item 2 lands, not before.

1b-old. **(withdrawn framing kept for the reasoning) BLOCKED on the trust floor**
   CORRECTION to an earlier note in this file: I recorded this as "WORKS, end to
   end, sha256 verified". That result was real but it was produced by the
   escalation in 1a. With the escalation fixed, it does not deliver, and the
   earlier success was the bug rather than the feature.

   What IS built and verified: certificate-verified dialing of a sibling,
   wrong-sibling rejection (measured: asked for `laptop`, `owner` answered, and
   it refused rather than misdeliver), and offers gated on identity.

   THE BLOCKER (corrected). An earlier version of this entry said "blocked on the
   trust floor". That was WRONG: `cap_trust_floor` already passes when
   `binding == Proven`, which a verified `fleet-hello` sets. Do not redesign the
   trust model on the strength of that sentence.

   What is true:
   - DEFAULT (shadow) mode falls back to `legacy_ok`, which in daemon mode is
     `link_trusted`. A fleet link is untrusted by design, so it declines. That is
     section 4b working, not a defect.
   - Under `FILAMENT_CAP_AUTHORITATIVE=1` the capability layer ALREADY has a
     fleet transfer path (`cap_fleet_inputs` + `scoped_in_bounds`): a same-owner
     Proven device may land a file inside the receiver's own drop dir. The
     mechanism exists and was built for this case.

   ROOT CAUSE FOUND AND FIXED, then a SECOND one found (2026-08-26).

   FIXED: the offer was never emitted. `send_cmd` defers offers until identity is
   proven, but the offer lives in the `ChannelReady` handler, which had already
   run and deferred. Setting `fleet_proven` without RE-ENTERING that handler
   meant the offer never happened at all: sender sat until timeout, receiver's
   gate never saw a request. The PAKE path documents the same remedy for itself
   ("sets `pake_done` and re-emits ChannelReady to fall through here and offer");
   the fleet path now re-emits too. Verified: the offer reaches the gate.

   REMAINING, and it is a policy-store gap, not plumbing. With the offer
   arriving, the receiver's gate reports:

       transfer-gate: allowed=false binding=Proven own_user=false has_grant=false
                      in_bounds=true revoked=false authoritative=true

   `own_user=false` is the blocker. `cap_fleet_inputs` derives it from a
   `cap_header` in the capability store, and a JOINED device does not have one:
   measured, the owner device has `caps.json` with a cap_header, the joined
   device has no `caps.json` at all. So the fleet-scope transfer path (the one
   built for exactly this case) can never engage on a joined device, and the
   `has_grant` path cannot either, because grants are evaluated against that same
   store.

   ITEM 2 PROGRESS, measured (2026-08-26/27):
     - `cap_header` delivered at enrollment: WORKS. Gate now reports
       `own_user=true` where it was `false` before. That is the header doing
       exactly its job.
     - `cap_ratchet` initialised on the joined device: WORKS. An owner has
       `{cap_header, cap_ratchet}`; a joined device had only the header, which is
       half of what `ensure_self_genesis_header` writes. The ratchet needs no
       signature (local anti-rollback keyed on owner_pub, which the header
       carries), so the joiner creates its own. Verified: B's store now has both.
     - End-to-end transfer to a sibling WORKS, with an explicit grant:

           filament grant <sibling> transfer     (on the receiver)
           gate: allowed=true legacy_ok=false trusted=false binding=Proven
                 own_user=true has_grant=false in_bounds=true
           inboxes: owner[]  laptop[gr.txt]      <- the NAMED device

       `legacy_ok=false` and `trusted=false` matter: the link is NOT trusted, so
       this was authorized purely by the capability layer, and the file reached
       the device the user named rather than the owner.

     WHY THE EARLIER DENIALS WERE CORRECT, not a bug. Answered by READING
     `cap_gate_effective` rather than more instrumenting: the delegated-principal
     ceiling (check 2 of 2) is unconditional in both modes and purely
     restrictive. A fleet link is admitted with `device_caps(name)` as its
     ceiling, which is `Some([])` for a sibling with no grant, so it denies
     before the fleet-scope branch is ever consulted. Every earlier measurement
     was taken WITHOUT a grant. That is section 4b working exactly as designed:
     reachability by default, capability only on an explicit grant.

     So item 2's first two increments (header + ratchet delivery) are sufficient
     for granted transfer. What remains of item 2 is the ungranted fleet-scope
     case and grant DISTRIBUTION, not this.

   ORIGINAL NOTE. FIRST INCREMENT OF ITEM 2 IS LANDED (2026-08-26): the owner now hands its
   signed `cap_header` to a joining device in the enrollment ack, and both join
   paths store it. VERIFIED: after a fresh three-node enrollment all three
   devices have a `cap_header`, where previously only the owner did. The header
   carries no secret (signed, self-certifying, names `owner_pub` + nonce), and
   authoritative mode is off by default, so default behaviour is unchanged.

   CHARACTERISED, and a false alarm RETRACTED. Correcting two earlier notes in
   this file, both of which were wrong.

   Wrong note 1: "timing-dependent / flaky". Repeated runs against one stable
   fleet in default (shadow) mode are 3/3 identical:
       verifying fleet identity -> declined
   Consistent, not flaky.

   Wrong note 2, and this is the important one. Three authoritative-mode runs
   showed run 1 DELIVERING a file with zero `transfer-gate:` lines, which I began
   recording as a suspected authorization hole. IT IS NOT. The test harness was
   at fault: all three nodes had `dir` unset, so A, B and C shared ONE inbox
   (`/root/Filament`). "A file appeared in the inbox" therefore could not
   identify WHICH node accepted it, and C is legitimately paired with A, so a
   file A accepted over its normal trusted link looked exactly like B accepting
   one without a gate check.

   Re-run with a distinct inbox per node:
       verifying fleet identity -> declined,  and NO node received anything.

   So the behaviour is correct and there is no hole. Recorded at length because
   the near-miss is the lesson: the measuring instrument could not tell the
   nodes apart, and it produced a false security finding that was one step from
   being written down as real. Any future fleet test MUST set a distinct `dir`
   per node before its results mean anything.

   ORIGINAL CLOSING NOTE: this IS item 2, not a separate bug. A joined device
   cannot simply create the missing header. `ensure_self_genesis_header` SIGNS it
   with the owner's `UserKey` (`sign_cap_header`), which a joined device does not
   hold and cannot synthesize. The header is an owner-signed artifact, so a fleet
   device can only RECEIVE one, the way it receives `fleet_rv`, and it would also
   need owner-signed grant entries to evaluate `has_grant` at all.

   That is precisely the deferred design, and the codebase says so itself: the
   `cap_authoritative` doc comment calls the env var "the opt-in switch, pending
   same-owner fleet-trust that makes the default-on flip safe". Distributing
   owner-signed capability state to fleet devices IS same-owner fleet-trust.

   So the two open items collapse into one. Do item 2 (owner-signed fleet
   ceiling / policy distribution) and `send --to` for siblings follows from it;
   there is nothing separate left to fix in the transfer path. Everything
   upstream of the capability store now works and is measured: dial, certificate
   verification, wrong-sibling rejection, offer emission, and delivery of the
   offer to the receiver's gate.

   (superseded note follows)
   ANSWERED (2026-08-26). The receiver's transfer gate is now instrumented (a
   `transfer-gate:` debug line carrying allowed / legacy_ok / trusted / binding /
   own_user / has_grant / in_bounds / revoked / authoritative / reason, visible
   at `-vv`). Run with the receiver in authoritative mode and a `transfer` grant
   in place: the line NEVER FIRES. The offer does not reach the capability layer
   at all, so nothing about caps, floors or grants is responsible.

   The blocker is UPSTREAM of the gate: either the sender never emits the
   file-offer, or the link does not carry it. Note the sender also printed
   nothing under `-vv` before its timeout, which points at the sender side.
   Start there, not in capability.rs: find where `send_cmd` stops after
   "verifying fleet identity" succeeds, i.e. whether it ever reaches its offer
   emission for a fleet target. The gate instrumentation is kept (debug-level,
   one line per offer) because it is what turned a plausible wrong answer into
   a measured one.

   The opt-in stays OFF; `send --to <sibling>` keeps the accurate
   "not yet a send target" message.

1c. **(historical: the earlier assessment that this needed its own session)**
   Set `FILAMENT_FLEET_SEND=1` to exercise it. Off by default because a
   half-finished feature should not be the default path; without it the clear
   "not yet a send target" message is what users get.

   WHAT WORKS AND IS VERIFIED LIVE:
   - `send_cmd` resolves a fleet sibling as a target and dials it on the fleet
     secret / fleet channel.
   - Offers are GATED on the peer's certificate, so nothing is offered to an
     unproven peer.
   - Wrong-sibling detection works and was measured: asked for `laptop`, the peer
     that answered first was `owner`, and it refused with "proved a different
     identity. Nothing was sent." Without that check the file would have gone to
     the wrong device. This is the single most valuable part of the work.
   - After the skip-and-keep-looking fix, the sender then reaches the RIGHT peer.

   WHAT IS NOT FINISHED: the binding handshake on a transport with no RFC-5705
   exporter. The peer's `fleet-hello` can arrive before the sender has set up its
   challenge nonce, so `fleet_bind_ours` is still None and verification fails
   closed with "cannot verify its certificate". Fails SAFE (never misdelivers),
   but does not complete. The daemon solves the same problem in its ChannelReady
   path; the sender needs the equivalent ordering, which most likely means
   establishing the nonce before the link can deliver control messages rather
   than on ChannelReady.

   Also landed and independently useful: `bring_up_to_known` (l2.rs) now dials a
   fleet sibling and calls `verify_fleet_identity` before returning the link, so
   the COLD paths (ssh / netcat / forward / pty) get certificate-checked fleet
   dialing.

1c. **(superseded assessment, kept for the reasoning)**
   This is the last gap for fleet peers (every other verb works: see the
   verb-by-verb table in design-fleet-automesh.md). It needs the daemon to run a
   transfer over a link the one-shot cannot dial, which means a new warm-send
   request kind AND a transfer core that can run over an EXISTING transport.

   The cost is the reason it is not done. `send_cmd` is `cli/src/main.rs`
   13077-14356, about 1280 lines, and it interleaves connection establishment,
   the PAKE ceremony, its own event loop, offers, chunking, resume and progress
   UI. Nothing separates "set up a link" from "move the bytes", so a warm-send
   means extracting the transfer core out of the most safety-critical path in the
   product, one with a documented corruption history and its own resilience
   gates. Duplicating it into the daemon instead would be worse.

   **The cheap-looking alternative is worse, do not take it.** The obvious
   shortcut is to skip the daemon entirely and let the ONE-SHOT dial the sibling
   itself: `fleet.rv` is on disk, so `bring_up_to_known` (l2.rs:1048) could fall
   back to the fleet secret and the fleet channel when there is no pair secret,
   and every verb would work with no `send_cmd` change at all.

   It breaks on identity. A pair channel has exactly ONE peer on it, which is why
   that function can dial "the known device" it finds there. The FLEET channel has
   every sibling on it, so the one-shot would have to pick by the peer's
   ADVERTISED presence name, which is self-asserted and unverified at that point.
   Any fleet member could answer to "laptop" and receive the file. The daemon does
   not have this problem because it runs `fleet-hello` and checks the certificate
   before admitting; a one-shot taking this shortcut would be trusting a name.
   (This is the same trap as 4c in design-fleet-automesh.md: a proven key is not a
   proven name. It has now bitten in three separate places.)

   So the shortcut also needs certificate verification on the sending side, which
   is most of the work it was supposed to avoid. Either route needs identity
   verification before bytes move; the daemon route at least reuses the one that
   already exists and is tested.

   That refactor deserves its own session, run against the transfer gates and the
   test-record pipeline, not a tail-end change. Meanwhile the gap is signposted
   rather than silent: `send --to <sibling>` names the limitation and points at
   the two things that DO work (the peer's `.mesh` address, or pairing directly).

1d. **Ungranted fleet-scope transfer: DONE (`PrincipalKind::FleetDevice`).**
   A sibling with NO grant now lands a file in the receiver's drop dir; the
   deliberate tier stays grant-only. Measured:
       transfer, no grant -> allowed=true has_grant=false in_bounds=true,
                             delivered to the NAMED device
       shell,    no grant -> refused, "capability not granted"
   410 bin tests + 90 capability-crate tests green.

   The earlier entry below called this a security-model change on the grounds
   that a ceiling-less kind would inherit the owner shortcut. That reasoning was
   WRONG: `cap_gate_effective` already discards the owner shortcut for a
   same-owner peer and recomputes from fleet policy (its own finding-#24 note
   says so). The policy was already written and reviewed; it could simply never
   be reached, because `Delegated`'s ceiling is unconditional and a sibling
   starts with an empty one. `Delegated` was wrong twice over: it also means
   "ephemeral, drop on disconnect", which a persistent sibling is not.

1d-old. **(superseded analysis, kept for the reasoning) needed a NEW PRINCIPAL KIND** The capability layer already implements the policy: a same-owner
   Proven device may land a file inside the receiver's own drop dir without a
   grant (`cap_fleet_inputs` + `scoped_in_bounds`). It cannot fire for a fleet
   link, and the reason is structural rather than a tweak:

   - `cap_gate_effective` applies the delegated ceiling only `if let Some(caps) =
     auth_key_caps`. A `Delegated` principal always has a ceiling; an empty one
     denies everything before fleet-scope is consulted.
   - So reaching fleet-scope requires `auth_key_caps == None`, i.e. NOT
     `Delegated`. The only other kind is `OwnerDevice`, which is owner-equivalent
     and is exactly the escalation removed earlier in this session.

   There is no kind that means "identity proven, no ceiling, NOT owner". That is
   what ungranted fleet-scope needs, and inventing it is a security-model change,
   not a one-line default flip. Note this also means the conservative empty
   ceiling chosen in 4b is not merely cautious: given the current kinds, it is
   the only safe option.

   Granted transfer already works today and is verified, so this affects the
   no-grant convenience case only.

1j. **The gates' fault-injection hooks were compiled out, and the warning
   ratchet hid it (2026-08-29).** Read this before trusting a P1 or P5 number
   taken between the transport carve and this fix.

   `filament-transport` was carved out of `cli/src` with its
   `#[cfg(feature = "test-hooks")]` blocks intact, but the feature DECLARATIONS
   stayed in `cli/Cargo.toml`. A cfg naming a feature its own crate does not
   declare is unconditionally false, and `test-hooks = []` in the CLI enables
   nothing in another crate. So ~20 hooks in `direct.rs` and `net.rs` were
   stripped from every build, including the gates' `--features test-hooks` one:
   the data-path freeze, the persistent freeze P1's relay fallback needs, the
   unblock P5's upgrade needs, the flaky-standby no-flap probe.

   NOT A MISSING FEATURE, A MISSING INSTRUMENT. P1 and P5 do not assert "a freeze
   happened", they assert the transfer completed. With the freeze never injected
   it completes directly, so the gate can report success while proving nothing
   about fallback. A detector cannot be validated by its own clean-run count.

   THE RATCHET IS WHY IT SURVIVED, and this is the transferable part. rustc
   emitted "unexpected cfg condition value: test-hooks" on every build, 28 of
   them counting `debug-logs`. They sat inside the ratchet's total of 185, and
   the ratchet only forbids that number going UP. A warning already in the
   baseline is invisible forever: the job stayed green while printing the defect
   every run. A count is not a reading. Anything that classifies warnings, rather
   than totalling them, would have caught this the day it landed.

   Fixed by declaring both features on the crate and FORWARDING from the CLI.
   Verified by building: all four env strings present under `--features
   test-hooks`, all absent from release (CI's no-hooks-in-release assertion still
   holds), the 28 cfg warnings gone.

   THE GATE NUMBERS ARE NOW UNKNOWN, in both directions. If P1/P5 were among the
   tracked-red gates this may turn them green; if they were passing they were
   passing vacuously and should now fail honestly. Nothing was added to
   EXPECTED_GREEN, because that list is measured and this invalidates the
   measurement it would rest on. Re-run the gates and re-establish it.

1ah. **Gates Core red on 991c5e08 was a TIMEOUT, not a failing gate
   (2026-08-31).** Recorded because "Gates Core is red" invites the wrong
   diagnosis. The annotation is:

     The job has exceeded the maximum execution time of 1h30m0s
     deterministic core ratchet ... The operation was canceled.

   No gate asserted. It ran out of wall clock at GitHub's ceiling.

   Two independent reasons it is not the petname change: the SAME tree passed
   Gates Core on 4c15dfdb (991c5e08 plus a docs-only commit), and the failure is
   a cancellation rather than an assertion.

   Likely cause, visible in the same log: **sccache reported `0 hits, 0 misses,
   0 errors`**, so the cache did nothing and the run compiled cold. An earlier
   run of this job was also cancelled at 1h30m, so this is the flake in 1i/1k
   showing its mechanism rather than a new fault: the job is sized so close to
   the ceiling that a cold cache pushes it over.

   **FIXED by scoping sccache correctly.** The cause was not a cold cache, it was
   that `RUSTC_WRAPPER`/`SCCACHE_GHA_ENABLED` were set ONLY on the "Build the gate
   binary" step. The expensive work is `bash tests/gates.sh --with-relay`, which
   runs its own RELEASE cargo builds, and those were entirely OUTSIDE the
   wrapper's scope. That is why the stats read `0 hits, 0 MISSES, 0 errors`: zero
   misses means the wrapper never saw the build, not that it missed. Hoisted the
   env to workflow level, which is exactly what `test.yml` already does (and
   test.yml finishes fast), so this is the existing working pattern.

   The general point: a gate whose pass/fail depends on cache warmth measures the
   runner, not the tree, which is the "instrument, not result" problem of 1s. And
   `0 misses` was the tell that distinguished a misconfigured wrapper from a cold
   cache; `0 hits` alone would have sent me to the wrong fix.

   Also worth noting for my own tooling: my first read said "FAILED: Gates Core"
   while it was still IN PROGRESS, because I compared `conclusion != 'success'`
   and a running job has conclusion None. A check true in general, wider than the
   decision resting on it, in the very session spent cataloguing that shape.

1ag. **1ad's three "superseded, delete later" candidates are all UNWIRED
   CAPABILITIES. Keep all three (2026-08-31).** Ran the two-hop check properly
   instead of deleting on first-hop evidence. Every one turned out to be a
   feature that exists and cannot be reached, not a duplicate:

   - **`ssh_transport_args` (l2.rs)** builds a `ProxyCommand` that tunnels ssh
     through `filament forward <peer>:<port> --stdio`, with `--relay` support.
     The live `spawn_ssh_direct` has NO ProxyCommand: it ssh's straight to the
     mesh hostname, which only works when the L3 overlay is up. So this is the
     FALLBACK for no-L3 environments (no CAP_NET_ADMIN, containers, relay-only
     paths). The `-o` flags matching is what made it look like a duplicate;
     the transport underneath is different.

   - **`try_mount_health` (ctl.rs)** sends `op: "mount-health"` to the daemon over
     the control socket, and **the daemon HANDLES it** (ctl.rs:733). The live
     `check_mount_health` (mount.rs:156) is a LOCAL stat. Different authority: the
     daemon owns the mount, so asking it is the stronger check. Server side live,
     client side unreachable.

   - **`run_get` (settings.rs)** implements `get <key> [--show-origin] [--default]
     [--json] [--peer]`, and its doc comment describes that verb. `get` was
     unified into `set <key>` with no value and `unset` into `set --reset`, which
     covers key/value/peer/json but NOT `--show-origin`. Checked whether
     provenance surfaces anywhere else: `build_affordance` DISCARDS origin
     (`let (cur_val, _)`), and the only other use is inside `get_str`, an internal
     reader that uses it to tell default-empty from set-empty. **No live path
     shows provenance to a user**, though the settings design called for it.

   So the "21 never-used functions" are not 21 deletions. Counting what has now
   been checked two hops: 3 were genuine leftovers (deleted, 1ac), 1 was a
   stricter unwired check that became a bug fix (1af), 4 are staged design
   (wg.rs/ADR-0001), and these 3 are unwired capabilities. **Zero of the ones
   examined carefully were safe bulk deletions.** The warning count is a poor
   proxy for dead code in this tree, which is the standing argument for the
   baseline being a ratchet rather than a target.

1af. **Petname collision is case-SENSITIVE; the fix is ready and deliberately
   HELD until testing ends (2026-08-31).** Re-examined 1ad's "design decision"
   and it is closer to a bug. The live check is inline at main.rs:1624:

       arr.iter().any(|d| d["name"].as_str() == Some(name))

   an exact compare, so `Laptop` and `laptop` become two devices. Petnames are
   what `send --to <name>` targets, so near-duplicate names are a targeting
   footgun, and the unused `devices_name_taken` already implements the
   case-insensitive version with a doc comment saying so. Documented intent,
   unwired.

   The clean fix is NOT to call `devices_name_taken` there: it re-reads from disk
   via `devices_load()` while the call site works on an in-memory `arr` that is
   mid-modification. Make the inline compare case-insensitive instead:

       arr.iter().any(|d| d["name"].as_str()
           .is_some_and(|n| n.eq_ignore_ascii_case(name)))

   and the same inside the suffix `while`. `devices_name_taken` then becomes a
   true duplicate and can go, taking warnings 117 -> 116.

   **APPLIED, same day.** The hold was the right instinct but the wrong remedy:
   skew only exists if HEAD and the hub DIVERGE, so the fix is to move them
   together, not to sit on a known bug. Landed the case-insensitive compare,
   deleted `devices_name_taken` (now a true duplicate), and re-armed both hub
   artifacts from the same commit so nothing is out of step.

   Verified both directions: reverting to the exact compare fails
   `petname_collision_ignores_case` with "case must not create a new device";
   restoring passes. Suite 394/0, warnings 117 -> 116, baseline ratcheted down.

1ae. **Hub armed at 9be1b809 for linux-musl and windows-gnu; msvc/macOS
   deliberately NOT (2026-08-31).** `publish.sh` + end-to-end verification: the
   Linux `install.sh` was run for real into a throwaway prefix (fetch, checksum,
   extract, execute, correct stamp), and the Windows artifact was checked for
   checksum, `./filament.exe` contents, and stamp. Branch pushed; 8/8 CI green on
   the commit, including Gates Core and the ratcheted-down Warning Ratchet.

   **msvc and macOS stay at 22fed78, and the reason is provenance, not
   capability.** `cli-release.yml` is TAG-ONLY with no `workflow_dispatch`, and a
   `cli-v*` tag also fires `publish-registries` (crates.io) and `winget-publish`.
   Both are irreversible, so arming those targets is a release decision.

   I first wrote that msvc "can't be cross-built here". **That was imprecise**:
   `cargo-xwin` cross-compiles MSVC targets from Linux and is installable. The
   real reason to refuse is that an xwin-built binary is a DIFFERENT TOOLCHAIN
   from CI's, so publishing it into the `x86_64-pc-windows-msvc` slot would make
   BUILDS assert a provenance that is false: someone installing "the msvc build"
   would get something CI never produced. That is the same defect shape this
   whole session was spent removing (a label true in a narrow sense, wider than
   the decision resting on it), and the distribution path is the last place to
   introduce it.

   Consequence to remember: `irm .../install.ps1 | iex` hardcodes msvc, so it
   serves PRE-SESSION code with nothing signalling that. Windows testing at HEAD
   must use the raw-exe artifact directly.

   Also caught while arming: the local `filament up` daemon was executing a
   DELETED inode (`/proc/PID/exe -> ... (deleted)`) because the install replaced
   the file underneath it, so it served 1.5-day-old code while the new binary sat
   on disk. Restarted and hash-verified against the on-disk binary. **Any machine
   installed to needs the same restart**, or it tests the old build and passes.

1ad. **Two-hop sweep of the rest of 1u's list, and it cuts BOTH ways
   (2026-08-30).** Applied the corrected methodology (1ac) to the remaining
   never-used functions. Reference counts are all zero; the second hop is whether
   the CAPABILITY is reached another way. Results:

   - **`wg.rs` (4 fns): KEEP, confirmed staged.** Reachable only via `mod wg;`.
     It implements `docs/adr-0001-wireguard-as-l3-data-plane.md`, whose **Status
     is Proposed**, dated 2026-07-25, decider = project owner. That is a live
     proposal awaiting a decision, not abandoned code. The two-hop check CONFIRMS
     here rather than refuting, which is the point of doing it.

   - **`devices_name_taken`: KEEP, and it is a possible BUG.** The live collision
     check is INLINE at main.rs:1624, `d["name"].as_str() == Some(name)`, which is
     case-SENSITIVE. The unused fn lowercases both sides and its doc comment says
     "(case-insensitive)". So the unwired function is the STRICTER, more correct
     one, and today `Laptop` and `laptop` register as two distinct devices.
     Deleting it would erase the evidence that case-insensitive collision was
     intended. **Open: wire it, or decide case-sensitive petnames are correct.**

   - Superseded-and-deletable on the evidence so far: `ssh_transport_args` (l2.rs
     builds the `-o` args inline at 4357+), `try_mount_health` (live equivalent
     `check_mount_health` at mount.rs:156, called three times), `run_get`
     (no `Cmd::Get` exists; `set <key>` with no value displays the value).
     NOT deleted yet: each still wants the same care 1ac shows is needed, and the
     `devices_name_taken` result is exactly why.

   The generalisable finding: "unused" partitions into at least THREE kinds, not
   two. A leftover (delete), a disconnected instrument or staged design (keep),
   and **a stricter check that was written and never wired** (keep AND fix). Only
   the last was invisible to every heuristic I tried today.

1ac. **CORRECTION to 1u: all three "disconnected features" were leftovers, and
   I verified one hop too shallow (2026-08-30).** 1u justified keeping the
   never-used functions, and moving the baseline instead of deleting, partly on
   three examples I called live-but-unreached. Checked them properly and all
   three were wrong:

   - `render_missing_steer` / `render_missing_json` are EXACT duplicates of the
     inline json and plain branches of `set <key>` with no value
     (settings.rs ~812-824). The nudge always DID render. I saw them call
     `interact::render_steer` and `build_affordance`, concluded "wired into the
     nudge system", and never checked whether that branch was already covered.
   - `cap_status_cmd` wraps `ctl::try_cap_status`, which IS consumed live in the
     shell-capability path (main.rs ~14129). It was a second, unreached consumer,
     not an orphaned feature.

   That is [[verify-one-layer-down]] exactly: I checked ONE hop (does it call
   something real?) and ruled, when the answer was a layer below (is that thing
   already reached elsewhere?). Same failure I had just finished documenting in
   the code.

   Deleted all three, 88 lines. Suite 393/0, warnings 120 -> 117, baseline
   ratcheted DOWN to 117.

   **What survives of 1u's argument, and what does not.** The PRINCIPLE stands
   and was proven by the ack-loss hook (1s): a zero-caller instrument and a
   zero-caller leftover are indistinguishable to `cargo check` and are opposites.
   The three EXAMPLES did not support it. The wg.rs entries remain legitimate
   keeps (staged L3, build-order item 5). The right rule is neither "bulk delete"
   nor "bulk keep": read each one, two hops deep.

1ab. **"Needs a two-box rig" was wrong a THIRD time, for a third reason
   (2026-08-30).** After 1z and 1aa I kept saying the cross-machine ack-loss run
   was blocked on "hardware I don't have". Checked instead of asserting:
   `interserver-0x0` is ONLINE, 78ms, warm direct link. And the premature-close
   hook is RECEIVER-side, so only this box needs the test-hooks build; the remote
   sends with a stock binary and no deployment is required.

   So the block was imaginary again. The real reason not to run it now is a
   better one, and it is about DISCRIMINATION, not access: the verdict turns on
   whether the sender RE-PROBES, gated by ack_wait=15s and ack_reprobe=5s. At
   78ms RTT a 1 MB cross-machine run differs from localhost by three orders of
   magnitude LESS than the thresholds that decide it, so it cannot distinguish
   pass from fail any better than 1aa already did. The run that WOULD
   discriminate is the 10 GB transfer where the original 1-in-5 failures lived,
   because the bug is a duration/scale effect, not an RTT effect. That is a real
   bandwidth and time commitment on the owner's link, which is a cost decision
   rather than a capability one.

   Three "blocked on hardware" claims today, all false, each dissolving the
   moment I asked what SPECIFICALLY was in the way instead of reasoning from the
   category. Same defect shape as the code findings: a statement true in general
   but wider than the decision resting on it.

1aa. **BUG-ACKLOSS: first real verdict in the reproducer's life, and it is GREEN
   (2026-08-30).** I twice called this blocked on "a two-box rig". Wrong twice
   over: the reproducer runs BOTH ends on localhost, and what actually blocked it
   was the #161 `debug_assert` panicking the receiver (1v). That assertion is
   compiled out in RELEASE, so a `--release --features test-hooks` build has the
   injection hooks AND no panic. Added a `FILAMENT_BIN` override to the script
   (it hardcoded `/debug/`) and pointed it at such a build.

     baseline (no hook)     : delivered + verified   [harness OK]
     premature-close (recv) : not confirmed (77s)  [PROMPT: sender detected the
                              dead conn, no re-probe -- correct]
     TRUE EXIT: 0

   Exit 0 is the ONLY passing outcome the script defines for that round.

   Three things follow, and the middle one is the point of the whole exercise:
   - The harness passed its own precondition for the first time.
   - **The injection FIRED.** Baseline delivered, premature did not: behaviour
     DIFFERED between rounds, which is direct evidence the hook restored in 1s is
     live. For ~620 commits both rounds were the same code path.
   - **BUG-ACKLOSS does not reproduce.** The sender detected the dead connection
     and did NOT re-probe, which is the correct outcome; the keepalive leak is
     fixed.

   The lesson is 1z's again, one turn later: "needs hardware" was a property of
   how I was RUNNING it, not of the test. Both times the block dissolved on
   asking what specifically was in the way.

   Caveat kept honest: this measures the LOCALHOST path with a release binary.
   The original 1-in-5 failures were 10 GB cross-machine, and a two-box run is
   still worth doing, but it is now a broader-coverage question, not a blocker.

1z. **The escalation fix now has the regression test it deserved (2026-08-30).**
   1w fixed the relay->direct cutover minting owner-equivalence but shipped with
   only reading to defend it, and I twice called that "needs a two-box rig". It
   does not: the rig is only needed to demo the EXPLOIT, not to pin the RULE.

   `Conn::for_command` needs a live socket.io client, so the calling method
   genuinely cannot be unit-tested, and that is precisely WHY the rule went
   unenforced. Extracted the decision into a pure `upgrade_principal` and tested
   that: a fleet device stays FleetDevice and stays untrusted; a TRUSTED fleet
   device keeps its kind (the case the old code silently collapsed to
   OwnerDevice); an owner device is unchanged, so the fix is not a regression for
   the ordinary path; None keeps the old default.

   Verified both directions: reverting `upgrade_principal` to the pre-fix
   `(true, OwnerDevice)` fails with "an untrusted link must not become trusted by
   upgrading"; restoring passes. Suite 393/0.

   The transferable bit: "untestable" was a property of the CALL SITE, not of the
   rule. When a rule cannot be tested where it lives, move the rule, not the
   goalpost. A two-box rig is still wanted to demonstrate the revoked-device path
   end to end, but it is no longer what stands between this fix and a guard.

1y. **A narrowing of the #161 predicate was designed and REJECTED (2026-08-30).**
   Recorded so it is not re-proposed. The tempting fix for the probe panicking
   debug builds on the primary flow (1v) is to thread an
   `identity_resolution_attempted` flag into `cap_gate_effective` and fire only
   when a path reaches the gate WITHOUT attempting resolution.

   The 25 call sites are not the obstacle: adding a parameter is compiler
   enforced, so a missed site is a build error rather than a silent bug.

   **It is wrong on the semantics.** `resolve_peer_identity` reads the cert from
   the LOCAL store, and a cert can arrive AFTER a first resolve attempt, pushed
   by a later `fleet-hello` (which is exactly how owner-signed cap ops propagate,
   see 2-DONE). In that state resolution was attempted, found nothing, and
   identity is still genuinely PENDING. The narrowed predicate passes
   `attempted = true` and goes quiet while the window is open.

   That is the failure the comment at capability.rs:456 names: the assertion
   going quiet because it was RELAXED rather than because the ordering was fixed.
   The narrowing is not a refinement of the probe, it is the forbidden change in
   better clothes.

   The genuine fix remains what that comment says: resolve identity before the
   gate is consulted, or deny when `device_pub` is None under legacy trust. Both
   change authorization behaviour and are the owner's call. 1x is the evidence
   base for making it.

1x. **The revocation question now has evidence, not an argument (2026-08-30).**
   1v and 1w both turned on "does revocation actually hold?", which I had argued
   about from comments rather than measured. `revocation_is_only_consultable_once_identity_resolved`
   pins both halves against the real gate:

   - **resolved + revoked -> DENIED**, even with legacy trust present. The
     security property HOLDS wherever identity resolves. That is the reassuring
     half and it was previously assumed, not tested.
   - **unresolved -> allowed on legacy trust**, because `cert_revoked_for(None)`
     is false: revocation there is UNKNOWABLE, not absent.

   So the exposure is precisely bounded: it exists only where identity never
   resolves. Together with 1w closing the path that MINTED trusted-but-
   unidentified links (the relay->direct upgrade), the practical surface is much
   smaller than 1v first suggested.

   This also gives the 1v predicate decision a base: if the ordering is ever
   fixed, case 2 flips and the test says so in a diff. Suite 392/0.

1w. **The relay->direct upgrade PROMOTED any link to owner-equivalence. FIXED
   2026-08-30.** Following 1v's thread into who sets `trusted` without an
   identity, `perform_upgrade` (the P5 relay->direct cutover) does this:

     let known = ...expected_secret          // read from the old link
     self.drop_link(pid);                    // destroys trust + principal state
     self.adopt_direct_transport(pid, t, route, known);

   and `adopt_direct_transport` rebuilt the Link with a HARDCODED
   `trusted: true` and `principal_kind: OwnerDevice`. So whatever the link was
   before the upgrade, it came back owner-equivalent.

   This is not a hypothetical. The sibling constructor `adopt_direct` carries an
   explicit fail-safe for exactly this, and its comment records the incident:
   "a device whose transfer grant had been REVOKED still delivered a file,
   because the acceptor had granted it owner-equivalence at link birth." **The
   fix landed in `adopt_direct` and never in `adopt_direct_transport`.** One bug,
   two constructors, fixed in one: the shape logged in
   [[cross-impl-comparison-invariant]].

   It also contradicted the function's own doc, which says it reuses the known
   identity so "only the wire path changes". Minting a principal is not that.

   Fixed by carrying `(trusted, principal_kind)` from the pre-upgrade link across
   the swap. Owner links are unchanged; a fleet or delegated link keeps its lower
   privilege instead of being promoted. Suite 391/0.

   **Not verified end to end:** a fleet relay->direct upgrade carrying a REVOKED
   device, which needs a live two-box rig. The change is sound by construction
   (it can only ever lower privilege relative to the old behaviour, never raise
   it), but the escalation itself was found by reading, not by a failing test,
   and it deserves one.

1v. **The #161 revocation-ordering probe FIRES on the plainest flow there is
   (2026-08-30). OPEN, and the most important thing found today.** Chasing why
   the ack-loss harness failed, I ran a bare `send --word` + `receive <code>`
   between two fresh config dirs on a debug build. The receiver PANICKED:

     capability.rs:456: gate reached before identity resolution:
     legacy trust with no resolved device identity

   That is not a crash to silence. It is the deliberate #161 probe, and its own
   comment states the consequence: `trusted` (pair-secret MAC, feeds
   legacy_allowed) and `identity_device_pub` (lazy resolve_peer_identity, feeds
   device_pub) are set by SEPARATE events, so if the gate is reached with legacy
   trust and no resolved identity, `cert_revoked_for(None)` is false while
   `legacy_allowed` is true, and **a revoked device is authorized until identity
   settles**. The comment is explicit that it "goes quiet only because the
   ordering is fixed, never because the assertion was relaxed."

   `gate_live()` scopes the probe to real flows, so this IS an exercised path,
   not a synthetic unit-test state. Reproduced three times: once directly, and
   twice as the ack-loss harness failing its BASELINE round, where the receiver
   dies and the sender then reports "peer did not come back within 45s". That
   single panic explains 1t entirely.

   **CORRECTION, same day, after tracing `resolve_peer_identity`.** The above
   over-states the security impact and the correction matters. That function
   returns early leaving `device_pub` None in two cases: no proven name, or NO
   DEVICE CERT for the name. Two fresh installs doing a code-based transfer have
   no cert for each other by design (that is the whole "send with a code, no
   account" flow), so `legacy_allowed && device_pub.is_none()` is the NORMAL AND
   PERMANENT state there, not a transient pre-resolution window. Revocation is a
   property of CERTIFIED devices; with no cert there is nothing to revoke, so
   nothing is bypassed in this instance.

   So the probe's predicate is BROADER than the defect it targets: it cannot
   distinguish "identity is pending and will settle" from "identity is absent by
   design". Which is the same shape as the defect it was written to catch, now
   in the probe itself, and the same shape as 1q and 1e: a condition that is true
   but wider than the decision resting on it.

   The REAL defect this leaves is not the revocation window, it is that the probe
   PANICS the receiver on the primary user flow in every debug build. That is why
   the ack-loss harness fails its baseline, and why three runs died identically.
   Any debug-build harness doing a plain code transfer is unusable.

   The fix is to narrow the predicate to "resolvable but unresolved" (verified
   name present AND a cert exists for it), which needs an `identity_pending` flag
   plumbed from the call site, since `cap_gate_effective` sees only device_pub.
   **NOT done unilaterally.** The comment at capability.rs:456 explicitly says the
   assertion must go quiet only by fixing the ordering, never by being relaxed,
   and a narrowing that is wrong would hide a genuine revocation bug. It needs the
   owner, plus the revocation test below to confirm the certified path is sound.

   **What is verified:** the probe fires on code-based receive with fresh state;
   the receiver exits 101; it is a `debug_assert!`, so RELEASE builds do not
   panic and the window is simply SILENT there.
   **What is NOT verified:** that a genuinely revoked device is let through end
   to end. That needs a revocation test built on this repro, and it is the next
   thing to do.

   Do NOT "fix" this by relaxing the assertion. The fix is the ordering: resolve
   peer identity before the gate is consulted, or deny when `device_pub` is None
   under legacy trust. Note the shape, which is the recurring one in this tree
   (see [[decision-on-a-narrow-view]]): a decision resting on a fact that is true
   but narrower than the decision, here "trusted" standing in for "trusted AND
   identified".

1u. **The warning ratchet was breached at 154/108, and the obvious fix was the
   wrong one (2026-08-30).** Measured with CI's exact command, exit status
   captured. Confirmed pre-existing, not from this session's commits: HEAD~1 also
   measured 154. CI would have failed on the next push.

   Brought 154 -> 120 by fixing causes rather than counting:
   - **`mount-macos` was never declared** in `cli/Cargo.toml` while FIVE cfgs
     gate on it (`mount_fuse.rs` plus four sites in `main.rs`). A cfg naming an
     undeclared feature is unconditionally false, so the macOS FUSE adapter was
     compiled out of every build AND `cargo build --features mount-macos` failed
     as an unknown feature: there was no way to turn macOS mount on at all.
     Declared it, and made `fuser` an optional macOS dep so the feature pulls
     what it needs. Same shape as the test-hooks bug (1j) and found the same way.
   - `cargo fix` for the mechanical rest (unused imports, unnecessary `mut`,
     unused bindings) across 11 files. Suite still 391/0.

   **The remaining 12 were NOT deleted, deliberately.** 21 functions have zero
   references, and the tempting move is to delete enough of them to get under
   108. Three that I checked turned out to be DISCONNECTED FEATURES, not dead
   code:
   - `render_missing_steer` / `render_missing_json` (settings.rs) call
     `interact::render_steer` and `build_affordance`, i.e. the NUDGE affordance
     system. Unused means the missing-value nudge never renders.
   - `cap_status_cmd` (main.rs) calls the real ctl op `ctl::try_cap_status`, so
     the op exists with no verb reaching it.
   - The four `wg.rs` entries are the staged WireGuard L3 data plane (master
     build order item 5, "built + measured, ready"), not garbage.

   That is the THIRD instance today of "never used" meaning "wired wrong" rather
   than "dead" (see 1s, and 1j before it). `cargo check` cannot tell a
   zero-caller instrument or a zero-caller feature from a zero-caller leftover;
   they are opposites, and only reading each one distinguishes them. Deleting to
   satisfy a counter would have destroyed working code and closed the gaps
   permanently, which is exactly what nearly happened to the ack-loss hook.

   So the baseline is updated to 120 INTENTIONALLY (the gate's own message
   sanctions this) to restore its real function, which is "no NEW warnings".
   This is not a claim that the 21 are fine. Each needs a per-item wire-or-delete
   decision, and the three above should be WIRED:

     settings.rs      render_missing_steer, render_missing_json, run_get
     main.rs          cap_status_cmd, devices_name_taken
     ctl.rs           try_list_mounts, try_mount_health
     wg.rs            gen_keypair, create_iface, configure_peer, network_cidr
     l3.rs            run_point_to_point
     l2.rs            ssh_transport_args
     mount.rs         print_mount_help, interactive_mount_fancy
     sshd.rs          is_configured
     local.rs         from_stream
     ui.rs            glyph_deliberate
     fleet_ui/mod.rs  confirm_mistype, err_bad_arg
     recovery.rs      render_guardians_header

1t. **The ack-loss reproducer had a SECOND independent break, and its first real
   run still produced no verdict (2026-08-30).** Beyond the missing hook wiring
   (1s), the script hardcoded `BIN="$CLI_DIR/target/debug/filament"`. This box
   sets a shared `target-dir` in `~/.cargo/config.toml`, so that path does not
   exist: the script BUILT fine and then looked for the binary somewhere cargo
   never writes. Fixed to ask `cargo metadata` for the effective target
   directory, honouring CARGO_TARGET_DIR and falling back to ./target.

   Ran it with both breaks fixed. **It still gives no verdict:** the BASELINE
   round (no hook, must simply deliver) came back `NOT confirmed [HARNESS
   BROKEN]`, with a stall on a peer that disconnected and did not return inside
   45s. Per the script's own contract that is a setup failure, not a result, so
   this run says NOTHING about whether BUG-ACKLOSS still reproduces. Do not read
   it as either a pass or a fix.

   The likely cause is environment, not code: 8 filament processes were already
   running before the run (including two `/root/finalcheck2/filament up` pointed
   at PRODUCTION and a shell that has been alive 8 days), which is the same
   contamination that once made `send --to owner` fail twice and read as a grant
   regression. The run also leaked its own autostarted backend on :8077 because
   the cleanup trap does not fire when `timeout` kills the wrapper. A verdict
   needs a clean rig first.

   And a self-inflicted one worth naming: I captured the script's exit status as
   `bash repro.sh | tail -30; echo $?`, which reports TAIL's status, always 0.
   That is precisely the swallowed-exit-code trap `.github/workflows/warning-
   ratchet.yml` documents in its own comments, and I walked into it while
   verifying an instrument. The reported "EXIT: 0" was meaningless.

1s. **The BUG-ACKLOSS reproducer injected nothing for ~620 commits
   (2026-08-30). FIXED.** `cli/tests/ack-loss-repro.sh` exists to reproduce the
   delivery-ack teardown race deterministically on a 1 MB transfer, something the
   multi-stream push otherwise hit about 1-in-5 on 10 GB cross-machine runs. Its
   whole mechanism is `FILAMENT_TEST_PREMATURE_CLOSE=1`, which is supposed to make
   the receiver tear the link down at the instant the ack is due.

   **Nothing read the flag.** `premature_close_after_ack`, `premature_close_once`,
   `premature_already_fired` and `premature_mark_fired` had ZERO call sites. The
   "premature" round ran an ordinary transfer, and the promptness verdict
   (did the sender re-probe?) measured the happy path. It passed, and passing
   meant nothing.

   How it happened, which is the part worth keeping: the wiring WAS present in
   12a8db82 (an ancestor of HEAD) at `main.rs:9616`, and was already gone by the
   next commit. **No commit deletes it.** The if/else-if chain survived MINUS its
   first arm, leaving `suppress_delivery_ack` (the second arm) correctly wired,
   which is the shape a bad conflict resolution leaves, not a deliberate removal.
   The other hooks in the family kept their call sites, so this was never a
   blanket strip.

   Three separate things failed to notice:
   - The warning ratchet DID report the unused stub. It was 1 of 154 warnings
     against a baseline of 108, so it read as ordinary dead code.
   - The gate itself cannot notice. A detector is never validated by its own
     clean-run count; see [[instrument-must-be-verified-present]].
   - **I nearly made it permanent.** The stub was on my list of 20 "provably
     dead" functions to delete to bring the ratchet back under baseline.
     Deleting it would have erased the evidence and closed the gap for good.
     A zero-caller INSTRUMENT and a zero-caller helper look identical to
     `cargo check`, and they are opposites: one is safe to delete, the other is
     a live defect. Never bulk-delete never-used functions in this tree without
     asking, for each one, whether something was supposed to be calling it.

   Fixed by restoring the arm at BOTH receiver sites (the inline fast path and
   the `Ev::MaybeComplete` writer-completion path; the original had one, the code
   has since split in two) and adding `hooks_that_nothing_calls`, which parses the
   no-op module for hook names and fails if any has no call site. Verified in both
   directions: stripping the arms makes it fail and name all four orphans;
   restoring passes. Suite 391 passed / 0 failed.

1q. **`filament --help` advertised a verb that no longer existed, and the test
   written to prevent exactly that could not see it (2026-08-30).** The COMMANDS
   banner listed `ephemeral mint`. That verb was removed when minting collapsed
   into `add --for runner`; `EphemeralAction` has only `Enroll` left. So the
   first thing a new user reads told them to type a command clap rejects.

   `printed_hints_name_verbs_that_exist` exists for this exact class (it was
   written after `filament unmount` survived in five places). It missed for two
   structural reasons, and both are more interesting than the string:

   - **It anchors on the literal `"filament "`.** The COMMANDS column lists bare
     verbs in a column with no such prefix, so the banner, the single most-read
     surface in the CLI, was never scanned at all. The guard covered every
     sentence that mentions the binary and not the page that lists its commands.
   - **It reads one word.** Even where it did look, `ephemeral mint` would have
     passed on `ephemeral` alone, because a valid parent was treated as a valid
     command.

   Fixed both by adding `help_banner_names_commands_that_exist`, which parses the
   `EXAMPLES` constant and walks each printed command through clap by token:
   subcommand, then sub-subcommand, then flags, skipping flag VALUES (`--for
   person`) and placeholders (`<device>`, `[code]`, `laptop:5432`). It validates
   34 commands. It also asserts `checked >= 10`, so if the banner's shape ever
   changes under it the test fails loudly instead of silently validating nothing,
   which is the failure mode that made the older guard useless here.

   The generalisable point, and it is the same one as 1e/1p: **the guard was not
   weak, it was narrower than the thing it was believed to cover.** "We have a
   test for printed verbs" was true. "Printed verbs are checked" was not. The
   gap sat exactly where the two differ, and nothing about a green suite could
   show it, because the test passed for the whole time the banner was wrong.

1r. **`filament-transport` could not be built static outside this repo
   (2026-08-30).** `cli/Cargo.toml` declares `static = ["dep:openssl-sys"]` with
   vendored OpenSSL, because `rust_socketio` hard-depends on `native-tls`.
   `filament-transport` carries that same `rust_socketio` dependency and declared
   no such feature, so the CLI had an escape hatch for fully-static (musl) builds
   that no other consumer of the crate could reach. The crate always compiled;
   it was the STATIC build that was reachable only from inside this tree.

   Added the mirrored `static` feature. Found by asking whether these crates are
   usable elsewhere and measuring it, not by anything failing, which is the point
   worth keeping: a carve that compiles looks finished, and the asymmetries it
   leaves behind are invisible from inside the repo that still has the original.

1p. **The right filter on the wrong candidate set (2026-08-30).** 1e-old says
   "identify a test daemon by its config dir in /proc/environ, never by its
   command line". The acceptance suite's FILTER did exactly that. Its CANDIDATE
   LIST did not:

       for p in $(pgrep -f "release/filament"); do
           grep -q "FILAMENT_CONFIG_DIR=/tmp/claude-0" /proc/$p/environ && kill
       done

   A daemon launched from an INSTALLED binary (/root/hubtest/filament,
   /root/finalcheck/filament) never reaches the filter, because pgrep never
   offers it. And running the installed artifact is exactly the habit 1n
   recommends, so the good practice manufactured daemons the purge could not
   see. 36 were alive; two from hours earlier still held acc/O and acc/D.

   COST: `send --to owner` failed on two consecutive runs of the shipped
   binary, same error both times, immediately after a change to the grant path.
   Reproducible, not flaky, and pointing straight at the most recent security
   work. On a cleaned rig the same binary scores 24/0.

   WHAT STOPPED THE WRONG CONCLUSION was reading the daemon log rather than the
   pass count: `connection_key_divergence: device 'laptop' overlay key X !=
   pinned cert device_pub Y`, several different overlay keys claiming one
   device, which is the stale-daemon signature 1e-old describes. The failure
   text the SENDER shows ("no peer connected within 60s") names ICE and mDNS and
   points nowhere near the real cause.

   FIXED both halves: enumerate by identity (pgrep -x filament plus a path-tail
   match) and then ASSERT zero strays before running. A purge that silently
   matched nothing is how these survived every earlier run while each reported
   itself clean.

   SEVENTH HARNESS DEFECT THIS SESSION. The lesson was already written down here
   and applied to the part I was looking at. Recording a rule does not protect
   the place you did not think to apply it.

1n. **The hub served a binary that misreported its own commit (2026-08-30).**
   BUILDS said 7d11093, the binary said 975d5630, and the CODE was 7d11093: it
   minted a spoken code for `add --word`, which only the newer build does. The
   label was a commit stale, not the artifact.

   CAUSE. cli/build.rs stamps the sha from `git rev-parse` and re-runs only when
   its watched git paths change. In the cross-target musl build that did not
   re-fire, so the crate recompiled against the CACHED FILAMENT_BUILD_INFO from
   the previous publish. build.rs already supports FILAMENT_BUILD_SHA for
   exactly this ("CI can override"), and no publish path ever set it.

   WHY IT MATTERS MORE THAN IT LOOKS. "The installer reports the commit it
   actually installed, read from BUILDS rather than baked in" is the property
   this hub exists to provide, and it is the thing I used all session to confirm
   what was deployed. It was quietly false for at least one publish. A stale
   label on a correct binary is the benign case; the same mechanism would hide a
   stale BINARY just as well.

   FIXED at the publish boundary rather than by remembering: publish.sh reads the
   stamp and REFUSES when it disagrees with the commit being published.

   THE FIRST VERSION OF THAT GUARD WAS ITSELF TOO NARROW. It read the stamp by
   RUNNING the binary, which only works for the host's own target, so it skipped
   Windows and macOS -- and the raw .exe promptly sailed past it, stamped
   975d5630 while published as 7d11093. A guard that cannot inspect three of
   four artifacts is not a guard. It now reads the string out of the binary with
   `strings`, which works for every target and executes nothing, and it refuses
   an UNREADABLE stamp too, because "could not check" must not read as "passed".

   THE PATTERN, once all four were finally inspected: every locally cross-built
   artifact had a stale stamp (musl, windows-gnu) and every CI-built one was
   correct (msvc, darwin). CI checks out fresh, so build.rs re-runs; a local
   cross build under its own CARGO_TARGET_DIR does not trip build.rs's watched
   paths and recompiles against the cached value. Builders should pass
   FILAMENT_BUILD_SHA.

   Impact was contained: install.ps1 uses the MSVC artifact, which was correct.
   Only the direct .exe download carried a possibly-stale binary under a current
   label. Verified in both directions on a Windows binary before being trusted:
   publishing it under the wrong commit is refused, under the right one accepted.

   FOUND BY running the acceptance suite against the INSTALLED binary rather
   than a local build, which is also what exposed 1m. Testing the artifact a
   user receives keeps finding things that testing the tree does not.

1o. **The acceptance suite went stale at the unification and I stopped noticing
   (2026-08-30).** The run above reported 21 passed / 4 failed, which reads as a
   product regression. All four were in the ephemeral section, driving
   `ephemeral mint --caps ... --ttl ...`, a verb removed in cb05567 when it
   collapsed into `add --for runner`. Harness stale, product fine.

   The suite had been green at 25/0 before the unification, and I ran unit tests
   and CI afterwards instead of it, so nothing said the checks had stopped
   describing the product. A suite that tests a removed verb does not fail
   loudly as "removed"; it fails as four ordinary-looking FAILs.

   Updated to `add --for runner --allow ... --expires ...`, and it now also
   asserts the artifact is the ONE credential format, which is the property the
   unification actually bought.

   SIXTH HARNESS DEFECT THIS SESSION, and the second that presented as a product
   result. Reading the failure NAMES rather than the pass count is what
   separated them.

1m. **A regression shipped past 389 tests, 7/7 CI, and my own live check
   (2026-08-30, fixed in 7d11093).** Worth its own item because of what did NOT
   catch it.

   975d563 made non-interactive `add` default to the `file` transport, on the
   correct reasoning that a spoken code has to be READ ALOUD to somebody. Applied
   unconditionally, which ignored that `--word` IS the code transport: it sets
   the SPAKE2 password for a spoken code and means nothing to a file. So a
   scripted `add --for device --word "..."` silently wrote an invitation file
   instead of minting the code the caller had just chosen words for.

   THAT IS HOW THE ACCEPTANCE RIG PAIRS. The change would have broken the suite
   that validated everything else in that session, and it reached the hub.

   WHAT MISSED IT: 389 unit tests, all seven CI jobs on that commit, and a live
   terminal check of the very feature. The live check ran `add`, `add --for`,
   `add laptop` and the one-shot, and never `add --word`, because those were the
   paths being thought about. Testing the paths you have in mind is the same
   narrowness that produced the authz safety claim in 1k.

   WHAT FOUND IT: trying to USE the feature for something else, building a rig
   for the grant work in 1l, and noticing the pairing produced no code. It
   presented as the fifth harness failure of the session and was a real product
   regression. Harness failures are worth reading as signal.

1l. **`grant` skipped the validations `revoke` runs. FIXED 2026-08-30
   (7b314d6).** A TODO in main.rs (~13872) said "route grant through apply_cap_op
   so there is one validated op-creation path (sig-verify + floor + monotonic +
   ratchet), not two". Checked, and it is accurate:

       revoke   build CapOp -> sign -> apply_cap_op(store, hdr, op, now)
       grant    build CapOp -> sign -> store.push(op_json)

   `apply_cap_op` verifies the signature against header.owner_pub, requires the
   resource header to exist, and enforces the VERSION FLOOR. Grant does none of
   these, then calls `update_ratchet` by hand to patch the one consequence
   somebody noticed (evaluate() hitting "ratchet uninitialized").

   THE FLOOR IS THE SUBSTANTIVE GAP. It is what stops an op being written below
   the monotonic floor, and the comment beside the manual ratchet call describes
   having already been bitten by a grant that "did NOT take" and would "deny
   forever". A grant that bypasses the floor can land in the store and be
   refused at evaluation.

   DEFERRED ONCE, THEN DONE, and the deferral had a stated condition rather than
   a vague worry: knowing the gate's pass rate on an unchanged tree, so a red
   could be READ instead of guessed at. Closing 1k supplied it (7 of 9, ~78%),
   which is why the work happened an hour later and not before.

   A SECOND BUG SURFACED IN THE DOING. Grant used hlc_next(0, ..), starting from
   zero and ignoring the store, where revoke uses hlc_next(existing_ver, ..). So
   a REGRANT could be minted below the floor. That could never fail while the op
   was pushed straight in; through apply_cap_op it is refused, which is the
   point. Grant now computes existing_ver the way revoke does.

   VERIFIED AGAINST A REAL STORE, because the floor only bites on the SECOND
   grant to one target and no unit test reaches that:

       grant / regrant / regrant-after-revoke   all succeed
       versions   1788057406968 -> ...424611 -> ...424678, monotonic
       store      cap_header, cap_ratchet, cap_grant
                  ratchet written by apply_cap_op, not the deleted hand call
                  one cap_grant entry, replaced in place, never duplicated

   The risk was that routing through the validated path would start refusing
   legitimate regrants. It does not.

   AND THE RIG THAT PROVED IT CAUGHT A SHIPPED REGRESSION. Building it exposed
   that 975d563 had broken scripted `add --word`: non-interactive was defaulting
   to `file` unconditionally, and --word IS the code transport. See 1m.

1k. **The flake was measured again, and I misread it twice (2026-08-29).** Item
   1i said "a red here is not evidence on its own". I read that sentence, quoted
   it while analysing a red, and then treated the red as proof anyway. Recording
   the numbers and the mistake, because the mistake is the reusable part.

   Extracting the authorization preamble (five copies -> one function) produced:

       tree            Gates Core
       clean           56cc23b, 8848880                      2 pass, 0 fail
       authz           44e91bf FAIL then PASS on re-run,
                       f185f9c FAIL, then e03a341, 25587b3,
                       f17c159, d591a56, 975d563, c9a0665
                       all PASS                              7 pass, 2 fail

   THE SAME COMMIT BOTH FAILED AND PASSED. 44e91bf's two attempts ran the same
   tree and disagreed, which is the cleanest possible demonstration that this
   gate cannot, by itself, tell you whether a tree regressed. `code transfer` is
   the same gate 1i already named as flipping.

   8848880 is a free CONTROL and worth noticing as a technique: it was a revert,
   so its main.rs is byte-identical to 56cc23b. Running the gate on a tree you
   already have a result for is how you separate "this change broke it" from
   "this gate flips", and it cost nothing because the revert had to run anyway.

   SETTLED. Every commit after the restore kept the authz code and every one of
   them passed, so the tally is 7 pass / 2 fail, a 78% pass rate against the ~67%
   this item measured for the gate on an UNCHANGED tree. The authz tree passes at
   or above the historical rate. There is no regression signal, and the two reds
   were the flake this file had already warned about.

   The arc is the lesson. At 1 of 3 the numbers leaned toward a real difference
   and I read them as proof, reverting working code. At 2 of 4 the lean was gone.
   At 7 of 9 it is clearly fine. Nothing about the code changed across those
   readings; only the number of samples did.

   It still does NOT prove the extraction safe. The original safety argument was
   too narrow whatever the gate says: it examined cert_revoked and generalised to
   four other inputs, and the borrows-to-owned-copies change was never reasoned
   about. What the samples establish is that the reds carried no information,
   which is the only claim they ever supported.

   THE FAILURE MODE, twice in one hour and in opposite directions. First I
   shipped the extraction claiming "every decision below the preamble is
   byte-identical", an argument that examined cert_revoked and generalised to
   the other four inputs, ignoring that borrows had become owned copies and that
   an immutable borrow of `conn` held across the arm was dropped. Then I read two
   reds as "two independent runs" and reverted, when they came from a gate
   already measured as non-deterministic. Neither error was a missing fact. Both
   were a conclusion running ahead of what had actually been checked.

1i. **The deterministic-core ratchet flakes, measured (2026-08-28).** Recorded
   because it will be hit again and looks exactly like a regression.

   Three CI runs of `Gates Core`, and the middle one contains ALL of the pairing
   and enrolment work:

       8929218  before that work    12 passed, 10 failed
       4ac8494  after it, PASSED    13 passed,  9 failed
       f2d24b1  .gitignore ONLY     11 passed, 11 failed  <- ratchet went RED

   `f2d24b1` differs from `4ac8494` by one file, `.gitignore`, and the deletion
   of untracked build artifacts. No source, no test, no gate script. So the green
   set moves by +-1 on an unchanged tree: `kill-resume` failed in the first run
   and passed in the other two, `code transfer` passed twice and failed once.

   Two consequences worth keeping.

   FIRST, a red here is not evidence on its own. It was taken as proof that the
   enrolment commit had regressed gate 11b, and the commit carrying all of that
   work in fact scored BEST of the three. The 15s pairing delay that was fixed in
   response was real and independently measured (15s -> 1s), but the CI red that
   prompted the look was flake. Right repair, wrong stated cause.

   SECOND, `pair-ceremony` and `pair fail-fast` are KNOWN-RED and therefore
   invisible to the ratchet, which is exactly where a real regression could hide
   while the pairing ceremony was being changed. They are byte-identical across
   all three runs, so nothing was broken there, but that had to be checked
   deliberately: the ratchet would not have said.

   AND THE GATE THAT KEEPS FLIPPING IS 11b, WHICH FAILS UNDER A DIFFERENT NAME.
   Its two branches do not use the same string:

       ok  "active link preserved across same-uid reconnect (kept deliberately...)"
       bad "flow-preserve (#28)"

   `EXPECTED_GREEN` matches the ok-text, so a genuine failure of 11b can never be
   matched as a FAIL by the ratchet: it sees no PASS and no FAIL under that name.
   Every ratchet red for this gate has therefore been reported as though the gate
   vanished, when it ran and failed under its own label. The failed-gate summary
   line ("N passed, M failed - route detection ... flow-preserve (#28) ...") is
   the only place that says so.

   FIXED 2026-08-28, in the ratchet rather than in the gates. It was not just
   11b: measured, TEN of the eleven expected-green gates announce failure under a
   different label than success ("code transfer, hashes match" fails as "code
   transfer", "transferred + hash match within ceiling" fails as "bulk
   transfer", and so on). Only "unit tests" matches. So the ratchet could never
   report FAILED for almost any gate, and every red was phrased as though the
   gate had vanished.

   `EXPECTED_GREEN` now carries `"<pass text>|<fail text>"` per gate, so the
   three cases are distinguished: PASS, FAILED (it ran and failed), and NO
   VERDICT (neither, which usually means the suite died earlier and marks every
   later gate at once). Verdicts are unchanged; only the diagnosis is. Fixing it
   here rather than by renaming gate output keeps main's test strings untouched.

   ROOT CAUSE OF THE 11b FLAKE, found 2026-08-29. It is a race in the GATE, not
   in the product, and it is arithmetic rather than mystery.

   11b must observe a same-uid reconnect WHILE the transfer is still flowing.
   It waits for 8 MB of an 80 MB file to land, polling every 0.5s, then starts
   the second receiver. But gate 9 measures ~96 MB/s on the same runner, so the
   whole 80 MB completes in about 0.83s. The 8 MB threshold is reached in ~0.08s,
   inside the first poll interval, and by the time the loop notices and spawns a
   process the transfer can already be finished. Then the sender never sees a
   reconnect mid-flow, never logs "keeping active link", and the gate fails as
   "flow-preserve (#28)".

   So it fails when the machine is FAST. That matches everything observed: it
   flips run to run on identical trees, and it is the gate most sensitive to
   runner speed.

   THE FIX HAS A PRECEDENT IN THIS FILE'S OWN SUITE. Gate 17b faced exactly this
   ("same-machine pairs otherwise finish in ~1s") and solved it with a test hook,
   `FILAMENT_TEST_PAIR_STALL`, so the ceremony budget fires deterministically
   rather than racing the machine. 11b needs the transfer equivalent: a
   feature-gated stall that holds the send mid-flight so the reconnect provably
   lands inside the window. Enlarging the payload only buys margin; it does not
   make the gate deterministic, and it makes every run slower.

   FIXED 2026-08-29. `FILAMENT_TEST_TRANSFER_STALL_MS` holds each chunk briefly,
   exactly as `FILAMENT_TEST_PAIR_STALL` does for 17b, and 11b sets it to 3ms.
   That number is derived, not guessed: 80 MB in ~60 KiB chunks is ~1365 chunks,
   so 3ms each adds ~4.1s and the transfer lasts ~4.9s, against the ~0.6s R2
   needs to spawn. About 8x margin for four seconds of suite time. (25ms, the
   first value tried, would have added 34s.)

   Both halves verified: the hook string is present in a `--features test-hooks`
   build and ABSENT from a release build, which is the property the "release
   build (no test-hooks)" job exists to protect.

   THE DESIGN ISSUE. `gates-ratchet.sh` treats "no `PASS:` line" as a regression,
   which conflates FAILED, DID NOT RUN, and FLAKED. Against a suite where ~9-11
   gates are red and the green set drifts by one per run, it blocks merges at
   random and teaches people to force past it, which is the opposite of what a
   ratchet is for. Either quarantine the unstable gates by name, or require N
   consecutive reds before failing.

1g. **libfilament: four crates carved (2026-08-27).** See
   `docs/design-libfilament.md` for the rule and the order.

       filament-transfer   byte mechanics: reassembly, safe names, pwrite   14 tests
       filament-proto      wire vocabulary + pure ceremony decisions         8 tests
       filament-overlay    self-certifying addresses, link-bound announces  13 tests
       filament-fleet      admission ceremony + the per-peer session        13 tests

   The rule each one obeys: a thing may leave when it has no opinion about how a
   peer was found, where files live on this machine, or how anything is rendered.
   Where a pure module still needed host state, it is INJECTED (the fleet session
   takes a hello-builder closure) rather than reaching for the filesystem, which
   is the shape `filament-id` already used with `&dyn KeyStore`.

   Found while moving: the reassembly functions, which DECIDE whether a file is
   complete, had no tests at all, in the one path with a measured corruption
   history. And `pwrite_at` printed a short-write diagnostic to stderr from
   inside the byte-writing primitive; it now returns the count and the caller
   decides. Total 525 tests, all green, model checker still proves all tiers.

   REMAINING, both genuinely multi-session:
     - `filament-transport`: ~23 coupling sites across 4,000 lines, 15 of them
       `ui::trace`. Concrete injection list now in design-libfilament.md.
     - one peer loop replacing eight: the big one, and it should be ASSEMBLED
       from the crates above rather than extracted around them.

1f. **Shared module extracted: now `crates/filament-fleet/src/session.rs`
   (started life as `cli/src/fleet_session.rs`, 2026-08-27).**
   The fleet identity handshake was typed out TWICE, inline: once in the
   daemon's receive loop and once in `send_cmd`. Every per-peer bug this session
   existed in one copy and not the other, and the daemon's copy was the one that
   already had it right (its bindings were per-peer `HashMap`s while the
   sender's were single values). So the module follows the DAEMON's shape, and
   the sender's duplicate was deleted: 225 lines out, 97 in.

   The module owns the conversation (who is challenged, proved, wrong, lapsed)
   and does no I/O: `greet`/`on_control` return an `Action`/`Outcome` and the
   caller sends it. That makes it testable without a network and lets two very
   different event loops share one implementation. 11 tests, each pinning one of
   the four bug shapes so they cannot be reintroduced.

   NOT YET DONE: the daemon still runs its own copy of the same conversation.
   Porting it onto `FleetSession` is the other half and is what makes the
   extraction pay. Also still inline: the TRANSFER core (offer/chunk/resume/
   progress) inside `send_cmd`, which is what blocks warm-send.

   THE BIGGER DUPLICATION, measured: `main.rs` is 22,691 lines and hand-writes
   the peer event loop EIGHT times (24 `Ev::ChannelReady` arms, 24 `Ev::Control`,
   22 `Ev::Signal`, 14 `Ev::DirectReady`, 9 `Ev::PeerLeft`). This file already
   records one instance of the cost: the close-reason hole was found and fixed
   for `mount` and survived in `pty` because nobody walked the other copy.

1h. **SOLVED: brokered rendezvous. Sibling send is reliable and ON by default
   (2026-08-27).** The architectural fix the evidence had been pointing at.

   The daemon already holds a certificate-verified link to the sibling. So it
   mints a SINGLE-USE secret, hands it over THAT link, and returns the same
   secret to the one-shot. Both ends then meet on `channel_of(secret)`, where
   exactly two parties exist, instead of the fleet channel where every sibling
   does. The secret doubles as the proof, which is why this reuses the
   most-tested path in the product instead of adding one: `send --to` already
   knows how to meet a known device on a shared secret, so a brokered send is
   just an ordinary known-device send. Its authenticity is inherited from the
   link it travelled over, which was verified by certificate.

   The race does not get safer. It stops existing, because only the target was
   ever told the address.

   MEASURED, three gated rigs, interleaved against the paired control, 58/58:

       rig 1   sibling 15/15    paired 15/15
       rig 2   sibling 15/15    paired 15/15
       rig 3   sibling 20/20    paired 20/20
       default path, NO flag    8/8

   That is the first 100% this path has ever recorded, after four patches that
   each made it worse. FILAMENT_FLEET_SEND is no longer needed: brokering works
   without it, and the flag now only exercises the old unbrokered fallback
   deliberately. A fleet name is accepted as a `send --to` target whenever a
   daemon is present to broker.

   SECURITY. The ticket is accepted ONLY from a link whose certificate we
   already verified (`fleet_verified.contains(&pid)`). Otherwise mere presence
   on the fleet channel could manufacture a trusted-looking peering, which is
   the one thing this design says presence must never buy.

1e-old. **`send --to <sibling>`: was OPT-IN, superseded by 1h. Four bugs fixed, still ~50% (2026-08-27).**
   Item 1b said "enable it when item 2 lands, not before". Item 2 has landed, so
   the gate was re-examined and the flip is REFUSED on measurement.

   FIRST, the instrument. Every earlier fleet-send number in this file is VOID,
   including "verified in one topology". Repeated rig rebuilds left daemons from
   previous runs alive, and a stale daemon sits on the SAME fleet channel under
   the SAME owner key, so it is indistinguishable from a real sibling: the sender
   was choosing among as many as 15 impostors instead of 2 devices. It was caught
   only because the PAIRED control path, 8/8 in every honest run, fell to 0/8.
   `fleetsend2.sh` now kills every scratchpad daemon and asserts zero before it
   starts. This is the second time a fleet finding turned out to be a harness
   defect, after the shared-inbox one; a fleet result without a stated
   zero-daemon check should not be believed.

   MEASURED, clean rig, release build, 8 attempts per direction:

       sibling -> sibling    6/16   HEAD 1c4b783 (baseline)
       sibling -> sibling    8/16   with the fixes below
       device  -> owner     16/16   both (the ordinary PAIRED path)

   So sibling send was NEVER reliable; the flag was hiding it, not protecting a
   working feature. It fails closed and has never misdelivered in any run.

   FIXED HERE, four bugs, each real and each found by measurement:
   - `fleet_bind_ours` / `fleet_bind_theirs` / `fleet_rechallenged` were single
     values on a channel that carries EVERY sibling, so the last peer to connect
     overwrote the binding the previous one signed against and the real target's
     hello failed as "channel-binding mismatch", spending the single retry.
     Now keyed by pid. This is the same shape as the `fleet_proven` bool and the
     THIRD instance of one-value-for-many-siblings on this channel.
   - `fleet_bind_theirs` was written and never read; removed.
   - A peer PROVEN to be a different sibling was dropped but not remembered, so
     the next roster tick re-adopted it as the target, in a loop, starving the
     real device. Now recorded in `fleet_wrong` and never targeted again.
   - Nothing bounded how long an unproven peer could hold the target slot. The
     OWNER is the standing case: it is PAIRED with us, so its daemon never sends
     `fleet-hello` at all, and waiting for its proof waits forever. Now a 12s
     per-peer budget (`FILAMENT_FLEET_PROOF_SECS`) releases the slot.
   - Receiver side: an offer arriving while the sender's `fleet-hello` was still
     in flight was DECIDED against a link that read `binding=None`, declining a
     peer that was about to be Proven. Now deferred and replayed on verification.
     Note the first version of that fix hung the replay inside `if fresh`, which
     fires only on a link's FIRST verification, so on a warm link every deferred
     offer was stranded: 0/8. That is "decision on a narrow view" again, mine.

   ROOT CAUSE FOUND (2026-08-27). It was never a discovery race. The
   `ChannelReady` handler opens with `if !conn.is_active(&pid) { continue }`, and
   the fleet path re-emits `ChannelReady` when a peer proves its certificate. On
   the fleet channel some OTHER sibling routinely wins the active slot first (the
   owner especially, since it is paired with everyone and answers no fleet
   challenge). So the real target proved itself into a slot it did not own, its
   re-emit was discarded one line in, its offer was never made, and the send
   timed out 45s after verifying the right device. Fixed: on a fleet send,
   identity IS the selector, so a peer whose certificate names the target BECOMES
   the active peer (`conn.active = Some(pid)`) before the re-emit.

   That also explains the cold/warm pattern that made this look environmental:
   warm runs passed because the target happened to win the slot, cold runs failed
   because a competitor did.

   MEASURED, interleaved A/B (treatment and control alternate inside the same
   time window, so any drift hits both), two independent rigs:

       sibling -> sibling   ~50/55  (91%)   with all fixes
       sibling -> sibling    8/15   (53%)   before the active-slot fix
       device  -> owner     45/45  (100%)   throughout

   METHODOLOGY, and it is why the earlier numbers moved. Running all of one arm
   then all of the other let a bad two-minute window land entirely on one arm:
   the SAME binary measured 2/8 and 8/8. Only interleaved runs are comparable.

   STILL OPEN AT THE TIME, ~9%, AND CLOSED BY 1h RATHER THAN BY FIXING IT: the
   receiver sometimes declines with "not in auth key caps".
   Its gate decides the offer before the one-shot sender's `fleet-hello` has been
   verified, so an unverified fleet link is judged against the empty ceiling it
   is born with. The narrow deferral (`fleet_pending`, meaning "a hello IS
   coming") plus a bounded grace covers most of it. Broadening the predicate to
   "any untrusted fleet-shaped link could still verify" was tried and MEASURED
   WORSE, 11/15 -> 3/15: it parks offers whose hello was already handled, which
   then wait out the grace and are declined anyway. Do not retry that.

   MEASUREMENT WAS THE BLOCKER THEN, and it is why this item stops here: the
   next thing built was 1h, not a fifth patch to this ceremony. The rig-identity
   confounder below is still live for ANY future sibling-path measurement.
   Interleaving controls for drift WITHIN a rig, but RIG IDENTITY is a
   confounder and it is larger than any effect being chased. The same release
   binary measured:

       rig A   sibling 17/20      rig B   sibling  7/20
       rig A   paired  20/20      rig B   paired  20/20

   The paired control is 20/20 on BOTH, so a rig is not simply "bad": whatever
   varies touches only the sibling path. Until a rig-to-rig control exists, any
   two numbers from different rigs are not comparable, and three separate
   conclusions in this file were drawn from exactly that comparison before the
   confounder was noticed. Candidate controls: many rigs per arm with the arm
   randomised per rig, or a deterministic harness that removes real signaling
   and ICE from the loop (the Python control-plane harness already does this for
   the signaling flakiness and is the obvious model).

   THE HARNESS HAD THREE HOLES, all found by disbelieving its own output:
     1. stale daemons from earlier runs sit on the SAME fleet channel under the
        SAME owner key, indistinguishable from real siblings;
     2. the cleanup matched `release/filament up`, which does NOT match a daemon
        started as `filament -vv up`, so a hand-started verbose daemon survived
        every purge AND was invisible to the "0 strays" assertion, since both
        used the same pattern. Identify a test daemon by its config dir in
        /proc/environ, never by its command line;
     3. no health gate, so a run where B and C never started reported 0/20 on
        BOTH arms, including a paired control that has never honestly failed.
   All three are now asserted before any sweep, and the gate polls, because
   `up --detach` returns well before the daemon is serving (A can take over 40s).
   A number from an ungated rig is not evidence.

   THINGS TRIED THAT MEASURED WORSE, recorded so they are not retried blind:
     - broaden the receiver deferral to any fleet-shaped link:  11/15 -> 3/15
     - classify fleet links at adoption instead of ChannelReady: 0/20 and 5/20
     - greet every fleet link, not only the active one:         17/20 and 7/20
     - mutual `fleet-hello-ack` before offering:                0/15
   All four are plausible on paper, and the fourth is arguably the CORRECT
   protocol fix: verification is mutual, the sender only ever knew its own half,
   and it offered into a race it could not see. It still measured 0/15 against a
   paired control of 15/15 on the same rig, and a verbose run showed the target
   never proving at all rather than the offer being held. Reverted.

   FOUR patches to this handshake, four regressions. That is the finding, not an
   accident: each one adds a wait or a condition to a ceremony that is already
   losing races, and the marginal fix keeps making the ceremony longer. The
   conclusion the evidence supports is the architectural one below, and future
   work should go THERE rather than at a fifth condition.

   THE RIGHT FIX IS ARCHITECTURAL, and the data points at it. The daemon-to-daemon
   mesh verified 100% of the time in every run, including every run where the
   one-shot send failed. The one-shot is a THIRD process that re-does discovery
   and identity from scratch against a channel full of siblings. It should not:
   it should ride the daemon's already-verified link (item 1c, warm-send), or
   have the daemon broker a private single-use rendezvous for it. Build the
   flaky thing on top of the thing that is already reliable.

   THAT IS EXACTLY WHAT 1h DID, and it measured 58/58. This paragraph is kept
   because the reasoning that produced it (four marginal patches, four
   regressions, so stop patching the ceremony and remove the race instead) is
   the transferable part; the plan itself is done.

2-DONE. **Owner-signed grant distribution: BUILT and verified (2026-08-27).**
   Owner-signed `CapOp`s now reach fleet devices two ways: seeded in the
   enrollment ack, and re-pushed on every verified `fleet-hello` so later grants
   propagate. `merge_owner_cap_ops` keeps only ops whose grantor IS the owner key
   the receiver already holds and whose signature verifies, so a peer relays
   policy without being able to author it. Measured: a grant made after
   enrollment reached both siblings, byte-identical, and stayed at one op across
   a full mesh restart (idempotent).

2-old. **Owner-signed fleet ceiling.** Capabilities do not flow across a fleet today;
   every grant stays explicit. An owner-signed default ceiling delivered at
   enrollment is the shape, deferred deliberately.
3. **L3-over-relay performance.** The DataChannel is reliable and ordered, so the
   tunnel head-of-line blocks and shares the channel with file transfer. Fine as
   a fallback, worth a second unreliable channel if it ever carries real load.

## 2026-09-01: subnet routes proven between two real machines

`experiments/subnet-route-e2e.sh` runs the feature between do-vm and a KVM VPS
(interserver-0x0) over the real internet, and it now passes end to end.

**Result.** Two phases, identical in every respect except the owner-signed
invitation ceiling:

    ceiling transfer,mount        -> refused,   10.66.0.5 UNREACHABLE
    ceiling transfer,mount,route  -> installed, 10.66.0.5 REACHABLE
                                     (10.66.0.0/24 dev filament0)

Both phases are in one run on purpose. Running only the success case would show
that routes CAN install, not that authorization is what permits them; an
unconditional `return true` would pass that test just as well.

**Six defects found, all by running it.** Five lived in the seam between two
components that were individually correct and fully unit-tested, which is why
the suite was green throughout. Full write-up in `docs/design-subnet-routes.md`;
in short: the advertisement was never put on the wire; no kernel route was ever
installed; `route` was missing from the invitation bitmask whose encoder
silently collapsed the entire ceiling to empty; `mint_capability` was a second
hardcoded capability list; enforcement derived the owner key in a way that
returns `None` on exactly the devices the feature is for; and the ceiling was
read from a link principal that only carries caps on the first join.

**Rig notes worth keeping.** `l3::ifname()` is a hardcoded const, so a second
daemon on a host that already runs one cannot get a kernel TUN and silently
degrades to the userspace overlay, which installs no kernel routes. Each test
daemon therefore runs in its own network namespace. Test daemons must be killed
by EXECUTABLE, not by config dir: `FILAMENT_CONFIG_DIR` is an env var and never
appears in `/proc/<pid>/cmdline`, so three leaked daemons piled up before a
"Text file busy" on rebuild gave it away. The rig pins its binary out of the
shared `CARGO_TARGET_DIR` and asserts its hash.

**Verification.** cli 401 tests pass, filament-cap 97 pass, warning ratchet 116
against a baseline of 116. The release binary that produced the green run is
byte-identical (`58e9123b3d13db9da16a`) to a rebuild of the committed tree.

**Open decision for the owner.** A ceiling records an ACTION and no resource, so
`route` in a ceiling authorizes any prefix that fleet member advertises,
including `0.0.0.0/0`. It is bounded by `accept-routes` being off by default and
per-peer settable. Narrowing to a per-prefix ceiling requires a v3 invitation
token, since v2 encodes caps as an 8-bit mask with nowhere for a CIDR.

## 2026-09-02: certificate renewal, so the mesh stops dying on a timer

`docs/design-pairing-ux.md` rule 2 has always said expiry is the only bound,
that fleet certs are short and auto-renewed, and that removing a device is
"stop renewing". None of it was built. #236 found the UI promising
"renews in 87d" and fixed the SENTENCE, which left both halves broken: devices
silently fell off the mesh when their certificate lapsed, and a removed device
kept full fleet trust until a 90-day certificate ran out.

`cli/src/fleet_renewal.rs` is the decision core (pure, 13 unit tests) and
`experiments/cert-renewal-e2e.sh` proves it between do-vm and the KVM VPS:

    good standing:  1788350731 -> 1788350950   renewed on a LIVE link
    revoked:        unchanged                  refused, left to expire

**The rule-2 / rule-3 tension, resolved deliberately.** Rule 3 forbids any
ambient or remote signing path. Renewal is not a new trust decision: it re-signs
a device the owner already admitted, same key, same ceiling, moving only the
clock, so it renews good standing and can never ADMIT. Absent, revoked and
lapsed all refuse. Lapsed is the interesting one: enrollment revives a lapsed
device because a human issued a fresh invitation, and renewal has no human in
it, so allowing it to revive would build exactly the ambient path rule 3 bans.

**Two bugs the rig caught that unit tests could not.**
1. Renewal only triggered on link-up, so a device connected for its whole
   certificate lifetime never re-checked and expired while online, which is the
   silent death the feature exists to prevent. Now also on a 30s timer.
2. Persistence used `write_owner_only_file`, which opens `create_new(true)`
   because it exists to mint invitations, so it refused to clobber. The owner
   signed, the device accepted, and the last line failed. Every step reported
   success except the one that mattered. Now uses `SecretFile::write_str`, the
   same writer enrollment uses for that exact file.

**Renewal cannot widen.** `renewal_ttl` re-signs for the lifetime the current
certificate already has, clamped to the default. A guest invited with
`--expires 1h` renewing into a 90-day member would widen the very bound renewal
enforces. Verified in the rig: a 300s invitation renewed to 297s, not 90 days.

**Recorded honestly:** in the revoked arm the refusal came from
"requester is not identity-proven on this link", not from the revocation branch.
Revoking the certificate denies the device at the capability gate before it can
reach that check, so the property holds by two independent refusals, but the
`Decision::Refuse("device is revoked")` branch is covered only by its unit test,
not by the end-to-end run.

**Still open.** Certificates remain 90 days by default. Rule 2 wants days, and
renewal is what makes short certs survivable, so shortening the default is now
possible and is a deliberate policy call rather than a code change.
