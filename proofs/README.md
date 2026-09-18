# Filament establishment proof

An exhaustive, re-runnable correctness check for the peer-to-peer
connection-establishment protocol. Run it:

```
python3 establishment_model.py        # N=2 and N=3, both tiers
python3 establishment_model.py 2      # only the 2-peer runs
```

It explores the **entire** reachable state space of a faithful model and
verifies, for N peers:

| Tier | Assumptions | What is proven |
|---|---|---|
| **0 GoodNet** | reliable bounded delivery, no spurious disconnect, connectivity exists (ICE finds a path), fair scheduling | no invalid state; no deadlock; CONNECTED always reachable; clean-FAIL **never** reached |
| **1 DegradedNet** | GoodNet **minus** reliability: up to K network faults (lost signals, unclean disconnect, black-holed link, peer supersede) | invariants still hold in every state; **no deadlock at any point** (a timer always rescues a wait); every trajectory reaches a terminal in bounded steps; and once faults stop the system **self-heals to CONNECTED** instead of stalling at FAIL |

Exhaustive over a bounded model is a *definitive* result for that bound: the
checker finds **every** stuck/invalid state, not just one we tripped over. This
is the same class of technique as TLA+/TLC or Spin, written as a self-contained
explicit-state checker so it has no external dependencies and is fully auditable.

## Latest result

```
GoodNet  N=2  -> PROVEN (4 states)        GoodNet  N=3  -> PROVEN (64 states)
Degraded N=2  -> PROVEN (K=1,2,3)         Degraded N=3  -> PROVEN (K=1: 4544, K=2: 66976 states)
```
0 invariant violations, 0 deadlocks, 0 unreachable-terminal states, 0 post-fault
states that can't self-heal — in all runs.

## Companion: the transport-lifecycle proof

`establishment_model.py` proves the **signaling** protocol (offer → answer → ICE
→ CONNECTED). Its sibling, `transport_lifecycle_model.py`, proves the **data
plane** that begins once a pair is CONNECTED: carrying a file over a transport,
confirming whole-file delivery, tearing the transport down, and reusing it for a
second transfer. Run it:

```
python3 transport_lifecycle_model.py
```

Every bug in the multi-stream throughput push (a dead-link **corpse** that blocks
its own re-dial; a **lost delivery-ack** from a premature QUIC close; a
**both-answerer role** that dials nothing) lived in the gap *between* the
establishment model and the liveness classifier — each assumed the other owned a
transport-less-but-established link. This model closes that gap. It encodes the
three fixes as independent booleans and checks all 2³ combinations, proving:

- **GoodNet** (perfect DO↔DO link): correct **⟺ `role ∧ (teardown ∨ guard)`** —
  verified on all 8 combos. Each conjunct is necessary; together sufficient.
- **Degraded** (real mid-transfer drops): the liveness-aware re-dial (`guard`)
  becomes *independently* necessary; all fixes on → self-heals in bounded steps.

The design write-up is [`docs/transport-lifecycle-state-machine.md`](../docs/transport-lifecycle-state-machine.md).

## Companion: the transport-upgrade proof

`transport_upgrade_model.py` covers the layer the other two structurally cannot
see. Both of them model a **single** transport slot, so the upgrade — two paths,
one destroyed in order to try the other — is not representable in either. They
stayed green through every defect below, and a clean run from an instrument that
cannot represent the fault is not evidence.

After the PAKE ceremony the code drops the authenticated WebRTC link and races a
direct-QUIC dial ("Option A"). Six separate fixes over three days were each a way
of making the resulting gap smaller: reordering `establish()`, carrying
`expected_secret` across the rebuild, `DirectIntent::Promote`, the
`direct_pending` removal that precedes a `bind_endpoint` failure, sync-digest
roster reconciliation, and the macOS regression. They are one defect. This model
makes it a state predicate:

> **I-GAP** — no live path, and no armed successor.

It checks three designs (`EAGER` = main, `LATE` = the promote-intent branches,
`PATHSET` = build-alongside-then-promote) across 2⁴ environments, and refuses to
report anything until it first reproduces the four outcomes CI actually produced
on 2026-08-03. Results:

- **T3/T4** `PATHSET` dominates **only** when the post-PAKE link can attach a data
  plane on its own. While it cannot, destroying the link is the *only* route to a
  live transport, so `PATHSET` is clean in 0/8 against `EAGER`'s 4/8. The obvious
  first-principles redesign would be **strictly worse than main** if adopted
  first. Data-plane attachment must be fixed *before* the redesign.
- **T5** `LATE` (1/8) is strictly worse than `EAGER` (4/8) under the same
  condition, which is the regression PRs #78/#79 shipped, derived rather than
  guessed from a red check.
- **T6** roster reconciliation is **load-bearing**: all four environments where
  `EAGER` breaks have it off. It must not be removed. Given the `D_BURNT`
  correction it is also the only thing standing between a failed fallback attempt
  and I-GAP, so it is *more* load-bearing than the first version of this model
  said, not less.

Two corrections from `claude-advisor` are folded in, and both made `main` look
worse rather than better. `D_FAILED` buys exactly **one fallible, unretried**
recovery attempt (`main.rs:7608` logs the `establish()` failure and moves on),
not an armed successor, so a `D_BURNT` state was added; and a pending can be
**cancelled** rather than expired by the `link_dead` branch, which reaches the
same gap by a second route. Together they cost `EAGER` an environment (5/8 → 4/8)
and `LATE` one (2/8 → 1/8).

`ctrl_carries` — *can a transfer **complete** over the post-PAKE link without that
link first being destroyed and rebuilt?* — is a free parameter rather than an
assumption. Gate 0 derives it: `False` is the only value reproducing all four
observed outcomes (2/4 with it `True`). Four points against one free bit is a fit
as much as a derivation, so the falsification test carried the weight, and it has
now **run**: the green `main` macOS artifact (run 30825113095, job 91724637129)
shows the drop at `main.rs:10871`, ICE closing, a second gather on a new host
port, and sha256 delivery success only *after* the rebuild. The green path rides
a rebuilt link. Confirmed by artifact, not by fit.

The definition is deliberately **observational**. Two readings still fit and this
model does not distinguish them: (A) the retained link genuinely cannot carry
data, or (B) the link is fine and the sender never progresses because it waits on
a transition only a rebuild emits. They imply different fixes, so nothing here
should be read as asserting A. The discriminator is whether the sender ever
*attempted* to send file data on the retained link.

All of these proofs are required CI gates (`.github/workflows/proof.yml`).

## Companion: the stall-ladder model

`stall_ladder_model.py` models the five-rung correction ladder with transience,
failure type, and discarded recovery state as explicit inputs. Gate 0 first
reproduces the observed #31, #50, and #38 outcomes: five attempts, 75 seconds,
and no ladder recovery. The observations alone cannot distinguish a persistent
condition from a transient condition whose required state the teardown
discarded. It then shows the boundary: a transient condition can recover on a
later rung only when the state that rung needs was retained. #50 directly shows
state destruction, but whether its ICE condition was transient remains
unmeasured; #38's later roster recovery is external and is not credited to the
ladder.

The model sweeps transient windows of 0.5, 1, 2, 3, and 5+ rungs against both
 fail-fast and preserve-state candidates, with retention boundedness explicit.
It reports their divergence band and requires the separating measurement to
instrument the ICE condition and conntrack state directly, never file arrival.

The retention precondition is a code question before it is a network question:

| State a preserve-state rung would hold | Bound status | Cost / open question |
|---|---|---|
| WebRTC peer and ICE/DTLS sockets | BOUNDABLE | Holding a peer/socket for one rung costs roughly 15 seconds of resources; a lifetime policy does not exist today |
| NAT mapping and conntrack state | NOT OURS TO BOUND | Host defaults are `nf_conntrack_udp_timeout=30s` and `nf_conntrack_udp_timeout_stream=120s`; the five-rung ladder is 75s. The #50 dumps showed `[UNREPLIED]` entries, which use the shorter timeout, so the kernel can expire the state before the ladder finishes. The app can send traffic but cannot set the entry's lifetime. |
| QUIC transport file descriptor and UDP port | BOUNDABLE | One descriptor/port per retained transport for at most one rung; count is bounded per link and configured worker count, but the lifetime policy does not exist today |
| `direct_pending` expiry | BOUNDED TODAY | Pending state already has an expiry path |
| `buffered_offers` / `deferred_left` entries | BOUNDABLE | Per-peer entries are small, but a global retention ceiling would need to be designed |
| Active link slot | BOUNDABLE | Count one per peer; lifetime still follows the retained transport |

The host check also showed live UDP entries in both states: `[UNREPLIED]` and
`[ASSURED]`. That matters because only the latter has the longer stream timeout;
the relevant #50 entries were `[UNREPLIED]`. This is evidence that conntrack is
not ours to bound for the ICE case, not evidence that every NAT flow expires in
30 seconds. The exact arithmetic from this host's operator-configurable kernel
defaults is decisive for the observed case:

```
nf_conntrack_udp_timeout          30s   (UNREPLIED)
nf_conntrack_udp_timeout_stream  120s   (ASSURED)
ladder                            5 x 15s = 75s
#50's observed entries            [UNREPLIED]
```

An `UNREPLIED` entry expires at 30 seconds, so it is gone before rung 3 of a
75-second ladder. An entry only earns the 120-second `ASSURED` timeout by
receiving a reply; #50's defining failure was that no reply arrived. The entry
therefore cannot be promoted and expires mid-ladder by construction. The
failure that prevents the reply is also what prevents the state surviving long
enough for the retries to use it.

This closes the ICE/conntrack half of #63: bounded preserve-state cannot retain
that kernel-owned state, so fail-fast or a fundamentally different approach is
what remains and the expensive condition measurement is unnecessary there. It
does not close the QUIC fd/port case, where state is ours and a bound is
constructible, nor #31's transport-level data-freeze case, which is not
conntrack. The sysctl values are from this host and an operator can change them;
the arithmetic must be recalculated for a deployment with different defaults.

If retention cannot be bounded, naive preserve-state without an explicit
lifetime bound is unsafe and fail-fast wins for that design. A bounded
preserve-state variant remains live: the sweep says the candidates diverge
across the full 0.5-5 rung range, so condition instrumentation remains worth
taking. This is an inventory only; it does not implement state preservation.

Gate 0 also reads `MAX_ATTEMPTS` from anywhere under `cli/src` (shared_defs.rs
since the 2026-09-12 decomposition) and `WATCHDOG_SECS` from
`crates/filament-transport/src/net.rs` (moved out of `cli/src` on 2026-08-27);
a source change fails the model until its calibration is
explicitly redone.

Run it with:

```
python3 stall_ladder_model.py
```

## The properties

- **I1 glare-freedom** (safety, structural): of any pair the lexically-lesser
  uid is the sole OFFERER. `polite_role` is a strict total order, so exactly one
  side offers — glare can't deadlock. (net.rs:1002; webrtc.js:314; CONTRACT.md:66)
- **I2 no half-open** (safety): never one endpoint READY while the other has
  given up (FAIL) or never started (IDLE).
- **No deadlock** (safety): every non-terminal state has an enabled transition —
  a watchdog/grace/stall timer always exists to break a wait. This is *the*
  "never stuck at any point in time" guarantee.
- **Liveness AG-EF**: from every reachable state a terminal is reachable (no
  stuck SCC). GoodNet's terminal is always CONNECTED; Degraded's is CONNECTED or
  an honest clean FAIL, and post-fault states can always still reach CONNECTED.
- **Bounded recovery**: the BFS depth (`depth<=`) is a finite upper bound on
  steps-to-settle — recovery per fault is bounded, never open-ended.

## State <-> code mapping (faithfulness)

The model is extracted from the deployed code; this is the weak link of any such
proof, so it is spelled out. Both clients implement the same protocol
(cross-impl parity is test-pinned), so one canonical FSM models both.

| Model element | Rust (`cli/src/`) | Web (`frontend/src/`) |
|---|---|---|
| role = polite_role total order | `net.rs:1002` | `lib/webrtc.js:314` |
| OFFERER creates offer; ANSWERER waits | `net.rs:1118-1145` | `webrtc.js:451-462,517` |
| glare: impolite ignores / polite rebuilds-or-rolls-back | `net.rs:1233-1252`, `main.rs:4043-4058` | `webrtc.js:540-553` |
| deliver offer -> answer | `net.rs:1254-1281` | `webrtc.js:547-553` |
| deliver answer -> connected (ICE succeeds, A4) | `net.rs:1247-1264` | `webrtc.js:468-471,653` |
| establishment watchdog (15s) -> retry/FAIL | `net.rs:48`, `main.rs:3101` (MAX_ATTEMPTS=3) | `webrtc.js:524`, `useFilament.js:471` (cap 2) |
| disconnect grace (6s) -> retry/FAIL | `main.rs:3870` GraceExpired | `webrtc.js:499-505` |
| stall ladder: repair -> relay (once) -> clean FAIL | `main.rs:3284` correct_stall (STALL_MAX_REPAIRS=5) | `stall.js`, `recovery.js:22-27` |
| supersede on reconnect (same uid, new sid) | `main.rs:2534-2563` | `useFilament.js:292-308` |
| self-heal from FAIL (known-peer / re-pair) | C12 channels, `subscribe` | `lib/devices.js`, digest reconcile |
| fault: lost signal | (network) | (network) |
| fault: black-holed link (the zombie) | the verify-before-accept fix, beta.23 | n/a |

## Honest boundary

This proves the **signaling + establishment logic** as abstracted here. It does
**not** prove WebRTC's own ICE/DTLS stack or the OS network — those are
assumption A4 ("a path exists" = what "good internet" means). It checks bounded
N and a bounded fault budget. The model is hand-extracted, not mechanically
generated from the code, so the mapping table above is the thing to keep honest
as the code changes.

The payoff is the clean separation the whack-a-mole was missing: **every failure
mode we have chased (zombie links, ghost presence, the 15s stall) is a violation
of a Tier-1 assumption — a real network fault — and Tier-1 proves each one
recovers in bounded time. There is no GoodNet failure.** New protocol changes
should update the model + mapping first, re-run this, and stay green.

## Companion: the capability-ledger proof

`capability_ledger_model.py` checks the authorization plane defined by
CONTRACT.md's **Capability ledger (append-only signed ops)** section: an
append-only log of signed ops, and `decide(facts, request)` as a pure function
of it. Run it:

```
python3 capability_ledger_model.py              # the laws
python3 capability_ledger_model.py --self-test  # break one law at a time
```

It is the only model here that checks a design **before** the code exists. The
engine today (`crates/filament-cap/src/capability.rs`, `cli/src/shell_gate.rs`)
has no deny, no pause, and no subject-signed accept: `CapOpKind` is
`Grant | Revoke | Modify` and `Revoke` deletes the row. So gate 0 reproduces
only the behaviour that DOES exist -- the oracle rows of
`exec_matches_pty_across_gate_matrix` (revoked must deny, a narrow ceiling must
deny, trusted-plus-granted must allow) and CONTRACT.md's "expiry IS the
revocation mechanism" -- and prints the new primitives as new rather than
claiming to have reproduced them.

Eighteen laws, each a numbered clause in CONTRACT.md and a named check here.
L14-L18 arrived as review rulings and the contract now declares them:

| Law | What it pins |
|---|---|
| L1 / L2 | purity, and that display names -- and ONLY display names -- move no verdict |
| L3 / L9 | every op has an interval; `valid_until` is returned, and the verdict cannot change before it |
| L4 | deny absolute, ceiling only narrows, newest version per author wins |
| L5 | widening needs a Grant AND a subject-signed Accept; narrowing needs one signature |
| L6 | signature and version checks at ingest, never inside the evaluator |
| L7 | `because` is a minimal sufficient cause, verified by deletion |
| L8 | capabilities are opaque `(action, resource)` pairs plus `covers()` |
| L10 | no widening by combination; a deny is a tombstone only its author lifts |
| L11 | arrival order and replay change nothing |
| L12 / L13 | pause is author-only, pattern-scoped, and reads `paused`, not `denied`; accept names one live grant |
| L14 | `Pass` is a Grant species and attenuation-only: a pass its author cannot back is INERT, and "backed" excludes the author's own self-certified grant |
| L15 | a revoked or expired certificate denies absolutely, with `revoked` and `expired` as DISTINCT reasons |
| L16 | every allow needs `binding` at least as strong as the STRONGEST `min_binding` in its cause; `inferred` is a plain-Grant property only |
| L17 | the held author key is the trust root: its own ops are effective, a delegated op is effective only inside a ceiling it granted, and ACCEPTS are exempt because L13 governs them |
| L18 | compaction preserves every verdict AND every `because`; a Deny tombstone and a shorter-interval revision both agree with the deletion they replace |

Two properties of the run matter as much as the green:

**Vacuity is a failure, not a footnote, and now PER TIER.** The run asserts that
every verdict shape -- `Allow`, `denied`, `paused`, `above-ceiling`,
`unaccepted`, `no-grant`, `revoked`, `expired`, `unproven` -- was actually
produced, that the checks guarding the rarest of them ran at least once, AND
that each tier reaches the verdict shapes it must reach: a tier that ran and
could only produce denials fails the run, and so does a tier that ran without
declaring what it must reach.

That last check exists because a global total hid a real defect. The first L17
filtered the ACCEPT out of the trust model, so an owner-granted device could
never allow: the DEPLOYED owner->device shape produced 544 denies and ZERO
allows, every law still passed, and the run reported 2.88 million cells and no
violations. Cell counts are not evidence that a law constrains the
configurations that SHIP, so the deployed shape is its own tier now, its allow
count is printed (`allows with held != subject`), and reintroducing the bug is a
mutation -- `trust-filter-drops-accepts` -- that the per-tier gate must catch.

The same gate also catches the older, milder hole: the first version of this
model never reached `paused` or `above-ceiling` at all: at N=2 a grant and its accept fill the log, leaving
no slot for a ceiling or a pause, so both checks passed without being tested.
That is the `S1`-under-tier-0 failure from the fleet model in a new costume,
and the N=3 tier exists because of it.

**The checker is validated by mutation.** `--self-test` breaks one rule at a
time -- deny no longer absolute, accept no longer required, a ceiling that
grants, stale versions winning, `valid_until` pushed past the change point,
`because` returned unminimised, ingest admitting a stale op or a bad
signature, the evaluator reading the cert or the display name -- and requires
the law that each breach violates to go red. The ceiling mutation had to be
rewritten to make it bite: making a ceiling merely INERT still satisfies "only
narrows" (it narrows by nothing), so the mutation had to be a ceiling that
actually grants. A mutation that does not violate the law it targets proves
nothing about the check.

The model states its reading of the under-constrained points rather than
resolving them quietly: `Certify` is not a ledger op at all (it is an
identity-lifecycle event whose result reaches the evaluator as Facts.cert, law
L15), `Pass` is a Grant species whose attenuation rule is L14, and a `Pause` is
scoped by its own capability pattern. It also records that L10's plain-English form
is contradicted by L5 -- a Grant and an Accept each deny alone and allow
together -- and checks the restricted form, requiring that pair to be the
ONLY widening combination in the whole universe.

### Latest result

```
2,591,593 cells, 0 violations, 6.1 s      12/12 mutations caught
```

## Companion: the fleet auto-mesh proof

`fleet_automesh_model.py` model-checks the membership plane added by
`docs/design-fleet-automesh.md`: devices certified by one owner key discovering
and admitting each other over a shared rendezvous channel, with revocation,
fleet_rv rotation, and offline churn. Run it:

```
python3 fleet_automesh_model.py        # all three tiers
python3 fleet_automesh_model.py 2      # only the intruder tier
```

| Tier | Assumptions | What is proven |
|---|---|---|
| **0 GoodNet** | every device online, no revocation | convergence to a full mesh under EVERY enrollment / subscribe / discover interleaving |
| **2 Intruder** | GoodNet plus an uncertified device parked on every channel id it could learn | presence on the fleet channel authorizes **nothing**: admission needs an owner-signed cert, and the fleet still converges with a squatter present |
| **1 Degraded** | GoodNet **minus** stability: revocation, epoch rotation, revocation-propagation lag, offline/online churn | no reachable state is a trap (the fleet can always still converge), rotation never permanently partitions the fleet, and a learned revocation is never undone |

Liveness is checked by backward reachability from the goal, so the result is the
strong form: not "the goal is reachable from the start" but "**no** reachable
state is a trap".

### Latest result

```
GoodNet  N=2 -> 9      N=3 -> 96     N=4 -> 4644
Intruder N=2 -> 33     N=3 -> 708    N=2 K=1 -> 222
Degraded N=2 K=1 -> 34               N=3 K=1 -> 3584
```

0 safety violations, 0 trap states, in all runs.

### Negative controls (why a green run means something)

The checker was validated by mutation, not by its own clean-run count. Deleting
the local-revocation check makes Degraded fail `S2`; deleting the rotation
delivery makes Degraded N=3 report 1088 trap states; deleting the certificate
check makes Intruder fail `S1`.

That last one is the reason the Intruder tier exists. Under tiers 0 and 1 alone,
removing the cert check from `discover` changed **nothing**, because only an
enrolled device could ever be on a channel, so `S1` was vacuous and passed on a
model that could not express the attack. A check that cannot fail is not
evidence. If you extend this model, mutate it and confirm it bites before
trusting a green run.

## Companion: the bootstrap card reference codec

`card_vectors.py` is not a model checker; it is the other kind of evidence.
The bootstrap card (`fc1`, specified in [`CONTRACT.md`](../CONTRACT.md)) is a
signed structure, so its correctness lives in BYTES: "deterministic CBOR,
sorted keys, shortest ints" is the wire, not a style note, and a spec precise
enough to read is not automatically precise enough to implement twice. This
file implements the card a second time in pure Python (a minimal deterministic
CBOR encoder, the `fdf1` overlay derivation, and the contract's six-step verify
order) and emits `card_vectors.json` so the Rust implementation has fixtures to
agree with rather than a paragraph to interpret. Run it:

```
python3 card_vectors.py           # self-check, then write card_vectors.json
python3 card_vectors.py --check   # self-check and fail on drift (the CI gate)
```

The vectors are two accepted cards (public and private) and one per refusal in
the contract: tampered field, expired, wrong derivation, unknown version, psk
in a public card, oversized endpoint list. Each refusal vector asserts the
SPECIFIC reason, which is what makes them worth having: a refusal that starts
happening for a different reason than the contract gives has drifted even
though the test still says "refused". Ed25519 comes from `cryptography` when it
is installed; without it the script falls back to a loudly marked placeholder
backend and stamps `signature_backend` in the JSON, so structure vectors stay
usable and nobody mistakes a placeholder for a crypto fixture. Runtime is under
a tenth of a second.
