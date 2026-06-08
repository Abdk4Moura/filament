# Observability: the session state machine (allowlist monitoring)

Status: DESIGN + LIVE (`scripts/tel-watch.py`). Sibling of
`design-c30-convergent-session.md`: C30 makes divergence *self-correct*;
this makes divergence *visible*. The two are the same philosophy at two
layers — convergence in the product, allowlist in the observatory.

## Why allowlist, not denylist

The first monitor grepped a list of known-bad event names
(`pair-claim-fail|proof-fail|second-wind|…`). That can only catch failures
already seen — the exact overconfidence reality punishes. Proof, 2026-06-08:
two CLIs entered the same pair room, exchanged no completing handshake, the
creator watchdog'd out and quit, the claimer orphaned — and **not one event
in the denylist fired.** The ceremony "failed" by *not happening*, and you
cannot grep for an absence.

The fix is to invert: define the LEGAL state machine for every client, and
flag any trajectory that leaves it — including by *dwelling too long in a
non-terminal state* (the absence case) and by *reaching a terminal state
without success*. Divergence, not signature.

## Client taxonomy (by sid/uid prefix)

| Kind | uid prefix | Telemetry | Role |
|---|---|---|---|
| browser | (random uuid) | `web:*` per session `s` + server `connect/join/sync` per `sid` | mesh peer |
| cli send | `cli-s-` | server `connect/join/sync/pair-create` | one-shot sender |
| cli recv / up | `cli-r-` | server `connect/join/sync/subscribe` | listener / daemon |
| cli pair | `cli-p-` | server `connect/join/sync/pair-create/pair-claim` | pairing ceremony |
| cli introduce | (cli-s/p) | as above + dual channels | voucher |

Signals (SDP/ICE) are deliberately NOT telemetered (too hot). So the
WebRTC handshake is observed *indirectly*: a pairing that connects at the
signaling layer (two sids, one room) but never reaches a terminal-good
state within the budget is STUCK — exactly the gap that hid the CLI bug.

## The legal lifecycle (every client)

```
            connect
               │  (≤12s)                       D1: connected, never joined
               ▼
             join ──────────────► IN_ROOM ◄────── sync (heartbeat, ≤ every 35s
               │                    │              while live; gap ⇒ D6 silent)
   pair-create │                    │ subscribe
               ▼                    ▼
         WAITING_CLAIM         SUBSCRIBED ─────► known-peer ⇒ PAIRED_ROOM
               │  (claim)           (channel rendezvous)
               ▼
          (pair-claim-ok) ─────► PAIRED_ROOM
                                     │  (≤30s: must progress to a terminal)
                                     ▼
                          ┌──────────┴───────────┐
                          ▼                       ▼
                    TRANSFERRED              MUTUAL_REMEMBER
                  (web: peer ready,         (pair-keep-stored /
                   transfer complete)        proof-ok both ends)
                          │                       │
                          └──────────┬────────────┘
                                     ▼
                              clean disconnect      ◄── TERMINAL-GOOD
```

### Terminal-good (no flag)
- A transfer reached `complete` / `done`, then disconnect.
- A pairing reached `pair-keep-stored` + `proof-ok`, then disconnect.
- A browser session went `hidden`/`pagehide` (user navigated away) with no
  obligation outstanding.

### Divergences the monitor flags (the allowlist's complement)

| ID | Condition | Why it matters |
|---|---|---|
| **D1** | `connect` with no `join` within **12 s** | roomless ghost forming |
| **D2** | `pair-claim-ok`, then **30 s** with no terminal-good for either party (no web-ready, no proof-ok, no clean co-disconnect) | the CLI bug: pairing connected, handshake never completed |
| **D3** | one party of a claimed pair `disconnect`s while the other stays live **>15 s** | orphaned waiter |
| **D4** | a web peer enters `connecting` and within **25 s** reaches **neither** `ready` **nor** `failed` | the SILENT stuck (failed is loud; never-resolving is the quiet killer) |
| **D5** | a `pairc-`/`up-`/`intro-` room holds exactly **1** sid for **>10 min** | orphan ceremony / abandoned daemon waiter |
| **D6** | a live sid's `sync` heartbeat gap **>90 s** while still connected | session loop wedged (the convergence engine itself stalling) |
| **D7** | known-bad still pass through (`pair-claim-fail`, `proof-fail/rejected`, `subscribe-retry`, `state-diverged`, web `peer connecting→failed`) | retained as a SUBSET — loud failures stay loud |

The invariant set these encode (cross-ref the C30 design's invariants):
1. *Every connect reaches a room.* (D1)
2. *Every claimed code reaches a completed pairing, or someone is told.* (D2/D3)
3. *Every `connecting` resolves — to ready or to honest failure, never limbo.* (D4)
4. *No ceremony room stays half-occupied forever.* (D5)
5. *The convergence loop never goes silent while alive.* (D6)

New legal states get added HERE first (an entry in the lifecycle), then the
monitor's allowlist, then the divergence table — never silently, same
discipline as the resilience ledger. A divergence the monitor can't yet
classify is printed as `D?: <sid> unexpected <event> in <state>` rather than
dropped — an unknown is louder than a known, by design.
