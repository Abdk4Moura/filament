# Transport resilience: the never-flaky model + relay honesty

*Design doc. Decision-grade, no code in this change. Targets the Rust CLI in
`cli/src/` and the browser client in `frontend/src/`. Companion to the failure
ledgers [`../cli-resilience.md`](../cli-resilience.md) (C-series) and
[`../resilience.md`](../resilience.md) (browser's 11 fixes), and to the runner
post-mortem [`../runner/jobrunner-challenges.md`](../runner/jobrunner-challenges.md).*

---

## TL;DR

Two promises, made precise:

1. **Never flaky.** For every client — phone browser, desktop browser, and CLI —
   a session must survive NAT churn, route stalls, signaling drops, and peer
   sleep/wake without the user babysitting or manually retrying. The failure we
   keep hitting is not "connection refused" — it is a **hang**: a channel that is
   *open and alive* but **moving zero bytes** (Pixel delivery stuck at 0% on a
   `direct` route; the runner's box→host result truncating at 7 KB). The model
   below makes that the *primary* signal, not an afterthought:

   > **Detect the stall by watching bytes, not liveness. Correct it on the
   > least-disruptive rung that preserves progress. Only fall to relay when the
   > direct rungs are exhausted.**

   The correction ladder, in order of *least* disruption (each rung preserves the
   filament partials/resume already on disk):
   **(a)** resume/retry on the *same* transport →
   **(b)** switch to an already-warm *redundant* transport →
   **(c)** repair the transport in place (ICE-restart / re-dial / fresh QUIC) under
   the live session →
   **(d)** fall back to **relay** (TURN).

2. **Relay honesty.** Relay (rung-d) routes your bytes *through a TURN server*. It
   is still end-to-end encrypted (DTLS for WebRTC, the pair-secret-keyed QUIC for
   direct), but it is **not a direct link** — the "no middleman on the wire"
   property is gone. So when a client lands on relay it **must show it**, visibly
   and persistently, with an honest one-line explainer. Silent relay is a broken
   promise.

**SLO.** 99.999% of sessions that *can* connect (both peers reachable, internet
up on both ends) complete without user intervention. Out of scope: genuine
internet-down on either side. Measured by the flaky-link sim harness
(`runner/sim/`) plus a relay-fallback livetest.

---

## 1. Audit — what already exists vs the real gaps

This design does **not** start from zero. Filament already has a large, gated,
tested resilience surface. The honest summary: **establishment and recovery are
strong; in-flight stall detection is the hole.**

### 1.1 The transport ladder (CLI)

Three rungs exist today, gated and additive, all behind a single
`Transport` trait (`cli/src/net.rs:109`) so the transfer/L2 logic is
transport-agnostic:

| Rung | Path | Code | Gate | Route label |
|---|---|---|---|---|
| 1 | direct-dial QUIC over host/public candidates | `direct.rs::race_connect` | `FILAMENT_DIRECT` / `FILAMENT_L2` | `direct-quic` |
| 2 | STUN srflx + UDP hole-punch, then rung-1's QUIC verbatim | `holepunch.rs::connect` (+ `direct::race_connect_labeled`) | `FILAMENT_HOLEPUNCH` | `holepunched` |
| 3 | WebRTC / ICE (host/srflx/relay), DTLS data channel | `net.rs::Peer` + `DataChannelTransport` | always (the shipped default) | `local` / `direct` / `relayed` |

The rungs run as a **sequential ladder**, not a happy-eyeballs race:
`start_direct` (`main.rs:1951`) advertises candidates via an opaque
`transport-offer`, the peer's offer drives `on_transport_offer` (`main.rs:2062`),
and `race_connect` does a **simultaneous-open race over candidates** within
`DIRECT_BUDGET` (5 s, `direct.rs:62`). If no authenticated QUIC connection wins,
`expired_direct` (`main.rs:2160`) steps down to WebRTC at a deadline. Inside
rung-3, WebRTC's own ICE then races host/srflx/relay candidates the standard way.

Authentication for the direct rungs is a pair-secret keying-material MAC
(`direct.rs::authenticate`) — strong enough that a relay terminating TLS fails the
MAC. The route label for direct links is carried explicitly (`direct_route` on the
`Link`, `main.rs:1931`/`2151`) because a direct QUIC link has no WebRTC
`route()` to query.

**`--relay`** (`main.rs:122`) forces `RTCIceTransportPolicy::Relay`
(`net.rs:431`) — relay-only ICE. It is the runner's *default* for WAN boxes
(`jobrunner-challenges.md` open-items), precisely because direct-QUIC was the
unstable path. The flag also "hides your IP from the peer" (privacy).

### 1.2 Establishment + recovery (already resilient)

The C-series ledger is genuinely deep. The load-bearing pieces:

- **Establishment watchdog (C3).** `Peer::connect` arms a 15 s,
  generation-tagged timer (`net.rs:508`, `WATCHDOG_SECS`); on expiry →
  `Ev::Stuck` → `on_stuck` (`main.rs:2199`) retries with **fresh ICE config**
  (C5) up to `MAX_ATTEMPTS=3`, then drops honestly. The browser mirror is
  `webrtc.js` `_watchdog` (line 182).
- **Transient `disconnected` ≠ terminal (C4).** `on_pc_state` (`main.rs:2270`)
  gives a 6 s grace + `restart_ice()` from the impolite side (`net.rs:549`),
  then `Ev::GraceExpired` → reconnect. Browser mirror at `webrtc.js:146`.
- **TURN credential refresh (C5).** `fetch_config` (`net.rs:256`) re-fetched
  **before every connection attempt** with 3× HTTP retry — no cached creds to
  go stale.
- **Drop is resumable (C4/C5/C7).** Receiver partials park on disk as
  `<name>.part` + a `<name>.part.meta` sidecar (`PartMeta`, `main.rs:460`)
  carrying `{size, head}`; `head` is sha256 of the first 256 KiB
  (`head_hash`, `main.rs:444`) so resume can detect a different file wearing the
  same name+size. Senders re-offer unfinished transfers with `resume: true` on
  every new channel. Gate 2 verifies kill-`-9`-mid-transfer → replacement →
  resume → hash match.
- **uid supersede + deferred drop (C6 / C6b / #28).** `maybe_adopt`
  (`main.rs:~1782`) replaces a same-uid zombie link, and the **deferred-drop**
  machinery (`on_peer_left` + `reap_deferred`) keeps a *flowing* link alive
  through a cosmetic signaling reconnect. This is where today's only real
  byte-flow signal lives (see 1.4).
- **Convergent session (C30).** A `sync` protocol + per-client session modules
  (`session.rs`, `lib/session.js`) hold desired-vs-confirmed state with one
  5 s repair loop — dissolving five edge-triggered "lost-emit" belts into a
  level-triggered convergence loop. This is the *signaling-plane* analogue of
  what we want on the *data-plane*.

### 1.3 The runner's hard-won patterns (PROVEN — to be lifted into the core)

The runner (`runner/`, owned separately — we do not modify it here) re-derived
the never-flaky model *on top of* filament because the core lacked it. These are
proven patterns to pull *down* into the transport layer so **every** client gets
them, not just the runner (`jobrunner-challenges.md` "Layer B"):

- **Retry-until-peer.** Bounded per-invocation send timeout
  (`FILAMENT_SEND_TIMEOUT`, 45 s) inside a retry loop with backoff against a
  generous overall deadline — "a wedged establishment is abandoned and
  re-invoked (a fresh connect clears a stuck candidate pair)." This is the
  outer-reconnect loop the CLI lacks (1.4).
- **Integrity + resume-to-completion.** A result set is accepted **only** when
  every declared output's sha256 matches the manifest — a truncated/partial
  output fails verification and the receiver keeps awaiting. This is full-file
  integrity, beyond filament's head-hash resume seam (C7).
- **Result-ACK loop.** The receiver pushes a tiny `ack-<job_id>` back; the
  sender re-ships each round and **stops the instant it sees the ack**. A
  lost completion signal costs one extra round, never a hang.
- **Supervised acceptor.** `up_supervisor.sh` keeps a long-lived `up` acceptor
  alive across signaling drops by proactively restarting it — a userspace patch
  for the `reconnect(false)` gap (1.4).
- **Local flaky-link repro.** `runner/sim/flaky_proxy.py` severs the socket.io
  link on a randomized schedule; `flaky_e2e.py` + `test_resilience_unit.py` pin
  the three guarantees deterministically. **This harness is our SLO measurement
  rig** (§6).

### 1.4 The real gaps

Stated honestly, smallest-to-largest:

- **GAP-1 — No in-flight stall detector (THE core gap).** Nothing watches
  *bytes-moved per transfer* and declares a transport bad when an **open, alive**
  channel stops moving data. The only byte-flow signal that exists,
  `Transport::idle_ms()` (`net.rs:131`), was built for a *different* purpose: it
  lets `maybe_adopt`/`reap_deferred` tell a frozen-alive link from a flowing one
  during a **supersede** decision (#28, threshold `FILAMENT_ADOPT_ACTIVE_MS`,
  default 3 s). It is **never consulted to abort and re-route a stuck transfer**.
  So a `direct` link that establishes and then moves zero bytes (the Pixel-at-0%
  hang) sits there until something *else* (a socket death, a watchdog on a *new*
  attempt) trips — or forever. `idle_ms()` is the right primitive; it is wired to
  the wrong consumer.

- **GAP-2 — `reconnect(false)` + no outer reconnect loop in `up`/`up --dir`.**
  The socket.io client is built `.reconnect(false)` (`net.rs:338`) and a
  long-lived acceptor runs *one* signaling connection. When the signaling TCP is
  severed, the acceptor dies silently and never re-announces — a zombie the
  sender can't rediscover (documented at length in `up_supervisor.sh`'s header
  and reproduced by `runner/sim/flaky_sim_test.sh`). Short discrete `send`s
  recover because each reconnects fresh; the acceptor does not. Today this is
  patched *outside* the binary by the supervisor script.

- **GAP-3 — Sequential ladder, no warm redundancy.** The rungs try one path at
  a time and tear the loser down. There is no *second, already-established*
  transport kept warm for instant failover — so correction rung (b) (switch to a
  redundant transport) has nothing to switch *to* yet; today it collapses into
  rung (c) (repair in place), which is slower.

- **GAP-4 — No automatic relay fallback on persistent direct stalls.** `--relay`
  is a *manual* flag or a static default. There is no policy that says "direct
  rungs stalled N times → escalate to relay automatically" — exactly the manual
  step the Pixel delivery and the runner both had to perform by hand. (The runner
  *chose* relay as a static default precisely because this automatic step
  doesn't exist.)

- **GAP-5 — Full per-chunk in-flight integrity is ROADMAP (C7/C8b).** DTLS/SCTP
  and QUIC checksum the wire, and the head-hash guards the *resume seam*, but
  there is no end-to-end content digest on completion in the core (the runner
  added one above the transport). Relevant because a stall-and-reroute that
  resumes from a partial must not silently stitch a corrupt boundary.

- **Frontend route surfacing is thin.** `_detectRoute` (`webrtc.js:243`)
  classifies `local`/`direct`/`relayed` and the tile shows a `RouteBadge`
  (`Filament.jsx:103`) — but relay renders as a quiet amber `RELAY` chip with the
  tooltip "via a relay" (`routeMeta`, `Filament.jsx:99`). It is *legible* but not
  *loud*, and there is no global session indicator, no explainer, and no
  prefer-direct / allow-relay control.

---

## 2. The never-flaky transport layer

Six concerns. Each maps onto the real code above.

### 2.1 Path enumeration + racing

Today the CLI enumerates: LAN/overlay host candidates + a public candidate
(`direct::gather_candidates`, `direct.rs:203`), a STUN srflx
(`gather_srflx`, `main.rs:2041`), and WebRTC's host/srflx/relay set from
`fetch_config`. WebRTC already races its candidates internally; the *cross-rung*
order is a **sequential ladder** with a 5 s budget per direct attempt.

**Design.** Keep the **preference ordering** `direct > holepunch > relay`
(it encodes the honesty rule: a direct path is both faster *and* keeps the
no-middleman promise). But tighten the ladder toward **happy-eyeballs within a
tight budget** so a dead rung never burns the whole 5 s:

- **Per-candidate sub-budgets.** Inside `race_connect`'s `FuturesUnordered`
  (`direct.rs:654`), a candidate that hasn't completed its QUIC handshake within
  a short sub-budget (≈1.5 s; LAN/overlay candidates resolve in tens of ms) is
  dropped from the race rather than holding the 5 s wall. The acceptor future and
  the winning-candidate dialer stay.
- **Overlap rung-2 with rung-1's tail.** Today rung-2 fires only *after* rung-1's
  full budget burns (`on_transport_offer`, `main.rs:2077`). Start the STUN srflx
  discovery (`gather_srflx`) **eagerly at offer time** (it already runs there) and
  begin the punch as soon as rung-1's host candidates have all failed their
  sub-budgets — not at the 5 s wall.
- **Ordering invariant.** First *authenticated* connection wins and the rest are
  dropped (unchanged). The label travels with the winner (`direct-quic` /
  `holepunched` / WebRTC's `route()`), so the UX always knows the truth.

Browser side: ICE already does happy-eyeballs across host/srflx/relay; the
ordering preference is enforced by `_detectRoute`'s classification + the
prefer-direct control (§3).

### 2.2 Stall / hang detection — the heart of it

**This is GAP-1, the thing that caused every 0% hang.** The fix is a
**per-transfer, per-connection no-progress detector** that the *transfer driver*
consults, not just the supersede logic.

**Signal (already present, repurposed).** Every transport stamps a monotonic
`last_activity` at the unambiguous "a data byte moved" point — `send_frame`
returning `Ok` and the read loop delivering a *data* frame (`net.rs:213` /
`net.rs:848`; `direct.rs:442` / `direct.rs:537`). Control frames deliberately do
**not** stamp it (so periodic acks/state pings can't mask an idle link). Exposed
as `Transport::idle_ms()` (`net.rs:131`). A *frozen receiver* stalls the sender
in backpressure (the WebRTC `HIGH_WATER` park at `net.rs:193`, or QUIC's flow
window at `direct.rs:413`), so `last_activity` stops advancing — exactly the
signal we want.

**The detector (new consumer).** A **bytes-moved watchdog** running in the main
loop while a transfer is in flight (`by_sid` non-empty):

1. **No-progress timeout.** For each active link with a transfer in flight, if
   `idle_ms()` exceeds a **stall threshold** *and* the link is not legitimately
   blocked on local backpressure we *caused* (i.e. our own send buffer is
   drained / receive window is open), declare the transport **stalled**. Suggested
   threshold: **5–8 s** (well above a slow-but-moving link's inter-chunk gap on a
   bad mobile uplink, well below human patience). Configurable via a
   `FILAMENT_STALL_MS` knob mirroring the existing `FILAMENT_ADOPT_ACTIVE_MS` /
   `FILAMENT_REJOIN_SECS` style.
2. **Distinguish slow-but-moving from hung.** "Slow" still advances
   `last_activity` (a 1-byte chunk resets it); "hung" does not. The threshold is
   on *time since the last byte*, never on throughput — so we never punish a slow
   link, only a frozen one. (This mirrors the determinism rule in
   `cli-resilience.md` Part 4: never assert MB/s; assert *progress*.)
3. **Liveness cross-check.** Before declaring bad, fire a cheap **liveness probe**
   on the control channel (a `ping` control frame; WebRTC/QUIC both reliable and
   ordered). If the peer answers but bytes still don't move, the *data path* is
   wedged while signaling is fine — the classic NAT-rebinding silent black-hole.
   If the probe also times out, the whole link is gone (fall straight to the
   harder rungs). This is the data-plane analogue of the C30 convergent
   "assert → verify → reconcile" loop.

**Emit `Ev::TransferStalled { id, pid, link_idle_ms }`** into the same single
event loop that already carries `Ev::Stuck` / `Ev::GraceExpired`, so the
correction ladder (2.3) is driven from one place with no new concurrency hazards
(respecting F8: the event loop must never await anything a remote peer controls).

Browser parity: the transfer-progress callback (`onTransfer`) already sees byte
counts; add the same time-since-last-byte watchdog in `webrtc.js` keyed off the
data-channel `onmessage` / send path, surfaced through `onStuck` (which already
exists, `webrtc.js` ctor).

### 2.3 Least-disruptive correction ladder

On `Ev::TransferStalled`, escalate in order of **least disruption**, **preserving
the on-disk partial at every rung** (filament already parks `<name>.part` +
`.part.meta` and re-offers with `resume: true`):

> **(a) Resume/retry on the SAME transport.**
> Cheapest. Re-issue the stalled file's offer with `resume: true` and the current
> `.part` offset; if the channel is merely wedged on a transient pause it picks up
> where it left off. Bounded: **1 attempt**, short timeout (≈ the stall threshold
> again). Backoff: none (immediate). If progress resumes, done — the user never
> sees anything.

> **(b) Switch to an already-warm REDUNDANT transport.**
> If a second transport is kept warm for this peer (2.4), swap the `Link`'s
> `transport` to it and re-offer from the partial offset. This is a pointer swap
> + a resume — **no handshake, no teardown of the session**. Sub-second. Requires
> GAP-3's warm-standby work; until then this rung degrades into (c).

> **(c) Repair the transport IN PLACE under the live session.**
> No warm standby available → rebuild a path *without ending the session*:
> - WebRTC: `restart_ice()` (already implemented, `net.rs:549`) — keeps the
>   `RTCPeerConnection`, the DTLS keys, and the data channel; only ICE re-gathers.
>   Transfers resume on the same channel once ICE re-converges.
> - direct-QUIC: a **fresh QUIC dial** over the *already-known* peer candidates
>   (re-run `race_connect` with the cached `peer_cands`), then inject the new
>   transport as `Ev::DirectReady` and resume from the partial — the transport
>   trait makes this a hot-swap the transfer logic doesn't notice. quinn
>   *connection migration* can absorb a NAT rebind transparently for the common
>   case; the fresh dial is the fallback when migration can't (e.g. the mapping is
>   gone entirely).
> Bounded by `MAX_ATTEMPTS` (3, reuse `on_stuck`'s counter); exponential-ish
> backoff (the existing 6 s grace + watchdog cadence is a reasonable starting
> point).

> **(d) Fall back to RELAY.**
> Direct rungs exhausted (a–c failed `MAX_ATTEMPTS` times, or the liveness probe
> says the data path is black-holed and ICE-restart didn't fix it) → **escalate to
> relay**: re-establish with `RTCIceTransportPolicy::Relay` (the `--relay`
> machinery, `net.rs:431`) and resume from the partial. **This rung is the one the
> user MUST be told about** (§3) — it trades the no-middleman promise for
> reliability. Closes GAP-4: the automatic version of what the Pixel delivery and
> the runner did by hand.

**Progress preservation across all rungs** is the invariant that makes this safe:
each rung re-offers with `resume: true` against the same `.part`, and C7's
head-hash guards the seam (a different file wearing the same name restarts from 0
rather than stitching corruption). Lifting the runner's **full-file sha256 gate**
(1.3) into the completion path hardens the seam further (GAP-5) — the receiver
accepts a transfer as complete only when the whole-file digest matches, so no
reroute can silently truncate.

### 2.4 Multiple / redundant transports + failover

**The tradeoff.** Keeping a second transport *warm* makes rung (b) instant
(pointer swap) but costs a second handshake + holds a second socket/NAT mapping
open (keepalive traffic, battery on mobile). Keeping only one and *lazily
re-establishing* is cheaper but turns every failover into rung (c) (a
handshake-latency stall the user might perceive).

**Decision — tiered, by session kind:**

- **Bulk one-shot file transfer (the 90%):** *lazy*. The on-disk partial + resume
  already makes rung (c) correct and bounded; a handshake-latency blip mid-file is
  acceptable and rare. Don't pay for warm standby. Establishment stays the
  sequential ladder (2.1).
- **Long-lived / interactive sessions (PTY, L2 tunnels, `up` acceptors, the
  runner's control plane):** *warm redundancy worth it*. These are exactly the
  sessions the runner post-mortem showed cannot tolerate a drop
  (`jobrunner-challenges.md`: "a long-lived interactive PTY is the wrong
  abstraction for a flaky link"). For these, **establish the best direct rung AND
  keep a relay path warm** (or a second direct candidate), so a mid-session stall
  fails over in (b) without the human noticing. The cost (a warm relay allocation)
  is trivial against a dropped multi-minute job.

This makes the runner's "just default to relay" a *fallback*, not the only
option: interactive sessions get **direct-first with warm relay standby**, so they
keep the fast/honest path when it works and fail over instantly when it doesn't.

### 2.5 Session-preserving repair

The hard part. Re-establishing a path under a *live* session (transfers, PTY,
tunnels) without the app or user noticing requires three things, two of which
filament already has:

- **Idempotent resume offsets (HAVE).** Every transfer is resumable from its
  `.part` offset; re-offering is idempotent (C23 enforces one stream per `.part`).
  So a transfer survives any number of transport swaps.
- **Transport hot-swap behind the trait (HAVE).** The `Transport` trait
  (`net.rs:109`) already lets a `Link` swap its `transport` field; `adopt_direct`
  (`main.rs:2115`) and `maybe_adopt` do this for *new* links. The new work is to
  swap **under an in-flight transfer** rather than only at link birth — re-pointing
  `by_sid` book-keeping at the new transport and replaying the partial offset.
- **Mid-session re-key (the genuinely hard bit, HONEST).** Rungs (c)/(d) that
  build a *fresh* connection (fresh QUIC dial, relay re-establish) get **fresh
  keys** — WebRTC re-negotiates DTLS, a fresh QUIC connection re-runs the
  pair-secret MAC (`direct::authenticate`). That is *correct* (each path is
  independently authenticated to the same pair secret) but it means the swap is a
  **new authenticated transport adopted into the existing session**, not a literal
  re-key of one connection. The session-level identity (the pair secret / verified
  petname) is stable across the swap, so trust is continuous; the *wire* keys
  rotate. `restart_ice()` (rung c, WebRTC) is the one case that keeps the same
  DTLS keys (only ICE re-gathers) — preferred when available precisely because it
  avoids the re-key entirely. Document this clearly: "repair" sometimes means
  "adopt a freshly-authenticated transport into the live session," and that is a
  feature (defense in depth), not a leak.

**Close GAP-2 in the core (retire the supervisor script).** Give the long-lived
acceptors (`up`/`up --dir`/`up --shell`) the **outer reconnect loop** the
supervisor fakes: on signaling-socket death, re-run `connect_signaling`
(`net.rs:320`) and re-assert presence through the C30 session module — instead of
relying on `reconnect(false)` + an external restart. The C30 convergent loop is
the right home: it already re-subscribes on fresh sid; extend it to *own the
socket lifecycle*, not just the subscriptions on top of it. This makes every
client self-healing without the userspace patch.

### 2.6 The 99.999% framing

**Failure modes this layer must cover** (each mapped to its rung/owner):

| Failure mode | Detected by | Corrected by | Status |
|---|---|---|---|
| Establishment never completes (swallowed offer, dead sid) | watchdog C3 (`Ev::Stuck`) | retry w/ fresh config ×3 | HAVE |
| Transient ICE `disconnected` blip | C4 grace | `restart_ice` + grace | HAVE |
| **Open channel, zero bytes (the 0% hang)** | **bytes-moved watchdog `Ev::TransferStalled`** | **correction ladder a→d** | **GAP-1 (this design)** |
| NAT rebind / mapping churn mid-transfer | bytes-moved watchdog + liveness probe | rung (c) ICE-restart / fresh QUIC; quinn migration | GAP-1 + 2.5 |
| Signaling socket dies under a long-lived acceptor | (silent today) | outer reconnect loop in core (C30) | GAP-2 |
| Peer sleep/wake (mobile tab suspend) | `brb`/`back` + rejoin window (C21) | hold-the-line + supersede | HAVE |
| Stale TURN creds | — | fresh config per attempt (C5) | HAVE |
| Persistent direct stall on a bad path | bytes-moved watchdog (N stalls) | **auto relay fallback** | GAP-4 (rung d) |
| Truncated/corrupt resume seam | head-hash (C7) + full-file sha256 | restart-from-0 / reject partial | HAVE + GAP-5 |
| Lost completion signal (file-END / manifest) | — | result-ACK loop (lift from runner) | runner HAVE → core |

**Explicitly OUT of scope:** genuine internet-down on either side (no path
exists — relay included), and the user *forbidding* relay (§3) which caps the SLO
to "direct-reachable" sessions by their own choice.

**SLO statement.** Of all sessions where a path *exists* (both peers reachable,
internet up), ≥ 99.999% complete without the user manually retrying or switching
transports. "Complete" = bytes delivered + integrity verified, or an *honest*
terminal failure with a kept-partial (never a silent hang).

---

## 3. Relay-transparency UX

The honesty rule, made concrete. Relay is still E2E-encrypted, but **not a direct
link** — the wording everywhere must be precise enough to neither over-claim
("the server can never see anything" — false framing for relay: it transits the
server, encrypted) nor under-claim ("your data is exposed" — also false: it's
still encrypted end to end).

### 3.1 Principles

- **Persistent, not transient.** A relay session shows its state for the *whole*
  session, not a flash on connect. Today's `RouteBadge` is persistent on the tile
  (good) but visually quiet for relay (`routeMeta` amber `RELAY`, tooltip "via a
  relay", `Filament.jsx:99`). Make relay **loud**: a ⚠ chip, not a calm one.
- **Legible route everywhere.** Keep the four honest labels — **LAN** (local),
  **P2P** (direct), **HOLEPUNCHED** (NAT-traversed direct, still no middleman),
  **RELAY** (TURN). LAN/P2P/holepunched are all "no middleman"; relay is the only
  one that isn't, so only relay gets the warning treatment.
- **Explainer on demand.** The relay chip carries a one-line plain-language
  explainer, expandable to two sentences. No jargon in the headline.
- **A user control.** "Prefer direct (don't use relay)" vs "Allow relay for
  reliability" — and an honest consequence note (3.4).
- **Dark/mono aesthetic preserved.** Reuse the existing theme tokens
  (`T.warn = #FFC857` dark / `#9A6B00` light; `T.bad`, `T.line`, `T.sub`,
  `Filament.jsx:60`/`69`). The relay chip is amber-on-mono with a ⚠, matching the
  existing `away`/warn vocabulary — no new color language.

### 3.2 The tile chip (per-peer, persistent)

Non-relay (unchanged-ish, quiet, the no-middleman paths):

```
┌──────────────────────────────┐
│ ▪                  [▬ P2P] ● │   ← P2P / LAN / HOLEPUNCHED : calm, mono
│                              │
│  my-laptop                   │
│  ready          ↳ drop to send│
└──────────────────────────────┘
```

Relay (loud, persistent, with the honest explainer on hover/tap):

```
┌──────────────────────────────┐
│ ▪          [⚠ RELAY ▾] ●     │   ← amber ⚠ chip, NOT calm
│                              │
│  pixel-7                     │
│  ready · via relay           │   ← status line also says it
│                              │
│  ┌─ on hover / tap ────────┐ │
│  │ Routed through a TURN   │ │
│  │ server — not a direct   │ │
│  │ link. Still end-to-end  │ │
│  │ encrypted; the server   │ │
│  │ relays bytes it can't   │ │
│  │ read. [prefer direct]   │ │
│  └─────────────────────────┘ │
└──────────────────────────────┘
```

### 3.3 Global session indicator

When *any* active link is on relay, a persistent status strip (the app's existing
top bar, alongside `LanChip`, `Filament.jsx:249`) shows it so the user is never
unaware even if the tile is scrolled off:

```
 filament                          ⚠ 1 peer on relay · routed via TURN  [ details ]
 ───────────────────────────────────────────────────────────────────────────────
```

`[ details ]` opens the same explainer + the prefer-direct/allow-relay control.
CLI parity: `filament send`/`recv`/`pty` already print `route: relayed`
(`direct.rs:684`, WebRTC `route()`); make the relay line **stand out** in the CLI
too — a one-line honest banner on first reaching relay, e.g.:

```
⚠ on relay — routed via a TURN server, not a direct link (still encrypted)
```

reusing the `ui::Tone::Warn` paint already in `ui.rs`, consistent with the C26
presence roster glyphs.

### 3.4 The prefer-direct / allow-relay control

A per-session (and persistable) toggle:

- **Allow relay for reliability (default).** The never-flaky promise holds in
  full: rung (d) is available, so a path that *can* connect *will*, even behind
  hard NAT. The cost is the visible relay state when it's used.
- **Prefer direct (don't use relay).** Honors users who require the no-middleman
  property (privacy, policy). **Honest consequence, shown inline:** *"Some peers
  behind strict firewalls may not connect, and a session can drop instead of
  falling back. Filament will keep trying direct paths and tell you if it can't
  reach a peer."* This is the one place the SLO is *intentionally* capped by user
  choice — and the UI says so rather than silently breaking the promise. Maps to
  forcing the ladder to stop at rung (c) and never escalate to `--relay`.

The inverse of today's CLI `--relay` (force relay) is a future `--no-relay`
(forbid relay) flag for parity; `--relay` stays for the privacy/testing case where
the user *wants* the middleman to hide their IP.

### 3.5 Trust framing (exact words)

- ✅ "Routed through a TURN server — not a direct link. Still end-to-end
  encrypted; the relay forwards bytes it can't read."
- ❌ "Your connection is insecure / exposed." (false — it's encrypted)
- ❌ "Direct and private." (false on relay — there *is* a middleman on the wire)
- For LAN/P2P/holepunched: "Direct link — bytes go straight between you, no
  middleman." (true — these are address-property guarantees, see C2's
  `is_private_addr`/`is_own_addr` classification, `net.rs:742`/`757`).

---

## 4. Measurement / SLO

**Rig:** the existing flaky-link sim (`runner/sim/`) is the measurement harness,
generalized from "runner result transfers" to "any transfer":

- `flaky_proxy.py` already severs + flaps the signaling link on a randomized
  schedule — the local equivalent of a WAN path dropping. Extend it with a
  **data-path** stall mode (hold bytes while keeping the channel open) to exercise
  GAP-1 specifically — that's the 0% hang the proxy doesn't yet reproduce (it
  drops the *link*; we also need "alive but frozen").
- New deterministic gates in `cli/tests/gates.sh` style (the determinism rule
  from `cli-resilience.md` Part 4 applies: assert *progress/correctness*, never
  MB/s):
  - **Gate (stall-detect):** inject a data-path freeze mid-transfer (a test hook
    like `FILAMENT_TEST_FREEZE_AFTER_BYTES`); assert the bytes-moved watchdog
    fires within the stall threshold and the correction ladder resumes + completes
    + hash-matches. A/B with the detector disabled must hang (proving the detector
    is load-bearing, mirroring gate 11c's `NO_DEFER` baseline).
  - **Gate (auto-relay):** force all direct rungs to fail (the existing
    `FILAMENT_DIRECT_TEST_BLOCK`, `direct.rs:57`, generalized to also block
    WebRTC-direct + holepunch); assert the ladder auto-escalates to relay,
    completes, and the relay state is *surfaced* (the CLI banner / a UI assertion).
  - **Gate (acceptor self-heal):** sever the signaling link under a long-lived
    `up`; assert the **in-core** outer reconnect re-announces and the peer
    rediscovers — *without* `up_supervisor.sh` (GAP-2 closed in-core).
- **Livetest:** drive a real cross-NAT pair (the Tailscale/GitHub-runner livetest
  pattern from memory `relay-ci-livetest`) and force a direct stall mid-transfer
  (block UDP to the chosen candidate); assert auto-fallback to relay + visible
  relay state + completion.

**The 99.999% number** is a *target*, asserted by construction (every failure
mode in §2.6 has a deterministic gate that proves it recovers) rather than by
sampling — one green run never proves five-nines, but a deterministic gate per
failure mode lets us *reason* that the uncovered space is small. The livetest is
the integration proof; the sim gates are the regression wall.

---

## 5. Phased implementation plan

Shippable steps, each independently valuable, each gated. The runner's proven
patterns are lifted **down into the core** so every client inherits them.

**Phase 0 — Wire the existing signal to a new consumer (the core fix).**
Add the **bytes-moved watchdog** (2.2): a main-loop check that consults the
*already-existing* `idle_ms()` for in-flight transfers and emits
`Ev::TransferStalled`. Implement correction rung **(a)** (resume on same
transport) and rung **(c)** (ICE-restart / fresh-QUIC dial, reusing
`restart_ice`/`race_connect`). No new transports, no warm standby. Gate:
stall-detect. *This alone fixes the Pixel-at-0% class.*

**Phase 1 — Automatic relay fallback (rung d) + honesty UX.**
On N persistent stalls, auto-escalate to relay (reuse the `--relay` ICE policy).
Ship the **relay-transparency UX**: loud tile chip, global indicator, CLI banner
(§3.2–3.3), and the **prefer-direct / allow-relay** control + `--no-relay` flag
(§3.4). Gate: auto-relay (completion *and* surfaced state).

**Phase 2 — Close the `reconnect(false)` gap in core (GAP-2).**
Give long-lived acceptors the outer reconnect loop via the C30 session module
(2.5); retire the dependence on `up_supervisor.sh`. Gate: acceptor self-heal
without the supervisor.

**Phase 3 — Warm redundancy for interactive sessions (rung b, GAP-3).**
For PTY/L2/`up --shell`/runner-style long-lived sessions, establish direct + keep
a relay (or second-direct) path **warm** for instant pointer-swap failover (2.4).
Bulk transfers stay lazy. Gate: mid-PTY-session direct stall fails over in < 1 s,
session unbroken.

**Phase 4 — Full-file integrity in core (GAP-5) + happy-eyeballs tightening.**
Lift the runner's **whole-file sha256 completion gate** and **result-ACK loop**
(1.3) into the transfer protocol so every client gets integrity-to-completion and
lost-END repair. Tighten the ladder per-candidate sub-budgets (2.1). Gate:
truncation rejected + lost-file-END repaired, in the core (not just the runner).

**Sequencing rationale:** Phase 0 is the highest-value, lowest-risk step — it
reuses an existing signal and an existing repair primitive to kill the exact hang
the mandate names, behind a test hook, touching only the main loop's stalled-path
handling. Honesty (Phase 1) ships next because the moment auto-relay exists, the
user *must* be told. The harder structural work (GAP-2 outer loop, GAP-3 warm
standby, GAP-5 core integrity) follows, each independently shippable.

---

## 6. The hard parts (decisive + honest)

- **The `reconnect(false)` core gap is real and currently patched out-of-binary.**
  The supervisor script proves the fix works; the principled version is the C30
  convergent loop owning the socket lifecycle. Until Phase 2 lands, long-lived
  acceptors are only as resilient as their supervisor. We name this rather than
  pretend `up` self-heals.
- **Mid-session repair sometimes means re-key, and that's a feature.** Rungs
  (c)/(d) that build a fresh connection rotate the wire keys (fresh DTLS / fresh
  QUIC MAC). The *session identity* (pair secret, verified petname) is stable, so
  trust is continuous — but it is honest to call this "adopt a freshly
  authenticated transport into the live session," not "re-key one connection."
  `restart_ice` is preferred precisely because it avoids the re-key.
- **Racing has a cost.** Warm redundancy (rung b) holds a second socket / NAT
  mapping and keepalive traffic — real battery/mobile cost. That's why §2.4 makes
  it *tiered*: only long-lived interactive sessions pay for it; the 90% bulk-file
  case stays lazy and leans on partials+resume.
- **Five-nines is asserted by construction, not by sampling.** We do not claim a
  measured 99.999%; we claim a deterministic gate per failure mode so the
  uncovered space is small and *reasoned about*, exactly the discipline
  `cli-resilience.md` already enforces ("one green never proves it, but you can
  reason it cannot flake").
- **The stall threshold is a tuned constant.** Too low punishes a genuinely slow
  mobile uplink (false reroute, churn); too high makes the user wait. 5–8 s is the
  proposed starting point, behind a knob, validated by the sim under deliberately
  slow-but-moving conditions — never by a throughput floor.

---

*Cross-references: protocol contract in [`../../CONTRACT.md`](../../CONTRACT.md);
CLI failure ledger in [`../cli-resilience.md`](../cli-resilience.md); browser
fixes in [`../resilience.md`](../resilience.md); runner post-mortem in
[`../runner/jobrunner-challenges.md`](../runner/jobrunner-challenges.md). The
runner code under `runner/` is owned separately and is not modified by this
design — its patterns are referenced as proven prior art to lift into the core.*
