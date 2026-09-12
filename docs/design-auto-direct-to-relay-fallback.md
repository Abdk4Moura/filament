# Auto direct-to-relay fallback for L2 cold establish

> Status: proposed. Design only; verify current L2 behavior before implementation.

## Problem

`bring_up_to_known` (l2.rs:983) unconditionally races a direct-QUIC dial against
WebRTC. When direct-quic binds (i.e. the local host has a usable network
interface) but the resulting L2 stream fails or stalls — common on virtualized /
hyperkit / hostile NAT environments — the user gets a hard 45s timeout error
("couldn't establish a link") with no automatic fallback.

The product promise is "it just connects so long as both are up" (Tailscale-style
direct-OR-DERP-relay). Today, the relay path exists in the candidate set (ICE
srflx + TURN relay when `--relay` is passed) but is unreachable because the
direct-QUIC race always wins and consumes the transport slot, leaving no path
for WebRTC+relay to take over.

## Trigger

Two failure modes need automatic fallback:

1. **Stream fail**: direct-QUIC binds, connection (quinn Connection) is
   established, but the L2 stream (`pty-open`, `netcat-open`, etc.) fails
   within a bounded window. The quinn stream-level error is visible as
   `ApplicationClose` (error_code 0, clean close) or a read/write error on the
   L2 control channel.

2. **Stall timeout**: direct-QUIC is in the candidate race, ICE `checking`
   produces srflx candidates, but the nominated pair never completes within
   budget. Today the per-candidate budget (7s default,
   FILAMENT_L2_CANDIDATE_SECS) fires and rotates to the next signaling
   candidate — but the direct race is never abandoned; the initiator just
   re-attempts WebRTC to the same peer.

The unifying trigger: **L2 stream not acknowledged within T_fallback** after
`DirectReady` is received.

## How fallback composes with existing race

The current race (line 1142-1177) is:

1. Bind QUIC endpoint
2. Gather candidates
3. Advertise to peer on `KnownPeer` event
4. Peer's `transport-offer` triggers `start_direct` (via `Ev::Signal`)
5. Both direct-quic and WebRTC run concurrently
6. First to reach `DirectReady` / `ChannelReady` wins

Proposed: keep the head-start race, but add a **fallback timeout**:

1. (unchanged) Bind + advertise + race on `KnownPeer`
2. When `DirectReady` fires:
   a. Open L2 stream (unchanged)
   b. **Start fallback timer** (T_fallback = 5s)
3. If L2 stream ACK (`l2-open-ack`) arrives within T_fallback: cancel timer, done
4. If T_fallback fires before ACK (or stream produces an error):
   a. Drop the direct transport (close QUIC connection)
   b. Signal the race to fall back to WebRTC
   c. WebRTC (with srflx + relay candidates) takes over
   d. Re-open L2 stream over WebRTC transport

The WebRTC path is already running in parallel (step 5 above), so the fallback
is a transport switch at the Mux level rather than a cold restart of the whole
establish.

## Establishment model impact

`proofs/establishment_model.py` models the establishment FSM. This change adds a
new phase:

```
L2Open -> L2Pending (on DirectReady, with fallback timer)
L2Pending -> L2Open (on l2-open-ack, fallback timer cancelled)
L2Pending -> Relaying (on fallback timer expiry: drop direct, switch to WebRTC relay)
Relaying -> L2Open (re-open L2 stream over relay transport, on l2-open-ack)
```

The `Relaying` state is new. The model must verify that:

1. Every establisher eventually transitions from `L2Pending` to either `L2Open`
   or `Relaying -> L2Open`
2. No deadlocks (the WebRTC transport must still be available when fallback
   fires — it must not have been closed by the direct-QUIC win)
3. The fallback preserves pairwise authentication (identity proof over relay
   must match the identity proof that direct-QUIC would have produced)

The proof.yml gate currently asserts the state-machine contract from the model.
The model must be updated FIRST, and the code must match the updated model,
before merging the fallback.

## State-marker evidence

To make fallback observable in production and CI:

- Fallback events emit a diag Phase: `L2Fallback` with the reason
  (stream_fail / stall)
- The route label in user-facing output changes from `direct-quic` to `relay`
  on fallback
- The `web:phase` telemetry records `phase: "fallback"` with `reason` and the
  transport after fallback

## CI integration

With the gate from PR (direct_enabled() check for bring_up_to_known), macOS CI
tests skip direct-quic entirely and exercise relay-only, already green. The
auto-fallback would additionally let the Linux/Windows tests hit their existing
direct-OR-relay contract: direct wins normally, and the test can inject a
direct-quic stall to verify fallback (future test, not part of this design).

## Non-goals (for this PR)

- Relay fallback for file transfer (send/recv) — this is a separate transport
  decision
- Relay fallback for daemon-to-daemon links (those are already warm-held)
- TURN relay server provisioning (production already has `turn:filament.autumated.com:3478`)
- Any change to `FILAMENT_DIRECT` semantics for file-transfer paths

## CI caveat: macOS hyperkit runner

The macOS ARM64 GitHub runner uses hyperkit virtualization with a bridge
network that blocks ALL transports — direct-quic AND WebRTC srflx/relay
candidates (proven by 5-run empirical measurement, July 2026). The relay path
relies on ICE srflx candidates which require a routable host candidate; on
hyperkit the bridge IP (192.168.64.x) is local-only and the STUN-reflexive
candidate points at a NAT-gatewayed external IP that the virtualized guest
cannot loop back to. The production relay path works for real users (their
hosts have routable IPs), but hyperkit cannot exercise it.

The auto-fallback design is tested on ubuntu + real macOS hardware. The CI
gates establish tests off macOS (separate PR), and the product gating on
`direct_enabled()` (separate PR) is the correct config fix for users who
explicitly disable direct.
