# Diagnosis: #212 and #214 share one harness root cause

Written 2026-08-13 by rig-verifier. Both open issues block the capability rig
from testing the enrollment and remembered-device flows. Source-verified chain
below; the decisive experiment (build + run the join cell against a non-relay
issuer) is requested but not yet run.

## The chain (each link verified in source)

1. The harness spawns every daemon with `up --relay`
   (`cli/tests/capability_harness.rs:435`).
2. `--relay` sets `Conn.relay_only` on the daemon (`cli/src/main.rs:6006`,
   `6415`, threaded through `Conn::for_command` at `7780`).
3. Every WebRTC link the daemon builds uses `relay_ice = self.relay_only`
   (`cli/src/main.rs:8279`) and passes it to `Peer::connect`.
4. `Peer::connect` maps it to `RTCIceTransportPolicy::Relay`
   (`cli/src/net.rs:1261-1265`). Under Relay policy, webrtc-rs gathers ONLY
   TURN relay candidates.
5. The harness backend serves STUN-only ICE config: `backend/config.py`
   `DEFAULT_ICE = [{"urls": "stun:stun.l.google.com:19302"}]`; TURN is only
   present when `FIL_TURN_HOST` + `FIL_TURN_SECRET` are set, and CI sets
   neither. So a relay-only peer gathers ZERO candidates.
6. A peer that gathers zero candidates can never complete ICE, whatever the
   other side offers.

The product's own comment at `main.rs:8284-8285` states the mechanism:
"a relay-only policy with no relay servers has no candidates and fails
cleanly, which is the point."

## #212 (enrollment link cannot establish)

The enrollment link is joiner <-> issuer DAEMON. The issuer daemon is spawned
with `--relay`, so the issuer's side of the link is relay-only with no TURN:
it gathers nothing, ICE can never nominate, and the joiner times out after 60s.
Identical on all three platforms because the configuration is identical on all
three. The joiner's observed "srflx only, no host candidate" is a secondary
artifact (the joiner in the failing runs was also not loopback-filtered); even
with perfect host candidates the issuer contributes nothing.

## #214 (paired-device fallback glare under direct-block)

The revocation control is A (one-shot `send`) -> B's daemon, direct forced ON
and BLOCKED. When direct is blocked, the transfer must fall back to WebRTC
against B's daemon, which is relay-only -> the fallback can never connect, so
the DIRECT-BLOCKED storm retries forever and no DIRECT-FALLBACK marker can ever
settle. The polite-role glare is churn on top of that: A (no roster) uses
`polite_role_legacy` (sid comparison), B's daemon (roster knows A) uses
`polite_role` (uid-first); the two role functions can disagree, so a rebuild
can land both sides on the same role and re-glare.

## Why the passing siblings pass

`pair_and_transfer_smoke` and `direct_blocked_falls_back_to_webrtc_promptly`
never involve a daemon. Both ends are one-shot `send`/`receive` processes
without `--relay`, so both are `RTCIceTransportPolicy::All` and both gather
host candidates (loopback on ubuntu/windows, bridge IP on macOS) -> ICE
connects. Corroboration: every daemon-dependent flow is already skipped or
flaky on macOS (`warm_all_makes_first_contact_warm` is cfg'd off macOS,
`shell_daemon_live_pairing_no_restart` skips Windows and macOS), where
direct-QUIC is off and a link MUST ride WebRTC.

## The fix (harness side, product untouched)

`spawn_daemon_inner` should not pass `--relay`. Two daemons on one host pair
via direct-QUIC over loopback, and where a WebRTC link is needed (macOS,
direct-off), they gather host candidates exactly like the passing cells.
`--relay` is a testing/privacy knob ("hides your IP from the peer"); it was
never the right flag for a same-host harness.

## Verification requested

Decisive control before touching the harness: build the test-hooks binary and
run the join cell with a non-relay issuer (expected: green) vs a `--relay`
issuer (expected: red with the #212 signature). If the control confirms, drop
`--relay` from `spawn_daemon_inner`, re-run capability-ci on all three, and
reopen the join + send-to cells as the first coverage-ledger repayments.
