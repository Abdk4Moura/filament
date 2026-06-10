# Item 3 — L2/ssh rides the direct-QUIC ladder

## Problem (diagnosed live, do not re-derive)
Seamless `filament ssh` is unreliable cross-machine because the L2 link rides WebRTC,
which gets `connection stuck while connecting → dropping peer` cross-machine **even over
`--relay`** (verified do-vm↔pop-os). Meanwhile a plain file transfer over direct-QUIC to
do-vm's PUBLIC IP is rock-solid (`route: direct-quic`, byte-exact).

Root cause, pinned: the L2 initiator path `bring_up_to_known()` (`cli/src/l2.rs:399`) only
ever calls `Peer::connect(...)` (WebRTC) on `Ev::KnownPeer`. It **never starts a direct
attempt**. The `up` acceptor DOES (`start_direct` in `main.rs` sends a `transport-offer`
with its candidates — we saw `DIRECT-OFFER sent to popos`), but with no dialer on the
initiator side, only the hard leg (acceptor → NAT'd initiator) is tried, which fails
(`no authenticated QUIC in budget`). The initiator (pop-os) dialing do-vm's PUBLIC IP is
the leg that works, and nothing performs it.

## The hard rule (must not break)
`up` is BOTH the file-transfer acceptor and the L2/ssh acceptor. Do NOT change the
file-transfer default transport. `FILAMENT_DIRECT` stays opt-in for file transfer. Scope
direct-for-L2 to the L2 use-case only.

## Reusable primitives (already public in `direct.rs` — no extraction needed)
- `direct::bind_endpoint() -> (Endpoint, u16)`
- `direct::gather_candidates(server, port) -> Vec<String>`
- `direct::race_connect_labeled(...)` (direct.rs:588) — the core race that, given the
  endpoint + the peer's candidates + the pair secret + dialer role, returns an
  authenticated QUIC `Transport` (or None within budget). This is exactly what
  `start_direct`'s machinery drives in the main loop; here we call it directly.

## The change (two scoped edits)

### 1. Acceptor enablement — make `FILAMENT_L2` imply direct (small, safe)
In `direct::direct_enabled()` (direct.rs:43): return true if `FILAMENT_DIRECT==1` **OR
`FILAMENT_L2==1`**. Rationale: the L2 acceptor (`FILAMENT_L2=1 filament up`) wants reliable
CLI↔CLI; a plain `filament up`/`send` WITHOUT FILAMENT_L2 keeps the WebRTC default
untouched (hard rule preserved). The acceptor already sends offers + races once enabled.

### 2. Initiator — give `bring_up_to_known` a direct dial that races WebRTC
In `bring_up_to_known` (l2.rs:399), the standalone `while let Some(ev) = rx.recv()` loop:
- On `Ev::KnownPeer` (after `Peer::connect`): also `bind_endpoint()` + `gather_candidates()`
  and `emit("signal", {to: pid, data: {type:"transport-offer", v:1, addrs:<cands>}})` —
  mirror `start_direct`'s offer. Keep the endpoint in scope.
- Intercept incoming `transport-offer` signals: in the `Ev::Signal` arm, if
  `data["type"]=="transport-offer"`, do NOT pass it to the WebRTC `Peer`; instead spawn the
  race: `race_connect_labeled(endpoint, peer_addrs, secret, is_dialer=true, ...)` as a
  tokio task that sends its result back via a oneshot/Ev. (Both sides race; the
  initiator→acceptor-public-IP leg is the one that lands.)
- First transport to arrive wins:
  - direct race returns a `Transport` → send the `pair-proof` over it (same as the
    ChannelReady arm — the acceptor's cap gate keys on the proven petname) and
    `return Ok((t, rx, guard))` with `route = direct-quic`.
  - else `Ev::ChannelReady` (WebRTC) fires first → existing behavior.
- Budget: reuse `direct::DIRECT_BUDGET`; on expiry, WebRTC continues as today (no regression).

NOTE the pair-proof: the direct path's MAC auth already proves the secret, but the L2
acceptor's trust/cap gate currently keys on the post-WebRTC `pair-proof` + `verified_name`.
Ensure the direct link ALSO drives `verified_name` to `trusted` on the acceptor (the
existing DirectReady path in `up` marks direct links pre-trusted — confirm the L2 acceptor
honors that, or send the pair-proof over the direct transport too, which the ChannelReady
arm already does and should be replicated).

## Validation
- **netns** (`/root/wt-stress/cli/tests/transport-lab/`): one publicly-reachable ns +
  one NAT'd; assert an L2/ssh link comes up `route: direct-quic` where the acceptor is
  reachable, and falls back to WebRTC where neither side is.
- **Gates, no regression:** `cli/tests/ssh-gates.sh` (4), `l2-gates.sh` (5),
  `transport-gates.sh` rung-1 (4), and `gates.sh` send/recv (file transfer untouched).
- **Live (human runs — agent can't reach pop-os):**
  - do-vm: `FILAMENT_L2=1 filament up`   (no FILAMENT_DIRECT needed now)
  - do-vm: `filament grant popos shell`  (already granted)
  - pop-os: `filament ssh root@dovm 'hostname'`  → returns do-vm's hostname, route
    direct-quic, no keys, no prompts.

## Durability / safety
Commit this doc first (done). Then commit edit 1, then edit 2, incrementally. NO
Co-Authored-By. Do not weaken the seamless-ssh security gate (shell cap + trusted +
single authorized_keys writer). netns confinement; build to target/release; do not install.
