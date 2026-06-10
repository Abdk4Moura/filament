# Rung-2: UDP hole-punching (FILAMENT_HOLEPUNCH=1)

Additive transport rung that sits BETWEEN rung-1 (direct-dial QUIC) and rung-3
(relay / the shipped WebRTC fallback) on the ladder. The ladder's rule is "max
out each rung before stepping down": rung-1 already wins whenever a host or
public candidate is directly dialable; rung-2 catches the case where it can't —
both peers behind NAT, no directly-reachable candidate — by opening the NATs
with a simultaneous-open UDP punch, then running rung-1's *unchanged*
authenticated QUIC handshake over the punched socket. Only if the punch also
fails do we step down to WebRTC/relay.

## Non-negotiables (what makes this safe to land)

- **Gated.** The entire rung-2 path is dead unless `FILAMENT_HOLEPUNCH=1`. With
  the flag off, `start_direct` / `on_transport_offer` behave byte-for-byte as
  rung-1 does today. With `FILAMENT_DIRECT` *also* off, neither rung runs and the
  WebRTC path is untouched.
- **Reuses rung-1 wholesale.** Rung-2 changes ONLY how the UDP socket becomes
  connectable: it punches a hole, then hands the punched socket to a quinn
  `Endpoint` and calls rung-1's existing `race_connect` (and thus the existing
  `keying_material` RFC-5705 exporter auth, `auth_tag`, `authenticate`, and
  `drain_finish`). The QUIC handshake, the pair-secret MAC, the framing, the
  drain — all identical. The single change to `race_connect` is parameterizing
  the hardcoded `route: direct-quic` log string so rung-2 can emit
  `route: holepunched`.
- **No regression.** Rung-2 uses its OWN, second UDP socket (see below). Rung-1's
  quinn endpoint and its socket are constructed and raced exactly as before; the
  rung-2 attempt only begins *after* rung-1's host-candidate race returns None.

## The load-bearing constraint: rung-2 needs its own socket

A server-reflexive (srflx) candidate is a property of one specific UDP socket's
NAT mapping — the public `ip:port` the NAT assigned to *that socket*. The hole we
punch and the QUIC we run MUST be on the exact socket whose srflx we advertised,
or the peer punches/dials a mapping that doesn't lead to us.

quinn takes **ownership** of the `std::net::UdpSocket` it is built on
(`Endpoint::new(config, server_config, socket, runtime)` wraps it for async I/O
and sets it nonblocking). So we cannot: STUN socket S → build rung-1's quinn
endpoint on S → later raw-punch S for rung-2. Raw punching and quinn ownership
are mutually exclusive on one socket.

Therefore rung-1 and rung-2 use **two different sockets**:

- **rung-1 socket:** the existing `bind_endpoint()` quinn endpoint. Untouched.
  Advertised as host candidates (`addrs` in the transport-offer). This is the
  guarantee of no-regression: rung-1's machinery never sees rung-2.
- **rung-2 punch socket:** a second raw `std::net::UdpSocket` bound at
  `start_direct` time. We STUN it to learn its srflx mapping, advertise that
  srflx in a new `srflx` field of the transport-offer, keep the socket **raw**
  (parked, unconnected) until the punch, then — only if rung-1 fails — punch on
  it and hand the still-unconnected socket to `Endpoint::new`.

The punch socket is bound and STUN'd BEFORE the offer is emitted, because srflx
must travel in the offer. Its NAT mapping is kept alive simply by existing
(UDP conntrack timeout ≫ the 5s rung-1 budget — no re-STUN needed). quinn
discards any late/leftover punch bytes still in the socket as undecryptable QUIC,
so we don't drain it.

## Flow (chained rungs inside the existing direct state machine)

`start_direct(pid, name, secret)` (flag on):
1. `bind_endpoint()` → rung-1 quinn endpoint + its port (as today).
2. If `FILAMENT_HOLEPUNCH=1`: bind a second raw `UdpSocket` on `0.0.0.0:0`; run a
   STUN Binding against the configured STUN server to learn its srflx; remember
   the raw socket + srflx in the pending state. STUN/public-IP failure just means
   no srflx is advertised (graceful — rung-2 simply won't fire for this peer).
3. Emit the transport-offer with BOTH `addrs` (host, rung-1) and `srflx` (rung-2).
4. Stash `DirectPending` with the rung-1 endpoint AND the rung-2 punch socket +
   the peer's-srflx slot (filled when their offer arrives).

`on_transport_offer(pid, peer_addrs, peer_srflx)` spawns ONE task that chains the
ladder:
1. **rung-1:** `race_connect(rung1_endpoint, peer_addrs, secret, …)` — unchanged.
   On success → `Ev::DirectReady` (route `direct-quic`). Done.
2. **rung-2** (only if rung-1 returned None, the flag is on, we have a punch
   socket, and the peer advertised an srflx):
   a. **Punch:** retransmit a small UDP datagram to the peer's srflx every ~75ms
      on the raw socket, while reading inbound with a short timeout. The
      OUTBOUND send is what opens *our* NAT's mapping+filter toward the peer;
      receiving *their* punch confirms *their* filter is open for us. Continue
      until we have BOTH sent ≥1 and received ≥1 punch packet (bidirectional
      confirmation) or a punch budget (~3s) expires.
      - **Zero-RTT mapping race:** if quinn's first Initial arrives before the
        peer's NAT mapping exists, it's dropped. The explicit punch handshake
        (send-and-confirm-receive) guarantees both mappings are open before any
        QUIC byte. In netns the RTT is ~0, which makes the race WORSE than real
        WAN, so the lab adds netem latency on the NAT routers.
   b. **QUIC over the punched socket:** `Endpoint::new(EndpointConfig::default(),
      Some(server_config()), punch_socket, runtime)` + `set_default_client_config`,
      then `race_connect(punch_endpoint, vec![peer_srflx], secret, …,
      route="holepunched")` — rung-1's code, unchanged but for the route label.
      On success → `Ev::DirectReady` (route `holepunched`).
3. If both rungs return None, the spawned task ends; `expired_direct`'s per-tick
   reaper falls back to WebRTC at the deadline (unchanged).

Route labels stay distinct: `direct-quic` (rung-1), `holepunched` (rung-2),
`relayed` / `local` (WebRTC, rung-3).

## STUN: hand-rolled (no libjuice)

We need server-reflexive *discovery* only — not symmetric-NAT detection (the
punch failing IS the detection; symmetric defeats punching and we step down). A
STUN Binding request is a 20-byte header (type 0x0001, magic cookie
0x2112A442, 96-bit transaction id); the response's XOR-MAPPED-ADDRESS attribute
(0x0020) holds our public `ip:port` XOR'd with the cookie/txid. ~50 lines, std
sockets only, sent from the punch socket so the mapping we learn is the one we'll
punch+QUIC. Hand-rolling avoids a new dependency and matches the task's stated
preference; libjuice would only be justified if we needed symmetric-correct
candidate prediction, which we explicitly do not.

The STUN server URL comes from the existing ICE config (`stun:host:port` in
`/api/config`'s iceServers) — the same coturn rung-3 already uses. An env
override `FILAMENT_STUN` is honored for the lab.

## Validation (netns lab — real NAT, not loopback)

Loopback can't exercise NAT, and `transport-gates.sh` runs a backend with no
TURN. Rung-2's two gates are modeled on `run-matrix.sh`: `lab_build_core` +
`start_backend` + `start_turn` (real coturn) + `lab_add_nat_client`.

- **Cone-ish pair → punch SUCCEEDS.** `port-restricted` both sides (lib.sh's
  port-restricted is plain MASQUERADE = Endpoint-Independent Mapping → the srflx
  port is stable across destinations → punchable). `natprobe.py` first PROVES the
  topology is EIM. Assert `route: holepunched`, byte-exact transfer, NO relay.
- **Symmetric pair → punch FAILS, steps down.** `symmetric` both sides
  (`MASQUERADE --random-fully` = Endpoint-Dependent Mapping → the srflx port the
  STUN server sees differs from the port toward the peer → the punch lands on the
  wrong port and times out). We do NOT pre-detect this; we let the punch time out
  and fall through. `natprobe.py` first PROVES EDM. Assert `route: relayed`,
  byte-exact transfer (the graceful step-down is as important as the success).

netem latency (`tc qdisc … netem delay`) on the NAT routers gives the punch the
natural RTT real WAN has, so quinn's Initial can't beat the mapping in netns.
Added as a lab-prefixed helper in lib.sh.

Rung-1's `transport-gates.sh` must still pass unchanged (flag-off and
`FILAMENT_DIRECT=1` paths are untouched by rung-2).

## Confinement / safety

All rung-2 lab networking stays inside the existing `filtest-*` netns (per
lib.sh's safety model); netem is applied only inside `filtest-nat{A,B}`. Cleanup
via the existing traps. Never touches host eth0, the prod coturn, or prod
networking. Secrets (pair secret, transport key, TURN secret) are never printed
or committed.
