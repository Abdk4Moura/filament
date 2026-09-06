# ADR-0001: Adopt WireGuard as the default L3 data plane

- Status: Proposed
- Date: 2026-07-25
- Deciders: project owner (Abdk4Moura)
- Related: `docs/design-adaptive-transport-portfolio.md`

## Context

### What filament's L3 (VPN) data plane is today

`filament up` attaches an IP plane to the mesh. The current implementation
(`l3.rs`, `tun/linux.rs`, `direct.rs`) is:

- A kernel TUN device `filament0` (`IFF_TUN | IFF_NO_PI`), configured via iproute2.
  This gives a real kernel netdev (routing, host firewall, MagicDNS names). It is
  the only "kernel" part.
- A **userspace QUIC-datagram data plane**. The hot path is, per packet:
  `tun.recv()` one packet (`tun/linux.rs:260`) -> `dest_ip()` route lookup ->
  `conn.send_datagram(Bytes::copy_from_slice(pkt))` (an unreliable QUIC DATAGRAM,
  RFC 9221, over UDP; `direct.rs:1225`) -> peer `read_datagram()` -> `tun.send()`
  one packet. Crypto is QUIC's TLS 1.3, in userspace.

This is architecturally **wireguard-go-class (userspace), not in-kernel-WireGuard
class**, and in fact sits *below* the wireguard-go baseline because it lacks every
optimization wireguard-go added. Confirmed structural ceilings:

1. Per-packet syscalls, zero batching. One `read()`/`write()` per packet. No
   `IFF_VNET_HDR` (GSO/GRO), no `IFF_MULTI_QUEUE`, no `sendmmsg`/`recvmmsg`
   (grep-verified absent across `tun/`, `l3.rs`, `net.rs`, `direct.rs`).
2. A per-packet allocation + copy (`Bytes::copy_from_slice`, `direct.rs:1230`).
3. Single core: one task pumps the TUN for the whole node (`l3.rs:216`); one task
   per link drains datagrams to the TUN (`l3.rs:376`). Classic one-flow-one-core.
4. UDP-only, so it eats the same UDP rate policer we measured on the
   do-vm <-> other-do link (TCP 2.0 Gbps, UDP throttled ~1.3 Gbps). Relay links
   carry no L3 at all. Default overlay MTU ~1280, which maximizes packet count.

### Why it was built this way (the real reason, not a strawman)

filament's L3 datagrams ride the **same authenticated QUIC connection** that
already punched through NAT and completed the PAKE. The overlay thus inherits all
of filament's connectivity and identity for free, over one connection. WireGuard
would need a *second, separate UDP flow* with its own hole-punching and its own
static-key trust model. That code-reuse and simplicity is genuine. The cost is an
order-of-magnitude throughput hit and a data plane we must optimize and secure
ourselves.

### The forcing function

The distributed-GPU / high-throughput direction needs a credible multi-10-Gbps
data plane. Kernel WireGuard is that (10-Gbps-class, GSO/GRO, multiqueue, audited
Noise crypto, years of tuning). The QUIC-datagram path is disqualifying for it.
Catching the homegrown plane up (GSO/GRO, multiqueue, sendmmsg, zero-copy) is a
multi-month project to reach what WireGuard gives for free in a tiny audited
codebase. Two independent reviews (an internal skeptic and a cited research pass)
converged on the same conclusion.

### Measured evidence (2026-07-25)

The "order of magnitude" above was an inference from architecture. It has now been
measured head-to-head. Rig: one host, two network namespaces joined by a veth pair
(the underlay), same overlay IPs (10.9.0.0/24), same `iperf3` tests. filament's L3
via `serve-tun` (the QUIC-datagram pump) vs a kernel-WireGuard tunnel, both at the
default 1280 TUN MTU. The veth underlay itself sustained ~14,960 Mbps, so neither
overlay was link-bound.

| Test (MTU 1280) | filament L3 (QUIC datagram) | kernel WireGuard |
|---|---|---|
| Single-stream TCP | 479 Mbps, 382 retransmits | 1218 Mbps, 0 retransmits |
| 4 parallel TCP | 543 Mbps | 1122 Mbps |
| UDP, offer 3 Gbit | 464 Mbps delivered, 61% loss | 454 Mbps delivered, 35% loss |
| CPU during TCP | ~0.5 core each, NOT saturated | ~88% across all 4 cores |
| At native 1420 MTU | n/a (QUIC datagrams cap ~1280) | 1314 Mbps, 0 retransmits |

Reading:

- Raw same-rig ratio is ~2.5x (1218 vs 479 Mbps), but that **understates** the win.
  The rig is conservative *for WireGuard*: WireGuard is CPU-bound here (both
  endpoints' crypto plus iperf competing for 4 cores), so 1.2 Gbps is a floor, not
  its ceiling. filament is NOT CPU-bound (half a core), it is architecture-bound, so
  its 0.5 Gbps is near its true ceiling. On dedicated hardware per end, kernel
  WireGuard reaches the 5-13 Gbps range; filament would barely move. The real gap is
  multiples of 2.5x.
- The qualitative difference matters as much as the ratio: WireGuard delivered with
  **zero retransmits**; filament threw 382 and lost 61% of the UDP flood. filament's
  unreliable-datagram plane drops under load (quinn discards datagrams past the
  congestion window), so the inner TCP keeps backing off. That is *why* it sits at
  0.5 Gbps on a 15 Gbps underlay with spare CPU. One plane fights the traffic inside
  it; the other carries it.
- WireGuard also gets a packet-size edge filament structurally cannot match (1420 vs
  ~1280), because QUIC datagrams do not do jumbo.

Bench scripts: `l3bench.sh` (before) and `wgbench.sh` (after) in the working notes.

## Decision

**Adopt WireGuard as filament's default L3 data plane. Keep filament as the network
(control plane + connectivity) around it.** Concretely:

1. **WireGuard is the primary L3 data plane.**
   - Admin mode: kernel WireGuard when `CAP_NET_ADMIN` is available and a UDP path
     exists. (Windows already uses Wintun, WireGuard's TUN driver.)
   - No-admin mode: a userspace WireGuard (boringtun / wireguard-go / a Rust impl),
     still faster than the single-threaded QUIC-datagram TUN, still audited crypto.
2. **Layer the two planes; do not couple them.** The no-regret transport portfolio
   applies to the **connectivity / underlay** layer, not the L3 layer:
   - The portfolio selects how to get packets between the two hosts: direct UDP
     when possible; a UDP-over-TCP / relay shim when UDP is blocked or policed;
     WebRTC when browser.
   - **WireGuard rides on top of whichever underlay path won.** The direct-TCP arm
     stops being a competing L3 plane and becomes a path option *under* WireGuard.
3. **Preserve unified identity via the control channel.** Do PAKE / key exchange
   over filament's existing authenticated control channel, then *install the
   resulting keys* into WireGuard. filament keeps owning identity, discovery, NAT
   traversal, hole-punching, and relay selection.
4. **Keep the QUIC/WebRTC plane only as a bridge**, not a destination: for the
   browser/WebRTC case (browsers cannot run WireGuard), the no-admin case while a
   userspace-WG story matures, and during migration.

```
   Layered model (the decision in one picture):

   +-----------------------------------------------------------+
   |  filament control plane (STAYS ours):                     |
   |  identity, PAKE codes, discovery, NAT traversal/holepunch,|
   |  relay selection, transport portfolio (PATH selection)    |
   +-----------------------------------------------------------+
                     | selects an underlay PATH
                     v
   +----------------------+  +----------------------+  +----------------+
   | direct UDP           |  | UDP-over-TCP / relay  |  | WebRTC (browser|
   | (clean case)         |  | (UDP blocked/policed) |  |  / no-WG case) |
   +----------------------+  +----------------------+  +----------------+
                     | WireGuard rides on top of the chosen path
                     v
   +-----------------------------------------------------------+
   |  L3 DATA PLANE = WireGuard (kernel when admin, userspace   |
   |  WG otherwise). Encrypted IP-packet tunnel. BORROWED.     |
   |  (legacy QUIC-datagram plane retained only as a bridge)    |
   +-----------------------------------------------------------+
```

## Consequences

### Positive

- Multi-10-Gbps-class data plane with GSO/GRO, multiqueue, and audited Noise crypto
  for free, instead of a multi-month optimization project we own and must secure.
- Less security-critical code to own. WireGuard's data plane is tiny and audited;
  ours is neither.
- Correct semantics: WireGuard is a best-effort packet tunnel, which is what an L3
  VPN should be (the inner protocol owns reliability; avoids TCP-over-TCP).
- The connectivity moat (PAKE, discovery, NAT traversal, relay, path portfolio)
  stays filament's and is untouched.

### Negative / costs

- A WireGuard dependency: kernel WG where present, plus a userspace WG for no-admin.
  Cuts against filament's dependency-light ethos.
- Identity bridge work: map filament's Ed25519 + PAKE + channel-binding identity to
  WireGuard's static Curve25519 keypair model (exchange over the control channel,
  install keys).
- Two crypto stacks during migration (WireGuard Noise + the retained QUIC/WebRTC
  bridge).
- Need a UDP-over-TCP / relay shim so WireGuard survives UDP-hostile networks
  (WireGuard is UDP-only and will not fall back on its own).

### The one defensible reason to retain the homegrown path long-term

Browser / WebRTC. Tunneling IP from a browser requires WebRTC data channels;
WireGuard cannot help there. Keep the WebRTC path for that beachhead, but kernel
WireGuard is still the admin-mode default for non-browser users.

## Alternatives considered

1. **Status quo (homegrown QUIC-datagram L3).** Rejected: below wireguard-go
   baseline, single-core, per-packet, UDP-policed; disqualifying for the throughput
   direction.
2. **Fix the homegrown plane (add GSO/GRO, multiqueue, sendmmsg, zero-copy).**
   Rejected as the primary plan: multi-month effort to re-derive what WireGuard
   already gives, in code we must audit. May still do the cheap subset (kill the
   per-packet copy) for the retained bridge path.
3. **Adopt WireGuard as the data plane (this ADR).** Chosen.

## Migration / phasing (sketch, non-binding)

1. Prototype the smallest end-to-end slice: filament brokers a WireGuard tunnel
   between two peers (PAKE over control channel -> install WG keys -> kernel WG over
   the punched UDP path). Measure vs the current QUIC-datagram plane on loopback
   (CPU ceiling) and cross-machine (policer-bound).
2. Add the userspace-WG (no-admin) arm.
3. Add the UDP-over-TCP / relay shim so WG survives UDP-hostile links; wire it to
   the portfolio's path selection.
4. Make WireGuard the default; demote the QUIC-datagram plane to the
   browser/no-WG/migration bridge.

## Status 2026-09-06: wired and reconciling; the key exchange does not yet complete

See the commit history for detail. The module is wired (warnings 115 -> 95),
reconciles on a 10s tick, and creates `filament-wg` on both machines. The peer is
not configured yet: `wg show` reports zero peers, so no tunnel has carried a
packet. Three real bugs were found and fixed on the way (a probe interface name
one character over the Linux 15-char limit, which made the capability check
always answer no; both ends able to pick the same exchange role; and no timeout
on the exchange, which made that deadlock silent). Reproduce with
`experiments/wireguard-2machine.sh`.
