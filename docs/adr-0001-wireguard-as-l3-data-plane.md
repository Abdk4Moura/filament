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

## 2026-09-07: the relay is deleted, and boringtun is NOT the answer here

The loopback relay is gone. It was dominated, as recorded below. But the
replacement it was supposed to make way for, boringtun over filament's transport,
should NOT be built, and the reason is specific to filament rather than a
judgement about boringtun.

**filament's transport is already an authenticated encrypted channel.** A direct
link is QUIC with rustls/TLS 1.3; a relayed link is a WebRTC DataChannel over
DTLS. Running WireGuard inside either encrypts the same bytes twice and
authenticates a peer that the transport has already authenticated. It costs CPU
and buys nothing.

**That is exactly where filament differs from Tailscale.** Tailscale needs
wireguard-go because DERP is a dumb packet forwarder with no per-peer crypto of
its own: WireGuard IS its security layer, so it must run somewhere, and userspace
is the only place they can own the socket. filament's relay is not DERP. It is a
mutually authenticated tunnel in its own right, so the security layer already
exists and the QUIC-datagram plane already carries a NATed peer over the same
punched path.

So the honest shape is two planes, not three:

1. **Kernel WireGuard, direct**, when the peer's endpoint is reachable. Kernel
   crypto, kernel data path, no userspace at all. This is the whole reason to use
   kernel WireGuard, and it is the case that is worth having.
2. **The existing QUIC-datagram plane** for everyone else. Already written,
   already measured, already encrypted and authenticated.

A peer whose direct WireGuard path does not handshake within 8s has its peer
entry REMOVED rather than re-pointed at a tunnel-inside-a-tunnel, so it stays on
the plane it was already using and no route is left pointing into something that
carries nothing.

What would change this: if filament ever gains a transport that forwards
ciphertext without authenticating peers (a true DERP equivalent), WireGuard would
become the security layer for that path and boringtun would earn its place.

## 2026-09-08: DIRECT kernel-to-kernel, verified with no NAT anywhere

Both daemons in ROOT namespaces on their real public IPs. No namespace, no
MASQUERADE, no DNAT in the path:

    owner  endpoint 162.35.114.254:51820  handshake 1m40s ago  220 B recv / 180 B sent
    peer   endpoint 165.22.207.231:51820  handshake 1m42s ago  180 B recv / 400 B sent

Real addresses on both sides, not 127.0.0.1, so nothing is being relayed: kernel
crypto, kernel data path, zero userspace hops. That is the design this ADR asked
for, and the opt-in default is now the only thing between it and being on.

### Three bugs, none of which the namespace rig could reach

1. **`peer_overlay_of` used `try_lock`**, so ordinary CONTENTION returned `None`,
   indistinguishable from "that peer is not on the overlay". A key announcement
   was rejected with "no direct endpoint or overlay address yet" for a peer
   plainly on the mesh, intermittently.
2. **WireGuard was attempted with no kernel TUN.** A node on the userspace
   overlay has no kernel device to bind the overlay address to, and the result
   was a literal `ip addr add /128` with nothing before the prefix. `usable()`
   checked the wg tools and the module, which say nothing about that.
3. **`ip addr add` idempotence matched only the IPv4 wording.** iproute2 says
   "File exists" for IPv4 and "address already assigned" for IPv6, and the
   overlay is an IPv6 ULA, so every retry and every second peer failed there and
   took the whole adopt down.

### The finding that is not about WireGuard

The peer had **IPv6 disabled system-wide** (`net.ipv6.conf.all.disable_ipv6=1`),
which is a common hardening default. filament's overlay IS an IPv6 ULA, so
`ip addr add` failed, the node fell back to the userspace overlay, and the only
evidence was a log line quoting the failed command. A host with IPv6 disabled
silently loses the kernel data plane. filament should DETECT this and say so by
name; that is worth a separate fix and is not done.

## 2026-09-07, correction: kernel-direct works, and my rig said otherwise

Plain kernel WireGuard between do-vm and the KVM VPS, no filament involved:

    endpoint: 162.35.114.254:51999
    latest handshake: 11 seconds ago
    3 packets transmitted, 3 received, rtt avg 76.345 ms

So the earlier conclusion that kernel-to-kernel could not handshake was WRONG,
and it was wrong because of the test rig, not the code. Each daemon runs in a
network namespace (l3::ifname() is a const, so two daemons on one host cannot
both hold filament0), and those namespaces reach the internet through a
MASQUERADE I wrote. That self-inflicted NAT is what had no inbound mapping for
WireGuard's port. Both machines have PUBLIC IPs; in the real topology the NAT
does not exist. An artificial constraint in the harness was read as a property of
the system.

### What this changes

**Kernel-direct is the default, not a rung.** For any peer whose WireGuard port
is reachable (a public IP, a port-forward), there is no userspace in the data
path at all, which is the entire reason to use kernel WireGuard. That covers
servers, which is where throughput matters most.

**Reachability, not privilege, is the only thing that can force a fallback.**
Privilege decides whether kernel WireGuard is available; NAT decides whether its
socket can be reached. They are independent, and the second is the harder one:
filament punches holes with its OWN socket, and kernel WireGuard cannot share it.

### On the fallback, and what Tailscale actually does

Tailscale does not use kernel WireGuard for this. It ships **wireguard-go**, a
USERSPACE implementation, precisely so it owns the UDP socket and can do its own
endpoint discovery and DERP relaying. Owning the socket is what makes NAT
traversal possible at all, and they pay userspace crypto to get it.

That is the lesson, and it says the loopback relay currently in the tree is the
wrong fallback. It costs kernel WireGuard -> userspace relay -> transport, two
extra context switches per packet, to get what an in-process userspace WireGuard
gets in one: encrypt in process, hand straight to the transport.

So the shape should be:

1. **Kernel WireGuard, direct** when the peer's endpoint is reachable. Default.
   No userspace in the path. Proven above.
2. **boringtun** (an audited Rust WireGuard) over filament's transport when it is
   not. This is Tailscale's model and strictly cheaper than the loopback relay.
3. **Delete the loopback relay** once 2 exists; it is dominated by it.

And explicitly NOT: reimplementing the WireGuard protocol over QUIC. The protocol
is the valuable part and it is already implemented well; a rewrite would inherit
the risk of hand-rolled crypto for none of the benefit. Using boringtun is the
same idea done with a library.

## Status 2026-09-07: WORKING. Kernel WireGuard over filament's transport.

A kernel WireGuard tunnel between two machines, keyed over filament's own
authenticated connection, with a completed handshake, verified by
`experiments/wireguard-2machine.sh`:

    peers: 1
    endpoint: 127.0.0.1:57333
    allowed ips: fdf1:1af7:c30d:a2:a7e7:1a0d:e2e1:40e8/128
    latest handshake: 1 second ago
    transfer: 124 B received, 180 B sent

### The design, and why it is decision 2 of this ADR rather than a workaround

Kernel WireGuard owns its UDP socket, so it does its own NAT traversal, and it
has none: both ends announced their INTERNAL listen port, the NAT had no inbound
mapping, and every handshake was dropped. The answer is not to teach WireGuard
about NAT. It is to stop WireGuard touching the network at all.

Each side points its peer's endpoint at a filament-owned UDP socket on LOOPBACK,
and filament carries the frames over the path it has already punched:

    kernel WG --UDP--> 127.0.0.1:relay --filament transport--> peer's relay --> its WG

That is exactly "WireGuard rides on top of whichever underlay path won": filament
keeps identity, discovery, NAT traversal and relay fallback; WireGuard gets the
data plane. The `endpoint: 127.0.0.1` in the output above is the whole point.

**The demux needs no format change.** Datagrams already carry raw IP packets and
the receiver reads the version nibble. A WireGuard frame's first byte is its
message type, 1..=4, which cannot collide with 0x4_ (IPv4) or 0x6_ (IPv6), so a
WireGuard frame is self-identifying on the existing datagram channel. The L3
pump splits them: WireGuard frames go to the peer's relay, everything else to the
TUN, where a WireGuard frame would have been a malformed IP packet.

**It is not slower than the plane it joins.** The hot path was
`TUN read -> transport`; it is now `UDP read -> transport`, the same number of
userspace copies, with the crypto moved into the kernel and onto WireGuard's
multi-threaded data path instead of the single-threaded QUIC-datagram loop this
ADR was written to replace.

### Still to do before it is the default

- It is opt-in (`filament set wireguard on`) and stays that way until the
  throughput case is measured against the QUIC plane on the two-machine rig.
- The relay socket binds `127.0.0.1:0` per peer. Anything that could reach it
  could inject frames the peer never sent, which is why it is loopback-only;
  a shared socket with per-peer demux would be tidier and is not required.
- macOS and Windows are untouched: `usable()` answers no there, and the QUIC
  plane carries everything as before.

## Status 2026-09-07: keys exchange and peers configure; the handshake is blocked by NAT

The module had `mod wg;` and ZERO callers. It is now wired, reconciling, and both
ends configure each other. What it does NOT yet do is complete a handshake, and
the reason is architectural rather than a bug.

### What works

`filament set wireguard on` (off by default: this changes the DATA PLANE).
Reconciliation runs on a 10s TICK, not an event, because a link that starts
relayed upgrades to direct AFTER the announce and an event hook missed it.

The key exchange rides the CONTROL CHANNEL, the same path certificate renewal
uses. The first version opened a raw QUIC bi-stream and both ends hung forever
after creating their interface: filament multiplexes its own protocol over that
connection and runs its own stream acceptor, so an out-of-band stream races with
it. The exchange is now symmetric with no initiator: each side announces its key,
each configures the other on receipt, and two messages converge.

Measured between two machines over the real internet: both logged
`WireGuard tunnel to <peer>`, `wg show` reported **1 peer** with the right
endpoint and allowed-ips, and 148 B was sent.

### What does not, and why it is not a bug to fix in wg.rs

**0 B received, no handshake.** The endpoint each side announces is its own
WireGuard listen port, and both daemons sit behind NAT. The announced port is the
INTERNAL one; the NAT has no inbound mapping for it, so handshake packets are
dropped. WireGuard opened its own UDP socket instead of using the path filament
had already punched.

That is exactly what decision point 2 of this ADR says must not happen:
"WireGuard rides on top of whichever underlay path won... The direct-TCP arm
stops being a competing L3 plane and becomes a path option *under* WireGuard."
A WireGuard peer with its own socket is a SECOND connectivity story, and it
inherits none of filament's NAT traversal.

### The next step, concretely

Two options, and they are not equivalent:

1. **Userspace WireGuard over filament's transport** (boringtun-style): WG frames
   ride filament's existing punched path as datagrams. Keeps every property
   filament already has, is the ADR's stated design, and is the larger job.
2. **Kernel WireGuard with a punched endpoint**: teach the exchange to announce
   the EXTERNAL mapped address, which means either reusing filament's ICE result
   for the WG socket or port-forwarding. Cheaper, but it re-implements NAT
   traversal that filament already owns, which is what the ADR warns against.

Option 1 is the right one. `experiments/wireguard-2machine.sh` reproduces the
current state end to end and fails on the handshake assertion, which is the
correct place for it to fail.

## Status 2026-09-06: wired and reconciling; the key exchange does not yet complete

See the commit history for detail. The module is wired (warnings 115 -> 95),
reconciles on a 10s tick, and creates `filament-wg` on both machines. The peer is
not configured yet: `wg show` reports zero peers, so no tunnel has carried a
packet. Three real bugs were found and fixed on the way (a probe interface name
one character over the Linux 15-char limit, which made the capability check
always answer no; both ends able to pick the same exchange role; and no timeout
on the exchange, which made that deadlock silent). Reproduce with
`experiments/wireguard-2machine.sh`.
