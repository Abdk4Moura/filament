# Direct CLI↔CLI transport — bypass WebRTC/ICE when neither end is a browser

Status: DESIGN. Realizes the long-stubbed `Transport` trait second impl
(`net.rs`: "DataChannelTransport is implementation #1; a QUIC transport for
CLI↔CLI bulk speed slots in later without touching the transfer logic").
Motivated by a live failure: two CLIs, one of them do-vm (public IP, no
firewall), failed to pair — forced through WebRTC/ICE, whose cross-NAT
traversal never completed (creator watchdog'd 3×15 s and quit; claimer
orphaned). They never needed ICE at all.

## The thesis

WebRTC/ICE/STUN/TURN exist because **browsers cannot open raw sockets**. Two
CLIs are full network stacks. When either end is directly reachable — a
public IP (servers, do-vm, VPS), a shared LAN, a Tailscale/WireGuard overlay
— a plain dial connects with none of ICE's fragility and none of the TURN
relay tax (the state-machine diagram showed even do-vm↔phone paying it). ICE
should be the **fallback** for the hard case (both behind symmetric NAT,
neither reachable), not the default for every pair.

## When it engages

Only when BOTH peers are CLIs. The browser is the constraint; if either peer
is a browser, WebRTC stays. Detection: the signaling `uid` already prefixes
CLI processes (`cli-s/r/p-`), but uid is not authenticated for capability, so
peers also exchange an explicit `transport-offer` control message at connect
time. No `transport-offer` from the other side within the budget ⇒ it's a
browser (or an old CLI) ⇒ use WebRTC. Fully backward compatible.

## The handshake (over the existing signaling channel)

```
both CLIs, in the same room / known-peer channel:
  1. each binds a TCP listener on an ephemeral port
  2. each gathers its OWN candidate addrs (cheap, no STUN round-trip):
       - every non-loopback local interface ip:port
       - the public ip:port IF known (configured, or learned via a
         one-line /api/whoami echo of the socket's remote addr)
  3. exchange via signaling:  { type:"transport-offer", v:1,
       addrs:[ "ip:port", ... ], nonce }   (relayed, opaque to server)
  4. SIMULTANEOUS connect: each dials every addr the peer advertised,
     in parallel, racing its own listener accept. First socket to finish
     the auth handshake (below) WINS; all others close.
  5. on a winning socket -> wrap as TcpTransport (impl Transport) and the
     transfer logic proceeds UNCHANGED (same control JSON + sid-framed
     binary it already speaks over the DataChannel).
  6. budget ~5s: no authed socket ⇒ tear down, fall back to WebRTC.
```

Simultaneous-open + dial-all-candidates is the same idea ICE uses, minus the
STUN/TURN apparatus and minus the SDP — because at least one CLI is usually
directly reachable, the common case resolves in one RTT.

## Security — NON-NEGOTIABLE: must match DTLS, not regress from it

WebRTC gave authenticated encryption for free (DTLS + the C20 fingerprint
proof). A raw TCP transport must provide the SAME: confidentiality,
integrity, and peer authentication. Plaintext or unauthenticated TCP is a
hard NO — it would be a catastrophic regression for a file-transfer tool.

Design: a **Noise protocol handshake** (Noise_NNpsk0 or Noise_KKpsk2) over
the raw TCP socket, keyed differently per pairing mode:

- **Known devices** (`--to name`, paired): the pre-shared `pair secret`
  (32 bytes, already mutually held) is the Noise PSK. This AUTHENTICATES
  the peer cryptographically — the same guarantee C20's HMAC proof gives,
  now binding the transport itself. A MITM without the secret cannot
  complete the handshake. This is strictly STRONGER than the WebRTC path
  (no TURN server in the trust path at all).
- **One-time code** (`pair <code>`): the code alone is low-entropy (~22
  bits) — not a safe PSK against an active MITM who can guess it. Phase 1:
  for code pairing, KEEP WebRTC (its DTLS + the signaling server's
  single-claim burn is the existing trust model); the direct transport
  engages only AFTER a secret is established, or for `--to` known devices.
  Phase 2 (later): a PAKE (C15) over the code makes code-based direct
  transport safe; tracked separately.

So phase 1 scope: **direct transport for KNOWN DEVICES only** (`--to`,
`up`, daemon) — exactly the case that failed live, exactly the case with a
real PSK. The `nonce` in transport-offer is the Noise handshake nonce;
replay is prevented by it + the PSK.

## What it fixes / improves (all measurable)

- the live cli↔cli failure: do-vm is directly dialable ⇒ connects in 1 RTT,
  no ICE, no watchdog, no orphan
- the relay tax: known-device transfers that currently go `route: relayed`
  (observed do-vm↔phone, though phone is browser so stays WebRTC — but
  cli↔cli daemon transfers stop relaying)
- throughput: a direct TCP/QUIC stream beats SCTP-over-DTLS for bulk
- the gate-L philosophy extends: a new chaos cell drops the direct path and
  asserts the WebRTC fallback still completes — neither transport is
  load-bearing alone

## Build plan (phase 1, known-devices)

1. `net.rs`: `TcpTransport` impl `Transport` (the trait is already the seam;
   send_control = length-prefixed JSON, send_frame = the existing sid+payload
   framing, both over the Noise-encrypted socket).
2. `net.rs`: Noise_KKpsk2 (or NNpsk0) handshake helper keyed by the pair
   secret; a `snow`-crate session wrapping the TcpStream.
3. address gather (`local_addrs()` + optional `/api/whoami`), `transport-offer`
   control message, the simultaneous-open dialer with a 5s budget.
4. wire into the known-device connect paths (`--to`, `up`): try direct first,
   fall back to the existing WebRTC establish on timeout.
5. gates: a CLI↔CLI direct transfer gate (assert `route: direct-tcp`, hash
   match) + a chaos gate that blocks the direct port and asserts WebRTC
   fallback still completes.
6. ledger + CONTRACT entries; `route` taxonomy grows a `direct-tcp` value.

Phase 1 deliberately leaves browsers, code-pairing, and QUIC for later —
smallest change that kills the failure class the monitor just caught.
