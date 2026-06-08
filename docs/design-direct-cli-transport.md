# Direct CLI↔CLI transport — bypass WebRTC/ICE when neither end is a browser

Status: DESIGN. Realizes the long-stubbed `Transport` trait second impl
(`net.rs`: "DataChannelTransport is implementation #1; a QUIC transport for
CLI↔CLI bulk speed slots in later without touching the transfer logic").
Motivated by — but NOT causally pinned to — a live failure: two CLIs, one of
them do-vm (public IP, no firewall), failed to pair, forced through
WebRTC/ICE. The exact root cause was never reproduced cross-machine (test B
below proves only do-vm's half can allocate on coturn; whether the *remote*
box could is the unconfirmed unknown). The honest framing: **this transport
sidesteps the whole NAT-traversal class regardless of that incident's root
cause.** It stands on its own merits — 1-RTT, no relay tax (the
state-machine diagram showed transfers paying it), and the plain fact that
two full network stacks should not need browser NAT-traversal machinery.

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

### Threat model (the address channel is untrusted)
The `transport-offer{addrs}` rides the **untrusted signaling server**. A
malicious or compromised server can substitute addresses → you dial an
attacker's box → the Noise handshake **fails** (the attacker has no PSK) →
you fall back to WebRTC. So the server can **DoS** (point you at dead/wrong
addresses, force a fallback) but **cannot MITM**. *All* security rests on
the PSK handshake; the address channel needs no integrity protection. This
is the load-bearing statement — everything else follows from it.

### The handshake
A **Noise_NNpsk0** handshake (via the `snow` crate — do NOT hand-roll the
state machine) over the raw TCP socket. NNpsk0 fits the constraints: no
pre-existing static keys (rules out KKpsk2), mutual auth derived from the
PSK, and the ephemeral `ee` gives forward secrecy even if the secret later
leaks. Rely on Noise's own ephemerals for replay + FS — **no homemade nonce
scheme** bolted on top (redundant at best, weakening at worst).

### Key derivation — the PSK is NOT the raw secret
The pair secret already keys TWO things: the C20 HMAC proof, and the public
channel id `sha256("filament-pair:"+secret)`. Feeding the *same* raw secret
into a third primitive is cross-context key reuse — the classic footgun.
Derive an independent transport key:
```
psk = HKDF-SHA256(ikm=secret, info="filament-direct-transport-v1")[:32]
```
Now the transport key is cryptographically independent of the proof key and
the (published) channel hash.

### Scope + downgrade safety
- **Phase 1: KNOWN DEVICES only** (`--to`, `up`, daemon) — the case with a
  real high-entropy PSK. The `nonce` in transport-offer is dropped (Noise
  owns replay).
- **One-time code** (`pair <code>`): the code is low-entropy (~22 bits), not
  a safe PSK against an active guesser. Code pairing KEEPS WebRTC until a
  PAKE (C15) makes it safe — tracked separately.
- **Downgrade safety:** the WebRTC fallback STILL requires the C20
  fingerprint proof. Forcing a fallback (the server's DoS power) therefore
  never drops authentication — both transports authenticate, neither is a
  soft path.

### New attack surface (raw listener)
- bind the TCP listener ONLY for the connection window; close it after the
  handshake resolves (success or fallback). No idle open port.
- rate-limit handshake attempts per source (a scanner that finds the port
  fails the PSK, but must not be able to grind).

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
5. gates — THREE, and the negative one is the security claim:
   - **positive**: two secret-holders connect direct (`route: direct-tcp`,
     hash match).
   - **NEGATIVE (the actual security test)**: a dialer with a WRONG/ABSENT
     PSK must be REJECTED — handshake fails, zero bytes flow. An auth gate
     that only tests authorized access verifies nothing; per the ledger
     rule, VERIFIED here *means this test exists*.
   - **chaos fallback**: block the direct port → WebRTC fallback completes
     AND still performs the C20 proof (downgrade never drops auth).
6. ledger + CONTRACT entries; `route` taxonomy grows a `direct-tcp` value.

Phase 1 deliberately leaves browsers, code-pairing, and QUIC for later —
smallest change that kills the failure class the monitor just caught.
