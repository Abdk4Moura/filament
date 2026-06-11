# Primitives reference

The lab is built from 7 small, composable primitives, each with a single
responsibility and a documented interface. Providers (the `link` primitive)
compose the others.

## 1. tun — `primitives/tun.py` (+ `tun_io.py`)

Create a TUN iface in a node's netns and (optionally) address it on the overlay.

```python
tun.create(ledger, ns, iface, addr_cidr=None, mtu=1380)
```
- The engine creates TUNs **bare** (no address); each carrier addresses the
  overlay on its real data-path iface, so a carrier-less TUN never wins a
  competing on-link route.
- `tun_io.open_tun(iface)` / `read_packet(fd)` / `write_packet(fd, pkt)` give raw
  IP-packet access from Python (used by the udp + filament userspace relays). The
  TUN is `IFF_TUN | IFF_NO_PI` → bare IP packets, no Ethernet header.

## 2. link — `providers/`

The pluggable carrier between two endpoints. Interface: `up(ctx)` establishes the
carrier and records resources in the ledger; `down(ctx)` is provider-specific
teardown (the ledger sweep is the backstop). Providers:

| provider | datapath | crypto | proves |
| --- | --- | --- | --- |
| `pipe`/`veth` | veth pair joins the two netns directly | none | topology engine + tun + route + probe |
| `udp` | userspace UDP relay over the veth underlay | none | frame primitive + a real socket hop |
| `wg` | **real WireGuard** (kernel, or wireguard-go/boringtun) | wg-noise | the provider abstraction vs production crypto |
| `filament` | filament data channel via an L2 forward stream | none (channel is DTLS) | **filament as an L3 carrier** (integration target) |

`LinkContext` (`labkit/context.py`) gives a provider: the two `Endpoint`s (node,
ns, overlay_ip, underlay_ip), consistent iface-name helpers
(`tun_iface`/`underlay_iface`/`wg_iface`), the MTU, prefix lengths, and the log
dir.

## 3. frame — `primitives/frame.py`

IP packet ⇄ length-prefixed link frame for **stream** carriers. `encode(pkt)`
prepends a 2-byte big-endian length; `Decoder().feed(chunk)` reassembles whole
packets across arbitrary chunk boundaries. Used by `filament` (the L2 stream is a
byte stream). `udp` doesn't need it (one packet per datagram).

## 4. route — `primitives/route.py`

The allowed-IPs / dest-IP→peer table (WireGuard's cryptokey-routing model).
`RouteTable.add(cidr, peer)` / `lookup(dst_ip)` with longest-prefix match;
`dst_ip_of(packet)` extracts the dst from a raw IPv4/IPv6 packet. Trivial for two
nodes, but makes the jump to >2 nodes a data change — and is exactly the table a
native `serve_tun` will need.

## 5. crypto — `primitives/crypto.py`

A declarative selector, NOT a crypto implementation. `validate(crypto, provider)`
rejects incoherent combinations; the carrier supplies the actual encryption:

| value | meaning | coherent with |
| --- | --- | --- |
| `none` | no lab-added crypto (lean on the carrier or run clear) | pipe, udp, filament |
| `wg-noise` | WireGuard Noise_IKpsk2 + ChaCha20-Poly1305 (carrier-native) | wg |
| `dtls` | DTLS provided by the carrier (filament's data channel) | filament |

## 6. fault — `primitives/fault.py`

Induce adverse conditions on a carrier's data-path iface (inside a netns; host
untouched). Recorded in the ledger so teardown clears the qdisc.

```python
fault.apply(ledger, ns, iface, kind, **params)   # kind: loss|latency|bandwidth|stall
fault.clear(ledger, ns, iface)
```
- `loss` (e.g. `percent=20`), `latency` (`delay=80ms` `[jitter=10ms]`),
  `bandwidth` (`rate=1mbit`) — via `tc netem`.
- **`stall`** — 100% loss: the iface stays **UP**, the carrier sees no close, but
  every packet vanishes. A frozen-but-"connected" tunnel — the exact failure the
  transport-resilience P0 work must detect and self-heal. `clear` lifts it.

## 7. probe — `probe/probe.py`

Drive + measure across the tunnel; all emit machine-readable dicts (`--json`).

| probe | what | key fields |
| --- | --- | --- |
| `ping` | reachability + RTT (retries for slow carriers) | `ok`, `loss_percent`, `rtt_ms` |
| `iperf` | throughput (starts iperf3 -s in the dest ns) | `ok`, `sent_mbps`, `received_mbps` |
| `curl` | app reachability (one-shot HTTP server in dest ns) | `ok`, `http_code`, `time_total_s` |
| `counters` | TUN packet/byte counters per node | `nodes.<n>.{rx,tx}` |

All probes target **overlay** IPs and run via `ip netns exec` — never the host.
