# filament networking dev-lab (`lab/`)

A careful, reproducible **"lab as code"** for developing and testing filament's
networking — built immediately to develop **L3** (an IP-level tunnel: a TUN
device whose packets ride filament's data channel) but designed as a general
place to build smaller networking things too.

Nodes are **Linux network namespaces** on this one host (no cloud, no
containers). Links between nodes are **pluggable providers**. The same topology
runs over a bare veth, a real WireGuard tunnel, or filament's data channel — so
you can compare them side by side.

> **Status:** baseline proven. The *same* `two-nodes` topology pings across
> `pipe`, `wg`, **and** `filament` links (see [Proof](#proof)). Teardown is
> leak-free; a `doctor` preflight gates each carrier.

---

## What's netlab-inspired (and what we deliberately did NOT take)

We borrowed the good ideas from [netlab](https://netlab.tools) and reimplemented
them lightly — **no Ansible, no containers, no cloud, stdlib Python + standard
net tools only**:

| netlab idea we adopted | how the lab does it |
| --- | --- |
| Declarative **topology-as-code** | `topologies/*.yml`: nodes + links + per-node params, with `defaults` + overrides. `lab up <topology>` realizes it; `lab down` destroys it. Idempotent + reproducible. |
| **Provider / abstraction split** | the topology is provider-agnostic; the *link* between two nodes is a pluggable provider (`providers/`). `lab up two-nodes --link pipe\|udp\|wg\|filament`. |
| **Defaults + overrides, labels, clean lifecycle** | `defaults:` merge under per-node params; everything is `lab-`-prefixed; `up`/`down`/`status`/`probe` are the lifecycle. |

We did **not** depend on netlab itself, nor adopt its Ansible provisioning,
multi-VM/clos fabric machinery, or container providers — overkill for a
two-namespace dev lab on one host.

---

## The network-namespace model

Each **node** is an `ip netns` — a "machine" on this host with its own
interfaces, addresses, routes, and processes. Two (or more) nodes live on one
host. There are two addressing planes:

- **overlay** (`subnet:`, e.g. `10.50.0.0/24`) — the TUN/tunnel addresses the
  probes target. `ping 10.50.0.2` is the test that the carrier works as an L3
  path.
- **underlay** (`transport_subnet:`, e.g. `10.77.0.0/24`) — the carrier's own
  endpoint addresses (the veth/UDP/WireGuard endpoints).

**Safety invariant (enforced, not aspirational):** the lab **never modifies host
networking**. Every interface/address/route/qdisc lives inside a lab-created
namespace (run via `ip netns exec`). The only host-namespace operations are
`ip netns add/del` and creating a veth pair that is *immediately* moved into the
lab namespaces. The lab never touches the running `filament up` daemon, the
installed `~/.local/bin/filament`, `~/.config/filament`, the live site, or the
live T4. The `filament` link uses the **locally-built**
`cli/target/release/filament` and **fully isolated** `FILAMENT_CONFIG_DIR`
identities.

---

## The 7 composable primitives

Each is a small module with a documented interface (`primitives/`,
`providers/`, `probe/`).

1. **tun** (`primitives/tun.py`) — create a TUN iface in a node's netns, address
   it on the overlay, bring it up. `tun_io.py` reads/writes raw IP packets from
   the fd (the userspace carriers use this).
2. **link** (`providers/`) — the carrier between two endpoints, a **pluggable
   provider**:
   - `pipe` (a.k.a. `veth`) — a veth pair directly joins the two namespaces;
     zero-magic local baseline.
   - `udp` — a userspace UDP relay carries TUN packets over the veth underlay
     (proves the frame primitive + a real socket hop).
   - `wg` — a **real WireGuard** tunnel between the namespaces (kernel datapath
     if the module is present, else `wireguard-go`/`boringtun` userspace).
   - `filament` — **filament's data channel as the carrier** (the integration
     target — see [below](#the-filament-link-today-vs-the-serve_tun-target)).
3. **frame** (`primitives/frame.py`) — IP packet ⇄ length-prefixed link frame;
   shared by the udp and filament stream carriers.
4. **route** (`primitives/route.py`) — the allowed-IPs table: dest IP → peer
   (WireGuard's cryptokey-routing model), longest-prefix match.
5. **crypto** (`primitives/crypto.py`) — a declarative selector: `none` |
   `wg-noise` | `dtls`. The lab does **not** roll its own crypto; this records
   *which layer* provides confidentiality and validates it against the carrier
   (e.g. `filament` ⇒ `none`, because the data channel is already DTLS +
   pair-proof).
6. **fault** (`primitives/fault.py`) — induce `loss` / `latency` / `bandwidth`
   (tc netem) and especially **`stall`** (100% loss: freeze the data path while
   the link stays "up" — the exact failure mode the transport-resilience P0 work
   must detect + self-heal). Applied to the carrier's real data-path iface.
7. **probe** (`probe/probe.py`) — drive + measure across the tunnel: `ping`,
   `iperf3`, `curl`, and TUN packet/byte `counters`. Emits machine-readable JSON
   (`--json`).

---

## Topology schema

See [`resources/topology-schema.md`](resources/topology-schema.md) for the full
reference. In brief:

```yaml
name: two-nodes              # lab name (also the ledger key)
subnet: 10.50.0.0/24         # OVERLAY subnet (the TUN addresses probes target)
defaults:                    # merged under every node unless overridden
  mtu: 1380
nodes:
  a: { addr: 10.50.0.1 }     # per-node overrides
  b: { addr: 10.50.0.2 }
link:
  provider: pipe             # default carrier (override with `up --link`)
  endpoints: [a, b]          # exactly two nodes today
  transport_subnet: 10.77.0.0/24   # UNDERLAY addrs (veth/udp/wg endpoints)
  crypto: none               # optional; defaults per provider
```

YAML is parsed by a tiny built-in subset parser (no PyYAML required; used if
present). JSON topologies are also accepted.

Bundled topologies (`topologies/`): `two-nodes` (the baseline, any `--link`),
`wg-pair` (wg by default), `filament-l3` (filament by default).

---

## Usage

```bash
lab/lab doctor --link wg            # preflight: root, modules, tools (per carrier)
lab/lab list                       # topologies + running labs
lab/lab compose two-nodes --link wg  # preview what `up` will create (no changes)

sudo lab/lab up two-nodes --link pipe        # realize it
sudo lab/lab probe ping two-nodes            # ping across the tunnel
sudo lab/lab probe iperf two-nodes           # throughput
sudo lab/lab status                          # what's up, which processes
sudo lab/lab fault stall two-nodes           # freeze the data path (link stays up)
sudo lab/lab fault clear two-nodes           # lift it
sudo lab/lab down two-nodes                  # robust teardown
sudo lab/lab down --all --purge-logs         # tear down everything + sweep strays
```

Add `--json` to any command for machine-readable output (the `/lab` Claude skill
relies on this). Run the same topology with `--link pipe|udp|wg|filament` to
compare carriers side by side.

You can drive the lab three ways: the **`lab` CLI** (`lab/lab`), the
**`/lab` Claude skill** (`lab/skill/SKILL.md`, installed to
`~/.claude/skills/lab/`), or the Python engine directly
(`PYTHONPATH=lab python3 -m labkit.cli ...`).

---

## Safety, idempotency & teardown

- **Root** is required for netns/tun/wg. `lab doctor` (and every `up`) checks it
  and fails with a clear message + install hints for any missing tool/module. A
  userspace WireGuard fallback is documented when the kernel module is absent.
- **Idempotent `up`:** re-running is safe (existing namespaces/addresses are
  reused, not duplicated).
- **Robust teardown:** every host resource the lab creates (netns, veth, tun, wg
  iface, spawned PID, tc qdisc, scratch file) is recorded in a per-lab ledger
  under `.state/<lab>.json` *as it is created*. `down` walks the ledger in
  reverse and destroys everything — **even after a crashed/partial `up`**.
  Deleting a netns frees any iface still inside it (the backstop). `down --all`
  additionally sweeps any stray `lab-`-prefixed namespace or host-ns iface even
  with no ledger. **No leaks** — proven by the e2e leak-check after every
  carrier.

---

## The filament link: today vs the `serve_tun` target

**Native `filament serve_tun` (L3) does not exist yet — building it is the whole
point of this lab.** So the `filament` provider today is a **first
approximation**: it tunnels the TUN's IP packets over an existing filament **L2
forward/netcat stream** between two isolated filament identities.

Datapath today (`a → b`):

```
TUN-a (node-a ns)
  → fil_relay(connect)  --TCP 127.0.0.1:LPORT (host ns)-->
  → `filament forward LPORT labB RPORT`   (isolated config A, host ns)
  ==[ filament DATA CHANNEL / L2 stream ]==>
  → `filament up` acceptor   (isolated config B, host ns, FILAMENT_L2=1)
  → dials 127.0.0.1:RPORT
  → fil_relay(listen)
  → TUN-b (node-b ns)
```

The two filament endpoints run in the **host** netns (they need outbound
signaling); the TUN fds are opened by the relays via `setns` into the node
namespaces, so **no veth-to-host is created** and host networking is untouched.
The two identities are fully isolated (`FILAMENT_CONFIG_DIR=.state/logs/<lab>/fil-{A,B}`),
pre-seeded with a shared pair secret, and never see `~/.config/filament` or the
running daemon.

> **`TODO(serve_tun)`** — replace the whole TCP-stream hop (`forward` + two
> relays + framing) with a native `filament serve_tun` that reads/writes IP
> packets on the data channel directly. When that lands, this provider collapses
> to "create TUN in each netns; run `serve_tun` on each side" and the same
> `filament-l3` topology runs over it unchanged. This provider is the scaffold
> and the integration test for that work.

**Honest note / a real finding:** on this single host, two isolated filament
identities connecting to *each other's loopback* over `direct-quic` exhibit
periodic link **flapping** ("direct connection closed" every few seconds). The
lab works around it (the acceptor gets a signaling head-start so the *first*
link comes up; the relays reconnect; the probe retries) and the ping reliably
succeeds — but the flap itself is exactly the kind of instability the
transport-resilience P0 work targets, now reproducible on demand in the lab.

---

## Proof

The same `two-nodes` topology, pinged across all three required carriers
(captured from this host; RTT rises with each layer — exactly the comparison the
lab is for):

```
========== lab up two-nodes --link pipe ==========
[OK] ping a->b    loss=0.0%  rtt avg=0.06ms

========== lab up two-nodes --link wg ==========
[OK] ping a->b    loss=0.0%  rtt avg=0.31ms      (real WireGuard, kernel datapath)

========== lab up two-nodes --link filament ==========
[OK] ping a->b    loss=0.0%  rtt avg=1.21ms      (filament data channel, direct-quic)

FINAL LEAK CHECK: netns=0  host-ifaces=0  relays=0
```

Throughput (`lab probe iperf two-nodes`): pipe ≈ 19 Gbps, wg ≈ 1.46 Gbps,
filament ≈ 0.45 Gbps — the carrier cost is visible end to end.

`stall` demonstrated: under `lab fault stall`, ping fails (frozen path, link
still "up"); `lab fault clear` restores it.

---

## Tests

```bash
python3 lab/tests/test_unit.py          # pure logic: frame/route/crypto/yaml/ledger (no root)
sudo lab/tests/test_e2e.sh              # all carriers up→ping→stall→down, asserts NO leaks
sudo lab/tests/test_e2e.sh "pipe wg"    # a subset
```

---

## Dependencies

Light by design: **bash + Python 3 stdlib** + standard net tools —
`iproute2` (`ip`, `tc`), `iputils-ping`, and per-carrier: `wireguard-tools`
(+ kernel `wireguard` module *or* `wireguard-go`/`boringtun`) for `wg`,
`iperf3` for the throughput probe, `curl` for the curl probe, and the
locally-built `cli/target/release/filament` for the `filament` link. `lab
doctor` reports exactly what's present/missing with install hints.

---

## Layout

```
lab/
  lab                  the CLI entrypoint (bash → labkit.cli)
  README.md            this file
  labkit/              the engine (stdlib Python)
    state.py           the resource ledger (safe teardown)
    netns.py           audited, namespace-scoped ip/tc/wg wrappers
    topology.py        topology-as-code (+ tiny YAML-subset parser)
    context.py         the LinkContext handed to providers
    engine.py          realize (up) / destroy (down) lifecycle
    doctor.py          preflight checks
    cli.py             the argparse front-end
  primitives/          tun, tun_io, frame, route, crypto, fault
  providers/           pipe, udp, wg, filament (+ underlay, relays)
  probe/               ping / iperf3 / curl / counters
  topologies/          two-nodes.yml, wg-pair.yml, filament-l3.yml
  resources/           topology schema, primitives reference, safety runbook
  skill/               the /lab Claude skill (SKILL.md)
  tests/               test_unit.py, test_e2e.sh
  .state/              per-lab ledgers + logs (runtime; git-ignored)
```
