# Topology schema reference

A topology is a small **YAML** (or JSON) file under `lab/topologies/` describing
nodes + links + per-node params. It is **provider-agnostic**: it says *what* to
connect; the carrier (*how*) is chosen at `up` time via `--link` (or the link's
own `provider:`). Parsed by a tiny built-in YAML-subset parser (PyYAML used if
installed); JSON is always accepted.

## Full shape

```yaml
name: two-nodes                # REQUIRED. Lab name + ledger key (.state/<name>.json).
subnet: 10.50.0.0/24           # REQUIRED. OVERLAY subnet — the TUN addresses the
                               #   probes target. `ping <peer overlay ip>` is the
                               #   test that the carrier works as an L3 path.
defaults:                      # OPTIONAL. Merged UNDER each node's own params.
  mtu: 1380                    #   (per-node keys override these.)
nodes:                         # REQUIRED. A mapping of node-name -> params.
  a:
    addr: 10.50.0.1            #   REQUIRED per node: its overlay IP (no prefix).
    mtu: 1380                  #   OPTIONAL per-node override of a default.
  b:
    addr: 10.50.0.2
link:                          # REQUIRED. The carrier between two endpoints.
  provider: pipe               #   DEFAULT carrier; override at runtime with
                               #   `lab up <topo> --link pipe|udp|wg|filament`.
  endpoints: [a, b]            #   Exactly two node names today.
  transport_subnet: 10.77.0.0/24   # UNDERLAY subnet — the carrier's own endpoint
                               #   addresses (veth / UDP / WireGuard endpoints).
                               #   Must NOT overlap `subnet`.
  crypto: none                 #   OPTIONAL. none | wg-noise | dtls. Defaults per
                               #   provider (pipe/udp/filament -> none; wg ->
                               #   wg-noise). Validated for coherence with the
                               #   carrier.
```

## Field reference

| field | required | meaning |
| --- | --- | --- |
| `name` | yes | lab name; also the `.state/<name>.json` ledger key and the netns prefix `lab-<name>-<node>`. |
| `subnet` | yes | overlay (tunnel) CIDR. Node `addr`s must fall inside it. |
| `defaults` | no | a map merged under every node's params (per-node keys win). |
| `nodes` | yes | map of `name -> { addr, ...params }`. `addr` (overlay IP, no prefix) is required per node. A list form `[{name: a, addr: ...}]` is also accepted. |
| `nodes.<n>.mtu` | no | overlay-iface MTU (default 1380; 1280 recommended for `filament` to leave framing headroom). |
| `link.provider` | no | default carrier; `pipe` if omitted. Override with `--link`. |
| `link.endpoints` | no | the two node names to connect; defaults to the first two nodes. |
| `link.transport_subnet` | no | underlay CIDR (default `10.77.0.0/24`). Keep distinct per concurrent lab. |
| `link.crypto` | no | `none` \| `wg-noise` \| `dtls`; defaults per provider. |

## Addressing planes

- **overlay** (`subnet`) — what you ping. Assigned to the data-path iface (TUN
  for udp/filament; veth for pipe; wg iface for wg).
- **underlay** (`transport_subnet`) — the carrier's transport endpoints. The
  engine derives `.1` and `.2` from this subnet for endpoints `a` and `b`.

## Bundled topologies

| file | default carrier | notes |
| --- | --- | --- |
| `two-nodes.yml` | `pipe` | the canonical baseline; run with any `--link`. |
| `wg-pair.yml` | `wg` | ready-made WireGuard example (`crypto: wg-noise`). |
| `filament-l3.yml` | `filament` | the integration target; `mtu: 1280`, `crypto: none`. |

## Validation & errors

- A node without `addr` is rejected.
- `crypto` incoherent with the carrier is rejected (e.g. `wg-noise` on `pipe`,
  `dtls` on `wg`) — the lab does not synthesize crypto the carrier can't provide.
- `up` runs `lab doctor` for the chosen carrier first and aborts with install
  hints on a fatal miss (override with `--no-doctor`, not recommended).
