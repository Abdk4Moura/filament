---
name: lab
description: Drive the filament networking dev-lab — reproducible "lab as code" using Linux network namespaces. Bring up two-node topologies over pluggable link carriers (pipe/udp/wg/filament), ping/iperf/curl across the tunnel, inject loss/latency/stall faults, and tear down with no leaks. Use when the user wants to develop or test filament L3 (TUN-over-data-channel), compare a WireGuard vs filament data path, reproduce a stalled/flapping tunnel for transport-resilience work, or build small networking experiments on this host. Triggers: "the lab", "lab up", "spin up two nodes", "ping across the filament link", "test L3 / serve_tun", "wireguard vs filament", "stall the tunnel".
---

# lab — filament networking dev-lab

A reproducible **lab as code** (netlab-inspired, no heavy deps). Nodes are Linux
**network namespaces** on this host; links are **pluggable providers**. The same
topology runs over a bare veth, real WireGuard, or filament's data channel.

**Canonical CLI:** `lab/lab` (repo: `/root/stunning-tribble/lab`). This skill is a
symlink of `lab/skill/`; the source of truth is version-controlled in the repo.

Full reference: `/root/stunning-tribble/lab/README.md`. Resources:
`lab/resources/{topology-schema.md, primitives-reference.md, safety-runbook.md}`.

## When to use

- Develop/test filament **L3** (a TUN whose IP packets ride the data channel).
  The `filament` link is the integration target (today: an L2-forward
  approximation; the native `serve_tun` is what the lab is FOR).
- Compare link carriers side by side (`--link pipe|udp|wg|filament`).
- Reproduce adverse conditions (loss/latency/**stall**) for the
  transport-resilience P0 work.
- Build other small networking experiments in isolated namespaces.

## Hard safety rules (do not violate)

- **Root required** (netns/tun/wg). Run `lab` commands with `sudo` if not root.
- The lab **only** touches `lab-`-prefixed network namespaces. NEVER modify host
  networking, the running `filament up` daemon, the installed
  `~/.local/bin/filament`, `~/.config/filament`, the live site, or the live T4.
- The `filament` link uses the **locally-built** `cli/target/release/filament`
  and **isolated** `FILAMENT_CONFIG_DIR` identities only.
- Always `lab down` (or `lab down --all`) when finished — teardown is leak-free
  and idempotent.

## Commands (all accept `--json` for machine-readable output)

Run from the repo root; prefix with `sudo` if not already root.

```bash
lab/lab doctor [--link pipe|udp|wg|filament]   # preflight: root, modules, tools + hints
lab/lab list                                   # topologies + running labs
lab/lab compose <topology> [--link L]          # PREVIEW what `up` creates (no changes)

lab/lab up <topology> [--link L] [--crypto C] [--no-doctor]
lab/lab status [<lab>]
lab/lab probe <ping|iperf|curl|counters> [<lab>] [--count N] [--seconds S]
lab/lab fault <loss|latency|bandwidth|stall|clear> [<lab>] [value]
lab/lab down [<lab>] [--all] [--purge-logs]
```

- `<topology>`: a name under `lab/topologies/` (`two-nodes`, `wg-pair`,
  `filament-l3`) or a path to a YAML/JSON file.
- `--link`: override the carrier — `pipe` (veth baseline), `udp` (userspace UDP),
  `wg` (real WireGuard), `filament` (filament data channel).
- `fault value` examples: `lab fault loss two-nodes 20` (20%),
  `lab fault latency two-nodes delay=80ms`, `lab fault bandwidth two-nodes rate=1mbit`,
  `lab fault stall two-nodes` (freeze; link stays up), `lab fault clear two-nodes`.
- If exactly one lab is up, the `<lab>` arg is optional for probe/fault/down/status.

## The 7 primitives (compose / wire)

`tun` · `link` (the pluggable carrier) · `frame` (IP↔link frame) · `route`
(dest-IP→peer) · `crypto` (`none`/`wg-noise`/`dtls`) · `fault`
(loss/latency/bandwidth/**stall**) · `probe` (ping/iperf3/curl/counters). See
`lab/resources/primitives-reference.md`. `lab compose <topology>` shows how a
topology wires them before you realize it.

## Typical flows

Baseline + carrier comparison:
```bash
sudo lab/lab up two-nodes --link pipe && sudo lab/lab probe ping two-nodes
sudo lab/lab down two-nodes
sudo lab/lab up two-nodes --link wg   && sudo lab/lab probe ping two-nodes
sudo lab/lab down two-nodes
sudo lab/lab up two-nodes --link filament && sudo lab/lab probe ping two-nodes
sudo lab/lab down two-nodes
```

Demonstrate a stalled tunnel (transport-resilience):
```bash
sudo lab/lab up two-nodes --link filament
sudo lab/lab fault stall two-nodes      # ping now fails; link still "up"
sudo lab/lab probe ping two-nodes
sudo lab/lab fault clear two-nodes      # recovers
sudo lab/lab down two-nodes
```

Clean up anything left behind:
```bash
sudo lab/lab down --all --purge-logs    # tears down every lab + sweeps strays
```

## Notes for the assistant

- Prefer `--json` when you need to parse results (e.g. assert `ok: true`,
  read `rtt_ms.avg` or `received_mbps`).
- The `filament` carrier needs a few seconds to wire (data channel + relays);
  `up` waits for the path and `probe ping` retries. A first ping may still need
  a moment — re-run `probe ping` if it transiently fails.
- If `doctor` reports a missing tool/module, surface its install hint rather than
  forcing the carrier; offer a different `--link` if appropriate.
- Always tear down when done.
