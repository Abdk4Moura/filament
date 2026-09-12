# Current project state

> **Status:** canonical current-state index  
> **Last verified:** 2026-09-07 against commit `3c6599f`  
> **Authority:** this file states only source-audited present state. `ROADMAP.md` is the priority backlog; designs are not implementation claims.

## Product

Filament is a peer-to-peer device-connectivity system. A React/WebRTC browser peer, a Flask + Socket.IO signaling service, and the Rust CLI share the protocol. The server coordinates peers; file and interactive data are intended to travel peer-to-peer.

The CLI package is `filament-cli` **0.8.5**. Its scope includes transfers, pairing, device identity and capabilities, shell/PTY, port forwarding, mounts, direct QUIC transport, and an L3 overlay. Focused Rust crates hold shared transport, protocol, transfer, pairing, identity, capability, overlay, fleet, and secure-storage code.

## Recently verified changes

- **WireGuard L3 wiring:** commit `3c6599f` wires the previously uncalled WireGuard module and carries route-ceiling scope.
- **Footprint/startup:** commit `cf5f896` records measurements and reduces binary/startup cost.
- **Certificate renewal and exit-route safety:** commit `2f434b0`.
- **Subnet routes:** commits `452356f`, `2f434b0`, and `3c6599f` complete signed route advertisement, scoped route authorization, kernel forwarding/NAT, withdrawal cleanup, and real-machine end-to-end evidence. See `docs/design-subnet-routes.md`.
- **Fleet auto-mesh:** commit `1271f83` adds same-owner device mesh behavior and reliable sibling sends.
- **Capability CI:** commit `96de120` ratchets deterministic core checks; GitHub workflows cover browser, capability, mount, proof, release, and platform test paths.

## Current boundaries

- `CONTRACT.md` is the normative cross-component protocol/UI contract. It describes shipped interoperable behavior only.
- `ROADMAP.md` is the sole ordered backlog. A roadmap item is not proof that work exists in the tree.
- `docs/design*/` contains proposals and implementation records. Read each document's status before relying on it.
- `docs/cli-resilience.md` and `docs/resilience.md` are failure ledgers; their named gates are the evidence for verified fixes.
- Product-specific compute/GPU work is intentionally outside Filament core; `docs/design-product-interface.md` remains a design for the local product interface.

## Open design directions

These are not active implementation claims: the versioned local product interface, per-stream L2 QUIC, edge signaling, enterprise async delivery, and expanded transport rungs remain design/proposal material unless a document explicitly records a landed change.

## Historical records

Session handoffs, investigations, completed plans, and previous work-state material live under `docs/archive/`. They preserve rationale and evidence but are not current instructions. Use `docs/README.md` to navigate the documentation and its authority levels.
