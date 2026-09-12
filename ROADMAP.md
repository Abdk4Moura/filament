# Filament roadmap

> **Status:** canonical priority backlog
> **Last reviewed:** 2026-09-07 against commit `3c6599f`
> **Rule:** this is the only ordered backlog. A design document is not an in-flight commitment; move work here only after its scope and evidence are verified.

## Now

No implementation item is asserted in flight from repository history alone. Add the next owner-approved, source-audited slice here before starting it.

## Next

1. **Make the local product interface real.** Turn the existing control-socket seam into a versioned, documented local API only after its contract and authorization boundary are approved. Source: [`docs/design-product-interface.md`](docs/design-product-interface.md).
2. **Choose and scope the next L2 transport slice.** Per-stream QUIC is proposal material, not an active implementation claim. Confirm its benefit and compatibility constraints before work begins. Source: [`docs/design-l2-perstream-quic.md`](docs/design-l2-perstream-quic.md).
3. **Continue cross-platform capability parity from measured failures.** Keep platform behavior behind portable adapters and extend capability CI with every user-facing capability change. Sources: [`docs/architecture/PLATFORM.md`](docs/architecture/PLATFORM.md) and [`docs/design-per-os-ci.md`](docs/design-per-os-ci.md).

## Backlog / exploration

- Edge signaling architecture
- Additional transport rungs (hole punching and direct-to-relay recovery)
- Enterprise asynchronous delivery
- UX nudges and command-surface simplification

These remain proposals. Their design documents state scope and status; they must not be presented as shipped functionality.

## Recently shipped

- WireGuard L3 module wiring and scoped route ceilings (#297, 2026-09-07)
- Startup and binary-footprint reduction (#296, 2026-09-05)
- Certificate renewal and unsafe exit-route guard (#295, 2026-09-03)
- Initial subnet-route support (#293, 2026-09-02)
- Same-owner fleet auto-mesh and sibling-send reliability (#291, 2026-09-01)
- Deterministic-core CI ratchet (#288, 2026-08-25)

For present implementation status, use [`docs/status/CURRENT.md`](docs/status/CURRENT.md). For release history, use [`CHANGELOG.md`](CHANGELOG.md).
