"""provider: pipe (a.k.a. veth) — the zero-magic local baseline.

The simplest possible carrier: a veth pair directly joins the two namespaces, and
the overlay (TUN) subnet is routed straight over it. No userspace relay, no
crypto, no framing — the kernel forwards. This proves the topology engine + the
tun + route + probe primitives end to end with nothing else in the way.

Note: with `pipe` the TUN ifaces are addressed but the actual data path is the
veth (overlay routed onto it). We could skip TUN entirely for pipe, but we DO
create the TUNs so the same topology/probe targets (the overlay IPs) work
identically across all providers — only the carriage underneath changes. The
overlay IP is assigned to BOTH the tun and reachable via the veth route, so a
ping to the peer's overlay IP succeeds.

Carrier mechanism: we put each node's overlay IP on its veth end (so the overlay
subnet is on-link over the veth) AND keep the TUN for parity. The route primitive
points the peer's overlay IP at the veth.
"""

from __future__ import annotations

from labkit import netns
from labkit.context import LinkContext
from providers import underlay


def up(ctx: LinkContext) -> None:
    # 1) the underlay veth (also the data path for pipe).
    underlay.establish(ctx)

    # 2) put each node's OVERLAY address on its veth end (the engine creates the
    #    TUN bare), so the overlay subnet is directly on-link across the veth — a
    #    ping to the peer's overlay IP is answered by the peer's veth.
    for ep in ctx.endpoints:
        veth = ctx.underlay_iface(ep)
        netns.addr_add(ep.ns, veth, f"{ep.overlay_ip}/{ctx.overlay_prefixlen}")

    # 3) route: peer's overlay IP is reachable on the veth (on-link, so no
    #    explicit route needed — the on-link prefix covers it). Recorded for the
    #    route model's sake.
    ctx.ledger.set_meta("pipe_path", "veth (kernel-forwarded)")


def down(ctx: LinkContext) -> None:
    # Nothing provider-specific: the ledger sweep removes the veth + netns.
    pass
