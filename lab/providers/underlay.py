"""underlay — a veth pair joining the two endpoint namespaces.

The shared "wire" the udp and wg carriers run their transport over (and which the
pipe carrier uses directly as the data path). One veth pair: one end in each
node's netns, addressed from the topology's ``transport_subnet``. This is purely
the lab's private underlay between two namespaces — it is created inside lab
namespaces and never touches host networking.
"""

from __future__ import annotations

from labkit import netns
from labkit.context import LinkContext, Endpoint


def establish(ctx: LinkContext) -> None:
    """Create + address the veth pair between ctx.a and ctx.b. Idempotent."""
    a_if = ctx.underlay_iface(ctx.a)
    b_if = ctx.underlay_iface(ctx.b)

    netns.veth_add(a_if, ctx.a.ns, b_if, ctx.b.ns)
    ctx.ledger.add("veth", a_if, ns=ctx.a.ns, peer=b_if, peer_ns=ctx.b.ns)

    for ep, iface in ((ctx.a, a_if), (ctx.b, b_if)):
        netns.addr_add(ep.ns, iface,
                       f"{ep.underlay_ip}/{ctx.transport_prefixlen}")
        netns.nsx(ep.ns, "ip", "link", "set", iface, "mtu", "1500")
        netns.link_up(ep.ns, iface)


def iface_of(ctx: LinkContext, ep: Endpoint) -> str:
    return ctx.underlay_iface(ep)
