"""provider: udp — a raw-UDP userspace carrier over the veth underlay.

Each node runs a small relay (udp_relay.py) INSIDE its netns: TUN packets are
sent as UDP datagrams to the peer's underlay (veth) address and vice-versa. This
proves the lab works with a real socket hop and a userspace datapath (the same
shape the filament carrier uses), without any crypto — the honest middle ground
between the bare `pipe` and the encrypted `wg`/`filament` carriers.

Datapath (a -> b)::
    TUN-a -> udp_relay(a) --UDP veth--> udp_relay(b) -> TUN-b
"""

from __future__ import annotations

import os
import sys

from labkit import netns
from labkit.context import LinkContext
from providers import underlay


UDP_PORT = 51900


def up(ctx: LinkContext) -> None:
    underlay.establish(ctx)

    # The TUN is the data path for udp: address the overlay on it.
    for ep in ctx.endpoints:
        netns.addr_add(ep.ns, ctx.tun_iface(ep),
                       f"{ep.overlay_ip}/{ctx.overlay_prefixlen}")

    relay = os.path.join(os.path.dirname(__file__), "udp_relay.py")
    for ep in ctx.endpoints:
        peer = ctx.other(ep)
        pid = netns.spawn(
            [sys.executable, relay,
             "--tun", ctx.tun_iface(ep),
             "--local-ip", ep.underlay_ip,
             "--peer-ip", peer.underlay_ip,
             "--port", str(UDP_PORT)],
            ns=ep.ns, logfile=ctx.log(f"udp-relay-{ep.node}"))
        ctx.ledger.add("pid", str(pid), role=f"udp-relay-{ep.node}", ns=ep.ns)

        # route the peer's overlay /32 over this node's TUN
        netns.route_add(ep.ns, f"{peer.overlay_ip}/32", dev=ctx.tun_iface(ep))


def down(ctx: LinkContext) -> None:
    pass
