"""primitive 1 — tun: a TUN iface in a node's netns, addressed on the overlay.

Interface:
    create(ledger, ns, iface, addr_cidr, mtu) -> None
        Create the TUN iface inside ``ns``, assign ``addr_cidr`` (e.g.
        10.50.0.1/24), set MTU, bring it up. Records the tun in the ledger so
        teardown removes it (and the netns deletion is the backstop). Idempotent.

A TUN device is the L3 endpoint: anything written to its fd appears as an inbound
IP packet on ``iface``, and any packet routed to ``iface`` is readable from the
fd. The carrier (udp/filament providers) owns that fd via tun_io.py; the pipe and
wg carriers instead route real kernel traffic and never touch the fd.

For reading/writing raw packets from Python (the udp + filament userspace
carriers) see ``tun_io.py``.
"""

from __future__ import annotations

from labkit import netns


def create(ledger, ns: str, iface: str, addr_cidr: str = None,
           mtu: int = 1380) -> None:
    """Create + bring up a TUN iface; optionally address it on the overlay.

    ``addr_cidr`` is OPTIONAL: only carriers that use the TUN as the actual data
    path (udp, filament) address the overlay here. Carriers whose data path is a
    different iface (pipe -> veth, wg -> wg iface) create the TUN bare so its
    (carrier-less, DOWN) presence never wins a competing on-link route to the
    real path. Idempotent.
    """
    netns.tun_add(ns, iface)
    ledger.add("tun", iface, ns=ns)
    if addr_cidr:
        netns.addr_add(ns, iface, addr_cidr)
    netns.nsx(ns, "ip", "link", "set", iface, "mtu", str(mtu))
    netns.link_up(ns, iface)
