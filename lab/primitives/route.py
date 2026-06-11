"""primitive 4 — route: the allowed-IPs / dest-IP -> peer table (the WG model).

WireGuard's central idea is *cryptokey routing*: each peer is associated with a
set of allowed source/dest IPs, and the dest IP of a packet selects the peer to
send it to. Our lab generalizes that to every carrier: given a packet read off a
TUN, which peer endpoint should carry it?

For the two-node case the table is trivial (everything that isn't ours goes to
the one peer), but modelling it explicitly (a) matches the WG mental model the
lab teaches, (b) makes the jump to >2 nodes a data change not a code change, and
(c) is exactly the table a future native ``serve_tun`` will need.

Interface:
    RouteTable.add(dest_cidr, peer) — route packets for dest_cidr to ``peer``.
    RouteTable.lookup(dst_ip)       — return the peer (opaque) for a dest IP.
"""

from __future__ import annotations

import ipaddress
from typing import Any, List, Optional, Tuple


class RouteTable:
    def __init__(self) -> None:
        # longest-prefix-match wins, so we keep them sorted by prefixlen desc.
        self._routes: List[Tuple[ipaddress._BaseNetwork, Any]] = []

    def add(self, dest_cidr: str, peer: Any) -> None:
        net = ipaddress.ip_network(dest_cidr, strict=False)
        self._routes.append((net, peer))
        self._routes.sort(key=lambda r: r[0].prefixlen, reverse=True)

    def lookup(self, dst_ip: str) -> Optional[Any]:
        try:
            ip = ipaddress.ip_address(dst_ip)
        except ValueError:
            return None
        for net, peer in self._routes:
            if ip in net:
                return peer
        return None


def dst_ip_of(packet: bytes) -> Optional[str]:
    """Extract the destination IP (v4 or v6) from a raw IP packet, or None."""
    if not packet:
        return None
    version = packet[0] >> 4
    try:
        if version == 4 and len(packet) >= 20:
            return ".".join(str(b) for b in packet[16:20])
        if version == 6 and len(packet) >= 40:
            import ipaddress as _ip
            return str(_ip.IPv6Address(packet[24:40]))
    except Exception:
        return None
    return None
