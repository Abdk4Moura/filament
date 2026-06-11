"""context.py — the LinkContext handed to a provider's up()/down().

Bundles everything a carrier needs to establish itself between the two endpoint
nodes: the topology, the ledger, resolved namespace names, overlay (TUN) and
underlay (transport) addressing, and helpers to allocate the standard names so
every provider is consistent and teardown can find resources.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List

from labkit import netns
from labkit.state import Ledger
from labkit.topology import Topology


# Where the locally-built filament binary lives (filament provider uses it).
from labkit.doctor import FILAMENT_BIN  # noqa: F401  (re-export for providers)


@dataclass
class Endpoint:
    node: str           # node name (e.g. "a")
    ns: str             # its network namespace
    overlay_ip: str     # TUN address (no prefix)
    underlay_ip: str    # transport address (no prefix)


class LinkContext:
    def __init__(self, topo: Topology, ledger: Ledger, link_provider: str,
                 crypto: str, log_dir: str):
        self.topo = topo
        self.ledger = ledger
        self.provider = link_provider
        self.crypto = crypto
        self.log_dir = log_dir

        a_name, b_name = topo.link.endpoints[0], topo.link.endpoints[1]
        a, b = topo.node(a_name), topo.node(b_name)

        # Underlay (transport) addressing: derive .1/.2 from transport_subnet.
        tnet = ipaddress.ip_network(topo.link.transport_subnet, strict=False)
        hosts = list(tnet.hosts())
        ua, ub = str(hosts[0]), str(hosts[1])

        self.a = Endpoint(a_name, netns.ns_name(topo.name, a_name), a.addr, ua)
        self.b = Endpoint(b_name, netns.ns_name(topo.name, b_name), b.addr, ub)
        self.transport_prefixlen = tnet.prefixlen

    # ---- consistent name allocation -------------------------------------

    @property
    def overlay_prefixlen(self) -> int:
        return self.topo.prefixlen

    @property
    def mtu(self) -> int:
        return int(self.topo.node(self.a.node).params.get("mtu", 1380))

    def tun_iface(self, ep: Endpoint) -> str:
        # short, <=15 chars: labtun-a / labtun-b
        return f"labtun-{ep.node}"[:15]

    def underlay_iface(self, ep: Endpoint) -> str:
        # veth ends: labu-a / labu-b
        return f"labu-{ep.node}"[:15]

    def wg_iface(self, ep: Endpoint) -> str:
        return f"labwg-{ep.node}"[:15]

    @property
    def endpoints(self) -> List[Endpoint]:
        return [self.a, self.b]

    def other(self, ep: Endpoint) -> Endpoint:
        return self.b if ep is self.a else self.a

    def log(self, name: str) -> str:
        return f"{self.log_dir}/{name}.log"
