"""providers/ — pluggable LINK carriers between two lab nodes.

A provider is the netlab-style abstraction: the topology is provider-agnostic and
says only "carry the overlay between node a and node b"; the provider decides HOW
the bytes move. The SAME two-node topology runs over any provider, so they can be
compared side by side (`lab up two-nodes --link pipe|wg|filament`).

Each provider implements two functions::

    def up(ctx: LinkContext) -> None     # establish the carrier; record resources
    def down(ctx: LinkContext) -> None   # provider-specific teardown (optional;
                                         # the ledger sweep is the backstop)

`up` is responsible for getting an IP packet that enters node-a's tunnel to come
out of node-b's tunnel and vice-versa. The four providers differ only in the
"middle":

  pipe   — a veth pair joins the two netns directly; the TUN packets are routed
           over the veth. Zero magic; the baseline that proves tun+route+probe.
  udp    — a userspace UDP relay (frame.py) carries TUN packets between the netns
           over a veth underlay. Proves the frame primitive + a real socket hop.
  wg     — a real WireGuard tunnel between the two netns (kernel datapath, or a
           userspace wireguard-go/boringtun fallback). Proves the provider
           abstraction against production-grade crypto carriage.
  filament — filament's data channel as the carrier. Since native serve_tun (L3)
           does NOT exist yet, this tunnels the TUN packets over an existing
           filament L2 forward/netcat stream between two isolated filament
           identities. The integration target; clearly marked as an approximation.

All four share the tun + route + frame + (optionally) fault primitives.
"""

from providers import pipe, udp, wg, filament  # noqa: F401

REGISTRY = {
    "pipe": pipe,
    "veth": pipe,      # alias
    "udp": udp,
    "wg": wg,
    "filament": filament,
}


def get(name: str):
    if name not in REGISTRY:
        raise KeyError(
            f"unknown link provider {name!r}; choose one of "
            f"{', '.join(sorted(set(REGISTRY)))}")
    return REGISTRY[name]
