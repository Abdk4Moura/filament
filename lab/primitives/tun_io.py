"""tun_io — open a TUN iface fd and read/write raw IP packets (userspace path).

Used by the udp and filament carriers, whose relay process runs INSIDE a node's
netns (spawned via ``ip netns exec``) and attaches to the pre-created TUN iface
by name. Pure stdlib + ioctl; no external deps.

A TUN device hands us bare IP packets (no Ethernet header) because we set
IFF_TUN | IFF_NO_PI. ``read()`` returns one IP packet; ``write()`` injects one.
"""

from __future__ import annotations

import fcntl
import os
import struct

# linux/if_tun.h
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def open_tun(iface: str) -> int:
    """Open /dev/net/tun and attach to an EXISTING tun iface by name.

    The iface must already exist in the current netns (created by primitive
    `tun`). Returns a file descriptor delivering/accepting raw IP packets.
    """
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", iface.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


def read_packet(fd: int, mtu: int = 2048) -> bytes:
    return os.read(fd, mtu)


def write_packet(fd: int, pkt: bytes) -> int:
    return os.write(fd, pkt)
