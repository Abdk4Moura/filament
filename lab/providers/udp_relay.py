"""udp_relay.py — userspace TUN<->UDP bridge for the `udp` carrier.

One process per node, run INSIDE the node's netns (so both the TUN and the UDP
socket live in the same netns, reachable over the veth underlay — no setns needed
here, unlike the filament relay). Reads IP packets from the TUN and sends each as
one UDP datagram to the peer's underlay address; receives UDP datagrams and
writes them to the TUN. One packet per datagram, so no length framing is required
(the datagram boundary IS the frame) — but we still cap at the MTU.
"""

from __future__ import annotations

import argparse
import os
import select
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from primitives import tun_io  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tun", required=True)
    ap.add_argument("--local-ip", required=True)
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--port", type=int, default=51900)
    args = ap.parse_args()

    tun_fd = tun_io.open_tun(args.tun)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.local_ip, args.port))
    sock.setblocking(False)
    peer = (args.peer_ip, args.port)

    while True:
        r, _, _ = select.select([tun_fd, sock.fileno()], [], [])
        if tun_fd in r:
            try:
                pkt = tun_io.read_packet(tun_fd, 2048)
            except OSError:
                break
            if pkt:
                try:
                    sock.sendto(pkt, peer)
                except OSError:
                    pass
        if sock.fileno() in r:
            try:
                data, _ = sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                break
            if data:
                try:
                    tun_io.write_packet(tun_fd, data)
                except OSError:
                    break
    os.close(tun_fd)
    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
