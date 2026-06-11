"""fil_relay.py — the userspace TUN<->TCP bridge for the `filament` carrier.

Run as a standalone process (one per node), spawned by the filament provider. It
bridges ONE node's TUN device to a TCP socket; filament's L2 forward/netcat moves
the TCP bytes between the two nodes' relays. Length-prefix framing (primitive
`frame`) delimits packets on the byte stream.

Why a separate process / why setns: the TUN fd must be opened INSIDE the node's
netns, but the TCP socket must reach the filament processes in the HOST netns
localhost. So this process opens the TUN by momentarily entering the node netns
(setns), then does its socket I/O in the host netns. No veth-to-host, so host
networking is never modified.

Two roles:
  --role listen  : bind 127.0.0.1:<port> and accept ONE connection (node-b side;
                   filament's `up` acceptor dials this as the forward target).
  --role connect : connect to 127.0.0.1:<port> (node-a side; filament `forward`
                   listens there).

This is the L2-FORWARD APPROXIMATION of an L3 filament tunnel. The TODO is to
replace the whole TCP-stream hop with a native `filament serve_tun` that carries
IP packets directly on the data channel (see lab/README.md).
"""

from __future__ import annotations

import argparse
import ctypes
import os
import select
import socket
import sys
import time

# Make sibling primitives importable when run as a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from primitives import frame, tun_io  # noqa: E402

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
CLONE_NEWNET = 0x40000000


def _setns(ns_name: str) -> None:
    fd = os.open(f"/var/run/netns/{ns_name}", os.O_RDONLY)
    try:
        if _libc.setns(fd, CLONE_NEWNET) != 0:
            e = ctypes.get_errno()
            raise OSError(e, f"setns({ns_name}): {os.strerror(e)}")
    finally:
        os.close(fd)


def open_tun_in_ns(ns_name: str, iface: str) -> int:
    """Open the TUN fd inside ``ns_name``, then return to the host netns."""
    host_fd = os.open("/proc/1/ns/net", os.O_RDONLY)  # host (init) netns
    try:
        _setns(ns_name)
        tun_fd = tun_io.open_tun(iface)
    finally:
        # Return to the host netns so subsequent sockets are host-local.
        if _libc.setns(host_fd, CLONE_NEWNET) != 0:
            e = ctypes.get_errno()
            os.close(host_fd)
            raise OSError(e, f"setns(host): {os.strerror(e)}")
        os.close(host_fd)
    return tun_fd


def _connect_with_retry(port: int, timeout: float = 30.0) -> socket.socket:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            return s
        except (ConnectionRefusedError, OSError):
            time.sleep(0.3)
    raise TimeoutError(f"could not connect to 127.0.0.1:{port}")


def _listen(port: int) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    return srv


def pump(tun_fd: int, sock: socket.socket) -> None:
    """Bridge: TUN packets -> framed -> socket; socket -> de-framed -> TUN."""
    sock.setblocking(False)
    dec = frame.Decoder()
    sock_fileno = sock.fileno()
    while True:
        r, _, _ = select.select([tun_fd, sock_fileno], [], [])
        if tun_fd in r:
            try:
                pkt = tun_io.read_packet(tun_fd, 2048)
            except OSError:
                break
            if pkt:
                try:
                    sock.sendall(frame.encode(pkt))
                except OSError:
                    break
        if sock_fileno in r:
            try:
                data = sock.recv(65535)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                break
            if not data:
                break
            for pkt in dec.feed(data):
                try:
                    tun_io.write_packet(tun_fd, pkt)
                except OSError:
                    break


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns", required=True, help="node netns holding the TUN")
    ap.add_argument("--tun", required=True, help="TUN iface name")
    ap.add_argument("--role", choices=["listen", "connect"], required=True)
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()

    # The TUN fd is opened ONCE and reused across reconnects. The filament L2
    # link can drop + re-establish (e.g. a transient direct-quic reconnect on
    # rapid bring-up); when it does, the local TCP socket dies and we must wire a
    # FRESH one to the new stream — keeping the TUN so the node never loses its
    # overlay endpoint. Hence the reconnect loop.
    tun_fd = open_tun_in_ns(args.ns, args.tun)
    srv = _listen(args.port) if args.role == "listen" else None
    try:
        while True:
            if args.role == "listen":
                try:
                    sock, _ = srv.accept()
                except OSError:
                    break
            else:
                try:
                    sock = _connect_with_retry(args.port, timeout=60.0)
                except TimeoutError:
                    break
            try:
                pump(tun_fd, sock)          # returns when this stream dies
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
            # loop back: re-accept / re-connect to the next stream incarnation.
    finally:
        if srv is not None:
            srv.close()
        os.close(tun_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
