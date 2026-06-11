"""primitive 3 — frame: IP packet <-> link frame.

A length-prefixed framing so a stream/datagram carrier can carry discrete IP
packets without ambiguity. Shared by the udp carrier (datagram: one packet per
UDP payload, framing optional) and the filament carrier (STREAM: filament's L2
forward is a byte stream, so packets MUST be length-delimited).

Wire format (stream framing)::

    +--------+--------+==================+
    | len hi | len lo |   payload (len)  |
    +--------+--------+==================+

A 16-bit big-endian length prefix (max 65535 — far above any tunnel MTU). The SID
concept from filament's L2 lives one layer below us (the L2 stream already
demuxes); here a "frame" is exactly one IP packet.
"""

from __future__ import annotations

import struct
from typing import Iterator


HDR = struct.Struct("!H")  # 2-byte big-endian length


def encode(packet: bytes) -> bytes:
    """Length-prefix one IP packet for a stream carrier."""
    if len(packet) > 0xFFFF:
        raise ValueError(f"packet too large to frame: {len(packet)} bytes")
    return HDR.pack(len(packet)) + packet


class Decoder:
    """Incremental stream de-framer: feed bytes, yield whole packets.

    A stream carrier delivers arbitrary chunk boundaries; this reassembles them
    into exactly the packets that were ``encode``d, holding any partial frame
    until the rest arrives.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> Iterator[bytes]:
        self._buf.extend(chunk)
        while True:
            if len(self._buf) < HDR.size:
                return
            (plen,) = HDR.unpack_from(self._buf, 0)
            if len(self._buf) < HDR.size + plen:
                return
            start = HDR.size
            end = start + plen
            yield bytes(self._buf[start:end])
            del self._buf[:end]
