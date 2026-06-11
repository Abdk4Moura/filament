"""Unit tests for the lab's pure logic (no root, no netns needed).

Run: python3 -m pytest lab/tests/test_unit.py   (or: python3 lab/tests/test_unit.py)
These cover the parts that don't touch the host: the YAML-subset parser, the
frame codec, the route table, crypto coherence, and the state ledger. The
namespace/end-to-end behaviour is covered by tests/test_e2e.sh (needs root).
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from primitives import frame, route, crypto  # noqa: E402
from labkit import topology, state  # noqa: E402


def test_frame_roundtrip():
    pkts = [b"", b"a", b"hello world", bytes(range(256)) * 4]
    enc = b"".join(frame.encode(p) for p in pkts)
    dec = frame.Decoder()
    got = []
    # feed in awkward chunk boundaries to exercise reassembly
    for i in range(0, len(enc), 7):
        got.extend(dec.feed(enc[i:i + 7]))
    assert got == pkts, "frame decode must reassemble exactly what was encoded"


def test_frame_partial_held():
    dec = frame.Decoder()
    enc = frame.encode(b"abcdef")
    assert list(dec.feed(enc[:3])) == []      # partial header/body held
    assert list(dec.feed(enc[3:])) == [b"abcdef"]


def test_route_longest_prefix():
    rt = route.RouteTable()
    rt.add("10.0.0.0/8", "peerA")
    rt.add("10.50.0.0/24", "peerB")
    assert rt.lookup("10.50.0.9") == "peerB"   # more specific wins
    assert rt.lookup("10.1.2.3") == "peerA"
    assert rt.lookup("8.8.8.8") is None


def test_route_dst_ip_v4():
    # minimal IPv4 header with dst = 10.50.0.2
    hdr = bytes([0x45, 0, 0, 20] + [0] * 12 + [10, 50, 0, 2])
    assert route.dst_ip_of(hdr) == "10.50.0.2"


def test_crypto_coherence():
    crypto.validate("none", "pipe")
    crypto.validate("wg-noise", "wg")
    crypto.validate("none", "filament")
    crypto.validate("dtls", "filament")
    for bad in [("wg-noise", "pipe"), ("dtls", "wg"), ("bogus", "pipe")]:
        try:
            crypto.validate(*bad)
            assert False, f"{bad} should be rejected"
        except ValueError:
            pass


def test_yaml_subset_parser():
    text = (
        "name: t\n"
        "subnet: 10.50.0.0/24\n"
        "defaults:\n"
        "  mtu: 1380\n"
        "nodes:\n"
        "  a:\n"
        "    addr: 10.50.0.1\n"
        "  b:\n"
        "    addr: 10.50.0.2\n"
        "link:\n"
        "  provider: pipe\n"
        "  endpoints: [a, b]\n"
        "  transport_subnet: 10.77.0.0/24\n"
    )
    topo = topology.from_dict(topology.load_text(text, "yaml"))
    assert topo.name == "t"
    assert topo.subnet == "10.50.0.0/24"
    assert [n.name for n in topo.nodes] == ["a", "b"]
    assert topo.node("a").addr == "10.50.0.1"
    assert topo.node("a").params["mtu"] == 1380   # default merged
    assert topo.link.provider == "pipe"
    assert topo.link.endpoints == ["a", "b"]
    assert topo.link.transport_subnet == "10.77.0.0/24"


def test_ledger_record_and_reverse():
    with tempfile.TemporaryDirectory() as d:
        # point the ledger at a temp dir
        state.STATE_DIR = __import__("pathlib").Path(d)
        led = state.Ledger("unit")
        led.add("netns", "lab-unit-a")
        led.add("tun", "labtun-a", ns="lab-unit-a")
        led.add("pid", "12345", role="relay")
        # idempotent re-add updates, not duplicates
        led.add("tun", "labtun-a", ns="lab-unit-a")
        kinds = [r["kind"] for r in led.resources()]
        assert kinds == ["netns", "tun", "pid"]
        rev = [r["kind"] for r in led.resources_reversed()]
        assert rev == ["pid", "tun", "netns"], "teardown order is reverse"
        # persistence roundtrip
        led2 = state.Ledger("unit")
        assert len(led2.resources()) == 3


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok   {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa
            failed += 1
            print(f"  ERR  {fn.__name__}: {e!r}")
    print(f"{len(fns) - failed}/{len(fns)} unit tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
