#!/usr/bin/env python3
"""Reference codec and test vectors for the bootstrap card (`fc1`).

The normative text is CONTRACT.md, section "Bootstrap card (fc1)". This file
is the executable half of it: a small, dependency-light second implementation
whose only job is to produce fixtures the Rust implementation must reproduce
byte for byte, and to demonstrate that every refusal in the contract is a
refusal in practice rather than a sentence.

Why a second implementation at all: the card's signature is over BYTES, so
"deterministic CBOR" is not a style note, it is the wire. Two independent
encoders agreeing on those bytes is the only cheap evidence that the rule was
written precisely enough to implement twice. The CBOR encoder here is
deliberately minimal (the exact subset the card uses, nothing more) so it can
be read end to end in a minute.

Standard library only, plus `cryptography` IF it is installed:

  * installed  -> real Ed25519. The emitted vectors are usable as crypto
                  fixtures and `signature_backend` says "ed25519".
  * missing    -> a clearly marked PLACEHOLDER backend (SHA-512 of a tagged
                  message). Structure, canonical bytes, derivation, expiry,
                  class and size refusals are all still exercised and still
                  meaningful; the signature bytes are NOT Ed25519 and must not
                  be used to test a real verifier. `signature_backend` says
                  "placeholder-not-ed25519" and every vector repeats it.

Usage:

    python3 proofs/card_vectors.py            # run self-checks, write the JSON
    python3 proofs/card_vectors.py --check    # run self-checks, fail on drift

Runtime is a few milliseconds; there is no search here, only construction.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from base64 import urlsafe_b64decode, urlsafe_b64encode

# --------------------------------------------------------------------------
# Signature backend
# --------------------------------------------------------------------------

try:  # pragma: no cover - environment dependent
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    SIGNATURE_BACKEND = "ed25519"
except Exception:  # pragma: no cover - environment dependent
    Ed25519PrivateKey = None
    Ed25519PublicKey = None
    SIGNATURE_BACKEND = "placeholder-not-ed25519"

PLACEHOLDER_TAG = b"PLACEHOLDER-NOT-A-SIGNATURE/card_vectors.py\0"


def keypair_from_seed(seed: bytes) -> tuple[bytes, object]:
    """Return (public_key_bytes32, signer). Deterministic in both backends."""
    assert len(seed) == 32
    if SIGNATURE_BACKEND == "ed25519":
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = sk.public_key().public_bytes_raw()
        return pub, sk
    # Placeholder: the "public key" is a hash of the seed so it is still a
    # stable 32 bytes that the derivation can chew on.
    pub = hashlib.sha256(b"placeholder-pub/" + seed).digest()
    return pub, seed


def sign(signer: object, msg: bytes) -> bytes:
    if SIGNATURE_BACKEND == "ed25519":
        return signer.sign(msg)
    return hashlib.sha512(PLACEHOLDER_TAG + signer + msg).digest()


def verify_sig(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if SIGNATURE_BACKEND == "ed25519":
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except Exception:
            return False
    # Placeholder verification needs the seed, which a verifier does not have;
    # we recover it from the vector table instead. See PLACEHOLDER_SEEDS.
    seed = PLACEHOLDER_SEEDS.get(pub)
    if seed is None:
        return False
    return sig == hashlib.sha512(PLACEHOLDER_TAG + seed + msg).digest()


PLACEHOLDER_SEEDS: dict[bytes, bytes] = {}


# --------------------------------------------------------------------------
# Deterministic CBOR (RFC 8949 section 4.2.1 core deterministic encoding)
#
# Only the subset the card needs: unsigned ints, byte strings, text strings,
# arrays, maps. Definite lengths, shortest-form heads, map keys sorted by
# their ENCODED bytes. No tags, no floats, no indefinite lengths.
# --------------------------------------------------------------------------


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    raise ValueError("value too large for CBOR")


def cbor_encode(v: object) -> bytes:
    if isinstance(v, bool):
        raise TypeError("bool is not part of the card's CBOR subset")
    if isinstance(v, int):
        if v < 0:
            raise ValueError("negative integers are not used in cards")
        return _head(0, v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        items = [(cbor_encode(k), cbor_encode(val)) for k, val in v.items()]
        # Canonical ordering: bytewise over the ENCODED key. For the card's
        # text keys this is length-first, then lexicographic.
        items.sort(key=lambda kv: kv[0])
        if len({k for k, _ in items}) != len(items):
            raise ValueError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + val for k, val in items)
    raise TypeError(f"unsupported CBOR type: {type(v).__name__}")


class CborError(Exception):
    pass


def cbor_decode(buf: bytes) -> tuple[object, int]:
    """Decode one item. Returns (value, bytes_consumed). Strict subset."""
    if not buf:
        raise CborError("truncated")
    ib = buf[0]
    major, ai = ib >> 5, ib & 0x1F
    if ai < 24:
        n, off = ai, 1
    elif ai == 24:
        if len(buf) < 2:
            raise CborError("truncated head")
        n, off = buf[1], 2
        if n < 24:
            raise CborError("non-shortest int encoding")
    elif ai in (25, 26, 27):
        width = {25: 2, 26: 4, 27: 8}[ai]
        if len(buf) < 1 + width:
            raise CborError("truncated head")
        n, off = int.from_bytes(buf[1 : 1 + width], "big"), 1 + width
        bound = {25: 0x100, 26: 0x10000, 27: 0x100000000}[ai]
        if n < bound:
            raise CborError("non-shortest int encoding")
    else:
        raise CborError("indefinite length or unsupported additional info")

    if major == 0:
        return n, off
    if major == 2:
        if len(buf) < off + n:
            raise CborError("truncated byte string")
        return buf[off : off + n], off + n
    if major == 3:
        if len(buf) < off + n:
            raise CborError("truncated text string")
        return buf[off : off + n].decode("utf-8"), off + n
    if major == 4:
        out = []
        for _ in range(n):
            item, used = cbor_decode(buf[off:])
            out.append(item)
            off += used
        return out, off
    if major == 5:
        out = {}
        for _ in range(n):
            k, used = cbor_decode(buf[off:])
            off += used
            val, used = cbor_decode(buf[off:])
            off += used
            if not isinstance(k, str):
                raise CborError("non-text map key")
            if k in out:
                raise CborError("duplicate map key")
            out[k] = val
        return out, off
    raise CborError(f"unsupported major type {major}")


# --------------------------------------------------------------------------
# fdf1 overlay address derivation (crates/filament-overlay/src/lib.rs)
# --------------------------------------------------------------------------

ADDR_DOMAIN = b"filament/overlay-addr/v1\0"
ADDR_PREFIX = bytes([0xFD, 0xF1, 0x1A, 0xF7, 0xC3, 0x0D])


def addr_from_pubkey(pub: bytes) -> str:
    """PREFIX(48) || SHA256(ADDR_DOMAIN || pubkey)[..10], as a v6 literal."""
    if len(pub) != 32:
        raise ValueError("device_pub must be 32 bytes")
    digest = hashlib.sha256(ADDR_DOMAIN + pub).digest()
    octets = ADDR_PREFIX + digest[:10]
    groups = [f"{octets[i] << 8 | octets[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(groups)


# --------------------------------------------------------------------------
# Card encode / decode / verify
# --------------------------------------------------------------------------

PREFIX = "fc1"
MAX_ENDPOINTS = 4
SUPPORTED_VERSION = 1


class CardRefused(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def b64u(b: bytes) -> str:
    return urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    if "=" in s:
        raise CardRefused("malformed", "base64url must be unpadded")
    return urlsafe_b64decode(s + "=" * (-len(s) % 4))


def build_card(
    signer: object,
    device_pub: bytes,
    endpoints: list[dict],
    expires: int,
    relay: dict | None = None,
    psk: bytes | None = None,
    *,
    tamper: callable | None = None,
) -> str:
    """Mint a card. `tamper` mutates the map AFTER signing (for the vectors)."""
    body: dict = {
        "v": SUPPORTED_VERSION,
        "device_pub": device_pub,
        "endpoints": endpoints,
        "expires": expires,
    }
    if relay is not None:
        body["relay"] = relay
    if psk is not None:
        body["psk"] = psk
    sig = sign(signer, cbor_encode(body))
    body["sig"] = sig
    if tamper is not None:
        tamper(body)
    return PREFIX + b64u(cbor_encode(body))


def verify_card(
    card: str,
    *,
    now: int,
    claimed_addr: str | None = None,
    source: str = "private",
) -> dict:
    """Implement CONTRACT.md's verify order. Raise CardRefused, or return the
    field summary `addr --parse` prints and the dial path logs."""
    if source not in ("public", "private"):
        raise ValueError("source must be 'public' or 'private'")

    # 1. parse
    if not card.startswith(PREFIX):
        raise CardRefused("malformed", "missing fc1 prefix")
    raw = b64u_decode(card[len(PREFIX) :])
    try:
        body, used = cbor_decode(raw)
    except CborError as e:
        raise CardRefused("malformed", str(e)) from None
    if used != len(raw):
        raise CardRefused("malformed", "trailing bytes after the CBOR map")
    if not isinstance(body, dict):
        raise CardRefused("malformed", "top level is not a map")

    known = {"v", "device_pub", "endpoints", "relay", "psk", "expires", "sig"}
    unknown = sorted(set(body) - known)
    if unknown:
        raise CardRefused("malformed", f"unknown keys: {unknown}")
    for k in ("v", "device_pub", "endpoints", "expires", "sig"):
        if k not in body:
            raise CardRefused("malformed", f"missing required key: {k}")
    if not isinstance(body["device_pub"], bytes) or len(body["device_pub"]) != 32:
        raise CardRefused("malformed", "device_pub must be 32 bytes")
    if not isinstance(body["sig"], bytes) or len(body["sig"]) != 64:
        raise CardRefused("malformed", "sig must be 64 bytes")
    if "psk" in body and (not isinstance(body["psk"], bytes) or len(body["psk"]) != 32):
        raise CardRefused("malformed", "psk must be 32 bytes")
    if not isinstance(body["endpoints"], list):
        raise CardRefused("malformed", "endpoints must be an array")
    if len(body["endpoints"]) > MAX_ENDPOINTS:
        raise CardRefused(
            "too_many_endpoints",
            f"{len(body['endpoints'])} endpoints, cap is {MAX_ENDPOINTS}",
        )
    for ep in body["endpoints"]:
        if not isinstance(ep, dict) or set(ep) != {"ip", "port", "proto"}:
            raise CardRefused("malformed", "endpoint must be {ip, port, proto}")
    # Canonical-form check: the bytes we were handed must already be the ones
    # a canonical encoder would produce. Re-normalizing silently would let two
    # distinct strings carry one signature.
    if cbor_encode(body) != raw:
        raise CardRefused("malformed", "CBOR is not canonical")

    # 2. version
    if body["v"] != SUPPORTED_VERSION:
        raise CardRefused("unknown_version", f"v={body['v']!r}, this build knows 1")

    # 3. expiry (now is a parameter, never the host clock)
    if not isinstance(body["expires"], int) or body["expires"] == 0:
        raise CardRefused("malformed", "expires must be a nonzero uint")
    if body["expires"] <= now:
        raise CardRefused("expired", f"expires={body['expires']} now={now}")

    # 3b. class. Public channel plus a psk is malformed, never stripped.
    is_private = "psk" in body
    if is_private and source == "public":
        raise CardRefused("psk_in_public_card", "psk arrived over a public channel")

    # 4. derivation, BEFORE the signature: free, and it is the "who" check.
    derived = addr_from_pubkey(body["device_pub"])
    if claimed_addr is not None and derived != claimed_addr:
        raise CardRefused("addr_mismatch", f"derived {derived}, claimed {claimed_addr}")

    # 5. signature over the canonical encoding without `sig`
    signed_view = {k: v for k, v in body.items() if k != "sig"}
    if not verify_sig(body["device_pub"], body["sig"], cbor_encode(signed_view)):
        raise CardRefused("bad_signature", "signature does not verify")

    # 6. the summary the dial path logs. Dialing is the caller's business,
    # and the guard verdicts below are advisory data, not a decision made here.
    return {
        "version": body["v"],
        "class": "private" if is_private else "public",
        "derived_addr": derived,
        "expires": body["expires"],
        "seconds_remaining": body["expires"] - now,
        "endpoints": [dict(ep, guard=guard_verdict(ep["ip"])) for ep in body["endpoints"]],
        "relay": body.get("relay"),
    }


def guard_verdict(ip: str) -> str:
    """Dial-guard classification of one endpoint hint. `refuse` is absolute;
    `private` is refused unless the card came from a paired device or the
    operator passed --allow-private."""
    low = ip.lower()
    if low in ("::1", "0.0.0.0", "::") or low.startswith("127."):
        return "refuse"
    if low.startswith("169.254.") or low.startswith("fe80:"):
        return "refuse"
    if low.startswith("ff") and ":" in low:
        return "refuse"
    try:
        first = int(low.split(".")[0])
        if 224 <= first <= 239:
            return "refuse"
    except ValueError:
        pass
    if low.startswith("10.") or low.startswith("192.168."):
        return "private"
    if low.startswith("172."):
        try:
            if 16 <= int(low.split(".")[1]) <= 31:
                return "private"
        except (IndexError, ValueError):
            pass
    if low.startswith(("fc", "fd")) and ":" in low:
        return "private"
    return "allow"


# --------------------------------------------------------------------------
# Vectors
# --------------------------------------------------------------------------

# Fixed seeds and a fixed clock: the emitted JSON must be byte-identical on
# every run, or it is not a fixture, it is churn in the diff.
SEED_A = bytes(range(1, 33))
SEED_B = bytes(range(101, 133))
NOW = 1_760_000_000  # 2025-10-09T07:33:20Z, the reference "now" for all vectors
HOUR = 3600
DAY = 24 * HOUR

PSK = bytes.fromhex("a0" * 32)


def build_vectors() -> dict:
    pub_a, sk_a = keypair_from_seed(SEED_A)
    pub_b, _sk_b = keypair_from_seed(SEED_B)
    PLACEHOLDER_SEEDS[pub_a] = SEED_A
    PLACEHOLDER_SEEDS[pub_b] = SEED_B

    addr_a = addr_from_pubkey(pub_a)
    addr_b = addr_from_pubkey(pub_b)

    eps = [
        {"ip": "198.51.100.7", "port": 41641, "proto": "quic"},
        {"ip": "2001:db8::7", "port": 41641, "proto": "quic"},
    ]
    relay = {"addr": "relay.example.net:443", "mechanism": "turns"}

    vectors = []

    def add(name, card, *, expect, reason=None, source="private", claimed=addr_a, note=""):
        vectors.append(
            {
                "name": name,
                "expect": expect,
                "reason": reason,
                "card": card,
                "verify_with": {"now": NOW, "claimed_addr": claimed, "source": source},
                "note": note,
            }
        )

    # --- accepted ---
    add(
        "valid_public",
        build_card(sk_a, pub_a, eps, NOW + 30 * DAY, relay=relay),
        expect="accept",
        source="public",
        note="what `addr --card` prints and what DNS publishes; no psk",
    )
    add(
        "valid_private",
        build_card(sk_a, pub_a, eps[:1], NOW + HOUR, psk=PSK),
        expect="accept",
        source="private",
        note="the invitation / pair-QR form; psk present, private channel",
    )

    # --- refused ---
    add(
        "tampered_field",
        build_card(
            sk_a,
            pub_a,
            eps,
            NOW + DAY,
            tamper=lambda b: b["endpoints"][0].__setitem__("port", 1234),
        ),
        expect="refuse",
        reason="bad_signature",
        source="public",
        note="port edited after signing; every other check still passes",
    )
    add(
        "expired",
        build_card(sk_a, pub_a, eps, NOW - 1),
        expect="refuse",
        reason="expired",
        source="public",
        note="one second past; expiry is checked against the `now` parameter",
    )
    add(
        "wrong_derivation",
        build_card(sk_a, pub_a, eps, NOW + DAY),
        expect="refuse",
        reason="addr_mismatch",
        source="public",
        claimed=addr_b,
        note="a perfectly valid card for A, offered as the record for B",
    )
    unknown_v = build_card(sk_a, pub_a, eps, NOW + DAY)
    unknown_v_body, _ = cbor_decode(b64u_decode(unknown_v[len(PREFIX) :]))
    unknown_v_body["v"] = 2
    add(
        "unknown_version",
        PREFIX + b64u(cbor_encode(unknown_v_body)),
        expect="refuse",
        reason="unknown_version",
        source="public",
        note="v=2; refused before the signature, no best-effort parse",
    )
    add(
        "psk_in_public",
        build_card(sk_a, pub_a, eps, NOW + DAY, psk=PSK),
        expect="refuse",
        reason="psk_in_public_card",
        source="public",
        note="structurally valid private card retrieved from a public channel",
    )
    add(
        "oversized_endpoints",
        build_card(
            sk_a,
            pub_a,
            [
                {"ip": f"198.51.100.{i}", "port": 41641, "proto": "quic"}
                for i in range(1, 6)
            ],
            NOW + DAY,
        ),
        expect="refuse",
        reason="too_many_endpoints",
        source="public",
        note="5 endpoints; refused at parse, never truncated to 4",
    )

    return {
        "format": "filament bootstrap card (fc1) test vectors",
        "contract": "CONTRACT.md, section 'Bootstrap card (fc1)'",
        "generator": "proofs/card_vectors.py",
        "signature_backend": SIGNATURE_BACKEND,
        "signature_backend_note": (
            "real Ed25519; these vectors are usable as crypto fixtures"
            if SIGNATURE_BACKEND == "ed25519"
            else "PLACEHOLDER, NOT Ed25519. Structure/derivation/expiry/class/size "
            "vectors are valid; signature bytes are not. Regenerate with the "
            "`cryptography` package installed before using as crypto fixtures."
        ),
        "now": NOW,
        "keys": {
            "device_a": {"pub_hex": pub_a.hex(), "seed_hex": SEED_A.hex(), "addr": addr_a},
            "device_b": {"pub_hex": pub_b.hex(), "seed_hex": SEED_B.hex(), "addr": addr_b},
        },
        "psk_hex": PSK.hex(),
        "vectors": vectors,
    }


def self_check(doc: dict) -> None:
    """Every vector must behave exactly as it claims. A refusal vector that
    quietly starts passing is the failure this gate exists to catch."""
    seen = set()
    for vec in doc["vectors"]:
        assert vec["name"] not in seen, f"duplicate vector name {vec['name']}"
        seen.add(vec["name"])
        kw = vec["verify_with"]
        try:
            summary = verify_card(
                vec["card"],
                now=kw["now"],
                claimed_addr=kw["claimed_addr"],
                source=kw["source"],
            )
        except CardRefused as e:
            assert vec["expect"] == "refuse", f"{vec['name']}: unexpected refusal {e}"
            assert e.reason == vec["reason"], (
                f"{vec['name']}: refused for {e.reason!r}, vector says {vec['reason']!r}"
            )
            print(f"  refuse  {vec['name']:<22} {e.reason}")
            continue
        assert vec["expect"] == "accept", (
            f"{vec['name']}: accepted, vector says refuse ({vec['reason']})"
        )
        assert summary["derived_addr"] == kw["claimed_addr"]
        print(f"  accept  {vec['name']:<22} {summary['class']}, "
              f"{summary['seconds_remaining']}s left")

    # Structural invariants the vectors alone do not pin.
    pub_a, sk_a = keypair_from_seed(SEED_A)
    PLACEHOLDER_SEEDS[pub_a] = SEED_A
    card = build_card(sk_a, pub_a, [], NOW + HOUR)
    raw = b64u_decode(card[len(PREFIX) :])
    body, _ = cbor_decode(raw)
    assert cbor_encode(body) == raw, "round trip is not canonical"
    keys = [k for k in body]
    assert keys == ["v", "sig", "expires", "endpoints", "device_pub"], (
        f"canonical key order changed: {keys}"
    )
    assert addr_from_pubkey(pub_a).startswith("fdf1:1af7:c30d:"), "wrong overlay prefix"
    # A card with no endpoints at all is well formed: relay-only bootstrap.
    verify_card(card, now=NOW, claimed_addr=addr_from_pubkey(pub_a), source="public")
    # Padded base64url is refused, so one card has exactly one string form.
    try:
        verify_card(card + "=", now=NOW, source="public")
        raise AssertionError("padded base64url was accepted")
    except CardRefused as e:
        assert e.reason == "malformed"
    print("  ok      canonical order, empty-endpoint card, padding refusal")


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, "card_vectors.json")

    print(f"card vectors  (signature backend: {SIGNATURE_BACKEND})")
    doc = build_vectors()
    self_check(doc)
    rendered = json.dumps(doc, indent=2, sort_keys=True) + "\n"

    if check_only:
        if not os.path.exists(out_path):
            print(f"FAIL: {out_path} is missing; run without --check to write it")
            return 1
        on_disk = open(out_path, encoding="utf-8").read()
        if on_disk != rendered:
            if SIGNATURE_BACKEND != "ed25519":
                print(
                    "FAIL: committed vectors differ from this run. NOTE this run "
                    "used the placeholder backend; install `cryptography` before "
                    "concluding the codec drifted."
                )
            else:
                print("FAIL: committed card_vectors.json differs from this run.")
                print("      Regenerate with: python3 proofs/card_vectors.py")
            return 1
        print(f"  ok      {out_path} matches")
        return 0

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"  wrote   {out_path} ({len(doc['vectors'])} vectors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
