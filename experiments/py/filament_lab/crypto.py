"""Filament identity + pairing crypto — a faithful Python port of the Rust.

Every function here is a byte-for-byte mirror of a Rust counterpart so a Python
peer can sit on the same wire as the real `filament` binary:

  channel_of(secret)          <- cli/src/main.rs:622   (presence rendezvous)
  proof_for(...)              <- cli/src/main.rs:655   (the trust-gate MAC)
  norm_code / split_code      <- pake/src/lib.rs:187   (spoken-code handling)
  mint_words / mint_nameplate <- pake/src/words.rs     (code minting)
  Pake (SPAKE2 + confirm)     <- pake/src/lib.rs        (the L1-a ceremony)

SCOPE NOTE (read before trusting interop):
  * channel_of / proof_for / norm_code / split_code are wire-reachable and are
    exercised against the real binary (proof_for satisfies the acceptor's
    auto-accept gate; channel_of is the shared rendezvous).
  * The SPAKE2 ceremony is implemented faithfully and unit-tested PYTHON<->PYTHON.
    It is NOT verified Rust<->Python over the wire because the Rust key-confirmation
    MAC folds in the WebRTC DTLS fingerprints (main.rs:1163), which only exist once
    a real WebRTC peer connection is up — outside this control-plane library's scope.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets as _secrets

# --------------------------------------------------------------- channel_of --

def channel_of(secret: str) -> str:
    """sha256("filament-pair:" + secret), hex. Mirrors cli/src/main.rs:622.

    Two devices that share `secret` subscribe to the same channel and the
    signaling server tells them about each other (known-peer) without ever
    seeing the secret.
    """
    h = hashlib.sha256()
    h.update(b"filament-pair:")
    h.update(secret.encode())
    return h.hexdigest()


# ----------------------------------------------------------------- proof_for --

def _hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    """HMAC-SHA256 -> lowercase hex. Matches the manual construction in
    cli/src/main.rs:630 (which avoids a crate version dance but is plain HMAC)."""
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def proof_for(secret: str, prover_uid: str, a_uid: str, b_uid: str,
              fp1: str, fp2: str) -> str:
    """The C20 trust-gate MAC. Mirrors cli/src/main.rs:655 exactly.

    uids are order-normalized (lo,hi) and BOTH DTLS fingerprints are mixed in
    sorted order, with the prover's uid as a direction tag. A Python peer that
    knows the shared `secret` can emit this so the Rust acceptor's `pair-proof`
    handler (main.rs:3986) auto-accepts it as a known device.
    """
    lo, hi = (a_uid, b_uid) if a_uid < b_uid else (b_uid, a_uid)
    f_lo, f_hi = (fp1, fp2) if fp1 < fp2 else (fp2, fp1)
    msg = f"filament-proof2:{prover_uid}|{lo}|{hi}|{f_lo}|{f_hi}"
    return _hmac_sha256_hex(secret.encode(), msg.encode())


def fresh_secret() -> str:
    """A new 32-byte device secret as 64-hex. Mirrors main.rs:664."""
    return _secrets.token_bytes(32).hex()


# ----------------------------------------------------------- code handling ----

def norm_code(raw: str) -> str:
    """Normalize a spoken code. Mirrors pake/src/lib.rs:187 (and backend
    _norm_code): lowercase, runs of whitespace -> single dash, strip anything
    outside [a-z0-9-], cap at 48 chars. MUST be byte-identical or the two sides
    feed different passwords to SPAKE2."""
    lowered = raw.strip().lower()
    spaced = re.sub(r"\s+", "-", lowered)
    filtered = "".join(c for c in spaced if c.islower() or c.isdigit() or c == "-")
    # islower() is True for non-ascii lowercase too; restrict to ascii like Rust.
    filtered = "".join(c for c in filtered if c in "abcdefghijklmnopqrstuvwxyz0123456789-")
    return filtered[:48]


def split_code(normalized: str) -> tuple[str, str]:
    """(nameplate, password). The nameplate is the TRAILING group after the LAST
    dash; the password is everything before it. Mirrors pake/src/lib.rs:213.
      "brave-otter-ruby-314" -> ("314", "brave-otter-ruby")
    """
    i = normalized.rfind("-")
    if i == -1:
        return (normalized, "")
    return (normalized[i + 1:], normalized[:i])


def canonical_caps(caps: list[str]) -> str:
    """Trim, lowercase, dedupe, sort, comma-join. Mirrors pake/src/lib.rs:222."""
    v = sorted({c.strip().lower() for c in caps if c.strip()})
    return ",".join(v)


# Speakable-code vocabulary. The CLI mints words LOCALLY (the server never sees
# them); these lists mirror pake/src/words.rs so a Python creator can mint a
# code the same shape. (We only need the structure, not byte-identical lists,
# because words never cross the wire — only the numeric nameplate does.)
def mint_nameplate() -> str:
    """A numeric nameplate in 1000..=9999. Mirrors pake/src/words.rs:71."""
    return str(1000 + _secrets.randbelow(9000))


# ------------------------------------------------------------------- SPAKE2 ---
# Mirrors pake/src/lib.rs: symmetric SPAKE2 over Ed25519, identity bound to the
# nameplate, K -> HKDF -> pinned 64-hex secret, and the §4 confirmation MAC over
# sorted fingerprints + caps.

_IDENTITY_PREFIX = b"filament-pair-pake-v1:"
_SECRET_INFO = b"filament-pair-pake-v1:pinned-secret"
_CONFIRM_LABEL = b"filament-pake-confirm-v1"


def _identity_bytes(nameplate: bytes) -> bytes:
    return _IDENTITY_PREFIX + nameplate


def _hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 with no salt (salt=None == hashlen of zeros), mirroring
    Rust `Hkdf::<Sha256>::new(None, k)` then expand(info)."""
    # Extract
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, ikm, hashlib.sha256).digest()
    # Expand
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def secret_from_k(k: bytes) -> str:
    """§5.1 HKDF(K) -> 32-byte pinned secret as 64-hex. Mirrors lib.rs:174."""
    return _hkdf_sha256(k, _SECRET_INFO, 32).hex()


def confirm_mac(k: bytes, direction: str, fp_lo: str, fp_hi: str, caps: str) -> bytes:
    """§4 key-confirmation MAC. Length-prefixed variable fields (u32 LE) exactly
    as pake/src/lib.rs:98."""
    m = hmac.new(k, b"", hashlib.sha256)
    m.update(_CONFIRM_LABEL)
    m.update(direction.encode())
    for field in (fp_lo.encode(), fp_hi.encode(), caps.encode()):
        m.update(len(field).to_bytes(4, "little"))
        m.update(field)
    return m.digest()


def sort_fps(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a < b else (b, a)


def confirm_dirs(my_fp: str, fp_lo: str) -> tuple[str, str]:
    """(send_dir, expect_dir). Mirrors lib.rs:126."""
    return ("A->B", "B->A") if my_fp == fp_lo else ("B->A", "A->B")


def our_confirm(k: bytes, my_fp: str, their_fp: str, caps: str) -> bytes:
    lo, hi = sort_fps(my_fp, their_fp)
    send_dir, _ = confirm_dirs(my_fp, lo)
    return confirm_mac(k, send_dir, lo, hi, caps)


def verify_peer_confirm(k: bytes, my_fp: str, their_fp: str, caps: str,
                        received: bytes) -> bool:
    lo, hi = sort_fps(my_fp, their_fp)
    _, expect_dir = confirm_dirs(my_fp, lo)
    expected = confirm_mac(k, expect_dir, lo, hi, caps)
    return hmac.compare_digest(expected, received)


class Pake:
    """A symmetric SPAKE2 session mirroring pake/src/lib.rs `start`/`finish`.

    Usage (both peers identical — start_symmetric, §3.1):
        p = Pake(password=words.encode(), nameplate=np.encode())
        out = p.message()                 # 33-byte element to relay
        k = p.finish(peer_message)        # raw shared key K
        secret = secret_from_k(k)         # the agreed 64-hex pinned secret
    """

    def __init__(self, password: bytes, nameplate: bytes):
        from spake2 import SPAKE2_Symmetric
        from spake2.parameters.ed25519 import ParamsEd25519

        self._s = SPAKE2_Symmetric(
            password,
            idSymmetric=_identity_bytes(nameplate),
            params=ParamsEd25519,
        )
        self._msg = self._s.start()
        self.k: bytes | None = None

    def message(self) -> bytes:
        return self._msg

    def finish(self, peer_message: bytes) -> bytes:
        self.k = self._s.finish(peer_message)
        return self.k
