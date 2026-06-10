"""Crypto fidelity tests — run with: python test_crypto.py (no pytest needed).

These pin the Python crypto against the Rust references (pake/src/lib.rs tests,
cli/src/main.rs). channel_of is ALSO cross-checked against the real binary in
the README; here we assert the pure-Python invariants the ceremony depends on.
"""
from filament_lab import crypto as c


def test_channel_of_vector():
    # Cross-checked against the release binary: a device with this secret prints
    # `channel d6b6e37400ac` in `filament devices`.
    full = c.channel_of("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    assert full[:12] == "d6b6e37400ac", full
    assert len(full) == 64


def test_norm_and_split():
    assert c.norm_code("  Brave Otter Ruby 314 ") == "brave-otter-ruby-314"
    assert c.norm_code("BRAVE-OTTER-314") == "brave-otter-314"
    assert c.split_code("brave-otter-ruby-314") == ("314", "brave-otter-ruby")
    assert c.split_code("brave otter 314".replace(" ", "-")) == ("314", "brave-otter")
    assert c.split_code("nodash") == ("nodash", "")


def test_canonical_caps_order_independent():
    assert c.canonical_caps(["Transfer", "clipboard"]) == c.canonical_caps(["clipboard", "TRANSFER"])
    assert c.canonical_caps([]) == ""
    assert c.canonical_caps(["transfer", "transfer"]) == "transfer"


def test_proof_for_normalizes_uid_and_fp_order():
    # proof_for sorts (a_uid,b_uid) and (fp1,fp2) — swapping inputs is identical.
    s = "abc123" * 10
    p1 = c.proof_for(s, "prover", "u-a", "u-b", "FP1", "FP2")
    p2 = c.proof_for(s, "prover", "u-b", "u-a", "FP2", "FP1")
    assert p1 == p2
    # different prover tag => different proof (direction binding)
    assert c.proof_for(s, "u-a", "u-a", "u-b", "FP1", "FP2") != \
           c.proof_for(s, "u-b", "u-a", "u-b", "FP1", "FP2")


def test_spake2_mutual_secret_and_confirm():
    pw, np = b"brave-otter-ruby", b"314"
    a, b = c.Pake(pw, np), c.Pake(pw, np)
    ka = a.finish(b.message())
    kb = b.finish(a.message())
    assert c.secret_from_k(ka) == c.secret_from_k(kb)
    assert len(c.secret_from_k(ka)) == 64
    FP_A, FP_B = "SHA-256 AA:BB:CC", "SHA-256 DD:EE:FF"
    caps = c.canonical_caps(["transfer"])
    a_sends = c.our_confirm(ka, FP_A, FP_B, caps)
    b_sends = c.our_confirm(kb, FP_B, FP_A, caps)
    assert c.verify_peer_confirm(kb, FP_B, FP_A, caps, a_sends)
    assert c.verify_peer_confirm(ka, FP_A, FP_B, caps, b_sends)


def test_spake2_reflection_rejected():
    pw, np = b"brave-otter", b"314"
    a, b = c.Pake(pw, np), c.Pake(pw, np)
    ka = a.finish(b.message()); b.finish(a.message())
    caps = c.canonical_caps(["transfer"])
    a_sends = c.our_confirm(ka, "FP_A", "FP_B", caps)
    # A must NOT accept its own MAC reflected back.
    assert not c.verify_peer_confirm(ka, "FP_A", "FP_B", caps, a_sends)


def test_spake2_wrong_password_diverges():
    np = b"314"
    a, b = c.Pake(b"brave-otter", np), c.Pake(b"tidy-walrus", np)
    ka = a.finish(b.message()); kb = b.finish(a.message())
    assert c.secret_from_k(ka) != c.secret_from_k(kb)
    caps = c.canonical_caps(["transfer"])
    a_sends = c.our_confirm(ka, "FP_A", "FP_B", caps)
    assert not c.verify_peer_confirm(kb, "FP_B", "FP_A", caps, a_sends)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} crypto fidelity tests passed")
