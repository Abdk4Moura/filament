"""Variance & security tests for the speakable one-time pairing codes.

These exist because small-or-biased name spaces LOOK random while repeating
constantly (the original 10x10x90 space produced visible repeats in normal
use). Every test here guards a property the full mathematical treatment (see
the variance-analysis repo) shows we need:

  1. the space never silently shrinks below 1M codes
  2. minting is uniform across every component (no modulo / choice bias)
  3. minting uses a CSPRNG (`secrets`), never `random`
  4. observed collisions match the birthday bound for the space
  5. claims are rate-limited (entropy is meaningless if the space is sweepable)
  6. codes burn exactly once, atomically

Run:  python -m unittest backend.tests.test_pair_codes  (or via cli/tests/gates.sh gate 0)
"""
import inspect
import math
import re
import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402


class WordlistContract(unittest.TestCase):
    def test_sizes_and_uniqueness(self):
        self.assertEqual(len(signaling._ADJ), 64)
        self.assertEqual(len(set(signaling._ADJ)), 64)
        self.assertEqual(len(signaling._ANIMAL), 64)
        self.assertEqual(len(set(signaling._ANIMAL)), 64)
        # no word may collide across the two lists (codes stay parseable)
        self.assertFalse(set(signaling._ADJ) & set(signaling._ANIMAL))

    def test_words_are_speakable_tokens(self):
        for w in signaling._ADJ + signaling._ANIMAL:
            self.assertRegex(w, r"^[a-z]{3,8}$", f"{w!r} must be short lowercase alpha (no hyphens)")

    def test_space_floor(self):
        """Regression guard: the code space must never shrink below 1M."""
        space = len(signaling._ADJ) * len(signaling._ANIMAL) * 900
        self.assertGreaterEqual(space, 1_000_000, "code space shrank — see variance analysis before changing lists")

    def test_mint_uses_csprng(self):
        src = inspect.getsource(signaling._mint_pair_code)
        self.assertIn("_secrets.", src, "minting must use the `secrets` CSPRNG")
        self.assertNotIn("random.", src.replace("_secrets.", ""), "never `random` for codes")


class MintDistribution(unittest.TestCase):
    N = 200_000

    @classmethod
    def setUpClass(cls):
        cls.codes = [signaling._mint_pair_code() for _ in range(cls.N)]

    def test_format(self):
        pat = re.compile(r"^[a-z]{3,8}-[a-z]{3,8}-[1-9][0-9]{2}$")
        for c in self.codes[:1000]:
            self.assertRegex(c, pat)

    def _assert_uniform(self, values, bins, label):
        """Every bin within 6 sigma of expectation (per-test false-positive
        probability < 1e-6 even across all bins)."""
        counts = Counter(values)
        self.assertEqual(set(counts), set(bins), f"{label}: every bin must be reachable at N={self.N}")
        exp = self.N / len(bins)
        sigma = math.sqrt(exp * (1 - 1 / len(bins)))
        worst = max(abs(counts[b] - exp) for b in bins)
        self.assertLess(
            worst,
            6 * sigma,
            f"{label}: worst bin deviates {worst:.0f} (> 6 sigma = {6 * sigma:.0f}) from expected {exp:.0f}",
        )

    def test_adjective_uniform(self):
        self._assert_uniform([c.split("-")[0] for c in self.codes], signaling._ADJ, "adjectives")

    def test_animal_uniform(self):
        self._assert_uniform([c.split("-")[1] for c in self.codes], signaling._ANIMAL, "animals")

    def test_number_uniform(self):
        self._assert_uniform([c.rsplit("-", 1)[1] for c in self.codes], [str(n) for n in range(100, 1000)], "numbers")

    def test_collisions_match_birthday_bound(self):
        """E[collisions] for n draws from d codes ~ n(n-1)/(2d). For n=200k,
        d=3,686,400: ~5,400 colliding draws -> distinct >= n - 3*expected is a
        loose, deterministic-enough bound. The OLD 9,000-code space would have
        only ~8,800 distinct values here and fails catastrophically."""
        n, d = self.N, 64 * 64 * 900
        expected_collisions = n * (n - 1) / (2 * d)
        distinct = len(set(self.codes))
        self.assertGreater(distinct, n - 3 * expected_collisions)
        self.assertGreater(distinct, 9_000, "would fail if space regressed to the old 10x10x90")


class NormalizationAndBurn(unittest.TestCase):
    def test_norm_code(self):
        self.assertEqual(signaling._norm_code("  Brave  Otter 123 "), "brave-otter-123")
        self.assertEqual(signaling._norm_code("CLEVER-LYNX-63!"), "clever-lynx-63")
        self.assertEqual(signaling._norm_code(None), "")
        self.assertEqual(signaling._norm_code({"click": "event"}), "")
        self.assertEqual(len(signaling._norm_code("x" * 500)), 48)

    def test_burn_once_atomic(self):
        reg = signaling._MemRegistry()
        self.assertTrue(reg.pair_create("brave-otter-123", "sid-a", ttl=600))
        self.assertFalse(reg.pair_create("brave-otter-123", "sid-b", ttl=600), "NX: duplicate create must fail")
        self.assertEqual(reg.pair_claim("brave-otter-123"), "sid-a")
        self.assertIsNone(reg.pair_claim("brave-otter-123"), "second claim must find nothing (burned)")


class ClaimRateLimit(unittest.TestCase):
    """The 21.8-bit space only holds against an attacker because claims are
    throttled: 5/min means sweeping 3.7M codes takes >1.4 years per identity,
    far beyond the 10-minute TTL. (The unthrottled original: 9,000 codes at
    socket speed ~ under a minute.)"""

    def test_limiter_blocks_sixth_claim_and_burst_sweep(self):
        from flask import Flask
        from flask_socketio import SocketIO

        app = Flask(__name__)
        sio = SocketIO(app, async_mode="threading")
        signaling.register(sio, signaling._MemRegistry())
        client = sio.test_client(app)
        client.get_received()  # drain connect events

        errors = []
        for i in range(8):
            client.emit("pair-claim", {"code": f"none-such-{i}00"})
            for ev in client.get_received():
                if ev["name"] == "pair-error":
                    errors.append(ev["args"][0]["error"])
        self.assertEqual(errors[:5], ["invalid"] * 5, "first 5 attempts get the normal miss")
        self.assertTrue(
            all(e == "slow-down" for e in errors[5:]) and len(errors) == 8,
            f"attempts beyond 5/min must be throttled, got {errors}",
        )


if __name__ == "__main__":
    unittest.main()
