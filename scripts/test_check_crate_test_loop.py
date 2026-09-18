#!/usr/bin/env python3
"""Tests for scripts/check_crate_test_loop.py.

The guard's whole value is that it REFUSES, so these tests build the two ways a
hand-maintained list rots and require the refusal: a crate with tests that is
absent from the loop, and a name in the loop with no crate behind it (which the
loop's own `[ -f ... ]` guard skips silently).
"""
import pathlib
import tempfile
import unittest

import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_crate_test_loop as guard  # noqa: E402


class CrateTestLoopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        (self.root / "crates").mkdir()
        (self.root / ".github" / "workflows").mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def crate(self, name, body):
        d = self.root / "crates" / name / "src"
        d.mkdir(parents=True)
        (self.root / "crates" / name / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\n')
        (d / "lib.rs").write_text(body + "\n")

    def workflow(self, names):
        (self.root / ".github" / "workflows" / "test.yml").write_text(
            "      - name: Test the local crates\n"
            "        run: |\n"
            "          set -e\n"
            "          for c in " + " ".join(names) + "; do\n"
            "            if [ -f \"crates/$c/Cargo.toml\" ]; then\n"
            "              cargo test --release --manifest-path \"crates/$c/Cargo.toml\"\n"
            "            fi\n"
            "          done\n")

    def test_every_test_carrying_crate_in_the_loop_passes(self):
        self.crate("crate-a", "#[cfg(test)]\nmod tests { #[test] fn t() {} }")
        self.crate("crate-b", "#[test]\nfn t() {}")
        self.workflow(["crate-a", "crate-b"])
        errors, _ = guard.check(self.root)
        self.assertEqual(errors, [])

    def test_crate_with_tests_absent_from_the_loop_is_rejected(self):
        """The 2026-09-18 case: filament-transport, 23 tests, in no loop."""
        self.crate("crate-a", "#[test]\nfn t() {}")
        self.crate("crate-orphan", "#[cfg(test)]\nmod tests { #[test] fn t() {} }")
        self.workflow(["crate-a"])
        errors, _ = guard.check(self.root)
        self.assertTrue(any("crate-orphan" in e and "NOT in" in e for e in errors),
                        errors)

    def test_crate_without_tests_may_be_absent(self):
        self.crate("crate-a", "#[test]\nfn t() {}")
        self.crate("secret-write", "pub fn nothing(){}\n")
        self.workflow(["crate-a"])
        errors, _ = guard.check(self.root)
        self.assertEqual(errors, [])

    def test_stale_loop_name_is_rejected(self):
        """A renamed crate would be skipped silently by the loop's [ -f ] guard."""
        self.crate("crate-a", "#[test]\nfn t() {}")
        self.workflow(["crate-a", "crate-gone"])
        errors, _ = guard.check(self.root)
        self.assertTrue(any("crate-gone" in e for e in errors), errors)

    def test_missing_workflow_is_rejected(self):
        self.crate("crate-a", "#[test]\nfn t() {}")
        errors, _ = guard.check(self.root)
        self.assertTrue(any("crate-a" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
