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

# A log shaped like the CI job's: one ::group:: per crate, one result line each.
LOG = """::group::crate-a
test result: ok. 7 passed; 0 failed; 0 ignored
::endgroup::
::group::crate-b
test result: ok. 3 passed; 0 failed; 0 ignored
test result: ok. 2 passed; 0 failed; 0 ignored
::endgroup::
"""


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
        errors, _ = guard.static_check(self.root)
        self.assertEqual(errors, [])

    def test_crate_with_tests_absent_from_the_loop_is_rejected(self):
        """The 2026-09-18 case: filament-transport, 23 tests, in no loop."""
        self.crate("crate-a", "#[test]\nfn t() {}")
        self.crate("crate-orphan", "#[cfg(test)]\nmod tests { #[test] fn t() {} }")
        self.workflow(["crate-a"])
        errors, _ = guard.static_check(self.root)
        self.assertTrue(any("crate-orphan" in e and "NOT in" in e for e in errors),
                        errors)

    def test_crate_without_tests_may_be_absent(self):
        self.crate("crate-a", "#[test]\nfn t() {}")
        self.crate("secret-write", "pub fn nothing(){}\n")
        self.workflow(["crate-a"])
        errors, _ = guard.static_check(self.root)
        self.assertEqual(errors, [])

    def test_stale_loop_name_is_rejected(self):
        """A renamed crate would be skipped silently by the loop's [ -f ] guard."""
        self.crate("crate-a", "#[test]\nfn t() {}")
        self.workflow(["crate-a", "crate-gone"])
        errors, _ = guard.static_check(self.root)
        self.assertTrue(any("crate-gone" in e for e in errors), errors)

    def test_missing_workflow_is_rejected(self):
        self.crate("crate-a", "#[test]\nfn t() {}")
        errors = guard.static_check(self.root)[0]
        self.assertTrue(any("crate-a" in e for e in errors), errors)

    # ---------------------------------------------------------------- ratchet

    def test_counts_are_summed_per_crate(self):
        self.assertEqual(guard.counts_from_log(LOG, {"crate-a", "crate-b"}),
                         {"crate-a": 7, "crate-b": 5})

    def test_count_drop_is_rejected(self):
        """Presence alone passes an empty suite; the count is what refuses."""
        errors = guard.verify_counts(LOG, {"crate-a": 7, "crate-b": 6}, {"crate-a", "crate-b"})
        self.assertTrue(any("crate-b" in e and "DROPPED" in e for e in errors), errors)

    def test_equal_counts_pass(self):
        self.assertEqual(guard.verify_counts(LOG, {"crate-a": 7, "crate-b": 5},
                                             {"crate-a", "crate-b"}), [])

    def test_crate_with_no_result_line_is_rejected(self):
        """Collected but empty: exit 0, zero tests -- the disease one level up."""
        errors = guard.verify_counts(LOG, {"crate-a": 7, "crate-gone": 4},
                                     {"crate-a", "crate-b"})
        self.assertTrue(any("crate-gone" in e and "no `test result:`" in e
                            for e in errors), errors)

    def test_unrecorded_crate_is_rejected(self):
        errors = guard.verify_counts(LOG, {"crate-a": 7}, {"crate-a", "crate-b"})
        self.assertTrue(any("crate-b" in e and "absent from" in e for e in errors),
                        errors)

    def test_wrapper_step_groups_are_not_mistaken_for_crates(self):
        """A CI log carries the runner's own groups (Run/Runner/Setting); those
        must not look like crates that ran and are absent from the baseline."""
        noisy = LOG + "::group::Run\ntest result: ok. 970 passed; 0 failed\n::endgroup::\n"
        self.assertEqual(guard.verify_counts(noisy, {"crate-a": 7, "crate-b": 5},
                                             {"crate-a", "crate-b"}), [])

    def test_failure_message_names_the_line_to_add(self):
        self.crate("crate-orphan", "#[test]\nfn t() {}")
        self.crate("crate-a", "#[test]\nfn t() {}")
        self.workflow(["crate-a"])
        errors, _ = guard.static_check(self.root)
        self.assertTrue(any("add `crate-orphan` to the" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
