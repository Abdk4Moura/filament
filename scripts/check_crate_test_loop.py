#!/usr/bin/env python3
"""Every crate under crates/ that carries tests must be run by test.yml's loop.

WHY THIS EXISTS. `cargo test` in cli/ runs the CLI package's tests only: a path
dependency is BUILT, never tested. `.github/workflows/test.yml` closes that with
an EXPLICIT loop over crate names, and the comment there explains the choice --
"named explicitly rather than globbed so adding a crate is a deliberate act that
shows up in review".

That explicitness is the fix and the failure mode at once. On 2026-09-18 the
loop ran eight crates and two crates with tests were absent from it:
`filament-transport` (23 tests, including the two added by the #312 slice) and
`authkeys-managed` (4). 27 tests were collected by nothing, and nothing said so:
a suite that is never run looks exactly like a suite that passes.

So this guard does what the artifact registry does for executables -- it treats
"exists but is not run" as an ERROR rather than a note:

  * a crate under crates/ that carries tests and is NOT in the loop fails;
  * a name in the loop with no crate under crates/ fails too, because the loop's
    `if [ -f ... ]` guard SKIPS a stale name silently, which is the other way a
    hand-maintained list rots.

Run it: python3 scripts/check_crate_test_loop.py [--root DIR]
Its own behaviour is tested by scripts/test_check_crate_test_loop.py.
"""
import argparse
import pathlib
import re
import sys

TEST_MARKERS = ("#[test]", "#[tokio::test]", "#[cfg(test)]")


def crate_dir(root: pathlib.Path, name: str) -> pathlib.Path:
    return root / "crates" / name


def discover(root: pathlib.Path) -> dict[str, int]:
    """{package name: number of test-carrying files} for every crate under crates/."""
    found: dict[str, int] = {}
    crates = root / "crates"
    if not crates.is_dir():
        return found
    for manifest in sorted(crates.glob("*/Cargo.toml")):
        text = manifest.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^name\s*=\s*"([^"]+)"', text, re.M)
        if not m:
            continue
        name = m.group(1)
        carrying = 0
        for rs in sorted(manifest.parent.rglob("*.rs")):
            body = rs.read_text(encoding="utf-8", errors="replace")
            if any(marker in body for marker in TEST_MARKERS):
                carrying += 1
        found[name] = carrying
    return found


def loop_crates(root: pathlib.Path) -> list[str]:
    """The crate names test.yml's `for c in ...; do` loop names, in order."""
    workflow = root / ".github" / "workflows" / "test.yml"
    if not workflow.is_file():
        return []
    text = workflow.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"for\s+c\s+in\s+(.*?);\s*do", text, re.S)
    if not m:
        return []
    return re.findall(r"[A-Za-z0-9_.-]+", m.group(1))


def check(root: pathlib.Path) -> tuple[list[str], str]:
    """Return (errors, table) for the tree at `root`."""
    discovered = discover(root)
    listed = loop_crates(root)
    errors: list[str] = []
    rows = []
    for name in sorted(discovered):
        carrying = discovered[name]
        in_loop = name in listed
        if carrying and not in_loop:
            errors.append(
                f"{name}: carries tests in {carrying} file(s) but is NOT in "
                "test.yml's loop, so `cargo test` in cli/ never collects them "
                "(a path dependency is built, never tested). Add it to the loop.")
        rows.append(f"  {name:<24} test-files={carrying:<3} in-loop={'yes' if in_loop else 'NO'}")
    for name in listed:
        if name not in discovered:
            errors.append(
                f"{name}: named in test.yml's loop but no package under crates/ "
                "has that name. The loop's `[ -f ... ]` guard skips a stale name "
                "SILENTLY, so this is a test that quietly stopped running.")
    table = "\n".join(rows)
    return errors, table


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root")
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()
    errors, table = check(root)
    print("crate test loop: discovered crates and whether test.yml runs them")
    print(table)
    if errors:
        print("\ncrate test loop: FAIL")
        for e in errors:
            print(f"  {e}")
        return 1
    print("\ncrate test loop: PASS (every crate that carries tests is run by test.yml)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
