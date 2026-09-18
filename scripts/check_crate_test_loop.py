#!/usr/bin/env python3
"""Every crate under crates/ that carries tests must be RUN, and must not shrink.

WHY THIS EXISTS. `cargo test` in cli/ runs the CLI package's tests only: a path
dependency is BUILT, never tested. `.github/workflows/test.yml` closes that with
an EXPLICIT loop over crate names, and its comment explains the choice -- "named
explicitly rather than globbed so adding a crate is a deliberate act that shows
up in review".

That explicitness is the fix and the failure mode at once. On 2026-09-18 the loop
ran eight crates and two crates with tests were absent from it:
`filament-transport` (23 tests, including the pair added by the #312 slice) and
`authkeys-managed` (4). 27 tests were collected by nothing, and nothing said so:
a suite that is never run looks exactly like a suite that passes.

PRESENCE IS NOT ENOUGH, which is why this has two halves:

  * STATIC (no build): a crate under crates/ that carries tests and is absent
    from the loop fails; a name in the loop with no crate behind it fails too,
    because the loop's `if [ -f ... ]` guard SKIPS a stale name silently.
  * COUNT RATCHET (`--verify-log`): presence still passes a suite that is
    collected but EMPTY -- a rename, a `#[cfg(test)] mod` that stops compiling
    in, or a filter that matches nothing all leave exit 0 with zero tests. So the
    per-crate `test result: ok. N passed` counts are read out of the run and
    compared with `scripts/crate_test_counts.json`: a crate whose count DROPS, or
    which produces no result line at all, fails. This is the same shape as
    cli/tests/gates-ratchet.sh and the warning/platform ratchets.

Usage:
    python3 scripts/check_crate_test_loop.py                     # static check
    python3 scripts/check_crate_test_loop.py --verify-log LOG    # ratchet
    python3 scripts/check_crate_test_loop.py --record-log LOG    # refresh counts
"""
import argparse
import json
import pathlib
import re
import sys

TEST_MARKERS = ("#[test]", "#[tokio::test]", "#[cfg(test)]")
COUNTS_FILE = "scripts/crate_test_counts.json"
# `test result: ok. 110 passed; 0 failed; ...` -- cargo emits one line per test
# binary (lib, integration, doc), so the per-crate total is the SUM.
#
# The log this parses is the job's RAW stdout (what `tee` writes): the loop
# echoes `::group::<crate>` itself, so that literal is what appears there.
# A log DOWNLOADED from the Actions UI has those RENDERED as `##[group]<crate>`,
# so verifying against a download needs `sed 's/##\[group\]/::group::/'` first
# (the CI job does not, and that is the case that matters).
RESULT_RE = re.compile(r"test result:\s*(\w+)\.\s*(\d+)\s+passed")
GROUP_RE = re.compile(r"::group::\s*([A-Za-z0-9_.-]+)")


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


def add_line(crate: str) -> str:
    """The paste-ready edit, so the fix is one line rather than a lookup."""
    return f"add `{crate}` to the `for c in ...` list in .github/workflows/test.yml"


def static_check(root: pathlib.Path) -> tuple[list[str], str]:
    """(errors, table) for the tree at `root`, no build required."""
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
                f"(a path dependency is built, never tested). Fix: {add_line(name)}.")
        rows.append(f"  {name:<24} test-files={carrying:<3} in-loop={'yes' if in_loop else 'NO'}")
    for name in listed:
        if name not in discovered:
            errors.append(
                f"{name}: named in test.yml's loop but no package under crates/ "
                "has that name. The loop's `[ -f ... ]` guard skips a stale name "
                "SILENTLY, so this is a test that quietly stopped running. Fix: "
                f"remove `{name}` from the list, or add the crate back.")
    return errors, "\n".join(rows)


def counts_from_log(text: str, known: set[str] | None = None) -> dict[str, int]:
    """{crate: passed} from a cargo-test log that groups each crate.

    `known` restricts which groups count (normally the loop's own crate names).
    Without it, ANY `::group::` marker opens a bucket -- and a log from a CI run
    carries the runner's own step groups too (`Run`, `Runner`, `Setting`,
    `Fetching` ...), which then look like crates that produced tests and are
    absent from the baseline. That is a false refusal produced by the wrapper, not
    by the code, so the parser only ever counts groups it was told are crates.
    """
    counts: dict[str, int] = {}
    current: str | None = None
    for line in text.splitlines():
        g = GROUP_RE.search(line)
        if g:
            name = g.group(1)
            current = name if (known is None or name in known) else None
            if current is not None:
                counts.setdefault(current, 0)
            continue
        r = RESULT_RE.search(line)
        if r and current:
            counts[current] = counts.get(current, 0) + int(r.group(2))
    return counts


def load_baseline(root: pathlib.Path) -> dict[str, int]:
    path = root / COUNTS_FILE
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def verify_counts(log_text: str, baseline: dict[str, int],
                  known: set[str] | None = None) -> list[str]:
    """Fail on any crate whose passed-count DROPS, or that produced no result."""
    seen = counts_from_log(log_text, known)
    errors: list[str] = []
    for crate, floor in sorted(baseline.items()):
        got = seen.get(crate)
        if got is None:
            errors.append(
                f"{crate}: no `test result:` line in this run at all. A suite that "
                "is collected but produces nothing passes a presence check and "
                "proves nothing. Expected at least {floor} passing test(s).")
        elif got < floor:
            errors.append(
                f"{crate}: {got} passing test(s), baseline {floor} -- the count "
                "DROPPED. If the tests were removed deliberately, lower the "
                f"baseline in {COUNTS_FILE} in the same commit and say why.")
    for crate in sorted(seen):
        if crate not in baseline:
            errors.append(
                f"{crate}: ran and produced {seen[crate]} passing test(s) but is "
                f"absent from {COUNTS_FILE}. Record it in the same commit "
                "(`--record-log`) so its count is protected from here on.")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root")
    ap.add_argument("--verify-log", help="cargo-test log to ratchet against the baseline")
    ap.add_argument("--record-log", help="cargo-test log to record baselines from")
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()

    errors, table = static_check(root)
    print("crate test loop: discovered crates and whether test.yml runs them")
    print(table)

    if args.record_log:
        text = pathlib.Path(args.record_log).read_text(encoding="utf-8", errors="replace")
        counts = counts_from_log(text, set(loop_crates(root)))
        if not counts:
            print("\ncrate test loop: RECORD FAILED (no ::group:: markers / result lines)")
            return 1
        (root / COUNTS_FILE).write_text(json.dumps(counts, indent=2, sort_keys=True) + "\n")
        print(f"\nrecorded {len(counts)} crate count(s) into {COUNTS_FILE}")
        return 1 if errors else 0

    if args.verify_log:
        text = pathlib.Path(args.verify_log).read_text(encoding="utf-8", errors="replace")
        baseline = load_baseline(root)
        if not baseline:
            print(f"\ncrate test loop: FAIL ({COUNTS_FILE} is missing or empty; "
                  "record it with --record-log)")
            return 1
        errors += verify_counts(text, baseline, set(loop_crates(root)))

    if errors:
        print("\ncrate test loop: FAIL")
        for e in errors:
            print(f"  {e}")
        return 1
    print("\ncrate test loop: PASS (every crate that carries tests is run, and no count dropped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
