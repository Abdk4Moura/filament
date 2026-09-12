#!/usr/bin/env python3
"""Model the stall correction ladder, including what each rung destroys.

The ladder retries a stuck transfer five times, with a 15-second watchdog per
rung. This model does not assume that "stuck while connecting" has one cause:
transience and failure type are explicit environment parameters. A retry can
only benefit from a transient condition if it preserves the state that the
next attempt needs.

Run this file directly. Gate 0 first reproduces the observed #31, #50, and #38
outcomes before the model prints any recommendation.
"""
from dataclasses import dataclass
from itertools import combinations, product
import os
import re


MAX_ATTEMPTS = 5
WATCHDOG_SECS = 15
TRANSIENT, PERSISTENT = "transient", "persistent"
UNDETERMINED = "undetermined"

FAILURE_STATE = {
    "data-freeze": "transport",
    "ice-connect": "ice",
    "roster-re-adoption": "roster",
}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def source_ladder_constants():
    """Read the ladder bounds from the Rust tree this model claims to describe."""
    # Anchor is anywhere in cli/src since the 2026-09-12 main.rs
    # decomposition (const MAX_ATTEMPTS now lives in shared_defs.rs).
    import glob
    src_dir = os.path.join(ROOT, "cli", "src")
    files = sorted(glob.glob(os.path.join(src_dir, "**", "*.rs"), recursive=True))
    if not files:
        raise SystemExit(
            "stall-ladder guard: no .rs files under cli/src; "
            "the calibration cannot be confirmed current. Refusing to report."
        )
    main = "".join(open(p, encoding="utf-8", errors="replace").read() for p in files)
    # net.rs moved to crates/filament-transport on 2026-08-27. This guard READS
    # the source to keep the model calibrated against it, so a file move breaks
    # it loudly, which is how the move was caught. Try the current home, fall
    # back to the old one so the guard still works on older checkouts.
    net_paths = [
        os.path.join(ROOT, "crates", "filament-transport", "src", "net.rs"),
        os.path.join(ROOT, "cli", "src", "net.rs"),
    ]
    net_path = next((p for p in net_paths if os.path.exists(p)), None)
    if net_path is None:
        raise SystemExit(
            "stall-ladder guard: cannot find net.rs in any known location "
            f"({net_paths}). This guard calibrates against the source, so it "
            "must be pointed at the file rather than skipped."
        )
    net = open(net_path).read()
    attempts = re.search(r"const\s+MAX_ATTEMPTS:\s*u32\s*=\s*(\d+)", main)
    watchdog = re.search(r"pub\s+const\s+WATCHDOG_SECS:\s*u64\s*=\s*(\d+)", net)
    if not attempts or not watchdog:
        raise SystemExit("LADDER COHERENCE FAILED: could not find MAX_ATTEMPTS or WATCHDOG_SECS")
    return int(attempts.group(1)), int(watchdog.group(1))


def coherence_guard():
    source_attempts, source_watchdog = source_ladder_constants()
    if (source_attempts, source_watchdog) != (MAX_ATTEMPTS, WATCHDOG_SECS):
        raise SystemExit(
            "LADDER COHERENCE FAILED: source changed to "
            f"MAX_ATTEMPTS={source_attempts}, WATCHDOG_SECS={source_watchdog}; "
            "recalibrate this model before changing its constants"
        )
    print(f"COHERENCE: source MAX_ATTEMPTS={source_attempts}, WATCHDOG_SECS={source_watchdog}")


@dataclass(frozen=True)
class Environment:
    transience: str
    failure_type: str
    discarded_state: frozenset[str]


@dataclass(frozen=True)
class Result:
    recovered: bool
    attempts: int
    elapsed_secs: int
    terminal: str


WINDOWS = ((0.5, "0.5"), (1.0, "1"), (2.0, "2"), (3.0, "3"), (5.0, "5"), (6.0, "5+"))


def candidate_result(window, fix, retention_bounded):
    """Evaluate the two candidate fixes without using transfer completion as a clock."""
    if fix == "fail-fast":
        return False, "hard-fail"
    if not retention_bounded:
        return False, "unsafe-unbounded-retention"
    return window <= MAX_ATTEMPTS, ("recovered" if window <= MAX_ATTEMPTS else "hard-fail")


def candidate_sweep(retention_bounded):
    rows = []
    for window, label in WINDOWS:
        fail_fast = candidate_result(window, "fail-fast", retention_bounded)
        preserve = candidate_result(window, "preserve-state", retention_bounded)
        rows.append((label, fail_fast, preserve, fail_fast[0] != preserve[0]))
    return rows


def sweep_guard():
    bounded = candidate_sweep(True)
    divergent = [label for label, _, _, differs in bounded if differs]
    expected = ["0.5", "1", "2", "3", "5"]
    if divergent != expected:
        raise SystemExit(f"SWEEP FAILED: expected bounded-retention divergence {expected}, got {divergent}")
    if any(differs for _, _, _, differs in candidate_sweep(False)):
        raise SystemExit("SWEEP FAILED: unbounded retention must not recommend preserve-state")


def run_ladder(environment: Environment, attempts=MAX_ATTEMPTS) -> Result:
    """Run the ladder; return whether the ladder itself recovered the transfer."""
    required = FAILURE_STATE[environment.failure_type]
    for rung in range(1, attempts + 1):
        # A persistent condition never clears. A transient condition clears after
        # the first failed cycle, but only retained state can make that useful.
        condition_cleared = environment.transience == TRANSIENT and rung > 1
        state_available = required not in environment.discarded_state
        if condition_cleared and state_available:
            return Result(True, rung, rung * WATCHDOG_SECS, "recovered")
    return Result(False, attempts, attempts * WATCHDOG_SECS, "ladder-exhausted")


CALIBRATIONS = {
    # These observations establish the terminal shape, not transience. Both a
    # persistent condition and a transient condition whose required state was
    # discarded produce five failed rungs.
    "#31 data freeze": Environment(UNDETERMINED, "data-freeze", frozenset({"transport"})),
    # #50 directly observed new sockets, new mapped ports, and invalidated
    # conntrack state on every drop. Whether ICE itself was transient remains
    # unmeasured.
    "#50 NAT ICE": Environment(UNDETERMINED, "ice-connect", frozenset({"ice", "conntrack"})),
    "#38 roster re-adoption": Environment(UNDETERMINED, "roster-re-adoption", frozenset({"roster"})),
}


def gate_0():
    """Reproduce the observed terminal behavior before making recommendations."""
    expected = (False, MAX_ATTEMPTS, MAX_ATTEMPTS * WATCHDOG_SECS)
    failures = []
    for name, observation in CALIBRATIONS.items():
        for transience in (PERSISTENT, TRANSIENT):
            environment = Environment(transience, observation.failure_type, observation.discarded_state)
            result = run_ladder(environment)
            if (result.recovered, result.attempts, result.elapsed_secs) != expected:
                failures.append(f"{name} ({transience}): expected {expected}, got {result}")
    if failures:
        raise SystemExit("GATE 0 FAILED: model does not reproduce observations\n" + "\n".join(failures))
    print("GATE 0: PASS (#31, #50, #38 all exhaust 5 rungs without ladder recovery)")


def explore():
    """Show whether any modeled environment lets a later rung recover."""
    outcomes = []
    all_states = sorted(set(FAILURE_STATE.values()))
    discarded_states = [
        frozenset(subset)
        for size in range(len(all_states) + 1)
        for subset in combinations(all_states, size)
    ]
    for transience, failure_type, discarded in product(
        (PERSISTENT, TRANSIENT),
        sorted(FAILURE_STATE),
        discarded_states,
    ):
        result = run_ladder(Environment(transience, failure_type, discarded))
        outcomes.append((transience, failure_type, bool(discarded), result))
    return outcomes


def main():
    coherence_guard()
    gate_0()
    sweep_guard()
    for name, observation in CALIBRATIONS.items():
        outcomes = [
            run_ladder(Environment(transience, observation.failure_type, observation.discarded_state))
            for transience in (PERSISTENT, TRANSIENT)
        ]
        external = "; #38 later recovery is external roster adoption" if name == "#38 roster re-adoption" else ""
        print(f"{name}: persistent={outcomes[0].terminal}, transient+discarded={outcomes[1].terminal}{external}")

    later_rung_successes = [
        row for row in explore() if row[3].recovered and row[3].attempts > 1
    ]
    print(f"TRANSIENT + RETAINED STATE: later-rung recoveries={len(later_rung_successes)}")
    print("OBSERVED FAILURES: indistinguishable between (a) persistent conditions and (b) transient conditions whose required state the teardown discarded.")
    for bounded in (True, False):
        rows = candidate_sweep(bounded)
        divergent = [label for label, _, _, differs in rows if differs]
        retention = "bounded" if bounded else "unbounded"
        suffix = "" if bounded else " (preserve-state unsafe)"
        print(f"CANDIDATES retention={retention}: divergent windows={divergent or 'none'}{suffix}")
    print("RETENTION PRECONDITION: bounded retention is required before the condition measurement is worth taking.")
    print("RETENTION DECISION: unbounded retention rules out preserve-state WITHOUT AN EXPLICIT LIFETIME BOUND; a bounded variant remains in the divergent set and still requires condition measurement.")
    print("SEPARATING MEASUREMENT: instrument the condition directly (when the ICE pair becomes usable again and when the conntrack entry reappears), not when the file arrives.")
    print("#50 evidence: each drop destroyed ICE progress, sockets, mapped ports, and conntrack state; whether the underlying ICE condition was transient remains unmeasured.")
    print("RECOMMENDATION: bounded retention diverges for windows 0.5-5 rungs; naive unbounded retention is unsafe. Measure the condition directly before choosing fail-fast versus bounded preserve-state.")


if __name__ == "__main__":
    main()
