# Executable artifact registry

`.github/executable-artifacts.json` assigns every executable under the test,
deployment, and proof roots exactly one disposition:

- `required`: a runnable gate with an explicit platform and topology matrix.
- `diagnostic`: never coverage; requires a real issue, owner, and expiry date.
- `retired`: removed from executable locations, with the reason retained.
- `operational`: installed or manually run on a host rather than used as CI
  coverage.
- `support`: an executable helper consumed by another active registered
  artifact. A helper with no active consumer fails validation.

`scripts/check_artifact_registry.py` derives the inventory recursively from Git
executable bits and first-line shebangs. The scan roots are code constants, not
registry data, so the registry cannot narrow its own enforcement scope. A new
artifact under those roots fails CI until it is classified. An expired
diagnostic also fails CI and must be fixed, deliberately extended, or retired.

Phase 1 covers `cli/tests/`, `deploy/`, and `proofs/`. Repo-wide enumeration was
considered and deferred: it finds 115 candidates instead of 31 and mixes the
coverage problem with product launchers, packaging, experiments, and 26 SVG
assets accidentally stored with mode `100755`. Those mode bits are recorded
here as follow-up inventory, not release work.

The registry also records known gates that return success after a platform skip.
Phase 1 does not repair those verdicts; it keeps the Phase 2 work visible.

## Retired artifacts

- `cli/tests/livelock-nat-gates.sh`: removed because the netns/coturn
  transport lab it needs was never committed and does not exist, so the
  script exits 2 rather than running. Its deterministic content is the
  cargo unit test `link_dead_and_live_predicates_encode_246_without_suppressing_disconnected_recovery`,
  and its end-to-end half only reddens under box load, which its own
  header disclaims as a verdict. Issue #246 is closed.
- `cli/tests/holepunch-gates.sh`: removed because its external transport lab
  was never committed and no longer exists. The finding was established in
  PR #94.
- `cli/tests/reliability_test.sh`: removed because it targeted the hard-coded
  live peer `jade`, did not verify receiver bytes, and normally exited zero even
  when its operations failed. This document is its durable retirement record.
