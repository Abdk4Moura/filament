#!/usr/bin/env bash
# Ratchet for the deterministic core (#249 item 1, #34).
#
# gates.sh does not currently pass in full: at the time of writing 12 of 22
# report PASS and the rest have named, tracked causes. Two dishonest ways to get
# a green tick from that were rejected:
#
#   continue-on-error  a step that reports success while proving nothing, which
#                      is the exact defect #249 exists to fix
#   a pass-count floor a run can hit "12 passed" with a DIFFERENT twelve, so the
#                      number says nothing about which behaviour still holds
#
# Instead this asserts, by name, that every gate KNOWN to work still works. A
# regression in any of them fails the build. A still-broken gate does not,
# because it was already broken and this job is not where that gets discovered.
#
# When a red gate is repaired, add it to EXPECTED_GREEN in the same commit. The
# list only ever grows; that is the ratchet. Removing an entry needs a reason in
# the commit message, because it means a behaviour that used to hold no longer
# does.
#
# MEASURE THE LIST WHERE THE RATCHET RUNS. The first version of this list was
# measured on the do-vm host and asserted against GitHub runners, and one gate
# differed: "kill-resume: replacement receiver resumed" passes locally and fails
# on a runner. It is deliberately NOT in the list below. The kill half works
# there (the .part reached 20336640 bytes, so the gate's premise held); it is
# the resume half that does not, which makes it environment-sensitive rather
# than deterministic by construction, and an environment-sensitive gate in this
# list makes the job fail for reasons that are not regressions.
#
# It is a candidate to add back once it is understood, not a gate to quietly
# drop. Tracked in #249.
#
# Matching is on a stable SUBSTRING of each gate's ok() text, deliberately not
# the whole line: some carry a measured value ("22.8 MB/s") that varies per run,
# and pinning those would make this fail for the wrong reason.
set -uo pipefail

LOG="${1:-}"
[ -n "$LOG" ] && [ -r "$LOG" ] || { echo "usage: gates-ratchet.sh <gates-output.log>" >&2; exit 2; }

# "<substring of the PASS text>|<substring of the FAIL text>".
#
# A gate almost never announces failure under the name it announces success:
# measured, 10 of the 11 below use a different label, e.g. it passes as
# "active link preserved across same-uid reconnect ..." and fails as
# "flow-preserve (#28)". Matching only the pass-text therefore made a real
# failure indistinguishable from a gate that never ran, and every red here was
# reported as though the gate had vanished. Carrying both labels is what lets
# this say FAILED when the gate failed.
EXPECTED_GREEN=(
  "unit tests|unit tests"
  "pair-code variance/security tests|pair-code tests"
  "code transfer, hashes match|code transfer"
  "code burns on first use|code burn"
  "head mismatch detected, restarted from 0|corruption guard"
  "dir tar + stdin round-trip|dir/stdin"
  "offer declined without consent|consent decline"
  "transferred + hash match within ceiling|bulk transfer"
  "active link preserved across same-uid reconnect|flow-preserve (#28)"
  "deferred drop: flowing link survives its peer-left|deferred-drop (#28 trigger)"
  "stepped-away sender: held|stepped-away wait"
  "U1: created once|u1-implicit-init"
)

# A missing PASS line has three different causes and they want different
# responses: the gate FAILED, the gate never RAN (the suite died earlier, so
# every later gate looks regressed at once), or it FLAKED. The verdict below is
# unchanged - any missing PASS still fails the job - but saying WHICH is the
# difference between a one-command diagnosis and re-reading the whole log.
#
# Measured 2026-08-28: three runs of this suite scored 12, 13 and 11 of the
# expected-green gates, where the 11 differed from the 13 by one file
# (.gitignore) and nothing else. So a red here is not on its own evidence that
# the tree changed for the worse, and the message should not imply that it is.
missing=0
not_run=0
for entry in "${EXPECTED_GREEN[@]}"; do
  want="${entry%%|*}"
  fail_label="${entry#*|}"
  if grep -aq "^PASS:.*$want" "$LOG"; then
    printf '  ok         %s\n' "$want"
  elif grep -aqF "FAIL: $fail_label" "$LOG"; then
    # It ran and it failed. This is the case that actually wants attention.
    printf '  FAILED     %s\n' "$want"
    missing=$((missing + 1))
  else
    # No PASS and no FAIL under either name: the gate produced no verdict, which
    # usually means the suite died before reaching it and every later gate will
    # look the same way.
    printf '  NO VERDICT %s (did it run?)\n' "$want"
    missing=$((missing + 1))
    not_run=$((not_run + 1))
  fi
done

green=$(grep -ac '^PASS:' "$LOG" || true)
red=$(grep -ac '^FAIL:' "$LOG" || true)
printf '\n%s of %s expected-green gates held; run reported %s PASS / %s FAIL\n' \
  "$(( ${#EXPECTED_GREEN[@]} - missing ))" "${#EXPECTED_GREEN[@]}" "$green" "$red"

if [ "$missing" -gt 0 ]; then
  echo "FAIL: $missing gate(s) that used to pass no longer do. That is a regression, not a known-red gate." >&2
  if [ "$not_run" -gt 0 ]; then
    echo "NOTE: $not_run produced NO verdict at all, neither pass nor fail. That usually" >&2
    echo "      means the suite died before reaching them, which marks every later gate" >&2
    echo "      at once. Check the end of the run before treating them as regressions." >&2
  fi
  echo "NOTE: this suite is known to flake (the historical 'docs/archive/handoffs/WORK-STATE-2026-09-03.md' §1i: 12/13/11 of the" >&2
  echo "      expected-green gates across three runs, one of which differed only in" >&2
  echo "      .gitignore). Confirm against a re-run before concluding the tree broke." >&2
  exit 1
fi
echo "ratchet held. Known-red gates remain red and are tracked in #249; this job does not police them."
