#!/usr/bin/env bash
# flake-check: run a test target N times at a fixed thread count and report the
# failure count and wall time. Runs ON THE CODESPACE (feed it via
# `rbuild cs sh "bash -s -- DIR N THREADS [FILTER]" < flake-check.sh`), so the
# disk it checks is the box that actually holds the build.
#
#   usage: flake-check.sh <remote-worktree-dir> [iterations] [threads] [filter]
#   exit:  0 = every iteration clean   1 = some iteration failed   3 = REFUSED
#
# CONVENTION -- the generalisation, of which this script is one implementation:
# a harness that cannot distinguish "the code is broken" from "the box cannot hold
# the build" must REFUSE TO REPORT, with an exit code distinct from both pass and
# fail. Assert your preconditions (free space, a warm toolchain, a free port, a
# writable temp dir) BEFORE measuring, and when one is unmet print a single line
# naming it instead of a number -- because a number produced under a broken
# precondition is indistinguishable from a defect and will be read as one. See the
# exit codes below: 0 = clean, 1 = a real failure, 3 = refused; there is no exit
# code that means "probably fine".
#
# WHY THE PREFLIGHT EXISTS. A full disk makes `cargo test` report failures that
# look exactly like product defects: one run of this check reported 20/20 FAILED
# while the only tell was `No space left on device (os error 28)` buried in the
# log, and nothing in the harness was watching for it. That is the same shape as
# an exit code that cannot fail and a parser whose output looked like data: an
# instrument that is confident and wrong. A check that cannot distinguish "the
# code is broken" from "the box cannot hold the build" must not report a number
# at all, so it REFUSES (exit 3) below the floor instead.
#
# CLEANING, when it refuses: remove only YOUR OWN worktrees' target dirs. On this
# box other agents' worktrees live under /workspaces too, and their build caches
# are not yours to delete.
set -uo pipefail

DIR="${1:?usage: flake-check.sh <remote-dir> [iterations] [threads] [filter]}"
ITER="${2:-20}"
THREADS="${3:-16}"
FILTER="${4:-}"

# 2 GiB. Below this a cold test target cannot be built reliably, and partial
# writes are what produce the product-looking failures. Overridable so the
# refusal itself can be demonstrated (FLAKE_CHECK_FLOOR_KB=999999999 ...).
FREE_FLOOR_KB=$((2 * 1024 * 1024))
FREE_FLOOR_KB="${FLAKE_CHECK_FLOOR_KB:-$FREE_FLOOR_KB}"

avail_kb=$(df -Pk /workspaces | awk 'NR==2 {print $4}')
if [ -z "${avail_kb:-}" ] || [ "$avail_kb" -lt "$FREE_FLOOR_KB" ]; then
  echo "flake-check: REFUSING TO REPORT -- /workspaces has $(( ${avail_kb:-0} / 1024 ))M free," \
       "below the $((FREE_FLOOR_KB / 1024))M preflight floor."
  echo "flake-check: a full disk makes a test target report product-looking failures." \
       "Free space first, and remove only your own worktrees' target dirs."
  exit 3
fi
echo "flake-check: preflight ok ($(( avail_kb / 1024 ))M free), dir=$DIR iters=$ITER threads=$THREADS filter=${FILTER:-<none>}"

cd "/workspaces/$DIR/cli" || { echo "flake-check: no such remote dir /workspaces/$DIR/cli"; exit 3; }

fails=0
total=0
declare -A per_test
for i in $(seq 1 "$ITER"); do
  s=$(date +%s)
  if [ -n "$FILTER" ]; then
    out=$(cargo test --bin filament "$FILTER" -- --test-threads="$THREADS" 2>&1)
  else
    out=$(cargo test --bin filament -- --test-threads="$THREADS" 2>&1)
  fi
  rc=$?
  e=$(date +%s)
  total=$(( total + e - s ))
  if [ "$rc" -ne 0 ]; then
    fails=$(( fails + 1 ))
    echo "iter $i FAILED ($(( e - s ))s)"
    printf '%s\n' "$out" | grep -E 'FAILED|panicked|left:|right:|error' | head -5
    # Attribute the failure to a test so a flake count can never be read as
    # "everything is broken": the name is what makes the number actionable.
    while read -r name; do
      per_test["$name"]=$(( ${per_test["$name"]:-0} + 1 ))
    done < <(printf '%s\n' "$out" | grep -oE '^test [a-z0-9_:]+ \.\.\. FAILED' | awk '{print $2}')
  else
    echo "iter $i ok ($(( e - s ))s)"
  fi
done

echo "flake-check TOTAL: fails=$fails over $ITER iters, mean=$(( total / ITER ))s"
for name in "${!per_test[@]}"; do
  echo "flake-check per-test: $name -> ${per_test[$name]} failure(s)"
done
[ "$fails" -eq 0 ] || exit 1
