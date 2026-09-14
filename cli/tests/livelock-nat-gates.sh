#!/usr/bin/env bash
# Livelock gate for #246: the relay fallback must never drop a link that is
# still establishing.
#
# The gate is DIAGNOSTIC and owned (see .github/executable-artifacts.json).
# It is not wired to CI: nothing in .github/workflows runs cli/tests/*-gates.sh,
# and this gate cannot be required until its lab is committed. Register the
# wt-hp2 lab (/root/wt-hp2/lab: netns + real coturn STUN/TURN + two NAT routers
# + netem) with the repo before promoting this to `required`. The #247 rule: a
# gate whose instrument lives outside the repo rots the moment the directory
# does, and a gate that cannot run must be a failure, not a silent skip.
#
# WHAT THIS GATE COVERS
#  - The #246 hazard is a condition on the ladder, not a networking failure:
#    start_direct must never drop a WebRTC link whose peer is still making
#    progress (Peer::is_live: anything but Failed/Closed), and a Normal re-dial
#    must never arm a fresh direct pending while such a link exists. Those
#    invariants are enforced and UNIT-TESTED here (L1,
#    link_dead_and_live_predicates_encode_246, deterministic, runs in cargo
#    test). The unit test is the deterministic home of this gate.
#  - End-to-end (L3): on the remapping cone topology with netem delay+loss a
#    build that violates the invariants shows non-establishment trials, and
#    this build does not. The fixture reproduces the race occasionally on an
#    idle box (2026-08-18: red binary 1/15 fail at delay=100ms loss=3%, 2/15
#    at loss=5%; ~100% under box load mid-teens, chief-ux's original 15/15)
#    and the netem pair is the run that shows it. The gate records the binary
#    sha and host load (LOT) next to every result so a number is never read
#    detached from the conditions that produced it.
#
# WHAT THIS GATE DOES NOT COVER (read before trusting green)
#  - The end-to-end kill's trigger is a queueing race: the peer's announce
#    train must still hold a start_direct-triggering event at the moment the
#    fallback's establish begins. On an idle box that alignment is rare; under
#    load it is ~certain. The netem pair therefore does NOT redden reliably on
#    an idle box, so it is not a pass/fail gate on the red side. The FIXED
#    side asserts the two mechanism signatures only: no fallback re-offer and
#    no link_dead killer drop. Delivery is reported beside the LOT, not
#    asserted: #252 is an independent C3 watchdog handoff race. The
#    deterministic red is the L1 unit test (first fix, it must fail and the
#    fixed predicate must pass).
#  - The boundary on "still live" is not proved here: New/Connecting are
#    bounded by the C3 establishment watchdog (WATCHDOG_SECS=15s, Ev::Stuck),
#    Disconnected by on_pc_state's grace timer (6s or away+15s,
#    Ev::GraceExpired), both generation-keyed. A regression of those timers
#    would not be caught by this gate.
set -uo pipefail

LAB=/root/wt-hp2/lab
[ -d "$LAB" ] || { echo "FATAL: netns transport lab not found at $LAB (needed for L2/L3; L1 still runs)"; exit 2; }

BIN="${FILAMENT_BIN:-/root/246-fix-target/release/filament}"
RED_BIN="${FILAMENT_RED_BIN:-}"
TRIALS="${LIVELOCK_TRIALS:-15}"
DELAY_MS="${LIVELOCK_DELAY_MS:-100}"
LOSS_PCT="${LIVELOCK_LOSS_PCT:-3}"
SEND_TIMEOUT="${LIVELOCK_SEND_TIMEOUT:-90}"

fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "  ok: $*"; }

echo "=== #246 livelock gate ==="
echo "BIN: $(sha256sum "$BIN" | cut -d' ' -f1)  $BIN"
"$BIN" --version 2>/dev/null | head -1
echo "DATE: $(date -Is)"
echo "LOT: $(uptime)  /  $(free -m | awk '/Mem:/{print $2"MB total, "$7"MB available"}')"

# The invariants. Log-level, on the FIXED build, deterministic:
#  (a) no DIRECT-OFFER may be born after a DIRECT-FALLBACK has fired for the
#      same peer in the same trial. A re-dial that proceeded to offer while a
#      fallback link is establishing is the born-pending hazard: its own 5s
#      budget re-enters establish and swaps the still-establishing link.
#  (b) the link_dead killer site must not fire. Resolve the tracked caller
#      from this source tree rather than pinning a line number that silently
#      goes stale when unrelated code shifts the file.
assert_fixed_invariants() {
  local work="$1" tag="$2"
  local reoffers
  # (a) a DIRECT-OFFER line whose line number is greater than the FIRST
  # DIRECT-FALLBACK line, within the same send or recv log.
  reoffers=$(for f in "$work"/send-"$tag"*.log "$work"/recv-"$tag"*.log; do
    [ -f "$f" ] || continue
    local fb of
    fb=$(grep -n "DIRECT-FALLBACK" "$f" | head -1 | cut -d: -f1)
    [ -n "${fb:-}" ] || continue
    of=$(grep -n "DIRECT-OFFER sent" "$f" | awk -F: 'int($1)>int('"$fb"'){print $0}')
    [ -n "${of:-}" ] && echo "$f: $of"
  done)
  [ -z "$reoffers" ] || fail "tag $tag: DIRECT-OFFER after DIRECT-FALLBACK (born-pending hazard) in: $reoffers"
  ok "no re-offer after fallback"
  local killer_line kills killer_src
  # link_dead_for lived in main.rs until the 2026-09-12 decomposition moved it
  # to conn.rs; search both, first hit wins.
  killer_src=""
  for _f in "$L1_CARGO_DIR/cli/src/conn.rs" "$L1_CARGO_DIR/cli/src/main.rs"; do
    killer_line=$(awk '/link_dead_for\(/ { armed=1 } armed && /self\.drop_link\(pid\);/ { print NR; exit }' "$_f")
    if [ -n "$killer_line" ]; then killer_src="$_f"; break; fi
  done
  [ -n "$killer_line" ] || fail "could not locate the link_dead killer site"
  killer_rel="src/${killer_src##*/cli/src/}"
  kills=$(grep -h "ordered by ${killer_rel}:${killer_line}:" "$work"/send-"$tag"*.log "$work"/recv-"$tag"*.log 2>/dev/null | wc -l)
  [ "${kills:-0}" -eq 0 ] || fail "tag $tag: killer drop (${killer_rel}:${killer_line}) present, $kills hits"
  ok "no link_dead killer drop"
}

# L1: the predicate. Deterministic; a broken build fails this before any
# networking runs.
L1_CARGO_DIR="${LIVELOCK_CARGO_DIR:-}"
[ -n "$L1_CARGO_DIR" ] || L1_CARGO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
echo "=== L1: predicate invariants (cargo test) ==="
OUT=$( ( cd "$L1_CARGO_DIR/cli" && cargo test --release --bin filament link_dead_and_live_predicates_encode_246 --quiet ) 2>&1 )
echo "$OUT" | tail -2
echo "$OUT" | grep -q "test result: ok.* 1 passed" && ok "link_dead/live predicates hold (the killer is unreachable by construction)" \
  || fail "L1 predicate unit test did not pass (broken on the #246 defect)";

echo "=== L2/L3: end-to-end, fixed binary, $TRIALS trials (delay=${DELAY_MS}ms loss=${LOSS_PCT}%, send timeout ${SEND_TIMEOUT}s) ==="
RUN_LOG=$(mktemp /tmp/livelock-gate.XXXX.log)
{
  echo "### remapping run trials=${TRIALS} delay=${DELAY_MS}ms loss=${LOSS_PCT}%"
  WAN_DELAY_MS="$DELAY_MS" WAN_LOSS="$LOSS_PCT" FILAMENT_BIN="$BIN" \
    FILAMENT_SEND_TIMEOUT="$SEND_TIMEOUT" timeout 3600 "$LAB/run.sh" remapping gate-fixed "$TRIALS"
} >"$RUN_LOG" 2>&1
grep -E "trial |topology|natprobe|paired" "$RUN_LOG"
WORK=$(grep "logs:" "$RUN_LOG" | tail -1 | awk '{print $NF}')
[ -n "$WORK" ] || fail "no work dir from the fixed run"
GREP=$(grep -E "trial [0-9]+:" "$RUN_LOG")
BAD=$(echo "$GREP" | grep -cE "\|no\|" || true)
echo "$GREP"
echo "  delivery context: $((TRIALS - BAD))/$TRIALS (${BAD:-0} non-establishment; not a #246 verdict)"
assert_fixed_invariants "$WORK" gate-fixed

echo "=== control: relay alone at the same params (FILAMENT_DIRECT=0) ==="
{
  echo "### remapping gate-ctrl trials=3 delay=${DELAY_MS}ms loss=${LOSS_PCT}% DIRECT=0"
  WAN_DELAY_MS="$DELAY_MS" WAN_LOSS="$LOSS_PCT" FILAMENT_BIN="$BIN" \
    FILAMENT_SEND_TIMEOUT="$SEND_TIMEOUT" timeout 1500 "$LAB/run.sh" remapping gate-ctrl 3 FILAMENT_DIRECT=0
} >"$RUN_LOG.ctrl" 2>&1
grep -E "trial |PAIRING" "$RUN_LOG.ctrl" || true
grep -q "PAIRING-FAILED" "$RUN_LOG.ctrl" && fail "control: pairing failed (fixture flake, not a product result); treat the block as INC, not green"
CTRL_BAD=$(grep -E "trial [0-9]+:" "$RUN_LOG.ctrl" | grep -cE "\|no\|" || true)
echo "  relay-only delivery context: $((3 - CTRL_BAD))/3 (${CTRL_BAD:-0} non-establishment; not a #246 verdict)"

# Comparative red smear (INFORMATIONAL, not a hard assertion: the race fires
# probabilistically on this box when idle). Prints the rows so a reviewer can
# see the mechanism when it does fire, and records the load at which it did.
if [ -n "$RED_BIN" ]; then
  echo "=== comparison: RED binary at the same params (informational; probabilistic on idle) ==="
  {
    echo "### remapping gate-red trials=${TRIALS} delay=${DELAY_MS}ms loss=${LOSS_PCT}%"
    WAN_DELAY_MS="$DELAY_MS" WAN_LOSS="$LOSS_PCT" FILAMENT_BIN="$RED_BIN" \
      FILAMENT_SEND_TIMEOUT="$SEND_TIMEOUT" timeout 3600 "$LAB/run.sh" remapping gate-red "$TRIALS"
  } >"$RUN_LOG.red" 2>&1
  RWORK=$(grep "logs:" "$RUN_LOG.red" | tail -1 | awk '{print $NF}')
  echo "RED LOT was: $(uptime)"
  grep -E "trial |logs:" "$RUN_LOG.red"
  REDBAD=$(grep -E "trial [0-9]+:" "$RUN_LOG.red" | grep -cE "\|no\|" || true)
  echo "  red non-establishment: ${REDBAD:-0}/$TRIALS (informational)"
  ROFF=$(for f in "$RWORK"/send-gate-red*.log "$RWORK"/recv-gate-red*.log; do
    [ -f "$f" ] || continue
    grep -q "DIRECT-OFFER sent" "$f" || continue
    fb=$(grep -n "DIRECT-FALLBACK" "$f" | head -1 | cut -d: -f1)
    [ -n "${fb:-}" ] || continue
    grep -q "DIRECT-OFFER sent" <(sed -n "$((fb+1)),\$p" "$f") && echo "  re-offer in $f"
  done)
  [ -z "$ROFF" ] || echo "  born-pending re-offers seen: $ROFF"
fi

echo
echo "=== PASS: L1 predicate holds (killer unreachable by construction); fixed binary has no fallback re-offer or link_dead killer drop ==="
echo "next reader note: a gate that only reddens under box load is a coin flip wearing a pass/fail label. The deterministic assertion lives in L1; L2/L3 are evidence, not a verdict. If the watchdog timers (net.rs WATCHDOG_SECS, on_pc_state grace) regress, this gate stays green: they are covered elsewhere."
