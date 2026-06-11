#!/usr/bin/env bash
# test_e2e.sh — end-to-end lab tests (NEEDS ROOT; creates + destroys netns).
#
# Proves the baseline for every available carrier and asserts ZERO leaks after
# teardown. Safe: everything is in lab-prefixed namespaces; the host, the running
# filament daemon, and ~/.config/filament are never touched.
#
#   sudo lab/tests/test_e2e.sh            # all carriers
#   sudo lab/tests/test_e2e.sh pipe wg    # a subset
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$LAB_DIR/lab"
TOPO=two-nodes
CARRIERS=("${@:-pipe udp wg filament}")
read -ra CARRIERS <<< "${CARRIERS[*]}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "test_e2e: needs root (netns/tun/wg)." >&2; exit 1
fi

pass=0; fail=0
note() { printf "%s\n" "$*"; }

assert_no_leaks() {
  local ns ifc rel
  ns=$(ls /var/run/netns 2>/dev/null | grep -c '^lab-' || true)
  ifc=$(ip -br link 2>/dev/null | grep -cE 'labtun|labu-|labwg' || true)
  rel=$(ps aux | grep -E 'relay\.py' | grep -v grep | wc -l)
  if [[ "$ns" -eq 0 && "$ifc" -eq 0 && "$rel" -eq 0 ]]; then
    note "  leak-check: OK (no netns/ifaces/relays)"; ((pass++))
  else
    note "  leak-check: FAIL (netns=$ns ifaces=$ifc relays=$rel)"; ((fail++))
  fi
}

# Always start clean.
"$LAB" down --all --purge-logs >/dev/null 2>&1 || true

for link in "${CARRIERS[@]}"; do
  note ""
  note "### carrier: $link ###"
  if ! "$LAB" doctor --link "$link" >/dev/null 2>&1; then
    note "  SKIP $link (doctor failed — missing deps)"; continue
  fi
  if "$LAB" up "$TOPO" --link "$link" >/dev/null 2>&1; then
    note "  up: OK"; ((pass++))
  else
    note "  up: FAIL"; ((fail++)); continue
  fi
  if "$LAB" probe ping "$TOPO" --count 4 >/dev/null 2>&1; then
    note "  ping: OK"; ((pass++))
  else
    note "  ping: FAIL"; ((fail++))
  fi
  # fault: stall must break the path, clear must restore it (skip for speed on
  # carriers where the tun is not the immediate path — but it works for all).
  "$LAB" fault stall "$TOPO" >/dev/null 2>&1
  if ! "$LAB" probe ping "$TOPO" --count 1 >/dev/null 2>&1; then
    note "  stall breaks path: OK"; ((pass++))
  else
    note "  stall breaks path: FAIL (still reachable under 100% loss)"; ((fail++))
  fi
  "$LAB" fault clear "$TOPO" >/dev/null 2>&1
  "$LAB" down "$TOPO" >/dev/null 2>&1
  assert_no_leaks
done

# --all sweep leaves nothing.
"$LAB" down --all --purge-logs >/dev/null 2>&1
note ""
note "==== e2e: $pass passed, $fail failed ===="
exit $(( fail > 0 ? 1 : 0 ))
