#!/usr/bin/env bash
# Certificate revocation against a CERTIFIED fleet device, live. Standalone,
# hermetic, fixture port 8121 ONLY.
#
#   FILAMENT_BIN=/path/to/filament ./fleet-cert-gates.sh
#
# WHY THIS EXISTS. Every other shell-class gate in this directory pairs its two
# daemons by hand-writing a shared secret into both devices.json files. A
# secret-paired link never resolves a device IDENTITY, so `cert_revoked_for`
# is asked about `None` and answers false by design (identity_state.rs: an
# unidentified peer is unidentified, not revoked). The gate input
# `cert_revoked` was therefore pinned to false in every live harness, and the
# one guarantee that matters most -- revoking a device's CERTIFICATE ends its
# access -- could only be asserted unit-level, over fabricated inputs
# (shell_gate.rs `exec_matches_pty_across_gate_matrix`). That was recorded as
# verdict debt rather than covered.
#
# So this harness enrols through the REAL product path instead:
#
#   owner:  filament init                      mints the user identity + SSH CA
#   owner:  filament up                        the acceptor
#   owner:  filament add --for <spoke> --allow shell --out <file>
#                                              a signed, bounded invitation
#   spoke:  filament join --invite-file <file> claims it; both ends persist certs
#   spoke:  filament up                        the second daemon
#
# Nothing is hand-provisioned: no secret is written by this script, no
# certificate is fabricated, no cap store is edited. `assert_certified` (in
# lib/fixture.sh) proves that before any gate runs.
#
# THE REVOCATION IS THE CERTIFICATE'S, NOT THE GRANT'S. `filament revoke
# <device> --certificate` writes the durable `certRevoked` marker
# (identity_state.rs `set_device_revoked`) and touches nothing else -- gate B
# asserts exactly that by diffing the store, so a reader can see that the
# spoke's shell authority (its enrolment ceiling) is still fully in place when
# gates C/D/E refuse it. The refusal can only be the certificate.
#
# NOTE ON `grant`. A certified device's shell authority comes from the ceiling
# on its fleet certificate, and `filament grant <delegated-device> shell` is
# refused on purpose (#226, covered by cap-verbs-gates.sh gate A): a grant
# cannot widen a signed ceiling. So the positive control here is the ceiling,
# which IS the product path for a fleet device, and `grant` is deliberately
# never called.
#
# Gates:
#   enrolment x3  both ends resolved a certified identity (lib/fixture.sh)
#   A   POSITIVE exec    -- the certified spoke runs a remote command, rc=0
#   A2  POSITIVE shell   -- and opens a remote shell (the pty path)
#   A3  POSITIVE ssh-sign-- and the owner SIGNS an ssh certificate for it
#   B   the revoke changes ONLY certRevoked; the shell ceiling survives it
#   C   NEGATIVE exec    -- refused, nonzero, "revoked" on both ends
#   D   NEGATIVE shell   -- refused, nonzero, reason
#   E   NEGATIVE ssh-sign-- refused AT THE GATE (owner log names the reason)
#   F   no ssh key was installed anywhere by A3/E (authorized_keys byte-equal)
#   G   A/B CONTROL: `devices restore` and exec works again -- so C/D/E were
#       the revocation and not a broken link, a dead daemon or a lost secret.
#
# G is the gate that stops this suite passing for the wrong reason. Without it
# "everything is refused after the revoke" is equally satisfied by a harness
# that simply broke its own link.
#
# PLATFORM: unix-only in practice (ss, /bin/echo, the fixture backend), like
# every other *-gates.sh here. The property is platform-independent.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8121
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-fleet-cert.XXXXXX")"
DA="$WORK/owner"
SPOKE=spoke
DS="$WORK/$SPOKE"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

# `shell --ssh` must never reach a real sshd: the dial port is redirected to
# the discard port so the SIGNING half (the part these gates are about) runs
# and the login half fails fast, touching nothing on the host.
SSH_ENV=(env FILAMENT_NO_L3_SSH=1 FILAMENT_SSH_PORT=9)
AK_FILE="$HOME/.ssh/authorized_keys"
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$WORK/ak.before" || : > "$WORK/ak.before"

O_ENV=(env FILAMENT_CONFIG_DIR="$DA")
S_ENV=(env FILAMENT_CONFIG_DIR="$DS")

start_backend
init_owner "$DA"
start_acceptor "$DA"

# The enrolment ceiling carries shell: that, and only that, is what authorises
# the positive gates below. `--allow` replaces the default ceiling, so transfer
# is named explicitly rather than lost.
enroll_delegate "$SPOKE" --allow shell,transfer
start_spoke "$DS" "$SPOKE"
# Warm links + the owner's roster tick.
sleep 6

say "enrolment: a certified fleet relationship, built by the product"
assert_certified "$DA" "$DS" "$SPOKE"

# ===================================================================== GATE A ==
say "A: certified spoke runs a remote command"
OUTA=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo FLEET-EXEC-OK 2>"$WORK/A.err" </dev/null)
rcA=$?
echo "## (exec) rc=$rcA out='$OUTA'"
if [ "$rcA" = "0" ] && [ "$OUTA" = "FLEET-EXEC-OK" ]; then
  ok "gateA: certified spoke ran a remote exec (rc=0, exact output)"
else
  echo "-- A.err --"; cat "$WORK/A.err"; tail -5 "$WORK/up.log"
  bad "gateA: certified exec did not run (rc=$rcA out='$OUTA')"
fi

# ==================================================================== GATE A2 ==
say "A2: and opens a remote shell (the pty path)"
OUTA2=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" shell alpha -- 'echo FLEET-SHELL-OK' 2>"$WORK/A2.err" </dev/null)
rcA2=$?
echo "## (shell) rc=$rcA2"
if [ "$rcA2" = "0" ] && echo "$OUTA2" | grep -q "FLEET-SHELL-OK"; then
  ok "gateA2: certified spoke opened a remote shell"
else
  echo "-- A2.err --"; cat "$WORK/A2.err"
  bad "gateA2: certified shell did not run (rc=$rcA2)"
fi

# ==================================================================== GATE A3 ==
# The signing half of `shell --ssh`. The login half cannot succeed (the dial
# port is the discard port) and its exit code is deliberately not asserted:
# what is asserted is that the owner's daemon passed the ssh-sign gate and
# ISSUED, which is the third path through shell_gate::decide.
say "A3: the owner signs an ssh certificate for the certified spoke"
timeout 60 "${SSH_ENV[@]}" FILAMENT_CONFIG_DIR="$DS" "$BIN" --server "$SERVER" \
  shell --ssh alpha -- 'echo NO-SSHD-HERE' >"$WORK/A3.out" 2>"$WORK/A3.err" </dev/null
echo "## (ssh sign) rc=$?"
SIGNED_BEFORE=$(grep -c "ssh-ca: signed for '$SPOKE'" "$WORK/up.log")
if [ "$SIGNED_BEFORE" -ge 1 ]; then
  ok "gateA3: owner signed an ssh certificate for the certified spoke"
else
  echo "-- A3.err --"; tail -5 "$WORK/A3.err"
  echo "-- owner log (ssh) --"; grep -i "ssh" "$WORK/up.log" | tail -5
  bad "gateA3: no ssh certificate was issued for '$SPOKE'"
fi

# ===================================================================== GATE B ==
# Revoke the CERTIFICATE. Snapshot the owner's record for the spoke first, so
# the diff below can show that the shell authority is untouched: whatever the
# gates after this refuse, they are not refusing a withdrawn grant.
say "B: revoke the certificate, and only the certificate"
python3 - "$DA/devices.json" "$SPOKE" >"$WORK/rec.before" <<'PY'
import json,sys
rec=[d for d in json.load(open(sys.argv[1])) if d.get("name")==sys.argv[2]][0]
print(json.dumps({"caps":rec.get("caps"),"ceiling":rec.get("principalCeiling"),
                  "certRevoked":rec.get("certRevoked",False),
                  "hasCert":bool(rec.get("deviceCert"))},sort_keys=True))
PY
"${O_ENV[@]}" "$BIN" --server "$SERVER" revoke "$SPOKE" --certificate --yes >"$WORK/revoke.log" 2>&1
rcRev=$?
python3 - "$DA/devices.json" "$SPOKE" >"$WORK/rec.after" <<'PY'
import json,sys
rec=[d for d in json.load(open(sys.argv[1])) if d.get("name")==sys.argv[2]][0]
print(json.dumps({"caps":rec.get("caps"),"ceiling":rec.get("principalCeiling"),
                  "certRevoked":rec.get("certRevoked",False),
                  "hasCert":bool(rec.get("deviceCert"))},sort_keys=True))
PY
echo "## before: $(cat "$WORK/rec.before")"
echo "## after:  $(cat "$WORK/rec.after")"
if [ "$rcRev" = "0" ] \
   && python3 - "$WORK/rec.before" "$WORK/rec.after" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); a=json.load(open(sys.argv[2]))
ok = (b["certRevoked"] is False and a["certRevoked"] is True
      and b["caps"] == a["caps"] and b["ceiling"] == a["ceiling"]
      and "shell" in (a["ceiling"] or []) and a["hasCert"])
sys.exit(0 if ok else 1)
PY
then
  ok "gateB: revoke --certificate set certRevoked and left the shell ceiling intact"
else
  echo "-- revoke.log --"; cat "$WORK/revoke.log"
  bad "gateB: the revoke did not isolate the certificate (rc=$rcRev)"
fi

# ===================================================================== GATE C ==
say "C: the revoked spoke's exec is refused"
OUTC=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo SHOULD-NOT-RUN 2>"$WORK/C.err" </dev/null)
rcC=$?
echo "## (exec after revoke) rc=$rcC out='$OUTC'"
if [ "$rcC" != "0" ] \
   && ! echo "$OUTC" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "revoked" "$WORK/C.err" \
   && grep -q "exec refused: device revoked" "$WORK/up.log"; then
  ok "gateC: revoked certificate REFUSED the exec (nonzero, reason on both ends)"
else
  echo "-- C.err --"; cat "$WORK/C.err"
  echo "-- owner log --"; grep -i "refused" "$WORK/up.log" | tail -5
  bad "gateC: revoked exec NOT refused (rc=$rcC out='$OUTC')"
fi

# ===================================================================== GATE D ==
say "D: the revoked spoke's shell is refused"
OUTD=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" shell alpha -- 'echo SHOULD-NOT-RUN' 2>"$WORK/D.err" </dev/null)
rcD=$?
echo "## (shell after revoke) rc=$rcD"
if [ "$rcD" != "0" ] && ! echo "$OUTD" | grep -q "SHOULD-NOT-RUN"; then
  ok "gateD: revoked certificate REFUSED the shell (nonzero, nothing ran)"
else
  echo "-- D.err --"; cat "$WORK/D.err"
  bad "gateD: revoked shell NOT refused (rc=$rcD)"
fi

# ===================================================================== GATE E ==
# The wire refusal for ssh-sign is deliberately generic ("ssh-sign refused")
# so a denied peer cannot oracle which check failed; the REASON goes to the
# owner's log only. So assert there, and assert it names the revocation --
# a refusal from any later stage (CA key, clamp, re-sign ledger) would read
# differently and would not prove the gate ran.
say "E: the revoked spoke's ssh-sign is refused at the gate"
timeout 60 "${SSH_ENV[@]}" FILAMENT_CONFIG_DIR="$DS" "$BIN" --server "$SERVER" \
  shell --ssh alpha -- 'echo SHOULD-NOT-RUN' >"$WORK/E.out" 2>"$WORK/E.err" </dev/null
rcE=$?
SIGNED_AFTER=$(grep -c "ssh-ca: signed for '$SPOKE'" "$WORK/up.log")
echo "## (ssh sign after revoke) rc=$rcE issuances=$SIGNED_BEFORE -> $SIGNED_AFTER"
if [ "$rcE" != "0" ] \
   && ! grep -q "SHOULD-NOT-RUN" "$WORK/E.out" \
   && grep -q "ssh-sign refused: device revoked" "$WORK/up.log" \
   && [ "$SIGNED_AFTER" = "$SIGNED_BEFORE" ]; then
  ok "gateE: revoked certificate REFUSED ssh-sign at the gate (no further issuance)"
else
  echo "-- E.err --"; tail -5 "$WORK/E.err"
  echo "-- owner log (ssh) --"; grep -i "ssh-sign\|ssh-ca" "$WORK/up.log" | tail -5
  bad "gateE: revoked ssh-sign NOT refused at the gate (rc=$rcE issuances=$SIGNED_BEFORE -> $SIGNED_AFTER)"
fi

# ===================================================================== GATE F ==
say "F: nothing was installed in authorized_keys"
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$WORK/ak.after" || : > "$WORK/ak.after"
if cmp -s "$WORK/ak.before" "$WORK/ak.after"; then
  ok "gateF: authorized_keys unchanged by the ssh-cert paths"
else
  echo "-- diff --"; diff "$WORK/ak.before" "$WORK/ak.after" | head -5
  bad "gateF: authorized_keys CHANGED (a cert path installed a key)"
fi

# ===================================================================== GATE G ==
# The control. If C/D/E were refusals for any reason OTHER than the
# revocation -- a dead daemon, a torn-down link, a lost secret -- restoring
# the record cannot bring exec back. It must.
say "G: restore the certificate and the same exec works again"
"${O_ENV[@]}" "$BIN" --server "$SERVER" devices restore "$SPOKE" >"$WORK/restore.log" 2>&1
sleep 8
OUTG=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo FLEET-RESTORED-OK 2>"$WORK/G.err" </dev/null)
rcG=$?
echo "## (exec after restore) rc=$rcG out='$OUTG'"
if [ "$rcG" = "0" ] && [ "$OUTG" = "FLEET-RESTORED-OK" ]; then
  ok "gateG: restore brought the exec back, so C/D/E were the revocation itself"
else
  echo "-- G.err --"; cat "$WORK/G.err"
  echo "-- restore.log --"; cat "$WORK/restore.log"
  bad "gateG: exec did not come back after restore (rc=$rcG out='$OUTG')"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "fleet-cert gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
