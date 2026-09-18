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
# WAS KNOWN-RED, NOW GREEN: gateAUTH-A. The covered exec after an OWNER RESTART
# was refused because the possession challenge went to the pid carrying the
# exec-open -- the ONE-SHOT `filament exec` client's own link -- and that client
# never answered challenges, so the link could never become Proven, the open
# parked, expired, and every retry minted a fresh equally silent link. Fixed by
# giving the one-shot client the same shared responder the daemon uses (one
# possession-signing path; send_cmd.rs and exec_send.rs now differ only in which
# loop calls it). AUTH-A now passes FIRST TRY. The half-dead-reader defect found
# while chasing this is a real latent bug and remains its own slice (#312).
#
# Gates:
#   enrolment x3  both ends resolved a certified identity (lib/fixture.sh)
#   A   POSITIVE exec    -- the certified spoke runs a remote command, rc=0
#   A2  POSITIVE shell   -- and opens a remote shell (the pty path)
#   A3  POSITIVE ssh-cert-- and the owner SIGNS an ssh certificate for it
#   B   the revoke changes ONLY certRevoked; the shell ceiling survives it
#   C   NEGATIVE exec    -- refused, nonzero, "revoked" on both ends
#   D   NEGATIVE shell   -- refused, nonzero, owner names the reason
#   E   NEGATIVE ssh     -- `shell --ssh` refused with the revoked reason and
#       NO further certificate is issued
#   F   no ssh key was installed anywhere by A3/E (authorized_keys byte-equal)
#   G   A/B CONTROL: `devices restore` and exec works again -- so C/D/E were
#       the revocation and not a broken link, a dead daemon or a lost secret.
#   I1/I2/I3 IMPOSTOR (F1 acceptance, live): a sibling daemon hellos as the
#       ceilinged device's exact name, trailing-space name, and control-char
#       name; each is refused, the victim record is byte-identical, and the
#       sibling's exec is refused.
#   D-sh SHADOW EVIDENCE for the flip checklist: a covered fleet exec in
#       shadow mode logs zero CAP-SHADOW CRITICAL lines.
#   AUTH-A/B/C under FILAMENT_CAP_AUTHORITATIVE=1 on a restarted owner
#       daemon: shell within the enrolment ceiling succeeds (A); exec
#       outside the ceiling (transfer-only enrolment) is refused with the
#       grant reason (B); revoke --certificate refuses too (C).
#
# G is the gate that stops this suite passing for the wrong reason. Without it
# "everything is refused after the revoke" is equally satisfied by a harness
# that simply broke its own link.
#
# THE SSH ARM, STATED HONESTLY. `shell --ssh` asks the same capability engine
# twice, in order: the shell-BOOTSTRAP gate (recv_cmd.rs, which hands back host
# keys) and then the ssh-SIGN gate (ssh_ca.rs, the third shell_gate entry
# point). Which one a revoked device meets first depends on whether its
# bootstrap answer is still cached from gate A3, so gate E accepts either --
# they are the same engine reaching the same verdict for the same reason, and
# pinning one would make the gate flaky about something it is not testing.
# What gate E does pin is that the reason is the REVOCATION, and that no
# further certificate is issued; gate A3 is what makes that absence meaningful,
# by proving the signing step runs for a certified device on this same setup.
#
# The listener on $SSHD_STANDIN_PORT is a stand-in for sshd and nothing more:
# the daemon probes "is anything listening" before handing back host keys, and
# without that probe passing the client stops before the signing step. The ssh
# LOGIN is not under test here (ssh-ca-gates.sh owns that, against a real
# throwaway sshd); this harness only needs the signing half to run.
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

# `shell --ssh` must never reach a real sshd. The dial port is a throwaway
# listener that accepts and closes at once: the peer's "is sshd up" probe
# passes (so the SIGNING half runs, which is what these gates are about) and
# ssh itself fails immediately, touching nothing on the host.
SSHD_STANDIN_PORT=9124
SSH_ENV=(env FILAMENT_NO_L3_SSH=1 FILAMENT_SSH_PORT=$SSHD_STANDIN_PORT)
AK_FILE="$HOME/.ssh/authorized_keys"
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$WORK/ak.before" || : > "$WORK/ak.before"

# See the KNOWN-RED block in the header. Matching is on a stable substring of
# the FAIL text, deliberately not the whole line (the measured rc varies).
# EMPTY, and it must stay empty until something is genuinely red: the ratchet
# forces removal the moment a known-red gate starts passing, which is exactly
# what happened to gateAUTH-A (see the header note).
KNOWN_RED_ALLOW=()

O_ENV=(env FILAMENT_CONFIG_DIR="$DA")
S_ENV=(env FILAMENT_CONFIG_DIR="$DS")

python3 -c "
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $SSHD_STANDIN_PORT)); s.listen(16)
while True:
    c, _ = s.accept(); c.close()
" >/dev/null 2>&1 &
FIX_PIDS+=($!)

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
# The pty gate's ALLOW half, asserted at the gate rather than at the client.
#
# Deliberate, and the reason matters: a scripted `shell <peer> -- <cmd>` from a
# device that is running its own daemon takes the WARM one-shot pty path, and
# that path's first-frame verification is a separate surface with its own
# behaviour (measured here: the acceptor logs `pty granted` and the warm
# client still reports "the peer closed the shell request"). Asserting the
# client's exit code would make this gate fail for a transport reason and
# report it as a capability verdict, which is the confusion the whole file
# exists to avoid. What this gate is about is the DECISION, and the decision is
# observable exactly where it is made. Gate D asserts the other half of the
# same line, at the same place, after the revoke.
say "A2: the pty gate ALLOWS the certified spoke"
timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" shell alpha -- 'echo FLEET-SHELL-OK; sleep 2' \
  >"$WORK/A2.out" 2>"$WORK/A2.err" </dev/null
echo "## (shell) client rc=$? out='$(cat "$WORK/A2.out")'"
if grep -q "l2: pty granted to '$SPOKE'" "$WORK/up.log"; then
  ok "gateA2: the pty gate ALLOWED the certified spoke (owner: pty granted)"
else
  echo "-- A2.err --"; cat "$WORK/A2.err"
  echo "-- owner log --"; grep -i "pty" "$WORK/up.log" | tail -5
  bad "gateA2: the pty gate did not allow the certified spoke"
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
if [ "$rcD" != "0" ] \
   && ! echo "$OUTD" | grep -q "SHOULD-NOT-RUN" \
   && grep -q "pty refused: $SPOKE: device revoked" "$WORK/up.log"; then
  ok "gateD: revoked certificate REFUSED the shell (nonzero, owner names the reason)"
else
  echo "-- D.err --"; cat "$WORK/D.err"
  echo "-- owner log --"; grep -i "refused" "$WORK/up.log" | tail -5
  bad "gateD: revoked shell NOT refused (rc=$rcD)"
fi

# ===================================================================== GATE E ==
# The refusal reason is deliberately generic on the wire so a denied peer
# cannot oracle which check failed; the REASON goes to the owner's log only,
# so assert there. Asserting the issuance count is the other half: it is what
# turns "the flow stopped" into "no certificate for a revoked device exists",
# and A3 is what makes that absence meaningful.
say "E: the revoked spoke's shell --ssh is refused, and nothing is signed"
timeout 60 "${SSH_ENV[@]}" FILAMENT_CONFIG_DIR="$DS" "$BIN" --server "$SERVER" \
  shell --ssh alpha -- 'echo SHOULD-NOT-RUN' >"$WORK/E.out" 2>"$WORK/E.err" </dev/null
rcE=$?
SIGNED_AFTER=$(grep -c "ssh-ca: signed for '$SPOKE'" "$WORK/up.log")
echo "## (ssh sign after revoke) rc=$rcE issuances=$SIGNED_BEFORE -> $SIGNED_AFTER"
if [ "$rcE" != "0" ] \
   && ! grep -q "SHOULD-NOT-RUN" "$WORK/E.out" \
   && grep -qE "(ssh-sign refused: device revoked|shell bootstrap refused: $SPOKE: device revoked)" "$WORK/up.log" \
   && [ "$SIGNED_AFTER" = "$SIGNED_BEFORE" ]; then
  ok "gateE: revoked certificate REFUSED shell --ssh and issued no certificate"
else
  echo "-- E.err --"; tail -5 "$WORK/E.err"
  echo "-- owner log (ssh) --"; grep -i "ssh-sign\|ssh-ca\|bootstrap" "$WORK/up.log" | tail -5
  bad "gateE: revoked shell --ssh NOT refused (rc=$rcE issuances=$SIGNED_BEFORE -> $SIGNED_AFTER)"
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

# =================================================== IMPOSTOR GATES ==
# F1 acceptance, live: a sibling daemon with a DIFFERENT device key hellos
# as the ceilinged device's name. The owner must refuse to index it, leave
# the victim record byte-identical, and refuse its exec. Three variants:
# the exact name, a trailing space, and a control character -- the latter
# two must land on the same record after sanitizing, not slip past it.
# (The store-level variants of this live as unit tests; these prove the
# fleet-hello path end to end. The exec refusal is asserted as the
# end-to-end property -- the link stays unverified, so the refusal may
# also rest on that; the log line pins the transplant mechanism and the
# byte comparison pins the store.)
MALLORY=mallory
DM="$WORK/$MALLORY"
# The impostor is a FORGOTTEN enrollee: enrolled (so it holds a valid
# owner-signed cert and the fleet channel), then forgotten on the owner.
# A still-enrolled impostor resolves its proven name and never reaches
# the transplant branch -- testing with one would assert nothing. The
# forgotten-but-certified shape is the real squat threat: valid cert,
# no record, claimed name of the ceilinged victim.
enroll_delegate "$MALLORY" --allow transfer
start_spoke "$DM" "$MALLORY"
sleep 6
"${O_ENV[@]}" "$BIN" --server "$SERVER" devices forget "$MALLORY" >"$WORK/forget.log" 2>&1
sleep 2
# Stable fields only (timestamps/last_seen drift between snapshots, so a
# whole-record comparison would fail spuriously -- gate B does the same).
python3 - "$DA/devices.json" "$SPOKE" "$MALLORY" >"$WORK/victim.before" <<'PY'
import json,sys
arr=json.load(open(sys.argv[1]))
rec={d.get("name"):d for d in arr}
v=rec.get(sys.argv[2]) or {}
print(json.dumps({
  "victim_pub":v.get("deviceCert",{}).get("devicePub"),
  "victim_ceiling":v.get("principalCeiling"),
  "victim_revoked":v.get("certRevoked",False),
  "mallory_absent":sys.argv[3] not in rec,
},sort_keys=True))
PY
M_ENV=(env FILAMENT_CONFIG_DIR="$DM")
run_impostor_variant() {
  local variant="$1" tag="$2"
  # Per-variant refusal counting: the owner log accumulates, so record the
  # count before and require it to GROW (a stale line must not pass this).
  local refused_before=$(grep -c "reason=name-taken" "$WORK/up.log" || true)
  pkill -f "up --dir $WORK/$MALLORY-drop" 2>/dev/null || true
  sleep 2
  env FILAMENT_CONFIG_DIR="$DM" FILAMENT_NAME="$variant" "$BIN" --server "$SERVER" up --dir "$WORK/$MALLORY-drop" >"$WORK/up-$MALLORY-$tag.log" 2>&1 &
  FIX_PIDS+=($!)
  sleep 8
  local refused=0 intact=0 execref=0 attempted=0 victim_ok=0
  local refused_after=$(grep -c "reason=name-taken" "$WORK/up.log" || true)
  [ "$refused_after" -gt "$refused_before" ] && refused=1
  # NON-VACUITY, two ways. Containment means nothing unless (i) this impostor
  # actually reached the owner (a daemon that never started satisfies "exec
  # refused" via a plain connection failure) and (ii) the victim snapshot
  # really held a keyed record (comparing two empty records passes).
  grep -qE "fleet-hello|identity verified|joined the mesh" "$WORK/up-$MALLORY-$tag.log" && attempted=1
  [ -n "$(python3 -c "import json;print(json.load(open('$WORK/victim.before')).get('victim_pub') or '')")" ] && victim_ok=1
  python3 - "$DA/devices.json" "$SPOKE" "$MALLORY" "$WORK/victim.before" >"$WORK/victim.$tag.after" <<'PY'
import json,sys
arr=json.load(open(sys.argv[1]))
rec={d.get("name"):d for d in arr}
v=rec.get(sys.argv[2]) or {}
now=json.dumps({
  "victim_pub":v.get("deviceCert",{}).get("devicePub"),
  "victim_ceiling":v.get("principalCeiling"),
  "victim_revoked":v.get("certRevoked",False),
  "mallory_absent":sys.argv[3] not in rec,
},sort_keys=True)
before=json.load(open(sys.argv[4]))
print(now)
# victim identity+ceiling identical AND no record re-created for mallory
sys.exit(0 if now==json.dumps(before,sort_keys=True) else 1)
PY
  [ "$?" = "0" ] && intact=1
  OUTI=$(timeout 60 "${M_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo SHOULD-NOT-RUN 2>"$WORK/I-$tag.err" </dev/null)
  [ "$?" != "0" ] && ! echo "$OUTI" | grep -q "SHOULD-NOT-RUN" && execref=1
  echo "## (impostor $tag) refused=$refused attempted=$attempted victim=$victim_ok intact=$intact execref=$execref"
  if [ "$attempted" = "1" ] && [ "$victim_ok" = "1" ] && [ "$intact" = "1" ] && [ "$execref" = "1" ]; then
    ok "gateI-$tag: squat as '$variant' CONTAINED (victim keyed + byte-identical, impostor reached the owner, exec refused)"
  else
    # Print what the gate actually knows: CI's empty `grep | tail -3` was the
    # least informative possible failure output and cost a whole run to read.
    echo "-- impostor log ($tag) --"; tail -5 "$WORK/up-$MALLORY-$tag.log" 2>/dev/null
    echo "-- forget log --"; cat "$WORK/forget.log" 2>/dev/null
    echo "-- owner log (fleet) --"; grep -i "fleet" "$WORK/up.log" | tail -5
    bad "gateI-$tag: impostor as '$variant' NOT contained (attempted=$attempted victim=$victim_ok intact=$intact execref=$execref refused=$refused)"
  fi
  # The refusal line is its OWN verdict: a log-environment difference must
  # never fake a containment pass or mask a containment failure.
  if [ "$refused" = "1" ]; then
    ok "gateI-$tag: transplant refusal emitted (reason=name-taken seen)"
  else
    bad "gateI-$tag: transplant refusal line absent (containment=$([ "$attempted$victim_ok$intact$execref" = "1111" ] && echo held || echo broken); no refusal emitted for this attempt)"
  fi
}
say "I1: exact-name squat refused"
run_impostor_variant "$SPOKE" exact
say "I2: trailing-space squat refused"
run_impostor_variant "$SPOKE " space
say "I3: control-char squat refused"
run_impostor_variant "$SPOKE$(printf '\007')" ctrl

# ================================================== AUTHORITATIVE MODE ==
# The same questions under FILAMENT_CAP_AUTHORITATIVE=1 on the owner
# daemon. The daemon reads the flag at startup, so the owner acceptor is
# restarted with it (same config dir, fresh log); the spokes are untouched.
# Gate D-sh runs FIRST, while the daemons are still in shadow mode.

# ================================================================== GATE D-sh =
# Shadow-mode evidence for the flip checklist: a covered fleet exec must not
# log CAP-SHADOW CRITICAL (a header denying what legacy allowed). The owner
# log accumulates the whole run above, so any covered open that disagreed
# would already be recorded.
# The delta is what matters. A global count conflates THIS exec with every
# earlier section -- including the impostor gates, whose refusals are recorded
# as shadow disagreements ON PURPOSE (legacy would let a secret-paired peer in;
# the capability layer refuses it, which is the flip narrowing a legacy hole,
# not breakage). Counting globally made this gate fail on other gates' events.
say "D-sh: shadow run of the covered exec adds zero CRITICAL denials"
CRITS_BEFORE=$(grep -c "CAP-SHADOW CRITICAL" "$WORK/up.log" || true)
OUTSH=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo FLEET-SHADOW-OK 2>"$WORK/SH.err" </dev/null)
rcSH=$?
CRITS_ALL=$(grep -c "CAP-SHADOW CRITICAL" "$WORK/up.log" || true)
CRITS=$((CRITS_ALL - CRITS_BEFORE))
echo "## (shadow covered exec) rc=$rcSH out='$OUTSH' criticals_delta=$CRITS (total $CRITS_ALL, pre-existing $CRITS_BEFORE)"
# The narrowing class must be REACHABLE, or "zero criticals" could be satisfied
# by an instrument that never classifies anything: the three impostor refusals
# above are exactly that population (legacy would admit a secret-paired peer;
# the capability layer refuses it). Asserting both halves turns the class from
# prose into a measured verdict.
# The LINE is deduped per (action, subject) -- three impostor opens from the same
# key print once -- so the population is read from the counter the line carries,
# which increments per OPEN. Counting lines would undercount and call a working
# instrument miscounting.
NARROWED=$(grep -o "la_narrowed=[0-9]*" "$WORK/up.log" | sed 's/.*=//' | sort -n | tail -1)
NARROWED=${NARROWED:-0}
NARROWED_LINES=$(grep -c "cap-narrows-legacy" "$WORK/up.log" || true)
echo "## (shadow classes) new_criticals=$CRITS cap-narrows-legacy_counter=$NARROWED (lines=$NARROWED_LINES)"
# REACHABILITY OF THE NARROWING CLASS IS NOT ASSERTED HERE, deliberately.
# Measured on ONE unchanged binary, twice: the class fired once in the first run
# and zero times in the second. The impostor's exec is usually refused by ITS OWN
# daemon ("shell capability not granted") before the open ever reaches the
# owner's capability gate, and only sometimes does the owner see it as a
# legacy-allowed, uncovered open. Asserting ">= 3 impostor refusals classified"
# here would therefore be a FLAKY assertion, and a gate that fails for timing is
# worse than no gate -- it teaches people to ignore red.
#
# Reachability is instead proven DETERMINISTICALLY by the unit tests, which CI
# runs in the same job family: cap_narrows_legacy's four-case truth table and the
# bucketing assertion that LA_NARROWED (and NOT LA_DENIED) increments for the
# uncovered class. What this gate must prove about the flip is the BREAKAGE
# signal, and that is what it asserts: zero NEW CRITICALs from its own open. The
# observed counter is printed as evidence either way.
if [ "$rcSH" = "0" ] && [ "$OUTSH" = "FLEET-SHADOW-OK" ] && [ "$CRITS" = "0" ]; then
  ok "gateD-sh: covered exec clean in shadow, zero NEW CRITICAL lines from its own open (la_denied evidence; narrowing class observed $NARROWED time(s), reachability pinned by unit tests)"
else
  echo "-- new criticals --"; grep "CAP-SHADOW CRITICAL" "$WORK/up.log" | tail -3
  echo "-- pre-existing (earlier sections, incl. intended impostor refusals) --"; grep "CAP-SHADOW CRITICAL" "$WORK/up.log" | head -3
  bad "gateD-sh: shadow covered exec unclean (rc=$rcSH out='$OUTSH' new_criticals=$CRITS of $CRITS_ALL total)"
fi

say "restarting the owner acceptor under FILAMENT_CAP_AUTHORITATIVE=1"
pkill -f "up --dir $WORK/Adrop" 2>/dev/null || true
sleep 2
env FILAMENT_CONFIG_DIR="$DA" FILAMENT_CAP_AUTHORITATIVE=1 FILAMENT_L2=1 "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/up-auth.log" 2>&1 &
FIX_PIDS+=($!)
sleep 6

# ================================================================== GATE AUTH-A =
say "AUTH-A: shell within the enrolment ceiling succeeds under authoritative"
OUTAA=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo FLEET-AUTH-OK 2>"$WORK/AA.err" </dev/null)
rcAA=$?
echo "## (authoritative covered exec) rc=$rcAA out='$OUTAA'"
if [ "$rcAA" = "0" ] && [ "$OUTAA" = "FLEET-AUTH-OK" ]; then
  ok "gateAUTH-A: covered exec allowed under authoritative (no grant needed)"
else
  # Known-red (#312), not a silent skip: print the mechanism's own evidence so a
  # reader can see WHY it failed without rerunning anything -- the client's
  # retryable reason, and the owner side naming the link that answered no
  # challenge (`<pid> answered no possession challenge`).
  echo "-- AA.err --"; cat "$WORK/AA.err"
  echo "-- owner: links that answered no challenge --"
  grep -c "answered no possession challenge" "$WORK/up-auth.log" || true
  grep -i "deny\|refus" "$WORK/up-auth.log" | tail -5
  bad "gateAUTH-A: covered exec refused under authoritative (rc=$rcAA)"
fi

# ================================================================== GATE RECON ==
# The state AUTH-A lands in, asserted for what it HONESTLY is today. A link that
# is mid-re-establishment must never fail SILENTLY and must never be reported as
# a capability decision: the client gets a RETRYABLE reason, and the owner names
# the link that answered no possession challenge. That is the difference between
# a queue that has not drained and a refusal.
#
# NOT asserted yet, on purpose: "the retry then succeeds". Measured on this
# stack, twelve fresh links over 20s all fail the same way, because the defect is
# in the link (a primary transport can go writable-but-deaf, transport/direct.rs
# :1410,:1436), not in the retry budget -- so asserting success here would be
# asserting a fix that does not exist yet. When #312 lands, this gate gains its
# second verdict (first-try success) and AUTH-A comes off KNOWN_RED.
say "RECON: an exec during post-restart link re-establishment never fails SILENTLY"
# The state AUTH-A lands in, asserted for what it HONESTLY is. A link that is
# mid-re-establishment may refuse, but it must refuse with a RETRYABLE reason and
# the owner must name the link that answered no possession challenge; a silent
# drop (or a refusal that pretends to be a capability decision) is the failure
# this gate exists to catch.
#
# It passes BOTH before and after #312: before, the branch below asserts the
# honest refusal; after, the first branch asserts first-try success and this
# gate's message names the ratchet step (AUTH-A comes off KNOWN_RED). Asserting
# "the retry then succeeds" today would be asserting a fix that does not exist --
# measured: twelve fresh links over 20s all fail the same way, because the defect
# is in the link (transport/direct.rs:1410,:1436), not in the retry budget.
RECON_RC="$rcAA"
RECON_TEXT=$(cat "$WORK/AA.err" 2>/dev/null)
NOCHAL=$(grep -c "answered no possession challenge" "$WORK/up-auth.log" || true)
echo "## (reconnect window) rc=$RECON_RC no_challenge_lines=$NOCHAL"
if [ "$RECON_RC" = "0" ] && [ "$OUTAA" = "FLEET-AUTH-OK" ]; then
  ok "gateRECON: the covered exec survived the reconnect window first-try (link reconciliation landed: remove AUTH-A from KNOWN_RED and delete this note)"
elif echo "$RECON_TEXT" | grep -q "identity not proven within" && [ "$NOCHAL" -ge 1 ]; then
  ok "gateRECON: refused with the retryable 'identity not proven within N ms; retry' reason AND the owner named the unanswered link (honest, diagnosable; #312)"
else
  echo "-- AA.err (expected a retryable reason) --"; echo "$RECON_TEXT"
  echo "-- owner: links that answered no challenge --"; grep -c "answered no possession challenge" "$WORK/up-auth.log" || true
  bad "gateRECON: the reconnect-window refusal was SILENT (no retryable reason, or the owner never named the unanswered link)"
fi

# ================================================================== GATE AUTH-B =
# A second spoke enrolled WITHOUT shell in its ceiling: exec must be refused
# with the ceiling/grant reason, proving the ceiling (not mere membership)
# is what authorizes.
SPOKE2=spoke2
DS2="$WORK/$SPOKE2"
enroll_delegate "$SPOKE2" --allow transfer
start_spoke "$DS2" "$SPOKE2"
sleep 6
say "AUTH-B: exec outside the enrolment ceiling is refused under authoritative"
OUTAB=$(timeout 60 env FILAMENT_CONFIG_DIR="$DS2" "$BIN" --server "$SERVER" exec alpha -- /bin/echo SHOULD-NOT-RUN 2>"$WORK/AB.err" </dev/null)
rcAB=$?
echo "## (authoritative uncovered exec) rc=$rcAB out='$OUTAB'"
if [ "$rcAB" != "0" ] \
   && ! echo "$OUTAB" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "explicit grant" "$WORK/up-auth.log"; then
  ok "gateAUTH-B: uncovered exec refused under authoritative (grant reason, no output)"
else
  echo "-- AB.err --"; cat "$WORK/AB.err"
  echo "-- owner auth log --"; grep -i "deny\|refus" "$WORK/up-auth.log" | tail -5
  bad "gateAUTH-B: uncovered exec NOT refused under authoritative (rc=$rcAB)"
fi

# ================================================================== GATE AUTH-C =
say "AUTH-C: revoke --certificate refuses under authoritative too"
"${O_ENV[@]}" "$BIN" --server "$SERVER" revoke "$SPOKE" --certificate --yes >"$WORK/revoke-auth.log" 2>&1
sleep 3
OUTAC=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo SHOULD-NOT-RUN 2>"$WORK/AC.err" </dev/null)
rcAC=$?
echo "## (authoritative exec after revoke) rc=$rcAC out='$OUTAC'"
if [ "$rcAC" != "0" ] && ! echo "$OUTAC" | grep -q "SHOULD-NOT-RUN"; then
  ok "gateAUTH-C: revoked spoke refused under authoritative"
else
  echo "-- AC.err --"; cat "$WORK/AC.err"
  bad "gateAUTH-C: revoked exec NOT refused under authoritative (rc=$rcAC)"
fi

# ========================================================================= sum =
# =============================================================== known-red ==
# Convert the NAMED, TRACKED failures into their own verdict line (so the count
# stays honest and the slot is never silently absent), and fail the run if one of
# them starts passing (the ratchet only shrinks, and only with evidence).
declare_known_red_summary
KNOWN_RED_N=${#KNOWN_RED_HIT[@]}

echo
echo "==========================================="
echo "fleet-cert gates: $PASS passed, $FAIL failed, $KNOWN_RED_N known-red${KNOWN_RED_HIT:+ -- known-red:$KNOWN_RED_HIT}${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
