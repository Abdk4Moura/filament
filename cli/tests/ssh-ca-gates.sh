#!/usr/bin/env bash
# `filament shell --ssh` via local CA, end to end. Standalone, hermetic,
# fixture port 8120 ONLY. No system files are touched: the throwaway sshd
# listens on 127.0.0.1:9123 (reached through the mesh tunnel because
# FILAMENT_SSH_PORT overrides the dial port), with temp hostkeys, temp
# PidFile, temp CA trust. The only host residue is the pre-existing
# managed-key bootstrap block (removable `# BEGIN/END filament-managed`
# in root's authorized_keys -- the same residue any `shell --ssh` leaves).
#
#   FILAMENT_BIN=/path/to/filament ./ssh-ca-gates.sh
#
# Gates:
#   A  POSITIVE cert login -- ephemeral key signed over the mesh, real sshd
#      accepts the cert (no AuthorizedKeysFile configured: cert-only proof),
#      remote command runs, rc=0, exact output.
#   B  NEGATIVE revoked -- after `revoke <dev> shell`, signing is refused
#      (nonzero + reason); no new cert issues.
#
# Topology: side B = signer + sshd host, side A = initiator, reciprocal pair
# secret (same-owner fleet). B's CA key is pre-provisioned at its config dir
# (0600, like production); B's daemon user is root (this harness runs as
# root, shell-user unset -- the same resolution production uses).
#
# PLATFORM NOTE: unix-only in practice (sshd, ssh-keygen, /dev/urandom, ss),
# like the other *-gates.sh harnesses. The wire property (cert auth, no
# installed keys) is platform-independent.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8120
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-ssh-ca-gates.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== ssh-ca gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

# --- own fixture backend on $PORT ---
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
[ -x "$BIN" ] || { echo "build first: FILAMENT_BIN=/path/to/filament"; exit 2; }
command -v sshd >/dev/null || { echo "no sshd on PATH"; exit 2; }
command -v ssh-keygen >/dev/null || { echo "no ssh-keygen on PATH"; exit 2; }
command -v ssh >/dev/null || { echo "no ssh on PATH"; exit 2; }

DA="$WORK/A"; DB="$WORK/B"; mkdir -p "$DA" "$DB"
SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxB","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxA","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"

A_ENV=(env FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=boxA)
B_USER="$(id -un)"
SSH_ENV=(env FILAMENT_NO_L3_SSH=1 FILAMENT_SSH_PORT=9123)

# --- B's CA key (operator-provisioned, 0600, at the default path) ---
mkdir -p "$DB/ssh"
ssh-keygen -q -t ed25519 -f "$DB/ssh/ssh_ca" -N "" -C "test-ca"
chmod 600 "$DB/ssh/ssh_ca"

# --- throwaway sshd on 127.0.0.1:9123 with CA trust ONLY (no
# AuthorizedKeysFile at all: cert auth is the only way in, which is exactly
# what gate A proves). Reached through the mesh tunnel because the dial port
# below overrides the bootstrap default. ---
# The temp sshd below runs on the HOOK-WRITTEN config (product writer output,
# not hand-provisioned trust): base Port/HostKey here, Match block +
# principals + anchor added by up/grant arming through the overrides.
SSHD="$WORK/sshd"; mkdir -p "$SSHD"
mkdir -p /run/sshd 2>/dev/null
SSHD_PORT=9123

# --- B acceptor (daemon user = root via USER; hostkeys pinned to temp) ---
# Hook paths overridden to temp files: up/grant arming writes here (real
# writer code, observable), never to the live /etc/ssh.
HOOK_ENV=(env FILAMENT_SSH_SSHD_CONFIG="$WORK/hooked-sshd-config" FILAMENT_SSH_PRINCIPALS_DIR="$WORK/hooked-principals" FILAMENT_SSH_CA_PUB_ANCHOR="$WORK/hooked-ca.pub")
ssh-keygen -q -t ed25519 -f "$WORK/hooked-hostkey" -N ""
chmod 600 "$WORK/hooked-hostkey"
printf 'Port 9123\nHostKey %s\nListenAddress 127.0.0.1\nPidFile %s\nPasswordAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nStrictModes no\nPermitRootLogin prohibit-password\nLogLevel VERBOSE\n' "$WORK/hooked-hostkey" "$SSHD/sshd.pid" > "$WORK/hooked-sshd-config"
env FILAMENT_L2=1 FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB USER="$B_USER" \
  FILAMENT_SSH_HOSTKEY="$WORK/hooked-hostkey.pub" \
  "${HOOK_ENV[@]}" "$BIN" up --dir "$WORK/Bdrop" --server "$SERVER" >"$WORK/up.log" 2>&1 &
pids+=($!)
sleep 3
env FILAMENT_CONFIG_DIR="$DB" "${HOOK_ENV[@]}" "$BIN" grant boxA shell >"$WORK/grant.log" 2>&1

# A ~10-minute grant window, seeded AFTER the grant (grant rewrites the
# device record and would wipe a pre-seeded capExpires -- gate D caught
# exactly that): the cert clamp must not exceed it (CB-2).
GRANT_NOW=$(date +%s)
GRANT_EXP=$((GRANT_NOW + 600))
python3 - "$DB/devices.json" "$GRANT_EXP" <<'PY2'
import json,sys
p,exp=sys.argv[1],int(sys.argv[2])
arr=json.load(open(p))
for d in arr:
    if d.get("name")=="boxA":
        d.setdefault("capExpires",{})["shell"]=exp
json.dump(arr,open(p,"w"))
PY2
grep -q '"shell"' "$DB/devices.json" || { echo "## grant did not persist"; cat "$DB/devices.json"; }

# --- temp sshd on the PRODUCT-WRITTEN config (proves the writer output works) ---
/usr/sbin/sshd -f "$WORK/hooked-sshd-config" -E "$SSHD/sshd.log" -D &
SSHD_PID=$!
pids+=($SSHD_PID)
sleep 1
ss -tlnp 2>/dev/null | grep -q ":$SSHD_PORT " || { echo "## sshd FAILED (product config?)"; cat "$SSHD/sshd.log"; tail -3 "$WORK/up.log"; exit 2; }

# The ONLY authorized_keys on the box that matters here is root's (the
# temp sshd has no AuthorizedKeysFile line at all). Snapshot it: CB-3
# asserts cert login leaves it byte-identical (no permanent key install).
AK_FILE="$HOME/.ssh/authorized_keys"
AK_BEFORE="$WORK/ak.before"; AK_AFTER="$WORK/ak.after"
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$AK_BEFORE" || : > "$AK_BEFORE"

# ===================================================================== GATE A ==
# POSITIVE: cert round trip + real sshd login with the cert. No
# authorized_keys exists anywhere, so rc=0 with output proves cert auth.
say A
OUTA=$(timeout 90 "${SSH_ENV[@]}" "${A_ENV[@]}" "$BIN" --server "$SERVER" shell --ssh boxB -- 'echo SSH-CA-OK; id -un' 2>"$WORK/A.err" </dev/null)
rcA=$?
echo "## (cert login) rc=$rcA"
echo "$OUTA" | sed 's/^/##   /'
if [ "$rcA" = "0" ] && echo "$OUTA" | grep -q "SSH-CA-OK" && echo "$OUTA" | grep -qx "$B_USER"; then
  ok "gateA: cert login ran a remote command (rc=0, exact output, no installed keys)"
else
  echo "-- A.err --"; cat "$WORK/A.err"; tail -5 "$WORK/up.log"
  bad "gateA: cert login FAILED (rc=$rcA)"
fi

# ===================================================================== GATE B ==
# NEGATIVE revoked: same command refused after the grant goes (nonzero).
say B
env FILAMENT_CONFIG_DIR="$DB" "${HOOK_ENV[@]}" "$BIN" revoke boxA shell -y >"$WORK/revoke.log" 2>&1
OUTB=$(timeout 90 "${SSH_ENV[@]}" "${A_ENV[@]}" "$BIN" --server "$SERVER" shell --ssh boxB -- 'echo SHOULD-NOT-RUN' 2>"$WORK/B.err" </dev/null)
rcB=$?
echo "## (revoked) rc=$rcB out='$OUTB'"
if [ "$rcB" != "0" ] \
   && ! echo "$OUTB" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "refused\|revoked\|not granted\|no shell cap\|no cert" "$WORK/B.err"; then
  ok "gateB: revoked cert login REFUSED (nonzero + reason)"
else
  echo "-- B.err --"; cat "$WORK/B.err"
  bad "gateB: revoked login NOT refused (rc=$rcB)"
fi

# ===================================================================== GATE D ==
# CLAMP: with a ~10-minute grant window, the issued cert's validity must be
# <= that window (ssh-keygen -L reads the actual cert back).
say D
CERT_LINE=$(grep -oE 'expiry [0-9]+' "$WORK/up.log" | tail -1 | awk '{print $2}')
VALID=$(grep -oE 'Valid: from [^ ]+ to [^ ]+' "$WORK/sshd/sshd.log" 2>/dev/null | tail -1)
echo "## cert expiry epoch: $CERT_LINE"
if [ -n "$CERT_LINE" ]; then
  DELTA=$(( CERT_LINE - GRANT_NOW ))
  if [ "$DELTA" -le 600 ] && [ "$DELTA" -ge 540 ]; then
    ok "gateD: cert validity clamped to the 10-minute grant (${DELTA}s)"
  else
    bad "gateD: cert validity ${DELTA}s exceeds/misses the grant window"
  fi
else
  bad "gateD: no issuance expiry found in B's log"
fi

# ===================================================================== GATE C ==
# WIRING: up/grant arming wrote the Match block + daemon principals entry
# through the product writer (temp paths above prove it without touching
# /etc/ssh).
say C
if grep -q "Match User $B_USER" "$WORK/hooked-sshd-config" \
   && grep -q "TrustedUserCAKeys" "$WORK/hooked-sshd-config" \
   && [ "$(cat "$WORK/hooked-principals/$B_USER" 2>/dev/null)" = "$B_USER" ] \
   && cmp -s "$DB/ssh/ssh_ca.pub" "$WORK/hooked-ca.pub"; then
  ok "gateC: arming wrote block + principals + anchor copy (product writer)"
else
  echo "-- hooked-sshd-config --"; cat "$WORK/hooked-sshd-config" 2>/dev/null
  echo "-- hooked-principals --"; ls -la "$WORK/hooked-principals" 2>/dev/null
  echo "-- anchor vs daemon pub --"; cmp "$DB/ssh/ssh_ca.pub" "$WORK/hooked-ca.pub" 2>&1 | head -2
  bad "gateC: arming outputs missing"
fi

# ===================================================================== GATE E ==
# NO-INSTALL: B's authorized_keys is byte-identical after cert login --
# `shell --ssh` installed nothing permanent (host-key pinning only).
say E
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$AK_AFTER" || : > "$AK_AFTER"
if cmp -s "$AK_BEFORE" "$AK_AFTER"; then
  ok "gateE: authorized_keys unchanged by cert login (no key install)"
else
  echo "-- diff --"; diff "$AK_BEFORE" "$AK_AFTER" | head -5
  bad "gateE: authorized_keys CHANGED by cert login"
fi

# E2: re-grant (gate B revoked), then kill sshd so the retry path runs:
# cached bootstrap hits 255, the rebootstrap (cert mode too) retries, ssh
# fails 255 again -- and STILL nothing is installed. Proves the 255 retry
# path honors cert-only.
env FILAMENT_CONFIG_DIR="$DB" "${HOOK_ENV[@]}" "$BIN" grant boxA shell >"$WORK/grantE2.log" 2>&1
kill "$SSHD_PID" 2>/dev/null; sleep 1
OUTE2=$(timeout 90 "${SSH_ENV[@]}" "${A_ENV[@]}" "$BIN" --server "$SERVER" shell --ssh boxB -- 'echo NOPE' 2>"$WORK/E2.err" </dev/null)
rcE2=$?
echo "## (dead sshd) rc=$rcE2"
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$WORK/ak.after2" || : > "$WORK/ak.after2"
if [ "$rcE2" != "0" ] \
   && grep -q "re-authenticating" "$WORK/E2.err" \
   && cmp -s "$AK_BEFORE" "$WORK/ak.after2"; then
  ok "gateE2: dead-sshd retry ran cert-only and installed nothing (rc=$rcE2)"
else
  echo "-- E2.err --"; tail -5 "$WORK/E2.err"
  diff "$AK_BEFORE" "$WORK/ak.after2" | head -5
  bad "gateE2: retry misbehaved (rc=$rcE2)"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "ssh-ca gates: $PASS passed, $FAIL failed${FAILED:+ — failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
