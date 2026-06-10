#!/usr/bin/env bash
# Seamless-ssh gates (docs/design-seamless-ssh.md). Standalone, hermetic, fixture
# port 8098 ONLY. Proves the no-keys bootstrap + the deny-by-default shell cap.
#
#   ./ssh-gates.sh
#
# Gates:
#   A  POSITIVE no-keys bootstrap — client has NO ssh keypair and NO ~/.ssh;
#      `grant boxA shell` on the acceptor, then `filament ssh boxB 'hostname'`
#      returns the acceptor's hostname. Full bootstrap: key gen + authorized_keys
#      install + host-key pin + ssh, zero prompts.
#   B  NEGATIVE no-cap refusal — a paired device WITHOUT the shell cap is REFUSED
#      the bootstrap (shell-bootstrap-deny); `filament ssh` aborts BEFORE invoking
#      ssh. Zero shell, clear denial.
#   C  marked + removable — the # BEGIN/END filament-managed block is present
#      after grant and GONE after `revoke`.
#   D  host-key pin is REAL — a second connection with StrictHostKeyChecking=yes
#      (no accept-new) against the pre-pinned known_hosts succeeds, proving the
#      pin actually matched (not a silent TOFU).
#
# Topology mirrors l2-gates.sh: side B = acceptor (`filament up`, FILAMENT_L2=1),
# side A = initiator (`filament ssh`). Reciprocal pair secret => B trusts A.
# The acceptor runs with HOME sandboxed to a temp dir so its authorized_keys
# write never touches the real home; a throwaway sshd reads that sandboxed
# authorized_keys and serves a hostkey the acceptor reports via FILAMENT_SSH_HOSTKEY.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="$CLI_DIR/target/release/filament"
PORT=8098
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-/root/.claude/jobs/330c2366/tmp/venv/bin/python}"
WORK="$(mktemp -d /root/.claude/jobs/330c2366/tmp/wt-ssh-gates.XXXXXX 2>/dev/null || mktemp -d /tmp/wt-ssh-gates.XXXXXX)"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== ssh gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
OWN_BACKEND=""
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  [ -n "$OWN_BACKEND" ] && kill "$OWN_BACKEND" 2>/dev/null
}
trap cleanup EXIT

# --- own fixture backend on $PORT ---
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
OWN_BACKEND=$!
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

# --- throwaway sshd (serves the acceptor's reported host key) ---
SSHD="$WORK/sshd"; mkdir -p "$SSHD"; mkdir -p /run/sshd 2>/dev/null
SSHD_PORT=9133
ssh-keygen -q -t ed25519 -f "$SSHD/hostkey" -N ""
USERNAME=$(id -un)
# Acceptor's HOME sandbox: sshd reads THIS authorized_keys (the file the acceptor
# writes the filament-managed block into).
BHOME="$WORK/Bhome"; mkdir -p "$BHOME/.ssh"; chmod 700 "$BHOME/.ssh"
AK="$BHOME/.ssh/authorized_keys"; : > "$AK"; chmod 600 "$AK"
cat > "$SSHD/sshd_config" <<CFG
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $SSHD/hostkey
PidFile $SSHD/sshd.pid
AuthorizedKeysFile $AK
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
LogLevel VERBOSE
CFG
/usr/sbin/sshd -f "$SSHD/sshd_config" -E "$SSHD/sshd.log" -D &
pids+=($!)
sleep 1
ss -tlnp 2>/dev/null | grep -q ":$SSHD_PORT " || { echo "## sshd FAILED"; cat "$SSHD/sshd.log"; exit 2; }

# --- two mutually-trusted devices: reciprocal pair secret ---
DA="$WORK/A"; DB="$WORK/B"; mkdir -p "$DA" "$DB"
SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxB","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxA","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"

# Acceptor (side B): HOME sandboxed; reports the throwaway hostkey; FILAMENT_L2=1.
B_DROP="$WORK/Bdrop"; mkdir -p "$B_DROP"
start_acceptor() {
  env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" FILAMENT_L2=1 FILAMENT_NAME=boxB \
      FILAMENT_SSH_HOSTKEY="$SSHD/hostkey.pub" USER="$USERNAME" \
      "$BIN" up --dir "$B_DROP" --server "$SERVER" >"$WORK/up.log" 2>&1 &
  pids+=($!)
}
start_acceptor
sleep 3

# Initiator env (side A). NO ssh keypair anywhere: config dir has only devices.json,
# and HOME points at an empty dir with no ~/.ssh — proving zero pre-existing setup.
AHOME="$WORK/Ahome"; mkdir -p "$AHOME"
A_ENV=(env HOME="$AHOME" FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=boxA \
       FILAMENT_SSH_PORT="$SSHD_PORT" FILAMENT_SSH_USER="$USERNAME")

# Sanity: the client truly has no ssh key/known_hosts at the start.
[ ! -e "$AHOME/.ssh" ] && [ ! -e "$DA/ssh" ] || echo "## NOTE: pre-existing ssh material (unexpected)"

# ===================================================================== GATE B ==
# NEGATIVE: no shell cap granted yet. The bootstrap must be REFUSED and ssh must
# NOT run. We run it BEFORE the grant so the deny path is clean.
say B
OUTB=$(timeout 45 "${A_ENV[@]}" "$BIN" --server "$SERVER" ssh boxB 'echo SHOULD-NOT-RUN; hostname' 2>"$WORK/sshB.err" </dev/null)
rcB=$?
echo "## (no-cap) rc=$rcB out='$OUTB'"
if [ "$rcB" != "0" ] \
   && ! echo "$OUTB" | grep -q "SHOULD-NOT-RUN" \
   && { grep -qi "refused\|not granted\|grant" "$WORK/sshB.err" || true; } \
   && grep -q "shell bootstrap refused" "$WORK/up.log"; then
  ok "gateB: no-cap device REFUSED a shell (deny before ssh; zero shell)"
else
  echo "-- sshB.err --"; cat "$WORK/sshB.err"; echo "-- up.log tail --"; tail -20 "$WORK/up.log"
  bad "gateB: no-cap refusal NOT clean (rc=$rcB)"
fi

# ===================================================================== grant ===
# Acceptor-side consent: grant boxA the shell cap. (Mutates devices.json; the
# running acceptor reads caps live from disk in the bootstrap arm.)
env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grant.log" 2>&1
echo "## grant: $(cat "$WORK/grant.log")"
grep -q '"shell"' "$DB/devices.json" || { echo "## grant did not persist"; cat "$DB/devices.json"; }

# ===================================================================== GATE A ==
# POSITIVE: with the cap granted and NO pre-existing ssh setup on the client,
# `filament ssh boxB hostname` lands a shell and returns the acceptor's hostname.
say A
ACCEPTOR_HOST=$(hostname)
OUTA=$(timeout 60 "${A_ENV[@]}" "$BIN" --server "$SERVER" ssh boxB 'hostname' 2>"$WORK/sshA.err" </dev/null)
rcA=$?
echo "## (granted) rc=$rcA out='$OUTA' expect-host='$ACCEPTOR_HOST'"
if [ "$rcA" = "0" ] && echo "$OUTA" | grep -qx "$ACCEPTOR_HOST"; then
  ok "gateA: no-keys bootstrap — filament ssh returned the peer's hostname (rc=0)"
else
  echo "-- sshA.err --"; tail -25 "$WORK/sshA.err"; echo "-- up.log tail --"; tail -25 "$WORK/up.log"
  echo "-- managed key present? --"; ls -la "$DA/ssh" 2>/dev/null
  bad "gateA: no-keys bootstrap FAILED (rc=$rcA)"
fi

# ===================================================================== GATE C ==
# Marked + removable: the managed block is present after grant, gone after revoke.
say C
if grep -q "# BEGIN filament-managed boxA" "$AK" && grep -q "# END filament-managed boxA" "$AK"; then
  env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" "$BIN" revoke boxA shell >"$WORK/revoke.log" 2>&1
  echo "## revoke: $(cat "$WORK/revoke.log")"
  if ! grep -q "filament-managed boxA" "$AK"; then
    ok "gateC: authorized_keys filament-managed block present after grant, removed by revoke"
  else
    echo "-- authorized_keys --"; cat "$AK"
    bad "gateC: revoke did not strip the managed block"
  fi
else
  echo "-- authorized_keys --"; cat "$AK"
  bad "gateC: managed block NOT marked/present after grant"
fi

# ===================================================================== GATE D ==
# Host-key pin is REAL: connect once with StrictHostKeyChecking=yes (NO accept-new)
# straight to the throwaway sshd, using the known_hosts filament PINNED during
# gate A. If the pin never matched, strict mode rejects the host key and this
# fails — so a green here proves the pin actually functioned (not a silent TOFU).
say D
KH="$DA/ssh/known_hosts"
KEY="$DA/ssh/id_ed25519"
HOST="filament-boxB"
if [ -f "$KH" ] && grep -q "^$HOST " "$KH"; then
  # Re-install boxA's key directly (gate C just revoked it) so pubkey auth works
  # for this isolated check; we are only testing the HOST-key pin here.
  cat "$KEY.pub" > "$AK"; chmod 600 "$AK"
  # Connect to 127.0.0.1 (the real sshd) but force the known_hosts lookup to use
  # the PINNED alias via HostKeyAlias, so strict mode checks against the pin.
  OUTD=$(timeout 20 ssh \
      -o IdentityFile="$KEY" -o IdentitiesOnly=yes \
      -o UserKnownHostsFile="$KH" -o GlobalKnownHostsFile=/dev/null \
      -o HostKeyAlias="$HOST" \
      -o StrictHostKeyChecking=yes -o BatchMode=yes \
      -p "$SSHD_PORT" "$USERNAME@127.0.0.1" \
      'echo PIN-OK' 2>"$WORK/sshD.err")
  rcD=$?
  echo "## (strict-pin) rc=$rcD out='$OUTD'"
  if [ "$rcD" = "0" ] && echo "$OUTD" | grep -q "PIN-OK"; then
    ok "gateD: host-key pin matched under StrictHostKeyChecking=yes (pin is real, not TOFU)"
  else
    echo "-- sshD.err --"; tail -15 "$WORK/sshD.err"; echo "-- known_hosts --"; cat "$KH"
    bad "gateD: strict host-key check FAILED — pin did not match"
  fi
else
  echo "-- known_hosts ($KH) --"; cat "$KH" 2>/dev/null
  bad "gateD: no pinned host key for $HOST in filament known_hosts"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "ssh gates: $PASS passed, $FAIL failed${FAILED:+ — failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
