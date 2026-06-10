#!/usr/bin/env bash
# UX scenario bodies. Each scenario:
#   - prints captioned banners (=== UX: ... ===) so a human reads what runs,
#   - drives the REAL /root/.local/bin/filament against our LOCAL backend,
#   - ends by printing a single line "RESULT <id> PASS|FAIL <detail>".
#
# Every scenario sets FILAMENT_CONFIG_DIR under /tmp/ux (never the real store)
# and only kills processes it started (tracked, or matched by its own cfg dir).
#
# This file is SOURCED by record.sh inside an asciinema session (one scenario
# per recording). Run a single scenario:  ./scenarios.sh <id>
set -uo pipefail
: "${ZSH_VERSION:=}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/rig/lib.sh"

# ---- presentation helpers --------------------------------------------------
C_RESET=$'\033[0m'; C_CAP=$'\033[1;36m'; C_A=$'\033[1;33m'; C_B=$'\033[1;35m'
C_OK=$'\033[1;32m'; C_BAD=$'\033[1;31m'; C_DIM=$'\033[2m'
cap()  { printf '\n%s=== UX: %s ===%s\n' "$C_CAP" "$1" "$C_RESET"; }
note() { printf '%s  %s%s\n' "$C_DIM" "$1" "$C_RESET"; }
a()    { printf '%s[A]%s %s\n' "$C_A" "$C_RESET" "$1"; }
b()    { printf '%s[B]%s %s\n' "$C_B" "$C_RESET" "$1"; }
runA() { printf '%s[A]$%s %s\n' "$C_A" "$C_RESET" "$*"; }
runB() { printf '%s[B]$%s %s\n' "$C_B" "$C_RESET" "$*"; }
pause(){ sleep "${1:-0.6}"; }
pass() { printf '\n%s  ✔ PASS%s  %s\n' "$C_OK" "$C_RESET" "$1"; echo "RESULT $SC_ID PASS $1"; }
fail() { printf '\n%s  ✘ FAIL%s  %s\n' "$C_BAD" "$C_RESET" "$1"; echo "RESULT $SC_ID FAIL $1"; }

# A receiver that completes a transfer can linger in the rejoin window after the
# sender disconnects; bound it tight so demos stay snappy.
export FILAMENT_REJOIN_SECS=3

# poll a logfile for the minted 4-segment pair code (lower-cased)
wait_code() { local f="$1" n=0 c=""; while [ $n -lt 80 ]; do
  c=$(grep -oE '[A-Za-z]+-[A-Za-z]+-[A-Za-z]+-[0-9]+' "$f" 2>/dev/null | head -1 | tr 'A-Z' 'a-z')
  [ -n "$c" ] && { echo "$c"; return 0; }; n=$((n+1)); sleep 0.2; done; return 1; }

# kill only filament procs whose env points at the given cfg-dir prefix
kill_by_cfg() { local pfx="$1"; for p in $(pgrep -f "$FILAMENT" 2>/dev/null); do
  tr '\0' ' ' < /proc/$p/environ 2>/dev/null | grep -q "FILAMENT_CONFIG_DIR=$pfx" && kill "$p" 2>/dev/null; done; }

PAY="$UX_WORK/payload.bin"
ensure_payload() { [ -f "$PAY" ] || head -c 1500000 /dev/urandom > "$PAY"; }

# ======================================================================== 01 ==
sc_01_pair() {
  cap "pair two devices — A mints a code, B claims it (PAKE, no key crosses the server)"
  local DA=$(fresh_cfg s01A) DB=$(fresh_cfg s01B)
  runA "filament pair --name phone"
  FILAMENT_CONFIG_DIR="$DA" timeout 40 "$FILAMENT" pair --name phone --server "$UX_SERVER" >"$UX_WORK/01a.log" 2>&1 & local PA=$!; track $PA
  local C; C=$(wait_code "$UX_WORK/01a.log") || { fail "code never minted"; return; }
  a "minted: ${C^^}"; pause
  runB "filament pair $C --name laptop"
  FILAMENT_CONFIG_DIR="$DB" timeout 40 "$FILAMENT" pair "$C" --name laptop --server "$UX_SERVER" >"$UX_WORK/01b.log" 2>&1
  wait $PA
  local CHA CHB
  CHA=$(FILAMENT_CONFIG_DIR="$DA" "$FILAMENT" devices 2>/dev/null | grep -oE 'channel [0-9a-f]+' | head -1)
  CHB=$(FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" devices 2>/dev/null | grep -oE 'channel [0-9a-f]+' | head -1)
  a "$(FILAMENT_CONFIG_DIR="$DA" "$FILAMENT" devices 2>/dev/null)"
  b "$(FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" devices 2>/dev/null)"
  note "both stores derived the SAME channel id from one mutual secret"
  [ -n "$CHA" ] && [ "$CHA" = "$CHB" ] && pass "paired; matching $CHA" || fail "channels differ ($CHA vs $CHB)"
}

# ======================================================================== 02 ==
sc_02_devices() {
  cap "devices: list / rename / forget — and a forget must NOT wipe another device's caps"
  local DC=$(fresh_cfg s02)
  local s1=$(mk_secret) s2=$(mk_secret) s3=$(mk_secret)
  seed_store "$DC" "[{\"name\":\"laptop\",\"secret\":\"$s1\",\"caps\":[\"shell\"]},{\"name\":\"phone\",\"secret\":\"$s2\"},{\"name\":\"tv\",\"secret\":\"$s3\"}]"
  note "seeded 3 devices; 'laptop' holds a granted shell cap"
  runA "filament devices"; FILAMENT_CONFIG_DIR="$DC" "$FILAMENT" devices; pause
  runA "filament devices rename tv livingroom"; FILAMENT_CONFIG_DIR="$DC" "$FILAMENT" devices rename tv livingroom; pause
  runA "filament devices forget phone"; FILAMENT_CONFIG_DIR="$DC" "$FILAMENT" devices forget phone; pause
  runA "filament devices"; FILAMENT_CONFIG_DIR="$DC" "$FILAMENT" devices
  local survived
  survived=$(python3 -c "import json;d=json.load(open('$DC/devices.json'));print('yes' if any(x['name']=='laptop' and 'shell' in x.get('caps',[]) for x in d) else 'no')")
  note "regression check: laptop's shell cap after forgetting a DIFFERENT device = $survived"
  [ "$survived" = "yes" ] && ! grep -q '"phone"' "$DC/devices.json" \
    && pass "rename+forget worked; laptop's shell cap SURVIVED the unrelated forget" \
    || fail "shell cap wiped by forget (the regression) or phone not removed"
}

# ======================================================================== 03 ==
sc_03_code_xfer() {
  cap "send a file with a one-time code; the other side claims it and receives"
  ensure_payload; local DS=$(fresh_cfg s03S) DR=$(fresh_cfg s03R) OUT=$(fresh_cfg s03out)
  local h1; h1=$(hashof "$PAY")
  # Single-host CLI<->CLI ICE between two fresh ephemeral peers can wedge on a
  # "connecting…" attempt (esp. under recorder load); both send and recv are
  # bounded by `timeout` and the whole exchange is retried so a transient wedge
  # doesn't hang or fail the demo. Verify the received BYTES by hash (the file
  # lands under the sender's source basename — `send --name` does not rename it).
  local h2=none RCV W
  for try in 1 2 3; do
    rm -rf "$OUT"; mkdir -p "$OUT"; W="ux-$RANDOM-demo"
    runA "filament send report.pdf --word $W"
    FILAMENT_CONFIG_DIR="$DS" timeout 30 "$FILAMENT" send "$PAY" --word "$W" --name report.pdf --server "$UX_SERVER" >"$UX_WORK/03s.log" 2>&1 & local SP=$!; track $SP
    pause 1.5; a "code is $W — read it to the other device"
    runB "filament recv $W -y"
    FILAMENT_CONFIG_DIR="$DR" timeout 28 "$FILAMENT" recv "$W" -y --dir "$OUT" --server "$UX_SERVER" >"$UX_WORK/03r.log" 2>&1
    wait $SP 2>/dev/null
    RCV=$(ls "$OUT" 2>/dev/null | head -1); h2=$(hashof "$OUT/$RCV" 2>/dev/null || echo none)
    [ "$h2" = "$h1" ] && break
    note "transfer attempt $try did not land (single-host ICE wedge) — retrying"; pause 1
  done
  b "$(tail -2 "$UX_WORK/03r.log" | sed 's/\x1b\[[0-9;]*m//g')"
  b "landed as: ${RCV:-<none>}"
  [ "$h2" = "$h1" ] && pass "received ${RCV}; sha256 matches end-to-end" || fail "hash mismatch ($h2)"
}

# ======================================================================== 04 ==
sc_04_to_known() {
  cap "send --to a KNOWN device: no code, identity proof-verified, auto-accepted"
  ensure_payload; local sec=$(mk_secret)
  local DA=$(fresh_cfg s04A) DB=$(fresh_cfg s04B) DD=$(fresh_cfg s04drop)
  seed_store "$DA" "[{\"name\":\"laptop\",\"secret\":\"$sec\"}]"
  seed_store "$DB" "[{\"name\":\"phone\",\"secret\":\"$sec\"}]"
  note "phone and laptop already know each other (paired earlier)"
  runB "filament up   (laptop, always-on receiver)"
  FILAMENT_CONFIG_DIR="$DB" timeout 40 "$FILAMENT" up --dir "$DD" --server "$UX_SERVER" </dev/null >"$UX_WORK/04up.log" 2>&1 & local UP=$!; track $UP
  pause 3
  runA "filament send slides.key --to laptop"
  FILAMENT_CONFIG_DIR="$DA" timeout 30 "$FILAMENT" send "$PAY" --name slides.key --to laptop --server "$UX_SERVER" >"$UX_WORK/04s.log" 2>&1
  local rc=$?; pause 1; kill $UP 2>/dev/null
  b "$(grep -m1 'identity verified' "$UX_WORK/04up.log" | sed 's/\x1b\[[0-9;]*m//g')"
  # `up` writes the file under the SENDER's source basename — it ignores the
  # sender's --name (a product quirk: only recv honors --name). So verify the
  # received BYTES by hash, whatever the landed filename is.
  local h1 h2 RCV; h1=$(hashof "$PAY")
  RCV=$(ls "$DD" 2>/dev/null | head -1); h2=$(hashof "$DD/$RCV" 2>/dev/null || echo none)
  b "delivered as: ${RCV:-<none>}"
  note "(receiver 'up' saves under the source basename, not the sender's --name)"
  [ $rc -eq 0 ] && [ "$h1" = "$h2" ] && grep -q "identity verified" "$UX_WORK/04up.log" \
    && pass "no code; verified 'laptop'; delivered + hash match" || fail "delivery/verify failed (rc=$rc h=$h2)"
}

# ======================================================================== 05 ==
sc_05_up_status_down() {
  cap "always-on receiver: up + a paired send into it; status; down"
  ensure_payload; local sec=$(mk_secret)
  local DA=$(fresh_cfg s05A) DB=$(fresh_cfg s05B) DD=$(fresh_cfg s05drop)
  seed_store "$DA" "[{\"name\":\"laptop\",\"secret\":\"$sec\"}]"
  seed_store "$DB" "[{\"name\":\"phone\",\"secret\":\"$sec\"}]"
  runB "filament up   (laptop)"
  FILAMENT_CONFIG_DIR="$DB" timeout 45 "$FILAMENT" up --dir "$DD" --server "$UX_SERVER" </dev/null >"$UX_WORK/05up.log" 2>&1 & local UP=$!; track $UP
  pause 3
  runA "filament send backup.tar --to laptop"
  FILAMENT_CONFIG_DIR="$DA" timeout 30 "$FILAMENT" send "$PAY" --name backup.tar --to laptop --server "$UX_SERVER" >"$UX_WORK/05s.log" 2>&1; local rc=$?
  pause 1
  runB "filament status"
  local ST; ST=$(FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" status 2>&1 | sed 's/\x1b\[[0-9;]*m//g'); echo "$ST"
  pause 0.5
  runB "filament down"; FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" down 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  pause 0.5; kill $UP 2>/dev/null
  # `up` writes under the source basename (ignores the sender's --name); verify bytes.
  local h2 RCV; RCV=$(ls "$DD" 2>/dev/null | head -1); h2=$(hashof "$DD/$RCV" 2>/dev/null || echo none)
  [ $rc -eq 0 ] && [ "$h2" = "$(hashof "$PAY")" ] && pass "up received; status reported; down stopped it" \
    || fail "up/status/down flow failed (rc=$rc h=$h2)"
}

# ======================================================================== 06 ==
sc_06_ssh() {
  cap "grant shell, then 'filament ssh peer -- echo OK' over the data-channel tunnel"
  local W; W=$(mktemp -d "$UX_TMP/s06.XXXXXX")
  local SSHD="$W/sshd"; mkdir -p "$SSHD" /run/sshd 2>/dev/null
  local PORT=$((9300 + RANDOM % 200))
  ssh-keygen -q -t ed25519 -f "$SSHD/hostkey" -N ""
  local USERNAME; USERNAME=$(id -un)
  local BHOME="$W/Bhome"; mkdir -p "$BHOME/.ssh"; chmod 700 "$BHOME/.ssh"
  local AK="$BHOME/.ssh/authorized_keys"; : > "$AK"; chmod 600 "$AK"
  cat > "$SSHD/sshd_config" <<CFG
Port $PORT
ListenAddress 127.0.0.1
HostKey $SSHD/hostkey
PidFile $SSHD/sshd.pid
AuthorizedKeysFile $AK
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
CFG
  /usr/sbin/sshd -f "$SSHD/sshd_config" -E "$SSHD/sshd.log" -D & track $!
  sleep 1
  local DA="$W/A" DB="$W/B"; mkdir -p "$DA" "$DB"
  local sec; sec=$(mk_secret)
  seed_store "$DA" "[{\"name\":\"server\",\"secret\":\"$sec\"}]"
  seed_store "$DB" "[{\"name\":\"laptop\",\"secret\":\"$sec\"}]"
  note "topology: B = the box you ssh INTO (acceptor, FILAMENT_L2=1); A = you"
  runB "FILAMENT_L2=1 filament up    (the box, accepts tunnels)"
  env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" FILAMENT_L2=1 FILAMENT_NAME=laptop \
      FILAMENT_SSH_HOSTKEY="$SSHD/hostkey.pub" USER="$USERNAME" \
      "$FILAMENT" up --dir "$W/drop" --server "$UX_SERVER" >"$W/up.log" 2>&1 & local UP=$!; track $UP
  sleep 4
  runB "filament grant laptop shell   (consent: deny-by-default)"
  env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" grant laptop shell 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  sleep 1
  local AHOME="$W/Ahome"; mkdir -p "$AHOME"
  runA "filament ssh server -- echo OK"
  local OUT rc tries=0
  while [ $tries -lt 3 ]; do
    OUT=$(timeout 35 env HOME="$AHOME" FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=server \
       FILAMENT_SSH_PORT="$PORT" FILAMENT_SSH_USER="$USERNAME" \
       "$FILAMENT" --server "$UX_SERVER" ssh server 'echo OK-OVER-FILAMENT' 2>"$W/ssh.err" </dev/null)
    rc=$?; echo "$OUT" | grep -q OK-OVER-FILAMENT && break
    tries=$((tries+1)); sleep 2
  done
  a "remote stdout: ${OUT:-<none>}   (attempts: $((tries+1)))"
  kill_by_cfg "$W"; kill $UP 2>/dev/null
  # tear down OUR throwaway sshd so it doesn't linger and contend with later runs
  [ -f "$SSHD/sshd.pid" ] && kill "$(cat "$SSHD/sshd.pid")" 2>/dev/null
  pkill -f "sshd_config.*$W/sshd" 2>/dev/null
  echo "$OUT" | grep -q OK-OVER-FILAMENT \
    && pass "shell granted; ssh ran a remote command over the tunnel" \
    || fail "ssh over tunnel did not return remote output (rc=$rc)"
}

# ======================================================================== 07 ==
sc_07_introduce() {
  cap "introduce: vouch two of YOUR devices to each other (run on the device that knows both)"
  # S knows A and B (distinct secrets). introduce mints a fresh mutual secret
  # and delivers it to both over verified channels. A and B must be online.
  local DS=$(fresh_cfg s07S) DA=$(fresh_cfg s07A) DB=$(fresh_cfg s07B)
  local secA=$(mk_secret) secB=$(mk_secret)
  seed_store "$DS" "[{\"name\":\"alice\",\"secret\":\"$secA\"},{\"name\":\"bob\",\"secret\":\"$secB\"}]"
  seed_store "$DA" "[{\"name\":\"hub\",\"secret\":\"$secA\"}]"
  seed_store "$DB" "[{\"name\":\"hub\",\"secret\":\"$secB\"}]"
  note "hub knows alice & bob; alice & bob do NOT yet know each other"
  runA "alice: filament up   (online, waiting)"
  FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=alice timeout 45 "$FILAMENT" up --dir "$UX_WORK/s07da" --server "$UX_SERVER" </dev/null >"$UX_WORK/07a.log" 2>&1 & local PA=$!; track $PA
  runB "bob:   filament up   (online, waiting)"
  FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=bob timeout 45 "$FILAMENT" up --dir "$UX_WORK/s07db" --server "$UX_SERVER" </dev/null >"$UX_WORK/07b.log" 2>&1 & local PB=$!; track $PB
  sleep 3
  runA "hub:   filament introduce alice bob"
  FILAMENT_CONFIG_DIR="$DS" FILAMENT_NAME=hub timeout 35 "$FILAMENT" introduce alice bob --server "$UX_SERVER" >"$UX_WORK/07i.log" 2>&1; local rc=$?
  sleep 1; kill $PA $PB 2>/dev/null
  echo "$(tail -4 "$UX_WORK/07i.log" | sed 's/\x1b\[[0-9;]*m//g')"
  # success: alice's store now lists bob and bob's store lists alice (new petname),
  # OR the introduce command reports it delivered to both.
  local okA okB
  okA=$(FILAMENT_CONFIG_DIR="$DA" "$FILAMENT" devices 2>/dev/null | grep -vc '^$')
  okB=$(FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" devices 2>/dev/null | grep -vc '^$')
  a "alice now knows: $(FILAMENT_CONFIG_DIR="$DA" "$FILAMENT" devices 2>/dev/null | tr '\n' ' ')"
  b "bob now knows:   $(FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" devices 2>/dev/null | tr '\n' ' ')"
  if [ $rc -eq 0 ] && grep -qiE "introduc|delivered|vouch|done" "$UX_WORK/07i.log" && [ "$okA" -ge 2 ] && [ "$okB" -ge 2 ]; then
    pass "introduce delivered a fresh mutual secret; alice<->bob now know each other"
  else
    fail "introduce did not establish mutual trust (rc=$rc okA=$okA okB=$okB)"
  fi
}

# dispatcher: run one scenario by id
SC_ID="${1:-}"
case "$SC_ID" in
  01) sc_01_pair ;;
  02) sc_02_devices ;;
  03) sc_03_code_xfer ;;
  04) sc_04_to_known ;;
  05) sc_05_up_status_down ;;
  06) sc_06_ssh ;;
  07) sc_07_introduce ;;
  *) echo "usage: scenarios.sh <01..07>"; exit 2 ;;
esac
