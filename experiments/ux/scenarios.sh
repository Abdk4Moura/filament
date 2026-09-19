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
  c=$(grep -oE '[A-Za-z]+-[A-Za-z]+-[0-9]+' "$f" 2>/dev/null | head -1 | tr 'A-Z' 'a-z')
  [ -n "$c" ] && { echo "$c"; return 0; }; n=$((n+1)); sleep 0.2; done; return 1; }

# kill only filament procs whose env points at the given cfg-dir prefix
kill_by_cfg() { local pfx="$1"; for p in $(pgrep -f "$FILAMENT" 2>/dev/null); do
  tr '\0' ' ' < /proc/$p/environ 2>/dev/null | grep -q "FILAMENT_CONFIG_DIR=$pfx" && kill "$p" 2>/dev/null; done; }

# Payload lives under the per-scenario UX_TMP so parallel rigs never race on a
# shared file (each isolated rig gets its own /tmp/ux/<id>).
PAY="$UX_TMP/payload.bin"
ensure_payload() { [ -f "$PAY" ] || head -c 1500000 /dev/urandom > "$PAY"; }

# ======================================================================== 01 ==
sc_01_pair() {
  cap "pair two devices — A mints a code, B claims it (PAKE, no key crosses the server)"
  local DA=$(fresh_cfg s01A) DB=$(fresh_cfg s01B) W
  W=$(ux_words)
  runA "filament add --word '$W' --name phone"
  FILAMENT_CONFIG_DIR="$DA" timeout -k 5 40 "$FILAMENT" add --word "$W" --name phone -y --server "$UX_SERVER" >"$UX_WORK/01a.log" 2>&1 & local PA=$!; track $PA
  local C; C=$(wait_code "$UX_WORK/01a.log") || { fail "code never minted"; return; }
  a "minted: ${C^^}"; pause
  runB "filament add $C --name laptop"
  FILAMENT_CONFIG_DIR="$DB" timeout -k 5 40 "$FILAMENT" add "$C" --name laptop -y --server "$UX_SERVER" >"$UX_WORK/01b.log" 2>&1
  wait $PA
  # Invariant: each store lists the other device. The claim only succeeds with
  # a code carrying the channel the mint derived, so mutual listing IS the proof
  # the ceremony ran end-to-end. (The old "channel id" field is gone from
  # `devices` in 0.8.5; asserting on a removed field is how this rotted.)
  a "$(FILAMENT_CONFIG_DIR="$DA" "$FILAMENT" devices 2>/dev/null)"
  b "$(FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" devices 2>/dev/null)"
  local okA okB
  okA=$(FILAMENT_CONFIG_DIR="$DA" "$FILAMENT" devices 2>/dev/null | grep -q phone && echo 1 || echo 0)
  okB=$(FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" devices 2>/dev/null | grep -q laptop && echo 1 || echo 0)
  [ "$okA" = "1" ] && [ "$okB" = "1" ] && pass "paired; A lists phone, B lists laptop" || fail "mutual recognition missing (A→phone=$okA B→laptop=$okB)"
}

# ======================================================================== 02 ==
sc_02_devices() {
  cap "devices: list / rename / forget — and a forget must NOT wipe another device's caps"
  local DC=$(fresh_cfg s02) D1=$(fresh_cfg s02b) D2=$(fresh_cfg s02c) D3=$(fresh_cfg s02d)
  # Pair all three for real via the shipping add ceremony; nothing is hand-written.
  pair_two "$DC" laptop "$D1" box || { fail "pair_two laptop failed"; return; }
  pair_two "$DC" phone  "$D2" box || { fail "pair_two phone failed"; return; }
  pair_two "$DC" tv     "$D3" box || { fail "pair_two tv failed"; return; }
  note "paired 3 devices for real: laptop, phone, tv"
  runA "filament grant laptop shell"
  FILAMENT_CONFIG_DIR="$DC" "$FILAMENT" grant laptop shell; pause
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
  # doesn't hang or fail the demo. Verify the received BYTES by hash.
  # The minted code is word + a machine-assigned connect number ("ux-8116-demo-665");
  # 0.8.5 requires the FULL code to claim, not just the word (found while
  # converting the rig). Extract it from the send output.
  local h2=none RCV W C
  for try in 1 2 3; do
    rm -rf "$OUT"; mkdir -p "$OUT"; W="ux-$RANDOM-demo"
    runA "filament send report.pdf --word $W"
    FILAMENT_CONFIG_DIR="$DS" timeout -k 5 30 "$FILAMENT" send "$PAY" --word "$W" --name report.pdf --server "$UX_SERVER" >"$UX_WORK/03s.log" 2>&1 & local SP=$!; track $SP
    # wait until the sender has registered the code, then take the FULL code.
    wait_log "$UX_WORK/03s.log" "code +$W" 12 0.15 || pause 1.5
    C=$(grep -oE "${W}-[0-9]+" "$UX_WORK/03s.log" 2>/dev/null | head -1)
    a "code is ${C:-$W} — read it to the other device"
    runB "filament receive ${C:-$W} -y"
    FILAMENT_CONFIG_DIR="$DR" timeout -k 5 28 "$FILAMENT" receive "${C:-$W}" -y --dir "$OUT" --server "$UX_SERVER" >"$UX_WORK/03r.log" 2>&1
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
  ensure_payload
  local DA=$(fresh_cfg s04A) DB=$(fresh_cfg s04B) DD=$(fresh_cfg s04drop)
  note "pairing A with B for real via the shipping add ceremony"
  pair_two "$DA" laptop "$DB" phone || { fail "pair_two failed"; return; }
  note "phone and laptop already know each other (paired earlier)"
  runB "filament up   (laptop, always-on receiver)"
  FILAMENT_CONFIG_DIR="$DB" timeout -k 5 40 "$FILAMENT" up --dir "$DD" --server "$UX_SERVER" </dev/null >"$UX_WORK/04up.log" 2>&1 & local UP=$!; track $UP
  # wait for the receiver to print its ready banner instead of a blind sleep
  wait_log "$UX_WORK/04up.log" 'filament up —' 15 0.15 || note "up ready-banner not seen (continuing)"
  pause 0.4   # tiny settle so the receiver has joined its room
  runA "filament send slides.key --to laptop"
  FILAMENT_CONFIG_DIR="$DA" timeout -k 5 30 "$FILAMENT" send "$PAY" --name slides.key --to laptop --server "$UX_SERVER" >"$UX_WORK/04s.log" 2>&1
  local rc=$?; pause 1; kill $UP 2>/dev/null
  b "$(grep -m1 'known device\|verified (whole-file sha256 matched)' "$UX_WORK/04up.log" | sed 's/\x1b\[[0-9;]*m//g')"
  # The receiver lands the file under the sender's --name (0.8.5 up honors it)
  # and verifies whole-file sha256. Assert on bytes + that verified line.
  local h1 h2 RCV; h1=$(hashof "$PAY")
  RCV=$(ls "$DD" 2>/dev/null | head -1); h2=$(hashof "$DD/$RCV" 2>/dev/null || echo none)
  b "delivered as: ${RCV:-<none>}"
  note "(receiver 'up' saves under the sender's --name, verified by whole-file sha256)"
  [ $rc -eq 0 ] && [ "$h1" = "$h2" ] && grep -qE "verified \(whole-file sha256 matched\)" "$UX_WORK/04up.log" \
    && pass "no code; known device auto-accepted; delivered + hash match" || fail "delivery/verify failed (rc=$rc h=$h2)"
}

# ======================================================================== 05 ==
sc_05_up_status_down() {
  cap "always-on receiver: up + a paired send into it; status; down"
  ensure_payload
  local DA=$(fresh_cfg s05A) DB=$(fresh_cfg s05B) DD=$(fresh_cfg s05drop)
  note "pairing A with B for real via the shipping add ceremony"
  pair_two "$DA" laptop "$DB" phone || { fail "pair_two failed"; return; }
  runB "filament up   (laptop)"
  FILAMENT_CONFIG_DIR="$DB" timeout -k 5 45 "$FILAMENT" up --dir "$DD" --server "$UX_SERVER" </dev/null >"$UX_WORK/05up.log" 2>&1 & local UP=$!; track $UP
  wait_log "$UX_WORK/05up.log" 'filament up —' 15 0.15 || note "up ready-banner not seen (continuing)"
  pause 0.4
  runA "filament send backup.tar --to laptop"
  FILAMENT_CONFIG_DIR="$DA" timeout -k 5 30 "$FILAMENT" send "$PAY" --name backup.tar --to laptop --server "$UX_SERVER" >"$UX_WORK/05s.log" 2>&1; local rc=$?
  pause 1
  runB "filament status"
  local ST; ST=$(FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" status 2>&1 | sed 's/\x1b\[[0-9;]*m//g'); echo "$ST"
  pause 0.5
  runB "filament down"; FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" down 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  pause 0.5; kill $UP 2>/dev/null
  # `up` lands the file under the sender's --name; verify bytes by hash.
  local h2 RCV; RCV=$(ls "$DD" 2>/dev/null | head -1); h2=$(hashof "$DD/$RCV" 2>/dev/null || echo none)
  [ $rc -eq 0 ] && [ "$h2" = "$(hashof "$PAY")" ] && pass "up received; status reported; down stopped it" \
    || fail "up/status/down flow failed (rc=$rc h=$h2)"
}

# ======================================================================== 06 ==
sc_06_ssh() {
  cap "grant shell, then 'filament shell peer --ssh -- echo OK' over the data-channel tunnel"
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
  # wait for OUR throwaway sshd to actually accept on its port, not a blind sleep
  wait_for 10 0.1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" || note "sshd not listening yet (continuing)"
  local DA="$W/A" DB="$W/B"; mkdir -p "$DA" "$DB"
  note "pairing A (you) with B (the box) for real, via the shipping add ceremony"
  pair_two "$DA" server "$DB" laptop || { fail "pair_two A/B failed"; return; }
  note "topology: B = the box you ssh INTO (acceptor, FILAMENT_L2=1); A = you"
  runB "FILAMENT_L2=1 filament up    (the box, accepts tunnels)"
  env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" FILAMENT_L2=1 FILAMENT_NAME=laptop \
      FILAMENT_SSH_HOSTKEY="$SSHD/hostkey.pub" USER="$USERNAME" \
      "$FILAMENT" up --dir "$W/drop" --server "$UX_SERVER" >"$W/up.log" 2>&1 & local UP=$!; track $UP
  # wait for the acceptor's ready banner instead of a fixed 4s
  wait_log "$W/up.log" 'filament up —' 20 0.2 || note "L2 up ready-banner not seen (continuing)"
  pause 0.5
  runB "filament grant laptop shell   (consent: deny-by-default)"
  env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" "$FILAMENT" grant laptop shell 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  pause 0.5   # small settle so the grant propagates before the ssh attempt
  local AHOME="$W/Ahome"; mkdir -p "$AHOME"
  runA "filament shell server --ssh -- echo OK"
  local OUT rc tries=0
  while [ $tries -lt 3 ]; do
    OUT=$(timeout 35 env HOME="$AHOME" FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=server \
       FILAMENT_SSH_PORT="$PORT" FILAMENT_SSH_USER="$USERNAME" \
       "$FILAMENT" --server "$UX_SERVER" shell server --ssh 'echo OK-OVER-FILAMENT' 2>"$W/ssh.err" </dev/null)
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
    || fail "ssh over tunnel did not return remote output (rc=$rc); shell --ssh ProxyCommand calls 'filament netcat' which is not a verb in the 0.8.5 surface (product bug, not a rig fault)"
}

# ======================================================================== 11 ==
# Regression demo for the live-pairing bug: a device paired AFTER the always-on
# daemon started used to be invisible until restart. Now the running daemon
# picks it up live ("new device 'X' paired — now reachable") and it connects.
sc_11_live_pairing() {
  cap "always-on 'up'; pair a NEW device MID-SESSION; it connects live — no restart"
  ensure_payload
  local DUP=$(fresh_cfg s11up) DOLD=$(fresh_cfg s11old) DNEW=$(fresh_cfg s11new) DD=$(fresh_cfg s11drop)
  # The daemon starts knowing ONLY 'old', created by a real ceremony.
  pair_two "$DUP" old "$DOLD" box || { fail "pair_two old failed"; return; }
  runB "filament up   (the box — knows only 'old' right now)"
  FILAMENT_CONFIG_DIR="$DUP" timeout -k 5 60 "$FILAMENT" up --dir "$DD" --server "$UX_SERVER" </dev/null >"$UX_WORK/11up.log" 2>&1 & local UP=$!; track $UP
  wait_log "$UX_WORK/11up.log" 'filament up —' 15 0.15 || note "up ready-banner not seen (continuing)"
  pause 0.6
  b "roster at startup: { old }   (the daemon is now running, untouched from here on)"
  pause 0.8
  note "── now, WITHOUT restarting the daemon, a real 'add' ceremony adds a NEW device ──"
  runA "new device:  filament add --name box   (mints a code; claims into the live store)"
  # A real add ceremony runs against the LIVE daemon's store: 'new' mints, the
  # box's config claims. No record is written by hand, so the shape on disk is
  # whatever the shipping ceremony actually writes. The daemon re-scans ~2s and
  # subscribes live.
  pair_two "$DNEW" box "$DUP" new || { fail "mid-session add failed"; kill $UP 2>/dev/null; return; }
  b "store is now { old, new } — the daemon was NOT restarted"
  # The fixed daemon re-scans the store every ~2s and subscribes live.
  if wait_log "$UX_WORK/11up.log" "new device 'new' paired, now reachable" 10 0.25; then
    b "$(grep -h "now reachable" "$UX_WORK/11up.log" | tail -1)"
  else
    note "(daemon did not log live pickup — on an UNFIXED build it never would)"
  fi
  pause 0.8
  runA "new device:  filament send report.pdf --to box   (no restart, no code)"
  FILAMENT_CONFIG_DIR="$DNEW" timeout -k 5 30 "$FILAMENT" send "$PAY" --name report.pdf --to box --server "$UX_SERVER" >"$UX_WORK/11s.log" 2>&1; local rc=$?
  pause 1
  kill $UP 2>/dev/null
  local h2 RCV; RCV=$(ls "$DD" 2>/dev/null | head -1); h2=$(hashof "$DD/$RCV" 2>/dev/null || echo none)
  local logged=0; grep -q "new device 'new' paired, now reachable" "$UX_WORK/11up.log" && logged=1
  if [ $rc -eq 0 ] && [ "$h2" = "$(hashof "$PAY")" ] && [ "$logged" -eq 1 ]; then
    pass "device paired mid-session connected live and delivered — no restart needed"
  else
    fail "mid-session-paired device did not connect live (rc=$rc logged=$logged)"
  fi
}

# ======================================================================== 12 ==
# down must stop only the daemon it targets, through the right manager. Two
# daemons coexist, one system-managed, one user-managed, both named with the
# 'filament' substring so a substring-based manager pick is ambiguous. The
# invariant is the negative case a single-unit test cannot see: after `down` for
# one config dir, the OTHER daemon's process is untouched.
#
# NOTE on Restart: product units (install_system_service / install_systemd_user)
# use Restart=always, so the pid-kill `down` cannot keep a systemd daemon down
# (systemd restarts it in RestartSec). These test units deliberately omit
# Restart so the TARGETING invariant is deterministic; the restart gap is a
# separate product finding, not something this scenario should paper over.
sc_12_down_dual() {
  cap "down targets ONE daemon: system-managed + user-managed coexist; down stops only its own"
  [[ "$(id -u)" -eq 0 ]] || { fail "needs root to create the system unit"; return; }
  backend_start || { fail "backend did not start"; return; }
  local SYS="filament-uxrig-sys" USR="filament-uxrig-user"
  local DSYS USR_DROP USER_DROP
  DSYS=$(fresh_cfg s12sys); local DUSR=$(fresh_cfg s12usr)
  local DS=$(fresh_cfg s12drop) DU=$(fresh_cfg s12drop2)
  local SYSUNIT="/etc/systemd/system/$SYS.service"
  local USRUNIT="$HOME/.config/systemd/user/$USR.service"
  cleanup12() {
    systemctl stop "$SYS" 2>/dev/null; systemctl disable "$SYS" 2>/dev/null
    systemctl --user stop "$USR" 2>/dev/null; systemctl --user disable "$USR" 2>/dev/null
    rm -f "$SYSUNIT" "$USRUNIT"
    systemctl daemon-reload 2>/dev/null; systemctl --user daemon-reload 2>/dev/null
  }
  # clear any leftovers from a previous failed run, then install both units
  cleanup12
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$SYSUNIT" <<UNIT
[Unit]
Description=filament ux rig system daemon
After=network-online.target
[Service]
Type=simple
Environment=FILAMENT_CONFIG_DIR=$DSYS
Environment=FILAMENT_SERVER=$UX_SERVER
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$FILAMENT up --dir $DS
[Install]
WantedBy=multi-user.target
UNIT
  cat > "$USRUNIT" <<UNIT
[Unit]
Description=filament ux rig user daemon
[Service]
Type=simple
Environment=FILAMENT_CONFIG_DIR=$DUSR
Environment=FILAMENT_SERVER=$UX_SERVER
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$FILAMENT up --dir $DU
[Install]
WantedBy=default.target
UNIT
  systemctl daemon-reload || { fail "system daemon-reload"; cleanup12; return; }
  systemctl start "$SYS" || { fail "system unit start"; cleanup12; return; }
  systemctl --user daemon-reload || { fail "user daemon-reload"; cleanup12; return; }
  systemctl --user start "$USR" || { fail "user unit start"; cleanup12; return; }
  wait_for 25 0.4 test -f "$DSYS/up.pid" || { fail "system daemon never wrote up.pid"; cleanup12; return; }
  wait_for 25 0.4 test -f "$DUSR/up.pid" || { fail "user daemon never wrote up.pid"; cleanup12; return; }
  local PID_SYS PID_USR
  PID_SYS=$(cat "$DSYS/up.pid" 2>/dev/null); PID_USR=$(cat "$DUSR/up.pid" 2>/dev/null)
  note "system daemon pid=$PID_SYS  user daemon pid=$PID_USR"
  kill -0 "$PID_SYS" 2>/dev/null || { fail "system daemon not alive"; cleanup12; return; }
  kill -0 "$PID_USR" 2>/dev/null || { fail "user daemon not alive"; cleanup12; return; }
  runA "filament down -y   (config dir of the SYSTEM daemon)"
  FILAMENT_CONFIG_DIR="$DSYS" "$FILAMENT" down -y 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  sleep 2
  # invariant: the targeted (system) daemon is gone; the user daemon is untouched.
  local sys_gone=1 usr_same=0
  kill -0 "$PID_SYS" 2>/dev/null && sys_gone=0
  kill -0 "$PID_USR" 2>/dev/null && [ "$(cat "$DUSR/up.pid" 2>/dev/null)" = "$PID_USR" ] && usr_same=1
  local sys_state usr_state
  sys_state=$(systemctl is-active "$SYS" 2>/dev/null | head -1)
  usr_state=$(systemctl --user is-active "$USR" 2>/dev/null | head -1)
  note "after down: system=$sys_state (pid gone=$([ $sys_gone = 1 ] && echo yes || echo NO))  user=$usr_state (pid untouched=$([ $usr_same = 1 ] && echo yes || echo NO))"
  if [ "$sys_gone" = 1 ] && [ "$usr_same" = 1 ]; then
    pass "down stopped ONLY the system daemon; the user daemon survived untouched"
  else
    fail "down did not target cleanly (system gone=$sys_gone, user untouched=$usr_same)"
  fi
  cleanup12
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
  11) sc_11_live_pairing ;;
  12) sc_12_down_dual ;;
  *) echo "usage: scenarios.sh <01..06|11|12>"; exit 2 ;;
esac
