#!/usr/bin/env bash
# Shared hermetic-gate fixture. Source this from a gate script (which must set
# PORT, SERVER, WORK, BIN, CLI_DIR, PYV, DA before sourcing), then call the
# helpers below. See mount-revoke-gates.sh / pty-revoke-gates.sh /
# l2-revoke-gates.sh for the pattern.
#
# `FILAMENT_L2=1` on the acceptor is baked into `start_acceptor`, not left to the
# caller, because pty-open / mount-open / l2-open are all gated on `l2_enabled`
# and a plain `up` leaves it off with a failure that is silent on both sides.

# --- Preconditions and refusal ---
# A HARNESS THAT CANNOT DISTINGUISH "the code is broken" from "the box cannot
# hold the build" MUST REFUSE TO REPORT, with an exit code distinct from both
# pass and fail. Assert your preconditions (free space, a warm toolchain, a free
# port, a writable temp dir) BEFORE measuring, and when one is unmet print a
# single line naming it instead of a result -- a result produced under a broken
# precondition is indistinguishable from a defect and will be read as one.
# There is no exit code that means "probably fine".
#
# Reference implementation: `scripts/flake-check.sh` (exit 0 = clean, 1 = a real
# failure, 3 = refused). A full disk once made a test target report 20/20
# failures that looked like product defects, with the only tell a single
# `No space left on device` line nothing was watching for.

# --- assertion bookkeeping ---
PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); PASSED_LIST+=("$1"); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; FAILED_LIST+=("$1"); }

# A gate whose failure is a NAMED, TRACKED defect rather than a regression.
# Same philosophy as gates-ratchet.sh: a still-broken gate does not fail the
# build (it was already broken and this job is not where that is discovered),
# but the list only ever SHRINKS -- a known-red gate that starts passing fails
# the run so the entry gets removed in the same commit, with evidence.
#
# Usage: declare KNOWN_RED_ALLOW=( "<substring of the FAIL text>" ... ) in the
# gate script, and end with `declare_known_red_summary`; see
# fleet-cert-gates.sh's AUTH-A for the worked example.
# Entries are "<pass-text>|<fail-text>" pairs, following gates-ratchet.sh: a
# gate almost never announces failure under the name it announces success, so a
# single substring cannot tell "it passed" from "it never ran".
KNOWN_RED_ALLOW=()
KNOWN_RED_HIT=()
FAILED_LIST=()
PASSED_LIST=()
declare_known_red_summary() {
  # Array-based on purpose: gate texts contain spaces, so word-splitting the
  # accumulated string would compare fragments and silently fail to match.
  local entry f hit pass_txt fail_txt
  local remaining=()
  for f in ${FAILED_LIST[@]+"${FAILED_LIST[@]}"}; do
    hit=0
    for entry in ${KNOWN_RED_ALLOW[@]+"${KNOWN_RED_ALLOW[@]}"}; do
      fail_txt="${entry#*|}"
      case "$f" in *"$fail_txt"*) hit=1 ;; esac
    done
    if [ "$hit" = "1" ]; then
      echo "KNOWN-RED: $f"
      KNOWN_RED_HIT+=("$f")
    else
      remaining+=("$f")
    fi
  done
  # The ratchet: the list only ever SHRINKS, and only with evidence.
  for entry in ${KNOWN_RED_ALLOW[@]+"${KNOWN_RED_ALLOW[@]}"}; do
    pass_txt="${entry%%|*}"
    fail_txt="${entry#*|}"
    case " ${PASSED_LIST[*]-} " in
      *"$pass_txt"*)
        echo "KNOWN-RED handled: the known-red gate '$pass_txt' now PASSES."
        echo "FAIL: a known-red gate started passing; remove its entry from KNOWN_RED_ALLOW in this commit (the list only shrinks)."
        remaining+=("known-red-gate-started-passing:$pass_txt")
        ;;
      *)
        case " ${FAILED_LIST[*]-} " in
          *"$fail_txt"*) : ;;  # reported above as KNOWN-RED
          *)
            echo "FAIL: the known-red gate '$fail_txt' neither passed nor failed -- it did not run."
            remaining+=("known-red-gate-did-not-run:$fail_txt")
            ;;
        esac
        ;;
    esac
  done
  FAILED=""
  for f in ${remaining[@]+"${remaining[@]}"}; do FAILED="$FAILED $f"; done
  FAIL=${#remaining[@]}
}

FIX_PIDS=()
fixture_cleanup() {
  for p in "${FIX_PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
}

# Start the fixture signaling backend on $PORT and block until healthy.
start_backend() {
  for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
  sleep 1
  ( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
      "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
  FIX_PIDS+=($!)
  for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
  [ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
}

# $1 = config dir. Create an owner identity named alpha there.
init_owner() {
  mkdir -p "$1"
  env FILAMENT_CONFIG_DIR="$1" "$BIN" init --name alpha --recovery-file "$1/rec.txt" --yes >/dev/null 2>&1 \
    || { echo "init failed"; exit 2; }
}

# $1 = acceptor config dir. Start the acceptor daemon (FILAMENT_L2=1 baked in).
start_acceptor() {
  env FILAMENT_CONFIG_DIR="$1" FILAMENT_L2=1 "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/up.log" 2>&1 &
  FIX_PIDS+=($!)
  sleep 2
}

# $1 = device name, $2... = extra `add` flags (e.g. `--allow shell`). Enroll a
# delegated device from the owner config, then have it join from a fresh dir.
enroll_delegate() {
  local name="$1"; shift
  local ddir="$WORK/$name"; mkdir -p "$ddir"
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" add --for "$name" "$@" --out "$WORK/$name-inv.txt" --yes >/dev/null 2>&1
  env FILAMENT_CONFIG_DIR="$ddir" "$BIN" --server "$SERVER" join --invite-file "$WORK/$name-inv.txt" --name "$name" --no-interactive >"$WORK/$name-join.log" 2>&1
  sleep 2
}

# Run `$@` with a HARD bound that can distinguish a refusal from a hang.
#
# `timeout` is not enough and neither is SIGKILL: a client waiting on a server
# that never replies can sit in uninterruptible D state, where no signal lands.
# So run detached, poll for a completion marker, and if the marker never appears
# declare it WEDGED. A wedge is a FAILURE, not a pass: "the output stopped" is
# satisfied by a hang exactly as well as by a refusal.
# Echoes the output; writes ok|err|wedged to $WORK/fs.state (a FILE, because
# callers use $(...) and a variable set inside a command substitution dies with
# its subshell). Read it with fs_state.
fs_bounded() {  # $1 = seconds, rest = command
  local secs="$1"; shift
  local out="$WORK/fs.out" done="$WORK/fs.done"
  rm -f "$out" "$done"
  ( "$@" >"$out" 2>&1; echo $? >"$done" ) &
  for _ in $(seq 1 $((secs * 2))); do [ -f "$done" ] && break; sleep 0.5; done
  if [ -f "$done" ]; then
    [ "$(cat "$done")" = "0" ] && echo ok >"$WORK/fs.state" || echo err >"$WORK/fs.state"
  else
    echo wedged >"$WORK/fs.state"
  fi
  cat "$out" 2>/dev/null
}
fs_state() { cat "$WORK/fs.state" 2>/dev/null; }

# --- certified fleet pair (two daemons, real enrolment) ----------------------
#
# `enroll_delegate` above stops at the join: it leaves the spoke's certificate
# on disk but no daemon behind it, and it asserts nothing about whether either
# end actually RESOLVED an identity. Both matter for any gate about
# certificates, because a secret-paired link resolves no identity at all, so
# `cert_revoked_for(None)` is false there and a cert-revocation gate written on
# such a link passes whatever the product does. The two helpers below close
# that: one brings the spoke's own daemon up (the product topology is two
# daemons, not a daemon plus a one-shot client), the other asserts the
# certified relationship BEFORE any gate leans on it.

# $1 = spoke config dir, $2 = spoke name. Start the joined device's daemon.
start_spoke() {
  env FILAMENT_CONFIG_DIR="$1" "$BIN" --server "$SERVER" up --dir "$WORK/$2-drop" \
    >"$WORK/up-$2.log" 2>&1 &
  FIX_PIDS+=($!)
  sleep 2
}

# $1 = owner config dir, $2 = spoke config dir, $3 = spoke name.
# Three verdicts, all of them about identity rather than reachability:
#   the owner holds a certificate for the spoke, chained to the owner user key
#   the spoke holds its own joined certificate under the same user fingerprint
#   the owner's device list does NOT file the spoke as uncertified
# The third is the one that catches a harness that "worked" by hand-seeding a
# pair secret: such a device shows up as "uncertified, trusted in full".
assert_certified() {
  local odir="$1" sdir="$2" name="$3"
  local ojson sjson
  ojson=$(env FILAMENT_CONFIG_DIR="$odir" "$BIN" id --json 2>/dev/null)
  sjson=$(env FILAMENT_CONFIG_DIR="$sdir" "$BIN" id --json 2>/dev/null)

  if printf '%s' "$ojson" | python3 -c "
import json,sys
d=json.load(sys.stdin)
sys.exit(0 if d.get('role')=='owner' and any(x['name']==sys.argv[1] and x.get('devicePub') for x in d.get('devices',[])) else 1)
" "$name" 2>/dev/null; then
    ok "enrolment: owner certified '$name' (filament id lists its device key)"
  else
    echo "-- owner id --json --"; printf '%s\n' "$ojson"
    bad "enrolment: owner holds no certificate for '$name'"
  fi

  # The fingerprint is the first 8 hex of the user pubkey on BOTH surfaces
  # (owner: its own key; joined device: the user_pub inside its certificate),
  # so comparing them is what proves the spoke's certificate chains to THIS
  # owner rather than merely existing.
  if OJ="$ojson" SJ="$sjson" python3 -c "
import json,os,sys
o=json.loads(os.environ['OJ']); s=json.loads(os.environ['SJ'])
sys.exit(0 if (s.get('configured') and s.get('role')=='joined-device'
               and s.get('holdsOwnerSigningKey') is False
               and s.get('fingerprint') and s['fingerprint']==o.get('fingerprint')) else 1)
" 2>/dev/null; then
    ok "enrolment: '$name' holds a joined certificate chained to the owner's key"
  else
    echo "-- spoke id --json --"; printf '%s\n' "$sjson"
    bad "enrolment: '$name' did not end up as a joined device"
  fi

  local list
  list=$(env FILAMENT_CONFIG_DIR="$odir" "$BIN" devices 2>&1)
  if printf '%s' "$list" | grep -q "$name" \
     && ! printf '%s' "$list" | grep -q "NEEDS REVIEW" \
     && ! printf '%s' "$list" | grep -qi "uncertified"; then
    ok "enrolment: owner files '$name' as certified, not 'uncertified, trusted in full'"
  else
    echo "-- owner devices --"; printf '%s\n' "$list"
    bad "enrolment: owner still sees '$name' as uncertified"
  fi
}
