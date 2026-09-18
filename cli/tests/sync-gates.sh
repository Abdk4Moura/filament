#!/usr/bin/env bash
# `filament sync` end-to-end gates. Standalone, hermetic, fixture port 8107 ONLY.
# Two daemons' worth of identity (acceptor `up` + one-shot initiator), a
# reciprocal pair secret so B trusts A, real bytes over the real link.
#
#   FILAMENT_BIN=/path/to/filament ./sync-gates.sh
#
# TWO PAIRING STYLES, and the gate says which arm uses which:
#   * A to H are SECRET-PAIRED: each side hand-writes the other's name and a
#     shared secret into devices.json. That link resolves NO device identity, so
#     no capability or ceiling check can bind to it. It is the right fixture for
#     everything about paths, deltas, resumes and refusals of the wrong target.
#   * I is ENROLLED: an owner mints an invitation for a named device with an
#     explicit ceiling (`add --for <name> --allow <caps>`), the device joins, and
#     the capability check has an identity to bind to. This is the only style in
#     which "a peer that cannot send/receive cannot sync" can be EXPRESSED at all;
#     asserted on a secret-paired link it would pass for the wrong reason.
#
# Gates:
#   A  FIRST SYNC -- every file lands (`sent`), the symlink is `skipped: symlink`,
#      bytes moved == the tree's size, landed bytes identical.
#   B  DELTA -- change ONE chunk of one file and add one file: exactly those two
#      move (one `updated` of exactly one chunk, one `sent`), the rest `same`,
#      bytes moved == that chunk + the new file. The rsync claim, measured.
#   C  NO-OP -- an unchanged re-run moves 0 bytes.
#   D  ESCAPE -- `boxB:../x` and `boxB:/etc` are refused (exit 4), nothing created.
#   E  DRY RUN -- `-n` prints the plan and creates nothing on B.
#   F  UNKNOWN DEVICE -- exit 3.
#   G  DELETE -- `--delete` removes the one file B has that A no longer does.
#   H  RESUME -- with a landed file gone and another truncated on B, a re-run
#      moves only the missing chunk and the missing file.
#   I  CAPABILITY (enrolled pairing) -- a device whose ceiling has NO transfer is
#      refused with exit 4 and a named reason, and a device whose ceiling HAS
#      transfer syncs on the same fixture. The positive half is what separates
#      "refuses the right thing" from "refuses everything".
#   J  CORRUPTION -- a landed file overwritten with SAME-SIZE different bytes is
#      re-sent (`updated`, whole file), never accepted as up to date. Same size on
#      purpose: a size-only or mtime-only comparison would call it `same`.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8107
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-sync-gates.XXXXXX")"
DA="$WORK/A"; DB="$WORK/B"; mkdir -p "$DA" "$DB"

# shellcheck source=lib/fixture.sh
. "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
start_backend

SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxB","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxA","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"
DROP="$WORK/Bdrop"; mkdir -p "$DROP"
env FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB "$BIN" up --dir "$DROP" --server "$SERVER" >"$WORK/up.log" 2>&1 &
FIX_PIDS+=($!)
sleep 3

SYNC=(env FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=boxA timeout 120 "$BIN" --server "$SERVER")
CHUNK=262144

# --- the tree: a (300 B), big (3 chunks), sub/c (5 B), link (symlink) ---
TREE="$WORK/tree"; mkdir -p "$TREE/sub"
head -c 300 /dev/urandom > "$TREE/a"
python3 -c "import sys; sys.stdout.buffer.write(bytes(i % 251 for i in range($CHUNK*3)))" > "$TREE/big"
printf 'hello' > "$TREE/sub/c"
ln -s /etc/hostname "$TREE/link"
TOTAL=$((300 + CHUNK*3 + 5))

# state<TAB>file<TAB>bytes per per-file record, sorted by file
jstates() { python3 - "$1" <<'PY'
import json,sys
rows=[]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    d=json.loads(line).get("data",{})
    if "file" in d: rows.append((d["file"],d["state"],d["bytes"]))
for f,s,b in sorted(rows): print(f"{s}\t{f}\t{b}")
PY
}
# one field of the LAST record's data (or error) object
jfinal() { python3 - "$1" "$2" <<'PY'
import json,sys
lines=[l for l in open(sys.argv[1]) if l.strip()]
d=json.loads(lines[-1]); print((d.get("data") or d.get("error") or {}).get(sys.argv[2]))
PY
}
same_bytes() { cmp -s "$TREE/$1" "$DROP/inbox/$1"; }

# ===================================================================== GATE A ==
say A
"${SYNC[@]}" --json sync "$TREE" boxB:inbox >"$WORK/A.jsonl" 2>"$WORK/A.err"; rcA=$?
echo "## rc=$rcA"; cat "$WORK/A.jsonl"
if [ "$rcA" = 0 ]; then ok "gateA: first sync exits 0"; else cat "$WORK/A.err"; tail -20 "$WORK/up.log"; bad "gateA: first sync rc=$rcA"; fi
if [ "$(jstates "$WORK/A.jsonl")" = "$(printf 'sent\ta\t300\nsent\tbig\t%s\nskipped\tlink\t0\nsent\tsub/c\t5' $((CHUNK*3)))" ]; then
  ok "gateA: three files sent, the symlink skipped"
else jstates "$WORK/A.jsonl"; bad "gateA: per-file records wrong"; fi
[ "$(jfinal "$WORK/A.jsonl" moved)" = "$TOTAL" ] && ok "gateA: bytes moved == tree size ($TOTAL)" || bad "gateA: moved=$(jfinal "$WORK/A.jsonl" moved) want $TOTAL"
if same_bytes a && same_bytes big && same_bytes sub/c && [ ! -e "$DROP/inbox/link" ]; then
  ok "gateA: landed bytes identical, no symlink landed"
else ls -la "$DROP/inbox"; bad "gateA: landed tree differs"; fi

# ===================================================================== GATE B ==
say B
python3 - "$TREE/big" "$CHUNK" <<'PY'
import sys
p,chunk=sys.argv[1],int(sys.argv[2])
with open(p,"r+b") as f:
    f.seek(chunk+100); f.write(b"\xff\xfe\xfd")
PY
head -c 1000 /dev/urandom > "$TREE/d"
"${SYNC[@]}" --json sync "$TREE" boxB:inbox >"$WORK/B.jsonl" 2>"$WORK/B.err"; rcB=$?
echo "## rc=$rcB"; cat "$WORK/B.jsonl"
if [ "$rcB" = 0 ] && [ "$(jstates "$WORK/B.jsonl")" = "$(printf 'same\ta\t0\nupdated\tbig\t%s\nsent\td\t1000\nskipped\tlink\t0\nsame\tsub/c\t0' "$CHUNK")" ]; then
  ok "gateB: exactly two files moved: one chunk of big, all of d"
else cat "$WORK/B.err"; jstates "$WORK/B.jsonl"; bad "gateB: delta records wrong (rc=$rcB)"; fi
[ "$(jfinal "$WORK/B.jsonl" moved)" = "$((CHUNK + 1000))" ] && ok "gateB: bytes moved == one chunk + d ($((CHUNK+1000)))" || bad "gateB: moved=$(jfinal "$WORK/B.jsonl" moved)"
if same_bytes big && same_bytes d && same_bytes a; then ok "gateB: landed bytes identical after the delta"; else bad "gateB: landed tree differs after the delta"; fi

# ===================================================================== GATE C ==
say C
"${SYNC[@]}" sync "$TREE" boxB:inbox >"$WORK/C.out" 2>&1; rcC=$?
cat "$WORK/C.out"
if [ "$rcC" = 0 ] && grep -q '0 B of .* moved' "$WORK/C.out" && [ "$(grep -c '^  same ' "$WORK/C.out")" = 4 ] && ! grep -qE '^  (sent|updated) ' "$WORK/C.out"; then
  ok 'gateC: unchanged re-run moves 0 bytes, four same lines'
else bad "gateC: no-op re-run moved something (rc=$rcC)"; fi

# ===================================================================== GATE D ==
say D
"${SYNC[@]}" sync "$TREE" boxB:../escape >"$WORK/D1.out" 2>&1; rcD1=$?
cat "$WORK/D1.out"
if [ "$rcD1" = 4 ] && grep -qi 'outside' "$WORK/D1.out" && [ ! -e "$WORK/escape" ]; then
  ok "gateD: ../escape refused with exit 4, nothing created"
else ls "$WORK"; bad "gateD: ../escape not refused cleanly (rc=$rcD1)"; fi
"${SYNC[@]}" --json sync "$TREE" boxB:/etc >"$WORK/D2.jsonl" 2>/dev/null; rcD2=$?
cat "$WORK/D2.jsonl"
if [ "$rcD2" = 4 ] && [ "$(jfinal "$WORK/D2.jsonl" code)" = denied ]; then
  ok "gateD: absolute /etc refused, --json error envelope code=denied exit 4"
else bad "gateD: /etc not refused (rc=$rcD2)"; fi

# ===================================================================== GATE E ==
say E
"${SYNC[@]}" sync -n "$TREE" boxB:dry >"$WORK/E.out" 2>&1; rcE=$?
cat "$WORK/E.out"
if [ "$rcE" = 0 ] && [ ! -e "$DROP/dry" ] && [ "$(grep -c '^  would send ' "$WORK/E.out")" = 4 ] && grep -q 'nothing moved' "$WORK/E.out"; then
  ok "gateE: dry run prints the plan and creates nothing on B"
else ls -la "$DROP"; bad "gateE: dry run touched B or printed no plan (rc=$rcE)"; fi

# ===================================================================== GATE F ==
say F
"${SYNC[@]}" sync "$TREE" nosuchbox:inbox >"$WORK/F.out" 2>&1; rcF=$?
cat "$WORK/F.out"
[ "$rcF" = 3 ] && ok "gateF: unknown device exits 3" || bad "gateF: unknown device rc=$rcF"

# ===================================================================== GATE G ==
say G
rm "$TREE/a"
"${SYNC[@]}" sync --delete "$TREE" boxB:inbox >"$WORK/G.out" 2>&1; rcG=$?
cat "$WORK/G.out"
if [ "$rcG" = 0 ] && [ ! -e "$DROP/inbox/a" ] && grep -q '^  deleted  a$' "$WORK/G.out" && same_bytes big; then
  ok "gateG: --delete removed the one extraneous file"
else ls "$DROP/inbox"; bad "gateG: --delete did not remove a (rc=$rcG)"; fi

# ===================================================================== GATE H ==
say H
rm "$DROP/inbox/sub/c"
truncate -s $((CHUNK*2)) "$DROP/inbox/big"
"${SYNC[@]}" --json sync "$TREE" boxB:inbox >"$WORK/H.jsonl" 2>"$WORK/H.err"; rcH=$?
echo "## rc=$rcH"; cat "$WORK/H.jsonl"
if [ "$rcH" = 0 ] && [ "$(jstates "$WORK/H.jsonl")" = "$(printf 'updated\tbig\t%s\nsame\td\t0\nskipped\tlink\t0\nsent\tsub/c\t5' "$CHUNK")" ] && same_bytes big && same_bytes sub/c; then
  ok "gateH: resume moves only the missing chunk and the missing file"
else cat "$WORK/H.err"; jstates "$WORK/H.jsonl"; bad "gateH: resume moved the wrong set (rc=$rcH)"; fi


# ===================================================================== GATE I ==
# Criterion (a): a peer that cannot send/receive cannot sync, and one that CAN
# still does. THIS IS THE ONLY ARM IN THIS GATE THAT USES THE ENROLLED PAIRING
# STYLE, and it has to be: the capability check is keyed on IDENTITY, while the
# boxA/boxB pair above is secret-paired and therefore resolves no identity at all
# (the same reason fleet-cert-gates.sh exists). Asserting a capability refusal on
# a secret-paired link would pass for the wrong reason, which is the disease, not
# the cure.
#
# The enrol commands are inlined rather than calling enroll_delegate, because
# that helper reads `$DA` as the owner directory and this arm's owner is a fresh
# one; the COMMANDS are the same ones the helper issues.
say I
DO="$WORK/owner"
init_owner "$DO"
env FILAMENT_CONFIG_DIR="$DO" FILAMENT_NAME=alpha "$BIN" --server "$SERVER" up --dir "$WORK/owner-drop" >"$WORK/up-owner.log" 2>&1 &
FIX_PIDS+=($!)
sleep 3
for d in nosend cansend; do
  case "$d" in
    nosend) ALLOW="shell" ;;      # NO transfer in the ceiling
    cansend) ALLOW="transfer" ;;  # transfer IS in the ceiling
  esac
  DDC="$WORK/$d"
  mkdir -p "$DDC"
  env FILAMENT_CONFIG_DIR="$DO" "$BIN" --server "$SERVER" add --for "$d" --allow "$ALLOW" \
    --out "$WORK/$d-inv.txt" --yes >/dev/null 2>&1
  env FILAMENT_CONFIG_DIR="$DDC" "$BIN" --server "$SERVER" join \
    --invite-file "$WORK/$d-inv.txt" --name "$d" --no-interactive >"$WORK/$d-join.log" 2>&1
done
sleep 2
mkdir -p "$WORK/itree"; head -c 100 /dev/urandom > "$WORK/itree/f"

# NEGATIVE: no transfer in the ceiling -> refused, exit 4, with a reason.
env FILAMENT_CONFIG_DIR="$WORK/nosend" FILAMENT_NAME=nosend timeout 120 "$BIN" \
  --server "$SERVER" sync "$WORK/itree" alpha:inbox >"$WORK/I-neg.out" 2>&1; rcI=$?
# The refusal is asserted in TWO places, because they say different things:
#   * the OWNER'S LOG carries the decision, and it names the ceiling: "this
#     capability is outside the device's invitation ceiling";
#   * the CLIENT is told "identity not proven within 2000 ms; retry", because the
#     open is parked for identity proof and the settle window expires first. That
#     surfaced reason is a FINDING about the message (it names the settle timeout
#     rather than the capability, and its "retry" invites a loop for a capability
#     that will never be granted) and is reported rather than asserted here.
if [ "$rcI" = 4 ] && grep -qi "outside the device's invitation ceiling" "$WORK/up-owner.log"; then
  ok "gateI: a peer without transfer in its ceiling is refused (exit 4, owner names the ceiling)"
else
  cat "$WORK/I-neg.out"; tail -20 "$WORK/up-owner.log"
  bad "gateI: peer without transfer not refused (rc=$rcI)"
fi

# POSITIVE half, so a gate that refuses EVERYTHING is distinguishable from one
# that refuses only the wrong thing.
env FILAMENT_CONFIG_DIR="$WORK/cansend" FILAMENT_NAME=cansend timeout 120 "$BIN" \
  --server "$SERVER" sync "$WORK/itree" alpha:inbox >"$WORK/I-pos.out" 2>&1; rcI2=$?
if [ "$rcI2" = 0 ] && [ -f "$WORK/owner-drop/inbox/f" ]; then
  ok "gateI: a peer WITH transfer in its ceiling syncs (exit 0, file landed)"
else
  cat "$WORK/I-pos.out"; tail -20 "$WORK/up-owner.log"; ls -la "$WORK/owner-drop" 2>/dev/null
  bad "gateI: covered peer did not sync (rc=$rcI2)"
fi

# ===================================================================== GATE J ==
# Criterion (c): the delta path verifies content hashes on arrival, so a partial
# or corrupted block is never accepted as up to date. The corruption is SAME SIZE
# on purpose: a size-only or mtime-only comparison would call this file "same" and
# skip it, so the arm is discriminating only in this shape.
say J
BIGSZ=$(stat -c%s "$TREE/big")
python3 -c "import sys; sys.stdout.buffer.write(bytes((i*7+3) % 251 for i in range($BIGSZ)))" > "$DROP/inbox/big"
if cmp -s "$TREE/big" "$DROP/inbox/big"; then
  bad "gateJ: the corruption did not take, so this arm would have tested nothing"
else
  "${SYNC[@]}" --json sync "$TREE" boxB:inbox >"$WORK/J.jsonl" 2>"$WORK/J.err"; rcJ=$?
  echo "## rc=$rcJ"; cat "$WORK/J.jsonl"
  if [ "$rcJ" = 0 ] && jstates "$WORK/J.jsonl" | grep -q "$(printf 'updated\tbig\t%s' "$BIGSZ")" && same_bytes big; then
    ok "gateJ: a same-size corrupted block is re-sent ($BIGSZ bytes, state updated), never accepted as up to date"
  else
    cat "$WORK/J.err"; jstates "$WORK/J.jsonl"
    bad "gateJ: a corrupted same-size block was treated as up to date (rc=$rcJ)"
  fi
fi
echo
echo "== sync gates: PASS=$PASS FAIL=$FAIL${FAILED:+ (failed:$FAILED)} =="
[ "$FAIL" = 0 ]
