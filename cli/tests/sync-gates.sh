#!/usr/bin/env bash
# `filament sync` end-to-end gates. Standalone, hermetic, fixture port 8107 ONLY.
# Two daemons' worth of identity (acceptor `up` + one-shot initiator), a
# reciprocal pair secret so B trusts A, real bytes over the real link.
#
#   FILAMENT_BIN=/path/to/filament ./sync-gates.sh
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

echo
echo "== sync gates: PASS=$PASS FAIL=$FAIL${FAILED:+ (failed:$FAILED)} =="
[ "$FAIL" = 0 ]
