#!/usr/bin/env bash
# cs: the reserve Codespace for interactive Rust work on filament.
#
# Codespaces hours are limited, so the default build path is scripts/rbuild.sh
# (free Actions runner). This script is for the cases Actions cannot do: a
# tight edit/compile loop, debugging a failing test, poking at a live binary.
# It reuses ONE existing Codespace (by default the Egregoria one, a 4-core
# 16 GB machine) rather than creating more, keeps filament cloned at
# /workspaces/filament on its disk so builds stay incremental, and always
# hands you a `down` to stop the meter.
#
#   scripts/cs.sh status              # state, disk, filament checkout
#   scripts/cs.sh up                  # start, clone/refresh filament, check toolchain
#   scripts/cs.sh build [--ref R] [-- cargo args]   # up + build on the remote
#   scripts/cs.sh fetch [--out DIR]   # copy cli/target/release/filament back
#   scripts/cs.sh run   [--ref R] [--out DIR] [-- cargo args]  # up+build+fetch+down
#   scripts/cs.sh sync                # rsync the working tree (uncommitted ok)
#   scripts/cs.sh sh [cmd...]         # interactive shell, or run one command
#   scripts/cs.sh clean               # cargo clean Egregoria + filament targets
#   scripts/cs.sh down                # stop it (ALWAYS do this when done)
#
# Env: FILAMENT_CS (codespace name), FILAMENT_CS_DIR (remote checkout dir).
# The Codespace's idle timeout (30 min) cannot be changed with gh; it is the
# safety net, `down` is the rule.

set -euo pipefail

CS="${FILAMENT_CS:-effective-spoon-pg59gwpxj6cxv5}"
RDIR="${FILAMENT_CS_DIR:-/workspaces/filament}"
REPO_URL="${FILAMENT_CS_REPO:-https://github.com/Abdk4Moura/filament.git}"
OUT="${FILAMENT_CS_OUT:-./out/cs}"
REF=""
EXTRA=()

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "cs: missing $1" >&2; exit 2; }; }
need gh; need jq

VERB="${1:-status}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    --) shift; EXTRA=("$@"); break ;;
    *) EXTRA+=("$1"); shift ;;
  esac
done

# Run a command on the codespace. gh starts a stopped codespace implicitly.
rsh() { gh codespace ssh -c "$CS" -- "$@"; }
rbash() { gh codespace ssh -c "$CS" -- bash -lc "$(printf '%q ' "$@")"; }
state() { gh codespace view -c "$CS" --json state --jq .state 2>/dev/null || echo unknown; }

cmd_status() {
  gh codespace view -c "$CS"
  if [ "$(state)" = "Available" ]; then
    echo "--- remote"
    gh codespace ssh -c "$CS" -- bash -lc "
      df -h /workspaces 2>/dev/null | tail -1 | awk '{print \"disk: \"\$3\" used / \"\$2\" (\"\$5\")\"}'
      for d in /workspaces/*/; do t=\"\$d/target\"; [ -d \"\$t\" ] && echo \"target: \$(du -sh \"\$t\" 2>/dev/null | cut -f1) \$t\"; done
      [ -d $RDIR/cli/target ] && echo \"target: \$(du -sh $RDIR/cli/target 2>/dev/null | cut -f1) $RDIR/cli/target\"
      if [ -d $RDIR/.git ]; then cd $RDIR && echo \"filament: \$(git rev-parse --abbrev-ref HEAD) \$(git rev-parse --short HEAD)\"; else echo 'filament: not cloned'; fi
      command -v cargo >/dev/null && echo \"cargo: \$(cargo --version)\" || echo 'cargo: MISSING'
      nproc | sed 's/^/cores: /'"
  else
    echo "(stopped: no remote details; \`cs.sh up\` to start)"
  fi
}

cmd_up() {
  echo "cs: starting $CS (state: $(state))"
  t0=$(date +%s)
  gh codespace ssh -c "$CS" -- bash -lc "
    set -e
    if ! command -v cargo >/dev/null 2>&1; then
      echo 'cs: installing rust toolchain'
      curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
    fi
    if [ ! -d $RDIR/.git ]; then
      echo 'cs: cloning filament'
      git clone -q $REPO_URL $RDIR
    fi
    cd $RDIR && git fetch -q origin
    echo \"cs: ready  \$(cargo --version)  \$(nproc) cores  \$(df -h /workspaces | tail -1 | awk '{print \$4\" free\"}')\""
  echo "cs: up in $(( $(date +%s) - t0 ))s"
}

cmd_build() {
  cmd_up
  [ -n "$REF" ] || REF="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
  echo "cs: building origin/$REF with: cargo build --release ${EXTRA[*]:-}"
  t0=$(date +%s)
  gh codespace ssh -c "$CS" -- bash -lc "
    set -e
    cd $RDIR
    git fetch -q origin $REF
    git checkout -q --detach FETCH_HEAD
    echo \"cs: at \$(git rev-parse --short HEAD)\"
    export FILAMENT_BUILD_SHA=\$(git rev-parse --short HEAD) FILAMENT_BUILD_DATE=\$(date -u +%F)
    cd cli && cargo build --release ${EXTRA[*]:-}"
  echo "cs: build took $(( $(date +%s) - t0 ))s"
}

cmd_fetch() {
  mkdir -p "$OUT"
  gh codespace cp -c "$CS" "remote:$RDIR/cli/target/release/filament" "$OUT/filament"
  chmod +x "$OUT/filament"
  echo "cs: binary -> $OUT/filament"
}

cmd_sync() {
  need rsync
  ROOT="$(git rev-parse --show-toplevel)"
  cfg="$(mktemp)"; gh codespace ssh -c "$CS" --config > "$cfg"
  host="$(awk '/^Host /{print $2; exit}' "$cfg")"
  echo "cs: rsync $ROOT/ -> $host:$RDIR/"
  rsync -az --delete -e "ssh -F $cfg" \
    --exclude .git --exclude target --exclude node_modules --exclude out \
    "$ROOT/" "$host:$RDIR/"
  rm -f "$cfg"
}

cmd_clean() {
  gh codespace ssh -c "$CS" -- bash -lc "
    for d in /workspaces/*/target $RDIR/cli/target; do
      [ -d \"\$d\" ] && { echo \"cs: removing \$(du -sh \"\$d\" | cut -f1) \$d\"; rm -rf \"\$d\"; }
    done
    df -h /workspaces | tail -1 | awk '{print \"cs: \"\$4\" free\"}'"
}

cmd_down() {
  if [ "$(state)" = "Shutdown" ]; then echo "cs: already stopped"; return; fi
  gh codespace stop -c "$CS"
  echo "cs: stopped $CS"
}

case "$VERB" in
  status) cmd_status ;;
  up)     cmd_up ;;
  build)  cmd_build ;;
  fetch)  cmd_fetch ;;
  run)    trap 'cmd_down' EXIT; cmd_build; cmd_fetch ;;
  sync)   cmd_sync ;;
  sh)     if [ ${#EXTRA[@]} -gt 0 ]; then rbash "${EXTRA[@]}"; else gh codespace ssh -c "$CS"; fi ;;
  clean)  cmd_clean ;;
  down)   cmd_down ;;
  -h|--help|help) usage 0 ;;
  *) echo "cs: unknown verb $VERB" >&2; usage 2 ;;
esac
