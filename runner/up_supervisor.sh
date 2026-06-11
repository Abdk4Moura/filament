#!/usr/bin/env bash
# Keep a long-lived `filament up` acceptor ALIVE across signaling drops.
#
# WHY: the filament socket.io client is built with reconnect(false) (cli/src/net.rs),
# and `up`/`up --dir` runs ONE signaling connection with no outer reconnect loop. On
# a flaky WAN link, when the signaling TCP is severed the acceptor's socket dies and
# it never re-announces — it becomes a zombie that the sender can no longer discover
# (reproduced deterministically by runner/sim/flaky_sim_test.sh). Short discrete
# `filament send`s recover (each reconnects fresh), but a long-lived acceptor does not.
#
# This supervisor makes the acceptor self-healing WITHOUT a core CLI change: it runs
# the acceptor and PROACTIVELY RESTARTS it on a cadence (and immediately if it exits),
# so a fresh acceptor — which re-announces and is rediscoverable — is always present
# within `--cadence` seconds. Restarting `up --dir` is safe/idempotent: it just
# receives files into the inbox, and filament keeps partials + resumes, so an
# interrupted transfer continues on the next send.
#
# Usage:
#   up_supervisor.sh --cadence 25 --log /path/up.log -- \
#       filament up --server "$SRV" --name-as box-din --dir "$INBOX" --relay
#
# Env: FILAMENT_CONFIG_DIR / HOME / FILAMENT_L2 are inherited by the child as set.
set -u

CADENCE=25
LOG=""
PIDFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cadence) CADENCE="$2"; shift 2;;
    --log)     LOG="$2"; shift 2;;
    --pidfile) PIDFILE="$2"; shift 2;;
    --)        shift; break;;
    *) echo "up_supervisor: unknown arg $1" >&2; exit 2;;
  esac
done
[ $# -gt 0 ] || { echo "up_supervisor: provide the acceptor command after --" >&2; exit 2; }

[ -n "$PIDFILE" ] && echo $$ > "$PIDFILE"
say() { printf '[up-supervisor] %s\n' "$*"; [ -n "$LOG" ] && printf '[up-supervisor] %s\n' "$*" >> "$LOG"; }

CHILD=""
cleanup() { [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

say "supervising: $* (restart cadence ${CADENCE}s)"
while true; do
  if [ -n "$LOG" ]; then
    "$@" >>"$LOG" 2>&1 &
  else
    "$@" &
  fi
  CHILD=$!
  # wait up to CADENCE seconds, but react immediately if the child exits
  waited=0
  while [ "$waited" -lt "$CADENCE" ]; do
    kill -0 "$CHILD" 2>/dev/null || { say "acceptor exited; restarting"; break; }
    sleep 1; waited=$((waited+1))
  done
  # proactive cycle: replace a possibly-zombied acceptor with a fresh, re-announcing one
  kill "$CHILD" 2>/dev/null || true
  wait "$CHILD" 2>/dev/null || true
  CHILD=""
done
