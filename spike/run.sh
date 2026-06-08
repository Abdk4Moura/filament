#!/usr/bin/env bash
# SPIKE runner — reproduces all L1-0 spike gates. Throwaway quality.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "=== [1] native SPAKE2 over relay (items 1,3,4) ==="
( cd "$HERE/pake-demo" && cargo run --quiet )

echo
echo "=== [2] WASM<->native interop (item 2 — the make/break) ==="
( cd "$HERE/pake-core" \
  && cargo build --quiet --bin native_side \
  && cargo build --quiet --release --target wasm32-unknown-unknown \
  && node interop.js )

echo
echo "=== ALL SPIKE GATES GREEN ==="
