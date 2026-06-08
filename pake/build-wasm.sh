#!/usr/bin/env bash
# Build the shared SPAKE2 core to WASM and emit wasm-bindgen JS bindings into
# the frontend. Run from anywhere. Regenerate after any change to pake/src.
#
# Output: frontend/src/pake/  (filament_pake.js, filament_pake_bg.wasm, .d.ts)
# These are COMMITTED so a plain `npm run build` needs no Rust toolchain.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../frontend/src/pake"

cargo build --manifest-path "$HERE/Cargo.toml" --release --target wasm32-unknown-unknown
mkdir -p "$OUT"
wasm-bindgen --target web --out-dir "$OUT" \
  "$HERE/target/wasm32-unknown-unknown/release/filament_pake.wasm"

# Optional: shrink with wasm-opt if available (spec risk #3 — measure size).
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz -o "$OUT/filament_pake_bg.wasm" "$OUT/filament_pake_bg.wasm"
  echo "wasm-opt applied"
fi
echo "wasm size: $(wc -c < "$OUT/filament_pake_bg.wasm") bytes"
echo "wrote bindings to $OUT"
