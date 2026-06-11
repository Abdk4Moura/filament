#!/usr/bin/env bash
# filament job-runner — HOST pairing helper.
#
# Generates the three pair secrets (ctl/din/dout) and plants them in the host's
# job-runner config dirs, then prints the exact env block to paste into the T4
# bring-up. Run this ONCE on the host (this machine); keep the secrets private.
#
# Usage:  runner/pair_host.sh [host_config_root]
#   host_config_root defaults to ~/.filament-jobrunner
set -euo pipefail

ROOT="${1:-$HOME/.filament-jobrunner}"
SERVER="${FILJOB_SERVER:-https://api.filament.autumated.com}"
mkdir -p "$ROOT/host" "$ROOT/host-dout"

gen() { openssl rand -hex 32; }
SEC_CTL="$(gen)"; SEC_DIN="$(gen)"; SEC_DOUT="$(gen)"

python3 - "$ROOT" "$SEC_CTL" "$SEC_DIN" "$SEC_DOUT" <<'PY'
import json, sys
root, ctl, din, dout = sys.argv[1:5]
# host main config: knows the box on all three channels (initiator-only here).
json.dump([{"name":"box","secret":ctl},{"name":"box-in","secret":din},{"name":"box-out","secret":dout}],
          open(f"{root}/host/devices.json","w"))
# host dout config: the dout sink acceptor uses ONLY the dout secret.
json.dump([{"name":"box-out","secret":dout}], open(f"{root}/host-dout/devices.json","w"))
print("[pair] planted host config under", root)
PY

cat <<EOF

=== Host config ready under: $ROOT ===
  host_config_dir   = $ROOT/host
  dout_config_dir   = $ROOT/host-dout

=== Paste THIS on the T4 (then run bringup_t4.sh) ===
export FILJOB_SERVER="$SERVER"
export SEC_CTL="$SEC_CTL"
export SEC_DIN="$SEC_DIN"
export SEC_DOUT="$SEC_DOUT"

Keep these secrets private. Anyone with all three can pair as your box.
EOF
