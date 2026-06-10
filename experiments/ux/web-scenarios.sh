#!/usr/bin/env bash
# cli<->web scenarios (08, 09). Each records the CLI side as an asciinema cast
# (rendered to GIF) AND the browser tab as a webm video, then composes them
# side-by-side into gallery/<id>.gif with ffmpeg.
#
#   ./web-scenarios.sh <08|09>
#
# The "web" side is the LOCAL frontend served same-origin by our backend on
# $UX_PORT (frontend/dist, built with VITE_FILAMENT_API= so it signals to the
# same origin). Both peers live on 127.0.0.1 → same auto-room; the file moves by
# normal same-network discovery. (Browser mDNS is disabled in the drivers so
# single-host CLI<->browser ICE completes — see web/recv-by-code.js.)
set -uo pipefail
: "${ZSH_VERSION:=}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/rig/lib.sh"
ID="$1"
RES="$UX_WORK/results-$ID.txt"
GIF="$HERE/gallery/$ID.gif"
mkdir -p "$HERE/gallery" "$HERE/casts"

# ensure the frontend dist exists + is same-origin
DIST="$REPO/frontend/dist/index.html"
if [ ! -f "$DIST" ] || grep -ql "api.filament.autumated.com" "$REPO"/frontend/dist/assets/*.js 2>/dev/null; then
  echo "[web] (re)building frontend same-origin…"
  ( cd "$REPO/frontend" && VITE_FILAMENT_API= npm run build >"$UX_WORK/frontbuild.log" 2>&1 ) || { echo "RESULT $ID FAIL frontend-build-failed" | tee "$RES"; exit 1; }
fi

backend_start || { echo "RESULT $ID FAIL backend"; exit 1; }
head -c 350000 /dev/urandom > "$UX_WORK/web-$ID.bin"
H=$(hashof "$UX_WORK/web-$ID.bin")
VID="$UX_WORK/vid-$ID"; rm -rf "$VID"; mkdir -p "$VID"
CLICAST="$HERE/casts/$ID-cli.cast"

drive_browser() { :; }   # set per scenario

if [ "$ID" = "08" ]; then
  # CLI sends; browser (auto-room) receives + downloads.
  DS=$(fresh_cfg s08S)
  # record the CLI sender as a cast; the browser runs alongside.
  (
    "$UX_BIN/asciinema" rec -f asciicast-v2 --idle-time-limit 1.4 -q --overwrite --cols 64 --rows 26 \
      -c "bash -c '
        printf \"\n\033[1;36m=== UX: CLI sends a file → the WEB app receives it ===\033[0m\n\"
        printf \"\033[1;33m[CLI]\$\033[0m filament send invoice.pdf\n\"
        FILAMENT_CONFIG_DIR=$DS $FILAMENT send $UX_WORK/web-$ID.bin --name invoice.pdf --server $UX_SERVER 2>&1 | sed -u \"s/\\x1b\\[[0-9;]*m//g\" | grep -vE \"waiting…|spinner\" | head -40
      '" "$CLICAST" >/dev/null 2>&1
  ) & CASTPID=$!
  sleep 2
  node web/recv-by-code.js "$UX_SERVER/" "x" "$VID" >"$UX_WORK/$ID-web.log" 2>&1
  WEB_RC=$?
  wait $CASTPID 2>/dev/null
  for p in $(pgrep -f "$FILAMENT"); do tr '\0' ' ' </proc/$p/environ 2>/dev/null | grep -q "FILAMENT_CONFIG_DIR=$DS" && kill $p 2>/dev/null; done
  PASSWEB=$(grep -q "DOWNLOAD READY" "$UX_WORK/$ID-web.log" && echo yes || echo no)
  DETAIL="CLI offered invoice.pdf; browser accepted and reached the download (save) affordance"
  [ "$PASSWEB" = yes ] && VERDICT=PASS || VERDICT=FAIL

elif [ "$ID" = "09" ]; then
  # Browser sends; CLI recv receives + verifies the bytes.
  #
  # DECOUPLED into two passes (see plan): single-host browser->CLI WebRTC is the
  # most contention-sensitive flow, and a concurrent webm recorder reliably
  # breaks its ICE/datachannel timing on this one host. So:
  #   (1) VERIFY PASS  — no video. Real browser->CLI transfer, asserts sha256.
  #                      This produces the AUTHORITATIVE verdict. Retry up to 3x.
  #   (2) VISUAL PASS  — best-effort. Records the browser tab (webm) + CLI cast
  #                      for an illustrative GIF. Its outcome does NOT change the
  #                      verdict; if recording contention breaks the transfer the
  #                      GIF still shows the attempt and we say so in the gallery.
  H2=none; VERDICT=FAIL

  # ---- (1) verify pass: authoritative, no recorder ----
  for attempt in 1 2 3; do
    DR=$(fresh_cfg s09R); OUT=$(fresh_cfg s09out)
    FILAMENT_REJOIN_SECS=2 FILAMENT_CONFIG_DIR="$DR" timeout 40 "$FILAMENT" recv -y --dir "$OUT" --server "$UX_SERVER" >"$UX_WORK/09-recv.log" 2>&1 & RVPID=$!
    sleep 2
    timeout 55 node web/send-to-cli-novideo.js "$UX_SERVER/" "$UX_WORK/web-$ID.bin" "$VID" >"$UX_WORK/09-verify.log" 2>&1
    for _ in $(seq 1 20); do RCV=$(ls "$OUT" 2>/dev/null | head -1); [ -n "$RCV" ] && [ "$(hashof "$OUT/$RCV" 2>/dev/null)" = "$H" ] && break; sleep 0.5; done
    kill $RVPID 2>/dev/null; wait $RVPID 2>/dev/null
    RCV=$(ls "$OUT" 2>/dev/null | head -1); H2=$(hashof "$OUT/$RCV" 2>/dev/null || echo none)
    if [ "$H2" = "$H" ]; then VERDICT=PASS; echo "[web] verify pass attempt $attempt OK (sha256 match)"; break; fi
    echo "[web] verify pass attempt $attempt failed (h=$H2) — retrying"; sleep 2
  done

  # ---- (2) visual pass: best-effort GIF (records the browser tab) ----
  rm -rf "$VID"; mkdir -p "$VID"
  DR=$(fresh_cfg s09Rv); OUT=$(fresh_cfg s09outv)
  (
    "$UX_BIN/asciinema" rec -f asciicast-v2 --idle-time-limit 1.4 -q --overwrite --cols 64 --rows 26 \
      -c "bash -c '
        printf \"\n\033[1;36m=== UX: the WEB app sends a file → CLI recv receives it ===\033[0m\n\"
        printf \"\033[1;33m[CLI]\$\033[0m filament recv -y\n\"
        FILAMENT_REJOIN_SECS=2 FILAMENT_CONFIG_DIR=$DR timeout 30 $FILAMENT recv -y --dir $OUT --server $UX_SERVER 2>&1 | sed -u \"s/\\x1b\\[[0-9;]*m//g\" | head -40
      '" "$CLICAST" >/dev/null 2>&1
  ) & CASTPID=$!
  sleep 3
  timeout 45 node web/send-to-cli.js "$UX_SERVER/" "$UX_WORK/web-$ID.bin" "$VID" >"$UX_WORK/$ID-web.log" 2>&1 || true
  sleep 2
  for p in $(pgrep -f "$FILAMENT"); do tr '\0' ' ' </proc/$p/environ 2>/dev/null | grep -q "FILAMENT_CONFIG_DIR=$DR" && kill $p 2>/dev/null; done
  kill $CASTPID 2>/dev/null; wait $CASTPID 2>/dev/null

  DETAIL="VERIFY pass (no recorder): sha256 $([ "$H2" = "$H" ] && echo MATCHES || echo MISMATCH). GIF is a best-effort visual; single-host browser→CLI WebRTC can't complete while the webm recorder runs (recording-contention, not a product break)."
elif [ "$ID" = "10" ]; then
  # CLI `pair` mints a 4-segment PAKE code; the browser claims it via
  # "pair with code" and stores the device (localStorage filament-known-devices).
  DS=$(fresh_cfg s10S)
  (
    "$UX_BIN/asciinema" rec -f asciicast-v2 --idle-time-limit 1.4 -q --overwrite --cols 64 --rows 26 \
      -c "bash -c '
        printf \"\n\033[1;36m=== UX: pair the WEB app with the CLI (PAKE; key never crosses the server) ===\033[0m\n\"
        printf \"\033[1;33m[CLI]\$\033[0m filament pair --name browser\n\"
        FILAMENT_CONFIG_DIR=$DS timeout 50 $FILAMENT pair --name browser --server $UX_SERVER 2>&1 | sed -u \"s/\\x1b\\[[0-9;]*m//g\" | head -40
      '" "$CLICAST" >/dev/null 2>&1
  ) & CASTPID=$!
  # poll the cast file for the minted 4-segment code
  C=""; for _ in $(seq 1 60); do
    C=$(python3 - "$CLICAST" <<'PY'
import json,sys,re
out=[]
try:
  for i,l in enumerate(open(sys.argv[1])):
    if i==0: continue
    ev=json.loads(l)
    if len(ev)>=3 and ev[1]=="o": out.append(ev[2])
except Exception: pass
t=re.sub(r'\x1b\[[0-9;]*m','',''.join(out))
m=re.search(r'[A-Za-z]+-[A-Za-z]+-[A-Za-z]+-[0-9]+', t)
print(m.group(0).lower() if m else "")
PY
)
    [ -n "$C" ] && break; sleep 0.4
  done
  echo "[web] CLI minted pair code: $C"
  node web/pair-with-cli.js "$UX_SERVER/" "$C" "$VID" >"$UX_WORK/$ID-web.log" 2>&1
  WEB_RC=$?
  wait $CASTPID 2>/dev/null
  for p in $(pgrep -f "$FILAMENT"); do tr '\0' ' ' </proc/$p/environ 2>/dev/null | grep -q "FILAMENT_CONFIG_DIR=$DS" && kill $p 2>/dev/null; done
  # success: browser stored the device AND the CLI store now lists 'browser'
  STORED=$(grep -q "SECRET STORED" "$UX_WORK/$ID-web.log" && echo yes || echo no)
  CLIHAS=$(FILAMENT_CONFIG_DIR="$DS" "$FILAMENT" devices 2>/dev/null | grep -c "browser")
  if [ "$STORED" = yes ] && [ "$CLIHAS" -ge 1 ]; then VERDICT=PASS; else VERDICT=FAIL; fi
  DETAIL="browser claimed the CLI's PAKE code; both sides stored the mutual device"
fi

# ---- render: CLI cast -> gif, browser webm -> gif, hstack -------------------
# Aggressive shrink (target a few MB): 6fps, ~360px tall, 96-colour palette,
# then a gifsicle lossy+optimize pass. The browser webm dominates GIF size, so
# it is scaled hardest.
CLIGIF="$UX_WORK/$ID-cli.gif"; WEBGIF="$UX_WORK/$ID-web.gif"
"$UX_BIN/agg" --cols 64 --rows 26 --font-size 15 --speed 1.4 --theme asciinema "$CLICAST" "$CLIGIF" >/dev/null 2>&1 || true
WEBM=$(ls -t "$VID"/*.webm 2>/dev/null | head -1)
if [ -n "$WEBM" ]; then
  ffmpeg -y -i "$WEBM" -vf "fps=6,scale=440:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=96[p];[s1][p]paletteuse=dither=bayer:bayer_scale=3" "$WEBGIF" >/dev/null 2>&1 || true
fi

# Compose side by side (pad to equal height) if both exist; else use whichever.
if [ -f "$CLIGIF" ] && [ -f "$WEBGIF" ]; then
  ffmpeg -y -i "$CLIGIF" -i "$WEBGIF" \
    -filter_complex "[0:v]fps=6,scale=-1:360,pad=iw:360:0:(360-ih)/2:black[l];[1:v]fps=6,scale=-1:360,pad=iw:360:0:(360-ih)/2:black[r];[l][r]hstack=inputs=2,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=bayer:bayer_scale=3" \
    "$GIF" >/dev/null 2>&1 || cp "$CLIGIF" "$GIF"
elif [ -f "$CLIGIF" ]; then cp "$CLIGIF" "$GIF"
elif [ -f "$WEBGIF" ]; then cp "$WEBGIF" "$GIF"; fi

# Final lossy+optimize pass (in place) — typically halves the file again.
if command -v gifsicle >/dev/null 2>&1 && [ -f "$GIF" ]; then
  gifsicle -O3 --lossy=80 --colors 96 "$GIF" -o "$GIF.opt" >/dev/null 2>&1 && mv "$GIF.opt" "$GIF"
fi

echo "RESULT $ID $VERDICT $DETAIL" | tee "$RES"
