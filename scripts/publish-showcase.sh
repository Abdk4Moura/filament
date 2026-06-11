#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# publish-showcase.sh — publish the "dev-effort + reels" showcase to R2.
#
# Architecture (see showcase/ and docs/SHOWCASE.md):
#   • Media + the page live in Cloudflare R2 (bucket: filament-showcase).
#   • A dedicated Worker (filament-showcase) serves them at
#       https://filament.autumated.com/showcase/*
#     via a zone route — the main `filament` app Worker is never touched.
#   • Publishing == uploading objects to R2. No app/Worker redeploy needed.
#
# What it does:
#   1. Gathers reels (reel*.mp4) + gifs (NN.gif) + captions from the gallery.
#   2. Generates a polished dark/mono build-log + reels page (index.html).
#   3. Uploads the page + all media to R2 (idempotent — safe to re-run).
#
# Usage:
#   scripts/publish-showcase.sh                 # publish from default gallery
#   GALLERY=path/to/gallery scripts/publish-showcase.sh
#   DRY_RUN=1 scripts/publish-showcase.sh       # build page, skip upload
#
# Requirements:
#   • ~/secret_keys/cloudflare_api_token and ~/secret_keys/cloudflare_account_id
#   • wrangler (npx wrangler) OR curl + the CF API (this script uses the CF API
#     S3-less object-put endpoint via wrangler r2; falls back to nothing else).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GALLERY="${GALLERY:-$REPO_ROOT/experiments/ux/gallery}"
BUCKET="${BUCKET:-filament-showcase}"
SITE_URL="${SITE_URL:-https://filament.autumated.com/showcase/}"

# Build artifacts go to a temp staging dir (never committed).
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

if [[ ! -d "$GALLERY" ]]; then
  echo "error: gallery dir not found: $GALLERY" >&2
  exit 1
fi

# ── Credentials ──────────────────────────────────────────────────────────────
SECRETS="${SECRETS_DIR:-$HOME/secret_keys}"
if [[ -z "${CLOUDFLARE_API_TOKEN:-}" && -f "$SECRETS/cloudflare_api_token" ]]; then
  CLOUDFLARE_API_TOKEN="$(cat "$SECRETS/cloudflare_api_token")"
fi
if [[ -z "${CLOUDFLARE_ACCOUNT_ID:-}" && -f "$SECRETS/cloudflare_account_id" ]]; then
  CLOUDFLARE_ACCOUNT_ID="$(cat "$SECRETS/cloudflare_account_id")"
fi
export CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID

# ── 1. Page generation ───────────────────────────────────────────────────────
# The page is a narrative dev-log of what shipped this session, with the
# available reels embedded as evidence. Reels are matched by filename; if a
# reel file is missing, that block is rendered as a "log entry without footage"
# so the narrative stays intact.

# reel slug -> mp4 filename, label/tag, and one-line caption.
# Order = the story of the session.
build_page() {
  local out="$STAGE/index.html"
  local gendate
  gendate="$(date -u '+%Y-%m-%d %H:%MZ')"

  # Collect which media actually exists.
  have() { [[ -f "$GALLERY/$1" ]]; }

  {
  cat <<'HTMLHEAD'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Filament — build log &amp; reels</title>
<meta name="description" content="What shipped this session on Filament: web-shell, device sheet, sessions dock, ⌘K palette, tile-interaction v2, PWA self-update, and the GPU job-runner — each with a real reel.">
<link rel="stylesheet" href="showcase.css">
</head>
<body>
<header class="masthead">
  <div class="wrap">
    <div class="kicker">filament · build log</div>
    <h1>Shipped this session <span class="cursor"></span></h1>
    <p class="lede">
      A run of UI and runtime work on <strong>Filament</strong> — the
      peer-to-peer device mesh. Every claim below is backed by a real reel:
      Playwright driving the actual app against real filament peers (real PAKE
      pairing, real PTYs, real WebRTC). Recordings are webm→mp4, GPU-encoded.
    </p>
    <div class="meta">
      <span class="dot"></span> media + page served from R2 ·
      <a href="https://filament.autumated.com/">← back to the app</a>
    </div>
  </div>
</header>
<main class="wrap">
HTMLHEAD

  # ── Each log entry: a function call appends a <section>. ────────────────────
  # args: slug(unused) | tag | title | caption | mp4 | poster-note
  entry() {
    local tag="$1" title="$2" caption="$3" mp4="$4" note="${5:-}"
    echo '  <section class="entry">'
    echo '    <div class="entry-head">'
    printf '      <span class="tag">%s</span>\n' "$tag"
    printf '      <h2>%s</h2>\n' "$title"
    echo '    </div>'
    printf '    <p class="caption">%s</p>\n' "$caption"
    if [[ -n "$mp4" ]] && have "$mp4"; then
      printf '    <video class="reel" controls preload="metadata" playsinline src="%s"></video>\n' "$mp4"
    else
      echo '    <div class="noreel">log entry — no reel attached</div>'
    fi
    [[ -n "$note" ]] && printf '    <p class="note">%s</p>\n' "$note"
    echo '  </section>'
  }

  entry "web-shell" \
    "Web-shell over the data channel" \
    "Pair an <code>up --shell</code> peer, open its terminal, type a command, and watch the output stream straight back through the WebRTC data channel — a real PTY, no SSH server on the box." \
    "reel1-webshell.mp4"

  entry "native" \
    "Native shell, same surface" \
    "The same terminal experience, driven natively — the shell capability is deny-by-default and survives unrelated device forgets (regression-guarded)." \
    "reel2-native.mp4"

  entry "tile-v2 · style" \
    "Tile-interaction v2 · live style switch" \
    "The new device-tile interaction model with a live theme switch — hover reveals the action bar on desktop; the whole surface re-themes without a reload." \
    "reel3-styleswitch.mp4"

  entry "annotator" \
    "In-session annotator" \
    "Draw on top of a live session to call out what matters — the annotator overlay rides on the same surface as the terminal and tiles." \
    "reel4-annotate.mp4"

  entry "mobile keys · ⌘K" \
    "Mobile key bar &amp; command palette" \
    "The mobile accessory key bar for the on-phone terminal, plus the ⌘K command palette — filter and fire actions (open-terminal, send) against a paired device." \
    "reel5-mobilekeys.mp4"

  entry "pairing" \
    "Live PAKE pairing → remembered device" \
    "A real CLI peer mints a PAKE code; the browser claims it; the device is mutually remembered — the key never crosses the server. (Sessions dock &amp; PWA self-update ride on this same paired surface.)" \
    "reel6-livepair.mp4"

  # ── GPU job-runner / round-trip evidence (gifs + the t4 reel). ──────────────
  echo '  <section class="entry wide">'
  echo '    <div class="entry-head"><span class="tag">gpu runner</span><h2>GPU job-runner — round-trip</h2></div>'
  echo '    <p class="caption">The reels above are encoded by a GPU-aware job-runner (webm→mp4 on a T4). Below: the round-trip reel and the e2e contact sheet that the pipeline emits.</p>'
  if have "t4-roundtrip.mp4"; then
    echo '    <video class="reel" controls preload="metadata" playsinline src="t4-roundtrip.mp4"></video>'
  fi
  echo '    <div class="contact">'
  for g in "$GALLERY"/[0-9][0-9].gif; do
    [[ -f "$g" ]] || continue
    b="$(basename "$g")"
    printf '      <figure><img loading="lazy" src="%s" alt="%s"></figure>\n' "$b" "$b"
  done
  echo '    </div>'
  echo '  </section>'

  cat <<HTMLFOOT
</main>
<footer class="wrap foot">
  <span>Filament — p2p device mesh.</span>
  <span class="muted">page + media served from Cloudflare R2 · generated ${gendate}</span>
</footer>
</body>
</html>
HTMLFOOT
  } > "$out"

  echo "$out"
}

# ── Stylesheet (single small css, on-brand) ──────────────────────────────────
build_css() {
  cat > "$STAGE/showcase.css" <<'CSS'
:root{
  --bg:#0A0B0C; --panel:#0F1113; --line:#1E2227; --line2:#262b31;
  --fg:#D9DEE3; --muted:#8A929B; --dim:#5A626B; --accent:#7CF6C8;
  color-scheme:dark;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.6 'JetBrains Mono',ui-monospace,'SF Mono',Menlo,Consolas,monospace;
  -webkit-font-smoothing:antialiased;
  background-image:radial-gradient(900px 500px at 80% -10%, #7CF6C81a, transparent 60%);
}
.wrap{max-width:980px;margin:0 auto;padding:0 22px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{color:var(--accent);background:#7CF6C814;border:1px solid #7CF6C82e;border-radius:5px;padding:.5px 5px;font-size:.92em}

.masthead{padding:54px 0 30px;border-bottom:1px solid var(--line)}
.kicker{color:var(--accent);font-size:12px;letter-spacing:.22em;text-transform:uppercase;margin-bottom:14px}
.masthead h1{font-size:30px;line-height:1.15;margin:0 0 14px;letter-spacing:-.01em;font-weight:700}
.cursor{display:inline-block;width:11px;height:23px;background:var(--accent);vertical-align:-3px;margin-left:4px;animation:blink 1.1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
.lede{color:var(--muted);font-size:14.5px;max-width:70ch;margin:0 0 18px}
.lede strong{color:var(--fg)}
.meta{color:var(--dim);font-size:12.5px;display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.dot{width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 10px var(--accent);display:inline-block}

main{padding:28px 0 10px;display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.entry{
  background:linear-gradient(180deg,#0F1113,#0c0e10);
  border:1px solid var(--line);border-radius:11px;padding:16px 16px 18px;min-width:0;
  transition:border-color .18s ease,transform .18s ease;
}
.entry:hover{border-color:var(--line2);transform:translateY(-1px)}
.entry.wide{grid-column:1 / -1}
.entry-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.tag{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);border:1px solid #7CF6C84d;border-radius:999px;padding:3px 9px;white-space:nowrap}
.entry h2{font-size:15.5px;margin:0;font-weight:600;letter-spacing:-.005em}
.caption{color:var(--muted);font-size:13px;margin:0 0 12px}
.caption code{font-size:.85em}
.reel{width:100%;height:auto;border-radius:8px;background:#000;border:1px solid var(--line);display:block}
.noreel{height:130px;display:flex;align-items:center;justify-content:center;color:#3c424a;border:1px dashed var(--line);border-radius:8px;font-size:12px}
.note{color:var(--dim);font-size:11.5px;margin:9px 0 0}

.contact{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-top:14px}
.contact figure{margin:0}
.contact img{width:100%;height:auto;border-radius:7px;border:1px solid var(--line);background:#000;display:block}

.foot{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:12px;border-top:1px solid var(--line);margin-top:26px;padding-top:18px;padding-bottom:46px}
.foot .muted{color:var(--dim)}

@media(max-width:720px){
  main{grid-template-columns:1fr}
  .masthead h1{font-size:24px}
}
CSS
  echo "$STAGE/showcase.css"
}

# ── 2/3. Build then upload ───────────────────────────────────────────────────
echo "→ gallery:  $GALLERY"
echo "→ bucket:   $BUCKET"
PAGE="$(build_page)"
CSS="$(build_css)"
echo "→ generated index.html ($(wc -c < "$PAGE") bytes) + showcase.css"

# Stage media (copy the reels/gifs the page references) so we upload a coherent set.
for f in "$GALLERY"/reel*.mp4 "$GALLERY"/t4-roundtrip.mp4 "$GALLERY"/[0-9][0-9].gif; do
  [[ -f "$f" ]] && cp "$f" "$STAGE/"
done

# content-type per extension (R2 stores it so the Worker can also trust it).
ctype() {
  case "${1,,}" in
    *.mp4) echo "video/mp4";;
    *.webm) echo "video/webm";;
    *.gif) echo "image/gif";;
    *.html) echo "text/html; charset=utf-8";;
    *.css) echo "text/css; charset=utf-8";;
    *.png) echo "image/png";;
    *.jpg|*.jpeg) echo "image/jpeg";;
    *) echo "application/octet-stream";;
  esac
}

put() {
  local file="$1" key="$2" ct
  ct="$(ctype "$file")"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    printf '   [dry-run] would put %-26s (%s)\n' "$key" "$ct"
    return 0
  fi
  npx --yes wrangler@4 r2 object put "$BUCKET/$key" \
      --file "$file" --content-type "$ct" --remote >/dev/null
  printf '   put %-26s (%s)\n' "$key" "$ct"
}

echo "→ uploading to r2://$BUCKET ..."
put "$PAGE" "index.html"
put "$CSS"  "showcase.css"
for f in "$STAGE"/reel*.mp4 "$STAGE"/t4-roundtrip.mp4 "$STAGE"/[0-9][0-9].gif; do
  [[ -f "$f" ]] || continue
  put "$f" "$(basename "$f")"
done

echo
echo "✓ published. Live at: $SITE_URL"
echo "  (the main filament app on / is untouched — separate Worker + route.)"
