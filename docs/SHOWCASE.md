# Filament Showcase (R2-backed, isolated from the app)

A public "dev-effort + reels" showcase served at
**https://filament.autumated.com/showcase/** — a dark/mono build-log page with
the session's reels (web-shell, native shell, tile-interaction v2, annotator,
mobile keys + ⌘K, live pairing) embedded as real evidence, plus the GPU
job-runner contact sheet.

## Why this is safe (the whole point)

The main app (`filament` Worker, the SPA) is bound to the **entire hostname**
`filament.autumated.com` via a Worker **Custom Domain**. This showcase is a
**separate** Worker (`filament-showcase`) attached to a more-specific **zone
route** `filament.autumated.com/showcase/*`. Cloudflare resolves the
more-specific path route ahead of the catch-all Custom Domain, so:

- `GET /` and everything else → main `filament` app (untouched).
- `GET /showcase/*` → this showcase Worker → R2.

Nothing about the main app's Worker, `wrangler.jsonc`, or `dist` is modified.
**Media and the page live in R2** (bucket `filament-showcase`) — zero egress
cost, no big mp4s in git or in the app build.

## Pieces

| Piece | Where |
| --- | --- |
| Showcase Worker | `showcase/` (`src/index.ts`, `wrangler.jsonc`) |
| R2 bucket | `filament-showcase` (account R2) |
| Route | `filament.autumated.com/showcase/*` (zone `autumated.com`) |
| Publish script | `scripts/publish-showcase.sh` |

The Worker maps `GET /showcase/<path>` → R2 object `<path>`, serves
`index.html` for `/showcase` and `/showcase/`, sets correct `Content-Type`
(mp4 → `video/mp4`, gif, html, css), long-immutable cache for media + short
revalidate for html, supports HTTP **Range** requests (video seeking) and
conditional GETs, and returns a plain **404** for misses.

## Publishing (no app/Worker redeploy needed)

Publishing is just uploading objects to R2:

```bash
# uses ~/secret_keys/cloudflare_api_token + cloudflare_account_id
scripts/publish-showcase.sh
```

It (1) gathers reels (`reel*.mp4`) + gifs (`NN.gif`) from
`experiments/ux/gallery/`, (2) generates the dark/mono build-log page
(`index.html` + `showcase.css`), (3) uploads page + media to the
`filament-showcase` bucket. **Idempotent** — safe to re-run; re-running just
re-uploads (html cache is short so updates show quickly).

Options:

- `DRY_RUN=1 scripts/publish-showcase.sh` — build + list, skip upload.
- `GALLERY=/path scripts/publish-showcase.sh` — different gallery dir.
- `BUCKET=name scripts/publish-showcase.sh` — different bucket.

## Pipeline hook

The test-record pipeline (under `experiments/ux/`) can call publishing as its
final step. The entry point is intentionally outside `experiments/ux/` so the
pipeline scripts stay owned by their agent:

```bash
# final step of the record pipeline, after reels land in the gallery:
GALLERY="$PWD/experiments/ux/gallery" scripts/publish-showcase.sh
```

(or, with no args, it defaults to `experiments/ux/gallery`). Add that one line
to the pipeline's publish/finish target — nothing else is required.

## Re-deploying the Worker (rarely needed)

Only needed if `showcase/src/index.ts` or its config changes — NOT for content
updates:

```bash
cd showcase && CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… npx wrangler deploy
```

## Verify

```bash
curl -sI https://filament.autumated.com/showcase/                 # 200 text/html
curl -sI https://filament.autumated.com/showcase/reel1-webshell.mp4   # 200 video/mp4
curl -sI https://filament.autumated.com/                          # 200 — app SPA, untouched
```
