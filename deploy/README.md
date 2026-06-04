# Deploying Filament

Split deploy: **static frontend on Cloudflare Pages**, **signaling API + TURN on
a DigitalOcean droplet**. Files never touch either — they go peer-to-peer over
WebRTC; the droplet only relays signaling, and coturn relays media for the
minority of networks that can't connect directly.

```
   browser ───────────── static SPA ──────────────► Cloudflare Pages
      │                  (filament.pages.dev)
      │   REST /api/* + Socket.IO  ──► Caddy(TLS) ──► api (gunicorn+eventlet)   ┐
      │                                                                          │ droplet
      └── WebRTC: STUN/TURN ─────────────────────────► coturn (3478)            ┘
                 (P2P direct, or relayed via coturn when NAT blocks direct)
```

## 0. Prerequisites
- A domain. You'll use two subdomains pointing at the **droplet's public IP**:
  - `api.<domain>` — the signaling API (Caddy gets a Let's Encrypt cert for it)
  - `turn.<domain>` — coturn
- DNS: create **A records** for both → droplet IP. If your DNS is on Cloudflare,
  set **`api.<domain>` to "DNS only" (grey cloud)** so Caddy's ACME challenge
  works. `turn.<domain>` must also resolve to the raw IP (grey cloud).
- Droplet firewall — open: `80,443/tcp` (Caddy), `3478/tcp+udp` and
  `49160-49200/udp` (coturn). Optionally `5349/tcp` for `turns:`.

## 1. Backend + TURN on the droplet
```bash
# install Docker + compose plugin, then:
git clone https://github.com/Abdk4Moura/filament.git
cd filament/deploy
cp .env.example .env
nano .env        # set domains, droplet IP, and two long random secrets
docker compose up -d --build
docker compose logs -f   # watch api + caddy + coturn come up
```
Fill `.env`:
- `API_DOMAIN=api.<domain>`, `TURN_REALM=turn.<domain>`, `DROPLET_IP=<public ip>`
- `FIL_CORS_ORIGINS=https://<your>.pages.dev` (add your custom domain too)
- `FIL_TURN_HOST=turn:turn.<domain>:3478,turn:turn.<domain>:3478?transport=tcp`
- `FIL_SECRET` and `FIL_TURN_SECRET` → two different long random strings
  (`openssl rand -hex 32`). `FIL_TURN_SECRET` is shared between the API and
  coturn automatically via compose — set it once.

Check it's live: `curl https://api.<domain>/api/health` → `{"ok":true}`, and
`curl https://api.<domain>/api/config` should list your `turn:` server with a
fresh `username`/`credential`.

## 2. Frontend on Cloudflare Pages
Create a Pages project from the GitHub repo with these **build settings**:
- **Root directory:** `/` (repo root)
- **Build command:** `cd frontend && npm install && npm run build`
- **Output directory:** `backend/dist`
- **Environment variable:** `VITE_FILAMENT_API = https://api.<domain>`

Deploy. `_redirects` (shipped in the build) gives SPA fallback so `/rooms/:id`
deep links work. Add a custom domain in Pages if you want (then add it to
`FIL_CORS_ORIGINS` and redeploy the API).

## 3. Verify end-to-end
1. Open the Pages URL in two tabs (or two devices). They auto-join the same room
   ("people near you") or use a code; tiles should appear.
2. Send a file between them.
3. Check the **route badge** on a peer tile: `LAN` (same WiFi, direct),
   `P2P` (direct over internet), or `RELAY` (went through coturn). Force a relay
   to test coturn by trying two networks (e.g. phone on cellular).
4. coturn sanity: the [Trickle ICE tester](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/)
   with your `turn:` URL + a username/credential from `/api/config` should yield
   a `relay` candidate.

## Updating
- **Frontend:** push to the repo → Pages rebuilds automatically.
- **Backend:** `git pull && docker compose up -d --build` on the droplet.

## Scaling (later)
The API runs a **single worker** because room membership lives in memory
(`signaling.py`). To run multiple workers/instances, add a Redis message queue
(`SocketIO(message_queue=...)`) and move the room registry into Redis. Not
needed for launch.

## Server note
The API runs under **gunicorn's eventlet worker** (`-k eventlet`, pinned
`gunicorn<24` since 24+ dropped the bundled eventlet worker). eventlet prints a
deprecation warning — harmless. If you ever want off eventlet, switch to
`gevent` + `gevent-websocket` and update `FIL_ASYNC_MODE` + the Dockerfile CMD.

## Security notes
- TURN credentials are **ephemeral** (time-limited HMAC), so the browser never
  holds a long-lived TURN password. Keep `FIL_TURN_SECRET` secret.
- `.env` is gitignored — never commit real secrets.
- Lock `FIL_CORS_ORIGINS` to your exact Pages/custom origins (not `*`) in prod.
