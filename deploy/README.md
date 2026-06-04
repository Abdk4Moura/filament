# Deploying Filament

Split deploy: **static frontend on Cloudflare Pages** (`filament.autumated.com`)
and **signaling API + TURN on a DigitalOcean droplet** (`api.filament.autumated.com`).
Files never touch either — they go peer-to-peer over WebRTC; the droplet only
relays signaling, and coturn relays media for the minority of networks that
can't connect directly.

```
   browser ───────────── static SPA ──────────────► Cloudflare Pages
      │                  filament.autumated.com
      │   REST /api/* + Socket.IO  ─► Caddy(TLS :443) ─► api    api.filament.autumated.com  ┐
      │                                                                                      │ droplet
      └── WebRTC: STUN/TURN ───────► coturn (:3478)             turn.filament.autumated.com ┘
```

## 0. DNS + firewall
A single **wildcard** points all the backend subdomains at the droplet:

- **A record** `*.filament.autumated.com` → droplet public IP, **DNS only
  (grey cloud)** in Cloudflare. This covers both `api.` (Caddy needs grey cloud
  for its ACME challenge) and `turn.` (coturn needs the raw IP on :3478).
- `filament.autumated.com` itself is the Pages custom domain (step 2) — a
  separate record, and it can stay proxied/orange (the wildcard doesn't cover
  the bare `filament.autumated.com`).
- Droplet firewall — open: `80,443/tcp` (Caddy), `3478/tcp+udp` and
  `49160-49200/udp` (coturn).

## 1. Backend + TURN on the droplet (one-time)
```bash
# install Docker + the compose plugin, then:
sudo git clone https://github.com/Abdk4Moura/filament.git /opt/filament
cd /opt/filament/deploy
cp .env.example .env
nano .env        # set FIL_SECRET, FIL_TURN_SECRET (two `openssl rand -hex 32`),
                 # and DROPLET_IP. Domains are already filled in.
docker compose up -d --build
docker compose logs -f
```
Check it's live:
- `curl https://api.filament.autumated.com/api/health` → `{"ok":true}`
- `curl https://api.filament.autumated.com/api/config` lists your `turn:` server
  with a fresh `username`/`credential`.

`/opt/filament` and `/opt/filament/deploy/.env` are what the auto-deploy
(step 3) reuses, so keep them.

## 2. Frontend on Cloudflare Pages
Create a Pages project from the GitHub repo:
- **Build command:** `cd frontend && npm install && npm run build`
- **Output directory:** `backend/dist`
- **Environment variable:** `VITE_FILAMENT_API = https://api.filament.autumated.com`
- After the first deploy, add **custom domain** `filament.autumated.com`.

`_redirects` (shipped in the build) gives SPA fallback so `/rooms/:id` deep
links work. Pages rebuilds automatically on every push to `main`.

## 3. Auto-deploy the backend (GitHub Actions)
`.github/workflows/deploy-backend.yml` SSHes into the droplet on every push that
touches `backend/**` or `deploy/**` and runs `git reset --hard origin/main` +
`docker compose up -d --build`. Set these **repo secrets**
(Settings → Secrets and variables → Actions):

| Secret | Value |
|---|---|
| `DROPLET_HOST` | droplet public IP (or `api.filament.autumated.com`) |
| `DROPLET_USER` | SSH user, e.g. `root` or a `deploy` user |
| `DROPLET_SSH_KEY` | a **private** SSH key whose public half is in the droplet's `~/.ssh/authorized_keys` |
| `DEPLOY_PATH` | `/opt/filament` |
| `DROPLET_PORT` | (optional) SSH port, default `22` |

Generate a deploy key:
```bash
ssh-keygen -t ed25519 -f filament_deploy -N ""
# put filament_deploy.pub in the droplet's authorized_keys; paste filament_deploy
# (the private key) into the DROPLET_SSH_KEY secret.
```
After step 1 created `/opt/filament` + `.env`, pushes auto-deploy. You can also
run it manually from the Actions tab (workflow_dispatch).

## 4. Verify end-to-end
1. Open `https://filament.autumated.com` in two tabs/devices — they auto-join
   the same room or pair via a code; tiles appear.
2. Send a file.
3. Check the **route badge**: `LAN` (same WiFi), `P2P` (direct over internet),
   `RELAY` (via coturn). Test the relay by using two different networks.
4. coturn sanity: the [Trickle ICE tester](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/)
   with your `turn:` URL + a username/credential from `/api/config` should yield
   a `relay` candidate.

## Server note
The API runs under **gunicorn's eventlet worker** (`-k eventlet`, pinned
`gunicorn<24` since 24+ dropped the bundled eventlet worker). eventlet prints a
deprecation warning — harmless. To move off eventlet later, switch to `gevent` +
`gevent-websocket` and update `FIL_ASYNC_MODE` + the Dockerfile CMD.

## Scaling (later)
The API runs a **single worker** because room membership lives in memory
(`signaling.py`). To run multiple workers/instances, add a Redis message queue
(`SocketIO(message_queue=...)`) and move the room registry into Redis. Not
needed for launch.

## Security notes
- TURN credentials are **ephemeral** (time-limited HMAC), so the browser never
  holds a long-lived TURN password. Keep `FIL_TURN_SECRET` secret.
- `.env` is gitignored — never commit real secrets.
- `FIL_CORS_ORIGINS` is locked to `https://filament.autumated.com` (not `*`).
