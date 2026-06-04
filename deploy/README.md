# Deploying Filament

Split deploy, tuned for a **shared droplet that also runs other important
services**: nothing binds the host's public web ports, the image is built in CI
(no build load on the droplet), every container is resource-capped, and the api
scales up/down in seconds.

- **Frontend** — static on Cloudflare Pages (`filament.autumated.com`).
- **API** — Flask signaling, reached via a **Cloudflare Tunnel** (no open ports).
- **Redis** — shared room registry + Socket.IO message queue (lets the api scale).
- **coturn** — self-hosted STUN/TURN (`turn.filament.autumated.com:3478`).

```
   browser ───── static SPA ─────► Cloudflare Pages (filament.autumated.com)
      │
      │  REST + Socket.IO          ┌─────────── droplet (165.22.207.231) ───────────┐
      │  api.filament.autumated.com│  cloudflared ──► api ×N ──► redis               │
      └───────► Cloudflare edge ───┼──(tunnel, no open ports)                        │
      │                            │                                                 │
      └──── WebRTC STUN/TURN ──────┼─► coturn :3478  (turn.filament.autumated.com)   │
                                   └─────────────────────────────────────────────────┘
       image built in CI → GHCR → droplet pulls (no build on the droplet)
```

## 0. DNS (Cloudflare)
- `api.filament.autumated.com` → **created automatically** by the tunnel. Don't make it.
- `turn.filament.autumated.com` → **A record → `165.22.207.231`, DNS-only (grey
  cloud)**. The only manual record (UDP can't go through the tunnel).
- `filament.autumated.com` → added as a custom domain in the Pages project.
- Firewall: open **`3478/tcp+udp`** and **`49160-49200/udp`** (coturn) on the
  droplet / DO cloud firewall. Nothing else.

## 1. Cloudflare Tunnel (one-time)
Zero Trust → Networks → Tunnels → **Create a tunnel** (named, e.g. `filament`):
1. Add a **Public Hostname**: `api.filament.autumated.com` → type `HTTP` →
   URL `api:8000`. (That hostname is the api service on the droplet's compose
   network — cloudflared runs there.)
2. Copy the tunnel **token** → it goes in `.env` as `CF_TUNNEL_TOKEN`.

## 2. Bring the stack up on the droplet (one-time)
```bash
sudo git clone https://github.com/Abdk4Moura/filament.git /opt/filament
cd /opt/filament/deploy
cp .env.example .env
# edit .env: paste CF_TUNNEL_TOKEN, set FIL_SECRET + FIL_TURN_SECRET
# (openssl rand -hex 32 each). Domains + DROPLET_IP are already filled.
docker compose up -d
docker compose ps
```
This starts cloudflared + redis + coturn + 1 api. (api pulls from GHCR — make the
package public first, step 4, or `docker login ghcr.io` once.) Check:
- `curl https://api.filament.autumated.com/api/health` → `{"ok":true}`
- `/api/config` lists your `turn:` server with a fresh `username`/`credential`.

## 3. Frontend on Cloudflare Pages
New Pages project from the repo:
- Build command: `cd frontend && npm install && npm run build`
- Output directory: `backend/dist`
- Env var: `VITE_FILAMENT_API = https://api.filament.autumated.com`
- After first deploy, add custom domain `filament.autumated.com`.
Pages rebuilds on every push; `_redirects` handles SPA deep links.

## 4. Auto-deploy the backend (GitHub Actions)
`.github/workflows/deploy-backend.yml` **builds the image in CI**, pushes it to
GHCR, then SSHes in to `docker compose pull api && up -d --no-deps api` — only
the tiny api container restarts; cloudflared/redis/coturn are untouched.

- Make the GHCR package **public** once: GitHub → your profile → Packages →
  `filament-api` → Package settings → Change visibility → Public. (Otherwise add
  `docker login ghcr.io` on the droplet with a PAT.)
- Repo secrets (Settings → Secrets and variables → Actions):

  | Secret | Value |
  |---|---|
  | `DROPLET_HOST` | `165.22.207.231` |
  | `DROPLET_USER` | SSH user (e.g. `root`) |
  | `DROPLET_SSH_KEY` | a private deploy key (public half in droplet `authorized_keys`) |
  | `DEPLOY_PATH` | `/opt/filament` |
  | `DROPLET_PORT` | (optional) default `22` |

## 5. Scaling — fast, up or down
The api is **stateless behind Redis**, so add/remove replicas in seconds:
```bash
cd /opt/filament/deploy
./scale.sh 4      # 4 api replicas
./scale.sh 1      # back to one
```
cloudflared round-robins across replicas; any replica can serve any peer (Redis
shares room state + delivery). To resize a single container instead, bump
`API_CPUS`/`API_MEM` in `.env` and `docker compose up -d --no-deps api`.

**Reality check on what to scale:** signaling is *cheap* — it only relays small
SDP/ICE messages; the files themselves go peer-to-peer and never touch the
droplet. One eventlet worker handles thousands of concurrent connections, so the
api rarely needs replicas. The component that grows with usage is **coturn**
(it relays real media bytes for hard-NAT peers) — scale that with bandwidth /
more relay ports / additional coturn nodes.

For metric-driven *auto*scaling (CPU/conns trigger replica count), point a
controller at `./scale.sh`, or move to an orchestrator (Swarm/Nomad/k8s HPA) —
the Redis groundwork here makes the api ready for it.

## 6. Verify end-to-end
1. Open `https://filament.autumated.com` in two devices — tiles appear.
2. Send a file.
3. Route badge: `LAN` / `P2P` / `RELAY`. Force a relay across two networks to
   exercise coturn.
4. coturn: the [Trickle ICE tester](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/)
   with your `turn:` URL + a username/credential from `/api/config` should yield
   a `relay` candidate.

## Resource caps & notes
- Every container is capped via `.env` (`API_MEM`, `COTURN_CPUS`, …). Defaults
  total well under what's free; raise them as load grows.
- The API runs gunicorn's **eventlet** worker (`gunicorn<24`, which still bundles
  it). eventlet logs a deprecation warning — harmless.
- TURN credentials are **ephemeral** (time-limited HMAC); the browser never holds
  a standing TURN password. Keep `FIL_TURN_SECRET` secret. `.env` is gitignored.
