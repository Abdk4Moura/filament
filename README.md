# Filament

**Live: [filament.autumated.com](https://filament.autumated.com)**. Send files directly between any two devices: no upload, no size cap, no account.

Files travel **peer to peer** over a WebRTC data channel. The server only helps the two ends find each other (signaling) and never sees a byte of your files.

## Works anywhere

The receiving end never needs anything installed. That is the core design decision, and it is what nothing else in this space offers:

| From | To | How |
|---|---|---|
| Android phone | iPhone | both open the website |
| Linux server (headless) | your phone | `filament send` on the box, browser on the phone |
| Windows laptop | Mac terminal | `winget install Abdk4Moura.Filament` and `brew install abdk4moura/tap/filament` |
| any browser | any browser | same WiFi auto-discovers; across networks, speak a one-time code |
| terminal | terminal | the classic croc-style flow, plus resume that survives restarts |

```
# Linux / macOS
curl -fsSL https://filament.autumated.com/install | sh

# Windows
winget install Abdk4Moura.Filament

# or just open https://filament.autumated.com on both devices

filament pair --name phone     # remember a device — no file needed
filament up                    # interactive session: pair / devices / forget in-session
```

## Why Filament over the alternatives

- **vs croc / magic-wormhole**: superb tools, but both ends must install them. Filament's other end can be your wife's phone with literally nothing installed: she opens a URL and taps accept. The CLI also resumes transfers across process restarts (croc parity) and a browser can be either side.
- **vs Snapdrop / PairDrop**: same-network discovery is just the starting point here. Filament adds speakable one-time codes that burn on first use (an overheard code is worthless), resumable transfers with content-hash verification, and a native CLI for servers and scripts.
- **vs WeTransfer / Drive / email**: nothing is uploaded, ever. There is no size limit, no account, no link that sits on someone's server. Bytes go device to device, DTLS-encrypted.
- **Route transparency, unique as far as we know**: every connection shows whether bytes went `local` (never left your network), `direct` (peer to peer across the internet), or `relayed` (through the TURN server). You can see what your data did.
- **Self-hostable end to end**: Flask signaling + Redis + coturn in one `docker compose up`. Point the apps at your instance with one env var.

## How it works

```
              one origin
   browser ── REST /api/* ─────────► Flask ── serves React build (dist/)
      │       Socket.IO /socket.io ► signaling relay
      └────── WebRTC DataChannel ──► other browser / CLI   (the files go here)
```

Reliability is documented failure-by-failure: [docs/resilience.md](docs/resilience.md) (the browser's 11 fixes) and [docs/cli-resilience.md](docs/cli-resilience.md) (the CLI's ledger, every entry gated by a test in `cli/tests/gates.sh`).

## Layout

```
backend/        Flask app
  app.py          routes + SPA serving + Socket.IO mount
  signaling.py    the signaling relay (dumb pipe; never sees files)
  config.py       runtime config served at /api/config
frontend/       React app (Vite); src/lib/ is the networking layer
cli/            Rust CLI (same wire protocol; browsers are first-class peers)
deploy/         docker compose: api + redis + coturn + cloudflared
CONTRACT.md     the shape everything agrees on (REST + events + hook)
```

## Run it

**Dev (hot reload, two processes):**
```bash
cd backend && pip install -r requirements.txt && python app.py    # :5000
cd frontend && npm install && npm run dev                         # :5173
```

**Production-style (one process):**
```bash
cd frontend && npm install && npm run build
cd ../backend && pip install -r requirements.txt && python app.py
```

Open the same room link in two tabs or two devices to pair, then click a peer tile (or drag files onto it) to send.

## Configuration

Everything is driven by `/api/config`, so no rebuild is needed: `FIL_SIGNALING` (socketio default, firebase optional), `FIL_ICE_SERVERS` / `FIL_TURN_HOST` + `FIL_TURN_SECRET` (TURN for hard NATs), `FIL_SECRET`, `FIL_CHUNK_SIZE`, `FIL_REDIS_URL` (horizontal scaling), `PORT`.

## A note on the "framework"

An earlier version of this project shipped a hand-rolled, Flutter-flavored reactive UI engine (a `StateNotifier` + lifecycle-driven element system). That experiment now lives on its own as **[statelet](https://github.com/Abdk4Moura/statelet)**. This repo uses real React.
