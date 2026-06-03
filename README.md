# Filament

Peer-to-peer file sharing in the browser. Files travel **directly between
browsers** over a WebRTC data channel — the server only helps two peers find
each other (signaling). No uploads, no size cap, no account.

This repo is a small, honest demo of **how Flask and React work together**: one
Flask app serves the built React bundle, exposes a tiny REST surface, and relays
WebRTC signaling over Socket.IO. Firebase is supported as an alternative
signaling channel, selectable at runtime.

```
              one origin
   browser ── REST /api/* ─────────► Flask ── serves React build (dist/)
      │       Socket.IO /socket.io ► signaling relay
      └────── WebRTC DataChannel ──► other browser   (the files go here)
```

## Layout

```
backend/        Flask app
  app.py          routes + SPA serving + Socket.IO mount
  signaling.py    the signaling relay (dumb pipe; never sees files)
  config.py       runtime config served at /api/config
  requirements.txt
frontend/       React app (Vite)
  src/lib/        the networking layer — the part that must "just work"
    signaling.js    Socket.IO ⟷ Firebase abstraction (one interface)
    webrtc.js       PeerLink: RTCPeerConnection + chunked file transfer
    useFilament.js the single hook the UI consumes
  src/App.jsx     placeholder UI (replace with Claude Design's output)
CONTRACT.md     the shape everything agrees on (REST + events + hook)
CLAUDE_DESIGN_PROMPT.md  prompt that makes Claude Design produce the UI
```

## Run it

**Dev (hot reload, two processes):**
```bash
# 1. backend
cd backend
pip install -r requirements.txt
python app.py                     # http://localhost:5000

# 2. frontend (new terminal) — proxies /api + /socket.io to Flask
cd frontend
npm install
npm run dev                       # http://localhost:5173
```

**Production-style (one process):**
```bash
cd frontend && npm install && npm run build   # emits backend/dist
cd ../backend && pip install -r requirements.txt && python app.py
# open http://localhost:5000
```

Open the same room link in two tabs / two devices to pair, then click a peer
tile (or drag files onto it) to send.

## Switching signaling backends

Everything is driven by `/api/config`, so no rebuild is needed:

```bash
export FIL_SIGNALING=socketio          # default
# or, to use Firebase Firestore signaling:
export FIL_SIGNALING=firebase
export FIL_FIREBASE_CONFIG='{"apiKey":"…","projectId":"…"}'   # web config
```

Other env knobs: `FIL_ICE_SERVERS` (JSON array, add TURN for hard NATs),
`FIL_SECRET` (salts the default room name), `FIL_CHUNK_SIZE`, `PORT`.

## Designing the UI with Claude Design

See `CLAUDE_DESIGN_PROMPT.md`. The prompt is written against `CONTRACT.md` so
the generated component drops onto `useFilament()` with no rewrites.

## A note on the "framework"

An earlier version of this project shipped a hand-rolled, Flutter-flavored
reactive UI engine (a `StateNotifier` + lifecycle-driven element system). That
experiment now lives on its own as **[statelet](https://github.com/Abdk4Moura/statelet)**.
This repo uses real React so the Flask⟷React question stays the focus.
