#!/usr/bin/env python3
"""Filament backend: one Flask app that does three things and nothing else.

  1. Serves the built React app (frontend/dist) as a single-page app.
  2. Exposes a tiny REST surface under /api (config + default room name).
  3. Relays WebRTC signaling over Socket.IO (see signaling.py).

Files themselves never touch this server: they go peer-to-peer over a WebRTC
data channel. The server only helps two browsers find each other.
"""
import os

# Eventlet's cooperative concurrency must be installed BEFORE anything imports
# threading/socket, so this runs first — but ONLY for a direct `python app.py`
# run that opts in via FIL_SELF_MONKEYPATCH=1 (the gate fixture). Prod runs
# under `gunicorn -k eventlet`, which already monkey-patches in the worker, and
# sets FIL_ASYNC_MODE=eventlet but NOT this flag — so prod's import path is
# untouched. Rationale: the threading + Werkzeug dev server services socket.io
# heartbeats poorly under load (a browser whose pings lag disconnects →
# reconnects → stale-answer glare, the gate-6/12 flake); eventlet matches prod
# and handles the concurrency reliably.
if os.environ.get("FIL_SELF_MONKEYPATCH") == "1":
    import eventlet  # noqa: E402
    eventlet.monkey_patch()

import json  # noqa: E402
import hashlib  # noqa: E402
import ipaddress  # noqa: E402
import secrets  # noqa: E402

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix

import config
import signaling

# The React build lands here (see frontend/vite.config.js -> build.outDir).
# In the split deploy (Cloudflare Pages serves the SPA) this may be absent — the
# API still works; only the SPA-fallback routes return 503.
DIST_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")

# CORS origins: "*" or a comma-separated allowlist (the Pages origin in prod).
_origins = "*" if config.CORS_ALLOWED_ORIGINS == "*" else [
    o.strip() for o in config.CORS_ALLOWED_ORIGINS.split(",") if o.strip()
]

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
# The SPA on Pages fetches /api/* cross-origin, so allow it there.
CORS(app, resources={r"/api/*": {"origins": _origins}})

# Dev defaults to the dependency-light threading server; prod sets
# FIL_ASYNC_MODE=eventlet and runs under gunicorn's eventlet worker.
ASYNC_MODE = os.environ.get("FIL_ASYNC_MODE", "threading")
# FIL_REDIS_URL turns on horizontal scaling: a shared message queue (so emits
# reach peers on any replica) + a shared room registry. Unset = single instance.
# ping_timeout/interval govern how long a transiently-unresponsive client is
# tolerated before engine.io declares it gone. Defaults (20s/25s) are fine in
# prod, but a CPU-STARVED headless browser in CI can't service pings in time,
# gets disconnected, reconnects with a fresh sid, and triggers a stale-answer
# negotiation glare — the gate-6/12 flake. FIL_PING_TIMEOUT (set generously by
# the test fixture) keeps a briefly-starved tab connected, removing the trigger
# deterministically. Real users aren't CPU-starved, so prod keeps the defaults.
socketio = SocketIO(
    app,
    async_mode=ASYNC_MODE,
    cors_allowed_origins=_origins,
    message_queue=config.REDIS_URL or None,
    ping_timeout=int(os.environ.get("FIL_PING_TIMEOUT", "20")),
    ping_interval=int(os.environ.get("FIL_PING_INTERVAL", "25")),
)
signaling.register(socketio, signaling.make_registry(config.REDIS_URL))


# ---------------------------------------------------------------- REST API ---
@app.get("/api/config")
def api_config():
    """Everything the frontend needs to bootstrap (signaling kind, ICE, ...)."""
    return jsonify(config.public_config())


# Human-friendly code alphabet: no 0/O/1/I/L to avoid mistyping.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _client_ip():
    return request.headers.get("cf-connecting-ip", request.remote_addr or "0.0.0.0")


def _network_key(ip_str):
    """Group peers onto the same LAN.

    IPv4 devices behind a home/office router share one public IPv4, so the full
    address groups them. IPv6 devices each get a unique address but share a /64
    prefix on the same link, so we group on that prefix instead — otherwise
    every IPv6 device would land in its own room and never see each other.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return ("raw", ip_str)
    if ip.version == 6:
        return ("ipv6", str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address))
    return ("ipv4", str(ip))


@app.get("/api/room")
def api_room():
    """A stable default room derived from the caller's network — 'people near you'.

    Devices on the same WiFi resolve to the same room automatically (no link to
    share). WebRTC/ICE then connects them host-to-host straight over the LAN.
    """
    network, key = _network_key(_client_ip())
    room = hashlib.sha256(f"{config.SECRET}:{key}".encode()).hexdigest()[:12]
    return jsonify({"room": room, "network": network, "scope": "auto"})


@app.get("/api/room/code")
def api_room_code():
    """Mint a short human code for pairing ACROSS networks (over the internet).

    For when the IP-grouping can't help — different WiFi, mobile data, CGNAT.
    The code maps to a deterministic room id both sides join.
    """
    code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(6))
    return jsonify({"code": code, "room": f"code-{code}", "scope": "code"})


@app.get("/api/health")
def api_health():
    return jsonify({"ok": True})


# ----------------------------------------------------------- Telemetry -------
@app.post("/api/telemetry")
def telemetry():
    """C24: browser clients beacon lifecycle events here (sendBeacon survives
    page-hide). One TEL line per event into the container logs. Size-capped;
    no file names or contents are ever sent."""
    from signaling import _tel

    raw = request.get_data(cache=False, as_text=True)[:8192]
    try:
        events = json.loads(raw)
        if not isinstance(events, list):
            events = [events]
        for e in events[:50]:
            if isinstance(e, dict) and isinstance(e.get("ev"), str):
                _tel("web:" + e.pop("ev")[:40], **{k: v for k, v in list(e.items())[:12]})
    except (ValueError, TypeError):
        pass
    return {"ok": True}


# --------------------------------------------------------- Static / SPA -------
@app.get("/")
@app.get("/rooms/<path:_room_id>")
def index(_room_id=None):
    return _send_index()


@app.get("/<path:path>")
def static_proxy(path):
    """Serve real build assets; fall back to index.html for client-side routes."""
    full = os.path.join(DIST_DIR, path)
    if os.path.isfile(full):
        return send_from_directory(DIST_DIR, path)
    return _send_index()


def _send_index():
    index_path = os.path.join(DIST_DIR, "index.html")
    if not os.path.isfile(index_path):
        return (
            "Frontend not built yet. Run `npm install && npm run build` in "
            "../frontend (or `npm run dev` for the live dev server).",
            503,
        )
    return send_from_directory(DIST_DIR, "index.html")


if __name__ == "__main__":
    # debug=True enables the Werkzeug auto-reloader, which forks + watches
    # files and can RESTART the server mid-run — dropping every socket, which
    # makes clients reconnect and triggers the stale-answer negotiation glare
    # (the gate-6/12 browser flake). Default OFF; set FIL_DEBUG=1 for local
    # dev. (Prod runs via gunicorn, unaffected by this block.)
    _debug = os.environ.get("FIL_DEBUG", "0") == "1"
    socketio.run(app, host="0.0.0.0", port=config.PORT, debug=_debug,
                 use_reloader=False, allow_unsafe_werkzeug=True)
