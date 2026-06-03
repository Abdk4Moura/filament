#!/usr/bin/env python3
"""Quickshare backend: one Flask app that does three things and nothing else.

  1. Serves the built React app (frontend/dist) as a single-page app.
  2. Exposes a tiny REST surface under /api (config + default room name).
  3. Relays WebRTC signaling over Socket.IO (see signaling.py).

Files themselves never touch this server: they go peer-to-peer over a WebRTC
data channel. The server only helps two browsers find each other.
"""
import hashlib
import os

from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix

import config
import signaling

# The React build lands here (see frontend/vite.config.js -> build.outDir).
DIST_DIR = os.path.join(os.path.dirname(__file__), "dist")

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

socketio = SocketIO(app, async_mode="threading", cors_allowed_origins=config.CORS_ALLOWED_ORIGINS)
signaling.register(socketio)


# ---------------------------------------------------------------- REST API ---
@app.get("/api/config")
def api_config():
    """Everything the frontend needs to bootstrap (signaling kind, ICE, ...)."""
    return jsonify(config.public_config())


@app.get("/api/room")
def api_room():
    """A stable default room name derived from the caller's network address.

    Two people behind the same public IP get the same name, so they land in the
    same room automatically — the original Quickshare 'people near you' idea.
    """
    ip = request.headers.get("cf-connecting-ip", request.remote_addr or "0.0.0.0")
    name = hashlib.sha256(f"{config.SECRET}:{ip}".encode()).hexdigest()[:12]
    return jsonify({"room": name})


@app.get("/api/health")
def api_health():
    return jsonify({"ok": True})


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
    socketio.run(app, host="0.0.0.0", port=config.PORT, debug=True, allow_unsafe_werkzeug=True)
