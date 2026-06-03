#!/usr/bin/env python3
"""Quickshare backend: one Flask app that does three things and nothing else.

  1. Serves the built React app (frontend/dist) as a single-page app.
  2. Exposes a tiny REST surface under /api (config + default room name).
  3. Relays WebRTC signaling over Socket.IO (see signaling.py).

Files themselves never touch this server: they go peer-to-peer over a WebRTC
data channel. The server only helps two browsers find each other.
"""
import hashlib
import ipaddress
import os
import secrets

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
