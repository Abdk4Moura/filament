"""Runtime configuration for the Filament backend.

Everything the frontend needs in order to bootstrap is exposed through
``public_config()`` and served at ``GET /api/config`` so the React app never
has to be rebuilt to switch signaling backends or ICE servers.
"""
import json
import os


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")


# Which signaling channel the client should use: "socketio" (default, served by
# this Flask app) or "firebase" (serverless, talks straight to Firestore).
SIGNALING = os.environ.get("FIL_SIGNALING", "socketio").lower()

# Secret used to derive a stable, non-reversible default room name per network.
SECRET = os.environ.get("FIL_SECRET", "filament-dev-secret")

PORT = int(os.environ.get("PORT", 5000))

# Allow the Vite dev server origin to open the websocket during development.
CORS_ALLOWED_ORIGINS = os.environ.get("FIL_CORS_ORIGINS", "*")

# ICE servers handed to the browser's RTCPeerConnection. STUN is enough for most
# networks; add a TURN entry here (JSON) for restrictive NATs.
DEFAULT_ICE = [{"urls": "stun:stun.l.google.com:19302"}]


def _ice_servers():
    raw = os.environ.get("FIL_ICE_SERVERS")
    if not raw:
        return DEFAULT_ICE
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return DEFAULT_ICE


def _firebase_web_config():
    """The Firebase *web* config (safe to expose) used only when SIGNALING=firebase."""
    raw = os.environ.get("FIL_FIREBASE_CONFIG")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def public_config() -> dict:
    """The exact JSON shape the frontend consumes at startup."""
    firebase = _firebase_web_config()
    # Fall back to socket.io if firebase was requested but not configured.
    signaling = SIGNALING if (SIGNALING != "firebase" or firebase) else "socketio"
    return {
        "signaling": signaling,
        "iceServers": _ice_servers(),
        "firebase": firebase if signaling == "firebase" else None,
        # Tuning knobs the transfer layer reads (kept server-side so they can be
        # changed without a rebuild).
        "chunkSize": int(os.environ.get("FIL_CHUNK_SIZE", 64 * 1024)),
    }
