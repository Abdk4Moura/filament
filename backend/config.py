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

# Set to a redis:// URL to scale horizontally (shared room registry + Socket.IO
# message queue across api replicas). Unset = single in-memory instance.
REDIS_URL = os.environ.get("FIL_REDIS_URL")

# Allow the Vite dev server origin to open the websocket during development.
CORS_ALLOWED_ORIGINS = os.environ.get("FIL_CORS_ORIGINS", "*")

# ICE servers handed to the browser's RTCPeerConnection. STUN is enough for most
# networks; TURN (below) is the fallback for the ~10-15% that need a relay.
DEFAULT_ICE = [{"urls": "stun:stun.l.google.com:19302"}]

# Self-hosted coturn. We hand out *ephemeral* credentials (coturn's REST-API /
# use-auth-secret scheme): a time-limited username + an HMAC of it, so the
# browser never holds a long-lived TURN password.
#   FIL_TURN_HOST   comma-separated TURN urls, e.g.
#                   "turn:turn.filament.example.com:3478,turn:turn.filament.example.com:3478?transport=tcp"
#   FIL_TURN_SECRET must equal coturn's `static-auth-secret`
#   FIL_TURN_TTL    credential lifetime in seconds (default 1h)
TURN_HOST = os.environ.get("FIL_TURN_HOST")
TURN_SECRET = os.environ.get("FIL_TURN_SECRET")
TURN_TTL = int(os.environ.get("FIL_TURN_TTL", 3600))


def _turn_servers():
    if not (TURN_HOST and TURN_SECRET):
        return []
    import hashlib
    import hmac
    import time
    from base64 import b64encode

    username = str(int(time.time()) + TURN_TTL)  # username IS the expiry timestamp
    credential = b64encode(
        hmac.new(TURN_SECRET.encode(), username.encode(), hashlib.sha1).digest()
    ).decode()
    urls = [u.strip() for u in TURN_HOST.split(",") if u.strip()]
    return [{"urls": urls, "username": username, "credential": credential}]


def _ice_servers():
    raw = os.environ.get("FIL_ICE_SERVERS")
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    # Default STUN + (when configured) ephemeral self-hosted TURN.
    return DEFAULT_ICE + _turn_servers()


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
        # changed without a rebuild). 60 KiB, NOT 64: chunks carry a 4-byte
        # stream-id header and SCTP's default max message size is 65535 —
        # 64 KiB + 4 overflows it. Chrome tolerates the overage between
        # browsers, but strict stacks (webrtc-rs, i.e. the CLI) reject it.
        # See docs/cli-resilience.md C1.
        "chunkSize": int(os.environ.get("FIL_CHUNK_SIZE", 60 * 1024)),
    }
