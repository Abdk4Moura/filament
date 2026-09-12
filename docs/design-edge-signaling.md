# Edge signaling — Cloudflare Workers + Durable Objects

> Status: proposed. Design only; the Flask + Socket.IO backend remains the shipped implementation.

**Status:** design. The one rearchitecture that fixes *speed*, *presence reliability*,
and *scale* at once, because all three have the same root cause: a **single-origin
socket.io backend**.

## The problem (one cause, three symptoms)

Today signaling is Flask + `python-socketio` on a single gunicorn origin (one region).

- **Slow (speed):** a client in Lagos connects to a US/EU origin. A cold socket.io
  connect is ~6 sequential round-trips (TCP → TLS → socket.io HTTP handshake → WS
  upgrade → register → subscribe/presence); at ~280 ms RTT that's ~1.6 s CLI /
  5 s+ web. The RTT is fixed by *distance to the single origin*.
- **Unreliable (presence):** with >1 gunicorn worker and no shared pub/sub, a
  `known-peer` emitted on worker A doesn't reach a socket on worker B, so presence
  arrives late (only via a sync fallback) or not at all. (The backend even
  documents this: "async known-peer push … unreliable across prod workers".)
- **Doesn't scale:** one origin, one process pool, in-process room/presence state.
  Vertical only; a hard ceiling well below millions of concurrent connections.

The data plane is already P2P (bytes never touch us), so signaling is the *only*
thing that must scale — and it's the thing that's centralized.

## The shape

```
  peer (Lagos)                 nearest CF edge PoP                  peer (dovm)
     │   WS upgrade  ───────────────►  Worker  ◄─────────────── WS  │
     │                                  │ route by channel/room id  │
     │                                  ▼                           │
     │                         Durable Object  (one per channel)    │
     │                         - the ≤2 (or room-N) peers' sockets  │
     │                         - presence (known-peer / left)       │
     │                         - relays offer/answer + candidates   │
     │                         - TTL / hibernation                  │
```

- **Worker** (runs at the PoP nearest each peer): terminates the WebSocket at the
  *edge* (this is the latency win — the RTT-heavy TCP+TLS+WS handshake now lands
  on a nearby PoP, not the far origin), authenticates nothing sensitive (identity
  is client-side crypto), and forwards the connection to the right Durable Object
  by name.
- **Durable Object** (the coordinator): exactly one per signaling **channel**.
  A DO is single-threaded and single-instance globally for its id, so it is *the*
  source of truth for its channel — presence and message routing are consistent
  by construction. It holds the live sockets for that channel, relays
  `signal`/`candidate`/`description` between them, and emits
  `known-peer`/`known-peer-left`/`peer-joined`/`peer-left`.

## Mapping filament's model onto DOs (clean, because it already shards)

filament already keys signaling on two kinds of id, both perfect DO names:

- **Persistent pair channel** (C12): the channel id is a **hash of the pair
  secret** — the server only ever sees "meeting points", never secrets. Map it
  directly: `env.CHANNEL.idFromName(channelHash)`. That DO coordinates the ≤2
  known devices sharing that secret: their presence + signal relay.
- **Code/word room** (first-contact pairing): `env.ROOM.idFromName(roomId)`. That
  DO is the ephemeral rendezvous for a pairing code; it dies (TTL) after the pair
  completes.

Millions of pairs/rooms → millions of *tiny* DOs, each holding ≤ a handful of
sockets. Horizontal by construction; no shared state, no central DB.

## Why this fixes all three

- **Speed:** WS handshake terminates at the nearest PoP (RTT to edge ≪ RTT to
  origin). Combined with the client-side wins already landed (WebSocket-first
  transport, preconnect) and the *cache-and-dial* optimization (known peers skip
  signaling entirely on reconnect), first-connect drops from seconds to a beat.
- **Presence reliability:** one DO per channel = one authoritative coordinator.
  There is no "other worker" to lose an event to — the cross-worker bug is
  *structurally* gone.
- **Scale:** DOs shard on id; idle connections use the **WebSocket Hibernation
  API** (a DO with thousands of mostly-idle presence sockets is evicted from
  memory and woken on message), so a daemon staying reachable costs ~nothing until
  a peer actually calls. This is what makes "millions of always-online daemons"
  affordable.

## What stays the same

- **The wire protocol.** Keep the existing events (`welcome`, `peer-joined`,
  `peer-left`, `signal`, `pair-*`, `known-peer`, `known-peer-left`) so clients
  barely change — implement the same semantics over Workers+DO (raw WS, not
  socket.io; the client's transport layer swaps `socket.io-client` for a thin WS
  client speaking the same messages).
- **Identity & rosters stay client-side.** Crypto-addressed identity → no account
  DB. `devices.json` rosters → no per-user server state. Presence is the *only*
  server state, and it lives in the per-channel DO (ephemeral).

## Relay (TURN) is separate — do NOT put it in Workers

Workers/DOs are for signaling (small control messages), not for relaying bulk UDP.
TURN stays its own regionally-distributed fleet (or **Cloudflare Calls / TURN**,
which is purpose-built and edge-distributed). Relay is the one metered/costly tier
(see the scaling notes): minimize its use (maximize direct success), keep it
regional, and it's the natural free-vs-paid line.

## Migration path (incremental, low-risk)

1. Stand up the Workers+DO signaling behind a *new* URL (e.g. `wss://sig.filament…`),
   speaking the same message protocol.
2. Add a client transport that talks raw WS to it (behind a `server`/flag), keeping
   the socket.io path as fallback. Dogfood on a few devices.
3. Flip the default `server` setting once parity + presence are verified; keep the
   socket.io origin as a fallback for a release.
4. Retire the gunicorn origin (or keep it only as a TURN/health endpoint).

## Open questions / risks

- **DO WebSocket Hibernation semantics** — confirm wake latency on inbound message
  is acceptable for a presence ping (should be ms).
- **Presence TTL / reconnect** — define how a DO expires a stale socket and
  re-announces on reconnect (mirror the current heartbeat/TTL reaper).
- **Room→DO global uniqueness** — `idFromName` gives a globally-unique DO per name;
  ensure the channel-hash / room-id derivation is collision-safe (it already is —
  a hash of the secret).
- **Cost model** — DO request + duration + WS message pricing vs the current
  droplet; hibernation should keep idle cost near zero, but model the active-
  connection cost at target scale.
- **Web transport** — pairs with the WebTransport-for-reachable-peers plan
  (docs/…): once the data path is QUIC/WebTransport, the whole stack (signaling
  edge + QUIC data) is CF-native and unified with the CLI.

## Bottom line

Move signaling from *one origin* to *the edge, sharded per channel*. It's the same
move that makes connect fast, makes presence correct, and makes the system scale to
millions — while the P2P data plane keeps carrying the bytes for free.
