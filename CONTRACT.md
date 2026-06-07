# Filament contract

The one document that pins how the pieces talk. The backend, the frontend
networking layer, the CLI, and any UI all depend on this and nothing else.

```
              one origin (Flask, :5000 prod / Vite :5173 dev)
   browser ──────────── REST /api/* ─────────────► Flask
      │                 Socket.IO /socket.io ─────► signaling relay
      │
      └────────── WebRTC DataChannel (P2P) ───────► other browser
                  (files travel here; server never sees bytes)
```

## REST (Flask → browser)

| Method | Path                | Returns |
|--------|---------------------|---------|
| GET    | `/api/config`       | `{ signaling: "socketio"\|"firebase", iceServers: RTCIceServer[], firebase: object\|null, chunkSize: number }` |
| GET    | `/api/room`         | `{ room: string }` — stable default room derived from caller IP |
| GET    | `/api/health`       | `{ ok: true }` |
| GET    | `/` and `/rooms/:id`| the SPA (`index.html`) |

## Signaling events (browser ↔ Flask, Socket.IO)

A dumb relay. It tracks room membership and forwards opaque WebRTC payloads.
Firebase mode mirrors these exact events client-side via Firestore.

**client → server**
- `join`   `{ room, name }`
- `signal` `{ to, data }`  — relay `data` to peer whose id == `to`
- `leave`  `{}`
- `subscribe` `{ channels: [sha256hex] }` — C12: raise known-device presence
  channels. A channel id is `sha256("filament-pair:" + secret)` — the server
  never sees a secret, only meeting points. Re-send on every reconnect (a
  fresh sid loses its subscriptions). Implemented by the CLI AND the browser
  (`lib/devices.js`): acknowledgement is mutual by construction — presence
  only lights up when both holders raise the same channel.

**server → client**
- `welcome`     `{ id, peers: [{ id, name }] }` — your id + who's already here
- `peer-joined` `{ id, name }`
- `peer-left`   `{ id }`
- `signal`      `{ from, data }`
- `known-peer`  `{ id, name, uid, channel }` — C12: a fellow subscriber of
  `channel` is online (sent to BOTH sides, regardless of rooms). Signals to
  that sid relay normally — links form room-lessly.
- `known-peer-left` `{ id, channel }`

Convention: the **newer** peer always initiates the WebRTC offer.

### Rooms / discovery (REST)
- `GET /api/room` → `{ room, network: "ipv4"|"ipv6"|"raw", scope: "auto" }` —
  the **auto** room: everyone on the same network lands here automatically
  ("people near you"). IPv6 is grouped by /64 prefix, IPv4 by public address.
- `GET /api/room/code` → `{ code, room, scope: "code" }` — a short human code to
  pair **across** networks (different WiFi / mobile data).

## UI contract — `useFilament()`

The UI imports `useFilament()` and renders from its return value. It must not
touch the socket, Firestore, or RTCPeerConnection directly.

```ts
{
  me: { id: string, name: string, color: string } | null,
  connected: boolean,
  signalingKind: "socketio" | "firebase" | null,

  // room / discovery
  roomId: string | null,
  roomUrl: string | null,            // share this to pair
  roomScope: "auto" | "code" | "link" | "pair" | null,  // how you got into this room
  roomCode: string | null,           // the 6-char code when scope === "code"
  network: "ipv4" | "ipv6" | "raw" | null,     // how the auto room was grouped

  peers: Array<{
    id: string,
    name: string,
    color: string,                   // stable hsl() per peer
    status: "connecting" | "ready" | "failed" | "away",  // away = declared brb (C21)
    route: "local" | "direct" | "relayed" | null,  // PATH the data takes (Part A)
    uid: string | null,              // stable per-tab identity (survives reconnects)
  }>,

  transfers: Array<{
    id: string,
    peerId: string,
    peerName: string,
    direction: "send" | "receive",
    name: string,                    // file name
    size: number,                    // bytes
    mime: string,
    progress: number,                // 0..1
    status: "offered" | "transferring" | "paused" | "complete" | "declined" | "failed",
    url?: string,                    // present on completed RECEIVES → download
  }>,

  // optional native LAN-discovery helper (Part C); available:false when absent
  localHelper: { available: boolean, peers: Array<{ id, name, addr }> },

  // actions
  sendFiles(peerId: string, files: FileList | File[]): void,
  acceptTransfer(transferId: string): void,   // receiver accepts an "offered"
  declineTransfer(transferId: string): void,
  saveTransfer(transferId: string): void,     // download a completed receive
  clearTransfer(transferId: string): void,    // dismiss from the list
  pairWithCode(code: string): void,           // claim a ONE-TIME code (burned on use)
  generateCode(keyword?: string): Promise<string>, // mint a speakable one-time code
  useAutoRoom(): Promise<void>,               // back to the "people near you" room
}
```

### State rules the UI should honor
- A peer is only a valid send target when `status === "ready"`.
- A `receive` transfer starts as `offered` → show **accept / decline**.
- After accept it goes `transferring` (watch `progress`) → `complete`.
- A completed `receive` exposes `url` → show **save**.
- A `send` transfer is `offered` until the peer accepts, then `transferring` → `complete`, or `declined`.
- `paused` = the link dropped mid-transfer but it CAN resume (the sender still
  holds the file / the receiver still holds the partial bytes). It resumes
  automatically on re-pair — show a frozen progress bar + "resumes on
  reconnect"; allow **clear** to abandon it.

### Signaling additions for resume
- `join` carries a `uid` (stable per-tab id); `welcome` peers and `peer-joined`
  include it. Transfer control messages: `file-offer` may carry `resume: true`;
  `file-accept` carries `offset` (bytes already received).

### Part A — `peer.route` (the privacy/trust signal)
Once a peer connects, `route` tells you the **physical path** ICE chose:
- `"local"` — host↔host, straight across the LAN; **bytes never hit the internet**.
- `"direct"` — peer-to-peer over the internet (NAT-traversed, no relay).
- `"relayed"` — falling back through a TURN relay.
Surface it on the peer tile (e.g. a small badge: `⟶ local` / `⟶ direct` / `⟶ relayed`).

### Declared absences — `brb` / `back` (C21)
Control messages over the DataChannel (additive; unknown types are ignored):
- `{ type: "brb", ttl: 120 }` — "I'm stepping away; hold the line for ttl
  seconds." The browser broadcasts it on `visibilitychange → hidden` (a
  mobile file picker hides the whole tab). Receivers extend their disconnect
  grace / rejoin window to the declared ttl (capped 300 s) and suppress
  failure-path messaging.
- `{ type: "back" }` — absence over; any other traffic implies it too.
Waits become *informed*: longer when promised, shorter (45 s default) when a
peer vanishes without a word.

### Known devices — `pair-keep` / `pair-proof` (C12/C20)
Control messages over the DataChannel; the browser implements both sides
(`lib/devices.js`), mirroring the CLI byte-for-byte:
- `{ type: "pair-keep", secret }` — "remember me." Sent by a `--remember`
  sender after connect. The receiver persists `{name, secret}` (browser:
  localStorage `filament-known-devices`) and immediately `subscribe`s the
  derived channel — from then on either side coming online finds the other
  through `known-peer`, no rooms, no codes. Acknowledgement is MUTUAL:
  a stored-but-unreciprocated secret does nothing (one-sided waving was the
  iPad↔CLI reconnect failure observed live 2026-06-07).
- `{ type: "pair-proof", mac }` — trust, asserted per link.
  `mac = HMAC-SHA256(secret, "filament-proof2:{proverUid}|{loUid}|{hiUid}|{loFp}|{hiFp}")`
  where uids and the two DTLS `a=fingerprint:` values (trimmed, uppercased)
  are sorted lexicographically. Binding to fingerprints means a channel
  MITM'd by anyone — including the signaling server — fails verification.
  Both sides prove; each verifies against every stored secret. Cross-impl
  parity is pinned by test vectors (cli `proof_matches_browser`, gate 16).
- `{ type: "pair-keep-ack", ok }` — C27: the HUMAN's answer to pair-keep.
  Remembering is a trust grant, so the browser asks (consent banner) instead
  of auto-storing; the CLI answers from its `--remember` flag. On `ok:false`
  the offering sender DISCARDS its stored half ("declined to be remembered")
  — a kept-but-unreciprocated secret is exactly the one-sided dead weight
  C12 cured. Silence (old clients) keeps legacy sender-stores behavior.
- `{ type: "pair-proof-ack", ok }` — C27: the verifier's verdict on a proof.
  `ok:false` means "never met you" — the prover drops its expectation for
  that link and tells the user to re-pair, instead of forever claiming an
  acquaintance the other side has no memory of.

#### The `filament pair` ceremony
A dedicated pairing-only flow (`filament pair [code] [--name X]`) that runs the
`pair-keep`/`pair-keep-ack` exchange and exits — no file moves. One side mints a
one-time code (the **creator**); the other **claims** it. On connect exactly one
fresh 64-hex secret crosses the link, by a single rule layered on the line-50
WebRTC convention:
- the **creator** sends `{type:"pair-keep", secret}` the moment the peer is
  ready — it is always the one that hands the secret over;
- the **claimer** waits **3 s** and only then hands over ITS secret as a
  fallback, because browsers (and legacy peers) never initiate the keep. So a
  CLI↔CLI pair settles on the creator's secret; a browser-creator pair settles
  on the claimer's after the 3 s window.
Consent is mutual per C27: the browser asks (banner); a running `filament pair`
IS consent and acks `{type:"pair-keep-ack", ok:true}` automatically. On `ok`
both sides store `{name, secret}` (CLI: `devices.json`; browser: localStorage
`filament-known-devices`) and subscribe the derived channel — "mutually
remembered". `--name` sets the local petname (a local alias; the secret is the
identity).

### One-time pairing (#11)
`generateCode()` mints a **speakable, single-use** code (`clever-lynx-63`; or
pass a custom keyword — collisions are rejected). Say it aloud; the other side
claims it via `pairWithCode()`. The claim is **atomic and additive**: the code
burns on first use, the claimer joins the *creator's current room*
(`roomScope === "pair"` on the claimer), and the creator never moves — nearby
detection stays intact. To add another person, mint another code. A second
claim, or an eavesdropper after the fact, gets `invalid`. Unclaimed codes
evaporate after 10 minutes.

### Part B — discovery modes
- `roomScope === "auto"` → "people near you"; show the `network` and that it's automatic.
- `roomScope === "code"` → show the big `roomCode` to read aloud; offer "back to nearby" (`useAutoRoom`).
- Provide a "pair with code" entry (calls `pairWithCode`) and a "create code" button (`generateCode`).

### Part C — `localHelper`
When `localHelper.available`, optionally show its `peers` as "found on your LAN
(offline)". It's a presence hint from the native helper; absent by default.
