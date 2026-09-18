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
- `sync` `{ v:1, room, name, uid, channels: [sha256hex] }` — C30: the
  convergent session's ONE idempotent emit, carrying the client's full
  desired session state. The server ensures membership (join flow only if
  the room changed), unions subscriptions, refreshes the lease, and replies
  with its digest `{ v:1, ok, room, channels, lease }` BOTH as the socket.io
  ack and as a `synced` event (the Rust client consumes events only). The
  old events above remain the fast path; clients re-sync whenever desired ≠
  confirmed or confirmed is stale (30 s) — no single emit is load-bearing.
  Phase 2: the digest also carries `peers` (welcome-shaped roster of the
  caller's room, excluding self, sorted by sid, capped 32; only on ok:true)
  — clients reconcile it so missed peer-joined/left self-correct.

  **This reconciliation carries a TRANSPORT-RECOVERY obligation it was not
  designed for. Read this before changing its cadence or its adopt path.**

  The *designed* transport fallback is `expired_direct` → `establish()`. That
  path buys exactly ONE fallible, unretried attempt: `establish()` performs a
  `fetch_config` network round trip, and on failure `main.rs` logs it and the
  loop moves on. `expired_direct` has already reaped the pending, so the
  trigger is consumed and no successor exists. What actually recovers the
  transfer at that point is roster re-adoption — a mechanism added to fix a
  *signaling* defect (a client discarding this digest roster), never tuned,
  measured or documented as transport recovery.

  Two ways to break transport recovery without touching transport code:
  tune the sync interval for signaling reasons and you silently change
  transport-recovery latency; optimise the adopt path to skip redundant work
  and you can delete transport recovery outright. Neither change would have
  any reason to look at the transport layer.

  So: changes here must be evaluated against **I-GAP** (*no live path, and no
  armed successor*) in `proofs/transport_upgrade_model.py`, not only against
  signaling correctness. That model scores the current design clean in 4 of 8
  environments, and all four of the broken ones are precisely the ones where
  this reconciliation is unavailable.

  Note that re-adoption is gated on the link being ABSENT, so it cannot fire
  for a peer whose link was never dropped, and it cannot fire at all for a
  peer known only via `channel` unless the digest's `channel_peers` reaches
  the adopt path. Both gaps are load-bearing, not incidental.
- DataChannel control `{ type:"state", v:1, transfers:{id:bytes}, trusted,
  away }` — C30 phase 3, sent every ~10 s per open link by both ends.
  Receivers correct divergence: re-offer (resume) a "complete" transfer the
  peer holds short; re-prove once on trusted:false; clear away-marks on any
  state ping (frozen peers can't ping). Additive — unknown types ignored.

**server → client**
- `welcome`     `{ id, peers: [{ id, name }] }` — your id + who's already here.
  `id` is mandatory. The Flask relay always emits the Socket.IO sid at
  `backend/signaling.py:391`, and the Firebase adapter always emits its local
  id at `frontend/src/lib/signaling.js:161`; there is no supported welcome
  variant without it. Rust's `as_str().map(...)` handling in
  `cli/src/l2.rs:1247` and the browser's destructuring in
  `frontend/src/lib/useFilament.js:586` are defensive tolerance for malformed
  input, not protocol permission to omit the field. Implementations must send
  the id and clients may treat a welcome without one as malformed.
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

### Transport eligibility and first contact

Direct QUIC is an authenticated transport, not discovery or trust bootstrap.
Its key is derived from the mutually remembered pair secret. The signaling relay
may carry direct candidates, but it never supplies that secret.

- An unknown peer, including a one-time code pairing, has no shared secret before
  the connection. WebRTC therefore carries the PAKE ceremony and its DTLS-bound
  confirmation first. After confirmation, the newly derived secret may promote
  the link to direct QUIC where both peers are CLIs.
- A known CLI peer already has a stored pair secret. Known-peer discovery can
  start the authenticated direct-QUIC race before WebRTC, with WebRTC retained as
  the fallback. This is the normal second-and-later contact path, even when it is
  the first connection in a fresh process session.
- If either peer is a browser, WebRTC remains the transport because browser peers
  cannot participate in the CLI direct-QUIC handshake.

Thus "first contact rides WebRTC" is correct for first contact with an unknown
peer, and is required by the authentication order. It is not a statement that
every connection or every platform always starts on WebRTC.

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

## Relationship frames

Wire-visible pieces of the relationship model designed in
`docs/design-relationship-ux.md`. Only what crosses a link or a signaling
socket is here; the state model, the verbs and their prompts are not wire and
live in that document.

### One-shot verb codes (`serve <verb>` / `<verb> <code>`)

A speakable code scoped to ONE verb and ONE session. It reuses the existing
pairing code machinery unchanged and adds exactly one thing: the verb is bound
into the key-confirmation MAC.

- **Grammar.** `adjective-animal-NNNN`, the four-digit pairing nameplate
  (`mint_words` / `mint_pair_nameplate`). The two words are the SPAKE2
  password and NEVER leave the machine; the nameplate is the only part
  registered with the signaling server. Splitting is `norm_code` then
  `split_code`, identical to `add`/`join`.
- **Registration.** Unchanged: the server sees `pair-create {nameplate, v:2}`
  from the serving side and `pair-claim {nameplate, v:2}` from the claimer. The
  verb is NOT sent. A server that learns the nameplate learns that a code
  exists, not what it opens.
- **Burn on use.** Unchanged and server-side. A second claim, or a claim after
  the 10-minute TTL, yields `pair-error` and the claimer is told the code is
  spent, never served.
- **The scope byte.** `pake-confirm` already carries `scope`
  (`{ type:"pake-confirm", v:2, mac, caps, scope }`), and the MAC is computed
  over `K`, the two sorted DTLS fingerprints, the canonical caps and that byte.
  Values `0x00`/`0x01` keep their present meaning (`IntroScope::Device` /
  `User`). Verb scopes occupy a reserved range, one byte per verb:

  | byte | scope |
  |---|---|
  | `0x00` | intro, device (existing) |
  | `0x01` | intro, user (existing) |
  | `0x10` | verb `shell` |
  | `0x11` | verb `exec` |
  | `0x12` | verb `forward` |
  | `0x13` | verb `mount` |
  | `0x14`-`0x1f` | reserved for future verb scopes |

  Unknown scope bytes are REFUSED, not ignored: a confirmation whose scope byte
  the receiver does not know must abort the ceremony. Skipping an unknown scope
  would let a future verb be served by an older peer that has no idea what it
  agreed to.
- **Session, not relationship.** A verb-code ceremony persists NOTHING. The
  derived secret (`secret_from_k`) is held for the life of the session and
  discarded, exactly as `send`'s ephemeral ceremony does today. No
  `devices.json` record is created and no capability op is written.

Invariants:

- The code is PAKE-protected and therefore **low-entropy-safe**: the words never
  cross the wire, so there is no transcript to attack offline. An attacker gets
  ONE online guess per nameplate, and a wrong guess fails key confirmation and
  burns nothing on the honest side; a right guess burns the code for everyone.
- **A code scoped to one verb cannot open another.** The verb is inside the
  confirmation MAC, so a `shell` code presented to `mount` fails key
  confirmation. This is a cryptographic property, not a policy check the
  receiver could forget to make.
- **The code authorizes a session, and `serve` authorizes the verb.** A peer
  that completes the ceremony gets the one verb the serving side chose to serve.
  It does not get a capability, a grant, a role, or the right to come back.

### Remember offer and accept

Promoting a session to a remembered relationship. This extends the existing
`pair-keep` / `pair-keep-ack` control messages (see *Known devices*); v:1
messages keep their present behaviour exactly.

- `{ type:"pair-keep", v:2, offer_id, secret, name }` — the offer. `offer_id` is
  a fresh 16-hex nonce. `name` is the OFFERER's proposed display name for
  itself; it is a suggestion, never authoritative, and the receiver's petname
  stays local (C12: names are local aliases for secrets).
- `{ type:"pair-keep-ack", v:2, offer_id, ok }` — the answer. It MUST echo the
  `offer_id` it answers. An ack whose `offer_id` matches no outstanding offer is
  ignored. A v:1 ack (no `offer_id`) answers the single most recent outstanding
  offer, which is the legacy behaviour.
- Either side may send `pair-keep` at any point in a session, and either side
  may send it first. The 3-second creator/claimer tie-break in the `filament
  pair` ceremony applies to that ceremony only, not here.

Invariants:

- **Remembering is mutual or it does not happen.** On `ok:false`, and on a v:2
  offer that receives no ack before the session ends, the offerer discards its
  half. A kept-but-unreciprocated secret is the exact defect C12/C27 cured, and
  v:2 closes the remaining hole by making silence a refusal rather than a
  legacy sender-store.
- **Silence is not consent.** This is the one behavioural difference from v:1,
  and it is why the version bumped.
- **`pair-keep` carries no grant and no role.** The secret makes two devices
  findable and mutually authenticated. It authorizes nothing. A receiver that
  infers any capability from having been remembered is non-conformant.

### `pass` — a Grant to a person key with a device budget

A pass is a widening op in the capability ledger, governed by exactly the L5
rules that govern `Grant`, plus two restrictions of its own.

```
Pass { id, author: key, subject: person_key,
       capability: (action, resource),     // resource-scoped, see below
       way: In | Out | Both,
       devices: u16,                       // device budget, 1..=n
       interval: [not_before, not_after),  // half-open, UTC seconds
       version: u64, sig }
```

- **Effective only while accepted.** Like any widening op, a `Pass` authorizes
  nothing until a live subject-signed `Accept` naming its `id` exists (L5, L13).
- **Attenuation only.** A `Pass` whose `(action, resource)` is not covered by
  EVERY live `Ceiling` on its author is refused at ingest (L6), not merely
  denied at evaluation. The refusal is at the boundary because a pass that the
  author could not have honoured should never enter the log.
- **No re-delegation.** An author whose own authority for that capability comes
  from a `Pass` may not author a `Pass` for it. Ingest refuses it. A pass is a
  leaf.
- **The device budget.** Each distinct `device_pub` appearing in a live `Accept`
  that names this pass consumes one slot. An `Accept` that would take the count
  past `devices` is refused at ingest, with reason `budget` — distinct from
  `denied` and from `paused`, because the remedy is "the grantor raises the
  count", not "ask again".
- **The card is a carrier, not an authority.** The card handed to a person
  carries the signed `Pass` and nothing that authorizes by itself. Claiming a
  card produces an `Accept` that the author must ingest before anything is
  allowed. The same pass may also be delivered as a one-shot code, in which case
  the code is a verb code for `join` and burns on first use.

Invariant: **no frame carries a grant or a role the receiver did not sign for.**
A card, a code, or an inbound `Pass` frame confers nothing until the holder's
own `Accept` is signed and the author has ingested it. Arriving with a valid
signed pass is not arriving with access.

### The direction bit on grants

`way` is a field on `Grant` and `Pass`. It is defined relative to the AUTHOR's
resource.

| `way` | meaning | authorizes the subject? |
|---|---|---|
| `In` | the subject may act on the author's resource | yes |
| `Out` | the author may act on the subject's resource | **no** |
| `Both` | both statements, together | only the `In` half |

Invariants:

- **`Out` grants the counterpart NOTHING.** An `Out` entry is a statement about
  the author's own side. It does not authorize the subject, and it is not by
  itself sufficient for the author either: the author may act on the subject's
  resource only when the SUBJECT has authored a live, accepted `In` grant for
  it. The reverse direction never exists unless it is separately granted.
- `Both` is shorthand for the pair, and it widens nothing beyond its `In` half.
  An implementation that treats `Both` as mutual authorization from one
  signature is non-conformant.
- `way` is a field on the op and part of the signed blob. It is never inferred
  from the verb, the transport, or which side opened the connection.

### Resource-scoped capabilities and the lattice

Today a capability is `action` or, for `route` alone, `action:resource`; every
other action resolves to the fixed resource `self`. Resource scoping generalizes
that. The wire form is a canonical string in `CapOp.resource`.

```
capability := action [ ":" target [ ":" detail ] ]

target     := device-key | "tag" ":" tag-id | "fleet" ":" owner-key | "*"
detail     := port | port-range | path-prefix | cidr | "*"
```

| example (as the CLI renders it) | action | target | detail |
|---|---|---|---|
| `shell` | shell | self | — |
| `forward:ws:8080` | forward | device `ws` | port 8080 |
| `forward:ws:8000-8099` | forward | device `ws` | port range |
| `receive:nas:~/share` | receive | device `nas` | path prefix |
| `see:tag:lab` | see | tag `lab` | — |
| `route:10.0.0.0/24` | route | self | CIDR (existing, unchanged) |
| `shell:fleet:<owner>` | shell | every live-certified device of that owner | — |

**Keys on the wire, names in the CLI.** A `device` target is the device's
32-byte public key, and a `fleet` target is the owner's. Petnames appear only in
the CLI's rendering. This is ledger law L2: renaming a device must change no
verdict, and re-pairing one must change every verdict about it.

**The lattice.** `covers(claim, pattern)` is supplied by the caller, never by
the ledger (L8). It is component-wise, with `*` as top at each level:

- action: exact, or `*`.
- target: exact key, or `*`. `tag:X` covers every principal or resource bearing
  a live binding for `X`; `fleet:O` covers every device with a live cert
  chaining to `O`. A tag or fleet pattern NEVER covers another tag or fleet.
- port: exact, a closed range, or `*`.
- path: prefix match, boundary-aligned on `/`. `~/share` covers `~/share` and
  `~/share/a`, and does NOT cover `~/shared`. A pattern containing `..` is
  refused at ingest, not normalized.
- cidr: containment, as today.

A claim with a component the pattern does not mention is NOT covered: a pattern
of `forward:ws` does not cover `forward:ws:8080`. Widening to "unspecified means
any" is the single most attractive shortcut here and it is forbidden, because it
turns every under-specified grant into a wildcard.

Invariants:

- **The request is daemon-derived, never peer-supplied.** The resource in a
  `Request` is named by the receiving daemon from the connection it actually
  accepted — the port it is listening on, the path the open named after
  canonicalization. A peer asking for `forward:ws:8080` does not get to say what
  it is asking for.
- **A ceiling can only narrow.** An allow must lie within every live `Ceiling`
  on that subject, and no wildcard in a grant can escape one (L4).
- Unknown actions and unknown target forms are REFUSED at ingest. A capability
  string the boundary cannot parse is not a capability it may store and skip.

## Exec streams (`filament exec`)

Remote command execution over an established link, as a session-stream kind
beside `mount-open` / `pty-open`: same sid-keyed streams table, same
`send_control` framing, same `*-ack` open handshake. Additive -- unknown
stream kinds are refused, never misinterpreted.

- `exec-open` `{ type: "exec-open", sid, err_sid, argv: [...], cwd, env, tty }` --
  open an exec stream. `argv` is carried EXACTLY, element by element: the
  initiator must send the argument vector as an array and the receiver must
  spawn exactly those elements, with no joining, no splitting, no quoting
  pass, and no shell in between. Spaces, quotes and glob characters survive
  because they are never re-parsed -- that property is load-bearing, not
  incidental, and the spaces/quotes/glob e2e gates pin it on the platforms
  they run on. `err_sid` is REQUIRED: the initiator-allocated stderr stream
  id, announced so both ends use one value (same discipline as `sid`); an
  open with it missing, unparseable, or outside the L2 sid half is refused
  rather than served with a second locally-allocated sid nobody listens on.
  `cwd` is the requested working directory (default: the daemon's home).
  `env` carries ONLY the allowlist: `TERM`, `LANG`, `LC_*`, plus explicit
  `--env KEY=VALUE` pairs. Nothing else from either side's environment
  crosses the link. `tty` requests a pty instead of pipes.
- `exec-open-ack` `{ type: "exec-open-ack", sid, out, err }` -- the
  receiver's acceptance: `out` (== `sid`) names the stdout stream, `err`
  (== the open's `err_sid`) the stderr stream. Informational: both pipes
  are registered before the open goes out, so bytes racing the ack are
  already routable.
- Standard output and standard error travel on SEPARATE streams (`out` for
  stdout, `err` for stderr -- two distinct sids, not two channels under
  one), never interleaved into one byte stream. A receiver that merges
  them is non-conformant: exit-status attribution and error triage depend
  on the split.
- Close payload `{ type: "exec-close", sid, status, out_bytes, err_bytes }` --
  `status` is the raw process exit code. Death by signal is reported as
  `128 + signal number` (the shell convention: 137 for SIGKILL, 143 for
  SIGTERM), never as 0 and never as a bare code that collides with one.
  No exit-status payload means the process did not exit cleanly; clients
  must not render that as success. The byte counts let the initiator drain
  stragglers deterministically: close travels control while bytes travel
  frames, so a fast-exiting child can beat its own tail.
- HALF-CLOSE: stdin EOF is non-terminal. An empty stdin frame shuts the
  child's write-half (it may still produce output -- EOF ends input, not
  the session); only the exec-close frame ends the stream. The receiver
  serves each accepted open as a detached task, so one session's lifetime
  never blocks the daemon's event loop or another stream.
- SHELL GATE: an exec stream is allowed exactly where a shell is allowed.
  The receiver enforces the same gate as `up --shell`, and `--shell-only
a,b` scopes it to the listed peers/devices identically: a peer outside the
  scope gets the open refused, the same verdict an out-of-scope shell
  attempt receives. Exec adds no new trust -- it rides the shell grant.

## Capability ledger (append-only signed ops)

Authorization is a **log**, not a mutable store. Every authorization fact is an
append-only signed operation; the decision is a **pure function** of the log,
the request, and the current instant. This replaces today's destructive model
(`CapOpKind::Revoke` deletes the grant row, `apply_cap_op` -> `store.remove`),
where the reason an action is refused stops existing the moment it takes
effect. The ops below (`Deny`, `Pause`, `Accept`) are new primitives, not
renamings of anything in `crates/filament-cap`: there is no deny object, no
pause, and no subject counter-signature in the engine today.

```
Op      { id, author: key, subject: key, capability: (action, resource),
          interval: [not_before, not_after),   // half-open, UTC seconds
          kind: Grant | Deny | Ceiling | Pass | Pause | Accept,
          version: u64,                        // per author, monotone
          sig }
Facts   { now, subject: key, binding: None|Inferred|Proven,
          cert: Option<{ device_pub, user_pub, expires, revoked }>,
          held_author_key: Option<key>, ops: verified ops }
Request { action, resource }                   // DAEMON-derived, never peer-supplied
Verdict { decision: Allow | Deny(reason), valid_until: Option<u64>,
          because: [op id] }
```

`decide(facts, request) -> Verdict`. A `ResourceLattice::covers(claim, pattern)`
supplied by the caller decides "within" for device / port / path / tag
patterns; the library itself knows no verbs. **Forget is a STORAGE action** --
it removes a record and every op about it from the log, and it is not an op:
nothing in the log can describe its own erasure.

### The laws

**L1 -- Pure and deterministic.** `decide` reads no clock, no store, no
network, no environment. `now` is an argument; UTC seconds at the boundary.
Two calls with equal arguments return equal verdicts, byte for byte. A
`decide` that consults `SystemTime::now()`, a file, or an env var is
non-conformant however correct its answer.

**L2 -- Keys are identity, names are presentation.** The library never sees a
display name, a petname, or a device label. Every `author` and `subject` is a
key. Renaming a device changes no verdict; re-pairing one (a new key) changes
every verdict about it. `Facts.binding`, `Facts.cert` and
`Facts.held_author_key` are carried for the CLI's view layer and for
boundary-side ingest, and `decide` does **not** read them: the verdict is a
function of `now`, `ops` and `request` alone. Widening that -- making the
verdict depend on the cert or the binding -- is a contract change, not an
implementation detail.

**L3 -- Time is first-class.** Every op carries a half-open interval
`[not_before, not_after)`; an op is live at `t` iff `not_before <= t <
not_after`. Every verdict returns `valid_until`: the next instant at which the
verdict could change if nothing else does. ONE generic re-evaluation scheduled
at `valid_until` replaces every per-path revoke ticker; a subsystem that wants
its own expiry timer is duplicating this and will drift from it.

**L4 -- Composition.** `Deny` is absolute over any overlapping `Grant` /
`Pass` / `Accept`. `Ceiling` only ever narrows: an allow must lie within EVERY
live ceiling on that subject, and a ceiling can never make an otherwise-denied
request allowed. Newest version per author wins -- for a given op id, only the
highest version is effective and older versions by the same author are
ignored entirely, never merged. A widening op **never** erases an earlier
`Deny`.

**L5 -- Widening needs two signatures.** A `Grant` (and a `Pass`) is effective
only while a subject-signed `Accept` naming that op's id is itself live.
Narrowing needs only the author's signature: `Deny`, `Pause`, a `Ceiling` that
narrows, and a newer version of the author's own op with a shorter interval
all take effect unilaterally. The asymmetry is the point -- you can always
reduce what you have handed out, and you can never hand out more alone.

**L6 -- Verification at the boundary.** Ops enter the log only after signature
and version checks. Ingest refuses an op whose signature does not verify,
whose id is already held under a DIFFERENT author, or whose version is not
strictly greater than the highest version already recorded for that author.
A refused op is refused, not silently sorted to the back of the log: the
evaluator trusts the log completely and has no second line of defence.
Revisions SHARE an op id, and the highest version recorded for an id is the
one that decides. An id names one author for its whole life: a revision whose
author differs from the id's first author is refused, because otherwise a
foreign author could take over an id whose interval the subject already
accepted.

**L7 -- Explainable.** `because` is a MINIMAL SUFFICIENT CAUSE of the decision
and its reason: evaluating the request against only the ops in `because`
yields the same decision and reason, and removing any one of them does not.
It explains the decision, not `valid_until`, which is derived from the whole
log. The selection is canonical, so the same log always produces the same
`because`.

**L8 -- Verb-agnostic, with a lattice.** Capabilities are opaque
`(action, resource)` pairs. Containment is `covers(claim, pattern)`, supplied
by the caller: exact match, `*`, and prefix patterns for paths and ports.
Mapping a verb onto another (exec riding the shell grant, `ssh-sign` riding
the same gate -- see `cli/src/shell_gate.rs`) happens at the BOUNDARY, before
`decide` is called. The ledger does not know that `exec` and `pty` are the
same thing; the gate does.

**L9 -- `valid_until` soundness.** Given unchanged facts, the verdict for the
same request cannot change at any instant strictly between `now` and
`valid_until`. At `valid_until` it may. `None` means it can never change
again for those facts. A `valid_until` later than the first instant of change
is a correctness bug, not a performance tuning knob.

**L10 -- No widening by combination.** No combination of ops other than a
`Grant` with its referenced `Accept` (L5) may turn denials into an allow.
`Deny` is a TOMBSTONE: only its own author can lift it, and only by
publishing a newer version of that same op with a shorter interval. No other
author, no accumulation of grants, and no ceiling can retire someone else's
deny. The single deliberate exception is the L5 pair: a `Grant` alone denies
(unaccepted) and its `Accept` alone denies (nothing to accept), and together
they allow. That pair is the ONLY combination of individually-denying ops
that may allow, and an implementation that admits a second one is
non-conformant. The model enumerates every pair of individually-denying ops
that allows together and fails unless each one is a grant or pass together
with its own accept.

**L11 -- Idempotence and order independence.** Replaying the same op set in
any arrival order, with any duplicates, yields the same verdict and the same
`because`. The log is a set with versions, not a sequence: nothing about a
decision may depend on which op arrived first.

**L12 -- Pause.** Author-only, subject is the counterpart key,
interval-bounded. A live `Pause` suppresses every allow its author would
otherwise give for that subject during its interval, and the refusal carries
reason `paused`, DISTINCT from `denied`. A pause is not a deny: it needs no
lifting op, it expires on its own, and it leaves the author's grants intact
underneath. A pause is PATTERN-SCOPED: its capability pattern is matched with
the same `covers` rule as everything else, so the lattice top is the wholesale
form ("pause everything I could otherwise allow") and a narrower pattern
pauses exactly what it covers. Narrower pauses compose by intersection: an
allow survives only while no live pause covers the request.

**L13 -- Accept.** An `Accept` references exactly one `Grant` or `Pass` op id,
is signed by that op's subject, and is meaningful only while both it and the
referenced op are live. An `Accept` naming an op that does not exist, or
signed by anyone but the subject, authorizes nothing.

**L14 -- `Pass` is attenuated delegation.** A `Pass` is a `Grant` whose
SUBJECT is a person key with a device budget: the subject may re-issue it, for
its own device keys, strictly within what the author's own ceiling toward that
resource allows. Attenuation-only is the whole law -- a `Pass` wider than its
author's ceiling is inert, it can never be narrowed back into a widening, and
it is governed by the same L5 pair rule as any other widening op. WHO may pass
is anyone who already holds the capability being passed, so no separate
authority is required and none can be manufactured: you cannot pass what you
do not hold.

**L15 -- Certificate facts are absolute.** A `Facts.cert` whose `revoked` is
set, or whose `expires` is not after `now`, denies every request about that
subject: like a tombstone, no grant, ceiling, pass, or combination outranks it.
The reasons are DISTINCT -- `revoked` and `expired` -- because an operator
debugging a lockout must be able to tell a deliberate revocation from a lapse.
`Certify` is NOT an op kind: minting a certificate is an identity-lifecycle
event whose only ledger-visible result is this `Facts.cert`.

**L16 -- Binding is a precondition of every allow.** Every allow requires
`Facts.binding` to be at least the op's `min_binding`, which is `Proven` by
default; `None` and `Inferred` are below it. `Inferred` is accepted for exactly
one population -- a `Grant` over a pair secret, which is today's legacy path --
so the migration has a home and nothing else silently inherits the weaker bar.
An `Inferred` binding is never enough on its own: `unproven` is a distinct
denial reason, so a caller can tell "no proof yet" from "refused".

**L17 -- The held author key is the trust root.** Ops authored by
`Facts.held_author_key` ARE the subject's own policy and decide on their own.
Ops by any OTHER author are effective only within a ceiling that the held key
granted them: a delegated op can never exceed the local policy that admitted
its author, and no chain of foreign authors can walk the boundary outward.
The model keys this as `own-policy-is-trust-root` and
`delegated-ops-need-ceiling`.

**L18 -- Compaction preserves verdicts.** Compaction may drop ops that cannot
affect any verdict, and nothing else: for every request and instant, `decide`
on the compacted log returns the same decision, the same reason, and the same
`because` as on the full log. This is what makes the migration from today's
store safe. `Revoke` currently DELETES the grant row (`store.remove`), so the
reason a device lost access stops existing the moment it takes effect; in the
ledger the same act is a `Deny` tombstone (or a shorter-interval revision of
the `Grant` by its author), and the reason survives the operation that removed
the access. Compaction must not be allowed to quietly recreate the old
behaviour by discarding it.

### Tiers are views, not state

`external` / `paired` / `fleet` / `dormant` / `paused` are **computed by the
CLI** from verdicts plus `Facts` (binding, cert, whether any op exists at
all). They are never stored, never signed, and never an input to `decide`. A
tier is a way of describing the answer to a human; a change in vocabulary is a
change to the CLI, never a migration of the log. This matches the engine today
(`PrincipalKind`, `BindingStrength` and `same_owner` are all derived per call
and nothing persists a tier field) and the ledger must not regress it.

### Deliberately unresolved

Two points are recorded here rather than resolved, because resolving them
silently would be worse than naming them:

- `Pass`'s device budget is NAMED but not pinned. L14 fixes the shape
  (person-key subject, re-issuable to its own device keys, attenuation-only,
  never wider than the author's ceiling) and fixes who may pass (anyone holding
  what is passed). Whether the budget is a count, an explicit list of device
  keys, or a scope, and how it is decremented, is a product decision that must
  be made before `Pass` is implemented -- resolving it silently here would
  invent policy.
- L10's plain-English form ("ops that each deny never combine into an allow")
  is contradicted by L5, whose whole mechanism is two individually-denying ops
  combining into an allow. L10 above states the restriction WITH its single
  exception named, and the model enforces the enumeration rather than the
  prose.
- `Facts.binding` for a foreign author is not pinned: L16 says a foreign op is
  effective only inside a ceiling the held key granted it, and that every allow
  needs binding >= `min_binding`, but whether a FOREIGN grant may carry
  `Inferred` (a pair secret the subject's own key never proved) is left to the
  migration, because today's fleet links reach `Proven` only on direct-link
  adoption and a hard `Proven`-only rule for foreign ops would be a behaviour
  change smuggled in by a contract.

The model checker for all eighteen laws (L14-L18 are the review rulings above; the
model implements them and keys each check against these numbers) is
`proofs/capability_ledger_model.py`,
a required gate in `.github/workflows/proof.yml`.
## Bootstrap card (fc1)

A bootstrap card is a short self-describing string that says "this key,
reachable maybe at these addresses, until this instant", signed by the
key it names. It is what `filament addr --card` prints, what an
invitation carries, what a pair QR encodes, and what a DNS TXT record
publishes. It exists so a peer can be reached when the signaling server
is unreachable, untrusted, or unwanted. It is also the ONLY artifact in
filament a stranger may hand you before any link exists, which is why
every rule below is about what it is not allowed to do.

- WIRE FORMAT: `fc1` followed immediately by base64url (RFC 4648 §5,
  NO padding, no line breaks) of a CBOR map:

  ```
  { v: 1,                      ; uint, wire version
    device_pub: bytes(32),     ; Ed25519 public key, the identity
    endpoints: [ { ip, port, proto } ... ],   ; 0..4 entries
    relay:  { addr, mechanism },              ; optional
    psk:    bytes(32),                        ; optional, PRIVATE cards only
    expires: uint,                            ; UTC seconds since epoch
    sig:    bytes(64) }                       ; Ed25519 over the rest
  ```

  There is no other envelope: no JSON, no hex, no compression. A string
  that does not start with `fc1` is not a card and must not be guessed
  at.
- CANONICAL CBOR (RFC 8949 §4.2.1 core deterministic encoding):
  definite lengths everywhere, map keys sorted by their ENCODED bytes,
  integers in their shortest form, no indefinite-length strings, no
  tags, no duplicate keys, no unknown keys. Key order in the top map is
  therefore `v`, `psk`, `sig`, `relay`, `expires`, `endpoints`,
  `device_pub`; in an endpoint `ip`, `port`, `proto`; in a relay `addr`,
  `mechanism`. An encoder that emits any other byte sequence for the
  same fields is non-conformant, because the signature is over bytes.
- SIGNATURE DOMAIN: `sig` is `Ed25519(device_privkey)` over the
  canonical CBOR encoding of the SAME map with the `sig` key absent
  (not present-and-zeroed). The card is self-signed: the key that
  signs is the key the card names, so a card proves possession of
  `device_pub` and nothing else about who holds it.
- VERIFY ORDER, in this order, refusing at the first failure, before
  any packet is sent anywhere:
  1. parse: strip `fc1`, base64url-decode, CBOR-decode, and re-encode
     canonically -- a card whose bytes are not already canonical is
     REFUSED as malformed, never silently re-normalized;
  2. check `v`: `1` is the only accepted value (see UNKNOWN VERSION);
  3. check `expires > now`, where `now` is a PARAMETER in UTC seconds
     supplied by the caller, never read from the clock inside the
     verifier -- so the check is testable and a skewed host is a
     caller-visible fact;
  4. DERIVE the overlay address from `device_pub`
     (`fdf1:1af7:c30d::/48` prefix ||
     `SHA256(b"filament/overlay-addr/v1\0" || device_pub)[..10]`, the
     same function the L3 overlay uses) and REFUSE on mismatch with the
     record the card claims to be about;
  5. verify `sig` over the canonical re-encoding from step 1;
  6. only now may the dial path use the card, subject to DIAL GUARD.

  The order is load-bearing. Signature verification is the expensive
  step and derivation is free, so a mismatched address costs an attacker
  nothing to have checked; and a verifier that dials before step 6 has
  turned an unauthenticated string into a network action.
- DERIVATION IS THE IDENTITY CHECK, not a convenience. Step 4 is what
  stops a card from relabelling a known peer: an attacker with a valid
  self-signed card for their OWN key can always produce a card that
  verifies, and the only thing that stops it from being accepted as
  peer B is that it does not derive to B's address. A verifier that
  skips step 4 because it "already verified the signature" has verified
  nothing about WHO.
- TWO CLASSES, distinguished by `psk`:
  - PUBLIC card -- no `psk`. This is what `addr --card` prints and what
    DNS publishes. It may be copied, logged, indexed, and handed to
    anyone; it grants nothing.
  - PRIVATE card -- `psk` present. It lives only inside an invitation,
    a pair QR, or a file handed to one named recipient, and it is a
    secret for exactly as long as its `expires`. It must never be
    printed to a shared terminal transcript, written to DNS, or logged.
- PSK IN A PUBLIC CARD IS MALFORMED: a card that arrives over a public
  channel (a DNS answer, a web page, a broadcast) and carries `psk` is
  REFUSED, not stripped and not used. Refusing rather than degrading is
  the point: a psk on a public channel is either a leaked secret or an
  attacker's, and both deserve the same verdict. NOTE that "public
  channel" is a property of the retrieval, not of the bytes; the caller
  supplies it, and a caller that cannot say must pass "public".
- AUTHENTICATES, AUTHORIZES NOTHING. The card AUTHENTICATES a peer and
  AUTHORIZES nothing. Capability gates are unchanged: a verified card
  gets a dial, not a grant, not a shell, not a mount, not a route. It
  is not a bearer credential, unlike tailcat's token -- possession of a
  card confers no ability its holder did not already have, which is why
  a public card can be published at all.
- HINTS NEVER IDENTITY: `endpoints` and `relay` are HINTS. They say
  where the key MIGHT answer; they never say who answered. Whoever is
  found at an endpoint still has to prove possession of `device_pub`
  through the normal handshake, and a peer that proves it at an
  endpoint the card did not list is equally acceptable. Corollary: a
  stale, wrong, or hostile endpoint list costs connect time, never
  trust.
- DIAL GUARD, enforced by the dial path on every card:
  - REFUSE loopback, link-local, and multicast endpoints outright
    (127.0.0.0/8, ::1, 169.254.0.0/16, fe80::/10, 224.0.0.0/4, ff00::/8,
    0.0.0.0, ::): a card must never be able to make a host dial itself
    or its own link-local neighbours.
  - REFUSE RFC1918 and ULA endpoints (10/8, 172.16/12, 192.168/16,
    fc00::/7) UNLESS the card came from an already-paired device or the
    operator passed `--allow-private`. An unpaired card that names
    private space is asking a host to port-scan its own LAN.
  - CAP the endpoint list at 4 entries; a card carrying more is
    malformed, refused at parse, not truncated.
  - CAP dial attempts at N per card per minute (N is a settings key;
    see Deliberately unresolved).
  - LOG the endpoint tried, one line per attempt, so an unexpected dial
    is visible after the fact without a packet capture.
- PSK SEMANTICS, stated exactly: the psk adds harvest-now-decrypt-later
  resistance to the session key exchange for privately exchanged cards;
  identity remains Ed25519; this is not a post-quantum signature. It
  mixes into the key schedule, it does not replace or re-anchor the
  identity check, and an attacker who later breaks Ed25519 still cannot
  read a session that used a psk they never saw.
- EXPIRY IS MANDATORY: `expires` is never absent and never zero. A
  pairing card rides its invitation's expiry and must not outlive it
  (`min(invitation.expires, card.expires)` when both are present; the
  card may be shorter, never longer). A card published in DNS carries
  at most 30 days and is rotated before then. A verifier refuses an
  expired card, and refuses one whose expiry is implausibly far in the
  future for its class rather than trusting the number.
- UNKNOWN VERSION REFUSED: a `v` other than 1 is refused with a clear
  "newer card, upgrade filament" error. No field-by-field best effort,
  no ignoring unknown keys: a card the verifier does not fully
  understand is one it cannot safely dial.
- SHORT FORM IS A REFERENCE, NEVER A CARRIER. The speakable short form
  is `version + 64-bit device_pub fingerprint + checksum`, 8 to 10
  words from filament's pairing wordlists (8 bits per word, so 64 to 80
  bits of payload). It is a RENDEZVOUS / FINGERPRINT REFERENCE: it
  names which key to expect, it does not carry the card. The floor is
  arithmetic, not taste -- `device_pub` (32 B) plus `sig` (64 B) alone
  is 768 bits before any expiry, endpoint, or CBOR framing, and a
  minimal one-endpoint card is about 169 B = 1352 bits, roughly 169
  words at 8 bits each and still about 123 words on a 2048-word list.
  No word code that a human will read aloud can carry a card, and any
  proposal to shorten the card until it fits is a proposal to remove
  the signature or the key. VERIFICATION: after the rendezvous
  completes and a key is actually met, the met key's fingerprint MUST
  equal the one in the short form, else REFUSE. The short form is
  therefore an out-of-band integrity check on a card obtained some
  other way, exactly like a pairing SAS.
- DNS PUBLICATION: one TXT record at `_filament.<name>`, whose value is
  `fc1:<base64url>` (the `fc1:` here is the record's own tag; the
  card's own prefix form is `fc1` with no colon, and a publisher emits
  exactly one of the two shapes per channel). ONE record: a name with
  two `_filament` TXT values is ambiguous and is refused rather than
  merged or raced. The published card is always PUBLIC class, always
  `expires <= 30 days`, and rotation is the publisher's job -- an
  expired record is a refusal, not a fallback.
- DNS TRUST, honestly: DNSSEC where it is present gives the record an
  authenticated origin, and that is the only case where the card's
  endpoints inherit any authority. Without DNSSEC the record is
  TOFU-pinned: the first card seen for a name pins `device_pub`, and a
  later record that derives to a different address is refused and
  surfaced as a conflict, not accepted as a rotation. DNS never
  confers trust by itself; it is a faster way to learn a key you then
  verify exactly as you would verify a key from anywhere else.
- CLI SURFACE (shape, not implementation): `filament addr --card`
  prints this machine's PUBLIC card; `--private` adds the psk and
  prints the PRIVATE form with a "do not publish this" banner.
  `filament addr --parse <card>` is fully OFFLINE: it decodes, runs
  steps 1 to 5, and prints the field summary the dial path logs
  (version, derived address, expiry with remaining time, endpoint list
  with the guard verdict per endpoint, relay, class, signature
  verdict). It never dials. `filament reach --until-direct` uses a
  card's hints to keep trying for a direct path instead of settling for
  the first relayed one.

### Deliberately unresolved

Stated so nobody implements a guess and calls it the contract:

- RELAY MECHANISM ENUM: `relay.mechanism` has no fixed value set. What
  strings are legal, and what an unknown mechanism does (refuse the
  card, or ignore the relay hint and keep the endpoints) is undecided.
- ENDPOINT PROTO ENUM: same for `endpoints[].proto`. Whether `quic`,
  `udp`, `tcp`, and a future transport are the closed set, and whether
  an unknown proto is a parse refusal or a skipped hint, is undecided.
- ENDPOINT `ip` TYPE: text ("192.0.2.1", "2001:db8::1") versus a 4/16
  byte bstr. The reference codec in `proofs/card_vectors.py` uses text
  PROVISIONALLY so the vectors exist; this is not yet a decision.
- NO DOMAIN-SEPARATION PREFIX. Every other signed filament struct tags
  its signed bytes (`filament-auth-key-v2`, `INV_FORMAT`,
  `filament/overlay-addr/v1\0`). The card as designed signs bare
  canonical CBOR, so the same key signing a card and signing some other
  bare-CBOR structure has overlapping domains. Whether to add a prefix
  before v1 ships is open.
- MAXIMUM ENCODED LENGTH: no cap on the base64url body is fixed, so a
  decoder has no stated input bound. The 4-endpoint cap bounds a WELL
  FORMED card, not a hostile string.
- DIAL RATE N: the "N dial attempts per card per minute" bound has no
  number and no settings key name yet.
- UNCLAIMED CARDS: step 4 compares against "the record it claims". A
  bare card read from a file claims nothing, so there is nothing to
  mismatch. Whether such a card is refused, or accepted as a
  first-contact TOFU pin, is undecided.
- ROTATION: expiry is the only revocation mechanism (as with SSH
  certificates above). There is no revocation list and no rotation
  signal inside the card, so a compromised device key is reachable
  until every published card expires.

## SSH certificates (`filament shell --ssh` via local CA)

Passwordless ssh between fleet devices without installed keys: the
initiator A mints a fresh ephemeral ed25519 key per invocation, asks the
target daemon B to sign it, and logs into B's sshd with the returned
certificate. The CA key is B's own permanent key (0600 beside the
identity key, passed by path); v1 shells out to `ssh-keygen -s`. Both
frames ride L2 control on the established link (request/response, no
bulk -- the Bootstrap precedent); all lifetimes are seconds on the wire.

- `ssh-sign-request` `{ type: "ssh-sign-request", sid, device_id,
  ephemeral_pubkey, ttl_secs }` -- A asks B to certify a key.
  `device_id` is A's device id (verified name); `ephemeral_pubkey` is the
  OpenSSH wire form of an ed25519 key; `ttl_secs` is A's requested
  lifetime (may be clamped down, never up).
- `ssh-sign-response` `{ type: "ssh-sign-response", sid, cert }` -- B's
  answer: the OpenSSH certificate string, or (on refusal) an `l2-close`
  carrying the reason instead of a cert. No cert, clear error, and NEVER
  an authorized_keys fallback: a failed signing reports failure, it does
  not silently downgrade the auth.
- INVARIANT: a certificate is B's statement about A, issued ONLY against
  B's LOCAL grant store; no capability crosses the wire. The request
  carries no grant, no ceiling, no role -- B resolves everything from its
  own store at sign time, through the same shell gate as pty/exec.
- REFUSAL WITHOUT GRANT: no shell grant for A on B means no cert, with
  the gate's reason on the wire. A grievance-free `ssh` that falls back
  to installed keys on refusal is non-conformant.
- REVOCATION WINDOW: revoke stops NEW issuance immediately, but already-
  issued certs stay valid until their expiry (bounded above by 24h, in
  practice by the grant window they were clamped to). There is no live
  revocation list; expiry IS the revocation mechanism, which is why the
  clamp keeps lifetimes short.
- EXPIRY CLAMP: validity `-V` is `min(grant expiry, requested ttl,
  ssh.cert_ttl)` where `ssh.cert_ttl` comes through the settings
  registry (default 1h, hard max 24h). No expiry source may extend
  another: the cert always dies with the first of them.
- PINNING (passed to `ssh-keygen -s` verbatim): `-I` A's device id and
  nothing else; `-n` B's daemon user and nothing else; `-z` a monotonic
  serial (reused serials are refused); `-O clear` plus `-O permit-pty`
  and no other options; ed25519 keys only. A pubkey already signed for a
  DIFFERENT device id is refused, never re-signed.
- ISSUANCE LOG: B logs one line per signing (who/device id, principal,
  serial, expiry) so cert issuance is auditable without sniffing the link.
- CLIENT HYGIENE: the ephemeral key lives in a 0700 tmpdir, fresh per
  invocation, removed by a scope guard on exit AND on signal. A reused
  or surviving ephemeral key is non-conformant.
- DAEMON SSHD: B's sshd trusts the CA via `TrustedUserCAKeys` plus
  `AuthorizedPrincipalsFile`/`AuthorizedPrincipalsCommand` restricted to
  the daemon user. When those lines are unwritable the daemon prints
  both lines plus the reload step instead of silently serving plaintext
  auth; `filament doctor` checks their presence. sshd integration (config
  lines, `sshd -t` validation, reload) targets unix OpenSSH: a bad config
  rolls back before any reload, and on Windows the writer prints the lines
  for manual application (no system sshd to drive there).

## Warm forward + ssh session reuse (`forward --stdio`, `shell --ssh`)

Every `shell --ssh` invocation today pays the full price: fresh ephemeral
key, fresh cert issuance over a fresh link, fresh ssh handshake. These rules
make the second invocation cost milliseconds. Additive: a peer that does not
implement them behaves exactly as before, only slower.

- WARM FIRST: `forward --stdio` (the ssh ProxyCommand shape) asks the local
  daemon for a stream first (control socket, unix). On a hit, stdio bridges
  the daemon-opened stream with no new signaling and no new establishment;
  on a miss it falls back to a fresh establish with the existing clear
  errors. The fallback order (warm, then fresh) is load-bearing: callers
  must never skip the warm attempt, and a warm miss must never read as a
  refusal.
- CERT REUSE (amends the "fresh per invocation" rule in SSH certificates
  above, deliberately): the issued cert plus its ephemeral key are cached
  per peer in a 0700 dir and reused while the cert is valid (bounds read
  from the cert itself via `ssh-keygen -L`, never from wall-clock
  arithmetic on issuance time). Reissue happens only when no cached cert
  exists or the cached one is expired or within 5 minutes of expiry. The
  cache dir is wiped on `revoke`, on `--ssh` refusal, and when the shell
  grant disappears. Rationale for the amendment: a cached key is usable
  exactly as long as the cert the CA already bounded, so reuse adds no
  window theft of a live session does not already have; minting a fresh
  key per keystroke-typing human is ceremony, minting one per daemon
  restart or expiry is hygiene. A surviving cache past cert expiry, or a
  cache shared between peers, is non-conformant.
- MULTIPLEXING: `shell --ssh` passes `-o ControlMaster=auto`,
  `-o ControlPath=<sockdir>/cm-%C`, `-o ControlPersist=<min(cert ttl,
  10m)>` (`%C` hashes the connection parameters so long or odd peer
  names cannot break socket paths). The first invocation establishes and
  later ones ride the same connection. The control socket lives beside
  the cert cache (0700) and dies with it: on expiry, revoke, or grant
  loss the master is stopped (`ssh -O exit`) before the cache is wiped,
  so no multiplexed session outlives its authorization.
  `FILAMENT_NO_SSH_MUX=1` opts out to one-connection-per-invocation for
  debugging.
- B-SIDE ENFORCEMENT (the security property; A's cleanup above is
  hygiene, not enforcement). Revocation happens in B's store and A may
  never learn of it, so the guarantee lives on B: when B revokes A's
  shell grant, or A's cert is revoked or expires, B's daemon tears down
  the L2 stream carrying A's ssh. The stream `forward --stdio B:22`
  opens is admitted on link trust plus `l2_target_allowed`, and for its
  lifetime it rides the same revoke ticker as every daemon-served
  stream: the ticker re-asks `cert_revoked_for` on the stream's resolved
  peer identity and closes with reason on a hit, so any multiplexed
  session dies regardless of what A does. The ticker covers cert
  revocation today; shell-grant revocation is wired into the same tick
  (a grant check beside the cert check), with a gate pinning it: revoke
  on B while an ssh session is live -> the session dies within
  `revoke_recheck_interval`.
- CACHE KEYS: by peer IDENTITY (device_pub fingerprint), never by name;
  a re-paired or renamed device gets a cold cache. Also keyed by B's CA
  public key: a rotated CA deadens the cached cert and the miss reads as
  "reissue", never as refusal.
- CACHE LIFECYCLE, explicit: one dir per peer identity, 0600 files
  inside the 0700 dir; wiped on daemon start (per-restart minting is
  hygiene), on `revoke`, on refusal, on grant loss, and on `reset`.
  Setting `ssh.cert_cache` (registry, `on`|`off`, default on) and
  `--fresh` on `shell --ssh` force reissue.
- REUSE VALIDATION: before offering a cached cert, check its `-I`
  equals our device id and its principal equals the expected user. A
  cache poisoned or swapped by another local process must never be
  used.
- WARM IDENTITY: a warm hit must reach the same verified peer identity
  a fresh establish would reach -- no reuse of a warm link to a device
  re-paired under the same name. The peer-side gate on a warm-opened
  stream is identical to the gate on a fresh one.
- HONEST WIDENING: caching extends A-local credential lifetime from
  "while the session is open" to "until cert expiry" against a
  same-user attacker on A. The bound is `ssh.cert_ttl`, and the cache
  lifecycle plus B-side teardown above exist to hold it.

## Capability ceilings (who may write them)

The persisted per-device ceiling (the record field `principal_ceiling_for`
reads) is owner-signed policy, and only three paths may write it -- all of
them local consequences of owner-signed artifacts, never network input:

- `join` writes the ceiling from the invitation, and only after the
  invitation's owner signature verifies;
- `certify --scope` (planned; not yet built) will write it as an
  owner-signed CapOp through the grant path on the owner side -- until
  then, only renewal_lifecycle's post-verify ceiling write does;
- renewal writes the CERTIFICATE only, never the ceiling.

In particular: `identity-cert-delivery` and cert renewal persist the cert
and must not touch the ceiling field (pinned by test); no UNSIGNED frame
carries a ceiling, a grant, or a role -- `fleet-policy` push carries
owner-signed ops verified against the held owner key, and every other
frame's receiver resolves everything from its local stores. The shell/exec gate reads the ceiling fresh at
gate time and on every revoke tick (never cached at link open), keyed by
the peer's verified device identity, and checks the requested action
against it (`ceiling_covers_action`). Anything outside the ceiling needs
an explicit grant exactly as before.

## Shadow accounting classes

Shadow mode decides on the legacy fold and records what the flip WOULD do, so
the classes must be separated or a stricter flip reads as a broken one. Four,
each with its own counter and its own verdict text:

- **BREAKAGE** -- legacy ALLOWED, the capability layer DENIES, and the subject
  IS covered (ceiling or explicit grant). Counted `la_denied`, logged
  `CAP-SHADOW CRITICAL`, and it is the only class that blocks the flip. A
  CRITICAL means "a covered, legitimate population would lose access".
- **cap-narrows-legacy** -- legacy ALLOWED, the capability layer DENIES, and the
  subject is NOT covered by anything (no ceiling, no grant). Counted
  `la_narrowed` (never `la_denied`), logged at Info. This is the flip CLOSING a
  legacy hole where mere pairing sufficed -- e.g. a peer that hellos as a
  ceilinged device's name -- so it is intended, and it must not pollute the
  breakage signal. Deliberately excluded from `flip_ready`.
- **pending-proof** -- legacy ALLOWED, the layer DENIES, and the only obstacle is
  that the link's possession proof has not settled. Logged at Info. The flip
  admits the open once the link is Proven, so a transient reconnect is not
  breakage; the settle path above exists to wait exactly that transient out.
- **WIDENING** -- legacy DENIED, the layer AUTHORIZES: opens the flip will newly
  permit. Counted `ld_authorized`, never gated (a hard zero would forbid the
  point of the migration), but it MUST be enumerated in the flip commit.

`ceiling_admitted` is informational alongside them: opens admitted by the
enrolment ceiling without an explicit grant, i.e. the population the flip newly
permits. Reviewed, not gated.

## Settle-then-evaluate for shell-class opens

DECIDE FIRST, park second. Every shell-class open runs the live gate before
anything else; the settle layer only ever sees an open the gate ALREADY
denied. An allow is never parked, so every existing allow -- including a
secret-paired, shell-granted peer with no resolved certificate, which the
capability layer admits in shadow mode -- behaves exactly as it did before
this feature existed. What parks is a DENY that may have been caused by an
unproven binding: the open is held up to `gate.settle_ms` (registry,
default 2000, hard max 5000) and re-decided on the settled state.

Parking is conditioned, not automatic. A denied open parks only when ALL of:
the binding is not Proven; the link carries a resolved device key that
maps to a local device record (an unknown key cannot become Proven and must
not occupy budget); the device is not certificate-revoked; the peer is not
explicitly denied; and budget remains. Otherwise the live verdict stands
and the caller emits it (with its usual access-request tell). A denied open
with no resolved key at all also keeps its live verdict -- there is nothing
for a hold to bind to.

- A parked open carries (pid, device key, link GENERATION, kind, frame,
  sid, settle deadline). Release requires the SAME generation proven for
  the SAME device key. The generation check is load-bearing: a reconnect or
  repair swaps the transport under an existing link (and its sids restart
  per mux), so a hold keyed by pid+key alone could fire into a transport
  that never carried the challenge, or answer a parked sid that now belongs
  to an unrelated stream.
- Three stale outcomes, each denied with its own reason: the peer re-keyed
  (device key changed), the link was replaced (newer generation, even for
  the same key), or the link dropped. A close is sent only when the live
  generation still matches the parked one; otherwise the denial is local
  only, because the peer's stream died with its old link and the parked sid
  may now name somebody else's stream.
- Bounds: at most 2 parked opens per link, 32 per daemon; excess denies
  immediately with "identity settling, retry".
- Timeout denies with "identity not proven within N ms; retry" (never
  silently, never as success). One log line per outcome (parked with the
  gate's own reason, proven-in-N-ms re-drive, timed-out, replaced, dropped,
  bound-hit). While anything is parked the loop ticks at 100ms instead of
  2s, so a proof dispatched this iteration is acted on promptly rather than
  up to two seconds late.
- Applies to exec-open, pty-open, ssh-sign-request and l2-open (forward).
  Forward parses and validates its port range BEFORE the gate, so an
  out-of-range port keeps its own immediate denial instead of parking.
- AUTO-TRUST CLASSES, DISTINCT ON PURPOSE: `scoped_in_bounds` is the
  SCOPE DEFAULT class (a transfer into the drop dir, a forward to an exposed
  port) and has always auto-authorized a same-owner Proven device in BOTH
  modes. The enrolment CEILING is a separate input and authorizes a
  deliberate-tier action (shell/exec/pty/ssh-sign) only in authoritative
  mode. It still counts as *would-allow* in shadow accounting, because the
  flip PERMITS those opens rather than breaking them: classifying them as
  denials produced a false BREAKAGE alarm on a population the flip is meant
  to admit. Shadow decisions are unchanged by construction -- shadow always
  decides on the legacy fold. The ceiling class needs no LINK trust: it is
  owner-signed policy plus a Proven possession proof (and the identity may
  never be revoked), so a fleet sibling admitted without the legacy
  `trusted` flag is exactly the case it exists for.
- KNOWN DEVIATION, deliberate: for ssh-sign the settle denials use their
  own retryable reasons rather than the intentionally-generic "ssh-sign
  refused". The generic wording exists so a denied peer cannot oracle which
  check failed; the settle reasons reveal only that the link was not
  identity-proven, which the peer already knows about itself, and they are
  what lets a client retry cheaply on the warm link instead of re-running
  the full ceremony.
- Re-drive calls the SAME handler the live path uses, which re-gathers
  every input fresh (identity, denied, ceiling, certificate revocation,
  liveness), so a revoke that lands during the hold denies at re-drive.
- FUTURE WORK, not built: the cleaner shape is client-side (the client
  waits for a "proven" acknowledgement before sending the open), which
  would remove the server-side hold entirely.
## Certify (`filament certify <device>` -- NeedsReview exit)

A NeedsReview device has a record but no stored certificate and is trusted
in full. `certify` ends that state atomically: it re-proves identity AND
writes a capability ceiling in one owner-side transaction, then tells the
owner exactly what changed in one plain sentence.

- CONTINUITY (load-bearing, not incidental): the minted cert's `device_pub`
  MUST equal the pairwise-known key from the device's existing record.
  Mismatch refuses with "this is not the device you paired with" and
  demands a fresh pairing code. There is deliberately no `--force` and no
  `--trust-new-key` in v1: a name-squatting impostor is exactly the case
  this command exists for, and any override would be the attack.
- ONE SIGNER: the DeviceCert is minted through `DeviceCert::certify` with
  the owner key -- the same call enrollment and renewal use. No second
  signing path may exist; a new signer is a defect, not a feature.
- NO WINDOW: the tier change (uncertified-full-trust to certified-with-
  ceiling) and the ceiling write happen under one lock on the owner side.
  Any failure leaves the record byte-identical to before (pinned by a
  test that injects a store-write failure between the two steps).
- DEFAULT SCOPE IS EMPTY AND SAID PLAINLY: with no `--scope` the command
  prints "<name> certified; can do nothing until you grant". Scoping goes
  through owner-signed CapOps only; nothing in this command writes to the
  cap store from the network.
- DELIVERY: the certified device receives its cert over the authenticated
  link as `identity-cert-delivery { cert }`. The receiver accepts it ONLY
  if (a) the cert's subject device_pub equals the receiver's OWN
  device_pub, (b) the signature verifies against the owner public key the
  receiver already trusts from pairing/enrolment, (c) the cert is not
  expired, and (d) it does not downgrade: a replayed OLDER cert (lower
  serial/issued-at than the stored one) is refused. Otherwise the frame
  is dropped with a logged reason and NOTHING is written. This is the
  same validation the renewal-ack persist path performs, so the frame
  adds no new network write into the identity store beyond one the
  contract already permits.
- PENDING DELIVERY: the owner keeps a "cert issued, not yet delivered"
  flag on the device record. Redelivery is idempotent (the receiver
  applies (a)-(d) and treats an identical cert as a no-op), and the
  pending state is visible in `devices` ("certified, cert not yet
  delivered") so the owner is never confused by a device that still
  presents as uncertified elsewhere. If the device is offline,
  certification still completes locally and the cert is delivered on
  next contact; until then the owner-side ceiling already governs what
  it can do to us.
- AUDIT: one issuance line (name, device_pub fingerprint, scope, expiry).
  `devices` drops the NEEDS REVIEW tier immediately; `doctor` stops
  nagging for it.
