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
          kind: Grant | Deny | Ceiling | Certify | Pass | Pause | Accept,
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

**L10 -- No widening by combination.** Ops that each deny do not combine into
an allow. `Deny` is a TOMBSTONE: only its own author can lift it, and only by
publishing a newer version of that same op with a shorter interval. No other
author, no accumulation of grants, and no ceiling can retire someone else's
deny. The single deliberate exception is the L5 pair: a `Grant` alone denies
(unaccepted) and its `Accept` alone denies (nothing to accept), and together
they allow. That pair is the ONLY combination of individually-denying ops
that may allow, and an implementation that admits a second one is
non-conformant.

**L11 -- Idempotence and order independence.** Replaying the same op set in
any arrival order, with any duplicates, yields the same verdict and the same
`because`. The log is a set with versions, not a sequence: nothing about a
decision may depend on which op arrived first.

**L12 -- Pause.** Author-only, subject is the counterpart key,
interval-bounded. A live `Pause` suppresses every allow its author would
otherwise give for that subject during its interval, and the refusal carries
reason `paused`, DISTINCT from `denied`. A pause is not a deny: it needs no
lifting op, it expires on its own, and it leaves the author's grants intact
underneath.

**L13 -- Accept.** An `Accept` references exactly one `Grant` or `Pass` op id,
is signed by that op's subject, and is meaningful only while both it and the
referenced op are live. An `Accept` naming an op that does not exist, or
signed by anyone but the subject, authorizes nothing.

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

- `Certify` and `Pass` are op kinds with no law constraining them. This
  contract pins the conservative reading and no more: `Certify` is an
  attestation that contributes nothing to a verdict and never appears in
  `because`, and `Pass` is a widening op governed by exactly the L5 rules that
  govern `Grant`. WHO may `Pass` WHAT -- the delegation rule -- is not pinned
  by L1..L13 and must be decided before `Pass` is implemented.
- L10's plain-English form ("ops that each deny never combine into an allow")
  is contradicted by L5, whose whole mechanism is two individually-denying ops
  combining into an allow. L10 above states the restriction WITH its single
  exception named. `proofs/capability_ledger_model.py` checks exactly that: it
  enumerates every pair of individually-denying ops that allows together and
  fails unless each one is a grant/pass and its own accept.

The model checker for all thirteen laws is `proofs/capability_ledger_model.py`,
a required gate in `.github/workflows/proof.yml`.

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
