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
