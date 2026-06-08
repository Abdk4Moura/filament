# CLI failure modes & resilience ledger

Companion to [`resilience.md`](resilience.md) (the browser's 11 fixes), for the
Rust CLI in `cli/`. Same discipline, made explicit:

> **The rule.** Every known failure mode lives in this file with a status.
> Nothing ships a fix without flipping its status here, and a status only
> reaches **VERIFIED** with a named test that exercises it. New failure modes
> get an entry *before* (or with) their fix — never silently. The goal is that
> nothing in this file ever happens to a user, and nothing that happened once
> can quietly happen again.

Statuses: **OPEN** (known, unfixed) · **FIXED** (code landed) ·
**VERIFIED** (a standing gate exercises it — see Part 4) ·
**ROADMAP** (absent feature, not a defect — tracked, disclosed) ·
**N/A** (doesn't apply to the CLI).

The standing gates live in `cli/tests/gates.sh` (gates 0–10; browser gates via
Playwright, relay gate via a local coturn container; gates must not run
concurrently — two suites share the auto-room and contaminate each other).
Last full run: **18/18, 2026-06-07** (incl. gate 13 multi-link and gate 14
daemon). Earlier milestone runs:
**15/15, 2026-06-06**, plus live-production runs through
`api.filament.autumated.com`: CLI↔CLI direct, CLI↔CLI forced-relay
(`route: relayed` both ends), and the real `filament.autumated.com` site
sending 64 KiB-framed files to `filament recv`.

---

## Part 1 — Parity matrix: the browser's 11 fixes vs the CLI

| # | Browser fix | CLI status | Where / verified by |
|---|---|---|---|
| 1 | Perfect negotiation / deterministic politeness | **VERIFIED** | `polite_role()`; every CLI↔CLI and CLI↔browser gate |
| 2 | Signal FIFO + candidate buffering + non-fatal signal errors | **VERIFIED** | single event loop; `pending_candidates`; signal errors log-and-recover (F6); gates 1–7 |
| 3 | Ghost tiles / late-callback guard | **VERIFIED** | `Peer.closed` flag silences callbacks of torn-down peers; exercised by every retry/supersede path in gate 2 |
| 4 | Chunk framing + shared backpressure | **VERIFIED** | sid framing; one Notify wakes all parked senders; gates 1–6, 9 |
| 5 | Drop marks transfers terminal/resumable | **VERIFIED** | partials park on disk, `TransferFailed` events; gate 2 |
| 6 | Transient `disconnected` ≠ terminal | **FIXED** (C4) | 6 s grace + `restart_ice` from the impolite side; the hard-drop path is gate-2-verified, the soft-blip path lacks a deterministic local test (gap G-a) |
| 7 | Don't trust stray signal senders | **VERIFIED** | signals filtered to the linked peer's sid; gate 7 (third parties in room) |
| 8 | Establishment watchdog | **FIXED** (C3) | 15 s watchdog, generation-tagged, retries ×3 with fresh config; observed firing in gate logs; no deterministic swallowed-offer gate yet (gap G-b) |
| 9 | TURN credential refresh | **FIXED** (C5) | config re-fetched before EVERY connection attempt (+ HTTP retry ×3); no TTL-expiry end-to-end gate (gap G-c) |
| 10 | Zombie presence / uid supersede | **VERIFIED** (C6) | same-uid supersede in `maybe_adopt`; gate 11 (frozen receiver, same-uid replacement, resume + hash); gate 2 covers the different-peer flavor |
| 11 | One-time pairing | **VERIFIED** | gate 1 (transfer + second-claim-rejected burn check) |

## Part 2 — CLI failure modes (C-series)

### C1. Browser → CLI chunk overflow — **VERIFIED IN PRODUCTION (no deploy needed)**
The browser frames 64 KiB + 4-byte header = 65,540 bytes. TWO independent
limits broke this against the CLI: (a) Chrome refuses to send messages larger
than the peer's advertised `a=max-message-size`, and webrtc-rs never writes
that attribute, so Chrome assumed the RFC 8841 default of 64 K — 4 bytes too
small; (b) even when told to send, webrtc-rs's managed read loop has a
HARDCODED 65,535-byte buffer (`DATA_CHANNEL_BUFFER_SIZE: u16::MAX`) and the
oversized message kills the channel.
**Fix, entirely client-side:** the CLI appends `a=max-message-size:262144` to
the application m-section of every description it relays
(`advertise_max_message_size`), and uses DETACHED data channels
(`SettingEngine::detach_data_channels`) with its own 1 MiB read loop. The
backend also now serves `chunkSize: 61440` by default (belt-and-suspenders;
optional one-line env on the droplet — `FIL_CHUNK_SIZE=61440` — tightens prod
the same way, but is no longer required for correctness).
**Verified by:** gate 6 (61440 framing), gate 12 (a fixture backend serving
chunkSize 65536 — the exact production config — browser sends two 65,540-byte-
framed files, hashes match), and a LIVE run against the real production site:
headless Chromium on `https://filament.autumated.com` sent 4 MB to
`filament recv` through `api.filament.autumated.com`, hash identical,
10.3 MB/s (2026-06-06). The failure mode no longer occurs in the live system.

### C2. Route label disagreement — **VERIFIED** (with documented residual)
**Fix:** route now reads the agent's actual selected pair
(`get_selected_candidate_pair`) and classifies by ADDRESS, not candidate type:
relay → `relayed`; same address both ends (same machine) or both private
(RFC1918/4193, loopback, link-local, CGNAT-100.64/10 overlays) → `local`;
else `direct`. The answering side seeing its peer as prflx no longer flips the
label, and the badge's actual promise ("bytes never leave your network") is an
address property.
**Verified by:** unit `route_address_classification`; gate 1 (local detected,
no false relayed); gate 10 (`route: relayed` under relay-only policy).
**Residual:** on a multi-homed host with a PUBLIC IP on its NIC running BOTH
peers (our droplet test topology), ICE may select different interface
addresses per side and the ends can report local/direct asymmetrically — each
end is reporting its own selected pair truthfully. Across two distinct
machines the labels agree.

### C3. No establishment watchdog → infinite "connecting" — **FIXED**
15 s watchdog per connection attempt (`net::WATCHDOG_SECS`), generation-tagged
so stale timers from superseded attempts are ignored, → teardown + fresh
attempt (fresh ICE config, C5) ×3 → honest failure. Gap G-b: no deterministic
gate swallows an offer yet; the path is observed in real gate logs whenever a
peer is busy/frozen.

### C4. Transient drops were fatal — **VERIFIED**
`disconnected` → 6 s grace + `restart_ice()` (impolite side); `failed`/grace
expiry → full reconnect attempts; peer socket death → 120 s rejoin window with
partials parked on disk; senders re-offer unfinished transfers with
`resume: true` on every new channel.
**Verified by:** gate 2 — receiver kill -9 at ~11 MB of an 80 MB transfer, a
replacement receiver joins, resumes from the `.part`, hashes match, both exit 0.

### C5. Stale TURN credentials in long-lived processes — **FIXED**
Config (ICE servers incl. expiry-stamped TURN HMAC creds) is fetched fresh
before EVERY connection attempt — initial, retry, supersede — with 3× HTTP
retry so an API blip can't kill a session. There is no cached-at-startup
credential anywhere left to go stale. Gap G-c: no end-to-end gate ages a
credential past its TTL (would need a >TTL-long test run or a short-TTL
backend fixture).

### C6. Reconnecting peer ignored (no uid supersede) — **VERIFIED**
`maybe_adopt`: a peer-joined carrying the SAME uid as the current link
replaces it (mark old closed, spawn teardown, fresh connect, transfers
re-offered with resume). **Verified by:** gate 11 — receiver SIGSTOPped
mid-transfer (socket alive, lease alive), replacement with the SAME uid
(`FILAMENT_UID` test hook) joins, sender logs "superseding old link", resume
completes, hash matches. Gate 2 covers the different-uid replacement flavor.

### C6b. Live signaling reconnect must not tear down a flowing link (#28) — **VERIFIED**
The WebRTC data channel is INDEPENDENT of the signaling socket, so a peer's
socket reconnect mid-transfer must not kill the live channel. #28 has two
triggers on the CLI side, both now closed (the browser keep-connected half is
a separate change, commit `a55e494`):

- **Supersede trigger** (`maybe_adopt`, ~1161): the reconnect arrives as a new
  sid carrying the same uid. If the existing link is still flowing
  (`link_flowing` — `idle_ms()` below `FILAMENT_ADOPT_ACTIVE_MS`, default 3s),
  the reconnect is cosmetic; KEEP the old link ("keeping active link") instead
  of superseding. A frozen-alive peer (gate 11) stops stamping activity, reads
  idle, and still supersedes. **Verified by:** gate 11b.

- **peer-left trigger / DEFERRED DROP** (`on_peer_left` + `reap_deferred`): the
  server fires `peer-left` for the OLD sid while the channel stays alive.
  Dropping unconditionally killed the transfer; the naive "skip drop if
  flowing" guard hung gate 2 (a hard-killed peer reads flowing for a beat
  before DTLS notices, so swallowing its one-shot peer-left strands the
  sender). Instead: on peer-left for a flowing link, stash the payload in
  `deferred_left` and re-check each main-loop tick (`reap_deferred`, hooked
  after every `sess.tick`). Once the link goes idle past the threshold OR its
  channel is dead (`idle_ms()==u64::MAX`), re-inject the stored peer-left with
  a `__fil_force_drop` marker so the normal handler drops it then (opening the
  rejoin window). A live reconnect never goes idle → the transfer finishes on
  it → the idle link is reaped harmlessly. `roster.remove` stays immediate;
  only the LINK drop is deferred. `drop_link` clears `deferred_left` (invariant:
  it only holds live links), so a supersede of a deferred sid leaves no stale
  blocker. The adoption gate treats a deferred-active slot as claimable
  (`active_deferred`), so a DIFFERENT-uid replacement (gate 2) still takes over
  during the deferral window instead of being squatted out. **Verified by:**
  gate 11c (A/B: `FILAMENT_TEST_INJECT_PEER_LEFT` synthesizes the peer-left for
  the active sid mid-stream without touching the channel; `FILAMENT_TEST_NO_DEFER`
  proves the baseline drops it and the transfer dies). Side effect: a receiver
  now defers the sender's link on NORMAL completion too, reaping ~one threshold
  later before its clean exit (bounded ~3-5s, exits 0; measured).

### C7. Resume trusted name+size — silent corruption — **VERIFIED**
`file-offer` now carries `head`: sha256 of the first 256 KiB. The receiver's
`.part.meta` sidecar stores `{size, head}`; resume requires size match AND
head match (when both sides have one — legacy peers fall back to size-only).
Mismatch → truncate, restart from 0, tell the user. The BROWSER sender ships
`head` too (`webrtc.js headHash`), so browser→CLI resumes are protected.
**Verified by:** gate 3 (planted wrong-content partial → "different content"
→ restart → hash match) and gate 2 (genuine partial → resumed → hash match).
Full per-chunk integrity remains ROADMAP (this guards the resume seam, not
in-flight corruption, which DTLS/SCTP already checksum).

### C8. Throughput — **C8a VERIFIED · C8b ROADMAP**
(a) Backpressure is now event-driven: one `buffered_amount_low` subscription
wakes all parked senders; `on_close` also notifies so a sender parked on a
dying channel errors out instead of leaking. Gate 9 enforces a ≥8 MB/s
loopback floor (observed 10–17 MB/s).
(b) The order-of-magnitude fix is the QUIC transport for CLI↔CLI behind the
existing `Transport` trait — ROADMAP, not a defect. Do not market speed until
it lands.

### C9. Receiver idle-exit dropped human-paced sends — **VERIFIED**
The receiver's lifetime is now tied to the peer connection: it stays as long
as the sender is connected, exits when the peer leaves (or runs forever with
`--keep-open`). **Verified by:** gate 6 — browser sends file A, waits 5 s,
sends file B; CLI receives both and exits cleanly on tab close.

### C10. `process::exit` in stream tasks — **FIXED**
Stream tasks emit `Ev::TransferDone` / `Ev::TransferFailed` through the main
loop; failures leave the transfer pending for re-offer (resume) instead of
killing the process; temp spools are cleaned on the single exit path.

### C11. Blocking file I/O on the async runtime — **FIXED**
Receive path is `tokio::fs` + async `BufWriter` end to end (create/append/
write/flush/rename). Send-side reads remain std (chunk-sized, sequential —
revisit with QUIC speeds).

### C12. No stable device identity across invocations — **VERIFIED (shipped in 0.2.0)**
The persistent-pairing layer landed: `--remember` exchanges a pair secret
END-TO-END over the DataChannel; presence via `subscribe` with hashed
channels; `--to <device>` resolves by identity; `filament introduce A B`
vouches two known devices to each other over C20-verified links; per-install
`device.id` keeps a sender from adopting its own daemon (presence-channel
scope only — room loopback still works). **Verified by:** gate 14 plus the
live 3-device introduce flow (hub pairs B and C, introduces them, B sends
`--to deviceC` with no code ever exchanged between them, proof verifies as
'deviceB', hash match).

### C13. Peer selection — **VERIFIED** (enhancement tracked under C12)
The failure modes — a receiver wedging itself on another idle receiver, and a
sender delivering to the wrong device — are fixed and gated: `--to <name>`
filters by display name (gate 7: two receivers + a bystander, file lands only
in bob's dir), and same-role CLI peers never adopt each other (uid
`cli-s-*`/`cli-r-*` prefix check). What remains is an *enhancement*, not a
defect: identity-based addressing (pick a device, not a name substring),
which arrives with C12's pairing layer. Until then an idle browser in the
auto-room can occupy an unfiltered receiver — use `--to`/`--code` to
disambiguate, as documented.

### C14. Code claim auto-accepted without consent — **VERIFIED**
Claiming a code no longer implies accepting arbitrary files. Acceptance now:
`-y`, OR a resume continuing a partial we already accepted (head-checked), OR
an interactive prompt naming the sender and the file. No tty + no `-y` →
decline with a hint. **Verified by:** gate 8 (no-tty decline; sender exits
cleanly) and gate 1 (`-y` path).

### C15. No PAKE — active signaling-server MITM — **ROADMAP (security)**
Unchanged, applies to the web app equally; DTLS protects against passive
observers only. The spoken code is ideal SPAKE2 input; binding its derived key
to the DTLS cert fingerprints is the design. Until then this is a disclosed
limitation — never claim "the server can never read files" beyond the passive
case.

### C16. Distribution — **VERIFIED (Linux/macOS/Windows shipped); winget PR = operator step**
Release **cli-v0.1.0 is published** (GitHub Actions, run 27075331708): four
platform binaries (linux-musl static, macOS arm64, macOS x86_64 cross-built on
arm64, Windows MSVC), SHA256SUMS, and build-provenance attestations. Verified
end-to-end against the LIVE release:
- `curl -fsSL https://filament.autumated.com/install | sh` downloads,
  checksum-verifies, installs, and the installed binary completed a real
  transfer through production.
- `filament update`: a 0.0.9 build detected 0.1.0, downloaded, verified the
  checksum, and atomically replaced itself.
- Homebrew tap (Abdk4Moura/homebrew-tap) pushed with real hashes +
  `Formula/filament.rb` committed in-repo; `cargo publish --dry-run` clean.
- winget manifests rendered with the real Windows-zip SHA and schema-validated
  (`packaging/winget/0.1.0/`). The only remaining step is the PR to
  microsoft/winget-pkgs — an external submission under the maintainer's
  identity, run `packaging/release-followup.sh cli-v0.1.0 --pr` with operator
  consent. Gap G-e (macOS/Windows never built) is **closed** — both built and
  released this run.

### C17. Never run against production — **VERIFIED (2026-06-06)**
- Hermetic relay: gate 10 — local coturn, relay-only ICE policy, transfer
  completes, `route: relayed` reported.
- Live production: CLI↔CLI through `api.filament.autumated.com` — direct
  (8.3 MB/s, `route: local`/`direct`) and forced `--relay` through the
  droplet's coturn (5–7 MB/s, **`route: relayed` on both ends**, sha256
  verified). TURN ephemeral credentials, the Cloudflare tunnel, and the :3478
  relay all exercised end to end.

### C18. Single-link CLI wedges multi-peer rooms — **OPEN (fix in progress)**
Found by the maintainer on a real network: browsers are MESH peers (they
connect to every room member), but the CLI holds ONE link and ignores signals
from everyone else. With a CLI + >=2 browsers in a room, the unanswered
browsers sit at "connecting" forever, retry storms tear down and re-offer,
and the room degenerates into nobody-connects. **Fix:** multi-link (browser
parity): a links map keyed by sid; every offer gets answered politely; one
peer is the active transfer target; per-link trust/state. Also the
prerequisite for the daemon (C19), pairing-while-paired, and introductions.
**Verify with:** gate: CLI + two headless browsers in one room, all three
pairwise connections reach connected, transfer still completes.

### C19. Daemon (`filament up`) — **VERIFIED (shipped in 0.2.0)**
Implemented per the locked design: joins NO room (presence subscriptions
only — invisible to strangers; the gate asserts no "listening in room" line);
accepts solely fingerprint-verified known devices, silent-declines everything
else; receive ledger (`up.log`), pidfile, SIGTERM-clean exit; `status`/`down`
manage it; `up --install` writes a systemd user unit (no hand-rolled forks).
**Verified by:** gate 14 (pair → up → `--to` send: identity verified,
room-less, hash match) and the live 3-device flow. Remaining hardening from
the assessment, tracked open: config caps (max size / daily quota /
free-space floor), per-device auto/ask policy, desktop notifications,
`devices revoke` (gap G-g).

### C20. pair-proof not bound to the channel — **VERIFIED (shipped in 0.2.0)**
Implemented: `proof2 = HMAC(secret, prover_uid | sorted uids | sorted DTLS
cert fingerprints)` — fingerprints parsed from the exchanged SDP. A channel
MITM'd by anyone, the signaling server included, has different fingerprints,
so verification fails and auto-accept refuses. **Verified by:** gate 14 (the
daemon's accept requires it) + tamper test (corrupted stored secret yields
zero verifications and silent decline). Closes active-MITM for known devices
without full PAKE; the original design note follows for the record.
Original: include both DTLS certificate fingerprints (already present in the
relayed SDP) in the HMAC: a MITM'd channel has different fingerprints, the
proof fails, auto-accept refuses. Closes active-MITM for known devices
without full PAKE; C15 remains for code-pairing and the web app.
**2026-06-07 — the browser half (Phase A).** Maintainer diagnosed the
iPad↔CLI reconnect failure as one-sided acknowledgement, and that was
literally true: the CLI had `daft-gibbon` in its device store and subscribed
its channel; the browser had received the pair-keep secret and DROPPED it
(no handler). The browser now persists secrets (localStorage), re-subscribes
on every socket-up, answers `known-peer` introductions room-lessly, and
both sends and verifies proofs (`frontend/src/lib/devices.js`, crypto.subtle).
Cross-impl parity pinned to an openssl-derived vector on both sides
(`proof_matches_browser` unit test ↔ Node check). Gate 16 verifies the whole
chain: claim+remember → secret stored → fresh CLI `--to` in an ISOLATED room
finds the browser via the channel alone, transfers with no code.

### C21. Paired recv treated a vanished sender as instantly fatal — **FIXED (gate 15)**
Found live by the maintainer: claim a code, connect, the sender's phone opens
its file picker → Android suspends the tab → socket dies → `peer-left` → the
CLI bailed `sender left before sending anything` while the human was still
choosing a file. **Fix:** never instant-fail a paired peer-left; hold a
rejoin window (their client auto-rejoins on refocus; supersede/adopt
completes recovery). Windows are *informed* via the new `brb`/`back` control
messages (see CONTRACT.md): a declared absence gets its promised ttl
(picker = 120 s), an unannounced vanish gets 45 s — shorter than the old
blind 120 s. While a peer is `brb`: gentler messaging, disconnect grace
extends to the declared window, and the watchdog stops burning retry
attempts against a suspended tab. Bonus from the same field report: a
listening `recv` now claims a code typed straight into it (the first thing
the user actually tried). Gate 15 verifies the hold-the-line path
deterministically; the browser-driven `brb` path is gap G-h (needs a
visibility-state mock in Playwright).

### C22. Two stdin readers raced for one terminal — **FIXED**
The remote-input claimer and the consent prompt both read stdin; whichever
grabbed the line first won, so a typed `y` could vanish into a transfer
stream. One owner now: a single raw-mode reader (`stty cbreak`, RAII guard
restores the tty) emits `StdinLine` events; consent questions queue
(`pending`) and answers route by a per-process `consent_token` a remote peer
cannot forge. Single-keypress y/n — no Enter needed, answer echoed (`↳ y`).

### C23. Ghost questions + duplicate streams into one `.part` — **FIXED**
A superseded link could leave its consent question on screen (answering it
did nothing) and a re-offer could open a second stream into the same `.part`
mid-write. Questions are purged when their link dies; one stream per `.part`
enforced; finalize errors are non-fatal (the file is re-offerable).

### C24. Create-code zombie mints — **FIXED + MEASURED (web/server)**
Field report: a phone tab alive "for a few minutes" mints codes nobody can
claim. Telemetry (server `TEL` lines + browser beacons) measured the cause:
the hidden tab's socket dies ~5 s after hiding and recovery takes ~4.3 s
after refocus — the mint raced the dead socket. Fix: client waits for
socket-up and auto-retries once; server refreshes the creator's lease at
`pair-create`; `peek_pair` diagnoses stale claims (`existed`/`creator_alive`).
The same instrumentation later proved the rejoin-belt (#14) and second-wind
(#13) web fixes live.

### C25. Questions could be invisibly declined — **FIXED**
A question rendered only as a sticky line could be missed entirely, and a
stray Enter (queued before the question appeared) declined it silently —
a destructive default. Questions now print as permanent lines too, empty
input never declines, and keystrokes buffered before the question was shown
(300 ms guard) are discarded instead of consumed as answers.

### C26. Peer presence invisible in the CLI — **FIXED**
The browser shows an amber "away" tile; the CLI only had transient dim
notes. Every link now tracks a `Presence` (connecting/ready/away/
reconnecting) and each state change prints a static colored ROSTER line —
all peers side by side, the changed one carrying the note:
`✓ daring-wombat   ● deft-gibbon  away — holding the line`. Glyphs:
`✓` ready/back/recovered (green), `●` away (amber), `◌` reconnecting
(amber), `○` left (dim). One line per transition — readable scrollback
history, no repaint tricks; "recovered" only fires on a link that was
previously up (presence-gated, not attempt-gated).

### C27. Trust handshakes were one-way streets — **FIXED (gate 16)**
Two maintainer-diagnosed asymmetries, same disease as C12's:
(1) the browser auto-stored any pair-keep secret — a silent trust grant the
receiving human never approved. Now a consent banner asks ("remember /
not now") and the answer flows back as `pair-keep-ack`; a declined sender
REMOVES its stored half instead of waving at a dead meeting point forever.
(2) a prover whose proof failed never learned it — it kept saying "oh, I
know you" to a peer that never met it (cleared store, re-paired browser).
`pair-proof-ack {ok:false}` tells it; the CLI drops the link's expectation
and says "doesn't recognize this device — re-pair with --remember".
Bonus fix found live mid-build ("connecting and then gotcha… it
disappears"): every `welcome` wiped ALL links and rebuilt from the ROOM
roster — channel-introduced known devices are in no room roster, so the
rejoin belt's second welcome erased them moments after `known-peer` created
them. Welcome now preserves channel peers and re-raises subscriptions.
Gate 16 covers all three: consent-gated store, channel rendezvous, decline
purge.

### C28. Presence was fire-and-forget — **FIXED**
Field report: `filament up` couldn't see a known browser until a page
reload. Third instance of one disease: an emit dying in a half-open socket
(join → rejoin belt #14; create-code → C24; now `subscribe`). The channel
registry is sid-keyed, and `known-peer` is only emitted AT subscribe time —
one lost subscribe = mutual invisibility with no retry path. The cure is a
system, not a patch: **assert presence, verify the assertion, reconcile
periodically.** (1) `subscribe` is now ACKed (socket.io ack = handler
return); the browser re-emits up to 3× on a missing ack. (2) The browser
re-asserts channels every 45 s and on every tab-visible — and since the
server re-introduces BOTH parties on every subscribe, a daemon that
exhausted its dial budget against a frozen tab gets re-told within one
tick: self-healing, no reload, no restart. (3) CLI flavor: every `welcome`
(fresh sid) re-subscribes in all three subscribing loops (up/recv,
send --to, introduce) — `up`'s subscribe-once-at-startup had the same hole.

### C29. Pairing required pretending to transfer a file — **FIXED (gate 17)**
Maintainer: "I should be able to simply add a device and remember it
without having to pretend to send something." Two additions:
`filament pair [code] [--name X]` — a first-class ceremony: mint or claim,
connect, hand the secret over the encrypted link (C27 consent applies),
confirm mutuality, exit. And `filament up` became a SESSION (the CLI's
browser tab): with a terminal attached, type a code to pair (remember
ceremony runs in-session, device usable immediately — channel raised
live), `pair` mints a code, `devices`/`forget <name>` manage petnames.
Initiation discipline (no double secrets): the code CREATOR initiates;
a claimer waits 3 s (browsers never initiate), then takes over. Headless
`up --install` (no tty) is unchanged — stdin-free. Gate 17 asserts the
sharp invariant: after the ceremony, both stores' channel ids are EQUAL
(one mutual secret, not two halves of nothing).

### C30. The lost-emit disease class — **PHASE 1 VERIFIED (gate 19)**
Design: `design-c30-convergent-session.md`. Five field incidents shared one
shape — edge-triggered session emits with no convergence loop. Phase 1 lands
the cure: a `sync` protocol (server ensures room/channels/lease idempotently,
acks + emits its digest) and per-client session modules (browser
`lib/session.js`, CLI `session.rs`) holding desired-vs-confirmed state with
ONE repair loop (5 s tick / socket-up / tab-visible; invalidate on fresh sid).
The five belts (#14 rejoin, C28 retries+reconcile+debounce, the C24 lease
refresh client half, the CLI welcome re-subscribes ×3) are dissolved into it.
ALL CLI session-state emits flow through the module's loss shim
(`FILAMENT_TEST_EMIT_LOSS`/`_SEED`, deterministic xorshift), which is what
gate 19 (gate L) attacks: seed 16 drops BOTH processes' join+subscribe; the
rendezvous succeeds only through repair. The choreography found two real
bugs BEFORE becoming a gate: (1) `send --to`'s full-deadline blocking read
starved the tick — a dropped subscribe could never be repaired and the wait
never succeeded; (2) both client modules initially treated a fast reconnect
as still-confirmed (fresh sid, dead subscriptions) — fixed with
invalidate-on-welcome. **Phases 2+3 LANDED same day:** the digest carries
the room roster (welcome-shaped, deterministic sort-cap-32) and both
clients reconcile it — adopt a peer we never heard join, drop a room peer
absent from two consecutive digests (channel links exempt); recv's
quiet-exit is also satisfied when the digest says the room is empty (the
G-k class, answered level-triggered). Link mini-sync: every open link
exchanges {type:"state", transfers, trusted, away} every ~10 s — a sender
re-offers (resume) when it believes a transfer complete that the peer
holds short (the lost-END repair), a secret-holder re-proves once on
trusted:false, and any state ping clears a stale away-mark. All additive;
old clients ignore unknown types and digests without `peers`.

## Part 3 — Failure modes hit and fixed during development (F-series)

### F1. SCTP outbound frame overflow — **FIXED + VERIFIED**
64 KiB + 4 > 65,535. Chunk reduced to 60 KiB (`net::MAX_DC_PAYLOAD`); C1 is
the same bug's server-config mirror. Every gate exercises the framing.

### F2. rustls dual-provider panic — **FIXED + VERIFIED**
reqwest brought a second rustls crypto provider next to webrtc's ring; rustls
panics rather than guess. `install_default(ring)` is the FIRST line of main —
the fix is order-dependent; any new TLS-touching dependency can re-break it.

### F3. Wait-for-peer deadline fired mid-transfer — **FIXED**
The 600 s claim deadline now applies only while no peer is linked.

### F4. Sender raced the receiver's goodbye — **FIXED + VERIFIED**
`TransferDone` events + all-done checks in `peer-left`/`failed` handlers.
Gate 1's clean-exit assertion holds the line.

### F5. Browser declared 'complete' before the SCTP buffer drained — **FIXED + VERIFIED**
Found BY gate 6: the browser marked a send complete with ~1 MB still buffered;
closing the tab (which "complete" invites) truncated the receiver's tail.
`webrtc.js _streamFile` now drains `bufferedAmount` to 0 after `file-end`
before reporting complete. A real product bug in the web app that two
independent implementations + adversarial gates surfaced — exactly why the
CLI's tests exist. Gate 6 verifies (browser closes immediately after
'complete'; CLI hashes both files).

### F6. A failed signal application killed the process — **FIXED + VERIFIED**
webrtc-rs's `set_remote_description` internally restarts ICE when remote
credentials change; mid-gather that returns "ICE Agent can not be restarted
when gathering", which propagated through `?` and exited the CLI. Signal
errors are now log-and-recover (the watchdog/grace machinery owns dead
negotiations) — the browser's catch-and-log signal queue, CLI flavor.
Surfaced by gate-6/gate-5 overlap traffic; the suite passes twice
consecutively since.

### F7. coturn 403s loopback peers — **test-infra note**
Hermetic relay tests need `--allow-loopback-peers` on coturn (both peers are
127.0.0.1 there). Production coturn must NOT carry that flag.

### F8. Inline pc.close() deadlocked the event loop — **FIXED + VERIFIED**
Found BY gate 11: superseding a link awaited `pc.close()` inline in the event
loop, and webrtc-rs's close can block on network teardown against a frozen
peer — freezing the entire process (no watchdogs, no signals, nothing).
Fix: `mark_closed()` (atomic, synchronous — callbacks silenced immediately) +
the actual close spawned off-loop. Same hazard class: HTTP fetches from the
loop now carry an explicit 10 s reqwest timeout (reqwest has NONE by
default). Rule distilled: the event loop may never await anything whose
completion depends on a remote peer behaving. Gate 11 verifies.

## Part 4 — Standing test gates (`cli/tests/gates.sh`)

> **Two tiers (2026-06-08).** The suite splits by *kind* of determinism:
> - **CORE** (`SKIP_BROWSER=1 ./gates.sh --with-relay`) — every gate
>   deterministic BY CONSTRUCTION (CLI-only, seeded loss, fixture-pinned).
>   This is the commit/merge gate and must be **100%**; one green never proves
>   it, but you can *reason* it cannot flake.
> - **BROWSER-INTEROP** (gates 5, 6, 12, 13, 16) — real headless Chromium +
>   real WebRTC ICE/DTLS. Timing-dependent BY NATURE; cannot be proven 100% by
>   sampling on a contended host (prod containers + coturn + monitors + an
>   80 MB transfer all share the box). Best-effort here; meant for a quiescent
>   CI runner. The eventlet fixture (matching prod, vs the threading+Werkzeug
>   dev server) made gates 5/12/13/16 reliable; **gate 6 still flakes** — its
>   tab has the longest exposure (two sequential sends + a 5 s gap) and hits a
>   transport-churn event most often. The killer is the browser's socket
>   churning mid-transfer (`✓ route: local` → `○ left` repeated), NOT the
>   stale-answer glare (which self-recovers). Real fix: browser↔CLI resume
>   across a browser reconnect — tracked as a product bug (G-i / task #28),
>   NOT a test knob. (The CLI-side #28 halves are now closed — see C6b: a
>   receiver deferring the sender's link on a flowing peer-left is exactly this
>   churn case, so the deferred drop *plausibly* softens gate 6. UNVERIFIED for
>   the browser path — gate 6 is browser-interop / full-suite only and was not
>   run here; its row and status are unchanged.)
>
> **Determinism rule (2026-06-08).** A flaky gate has a hidden dependency on
> timing or load; the fix is to remove the dependency, never to retry (a retry
> hides non-determinism, it doesn't eliminate it). Three load-induced flakes
> were rooted out under deliberately-loaded "so-so" conditions:
> - **claim rate-limit** ('slow-down'): the suite owns its fixture backend
>   with `FIL_CLAIM_LIMIT` pinned sky-high — the 5/min limit is a prod
>   security control, but in a test it makes rapid claims a timing lottery.
> - **throughput floor** (8 MB/s): an absolute MB/s pass/fail *is*
>   non-determinism (it encodes machine speed). Replaced by a correctness
>   assertion (80 MB completes + hash) under a generous hang ceiling (240s);
>   speed is logged, never asserted.
> - **browser glare** (gate 6/12, the G-i flake): a CPU-starved headless
>   Chromium dropped its socket → reconnected → triggered a stale-answer
>   negotiation glare. `FIL_PING_TIMEOUT=120` on the fixture keeps a briefly-
>   starved tab connected, removing the trigger. Real users aren't CPU-
>   starved, so prod keeps the 20s default.

| Gate | Covers | Status |
|---|---|---|
| 0 unit tests (politeness, meta, head-hash, paths, route addrs, sanitization) | #1, C2, C7 | green |
| 1 one-time code transfer + clean exits + code burn + route sanity | #11, C2, F4 | green |
| 2 chaos: receiver kill -9 mid-transfer → replacement resumes, hash match | C4, C5, C6, C7 | green |
| 3 corruption guard: planted wrong-content partial restarts from 0 | C7 | green |
| 4 directory tar + stdin pipe round-trip | core | green |
| 5 CLI → browser (Playwright, production frontend bundle) | interop | green |
| 6 browser → CLI ×2, human-paced, tab-close after 'complete' | C1, C9, F5, F6 | green |
| 7 `--to` selection with bystander receivers | C13, #7 | green |
| 8 consent: no tty + no `-y` declines | C14 | green |
| 9 throughput floor ≥8 MB/s | C8a regression | green |
| 10 TURN relay via coturn container, `route: relayed` | C2, C17 | green (needs docker) |
| 12 browser with PROD config (65536 framing) → CLI | C1 | green |
| 11 frozen receiver superseded by same-uid replacement, resume | C6, F8 | green |
| 11b active same-uid link survives a live reconnect (kept, no supersede), hash match | C6b, #28 | verified standalone on 8091; integrator to confirm in-suite |
| 11c flowing link survives a peer-left (deferred drop), transfer completes, no supersede — A/B (NO_DEFER baseline fails) | C6b, #28 | verified standalone on 8091 (3×, A/B); integrator to confirm in-suite |
| 13 multi-link: CLI + two browsers, transfer with bystander, nobody wedges | C18 | green |
| 14 daemon: pair `--remember`, verified identity, room-less `up` receive | C19, C20, C12 | green |
| 15 paired recv holds the line on sender vanish, fails honestly after window | C21 | green |
| 16 known-device rendezvous: consent-gated pair-keep store, `--to` finds the browser cross-room via channel (no code), decline purges the sender's half | C12, C20 web half, C27 | green |
| 17 pair ceremony: no file, both exit clean, both stores' channel ids EQUAL (one mutual secret) | C29 | green |
| 18 recv quiet-exit when peer-left is dropped at the delivery boundary (test hook), exit 0, hash match | G-k | green |
| 19 gate L: 50% session-emit loss (seed 16 drops both sides' join+subscribe) — rendezvous must converge via repair | C30 | green |
| 18 recv quiet-exit when peer-left never arrives (SIGSTOP'd sender keeps its lease, link dies via grace, quiet branch fires, exit 0) | G-k | green |
| — live prod direct + `--relay` | C17 | run manually 2026-06-06, both green |

**Known coverage gaps (tracked, not hidden):**
- **G-a** soft-blip recovery (ICE `disconnected` → recovers within grace) has
  no deterministic local simulation; needs netem/SIGSTOP choreography.
- **G-b** watchdog lacks a swallowed-offer fixture peer.
- **G-c** TURN TTL expiry needs a short-TTL backend fixture.
- **G-j** known-device browser half (gate 16) proves Chromium and the
  CLI→browser direction only. Untested: Safari/WebKit (the iPad — crypto.subtle
  and fingerprint parsing should hold, but Private Browsing silently refuses
  localStorage: the secret won't persist, console.warn flags it) and the
  reverse direction (browser sending to a `filament up` daemon, where the
  daemon must verify the BROWSER's proof to auto-accept).
- **G-k — VERIFIED (gate 18)** recv's clean exit no longer depends on `peer-left`
  DELIVERY. Originally observed once (gate 6 under load, 2026-06-07) — both
  transfers completed, hashes matched, the browser closed, but the peer-left
  event never reached recv (no `○ left` line) so it idled to timeout instead of
  exiting "done (2 files)"; same emit-mortality disease as C28, inbound flavor.
  **Fix:** the recv event loop now ticks on a 2 s `tokio::time::timeout`
  wrapping `next_ev` (call-site only — the `up`/rejoin paths are untouched),
  and a fallback quiet-check runs every iteration: if `completed > 0 &&
  !keep_open && by_sid.is_empty() && conn.links.is_empty() && pending.is_empty()`
  holds quietly for the quiet-exit window (10 s default, overridable via
  `FILAMENT_QUIET_EXIT_SECS` — the gate-18 test knob, mirroring
  `FILAMENT_REJOIN_SECS`), recv prints the same `done (N files).` line the
  peer-left path emits (preceded by a dim "(peer-left never arrived — exiting
  on quiet)" note) and disconnects cleanly. Any attaching link / new question
  resets the timer.
  **Verification (gate 18):** a sender completes a one-file transfer, then is
  SIGSTOP'd the instant it logs `done.` (flush precedes that print, so all
  bytes + file-end are already delivered) — its frozen socket keeps the server
  lease alive, so peer-left is never emitted, while its peerconnection goes
  silent. recv (`FILAMENT_QUIET_EXIT_SECS=3`) watches its link die through the
  disconnect→grace→retry teardown, then the quiet branch fires: recv exits 0,
  its log carries "(peer-left never arrived — exiting on quiet)" and
  "done (1 file)", and the received hash matches. The teardown latency
  (6 s grace + 3×15 s watchdog retries before links empty) puts the gate's
  walltime around 50–90 s under `timeout 120`.
- **G-i** stale-answer glare can strand a link through all 3 retries: observed
  once (gate 12, 2026-06-07, machine under load) — browser socket dropped
  pre-link, its stale answer hit the fresh link ("invalid transition from
  stable applying remote answer", F6 recovered), then every rebuild ran
  against a browser already wedged waiting; 19/19 on re-run. Needs a
  deterministic delayed-answer fixture to decide whether re-establish should
  also bump some glare-breaking state (e.g. force a new uid-tiebreak round).
- **G-e** macOS/Windows: the release workflow's macOS job has never executed
  (runs on first `cli-v*` tag); Windows is not built (part of C16).

A dockerized "dummy machines" topology (two isolated bridge networks forced
through coturn) was considered and intentionally NOT built: the `--relay` flag
(relay-only ICE policy) + a host-net coturn yields the same relay-path
coverage hermetically with far less harness. If CI later needs to run where
the relay can't bind host network, revisit with a compose file then.

---

*Cross-references: protocol contract in [`../CONTRACT.md`](../CONTRACT.md);
browser failure modes in [`resilience.md`](resilience.md); CLI usage in
[`../cli/README.md`](../cli/README.md).*
