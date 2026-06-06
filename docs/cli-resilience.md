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
Playwright, relay gate via a local coturn container). Last full run:
**13/13, twice consecutively, 2026-06-06**, plus live-production direct and
forced-relay transfers through `api.filament.autumated.com`.

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
| 10 | Zombie presence / uid supersede | **FIXED** (C6) | same-uid supersede in `maybe_adopt`; rejoin window covers socket death (gate 2 covers replacement-peer; same-uid rejoin lacks a dedicated gate — gap G-d) |
| 11 | One-time pairing | **VERIFIED** | gate 1 (transfer + second-claim-rejected burn check) |

## Part 2 — CLI failure modes (C-series)

### C1. Browser → CLI chunk overflow — **VERIFIED**
The browser framed 64 KiB + 4-byte header = 65,540 bytes; SCTP's default max
message is 65,535. Chrome tolerates it between browsers; webrtc-rs doesn't.
**Fix:** `/api/config` now serves `chunkSize: 61440` (the browser honors it at
runtime, no rebuild needed) and the CLI clamps to 60 KiB on send.
**Verified by:** gate 6 (browser → CLI, hash-compared).
**Residual:** a browser tab holding a cached pre-deploy config can still frame
64 KiB for up to ~10 minutes after the backend deploy (config refreshes every
10 min and on every reconnect); a transfer attempted in that window against a
CLI fails and succeeds on retry. Accepted as a transient deploy window.

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

### C6. Reconnecting peer ignored (no uid supersede) — **FIXED**
`maybe_adopt`: a peer-joined carrying the SAME uid as the current link
replaces it (close old, fresh connect, transfers re-offered). Socket-death +
*different*-uid replacement is gate-2-verified; the same-uid rejoin path lacks
its own gate (gap G-d).

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

### C12. No stable device identity across invocations — **ROADMAP**
A fresh uid per run is by design until the persistent-pairing layer
(E2E-exchanged pair secret, `subscribe` presence, KNOWN DEVICES). That feature
also upgrades C13's `--to` from name-matching to identity, and enables daemon
auto-accept-from-trusted-only. Not a defect: resume works without it (C7
guards the seam).

### C13. Peer selection — **MITIGATED, full fix ROADMAP (C12)**
`--to <name>` on both commands filters by display name (gate 7: two receivers,
`--to bob`, file lands only in bob's dir). Same-role CLI peers never adopt
each other (uid `cli-s-*`/`cli-r-*` prefix check) — a receiver can no longer
wedge itself on another idle receiver. Remaining: an idle *browser* in the
auto-room can still be adopted by an unfiltered CLI receiver; identity-based
selection (C12) is the real fix.

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

### C16. Distribution — **OPEN (release gate, not a runtime defect)**
Still dynamic-OpenSSL, no musl static build, macOS/Windows unbuilt/untested,
no release CI. Gates any public CLI announcement. First step: move
reqwest/rust_socketio onto rustls and add a musl + macos release workflow.

### C17. Never run against production — **VERIFIED (2026-06-06)**
- Hermetic relay: gate 10 — local coturn, relay-only ICE policy, transfer
  completes, `route: relayed` reported.
- Live production: CLI↔CLI through `api.filament.autumated.com` — direct
  (8.3 MB/s, `route: local`/`direct`) and forced `--relay` through the
  droplet's coturn (5–7 MB/s, **`route: relayed` on both ends**, sha256
  verified). TURN ephemeral credentials, the Cloudflare tunnel, and the :3478
  relay all exercised end to end.

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

## Part 4 — Standing test gates (`cli/tests/gates.sh`)

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
| — live prod direct + `--relay` | C17 | run manually 2026-06-06, both green |

**Known coverage gaps (tracked, not hidden):**
- **G-a** soft-blip recovery (ICE `disconnected` → recovers within grace) has
  no deterministic local simulation; needs netem/SIGSTOP choreography.
- **G-b** watchdog lacks a swallowed-offer fixture peer.
- **G-c** TURN TTL expiry needs a short-TTL backend fixture.
- **G-d** same-uid rejoin (supersede) lacks a dedicated gate (replacement-peer
  flavor is covered by gate 2).
- **G-e** macOS/Windows: nothing runs in CI for them yet (part of C16).

A dockerized "dummy machines" topology (two isolated bridge networks forced
through coturn) was considered and intentionally NOT built: the `--relay` flag
(relay-only ICE policy) + a host-net coturn yields the same relay-path
coverage hermetically with far less harness. If CI later needs to run where
the relay can't bind host network, revisit with a compose file then.

---

*Cross-references: protocol contract in [`../CONTRACT.md`](../CONTRACT.md);
browser failure modes in [`resilience.md`](resilience.md); CLI usage in
[`../cli/README.md`](../cli/README.md).*
