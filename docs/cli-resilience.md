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
**VERIFIED** (test exists and passed) · **N/A** (doesn't apply to the CLI).

---

## Part 1 — Parity matrix: the browser's 11 fixes vs the CLI

The browser earned these scars one by one (see `resilience.md`). The CLI
reimplements the client side, so each one must be re-accounted for:

| # | Browser fix | CLI status | Notes |
|---|---|---|---|
| 1 | Perfect negotiation / deterministic politeness | **VERIFIED** | `polite_role()` mirrors `politeRole()`; exercised by every CLI↔CLI and CLI↔browser test |
| 2 | Signal FIFO + candidate buffering | **VERIFIED** | single event loop serializes signals; `pending_candidates` buffers until remote description (`net.rs`) |
| 3 | Ghost tiles / late-callback guard | **N/A** | no UI to resurrect; process exit tears everything down |
| 4 | Chunk framing + shared backpressure | **VERIFIED** | `[u32 sid][payload]` framing; one transport, frames serialized per send |
| 5 | Fail-on-drop marks transfers terminal | **PARTIAL** | partials are kept on disk for resume, but see C4: the *process* treats any failure as fatal |
| 6 | Transient `disconnected` ≠ terminal | **OPEN** → C4 | |
| 7 | Don't trust stray signal senders | **VERIFIED** | signals filtered by the connected peer's sid; others ignored |
| 8 | Establishment watchdog | **OPEN** → C3 | |
| 9 | TURN credential refresh | **OPEN** → C5 | regression risk is the long-lived `--keep-open` daemon |
| 10 | Zombie presence / uid supersede | **OPEN** → C6 | server-side leases still protect the roster; client supersede missing |
| 11 | One-time pairing | **VERIFIED** | `pair-create`/`pair-claim` flows; code burn confirmed by test (second claim → `invalid`) |

## Part 2 — CLI-specific failure modes

### C1. Browser → CLI transfer likely fails on chunk size — **OPEN (suspected breakage)**

**Symptom (predicted).** A browser sending to `filament recv` stalls or errors
after accept; CLI→browser works fine.

**Cause.** The browser frames 64 KiB + 4-byte header = 65,540-byte messages.
SCTP's default max message size is 65,535 and webrtc-rs enforces it strictly —
it already rejected our *outbound* 65,540 frames; inbound handling is untested
and must be presumed broken. Chrome tolerates the overage between browsers,
which is why the web app never noticed.

**Fix plan (both ends, belt and suspenders).** (a) Serve `chunkSize: 61440`
from `/api/config` so browser senders stay under the limit (the browser
already honors the config value); (b) raise the CLI's accepted max via
webrtc-rs `SettingEngine` for tolerance of old cached frontends.

**Verify with.** Playwright: browser file-input send → CLI recv, hash compare.
This is the missing direction of the existing interop test.

### C2. Route label disagrees across ends — **OPEN**

**Symptom.** Loopback test: receiver printed `route: local`, sender printed
`route: direct` for the same candidate pair.

**Cause.** `Peer::route()` does two `get_stats()` passes and matches candidate
ids to types; on one side it evidently matches a prflx/srflx candidate and
falls through to `direct`. The browser's single-pass selected-pair logic is
the reference implementation.

**Fix plan.** Port the browser's logic exactly: find the transport's
`selectedCandidatePairId` first, fall back to `succeeded && nominated`, then
classify from that one pair's local/remote types in the same stats snapshot.

**Verify with.** CLI↔CLI loopback asserting both ends print `local`.

### C3. No establishment watchdog → infinite "connecting" — **OPEN**

The exact failure the browser fixed as #8: if signaling loses the offer (peer
suspended, message dropped), ICE never starts, never times out, never retries.
The CLI's 600 s wait-for-peer deadline does not cover a peer that joined but
never completed negotiation.

**Fix plan.** 15 s watchdog after `Peer::connect`; on expiry tear down and
recreate the peer with a fresh offer (and freshly fetched ICE config), retry
twice, then exit nonzero with a clear message. Same constants as the browser.

**Verify with.** A test harness peer that joins the room but swallows the
offer; assert retry then clean failure.

### C4. Any connection failure is fatal; transient drops kill the run — **OPEN**

**Symptom.** A WiFi blip mid-transfer prints `connection failed (partial files
kept for resume)` and exits. The browser survives this via #6 (grace timer +
`restartIce`) and resumes automatically.

**Cause.** `PcState("failed")` → `bail!`. `disconnected` is currently not even
distinguished.

**Fix plan.** Mirror the browser: on `disconnected`, start a 6 s grace timer
and have the impolite side `restart_ice()`; only on true `failed` (or grace
expiry) tear down — and then *retry the whole connection* (rejoin, re-pair is
unnecessary since the room persists) up to N times, re-offering unfinished
transfers with `resume: true`. The disk partials make this strictly easier
than the browser's version.

**Verify with.** Drop traffic mid-transfer (nft/tc or kill -STOP on the peer),
restore, assert auto-resume completes with matching hash.

### C5. Stale TURN credentials in a long-lived `recv --keep-open` daemon — **OPEN**

The browser's #9, reintroduced. `/api/config` is fetched once at startup; TURN
credentials are expiry-stamped HMACs (6 h TTL in prod). A daemon that has been
listening overnight hands dead credentials to every new connection → all
relay-dependent peers fail, LAN peers still work — the classic "works for me"
half-failure.

**Fix plan.** Refresh config every 10 minutes and before constructing each new
`Peer` (the CLI builds peers lazily, so per-peer fetch is nearly free).

**Verify with.** Unit-level: assert a fresh fetch happens per peer; live: a
daemon older than the TTL accepting a relayed transfer.

### C6. Reconnecting peer is ignored (no uid supersede) — **OPEN**

**Symptom.** Peer's network flaps; they rejoin with a new sid. The CLI logs
`ignoring extra peer` (single-peer guard) and is now wedged: its `Peer` points
at a dead sid.

**Fix plan.** When a `peer-joined` arrives with the *same uid* as the current
peer, replace the existing `Peer` (close old, connect new) — the browser's #10
client half. Combined with C4's retry this makes flaky-network behavior
match the web app.

**Verify with.** Kill and restart a CLI peer with a pinned uid; assert the
other side reconnects and resumes.

### C7. Resume trusts name+size — silent corruption possible — **OPEN**

**Symptom (predicted).** `report.pdf` (1 MB) half-received; sender later sends
a *different* `report.pdf` that happens to be 1 MB. Receiver offsets into the
new stream → a file that is half old bytes, half new, with no error.

**Cause.** `.part.meta` records only expected size; the offer carries no
content identity.

**Fix plan.** Sender includes `head: sha256(first 256 KiB)` in `file-offer`
(cheap, streamable); receiver hashes its `.part` prefix and only offsets on
match, else restarts from 0. Browser sender can adopt the same field
opportunistically (additive, backward compatible — receivers ignore unknown
fields today). Full per-chunk integrity remains the bigger backlog item.

**Verify with.** The corruption scenario above; assert restart-from-0 and a
correct final hash.

### C8. Throughput ceiling (~10–17 MB/s loopback) — **OPEN (accepted for v1)**

**Causes, compounding:** webrtc-rs SCTP pacing; 60 KiB chunks; 5 ms sleep-poll
backpressure in `DataChannelTransport::send_frame` instead of event-driven
`on_buffered_amount_low`.

**Fix plan.** (a) Event-driven backpressure (notify on buffered-amount-low) —
cheap, do first; (b) the real fix is the QUIC transport for CLI↔CLI (the
`Transport` trait exists for exactly this). Do not market speed before then.

**Verify with.** Loopback benchmark in CI printing MB/s; regression threshold.

### C9. Receiver exits 1.5 s after a batch — drops human-paced second sends — **OPEN**

CLI senders offer everything up front, so CLI↔CLI is safe. A *browser* user
who drags a second file after the first completes finds the CLI gone.

**Fix plan.** Default changes to: stay alive while the peer connection is
alive; exit when the peer leaves (already handled) or on Ctrl-C. The timer
heuristic remains only for `--once` semantics if we add that flag.

**Verify with.** Playwright: browser sends file A, waits 5 s, sends file B;
assert both received.

### C10. `std::process::exit(1)` in the stream task — **OPEN (debt)**

Skips temp-spool cleanup and the socket goodbye. Replace with an error event
through the main loop (`Ev::TransferDone` already exists; add an error
variant) so `send_cmd` can clean up and exit through one path.

### C11. Blocking `std::fs` I/O on the async runtime — **OPEN (debt)**

Chunk-sized writes through `BufWriter` are fine at current throughput; fix
alongside C8 (`tokio::fs` or a dedicated writer thread) or it will surface as
mysterious latency under QUIC speeds.

### C12. No stable device identity across invocations — **OPEN (by design until pairing layer)**

A fresh uid per run means peers can't recognize "same device, new process".
Resume works anyway (receiver keys on name+size — see C7 for the cost).
The persistent-pairing layer (E2E-exchanged pair secret + `subscribe`
presence) is the designed fix and unlocks `--to <device>` and daemon
auto-accept-from-known-devices.

### C13. Single peer, first-joiner-wins — **OPEN (v1 scope)**

On a busy auto-room the CLI may bind to the wrong device; there is no
`--to`/picker. Interim mitigation: prefer `--code` flows (deterministic).
Real fix arrives with C12's identity layer.

### C14. Code claim auto-accepts without confirmation — **OPEN**

Claiming a code is treated as consent (right default), but a mistyped code
that happens to match a stranger's live code receives *their* files into your
directory. Cheap fix: print `sender: <name>  files: <list>` and require Enter
unless `-y` — keeps the daemon path scriptable while closing the
wrong-room-key hole.

### C15. No PAKE — active signaling-server MITM is theoretically possible — **OPEN (applies to web app equally)**

DTLS is end-to-end against passive observers; a *malicious* signaling server
could MITM the handshake. The spoken one-time code is ideal SPAKE2 input:
derive a verification key from it and bind it to the DTLS certificate
fingerprints. Wormhole-grade security using UX we already have. Until then:
disclose honestly (HN will ask), do not claim "server can never read files"
beyond the passive case.

### C16. Distribution is not real yet — **OPEN**

Dynamic OpenSSL link (rustls/ring swap needed), no static musl build, no
macOS/Windows builds or testing (`/etc/hostname` has a fallback; nothing
verified), no release CI, no `curl | sh`. Gate any public CLI announcement on:
musl static binary + macOS arm64 build + a GitHub Releases workflow.

### C17. Never run against production — **OPEN (gate)**

All tests so far hit a local backend on loopback. Required before calling the
CLI real: a transfer through `api.filament.autumated.com` from a network that
forces TURN (verifies ephemeral creds + `:443` fallback end-to-end), and one
CLI↔phone-browser transfer across carrier NAT.

## Part 3 — Failure modes already hit and fixed during development

Recorded so they cannot regress unnoticed:

### F1. SCTP outbound frame overflow — **FIXED + VERIFIED**
First transfer attempt died: `outbound packet larger than maximum message
size`. 64 KiB payload + 4-byte header = 65,540 > 65,535. Chunk reduced to
60 KiB (`net::MAX_DC_PAYLOAD`); config `chunkSize` is additionally clamped to
it. C1 is this same bug's mirror on the inbound/browser side.

### F2. rustls dual-provider panic — **FIXED + VERIFIED**
Adding `reqwest` introduced a second rustls crypto provider (aws-lc alongside
webrtc's ring); rustls panics at DTLS setup rather than guess. Fixed by
explicit `rustls::crypto::ring::default_provider().install_default()` first
thing in `main`. Any new dependency that touches rustls can re-break this —
the fix is order-dependent (must run before any TLS use).

### F3. Wait-for-peer deadline fired mid-transfer — **FIXED**
The 600 s "waiting for a peer" timeout wrapped the *whole* event loop, so a
transfer longer than the remaining budget would be killed as "timed out
waiting for a peer". Timeout now applies only while `peer.is_none()`.
*Verify-with gap:* no test sends for >600 s; covered implicitly once C8's
benchmark sends large payloads.

### F4. Sender raced the receiver's goodbye — **FIXED + VERIFIED**
Receiver finishes, disconnects after its 1.5 s grace; sender's event loop saw
`peer-left` before re-checking completion and reported "peer left before the
transfer finished" despite a complete transfer. Two fixes: stream tasks emit
`Ev::TransferDone` so the loop re-evaluates immediately, and
`peer-left`/`failed` handlers check the all-done flag before bailing.

## Part 4 — Standing test gates

Run before any CLI release tag (currently manual; CI is part of C16):

1. CLI↔CLI one-time code transfer, hash compare, both exit 0 (covers #1/#2/#11, F4)
2. Resume from interrupted partial, hash compare (covers resume path, C7 once hashed)
3. Directory tar + stdin pipe round-trips
4. CLI → headless-browser transfer (Playwright)
5. Browser → CLI transfer (Playwright) — **missing until C1 is fixed**
6. Live-prod transfer exercising TURN — **missing until C17**

---

*Cross-references: protocol contract in [`../CONTRACT.md`](../CONTRACT.md);
browser failure modes in [`resilience.md`](resilience.md); CLI usage in
[`../cli/README.md`](../cli/README.md).*
