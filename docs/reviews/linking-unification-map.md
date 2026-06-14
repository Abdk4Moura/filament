# Linking unification map — send/recv + pair → one core

Generated 2026-06-14. Builds on `docs/notes/code-unification.md` (Jun 13, which
recommended *not* unifying yet). The owner has since decided to pursue
unification + user-chosen codes + a single 3-segment shape, so this map scopes
the actual refactor. Read-only analysis; cites `file:line`.

## TL;DR

"Linking two devices" is already **one pipeline** for both flows. They share:
signaling connect (`net::connect_signaling` net.rs:496), the `Conn` event loop
(main.rs:1838+), WebRTC bring-up (`net::Peer` / `PeerLink` webrtc.js:256),
the C30 session (session.rs / session.js), and the file-transfer wire protocol.
They diverge in exactly **two** places:

1. **Code minting/claiming** — transfer uses a v1 *server-minted* 3-seg code
   (`adj-animal-NNN`); pairing uses a v2 *client-minted* code
   (`adj-animal-extra-NNNN`) where only the numeric nameplate reaches the server.
2. **Post-transport action** — transfer streams bytes and forgets; pairing runs
   SPAKE2 over the signal relay and *stores* the agreed secret.

So: `pair` = **link + remember**; `send` = **link + stream**. Unify the link;
let the verb decide persistence. Converge both on PAKE (it's strictly stronger
than the server-minted code), making one code system.

## The split that matters (for user-chosen codes)

A code has two jobs that pull opposite ways:

| Part | Job | Owner |
|---|---|---|
| words (`gigantic-element`) | SPAKE2 password — never leaves the device | **human picks** (memorable) |
| number (`-7`) | nameplate — routing selector the server matches | **machine assigns** |

`split_code` (pake/src/lib.rs:213) already takes the trailing numeric group as
the nameplate and everything before as the password — it is segment-count- and
mint-agnostic. The server's `_NAMEPLATE_RE = ^[0-9]{3,5}$` (signaling.py:421)
accepts any 3–5 digit nameplate and does not care whether it was minted.
**So user-chosen 3-seg codes already work at the protocol level.** Blocking it
today: minting defaults emit 4 segments, the browser has no custom-entry field,
and `looks_like_pake_code` assumes 4 segments.

Steering when a user types `gigantic-element` (no number): **do not reject —
append a machine-assigned free nameplate** (`gigantic-element-7`, smallest free
number, magic-wormhole style). Never derive the number from the words (that
would leak the secret to the server).

## Collisions

- **Routing (same number, two live links):** eliminated by construction — the
  server allocates the nameplate NX and the system hands back the smallest free
  one. Only user-chosen *numbers* can clash → "taken" → reprompt. Let users pick
  words, not numbers.
- **Password reuse (two pairs pick the same words):** harmless. SPAKE2 identity
  is `"filament-pair-pake-v1:" || nameplate` (pake/src/lib.rs:51), so different
  nameplates → different sessions even with identical words.
- **The real risk is weak passwords**, not collisions — bounded by burn +
  5-claims/min rate-limit (≈1 online guess per code, no offline attack) plus a
  min-strength steer.

## Duplication inventory (what to actually merge)

- **D1 — three "remember a device" ceremonies, two protocols.** `pair_cmd`
  (main.rs:1370) runs SPAKE2 v2 (relay-blind, stores via `devices_store_v2`).
  `send --remember` (main.rs:4460-4464) and the C29 daemon ceremony in `recv_cmd`
  (main.rs:5755-6040) instead hand a plaintext 32-byte secret over the
  DataChannel (`pair-keep`, v1). Same goal, three impls, weaker crypto on two.
- **D2 — `Conn` constructed 3× with the same 17 fields** (main.rs:1421, 4120,
  5034). Differ only in `relay_only`/`to_filter`/`warm_standby`.
- **D3 — code-shape validators in 2 languages.** `regex_lite_code`/
  `looks_like_pake_code` (main.rs:466/482) vs the inline checks in
  `pairWithCode` (useFilament.js:891-901).
- **D4 — wordlists in 4 places** (signaling.py:36, useFilament.js:26, words.js:10,
  words.rs:19), kept in sync by comment convention only.
- **D5 — `channel_of`/`channelOf` and `proof_for`/`proofFor`** reimplemented in
  Rust (main.rs:881/914) and JS (devices.js:101/108); must be byte-identical, no
  test enforces it.
- **D6 — `devices_store` vs `devices_store_v2`** (and JS twins) — v2 just adds
  `v`/`caps`/`addedAt`.

## Already shared — do NOT "unify" these

`net::connect_signaling`, `Conn` + all methods, `net::Peer`/`PeerLink`, the C30
`Session`, the `Transport` trait, the `pake` crate (SPAKE2 core + `norm_code`/
`split_code`, compiled native for CLI and WASM for browser), the file-transfer
wire protocol, the registry abstraction, the claim rate-limiter, burn semantics.

## The one big gap: the browser has no receive path

`pairWithCode` drives PAKE pairing; there is **no `receiveWithCode`** that claims
a code and downloads a file (useFilament.js / pairing.js — confirmed, and called
out in the Jun 13 note line 62/100). True unification requires building the
browser receive flow: claim → PAKE → open DataChannel → accept `file-offer` →
write download. Non-trivial, security-reviewed scope on its own.

## Security invariant to preserve throughout

The PAKE words never cross the signaling server, and the confirmation MAC binds
both sides' DTLS fingerprints so a server/relay MITM is detectable. The v1
`pair-keep` hand-over (DataChannel plaintext) is weaker — folding it into PAKE is
a security *upgrade*; never go the other way to "save a word".

## Staged refactor (each step independently shippable, no peer break)

1. **Extract `Conn::for_command(...)`** — collapse the 3 struct literals. Zero
   wire change. (main.rs:1421/4120/5034)
2. **Frontend wordlist consolidation** — import from `words.js`, drop the copy in
   useFilament.js:26-45. Zero wire change.
3. **Byte-identity tests** for `channel_of`/`proof_for` across Rust↔JS. Safe.
4. **Frontend validator → shared WASM** `splitCode`/`normCode` in `pairWithCode`.
   Safe.
5. **`send --remember` → PAKE** instead of v1 `pair-keep` (closes the
   DataChannel-MITM gap). Needs receiver ≥ this version → version-gate.
6. **`send --code` → v2 nameplate minting** (3-seg, drop the `extra` word; allow
   user-chosen words). Server already supports v2; update `recv` claim to
   `split_code` + `pair-claim {nameplate, v:2}`. Mixed-version `recv` must fail
   loudly, not hang.
7. **Ephemeral PAKE on the transfer path** — run the ceremony, *discard* the
   secret (auth only). Extract the PAKE state machine from `pair_cmd` into a
   shared `pake_ceremony` module called by both. Benchmark added time-to-first-byte.
8. **Browser receive path** — the prerequisite for cross-client unification.
9. **Retire the v1 server branch** after a migration cycle (signaling.py:457-469,
   `_mint_pair_code`).

Order 1-4 are safe cleanups landable now. 5-7 converge the trust model. 8 is the
gating scope. 9 is cleanup once the fleet has migrated.
