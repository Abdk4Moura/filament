# L1 PAKE pairing — protocol spec (L1-0 output)

Status: **SPEC / spike-validated. NOT IMPLEMENTED.** This is the reviewable
design produced by the L1-0 de-risking spike (`spike/`). It closes the
first-pairing server-MITM gap by running a real PAKE over the spoken code
*before* any DataChannel exists. A follow-up implementation agent builds the
real pairing change from this; until then the production pairing path is
unchanged. Crypto-critical: this document is a human-review checkpoint.

Spike that backs every claim below: `spike/run.sh` (native gates +
WASM↔native interop). Crate: `spake2 = "=0.4.0"` (RustCrypto/PAKEs).

---

## 1. The gap being closed (precise)

On the **first** pairing two devices share no secret yet. Today:

1. Both join a solo room; the server matches them via the one-time
   `adj-animal-NNN` code (`pair-create`/`pair-claim`, `backend/signaling.py`).
2. WebRTC SDP **and DTLS fingerprints are relayed through the server**.
3. One side generates a 32-byte `secret` (`fresh_secret`, `cli/src/main.rs`)
   and sends it to the other **over the DataChannel** (`pair-keep`,
   `cli/src/main.rs` ~916).

A malicious/compromised signaling server can MITM step 2 — present its own
DTLS certificate to each side, terminating two DTLS sessions — and then read
the `secret` in transit at step 3. **The C20 reconnect proof
(`proof_for`, HMAC over the secret + sorted DTLS fingerprints) protects
pairing #2+, NOT #1**: on the very first pairing there is no secret yet to key
the HMAC with. The whole trust chain (`channel_of`, `proof_for`, the
direct-TCP PSK in `design-direct-cli-transport.md`) is rooted in a secret that
the server may have learned at enrollment.

**A PAKE over the spoken code closes this**: both sides derive a strong key K
that the server cannot compute even while relaying every PAKE message, and the
pinned secret is *derived from K* (agreed, never transmitted).

---

## 2. The code split (server matches a nameplate, never sees the password)

The server currently knows the **whole** code, so it cannot double as the PAKE
password. We split it wormhole-style.

### 2.0 Who mints the words — the load-bearing change (must read first)

Today `_mint_pair_code` runs **server-side** (`backend/signaling.py`): the
server picks the adjective, animal AND number, then sends the whole code back
in `pair-code`. **If the server mints the words it knows the PAKE password and
the entire MITM-resistance claim collapses.** So v2 makes one structural change
that is more invasive than "split a string":

- **The client CSPRNG-mints the words locally.** The `_ADJ`/`_ANIMAL` wordlists
  move (or are duplicated) to the client (CLI + browser); the server no longer
  generates or ever receives the words.
- **The server only allocates/matches the nameplate** (§2.1). It hands back at
  most a nameplate, never the words.
- The full `adj-animal-NNN` string is **assembled and displayed client-side**.

The spike models exactly this post-change world: `SpokenCode::from_spoken`
splits a code the *client* holds, and the `Relay` is never given the password.
Magic-wormhole works the same way — the client owns the codeword entropy.

### 2.1 Recommended split (decision — flagged for review)

Today's code is `adj-animal-NNN`: 64 adj × 64 animal × 900 numbers = 3,686,400
(~21.8 bits), 10-min TTL, NX burn-on-claim, 5 claims/min rate limit.

**RECOMMENDED — Option A (suffix nameplate):**

```
spoken code:  brave-otter-314
nameplate  =  "314"          -> sent to server as the rendezvous selector
password   =  "brave-otter"  -> kept client-side, feeds SPAKE2, NEVER sent
```

- **Nameplate** = the `NNN` suffix (900 values, ~9.8 bits). The server matches
  on it exactly as it matches the full code today (NX create / GETDEL claim).
- **Password** = the `adj-animal` words (4096 values, ~12 bits). Feeds the PAKE
  and is never transmitted.
- **No UX change**: the user still speaks one `adj-animal-NNN` string. The
  words are minted client-side (§2.0); only the nameplate ever reaches the
  server.

**Why this is safe despite only ~12-bit words — the online-guess model
(load-bearing argument a reviewer must check):**

- K never transits the wire, so there is **no offline attack** on the
  password. The only attack is an *online* guess: an attacker claims the
  nameplate and runs the PAKE with a guessed password.
- SPAKE2 leaks **nothing** about whether a guess was right except via the
  key-confirmation step (§4) — one failed confirmation = one eliminated guess.
- **Burn-on-claim gives the attacker ~1 online guess per code.** A claim
  consumes the nameplate (GETDEL). A failed PAKE/confirmation burns it; the
  honest peer's claim then fails and the user re-mints. So an attacker racing
  the real claimer gets a *single* 1-in-4096 guess, not an offline sweep.
- The existing 5-claims/min IP+sid rate limit (`_claim_allowed`) further caps
  online grinding across many codes.

This is the entire point of PAKE: it converts a low-entropy secret into a
strong key with **only online, rate-limited, single-shot** attackability.

### 2.2 Cost / open decision of Option A

- **Nameplate collision surface shrinks to 900 concurrent slots.** Today a full
  21.8-bit code rarely collides; a 900-value nameplate space collides sooner
  under load. Mitigation: on `pair-create`, the server already retries minting
  on NX-collision (`on_pair_create`, 4 tries). Keep that; if 900 proves too
  tight under real concurrency, widen `NNN` to 4 digits (nameplate ~13 bits,
  password unchanged) — a one-line vocab change. **DECISION FOR REVIEW: ship
  900 and monitor, or pre-emptively widen.**

**Alternative — Option B (dedicated nameplate token):** keep the full
`adj-animal-NNN` (21.8 bits) as the password and have the server mint a
separate short routing token (e.g. a 4-char base32 `nameplate`). Preserves all
entropy in the PAKE and decouples rendezvous capacity from password entropy,
at the cost of the user handling two tokens or a longer string. **Rejected as
default** for UX; documented as the fallback if nameplate capacity or a desire
for >12-bit passwords forces it.

---

## 3. SPAKE2 message flow over signaling (before any DataChannel)

### 3.1 Variant and the identity-string footgun

Use **`Spake2::<Ed25519Group>::start_symmetric`** (RustCrypto `spake2` 0.4.0).
Symmetric because either peer may initiate (creator or claimer) — same choice
magic-wormhole makes. **Both sides MUST pass the identical `Password` AND the
identical `Identity`** or they derive two valid-but-different K's with no error
(indistinguishable from a wrong password). The spike pins the identity to the
nameplate for domain separation:

```
identity = b"filament-pair-pake-v1:" || nameplate
password = adj-animal words (utf-8, normalized via the existing _norm_code rules)
```

SPAKE2 here is a **single round**: each side computes one outbound element and
finishes on the peer's element. No A/B role coordination is needed with
`start_symmetric`.

### 3.2 New socket.io events (additive — old `pair-*` events untouched)

The PAKE rides the existing relay (`on_signal` is already a dumb opaque pipe).
We reuse `pair-create`/`pair-claim` for rendezvous on the **nameplate**, then
exchange PAKE bytes as opaque `signal` payloads (preferred — zero new server
code, server stays a dumb relay) OR as dedicated events if telemetry is wanted:

```
# creator CSPRNG-mints adj-animal-NNN LOCALLY (server never sees the words):
client -> server  pair-create { nameplate, v:2 }          # only the NNN suffix
server -> client  pair-ok     { nameplate, ttl }          # ack; NO words echoed
                                                          # creator displays full
                                                          # code from its OWN mint
client -> server  pair-claim  { nameplate, v:2 }          # claimer types full code,
                                                          # sends only the nameplate
server -> client  pair-matched{ room }                     # both in solo room

# then, over the existing opaque `signal` relay (server cannot read these):
A -> B   signal { type:"pake-msg",     v:2, msg:<33-byte SPAKE2 element, b64> }
B -> A   signal { type:"pake-msg",     v:2, msg:<33-byte SPAKE2 element, b64> }
A -> B   signal { type:"pake-confirm", v:2, mac:<32-byte HMAC, b64>, caps:[...] }
B -> A   signal { type:"pake-confirm", v:2, mac:<32-byte HMAC, b64>, caps:[...] }
```

The server matches `nameplate`, moves the claimer into the creator's room, and
relays the four opaque messages. **It never receives `password` and cannot
derive K** (spike `[gate:relay-blind]`: the password never appears in any
relayed byte).

### 3.3 Where this sits relative to DTLS

PAKE runs **on the signaling channel, before WebRTC/DTLS is established**. The
derived K then *binds* the subsequent DTLS handshake (§5). This is the
ordering that lets K detect a DTLS-layer MITM: K is fixed by the spoken
password the server doesn't have, so a server that substitutes DTLS certs
produces fingerprints that fail the K-keyed confirmation.

---

## 4. Key confirmation — the actual negative gate (NOT optional)

**SPAKE2 outputs K but does not tell either side the peer derived the same K.**
A wrong-password peer silently gets a different K; an active relay can inject
its own element. Confirmation makes both **detected**. Each side sends, and
verifies, a MAC over a fixed transcript:

```
conf_{dir} = HMAC-SHA256(K, "filament-pake-confirm-v1" || dir || fp_lo || fp_hi)
   dir    in {"A->B","B->A"}   (direction tag; prevents reflection)
   fp_lo,fp_hi = the two DTLS fingerprints, SORTED   (§5 binding)
```

A side aborts the pairing if the received MAC does not match the value it
recomputes under its own K. Spike results:

- `[gate:wrong-password]`: different password → confirmation FAILS → refused.
- `[gate:mitm]`: an active relay that does not know the password substitutes
  its own SPAKE2 element → A derives a different K → confirmation FAILS →
  substitution **detected and refused**. The relay cannot silently inject a key
  of its choosing.

This confirmation MAC is **literally `proof_for` for pairing #1, keyed by K
instead of the not-yet-existing pinned secret** — it folds in the same sorted
DTLS fingerprints (`proof_for`, `cli/src/main.rs` ~470). The whole design is a
natural extension of C20, not a bolt-on.

---

## 5. Binding K to the handshake (two bindings, both done)

### 5.1 Derive the pinned secret from K (agreed, never transmitted)

```
secret = HKDF-SHA256(ikm = K, salt = none,
                     info = "filament-pair-pake-v1:pinned-secret")[0:32]   # hex
```

The 32-byte device identity is now **AGREED**, not sent over the DataChannel.
The `pair-keep` secret-over-DataChannel step is **removed** from the v2 path.
This is the same HKDF-info construction already used for the direct-TCP PSK
(`design-direct-cli-transport.md` §"Key derivation"), keeping a single,
auditable KDF pattern. The resulting `secret` drops straight into the existing
`devices.json` `{name, secret}` store, `channel_of`, and `proof_for` — **no
downstream change**; pairing #2+ keeps working exactly as today.

### 5.2 MAC the DTLS fingerprints under K (server-MITM-on-enrollment detection)

The confirmation MAC (§4) already includes the sorted DTLS fingerprints
`fp_lo, fp_hi`. If the server MITMs the DTLS handshake, the two sides see
different fingerprint pairs, so their confirmation MACs disagree under the same
K and the pairing aborts. This makes a **server-MITM on first enrollment
cryptographically detectable** — the exact protection C20 gives reconnections,
now extended to pairing #1.

---

## 6. Version negotiation and back-compat

**Additive, never regressing** (per `design-direct-cli-transport.md`
"NON-NEGOTIABLE: must match DTLS, not regress from it").

- **Remembered devices are untouched.** They already hold a `secret` and use
  `channel_of`/`proof_for`. The PAKE only changes *first* enrollment; reconnect
  of an existing device is unchanged and needs no PAKE.
- **Capability flag `v:2`** on `pair-create`/`pair-claim` and on the `signal`
  payloads marks a PAKE-capable client.
- **Mixed-version pairing:** if exactly one side is `v:1` (old client), the
  pair either (a) refuses with a clear "update to pair securely" message, or
  (b) — only if a transition window is required — falls back to the legacy
  secret-over-DataChannel path **with an explicit, logged downgrade**. See §7:
  the safe default is **refuse the downgrade once both sides are v2**.

### 6.1 Downgrade resistance (critical — the blind spot)

A malicious server can strip the `v:2` flag from relayed messages to force the
old vulnerable path. Therefore:

- **The capability set is carried INSIDE the PAKE-confirmed transcript** (the
  `caps` field is folded into / sent alongside the confirmation MAC under K),
  **not taken on the server's word.** A server that rewrites `caps` breaks the
  confirmation MAC.
- **Policy: once a client knows the peer is v2, a v1 first-pairing is
  REFUSED.** The server's only power becomes denial-of-service (force a
  retry), never a silent downgrade to the readable-secret path.
- The legacy fallback, if shipped at all, is **time-boxed to the migration
  window** and removed once clients are updated.

---

## 7. Threat model — malicious server, before vs after

| Capability of a malicious/compromised signaling server | Before (today) | After (PAKE v2) |
|---|---|---|
| See the spoken code | **Yes** (knows whole code) | **No** — sees only the nameplate; password never sent |
| Read the pinned secret on FIRST pairing | **Yes** (DTLS-MITM + secret over DataChannel) | **No** — secret = HKDF(K), K not derivable, never transmitted |
| MITM the first-pairing DTLS session undetected | **Yes** | **No** — fingerprints bound into K-keyed confirmation MAC; mismatch aborts |
| Silently substitute its own key | **Yes** (it is an endpoint of each DTLS session) | **No** — `[gate:mitm]`: substitution fails confirmation |
| Read the secret on RECONNECT (pair #2+) | No (C20 proof) | No (unchanged) |
| Online-guess the password | n/a (had the code) | **~1 guess/code** (burn-on-claim) + 5/min rate limit |
| Offline brute-force the password | n/a | **Impossible** — K never transits |
| Deny service (force retry/fallback) | Yes | **Yes** (unavoidable for a relay) — but never drops auth |
| Force a downgrade to the readable path | n/a | **No** once both are v2 (§6.1) |

**Residual risks the server still has:** denial of service (refuse to relay,
exhaust nameplates), traffic analysis (sees who rendezvous with whom on a
nameplate), and the single online password guess per code. None of these read
the secret.

---

## 8. Capability-set data model sketch (for L1-b)

The pinned device record grows a capability list, **deny-by-default**:

```jsonc
// devices.json entry (v2)
{
  "name": "alice-laptop",        // local petname (unchanged)
  "secret": "<64 hex>",          // = HKDF(K); identity (unchanged shape)
  "v": 2,                        // record schema version
  "caps": ["transfer"],          // GRANTED capabilities; empty = nothing but presence
  "addedAt": 1733000000          // already present browser-side
}
```

- `caps` is **deny-by-default**: an absent/empty list grants only what L0
  already allowed (be findable, attempt a transfer the user accepts per C27).
  Future L-layers add `caps` values (e.g. `"daemon-push"`, `"clipboard"`,
  `"remote-exec"`) and gate features on them.
- The capability set is agreed at enrollment **under K** (§6.1), so neither the
  server nor a later MITM can escalate a device's caps without the user.
- v1 records (no `v`/`caps`) are read as `v:1, caps:["transfer"]` for
  backward compatibility.

---

## 9. Composition with existing primitives

- **`channel_of(secret)`** = `sha256("filament-pair:"+secret)`: unchanged.
  Because `secret = HKDF(K)`, both sides compute the same channel from the
  agreed secret; presence (C12) works identically.
- **`proof_for(secret, ...)`**: unchanged for reconnect. The PAKE confirmation
  MAC is its pairing-#1 analogue keyed by K.
- **Direct-TCP PSK** (`design-direct-cli-transport.md`):
  `HKDF(secret, "filament-direct-transport-v1")` — unchanged; it now keys off a
  secret that was *agreed*, not server-readable, strengthening that path too.
- **Cross-context separation:** K → secret uses info
  `"filament-pair-pake-v1:pinned-secret"`; the confirmation MAC uses label
  `"filament-pake-confirm-v1"`. Distinct from the channel hash prefix and the
  proof label — no cross-context key reuse.

---

## 10. Gates the implementation must ship (each is a hard pass/fail)

1. **mutual-key** — two honest peers with the same code derive the same
   pinned secret; confirmation passes. (spike: `[gate:mutual-key]` ✓)
2. **adversarial / server-can't-derive (NEGATIVE — the security test)** — a
   relay/MITM without the password cannot derive K and cannot substitute its
   own key: confirmation MAC fails, pairing aborts, zero secret agreed.
   (spike: `[gate:mitm]`, `[gate:relay-blind]` ✓) *Per the ledger rule, an auth
   feature is VERIFIED only if this negative test exists.*
3. **wrong-password-burns / no-retry** — a wrong password fails confirmation
   AND consumes the nameplate, and the creator MUST NOT re-run the PAKE with the
   same password: a failed pairing forces a **re-mint with fresh words**, never
   a retry of the same code. This is what makes the "~1 online guess per code"
   bound hold; a silent retry would hand the attacker unlimited guesses against
   one password. (spike: `[gate:wrong-password]` ✓ for the crypto half; the
   burn-and-no-retry half is server-/client-side, to be gated against the real
   `pair_claim` + creator loop.)
4. **browser↔CLI interop** — WASM and native derive the same secret from the
   same code. (spike: `[gate:browser<->cli interop]` ✓)
5. **capability deny-by-default** — a device with empty `caps` is refused any
   gated action; caps cannot be escalated without re-enrollment under K.
6. **downgrade-refused** — with both sides v2, a server that strips `v:2`
   cannot force the legacy readable-secret path. (to be gated against a real
   stripping fixture.)
7. **no-regression** — existing remembered devices reconnect unchanged; C20
   proof still holds for pair #2+.

---

## 11. Open decisions / risks for the human checkpoint

1. **Crate audit status.** `spake2` 0.4.0 (RustCrypto/PAKEs, ~640k downloads,
   used by magic-wormhole) is **NOT independently audited**. It is the most
   mature pure-Rust SPAKE2. **Decision:** accept with the RustCrypto provenance,
   or fund/seek an audit, or pin and vendor. Do **not** ship `0.5.0-pre.0`.
2. **CPace vs SPAKE2.** SPAKE2 chosen for the magic-wormhole ecosystem fit,
   the available maintained Rust crate, and the symmetric variant (no role
   coordination). CPace (RFC 9382 sibling / CFRG balanced PAKE) is arguably
   more modern but lacks an equally mature, WASM-proven Rust crate in this
   tree. **Recommendation: SPAKE2 now; revisit CPace only if an audit gap
   forces it.**
3. **WASM size/perf.** Release wasm is **538 KB** (`pake_core.wasm`,
   `cargo build --release --target wasm32-unknown-unknown`); a production build
   via `wasm-pack` + `wasm-opt` and a slimmer KDF surface should shrink it. One
   SPAKE2 op is sub-second (curve25519-dalek). **Risk: bundle size for the web
   app — measure post-`wasm-opt` before committing the WASM-shared path.**
4. **Password entropy (the number a reviewer will probe).** The `adj-animal`
   password is 64×64 = 4096 ≈ **12 bits**, so a single online guess succeeds
   with p ≈ 1/4096. magic-wormhole's default words carry ~16 bits. 12 bits is
   plausibly fine here given **burn-on-claim (1 guess/code) + 5 claims/min
   rate-limit**, but it is the load-bearing number. **DECISION FOR REVIEW:
   accept 1/4096, or widen the wordlists (e.g. 256×256 → 16 bits) — a wordlist
   change, no protocol change.** Note this is the *password* entropy; it is
   independent of, and more security-relevant than, the nameplate entropy in #5.
5. **Nameplate entropy (§2.2).** Ship 900-value (~9.8-bit) nameplate and
   monitor collisions, or widen to 4 digits up front. This affects rendezvous
   *capacity/collisions*, not password strength. **Recommendation: ship 900,
   monitor; widening is a one-line change.**
6. **Breaking-change migration.** Whether to ship the v1→v2 transition fallback
   at all, and for how long. v2 also relocates word-minting client-side (§2.0),
   so old `v:1` clients (server-minted words) cannot PAKE-pair with a v2 client.
   **Recommendation: refuse-downgrade by default; ship a fallback only if
   telemetry shows a meaningful v1 population, time-box it.**
7. **Spike shortcuts that production must NOT inherit:** the spike uses a
   seeded deterministic RNG for reproducible interop (production = OsRng /
   `crypto.getRandomValues`); the spike's `pake_begin`/`pake_finish` C-ABI uses
   a process-global `Mutex<Vec>` handle table (production = `wasm-bindgen`
   objects); the relay/confirmation transcript here is a demo shape, not the
   final wire encoding. None of these are production crypto.

---

## 12. Go / No-Go

- **`spake2` crate: GO** (0.4.0, RustCrypto) — builds native + wasm32, derives
  matching K, fails correctly on wrong password. Caveat: unaudited (risk #1).
- **WASM-shared browser path: GO** — WASM↔native interop proven
  (`[gate:browser<->cli interop]`). Browser and CLI can share ONE SPAKE2
  implementation. (The pre-approved CLI-first fallback is **not needed** — but
  gate the final call on the post-`wasm-opt` bundle size, risk #3.)
- **Overall approach: GO** — the magic-wormhole model (code-split → SPAKE2 over
  signaling → key-confirmation with DTLS-fingerprint binding → HKDF to the
  pinned secret) closes the first-pairing MITM gap, is strictly additive, and
  composes with `channel_of`/`proof_for`/direct-TCP unchanged.

**STOP HERE.** Implementation of the real pairing change is a separate task
behind human review of this spec.
