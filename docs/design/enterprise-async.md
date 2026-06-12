# Async send + enterprise for filament: opt-in layers on a zero-knowledge core

**Status:** design (doc-only). **Audience:** decision-grade — does this earn the
two markets filament cedes today, without spending the P2P user's simplicity or
the project's security posture?

---

## TL;DR — the thesis, and how the three hard constraints are met

Filament is pure peer-to-peer: account-free, end-to-end encrypted, pairing-based.
Both ends must be online at once. That is the source of its two biggest
"won't-use-it" gaps:

- **Async / send-to-anyone.** It cannot send a file to someone who is offline,
  on another of your own devices that is asleep, or who is not a filament user at
  all. That cedes the WeTransfer / email-a-link / Drive market.
- **Enterprise IT.** Ungoverned P2P + arbitrary pairing + a remote shell is the
  exact shape corporate IT *blocks*: no SSO, no ACLs, no audit, no perimeter
  control.

Both gaps reduce to the same move: **add a controlled, server-side component on
top of P2P.** The danger is that the obvious version of that move — "just run a
server that holds the files / brokers the trust" — destroys the two things that
make filament filament (a default with no middleman, and a server that never
sees plaintext).

**The thesis: build exactly one new server-side primitive — a *zero-knowledge
store-and-forward node* — and expose async and enterprise as *opt-in layers* on
top of it and the existing P2P core. The default path is untouched. Any server,
ours or the org's, only ever holds ciphertext it cannot read.**

How the three constraints are satisfied — stated up front, defended in §3, §5, §6:

1. **Does NOT make the common P2P user's life harder (the gate, §6).** The
   default is still *pair-and-go, direct, no account, no login, no config*. Async
   is an *additive affordance* ("the peer's offline — park it / get a link?"), never
   a mode the user must learn. Every enterprise control lives in the org/admin
   layer; an enrolled employee experiences only "my device joined via my company,"
   never a new dialog. Each feature below carries an explicit "common-user path
   unchanged" clause, and §6 names every place a naive design *would* add friction
   and how we avoid it.

2. **Does NOT make security worse.** The new store is **zero-knowledge / sealed**:
   the sender encrypts client-side to the recipient *before* anything touches the
   server; the server stores ciphertext + minimal metadata and **never holds a key
   or sees plaintext** — same model as Bitwarden Send / the former Firefox Send.
   The pairing trust root (SPAKE2 + DTLS-fingerprint-bound HMAC, already shipped)
   is *extended*, never bypassed. Enterprise audit logs **metadata + file hashes +
   shell-session records**, never decrypted content, so E2E survives compliance.

3. **Ideally makes security BETTER.** It does, on three axes (§3.4): (a) the async
   path *replaces* the insecure thing real users do today — emailing the file,
   dropping it in Drive, using WeTransfer — all of which expose plaintext to a
   provider; filament's store cannot read it. (b) Enterprise enrollment turns
   ad-hoc spoken pairing codes into **SSO-bound device identity**, raising the
   trust root from "whoever typed the code" to "this device belongs to this
   authenticated employee." (c) Self-hosting the store + signaling + `--no-relay`
   gives an org a **smaller, auditable trust surface than any incumbent SaaS** —
   the file-sharing server is one binary inside their perimeter that holds only
   sealed blobs.

The rest of this doc: the zero-knowledge store (crypto + the three uses + a
security analysis against the incumbents it beats), the enterprise governance
layer (SSO / ACL / audit-without-content / self-host / governed shell, and an
explicit resolution of the E2E-vs-DLP tension), the "common user stays simple"
gate per feature, a comparison table against six real systems, and a phased plan
grounded in real files — store first, because it is the single highest-leverage
piece and unlocks all three uses at once.

---

## 1. What we are building on (audited primitives — real files/functions)

This design **extends**, it does not replace. The trust root, the capability
model, the self-host knobs, and the never-flaky transport are already in tree.

### 1.1 The pairing trust root (PAKE / SPAKE2 + DTLS-bound HMAC)

- `pake/src/lib.rs` — symmetric **SPAKE2** PAKE. `start()` / `finish()` derive a
  shared key `K` from a low-entropy spoken code; `confirm_mac()` and
  `our_confirm()` / `verify_peer_confirm()` compute a key-confirmation HMAC-SHA256
  that **folds the sorted DTLS certificate fingerprints and the canonicalized
  capability set** (`confirm_mac(k, dir, fp_lo, fp_hi, caps)`,
  `canonical_caps()`). A signaling server that substitutes a cert produces
  mismatched fingerprints → confirmation fails (test
  `fingerprint_mismatch_confirmation_fails`). `secret_from_k()` is
  `HKDF-SHA256(K)` → the 32-byte **pinned device secret**, *agreed but never
  transmitted*.
- The spoken code carries ~16 bits of entropy (`pake/src/words.rs`:
  `ADJ[64] × ANIMAL[64] × EXTRA[16] = 2^16`), one-time use, server sees only the
  numeric **nameplate** (`mint_nameplate()`), never the words. This is the Magic
  Wormhole property: an active MITM gets exactly one online guess (1-in-65536),
  a passive server gets zero.
- `cli/src/main.rs` — `proof_for(secret, prover_uid, a_uid, b_uid, fp1, fp2)`
  binds the pair secret to the live DTLS session (HMAC over secret ‖ sorted UIDs ‖
  sorted fingerprints); `channel_of(secret)` = `SHA256("filament-pair:" ‖ secret)`
  is the server-visible rendezvous point — the server learns *meeting points, not
  secrets*. `cli/src/direct.rs` — `transport_key()` / `authenticate()` run a
  mutual confirm-MAC over the RFC-5705 QUIC exporter (`keying_material()`) before
  any byte of data.

This is the root we extend to (a) **org identity**, (b) **recipient pubkeys for
sealed delivery**, and (c) **claim-link keys** for non-users.

### 1.2 Deny-by-default capabilities (the ACL substrate)

- `cli/src/main.rs` — device records in `~/.config/filament/devices.json` carry
  `{name, secret, v:2, caps:[...], addedAt}` (`devices_store_v2()`). First pairing
  grants **only** `["transfer"]` (`pair_v2_caps()`, mirrored in
  `frontend/src/lib/pairing.js` as `PAIR_V2_CAPS`). `device_allows(name, cap)` is
  deny-by-default; `device_set_cap()` / `Cmd::Grant` / `Cmd::Revoke` add or remove
  caps. `shell` is never auto-granted.
- `enum ShellPolicy { Granted, All, Only(set) }` and the `--shell-user <USER>`
  flag (`runuser -l <user>`, drops the PTY to a non-root account) gate the
  web-shell; enforcement at accept time is `shell_policy.auto_allows(n) ||
  device_allows(n, "shell")`. `cli/src/sshkeys.rs` installs/strips a
  filament-managed `authorized_keys` block per grant. **This is the enterprise ACL
  engine already** — §5 puts an admin control plane in front of it.

### 1.3 Self-host + relay knobs (the perimeter substrate)

- `cli/src/main.rs` — `--server` / `FILAMENT_SERVER` (default
  `https://api.filament.autumated.com`) points the client at any signaling
  endpoint. The server (`backend/app.py`, `backend/signaling.py`) is a **dumb
  pipe**: it tracks room membership and relays opaque signal blobs, *never file
  bytes*. It already has the right shape to extend: `pair_create(code, sid,
  ttl=600)` is a TTL-bearing rendezvous slot; `_MemRegistry` / `_RedisRegistry`
  give single-node and horizontally-scaled deployments.
- `backend/config.py` — TURN is self-hostable with **ephemeral HMAC credentials**
  (`_turn_servers()`: `username = expiry-timestamp`, `credential = HMAC(secret,
  username)`), so the browser never holds a long-lived TURN password. The TURN
  relay is the natural host for the store-and-forward node (§3).
- `--relay` (force relay) exists; `--no-relay` (forbid relay, direct-only) is the
  shipping inverse. The **relay-honesty UX** (`docs/design/transport-resilience.md`
  §3) already makes "a server is on the wire" visible — amber ⚠ *"on relay —
  routed via a TURN server, not a direct link (still encrypted)"*. We reuse that
  exact surface to make "a store is in the path" honest too.

### 1.4 The never-flaky transport these layers ride on

- `docs/design/transport-resilience.md` — the correction ladder, stall detector,
  and **Phase 4 whole-file SHA-256 completion gate + result-ACK loop (GAP-5)**.
  The store's integrity guarantee (§3.3) is the *same* whole-file hash, lifted to
  the async path: a parked blob is verified end-to-end on pull, so async never
  weakens the integrity story the synchronous path just got.

---

## 2. The one new component

```
                         ┌─────────────────────────────────────────┐
                         │  zero-knowledge store-and-forward node   │
   sender (CLI/browser)  │  • stores: ciphertext blob + min. meta   │   recipient
   ── encrypt client-    │  • holds:  NO keys, NO plaintext, ever   │   ── pull + decrypt
      side to recipient ─┼─▶ TTL / size cap / integrity hash       ─┼─▶ client-side
      pubkey OR link key │  • runs on: our TURN node OR org's box   │   (browser or CLI)
                         └─────────────────────────────────────────┘
        (the existing P2P direct path is unchanged and still preferred)
```

One server-side primitive — a **sealed mailbox** — unlocks all three gaps:
async-to-self, send-to-anyone, and the enterprise data plane. It is *additive*:
when both peers are online, filament still does direct P2P first (§6). The store
is the fallback the user opts into per-send, or that an always-on node provides
transparently.

---

## 3. The zero-knowledge store-and-forward node

### 3.1 Crypto: sealed before it leaves the sender

The invariant: **the server is handed ciphertext and a hash; it is never handed a
key and never sees plaintext.** This is the Bitwarden Send / Firefox Send model
([Bitwarden Send encryption](https://bitwarden.com/help/send-encryption/),
[how it works](https://bitwarden.com/blog/bitwarden-send-how-it-works/)) and the
Magic Wormhole mailbox shape ([docs](https://magic-wormhole.readthedocs.io/en/latest/welcome.html)).

**Two delivery modes, one store:**

**(a) Sealed-to-pubkey (recipient is a paired device).**
The sender already holds the recipient's pinned device secret / public key via the
pairing root (§1.1). It generates a fresh random **content key** `Kc`, encrypts the
file with an AEAD (`Kc`, per-chunk nonces), then **seals `Kc` to the recipient's
public key** (libsodium `crypto_box` / sealed box; X25519 + the device identity).
Upload = `{ sealed(Kc), AEAD(file), whole-file SHA-256, min-meta }`. The server
stores the bytes under a random blob id. Only the recipient's private key opens
`Kc`. This is structurally **Signal sealed-sender** — the recipient-resolving and
key material live inside an envelope the server cannot open
([Signal sealed sender](https://signal.org/blog/sealed-sender/)) — and
**Keybase per-device provisioning**, where an existing device encrypts secrets to
a new device's public key
([Keybase key model](https://keybase.io/blog/keybase-new-key-model)).

**(b) Sealed-to-link (recipient is not a filament user / not yet paired).**
The sender generates `Kc`, encrypts the file, and **embeds `Kc` in the URL
fragment** of a claim link:
`https://<host>/claim/<blobid>#<base64url(Kc)>`. The fragment after `#` is
**never sent to any server** by the browser — it is parsed and used purely
client-side, exactly as Bitwarden Send does
([Bitwarden Send how-it-works](https://bitwarden.com/blog/bitwarden-send-how-it-works/)).
The recipient opens the link, the in-page WASM (`frontend/src/pake/`) pulls the
ciphertext and decrypts locally. Zero install, zero account. For a stronger
variant, the link carries only a low-entropy code and the parties run a one-shot
PAKE to derive `Kc` (the SPAKE2 we already ship), so even a leaked link is one
online guess rather than a key — the option in §3.4 for sensitive sends.

In **both** modes the upload is the *output* of client-side encryption. There is
no code path where the store receives a key or a plaintext byte. (The phased plan,
§7, defines `seal_to_pubkey()` / `seal_to_link()` as new functions in
`cli/src` and a WASM-exposed `sealClaim()` in `pake/src/lib.rs`, reusing
`OsRngCompat` for `Kc` and the existing HKDF labels for domain separation.)

### 3.2 Three uses from one store

1. **Async-to-self (Syncthing-shaped).** Your laptop sends to your phone; the
   phone is asleep. Two sub-options, both opt-in: (i) **mesh park** — if you run an
   always-on filament node (a home server, a `up` acceptor), it holds the sealed
   blob and forwards when the phone wakes; (ii) **hosted mailbox** — our store (or
   the org's) parks it. The recipient device is already paired, so this is
   sealed-to-pubkey (3.1a); the phone pulls + decrypts on wake. No new trust:
   the parking node is just another zero-knowledge relay.

2. **Send-to-anyone (the WeTransfer killer).** A claim link (3.1b) a non-user
   opens in any browser, zero-install. This is the single feature that opens the
   email-a-link market filament cedes today — and it opens it *more securely than
   the incumbent* (§3.4).

3. **Enterprise data plane.** The org **self-hosts the same store inside its
   perimeter** (`--server` + a store endpoint it operates, §1.3). Every internal
   async transfer is sealed-client-side and parked on a box the org runs and
   audits. The org's file-sharing server holds only blobs it cannot read — a
   smaller liability than any plaintext-holding SaaS.

### 3.3 Operational controls

- **TTL / expiry / size caps.** Reuse the existing TTL idiom (`pair_create(...,
  ttl=600)`, the 600 s claim deadlines, the `brb` TTL capped at 300 s). Each blob
  gets a TTL (default short, e.g. 24 h, admin-configurable), a max-download count
  (1 by default, like an exploding send), and a size cap. Expiry deletes
  ciphertext; no grace, no recovery — ephemeral by default, the Firefox Send
  posture.
- **Integrity.** The blob carries the **whole-file SHA-256** from
  transport-resilience Phase 4 (GAP-5). The recipient verifies it post-decrypt
  before the file is considered complete; truncation/tamper is rejected exactly as
  on the synchronous path. Async inherits integrity-to-completion for free.
- **Honesty UX.** A parked/async transfer is visibly *"stored & forwarded — a
  server is holding this until the other side picks it up; still end-to-end
  encrypted, the store can't read it,"* reusing the amber `ui::Tone::Warn` surface
  and the exact wording grammar from transport-resilience §3.5 (true statements
  only; never "direct and private" when a store is in the path).
- **Metadata minimization.** The store keeps only what delivery requires: blob id,
  size, TTL, ciphertext hash, recipient *routing* token (a `channel_of`-style hash,
  not an identity), upload time. No filenames in clear (the filename is inside the
  AEAD), no sender identity in clear for link mode (sealed-sender property).

### 3.4 Security analysis — better than the incumbents, and the residual risks

**Why this is strictly better than what users do today.** The async path competes
with email attachments, Google Drive links, and WeTransfer — **all of which hand
the provider your plaintext.** Filament's store is zero-knowledge: it competes by
being the option where *the server literally cannot read the file*. That is the
"makes security better" claim made concrete — we are not adding a risky new
surface, we are giving users a sealed alternative to the unsealed thing they
already do.

| Risk | Mitigation |
|---|---|
| **Link leak (mode b).** Anyone with the full URL (incl. `#Kc`) can decrypt. | Default TTL short + one-download burn; fragment never logged server-side (it never reaches the server); for sensitive sends, the PAKE-link variant (§3.1) downgrades a leaked link to a single online guess; enterprise policy can disable link mode entirely (§5). This is the *same* exposure surface as Bitwarden Send, with the same mitigations. |
| **Forward secrecy / key rotation.** Sealed-to-pubkey reuses a long-lived device key; compromise of that key opens past parked blobs still in the store. | Per-blob ephemeral `Kc` already limits blast radius to *parked, unexpired* blobs (deleted blobs are unrecoverable — ephemerality *is* the forward-secrecy story for the store). Device keys are rotatable via re-pair / `device_set_cap` revocation; a roadmap item is an ephemeral pre-key per recipient (X3DH-style) so even parked blobs get FS. State explicitly: the store is **forward-secret for delivered/expired content, not for content sitting parked**, and TTL bounds that window. |
| **Metadata exposure.** A server that sees who-sends-to-whom is a privacy leak. | Sealed-sender (3.1a) hides sender identity in the envelope; routing tokens are hashes, not identities; §3.3 minimization. We match Signal's posture: the server learns a recipient routing token and a time, not a social graph. |
| **Abuse: malware parking / spam / illegal content.** A zero-knowledge store can't scan content — the same bind every E2E service has. | Defense is *metadata-shaped*, not content-shaped: per-uploader rate limits and size/TTL caps (cheap to enforce on ciphertext); abuse-report → blob-id revocation (delete ciphertext, can't inspect it); for the *enterprise* store, the org owns the uploader identity (SSO, §5) and its own AUP enforcement. The hosted store publishes that it is zero-knowledge and therefore *cannot* be a content host of record — abuse handling is takedown-by-id, not inspection. |
| **Server compromise.** Attacker gets the whole store. | They get ciphertext + minimal metadata. No keys, no plaintext. This is the entire point and the reason it beats the plaintext incumbents under the same threat. |

---

## 4. (reserved — see §5 for the enterprise layer)

---

## 5. The enterprise governance layer (opt-in, E2E-preserving)

Every control here is **off by default** and lives in an admin/org layer. It
extends the existing primitives; it never adds a key escrow or a plaintext tap.

### 5.1 SSO / identity — extend the pair-proof root, don't replace it

Today a device is trusted because *someone typed the spoken code* (§1.1). For an
org that is too ad-hoc. We bind enrollment to **OIDC / SAML, with SCIM for
lifecycle**: the device runs the normal SPAKE2 pairing, but the *nameplate /
rendezvous* is issued by the org's enrollment endpoint after the user authenticates
via the IdP, and the resulting device secret is tagged with the SSO subject. The
pairing crypto is unchanged — the DTLS-fingerprint-bound confirm MAC still runs —
but the trust statement upgrades from "whoever typed the code" to **"this device
belongs to authenticated employee `sub`."** This is exactly Headscale/Tailscale's
model: nodes auto-register against an OIDC provider (Authelia, Keycloak, Entra,
Google) instead of manual codes
([Headscale ACLs/OIDC](https://headscale.net/stable/ref/acls/)), and structurally
Keybase device provisioning, where a new device's key is signed into a per-user
identity chain ([Keybase sigchain](https://keybase.io/docs/sigchain)). SCIM
deprovisioning revokes the device secret centrally — the kill switch below.

### 5.2 Admin control plane + ACLs over the existing caps

Put a thin admin plane in front of `device_allows()` / `device_set_cap()`
(`cli/src/main.rs`). It expresses, centrally and versionably:

- **Who-reaches-whom** (peer ACLs), **which capabilities** (`transfer` vs `shell`),
  **device allow/deny**, **expiry**, **kill switch** (revoke a device's secret /
  caps org-wide — the SCIM-driven deprovision).

Adopt the **Tailscale/Headscale HuJSON ACL format**, which is Git-versionable and
GitOps-friendly ([Headscale ACLs](https://headscale.net/stable/ref/acls/)). The
enforcement point is unchanged: the deny-by-default cap check already in tree. The
admin plane is just a *policy source* the device consults at connect time — the
device still enforces locally, so a compromised control plane can *restrict* but
cannot *forge plaintext access* (it has no keys).

### 5.3 Audit that preserves E2E — the explicit compliance answer

**The audit log records metadata + file hashes + shell-session records,
NEVER decrypted content.** This is the way to satisfy compliance *without breaking
E2E*, and it is precisely how Tailscale does auditable infrastructure access:
config audit logs capture actor/action/target/time, and **SSH session recordings
are streamed E2E-encrypted to a recorder node the org runs — Tailscale never sees
them** ([Tailscale session recording](https://tailscale.com/kb/1246/tailscale-ssh-session-recording),
[auditable access](https://tailscale.com/blog/auditable-infrastructure-access)).

Filament's audit events:
- **Transfers:** `{actor SSO sub, recipient routing token, file SHA-256, size,
  timestamp, route (direct/relay/store)}` — enough to prove *what hash went where,
  when*, for chain-of-custody, with no plaintext.
- **Shell:** session open/close, device, granted cap, and — opt-in — a **session
  recording in asciinema format streamed to an org-run recorder node** over the
  authenticated link (Tailscale's exact pattern), so the recording is E2E to the
  org's own recorder, not to us.
- All of it goes to the org's SIEM via the self-hosted server; nothing transits a
  filament-operated server in the enterprise deployment.

### 5.4 Perimeter control

- **Self-hosted signaling** (`--server`/`FILAMENT_SERVER`, §1.3) +
  **self-hosted store** (§3.2.3) + **self-hosted TURN** (`backend/config.py`),
  so no control, rendezvous, or stored blob leaves the org's network. This is the
  Headscale value proposition — run the official clients against infrastructure you
  operate ([Headscale](https://github.com/juanfont/headscale)).
- **`--no-relay` / direct-only-within-corp** (§1.3): an org can forbid the TURN
  hop entirely on the internal network, so traffic is provably host-to-host.
- **MDM / posture gating** (Intune / Jamf): enrollment (§5.1) checks device posture
  before issuing the device secret; a non-compliant device never pairs.

### 5.5 Governed shell — "secure remote access without exposing SSH/VPN"

The web-shell already supports `--shell-user` (non-root, `runuser -l`),
per-device `shell` grants (deny-by-default), global PTY caps
(`MAX_PTYS_GLOBAL = 32`), and managed `authorized_keys`
(`cli/src/sshkeys.rs`). The enterprise layer adds: central grant/revoke via the
control plane (§5.2), optional session recording to the org recorder (§5.3), and
posture gating (§5.4). Pitch: **governed remote shell with no inbound port, no
SSH daemon on the public internet, no VPN concentrator** — the access rides the
same authenticated P2P link, gated by central ACLs and recorded E2E to the org.

### 5.6 The E2E-vs-DLP tension — named and resolved, not hand-waved

Corporate DLP wants to *inspect content*; E2E means *no one but the endpoints can*.
These genuinely conflict. We resolve it with a **default and an explicit, visible
escape hatch — never a silent backdoor:**

- **Default (E2E intact): metadata + hash audit.** Most compliance needs —
  chain-of-custody, "what left the building, to whom, when" — are satisfied by the
  hash/metadata log (§5.3) with **zero plaintext access**. This is the recommended
  posture and the one we lead with.
- **Opt-in content inspection point — only as an explicit org choice, and
  *surfaced*.** An org that *contractually requires* content DLP can configure a
  **named inspection endpoint** that terminates encryption at an org-controlled
  proxy *before* the store. Three non-negotiable properties: (1) it is **off by
  default**; (2) it is an **explicit org configuration**, never enabled by us;
  (3) it is **visible to the user on the wire** — the relay-honesty UX shows
  *"content inspected by <org> DLP — not end-to-end to the recipient"* in the same
  amber surface that already says "on relay." We refuse to make this invisible. The
  honest-UX machinery (`docs/design/transport-resilience.md` §3.5) exists precisely
  so that "a middlebox can read this" is never silent. An org that does not turn it
  on keeps full E2E; we never weaken the default to court the DLP buyer.

This is the same line Tailscale draws — E2E by default, org-run recorders/inspection
as an opt-in the customer operates — and it keeps filament's promise honest for the
99% who never enable it.

---

## 6. The gate: the common P2P user's experience is UNCHANGED

This is constraint #1, treated as a **release gate**: a feature ships only if the
casual, no-account, pair-and-go path is provably untouched. Per feature:

| Feature | Common-user path after this change | Where a naive design would add friction → how we avoid it |
|---|---|---|
| **Direct P2P send (today)** | Identical. Pair once, send. No account, no login, no config. Direct path is still *preferred* (the ladder `direct > holepunch > relay`, transport-resilience §2.1); the store is never tried when both ends are online. | Naive: route everything through the store "for consistency." Avoided: store is strictly fallback/opt-in; online peers never touch it. |
| **Async-to-self** | Additive. When the target device is asleep, the UI offers *"park it — your phone will get it when it wakes."* One tap. No new concept; the user already understands "send to my phone." | Naive: make the user configure a mailbox/account first. Avoided: if they run an always-on node it's automatic; the hosted mailbox needs no account (sealed-to-pubkey uses the existing pairing). |
| **Send-to-anyone (claim link)** | Additive. When the recipient isn't a paired peer, the UI offers *"get a link to share."* The sender gets a URL; the recipient opens it in any browser, zero install. | Naive: require the recipient to install filament or sign up. Avoided: link mode is browser-only, account-free; the WASM decryptor is already in the frontend. |
| **SSO enrollment** | An enrolled employee sees *"join via <company>"* once, through their normal company login. Thereafter it is the same pair-and-go filament. They never see ACLs, audit config, or store settings. | Naive: surface org policy/ACLs to the end user. Avoided: all governance is in the admin plane; the device just consults policy silently at connect time. |
| **Enterprise audit / ACL / DLP** | Invisible to the end user unless an admin enabled the inspection escape hatch (§5.6), in which case the *honest UX* tells them — which is a feature, not friction. | Naive: per-send consent dialogs. Avoided: ACLs enforce silently (deny-by-default already does); only the rare content-inspection case surfaces, and it *should*. |
| **`--no-relay` / self-host** | A personal user never sets these. They are admin/power-user flags with safe defaults (relay allowed for reliability, hosted server default). | Naive: ask every user to choose a server. Avoided: `FILAMENT_SERVER` has a working default; orgs override it via MDM, not the user. |

**Gate statement.** No feature in this doc adds a step, an account, a login, or a
config to the default P2P flow. Async is one optional tap that appears only when
it is the answer (peer offline / not a user). Enterprise config exists only in the
org layer. If an implementation would violate this, it does not ship until it
doesn't.

---

## 7. How six real systems handle this (and what we borrow)

| System | What it solves | What filament borrows |
|---|---|---|
| **Magic Wormhole** ([docs](https://magic-wormhole.readthedocs.io/en/latest/welcome.html)) | PAKE (SPAKE2) over a low-entropy code; numeric nameplate routes to a mailbox, words are the PAKE secret; one-time code → 1-in-65536 MITM. | Already our pairing model (`pake/src/lib.rs`); the **mailbox shape** is the template for the store's rendezvous (§3). |
| **Bitwarden Send / Firefox Send** ([Bitwarden](https://bitwarden.com/help/send-encryption/), [how-it-works](https://bitwarden.com/blog/bitwarden-send-how-it-works/)) | Zero-knowledge ephemeral send: client-side AEAD, **key in the URL `#fragment`** (never sent to server), TTL + download-burn. | The **claim-link / sealed-to-link** design (§3.1b), fragment-key handling, TTL/expiry/burn semantics. |
| **Signal sealed-sender** ([blog](https://signal.org/blog/sealed-sender/)) | Sender identity hidden inside an encrypted envelope the server can't open; server learns recipient + time, not the social graph. | **Sealed-to-pubkey** envelope + metadata minimization (§3.1a, §3.3); the "server learns a routing token, not an identity" posture. |
| **Keybase** ([key model](https://keybase.io/blog/keybase-new-key-model), [sigchain](https://keybase.io/docs/sigchain)) | Per-device keys; an existing device provisions a new one by signing/encrypting to its pubkey; per-user sigchain as the identity record. | The **device-to-device sealing** pattern for async-to-self (§3.2.1) and the model for SSO-bound device identity as an append-only org record (§5.1). |
| **Tailscale / Headscale** ([Headscale](https://github.com/juanfont/headscale), [ACLs](https://headscale.net/stable/ref/acls/), [session recording](https://tailscale.com/kb/1246/tailscale-ssh-session-recording), [auditable access](https://tailscale.com/blog/auditable-infrastructure-access)) | OIDC SSO node enrollment, Git-versionable HuJSON ACLs, config audit logs, **E2E SSH session recording to a customer-run recorder**, fully **self-hostable control plane**. | The **entire enterprise layer's shape** (§5): SSO enrollment extending the trust root, HuJSON ACLs over our caps, audit-without-content, self-host = Headscale, session recording E2E to org recorder, the E2E-vs-DLP line. |

The synthesis filament is uniquely positioned for: Wormhole-grade PAKE pairing +
Bitwarden-grade sealed ephemeral send + Tailscale-grade governance + Signal-grade
metadata hygiene, all on **one** zero-knowledge store, with the P2P default
untouched.

---

## 8. Phased plan (grounded in real files)

Sequencing principle: **build the zero-knowledge store first** — it is the single
highest-leverage piece, unlocks all three async uses *and* the enterprise data
plane at once, and is the thing whose security must be gotten right before any
governance rides on it. Each phase is independently shippable and gated.

**Phase A — The sealed store, send-to-anyone first (highest leverage).**
- New `seal_to_link()` in `cli/src` + `sealClaim()` WASM in `pake/src/lib.rs`
  (random `Kc` via `OsRngCompat`, AEAD file, fragment-key URL). New store endpoints
  on the backend (`backend/app.py`/`signaling.py`), reusing the TTL idiom of
  `pair_create(...)` and the `_Mem`/`_Redis` registry split for blob storage
  (ciphertext only). Browser claim page reusing `frontend/src/pake/` to decrypt.
- Reuse transport-resilience **Phase 4 whole-file SHA-256** as the blob integrity
  gate. Reuse the amber honesty UX for "stored & forwarded."
- **Gate:** a non-user opens a link in a clean browser and decrypts; the server is
  shown (under test) to hold only ciphertext + minimal metadata; the default P2P
  send path is byte-for-byte unchanged when both peers are online.
- *Why first:* opens the WeTransfer market with the smallest surface, and it is the
  security-critical core everything else builds on.

**Phase B — Sealed-to-pubkey + async-to-self.**
- `seal_to_pubkey()` (libsodium sealed box to the recipient's pinned device key
  from `devices.json`); always-on `up` nodes park + forward; hosted mailbox parks
  for sleeping paired devices. Recipient pulls + AEAD-verifies on wake.
- **Gate:** laptop→sleeping-phone delivers on wake, sealed; no account added;
  online direct send still preferred.

**Phase C — Enterprise perimeter (self-host, the cheap governance win).**
- Document + harden self-hosting the store + signaling + TURN inside a perimeter;
  wire `--no-relay` as the direct-only-within-corp control. No new crypto — this is
  packaging the existing `--server`/TURN/`--no-relay` knobs for an org.
- **Gate:** an org runs the full stack with zero traffic leaving its network.

**Phase D — SSO enrollment + admin ACL plane + kill switch.**
- OIDC/SAML+SCIM enrollment issuing SSO-tagged device secrets over the existing
  SPAKE2 pairing (§5.1); admin plane in front of `device_allows()` /
  `device_set_cap()` speaking HuJSON ACLs (§5.2); SCIM deprovision = central
  revoke.
- **Gate:** revoking a user in the IdP kills their device's access org-wide; the
  end-user enrollment is one company-login tap; the personal user sees nothing.

**Phase E — Audit-without-content + governed shell recording + the DLP escape
hatch.**
- Metadata/hash transfer log + shell session records to the org SIEM (§5.3);
  opt-in asciinema session recording streamed E2E to an org recorder (Tailscale
  pattern); the explicit, *surfaced*, off-by-default content-inspection endpoint
  (§5.6).
- **Gate:** compliance can prove what-hash-went-where with zero plaintext; the
  inspection hatch is invisible-free (always shown when on) and off unless the org
  turns it on.

**Sequencing rationale.** A (sealed store) is the keystone — it is the security
core, the highest-leverage single piece, and the prerequisite for B and the
enterprise data plane. B extends it to paired devices with no new server. C is
almost-free governance (repackage existing self-host knobs). D adds the identity
spine. E adds the compliance surface last, because it is the most sensitive and
must sit on a proven, audited store. At no phase does the common user's pair-and-go
default change.

---

## 9. Decision

Ship the **zero-knowledge store-and-forward node** as the one new server-side
primitive, and expose async + enterprise as **opt-in layers** on it and the
existing P2P core. It is the rare move that closes filament's two biggest market
gaps while making the *default user's* experience no harder and the *overall*
security posture **better** — because the async path it adds is a sealed
replacement for the plaintext habits (email, Drive, WeTransfer) users have today,
and the enterprise path it adds is a self-hosted, hash-audited, E2E-preserving
alternative to the plaintext SaaS that corporate IT otherwise forces. Start with
Phase A.

---

### Sources

- Bitwarden Send encryption / how-it-works: https://bitwarden.com/help/send-encryption/ · https://bitwarden.com/blog/bitwarden-send-how-it-works/
- Signal sealed sender: https://signal.org/blog/sealed-sender/
- Magic Wormhole (SPAKE2 / mailbox): https://magic-wormhole.readthedocs.io/en/latest/welcome.html
- Keybase key model / sigchain: https://keybase.io/blog/keybase-new-key-model · https://keybase.io/docs/sigchain
- Headscale (self-host control plane) / ACLs: https://github.com/juanfont/headscale · https://headscale.net/stable/ref/acls/
- Tailscale SSH session recording / auditable access: https://tailscale.com/kb/1246/tailscale-ssh-session-recording · https://tailscale.com/blog/auditable-infrastructure-access
