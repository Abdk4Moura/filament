# Bug 4 — code unification assessment (ASSESS ONLY)

Status: the **conservative fix shipped**. This note scopes what a *full*
unification would take, the files/protocols involved, the risks, and a
recommendation. It does **not** propose implementing a wire-protocol change.

## What "Bug 4" was

Two different speakable codes look alike but are not interchangeable:

| | Transfer code | Pairing code |
|---|---|---|
| Shape | `word-word-NNNN` (**3 segments**) | `adj-animal-extra-NNNN` (**4 segments**) |
| Minted by | `filament send --code` | `filament pair` / browser "create code" |
| Consumed by | `filament recv` (and bare `filament <code>`) | `filament pair <code>` / browser "pair with code" |
| Purpose | one-time rendezvous to **move both peers into a room and stream files**, then forget | run **SPAKE2** and persist a long-lived pairing **secret** (a known device) |
| Server events | `pair-create` → `pair-code`; `pair-claim` (no `v`) → `pair-matched` | `pair-create {v:2, nameplate}` → `pair-ok`; `pair-claim {v:2, nameplate}` → `pair-matched` |
| What crosses the wire | whole code (server mints + echoes it) | **nameplate only**; the words feed SPAKE2 and never leave the client |

The bug: typing one kind of code into the wrong consumer silently never
connected (a transfer code into `pair`, or a pairing code into `recv`).

## The conservative fix (already shipped)

Two cheap segment-shape detectors plus clear redirect errors. Detection is by
segment count + charset only — it never authenticates (PAKE/SPAKE2 still does).

- `cli/src/main.rs`
  - `regex_lite_code()` (~L307): true for 3-seg transfer codes.
  - `looks_like_pake_code()` (~L323): true for 4-seg pairing codes.
  - `pair` command (~L1158): a 3-seg code → bail with "looks like a TRANSFER
    code, use `recv`".
  - `recv` (~L3516): a 4-seg code → bail with "looks like a PAIRING code, use
    `pair`".
  - bare-arg dispatch (~L2537-2548): `filament <3-seg>` → `recv`;
    `filament <4-seg>` → `pair`; a path → `send --code`.
  - tests at ~L5206 assert the two detectors never both match one string.

The two code worlds remain **separate**; the fix only makes a mismatch fail
loudly with the right next step instead of hanging.

## What FULL unification would require

Goal: one code that any consumer (browser "pair with code", CLI `recv`, CLI
`pair`) can accept — either the two protocols converge, or a single entry
point dispatches to the right one transparently.

### Files / protocols involved

- **Server** `backend/signaling.py`
  - `on_pair_create` (~L423): branches on `v==2` (nameplate-only) vs v1
    (server mints whole `word-word-NNNN`). Different responses: `pair-ok` vs
    `pair-code`.
  - `on_pair_claim` (~L496): `v==2` reads `nameplate`; v1 reads the whole
    `code`. Both end in `pair-matched`, but v2 then runs SPAKE2 client-side and
    v1 is "just go to the room".
  - `_NAMEPLATE_RE`, `_mint_pair_code`, `_norm_code`, the `Registry.pair_*`
    methods, the claim rate-limiter.
- **Frontend** `frontend/src/lib/pairing.js` (`parseSpokenCode`, `splitCode`,
  `PakePairing`) and `frontend/src/lib/useFilament.js`
  (`pairWithCode`/`generateCode` → SPAKE2; the **browser has no `recv` path** —
  it can only PAKE-pair, never claim a legacy transfer code).
- **CLI** `cli/src/main.rs` `send --code` (mint+offer) and `recv` (claim+room)
  legacy paths vs the `pair` PAKE ceremony; `cli/src/session.rs`; the shared
  `filament_pake` crate (`pake/`, `mint_words`/`mint_nameplate`, SPAKE2).

### Approaches

1. **Converge on PAKE for everything.** Make `send --code`/`recv` also run
   SPAKE2 (transfer becomes "pair ephemerally, then send, then forget the
   secret"). Cleanest end state; biggest change — touches the transfer hot path,
   the browser would gain a real receive path, and the server's v1 mint/echo
   branch could eventually retire.
2. **Single dispatching entry point** that keys off the segment count and
   routes to the existing transfer vs pairing machinery (essentially the
   conservative fix, promoted from "error message" to "do the right thing
   automatically"). Smaller, but keeps two protocols alive forever.
3. **One code carrying a discriminator** (e.g. a leading tag the parser strips)
   so length collisions are impossible. Requires re-minting format on all three
   clients + server simultaneously.

### Risks

- **Wire-format break.** Code shape and the `pair-*` event contract are shared
  by browser, CLI, and server, all independently deployed/cached. Any change is
  a coordinated multi-client migration; mixed-version pairs must degrade
  cleanly, not hang (exactly the failure Bug 4 created).
- **Security surface.** The v2 path's whole point is **relay-blind**: words
  never reach the server, SPAKE2 + DTLS-fingerprint confirmation gives a secret
  no server/MITM can forge. The legacy transfer path is server-mediated by
  design (the server mints and sees the code). Folding transfer into PAKE adds
  the ceremony's latency/complexity to every quick send; doing the reverse
  would *weaken* pairing. Don't blur the trust boundary to save a word.
- **Entropy / rate-limit coupling.** The 5-claims/min limiter and the 21.8-bit
  code entropy are sized for the legacy claim sweep; merging code spaces changes
  the threat model.
- **UX regression.** Transfer codes are intentionally one word shorter and
  one-shot; pairing codes are longer and grant lasting trust. A unified code
  must not make a casual one-time send *feel* like granting a permanent device.
- **Browser asymmetry.** The browser today can PAKE-pair but cannot `recv` a
  legacy transfer code at all. True unification implies building (and
  security-reviewing) a browser receive path — non-trivial scope on its own.

## Recommendation

**Keep the conservative fix; do not unify the wire protocol now.** The two
codes encode two genuinely different trust models (ephemeral server-mediated
transfer vs. persistent relay-blind pairing). The shipped detect-and-redirect
already removes the only real user harm — the silent never-connect — at near-zero
risk and with no migration.

If unification is ever pursued, prefer **Approach 1 (converge on PAKE)** as the
long-term direction, but gate it behind: (a) a browser receive path,
(b) a versioned, mixed-fleet migration plan with graceful downgrade, and
(c) a security review confirming the transfer path's new ceremony doesn't
weaken pairing or balloon quick-send latency. Until all three exist, the
clear-error redirect is the correct stopping point.
