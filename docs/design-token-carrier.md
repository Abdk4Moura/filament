# Token carrier: Biscuit for delegable tokens

> Status: decided, pending verification. Records the read-only spike into
> `biscuit-auth` (Biscuit tokens, biscuitsec.org) as the carrier for filament's
> delegable capability/pass tokens, and the acceptance list for the Rust
> adoption PR. No code yet. This doc does not modify the enrollment flow.

## Decision

- **Biscuit (crate `biscuit-auth` 6.0.0) is the CARRIER for delegable
  capability/pass tokens only.** Where a holder must narrow a credential it
  already holds (tighten expiry, drop a capability, restrict a resource),
  Biscuit does this offline with no root key.
- **The possession-bound invitation stays for enrollment.** The compact
  invitation in `crates/filament-cap/src/ephemeral.rs` (enroll keypair + nonce
  bound `enrollment_possession_msg`) remains the enrollment artifact. Biscuit is
  a bearer credential; it has no proof-of-possession, no single-use/N-use/burn,
  and no nonce binding, which are exactly the properties enrollment relies on.
- **The ledger and evaluator stay ours.** `crates/filament-cap/src/capability.rs`
  (`evaluate`, `evaluate_grants_only`, the grant store, the ratchet) is
  unchanged in authority. Biscuit is a carrier and a Datalog evaluator, not a
  replacement for the ledger.
- **`because: [op ids]` is the LEDGER's job.** Op ids are encoded as fact terms
  and queried; never rely on Biscuit provenance. The Rust API has no structured
  origin/reason surface (see Findings), so provenance is not available to build
  an audit trail from.

## Scope

In: delegable capability/pass tokens (a fleet device or person pass that may be
narrowed further downstream). Out: the enrollment invitation, the ledger, the
gate, and the human-speakable short code (see invariant below).

## Card contract invariant: the SHORT word code is never a carrier

The `fc1 + base64url(CBOR{...})` card MAY embed a Biscuit token as one CBOR byte
string (`Biscuit::to_vec()`, no double base64; Biscuit has no CBOR encoding of
its own, so the bytestring is opaque and idiomatic).

The SHORT form (8-10 speakable words) is a **rendezvous/fingerprint reference
and is NEVER a carrier**. Reason, as an invariant: the smallest observed Biscuit
token is 169 bytes = 1352 bits, while 8-10 words carry only 88-110 bits at a
2048-word list (103-129 bits at 7776). A full token needs ~105-123 words. A
short word code must therefore reference a token held elsewhere, never encode
one. Do not let a future "make the code carry the card" change violate this.

## Findings (from the spike)

1. **Attenuation without the issuer key: yes.** A holder needs only the token
   bytes, which carry `Proof.nextSecret`; `Biscuit::append(BlockBuilder)` mints a
   fresh block-local keypair and signs with the holder's key. Existing blocks
   cannot be removed ("cannot remove existing blocks without invalidating the
   signature"), and scopes stop later blocks widening rights (a block's
   rules/checks default to authority + current + authorizer facts).
2. **Authorizer reasons: no structured API in Rust 6.0.0.** `Authorizer::query`
   returns facts (`Vec<T>`), `datalog::Fact` has no origin field, and `dump()`
   strips origins. `Origin`/`FactSet::iter_all()` are public but the Authorizer's
   `world` is private. Only escape is parsing `print_world()` text
   (`// origin: N`), and an origin is a block index, not a CapOp id.
3. **Revocation + time.** `Biscuit::revocation_identifiers()` returns the 64-byte
   signature of each block (authority first), unique per mint; revoking the
   authority id tombstones the whole token. Rust does not auto-inject
   `revocation_id` facts, so the app adds facts plus a check/deny. Blocks carry
   `check if time($t), $t < <literal>`; the clock is supplied by the verifier
   (`AuthorizerBuilder::time()` uses `SystemTime::now()`), never at mint.
4. **Sealing exists but does not bind a device.** `Biscuit::seal()` makes the
   token non-attenuable (`append` then errors `AppendOnSealed`). It is still a
   bearer token, so sealing blocks sub-delegation only; device binding stays in
   the possession layer.
5. **Size.** Measured from real `biscuit-auth/samples/*.bc`: 1 block/1 symbol =
   169 B, 2 blocks/3 symbols = 358 B, 3 blocks/3 symbols = 454 B, 3 blocks/6
   symbols = 535 B. Raw to URL-safe base64 is about 1.34x (228, 480, 608, 716
   chars). Structural floor per `SignedBlock` is 108 B fixed plus block bytes and
   a ~40 B wrapper. A representative 3-block token is an estimated 300-550 B,
   within QR budget; the word-code budget is unreachable (see invariant).
6. **Deps.** Pure Rust, no C: `ed25519-dalek` 2.0 plus `p256`/`ecdsa`/
   `elliptic-curve` (RustCrypto), `prost`, `nom`, `regex`. No `ring`, no
   OpenSSL, no `protoc` at build. Costs a second Ed25519 implementation and a
   second sha2 major (0.9) unless feature flags or an adapter remove them.
7. **Card format.** Biscuit's container is its own protobuf `Biscuit` message;
   text form is URL-safe base64, optionally `biscuit:`-prefixed. Embedding
   `to_vec()` as one CBOR bytestring in our card is idiomatic; the only friction
   is two versioning axes, which Biscuit already owns internally.

## Acceptance list for the Rust adoption PR (five conditions, verbatim)

1. representative token <=600 B
2. op-id facts reconstruct a satisfied set
3. holder attenuation + seal() behave as specified
4. revocation-id stability across re-serialisation
5. a default-features=false build measuring the binary-size delta (and whether
   the second ed25519/sha2 can be avoided by feature flags or an adapter)

What each condition checks, for the implementing PR:

1. Mint a representative card (6 symbols, ~6 facts, an expiry check and a
   device-pub fact) and assert `serialized_size()` <= 600 B and base64 <= 800
   chars.
2. Encode op ids as fact terms; confirm a query or `print_world()` can
   reconstruct the set of satisfied op ids, then own that mapping in the ledger.
3. A holder holding only token bytes can append a stricter expiry and a
   capability-removal check; issuer checks still bind; original token unchanged;
   `append` on a sealed token fails.
4. Tombstone the authority revocation id, assert validation fails, and assert
   ids are stable across re-serialisation and unique across mints.
5. Build once with default features and once with `default-features = false`,
   diff binary size, and report whether the duplicate ed25519/sha2 can be
   dropped.

## UCAN note

UCAN's audience binding (the `aud` field must match the recipient's DID and an
invocation must be signed by the invoker) is the same property filament already
gets from its nonce-bound possession proof, so UCAN's headline advantage over
Biscuit is already covered by our enrollment layer, while UCAN adds per-hop
signed CBOR-with-CID chains that are heavier than a Biscuit token.

## Evidence

- Spec: https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md
  (Overview, Scopes, Revocation identifiers, Signature (appending/sealing),
  Format).
- Rust API: https://docs.rs/biscuit-auth/6.0.0/biscuit_auth/struct.Biscuit.html
  (`append`, `seal`, `revocation_identifiers`, `serialized_size`, `to_base64`),
  `struct.Authorizer.html` (`query`, `dump`), `datalog/struct.Fact.html`.
- Source: https://github.com/biscuit-auth/biscuit-rust (Cargo.toml,
  token/builder/authorizer.rs `time`, token/third_party.rs `AppendOnSealed`,
  format/schema.proto, samples/*.bc sizes, build.rs).
- UCAN: https://github.com/ucan-wg/spec/blob/main/README.md.

## Sequencing

Unchanged: #309 first, then card, certify, ledger contract + model, then the
carrier PR against the acceptance list above.
