//! Filament PAKE core — the single SPAKE2 implementation shared by the CLI
//! (native) and the browser (wasm32). See docs/L1-pake-protocol.md.
//!
//! Design (L1-a):
//!   - `Spake2::<Ed25519Group>::start_symmetric` (either peer may initiate).
//!     BOTH sides MUST pass the identical Password AND Identity (§3.1 footgun)
//!     or they derive two valid-but-different K with no error.
//!   - `start()` returns the 33-byte outbound element + opaque state.
//!   - `finish()` consumes the peer's element and returns **K itself** (not
//!     straight to the secret) — K is needed for BOTH the confirmation MAC and
//!     the HKDF-to-pinned-secret.
//!   - `confirm_mac(K, dir, fp_lo, fp_hi, caps)` is the §4 key-confirmation MAC,
//!     folding the SORTED DTLS fingerprints AND the agreed capability set, so a
//!     server that substitutes a DTLS cert OR rewrites caps breaks the MAC.
//!   - `secret_from_k(K)` is the §5.1 HKDF to the 32-byte pinned secret (agreed,
//!     never transmitted).
//!
//! Production RNG is OsRng (getrandom -> /dev/urandom on native,
//! crypto.getRandomValues on wasm). The spike's seeded RNG and C-ABI handle
//! table are GONE.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

type HmacSha256 = Hmac<Sha256>;

pub mod words;

/// The opaque SPAKE2 session type, re-exported so consumers (the CLI) can hold
/// it between `start` and `finish` without depending on the `spake2` crate.
pub type PakeState = Spake2<Ed25519Group>;

/// The production OS CSPRNG, as an `RngCore + CryptoRng`.
pub fn os_rng() -> impl RngCore + CryptoRng {
    OsRngCompat
}

/// Domain-separation prefix for the SPAKE2 identity. BOTH peers bind to the
/// nameplate so a code is domain-separated (spec §3.1).
const IDENTITY_PREFIX: &[u8] = b"filament-pair-pake-v1:";
/// HKDF info that turns K into the pinned device secret (spec §5.1).
const SECRET_INFO: &[u8] = b"filament-pair-pake-v1:pinned-secret";
/// Confirmation-MAC label (spec §4). Distinct from channel/proof labels — no
/// cross-context key reuse (spec §9).
const CONFIRM_LABEL: &[u8] = b"filament-pake-confirm-v1";

/// The full SPAKE2 identity string for a nameplate.
fn identity_bytes(nameplate: &[u8]) -> Vec<u8> {
    let mut v = IDENTITY_PREFIX.to_vec();
    v.extend_from_slice(nameplate);
    v
}

/// Begin a symmetric SPAKE2 exchange using the OS CSPRNG.
///
/// `password` = the normalized adj-animal words (NEVER sent to the server).
/// `nameplate` = the numeric routing suffix (the only thing the server sees).
///
/// Returns the opaque session state (consumed by `finish`) and the 33-byte
/// outbound SPAKE2 element to relay to the peer.
pub fn start(password: &[u8], nameplate: &[u8]) -> (Spake2<Ed25519Group>, Vec<u8>) {
    start_with_rng(password, nameplate, OsRngCompat)
}

/// Test/interop seam: begin with a caller-supplied RNG. Production uses
/// `start` (OsRng). Kept `pub` so deterministic interop harnesses can pin the
/// scalar — NEVER used on the real pairing path.
pub fn start_with_rng<R: RngCore + CryptoRng>(
    password: &[u8],
    nameplate: &[u8],
    rng: R,
) -> (Spake2<Ed25519Group>, Vec<u8>) {
    Spake2::<Ed25519Group>::start_symmetric_with_rng(
        &Password::new(password),
        &Identity::new(&identity_bytes(nameplate)),
        rng,
    )
}

/// Finish the exchange: consume the peer's 33-byte element, return the shared
/// key K (raw bytes). `None` if the element is malformed. NOTE: SPAKE2 alone
/// does NOT prove the peer derived the same K — the caller MUST run key
/// confirmation (`confirm_mac`) before trusting K.
pub fn finish(state: Spake2<Ed25519Group>, peer_msg: &[u8]) -> Option<Vec<u8>> {
    state.finish(peer_msg).ok()
}

/// §4 key-confirmation MAC. Folds the SORTED DTLS fingerprints (so a DTLS-layer
/// MITM is detected, §5.2) AND the agreed capability set (so a server that
/// rewrites caps breaks the MAC, §6.1). `dir` is the direction tag
/// ("A->B"/"B->A") that prevents reflection in the symmetric variant.
///
/// `caps` is the canonical capability string (callers MUST pass the SAME
/// canonical form on both sides — see `canonical_caps`).
pub fn confirm_mac(k: &[u8], dir: &str, fp_lo: &str, fp_hi: &str, caps: &str) -> Vec<u8> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(k).expect("HMAC accepts any key length");
    m.update(CONFIRM_LABEL);
    m.update(dir.as_bytes());
    // Length-prefix the variable fields so concatenation is unambiguous (no
    // boundary-confusion between fp_hi and caps).
    update_lp(&mut m, fp_lo.as_bytes());
    update_lp(&mut m, fp_hi.as_bytes());
    update_lp(&mut m, caps.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn update_lp(m: &mut HmacSha256, field: &[u8]) {
    m.update(&(field.len() as u32).to_le_bytes());
    m.update(field);
}

/// Canonical role derivation for the symmetric variant (§3.1 / §4).
///
/// `start_symmetric` makes neither peer inherently "A" or "B", but the
/// confirmation MAC's direction tag MUST differ between the two sides or
/// honest pairing fails (both send the same tag) / reflection becomes possible.
/// We break the symmetry with a value BOTH sides agree on: the SORTED
/// fingerprints. The side that owns `fp_lo` is "A"; it SENDS "A->B" and EXPECTS
/// "B->A". The other side is "B"; it SENDS "B->A" and EXPECTS "A->B".
///
/// Returns `(send_dir, expect_dir)`. Both sides feed the SAME sorted (fp_lo,
/// fp_hi) into the MAC; only the direction tag distinguishes them.
pub fn confirm_dirs(my_fp: &str, fp_lo: &str) -> (&'static str, &'static str) {
    if my_fp == fp_lo {
        ("A->B", "B->A") // I am "A"
    } else {
        ("B->A", "A->B") // I am "B"
    }
}

/// Sort two fingerprints into (lo, hi) — the SAME ordering both sides and
/// `proof_for` use, so the MAC inputs match byte-for-byte.
pub fn sort_fps<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a < b { (a, b) } else { (b, a) }
}

/// High-level: compute the confirmation MAC THIS side sends, given its own and
/// the peer's fingerprint and the agreed caps. Handles sorting + role
/// derivation so callers can't get the symmetry wrong.
pub fn our_confirm(k: &[u8], my_fp: &str, their_fp: &str, caps: &str) -> Vec<u8> {
    let (lo, hi) = sort_fps(my_fp, their_fp);
    let (send_dir, _expect) = confirm_dirs(my_fp, lo);
    confirm_mac(k, send_dir, lo, hi, caps)
}

/// High-level: verify the peer's received confirmation MAC under OUR K. Returns
/// true iff it matches what we expect from the peer (derives the peer's
/// direction tag from the SAME sorted fingerprints).
pub fn verify_peer_confirm(k: &[u8], my_fp: &str, their_fp: &str, caps: &str, received: &[u8]) -> bool {
    let (lo, hi) = sort_fps(my_fp, their_fp);
    let (_send, expect_dir) = confirm_dirs(my_fp, lo);
    let expected = confirm_mac(k, expect_dir, lo, hi, caps);
    ct_eq(&expected, received)
}

/// Constant-time comparison for MAC verification.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/// §5.1 derive the 32-byte pinned device secret from K, returned as 64-hex.
/// The identity is AGREED, never transmitted. Drops straight into the existing
/// devices.json `{name, secret}` store, `channel_of`, and `proof_for`.
pub fn secret_from_k(k: &[u8]) -> String {
    let hk = Hkdf::<Sha256>::new(None, k);
    let mut out = [0u8; 32];
    hk.expand(SECRET_INFO, &mut out)
        .expect("32 bytes is a valid HKDF length");
    hex::encode(out)
}

/// Normalize a spoken code the SAME way on every client (mirrors the backend
/// `_norm_code`): lowercase, whitespace -> dashes, strip anything outside
/// `[a-z0-9-]`, cap at 48 chars. This MUST be byte-identical to the JS
/// `normCode` or the two sides feed different passwords to SPAKE2 and derive
/// different K (the §3.1 footgun in another guise).
pub fn norm_code(raw: &str) -> String {
    let lowered = raw.trim().to_lowercase();
    // collapse any run of whitespace to a single dash
    let mut spaced = String::with_capacity(lowered.len());
    let mut prev_ws = false;
    for ch in lowered.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                spaced.push('-');
            }
            prev_ws = true;
        } else {
            spaced.push(ch);
            prev_ws = false;
        }
    }
    let filtered: String = spaced.chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-').collect();
    filtered.chars().take(48).collect()
}

/// Split a normalized spoken code into (nameplate, password). The nameplate is
/// the TRAILING numeric group (after the LAST dash); the password is everything
/// before it. Mirrors the JS `splitCode`. Example:
///   "brave-otter-ruby-314" -> nameplate "314", password "brave-otter-ruby".
/// If there is no dash, the whole thing is treated as the nameplate (password
/// empty) — a degenerate input that will simply fail confirmation.
pub fn split_code(normalized: &str) -> (String, String) {
    match normalized.rfind('-') {
        Some(i) => (normalized[i + 1..].to_string(), normalized[..i].to_string()),
        None => (normalized.to_string(), String::new()),
    }
}

/// Split a user-CHOSEN code (creation side) into (password, optional nameplate).
/// Trims surrounding dashes. The trailing dash-group is the nameplate ONLY if it
/// matches the server nameplate shape (3-5 ASCII digits); otherwise the whole
/// trimmed string is the password and the nameplate is machine-assigned.
///
/// Unlike `split_code` (which strips the trailing group UNCONDITIONALLY as the
/// nameplate — correct for CLAIMING a minted code), this is the CREATION side
/// where a two-word phrase like `gigantic-element` must keep BOTH words as the
/// password. Mirrors the JS `splitChosenCode`.
pub fn split_chosen_code(normalized: &str) -> (String, Option<String>) {
    let trimmed = normalized.trim_matches('-');
    if let Some(i) = trimmed.rfind('-') {
        let after = &trimmed[i + 1..];
        let before = &trimmed[..i];
        if !before.is_empty()
            && (3..=5).contains(&after.len())
            && after.bytes().all(|b| b.is_ascii_digit())
        {
            return (before.to_string(), Some(after.to_string()));
        }
    }
    (trimmed.to_string(), None)
}

/// Canonicalize a capability set so BOTH sides MAC the identical string:
/// trimmed, lowercased, de-duplicated, sorted, comma-joined. Empty set -> "".
pub fn canonical_caps(caps: &[String]) -> String {
    let mut v: Vec<String> = caps
        .iter()
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v.join(",")
}

// --------------------------------------------------------------------------
// OsRng wrapper. spake2 0.4 needs rand_core 0.6's RngCore+CryptoRng. We feed
// it directly from getrandom so there is no extra RNG dependency and the same
// code path is used on native and wasm.
// --------------------------------------------------------------------------
struct OsRngCompat;
impl RngCore for OsRngCompat {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS CSPRNG unavailable");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|e| rand_core::Error::from(e.code()))
    }
}
impl CryptoRng for OsRngCompat {}

// --------------------------------------------------------------------------
// wasm-bindgen surface (browser). Replaces the spike's C-ABI Mutex handle
// table with a real JS-owned object. The browser drives: new PakeSession ->
// .message() -> (relay) -> .finish(peer) -> .confirmMac(...) / .secret().
// --------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// A live SPAKE2 session for the browser. Owns the secret scalar; consumed
    /// by `finish`.
    #[wasm_bindgen]
    pub struct PakeSession {
        state: Option<Spake2<Ed25519Group>>,
        msg: Vec<u8>,
        k: Option<Vec<u8>>,
    }

    #[wasm_bindgen]
    impl PakeSession {
        /// Begin symmetric SPAKE2 with OsRng (crypto.getRandomValues).
        #[wasm_bindgen(constructor)]
        pub fn new(password: &[u8], nameplate: &[u8]) -> PakeSession {
            let (state, msg) = start(password, nameplate);
            PakeSession { state: Some(state), msg, k: None }
        }

        /// The 33-byte outbound SPAKE2 element to relay to the peer.
        #[wasm_bindgen(js_name = message)]
        pub fn message(&self) -> Vec<u8> {
            self.msg.clone()
        }

        /// Consume the peer's element; derive K (held internally). Returns true
        /// on success. After this, `confirm_mac`/`secret` are available.
        #[wasm_bindgen(js_name = finish)]
        pub fn finish_js(&mut self, peer_msg: &[u8]) -> bool {
            let Some(state) = self.state.take() else { return false };
            match super::finish(state, peer_msg) {
                Some(k) => {
                    self.k = Some(k);
                    true
                }
                None => false,
            }
        }

        /// §4 confirmation MAC THIS side sends. Handles fingerprint sorting +
        /// symmetric role derivation so the browser can't get it wrong.
        #[wasm_bindgen(js_name = ourConfirm)]
        pub fn our_confirm_js(&self, my_fp: &str, their_fp: &str, caps: &str) -> Option<Vec<u8>> {
            self.k.as_ref().map(|k| super::our_confirm(k, my_fp, their_fp, caps))
        }

        /// Verify the peer's confirmation MAC under our K. true == confirmed.
        #[wasm_bindgen(js_name = verifyPeerConfirm)]
        pub fn verify_peer_confirm_js(&self, my_fp: &str, their_fp: &str, caps: &str, received: &[u8]) -> bool {
            match self.k.as_ref() {
                Some(k) => super::verify_peer_confirm(k, my_fp, their_fp, caps, received),
                None => false,
            }
        }

        /// §5.1 derived 64-hex pinned secret. None until `finish` succeeds.
        #[wasm_bindgen(js_name = secret)]
        pub fn secret_js(&self) -> Option<String> {
            self.k.as_ref().map(|k| super::secret_from_k(k))
        }
    }

    /// Canonicalize a JS string[] capability set (for confirm-MAC parity).
    #[wasm_bindgen(js_name = canonicalCaps)]
    pub fn canonical_caps_js(caps: Vec<JsValue>) -> String {
        let v: Vec<String> = caps.into_iter().filter_map(|j| j.as_string()).collect();
        super::canonical_caps(&v)
    }

    /// Constant-time MAC comparison exposed for the browser verify step.
    #[wasm_bindgen(js_name = ctEq)]
    pub fn ct_eq_js(a: &[u8], b: &[u8]) -> bool {
        super::ct_eq(a, b)
    }

    /// Normalize a spoken code (mirrors backend `_norm_code`).
    #[wasm_bindgen(js_name = normCode)]
    pub fn norm_code_js(raw: &str) -> String {
        super::norm_code(raw)
    }

    /// Split a normalized code into [nameplate, password].
    #[wasm_bindgen(js_name = splitCode)]
    pub fn split_code_js(normalized: &str) -> Vec<JsValue> {
        let (np, pw) = super::split_code(normalized);
        vec![JsValue::from_str(&np), JsValue::from_str(&pw)]
    }

    /// Split a user-CHOSEN code into [password, nameplate_or_empty_string]. The
    /// trailing group is the nameplate ONLY if it is 3-5 ASCII digits.
    #[wasm_bindgen(js_name = splitChosenCode)]
    pub fn split_chosen_code_js(normalized: &str) -> Vec<JsValue> {
        let (pw, np) = super::split_chosen_code(normalized);
        vec![
            JsValue::from_str(&pw),
            JsValue::from_str(np.as_deref().unwrap_or("")),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic RNG for tests ONLY (mirrors the old spike seed path) so two
    // in-process sides can be reproduced. NEVER used in production.
    struct SeedRng {
        state: [u8; 32],
        counter: u64,
        buf: [u8; 32],
        pos: usize,
    }
    impl SeedRng {
        fn new(seed: [u8; 32]) -> Self {
            SeedRng { state: seed, counter: 0, buf: [0u8; 32], pos: 32 }
        }
        fn refill(&mut self) {
            use sha2::Digest;
            let mut h = Sha256::new();
            h.update(self.state);
            h.update(self.counter.to_le_bytes());
            self.buf.copy_from_slice(&h.finalize());
            self.counter += 1;
            self.pos = 0;
        }
    }
    impl RngCore for SeedRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for d in dest.iter_mut() {
                if self.pos >= 32 {
                    self.refill();
                }
                *d = self.buf[self.pos];
                self.pos += 1;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for SeedRng {}

    // Two honest sides with DISTINCT fingerprints, using the REAL role
    // derivation (no hardcoded A/B). fp_a and fp_b are each side's own fp.
    const FP_A: &str = "SHA-256 AA:BB:CC";
    const FP_B: &str = "SHA-256 DD:EE:FF";

    #[test]
    fn mutual_key_same_password_same_secret() {
        let (sa, ma) = start_with_rng(b"brave-otter", b"314", SeedRng::new([1u8; 32]));
        let (sb, mb) = start_with_rng(b"brave-otter", b"314", SeedRng::new([2u8; 32]));
        let ka = finish(sa, &mb).unwrap();
        let kb = finish(sb, &ma).unwrap();
        let caps = canonical_caps(&["transfer".into()]);
        // Each side independently derives its role from fingerprint ownership.
        let a_sends = our_confirm(&ka, FP_A, FP_B, &caps);
        let b_sends = our_confirm(&kb, FP_B, FP_A, &caps);
        // Each verifies the other's MAC under its OWN K.
        assert!(verify_peer_confirm(&kb, FP_B, FP_A, &caps, &a_sends), "B verifies A");
        assert!(verify_peer_confirm(&ka, FP_A, FP_B, &caps, &b_sends), "A verifies B");
        // Same pinned secret.
        assert_eq!(secret_from_k(&ka), secret_from_k(&kb));
        assert_eq!(secret_from_k(&ka).len(), 64);
    }

    #[test]
    fn reflection_is_rejected() {
        // A relay mirrors A's own confirm MAC back to A. Because A sends "A->B"
        // and EXPECTS "B->A", verifying its own message must FAIL.
        let (sa, ma) = start_with_rng(b"brave-otter", b"314", SeedRng::new([1u8; 32]));
        let (sb, mb) = start_with_rng(b"brave-otter", b"314", SeedRng::new([2u8; 32]));
        let ka = finish(sa, &mb).unwrap();
        let _kb = finish(sb, &ma).unwrap();
        let caps = canonical_caps(&["transfer".into()]);
        let a_sends = our_confirm(&ka, FP_A, FP_B, &caps);
        // Reflected back to A: A must NOT accept its own MAC.
        assert!(!verify_peer_confirm(&ka, FP_A, FP_B, &caps, &a_sends), "reflection rejected");
    }

    #[test]
    fn wrong_password_confirmation_fails() {
        let (sa, ma) = start_with_rng(b"brave-otter", b"314", SeedRng::new([1u8; 32]));
        let (sb, mb) = start_with_rng(b"tidy-walrus", b"314", SeedRng::new([2u8; 32]));
        let ka = finish(sa, &mb).unwrap();
        let kb = finish(sb, &ma).unwrap();
        let caps = canonical_caps(&["transfer".into()]);
        let a_sends = our_confirm(&ka, FP_A, FP_B, &caps);
        // B cannot verify A's MAC: different K.
        assert!(!verify_peer_confirm(&kb, FP_B, FP_A, &caps, &a_sends));
    }

    #[test]
    fn fingerprint_mismatch_confirmation_fails() {
        // §5.2: a DTLS-MITM makes the two sides see DIFFERENT fingerprint pairs.
        let (sa, ma) = start_with_rng(b"brave-otter", b"314", SeedRng::new([1u8; 32]));
        let (sb, mb) = start_with_rng(b"brave-otter", b"314", SeedRng::new([2u8; 32]));
        let ka = finish(sa, &mb).unwrap();
        let kb = finish(sb, &ma).unwrap();
        let caps = canonical_caps(&["transfer".into()]);
        // A's view: own=FP_A, peer=MITM_TO_A. B's view: own=FP_B, peer=MITM_TO_B.
        let mitm_to_a = "SHA-256 99:MITM:A";
        let mitm_to_b = "SHA-256 99:MITM:B";
        let a_sends = our_confirm(&ka, FP_A, mitm_to_a, &caps);
        // B recomputes the expected A-message under its OWN fingerprint view.
        assert!(!verify_peer_confirm(&kb, FP_B, mitm_to_b, &caps, &a_sends));
    }

    #[test]
    fn caps_tamper_confirmation_fails() {
        // §6.1: a server rewriting caps breaks the MAC.
        let (sa, ma) = start_with_rng(b"brave-otter", b"314", SeedRng::new([1u8; 32]));
        let (sb, mb) = start_with_rng(b"brave-otter", b"314", SeedRng::new([2u8; 32]));
        let ka = finish(sa, &mb).unwrap();
        let kb = finish(sb, &ma).unwrap();
        let a_sends = our_confirm(&ka, FP_A, FP_B, &canonical_caps(&["transfer".into()]));
        // B was told (by a tampering server) caps=["transfer","remote-exec"].
        let tampered_caps = canonical_caps(&["transfer".into(), "remote-exec".into()]);
        assert!(!verify_peer_confirm(&kb, FP_B, FP_A, &tampered_caps, &a_sends));
    }

    #[test]
    fn norm_and_split_match_expected() {
        assert_eq!(norm_code("  Brave Otter Ruby 314 "), "brave-otter-ruby-314");
        assert_eq!(norm_code("BRAVE-OTTER-314"), "brave-otter-314");
        let (np, pw) = split_code(&norm_code("brave-otter-ruby-314"));
        assert_eq!(np, "314");
        assert_eq!(pw, "brave-otter-ruby");
        // The two halves recombine to the original normalized code.
        let (np2, pw2) = split_code(&norm_code("brave otter 314"));
        assert_eq!((np2.as_str(), pw2.as_str()), ("314", "brave-otter"));
    }

    #[test]
    fn split_chosen_code_keeps_words_unless_numeric_nameplate() {
        // No numeric trailing group: BOTH words stay in the password.
        assert_eq!(
            split_chosen_code("gigantic-element"),
            ("gigantic-element".to_string(), None)
        );
        // Trailing dash is trimmed, not treated as an empty nameplate.
        assert_eq!(
            split_chosen_code("gigantic-element-"),
            ("gigantic-element".to_string(), None)
        );
        // Leading + trailing dashes both trimmed.
        assert_eq!(
            split_chosen_code("-gigantic-element-"),
            ("gigantic-element".to_string(), None)
        );
        // A real 3-5 digit nameplate IS split off.
        assert_eq!(
            split_chosen_code("gigantic-element-9641"),
            ("gigantic-element".to_string(), Some("9641".to_string()))
        );
        // 1 digit is NOT a nameplate (below the 3-5 digit shape) — stays a word.
        assert_eq!(
            split_chosen_code("gigantic-element-7"),
            ("gigantic-element-7".to_string(), None)
        );
        // Single word, no dash.
        assert_eq!(split_chosen_code("cat"), ("cat".to_string(), None));
    }

    #[test]
    fn full_pairing_from_spoken_code() {
        // End-to-end: creator mints a code, claimer types it. Both split+normalize
        // to the SAME (nameplate, password), feed SPAKE2, confirm, agree secret.
        let spoken = "Brave-Otter-Ruby-314";
        let (np_c, pw_c) = split_code(&norm_code(spoken)); // creator
        let (np_k, pw_k) = split_code(&norm_code(spoken)); // claimer (typed)
        assert_eq!((np_c.as_str(), pw_c.as_str()), (np_k.as_str(), pw_k.as_str()));
        let (sa, ma) = start_with_rng(pw_c.as_bytes(), np_c.as_bytes(), SeedRng::new([7u8; 32]));
        let (sb, mb) = start_with_rng(pw_k.as_bytes(), np_k.as_bytes(), SeedRng::new([8u8; 32]));
        let ka = finish(sa, &mb).unwrap();
        let kb = finish(sb, &ma).unwrap();
        let caps = canonical_caps(&["transfer".into()]);
        assert!(verify_peer_confirm(&kb, FP_B, FP_A, &caps, &our_confirm(&ka, FP_A, FP_B, &caps)));
        assert_eq!(secret_from_k(&ka), secret_from_k(&kb));
    }

    #[test]
    fn canonical_caps_is_order_independent() {
        assert_eq!(
            canonical_caps(&["Transfer".into(), "clipboard".into()]),
            canonical_caps(&["clipboard".into(), "TRANSFER".into()])
        );
        assert_eq!(canonical_caps(&[]), "");
        assert_eq!(canonical_caps(&["transfer".into(), "transfer".into()]), "transfer");
    }
}
