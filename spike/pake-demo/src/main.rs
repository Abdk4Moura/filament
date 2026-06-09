//! SPIKE (throwaway) — L1-0 SPAKE2 de-risking demo.
//!
//! Proves / refutes the four spike items from the mission:
//!   1. Two parties derive the SAME strong key K from the SAME password via
//!      SPAKE2 over a RELAY, and FAIL to agree on a wrong password.
//!   2. (separate wasm crate) WASM<->native interop.
//!   3. Adversarial: a relay/MITM that does NOT know the password cannot
//!      derive K and cannot silently substitute its own key — the
//!      key-CONFIRMATION MAC catches it.
//!   4. Code-split: server matches a NAMEPLATE, never receives the PASSWORD.
//!
//! Run: cargo run -p pake-demo   (exit code 0 = all gates pass)

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

type HmacSha256 = Hmac<Sha256>;

// ---- Filament code-split model (item 4) -------------------------------------
// A spoken code today is `adj-animal-NNN`. We split it wormhole-style:
//   nameplate = the NNN suffix (or a dedicated routing token) -> goes to server
//   password  = the adj-animal words -> NEVER sent to server, feeds SPAKE2
// The "Relay" struct below physically cannot see `password`.
struct SpokenCode {
    nameplate: String, // server-visible rendezvous selector
    password: String,  // client-only PAKE password
}
impl SpokenCode {
    fn from_spoken(code: &str) -> Self {
        // "brave-otter-314" -> nameplate "314", password "brave-otter"
        let parts: Vec<&str> = code.rsplitn(2, '-').collect();
        // rsplitn yields [last, rest]
        SpokenCode {
            nameplate: parts.get(0).copied().unwrap_or("").to_string(),
            password: parts.get(1).copied().unwrap_or("").to_string(),
        }
    }
}

// The signaling server, modeled as a DUMB RELAY. It only ever sees the
// nameplate and the opaque SPAKE2/confirmation bytes it forwards. It is given
// NO access to `password`. This is the structural guarantee of the code-split.
struct Relay {
    seen_nameplate: Option<String>,
    relayed_bytes: Vec<Vec<u8>>, // everything that crossed the wire
}
impl Relay {
    fn new() -> Self { Relay { seen_nameplate: None, relayed_bytes: vec![] } }
    fn route(&mut self, nameplate: &str) { self.seen_nameplate = Some(nameplate.to_string()); }
    fn forward(&mut self, msg: &[u8]) -> Vec<u8> {
        // The relay can see and store the bytes (it's the network) but they are
        // SPAKE2 elements / MACs — useless without the password.
        self.relayed_bytes.push(msg.to_vec());
        msg.to_vec()
    }
}

// Shared SPAKE2 identity string. BOTH sides MUST pass the same Identity or
// they derive different (valid-but-mismatched) K — the classic footgun the
// advisor flagged. We bind it to the nameplate so a code is domain-separated.
fn pake_identity(nameplate: &str) -> Identity {
    Identity::new(format!("filament-pair-pake-v1:{nameplate}").as_bytes())
}

/// One full PAKE attempt over the relay between peer A and peer B.
/// Returns Ok((Ka, Kb)) with the derived pinned secrets IF key-confirmation
/// passes on both sides; Err(reason) if confirmation fails (wrong password or
/// MITM substitution).
fn run_pake_over_relay(
    relay: &mut Relay,
    code_a: &SpokenCode,
    code_b: &SpokenCode,
    // Optional active attacker that rewrites B's message to A (MITM attempt).
    mut tamper_b_to_a: Option<Box<dyn FnMut(&[u8]) -> Vec<u8>>>,
) -> Result<(String, String), String> {
    // Server routes purely on the nameplate. It never receives a password.
    relay.route(&code_a.nameplate);
    assert!(relay.seen_nameplate.is_some());

    // --- SPAKE2 round (symmetric: either peer may initiate) ---
    let (state_a, msg_a) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(code_a.password.as_bytes()),
        &pake_identity(&code_a.nameplate),
    );
    let (state_b, msg_b) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(code_b.password.as_bytes()),
        &pake_identity(&code_b.nameplate),
    );

    // Messages cross THROUGH the relay (server). Relay stores them.
    let msg_a_at_b = relay.forward(&msg_a);
    let mut msg_b_at_a = relay.forward(&msg_b);
    if let Some(t) = tamper_b_to_a.as_mut() {
        msg_b_at_a = t(&msg_b_at_a); // active MITM rewrites B->A
    }

    let k_a = state_a.finish(&msg_b_at_a).map_err(|e| format!("A finish: {e:?}"))?;
    let k_b = state_b.finish(&msg_a_at_b).map_err(|e| format!("B finish: {e:?}"))?;

    // --- KEY CONFIRMATION (item 3) — SPAKE2 alone does NOT prove a shared K. ---
    // Each side sends MAC(K, transcript). A mismatch => abort. This is what
    // turns "K differs silently" into a DETECTED failure. We also fold the
    // (here simulated) sorted DTLS fingerprints into the transcript — exactly
    // the C20 proof_for binding, but keyed by K instead of the not-yet-existing
    // pinned secret.
    let fp_lo = "AA:BB:fingerprint-of-cert-1";
    let fp_hi = "CC:DD:fingerprint-of-cert-2";
    let transcript = |k: &[u8], who: &str| -> Vec<u8> {
        let mut m = HmacSha256::new_from_slice(k).unwrap();
        m.update(b"filament-pake-confirm-v1");
        m.update(who.as_bytes()); // direction tag
        m.update(fp_lo.as_bytes());
        m.update(fp_hi.as_bytes());
        m.finalize().into_bytes().to_vec()
    };
    // A proves to B and vice-versa; tags differ so they can't be replayed.
    let conf_a = transcript(&k_a, "A->B");
    let conf_b = transcript(&k_b, "B->A");
    relay.forward(&conf_a);
    relay.forward(&conf_b);

    // Each side recomputes the OTHER's expected MAC under its OWN K and checks.
    let b_expects_from_a = transcript(&k_b, "A->B");
    let a_expects_from_b = transcript(&k_a, "B->A");
    let ok_at_b = constant_eq(&conf_a, &b_expects_from_a);
    let ok_at_a = constant_eq(&conf_b, &a_expects_from_b);
    if !(ok_at_a && ok_at_b) {
        return Err("key-confirmation FAILED (wrong password or MITM)".into());
    }

    // --- KDF: derive the pinned 32-byte device secret from K (item: binding) --
    // K is AGREED, never transmitted. Same HKDF-info pattern as
    // design-direct-cli-transport.md.
    Ok((derive_secret(&k_a), derive_secret(&k_b)))
}

fn derive_secret(k: &[u8]) -> String {
    let hk = Hkdf::<Sha256>::new(None, k);
    let mut out = [0u8; 32];
    hk.expand(b"filament-pair-pake-v1:pinned-secret", &mut out).unwrap();
    hex::encode(out)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) { d |= x ^ y; }
    d == 0
}

fn main() {
    let mut failures = 0;

    // ---------- GATE 1: code-split, server sees nameplate not password -------
    let spoken = "brave-otter-314";
    let sc = SpokenCode::from_spoken(spoken);
    println!("[item4] spoken={spoken}  nameplate={:?}  password={:?}", sc.nameplate, sc.password);
    assert_eq!(sc.nameplate, "314");
    assert_eq!(sc.password, "brave-otter");

    // ---------- GATE 2 (mutual key): same password -> same K -----------------
    {
        let mut relay = Relay::new();
        let a = SpokenCode::from_spoken("brave-otter-314");
        let b = SpokenCode::from_spoken("brave-otter-314");
        match run_pake_over_relay(&mut relay, &a, &b, None) {
            Ok((ka, kb)) => {
                let same = ka == kb;
                println!("[gate:mutual-key] confirmation PASSED, secrets match={same}");
                println!("                  pinned_secret = {}", &ka[..16]);
                if !same { failures += 1; println!("  !! secrets differ"); }
                // The relay forwarded bytes but cannot derive the password/K.
                let relay_knows_password = relay
                    .relayed_bytes
                    .iter()
                    .any(|m| m.windows(b.password.len().max(1)).any(|w| w == a.password.as_bytes()));
                println!("[gate:relay-blind] password appears in relayed bytes = {relay_knows_password}");
                if relay_knows_password { failures += 1; println!("  !! password leaked to relay"); }
            }
            Err(e) => { failures += 1; println!("[gate:mutual-key] UNEXPECTED FAIL: {e}"); }
        }
    }

    // ---------- GATE 3 (wrong-password-burns): different password -> abort ----
    {
        let mut relay = Relay::new();
        let a = SpokenCode::from_spoken("brave-otter-314");   // correct
        let b = SpokenCode::from_spoken("brave-otter-314");
        let b_wrong = SpokenCode { nameplate: b.nameplate.clone(), password: "tidy-walrus".into() };
        match run_pake_over_relay(&mut relay, &a, &b_wrong, None) {
            Ok(_) => { failures += 1; println!("[gate:wrong-password] LEAK: agreed on wrong password!"); }
            Err(e) => println!("[gate:wrong-password] correctly REFUSED: {e}"),
        }
    }

    // ---------- GATE 4 (adversarial MITM substitution) -----------------------
    // Active relay that does NOT know the password tries to substitute its own
    // SPAKE2 element for B's. It will derive a DIFFERENT K from A, so the
    // key-confirmation MAC must FAIL — the substitution is DETECTED.
    {
        let mut relay = Relay::new();
        let a = SpokenCode::from_spoken("brave-otter-314");
        let b = SpokenCode::from_spoken("brave-otter-314");
        // Attacker runs its own SPAKE2 with a GUESSED (wrong) password and
        // injects ITS msg toward A.
        let (_atk_state, atk_msg) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(b"attacker-guess"),
            &pake_identity(&a.nameplate),
        );
        let tamper = Box::new(move |_orig: &[u8]| atk_msg.clone());
        match run_pake_over_relay(&mut relay, &a, &b, Some(tamper)) {
            Ok(_) => { failures += 1; println!("[gate:mitm] BROKEN: MITM substitution undetected!"); }
            Err(e) => println!("[gate:mitm] MITM substitution DETECTED + refused: {e}"),
        }
    }

    println!("\n=== {} ===", if failures == 0 { "ALL SPIKE GATES PASSED" } else { "SPIKE FAILURES PRESENT" });
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
