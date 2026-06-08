//! GATE 2 (adversarial / server-can't-derive — the NEGATIVE security test).
//!
//! Models a malicious signaling relay that knows the NAMEPLATE but NOT the
//! password, and tries two attacks. Both must be DETECTED by key confirmation
//! and result in ZERO agreed secret. Uses the PRODUCTION pake-core API
//! (start/finish/our_confirm/verify_peer_confirm) — the exact code that ships.
//!
//! Prints A/B numbers: the honest baseline (secrets equal, confirm passes) vs
//! each adversarial case (secrets differ, confirm fails, nothing agreed).
//!
//! Run: cargo run --release --bin adversary  (exit 0 = all attacks defeated)

use filament_pake::{
    canonical_caps, finish, our_confirm, secret_from_k, start, verify_peer_confirm,
};

const NAMEPLATE: &str = "3141";
const PASSWORD: &str = "brave-otter-ruby";
const FP_A: &str = "SHA-256 AA:BB:CC:DD";
const FP_B: &str = "SHA-256 11:22:33:44";

fn caps() -> String {
    canonical_caps(&["transfer".to_string()])
}

fn main() {
    let mut failures = 0;

    // ---------- A) HONEST BASELINE ----------------------------------------
    // Two honest peers, same code, no attacker. Secrets MUST match; confirm
    // MUST pass. This is the A in the A/B comparison.
    {
        let (sa, ma) = start(PASSWORD.as_bytes(), NAMEPLATE.as_bytes());
        let (sb, mb) = start(PASSWORD.as_bytes(), NAMEPLATE.as_bytes());
        let ka = finish(sa, &mb).unwrap();
        let kb = finish(sb, &ma).unwrap();
        let sec_a = secret_from_k(&ka);
        let sec_b = secret_from_k(&kb);
        let a_conf = our_confirm(&ka, FP_A, FP_B, &caps());
        let b_ok = verify_peer_confirm(&kb, FP_B, FP_A, &caps(), &a_conf);
        println!("[A honest]  secret_A == secret_B : {}", sec_a == sec_b);
        println!("[A honest]  confirm passes       : {}", b_ok);
        println!("[A honest]  secret = {}", &sec_a[..16]);
        if sec_a != sec_b || !b_ok {
            failures += 1;
            println!("  !! honest baseline broken");
        }
    }

    // ---------- B1) SPAKE2-ELEMENT SUBSTITUTION (active MITM) --------------
    // The relay does NOT know the password. It runs its OWN SPAKE2 with a
    // GUESSED password and injects its element toward A (and likewise toward B),
    // trying to sit in the middle of two half-sessions. A derives a DIFFERENT K
    // from what the attacker has; the attacker's confirm MAC cannot satisfy A's
    // verify → DETECTED, zero secret agreed.
    {
        // A's honest session and its real element.
        let (sa, ma) = start(PASSWORD.as_bytes(), NAMEPLATE.as_bytes());
        // Attacker's session with a wrong (guessed) password.
        let (atk_state, atk_msg) = start(b"attacker-guess", NAMEPLATE.as_bytes());
        // The relay substitutes the attacker's element for B's toward A, and
        // forwards A's real element to the attacker.
        let ka = finish(sa, &atk_msg).unwrap(); // A finishes on attacker's element
        let katk = finish(atk_state, &ma).unwrap(); // attacker finishes on A's element
        let sec_a = secret_from_k(&ka);
        let sec_atk = secret_from_k(&katk);
        // The attacker now tries to forge A's expected peer-confirm. It MACs
        // under ITS K; A verifies under A's K.
        let atk_conf = our_confirm(&katk, FP_B, FP_A, &caps());
        let a_accepts = verify_peer_confirm(&ka, FP_A, FP_B, &caps(), &atk_conf);
        println!();
        println!("[B1 element-MITM] A_secret == attacker_secret : {}", sec_a == sec_atk);
        println!("[B1 element-MITM] A accepts attacker confirm   : {}", a_accepts);
        println!("[B1 element-MITM] attacker_secret = {}", &sec_atk[..16]);
        println!("[B1 element-MITM] A_secret        = {}", &sec_a[..16]);
        if sec_a == sec_atk {
            failures += 1;
            println!("  !! attacker derived A's secret");
        }
        if a_accepts {
            failures += 1;
            println!("  !! A accepted a forged confirmation (MITM undetected)");
        } else {
            println!("[B1 element-MITM] => DETECTED: A refuses, no secret agreed");
        }
    }

    // ---------- B2) a=fingerprint REWRITE (DTLS-MITM, §5.2) -----------------
    // The two peers share the SAME K (relay didn't touch SPAKE2), but the relay
    // terminates two DTLS sessions and rewrites the a=fingerprint it forwards.
    // So A sees (fp_A, fp_MITM_toA) and B sees (fp_MITM_toB, fp_B): DIFFERENT
    // sorted fingerprint pairs fold into the confirm MAC under the SAME K →
    // verify fails → DETECTED. This is the wire-level form of the unit test.
    {
        let (sa, ma) = start(PASSWORD.as_bytes(), NAMEPLATE.as_bytes());
        let (sb, mb) = start(PASSWORD.as_bytes(), NAMEPLATE.as_bytes());
        let ka = finish(sa, &mb).unwrap();
        let kb = finish(sb, &ma).unwrap();
        // Same K (honest SPAKE2) — proves the attack is purely the cert swap.
        let same_k = secret_from_k(&ka) == secret_from_k(&kb);
        let fp_mitm_to_a = "SHA-256 DE:AD:BE:EF:TO:A";
        let fp_mitm_to_b = "SHA-256 DE:AD:BE:EF:TO:B";
        // A's view: own=FP_A, peer=the MITM cert presented to A.
        let a_conf = our_confirm(&ka, FP_A, fp_mitm_to_a, &caps());
        // B verifies under ITS fingerprint view (own=FP_B, peer=MITM cert to B).
        let b_accepts = verify_peer_confirm(&kb, FP_B, fp_mitm_to_b, &caps(), &a_conf);
        println!();
        println!("[B2 fp-rewrite]   peers share K (cert-swap only) : {}", same_k);
        println!("[B2 fp-rewrite]   B accepts A confirm            : {}", b_accepts);
        if b_accepts {
            failures += 1;
            println!("  !! DTLS-MITM undetected (fingerprint binding broken)");
        } else {
            println!("[B2 fp-rewrite]   => DETECTED: confirm MAC mismatch, pairing aborts");
        }
    }

    // ---------- B3) caps REWRITE (§6.1 downgrade) --------------------------
    // A server that rewrites the relayed `caps` field to escalate privileges
    // breaks the confirm MAC (caps are folded under K).
    {
        let (sa, ma) = start(PASSWORD.as_bytes(), NAMEPLATE.as_bytes());
        let (sb, mb) = start(PASSWORD.as_bytes(), NAMEPLATE.as_bytes());
        let ka = finish(sa, &mb).unwrap();
        let kb = finish(sb, &ma).unwrap();
        let a_conf = our_confirm(&ka, FP_A, FP_B, &caps());
        // B was fed escalated caps by a tampering server.
        let escalated = canonical_caps(&["transfer".to_string(), "remote-exec".to_string()]);
        let b_accepts = verify_peer_confirm(&kb, FP_B, FP_A, &escalated, &a_conf);
        println!();
        println!("[B3 caps-rewrite] B accepts escalated caps        : {}", b_accepts);
        if b_accepts {
            failures += 1;
            println!("  !! caps escalation undetected");
        } else {
            println!("[B3 caps-rewrite] => DETECTED: confirm MAC mismatch, pairing aborts");
        }
    }

    println!();
    if failures == 0 {
        println!("GATE2 PASS: every attack DETECTED; server/MITM derives no secret, pairing aborts");
        std::process::exit(0);
    } else {
        println!("GATE2 FAIL: {failures} attack(s) NOT defeated");
        std::process::exit(1);
    }
}
