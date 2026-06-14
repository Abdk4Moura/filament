//! Shared SPAKE2 key-agreement ceremony, used by BOTH `pair` and the transfer
//! path (`send --code` / `recv <code>`).
//!
//! The pairing command historically inlined the whole L1-a SPAKE2 ceremony in
//! `pair_cmd`. The transfer path had NO PAKE at all (it used the legacy
//! server-minted v1 code, and `send --remember` handed a plaintext secret over
//! the DataChannel). This module factors the ceremony out so the two flows run
//! the IDENTICAL handshake and differ ONLY in what they do with the result:
//!
//!   * `pair`    : run the ceremony, then PERSIST the agreed secret (a known
//!                 device) via `devices_store_v2`.
//!   * transfer  : run the ceremony, VERIFY it, then DISCARD the secret. The
//!                 ceremony authenticates the link (mutual auth, MITM-detectable
//!                 via the DTLS-fingerprint-bound confirmation MAC); the transfer
//!                 keeps no lasting trust. "Link with mutual auth, then forget."
//!
//! SECURITY INVARIANTS (shared by both callers, enforced here):
//!   - The PAKE words (password) NEVER cross the signaling server. Only the
//!     numeric nameplate is sent (by the caller, via pair-create / pair-claim).
//!     This module only ever relays the opaque 33-byte SPAKE2 element and the
//!     32-byte confirmation MAC over the `signal` channel.
//!   - The confirmation MAC binds BOTH sides' DTLS fingerprints (and the agreed
//!     caps), so a server/relay that substitutes a DTLS cert is DETECTED and the
//!     ceremony ABORTS, agreeing nothing.
//!   - The agreed secret is HKDF(K): agreed on both sides, never transmitted.
//!     The transfer caller throws it away; only `pair` (or `--remember`) stores.
//!
//! This is a pure protocol state machine: it never touches the network or the
//! `Conn`. The caller drives it from its event loop, feeding in the peer's
//! signal payloads and the link's DTLS fingerprints, and relaying the opaque
//! payloads this module produces. That keeps it unit-testable end to end (two
//! in-process ceremonies, no sockets), see the tests at the bottom.

use filament_pake::{self, PakeState};
use serde_json::{json, Value};

/// The capability set v2 first-pairing / ephemeral transfer-auth agrees on.
/// "transfer" is the L0 baseline (always allowed); deny-by-default future caps
/// are NOT granted here. BOTH sides MAC the identical canonical string or
/// confirmation fails (spec §8 / gate 5), so this default is fixed.
pub fn pair_v2_caps() -> Vec<String> {
    vec!["transfer".to_string()]
}

/// Base64 (no external dep). Used only for the 33-byte SPAKE2 element / 32-byte
/// MAC opaque payloads on the signal relay. Mirrors the browser's b64.
pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &c in chunk {
            n = (n << 6) | val(c)?;
            bits += 6;
        }
        n <<= 24 - bits;
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Outcome of feeding an inbound `signal` payload into the ceremony.
pub enum Inbound {
    /// The payload WAS a PAKE message (consumed). The caller must NOT route it
    /// into the WebRTC signal path. Drive the ceremony again afterwards.
    Consumed,
    /// The payload was malformed key-exchange material. The caller MUST abort
    /// the ceremony loudly (agree nothing) with this message.
    Abort(String),
    /// Not a PAKE payload (it is SDP/ICE); fall through to the WebRTC path.
    Ignored,
}

/// One SPAKE2 ceremony with one peer. Holds all the protocol state the loops
/// previously inlined (the live session, our element, derived K, the sent-flags)
/// so both `pair` and the transfer path drive it identically.
pub struct Ceremony {
    /// The agreed capability set (relayed in the confirm payload) and its
    /// canonical form (fed to the MAC). The password (spoken words) and nameplate
    /// are consumed by the SPAKE2 `state` at construction and never re-read here,
    /// so they are not retained: the words NEVER leave the process by design.
    caps: Vec<String>,
    caps_canon: String,
    /// Live SPAKE2 session (consumed by `finish`). `None` after K is derived.
    state: Option<PakeState>,
    /// Our outbound 33-byte SPAKE2 element.
    msg: Vec<u8>,
    /// Derived shared key K (after finishing on the peer's element). Held until
    /// confirmation, then HKDF'd to the secret.
    k: Option<Vec<u8>>,
    /// The agreed pinned secret (HKDF(K)); set ONLY after confirmation passes.
    secret: Option<String>,
    /// Abort reason if the ceremony was refused (wrong code / tampering / etc.).
    aborted: Option<String>,
    sent_msg: bool,
    sent_confirm: bool,
}

impl Ceremony {
    /// Begin a symmetric SPAKE2 ceremony. `password` is the spoken words,
    /// `nameplate` the numeric routing suffix. Both sides MUST pass identical
    /// password AND nameplate (the SPAKE2 identity) or they derive different K.
    pub fn new(password: &str, nameplate: &str, caps: Vec<String>) -> Self {
        let caps_canon = filament_pake::canonical_caps(&caps);
        let (state, msg) = filament_pake::start(password.as_bytes(), nameplate.as_bytes());
        Ceremony {
            caps,
            caps_canon,
            state: Some(state),
            msg,
            k: None,
            secret: None,
            aborted: None,
            sent_msg: false,
            sent_confirm: false,
        }
    }

    /// Re-mint with a FRESH nameplate (and optionally fresh words) after a
    /// server `taken` collision. Resets the session and the sent-flag so the new
    /// element goes out. The caller re-emits `pair-create {nameplate}`.
    pub fn restart(&mut self, password: &str, nameplate: &str) {
        let (state, msg) = filament_pake::start(password.as_bytes(), nameplate.as_bytes());
        self.state = Some(state);
        self.msg = msg;
        self.k = None;
        self.secret = None;
        self.aborted = None;
        self.sent_msg = false;
        self.sent_confirm = false;
    }

    pub fn secret(&self) -> Option<&String> {
        self.secret.as_ref()
    }
    /// The abort reason, if the ceremony was refused. Callers normally act on the
    /// `Inbound::Abort` returned by `on_signal`; this accessor is used by the
    /// module's own tests to assert the terminal state.
    #[cfg(test)]
    pub fn aborted(&self) -> Option<&String> {
        self.aborted.as_ref()
    }

    /// The opaque `signal` payload carrying our SPAKE2 element, IF it hasn't been
    /// sent yet. `None` once sent (idempotent). Marks it sent. The caller relays
    /// the returned JSON to the peer (`{to, data: <this>}`).
    pub fn take_msg_payload(&mut self) -> Option<Value> {
        if self.sent_msg {
            return None;
        }
        self.sent_msg = true;
        Some(json!({ "type": "pake-msg", "v": 2, "msg": b64_encode(&self.msg) }))
    }

    /// The opaque `signal` payload carrying our key-confirmation MAC, IF K is
    /// derived AND it hasn't been sent yet. Needs both DTLS fingerprints (so the
    /// MAC binds them). `None` until ready / once sent. Marks it sent.
    pub fn take_confirm_payload(&mut self, my_fp: &str, their_fp: &str) -> Option<Value> {
        if self.sent_confirm {
            return None;
        }
        let k = self.k.as_ref()?;
        let mac = filament_pake::our_confirm(k, my_fp, their_fp, &self.caps_canon);
        self.sent_confirm = true;
        Some(json!({
            "type": "pake-confirm", "v": 2,
            "mac": b64_encode(&mac),
            "caps": self.caps.clone(),
        }))
    }

    /// Whether K has been derived (the peer's element was consumed).
    pub fn has_k(&self) -> bool {
        self.k.is_some()
    }

    /// Feed an inbound `signal` payload. PAKE messages are consumed; SDP/ICE is
    /// ignored (falls through to the WebRTC path). A `pake-confirm` carries the
    /// fingerprints to verify against (the caller supplies the link's current
    /// fingerprints). On a verified confirm the secret is derived.
    pub fn on_signal(&mut self, data: &Value, fps: Option<(&str, &str)>) -> Inbound {
        match data["type"].as_str() {
            Some("pake-msg") => {
                if self.k.is_none() {
                    if let Some(state) = self.state.take() {
                        let peer_el = data["msg"].as_str().and_then(b64_decode).unwrap_or_default();
                        match filament_pake::finish(state, &peer_el) {
                            Some(k) => self.k = Some(k),
                            None => {
                                return Inbound::Abort(
                                    "malformed key-exchange message (abort)".to_string(),
                                )
                            }
                        }
                    }
                }
                Inbound::Consumed
            }
            Some("pake-confirm") => {
                let Some(k) = self.k.clone() else {
                    return Inbound::Abort(
                        "confirmation arrived before key exchange (abort)".to_string(),
                    );
                };
                let recv_mac = data["mac"].as_str().and_then(b64_decode).unwrap_or_default();
                let Some((my_fp, their_fp)) = fps else {
                    return Inbound::Abort(
                        "no DTLS fingerprints to bind confirmation (abort)".to_string(),
                    );
                };
                // We MAC against OUR fixed caps, so a server that rewrites the
                // relayed `caps` field cannot make the MAC verify.
                if filament_pake::verify_peer_confirm(
                    &k,
                    my_fp,
                    their_fp,
                    &self.caps_canon,
                    &recv_mac,
                ) {
                    self.secret = Some(filament_pake::secret_from_k(&k));
                    Inbound::Consumed
                } else {
                    self.aborted = Some("key confirmation failed".to_string());
                    Inbound::Abort(
                        "key confirmation failed: wrong code, or the connection is being tampered with (a server cannot forge this)".to_string(),
                    )
                }
            }
            _ => Inbound::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fps_for(a_is_lo: bool) -> ((&'static str, &'static str), (&'static str, &'static str)) {
        // Distinct fingerprints; each side passes (mine, theirs).
        let a = "SHA-256 AA:BB:CC";
        let b = "SHA-256 DD:EE:FF";
        if a_is_lo {
            ((a, b), (b, a))
        } else {
            ((a, b), (b, a))
        }
    }

    // Run a full two-party ceremony in process and return both outcomes.
    fn run_pair(pw_a: &str, pw_b: &str, np: &str) -> (Ceremony, Ceremony) {
        let mut a = Ceremony::new(pw_a, np, pair_v2_caps());
        let mut b = Ceremony::new(pw_b, np, pair_v2_caps());
        let ((a_mine, a_theirs), (b_mine, b_theirs)) = fps_for(true);

        // Exchange elements.
        let a_msg = a.take_msg_payload().unwrap();
        let b_msg = b.take_msg_payload().unwrap();
        assert!(matches!(b.on_signal(&a_msg, None), Inbound::Consumed));
        assert!(matches!(a.on_signal(&b_msg, None), Inbound::Consumed));
        assert!(a.has_k() && b.has_k());

        // Exchange confirms (each binds its OWN fingerprint view).
        let a_conf = a.take_confirm_payload(a_mine, a_theirs).unwrap();
        let b_conf = b.take_confirm_payload(b_mine, b_theirs).unwrap();
        let _ = b.on_signal(&a_conf, Some((b_mine, b_theirs)));
        let _ = a.on_signal(&b_conf, Some((a_mine, a_theirs)));
        (a, b)
    }

    #[test]
    fn honest_ceremony_agrees_same_secret() {
        let (a, b) = run_pair("brave-otter", "brave-otter", "314");
        assert!(a.secret().is_some(), "A agreed a secret");
        assert!(b.secret().is_some(), "B agreed a secret");
        assert_eq!(a.secret(), b.secret(), "both sides agree the SAME secret");
        assert_eq!(a.secret().unwrap().len(), 64);
        assert!(a.aborted().is_none() && b.aborted().is_none());
    }

    #[test]
    fn wrong_password_aborts_no_secret() {
        let (a, b) = run_pair("brave-otter", "tidy-walrus", "314");
        // Different passwords -> different K -> confirmation fails on both sides.
        assert!(a.secret().is_none(), "A agrees nothing on a wrong code");
        assert!(b.secret().is_none(), "B agrees nothing on a wrong code");
        assert!(a.aborted().is_some() || b.aborted().is_some());
    }

    #[test]
    fn fingerprint_mismatch_aborts() {
        // A server-substituted DTLS cert => the two sides see different peer
        // fingerprints => confirmation MAC fails => abort, no secret.
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps());
        let mut b = Ceremony::new("brave-otter", "314", pair_v2_caps());
        let a_msg = a.take_msg_payload().unwrap();
        let b_msg = b.take_msg_payload().unwrap();
        b.on_signal(&a_msg, None);
        a.on_signal(&b_msg, None);
        // A's view: own=AA, peer=MITM_A. B's view: own=BB, peer=MITM_B.
        let a_conf = a.take_confirm_payload("SHA-256 AA", "SHA-256 MITM-A").unwrap();
        let r = b.on_signal(&a_conf, Some(("SHA-256 BB", "SHA-256 MITM-B")));
        assert!(matches!(r, Inbound::Abort(_)));
        assert!(b.secret().is_none());
    }

    #[test]
    fn confirm_before_key_exchange_aborts() {
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps());
        let stray = json!({ "type": "pake-confirm", "v": 2, "mac": b64_encode(&[0u8; 32]), "caps": ["transfer"] });
        let r = a.on_signal(&stray, Some(("SHA-256 AA", "SHA-256 BB")));
        assert!(matches!(r, Inbound::Abort(_)));
    }

    #[test]
    fn non_pake_signal_is_ignored() {
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps());
        let sdp = json!({ "type": "description", "description": { "type": "offer" } });
        assert!(matches!(a.on_signal(&sdp, None), Inbound::Ignored));
    }

    #[test]
    fn b64_roundtrips() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data);
        }
    }
}
