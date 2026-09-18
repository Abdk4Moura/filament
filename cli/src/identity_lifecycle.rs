//! Peer-identity proof and expose lifecycle, lifted out of `main.rs`.
//!
//! Who a peer is, and how it proves it mid-session: resolve the link's claimed
//! identity (`resolve_peer_identity`, `principal_after_liveness`,
//! `pin_delegated_denied`), challenge it for possession (`send_identity_challenge`,
//! `issue_proven_challenge_and_hold`), consume the peer's own expose
//! (`handle_identity_expose`) and answer a challenge addressed to us
//! (`respond_to_identity_challenge`), then persist what was proven
//! (`update_peer_identity`, `VOUCH_CERT_SCOPE`) plus the deliberately
//! non-durable provisional overlay record (`store_provisional_identity`,
//! `load_provisional_identity`, `clear_provisional_identity`).
//!
//! Every function takes its inputs explicitly (`&mut Link`, `&crate::Conn`, a
//! peer id, `&Value`, the nonce/hold maps), so the move is a relocation: no
//! context struct, no closure capture, no ownership change. The block has no
//! cfg or feature branches, no test hooks and no spawned tasks.
use crate::conn::Link;
use crate::identity;
use crate::net::Transport;
use crate::ui;
use crate::{
    device_cert_for, device_cert_valid_for, devices_load, effective_principal_deadline,
    local_device_cert, persisted_principal_for_cert, principal_ceiling_for, upsert_peer_record,
    with_devices_mut,
};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Populate link identity from the peer's stored device cert, if the
/// link already has a proof-verified name but identity pubkeys are absent.
/// Cached back onto the link on first successful resolution (resolve-once,
/// not per open).
///
/// The binding model: `verified_name` is set ONLY after a session-bound
/// pair-proof HMAC (proof_for over shared secret + UIDs + fingerprints),
/// so the name is cryptographically bound to this link. `device_cert_for`
/// returns the cert we already verified at pairing (provisional_promote_ok
/// checked device_pub against the overlay transport key at storage time).
/// Together these form a sufficient trust join: a proven name plus the
/// cert trusted-for-that-name. No additional link-level cert-to-transport
/// comparison is needed.
///
/// Fail-closed on: no verified_name, no stored cert, cert expired or
/// otherwise invalid. For a DELEGATED peer "fail closed" cannot be a bare
/// `return`: see `pin_delegated_denied`.
pub(crate) fn resolve_peer_identity(link: &mut Link) {
    // Precedence rule: a Proven binding must NOT be downgraded to Inferred.
    // The identity-expose handler (possession-sig) sets Proven, and this
    // function (symmetric-secret proof + name->cert lookup) sets Inferred.
    // An Inferred MAY later be upgraded to Proven by identity-expose.
    if link.identity_device_pub.is_some() || link.identity_user_pub.is_some() {
        return; // already resolved (any binding, Proven or Inferred, stays)
    }
    let name = match &link.verified_name {
        Some(n) => n.clone(),
        None => return, // no proven name, nothing to resolve
    };
    let Some(cert) = device_cert_for(&name) else {
        pin_delegated_denied(link, &name);
        return;
    };
    let now = crate::identity::now_secs();
    if cert.verify(now).is_err() {
        pin_delegated_denied(link, &name);
        return;
    }
    link.identity_device_pub = Some(cert.device_pub);
    link.identity_user_pub = Some(cert.user_pub);
    link.identity_binding = crate::capability::BindingStrength::Inferred;
    let (principal_kind, not_after, max_offline, last_seen) = persisted_principal_for_cert(&cert);
    let (deadline, _clock) =
        effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
    link.identity_cert_expires = Some(deadline);
    // A delegated principal runs on three clocks: cert expiry, an absolute stop
    // time, and an offline budget. `effective_principal_deadline` already
    // composes them, and `cap_gate_effective` composes `identity_cert_expires`
    // into the outcome, but that composer is a no-op while the capability
    // engine is in SHADOW mode, where the effective decision is the legacy one.
    // The ceiling is the only thing enforcing a delegated principal in shadow,
    // so a passed deadline has to empty the ceiling here (#272).
    link.principal_kind = principal_after_liveness(principal_kind, deadline > now);
}

/// The principal a link must carry once liveness is known. `alive` is whether
/// the peer's certificate verifies AND its composed deadline is still ahead.
///
/// A delegated principal that is not alive collapses to an EMPTY ceiling, which
/// denies every action, because an empty `auth_key_caps` matches no action in
/// `cap_gate_effective`. An owner device passes through unchanged: owner cert
/// semantics are a separate question and this is not the place to answer it.
///
/// Pure on purpose. The bug this closes (#272) lived in the one branch that had
/// no test, so the branch is now reachable without a `Link` or a config dir.
pub(crate) fn principal_after_liveness(
    stored: crate::capability::PrincipalKind,
    alive: bool,
) -> crate::capability::PrincipalKind {
    match stored {
        crate::capability::PrincipalKind::Delegated { .. } if !alive => {
            crate::capability::PrincipalKind::Delegated { caps: Vec::new() }
        }
        other => other,
    }
}

/// Pin a DELEGATED peer to a ceiling-less principal, which denies every action.
/// A no-op for an owner device, whose semantics are unchanged.
///
/// This is what "fail closed" has to mean on the resolver's early-return paths.
/// A bare `return` was not it (#272): a `Link` is constructed with
/// `PrincipalKind::OwnerDevice`, and `auth_key_caps()` returns None for an
/// owner device, so the ceiling check in `cap_gate_effective` is skipped
/// entirely. Leaving the principal untouched therefore left an expired guest
/// owner-equivalent, and the same guest was refused MORE while its certificate
/// was still valid. Measured: a transfer-only guest whose cert had expired
/// opened a TCP connection to an arbitrary port on the owner's loopback, which
/// it could not do three minutes earlier.
fn pin_delegated_denied(link: &mut Link, name: &str) {
    if let Some(caps) = principal_ceiling_for(name) {
        link.principal_kind =
            principal_after_liveness(crate::capability::PrincipalKind::Delegated { caps }, false);
    }
}

/// When a link becomes trusted, send a nonce challenge to the peer so it can
/// prove device-key possession (0x02 possession_sig). When the response arrives
/// in the event loop, the `identity-expose` handler upgrades the binding to
/// Proven. Called at LINK READINESS — from DirectReady for direct links (which
/// holds ChannelReady until Proven) AND from ChannelReady itself for links that
/// did not go through DirectReady (relay/DataChannel), so Proven is reached on
/// EVERY connection, not only direct ones (#39). Both sites dedupe against
/// pending_proven so a single link is never double-challenged. NOT called at
/// individual open sites — Proven settles once at readiness, before gated opens
/// decide (the gates additionally honor the pending_proven hold, #30 GAP 2).
async fn send_identity_challenge(
    conn: &crate::Conn,
    pid: &str,
    identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) {
    if let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() {
        if let Some(t) = conn.transport_of(pid) {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut nonce = [0u8; 32];
            let _ = rng.fill(&mut nonce);
            identity_nonces.insert(pid.to_string(), (nonce, Instant::now(), own_dpub));
            let challenge = json!({
                "type": "identity-nonce-challenge",
                "nonce": hex::encode(nonce),
                "receiver_device_pub": hex::encode(own_dpub)
            });
            // MUST await: send_control is async; dropping the future would leave
            // the challenge unsent (the peer never learns it must prove Proven).
            if let Err(e) = t.send_control(&challenge).await {
                crate::ui::say(&format!(
                    "l2: identity challenge to {pid} could NOT be sent ({e})"
                ));
            }
        }
    }
}

/// The shared "register the Proven hold, then issue the possession challenge"
/// sequence, called by BOTH readiness sites (DirectReady adoption AND the daemon
/// ChannelReady handler, #39) so the two cannot DIVERGE on ordering. HOLD-THEN-AWAIT:
/// the pending_proven entry is inserted (fresh 3s deadline, overwriting any stale
/// one so a reconnect re-challenges) BEFORE the challenge is awaited, so a gated
/// open can never observe the link un-held in the window between send and hold.
/// Today the single-consumer event loop makes that window unreachable; the ordering
/// is belt-and-braces for a future concurrent loop, and — the point — it removes the
/// asymmetry between the two call sites. The CALLER owns the release policy after:
/// DirectReady holds ChannelReady and its timer RE-EMITS it; the ChannelReady site
/// does not hold and its timer only CLEARS the entry (no re-emit → no cycle).
pub(crate) async fn issue_proven_challenge_and_hold(
    conn: &crate::Conn,
    pid: &str,
    t: &Arc<dyn Transport>,
    pending_proven: &Arc<Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
    identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) {
    // IDEMPOTENT: if a challenge is already in flight for this pid (a live,
    // non-expired hold), do NOT issue a second one. send_identity_challenge keys
    // identity_nonces by pid, so a second challenge OVERWRITES the first nonce; a
    // peer that answers the first challenge would then verify against the second
    // nonce and never reach Proven. Both readiness sites (DirectReady and the
    // pair-proof handler) call this, and a transient re-adoption can make even one
    // site fire twice — so the dedupe MUST live here, not at the call sites, to be
    // order-independent for any caller. A STALE (expired) entry is treated as
    // absent so a reconnect re-challenges. Check-and-insert under ONE lock (dropped
    // before the await — never hold a std Mutex across .await).
    {
        let mut pend = pending_proven.lock().unwrap();
        // A hold counts as live only when it is BOTH unexpired AND bound to
        // the link we would send on now. A hold recorded for a transport
        // that has since been replaced (reconnect/repair re-adopts the pid
        // with a new transport) is unusable: the peer's answer would arrive
        // on the new link while the nonce it used was issued for the old
        // one, so the proof could never land and the link would never reach
        // Proven. Treat that exactly like an expired hold -- re-challenge --
        // which is what makes a parked open's wait terminate in a proof
        // instead of a timeout.
        if let Some((held_t, deadline)) = pend.get(pid) {
            if Instant::now() < *deadline && Arc::ptr_eq(held_t, t) {
                return; // challenge already in flight on THIS link; do not clobber its nonce
            }
        }
        pend.insert(
            pid.to_string(),
            (t.clone(), Instant::now() + PROVEN_CHALLENGE_DEADLINE),
        );
    }
    send_identity_challenge(conn, pid, identity_nonces).await;
}

/// Re-send the challenge already held for this link, SAME nonce: idempotent
/// for the peer, and the reason it exists is a measurement -- installing a
/// fresh nonce on every retry races the peer's reply whenever the reply's
/// RTT exceeds the retry cadence (200-400ms on relay paths), which drops
/// every answer and trades a deterministic timeout for a probabilistic one.
/// A fresh nonce is minted only when the held one has expired or belongs to
/// a different transport (see the settle caller).
pub(crate) async fn resend_identity_challenge(
    conn: &crate::Conn,
    pid: &str,
    identity_nonces: &std::collections::HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) -> bool {
    let Some((nonce, _issued, recv_dpub)) = identity_nonces.get(pid) else {
        return false;
    };
    let Some(t) = conn.transport_of(pid) else {
        return false;
    };
    let challenge = serde_json::json!({
        "type": "identity-nonce-challenge",
        "nonce": hex::encode(nonce),
        "receiver_device_pub": hex::encode(recv_dpub)
    });
    if let Err(e) = t.send_control(&challenge).await {
        // A challenge we could not write is indistinguishable, from the
        // challenger's side, from a peer that ignores us. Name it.
        crate::ui::say(&format!(
            "l2: identity challenge to {pid} could NOT be sent ({e}); the peer cannot prove until this link carries frames"
        ));
        return false;
    }
    true
}

/// A dropped proof is a SECURITY verdict and must never be invisible -- but
/// it is also peer-triggerable, so it is deduped per (link, reason) with a
/// cap: the operator sees the first one (at default level, like the other
/// refusals), and a peer replaying bad exposes cannot flood the log.
fn drop_once(pid: &str, why: &str) {
    const DROP_ONCE_CAP: usize = 512;
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    if let Ok(mut g) = seen.lock() {
        let key = format!("{pid}|{why}");
        if g.contains(&key) || g.len() >= DROP_ONCE_CAP {
            return;
        }
        g.insert(key);
    }
    crate::ui::say(&format!(
        "l2: identity-expose dropped for {pid}: {why} (not repeated for this link)"
    ));
}

/// Whether a recorded challenge hold has served its whole deadline. Pure so
/// the expiry rule is testable without a Conn or a sleeping test.
pub(crate) fn hold_expired(deadline: Instant, now: Instant) -> bool {
    now >= deadline
}

/// #161: how long the possession challenge stays LIVE. Must be raised in
/// lockstep with the offer hold (RECV_IDENTITY_HOLD_DEADLINE) and the nonce
/// lifetime: if the challenge entry expires first, a re-issue clobbers the
/// in-flight nonce and the peer's answer verifies against the wrong nonce and
/// never reaches Proven. Identity resolution normally settles well under a
/// second; the window exists for slow fallback links so a revoked device's
/// cert can still reach the gate's absolute Deny.
pub(crate) const PROVEN_CHALLENGE_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(20);

/// Handle a possession-sig identity-expose response sent by a peer after we
/// challenged it. Verifies the nonce (single-use), the possession_sig under
/// the peer's device_pub, and reflection (not self). On success, upgrades the
/// link binding to Proven so capability gates under authoritative can pass.
pub(crate) fn handle_identity_expose(
    conn: &mut crate::Conn,
    pid: &str,
    v: &Value,
    identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) -> bool {
    // Every drop below used to be silent, which made an unprovable link
    // indistinguishable from a link nobody challenged: the whole identity
    // path looked idle while a peer's proof was being discarded. Debug
    // level, so it costs nothing unless asked for.
    let fail = |why: &'static str| {
        drop_once(pid, why);
        crate::ui::debug(&format!("identity-expose dropped for {pid}: {why}"));
        false
    };
    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
    let Ok(nonce_bytes) = hex::decode(nonce_hex) else {
        return fail("malformed nonce");
    };
    if nonce_bytes.len() != 32 {
        return fail("nonce wrong length");
    }
    let mut nonce_arr = [0u8; 32];
    nonce_arr.copy_from_slice(&nonce_bytes);
    // Check held nonce matches (single-use)
    let Some((held_nonce, _ts, _held_recv_dpub)) = identity_nonces.get(pid) else {
        return fail("no challenge is held for this link (proof arrived on a different link?)");
    };
    if held_nonce != &nonce_arr {
        return fail("nonce does not match the one held for this link");
    }
    // Verify cert and possession sig
    let Some(cert_json) = v.get("cert") else {
        return fail("no certificate in the frame");
    };
    let Some(cert) = identity::DeviceCert::from_json(cert_json) else {
        return fail("unparseable certificate");
    };
    if cert.verify(identity::now_secs()).is_err() {
        return fail("certificate expired or malformed");
    }
    let Some(sig_hex) = v.get("possession_sig").and_then(|x| x.as_str()) else {
        return fail("no possession signature");
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return fail("possession signature is not hex");
    };
    if sig_bytes.len() != 64 {
        return fail("possession signature wrong length");
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    // Recompute possession_msg with held nonce
    let scope = crate::identity::IntroScope::User.to_byte();
    let caps_d = crate::identity::caps_digest("transfer");
    let chash = crate::identity::cert_hash(&cert);
    let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() else {
        return fail("this device has no overlay key");
    };
    let sender_dpub = cert.device_pub;
    let receiver_dpub = own_dpub;
    let msg = crate::identity::possession_msg(
        0x02,
        &nonce_arr,
        scope,
        &caps_d,
        &chash,
        &sender_dpub,
        &receiver_dpub,
    );
    if crate::identity::verify_possession_sig(&cert.device_pub, &msg, &sig_arr).is_err() {
        return fail("possession signature does not verify");
    }
    // Anti-reflection, narrowed to device_pub (#41). A REFLECTION is my own message
    // bounced back to me, which necessarily carries MY OWN device cert, so
    // `cert.device_pub == own_device_pub` catches exactly that. The OLD check refused
    // on `user_pub == own_user_pub`, which ALSO refused every legitimate same-owner
    // FLEET device (a DIFFERENT device_pub under the same user key) — that was the bug
    // that made OwnerDevice fleet unreachable. Narrowing keeps identical reflection
    // coverage and admits real fleet members. `own_dpub` is THIS machine's LOCAL device
    // pubkey (loaded above via overlay_pubkey_bytes), NEVER anything from the peer's
    // payload. On this 0x02 path the possession_msg also binds receiver_dpub non-zero,
    // so message binding is a second barrier here; on the 0x01 PAKE path it is not.
    if cert.device_pub == own_dpub {
        return fail("reflection: the certificate is this device's own");
    }
    // Store as provisional, then promote on link
    let _ = store_provisional_identity(&format!("peer-{}", pid), &cert);
    let (principal_kind, not_after, max_offline, last_seen) = persisted_principal_for_cert(&cert);
    if let Some(l) = conn.link_mut(pid) {
        l.identity_device_pub = Some(cert.device_pub);
        l.identity_user_pub = Some(cert.user_pub);
        l.identity_binding = crate::capability::BindingStrength::Proven;
        let (deadline, _clock) =
            effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
        l.identity_cert_expires = Some(deadline);
        l.principal_kind = principal_kind;
    }
    ui::say(&format!(
        "{} identity proven for peer {}",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        pid
    ));
    // #243: a vouch writes {name, secret} and nothing else, so the record carries
    // no certificate for revocation to key on: `revoke --certificate` bails with
    // "no stored fleet certificate", the peer re-derives as legacy trust on every
    // reconnect, and it renders as "trusted in full". The verified certificate is
    // right here, and until now only ever reached the pid-keyed sidecar that
    // `resolve_peer_identity` (petname-keyed) never reads.
    //
    // THE MODEL IS TRUST-ON-FIRST-USE, and it should be called that. `vouch` is
    // the CROSS-OWNER mechanism, so the peer's certificate cannot chain to our
    // root and `verify_chain` is not available; `cert.verify` only checks a cert
    // against its own embedded user_pub, which cannot say whose mesh this is. So
    // the first identity to answer for this petname is the one that gets pinned.
    // That is a defensible model, but it is a decision, not a fact, and the line
    // we print says so.
    //
    // What it is NOT: privilege escalation. A peer reaching here already holds
    // the pairing secret, so it already IS this petname to this device. The bound
    // is petname squatting and durable misidentification: the legitimate device
    // can never be certified under that name afterwards.
    //
    // Scoped to the VOUCH SHAPE, a known petname holding a secret with no cert.
    // Certifying every expose would undo the stated design of
    // `store_provisional_identity`, that a failed overlay session leaves no
    // durable anchor.
    let petname = conn.link(pid).map(|l| l.name.clone()).unwrap_or_default();
    if !petname.is_empty()
        // #266: VALID, not merely present. With a plain existence check an expired
        // vouch certificate held this gate shut forever while failing `verify`
        // everywhere else, so the device could never be re-certified.
        //
        // This relaxation is what makes the guard inside `update_peer_identity`
        // load-bearing rather than decorative: a second durable write becomes
        // reachable, and that guard refuses one carrying a different user key.
        && device_cert_valid_for(&petname).is_none()
        && devices_load().iter().any(|(n, _)| n == &petname)
    {
        match update_peer_identity(&petname, &cert, VOUCH_CERT_SCOPE) {
            Ok(()) => ui::say(&format!(
                "  {} first identity for '{}' pinned; `filament revoke {} --certificate` can now reach it",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                petname,
                petname
            )),
            // The in-memory Proven binding still holds for this link, but the
            // durable record stays un-revocable, which is the whole defect. Name
            // it rather than let the vouch look complete.
            Err(e) => ui::caution(
                &format!("'{petname}' is paired but not certified"),
                Some(&format!(
                    "its certificate was not stored ({e}), so revoke has nothing to key on."
                )),
                &[format!(
                    "remove it instead: filament devices forget {petname}"
                )],
            ),
        }
    }
    // Erase held nonce (single-use)
    identity_nonces.remove(pid);
    true
}

/// #30 shared responder: on receiving an identity-nonce-challenge, prove
/// device-key possession by signing possession_sig(0x02) over the peer-provided
/// nonce and replying with an identity-expose. The challenger's identity-expose
/// handler (`handle_identity_expose`) then upgrades our binding to Proven.
/// Shared by recv_cmd (the `up`/receiver loop) AND send_cmd (the one-shot
/// sender session) so a sender can prove possession and be authorized under an
/// authoritative cap gate. Reflection-guarded and echoes the challenger nonce.
///
/// WHICH KEY IS WHICH, because the names invite the opposite reading.
/// `receiver_device_pub` is the CHALLENGER's key, not ours: the challenger mints
/// it from its own overlay key (recv_cmd.rs, the pair-intro branch: "Receiver
/// device_pub is our own overlay key") and verifies the reply against
/// `receiver_dpub = own_dpub`. So there is deliberately NO "refuse unless the
/// receiver is us" rule here -- that rule, applied to a real challenge, would
/// refuse every peer in the fleet. possession_msg always carries OUR cert's
/// device_pub as sender, so this path can only ever sign as itself; the
/// challenger's key is the intended binding. The only refusal on the receiver
/// side is the REFLECTION guard below, and inverting it would be a PROTOCOL
/// change, not a hardening.
pub(crate) async fn respond_to_identity_challenge(t: &Arc<dyn Transport>, v: &Value) {
    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
    let recv_dpub_hex = v["receiver_device_pub"].as_str().unwrap_or_default();
    let (Ok(nonce_bytes), Ok(recv_dpub_bytes)) =
        (hex::decode(nonce_hex), hex::decode(recv_dpub_hex))
    else {
        crate::ui::debug("identity challenge ignored: malformed nonce/receiver fields");
        return;
    };
    if nonce_bytes.len() != 32 || recv_dpub_bytes.len() != 32 {
        crate::ui::debug("identity challenge ignored: nonce/receiver wrong length");
        return;
    }
    let mut nonce_arr = [0u8; 32];
    nonce_arr.copy_from_slice(&nonce_bytes);
    let mut recv_dpub_arr = [0u8; 32];
    recv_dpub_arr.copy_from_slice(&recv_dpub_bytes);
    // Reflection guard: never answer a challenge that names our own device key
    // as the challenger (a self-challenge).
    if let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() {
        if recv_dpub_arr == own_dpub {
            crate::ui::debug("identity challenge ignored: it names my own device key");
            return;
        }
    }
    let Some(local_cert) = local_device_cert() else {
        // LOUD, not debug: this refusal is why the peer will see no proof at
        // all, and a silent one is exactly how a link that cannot prove itself
        // reads as a link that was refused. Same class as the capsule's other
        // refusals, which are visible at the default level.
        crate::ui::say(
            "identity challenge NOT answered: this device holds no certificate for its own key",
        );
        return;
    };
    // Self-binding, made explicit rather than inherited: the certificate we are
    // about to sign with must BE this device's own key. `local_device_cert()`
    // already filters on that (it returns the cert only when
    // `cert.device_pub == overlay_pub` and the cert verifies), so this is
    // belt-and-braces against a future change to that accessor -- and it is the
    // invariant a reader is looking for when they ask "can this path sign as
    // somebody else?". It cannot: the signature is made with the overlay key
    // and carries this cert's device_pub as sender.
    match crate::overlay::overlay_pubkey_bytes() {
        Ok(own_pub) if local_cert.device_pub == own_pub => {}
        Ok(_) => {
            crate::ui::say(
                "identity challenge NOT answered: the local certificate is not this device's key (refusing to sign as another identity)",
            );
            return;
        }
        Err(e) => {
            crate::ui::say(&format!(
                "identity challenge NOT answered: this device's key is unreadable ({e}); nothing can be signed"
            ));
            return;
        }
    }
    let scope = crate::identity::IntroScope::User.to_byte();
    let caps_d = crate::identity::caps_digest("transfer");
    let chash = crate::identity::cert_hash(&local_cert);
    let sender_dpub = local_cert.device_pub;
    let msg = crate::identity::possession_msg(
        0x02,
        &nonce_arr,
        scope,
        &caps_d,
        &chash,
        &sender_dpub,
        &recv_dpub_arr,
    );
    if let Ok(sig) = crate::overlay::overlay_sign_possession(&msg) {
        // Echo the challenger's nonce so its held-nonce single-use check matches.
        let payload = json!({
            "type": "identity-expose",
            "v": 2,
            "binding_type": 0x02,
            "nonce": hex::encode(nonce_arr),
            "cert": local_cert.to_json(),
            "possession_sig": hex::encode(sig)
        });
        match t.send_control(&payload).await {
            Ok(()) => crate::ui::debug("identity challenge answered (identity-expose sent)"),
            Err(e) => crate::ui::say(&format!(
                "l2: identity-expose could NOT be sent ({e}); the challenger will see no proof"
            )),
        }
    } else {
        crate::ui::debug("identity challenge NOT answered: possession signing failed");
    }
}

/// #243: the intro scope a vouch stores. A vouch introduces a DEVICE, not a
/// user, so `Device` (0x01) is the correct anchor. The value is NOT cosmetic:
/// `apply_peer_identity` gates its device-pinning branch on
/// `existing_scope == 0x01`, so storing `User` here would silently disarm that
/// check for every LATER write to the same petname on the path where the guard
/// does run (l3-announce). Named as a constant so the choice is one line, is
/// testable, and cannot drift.
pub(crate) const VOUCH_CERT_SCOPE: u8 = 0x01; // identity::IntroScope::Device

pub(crate) fn update_peer_identity(
    name: &str,
    peer_cert: &identity::DeviceCert,
    scope: u8,
) -> Result<()> {
    // #243: refuse a re-anchor HERE, in the writer, rather than trusting each
    // caller to have checked first.
    //
    // `devices_upsert_atomic` -> `upsert_peer_record` overwrites `userKey` and
    // `deviceCert` unconditionally, with no comparison and no bail. The takeover
    // guard people assume protects this (`identity::apply_peer_identity`) had
    // exactly one production caller, the l3-announce path, and was never on this
    // one. I asserted otherwise in the first draft of this fix without tracing
    // the call, which is the same defect this issue is about.
    //
    // Today this is INERT for the vouch flow: the only caller gates on
    // `device_cert_for(..).is_none()`, so a second write never arrives. It is
    // here anyway because that gate is a policy in a caller while this is an
    // invariant in the store, and only one of those survives an edit. The edit
    // is already foreseeable: #266 (device_cert_for ignores expiry, so an
    // expired cert permanently blocks re-certification) will be fixed by
    // relaxing that gate to `is_none() || expired`, and at that moment a second
    // durable write becomes reachable and this is what refuses it.
    //
    // Do not delete this because it never fires. That is the point of it.
    // Guard and write in ONE with_devices_mut, not two.
    //
    // The first version called the guard in its own with_devices_mut and then
    // `devices_upsert_atomic` in a second. On Windows that failed outright with
    // "atomic write devices.json": the first cycle's handle was still open when
    // the second tried to rename over the file, and Windows will not replace an
    // open file. Linux tolerated it silently, so only the Windows CI job found
    // it. Two lock-and-write cycles where the operation is one.
    //
    // It was also a TOCTOU window: between the guard reading the record and the
    // upsert writing it, another writer could have changed the very thing the
    // guard just approved. Folding them removes the window as well as the
    // Windows failure, which is the better reason of the two.
    with_devices_mut(|arr| {
        identity::apply_peer_identity(arr, name, peer_cert, scope)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        upsert_peer_record(
            arr,
            name,
            None,
            Some(peer_cert),
            None,
            Some(scope),
            None,
            None,
        );
        Ok(())
    })?;
    Ok(())
}

/// Store provisional identity (held in memory, not durable trust) for later overlay check.
/// Written to a temp file, not devices.json, so a failed overlay session leaves no anchor.
pub(crate) fn store_provisional_identity(
    name: &str,
    peer_cert: &identity::DeviceCert,
) -> Result<()> {
    let p = crate::platform::Paths::config_path(format!("provisional_{}.json", name));
    let data = json!({
        "name": name,
        "deviceCert": peer_cert.to_json(),
        "storedAt": identity::now_secs()
    });
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&data)?)?;
    Ok(())
}

pub(crate) fn load_provisional_identity(name: &str) -> Option<identity::DeviceCert> {
    let p = crate::platform::Paths::config_path(format!("provisional_{}.json", name));
    let raw = std::fs::read_to_string(&p).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    identity::DeviceCert::from_json(&v["deviceCert"])
}

pub(crate) fn clear_provisional_identity(name: &str) {
    let p = crate::platform::Paths::config_path(format!("provisional_{}.json", name));
    let _ = std::fs::remove_file(&p);
}
