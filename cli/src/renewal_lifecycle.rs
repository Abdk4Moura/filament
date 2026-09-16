//! Certificate-renewal and auth-key enrolment lifecycle, lifted out of
//! `main.rs`.
//!
//! What a same-owner device does mid-session to keep its authority current:
//! ask us to renew its certificate (`respond_to_cert_renew_request`), tell us
//! its renewal landed (`handle_cert_renew_ack`), enrol an auth key with us
//! (`respond_to_auth_key_enroll_request`), report the enrolment result
//! (`handle_auth_key_enroll_response`), and decide whether we ourselves need to
//! ask for renewal (`renewal_standing_for`, `maybe_request_cert_renewal`).
//!
//! Every function takes what it needs explicitly (`&mut Conn`, a peer id, a
//! `Value`), so the move is a relocation: no context struct, no closure capture,
//! no ownership change. There are no cfg or feature branches in this block and
//! no spawned tasks, so the receive loop keeps ownership of its own state.
use crate::Conn;
use crate::identity;
use crate::ui;
use crate::{
    PRINCIPAL_STATE_LAPSED, PRINCIPAL_STATE_REVOKED, capability_list_summary,
    devices_find_by_device_pub, devices_upsert_atomic, display_name, enrollment_refusal,
    fmt_short_duration, fresh_secret, load_owner_key, local_device_cert, local_device_cert_path,
    mesh_enrolment,
};
use serde_json::{Value, json};

fn renewal_standing_for(device_pub: &[u8; 32]) -> crate::fleet_renewal::Standing {
    let Some(record) = devices_find_by_device_pub(device_pub) else {
        return crate::fleet_renewal::Standing::default();
    };
    let stored = record["deviceCert"]["devicePub"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
    crate::fleet_renewal::Standing {
        known: true,
        revoked: record["certRevoked"].as_bool() == Some(true)
            || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED),
        lapsed: record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED),
        stored_device_pub: stored,
    }
}

/// OWNER SIDE: re-sign a fleet device's certificate, or refuse.
///
/// THE DEVICE KEY COMES FROM THE PROVEN LINK, never from the message body. A
/// renewal names a device, so if the caller could name it, any peer could ask us
/// to re-sign somebody else's certificate and then present the result. The link
/// binding is the only statement about who is actually talking, so it is the
/// only thing allowed to answer that question.
///
/// Refusals are logged locally and answered with a bare error to the peer. A
/// refusal that explains itself turns this into an oracle for probing which
/// device keys the owner knows.
pub(crate) async fn respond_to_cert_renew_request(conn: &mut Conn, pid: String) {
    let Some(link) = conn.link(&pid) else { return };
    let proven = link.identity_binding == crate::capability::BindingStrength::Proven;
    let device_pub = link.identity_device_pub;
    let (Some(device_pub), true) = (device_pub, proven) else {
        ui::debug("  cert renewal refused: requester is not identity-proven on this link");
        if let Some(t) = conn.transport_of(&pid) {
            let _ = t
                .send_control(&json!({"type": "identity-cert-renew-error"}))
                .await;
        }
        return;
    };

    // Only a machine holding the owner SIGNING key can renew. A fleet member
    // that is asked simply declines: it is not a failure, it is not a primary.
    let Some(owner_key) = load_owner_key() else {
        ui::debug("  cert renewal declined: this device holds no owner signing key");
        if let Some(t) = conn.transport_of(&pid) {
            let _ = t
                .send_control(&json!({"type": "identity-cert-renew-error"}))
                .await;
        }
        return;
    };

    let standing = renewal_standing_for(&device_pub);
    match crate::fleet_renewal::owner_decides(&standing, device_pub) {
        crate::fleet_renewal::Decision::Refuse(why) => {
            ui::debug(&format!("  cert renewal refused: {why}"));
            if let Some(t) = conn.transport_of(&pid) {
                let _ = t
                    .send_control(&json!({"type": "identity-cert-renew-error"}))
                    .await;
            }
        }
        crate::fleet_renewal::Decision::Renew => {
            let now = identity::now_secs();
            // The lifetime the device ALREADY has, not the global default. See
            // fleet_renewal::renewal_ttl: renewing a one-hour guest into a
            // 90-day member would widen the exact bound renewal enforces.
            let ttl = match devices_find_by_device_pub(&device_pub)
                .as_ref()
                .and_then(|r| identity::DeviceCert::from_json(&r["deviceCert"]))
            {
                Some(current) => {
                    crate::fleet_renewal::renewal_ttl(&current, identity::CERT_TTL_SECS)
                }
                None => identity::CERT_TTL_SECS,
            };
            let Ok(fresh) = identity::DeviceCert::certify(&owner_key, device_pub, now, ttl) else {
                ui::debug("  cert renewal failed: could not sign");
                return;
            };
            // Keep OUR copy in step, so the roster and every expiry readout
            // agree with what the device now holds. A renewal the owner cannot
            // see is how "renews in 87d" became a lie the first time.
            if let Some(record) = devices_find_by_device_pub(&device_pub) {
                if let Some(name) = record["name"].as_str() {
                    // Strict: renewal must never re-anchor (the proven link
                    // key always matches the pinned record in production).
                    let _ = devices_upsert_atomic(
                        name,
                        None,
                        Some(&fresh),
                        None,
                        None,
                        None,
                        None,
                        false,
                    );
                }
            }
            if let Some(t) = conn.transport_of(&pid) {
                let _ = t
                    .send_control(&json!({
                        "type": "identity-cert-renew-ack",
                        "cert": fresh.to_json(),
                    }))
                    .await;
            }
            ui::debug(&format!(
                "  renewed certificate for {}",
                hex::encode(device_pub).chars().take(8).collect::<String>()
            ));
        }
    }
}

/// REQUESTING SIDE: adopt a renewed certificate, or keep the one we have.
///
/// Every check lives in `fleet_renewal::accept_renewal`, which refuses a changed
/// device key, a changed owner, a different signer, and a replayed older cert.
/// Nothing here is trusted just because it arrived on a link we like.
pub(crate) async fn handle_cert_renew_ack(v: &Value) {
    let Some(fresh) = identity::DeviceCert::from_json(&v["cert"]) else {
        ui::debug("  renewal ack carried no readable certificate");
        return;
    };
    let Some(current) = local_device_cert() else {
        // Nothing to renew FROM. Adopting a cert here would be accepting an
        // identity rather than extending one.
        ui::debug("  renewal ack ignored: this device holds no certificate to extend");
        return;
    };
    let owner_pub = current.user_pub;
    if let Err(e) =
        crate::fleet_renewal::accept_renewal(&current, &fresh, &owner_pub, identity::now_secs())
    {
        ui::debug(&format!("  renewal rejected: {e}"));
        return;
    }
    let path = local_device_cert_path();
    let record = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
    let name = record
        .as_ref()
        .and_then(|r| r["name"].as_str().map(str::to_string))
        .unwrap_or_default();
    let body = json!({ "name": name, "cert": fresh.to_json() });
    // SecretFile::write_str, the same writer enrollment uses for this exact
    // file, not write_owner_only_file. That helper opens with create_new(true)
    // because it exists to mint invitations, so it refuses to clobber and every
    // renewal failed on the last line of the whole flow: the owner signed, the
    // device accepted, and then could not save it. The chain reported success
    // at every step except the one that mattered.
    match crate::platform::SecretFile::write_str(
        &path,
        &serde_json::to_string_pretty(&body).unwrap_or_default(),
    ) {
        Ok(()) => ui::debug(&format!(
            "  certificate renewed, now valid for {}",
            fmt_short_duration(fresh.expires.saturating_sub(identity::now_secs()))
        )),
        Err(e) => ui::debug(&format!("  could not persist renewed certificate: {e}")),
    }
}

/// Ask a peer to renew our certificate, if it is time and we are a fleet member.
///
/// Cheap and idempotent: not-due is the common case and returns immediately, so
/// this can be called on every link that comes up. An owner device has no one to
/// ask and never asks.
pub(crate) async fn maybe_request_cert_renewal(conn: &Conn, pid: &str) {
    if load_owner_key().is_some() {
        return; // we sign our own; there is nothing to request
    }
    let Some(cert) = local_device_cert() else {
        return;
    };
    if !crate::fleet_renewal::renewal_due(&cert, identity::now_secs()) {
        return;
    }
    if let Some(t) = conn.transport_of(pid) {
        let _ = t
            .send_control(&json!({"type": "identity-cert-renew-request"}))
            .await;
    }
}

pub(crate) async fn respond_to_auth_key_enroll_request(
    conn: &mut Conn,
    pid: String,
    v: serde_json::Value,
) {
    let Some(t) = conn.transport_of(&pid) else {
        return;
    };

    // Rate-limit FIRST — keyed on pid, counts EVERY request including garbage.
    // An attacker sending unparseable JSON is bounded here, before parse cycles.
    if let Err(e) = crate::ephemeral::check_rate_limit(&pid) {
        ui::debug(&format!("enroll request rate-limited: {e}"));
        let _ = t
            .send_control(
                &json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"}),
            )
            .await;
        return;
    }

    // Enroll-and-use is coherent in BOTH modes: the delegated ceiling is
    // enforced in shadow mode too (cap_gate_effective's ceiling check is
    // mode-independent and load-bearing exactly because shadow's effective
    // decision is legacy_allowed, which the ceiling check precedes). An
    // earlier gate refused enrollment unless FILAMENT_CAP_AUTHORITATIVE=1;
    // that rationale is stale and it made the flagship join flow fail for a
    // default-configured owner. The joined device's ceiling binds either way.

    // ONE READER. The enrolment request carries the invitation payload,
    // base64url. There was a second branch here for an `auth_key` JSON, whose
    // own comment said "the legacy v1 mint/enroll path (hidden) still sends"
    // it: that path was `ephemeral mint`, which no longer exists, so nothing
    // produces that form and this accepted a shape it could never receive.
    //
    // A second accepted credential shape on an ENROLMENT handler is not free
    // even when unused. It is a second way to become a principal, reviewed
    // once and then carried, and it is the kind of thing that outlives the
    // reason it was added.
    let ak = {
        use base64::Engine;
        let Some(v2_b64) = v.get("auth_key_v2").and_then(|x| x.as_str()) else {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        };
        let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v2_b64) else {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        };
        match crate::ephemeral::Invitation::from_payload(&bytes) {
            Some(inv) => crate::ephemeral::EnrollmentPrincipal::Compact(inv),
            None => {
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
        }
    };

    // Verify against our trusted owner
    let owner_key = match crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        Ok(Some(uk)) => uk,
        _ => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let owner_pub = owner_key.public_key_bytes();
    let verifier_pub = match crate::overlay::overlay_pubkey_bytes() {
        Ok(pk) => pk,
        Err(e) => {
            ui::debug(&format!("enroll request overlay-key error: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    // Verify the principal under our trusted owner, then reconstruct the full
    // auth key (Compact: fingerprint + compact signature; Legacy: full-issuer
    // verify) for the principal registration that follows.
    let _ak = match &ak {
        crate::ephemeral::EnrollmentPrincipal::Compact(inv) => {
            if !inv.verify_against_owner(&owner_pub) {
                ui::debug("enroll request auth-key rejected (fingerprint or signature)");
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
            if identity::now_secs() >= inv.expires {
                ui::debug("enroll request auth-key expired");
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
            inv.to_auth_key(&owner_pub)
        }
        crate::ephemeral::EnrollmentPrincipal::Legacy(ak) => {
            if ak.verify_against_owner(&owner_pub, &verifier_pub).is_err() {
                ui::debug("enroll request legacy auth-key rejected");
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
            ak.clone()
        }
    };

    // Generate nonce challenge — include daemon's device cert so the enroller
    // can verify it chains to the auth key's issuer (mutual authentication).
    let nonce = match crate::ephemeral::generate_nonce(&pid) {
        Ok(n) => n,
        Err(e) => {
            ui::debug(&format!("enroll request nonce CSPRNG failure: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let cert_value = local_device_cert().map(|c| c.to_json());
    let _ = t
        .send_control(&json!({
            "type": "identity-auth-key-enroll-challenge",
            "nonce": hex::encode(nonce),
            "verifier_pub": hex::encode(verifier_pub),
            "device_cert": cert_value,
        }))
        .await;
}

/// Handle the enrollment response from the enroller.
/// Step 4 (burn only on SUCCESS): consume nonce, verify payload, admit as delegated.
pub(crate) async fn handle_auth_key_enroll_response(
    conn: &mut Conn,
    pid: String,
    v: serde_json::Value,
) {
    let Some(t) = conn.transport_of(&pid) else {
        return;
    };
    let payload = match crate::ephemeral::EnrollmentPayload::from_json(&v) {
        Some(p) => p,
        None => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let owner_key = match crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        Ok(Some(uk)) => uk,
        _ => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let owner_pub = owner_key.public_key_bytes();
    let verifier_pub = match crate::overlay::overlay_pubkey_bytes() {
        Ok(pk) => pk,
        Err(e) => {
            ui::debug(&format!("enroll response overlay-key error: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };

    // Structural nonce consumption — daemon retrieves its OWN stored nonce,
    // never trusts a nonce value echoed by the enroller.
    let nonce = match crate::ephemeral::consume_latest_nonce(&pid) {
        Ok(n) => n,
        Err(e) => {
            ui::debug(&format!("enroll response nonce consumption failed: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };

    // Verify payload with consumed nonce
    match payload.verify(&owner_pub, &nonce, &verifier_pub) {
        Ok((enroll_pub, device_pub, ak)) => {
            // Burn ON SUCCESS only (never-reset counter)
            if let Err(e) = crate::ephemeral::burn_auth_key(&enroll_pub, &ak.reuse) {
                ui::debug(&format!("enroll response burn failed: {e}"));
                // #222: the burn state knows WHY it refused (already used,
                // use limit reached, rate-limited). Send that specific fact,
                // not the generic "enrollment denied", so the joiner can say
                // it the way the expired path does.
                let msg = e.to_string();
                let reason = if msg.contains("already used") {
                    "already used"
                } else if msg.contains("exhausted") {
                    "use limit reached"
                } else if msg.contains("rate-limited") {
                    "rate-limited"
                } else {
                    "enrollment denied"
                };
                let _ = t
                    .send_control(
                        &json!({"type": "identity-auth-key-enroll-error", "reason": reason}),
                    )
                    .await;
                return;
            }
            // #155: the enrollment side READS the signed `ephemeral` flag. An
            // ephemeral key admits in-memory only: nothing durable is written,
            // so the device is gone at daemon restart by construction (Q2). A
            // persistent key writes the durable record with the ceiling and the
            // offline-budget pair, surviving restart.
            let persistent = !ak.ephemeral;
            let mut requested_name = conn
                .link(&pid)
                .map(|link| link.name.clone())
                .unwrap_or_else(|| "joined-device".to_string());
            // A device re-joining with its own device_pub meets its prior record.
            // LAPSED revives (a network accident): keep the name for continuity,
            // and the delegated write below OVERWRITES the whole bounding set
            // from the NEW key (fresh bounds win, never merged). REVOKED is a
            // decision, not an accident: refuse, and tell the owner only
            // `devices restore` undoes it.
            let prior = devices_find_by_device_pub(&device_pub);
            if let Some(prior_record) = &prior {
                if let Some(reason) = enrollment_refusal(prior_record) {
                    ui::debug(&format!(
                        "enroll response refused: device {pid} was revoked"
                    ));
                    let _ = t
                        .send_control(
                            &json!({"type": "identity-auth-key-enroll-error", "reason": reason}),
                        )
                        .await;
                    return;
                }
                if persistent
                    && prior_record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED)
                {
                    if let Some(name) = prior_record["name"].as_str() {
                        requested_name = name.to_string();
                    }
                }
            }
            // Re-anchor ONLY an identity we already know under this exact
            // name (this same key re-enrolling, e.g. the lapsed revival
            // above reusing its name). A new key under a taken name takes
            // a free-or-suffixed name and never overwrites another
            // identity's record -- the invitation authorizes enrollment,
            // not name-squatting.
            let mut candidate = crate::sanitize_device_name(&requested_name);
            let mut allow_reanchor =
                prior.as_ref().and_then(|r| r["name"].as_str()) == Some(candidate.as_str());
            if !allow_reanchor {
                let base = candidate.clone();
                let hex = hex::encode(device_pub);
                let mut n = 2u32;
                while crate::devices_store::name_pinned_by_other(&candidate, &hex) && n < 1000 {
                    candidate = format!("{base}-{n}");
                    n += 1;
                }
            }
            let requested_name = candidate;
            let secret = fresh_secret();
            let now = identity::now_secs();
            let _certificate_ttl = ak.expires.saturating_sub(now);
            // ONE enrolment builder, shared with the pairing ceremony. Minting a
            // certificate for a peer happens in exactly one place.
            let (device_cert, enrolment) = match mesh_enrolment(
                &owner_key, device_pub, &ak.caps, ak.expires, persistent,
            ) {
                Ok(pair) => pair,
                Err(error) => {
                    ui::debug(&format!("enroll response certificate failed: {error}"));
                    let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                    return;
                }
            };
            // `ak.caps` already carries the route scope as `route:<cidr>`:
            // Invitation::to_auth_key does that conversion once, so nothing here
            // has to reassemble it.
            let stored_name = if persistent {
                match devices_upsert_atomic(
                    &requested_name,
                    Some(&secret),
                    Some(&device_cert),
                    Some(&ak.caps),
                    Some(identity::IntroScope::Device.to_byte()),
                    None,
                    Some((&ak.caps, ak.expires, ak.max_offline, ak.max_offline)),
                    allow_reanchor,
                ) {
                    Ok(name) => name,
                    Err(error) => {
                        ui::debug(&format!("enroll response persistence failed: {error}"));
                        let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                        return;
                    }
                }
            } else {
                // Ephemeral: nothing durable is written; the name is session-only.
                requested_name
            };
            // Admit as Delegated principal — structurally, all four fields together
            if let Some(link) = conn.link_mut(&pid) {
                link.verified_name = Some(stored_name.clone());
                link.admit_delegated(owner_pub, device_pub, ak.expires, ak.caps.clone());
            }
            let mut ack = enrolment;
            ack["type"] = json!("identity-auth-key-enroll-ack");
            ack["name"] = json!(stored_name);
            ack["owner_name"] = json!(display_name());
            ack["secret"] = json!(secret);
            ack["device_pub"] = json!(hex::encode(device_pub));
            ack["max_offline"] = json!(ak.max_offline);
            let _ = t.send_control(&ack).await;
            ui::say(&format!(
                "  {} ephemeral device {pid} enrolled (caps: {})",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                capability_list_summary(&ak.caps)
            ));
        }
        Err(e) => {
            ui::debug(&format!("enroll response verify failed: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
        }
    }
}
