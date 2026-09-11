//! The enrolment command surface, lifted out of `main.rs`.
//!
//! `filament enroll` (join an owner's mesh with an invitation) and
//! `filament enroll --send` (enrol a device and then hand it a file), plus the
//! two helpers they share: `persist_join_ack`, which writes the join
//! acknowledgement into the local device store, and `enrollment_timeout`, the
//! shared long-op budget. Both helpers are called only from inside this module,
//! so they are module-private rather than re-exported.
//!
//! Two `tokio::spawn`s live here (one per command) and are self-contained: each
//! command owns its own event loop and spawns only owned values. No cfg
//! branches, no test hooks, no dlog. `base64::Engine` is imported once, inside
//! `enroll_cmd`, and travels with the body.
use crate::net::{self, Ev};
use crate::{AdoptSource, Conn, direct, fleet, identity, session, shutdown, ui};
use crate::{
    capability_list_summary, config_set, devices_upsert_atomic, display_name, fresh_secret,
    is_self_uid, load_delegation, local_device_cert_path, merge_owner_cap_ops, mk_uid,
    open_enrollment,
};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Store the certificates a join acknowledgement carried, and return the name.
///
/// ONE of these. There were two, `persist_join_ack` and `persist_join_ack_v2`,
/// identical but for a hoisted local: one took an AuthKey and one an Invitation,
/// which made them look like different functions. Once the two credentials
/// collapsed into one, the signatures became the same and so did the bodies.
fn persist_join_ack(v: &Value, inv: &crate::ephemeral::Invitation) -> Result<String> {
    if identity::UserKey::load(&crate::platform::PlatformKeyStore)?.is_some() {
        bail!(
            "this device already holds an identity key; join only from a clean Filament identity"
        );
    }
    if local_device_cert_path().exists() {
        bail!("this device already holds a joined certificate; refusing to overwrite it");
    }
    let assigned_name = v["name"]
        .as_str()
        .ok_or_else(|| anyhow!("join acknowledgement omitted the device name"))?;
    let owner_name = v["owner_name"]
        .as_str()
        .ok_or_else(|| anyhow!("join acknowledgement omitted the owner name"))?;
    let secret = v["secret"]
        .as_str()
        .ok_or_else(|| anyhow!("join acknowledgement omitted the reconnect secret"))?;
    if hex::decode(secret).map(|bytes| bytes.len()).ok() != Some(32) {
        bail!("join acknowledgement carried an invalid reconnect secret");
    }
    let expires = v["expires"]
        .as_u64()
        .ok_or_else(|| anyhow!("join acknowledgement omitted its expiry"))?;
    let ceiling = v["ceiling"]
        .as_array()
        .ok_or_else(|| anyhow!("join acknowledgement omitted its capability ceiling"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("join ceiling contains a non-string capability"))
        })
        .collect::<Result<Vec<_>>>()?;
    let max_offline = v["max_offline"]
        .as_u64()
        .ok_or_else(|| anyhow!("join acknowledgement omitted its offline budget ceiling"))?;
    let persistent = v["persistent"].as_bool().unwrap_or(false);
    if expires != inv.expires
        || ceiling != inv.caps
        || max_offline != inv.max_offline
        || persistent != !inv.ephemeral
    {
        bail!(
            "join acknowledgement changed a signed principal bound (ceiling, expiry, offline budget, or persistence)"
        );
    }
    let local_cert = identity::DeviceCert::from_json(&v["device_cert"])
        .ok_or_else(|| anyhow!("join acknowledgement omitted the local device certificate"))?;
    let owner_cert = identity::DeviceCert::from_json(&v["owner_cert"])
        .ok_or_else(|| anyhow!("join acknowledgement omitted the owner certificate"))?;
    let overlay_pub = crate::overlay::overlay_pubkey_bytes()?;
    let fp = crate::ephemeral::issuer_fingerprint(&owner_cert.user_pub);
    if local_cert.device_pub != overlay_pub
        || crate::ephemeral::issuer_fingerprint(&local_cert.user_pub) != inv.issuer_fp
        || local_cert.expires != expires
        || local_cert.verify(identity::now_secs()).is_err()
    {
        bail!("join acknowledgement carried an invalid local device certificate");
    }
    if fp != inv.issuer_fp || owner_cert.verify(identity::now_secs()).is_err() {
        bail!("join acknowledgement carried an invalid owner certificate");
    }
    let cert_path = local_device_cert_path();
    crate::platform::SecretFile::write_str(
        &cert_path,
        &serde_json::to_string_pretty(
            &json!({ "name": assigned_name, "cert": local_cert.to_json() }),
        )?,
    )?;
    let transfer_caps = vec!["transfer".to_string()];
    devices_upsert_atomic(
        owner_name,
        Some(secret),
        Some(&owner_cert),
        Some(&transfer_caps),
        Some(identity::IntroScope::Device.to_byte()),
        None,
        None,
    )?;
    // Fleet auto-mesh: keep the rendezvous secret the owner sent. Its ABSENCE is
    // not a failure, it just means no auto-mesh (an older owner, or a join that
    // was not persistent).
    if let Some(rv) = v["fleet_rv"].as_str() {
        if let Err(e) = fleet::store_rv(rv) {
            ui::debug(&format!("fleet rendezvous secret not stored: {e}"));
        }
    }
    // Same-owner fleet-trust: keep the owner's signed capability header so this
    // device knows which owner its policy answers to. Absence is not a failure
    // (an older owner simply does not send one); it just leaves the capability
    // layer unprovisioned here, which is the previous behaviour.
    if let Some(hdr) = v["cap_header"].as_object() {
        let dir = crate::settings::config_dir();
        let mut store = crate::capability::load_cap_store(&dir);
        let already = store.iter().any(|e| {
            e.get("type").and_then(|x| x.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some("self")
        });
        if !already {
            store.push(Value::Object(hdr.clone()));
            // The header alone is HALF of what an owner device has:
            // `ensure_self_genesis_header` writes a header AND a cap_ratchet, and
            // evaluation needs both. Measured with only the header delivered:
            // `own_user` resolved (so the header does its job) but the gate still
            // denied. The ratchet is a LOCAL anti-rollback record keyed on
            // owner_pub, carries no signature, and owner_pub is right here in the
            // header, so the joined device can create its own.
            let owner_pub = hdr
                .get("owner_pub")
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            if let Some(owner_pub) = owner_pub {
                let issued = hdr.get("issued_at").and_then(|v| v.as_u64()).unwrap_or(0);
                if let Err(e) = crate::capability::update_ratchet(&mut store, &owner_pub, issued) {
                    ui::debug(&format!("capability ratchet not initialised: {e}"));
                }
            }
            if let Err(e) = crate::capability::save_cap_store(&dir, &store) {
                ui::debug(&format!("owner capability header not stored: {e}"));
            }
        }
    }
    // Fleet policy from the owner. Verified against the owner key in the header
    // just stored, so an unverifiable or foreign-grantor entry is dropped.
    if let Some(ops) = v["cap_ops"].as_array() {
        let n = merge_owner_cap_ops(ops);
        if n > 0 {
            ui::debug(&format!("stored {n} owner-signed capability op(s)"));
        }
    }
    config_set("name", assigned_name)?;
    Ok(assigned_name.to_string())
}

pub(crate) async fn enroll_cmd(
    server: &str,
    inv: crate::ephemeral::Invitation,
    to_name: Option<String>,
    relay: bool,
    proposed_name: Option<&str>,
    json_output: bool,
) -> Result<()> {
    use base64::Engine;
    let enroll_seed = inv.enroll_private_key;
    let device_pub = crate::overlay::overlay_pubkey_bytes()?;

    if !json_output {
        ui::say(&format!(
            "{} invitation loaded (caps: {})",
            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
            capability_list_summary(&inv.caps)
        ));
    }

    let my_uid = mk_uid("e");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;

    // Join enrollment rendezvous channel derived from the owner's key
    // FINGERPRINT: the compact invitation carries only the 8-byte fp (#186),
    // and the owner's daemon derives the same channel from its full key.
    let enroll_chan = crate::ephemeral::enroll_channel_fp(&inv.issuer_fp);
    let local_name = proposed_name
        .map(str::to_string)
        .unwrap_or_else(display_name);
    let mut sess = session::Session::new(&local_name, &my_uid);
    sess.room = Some(format!("enrollup-{}", fresh_secret()));
    sess.channels = vec![enroll_chan.clone()];
    sess.emit(
        &sio,
        "join",
        json!({ "room": sess.room.as_ref().unwrap(), "name": local_name, "uid": my_uid }),
    )
    .await;
    sess.emit(&sio, "subscribe", json!({ "channels": [enroll_chan] }))
        .await;

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid,
        relay,
        to_name,
        false,
        direct::direct_enabled(),
    );

    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let started = Instant::now();
    let enroll_deadline = Duration::from_secs(60);

    loop {
        let elapsed = started.elapsed();
        if elapsed >= enroll_deadline {
            return Err(enrollment_timeout(enroll_deadline.as_secs()));
        }

        let slice = Duration::from_secs(2).min(enroll_deadline.saturating_sub(elapsed));
        let ev = match tokio::time::timeout(slice, rx.recv()).await {
            Ok(Some(ev)) => Some(ev),
            Ok(None) => bail!("signaling channel closed"),
            Err(_) => None,
        };

        sess.tick(&sio).await;

        let Some(ev) = ev else { continue };

        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, false).await?;
                    }
                }
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, false).await?;
            }
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, false, AdoptSource::Digest).await?;
                    }
                    for p in &roster.channel_peers {
                        if p["channel"].as_str() == Some(enroll_chan.as_str())
                            && !is_self_uid(&conn.my_uid, p["uid"].as_str())
                        {
                            conn.maybe_adopt_from(p, false, AdoptSource::Digest).await?;
                        }
                    }
                }
            }
            Ev::KnownPeer(v) => {
                // The owner daemon is present on the enroll channel. DIAL it as
                // the IMPOLITE peer (offerer): the owner answers via
                // ensure_responder (forced polite) and cannot reliably learn of
                // a late-arriving enroller from server presence, so the enroller
                // MUST drive the offer regardless of uid ordering.
                if !is_self_uid(&conn.my_uid, v["uid"].as_str())
                    && v["channel"].as_str() == Some(enroll_chan.as_str())
                {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty()
                        && !conn.links.contains_key(&pid)
                        && !conn.direct_pending.contains_key(&pid)
                    {
                        conn.roster.insert(pid.clone(), v.clone());
                        conn.establish_as(v.clone(), Some(false)).await?;
                        if conn.active.is_none() {
                            conn.active = Some(pid);
                        }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            Ev::ChannelReady(pid, t) => {
                conn.mark_ready(&pid, &t, true);

                crate::ephemeral::register_enrollment(
                    pid.clone(),
                    enroll_seed,
                    device_pub,
                    inv.clone(),
                );

                let _ = t.send_control(&json!({
                    "type": "identity-auth-key-enroll-request",
                    "auth_key_v2": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(inv.to_payload()),
                    "device_pub": hex::encode(device_pub),
                })).await;
                if !json_output {
                    ui::say(&format!(
                        "  {} sent enrollment request to {}",
                        ui::paint(ui::Tone::Dim, "->"),
                        pid
                    ));
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("identity-auth-key-enroll-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                        let verifier_hex = v["verifier_pub"].as_str().unwrap_or_default();
                        if let (Ok(nonce_bytes), Ok(verifier_bytes)) =
                            (hex::decode(nonce_hex), hex::decode(verifier_hex))
                        {
                            if let (Ok(nonce_arr), Ok(verifier_pub)) = (
                                nonce_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                                verifier_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            ) {
                                let device_cert = v
                                    .get("device_cert")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null);
                                if let Some(response) = crate::ephemeral::build_enrollment_response(
                                    &pid,
                                    nonce_arr,
                                    verifier_pub,
                                    &device_cert,
                                ) {
                                    let mut msg =
                                        json!({ "type": "identity-auth-key-enroll-response" });
                                    if let Some(obj) = response.as_object() {
                                        for (k, v) in obj {
                                            msg[k] = v.clone();
                                        }
                                    }
                                    let _ = t.send_control(&msg).await;
                                }
                            }
                        }
                    }
                }
                Some("identity-auth-key-enroll-ack") => {
                    let name = persist_join_ack(&v, &inv)?;
                    if json_output {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "joined": true,
                                "name": name,
                                "devicePub": hex::encode(device_pub),
                                "ceiling": inv.caps,
                                "expires": inv.expires,
                                "persistsAcrossReconnect": true,
                            }))?
                        );
                    } else {
                        ui::say(&format!(
                            "{} joined as '{}' with a persisted ceiling (device_pub: {})",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                            name,
                            hex::encode(device_pub)
                        ));
                    }
                    return Ok(());
                }
                Some("identity-auth-key-enroll-error") => {
                    // #222: name the reason the way the expired path does. The
                    // server sends a specific fact (already used / use limit
                    // reached / rate-limited) instead of a generic denial.
                    let reason = v["reason"].as_str().unwrap_or("unknown");
                    bail!(match reason {
                        "already used" => "this invitation has already been used".to_string(),
                        "use limit reached" =>
                            "this invitation has reached its use limit".to_string(),
                        _ => format!("enrollment denied: {reason}"),
                    });
                }
                _ => {}
            },
            Ev::Interrupted => bail!("cancelled"),
            Ev::SignalingDown(reason) => {
                bail!("signaling connection lost: {reason}");
            }
            _ => {}
        }
    }
}

/// Loads auth key, joins enrollment channel, completes handshake, then sends
/// files over the enrolled transport. The owner's daemon applies the ceiling.
pub(crate) async fn enroll_and_send_cmd(
    server: &str,
    auth_key_path: PathBuf,
    to_name: Option<String>,
    paths: Vec<String>,
    relay: bool,
    remember: Option<String>,
) -> Result<()> {
    let ak = load_delegation(&auth_key_path)?;
    let enroll_seed: [u8; 32] = ak.enroll_private_key;
    let device_pub = crate::overlay::overlay_pubkey_bytes()?;

    ui::say(&format!(
        "  {} enrolling as delegated (caps: {})",
        ui::paint(ui::Tone::Dim, "->"),
        capability_list_summary(&ak.caps)
    ));

    let enroll_chan = crate::ephemeral::enroll_channel_fp(&ak.issuer_fp);
    let my_uid = mk_uid("a");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.channels = vec![enroll_chan.clone()];
    sess.room = Some(format!("enrollup-{}", fresh_secret()));
    sess.emit(
        &sio,
        "join",
        json!({ "room": sess.room.as_ref().unwrap(), "name": display_name(), "uid": my_uid }),
    )
    .await;
    sess.emit(&sio, "subscribe", json!({ "channels": [enroll_chan] }))
        .await;

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid,
        relay,
        to_name.clone(),
        false,
        direct::direct_enabled(),
    );

    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let started = Instant::now();
    let deadline = Duration::from_secs(60);

    loop {
        if started.elapsed() >= deadline {
            return Err(enrollment_timeout(deadline.as_secs()));
        }
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        let Ok(Some(ev)) = ev else {
            // Check if we have a path to send — enrollment may already be done
            if conn.active.is_some() {
                break;
            }
            continue;
        };
        match ev {
            Ev::Welcome(v) => {
                // The owner daemon is already in the enroll room; the server hands
                // us its roster here. Dial each peer (owner answers) so rendezvous
                // does not depend on a later peer-joined we would otherwise miss.
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, true).await?;
            }
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                    }
                    for p in &roster.channel_peers {
                        if p["channel"].as_str() == Some(enroll_chan.as_str())
                            && !is_self_uid(&conn.my_uid, p["uid"].as_str())
                        {
                            conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                        }
                    }
                }
            }
            Ev::KnownPeer(v) => {
                // Enroller drives: dial the owner daemon (present on the enroll
                // channel) as the IMPOLITE offerer; the owner answers via
                // ensure_responder. Server presence does not reliably notify the
                // pre-existing owner of a late enroller, so we must initiate.
                if !is_self_uid(&conn.my_uid, v["uid"].as_str())
                    && v["channel"].as_str() == Some(enroll_chan.as_str())
                {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty()
                        && !conn.links.contains_key(&pid)
                        && !conn.direct_pending.contains_key(&pid)
                    {
                        conn.roster.insert(pid.clone(), v.clone());
                        conn.establish_as(v.clone(), Some(false)).await?;
                        if conn.active.is_none() {
                            conn.active = Some(pid);
                        }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            Ev::ChannelReady(pid, t) => {
                open_enrollment(&mut conn, &pid, &t, enroll_seed, device_pub, &ak).await;
                ui::say(&format!(
                    "  {} enrollment request sent",
                    ui::paint(ui::Tone::Dim, "->")
                ));
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("identity-auth-key-enroll-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                        let verifier_hex = v["verifier_pub"].as_str().unwrap_or_default();
                        let cert_val = v
                            .get("device_cert")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        if let (Ok(nonce_bytes), Ok(verifier_bytes)) =
                            (hex::decode(nonce_hex), hex::decode(verifier_hex))
                        {
                            if let (Ok(nonce_arr), Ok(verifier_pub)) = (
                                nonce_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                                verifier_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            ) {
                                if let Some(response) = crate::ephemeral::build_enrollment_response(
                                    &pid,
                                    nonce_arr,
                                    verifier_pub,
                                    &cert_val,
                                ) {
                                    let _ = t.send_control(&json!({
                                        "type": "identity-auth-key-enroll-response",
                                        "auth_key": response["auth_key"],
                                        "device_pub": response["device_pub"],
                                        "enroll_possession_sig": response["enroll_possession_sig"],
                                        "device_possession_sig": response["device_possession_sig"],
                                    })).await;
                                }
                            }
                        }
                    }
                }
                Some("identity-auth-key-enroll-ack") => {
                    let name = persist_join_ack(&v, &ak)?;
                    ui::say(&format!(
                        "  {} joined as {name}",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok())
                    ));
                    // Enrollment complete — break to send files
                    conn.active = Some(pid.clone());
                    break;
                }
                Some("identity-auth-key-enroll-error") => {
                    bail!(
                        "enrollment denied: {}",
                        v["reason"].as_str().unwrap_or("unknown")
                    );
                }
                _ => {}
            },
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }

    // Enrollment complete — now send files over the enrolled transport.
    // The owner's daemon applies the ceiling against auth_key.caps.
    ui::say(&format!(
        "  {} sending {} file(s)",
        ui::paint(ui::Tone::Dim, "->"),
        paths.len()
    ));
    let active_pid = conn.active.as_ref().cloned().unwrap_or_default();
    let t = conn
        .transport_of(&active_pid)
        .ok_or_else(|| anyhow::anyhow!("no transport after enrollment"))?;
    for path in &paths {
        let data = tokio::fs::read(path).await?;
        let name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");
        let id = format!("ak-{}", paths.iter().position(|p| p == path).unwrap_or(0));

        // Send file offer using the standard protocol
        let offer = crate::protocol::offer_msg(&id, 0, name, data.len() as u64, None, None, false);
        if let Err(e) = t.send_control(&offer).await {
            bail!("failed to send file offer for {name}: {e}");
        }

        // Wait for accept/decline (30s)
        let offer_start = Instant::now();
        let mut accepted = false;
        loop {
            if offer_start.elapsed() >= Duration::from_secs(30) {
                bail!("file offer for {name} timed out (no accept/decline)");
            }
            let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
            let Ok(Some(ev)) = ev else {
                continue;
            };
            if let Ev::Control(ref pid, ref v) = ev {
                if pid == &active_pid && v["id"].as_str() == Some(&id) {
                    match v["type"].as_str() {
                        Some("file-accept") => {
                            accepted = true;
                            break;
                        }
                        Some("file-decline") => {
                            bail!(
                                "file {name} declined: {}",
                                v["reason"].as_str().unwrap_or("not authorized")
                            );
                        }
                        _ => {}
                    }
                }
            }
            if matches!(ev, Ev::Interrupted) {
                bail!("interrupted");
            }
        }
        if !accepted {
            bail!("transfer of {name} not accepted");
        }

        // Write data chunks via send_frame (sid=0, offset-incremented)
        let total = data.len();
        let max_payload = t.max_payload().max(1024);
        let mut sent = 0usize;
        while sent < total {
            let end = total.min(sent + max_payload);
            let chunk = &data[sent..end];
            t.send_frame(0, sent as u64, chunk).await.map_err(|e| {
                anyhow::anyhow!(
                    "data channel failed during transfer of {name} (sent {sent}/{total}): {e}"
                )
            })?;
            sent = end;
        }
        let _ = t.flush().await;
        // File-end marker so the receiver finalizes + hashes the complete file.
        // Must match the sid declared in the offer (0).
        t.send_control(&crate::protocol::end_msg(&id, 0))
            .await
            .map_err(|e| anyhow::anyhow!("failed to send file-end for {name}: {e}"))?;
        ui::say(&format!(
            "  {} sent {} ({} bytes)",
            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
            name,
            total
        ));
    }
    if let Some(name) = remember {
        // The SIGNED key decides persistence, not this flag (it cannot flip a
        // signature). An ephemeral key cannot be remembered: a durable device
        // needs a join invitation, which mints a persistent key.
        if ak.ephemeral {
            ui::say(&format!(
                "  {} --remember cannot persist this enrollment: the key is signed ephemeral. For a remembered device, the owner mints `filament add --for device` and it joins (`filament join`).",
                ui::paint(ui::Tone::Warn, "·"),
            ));
        } else {
            ui::say(&format!(
                "  {} enrolled persistently as '{name}'",
                ui::paint(ui::Tone::Ok, ui::glyph_ok())
            ));
        }
    }
    Ok(())
}

/// The enrolment timeout message, said once.
///
/// It was said three times and had already drifted into three different
/// sentences: "timed out after Ns (no response from peer)", "timed out after
/// Ns", and a bare "timed out". Which one an operator saw depended on whether
/// they were joining, sending with a key, or opening a port, which is not a
/// distinction they can act on. The least informative was the one a CI runner
/// hit, where there is nobody watching to fill in the gap.
fn enrollment_timeout(secs: u64) -> anyhow::Error {
    anyhow!("enrollment timed out after {secs}s (no response from peer)")
}
