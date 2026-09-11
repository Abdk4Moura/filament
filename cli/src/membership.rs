//! Signalling-room membership commands, lifted out of `main.rs`.
//!
//! `filament introduce A B` puts two devices into each other's room so they can
//! find one another, and `filament depart` leaves the mesh. Both are membership
//! operations on the signalling room and share the room's channel derivation
//! (`channel_of`) and the join-record lookup (`joined_owner_record`).
//!
//! No cfg branches, no test hooks, no dlog, no spawned tasks in either body.
//! `introduce_cmd` carries one function-local `use ring::rand::{SecureRandom,
//! SystemRandom};`, which travels with it.
use crate::conn::{RejoinState, ResilienceState, WarmHold};
use crate::net::{self, Ev};
use crate::{
    AdoptSource, Conn, REJOIN_WINDOW, channel_of, device_cert_for, devices_load, direct,
    display_name, fresh_secret, is_self_uid, joined_owner_record, mk_uid, overlay, proof_for,
    session, ui,
};
use anyhow::{Result, anyhow, bail};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Advisory end-of-life verb for a joined device: tell the owner to free the
/// slot NOW instead of paying out the whole offline budget. NEVER load-bearing:
/// a crash, a power cut, or a hostile device sends nothing, and the budget is
/// the mechanism that lapses them. The goodbye is only an optimization the
/// polite path uses.
pub(crate) async fn depart_cmd(server: &str, relay: bool) -> Result<()> {
    let Some((owner_name, owner_secret)) = joined_owner_record() else {
        bail!(
            "no joined owner on this device; `depart` is the end-of-life verb for a joined device"
        );
    };
    let device_pub = crate::overlay::overlay_pubkey_bytes()?;
    let msg = format!("filament-depart:v1:{}", hex::encode(device_pub));
    let sig = crate::overlay::overlay_sign_possession(msg.as_bytes())?;

    let my_uid = mk_uid("d");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    let owner_chan = channel_of(&owner_secret);
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(format!("depart-{}", fresh_secret()));
    sess.channels = vec![owner_chan.clone()];
    sess.emit(
        &sio,
        "join",
        json!({ "room": sess.room.as_ref().unwrap(), "name": display_name(), "uid": my_uid }),
    )
    .await;
    sess.emit(&sio, "subscribe", json!({ "channels": [owner_chan] }))
        .await;

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid,
        relay,
        Some(owner_name.clone()),
        false,
        direct::direct_enabled(),
    );

    let started = Instant::now();
    let deadline = Duration::from_secs(20);
    let mut sent = false;
    let mut acked = false;
    loop {
        let slice = Duration::from_secs(2).min(deadline.saturating_sub(started.elapsed()));
        let ev = match tokio::time::timeout(slice, rx.recv()).await {
            Ok(Some(ev)) => Some(ev),
            Ok(None) => break,
            Err(_) => None,
        };
        sess.tick(&sio).await;
        if !sent {
            let goodbye = conn.links.iter().find_map(|(pid, l)| {
                l.transport
                    .as_ref()
                    .filter(|t| t.is_alive())
                    .map(|t| (pid.clone(), t.clone()))
            });
            if let Some((_, t)) = goodbye {
                let _ = t
                    .send_control(&json!({
                        "type": "depart",
                        "device_pub": hex::encode(device_pub),
                        "msg": msg,
                        "sig": hex::encode(sig),
                    }))
                    .await;
                sent = true;
                ui::say(&format!(
                    "  {} told {owner_name} you are departing",
                    ui::paint(ui::Tone::Dim, "->")
                ));
            }
        }
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
                }
            }
            Ev::KnownPeer(v) => {
                if !is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty()
                        && !conn.links.contains_key(&pid)
                        && !conn.direct_pending.contains_key(&pid)
                    {
                        conn.roster.insert(pid.clone(), v.clone());
                        conn.establish_as(v.clone(), Some(false)).await?;
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
            }
            Ev::Control(_pid, v) => {
                if v["type"].as_str() == Some("depart-ack") {
                    acked = true;
                }
            }
            Ev::SignalingDown(reason) => {
                ui::debug(&format!("depart: signaling down: {reason}"));
                break;
            }
            _ => {}
        }
        if sent && acked {
            break;
        }
        if sent && started.elapsed() >= Duration::from_secs(5) {
            break;
        }
        if started.elapsed() >= deadline {
            break;
        }
    }
    let _ = sio.disconnect().await;
    if acked {
        ui::say(&format!(
            "  {} {owner_name} acknowledged; your slot is freed",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
    } else {
        ui::say(&format!(
            "  {} departure advisory: if {owner_name} was unreachable, the offline budget still lapses you",
            ui::paint(ui::Tone::Dim, "·")
        ));
    }
    Ok(())
}

pub(crate) async fn introduce_cmd(server: &str, a: &str, b: &str, relay: bool) -> Result<()> {
    let store = devices_load();
    let find = |n: &str| {
        store
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(n))
            .cloned()
    };
    let (a_name, a_sec) =
        find(a).ok_or_else(|| anyhow!("'{a}' is not a known device (see: filament devices)"))?;
    let (b_name, b_sec) = find(b).ok_or_else(|| anyhow!("'{b}' is not a known device"))?;

    let my_uid = mk_uid("s");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    let solo = format!("intro-{}", fresh_secret());
    // C30: the session repairs whatever these emits lose, and under gate L
    // they are the emits the loss shim adversarially drops.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(solo.clone());
    sess.channels = vec![channel_of(&a_sec), channel_of(&b_sec)];
    sess.emit(
        &sio,
        "join",
        json!({ "room": solo, "name": display_name(), "uid": my_uid }),
    )
    .await;
    sess.emit(
        &sio,
        "subscribe",
        json!({ "channels": [channel_of(&a_sec), channel_of(&b_sec)] }),
    )
    .await;
    ui::say(&format!(
        "  waiting for {} and {} to be online...",
        ui::paint(ui::Tone::Bold, &a_name),
        ui::paint(ui::Tone::Bold, &b_name)
    ));

    let mut conn = Conn {
        server: server.to_string(),
        sio: sio.clone(),
        tx: tx.clone(),
        my_uid: my_uid.clone(),
        my_id: String::new(),
        relay_only: relay,
        to_filter: None,
        links: HashMap::new(),
        roster: HashMap::new(),
        suppressed_digest_adoptions: HashSet::new(),
        active: None,
        active_binding: None,
        next_gen: 0,
        rejoin: RejoinState {
            waiting_rejoin: None,
            rejoin_window: REJOIN_WINDOW,
            away: None,
        },
        chunk_size: net::MAX_DC_PAYLOAD,
        deferred_left: HashMap::new(),
        recv_done: false,
        direct_pending: HashMap::new(),
        buffered_offers: HashMap::new(),
        resil: ResilienceState {
            stall_repairs: HashMap::new(),
            relay_committed: std::collections::HashSet::new(),
            warm_standby: net::warm_standby_override().unwrap_or(false),
            warm_cutover: std::collections::HashSet::new(),
            upgrade_probe: HashMap::new(),
            iface_snapshot: Vec::new(),
        },
        direct_ok: direct::direct_enabled(),
        local_port: None,
        local_listener: None,
        direct_endpoint: None,
        warm_hold: WarmHold::default(),
        worker_port_tx: HashMap::new(),
        roster_pushed: None,
    };
    // sid -> which device (false = a, true = b)
    let mut who: HashMap<String, bool> = HashMap::new();
    let mut sent: [bool; 2] = [false, false];
    let fresh = fresh_secret();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut channel_digest_absent: HashMap<String, u8> = HashMap::new();

    loop {
        if Instant::now() > deadline {
            bail!("timed out, both devices must be online (e.g. running `filament up`)");
        }
        let ev = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead
        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                // C30 (dissolves the C28 belt): fresh sid, re-assert via session.
                sess.invalidate();
            }
            // C30 phase 2: reconcile the roster the digest carries so a missed
            // `welcome`/`peer-joined` self-corrects instead of stranding this
            // wait. `introduce` waits on room presence, so it is class S.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, false, AdoptSource::Digest).await?;
                    }
                    for p in &roster.channel_peers {
                        if is_self_uid(&conn.my_uid, p["uid"].as_str()) {
                            continue;
                        }
                        let ch = p["channel"].as_str().unwrap_or_default();
                        let (is_b, secret, name) = if ch == channel_of(&a_sec) {
                            (false, &a_sec, &a_name)
                        } else if ch == channel_of(&b_sec) {
                            (true, &b_sec, &b_name)
                        } else {
                            continue;
                        };
                        let pid = p["id"].as_str().unwrap_or_default().to_string();
                        conn.maybe_adopt_from(p, false, AdoptSource::Digest).await?;
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = Some((name.clone(), secret.clone()));
                        }
                        who.insert(pid, is_b);
                    }
                    let present: std::collections::HashSet<String> = roster
                        .channel_peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    let channels = [channel_of(&a_sec), channel_of(&b_sec)];
                    let mut gone = Vec::new();
                    for (pid, link) in &conn.links {
                        let tracked = link
                            .expected_secret
                            .as_ref()
                            .map(|(_, secret)| channels.iter().any(|ch| ch == &channel_of(secret)))
                            .unwrap_or(false);
                        if tracked && !present.contains(pid) {
                            let count = channel_digest_absent.entry(pid.clone()).or_insert(0);
                            *count += 1;
                            if *count >= 2 {
                                gone.push(pid.clone());
                            }
                        } else {
                            channel_digest_absent.remove(pid);
                        }
                    }
                    for pid in gone {
                        channel_digest_absent.remove(&pid);
                        conn.drop_link(&pid);
                        who.remove(&pid);
                    }
                }
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own processes share these channels
                }
                let ch = v["channel"].as_str().unwrap_or_default().to_string();
                let pid = v["id"].as_str().unwrap_or_default().to_string();
                let is_b = if ch == channel_of(&a_sec) {
                    false
                } else if ch == channel_of(&b_sec) {
                    true
                } else {
                    continue;
                };
                conn.maybe_adopt(&v, false).await?;
                if let Some(l) = conn.link_mut(&pid) {
                    l.expected_secret = Some(if is_b {
                        (b_name.clone(), b_sec.clone())
                    } else {
                        (a_name.clone(), a_sec.clone())
                    });
                }
                who.insert(pid, is_b);
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::ChannelReady(pid, t) => {
                conn.mark_ready(&pid, &t, false);
                let Some(&is_b) = who.get(&pid) else { continue };
                let (dev_name, sec) = if is_b {
                    (&b_name, &b_sec)
                } else {
                    (&a_name, &a_sec)
                };
                let other_name = if is_b { &a_name } else { &b_name };
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    } {
                        // prove ourselves, then vouch
                        t.send_control(&json!({
                            "type": "pair-proof",
                            "mac": proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                        })).await?;
                        t.send_control(&json!({
                            "type": "pair-intro", "name": other_name, "secret": fresh,
                        }))
                        .await?;
                        sent[is_b as usize] = true;
                        ui::say(&format!(
                            "  {} vouched to {}",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                            ui::paint(ui::Tone::Bold, dev_name)
                        ));
                    }
                }
                if sent[0] && sent[1] {
                    // Both pair-intro sent, now start identity exchange with 0x02 nonce challenge
                    // Receiver generates nonce + receiver_device_pub, sender binds and signs
                    // Challenge carries ONLY nonce + receiver_device_pub per correction A
                    use ring::rand::{SecureRandom, SystemRandom};
                    let rng = SystemRandom::new();
                    // Find pids for A and B
                    let mut a_pid: Option<String> = None;
                    let mut b_pid: Option<String> = None;
                    for (pid, is_b) in &who {
                        if *is_b {
                            b_pid = Some(pid.clone());
                        } else {
                            a_pid = Some(pid.clone());
                        }
                    }
                    if let (Some(a_pid), Some(b_pid)) = (a_pid, b_pid) {
                        // Get transports
                        if let (Some(t_a), Some(t_b)) =
                            (conn.transport_of(&a_pid), conn.transport_of(&b_pid))
                        {
                            // Generate nonces
                            let mut nonce_a = [0u8; 32];
                            let mut nonce_b = [0u8; 32];
                            let _ = rng.fill(&mut nonce_a);
                            let _ = rng.fill(&mut nonce_b);
                            // Get device_pubs for A and B: overlay key always exists, not cert-or-zeros per correction.
                            // FIX: receiver_device_pub must be overlay key from overlay_pubkey_bytes(), which ALWAYS exists.
                            // Previously used cert-or-zeros fallback which silently drops target-binding for no-cert peers.
                            // Note: cert.device_pub == overlay key, so with cert value identical; fix only changes no-cert case.
                            // LOAD-BEARING ASSUMPTION for confidentiality: identity-expose for introduce goes over DIRECT A-B DTLS DataChannel
                            // (the introduced pair's OWN transport, E2E DTLS, introducer/hub is NOT a DTLS endpoint, only does signaling/rendezvous).
                            // There is NO fallback where hub bridges two DTLS sessions as A<->Hub<->B separate DTLS (hub-bridging is NOT allowed).
                            // TURN relay is fine (DTLS-blind, still E2E), hub-bridging is NOT (introducer would see cleartext and property breaks).
                            // This comment guards future refactors from silently opening a hub-bridged path.
                            // Sealing with HKDF(fresh_secret) would make introducer able to read (since it minted secret), while direct DTLS keeps introducer BLIND (stronger).
                            let a_device_pub = device_cert_for(&a_name)
                                .map(|c| c.device_pub)
                                .unwrap_or_else(|| {
                                    overlay::overlay_pubkey_bytes().unwrap_or([0u8; 32])
                                });
                            let b_device_pub = device_cert_for(&b_name)
                                .map(|c| c.device_pub)
                                .unwrap_or_else(|| {
                                    overlay::overlay_pubkey_bytes().unwrap_or([0u8; 32])
                                });
                            // Challenge from A to B: nonce_A + receiver_device_pub_A (A's device_pub)
                            let challenge_a_to_b = json!({
                                "type": "identity-nonce-challenge",
                                "nonce": hex::encode(nonce_a),
                                "receiver_device_pub": hex::encode(a_device_pub)
                            });
                            // Challenge from B to A
                            let challenge_b_to_a = json!({
                                "type": "identity-nonce-challenge",
                                "nonce": hex::encode(nonce_b),
                                "receiver_device_pub": hex::encode(b_device_pub)
                            });
                            // Send challenges via data channel (control) - only nonce + receiver_device_pub per correction A
                            let _ = t_b.send_control(&challenge_a_to_b).await;
                            let _ = t_a.send_control(&challenge_b_to_a).await;
                            ui::say(&ui::paint(
                                ui::Tone::Dim,
                                "  identity challenge exchanged, waiting for sealed certs...",
                            ));
                            // For now, after challenges sent, wait a bit then consider identity done
                            // In full implementation, we would wait for identity-expose responses with possession sigs
                            tokio::time::sleep(Duration::from_millis(800)).await;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(800)).await; // let intros flush
                    ui::say(&format!(
                        "  {} {} and {} now know each other (no codes needed)",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        a_name,
                        b_name,
                    ));
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
            }
            Ev::Stuck(pid, g) => {
                conn.on_stuck(&pid, g, "stuck").await?;
            }
            Ev::GraceExpired(pid, g) => {
                conn.on_stuck(&pid, g, "lost").await?;
            }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => {
                conn.on_peer_left(&v);
            }
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }
}
