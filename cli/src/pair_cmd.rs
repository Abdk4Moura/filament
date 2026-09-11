//! The pairing command (`filament pair`), lifted out of `main.rs`.
//!
//! Drives the L1-a PAKE ceremony at the terminal: mint a spoken code or claim
//! one, show the join screen, and hand the agreed secret to the device store.
//! Three pair-specific helpers live here because this module is their only
//! caller: `malformed_entry_banner`, `persist_mesh_grant` and
//! `invitation_not_a_code_msg` (the latter also drives a unit test, which
//! imports it back under `#[cfg(test)]`).
//!
//! `looks_like_pake_code` deliberately did NOT come with it: it has eleven call
//! sites outside pairing, so it stays in the crate root and is imported.
//! Two `tokio::spawn`s and one `test_hooks` call travel with `pair_cmd`; there
//! are no cfg branches here.
use crate::conn::{AdoptSource, Conn, Presence};
use crate::net::{self, Ev};
use crate::pake_ceremony::{Ceremony, Inbound as PakeInbound, pair_v2_caps};
use crate::{
    cancelled, capability_list_summary, codeentry, devices_path, devices_store_v2,
    devices_upsert_atomic, direct, display_name, fleet, fleet_ui, fresh_secret, identity,
    interactive_allowed, load_owner_key, local_device_cert, local_device_cert_path,
    looks_like_pake_code, merge_owner_cap_ops, mesh_enrolment, mk_uid, regex_lite_code, session,
    shutdown, store_provisional_identity, test_hooks, ui,
};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::io::IsTerminal;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Store an owner-signed enrolment received over the pairing ceremony.
///
/// VERIFIES BEFORE IT STORES. The grant arrives sealed under the PAKE key, so
/// only the party we completed the ceremony with could have sent it, but that
/// says who sent it and nothing about whether it is well-formed. A certificate
/// that does not name OUR device key, or does not verify, is refused rather than
/// written: the whole value of the certificate is that it names one key.
fn persist_mesh_grant(grant: &Value) -> Result<()> {
    if local_device_cert_path().exists() {
        bail!("this device already holds a certificate; refusing to overwrite it");
    }
    let our_pub = crate::overlay::overlay_pubkey_bytes()
        .map_err(|e| anyhow!("cannot read this device's key: {e}"))?;
    let cert = identity::DeviceCert::from_json(&grant["device_cert"])
        .ok_or_else(|| anyhow!("the enrolment carried no certificate"))?;
    if cert.device_pub != our_pub {
        bail!("the certificate names a different device; refusing it");
    }
    cert.verify(identity::now_secs())
        .map_err(|e| anyhow!("the certificate does not verify: {e}"))?;
    let owner_name = grant["owner_name"].as_str().unwrap_or("owner");
    crate::platform::SecretFile::write_str(
        &local_device_cert_path(),
        &serde_json::to_string_pretty(&json!({ "name": owner_name, "cert": cert.to_json() }))?,
    )?;
    // The meeting point, and the owner-signed policy that makes it useful. Each
    // op is verified against the owner key in the header, so this is a relay of
    // the owner's decisions rather than trust in whoever transmitted them.
    if let Some(rv) = grant["fleet_rv"].as_str() {
        if let Err(e) = fleet::store_rv(rv) {
            ui::debug(&format!("fleet rendezvous secret not stored: {e}"));
        }
    }
    if let Some(hdr) = grant["cap_header"].as_object() {
        let dir = crate::settings::config_dir();
        let mut store = crate::capability::load_cap_store(&dir);
        let already = store.iter().any(|e| {
            e.get("type").and_then(|x| x.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some("self")
        });
        if !already {
            store.push(Value::Object(hdr.clone()));
            let _ = crate::capability::save_cap_store(&dir, &store);
        }
    }
    if let Some(ops) = grant.get("cap_ops").and_then(|v| v.as_array()) {
        let added = merge_owner_cap_ops(ops);
        ui::debug(&format!("mesh grant: merged {added} owner-signed ops"));
    }
    Ok(())
}

/// The one-line dim banner shown right before we open the guided entry on a
/// MALFORMED arg, so the user knows WHY the prompt appeared and how to make it
/// fail fast in scripts.
fn malformed_entry_banner(arg: &str) {
    ui::say(&ui::paint(
        ui::Tone::Dim,
        &format!(
            "couldn't parse '{arg}', opening guided entry · set FILAMENT_NONINTERACTIVE=1 to fail fast in scripts"
        ),
    ));
}

pub(crate) fn invitation_not_a_code_msg() -> String {
    "that is an invitation, not a pairing code.\n  \
     Run `filament join` and paste it at the prompt; it is cleared from the terminal after reading.\n  \
     If you saved it to a file: `filament join --invite-file <path>`.\n  \
     Invitation material is deliberately never read from the command line, where it would land in `ps` output and shell history."
        .to_string()
}

/// `internal` means: issue the peer an owner-signed certificate and admit it to
/// this mesh. `posture` is the ceiling to grant it, empty meaning the
/// same-person default. Both are decided by the operator at the moment of
/// adding, because that is when they know what the machine is for.
pub(crate) async fn pair_cmd(
    server: &str,
    mut code: Option<String>,
    name: Option<String>,
    mut word: Option<String>,
    relay: bool,
    internal: bool,
    posture: Vec<String>,
) -> Result<()> {
    if code.is_none() && word.is_none() && !interactive_allowed() {
        let (message, exit_code) = fleet_ui::pair_ui::err_pair_interactive();
        eprintln!("{message}");
        std::process::exit(exit_code);
    }
    // INTERACTIVE GATE (scripts safe by default, see `interactive_allowed`).
    //   * `pair` with no code AND no --word -> guided CREATE entry. Empty submit
    //     falls back to today's auto-mint; typed words become the chosen password.
    //   * `pair <malformed>` (a positional that isn't a valid claim shape) ->
    //     banner, then guided CLAIM entry PRE-FILLED with the normalized input.
    // When the gate is closed we keep EXACTLY today's behavior below.
    //
    // If the guided CREATE entry runs, it mints the nameplate ONCE here and shows
    // it in the preview; we carry it forward so the code we actually create uses
    // the SAME number the user saw (no shown-one-number, got-another mismatch).
    let mut preview_nameplate: Option<String> = None;
    if word.is_none() && interactive_allowed() {
        let malformed = code.as_deref().filter(|c| {
            // A "valid claim shape" is words + a trailing dash-group; anything that
            // split_code can't peel into (nameplate, non-empty words) is malformed.
            let normalized = crate::pake::norm_code(c);
            let (np, pw) = crate::pake::split_code(&normalized);
            pw.is_empty() || np.is_empty()
        });
        match (&code, malformed) {
            // No code at all -> CREATE entry.
            (None, _) => {
                let auto_np = crate::pake::words::mint_pair_nameplate();
                match codeentry::run(
                    "  add / choose words  ",
                    codeentry::Mode::Create,
                    "",
                    &auto_np,
                )? {
                    codeentry::Outcome::Submitted(words) => {
                        word = Some(words);
                        // Reuse the SAME nameplate we just previewed, so the code
                        // we mint matches the number the user saw.
                        preview_nameplate = Some(auto_np);
                    }
                    // Empty submit -> fall through to auto-mint, but still keep the
                    // previewed nameplate so an empty (auto-words) create reuses it.
                    codeentry::Outcome::Empty => preview_nameplate = Some(auto_np),
                    codeentry::Outcome::Cancelled => return Err(cancelled()),
                }
            }
            // Malformed positional -> banner + prefilled CLAIM entry.
            (Some(raw), Some(_)) => {
                malformed_entry_banner(raw);
                let prefill = crate::pake::norm_code(raw);
                match codeentry::run("  add / code  ", codeentry::Mode::Claim, &prefill, "")? {
                    codeentry::Outcome::Submitted(c) => code = Some(c),
                    // Empty submit on a claim-fix means "give up on this code".
                    codeentry::Outcome::Empty => return Err(cancelled()),
                    codeentry::Outcome::Cancelled => return Err(cancelled()),
                }
            }
            // A well-formed positional -> no prompt, proceed as today.
            (Some(_), None) => {}
        }
    }
    // STEERING: --word lets the creator choose the SPAKE2 password. The positional
    // `code` arg still means "claim", so --word + a code is contradictory.
    if word.is_some() && code.is_some() {
        bail!(
            "--word chooses your OWN pairing words (creator); it can't be combined with a code to claim. Drop one."
        );
    }
    // A custom phrase must clear the password gate (Decision #3) BEFORE we touch
    // the network. Normalize with the SHARED norm_code so the echoed/created code
    // is exactly what SPAKE2 will hash, then validate against the blocklist.
    let custom_words: Option<String> = match &word {
        Some(w) => {
            let (words, _np) = crate::pake::split_chosen_code(&crate::pake::norm_code(w));
            if let Err(why) = crate::pake::words::validate_chosen_password(&words, &display_name())
            {
                bail!("'{w}' is too weak: {why}");
            }
            Some(words)
        }
        None => None,
    };
    let my_uid = mk_uid("p");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    // Meta must exist for pairing; an unguessable solo room keeps strangers
    // out (the daemon's trick), the pair-claim moves people, not the room.
    let solo = format!("pairc-{}", fresh_secret());
    // C30: the session repairs the solo-room membership/lease if the join dies.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(solo.clone());
    sess.emit(
        &sio,
        "join",
        json!({ "room": solo, "name": display_name(), "uid": my_uid }),
    )
    .await;
    // A code that looks like a one-time TRANSFER code (word-word-NNN, 2-3 digit
    // trailing) typed into `pair`, which runs the PAKE pairing ceremony,
    // redirect clearly before the handshake stalls against a peer that isn't
    // pairing. ADVISORY only (by trailing-number width); PAKE still authenticates.
    if let Some(c) = &code {
        if regex_lite_code(c) && !looks_like_pake_code(c) {
            bail!(
                "'{c}' looks like a one-time TRANSFER code (from `filament send --code`), not a pairing code.\n  \
                 To receive that transfer: run `filament receive {c}`\n  \
                 An add code ends in a 4-digit number, e.g. `brave-otter-3141`."
            );
        }
    }
    let creator = code.is_none();
    // L1-a: the spoken code is split CLIENT-SIDE into (nameplate, password). The
    // password (words) NEVER leaves this process; only the nameplate is sent.
    let mut my_words; // the password (creator mints; claimer types)
    let mut my_nameplate;
    match &code {
        Some(c) => {
            // An INVITATION is not a pairing code, and pasting one here is the
            // obvious mistake: `add --for` prints the token on screen beside a
            // QR, so the natural next move is to paste it into the verb that
            // just produced it. Without this the token is sent as a nameplate,
            // the server rejects it, and the user is told "codes burn after one
            // use" about a token that was never claimed, with a remedy
            // (`re-run filament add`) that mints a code and cannot help.
            if c.starts_with("filament-invite:") {
                bail!("{}", invitation_not_a_code_msg());
            }
            // Claimer: normalize the typed code, split, send ONLY the nameplate.
            let normalized = crate::pake::norm_code(c);
            let (np, pw) = crate::pake::split_code(&normalized);
            if pw.is_empty() || np.is_empty() {
                bail!(
                    "that code doesn't look right, expected something like brave-otter-ruby-3141"
                );
            }
            my_words = pw;
            my_nameplate = np.clone();
            ui::say(&format!("  claiming {}...", ui::paint(ui::Tone::Brand, c)));
            sio.emit("pair-claim", json!({ "nameplate": np, "v": 2 }))
                .await
                .ok();
        }
        None => {
            // Creator: use the user's chosen words (--word) or mint them; the
            // nameplate is ALWAYS machine-minted. Ask the server to allocate ONLY
            // the nameplate. The full code is displayed from our own words when
            // pair-ok arrives (the server never echoes any words).
            my_words = custom_words
                .clone()
                .unwrap_or_else(crate::pake::words::mint_words);
            // Reuse the nameplate the guided entry already previewed (if any), so
            // the created code matches what the user saw; otherwise mint fresh.
            my_nameplate = preview_nameplate
                .clone()
                .unwrap_or_else(crate::pake::words::mint_pair_nameplate);
            // STEERING: echo the normalized code we're about to create so the
            // creator sees EXACTLY what their peer must type (== what SPAKE2 hashes).
            if custom_words.is_some() {
                ui::say(&format!(
                    "  using your words: {}",
                    ui::paint(ui::Tone::Brand, &format!("{my_words}-{my_nameplate}"))
                ));
            }
            sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 }))
                .await
                .ok();
        }
    }

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid.clone(),
        relay,                    // relay_only
        None,                     // to_filter
        false,                    // warm_standby default (pair is one-shot)
        direct::direct_enabled(), // direct_ok: env gate only (no L2 acceptor here)
    );
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Bounded force-exit guarantee: the Interrupted bail unwinds and drops
            // the peers, and a webrtc/quinn drop can itself deadlock. Arm a
            // watchdog so Ctrl-C always exits promptly regardless.
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let mut petname = name; // resolved --name, prompt answer, or peer's display name
    let mut prompted = false;
    let mut peer: Option<(String, String)> = None; // (pid, display name)

    // ---- L1-a PAKE state (shared ceremony) ----------------------------------
    // The agreed pinned secret (HKDF(K)); set ONLY after key confirmation passes.
    // `pair` PERSISTS it (a known device); the transfer path runs the SAME
    // ceremony but DISCARDS it. The ceremony state machine lives in
    // `pake_ceremony::Ceremony` and is driven identically by both flows.
    let mut agreed_secret: Option<String> = None;
    // Peer identity cert received via identity-expose inside the authed PAKE channel.
    // The flow exposes EXACTLY ONE device + its cert; privacy test asserts on actual wire payload.
    let mut peer_identity_cert: Option<identity::DeviceCert> = None;
    // A certless device offers its device key once, so an owner running
    // `add --internal` has something to certify.
    let mut sent_enrol_offer = false;
    // The certificate this side ISSUED to a certless peer, held until the
    // ceremony completes so it can be stored together with the pair secret.
    let mut issued_cert: Option<(identity::DeviceCert, Vec<String>)> = None;
    // Set once the owner's answer has been handled. A device that OFFERED its key
    // must not finish the ceremony before the answer lands: the owner sends the
    // grant only after seeing the offer, so completing on the pairing result alone
    // exits first and the certificate is never stored. That is exactly what left
    // `add --internal` reporting success on the owner side while the device stayed
    // EXTERNAL.
    let mut enrol_settled = false;
    let mut enrol_deadline: Option<Instant> = None;
    let mut sent_identity: bool = false;
    let mut identity_exchange_window: Option<std::time::Instant> = None;
    // Peer signaling sid we run the PAKE with (set when the link is adopted).
    let mut pake_peer: Option<String> = None;
    let caps = pair_v2_caps();
    // Start our SPAKE2 ceremony immediately: identity = nameplate, password =
    // words. Both sides MUST pass identical password AND nameplate (spec §3.1).
    // Fixed convention for plain pair: Device-scoped (device-to-device). Scope byte is derived from the authenticated introduction token, not a local guess. Both sides must pass same scope or confirmation fails.
    let scope = crate::identity::IntroScope::Device.to_byte();
    let mut cer = Ceremony::new(&my_words, &my_nameplate, caps.clone(), scope);
    let deadline = Instant::now() + Duration::from_secs(600); // code TTL
    // The pairing peer left before the ceremony finished. Give a short grace
    // for a transient reconnect, then FAIL FAST, don't orphan in the room
    // for the full 10-min TTL (the D3/D5 divergence the monitor kept
    // catching: creator's connect failed, it quit, claimer sat silent).
    // Once the code is CLAIMED, the ceremony must finish in seconds. Bound it:
    // if it hasn't completed within this budget, the peer disconnected or could
    // never connect, fail fast instead of orphaning in the room for the full
    // 600s TTL (the D3/D5 divergence the monitor kept catching). 60s is generous
    // (covers a slow cross-NAT WebRTC with its 3×15s establishment retries);
    // FILAMENT_PAIR_GRACE_SECS shortens it for gate 17b.
    let ceremony_budget = Duration::from_secs(
        std::env::var("FILAMENT_PAIR_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
    );
    let mut ceremony_deadline: Option<Instant> = None;
    // Gate 17b hook: connect but never complete, so the ceremony budget fires
    // deterministically (same-machine pairs otherwise finish in ~1s).
    let stall = test_hooks::pair_stall();

    loop {
        // Done when the petname is settled AND the PAKE agreed a secret (key
        // confirmation passed). The secret is HKDF(K), never transmitted, the
        // same on both sides; it drops straight into devices.json.
        if let Some(n) = petname.clone() {
            if let Some(sec) = agreed_secret.clone() {
                if identity_exchange_window.map_or(false, |dl| std::time::Instant::now() < dl)
                    && peer_identity_cert.is_none()
                {
                    // A device that holds NO certificate yet still has a device
                    // key, and that key is the thing an owner must certify. The
                    // exchange below is gated on having a cert to present, so a
                    // fresh machine said nothing at all and the owner had nothing
                    // to sign. That is why `add` could never enrol anybody.
                    //
                    // Expose the key alone, sealed under the PAKE key and proven
                    // by possession. It confers nothing by itself: the owner still
                    // has to decide to certify it, and only does so when the
                    // operator asked for --internal.
                    if !sent_enrol_offer && local_device_cert().is_none() {
                        if let (Some(ref pid2), Some(k)) = (pake_peer.clone(), cer.k()) {
                            if let Ok(dpub) = crate::overlay::overlay_pubkey_bytes() {
                                let mut cmv_arr = [0u8; 32];
                                if let Some(l) = conn.link(&pid2) {
                                    if let Some((my_fp, their_fp)) = match &l.peer {
                                        Some(p) => p.fingerprints().await,
                                        None => None,
                                    } {
                                        let cmv = crate::pake::our_confirm(
                                            k,
                                            &my_fp,
                                            &their_fp,
                                            cer.caps_canon(),
                                            cer.scope(),
                                        );
                                        cmv_arr.copy_from_slice(&cmv);
                                        let caps_d = crate::identity::caps_digest(cer.caps_canon());
                                        let pmsg = crate::identity::possession_msg(
                                            0x01,
                                            &cmv_arr,
                                            cer.scope(),
                                            &caps_d,
                                            &[0u8; 32],
                                            &dpub,
                                            &[0u8; 32],
                                        );
                                        if let Ok(psig) =
                                            crate::overlay::overlay_sign_possession(&pmsg)
                                        {
                                            let inner = serde_json::json!({
                                                "device_pub": hex::encode(dpub),
                                                "possession_sig": hex::encode(psig),
                                                "name": display_name(),
                                            });
                                            let sk = crate::identity::sealing_key_from_k(k);
                                            if let Ok((n, sealed)) = crate::identity::seal_plaintext(
                                                &sk,
                                                inner.to_string().as_bytes(),
                                            ) {
                                                sio.emit("signal", serde_json::json!({
                                                    "to": pid2,
                                                    "data": {"type": "enrol-offer", "v": 1,
                                                             "nonce": hex::encode(n), "sealed": hex::encode(sealed)}
                                                })).await.ok();
                                                sent_enrol_offer = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !sent_identity {
                        if let Some(local_cert) = local_device_cert() {
                            if let Some(ref pid2) = pake_peer {
                                if let Some(k) = cer.k() {
                                    if let Some(l) = conn.link(pid2) {
                                        if let Some((my_fp, their_fp)) = match &l.peer {
                                            Some(p) => p.fingerprints().await,
                                            None => None,
                                        } {
                                            let cmv = crate::pake::our_confirm(
                                                k,
                                                &my_fp,
                                                &their_fp,
                                                cer.caps_canon(),
                                                cer.scope(),
                                            );
                                            let mut cmv_arr = [0u8; 32];
                                            cmv_arr.copy_from_slice(&cmv);
                                            let dpub = local_cert.device_pub;
                                            let scope_b = cer.scope();
                                            let caps_d =
                                                crate::identity::caps_digest(cer.caps_canon());
                                            let ch = crate::identity::cert_hash(&local_cert);
                                            let rz = [0u8; 32];
                                            let pmsg = crate::identity::possession_msg(
                                                0x01, &cmv_arr, scope_b, &caps_d, &ch, &dpub, &rz,
                                            );
                                            if let Ok(psig) =
                                                crate::overlay::overlay_sign_possession(&pmsg)
                                            {
                                                let inner = serde_json::json!({"cert":local_cert.to_json(),"possession_sig":hex::encode(psig),"device_pub":hex::encode(dpub)});
                                                let sk = crate::identity::sealing_key_from_k(k);
                                                if let Ok((n, s)) = crate::identity::seal_plaintext(
                                                    &sk,
                                                    inner.to_string().as_bytes(),
                                                ) {
                                                    sio.emit("signal", serde_json::json!({"to":pid2,"data":{"type":"identity-expose","v":2,"nonce":hex::encode(n),"sealed":hex::encode(s)}})).await.ok();
                                                    sent_identity = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // We offered our device key and the owner has not answered yet.
                    // Wait, bounded: if no grant arrives we finish as an ordinary
                    // pair, which is the pre-existing behaviour, so waiting can only
                    // add an outcome and never remove one.
                    // NOT `continue`: that jumps to the top of the loop and skips the
                    // event processing further down, so the ceremony would spin here
                    // for the whole window without ever READING the grant it is
                    // waiting for. Measured exactly that way: the owner logged the
                    // grant, the claimer logged "no grant arrived", and no signal was
                    // processed in between. Fall through to the event loop instead and
                    // re-enter this block on the next pass.
                    let awaiting_enrolment = sent_enrol_offer && !enrol_settled && {
                        let dl = *enrol_deadline
                            .get_or_insert_with(|| Instant::now() + Duration::from_secs(15));
                        if Instant::now() >= dl {
                            ui::debug("enrol: no grant arrived; completing as an ordinary pair");
                            false
                        } else {
                            true
                        }
                    };
                    if !awaiting_enrolment {
                        let same_person = peer_identity_cert
                            .as_ref()
                            .and_then(|cert| {
                                load_owner_key()
                                    .map(|owner| owner.public_key_bytes() == cert.user_pub)
                            })
                            .unwrap_or(false);
                        // External pairs currently receive only the baseline transfer
                        // capability. Do not render render_someone_else_banner or
                        // render_inter_user_form: pair has no bounded per-cap grant
                        // contract, so those surfaces would claim choices it ignores.
                        // Do not render render_pake_words: the pair code is not a
                        // transcript-derived SAS; showing it as trust would invert the
                        // MITM check. A real SAS belongs in the crypto gate.
                        // Fail-closed: check BEFORE any write if peer previously had identity and now does NOT expose
                        if same_person {
                            ui::say(&fleet_ui::pair_ui::render_same_person_banner(&n));
                        }
                        if peer_identity_cert.is_none() {
                            let p = devices_path();
                            if let Ok(raw) = std::fs::read_to_string(&p) {
                                if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                                    if let Err(e) = identity::check_fail_closed(&arr, &n, None) {
                                        bail!("fail-closed: {}", e);
                                    }
                                }
                            }
                            // No cert: store secret only (legacy or first-pair no identity)
                            devices_store_v2(&n, &sec, &caps)?;
                            // ...unless WE certified them during this ceremony. Then the
                            // secret and the certificate belong in one record: the owner
                            // dials on the secret and judges on the certificate, and a
                            // row holding only one of them is either unreachable or
                            // "uncertified, trusted in full".
                            if let Some((cert, caps)) = issued_cert.as_ref() {
                                if let Err(e) = devices_upsert_atomic(
                                    &n,
                                    Some(&sec),
                                    Some(cert),
                                    Some(caps),
                                    Some(identity::IntroScope::Device.to_byte()),
                                    None,
                                    None,
                                ) {
                                    ui::debug(&format!(
                                        "enrol: could not record the certificate: {e}"
                                    ));
                                }
                            }
                        } else {
                            // #23: atomic (secret,cert) together in ONE write, not separate writes.
                            // devices_store_v2 writes secret, store_provisional writes cert to temp file.
                            // If process crashes between them, cap_authorize sees new-secret + old-cert (or no cert)
                            // yielding wrong userPub. Fix: devices_upsert_atomic writes both fields together.
                            let pcert = peer_identity_cert.as_ref().unwrap();
                            devices_upsert_atomic(
                                &n,
                                Some(&sec),
                                Some(pcert),
                                Some(&caps),
                                Some(scope),
                                None,
                                None,
                            )
                            .context("atomic store secret+cert")?;
                            // Also store provisional for overlay check: on overlay failure, REMOVE the durable anchor
                            store_provisional_identity(&n, pcert).context("store provisional")?;
                        }
                        if same_person {
                            ui::say(&fleet_ui::pair_ui::render_same_person_success(&n));
                        } else {
                            ui::say(&format!(
                                "  {} {} mutually remembered, verified end-to-end (no key ever crossed the server)",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                            ui::say(&ui::paint(
                                ui::Tone::Dim,
                                &format!("  try: filament send <file> --to {n}   ·   filament up"),
                            ));
                        }
                        tokio::time::sleep(Duration::from_millis(300)).await; // let acks flush
                        let _ = sio.disconnect().await;
                        return Ok(());
                    } // close: not awaiting an enrolment answer
                } // close identity_exchange_window else
            }
        }
        if Instant::now() > deadline {
            bail!("timed out, the code was never used (codes expire after 10 minutes)");
        }
        // Fail fast: the code was claimed but the ceremony didn't finish in
        // time, the peer disconnected or never connected.
        if let Some(dl) = ceremony_deadline {
            if Instant::now() > dl {
                bail!(
                    "the other device disconnected before setup finished; make sure both run `filament add` at the same time, then try again"
                );
            }
        }
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead

        // ---- L1-a PAKE progression (runs every iteration) ------------------
        // 1) Once we know the peer's signaling sid, send our SPAKE2 element over
        //    the opaque `signal` relay (the server cannot read it).
        if let Some(pid) = pake_peer.clone() {
            // gate 17b (FILAMENT_TEST_PAIR_STALL): never send our SPAKE2 element,
            // so the exchange can't complete on either side and the ceremony's
            // fail-fast `ceremony_deadline` fires, proving the no-10-min-orphan
            // guard. Test-only: `stall` is set solely by that env var.
            if !stall {
                if let Some(data) = cer.take_msg_payload() {
                    sio.emit("signal", json!({ "to": pid, "data": data }))
                        .await
                        .ok();
                }
            }
            // 2) Once K is derived AND both DTLS fingerprints are known, send the
            //    key-confirmation MAC over K + sorted fingerprints + caps. The MAC
            //    is gated on the fingerprints so a server that substitutes a DTLS
            //    cert produces a different fingerprint → the peer's verify fails.
            if cer.has_k() {
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    } {
                        if let Some(data) = cer.take_confirm_payload(&my_fp, &their_fp) {
                            sio.emit("signal", json!({ "to": pid, "data": data }))
                                .await
                                .ok();
                        }
                    }
                }
            }
            // Identity expose: after PAKE confirmation and secret agreed, if we have a local
            // device cert, send EXACTLY ONE device + its cert sealed under K-derived key
            // with possession signature, inside the authed channel. Server never sees
            // user key (sealed) and cannot substitute (possession sig binds to session).
            if !sent_identity {
                if agreed_secret.is_some() {
                    if let Some(local_cert) = local_device_cert() {
                        if let Some(pid2) = pake_peer.clone() {
                            if let Some(k) = cer.k() {
                                if let Some(l) = conn.link(&pid2) {
                                    if let Some((my_fp, their_fp)) = match &l.peer {
                                        Some(p) => p.fingerprints().await,
                                        None => None,
                                    } {
                                        // Confirm MAC that we sent (session-bound, already binds K+fps+caps+scope)
                                        let confirm_mac_vec = crate::pake::our_confirm(
                                            k,
                                            &my_fp,
                                            &their_fp,
                                            cer.caps_canon(),
                                            cer.scope(),
                                        );
                                        let mut cmv_arr = [0u8; 32];
                                        cmv_arr.copy_from_slice(&confirm_mac_vec);
                                        let device_pub = local_cert.device_pub;
                                        let scope_byte = cer.scope();
                                        let caps_digest =
                                            crate::identity::caps_digest(cer.caps_canon());
                                        let chash = crate::identity::cert_hash(&local_cert);
                                        let receiver_zero = [0u8; 32];
                                        let possession_msg = crate::identity::possession_msg(
                                            0x01,
                                            &cmv_arr,
                                            scope_byte,
                                            &caps_digest,
                                            &chash,
                                            &device_pub,
                                            &receiver_zero,
                                        );
                                        if let Ok(possession_sig) =
                                            crate::overlay::overlay_sign_possession(&possession_msg)
                                        {
                                            let inner = serde_json::json!({
                                                "cert": local_cert.to_json(),
                                                "possession_sig": hex::encode(possession_sig),
                                                "device_pub": hex::encode(device_pub)
                                            });
                                            let sealing_key =
                                                crate::identity::sealing_key_from_k(k);
                                            if let Ok((nonce, sealed)) =
                                                crate::identity::seal_plaintext(
                                                    &sealing_key,
                                                    inner.to_string().as_bytes(),
                                                )
                                            {
                                                let payload = serde_json::json!({
                                                    "type": "identity-expose",
                                                    "v": 2,
                                                    "nonce": hex::encode(nonce),
                                                    "sealed": hex::encode(sealed)
                                                });
                                                sio.emit("signal", serde_json::json!({"to": pid2, "data": payload})).await.ok();
                                                sent_identity = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let ev = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
                sess.invalidate(); // C30: fresh sid, re-assert next tick
            }
            // C30 phase 2: same reconciliation as the Welcome arm above. Pairing
            // waits on the peer arriving in the room, so a dropped `peer-joined`
            // would otherwise strand the ceremony until the deadline.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                    }
                }
            }
            Ev::PairOk(_v) => {
                // L1-a: the server allocated our nameplate. Display the FULL code
                // from OUR OWN local mint (the server never echoed any words).
                let full = format!("{my_words}-{my_nameplate}");
                ui::clipboard(&full);
                ui::say("");
                ui::say(&format!(
                    "      {}",
                    ui::paint(ui::Tone::Brand, &full.to_uppercase())
                ));
                ui::say("");
                if interactive_allowed() {
                    ui::say(&ui::paint(
                        ui::Tone::Dim,
                        "  scan this in Filament, or enter the code below it",
                    ));
                    ui::say(&ui::qr_or_text(&full, 6));
                }
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  on the other device: type it into the web app, or `filament join <code>`",
                ));
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  keep this window open until the other device claims it",
                ));
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  one claim · expires in 10 min · paired end-to-end (no key crosses the server)",
                ));
            }
            Ev::PairCode(v) => {
                // v1 server (shouldn't happen for a v2 create, but be safe): a
                // legacy server-minted code means the peer can't PAKE-pair.
                let c = v["code"].as_str().unwrap_or("?");
                let _ = c;
                bail!(
                    "this server returned a legacy code. Update the server (or the peer) to pair securely."
                );
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed, connecting..."));
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
            }
            Ev::PairMatched(v) => {
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
                ui::say(&format!(
                    "  {} code accepted, connecting",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok())
                ));
                sess.room = Some(room.clone()); // C30: desire moves with us
                sess.touch();
                sess.emit(
                    &sio,
                    "join",
                    json!({ "room": room, "name": display_name(), "uid": my_uid }),
                )
                .await;
            }
            Ev::PairError(v) => {
                // Creator nameplate collision: re-mint a FRESH nameplate (and
                // fresh words) and retry, never reuse a burned code.
                if creator && v["error"].as_str() == Some("taken") {
                    // Re-mint a FRESH nameplate; KEEP the creator's chosen words
                    // (--word), only mint fresh words when we minted them.
                    if custom_words.is_none() {
                        my_words = crate::pake::words::mint_words();
                    }
                    my_nameplate = crate::pake::words::mint_pair_nameplate();
                    cer.restart(&my_words, &my_nameplate);
                    sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 }))
                        .await
                        .ok();
                    continue;
                }
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => {
                        "that code's creator already left, ask them for a fresh one".to_string()
                    }
                    _ => format!(
                        "{}, codes burn after one use; a failed setup needs a FRESH code (re-run `filament add`)",
                        v["error"].as_str().unwrap_or("?")
                    ),
                };
                bail!("code rejected: {hint}");
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, true).await?;
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // L1-a: PAKE messages ride the opaque `signal` relay. Branch them
                // OUT of the WebRTC signal path (SDP/ICE) into the shared ceremony.
                // A `pake-confirm` verify ⇒ wrong password OR a server that
                // substituted a DTLS cert OR rewrote caps ⇒ ABORT, agree NOTHING.
                if matches!(
                    data["type"].as_str(),
                    Some("pake-msg") | Some("pake-confirm")
                ) {
                    pake_peer.get_or_insert(from.clone());
                    let fps = match conn.link(&from) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                    match cer.on_signal(&data, fp_ref) {
                        PakeInbound::Consumed => {
                            if let Some(sec) = cer.secret() {
                                agreed_secret = Some(sec.clone());
                                identity_exchange_window = Some(
                                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                                );
                            }
                        }
                        PakeInbound::Abort(why) => {
                            bail!(
                                "pairing REFUSED: {why}. Nothing was stored; ask for a FRESH code."
                            );
                        }
                        PakeInbound::Ignored => {}
                    }
                    continue;
                }
                // Identity expose: sealed cert + possession signature, inside authed PAKE channel.
                // Fixes holes A (confidentiality+integrity via K-derived seal, server never sees user_pub)
                // and B (replayable bearer: possession signature over session-bound confirm MAC, bound to device key).
                // A certless peer offered its device key. Certify it ONLY when the
                // operator asked for --internal: completing a pairing code proves a
                // human meant to pair, never that the machine is one of ours, and
                // this is the step that would otherwise turn "typed the code" into
                // "member of the mesh".
                // ALWAYS answer an offer, even to refuse it. Staying silent makes
                // the other side wait out its whole window before completing as an
                // ordinary pair, which put 15s on EVERY pairing where the peer is
                // certless and the operator did not ask to enrol. That is most of
                // them, and it regressed a gate that times the ceremony.
                if data["type"].as_str() == Some("enrol-offer")
                    && (!internal || load_owner_key().is_none())
                {
                    sio.emit(
                        "signal",
                        json!({
                            "to": from,
                            "data": {"type": "enrol-decline", "v": 1}
                        }),
                    )
                    .await
                    .ok();
                }
                if data["type"].as_str() == Some("enrol-offer") && internal {
                    if let (Some(k), Some(owner_key)) = (cer.k(), load_owner_key()) {
                        if let (Some(nh), Some(sh)) = (
                            data.get("nonce").and_then(|v| v.as_str()),
                            data.get("sealed").and_then(|v| v.as_str()),
                        ) {
                            if let (Ok(nb), Ok(sb)) = (hex::decode(nh), hex::decode(sh)) {
                                if nb.len() == 12 {
                                    let mut na = [0u8; 12];
                                    na.copy_from_slice(&nb);
                                    let sk = identity::sealing_key_from_k(k);
                                    if let Ok(pt) = identity::open_sealed(&sk, &na, &sb) {
                                        if let Ok(inner) = serde_json::from_slice::<Value>(&pt) {
                                            let dpub = inner
                                                .get("device_pub")
                                                .and_then(|v| v.as_str())
                                                .and_then(|h| hex::decode(h).ok())
                                                .filter(|b| b.len() == 32)
                                                .map(|b| {
                                                    let mut a = [0u8; 32];
                                                    a.copy_from_slice(&b);
                                                    a
                                                });
                                            if let Some(dpub) = dpub {
                                                // The posture the operator chose. Empty means the
                                                // same-person convenience; anything given is the
                                                // ceiling verbatim, so a device added deliberately
                                                // without shell does not get shell.
                                                let caps: Vec<String> = if posture.is_empty() {
                                                    vec![
                                                        "transfer".to_string(),
                                                        "mount".to_string(),
                                                        "shell".to_string(),
                                                    ]
                                                } else {
                                                    posture.clone()
                                                };
                                                let expires = identity::now_secs()
                                                    .saturating_add(identity::CERT_TTL_SECS);
                                                match mesh_enrolment(
                                                    &owner_key, dpub, &caps, expires, true,
                                                ) {
                                                    Ok((cert, mut grant)) => {
                                                        // Remember what we issued; the RECORD is
                                                        // written at ceremony completion, where the
                                                        // pair secret also exists. Writing it here
                                                        // instead created the row early with a cert
                                                        // and no secret, and the owner then never
                                                        // subscribed to that pair channel, so
                                                        // `send --to` from the joined device found
                                                        // nobody. Measured exactly that way.
                                                        issued_cert =
                                                            Some((cert.clone(), caps.clone()));
                                                        grant["type"] = json!("enrol-grant");
                                                        grant["owner_name"] = json!(display_name());
                                                        if let Ok((gn, gs)) =
                                                            identity::seal_plaintext(
                                                                &sk,
                                                                grant.to_string().as_bytes(),
                                                            )
                                                        {
                                                            sio.emit("signal", json!({
                                                                "to": from,
                                                                "data": {"type": "enrol-grant", "v": 1,
                                                                         "nonce": hex::encode(gn),
                                                                         "sealed": hex::encode(gs)}
                                                            })).await.ok();
                                                            ui::say(&format!(
                                                                "  {} enrolling as one of your devices (ceiling: {})",
                                                                ui::paint(
                                                                    ui::Tone::Ok,
                                                                    ui::glyph_ok()
                                                                ),
                                                                capability_list_summary(&caps)
                                                            ));
                                                        }
                                                    }
                                                    Err(e) => ui::debug(&format!(
                                                        "enrol grant failed: {e}"
                                                    )),
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // The owner certified us. Persist exactly what `join` persists, so a
                // device enrolled by code is indistinguishable from one enrolled by
                // invitation: same certificate, same meeting point, same policy.
                // Refused, or the peer is not enrolling. Settle at once rather
                // than sitting out the window: the answer has arrived, it is just
                // "no", and an ordinary pair is exactly what happens next.
                if data["type"].as_str() == Some("enrol-decline") {
                    enrol_settled = true;
                }
                if data["type"].as_str() == Some("enrol-grant") {
                    if let Some(k) = cer.k() {
                        if let (Some(nh), Some(sh)) = (
                            data.get("nonce").and_then(|v| v.as_str()),
                            data.get("sealed").and_then(|v| v.as_str()),
                        ) {
                            if let (Ok(nb), Ok(sb)) = (hex::decode(nh), hex::decode(sh)) {
                                if nb.len() == 12 {
                                    let mut na = [0u8; 12];
                                    na.copy_from_slice(&nb);
                                    let sk = identity::sealing_key_from_k(k);
                                    if let Ok(pt) = identity::open_sealed(&sk, &na, &sb) {
                                        if let Ok(grant) = serde_json::from_slice::<Value>(&pt) {
                                            enrol_settled = true;
                                            match persist_mesh_grant(&grant) {
                                                Ok(()) => ui::say(&format!(
                                                    "  {} joined {}'s mesh",
                                                    ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                                    ui::paint(
                                                        ui::Tone::Bold,
                                                        grant["owner_name"]
                                                            .as_str()
                                                            .unwrap_or("the owner")
                                                    )
                                                )),
                                                Err(e) => ui::say(&ui::paint(
                                                    ui::Tone::Warn,
                                                    &format!(
                                                        "  paired, but could not join the mesh: {e}"
                                                    ),
                                                )),
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if data["type"].as_str() == Some("identity-expose") {
                    if let Some(k) = cer.k() {
                        if let Some(nonce_hex) = data.get("nonce").and_then(|v| v.as_str()) {
                            if let Some(sealed_hex) = data.get("sealed").and_then(|v| v.as_str()) {
                                if let Ok(nonce_bytes) = hex::decode(nonce_hex) {
                                    if let Ok(sealed_bytes) = hex::decode(sealed_hex) {
                                        if nonce_bytes.len() == 12 {
                                            let mut nonce_arr = [0u8; 12];
                                            nonce_arr.copy_from_slice(&nonce_bytes);
                                            let sealing_key = identity::sealing_key_from_k(k);
                                            if let Ok(plaintext) = identity::open_sealed(
                                                &sealing_key,
                                                &nonce_arr,
                                                &sealed_bytes,
                                            ) {
                                                if let Ok(inner) =
                                                    serde_json::from_slice::<Value>(&plaintext)
                                                {
                                                    if let Some(cert_json) = inner.get("cert") {
                                                        if let Some(cert) =
                                                            identity::DeviceCert::from_json(
                                                                cert_json,
                                                            )
                                                        {
                                                            if cert
                                                                .verify(identity::now_secs())
                                                                .is_ok()
                                                            {
                                                                if let Some(sig_hex) = inner
                                                                    .get("possession_sig")
                                                                    .and_then(|v| v.as_str())
                                                                {
                                                                    if let Ok(sig_bytes) =
                                                                        hex::decode(sig_hex)
                                                                    {
                                                                        if sig_bytes.len() == 64 {
                                                                            let mut sig_arr =
                                                                                [0u8; 64];
                                                                            sig_arr
                                                                                .copy_from_slice(
                                                                                    &sig_bytes,
                                                                                );
                                                                            // Re-derive fps for possession verification (session-bound)
                                                                            let fps2 = match conn.link(&from) {
                                                                                Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                                                                                None => None,
                                                                            };
                                                                            if let Some((
                                                                                my_fp2,
                                                                                their_fp2,
                                                                            )) = fps2
                                                                            {
                                                                                let (lo, hi) = crate::pake::sort_fps(&my_fp2, &their_fp2);
                                                                                let scope =
                                                                                    cer.scope();
                                                                                let (_send, expect_dir) = crate::pake::confirm_dirs(&my_fp2, lo);
                                                                                let expected_confirm_vec = crate::pake::confirm_mac(k, expect_dir, lo, hi, cer.caps_canon(), scope);
                                                                                let mut cmv_arr =
                                                                                    [0u8; 32];
                                                                                cmv_arr.copy_from_slice(&expected_confirm_vec);
                                                                                // Reconstruct cert_hash locally from parsed cert fields (never hash sender-framed blob)
                                                                                let chash = identity::cert_hash(&cert);
                                                                                let caps_digest = identity::caps_digest(cer.caps_canon());
                                                                                let sender_pub =
                                                                                    cert.device_pub;
                                                                                let receiver_zero =
                                                                                    [0u8; 32];
                                                                                // For PAKE path, receiver_device_pub MUST be zeros (verifier rejects non-zero)
                                                                                let possession_msg = identity::possession_msg(
                                                                                    0x01, &cmv_arr, scope, &caps_digest, &chash, &sender_pub, &receiver_zero
                                                                                );
                                                                                if identity::verify_possession_sig(&cert.device_pub, &possession_msg, &sig_arr).is_ok() {
                                                                                    // Anti-reflection, narrowed to device_pub (#41). LOAD-BEARING on this
                                                                                    // 0x01 (PAKE) path: receiver_device_pub is ZEROED in the possession_msg
                                                                                    // above (receiver_zero), so message binding does NOT carry the receiver
                                                                                    // identity — THIS single comparison is the ONLY thing preventing a
                                                                                    // reflection here. Do NOT remove it as "redundant with message binding";
                                                                                    // on 0x01 it is not. Compare cert.device_pub against THIS machine's LOCAL
                                                                                    // device pubkey (overlay), never the peer payload; fail closed if the
                                                                                    // local key can't be obtained. A same-owner fleet device has a DIFFERENT
                                                                                    // device_pub under the same user key, so it is correctly admitted (the old
                                                                                    // user_pub check refused it — the OwnerDevice-fleet bug).
                                                                                    match crate::overlay::overlay_pubkey_bytes() {
                                                                                        Ok(own_dpub) if cert.device_pub == own_dpub => {
                                                                                            // reflection-to-self refused
                                                                                        }
                                                                                        Ok(_) => {
                                                                                            peer_identity_cert = Some(cert);
                                                                                        }
                                                                                        Err(_) => {
                                                                                            // cannot obtain own device_pub -> cannot rule out reflection -> refuse
        }
    }

}
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::ChannelReady(pid, t) => {
                let display = match conn.link_mut(&pid) {
                    Some(l) => {
                        l.transport = Some(t.clone());
                        l.presence = Presence::Ready;
                        l.name.clone()
                    }
                    None => continue,
                };
                ui::say(&format!(
                    "  {} {}",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                    ui::paint(ui::Tone::Bold, &display)
                ));
                peer = Some((pid.clone(), display.clone()));
                let _ = &t; // transport not used on the v2 path (no secret over DC)
                if stall {
                    continue; // gate 17b: connected, but deliberately never complete
                }
                // L1-a: the link is up and SDP fingerprints exist. Mark this peer
                // as our PAKE counterpart; the progression block (top of the loop)
                // sends our SPAKE2 element and, once K + fingerprints are known,
                // the key-confirmation MAC. NO secret is sent over the DataChannel.
                pake_peer.get_or_insert(pid.clone());
                // Settle the petname: --name wins; otherwise ask (tty) or
                // default to their display name (scripts, pipes).
                if petname.is_none() && !prompted {
                    prompted = true;
                    if std::io::stdin().is_terminal() {
                        eprint!("  remember this device as [{display}]: ");
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            use tokio::io::AsyncBufReadExt;
                            let mut line = String::new();
                            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
                            if reader.read_line(&mut line).await.is_ok() {
                                let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                            }
                        });
                    } else {
                        petname = Some(display.clone());
                    }
                }
            }
            Ev::StdinLine(line) => {
                if petname.is_none() && prompted {
                    let n = if line.is_empty() {
                        peer.as_ref()
                            .map(|(_, d)| d.clone())
                            .unwrap_or_else(|| "device".into())
                    } else {
                        line
                    };
                    petname = Some(n);
                }
            }
            Ev::Control(pid, v) if stall => {
                let _ = (pid, v); // gate 17b: connected, but ignore all ceremony control
            }
            Ev::Control(_pid, v) => match v["type"].as_str() {
                // L1-a downgrade-refusal (spec §6.1): a v2 client NEVER stores a
                // secret handed over the DataChannel. Receiving a `pair-keep` means
                // the PEER is a legacy v1 client. We refuse, pairing securely
                // requires v2 on both ends. A malicious server stripping `v:2`
                // cannot exploit this: there is no path here that stores a
                // server-readable secret.
                Some("pair-keep") => {
                    bail!(
                        "the other device uses an older version and can't pair securely. Update it (or this CLI) so first-pairing runs the encrypted handshake. Nothing was stored."
                    );
                }
                _ => {}
            },
            Ev::Stuck(pid, g) => {
                conn.on_stuck(&pid, g, "stuck").await?;
            }
            Ev::GraceExpired(pid, g) => {
                conn.on_stuck(&pid, g, "lost").await?;
            }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => {
                // A faster, friendlier signal than the ceremony budget when it
                // arrives: the pairing peer left the room. (The budget is the
                // hard backstop, server peer-left can lag behind a hard kill.)
                let gone = v["id"]
                    .as_str()
                    .and_then(|p| conn.link(p))
                    .map(|l| l.name.clone());
                conn.on_peer_left(&v);
                let n = gone.unwrap_or_else(|| "the other device".into());
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    &format!("  {n} disconnected, waiting briefly in case it reconnects..."),
                ));
            }
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }
}
