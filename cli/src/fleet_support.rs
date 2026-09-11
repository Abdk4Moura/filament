//! Fleet helpers and the mesh housekeeping that goes with them.
//!
//! The fleet half resolves a peer to its fleet name, route, shaped link and root,
//! and reports a missing or pending fleet certificate. The housekeeping half is the
//! other side of the same state: sweeping completed streams and lapsed devices,
//! applying a reconfigure, and making sure this device's genesis header exists.
//!
//! Moved as ELEVEN separate blocks scattered from L992 to L3929; nothing between
//! them is part of this module. NO CFG ANYWHERE: neither these bodies nor any
//! dependency they use anyhow::{ Result };
use crate::PRINCIPAL_STATE_LAPSED;
use crate::PRINCIPAL_STATE_REVOKED;
use crate::ShellPolicy;
use crate::config_get;
use crate::conn::Conn;
use crate::default_drop_dir;
use crate::device_view::device_cert_for;
use crate::devices_store::devices_path;
use crate::display_name;
use crate::effective_principal_deadline;
use crate::fleet;
use crate::identity;
use crate::load_owner_key;
use crate::platform;
use crate::recv_files::{IncomingFile, finalize_incoming};
use crate::session;
use crate::settings;
use crate::shell_policy_from_settings;
use crate::ui;
use anyhow::{Result};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

pub(crate) fn fleet_certificate_warning(name: &str) -> Option<String> {
    let cert = device_cert_for(name)?;
    let owner = load_owner_key()?;
    fleet_certificate_warning_for(name, &cert, owner.public_key_bytes(), identity::now_secs())
}

pub(crate) fn fleet_certificate_warning_for(
    name: &str,
    cert: &identity::DeviceCert,
    owner_pub: [u8; 32],
    now: u64,
) -> Option<String> {
    if cert.user_pub != owner_pub || cert.expires <= now {
        return None;
    }
    Some(format!(
        "{} {} still has fleet access via its certificate.\n  Revoke it: filament revoke {} --certificate",
        ui::paint(ui::Tone::Warn, ui::glyph_warn()),
        name,
        name,
    ))
}

/// Local-only fleet certificate revocation marker. This deliberately lives
/// beside the device record: no CRL or network dependency is introduced.
///
/// Absence semantics: a device with NO record at all is UNKNOWN, not revoked
/// (#161: the typed-code possession ceremony resolves a fresh code peer's
/// cert, which has no record yet; treating unknown as revoked would deny every
/// one-shot transfer the product ships). Revocation is a decision about a
/// KNOWN device: only a record that EXISTS and is marked `certRevoked` denies.
/// The #156 fix is the field-absence half: a KNOWN record whose field is
/// absent starts clean (NOT revoked) - the old `.and_then(...).unwrap_or(true)`
/// collapsed it with `true`, so every legacy record without the field read as
/// revoked (6 live production records).
///
/// A revoked device whose record was deleted is NOT re-authorized: deleting
/// the record also deletes the pair secret, so the pair-proof fails, the link
/// is untrusted, and the gate denies it before revocation is even consulted.
/// The local petname for a device, looked up by its PROVEN certificate key.
///
/// `Link::verified_name` is the capability-store key, so it may only ever be set
/// from something the peer PROVED, never from a name it asserted. A fleet peer
/// that could name itself could name itself after a device that holds grants.
/// Returns None when we hold no record for that key, which is the normal case
/// for a sibling met for the first time.
/// May we install an overlay route for this peer over the link we hold?
///
/// A direct-QUIC link always can (real QUIC datagrams). A RELAY link can only if
/// the peer said it understands relay datagrams, because the packets ride a
/// reserved sid an older peer would silently discard. Installing a route into a
/// peer that drops it is worse than having no route: it looks reachable and is
/// not.
pub(crate) fn fleet_route_ok(conn: &Conn, pid: &str, peer_relay_datagrams: bool) -> bool {
    conn.link(pid).map(|l| l.direct).unwrap_or(false) || peer_relay_datagrams
}

/// Is this link one that must prove itself with a `fleet-hello`?
///
/// Answered from the LINK's own shape, deliberately not from `fleet_pending`.
/// That set is populated only by the fleet-channel presence branch, but warm-hold
/// re-establishes links BY NAME, so a re-established link was never marked, never
/// sent a hello, and silently reverted to unverified while looking alive and
/// correctly named. That is what made a verified sibling ineligible for the warm
/// path after its first reconnect.
///
/// Fleet-shaped means: not already identity-proven by a pair secret, and either
/// carrying no secret at all or carrying the FLEET secret (which is what
/// `start_direct_fleet` puts there, and which proves membership, not identity).
pub(crate) fn fleet_shaped_link(conn: &Conn, pid: &str) -> bool {
    conn.link(pid)
        .map(|l| {
            !l.trusted
                && match &l.expected_secret {
                    None => true,
                    Some((_, secret)) => fleet::rv().as_deref() == Some(secret.as_str()),
                }
        })
        .unwrap_or(false)
}

/// Must L3 wait for `fleet-hello` on this link?
///
/// Only when the link has NOTHING else proving who the peer is. Two devices in
/// one fleet are usually ALSO paired, so they meet on both channels and the pid
/// lands in `fleet_pending` even though the pair-secret MAC already proved
/// identity. Withholding a route from such a link is wrong, and it is what made
/// L3 silently unavailable between a joined device and its owner.
pub(crate) fn fleet_identity_pending(
    conn: &Conn,
    pid: &str,
    pending: bool,
    verified: bool,
) -> bool {
    if !pending || verified {
        return false;
    }
    // A pair secret on the link is independent proof; fleet-hello adds nothing.
    conn.link(pid)
        .map(|l| l.expected_secret.is_none())
        .unwrap_or(true)
}

pub(crate) fn fleet_indexed_name(name: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else {
        return false;
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        return false;
    };
    arr.iter().any(|d| {
        d["name"]
            .as_str()
            .map(|n| n.eq_ignore_ascii_case(name))
            .unwrap_or(false)
            && d["secret"].as_str().is_none()
    })
}

/// Mark delegated records whose effective deadline has passed as lapsed.
/// Idempotent; never touches revoked or already-lapsed records; the record is
/// KEPT as evidence (a vanished record is indistinguishable from one never
/// there). Returns how many records newly lapsed.
pub(crate) fn sweep_lapsed(records: &mut Vec<Value>, now: u64) -> usize {
    let mut changed = 0;
    for record in records.iter_mut() {
        if record["principalKind"].as_str() != Some("delegated") {
            continue;
        }
        if record["certRevoked"].as_bool() == Some(true)
            || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED)
            || record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED)
        {
            continue;
        }
        let Some(cert) = identity::DeviceCert::from_json(&record["deviceCert"]) else {
            continue;
        };
        let not_after = record["principalExpires"].as_u64();
        let last_seen = record["lastSeen"].as_u64();
        let max_offline = record["principalMaxOffline"].as_u64();
        let (deadline, _clock) =
            effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
        if deadline <= now {
            record["principalState"] = json!(PRINCIPAL_STATE_LAPSED);
            record["lapsedAt"] = json!(now);
            changed += 1;
        }
    }
    changed
}

/// The read-only SHARE ROOT a same-owner fleet device may mount without an
/// explicit grant. Config value `share` (a directory path); default a dedicated
/// `~/filament-share`, never home. A mount whose requested root escapes this dir
/// is out of scope (the deliberate tier) and needs an explicit grant.
///
/// COMPOSITION INVARIANT (load-bearing — do not break in a refactor): the
/// transfer INBOX (`drop_dir`, default `~/Filament`) must NOT be inside this
/// share root. Two scoped defaults compose dangerously if it is: `transfer`
/// (write, auto-trusted) could place a file — or, absent plain-file-only write
/// hardening, a symlink — that the read-only `mount` default then serves,
/// turning two individually-correct defaults into arbitrary filesystem read.
/// The defaults (`~/Filament` vs `~/filament-share`) are disjoint by
/// construction; a user who points `dir` and `share` at overlapping paths
/// re-opens this, so the mount server must additionally refuse to traverse
/// out of the share root at open time (see the beneath-root hardening).
pub(crate) fn fleet_share_root() -> PathBuf {
    config_get("share")
        .map(PathBuf::from)
        .unwrap_or_else(|| platform::Paths::home_dir().join("filament-share"))
}

/// Apply a `filament set <key>` change to the LIVE daemon state, the heart of
/// live-reconfigure. Returns whether the change took effect without a restart.
/// Keys woven into startup (relay/server force, or arming the L2 acceptor from
/// cold) return `false`, so the client tells the user to run `filament up`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_reconfigure(
    key: &str,
    dir: &mut PathBuf,
    shell_policy: &mut ShellPolicy,
    shell_user: &mut Option<String>,
    l2_enabled: bool,
    sess: &mut session::Session,
    sio: &filament_signal::Client,
    my_uid: &str,
) -> bool {
    match key {
        "drop-dir" => {
            let nd = settings::get_str("drop-dir", None)
                .map(PathBuf::from)
                .unwrap_or_else(default_drop_dir);
            let _ = std::fs::create_dir_all(&nd);
            *dir = nd;
            true
        }
        "shell-user" => {
            *shell_user = settings::get_str("shell-user", None);
            true
        }
        // auto-extract is re-read on every received file (finalize_incoming), so
        // it is already live; nothing to mutate here.
        "auto-extract" => true,
        "shell" => {
            *shell_policy = shell_policy_from_settings();
            // The per-request accept check consults `shell_policy` live, so a
            // narrow/disable applies instantly. But going from no-shell to shell
            // needs the L2 acceptor that was wired at startup: live only if it was
            // already armed (`l2_enabled`).
            l2_enabled || !shell_policy.enables_l2()
        }
        "name" => {
            // Re-announce presence with the fresh name. Same uid + room, so peers
            // update the label without minting a new presence identity (no ghost).
            if let Some(room) = sess.room.clone() {
                sess.emit(
                    sio,
                    "join",
                    json!({ "room": room, "name": display_name(), "uid": my_uid }),
                )
                .await;
            }
            true
        }
        // relay/server are bound into the establishment + signaling setup at
        // startup; changing them safely needs a fresh `filament up`.
        _ => false,
    }
}

/// Idempotently seed the owner's `self` genesis capability header AND the
/// per-owner ratchet.
///
/// Under authoritative enforcement `cap_authorize` returns `Unprovisioned`
/// until the `self` header exists, and `evaluate()` then denies "ratchet
/// uninitialized" until the per-owner monotonic ratchet exists — so BOTH are
/// required for the capability layer to authorize anything on `self` (owner or
/// delegated principal under its ceiling). Both are tautological: the owner
/// asserts ownership of its OWN self-certifying resource and its own ratchet
/// floor; they widen nothing. Mirrors the genesis block `Cmd::Grant` was the
/// sole (accidental) seeder of. Each half is seeded independently so a store
/// missing only one is healed. Returns true when the store changed. Persisted
/// with `save_cap_store` (a plain write, no reconcile): seeding grants no ssh
/// access and must not trigger the authorized_keys reconciler.
pub(crate) fn ensure_self_genesis_header(
    config_dir: &std::path::Path,
    user_key: &crate::identity::UserKey,
) -> bool {
    let mut store = crate::capability::load_cap_store(config_dir);
    let pk = user_key.public_key_bytes();
    let owner_hex = hex::encode(pk);
    let has_header = store.iter().any(|e| {
        e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
            && e["resource"].as_str() == Some("self")
    });
    let has_ratchet = store.iter().any(|e| {
        e.get("type").and_then(|v| v.as_str()) == Some("cap_ratchet")
            && e["owner_pub"].as_str() == Some(owner_hex.as_str())
    });
    if has_header && has_ratchet {
        return false;
    }
    let now = crate::capability::now_secs();
    if !has_header {
        let nonce = crate::capability::self_resource_nonce();
        let resource = crate::capability::self_resource_id(&pk);
        let mut hdr = crate::capability::CapHeader {
            resource,
            epoch: 0,
            owner_pub: pk,
            nonce,
            floors: vec![],
            issued_at: now,
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        hdr.sig = crate::capability::sign_cap_header(&hdr, &user_key.keypair());
        let mut hdr_json = hdr.to_json();
        // Stored under the caller-facing resource id "self" (what cap_authorize
        // looks up); the signature commits to the self-certifying derived id.
        hdr_json["resource"] = serde_json::json!("self");
        store.push(hdr_json);
    }
    if !has_ratchet && crate::capability::update_ratchet(&mut store, &pk, now).is_err() {
        return false;
    }
    crate::capability::save_cap_store(config_dir, &store).is_ok()
}

/// G-k completion sweep: file-end delivery is best-effort. A stream can
/// receive every expected byte yet have its file-end LOST when the sender's
/// PeerConnection tears down first (observed under load). The bytes are whole
/// (held in `inc.received`; `finalize_incoming` flushes the BufWriter before
/// rename so the on-disk file is complete), but the stream is stranded in
/// `by_sid` with no live link to ever deliver file-end, and that non-empty
/// `by_sid` plus `completed == 0` blocks the quiet-exit while the dead link
/// spins through the reconnect-retry loop to the 120s ceiling. Finalize any
/// fully received stream whose link is gone. `received == size` is exactly the
/// bar the file-end handler itself checks, so this can never claim a genuine
/// partial (received < size stays parked for resume, gate 2) and never
/// touches the offer-stage corruption guard (gate 3). Called both at top-of-
/// loop and right after a link is dropped in the Stuck/GraceExpired handlers,
/// so the bail on `completed == 0` sees the finalized file.
pub(crate) async fn sweep_completed_streams(
    by_sid: &mut HashMap<(String, u32), IncomingFile>,
    conn: &Conn,
    dir: &Path,
    output: &Option<String>,
    to_stdout: bool,
    daemon: bool,
    completed: &mut usize,
) -> Result<()> {
    let done_sids: Vec<(String, u32)> = by_sid
        .iter()
        .filter(|((pid, _), inc)| {
            inc.received.load(Ordering::Relaxed) == inc.size && !conn.links.contains_key(pid)
        })
        .map(|(k, _)| k.clone())
        .collect();
    for key in done_sids {
        if let Some(inc) = by_sid.remove(&key) {
            if to_stdout {
                let f = inc.file.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = f.sync_all();
                })
                .await;
                *completed += 1;
                continue;
            }
            let rename_to = if *completed == 0 {
                output.clone()
            } else {
                None
            };
            ui::say(&ui::paint(
                ui::Tone::Dim,
                &format!(
                    "  ({} fully received, sender left before file-end; finalizing)",
                    inc.name
                ),
            ));
            if finalize_incoming(inc, dir, rename_to.as_deref(), daemon, "").await? {
                *completed += 1;
            }
        }
    }
    Ok(())
}
