//! Identity, principal and capability state helpers.
//!
//! The read and write side of this device's identity state: naming and sanitising
//! device names, computing a principal's effective ceiling and deadline from its
//! records, reading and merging the owner-signed capability ops, checking and
//! setting revocation, certifying a local device, summarising a capability list,
//! minting a capability, and marking a lapsed principal.
//!
//! SIXTEEN scattered blocks. NO CFG ANYWHERE: no member carries a definition- or
//! statement-level attribute, and no dependency is gated once cfg pairs are taken
//! into account. All sixteen are called from sibling modules, so they are pub(crate)
//! here and re-exported from the crate root in one unconditional group. The stray
//! #[test] fn that sat between mint_capability and mark_lapsed_now stayed in main.rs.
use crate::device_view::device_cert_revoked;
use crate::devices_store::{devices_load, devices_path, with_devices_mut};
use crate::identity_flow::principal_from_records;
use crate::{
    DeadlineClock, PRINCIPAL_STATE_LAPSED, PRINCIPAL_STATE_REVOKED, fleet, fleet_ui, identity,
    load_owner_key, local_device_cert_path, ui,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

/// Strip terminal escape sequences and control characters from a device petname
/// before it is stored. A name typed or pasted in a terminal can capture the
/// terminal's own device-attributes reply (`ESC[?1;2c...`); that junk then never
/// matches `--to <name>`, silently breaking targeting (observed live: a `send
/// --to pixel` whose stored name was `...escapes...pixel` fell back to the local
/// room and the Pixel never received). Keep only printable, non-control chars.
pub(crate) fn sanitize_device_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // ESC: drop a CSI escape (`ESC [ ... final-letter`) wholesale.
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue; // also drops a lone/other ESC
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// The single moment a delegated device stops being recognized:
/// `min(cert_expiry, not_after, last_seen + max_offline)`. Each term is a
/// hard bound; whichever comes first is the truth, and the returned clock says
/// which one it was. `last_seen == 0` (never seen) does NOT start the budget
/// clock, so a freshly enrolled or legacy device is governed by its absolute
/// bounds until its first observation.
pub(crate) fn effective_principal_deadline(
    cert_expires: u64,
    not_after: Option<u64>,
    last_seen: Option<u64>,
    max_offline: Option<u64>,
) -> (u64, DeadlineClock) {
    let mut deadline = cert_expires;
    let mut clock = DeadlineClock::CertExpiry;
    if let Some(na) = not_after {
        if na < deadline {
            deadline = na;
            clock = DeadlineClock::AbsoluteStop;
        }
    }
    if let (Some(ls), Some(mo)) = (last_seen, max_offline) {
        if ls > 0 {
            let budget_deadline = ls.saturating_add(mo);
            if budget_deadline < deadline {
                deadline = budget_deadline;
                clock = DeadlineClock::LivenessBudget;
            }
        }
    }
    (deadline, clock)
}

pub(crate) fn persisted_principal_for_cert(
    cert: &identity::DeviceCert,
) -> (
    crate::capability::PrincipalKind,
    Option<u64>,
    Option<u64>,
    Option<u64>,
) {
    let records = std::fs::read_to_string(devices_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
        .unwrap_or_default();
    let own_user_pub = load_owner_key().map(|owner| owner.public_key_bytes());
    principal_from_records(&records, cert, own_user_pub.as_ref())
}

/// Our own signed `cap_header` for resource "self", if this device has one.
///
/// Only an owner device does: the header is signed with the UserKey. This is what
/// gets handed to a joining device so its capability store can resolve which
/// owner it answers to.
/// Every capability OP this device holds that the FLEET owner signed.
///
/// A grant is a `CapOp` with `resource: "self"`, and the self-resource id is
/// derived from the OWNER's key, not the machine's. So an owner-signed op means
/// the same thing on every device in the fleet, which is what makes distributing
/// them coherent rather than a category error.
pub(crate) fn owner_signed_cap_ops() -> Vec<Value> {
    let dir = crate::settings::config_dir();
    let store = crate::capability::load_cap_store(&dir);
    let Some(owner) = fleet::my_owner_pub() else {
        return Vec::new();
    };
    store
        .into_iter()
        .filter(|e| {
            crate::capability::CapOp::from_json(e)
                .map(|op| op.grantor == owner)
                .unwrap_or(false)
        })
        .collect()
}

/// Merge fleet policy received from a peer, keeping only what the OWNER signed.
///
/// Every op is verified against the owner key THIS device already trusts (from
/// its own cap header), so a peer cannot inject policy: it can only relay ops the
/// owner authored. Unverifiable or foreign-grantor entries are dropped silently,
/// and duplicates are skipped so repeated pushes are idempotent. Returns how many
/// were newly stored.
pub(crate) fn merge_owner_cap_ops(ops: &[Value]) -> usize {
    let Some(owner) = fleet::my_owner_pub() else {
        return 0;
    };
    let dir = crate::settings::config_dir();
    let mut store = crate::capability::load_cap_store(&dir);
    let now = crate::capability::now_secs();
    let mut added = 0usize;
    for v in ops {
        let Some(op) = crate::capability::CapOp::from_json(v) else {
            continue;
        };
        if op.grantor != owner || op.verify(&owner, now).is_err() {
            continue;
        }
        let dup = store.iter().any(|e| e == v);
        if !dup {
            store.push(v.clone());
            added += 1;
        }
    }
    if added > 0 {
        if let Err(e) = crate::capability::save_cap_store(&dir, &store) {
            ui::debug(&format!("fleet policy not stored: {e}"));
            return 0;
        }
    }
    added
}

pub(crate) fn owner_cap_header() -> Option<Value> {
    crate::capability::load_cap_store(&crate::settings::config_dir())
        .into_iter()
        .find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some("self")
        })
}

/// Reject a peer name that is not in the device store, and say what IS.
///
/// #241: `reach DGMFA` on a name that had never been paired reported
/// "unreachable, gave up at the establishing phase (~0ms) — DGMFA may be
/// offline, or not running `filament up`". It described a lookup miss as a
/// reachability outcome and sent the user to go and check a machine that was
/// not in their store. The `~0ms` was the tell: it gave up instantly because
/// there was nothing to look up.
///
/// The realistic case is a stale name, not a typo. A device that existed before
/// a `filament reset` and came back under a different name is exactly what
/// someone reaches for.
///
/// This is #221 in another verb. That one was fixed for `send --to` and left
/// everywhere else, so the resolution lives here now and the verbs share it.
///
/// Listing the known names is the part that makes it a fix rather than a better
/// error: the next question is always "then what is it called".
pub(crate) fn require_known_device(name: &str) -> Result<()> {
    let mut known: Vec<String> = devices_load().into_iter().map(|(n, _)| n).collect();
    // Mesh siblings learned from the owner-signed roster are known NAMES (they
    // resolve, and `devices` shows them), but they carry no reconnect secret, so
    // they are recognised, not reachable: a connection to them is not in v1.
    for n in crate::roster::roster_device_names() {
        if !known.iter().any(|k| k == &n) {
            known.push(n);
        }
    }
    if known.iter().any(|n| n == name) {
        return Ok(());
    }
    if known.is_empty() {
        bail!(
            "no device named '{name}'. You have not paired any devices yet: `filament add` to pair one"
        );
    }
    bail!(
        "no device named '{name}'. Known devices: {}\n  filament devices   to see them\n  filament add       to pair a new one",
        known.join(", ")
    )
}

/// #157 call-site derivation for the gate's `cert_revoked` input. A peer with
/// NO resolved device identity is UNIDENTIFIED, not revoked: revocation is a
/// decision about a KNOWN device, and an unidentified peer is one the gate
/// must judge by binding strength, trust floor and grants. An unknown DEVICE
/// (a device_pub with no record) is likewise not revoked; it is a fresh peer
/// the normal gate decides by consent and grants.
pub(crate) fn cert_revoked_for(idev: Option<&[u8; 32]>) -> bool {
    idev.map(device_cert_revoked).unwrap_or(false)
}

/// The revocation re-check interval, overridable for tests. Clamped so a
/// misconfiguration cannot make the re-check effectively never run, or spin on a
/// read-heavy stream by re-reading the device store every operation.
pub(crate) fn revoke_recheck_interval() -> std::time::Duration {
    let ms = std::env::var("FILAMENT_REVOKE_RECHECK_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0) // 0 and garbage mean "default", never "never re-check"
        .unwrap_or(5_000);
    std::time::Duration::from_millis(ms.clamp(250, 300_000))
}

/// How long a shell-class open waits for identity proof before denying it
/// outright. Setting `gate.settle_ms` (default 2000, hard max 5000); 0 and
/// garbage mean "default", never "wait forever" -- an unbounded hold would
/// be a parked-open DoS surface, which the per-link/per-daemon count bounds
/// below then could not mitigate.
pub(crate) fn gate_settle_ms() -> u64 {
    crate::settings::get_str("gate.settle_ms", None)
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(2_000)
        .clamp(250, 5_000)
}

/// Mark a stored device certificate revoked locally. The check path must
/// consult this marker before granting fleet trust; expiry remains separate.
pub(crate) fn set_device_cert_revoked(name: &str, revoked: bool) -> Result<()> {
    with_devices_mut(|arr| {
        let Some(device) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) else {
            bail!("device '{name}' is not in the device store");
        };
        device["certRevoked"] = json!(revoked);
        Ok(())
    })
}

/// Durable device-level revoke. Writes the SINGLE `certRevoked` marker (a
/// decision about the device, not a certificate): the gate refuses the device
/// on every reconnect, and a cert renewal must not clear it (the writer has no
/// clearing line). `principalState`/`revokedAt` are display only.
pub(crate) fn set_device_revoked(name: &str, revoked: bool) -> Result<()> {
    with_devices_mut(|arr| {
        let Some(device) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) else {
            bail!("device '{name}' is not in the device store");
        };
        device["certRevoked"] = json!(revoked);
        if revoked {
            device["revokedAt"] = json!(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            );
            device["principalState"] = json!(PRINCIPAL_STATE_REVOKED);
        } else {
            if let Some(map) = device.as_object_mut() {
                map.remove("revokedAt");
            }
            // Restore returns the device to its pre-revoke state: if it was lapsed
            // the sweeper's marker stays, otherwise clear the terminal state.
            if device["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED) {
                device["principalState"] = Value::Null;
            }
        }
        Ok(())
    })
}

pub(crate) fn certify_local_device(
    user_key: &identity::UserKey,
    name: &str,
) -> Result<identity::DeviceCert> {
    let device_pub = crate::overlay::overlay_pubkey_bytes()?;
    let cert = identity::DeviceCert::certify(
        user_key,
        device_pub,
        identity::now_secs(),
        identity::CERT_TTL_SECS,
    )?;
    let path = local_device_cert_path();
    crate::platform::SecretFile::write_str(
        &path,
        &serde_json::to_string_pretty(&json!({ "name": name, "cert": cert.to_json() }))?,
    )
    .with_context(|| format!("write local device certificate to {}", path.display()))?;
    Ok(cert)
}

/// The persisted capability ceiling of a device record, when that record is a
/// delegated (joined) device. None for an owner device or a plain pair, which
/// are not ceiling-restricted.
pub(crate) fn principal_ceiling_for(name: &str) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(devices_path()).ok()?;
    let arr = serde_json::from_str::<Value>(&raw).ok()?;
    let record = arr
        .as_array()?
        .iter()
        .find(|d| d["name"].as_str() == Some(name))?;
    if record["principalKind"].as_str() != Some("delegated") {
        return None;
    }
    Some(
        record["principalCeiling"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// Gate input: does the peer's persisted, owner-signed enrolment ceiling
/// cover `action`? Keyed by the peer's VERIFIED device identity, never by
/// display name (a name is a label; the key is what the certificate proved).
/// None identity, unknown device, non-delegated record, or missing ceiling
/// all mean "not covered" -- fail closed. Read fresh at every call:
/// ceiling narrowing (re-enrolment, certify --scope) must take effect on
/// the next gate evaluation, never at link-open time.
pub(crate) fn ceiling_covers_action(idev: Option<&[u8; 32]>, action: &str) -> bool {
    let hex = idev.map(hex::encode).unwrap_or_default();
    let covered = std::fs::read_to_string(devices_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|arr| {
            arr.as_array()?
                .iter()
                .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(hex.as_str()))
                .cloned()
        })
        .filter(|record| record["principalKind"].as_str() == Some("delegated"))
        .and_then(|record| record["principalCeiling"].as_array().cloned())
        // Case-insensitive, matching the auth-key ceiling check in
        // cap_gate_effective: two spellings of one capability must agree.
        .map(|items| {
            let want = action.to_lowercase();
            items
                .iter()
                .filter_map(|item| item.as_str())
                .any(|item| item.to_lowercase() == want)
        })
        .unwrap_or(false);
    idev.is_some() && covered
}

/// Liveness re-check for live sessions: recompose the delegated deadline
/// (cert expiry, absolute stop, offline budget) for the peer's STORED cert
/// and report whether it is still ahead. None means unresolvable (no
/// identity, no record, unparsable cert) -- no opinion, never a kill;
/// revocation has its own check. Some(false) ends the session.
pub(crate) fn peer_liveness_alive(idev: Option<&[u8; 32]>) -> Option<bool> {
    let idev = idev?;
    let hex = hex::encode(idev);
    let raw = std::fs::read_to_string(devices_path()).ok()?;
    let arr: Vec<Value> = serde_json::from_str(&raw).ok()?;
    let record = arr
        .iter()
        .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(hex.as_str()))?;
    let cert = identity::DeviceCert::from_json(&record["deviceCert"])?;
    let now = crate::identity::now_secs();
    if cert.verify(now).is_err() {
        return Some(false);
    }
    let (_, not_after, max_offline, last_seen) = persisted_principal_for_cert(&cert);
    let (deadline, _) =
        effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
    Some(deadline > now)
}

pub(crate) fn capability_list_summary(caps: &[String]) -> String {
    caps.iter()
        .map(|cap| match cap.as_str() {
            "shell" => "OWNER-EQUIVALENT shell (can act as you)".to_string(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn mint_capability(raw: &str) -> Result<String> {
    match raw {
        "send" => Ok("transfer".to_string()),
        "write" => Ok("mount".to_string()),
        // `all-ports` shapes an invitation, it is not a cap-store action, so it
        // is deliberately absent from CANONICAL_CAPABILITIES and stays explicit.
        "all-ports" => Ok(raw.to_string()),
        "reuse" => bail!("reuse is a lifetime option, not a capability"),
        "mesh" => {
            let (message, _) = fleet_ui::mint::err_mesh_not_grantable();
            bail!("{message}")
        }
        // DERIVED from the canonical list, not a second hardcoded copy of it.
        // This arm used to spell out shell|mount|transfer, so adding `route` to
        // CANONICAL_CAPABILITIES left `add --allow route` rejecting a capability
        // every other layer already accepted. The visible symptom was the CLI
        // printing "re-invite with route in the invitation" as the remedy for a
        // ceiling error and then refusing that exact command. Two lists that
        // must agree, and only one of them was updated.
        other if crate::capability::CANONICAL_CAPABILITIES.contains(&other) => {
            Ok(other.to_string())
        }
        other => bail!(
            "unsupported capability '{other}' (valid: {}, all-ports)",
            crate::capability::CANONICAL_CAPABILITIES.join(", ")
        ),
    }
}

/// Mark a device record lapsed immediately (advisory depart, or manual). The
/// record is KEPT (option b): evidence survives. Returns the device name.
pub(crate) fn mark_lapsed_now(device_pub: &[u8; 32]) -> Option<String> {
    let key = hex::encode(device_pub);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    with_devices_mut(|arr| {
        let name = arr
            .iter()
            .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
            .and_then(|d| d["name"].as_str().map(str::to_string))
            .ok_or_else(|| anyhow::anyhow!("device not in the store"))?;
        for d in arr.iter_mut() {
            if d["name"].as_str() == Some(&name) {
                d["principalState"] = json!(PRINCIPAL_STATE_LAPSED);
                d["lapsedAt"] = json!(now);
                break;
            }
        }
        Ok(name)
    })
    .ok()
}
#[cfg(test)]
mod tests {
    use crate::{cert_revoked_for, sanitize_device_name};

    #[test]
    fn sanitize_device_name_strips_escape_junk() {
        // The exact corruption observed on the snapshot: a terminal
        // device-attributes reply captured ahead of the real name.
        let dirty = "\u{1b}[?1;2c\u{1b}[?1;2c\u{1b}[>0;276;0cpixel";
        assert_eq!(sanitize_device_name(dirty), "pixel");
        // Lone control chars dropped; surrounding whitespace trimmed.
        assert_eq!(sanitize_device_name("  lap\u{7}top \n"), "laptop");
        // A clean name is unchanged.
        assert_eq!(sanitize_device_name("agboola@pop-os"), "agboola@pop-os");
    }

    #[test]
    fn unidentified_peer_is_not_revoked_but_unknown_device_is() {
        // #157 call-site derivation: a peer with NO resolved device identity
        // (idev=None) must derive cert_revoked=false. The old
        // `.map(device_cert_revoked).unwrap_or(true)` at the call sites
        // conflated "we do not know who you are" with "you are revoked", and
        // the absolute gate Deny turned that into a total transfer outage for
        // every freshly paired peer before identity resolution settles. An
        // unknown DEVICE (a device_pub with no record) is likewise not revoked:
        // revocation is a decision about a known device, and a fresh code peer
        // legitimately has no record yet (#161 composition).
        assert!(
            !cert_revoked_for(None),
            "no identity must not read as revoked"
        );
        let unknown = [0x44u8; 32];
        assert!(
            !cert_revoked_for(Some(&unknown)),
            "an unknown device (no record) is not revoked"
        );
    }
}
