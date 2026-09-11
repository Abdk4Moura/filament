//! Device-capability store and evaluation, lifted out of `main.rs`.
//!
//! What a known device is allowed to do, and how a grant is written: read the
//! granted capabilities (`device_caps`, `device_caps_at`, `device_caps_at_time`,
//! `device_allows`, `device_allows_at`), the single decision surface the
//! enforcement points share (`device_capability_denied`), the effective set
//! after the enrollment ceiling is applied (`effective_device_caps`, which
//! consults `principal_ceiling_for` where it still lives in the crate root),
//! and the two writers (`device_set_cap`, `mark_bounded_cap_source`,
//! `issue_signed_bounded_grant`) plus device removal (`devices_remove`).
//!
//! Every function takes its inputs explicitly (a device name, a capability,
//! `&mut Vec<Value>` through `with_devices_mut`), so the move is a relocation:
//! no context struct, no closure capture, no ownership change. No cfg or
//! feature branches, no test hooks and no spawned tasks in this block.
use crate::{
    device_cert_for, devices_path, load_owner_key, principal_ceiling_for, with_devices_mut,
};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::path::Path;

/// L1-a (spec §8): read a device's granted capabilities. v1 records (no `caps`)
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
/// read as `["transfer"]` for backward compatibility; deny-by-default otherwise.
/// Returns None if the device isn't known.
fn device_caps(name: &str) -> Option<Vec<String>> {
    device_caps_at(&devices_path(), name)
}

/// The capabilities enforcement actually honours for this device: the enrollment
/// ceiling for a delegated device (grant writes never widen it), or the grant
/// store for a non-delegated device. The devices display renders from this, and
/// `grant`/`revoke` consult the same `principal_ceiling_for` source, so none of
/// the three surfaces hand-writes the delegated/ceiling verdict and drifts.
pub(crate) fn effective_device_caps(name: &str) -> Vec<String> {
    match principal_ceiling_for(name) {
        Some(ceiling) => ceiling,
        None => device_caps(name).unwrap_or_else(|| vec!["transfer".to_string()]),
    }
}

/// Path-explicit core of `device_caps` (testable without touching the global
/// config-dir env var).
#[allow(dead_code)]
pub(crate) fn device_caps_at(path: &Path, name: &str) -> Option<Vec<String>> {
    device_caps_at_time(path, name, crate::capability::now_secs())
}

pub(crate) fn device_caps_at_time(path: &Path, name: &str, now: u64) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(path).ok()?;
    let arr = serde_json::from_str::<Value>(&raw).ok()?;
    for d in arr.as_array()? {
        if d["name"].as_str() == Some(name) {
            let mut caps = match d.get("caps").and_then(|c| c.as_array()) {
                Some(list) => list
                    .iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect(),
                None => vec!["transfer".to_string()], // v1 record
            };
            if let Some(expiries) = d.get("capExpires").and_then(|v| v.as_object()) {
                caps.retain(|cap| {
                    expiries
                        .get(cap)
                        .and_then(|v| v.as_u64())
                        .map(|expiry| crate::capability::grant_active(expiry, now))
                        .unwrap_or(true)
                });
            }
            return Some(caps);
        }
    }
    None
}

/// Path-explicit deny-by-default check (testable).
#[allow(dead_code)]
pub(crate) fn device_allows_at(path: &Path, name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline, never gated (spec §8)
    }
    device_caps_at_time(path, name, crate::capability::now_secs())
        .map(|c| c.iter().any(|g| g == capability))
        .unwrap_or(false)
}

/// L1-a (spec §8 / gate 5): deny-by-default capability enforcement hook. A
/// gated action is allowed only if the device's record grants the capability.
/// "transfer" is the L0 baseline (always allowed, even for empty caps) so this
/// never regresses existing send/recv. Wired now; future L-layers add caps.
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
pub(crate) fn device_allows(name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline, never gated (spec §8)
    }
    device_caps(name)
        .map(|c| c.iter().any(|g| g == capability))
        .unwrap_or(false)
}

/// Grant or revoke a capability on an EXISTING known device, preserving its
/// secret and any other caps. Promotes a v1 record (no `caps`) to v2 with the
/// back-compat baseline `["transfer"]` first, so granting `shell` never silently
/// drops `transfer`. Deny-by-default consent for `filament grant`/`revoke`.
/// Returns Err if the device is unknown (you can't grant a stranger a shell).
/// Has the owner explicitly revoked this capability from this device?
///
/// #244: `revoke <device> shell` wrote caps, and the blanket `up --shell`
/// policy never read caps: `ShellPolicy::All => true`, name and caps ignored.
/// So the command printed "revoked 'shell' from 'X'" and the shell kept
/// working. Worse for a vouched record, which has no certificate, so
/// `revoke --certificate` bailed too and NEITHER verb could reach it. The
/// operator ran the security verb, got a success line, and lost nothing.
///
/// A grant is a capability. A revoke is a DECISION, and a decision has to
/// outrank a policy default or it is not a decision. This is the durable record
/// of that decision, and the blanket policy is now subordinate to it.
pub(crate) fn device_capability_denied(name: &str, capability: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else {
        return false;
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        return false;
    };
    arr.iter()
        .find(|d| d["name"].as_str() == Some(name))
        .and_then(|d| d["deniedCaps"].as_array())
        .is_some_and(|list| list.iter().any(|c| c.as_str() == Some(capability)))
}

pub(crate) fn device_set_cap(
    name: &str,
    capability: &str,
    grant: bool,
    expires: Option<u64>,
) -> Result<()> {
    let capability = crate::capability::canonical_capability(capability)?;
    let mut found = false;
    with_devices_mut(|arr| {
        for d in arr.iter_mut() {
            if d["name"].as_str() != Some(name) {
                continue;
            }
            found = true;
            // #244: a revoke is a decision, not just the absence of a grant, so
            // record it durably where the blanket shell policy can see it.
            // Without this, `revoke <dev> shell` under `up --shell` printed
            // success and changed nothing, because auto_allows reads no caps.
            {
                let mut denied: Vec<String> = d
                    .get("deniedCaps")
                    .and_then(|c| c.as_array())
                    .map(|l| {
                        l.iter()
                            .filter_map(|c| c.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                denied.retain(|c| c != &capability);
                if !grant {
                    denied.push(capability.clone());
                }
                denied.sort();
                denied.dedup();
                d["deniedCaps"] = json!(denied);
            }
            // Current caps: v1 (absent) reads as the transfer baseline.
            let mut caps: Vec<String> = match d.get("caps").and_then(|c| c.as_array()) {
                Some(list) => list
                    .iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect(),
                None => vec!["transfer".to_string()],
            };
            caps.retain(|c| c != &capability);
            if grant {
                caps.push(capability.to_string());
            }
            if let Some(obj) = d.as_object_mut() {
                obj.insert("v".into(), json!(2));
                obj.insert("caps".into(), json!(caps));
                let mut cap_expires = obj
                    .get("capExpires")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();
                if grant {
                    if let Some(expiry) = expires {
                        cap_expires.insert(capability.to_string(), json!(expiry));
                    } else {
                        cap_expires.remove(&capability);
                    }
                } else {
                    cap_expires.remove(&capability);
                }
                obj.insert("capExpires".into(), json!(cap_expires));
                let mut sources = obj
                    .get("capSources")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();
                if grant && expires.is_some() {
                    sources.insert(capability.to_string(), json!("legacy"));
                } else {
                    sources.remove(&capability);
                }
                obj.insert("capSources".into(), json!(sources));
            }
        }
        if !found {
            return Err(anyhow::anyhow!(
                "no known device named '{name}', run `filament devices` to see who you've paired"
            ));
        }
        Ok(())
    })
}

pub(crate) fn mark_bounded_cap_source(name: &str, capability: &str, source: &str) -> Result<()> {
    with_devices_mut(|arr| {
        let Some(device) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) else {
            bail!("unknown device '{name}'")
        };
        let obj = device
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid device record"))?;
        let mut sources = obj
            .get("capSources")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        sources.insert(capability.to_string(), json!(source));
        obj.insert("capSources".into(), json!(sources));
        Ok(())
    })
}

/// Add the authoritative owner-signed bounded grant when the peer is certified.
/// Uncertified peers intentionally retain the legacy `capExpires` fallback.
pub(crate) fn issue_signed_bounded_grant(
    device: &str,
    capability: &str,
    expires: u64,
) -> Result<bool> {
    let Some(user_key) = load_owner_key() else {
        return Ok(false);
    };
    let Some(peer_cert) = device_cert_for(device) else {
        return Ok(false);
    };
    peer_cert.verify(crate::identity::now_secs()).map_err(|_| {
        anyhow::anyhow!("peer identity cert for '{device}' is expired; re-pair to refresh it")
    })?;
    let config_dir = crate::settings::config_dir();
    let mut store = crate::capability::load_cap_store(&config_dir);
    let pk = user_key.public_key_bytes();
    if !store.iter().any(|e| {
        e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
            && e["resource"].as_str() == Some("self")
    }) {
        let mut hdr = crate::capability::CapHeader {
            resource: crate::capability::self_resource_id(&pk),
            epoch: 0,
            owner_pub: pk,
            nonce: crate::capability::self_resource_nonce(),
            floors: vec![],
            issued_at: crate::capability::now_secs(),
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0; 64],
        };
        hdr.sig = crate::capability::sign_cap_header(&hdr, user_key.keypair());
        let mut value = hdr.to_json();
        value["resource"] = json!("self");
        store.push(value);
    }
    let mut op = crate::capability::CapOp {
        op: crate::capability::CapOpKind::Grant,
        grantor: pk,
        target_kind: 0x00,
        target: peer_cert.user_pub,
        resource: "self".into(),
        permissions: vec![capability.into()],
        expires,
        issued_at: crate::capability::now_secs(),
        version: crate::capability::hlc_next(0, crate::capability::now_ms()),
        sig: [0; 64],
    };
    op.sig = crate::capability::sign_cap_op(&op, user_key.keypair());
    let mut value = op.to_json();
    value["type"] = json!("cap_grant");
    store.push(value);
    crate::capability::update_ratchet(&mut store, &pk, op.issued_at)?;
    crate::capability::save_and_list_revoked(&store, &config_dir)?;
    Ok(true)
}

pub(crate) fn devices_remove(name: &str) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Raw-array filter so the REMAINING devices keep their v2 fields (caps,
    // addedAt). The old tuple round-trip rewrote every survivor as bare
    // {name, secret}, silently wiping their `shell` grants on any forget.
    with_devices_mut(|arr| {
        arr.retain(|d| d["name"].as_str() != Some(name));
        Ok(())
    })
}
