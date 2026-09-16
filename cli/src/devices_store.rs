//! The devices store: load, upsert and mutate `devices.json`, lifted out of
//! `main.rs`.
//!
//! The substrate every other capability and identity surface sits on:
//! `devices_path` (where the store lives), `devices_load` (read it, tolerating a
//! missing or malformed file), `with_devices_mut` (the write lock plus atomic
//! rewrite -- the one place mutating the store is safe), `devices_upsert_atomic`
//! (one-record upsert preserving v2 fields) and `upsert_peer_record` (the
//! peer-identity / capability write path).
//!
//! Re-exported from the crate root by `main.rs`, because `device_caps.rs`,
//! `identity_lifecycle.rs` and `renewal_lifecycle.rs` import these names from
//! there. No cfg or feature branches, no test hooks, no spawned tasks; every
//! function takes its inputs explicitly, so no ownership or loop-context change.
use crate::identity;
use crate::sanitize_device_name;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn devices_path() -> PathBuf {
    crate::platform::Paths::config_path("devices.json")
}

/// Lock, read, mutate, and atomically write devices.json. The read-modify-write
/// is atomic across processes via the `devices.json.lock` sidecar (#238), so the
/// daemon's liveness sweep and a concurrent `grant`/`revoke`/`add`/`join` cannot
/// lose each other's update (a lost update is a revoke that reports success and
/// does not persist). The closure runs on the freshly-read array; if it returns
/// Err the file is NOT written (a bail must not clobber a valid store), and if
/// the store cannot be read or parsed the write is skipped too.
pub(crate) fn with_devices_mut<T>(f: impl FnOnce(&mut Vec<Value>) -> Result<T>) -> Result<T> {
    let _lock = crate::platform::DevicesFileLock::acquire()?;
    let p = devices_path();
    let mut arr: Vec<Value> = match std::fs::read_to_string(&p) {
        Ok(raw) => {
            serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("parse devices.json: {e}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(anyhow::anyhow!("read devices.json: {e}")),
    };
    let out = f(&mut arr)?;
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr)?)
        .context("atomic write devices.json")?;
    Ok(out)
}

/// Pure merge step (no I/O): upsert the (secret, cert, caps, scope) fields for `name`
/// into `arr` as ONE record, returning the final stored name (auto-suffixed on a
/// new-name collision). This is the atomicity-relevant step: secret and cert land in
/// the SAME record object, so the single write that follows persists them together and
/// a reader can never observe new-secret + old-cert. Kept pure so the invariant is
/// unit-testable without the process-global config path.
pub(crate) fn upsert_peer_record(
    arr: &mut Vec<Value>,
    name: &str,
    secret: Option<&str>,
    cert: Option<&identity::DeviceCert>,
    caps: Option<&[String]>,
    scope: Option<u8>,
    user_key_hex: Option<&str>,
    delegated: Option<(&[String], u64, u64, u64)>,
) -> String {
    // For existing name, update in place preserving other fields.
    if let Some(existing) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) {
        if let Some(s) = secret {
            existing["secret"] = json!(s);
        }
        if let Some(c) = cert {
            existing["userKey"] = json!(hex::encode(c.user_pub));
            existing["deviceCert"] = c.to_json();
        } else if let Some(uk) = user_key_hex {
            existing["userKey"] = json!(uk);
        }
        if let Some(caps) = caps {
            existing["caps"] = json!(caps);
            existing["v"] = json!(2);
        }
        if let Some(sc) = scope {
            existing["identityScope"] = json!(sc);
        }
        if let Some((ceiling, expires, max_offline, max_offline_ceiling)) = delegated {
            existing["principalKind"] = json!("delegated");
            existing["principalCeiling"] = json!(ceiling);
            existing["principalExpires"] = json!(expires);
            existing["principalMaxOffline"] = json!(max_offline);
            existing["principalMaxOfflineCeiling"] = json!(max_offline_ceiling);
            // A fresh enrollment is a NEW signed claim: its bounds WIN over any
            // prior record's, never merged (a device re-joining with a narrower
            // key must not inherit its wider old ceiling). Clearing the terminal
            // state is the revival of a LAPSED record by name continuity; a
            // REVOKED record is refused upstream before this write runs.
            existing["principalState"] = Value::Null;
            if let Some(map) = existing.as_object_mut() {
                map.remove("lapsedAt");
            }
        }
        return existing["name"].as_str().unwrap_or(name).to_string();
    }

    // New device: auto-suffix if collision.
    //
    // CASE-INSENSITIVE. An exact compare here meant `Laptop` and `laptop` became
    // two devices, and a petname is what `send --to <name>` targets, so a
    // near-duplicate is a targeting footgun rather than a cosmetic one. The
    // intent was already written down: `devices_name_taken` implements exactly
    // this and its doc comment says "(case-insensitive)". It was never wired,
    // and an unwired stricter check reads identically to dead code, which is how
    // it survived (WORK-STATE 1ad/1af).
    //
    // Fixed HERE rather than by calling that fn: it re-reads from disk via
    // `devices_load()`, while this call site works on an in-memory `arr` that is
    // mid-modification, so the two could disagree.
    let mut final_name = name.to_string();
    let taken = |a: &Vec<Value>, n: &str| {
        a.iter().any(|d| {
            d["name"]
                .as_str()
                .is_some_and(|e| e.eq_ignore_ascii_case(n))
        })
    };
    if taken(arr, name) {
        let mut suffix = 2;
        let mut new_name = format!("{name}-{suffix}");
        while taken(arr, &new_name) {
            suffix += 1;
            new_name = format!("{name}-{suffix}");
        }
        eprintln!("  note: '{name}' already exists, pairing as '{new_name}'");
        final_name = new_name;
    }

    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), json!(&final_name));
    if let Some(s) = secret {
        obj.insert("secret".to_string(), json!(s));
    }
    if let Some(c) = cert {
        obj.insert("userKey".to_string(), json!(hex::encode(c.user_pub)));
        obj.insert("deviceCert".to_string(), c.to_json());
    } else if let Some(uk) = user_key_hex {
        obj.insert("userKey".to_string(), json!(uk));
    }
    obj.insert("v".to_string(), json!(2));
    if let Some(caps) = caps {
        obj.insert("caps".to_string(), json!(caps));
    }
    if let Some(sc) = scope {
        obj.insert("identityScope".to_string(), json!(sc));
    }
    if let Some((ceiling, expires, max_offline, max_offline_ceiling)) = delegated {
        obj.insert("principalKind".to_string(), json!("delegated"));
        obj.insert("principalCeiling".to_string(), json!(ceiling));
        obj.insert("principalExpires".to_string(), json!(expires));
        obj.insert("principalMaxOffline".to_string(), json!(max_offline));
        obj.insert(
            "principalMaxOfflineCeiling".to_string(),
            json!(max_offline_ceiling),
        );
    }
    obj.insert(
        "addedAt".to_string(),
        json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ),
    );
    arr.push(Value::Object(obj));
    final_name
}

/// Atomic per-peer (secret, cert) update: read-modify-write whole store via
/// `upsert_peer_record` (both fields in ONE record), persist via write-tmp-then-rename
/// (SecretFile::write already atomic on POSIX). A concurrent reader sees either the full
/// old peer or the full new peer, never a torn state.
/// `allow_reanchor` is the owner-agency escape hatch, and it is deliberately
/// a caller-visible boolean rather than inferred: re-anchoring a record to
/// a new device key is legitimate ONLY as a direct consequence of an
/// owner/user decision made outside this function (accepting an enrollment
/// or pairing ceremony, joining as the owner). The network-driven fleet
/// indexing path must always pass false -- a peer-asserted name may never
/// take over a pinned identity, which is the transplant the pin exists to
/// stop. Default to false unless the call site names the owner decision.
pub(crate) fn devices_upsert_atomic(
    name: &str,
    secret: Option<&str>,
    cert: Option<&identity::DeviceCert>,
    caps: Option<&[String]>,
    scope: Option<u8>,
    user_key_hex: Option<&str>,
    delegated: Option<(&[String], u64, u64, u64)>,
    allow_reanchor: bool,
) -> Result<String> {
    let clean = sanitize_device_name(name);
    let name = clean.as_str();
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).context("create config dir")?;
    }
    with_devices_mut(|arr| {
        // Identity pinning: records are keyed by identity, names are
        // presentation. A cert write whose device key differs from the
        // record's pinned one is a takeover (e.g. a fleet sibling naming
        // itself after a ceilinged device), so it is refused HERE, in the
        // writer, in the SAME lock cycle as the write -- never delegated
        // to callers and with no TOCTOU window between check and write.
        // Records with no pinned cert yet (secret-only pairs) accept.
        if let Some(c) = cert {
            if let Some(existing) = arr.iter().find(|d| d["name"].as_str() == Some(name)) {
                if let Some(pinned) = existing["deviceCert"]["devicePub"].as_str() {
                    let incoming = hex::encode(c.device_pub);
                    if pinned != incoming.as_str() && !allow_reanchor {
                        anyhow::bail!(
                            "refusing to re-anchor record '{name}': pinned device key {pinned} != presented key {incoming}"
                        );
                    }
                }
            }
        }
        let final_name = upsert_peer_record(
            arr,
            name,
            secret,
            cert,
            caps,
            scope,
            user_key_hex,
            delegated,
        );
        Ok(final_name)
    })
}

pub(crate) fn devices_load() -> Vec<(String, String)> {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else {
        return Vec::new();
    };
    serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|d| {
                        Some((
                            d["name"].as_str()?.to_string(),
                            d["secret"].as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}
