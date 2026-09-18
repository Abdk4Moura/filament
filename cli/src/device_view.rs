//! The read side of the device model.
//!
//! Lookups and views used across the CLI: resolving a pubkey or a device record
//! to a certificate, checking whether a cert is still valid or revoked, finding a
//! device by its public key, touching activity, sweeping lapsed devices, the caps
//! summary, the countdown line and the `devices` list renderer.
//!
//! Moved as FIFTEEN separate blocks -- they are scattered through main.rs from
//! L880 to L2959 and nothing between them is part of this module. None of the
//! fifteen has a cfg attribute, a spawn, a nested fn or a function-local use.
//! The fourteen that other files call are `pub(crate)` here because anyhow::{ Result };
use crate::delegated_device_state;
use crate::device_caps::effective_device_caps;
use crate::devices_store::{devices_load, devices_path, devices_upsert_atomic, with_devices_mut};
use crate::fleet_ui;
use crate::identity;
use crate::load_owner_key;
use crate::local_device_cert;
use crate::sweep_lapsed;
use crate::ui;
use crate::warm_device_names;
use anyhow::Result;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn devices_store(name: &str, secret: &str) -> Result<()> {
    // Delegate to atomic upsert: secret only, preserve cert
    devices_upsert_atomic(name, Some(secret), None, None, None, None, None, false)?;
    Ok(())
}

/// L1-a (spec §8): store a v2 device record with its agreed capability set.
/// `caps` is deny-by-default; "transfer" is the L0 baseline. The on-disk shape
/// grows `v` and `caps` but the existing `{name, secret}` fields are unchanged,
/// so the reconnect path (`devices_load`, which reads only name+secret) keeps
/// working byte-for-byte, no regression.
pub(crate) fn devices_store_v2(name: &str, secret: &str, caps: &[String]) -> Result<()> {
    // Delegate to atomic upsert: secret + caps together, preserve cert
    devices_upsert_atomic(
        name,
        Some(secret),
        None,
        Some(caps),
        None,
        None,
        None,
        false,
    )?;
    Ok(())
}

/// Read the device cert (if any) for a named device.
/// The certificate STORED for `name`, valid or not.
///
/// #266: this deliberately does NOT check expiry, and most of its callers want
/// exactly that, because they are asking "is there a record" or are about to run
/// their own `verify`. The name does not say so, which is the trap: a gate
/// written as `device_cert_for(..).is_none()` closes when the first certificate
/// is stored and never reopens when that certificate dies. Use
/// [`device_cert_valid_for`] for any decision that should reopen on expiry.
pub(crate) fn device_cert_for(name: &str) -> Option<identity::DeviceCert> {
    let p = devices_path();
    let raw = std::fs::read_to_string(&p).ok()?;
    let arr: Vec<Value> = serde_json::from_str(&raw).ok()?;
    for d in arr {
        if d["name"].as_str() == Some(name) {
            return identity::DeviceCert::from_json(&d["deviceCert"]);
        }
    }
    None
}

/// The certificate stored for `name` IF it is still valid right now.
///
/// #266: the expiry-aware half of [`device_cert_for`]. A gate meaning "do we
/// already have a usable identity for this device" must ask this one, or an
/// expired certificate wedges the record: unusable everywhere that verifies,
/// still present to anything that only checks existence, with `devices forget`
/// as the sole exit.
pub(crate) fn device_cert_valid_for(name: &str) -> Option<identity::DeviceCert> {
    device_cert_for(name).filter(|c| c.verify(identity::now_secs()).is_ok())
}

/// Is `name` a device we hold an INDEX entry for but no pair secret?
///
/// That is exactly a fleet sibling: recorded so `filament devices` can show the
/// fleet, deliberately without a secret so it never becomes a dial target. The
/// distinction matters for error copy, because such a name is simultaneously
/// "listed" and "not reachable by this verb".
/// Does a device record exist at all, secret or not?
///
/// `devices_load()` filter-maps on `secret`, so every check written against it
/// silently means "devices I can DIAL", not "devices I know". A fleet sibling is
/// indexed without a secret, so those checks answer "no device named X" while
/// `filament devices` is listing X on the next line. For `revoke` that is worse
/// than confusing: a device you can SEE but cannot revoke.
pub(crate) fn device_record_exists(name: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else {
        return false;
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        return false;
    };
    arr.iter().any(|d| d["name"].as_str() == Some(name))
}

pub(crate) fn device_name_for_pub(device_pub: &[u8; 32]) -> Option<String> {
    let raw = std::fs::read_to_string(devices_path()).ok()?;
    let arr: Vec<Value> = serde_json::from_str(&raw).ok()?;
    let key = hex::encode(device_pub);
    arr.iter()
        .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
        .and_then(|d| d["name"].as_str().map(str::to_string))
}

pub(crate) fn device_cert_revoked(device_pub: &[u8; 32]) -> bool {
    let p = devices_path();
    // A GENUINELY ABSENT store means no device records at all: every peer is
    // unknown, not revoked (a fresh init has no devices.json until the first
    // pair). An EXISTING store that is unreadable or unparseable FAILS CLOSED
    // to revoked: a corrupt store must not silently un-revoke every device
    // (advisor ruling). `exists()` is NOT the absence check: it returns false
    // on permission-denied too, which would take the un-revoke branch. Use
    // metadata and distinguish NotFound (absent) from every other error
    // (exists but unreadable: fail closed).
    match std::fs::metadata(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
        Ok(_) => {}
    }
    let Ok(raw) = std::fs::read_to_string(&p) else {
        return true;
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        return true;
    };
    let key = hex::encode(device_pub);
    match arr
        .iter()
        .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
    {
        None => false, // unknown device, not revoked
        Some(d) => d["certRevoked"].as_bool().unwrap_or(false),
    }
}

/// The full record for a device identified by its cert's device_pub, if any.
/// Used by the enrollment path to decide revive (lapsed) vs refuse (revoked).
pub(crate) fn devices_find_by_device_pub(device_pub: &[u8; 32]) -> Option<Value> {
    let p = devices_path();
    let Ok(raw) = std::fs::read_to_string(&p) else {
        return None;
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        return None;
    };
    let key = hex::encode(device_pub);
    arr.into_iter()
        .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
}

/// Sweep the device store for lapsed delegated records. Called periodically by
/// the daemon. Returns how many records newly lapsed.
pub(crate) fn devices_sweep_lapsed(now: u64) -> usize {
    with_devices_mut(|arr| Ok(sweep_lapsed(arr, now))).unwrap_or(0)
}

/// Update the `lastSeen` timestamp and overlay addresses for a known device.
/// Called on each connect so `filament addr <device>` can show recency and addresses.
pub(crate) fn devices_touch(
    name: &str,
    v6: Option<std::net::Ipv6Addr>,
    v4: Option<std::net::Ipv4Addr>,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = devices_touch_at(name, v6, v4, now);
}

/// Clock-injectable form of `devices_touch` so the liveness tests can advance
/// time without sleeping. The production call site passes the real wall clock.
pub(crate) fn devices_touch_at(
    name: &str,
    v6: Option<std::net::Ipv6Addr>,
    v4: Option<std::net::Ipv4Addr>,
    now: u64,
) -> Result<()> {
    with_devices_mut(|arr| {
        for d in arr.iter_mut() {
            if d["name"].as_str() == Some(name) {
                d["lastSeen"] = json!(now);
                if let Some(v6) = v6 {
                    d["overlayV6"] = json!(v6.to_string());
                }
                if let Some(v4) = v4 {
                    d["overlayV4"] = json!(v4.to_string());
                }
                break;
            }
        }
        Ok(())
    })
}

/// Read the `lastSeen` timestamp and overlay addresses for a known device.
pub(crate) fn devices_info(name: &str) -> Option<(u64, Option<String>, Option<String>)> {
    let p = devices_path();
    let raw = std::fs::read_to_string(p).ok()?;
    let arr: Vec<Value> = serde_json::from_str(&raw).ok()?;
    let d = arr.iter().find(|d| d["name"].as_str() == Some(name))?;
    let last_seen = d["lastSeen"].as_u64();
    let v6 = d["overlayV6"].as_str().map(|s| s.to_string());
    let v4 = d["overlayV4"].as_str().map(|s| s.to_string());
    Some((last_seen.unwrap_or(0), v6, v4))
}

/// How long this device's certificate has left, in the words of what actually
/// happens to it.
///
/// #236: Fleet used to get "renews in 87d", and an already-expired Fleet cert
/// got "renews until <a date in the past>" while External got "expired" for the
/// same condition. Nothing renews. `DeviceCert::certify` is reached only from
/// init, recover, enrollment/join and pairing cert storage: no timer, no
/// opportunistic-on-connect path, no verb. The wording came from
/// docs/design-pairing-ux.md rule 2, "auto-renewed by a primary while the device
/// is in good standing", which was designed and never built, so the string was
/// describing a security model the product does not have. Meanwhile the gate
/// fails the cert at exactly the moment the screen said it would renew.
///
/// The tier no longer changes the sentence, because the tier does not change
/// the fact. If renewal is ever built, this is where the distinction earns its
/// way back, and not before.
pub(crate) fn device_countdown(
    _tier: fleet_ui::devices::DeviceTier,
    cert: Option<&identity::DeviceCert>,
) -> String {
    let Some(cert) = cert else {
        // #240: was "promote to continue", the SECOND source of that string
        // after the row flag. No certificate means there is no expiry to count
        // down to, and nothing is blocked, so the column says what is true and
        // the tier heading carries the explanation.
        return "no certificate".to_string();
    };
    let now = identity::now_secs();
    if cert.expires <= now {
        let date = chrono::DateTime::from_timestamp(cert.expires as i64, 0)
            .map(|at| at.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "expired".to_string());
        return format!("expired {date}");
    }
    // Round UP to the nearest whole unit, so a cert issued for 90 days reads
    // "90d", not "129600m" or a seconds figure a few seconds short of the day.
    let secs = cert.expires - now;
    let text = if secs >= 86400 {
        format!("{}d", (secs + 86399) / 86400)
    } else if secs >= 3600 {
        format!("{}h", (secs + 3599) / 3600)
    } else if secs >= 60 {
        format!("{}m", (secs + 59) / 60)
    } else {
        format!("{secs}s")
    };
    format!("expires in {text}")
}

fn device_caps_summary(caps: &[String], tier: fleet_ui::devices::DeviceTier) -> String {
    let mut labels = Vec::new();
    for cap in caps {
        let label = match (tier, cap.as_str()) {
            (fleet_ui::devices::DeviceTier::External, "transfer") => "send→you",
            (_, "transfer") => "inbox",
            (_, "shell") => "OWNER-EQUIVALENT shell",
            (_, "mount") => "mount",
            (_, "send") => "send→you",
            (_, "read") => "read ~/share",
            _ => cap.as_str(),
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        "(none)".to_string()
    } else {
        labels.join(" ")
    }
}

pub(crate) fn device_entries(warm: Option<&Value>) -> Vec<fleet_ui::devices::DeviceEntry> {
    let warm_names = warm_device_names(warm);
    let owner = load_owner_key().map(|key| key.public_key_bytes());
    // The key that identifies "same mesh as me": my own owner key if I have one,
    // else the issuer key held in my own device certificate (the owner I joined
    // under). A device whose cert chains to THIS key is fleet, not external; so
    // a spoke stops filing its owner under "other people".
    let same_owner = owner
        .as_ref()
        .copied()
        .or_else(|| local_device_cert().map(|c| c.user_pub));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let records: Vec<Value> = std::fs::read_to_string(devices_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
        .unwrap_or_default();

    // Iterate the RAW records, not devices_load(): that helper requires a pair
    // secret, and a fleet sibling is indexed without one, so listing through it
    // would hide exactly the devices this surface exists to show.
    records
        .iter()
        .filter_map(|r| r["name"].as_str().map(str::to_string))
        .map(|name| {
            let cert = device_cert_for(&name);
            let tier = match cert.as_ref() {
                None => fleet_ui::devices::DeviceTier::NeedsReview,
                Some(cert) if same_owner.as_ref() == Some(&cert.user_pub) => {
                    fleet_ui::devices::DeviceTier::Fleet
                }
                Some(_) => fleet_ui::devices::DeviceTier::External,
            };
            let caps = effective_device_caps(&name);
            let (last_seen, stored_v6, stored_v4) = devices_info(&name).unwrap_or((0, None, None));
            let address = stored_v6.or(stored_v4);
            let last_seen = (last_seen > 0).then(|| {
                let ago = now.saturating_sub(last_seen);
                if ago < 60 {
                    "just now".to_string()
                } else if ago < 3600 {
                    format!("{}m ago", ago / 60)
                } else if ago < 86400 {
                    format!("{}h ago", ago / 3600)
                } else {
                    format!("{}d ago", ago / 86400)
                }
            });
            // #240: this tier is reached whenever a device has no stored
            // certificate, which every code-flow pairing does. The row used to
            // say "promote to continue" and print `filament devices promote
            // <name>` underneath. Three things wrong at once: the verb does not
            // exist (#191), nothing is blocked (a transfer to such a device
            // works immediately, verified between two machines), and the tier
            // heading blamed "paired before scoped trust" for a pairing made
            // minutes earlier on the current build.
            //
            // So the row now states the condition and prescribes nothing. What
            // is TRUE is that the peer's identity was never certified, so it is
            // trusted in full rather than scoped. The tier's own design is #191
            // and #195 and is not settled here; this only stops the screen
            // asserting a blocked state and an impossible remedy.
            let caps_summary = if tier == fleet_ui::devices::DeviceTier::NeedsReview {
                "uncertified · trusted in full".to_string()
            } else {
                device_caps_summary(&caps, tier)
            };
            let caps_summary = match address {
                Some(address) => format!("{caps_summary}  {address}"),
                None => caps_summary,
            };
            fleet_ui::devices::DeviceEntry {
                name: name.clone(),
                tier,
                // #217: online is authoritative only when the warm-link reply is
                // present. On a platform with no control channel (or no daemon)
                // `warm` is None and the row omits the status instead of
                // rendering "offline" for every device always.
                online: warm.map(|_| warm_names.contains(&name)),
                caps_summary,
                countdown: match delegated_device_state(&name, cert.as_ref(), now, &records) {
                    Some((text, tone)) => ui::paint(tone, &text),
                    None => device_countdown(tier, cert.as_ref()),
                },
                last_seen,
            }
        })
        .collect::<Vec<_>>()
        .into_iter()
        .chain(
            crate::roster::stored_roster()
                .and_then(|r| r["devices"].as_array().cloned())
                .map(|arr| {
                    let self_pub = crate::overlay::overlay_pubkey_bytes().ok();
                    arr.into_iter()
                        .filter_map(move |d| {
                            let name = d["petname"].as_str()?.to_string();
                            // Skip a sibling that is ALREADY in the local store (it has a
                            // secret and a real channel; the roster adds nothing).
                            if devices_load().iter().any(|(n, _)| n == &name) {
                                return None;
                            }
                            // Skip MYSELF: the roster lists the owner's devices, and on a
                            // spoke that includes this device's own key, which must never
                            // render as its own sibling.
                            if let (Some(self_pub), Some(hex_pub)) =
                                (self_pub.as_ref(), d["device_pub"].as_str())
                            {
                                if let Ok(decoded) = hex::decode(hex_pub) {
                                    if decoded.as_slice() == self_pub {
                                        return None;
                                    }
                                }
                            }
                            Some(fleet_ui::devices::DeviceEntry {
                                name,
                                tier: fleet_ui::devices::DeviceTier::MeshRoster,
                                online: None, // unknown liveness (#217), never idle/offline
                                caps_summary: "known via owner".to_string(),
                                countdown: String::new(),
                                last_seen: None,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
        .collect()
}
