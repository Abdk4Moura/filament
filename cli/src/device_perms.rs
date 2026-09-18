//! `filament devices --caps [<device>]`: what a device can do to me, until when.
//!
//! Read-only over `devices.json` and `caps.json`. The view does not compute its
//! own truth. The tier is `device_view::tier_for`, the derivation `devices`
//! renders. The rows are read off the same records and signed ops the gates
//! read: the enrolment ceiling (`principalCeiling`), the pair-secret record
//! (`caps` / `capExpires`) and the owner-signed `cap_grant` ops that target the
//! device's keys. EFFECTIVE is the gate's own decision, `shell_gate::
//! pty_gate_decision` for shell and `cap_gate_effective` for the rest, fed the
//! store-derived inputs `gather_shell_gate_inputs` resolves. Two inputs exist
//! only on a live link and are assumed here, stated in the footer: the link is
//! authenticated (`trusted`) and the daemon's `--shell` policy is not applied.
//!
//! `device_cert_for` skips expiry by design (#266). This view shows the row the
//! way `devices` files it and adds the "cert expired" caveat beside it rather
//! than masking the tier.
use crate::capability::{self, BindingStrength, GateDecision, CAP_SHELL};
use crate::device_caps::{device_allows, device_capability_denied};
use crate::device_view::{same_owner_key, tier_for};
use crate::devices_store::devices_path;
use crate::fleet_ui::devices::DeviceTier;
use crate::identity;
use crate::shell_gate::{pty_gate_decision, ShellGateInputs};
use crate::ui;
use crate::{
    PRINCIPAL_STATE_LAPSED, PRINCIPAL_STATE_REVOKED, cert_revoked_for,
    effective_principal_deadline, format_approval_expiry, persisted_principal_for_cert,
};
use anyhow::Result;
use serde_json::{Value, json};

const ASSUMPTION: &str = "EFFECTIVE is the gate's decision for an authenticated link right now; the running daemon's --shell policy is not consulted here.";

pub(crate) struct CapRow {
    pub action: String,
    pub resource: String,
    pub source: String,
    pub valid_until: Option<u64>,
    /// `Some(verdict)` from the gate; `None` when the gate cannot be asked
    /// from the store alone (an uncertified device has no identity to
    /// evaluate, and the gate refuses trust without one, see #161).
    pub effective: Option<bool>,
    pub reason: String,
}

pub(crate) struct DevicePerms {
    pub name: String,
    pub fingerprint: Option<String>,
    pub addr: Option<String>,
    pub tier: &'static str,
    pub caveats: Vec<String>,
    pub caps: Vec<CapRow>,
    pub denies: Vec<String>,
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// The gate's inputs for `name` doing `action` on `resource`, resolved from the
/// store exactly as `gather_shell_gate_inputs` resolves them, with the link-only
/// facts (trusted, policy) fixed to the values named in `ASSUMPTION`.
fn gate_inputs(
    name: &str,
    action: &str,
    resource: &str,
    cert: Option<&identity::DeviceCert>,
) -> ShellGateInputs {
    let config_dir = crate::settings::config_dir();
    let (idev, iusr, binding, expires, ak_caps) = match cert {
        Some(c) => (
            Some(c.device_pub),
            Some(c.user_pub),
            BindingStrength::Proven,
            Some(c.expires),
            persisted_principal_for_cert(c).0.auth_key_caps().map(|s| s.to_vec()),
        ),
        // Never reached with trusted=true (see perms_for); kept total so the
        // matrix stays fabricable.
        None => (None, None, BindingStrength::None, None, None),
    };
    let outcome = capability::cap_authorize(
        &config_dir, resource, action, idev.as_ref(), iusr.as_ref(), ak_caps.as_deref(),
    );
    let (own_user, has_grant) = capability::cap_fleet_inputs(
        &config_dir, resource, action, idev.as_ref(), iusr.as_ref(), ak_caps.as_deref(),
    );
    ShellGateInputs {
        trusted: true,
        denied: device_capability_denied(name, action),
        policy_allows: false,
        store_allows: device_allows(name, action),
        outcome,
        idev,
        iusr,
        binding,
        expires,
        ak_caps,
        own_user,
        has_grant,
        cert_revoked: cert_revoked_for(idev.as_ref()),
        ceiling_covers: crate::identity_state::ceiling_covers_action(idev.as_ref(), action),
        scoped_default: capability::is_scoped_default_action(action),
        action: action.to_string(),
    }
}

/// The gate's verdict. Shell goes through the shared shell gate; every other
/// action through the single policy site with the same legacy fold and the
/// same inputs, `scoped_in_bounds` set the way the daemon sets it for an open
/// inside the scoped default (inbox, read-only share root). The resource is
/// the row's, so a route grant is judged against its own header.
fn decide(action: &str, resource: &str, inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    if action == CAP_SHELL && resource == "self" {
        return pty_gate_decision(inputs);
    }
    let legacy_ok =
        inputs.trusted && !inputs.denied && (inputs.policy_allows || inputs.store_allows);
    match capability::cap_gate_effective(
        legacy_ok,
        &inputs.outcome,
        action,
        resource,
        inputs.idev.as_ref(),
        inputs.iusr.as_ref(),
        inputs.binding,
        inputs.expires,
        inputs.ak_caps.as_deref(),
        inputs.own_user.as_ref(),
        inputs.scoped_default,
        inputs.has_grant,
        inputs.cert_revoked,
        inputs.denied,
        inputs.ceiling_covers,
    ) {
        GateDecision::Allow => Ok(()),
        GateDecision::Deny { cap_reason } => Err(cap_reason),
    }
}

/// One device's permissions toward me, from its raw record and the cap store.
pub(crate) fn perms_for(
    record: &Value,
    store: &[Value],
    same_owner: Option<&[u8; 32]>,
    now: u64,
) -> DevicePerms {
    let name = record["name"].as_str().unwrap_or("").to_string();
    let cert = identity::DeviceCert::from_json(&record["deviceCert"]);
    let tier = match tier_for(cert.as_ref(), same_owner) {
        DeviceTier::Fleet => "FLEET",
        DeviceTier::External => "EXTERNAL",
        DeviceTier::NeedsReview => "NEEDS REVIEW",
        DeviceTier::MeshRoster => "MESH",
    };
    let state = record["principalState"].as_str();
    let mut caveats = Vec::new();
    match cert.as_ref() {
        None => caveats.push("uncertified, trusted in full".to_string()),
        Some(c) if c.expires <= now => caveats.push(format!("cert expired {}", when(c.expires, now))),
        Some(_) => {}
    }
    if record["certRevoked"].as_bool() == Some(true) || state == Some(PRINCIPAL_STATE_REVOKED) {
        caveats.push("cert revoked".to_string());
    }
    if state == Some(PRINCIPAL_STATE_LAPSED) {
        caveats.push("lapsed".to_string());
    }

    let mut rows = Vec::new();
    // 1. The enrolment ceiling, which is what enforcement honours for a
    //    delegated device (effective_device_caps). Its clock is the binding
    //    deadline, the same min() delegated_device_state quotes.
    let delegated = record["principalKind"].as_str() == Some("delegated");
    let ceiling = if delegated { strings(&record["principalCeiling"]) } else { Vec::new() };
    if delegated {
        let until = cert.as_ref().map(|c| {
            effective_principal_deadline(
                c.expires,
                record["principalExpires"].as_u64(),
                record["lastSeen"].as_u64(),
                record["principalMaxOffline"].as_u64(),
            )
            .0
        });
        for cap in &ceiling {
            rows.push(row(cap, "self", "enrolment ceiling", until));
        }
    }
    // 2. The pair-secret record: `caps`, a v1 record reading as ["transfer"]
    //    (device_caps_at_time), each bounded by capExpires when present. Shown
    //    even when expired, so the operator sees what lapsed and when.
    let v1 = record.get("caps").is_none();
    let legacy = if v1 { vec!["transfer".to_string()] } else { strings(&record["caps"]) };
    for cap in legacy {
        if ceiling.contains(&cap) {
            continue; // the ceiling row above is the one enforcement reads
        }
        let until = record["capExpires"][&cap].as_u64();
        let source = if v1 { "pair-secret legacy (v1 default)" } else { "pair-secret legacy" };
        rows.push(row(&cap, "self", source, until));
    }
    // 3. Owner-signed ops in the cap store that name this device's keys (user
    //    target 0x00, device target 0x01). Tag targets need the tag bindings
    //    resolved and are not listed here.
    if let Some(c) = cert.as_ref() {
        let (user_hex, dev_hex) = (hex::encode(c.user_pub), hex::encode(c.device_pub));
        for e in store.iter().filter(|e| e["type"].as_str() == Some("cap_grant")) {
            let hit = match e["targetKind"].as_u64() {
                Some(0x00) => e["target"].as_str() == Some(user_hex.as_str()),
                Some(0x01) => e["target"].as_str() == Some(dev_hex.as_str()),
                _ => false,
            };
            if !hit {
                continue;
            }
            let grantor = e["grantor"].as_str().unwrap_or("");
            let source = format!(
                "grant by {} v{}",
                grantor.chars().take(8).collect::<String>(),
                e["version"].as_u64().unwrap_or(0)
            );
            let resource = e["resource"].as_str().unwrap_or("self");
            for perm in strings(&e["permissions"]) {
                rows.push(row(&perm, resource, &source, e["expires"].as_u64()));
            }
        }
    }

    // EFFECTIVE: this row is live at `now` AND the gate allows the action for
    // this device. The gate decides per (device, action), so two rows for one
    // action share a verdict and differ only in their own clock.
    for r in rows.iter_mut() {
        let live = r.valid_until.is_none_or(|t| capability::grant_active(t, now));
        if !live {
            r.effective = Some(false);
            r.reason = format!("expired {}", when(r.valid_until.unwrap_or(0), now));
            continue;
        }
        // The gate refuses legacy trust with no resolved identity (#161), so
        // with no certificate there is no gate call to make: the verdict is
        // decided on the live link, and the row says so instead of guessing.
        let Some(c) = cert.as_ref() else {
            r.reason = "not evaluated: uncertified, the gate decides on the live link".to_string();
            continue;
        };
        match decide(&r.action, &r.resource, &gate_inputs(&name, &r.action, &r.resource, Some(c))) {
            Ok(()) => {
                r.effective = Some(true);
                r.reason = "gate allows".to_string();
            }
            Err(Some(reason)) => {
                r.effective = Some(false);
                r.reason = reason;
            }
            Err(None) => {
                r.effective = Some(false);
                r.reason = "refused: legacy trust does not allow it".to_string();
            }
        }
    }

    let addr = record["overlayV6"]
        .as_str()
        .or_else(|| record["overlayV4"].as_str())
        .map(String::from);
    DevicePerms {
        name,
        fingerprint: cert.as_ref().map(|c| hex::encode(c.device_pub).chars().take(8).collect()),
        addr,
        tier,
        caveats,
        caps: rows,
        denies: strings(&record["deniedCaps"]),
    }
}

fn row(action: &str, resource: &str, source: &str, valid_until: Option<u64>) -> CapRow {
    CapRow {
        action: action.to_string(),
        resource: resource.to_string(),
        source: source.to_string(),
        valid_until,
        effective: None,
        reason: String::new(),
    }
}

/// Every record in devices.json, in store order.
pub(crate) fn all_device_perms(now: u64) -> Vec<DevicePerms> {
    let records: Vec<Value> = std::fs::read_to_string(devices_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    let store = capability::load_cap_store(&crate::settings::config_dir());
    let same_owner = same_owner_key();
    records
        .iter()
        .filter(|r| r["name"].is_string())
        .map(|r| perms_for(r, &store, same_owner.as_ref(), now))
        .collect()
}

/// Absolute UTC plus the relative distance, rounded up to one unit.
fn when(ts: u64, now: u64) -> String {
    let (secs, tail) = if ts > now { (ts - now, "") } else { (now - ts, " ago") };
    let unit = if secs >= 86400 {
        format!("{}d", secs.div_ceil(86400))
    } else if secs >= 3600 {
        format!("{}h", secs.div_ceil(3600))
    } else if secs >= 60 {
        format!("{}m", secs.div_ceil(60))
    } else {
        format!("{secs}s")
    };
    let rel = if ts > now { format!("in {unit}") } else { format!("{unit}{tail}") };
    format!("{} ({rel})", format_approval_expiry(ts))
}

fn to_json(d: &DevicePerms) -> Value {
    json!({
        "name": d.name,
        "fingerprint": d.fingerprint,
        "addr": d.addr,
        "tier": d.tier,
        "caveats": d.caveats,
        "caps": d.caps.iter().map(|r| json!({
            "action": r.action,
            "resource": r.resource,
            "source": r.source,
            "valid_until": r.valid_until,
            "effective": r.effective,
            "reason": r.reason,
        })).collect::<Vec<_>>(),
        "denies": d.denies,
    })
}

pub(crate) fn render(devices: &[&DevicePerms], now: u64) -> String {
    let mut out = Vec::new();
    if devices.is_empty() {
        out.push(ui::paint(ui::Tone::Dim, "  No devices yet; see `filament add`."));
    }
    for d in devices {
        let fp = d.fingerprint.as_deref().unwrap_or("no certificate");
        let addr = d.addr.as_deref().unwrap_or("");
        out.push(format!(
            "  {}  {}  {}  {}",
            ui::paint(ui::Tone::Bold, &d.name),
            ui::paint(ui::Tone::Brand, d.tier),
            ui::paint(ui::Tone::Dim, fp),
            ui::paint(ui::Tone::Dim, addr)
        ));
        for c in &d.caveats {
            out.push(format!("     {} {}", ui::paint(ui::Tone::Warn, ui::glyph_warn()), c));
        }
        if d.caps.is_empty() {
            out.push(ui::paint(ui::Tone::Dim, "     (holds no capability toward this machine)"));
        } else {
            let cells: Vec<[String; 6]> = d
                .caps
                .iter()
                .map(|r| {
                    [
                        r.action.clone(),
                        r.resource.clone(),
                        r.source.clone(),
                        r.valid_until.map_or("no expiry".to_string(), |t| when(t, now)),
                        match r.effective {
                            Some(true) => "yes".to_string(),
                            Some(false) => "no".to_string(),
                            None => "?".to_string(),
                        },
                        r.reason.clone(),
                    ]
                })
                .collect();
            let head = ["ACTION", "RESOURCE", "SOURCE", "VALID UNTIL", "EFFECTIVE", "WHY"];
            let widths: Vec<usize> = (0..6)
                .map(|i| cells.iter().map(|c| c[i].len()).chain([head[i].len()]).max().unwrap_or(0))
                .collect();
            let line = |c: &[&str]| -> String {
                let mut s = String::from("     ");
                for (i, cell) in c.iter().enumerate() {
                    s.push_str(&format!("{:<w$}  ", cell, w = widths[i]));
                }
                s.trim_end().to_string()
            };
            out.push(ui::paint(ui::Tone::Dim, &line(&head)));
            for c in &cells {
                let refs: Vec<&str> = c.iter().map(String::as_str).collect();
                out.push(line(&refs));
            }
        }
        if !d.denies.is_empty() {
            out.push(format!(
                "     {} denied: {}",
                ui::paint(ui::Tone::Err, ui::glyph_err()),
                d.denies.join(", ")
            ));
        }
        out.push(String::new());
    }
    out.push(ui::paint(ui::Tone::Dim, &format!("  {ASSUMPTION}")));
    out.join("\n")
}

/// `filament devices --caps [<device>]`. Exit 3 for an unknown name.
pub(crate) fn devices_caps_cmd(name: Option<&str>, json: bool) -> Result<()> {
    let now = capability::now_secs();
    let all = all_device_perms(now);
    let selected: Vec<&DevicePerms> = match name {
        None => all.iter().collect(),
        Some(n) => all.iter().filter(|d| d.name == n).collect(),
    };
    if name.is_some() && selected.is_empty() {
        let message = format!("no device named '{}', see `filament devices`", name.unwrap_or(""));
        if json {
            println!(
                "{}",
                json!({"ok": false, "verb": "devices", "error": {"code": "unknown_device", "exit": 3, "message": message}})
            );
        } else {
            ui::critical(&message);
        }
        std::process::exit(3);
    }
    if json {
        let devices: Vec<Value> = selected.iter().map(|d| to_json(d)).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "verb": "devices",
                "data": {"devices": devices, "assumption": ASSUMPTION},
            }))?
        );
    } else {
        println!("{}", render(&selected, now));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::lock_test_config;

    const OWNER: [u8; 32] = [0x11; 32];

    fn cert(user: u8, device: u8, expires: u64) -> Value {
        json!({
            "devicePub": hex::encode([device; 32]),
            "userPub": hex::encode([user; 32]),
            "expires": expires,
            "issued": 1u64,
            "sig": hex::encode([0u8; 64]),
        })
    }

    fn grant(user: u8, perms: &[&str], expires: u64, version: u64) -> Value {
        json!({
            "type": "cap_grant", "op": 0, "grantor": hex::encode(OWNER), "targetKind": 0,
            "target": hex::encode([user; 32]), "resource": "self", "permissions": perms,
            "expires": expires, "issued_at": 1u64, "version": version, "sig": hex::encode([0u8; 64]),
        })
    }

    /// A store with: a live signed shell grant (laptop), an expired legacy cap
    /// plus an expired signed grant (oldbox), a ceiling-covered delegated fleet
    /// device (joined), a denied cap on a revoked cert (locked), an expired cert
    /// (stale) and a v1 record (plain).
    fn fixture(now: u64) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fil-devperms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", &dir) };
        let sec = "c".repeat(64);
        let devices = json!([
            {"name": "laptop", "secret": sec, "v": 2, "caps": ["transfer", "shell"],
             "deviceCert": cert(0x22, 0xa2, now + 30 * 86400), "overlayV6": "fdf1::a2"},
            {"name": "oldbox", "secret": sec, "v": 2, "caps": ["transfer", "mount"],
             "capExpires": {"mount": now - 10}, "capSources": {"mount": "legacy"},
             "deviceCert": cert(0x33, 0xa3, now + 30 * 86400)},
            {"name": "joined", "v": 2, "caps": ["transfer", "mount"], "principalKind": "delegated",
             "principalCeiling": ["transfer", "mount"], "principalExpires": now + 7200,
             "deviceCert": cert(0x11, 0xa4, now + 30 * 86400)},
            {"name": "locked", "secret": sec, "v": 2, "caps": ["transfer"], "deniedCaps": ["shell"],
             "certRevoked": true, "deviceCert": cert(0x44, 0xa5, now + 30 * 86400)},
            {"name": "stale", "secret": sec, "v": 2, "caps": ["transfer"],
             "deviceCert": cert(0x55, 0xa6, now - 100)},
            {"name": "plain", "secret": sec},
        ]);
        std::fs::write(dir.join("devices.json"), serde_json::to_string_pretty(&devices).unwrap()).unwrap();
        let mut hdr = capability::CapHeader {
            resource: "self".into(), epoch: 0, owner_pub: OWNER, nonce: [7; 32], floors: vec![],
            issued_at: 1, prev_owner_pub: None, prev_header_hash: None, sig: [0; 64],
        }
        .to_json();
        hdr["resource"] = json!("self");
        let store = json!([
            hdr,
            {"type": "cap_ratchet", "owner_pub": hex::encode(OWNER), "max_issued_at": 1},
            grant(0x22, &["shell"], now + 3600, 5),
            grant(0x33, &["mount"], now - 10, 9),
        ]);
        std::fs::write(dir.join("caps.json"), serde_json::to_string_pretty(&store).unwrap()).unwrap();
        capability::invalidate_cap_cache();
        dir
    }

    fn find<'a>(d: &'a DevicePerms, action: &str, source_prefix: &str) -> &'a CapRow {
        d.caps
            .iter()
            .find(|r| r.action == action && r.source.starts_with(source_prefix))
            .unwrap_or_else(|| panic!("{}: no row {action} from {source_prefix}", d.name))
    }

    #[test]
    fn rows_come_from_the_store_and_effective_from_the_gate() {
        let _guard = lock_test_config();
        let prior = std::env::var("FILAMENT_CAP_AUTHORITATIVE").ok();
        unsafe { std::env::set_var("FILAMENT_CAP_AUTHORITATIVE", "0") };
        let now = capability::now_secs();
        let dir = fixture(now);
        let before = (
            std::fs::read(dir.join("devices.json")).unwrap(),
            std::fs::read(dir.join("caps.json")).unwrap(),
        );

        let all = all_device_perms(now);
        let by = |n: &str| all.iter().find(|d| d.name == n).unwrap();

        // A granted shell: legacy row without expiry, signed row with one, both effective.
        let laptop = by("laptop");
        assert_eq!(laptop.tier, "EXTERNAL");
        assert_eq!(laptop.fingerprint.as_deref(), Some("a2a2a2a2"));
        assert_eq!(laptop.addr.as_deref(), Some("fdf1::a2"));
        let signed = find(laptop, "shell", "grant by 11111111 v5");
        assert_eq!(signed.valid_until, Some(now + 3600));
        assert_eq!(signed.effective, Some(true), "{}", signed.reason);
        assert_eq!(find(laptop, "shell", "pair-secret legacy").effective, Some(true));
        assert_eq!(find(laptop, "transfer", "pair-secret legacy").effective, Some(true));

        // An expired grant is listed, not effective, and says when it lapsed.
        let oldbox = by("oldbox");
        let legacy = find(oldbox, "mount", "pair-secret legacy");
        assert_eq!(legacy.valid_until, Some(now - 10));
        assert!(legacy.effective == Some(false) && legacy.reason.starts_with("expired"), "{}", legacy.reason);
        let sig = find(oldbox, "mount", "grant by 11111111 v9");
        assert!(sig.effective == Some(false) && sig.reason.starts_with("expired"));

        // A ceiling-covered cap: one row per ceiling entry, clocked by the binding deadline.
        let joined = by("joined");
        // The tier is `devices`' derivation: the same owner key files it as FLEET.
        let record = serde_json::from_str::<Vec<Value>>(&std::fs::read_to_string(dir.join("devices.json")).unwrap())
            .unwrap()
            .into_iter()
            .find(|r| r["name"] == "joined")
            .unwrap();
        let store = capability::load_cap_store(&dir);
        assert_eq!(perms_for(&record, &store, Some(&OWNER), now).tier, "FLEET");
        assert_eq!(perms_for(&record, &store, None, now).tier, "EXTERNAL");
        let mount = find(joined, "mount", "enrolment ceiling");
        assert_eq!(mount.valid_until, Some(now + 7200));
        assert_eq!(mount.effective, Some(true), "{}", mount.reason);
        assert!(joined.caps.iter().all(|r| r.source == "enrolment ceiling"), "no duplicate legacy rows");
        assert!(joined.caps.iter().all(|r| r.action != "shell"));

        // A denied cap on a revoked cert: the deny is listed, the caveat is
        // shown, and the gate refuses even the transfer baseline.
        let locked = by("locked");
        assert_eq!(locked.denies, vec!["shell".to_string()]);
        assert!(locked.caveats.iter().any(|c| c == "cert revoked"));
        let xfer = find(locked, "transfer", "pair-secret legacy");
        assert!(xfer.effective == Some(false) && xfer.reason.contains("revoked"), "{}", xfer.reason);

        // An expired cert keeps the tier `devices` gives it and gains the caveat.
        let stale = by("stale");
        assert_eq!(stale.tier, "EXTERNAL");
        assert!(stale.caveats.iter().any(|c| c.starts_with("cert expired")), "{:?}", stale.caveats);

        // A v1 record reads as the transfer baseline; with no certificate the
        // gate is not asked (it refuses trust without an identity, #161).
        let plain = by("plain");
        assert_eq!(plain.tier, "NEEDS REVIEW");
        let base = find(plain, "transfer", "pair-secret legacy (v1 default)");
        assert_eq!(base.effective, None);
        assert!(base.reason.starts_with("not evaluated"), "{}", base.reason);

        // Read-only: the view wrote nothing.
        let rendered = render(&all.iter().collect::<Vec<_>>(), now);
        assert!(rendered.contains("grant by 11111111 v5"));
        let after = (
            std::fs::read(dir.join("devices.json")).unwrap(),
            std::fs::read(dir.join("caps.json")).unwrap(),
        );
        assert_eq!(before, after, "devices --caps must not write the store");

        match prior {
            Some(v) => unsafe { std::env::set_var("FILAMENT_CAP_AUTHORITATIVE", v) },
            None => unsafe { std::env::remove_var("FILAMENT_CAP_AUTHORITATIVE") },
        }
        unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_device_selects_nothing() {
        let _guard = lock_test_config();
        let now = capability::now_secs();
        let dir = fixture(now);
        assert!(all_device_perms(now).iter().all(|d| d.name != "ghost"));
        unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}
