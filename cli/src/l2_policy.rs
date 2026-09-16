//! L2 allow/open policy for the receive side.
//!
//! Whether an incoming l2 request is allowed in: the blanket modes
//! (--shell / --shell-only / FILAMENT_L2) keep their existing behaviour, the
//! allow-list path and its loader, and the target checks that decide whether a
//! specific requested target is permitted.
//!
//! Five adjacent blocks, NO cfg, NO nested fns, and ZERO back-edges: this group
//! calls nothing outside itself, so it needs no imports. l2_allow_path and
//! l2_allow_load are used only inside this module and stay private; the three the
//! receive path and the tests reach are pub(crate) and re-exported.

use crate::devices_store::devices_path;
use serde_json::Value;
use std::path::PathBuf;

/// Whether to serve an `l2-open` (TCP tunnel / ssh data link) from a peer.
/// Blanket modes (`--shell` / `--shell-only` / `FILAMENT_L2`) keep their existing
/// trusted-gated behavior. But when L2 is on ONLY because some device was
/// `grant`ed shell, the OPENING peer must itself hold that grant: otherwise a
/// grant for ONE device would let EVERY trusted device open loopback tunnels.
/// `trusted` is still required upstream; this is the additional per-device gate.
/// An explicit deny outranks both blanket mode and the peer's own grant:
/// a shell-denied device opens no tunnels, period (#244 class).
pub(crate) fn l2_open_allowed(blanket: bool, peer_has_shell: bool, denied: bool) -> bool {
    !denied && (blanket || peer_has_shell)
}

/// Opt-in non-loopback forward allowlist: `{config_dir}/l2-allow.json`. Absent or
/// malformed file => no entries => loopback-only (the default SSRF posture). Lets
/// an operator deliberately turn the daemon into a gateway to SPECIFIC hosts for
/// SPECIFIC devices, without opening blanket SSRF. Shape:
///   { "laptop": ["10.0.0.5:5432", "192.168.1.10:*"], "*": ["db.internal:5432"] }
/// A "*" device key applies to any authorized device; "host:*" allows any port.
fn l2_allow_path() -> PathBuf {
    devices_path().with_file_name("l2-allow.json")
}

fn l2_allow_load() -> Value {
    std::fs::read_to_string(l2_allow_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or(Value::Null)
}

/// True if `allow` lists `host:port` (or `host:*`) for `device` or for "*". Pure,
/// so the matching logic is unit-testable without the filesystem. Host match is
/// case-insensitive; the device key must match the proven `verified_name` exactly
/// (or be "*").
pub(crate) fn l2_target_allowed_in(allow: &Value, device: &str, host: &str, port: u16) -> bool {
    let matches = |list: &Value| -> bool {
        list.as_array()
            .map(|a| {
                a.iter().any(|e| {
                    let s = e.as_str().unwrap_or("");
                    match s.rsplit_once(':') {
                        Some((h, "*")) => h.eq_ignore_ascii_case(host),
                        Some((h, p)) => {
                            h.eq_ignore_ascii_case(host) && p.parse::<u16>().ok() == Some(port)
                        }
                        None => false,
                    }
                })
            })
            .unwrap_or(false)
    };
    allow.get(device).map(&matches).unwrap_or(false)
        || allow.get("*").map(&matches).unwrap_or(false)
}

pub(crate) fn l2_target_allowed(device: &str, host: &str, port: u16) -> bool {
    l2_target_allowed_in(&l2_allow_load(), device, host, port)
}

#[cfg(test)]
mod tests {
    use crate::{l2_open_allowed, l2_target_allowed_in};
    use serde_json::{Value, json};

    #[test]
    fn l2_open_gate_scopes_grant_mode() {
        // Blanket mode (--shell / --shell-only / FILAMENT_L2): any trusted peer
        // may open, regardless of its own per-device grant (unchanged behavior).
        assert!(l2_open_allowed(true, false, false));
        assert!(l2_open_allowed(true, true, false));
        // Grant-only mode (L2 on solely because SOME device has a shell grant):
        // the opening peer must itself hold the grant.
        assert!(l2_open_allowed(false, true, false), "granted device may open");
        assert!(
            !l2_open_allowed(false, false, false),
            "ungranted device denied in grant mode"
        );
        // Explicit deny outranks everything, including blanket mode.
        assert!(
            !l2_open_allowed(true, true, true),
            "denied device opens nothing, even blanketed and granted"
        );
    }

    #[test]
    fn l2_target_allowlist_matches() {
        let allow = json!({
            "laptop": ["10.0.0.5:5432", "192.168.1.10:*"],
            "*": ["db.internal:5432"]
        });
        // Exact host:port for the named device.
        assert!(l2_target_allowed_in(&allow, "laptop", "10.0.0.5", 5432));
        // host:* allows any port for that host.
        assert!(l2_target_allowed_in(&allow, "laptop", "192.168.1.10", 9999));
        // "*" device entry applies to any device.
        assert!(l2_target_allowed_in(&allow, "phone", "db.internal", 5432));
        // Wrong port (no wildcard) is denied.
        assert!(!l2_target_allowed_in(&allow, "laptop", "10.0.0.5", 22));
        // Host not listed is denied.
        assert!(!l2_target_allowed_in(&allow, "laptop", "10.0.0.9", 5432));
        // A device with no entry (and not matching "*") is denied.
        assert!(!l2_target_allowed_in(&allow, "phone", "10.0.0.5", 5432));
        // No allowlist at all (null) denies everything (loopback-only default).
        assert!(!l2_target_allowed_in(
            &Value::Null,
            "laptop",
            "10.0.0.5",
            5432
        ));
        // Host match is case-insensitive.
        assert!(l2_target_allowed_in(&allow, "phone", "DB.INTERNAL", 5432));
    }
}
