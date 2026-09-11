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
pub(crate) fn l2_open_allowed(blanket: bool, peer_has_shell: bool) -> bool {
    blanket || peer_has_shell
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
