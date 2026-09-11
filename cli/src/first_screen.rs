//! The bare-argument comfort router and the first-screen action list.
//!
//! `classify_bare_token` decides what a bare `filament <word>` means (help, a
//! path to send, a nameplate, `device:port`, `device.mesh`, a known device name,
//! or nothing it recognises), and `first_screen_actions` is the list the no-args
//! screen offers. They travel together because anyhow::{Context, Result, anyhow, bail};
use crate::BareTarget;
use crate::looks_like_pake_code;
use crate::regex_lite_code;

/// `add` was handed an invitation instead of a pairing code. One source for the
/// sentence so the test and the error cannot drift apart.
/// What the bare `filament` screen offers, given what this machine actually has.
///
/// Extracted so #194 can be pinned without driving a terminal: the bug was a
/// menu that contradicted the header printed directly above it.
pub(crate) fn first_screen_actions(
    owner: bool,
    joined: bool,
    device_count: usize,
) -> Vec<(&'static str, &'static str)> {
    if owner {
        vec![
            ("Send something", "send"),
            ("Receive something", "receive"),
            ("Mount remote files", "mount"),
            ("Connect a device with me now", "add"),
            ("Invite a device or person", "add --for"),
            // #209's shape once more, reported by the owner: `ephemeral mint`
            // existed as a verb and this screen never offered it, so the only
            // way to reach it was to already know it. A mint path whose claim
            // surface never grew an entry, exactly like `join` before it.
            //
            // It is a THIRD thing, not a rewording of the two above. Both of
            // those are pairing: a second party is present and consents live.
            // An ephemeral key is for when nobody is there, a CI runner or a
            // borrowed machine that enrols later, so it cannot be folded into
            // either without losing what makes it different.
            (
                "Mint a temporary key (CI, borrowed box)",
                "add --for runner",
            ),
            ("Serve in the background", "up --install"),
            ("See every device", "devices"),
            ("View my identity", "id"),
        ]
    } else if joined {
        vec![
            ("Send something", "send"),
            ("Receive something", "receive"),
            ("Mount remote files", "mount"),
            ("See every device", "devices"),
            ("View my joined identity", "id"),
        ]
    } else if device_count == 0 {
        vec![
            ("Set up this first device", "init"),
            // #209: there are TWO ways to be brought into an identity. `add`
            // mints a pairing code claimed with `add <code>`; `add --for` mints
            // a bounded invitation claimed with `join`. This menu offered only
            // the second, so someone holding a pairing code, which is the path
            // the OWNER side presents first as "Connect a device with me now",
            // had no entry here and had to know to type it. #198's shape: two
            // mint paths, and the claim surface grew only one of them.
            ("Pair with a code I was given", "add"),
            ("Join with an invitation", "join"),
            ("Receive a one-time transfer", "receive"),
        ]
    } else {
        // #194: this branch is about having no IDENTITY, not about being the
        // first device. A machine paired by code has peers in devices.json
        // and no identity of its own, so the header counted "2 DEVICES"
        // directly above an item reading "Set up this first device". The
        // owner hit exactly that and called it strange, which it is.
        //
        // Say what is actually missing, and offer what already works: those
        // peers are reachable right now, so hiding `send` and `devices`
        // behind a setup step nobody needs is its own small lie.
        vec![
            ("Send something", "send"),
            ("Receive something", "receive"),
            ("See every device", "devices"),
            ("Create an identity for this device", "init"),
            ("Pair with a code I was given", "add"), // #209, as above
            ("Join with an invitation", "join"),
        ]
    }
}

/// Pure classification for the bare-argument router. All environment access is
/// injected through the closures so tests can pass fakes. The function does NOT
/// touch capabilities, prompts, or authorizations: it is a router only.
pub(crate) fn classify_bare_token(
    token: &str,
    file_exists: &dyn Fn(&str) -> bool,
    is_known_device: &dyn Fn(&str) -> bool,
) -> BareTarget {
    if token == "help" {
        return BareTarget::Help;
    }
    // Preserve the existing path-first behavior, except when the same bare name
    // is also a known device. A code-shaped filename is still a filename here.
    let is_file = file_exists(token);
    let is_device = is_known_device(token);
    if is_file && is_device {
        return BareTarget::AmbiguousFileDevice;
    }
    if is_file {
        return BareTarget::Send;
    }
    // 4-digit nameplates are the pairing-code shape; keep routing them to `pair`
    // because that is the long-standing bare-code behavior.
    if looks_like_pake_code(token) {
        return BareTarget::Add;
    }
    // 2-3 digit nameplates are the legacy one-time transfer-code shape.
    if regex_lite_code(token) {
        return BareTarget::Receive;
    }
    // `device:port` -> forward (same port locally and remotely). The device part
    // must be a known petname and the port must parse as a u16. If either fails,
    // fall through to the did-you-mean path; do not guess.
    if let Some((dev, port_str)) = token.rsplit_once(':') {
        if !dev.is_empty() && port_str.parse::<u16>().is_ok() && is_known_device(dev) {
            let port = port_str.to_string();
            return BareTarget::Forward {
                lport: port.clone(),
                peer: dev.to_string(),
                rport: port,
            };
        }
    }
    // `device.mesh` or `device.mesh:port` -> reach. The reach command validates
    // the address and reports unknown peers, so do not require a local petname
    // here. Mesh addresses are not limited to the current device index.
    if token.ends_with(".mesh")
        || token
            .split_once(".mesh:")
            .is_some_and(|(dev, port)| !dev.is_empty() && !port.is_empty())
    {
        return BareTarget::Reach(token.to_string());
    }
    // A non-file known device opens a PTY. The router never escalates privilege,
    // so the command path remains responsible for capability checks.
    if is_device {
        return BareTarget::Shell;
    }
    BareTarget::Unknown
}
