//! Policy gates: interactivity, relay, quiet-exit and cancellation.
//!
//! Five tiny predicates the commands consult before acting: whether this run may
//! interact, whether relay fallback is forbidden, the relay warning banner, how long
//! a quiet receive may wait before exiting, and the cancellation error.
//!
//! Five scattered blocks. NO cfg, NO spawns, NO nested fns, NO function-local uses.
use crate::shared_defs::{NO_INTERACTIVE, NO_RELAY};
use crate::ui;
use anyhow::{anyhow};
use std::io::IsTerminal;
use std::time::Duration;

/// G-k: how long the recv quiet-check must hold (everything done, nobody
/// attached, no questions) before exiting without a `peer-left`. The 10 s
/// default is overridable for tests (gate 18).
pub(crate) fn quiet_exit_window() -> Duration {
    std::env::var("FILAMENT_QUIET_EXIT_SECS") // test knob (gate 18)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10))
}

/// True when the user passed `--no-relay`: relay fallback is forbidden.
pub(crate) fn relay_forbidden() -> bool {
    NO_RELAY.load(std::sync::atomic::Ordering::Relaxed)
}

/// THE interactivity GATE, scripts/automation are safe BY DEFAULT. Three layers:
///   1. stdin is not a TTY  -> never interactive (pipes, CI, `< /dev/null`).
///   2. TTY but opted out    -> never interactive: `--no-interactive` OR the env
///                              var `FILAMENT_NONINTERACTIVE` (any value).
///   3. TTY and not opted out -> interactive (the guided entry may open).
/// When this returns false, callers MUST keep exactly today's behavior (a clear
/// parse error + expected format and non-zero exit for a malformed arg, or the
/// existing non-interactive default for a missing-but-optional code). NEVER block.
pub(crate) fn interactive_allowed() -> bool {
    std::io::stdin().is_terminal()
        && !NO_INTERACTIVE.load(std::sync::atomic::Ordering::Relaxed)
        && std::env::var_os("FILAMENT_NONINTERACTIVE").is_none()
}

/// The one honest CLI line shown whenever a transfer/connection is actually on
/// the TURN relay route (rung d). Relay is still end-to-end encrypted, but it is
/// NOT a direct link, the "no middleman on the wire" property is gone, so we say
/// so, loudly (amber ⚠), reusing `ui::Tone::Warn`. §3.3 of the design.
pub(crate) fn relay_banner() -> String {
    ui::paint(
        ui::Tone::Warn,
        "⚠ on relay, via a TURN server, not a direct link (still end-to-end encrypted)",
    )
}

pub(crate) fn cancelled() -> anyhow::Error {
    anyhow!("cancelled")
}
