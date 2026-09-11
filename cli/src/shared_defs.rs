//! Definitions shared across the crate: limits, wire constants, and the small types
//! the modules pass around.
//!
//! These 28 items were the last block of definitions left in the crate root. They
//! are consts and statics (limits, wire markers, env-gated test knobs), and small
//! structs/enums that several modules exchange: RecvState, PeerAuthz, ServiceManager,
//! ShellPolicy, RevokeRecheck, DeadlineClock, PendingRequest, PartMeta, UiCapability,
//! TtyGuard, MountPlan, SendOutcome.
//!
//! NO item here carries a cfg attribute, so every re-export in the crate root is
//! unconditional. BareTarget deliberately stays in main.rs (clap-slice instruction)
//! and so does the `dlog` macro_rules!, since macros are a different visibility class.
use crate::net::Transport;
use crate::pake_ceremony::Ceremony;
use crate::recv_files::IncomingFile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_SERVER: &str = "https://api.filament.autumated.com";

/// C7: content identity for resume, sha256 over the first 256 KiB.
pub(crate) const HEAD_BYTES: u64 = 256 * 1024;

/// C4/C6/C21: how long we wait for a vanished peer to rejoin. UNWARNED is the
/// blind default; a peer that announced `brb` (e.g. the browser opening a
/// mobile file picker suspends the whole tab) gets its declared ttl instead,
/// informed waits are both longer when promised and shorter when not.
pub(crate) const REJOIN_WINDOW: Duration = Duration::from_secs(120);

/// C3/C4: connection (re)establishment attempts before failing honestly.
pub(crate) const MAX_ATTEMPTS: u32 = 5;

/// P1 (GAP-4): process-global "the user forbade relay" flag, set once from the
/// `--no-relay` CLI flag at startup. Read by `Conn::relay_forbidden` so the
/// stall ladder knows, at `Rung::Exhausted`, whether it MAY auto-escalate to a
/// TURN relay (the never-flaky promise) or must FAIL CLEANLY (the hard
/// direct-only promise the user asked for). A global rather than a threaded
/// param so the many `Conn` construction sites stay untouched; written exactly
/// once, before the runtime spawns any worker (mirrors the `FILAMENT_NAME`
/// single-threaded-set pattern in `run`).
pub(crate) static NO_RELAY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set once in `run`, before any worker spawns, from the global `--no-interactive`
/// flag (mirrors NO_RELAY). The guided code entry NEVER opens when this is set.
pub(crate) static NO_INTERACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(crate) static FORCE_INTERACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// P0 (GAP-1): stall-correction ladder bound. Attempt 0 is rung (a) (resume on
/// the same transport); attempts 1..STALL_MAX_REPAIRS are rung (c) (repair the
/// transport in place, a fresh direct dial / ICE-restart). At the ceiling the
/// ladder is exhausted (P1's relay fallback is the next rung, a clean hook).
/// Slightly above MAX_ATTEMPTS because a fresh direct dial needs BOTH ends to
/// re-offer within one race budget, which can take a couple of aligned ticks;
/// a re-dial is cheap, so a few extra are worth a deterministic recovery.
pub(crate) const STALL_MAX_REPAIRS: u32 = 5;

/// P5 (GAP-6): reserved sid for the relay->direct upgrade VERIFY heartbeat. A
/// real DATA frame on this sid lets the prober confirm the new direct path is
/// actually MOVING data (not just connected) before cutting over. It lives in the
/// non-L2 sid space and far above any file-transfer counter, so it never collides;
/// the receiver has no `by_sid` entry for it, so the inbound chunk is dropped
/// harmlessly (after stamping inbound activity, which is the point: symmetric
/// verify). See `Conn::judge_upgrade_standby`.
pub(crate) const VERIFY_PROBE_SID: u32 = 0x7FFF_FFFF;

/// P4 (GAP-5): how many times the receiver re-requests a transfer whose
/// whole-file sha256 didn't match on completion (truncated/corrupt) before it
/// gives up and fails CLEARLY (kept partial, no silent bad file). A transient
/// truncation recovers on the first resume; this bound only catches a payload
/// that is genuinely, repeatedly corrupt, never a hang, never a silent accept.
pub(crate) const MAX_VERIFY_FAILS: u32 = 3;

/// Sidecar metadata for a partial receive (`<name>.part.meta`).
/// JSON {"size":N,"head":"hex","full":"hex"}; legacy files hold a bare size string.
/// `full` is the whole-file sha256 the sender offered (P4), persisted so a
/// resume after a process restart can still verify-on-completion.
pub(crate) struct PartMeta {
    pub(crate) size: u64,
    pub(crate) head: Option<String>,
    pub(crate) full: Option<String>,
}

/// The three clocks that can end a delegated device's recognition. The binding
/// one is whichever expires first; the state display names it so "X time left"
/// never lies about which bound is actually in charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadlineClock {
    /// The device certificate's own expiry (`verify` fails past it).
    CertExpiry,
    /// The signed absolute stop (`not_after` from the auth key).
    AbsoluteStop,
    /// The liveness budget (`last_seen + effective_max_offline`).
    LivenessBudget,
}

/// Re-checks a live session's authorization on a bounded interval, so a revoked
/// peer loses a long-lived stream (mount, pty, l2) without re-reading the device
/// store per operation. The interval-and-verdict decision lives here, once,
/// instead of being re-derived in each serve loop where it can drift (the shape
/// of #226 and #228).
///
/// The caller MUST deliver the denial in a form its client can act on, then
/// close. Returning silently is not enough: a client that just stops receiving
/// parks where no signal lands (see #235's FUSE D-state).
pub(crate) struct RevokeRecheck {
    pub(crate) last: std::time::Instant,
    pub(crate) interval: std::time::Duration,
}

/// Terminal principal states written to `principalState` on a device record.
pub(crate) const PRINCIPAL_STATE_LAPSED: &str = "lapsed";

pub(crate) const PRINCIPAL_STATE_REVOKED: &str = "revoked";

/// Display name for a fleet link before its certificate names it. Contains a
/// space and a colon so it cannot collide with a device petname, and it is never
/// used as a capability key regardless.
pub(crate) const FLEET_LINK_NAME: &str = "fleet: unverified";

/// Auto-shell policy for the `up`/`recv` acceptor: which proof-verified devices
/// may `filament shell --ssh` in WITHOUT a per-device `grant`. Trust (pair-proof) is
/// always enforced separately, this is purely the capability side.
#[derive(Clone, Debug)]
pub(crate) enum ShellPolicy {
    /// Default: only devices explicitly `grant`ed the `shell` cap.
    Granted,
    /// `up --shell`: any paired device. M-2: this INTENTIONALLY grants every
    /// proof-verified paired device, including ones introduced later via
    /// pair-intro. Use `Only`/`--shell-only` to scope it.
    All,
    /// `up --shell-only a,b`: only these petnames auto-shell; others need a grant.
    Only(std::collections::HashSet<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PendingRequest {
    pub(crate) id: u64,
    pub(crate) peer: String,
    pub(crate) capability: String,
    pub(crate) timestamp: u64,
    pub(crate) status: String, // "pending", "approved", "denied", "expired"
    pub(crate) granted_at: Option<u64>,
}

pub(crate) const MAX_PENDING: usize = 100;

pub(crate) const REQUEST_TTL_SECS: u64 = 3600;

/// Stop the daemon through its service manager, if one owns it. Returns true
/// only when a manager stop actually succeeded. The system and per-user
/// systemd units are tried first, then launchd on macOS; a box where the
/// daemon is not a managed service (a foreground `up`, no systemd) falls back
/// to a plain kill.
/// Which systemd manager owns a daemon pid, if any. Two units can share the
/// name `filament.service` (a system unit and a per-user unit under Linger),
/// so the cgroup's SCOPE, not the unit name, decides which manager to ask:
///   system unit:  /system.slice/filament.service
///   user unit:    /user.slice/user-0.slice/user@0.service/app.slice/filament.service
/// The unit name is matched as a cgroup segment (`/filament.service`), never as
/// a substring, so a neighbouring unit (`my-filament.service`) cannot collide.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ServiceManager {
    SystemdSystem,
    SystemdUser,
}

/// Everything the capability gate needs to know about a peer, resolved once.
///
/// This preamble was written FIVE times in the daemon, identically: lazy-resolve
/// the peer's identity from its stored certificate, then read binding, expiry,
/// revocation and the auth-key ceiling off the link. Five copies of the inputs
/// to an authorization decision.
///
/// This file already records what that shape costs. The four role-election bugs
/// were ONE bug: an input trusted to be computed the same way in several places,
/// with nothing enforcing it. Aimed at the gate that decides who may open a
/// shell, mount a folder or receive a file, it is the same wager.
///
/// Checked before extracting, because a divergence would be a live bug rather
/// than untidiness: all five DO reach cap_gate_effective with cert_revoked. Four
/// compute it here and the transfer arm computed it a few lines later, after its
/// trust floor. Ordering differed; the input did not. Two copies had also
/// drifted in whitespace, which is the usual sign of paste.
///
/// Owned, not borrowed, so a caller can hold it while still using `conn`.
pub(crate) struct PeerAuthz {
    pub(crate) idev: Option<[u8; 32]>,
    pub(crate) iusr: Option<[u8; 32]>,
    pub(crate) binding: crate::capability::BindingStrength,
    pub(crate) expires: Option<u64>,
    pub(crate) cert_revoked: bool,
    pub(crate) ak_caps: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountPlan {
    pub(crate) peer: String,
    pub(crate) remote: String,
    pub(crate) local: String,
    pub(crate) read_only: bool,
}

pub(crate) const REPO: &str = "Abdk4Moura/filament";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    Complete { completed: usize },
    Declined { completed: usize, declined: usize },
}

#[allow(clippy::too_many_arguments)]
/// Receive-transfer and consent state for one `recv_cmd` session.
///
/// Grouped out of the function's locals so the transfer arms can be lifted
/// next. Field types, initial values and comments are exactly what the locals
/// had; nothing else moved.
pub(crate) struct RecvState {
    pub(crate) by_sid: HashMap<(String, u32), IncomingFile>,
    // P4 (GAP-5): per-transfer count of whole-file-verify FAILURES (the digest
    // didn't match on completion). Each failure re-requests a resume (truncated)
    // or a from-zero re-fetch (corrupt body); bounded so a genuinely
    // unrecoverable corruption fails CLEARLY after a few rounds rather than
    // looping forever. Keyed by transfer id.
    pub(crate) verify_fails: HashMap<String, u32>,
    pub(crate) completed: usize,
    pub(crate) ever_received: bool,
    // C22: offers awaiting consent, exactly ONE stdin owner (the reader
    // task); answers arrive as StdinLine events, never via a competing
    // blocking read racing for the user's "y".
    pub(crate) pending: std::collections::VecDeque<(String, Value)>,
    // #30: hold ChannelReady until Proven settles or 3s timeout, so short-session
    // gates never decide on Inferred while the possession-sig challenge is in flight.
    pub(crate) pending_proven: Arc<Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
    // A listening recv accepts a code typed straight into it, the first
    // thing real users try (observed live). C22: stdin runs RAW (cbreak) on a
    // tty so an open y/N question resolves on a single keypress, no Enter;
    // outside a question, bytes accumulate into lines (echoed manually since
    // raw mode disables terminal echo).
    pub(crate) question_open: Arc<std::sync::atomic::AtomicBool>,
    // C25: when the current question appeared (answers sooner than 300ms are
    // buffered keystrokes, not decisions)
    pub(crate) question_shown: Instant,
    // Once a peer wins authentication, Conn binds the receive to its sid/install
    // uid. Only that peer (or its same-uid signaling rejoin) may become active or
    // offer files.
    // A file-offer can race ahead of auth: the sender offers as soon as IT has our
    // confirm, which can land a tick BEFORE we finish verifying ITS confirm (the
    // two confirms cross on the wire, and the shared-room mesh widens that gap). We
    // must not silently drop that offer, the sender offers it only once. So we
    // BUFFER the most recent pre-auth offer per candidate peer and REPLAY it the
    // instant that peer authenticates. Bounded by RECV_MAX_CANDIDATES (same keys).
    pub(crate) recv_pending_offers: HashMap<String, Value>,
    // Each candidate peer's own ephemeral ceremony, keyed by peer id.
    pub(crate) recv_cers: HashMap<String, Ceremony>,
    // Each candidate peer's own bounded budget (armed when its channel comes up).
    pub(crate) recv_deadlines: HashMap<String, Instant>,
}

/// C22: cbreak-mode guard, single-keypress answers without losing line
/// input. `stty` keeps us dependency-free; Drop restores the terminal (and
/// the Interrupted path calls restore() explicitly since process::exit skips
/// Drop).
pub(crate) struct TtyGuard {
    pub(crate) saved: Option<String>,
}
