// filament — anywhere-to-anywhere P2P file transfer, CLI end.
//
// Speaks the exact same wire protocol as the browser app at
// https://filament.autumated.com: Socket.IO signaling, perfect-negotiation
// WebRTC, one-time pairing codes, and sid-framed chunk transfer with
// offset-based resume. A browser is a first-class peer: `filament send` can
// deliver straight to a phone with nothing installed on it.
//
//   filament send video.mp4 --code          mint a speakable one-time code
//   filament recv clever-lynx-63            claim it on the other machine
//   filament send ./dir --room demo         directories are tarred on the fly
//   tar c logs | filament send - --name logs.tar --code
//   filament recv -y --dir ~/Drops          auto-accept into a directory
//
// Failure-mode ledger: ../docs/cli-resilience.md — every resilience behavior
// in this file carries its ledger number (C1..C17 / F1..F4).

mod direct;
mod holepunch;
mod l2;
mod net;
mod session;
mod sshkeys;
mod ui;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use net::{Ev, Peer, Transport};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{IsTerminal, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const DEFAULT_SERVER: &str = "https://api.filament.autumated.com";
/// C7: content identity for resume — sha256 over the first 256 KiB.
const HEAD_BYTES: u64 = 256 * 1024;
/// C4/C6/C21: how long we wait for a vanished peer to rejoin. UNWARNED is the
/// blind default; a peer that announced `brb` (e.g. the browser opening a
/// mobile file picker suspends the whole tab) gets its declared ttl instead —
/// informed waits are both longer when promised and shorter when not.
const REJOIN_WINDOW: Duration = Duration::from_secs(120);
fn rejoin_unwarned() -> Duration {
    std::env::var("FILAMENT_REJOIN_SECS") // test knob (gate 15)
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(45))
}
/// G-k: how long the recv quiet-check must hold (everything done, nobody
/// attached, no questions) before exiting without a `peer-left`. The 10 s
/// default is overridable for tests (gate 18).
fn quiet_exit_window() -> Duration {
    std::env::var("FILAMENT_QUIET_EXIT_SECS") // test knob (gate 18)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10))
}
/// C3/C4: connection (re)establishment attempts before failing honestly.
const MAX_ATTEMPTS: u32 = 3;

/// Test/injection hooks — env-gated fault injectors used ONLY by the resilience
/// gates (runner/sim/*) to drive deterministic failure modes. They are compiled
/// in ONLY under `--features test-hooks`; a default/release build strips them
/// entirely (no env reads, no injection logic in the shipped binary). Each hook
/// has a `not(feature = "test-hooks")` twin that returns the production value
/// (the no-hook path), so the surrounding real logic compiles and behaves
/// EXACTLY as if the hook were absent. See cli/Cargo.toml [features].test-hooks.
#[cfg(feature = "test-hooks")]
mod test_hooks {
    /// gate 17b: connect but never send our SPAKE2 element so the ceremony budget fires.
    pub fn pair_stall() -> bool {
        std::env::var("FILAMENT_TEST_PAIR_STALL").is_ok()
    }
    /// P1: force every WebRTC link relay-only (models a hard-NAT peer).
    pub fn webrtc_relay_only() -> bool {
        std::env::var("FILAMENT_TEST_WEBRTC_RELAY_ONLY").map(|v| v == "1").unwrap_or(false)
    }
    /// gate 18b: revert the mode-B post-completion drop to reconnect-always.
    pub fn disable_modeb_drop() -> bool {
        std::env::var("FILAMENT_TEST_DISABLE_MODEB_DROP").is_ok()
    }
    /// #28: revert the deferred peer-left drop to unconditional-drop.
    pub fn no_defer() -> bool {
        std::env::var("FILAMENT_TEST_NO_DEFER").is_ok()
    }
    /// #28: synthesize a peer-left for the active sid once N file-data bytes are sent.
    pub fn inject_peer_left_at() -> Option<u64> {
        std::env::var("FILAMENT_TEST_INJECT_PEER_LEFT").ok().and_then(|v| v.parse::<u64>().ok())
    }
    /// signaling-drop gate: revert the daemon acceptor to the no-outer-loop path.
    pub fn no_signaling_reconnect() -> bool {
        std::env::var("FILAMENT_TEST_NO_SIGNALING_RECONNECT").is_ok()
    }
    /// warm-standby gate: churn surviving links after completion to force the C4 flap.
    pub fn churn_after_complete() -> bool {
        std::env::var("FILAMENT_TEST_CHURN_AFTER_COMPLETE").is_ok()
    }
    /// gate 18: drop the file-end control frame so the completion sweep must finalize.
    pub fn drop_file_end() -> bool {
        std::env::var("FILAMENT_TEST_DROP_FILE_END").is_ok()
    }
    /// gate 18: drop a peer-left event so the quiet-exit fallback is exercised.
    pub fn drop_peer_left() -> bool {
        std::env::var("FILAMENT_TEST_DROP_PEER_LEFT").is_ok()
    }

    /// truncation/ack gate corruption injector. `FILAMENT_TEST_CORRUPT_RECV=<id>`
    /// flips the last on-disk byte of the matching transfer; `_CORRUPT_ONCE=1`
    /// fires exactly once (proving auto-recovery). The "already fired" latch is a
    /// process-global AtomicBool — no env mutation (the old code did an unsafe
    /// `set_var` of `FILAMENT_TEST_CORRUPT_FIRED` inside the async runtime).
    static CORRUPT_FIRED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    /// The configured corrupt-recv target id, if any.
    pub fn corrupt_recv_target() -> Option<String> {
        std::env::var("FILAMENT_TEST_CORRUPT_RECV").ok()
    }
    pub fn corrupt_recv_once() -> bool {
        std::env::var("FILAMENT_TEST_CORRUPT_ONCE").map(|v| v == "1").unwrap_or(false)
    }
    pub fn corrupt_already_fired() -> bool {
        CORRUPT_FIRED.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn corrupt_mark_fired() {
        CORRUPT_FIRED.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Production twins of the test hooks: each returns the no-hook value so the real
/// logic is byte-for-byte the shipped behavior when `test-hooks` is off.
#[cfg(not(feature = "test-hooks"))]
mod test_hooks {
    #[inline] pub fn pair_stall() -> bool { false }
    #[inline] pub fn webrtc_relay_only() -> bool { false }
    #[inline] pub fn disable_modeb_drop() -> bool { false }
    #[inline] pub fn no_defer() -> bool { false }
    #[inline] pub fn inject_peer_left_at() -> Option<u64> { None }
    #[inline] pub fn no_signaling_reconnect() -> bool { false }
    #[inline] pub fn churn_after_complete() -> bool { false }
    #[inline] pub fn drop_file_end() -> bool { false }
    #[inline] pub fn drop_peer_left() -> bool { false }
    #[inline] pub fn corrupt_recv_target() -> Option<String> { None }
}

/// P1 (GAP-4): process-global "the user forbade relay" flag, set once from the
/// `--no-relay` CLI flag at startup. Read by `Conn::relay_forbidden` so the
/// stall ladder knows, at `Rung::Exhausted`, whether it MAY auto-escalate to a
/// TURN relay (the never-flaky promise) or must FAIL CLEANLY (the hard
/// direct-only promise the user asked for). A global rather than a threaded
/// param so the many `Conn` construction sites stay untouched; written exactly
/// once, before the runtime spawns any worker (mirrors the `FILAMENT_NAME`
/// single-threaded-set pattern in `run`).
static NO_RELAY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True when the user passed `--no-relay`: relay fallback is forbidden.
fn relay_forbidden() -> bool {
    NO_RELAY.load(std::sync::atomic::Ordering::Relaxed)
}

/// The one honest CLI line shown whenever a transfer/connection is actually on
/// the TURN relay route (rung d). Relay is still end-to-end encrypted, but it is
/// NOT a direct link — the "no middleman on the wire" property is gone, so we say
/// so, loudly (amber ⚠), reusing `ui::Tone::Warn`. §3.3 of the design.
fn relay_banner() -> String {
    ui::paint(
        ui::Tone::Warn,
        "⚠ on relay — via a TURN server, not a direct link (still end-to-end encrypted)",
    )
}

/// P0 (GAP-1): stall-correction ladder bound. Attempt 0 is rung (a) (resume on
/// the same transport); attempts 1..STALL_MAX_REPAIRS are rung (c) (repair the
/// transport in place — a fresh direct dial / ICE-restart). At the ceiling the
/// ladder is exhausted (P1's relay fallback is the next rung — a clean hook).
/// Slightly above MAX_ATTEMPTS because a fresh direct dial needs BOTH ends to
/// re-offer within one race budget, which can take a couple of aligned ticks;
/// a re-dial is cheap, so a few extra are worth a deterministic recovery.
const STALL_MAX_REPAIRS: u32 = 5;

/// P5 (GAP-6): reserved sid for the relay->direct upgrade VERIFY heartbeat. A
/// real DATA frame on this sid lets the prober confirm the new direct path is
/// actually MOVING data (not just connected) before cutting over. It lives in the
/// non-L2 sid space and far above any file-transfer counter, so it never collides;
/// the receiver has no `by_sid` entry for it, so the inbound chunk is dropped
/// harmlessly (after stamping inbound activity — which is the point: symmetric
/// verify). See `Conn::judge_upgrade_standby`.
const VERIFY_PROBE_SID: u32 = 0x7FFF_FFFF;

/// P4 (GAP-5): how many times the receiver re-requests a transfer whose
/// whole-file sha256 didn't match on completion (truncated/corrupt) before it
/// gives up and fails CLEARLY (kept partial, no silent bad file). A transient
/// truncation recovers on the first resume; this bound only catches a payload
/// that is genuinely, repeatedly corrupt — never a hang, never a silent accept.
const MAX_VERIFY_FAILS: u32 = 3;

/// Gate-18 Mode B: the single predicate that decides whether a stuck/lost link
/// should be DROPPED (transfer is complete; nothing left to fetch) rather than
/// reconnected. Pulled out as a pure function so the gate-2 / gate-11c fence
/// (mid-transfer links must NEVER be dropped) is unit-testable without a live
/// WebRTC peer. The recv loop computes `conn.recv_done` from exactly this each
/// tick; `on_stuck` then reads the flag.
///
/// - `completed`: files fully placed on disk so far.
/// - `keep_open`: the receiver was asked to stay resident (gate 13).
/// - `by_sid_empty`: NO stream is in flight (an in-progress reconnect/resume
///   keeps a by_sid entry, which must keep the link reconnecting — gate 2/11c).
fn recv_transfer_done(completed: usize, keep_open: bool, by_sid_empty: bool) -> bool {
    completed > 0 && !keep_open && by_sid_empty
}

/// Bug 5: after repeated stuck-while-connecting on establishment, the user has
/// no clue WHY. The dominant single-host cause is a browser publishing mDNS
/// (`*.local`) ICE candidates the CLI can't resolve when both ends share one
/// machine — the candidate pair never nominates and the link wedges silently.
/// Print this hint at most once per command. `shown` is the caller's one-shot
/// latch so the hint never repeats and never fires on a normal first blip.
fn maybe_hint_local_wedge(shown: &mut bool) {
    if *shown {
        return;
    }
    *shown = true;
    ui::say(&ui::paint(
        ui::Tone::Dim,
        "  still can't connect — if both ends are on the SAME machine, a browser's \
         mDNS (.local) ICE candidates can block this; try a different network path, \
         or disable mDNS ICE in the browser (chrome://flags → \"Anonymize local IPs\").",
    ));
}

const VERSION: &str = env!("FILAMENT_BUILD_INFO"); // stamped by build.rs

const EXAMPLES: &str = "\
EXAMPLES:
  filament video.mp4                 send it; mints a speakable one-time code + QR
  filament clever-lynx-63            claim a code and receive
  filament send ./photos --code      directories tar on the fly
  filament recv <code> -o - | tar x  stream straight into a pipe
  filament pair --name phone         remember a device — a ceremony, no file needed
  filament send big.iso --to laptop  no code: a remembered device, verified by proof
  filament up --install              always-on drop target (trusted devices only)
  filament introduce laptop phone    vouch two of your devices to each other

  The other end never needs anything installed: https://filament.autumated.com";

#[derive(Parser)]
#[command(name = "filament", version = VERSION, about = "P2P file transfer between terminals and browsers — no upload, no account", after_help = EXAMPLES)]
struct Cli {
    /// Signaling server (self-hosters: point at your own instance)
    #[arg(long, global = true, env = "FILAMENT_SERVER", default_value = DEFAULT_SERVER)]
    server: String,
    /// Force TURN relay (testing/privacy; hides your IP from the peer)
    #[arg(long, global = true)]
    relay: bool,
    /// Forbid relay: keep a hard direct-only promise. The never-flaky guarantee
    /// is traded for "no middleman, ever" — a path that can't go direct FAILS
    /// CLEANLY (a clear error, a kept partial) instead of falling back to a TURN
    /// relay. Conflicts with --relay (which forces relay).
    #[arg(long, global = true, conflicts_with = "relay")]
    no_relay: bool,
    /// Display name shown to peers (default: config file, then user@host)
    #[arg(long, global = true)]
    name_as: Option<String>,
    /// Verbose output: -v shows resilience internals (stalls, repairs,
    /// reconnects, upgrade probes); -vv adds ICE/per-frame trace. The
    /// value-prop lines (route, relay banner) always print. Overridden by
    /// FILAMENT_LOG=<critical|info|debug|trace>.
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Quiet: print only the must-see lines (route label, relay banner, P1/P5
    /// path changes, fatal errors). Conflicts with -v. Overridden by
    /// FILAMENT_LOG.
    #[arg(short = 'q', long = "quiet", global = true, conflicts_with = "verbose")]
    quiet: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send files or directories to a peer (browser or CLI)
    Send {
        /// Files or directories to send; '-' reads stdin
        paths: Vec<String>,
        /// Mint a speakable one-time code the receiver claims
        #[arg(long)]
        code: bool,
        /// Choose the one-time code word yourself (implies --code)
        #[arg(long)]
        word: Option<String>,
        /// After a code pairing, remember the other device under this name
        #[arg(long)]
        remember: Option<String>,
        /// Join an explicit room instead of the same-network auto room
        #[arg(long)]
        room: Option<String>,
        /// Only connect to a peer whose display name contains this (C13)
        #[arg(long)]
        to: Option<String>,
        /// Override the offered file name (for stdin '-', or a single file)
        #[arg(long)]
        name: Option<String>,
    },
    /// Receive files from a peer (browser or CLI)
    Recv {
        /// One-time code spoken by the sender (omit to use the auto room)
        code: Option<String>,
        /// Directory to write received files into
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Accept every offer without prompting
        #[arg(long, short = 'y')]
        yes: bool,
        /// Join an explicit room instead of the same-network auto room
        #[arg(long)]
        room: Option<String>,
        /// Only accept a sender whose display name contains this (C13)
        #[arg(long)]
        to: Option<String>,
        /// Keep listening after a sender disconnects
        #[arg(long)]
        keep_open: bool,
        /// After a code pairing, remember the other device under this name
        #[arg(long)]
        remember: Option<String>,
        /// Rename the (single) received file; '-' streams it to stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },
    /// Remember a device — a pairing ceremony, no file needed. Mints a code
    /// (or claims one) and exchanges the pair secret with consent on both ends
    Pair {
        /// A code from the other device; omit to mint one for them
        code: Option<String>,
        /// What to call them (asked interactively if omitted)
        #[arg(long)]
        name: Option<String>,
    },
    /// List devices remembered via --remember (trusted for --to and auto-accept)
    Devices {
        #[command(subcommand)]
        action: Option<DevicesAction>,
    },
    /// Always-on receiver: trusted known devices only, invisible to strangers
    Up {
        /// Install + start a systemd user service instead of running attached
        #[arg(long)]
        install: bool,
        /// Drop directory (default: `filament config dir`, else ~/Filament)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Accept seamless `filament ssh` from ANY paired (proof-verified) device
        /// — no per-device `grant` needed. Enables the tunnel acceptor too, so you
        /// don't also need FILAMENT_L2=1. Strangers still can't get in (pairing is
        /// required). Prints a security banner.
        #[arg(long)]
        shell: bool,
        /// Like --shell but ONLY for these devices (comma-separated petnames);
        /// every other device still needs an explicit `grant <dev> shell`.
        #[arg(long, value_name = "DEVICES")]
        shell_only: Option<String>,
        /// Drop the web-shell / ssh PTY to this non-root account (via
        /// `runuser -l <user>`). STRONGLY recommended when `up` runs as root:
        /// without it, a granted device gets a shell as the up-process user
        /// (often root). Requires `up` to run as root (runuser is setuid).
        #[arg(long, value_name = "USER")]
        shell_user: Option<String>,
    },
    /// Show whether the daemon runs and what it received recently
    Status,
    /// Stop the daemon
    Down,
    /// Vouch between two known devices: mints a fresh secret and delivers it
    /// to both over verified channels (run on the device that knows both)
    Introduce { a: String, b: String },
    /// Get or set config (keys: name, server, dir) in ~/.config/filament/config
    Config { key: Option<String>, value: Option<String> },
    /// Update filament to the latest release
    Update {
        /// Check only; don't install
        #[arg(long)]
        check: bool,
        /// Include prerelease (beta) builds
        #[arg(long)]
        beta: bool,
    },
    /// Generate shell completions (bash, zsh, fish, elvish, powershell)
    Completions {
        shell: clap_complete::Shell,
    },
    /// Print the man page (roff) to stdout
    #[command(hide = true)]
    Man,
    /// Tunnel: wire stdio to one TCP stream on a known peer's localhost (the
    /// ssh ProxyCommand primitive). Off by default; FILAMENT_L2=1 enables the
    /// acceptor side in `up`/`recv`.
    Netcat {
        /// Known device (petname) to tunnel through
        peer: String,
        /// Remote port on the peer's localhost
        rport: u16,
    },
    /// Open a PTY shell on a known device and bridge it to this terminal (the CLI
    /// sibling of the browser web-shell). The peer must run `up --shell` (or grant
    /// shell). Off by default; FILAMENT_L2=1 / --shell enables the acceptor.
    Pty {
        /// Known device (petname) to open a shell on
        peer: String,
    },
    /// Tunnel: local TCP listener; each connection becomes one stream to the
    /// peer's localhost:<rport>.
    Forward {
        /// Local port to listen on (127.0.0.1)
        lport: u16,
        /// Known device (petname) to tunnel through
        peer: String,
        /// Remote port on the peer's localhost
        rport: u16,
    },
    /// Tunnel: run your real `ssh` over the data channel via ProxyCommand
    /// (reuses your keys, known_hosts, and ~/.ssh/config).
    Ssh {
        /// Known device (petname) to ssh into
        peer: String,
        /// Extra args passed through to ssh (user@host, commands, -p, ...)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Grant a known device a capability (deny-by-default). `shell` permits
    /// seamless `filament ssh` into THIS machine — a separate consent from
    /// file transfer; pairing alone never yields a shell.
    Grant {
        /// Known device (petname)
        device: String,
        /// Capability to grant (e.g. `shell`)
        capability: String,
    },
    /// Revoke a capability from a known device. Revoking `shell` also strips the
    /// device's filament-managed block from this machine's authorized_keys.
    Revoke {
        /// Known device (petname)
        device: String,
        /// Capability to revoke (e.g. `shell`)
        capability: String,
    },
}

/// Petname management (C12): names are LOCAL aliases for pair secrets — the
/// secret is the identity, the name is yours to fix when you mislabel one.
#[derive(Subcommand)]
enum DevicesAction {
    /// Forget a device: deletes the secret; it can no longer find you
    Forget { name: String },
    /// Rename your local alias (the other side is unaffected)
    Rename { old: String, new: String },
}

/// Looks like a legacy speakable TRANSFER code: word-word-digits (3 segments).
/// This is what `send --code` mints and `recv` claims.
fn regex_lite_code(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3
        && parts[0].chars().all(|c| c.is_ascii_lowercase())
        && parts[1].chars().all(|c| c.is_ascii_lowercase())
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[2].len() >= 2
        && parts[2].chars().all(|c| c.is_ascii_digit())
}

/// Bug 4: looks like a PAKE PAIRING code: adj-animal-extra-NNNN (4 segments,
/// three lowercase words then a numeric nameplate). This is what `pair` mints
/// and the browser's "pair with code" consumes — NOT interchangeable with the
/// 3-segment transfer code above. Used only to give a helpful error/route, not
/// to authenticate (the PAKE does that).
fn looks_like_pake_code(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 4
        && parts[..3].iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
        && parts[3].len() >= 2
        && parts[3].chars().all(|c| c.is_ascii_digit())
}

// --------------------------------------------------------------- utilities --

/// Persistent per-install identity (shared by every process using this
/// config dir). Lets a sender recognize — and never target — its OWN daemon
/// when both sit on the same pair-presence channels.
fn install_id() -> String {
    let p = devices_path().with_file_name("device.id");
    if let Ok(id) = std::fs::read_to_string(&p) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    let id: String = fresh_secret()[..8].to_string();
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&p, &id);
    id
}

pub(crate) fn mk_uid(prefix: &str) -> String {
    // Test hook (gate 11): a pinned uid lets the harness exercise the
    // same-device-rejoined supersede path (C6). The cli-s-/cli-r- role prefix
    // must survive the override or same-role skip (C13) breaks.
    if let Ok(forced) = std::env::var("FILAMENT_UID") {
        return format!("cli-{prefix}-{forced}");
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("cli-{prefix}-{}-{:x}{:x}", install_id(), std::process::id(), nanos)
}

/// Same install (our own daemon / another process of this device)?
pub(crate) fn is_self_uid(my_uid: &str, peer_uid: Option<&str>) -> bool {
    if std::env::var("FILAMENT_UID").is_ok() {
        return false; // test hook pins uids; don't second-guess it
    }
    let id = install_id();
    let _ = my_uid;
    peer_uid.map(|p| p.contains(&format!("-{id}-"))).unwrap_or(false)
}

fn config_path() -> PathBuf {
    devices_path().with_file_name("config")
}

/// Tiny `key value` per-line config; no toml dependency for three keys.
fn config_get(key: &str) -> Option<String> {
    std::fs::read_to_string(config_path()).ok()?.lines().find_map(|l| {
        let (k, v) = l.split_once(char::is_whitespace)?;
        (k == key && !v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

fn config_set(key: &str, value: &str) -> Result<()> {
    let p = config_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut lines: Vec<String> = std::fs::read_to_string(&p)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(key))
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{key} {value}"));
    std::fs::write(&p, lines.join("\n") + "\n")?;
    Ok(())
}

pub(crate) fn display_name() -> String {
    if let Ok(n) = std::env::var("FILAMENT_NAME") {
        return n;
    }
    if let Some(n) = config_get("name") {
        return n;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    let host = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "cli".into());
    format!("{user}@{host}")
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", U[i]) }
}

/// C7: hash of the first min(256 KiB, len) bytes — cheap content identity
/// carried in file-offer so resume can detect a different file wearing the
/// same name + size.
fn head_hash(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD_BYTES as usize];
    let mut got = 0usize;
    while got < buf.len() {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    let mut h = Sha256::new();
    h.update(&buf[..got]);
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// P4 (GAP-5): sha256 over the WHOLE file — the end-to-end content digest the
/// receiver compares against on completion so a truncated/corrupt transfer can
/// never be declared "done" (the runner had to bolt this above the transport;
/// P4 makes it a core guarantee). Streamed in 1 MiB reads so a large payload
/// doesn't have to be slurped into RAM. `None` if the file can't be read — the
/// offer then omits `full` and the receiver degrades to the legacy size-only
/// check (backward-compat; bounded, never a hang).
fn full_hash(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Sidecar metadata for a partial receive (`<name>.part.meta`).
/// JSON {"size":N,"head":"hex","full":"hex"}; legacy files hold a bare size string.
/// `full` is the whole-file sha256 the sender offered (P4) — persisted so a
/// resume after a process restart can still verify-on-completion.
struct PartMeta {
    size: u64,
    head: Option<String>,
    full: Option<String>,
}

impl PartMeta {
    fn load(path: &Path) -> Option<PartMeta> {
        let raw = std::fs::read_to_string(path).ok()?;
        if let Ok(v) = serde_json::from_str::<Value>(&raw) {
            if let Some(size) = v["size"].as_u64() {
                return Some(PartMeta {
                    size,
                    head: v["head"].as_str().map(|s| s.to_string()),
                    full: v["full"].as_str().map(|s| s.to_string()),
                });
            }
        }
        raw.trim().parse::<u64>().ok().map(|size| PartMeta { size, head: None, full: None })
    }
    fn store(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, json!({ "size": self.size, "head": self.head, "full": self.full }).to_string())
    }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    for i in 1..1000 {
        let c = dir.join(format!("{name}.{i}"));
        if !c.exists() {
            return c;
        }
    }
    dir.join(format!("{name}.dup"))
}

// ------------------------------------------------------- known devices (C12) --
// Persistent pairing: during a code-paired session, both sides exchange a
// 32-byte secret END-TO-END over the DataChannel (the server never sees it)
// and store it under a local nickname. Presence: subscribe with
// sha256("filament-pair:" + secret) — the server learns only meeting points.
// Trust: an HMAC(secret) proof exchanged after connect, so the server cannot
// impersonate a known device. Full PAKE remains roadmap (ledger C15).

fn devices_path() -> PathBuf {
    if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
        return PathBuf::from(d).join("devices.json");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/filament/devices.json")
}

pub(crate) fn devices_load() -> Vec<(String, String)> {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else { return Vec::new() };
    serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|d| Some((d["name"].as_str()?.to_string(), d["secret"].as_str()?.to_string())))
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn devices_store(name: &str, secret: &str) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Operate on the raw JSON so OTHER records keep their v2 fields (caps,
    // addedAt) verbatim. Going through the (name, secret) tuples of
    // devices_load() silently rewrote every other device as bare
    // {name, secret}, wiping their `shell` grants on any store (pairing,
    // introduce, rename) — a quiet privilege-loss bug.
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    match arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) {
        // Re-storing an existing name: only the secret rotates; keep its caps.
        Some(existing) => existing["secret"] = json!(secret),
        None => arr.push(json!({"name": name, "secret": secret})),
    }
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// L1-a (spec §8): store a v2 device record with its agreed capability set.
/// `caps` is deny-by-default; "transfer" is the L0 baseline. The on-disk shape
/// grows `v` and `caps` but the existing `{name, secret}` fields are unchanged,
/// so the reconnect path (`devices_load`, which reads only name+secret) keeps
/// working byte-for-byte — no regression.
fn devices_store_v2(name: &str, secret: &str, caps: &[String]) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Preserve other records verbatim (including their v/caps if present).
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    arr.retain(|d| d["name"].as_str() != Some(name));
    arr.push(json!({"name": name, "secret": secret, "v": 2, "caps": caps,
                    "addedAt": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)}));
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// L1-a (spec §8): read a device's granted capabilities. v1 records (no `caps`)
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
/// read as `["transfer"]` for backward compatibility; deny-by-default otherwise.
/// Returns None if the device isn't known.
fn device_caps(name: &str) -> Option<Vec<String>> {
    device_caps_at(&devices_path(), name)
}

/// Path-explicit core of `device_caps` (testable without touching the global
/// config-dir env var).
#[allow(dead_code)]
fn device_caps_at(path: &Path, name: &str) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(path).ok()?;
    let arr = serde_json::from_str::<Value>(&raw).ok()?;
    for d in arr.as_array()? {
        if d["name"].as_str() == Some(name) {
            return Some(match d.get("caps").and_then(|c| c.as_array()) {
                Some(list) => list.iter().filter_map(|c| c.as_str().map(String::from)).collect(),
                None => vec!["transfer".to_string()], // v1 record
            });
        }
    }
    None
}

/// Path-explicit deny-by-default check (testable).
#[allow(dead_code)]
fn device_allows_at(path: &Path, name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline — never gated (spec §8)
    }
    device_caps_at(path, name).map(|c| c.iter().any(|g| g == capability)).unwrap_or(false)
}

/// L1-a (spec §8 / gate 5): deny-by-default capability enforcement hook. A
/// gated action is allowed only if the device's record grants the capability.
/// "transfer" is the L0 baseline (always allowed, even for empty caps) so this
/// never regresses existing send/recv. Wired now; future L-layers add caps.
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
fn device_allows(name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline — never gated (spec §8)
    }
    device_caps(name).map(|c| c.iter().any(|g| g == capability)).unwrap_or(false)
}

/// Grant or revoke a capability on an EXISTING known device, preserving its
/// secret and any other caps. Promotes a v1 record (no `caps`) to v2 with the
/// back-compat baseline `["transfer"]` first, so granting `shell` never silently
/// drops `transfer`. Deny-by-default consent for `filament grant`/`revoke`.
/// Returns Err if the device is unknown (you can't grant a stranger a shell).
fn device_set_cap(name: &str, capability: &str, grant: bool) -> Result<()> {
    let p = devices_path();
    let raw = std::fs::read_to_string(&p)
        .map_err(|_| anyhow::anyhow!("no known device named '{name}' — pair first"))?;
    let mut arr: Vec<Value> = serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut found = false;
    for d in arr.iter_mut() {
        if d["name"].as_str() != Some(name) {
            continue;
        }
        found = true;
        // Current caps: v1 (absent) reads as the transfer baseline.
        let mut caps: Vec<String> = match d.get("caps").and_then(|c| c.as_array()) {
            Some(list) => list.iter().filter_map(|c| c.as_str().map(String::from)).collect(),
            None => vec!["transfer".to_string()],
        };
        caps.retain(|c| c != capability);
        if grant {
            caps.push(capability.to_string());
        }
        if let Some(obj) = d.as_object_mut() {
            obj.insert("v".into(), json!(2));
            obj.insert("caps".into(), json!(caps));
        }
    }
    if !found {
        return Err(anyhow::anyhow!(
            "no known device named '{name}' — run `filament devices` to see who you've paired"
        ));
    }
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// C27: a declined remember offer must not leave one-sided dead weight.
fn devices_remove(name: &str) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Raw-array filter so the REMAINING devices keep their v2 fields (caps,
    // addedAt). The old tuple round-trip rewrote every survivor as bare
    // {name, secret}, silently wiping their `shell` grants on any forget.
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    arr.retain(|d| d["name"].as_str() != Some(name));
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub(crate) fn channel_of(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"filament-pair:");
    h.update(secret.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA256 (manual: avoids a hmac-crate version dance with sha2 0.11).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner.finalize());
    outer.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// C20: the proof binds the pair secret to the DTLS session. uids are
/// order-normalized (direction-tagged by the prover's uid prefix) and BOTH
/// certificate fingerprints are mixed in sorted order — a channel MITM'd by
/// anyone (including the signaling server) has different fingerprints, so
/// the proof fails and auto-accept refuses.
pub(crate) fn proof_for(secret: &str, prover_uid: &str, a_uid: &str, b_uid: &str, fp1: &str, fp2: &str) -> String {
    let (lo, hi) = if a_uid < b_uid { (a_uid, b_uid) } else { (b_uid, a_uid) };
    let (f_lo, f_hi) = if fp1 < fp2 { (fp1, fp2) } else { (fp2, fp1) };
    hmac_sha256(
        secret.as_bytes(),
        format!("filament-proof2:{prover_uid}|{lo}|{hi}|{f_lo}|{f_hi}").as_bytes(),
    )
}

pub(crate) fn fresh_secret() -> String {
    let mut buf = [0u8; 32];
    // std-only CSPRNG is unavailable; derive from getrandom via std::fs on unix
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // fallback (non-unix): hash of time+pid noise, still unpredictable enough
        let mut h = Sha256::new();
        h.update(format!("{:?}{}", SystemTime::now(), std::process::id()));
        buf.copy_from_slice(&h.finalize()[..32]);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------- daemon (C19) --

fn drop_dir(flag: Option<PathBuf>) -> PathBuf {
    flag.or_else(|| config_get("dir").map(PathBuf::from)).unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join("Filament")
    })
}

/// Minimal `YYYY-MM-DD HH:MM` UTC stamp (civil-from-days; avoids chrono).
fn chrono_now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = (secs / 86400, secs % 86400);
    let (hh, mm) = (rem / 3600, (rem % 3600) / 60);
    // Howard Hinnant's civil_from_days
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

fn pidfile() -> PathBuf {
    devices_path().with_file_name("up.pid")
}
fn up_log() -> PathBuf {
    devices_path().with_file_name("up.log")
}

fn daemon_alive() -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(pidfile()).ok()?.trim().parse().ok()?;
    let cmd = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).ok()?;
    cmd.contains("filament").then_some(pid)
}

/// The argv for a web-shell PTY.
///
/// M-1 (privilege-drop): when `--shell-user <name>` is set, drop the PTY to that
/// account via `runuser -l <user>` (a clean setuid+login-shell wrapper available
/// on every systemd distro). `runuser` does no PAM password prompt, so it only
/// works when `up` itself runs as root — which is exactly the case the flag is
/// meant to de-fang (a root daemon should hand out a NON-root shell). Without the
/// flag the PTY runs as the up-process user (often root on a server); this is an
/// ACCEPTED RISK documented in docs/security/web-shell-review.md (M-1) and in the
/// `up --shell` help. Operators are urged to pass `--shell-user`.
fn shell_argv(shell_user: Option<&str>) -> Vec<String> {
    let shell = std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
        if std::path::Path::new("/bin/bash").exists() { "/bin/bash".into() } else { "/bin/sh".into() }
    });
    match shell_user {
        // `runuser -l <user>` opens a fresh login shell as <user>; we don't force
        // a specific shell so the target account's own login shell is honored.
        Some(user) => vec!["runuser".into(), "-l".into(), user.into()],
        None => vec![shell, "-l".into()],
    }
}

/// Auto-shell policy for the `up`/`recv` acceptor: which proof-verified devices
/// may `filament ssh` in WITHOUT a per-device `grant`. Trust (pair-proof) is
/// always enforced separately — this is purely the capability side.
#[derive(Clone, Debug)]
enum ShellPolicy {
    /// Default: only devices explicitly `grant`ed the `shell` cap.
    Granted,
    /// `up --shell`: any paired device. M-2: this INTENTIONALLY grants every
    /// proof-verified paired device — including ones introduced later via
    /// pair-intro. Use `Only`/`--shell-only` to scope it.
    All,
    /// `up --shell-only a,b`: only these petnames auto-shell; others need a grant.
    Only(std::collections::HashSet<String>),
}

impl ShellPolicy {
    fn auto_allows(&self, name: &str) -> bool {
        match self {
            ShellPolicy::Granted => false,
            ShellPolicy::All => true,
            ShellPolicy::Only(set) => set.contains(name),
        }
    }
    /// Active policy implies the L2 tunnel acceptor is on (you can't ssh without it).
    fn enables_l2(&self) -> bool {
        !matches!(self, ShellPolicy::Granted)
    }
}

async fn up_cmd(
    server: &str,
    install: bool,
    dir: Option<PathBuf>,
    relay: bool,
    shell: bool,
    shell_only: Option<String>,
    shell_user: Option<String>,
) -> Result<()> {
    let shell_policy = match &shell_only {
        Some(csv) => ShellPolicy::Only(
            csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        ),
        None if shell => ShellPolicy::All,
        None => ShellPolicy::Granted,
    };
    if install {
        let exe = std::env::current_exe()?;
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
        std::fs::create_dir_all(&unit_dir)?;
        let unit = unit_dir.join("filament.service");
        // Carry the shell policy into the unit so a service install keeps the
        // same seamless-ssh posture the user asked for on the command line.
        let mut up_args = String::from(" up");
        if let Some(csv) = &shell_only {
            up_args.push_str(&format!(" --shell-only {csv}"));
        } else if shell {
            up_args.push_str(" --shell");
        }
        if let Some(u) = &shell_user {
            up_args.push_str(&format!(" --shell-user {u}"));
        }
        std::fs::write(&unit, format!(
            "[Unit]\nDescription=Filament drop target (trusted devices only)\nAfter=network-online.target\n\n[Service]\nExecStart={}{}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
            exe.display(), up_args
        ))?;
        ui::say(&format!("  {} wrote {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), unit.display()));
        let enabled = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .and_then(|_| std::process::Command::new("systemctl").args(["--user", "enable", "--now", "filament"]).status())
            .map(|st| st.success())
            .unwrap_or(false);
        if enabled {
            ui::say(&format!("  {} service enabled and started — logs: journalctl --user -u filament", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
        } else {
            ui::say(&format!("  start it with: {}", ui::paint(ui::Tone::Bold, "systemctl --user enable --now filament")));
        }
        return Ok(());
    }
    if let Some(pid) = daemon_alive() {
        bail!("already up (pid {pid}) — `filament status` / `filament down`");
    }
    let dir = drop_dir(dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(pidfile(), std::process::id().to_string())?;
    match &shell_policy {
        // M-2: --shell intentionally grants ALL proof-verified paired devices
        // (current AND any introduced later via pair-intro). This is a broad,
        // deliberate over-grant; --shell-only is the scoped, safer alternative.
        ShellPolicy::All => ui::say(&format!(
            "  {} seamless shell ON — ANY paired device (now or paired later) can `filament ssh` into this machine",
            ui::paint(ui::Tone::Warn, "!"),
        )),
        ShellPolicy::Only(set) => {
            let mut names: Vec<&String> = set.iter().collect();
            names.sort();
            let list = names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            ui::say(&format!(
                "  {} seamless shell ON for: {list} — they can `filament ssh` into this machine",
                ui::paint(ui::Tone::Warn, "!"),
            ));
        }
        ShellPolicy::Granted => {}
    }
    // M-1: warn loudly when a shell policy is active but the PTY is NOT dropped to
    // a non-root account. The granted device would get a shell as the up-process
    // user (often root on a server). `--shell-user <name>` de-fangs this.
    if shell_policy.enables_l2() && shell_user.is_none() {
        ui::say(&format!(
            "  {} shell PTYs run as THIS user (root if the daemon is root) — pass `--shell-user <name>` to drop to a non-root account",
            ui::paint(ui::Tone::Warn, "!"),
        ));
    }
    let res = recv_cmd(server, None, dir, false, None, None, true, relay, None, true, None, shell_policy, shell_user).await;
    let _ = std::fs::remove_file(pidfile());
    res
}

fn status_cmd() -> Result<()> {
    match daemon_alive() {
        Some(pid) => ui::say(&format!("  {} up (pid {pid})", ui::paint(ui::Tone::Ok, ui::glyph_ok()))),
        None => ui::say(&format!("  {} not running — start with: filament up", ui::paint(ui::Tone::Dim, "·"))),
    }
    let n = devices_load().len();
    ui::say(&format!("  {} known device{}", n, if n == 1 { "" } else { "s" }));
    if let Ok(log) = std::fs::read_to_string(up_log()) {
        let recent: Vec<&str> = log.lines().rev().take(8).collect();
        if !recent.is_empty() {
            ui::say(&ui::paint(ui::Tone::Dim, "  recent receives:"));
            for l in recent.iter().rev() {
                ui::say(&format!("    {l}"));
            }
        }
    }
    Ok(())
}

fn down_cmd() -> Result<()> {
    match daemon_alive() {
        Some(pid) => {
            std::process::Command::new("kill").arg(pid.to_string()).status()?;
            let _ = std::fs::remove_file(pidfile());
            ui::say(&format!("  {} stopped (pid {pid})", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
            Ok(())
        }
        None => {
            ui::say("  not running");
            Ok(())
        }
    }
}

// ------------------------------------------------------------ introduce ----
// Vouched pairing: the hub (which already trusts A and B) mints a fresh
// secret and delivers it to both over channels it has PROVEN itself on
// (fingerprint-bound, C20). Receivers only honor pair-intro from a verified
// link, so a stranger — or the server — can't inject trust.

async fn introduce_cmd(server: &str, a: &str, b: &str, relay: bool) -> Result<()> {
    let store = devices_load();
    let find = |n: &str| store.iter().find(|(name, _)| name.eq_ignore_ascii_case(n)).cloned();
    let (a_name, a_sec) = find(a).ok_or_else(|| anyhow!("'{a}' is not a known device (see: filament devices)"))?;
    let (b_name, b_sec) = find(b).ok_or_else(|| anyhow!("'{b}' is not a known device"))?;

    let my_uid = mk_uid("s");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    let solo = format!("intro-{}", fresh_secret());
    // C30: the session repairs whatever these emits lose — and under gate L
    // they are the emits the loss shim adversarially drops.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(solo.clone());
    sess.channels = vec![channel_of(&a_sec), channel_of(&b_sec)];
    sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
    sess.emit(&sio, "subscribe", json!({ "channels": [channel_of(&a_sec), channel_of(&b_sec)] })).await;
    ui::say(&format!("  waiting for {} and {} to be online…", ui::paint(ui::Tone::Bold, &a_name), ui::paint(ui::Tone::Bold, &b_name)));

    let mut conn = Conn {
        server: server.to_string(),
        sio: sio.clone(),
        tx: tx.clone(),
        my_uid: my_uid.clone(),
        my_id: String::new(),
        relay_only: relay,
        to_filter: None,
        links: HashMap::new(),
        roster: HashMap::new(),
        active: None,
        next_gen: 0,
        waiting_rejoin: None,
        rejoin_window: REJOIN_WINDOW,
        away: None,
        chunk_size: net::MAX_DC_PAYLOAD,
        deferred_left: HashMap::new(),
        recv_done: false,
    direct_pending: HashMap::new(),
    stall_repairs: HashMap::new(),
    relay_committed: std::collections::HashSet::new(),
    // P3 (GAP-3): warm redundancy is selective — OFF for one-shot / non-session
    // flows; the long-lived `up` acceptor turns it ON below. The override knob
    // (`FILAMENT_WARM_STANDBY`) can force it either way.
    warm_standby: net::warm_standby_override().unwrap_or(false),
    warm_cutover: std::collections::HashSet::new(),
    upgrade_probe: HashMap::new(),
    iface_snapshot: Vec::new(),
    };
    // sid -> which device (false = a, true = b)
    let mut who: HashMap<String, bool> = HashMap::new();
    let mut sent: [bool; 2] = [false, false];
    let fresh = fresh_secret();
    let deadline = Instant::now() + Duration::from_secs(120);

    loop {
        if Instant::now() > deadline {
            bail!("timed out — both devices must be online (e.g. running `filament up`)");
        }
        let ev = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead
        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                // C30 (dissolves the C28 belt): fresh sid — re-assert via session.
                sess.invalidate();
            }
            Ev::Synced(v) => { sess.on_synced(&v); }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own processes share these channels
                }
                let ch = v["channel"].as_str().unwrap_or_default().to_string();
                let pid = v["id"].as_str().unwrap_or_default().to_string();
                let is_b = if ch == channel_of(&a_sec) { false } else if ch == channel_of(&b_sec) { true } else { continue };
                conn.maybe_adopt(&v, false).await?;
                if let Some(l) = conn.link_mut(&pid) {
                    l.expected_secret = Some(if is_b { (b_name.clone(), b_sec.clone()) } else { (a_name.clone(), a_sec.clone()) });
                }
                who.insert(pid, is_b);
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                }
                let Some(&is_b) = who.get(&pid) else { continue };
                let (dev_name, sec) = if is_b { (&b_name, &b_sec) } else { (&a_name, &a_sec) };
                let other_name = if is_b { &a_name } else { &b_name };
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                        // prove ourselves, then vouch
                        t.send_control(&json!({
                            "type": "pair-proof",
                            "mac": proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                        })).await?;
                        t.send_control(&json!({
                            "type": "pair-intro", "name": other_name, "secret": fresh,
                        })).await?;
                        sent[is_b as usize] = true;
                        ui::say(&format!("  {} vouched to {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, dev_name)));
                    }
                }
                if sent[0] && sent[1] {
                    tokio::time::sleep(Duration::from_millis(800)).await; // let intros flush
                    ui::say(&format!(
                        "  {} {} and {} now know each other (no codes needed)",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        a_name, b_name,
                    ));
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
            }
            Ev::Stuck(pid, g) => { conn.on_stuck(&pid, g, "stuck").await?; }
            Ev::GraceExpired(pid, g) => { conn.on_stuck(&pid, g, "lost").await?; }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => { conn.on_peer_left(&v); }
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }
}

// ----------------------------------------------------------------- pair ----
// L1-a (PAKE v2): remembering a device is a first-class ceremony — no file
// transfer to pretend through. The first-pairing now runs a real SPAKE2 PAKE
// over the SPOKEN code so a malicious signaling server cannot MITM enrollment.
//
// The load-bearing change vs v1:
//   - The CLIENT mints the words locally (server sees only the numeric
//     nameplate); the password (words) NEVER reaches the server.
//   - SPAKE2 runs over the opaque `signal` relay BEFORE any secret exists.
//   - A key-confirmation MAC folds in the SORTED DTLS fingerprints + caps, so a
//     server that substitutes a DTLS cert OR rewrites caps is DETECTED → abort.
//   - The 32-byte pinned secret is HKDF(K) — AGREED, never transmitted. The old
//     `pair-keep` secret-over-DataChannel step is GONE from the v2 path.
//   - Downgrade is structurally impossible: a v2 client NEVER sends pair-keep
//     and NEVER stores a secret from a received pair-keep. A received pair-keep
//     means the peer is v1 → abort with "update to pair securely". A server
//     stripping `v:2` therefore cannot force the readable-secret path.
//
// Helpers below decode/encode the opaque PAKE payloads carried on `signal`.

/// Base64 (no external dep — small alphabet table). Used only for the 33-byte
/// SPAKE2 element / 32-byte MAC opaque payloads on the signal relay.
fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &c in chunk {
            n = (n << 6) | val(c)?;
            bits += 6;
        }
        n <<= 24 - bits;
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// The capability set v2 first-pairing agrees on. "transfer" is the L0 baseline
/// (always allowed); deny-by-default future caps are NOT granted at first
/// enrollment. BOTH sides MAC the identical canonical string or confirmation
/// fails — so this default is fixed and unconditional (spec §8 / gate 5).
fn pair_v2_caps() -> Vec<String> {
    vec!["transfer".to_string()]
}

async fn pair_cmd(server: &str, code: Option<String>, name: Option<String>, relay: bool) -> Result<()> {
    let my_uid = mk_uid("p");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    // Meta must exist for pairing; an unguessable solo room keeps strangers
    // out (the daemon's trick) — the pair-claim moves people, not the room.
    let solo = format!("pairc-{}", fresh_secret());
    // C30: the session repairs the solo-room membership/lease if the join dies.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(solo.clone());
    sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
    // Bug 4: a 3-segment legacy TRANSFER code (word-word-digits) typed into
    // `pair`, which expects a 4-segment PAKE pairing code — redirect clearly
    // before the PAKE handshake stalls forever against a peer that isn't pairing.
    if let Some(c) = &code {
        if regex_lite_code(c) && !looks_like_pake_code(c) {
            bail!(
                "'{c}' looks like a one-time TRANSFER code (from `filament send --code`), not a pairing code.\n  \
                 To receive that transfer: run `filament {c}` (or `filament recv {c}`)\n  \
                 A pairing code looks like `brave-otter-ruby-3141` (one more word)."
            );
        }
    }
    let creator = code.is_none();
    // L1-a: the spoken code is split CLIENT-SIDE into (nameplate, password). The
    // password (words) NEVER leaves this process; only the nameplate is sent.
    let mut my_words; // the password (creator mints; claimer types)
    let mut my_nameplate;
    match &code {
        Some(c) => {
            // Claimer: normalize the typed code, split, send ONLY the nameplate.
            let normalized = filament_pake::norm_code(c);
            let (np, pw) = filament_pake::split_code(&normalized);
            if pw.is_empty() || np.is_empty() {
                bail!("that code doesn't look right — expected something like brave-otter-ruby-3141");
            }
            my_words = pw;
            my_nameplate = np.clone();
            ui::say(&format!("  claiming {}…", ui::paint(ui::Tone::Brand, c)));
            sio.emit("pair-claim", json!({ "nameplate": np, "v": 2 })).await.ok();
        }
        None => {
            // Creator: mint words + nameplate locally; ask the server to allocate
            // ONLY the nameplate. The full code is displayed from our own mint
            // when pair-ok arrives (the server never echoes any words).
            my_words = filament_pake::words::mint_words();
            my_nameplate = filament_pake::words::mint_nameplate();
            sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 })).await.ok();
        }
    }

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid.clone(),
        relay,        // relay_only
        None,         // to_filter
        false,        // warm_standby default (pair is one-shot)
    );
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let mut petname = name; // resolved --name, prompt answer, or peer's display name
    let mut prompted = false;
    let mut peer: Option<(String, String)> = None; // (pid, display name)

    // ---- L1-a PAKE state ----------------------------------------------------
    // The agreed pinned secret (HKDF(K)); set ONLY after key confirmation passes.
    let mut agreed_secret: Option<String> = None;
    // Our live SPAKE2 session (consumed by finish) and our outbound element.
    let mut pake_state: Option<filament_pake::PakeState>;
    let mut pake_msg: Vec<u8>;
    // Derived K (after finishing on the peer's element). Held until confirmation.
    let mut pake_k: Option<Vec<u8>> = None;
    // Peer signaling sid we run the PAKE with (set when the link is adopted).
    let mut pake_peer: Option<String> = None;
    let mut sent_pake_msg = false;
    let mut sent_confirm = false;
    let caps = pair_v2_caps();
    let caps_canon = filament_pake::canonical_caps(&caps);

    // Start our SPAKE2 session immediately: identity = nameplate, password =
    // words. Both sides MUST pass identical Password AND Identity (spec §3.1).
    {
        let (st, msg) = filament_pake::start(my_words.as_bytes(), my_nameplate.as_bytes());
        pake_state = Some(st);
        pake_msg = msg;
    }
    let deadline = Instant::now() + Duration::from_secs(600); // code TTL
    // The pairing peer left before the ceremony finished. Give a short grace
    // for a transient reconnect, then FAIL FAST — don't orphan in the room
    // for the full 10-min TTL (the D3/D5 divergence the monitor kept
    // catching: creator's connect failed, it quit, claimer sat silent).
    // Once the code is CLAIMED, the ceremony must finish in seconds. Bound it:
    // if it hasn't completed within this budget, the peer disconnected or could
    // never connect — fail fast instead of orphaning in the room for the full
    // 600s TTL (the D3/D5 divergence the monitor kept catching). 60s is generous
    // (covers a slow cross-NAT WebRTC with its 3×15s establishment retries);
    // FILAMENT_PAIR_GRACE_SECS shortens it for gate 17b.
    let ceremony_budget = Duration::from_secs(
        std::env::var("FILAMENT_PAIR_GRACE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60),
    );
    let mut ceremony_deadline: Option<Instant> = None;
    // Gate 17b hook: connect but never complete, so the ceremony budget fires
    // deterministically (same-machine pairs otherwise finish in ~1s).
    let stall = test_hooks::pair_stall();

    loop {
        // Done when the petname is settled AND the PAKE agreed a secret (key
        // confirmation passed). The secret is HKDF(K) — never transmitted, the
        // same on both sides; it drops straight into devices.json.
        if let Some(n) = petname.clone() {
            if let Some(sec) = agreed_secret.clone() {
                // caps_v2 (spec §8): record GRANTED caps, deny-by-default.
                devices_store_v2(&n, &sec, &caps)?;
                ui::say(&format!(
                    "  {} {} mutually remembered — verified end-to-end (no key ever crossed the server)",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                    ui::paint(ui::Tone::Bold, &n),
                ));
                ui::say(&ui::paint(ui::Tone::Dim, &format!("  try: filament send <file> --to {n}   ·   filament up")));
                tokio::time::sleep(Duration::from_millis(300)).await; // let acks flush
                let _ = sio.disconnect().await;
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            bail!("timed out — the code was never used (codes expire after 10 minutes)");
        }
        // Fail fast: the code was claimed but the ceremony didn't finish in
        // time — the peer disconnected or never connected.
        if let Some(dl) = ceremony_deadline {
            if Instant::now() > dl {
                bail!("the other device disconnected or could not connect before pairing finished — make sure both run `filament pair` at the same time, then try again");
            }
        }
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead

        // ---- L1-a PAKE progression (runs every iteration) ------------------
        // 1) Once we know the peer's signaling sid, send our SPAKE2 element over
        //    the opaque `signal` relay (the server cannot read it).
        if let Some(pid) = pake_peer.clone() {
            // gate 17b (FILAMENT_TEST_PAIR_STALL): never send our SPAKE2 element,
            // so the exchange can't complete on either side and the ceremony's
            // fail-fast `ceremony_deadline` fires — proving the no-10-min-orphan
            // guard. Test-only: `stall` is set solely by that env var.
            if !sent_pake_msg && !stall {
                sio.emit("signal", json!({ "to": pid, "data": {
                    "type": "pake-msg", "v": 2, "msg": b64_encode(&pake_msg)
                }})).await.ok();
                sent_pake_msg = true;
            }
            // 2) Once K is derived AND both DTLS fingerprints are known, send the
            //    key-confirmation MAC over K + sorted fingerprints + caps. The MAC
            //    is gated on the fingerprints so a server that substitutes a DTLS
            //    cert produces a different fingerprint → the peer's verify fails.
            if !sent_confirm {
                if let Some(k) = pake_k.clone() {
                    if let Some(l) = conn.link(&pid) {
                        if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                            let mac = filament_pake::our_confirm(&k, &my_fp, &their_fp, &caps_canon);
                            sio.emit("signal", json!({ "to": pid, "data": {
                                "type": "pake-confirm", "v": 2,
                                "mac": b64_encode(&mac),
                                "caps": caps.clone(),
                            }})).await.ok();
                            sent_confirm = true;
                        }
                    }
                }
            }
        }

        let ev = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
                sess.invalidate(); // C30: fresh sid — re-assert next tick
            }
            Ev::Synced(v) => { sess.on_synced(&v); }
            Ev::PairOk(_v) => {
                // L1-a: the server allocated our nameplate. Display the FULL code
                // from OUR OWN local mint (the server never echoed any words).
                let full = format!("{my_words}-{my_nameplate}");
                ui::clipboard(&full);
                ui::say("");
                ui::say(&format!("      {}", ui::paint(ui::Tone::Brand, &full.to_uppercase())));
                ui::say("");
                ui::say(&ui::paint(ui::Tone::Dim, "  on the other device: type it into the web app, or `filament pair <code>`"));
                ui::say(&ui::paint(ui::Tone::Dim, "  one claim · expires in 10 min · paired end-to-end (no key crosses the server)"));
            }
            Ev::PairCode(v) => {
                // v1 server (shouldn't happen for a v2 create, but be safe): a
                // legacy server-minted code means the peer can't PAKE-pair.
                let c = v["code"].as_str().unwrap_or("?");
                let _ = c;
                bail!("this server returned a legacy code — update the server (or the peer) to pair securely");
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed — connecting…"));
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
            }
            Ev::PairMatched(v) => {
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
                ui::say(&format!("  {} code accepted — connecting", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                sess.room = Some(room.clone()); // C30: desire moves with us
                sess.touch();
                sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            }
            Ev::PairError(v) => {
                // Creator nameplate collision: re-mint a FRESH nameplate (and
                // fresh words) and retry — never reuse a burned code.
                if creator && v["error"].as_str() == Some("taken") {
                    my_words = filament_pake::words::mint_words();
                    my_nameplate = filament_pake::words::mint_nameplate();
                    let (st, msg) = filament_pake::start(my_words.as_bytes(), my_nameplate.as_bytes());
                    pake_state = Some(st);
                    pake_msg = msg;
                    sent_pake_msg = false;
                    sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 })).await.ok();
                    continue;
                }
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => "that code's creator already left — ask them for a fresh one".to_string(),
                    _ => format!("{} — codes burn after one use; a failed pairing needs a FRESH code (re-run `filament pair`)", v["error"].as_str().unwrap_or("?")),
                };
                bail!("code rejected: {hint}");
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, true).await?;
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // L1-a: PAKE messages ride the opaque `signal` relay. Branch them
                // OUT of the WebRTC signal path (SDP/ICE) into the PAKE machine.
                match data["type"].as_str() {
                    Some("pake-msg") => {
                        pake_peer.get_or_insert(from.clone());
                        if pake_k.is_none() {
                            if let Some(state) = pake_state.take() {
                                let peer_el = data["msg"].as_str().and_then(b64_decode).unwrap_or_default();
                                match filament_pake::finish(state, &peer_el) {
                                    Some(k) => pake_k = Some(k),
                                    None => bail!("pairing failed: malformed key-exchange message (abort)"),
                                }
                            }
                        }
                        continue;
                    }
                    Some("pake-confirm") => {
                        // Verify the peer's key-confirmation MAC under OUR K, folding
                        // the SORTED DTLS fingerprints + caps. Mismatch ⇒ wrong
                        // password OR a server that substituted a DTLS cert OR
                        // rewrote caps ⇒ ABORT, agree NOTHING.
                        let Some(k) = pake_k.clone() else {
                            bail!("pairing failed: confirmation arrived before key exchange (abort)");
                        };
                        let recv_mac = data["mac"].as_str().and_then(b64_decode).unwrap_or_default();
                        let fps = match conn.link(&from) {
                            Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                            None => None,
                        };
                        let Some((my_fp, their_fp)) = fps else {
                            bail!("pairing failed: no DTLS fingerprints to bind confirmation (abort)");
                        };
                        // We MAC against OUR fixed caps, so a server that rewrites the
                        // relayed `caps` field cannot make the MAC verify.
                        if filament_pake::verify_peer_confirm(&k, &my_fp, &their_fp, &caps_canon, &recv_mac) {
                            agreed_secret = Some(filament_pake::secret_from_k(&k));
                        } else {
                            bail!("pairing REFUSED: key confirmation failed — wrong code, or the connection is being tampered with (a server cannot forge this). Nothing was stored; ask for a FRESH code.");
                        }
                        continue;
                    }
                    _ => {}
                }
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            Ev::ChannelReady(pid, t) => {
                let display = match conn.link_mut(&pid) {
                    Some(l) => {
                        l.transport = Some(t.clone());
                        l.presence = Presence::Ready;
                        l.name.clone()
                    }
                    None => continue,
                };
                ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, &display)));
                peer = Some((pid.clone(), display.clone()));
                let _ = &t; // transport not used on the v2 path (no secret over DC)
                if stall {
                    continue; // gate 17b: connected, but deliberately never complete
                }
                // L1-a: the link is up and SDP fingerprints exist. Mark this peer
                // as our PAKE counterpart; the progression block (top of the loop)
                // sends our SPAKE2 element and, once K + fingerprints are known,
                // the key-confirmation MAC. NO secret is sent over the DataChannel.
                pake_peer.get_or_insert(pid.clone());
                // Settle the petname: --name wins; otherwise ask (tty) or
                // default to their display name (scripts, pipes).
                if petname.is_none() && !prompted {
                    prompted = true;
                    if std::io::stdin().is_terminal() {
                        eprint!("  remember this device as [{display}]: ");
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            use tokio::io::AsyncBufReadExt;
                            let mut line = String::new();
                            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
                            if reader.read_line(&mut line).await.is_ok() {
                                let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                            }
                        });
                    } else {
                        petname = Some(display.clone());
                    }
                }
            }
            Ev::StdinLine(line) => {
                if petname.is_none() && prompted {
                    let n = if line.is_empty() {
                        peer.as_ref().map(|(_, d)| d.clone()).unwrap_or_else(|| "device".into())
                    } else {
                        line
                    };
                    petname = Some(n);
                }
            }
            Ev::Control(pid, v) if stall => {
                let _ = (pid, v); // gate 17b: connected, but ignore all ceremony control
            }
            Ev::Control(_pid, v) => match v["type"].as_str() {
                // L1-a downgrade-refusal (spec §6.1): a v2 client NEVER stores a
                // secret handed over the DataChannel. Receiving a `pair-keep` means
                // the PEER is a legacy v1 client. We refuse — pairing securely
                // requires v2 on both ends. A malicious server stripping `v:2`
                // cannot exploit this: there is no path here that stores a
                // server-readable secret.
                Some("pair-keep") => {
                    bail!("the other device uses an older version and can't pair securely — update it (or this CLI) so first-pairing runs the encrypted handshake. Nothing was stored.");
                }
                _ => {}
            },
            Ev::Stuck(pid, g) => {
                conn.on_stuck(&pid, g, "stuck").await?;
            }
            Ev::GraceExpired(pid, g) => {
                conn.on_stuck(&pid, g, "lost").await?;
            }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => {
                // A faster, friendlier signal than the ceremony budget when it
                // arrives: the pairing peer left the room. (The budget is the
                // hard backstop — server peer-left can lag behind a hard kill.)
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                conn.on_peer_left(&v);
                let n = gone.unwrap_or_else(|| "the other device".into());
                ui::say(&ui::paint(ui::Tone::Dim, &format!("  {n} disconnected — waiting briefly in case it reconnects…")));
            }
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }
}

// ---------------------------------------------------------- link machinery --
// One peer at a time, but with the browser's survival rules: establishment
// watchdog (C3), disconnected-grace + ICE restart + reconnect attempts (C4),
// fresh ICE config per attempt (C5), uid supersede on rejoin (C6), and a
// rejoin window when the peer's socket dies entirely.

struct Link {
    /// WebRTC peer connection. `None` for a rung-1 direct link (no ICE/DTLS
    /// negotiation — it rides authenticated QUIC), so every WebRTC-only call
    /// site (`handle_signal`, `fingerprints`, `restart_ice`, the watchdog's
    /// `is_connected`) is reachable only when this is `Some`.
    peer: Option<Arc<Peer>>,
    info: Value, // {id,name,uid} as last seen — enough to re-establish
    name: String,
    uid: Option<String>,
    transport: Option<Arc<dyn Transport>>,
    generation: u32,
    attempts: u32,
    /// C12: proof-verified known device (per link, not global)
    trusted: bool,
    /// (name, secret) hypothesis to prove/verify on this link
    expected_secret: Option<(String, String)>,
    /// The devices.json PETNAME this link proved as (the cap-store key). Set on a
    /// verified `pair-proof` (WebRTC) or at birth for a direct link (already
    /// identity-bound). `None` until proven. Capability lookups (e.g. the `shell`
    /// gate) MUST key on this, NOT on `name` (a presence display string that may
    /// not match a stored record).
    verified_name: Option<String>,
    /// C26: what the status roster shows for this peer
    presence: Presence,
    /// rung-1 (FILAMENT_DIRECT): this link's transport is an authenticated direct
    /// QUIC connection — its pair-secret MAC already proved identity, so the
    /// post-channel DTLS pair-proof is skipped and the link is born trusted.
    direct: bool,
    /// Route label for a direct link (no WebRTC `route()` to query): `direct-quic`
    /// for rung-1, `holepunched` for rung-2. Ignored for WebRTC links.
    direct_route: &'static str,
}

/// C26: per-peer presence for the static status roster.
#[derive(Clone, Copy, PartialEq)]
enum Presence {
    Connecting,
    Ready,
    Away,
    Reconnecting,
}

fn presence_glyph(p: Presence) -> (&'static str, ui::Tone, &'static str) {
    match p {
        Presence::Ready => (ui::glyph_ok(), ui::Tone::Ok, ""),
        Presence::Away => ("●", ui::Tone::Warn, "away"),
        Presence::Reconnecting => ("◌", ui::Tone::Warn, "reconnecting…"),
        Presence::Connecting => ("◌", ui::Tone::Dim, "connecting…"),
    }
}

/// C18: browsers are mesh peers — they connect to EVERY room member. The CLI
/// must answer every offer politely or unanswered browsers wedge at
/// "connecting" (and their retry storms degrade the whole room). So: a links
/// MAP, every peer answered; SEND still aims transfers at one `active`
/// target; RECV accepts from any link, gated per-link by consent/trust.
const MAX_LINKS: usize = 16;

struct Conn {
    server: String,
    sio: rust_socketio::asynchronous::Client,
    tx: mpsc::UnboundedSender<Ev>,
    my_uid: String,
    my_id: String,
    relay_only: bool,
    to_filter: Option<String>,
    links: HashMap<String, Link>,
    roster: HashMap<String, Value>, // sid -> {id,name,uid} from welcome/peer-joined
    active: Option<String>,        // the transfer-target sid (send side)
    next_gen: u32,
    waiting_rejoin: Option<Instant>,
    /// How long the current rejoin window runs (set when it opens; depends on
    /// whether the peer declared `brb`).
    rejoin_window: Duration,
    /// (peer sid, until) — the peer told us it's stepping away (C21).
    away: Option<(String, Instant)>,
    chunk_size: usize,
    /// #28 (deferred drop): sids that got a peer-left while their data channel
    /// was still FLOWING. The signaling socket left the room, but the WebRTC
    /// link is independent and may be a cosmetic reconnect mid-transfer. We do
    /// NOT drop immediately (that kills a live transfer) and do NOT drop never
    /// (a hard-killed peer reads flowing for a beat and would strand the
    /// sender). Instead we stash the original peer-left payload here and
    /// re-check on every main-loop tick: once the link goes idle past the
    /// flowing threshold (or its channel is dead), we re-inject the stored
    /// peer-left so the normal handler runs verbatim — now dropping it. A live
    /// reconnect never goes idle (the transfer completes on it), so its entry
    /// is reaped harmlessly once done. Cleared in drop_link so a supersede of a
    /// deferred sid can't leave a stale blocker.
    deferred_left: HashMap<String, Value>,
    /// Gate-18 Mode B: set TRUE by the recv loop, each tick, exactly when the
    /// transfer is COMPLETE and nothing is in flight (`completed>0 &&
    /// by_sid.is_empty() && !keep_open`). When it holds, `on_stuck` DROPS a
    /// stuck/lost link instead of re-establishing it: there is nothing left to
    /// fetch, so reconnect attempts are pointless and a sender that departs
    /// AFTER delivering every byte would otherwise FLAP the link forever
    /// (establish → connect → die → Stuck → establish …), each cycle resetting
    /// `attempts` (so MAX_ATTEMPTS never caps it) and re-arming `expected_secret`
    /// (so `digest_says_alone` never holds) — `conn.links` never empties and the
    /// quiet-exit never fires → RC=124 hang. Dropping the link empties
    /// `conn.links` and lets the quiet-exit fire. Recomputed PER TICK (never
    /// sticky) so a mid-transfer link (`by_sid` non-empty) always reconnects
    /// normally — kill-resume (gate 2) and the #28 deferred-drop (gate 11c)
    /// reconnect paths are untouched. Defaults false, so the send-side and
    /// connecting-phase `on_stuck` callers are unaffected.
    recv_done: bool,
    /// rung-1 (FILAMENT_DIRECT): in-flight direct-QUIC attempts, keyed by peer
    /// sid. While an attempt is pending we do NOT establish WebRTC for that peer
    /// (sequential, per the design review — avoids two transports racing to
    /// ChannelReady). On deadline expiry with no DirectReady the entry is
    /// dropped and the normal WebRTC `establish` runs; the fallback is unchanged.
    direct_pending: HashMap<String, DirectPending>,
    /// P0 (GAP-1): per-peer stall-repair bookkeeping for the bytes-moved
    /// watchdog. Tracks how many correction-ladder repairs we've already run for
    /// the current stall episode (bounded by MAX_ATTEMPTS) and whether a repair
    /// is in flight, so a single stall can't re-fire the ladder every tick while
    /// a repair is converging. Reset once the link starts flowing again.
    stall_repairs: HashMap<String, StallState>,
    /// P1 (GAP-4): peers this session has COMMITTED to the relay route after the
    /// direct ladder exhausted (rung d). Once a pid is in here, we stop dialing /
    /// answering direct-QUIC for it (the direct path is what just failed and would
    /// only re-freeze, racing the relay link); all (re)establishment for it goes
    /// over relay-only WebRTC. Survives link drops (keyed by pid, not stored on the
    /// Link), so a re-establish never bounces back to the known-bad direct path.
    relay_committed: std::collections::HashSet<String>,
    /// P3 (GAP-3): the WARM-REDUNDANCY selectivity gate. TRUE only for long-lived
    /// / interactive sessions (the `up`/`up --shell` daemon acceptor; a transfer
    /// flagged interactive via `FILAMENT_WARM_STANDBY=1` standing in for a tunnel)
    /// — the sessions §2.4 says a mid-session drop is intolerable for. When set,
    /// `correct_stall` keeps the relay path as a pre-designated WARM standby and
    /// CUTS OVER to it on the FIRST stall (rung b) instead of grinding through the
    /// slow direct-repair rung (c)'s up-to-MAX_ATTEMPTS cold re-dials — so the
    /// failover is near-instant rather than a perceptible gap. FALSE for one-shot
    /// file `send` (the 90% case): the on-disk partial + C7 resume make the cold
    /// repair ladder correct and bounded, and a warm standby isn't worth a second
    /// socket / NAT mapping / keepalive for a single transfer (the honest cost
    /// tradeoff, §2.4 / §6). Defaulted by session kind at construction, overridable
    /// by `net::warm_standby_override()` (`FILAMENT_WARM_STANDBY`).
    warm_standby: bool,
    /// P3: per-peer warm-standby bookkeeping — peers whose relay standby has
    /// already been cut over to in the current stall episode, so a flapping relay
    /// path can't re-fire the instant cutover every tick (it falls through to the
    /// bounded relay-stalled `Exhausted` honesty instead). Cleared by
    /// `note_progress` once bytes move again.
    warm_cutover: std::collections::HashSet<String>,
    /// P5 (GAP-6): per-peer relay->direct UPGRADE-PROBE bookkeeping. Present only
    /// for peers currently committed to relay (`relay_committed`) on a session
    /// where the prober is eligible (warm_standby/daemon, relay permitted). Drives
    /// the backoff schedule (probe soon, then steady cadence) and the
    /// verify-before-upgrade window for a connected direct standby. Removed on a
    /// successful upgrade (cutover) or when the peer leaves.
    upgrade_probe: HashMap<String, UpgradeProbe>,
    /// P5: a snapshot of the local interface set (sorted IP strings) at the last
    /// probe schedule. A change (new/removed interface, wifi<->cellular,
    /// default-route move surfacing a new local IP) is the "walked home onto wifi"
    /// signal — we re-probe IMMEDIATELY. Polled cheaply each tick (no platform
    /// netlink dependency); the portable best-effort trigger the plan asks for.
    iface_snapshot: Vec<String>,
}

/// P0: one peer's stall-repair episode state.
#[derive(Default)]
struct StallState {
    /// Repairs attempted in the current episode (rung a is the first).
    attempts: u32,
    /// `true` between firing the ladder and the next observed byte of progress,
    /// so the per-tick watchdog doesn't re-arm while a repair is converging.
    pending: bool,
    /// P1 (GAP-4): `true` once this episode escalated to relay (rung d) and a
    /// FRESH relay WebRTC link is establishing (no transport yet). The new link
    /// isn't tracked by `direct_pending`, so without this latch `detect_stall`
    /// would keep seeing the (transport-less) link idle and re-fire the ladder
    /// into a premature `Exhausted` before relay even connects. Cleared by
    /// `note_progress` on the first byte over the relay path.
    relayed: bool,
}

/// P5 (GAP-6): one peer's relay->direct UPGRADE-PROBE state. Lifecycle:
///   IDLE   — armed (relay-committed); `next_at` is when the next probe fires,
///            `attempt` drives the exponential backoff (first_ms → steady_ms).
///   PROBING— a direct dial is in flight (a `DirectPending{probe:true}` exists);
///            we don't re-fire until it resolves (win → VERIFYING, or expiry →
///            back to IDLE with a longer backoff).
///   VERIFYING — a direct standby CONNECTED (`standby` set). It must move data
///            CONTINUOUSLY for `verify_ms` before we cut over; `verify_started`
///            marks when it connected. If it goes idle past `verify_idle_ms` or
///            never reaches `verify_ms` of sustained progress, it is DISCARDED
///            and we go back to IDLE (stay on relay — the no-flap guard).
struct UpgradeProbe {
    /// failed-probe count; each failure backs the cadence off toward steady_ms.
    attempt: u32,
    /// when the next probe may fire (None ⇒ probe ASAP, e.g. just armed or a
    /// network-change re-probe).
    next_at: Option<Instant>,
    /// the connected-but-unverified direct standby transport (VERIFYING state).
    standby: Option<Arc<dyn Transport>>,
    /// the route label of the standby (`direct-quic` / `holepunched`).
    standby_route: &'static str,
    /// when the standby connected — the start of the verify window.
    verify_started: Option<Instant>,
    /// the standby's `idle_ms()` floor observed so far in the verify window, used
    /// to require SUSTAINED progress (it must keep moving, not just connect).
    verify_last_idle: u64,
}

impl UpgradeProbe {
    fn armed() -> Self {
        UpgradeProbe {
            attempt: 0,
            next_at: None, // first probe is scheduled by the prober tick
            standby: None,
            standby_route: "direct-quic",
            verify_started: None,
            verify_last_idle: u64::MAX,
        }
    }
}

/// P0: which correction rung the stall ladder took (see `Conn::correct_stall`).
#[derive(Debug, PartialEq)]
enum Rung {
    /// (a) re-offer unfinished transfers on the SAME transport (resume:true).
    Resume,
    /// (c) the transport was repaired in place (fresh direct dial / ICE-restart).
    Repaired,
    /// (d) P1: direct rungs a→c spent → the link was RE-ESTABLISHED over the TURN
    /// relay (relay-only ICE), preserving the on-disk partial. The fresh relay
    /// transport's ChannelReady re-offers the unfinished transfers (resume:true)
    /// and prints the honest relay banner.
    Relayed,
    /// rungs a→d unavailable: direct rungs spent AND relay is forbidden
    /// (`--no-relay`) or we were already on relay. The caller FAILS CLEANLY — a
    /// kept partial, a clear error, never a hang.
    Exhausted,
}

/// rung-1: state for one in-flight direct-QUIC attempt.
struct DirectPending {
    /// (name, secret) for the known device — gates the attempt and keys the MAC.
    secret: (String, String),
    /// budget deadline; on expiry with no DirectReady we fall back to WebRTC.
    deadline: Instant,
    /// set once the peer's transport-offer arrived and we spawned the racer, so
    /// a duplicate offer doesn't spawn a second race.
    racing: bool,
    /// kept alive so the bound UDP port stays ours until the race consumes it.
    endpoint: Option<quinn::Endpoint>,
    /// rung-2 (FILAMENT_HOLEPUNCH): a SECOND raw UDP socket, already STUN'd, kept
    /// raw (not connected) so its NAT mapping is the one we punch + run QUIC on.
    /// Consumed by the chained ladder in `on_transport_offer` only if rung-1
    /// fails. None when hole-punch is off or STUN discovery failed.
    punch_sock: Option<std::net::UdpSocket>,
    /// rung-2: our advertised srflx (logged at offer time; kept for diagnostics).
    #[allow(dead_code)]
    my_srflx: Option<std::net::SocketAddr>,
    /// P5 (GAP-6): this is a relay->direct UPGRADE probe — a direct dial run
    /// ALONGSIDE a live relay link (not the cold establishment path). When the
    /// race wins, `on_transport_offer` posts `Ev::DirectUpgradeReady` (verify-
    /// before-upgrade) instead of `Ev::DirectReady` (which would clobber the
    /// serving relay link). When the budget expires with no winner, `expired_direct`
    /// just DROPS the pending (no WebRTC fallback — the relay link is still serving)
    /// and the prober schedules the next backoff.
    probe: bool,
}

impl Conn {
    /// Single constructor for the `pair`/`send`/`recv` command event loops, which
    /// built the identical ~17-field `Conn` literal three times (the only
    /// per-command differences are `relay_only`, `to_filter`, and the
    /// warm-standby default). Everything else is the fixed fresh-session state.
    /// `warm_standby_default` is the per-session-kind default that the
    /// `FILAMENT_WARM_STANDBY` override (via `net::warm_standby_override`) can
    /// still force either way. NOTE: the long-lived `up` daemon loop keeps its
    /// own literal on purpose — it is a different (non-command) session.
    fn for_command(
        server: &str,
        sio: rust_socketio::asynchronous::Client,
        tx: mpsc::UnboundedSender<Ev>,
        my_uid: String,
        relay_only: bool,
        to_filter: Option<String>,
        warm_standby_default: bool,
    ) -> Self {
        Conn {
            server: server.to_string(),
            sio,
            tx,
            my_uid,
            my_id: String::new(),
            relay_only,
            to_filter,
            links: HashMap::new(),
            roster: HashMap::new(),
            active: None,
            next_gen: 0,
            waiting_rejoin: None,
            rejoin_window: REJOIN_WINDOW,
            away: None,
            chunk_size: net::MAX_DC_PAYLOAD,
            deferred_left: HashMap::new(),
            recv_done: false,
            direct_pending: HashMap::new(),
            stall_repairs: HashMap::new(),
            relay_committed: std::collections::HashSet::new(),
            // P3 (GAP-3): warm redundancy is selective; the caller passes the
            // per-session default and the override knob can still force either way.
            warm_standby: net::warm_standby_override().unwrap_or(warm_standby_default),
            warm_cutover: std::collections::HashSet::new(),
            upgrade_probe: HashMap::new(),
            iface_snapshot: Vec::new(),
        }
    }

    fn link(&self, pid: &str) -> Option<&Link> {
        self.links.get(pid)
    }
    fn link_mut(&mut self, pid: &str) -> Option<&mut Link> {
        self.links.get_mut(pid)
    }
    fn active_link(&self) -> Option<&Link> {
        self.active.as_ref().and_then(|a| self.links.get(a))
    }
    fn is_active(&self, pid: &str) -> bool {
        self.active.as_deref() == Some(pid)
    }
    fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.active_link().and_then(|l| l.transport.clone())
    }
    fn transport_of(&self, pid: &str) -> Option<Arc<dyn Transport>> {
        self.links.get(pid).and_then(|l| l.transport.clone())
    }

    /// #28: is the link keyed by `pid` actively moving transfer bytes right now?
    /// The data channel is independent of the signaling socket, so when a
    /// same-uid reconnect arrives as a new sid, superseding must NOT tear down
    /// an old link that's still flowing. A frozen-alive peer (gate 11's
    /// SIGSTOP'd receiver) stops stamping activity, so it reads as not-flowing
    /// and the supersede proceeds as before. Threshold is overridable for
    /// deterministic gating (FILAMENT_ADOPT_ACTIVE_MS); the 3 s default sits
    /// well above a healthy sub-100 ms inter-frame gap so a transient ICE blip
    /// can't masquerade as idle and let a spurious supersede through.
    fn link_flowing(&self, pid: &str) -> bool {
        let threshold = std::env::var("FILAMENT_ADOPT_ACTIVE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3000);
        self.transport_of(pid)
            .map(|t| t.idle_ms() < threshold)
            .unwrap_or(false)
    }

    /// May this peer become the TRANSFER TARGET? (Filters gate targeting,
    /// never answering — every peer still gets a polite link.)
    fn targetable(&self, name: &str, peer_uid: Option<&str>) -> bool {
        if let Some(filter) = &self.to_filter {
            if !name.to_lowercase().contains(&filter.to_lowercase()) {
                return false;
            }
        }
        // Same-role CLI peers never transfer to each other (gate 7).
        if let (Some(pu), Some(my_role)) = (peer_uid, self.my_uid.get(..6)) {
            if pu.starts_with(my_role) {
                return false;
            }
        }
        true
    }

    /// Track a roster entry and (re)connect to it. `want_active` marks it as
    /// the intended transfer target if it passes the target filters and no
    /// target exists yet. Returns true if this peer is (now) the active one.
    async fn maybe_adopt(&mut self, v: &Value, want_active: bool) -> Result<bool> {
        let peer_id = v["id"].as_str().unwrap_or_default().to_string();
        let peer_uid = v["uid"].as_str().map(|s| s.to_string());
        let name = v["name"].as_str().unwrap_or("peer").to_string();
        if peer_id.is_empty() || peer_id == self.my_id {
            return Ok(false);
        }
        // NOTE: same-install peers (our own daemon) are filtered at the
        // KnownPeer call sites, NOT here — room discovery must keep working
        // between two processes of one machine (loopback self-send is the
        // first thing every new user tries).
        self.roster.insert(peer_id.clone(), v.clone());

        // C6: same device on a NEW sid — supersede the stale link.
        let stale: Option<String> = self
            .links
            .iter()
            .find(|(sid, l)| l.uid.is_some() && l.uid == peer_uid && **sid != peer_id)
            .map(|(sid, _)| sid.clone());
        if let Some(old_sid) = stale {
            // #28: the same device reconnected its signaling socket (fresh sid).
            // If its existing data channel is still flowing, the reconnect is
            // cosmetic — superseding would tear down an active transfer. Keep the
            // old link; once it goes idle a later roster/presence event supersedes.
            if self.link_flowing(&old_sid) {
                // Observable so a gate can assert the keep happened (true
                // positive), not merely that no supersede line appeared.
                ui::debug(&format!("{name} reconnected — keeping active link"));
                return Ok(self.is_active(&old_sid));
            }
            ui::debug(&format!("{name} reconnected — superseding old link"));
            let was_active = self.is_active(&old_sid);
            let secret = self.links.get(&old_sid).and_then(|l| l.expected_secret.clone());
            self.drop_link(&old_sid);
            self.establish(v.clone()).await?;
            if let Some(l) = self.links.get_mut(&peer_id) {
                l.expected_secret = secret;
            }
            if was_active {
                self.active = Some(peer_id.clone());
            }
            return Ok(self.is_active(&peer_id));
        }

        if !self.links.contains_key(&peer_id) {
            if self.links.len() >= MAX_LINKS {
                return Ok(false);
            }
            self.establish(v.clone()).await?;
        }
        // #28: a deferred-active slot is claimable. When the active link got a
        // peer-left but is still flowing, we keep `active` pointing at it (so a
        // same-uid reconnect's supersede still sees it active, and the live
        // transfer's offer/exit machinery is undisturbed). But a DIFFERENT-uid
        // replacement (gate 2: hard-killed receiver, fresh recv) must still be
        // able to take over — otherwise the deferred link squats the slot until
        // the reap, and the replacement (whose ChannelReady already fired) never
        // gets promoted or offered the file. Treating a deferred active as
        // "claimable" promotes the replacement at peer-joined, before its
        // ChannelReady, so the offer goes out on the same baseline path.
        let active_deferred = self
            .active
            .as_ref()
            .is_some_and(|a| self.deferred_left.contains_key(a));
        if want_active && (self.active.is_none() || active_deferred) && self.targetable(&name, peer_uid.as_deref()) {
            // Claiming the slot from a deferred link: discharge that link now
            // (it left the room and is being replaced) so reap doesn't later
            // re-inject a stale peer-left against the slot the new peer holds.
            if active_deferred {
                if let Some(old) = self.active.clone() {
                    if old != peer_id {
                        self.drop_link(&old);
                    }
                }
            }
            self.active = Some(peer_id.clone());
            self.waiting_rejoin = None;
        }
        Ok(self.is_active(&peer_id))
    }

    fn drop_link(&mut self, pid: &str) {
        // #28: dropping a link also discharges any deferred peer-left for it —
        // so a supersede (maybe_adopt) of a deferred same-uid sid can't leave a
        // stale entry blocking adoption. Invariant: deferred_left only ever
        // holds sids that are still live links.
        self.deferred_left.remove(pid);
        if let Some(old) = self.links.remove(pid) {
            // Never await close in the event loop (F8): mark + spawn. A direct
            // link has no WebRTC peer; dropping the Link drops its QUIC transport
            // (the keepalive task observes conn.closed() and tears down).
            if let Some(p) = old.peer.clone() {
                p.mark_closed();
                tokio::spawn(async move { p.close().await });
            }
        }
        if self.is_active(pid) {
            self.active = None;
        }
    }

    async fn establish(&mut self, info: Value) -> Result<()> {
        self.establish_as(info, None).await
    }

    /// `force_polite: Some(true)` builds a pure responder link (no local offer)
    /// regardless of uid comparison — required when the link exists to ANSWER
    /// an incoming offer (ensure_responder / glare rebuild). The uid-based role
    /// can come out impolite there (especially on the bare `{id}` roster-miss
    /// fallback, which compares sids), making the "responder" offer too: glare.
    async fn establish_as(&mut self, info: Value, force_polite: Option<bool>) -> Result<()> {
        let peer_id = info["id"].as_str().unwrap_or_default().to_string();
        // rung-1: a direct-QUIC attempt owns this peer until its budget expires.
        // Suppress the WebRTC offer so the path stays SEQUENTIAL (no two
        // transports racing to ChannelReady). `expired_direct` removes the
        // pending before calling us for the fallback, so this never blocks it.
        if self.direct_pending.contains_key(&peer_id) {
            return Ok(());
        }
        // P1 (GAP-4): once a peer is committed to relay, a live link already
        // carries (or is converging on) the relay route. Re-establish events
        // (KnownPeer re-announce, expired_direct fallback, a watchdog tick) must
        // NOT tear it down and rebuild mid-handshake — that thrash is exactly why
        // the relay link got "stuck while connecting". A genuinely failed link is
        // removed by the normal drop path (on_pc_state/GraceExpired) FIRST, so when
        // no link is present here we DO proceed to (re)build the relay link.
        if self.relay_committed.contains(&peer_id) && self.links.contains_key(&peer_id) {
            return Ok(());
        }
        self.drop_link(&peer_id); // re-establish replaces any same-sid link
        let peer_uid = info["uid"].as_str().map(|s| s.to_string());
        let name = info["name"].as_str().unwrap_or("peer").to_string();
        // C5: fresh ICE config (TURN creds are expiry-stamped HMACs) for
        // every attempt, not just the first.
        let mut cfg = net::fetch_config(&self.server).await?;
        self.chunk_size = cfg.chunk_size;
        let polite = force_polite.unwrap_or_else(|| {
            net::polite_role(&self.my_uid, peer_uid.as_deref(), &self.my_id, &peer_id)
        });
        self.next_gen += 1;
        let generation = self.next_gen;
        // P1 relay-fallback gate (test-only): FILAMENT_TEST_WEBRTC_RELAY_ONLY=1
        // models a peer with NO direct WebRTC path (hard NAT) — every WebRTC link
        // is relay-only, so when the direct-QUIC ladder freezes/exhausts the
        // transfer can ONLY complete over the TURN relay. Faithful to the real
        // "direct can't, relay can" condition the auto-fallback exists for; never a
        // product knob. OR'd with the real relay_only (set by --relay or by an
        // auto escalate_to_relay).
        let relay_ice = self.relay_only || test_hooks::webrtc_relay_only();
        // P1 (GAP-4): --no-relay is a HARD direct-only promise — never traverse a
        // relay. Strip TURN servers from the ICE config so no relay candidate can
        // ever be gathered. A peer reachable ONLY via relay then simply fails to
        // connect — honestly, by the user's own choice — instead of silently using
        // a middleman. (The ICE policy is left as-is: a relay-only policy with no
        // relay servers has no candidates and fails cleanly, which is the point.)
        if relay_forbidden() {
            cfg.ice_servers.retain(|s| net::is_stun_only(s));
        }
        let peer = Peer::connect(
            peer_id.clone(),
            polite,
            cfg.ice_servers,
            relay_ice,
            self.sio.clone(),
            self.tx.clone(),
            generation,
        )
        .await?;
        self.links.insert(
            peer_id,
            Link {
                peer: Some(peer),
                info,
                name,
                uid: peer_uid,
                transport: None,
                generation,
                attempts: 0,
                trusted: false,
                expected_secret: None,
                verified_name: None,
                presence: Presence::Connecting,
                direct: false,
                direct_route: "direct-quic", // unused for WebRTC links (peer.is_some())
            },
        );
        Ok(())
    }

    // --- rung-1 direct-QUIC path (FILAMENT_DIRECT) ---------------------------
    //
    // Sequential by design: when both peers are CLIs and a pair secret is known,
    // try a direct authenticated QUIC connection FIRST and only fall back to the
    // WebRTC `establish` above if no authenticated connection lands within the
    // budget. The whole thing is gated on `direct::direct_enabled()`, so with the
    // flag OFF none of this runs and the WebRTC path is byte-for-byte unchanged.

    /// Begin a direct attempt against `pid`: bind a quinn endpoint, advertise our
    /// candidates via a relayed `transport-offer`, and stash the pending state.
    /// No Link is created yet — it is born (with `peer: None`, pre-trusted) only
    /// when an authenticated connection wins (Ev::DirectReady). Idempotent per
    /// peer (a second call while pending is a no-op). The peer's own
    /// transport-offer (Ev::TransportOffer) drives the race.
    async fn start_direct(&mut self, pid: &str, name: &str, secret: &str) {
        self.start_direct_inner(pid, name, secret, false).await
    }

    /// P5 (GAP-6): arm a relay->direct UPGRADE probe — a direct dial run
    /// ALONGSIDE the live relay link. Bypasses the `relay_committed` /
    /// already-linked early-returns of `start_direct` (the whole POINT is to dial
    /// direct while a relay link serves), and marks the `DirectPending` as a
    /// probe so the winner posts `Ev::DirectUpgradeReady` (verify-before-upgrade)
    /// rather than clobbering the serving relay link. A no-op if a probe is
    /// already in flight for this peer.
    async fn start_upgrade_probe(&mut self, pid: &str, name: &str, secret: &str) {
        // A probe already in flight (its own DirectPending) — don't double-dial.
        if self.direct_pending.contains_key(pid) {
            return;
        }
        self.start_direct_inner(pid, name, secret, true).await
    }

    async fn start_direct_inner(&mut self, pid: &str, name: &str, secret: &str, probe: bool) {
        if !direct::direct_enabled() {
            return;
        }
        if !probe && self.relay_committed.contains(pid) {
            // P1: this peer escalated to relay — never re-dial direct (it would
            // only re-freeze and race the relay link). If a link already exists
            // (the relay link that escalate_to_relay built, possibly still
            // converging), DON'T rebuild it — repeated KnownPeer/`appeared` events
            // would otherwise tear it down and re-establish mid-handshake, so it
            // never connects ("stuck while connecting"). Only (re)establish over
            // relay when there is no link at all to carry the session.
            // P5 (GAP-6): a `probe` deliberately bypasses this guard — it dials
            // direct ALONGSIDE the serving relay link (warm direct standby) and
            // never touches `links`, so it cannot disturb the relay path.
            if !self.links.contains_key(pid) {
                let info = json!({ "id": pid, "name": name });
                let _ = self.establish(info).await;
            }
            return;
        }
        // A probe expects a relay link to be present (it's the one we'd upgrade
        // AWAY from); only the cold path bails when a link already exists.
        if self.direct_pending.contains_key(pid) || (!probe && self.links.contains_key(pid)) {
            return; // already trying, or already linked (WebRTC or direct)
        }
        let (ep, port) = match direct::bind_endpoint() {
            Ok(v) => v,
            Err(e) => {
                ui::trace(&format!("filament: direct disabled (endpoint bind failed: {e})"));
                return;
            }
        };
        let cands = direct::gather_candidates(&self.server, port).await;

        // rung-2 (FILAMENT_HOLEPUNCH): bind a SECOND raw socket and STUN it so we
        // can advertise a server-reflexive candidate. This socket is kept RAW
        // (not handed to quinn) — its NAT mapping is the one we'll punch + run
        // QUIC on if rung-1's host-candidate race fails. STUN failure is graceful:
        // no srflx is advertised and rung-2 simply won't fire for this peer.
        let (punch_sock, my_srflx) = if holepunch::holepunch_enabled() {
            match self.gather_srflx().await {
                Some((sock, srflx)) => (Some(sock), Some(srflx)),
                None => (None, None),
            }
        } else {
            (None, None)
        };

        // transport-offer rides the OPAQUE signaling relay (same channel as ICE
        // signals); the server cannot read or forge it without failing the MAC.
        let mut offer = json!({ "type": "transport-offer", "v": 1, "addrs": cands });
        if let Some(s) = my_srflx {
            offer["srflx"] = json!(s.to_string());
        }
        // P5 (GAP-6): tag a probe offer so the PEER races it as an upgrade probe
        // too — its winning side then posts Ev::DirectUpgradeReady (verify-before-
        // upgrade) instead of clobbering ITS serving relay link. Both ends must
        // treat the new direct path as a standby until verified, or one end would
        // tear down its relay link unilaterally.
        if probe {
            offer["probe"] = json!(true);
        }
        let _ = self
            .sio
            .emit("signal", json!({ "to": pid, "data": offer.clone() }))
            .await;
        // TRACE — direct-offer / signaling detail.
        ui::trace(&format!(
            "filament: {} sent to {name} ({pid}) — port {} srflx {}",
            if probe { "UPGRADE-PROBE-OFFER" } else { "DIRECT-OFFER" },
            port,
            my_srflx.map(|s| s.to_string()).unwrap_or_else(|| "-".into())
        ));
        // Re-send the offer periodically. The L2 initiator (netcat/ssh) subscribes
        // to the channel AFTER us, so on a late join it can miss BOTH our single
        // fire-once offer AND its own KnownPeer for us (presence delivery is racy)
        // — the cross-machine stall. Re-emitting lets it catch a later offer and
        // dial our (reachable) candidates; the initiator only races the FIRST
        // offer it gets, so the extra emits are harmless once linked.
        {
            let sio = self.sio.clone();
            let pid_c = pid.to_string();
            tokio::spawn(async move {
                for _ in 0..6 {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    let _ = sio
                        .emit("signal", json!({ "to": pid_c, "data": offer.clone() }))
                        .await;
                }
            });
        }
        // The WebRTC fallback reaper (`expired_direct`) fires at this deadline.
        // rung-1's race always burns the full DIRECT_BUDGET when it can't win
        // (its acceptor future never self-completes), so with hole-punch enabled
        // the deadline MUST cover the WHOLE ladder — rung-1 budget + punch budget
        // + QUIC handshake slack — or the reaper would race WebRTC against an
        // in-flight punch and the route would be a coin flip. Flag-gated, so
        // rung-1-only timing is byte-identical.
        let deadline = if holepunch::holepunch_enabled() {
            Instant::now() + direct::DIRECT_BUDGET + holepunch::PUNCH_BUDGET + Duration::from_secs(3)
        } else {
            Instant::now() + direct::DIRECT_BUDGET
        };
        self.direct_pending.insert(
            pid.to_string(),
            DirectPending {
                secret: (name.to_string(), secret.to_string()),
                deadline,
                racing: false,
                endpoint: Some(ep),
                punch_sock,
                my_srflx,
                probe,
            },
        );
    }

    /// rung-2: bind a raw punch socket and discover its srflx via STUN against
    /// the ICE config's STUN server. Returns (raw socket, srflx) or None.
    async fn gather_srflx(&self) -> Option<(std::net::UdpSocket, std::net::SocketAddr)> {
        let cfg = net::fetch_config(&self.server).await.ok()?;
        let stun_urls: Vec<String> = cfg
            .ice_servers
            .iter()
            .flat_map(|s| s.urls.iter().cloned())
            .collect();
        let stun_addr = holepunch::stun_server_addr(&stun_urls)?;
        let sock = holepunch::bind_punch_socket().ok()?;
        // STUN is blocking UDP I/O — run it off the reactor.
        tokio::task::spawn_blocking(move || {
            holepunch::stun_srflx(&sock, stun_addr).map(|srflx| (sock, srflx))
        })
        .await
        .ok()?
        .ok()
    }

    /// The peer advertised its candidates. If we have a matching pending attempt
    /// and haven't started the race yet, consume the endpoint and spawn the
    /// simultaneous-open + auth race; the winner posts Ev::DirectReady (or, for an
    /// upgrade probe, Ev::DirectUpgradeReady — verify-before-upgrade).
    fn on_transport_offer(&mut self, pid: &str, peer_cands: Vec<String>, peer_srflx: Option<String>) {
        let Some(p) = self.direct_pending.get_mut(pid) else { return };
        if p.racing {
            return;
        }
        let Some(ep) = p.endpoint.take() else { return };
        p.racing = true;
        let secret = p.secret.1.clone();
        // P5 (GAP-6): is THIS the upgrade-probe pending? Then the winner posts
        // DirectUpgradeReady (verify-before-upgrade) so the serving relay link is
        // never clobbered. A cold pending posts DirectReady as before.
        let is_probe = p.probe;
        // rung-2: hand the punch socket + peer's srflx to the chained ladder.
        let punch_sock = p.punch_sock.take();
        let peer_srflx_addr = peer_srflx
            .as_deref()
            .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
        let tx = self.tx.clone();
        let pid_s = pid.to_string();
        let mk = move |pid: String, t: Arc<dyn Transport>, route: &'static str| {
            if is_probe {
                Ev::DirectUpgradeReady(pid, t, route)
            } else {
                Ev::DirectReady(pid, t, route)
            }
        };
        tokio::spawn(async move {
            // rung-1: direct-dial QUIC over host candidates (UNCHANGED).
            if let Some(t) =
                direct::race_connect(ep, peer_cands, &secret, pid_s.clone(), tx.clone()).await
            {
                let _ = tx.send(mk(pid_s, t, "direct-quic"));
                return;
            }
            // rung-2: UDP hole-punch, then rung-1's QUIC race over the punched
            // socket. Only fires with the flag on, a punch socket bound, and a
            // peer srflx to punch toward. On failure (e.g. symmetric NAT) we fall
            // through to the WebRTC step-down via the per-tick reaper.
            if holepunch::holepunch_enabled() {
                if let (Some(sock), Some(peer_srflx)) = (punch_sock, peer_srflx_addr) {
                    // TRACE — direct/hole-punch detail.
                    ui::trace(&format!("filament: rung-1 failed — attempting hole-punch to {peer_srflx}"));
                    if let Some(t) = holepunch::connect(
                        sock,
                        peer_srflx,
                        &secret,
                        pid_s.clone(),
                        tx.clone(),
                    )
                    .await
                    {
                        let _ = tx.send(mk(pid_s, t, "holepunched"));
                        return;
                    }
                }
            }
            // On None the per-tick reaper handles the WebRTC fallback at deadline.
        });
    }

    /// P5 (GAP-6): a relay-committed peer received an UPGRADE-PROBE transport-
    /// offer (`probe:true`) from the other end while we have no probe pending of
    /// our own yet. ARM a matching upgrade probe so the symmetric direct dial can
    /// complete (both ends must offer their candidates for the QUIC simultaneous-
    /// open race). Only fires for a peer we are actually serving on relay
    /// (`relay_committed` + a live link) and only when the prober is enabled and
    /// relay isn't forbidden — otherwise the probe offer is ignored.
    async fn answer_upgrade_probe(&mut self, pid: &str) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        if !self.relay_committed.contains(pid) || !self.links.contains_key(pid) {
            return;
        }
        if self.direct_pending.contains_key(pid) {
            return; // our own probe is already in flight — its race will consume the offer
        }
        let known = self.links.get(pid).and_then(|l| l.expected_secret.clone());
        if let Some((name, secret)) = known {
            self.start_upgrade_probe(pid, &name, &secret).await;
        }
    }

    /// Create the Link for a direct connection that won the race. `peer: None`
    /// (no WebRTC), `direct: true`, `trusted: true` (the pair-secret MAC already
    /// proved identity — at least as strong as the DTLS pair-proof it replaces).
    fn adopt_direct(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let pend = self.direct_pending.remove(pid);
        let (name, secret) = match pend {
            Some(p) => p.secret,
            None => ("peer".to_string(), String::new()),
        };
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": name }));
        let uid = info["uid"].as_str().map(|s| s.to_string());
        let expected_secret = if secret.is_empty() {
            None
        } else {
            Some((name.clone(), secret))
        };
        self.next_gen += 1;
        let generation = self.next_gen;
        self.links.insert(
            pid.to_string(),
            Link {
                peer: None,
                info,
                name,
                uid,
                transport: Some(t),
                generation,
                attempts: 0,
                trusted: true,
                // A direct link is born identity-bound (its pair-secret MAC
                // already proved who it is), so the petname is known up front.
                verified_name: expected_secret.as_ref().map(|(n, _)| n.clone()),
                expected_secret,
                presence: Presence::Ready,
                direct: true,
                direct_route: route,
            },
        );
    }

    /// Per-tick: a direct attempt whose budget expired without an authenticated
    /// connection falls back to the WebRTC `establish` (unchanged). Returns the
    /// list of (pid, info) to establish — caller awaits establish outside the
    /// borrow. Also drops any pending whose Link already exists.
    fn expired_direct(&mut self) -> Vec<(String, Value, (String, String))> {
        let now = Instant::now();
        let mut fell_back = Vec::new();
        // P5 (GAP-6): an UPGRADE-PROBE pending whose budget expired with no winner
        // must NOT fall back to WebRTC — the relay link is still serving and the
        // whole point of the probe was to find a DIRECT path. Just DROP it and let
        // the prober's backoff schedule the next attempt (mark_probe_failed). The
        // cold (non-probe) pendings keep their existing WebRTC-fallback behavior.
        let expired_probes: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(_, p)| p.probe && now >= p.deadline)
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired_probes {
            self.direct_pending.remove(&pid);
            // DEBUG — resilience internal (upgrade probe found no path).
            ui::debug(&format!("filament: UPGRADE-PROBE for {pid} found no direct path in budget — staying on relay"));
            self.mark_probe_failed(&pid);
        }
        let expired: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| !p.probe && now >= p.deadline && !self.links.contains_key(*pid))
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired {
            if let Some(p) = self.direct_pending.remove(&pid) {
                let info = self
                    .roster
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| json!({ "id": pid, "name": p.secret.0 }));
                // DEBUG — resilience internal (direct→WebRTC fallback).
                ui::debug(&format!(
                    "filament: DIRECT-FALLBACK for {} — no authenticated QUIC in budget, using WebRTC",
                    p.secret.0
                ));
                fell_back.push((pid, info, p.secret));
            }
        }
        // Drop pendings whose link landed by another route (cleanup). P5 (GAP-6):
        // EXCLUDE upgrade probes — a probe pending ALWAYS coexists with the serving
        // relay link (that's the point), so this cleanup must not reap it before its
        // race runs; a probe is reaped only by its own deadline (above) or by the
        // upgrade cutover consuming it.
        let linked: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| !p.probe && self.links.contains_key(*pid))
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in linked {
            self.direct_pending.remove(&pid);
        }
        fell_back
    }

    /// C3/C4: watchdog or grace expiry — retry that LINK with fresh config,
    /// up to MAX_ATTEMPTS, then drop it. Returns true when the exhausted link
    /// was the active transfer target (send decides whether that is fatal).
    async fn on_stuck(&mut self, pid: &str, generation: u32, why: &str) -> Result<bool> {
        // C21: don't burn retry attempts against a peer that told us it's
        // away — re-dialing a suspended tab is wasted attrition.
        if self.is_away(pid) {
            return Ok(false);
        }
        let Some(l) = self.links.get(pid) else { return Ok(false) };
        // rung-1: a direct link has no WebRTC watchdog (no Peer::connect timer),
        // so on_stuck can't fire for it; defensively no-op if it ever does.
        if l.direct {
            return Ok(false);
        }
        if l.generation != generation || l.peer.as_ref().map(|p| p.is_connected()).unwrap_or(true) {
            return Ok(false); // stale timer from a superseded attempt
        }
        // Gate-18 Mode B: the transfer is COMPLETE (recv_done; recomputed per
        // tick by the recv loop, so this can only be true with by_sid empty and
        // !keep_open) and this link just went stuck/lost. Reconnecting would
        // fetch nothing and merely FLAP the link — resetting attempts and
        // re-arming expected_secret each cycle — so conn.links never empties and
        // the quiet-exit can't fire (RC=124 hang under contention). DROP it
        // instead: links empties, quiet-exit fires. Fenced to complete-only, so
        // a mid-transfer link (recv_done=false) reconnects normally (gate 2/11c).
        // FILAMENT_TEST_DISABLE_MODEB_DROP reverts to the old reconnect-always
        // behaviour so the gate proves A/B with ONE binary: baseline (toggle set)
        // hangs to RC=124 under the churn hook; fix (toggle unset) exits cleanly.
        if self.recv_done && !test_hooks::disable_modeb_drop() {
            let was_active = self.is_active(pid);
            ui::debug(&ui::paint(ui::Tone::Dim, &format!("dropping peer (connection {why} after completion — nothing left to fetch)")));
            self.drop_link(pid);
            return Ok(was_active);
        }
        let attempts = l.attempts + 1;
        if attempts >= MAX_ATTEMPTS {
            let was_active = self.is_active(pid);
            ui::debug(&ui::paint(ui::Tone::Dim, &format!("dropping peer (connection {why} after {attempts} attempts)")));
            self.drop_link(pid);
            return Ok(was_active);
        }
        // DEBUG — resilience internal (link retry).
        ui::debug(&format!("connection {why} — retrying ({}/{})", attempts + 1, MAX_ATTEMPTS));
        let info = l.info.clone();
        let secret = l.expected_secret.clone();
        // C26: a link that was ever up is *re*connecting; one that never
        // connected is still just connecting — keeps "recovered" honest.
        let prev = match l.presence {
            Presence::Connecting => Presence::Connecting,
            _ => Presence::Reconnecting,
        };
        let was_active = self.is_active(pid);
        self.establish(info).await?;
        if let Some(nl) = self.links.get_mut(pid) {
            nl.attempts = attempts;
            nl.expected_secret = secret;
            nl.presence = prev;
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        Ok(false)
    }

    // --- P0 (GAP-1): the bytes-moved STALL watchdog + correction ladder ------
    //
    // The single byte-flow primitive `Transport::idle_ms()` already exists
    // (net.rs) and is stamped at the unambiguous "a data byte moved" point on
    // both send and receive. #28 wired it ONLY to the supersede decision; this
    // is the second consumer the audit calls the core gap: a watchdog that
    // declares an OPEN, ALIVE link bad when an in-flight transfer moves zero
    // bytes — the "stuck at 0%" hang — and drives the least-disruptive
    // correction. Run from the main event loop's tick (no new concurrency: F8).

    /// Per-tick check: if a transfer is in flight (`in_flight`) on a link whose
    /// `idle_ms()` has crossed the stall threshold, return its (pid, idle_ms) so
    /// the loop can emit `Ev::TransferStalled`. Returns `None` for a flowing or
    /// idle-but-empty link. Resetting bookkeeping on observed progress lives in
    /// `note_progress`, so a slow-but-MOVING link (which keeps advancing
    /// idle_ms's baseline) never trips — the threshold is on time-since-last-byte,
    /// never on throughput.
    fn detect_stall(&mut self, pid: &str, in_flight: bool) -> Option<u64> {
        let in_episode = self.stall_repairs.get(pid).map(|s| s.pending).unwrap_or(false);
        // Transport recency is the ground truth for "are bytes moving NOW".
        let idle = self.links.get(pid).and_then(|l| l.transport.as_ref()).map(|t| t.idle_ms());
        let threshold = net::stall_ms();

        // FLOWING again: a transport exists and moved a byte within the window.
        // This is the ONLY thing that clears an open episode — so the brief
        // windows during a repair (by_sid flushed empty, or the new transport
        // not yet up) do NOT reset the attempt counter and re-arm rung (a).
        if matches!(idle, Some(ms) if ms < threshold) {
            self.note_progress(pid);
            return None;
        }

        if !in_episode {
            // No episode open yet. A stall can only START while a transfer is in
            // flight on a transport that has gone idle past the threshold.
            match (in_flight, idle) {
                (true, Some(ms)) if ms >= threshold => return Some(ms),
                _ => {
                    // Idle-but-empty / still establishing / flowing — clear stray
                    // bookkeeping and do nothing.
                    self.stall_repairs.remove(pid);
                    return None;
                }
            }
        }

        // An episode is OPEN and we have NOT yet seen fresh progress. Keep
        // driving the ladder: if a repair is in flight wait for it to converge
        // (re-emitting every tick would thrash); otherwise (the prior repair's
        // new transport itself went idle past the threshold) escalate again.
        match idle {
            Some(ms) if ms >= threshold && !self.repair_in_flight(pid) => Some(ms),
            _ => None,
        }
    }

    /// Is a repair for this peer's stall episode currently converging (a re-dial
    /// in flight or the ladder mid-step)? Used to avoid re-firing every tick.
    fn repair_in_flight(&self, pid: &str) -> bool {
        // A direct re-dial is pending, OR the ladder just acted and we're waiting
        // on the next observation. We treat `direct_pending` as the convergence
        // signal for rung (c)'s fresh dial. P1: a relay escalation (rung d) builds
        // a fresh WebRTC link NOT tracked by `direct_pending`, so the per-episode
        // `relayed` latch is its convergence signal — both keep the watchdog from
        // re-firing while the replacement transport is still establishing.
        if self.direct_pending.contains_key(pid) {
            return true;
        }
        self.stall_repairs.get(pid).map(|s| s.relayed).unwrap_or(false)
    }

    /// Clear a peer's stall episode — called when bytes are observed moving
    /// again (the link recovered) or nothing is in flight.
    fn note_progress(&mut self, pid: &str) {
        self.stall_repairs.remove(pid);
        // P3: a fresh byte means the (warm-cut-over) path is healthy again — let a
        // FUTURE episode warm-cut-over once more if it too stalls.
        self.warm_cutover.remove(pid);
    }

    /// P0 liveness cross-check: is the link's CONTROL path still answering? A
    /// black-holed *data* path (the case we recover) still carries reliable,
    /// ordered control frames, so a successful control send distinguishes
    /// "data wedged, link alive" (→ correction ladder) from "link dead" (→ the
    /// established C3/C4 establishment-retry path, which already handles it).
    /// We send a cheap `ping` control frame; success ⇒ alive. We do NOT await a
    /// pong (F8: the event loop must never block on something a remote controls)
    /// — a send that returns Ok over a reliable channel is sufficient evidence
    /// the transport itself is up; a dead transport errors or is flagged dead and
    /// returns Err here.
    async fn link_alive(&self, pid: &str) -> bool {
        match self.transport_of(pid) {
            Some(t) => t
                .send_control(&json!({ "type": "ping", "v": 1, "reason": "stall-probe" }))
                .await
                .is_ok(),
            None => false,
        }
    }

    /// Decide the correction RUNG for the current stall episode and (for rung c)
    /// repair the transport in place WITHOUT tearing the session down. Returns:
    ///   `Rung::Resume`  — rung (a): caller re-offers unfinished transfers with
    ///                     resume:true on the SAME transport (cheapest).
    ///   `Rung::Repaired`— rung (c): the transport was repaired in place
    ///                     (direct: fresh QUIC dial of the known device;
    ///                     WebRTC: restart_ice) — caller re-offers once it's back.
    ///   `Rung::Relayed` — rung (b)/(d): re-established over the TURN relay. P3
    ///                     reaches this on the FIRST stall for a warm-standby
    ///                     (interactive) session — instant failover to the
    ///                     pre-designated warm alternate; P1 reaches it at the
    ///                     ladder ceiling for a one-shot transfer.
    ///   `Rung::Exhausted`— rungs a→c spent (MAX_ATTEMPTS) AND relay unavailable
    ///                     (forbidden / already on relay) — fail clean, kept partial.
    /// Bounds the episode by MAX_ATTEMPTS, reusing the same ceiling as on_stuck.
    async fn correct_stall(&mut self, pid: &str) -> Rung {
        // P3 (GAP-3): once this episode has CUT OVER to the warm relay standby, a
        // SECOND Ev::TransferStalled that was already QUEUED before the cutover ran
        // (the loops emit one per tick while the stall holds) must NOT re-enter the
        // ladder and run a COLD in-place repair on top of the converging cutover —
        // that tore the fresh relay link down ("ICE Agent can not be restarted when
        // gathering"). Swallow it as a no-op (`Repaired` is the benign "in flight,
        // nothing to do" for both handlers). This guard is keyed on `warm_cutover`,
        // which is ONLY ever set on the warm path — so the COLD ladder (P0/P1) is
        // byte-for-byte unchanged and still climbs rung a→c→d normally. Cleared by
        // `note_progress` when the relay path moves a byte.
        if self.warm_cutover.contains(pid) {
            return Rung::Repaired;
        }
        let st = self.stall_repairs.entry(pid.to_string()).or_default();
        st.pending = true;
        let attempt = st.attempts;
        st.attempts += 1;

        // P3 (GAP-3): WARM-REDUNDANCY instant failover (rung b). For a long-lived
        // / interactive session (`warm_standby`), the relay is a PRE-DESIGNATED
        // WARM standby kept ready alongside the primary direct path. On the FIRST
        // detected stall we CUT OVER to it IMMEDIATELY rather than grinding through
        // the slow direct-repair rungs — rung (a)'s resume-and-wait-another-stall,
        // then rung (c)'s up-to-MAX_ATTEMPTS cold re-dials, each of which costs a
        // full stall threshold before it gives up. Those rungs are correct for a
        // one-shot file (the on-disk partial makes a cold repair fine), but for an
        // interactive session every one of those windows is a visible, intolerable
        // gap. Cutting straight to the warm relay collapses N×stall_ms of cold
        // re-establish into a single relay cutover (rung d's machinery, but reached
        // on stall #1 instead of stall #~6), preserving the on-disk partial / PTY
        // stream / tunnel state via the same C7 resume seam.
        //
        // Gated tightly so we never pay this on the wrong session:
        //   - `warm_standby` (session-kind selectivity) must be on;
        //   - relay must be PERMITTED (`--no-relay` keeps the hard direct-only
        //     promise → fall through to the normal ladder, which fails clean);
        //   - we must not be ON relay already (`relay_only`) — then relay is the
        //     PRIMARY that stalled, so there's no warmer alternate; fall through to
        //     the ladder, which lands on the honest "still stalled on relay" exit;
        //   - we cut over at most ONCE per episode (`warm_cutover`) — a flapping
        //     relay can't re-fire instant cutover every tick; the second stall on
        //     the relay path falls through to the bounded relay-stalled honesty.
        let warm_eligible = self.warm_standby
            && !relay_forbidden()
            && !self.relay_only
            && !self.warm_cutover.contains(pid);
        if attempt == 0 && warm_eligible {
            // DEBUG — resilience internal (warm cutover). Visible at -v / the gates
            // run with FILAMENT_LOG=debug.
            ui::debug(&ui::paint(
                ui::Tone::Warn,
                "  transfer stalled — cutting over to the warm relay standby (instant failover)",
            ));
            self.warm_cutover.insert(pid.to_string());
            // Latch the episode as relaying so detect_stall waits for the fresh
            // relay path to move a byte (clearing the whole episode) instead of
            // re-firing the ladder while the cutover converges (P1's convergence
            // signal, reused).
            if let Some(st) = self.stall_repairs.get_mut(pid) {
                st.relayed = true;
            }
            self.escalate_to_relay(pid).await;
            return Rung::Relayed;
        }

        if attempt == 0 {
            // Rung (a): cheapest — re-issue on the same transport. The caller
            // owns `outgoing`, so it does the actual re-offer; we just classify.
            // (Reached when warm redundancy is OFF — the one-shot `send` default —
            // or relay is forbidden / already in use; the P0/P1 ladder is correct
            // and bounded there.)
            // DEBUG — resilience internal (rung (a) resume on the same link).
            ui::debug(&ui::paint(ui::Tone::Warn, "  transfer stalled — resuming on the same link"));
            return Rung::Resume;
        }
        if attempt >= STALL_MAX_REPAIRS {
            // Rungs (a)+(c) spent — the direct/in-place-repair ladder is exhausted.
            // P1 (GAP-4): this is the rung-(d) seam. Either auto-escalate to the
            // TURN relay (the never-flaky promise) or, if the user forbade relay
            // / we're already on relay, FAIL CLEANLY with a kept partial.
            let already_relayed = self.relay_only;
            if relay_forbidden() {
                // The hard direct-only promise: never silently fall to a relay.
                // CRITICAL — a clean fatal path-decision the user must see (-q too).
                ui::critical(&ui::paint(
                    ui::Tone::Warn,
                    "  couldn't establish a direct path; relay disabled (--no-relay) \
                     — partial kept on disk. Re-run to resume, or drop --no-relay to \
                     allow relay fallback.",
                ));
                return Rung::Exhausted;
            }
            if already_relayed {
                // We already re-established over relay and it ALSO stalled — there
                // is no harder rung. Stop honestly with the partial preserved
                // (this is the genuine out-of-scope case: no path exists).
                // CRITICAL — a terminal honesty line the user must see (-q too).
                ui::critical(&ui::paint(
                    ui::Tone::Warn,
                    "  transfer still stalled on the relay route — partial kept on disk. \
                     Re-run to resume.",
                ));
                return Rung::Exhausted;
            }
            // Rung (d): re-establish this transfer over the TURN relay, preserving
            // the on-disk partial (C7 resume). Bounded: one escalation per episode.
            // CRITICAL — P1's value-prop: the never-flaky promise kicking in. The
            // user must see the path change to relay even under -q.
            ui::critical(&ui::paint(
                ui::Tone::Warn,
                "  direct paths exhausted — falling back to the TURN relay",
            ));
            // Latch the episode as "relaying": the fresh relay link establishes
            // with no transport yet, so this stops detect_stall from re-firing the
            // ladder (into a premature Exhausted) until the relay path moves a byte
            // (which clears the whole episode via note_progress).
            if let Some(st) = self.stall_repairs.get_mut(pid) {
                st.relayed = true;
            }
            self.escalate_to_relay(pid).await;
            return Rung::Relayed;
        }
        // Rung (c): repair the transport IN PLACE under the live session.
        // DEBUG — resilience internal (in-place repair).
        ui::debug(&ui::paint(
            ui::Tone::Warn,
            &format!("  transfer stalled — repairing the link in place (attempt {}/{})", attempt, STALL_MAX_REPAIRS),
        ));
        self.repair_link_in_place(pid).await;
        Rung::Repaired
    }

    /// Rung (c): rebuild a path under the LIVE session, preserving the on-disk
    /// partial (C7 resume re-offers from the saved offset on the new transport).
    /// - direct-QUIC link: drop the wedged transport and re-arm the known-device
    ///   direct dial (`start_direct`), which re-advertises candidates; the peer's
    ///   matching re-dial (it runs the same watchdog) completes a FRESH
    ///   authenticated QUIC connection → `Ev::DirectReady` → `adopt_direct` swaps
    ///   in the new transport → ChannelReady re-offers the unfinished transfers.
    /// - WebRTC link: `restart_ice()` — keeps the RTCPeerConnection + DTLS keys;
    ///   only ICE re-gathers, so transfers resume on the same channel once ICE
    ///   re-converges (no re-key, the preferred repair when available).
    async fn repair_link_in_place(&mut self, pid: &str) {
        let Some(l) = self.links.get(pid) else { return };
        if l.direct {
            // Fresh QUIC dial of the known device. Pull the (name,secret) the
            // link was born with so the re-dial re-authenticates to the SAME pair
            // secret (session identity is stable across the swap; only the wire
            // keys rotate — documented in §2.5).
            let known = l.expected_secret.clone();
            let info = l.info.clone();
            let was_active = self.is_active(pid);
            self.drop_link(pid); // tears down the wedged transport (frees the port)
            if let Some((name, secret)) = known {
                self.start_direct(pid, &name, &secret).await;
                if was_active {
                    // start_direct creates no Link yet; keep the slot pointed here
                    // so adopt_direct's ChannelReady re-offers to the right target.
                    self.active = Some(pid.to_string());
                }
            } else {
                // No stored secret to re-dial direct — fall back to a WebRTC
                // re-establish under the session (still preserves the partial).
                let _ = self.establish(info).await;
                if was_active {
                    self.active = Some(pid.to_string());
                }
            }
        } else if let Some(p) = l.peer.clone() {
            // WebRTC: ICE-restart in place — no teardown, no re-key.
            p.restart_ice().await;
        }
    }

    /// Rung (d) — P1 (GAP-4): the direct/in-place ladder is exhausted, so
    /// RE-ESTABLISH this transfer over the TURN relay (relay-only ICE), the
    /// automatic version of the manual `--relay` the Pixel delivery and the runner
    /// both had to perform by hand. The on-disk partial is preserved at the seam:
    /// we re-establish a fresh WebRTC link with `RTCIceTransportPolicy::Relay`, and
    /// its ChannelReady re-offers the unfinished transfers with `resume:true` from
    /// the saved `.part` offset (no restart-from-zero, C7). Flipping the
    /// connection-wide `relay_only` flag also makes any subsequent repair on this
    /// session relay-only, so we don't bounce back to a known-bad direct path.
    /// Session identity (the pair secret / verified petname) is stable across the
    /// swap — only the wire keys rotate (§2.5). Bounded: one escalation per stall
    /// episode (the caller returns `Rung::Relayed` and the `stall_repairs` counter
    /// is already at the ceiling, so the ladder can't re-fire until progress
    /// resumes and resets it).
    async fn escalate_to_relay(&mut self, pid: &str) {
        // Latch the whole connection onto relay-only ICE: the re-establish below
        // and every later (re)establish for this session now forces TURN.
        self.relay_only = true;
        // Commit THIS peer to relay: stop dialing/answering direct-QUIC for it, so
        // the known-bad direct path can't keep winning the race and re-freezing
        // while the relay link tries to form (the exact thrash the sim exposed).
        self.relay_committed.insert(pid.to_string());
        let Some(l) = self.links.get(pid) else { return };
        let info = l.info.clone();
        let known = l.expected_secret.clone();
        let was_active = self.is_active(pid);
        // Tear down the wedged (direct) transport, then re-establish over WebRTC
        // relay-only. We deliberately do NOT re-arm the direct-QUIC dial here even
        // if a secret is known: direct is what just failed, and relay is a WebRTC
        // path, so we go straight to `establish` (relay-only ICE).
        self.drop_link(pid);
        // Clear any stray pending direct attempt so `establish` (which early-
        // returns while a direct attempt owns the peer, to keep the ladder
        // sequential) is never suppressed for the relay re-establish.
        self.direct_pending.remove(pid);
        // Carry the proven identity into the fresh relay link so the post-channel
        // pair-proof still binds to the same device (set after establish creates
        // the Link below).
        let _ = self.establish(info).await;
        if let (Some(l), Some(ks)) = (self.links.get_mut(pid), known) {
            l.expected_secret = Some(ks);
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        // Honest, loud: the user must know this session is now on a relay.
        // CRITICAL — the value-prop path label; shown even under -q.
        ui::critical(&format!("  {}", relay_banner()));
        // P5 (GAP-6): ARM the relay->direct upgrade prober for this peer. Relay is
        // a way-station, not a destination: while we serve on relay we keep probing
        // for a direct path and upgrade back the moment one is confirmed stable.
        // Eligibility mirrors warm redundancy (long-lived/interactive sessions +
        // the daemon — a one-shot send that already completed doesn't need it) and
        // requires relay to be PERMITTED. The kill switch (`FILAMENT_UPGRADE_PROBE=0`)
        // and `--no-relay` both make this a no-op.
        if self.upgrade_eligible() {
            self.upgrade_probe
                .entry(pid.to_string())
                .or_insert_with(UpgradeProbe::armed);
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  on relay — will keep trying for a direct path and upgrade automatically",
            ));
        }
    }

    /// P5 (GAP-6): is this session eligible to run the relay->direct prober?
    /// Selective like P3's warm redundancy: ON for long-lived / interactive
    /// sessions (the `up`/`up --shell` daemon acceptor; a transfer flagged
    /// interactive via `FILAMENT_WARM_STANDBY=1`). Gated off by the kill switch
    /// and by `--no-relay` (which never reaches relay anyway).
    fn upgrade_eligible(&self) -> bool {
        self.warm_standby && net::upgrade_prober_enabled() && !relay_forbidden()
    }

    /// P5 (GAP-6): a portable network-change-ish event fired (a signaling
    /// reconnect / fresh welcome). Re-probe every relay-committed peer IMMEDIATELY
    /// (reset its backoff to fire now), unless it's already mid-verify on a standby.
    /// Cheap and idempotent — the prober tick does the actual dialing.
    fn reprobe_on_network_event(&mut self) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        for up in self.upgrade_probe.values_mut() {
            if up.standby.is_none() {
                up.next_at = Some(Instant::now());
            }
        }
    }

    /// P5 (GAP-6): record a failed/expired probe and back the cadence off toward
    /// the steady cadence (exponential, capped at steady_ms). Also clears any
    /// stale standby/verify state so the next probe starts clean.
    fn mark_probe_failed(&mut self, pid: &str) {
        let Some(up) = self.upgrade_probe.get_mut(pid) else { return };
        up.attempt = up.attempt.saturating_add(1);
        up.standby = None;
        up.verify_started = None;
        up.verify_last_idle = u64::MAX;
        // Backoff: first failure → first_ms; then double toward steady_ms (cap).
        let first = net::upgrade_first_ms();
        let steady = net::upgrade_steady_ms();
        let backoff = first.saturating_mul(1u64 << up.attempt.min(8)).min(steady);
        up.next_at = Some(Instant::now() + Duration::from_millis(backoff));
    }

    /// P5 (GAP-6): the per-tick prober. Run from each live-session event loop's
    /// tick (no new concurrency, F8). For every peer currently committed to relay
    /// with an armed `UpgradeProbe`: (1) if a direct standby is mid-VERIFY, judge
    /// it (cut over if it has sustained progress for verify_ms; discard + back off
    /// if it regressed); (2) else if a probe is due (`next_at`), fire a fresh
    /// direct dial ALONGSIDE the relay link (warm direct standby) without
    /// disturbing it. Also detects a local interface change (`iface_snapshot`) and
    /// re-probes IMMEDIATELY — the "walked home onto wifi" trigger.
    async fn tick_upgrade_prober(&mut self) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        if self.upgrade_probe.is_empty() {
            return;
        }
        // Network-change trigger: a change to the local interface set is the
        // strongest "a new direct path may exist NOW" signal we can read without a
        // platform netlink dependency. On change, reset every armed probe's
        // backoff to fire immediately (catches the wifi/cellular handoff instantly).
        let snap = direct::local_ip_snapshot();
        if snap != self.iface_snapshot {
            if !self.iface_snapshot.is_empty() {
                // DEBUG — resilience internal (upgrade-probe trigger).
                ui::debug(&ui::paint(
                    ui::Tone::Dim,
                    "  network changed — re-probing for a direct path now",
                ));
                for up in self.upgrade_probe.values_mut() {
                    if up.standby.is_none() {
                        up.next_at = Some(Instant::now()); // fire ASAP
                    }
                }
            }
            self.iface_snapshot = snap;
        }

        let now = Instant::now();
        let pids: Vec<String> = self.upgrade_probe.keys().cloned().collect();
        for pid in pids {
            // A peer that is no longer relay-committed (already upgraded or gone)
            // shouldn't be probed; drop its entry.
            if !self.relay_committed.contains(&pid) || !self.links.contains_key(&pid) {
                self.upgrade_probe.remove(&pid);
                self.direct_pending.remove(&pid);
                continue;
            }
            // VERIFYING: a standby connected — judge it before scheduling anything.
            let verifying = self
                .upgrade_probe
                .get(&pid)
                .map(|u| u.standby.is_some())
                .unwrap_or(false);
            if verifying {
                self.judge_upgrade_standby(&pid).await;
                continue;
            }
            // PROBING: a direct dial is in flight (its DirectPending) — wait for it
            // to win (→ DirectUpgradeReady) or expire (→ expired_direct backoff).
            if self.direct_pending.contains_key(&pid) {
                continue;
            }
            // IDLE: schedule / fire the next probe per the backoff.
            let due = match self.upgrade_probe.get(&pid).and_then(|u| u.next_at) {
                None => true,            // armed but unscheduled → schedule first probe
                Some(at) => now >= at,   // due
            };
            if let Some(up) = self.upgrade_probe.get_mut(&pid) {
                if up.next_at.is_none() {
                    // First scheduling after arming: probe after first_ms.
                    up.next_at = Some(now + Duration::from_millis(net::upgrade_first_ms()));
                    continue;
                }
            }
            if !due {
                continue;
            }
            // Fire a probe: dial direct ALONGSIDE the relay link.
            let known = self.links.get(&pid).and_then(|l| l.expected_secret.clone());
            let Some((name, secret)) = known else {
                // No stored secret to authenticate a direct dial — can't probe;
                // disarm so we don't spin.
                self.upgrade_probe.remove(&pid);
                continue;
            };
            // DEBUG — resilience internal (upgrade probe attempt).
            ui::debug(&ui::paint(
                ui::Tone::Dim,
                "  probing for a direct path (alongside the relay)…",
            ));
            // Pre-set the NEXT backoff deadline so a probe that silently makes no
            // progress still re-schedules (expired_direct also calls
            // mark_probe_failed on budget expiry; whichever fires first wins).
            self.start_upgrade_probe(&pid, &name, &secret).await;
        }
    }

    /// P5 (GAP-6): VERIFY-before-upgrade. A direct standby has connected for
    /// `pid`. Decide whether it is STABLE enough to cut over to:
    ///   - if it has been moving data (idle_ms stays low) CONTINUOUSLY for
    ///     `verify_ms`, perform the upgrade (clear relay_committed/relay_only, cut
    ///     over to the direct transport, tear down relay, re-offer transfers);
    ///   - if it goes idle past `verify_idle_ms` before that, DISCARD it and stay
    ///     on relay (back off) — the mandatory no-flap guard against a flaky direct
    ///     path that connects then immediately re-stalls.
    /// We drive a tiny VERIFY heartbeat over the standby (a control ping) so a
    /// healthy path keeps stamping its `idle_ms()` low even before the session's
    /// real transfer bytes are re-routed onto it.
    async fn judge_upgrade_standby(&mut self, pid: &str) {
        let verify_ms = net::upgrade_verify_ms();
        let verify_idle_ms = net::upgrade_verify_idle_ms();
        // Heartbeat the standby with a real DATA frame (reserved verify sid) so a
        // healthy path advances its activity clock (`idle_ms()` stays low) while a
        // stalled/flaky standby — which black-holes the DATA path, not the control
        // path — either errors here or lets idle climb. A control ping would wrongly
        // pass on a flaky standby (whose control path stays alive), so we MUST probe
        // the data path. The peer drops the unknown-sid chunk harmlessly but stamps
        // its inbound activity, so its side's idle drops too (symmetric verify).
        let standby = self.upgrade_probe.get(pid).and_then(|u| u.standby.clone());
        let Some(standby) = standby else { return };
        // BOUND the heartbeat (F8: never block the event loop on something a remote
        // / a wedged path controls). A flaky standby's data path black-holes — the
        // send_frame would park forever — so a timeout reads as "didn't hold".
        let beat_ok = matches!(
            tokio::time::timeout(
                Duration::from_millis(500),
                standby.send_frame(VERIFY_PROBE_SID, b"upgrade-verify"),
            )
            .await,
            Ok(Ok(()))
        );
        let idle = standby.idle_ms();
        let Some(up) = self.upgrade_probe.get_mut(pid) else { return };
        let started = match up.verify_started {
            Some(t) => t,
            None => {
                up.verify_started = Some(Instant::now());
                up.verify_last_idle = idle;
                return;
            }
        };
        // Regressed: control send failed OR the path went idle past the guard.
        // Discard the standby, stay on relay, back off (the no-flap guard).
        if !beat_ok || idle >= verify_idle_ms {
            // DEBUG — resilience internal (no-flap guard rejecting a standby).
            ui::debug(&ui::paint(
                ui::Tone::Warn,
                "  direct path connected but didn't hold — staying on relay (no flap)",
            ));
            self.direct_pending.remove(pid);
            self.mark_probe_failed(pid);
            return;
        }
        up.verify_last_idle = up.verify_last_idle.min(idle);
        // Sustained: moved data continuously for the whole verify window → upgrade.
        if started.elapsed() >= Duration::from_millis(verify_ms) {
            let t = standby;
            let route = self.upgrade_probe.get(pid).map(|u| u.standby_route).unwrap_or("direct-quic");
            self.perform_upgrade(pid, t, route).await;
        }
    }

    /// P5 (GAP-6): the upgrade cutover. The direct standby is CONFIRMED stable —
    /// commit it as the session's transport, preserving the session (the same
    /// cutover seam P1/P3 use): clear `relay_committed` + `relay_only` so direct
    /// may win again, swap the verified direct transport into the link (the relay
    /// link/transport is dropped), and re-offer any unfinished transfers
    /// (resume:true) on the new direct path. Honest + loud, mirroring the relay
    /// banner: the user is told they're back on a direct path.
    async fn perform_upgrade(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let was_active = self.is_active(pid);
        let known = self.links.get(pid).and_then(|l| l.expected_secret.clone());
        // Clear the relay commitment FIRST so the new direct link isn't treated as
        // a known-bad path and so a future stall can escalate cleanly again.
        self.relay_committed.remove(pid);
        self.relay_only = false;
        self.upgrade_probe.remove(pid);
        self.direct_pending.remove(pid);
        // Swap the verified direct transport into the link, dropping the relay
        // link/transport (drop_link tears down the WebRTC peer). adopt the new
        // transport via the same direct-link shape adopt_direct builds, but reusing
        // the existing identity so the session is preserved across the swap.
        self.drop_link(pid);
        self.adopt_direct_transport(pid, t.clone(), route, known);
        if was_active {
            self.active = Some(pid.to_string());
        }
        // CRITICAL — P5's value-prop line: relay released, back on a direct path.
        ui::critical(&ui::paint(
            ui::Tone::Ok,
            &format!("  upgraded back to a direct path (route: {route}) — relay released"),
        ));
        // Re-offer unfinished transfers on the new direct transport (resume:true);
        // the ChannelReady re-emit drives the same path for the send loop.
        let _ = self.tx.send(Ev::ChannelReady(pid.to_string(), t));
    }

    /// P5 (GAP-6): build the post-upgrade DIRECT link from a verified standby
    /// transport, reusing the known identity (so the session/petname is stable
    /// across the relay->direct swap — only the wire path changes). Mirrors
    /// `adopt_direct` but takes an already-connected transport and a carried
    /// (name,secret) instead of consuming a `DirectPending`.
    fn adopt_direct_transport(
        &mut self,
        pid: &str,
        t: Arc<dyn Transport>,
        route: &'static str,
        known: Option<(String, String)>,
    ) {
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": known.as_ref().map(|(n, _)| n.clone()).unwrap_or_else(|| "peer".into()) }));
        let name = known
            .as_ref()
            .map(|(n, _)| n.clone())
            .or_else(|| info["name"].as_str().map(String::from))
            .unwrap_or_else(|| "peer".into());
        let uid = info["uid"].as_str().map(|s| s.to_string());
        self.next_gen += 1;
        let generation = self.next_gen;
        self.links.insert(
            pid.to_string(),
            Link {
                peer: None,
                info,
                name,
                uid,
                transport: Some(t),
                generation,
                attempts: 0,
                trusted: true,
                verified_name: known.as_ref().map(|(n, _)| n.clone()),
                expected_secret: known,
                presence: Presence::Ready,
                direct: true,
                direct_route: route,
            },
        );
    }

    /// P5 (GAP-6): a relay->direct upgrade probe's direct standby CONNECTED. Stash
    /// it on the peer's `UpgradeProbe` and START the verify window. Crucially, do
    /// NOT touch `links` — the relay link keeps serving until the standby is proven
    /// stable. If we have no armed probe for this peer (it upgraded/left while the
    /// race was in flight), just drop the transport (it closes on drop). Idempotent:
    /// a second DirectUpgradeReady for an already-stashed standby is ignored.
    fn stash_upgrade_standby(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        // Consume any probe DirectPending so expired_direct doesn't reap/backoff it
        // out from under the verify (the race already won).
        self.direct_pending.remove(pid);
        let Some(up) = self.upgrade_probe.get_mut(pid) else {
            // No armed probe — the transport is unowned; dropping it tears it down.
            return;
        };
        if up.standby.is_some() {
            return; // already verifying a standby; ignore the duplicate.
        }
        up.standby = Some(t);
        up.standby_route = route;
        up.verify_started = None; // judge_upgrade_standby stamps it on first look
        up.verify_last_idle = u64::MAX;
        // DEBUG — resilience internal (upgrade verify window opening).
        ui::debug(&ui::paint(
            ui::Tone::Dim,
            "  direct path connected — verifying it holds before upgrading…",
        ));
    }

    /// C4: transient `disconnected` — nudge ICE from the impolite side and
    /// give it grace before treating it as failure. C21: a peer that said
    /// `brb` gets its declared window instead of the 6 s blip grace, and no
    /// scary message.
    async fn on_pc_state(&mut self, pid: &str, s: &str) {
        let away = self.is_away(pid);
        let Some(l) = self.links.get_mut(pid) else { return };
        // C26: collect the announcement, print after the borrow ends so the
        // roster can read every link.
        let mut announce: Option<(&'static str, ui::Tone, &'static str)> = None;
        match s {
            "connected" => {
                if l.presence == Presence::Reconnecting {
                    announce = Some((ui::glyph_ok(), ui::Tone::Ok, "recovered"));
                }
                l.presence = Presence::Ready;
                l.attempts = 0;
            }
            "disconnected" => {
                let grace = if away {
                    l.presence = Presence::Away;
                    if let Some((_, until)) = &self.away {
                        until.duration_since(Instant::now()) + Duration::from_secs(15)
                    } else {
                        Duration::from_secs(6)
                    }
                } else {
                    l.presence = Presence::Reconnecting;
                    announce = Some(("◌", ui::Tone::Warn, "reconnecting…"));
                    Duration::from_secs(6)
                };
                if let Some(p) = &l.peer {
                    if !p.polite && !away {
                        p.restart_ice().await;
                    }
                }
                let tx = self.tx.clone();
                let pid = pid.to_string();
                let generation = l.generation;
                tokio::spawn(async move {
                    tokio::time::sleep(grace).await;
                    let _ = tx.send(Ev::GraceExpired(pid, generation));
                });
            }
            _ => {}
        }
        if let Some((mark, tone, note)) = announce {
            ui::say(&self.roster(pid, mark, tone, note, "peer"));
        }
    }

    /// A peer's socket died. Drop its link; if it was the active target, open
    /// the rejoin window (their client auto-rejoins; C6 supersede completes
    /// the recovery). Returns true if the ACTIVE peer left.
    ///
    /// #28 DEFERRED DROP: peer-left fires when a sid LEAVES THE ROOM, but the
    /// WebRTC data channel is independent and may still be flowing — either a
    /// cosmetic signaling reconnect mid-transfer (keep it!) or a hard-killed
    /// peer whose channel reads flowing for a beat before DTLS notices (must
    /// still drop, or the sender strands). We can't tell the two apart at this
    /// instant, so we DEFER: stash the payload and re-check each tick
    /// (`reap_deferred`). If it goes idle/dead it gets re-injected here with a
    /// force marker and dropped then; if it keeps flowing the transfer
    /// completes on the live channel and the idle link is reaped harmlessly.
    /// The roster entry is removed immediately (the sid truly left); only the
    /// LINK drop is deferred.
    fn on_peer_left(&mut self, v: &Value) -> bool {
        let Some(pid) = v["id"].as_str() else { return false };
        let pid = pid.to_string();
        self.roster.remove(&pid);
        if !self.links.contains_key(&pid) {
            return false;
        }
        // Defer the drop while the data channel is still moving bytes — unless
        // this is the force re-injection from reap_deferred (the link has since
        // gone idle/dead and must drop now). FILAMENT_TEST_NO_DEFER reverts to
        // the old unconditional-drop behaviour so an A/B repro can prove the
        // deferral is what saves the live transfer (baseline must FAIL).
        let forced = v["__fil_force_drop"].as_bool() == Some(true);
        let defer_disabled = test_hooks::no_defer();
        if !forced && !defer_disabled && self.link_flowing(&pid) {
            // Idempotent: first peer-left for this sid records the original
            // payload; a duplicate is swallowed (no double-defer, no drop).
            self.deferred_left.entry(pid.clone()).or_insert_with(|| v.clone());
            let name = self.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "peer".into());
            // DEBUG — resilience internal (deferred drop while channel flowing).
            ui::debug(&format!("{name} signaling left — data channel still flowing, deferring drop"));
            return false;
        }
        let was_active = self.is_active(&pid);
        self.drop_link(&pid);
        if was_active {
            // C21: informed waits — a peer that declared `brb` gets its
            // promised window (plus slack); an unannounced vanish gets the
            // short default. Their client auto-rejoins; C6 supersede or a
            // fresh adopt completes the recovery.
            self.rejoin_window = match &self.away {
                Some((apid, until)) if *apid == pid && *until > Instant::now() => {
                    until.duration_since(Instant::now()) + Duration::from_secs(15)
                }
                _ => rejoin_unwarned(),
            };
            self.waiting_rejoin = Some(Instant::now());
        }
        was_active
    }

    /// #28: re-check every deferred peer-left. Called on every main-loop tick
    /// (idempotent, cheap). A deferred sid is discharged when it is no longer
    /// flowing — its data channel went idle past the threshold OR died
    /// (idle_ms == u64::MAX). We then re-inject the ORIGINAL peer-left payload
    /// (flagged force) so the normal Ev::PeerLeft handler runs verbatim — same
    /// loop-side flush/messaging/rejoin behaviour as a non-deferred leave, with
    /// the link now correctly dropped. A sid that vanished from `links` (e.g. a
    /// supersede dropped it; drop_link already cleared its entry, but belt-and-
    /// braces) is forgotten silently. A still-flowing sid is left to keep
    /// flowing — the reconnect case, where the transfer completes on the live
    /// channel and the all-done exit reaps it.
    fn reap_deferred(&mut self) {
        if self.deferred_left.is_empty() {
            return;
        }
        let ready: Vec<(String, Value)> = self
            .deferred_left
            .iter()
            .filter(|(sid, _)| !self.links.contains_key(*sid) || !self.link_flowing(sid))
            .map(|(sid, v)| (sid.clone(), v.clone()))
            .collect();
        for (sid, mut payload) in ready {
            self.deferred_left.remove(&sid);
            if !self.links.contains_key(&sid) {
                continue; // link already gone (superseded); nothing to drop
            }
            // Force the drop this time (the channel is now idle/dead).
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("__fil_force_drop".into(), Value::Bool(true));
            }
            let name = self.link(&sid).map(|l| l.name.clone()).unwrap_or_else(|| "peer".into());
            // DEBUG — resilience internal (deferred-leave reap).
            ui::debug(&format!("{name} link went idle after deferred leave — dropping now"));
            // Re-inject so the loop's own peer-left branch handles partials,
            // messaging and the rejoin window exactly as a fresh leave would.
            let _ = self.tx.send(Ev::PeerLeft(payload));
        }
    }

    /// #28 exit reconciliation: true when every remaining link is one we're only
    /// holding open for its deferred-drop reap (vacuously true with no links). A
    /// link in `deferred_left` is a peer whose signaling already left; once all
    /// transfers are complete it protects nothing, so it must not delay exit by
    /// the full deferral window.
    fn only_deferred_links(&self) -> bool {
        self.links.keys().all(|k| self.deferred_left.contains_key(k))
    }

    /// C21: any traffic from a peer cancels its declared absence.
    fn note_alive(&mut self, pid: &str) {
        if matches!(&self.away, Some((apid, _)) if apid == pid) {
            self.away = None;
        }
    }

    /// C26: set a link's roster presence; returns its name for the announce.
    fn link_presence(&mut self, pid: &str, p: Presence) -> String {
        match self.links.get_mut(pid) {
            Some(l) => {
                l.presence = p;
                l.name.clone()
            }
            None => String::new(),
        }
    }

    fn is_away(&self, pid: &str) -> bool {
        matches!(&self.away, Some((apid, until)) if apid == pid && *until > Instant::now())
    }

    /// C26: one static colored status line showing EVERY peer, the changed
    /// one carrying the note — `✓ daring-wombat   ● deft-gibbon  away…`.
    /// `fallback_name` covers a peer already dropped from the map (peer-left).
    fn roster(&self, pid: &str, mark: &str, tone: ui::Tone, note: &str, fallback_name: &str) -> String {
        let mut links: Vec<(&String, &Link)> = self.links.iter().collect();
        links.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        let mut parts = Vec::new();
        let mut seen = false;
        for (id, l) in links {
            if id == pid {
                seen = true;
                parts.push(peer_entry(&l.name, mark, tone, note));
            } else {
                let (m, t, n) = presence_glyph(l.presence);
                parts.push(peer_entry(&l.name, m, t, n));
            }
        }
        if !seen {
            parts.push(peer_entry(fallback_name, mark, tone, note));
        }
        format!("  {}", parts.join("   "))
    }

    /// #7 for the CLI: an offer from a roster peer we haven't linked yet
    /// creates a polite responder link. Stray signals from unknowns drop.
    /// Apply a relayed signal to `from`'s link. Never fatal (F6): the
    /// watchdog/grace machinery owns failed negotiations. On polite-side
    /// glare (webrtc-rs can't roll back out of have-local-offer) the link is
    /// rebuilt as a pure responder and the colliding offer re-applied.
    async fn apply_signal(&mut self, from: &str, data: Value) {
        let peer = match self.link(from).and_then(|l| l.peer.clone()) {
            Some(p) => p,
            None => return,
        };
        match peer.handle_signal(data).await {
            Ok(net::SignalOutcome::Handled) => {}
            Ok(net::SignalOutcome::Glare(offer)) => {
                self.drop_link(from);
                if let Err(e) = self.ensure_responder(from, &offer).await {
                    ui::trace(&format!("signal: glare rebuild failed: {e} (recovering)"));
                    return;
                }
                if let Some(p) = self.link(from).and_then(|l| l.peer.clone()) {
                    if let Err(e) = p.handle_signal(offer).await {
                        ui::trace(&format!("signal failed to apply: {e} (recovering)"));
                    }
                }
            }
            Err(e) => ui::trace(&format!("signal failed to apply: {e} (recovering)")),
        }
    }

    async fn ensure_responder(&mut self, from: &str, data: &Value) -> Result<()> {
        if self.links.contains_key(from) {
            return Ok(());
        }
        if data["type"].as_str() == Some("description")
            && data["description"]["type"].as_str() == Some("offer")
        {
            // Answer a WebRTC offer from a channel-peer EVEN IF we never got its
            // known-peer. The existing-member known-peer notification is
            // unreliable on prod (proven via the signaling harness: the NEW
            // joiner is reliably notified, but the EXISTING member often is NOT)
            // — which left the acceptor ignoring a valid initiator's offer and
            // looking like "stuck connecting". One-sided discovery is now enough:
            // whoever discovers drives, the other answers. SAFE: trust still
            // gates entirely on the pair-proof MAC (an attacker without the
            // secret fails it and is never trusted) — we only answer the offer
            // and let the proof decide. A later known-peer refreshes name/uid.
            let info = self
                .roster
                .get(from)
                .cloned()
                .unwrap_or_else(|| json!({ "id": from }));
            if self.links.len() < MAX_LINKS {
                // Forced responder: this link exists to answer THEIR offer.
                self.establish_as(info, Some(true)).await?;
            }
        }
        Ok(())
    }
}

/// Receive the next event; while a rejoin window is open, tick every second
/// so the window can expire AND the countdown stays visible (C22 — "45s"
/// frozen on screen reads as broken).
async fn next_ev(
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    conn: &Conn,
    suppress_countdown: bool,
) -> Result<Option<Ev>> {
    if let Some(since) = conn.waiting_rejoin {
        if since.elapsed() > conn.rejoin_window {
            ui::clear_sticky();
            bail!(
                "peer did not come back within {}s (partial state kept for resume)",
                conn.rejoin_window.as_secs()
            );
        }
        if !suppress_countdown {
            let left = conn.rejoin_window.saturating_sub(since.elapsed()).as_secs();
            ui::sticky(&ui::paint(
                ui::Tone::Dim,
                &format!("  {} holding the line — {left}s for them to come back (Ctrl-C to stop)", ui::spinner_frame()),
            ));
        }
        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    } else {
        // C30: never block indefinitely — a 2s tick lets the convergent
        // session repair lost emits even when no events arrive.
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // F2: both ring (webrtc) and aws-lc (reqwest) end up in the dep tree;
    // rustls refuses to guess between two providers, so pick ring explicitly
    // BEFORE anything touches TLS.
    rustls::crypto::ring::default_provider().install_default().ok();
    // Bare-arg comfort dispatch: `filament <path>` sends it with a code;
    // `filament <something-like-a-code>` claims it. Subcommands still win.
    let mut argv: Vec<String> = std::env::args().collect();
    if let Some(first) = argv.get(1) {
        const CMDS: [&str; 17] = ["send", "recv", "devices", "update", "completions", "man", "config", "help", "up", "status", "down", "introduce", "netcat", "forward", "ssh", "grant", "revoke"];
        let code_re = regex_lite_code(first);
        if !first.starts_with('-') && !CMDS.contains(&first.as_str()) {
            if std::path::Path::new(first).exists() {
                argv.insert(1, "send".into());
                argv.push("--code".into());
            } else if code_re {
                argv.insert(1, "recv".into());
            } else if looks_like_pake_code(first) {
                // Bug 4: a 4-segment PAKE pairing code (from `filament pair`) —
                // claim it via the pairing ceremony, not recv.
                argv.insert(1, "pair".into());
            }
        }
    }
    let cli = Cli::parse_from(argv);
    // Resolve the global output verbosity ONCE, before any worker spawns:
    // FILAMENT_LOG (if set) overrides the -v/-q flags. Default = info.
    ui::init_verbosity(cli.verbose, cli.quiet);
    if let Some(n) = &cli.name_as {
        // single-threaded at this point (before the runtime spawns workers)
        unsafe { std::env::set_var("FILAMENT_NAME", n) };
    }
    // P1 (GAP-4): record the hard direct-only choice before any worker spawns.
    if cli.no_relay {
        NO_RELAY.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let server = if cli.server == DEFAULT_SERVER {
        config_get("server").unwrap_or(cli.server.clone())
    } else {
        cli.server.clone()
    };
    let server = server.trim_end_matches('/').to_string();
    match cli.cmd {
        Cmd::Send { paths, code, word, room, to, name, remember } => {
            send_cmd(&server, paths, code || word.is_some(), word, room, to, name, cli.relay, remember).await
        }
        Cmd::Recv { code, dir, yes, room, to, keep_open, remember, output } => {
            recv_cmd(&server, code, dir, yes, room, to, keep_open, cli.relay, remember, false, output, ShellPolicy::Granted, None).await
        }
        Cmd::Config { key, value } => {
            match (key, value) {
                (Some(k), Some(v)) => {
                    config_set(&k, &v)?;
                    println!("{k} = {v}");
                }
                (Some(k), None) => println!("{}", config_get(&k).unwrap_or_default()),
                (None, _) => {
                    for k in ["name", "server", "dir"] {
                        if let Some(v) = config_get(k) {
                            println!("{k} {v}");
                        }
                    }
                }
            }
            Ok(())
        }
        Cmd::Up { install, dir, shell, shell_only, shell_user } => up_cmd(&server, install, dir, cli.relay, shell, shell_only, shell_user).await,
        Cmd::Status => status_cmd(),
        Cmd::Down => down_cmd(),
        Cmd::Introduce { a, b } => introduce_cmd(&server, &a, &b, cli.relay).await,
        Cmd::Pair { code, name } => pair_cmd(&server, code, name, cli.relay).await,
        Cmd::Devices { action } => {
            match action {
                None => {
                    let all = devices_load();
                    if all.is_empty() {
                        println!("no known devices yet — run `filament pair` to add one");
                    }
                    for (n, s) in all {
                        // Show the granted capability set so `grant shell` is
                        // visible here (v1 records read as [transfer]).
                        let caps = device_caps(&n).unwrap_or_else(|| vec!["transfer".to_string()]);
                        println!("{n}  (channel {})  [{}]", &channel_of(&s)[..12], caps.join(", "));
                    }
                }
                Some(DevicesAction::Forget { name }) => {
                    let had = devices_load().iter().any(|(n, _)| n == &name);
                    if !had {
                        bail!("no device named '{name}' — see `filament devices`");
                    }
                    devices_remove(&name)?;
                    println!("forgot '{name}' — it can no longer find or auto-connect to this machine");
                    println!("(their side still holds its half; it will hear \"never met you\" on the next proof)");
                }
                Some(DevicesAction::Rename { old, new }) => {
                    // Rename in place on the raw record so caps/v2 fields ride
                    // along (remove+store dropped the renamed device's caps).
                    let p = devices_path();
                    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
                        .ok()
                        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default();
                    if !arr.iter().any(|d| d["name"].as_str() == Some(old.as_str())) {
                        bail!("no device named '{old}' — see `filament devices`");
                    }
                    if arr.iter().any(|d| d["name"].as_str() == Some(new.as_str())) {
                        bail!("'{new}' already exists — forget it first or pick another name");
                    }
                    for d in arr.iter_mut() {
                        if d["name"].as_str() == Some(old.as_str()) {
                            d["name"] = json!(new);
                        }
                    }
                    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
                    }
                    println!("renamed '{old}' -> '{new}' (local alias only — the secret, and the other side, are unchanged)");
                }
            }
            Ok(())
        }
        Cmd::Update { check, beta } => update_cmd(check, beta).await,
        Cmd::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut Cli::command(), "filament", &mut std::io::stdout());
            Ok(())
        }
        Cmd::Man => {
            use clap::CommandFactory;
            clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
            Ok(())
        }
        Cmd::Netcat { peer, rport } => l2::netcat_cmd(&server, &peer, rport, cli.relay).await,
        Cmd::Pty { peer } => l2::pty_cmd(&server, &peer, cli.relay).await,
        Cmd::Forward { lport, peer, rport } => l2::forward_cmd(&server, lport, &peer, rport, cli.relay).await,
        Cmd::Ssh { peer, args } => l2::ssh_cmd(&server, &peer, &args, cli.relay).await,
        Cmd::Grant { device, capability } => {
            device_set_cap(&device, &capability, true)?;
            println!(
                "granted '{capability}' to '{device}'. {}",
                if capability == "shell" {
                    "they can now `filament ssh` into this machine (their key is installed on first connect)."
                } else {
                    ""
                }
            );
            Ok(())
        }
        Cmd::Revoke { device, capability } => {
            device_set_cap(&device, &capability, false)?;
            if capability == "shell" {
                sshkeys::remove_authorized_key(&device)?;
                println!("revoked 'shell' from '{device}' and removed its filament-managed authorized_keys block.");
            } else {
                println!("revoked '{capability}' from '{device}'.");
            }
            Ok(())
        }
    }
}

// ----------------------------------------------------------------- update --
// Self-update against GitHub releases (tags cli-vX.Y.Z). Downloads the
// archive for this platform, verifies it against SHA256SUMS, and atomically
// replaces the current executable.

const REPO: &str = "Abdk4Moura/filament";

fn release_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

async fn update_cmd(check_only: bool, beta: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("filament/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Latest cli-v* release via the API (releases/latest may point at a web
    // release tag, so filter explicitly). Prereleases are SKIPPED unless the
    // user opted in (--beta) or is already running a prerelease — a beta tag
    // must never be pushed onto stable users.
    let beta_ok = beta || env!("CARGO_PKG_VERSION").contains('-');
    let releases: Value = client
        .get(format!("https://api.github.com/repos/{REPO}/releases?per_page=20"))
        .send()
        .await?
        .json()
        .await?;
    // semver-aware: never "update" to an older or equal release (betas of
    // the next version outrank the previous release; -pre < its release;
    // beta.2 > beta.1 — the prerelease NUMBER counts, found live when
    // `--beta` kept offering beta.1 to beta.2).
    fn key(v: &str) -> (u64, u64, u64, bool, u64) {
        let (core, pre) = v.split_once('-').map(|(c, p)| (c, Some(p))).unwrap_or((v, None));
        let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        let pre_num = pre.and_then(|p| p.rsplit('.').next()).and_then(|n| n.parse().ok()).unwrap_or(0);
        (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0), pre.is_none(), pre_num)
    }
    // Pick the HIGHEST eligible version, not the first listed — the API's
    // order is not newest-tag-first (observed live: cli-v0.2.0 listed above
    // cli-v0.2.1-beta.1, which made --beta serve stable).
    let latest = releases
        .as_array()
        .and_then(|a| {
            a.iter()
                .filter(|r| {
                    r["tag_name"].as_str().is_some_and(|t| t.starts_with("cli-v"))
                        && (beta_ok || !r["prerelease"].as_bool().unwrap_or(false))
                })
                .max_by_key(|r| key(r["tag_name"].as_str().unwrap_or_default().trim_start_matches("cli-v")))
        })
        .ok_or_else(|| anyhow!("no CLI release found"))?;
    let tag = latest["tag_name"].as_str().unwrap_or_default().to_string();
    let latest_ver = tag.trim_start_matches("cli-v").to_string();
    let current = env!("CARGO_PKG_VERSION");
    if key(&latest_ver) <= key(current) {
        println!("filament {current} is already the latest (released: {latest_ver})");
        return Ok(());
    }
    println!("update available: {current} -> {latest_ver}");
    if check_only {
        return Ok(());
    }

    let target = release_target().ok_or_else(|| anyhow!("no prebuilt binary for this platform; build from source"))?;
    let (asset, inner) = if cfg!(windows) {
        (format!("filament-{target}.zip"), "filament.exe")
    } else {
        (format!("filament-{target}.tar.gz"), "filament")
    };
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");

    ui::say(&format!("downloading {asset} ..."));
    let bytes = client.get(format!("{base}/{asset}")).send().await?.error_for_status()?.bytes().await?;
    let sums = client.get(format!("{base}/SHA256SUMS")).send().await?.error_for_status()?.text().await?;
    let got = sha256_hex(&bytes);
    let expected = sums
        .lines()
        .find(|l| l.contains(&asset))
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| anyhow!("{asset} missing from SHA256SUMS"))?;
    if got != expected {
        bail!("checksum mismatch for {asset}: got {got}, expected {expected}");
    }
    ui::say("checksum ok");

    // Unpack the single binary.
    let new_bin: Vec<u8> = if asset.ends_with(".tar.gz") {
        let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(&bytes[..]));
        let mut ar = tar::Archive::new(gz);
        let mut out = None;
        for entry in ar.entries()? {
            let mut e = entry?;
            if e.path()?.file_name().map(|n| n == inner).unwrap_or(false) {
                let mut v = Vec::new();
                e.read_to_end(&mut v)?;
                out = Some(v);
                break;
            }
        }
        out.ok_or_else(|| anyhow!("{inner} not found in archive"))?
    } else {
        bail!("zip self-update not supported yet; download {base}/{asset} manually");
    };

    // Atomic replace: write next to the current exe, then rename over it.
    let me = std::env::current_exe()?;
    let staging = me.with_extension("update-staging");
    std::fs::write(&staging, &new_bin)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&staging, &me).with_context(|| format!("replacing {}", me.display()))?;
    println!("updated to {latest_ver} -> {}", me.display());
    Ok(())
}

// ------------------------------------------------------------------- send --

struct Outgoing {
    id: String,
    sid: u32,
    name: String,
    size: u64,
    head: Option<String>,
    /// P4 (GAP-5): sha256 of the WHOLE file, carried in file-offer as `full`. The
    /// receiver compares its received bytes against this on completion and only
    /// accepts (and acks) on a match — so no transfer can "complete" truncated or
    /// corrupt. `None` only when the digest couldn't be computed (degrades to the
    /// legacy size-only check on the receiver — bounded, never a hang).
    full: Option<String>,
    path: PathBuf,
    temp: bool,          // delete after sending (tar spools, stdin spools)
    accepted_once: bool, // re-offers carry resume:true after first accept
    /// P4: the bytes left this side (stream finished / file-end sent). NOT the
    /// same as `done` anymore: a transfer is `sent` once but is only `done` after
    /// the receiver's whole-file-verified `delivery-ack` lands (or the bounded
    /// fallback fires for a peer too old to ack).
    sent: bool,
    /// P4: the receiver returned a verified `delivery-ack` for this id. This is
    /// the deterministic "it landed intact" signal — `send` completes only when
    /// every transfer is acked (or the bounded no-ack fallback declared it done).
    acked: bool,
    done: bool,
}

#[allow(clippy::too_many_arguments)]
async fn send_cmd(
    server: &str,
    paths: Vec<String>,
    use_code: bool,
    word: Option<String>,
    room: Option<String>,
    to: Option<String>,
    name: Option<String>,
    relay: bool,
    remember: Option<String>,
) -> Result<()> {
    if paths.is_empty() {
        bail!("nothing to send — pass files, directories, or '-' for stdin");
    }
    // --name overrides the offered name, but only makes sense for a SINGLE
    // payload (stdin, or one regular file). With multiple paths or a directory
    // there is no single name to override, so warn that it's ignored.
    if name.is_some() && paths.len() > 1 {
        ui::say(&ui::paint(ui::Tone::Warn, "--name is ignored when sending multiple paths"));
    }
    let single = paths.len() == 1;
    let my_uid = mk_uid("s");
    let mut outgoing: Vec<Outgoing> = Vec::new();
    for (i, p) in paths.iter().enumerate() {
        let sid = (i + 1) as u32;
        let id = format!("{}-{}", my_uid, sid);
        if p == "-" {
            let spool = std::env::temp_dir().join(format!("filament-stdin-{}", std::process::id()));
            let mut f = std::fs::File::create(&spool)?;
            let n = std::io::copy(&mut std::io::stdin().lock(), &mut f)?;
            drop(f);
            let head = head_hash(&spool);
            let full = full_hash(&spool);
            let offered = name.clone().filter(|_| single).unwrap_or_else(|| "stdin.bin".into());
            outgoing.push(Outgoing { id, sid, name: offered, size: n, head, full, path: spool, temp: true, accepted_once: false, sent: false, acked: false, done: false });
        } else {
            let path = PathBuf::from(p);
            let meta = std::fs::metadata(&path).with_context(|| format!("stat {p}"))?;
            if meta.is_dir() {
                if name.is_some() && single {
                    ui::say(&ui::paint(ui::Tone::Warn, "--name is ignored for a directory (it's tarred under the directory name)"));
                }
                let dirname = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dir".into());
                let spool = std::env::temp_dir().join(format!("filament-tar-{}-{}.tar", std::process::id(), i));
                ui::say(&format!("packing {p} -> {dirname}.tar ..."));
                {
                    let f = std::fs::File::create(&spool)?;
                    let mut b = tar::Builder::new(f);
                    b.append_dir_all(&dirname, &path)?;
                    b.finish()?;
                }
                let size = std::fs::metadata(&spool)?.len();
                let head = head_hash(&spool);
                let full = full_hash(&spool);
                outgoing.push(Outgoing { id, sid, name: format!("{dirname}.tar"), size, head, full, path: spool, temp: true, accepted_once: false, sent: false, acked: false, done: false });
            } else {
                // A single regular file with --name uses the override; otherwise
                // the basename. With multiple files --name was already warned off.
                let offered = name.clone().filter(|_| single).unwrap_or_else(|| {
                    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone())
                });
                let head = head_hash(&path);
                let full = full_hash(&path);
                outgoing.push(Outgoing { id, sid, name: offered, size: meta.len(), head, full, path, temp: false, accepted_once: false, sent: false, acked: false, done: false });
            }
        }
    }
    for o in &outgoing {
        ui::say(&format!("send: {} ({})", o.name, human(o.size)));
    }

    let room = match room {
        Some(r) => r,
        None => net::fetch_auto_room(server).await?,
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    // C30: the convergent session repairs room/channel/lease state the
    // one-shot emits lose (the fast path stays for old servers + latency);
    // under gate L these initial emits are exactly what the shim drops.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(room.clone());
    sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;

    // C12: --to matching a remembered device switches to identity mode —
    // subscribe to its presence channel and wait for known-peer.
    let known_target: Option<(String, String)> =
        to.as_ref().and_then(|t| devices_load().into_iter().find(|(n, _)| n.eq_ignore_ascii_case(t)));
    if let Some((n, sec)) = &known_target {
        ui::say(&format!("  waiting for known device {}", ui::paint(ui::Tone::Bold, n)));
        sess.channels = vec![channel_of(sec)];
        sess.emit(&sio, "subscribe", json!({ "channels": [channel_of(sec)] })).await;
    } else if use_code {
        let payload = match &word {
            Some(w) => json!({ "keyword": w }),
            None => json!({}),
        };
        sio.emit("pair-create", payload).await.ok();
    } else {
        ui::say(&format!("waiting for a peer in room {room} (same network auto-discovers; or use --code)"));
    }
    // Live spinner while nothing is connected yet (tty only; stops at adopt).
    let waiting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let waiting = waiting.clone();
        tokio::spawn(async move {
            while waiting.load(std::sync::atomic::Ordering::Relaxed) {
                ui::status(&format!("  {} waiting…", ui::spinner_frame()));
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
        });
    }

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid,
        relay,        // relay_only
        to,           // to_filter
        false,        // warm_standby default (one-shot send)
    );
    if known_target.is_some() {
        conn.to_filter = None; // identity supersedes name matching
    }
    let mut code_used = !use_code && known_target.is_none();
    // C30 phase 3: link mini-sync — pings out, divergence corrections in.
    let mut last_state_ping = Instant::now();
    let mut reproved: std::collections::HashSet<String> = Default::default();
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }
    let outgoing = Arc::new(tokio::sync::Mutex::new(outgoing));
    let started = Instant::now();
    let claim_deadline = Duration::from_secs(600);
    // Bug 6: bound ESTABLISHMENT. netcat/ssh cap how long they hunt for a peer;
    // `send` had no such bound, so an ICE wedge (no candidate pair ever
    // nominates) hung unbounded with the spinner spinning. Cap the time to the
    // FIRST live data channel (ChannelReady); once a channel is up, a long
    // legitimate transfer is never interrupted by this. Overridable / disablable
    // (0 = off) via FILAMENT_SEND_TIMEOUT.
    let establish_deadline = std::env::var("FILAMENT_SEND_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60));
    let mut established = false;
    // Bug 5: count stuck-while-connecting events to hint at the mDNS wedge once.
    let mut stuck_while_connecting = 0u32;
    let mut wedge_hint_shown = false;
    // P4 (delivery-ack BOUNDED FALLBACK): when every transfer's bytes have been
    // `sent` but the whole-file `delivery-ack` hasn't landed, we wait — but only
    // up to this bound, then declare done anyway so an OLD receiver (one that
    // verifies-on-size but never learned to send the ack) can never make `send`
    // hang forever. The link's data path drained (`drain_finish`) before we even
    // start waiting, so the bytes are on the wire; this only bounds the
    // KNOW-it-landed confirmation, never the delivery itself. Overridable via
    // FILAMENT_ACK_TIMEOUT (seconds; 0 disables the wait = legacy fire-and-forget).
    let ack_wait = std::env::var("FILAMENT_ACK_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(15));
    let mut sent_all_at: Option<Instant> = None;

    loop {
        // Bug 6: no data channel has come up within the establishment window —
        // an ICE wedge or a peer that claimed the code but never connected. Fail
        // honestly instead of spinning forever. A non-zero deadline only; a live
        // channel (established) disarms it so big transfers are never cut off.
        if !established
            && !establish_deadline.is_zero()
            && started.elapsed() >= establish_deadline
        {
            ui::clear_sticky();
            bail!(
                "no peer connected within {}s — is a receiver running / the page open? \
                 (set FILAMENT_SEND_TIMEOUT to change or 0 to disable)",
                establish_deadline.as_secs()
            );
        }
        // The wait-for-peer deadline only applies while we have no peer (F3).
        let ev = if conn.active.is_none() && conn.waiting_rejoin.is_none() {
            // C30: read in ≤2s slices — a blocking full-deadline read starves
            // the session tick, so a dropped initial subscribe was never
            // repaired and the wait could NEVER succeed (found by gate L's
            // seed-16 choreography: the daemon healed, the sender starved).
            if started.elapsed() >= claim_deadline {
                bail!("timed out waiting for a peer — is the other device online and on the same server? (--code makes pairing explicit)");
            }
            let slice = Duration::from_secs(2).min(claim_deadline.saturating_sub(started.elapsed()));
            match tokio::time::timeout(slice, rx.recv()).await {
                Ok(Some(ev)) => Some(ev),
                Ok(None) => bail!("signaling channel closed"),
                Err(_) => None, // tick
            }
        } else {
            next_ev(&mut rx, &conn, false).await?
        };
        // C30: converge session state every iteration (incl. ticks).
        sess.tick(&sio).await;
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // rung-1: a direct attempt that timed out without an authenticated QUIC
        // connection falls back to the WebRTC establish (unchanged path).
        for (pid, info, (n, sec)) in conn.expired_direct() {
            conn.establish(info).await?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
            if conn.to_filter.is_none() && conn.active.is_none() {
                conn.active = Some(pid.clone());
            }
        }
        // C30 phase 3: tell every link our truth every ~10s (sender side has
        // no receive-partials; the ping mainly carries trusted/away and keeps
        // the peer's away-mark honest).
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for l in conn.links.values() {
                if let Some(t) = &l.transport {
                    let _ = t
                        .send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": {},
                            "trusted": l.trusted,
                            "away": false,
                        }))
                        .await;
                }
            }
        }
        // P0 (GAP-1): bytes-moved STALL watchdog (send side). A transfer is in
        // flight once the active peer accepted an offer that isn't done; if that
        // link then moves zero bytes past the stall threshold (a black-holed data
        // path — the 0% hang) we emit Ev::TransferStalled, which drives the
        // correction ladder below. The control-channel liveness probe gates it so
        // a genuinely DEAD link falls to the C3/C4 path instead.
        if let Some(active) = conn.active.clone() {
            let in_flight = {
                let out = outgoing.lock().await;
                out.iter().any(|o| o.accepted_once && !o.done)
            };
            if let Some(idle) = conn.detect_stall(&active, in_flight) {
                if conn.link_alive(&active).await {
                    let _ = tx.send(Ev::TransferStalled(active, idle));
                } else {
                    // Control path also dead → not a data-only stall; let the
                    // establishment watchdog (C3/C4) own it. Clear the episode.
                    conn.note_progress(&active);
                }
            }
        }
        // P5 (GAP-6): relay->direct upgrade prober (send side). Probe for a direct
        // path while serving on relay; verify-before-upgrade cuts over only when a
        // direct standby is confirmed stable. No-op unless a peer is relay-committed
        // on an eligible session.
        conn.tick_upgrade_prober().await;
        let Some(ev) = ev else { continue };

        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                // P5 (GAP-6): a fresh signaling welcome (reconnect) is a moment a
                // new direct path may have appeared — re-probe immediately for any
                // relay-committed peer rather than waiting out the backoff.
                conn.reprobe_on_network_event();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, code_used).await?;
                    }
                }
                // C30 (dissolves the C28 belt): fresh sid = everything
                // sid-keyed is gone; invalidate and let the session re-assert.
                sess.invalidate();
            }
            // C30: server confirmed our session digest.
            Ev::Synced(v) => { sess.on_synced(&v); }
            Ev::PairCode(v) => {
                let code = v["code"].as_str().unwrap_or("?");
                let ttl = v["ttl"].as_u64().unwrap_or(600);
                let site = if server == DEFAULT_SERVER { "https://filament.autumated.com".to_string() } else { server.to_string() };
                let room_url = format!("{site}/rooms/{room}");
                ui::clipboard(code);
                ui::say("");
                ui::say(&format!("  code   {}   {}", ui::paint(ui::Tone::Brand, code), ui::paint(ui::Tone::Dim, "(copied to clipboard)")));
                ui::say(&format!("         {}", ui::paint(ui::Tone::Dim, &format!("terminal: filament recv {code}   browser: {} (PAIR WITH CODE)", ui::link(&site, &site.replace("https://", ""))))));
                let q = ui::qr(&room_url);
                if !q.is_empty() {
                    ui::say(&format!("\n{}", q.trim_end_matches('\n')));
                    ui::say(&format!("         {}", ui::paint(ui::Tone::Dim, &format!("or scan to join instantly · one claim · {} min", ttl / 60))));
                }
                ui::say("");
            }
            Ev::PairError(v) => bail!("pairing failed: {}", v["error"].as_str().unwrap_or("?")),
            Ev::PairUsed(_) => {
                ui::say("code claimed — connecting...");
                code_used = true;
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, code_used).await?;
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own daemon shares this channel
                }
                if let Some((n, sec)) = &known_target {
                    if v["channel"].as_str() == Some(channel_of(sec).as_str()) {
                        ui::say(&format!("known device '{n}' is online — connecting"));
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        // rung-1: both ends are CLIs (known device) — try direct
                        // QUIC FIRST. start_direct records the pending so the
                        // maybe_adopt->establish below skips the WebRTC offer
                        // until the budget expires (then it falls back).
                        let (n, sec) = (n.clone(), sec.clone());
                        conn.start_direct(&pid, &n, &sec).await;
                        conn.maybe_adopt(&v, true).await?;
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = Some((n.clone(), sec.clone()));
                        }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates — kick off the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    // rung-2: optional server-reflexive candidate for hole-punch.
                    let srflx = data["srflx"].as_str().map(String::from);
                    // P5 (GAP-6): a `probe:true` offer is a relay->direct UPGRADE
                    // probe from the other end. If we're serving this peer on relay
                    // and have no probe of our own yet, ARM one so the symmetric
                    // direct dial can complete (a later re-send of the offer — the
                    // peer re-emits 6x — is consumed by our now-armed pending). The
                    // winner posts DirectUpgradeReady (verify-before-upgrade), never
                    // clobbering the serving relay link.
                    if data["probe"].as_bool() == Some(true) {
                        conn.answer_upgrade_probe(&from).await;
                    }
                    conn.on_transport_offer(&from, cands, srflx);
                    continue;
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            // rung-1: the authenticated direct-QUIC connection won the race.
            // Create the (pre-trusted) Link, then funnel into the SAME ready
            // handler the WebRTC path uses (announce + offers) by re-emitting
            // ChannelReady — the transfer logic rides the trait unchanged.
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            // P5 (GAP-6): a relay->direct upgrade probe's direct standby connected
            // ALONGSIDE the live relay link. Do NOT adopt it (that would clobber the
            // serving relay link); stash it as a warm standby and enter VERIFY. The
            // per-tick prober (judge_upgrade_standby) decides whether to cut over
            // (sustained progress) or discard (no flap).
            Ev::DirectUpgradeReady(pid, t, route) => {
                conn.stash_upgrade_standby(&pid, t, route);
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                }
                // Responder links stop here: connected, polite, idle. Only
                // the active target gets announcements + offers.
                if !conn.is_active(&pid) {
                    continue;
                }
                // Bug 6: a live channel to the active peer disarms the
                // establishment timeout — the rest of the transfer is unbounded.
                established = true;
                waiting.store(false, std::sync::atomic::Ordering::Relaxed);
                if let Some(l) = conn.link(&pid) {
                    ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, &l.name)));
                    let is_direct = l.direct;
                    let direct_route = l.direct_route;
                    if let Some(p) = l.peer.clone() {
                        tokio::spawn(async move {
                            // ICE may renominate; retry briefly (mirrors the
                            // browser's _detectRoute attempts) so fast transfers
                            // still get a route line before the process exits.
                            for _ in 0..6 {
                                tokio::time::sleep(Duration::from_millis(400)).await;
                                if let Some(r) = p.route().await {
                                    // CRITICAL: the route label is the value-prop —
                                    // direct vs relayed. Always shown, even under -q.
                                    ui::critical(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {r}"))));
                                    // Relay honesty (§3.3): the quiet `route:` line
                                    // is legible but not loud. When the route is
                                    // actually the TURN relay, print the honest
                                    // one-line banner so the user is never unaware
                                    // they're on a middleman path. CRITICAL.
                                    if r == "relayed" {
                                        ui::critical(&format!("    {}", relay_banner()));
                                    }
                                    break;
                                }
                            }
                        });
                    } else if is_direct {
                        ui::critical(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {direct_route}"))));
                    }
                    // C12: prove identity to a known device (their daemon
                    // auto-accepts only after verifying); or hand over a new
                    // pair secret when the user asked to --remember. A DIRECT
                    // link already proved the secret via the QUIC keying-material
                    // MAC (>= the DTLS pair-proof), so it skips this dance.
                    if is_direct {
                        // pre-authenticated; nothing to prove over the channel.
                    } else if let Some((_n, sec)) = &l.expected_secret {
                        if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                            t.send_control(&json!({
                                "type": "pair-proof",
                                "mac": proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                            })).await?;
                        } else {
                            ui::say(&ui::paint(ui::Tone::Warn, "no DTLS fingerprints available — skipping identity proof"));
                        }
                    } else if let (Some(name), true) = (&remember, use_code) {
                        let sec = fresh_secret();
                        t.send_control(&json!({ "type": "pair-keep", "secret": sec })).await?;
                        devices_store(name, &sec)?;
                        ui::say(&format!("remembered this device as '{name}' (they must also pass --remember)"));
                    }
                    // (Re-)offer everything unfinished; resume:true after a
                    // prior accept so receivers continue from their partial.
                    for o in outgoing.lock().await.iter() {
                        if o.done {
                            continue;
                        }
                        let mut offer = json!({
                            "type": "file-offer", "id": o.id, "sid": o.sid,
                            "name": o.name, "size": o.size, "mime": "application/octet-stream",
                        });
                        if let Some(h) = &o.head {
                            offer["head"] = json!(h);
                        }
                        if let Some(f) = &o.full {
                            offer["full"] = json!(f);
                        }
                        if o.accepted_once {
                            offer["resume"] = json!(true);
                        }
                        t.send_control(&offer).await?;
                    }
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                _ if !conn.is_active(&pid) => {}
                Some("brb") => {
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.away = Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    ui::say(&conn.roster(&pid, "●", ui::Tone::Warn, "away — holding the line", &n));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                // C30 phase 3: the peer's periodic truth — correct one-sided
                // beliefs instead of letting them persist.
                Some("state") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid); // a state ping proves they're not frozen
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                    // Transfer divergence: I believe it complete; the peer
                    // holds fewer bytes — the END/tail was lost. Re-offer.
                    if let Some(obj) = v["transfers"].as_object() {
                        let mut out = outgoing.lock().await;
                        for o in out.iter_mut() {
                            if let Some(b) = obj.get(&o.id).and_then(|x| x.as_u64()) {
                                if o.done && b < o.size {
                                    o.done = false; // not actually done
                                    // DEBUG — resilience internal (state-divergence re-offer).
                                    ui::debug(&ui::paint(ui::Tone::Warn, &format!("  state-diverged: {} — peer holds {b}/{}; re-offering", o.name, o.size)));
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let mut offer = json!({
                                            "type": "file-offer", "id": o.id, "sid": o.sid,
                                            "name": o.name, "size": o.size, "mime": "application/octet-stream",
                                            "resume": true,
                                        });
                                        if let Some(h) = &o.head {
                                            offer["head"] = json!(h);
                                        }
                                        if let Some(f) = &o.full {
                                            offer["full"] = json!(f);
                                        }
                                        let _ = t.send_control(&offer).await;
                                    }
                                }
                            }
                        }
                    }
                    // Trust divergence: they don't recognize us but we hold a
                    // pair secret for them — re-prove ONCE per link.
                    if v["trusted"].as_bool() == Some(false) && !reproved.contains(&pid) {
                        let proof = match conn.link(&pid) {
                            Some(l) => match &l.expected_secret {
                                Some((_n, sec)) => (match &l.peer { Some(p) => p.fingerprints().await, None => None })
                                    .map(|(my_fp, their_fp)| proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp)),
                                None => None,
                            },
                            None => None,
                        };
                        if let Some(mac) = proof {
                            if let Some(t) = conn.transport_of(&pid) {
                                let _ = t.send_control(&json!({ "type": "pair-proof", "mac": mac })).await;
                                reproved.insert(pid.clone());
                                ui::debug(&ui::paint(ui::Tone::Dim, "  state-diverged: re-proving identity"));
                            }
                        }
                    }
                }
                // C27: the human on the other side answered our remember offer.
                Some("pair-keep-ack") => {
                    if let Some(name) = &remember {
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if v["ok"].as_bool() == Some(false) {
                            devices_remove(name)?;
                            ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "declined to be remembered — nothing stored", &n));
                        } else {
                            ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "mutually remembered — you'll reconnect automatically", &n));
                        }
                    }
                }
                // C27: their verdict on our identity proof. false = they have
                // no memory of us — stop acting like a known device.
                Some("pair-proof-ack") => {
                    if v["ok"].as_bool() == Some(false) {
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = None;
                        }
                        ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "doesn't recognize this device — re-pair with --remember", &n));
                    }
                }
                Some("file-accept") => {
                    let Some(t) = conn.transport() else { continue };
                    let offset = v["offset"].as_u64().unwrap_or(0);
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    {
                        let mut out = outgoing.lock().await;
                        if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                            o.accepted_once = true;
                        }
                    }
                    let out = outgoing.clone();
                    let chunk = conn.chunk_size.min(t.max_payload());
                    let tx2 = tx.clone();
                    // #28 test hook: the active peer's sid, so the streamer can
                    // synthesize a peer-left for it mid-flight (see stream_one).
                    let active_sid = conn.active.clone();
                    tokio::spawn(async move {
                        match stream_one(out, t, id.clone(), offset, chunk, active_sid, tx2.clone()).await {
                            Ok(()) => {
                                let _ = tx2.send(Ev::TransferDone(id));
                            }
                            Err(e) => {
                                // C10: surface through the loop; the transfer
                                // stays pending and re-offers on reconnect.
                                let _ = tx2.send(Ev::TransferFailed { id, err: e.to_string() });
                            }
                        }
                    });
                }
                Some("file-decline") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        ui::say(&format!("declined: {}", o.name));
                        o.done = true;
                    }
                }
                // P4 (delivery-ack): the receiver computed the whole-file sha256
                // of every byte it received and it MATCHED our offered digest —
                // the bytes landed INTACT. Only now is the transfer truly `done`
                // (vs the old fire-and-forget where `file-end` alone "completed"
                // it). This closes the loop the runner had to fake above the
                // transport: the sender deterministically KNOWS it landed whole.
                Some("delivery-ack") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        if !o.acked {
                            o.acked = true;
                            o.done = true;
                            ui::say(&ui::paint(ui::Tone::Dim, &format!("    {} delivered + verified (whole-file sha256 matched)", o.name)));
                        }
                    }
                }
                _ => {}
            },
            Ev::TransferFailed { id, err } => {
                let out = outgoing.lock().await;
                let name = out.iter().find(|o| o.id == id).map(|o| o.name.as_str()).unwrap_or("?");
                // DEBUG — resilience internal (transfer interrupted, will resume).
                ui::debug(&format!("{name}: interrupted ({err}) — will resume on reconnect"));
            }
            // P0 (GAP-1): the bytes-moved watchdog declared this transfer stalled.
            // Drive the least-disruptive correction ladder, preserving the on-disk
            // partial at every rung (C7 resume).
            Ev::TransferStalled(pid, idle_ms) => {
                if !conn.is_active(&pid) {
                    continue; // only the transfer-target peer's stall matters
                }
                // DEBUG — resilience internal (stall detection).
                ui::debug(&ui::paint(ui::Tone::Warn, &format!("  stall detected: {idle_ms}ms with no data — correcting")));
                match conn.correct_stall(&pid).await {
                    Rung::Resume => {
                        // Rung (a): re-issue every unfinished transfer with
                        // resume:true on the SAME transport. The receiver's
                        // file-accept carries its `.part` offset, so streaming
                        // continues from where it stalled (no restart-from-zero).
                        if let Some(t) = conn.transport_of(&pid) {
                            let out = outgoing.lock().await;
                            for o in out.iter().filter(|o| o.accepted_once && !o.done) {
                                let mut offer = json!({
                                    "type": "file-offer", "id": o.id, "sid": o.sid,
                                    "name": o.name, "size": o.size,
                                    "mime": "application/octet-stream", "resume": true,
                                });
                                if let Some(h) = &o.head {
                                    offer["head"] = json!(h);
                                }
                                if let Some(f) = &o.full {
                                    offer["full"] = json!(f);
                                }
                                let _ = t.send_control(&offer).await;
                            }
                        }
                    }
                    // Rung (c): the transport was repaired in place inside
                    // correct_stall (fresh direct dial / ICE-restart). The new
                    // transport's ChannelReady re-offers the unfinished transfers
                    // (resume:true) — nothing more to do here.
                    Rung::Repaired => {}
                    // Rung (d) P1: correct_stall re-established this transfer over
                    // the TURN relay (relay-only ICE), preserving the partial. The
                    // fresh relay link's ChannelReady re-offers the unfinished
                    // transfers (resume:true) and prints the route — nothing more
                    // to do here.
                    Rung::Relayed => {}
                    // Direct rungs spent AND relay forbidden (--no-relay) or relay
                    // itself stalled: the ladder failed CLEANLY (a kept partial, the
                    // clear cause already shown in correct_stall). PROMPTLY end the
                    // send rather than letting the frozen transfer hang to a timeout
                    // — the hard direct-only promise is "fail clean, fast", never a
                    // hang. The receiver kept its `.part`, so re-running resumes.
                    Rung::Exhausted => {
                        // The hard direct-only promise is "fail clean AND FAST" — never
                        // a hang. A signaling socket wedged by the same frozen path can
                        // make `disconnect()` itself block, so BOUND it: a 2s cap keeps
                        // the exit prompt (we're tearing down anyway; the OS reaps the
                        // socket). This only affects the already-failing path — it can
                        // never delay or alter a successful send.
                        let _ = tokio::time::timeout(Duration::from_secs(2), sio.disconnect()).await;
                        if relay_forbidden() {
                            bail!("couldn't establish a direct path and relay is disabled (--no-relay) — partial kept; re-run to resume, or drop --no-relay");
                        }
                        bail!("transfer stalled and no usable path remains — partial kept; re-run to resume");
                    }
                }
            }
            Ev::Interrupted => {
                ui::say(&format!("  {} interrupted — the receiver keeps its partial; re-run the same command to resume", ui::paint(ui::Tone::Warn, "!")));
                let _ = sio.disconnect().await;
                std::process::exit(130);
            }
            Ev::Stuck(pid, generation) => {
                // Bug 5: if we keep getting stuck BEFORE a channel ever came up,
                // surface the single-host mDNS hint once.
                if !established {
                    stuck_while_connecting += 1;
                    if stuck_while_connecting >= 2 {
                        maybe_hint_local_wedge(&mut wedge_hint_shown);
                    }
                }
                if conn.on_stuck(&pid, generation, "stuck while connecting").await? {
                    bail!("lost the receiving peer after {} attempts", MAX_ATTEMPTS);
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? {
                    bail!("lost the receiving peer after {} attempts", MAX_ATTEMPTS);
                }
            }
            Ev::PcState(pid, s) => conn.on_pc_state(&pid, &s).await,
            Ev::PeerLeft(v) => {
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let all_done = outgoing.lock().await.iter().all(|o| o.done);
                    if !all_done {
                        let secs = REJOIN_WINDOW.as_secs();
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => ui::say(&conn.roster(gid, "○", ui::Tone::Dim, &format!("disconnected — waiting up to {secs}s"), &n)),
                            // DEBUG — resilience internal (peer-disconnect wait).
                            None => ui::debug(&format!("peer disconnected — waiting up to {secs}s for them to come back")),
                        }
                    }
                }
            }
            _ => {}
        }
        // P4: every transfer's BYTES have left this side (`sent`), but a transfer
        // is only truly `done` once the receiver returns a whole-file-verified
        // `delivery-ack`. Drain the wire first (so the bytes are actually on it,
        // not parked in a send buffer), then WAIT — bounded by `ack_wait` — for
        // the ack. A modern receiver acks within a round-trip of finishing its
        // verify; an OLD receiver (verifies-on-size, never learned the ack) never
        // sends one, so after the bound we declare it done anyway rather than hang
        // (graceful backward-compat). The wait is on the KNOW-it-landed signal,
        // never on delivery — the drain already put the bytes on the wire.
        {
            let mut out = outgoing.lock().await;
            let all_sent = !out.is_empty() && out.iter().all(|o| o.sent);
            let all_acked = !out.is_empty() && out.iter().all(|o| o.done);
            if all_sent && !all_acked {
                if sent_all_at.is_none() {
                    sent_all_at = Some(Instant::now());
                    // Flush (NOT drain_finish) on first reaching the all-sent point:
                    // push the wire so the receiver can finish + verify + ack. We do
                    // NOT call drain_finish here because on direct-QUIC that ends the
                    // send half (`finish()`) — which would block a corrupt-case
                    // RE-FETCH that needs to stream more bytes. The final exit block
                    // does the authoritative drain_finish once the ack lands (no more
                    // re-fetch possible by then). On a DataChannel both are just
                    // flush(); on QUIC this keeps the stream open for a resume.
                    if let Some(t) = conn.transport() {
                        let _ = t.flush().await;
                    }
                }
                // Bounded fallback: ack never came (old/ack-less peer) — accept on
                // size, note it honestly, stop waiting. ack_wait==0 disables the
                // wait entirely (explicit legacy fire-and-forget).
                if sent_all_at.map(|t| t.elapsed() >= ack_wait).unwrap_or(false) {
                    for o in out.iter_mut().filter(|o| !o.done) {
                        ui::say(&ui::paint(ui::Tone::Warn, &format!(
                            "  {}: no delivery-ack within {}s — peer may be too old to confirm; accepting on size (bytes were delivered + drained)",
                            o.name, ack_wait.as_secs()
                        )));
                        o.done = true;
                    }
                }
            }
        }
        // Exit when every transfer reached a terminal state (`done` = acked, or the
        // bounded-fallback / un-hashable cases above).
        {
            let out = outgoing.lock().await;
            if !out.is_empty() && out.iter().all(|o| o.done) {
                if let Some(t) = conn.transport() {
                    // Block until the peer has acked every byte before we exit —
                    // a torn-down QUIC connection drops un-acked send-buffer bytes
                    // and truncates the last file (no-op on DataChannel, which
                    // already drained in flush()). Surface a drain failure rather
                    // than silently reporting "done" on a partial transfer.
                    if let Err(e) = t.drain_finish().await {
                        // CRITICAL — a possibly-incomplete delivery; must-see even under -q.
                        ui::critical(&ui::paint(ui::Tone::Warn, &format!("warning: transfer may be incomplete — {e}")));
                    }
                }
                for o in out.iter().filter(|o| o.temp) {
                    let _ = std::fs::remove_file(&o.path);
                }
                ui::say("done.");
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = sio.disconnect().await;
                return Ok(());
            }
        }
    }
}

async fn stream_one(
    outgoing: Arc<tokio::sync::Mutex<Vec<Outgoing>>>,
    t: Arc<dyn Transport>,
    id: String,
    offset: u64,
    chunk: usize,
    active_sid: Option<String>,
    tx: mpsc::UnboundedSender<Ev>,
) -> Result<()> {
    let (sid, name, size, path) = {
        let out = outgoing.lock().await;
        let o = out.iter().find(|o| o.id == id).ok_or_else(|| anyhow!("unknown transfer {id}"))?;
        (o.sid, o.name.clone(), o.size, o.path.clone())
    };
    if offset > 0 {
        // DEBUG — resilience internal (transfer resuming from a saved offset).
        ui::debug(&format!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0));
    }
    // #28 deterministic test hook: once we cross this byte offset, synthesize a
    // peer-left for the ACTIVE peer WITHOUT touching the data channel — exactly
    // the "signaling reconnect mid-transfer, channel stays alive" case. The
    // deferred-drop path must keep the link and let the transfer finish on it.
    // Injecting the active sid is critical: a wrong id makes on_peer_left
    // return early (link-not-found) and the test would falsely pass.
    let inject_at: Option<u64> = test_hooks::inject_peer_left_at();
    let mut injected = false;
    let mut f = std::fs::File::open(&path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut sent = offset;
    let mut buf = vec![0u8; chunk];
    let mut bar = ui::Progress::new(&name, size);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        t.send_frame(sid, &buf[..n]).await?;
        sent += n as u64;
        bar.tick(sent);
        if let (false, Some(at), Some(asid)) = (injected, inject_at, active_sid.as_ref()) {
            if sent >= at {
                injected = true;
                eprintln!("[test] injecting synthetic peer-left for active sid at {sent} bytes");
                let _ = tx.send(Ev::PeerLeft(json!({ "id": asid })));
            }
        }
    }
    t.send_control(&json!({ "type": "file-end", "id": id, "sid": sid })).await?;
    t.flush().await?;
    bar.done(sent - offset);
    let mut out = outgoing.lock().await;
    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
        // P4: the bytes + file-end left this side — but the transfer is NOT
        // `done` yet. It is `done` only once the receiver returns a whole-file-
        // verified `delivery-ack` (or the bounded no-ack fallback fires). A peer
        // that has nothing more to send for THIS file is `sent`; the all-done
        // exit waits on `acked`. If this file carries no `full` digest (we
        // couldn't hash it), there's nothing for the receiver to verify-and-ack,
        // so it's done on send — the legacy fire-and-forget behaviour, scoped to
        // exactly the un-hashable case.
        o.sent = true;
        if o.full.is_none() {
            o.acked = true;
            o.done = true;
        }
    }
    Ok(())
}

// ------------------------------------------------------------------- recv --

struct IncomingFile {
    id: String,
    name: String,
    size: u64,
    received: u64,
    file: tokio::io::BufWriter<tokio::fs::File>,
    part_path: PathBuf,
    /// P4 (GAP-5): the whole-file sha256 the SENDER offered (`full`). On
    /// completion we hash the received `.part` and compare — only a match
    /// finalizes + acks. `None` = the sender offered no digest (old peer / an
    /// un-hashable source); we fall back to the legacy size-only acceptance and
    /// do NOT ack (nothing to verify), which the sender's bounded fallback covers.
    full: Option<String>,
    bar: ui::Progress,
}

#[allow(clippy::too_many_arguments)]
async fn recv_cmd(
    server: &str,
    code: Option<String>,
    dir: PathBuf,
    yes: bool,
    room: Option<String>,
    to: Option<String>,
    keep_open: bool,
    relay: bool,
    remember: Option<String>,
    daemon: bool,
    output: Option<String>,
    shell_policy: ShellPolicy,
    // M-1: optional non-root account the web-shell/ssh PTY is dropped to. `None`
    // means the PTY runs as the up-process user (documented root risk).
    shell_user: Option<String>,
) -> Result<()> {
    let to_stdout = output.as_deref() == Some("-");
    // Bug 4: a 4-segment PAKE pairing code (adj-animal-extra-NNNN) was typed
    // into `recv`, which only claims 3-segment transfer codes — fail with a
    // clear redirect instead of a silent never-connect.
    if let Some(c) = &code {
        if looks_like_pake_code(c) && !regex_lite_code(c) {
            bail!(
                "'{c}' looks like a PAIRING code (from `filament pair`), not a transfer code.\n  \
                 To pair a device: run `filament pair {c}`\n  \
                 A transfer code looks like `brave-otter-37` (one fewer word)."
            );
        }
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let my_uid = mk_uid("r");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    // P2 (GAP-2): `mut` so the long-lived acceptor's outer reconnect loop can
    // swap in a freshly-dialed signaling client after a drop (see below). The
    // short-lived `recv`/`send` paths never reconnect — they re-invoke fresh —
    // so this is only exercised by the daemon (`up`/`up --dir`).
    let mut sio = net::connect_signaling(server, tx.clone()).await?;

    let mut paired = code.is_some();
    // C24: at most one typed claim in flight — a second typed code while one
    // is pending was silently dropped in live use; now it queues a message.
    let mut claim_in_flight = false;
    // C29: an in-session pairing ceremony (daemon mode): typed code or a
    // minted one — exactly ONE side hands over a fresh secret (creator
    // initiates; a claimer waits 3 s for the creator, then takes over —
    // browsers never initiate). Some(true) = we minted; Some(false) = we
    // claimed; None = no ceremony pending.
    let mut ceremony: Option<bool> = None;
    let mut ceremony_pid: Option<String> = None;
    let mut ceremony_secret = fresh_secret();
    // C25: when the current question appeared (answers sooner than 300ms are
    // buffered keystrokes, not decisions)
    let mut question_shown = Instant::now();
    let mut devices = devices_load(); // channel -> identity lookup for proofs
    // C30: the convergent session repairs whatever the one-shot emits below
    // lose — room membership, channel subscriptions, the lease. The emits
    // stay as the fast path (and old-server compat); the session is truth.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.channels = devices.iter().map(|(_, s)| channel_of(s)).collect();
    match &code {
        Some(c) => {
            sio.emit("pair-claim", json!({ "code": c.trim().to_lowercase() })).await.ok();
        }
        None if daemon => {
            // C19: the daemon joins NO room. Presence-channel subscriptions
            // only — strangers can't see it, probe it, or offer to it.
            // (We still `join` an unguessable solo room so the registry holds
            // our meta for known-peer events, but nobody else can land there.)
            let solo = format!("up-{}", fresh_secret());
            sess.room = Some(solo.clone());
            sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
            // C29: an interactive up can START empty and pair in-session.
            if devices.is_empty() && !std::io::stdin().is_terminal() {
                bail!("no known devices — run `filament pair` once, or `filament up` in a terminal to pair interactively");
            }
            let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
            sess.emit(&sio, "subscribe", json!({ "channels": chans })).await;
            ui::say(&format!(
                "  {} filament up — {} known device{} {} {}",
                ui::paint(ui::Tone::Brand, "●"),
                devices.len(),
                if devices.len() == 1 { "" } else { "s" },
                ui::glyph_arrow(),
                ui::paint(ui::Tone::Bold, &dir.display().to_string()),
            ));
            ui::say(&ui::paint(ui::Tone::Dim, "  trusted devices only · invisible to strangers · Ctrl-C or `filament down` to stop"));
            // C29: this is a SESSION, like a browser tab — pairing and petname
            // management happen right here.
            if std::io::stdin().is_terminal() {
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  type a code to pair a new device · `pair` mints one · `devices` · `forget <name>`",
                ));
            }
        }
        None => {
            let room = match &room {
                Some(r) => r.clone(),
                None => net::fetch_auto_room(server).await?,
            };
            // C22: proactive affordance — tell the user what they CAN do,
            // cargo-style gutter, before they have to guess.
            ui::say(&format!(
                "  {} listening — same-network devices appear automatically  {}",
                ui::paint(ui::Tone::Brand, "●"),
                ui::paint(ui::Tone::Dim, &format!("(room {room} · dir {})", dir.display())),
            ));
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  have a code? just type it here (like brave-otter-123) and press Enter",
            ));
            sess.room = Some(room.clone());
            sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            // C12: announce on every known device's presence channel
            if !devices.is_empty() {
                let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
                ui::say(&format!("watching for {} known device(s)", devices.len()));
                sess.emit(&sio, "subscribe", json!({ "channels": chans })).await;
            }
        }
    }

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid.clone(),
        relay,        // relay_only
        to,           // to_filter
        // P3 (GAP-3): the `up`/`up --shell` daemon acceptor is the canonical
        // long-lived / interactive session, so warm redundancy defaults ON for it
        // (a one-shot `recv` keeps daemon=false -> OFF).
        daemon,       // warm_standby default
    );
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }
    #[cfg(unix)]
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                term.recv().await;
                let _ = tx.send(Ev::Interrupted);
            }
        });
    }
    // A listening recv accepts a code typed straight into it — the first
    // thing real users try (observed live). C22: stdin runs RAW (cbreak) on a
    // tty so an open y/N question resolves on a single keypress, no Enter;
    // outside a question, bytes accumulate into lines (echoed manually since
    // raw mode disables terminal echo).
    let question_open = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // C29: the stdin owner also runs for an INTERACTIVE daemon (a terminal-
    // attached `filament up` is a session); `up --install` under systemd has
    // no tty, so headless daemons stay stdin-free.
    let interactive = !daemon || std::io::stdin().is_terminal();
    let tty_guard = if interactive && std::io::stdin().is_terminal() { Some(TtyGuard::raw()) } else { None };
    if interactive {
        let tx = tx.clone();
        let q = question_open.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 1];
            let mut line = String::new();
            while stdin.read(&mut buf).await.map(|n| n == 1).unwrap_or(false) {
                let c = buf[0] as char;
                if q.load(std::sync::atomic::Ordering::Relaxed) && "yYnN".contains(c) && line.is_empty() {
                    ui::answer_echo(c); // raw mode is no-echo; land it cleanly (C23)
                    let _ = tx.send(Ev::StdinLine(c.to_lowercase().to_string()));
                    continue;
                }
                match buf[0] {
                    b'\n' | b'\r' => {
                        eprintln!();
                        let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                        line.clear();
                    }
                    0x7f | 0x08 => {
                        if line.pop().is_some() {
                            eprint!("\x08 \x08");
                        }
                    }
                    _ if !c.is_control() => {
                        eprint!("{c}");
                        line.push(c);
                    }
                    _ => {}
                }
            }
        });
    }
    let mut by_sid: HashMap<(String, u32), IncomingFile> = HashMap::new();
    // P4 (GAP-5): per-transfer count of whole-file-verify FAILURES (the digest
    // didn't match on completion). Each failure re-requests a resume (truncated)
    // or a from-zero re-fetch (corrupt body); bounded so a genuinely
    // unrecoverable corruption fails CLEARLY after a few rounds rather than
    // looping forever. Keyed by transfer id.
    let mut verify_fails: HashMap<String, u32> = HashMap::new();
    // C22: offers awaiting consent — exactly ONE stdin owner (the reader
    // task); answers arrive as StdinLine events, never via a competing
    // blocking read racing for the user's "y".
    let mut pending: std::collections::VecDeque<(String, Value)> = Default::default();
    let mut completed = 0usize;
    // G-k: peer-left delivery is best-effort — a browser can close having
    // delivered every byte yet never emit its leave (observed under load,
    // gate 6). Tick the loop on a 2s timeout so a fallback quiet-check can
    // exit cleanly instead of idling to the connect-timeout.
    let mut last_quiet: Option<Instant> = None;
    let quiet_window = quiet_exit_window();
    // C30 phase 2: roster reconciliation from sync digests — a missed
    // peer-joined/left self-corrects. Absence must hold for TWO consecutive
    // digests before a drop (one digest can race a join in flight).
    let mut digest_absent: HashMap<String, u8> = HashMap::new();
    let mut digest_alone = false;
    // C30 phase 3: link mini-sync — state pings every ~10s per link.
    let mut last_state_ping = Instant::now();
    // L2 (ssh/TCP tunnel) acceptor: one mux per link, created on the first
    // l2-open seen on that link. OFF unless FILAMENT_L2=1 (opt-in) OR an active
    // `up --shell` policy turns it on (you can't ssh in without the acceptor).
    // The cap gate (shell-bootstrap) is enforced separately. Keyed by peer sid
    // so multiple links stay isolated.
    let l2_enabled = shell_policy.enables_l2()
        || std::env::var("FILAMENT_L2").map(|v| v == "1").unwrap_or(false);
    let mut l2_muxes: HashMap<String, Arc<l2::Mux>> = HashMap::new();
    // web-shell: per-sid resize senders are now owned by each Mux (l2.rs) so they
    // are freed on every teardown path (H-1: closes the prior pty_resizers leak).
    // Bug 5: surface the single-host mDNS wedge hint once after repeated stuck.
    let mut stuck_while_connecting = 0u32;
    let mut wedge_hint_shown = false;
    let mut ever_received = false;
    // C12 live-pairing: the roster (`devices`) is loaded ONCE at startup, and
    // KnownPeer events only fire for channels we've SUBSCRIBED. A device paired
    // into the shared store by a SEPARATE `filament pair` process AFTER the
    // daemon is up was therefore invisible until restart — it never got a
    // subscription, so its "appeared — connecting" flow never fired and it
    // could not connect (no transfer, no web-shell). We now re-scan the store
    // on a modest cadence and subscribe to any NEW device's channel live; the
    // session digest (which includes `sess.channels`) repairs a lost subscribe
    // on the next tick. Existing channels and live links are untouched.
    let mut known_channels: std::collections::HashSet<String> =
        devices.iter().map(|(_, s)| channel_of(s)).collect();
    let mut last_devices_scan = Instant::now();

    // P2 (GAP-2): outer reconnect / re-announce loop state for the long-lived
    // acceptor. `reconnect(false)` means a severed signaling TCP leaves the
    // socket dead with NO further events — the acceptor zombies and the sender
    // can't rediscover it (the documented `no peer connected` failure that
    // up_supervisor.sh patched from outside the binary). We close it IN-CORE:
    //  - `last_signaling`  : monotonic time of the last inbound signaling event;
    //                        any inbound Ev that originates from the socket bumps
    //                        it (welcome/synced/peer-*/signal/known-peer/...).
    //  - silence watchdog  : if it goes silent past `signaling_silence_ms` (and
    //                        a forced `sync` emit doesn't restore it), the link
    //                        is dead — re-dial. This is the AUTHORITATIVE trigger
    //                        because a hard TCP sever fires no close callback.
    //  - Ev::SignalingDown : the socket.io close/error fast-path accelerant.
    // Only the daemon acceptor self-heals (`signaling_self_heal`); the one-shot
    // recv/send paths re-invoke fresh, so they keep failing fast (unchanged).
    // FILAMENT_TEST_NO_SIGNALING_RECONNECT reverts to the OLD no-outer-loop path
    // so the signaling-drop gate's A/B baseline can prove the acceptor ZOMBIES
    // without the fix (the detector/loop is load-bearing, not incidental).
    let signaling_self_heal = daemon && !test_hooks::no_signaling_reconnect();
    let mut last_signaling = Instant::now();
    let mut signaling_down_since: Option<Instant> = None;
    let mut reconnect_attempt: u32 = 0;
    let mut last_reconnect_try = Instant::now();
    let mut probed_silence = false; // fired one forced sync before declaring down

    loop {
        let ev = match tokio::time::timeout(
            Duration::from_secs(2),
            next_ev(&mut rx, &conn, !pending.is_empty()),
        )
        .await
        {
            Ok(res) => res?,
            Err(_) => None, // 2s tick — run the fallback quiet-check below
        };

        // C30: converge session state (no-op unless diverged/stale/unconfirmed).
        sess.tick(&sio).await;

        // P2 (GAP-2): the OUTER RECONNECT / RE-ANNOUNCE loop for the long-lived
        // acceptor. Runs only in the daemon path; the one-shot recv/send paths
        // re-invoke fresh on failure and so never need it.
        if signaling_self_heal {
            // (1) Liveness accounting. Any inbound signaling event proves the
            // socket is alive; a successful `sync` ack (Ev::Synced) is the
            // strongest signal (the server answered). The fast-path close/error
            // callback marks the link down immediately.
            let mut saw_down = false;
            match &ev {
                Some(Ev::SignalingDown(_)) => saw_down = true,
                Some(
                    Ev::Welcome(_) | Ev::Synced(_) | Ev::PeerJoined(_) | Ev::PeerLeft(_)
                    | Ev::Signal(_) | Ev::KnownPeer(_) | Ev::KnownPeerLeft(_) | Ev::PairMatched(_)
                    | Ev::PairOk(_) | Ev::PairCode(_) | Ev::PairUsed(_) | Ev::PairError(_),
                ) => {
                    last_signaling = Instant::now();
                    signaling_down_since = None;
                    probed_silence = false;
                    reconnect_attempt = 0;
                }
                _ => {}
            }

            // (2) Silence watchdog — the AUTHORITATIVE trigger. A hard TCP sever
            // fires no close callback, so we watch the inbound gap. Once it
            // exceeds the threshold, fire ONE forced `sync` (the heartbeat); if
            // the socket is alive the server's `synced` ack lands within a tick
            // and resets the gap. If a second threshold passes with still no
            // event, the socket is dead — declare it down.
            let silence = net::signaling_silence_ms();
            let silent_ms = last_signaling.elapsed().as_millis() as u64;
            if signaling_down_since.is_none() {
                if saw_down {
                    signaling_down_since = Some(Instant::now());
                    last_reconnect_try = Instant::now() - Duration::from_secs(60); // re-dial now
                    // DEBUG — resilience internal (signaling reconnect).
                    ui::debug(&ui::paint(ui::Tone::Warn, "  signaling link closed — reconnecting"));
                } else if silent_ms >= silence {
                    if !probed_silence {
                        // Heartbeat probe: force a sync NOW (bypassing the C30
                        // cadence). A live socket answers; a dead one won't.
                        probed_silence = true;
                        sess.touch();
                        sess.tick(&sio).await;
                    } else if silent_ms >= silence.saturating_mul(2) {
                        signaling_down_since = Some(Instant::now());
                        last_reconnect_try = Instant::now() - Duration::from_secs(60);
                        // DEBUG — resilience internal (signaling reconnect).
                        ui::debug(&ui::paint(ui::Tone::Warn, &format!("  signaling silent for {silent_ms}ms — reconnecting")));
                    }
                }
            }

            // (3) Re-dial with backoff + jitter. Idempotent: a fresh `welcome`
            // re-asserts room + channel subscriptions through the C30 session
            // (sess.invalidate forces it next tick). Live DATA links are NOT torn
            // down — they ride independent WebRTC/QUIC transports and keep
            // flowing across the cosmetic signaling reconnect (the #28 contract).
            if let Some(down_at) = signaling_down_since {
                // backoff: 0.5s, 1s, 2s, 4s … capped at 8s, +/-25% jitter.
                let base = 500u64.saturating_mul(1 << reconnect_attempt.min(4)).min(8_000);
                let jitter = (down_at.elapsed().as_nanos() as u64 % (base / 2 + 1)) as i64 - (base as i64 / 4);
                let backoff = Duration::from_millis((base as i64 + jitter).max(100) as u64);
                if last_reconnect_try.elapsed() >= backoff {
                    last_reconnect_try = Instant::now();
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    let _ = sio.disconnect().await; // drop the dead client (no-op if already gone)
                    match net::reconnect_signaling(server, tx.clone()).await {
                        Ok(new_sio) => {
                            sio = new_sio;
                            conn.sio = sio.clone();
                            // C30: a fresh sid voids everything the server held —
                            // re-assert room + channels on the next tick. Re-fire
                            // the fast-path join/subscribe immediately too.
                            sess.invalidate();
                            if let Some(room) = sess.room.clone() {
                                sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
                            }
                            if !sess.channels.is_empty() {
                                let chans = sess.channels.clone();
                                sess.emit(&sio, "subscribe", json!({ "channels": chans })).await;
                            }
                            sess.tick(&sio).await;
                            // optimistic: a clean connect proves reachability; let
                            // the welcome confirm it (which resets the counters).
                            last_signaling = Instant::now();
                            signaling_down_since = None;
                            probed_silence = false;
                            // DEBUG — resilience internal (signaling reconnected).
                            ui::debug(&ui::paint(ui::Tone::Ok, "  signaling reconnected — re-announcing presence"));
                        }
                        Err(e) => {
                            // DEBUG — resilience internal (signaling reconnect retry).
                            ui::debug(&ui::paint(ui::Tone::Dim, &format!("  signaling reconnect failed ({e}) — retrying with backoff")));
                        }
                    }
                }
            }
        }

        // C12 live-pairing: pick up devices paired AFTER we started (a separate
        // `filament pair` writes them into the shared store atomically). Re-read
        // every ~2s, subscribe to any channel we don't already watch, and feed
        // them into `devices` so the KnownPeer handler recognizes them. We never
        // re-subscribe existing channels or touch live links. Daemon-only: a
        // one-shot `recv`/`send` has a fixed roster for its short lifetime.
        if daemon && last_devices_scan.elapsed() >= Duration::from_secs(2) {
            last_devices_scan = Instant::now();
            let mut new_chans: Vec<String> = Vec::new();
            for (n, s) in devices_load() {
                let ch = channel_of(&s);
                if known_channels.insert(ch.clone()) {
                    ui::say(&format!("new device '{n}' paired — now reachable"));
                    devices.push((n, s));
                    new_chans.push(ch);
                }
            }
            if !new_chans.is_empty() {
                // Fast-path emit now; the session digest carries the durable
                // subscription so a dropped emit self-repairs on the next tick.
                for ch in &new_chans {
                    if !sess.channels.contains(ch) {
                        sess.channels.push(ch.clone());
                    }
                }
                sess.emit(&sio, "subscribe", json!({ "channels": new_chans })).await;
            }
        }
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // rung-1: direct attempt timed out → fall back to WebRTC (unchanged).
        for (pid, info, (n, sec)) in conn.expired_direct() {
            conn.maybe_adopt(&info, true).await?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
        }

        // C30 phase 3: state pings — each open link hears our transfer/away
        // truth every ~10s, so one-sided beliefs between PEERS can't persist.
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for (pid, l) in &conn.links {
                if let Some(t) = &l.transport {
                    let mut transfers = serde_json::Map::new();
                    for ((p0, _), inc) in &by_sid {
                        if p0 == pid {
                            transfers.insert(inc.id.clone(), json!(inc.received));
                        }
                    }
                    let _ = t
                        .send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": Value::Object(transfers),
                            "trusted": l.trusted,
                            "away": false,
                        }))
                        .await;
                }
            }
        }

        // G-k completion sweep (top-of-loop): see sweep_completed_streams.
        sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;

        // Gate-18 Mode B: recompute the completion flag AFTER the sweep, every
        // tick (never sticky). When true, a stuck/lost link is DROPPED in
        // on_stuck instead of re-established — see Conn::recv_done. Refreshing it
        // here, where `completed`/`by_sid` were just settled, makes the gate-2/
        // gate-11c fence exact: a mid-transfer link (by_sid non-empty) sees
        // recv_done=false and reconnects unchanged.
        conn.recv_done = recv_transfer_done(completed, keep_open, by_sid.is_empty());
        if completed > 0 || !by_sid.is_empty() {
            ever_received = true; // a channel was up; Bug-5 wedge hint no longer applies
        }

        // P0 (GAP-1): bytes-moved STALL watchdog (RECEIVE side). The receiver is
        // the peer that visibly hangs at 0%: when an inbound transfer is in
        // flight (`by_sid` non-empty for a link) but no data byte has arrived
        // past the stall threshold, its transport's idle_ms() climbs. The
        // RECEIVER must also act so a direct-QUIC repair is SYMMETRIC — a fresh
        // authenticated QUIC connection needs both ends to re-dial. We emit
        // Ev::TransferStalled for each such link (liveness-gated), whose handler
        // re-arms this side's direct dial (rung c). The on-disk `.part` is kept,
        // so the resumed stream continues from the saved offset.
        {
            // Per-link: in_flight = this peer has an inbound file mid-transfer
            // (a by_sid entry) OR a stall episode is already open for it (the
            // .part was flushed to disk mid-repair, so by_sid is momentarily
            // empty — detect_stall keeps the episode alive until fresh progress).
            let all_pids: Vec<String> = conn.links.keys().cloned().collect();
            for pid in all_pids {
                let in_flight = by_sid.keys().any(|(p, _)| *p == pid);
                if let Some(idle) = conn.detect_stall(&pid, in_flight) {
                    if conn.link_alive(&pid).await {
                        let _ = tx.send(Ev::TransferStalled(pid, idle));
                    } else {
                        conn.note_progress(&pid);
                    }
                }
            }
        }

        // P5 (GAP-6): relay->direct upgrade prober (receive side). The `up` daemon
        // acceptor is the canonical long-lived session, so the prober defaults ON
        // here. Probe for a direct path while serving on relay; verify-before-
        // upgrade cuts over only on a confirmed-stable direct standby.
        conn.tick_upgrade_prober().await;

        // Gate-18 Mode B DETERMINISTIC repro hook: simulate the post-completion
        // FLAP that contention triggers in the wild (the sender's departure puts
        // the receiver's link into the C4 reconnect loop). Once everything is on
        // disk, force each surviving link to go stuck repeatedly — reset its
        // attempts (mirroring the real flap's attempts-reset, so MAX_ATTEMPTS
        // can never cap it) and re-inject Ev::Stuck. On the BASELINE (no fix)
        // on_stuck re-establishes → link persists → conn.links never empties →
        // hang to timeout (RC=124). WITH the fix on_stuck drops on recv_done →
        // links empties → no link to churn next tick → quiet-exit fires. Driven
        // at LOOP level (not inside on_stuck) so the A/B tests the fix, not
        // itself.
        if conn.recv_done && test_hooks::churn_after_complete() {
            let churn: Vec<(String, u32)> = conn
                .links
                .iter()
                .map(|(pid, l)| (pid.clone(), l.generation))
                .collect();
            for (pid, generation) in churn {
                if let Some(l) = conn.links.get_mut(&pid) {
                    l.attempts = 0; // mirror the real flap: cap never accumulates
                    // Tear the data channel down so on_stuck's is_connected()
                    // guard sees a dead link and the Stuck isn't swallowed.
                    if let Some(p) = &l.peer {
                        p.close().await;
                    }
                }
                let _ = conn.tx.send(Ev::Stuck(pid, generation));
            }
        }

        // #28 exit reconciliation: once everything is received and the only links
        // left are ones held open purely for their deferred-drop reap (their
        // sender's signaling left AFTER the transfer finished), there is nothing
        // in flight to protect — exit promptly instead of paying the full
        // FILAMENT_ADOPT_ACTIVE_MS deferral. Restores the pre-#28 prompt exit; an
        // in-progress reconnect keeps `by_sid` non-empty and so is unaffected.
        if completed > 0 && !keep_open && by_sid.is_empty() && pending.is_empty()
            && !conn.links.is_empty() && conn.only_deferred_links()
        {
            ui::say(&format!("done ({completed} file{}).", if completed == 1 { "" } else { "s" }));
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // Bug 2: the transfer is COMPLETE and the sender's link is fully GONE
        // (dropped via peer-left, or via the grace/Mode-B path when peer-left
        // was lost). With no live link and nothing left to fetch there is
        // nothing to wait for — exit at once instead of holding out the full
        // rejoin window (peer-left case) or the quiet-exit window (lost-peer-left
        // case). Fenced exactly like the exits above: by_sid empty + no pending
        // questions, so a mid-transfer reconnect (which keeps `by_sid`
        // non-empty) is untouched, and --keep-open still lingers by design.
        if completed > 0 && !keep_open && by_sid.is_empty() && pending.is_empty()
            && conn.links.is_empty()
        {
            conn.waiting_rejoin = None;
            ui::clear_sticky();
            ui::say(&format!("done ({completed} file{}).", if completed == 1 { "" } else { "s" }));
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // G-k fallback: everything done, nobody attached, no questions
        // outstanding — if that holds quietly for the quiet-exit window (10s
        // default, FILAMENT_QUIET_EXIT_SECS overrides), the peer-left we were
        // counting on for a clean exit never arrived; exit anyway. C30 ph2:
        // ALSO satisfied when the server's digest says the room is empty and
        // no room-independent (channel) link remains — lingering dead links
        // can't block the exit when the server knows nobody's there.
        let digest_says_alone = digest_alone && conn.links.values().all(|l| l.expected_secret.is_none());
        // #28 Mode B: a dead link that keeps FLAPPING — on_stuck reconnect, or a
        // roster/session reconcile re-adopting the gone sender and re-arming
        // `expected_secret` so `digest_says_alone` never holds — must NOT block
        // this fallback once everything is received; `conn.links` may never
        // empty under churn (the RC=124 hang). Surgical: discriminate on link
        // HEALTH, not existence — a churning/reconnecting/dead link (never
        // `Ready`) does not block exit, but a healthy `Ready` link (e.g. a
        // bystander between two human-paced sends, gate 6) STILL does. So this is
        // a no-op for healthy peers, not a behaviour change — only a peer we've
        // lost contact with stops blocking. FILAMENT_TEST_DISABLE_MODEB_DROP
        // restores the old links-gated behaviour so gate 18b proves the A/B
        // (baseline hangs, fix exits) with one binary.
        let no_healthy_link = conn.links.values().all(|l| !matches!(l.presence, Presence::Ready));
        let links_clear = if !test_hooks::disable_modeb_drop() {
            no_healthy_link
        } else {
            conn.links.is_empty() || digest_says_alone
        };
        if completed > 0 && !keep_open && by_sid.is_empty() && pending.is_empty() && links_clear {
            match last_quiet {
                None => last_quiet = Some(Instant::now()),
                Some(since) if since.elapsed() > quiet_window => {
                    ui::say(&ui::paint(ui::Tone::Dim, "  (peer-left never arrived — exiting on quiet)"));
                    ui::say(&format!("done ({completed} file{}).", if completed == 1 { "" } else { "s" }));
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
                Some(_) => {}
            }
        } else {
            last_quiet = None;
        }

        let Some(ev) = ev else { continue };

        // C23: questions from links that died (supersede/peer-left) are
        // moot — the sender re-offers on its new link. Purge them so a 'y'
        // can never accept a ghost (the duplicate-stream ENOENT crash).
        if !pending.is_empty() {
            let front_id = pending.front().map(|(_, v)| v["id"].clone());
            pending.retain(|(p, _)| conn.links.contains_key(p));
            if pending.front().map(|(_, v)| v["id"].clone()) != front_id {
                ui::clear_sticky();
                if let Some((qpid, qv)) = pending.front() {
                    let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                    {
                        let q = offer_question(&s, qv["name"].as_str().unwrap_or("file"), qv["size"].as_u64().unwrap_or(0), paired);
                        ui::say(&q); // permanent: a new question fronted (C25)
                        ui::sticky(&q);
                        question_shown = Instant::now();
                    }
                } else {
                    question_open.store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        match ev {
            Ev::PairMatched(v) => {
                claim_in_flight = false;
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ui::say(&format!("  {} code accepted — joining sender", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                sess.room = Some(room.clone()); // C30: desire moves; session repairs if the join dies
                sess.touch();
                sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            }
            // C30: server confirmed our session digest. Phase 2: reconcile
            // the roster it carries — missed peer-joined/left self-correct.
            Ev::Synced(v) => {
                if let Some(peers) = sess.on_synced(&v) {
                    digest_alone = peers.is_empty();
                    let present: std::collections::HashSet<String> = peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    // unknown in digest → a peer-joined we never received
                    for p in &peers {
                        let id = p["id"].as_str().unwrap_or_default();
                        if !id.is_empty() && !conn.links.contains_key(id) {
                            ui::debug(&ui::paint(ui::Tone::Dim, "  (digest: adopting a peer we never heard join)"));
                            conn.maybe_adopt(p, true).await?;
                        }
                    }
                    // known room-sourced link absent ×2 → a peer-left we
                    // never received (channel-introduced links are exempt:
                    // room-independent by design)
                    let mut gone: Vec<String> = Vec::new();
                    for (pid, l) in &conn.links {
                        if l.expected_secret.is_none() && !present.contains(pid) {
                            let c = digest_absent.entry(pid.clone()).or_insert(0);
                            *c += 1;
                            if *c >= 2 {
                                gone.push(pid.clone());
                            }
                        } else {
                            digest_absent.remove(pid);
                        }
                    }
                    for pid in gone {
                        digest_absent.remove(&pid);
                        let name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        conn.drop_link(&pid);
                        ui::say(&conn.roster(&pid, "○", ui::Tone::Dim, "left (digest reconcile) — still listening", &name));
                    }
                }
            }
            // C29: a code minted in-session (`pair` typed into up).
            Ev::PairCode(v) => {
                let c = v["code"].as_str().unwrap_or("?");
                ui::clipboard(c);
                ui::say("");
                ui::say(&format!("      {}", ui::paint(ui::Tone::Brand, &c.to_uppercase())));
                ui::say("");
                ui::say(&ui::paint(ui::Tone::Dim, "  say it aloud — they type it in the web app or `filament pair <code>` · one claim · 10 min"));
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed — connecting…"));
            }
            Ev::PairError(v) => {
                let why = v["error"].as_str().unwrap_or("?").to_string();
                // The server distinguishes (additively) a dead creator from a
                // typo'd/expired code — say the actionable thing for each.
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => "the sender who made that code already left — ask them for a fresh one".to_string(),
                    _ => format!("{why} — codes burn after one use and expire after 10 min"),
                };
                if code.is_some() && conn.links.is_empty() && completed == 0 {
                    // started WITH a code that failed: nothing else to do
                    bail!("code rejected: {hint}");
                }
                // a TYPED claim failing must not kill a listening session
                paired = false;
                claim_in_flight = false;
                ui::say(&format!(
                    "  {} code rejected: {hint}; still listening",
                    ui::paint(ui::Tone::Err, ui::glyph_err()),
                ));
            }
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                // P5 (GAP-6): a fresh welcome (signaling reconnect) may mean the
                // network just changed under us — re-probe relay-committed peers for
                // a direct path immediately instead of waiting out the backoff.
                conn.reprobe_on_network_event();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
                // C30 (dissolves the C28 belt): a welcome means a fresh sid —
                // everything sid-keyed (subscriptions, lease) died with the
                // old one. Invalidate; the next tick re-asserts everything.
                sess.invalidate();
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own sender/daemon shares these channels
                }
                if let Some((n, sec)) = devices.iter().find(|(_, s)| channel_of(s) == v["channel"].as_str().unwrap_or("")) {
                    ui::say(&format!("known device '{n}' appeared — connecting"));
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    // rung-1: known device = both CLIs; try direct QUIC first.
                    let (n, sec) = (n.clone(), sec.clone());
                    conn.start_direct(&pid, &n, &sec).await;
                    conn.maybe_adopt(&v, true).await?;
                    if let Some(l) = conn.link_mut(&pid) {
                        l.expected_secret = Some((n.clone(), sec.clone()));
                    }
                }
            }
            Ev::PeerJoined(v) => {
                let had_partials = !by_sid.is_empty();
                if conn.maybe_adopt(&v, true).await? && had_partials {
                    // Stale per-link sid routing dies with the old link; the
                    // .part files live on and the sender's resume re-offers.
                    flush_inflight(&mut by_sid).await;
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates — start the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    // rung-2: optional server-reflexive candidate for hole-punch.
                    let srflx = data["srflx"].as_str().map(String::from);
                    // P5 (GAP-6): a `probe:true` offer is a relay->direct UPGRADE
                    // probe from the other end. If we're serving this peer on relay
                    // and have no probe of our own yet, ARM one so the symmetric
                    // direct dial can complete (a later re-send of the offer — the
                    // peer re-emits 6x — is consumed by our now-armed pending). The
                    // winner posts DirectUpgradeReady (verify-before-upgrade), never
                    // clobbering the serving relay link.
                    if data["probe"].as_bool() == Some(true) {
                        conn.answer_upgrade_probe(&from).await;
                    }
                    conn.on_transport_offer(&from, cands, srflx);
                    continue;
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            // rung-1: authenticated direct-QUIC won the race — adopt as a
            // pre-trusted Link, then funnel into the normal ChannelReady handler.
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            // P5 (GAP-6): relay->direct upgrade standby connected (receiver side).
            // Stash + VERIFY rather than adopt — see the send-loop twin.
            Ev::DirectUpgradeReady(pid, t, route) => {
                conn.stash_upgrade_standby(&pid, t, route);
            }
            Ev::ChannelReady(pid, t) => {
                // web-shell discovery: tell the peer whether this receiver offers a
                // terminal (l2_enabled = `up --shell` / FILAMENT_L2). The browser
                // shows its per-device shell button ONLY when this is true; the
                // actual pty-open is still gated server-side by the cap/policy.
                let _ = t.send_control(&json!({ "type": "caps", "shell": l2_enabled })).await;
                if let Some(l) = conn.link_mut(&pid) {
                    ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, &l.name)));
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                    let is_direct = l.direct;
                    let direct_route = l.direct_route;
                    if let Some(p) = l.peer.clone() {
                        tokio::spawn(async move {
                            // ICE may renominate; retry briefly (mirrors the
                            // browser's _detectRoute attempts) so fast transfers
                            // still get a route line before the process exits.
                            for _ in 0..6 {
                                tokio::time::sleep(Duration::from_millis(400)).await;
                                if let Some(r) = p.route().await {
                                    // CRITICAL: the route label is the value-prop —
                                    // direct vs relayed. Always shown, even under -q.
                                    ui::critical(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {r}"))));
                                    // Relay honesty (§3.3): the quiet `route:` line
                                    // is legible but not loud. When the route is
                                    // actually the TURN relay, print the honest
                                    // one-line banner so the user is never unaware
                                    // they're on a middleman path. CRITICAL.
                                    if r == "relayed" {
                                        ui::critical(&format!("    {}", relay_banner()));
                                    }
                                    break;
                                }
                            }
                        });
                    } else if is_direct {
                        ui::critical(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {direct_route}"))));
                    }
                }
                // C29: an in-session pairing — exactly one side hands over a
                // secret; consent (pair-keep-ack / our store) completes it.
                // Only links that aren't ALREADY known are candidates.
                let fresh_link = conn.link(&pid).map(|l| l.expected_secret.is_none()).unwrap_or(false);
                if fresh_link {
                    match ceremony {
                        Some(true) => {
                            // we minted the code — initiate now
                            ceremony = None;
                            ceremony_pid = Some(pid.clone());
                            t.send_control(&json!({ "type": "pair-keep", "secret": ceremony_secret })).await.ok();
                        }
                        Some(false) => {
                            // we claimed — give a CLI creator 3 s to initiate
                            // (browsers never do), then take over.
                            let tx = tx.clone();
                            let pid = pid.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(3)).await;
                                let _ = tx.send(Ev::Control(pid, json!({ "type": "__pair_fallback" })));
                            });
                        }
                        None => {}
                    }
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                _ if !conn.links.contains_key(&pid) => {}
                // L2 (ssh/TCP tunnel) acceptor. Opt-in (FILAMENT_L2=1). The
                // capability gate is the proof-verified `trusted` flag on this
                // link (placeholder for L1-a caps); localhost-only is enforced in
                // accept_control. A non-trusted or non-loopback open is refused.
                Some("l2-open") | Some("l2-close") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let mux = l2_muxes
                        .entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    match mux.accept_control(&v, trusted).await {
                        l2::OpenVerdict::Accept { sid, host, port, rx } => {
                            tokio::spawn(mux.clone().dial_and_serve(sid, host, port, rx));
                        }
                        l2::OpenVerdict::Deny { sid, err } => {
                            // Log refused dials (threat model: port-scan / SSRF
                            // visibility). The gate observes this line.
                            // DEBUG — l2 diagnostic (port-scan / SSRF visibility).
                            ui::debug(&format!("l2: refused stream {sid:#x}: {err}"));
                            let _ = t
                                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": err }))
                                .await;
                        }
                        l2::OpenVerdict::Ignore => {}
                    }
                    // A PTY stream closing frees its resize channel — handled by
                    // the mux's `on_close`/`drop_stream` (H-1: resizer is owned by
                    // the mux now, so it can't leak past the stream).
                }
                // Seamless-shell bootstrap (acceptor). Opt-in (FILAMENT_L2=1).
                // DENY-BY-DEFAULT: install the initiator's managed pubkey ONLY
                // when the link is proof-verified (`trusted`) AND the proven
                // device holds the NEW `shell` capability — distinct from
                // `transfer`, so pairing for file transfer never yields a shell.
                // The write happens only here (over the authenticated channel)
                // into a clearly-marked, removable authorized_keys block.
                Some("shell-bootstrap") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Cap lookup keys on the PROVEN petname, not the presence name.
                    let dev = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    // Granted if the device was explicitly `grant`ed shell OR an
                    // active `up --shell[-only]` policy auto-allows it. Trust
                    // (pair-proof) is still required either way.
                    let granted = trusted
                        && dev
                            .as_deref()
                            .map(|n| shell_policy.auto_allows(n) || device_allows(n, "shell"))
                            .unwrap_or(false);
                    if !granted {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        ui::say(&format!("l2: shell bootstrap refused: {who} (no shell cap / untrusted)"));
                        let _ = t
                            .send_control(&json!({
                                "type": "shell-bootstrap-deny",
                                "reason": "shell capability not granted"
                            }))
                            .await;
                        continue;
                    }
                    let device = dev.unwrap();
                    let pubkey = v["pubkey"].as_str().unwrap_or_default().to_string();
                    // M-3 (authorized_keys injection): a single, well-formed key
                    // line ONLY. validate_pubkey rejects interior newlines / CR /
                    // control chars and multi-line payloads, so a trusted+shell
                    // peer can't inject extra authorized_keys lines. Enforced here
                    // AND again inside install_authorized_key (defense in depth).
                    let pubkey = match sshkeys::validate_pubkey(&pubkey) {
                        Ok(k) => k,
                        Err(e) => {
                            ui::say(&format!("l2: shell bootstrap refused: malformed pubkey from '{device}': {e}"));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "malformed pubkey"
                                }))
                                .await;
                            continue;
                        }
                    };
                    match sshkeys::install_authorized_key(&device, &pubkey) {
                        Ok(()) => {
                            let hostkeys = sshkeys::host_pubkeys();
                            let login = std::env::var("USER").unwrap_or_else(|_| "root".into());
                            ui::say(&format!("l2: shell granted to '{device}' — installed managed key (filament-managed block)"));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-ack",
                                    "hostkeys": hostkeys,
                                    "user": login
                                }))
                                .await;
                        }
                        Err(e) => {
                            ui::say(&format!("l2: shell bootstrap install failed for '{device}': {e}"));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "install failed"
                                }))
                                .await;
                        }
                    }
                }
                // web-shell (browser terminal): spawn a login shell in a PTY and
                // bridge it to a sid stream. Same deny-by-default gate as
                // shell-bootstrap — a PTY is a superset of ssh-key access, so it
                // reuses the `shell` cap / --shell policy and requires `trusted`.
                Some("pty-open") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    if !l2::is_l2_sid(sid) {
                        continue;
                    }
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let dev = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    let granted = trusted
                        && dev
                            .as_deref()
                            .map(|n| shell_policy.auto_allows(n) || device_allows(n, "shell"))
                            .unwrap_or(false);
                    if !granted {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        ui::say(&format!("l2: pty refused: {who} (no shell cap / untrusted)"));
                        let _ = t
                            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "shell capability not granted" }))
                            .await;
                        continue;
                    }
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    let mux = l2_muxes
                        .entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    // H-1 (DoS): refuse over the per-link stream cap or the global
                    // PTY cap BEFORE spawning a shell. A flaky/hostile paired
                    // device can otherwise flood `pty-open` and exhaust threads.
                    if mux.at_stream_cap().await {
                        ui::say("l2: pty refused: too many streams on this link");
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                        continue;
                    }
                    let Some(pty_guard) = l2::PtyGuard::try_acquire() else {
                        ui::say(&format!("l2: pty refused: too many PTYs (global cap {})", l2::MAX_PTYS_GLOBAL));
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                        continue;
                    };
                    let rx = mux.register_stream(sid).await; // before spawn (race fix)
                    let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<(u16, u16)>();
                    // Resizer is owned by the mux so it is freed on EVERY teardown
                    // path (inbound l2-close, serve_pty exit, link death) — H-1.
                    mux.register_resizer(sid, rtx).await;
                    ui::say(&format!("l2: pty granted to '{}' — {cols}x{rows}", dev.unwrap_or_default()));
                    let _ = t.send_control(&json!({ "type": "pty-open-ack", "sid": sid })).await;
                    tokio::spawn(l2::serve_pty(mux.clone(), sid, cols, rows, shell_argv(shell_user.as_deref()), rx, rrx, pty_guard));
                }
                Some("pty-resize") if l2_enabled => {
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    if let Some(mux) = l2_muxes.get(&pid) {
                        mux.resize_pty(sid, cols, rows).await;
                    }
                }
                Some("brb") => {
                    // C21: the peer announces a benign absence (mobile file
                    // picker suspends the tab). Hold the line that long.
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.away = Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    ui::say(&conn.roster(&pid, "●", ui::Tone::Warn, "away — choosing a file · holding the line", &n));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                // C30 phase 3: a state ping proves the peer is alive — clear
                // any away-mark (the receiver side has no sender corrections).
                Some("state") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                Some("pair-keep") => {
                    let sec = v["secret"].as_str().unwrap_or_default().to_string();
                    if sec.len() == 64 {
                        let kept = if let Some(name) = &remember {
                            devices_store(name, &sec)?;
                            ui::say(&format!("remembered this device as '{name}' — future sends auto-accept after proof"));
                            true
                        } else if ceremony == Some(false) {
                            // C29: we typed their code into this session — the
                            // creator initiated first; that's our ceremony.
                            ceremony = None;
                            let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "device".into());
                            devices_store(&n, &sec)?;
                            devices.push((n.clone(), sec.clone()));
                            sess.channels.push(channel_of(&sec)); // C30: desire grows; session repairs
                            sess.touch();
                            sio.emit("subscribe", json!({ "channels": [channel_of(&sec)] })).await.ok();
                            ui::say(&format!(
                                "  {} {} mutually remembered — rename anytime: filament devices rename {n} <new>",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                            true
                        } else {
                            ui::say("(sender offered to be remembered; re-run with --remember <name> to keep it)");
                            false
                        };
                        // C27: answer either way — a declined sender discards
                        // its half instead of waving at a dead meeting point.
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep-ack", "ok": kept })).await.ok();
                        }
                    }
                }
                // C29: claimer fallback — the creator never initiated
                // (browsers don't); hand over OUR secret instead.
                Some("__pair_fallback") => {
                    if ceremony == Some(false) {
                        ceremony = None;
                        ceremony_pid = Some(pid.clone());
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep", "secret": ceremony_secret })).await.ok();
                        }
                    }
                }
                // C29: their answer to OUR in-session remember offer.
                Some("pair-keep-ack") => {
                    if ceremony_pid.as_deref() == Some(pid.as_str()) {
                        ceremony_pid = None;
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "device".into());
                        if v["ok"].as_bool() == Some(false) {
                            ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "declined to be remembered — nothing stored", &n));
                        } else {
                            devices_store(&n, &ceremony_secret)?;
                            devices.push((n.clone(), ceremony_secret.clone()));
                            sess.channels.push(channel_of(&ceremony_secret)); // C30
                            sess.touch();
                            sio.emit("subscribe", json!({ "channels": [channel_of(&ceremony_secret)] })).await.ok();
                            ceremony_secret = fresh_secret(); // never reuse across devices
                            ui::say(&format!(
                                "  {} {} mutually remembered — rename anytime: filament devices rename {n} <new>",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                        }
                    }
                }
                Some("pair-proof") => {
                    let mac = v["mac"].as_str().unwrap_or_default();
                    let peer_uid = conn.link(&pid).and_then(|l| l.uid.clone()).unwrap_or_default();
                    let fps = match conn.link(&pid) {
                        Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                        None => None,
                    };
                    let Some((my_fp, their_fp)) = fps else {
                        ui::debug("pair-proof received before fingerprints known — ignoring");
                        continue;
                    };
                    // #9: pair secrets are symmetric — our own install holds
                    // every secret we do, so a same-host process could prove
                    // "pop2" and tunnel callers into the WRONG machine. Refuse.
                    let hit = if is_self_uid(&conn.my_uid, Some(peer_uid.as_str())) {
                        ui::debug("pair-proof from our own install — refusing (self-connect)");
                        None
                    } else {
                        devices
                            .iter()
                            .find(|(_, s)| proof_for(s, &peer_uid, &peer_uid, &conn.my_uid, &my_fp, &their_fp) == mac)
                    };
                    let ok = if let Some((n, _)) = hit {
                        if let Some(l) = conn.link_mut(&pid) {
                            l.trusted = true;
                            // Record the proven devices.json petname — the cap
                            // store key (the `shell` bootstrap gate looks up caps
                            // under exactly this, not the presence display name).
                            l.verified_name = Some(n.clone());
                        }
                        ui::say(&format!("identity verified: '{n}' (auto-accepting)"));
                        true
                    } else {
                        // CRITICAL — a security verdict the user must see (-q too).
                        ui::critical(&ui::paint(ui::Tone::Warn, "pair-proof FAILED verification — treating peer as untrusted"));
                        false
                    };
                    // C27: tell the prover the verdict — a rejected prover
                    // learns we never met and stops claiming acquaintance.
                    if let Some(t) = conn.transport_of(&pid) {
                        t.send_control(&json!({ "type": "pair-proof-ack", "ok": ok })).await.ok();
                    }
                }
                Some("pair-intro") => {
                    // C19/C20: only a fingerprint-verified known device may
                    // vouch new trust into this store.
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let iname = v["name"].as_str().unwrap_or_default().to_string();
                    let isec = v["secret"].as_str().unwrap_or_default().to_string();
                    let hub = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    if trusted && isec.len() == 64 && !iname.is_empty() {
                        devices_store(&iname, &isec)?;
                        devices.push((iname.clone(), isec.clone()));
                        sess.channels.push(channel_of(&isec)); // C30
                        sess.touch();
                        sio.emit("subscribe", json!({ "channels": [channel_of(&isec)] })).await.ok();
                        ui::say(&format!(
                            "  {} introduced to '{}' by {} — now a known device",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok()), iname, hub
                        ));
                    } else {
                        ui::say(&ui::paint(ui::Tone::Warn, &format!("  ignored pair-intro from unverified peer {hub}")));
                    }
                }
                Some("file-offer") => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // Never trust a remote name with path separators.
                    let raw = v["name"].as_str().unwrap_or("file.bin");
                    let name = Path::new(raw)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "file.bin".into());
                    let size = v["size"].as_u64().unwrap_or(0);
                    let offer_head = v["head"].as_str().map(|s| s.to_string());
                    // P4 (GAP-5): the sender's whole-file sha256 (absent for an old
                    // peer). Used to verify-on-completion + drive the delivery-ack.
                    let offer_full = v["full"].as_str().map(|s| s.to_string());
                    let is_resume = v["resume"].as_bool().unwrap_or(false);

                    let part_path = dir.join(format!("{name}.part"));
                    let meta_path = dir.join(format!("{name}.part.meta"));
                    // C7: a partial counts only if size matches AND the
                    // content head matches (when both sides have one).
                    let mut offset = 0u64;
                    // P4: the whole-file digest persisted with the partial, so a
                    // resume after a process restart can still verify-on-completion
                    // even if this particular re-offer omits `full`.
                    let mut prior_full: Option<String> = None;
                    if part_path.is_file() {
                        let prior = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
                        match PartMeta::load(&meta_path) {
                            Some(m) if m.size == size && prior <= size => {
                                let head_ok = match (&m.head, &offer_head) {
                                    (Some(a), Some(b)) => a == b,
                                    _ => true, // legacy peer — size-only fallback
                                };
                                if head_ok {
                                    offset = prior;
                                    prior_full = m.full;
                                } else {
                                    // DEBUG — resilience internal (resume mismatch, restart).
                                    ui::debug(&format!("{name}: same name+size but different content — restarting from 0"));
                                }
                            }
                            _ => {}
                        }
                    }

                    // C14/C22: consent. -y accepts everything; a resume of a
                    // partial we already said yes to auto-accepts; a verified
                    // device auto-accepts; otherwise the question joins the
                    // pending queue and the answer arrives via StdinLine — a
                    // per-process token marks re-enqueued offers so a remote
                    // peer can't forge "already consented".
                    let sender_name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    let link_trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let consented = v["__consent"].as_str() == Some(consent_token());
                    let ok = if daemon {
                        link_trusted
                    } else {
                        yes || consented || link_trusted || (is_resume && offset > 0)
                    };
                    if !ok {
                        if !daemon && std::io::stdin().is_terminal() {
                            pending.push_back((pid.clone(), v.clone()));
                            question_open.store(true, std::sync::atomic::Ordering::Relaxed);
                            if pending.len() == 1 {
                                // C25: the question is a PERMANENT line first
                                // (nothing can be asked invisibly), with the
                                // sticky as the live answer tail.
                                let q = offer_question(&sender_name, &name, size, paired);
                                ui::say(&q);
                                ui::sticky(&q);
                                question_shown = Instant::now();
                            }
                            continue; // decision arrives later via StdinLine
                        }
                        ui::say(&ui::paint(ui::Tone::Dim, &format!(
                            "  declined {name} from {sender_name} ({})",
                            if daemon { "unverified peer" } else { "no tty — use -y to auto-accept" }
                        )));
                        t.send_control(&json!({ "type": "file-decline", "id": id })).await?;
                        continue;
                    }

                    // C23: never run two streams into one .part — a rejoin
                    // can re-offer a file whose first stream is still live;
                    // accepting both corrupted the path and crashed on the
                    // second rename. First stream wins.
                    //
                    // P0 (GAP-1) exception: a STALL repair re-offers the same file
                    // (resume:true) on a FRESH transport while the OLD stream's
                    // by_sid entry may still linger (its data path went dark). If
                    // the existing stream's transport is itself STALLED past the
                    // threshold, the "first stream" is the wedged one — flush it to
                    // its .part and accept the resume on the live link instead of
                    // declining (a decline would mark the SENDER's transfer done
                    // and abort the recovery). A genuinely FLOWING duplicate still
                    // wins as before.
                    let want_part = dir.join(format!("{name}.part"));
                    if !to_stdout {
                        let dup_keys: Vec<(String, u32)> = by_sid
                            .iter()
                            .filter(|(_, inc)| inc.part_path == want_part)
                            .map(|(k, _)| k.clone())
                            .collect();
                        if !dup_keys.is_empty() {
                            // Is ANY existing stream for this file still flowing?
                            let any_flowing = dup_keys.iter().any(|(p, _)| {
                                conn.transport_of(p)
                                    .map(|t| t.idle_ms() < net::stall_ms())
                                    .unwrap_or(false)
                            });
                            if any_flowing {
                                // A real concurrent duplicate — first (flowing)
                                // stream wins. Ignore WITHOUT marking the sender
                                // done (a benign skip, not a user decline).
                                ui::say(&ui::paint(ui::Tone::Dim, &format!("  (duplicate offer for {name} ignored — already receiving it)")));
                                continue;
                            }
                            // The lingering stream(s) are STALLED — flush their
                            // partials to disk and drop them so the resume below
                            // re-opens the .part from its saved offset.
                            for k in dup_keys {
                                if let Some(mut inc) = by_sid.remove(&k) {
                                    let _ = inc.file.flush().await;
                                }
                            }
                        }
                    }

                    if to_stdout {
                        // Pipe mode: no part files, no resume — pure stream.
                        // Write through a dup'd stdout fd so dropping the
                        // writer never closes the process's real fd 1; the
                        // /dev/stdout open is the portable-unix way to dup.
                        // (Windows: -o - is not supported yet; see G-e.)
                        #[cfg(unix)]
                        let out = tokio::fs::OpenOptions::new().write(true).open("/dev/stdout").await?;
                        #[cfg(not(unix))]
                        {
                            bail!("-o - (stdout streaming) is not supported on this platform yet");
                        }
                        #[cfg(unix)]
                        {
                            by_sid.insert((pid.clone(), sid), IncomingFile {
                                id: id.clone(),
                                name,
                                size,
                                received: 0,
                                file: tokio::io::BufWriter::with_capacity(1 << 20, out),
                                part_path: PathBuf::new(),
                                // Pipe mode streams to a fd we can't re-read, so we
                                // can't recompute the digest — no verify, no ack
                                // (the sender's bounded fallback covers it).
                                full: None,
                                bar: ui::Progress::new("(stdout)", size),
                            });
                            t.send_control(&json!({ "type": "file-accept", "id": id, "offset": 0 })).await?;
                            continue;
                        }
                    }
                    // P4: the digest to verify against on completion — the current
                    // offer's, else the one persisted with the partial (resume).
                    let effective_full = offer_full.clone().or(prior_full);
                    let file = if offset > 0 {
                        // DEBUG — resilience internal (receiver resuming from offset).
                        ui::debug(&format!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0));
                        tokio::fs::OpenOptions::new().append(true).open(&part_path).await?
                    } else {
                        PartMeta { size, head: offer_head, full: effective_full.clone() }.store(&meta_path)?;
                        tokio::fs::File::create(&part_path).await?
                    };
                    let bar = ui::Progress::new(&name, size);
                    by_sid.insert((pid.clone(), sid), IncomingFile {
                        id: id.clone(),
                        name,
                        size,
                        received: offset,
                        file: tokio::io::BufWriter::with_capacity(1 << 20, file),
                        part_path,
                        full: effective_full,
                        bar,
                    });
                    t.send_control(&json!({ "type": "file-accept", "id": id, "offset": offset })).await?;
                }
                Some("file-end") => {
                    // Test hook (gate 18 standalone repro): drop the file-end
                    // control frame so a fully-received stream is stranded in
                    // by_sid — mirrors a sender whose PC tears down before the
                    // best-effort file-end is delivered. The G-k completion
                    // sweep must then finalize it on size and quiet-exit.
                    if test_hooks::drop_file_end() {
                        continue;
                    }
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    if let Some(mut inc) = by_sid.remove(&(pid.clone(), sid)) {
                        inc.file.flush().await?;
                        if to_stdout {
                            completed += 1;
                            continue;
                        }
                        // P4 (GAP-5): WHOLE-FILE INTEGRITY. The sender offered the
                        // file's full sha256 (`inc.full`). Before declaring "done",
                        // recompute it over the received `.part` and COMPARE. A
                        // truncated or corrupt receive (the 7 KB stub class) must
                        // NOT be accepted — instead keep the partial and re-request
                        // until the bytes are whole and the hash matches, or fail
                        // CLEARLY after a bound. Only on a MATCH do we finalize +
                        // send the delivery-ack. An old peer that offered no digest
                        // (`inc.full == None`) degrades to the legacy size check —
                        // no verify, no ack (the sender's bounded fallback covers
                        // it), so this never hangs against an ack-less peer.
                        let id = inc.id.clone();
                        if inc.full.is_some() {
                            let verdict = verify_incoming(&mut inc).await;
                            match verdict {
                                VerifyResult::Match => {
                                    // INTACT — finalize, then tell the sender it
                                    // landed whole (the deterministic delivery-ack).
                                    verify_fails.remove(&id);
                                    let rename_to = if completed == 0 { output.clone() } else { None };
                                    let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                                    let nm = inc.name.clone();
                                    if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await? {
                                        completed += 1;
                                        if let Some(t) = conn.transport_of(&pid) {
                                            let _ = t.send_control(&json!({
                                                "type": "delivery-ack", "id": id, "sid": sid, "v": 1,
                                            })).await;
                                            ui::say(&ui::paint(ui::Tone::Dim, &format!("    {nm} verified (whole-file sha256 matched) — acked", )));
                                        }
                                    }
                                }
                                VerifyResult::Mismatch { restart_from_zero } => {
                                    // TRUNCATED or CORRUPT — do NOT accept. Bound the
                                    // re-request so a genuinely-unrecoverable payload
                                    // fails clearly instead of looping forever.
                                    let fails = verify_fails.entry(id.clone()).or_insert(0);
                                    *fails += 1;
                                    if *fails > MAX_VERIFY_FAILS {
                                        // Give up CLEANLY: keep the partial, surface
                                        // the cause, do not finalize, do not ack. No
                                        // silent bad file; re-running can still retry.
                                        // CRITICAL — a clean terminal refusal (corrupt file
                                        // rejected); the user must see it even under -q.
                                        ui::critical(&ui::paint(ui::Tone::Err, &format!(
                                            "  {}: whole-file checksum still wrong after {MAX_VERIFY_FAILS} re-fetches — refusing to accept a corrupt file (partial kept)",
                                            inc.name
                                        )));
                                        verify_fails.remove(&id);
                                        // Leave the .part on disk; the stream is dropped
                                        // (by_sid already removed). The sender's transfer
                                        // stays un-acked; its bounded ack-wait then reports
                                        // honestly rather than declaring success.
                                        continue;
                                    }
                                    // Re-request: a truncated tail resumes from the
                                    // current `.part` offset; a corrupt body (full
                                    // size, wrong hash) restarts from 0 (the .part is
                                    // poisoned — truncate it and re-fetch whole).
                                    let mut req_offset = inc.received;
                                    if restart_from_zero {
                                        let _ = tokio::fs::File::create(&inc.part_path).await; // truncate to 0
                                        inc.received = 0;
                                        req_offset = 0;
                                        // DEBUG — resilience internal (P4 whole-file re-fetch).
                                        ui::debug(&ui::paint(ui::Tone::Warn, &format!(
                                            "  {}: received all bytes but whole-file checksum FAILED (corrupt) — re-fetching from 0 (attempt {})",
                                            inc.name, *fails
                                        )));
                                    } else {
                                        // DEBUG — resilience internal (P4 truncation re-request).
                                        ui::debug(&ui::paint(ui::Tone::Warn, &format!(
                                            "  {}: TRUNCATED ({}/{}) — checksum can't match yet; re-requesting the rest (attempt {})",
                                            inc.name, human(inc.received), human(inc.size), *fails
                                        )));
                                    }
                                    // Park the stream back in by_sid so resumed chunks
                                    // land in the same writer, and ask the sender to
                                    // (re)stream from req_offset.
                                    let _ = inc.file.flush().await;
                                    if req_offset == 0 {
                                        // Reopen the freshly-truncated file for append.
                                        if let Ok(f) = tokio::fs::OpenOptions::new().append(true).open(&inc.part_path).await {
                                            inc.file = tokio::io::BufWriter::with_capacity(1 << 20, f);
                                        }
                                    }
                                    by_sid.insert((pid.clone(), sid), inc);
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t.send_control(&json!({
                                            "type": "file-accept", "id": id, "offset": req_offset,
                                        })).await;
                                    }
                                }
                            }
                        } else {
                            // No digest offered (old peer / pipe source): legacy
                            // size-only acceptance, no ack.
                            let rename_to = if completed == 0 { output.clone() } else { None };
                            let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                            if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await? {
                                completed += 1;
                            }
                        }
                    }
                }
                _ => {}
            },
            Ev::Chunk(pid, sid, data) => {
                // L2 streams live in the HIGH half of the sid space — route them
                // to the tunnel mux, never the file-transfer table (the pure
                // high-bit prefix check keeps file send/recv byte-identical).
                if l2_enabled && l2::is_l2_sid(sid) {
                    if let Some(mux) = l2_muxes.get(&pid) {
                        mux.on_frame(sid, data).await;
                    }
                } else if let Some(inc) = by_sid.get_mut(&(pid, sid)) {
                    inc.file.write_all(&data).await?;
                    inc.received += data.len() as u64;
                    inc.bar.tick(inc.received);
                }
            }
            Ev::StdinLine(line) => {
                let ans = line.to_lowercase();
                if !pending.is_empty() {
                    // C22/C25: an open question owns stdin — but ONLY explicit
                    // answers count. An empty line (stray CR, idle Enter) used
                    // to default-decline an offer the user never saw; and any
                    // keypress within 300ms of the question appearing is a
                    // buffered stroke, not a decision.
                    if question_shown.elapsed() < Duration::from_millis(300) {
                        continue;
                    }
                    let mut answered = false;
                    if ans == "y" || ans == "yes" {
                        answered = true;
                        let (qpid, mut qv) = pending.pop_front().unwrap();
                        ui::clear_sticky();
                        qv["__consent"] = json!(consent_token());
                        let _ = tx.send(Ev::Control(qpid, qv)); // re-enter the offer path, consented
                    } else if ans == "n" || ans == "no" {
                        answered = true;
                        let (qpid, qv) = pending.pop_front().unwrap();
                        ui::clear_sticky();
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  declined {}", qv["name"].as_str().unwrap_or("file"))));
                        if let Some(t) = conn.transport_of(&qpid) {
                            t.send_control(&json!({ "type": "file-decline", "id": qv["id"] })).await?;
                        }
                    }
                    // show the next queued question (or re-show on gibberish)
                    if let Some((qpid, qv)) = pending.front() {
                        let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                        let q = offer_question(&s, qv["name"].as_str().unwrap_or("file"), qv["size"].as_u64().unwrap_or(0), paired);
                        if answered {
                            ui::say(&q); // a NEW question fronted — permanent line (C25)
                            question_shown = Instant::now();
                        }
                        ui::sticky(&q);
                    } else {
                        question_open.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                } else if ans == "devices" {
                    // C29: session commands — `up` is a place you live in.
                    if devices.is_empty() {
                        ui::say(&ui::paint(ui::Tone::Dim, "  no known devices yet — type a code or `pair` to add one"));
                    }
                    for (n, s) in &devices {
                        ui::say(&format!("  {}  {}", ui::paint(ui::Tone::Bold, n), ui::paint(ui::Tone::Dim, &format!("(channel {})", &channel_of(s)[..12]))));
                    }
                } else if let Some(n) = ans.strip_prefix("forget ") {
                    let n = n.trim();
                    if devices.iter().any(|(dn, _)| dn == n) {
                        devices_remove(n)?;
                        devices.retain(|(dn, _)| dn != n);
                        ui::say(&format!("  {} forgot '{n}' — it can no longer find this machine", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                    } else {
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  no device named '{n}' (try `devices`)")));
                    }
                } else if ans == "pair" || ans == "code" {
                    // C29: mint a code; whoever claims it gets the remember
                    // ceremony on connect (we created it, so WE initiate).
                    if daemon {
                        ceremony = Some(true);
                    }
                    sio.emit("pair-create", json!({})).await.ok();
                } else if regex_lite_code(&line) {
                    if claim_in_flight {
                        ui::say(&ui::paint(ui::Tone::Dim, "  (a claim is already in flight — wait for it to resolve)"));
                    } else {
                        ui::say(&format!("  claiming {}…", ui::paint(ui::Tone::Brand, &line)));
                        paired = true;
                        claim_in_flight = true;
                        if daemon {
                            ceremony = Some(false); // C29: in a session, pairing means remembering
                        }
                        sio.emit("pair-claim", json!({ "code": line.to_lowercase() })).await.ok();
                    }
                } else if !line.is_empty() {
                    ui::say(&ui::paint(ui::Tone::Dim, "  (type a code like brave-otter-123 to claim it · `pair` · `devices` · `forget <name>`)"));
                }
            }
            Ev::Interrupted => {
                flush_inflight(&mut by_sid).await;
                ui::say(&format!("  {} interrupted — partials kept; run the same command to resume", ui::paint(ui::Tone::Warn, "!")));
                if let Some(g) = &tty_guard {
                    g.restore(); // process::exit skips Drop
                }
                let _ = sio.disconnect().await;
                std::process::exit(130);
            }
            // P0 (GAP-1): the inbound transfer stalled (zero bytes, link alive).
            // The receiver participates in the SYMMETRIC direct-QUIC repair: it
            // re-arms its own direct dial so the fresh authenticated connection
            // can form. The `.part` stays on disk; the sender re-offers
            // resume:true on the new transport, so the file continues from its
            // saved offset (no restart-from-zero). For a WebRTC link the repair
            // is the impolite-side ICE-restart inside correct_stall.
            Ev::TransferStalled(pid, idle_ms) => {
                // DEBUG — resilience internal (inbound stall detection).
                ui::debug(&ui::paint(ui::Tone::Warn, &format!("  inbound stall: {idle_ms}ms with no data from peer — repairing link")));
                // P0 partial-preservation: flush THIS peer's in-flight partials
                // to their `.part` on disk and release the in-memory handles, so
                // the C23 "already receiving" guard doesn't reject the sender's
                // resume-offer on the FRESH repair link. The `.part` + `.meta`
                // stay on disk; the resume re-opens them from the saved offset
                // (no restart-from-zero). Only this peer's streams are dropped —
                // other links keep flowing.
                let stale: Vec<(String, u32)> =
                    by_sid.keys().filter(|(p, _)| *p == pid).cloned().collect();
                for key in stale {
                    if let Some(mut inc) = by_sid.remove(&key) {
                        let _ = inc.file.flush().await;
                        ui::debug(&format!("{}: parked at {} for resume", inc.name, human(inc.received)));
                    }
                }
                match conn.correct_stall(&pid).await {
                    // Receiver has nothing to re-offer; the sender owns the offer.
                    // Rung (a) is a no-op here — wait for the sender's re-offer.
                    Rung::Resume => {}
                    Rung::Repaired => {}
                    // Rung (d) P1: the receiver re-established over the TURN relay
                    // (relay-only ICE), preserving its `.part`. The sender re-offers
                    // resume:true on the fresh relay link — the file continues from
                    // its saved offset. Nothing to do here.
                    Rung::Relayed => {}
                    // Direct rungs spent AND relay forbidden / already on relay:
                    // failed CLEANLY, partial kept on disk (message already shown).
                    Rung::Exhausted => {}
                }
            }
            // Losing the sender is only an ERROR when nothing completed —
            // after a successful transfer it's just closure (the quiet-exit
            // prints the same `done (N files).` the peer-left path would).
            Ev::Stuck(pid, generation) => {
                // Bug 5: repeated stuck before ANY byte arrived → hint at the
                // single-host mDNS wedge once.
                if !ever_received {
                    stuck_while_connecting += 1;
                    if stuck_while_connecting >= 2 {
                        maybe_hint_local_wedge(&mut wedge_hint_shown);
                    }
                }
                if conn.on_stuck(&pid, generation, "stuck while connecting").await? && paired && !keep_open {
                    // G-k: the dropped link may have delivered every byte but
                    // lost its file-end — finalize before deciding it's fatal.
                    sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;
                    if completed == 0 {
                        bail!("lost the sender after {} attempts", MAX_ATTEMPTS);
                    }
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? && paired && !keep_open {
                    sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;
                    if completed == 0 {
                        bail!("lost the sender after {} attempts", MAX_ATTEMPTS);
                    }
                }
            }
            Ev::PcState(pid, s) => {
                // L2: a dead/closed link must abort every tunnel stream it
                // carried so no pump hangs on a peer that's gone (design §3.5).
                if l2_enabled && (s == "failed" || s == "closed" || s == "disconnected") {
                    if let Some(mux) = l2_muxes.remove(&pid) {
                        mux.shutdown_all().await;
                    }
                }
                conn.on_pc_state(&pid, &s).await;
            }
            Ev::PeerLeft(v) => {
                // Test hook (gate 18): peer-left delivery is best-effort in the
                // real world; this simulates the loss deterministically so the
                // quiet-exit fallback (G-k) can be exercised. SIGSTOP can't do
                // it — engine.io's ping timeout reaps a frozen client in ~30s
                // and the legit peer-left wins the race.
                if test_hooks::drop_peer_left() {
                    continue;
                }
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let secs = conn.rejoin_window.as_secs();
                    if !by_sid.is_empty() {
                        // Keep partials writable-but-parked; resume comes via
                        // rejoin (C6) or a later re-offer against the .part.
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  sender disconnected mid-transfer — waiting up to {secs}s")));
                        flush_inflight(&mut by_sid).await;
                    } else if completed > 0 && !keep_open {
                        ui::say(&format!("done ({completed} file{}).", if completed == 1 { "" } else { "s" }));
                        let _ = sio.disconnect().await;
                        return Ok(());
                    } else if paired && !keep_open {
                        // C21: NOT fatal — a phone opening its file picker
                        // suspends the whole tab and drops the socket. Hold
                        // the line; their client rejoins on refocus.
                        let gid = v["id"].as_str().unwrap_or_default();
                        let n = gone.unwrap_or_else(|| "sender".into());
                        ui::say(&conn.roster(gid, "●", ui::Tone::Warn, &format!("stepped away — holding the line up to {secs}s (Ctrl-C to stop)"), &n));
                    } else {
                        conn.waiting_rejoin = None; // open listener: keep going
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => ui::say(&conn.roster(gid, "○", ui::Tone::Dim, "left — still listening", &n)),
                            None => ui::say(&ui::paint(ui::Tone::Dim, "  peer left — still listening")),
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// P4 (GAP-5): outcome of the whole-file integrity check on completion.
enum VerifyResult {
    /// Received bytes hash to the sender's offered digest — accept + ack.
    Match,
    /// Hash didn't match. `restart_from_zero` distinguishes the two cases:
    /// a SHORT file (received < size) is merely TRUNCATED — resume the tail;
    /// a FULL-SIZE file with the wrong hash has a CORRUPT BODY — the partial is
    /// poisoned, so re-fetch from 0.
    Mismatch { restart_from_zero: bool },
}

/// P4 (GAP-5): recompute the whole-file sha256 of the received `.part` and
/// compare against the digest the sender offered (`inc.full`, guaranteed Some by
/// the caller). Flushes first so every buffered byte is on disk. This is the
/// CORE whole-file integrity guarantee the runner used to bolt on above the
/// transport — now every `recv` gets it.
///
/// Test hook (the truncation/ack gate): `FILAMENT_TEST_CORRUPT_RECV=<id>` flips
/// a byte of the on-disk `.part` for the matching transfer id right before the
/// hash is computed, deterministically inducing the corrupt-receive case so the
/// gate can prove reject + recover. `FILAMENT_TEST_CORRUPT_ONCE=1` makes it fire
/// exactly once (the re-fetch then succeeds), proving auto-recovery.
async fn verify_incoming(inc: &mut IncomingFile) -> VerifyResult {
    let want = match &inc.full { Some(w) => w.clone(), None => return VerifyResult::Match };
    let _ = inc.file.flush().await;

    // Test-only corruption injection (deterministic; gate proof). Compiled out
    // entirely on default/release builds — the `corrupt_recv_target` twin returns
    // None there, so this whole block strips to nothing. The "fired once" latch is
    // an AtomicBool inside test_hooks (no unsafe env mutation).
    if let Some(target) = test_hooks::corrupt_recv_target() {
        #[cfg(feature = "test-hooks")]
        {
            let once = test_hooks::corrupt_recv_once();
            let already = test_hooks::corrupt_already_fired();
            if target == inc.id && inc.received == inc.size && !(once && already) {
                if let Ok(mut bytes) = std::fs::read(&inc.part_path) {
                    if let Some(b) = bytes.last_mut() {
                        *b ^= 0xFF; // flip the final byte — same size, wrong hash
                        let _ = std::fs::write(&inc.part_path, &bytes);
                        eprintln!("[test] CORRUPT-RECV: flipped the last byte of {} (id {})", inc.name, inc.id);
                        if once { test_hooks::corrupt_mark_fired(); }
                    }
                }
            }
        }
        // Silence the unused binding on default builds (this arm never runs there).
        let _ = &target;
    }

    // A short file can't possibly match — it's truncated; resume the tail.
    if inc.received < inc.size {
        return VerifyResult::Mismatch { restart_from_zero: false };
    }
    let path = inc.part_path.clone();
    let got = tokio::task::spawn_blocking(move || full_hash(&path)).await.ok().flatten();
    match got {
        Some(g) if g == want => VerifyResult::Match,
        // Full size but wrong hash → corrupt body, re-fetch whole.
        _ => VerifyResult::Mismatch { restart_from_zero: true },
    }
}

/// Finalize a fully-received incoming file: flush, rename `.part` → final,
/// clean up the meta sidecar, and (in daemon mode) append to the upload log.
/// Returns true if the file was placed (so the caller bumps `completed`).
/// Shared by the file-end control-frame path and the G-k completion sweep —
/// the two must not drift. `daemon`/`from_name` drive only the daemon log.
async fn finalize_incoming(
    mut inc: IncomingFile,
    dir: &Path,
    rename_to: Option<&str>,
    daemon: bool,
    from_name: &str,
) -> Result<bool> {
    inc.file.flush().await?;
    drop(inc.file);
    let final_path = unique_path(dir, rename_to.unwrap_or(&inc.name));
    if let Err(e) = tokio::fs::rename(&inc.part_path, &final_path).await {
        // C23: a duplicate stream's partial may already be finalized — discard
        // quietly instead of dying.
        ui::say(&ui::paint(ui::Tone::Dim, &format!("  (stream for {} already finalized — duplicate discarded: {e})", inc.name)));
        return Ok(false);
    }
    let _ = tokio::fs::remove_file(dir.join(format!("{}.part.meta", inc.name))).await;
    let ok = inc.received == inc.size;
    inc.bar.done(inc.received);
    let shown = final_path.display().to_string();
    ui::say(&format!(
        "    {} {}{}",
        ui::paint(ui::Tone::Dim, ui::glyph_arrow()),
        ui::link(&format!("file://{shown}"), &shown),
        if ok { String::new() } else { ui::paint(ui::Tone::Err, "  SIZE MISMATCH") },
    ));
    if daemon {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(up_log()) {
            let _ = writeln!(f, "{}  {}  {}  from {}", chrono_now(), inc.name, human(inc.received), from_name);
        }
    }
    Ok(true)
}

/// G-k completion sweep: file-end delivery is best-effort. A stream can
/// receive every expected byte yet have its file-end LOST when the sender's
/// PeerConnection tears down first (observed under load). The bytes are whole
/// (held in `inc.received`; `finalize_incoming` flushes the BufWriter before
/// rename so the on-disk file is complete), but the stream is stranded in
/// `by_sid` with no live link to ever deliver file-end — and that non-empty
/// `by_sid` plus `completed == 0` blocks the quiet-exit while the dead link
/// spins through the reconnect-retry loop to the 120s ceiling. Finalize any
/// fully received stream whose link is gone. `received == size` is exactly the
/// bar the file-end handler itself checks, so this can never claim a genuine
/// partial (received < size stays parked for resume — gate 2) and never
/// touches the offer-stage corruption guard (gate 3). Called both at top-of-
/// loop and right after a link is dropped in the Stuck/GraceExpired handlers,
/// so the bail on `completed == 0` sees the finalized file.
async fn sweep_completed_streams(
    by_sid: &mut HashMap<(String, u32), IncomingFile>,
    conn: &Conn,
    dir: &Path,
    output: &Option<String>,
    to_stdout: bool,
    daemon: bool,
    completed: &mut usize,
) -> Result<()> {
    let done_sids: Vec<(String, u32)> = by_sid
        .iter()
        .filter(|((pid, _), inc)| inc.received == inc.size && !conn.links.contains_key(pid))
        .map(|(k, _)| k.clone())
        .collect();
    for key in done_sids {
        if let Some(mut inc) = by_sid.remove(&key) {
            if to_stdout {
                // Parity with the file-end handler: flush before counting it,
                // since dropping a tokio BufWriter does not async-flush.
                let _ = inc.file.flush().await;
                *completed += 1;
                continue;
            }
            let rename_to = if *completed == 0 { output.clone() } else { None };
            ui::say(&ui::paint(ui::Tone::Dim, &format!("  ({} fully received — sender left before file-end; finalizing)", inc.name)));
            if finalize_incoming(inc, dir, rename_to.as_deref(), daemon, "").await? {
                *completed += 1;
            }
        }
    }
    Ok(())
}

/// Park in-flight receives: flush buffers so the .part files are complete up
/// to the last byte received, then drop the per-link routing. Resume picks
/// them up from disk.
async fn flush_inflight(by_sid: &mut HashMap<(String, u32), IncomingFile>) {
    for (_sid, mut inc) in by_sid.drain() {
        let _ = inc.file.flush().await;
        ui::debug(&format!("{}: parked at {} for resume", inc.name, human(inc.received)));
    }
}

/// C22: cbreak-mode guard — single-keypress answers without losing line
/// input. `stty` keeps us dependency-free; Drop restores the terminal (and
/// the Interrupted path calls restore() explicitly since process::exit skips
/// Drop).
struct TtyGuard {
    saved: Option<String>,
}

impl TtyGuard {
    fn raw() -> TtyGuard {
        let saved = std::process::Command::new("stty")
            .arg("-g")
            .stdin(std::process::Stdio::inherit())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        if saved.is_some() {
            let _ = std::process::Command::new("stty")
                .args(["-icanon", "-echo", "min", "1", "time", "0"])
                .stdin(std::process::Stdio::inherit())
                .status();
        }
        TtyGuard { saved }
    }
    fn restore(&self) {
        if let Some(s) = &self.saved {
            let _ = std::process::Command::new("stty")
                .arg(s)
                .stdin(std::process::Stdio::inherit())
                .status();
        }
    }
}

impl Drop for TtyGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// C22: per-process token marking a locally re-enqueued (consented) offer.
/// A remote peer cannot know it, so it cannot forge consent in a control msg.
fn consent_token() -> &'static str {
    static T: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    T.get_or_init(fresh_secret)
}

/// C26: one-line colored peer status — static scrollback lines, the CLI's
/// equivalent of the web UI's amber 'away' tile.
///   ✓ deft-gibbon                    (connected)
///   ● deft-gibbon  away — choosing a file
///   ◌ deft-gibbon  reconnecting…
fn peer_entry(name: &str, mark: &str, tone: ui::Tone, note: &str) -> String {
    let mut s = format!("{} {}", ui::paint(tone, mark), ui::paint(ui::Tone::Bold, name));
    if !note.is_empty() {
        s.push_str(&format!("  {}", ui::paint(ui::Tone::Dim, note)));
    }
    s
}

fn offer_question(sender: &str, name: &str, size: u64, paired: bool) -> String {
    let sender = if sender.is_empty() { "unknown peer" } else { sender };
    let hint = if paired { " [paired]" } else { "" };
    format!(
        "  {}{} offers {} ({}) — accept? [y/N] ",
        ui::paint(ui::Tone::Bold, sender),
        hint,
        name,
        human(size)
    )
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_deny_by_default() {
        // GATE 5: deny-by-default. A device with empty caps is refused any gated
        // action; "transfer" is the always-allowed L0 baseline; a v1 record
        // (no caps) reads as ["transfer"]; future caps must be explicitly
        // granted (i.e. agreed under K at re-enrollment), not escalatable.
        let dir = std::env::temp_dir().join(format!("fil-caps-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("devices.json");
        let sec = "a".repeat(64);
        std::fs::write(
            &p,
            serde_json::to_string(&json!([
                {"name": "empty",   "secret": sec, "v": 2, "caps": []},
                {"name": "xfer",    "secret": sec, "v": 2, "caps": ["transfer"]},
                {"name": "execcap", "secret": sec, "v": 2, "caps": ["transfer", "remote-exec"]},
                {"name": "legacy",  "secret": sec}  // v1 record: reads as ["transfer"]
            ]))
            .unwrap(),
        )
        .unwrap();

        // transfer is the L0 baseline — allowed even for empty caps.
        assert!(device_allows_at(&p, "empty", "transfer"), "transfer is the L0 baseline");
        assert!(device_allows_at(&p, "xfer", "transfer"));
        // A v1 record reads as caps:["transfer"] (back-compat, spec §8).
        assert_eq!(device_caps_at(&p, "legacy"), Some(vec!["transfer".to_string()]));
        assert!(device_allows_at(&p, "legacy", "transfer"));
        // Deny-by-default: a gated future cap is REFUSED unless explicitly granted.
        assert!(!device_allows_at(&p, "empty", "remote-exec"), "empty caps must deny remote-exec");
        assert!(!device_allows_at(&p, "xfer", "remote-exec"), "transfer-only must deny remote-exec");
        assert!(!device_allows_at(&p, "legacy", "remote-exec"), "v1 record must deny remote-exec");
        // Only a device explicitly granted the cap (under K, at enrollment) is allowed.
        assert!(device_allows_at(&p, "execcap", "remote-exec"), "explicitly granted cap is allowed");
        // An unknown device grants no GATED cap (but transfer is the universal
        // L0 baseline, so it is allowed regardless — never regresses send/recv).
        assert!(!device_allows_at(&p, "ghost", "remote-exec"));
        assert!(device_allows_at(&p, "ghost", "transfer"), "transfer baseline is universal");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shell_policy_gates_auto_shell() {
        // `up` default: NOTHING auto-shells — a device needs an explicit grant.
        let g = ShellPolicy::Granted;
        assert!(!g.auto_allows("popos"));
        assert!(!g.enables_l2(), "default must not silently enable the L2 acceptor");
        // `up --shell`: every paired device auto-shells, and L2 is on.
        let a = ShellPolicy::All;
        assert!(a.auto_allows("popos") && a.auto_allows("anything"));
        assert!(a.enables_l2());
        // `up --shell-only popos,laptop`: only the listed petnames; others don't.
        let o = ShellPolicy::Only(["popos".to_string(), "laptop".to_string()].into_iter().collect());
        assert!(o.auto_allows("popos") && o.auto_allows("laptop"));
        assert!(!o.auto_allows("stranger"), "shell-only must not auto-shell unlisted devices");
        assert!(o.enables_l2());
    }

    #[test]
    fn forget_and_store_preserve_other_devices_caps() {
        // Regression: forgetting/pairing a device must NOT wipe the `shell`
        // (or any v2) caps of the OTHER devices. The old (name, secret) tuple
        // round-trip rewrote every survivor as bare {name, secret}, silently
        // dropping their grants — a remembered device lost its shell on the
        // next `forget`/`pair`.
        let dir = std::env::temp_dir().join(format!("fil-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Serialize: these tests mutate the process-global FILAMENT_CONFIG_DIR.
        unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", &dir) };
        let p = dir.join("devices.json");
        let sec = "b".repeat(64);
        std::fs::write(
            &p,
            serde_json::to_string(&json!([
                {"name": "shellbox", "secret": sec, "v": 2, "caps": ["transfer", "shell"]},
                {"name": "dupe",     "secret": sec, "v": 2, "caps": ["transfer"]},
            ]))
            .unwrap(),
        )
        .unwrap();

        // Forgetting 'dupe' must leave 'shellbox' with its shell cap intact.
        devices_remove("dupe").unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "forget wiped a survivor's shell cap");
        assert!(device_caps_at(&p, "dupe").is_none(), "dupe should be gone");

        // Storing a NEW pairing must also preserve 'shellbox'’s caps.
        devices_store("newpeer", &sec).unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "store wiped a survivor's shell cap");
        // And re-storing an existing name keeps its caps (only the secret rotates).
        devices_store("shellbox", &"c".repeat(64)).unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "re-store dropped the device's own caps");

        unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proof_matches_browser() {
        // Pinned to the SAME external vector as frontend devices.js (computed
        // with `printf 'filament-proof2:u1|u1|u2|FPA|FPB' | openssl dgst
        // -sha256 -hmac s3cret`). If either implementation drifts, browsers
        // and CLIs silently stop recognizing each other as known devices.
        // The JS half of this byte-identity proof asserts the IDENTICAL vectors:
        // cli/tests/l1a/gate8_byte_identity.mjs (channelOf/proofFor).
        let want = "f98c3b6b7a70ebdf4b200680e83383881bdb1a11476283507359c55ef03a8474";
        // deliberately unsorted inputs — proof_for must normalize
        assert_eq!(proof_for("s3cret", "u1", "u2", "u1", "FPB", "FPA"), want);
        assert_eq!(proof_for("s3cret", "u1", "u1", "u2", "FPA", "FPB"), want);
        // channel derivation, same cross-check (sha256 of "filament-pair:"+secret)
        assert_eq!(
            channel_of("topsecret"),
            "1e32e46e93691c29d9c0305545a10c86a00ae9f3c43d4eea3c7423c1528f9b5d"
        );
    }

    #[test]
    fn polite_role_matches_browser() {
        // uid comparison wins, string-lexicographic, mirrors webrtc.js politeRole
        assert!(net::polite_role("b", Some("a"), "x", "y")); // myUid > peerUid -> polite
        assert!(!net::polite_role("a", Some("b"), "x", "y"));
        // identical/missing uids fall back to sids
        assert!(net::polite_role("a", Some("a"), "y", "x"));
        assert!(!net::polite_role("a", None, "x", "y"));
        // exactly one side of any pair is impolite
        for (a, b) in [("a", "b"), ("cli-1", "cli-2"), ("zz", "aa")] {
            let p1 = net::polite_role(a, Some(b), "s1", "s2");
            let p2 = net::polite_role(b, Some(a), "s2", "s1");
            assert_ne!(p1, p2, "{a} vs {b} must disagree");
        }
    }

    #[test]
    fn part_meta_roundtrip_and_legacy() {
        let dir = std::env::temp_dir().join(format!("filament-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.part.meta");
        PartMeta { size: 42, head: Some("abc".into()), full: Some("deadbeef".into()) }.store(&p).unwrap();
        let m = PartMeta::load(&p).unwrap();
        assert_eq!(m.size, 42);
        assert_eq!(m.head.as_deref(), Some("abc"));
        // P4: the whole-file digest survives the round-trip too.
        assert_eq!(m.full.as_deref(), Some("deadbeef"));
        // legacy plain-size format still parses
        std::fs::write(&p, "1234").unwrap();
        let m = PartMeta::load(&p).unwrap();
        assert_eq!(m.size, 1234);
        assert!(m.head.is_none());
        assert!(m.full.is_none());
        // garbage does not
        std::fs::write(&p, "{not json").unwrap();
        assert!(PartMeta::load(&p).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn head_hash_is_prefix_stable() {
        let dir = std::env::temp_dir().join(format!("filament-test-h-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        // same first 256 KiB, different tails -> same head (by design: head is
        // a prefix identity, full integrity is the per-chunk-hash backlog)
        let mut base = vec![7u8; (HEAD_BYTES + 10) as usize];
        std::fs::write(&a, &base).unwrap();
        base[(HEAD_BYTES + 5) as usize] = 9;
        std::fs::write(&b, &base).unwrap();
        assert_eq!(head_hash(&a), head_hash(&b));
        // different first bytes -> different head
        base[0] = 1;
        std::fs::write(&b, &base).unwrap();
        assert_ne!(head_hash(&a), head_hash(&b));
        // short files hash their whole content
        std::fs::write(&a, b"tiny").unwrap();
        std::fs::write(&b, b"tinY").unwrap();
        assert_ne!(head_hash(&a), head_hash(&b));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_hash_whole_file_integrity() {
        // P4 (GAP-5): full_hash digests the WHOLE file (not just the 256 KiB
        // head), so a difference PAST the head — exactly the truncation/corrupt
        // case the head-hash can't see — produces a different digest.
        let dir = std::env::temp_dir().join(format!("filament-test-fh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let mut base = vec![3u8; (HEAD_BYTES + 4096) as usize];
        std::fs::write(&a, &base).unwrap();
        // identical head, byte flipped well PAST the head: head_hash agrees but
        // full_hash MUST differ (this is the whole-file guarantee).
        base[(HEAD_BYTES + 2048) as usize] = 4;
        std::fs::write(&b, &base).unwrap();
        assert_eq!(head_hash(&a), head_hash(&b), "tails past the head don't change the head hash");
        assert_ne!(full_hash(&a), full_hash(&b), "full_hash sees the whole file");
        // a truncated file (same prefix, shorter) also differs.
        std::fs::write(&b, &base[..base.len() - 100]).unwrap();
        assert_ne!(full_hash(&a), full_hash(&b), "truncation changes the full hash");
        // full_hash matches a one-shot sha256 of the bytes.
        assert_eq!(full_hash(&a), Some(sha256_hex(&vec![3u8; (HEAD_BYTES + 4096) as usize])));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_path_suffixes() {
        let dir = std::env::temp_dir().join(format!("filament-test-u-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt"));
        std::fs::write(dir.join("f.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt.1"));
        std::fs::write(dir.join("f.txt.1"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt.2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_address_classification() {
        // C2: the badge means "bytes never leave your network" — an address
        // property, not a candidate-type property.
        for a in ["127.0.0.1", "10.1.2.3", "192.168.1.9", "172.16.0.1", "169.254.1.1", "100.99.1.2", "::1", "fe80::1", "fd00::5"] {
            assert!(net::is_private_addr(a), "{a} should be private");
        }
        for a in ["1.2.3.4", "165.22.207.231", "2606:4700::1", "8.8.8.8", "not-an-ip", ""] {
            assert!(!net::is_private_addr(a), "{a} should be public/invalid");
        }
    }

    #[test]
    fn recv_done_drops_only_when_complete() {
        // Gate-18 Mode B: the drop-instead-of-reconnect decision must hold
        // ONLY when the transfer is complete and idle. This is the exact fence
        // that protects gate 2 (kill-resume) and gate 11c (deferred-drop): a
        // mid-transfer link (by_sid non-empty) must always reconnect.
        // complete + idle + not keep_open -> drop the dead link, let quiet-exit
        assert!(recv_transfer_done(1, false, true));
        assert!(recv_transfer_done(3, false, true));
    }

    #[test]
    fn recv_done_false_mid_transfer_protects_resume() {
        // by_sid NON-empty == a stream in flight (an in-progress reconnect or
        // resume). Must NOT drop — gate 2 / gate 11c reconnect paths depend on
        // this returning false so on_stuck re-establishes.
        assert!(!recv_transfer_done(0, false, false)); // nothing done, mid-stream
        assert!(!recv_transfer_done(1, false, false)); // file done but another in flight
        // keep_open (gate 13): a resident receiver never self-drops its links.
        assert!(!recv_transfer_done(1, true, true));
        assert!(!recv_transfer_done(5, true, true));
        // nothing completed yet (still connecting / first stream) -> reconnect.
        assert!(!recv_transfer_done(0, false, true));
    }

    #[test]
    fn filename_sanitization() {
        // the recv path strips directories from remote names
        let evil = "../../etc/passwd";
        let name = Path::new(evil).file_name().map(|n| n.to_string_lossy().into_owned());
        assert_eq!(name.as_deref(), Some("passwd"));
        let evil2 = "/absolute/path.bin";
        let name2 = Path::new(evil2).file_name().map(|n| n.to_string_lossy().into_owned());
        assert_eq!(name2.as_deref(), Some("path.bin"));
    }

    // Bug 1: `send --name X` is honored for a SINGLE regular file (offer name =
    // override), the basename otherwise, and "stdin.bin" for bare stdin. This
    // mirrors the send_cmd offer-name decision as a pure check.
    #[test]
    fn send_name_override_for_single_file() {
        let offered = |name: Option<&str>, single: bool, basename: &str| -> String {
            name.map(String::from)
                .filter(|_| single)
                .unwrap_or_else(|| basename.to_string())
        };
        // single file + --name → the override wins
        assert_eq!(offered(Some("renamed.bin"), true, "original.txt"), "renamed.bin");
        // single file, no --name → basename
        assert_eq!(offered(None, true, "original.txt"), "original.txt");
        // multiple paths (single=false) + --name → ignored, basename used
        assert_eq!(offered(Some("renamed.bin"), false, "original.txt"), "original.txt");
        // stdin default
        let stdin = |name: Option<&str>, single: bool| {
            name.map(String::from).filter(|_| single).unwrap_or_else(|| "stdin.bin".into())
        };
        assert_eq!(stdin(Some("logs.tar"), true), "logs.tar");
        assert_eq!(stdin(None, true), "stdin.bin");
    }

    // Bug 4: the legacy 3-segment transfer code and the 4-segment PAKE pairing
    // code are distinguishable, and never both match the same string.
    #[test]
    fn transfer_and_pairing_codes_are_distinguishable() {
        // legacy transfer code: word-word-digits
        assert!(regex_lite_code("brave-otter-37"));
        assert!(!looks_like_pake_code("brave-otter-37"));
        // PAKE pairing code: adj-animal-extra-NNNN
        assert!(looks_like_pake_code("brave-otter-ruby-3141"));
        assert!(!regex_lite_code("brave-otter-ruby-3141"));
        // neither classifier ever claims the same string
        for s in ["brave-otter-37", "brave-otter-ruby-3141", "calm-lynx-9", "swift-fox-teal-1000"] {
            assert!(!(regex_lite_code(s) && looks_like_pake_code(s)), "{s} ambiguous");
        }
        // junk matches neither
        assert!(!regex_lite_code("hello"));
        assert!(!looks_like_pake_code("hello"));
        assert!(!looks_like_pake_code("a-b-c-d")); // last seg not numeric
        assert!(!looks_like_pake_code("Brave-otter-ruby-3141")); // uppercase
    }
}
