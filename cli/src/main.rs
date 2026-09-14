// filament, anywhere-to-anywhere P2P file transfer, CLI end.
//
// Speaks the exact same wire protocol as the browser app at
// https://filament.autumated.com: Socket.IO signaling, perfect-negotiation
// WebRTC, one-time pairing codes, and sid-framed chunk transfer with
// offset-based resume. A browser is a first-class peer: `filament send` can
// deliver straight to a phone with nothing installed on it.
//
//   filament send video.mp4 --code          mint a speakable one-time code
//   filament receive clever-lynx-63          claim it on the other machine
//   filament send ./dir --room demo         directories are tarred on the fly
//   tar c logs | filament send - --name logs.tar --code
//   filament receive -y --dir ~/Drops       auto-accept into a directory
//
// Failure-mode ledger: ../docs/cli-resilience.md, every resilience behavior
// in this file carries its ledger number (C1..C17 / F1..F4).

mod codeentry;
mod armed;
mod ctl;
mod subnet_forward;
mod diag;
use filament_transport::direct;
mod doctor;
/// `filament ephemeral`: auth-key delegation for ephemeral devices, pre-authorized
/// self-enrollment, and delegated principal ceiling enforcement.
mod ephemeral;
mod fleet;
use filament_fleet::session as fleet_session;
// The byte-moving mechanics now live in their own crate: out-of-order range
// reassembly, the untrusted-name reduction, and the short-write-safe positional
// write. None of it has any opinion about how a peer was found, which is exactly
// why it could leave this file.
use filament_transfer::{
    pwrite_at, record_range, safe_incoming_name, 
};
mod fleet_enrollment;
mod fleet_renewal;
mod exit_route;
mod exec_recv;
mod exec_send;
mod ssh_ca;
/// `filament expose`: publish a local port on the L3 overlay. The CLI/config side
/// is portable; the daemon listeners (Exposer) are Linux-gated with L3.
mod expose;
mod holepunch;
// Multi-device user identity lives in the standalone `filament-id` crate; alias
// it as `identity` so every `crate::identity::…` / `identity::…` call site keeps
// resolving unchanged. Key persistence is injected via `platform::PlatformKeyStore`.
pub(crate) use filament_id as identity;
mod interact;
mod l2;
mod mount;
mod mount_proto;
#[cfg(target_os = "linux")]
mod mount_fuse;
#[cfg(all(target_os = "windows", feature = "mount-windows"))]
mod mount_winfsp;
mod backup;
mod capability;
// The transport ladder now lives in filament-transport. Aliased so every
// `net::` / `direct::` call site in the CLI reads unchanged.
use filament_transport::net;
mod overlay;
mod platform;
// PAKE first-pairing lives in the standalone `filament-pair` crate; alias it as
// `pake` so every `crate::pake::…` call site keeps resolving unchanged.
pub(crate) use filament_pair as pake;
mod pake_ceremony;
mod ping;
mod roster;
mod sdnotify;
// The wire vocabulary and its pure decisions now live in their own crate. Kept
// under the `protocol::` name so every call site reads unchanged.
use filament_proto as protocol;
mod resilience;
mod session;
/// Receive-file leaf helpers (assembly, resume, whole-file verification).
/// Daemon control-socket + warm-reuse handlers, lifted out of this file.
mod daemon_ctl;
/// Certificate-renewal + auth-key enrolment lifecycle handlers.
mod renewal_lifecycle;
/// Peer-identity proof/expose lifecycle handlers.
mod identity_lifecycle;
/// `filament enroll` and its shared helpers.
mod enrollment;
/// `filament introduce` / `filament depart`.
mod membership;
/// `filament pair` and its pair-specific helpers.
mod pair_cmd;
#[cfg(test)]
use pair_cmd::invitation_not_a_code_msg;
/// `filament up` / `filament logs`.
mod up_logs;
/// `filament add --for`.
mod add_for;
/// `filament recv`, the receive-side event loop.
mod recv_cmd;
use recv_cmd::recv_cmd;
/// `filament send`.
mod send_cmd;
/// The CLI dispatch table.
mod dispatch;
use dispatch::async_main;
/// Bare-argument routing and the first-screen actions.
mod first_screen;
pub(crate) use first_screen::{classify_bare_token, first_screen_actions};
/// `filament update`.
mod update_cmd;
pub(crate) use update_cmd::update_cmd;
/// Device lookups and views.
mod device_view;
pub(crate) use device_view::{devices_store, devices_store_v2, device_cert_for, device_cert_valid_for, device_record_exists, device_name_for_pub, device_cert_revoked, devices_find_by_device_pub, devices_sweep_lapsed, devices_touch, devices_info, device_countdown, device_entries};
#[cfg(test)]
pub(crate) use device_view::devices_touch_at;
/// Mount planning/implementation and reset.
mod mount_cmd;
pub(crate) use mount_cmd::{reset_cmd, resolve_mount_plan};
#[cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos"), all(target_os = "windows", feature = "mount-windows")))]
pub(crate) use mount_cmd::mount_fuse_cmd;
/// Fleet helpers and mesh housekeeping.
mod fleet_support;
pub(crate) use fleet_support::{apply_reconfigure, ensure_self_genesis_header, fleet_certificate_warning, fleet_identity_pending, fleet_indexed_name, fleet_route_ok, fleet_shaped_link, fleet_share_root, sweep_completed_streams, sweep_lapsed};
#[cfg(test)]
pub(crate) use fleet_support::fleet_certificate_warning_for;
/// Identity creation, joining and the state behind them.
mod identity_flow;
pub(crate) use identity_flow::{init_experience, join_cmd, local_device_cert, open_enrollment};
#[cfg(test)]
pub(crate) use identity_flow::principal_from_records;
/// The inspect commands and their state helpers.
mod status_cmd;
pub(crate) use status_cmd::{detach_up, delegated_device_state, mesh_enrolment, requests_cmd, status_cmd, tour_cmd};
/// Identity, principal and capability state helpers.
mod identity_state;
pub(crate) use identity_state::{capability_list_summary, cert_revoked_for, certify_local_device, effective_principal_deadline, mark_lapsed_now, merge_owner_cap_ops, mint_capability, owner_cap_header, owner_signed_cap_ops, persisted_principal_for_cert, principal_ceiling_for, require_known_device, revoke_recheck_interval, sanitize_device_name, set_device_cert_revoked, set_device_revoked};
/// Session, daemon and mount runtime helpers.
mod runtime_support;
pub(crate) use runtime_support::{add_pending_request, is_light_command, next_ev, read_owner_only_file, recover_identity, resolve_for_kind, spawn_session_pumps, stop_managed_service};
#[cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos"), all(target_os = "windows", feature = "mount-windows")))]
pub(crate) use runtime_support::unmount_fuse;
/// L2 allow/open policy.
mod l2_policy;
pub(crate) use l2_policy::{l2_open_allowed, l2_target_allowed};
#[cfg(test)]
pub(crate) use l2_policy::l2_target_allowed_in;
/// Owner-only files, pidfile and small parsers.
mod file_io;
pub(crate) use file_io::{parse_duration_secs, parse_invitation, parse_mint_ttl, pidfile, read_owner_only_fd, write_owner_only_fd, write_owner_only_file, write_pidfile};
/// Shared limits, wire constants and small types.
mod shared_defs;
pub(crate) use shared_defs::{DEFAULT_SERVER, DeadlineClock, FLEET_LINK_NAME, FORCE_INTERACTIVE, MAX_ATTEMPTS, MAX_PENDING, MAX_VERIFY_FAILS, MountPlan, NO_INTERACTIVE, NO_RELAY, PRINCIPAL_STATE_LAPSED, PRINCIPAL_STATE_REVOKED, PartMeta, PeerAuthz, PendingRequest, REJOIN_WINDOW, REPO, REQUEST_TTL_SECS, RecvState, RevokeRecheck, STALL_MAX_REPAIRS, SendOutcome, ServiceManager, ShellPolicy, TtyGuard, VERIFY_PROBE_SID};
#[cfg(test)]
pub(crate) use shared_defs::HEAD_BYTES;
/// Shell authority helpers and daemon/service probes.
mod shell_support;
pub(crate) use shell_support::{any_shell_grant, daemon_alive, daemon_running, require_shell_owner_ack, service_manager_for_pid, shell_argv, shell_grant_names, shell_root_note};
/// The single shell gate shared by pty-open and exec-open.
mod shell_gate;
#[cfg(test)]
pub(crate) use shell_support::service_manager_for_cgroup;
/// Hashing, time and randomness primitives.
mod crypto_atoms;
/// Policy gates.
mod policy;
pub(crate) use policy::{cancelled, interactive_allowed, quiet_exit_window, relay_banner, relay_forbidden};
pub(crate) use crypto_atoms::{chrono_now, fresh_secret, head_hash, hmac_sha256, link_nonce, sha256_hex};
#[cfg(test)]
pub(crate) use shell_support::shell_grant_names_at;
#[cfg(test)]
pub(crate) use shell_support::any_shell_grant_at;
use enrollment::{enroll_cmd};
/// `filament up --install`: the managed-service unit, per platform.
mod install_service;
use install_service::install_system_service;
/// The devices.json substrate: load, atomic upsert, locked mutation.
mod devices_store;
pub(crate) use devices_store::{
    devices_load, devices_path, devices_upsert_atomic, upsert_peer_record, with_devices_mut,
};
/// Device-capability store and evaluation helpers.
mod device_caps;
#[cfg(test)]
use device_caps::{device_allows_at, device_caps_at, device_caps_at_time};
use device_caps::{
    device_allows, device_capability_denied, device_set_cap, devices_remove,
    issue_signed_bounded_grant, mark_bounded_cap_source,
};
#[cfg(test)]
use identity_lifecycle::{VOUCH_CERT_SCOPE, principal_after_liveness, update_peer_identity};
use identity_lifecycle::{
    PROVEN_CHALLENGE_DEADLINE, clear_provisional_identity, handle_identity_expose,
    issue_proven_challenge_and_hold, load_provisional_identity, resolve_peer_identity,
    respond_to_identity_challenge, store_provisional_identity,
};
use renewal_lifecycle::{
    handle_auth_key_enroll_response, handle_cert_renew_ack, maybe_request_cert_renewal,
    respond_to_auth_key_enroll_request, respond_to_cert_renew_request,
};
// DaemonMounts/WarmPtys/sshd_listening exist on every target (handle_warm_req
// has a not(unix) stub); the rest are unix-only, so they need the gate their
// definitions carry. Call sites stay byte-identical to the monolith.
use daemon_ctl::{DaemonMounts, WarmPtys, handle_warm_req, sshd_listening};
#[cfg(unix)]
use daemon_ctl::{
    PendingBootstraps, complete_warm_bootstrap, handle_list_mounts, handle_list_warm,
    handle_mount, handle_mount_health, handle_unmount, handle_warm_bootstrap,
    reap_warm_bootstraps, warm_link_for,
};
mod recv_files;
#[cfg(test)]
use recv_files::unique_path;
#[cfg(test)]
use recv_files::full_hash;
use recv_files::{
    IncomingFile, finalize_incoming, safe_create_part, safe_resume_part,
    verify_incoming,
};
/// Connection state lifted out of this file (slice 1a of the decomposition):
/// the peer-link record, presence, the resilience/warm-hold bookkeeping, and
/// the pure decisions over them. `Conn`/`impl Conn` still live here.
mod conn;
pub(crate) use conn::Conn;
use conn::{AdoptSource, Presence, Rung, owner_pub_for_resources};
/// These names' last non-test user was the `impl Conn` that moved into `conn.rs`;
/// this file's own tests still exercise them, so import them for test builds only.
#[cfg(test)]
use conn::{
    active_binding_matches, link_dead_for, link_has_live_for, match_adoption_source,
    upgrade_principal,
};
mod settings;
/// L3 TUN data plane (serve_tun). Linux-only: it uses /dev/net/tun + TUNSETIFF,
/// which macOS (also `unix`) lacks, so gate on `target_os`, not `unix`.
#[cfg(l3)]
mod tun;
/// L3 overlay manager (routes IP packets across peer links); Linux-only.
#[cfg(l3)]
mod l3;
#[cfg(l3)]
mod wg;
mod shutdown;
mod sshd;
mod sshkeys;
mod local;
mod ui;
mod fleet_ui;

use anyhow::{bail, Result};
use net::{Ev, Transport};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

/// Positional write at an absolute offset, used by concurrent spawn_blocking
/// writer tasks for out-of-order multi-stream reassembly (no seek, atomic per
/// call). Cross-platform: `FileExt::write_at` on Unix, `seek_write` on Windows —
/// both write at `offset` without moving the shared handle's cursor.
// MUST write the ENTIRE buffer. A positional write (pwrite/seek_write) is allowed to
// write FEWER bytes than requested; the old code did `file.write_at(buf, offset)` and the
// caller discarded the returned count, so a short write left a gap while `received`
// advanced by the full length — a silent per-file corruption the whole-file digest then
// caught as a failed transfer (measured ~44% on direct-QUIC, ~88% on DataChannel for large
// files). Loop until the whole buffer lands; return Err on a real failure so the caller
// can react instead of silently dropping bytes.

fn rejoin_unwarned() -> Duration {
    std::env::var("FILAMENT_REJOIN_SECS") // test knob (gate 15)
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(45))
}

/// Test/injection hooks, env-gated fault injectors used ONLY by the resilience
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
    /// L3-over-relay gate: refuse the rung-1 direct-QUIC path even for a daemon.
    /// `direct_ok_for` forces direct ON for any long-lived acceptor (anti-glare),
    /// which is right in production and makes the DataChannel data path
    /// unreachable on a single box, so it cannot otherwise be exercised.
    pub fn no_direct() -> bool {
        std::env::var("FILAMENT_TEST_NO_DIRECT").map(|v| v == "1").unwrap_or(false)
    }
    /// gate 11b: hold each chunk briefly so a transfer is still FLOWING when the
    /// gate's second receiver rejoins.
    ///
    /// 11b asserts that a same-uid reconnect does not tear down a live transfer,
    /// which requires the transfer to still be live when the reconnect lands. It
    /// waits for 8 MB of an 80 MB file, but that file moves at ~96 MB/s on CI, so
    /// the whole thing finishes in under a second and the reconnect arrives after
    /// the fact. The gate then fails on a FAST machine, which is why it flips run
    /// to run. Same problem, and same remedy, as `pair_stall` for gate 17b.
    pub fn transfer_stall_ms() -> u64 {
        std::env::var("FILAMENT_TEST_TRANSFER_STALL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
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
    /// shutdown-hang gate: deterministically reproduce the multi-link shutdown
    /// hang by WEDGING the event loop forever (simulating a peer transport whose
    /// inline write never returns). With the wedge active, the graceful
    /// Ev::Interrupted is never processed; only the signal-owned force-exit
    /// watchdog can still terminate the process. Proves the A/B: a build whose
    /// watchdog is defeated hangs to the systemd timeout, the shipped one exits
    /// within the bounded grace.
    pub fn wedge_loop_on_shutdown() -> bool {
        std::env::var("FILAMENT_TEST_WEDGE_LOOP").is_ok()
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
    /// P4 silent-data-loss gate: the receiver finalizes the file INTACT but
    /// suppresses the outbound `delivery-ack`, faithfully simulating an ack that
    /// never reaches the sender on an otherwise-healthy link (the black-hole-on-
    /// the-ack case). The sender must then re-probe and end UNCONFIRMED, never a
    /// false "delivered + verified". Distinct from corrupt-recv (which drives the
    /// re-request loop): here the bytes are whole, only the ack is withheld.
    pub fn suppress_delivery_ack() -> bool {
        std::env::var("FILAMENT_TEST_SUPPRESS_ACK").is_ok()
    }

    /// BUG-ACKLOSS reproducer (test-only): `FILAMENT_TEST_PREMATURE_CLOSE=1` tears
    /// the link DOWN at the exact moment the delivery-ack is due, so the ack never
    /// reaches the sender and the sender's transport observes ApplicationClosed(0,"").
    /// QUIC has no flush-on-close (RFC 9000 s10.2), so this is precisely the
    /// self-inflicted teardown race the multi-stream push otherwise hit only ~1-in-5
    /// on 10GB cross-machine transfers -- made DETERMINISTIC on a 1MB localhost
    /// transfer. The sender then sits in AWAIT_ACK on a dead link (the corpse
    /// cascade). Models `premature_close` in proofs/transport_lifecycle_model.py.
    /// No-op on default/release (compiled out). `=1` fires on EVERY completion;
    /// `=once` fires exactly once then falls through to a normal ack -- so an `up`
    /// daemon receiver (which stays alive) can be re-dialed and RECOVER (deliver on
    /// the second attempt) instead of looping drop -> re-dial -> drop. The latch is
    /// a process-global AtomicBool, mirroring corrupt_once.
    pub fn premature_close_after_ack() -> bool {
        matches!(std::env::var("FILAMENT_TEST_PREMATURE_CLOSE").as_deref(), Ok("1") | Ok("once"))
    }
    static PREMATURE_FIRED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    pub fn premature_close_once() -> bool {
        std::env::var("FILAMENT_TEST_PREMATURE_CLOSE").as_deref() == Ok("once")
    }
    pub fn premature_already_fired() -> bool {
        PREMATURE_FIRED.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn premature_mark_fired() {
        PREMATURE_FIRED.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// truncation/ack gate corruption injector. `FILAMENT_TEST_CORRUPT_RECV=<id>`
    /// flips the last on-disk byte of the matching transfer; `_CORRUPT_ONCE=1`
    /// fires exactly once (proving auto-recovery). The "already fired" latch is a
    /// process-global AtomicBool, no env mutation (the old code did an unsafe
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
    /// No stall in a build without test hooks: the send loop is untouched.
    #[inline] pub fn transfer_stall_ms() -> u64 { 0 }
    #[inline] pub fn webrtc_relay_only() -> bool { false }
    #[inline] pub fn disable_modeb_drop() -> bool { false }
    #[inline] pub fn no_defer() -> bool { false }
    #[inline] pub fn inject_peer_left_at() -> Option<u64> { None }
    #[inline] pub fn no_signaling_reconnect() -> bool { false }
    #[inline] pub fn wedge_loop_on_shutdown() -> bool { false }
    #[inline] pub fn churn_after_complete() -> bool { false }
    #[inline] pub fn drop_file_end() -> bool { false }
    #[inline] pub fn drop_peer_left() -> bool { false }
    #[inline] pub fn suppress_delivery_ack() -> bool { false }
    #[inline] pub fn premature_close_after_ack() -> bool { false }
    #[inline] pub fn premature_close_once() -> bool { false }
    #[inline] pub fn premature_already_fired() -> bool { false }
    #[inline] pub fn premature_mark_fired() {}
    #[inline] pub fn corrupt_recv_target() -> Option<String> { None }
}




/// App-wide UI capability resolved once from flags + env. Controls how every
/// command renders: interactive vs steer, human vs JSON, color vs plain.
pub struct UiCapability {
    pub interactive: bool,
    pub json: bool,
    pub yes: bool,
    pub color: bool,
}

impl UiCapability {
    pub(crate) fn from_cli(cli: &Cli) -> Self {
        let interactive = std::io::stdin().is_terminal()
            && !cli.no_interactive
            && !cli.json
            && std::env::var_os("FILAMENT_NONINTERACTIVE").is_none();
        let color = match cli.color.as_deref() {
            Some("always") => true,
            Some("never") => false,
            _ => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        UiCapability { interactive, json: cli.json, yes: cli.yes, color }
    }

    pub fn confirm(&self, action: &str) -> Result<()> {
        if self.yes { return Ok(()); }
        if self.interactive {
            // #208: a confirmation should cost ONE keypress, not a key and an
            // Enter. On a TTY read a single key with crossterm (raw mode); bare
            // Enter takes the capitalised default (N). Scripts/pipes keep the
            // line-reading path below, so `echo y | filament ...` is unchanged.
            if std::io::stdin().is_terminal() {
                use crossterm::event::{read, Event, KeyCode, KeyEvent, KeyModifiers};
                use std::io::Write as _;
                eprint!("{action} [y/N] ");
                let _ = std::io::stderr().flush();
                // #208: read ONE key with crossterm in raw mode; bare Enter takes
                // the capitalised default (N). The guard restores the terminal on
                // every path, including a panic.
                let _guard = crate::codeentry::RawGuard::enable().ok();
                let answer = match read() {
                    Ok(Event::Key(KeyEvent { code: KeyCode::Char('y'), modifiers: KeyModifiers::NONE, .. }))
                    | Ok(Event::Key(KeyEvent { code: KeyCode::Char('Y'), modifiers: KeyModifiers::NONE, .. })) => true,
                    Ok(Event::Key(KeyEvent { code: KeyCode::Char('c'), modifiers: KeyModifiers::CONTROL, .. })) => false,
                    _ => false,
                };
                drop(_guard);
                if !answer {
                    anyhow::bail!("cancelled");
                }
            } else {
                use std::io::Write;
                eprint!("{action} [y/N] ");
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).ok();
                if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    anyhow::bail!("cancelled");
                }
            }
        } else {
            // "to" belongs here, not in the callers. `action` is also the
            // interactive prompt ("shut down the daemon [y/N]"), where an
            // infinitive would read wrong, so one string is being asked to fit
            // two grammars and only this side needs the particle. Without it
            // every caller is ungrammatical in exactly one of the two modes:
            // "refusing shut down the daemon", "refusing include deliberate
            // remote authority in this invitation ceiling".
            anyhow::bail!("refusing to {action} without --yes (non-interactive)");
        }
        Ok(())
    }
}


fn interactive_requested() -> bool {
    FORCE_INTERACTIVE.load(std::sync::atomic::Ordering::Relaxed)
}





/// Gate-18 Mode B: the single predicate that decides whether a stuck/lost link
/// should be DROPPED (transfer is complete; nothing left to fetch) rather than
/// reconnected. Pulled out as a pure function so the gate-2 / gate-11c fence
/// (mid-transfer links must NEVER be dropped) is unit-testable without a live
/// WebRTC peer. The recv loop computes `conn.recv_done` from exactly this each
/// tick; `on_stuck` then reads the flag.
///
/// The pure file-transfer decisions `recv_transfer_done` and `decide_ack_fallback`
/// (+ the `AckFallback` enum) now live in `protocol.rs` (the Rust mirror of the JS
/// net/protocol layer); the send/recv loops call `protocol::...`.

/// Bug 5: after repeated stuck-while-connecting on establishment, the user has
/// no clue WHY. The dominant single-host cause is a browser publishing mDNS
/// (`*.local`) ICE candidates the CLI can't resolve when both ends share one
/// machine, the candidate pair never nominates and the link wedges silently.
/// Print this hint at most once per command. `shown` is the caller's one-shot
/// latch so the hint never repeats and never fires on a normal first blip.
fn maybe_hint_local_wedge(shown: &mut bool) {
    if *shown {
        return;
    }
    *shown = true;
    ui::say(&ui::paint(
        ui::Tone::Dim,
        "  still can't connect, if both ends are on the SAME machine, a browser's \
         mDNS (.local) ICE candidates can block this; try a different network path, \
         or disable mDNS ICE in the browser (chrome://flags → \"Anonymize local IPs\").",
    ));
}

/// The clap command surface.
mod cli_def;
pub(crate) use cli_def::{Cli, Cmd, DevicesAction, EphemeralAction, IdAction};
#[cfg(test)]
pub(crate) use cli_def::EXAMPLES;

/// Looks like a speakable CODE of the shape `word-word-DIGITS` (3 segments: two
/// lowercase words then a numeric trailing group of >= 2 digits). BOTH a minted
/// transfer code (`adj-animal-NNN`, 3-digit) and a minted pairing code
/// (`adj-animal-NNNN`, 4-digit) now share this shape, the pairing-vs-transfer
/// HINT is by trailing-number WIDTH (see `looks_like_pake_code`), not segment
/// count. This is the claimable-code structural test (used by the `up` prompt).
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

/// The trailing numeric group's width (digit count), or 0 if the last segment
/// isn't all digits. The pairing-vs-transfer hint keys off this: minted pairing
/// nameplates are 4-digit; minted transfer codes are 3-digit.
fn trailing_num_width(s: &str) -> usize {
    match s.rsplit('-').next() {
        Some(t) if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) => t.len(),
        _ => 0,
    }
}

/// ADVISORY hint that a typed code is a PAIRING code (vs a one-time transfer
/// code). Both are now `word-word-DIGITS`; the only structural difference is the
/// trailing-number WIDTH, a 4-digit nameplate is what `filament pair` / the
/// browser "create code" mints, whereas a transfer code ends in 3 digits. This
/// is UX-only, it NEVER authenticates (PAKE/SPAKE2 does), so it's safe to be
/// approximate; a mismatch still fails LOUDLY with the right next command.
fn looks_like_pake_code(s: &str) -> bool {
    regex_lite_code(s) && trailing_num_width(s) >= 4
}

/// STEERING (min-strength floor): count the WORD tokens in a normalized password,
/// maximal runs of >= 2 ASCII letters. A user-chosen password must contain at
/// least 2 such tokens. WHY: a minted 2-word code is ~12 bits and online
/// guessing is bounded by claim-burn + the 5/min rate-limit (≈1 guess per code,
/// no offline attack); a single word like `cat` falls below that floor. Digits
/// and 1-letter fragments don't count.
pub(crate) fn password_word_tokens(normalized_password: &str) -> usize {
    let mut tokens = 0;
    let mut run = 0;
    for c in normalized_password.chars() {
        if c.is_ascii_lowercase() {
            run += 1;
            if run == 2 {
                tokens += 1; // crossed the >=2-letter threshold
            }
        } else {
            run = 0;
        }
    }
    tokens
}

// --------------------------------------------------------------- utilities --

/// Persistent per-install identity (shared by every process using this
/// config dir). Lets a sender recognize, and never target, its OWN daemon
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
    let _ = crate::platform::SecretFile::write_str(&p, &id);
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
    default_display_name()
}

/// The computed display name when nothing is configured (user@host). Kept
/// separate so the settings readout can show the true default.
pub(crate) fn default_display_name() -> String {
    // #183.1: USER and /etc/hostname are UNIX-only. On Windows the platform
    // provides USERNAME and COMPUTERNAME and no /etc/hostname, so the unix
    // read would offer every device the literal name "cli".
    #[cfg(not(target_os = "windows"))]
    {
        let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
        let host = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "cli".into());
        format!("{user}@{host}")
    }
    #[cfg(target_os = "windows")]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
        let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "cli".into());
        format!("{user}@{host}")
    }
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


// ------------------------------------------------------- known devices (C12) --
// Persistent pairing: during a code-paired session, both sides exchange a
// 32-byte secret END-TO-END over the DataChannel (the server never sees it)
// and store it under a local nickname. Presence: subscribe with
// sha256("filament-pair:" + secret), the server learns only meeting points.
// Trust: an HMAC(secret) proof exchanged after connect, so the server cannot
// impersonate a known device. Full PAKE remains roadmap (ledger C15).

/// Should THIS acceptor session take the rung-1 direct-QUIC path (answer the
/// initiator's transport-offer instead of building a colliding WebRTC peer)?
///
/// True when the env gate is set (`direct_enabled`), OR this is the L2/ssh
/// acceptor (`l2_enabled`), OR this is the long-lived `up` daemon (`daemon`).
///
/// The daemon case is the anti-glare fix for a PLAIN `filament up` (no `--shell`,
/// no `FILAMENT_L2`): two such daemons that are known devices to each other each
/// fire a KnownPeer for the other and each tries to be the WebRTC initiator. The
/// two offers collide (GLARE); the polite side drops and rebuilds as a responder,
/// the supersede churn loops ("appeared, connecting" repeatedly, "reconnecting...")
/// and never settles to one stable link. Answering the direct-QUIC dial instead is
/// sequential (one `direct_pending` per peer, one race, one link) and authenticated
/// by the pair-secret MAC, so it neither glares nor depends on cross-NAT ICE.
///
/// One-shot `send`/`recv`/`pair` pass `daemon=false` and so keep their WebRTC
/// default (`direct_enabled()` only): they are deliberately left unchanged.
fn direct_ok_for(daemon: bool, l2_enabled: bool) -> bool {
    #[cfg(feature = "test-hooks")]
    if test_hooks::no_direct() {
        return false;
    }
    direct::direct_enabled() || l2_enabled || daemon
}


// `devices_name_taken` lived here: the case-insensitive collision check that was
// written, documented, and never called, while the live check compared exactly.
// The behaviour it wanted now lives at the call site (see the `taken` closure in
// the device-record writer), so this is a genuine duplicate and goes. Kept in
// history because an unwired STRICTER check is not dead code, it is a bug, and
// deleting it before wiring the behaviour would have erased the evidence.

















/// The binding to SIGN outgoing `l3-announce` / `fleet-hello` with.
///
/// A direct-QUIC link exports one (RFC 5705). A DataChannel does not, so we use
/// the nonce the PEER chose: they will verify against what they sent. `None`
/// means the challenge has not completed yet and the caller must simply wait,
/// which is why every send site is inside an `if let`.
fn out_binding(
    t: &Arc<dyn Transport>,
    pid: &str,
    theirs: &HashMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    t.channel_binding().or_else(|| theirs.get(pid).cloned())
}

/// The binding to VERIFY an incoming `l3-announce` / `fleet-hello` against: our
/// own exporter value, or the nonce WE chose and sent to that peer.
fn in_binding(
    t: &Arc<dyn Transport>,
    pid: &str,
    ours: &HashMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    t.channel_binding().or_else(|| ours.get(pid).cloned())
}












impl RevokeRecheck {
    pub(crate) fn new() -> Self {
        Self {
            last: std::time::Instant::now(),
            interval: revoke_recheck_interval(),
        }
    }

    /// The re-check interval. Timer-driven loops (pty, l2) build a ticker at this
    /// cadence and re-ask the verdict directly; the request-shaped mount uses
    /// [`Self::revoked`] instead.
    pub(crate) fn interval(&self) -> std::time::Duration {
        self.interval
    }

    /// True when the interval has elapsed AND the peer is now revoked. The
    /// caller re-checks at its natural cadence (per request for mount); the
    /// interval bound inside keeps that cadence cheap.
    pub(crate) fn revoked(&mut self, idev: Option<&[u8; 32]>) -> bool {
        if self.last.elapsed() < self.interval {
            return false;
        }
        self.last = std::time::Instant::now();
        cert_revoked_for(idev)
    }
}





/// The enrollment refusal for a prior record of the same device_pub, if any.
/// REVOKED is a decision and is not revivable by any fresh invitation; LAPSED
/// (an accident) revives. None means the enrollment may proceed.
fn enrollment_refusal(prior: &Value) -> Option<String> {
    let revoked = prior["certRevoked"].as_bool() == Some(true)
        || prior["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED);
    if revoked {
        Some("this device was revoked; the owner must run 'filament devices restore <name>' to allow it back".to_string())
    } else {
        None
    }
}




fn load_owner_key() -> Option<crate::identity::UserKey> {
    crate::identity::UserKey::load(&crate::platform::PlatformKeyStore).ok().flatten()
}

fn local_device_cert_path() -> PathBuf {
    crate::platform::Paths::config_path("identity/device-cert.json")
}



fn certified_device_names(user_pub: &[u8; 32]) -> Vec<(String, identity::DeviceCert)> {
    let mut result = Vec::new();
    if let Ok(raw) = std::fs::read_to_string(local_device_cert_path()) {
        if let Ok(record) = serde_json::from_str::<Value>(&raw) {
            if let (Some(name), Some(cert)) = (
                record["name"].as_str(),
                identity::DeviceCert::from_json(&record["cert"]),
            ) {
                if cert.user_pub == *user_pub {
                    result.push((name.to_string(), cert));
                }
            }
        }
    }
    let Ok(raw) = std::fs::read_to_string(devices_path()) else { return result };
    let Ok(records) = serde_json::from_str::<Vec<Value>>(&raw) else { return result };
    result.extend(records.into_iter().filter_map(|record| {
            let name = record["name"].as_str()?.to_string();
            let cert = identity::DeviceCert::from_json(&record["deviceCert"])?;
            (cert.user_pub == *user_pub).then_some((name, cert))
        }));
    result
}


/// Pure in-memory merge with takeover guard, scope-aware anchor, single source of truth.
fn apply_peer_identity(arr: &mut Vec<Value>, name: &str, peer_cert: &identity::DeviceCert, scope: u8) -> Result<()> {
    identity::apply_peer_identity(arr, name, peer_cert, scope).map_err(|e| anyhow::anyhow!("{}", e))
}

















pub(crate) fn channel_of(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"filament-pair:");
    h.update(secret.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}


/// C20: the proof binds the pair secret to the DTLS session. uids are
/// order-normalized (direction-tagged by the prover's uid prefix) and BOTH
/// certificate fingerprints are mixed in sorted order, a channel MITM'd by
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


// ------------------------------------------------------------- daemon (C19) --

fn drop_dir(flag: Option<PathBuf>) -> PathBuf {
    flag.or_else(|| config_get("dir").map(PathBuf::from)).unwrap_or_else(default_drop_dir)
}

/// The built-in drop directory when nothing is configured (~/Filament). Shared
/// with the settings readout so it shows the true default.
pub(crate) fn default_drop_dir() -> PathBuf {
    platform::Paths::home_dir().join("Filament")
}


/// Lexically normalize a path (resolve `.`/`..` without touching the FS) so a
/// scope check can't be defeated by `share/../../etc`. Returns the normalized
/// component vector.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        use std::path::Component::*;
        match comp {
            ParentDir => {
                out.pop();
            }
            CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// True when `path`, lexically normalized, is within (or equal to) `root`. Used
/// to bound a fleet transfer landing path to the drop dir. A relative or
/// non-normalizable request fails closed (not within), so it falls through to
/// explicit-grant. LEXICAL is correct here because the landing path may not
/// exist yet (file about to be received); the actual symlink protection lives
/// in safe_create_part/safe_resume_part (O_NOFOLLOW|O_EXCL) at the write site.
fn path_within(root: &Path, path: &Path) -> bool {
    let root_n = lexical_normalize(root);
    let path_n = lexical_normalize(path);
    !root_n.as_os_str().is_empty() && path_n.starts_with(&root_n)
}

/// True when `path`, canonicalized (symlinks resolved), is within `root`.
/// Used to bound a fleet mount REQUEST to the share root. Both paths must
/// exist on disk (canonicalize fails on non-existent paths). A symlink at
/// the mount root or requested path escaping the share root is refused.
fn path_within_canonical(root: &Path, path: &Path) -> bool {
    let Ok(root_c) = root.canonicalize() else {
        return false;
    };
    let Ok(path_c) = path.canonicalize() else {
        return false;
    };
    !root_c.as_os_str().is_empty() && path_c.starts_with(&root_c)
}



fn up_log() -> PathBuf {
    devices_path().with_file_name("up.log")
}



/// Compare two executable paths the way daemon identity needs: symlinks
/// resolved, and the " (deleted)" suffix Linux appends to `/proc/<pid>/exe`
/// after an in-place binary upgrade ignored. Without the latter, upgrading the
/// binary under a running daemon reads as "not running" and starts a second
/// daemon, the very bug this check exists to prevent.
fn same_executable(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        let s = p.to_string_lossy();
        match s.strip_suffix(" (deleted)") {
            Some(t) => PathBuf::from(t),
            None => p.to_path_buf(),
        }
    };
    let (a, b) = (norm(a), norm(b));
    a.canonicalize().unwrap_or(a) == b.canonicalize().unwrap_or(b)
}


/// Dev-debug logging: dlog! expands to eprintln! only under debug-logs feature.
macro_rules! dlog {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-logs")]
        eprintln!($($arg)*);
    };
}
/// Re-exported so modules lifted out of this file can keep using `dlog!`.
pub(crate) use dlog;



impl ShellPolicy {
    pub(crate) fn auto_allows(&self, name: &str) -> bool {
        match self {
            ShellPolicy::Granted => false,
            ShellPolicy::All => true,
            ShellPolicy::Only(set) => set.contains(name),
        }
    }
    /// #244: the posture this daemon is actually serving, for `cap-status`.
    ///
    /// Reported by the RUNNING daemon rather than derived from settings by the
    /// asking process. `up --shell` sets the policy from a launch flag that
    /// never touches the settings file, so a settings-derived answer would be
    /// true about the config and wrong about the daemon, which is precisely the
    /// gap that lets `revoke <device> shell` report success while the policy
    /// keeps handing out the shell.
    fn label(&self) -> &'static str {
        match self {
            ShellPolicy::Granted => "granted",
            ShellPolicy::All => "all",
            ShellPolicy::Only(_) => "only",
        }
    }
    /// The petnames this policy auto-shells regardless of any per-device grant.
    /// Empty for `Granted`; `Only`'s set; `All` answers for every peer, so the
    /// caller must read `label() == "all"` rather than look for a name here.
    fn auto_names(&self) -> Vec<String> {
        match self {
            ShellPolicy::Only(set) => {
                let mut v: Vec<String> = set.iter().cloned().collect();
                v.sort();
                v
            }
            _ => Vec::new(),
        }
    }
    /// Active policy implies the L2 tunnel acceptor is on (you can't ssh without it).
    fn enables_l2(&self) -> bool {
        !matches!(self, ShellPolicy::Granted)
    }
}












fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn command_arg(value: &str) -> String {
    if value.chars().all(|character| character.is_ascii_alphanumeric() || "-._/:".contains(character)) {
        return value.to_string();
    }
    #[cfg(windows)]
    {
        return format!("\"{}\"", value.replace('"', "\\\""));
    }
    #[cfg(not(windows))]
    {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}






// `cap_status_cmd` lived here: an 85-line reader for `ctl::try_cap_status`
// that no verb ever reached. NOT a disconnected feature: the ctl op it wraps
// is consumed live in the shell-capability path, so this was a second,
// unreached consumer. Deleted rather than wired.


// ----------------------------------------------------------- consent queue --
// Pending-request queue for live-approval consent (docs/design-identity-access-ux.md §2).
// Requests arrive via the daemon from peers requesting shell/mount/transfer.
// The daemon holds them until the owner explicitly approves or denies via CLI.
// Deny-by-default: a pending request carries NO access.




fn requests_path() -> PathBuf {
    crate::settings::config_dir().join("requests.json")
}

fn load_requests() -> Vec<PendingRequest> {
    std::fs::read_to_string(requests_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_requests(reqs: &[PendingRequest]) {
    if let Ok(json) = serde_json::to_string_pretty(reqs) {
        let _ = crate::platform::SecretFile::write_str(&requests_path(), &json);
    }
}


fn expire_requests(requests: &mut Vec<PendingRequest>) {
    let now = crate::capability::now_secs();
    let mut changed = false;
    for r in requests.iter_mut().filter(|r| r.status == "pending") {
        if now.saturating_sub(r.timestamp) > REQUEST_TTL_SECS {
            r.status = "expired".to_string();
            changed = true;
        }
    }
    if changed {
        save_requests(requests);
    }
}


/// Enqueue a consent request for a denied action from an identified peer.
/// No-op if the peer is unidentified, the cap is not requestable, or a
/// duplicate (same peer+cap) is already pending (dedup).
fn enqueue_if_requestable(dev_petname: &str, cap: &str) {
    let name = dev_petname.trim();
    if name.is_empty() || name == "<unverified>" {
        return;
    }
    match cap {
        "shell" | "mount" | "transfer" => {}
        _ => return,
    }
    let mut requests = load_requests();
    expire_requests(&mut requests);
    let dup = requests.iter().any(|r| r.peer == name && r.capability == cap && r.status == "pending");
    if !dup {
        add_pending_request(name, cap, &mut requests);
    }
}

fn request_ago(timestamp: u64) -> String {
    let ago = crate::capability::now_secs().saturating_sub(timestamp);
    if ago < 60 {
        format!("{ago}s ago")
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else {
        format!("{}h ago", ago / 3600)
    }
}

fn request_entry(value: &Value) -> Option<fleet_ui::requests::RequestEntry> {
    let capability = value["capability"].as_str()?;
    Some(fleet_ui::requests::RequestEntry {
        id: value["id"].as_u64()?,
        peer: value["peer"].as_str()?.to_string(),
        capability: capability.to_string(),
        ago: request_ago(value["timestamp"].as_u64().unwrap_or(0)),
        // The request protocol does not carry provenance or a fingerprint.
        via: None,
        fingerprint: None,
        is_deliberate: fleet_ui::is_deliberate_capability(capability),
    })
}

fn request_entries(value: &Value, all: bool) -> Vec<fleet_ui::requests::RequestEntry> {
    value
        .get("requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|request| all || request["status"].as_str() == Some("pending"))
        .filter_map(request_entry)
        .collect()
}

fn local_request(id: u64) -> Option<PendingRequest> {
    load_requests().into_iter().find(|request| request.id == id)
}

fn warm_device_names(value: Option<&Value>) -> HashSet<String> {
    value
        .and_then(|v| v.get("links"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|link| link["warm"].as_bool() == Some(true))
        .filter_map(|link| link["name"].as_str().map(str::to_string))
        .collect()
}

fn pending_request_count(value: Option<&Value>) -> usize {
    value
        .and_then(|v| v.get("requests"))
        .and_then(Value::as_array)
        .map(|requests| {
            requests
                .iter()
                .filter(|request| request["status"].as_str() == Some("pending"))
                .count()
        })
        .unwrap_or(0)
}


fn format_approval_expiry(expires: u64) -> String {
    chrono::DateTime::from_timestamp(expires as i64, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| expires.to_string())
}




/// Compact human duration ("30d", "8h", "15m", "90s") for copy that names a
/// signed budget. Never em-dashes.
fn fmt_short_duration(secs: u64) -> String {
    if secs >= 86400 && secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs >= 3600 && secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 && secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}






#[test]
fn every_canonical_capability_is_mintable_in_an_invitation() {
    // The ceiling vocabulary and the cap-store vocabulary are the same
    // vocabulary. If a capability can be granted but cannot be written into the
    // invitation that bounds it, no joined device can ever legitimately hold it.
    for cap in crate::capability::CANONICAL_CAPABILITIES {
        assert_eq!(
            mint_capability(cap).ok().as_deref(),
            Some(*cap),
            "`add --allow {cap}` is rejected, so no invitation can ever confer it"
        );
    }
}


// interactive_mint_options lived here. It drove the guided capability/lifetime
// picker for `ephemeral mint`, and went dead when that verb collapsed into
// `add --for runner`. Left behind by that change and found by the warning
// count, not by reading: rustc had been saying "never used" ever since.


/// Render a duration the way the pickers show it.
fn human_duration(secs: u64) -> String {
    match secs {
        s if s % 604_800 == 0 && s >= 604_800 => format!("{}d", s / 86_400),
        s if s % 86_400 == 0 && s >= 86_400 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 && s >= 3600 => format!("{}h", s / 3600),
        s if s % 60 == 0 && s >= 60 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}


async fn ephemeral_cmd(server: &str, action: EphemeralAction, relay: bool) -> Result<()> {
    match action {
        EphemeralAction::Enroll { auth_key_file, to } => {
            let auth_key = Zeroizing::new(read_owner_only_file(&auth_key_file)?);
            // #186: the claim token is now the compact v2 invitation.
            let inv = parse_invitation(auth_key.as_str())?;
            if inv.expires <= identity::now_secs() {
                bail!("this invitation has expired");
            }
            enroll_cmd(server, inv, to, relay, None, false).await
        }
    }
}



/// The joined device's owner record: the stored device whose cert chains to our
/// own joined cert's issuer but is not this machine. `depart` uses it to reach
/// the owner and ask it to free the slot now.
fn joined_owner_record() -> Option<(String, String)> {
    let mine = local_device_cert()?;
    devices_load().into_iter().find(|(name, _)| {
        device_cert_for(name)
            .map(|cert| cert.user_pub == mine.user_pub && cert.device_pub != mine.device_pub)
            .unwrap_or(false)
    })
}







/// Enroll as delegated + send files in one session.
/// Read a delegation credential from an owner-only file.
///
/// ONE LOADER. This was written twice, byte for byte, in enroll_and_send_cmd and
/// enroll_and_netcat_cmd (the second even said "same as enroll_and_send_cmd" and
/// then repeated it), and it read a bundle format that only `ephemeral mint`
/// produced. Both callers need exactly two things out of it: the capability list
/// to show, and the issuer fingerprint to derive the enrolment channel from.
///
/// Both are in the ordinary invitation, so there is no second format to keep.
/// `enroll_channel(full_key)` IS `enroll_channel_fp(fingerprint(full_key))`, so
/// the 8-byte fingerprint an invitation carries reaches the same rendezvous the
/// daemon derives from its full key.
fn load_delegation(path: &std::path::Path) -> Result<crate::ephemeral::Invitation> {
    let raw = Zeroizing::new(read_owner_only_file(path)?);
    let inv = parse_invitation(raw.as_str())?;
    if inv.expires <= identity::now_secs() {
        bail!("this key has expired");
    }
    Ok(inv)
}


// enroll_and_netcat_cmd lived here: 178 lines that enrolled with a delegated
// credential and then opened an l2 shell. It had NO caller, and the verb it
// served was removed earlier (see the note about the dead netcat verb and its
// ProxyCommand call sites). It shared 138 of 169 normalised lines with
// enroll_and_send_cmd and had already drifted from it.
//
// Deleted rather than deduplicated. The first move here was to lift the shared
// prologue and loop into one driver with a tail enum, which built and passed,
// and was the wrong answer: it was abstracting a branch nothing could reach.
// With one live caller there is nothing to share, and a plain function is
// simpler than an enum that exists to serve a dead arm.


/// Respond to an identity-auth-key-enroll-request with a nonce challenge.
/// Step 1: rate-limit BEFORE expensive ops (anti-flood).
/// Step 2: verify auth key against owner.
/// Step 3: generate CSPRNG nonce, store, send challenge.
/// The requesting device's standing, lifted from its stored record.
///
/// Keyed by DEVICE KEY, not by name: names are re-usable and renewal must
/// follow the identity, not the label.



fn down_cmd() -> Result<()> {
    match daemon_alive() {
        Some(pid) => {
            // #191: a managed service restarts a killed process. systemd's
            // Restart=always reacts to an UNEXPECTED exit; a manual
            // `systemctl stop` is authoritative and is not restarted. So stop
            // through the manager first, and only fall back to a bare kill
            // when no manager owns the daemon (a foreground `up`, or a
            // non-service-managed box).
            if !stop_managed_service(pid) {
                std::process::Command::new("kill").arg(pid.to_string()).status()?;
            }
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







// ---------------------------------------------------------------- reset -----
// `filament reset`: a conservative clean-slate for the LOCAL machine. It removes
// only filament's OWN state under the config dir (identity/overlay keys, the
// paired-device store, the capability store, pending consent requests, the
// managed ssh material) and strips the delimited `# BEGIN/END filament-managed
// <device>` blocks it installed in ~/.ssh/authorized_keys. It NEVER touches the
// user's real ssh keys or any authorized_keys lines outside those blocks.

/// Remove `path` if present, pushing a human line into `wiped`. Files and
/// directories both handled; a missing path is silently skipped (idempotent).
fn reset_remove(path: &std::path::Path, label: &str, wiped: &mut Vec<String>) {
    let removed = if path.is_dir() {
        std::fs::remove_dir_all(path).is_ok()
    } else if path.exists() {
        std::fs::remove_file(path).is_ok()
    } else {
        false
    };
    if removed {
        wiped.push(format!("{label}  ({})", path.display()));
    }
}


// ------------------------------------------------------------ introduce ----
// Vouched pairing: the hub (which already trusts A and B) mints a fresh
// secret and delivers it to both over channels it has PROVEN itself on
// (fingerprint-bound, C20). Receivers only honor pair-intro from a verified
// link, so a stranger, or the server, can't inject trust.


// ----------------------------------------------------------------- pair ----
// L1-a (PAKE v2): remembering a device is a first-class ceremony, no file
// transfer to pretend through. The first-pairing now runs a real SPAKE2 PAKE
// over the SPOKEN code so a malicious signaling server cannot MITM enrollment.
//
// The load-bearing change vs v1:
//   - The CLIENT mints the words locally (server sees only the numeric
//     nameplate); the password (words) NEVER reaches the server.
//   - SPAKE2 runs over the opaque `signal` relay BEFORE any secret exists.
//   - A key-confirmation MAC folds in the SORTED DTLS fingerprints + caps, so a
//     server that substitutes a DTLS cert OR rewrites caps is DETECTED → abort.
//   - The 32-byte pinned secret is HKDF(K), AGREED, never transmitted. The old
//     `pair-keep` secret-over-DataChannel step is GONE from the v2 path.
//   - Downgrade is structurally impossible: a v2 client NEVER sends pair-keep
//     and NEVER stores a secret from a received pair-keep. A received pair-keep
//     means the peer is v1 → abort with "update to pair securely". A server
//     stripping `v:2` therefore cannot force the readable-secret path.
//
// The opaque PAKE payloads carried on `signal` (the 33-byte SPAKE2 element and
// the 32-byte confirmation MAC) are encoded/decoded by the shared
// `pake_ceremony` module, which also owns the ceremony state machine that BOTH
// `pair` and the transfer path (`send --code` / `recv`) now run.
use pake_ceremony::{pair_v2_caps, Ceremony, Inbound as PakeInbound};


/// Map a codeentry Outcome::Cancelled into a clean error (used by the wired
/// commands so a cancel exits non-zero without a stack-y message).
/// Where a written credential lands when the operator did not name a file.
///
/// Named after the invitee when we know it so two of them in one directory do
/// not collide. Both callers use this, because "the default path" is exactly
/// the sort of thing that gets spelled twice and then differs.
fn invite_path_for(named: Option<&str>, kind: &str) -> std::path::PathBuf {
    let stem = named.unwrap_or(kind);
    let safe: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect();
    std::path::PathBuf::from(format!("filament-invite-{safe}.txt"))
}



impl PeerAuthz {
    /// The gate's arguments in the order every call site uses them.
    ///
    /// Returned as one tuple because the alternative was five identical lines of
    /// destructuring at five call sites, which is the duplication this struct
    /// was extracted to remove, reintroduced one layer up.
    fn parts(
        &self,
    ) -> (
        Option<&[u8; 32]>,
        Option<&[u8; 32]>,
        crate::capability::BindingStrength,
        Option<u64>,
        bool,
        Option<&[String]>,
    ) {
        (
            self.idev.as_ref(),
            self.iusr.as_ref(),
            self.binding,
            self.expires,
            self.cert_revoked,
            self.ak_caps.as_deref(),
        )
    }
}

fn peer_authz(conn: &mut Conn, pid: &str) -> PeerAuthz {
    if let Some(l) = conn.link_mut(pid) {
        resolve_peer_identity(l);
    }
    let link = conn.link(pid);
    let idev = link.and_then(|l| l.identity_device_pub);
    let iusr = link.and_then(|l| l.identity_user_pub);
    PeerAuthz {
        binding: link
            .map(|l| l.identity_binding)
            .unwrap_or(crate::capability::BindingStrength::None),
        expires: link.and_then(|l| l.identity_cert_expires),
        cert_revoked: cert_revoked_for(idev.as_ref()),
        ak_caps: link
            .and_then(|l| l.principal_kind.auth_key_caps())
            .map(|c| c.to_vec()),
        idev,
        iusr,
    }
}

/// Does this positional look like a pairing code rather than a device name?
///
/// `add <name>` and the removed `add <code>` spelling occupy the same argv slot,
/// so this decides which the operator meant. A code is WORD-WORD-NNNN or
/// WORD-WORD-WORD-NNNN: at least two dashes and a last segment of exactly four
/// digits, the machine-assigned connect number.
///
/// The old rule was "contains a dash and any digit", which was fine while the
/// name only arrived through --for and became wrong the moment it went
/// positional: `add my-laptop-2` was answered with "run filament join
/// my-laptop-2".
fn token_is_pairing_code(token: &str) -> bool {
    let segs: Vec<&str> = token.split('-').collect();
    !token.starts_with('-')
        && segs.len() >= 3
        && segs
            .last()
            .map(|t| t.len() == 4 && t.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
        && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}





// ---------------------------------------------------------- link machinery --
// One peer at a time, but with the browser's survival rules: establishment
// watchdog (C3), disconnected-grace + ICE restart + reconnect attempts (C4),
// fresh ICE config per attempt (C5), uid supersede on rejoin (C6), and a
// rejoin window when the peer's socket dies entirely.




/// Per-peer-link map keyed by warm-pty `session` -> (pid, sid), so a later
/// `pty-resize` op can relay to the right stream. Shared between the event loop
/// (lookup) and the spawned bridge tasks (insert/remove). Inert on non-unix.

/// Classification result for the bare-argument comfort router. Pure data, no side
/// effects: the caller owns the argv rewrite and the user-visible error.
#[derive(Debug, PartialEq, Eq)]
enum BareTarget {
    /// `help` is not a real subcommand on the un-built clap command, so rewrite
    /// to `--help`.
    Help,
    /// An existing local path: `send <path> --code`.
    Send,
    /// A 4-digit nameplate looks like a pairing code (preserved muscle memory).
    Add,
    /// A 2-3 digit nameplate looks like a legacy transfer code.
    Receive,
    /// `device:port` -> forward local-port device remote-port.
    Forward { lport: String, peer: String, rport: String },
    /// `device.mesh` or `device.mesh:port` -> reach.
    Reach(String),
    /// A bare known device name -> shell.
    Shell,
    /// The token is both a file and a device name; refuse to pick a side.
    AmbiguousFileDevice,
    /// Nothing recognized; the caller should print the did-you-mean path.
    Unknown,
}


/// Install the CLI's answers to the transport's host questions. One place, so
/// there is no doubt about what the transport can and cannot see.
fn install_transport_hooks() {
    use filament_transport::hooks;
    hooks::set_trace(|m| ui::trace(m));
    hooks::set_debug(|m| ui::debug(m));
    hooks::set_say(|m| ui::say(m));
    hooks::set_ip_class(|ip| doctor::ip_class(ip));
    hooks::set_iface_for_ip(|ip| doctor::iface_for_ip(ip));
    hooks::set_settings_get_str(|k, p| settings::get_str(k, p));
    hooks::set_raw_membership(|p| settings::raw_membership(p));
    hooks::set_config_path(|n| platform::Paths::config_path(n));
    hooks::set_resolve_iface_name(|addr| {
        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
            for iface in interact::enumerate_interfaces() {
                if iface.ips.iter().any(|i| *i == ip) {
                    return iface.name;
                }
            }
        }
        "?".to_string()
    });
}


fn main() -> Result<()> {
    // Build the runtime AFTER deciding how much of one is needed. This is the
    // only reason `main` is not `#[tokio::main]`: that macro picks the runtime
    // before anything can look at the command.
    let first = std::env::args().nth(1);
    let rt = if is_light_command(first.as_deref()) {
        tokio::runtime::Builder::new_current_thread().enable_all().build()?
    } else {
        tokio::runtime::Builder::new_multi_thread().enable_all().build()?
    };
    rt.block_on(async_main())
}



fn default_mount_point(peer: &str, remote: &str) -> String {
    let leaf = Path::new(remote)
        .file_name()
        .filter(|name| !name.is_empty())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "files".to_string());
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join("Filament Mounts").join(peer).join(leaf).display().to_string()
}


// ------------------------------------------------------------------ mount --
// Mount a peer directory locally over the mesh-native mount protocol, presented
// through FUSE. Linux only for now (macOS/Windows adapters are a later round).




// ----------------------------------------------------------------- update --
// Self-update against GitHub releases (tags cli-vX.Y.Z). Downloads the
// archive for this platform, verifies it against SHA256SUMS, and atomically
// replaces the current executable.


fn release_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}


// ------------------------------------------------------------------- send --




fn send_outcome(completed: usize, declined: usize) -> SendOutcome {
    if declined == 0 {
        SendOutcome::Complete { completed }
    } else {
        SendOutcome::Declined { completed, declined }
    }
}


// ------------------------------------------------------------------- recv —

/// Reduce a remote-supplied file name to a safe single path component: basename
/// only (no path separators or `..`), with control characters (including NUL)
/// stripped. A NUL in particular would fail the CString conversion in
/// safe_open_beneath and abort the whole receive loop, so a peer must not be able
/// to embed one. Empties / `.` / `..` fall back to a fixed name.






/// Record a received byte interval [pos, pos+len) in the disjoint sorted range
/// list, merging overlapping/adjacent intervals. Returns (delta_new_bytes, total_unique).
/// Delta is the number of previously-unseen bytes added by this chunk.
/// Total is the authoritative received count for multi-stream OOO reassembly.
/// Optimized: binary search + incremental total via removed_total tracking.
/// Build the live shell policy from the persistent settings (global `shell` +
/// per-peer `shell on` overrides). Mirrors `up_cmd`'s startup construction so a
/// `set shell ...` reconfigure lands the daemon in the same state a restart would.
fn shell_policy_from_settings() -> ShellPolicy {
    if settings::get_bool("shell", None) {
        return ShellPolicy::All;
    }
    let peers = settings::peers_with("shell", "on");
    if peers.is_empty() {
        ShellPolicy::Granted
    } else {
        ShellPolicy::Only(peers.into_iter().collect())
    }
}








/// Park in-flight receives: sync so the .part files are complete up
/// to the last byte received, then drop the per-link routing. Resume picks
/// them up from disk.
async fn flush_inflight(by_sid: &mut HashMap<(String, u32), IncomingFile>) {
    for (_sid, inc) in by_sid.drain() {
        let f = inc.file.clone();
        let _ = tokio::task::spawn_blocking(move || { let _ = f.sync_all(); }).await;
        ui::debug(&format!("{}: parked at {} for resume", inc.name, human(inc.received.load(Ordering::Relaxed))));
    }
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

/// C26: one-line colored peer status, static scrollback lines, the CLI's
/// equivalent of the web UI's amber 'away' tile.
///   ✓ deft-gibbon                    (connected)
///   ● deft-gibbon  away, choosing a file
///   ◌ deft-gibbon  reconnecting...
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
        "  {}{} offers {} ({}), accept? [y/N] ",
        ui::paint(ui::Tone::Bold, sender),
        hint,
        name,
        human(size)
    )
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests;
