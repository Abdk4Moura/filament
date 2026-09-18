//! The inspect commands (`tour`, `status`, `requests`) and the state helpers they share.
//!
//! These are the read-mostly commands: what this daemon is doing (`status_cmd`), a
//! guided first look (`tour_cmd`), and approving or denying what others asked for
//! (`requests_cmd`). Alongside them sit the pieces of mesh state those views depend
//! on: `delegated_device_state`, `mesh_enrolment`, and `detach_up`.
//!
//! NO CFG ANYWHERE: no member carries a definition- or statement-level attribute,
//! and no dependency this group calls is gated (checked with cfg-pair awareness).
//! No spawns and no nested fns either. All six are called from non-test modules, so
//! the crate-root re-export is a single unconditional group.
use crate::DeadlineClock;
use crate::PRINCIPAL_STATE_LAPSED;
use crate::PRINCIPAL_STATE_REVOKED;
use crate::cli_def::RequestsAction;
use crate::daemon_alive;
use crate::devices_store::devices_load;
use crate::effective_principal_deadline;
use crate::expose;
use crate::fleet;
use crate::fleet_ui;
use crate::format_approval_expiry;
use crate::identity;
use crate::identity_flow::local_device_cert;
use crate::local_request;
use crate::owner_cap_header;
use crate::owner_signed_cap_ops;
use crate::parse_duration_secs;
use crate::pidfile;
use crate::request_entries;
use crate::ui;
use crate::up_log;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

/// Bare-command tour: what filament is, the current state, and the two or three
/// things you'd actually do next, adapted to whether you've paired anyone yet. No
/// flags to learn; `--help` still has the full surface. (CLI-UX work, point #2.)
pub(crate) fn tour_cmd() -> Result<()> {
    let color = ui::stdout_color();
    ui::say(&format!(
        "  {}  {}",
        ui::paint_when(color, ui::Tone::Brand, "filament"),
        ui::paint_when(color, ui::Tone::Dim, "/ one thread across every device"),
    ));
    ui::say("");
    match daemon_alive() {
        Some(pid) => ui::say(&format!(
            "  {} daemon up (pid {pid})",
            ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok())
        )),
        None => ui::say(&format!(
            "  {} daemon not running",
            ui::paint_when(color, ui::Tone::Dim, "·")
        )),
    }
    let n = devices_load().len();
    // U1: the first screen mints the identity instead of warning about it.
    let identity = crate::identity_flow::ensure_user_key(false)?;
    ui::say(&format!("  {n} device{}", if n == 1 { "" } else { "s" }));
    ui::say(&format!(
        "  identity {}",
        ui::paint_when(color, ui::Tone::Bold, &identity.fingerprint())
    ));
    ui::say("");
    ui::say(&ui::paint_when(color, ui::Tone::Dim, "  do this:"));
    let act = |cmd: &str, desc: &str| ui::say(&format!("    {:<24} {}", cmd, desc));
    act("filament send <file>", "send something");
    if n == 0 {
        act("filament add", "add a device or person");
    } else {
        act("filament mount", "open files from another device");
        act("filament shell <device>", "open an authorized terminal");
    }
    act("filament receive", "receive once");
    act("filament up", "serve: receive, mount (shell with --shell)");
    act("filament up --install", "the same, always-on");
    ui::say(&ui::paint_when(
        color,
        ui::Tone::Dim,
        "  more:  filament --help  /  filament devices  /  filament id",
    ));
    Ok(())
}

pub(crate) fn status_cmd(json: bool) -> Result<()> {
    if json {
        let pid = daemon_alive();
        let exposed: Vec<Value> = expose::load()
            .iter()
            .map(|b| json!({ "port": b.port, "target": b.target, "peers": b.peers.clone().unwrap_or_default() }))
            .collect();
        let mut recent: Vec<String> = std::fs::read_to_string(up_log())
            .map(|log| log.lines().rev().take(8).map(str::to_string).collect())
            .unwrap_or_default();
        recent.reverse();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "running": pid.is_some(),
                "pid": pid,
                "devices": devices_load().len(),
                "exposed": exposed,
                "recent": recent,
            }))?
        );
        return Ok(());
    }
    match daemon_alive() {
        Some(pid) => ui::say(&format!(
            "  {} up (pid {pid})",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        )),
        None => ui::say(&format!(
            "  {} not running, start with: filament up",
            ui::paint(ui::Tone::Dim, "·")
        )),
    }
    let n = devices_load().len();
    ui::say(&format!(
        "  {} known device{}",
        n,
        if n == 1 { "" } else { "s" }
    ));
    let exposed = expose::load();
    if !exposed.is_empty() {
        ui::say(&ui::paint(ui::Tone::Dim, "  exposed on .mesh:"));
        for b in exposed {
            let scope = match &b.peers {
                Some(p) if !p.is_empty() => p.join(","),
                _ => "any".into(),
            };
            ui::say(&format!(
                "    :{} {} {}  ({})",
                b.port,
                ui::glyph_arrow(),
                b.target,
                scope
            ));
        }
    }
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

/// Human state text for a DELEGATED device's row, quoting the binding clock
/// from effective_principal_deadline (never restating a bound we do not compute).
/// Returns None for owner devices (they keep the existing cert countdown).
pub(crate) fn delegated_device_state(
    name: &str,
    cert: Option<&identity::DeviceCert>,
    now: u64,
    records: &[Value],
) -> Option<(String, ui::Tone)> {
    let cert = cert?;
    let record = records.iter().find(|d| d["name"].as_str() == Some(name))?;
    // REVOCATION FIRST, before the principal-kind gate. Revoking is a decision
    // about a device, not about a principal kind, and it applies to any record we
    // hold. A fleet sibling is indexed WITHOUT a delegated principal, so gating
    // this behind "delegated" meant `devices revoke <sibling>` succeeded, wrote
    // certRevoked, correctly denied the device on reconnect, and then listed it
    // as perfectly healthy. A revocation you cannot see is one you cannot trust.
    if record["certRevoked"].as_bool() == Some(true)
        || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED)
    {
        return Some(("revoked".to_string(), ui::Tone::Err));
    }
    if record["principalKind"].as_str() != Some("delegated") {
        return None;
    }
    let not_after = record["principalExpires"].as_u64();
    let last_seen = record["lastSeen"].as_u64();
    let max_offline = record["principalMaxOffline"].as_u64();
    let (deadline, clock) =
        effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
    if record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED) || deadline <= now {
        return Some(("lapsed".to_string(), ui::Tone::Warn));
    }
    let secs = deadline - now;
    let (n, unit) = if secs < 3600 {
        (secs / 60, "m")
    } else if secs < 86400 {
        (secs / 3600, "h")
    } else {
        (secs / 86400, "d")
    };
    let clock_label = match clock {
        DeadlineClock::CertExpiry => "cert expires",
        DeadlineClock::AbsoluteStop => "stop time",
        DeadlineClock::LivenessBudget => "offline budget",
    };
    Some((format!("{n}{unit} left ({clock_label})"), ui::Tone::Dim))
}

/// CLI handler for `filament requests`
pub(crate) async fn requests_cmd(action: Option<RequestsAction>) -> Result<()> {
    match action {
        None | Some(RequestsAction::List { all: false }) => {
            let reply = crate::ctl::try_list_pending().await;
            match reply {
                Some(v) => ui::say(&fleet_ui::requests::render_requests(&request_entries(
                    &v, false,
                ))),
                None => ui::say("  daemon not running; no pending request state"),
            }
        }
        Some(RequestsAction::List { all: true }) => {
            let reply = crate::ctl::try_list_pending().await;
            match reply {
                Some(v) => ui::say(&fleet_ui::requests::render_requests(&request_entries(
                    &v, true,
                ))),
                None => ui::say("  daemon not running; no request state"),
            }
        }
        Some(RequestsAction::Approve {
            id,
            allow,
            duration,
        }) => {
            let expires =
                crate::capability::now_secs().saturating_add(parse_duration_secs(&duration)?);
            let reply = crate::ctl::try_approve_request(id, &allow, expires).await;
            match reply {
                Some(v) => {
                    if let Some(peer) = v.get("peer").and_then(|v| v.as_str()) {
                        if let Some(cap) = v.get("capability").and_then(|v| v.as_str()) {
                            if let Some(granted_expires) = v.get("expires").and_then(|v| v.as_u64())
                            {
                                let expiry = format_approval_expiry(granted_expires);
                                ui::say(&fleet_ui::requests::render_approve_success(
                                    peer, cap, &expiry,
                                ));
                            } else {
                                ui::say(&format!(
                                    "  {} approval succeeded but the grant expiry was missing",
                                    ui::paint(ui::Tone::Err, ui::glyph_err()),
                                ));
                            }
                        }
                    }
                }
                None => ui::say(&format!(
                    "  {} request {id} not found or daemon not running",
                    ui::paint(ui::Tone::Warn, "x")
                )),
            }
        }
        Some(RequestsAction::Deny { id }) => {
            let peer = local_request(id).map(|request| request.peer);
            let reply = crate::ctl::try_deny_request(id).await;
            match reply {
                Some(_) => {
                    if let Some(peer) = peer {
                        ui::say(&fleet_ui::requests::render_deny_success(&peer));
                    } else {
                        ui::say(&format!(
                            "  {} request {id} denied",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok())
                        ));
                    }
                }
                None => ui::say(&format!(
                    "  {} request {id} not found or daemon not running",
                    ui::paint(ui::Tone::Warn, "x")
                )),
            }
        }
    }
    Ok(())
}

/// The owner-signed artifact that makes a peer a member of this mesh.
///
/// A certificate for the peer's device key, our own certificate so it can verify
/// the chain, and (for a PERSISTENT member) the fleet meeting point plus the
/// capability header and signed policy.
///
/// This exists as ONE function because it is the only place a DeviceCert is
/// minted for somebody else. It was written inline in the enrol handler, and the
/// pairing ceremony could not produce one, which is why `filament add` left a
/// device paired but not on the mesh. Hand-writing it a second time is how the
/// fleet handshake ended up with four per-peer bugs in copies that had drifted.
///
/// `persistent` is the whole distinction between a member and a borrower: an
/// ephemeral peer holds a certificate for one session and never receives
/// `fleet_rv`, so it cannot take part in the fleet's standing presence.
pub(crate) fn mesh_enrolment(
    owner_key: &identity::UserKey,
    device_pub: [u8; 32],
    caps: &[String],
    expires: u64,
    persistent: bool,
) -> Result<(identity::DeviceCert, Value)> {
    let now = identity::now_secs();
    let cert =
        identity::DeviceCert::certify(owner_key, device_pub, now, expires.saturating_sub(now))
            .map_err(|e| anyhow!("could not certify the device: {e}"))?;
    let payload = json!({
        "device_cert": cert.to_json(),
        "owner_cert": local_device_cert().map(|c| c.to_json()),
        // Only a persistent member joins the fleet meeting point.
        "fleet_rv": persistent.then(|| fleet::rv_load_or_create().ok()).flatten(),
        // A joined device cannot make its own header: ensure_self_genesis_header
        // SIGNS it with the owner's UserKey, which the joiner does not hold. So
        // the owner hands it over. It carries no secret, being signed and
        // self-certifying, and naming owner_pub and a nonce.
        "cap_header": persistent.then(owner_cap_header).flatten(),
        // Owner-authored policy, relayed. The joiner verifies every op against
        // the owner key in the header above, so this is not a trust decision
        // handed to whoever transmits it.
        "cap_ops": persistent.then(|| json!(owner_signed_cap_ops())).unwrap_or(Value::Null),
        "ceiling": caps,
        "expires": expires,
        "persistent": persistent,
    });
    Ok((cert, payload))
}

/// this terminal. The detached child writes the pidfile and serves; its console
/// output goes to {config}/daemon.log so `filament logs` can follow it. The
/// detach itself is one portable operation in `platform::spawn_detached`, whose
/// two arms ship together (#215 was the half-written version: the Windows arm
/// computed the log path and threw it away).
pub(crate) async fn detach_up(server: &str, dir: Option<PathBuf>) -> Result<()> {
    let exe = std::env::current_exe()?;
    let log_path = crate::platform::Paths::config_path("daemon.log");
    let dir_arg: Option<String> = dir.as_deref().and_then(|d| d.to_str()).map(str::to_string);
    let mut args: Vec<&str> = vec!["up", "--server", server];
    if let Some(d) = dir_arg.as_deref() {
        args.push("--dir");
        args.push(d);
    }
    let child = crate::platform::spawn_detached(&exe, &args, &log_path)?;
    // Let the child write its pidfile before we return; poll briefly.
    let mut came_up = false;
    for _ in 0..50 {
        if daemon_alive().is_some() {
            came_up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child;
    if came_up {
        ui::say(&format!(
            "  {} daemon detached (pidfile at {}) - output: {}",
            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
            pidfile().display(),
            log_path.display()
        ));
    } else {
        ui::say(&format!(
            "  {} spawned the daemon but it did not come up within 5s - output: {}",
            ui::paint(ui::Tone::Warn, "!"),
            log_path.display()
        ));
    }
    Ok(())
}
