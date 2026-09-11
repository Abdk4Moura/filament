//! Session, daemon and mount runtime helpers.
//!
//! The shared machinery behind the long-running paths: the receive loop's event
//! ticker (next_ev), session pump setup (spawn_session_pumps), the pending-request
//! queue, identity recovery from a phrase, the owner-only file reader, the bare-token
//! resolver (resolve_for_kind), the managed-service stop, the light-command check
//! that decides whether a command needs the daemon, and the mount teardown.
//!
//! CFG: unmount_fuse is DEFINITION-GATED on the mount condition -- linux, or macos
//! with mount-macos, with NO windows arm -- so its crate-root re-export carries that
//! exact condition. read_owner_only_file's attributes are statements inside it and
//! travel with the body, and its dependency read_owner_only_fd is a cfg PAIR, so no
//! import here needs a gate. Two spawns travel inside spawn_session_pumps.
use crate::conn::Conn;
use crate::fleet_support::ensure_self_genesis_header;
use crate::identity_state::certify_local_device;
use crate::net::Ev;
use crate::{
    MAX_PENDING, PendingRequest, ServiceManager, UiCapability, cancelled, codeentry, display_name,
    identity, l2, prompt_line, read_owner_only_fd, save_requests, service_manager_for_pid, ui,
};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// #4: bridge ONE link's PTY stream to a persistent session. Inbound data frames
/// (`rx`, the mux's per-sid pipe) become keystrokes; resize events (`rrx`, the
/// mux resizer) become window-size changes. When the channel drops, `rx` closes
/// and this pump exits, but it does NOT end the session: a drop is a DETACH (the
/// PcState handler does that), so the shell keeps running for a reattach. Spawned
/// fresh on every open/reattach against that open's sid.
pub(crate) fn spawn_session_pumps(
    sess: l2::PtySessionHandle,
    mut rx: tokio::sync::mpsc::Receiver<Option<bytes::Bytes>>,
    mut rrx: tokio::sync::mpsc::UnboundedReceiver<(u16, u16)>,
) {
    // input pump: PTY keystrokes for THIS attachment
    let s_in = sess.clone();
    tokio::spawn(async move {
        while let Some(item) = rx.recv().await {
            match item {
                Some(bytes) => s_in.feed_input(bytes.to_vec()),
                None => break, // clean FIN for this stream; channel-drop also lands here
            }
        }
    });
    // resize pump: SIGWINCH for THIS attachment
    tokio::spawn(async move {
        while let Some((c, r)) = rrx.recv().await {
            sess.resize(c, r);
        }
    });
}

pub(crate) fn read_owner_only_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "open owner-only file {} without following links",
            path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect owner-only file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("secret input must be a regular file, not a symlink");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            bail!(
                "secret file must be owner-only (chmod 600 {})",
                path.display()
            );
        }
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("read owner-only file {}", path.display()))?;
    Ok(contents)
}

pub(crate) fn recover_identity(
    caps: &UiCapability,
    words_file: Option<PathBuf>,
    words_fd: Option<i32>,
) -> Result<()> {
    if identity::UserKey::load(&crate::platform::PlatformKeyStore)?.is_some() {
        bail!("an identity already exists; recovery will not overwrite it");
    }
    let phrase = Zeroizing::new(if let Some(path) = words_file.as_deref() {
        read_owner_only_file(path)?
    } else if let Some(fd) = words_fd {
        read_owner_only_fd(fd)?
    } else if caps.interactive {
        use crossterm::{execute, terminal};
        let mut err = std::io::stderr();
        execute!(
            err,
            terminal::EnterAlternateScreen,
            terminal::Clear(terminal::ClearType::All)
        )?;
        eprintln!("  Enter your 12 recovery words.");
        eprintln!(
            "  They remain visible while you correct them; this screen is cleared afterward."
        );
        let result = prompt_line("\n  words: ");
        let _ = execute!(err, terminal::LeaveAlternateScreen);
        result?
    } else {
        bail!("non-interactive recovery requires --words-file <path> or --words-fd <fd>");
    });
    let user_key =
        identity::UserKey::restore(&crate::platform::PlatformKeyStore, phrase.as_str().trim())?;
    certify_local_device(&user_key, &display_name())?;
    ensure_self_genesis_header(&crate::settings::config_dir(), &user_key);
    if caps.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "identity": user_key.fingerprint(),
                "restored": true,
                "revokedStolenDevices": false,
            }))?
        );
    } else {
        ui::say(&format!(
            "  {} identity restored: {}",
            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
            user_key.fingerprint()
        ));
        ui::say(&ui::paint(
            ui::Tone::Warn,
            "  Recovery does not revoke a stolen device or a key it already holds.",
        ));
    }
    Ok(())
}

pub(crate) fn add_pending_request(
    peer: &str,
    capability: &str,
    requests: &mut Vec<PendingRequest>,
) {
    let now = crate::capability::now_secs();
    let next_id = requests.iter().map(|r| r.id).max().unwrap_or(0) + 1;
    // Evict oldest pending if at capacity
    while requests.iter().filter(|r| r.status == "pending").count() >= MAX_PENDING {
        if let Some(pos) = requests.iter().position(|r| r.status == "pending") {
            let evicted = &requests[pos];
            ui::say(&format!(
                "consent queue full ({}), evicting oldest pending: id={} peer={} cap={}",
                MAX_PENDING, evicted.id, evicted.peer, evicted.capability
            ));
            requests.remove(pos);
        } else {
            break;
        }
    }
    requests.push(PendingRequest {
        id: next_id,
        peer: peer.to_string(),
        capability: capability.to_string(),
        timestamp: now,
        status: "pending".to_string(),
        granted_at: None,
    });
    // Fire notify hook if configured
    if let Ok(hook) = std::env::var("FILAMENT_NOTIFY_HOOK") {
        if !hook.is_empty() {
            // ARGV exec, never shell — petname is attacker-influenced
            let _ = std::process::Command::new(&hook)
                .arg(peer)
                .arg(capability)
                .spawn();
        }
    }
    save_requests(requests);
}

/// Resolve `--for` into "device" or "person", and an optional pre-filled name.
///
/// ONE spelling of the who-question, shared by both transports. It used to live
/// inside the invitation path only, so the pairing-code path grew its own flag
/// (`--internal`) meaning the same thing. Two spellings of one question is what
/// made this surface confusing; the fix is one resolver, not another flag.
///
/// Fails closed without a TTY: a script that does not say must never be assumed
/// to mean "this machine is mine", because that is the answer that hands out an
/// owner-signed certificate.
pub(crate) fn resolve_for_kind(
    caps: &UiCapability,
    for_: Option<String>,
) -> Result<(String, Option<String>)> {
    // `--for` with no value arrives as Some("") (clap's default_missing_value),
    // and it MEANS "ask me". Normalised here rather than in the callers because
    // it was normalised in exactly one of them: add_for_cmd filtered the empty
    // string, the spoken-code path did not, so `filament add --for` fell through
    // to the device-NAME arm below, silently resolved to kind=device with an
    // empty invitee name, and never asked the question. The menu entry "Invite a
    // device or person" is that argv, which is why it looked identical to
    // "Connect a device with me now".
    //
    // One question, one place that knows every way it can be spelled.
    let for_ = for_.filter(|v| !v.trim().is_empty());
    match for_.as_deref() {
        None => {
            if caps.interactive {
                // A cancelled picker (Ctrl-C / Esc) is a cancellation, not a
                // missing argument (#203): exit cleanly instead of reporting
                // the non-interactive requirement.
                // THE SAME THREE ANSWERS THE FLAG TAKES, in the same order, so
                // reading `--for runner` in a script and picking "An unattended
                // runner" here are visibly the same choice. The third answer is
                // what `ephemeral mint` used to be a separate verb for: an
                // unattended machine is not a member, it holds a temporary key.
                let choices = vec![
                    "A device I control          (joins my mesh)".to_string(),
                    "Another person              (paired, not a member)".to_string(),
                    "An unattended runner        (CI, borrowed box; temporary)".to_string(),
                ];
                match codeentry::pick("WHO IS JOINING", &choices)? {
                    Some(0) => Ok(("device".to_string(), None)),
                    Some(1) => Ok(("person".to_string(), None)),
                    Some(_) => Ok(("runner".to_string(), None)),
                    None => Err(cancelled()),
                }
            } else {
                // A NUDGE, not a restatement of the rule. The operator got this
                // far because they wanted to add something; tell them the next
                // command for each thing they might have meant, and name the
                // claim side too, because an invitation is useless if you do not
                // know the other end runs `join`.
                bail!(
                    "{}",
                    [
                        "--for needs to know who is joining:",
                        "",
                        "  a device you own   filament add laptop --out laptop.invite",
                        "  someone else       filament add --for person --out alice.invite",
                        "  a CI runner        filament add --for runner --out ci.key",
                        "",
                        "  A bare name means a device, so `add laptop` is `--for laptop`.",
                        "  They claim it with:  filament join <file>",
                    ]
                    .join("\n")
                )
            }
        }
        Some("device") | Some("person") | Some("runner") => Ok((for_.unwrap(), None)),
        Some(name) => Ok(("device".to_string(), Some(name.to_string()))),
    }
}

pub(crate) fn stop_managed_service(pid: u32) -> bool {
    // Only stop through the manager when THIS daemon is actually the managed
    // unit's process, AND the right manager. `systemctl stop filament` stops
    // the named unit even when down targets a DIFFERENT daemon (a detached
    // foreground `up` on another config), which killed another machine's
    // service during development. Two units share the name here, so the cgroup
    // scope decides which manager.
    match service_manager_for_pid(pid) {
        Some(ServiceManager::SystemdSystem) => std::process::Command::new("systemctl")
            .args(["stop", "filament"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        Some(ServiceManager::SystemdUser) => std::process::Command::new("systemctl")
            .args(["--user", "stop", "filament"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false),
        // Not a managed daemon (a detached foreground `up`, or no systemd):
        // the caller falls back to a plain kill.
        None => false,
    }
}

/// Receive the next event; while a rejoin window is open, tick every second
/// so the window can expire AND the countdown stays visible (C22, "45s"
/// frozen on screen reads as broken).
pub(crate) async fn next_ev(
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    conn: &Conn,
    suppress_countdown: bool,
) -> Result<Option<Ev>> {
    if let Some(since) = conn.rejoin.waiting_rejoin {
        if since.elapsed() > conn.rejoin.rejoin_window {
            ui::clear_sticky();
            bail!(
                "peer did not come back within {}s (partial state kept for resume)",
                conn.rejoin.rejoin_window.as_secs()
            );
        }
        if !suppress_countdown {
            let left = conn
                .rejoin
                .rejoin_window
                .saturating_sub(since.elapsed())
                .as_secs();
            ui::sticky(&ui::paint(
                ui::Tone::Dim,
                &format!(
                    "  {} holding the line, {left}s for them to come back (Ctrl-C to stop)",
                    ui::spinner_frame()
                ),
            ));
        }
        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    } else {
        // C30: never block indefinitely, a 2s tick lets the convergent
        // session repair lost emits even when no events arrive.
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    }
}

/// Commands that do no concurrent work and so need no worker threads.
///
/// OPT-IN, and the polarity is the point. `#[tokio::main]` builds a
/// multi-threaded runtime unconditionally, which spawns one worker per CPU
/// before `main` runs: `strace` shows four `clone3` calls on a 4-core box just
/// to print `--version`, and that cost scales with core count, so the bigger the
/// machine the slower the trivial commands feel. These verbs are pure local I/O
/// (read some files, print), so they get a current-thread runtime instead.
///
/// Anything NOT listed keeps the multi-threaded runtime, so an unrecognised or
/// future command behaves exactly as it does today. A wrong answer here is a
/// throughput question, never a correctness one: a current-thread runtime still
/// runs every future and still has a blocking pool for `spawn_blocking`. The one
/// API that would panic is `block_in_place`, and the tree contains none.
pub(crate) fn is_light_command(first_arg: Option<&str>) -> bool {
    match first_arg {
        // Bare `filament` is the tour: three file reads and a printout.
        None => true,
        Some(a) => matches!(
            a,
            "--version"
                | "-V"
                | "--help"
                | "-h"
                | "help"
                | "devices"
                | "id"
                | "status"
                | "addr"
                | "set"
                | "completions"
                | "man"
        ),
    }
}

/// Unmount a FUSE/macFUSE mountpoint. Tries fusermount3 then fusermount on Linux,
/// falling back to a lazy unmount so a busy mount still detaches. On macOS,
/// uses umount or diskutil unmount.
#[cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos")))]
pub(crate) fn unmount_fuse(local: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        for bin in ["fusermount3", "fusermount"] {
            if std::process::Command::new(bin)
                .args(["-u", local])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
        // Linux last resort: lazy unmount so a busy handle does not wedge teardown.
        let _ = std::process::Command::new("fusermount3")
            .args(["-uz", local])
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        // Try diskutil first (more reliable for macFUSE), fall back to umount.
        if std::process::Command::new("diskutil")
            .args(["unmount", "force", local])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Ok(());
        }
        let _ = std::process::Command::new("umount").args([local]).status();
    }
    Ok(())
}

/// Windows: WinFsp handles unmount through its own control path; this is a no-op
/// placeholder so the Linux/macOS cleanup flow compiles on Windows.
#[cfg(all(target_os = "windows", feature = "mount-windows"))]
pub(crate) fn unmount_fuse(_local: &str) -> std::io::Result<()> {
    Ok(())
}
