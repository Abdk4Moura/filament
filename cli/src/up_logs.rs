//! `filament up` / `filament logs`, lifted out of `main.rs`.
//!
//! `up_cmd` installs and starts the receiver (including the service-manager and
//! shell-policy paths, and the already-running case that follows the daemon's
//! log), and `logs_cmd` tails that log. Both spawn; `up_cmd` also carries one
//! in-body `#[cfg(target_os = "windows")]` and `logs_cmd` a function-local
//! `use tokio::io::{AsyncBufReadExt, AsyncSeekExt}` plus its own
//! `macro_rules! detached`, all of which travel with the bodies.
//!
//! Everything else here is imported from the crate root and stays where it was:
//! `daemon_alive` (fourteen call sites in thirteen functions), `recv_cmd`,
//! `detach_up`, the pidfile helpers and the shell-policy helpers. No item is
//! promoted for this move -- a private crate-root item is already visible to a
//! descendant module like this one.
use crate::{
    ServiceManager, ShellPolicy, daemon_alive, detach_up, direct, dlog, drop_dir,
    install_system_service, pidfile, platform, recv_cmd, require_shell_owner_ack,
    service_manager_for_pid, settings, shell_grant_names, shell_root_note, sshkeys, subnet_forward,
    ui, write_pidfile,
};
use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) async fn up_cmd(
    server: &str,
    install: bool,
    system: bool,
    detach: bool,
    dir: Option<PathBuf>,
    relay: bool,
    shell: bool,
    shell_only: Option<String>,
    shell_program: Option<String>,
    shell_user: Option<String>,
    i_know: bool,
    install_system_flag: bool,
    no_proxy_fallback: bool,
) -> Result<()> {
    let shell_enabled = shell || shell_only.is_some();
    let shell_config = settings::get_str("shell-program", None);
    let can_use_user =
        platform::Paths::shell_argv(None, shell_config.as_deref(), shell_user.as_deref()).1;
    require_shell_owner_ack(shell_enabled, shell_user.as_deref(), can_use_user, i_know)?;
    // Internal: re-invoked after elevation. Do the system-level install directly
    // and return. The privileged backend registers the service/daemon/task and exits.
    if install_system_flag {
        let host = platform::ServiceHost::detect();
        let exe = std::env::current_exe()?;
        // Build shell args from the current flag carried by the elevated process.
        let mut up_args = String::new();
        if let Some(csv) = &shell_only {
            up_args.push_str(&format!(" --shell-only {csv}"));
        } else if shell {
            up_args.push_str(" --shell");
        }
        if let Some(u) = &shell_user {
            up_args.push_str(&format!(" --shell-user {u}"));
        }
        if i_know {
            up_args.push_str(" --i-know");
        }
        host.install_system(&exe, &up_args)?;
        return Ok(());
    }
    // --shell-program -- persist it so the daemon picks it up (shell_argv reads
    // this from config). The env var FILAMENT_SHELL is also checked independently.
    if let Some(ref prog) = shell_program {
        settings::set("shell-program", prog, None).ok();
    }
    let shell_policy = match &shell_only {
        Some(csv) => ShellPolicy::Only(
            csv.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        ),
        None if shell => ShellPolicy::All,
        None => ShellPolicy::Granted,
    };
    // --shell-user is Unix-only (uses runuser). Warn early on Windows.
    if shell_user.is_some() && cfg!(windows) {
        ui::say(&format!(
            "  {} --shell-user is not supported on Windows.\n\
             \n\
             Windows requires CreateProcessAsUser or CreateProcessWithLogonW to run\n\
             a process as another user. CreateProcessAsUser needs SE_INCREASE_QUOTA_NAME\n\
             and SE_ASSIGNPRIMARYTOKEN_NAME privileges (typically requires admin).\n\
             CreateProcessWithLogonW needs the target user's credentials (username +\n\
             password), which is a security risk if stored or passed via CLI.\n\
             \n\
             The PTY will run as the current user. To run as a different user,\n\
             start filament from that user's session, or use 'runas /user:<name> filament'.",
            ui::paint(ui::Tone::Warn, "WARNING:")
        ));
    }
    if install && system {
        return install_system_service(shell, &shell_only, &shell_user, i_know);
    }
    if install {
        // Gate --install on a detected service manager.
        let host = platform::ServiceHost::detect();
        if !host.supports_install() {
            let hint = host.install_instructions();
            eprintln!("filament: --install is not supported on this platform. {hint}");
            return Ok(());
        }
        let exe = std::env::current_exe()?;
        let mut up_args = String::new();
        if let Some(csv) = &shell_only {
            up_args.push_str(&format!(" --shell-only {csv}"));
        } else if shell {
            up_args.push_str(" --shell");
        }
        if let Some(u) = &shell_user {
            up_args.push_str(&format!(" --shell-user {u}"));
        }
        if i_know {
            up_args.push_str(" --i-know");
        }
        // Try privileged system install (elevation popup). On decline, fall
        // back to user-level autostart. Never fail hard.
        // #173: on Windows the DEFAULT background receiver is per-user (HKCU
        // Run, no elevation), matching systemd --user and the LaunchAgent. A
        // machine-wide service is an explicit `--install-system` request; the
        // first-run wizard must not demand UAC.
        if cfg!(windows) {
            host.install_user(&exe, &up_args)?;
            // #182: HKCU Run only fires at logon. The user asked for the
            // inbox NOW (the other platforms' service managers do `enable
            // --now` / bootstrap). Start the receiver now, detached, and
            // confirm it is live before printing. The detach is the SAME
            // portable operation as `up --detach` (platform::spawn_detached),
            // so the receiver's console lands in daemon.log.
            let log_path = crate::platform::Paths::config_path("daemon.log");
            let started = match crate::platform::spawn_detached(&exe, &["up"], &log_path) {
                Ok(_) => {
                    // Give the receiver a moment to write its pidfile.
                    let mut live = false;
                    for _ in 0..40 {
                        if daemon_alive().is_some() {
                            live = true;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                    live
                }
                Err(_) => false,
            };
            if started {
                ui::say(&format!(
                    "  {} receiving now, and at every logon",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok())
                ));
            } else {
                ui::say(&format!(
                    "  {} autostart installed; starting the receiver now failed, run `filament up`",
                    ui::paint(ui::Tone::Warn, "!")
                ));
            }
        } else {
            match host.install_system(&exe, &up_args) {
                Ok(platform::InstallResult::System) => {
                    ui::say(&format!(
                        "  {} installed as a system service (autostart at boot)",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok())
                    ));
                }
                Ok(platform::InstallResult::User) | Err(_) => {
                    // Elevation declined: user-level autostart
                    host.install_user(&exe, &up_args)?;
                    ui::say(&format!(
                        "  {} installed as a user-level autostart",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok())
                    ));
                    ui::say(&format!(
                        "  {} run `filament up --install` again to grant admin for kernel overlay",
                        ui::paint(ui::Tone::Dim, "note:")
                    ));
                }
            }
        }
        #[cfg(target_os = "windows")]
        platform::add_firewall_rule(&exe);
        return Ok(());
    }
    if let Some(pid) = daemon_alive() {
        dlog!(
            "[up] already-up: pidfile={:?} pid={pid} cmdline={:?}",
            pidfile(),
            std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default()
        );
        // #192: `up` twice should not dead-end. The daemon is already serving;
        // follow its log. Ctrl-c detaches and leaves it running.
        ui::say(&format!(
            "  daemon already running (pid {pid}); following its log (ctrl-c to detach)"
        ));
        return logs_cmd(true, 20).await;
    }
    if detach {
        // --detach: spawn the daemon in the background, redirect its console to
        // {config}/daemon.log, return to the shell. The child writes the pidfile
        // and serves detached (survives closing this terminal).
        return detach_up(server, dir).await;
    }
    let dir = drop_dir(dir);
    std::fs::create_dir_all(&dir)?;
    write_pidfile()?;
    let granted_names = shell_grant_names();
    match &shell_policy {
        // M-2: --shell intentionally grants ALL proof-verified paired devices
        // (current AND any introduced later via pair-intro). This is a broad,
        // deliberate over-grant; --shell-only is the scoped, safer alternative.
        ShellPolicy::All => ui::say(&format!(
            "  {} seamless shell ON, ANY paired device (now or paired later) can `filament shell --ssh` into this machine",
            ui::paint(ui::Tone::Warn, "!"),
        )),
        ShellPolicy::Only(set) => {
            let mut names: Vec<&String> = set.iter().collect();
            names.sort();
            let list = names
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            ui::say(&format!(
                "  {} seamless shell ON for: {list}, they can `filament shell --ssh` into this machine",
                ui::paint(ui::Tone::Warn, "!"),
            ));
        }
        ShellPolicy::Granted if !granted_names.is_empty() => ui::say(&format!(
            "  {} seamless shell ON for: {}, they can `filament shell --ssh` into this machine",
            ui::paint(ui::Tone::Warn, "!"),
            granted_names.join(", "),
        )),
        ShellPolicy::Granted => {}
    }
    // Shell without a dropped account is owner-equivalent at any uid. A dropped
    // account is only safer if it cannot read FILAMENT_CONFIG_DIR.
    if shell_policy.enables_l2() {
        let warning = match shell_user.as_deref() {
            Some(user) if can_use_user => {
                format!(
                    "  note: shell PTYs run as {user}; verify this account cannot read FILAMENT_CONFIG_DIR or the drop is cosmetic"
                )
            }
            Some(user) => {
                format!(
                    "  {} --shell-user {user} is unsupported on this platform; the PTY runs as this process's user and has the owner's authority.",
                    ui::paint(ui::Tone::Warn, "!")
                )
            }
            None => {
                format!(
                    "  {} serving shell without --shell-user grants the peer the owner's authority because the PTY runs as this process's user and can read the config directory.{}",
                    ui::paint(ui::Tone::Warn, "!"),
                    shell_root_note()
                )
            }
        };
        ui::say(&warning);
    }
    // Pre-resolve our public IP off the critical path so the FIRST incoming
    // connect answers the transport-offer without an inline `/api/whoami` round
    // trip (the acceptor's gather is what the initiator waits on during
    // establishing). Best-effort, backgrounded so it never delays daemon start.
    {
        let server = server.to_string();
        tokio::spawn(async move {
            direct::warm_public_ip(&server).await;
        });
    }
    // Startup shell-key reconciliation. GATED on authoritative: in shadow the cap
    // layer gates NOTHING, so only REPORT what would be removed (it becomes part of
    // the pre-flip sample). Never delete a working key while the cap store is not
    // yet the authority, else the first `grant` on any node wipes every device that
    // has no cap grant yet.
    {
        let config_dir = crate::settings::config_dir();
        let authoritative = crate::capability::cap_authoritative();
        let revoked = crate::capability::devices_with_shell_revoked(&config_dir);
        let ak_path = sshkeys::authorized_keys_path();
        let ak_content = std::fs::read_to_string(&ak_path).unwrap_or_default();
        // Emit per-device shadow logs for the WOULD-remove devices that
        // actually have a block (avoid noise for devices without one).
        for device in &revoked {
            if sshkeys::has_block(&ak_content, device) && !authoritative {
                ui::critical(&format!(
                    "CAP-SHADOW RECONCILE (startup): WOULD remove shell key for '{device}' (cap store denies shell); NOT removing in shadow"
                ));
            }
        }
        let new_ak = crate::capability::reconcile_shell_keys(&revoked, &ak_content, authoritative);
        if new_ak != ak_content {
            if let Err(e) = crate::platform::SecretFile::write_str(&ak_path, &new_ak) {
                eprintln!("shell-key reconcile (startup): failed to write authorized_keys: {e}");
            }
        }
    }
    let res = recv_cmd(
        server,
        None,
        dir,
        false,
        None,
        None,
        true,
        relay,
        None,
        true,
        None,
        shell_policy,
        shell_user,
        no_proxy_fallback,
    )
    .await;
    let _ = std::fs::remove_file(pidfile());
    res
}

/// Follow or tail the daemon's diagnostic timeline (diag.jsonl). The daemon
/// writes structured JSONL connect spans here; `logs` renders them readably and
/// refuses to flood: a bounded backlog (default 20 lines, --tail 0 = live
/// only), then follows live with -f.
pub(crate) async fn logs_cmd(follow: bool, tail: usize) -> Result<()> {
    // The daemon's human console output goes to daemon.log when detached, and
    // the diagnostic timeline is diag.jsonl. Follow whichever exists; prefer
    // the console log when present (it is what a user means by "logs").
    let console = crate::platform::Paths::config_path("daemon.log");

    // A daemon under a service manager writes to the journal, not to a file we
    // own, so there is nothing here to read and there never will be. That is
    // the DEFAULT path: first-run offers "Stay available in the background?"
    // and installs a service, after which `filament logs` said "no log yet (the
    // daemon writes it while it runs)" forever, on a daemon that was running
    // and was writing plenty. The sentence blamed timing for a condition that
    // does not change. Hand the user the journal instead.
    if !console.exists() {
        if let Some(pid) = daemon_alive() {
            if let Some(mgr) = service_manager_for_pid(pid) {
                let scope = match mgr {
                    ServiceManager::SystemdSystem => "",
                    ServiceManager::SystemdUser => "--user ",
                };
                let n = tail.max(1);
                let follow_flag = if follow { "-f " } else { "" };
                let cmd = format!("journalctl {scope}-u filament {follow_flag}-n {n} --no-pager");
                ui::say(&format!(
                    "  this daemon runs as a service (pid {pid}); its output goes to the journal"
                ));
                ui::say(&ui::paint(ui::Tone::Dim, &format!("    {cmd}")));
                let status = std::process::Command::new("journalctl")
                    .args(scope.split_whitespace())
                    .args(["-u", "filament"])
                    .args(if follow { vec!["-f"] } else { vec![] })
                    .args(["-n", &n.to_string(), "--no-pager"])
                    .status();
                return match status {
                    Ok(st) if st.success() => Ok(()),
                    // Say which step failed. "no log yet" would be a third
                    // wrong explanation for the same situation.
                    _ => {
                        ui::say(
                            "  could not read the journal here; run the command above directly",
                        );
                        Ok(())
                    }
                };
            }
        }
    }

    let path = if console.exists() {
        console
    } else {
        crate::platform::Paths::config_path("diag.jsonl")
    };
    let read_tail = |count: usize| -> Result<()> {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            // Say what is true now, not what will happen later: nothing has
            // been written yet. Whether it WILL appear depends on the daemon
            // actually running (and, on some platforms, having a place to
            // write), which this process cannot establish.
            ui::say("  no log yet (nothing written so far)");
            return Ok(());
        };
        let lines: Vec<&str> = raw.lines().collect();
        let start = lines.len().saturating_sub(count);
        for line in &lines[start..] {
            eprintln!("{line}");
        }
        Ok(())
    };
    if tail > 0 {
        read_tail(tail)?;
    }
    if !follow {
        return Ok(());
    }
    // Follow live: read new appended lines until ctrl-c. Ctrl-c must detach
    // cleanly, never stop the daemon. The file may not exist yet (the daemon
    // is still starting); poll for it instead of erroring.
    use tokio::io::{AsyncBufReadExt, AsyncSeekExt};
    // #216: ONE interrupt registration, created before the loops and held for
    // the whole follow.
    //
    // The old shape built `tokio::signal::ctrl_c()` fresh inside each select and
    // awaited the idle sleep in the branch BODY, outside any select. A followed
    // log is idle almost all of the time, so almost every press landed in a
    // window where no ctrl_c future existed, and a signal delivered when nothing
    // is listening is not replayed to whatever listens next. The user saw
    // ^C^C^C^C do nothing while two banners promised ctrl-c detaches.
    //
    // `notify_one` (not `notify_waiters`) is the load-bearing choice: it stores a
    // permit when there is no waiter, so a press during a sleep is remembered and
    // consumed by the next `notified()`. `notify_waiters` would drop it and
    // reintroduce the bug in a subtler form.
    let interrupted = std::sync::Arc::new(tokio::sync::Notify::new());
    {
        let n = interrupted.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Remove any subnet-router forwarding rules this process installed.
            // A FORWARD ACCEPT that outlives the daemon keeps the machine
            // forwarding for an overlay that is gone, and nothing would report
            // it.
            subnet_forward::cleanup();
            // A WireGuard interface must not outlive the daemon that made it:
            // left behind, it keeps routing a peer's overlay address into a
            // tunnel with nobody on the other end, which looks exactly like the
            // network breaking. Best-effort and idempotent, like the rest of
            // teardown.
            crate::wg::teardown(crate::wg::WG_DEV);
            n.notify_one();
        });
    }
    macro_rules! detached {
        () => {{
            ui::say("\n  detached (the daemon keeps running)");
            return Ok(());
        }};
    }
    loop {
        match tokio::fs::OpenOptions::new().read(true).open(&path).await {
            Ok(f) => {
                let mut file = f;
                file.seek(std::io::SeekFrom::End(0)).await?;
                let mut reader = tokio::io::BufReader::new(file);
                let mut line = String::new();
                loop {
                    tokio::select! {
                        biased;
                        _ = interrupted.notified() => detached!(),
                        res = reader.read_line(&mut line) => {
                            if res? == 0 {
                                // The idle wait is a select ARM, not an awaited
                                // body, so the interrupt stays live through it.
                                tokio::select! {
                                    biased;
                                    _ = interrupted.notified() => detached!(),
                                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                                }
                                continue;
                            }
                            eprintln!("{}", line.trim_end());
                            line.clear();
                        }
                    }
                }
            }
            Err(_) => {
                // The same window while waiting for the file to appear: a daemon
                // that is slow to start must not make ctrl-c inert either.
                tokio::select! {
                    biased;
                    _ = interrupted.notified() => detached!(),
                    _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                }
                continue;
            }
        }
    }
}
