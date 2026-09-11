//! Installing filament as a managed service, lifted out of `main.rs`.
//!
//! Two platform halves of one function, both present so the CLI compiles
//! everywhere: the Linux half writes and enables a systemd unit (and refuses
//! loudly rather than guessing when it cannot elevate), and the non-Linux half
//! is a stub that prints the commands to run by hand. The `#[cfg]` attributes
//! and both doc comments travelled with their functions unchanged.
//!
//! Measured: no cfg beyond that pair, no test hooks, no spawned tasks, and no
//! back-edges into `main.rs` -- this module depends only on `ui`, `platform`,
//! `anyhow` and std.
#[cfg(not(target_os = "linux"))]
use crate::platform;
#[cfg(target_os = "linux")]
use crate::ui;
use anyhow::Result;
#[cfg(not(target_os = "linux"))]
use anyhow::bail;

/// Install a SYSTEM systemd unit that receives CAP_NET_ADMIN from systemd
/// (`AmbientCapabilities`), so the overlay's kernel TUN needs NO file capability on
/// the binary. That is what kills the recurring sudo: a file cap is lost when
/// `filament update` replaces the binary, but an ambient cap is granted afresh by
/// systemd on every (re)start, so updates never need `setcap` (hence never a
/// password). Writes `/etc/systemd/system/filament.service`, drops any stale file
/// cap, retires a pre-existing --user service, and enables it, using ONE `sudo` for
/// the privileged steps (a single interactive prompt, NOT a per-update one). If it
/// cannot elevate, it prints the exact unit + commands to run by hand.
#[cfg(target_os = "linux")]
pub(crate) fn install_system_service(
    shell: bool,
    shell_only: &Option<String>,
    shell_user: &Option<String>,
    i_know: bool,
) -> Result<()> {
    let exe = std::env::current_exe()?.display().to_string();
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".into());
    let home = std::env::var("HOME").unwrap_or_else(|_| format!("/home/{user}"));

    // Carry the same shell posture the user asked for into the unit's ExecStart.
    let mut up_args = String::from(" up");
    if let Some(csv) = shell_only {
        up_args.push_str(&format!(" --shell-only {csv}"));
    } else if shell {
        up_args.push_str(" --shell");
    }
    if let Some(u) = shell_user {
        up_args.push_str(&format!(" --shell-user {u}"));
    }
    if i_know {
        up_args.push_str(" --i-know");
    }

    let unit = format!(
        "[Unit]\n\
         Description=Filament drop target (trusted devices only)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=notify\n\
         User={user}\n\
         Environment=HOME={home}\n\
         Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
         ExecStart={exe}{up_args}\n\
         AmbientCapabilities=CAP_NET_ADMIN\n\
         CapabilityBoundingSet=CAP_NET_ADMIN\n\
         Restart=always\n\
         RestartSec=2\n\
         WatchdogSec=45\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let unit_path = "/etc/systemd/system/filament.service";
    let am_root = unsafe { libc::geteuid() } == 0;
    // Run a privileged command, using sudo only when not already root.
    let run_priv = |args: &[&str]| -> bool {
        let mut cmd = if am_root {
            std::process::Command::new(args[0])
        } else {
            let mut c = std::process::Command::new("sudo");
            c.arg(args[0]);
            c
        };
        cmd.args(&args[1..])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    ui::say(&format!(
        "filament: installing system service at {unit_path}"
    ));
    if !am_root {
        ui::say("  (one-time sudo for the system unit; updates afterward need none)");
    }
    // Write the unit as root by PIPING it to `tee` under the privileged runner.
    // Deliberately NO on-disk staging: a predictable, world-writable temp file
    // (e.g. /tmp/filament.service.tmp) is a TOCTOU - another local user could
    // swap or symlink it between our write and the privileged copy, yielding an
    // attacker-controlled ROOT-owned systemd unit (root code execution). Piping to
    // `tee` has no intermediary to race; sudo still reads its password from the tty,
    // not our stdin, so the small unit content flows to tee uncontended.
    let wrote = {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = if am_root {
            std::process::Command::new("tee")
        } else {
            let mut c = std::process::Command::new("sudo");
            c.arg("tee");
            c
        };
        match cmd
            .arg(unit_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                if let Some(mut si) = child.stdin.take() {
                    let _ = si.write_all(unit.as_bytes());
                    // si drops here, closing stdin so tee finalizes the file.
                }
                child.wait().map(|s| s.success()).unwrap_or(false)
            }
            Err(_) => false,
        }
    };
    if wrote {
        // tee creates with the (root) umask; pin the mode explicitly.
        let _ = run_priv(&["chmod", "644", unit_path]);
    }
    if !wrote {
        ui::say("filament: could not elevate; install the system unit by hand:");
        ui::say(&format!(
            "  sudo tee {unit_path} >/dev/null <<'UNIT'\n{unit}UNIT"
        ));
        ui::say(&format!("  sudo setcap -r {exe} 2>/dev/null || true"));
        ui::say("  sudo systemctl daemon-reload && sudo systemctl enable --now filament");
        return Ok(());
    }
    // Drop any stale file cap (ambient replaces it; keeps updates clean); retire a
    // pre-existing --user service so the two don't fight over the mesh. Best-effort.
    let _ = run_priv(&["setcap", "-r", &exe]);
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "filament"])
        .status();
    let enabled = run_priv(&["systemctl", "daemon-reload"])
        && run_priv(&["systemctl", "enable", "--now", "filament"]);
    if enabled {
        ui::say(&format!(
            "  {} system service enabled; CAP_NET_ADMIN comes from systemd, so no setcap on update",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
        ui::say("  logs: journalctl -u filament");
    } else {
        ui::say("  wrote the unit; enable it with: sudo systemctl enable --now filament");
    }

    // Belt-and-suspenders: a NOPASSWD sudoers drop-in scoped to JUST restarting this
    // one service, so any fallback `sudo systemctl restart filament` (e.g. when the
    // reload op is unavailable) is password-free too. Written the same TOCTOU-safe
    // way (piped to tee, no world-writable staging), mode 0440, and validated with
    // visudo - a malformed sudoers drop-in must NEVER be left in place, so it is
    // removed if it does not parse.
    let systemctl = ["/usr/bin/systemctl", "/bin/systemctl"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied()
        .unwrap_or("/usr/bin/systemctl");
    let sudoers_path = "/etc/sudoers.d/filament";
    let sudoers = format!(
        "{user} ALL=(root) NOPASSWD: {systemctl} restart filament, {systemctl} daemon-reload\n"
    );
    let wrote_sudoers = {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = if am_root {
            std::process::Command::new("tee")
        } else {
            let mut c = std::process::Command::new("sudo");
            c.arg("tee");
            c
        };
        match cmd
            .arg(sudoers_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
        {
            Ok(mut ch) => {
                if let Some(mut si) = ch.stdin.take() {
                    let _ = si.write_all(sudoers.as_bytes());
                }
                ch.wait().map(|s| s.success()).unwrap_or(false)
            }
            Err(_) => false,
        }
    };
    if wrote_sudoers {
        let _ = run_priv(&["chmod", "0440", sudoers_path]);
        if run_priv(&["visudo", "-cf", sudoers_path]) {
            ui::say(&format!(
                "  {} passwordless `systemctl restart filament` for {user}",
                ui::paint(ui::Tone::Ok, ui::glyph_ok())
            ));
        } else {
            let _ = run_priv(&["rm", "-f", sudoers_path]);
            ui::say("  (skipped the restart sudoers rule: visudo validation failed)");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn install_system_service(
    _shell: bool,
    _shell_only: &Option<String>,
    _shell_user: &Option<String>,
    _i_know: bool,
) -> Result<()> {
    let hint = platform::ServiceHost::detect().install_instructions();
    bail!(
        "--install --system (ambient-cap system service) is not supported on this platform. {hint}"
    );
}
