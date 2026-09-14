use anyhow::{bail, Result};
use std::path::Path;

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const FILAMENT_MARKER: &str = "# Added by filament for L3 overlay access";

/// Configure sshd to listen on the L3 overlay addresses AND localhost.
/// Appends ListenAddress entries for both IPv6 and IPv4 overlay addresses,
/// plus 127.0.0.1 and ::1 so `filament ssh` (which dials localhost via the
/// L2 tunnel) continues to work. Without the localhost entries, sshd's
/// default all-interfaces listen is REPLACED by the explicit overlay entries
/// and localhost becomes unreachable (a regression).
pub fn configure_sshd_overlay(v6: &str, v4: &str) -> Result<()> {
    let config_path = Path::new(SSHD_CONFIG);
    
    if !config_path.exists() {
        bail!("sshd_config not found at {SSHD_CONFIG}");
    }
    
    let content = std::fs::read_to_string(config_path)?;
    
    // Check if already configured (idempotent)
    if content.contains(FILAMENT_MARKER) {
        crate::ui::say("sshd overlay addresses already configured");
        return Ok(());
    }
    
    // Build the entries to append — overlay addresses AND localhost.
    let entries = format!(
        "\n{FILAMENT_MARKER}\nListenAddress {v6}\nListenAddress {v4}\nListenAddress 127.0.0.1\nListenAddress ::1\n"
    );
    
    // Append to config
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(config_path)?;
    std::io::Write::write_all(&mut file, entries.as_bytes())?;
    
    crate::ui::say(&format!("added overlay addresses to sshd_config:"));
    crate::ui::say(&format!("  ListenAddress {v6}"));
    crate::ui::say(&format!("  ListenAddress {v4}"));
    
    // Reload sshd
    reload_sshd()?;
    
    Ok(())
}

/// Reload sshd to pick up configuration changes.
fn reload_sshd() -> Result<()> {
    // daemon-reload first to pick up unit file changes
    let _ = std::process::Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status();
    
    // Then restart sshd
    let status = std::process::Command::new("sudo")
        .args(["systemctl", "restart", "ssh"])
        .status();
    
    match status {
        Ok(s) if s.success() => {
            crate::ui::say("restarted sshd");
            Ok(())
        }
        _ => {
            // Try SIGHUP fallback
            let status = std::process::Command::new("sudo")
                .args(["kill", "-HUP"])
                .arg(get_sshd_pid()?)
                .status();
            
            match status {
                Ok(s) if s.success() => {
                    crate::ui::say("reloaded sshd via SIGHUP");
                    Ok(())
                }
                _ => bail!("failed to restart sshd (try: sudo systemctl restart ssh)"),
            }
        }
    }
}

/// Get the sshd PID.
fn get_sshd_pid() -> Result<String> {
    let output = std::process::Command::new("pidof")
        .arg("sshd")
        .output()?;
    
    let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if pid.is_empty() {
        bail!("sshd is not running");
    }
    
    // Take the first PID if multiple
    Ok(pid.split_whitespace().next().unwrap_or(&pid).to_string())
}

/// Check if sshd overlay addresses are configured.
pub fn is_configured() -> bool {
    let Ok(content) = std::fs::read_to_string(SSHD_CONFIG) else {
        return false;
    };
    content.contains(FILAMENT_MARKER)
}

const SSHD_CA_MARKER: &str = "# Added by filament for SSH certificates (shell --ssh)";
/// Default location of the CA public key the TrustedUserCAKeys line points at.
/// (The operator places the daemon's CA pub here out of band.)
pub const SSHD_CA_PUB_DEFAULT: &str = "/etc/ssh/filament_ca.pub";
const SSHD_CONFIG_DEFAULT: &str = "/etc/ssh/sshd_config";
const SSHD_PRINCIPALS_BASE_DEFAULT: &str = "/etc/ssh/filament_principals";

/// sshd_config path: env-overridable so e2e exercises the real writer
/// against temp files instead of the live config.
pub fn sshd_config_path() -> std::path::PathBuf {
    std::env::var("FILAMENT_SSH_SSHD_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(SSHD_CONFIG_DEFAULT))
}

/// Principals base dir (per-user files under it): env-overridable likewise.
pub fn principals_base_dir() -> std::path::PathBuf {
    std::env::var("FILAMENT_SSH_PRINCIPALS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(SSHD_PRINCIPALS_BASE_DEFAULT))
}

/// Trust-anchor path (where TrustedUserCAKeys points): env-overridable so
/// e2e asserts the product copy without touching /etc/ssh.
pub fn ca_pub_anchor_path() -> std::path::PathBuf {
    std::env::var("FILAMENT_SSH_CA_PUB_ANCHOR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(SSHD_CA_PUB_DEFAULT))
}

/// Install the daemon CA pub at the trust anchor (0644), creating parents.
/// Best-effort like everything here (loud error, Ok): the manual steps
/// cover the unwritable case.
pub fn install_ca_pub_anchor(src: &Path, anchor: &Path) -> Result<()> {
    let pub_text = std::fs::read_to_string(src)?;
    if let Some(parent) = anchor.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(anchor, pub_text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(anchor, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// Principals file for one login user under a base dir.
pub fn principals_file_for(base: &Path, user: &str) -> std::path::PathBuf {
    base.join(user)
}

/// Ensure the principals file lists exactly the daemon principal (single
/// line, idempotent): without it even a valid cert fails at sshd, so the
/// arming flows write it in the same breath. Best-effort (loud error,
/// Ok): up/grant must not newly require root.
pub fn ensure_principals_entry(base: &Path, user: &str) -> Result<()> {
    std::fs::create_dir_all(base)?;
    let path = principals_file_for(base, user);
    let want = format!("{user}\n");
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    if have != want {
        std::fs::write(&path, want)?;
    }
    Ok(())
}

/// Exact CA block: a Match-User scope (everything restricted to the daemon
/// user) with the trust anchor plus the principals line. Rendered pure so
/// the text is unit-tested byte-exact without touching a real sshd_config.
pub fn render_sshd_ca_block(
    ca_pub_path: &Path,
    daemon_user: &str,
    principals_file: &Path,
) -> String {
    format!(
        "\n{SSHD_CA_MARKER}\nMatch User {daemon_user}\n    TrustedUserCAKeys {}\n    AuthorizedPrincipalsFile {}\n",
        ca_pub_path.display(),
        principals_file.display(),
    )
}

/// Manual steps printed when the config is unwritable (operator applies them
/// with privilege instead), including the CA-pub copy. Pure for the same
/// reason as the renderer.
pub fn sshd_ca_manual_steps(
    ca_src: &Path,
    anchor: &Path,
    daemon_user: &str,
    principals_file: &Path,
) -> String {
    format!(
        "sshd_config is not writable; apply as root, then reload sshd:\n# cp {} {} && chmod 644 {}\n{}\n# then: sudo systemctl restart ssh (or: sudo kill -HUP $(pidof sshd))",
        ca_src.display(),
        anchor.display(),
        anchor.display(),
        render_sshd_ca_block(anchor, daemon_user, principals_file).trim(),
    )
}

/// Ensure the CA block is present (idempotent via marker). Writable: append
/// and optionally reload. Unwritable: print both lines plus the reload step
/// and succeed -- the operator applies them, nothing fails silently.
/// `reload` runs the real sudo reload; tests pass false.
pub fn ensure_sshd_ca(
    config_path: &Path,
    ca_pub_path: &Path,
    daemon_user: &str,
    principals_file: &Path,
    ca_src: &Path,
    reload: bool,
) -> Result<()> {
    let current = std::fs::read_to_string(config_path).map_err(|_| {
        anyhow::anyhow!("sshd_config not found at {}", config_path.display())
    })?;
    if current.contains(SSHD_CA_MARKER) {
        crate::ui::say("sshd CA trust already configured");
        return Ok(());
    }
    let block = render_sshd_ca_block(ca_pub_path, daemon_user, principals_file);
    let mut file = match std::fs::OpenOptions::new().append(true).open(config_path) {
        Ok(f) => f,
        Err(_) => {
            crate::ui::say(&sshd_ca_manual_steps(ca_src, ca_pub_path, daemon_user, principals_file));
            return Ok(());
        }
    };
    std::io::Write::write_all(&mut file, block.as_bytes())?;
    drop(file);
    // Test BEFORE reload: a bad config must roll back, never ship behind a
    // restart. `sshd -t -f` validates without touching the live daemon.
    // (Unix OpenSSH path; on Windows there is no system sshd to reload --
    // the writer still renders correct lines for manual application, and
    // the unwritable branch above is how that surfaces.)
    let tested = std::process::Command::new("sshd")
        .args(["-t", "-f"])
        .arg(config_path)
        .stdin(std::process::Stdio::null())
        .output();
    match tested {
        Ok(out) if out.status.success() => {}
        tested => {
            let detail = match tested {
                Ok(out) => String::from_utf8_lossy(&out.stderr).trim().to_string(),
                Err(e) => format!("could not run sshd: {e}"),
            };
            if std::fs::write(config_path, &current).is_err() {
                anyhow::bail!(
                    "sshd rejected the new config AND rollback failed; {} may be left modified -- restore it by hand",
                    config_path.display()
                );
            }
            anyhow::bail!(
                "sshd rejected the new config ({detail}) (rolled back, daemon untouched); apply manually: {}",
                sshd_ca_manual_steps(ca_src, ca_pub_path, daemon_user, principals_file)
                    .replace('\n', " | ")
            );
        }
    }
    crate::ui::say("added SSH CA trust to sshd_config");
    if reload {
        reload_sshd()?;
    }
    Ok(())
}

/// Pure presence check over config text: (TrustedUserCAKeys ours, principals
/// line ours). Both must carry our marker block to count.
pub fn sshd_ca_status(config_text: &str) -> (bool, bool) {
    let ours = config_text.contains(SSHD_CA_MARKER);
    (
        ours && config_text.contains("TrustedUserCAKeys"),
        ours && config_text.contains("AuthorizedPrincipalsFile"),
    )
}

/// Doctor check: both CA lines present in the live sshd_config.
pub fn check_sshd_ca() -> std::result::Result<(), String> {
    check_sshd_ca_at(Path::new(SSHD_CONFIG_DEFAULT))
}

/// Best-effort arming for shell-serving flows (`up --shell`, `grant shell`):
/// ensure the CA block plus the daemon principals entry. Loud on any
/// failure but always Ok: serving must not newly require root. Paths honor
/// the test overrides, so e2e exercises the real writer, not a stub.
pub async fn arm_ssh_ca_for_serving() {
    let Some(user) = crate::ssh_ca::daemon_username() else {
        crate::ui::say("ssh CA arming skipped (cannot determine serving user); cert logins will refuse until applied");
        return;
    };
    let config_dir = crate::settings::config_dir();
    // CA key first: pre-existing installs never ran init, so mint here
    // (idempotent). A mint failure stops arming loudly -- without a CA
    // there is nothing to anchor or trust.
    if let Err(e) = crate::ssh_ca::ensure_ca_key(&config_dir).await {
        crate::ui::say(&format!(
            "ssh CA arming skipped (no CA key: {e}); cert logins will refuse until applied"
        ));
        return;
    }
    // Trust anchor next: copy the daemon CA pub where the Match block
    // points, so -t validates what sshd will actually read. Unwritable:
    // print the manual steps (including this copy) and stop -- the block
    // below would fail its own -t against a missing anchor.
    let anchor = ca_pub_anchor_path();
    let ca_src = crate::ssh_ca::ca_key_path(&config_dir).with_extension("pub");
    if let Err(e) = install_ca_pub_anchor(&ca_src, &anchor) {
        crate::ui::say(&format!(
            "ssh CA arming skipped (anchor unwritable: {e}); cert logins will refuse until applied:\n{}",
            sshd_ca_manual_steps(
                &ca_src,
                &anchor,
                &user,
                &principals_file_for(&principals_base_dir(), &user)
            )
        ));
        return;
    }
    let principals = principals_file_for(&principals_base_dir(), &user);
    if let Err(e) = ensure_sshd_ca(
        &sshd_config_path(),
        &anchor,
        &user,
        &principals,
        &ca_src,
        true,
    ) {
        crate::ui::say(&format!(
            "ssh CA arming skipped ({e}); cert logins will refuse until applied"
        ));
        return;
    }
    if let Err(e) = ensure_principals_entry(&principals_base_dir(), &user) {
        crate::ui::say(&format!(
            "ssh principals entry skipped ({e}); cert logins will refuse until applied"
        ));
    }
}

/// Same against an explicit path (tests use temp files, never the live one).
pub fn check_sshd_ca_at(path: &Path) -> std::result::Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("sshd config unreadable at {}: {e}", path.display()))?;
    match sshd_ca_status(&text) {
        (true, true) => Ok(()),
        (false, _) => Err("TrustedUserCAKeys line missing (run the CA setup)".to_string()),
        (_, false) => Err("AuthorizedPrincipalsFile line missing (run the CA setup)".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_block_is_a_daemon_user_match_with_both_lines() {
        let block = render_sshd_ca_block(
            Path::new("/etc/ssh/filament_ca.pub"),
            "filament",
            Path::new("/etc/ssh/filament_principals/%u"),
        );
        assert_eq!(
            block,
            "\n# Added by filament for SSH certificates (shell --ssh)\nMatch User filament\n    TrustedUserCAKeys /etc/ssh/filament_ca.pub\n    AuthorizedPrincipalsFile /etc/ssh/filament_principals/%u\n"
        );
    }

    #[test]
    fn anchor_copy_installs_0644_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-anchor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("ssh_ca.pub");
        std::fs::write(&src, "ssh-ed25519 AAAAC3test\n").unwrap();
        let anchor = dir.join("sub").join("anchor.pub");
        install_ca_pub_anchor(&src, &anchor).unwrap();
        install_ca_pub_anchor(&src, &anchor).unwrap();
        assert_eq!(
            std::fs::read_to_string(&anchor).unwrap(),
            "ssh-ed25519 AAAAC3test\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&anchor).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
        assert!(install_ca_pub_anchor(&dir.join("missing"), &anchor).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn principals_entry_lists_exactly_the_daemon_user() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-princ-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_principals_entry(&dir, "daemon").unwrap();
        ensure_principals_entry(&dir, "daemon").unwrap();
        assert_eq!(
            std::fs::read_to_string(principals_file_for(&dir, "daemon")).unwrap(),
            "daemon\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manual_steps_contain_both_lines_and_reload() {
        let steps = sshd_ca_manual_steps(
            Path::new("/ssh/ssh_ca.pub"),
            Path::new("/ca.pub"),
            "daemon",
            Path::new("/p/%u"),
        );
        assert!(steps.contains("TrustedUserCAKeys /ca.pub"), "{steps}");
        assert!(steps.contains("AuthorizedPrincipalsFile"), "{steps}");
        assert!(steps.contains("systemctl restart ssh"), "{steps}");
        assert!(steps.contains("/ssh/ssh_ca.pub"), "{steps}");
        assert!(steps.contains("/ca.pub"), "{steps}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_is_idempotent_and_refuses_missing_file() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // sshd -t needs real host keys, else every ensure rolls back.
        for name in ["hostkey", "ca"] {
            let st = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-f"])
                .arg(dir.join(name))
                .args(["-N", ""])
                .status()
                .expect("ssh-keygen present");
            assert!(st.success());
        }
        // sshd -t refuses an unprotected host private key (umask-dependent
        // otherwise): tighten like production key material.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("hostkey"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let ca_pub = dir.join("ca.pub");
        let cfg = dir.join("sshd_config");
        std::fs::write(
            &cfg,
            format!("Port 22\nHostKey {}\n", dir.join("hostkey").display()),
        )
        .unwrap();
        ensure_sshd_ca(&cfg, &ca_pub, "daemon", Path::new("/p/%u"), &ca_pub, false).unwrap();
        ensure_sshd_ca(&cfg, &ca_pub, "daemon", Path::new("/p/%u"), &ca_pub, false).unwrap();
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(
            text.matches(SSHD_CA_MARKER).count(),
            1,
            "second ensure must not duplicate: {text}"
        );
        assert!(check_sshd_ca_at(&cfg).is_ok());
        assert!(ensure_sshd_ca(
            &dir.join("nope"),
            Path::new("/ca.pub"),
            "daemon",
            Path::new("/p/%u"),
            Path::new("/ssh/ssh_ca.pub"),
            false
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn bad_config_rolls_back_and_refuses() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-rb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-f"])
            .arg(dir.join("hostkey"))
            .args(["-N", ""])
            .status()
            .expect("ssh-keygen present");
        assert!(st.success());
        let before = format!(
            "Port 22\nHostKey {}\nBogusDirective yes\n",
            dir.join("hostkey").display()
        );
        let cfg = dir.join("sshd_config");
        std::fs::write(&cfg, &before).unwrap();
        let e = ensure_sshd_ca(&cfg, Path::new("/ca.pub"), "daemon", Path::new("/p/%u"), Path::new("/ssh/ssh_ca.pub"), false)
            .unwrap_err();
        assert!(e.to_string().contains("rolled back"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&cfg).unwrap(),
            before,
            "failed config must be restored byte-identical"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_distinguishes_missing_halves() {
        let (t, p) = sshd_ca_status("Port 22\n");
        assert!(!t && !p);
        let full = render_sshd_ca_block(Path::new("/ca.pub"), "d", Path::new("/p/%u"));
        let (t, p) = sshd_ca_status(&full);
        assert!(t && p);
        let mut partial = full.replace("AuthorizedPrincipalsFile", "AuthorizedKeysFile");
        let (t, p) = sshd_ca_status(&partial);
        assert!(t && !p, "wrong principals directive must not count");
        partial = full.replace(SSHD_CA_MARKER, "# foreign");
        let (t, p) = sshd_ca_status(&partial);
        assert!(!t && !p, "keys without our marker must not count");
    }
}
