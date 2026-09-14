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
#[allow(dead_code)] // CA-2: wired later (see module note)
/// Principals file consulted per authenticating user; restricted to the
/// daemon user by the Match block below. Its CONTENT (which principals are
/// allowed) is maintained by the sign flow, not here.
pub const SSHD_PRINCIPALS_FILE: &str = "/etc/ssh/filament_principals/%u";
#[allow(dead_code)] // CA-2: wired later (see module note)
/// Default location of the CA public key the TrustedUserCAKeys line points at.
pub const SSHD_CA_PUB_DEFAULT: &str = "/etc/ssh/filament_ca.pub";
const SSHD_CONFIG_DEFAULT: &str = "/etc/ssh/sshd_config";

#[allow(dead_code)] // CA-2: wired later (see module note)
/// Exact CA block: a Match-User scope (everything restricted to the daemon
/// user) with the trust anchor plus the principals line. Rendered pure so
/// the text is unit-tested byte-exact without touching a real sshd_config.
pub fn render_sshd_ca_block(ca_pub_path: &Path, daemon_user: &str) -> String {
    format!(
        "\n{SSHD_CA_MARKER}\nMatch User {daemon_user}\n    TrustedUserCAKeys {}\n    AuthorizedPrincipalsFile {SSHD_PRINCIPALS_FILE}\n",
        ca_pub_path.display(),
    )
}

#[allow(dead_code)] // CA-2: wired later (see module note)
/// Manual steps printed when the config is unwritable (operator applies them
/// with privilege instead). Pure for the same reason as the renderer.
pub fn sshd_ca_manual_steps(ca_pub_path: &Path, daemon_user: &str) -> String {
    format!(
        "sshd_config is not writable; apply as root, then reload sshd:\n{}\n# then: sudo systemctl restart ssh (or: sudo kill -HUP $(pidof sshd))",
        render_sshd_ca_block(ca_pub_path, daemon_user).trim(),
    )
}

#[allow(dead_code)] // CA-2: wired later (see module note)
/// Ensure the CA block is present (idempotent via marker). Writable: append
/// and optionally reload. Unwritable: print both lines plus the reload step
/// and succeed -- the operator applies them, nothing fails silently.
/// `reload` runs the real sudo reload; tests pass false.
pub fn ensure_sshd_ca(
    config_path: &Path,
    ca_pub_path: &Path,
    daemon_user: &str,
    reload: bool,
) -> Result<()> {
    let current = std::fs::read_to_string(config_path).map_err(|_| {
        anyhow::anyhow!("sshd_config not found at {}", config_path.display())
    })?;
    if current.contains(SSHD_CA_MARKER) {
        crate::ui::say("sshd CA trust already configured");
        return Ok(());
    }
    let block = render_sshd_ca_block(ca_pub_path, daemon_user);
    let mut file = match std::fs::OpenOptions::new().append(true).open(config_path) {
        Ok(f) => f,
        Err(_) => {
            crate::ui::say(&sshd_ca_manual_steps(ca_pub_path, daemon_user));
            return Ok(());
        }
    };
    std::io::Write::write_all(&mut file, block.as_bytes())?;
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
        let block = render_sshd_ca_block(Path::new("/etc/ssh/filament_ca.pub"), "filament");
        assert_eq!(
            block,
            "\n# Added by filament for SSH certificates (shell --ssh)\nMatch User filament\n    TrustedUserCAKeys /etc/ssh/filament_ca.pub\n    AuthorizedPrincipalsFile /etc/ssh/filament_principals/%u\n"
        );
    }

    #[test]
    fn manual_steps_contain_both_lines_and_reload() {
        let steps = sshd_ca_manual_steps(Path::new("/ca.pub"), "daemon");
        assert!(steps.contains("TrustedUserCAKeys /ca.pub"), "{steps}");
        assert!(steps.contains("AuthorizedPrincipalsFile"), "{steps}");
        assert!(steps.contains("systemctl restart ssh"), "{steps}");
    }

    #[test]
    fn ensure_is_idempotent_and_refuses_missing_file() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("sshd_config");
        std::fs::write(&cfg, "Port 22\n").unwrap();
        ensure_sshd_ca(&cfg, Path::new("/ca.pub"), "daemon", false).unwrap();
        ensure_sshd_ca(&cfg, Path::new("/ca.pub"), "daemon", false).unwrap();
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(
            text.matches(SSHD_CA_MARKER).count(),
            1,
            "second ensure must not duplicate: {text}"
        );
        assert!(check_sshd_ca_at(&cfg).is_ok());
        assert!(ensure_sshd_ca(&dir.join("nope"), Path::new("/ca.pub"), "daemon", false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_distinguishes_missing_halves() {
        let (t, p) = sshd_ca_status("Port 22\n");
        assert!(!t && !p);
        let full = render_sshd_ca_block(Path::new("/ca.pub"), "d");
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
