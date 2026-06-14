// sshkeys, filament-managed ssh auth material for the seamless `filament ssh`
// path (docs/design-seamless-ssh.md). NEVER touches the user's ~/.ssh.
//
// Two roles:
//   * INITIATOR keeps an ephemeral managed keypair + a private known_hosts under
//     the filament config dir. `filament ssh` points ssh at exactly these via
//     -o IdentityFile / -o UserKnownHostsFile / -o IdentitiesOnly=yes, so a user
//     with ZERO ssh setup connects with no prompts and no key copying.
//   * ACCEPTOR installs an initiator's managed pubkey into its OWN
//     $HOME/.ssh/authorized_keys inside a CLEARLY-MARKED, removable
//     `# BEGIN/END filament-managed <device>` block, ONLY over the authenticated
//     channel AND ONLY when the `shell` cap is granted (enforced by the caller).
//     It also reports its real host public keys so the initiator can pin them.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

/// The filament config dir (same root as devices.json), honoring
/// FILAMENT_CONFIG_DIR for hermetic tests. NOT the user's ~/.ssh.
fn config_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/filament")
}

/// Directory holding the managed keypair + private known_hosts.
fn ssh_dir() -> PathBuf {
    config_dir().join("ssh")
}

/// Managed private key path (`id_ed25519`). The pubkey is `<this>.pub`.
pub fn managed_key_path() -> PathBuf {
    ssh_dir().join("id_ed25519")
}

/// Filament-private known_hosts (pin store), never the user's.
pub fn known_hosts_path() -> PathBuf {
    ssh_dir().join("known_hosts")
}

#[cfg(unix)]
fn chmod(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn chmod(_p: &Path, _mode: u32) {}

/// Ensure the managed ed25519 keypair exists; generate it on demand via
/// `ssh-keygen` if absent. Returns the PUBLIC key line (one line, no trailing
/// newline). The private key NEVER leaves disk and is never printed.
pub fn ensure_managed_key() -> Result<String> {
    let key = managed_key_path();
    // ssh-keygen writes the pubkey to "<key>.pub".
    let pub_path = PathBuf::from(format!("{}.pub", key.display()));

    if !key.exists() {
        if let Some(dir) = key.parent() {
            std::fs::create_dir_all(dir).context("create filament ssh dir")?;
            chmod(dir, 0o700);
        }
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "filament-managed", "-f"])
            .arg(&key)
            .status()
            .context("run ssh-keygen (is openssh-client installed?)")?;
        if !st.success() {
            return Err(anyhow!("ssh-keygen failed to create the managed key"));
        }
        chmod(&key, 0o600);
        chmod(&pub_path, 0o644);
    }
    let line = std::fs::read_to_string(&pub_path).context("read managed pubkey")?;
    Ok(line.trim().to_string())
}

// ----------------------------------------------------- ACCEPTOR: authorized_keys

const BEGIN: &str = "# BEGIN filament-managed";
const END: &str = "# END filament-managed";

/// Path to the ACCEPTOR daemon user's authorized_keys ($HOME/.ssh/authorized_keys).
/// Deliberately rooted at $HOME (NOT the config dir), that is where sshd reads
/// it. Tests sandbox the write by running the acceptor with HOME set to a temp.
pub fn authorized_keys_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".ssh/authorized_keys")
}

/// M-3 (authorized_keys injection): validate that `pubkey` is a SINGLE, well-
/// formed ssh public-key line before it is ever written. A trusted+shell peer
/// could otherwise send a pubkey containing an interior `\n` (which `.trim()`
/// does NOT strip) to inject EXTRA authorized_keys lines, extra keys, a
/// `command=`/`from=` forced-command, etc. We reject anything with a control
/// character (newline, CR, tab, …) or more than one whitespace-separated key
/// line, and require the shape `<key-type> <base64-blob> [single-line comment]`.
///
/// Returns the trimmed, validated single-line key on success.
pub fn validate_pubkey(pubkey: &str) -> Result<String> {
    let key = pubkey.trim();
    if key.is_empty() {
        return Err(anyhow!("empty pubkey"));
    }
    // Reject ANY control character (covers \n, \r, \t, NUL, vertical tab, …).
    // After trimming surrounding whitespace, a control char anywhere means the
    // value is not a single clean line, refuse outright.
    if key.chars().any(|c| c.is_control()) {
        return Err(anyhow!("pubkey contains a control character (multi-line injection?)"));
    }
    // Shape: 2 or 3 whitespace-separated fields. Field 0 is the key type, field 1
    // is the base64 blob, optional field 2 is a single-line comment.
    let mut fields = key.split_whitespace();
    let key_type = fields.next().ok_or_else(|| anyhow!("pubkey missing key type"))?;
    let blob = fields.next().ok_or_else(|| anyhow!("pubkey missing key material"))?;
    // The comment may itself contain spaces, so collapse the rest into one field;
    // what matters is there is no embedded newline (already rejected above).
    let _comment: String = fields.collect::<Vec<_>>().join(" ");
    if !(key_type.starts_with("ssh-") || key_type.starts_with("ecdsa-") || key_type.starts_with("sk-")) {
        return Err(anyhow!("unrecognized pubkey type '{key_type}'"));
    }
    // base64 blob: non-empty and only the base64 alphabet (+ '=' padding).
    if blob.is_empty()
        || !blob.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err(anyhow!("pubkey key material is not base64"));
    }
    Ok(key.to_string())
}

/// Install (or replace) `pubkey` in a marked block for `device` in
/// authorized_keys. Idempotent: a re-grant replaces that device's block rather
/// than appending a duplicate. Creates ~/.ssh (0700) and the file (0600) if
/// absent. SECURITY: the caller MUST have verified the trusted channel + `shell`
/// cap before calling this. The pubkey is re-validated here (M-3), defense in
/// depth, so a bad key is NEVER written even if a caller forgot to check.
pub fn install_authorized_key(device: &str, pubkey: &str) -> Result<()> {
    let pubkey = validate_pubkey(pubkey)?;
    let pubkey = pubkey.as_str();
    let path = authorized_keys_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context("create ~/.ssh")?;
        chmod(dir, 0o700);
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut kept = strip_block(&existing, device);
    if !kept.is_empty() && !kept.ends_with('\n') {
        kept.push('\n');
    }
    kept.push_str(&format!("{BEGIN} {device}\n{pubkey}\n{END} {device}\n"));
    std::fs::write(&path, kept).context("write authorized_keys")?;
    chmod(&path, 0o600);
    Ok(())
}

/// Remove `device`'s marked block from authorized_keys (the "removable" half of
/// the audit story; used by `filament revoke`). No-op if absent.
pub fn remove_authorized_key(device: &str) -> Result<()> {
    let path = authorized_keys_path();
    let Ok(existing) = std::fs::read_to_string(&path) else { return Ok(()) };
    let kept = strip_block(&existing, device);
    std::fs::write(&path, kept).context("write authorized_keys")?;
    chmod(&path, 0o600);
    Ok(())
}

/// Return `content` with the `# BEGIN/END filament-managed <device>` block (and
/// the lines between) removed. Lines outside any such block are preserved
/// verbatim. Path-pure (testable), the file I/O wrappers call this.
pub fn strip_block(content: &str, device: &str) -> String {
    let begin = format!("{BEGIN} {device}");
    let end = format!("{END} {device}");
    let mut out = String::new();
    let mut skipping = false;
    for line in content.lines() {
        if line.trim() == begin {
            skipping = true;
            continue;
        }
        if skipping {
            if line.trim() == end {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// True if a marked block for `device` is present (used by the gate to prove the
/// block is installed / removed).
#[allow(dead_code)] // exercised by the unit test + grep in the gate
pub fn has_block(content: &str, device: &str) -> bool {
    content.lines().any(|l| l.trim() == format!("{BEGIN} {device}"))
}

// --------------------------------------------------------- ACCEPTOR: host keys

/// Read the acceptor's real public host keys. Prod reads /etc/ssh/ssh_host_*.pub;
/// the gate points FILAMENT_SSH_HOSTKEY at a throwaway sshd's hostkey pubfile so
/// it never needs to touch the system's. Returns the raw pubkey lines (e.g.
/// "ssh-ed25519 AAAA...").
pub fn host_pubkeys() -> Vec<String> {
    if let Ok(p) = std::env::var("FILAMENT_SSH_HOSTKEY") {
        if let Ok(s) = std::fs::read_to_string(&p) {
            return s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        }
    }
    let mut keys = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/etc/ssh") {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("ssh_host_") && name.ends_with(".pub") {
                if let Ok(s) = std::fs::read_to_string(e.path()) {
                    if let Some(l) = s.lines().next() {
                        let l = l.trim();
                        if !l.is_empty() {
                            keys.push(l.to_string());
                        }
                    }
                }
            }
        }
    }
    keys
}

// ------------------------------------------------------- INITIATOR: known_hosts

/// Pin the acceptor's host keys into our private known_hosts, keyed by the EXACT
/// destination token ssh will use (so the pin is not silently inert). Replaces
/// any prior pins for that token (host keys can rotate). Each `hostkeys` entry is
/// a pubkey line like "ssh-ed25519 AAAA...".
pub fn pin_host_keys(dest_token: &str, hostkeys: &[String]) -> Result<()> {
    let path = known_hosts_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context("create filament ssh dir")?;
        chmod(dir, 0o700);
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    // Drop prior lines for this token (first field == dest_token).
    let mut out: String = existing
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(dest_token))
        .map(|l| format!("{l}\n"))
        .collect();
    for k in hostkeys {
        let k = k.trim();
        if k.is_empty() {
            continue;
        }
        out.push_str(&format!("{dest_token} {k}\n"));
    }
    std::fs::write(&path, out).context("write known_hosts")?;
    chmod(&path, 0o600);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_block_removes_only_the_named_device() {
        let c = "ssh-rsa AAAAother user@host\n\
                 # BEGIN filament-managed boxA\n\
                 ssh-ed25519 AAAAfilament filament-managed\n\
                 # END filament-managed boxA\n\
                 ssh-ed25519 AAAAkeep keep@host\n";
        let out = strip_block(c, "boxA");
        assert!(!out.contains("filament-managed"));
        assert!(out.contains("AAAAother"));
        assert!(out.contains("AAAAkeep"));
        assert!(!has_block(&out, "boxA"));
    }

    #[test]
    fn validate_pubkey_accepts_a_single_well_formed_key() {
        let ok = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcDEF123+/= filament-managed";
        let v = validate_pubkey(ok).expect("a clean single-line key is accepted");
        assert_eq!(v, ok);
        // No-comment form is fine too.
        assert!(validate_pubkey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5").is_ok());
    }

    #[test]
    fn validate_pubkey_rejects_multiline_injection() {
        // M-3: a newline-bearing pubkey must be refused and NEVER reach the file.
        let inj = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ok\nssh-ed25519 AAAAEVILKEY attacker";
        assert!(validate_pubkey(inj).is_err(), "interior newline must be rejected");
        assert!(validate_pubkey("ssh-ed25519 AAAA\rmore").is_err(), "CR must be rejected");
        assert!(validate_pubkey("ssh-ed25519\tAAAA").is_err(), "tab control char rejected");
        assert!(validate_pubkey("not-a-key blob").is_err(), "bad key type rejected");
        assert!(validate_pubkey("ssh-ed25519 not_base64!!").is_err(), "non-base64 blob rejected");
        assert!(validate_pubkey("").is_err(), "empty rejected");

        // And the install path must refuse it too (defense in depth): the
        // validation runs BEFORE any filesystem write, so install_authorized_key
        // errors out on a multi-line key and never touches authorized_keys.
        let r = install_authorized_key("boxA", inj);
        assert!(r.is_err(), "install must reject the multi-line key before writing");
    }

    #[test]
    fn install_then_strip_is_idempotent_in_memory() {
        // Re-install must not duplicate: strip then add yields exactly one block.
        let mut c = String::new();
        c = strip_block(&c, "boxA");
        c.push_str(&format!("{BEGIN} boxA\nKEY1\n{END} boxA\n"));
        // simulate re-grant with a new key
        let mut c2 = strip_block(&c, "boxA");
        c2.push_str(&format!("{BEGIN} boxA\nKEY2\n{END} boxA\n"));
        assert_eq!(c2.matches(BEGIN).count(), 1);
        assert!(c2.contains("KEY2"));
        assert!(!c2.contains("KEY1"));
    }
}
