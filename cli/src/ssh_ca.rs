//! B-side SSH certificate signer (`filament shell --ssh` via local CA).
//!
//! The daemon holds a permanent CA key (0600 beside the identity key) and
//! signs initiators' ephemeral ed25519 keys with `ssh-keygen -s`, pinning
//! every flag the contract requires. Fail-closed throughout: no key, bad
//! perms, nonzero ssh-keygen, missing cert output, garbage ttl, or a pubkey
//! already signed for another device all refuse with a clear error -- never
//! a cert, never an authorized_keys fallback.
//!
//! CA-1 lands the signer ahead of its callers (sign-request handler arrives
//! in CA-3), so unused items are allowed dead here, not warning-neutral
//! debt: remove this attribute once the handler wires them.
#![allow(dead_code)]

use anyhow::{bail, Result};

/// Hard max certificate lifetime: 24h, per contract. The setting clamps here.
pub(crate) const CERT_TTL_HARD_MAX_SECS: u64 = 86_400;
/// Default lifetime when unset: 1h (mirrors the setting default).
pub(crate) const CERT_TTL_DEFAULT_SECS: u64 = 3_600;
/// Skew allowance subtracted from validity start (late clocks, slow links).
pub(crate) const CERT_SKEW_SECS: u64 = 300;

/// Parse a ttl value (plain seconds or `30m`/`1h`/`1d` durations) and clamp
/// to the hard max. Zero, negative (unparseable), and garbage refuse --
/// signing with a guessed lifetime would over-grant against operator intent.
pub(crate) fn parse_ttl_secs(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if let Ok(secs) = trimmed.parse::<u64>() {
        if secs == 0 {
            bail!("ssh cert ttl must be greater than zero");
        }
        return Ok(secs.min(CERT_TTL_HARD_MAX_SECS));
    }
    let secs = crate::parse_duration_secs(trimmed)?;
    Ok(secs.min(CERT_TTL_HARD_MAX_SECS))
}

/// Resolve the configured ttl through the settings registry (default 1h).
/// Garbage refuses (fail closed); the hard max applies after parsing.
pub(crate) fn resolve_cert_ttl_secs() -> Result<u64> {
    let Some(setting) = crate::settings::find("ssh.cert_ttl") else {
        return Ok(CERT_TTL_DEFAULT_SECS);
    };
    let (raw, _) = crate::settings::resolve(setting, None);
    parse_ttl_secs(&raw)
}

/// Effective validity: min(grant expiry if known, requested ttl, setting).
/// Requested 0 refuses (meaningless); the setting side is already clamped.
pub(crate) fn clamp_validity_secs(
    grant_expiry_secs: Option<u64>,
    requested_secs: u64,
    setting_secs: u64,
) -> Result<u64> {
    if requested_secs == 0 {
        bail!("ssh cert ttl must be greater than zero");
    }
    let mut out = requested_secs.min(setting_secs);
    if let Some(g) = grant_expiry_secs {
        out = out.min(g);
    }
    if out == 0 {
        bail!("ssh cert expires immediately under the clamp; refusing");
    }
    Ok(out)
}

/// Absolute `-V` interval for ssh-keygen from a ttl: `AFTER:BEFORE` with a
/// skew allowance on the start. Absolute timestamps (universally accepted),
/// never relative suffixes.
pub(crate) fn validity_interval(now_secs: u64, ttl_secs: u64) -> String {
    format!("{}:{}", stamp(now_secs.saturating_sub(CERT_SKEW_SECS)), stamp(now_secs + ttl_secs))
}

fn stamp(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|d| d.format("%Y%m%d%H%M%S").to_string())
        .unwrap_or_else(|| "19700101000000".to_string())
}

/// Check the CA key file: must exist and (unix) be exactly 0600. A group- or
/// world-readable CA key refuses -- fail closed, never sign anyway.
pub(crate) fn check_ca_key(path: &std::path::Path) -> Result<()> {
    if !path.is_file() {
        bail!("ssh CA key not found at {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "ssh CA key at {} has permissions {:o}, need 0600",
                path.display(),
                mode
            );
        }
    }
    Ok(())
}

/// Refuse anything but a bare ed25519 pubkey (options prefixes, other types,
/// and empty input all fail closed: ssh-keygen would happily sign them).
pub(crate) fn check_ephemeral_pubkey(text: &str) -> Result<()> {
    if text.starts_with("ssh-ed25519 ") && text.trim().split_whitespace().count() >= 2 {
        Ok(())
    } else {
        bail!("only bare ed25519 ephemeral keys are signed");
    }
}

/// Exact pinned ssh-keygen argv: `-I` device id only, `-n` daemon user only,
/// absolute `-V` interval, monotonic `-z` serial, `-O clear` + `-O permit-pty`
/// and nothing else. No shell involved (direct spawn by the caller).
pub(crate) fn build_sign_argv(
    ca_path: &std::path::Path,
    pubkey_file: &std::path::Path,
    key_id: &str,
    principal: &str,
    validity: &str,
    serial: u64,
) -> Vec<String> {
    vec![
        "-s".to_string(),
        ca_path.to_string_lossy().into_owned(),
        "-I".to_string(),
        key_id.to_string(),
        "-n".to_string(),
        principal.to_string(),
        "-V".to_string(),
        validity.to_string(),
        "-z".to_string(),
        serial.to_string(),
        "-O".to_string(),
        "clear".to_string(),
        "-O".to_string(),
        "permit-pty".to_string(),
        pubkey_file.to_string_lossy().into_owned(),
    ]
}

/// One issued-cert record: binds a pubkey to the device it was signed for,
/// so the same key is never re-signed for someone else.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct IssuedCert {
    pub pubkey: String,
    pub device_id: String,
    pub serial: u64,
}

/// Next monotonic serial: one past the max on record (starts at 1).
pub(crate) fn next_serial(records: &[IssuedCert]) -> u64 {
    records.iter().map(|r| r.serial).max().unwrap_or(0) + 1
}

/// Refuse a pubkey already signed for a DIFFERENT device id (key sharing
/// across devices). Same device re-issue is allowed (new serial).
pub(crate) fn refuse_resign(records: &[IssuedCert], pubkey: &str, device_id: &str) -> Result<()> {
    if let Some(r) = records.iter().find(|r| r.pubkey == pubkey) {
        if r.device_id != device_id {
            bail!("ephemeral key already signed for a different device; refusing re-sign");
        }
    }
    Ok(())
}

/// Sidecar path for the issued-cert record (config dir).
pub(crate) fn issued_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("ssh_ca_issued.json")
}

/// Load the record (missing file = no issuances yet, not an error).
pub(crate) fn load_issued(config_dir: &std::path::Path) -> Vec<IssuedCert> {
    let p = issued_path(config_dir);
    let Ok(raw) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

/// Append one issuance (best-effort persist; a lost record only loses the
/// re-sign check for old keys, never grants anything).
pub(crate) fn record_issuance(config_dir: &std::path::Path, rec: &IssuedCert) {
    let mut v = load_issued(config_dir);
    v.push(rec.clone());
    let _ = std::fs::write(issued_path(config_dir), serde_json::to_string(&v).unwrap_or_default());
}

/// Issuance log line fields (who, principal, serial, expiry), per contract.
pub(crate) fn format_issuance(device_id: &str, principal: &str, serial: u64, valid_before: &str) -> String {
    format!("ssh-ca: signed for '{device_id}' principal '{principal}' serial {serial} expiry {valid_before}")
}

/// Sign: write the pubkey to the workdir, run ssh-keygen, read back the
/// `<pubkey>-cert.pub` it writes. Nonzero exit, missing output, or any IO
/// failure refuses with a clear error -- never a cert, never a fallback.
/// `keygen_bin` is injectable so tests pass a stub instead of the real tool.
pub(crate) fn sign(
    keygen_bin: &std::path::Path,
    ca_path: &std::path::Path,
    pubkey_text: &str,
    key_id: &str,
    principal: &str,
    validity: &str,
    serial: u64,
    workdir: &std::path::Path,
) -> Result<String> {
    check_ephemeral_pubkey(pubkey_text)?;
    let pub_file = workdir.join("key.pub");
    std::fs::write(&pub_file, pubkey_text)?;
    let argv = build_sign_argv(ca_path, &pub_file, key_id, principal, validity, serial);
    let status = std::process::Command::new(keygen_bin)
        .args(&argv)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| anyhow::anyhow!("ssh-keygen failed to run: {e}"))?;
    if !status.status.success() {
        bail!(
            "ssh-keygen refused to sign (exit {}): {}",
            status.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    let cert_file = workdir.join("key-cert.pub");
    std::fs::read_to_string(&cert_file)
        .map(|s| s.trim().to_string())
        .map_err(|_| anyhow::anyhow!("ssh-keygen exited 0 but wrote no cert; refusing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_parses_seconds_and_durations_then_clamps() {
        assert_eq!(parse_ttl_secs("3600").unwrap(), 3600);
        assert_eq!(parse_ttl_secs("30m").unwrap(), 1800);
        assert_eq!(parse_ttl_secs("1h").unwrap(), 3600);
        assert_eq!(parse_ttl_secs("48h").unwrap(), 86_400);
        assert!(parse_ttl_secs("0").is_err());
        assert!(parse_ttl_secs("soon").is_err());
        assert!(parse_ttl_secs("").is_err());
    }

    #[test]
    fn clamp_takes_min_and_rejects_zero() {
        assert_eq!(clamp_validity_secs(None, 60, 3600).unwrap(), 60);
        assert_eq!(clamp_validity_secs(Some(30), 3600, 3600).unwrap(), 30);
        assert_eq!(clamp_validity_secs(None, 99_999, 3600).unwrap(), 3600);
        assert!(clamp_validity_secs(None, 0, 3600).is_err());
    }

    #[test]
    fn validity_is_absolute_with_skew() {
        // 2026-09-13T21:20:00Z == 1789334400: start backs off 5m skew.
        assert_eq!(
            validity_interval(1789334400, 3600),
            "20260913211500:20260913222000"
        );
    }

    #[test]
    fn sign_argv_pins_everything() {
        let argv = build_sign_argv(
            std::path::Path::new("/ca"),
            std::path::Path::new("/w/key.pub"),
            "boxA",
            "daemon",
            "20260914000000:20260914010000",
            7,
        );
        assert_eq!(
            argv,
            vec![
                "-s", "/ca", "-I", "boxA", "-n", "daemon", "-V",
                "20260914000000:20260914010000", "-z", "7", "-O", "clear",
                "-O", "permit-pty", "/w/key.pub"
            ]
        );
        assert!(!argv.iter().any(|a| a.contains(' ') && !a.contains('/')),
            "no joined/shell-quoted values: {argv:?}");
    }

    #[test]
    fn ephemeral_accepts_only_bare_ed25519() {
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAAC3xyz box").is_ok());
        assert!(check_ephemeral_pubkey("ssh-rsa AAAAB3xyz box").is_err());
        assert!(check_ephemeral_pubkey("no-touch-cert-request ssh-ed25519 AAAAC3xyz").is_err());
        assert!(check_ephemeral_pubkey("").is_err());
    }

    #[test]
    fn serials_monotonic_and_resign_bound_to_device() {
        let recs = vec![
            IssuedCert { pubkey: "k1".into(), device_id: "a".into(), serial: 4 },
            IssuedCert { pubkey: "k2".into(), device_id: "b".into(), serial: 9 },
        ];
        assert_eq!(next_serial(&recs), 10);
        assert_eq!(next_serial(&[]), 1);
        assert!(refuse_resign(&recs, "k1", "a").is_ok());
        assert!(refuse_resign(&recs, "k3", "zzz").is_ok());
        assert!(refuse_resign(&recs, "k1", "EVIL").is_err());
    }

    #[test]
    fn issuance_line_carries_contract_fields() {
        let line = format_issuance("boxA", "daemon", 7, "20260914010000");
        for field in ["boxA", "daemon", "7", "20260914010000"] {
            assert!(line.contains(field), "missing {field}: {line}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ca_key_requires_0600() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let strict = dir.join("ca");
        let loose = dir.join("ca-loose");
        let missing = dir.join("ca-missing");
        std::fs::write(&strict, "x").unwrap();
        std::fs::write(&loose, "x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&strict, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_ca_key(&strict).is_ok());
        assert!(check_ca_key(&loose).is_err());
        assert!(check_ca_key(&missing).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn sign_refuses_on_nonzero_and_missing_output() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0bW9Oq68v6Kz4pGk3Bn2K8R8m4t stunt";
        // Nonzero exit refuses with the stderr attached.
        let e = sign(
            std::path::Path::new("/bin/false"),
            std::path::Path::new("/ca"),
            key, "boxA", "daemon", "V", 1, &dir,
        )
        .unwrap_err();
        assert!(e.to_string().contains("refused to sign"), "{e}");
        // Zero exit but no cert file refuses too (never an empty cert).
        let e = sign(
            std::path::Path::new("/bin/true"),
            std::path::Path::new("/ca"),
            key, "boxA", "daemon", "V", 1, &dir,
        )
        .unwrap_err();
        assert!(e.to_string().contains("wrote no cert"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
