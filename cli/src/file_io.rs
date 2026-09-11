//! Owner-only files, the pidfile, and the small duration/ttl/invitation parsers.
//!
//! The file half: reading and writing owner-only files (both the path and the
//! file-descriptor forms), and the daemon pidfile writers. The parser half: the
//! duration and ttl parsers and the invitation parser, which are small and pure.
//!
//! TEN blocks, because write_owner_only_fd and read_owner_only_fd are cfg PAIRS --
//! a unix implementation and a not(unix) counterpart each. Both halves travel
//! together, and since the pairs cover every target the names exist everywhere, so
//! their imports and re-exports are UNGATED. Only two crate-root names are needed
//! (devices_path and the ephemeral module); no dependency has a lone gate.
use crate::devices_store::devices_path;
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) fn pidfile() -> PathBuf {
    devices_path().with_file_name("up.pid")
}

/// Record the daemon's identity beside its pid. A pid alone can be recycled and
/// a name substring can lie, so the pidfile carries the executable path the
/// daemon started from; `daemon_alive` confirms it against the live process.
pub(crate) fn write_pidfile() -> Result<()> {
    let pid = std::process::id();
    let exe = std::env::current_exe()?;
    std::fs::write(pidfile(), format!("{pid}\n{}\n", exe.display()))?;
    Ok(())
}

pub(crate) fn write_owner_only_file(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create owner-only file {}", path.display()))?;
    writeln!(file, "{contents}")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn write_owner_only_fd(fd: i32, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    if fd < 0 {
        bail!("secret file descriptor must be non-negative");
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    writeln!(file, "{contents}")?;
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_owner_only_fd(_fd: i32, _contents: &str) -> Result<()> {
    bail!(
        "file-descriptor secret output is not yet implemented on this platform; use a new owner-only file"
    )
}

#[cfg(unix)]
pub(crate) fn read_owner_only_fd(fd: i32) -> Result<String> {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    if fd < 0 {
        bail!("secret file descriptor must be non-negative");
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

#[cfg(not(unix))]
pub(crate) fn read_owner_only_fd(_fd: i32) -> Result<String> {
    bail!(
        "file-descriptor secret input is not yet implemented on this platform; use an owner-only file"
    )
}

pub(crate) fn parse_duration_secs(input: &str) -> Result<u64> {
    let (number, unit) = input.trim().split_at(input.trim().len().saturating_sub(1));
    let value: u64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{input}'"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid duration '{input}', use e.g. 30m, 1h, or 1d"),
    };
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("duration too large"))?;
    if seconds == 0 {
        bail!("duration must be greater than zero");
    }
    Ok(seconds)
}

/// CLI handler for `filament ephemeral`
pub(crate) fn parse_mint_ttl(raw: &str) -> Result<u64> {
    let raw = raw.trim().to_ascii_lowercase();
    let (number, unit) = raw.split_at(
        raw.trim_end_matches(|c: char| c.is_ascii_alphabetic())
            .len(),
    );
    let value: u64 = number
        .parse()
        .map_err(|_| anyhow!("invalid --ttl '{raw}'"))?;
    let multiplier = match unit {
        // A bare number is seconds. `ephemeral mint --ttl` was a raw u64 before
        // the mint verbs were collapsed, and its default is still "86400", so
        // dropping this arm would break every script that passes a number.
        "" => 1,
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid --ttl '{raw}', use a duration such as 15m or 1h (or plain seconds)"),
    };
    Ok(value.saturating_mul(multiplier))
}

pub(crate) fn parse_invitation(raw: &str) -> Result<crate::ephemeral::Invitation> {
    use base64::Engine;
    let token = raw.trim();
    let encoded = token
        .strip_prefix("filament-invite:")
        .ok_or_else(|| anyhow!("invitation has an unknown format"))?;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow!("invitation is not valid base64url"))?,
    );
    crate::ephemeral::Invitation::from_token(bytes.as_slice())
        .ok_or_else(|| anyhow!("invitation payload is not a valid v2 invitation"))
}
