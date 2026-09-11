//! The `filament update` command.
//!
//! Checks the release API for a newer `cli-v*` tag (skipping prereleases unless
//! `--beta` or already on one), verifies the download, swaps the binary atomically
//! and re-grants what the platform needs. Moved as one unit, including the nested
//! `key` helper that computes its own paths.
//!
//! Four cfg attributes gate statements inside the body -- the Linux getcap probe,
//! the Windows rename, the unix chmod and the daemon reload -- and all four travel
//! verbatim. No import needs a cfg gate: every crate-root item this uses (ctl,
//! daemon_alive, platform, release_target, sha256_hex, ui) is defined
//! unconditionally, and the unix permission call carries its own function-local
//! `use anyhow::{ Result, anyhow, bail };
use crate::REPO;
use crate::ctl;
use crate::daemon_alive;
use crate::platform;
use crate::release_target;
use crate::sha256_hex;
use crate::ui;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use std::io::Read;
use std::time::Duration;

pub(crate) async fn update_cmd(check_only: bool, beta: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("filament/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Latest cli-v* release via the API (releases/latest may point at a web
    // release tag, so filter explicitly). Prereleases are SKIPPED unless the
    // user opted in (--beta) or is already running a prerelease, a beta tag
    // must never be pushed onto stable users.
    let beta_ok = beta || env!("CARGO_PKG_VERSION").contains('-');
    let releases: Value = client
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases?per_page=20"
        ))
        .send()
        .await?
        .json()
        .await?;
    // semver-aware: never "update" to an older or equal release (betas of
    // the next version outrank the previous release; -pre < its release;
    // beta.2 > beta.1, the prerelease NUMBER counts, found live when
    // `--beta` kept offering beta.1 to beta.2).
    fn key(v: &str) -> (u64, u64, u64, bool, u64) {
        let (core, pre) = v
            .split_once('-')
            .map(|(c, p)| (c, Some(p)))
            .unwrap_or((v, None));
        let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        let pre_num = pre
            .and_then(|p| p.rsplit('.').next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        (
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
            pre.is_none(),
            pre_num,
        )
    }
    // Pick the HIGHEST eligible version, not the first listed, the API's
    // order is not newest-tag-first (observed live: cli-v0.2.0 listed above
    // cli-v0.2.1-beta.1, which made --beta serve stable).
    let latest = releases
        .as_array()
        .and_then(|a| {
            a.iter()
                .filter(|r| {
                    r["tag_name"]
                        .as_str()
                        .is_some_and(|t| t.starts_with("cli-v"))
                        && (beta_ok || !r["prerelease"].as_bool().unwrap_or(false))
                })
                .max_by_key(|r| {
                    key(r["tag_name"]
                        .as_str()
                        .unwrap_or_default()
                        .trim_start_matches("cli-v"))
                })
        })
        .ok_or_else(|| anyhow!("no CLI release found"))?;
    let tag = latest["tag_name"].as_str().unwrap_or_default().to_string();
    let latest_ver = tag.trim_start_matches("cli-v").to_string();
    let current = env!("CARGO_PKG_VERSION");
    if key(&latest_ver) <= key(current) {
        println!("filament {current} is already the latest (released: {latest_ver})");
        return Ok(());
    }
    println!("update available: {current} -> {latest_ver}");
    if check_only {
        return Ok(());
    }

    // Package-manager installs (brew, winget, scoop, cargo) must be updated
    // via their manager, not by writing over the binary.
    let source = platform::InstallSource::detect();
    if source != platform::InstallSource::SelfInstalled {
        let hint = source.upgrade_hint();
        println!("filament was installed via a package manager, update with: {hint}");
        return Ok(());
    }

    let target = release_target()
        .ok_or_else(|| anyhow!("no prebuilt binary for this platform; build from source"))?;
    let (asset, inner) = if cfg!(windows) {
        (format!("filament-{target}.zip"), "filament.exe")
    } else {
        (format!("filament-{target}.tar.gz"), "filament")
    };
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");

    ui::say(&format!("downloading {asset} ..."));
    let bytes = client
        .get(format!("{base}/{asset}"))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let sums = client
        .get(format!("{base}/SHA256SUMS"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let got = sha256_hex(&bytes);
    let expected = sums
        .lines()
        .find(|l| l.contains(&asset))
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| anyhow!("{asset} missing from SHA256SUMS"))?;
    if got != expected {
        bail!("checksum mismatch for {asset}: got {got}, expected {expected}");
    }
    ui::say("checksum ok");

    // Unpack the single binary.
    let new_bin: Vec<u8> = if asset.ends_with(".tar.gz") {
        let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(&bytes[..]));
        let mut ar = tar::Archive::new(gz);
        let mut out = None;
        for entry in ar.entries()? {
            let mut e = entry?;
            if e.path()?.file_name().map(|n| n == inner).unwrap_or(false) {
                let mut v = Vec::new();
                e.read_to_end(&mut v)?;
                out = Some(v);
                break;
            }
        }
        out.ok_or_else(|| anyhow!("{inner} not found in archive"))?
    } else {
        // Windows: unpack the .zip archive. Use the zip crate for a pure-Rust
        // reader (no system dependency on tar/powershell).
        use std::io::Read;
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes))
            .map_err(|e| anyhow!("zip reader: {e}"))?;
        let mut found = None;
        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| anyhow!("zip entry {i}: {e}"))?;
            if entry.name().ends_with(inner) {
                let mut v = Vec::new();
                entry.read_to_end(&mut v)?;
                found = Some(v);
                break;
            }
        }
        found.ok_or_else(|| anyhow!("{inner} not found in zip archive"))?
    };

    // Atomic replace: write staging file next to current exe, then swap.
    let me = std::env::current_exe()?;
    let staging = me.with_extension("update-staging");
    std::fs::write(&staging, &new_bin)?;
    // Preserve any CAP_NET_ADMIN grant across the update (Linux only).
    #[cfg(target_os = "linux")]
    let had_cap = std::process::Command::new("getcap")
        .arg(&me)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("cap_net_admin"))
        .unwrap_or(false);
    // On Unix, rename over the running binary (the kernel keeps the old inode
    // alive for the running process). On Windows, rename the running exe out of
    // the way first (MoveFile on the same volume succeeds even on an in-use .exe),
    // then put the new binary in place. The .old file is cleaned up on next update.
    #[cfg(windows)]
    {
        let old = me.with_extension("old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(&me, &old)
            .with_context(|| format!("renaming {} -> {}", me.display(), old.display()))?;
        std::fs::rename(&staging, &me)
            .with_context(|| format!("installing new {}", me.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&staging, &me).with_context(|| format!("replacing {}", me.display()))?;
    }
    println!("updated to {latest_ver} -> {}", me.display());
    #[cfg(target_os = "linux")]
    if had_cap {
        // Re-grant: directly if root, else via sudo (interactive on a TTY). If it
        // can't, tell the user the one command so L3 isn't silently broken.
        let is_root = unsafe { libc::geteuid() } == 0;
        let ok = if is_root {
            std::process::Command::new("setcap")
                .args(["cap_net_admin+eip"])
                .arg(&me)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            std::process::Command::new("sudo")
                .args(["setcap", "cap_net_admin+eip"])
                .arg(&me)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        if ok {
            println!("re-applied CAP_NET_ADMIN (L3 overlay)");
        } else {
            println!(
                "note: re-grant L3's capability:\n    sudo setcap cap_net_admin+eip {}",
                me.display()
            );
        }
        // A non-root L3 node also needs write on /etc/hosts to publish MagicDNS
        // names; grant the narrow per-file ACL here too so a plain `filament
        // update` is all it takes (no separate `set tun-addr` step). No-op for
        // root or if already granted.
        crate::tun::ensure_hosts_writable();
    }
    // Reload a running daemon onto the new binary with no manual restart. A
    // supervised daemon (systemd) takes the graceful SIGTERM path - which cleanly
    // closes the QUIC links so peers re-establish and L3 recovers - and its
    // supervisor restarts it with fresh ambient caps: no sudo. If it isn't
    // supervised (or predates this op), tell the user to restart it.
    #[cfg(unix)]
    {
        let reloading = matches!(ctl::try_reload().await, Some(ref v) if v["reloading"].as_bool() == Some(true));
        if reloading {
            println!("reloading the daemon onto the new binary (graceful restart, no sudo)");
        } else if daemon_alive().is_some() {
            println!(
                "restart the daemon to run the new binary: `systemctl restart filament` (or `filament down` then `filament up ...`)"
            );
        }
    }
    Ok(())
}
