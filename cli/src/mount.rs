use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::io::IsTerminal;

const MOUNTS_FILE: &str = "mounts.json";

fn mounts_path() -> PathBuf {
    crate::settings::config_dir().join(MOUNTS_FILE)
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct MountProfile {
    name: String,
    mounts: Vec<ProfileMount>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct ProfileMount {
    peer: String,
    remote: String,
    local: String,
    read_only: bool,
    auto_restore: bool,
}

fn profiles_dir() -> PathBuf {
    crate::settings::config_dir().join("mount-profiles")
}

fn load_profile(name: &str) -> Result<MountProfile> {
    let path = profiles_dir().join(format!("{name}.json"));
    let data = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&data)?)
}

fn save_profile(profile: &MountProfile) -> Result<()> {
    std::fs::create_dir_all(profiles_dir())?;
    let path = profiles_dir().join(format!("{}.json", profile.name));
    let data = serde_json::to_string_pretty(profile)?;
    // Atomic write: temp file + rename (prevents truncation on ENOSPC/crash)
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn list_profiles() -> Result<Vec<String>> {
    let dir = profiles_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    Ok(std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| e.path().file_stem().map(|s| s.to_string_lossy().into_owned()))
        .collect())
}

fn delete_profile(name: &str) -> Result<()> {
    let path = profiles_dir().join(format!("{name}.json"));
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

fn generate_mount_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 4];
    // Use /dev/urandom for true randomness.
    let _ = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf));
    let val = u32::from_ne_bytes(buf);
    format!("{:06x}", val & 0xffffff)
}

pub(crate) fn unique_mount_id() -> String {
    let mounts = load_mounts();
    loop {
        let id = generate_mount_id();
        if !mounts.iter().any(|m| m.id == id) {
            return id;
        }
    }
}

fn default_auto_restore() -> bool {
    false
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub(crate) struct MountEntry {
    pub(crate) id: String,
    pub(crate) parent_id: Option<String>,
    pub(crate) local: String,
    pub(crate) peer: String,
    pub(crate) remote: String,
    pub(crate) pid: u32,
    pub(crate) read_only: bool,
    #[serde(default = "default_auto_restore")]
    pub(crate) auto_restore: bool,
    pub(crate) created: String,
}

fn load_mounts() -> Vec<MountEntry> {
    let path = mounts_path();
    let Ok(data) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

fn save_mounts(mounts: &[MountEntry]) -> Result<()> {
    let path = mounts_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(mounts)?;
    std::fs::write(&path, data)?;
    Ok(())
}

pub(crate) fn add_mount(entry: MountEntry) -> Result<()> {
    let mut mounts = load_mounts();
    // Remove any stale entry for the same local path.
    mounts.retain(|m| m.local != entry.local);
    mounts.push(entry);
    save_mounts(&mounts)
}

pub(crate) fn remove_mount(local: &str) -> Result<()> {
    let mut mounts = load_mounts();
    mounts.retain(|m| m.local != local);
    save_mounts(&mounts)
}

pub(crate) fn find_parent_mount(local: &str) -> Option<String> {
    let mounts = load_mounts();
    mounts.iter()
        .filter(|m| local.starts_with(&m.local) && m.local != local && is_mount_alive(m))
        .max_by_key(|m| m.local.len())
        .map(|m| m.id.clone())
}

fn find_child_mounts(parent_id: &str) -> Vec<MountEntry> {
    load_mounts().into_iter()
        .filter(|m| m.parent_id.as_deref() == Some(parent_id))
        .collect()
}

fn is_mount_alive(entry: &MountEntry) -> bool {
    // Check if the mount point is still active via /proc/mounts.
    is_mount_point(&entry.local)
}

fn check_mount_health(entry: &MountEntry) -> MountStatus {
    if !Path::new(&entry.local).exists() {
        return MountStatus::Missing;
    }
    if !is_mount_alive(entry) {
        return MountStatus::Dead;
    }
    // Try to stat a file to check if mount is responsive.
    match std::fs::metadata(&entry.local) {
        Ok(_) => MountStatus::Healthy,
        Err(_) => MountStatus::Stale,
    }
}

#[derive(PartialEq)]
enum MountStatus {
    Healthy,
    Stale,
    Dead,
    Missing,
}

impl std::fmt::Display for MountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountStatus::Healthy => write!(f, "healthy"),
            MountStatus::Stale => write!(f, "stale (unresponsive)"),
            MountStatus::Dead => write!(f, "dead (process gone)"),
            MountStatus::Missing => write!(f, "missing (mount point gone)"),
        }
    }
}

/// Removes a mount-point directory we created if the mount never succeeds, so a
/// failed `filament mount` doesn't litter empty dirs (e.g. the peer has no sshd).
/// A failed mount leaves the dir empty, so `remove_dir` (empty-only) is safe: a
/// live/successful mount makes it non-empty and the removal simply no-ops. Only
/// dirs WE created are tracked, so a pre-existing dir is never touched.
struct MountPointGuard {
    path: String,
    active: bool,
}

impl MountPointGuard {
    fn disarm(&mut self) {
        self.active = false;
    }
    fn cleanup_now(&mut self) {
        if self.active {
            let _ = std::fs::remove_dir(&self.path);
            self.active = false;
        }
    }
}

impl Drop for MountPointGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

pub async fn mount_cmd(
    server: &str,
    peer: &str,
    remote: &str,
    local: Option<String>,
    read_only: bool,
    extra_opts: Option<String>,
    relay: bool,
    foreground: bool,
    auto_restore: bool,
) -> Result<()> {
    // For tilde paths, we need to resolve them on the remote side.
    // sshfs doesn't expand ~ when using ProxyCommand, so we'll use the
    // ssh:// syntax which handles path expansion properly.
    let remote_path = remote.to_string();
    
    let local_path = match local {
        Some(p) => p,
        None => {
            // For ~ paths, use the basename after ~/
            if remote_path.starts_with("~/") {
                remote_path[2..].to_string()
            } else {
                Path::new(&remote_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| peer.to_string())
            }
        }
    };

    // Track the mount point so a failed mount (e.g. the peer has no sshd) doesn't
    // leave an empty dir behind. Only dirs WE create are tracked; disarmed on any
    // success path.
    let mut mp_guard = if !Path::new(&local_path).exists() {
        std::fs::create_dir_all(&local_path)?;
        crate::ui::say(&format!("created mount point: {local_path}"));
        Some(MountPointGuard { path: local_path.clone(), active: true })
    } else {
        None
    };

    // Try daemon first (daemon handles sshfs spawn + monitoring centrally).
    #[cfg(unix)]
    if !foreground && crate::ctl::daemon_present().await {
        let port: u16 = std::env::var("FILAMENT_SSH_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(22);
        if let Some(_reply) = crate::ctl::try_mount(peer, &remote_path, &local_path, read_only, auto_restore, port).await {
            if let Some(g) = mp_guard.as_mut() { g.disarm(); }
            crate::ui::say(&format!("mounted {peer}:{remote_path} at {local_path} (daemon-managed)"));
            crate::ui::say(&format!("  check with: filament mount --check {local_path}"));
            crate::ui::say(&format!("  unmount with: filament mount --off {local_path}"));
            return Ok(());
        }
        // Daemon not available or mount failed, fall through to direct spawn.
    }

    if std::process::Command::new("which")
        .arg("sshfs")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        if let Some(g) = mp_guard.as_mut() { g.cleanup_now(); }
        crate::ui::problem(
            "sshfs not found",
            "sshfs is required for `filament mount` but is not installed.",
            &[
                "apt install sshfs          # Debian/Ubuntu".to_string(),
                "brew install sshfs         # macOS (via macFUSE)".to_string(),
                "pacman -S sshfs            # Arch".to_string(),
            ],
        );
        std::process::exit(1);
    }

    // `mount` currently rides sshfs, so it needs a real sshd on the peer, unlike
    // `pty`. If bootstrap fails (typically "no sshd"), say so honestly and point
    // at the paths that work today. (Guard drops here and removes the empty dir.)
    let info = match crate::l2::ensure_peer_bootstrap(server, peer, relay).await {
        Ok(i) => i,
        Err(e) => {
            crate::ui::say(&format!(
                "  note: `filament mount` currently rides sshfs and needs an sshd on '{peer}'. \
                 A no-sshd mesh-native mount is in progress; for now run an sshd there, set \
                 FILAMENT_SSH_PORT, or use `filament shell {peer}` for a shell."
            ));
            return Err(e);
        }
    };
    let peer_name = peer.strip_suffix(".mesh").unwrap_or(peer);

    // Build the sshfs command.
    let build_sshfs = |info: &crate::l2::PeerSshInfo, use_l3: bool| -> std::process::Command {
        let mut cmd = std::process::Command::new("sshfs");
        cmd.arg("-o").arg(format!("IdentityFile={}", info.key_path.display()));
        cmd.arg("-o").arg("IdentitiesOnly=yes");
        cmd.arg("-o").arg(format!("UserKnownHostsFile={}", info.known_hosts_path.display()));
        cmd.arg("-o").arg("GlobalKnownHostsFile=/dev/null");
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
        cmd.arg("-o").arg("ConnectTimeout=10");
        cmd.arg("-o").arg("ServerAliveInterval=15");
        cmd.arg("-o").arg("ServerAliveCountMax=4");

        if use_l3 {
            if let Some(dest) = crate::l2::l3_dest(info) {
                cmd.arg(format!("{dest}:{remote_path}"));
                return cmd;
            }
        }

        // L2 fallback.
        let exe = std::env::current_exe().unwrap();
        let exe = exe.to_string_lossy();
        let mut proxy = format!("{exe} --server {server}");
        if relay {
            proxy.push_str(" --relay");
        }
        proxy.push_str(&format!(" forward {peer_name}:{} --stdio", info.rport));
        cmd.arg("-o").arg(format!("ProxyCommand={proxy}"));
        let dest_token = format!("{}@{}", info.login, info.host);
        cmd.arg(format!("{dest_token}:{remote_path}"));
        cmd
    };

    let mut cmd = build_sshfs(&info, true);
    cmd.arg(&local_path);
    if read_only {
        cmd.arg("-o").arg("ro");
    }
    if let Some(opts) = &extra_opts {
        for opt in opts.split(',') {
            cmd.arg("-o").arg(opt.trim());
        }
    }

    // In foreground mode, run sshfs and wait. In background mode, spawn and track.
    if foreground {
        let status = cmd.status();
        match status {
            Ok(s) if s.success() => {
                if let Some(g) = mp_guard.as_mut() { g.disarm(); }
                crate::ui::say(&format!("mounted {peer}:{remote_path} at {local_path}"));
                crate::ui::say(&format!("  unmount with: filament mount --off {local_path}"));
                Ok(())
            }
            Ok(s) => {
                let code = s.code().unwrap_or(1);
                if code == 255 && info.took_fast_path {
                    crate::ui::say(&format!("filament: re-authenticating with '{peer}'..."));
                    let retry = crate::l2::rebootstrap_peer(server, peer, relay, false).await?;
                    let mut cmd = build_sshfs(&retry, true);
                    cmd.arg(&local_path);
                    if read_only { cmd.arg("-o").arg("ro"); }
                    if let Some(opts) = &extra_opts {
                        for opt in opts.split(',') { cmd.arg("-o").arg(opt.trim()); }
                    }
                    let s = cmd.status()?;
                    std::process::exit(s.code().unwrap_or(1));
                }
                bail!("sshfs exited with code {code}");
            }
            Err(e) => bail!("failed to run sshfs: {e}"),
        }
    } else {
        // Background mode: spawn sshfs, record PID, start monitor.
        let child = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        let pid = child.id();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mount_id = unique_mount_id();

        let parent_id = find_parent_mount(&local_path);

        add_mount(MountEntry {
            id: mount_id.clone(),
            parent_id,
            local: local_path.clone(),
            peer: peer_name.to_string(),
            remote: remote_path.clone(),
            pid,
            read_only,
            auto_restore,
            created: now,
        })?;

        if let Some(g) = mp_guard.as_mut() { g.disarm(); }
        crate::ui::say(&format!("mounted {peer}:{remote_path} at {local_path} (id: {mount_id})"));
        crate::ui::say(&format!("  check with: filament mount --check {mount_id}"));
        crate::ui::say(&format!("  unmount with: filament mount --off {local_path}"));

        // Spawn monitor thread (not tokio, because we use std::process::Command).
        let monitor_local = local_path.clone();
        let monitor_peer = peer_name.to_string();
        let monitor_remote = remote_path.clone();
        let monitor_server = server.to_string();
        std::thread::spawn(move || {
            monitor_mount(monitor_local, monitor_peer, monitor_remote, monitor_server, relay);
        });

        Ok(())
    }
}

fn monitor_mount(local: String, peer: String, remote: String, _server: String, _relay: bool) {
    let check_interval = std::time::Duration::from_secs(30);
    let mut consecutive_failures = 0u32;

    loop {
        std::thread::sleep(check_interval);

        let mounts = load_mounts();
        let entry = match mounts.iter().find(|m| m.local == local) {
            Some(e) => e.clone(),
            None => return, // Mount was removed.
        };

        let status = check_mount_health(&entry);
        match status {
            MountStatus::Healthy => {
                consecutive_failures = 0;
            }
            MountStatus::Stale | MountStatus::Dead => {
                consecutive_failures += 1;
                if consecutive_failures >= 3 {
                    crate::ui::say(&format!(
                        "mount {local} is {status}, run `filament mount --check {local}` for details"
                    ));
                    crate::ui::say(&format!(
                        "  to recover: filament mount --off {local} && filament mount {peer} {remote} {local}"
                    ));
                    let _ = remove_mount(&local);
                    return;
                }
            }
            MountStatus::Missing => {
                crate::ui::say(&format!("mount {local} point gone, removing tracking"));
                let _ = remove_mount(&local);
                return;
            }
        }
    }
}

pub fn list_cmd() -> Result<()> {
    let mounts = load_mounts();
    if mounts.is_empty() {
        crate::ui::say("no active filament mounts");
        return Ok(());
    }

    let is_tty = std::io::stdout().is_terminal();
    let mut healthy = 0;
    let mut unhealthy = 0;

    for entry in &mounts {
        let status = check_mount_health(entry);
        let status_str = status.to_string();
        let is_ok = status == MountStatus::Healthy;
        if is_ok { healthy += 1; } else { unhealthy += 1; }

        if is_tty {
            let color = if is_ok { "\x1b[32m" } else { "\x1b[31m" };
            let reset = "\x1b[0m";
            println!(
                "{color}{}{reset}  {color}{}{reset}  {}:{} -> {}",
                status_str, entry.id, entry.peer, entry.remote, entry.local
            );
        } else {
            println!(
                "{} {} {}:{} -> {}",
                status_str, entry.id, entry.peer, entry.remote, entry.local
            );
        }
    }

    if is_tty {
        println!("\n{healthy} healthy, {unhealthy} unhealthy, {} total", mounts.len());
        println!("unmount with: filament mount --off <path>");
    }

    Ok(())
}

pub async fn restore_mounts(server: &str, relay: bool) -> Result<()> {
    let mounts = load_mounts();
    let mut restored = 0;
    for entry in mounts {
        if !entry.auto_restore {
            continue;
        }
        if is_mount_alive(&entry) {
            continue;
        }
        crate::ui::say(&format!("restoring mount {}:{} at {}", entry.peer, entry.remote, entry.local));
        if let Err(e) = mount_cmd(server, &entry.peer, &entry.remote, Some(entry.local.clone()), entry.read_only, None, relay, false, entry.auto_restore).await {
            crate::ui::say(&format!("warning: failed to restore {}: {}", entry.local, e));
        } else {
            restored += 1;
        }
    }
    if restored > 0 {
        crate::ui::say(&format!("restored {} mount(s)", restored));
    }
    Ok(())
}

pub fn check_cmd(target: &str) -> Result<()> {
    let mounts = load_mounts();
    // Try to find by ID first, then by path.
    let entry = mounts.iter().find(|m| m.id == target || m.local == target);

    match entry {
        None => {
            // Not tracked, but check if it's a live mount anyway.
            if is_mount_point(target) {
                crate::ui::say(&format!("{target} is a mount point but not tracked by filament"));
                Ok(())
            } else {
                bail!("{target} is not a filament mount (use `filament mount --list` to see active mounts)");
            }
        }
        Some(entry) => {
            let status = check_mount_health(entry);
            let is_tty = std::io::stdout().is_terminal();

            if is_tty {
                let (color, label) = match status {
                    MountStatus::Healthy => ("\x1b[32m", "HEALTHY"),
                    _ => ("\x1b[31m", "UNHEALTHY"),
                };
                let reset = "\x1b[0m";
                println!("{color}[{label}]{reset} {} ({})", entry.id, entry.local);
                println!("  peer:   {}:{}", entry.peer, entry.remote);
                println!("  status: {status}");
                println!("  since:  {}", entry.created);
            } else {
                println!("{} {} {}:{} created={}", status, entry.id, entry.peer, entry.remote, entry.created);
            }

            if status != MountStatus::Healthy {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

pub(crate) fn is_mount_point(path: &str) -> bool {
    // Check /proc/mounts for FUSE mounts.
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            if line.contains("fuse.sshfs") && line.contains(path) {
                return true;
            }
        }
    }
    false
}

pub fn unmount_cmd(target: &str) -> Result<()> {
    let mounts = load_mounts();

    // Try to find by ID first, then by path.
    let entry = mounts.iter().find(|m| m.id == target || m.local == target);

    match entry {
        Some(entry) => {
            // Recursively unmount children first.
            let children = find_child_mounts(&entry.id);
            for child in children {
                if let Err(e) = unmount_cmd(&child.local) {
                    crate::ui::say(&format!("warning: failed to unmount child {}: {}", child.local, e));
                }
            }

            let path = &entry.local;
            // Try fusermount first.
            let status = std::process::Command::new("fusermount")
                .arg("-u")
                .arg(path)
                .status();

            match status {
                Ok(s) if s.success() => {
                    let _ = remove_mount(path);
                    crate::ui::say(&format!("unmounted {path} (id: {})", entry.id));
                    Ok(())
                }
                _ => {
                    let status = std::process::Command::new("umount").arg(path).status()?;
                    if status.success() {
                        let _ = remove_mount(path);
                        crate::ui::say(&format!("unmounted {path} (id: {})", entry.id));
                        Ok(())
                    } else {
                        // Still remove tracking even if unmount fails.
                        let _ = remove_mount(path);
                        bail!("failed to unmount {path}, but tracking removed");
                    }
                }
            }
        }
        None => {
            // Not tracked - try as a direct path.
            if Path::new(target).exists() {
                let status = std::process::Command::new("fusermount")
                    .arg("-u")
                    .arg(target)
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        crate::ui::say(&format!("unmounted {target}"));
                        Ok(())
                    }
                    _ => {
                        let status = std::process::Command::new("umount").arg(target).status()?;
                        if status.success() {
                            crate::ui::say(&format!("unmounted {target}"));
                            Ok(())
                        } else {
                            bail!("failed to unmount {target}");
                        }
                    }
                }
            } else {
                bail!("no mount found for '{target}' (use `filament mount --list` to see active mounts)");
            }
        }
    }
}

pub async fn unmount_cmd_async(target: &str) -> Result<()> {
    let mounts = load_mounts();

    let entry = mounts.iter().find(|m| m.id == target || m.local == target);

    #[cfg(unix)]
    {
        if crate::ctl::daemon_present().await {
            if let Some(_reply) = crate::ctl::try_unmount(target).await {
                crate::ui::say(&format!("unmounted {target} (daemon-managed)"));
                return Ok(());
            }
        }
    }

    match entry {
        Some(entry) => {
            let children = find_child_mounts(&entry.id);
            for child in children {
                if let Err(e) = Box::pin(unmount_cmd_async(&child.local)).await {
                    crate::ui::say(&format!("warning: failed to unmount child {}: {}", child.local, e));
                }
            }

            let path = &entry.local;
            let status = tokio::process::Command::new("fusermount")
                .arg("-u")
                .arg(path)
                .status()
                .await;

            match status {
                Ok(s) if s.success() => {
                    let _ = remove_mount(path);
                    crate::ui::say(&format!("unmounted {path} (id: {})", entry.id));
                    Ok(())
                }
                _ => {
                    let status = tokio::process::Command::new("umount")
                        .arg(path)
                        .status()
                        .await?;
                    if status.success() {
                        let _ = remove_mount(path);
                        crate::ui::say(&format!("unmounted {path} (id: {})", entry.id));
                        Ok(())
                    } else {
                        let _ = remove_mount(path);
                        bail!("failed to unmount {path}, but tracking removed");
                    }
                }
            }
        }
        None => {
            if Path::new(target).exists() {
                let status = tokio::process::Command::new("fusermount")
                    .arg("-u")
                    .arg(target)
                    .status()
                    .await;
                match status {
                    Ok(s) if s.success() => {
                        crate::ui::say(&format!("unmounted {target}"));
                        Ok(())
                    }
                    _ => {
                        let status = tokio::process::Command::new("umount")
                            .arg(target)
                            .status()
                            .await?;
                        if status.success() {
                            crate::ui::say(&format!("unmounted {target}"));
                            Ok(())
                        } else {
                            bail!("failed to unmount {target}");
                        }
                    }
                }
            } else {
                bail!("no mount found for '{target}' (use `filament mount --list` to see active mounts)");
            }
        }
    }
}

pub fn save_profile_cmd(name: &str) -> Result<()> {
    let mounts = load_mounts();
    let profile = MountProfile {
        name: name.to_string(),
        mounts: mounts.iter().map(|m| ProfileMount {
            peer: m.peer.clone(),
            remote: m.remote.clone(),
            local: m.local.clone(),
            read_only: m.read_only,
            auto_restore: m.auto_restore,
        }).collect(),
    };
    save_profile(&profile)?;
    crate::ui::say(&format!("saved profile '{}' with {} mount(s)", name, profile.mounts.len()));
    Ok(())
}

pub async fn apply_profile_cmd(name: &str, server: &str, relay: bool) -> Result<()> {
    let profile = load_profile(name)?;
    crate::ui::say(&format!("applying profile '{}' ({} mount(s))", name, profile.mounts.len()));
    for pm in &profile.mounts {
        mount_cmd(server, &pm.peer, &pm.remote, Some(pm.local.clone()),
                 pm.read_only, None, relay, false, pm.auto_restore).await?;
    }
    Ok(())
}

pub fn profiles_cmd() -> Result<()> {
    let profiles = list_profiles()?;
    if profiles.is_empty() {
        crate::ui::say("no saved profiles");
        return Ok(());
    }
    for name in &profiles {
        let profile = load_profile(name)?;
        println!("{}: {} mount(s)", name, profile.mounts.len());
    }
    Ok(())
}

pub fn delete_profile_cmd(name: &str) -> Result<()> {
    delete_profile(name)?;
    crate::ui::say(&format!("deleted profile '{name}'"));
    Ok(())
}

pub fn print_mount_help() {
    println!("filament mount - mount remote directories over the mesh");
    println!();
    println!("USAGE:");
    println!("  filament mount <peer> <remote-path> [local-path]   Mount a remote directory");
    println!("  filament mount --list                              List active mounts");
    println!("  filament mount --check <id|path>                   Check mount health");
    println!("  filament mount --save <name>                       Save current mounts as profile");
    println!("  filament mount --apply <name>                      Apply a saved profile");
    println!("  filament mount --profiles                          List saved profiles");
    println!();
    println!("OPTIONS:");
    println!("  --read-only                  Mount read-only");
    println!("  --foreground                 Run sshfs in foreground (blocks terminal)");
    println!("  --save-auto                  Auto-restore this mount on daemon start");
    println!("  --options <opts>             Extra sshfs options (comma-separated)");
    println!();
    println!("EXAMPLES:");
    println!("  filament mount other-do /data /mnt/data");
    println!("  filament mount other-do /data /mnt/data --read-only");
    println!("  filament mount other-do /data --save-auto");
    println!("  filament mount --list");
    println!("  filament mount --check abc123");
    println!("  filament mount --save work");
    println!("  filament mount --apply work");
}

// ---- Fancy interactive UI with arrow selection and type-to-filter ----

fn render_mount_ui(
    header: &str,
    items: &[(String, String)],  // (display_name, item_type)
    sel: usize,
    filter: &str,
    filter_active: bool,
    prev_lines: usize,
) -> usize {
    use std::io::Write;
    let mut out = std::io::stderr();
    let color = crate::ui::caps().color;

    // Move up to redraw previous content
    if prev_lines > 0 {
        let _ = write!(out, "\x1b[{}A", prev_lines);
    }

    // Header
    let _ = write!(out, "\r\x1b[2K{header}\r\n");

    // Filter line
    if filter_active {
        let _ = write!(out, "\r\x1b[2K  \x1b[33m>\x1b[0m {filter}\x1b[37m_\x1b[0m\r\n");
    } else {
        let _ = write!(out, "\r\x1b[2K\r\n");
    }

    // Items
    if items.is_empty() {
        let _ = write!(out, "\r\x1b[2K  \x1b[2m(no matches)\x1b[0m\r\n");
    } else {
        for (i, (name, _item_type)) in items.iter().enumerate() {
            let (mark, c, r) = if i == sel {
                if color {
                    ("\u{276f}", "\x1b[1;36m", "\x1b[0m")
                } else {
                    (">", "", "")
                }
            } else {
                (" ", "", "")
            };
            let _ = write!(out, "\r\x1b[2K  {c}{mark} {}{r}\r\n", name);
        }
    }

    // Blank line
    let _ = write!(out, "\r\x1b[2K\r\n");

    let _ = out.flush();

    // Return current line count for next redraw
    items.len() + 3  // header + filter + items + blank
}

fn filter_items(items: &[(String, String)], filter: &str) -> Vec<(usize, String, String)> {
    if filter.is_empty() {
        return items.iter().enumerate().map(|(i, (n, t))| (i, n.clone(), t.clone())).collect();
    }
    let lower = filter.to_lowercase();
    items.iter()
        .enumerate()
        .filter(|(_, (name, _))| name.to_lowercase().contains(&lower))
        .map(|(i, (n, t))| (i, n.clone(), t.clone()))
        .collect()
}

pub async fn interactive_mount_fancy(server: &str, relay: bool) -> Result<()> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use std::io::Write;

    let _guard = crate::codeentry::RawGuard::enable()?;

    // Collect all items: devices + profiles + current mounts
    let mut items: Vec<(String, String)> = Vec::new();  // (display_name, type)

    // Add available devices
    let devices = crate::devices_load();
    for (name, _) in &devices {
        items.push((name.clone(), "device".to_string()));
    }

    // Add saved profiles
    if let Ok(profiles) = list_profiles() {
        for name in &profiles {
            items.push((name.clone(), "profile".to_string()));
        }
    }

    // Add active mounts (filter out dead/missing)
    let mounts = load_mounts();
    for entry in &mounts {
        let status = check_mount_health(entry);
        if status == MountStatus::Dead || status == MountStatus::Missing {
            continue;  // Skip dead/missing mounts
        }
        let status_str = if status == MountStatus::Healthy { "ok" } else { "err" };
        items.push((
            format!("{}:{} -> {} [{}]", entry.peer, entry.remote, entry.local, status_str),
            "mount".to_string(),
        ));
    }

    if items.is_empty() {
        drop(_guard);
        println!("\x1b[33mNo devices paired and no mounts configured.\x1b[0m");
        println!("Add a device first: filament add");
        return Ok(());
    }

    let header = "  \x1b[2mMount from device, profile, or manage mount (up/down, enter, esc)\x1b[0m";
    let mut sel = 0usize;
    let mut filter = String::new();
    let mut filter_active = false;
    let mut prev_lines = 0usize;

    loop {
        let filtered = filter_items(&items, &filter);

        // Clamp selection
        if !filtered.is_empty() && sel >= filtered.len() {
            sel = filtered.len() - 1;
        }

        // Render
        let display: Vec<(String, String)> = filtered.iter().map(|(_, n, t)| (n.clone(), t.clone())).collect();
        prev_lines = render_mount_ui(header, &display, sel, &filter, filter_active, prev_lines);

        // Read event
        let ev = event::read()?;
        let Event::Key(k) = ev else { continue };
        if k.kind == KeyEventKind::Release {
            continue;
        }

        match k.code {
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                drop(_guard);
                println!("\r\x1b[2K\x1b[2mCancelled.\x1b[0m");
                return Ok(());
            }
            KeyCode::Esc => {
                if filter_active {
                    filter.clear();
                    filter_active = false;
                    sel = 0;
                } else {
                    drop(_guard);
                    println!("\r\x1b[2K\x1b[2mCancelled.\x1b[0m");
                    return Ok(());
                }
            }
            KeyCode::Enter => {
                if filtered.is_empty() {
                    continue;
                }
                let (_, name, item_type) = &filtered[sel];
                let name = name.clone();
                let item_type = item_type.clone();
                drop(_guard);

                if item_type == "device" {
                    println!();
                    print!("  Remote path on \x1b[1m{name}\x1b[0m: ");
                    std::io::stdout().flush()?;
                    let mut remote = String::new();
                    std::io::stdin().read_line(&mut remote)?;
                    let remote = remote.trim().to_string();
                    if remote.is_empty() {
                        bail!("remote path is required");
                    }

                    let default_local = Path::new(&remote)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| name.clone());
                    print!("  Local mount point [\x1b[2m{default_local}\x1b[0m]: ");
                    std::io::stdout().flush()?;
                    let mut local = String::new();
                    std::io::stdin().read_line(&mut local)?;
                    let local = if local.trim().is_empty() { 
                        default_local 
                    } else { 
                        let p = local.trim().to_string();
                        // Convert relative paths to absolute
                        if p.starts_with('/') {
                            p
                        } else {
                            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
                            cwd.join(p).to_string_lossy().into_owned()
                        }
                    };

                    println!();
                    return mount_cmd(server, &name, &remote, Some(local), false, None, relay, false, false).await;
                } else if item_type == "profile" {
                    println!();
                    println!("  \x1b[1mApplying profile: {name}\x1b[0m");
                    return apply_profile_cmd(&name, server, relay).await;
                } else {
                    // Active mount - show info
                    println!();
                    // Find the mount entry
                    if let Some(entry) = mounts.iter().find(|m| name.starts_with(&m.peer)) {
                        println!("  Mount: {}:{} -> {}", entry.peer, entry.remote, entry.local);
                        println!("  \x1b[2mCommands:\x1b[0m");
                        println!("    filament mount --check {}", entry.local);
                        println!("    filament mount --off {}", entry.local);
                    }
                    return Ok(());
                }
            }
            KeyCode::Up | KeyCode::Char('k') if !filter_active => {
                if sel > 0 {
                    sel -= 1;
                } else if !filtered.is_empty() {
                    sel = filtered.len() - 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') if !filter_active => {
                sel = (sel + 1) % filtered.len().max(1);
            }
            KeyCode::Char('/') if !filter_active => {
                filter_active = true;
            }
            KeyCode::Backspace if filter_active => {
                filter.pop();
                if filter.is_empty() {
                    filter_active = false;
                }
                sel = 0;
            }
            KeyCode::Char(c) if filter_active && !k.modifiers.contains(KeyModifiers::CONTROL) => {
                filter.push(c);
                sel = 0;
            }
            _ => {}
        }
    }
}
