use std::path::{Path, PathBuf};

use anyhow::Result;

/// Platform-specific paths for the filament CLI.
///
/// Uses the `directories` crate for proper OS placement:
/// - Linux:   `$XDG_CONFIG_HOME/filament` (falls back to `$HOME/.config/filament`)
/// - macOS:   `$HOME/Library/Application Support/filament`
/// - Windows: `%APPDATA%/filament`
///
/// All paths honor `FILAMENT_CONFIG_DIR` as an override (hermetic tests,
/// custom deployments).
pub struct Paths;

impl Paths {
    /// Config directory root.
    ///
    /// On first access, checks for legacy `./.config/filament` (cwd-relative,
    /// the broken Windows fallback when HOME was unset) and migrates contents
    /// to the platform-correct path.
    pub fn config_dir() -> PathBuf {
        if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
            return PathBuf::from(d);
        }
        Self::platform_config_dir()
    }

    fn platform_config_dir() -> PathBuf {
        if let Some(proj) = directories::ProjectDirs::from("", "", "filament") {
            return proj.config_dir().to_path_buf();
        }
        // #184: route through home_dir() (USERPROFILE on Windows) instead of a
        // bare HOME read that falls back to "." on Windows.
        Self::home_dir().join(".config").join("filament")
    }

    /// Resolve a config-relative path (file or subdirectory).
    pub fn config_path(relative: impl AsRef<Path>) -> PathBuf {
        Self::config_dir().join(relative)
    }

    /// Repair permissions on sensitive state left by older releases. This is
    /// intentionally separate from SecretFile::write: an unchanged legacy
    /// file is otherwise never rewritten and never gets its mode repaired.
    ///
    /// #178: this is a MIGRATION, so it runs ONCE per version, stamped in the
    /// config dir. SecretFile applies the owner-only ACL at write time, so
    /// every file this version creates is correct when created; the sweep
    /// exists solely to catch files written by older releases. Without the
    /// stamp it would (on Windows) shell out to icacls for every sensitive
    /// file on every command, adding 150-600ms to `--version`, `--help`, and
    /// everything else. Steady state after the stamp: zero process spawns,
    /// zero stat calls, no message. The stamp is a version number, not a
    /// boolean, so a future migration can bump it and re-run.
    pub fn repair_sensitive_permissions() -> std::io::Result<usize> {
        const MIGRATION_VERSION: u32 = 1;
        let dir = Self::config_dir();
        let stamp = dir.join("permissions-migration");
        let current = std::fs::read_to_string(&stamp)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        if current == Some(MIGRATION_VERSION) {
            return Ok(0);
        }
        let repaired = repair_sensitive_permissions_in(&dir)?;
        // Best-effort stamp: a failure to write it just means the sweep runs
        // once more next time, which is acceptable for a migration.
        let _ = std::fs::write(&stamp, MIGRATION_VERSION.to_string());
        Ok(repaired)
    }

    /// Migrate state from a legacy `$HOME/.config/filament` directory (the
    /// broken Windows fallback when HOME was unset, which resolved relative to
    /// the process cwd). Best-effort, safe to call repeatedly.
    ///
    /// Two guards, both earned:
    /// 1. An explicit FILAMENT_CONFIG_DIR override means the caller knows where
    ///    their config lives; migrating INTO it would copy whatever a
    ///    cwd-relative ".config/filament" resolves to — the production identity
    ///    when the shell's cwd is $HOME (issue #149, a key clone). Never
    ///    migrate under an override.
    /// 2. The legacy location is pinned to home_dir(), not the process cwd.
    ///    "./.config/filament" names a different directory in every process;
    ///    with the default shell cwd of $HOME it was indistinguishable from the
    ///    live production config, which is exactly what let the override case
    ///    clone keys. When HOME is unset, home_dir() falls back to ".", which
    ///    is the original broken-Windows behaviour.
    pub fn migrate_legacy() {
        if std::env::var_os("FILAMENT_CONFIG_DIR").is_some() {
            return;
        }
        let legacy = Self::home_dir().join(".config").join("filament");
        if !legacy.is_dir() {
            return;
        }
        let target = Self::config_dir();
        if target == legacy || target.exists() {
            return;
        }
        let _ = std::fs::create_dir_all(&target);
        if let Ok(entries) = std::fs::read_dir(&legacy) {
            for e in entries.flatten() {
                let dest = target.join(e.file_name());
                let _ = std::fs::copy(e.path(), &dest);
            }
        }
    }

    /// Platform-aware home directory for the current user.
    /// Unix: `$HOME`. Windows: `%USERPROFILE%`. Falls back to `"."` when unset.
    pub fn home_dir() -> PathBuf {
        #[cfg(unix)]
        {
            if let Ok(h) = std::env::var("HOME") {
                if !h.is_empty() {
                    return PathBuf::from(h);
                }
            }
        }
        #[cfg(windows)]
        {
            if let Ok(h) = std::env::var("USERPROFILE") {
                if !h.is_empty() {
                    return PathBuf::from(h);
                }
            }
        }
        PathBuf::from(".")
    }

    /// Platform-aware shell for PTY sessions. Returns `(argv, can_use_user)`.
    ///
    /// Resolution order (first match wins):
    /// 1. `shell_program` (from `--shell-program` flag)
    /// 2. `FILAMENT_SHELL` env var
    /// 3. `filament set shell` config (passed via `shell_config`)
    /// 4. `$SHELL` on Unix / powershell→cmd on Windows
    /// 5. Hardcoded fallback (`/bin/bash` → `/bin/sh` / `cmd.exe`)
    ///
    /// The value is argv-split so it can carry args: `bash -l`, `pwsh -NoLogo`.
    /// On Unix, `shell_user` uses `runuser -l`; on Windows it's unsupported
    /// because running a process as another user requires either elevated
    /// privileges (CreateProcessAsUser) or the target user's credentials
    /// (CreateProcessWithLogonW), both of which have security implications.
    pub fn shell_argv(shell_program: Option<&str>, shell_config: Option<&str>, shell_user: Option<&str>) -> (Vec<String>, bool) {
        let shell = shell_program
            .map(|s| s.to_string())
            .or_else(|| std::env::var("FILAMENT_SHELL").ok().filter(|s| !s.is_empty()))
            .or_else(|| shell_config.map(|s| s.to_string()))
            .unwrap_or_else(|| Self::default_shell());

        let parts: Vec<String> = shell.split_whitespace().map(|s| s.to_string()).collect();
        #[cfg(unix)]
        {
            let argv = match shell_user {
                Some(user) => vec!["runuser".into(), "-l".into(), user.into()],
                None => parts,
            };
            (argv, true)
        }
        #[cfg(windows)]
        {
            (parts, false)
        }
        #[cfg(not(any(unix, windows)))]
        {
            (parts, true)
        }
    }

    fn default_shell() -> String {
        #[cfg(unix)]
        {
            std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
                if Path::new("/bin/bash").exists() { "/bin/bash".into() } else { "/bin/sh".into() }
            })
        }
        #[cfg(windows)]
        {
            if Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe").exists() {
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into()
            } else if Path::new("C:\\Windows\\System32\\cmd.exe").exists() {
                "C:\\Windows\\System32\\cmd.exe".into()
            } else {
                "cmd.exe".into()
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            "/bin/sh".into()
        }
    }
}

fn repair_sensitive_permissions_in(dir: &Path) -> std::io::Result<usize> {
    let mut repaired = 0;
    for name in [
        "caps.json",
        "devices.json",
        "device.id",
        "peerconf",
        "identity.ed25519",
        "overlay.ed25519",
        "diag.jsonl",
    ] {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            repaired += repair_sensitive_dir(&path)?;
        } else if repair_sensitive_file(&path)? {
            repaired += 1;
        }
    }
    Ok(repaired)
}

fn repair_sensitive_dir(dir: &Path) -> std::io::Result<usize> {
    let mut repaired = 0;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(dir)?.permissions().mode() & 0o777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            repaired += 1;
        }
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && repair_sensitive_file(&path)? {
            repaired += 1;
        }
    }
    Ok(repaired)
}

fn repair_sensitive_file(path: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)?.permissions().mode() & 0o777 == 0o600 {
            return Ok(false);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        return Ok(true);
    }
    #[cfg(windows)]
    {
        // Reassert the owner-only ACL on existing files. APPDATA is already
        // user-scoped, but old files may predate the SecretFile writer. This
        // arm of the sweep is only reached by the one-time migration stamp
        // (repair_sensitive_permissions skips the sweep entirely once it has
        // run for this version), so its cost is not on the command hot path.
        SecretFile::restrict(path)?;
        return Ok(true);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(false)
    }
}

// ------------------------------------------------------------ SecretFile --

// The safe restricted-file writer now lives in the standalone `secret-write`
// crate. Re-exported here so existing `crate::platform::SecretFile` call sites
// (identity.rs, sshkeys.rs, capability.rs, main.rs, overlay.rs, settings.rs)
// keep resolving unchanged.
pub use secret_write::SecretFile;

/// Host key-persistence adapter for the standalone `filament-id` crate: it
/// forwards to `secret-write` (owner-only atomic write) and `Paths` (config
/// dir) so identity has no dependency on this platform module. Passed to
/// `identity::UserKey::generate` / `::load` at the CLI's call sites.
pub struct PlatformKeyStore;

impl filament_id::KeyStore for PlatformKeyStore {
    fn write_secret(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        SecretFile::write(path, data)
    }
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }
    fn config_path(&self, relative: &str) -> PathBuf {
        Paths::config_path(relative)
    }
}

// --------------------------------------------------------- DevicesFileLock --

/// An exclusive advisory lock on the `devices.json.lock` sidecar, held for the
/// lifetime of the guard. Coordinates the read-modify-write of `devices.json`
/// across processes (#238): the store itself is written by atomic replace
/// (temp + rename), so a lock on the store inode would be replaced out from
/// under a holder. The sidecar is never replaced.
///
/// Unix: flock(LOCK_EX). Windows: LockFileEx. Other platforms: the file is
/// opened but not locked (filament targets unix + windows).
pub struct DevicesFileLock {
    _file: std::fs::File,
}

impl DevicesFileLock {
    /// Acquire the lock, blocking until it is available.
    pub fn acquire() -> anyhow::Result<Self> {
        Self::acquire_at(&Paths::config_dir().join("devices.json.lock"))
    }

    /// The same exclusive lock on an arbitrary sidecar (the identity mint in
    /// `identity_flow::ensure_user_key_inner` uses `identity.lock`).
    pub fn acquire_at(path: &Path) -> anyhow::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc != 0 {
                return Err(anyhow::anyhow!(
                    "flock {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::LockFileEx;
            let handle = file.as_raw_handle() as HANDLE;
            // Lock the first u32::MAX bytes at offset 0 (a zeroed OVERLAPPED).
            // Blocking (no LOCKFILE_FAIL_IMMEDIATELY).
            let mut overlapped =
                std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
            let ok = unsafe {
                LockFileEx(
                    handle,
                    windows_sys::Win32::Storage::FileSystem::LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    overlapped.as_mut_ptr(),
                )
            };
            if ok == 0 {
                return Err(anyhow::anyhow!(
                    "LockFileEx {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(DevicesFileLock { _file: file })
    }
}

impl Drop for DevicesFileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self._file.as_raw_fd();
            unsafe { libc::flock(fd, libc::LOCK_UN) };
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
            let handle = self._file.as_raw_handle() as HANDLE;
            let mut overlapped =
                std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
            unsafe { UnlockFileEx(handle, 0, u32::MAX, u32::MAX, overlapped.as_mut_ptr()) };
        }
    }
}

// --------------------------------------------------------- ServiceHost --

/// The detected service manager on this platform.
///
/// Supports two install tiers:
/// - **system**: privileged, kernel TUN, autostart at boot (requires admin).
/// - **user**: unprivileged, userspace-only, autostart at logon.
///
/// `filament up --install` tries system first (elevation popup), falls back to
/// user on decline. `--uninstall` removes whatever was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceHost {
    Systemd,
    Launchd,
    WindowsService,
    None,
}

/// Outcome of an install attempt.
pub enum InstallResult {
    /// Privileged system-level service installed.
    System,
    /// User-level autostart installed (admin declined or unavailable).
    User,
}

impl ServiceHost {
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            if Self::has_systemd() { return ServiceHost::Systemd; }
            ServiceHost::None
        }
        #[cfg(target_os = "macos")]
        { ServiceHost::Launchd }
        #[cfg(target_os = "windows")]
        { ServiceHost::WindowsService }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        { ServiceHost::None }
    }

    pub fn supports_install(&self) -> bool {
        !matches!(self, ServiceHost::None)
    }

    pub fn install_instructions(&self) -> &'static str {
        match self {
            ServiceHost::Systemd => "",
            ServiceHost::Launchd => "On macOS, create a LaunchAgent plist in ~/Library/LaunchAgents/ and load it with launchctl.",
            ServiceHost::WindowsService => "On Windows, create a Scheduled Task (trigger: at logon) or register a Service with sc.exe.",
            ServiceHost::None => "No service manager detected. Start filament with `filament up` in a terminal, or configure your init system manually.",
        }
    }

    /// Attempt privileged install (system-level). Returns Ok if the privileged
    /// path completed, Err if elevation was declined or unavailable (caller
    /// should fall back to install_user).
    pub fn install_system(&self, exe: &Path, shell_args: &str) -> Result<InstallResult> {
        // If already elevated (root on unix, admin on Windows), do the actual
        // system install directly. Otherwise, try to elevate.
        if self.is_elevated() {
            self.do_install_system(exe, shell_args)?;
            return Ok(InstallResult::System);
        }
        let elevated = self.try_elevate(exe, shell_args)?;
        if elevated {
            return Ok(InstallResult::System);
        }
        Err(anyhow::anyhow!("elevation declined"))
    }

    fn is_elevated(&self) -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(windows)]
        {
            // #173: this used to return true unconditionally, on the
            // assumption that the only caller was an already-elevated
            // re-launch. It is ALSO the first, non-elevated call, so the UAC
            // re-launch could never run. Query the token elevation state
            // instead.
            unsafe {
                unsafe extern "system" {
                    fn GetCurrentProcess() -> isize;
                    fn OpenProcessToken(h: isize, access: u32, tok: *mut isize) -> i32;
                    fn GetTokenInformation(tok: isize, cls: u32, buf: *mut u8, len: u32, ret: *mut u32) -> i32;
                    fn CloseHandle(h: isize) -> i32;
                }
                const TOKEN_QUERY: u32 = 0x0008;
                const TOKEN_ELEVATION: u32 = 20;
                let mut tok: isize = 0;
                let h = GetCurrentProcess();
                if OpenProcessToken(h, TOKEN_QUERY, &mut tok) == 0 {
                    return false;
                }
                let mut elev: u32 = 0;
                let mut ret: u32 = 0;
                let ok = GetTokenInformation(
                    tok,
                    TOKEN_ELEVATION,
                    (&mut elev as *mut u32).cast::<u8>(),
                    std::mem::size_of::<u32>() as u32,
                    &mut ret,
                );
                CloseHandle(tok);
                ok != 0 && elev != 0
            }
        }
        #[cfg(not(any(unix, windows)))]
        { false }
    }

    fn do_install_system(&self, exe: &Path, shell_args: &str) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            ServiceHost::Systemd => {
                let unit = std::path::Path::new("/etc/systemd/system/filament.service");
                std::fs::write(unit, format!(
                    "[Unit]\nDescription=Filament drop target\nAfter=network-online.target\n\n[Service]\nType=notify\nExecStart={} up{}\nRestart=always\nRestartSec=2\nWatchdogSec=45\n\n[Install]\nWantedBy=multi-user.target\n",
                    exe.display(), shell_args
                ))?;
                let _ = std::process::Command::new("systemctl").args(["daemon-reload"]).status();
                let _ = std::process::Command::new("systemctl").args(["enable", "--now", "filament"]).status();
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // 0.8.5 (rec 4): a machine-wide Windows service cannot work yet.
                // `sc create` registers the exe as an SCM service, but filament
                // is a plain console program with no service protocol, so
                // `sc start` always times out (exit 1053). Until that protocol
                // exists, refuse clearly instead of half-installing. The default
                // per-user autostart (HKCU Run) is unaffected and never reaches
                // this path.
                anyhow::bail!(
                    "a machine-wide Windows service is not supported yet: filament has no service protocol, \
                     so the installed service could never start. The per-user autostart (the default) is \
                     already installed. See #177."
                );
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                let plist = std::path::Path::new("/Library/LaunchDaemons/autumated.filament.plist");
                std::fs::write(plist, format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>autumated.filament</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>up</string>{}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>"#,
                    exe.display(), shell_args
                ))?;
                let _ = std::process::Command::new("launchctl").args(["bootstrap", "system"]).arg(plist).status();
            }
            _ => anyhow::bail!("system install not supported"),
        }
        Ok(())
    }

    /// Install user-level autostart (no elevation needed).
    pub fn install_user(&self, exe: &Path, shell_args: &str) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            ServiceHost::Systemd => {
                install_systemd_user(exe, shell_args)
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // #173: per-user autostart via HKCU Run. No elevation needed:
                // autostarting a user's own file receiver at logon is not an
                // administrative act, and the first-run wizard must not demand
                // UAC for it (matches systemd --user and the LaunchAgent). A
                // machine-wide service is the explicit --install-system path.
                install_run_key(exe, shell_args)
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                install_launch_agent(exe, shell_args)
            }
            _ => Err(anyhow::anyhow!("no service manager detected")),
        }
    }

    /// Uninstall any previously-registered service or autostart.
    pub fn uninstall(&self) {
        match self {
            #[cfg(target_os = "linux")]
            ServiceHost::Systemd => {
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "disable", "--now", "filament"])
                    .status();
                let _ = std::process::Command::new("systemctl")
                    .args(["disable", "--now", "filament"])
                    .status();
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // #173: `sc delete` needs admin; only run it when elevated (the
                // machine-wide service path). The per-user autostart is removed
                // with the HKCU Run entry, which needs no elevation.
                if self.is_elevated() {
                    let _ = std::process::Command::new("sc")
                        .args(["delete", "filament"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
                let _ = std::process::Command::new("reg")
                    .args([
                        "delete",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v", "Filament",
                        "/f",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let _ = std::process::Command::new("schtasks")
                    .args(["/delete", "/tn", "Filament", "/f"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                let _ = std::process::Command::new("launchctl")
                    .args(["bootout", "gui/501/autumated.filament"])
                    .status();
            }
            _ => {}
        }
    }

    /// Try to elevate and re-run ourselves with admin privileges. Returns
    /// true if the elevation dialog was accepted, false if declined.
    fn try_elevate(&self, exe: &Path, shell_args: &str) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let ok = std::process::Command::new("pkexec")
                .arg(exe)
                .args(["--install-system", shell_args])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            return Ok(ok);
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::ffi::OsStrExt;

            unsafe extern "system" {
                fn ShellExecuteExW(pExecInfo: *mut SHELLEXECUTEINFOW) -> i32;
                fn WaitForSingleObject(h: isize, ms: u32) -> u32;
                fn GetExitCodeProcess(h: isize, code: *mut u32) -> i32;
                fn CloseHandle(h: isize) -> i32;
                fn GetLastError() -> u32;
            }

            // SHELLEXECUTEINFOW, fields through hProcess. repr(C) keeps the
            // Windows x64 layout (int nShow is followed by pointer alignment).
            #[repr(C)]
            struct SHELLEXECUTEINFOW {
                cb_size: u32,
                f_mask: u32,
                hwnd: isize,
                lp_verb: *const u16,
                lp_file: *const u16,
                lp_parameters: *const u16,
                lp_directory: *const u16,
                n_show: i32,
                h_inst_app: isize,
                lp_id_list: isize,
                lp_class: *const u16,
                hkey_class: isize,
                dw_hot_key: u32,
                h_icon: isize,
                h_process: isize,
            }

            const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
            const SW_HIDE: i32 = 0;

            let exe_win: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
            let args = format!("--install-system {shell_args}");
            let args_win: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();
            let verb: Vec<u16> = "runas\0".encode_utf16().collect();

            let mut sei = SHELLEXECUTEINFOW {
                cb_size: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                f_mask: SEE_MASK_NOCLOSEPROCESS,
                hwnd: 0,
                lp_verb: verb.as_ptr(),
                lp_file: exe_win.as_ptr(),
                lp_parameters: args_win.as_ptr(),
                lp_directory: std::ptr::null(),
                n_show: SW_HIDE,
                h_inst_app: 0,
                lp_id_list: 0,
                lp_class: std::ptr::null(),
                hkey_class: 0,
                dw_hot_key: 0,
                h_icon: 0,
                h_process: 0,
            };

            let ret = unsafe { ShellExecuteExW(&mut sei) };
            if ret == 0 {
                let code = unsafe { GetLastError() };
                if code == 1223 {
                    // ERROR_CANCELLED — user declined UAC
                    return Ok(false);
                }
                anyhow::bail!("elevation failed to launch: {}", code);
            }
            let h = sei.h_process;
            if h == 0 {
                return Ok(false);
            }
            // #177: wait for the elevated child and read its exit code. The
            // old ShellExecuteW returned the moment the UAC prompt was shown,
            // so the parent claimed "installed as a system service" before the
            // child had even run. A failed install must never print success.
            unsafe {
                WaitForSingleObject(h, 120_000); // generous bound; sc create is fast
                let mut exit_code: u32 = 0;
                GetExitCodeProcess(h, &mut exit_code);
                CloseHandle(h);
                if exit_code == 0 {
                    return Ok(true);
                }
            }
            anyhow::bail!("elevated install failed; the service was not created")
        }
        #[cfg(target_os = "macos")]
        {
            // Escape the exe path and shell_args for the AppleScript do-shell-script
            // double-quote context. The shell_args are our own --shell / --shell-only
            // flags so they are constrained, but we escape defensively anyway.
            let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
            let script = format!(
                "do shell script \"'{}' --install-system {}\" with administrator privileges",
                esc(&exe.display().to_string()),
                esc(shell_args)
            );
            let ok = std::process::Command::new("osascript")
                .args(["-e", &script])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            return Ok(ok);
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        { Ok(false) }
    }

    #[cfg(target_os = "linux")]
    fn has_systemd() -> bool {
        Path::new("/run/systemd/system").is_dir()
    }
}

// ------------------------------------------------- platform installers --

#[cfg(target_os = "linux")]
fn install_systemd_user(exe: &Path, shell_args: &str) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let unit = unit_dir.join("filament.service");
    std::fs::write(&unit, format!(
        "[Unit]\nDescription=Filament drop target (trusted devices only)\nAfter=network-online.target\n\n[Service]\nType=notify\nExecStart={} up{}\nRestart=always\nRestartSec=2\nWatchdogSec=45\n\n[Install]\nWantedBy=default.target\n",
        exe.display(), shell_args
    ))?;
    let ok = std::process::Command::new("systemctl").args(["--user", "daemon-reload"]).status()
        .and_then(|_| std::process::Command::new("systemctl").args(["--user", "enable", "--now", "filament"]).status())
        .map(|s| s.success()).unwrap_or(false);
    if !ok {
        anyhow::bail!("systemctl --user enable --now filament failed; run it manually or check journalctl --user -u filament");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_run_key(exe: &Path, shell_args: &str) -> Result<()> {
    // Per-user autostart via HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
    // Runs as the current user at logon with no elevation. This is the default
    // background receiver on Windows.
    let cmd = format!("\"{}\" up{}", exe.display(), shell_args);
    let out = std::process::Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v", "Filament",
            "/t", "REG_SZ",
            "/d", &cmd,
            "/f",
        ])
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("reg add HKCU Run failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_scheduled_task(exe: &Path, shell_args: &str) -> Result<()> {
    let task_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger/></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Actions><Exec><Command>{}</Command><Arguments>up{}</Arguments></Exec></Actions>
</Task>"#,
        exe.display(), shell_args
    );
    let tmp = std::env::temp_dir().join("filament-task.xml");
    std::fs::write(&tmp, &task_xml)?;
    let out = std::process::Command::new("schtasks")
        .args(["/create", "/tn", "Filament", "/xml", &tmp.to_string_lossy(), "/f"])
        .output()?;
    let _ = std::fs::remove_file(&tmp);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("schtasks failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launch_agent(exe: &Path, shell_args: &str) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(&home).join("Library/LaunchAgents");
    std::fs::create_dir_all(&dir)?;
    let plist = dir.join("autumated.filament.plist");
    std::fs::write(&plist, format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>autumated.filament</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>up</string>{}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>"#,
        exe.display(), shell_args
    ))?;
    let _ = std::process::Command::new("launchctl").args(["bootstrap", "gui/501", &plist.to_string_lossy()]).status();
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn add_firewall_rule(exe: &Path) {
    let _ = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "add", "rule",
            "name=Filament QUIC", "dir=in", "action=allow",
            "protocol=udp",
            "program=", &exe.display().to_string(),
            "enable=yes"])
        .output();
}

/// Spawn `exe` with `args` detached from this process's terminal, its stdout
/// and stderr appended to `log`. One portable operation with two arms, written
/// together: the unix arm detaches with `setsid`, the Windows arm with
/// `CREATE_NO_WINDOW | DETACHED_PROCESS`; both redirect the child's console to
/// the same log file. The caller polls the pidfile itself for "is it up yet"
/// (`daemon_alive` is portable since #204).
///
/// The two arms MUST ship together. #215 was a half-written detach: the
/// Windows arm computed the log path and then discarded it, so `logs`,
/// `up`-follows and `--detach` all dead-ended on a file that never appeared.
pub fn spawn_detached(exe: &Path, args: &[&str], log: &Path) -> Result<std::process::Child> {
    if let Some(parent) = log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::from(log_file.try_clone()?));
    cmd.stderr(std::process::Stdio::from(log_file));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("detached spawn is not supported on this platform");
    }
    Ok(cmd.spawn()?)
}

// --------------------------------------------------- process identity --

/// The absolute path of the executable backing a live process, or `None` when
/// the pid does not name a process we can inspect (a dead or recycled pid).
/// This is the identity check behind `daemon_alive`: a command-line substring
/// can be defeated by renaming the binary, the executable path cannot.
///
/// Linux reads the `/proc/<pid>/exe` symlink, macOS asks libproc for the pid's
/// image path, and Windows asks the kernel for the full image name (there is no
/// /proc on either). The arms must ship together; a missing variant makes
/// `daemon_alive` constant-false on that platform, which is the #204 bug this
/// predicate exists to close for good.
#[cfg(target_os = "linux")]
pub fn process_exe_path(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
}

#[cfg(target_os = "macos")]
pub fn process_exe_path(pid: u32) -> Option<PathBuf> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { proc_pidpath(pid as i32, buf.as_mut_ptr(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    // proc_pidpath may include the NUL terminator in its return count.
    let mut end = (n as usize).min(buf.len());
    if end > 0 && buf[end - 1] == 0 {
        end -= 1;
    }
    String::from_utf8(buf[..end].to_vec()).ok().map(PathBuf::from)
}

#[cfg(target_os = "windows")]
pub fn process_exe_path(pid: u32) -> Option<PathBuf> {
    unsafe {
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
            fn QueryFullProcessImageNameW(h: isize, flags: u32, buf: *mut u16, size: *mut u32) -> i32;
            fn CloseHandle(h: isize) -> i32;
        }
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h == 0 {
            return None;
        }
        let mut buf = [0u16; 512];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        Some(PathBuf::from(path))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn process_exe_path(_pid: u32) -> Option<PathBuf> {
    None
}

// ------------------------------------------------------- InstallSource --

/// How filament was installed. Used to gate `filament update`:
/// package-manager installs must be updated via their manager, not
/// by overwriting the binary directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallSource {
    Homebrew,
    Winget,
    Scoop,
    Cargo,
    /// Installed manually (curl | sh, direct download) or untraceable.
    SelfInstalled,
}

impl InstallSource {
    /// Classify the running binary by its canonical path.
    pub fn detect() -> Self {
        let path = match std::env::current_exe() {
            Ok(p) => match p.canonicalize() {
                Ok(c) => c,
                Err(_) => p,
            },
            Err(_) => return InstallSource::SelfInstalled,
        };
        Self::classify(&path)
    }

    fn classify(path: &Path) -> Self {
        let s = path.to_string_lossy().to_lowercase();
        // Cross-platform package manager fingerprints.
        if s.contains("/cellar/") || s.contains("/homebrew/") || s.contains("/linuxbrew/") {
            return InstallSource::Homebrew;
        }
        if s.contains("\\microsoft\\winget\\") || s.contains("/microsoft/winget/") {
            return InstallSource::Winget;
        }
        if s.contains("\\scoop\\apps\\") || s.contains("/scoop/apps/") {
            return InstallSource::Scoop;
        }
        if s.contains("/.cargo/bin") || s.contains("\\.cargo\\bin") {
            return InstallSource::Cargo;
        }
        InstallSource::SelfInstalled
    }

    /// Upgrade command the user should run instead of `filament update`.
    pub fn upgrade_hint(&self) -> &'static str {
        match self {
            InstallSource::Homebrew => "brew upgrade filament",
            InstallSource::Winget => "winget upgrade Abdk4Moura.Filament",
            InstallSource::Scoop => "scoop update filament",
            InstallSource::Cargo => "cargo install filament-cli",
            InstallSource::SelfInstalled => "",
        }
    }
}

// ----------------------------------------------------------- ShellHost --

/// Shell invocation strategy — the correct flag for running a command
/// depends on the shell family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellKind {
    /// sh / bash / zsh / fish / dash: `-c 'cmd'`
    Posix,
    /// powershell.exe / pwsh.exe / pwsh: `-Command 'cmd'`
    PowerShell,
    /// cmd.exe: `/c cmd`
    Cmd,
}

/// Resolves the shell program and provides the correct invocation for
/// interactive (login PTY) and one-shot (`exec cmd`) modes.
pub struct ShellHost {
    argv: Vec<String>,
    kind: ShellKind,
}

impl ShellHost {
    /// Resolve the shell from the precedence chain. No external resolution
    /// is done here — callers pass the already-resolved argv (from
    /// --shell-program / FILAMENT_SHELL / config / $SHELL / platform default).
    pub fn new(shell_argv: &[String]) -> Self {
        let binary = shell_argv.first().map(|s| s.as_str()).unwrap_or("");
        let name = Path::new(binary)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        let kind = if name.contains("pwsh") || name.contains("powershell") {
            ShellKind::PowerShell
        } else if name == "cmd.exe" || name == "cmd" {
            ShellKind::Cmd
        } else {
            ShellKind::Posix
        };
        ShellHost {
            argv: shell_argv.to_vec(),
            kind,
        }
    }

    /// Args for spawning an INTERACTIVE login shell (PTY session).
    pub fn interactive_args(&self) -> Vec<String> {
        let mut args = self.argv.clone();
        match self.kind {
            ShellKind::Posix => {
                if !args.iter().any(|a| a == "-l" || a == "--login") {
                    args.push("-l".into());
                }
                args
            }
            _ => args,
        }
    }

    /// Args for running a one-shot COMMAND (returns, no interactive shell).
    pub fn exec_cmd_args(&self, cmd: &str) -> Vec<String> {
        let mut args = vec![self.argv[0].clone()];
        match self.kind {
            ShellKind::Posix => {
                args.push("-c".into());
                args.push(cmd.to_string());
            }
            ShellKind::PowerShell => {
                args.push("-Command".into());
                args.push(cmd.to_string());
            }
            ShellKind::Cmd => {
                args.push("/c".into());
                args.push(cmd.to_string());
            }
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_a_valid_variant() {
        let host = ServiceHost::detect();
        // On Linux with systemd this is Systemd; on other platforms it's
        // whatever the detection says. The key property: it never panics,
        // and supports_install is consistent.
        assert!(
            matches!(
                host,
                ServiceHost::Systemd
                    | ServiceHost::Launchd
                    | ServiceHost::WindowsService
                    | ServiceHost::None
            ),
            "detect returned a valid variant: {host:?}"
        );
    }

    #[test]
    fn all_detected_hosts_support_install() {
        assert!(ServiceHost::Systemd.supports_install());
        assert!(ServiceHost::Launchd.supports_install());
        assert!(ServiceHost::WindowsService.supports_install());
        assert!(!ServiceHost::None.supports_install());
    }

    #[test]
    fn install_instructions_non_empty_when_no_backend() {
        assert!(!ServiceHost::Launchd.install_instructions().is_empty());
        assert!(!ServiceHost::WindowsService.install_instructions().is_empty());
        assert!(!ServiceHost::None.install_instructions().is_empty());
        // Systemd has a backend, so instructions should be empty.
        assert!(ServiceHost::Systemd.install_instructions().is_empty());
    }

    #[test]
    fn install_source_classify_brew() {
        let p = Path::new("/opt/homebrew/Cellar/filament/0.4.1/bin/filament");
        assert_eq!(InstallSource::classify(p), InstallSource::Homebrew);
        let p2 = Path::new("/home/linuxbrew/.linuxbrew/bin/filament");
        assert_eq!(InstallSource::classify(p2), InstallSource::Homebrew);
        let p3 = Path::new("/usr/local/Cellar/filament/0.3.1/bin/filament");
        assert_eq!(InstallSource::classify(p3), InstallSource::Homebrew);
    }

    #[test]
    fn install_source_classify_winget() {
        let p = Path::new("C:\\Users\\kabir\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Abdk4Moura.Filament_filament\\filament.exe");
        assert_eq!(InstallSource::classify(p), InstallSource::Winget);
    }

    #[test]
    fn install_source_classify_scoop() {
        let p = Path::new("C:\\Users\\kabir\\scoop\\apps\\filament\\0.4.1\\filament.exe");
        assert_eq!(InstallSource::classify(p), InstallSource::Scoop);
    }

    #[test]
    fn install_source_classify_cargo() {
        let p = Path::new("/home/kabir/.cargo/bin/filament");
        assert_eq!(InstallSource::classify(p), InstallSource::Cargo);
    }

    #[test]
    fn install_source_classify_self_installed() {
        let p = Path::new("/home/kabir/.local/bin/filament");
        assert_eq!(InstallSource::classify(p), InstallSource::SelfInstalled);
    }

    #[test]
    fn install_source_upgrade_hints() {
        assert_eq!(InstallSource::Homebrew.upgrade_hint(), "brew upgrade filament");
        assert_eq!(InstallSource::Winget.upgrade_hint(), "winget upgrade Abdk4Moura.Filament");
        assert_eq!(InstallSource::Cargo.upgrade_hint(), "cargo install filament-cli");
        assert_eq!(InstallSource::SelfInstalled.upgrade_hint(), "");
    }

    #[test]
    fn shell_host_interactive_posix_adds_login() {
        let sh = ShellHost::new(&["/bin/bash".into()]);
        assert!(sh.interactive_args().contains(&"-l".into()));
    }

    #[test]
    fn shell_host_exec_posix_uses_minus_c() {
        let sh = ShellHost::new(&["bash".into()]);
        let args = sh.exec_cmd_args("echo hi");
        assert_eq!(args[0], "bash");
        assert_eq!(args[1], "-c");
        assert_eq!(args[2], "echo hi");
    }

    #[test]
    fn shell_host_exec_powershell_uses_command_flag() {
        let sh = ShellHost::new(&["pwsh.exe".into()]);
        let args = sh.exec_cmd_args("Get-Date");
        assert_eq!(args[1], "-Command");
        assert_eq!(args[2], "Get-Date");
    }

    #[test]
    fn shell_host_exec_cmd_uses_slash_c() {
        let sh = ShellHost::new(&["cmd.exe".into()]);
        let args = sh.exec_cmd_args("dir");
        assert_eq!(args[1], "/c");
        assert_eq!(args[2], "dir");
    }

    #[test]
    fn shell_host_preserves_shell_argv_prefix() {
        let sh = ShellHost::new(&["bash".into(), "-l".into(), "-i".into()]);
        let args = sh.exec_cmd_args("echo x");
        assert_eq!(args[0], "bash");
        assert_eq!(args[1], "-c");
        assert_eq!(args[2], "echo x");
    }

    #[cfg(unix)]
    #[test]
    fn repairs_preexisting_world_readable_caps_store() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("filament-perm-repair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let caps = dir.join("caps.json");
        std::fs::write(&caps, "[]").unwrap();
        std::fs::set_permissions(&caps, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(std::fs::metadata(&caps).unwrap().permissions().mode() & 0o777, 0o644);

        let repaired = repair_sensitive_permissions_in(&dir).unwrap();

        assert_eq!(repaired, 1);
        assert_eq!(std::fs::metadata(&caps).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression for #149: setting FILAMENT_CONFIG_DIR to a fresh path from a
    /// shell whose cwd is $HOME must NOT migrate the production identity into
    /// it. Before the fix, `.config/filament` (cwd-relative) resolved to
    /// $HOME/.config/filament, the live production config, and the migration
    /// copied it wholesale into the override: a key clone.
    #[cfg(unix)]
    #[test]
    fn override_config_dir_is_not_migrated_into() {
        let uid = format!("{}-cfgdir-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let work = std::env::temp_dir().join(format!("fil-cfg-{uid}"));
        let home = work.join("home");
        let legacy = home.join(".config").join("filament");
        let target = work.join("target");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("identity.ed25519"), b"production key").unwrap();
        std::fs::write(legacy.join("overlay.ed25519"), b"production key 2").unwrap();

        // Snapshot the real process state so it can be restored even if the
        // assertion below fails (the failure must not leak into parallel tests).
        let old_cwd = std::env::current_dir().unwrap();
        let old_home = std::env::var_os("HOME");
        let old_override = std::env::var_os("FILAMENT_CONFIG_DIR");

        // Reproduce the report: fresh override, cwd == $HOME, populated legacy.
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("FILAMENT_CONFIG_DIR", &target);
        }
        std::env::set_current_dir(&home).unwrap();

        Paths::migrate_legacy();

        // Restore process-global state BEFORE asserting, so a failure cannot
        // leave env/cwd mutated for sibling tests.
        std::env::set_current_dir(&old_cwd).unwrap();
        match old_home {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        match old_override {
            Some(v) => unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", v) },
            None => unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") },
        }

        // The override must stay EMPTY: migrating production keys into a fresh
        // explicit config dir is the #149 key clone.
        let entries: Vec<_> = std::fs::read_dir(&target)
            .map(|it| it.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(
            entries.is_empty(),
            "FILAMENT_CONFIG_DIR override was populated by legacy migration: {entries:?}"
        );

        let _ = std::fs::remove_dir_all(&work);
    }
}

/// Policy routing for exit nodes, kept behind the platform adapter so the rest
/// of the tree stays free of `cfg(target_os)`.
///
/// The exit-node design (docs/design-subnet-routes.md) is expressed in iproute2
/// terms: a dedicated table, a rule, and carve-outs. That vocabulary is Linux's.
/// macOS and Windows have policy routing, but neither speaks these commands, so
/// the honest portable contract is "supported, or say so", not a silent no-op
/// that would leave a caller believing traffic is tunnelled when it is not.
pub mod policy_route {
    /// Whether this platform can install the exit-route policy at all.
    pub fn supported() -> bool {
        cfg!(target_os = "linux")
    }

    /// The current default gateway, if one can be determined.
    pub fn default_gateway() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let out = std::process::Command::new("ip")
                .args(["-4", "route", "show", "default"])
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&out.stdout);
            let mut fields = text.split_whitespace();
            while let Some(f) = fields.next() {
                if f == "via" {
                    return fields.next().map(str::to_string);
                }
            }
            None
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Run one `ip` plan produced by `exit_route`.
    ///
    /// Every step is attempted even after one fails, because a partly-applied
    /// plan whose CARVE-OUTS succeeded is strictly safer than one abandoned
    /// after the default route went in. Deleting something already absent is
    /// success, not failure: reconciliation is repeated and idempotent.
    pub fn run_plan(plan: &[Vec<String>]) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let mut failures = Vec::new();
            for step in plan {
                match std::process::Command::new("ip").args(step).output() {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => {
                        let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                        if !err.contains("No such process") && !err.contains("not found") {
                            failures.push(format!("ip {}: {err}", step.join(" ")));
                        }
                    }
                    Err(e) => failures.push(format!("ip {}: {e}", step.join(" "))),
                }
            }
            return if failures.is_empty() { Ok(()) } else { Err(failures.join("; ")) };
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = plan;
            Err("policy routing is implemented for Linux only".to_string())
        }
    }
}
