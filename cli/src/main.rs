// filament — anywhere-to-anywhere P2P file transfer, CLI end.
//
// Speaks the exact same wire protocol as the browser app at
// https://filament.autumated.com: Socket.IO signaling, perfect-negotiation
// WebRTC, one-time pairing codes, and sid-framed chunk transfer with
// offset-based resume. A browser is a first-class peer: `filament send` can
// deliver straight to a phone with nothing installed on it.
//
//   filament send video.mp4 --code          mint a speakable one-time code
//   filament recv clever-lynx-63            claim it on the other machine
//   filament send ./dir --room demo         directories are tarred on the fly
//   tar c logs | filament send - --name logs.tar --code
//   filament recv -y --dir ~/Drops          auto-accept into a directory
//
// Failure-mode ledger: ../docs/cli-resilience.md — every resilience behavior
// in this file carries its ledger number (C1..C17 / F1..F4).

mod net;
mod ui;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use net::{Ev, Peer, Transport};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{IsTerminal, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const DEFAULT_SERVER: &str = "https://api.filament.autumated.com";
/// C7: content identity for resume — sha256 over the first 256 KiB.
const HEAD_BYTES: u64 = 256 * 1024;
/// C4/C6/C21: how long we wait for a vanished peer to rejoin. UNWARNED is the
/// blind default; a peer that announced `brb` (e.g. the browser opening a
/// mobile file picker suspends the whole tab) gets its declared ttl instead —
/// informed waits are both longer when promised and shorter when not.
const REJOIN_WINDOW: Duration = Duration::from_secs(120);
fn rejoin_unwarned() -> Duration {
    std::env::var("FILAMENT_REJOIN_SECS") // test knob (gate 15)
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(45))
}
/// C3/C4: connection (re)establishment attempts before failing honestly.
const MAX_ATTEMPTS: u32 = 3;

const VERSION: &str = env!("FILAMENT_BUILD_INFO"); // stamped by build.rs

const EXAMPLES: &str = "\
EXAMPLES:
  filament video.mp4                 send it; mints a speakable one-time code + QR
  filament clever-lynx-63            claim a code and receive
  filament send ./photos --code      directories tar on the fly
  filament recv <code> -o - | tar x  stream straight into a pipe
  filament pair --name phone         remember a device — a ceremony, no file needed
  filament send big.iso --to laptop  no code: a remembered device, verified by proof
  filament up --install              always-on drop target (trusted devices only)
  filament introduce laptop phone    vouch two of your devices to each other

  The other end never needs anything installed: https://filament.autumated.com";

#[derive(Parser)]
#[command(name = "filament", version = VERSION, about = "P2P file transfer between terminals and browsers — no upload, no account", after_help = EXAMPLES)]
struct Cli {
    /// Signaling server (self-hosters: point at your own instance)
    #[arg(long, global = true, env = "FILAMENT_SERVER", default_value = DEFAULT_SERVER)]
    server: String,
    /// Force TURN relay (testing/privacy; hides your IP from the peer)
    #[arg(long, global = true)]
    relay: bool,
    /// Display name shown to peers (default: config file, then user@host)
    #[arg(long, global = true)]
    name_as: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send files or directories to a peer (browser or CLI)
    Send {
        /// Files or directories to send; '-' reads stdin
        paths: Vec<String>,
        /// Mint a speakable one-time code the receiver claims
        #[arg(long)]
        code: bool,
        /// Choose the one-time code word yourself (implies --code)
        #[arg(long)]
        word: Option<String>,
        /// After a code pairing, remember the other device under this name
        #[arg(long)]
        remember: Option<String>,
        /// Join an explicit room instead of the same-network auto room
        #[arg(long)]
        room: Option<String>,
        /// Only connect to a peer whose display name contains this (C13)
        #[arg(long)]
        to: Option<String>,
        /// File name when sending stdin ('-')
        #[arg(long, default_value = "stdin.bin")]
        name: String,
    },
    /// Receive files from a peer (browser or CLI)
    Recv {
        /// One-time code spoken by the sender (omit to use the auto room)
        code: Option<String>,
        /// Directory to write received files into
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Accept every offer without prompting
        #[arg(long, short = 'y')]
        yes: bool,
        /// Join an explicit room instead of the same-network auto room
        #[arg(long)]
        room: Option<String>,
        /// Only accept a sender whose display name contains this (C13)
        #[arg(long)]
        to: Option<String>,
        /// Keep listening after a sender disconnects
        #[arg(long)]
        keep_open: bool,
        /// After a code pairing, remember the other device under this name
        #[arg(long)]
        remember: Option<String>,
        /// Rename the (single) received file; '-' streams it to stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },
    /// Remember a device — a pairing ceremony, no file needed. Mints a code
    /// (or claims one) and exchanges the pair secret with consent on both ends
    Pair {
        /// A code from the other device; omit to mint one for them
        code: Option<String>,
        /// What to call them (asked interactively if omitted)
        #[arg(long)]
        name: Option<String>,
    },
    /// List devices remembered via --remember (trusted for --to and auto-accept)
    Devices {
        #[command(subcommand)]
        action: Option<DevicesAction>,
    },
    /// Always-on receiver: trusted known devices only, invisible to strangers
    Up {
        /// Install + start a systemd user service instead of running attached
        #[arg(long)]
        install: bool,
        /// Drop directory (default: `filament config dir`, else ~/Filament)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show whether the daemon runs and what it received recently
    Status,
    /// Stop the daemon
    Down,
    /// Vouch between two known devices: mints a fresh secret and delivers it
    /// to both over verified channels (run on the device that knows both)
    Introduce { a: String, b: String },
    /// Get or set config (keys: name, server, dir) in ~/.config/filament/config
    Config { key: Option<String>, value: Option<String> },
    /// Update filament to the latest release
    Update {
        /// Check only; don't install
        #[arg(long)]
        check: bool,
        /// Include prerelease (beta) builds
        #[arg(long)]
        beta: bool,
    },
    /// Generate shell completions (bash, zsh, fish, elvish, powershell)
    Completions {
        shell: clap_complete::Shell,
    },
    /// Print the man page (roff) to stdout
    #[command(hide = true)]
    Man,
}

/// Petname management (C12): names are LOCAL aliases for pair secrets — the
/// secret is the identity, the name is yours to fix when you mislabel one.
#[derive(Subcommand)]
enum DevicesAction {
    /// Forget a device: deletes the secret; it can no longer find you
    Forget { name: String },
    /// Rename your local alias (the other side is unaffected)
    Rename { old: String, new: String },
}

/// Looks like a speakable code: word-word-digits.
fn regex_lite_code(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3
        && parts[0].chars().all(|c| c.is_ascii_lowercase())
        && parts[1].chars().all(|c| c.is_ascii_lowercase())
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[2].len() >= 2
        && parts[2].chars().all(|c| c.is_ascii_digit())
}

// --------------------------------------------------------------- utilities --

/// Persistent per-install identity (shared by every process using this
/// config dir). Lets a sender recognize — and never target — its OWN daemon
/// when both sit on the same pair-presence channels.
fn install_id() -> String {
    let p = devices_path().with_file_name("device.id");
    if let Ok(id) = std::fs::read_to_string(&p) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    let id: String = fresh_secret()[..8].to_string();
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&p, &id);
    id
}

fn mk_uid(prefix: &str) -> String {
    // Test hook (gate 11): a pinned uid lets the harness exercise the
    // same-device-rejoined supersede path (C6). The cli-s-/cli-r- role prefix
    // must survive the override or same-role skip (C13) breaks.
    if let Ok(forced) = std::env::var("FILAMENT_UID") {
        return format!("cli-{prefix}-{forced}");
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("cli-{prefix}-{}-{:x}{:x}", install_id(), std::process::id(), nanos)
}

/// Same install (our own daemon / another process of this device)?
fn is_self_uid(my_uid: &str, peer_uid: Option<&str>) -> bool {
    if std::env::var("FILAMENT_UID").is_ok() {
        return false; // test hook pins uids; don't second-guess it
    }
    let id = install_id();
    let _ = my_uid;
    peer_uid.map(|p| p.contains(&format!("-{id}-"))).unwrap_or(false)
}

fn config_path() -> PathBuf {
    devices_path().with_file_name("config")
}

/// Tiny `key value` per-line config; no toml dependency for three keys.
fn config_get(key: &str) -> Option<String> {
    std::fs::read_to_string(config_path()).ok()?.lines().find_map(|l| {
        let (k, v) = l.split_once(char::is_whitespace)?;
        (k == key && !v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

fn config_set(key: &str, value: &str) -> Result<()> {
    let p = config_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut lines: Vec<String> = std::fs::read_to_string(&p)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(key))
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{key} {value}"));
    std::fs::write(&p, lines.join("\n") + "\n")?;
    Ok(())
}

fn display_name() -> String {
    if let Ok(n) = std::env::var("FILAMENT_NAME") {
        return n;
    }
    if let Some(n) = config_get("name") {
        return n;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    let host = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "cli".into());
    format!("{user}@{host}")
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", U[i]) }
}

/// C7: hash of the first min(256 KiB, len) bytes — cheap content identity
/// carried in file-offer so resume can detect a different file wearing the
/// same name + size.
fn head_hash(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD_BYTES as usize];
    let mut got = 0usize;
    while got < buf.len() {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    let mut h = Sha256::new();
    h.update(&buf[..got]);
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Sidecar metadata for a partial receive (`<name>.part.meta`).
/// JSON {"size":N,"head":"hex"}; legacy files hold a bare size string.
struct PartMeta {
    size: u64,
    head: Option<String>,
}

impl PartMeta {
    fn load(path: &Path) -> Option<PartMeta> {
        let raw = std::fs::read_to_string(path).ok()?;
        if let Ok(v) = serde_json::from_str::<Value>(&raw) {
            if let Some(size) = v["size"].as_u64() {
                return Some(PartMeta { size, head: v["head"].as_str().map(|s| s.to_string()) });
            }
        }
        raw.trim().parse::<u64>().ok().map(|size| PartMeta { size, head: None })
    }
    fn store(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, json!({ "size": self.size, "head": self.head }).to_string())
    }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    for i in 1..1000 {
        let c = dir.join(format!("{name}.{i}"));
        if !c.exists() {
            return c;
        }
    }
    dir.join(format!("{name}.dup"))
}

// ------------------------------------------------------- known devices (C12) --
// Persistent pairing: during a code-paired session, both sides exchange a
// 32-byte secret END-TO-END over the DataChannel (the server never sees it)
// and store it under a local nickname. Presence: subscribe with
// sha256("filament-pair:" + secret) — the server learns only meeting points.
// Trust: an HMAC(secret) proof exchanged after connect, so the server cannot
// impersonate a known device. Full PAKE remains roadmap (ledger C15).

fn devices_path() -> PathBuf {
    if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
        return PathBuf::from(d).join("devices.json");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/filament/devices.json")
}

fn devices_load() -> Vec<(String, String)> {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else { return Vec::new() };
    serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|d| Some((d["name"].as_str()?.to_string(), d["secret"].as_str()?.to_string())))
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn devices_store(name: &str, secret: &str) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut all = devices_load();
    all.retain(|(n, _)| n != name);
    all.push((name.to_string(), secret.to_string()));
    let arr: Vec<Value> = all.iter().map(|(n, s)| json!({"name": n, "secret": s})).collect();
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// C27: a declined remember offer must not leave one-sided dead weight.
fn devices_remove(name: &str) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut all = devices_load();
    all.retain(|(n, _)| n != name);
    let arr: Vec<Value> = all.iter().map(|(n, s)| json!({"name": n, "secret": s})).collect();
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    Ok(())
}

fn channel_of(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"filament-pair:");
    h.update(secret.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA256 (manual: avoids a hmac-crate version dance with sha2 0.11).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner.finalize());
    outer.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// C20: the proof binds the pair secret to the DTLS session. uids are
/// order-normalized (direction-tagged by the prover's uid prefix) and BOTH
/// certificate fingerprints are mixed in sorted order — a channel MITM'd by
/// anyone (including the signaling server) has different fingerprints, so
/// the proof fails and auto-accept refuses.
fn proof_for(secret: &str, prover_uid: &str, a_uid: &str, b_uid: &str, fp1: &str, fp2: &str) -> String {
    let (lo, hi) = if a_uid < b_uid { (a_uid, b_uid) } else { (b_uid, a_uid) };
    let (f_lo, f_hi) = if fp1 < fp2 { (fp1, fp2) } else { (fp2, fp1) };
    hmac_sha256(
        secret.as_bytes(),
        format!("filament-proof2:{prover_uid}|{lo}|{hi}|{f_lo}|{f_hi}").as_bytes(),
    )
}

fn fresh_secret() -> String {
    let mut buf = [0u8; 32];
    // std-only CSPRNG is unavailable; derive from getrandom via std::fs on unix
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // fallback (non-unix): hash of time+pid noise, still unpredictable enough
        let mut h = Sha256::new();
        h.update(format!("{:?}{}", SystemTime::now(), std::process::id()));
        buf.copy_from_slice(&h.finalize()[..32]);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------- daemon (C19) --

fn drop_dir(flag: Option<PathBuf>) -> PathBuf {
    flag.or_else(|| config_get("dir").map(PathBuf::from)).unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join("Filament")
    })
}

/// Minimal `YYYY-MM-DD HH:MM` UTC stamp (civil-from-days; avoids chrono).
fn chrono_now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = (secs / 86400, secs % 86400);
    let (hh, mm) = (rem / 3600, (rem % 3600) / 60);
    // Howard Hinnant's civil_from_days
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

fn pidfile() -> PathBuf {
    devices_path().with_file_name("up.pid")
}
fn up_log() -> PathBuf {
    devices_path().with_file_name("up.log")
}

fn daemon_alive() -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(pidfile()).ok()?.trim().parse().ok()?;
    let cmd = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).ok()?;
    cmd.contains("filament").then_some(pid)
}

async fn up_cmd(server: &str, install: bool, dir: Option<PathBuf>, relay: bool) -> Result<()> {
    if install {
        let exe = std::env::current_exe()?;
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
        std::fs::create_dir_all(&unit_dir)?;
        let unit = unit_dir.join("filament.service");
        std::fs::write(&unit, format!(
            "[Unit]\nDescription=Filament drop target (trusted devices only)\nAfter=network-online.target\n\n[Service]\nExecStart={} up\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
            exe.display()
        ))?;
        ui::say(&format!("  {} wrote {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), unit.display()));
        let enabled = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .and_then(|_| std::process::Command::new("systemctl").args(["--user", "enable", "--now", "filament"]).status())
            .map(|st| st.success())
            .unwrap_or(false);
        if enabled {
            ui::say(&format!("  {} service enabled and started — logs: journalctl --user -u filament", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
        } else {
            ui::say(&format!("  start it with: {}", ui::paint(ui::Tone::Bold, "systemctl --user enable --now filament")));
        }
        return Ok(());
    }
    if let Some(pid) = daemon_alive() {
        bail!("already up (pid {pid}) — `filament status` / `filament down`");
    }
    let dir = drop_dir(dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(pidfile(), std::process::id().to_string())?;
    let res = recv_cmd(server, None, dir, false, None, None, true, relay, None, true, None).await;
    let _ = std::fs::remove_file(pidfile());
    res
}

fn status_cmd() -> Result<()> {
    match daemon_alive() {
        Some(pid) => ui::say(&format!("  {} up (pid {pid})", ui::paint(ui::Tone::Ok, ui::glyph_ok()))),
        None => ui::say(&format!("  {} not running — start with: filament up", ui::paint(ui::Tone::Dim, "·"))),
    }
    let n = devices_load().len();
    ui::say(&format!("  {} known device{}", n, if n == 1 { "" } else { "s" }));
    if let Ok(log) = std::fs::read_to_string(up_log()) {
        let recent: Vec<&str> = log.lines().rev().take(8).collect();
        if !recent.is_empty() {
            ui::say(&ui::paint(ui::Tone::Dim, "  recent receives:"));
            for l in recent.iter().rev() {
                ui::say(&format!("    {l}"));
            }
        }
    }
    Ok(())
}

fn down_cmd() -> Result<()> {
    match daemon_alive() {
        Some(pid) => {
            std::process::Command::new("kill").arg(pid.to_string()).status()?;
            let _ = std::fs::remove_file(pidfile());
            ui::say(&format!("  {} stopped (pid {pid})", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
            Ok(())
        }
        None => {
            ui::say("  not running");
            Ok(())
        }
    }
}

// ------------------------------------------------------------ introduce ----
// Vouched pairing: the hub (which already trusts A and B) mints a fresh
// secret and delivers it to both over channels it has PROVEN itself on
// (fingerprint-bound, C20). Receivers only honor pair-intro from a verified
// link, so a stranger — or the server — can't inject trust.

async fn introduce_cmd(server: &str, a: &str, b: &str, relay: bool) -> Result<()> {
    let store = devices_load();
    let find = |n: &str| store.iter().find(|(name, _)| name.eq_ignore_ascii_case(n)).cloned();
    let (a_name, a_sec) = find(a).ok_or_else(|| anyhow!("'{a}' is not a known device (see: filament devices)"))?;
    let (b_name, b_sec) = find(b).ok_or_else(|| anyhow!("'{b}' is not a known device"))?;

    let my_uid = mk_uid("s");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    let solo = format!("intro-{}", fresh_secret());
    sio.emit("join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await.ok();
    sio.emit("subscribe", json!({ "channels": [channel_of(&a_sec), channel_of(&b_sec)] })).await.ok();
    ui::say(&format!("  waiting for {} and {} to be online…", ui::paint(ui::Tone::Bold, &a_name), ui::paint(ui::Tone::Bold, &b_name)));

    let mut conn = Conn {
        server: server.to_string(),
        sio: sio.clone(),
        tx: tx.clone(),
        my_uid: my_uid.clone(),
        my_id: String::new(),
        relay_only: relay,
        to_filter: None,
        links: HashMap::new(),
        roster: HashMap::new(),
        active: None,
        next_gen: 0,
        waiting_rejoin: None,
        rejoin_window: REJOIN_WINDOW,
        away: None,
        chunk_size: net::MAX_DC_PAYLOAD,
    };
    // sid -> which device (false = a, true = b)
    let mut who: HashMap<String, bool> = HashMap::new();
    let mut sent: [bool; 2] = [false, false];
    let fresh = fresh_secret();
    let deadline = Instant::now() + Duration::from_secs(120);

    loop {
        if Instant::now() > deadline {
            bail!("timed out — both devices must be online (e.g. running `filament up`)");
        }
        let ev = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                // C28: re-assert both parties' channels on every (re)connect.
                sio.emit("subscribe", json!({ "channels": [channel_of(&a_sec), channel_of(&b_sec)] })).await.ok();
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own processes share these channels
                }
                let ch = v["channel"].as_str().unwrap_or_default().to_string();
                let pid = v["id"].as_str().unwrap_or_default().to_string();
                let is_b = if ch == channel_of(&a_sec) { false } else if ch == channel_of(&b_sec) { true } else { continue };
                conn.maybe_adopt(&v, false).await?;
                if let Some(l) = conn.link_mut(&pid) {
                    l.expected_secret = Some(if is_b { (b_name.clone(), b_sec.clone()) } else { (a_name.clone(), a_sec.clone()) });
                }
                who.insert(pid, is_b);
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                if let Some(l) = conn.link(&from) {
                    if let Err(e) = l.peer.handle_signal(data).await {
                        eprintln!("signal failed to apply: {e} (recovering)");
                    }
                }
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                }
                let Some(&is_b) = who.get(&pid) else { continue };
                let (dev_name, sec) = if is_b { (&b_name, &b_sec) } else { (&a_name, &a_sec) };
                let other_name = if is_b { &a_name } else { &b_name };
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = l.peer.fingerprints().await {
                        // prove ourselves, then vouch
                        t.send_control(&json!({
                            "type": "pair-proof",
                            "mac": proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                        })).await?;
                        t.send_control(&json!({
                            "type": "pair-intro", "name": other_name, "secret": fresh,
                        })).await?;
                        sent[is_b as usize] = true;
                        ui::say(&format!("  {} vouched to {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, dev_name)));
                    }
                }
                if sent[0] && sent[1] {
                    tokio::time::sleep(Duration::from_millis(800)).await; // let intros flush
                    ui::say(&format!(
                        "  {} {} and {} now know each other (no codes needed)",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        a_name, b_name,
                    ));
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
            }
            Ev::Stuck(pid, g) => { conn.on_stuck(&pid, g, "stuck").await?; }
            Ev::GraceExpired(pid, g) => { conn.on_stuck(&pid, g, "lost").await?; }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => { conn.on_peer_left(&v); }
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }
}

// ----------------------------------------------------------------- pair ----
// C29: remembering a device is a first-class ceremony — no file transfer to
// pretend through. Mint (or claim) a one-time code, connect, hand the pair
// secret over the encrypted link (pair-keep; C27 consent applies on the far
// side), confirm mutuality, exit. Initiation rule: the code CREATOR sends the
// keep; a claimer falls back after 3 s of silence (browsers never initiate).

async fn pair_cmd(server: &str, code: Option<String>, name: Option<String>, relay: bool) -> Result<()> {
    let my_uid = mk_uid("p");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    // Meta must exist for pairing; an unguessable solo room keeps strangers
    // out (the daemon's trick) — the pair-claim moves people, not the room.
    let solo = format!("pairc-{}", fresh_secret());
    sio.emit("join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await.ok();
    let creator = code.is_none();
    match &code {
        Some(c) => {
            ui::say(&format!("  claiming {}…", ui::paint(ui::Tone::Brand, c)));
            sio.emit("pair-claim", json!({ "code": c.to_lowercase() })).await.ok();
        }
        None => {
            sio.emit("pair-create", json!({})).await.ok();
        }
    }

    let mut conn = Conn {
        server: server.to_string(),
        sio: sio.clone(),
        tx: tx.clone(),
        my_uid: my_uid.clone(),
        my_id: String::new(),
        relay_only: relay,
        to_filter: None,
        links: HashMap::new(),
        roster: HashMap::new(),
        active: None,
        next_gen: 0,
        waiting_rejoin: None,
        rejoin_window: REJOIN_WINDOW,
        away: None,
        chunk_size: net::MAX_DC_PAYLOAD,
    };
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let secret = fresh_secret(); // ours, if WE end up initiating
    let mut petname = name; // resolved --name, prompt answer, or peer's display name
    let mut their_secret: Option<String> = None; // a received keep (we claimed)
    let mut ack_ok = false; // our keep was consented to
    let mut initiated = false;
    let mut prompted = false;
    let mut peer: Option<(String, String)> = None; // (pid, display name)
    let deadline = Instant::now() + Duration::from_secs(600); // code TTL

    loop {
        // Done when the petname is settled AND a secret is mutual: either we
        // received theirs (claimer path) or ours was consented to (ack).
        if let Some(n) = petname.clone() {
            if let Some(sec) = their_secret.clone().or(if ack_ok { Some(secret.clone()) } else { None }) {
                devices_store(&n, &sec)?;
                ui::say(&format!(
                    "  {} {} mutually remembered — either device now finds the other automatically, no codes",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                    ui::paint(ui::Tone::Bold, &n),
                ));
                ui::say(&ui::paint(ui::Tone::Dim, &format!("  try: filament send <file> --to {n}   ·   filament up")));
                tokio::time::sleep(Duration::from_millis(300)).await; // let acks flush
                let _ = sio.disconnect().await;
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            bail!("timed out — the code was never used (codes expire after 10 minutes)");
        }
        let ev = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => bail!("signaling closed"),
            Err(_) => continue,
        };
        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
            }
            Ev::PairCode(v) => {
                let c = v["code"].as_str().unwrap_or("?");
                ui::clipboard(c);
                ui::say("");
                ui::say(&format!("      {}", ui::paint(ui::Tone::Brand, &c.to_uppercase())));
                ui::say("");
                ui::say(&ui::paint(ui::Tone::Dim, "  on the other device: type it into the web app, or `filament pair <code>`"));
                ui::say(&ui::paint(ui::Tone::Dim, "  one claim · expires in 10 min · waiting…"));
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed — connecting…"));
            }
            Ev::PairMatched(v) => {
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ui::say(&format!("  {} code accepted — connecting", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                sio.emit("join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await.ok();
            }
            Ev::PairError(v) => {
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => "that code's creator already left — ask them for a fresh one".to_string(),
                    _ => format!("{} — codes burn after one use and expire after 10 min", v["error"].as_str().unwrap_or("?")),
                };
                bail!("code rejected: {hint}");
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, true).await?;
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data).await?;
                if let Some(l) = conn.link(&from) {
                    if let Err(e) = l.peer.handle_signal(data).await {
                        eprintln!("signal failed to apply: {e} (recovering)");
                    }
                }
            }
            Ev::ChannelReady(pid, t) => {
                let display = match conn.link_mut(&pid) {
                    Some(l) => {
                        l.transport = Some(t.clone());
                        l.presence = Presence::Ready;
                        l.name.clone()
                    }
                    None => continue,
                };
                ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, &display)));
                peer = Some((pid.clone(), display.clone()));
                if creator && !initiated {
                    t.send_control(&json!({ "type": "pair-keep", "secret": secret })).await?;
                    initiated = true;
                } else if !creator {
                    // Fallback: browsers (and legacy peers) never initiate —
                    // give the creator 3 s, then hand over OUR secret.
                    let tx = tx.clone();
                    let pid = pid.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        let _ = tx.send(Ev::Control(pid, json!({ "type": "__pair_fallback" })));
                    });
                }
                // Settle the petname: --name wins; otherwise ask (tty) or
                // default to their display name (scripts, pipes).
                if petname.is_none() && !prompted {
                    prompted = true;
                    if std::io::stdin().is_terminal() {
                        eprint!("  remember this device as [{display}]: ");
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            use tokio::io::AsyncBufReadExt;
                            let mut line = String::new();
                            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
                            if reader.read_line(&mut line).await.is_ok() {
                                let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                            }
                        });
                    } else {
                        petname = Some(display.clone());
                    }
                }
            }
            Ev::StdinLine(line) => {
                if petname.is_none() && prompted {
                    let n = if line.is_empty() {
                        peer.as_ref().map(|(_, d)| d.clone()).unwrap_or_else(|| "device".into())
                    } else {
                        line
                    };
                    petname = Some(n);
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("pair-keep") => {
                    let sec = v["secret"].as_str().unwrap_or_default().to_string();
                    if sec.len() == 64 && !initiated {
                        // Running `filament pair` IS consent — ack and keep.
                        their_secret = Some(sec);
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep-ack", "ok": true })).await.ok();
                        }
                    }
                }
                Some("pair-keep-ack") => {
                    if v["ok"].as_bool() == Some(false) {
                        bail!("they declined to be remembered — nothing stored on either side");
                    }
                    ack_ok = true;
                }
                Some("__pair_fallback") => {
                    if !creator && !initiated && their_secret.is_none() {
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep", "secret": secret })).await?;
                            initiated = true;
                        }
                    }
                }
                _ => {}
            },
            Ev::Stuck(pid, g) => {
                conn.on_stuck(&pid, g, "stuck").await?;
            }
            Ev::GraceExpired(pid, g) => {
                conn.on_stuck(&pid, g, "lost").await?;
            }
            Ev::PcState(pid, st) => conn.on_pc_state(&pid, &st).await,
            Ev::PeerLeft(v) => {
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let n = gone.unwrap_or_else(|| "they".into());
                    ui::say(&ui::paint(ui::Tone::Dim, &format!("  {n} stepped away — holding the line (their client rejoins)")));
                }
            }
            Ev::Interrupted => bail!("interrupted"),
            _ => {}
        }
    }
}

// ---------------------------------------------------------- link machinery --
// One peer at a time, but with the browser's survival rules: establishment
// watchdog (C3), disconnected-grace + ICE restart + reconnect attempts (C4),
// fresh ICE config per attempt (C5), uid supersede on rejoin (C6), and a
// rejoin window when the peer's socket dies entirely.

struct Link {
    peer: Arc<Peer>,
    info: Value, // {id,name,uid} as last seen — enough to re-establish
    name: String,
    uid: Option<String>,
    transport: Option<Arc<dyn Transport>>,
    generation: u32,
    attempts: u32,
    /// C12: proof-verified known device (per link, not global)
    trusted: bool,
    /// (name, secret) hypothesis to prove/verify on this link
    expected_secret: Option<(String, String)>,
    /// C26: what the status roster shows for this peer
    presence: Presence,
}

/// C26: per-peer presence for the static status roster.
#[derive(Clone, Copy, PartialEq)]
enum Presence {
    Connecting,
    Ready,
    Away,
    Reconnecting,
}

fn presence_glyph(p: Presence) -> (&'static str, ui::Tone, &'static str) {
    match p {
        Presence::Ready => (ui::glyph_ok(), ui::Tone::Ok, ""),
        Presence::Away => ("●", ui::Tone::Warn, "away"),
        Presence::Reconnecting => ("◌", ui::Tone::Warn, "reconnecting…"),
        Presence::Connecting => ("◌", ui::Tone::Dim, "connecting…"),
    }
}

/// C18: browsers are mesh peers — they connect to EVERY room member. The CLI
/// must answer every offer politely or unanswered browsers wedge at
/// "connecting" (and their retry storms degrade the whole room). So: a links
/// MAP, every peer answered; SEND still aims transfers at one `active`
/// target; RECV accepts from any link, gated per-link by consent/trust.
const MAX_LINKS: usize = 16;

struct Conn {
    server: String,
    sio: rust_socketio::asynchronous::Client,
    tx: mpsc::UnboundedSender<Ev>,
    my_uid: String,
    my_id: String,
    relay_only: bool,
    to_filter: Option<String>,
    links: HashMap<String, Link>,
    roster: HashMap<String, Value>, // sid -> {id,name,uid} from welcome/peer-joined
    active: Option<String>,        // the transfer-target sid (send side)
    next_gen: u32,
    waiting_rejoin: Option<Instant>,
    /// How long the current rejoin window runs (set when it opens; depends on
    /// whether the peer declared `brb`).
    rejoin_window: Duration,
    /// (peer sid, until) — the peer told us it's stepping away (C21).
    away: Option<(String, Instant)>,
    chunk_size: usize,
}

impl Conn {
    fn link(&self, pid: &str) -> Option<&Link> {
        self.links.get(pid)
    }
    fn link_mut(&mut self, pid: &str) -> Option<&mut Link> {
        self.links.get_mut(pid)
    }
    fn active_link(&self) -> Option<&Link> {
        self.active.as_ref().and_then(|a| self.links.get(a))
    }
    fn is_active(&self, pid: &str) -> bool {
        self.active.as_deref() == Some(pid)
    }
    fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.active_link().and_then(|l| l.transport.clone())
    }
    fn transport_of(&self, pid: &str) -> Option<Arc<dyn Transport>> {
        self.links.get(pid).and_then(|l| l.transport.clone())
    }

    /// May this peer become the TRANSFER TARGET? (Filters gate targeting,
    /// never answering — every peer still gets a polite link.)
    fn targetable(&self, name: &str, peer_uid: Option<&str>) -> bool {
        if let Some(filter) = &self.to_filter {
            if !name.to_lowercase().contains(&filter.to_lowercase()) {
                return false;
            }
        }
        // Same-role CLI peers never transfer to each other (gate 7).
        if let (Some(pu), Some(my_role)) = (peer_uid, self.my_uid.get(..6)) {
            if pu.starts_with(my_role) {
                return false;
            }
        }
        true
    }

    /// Track a roster entry and (re)connect to it. `want_active` marks it as
    /// the intended transfer target if it passes the target filters and no
    /// target exists yet. Returns true if this peer is (now) the active one.
    async fn maybe_adopt(&mut self, v: &Value, want_active: bool) -> Result<bool> {
        let peer_id = v["id"].as_str().unwrap_or_default().to_string();
        let peer_uid = v["uid"].as_str().map(|s| s.to_string());
        let name = v["name"].as_str().unwrap_or("peer").to_string();
        if peer_id.is_empty() || peer_id == self.my_id {
            return Ok(false);
        }
        // NOTE: same-install peers (our own daemon) are filtered at the
        // KnownPeer call sites, NOT here — room discovery must keep working
        // between two processes of one machine (loopback self-send is the
        // first thing every new user tries).
        self.roster.insert(peer_id.clone(), v.clone());

        // C6: same device on a NEW sid — supersede the stale link.
        let stale: Option<String> = self
            .links
            .iter()
            .find(|(sid, l)| l.uid.is_some() && l.uid == peer_uid && **sid != peer_id)
            .map(|(sid, _)| sid.clone());
        if let Some(old_sid) = stale {
            eprintln!("{name} reconnected — superseding old link");
            let was_active = self.is_active(&old_sid);
            let secret = self.links.get(&old_sid).and_then(|l| l.expected_secret.clone());
            self.drop_link(&old_sid);
            self.establish(v.clone()).await?;
            if let Some(l) = self.links.get_mut(&peer_id) {
                l.expected_secret = secret;
            }
            if was_active {
                self.active = Some(peer_id.clone());
            }
            return Ok(self.is_active(&peer_id));
        }

        if !self.links.contains_key(&peer_id) {
            if self.links.len() >= MAX_LINKS {
                return Ok(false);
            }
            self.establish(v.clone()).await?;
        }
        if want_active && self.active.is_none() && self.targetable(&name, peer_uid.as_deref()) {
            self.active = Some(peer_id.clone());
            self.waiting_rejoin = None;
        }
        Ok(self.is_active(&peer_id))
    }

    fn drop_link(&mut self, pid: &str) {
        if let Some(old) = self.links.remove(pid) {
            // Never await close in the event loop (F8): mark + spawn.
            let p = old.peer.clone();
            p.mark_closed();
            tokio::spawn(async move { p.close().await });
        }
        if self.is_active(pid) {
            self.active = None;
        }
    }

    async fn establish(&mut self, info: Value) -> Result<()> {
        let peer_id = info["id"].as_str().unwrap_or_default().to_string();
        self.drop_link(&peer_id); // re-establish replaces any same-sid link
        let peer_uid = info["uid"].as_str().map(|s| s.to_string());
        let name = info["name"].as_str().unwrap_or("peer").to_string();
        // C5: fresh ICE config (TURN creds are expiry-stamped HMACs) for
        // every attempt, not just the first.
        let cfg = net::fetch_config(&self.server).await?;
        self.chunk_size = cfg.chunk_size;
        let polite = net::polite_role(&self.my_uid, peer_uid.as_deref(), &self.my_id, &peer_id);
        self.next_gen += 1;
        let generation = self.next_gen;
        let peer = Peer::connect(
            peer_id.clone(),
            polite,
            cfg.ice_servers,
            self.relay_only,
            self.sio.clone(),
            self.tx.clone(),
            generation,
        )
        .await?;
        self.links.insert(
            peer_id,
            Link {
                peer,
                info,
                name,
                uid: peer_uid,
                transport: None,
                generation,
                attempts: 0,
                trusted: false,
                expected_secret: None,
                presence: Presence::Connecting,
            },
        );
        Ok(())
    }

    /// C3/C4: watchdog or grace expiry — retry that LINK with fresh config,
    /// up to MAX_ATTEMPTS, then drop it. Returns true when the exhausted link
    /// was the active transfer target (send decides whether that is fatal).
    async fn on_stuck(&mut self, pid: &str, generation: u32, why: &str) -> Result<bool> {
        // C21: don't burn retry attempts against a peer that told us it's
        // away — re-dialing a suspended tab is wasted attrition.
        if self.is_away(pid) {
            return Ok(false);
        }
        let Some(l) = self.links.get(pid) else { return Ok(false) };
        if l.generation != generation || l.peer.is_connected() {
            return Ok(false); // stale timer from a superseded attempt
        }
        let attempts = l.attempts + 1;
        if attempts >= MAX_ATTEMPTS {
            let was_active = self.is_active(pid);
            eprintln!(
                "{}",
                ui::paint(ui::Tone::Dim, &format!("dropping peer (connection {why} after {attempts} attempts)"))
            );
            self.drop_link(pid);
            return Ok(was_active);
        }
        eprintln!("connection {why} — retrying ({}/{})", attempts + 1, MAX_ATTEMPTS);
        let info = l.info.clone();
        let secret = l.expected_secret.clone();
        // C26: a link that was ever up is *re*connecting; one that never
        // connected is still just connecting — keeps "recovered" honest.
        let prev = match l.presence {
            Presence::Connecting => Presence::Connecting,
            _ => Presence::Reconnecting,
        };
        let was_active = self.is_active(pid);
        self.establish(info).await?;
        if let Some(nl) = self.links.get_mut(pid) {
            nl.attempts = attempts;
            nl.expected_secret = secret;
            nl.presence = prev;
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        Ok(false)
    }

    /// C4: transient `disconnected` — nudge ICE from the impolite side and
    /// give it grace before treating it as failure. C21: a peer that said
    /// `brb` gets its declared window instead of the 6 s blip grace, and no
    /// scary message.
    async fn on_pc_state(&mut self, pid: &str, s: &str) {
        let away = self.is_away(pid);
        let Some(l) = self.links.get_mut(pid) else { return };
        // C26: collect the announcement, print after the borrow ends so the
        // roster can read every link.
        let mut announce: Option<(&'static str, ui::Tone, &'static str)> = None;
        match s {
            "connected" => {
                if l.presence == Presence::Reconnecting {
                    announce = Some((ui::glyph_ok(), ui::Tone::Ok, "recovered"));
                }
                l.presence = Presence::Ready;
                l.attempts = 0;
            }
            "disconnected" => {
                let grace = if away {
                    l.presence = Presence::Away;
                    if let Some((_, until)) = &self.away {
                        until.duration_since(Instant::now()) + Duration::from_secs(15)
                    } else {
                        Duration::from_secs(6)
                    }
                } else {
                    l.presence = Presence::Reconnecting;
                    announce = Some(("◌", ui::Tone::Warn, "reconnecting…"));
                    Duration::from_secs(6)
                };
                if !l.peer.polite && !away {
                    l.peer.restart_ice().await;
                }
                let tx = self.tx.clone();
                let pid = pid.to_string();
                let generation = l.generation;
                tokio::spawn(async move {
                    tokio::time::sleep(grace).await;
                    let _ = tx.send(Ev::GraceExpired(pid, generation));
                });
            }
            _ => {}
        }
        if let Some((mark, tone, note)) = announce {
            ui::say(&self.roster(pid, mark, tone, note, "peer"));
        }
    }

    /// A peer's socket died. Drop its link; if it was the active target, open
    /// the rejoin window (their client auto-rejoins; C6 supersede completes
    /// the recovery). Returns true if the ACTIVE peer left.
    fn on_peer_left(&mut self, v: &Value) -> bool {
        let Some(pid) = v["id"].as_str() else { return false };
        self.roster.remove(pid);
        if !self.links.contains_key(pid) {
            return false;
        }
        let was_active = self.is_active(pid);
        self.drop_link(pid);
        if was_active {
            // C21: informed waits — a peer that declared `brb` gets its
            // promised window (plus slack); an unannounced vanish gets the
            // short default. Their client auto-rejoins; C6 supersede or a
            // fresh adopt completes the recovery.
            self.rejoin_window = match &self.away {
                Some((apid, until)) if apid == pid && *until > Instant::now() => {
                    until.duration_since(Instant::now()) + Duration::from_secs(15)
                }
                _ => rejoin_unwarned(),
            };
            self.waiting_rejoin = Some(Instant::now());
        }
        was_active
    }

    /// C21: any traffic from a peer cancels its declared absence.
    fn note_alive(&mut self, pid: &str) {
        if matches!(&self.away, Some((apid, _)) if apid == pid) {
            self.away = None;
        }
    }

    /// C26: set a link's roster presence; returns its name for the announce.
    fn link_presence(&mut self, pid: &str, p: Presence) -> String {
        match self.links.get_mut(pid) {
            Some(l) => {
                l.presence = p;
                l.name.clone()
            }
            None => String::new(),
        }
    }

    fn is_away(&self, pid: &str) -> bool {
        matches!(&self.away, Some((apid, until)) if apid == pid && *until > Instant::now())
    }

    /// C26: one static colored status line showing EVERY peer, the changed
    /// one carrying the note — `✓ daring-wombat   ● deft-gibbon  away…`.
    /// `fallback_name` covers a peer already dropped from the map (peer-left).
    fn roster(&self, pid: &str, mark: &str, tone: ui::Tone, note: &str, fallback_name: &str) -> String {
        let mut links: Vec<(&String, &Link)> = self.links.iter().collect();
        links.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        let mut parts = Vec::new();
        let mut seen = false;
        for (id, l) in links {
            if id == pid {
                seen = true;
                parts.push(peer_entry(&l.name, mark, tone, note));
            } else {
                let (m, t, n) = presence_glyph(l.presence);
                parts.push(peer_entry(&l.name, m, t, n));
            }
        }
        if !seen {
            parts.push(peer_entry(fallback_name, mark, tone, note));
        }
        format!("  {}", parts.join("   "))
    }

    /// #7 for the CLI: an offer from a roster peer we haven't linked yet
    /// creates a polite responder link. Stray signals from unknowns drop.
    async fn ensure_responder(&mut self, from: &str, data: &Value) -> Result<()> {
        if self.links.contains_key(from) {
            return Ok(());
        }
        if data["type"].as_str() == Some("description")
            && data["description"]["type"].as_str() == Some("offer")
        {
            if let Some(info) = self.roster.get(from).cloned() {
                if self.links.len() < MAX_LINKS {
                    self.establish(info).await?;
                }
            }
        }
        Ok(())
    }
}

/// Receive the next event; while a rejoin window is open, tick every second
/// so the window can expire AND the countdown stays visible (C22 — "45s"
/// frozen on screen reads as broken).
async fn next_ev(
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    conn: &Conn,
    suppress_countdown: bool,
) -> Result<Option<Ev>> {
    if let Some(since) = conn.waiting_rejoin {
        if since.elapsed() > conn.rejoin_window {
            ui::clear_sticky();
            bail!(
                "peer did not come back within {}s (partial state kept for resume)",
                conn.rejoin_window.as_secs()
            );
        }
        if !suppress_countdown {
            let left = conn.rejoin_window.saturating_sub(since.elapsed()).as_secs();
            ui::sticky(&ui::paint(
                ui::Tone::Dim,
                &format!("  {} holding the line — {left}s for them to come back (Ctrl-C to stop)", ui::spinner_frame()),
            ));
        }
        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    } else {
        rx.recv().await.map(Some).ok_or_else(|| anyhow!("signaling channel closed"))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // F2: both ring (webrtc) and aws-lc (reqwest) end up in the dep tree;
    // rustls refuses to guess between two providers, so pick ring explicitly
    // BEFORE anything touches TLS.
    rustls::crypto::ring::default_provider().install_default().ok();
    // Bare-arg comfort dispatch: `filament <path>` sends it with a code;
    // `filament <something-like-a-code>` claims it. Subcommands still win.
    let mut argv: Vec<String> = std::env::args().collect();
    if let Some(first) = argv.get(1) {
        const CMDS: [&str; 12] = ["send", "recv", "devices", "update", "completions", "man", "config", "help", "up", "status", "down", "introduce"];
        let code_re = regex_lite_code(first);
        if !first.starts_with('-') && !CMDS.contains(&first.as_str()) {
            if std::path::Path::new(first).exists() {
                argv.insert(1, "send".into());
                argv.push("--code".into());
            } else if code_re {
                argv.insert(1, "recv".into());
            }
        }
    }
    let cli = Cli::parse_from(argv);
    if let Some(n) = &cli.name_as {
        // single-threaded at this point (before the runtime spawns workers)
        unsafe { std::env::set_var("FILAMENT_NAME", n) };
    }
    let server = if cli.server == DEFAULT_SERVER {
        config_get("server").unwrap_or(cli.server.clone())
    } else {
        cli.server.clone()
    };
    let server = server.trim_end_matches('/').to_string();
    match cli.cmd {
        Cmd::Send { paths, code, word, room, to, name, remember } => {
            send_cmd(&server, paths, code || word.is_some(), word, room, to, name, cli.relay, remember).await
        }
        Cmd::Recv { code, dir, yes, room, to, keep_open, remember, output } => {
            recv_cmd(&server, code, dir, yes, room, to, keep_open, cli.relay, remember, false, output).await
        }
        Cmd::Config { key, value } => {
            match (key, value) {
                (Some(k), Some(v)) => {
                    config_set(&k, &v)?;
                    println!("{k} = {v}");
                }
                (Some(k), None) => println!("{}", config_get(&k).unwrap_or_default()),
                (None, _) => {
                    for k in ["name", "server", "dir"] {
                        if let Some(v) = config_get(k) {
                            println!("{k} {v}");
                        }
                    }
                }
            }
            Ok(())
        }
        Cmd::Up { install, dir } => up_cmd(&server, install, dir, cli.relay).await,
        Cmd::Status => status_cmd(),
        Cmd::Down => down_cmd(),
        Cmd::Introduce { a, b } => introduce_cmd(&server, &a, &b, cli.relay).await,
        Cmd::Pair { code, name } => pair_cmd(&server, code, name, cli.relay).await,
        Cmd::Devices { action } => {
            match action {
                None => {
                    let all = devices_load();
                    if all.is_empty() {
                        println!("no known devices yet — run `filament pair` to add one");
                    }
                    for (n, s) in all {
                        println!("{n}  (channel {})", &channel_of(&s)[..12]);
                    }
                }
                Some(DevicesAction::Forget { name }) => {
                    let had = devices_load().iter().any(|(n, _)| n == &name);
                    if !had {
                        bail!("no device named '{name}' — see `filament devices`");
                    }
                    devices_remove(&name)?;
                    println!("forgot '{name}' — it can no longer find or auto-connect to this machine");
                    println!("(their side still holds its half; it will hear \"never met you\" on the next proof)");
                }
                Some(DevicesAction::Rename { old, new }) => {
                    let all = devices_load();
                    let Some((_, sec)) = all.iter().find(|(n, _)| n == &old) else {
                        bail!("no device named '{old}' — see `filament devices`");
                    };
                    if all.iter().any(|(n, _)| n == &new) {
                        bail!("'{new}' already exists — forget it first or pick another name");
                    }
                    let sec = sec.clone();
                    devices_remove(&old)?;
                    devices_store(&new, &sec)?;
                    println!("renamed '{old}' -> '{new}' (local alias only — the secret, and the other side, are unchanged)");
                }
            }
            Ok(())
        }
        Cmd::Update { check, beta } => update_cmd(check, beta).await,
        Cmd::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut Cli::command(), "filament", &mut std::io::stdout());
            Ok(())
        }
        Cmd::Man => {
            use clap::CommandFactory;
            clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
            Ok(())
        }
    }
}

// ----------------------------------------------------------------- update --
// Self-update against GitHub releases (tags cli-vX.Y.Z). Downloads the
// archive for this platform, verifies it against SHA256SUMS, and atomically
// replaces the current executable.

const REPO: &str = "Abdk4Moura/filament";

fn release_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

async fn update_cmd(check_only: bool, beta: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("filament/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Latest cli-v* release via the API (releases/latest may point at a web
    // release tag, so filter explicitly). Prereleases are SKIPPED unless the
    // user opted in (--beta) or is already running a prerelease — a beta tag
    // must never be pushed onto stable users.
    let beta_ok = beta || env!("CARGO_PKG_VERSION").contains('-');
    let releases: Value = client
        .get(format!("https://api.github.com/repos/{REPO}/releases?per_page=20"))
        .send()
        .await?
        .json()
        .await?;
    // semver-aware: never "update" to an older or equal release (betas of
    // the next version outrank the previous release; -pre < its release).
    fn key(v: &str) -> (u64, u64, u64, bool) {
        let (core, pre) = v.split_once('-').map(|(c, _)| (c, true)).unwrap_or((v, false));
        let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0), !pre)
    }
    // Pick the HIGHEST eligible version, not the first listed — the API's
    // order is not newest-tag-first (observed live: cli-v0.2.0 listed above
    // cli-v0.2.1-beta.1, which made --beta serve stable).
    let latest = releases
        .as_array()
        .and_then(|a| {
            a.iter()
                .filter(|r| {
                    r["tag_name"].as_str().is_some_and(|t| t.starts_with("cli-v"))
                        && (beta_ok || !r["prerelease"].as_bool().unwrap_or(false))
                })
                .max_by_key(|r| key(r["tag_name"].as_str().unwrap_or_default().trim_start_matches("cli-v")))
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

    let target = release_target().ok_or_else(|| anyhow!("no prebuilt binary for this platform; build from source"))?;
    let (asset, inner) = if cfg!(windows) {
        (format!("filament-{target}.zip"), "filament.exe")
    } else {
        (format!("filament-{target}.tar.gz"), "filament")
    };
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");

    eprintln!("downloading {asset} ...");
    let bytes = client.get(format!("{base}/{asset}")).send().await?.error_for_status()?.bytes().await?;
    let sums = client.get(format!("{base}/SHA256SUMS")).send().await?.error_for_status()?.text().await?;
    let got = sha256_hex(&bytes);
    let expected = sums
        .lines()
        .find(|l| l.contains(&asset))
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| anyhow!("{asset} missing from SHA256SUMS"))?;
    if got != expected {
        bail!("checksum mismatch for {asset}: got {got}, expected {expected}");
    }
    eprintln!("checksum ok");

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
        bail!("zip self-update not supported yet; download {base}/{asset} manually");
    };

    // Atomic replace: write next to the current exe, then rename over it.
    let me = std::env::current_exe()?;
    let staging = me.with_extension("update-staging");
    std::fs::write(&staging, &new_bin)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&staging, &me).with_context(|| format!("replacing {}", me.display()))?;
    println!("updated to {latest_ver} -> {}", me.display());
    Ok(())
}

// ------------------------------------------------------------------- send --

struct Outgoing {
    id: String,
    sid: u32,
    name: String,
    size: u64,
    head: Option<String>,
    path: PathBuf,
    temp: bool,          // delete after sending (tar spools, stdin spools)
    accepted_once: bool, // re-offers carry resume:true after first accept
    done: bool,
}

#[allow(clippy::too_many_arguments)]
async fn send_cmd(
    server: &str,
    paths: Vec<String>,
    use_code: bool,
    word: Option<String>,
    room: Option<String>,
    to: Option<String>,
    stdin_name: String,
    relay: bool,
    remember: Option<String>,
) -> Result<()> {
    if paths.is_empty() {
        bail!("nothing to send — pass files, directories, or '-' for stdin");
    }
    let my_uid = mk_uid("s");
    let mut outgoing: Vec<Outgoing> = Vec::new();
    for (i, p) in paths.iter().enumerate() {
        let sid = (i + 1) as u32;
        let id = format!("{}-{}", my_uid, sid);
        if p == "-" {
            let spool = std::env::temp_dir().join(format!("filament-stdin-{}", std::process::id()));
            let mut f = std::fs::File::create(&spool)?;
            let n = std::io::copy(&mut std::io::stdin().lock(), &mut f)?;
            drop(f);
            let head = head_hash(&spool);
            outgoing.push(Outgoing { id, sid, name: stdin_name.clone(), size: n, head, path: spool, temp: true, accepted_once: false, done: false });
        } else {
            let path = PathBuf::from(p);
            let meta = std::fs::metadata(&path).with_context(|| format!("stat {p}"))?;
            if meta.is_dir() {
                let dirname = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dir".into());
                let spool = std::env::temp_dir().join(format!("filament-tar-{}-{}.tar", std::process::id(), i));
                eprintln!("packing {p} -> {dirname}.tar ...");
                {
                    let f = std::fs::File::create(&spool)?;
                    let mut b = tar::Builder::new(f);
                    b.append_dir_all(&dirname, &path)?;
                    b.finish()?;
                }
                let size = std::fs::metadata(&spool)?.len();
                let head = head_hash(&spool);
                outgoing.push(Outgoing { id, sid, name: format!("{dirname}.tar"), size, head, path: spool, temp: true, accepted_once: false, done: false });
            } else {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone());
                let head = head_hash(&path);
                outgoing.push(Outgoing { id, sid, name, size: meta.len(), head, path, temp: false, accepted_once: false, done: false });
            }
        }
    }
    for o in &outgoing {
        eprintln!("send: {} ({})", o.name, human(o.size));
    }

    let room = match room {
        Some(r) => r,
        None => net::fetch_auto_room(server).await?,
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    sio.emit("join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await.ok();

    // C12: --to matching a remembered device switches to identity mode —
    // subscribe to its presence channel and wait for known-peer.
    let known_target: Option<(String, String)> =
        to.as_ref().and_then(|t| devices_load().into_iter().find(|(n, _)| n.eq_ignore_ascii_case(t)));
    if let Some((n, sec)) = &known_target {
        ui::say(&format!("  waiting for known device {}", ui::paint(ui::Tone::Bold, n)));
        sio.emit("subscribe", json!({ "channels": [channel_of(sec)] })).await.ok();
    } else if use_code {
        let payload = match &word {
            Some(w) => json!({ "keyword": w }),
            None => json!({}),
        };
        sio.emit("pair-create", payload).await.ok();
    } else {
        eprintln!("waiting for a peer in room {room} (same network auto-discovers; or use --code)");
    }
    // Live spinner while nothing is connected yet (tty only; stops at adopt).
    let waiting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let waiting = waiting.clone();
        tokio::spawn(async move {
            while waiting.load(std::sync::atomic::Ordering::Relaxed) {
                ui::status(&format!("  {} waiting…", ui::spinner_frame()));
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
        });
    }

    let mut conn = Conn {
        server: server.to_string(),
        sio: sio.clone(),
        tx: tx.clone(),
        my_uid,
        my_id: String::new(),
        relay_only: relay,
        to_filter: to,
        links: HashMap::new(),
        roster: HashMap::new(),
        active: None,
        next_gen: 0,
        waiting_rejoin: None,
        rejoin_window: REJOIN_WINDOW,
        away: None,
        chunk_size: net::MAX_DC_PAYLOAD,
    };
    if known_target.is_some() {
        conn.to_filter = None; // identity supersedes name matching
    }
    let mut code_used = !use_code && known_target.is_none();
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }
    let outgoing = Arc::new(tokio::sync::Mutex::new(outgoing));
    let started = Instant::now();
    let claim_deadline = Duration::from_secs(600);

    loop {
        // The wait-for-peer deadline only applies while we have no peer (F3).
        let ev = if conn.active.is_none() && conn.waiting_rejoin.is_none() {
            match tokio::time::timeout(claim_deadline.saturating_sub(started.elapsed()), rx.recv()).await {
                Ok(Some(ev)) => Some(ev),
                Ok(None) => bail!("signaling channel closed"),
                Err(_) => bail!("timed out waiting for a peer — is the other device online and on the same server? (--code makes pairing explicit)"),
            }
        } else {
            next_ev(&mut rx, &conn, false).await?
        };
        let Some(ev) = ev else { continue };

        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, code_used).await?;
                    }
                }
                // C28: fresh sid = dead subscriptions; re-assert the target's
                // channel or a blip strands `send --to` waiting forever.
                if let Some((_, sec)) = &known_target {
                    sio.emit("subscribe", json!({ "channels": [channel_of(sec)] })).await.ok();
                }
            }
            Ev::PairCode(v) => {
                let code = v["code"].as_str().unwrap_or("?");
                let ttl = v["ttl"].as_u64().unwrap_or(600);
                let site = if server == DEFAULT_SERVER { "https://filament.autumated.com".to_string() } else { server.to_string() };
                let room_url = format!("{site}/rooms/{room}");
                ui::clipboard(code);
                ui::say("");
                ui::say(&format!("  code   {}   {}", ui::paint(ui::Tone::Brand, code), ui::paint(ui::Tone::Dim, "(copied to clipboard)")));
                ui::say(&format!("         {}", ui::paint(ui::Tone::Dim, &format!("terminal: filament recv {code}   browser: {} (PAIR WITH CODE)", ui::link(&site, &site.replace("https://", ""))))));
                let q = ui::qr(&room_url);
                if !q.is_empty() {
                    ui::say(&format!("\n{}", q.trim_end_matches('\n')));
                    ui::say(&format!("         {}", ui::paint(ui::Tone::Dim, &format!("or scan to join instantly · one claim · {} min", ttl / 60))));
                }
                ui::say("");
            }
            Ev::PairError(v) => bail!("pairing failed: {}", v["error"].as_str().unwrap_or("?")),
            Ev::PairUsed(_) => {
                eprintln!("code claimed — connecting...");
                code_used = true;
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, code_used).await?;
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own daemon shares this channel
                }
                if let Some((n, sec)) = &known_target {
                    if v["channel"].as_str() == Some(channel_of(sec).as_str()) {
                        eprintln!("known device '{n}' is online — connecting");
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        conn.maybe_adopt(&v, true).await?;
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = Some((n.clone(), sec.clone()));
                        }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                if let Some(l) = conn.link(&from) {
                    // Never fatal (F6): the watchdog/grace machinery owns
                    // failed negotiations.
                    if let Err(e) = l.peer.handle_signal(data).await {
                        eprintln!("signal failed to apply: {e} (recovering)");
                    }
                }
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                }
                // Responder links stop here: connected, polite, idle. Only
                // the active target gets announcements + offers.
                if !conn.is_active(&pid) {
                    continue;
                }
                waiting.store(false, std::sync::atomic::Ordering::Relaxed);
                if let Some(l) = conn.link(&pid) {
                    ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, &l.name)));
                    let p = l.peer.clone();
                    tokio::spawn(async move {
                        // ICE may renominate; retry briefly (mirrors the
                        // browser's _detectRoute attempts) so fast transfers
                        // still get a route line before the process exits.
                        for _ in 0..6 {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                            if let Some(r) = p.route().await {
                                ui::say(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {r}"))));
                                break;
                            }
                        }
                    });
                    // C12: prove identity to a known device (their daemon
                    // auto-accepts only after verifying); or hand over a new
                    // pair secret when the user asked to --remember.
                    if let Some((_n, sec)) = &l.expected_secret {
                        if let Some((my_fp, their_fp)) = l.peer.fingerprints().await {
                            t.send_control(&json!({
                                "type": "pair-proof",
                                "mac": proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                            })).await?;
                        } else {
                            eprintln!("{}", ui::paint(ui::Tone::Warn, "no DTLS fingerprints available — skipping identity proof"));
                        }
                    } else if let (Some(name), true) = (&remember, use_code) {
                        let sec = fresh_secret();
                        t.send_control(&json!({ "type": "pair-keep", "secret": sec })).await?;
                        devices_store(name, &sec)?;
                        eprintln!("remembered this device as '{name}' (they must also pass --remember)");
                    }
                    // (Re-)offer everything unfinished; resume:true after a
                    // prior accept so receivers continue from their partial.
                    for o in outgoing.lock().await.iter() {
                        if o.done {
                            continue;
                        }
                        let mut offer = json!({
                            "type": "file-offer", "id": o.id, "sid": o.sid,
                            "name": o.name, "size": o.size, "mime": "application/octet-stream",
                        });
                        if let Some(h) = &o.head {
                            offer["head"] = json!(h);
                        }
                        if o.accepted_once {
                            offer["resume"] = json!(true);
                        }
                        t.send_control(&offer).await?;
                    }
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                _ if !conn.is_active(&pid) => {}
                Some("brb") => {
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.away = Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    ui::say(&conn.roster(&pid, "●", ui::Tone::Warn, "away — holding the line", &n));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                // C27: the human on the other side answered our remember offer.
                Some("pair-keep-ack") => {
                    if let Some(name) = &remember {
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if v["ok"].as_bool() == Some(false) {
                            devices_remove(name)?;
                            ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "declined to be remembered — nothing stored", &n));
                        } else {
                            ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "mutually remembered — you'll reconnect automatically", &n));
                        }
                    }
                }
                // C27: their verdict on our identity proof. false = they have
                // no memory of us — stop acting like a known device.
                Some("pair-proof-ack") => {
                    if v["ok"].as_bool() == Some(false) {
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = None;
                        }
                        ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "doesn't recognize this device — re-pair with --remember", &n));
                    }
                }
                Some("file-accept") => {
                    let Some(t) = conn.transport() else { continue };
                    let offset = v["offset"].as_u64().unwrap_or(0);
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    {
                        let mut out = outgoing.lock().await;
                        if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                            o.accepted_once = true;
                        }
                    }
                    let out = outgoing.clone();
                    let chunk = conn.chunk_size.min(t.max_payload());
                    let tx2 = tx.clone();
                    tokio::spawn(async move {
                        match stream_one(out, t, id.clone(), offset, chunk).await {
                            Ok(()) => {
                                let _ = tx2.send(Ev::TransferDone(id));
                            }
                            Err(e) => {
                                // C10: surface through the loop; the transfer
                                // stays pending and re-offers on reconnect.
                                let _ = tx2.send(Ev::TransferFailed { id, err: e.to_string() });
                            }
                        }
                    });
                }
                Some("file-decline") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        eprintln!("declined: {}", o.name);
                        o.done = true;
                    }
                }
                _ => {}
            },
            Ev::TransferFailed { id, err } => {
                let out = outgoing.lock().await;
                let name = out.iter().find(|o| o.id == id).map(|o| o.name.as_str()).unwrap_or("?");
                eprintln!("{name}: interrupted ({err}) — will resume on reconnect");
            }
            Ev::Interrupted => {
                ui::say(&format!("  {} interrupted — the receiver keeps its partial; re-run the same command to resume", ui::paint(ui::Tone::Warn, "!")));
                let _ = sio.disconnect().await;
                std::process::exit(130);
            }
            Ev::Stuck(pid, generation) => {
                if conn.on_stuck(&pid, generation, "stuck while connecting").await? {
                    bail!("lost the receiving peer after {} attempts", MAX_ATTEMPTS);
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? {
                    bail!("lost the receiving peer after {} attempts", MAX_ATTEMPTS);
                }
            }
            Ev::PcState(pid, s) => conn.on_pc_state(&pid, &s).await,
            Ev::PeerLeft(v) => {
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let all_done = outgoing.lock().await.iter().all(|o| o.done);
                    if !all_done {
                        let secs = REJOIN_WINDOW.as_secs();
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => ui::say(&conn.roster(gid, "○", ui::Tone::Dim, &format!("disconnected — waiting up to {secs}s"), &n)),
                            None => eprintln!("peer disconnected — waiting up to {secs}s for them to come back"),
                        }
                    }
                }
            }
            _ => {}
        }
        // Exit when every transfer reached a terminal state.
        {
            let out = outgoing.lock().await;
            if !out.is_empty() && out.iter().all(|o| o.done) {
                if let Some(t) = conn.transport() {
                    t.flush().await.ok();
                }
                for o in out.iter().filter(|o| o.temp) {
                    let _ = std::fs::remove_file(&o.path);
                }
                eprintln!("done.");
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = sio.disconnect().await;
                return Ok(());
            }
        }
    }
}

async fn stream_one(
    outgoing: Arc<tokio::sync::Mutex<Vec<Outgoing>>>,
    t: Arc<dyn Transport>,
    id: String,
    offset: u64,
    chunk: usize,
) -> Result<()> {
    let (sid, name, size, path) = {
        let out = outgoing.lock().await;
        let o = out.iter().find(|o| o.id == id).ok_or_else(|| anyhow!("unknown transfer {id}"))?;
        (o.sid, o.name.clone(), o.size, o.path.clone())
    };
    if offset > 0 {
        eprintln!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0);
    }
    let mut f = std::fs::File::open(&path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut sent = offset;
    let mut buf = vec![0u8; chunk];
    let mut bar = ui::Progress::new(&name, size);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        t.send_frame(sid, &buf[..n]).await?;
        sent += n as u64;
        bar.tick(sent);
    }
    t.send_control(&json!({ "type": "file-end", "id": id, "sid": sid })).await?;
    t.flush().await?;
    bar.done(sent - offset);
    let mut out = outgoing.lock().await;
    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
        o.done = true;
    }
    Ok(())
}

// ------------------------------------------------------------------- recv --

struct IncomingFile {
    #[allow(dead_code)] // transfer id; will key decline/cancel when added
    id: String,
    name: String,
    size: u64,
    received: u64,
    file: tokio::io::BufWriter<tokio::fs::File>,
    part_path: PathBuf,
    bar: ui::Progress,
}

#[allow(clippy::too_many_arguments)]
async fn recv_cmd(
    server: &str,
    code: Option<String>,
    dir: PathBuf,
    yes: bool,
    room: Option<String>,
    to: Option<String>,
    keep_open: bool,
    relay: bool,
    remember: Option<String>,
    daemon: bool,
    output: Option<String>,
) -> Result<()> {
    let to_stdout = output.as_deref() == Some("-");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let my_uid = mk_uid("r");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;

    let mut paired = code.is_some();
    // C24: at most one typed claim in flight — a second typed code while one
    // is pending was silently dropped in live use; now it queues a message.
    let mut claim_in_flight = false;
    // C29: an in-session pairing ceremony (daemon mode): typed code or a
    // minted one — exactly ONE side hands over a fresh secret (creator
    // initiates; a claimer waits 3 s for the creator, then takes over —
    // browsers never initiate). Some(true) = we minted; Some(false) = we
    // claimed; None = no ceremony pending.
    let mut ceremony: Option<bool> = None;
    let mut ceremony_pid: Option<String> = None;
    let mut ceremony_secret = fresh_secret();
    // C25: when the current question appeared (answers sooner than 300ms are
    // buffered keystrokes, not decisions)
    let mut question_shown = Instant::now();
    let mut devices = devices_load(); // channel -> identity lookup for proofs
    match &code {
        Some(c) => {
            sio.emit("pair-claim", json!({ "code": c.trim().to_lowercase() })).await.ok();
        }
        None if daemon => {
            // C19: the daemon joins NO room. Presence-channel subscriptions
            // only — strangers can't see it, probe it, or offer to it.
            // (We still `join` an unguessable solo room so the registry holds
            // our meta for known-peer events, but nobody else can land there.)
            let solo = format!("up-{}", fresh_secret());
            sio.emit("join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await.ok();
            // C29: an interactive up can START empty and pair in-session.
            if devices.is_empty() && !std::io::stdin().is_terminal() {
                bail!("no known devices — run `filament pair` once, or `filament up` in a terminal to pair interactively");
            }
            let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
            sio.emit("subscribe", json!({ "channels": chans })).await.ok();
            ui::say(&format!(
                "  {} filament up — {} known device{} {} {}",
                ui::paint(ui::Tone::Brand, "●"),
                devices.len(),
                if devices.len() == 1 { "" } else { "s" },
                ui::glyph_arrow(),
                ui::paint(ui::Tone::Bold, &dir.display().to_string()),
            ));
            ui::say(&ui::paint(ui::Tone::Dim, "  trusted devices only · invisible to strangers · Ctrl-C or `filament down` to stop"));
            // C29: this is a SESSION, like a browser tab — pairing and petname
            // management happen right here.
            if std::io::stdin().is_terminal() {
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  type a code to pair a new device · `pair` mints one · `devices` · `forget <name>`",
                ));
            }
        }
        None => {
            let room = match &room {
                Some(r) => r.clone(),
                None => net::fetch_auto_room(server).await?,
            };
            // C22: proactive affordance — tell the user what they CAN do,
            // cargo-style gutter, before they have to guess.
            ui::say(&format!(
                "  {} listening — same-network devices appear automatically  {}",
                ui::paint(ui::Tone::Brand, "●"),
                ui::paint(ui::Tone::Dim, &format!("(room {room} · dir {})", dir.display())),
            ));
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  have a code? just type it here (like brave-otter-123) and press Enter",
            ));
            sio.emit("join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await.ok();
            // C12: announce on every known device's presence channel
            if !devices.is_empty() {
                let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
                eprintln!("watching for {} known device(s)", devices.len());
                sio.emit("subscribe", json!({ "channels": chans })).await.ok();
            }
        }
    }

    let mut conn = Conn {
        server: server.to_string(),
        sio: sio.clone(),
        tx: tx.clone(),
        my_uid: my_uid.clone(),
        my_id: String::new(),
        relay_only: relay,
        to_filter: to,
        links: HashMap::new(),
        roster: HashMap::new(),
        active: None,
        next_gen: 0,
        waiting_rejoin: None,
        rejoin_window: REJOIN_WINDOW,
        away: None,
        chunk_size: net::MAX_DC_PAYLOAD,
    };
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }
    #[cfg(unix)]
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                term.recv().await;
                let _ = tx.send(Ev::Interrupted);
            }
        });
    }
    // A listening recv accepts a code typed straight into it — the first
    // thing real users try (observed live). C22: stdin runs RAW (cbreak) on a
    // tty so an open y/N question resolves on a single keypress, no Enter;
    // outside a question, bytes accumulate into lines (echoed manually since
    // raw mode disables terminal echo).
    let question_open = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // C29: the stdin owner also runs for an INTERACTIVE daemon (a terminal-
    // attached `filament up` is a session); `up --install` under systemd has
    // no tty, so headless daemons stay stdin-free.
    let interactive = !daemon || std::io::stdin().is_terminal();
    let tty_guard = if interactive && std::io::stdin().is_terminal() { Some(TtyGuard::raw()) } else { None };
    if interactive {
        let tx = tx.clone();
        let q = question_open.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 1];
            let mut line = String::new();
            while stdin.read(&mut buf).await.map(|n| n == 1).unwrap_or(false) {
                let c = buf[0] as char;
                if q.load(std::sync::atomic::Ordering::Relaxed) && "yYnN".contains(c) && line.is_empty() {
                    ui::answer_echo(c); // raw mode is no-echo; land it cleanly (C23)
                    let _ = tx.send(Ev::StdinLine(c.to_lowercase().to_string()));
                    continue;
                }
                match buf[0] {
                    b'\n' | b'\r' => {
                        eprintln!();
                        let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                        line.clear();
                    }
                    0x7f | 0x08 => {
                        if line.pop().is_some() {
                            eprint!("\x08 \x08");
                        }
                    }
                    _ if !c.is_control() => {
                        eprint!("{c}");
                        line.push(c);
                    }
                    _ => {}
                }
            }
        });
    }
    let mut by_sid: HashMap<(String, u32), IncomingFile> = HashMap::new();
    // C22: offers awaiting consent — exactly ONE stdin owner (the reader
    // task); answers arrive as StdinLine events, never via a competing
    // blocking read racing for the user's "y".
    let mut pending: std::collections::VecDeque<(String, Value)> = Default::default();
    let mut completed = 0usize;
    // G-k: peer-left delivery is best-effort — a browser can close having
    // delivered every byte yet never emit its leave (observed under load,
    // gate 6). Tick the loop on a 2s timeout so a fallback quiet-check can
    // exit cleanly instead of idling to the connect-timeout.
    let mut last_quiet: Option<Instant> = None;

    loop {
        let ev = match tokio::time::timeout(
            Duration::from_secs(2),
            next_ev(&mut rx, &conn, !pending.is_empty()),
        )
        .await
        {
            Ok(res) => res?,
            Err(_) => None, // 2s tick — run the fallback quiet-check below
        };

        // G-k fallback: everything done, nobody attached, no questions
        // outstanding — if that holds quietly for 10s, the peer-left we were
        // counting on for a clean exit never arrived; exit anyway.
        if completed > 0 && !keep_open && by_sid.is_empty() && conn.links.is_empty() && pending.is_empty() {
            match last_quiet {
                None => last_quiet = Some(Instant::now()),
                Some(since) if since.elapsed() > Duration::from_secs(10) => {
                    ui::say(&ui::paint(ui::Tone::Dim, "  (peer-left never arrived — exiting on quiet)"));
                    eprintln!("done ({completed} file{}).", if completed == 1 { "" } else { "s" });
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
                Some(_) => {}
            }
        } else {
            last_quiet = None;
        }

        let Some(ev) = ev else { continue };

        // C23: questions from links that died (supersede/peer-left) are
        // moot — the sender re-offers on its new link. Purge them so a 'y'
        // can never accept a ghost (the duplicate-stream ENOENT crash).
        if !pending.is_empty() {
            let front_id = pending.front().map(|(_, v)| v["id"].clone());
            pending.retain(|(p, _)| conn.links.contains_key(p));
            if pending.front().map(|(_, v)| v["id"].clone()) != front_id {
                ui::clear_sticky();
                if let Some((qpid, qv)) = pending.front() {
                    let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                    {
                        let q = offer_question(&s, qv["name"].as_str().unwrap_or("file"), qv["size"].as_u64().unwrap_or(0), paired);
                        ui::say(&q); // permanent: a new question fronted (C25)
                        ui::sticky(&q);
                        question_shown = Instant::now();
                    }
                } else {
                    question_open.store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        match ev {
            Ev::PairMatched(v) => {
                claim_in_flight = false;
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ui::say(&format!("  {} code accepted — joining sender", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                sio.emit("join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await.ok();
            }
            // C29: a code minted in-session (`pair` typed into up).
            Ev::PairCode(v) => {
                let c = v["code"].as_str().unwrap_or("?");
                ui::clipboard(c);
                ui::say("");
                ui::say(&format!("      {}", ui::paint(ui::Tone::Brand, &c.to_uppercase())));
                ui::say("");
                ui::say(&ui::paint(ui::Tone::Dim, "  say it aloud — they type it in the web app or `filament pair <code>` · one claim · 10 min"));
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed — connecting…"));
            }
            Ev::PairError(v) => {
                let why = v["error"].as_str().unwrap_or("?").to_string();
                // The server distinguishes (additively) a dead creator from a
                // typo'd/expired code — say the actionable thing for each.
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => "the sender who made that code already left — ask them for a fresh one".to_string(),
                    _ => format!("{why} — codes burn after one use and expire after 10 min"),
                };
                if code.is_some() && conn.links.is_empty() && completed == 0 {
                    // started WITH a code that failed: nothing else to do
                    bail!("code rejected: {hint}");
                }
                // a TYPED claim failing must not kill a listening session
                paired = false;
                claim_in_flight = false;
                ui::say(&format!(
                    "  {} code rejected: {hint}; still listening",
                    ui::paint(ui::Tone::Err, ui::glyph_err()),
                ));
            }
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
                // C28: a welcome means a (re)connect with a FRESH sid — every
                // channel subscription died with the old one. Re-assert, or a
                // socket blip makes this daemon invisible to known devices
                // until restart (the browser-reload bug, CLI flavor).
                if !devices.is_empty() {
                    let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
                    sio.emit("subscribe", json!({ "channels": chans })).await.ok();
                }
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own sender/daemon shares these channels
                }
                if let Some((n, sec)) = devices.iter().find(|(_, s)| channel_of(s) == v["channel"].as_str().unwrap_or("")) {
                    eprintln!("known device '{n}' appeared — connecting");
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    conn.maybe_adopt(&v, true).await?;
                    if let Some(l) = conn.link_mut(&pid) {
                        l.expected_secret = Some((n.clone(), sec.clone()));
                    }
                }
            }
            Ev::PeerJoined(v) => {
                let had_partials = !by_sid.is_empty();
                if conn.maybe_adopt(&v, true).await? && had_partials {
                    // Stale per-link sid routing dies with the old link; the
                    // .part files live on and the sender's resume re-offers.
                    flush_inflight(&mut by_sid).await;
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                if let Some(l) = conn.link(&from) {
                    // Never fatal (F6): the watchdog/grace machinery owns
                    // failed negotiations.
                    if let Err(e) = l.peer.handle_signal(data).await {
                        eprintln!("signal failed to apply: {e} (recovering)");
                    }
                }
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, &l.name)));
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                    let p = l.peer.clone();
                    tokio::spawn(async move {
                        // ICE may renominate; retry briefly (mirrors the
                        // browser's _detectRoute attempts) so fast transfers
                        // still get a route line before the process exits.
                        for _ in 0..6 {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                            if let Some(r) = p.route().await {
                                ui::say(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {r}"))));
                                break;
                            }
                        }
                    });
                }
                // C29: an in-session pairing — exactly one side hands over a
                // secret; consent (pair-keep-ack / our store) completes it.
                // Only links that aren't ALREADY known are candidates.
                let fresh_link = conn.link(&pid).map(|l| l.expected_secret.is_none()).unwrap_or(false);
                if fresh_link {
                    match ceremony {
                        Some(true) => {
                            // we minted the code — initiate now
                            ceremony = None;
                            ceremony_pid = Some(pid.clone());
                            t.send_control(&json!({ "type": "pair-keep", "secret": ceremony_secret })).await.ok();
                        }
                        Some(false) => {
                            // we claimed — give a CLI creator 3 s to initiate
                            // (browsers never do), then take over.
                            let tx = tx.clone();
                            let pid = pid.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(3)).await;
                                let _ = tx.send(Ev::Control(pid, json!({ "type": "__pair_fallback" })));
                            });
                        }
                        None => {}
                    }
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                _ if !conn.links.contains_key(&pid) => {}
                Some("brb") => {
                    // C21: the peer announces a benign absence (mobile file
                    // picker suspends the tab). Hold the line that long.
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.away = Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    ui::say(&conn.roster(&pid, "●", ui::Tone::Warn, "away — choosing a file · holding the line", &n));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                Some("pair-keep") => {
                    let sec = v["secret"].as_str().unwrap_or_default().to_string();
                    if sec.len() == 64 {
                        let kept = if let Some(name) = &remember {
                            devices_store(name, &sec)?;
                            eprintln!("remembered this device as '{name}' — future sends auto-accept after proof");
                            true
                        } else if ceremony == Some(false) {
                            // C29: we typed their code into this session — the
                            // creator initiated first; that's our ceremony.
                            ceremony = None;
                            let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "device".into());
                            devices_store(&n, &sec)?;
                            devices.push((n.clone(), sec.clone()));
                            sio.emit("subscribe", json!({ "channels": [channel_of(&sec)] })).await.ok();
                            ui::say(&format!(
                                "  {} {} mutually remembered — rename anytime: filament devices rename {n} <new>",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                            true
                        } else {
                            eprintln!("(sender offered to be remembered; re-run with --remember <name> to keep it)");
                            false
                        };
                        // C27: answer either way — a declined sender discards
                        // its half instead of waving at a dead meeting point.
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep-ack", "ok": kept })).await.ok();
                        }
                    }
                }
                // C29: claimer fallback — the creator never initiated
                // (browsers don't); hand over OUR secret instead.
                Some("__pair_fallback") => {
                    if ceremony == Some(false) {
                        ceremony = None;
                        ceremony_pid = Some(pid.clone());
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep", "secret": ceremony_secret })).await.ok();
                        }
                    }
                }
                // C29: their answer to OUR in-session remember offer.
                Some("pair-keep-ack") => {
                    if ceremony_pid.as_deref() == Some(pid.as_str()) {
                        ceremony_pid = None;
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "device".into());
                        if v["ok"].as_bool() == Some(false) {
                            ui::say(&conn.roster(&pid, ui::glyph_err(), ui::Tone::Warn, "declined to be remembered — nothing stored", &n));
                        } else {
                            devices_store(&n, &ceremony_secret)?;
                            devices.push((n.clone(), ceremony_secret.clone()));
                            sio.emit("subscribe", json!({ "channels": [channel_of(&ceremony_secret)] })).await.ok();
                            ceremony_secret = fresh_secret(); // never reuse across devices
                            ui::say(&format!(
                                "  {} {} mutually remembered — rename anytime: filament devices rename {n} <new>",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                        }
                    }
                }
                Some("pair-proof") => {
                    let mac = v["mac"].as_str().unwrap_or_default();
                    let peer_uid = conn.link(&pid).and_then(|l| l.uid.clone()).unwrap_or_default();
                    let fps = match conn.link(&pid) {
                        Some(l) => l.peer.fingerprints().await,
                        None => None,
                    };
                    let Some((my_fp, their_fp)) = fps else {
                        eprintln!("pair-proof received before fingerprints known — ignoring");
                        continue;
                    };
                    let hit = devices
                        .iter()
                        .find(|(_, s)| proof_for(s, &peer_uid, &peer_uid, &conn.my_uid, &my_fp, &their_fp) == mac);
                    let ok = if let Some((n, _)) = hit {
                        if let Some(l) = conn.link_mut(&pid) {
                            l.trusted = true;
                        }
                        eprintln!("identity verified: '{n}' (auto-accepting)");
                        true
                    } else {
                        eprintln!("pair-proof FAILED verification — treating peer as untrusted");
                        false
                    };
                    // C27: tell the prover the verdict — a rejected prover
                    // learns we never met and stops claiming acquaintance.
                    if let Some(t) = conn.transport_of(&pid) {
                        t.send_control(&json!({ "type": "pair-proof-ack", "ok": ok })).await.ok();
                    }
                }
                Some("pair-intro") => {
                    // C19/C20: only a fingerprint-verified known device may
                    // vouch new trust into this store.
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let iname = v["name"].as_str().unwrap_or_default().to_string();
                    let isec = v["secret"].as_str().unwrap_or_default().to_string();
                    let hub = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    if trusted && isec.len() == 64 && !iname.is_empty() {
                        devices_store(&iname, &isec)?;
                        devices.push((iname.clone(), isec.clone()));
                        sio.emit("subscribe", json!({ "channels": [channel_of(&isec)] })).await.ok();
                        ui::say(&format!(
                            "  {} introduced to '{}' by {} — now a known device",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok()), iname, hub
                        ));
                    } else {
                        ui::say(&ui::paint(ui::Tone::Warn, &format!("  ignored pair-intro from unverified peer {hub}")));
                    }
                }
                Some("file-offer") => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // Never trust a remote name with path separators.
                    let raw = v["name"].as_str().unwrap_or("file.bin");
                    let name = Path::new(raw)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "file.bin".into());
                    let size = v["size"].as_u64().unwrap_or(0);
                    let offer_head = v["head"].as_str().map(|s| s.to_string());
                    let is_resume = v["resume"].as_bool().unwrap_or(false);

                    let part_path = dir.join(format!("{name}.part"));
                    let meta_path = dir.join(format!("{name}.part.meta"));
                    // C7: a partial counts only if size matches AND the
                    // content head matches (when both sides have one).
                    let mut offset = 0u64;
                    if part_path.is_file() {
                        let prior = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
                        match PartMeta::load(&meta_path) {
                            Some(m) if m.size == size && prior <= size => {
                                let head_ok = match (&m.head, &offer_head) {
                                    (Some(a), Some(b)) => a == b,
                                    _ => true, // legacy peer — size-only fallback
                                };
                                if head_ok {
                                    offset = prior;
                                } else {
                                    eprintln!("{name}: same name+size but different content — restarting from 0");
                                }
                            }
                            _ => {}
                        }
                    }

                    // C14/C22: consent. -y accepts everything; a resume of a
                    // partial we already said yes to auto-accepts; a verified
                    // device auto-accepts; otherwise the question joins the
                    // pending queue and the answer arrives via StdinLine — a
                    // per-process token marks re-enqueued offers so a remote
                    // peer can't forge "already consented".
                    let sender_name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    let link_trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let consented = v["__consent"].as_str() == Some(consent_token());
                    let ok = if daemon {
                        link_trusted
                    } else {
                        yes || consented || link_trusted || (is_resume && offset > 0)
                    };
                    if !ok {
                        if !daemon && std::io::stdin().is_terminal() {
                            pending.push_back((pid.clone(), v.clone()));
                            question_open.store(true, std::sync::atomic::Ordering::Relaxed);
                            if pending.len() == 1 {
                                // C25: the question is a PERMANENT line first
                                // (nothing can be asked invisibly), with the
                                // sticky as the live answer tail.
                                let q = offer_question(&sender_name, &name, size, paired);
                                ui::say(&q);
                                ui::sticky(&q);
                                question_shown = Instant::now();
                            }
                            continue; // decision arrives later via StdinLine
                        }
                        ui::say(&ui::paint(ui::Tone::Dim, &format!(
                            "  declined {name} from {sender_name} ({})",
                            if daemon { "unverified peer" } else { "no tty — use -y to auto-accept" }
                        )));
                        t.send_control(&json!({ "type": "file-decline", "id": id })).await?;
                        continue;
                    }

                    // C23: never run two streams into one .part — a rejoin
                    // can re-offer a file whose first stream is still live;
                    // accepting both corrupted the path and crashed on the
                    // second rename. First stream wins.
                    if !to_stdout
                        && by_sid.values().any(|inc| inc.part_path == dir.join(format!("{name}.part")))
                    {
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  (duplicate offer for {name} ignored — already receiving it)")));
                        t.send_control(&json!({ "type": "file-decline", "id": id })).await?;
                        continue;
                    }

                    if to_stdout {
                        // Pipe mode: no part files, no resume — pure stream.
                        // Write through a dup'd stdout fd so dropping the
                        // writer never closes the process's real fd 1; the
                        // /dev/stdout open is the portable-unix way to dup.
                        // (Windows: -o - is not supported yet; see G-e.)
                        #[cfg(unix)]
                        let out = tokio::fs::OpenOptions::new().write(true).open("/dev/stdout").await?;
                        #[cfg(not(unix))]
                        {
                            bail!("-o - (stdout streaming) is not supported on this platform yet");
                        }
                        #[cfg(unix)]
                        {
                            by_sid.insert((pid.clone(), sid), IncomingFile {
                                id: id.clone(),
                                name,
                                size,
                                received: 0,
                                file: tokio::io::BufWriter::with_capacity(1 << 20, out),
                                part_path: PathBuf::new(),

                                bar: ui::Progress::new("(stdout)", size),
                            });
                            t.send_control(&json!({ "type": "file-accept", "id": id, "offset": 0 })).await?;
                            continue;
                        }
                    }
                    let file = if offset > 0 {
                        eprintln!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0);
                        tokio::fs::OpenOptions::new().append(true).open(&part_path).await?
                    } else {
                        PartMeta { size, head: offer_head }.store(&meta_path)?;
                        tokio::fs::File::create(&part_path).await?
                    };
                    let bar = ui::Progress::new(&name, size);
                    by_sid.insert((pid.clone(), sid), IncomingFile {
                        id: id.clone(),
                        name,
                        size,
                        received: offset,
                        file: tokio::io::BufWriter::with_capacity(1 << 20, file),
                        part_path,

                        bar,
                    });
                    t.send_control(&json!({ "type": "file-accept", "id": id, "offset": offset })).await?;
                }
                Some("file-end") => {
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    if let Some(mut inc) = by_sid.remove(&(pid.clone(), sid)) {
                        inc.file.flush().await?;
                        if to_stdout {
                            completed += 1;
                            continue;
                        }
                        drop(inc.file);
                        let rename_to = if completed == 0 { output.clone() } else { None };
                        let final_path = unique_path(&dir, rename_to.as_deref().unwrap_or(&inc.name));
                        if let Err(e) = tokio::fs::rename(&inc.part_path, &final_path).await {
                            // C23: a duplicate stream's partial may already be
                            // finalized — discard quietly instead of dying.
                            ui::say(&ui::paint(ui::Tone::Dim, &format!("  (stream for {} already finalized — duplicate discarded: {e})", inc.name)));
                            continue;
                        }
                        let _ = tokio::fs::remove_file(dir.join(format!("{}.part.meta", inc.name))).await;
                        let ok = inc.received == inc.size;
                        inc.bar.done(inc.received);
                        let shown = final_path.display().to_string();
                        ui::say(&format!(
                            "    {} {}{}",
                            ui::paint(ui::Tone::Dim, ui::glyph_arrow()),
                            ui::link(&format!("file://{shown}"), &shown),
                            if ok { String::new() } else { ui::paint(ui::Tone::Err, "  SIZE MISMATCH") },
                        ));
                        completed += 1;
                        if daemon {
                            use std::io::Write as _;
                            let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(up_log()) {
                                let _ = writeln!(f, "{}  {}  {}  from {}", chrono_now(), inc.name, human(inc.received), from);
                            }
                        }
                    }
                }
                _ => {}
            },
            Ev::Chunk(pid, sid, data) => {
                if let Some(inc) = by_sid.get_mut(&(pid, sid)) {
                    inc.file.write_all(&data).await?;
                    inc.received += data.len() as u64;
                    inc.bar.tick(inc.received);
                }
            }
            Ev::StdinLine(line) => {
                let ans = line.to_lowercase();
                if !pending.is_empty() {
                    // C22/C25: an open question owns stdin — but ONLY explicit
                    // answers count. An empty line (stray CR, idle Enter) used
                    // to default-decline an offer the user never saw; and any
                    // keypress within 300ms of the question appearing is a
                    // buffered stroke, not a decision.
                    if question_shown.elapsed() < Duration::from_millis(300) {
                        continue;
                    }
                    let mut answered = false;
                    if ans == "y" || ans == "yes" {
                        answered = true;
                        let (qpid, mut qv) = pending.pop_front().unwrap();
                        ui::clear_sticky();
                        qv["__consent"] = json!(consent_token());
                        let _ = tx.send(Ev::Control(qpid, qv)); // re-enter the offer path, consented
                    } else if ans == "n" || ans == "no" {
                        answered = true;
                        let (qpid, qv) = pending.pop_front().unwrap();
                        ui::clear_sticky();
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  declined {}", qv["name"].as_str().unwrap_or("file"))));
                        if let Some(t) = conn.transport_of(&qpid) {
                            t.send_control(&json!({ "type": "file-decline", "id": qv["id"] })).await?;
                        }
                    }
                    // show the next queued question (or re-show on gibberish)
                    if let Some((qpid, qv)) = pending.front() {
                        let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                        let q = offer_question(&s, qv["name"].as_str().unwrap_or("file"), qv["size"].as_u64().unwrap_or(0), paired);
                        if answered {
                            ui::say(&q); // a NEW question fronted — permanent line (C25)
                            question_shown = Instant::now();
                        }
                        ui::sticky(&q);
                    } else {
                        question_open.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                } else if ans == "devices" {
                    // C29: session commands — `up` is a place you live in.
                    if devices.is_empty() {
                        ui::say(&ui::paint(ui::Tone::Dim, "  no known devices yet — type a code or `pair` to add one"));
                    }
                    for (n, s) in &devices {
                        ui::say(&format!("  {}  {}", ui::paint(ui::Tone::Bold, n), ui::paint(ui::Tone::Dim, &format!("(channel {})", &channel_of(s)[..12]))));
                    }
                } else if let Some(n) = ans.strip_prefix("forget ") {
                    let n = n.trim();
                    if devices.iter().any(|(dn, _)| dn == n) {
                        devices_remove(n)?;
                        devices.retain(|(dn, _)| dn != n);
                        ui::say(&format!("  {} forgot '{n}' — it can no longer find this machine", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                    } else {
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  no device named '{n}' (try `devices`)")));
                    }
                } else if ans == "pair" || ans == "code" {
                    // C29: mint a code; whoever claims it gets the remember
                    // ceremony on connect (we created it, so WE initiate).
                    if daemon {
                        ceremony = Some(true);
                    }
                    sio.emit("pair-create", json!({})).await.ok();
                } else if regex_lite_code(&line) {
                    if claim_in_flight {
                        ui::say(&ui::paint(ui::Tone::Dim, "  (a claim is already in flight — wait for it to resolve)"));
                    } else {
                        ui::say(&format!("  claiming {}…", ui::paint(ui::Tone::Brand, &line)));
                        paired = true;
                        claim_in_flight = true;
                        if daemon {
                            ceremony = Some(false); // C29: in a session, pairing means remembering
                        }
                        sio.emit("pair-claim", json!({ "code": line.to_lowercase() })).await.ok();
                    }
                } else if !line.is_empty() {
                    ui::say(&ui::paint(ui::Tone::Dim, "  (type a code like brave-otter-123 to claim it · `pair` · `devices` · `forget <name>`)"));
                }
            }
            Ev::Interrupted => {
                flush_inflight(&mut by_sid).await;
                ui::say(&format!("  {} interrupted — partials kept; run the same command to resume", ui::paint(ui::Tone::Warn, "!")));
                if let Some(g) = &tty_guard {
                    g.restore(); // process::exit skips Drop
                }
                let _ = sio.disconnect().await;
                std::process::exit(130);
            }
            Ev::Stuck(pid, generation) => {
                if conn.on_stuck(&pid, generation, "stuck while connecting").await? && paired && !keep_open {
                    bail!("lost the sender after {} attempts", MAX_ATTEMPTS);
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? && paired && !keep_open {
                    bail!("lost the sender after {} attempts", MAX_ATTEMPTS);
                }
            }
            Ev::PcState(pid, s) => conn.on_pc_state(&pid, &s).await,
            Ev::PeerLeft(v) => {
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let secs = conn.rejoin_window.as_secs();
                    if !by_sid.is_empty() {
                        // Keep partials writable-but-parked; resume comes via
                        // rejoin (C6) or a later re-offer against the .part.
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  sender disconnected mid-transfer — waiting up to {secs}s")));
                        flush_inflight(&mut by_sid).await;
                    } else if completed > 0 && !keep_open {
                        eprintln!("done ({completed} file{}).", if completed == 1 { "" } else { "s" });
                        let _ = sio.disconnect().await;
                        return Ok(());
                    } else if paired && !keep_open {
                        // C21: NOT fatal — a phone opening its file picker
                        // suspends the whole tab and drops the socket. Hold
                        // the line; their client rejoins on refocus.
                        let gid = v["id"].as_str().unwrap_or_default();
                        let n = gone.unwrap_or_else(|| "sender".into());
                        ui::say(&conn.roster(gid, "●", ui::Tone::Warn, &format!("stepped away — holding the line up to {secs}s (Ctrl-C to stop)"), &n));
                    } else {
                        conn.waiting_rejoin = None; // open listener: keep going
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => ui::say(&conn.roster(gid, "○", ui::Tone::Dim, "left — still listening", &n)),
                            None => ui::say(&ui::paint(ui::Tone::Dim, "  peer left — still listening")),
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Park in-flight receives: flush buffers so the .part files are complete up
/// to the last byte received, then drop the per-link routing. Resume picks
/// them up from disk.
async fn flush_inflight(by_sid: &mut HashMap<(String, u32), IncomingFile>) {
    for (_sid, mut inc) in by_sid.drain() {
        let _ = inc.file.flush().await;
        eprintln!("{}: parked at {} for resume", inc.name, human(inc.received));
    }
}

/// C22: cbreak-mode guard — single-keypress answers without losing line
/// input. `stty` keeps us dependency-free; Drop restores the terminal (and
/// the Interrupted path calls restore() explicitly since process::exit skips
/// Drop).
struct TtyGuard {
    saved: Option<String>,
}

impl TtyGuard {
    fn raw() -> TtyGuard {
        let saved = std::process::Command::new("stty")
            .arg("-g")
            .stdin(std::process::Stdio::inherit())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        if saved.is_some() {
            let _ = std::process::Command::new("stty")
                .args(["-icanon", "-echo", "min", "1", "time", "0"])
                .stdin(std::process::Stdio::inherit())
                .status();
        }
        TtyGuard { saved }
    }
    fn restore(&self) {
        if let Some(s) = &self.saved {
            let _ = std::process::Command::new("stty")
                .arg(s)
                .stdin(std::process::Stdio::inherit())
                .status();
        }
    }
}

impl Drop for TtyGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// C22: per-process token marking a locally re-enqueued (consented) offer.
/// A remote peer cannot know it, so it cannot forge consent in a control msg.
fn consent_token() -> &'static str {
    static T: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    T.get_or_init(fresh_secret)
}

/// C26: one-line colored peer status — static scrollback lines, the CLI's
/// equivalent of the web UI's amber 'away' tile.
///   ✓ deft-gibbon                    (connected)
///   ● deft-gibbon  away — choosing a file
///   ◌ deft-gibbon  reconnecting…
fn peer_entry(name: &str, mark: &str, tone: ui::Tone, note: &str) -> String {
    let mut s = format!("{} {}", ui::paint(tone, mark), ui::paint(ui::Tone::Bold, name));
    if !note.is_empty() {
        s.push_str(&format!("  {}", ui::paint(ui::Tone::Dim, note)));
    }
    s
}

fn offer_question(sender: &str, name: &str, size: u64, paired: bool) -> String {
    let sender = if sender.is_empty() { "unknown peer" } else { sender };
    let hint = if paired { " [paired]" } else { "" };
    format!(
        "  {}{} offers {} ({}) — accept? [y/N] ",
        ui::paint(ui::Tone::Bold, sender),
        hint,
        name,
        human(size)
    )
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_matches_browser() {
        // Pinned to the SAME external vector as frontend devices.js (computed
        // with `printf 'filament-proof2:u1|u1|u2|FPA|FPB' | openssl dgst
        // -sha256 -hmac s3cret`). If either implementation drifts, browsers
        // and CLIs silently stop recognizing each other as known devices.
        let want = "f98c3b6b7a70ebdf4b200680e83383881bdb1a11476283507359c55ef03a8474";
        // deliberately unsorted inputs — proof_for must normalize
        assert_eq!(proof_for("s3cret", "u1", "u2", "u1", "FPB", "FPA"), want);
        assert_eq!(proof_for("s3cret", "u1", "u1", "u2", "FPA", "FPB"), want);
        // channel derivation, same cross-check (sha256 of "filament-pair:"+secret)
        assert_eq!(
            channel_of("topsecret"),
            "1e32e46e93691c29d9c0305545a10c86a00ae9f3c43d4eea3c7423c1528f9b5d"
        );
    }

    #[test]
    fn polite_role_matches_browser() {
        // uid comparison wins, string-lexicographic, mirrors webrtc.js politeRole
        assert!(net::polite_role("b", Some("a"), "x", "y")); // myUid > peerUid -> polite
        assert!(!net::polite_role("a", Some("b"), "x", "y"));
        // identical/missing uids fall back to sids
        assert!(net::polite_role("a", Some("a"), "y", "x"));
        assert!(!net::polite_role("a", None, "x", "y"));
        // exactly one side of any pair is impolite
        for (a, b) in [("a", "b"), ("cli-1", "cli-2"), ("zz", "aa")] {
            let p1 = net::polite_role(a, Some(b), "s1", "s2");
            let p2 = net::polite_role(b, Some(a), "s2", "s1");
            assert_ne!(p1, p2, "{a} vs {b} must disagree");
        }
    }

    #[test]
    fn part_meta_roundtrip_and_legacy() {
        let dir = std::env::temp_dir().join(format!("filament-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.part.meta");
        PartMeta { size: 42, head: Some("abc".into()) }.store(&p).unwrap();
        let m = PartMeta::load(&p).unwrap();
        assert_eq!(m.size, 42);
        assert_eq!(m.head.as_deref(), Some("abc"));
        // legacy plain-size format still parses
        std::fs::write(&p, "1234").unwrap();
        let m = PartMeta::load(&p).unwrap();
        assert_eq!(m.size, 1234);
        assert!(m.head.is_none());
        // garbage does not
        std::fs::write(&p, "{not json").unwrap();
        assert!(PartMeta::load(&p).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn head_hash_is_prefix_stable() {
        let dir = std::env::temp_dir().join(format!("filament-test-h-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        // same first 256 KiB, different tails -> same head (by design: head is
        // a prefix identity, full integrity is the per-chunk-hash backlog)
        let mut base = vec![7u8; (HEAD_BYTES + 10) as usize];
        std::fs::write(&a, &base).unwrap();
        base[(HEAD_BYTES + 5) as usize] = 9;
        std::fs::write(&b, &base).unwrap();
        assert_eq!(head_hash(&a), head_hash(&b));
        // different first bytes -> different head
        base[0] = 1;
        std::fs::write(&b, &base).unwrap();
        assert_ne!(head_hash(&a), head_hash(&b));
        // short files hash their whole content
        std::fs::write(&a, b"tiny").unwrap();
        std::fs::write(&b, b"tinY").unwrap();
        assert_ne!(head_hash(&a), head_hash(&b));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_path_suffixes() {
        let dir = std::env::temp_dir().join(format!("filament-test-u-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt"));
        std::fs::write(dir.join("f.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt.1"));
        std::fs::write(dir.join("f.txt.1"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt.2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_address_classification() {
        // C2: the badge means "bytes never leave your network" — an address
        // property, not a candidate-type property.
        for a in ["127.0.0.1", "10.1.2.3", "192.168.1.9", "172.16.0.1", "169.254.1.1", "100.99.1.2", "::1", "fe80::1", "fd00::5"] {
            assert!(net::is_private_addr(a), "{a} should be private");
        }
        for a in ["1.2.3.4", "165.22.207.231", "2606:4700::1", "8.8.8.8", "not-an-ip", ""] {
            assert!(!net::is_private_addr(a), "{a} should be public/invalid");
        }
    }

    #[test]
    fn filename_sanitization() {
        // the recv path strips directories from remote names
        let evil = "../../etc/passwd";
        let name = Path::new(evil).file_name().map(|n| n.to_string_lossy().into_owned());
        assert_eq!(name.as_deref(), Some("passwd"));
        let evil2 = "/absolute/path.bin";
        let name2 = Path::new(evil2).file_name().map(|n| n.to_string_lossy().into_owned());
        assert_eq!(name2.as_deref(), Some("path.bin"));
    }
}
