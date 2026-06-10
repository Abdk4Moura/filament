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

mod direct;
mod holepunch;
mod l2;
mod net;
mod session;
mod sshkeys;
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
/// G-k: how long the recv quiet-check must hold (everything done, nobody
/// attached, no questions) before exiting without a `peer-left`. The 10 s
/// default is overridable for tests (gate 18).
fn quiet_exit_window() -> Duration {
    std::env::var("FILAMENT_QUIET_EXIT_SECS") // test knob (gate 18)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10))
}
/// C3/C4: connection (re)establishment attempts before failing honestly.
const MAX_ATTEMPTS: u32 = 3;

/// Gate-18 Mode B: the single predicate that decides whether a stuck/lost link
/// should be DROPPED (transfer is complete; nothing left to fetch) rather than
/// reconnected. Pulled out as a pure function so the gate-2 / gate-11c fence
/// (mid-transfer links must NEVER be dropped) is unit-testable without a live
/// WebRTC peer. The recv loop computes `conn.recv_done` from exactly this each
/// tick; `on_stuck` then reads the flag.
///
/// - `completed`: files fully placed on disk so far.
/// - `keep_open`: the receiver was asked to stay resident (gate 13).
/// - `by_sid_empty`: NO stream is in flight (an in-progress reconnect/resume
///   keeps a by_sid entry, which must keep the link reconnecting — gate 2/11c).
fn recv_transfer_done(completed: usize, keep_open: bool, by_sid_empty: bool) -> bool {
    completed > 0 && !keep_open && by_sid_empty
}

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
        /// Accept seamless `filament ssh` from ANY paired (proof-verified) device
        /// — no per-device `grant` needed. Enables the tunnel acceptor too, so you
        /// don't also need FILAMENT_L2=1. Strangers still can't get in (pairing is
        /// required). Prints a security banner.
        #[arg(long)]
        shell: bool,
        /// Like --shell but ONLY for these devices (comma-separated petnames);
        /// every other device still needs an explicit `grant <dev> shell`.
        #[arg(long, value_name = "DEVICES")]
        shell_only: Option<String>,
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
    /// Tunnel: wire stdio to one TCP stream on a known peer's localhost (the
    /// ssh ProxyCommand primitive). Off by default; FILAMENT_L2=1 enables the
    /// acceptor side in `up`/`recv`.
    Netcat {
        /// Known device (petname) to tunnel through
        peer: String,
        /// Remote port on the peer's localhost
        rport: u16,
    },
    /// Open a PTY shell on a known device and bridge it to this terminal (the CLI
    /// sibling of the browser web-shell). The peer must run `up --shell` (or grant
    /// shell). Off by default; FILAMENT_L2=1 / --shell enables the acceptor.
    Pty {
        /// Known device (petname) to open a shell on
        peer: String,
    },
    /// Tunnel: local TCP listener; each connection becomes one stream to the
    /// peer's localhost:<rport>.
    Forward {
        /// Local port to listen on (127.0.0.1)
        lport: u16,
        /// Known device (petname) to tunnel through
        peer: String,
        /// Remote port on the peer's localhost
        rport: u16,
    },
    /// Tunnel: run your real `ssh` over the data channel via ProxyCommand
    /// (reuses your keys, known_hosts, and ~/.ssh/config).
    Ssh {
        /// Known device (petname) to ssh into
        peer: String,
        /// Extra args passed through to ssh (user@host, commands, -p, ...)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Grant a known device a capability (deny-by-default). `shell` permits
    /// seamless `filament ssh` into THIS machine — a separate consent from
    /// file transfer; pairing alone never yields a shell.
    Grant {
        /// Known device (petname)
        device: String,
        /// Capability to grant (e.g. `shell`)
        capability: String,
    },
    /// Revoke a capability from a known device. Revoking `shell` also strips the
    /// device's filament-managed block from this machine's authorized_keys.
    Revoke {
        /// Known device (petname)
        device: String,
        /// Capability to revoke (e.g. `shell`)
        capability: String,
    },
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

pub(crate) fn mk_uid(prefix: &str) -> String {
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
pub(crate) fn is_self_uid(my_uid: &str, peer_uid: Option<&str>) -> bool {
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

pub(crate) fn display_name() -> String {
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

pub(crate) fn devices_load() -> Vec<(String, String)> {
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
    // Operate on the raw JSON so OTHER records keep their v2 fields (caps,
    // addedAt) verbatim. Going through the (name, secret) tuples of
    // devices_load() silently rewrote every other device as bare
    // {name, secret}, wiping their `shell` grants on any store (pairing,
    // introduce, rename) — a quiet privilege-loss bug.
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    match arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) {
        // Re-storing an existing name: only the secret rotates; keep its caps.
        Some(existing) => existing["secret"] = json!(secret),
        None => arr.push(json!({"name": name, "secret": secret})),
    }
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// L1-a (spec §8): store a v2 device record with its agreed capability set.
/// `caps` is deny-by-default; "transfer" is the L0 baseline. The on-disk shape
/// grows `v` and `caps` but the existing `{name, secret}` fields are unchanged,
/// so the reconnect path (`devices_load`, which reads only name+secret) keeps
/// working byte-for-byte — no regression.
fn devices_store_v2(name: &str, secret: &str, caps: &[String]) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Preserve other records verbatim (including their v/caps if present).
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    arr.retain(|d| d["name"].as_str() != Some(name));
    arr.push(json!({"name": name, "secret": secret, "v": 2, "caps": caps,
                    "addedAt": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)}));
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// L1-a (spec §8): read a device's granted capabilities. v1 records (no `caps`)
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
/// read as `["transfer"]` for backward compatibility; deny-by-default otherwise.
/// Returns None if the device isn't known.
fn device_caps(name: &str) -> Option<Vec<String>> {
    device_caps_at(&devices_path(), name)
}

/// Path-explicit core of `device_caps` (testable without touching the global
/// config-dir env var).
#[allow(dead_code)]
fn device_caps_at(path: &Path, name: &str) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(path).ok()?;
    let arr = serde_json::from_str::<Value>(&raw).ok()?;
    for d in arr.as_array()? {
        if d["name"].as_str() == Some(name) {
            return Some(match d.get("caps").and_then(|c| c.as_array()) {
                Some(list) => list.iter().filter_map(|c| c.as_str().map(String::from)).collect(),
                None => vec!["transfer".to_string()], // v1 record
            });
        }
    }
    None
}

/// Path-explicit deny-by-default check (testable).
#[allow(dead_code)]
fn device_allows_at(path: &Path, name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline — never gated (spec §8)
    }
    device_caps_at(path, name).map(|c| c.iter().any(|g| g == capability)).unwrap_or(false)
}

/// L1-a (spec §8 / gate 5): deny-by-default capability enforcement hook. A
/// gated action is allowed only if the device's record grants the capability.
/// "transfer" is the L0 baseline (always allowed, even for empty caps) so this
/// never regresses existing send/recv. Wired now; future L-layers add caps.
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
fn device_allows(name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline — never gated (spec §8)
    }
    device_caps(name).map(|c| c.iter().any(|g| g == capability)).unwrap_or(false)
}

/// Grant or revoke a capability on an EXISTING known device, preserving its
/// secret and any other caps. Promotes a v1 record (no `caps`) to v2 with the
/// back-compat baseline `["transfer"]` first, so granting `shell` never silently
/// drops `transfer`. Deny-by-default consent for `filament grant`/`revoke`.
/// Returns Err if the device is unknown (you can't grant a stranger a shell).
fn device_set_cap(name: &str, capability: &str, grant: bool) -> Result<()> {
    let p = devices_path();
    let raw = std::fs::read_to_string(&p)
        .map_err(|_| anyhow::anyhow!("no known device named '{name}' — pair first"))?;
    let mut arr: Vec<Value> = serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut found = false;
    for d in arr.iter_mut() {
        if d["name"].as_str() != Some(name) {
            continue;
        }
        found = true;
        // Current caps: v1 (absent) reads as the transfer baseline.
        let mut caps: Vec<String> = match d.get("caps").and_then(|c| c.as_array()) {
            Some(list) => list.iter().filter_map(|c| c.as_str().map(String::from)).collect(),
            None => vec!["transfer".to_string()],
        };
        caps.retain(|c| c != capability);
        if grant {
            caps.push(capability.to_string());
        }
        if let Some(obj) = d.as_object_mut() {
            obj.insert("v".into(), json!(2));
            obj.insert("caps".into(), json!(caps));
        }
    }
    if !found {
        return Err(anyhow::anyhow!(
            "no known device named '{name}' — run `filament devices` to see who you've paired"
        ));
    }
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
    // Raw-array filter so the REMAINING devices keep their v2 fields (caps,
    // addedAt). The old tuple round-trip rewrote every survivor as bare
    // {name, secret}, silently wiping their `shell` grants on any forget.
    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    arr.retain(|d| d["name"].as_str() != Some(name));
    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub(crate) fn channel_of(secret: &str) -> String {
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
pub(crate) fn proof_for(secret: &str, prover_uid: &str, a_uid: &str, b_uid: &str, fp1: &str, fp2: &str) -> String {
    let (lo, hi) = if a_uid < b_uid { (a_uid, b_uid) } else { (b_uid, a_uid) };
    let (f_lo, f_hi) = if fp1 < fp2 { (fp1, fp2) } else { (fp2, fp1) };
    hmac_sha256(
        secret.as_bytes(),
        format!("filament-proof2:{prover_uid}|{lo}|{hi}|{f_lo}|{f_hi}").as_bytes(),
    )
}

pub(crate) fn fresh_secret() -> String {
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

/// The argv for a web-shell PTY: the up user's login shell. `$SHELL -l`, falling
/// back to bash/sh. (Privilege-drop to another account is a later `--shell-user`.)
fn shell_argv() -> Vec<String> {
    let shell = std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
        if std::path::Path::new("/bin/bash").exists() { "/bin/bash".into() } else { "/bin/sh".into() }
    });
    vec![shell, "-l".into()]
}

/// Auto-shell policy for the `up`/`recv` acceptor: which proof-verified devices
/// may `filament ssh` in WITHOUT a per-device `grant`. Trust (pair-proof) is
/// always enforced separately — this is purely the capability side.
#[derive(Clone, Debug)]
enum ShellPolicy {
    /// Default: only devices explicitly `grant`ed the `shell` cap.
    Granted,
    /// `up --shell`: any paired device.
    All,
    /// `up --shell-only a,b`: only these petnames auto-shell; others need a grant.
    Only(std::collections::HashSet<String>),
}

impl ShellPolicy {
    fn auto_allows(&self, name: &str) -> bool {
        match self {
            ShellPolicy::Granted => false,
            ShellPolicy::All => true,
            ShellPolicy::Only(set) => set.contains(name),
        }
    }
    /// Active policy implies the L2 tunnel acceptor is on (you can't ssh without it).
    fn enables_l2(&self) -> bool {
        !matches!(self, ShellPolicy::Granted)
    }
}

async fn up_cmd(
    server: &str,
    install: bool,
    dir: Option<PathBuf>,
    relay: bool,
    shell: bool,
    shell_only: Option<String>,
) -> Result<()> {
    let shell_policy = match &shell_only {
        Some(csv) => ShellPolicy::Only(
            csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        ),
        None if shell => ShellPolicy::All,
        None => ShellPolicy::Granted,
    };
    if install {
        let exe = std::env::current_exe()?;
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
        std::fs::create_dir_all(&unit_dir)?;
        let unit = unit_dir.join("filament.service");
        // Carry the shell policy into the unit so a service install keeps the
        // same seamless-ssh posture the user asked for on the command line.
        let mut up_args = String::from(" up");
        if let Some(csv) = &shell_only {
            up_args.push_str(&format!(" --shell-only {csv}"));
        } else if shell {
            up_args.push_str(" --shell");
        }
        std::fs::write(&unit, format!(
            "[Unit]\nDescription=Filament drop target (trusted devices only)\nAfter=network-online.target\n\n[Service]\nExecStart={}{}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
            exe.display(), up_args
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
    match &shell_policy {
        ShellPolicy::All => ui::say(&format!(
            "  {} seamless shell ON — ANY paired device can `filament ssh` into this machine",
            ui::paint(ui::Tone::Warn, "!"),
        )),
        ShellPolicy::Only(set) => {
            let mut names: Vec<&String> = set.iter().collect();
            names.sort();
            let list = names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            ui::say(&format!(
                "  {} seamless shell ON for: {list} — they can `filament ssh` into this machine",
                ui::paint(ui::Tone::Warn, "!"),
            ));
        }
        ShellPolicy::Granted => {}
    }
    let res = recv_cmd(server, None, dir, false, None, None, true, relay, None, true, None, shell_policy).await;
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
    // C30: the session repairs whatever these emits lose — and under gate L
    // they are the emits the loss shim adversarially drops.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(solo.clone());
    sess.channels = vec![channel_of(&a_sec), channel_of(&b_sec)];
    sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
    sess.emit(&sio, "subscribe", json!({ "channels": [channel_of(&a_sec), channel_of(&b_sec)] })).await;
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
        deferred_left: HashMap::new(),
        recv_done: false,
    direct_pending: HashMap::new(),
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
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead
        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                // C30 (dissolves the C28 belt): fresh sid — re-assert via session.
                sess.invalidate();
            }
            Ev::Synced(v) => { sess.on_synced(&v); }
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
                conn.apply_signal(&from, data).await;
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
                    if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
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
// L1-a (PAKE v2): remembering a device is a first-class ceremony — no file
// transfer to pretend through. The first-pairing now runs a real SPAKE2 PAKE
// over the SPOKEN code so a malicious signaling server cannot MITM enrollment.
//
// The load-bearing change vs v1:
//   - The CLIENT mints the words locally (server sees only the numeric
//     nameplate); the password (words) NEVER reaches the server.
//   - SPAKE2 runs over the opaque `signal` relay BEFORE any secret exists.
//   - A key-confirmation MAC folds in the SORTED DTLS fingerprints + caps, so a
//     server that substitutes a DTLS cert OR rewrites caps is DETECTED → abort.
//   - The 32-byte pinned secret is HKDF(K) — AGREED, never transmitted. The old
//     `pair-keep` secret-over-DataChannel step is GONE from the v2 path.
//   - Downgrade is structurally impossible: a v2 client NEVER sends pair-keep
//     and NEVER stores a secret from a received pair-keep. A received pair-keep
//     means the peer is v1 → abort with "update to pair securely". A server
//     stripping `v:2` therefore cannot force the readable-secret path.
//
// Helpers below decode/encode the opaque PAKE payloads carried on `signal`.

/// Base64 (no external dep — small alphabet table). Used only for the 33-byte
/// SPAKE2 element / 32-byte MAC opaque payloads on the signal relay.
fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &c in chunk {
            n = (n << 6) | val(c)?;
            bits += 6;
        }
        n <<= 24 - bits;
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// The capability set v2 first-pairing agrees on. "transfer" is the L0 baseline
/// (always allowed); deny-by-default future caps are NOT granted at first
/// enrollment. BOTH sides MAC the identical canonical string or confirmation
/// fails — so this default is fixed and unconditional (spec §8 / gate 5).
fn pair_v2_caps() -> Vec<String> {
    vec!["transfer".to_string()]
}

async fn pair_cmd(server: &str, code: Option<String>, name: Option<String>, relay: bool) -> Result<()> {
    let my_uid = mk_uid("p");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    // Meta must exist for pairing; an unguessable solo room keeps strangers
    // out (the daemon's trick) — the pair-claim moves people, not the room.
    let solo = format!("pairc-{}", fresh_secret());
    // C30: the session repairs the solo-room membership/lease if the join dies.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(solo.clone());
    sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
    let creator = code.is_none();
    // L1-a: the spoken code is split CLIENT-SIDE into (nameplate, password). The
    // password (words) NEVER leaves this process; only the nameplate is sent.
    let mut my_words; // the password (creator mints; claimer types)
    let mut my_nameplate;
    match &code {
        Some(c) => {
            // Claimer: normalize the typed code, split, send ONLY the nameplate.
            let normalized = filament_pake::norm_code(c);
            let (np, pw) = filament_pake::split_code(&normalized);
            if pw.is_empty() || np.is_empty() {
                bail!("that code doesn't look right — expected something like brave-otter-ruby-3141");
            }
            my_words = pw;
            my_nameplate = np.clone();
            ui::say(&format!("  claiming {}…", ui::paint(ui::Tone::Brand, c)));
            sio.emit("pair-claim", json!({ "nameplate": np, "v": 2 })).await.ok();
        }
        None => {
            // Creator: mint words + nameplate locally; ask the server to allocate
            // ONLY the nameplate. The full code is displayed from our own mint
            // when pair-ok arrives (the server never echoes any words).
            my_words = filament_pake::words::mint_words();
            my_nameplate = filament_pake::words::mint_nameplate();
            sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 })).await.ok();
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
        deferred_left: HashMap::new(),
        recv_done: false,
    direct_pending: HashMap::new(),
    };
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(Ev::Interrupted);
        });
    }

    let mut petname = name; // resolved --name, prompt answer, or peer's display name
    let mut prompted = false;
    let mut peer: Option<(String, String)> = None; // (pid, display name)

    // ---- L1-a PAKE state ----------------------------------------------------
    // The agreed pinned secret (HKDF(K)); set ONLY after key confirmation passes.
    let mut agreed_secret: Option<String> = None;
    // Our live SPAKE2 session (consumed by finish) and our outbound element.
    let mut pake_state: Option<filament_pake::PakeState>;
    let mut pake_msg: Vec<u8>;
    // Derived K (after finishing on the peer's element). Held until confirmation.
    let mut pake_k: Option<Vec<u8>> = None;
    // Peer signaling sid we run the PAKE with (set when the link is adopted).
    let mut pake_peer: Option<String> = None;
    let mut sent_pake_msg = false;
    let mut sent_confirm = false;
    let caps = pair_v2_caps();
    let caps_canon = filament_pake::canonical_caps(&caps);

    // Start our SPAKE2 session immediately: identity = nameplate, password =
    // words. Both sides MUST pass identical Password AND Identity (spec §3.1).
    {
        let (st, msg) = filament_pake::start(my_words.as_bytes(), my_nameplate.as_bytes());
        pake_state = Some(st);
        pake_msg = msg;
    }
    let deadline = Instant::now() + Duration::from_secs(600); // code TTL
    // The pairing peer left before the ceremony finished. Give a short grace
    // for a transient reconnect, then FAIL FAST — don't orphan in the room
    // for the full 10-min TTL (the D3/D5 divergence the monitor kept
    // catching: creator's connect failed, it quit, claimer sat silent).
    // Once the code is CLAIMED, the ceremony must finish in seconds. Bound it:
    // if it hasn't completed within this budget, the peer disconnected or could
    // never connect — fail fast instead of orphaning in the room for the full
    // 600s TTL (the D3/D5 divergence the monitor kept catching). 60s is generous
    // (covers a slow cross-NAT WebRTC with its 3×15s establishment retries);
    // FILAMENT_PAIR_GRACE_SECS shortens it for gate 17b.
    let ceremony_budget = Duration::from_secs(
        std::env::var("FILAMENT_PAIR_GRACE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60),
    );
    let mut ceremony_deadline: Option<Instant> = None;
    // Gate 17b hook: connect but never complete, so the ceremony budget fires
    // deterministically (same-machine pairs otherwise finish in ~1s).
    let stall = std::env::var("FILAMENT_TEST_PAIR_STALL").is_ok();

    loop {
        // Done when the petname is settled AND the PAKE agreed a secret (key
        // confirmation passed). The secret is HKDF(K) — never transmitted, the
        // same on both sides; it drops straight into devices.json.
        if let Some(n) = petname.clone() {
            if let Some(sec) = agreed_secret.clone() {
                // caps_v2 (spec §8): record GRANTED caps, deny-by-default.
                devices_store_v2(&n, &sec, &caps)?;
                ui::say(&format!(
                    "  {} {} mutually remembered — verified end-to-end (no key ever crossed the server)",
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
        // Fail fast: the code was claimed but the ceremony didn't finish in
        // time — the peer disconnected or never connected.
        if let Some(dl) = ceremony_deadline {
            if Instant::now() > dl {
                bail!("the other device disconnected or could not connect before pairing finished — make sure both run `filament pair` at the same time, then try again");
            }
        }
        sess.tick(&sio).await; // C30: converge every iteration (incl. ticks)
        conn.reap_deferred(); // #28: discharge deferred peer-left when idle/dead

        // ---- L1-a PAKE progression (runs every iteration) ------------------
        // 1) Once we know the peer's signaling sid, send our SPAKE2 element over
        //    the opaque `signal` relay (the server cannot read it).
        if let Some(pid) = pake_peer.clone() {
            // gate 17b (FILAMENT_TEST_PAIR_STALL): never send our SPAKE2 element,
            // so the exchange can't complete on either side and the ceremony's
            // fail-fast `ceremony_deadline` fires — proving the no-10-min-orphan
            // guard. Test-only: `stall` is set solely by that env var.
            if !sent_pake_msg && !stall {
                sio.emit("signal", json!({ "to": pid, "data": {
                    "type": "pake-msg", "v": 2, "msg": b64_encode(&pake_msg)
                }})).await.ok();
                sent_pake_msg = true;
            }
            // 2) Once K is derived AND both DTLS fingerprints are known, send the
            //    key-confirmation MAC over K + sorted fingerprints + caps. The MAC
            //    is gated on the fingerprints so a server that substitutes a DTLS
            //    cert produces a different fingerprint → the peer's verify fails.
            if !sent_confirm {
                if let Some(k) = pake_k.clone() {
                    if let Some(l) = conn.link(&pid) {
                        if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
                            let mac = filament_pake::our_confirm(&k, &my_fp, &their_fp, &caps_canon);
                            sio.emit("signal", json!({ "to": pid, "data": {
                                "type": "pake-confirm", "v": 2,
                                "mac": b64_encode(&mac),
                                "caps": caps.clone(),
                            }})).await.ok();
                            sent_confirm = true;
                        }
                    }
                }
            }
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
                sess.invalidate(); // C30: fresh sid — re-assert next tick
            }
            Ev::Synced(v) => { sess.on_synced(&v); }
            Ev::PairOk(_v) => {
                // L1-a: the server allocated our nameplate. Display the FULL code
                // from OUR OWN local mint (the server never echoed any words).
                let full = format!("{my_words}-{my_nameplate}");
                ui::clipboard(&full);
                ui::say("");
                ui::say(&format!("      {}", ui::paint(ui::Tone::Brand, &full.to_uppercase())));
                ui::say("");
                ui::say(&ui::paint(ui::Tone::Dim, "  on the other device: type it into the web app, or `filament pair <code>`"));
                ui::say(&ui::paint(ui::Tone::Dim, "  one claim · expires in 10 min · paired end-to-end (no key crosses the server)"));
            }
            Ev::PairCode(v) => {
                // v1 server (shouldn't happen for a v2 create, but be safe): a
                // legacy server-minted code means the peer can't PAKE-pair.
                let c = v["code"].as_str().unwrap_or("?");
                let _ = c;
                bail!("this server returned a legacy code — update the server (or the peer) to pair securely");
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed — connecting…"));
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
            }
            Ev::PairMatched(v) => {
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ceremony_deadline.get_or_insert_with(|| Instant::now() + ceremony_budget);
                ui::say(&format!("  {} code accepted — connecting", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
                sess.room = Some(room.clone()); // C30: desire moves with us
                sess.touch();
                sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            }
            Ev::PairError(v) => {
                // Creator nameplate collision: re-mint a FRESH nameplate (and
                // fresh words) and retry — never reuse a burned code.
                if creator && v["error"].as_str() == Some("taken") {
                    my_words = filament_pake::words::mint_words();
                    my_nameplate = filament_pake::words::mint_nameplate();
                    let (st, msg) = filament_pake::start(my_words.as_bytes(), my_nameplate.as_bytes());
                    pake_state = Some(st);
                    pake_msg = msg;
                    sent_pake_msg = false;
                    sio.emit("pair-create", json!({ "nameplate": my_nameplate, "v": 2 })).await.ok();
                    continue;
                }
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => "that code's creator already left — ask them for a fresh one".to_string(),
                    _ => format!("{} — codes burn after one use; a failed pairing needs a FRESH code (re-run `filament pair`)", v["error"].as_str().unwrap_or("?")),
                };
                bail!("code rejected: {hint}");
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, true).await?;
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // L1-a: PAKE messages ride the opaque `signal` relay. Branch them
                // OUT of the WebRTC signal path (SDP/ICE) into the PAKE machine.
                match data["type"].as_str() {
                    Some("pake-msg") => {
                        pake_peer.get_or_insert(from.clone());
                        if pake_k.is_none() {
                            if let Some(state) = pake_state.take() {
                                let peer_el = data["msg"].as_str().and_then(b64_decode).unwrap_or_default();
                                match filament_pake::finish(state, &peer_el) {
                                    Some(k) => pake_k = Some(k),
                                    None => bail!("pairing failed: malformed key-exchange message (abort)"),
                                }
                            }
                        }
                        continue;
                    }
                    Some("pake-confirm") => {
                        // Verify the peer's key-confirmation MAC under OUR K, folding
                        // the SORTED DTLS fingerprints + caps. Mismatch ⇒ wrong
                        // password OR a server that substituted a DTLS cert OR
                        // rewrote caps ⇒ ABORT, agree NOTHING.
                        let Some(k) = pake_k.clone() else {
                            bail!("pairing failed: confirmation arrived before key exchange (abort)");
                        };
                        let recv_mac = data["mac"].as_str().and_then(b64_decode).unwrap_or_default();
                        let fps = match conn.link(&from) {
                            Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                            None => None,
                        };
                        let Some((my_fp, their_fp)) = fps else {
                            bail!("pairing failed: no DTLS fingerprints to bind confirmation (abort)");
                        };
                        // We MAC against OUR fixed caps, so a server that rewrites the
                        // relayed `caps` field cannot make the MAC verify.
                        if filament_pake::verify_peer_confirm(&k, &my_fp, &their_fp, &caps_canon, &recv_mac) {
                            agreed_secret = Some(filament_pake::secret_from_k(&k));
                        } else {
                            bail!("pairing REFUSED: key confirmation failed — wrong code, or the connection is being tampered with (a server cannot forge this). Nothing was stored; ask for a FRESH code.");
                        }
                        continue;
                    }
                    _ => {}
                }
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
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
                let _ = &t; // transport not used on the v2 path (no secret over DC)
                if stall {
                    continue; // gate 17b: connected, but deliberately never complete
                }
                // L1-a: the link is up and SDP fingerprints exist. Mark this peer
                // as our PAKE counterpart; the progression block (top of the loop)
                // sends our SPAKE2 element and, once K + fingerprints are known,
                // the key-confirmation MAC. NO secret is sent over the DataChannel.
                pake_peer.get_or_insert(pid.clone());
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
            Ev::Control(pid, v) if stall => {
                let _ = (pid, v); // gate 17b: connected, but ignore all ceremony control
            }
            Ev::Control(_pid, v) => match v["type"].as_str() {
                // L1-a downgrade-refusal (spec §6.1): a v2 client NEVER stores a
                // secret handed over the DataChannel. Receiving a `pair-keep` means
                // the PEER is a legacy v1 client. We refuse — pairing securely
                // requires v2 on both ends. A malicious server stripping `v:2`
                // cannot exploit this: there is no path here that stores a
                // server-readable secret.
                Some("pair-keep") => {
                    bail!("the other device uses an older version and can't pair securely — update it (or this CLI) so first-pairing runs the encrypted handshake. Nothing was stored.");
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
                // A faster, friendlier signal than the ceremony budget when it
                // arrives: the pairing peer left the room. (The budget is the
                // hard backstop — server peer-left can lag behind a hard kill.)
                let gone = v["id"].as_str().and_then(|p| conn.link(p)).map(|l| l.name.clone());
                conn.on_peer_left(&v);
                let n = gone.unwrap_or_else(|| "the other device".into());
                ui::say(&ui::paint(ui::Tone::Dim, &format!("  {n} disconnected — waiting briefly in case it reconnects…")));
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
    /// WebRTC peer connection. `None` for a rung-1 direct link (no ICE/DTLS
    /// negotiation — it rides authenticated QUIC), so every WebRTC-only call
    /// site (`handle_signal`, `fingerprints`, `restart_ice`, the watchdog's
    /// `is_connected`) is reachable only when this is `Some`.
    peer: Option<Arc<Peer>>,
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
    /// The devices.json PETNAME this link proved as (the cap-store key). Set on a
    /// verified `pair-proof` (WebRTC) or at birth for a direct link (already
    /// identity-bound). `None` until proven. Capability lookups (e.g. the `shell`
    /// gate) MUST key on this, NOT on `name` (a presence display string that may
    /// not match a stored record).
    verified_name: Option<String>,
    /// C26: what the status roster shows for this peer
    presence: Presence,
    /// rung-1 (FILAMENT_DIRECT): this link's transport is an authenticated direct
    /// QUIC connection — its pair-secret MAC already proved identity, so the
    /// post-channel DTLS pair-proof is skipped and the link is born trusted.
    direct: bool,
    /// Route label for a direct link (no WebRTC `route()` to query): `direct-quic`
    /// for rung-1, `holepunched` for rung-2. Ignored for WebRTC links.
    direct_route: &'static str,
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
    /// #28 (deferred drop): sids that got a peer-left while their data channel
    /// was still FLOWING. The signaling socket left the room, but the WebRTC
    /// link is independent and may be a cosmetic reconnect mid-transfer. We do
    /// NOT drop immediately (that kills a live transfer) and do NOT drop never
    /// (a hard-killed peer reads flowing for a beat and would strand the
    /// sender). Instead we stash the original peer-left payload here and
    /// re-check on every main-loop tick: once the link goes idle past the
    /// flowing threshold (or its channel is dead), we re-inject the stored
    /// peer-left so the normal handler runs verbatim — now dropping it. A live
    /// reconnect never goes idle (the transfer completes on it), so its entry
    /// is reaped harmlessly once done. Cleared in drop_link so a supersede of a
    /// deferred sid can't leave a stale blocker.
    deferred_left: HashMap<String, Value>,
    /// Gate-18 Mode B: set TRUE by the recv loop, each tick, exactly when the
    /// transfer is COMPLETE and nothing is in flight (`completed>0 &&
    /// by_sid.is_empty() && !keep_open`). When it holds, `on_stuck` DROPS a
    /// stuck/lost link instead of re-establishing it: there is nothing left to
    /// fetch, so reconnect attempts are pointless and a sender that departs
    /// AFTER delivering every byte would otherwise FLAP the link forever
    /// (establish → connect → die → Stuck → establish …), each cycle resetting
    /// `attempts` (so MAX_ATTEMPTS never caps it) and re-arming `expected_secret`
    /// (so `digest_says_alone` never holds) — `conn.links` never empties and the
    /// quiet-exit never fires → RC=124 hang. Dropping the link empties
    /// `conn.links` and lets the quiet-exit fire. Recomputed PER TICK (never
    /// sticky) so a mid-transfer link (`by_sid` non-empty) always reconnects
    /// normally — kill-resume (gate 2) and the #28 deferred-drop (gate 11c)
    /// reconnect paths are untouched. Defaults false, so the send-side and
    /// connecting-phase `on_stuck` callers are unaffected.
    recv_done: bool,
    /// rung-1 (FILAMENT_DIRECT): in-flight direct-QUIC attempts, keyed by peer
    /// sid. While an attempt is pending we do NOT establish WebRTC for that peer
    /// (sequential, per the design review — avoids two transports racing to
    /// ChannelReady). On deadline expiry with no DirectReady the entry is
    /// dropped and the normal WebRTC `establish` runs; the fallback is unchanged.
    direct_pending: HashMap<String, DirectPending>,
}

/// rung-1: state for one in-flight direct-QUIC attempt.
struct DirectPending {
    /// (name, secret) for the known device — gates the attempt and keys the MAC.
    secret: (String, String),
    /// budget deadline; on expiry with no DirectReady we fall back to WebRTC.
    deadline: Instant,
    /// set once the peer's transport-offer arrived and we spawned the racer, so
    /// a duplicate offer doesn't spawn a second race.
    racing: bool,
    /// kept alive so the bound UDP port stays ours until the race consumes it.
    endpoint: Option<quinn::Endpoint>,
    /// rung-2 (FILAMENT_HOLEPUNCH): a SECOND raw UDP socket, already STUN'd, kept
    /// raw (not connected) so its NAT mapping is the one we punch + run QUIC on.
    /// Consumed by the chained ladder in `on_transport_offer` only if rung-1
    /// fails. None when hole-punch is off or STUN discovery failed.
    punch_sock: Option<std::net::UdpSocket>,
    /// rung-2: our advertised srflx (logged at offer time; kept for diagnostics).
    #[allow(dead_code)]
    my_srflx: Option<std::net::SocketAddr>,
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

    /// #28: is the link keyed by `pid` actively moving transfer bytes right now?
    /// The data channel is independent of the signaling socket, so when a
    /// same-uid reconnect arrives as a new sid, superseding must NOT tear down
    /// an old link that's still flowing. A frozen-alive peer (gate 11's
    /// SIGSTOP'd receiver) stops stamping activity, so it reads as not-flowing
    /// and the supersede proceeds as before. Threshold is overridable for
    /// deterministic gating (FILAMENT_ADOPT_ACTIVE_MS); the 3 s default sits
    /// well above a healthy sub-100 ms inter-frame gap so a transient ICE blip
    /// can't masquerade as idle and let a spurious supersede through.
    fn link_flowing(&self, pid: &str) -> bool {
        let threshold = std::env::var("FILAMENT_ADOPT_ACTIVE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3000);
        self.transport_of(pid)
            .map(|t| t.idle_ms() < threshold)
            .unwrap_or(false)
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
            // #28: the same device reconnected its signaling socket (fresh sid).
            // If its existing data channel is still flowing, the reconnect is
            // cosmetic — superseding would tear down an active transfer. Keep the
            // old link; once it goes idle a later roster/presence event supersedes.
            if self.link_flowing(&old_sid) {
                // Observable so a gate can assert the keep happened (true
                // positive), not merely that no supersede line appeared.
                eprintln!("{name} reconnected — keeping active link");
                return Ok(self.is_active(&old_sid));
            }
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
        // #28: a deferred-active slot is claimable. When the active link got a
        // peer-left but is still flowing, we keep `active` pointing at it (so a
        // same-uid reconnect's supersede still sees it active, and the live
        // transfer's offer/exit machinery is undisturbed). But a DIFFERENT-uid
        // replacement (gate 2: hard-killed receiver, fresh recv) must still be
        // able to take over — otherwise the deferred link squats the slot until
        // the reap, and the replacement (whose ChannelReady already fired) never
        // gets promoted or offered the file. Treating a deferred active as
        // "claimable" promotes the replacement at peer-joined, before its
        // ChannelReady, so the offer goes out on the same baseline path.
        let active_deferred = self
            .active
            .as_ref()
            .is_some_and(|a| self.deferred_left.contains_key(a));
        if want_active && (self.active.is_none() || active_deferred) && self.targetable(&name, peer_uid.as_deref()) {
            // Claiming the slot from a deferred link: discharge that link now
            // (it left the room and is being replaced) so reap doesn't later
            // re-inject a stale peer-left against the slot the new peer holds.
            if active_deferred {
                if let Some(old) = self.active.clone() {
                    if old != peer_id {
                        self.drop_link(&old);
                    }
                }
            }
            self.active = Some(peer_id.clone());
            self.waiting_rejoin = None;
        }
        Ok(self.is_active(&peer_id))
    }

    fn drop_link(&mut self, pid: &str) {
        // #28: dropping a link also discharges any deferred peer-left for it —
        // so a supersede (maybe_adopt) of a deferred same-uid sid can't leave a
        // stale entry blocking adoption. Invariant: deferred_left only ever
        // holds sids that are still live links.
        self.deferred_left.remove(pid);
        if let Some(old) = self.links.remove(pid) {
            // Never await close in the event loop (F8): mark + spawn. A direct
            // link has no WebRTC peer; dropping the Link drops its QUIC transport
            // (the keepalive task observes conn.closed() and tears down).
            if let Some(p) = old.peer.clone() {
                p.mark_closed();
                tokio::spawn(async move { p.close().await });
            }
        }
        if self.is_active(pid) {
            self.active = None;
        }
    }

    async fn establish(&mut self, info: Value) -> Result<()> {
        self.establish_as(info, None).await
    }

    /// `force_polite: Some(true)` builds a pure responder link (no local offer)
    /// regardless of uid comparison — required when the link exists to ANSWER
    /// an incoming offer (ensure_responder / glare rebuild). The uid-based role
    /// can come out impolite there (especially on the bare `{id}` roster-miss
    /// fallback, which compares sids), making the "responder" offer too: glare.
    async fn establish_as(&mut self, info: Value, force_polite: Option<bool>) -> Result<()> {
        let peer_id = info["id"].as_str().unwrap_or_default().to_string();
        // rung-1: a direct-QUIC attempt owns this peer until its budget expires.
        // Suppress the WebRTC offer so the path stays SEQUENTIAL (no two
        // transports racing to ChannelReady). `expired_direct` removes the
        // pending before calling us for the fallback, so this never blocks it.
        if self.direct_pending.contains_key(&peer_id) {
            return Ok(());
        }
        self.drop_link(&peer_id); // re-establish replaces any same-sid link
        let peer_uid = info["uid"].as_str().map(|s| s.to_string());
        let name = info["name"].as_str().unwrap_or("peer").to_string();
        // C5: fresh ICE config (TURN creds are expiry-stamped HMACs) for
        // every attempt, not just the first.
        let cfg = net::fetch_config(&self.server).await?;
        self.chunk_size = cfg.chunk_size;
        let polite = force_polite.unwrap_or_else(|| {
            net::polite_role(&self.my_uid, peer_uid.as_deref(), &self.my_id, &peer_id)
        });
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
                peer: Some(peer),
                info,
                name,
                uid: peer_uid,
                transport: None,
                generation,
                attempts: 0,
                trusted: false,
                expected_secret: None,
                verified_name: None,
                presence: Presence::Connecting,
                direct: false,
                direct_route: "direct-quic", // unused for WebRTC links (peer.is_some())
            },
        );
        Ok(())
    }

    // --- rung-1 direct-QUIC path (FILAMENT_DIRECT) ---------------------------
    //
    // Sequential by design: when both peers are CLIs and a pair secret is known,
    // try a direct authenticated QUIC connection FIRST and only fall back to the
    // WebRTC `establish` above if no authenticated connection lands within the
    // budget. The whole thing is gated on `direct::direct_enabled()`, so with the
    // flag OFF none of this runs and the WebRTC path is byte-for-byte unchanged.

    /// Begin a direct attempt against `pid`: bind a quinn endpoint, advertise our
    /// candidates via a relayed `transport-offer`, and stash the pending state.
    /// No Link is created yet — it is born (with `peer: None`, pre-trusted) only
    /// when an authenticated connection wins (Ev::DirectReady). Idempotent per
    /// peer (a second call while pending is a no-op). The peer's own
    /// transport-offer (Ev::TransportOffer) drives the race.
    async fn start_direct(&mut self, pid: &str, name: &str, secret: &str) {
        if !direct::direct_enabled() {
            return;
        }
        if self.direct_pending.contains_key(pid) || self.links.contains_key(pid) {
            return; // already trying, or already linked (WebRTC or direct)
        }
        let (ep, port) = match direct::bind_endpoint() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("filament: direct disabled (endpoint bind failed: {e})");
                return;
            }
        };
        let cands = direct::gather_candidates(&self.server, port).await;

        // rung-2 (FILAMENT_HOLEPUNCH): bind a SECOND raw socket and STUN it so we
        // can advertise a server-reflexive candidate. This socket is kept RAW
        // (not handed to quinn) — its NAT mapping is the one we'll punch + run
        // QUIC on if rung-1's host-candidate race fails. STUN failure is graceful:
        // no srflx is advertised and rung-2 simply won't fire for this peer.
        let (punch_sock, my_srflx) = if holepunch::holepunch_enabled() {
            match self.gather_srflx().await {
                Some((sock, srflx)) => (Some(sock), Some(srflx)),
                None => (None, None),
            }
        } else {
            (None, None)
        };

        // transport-offer rides the OPAQUE signaling relay (same channel as ICE
        // signals); the server cannot read or forge it without failing the MAC.
        let mut offer = json!({ "type": "transport-offer", "v": 1, "addrs": cands });
        if let Some(s) = my_srflx {
            offer["srflx"] = json!(s.to_string());
        }
        let _ = self
            .sio
            .emit("signal", json!({ "to": pid, "data": offer.clone() }))
            .await;
        eprintln!(
            "filament: DIRECT-OFFER sent to {name} ({pid}) — port {} srflx {}",
            port,
            my_srflx.map(|s| s.to_string()).unwrap_or_else(|| "-".into())
        );
        // Re-send the offer periodically. The L2 initiator (netcat/ssh) subscribes
        // to the channel AFTER us, so on a late join it can miss BOTH our single
        // fire-once offer AND its own KnownPeer for us (presence delivery is racy)
        // — the cross-machine stall. Re-emitting lets it catch a later offer and
        // dial our (reachable) candidates; the initiator only races the FIRST
        // offer it gets, so the extra emits are harmless once linked.
        {
            let sio = self.sio.clone();
            let pid_c = pid.to_string();
            tokio::spawn(async move {
                for _ in 0..6 {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    let _ = sio
                        .emit("signal", json!({ "to": pid_c, "data": offer.clone() }))
                        .await;
                }
            });
        }
        // The WebRTC fallback reaper (`expired_direct`) fires at this deadline.
        // rung-1's race always burns the full DIRECT_BUDGET when it can't win
        // (its acceptor future never self-completes), so with hole-punch enabled
        // the deadline MUST cover the WHOLE ladder — rung-1 budget + punch budget
        // + QUIC handshake slack — or the reaper would race WebRTC against an
        // in-flight punch and the route would be a coin flip. Flag-gated, so
        // rung-1-only timing is byte-identical.
        let deadline = if holepunch::holepunch_enabled() {
            Instant::now() + direct::DIRECT_BUDGET + holepunch::PUNCH_BUDGET + Duration::from_secs(3)
        } else {
            Instant::now() + direct::DIRECT_BUDGET
        };
        self.direct_pending.insert(
            pid.to_string(),
            DirectPending {
                secret: (name.to_string(), secret.to_string()),
                deadline,
                racing: false,
                endpoint: Some(ep),
                punch_sock,
                my_srflx,
            },
        );
    }

    /// rung-2: bind a raw punch socket and discover its srflx via STUN against
    /// the ICE config's STUN server. Returns (raw socket, srflx) or None.
    async fn gather_srflx(&self) -> Option<(std::net::UdpSocket, std::net::SocketAddr)> {
        let cfg = net::fetch_config(&self.server).await.ok()?;
        let stun_urls: Vec<String> = cfg
            .ice_servers
            .iter()
            .flat_map(|s| s.urls.iter().cloned())
            .collect();
        let stun_addr = holepunch::stun_server_addr(&stun_urls)?;
        let sock = holepunch::bind_punch_socket().ok()?;
        // STUN is blocking UDP I/O — run it off the reactor.
        tokio::task::spawn_blocking(move || {
            holepunch::stun_srflx(&sock, stun_addr).map(|srflx| (sock, srflx))
        })
        .await
        .ok()?
        .ok()
    }

    /// The peer advertised its candidates. If we have a matching pending attempt
    /// and haven't started the race yet, consume the endpoint and spawn the
    /// simultaneous-open + auth race; the winner posts Ev::DirectReady.
    fn on_transport_offer(&mut self, pid: &str, peer_cands: Vec<String>, peer_srflx: Option<String>) {
        let Some(p) = self.direct_pending.get_mut(pid) else { return };
        if p.racing {
            return;
        }
        let Some(ep) = p.endpoint.take() else { return };
        p.racing = true;
        let secret = p.secret.1.clone();
        // rung-2: hand the punch socket + peer's srflx to the chained ladder.
        let punch_sock = p.punch_sock.take();
        let peer_srflx_addr = peer_srflx
            .as_deref()
            .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
        let tx = self.tx.clone();
        let pid_s = pid.to_string();
        tokio::spawn(async move {
            // rung-1: direct-dial QUIC over host candidates (UNCHANGED).
            if let Some(t) =
                direct::race_connect(ep, peer_cands, &secret, pid_s.clone(), tx.clone()).await
            {
                let _ = tx.send(Ev::DirectReady(pid_s, t, "direct-quic"));
                return;
            }
            // rung-2: UDP hole-punch, then rung-1's QUIC race over the punched
            // socket. Only fires with the flag on, a punch socket bound, and a
            // peer srflx to punch toward. On failure (e.g. symmetric NAT) we fall
            // through to the WebRTC step-down via the per-tick reaper.
            if holepunch::holepunch_enabled() {
                if let (Some(sock), Some(peer_srflx)) = (punch_sock, peer_srflx_addr) {
                    eprintln!(
                        "filament: rung-1 failed — attempting hole-punch to {peer_srflx}"
                    );
                    if let Some(t) = holepunch::connect(
                        sock,
                        peer_srflx,
                        &secret,
                        pid_s.clone(),
                        tx.clone(),
                    )
                    .await
                    {
                        let _ = tx.send(Ev::DirectReady(pid_s, t, "holepunched"));
                        return;
                    }
                }
            }
            // On None the per-tick reaper handles the WebRTC fallback at deadline.
        });
    }

    /// Create the Link for a direct connection that won the race. `peer: None`
    /// (no WebRTC), `direct: true`, `trusted: true` (the pair-secret MAC already
    /// proved identity — at least as strong as the DTLS pair-proof it replaces).
    fn adopt_direct(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let pend = self.direct_pending.remove(pid);
        let (name, secret) = match pend {
            Some(p) => p.secret,
            None => ("peer".to_string(), String::new()),
        };
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": name }));
        let uid = info["uid"].as_str().map(|s| s.to_string());
        let expected_secret = if secret.is_empty() {
            None
        } else {
            Some((name.clone(), secret))
        };
        self.next_gen += 1;
        let generation = self.next_gen;
        self.links.insert(
            pid.to_string(),
            Link {
                peer: None,
                info,
                name,
                uid,
                transport: Some(t),
                generation,
                attempts: 0,
                trusted: true,
                // A direct link is born identity-bound (its pair-secret MAC
                // already proved who it is), so the petname is known up front.
                verified_name: expected_secret.as_ref().map(|(n, _)| n.clone()),
                expected_secret,
                presence: Presence::Ready,
                direct: true,
                direct_route: route,
            },
        );
    }

    /// Per-tick: a direct attempt whose budget expired without an authenticated
    /// connection falls back to the WebRTC `establish` (unchanged). Returns the
    /// list of (pid, info) to establish — caller awaits establish outside the
    /// borrow. Also drops any pending whose Link already exists.
    fn expired_direct(&mut self) -> Vec<(String, Value, (String, String))> {
        let now = Instant::now();
        let mut fell_back = Vec::new();
        let expired: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| now >= p.deadline && !self.links.contains_key(*pid))
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired {
            if let Some(p) = self.direct_pending.remove(&pid) {
                let info = self
                    .roster
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| json!({ "id": pid, "name": p.secret.0 }));
                eprintln!(
                    "filament: DIRECT-FALLBACK for {} — no authenticated QUIC in budget, using WebRTC",
                    p.secret.0
                );
                fell_back.push((pid, info, p.secret));
            }
        }
        // Drop pendings whose link landed by another route (cleanup).
        let linked: Vec<String> = self
            .direct_pending
            .keys()
            .filter(|pid| self.links.contains_key(*pid))
            .cloned()
            .collect();
        for pid in linked {
            self.direct_pending.remove(&pid);
        }
        fell_back
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
        // rung-1: a direct link has no WebRTC watchdog (no Peer::connect timer),
        // so on_stuck can't fire for it; defensively no-op if it ever does.
        if l.direct {
            return Ok(false);
        }
        if l.generation != generation || l.peer.as_ref().map(|p| p.is_connected()).unwrap_or(true) {
            return Ok(false); // stale timer from a superseded attempt
        }
        // Gate-18 Mode B: the transfer is COMPLETE (recv_done; recomputed per
        // tick by the recv loop, so this can only be true with by_sid empty and
        // !keep_open) and this link just went stuck/lost. Reconnecting would
        // fetch nothing and merely FLAP the link — resetting attempts and
        // re-arming expected_secret each cycle — so conn.links never empties and
        // the quiet-exit can't fire (RC=124 hang under contention). DROP it
        // instead: links empties, quiet-exit fires. Fenced to complete-only, so
        // a mid-transfer link (recv_done=false) reconnects normally (gate 2/11c).
        // FILAMENT_TEST_DISABLE_MODEB_DROP reverts to the old reconnect-always
        // behaviour so the gate proves A/B with ONE binary: baseline (toggle set)
        // hangs to RC=124 under the churn hook; fix (toggle unset) exits cleanly.
        if self.recv_done && std::env::var("FILAMENT_TEST_DISABLE_MODEB_DROP").is_err() {
            let was_active = self.is_active(pid);
            eprintln!(
                "{}",
                ui::paint(ui::Tone::Dim, &format!("dropping peer (connection {why} after completion — nothing left to fetch)"))
            );
            self.drop_link(pid);
            return Ok(was_active);
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
                if let Some(p) = &l.peer {
                    if !p.polite && !away {
                        p.restart_ice().await;
                    }
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
    ///
    /// #28 DEFERRED DROP: peer-left fires when a sid LEAVES THE ROOM, but the
    /// WebRTC data channel is independent and may still be flowing — either a
    /// cosmetic signaling reconnect mid-transfer (keep it!) or a hard-killed
    /// peer whose channel reads flowing for a beat before DTLS notices (must
    /// still drop, or the sender strands). We can't tell the two apart at this
    /// instant, so we DEFER: stash the payload and re-check each tick
    /// (`reap_deferred`). If it goes idle/dead it gets re-injected here with a
    /// force marker and dropped then; if it keeps flowing the transfer
    /// completes on the live channel and the idle link is reaped harmlessly.
    /// The roster entry is removed immediately (the sid truly left); only the
    /// LINK drop is deferred.
    fn on_peer_left(&mut self, v: &Value) -> bool {
        let Some(pid) = v["id"].as_str() else { return false };
        let pid = pid.to_string();
        self.roster.remove(&pid);
        if !self.links.contains_key(&pid) {
            return false;
        }
        // Defer the drop while the data channel is still moving bytes — unless
        // this is the force re-injection from reap_deferred (the link has since
        // gone idle/dead and must drop now). FILAMENT_TEST_NO_DEFER reverts to
        // the old unconditional-drop behaviour so an A/B repro can prove the
        // deferral is what saves the live transfer (baseline must FAIL).
        let forced = v["__fil_force_drop"].as_bool() == Some(true);
        let defer_disabled = std::env::var("FILAMENT_TEST_NO_DEFER").is_ok();
        if !forced && !defer_disabled && self.link_flowing(&pid) {
            // Idempotent: first peer-left for this sid records the original
            // payload; a duplicate is swallowed (no double-defer, no drop).
            self.deferred_left.entry(pid.clone()).or_insert_with(|| v.clone());
            let name = self.link(&pid).map(|l| l.name.clone()).unwrap_or_else(|| "peer".into());
            eprintln!("{name} signaling left — data channel still flowing, deferring drop");
            return false;
        }
        let was_active = self.is_active(&pid);
        self.drop_link(&pid);
        if was_active {
            // C21: informed waits — a peer that declared `brb` gets its
            // promised window (plus slack); an unannounced vanish gets the
            // short default. Their client auto-rejoins; C6 supersede or a
            // fresh adopt completes the recovery.
            self.rejoin_window = match &self.away {
                Some((apid, until)) if *apid == pid && *until > Instant::now() => {
                    until.duration_since(Instant::now()) + Duration::from_secs(15)
                }
                _ => rejoin_unwarned(),
            };
            self.waiting_rejoin = Some(Instant::now());
        }
        was_active
    }

    /// #28: re-check every deferred peer-left. Called on every main-loop tick
    /// (idempotent, cheap). A deferred sid is discharged when it is no longer
    /// flowing — its data channel went idle past the threshold OR died
    /// (idle_ms == u64::MAX). We then re-inject the ORIGINAL peer-left payload
    /// (flagged force) so the normal Ev::PeerLeft handler runs verbatim — same
    /// loop-side flush/messaging/rejoin behaviour as a non-deferred leave, with
    /// the link now correctly dropped. A sid that vanished from `links` (e.g. a
    /// supersede dropped it; drop_link already cleared its entry, but belt-and-
    /// braces) is forgotten silently. A still-flowing sid is left to keep
    /// flowing — the reconnect case, where the transfer completes on the live
    /// channel and the all-done exit reaps it.
    fn reap_deferred(&mut self) {
        if self.deferred_left.is_empty() {
            return;
        }
        let ready: Vec<(String, Value)> = self
            .deferred_left
            .iter()
            .filter(|(sid, _)| !self.links.contains_key(*sid) || !self.link_flowing(sid))
            .map(|(sid, v)| (sid.clone(), v.clone()))
            .collect();
        for (sid, mut payload) in ready {
            self.deferred_left.remove(&sid);
            if !self.links.contains_key(&sid) {
                continue; // link already gone (superseded); nothing to drop
            }
            // Force the drop this time (the channel is now idle/dead).
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("__fil_force_drop".into(), Value::Bool(true));
            }
            let name = self.link(&sid).map(|l| l.name.clone()).unwrap_or_else(|| "peer".into());
            eprintln!("{name} link went idle after deferred leave — dropping now");
            // Re-inject so the loop's own peer-left branch handles partials,
            // messaging and the rejoin window exactly as a fresh leave would.
            let _ = self.tx.send(Ev::PeerLeft(payload));
        }
    }

    /// #28 exit reconciliation: true when every remaining link is one we're only
    /// holding open for its deferred-drop reap (vacuously true with no links). A
    /// link in `deferred_left` is a peer whose signaling already left; once all
    /// transfers are complete it protects nothing, so it must not delay exit by
    /// the full deferral window.
    fn only_deferred_links(&self) -> bool {
        self.links.keys().all(|k| self.deferred_left.contains_key(k))
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
    /// Apply a relayed signal to `from`'s link. Never fatal (F6): the
    /// watchdog/grace machinery owns failed negotiations. On polite-side
    /// glare (webrtc-rs can't roll back out of have-local-offer) the link is
    /// rebuilt as a pure responder and the colliding offer re-applied.
    async fn apply_signal(&mut self, from: &str, data: Value) {
        let peer = match self.link(from).and_then(|l| l.peer.clone()) {
            Some(p) => p,
            None => return,
        };
        match peer.handle_signal(data).await {
            Ok(net::SignalOutcome::Handled) => {}
            Ok(net::SignalOutcome::Glare(offer)) => {
                self.drop_link(from);
                if let Err(e) = self.ensure_responder(from, &offer).await {
                    eprintln!("signal: glare rebuild failed: {e} (recovering)");
                    return;
                }
                if let Some(p) = self.link(from).and_then(|l| l.peer.clone()) {
                    if let Err(e) = p.handle_signal(offer).await {
                        eprintln!("signal failed to apply: {e} (recovering)");
                    }
                }
            }
            Err(e) => eprintln!("signal failed to apply: {e} (recovering)"),
        }
    }

    async fn ensure_responder(&mut self, from: &str, data: &Value) -> Result<()> {
        if self.links.contains_key(from) {
            return Ok(());
        }
        if data["type"].as_str() == Some("description")
            && data["description"]["type"].as_str() == Some("offer")
        {
            // Answer a WebRTC offer from a channel-peer EVEN IF we never got its
            // known-peer. The existing-member known-peer notification is
            // unreliable on prod (proven via the signaling harness: the NEW
            // joiner is reliably notified, but the EXISTING member often is NOT)
            // — which left the acceptor ignoring a valid initiator's offer and
            // looking like "stuck connecting". One-sided discovery is now enough:
            // whoever discovers drives, the other answers. SAFE: trust still
            // gates entirely on the pair-proof MAC (an attacker without the
            // secret fails it and is never trusted) — we only answer the offer
            // and let the proof decide. A later known-peer refreshes name/uid.
            let info = self
                .roster
                .get(from)
                .cloned()
                .unwrap_or_else(|| json!({ "id": from }));
            if self.links.len() < MAX_LINKS {
                // Forced responder: this link exists to answer THEIR offer.
                self.establish_as(info, Some(true)).await?;
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
        // C30: never block indefinitely — a 2s tick lets the convergent
        // session repair lost emits even when no events arrive.
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
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
        const CMDS: [&str; 17] = ["send", "recv", "devices", "update", "completions", "man", "config", "help", "up", "status", "down", "introduce", "netcat", "forward", "ssh", "grant", "revoke"];
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
            recv_cmd(&server, code, dir, yes, room, to, keep_open, cli.relay, remember, false, output, ShellPolicy::Granted).await
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
        Cmd::Up { install, dir, shell, shell_only } => up_cmd(&server, install, dir, cli.relay, shell, shell_only).await,
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
                    // Rename in place on the raw record so caps/v2 fields ride
                    // along (remove+store dropped the renamed device's caps).
                    let p = devices_path();
                    let mut arr: Vec<Value> = std::fs::read_to_string(&p)
                        .ok()
                        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default();
                    if !arr.iter().any(|d| d["name"].as_str() == Some(old.as_str())) {
                        bail!("no device named '{old}' — see `filament devices`");
                    }
                    if arr.iter().any(|d| d["name"].as_str() == Some(new.as_str())) {
                        bail!("'{new}' already exists — forget it first or pick another name");
                    }
                    for d in arr.iter_mut() {
                        if d["name"].as_str() == Some(old.as_str()) {
                            d["name"] = json!(new);
                        }
                    }
                    std::fs::write(&p, serde_json::to_string_pretty(&arr)?)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
                    }
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
        Cmd::Netcat { peer, rport } => l2::netcat_cmd(&server, &peer, rport, cli.relay).await,
        Cmd::Pty { peer } => l2::pty_cmd(&server, &peer, cli.relay).await,
        Cmd::Forward { lport, peer, rport } => l2::forward_cmd(&server, lport, &peer, rport, cli.relay).await,
        Cmd::Ssh { peer, args } => l2::ssh_cmd(&server, &peer, &args, cli.relay).await,
        Cmd::Grant { device, capability } => {
            device_set_cap(&device, &capability, true)?;
            println!(
                "granted '{capability}' to '{device}'. {}",
                if capability == "shell" {
                    "they can now `filament ssh` into this machine (their key is installed on first connect)."
                } else {
                    ""
                }
            );
            Ok(())
        }
        Cmd::Revoke { device, capability } => {
            device_set_cap(&device, &capability, false)?;
            if capability == "shell" {
                sshkeys::remove_authorized_key(&device)?;
                println!("revoked 'shell' from '{device}' and removed its filament-managed authorized_keys block.");
            } else {
                println!("revoked '{capability}' from '{device}'.");
            }
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
    // the next version outrank the previous release; -pre < its release;
    // beta.2 > beta.1 — the prerelease NUMBER counts, found live when
    // `--beta` kept offering beta.1 to beta.2).
    fn key(v: &str) -> (u64, u64, u64, bool, u64) {
        let (core, pre) = v.split_once('-').map(|(c, p)| (c, Some(p))).unwrap_or((v, None));
        let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        let pre_num = pre.and_then(|p| p.rsplit('.').next()).and_then(|n| n.parse().ok()).unwrap_or(0);
        (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0), pre.is_none(), pre_num)
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
    // C30: the convergent session repairs room/channel/lease state the
    // one-shot emits lose (the fast path stays for old servers + latency);
    // under gate L these initial emits are exactly what the shim drops.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(room.clone());
    sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;

    // C12: --to matching a remembered device switches to identity mode —
    // subscribe to its presence channel and wait for known-peer.
    let known_target: Option<(String, String)> =
        to.as_ref().and_then(|t| devices_load().into_iter().find(|(n, _)| n.eq_ignore_ascii_case(t)));
    if let Some((n, sec)) = &known_target {
        ui::say(&format!("  waiting for known device {}", ui::paint(ui::Tone::Bold, n)));
        sess.channels = vec![channel_of(sec)];
        sess.emit(&sio, "subscribe", json!({ "channels": [channel_of(sec)] })).await;
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
        deferred_left: HashMap::new(),
        recv_done: false,
    direct_pending: HashMap::new(),
    };
    if known_target.is_some() {
        conn.to_filter = None; // identity supersedes name matching
    }
    let mut code_used = !use_code && known_target.is_none();
    // C30 phase 3: link mini-sync — pings out, divergence corrections in.
    let mut last_state_ping = Instant::now();
    let mut reproved: std::collections::HashSet<String> = Default::default();
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
            // C30: read in ≤2s slices — a blocking full-deadline read starves
            // the session tick, so a dropped initial subscribe was never
            // repaired and the wait could NEVER succeed (found by gate L's
            // seed-16 choreography: the daemon healed, the sender starved).
            if started.elapsed() >= claim_deadline {
                bail!("timed out waiting for a peer — is the other device online and on the same server? (--code makes pairing explicit)");
            }
            let slice = Duration::from_secs(2).min(claim_deadline.saturating_sub(started.elapsed()));
            match tokio::time::timeout(slice, rx.recv()).await {
                Ok(Some(ev)) => Some(ev),
                Ok(None) => bail!("signaling channel closed"),
                Err(_) => None, // tick
            }
        } else {
            next_ev(&mut rx, &conn, false).await?
        };
        // C30: converge session state every iteration (incl. ticks).
        sess.tick(&sio).await;
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // rung-1: a direct attempt that timed out without an authenticated QUIC
        // connection falls back to the WebRTC establish (unchanged path).
        for (pid, info, (n, sec)) in conn.expired_direct() {
            conn.establish(info).await?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
            if conn.to_filter.is_none() && conn.active.is_none() {
                conn.active = Some(pid.clone());
            }
        }
        // C30 phase 3: tell every link our truth every ~10s (sender side has
        // no receive-partials; the ping mainly carries trusted/away and keeps
        // the peer's away-mark honest).
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for l in conn.links.values() {
                if let Some(t) = &l.transport {
                    let _ = t
                        .send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": {},
                            "trusted": l.trusted,
                            "away": false,
                        }))
                        .await;
                }
            }
        }
        let Some(ev) = ev else { continue };

        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, code_used).await?;
                    }
                }
                // C30 (dissolves the C28 belt): fresh sid = everything
                // sid-keyed is gone; invalidate and let the session re-assert.
                sess.invalidate();
            }
            // C30: server confirmed our session digest.
            Ev::Synced(v) => { sess.on_synced(&v); }
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
                        // rung-1: both ends are CLIs (known device) — try direct
                        // QUIC FIRST. start_direct records the pending so the
                        // maybe_adopt->establish below skips the WebRTC offer
                        // until the budget expires (then it falls back).
                        let (n, sec) = (n.clone(), sec.clone());
                        conn.start_direct(&pid, &n, &sec).await;
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
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates — kick off the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    // rung-2: optional server-reflexive candidate for hole-punch.
                    let srflx = data["srflx"].as_str().map(String::from);
                    conn.on_transport_offer(&from, cands, srflx);
                    continue;
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            // rung-1: the authenticated direct-QUIC connection won the race.
            // Create the (pre-trusted) Link, then funnel into the SAME ready
            // handler the WebRTC path uses (announce + offers) by re-emitting
            // ChannelReady — the transfer logic rides the trait unchanged.
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
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
                    let is_direct = l.direct;
                    let direct_route = l.direct_route;
                    if let Some(p) = l.peer.clone() {
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
                    } else if is_direct {
                        ui::say(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {direct_route}"))));
                    }
                    // C12: prove identity to a known device (their daemon
                    // auto-accepts only after verifying); or hand over a new
                    // pair secret when the user asked to --remember. A DIRECT
                    // link already proved the secret via the QUIC keying-material
                    // MAC (>= the DTLS pair-proof), so it skips this dance.
                    if is_direct {
                        // pre-authenticated; nothing to prove over the channel.
                    } else if let Some((_n, sec)) = &l.expected_secret {
                        if let Some((my_fp, their_fp)) = match &l.peer { Some(p) => p.fingerprints().await, None => None } {
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
                // C30 phase 3: the peer's periodic truth — correct one-sided
                // beliefs instead of letting them persist.
                Some("state") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid); // a state ping proves they're not frozen
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                    // Transfer divergence: I believe it complete; the peer
                    // holds fewer bytes — the END/tail was lost. Re-offer.
                    if let Some(obj) = v["transfers"].as_object() {
                        let mut out = outgoing.lock().await;
                        for o in out.iter_mut() {
                            if let Some(b) = obj.get(&o.id).and_then(|x| x.as_u64()) {
                                if o.done && b < o.size {
                                    o.done = false; // not actually done
                                    eprintln!(
                                        "{}",
                                        ui::paint(ui::Tone::Warn, &format!("  state-diverged: {} — peer holds {b}/{}; re-offering", o.name, o.size))
                                    );
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let mut offer = json!({
                                            "type": "file-offer", "id": o.id, "sid": o.sid,
                                            "name": o.name, "size": o.size, "mime": "application/octet-stream",
                                            "resume": true,
                                        });
                                        if let Some(h) = &o.head {
                                            offer["head"] = json!(h);
                                        }
                                        let _ = t.send_control(&offer).await;
                                    }
                                }
                            }
                        }
                    }
                    // Trust divergence: they don't recognize us but we hold a
                    // pair secret for them — re-prove ONCE per link.
                    if v["trusted"].as_bool() == Some(false) && !reproved.contains(&pid) {
                        let proof = match conn.link(&pid) {
                            Some(l) => match &l.expected_secret {
                                Some((_n, sec)) => (match &l.peer { Some(p) => p.fingerprints().await, None => None })
                                    .map(|(my_fp, their_fp)| proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp)),
                                None => None,
                            },
                            None => None,
                        };
                        if let Some(mac) = proof {
                            if let Some(t) = conn.transport_of(&pid) {
                                let _ = t.send_control(&json!({ "type": "pair-proof", "mac": mac })).await;
                                reproved.insert(pid.clone());
                                eprintln!("{}", ui::paint(ui::Tone::Dim, "  state-diverged: re-proving identity"));
                            }
                        }
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
                    // #28 test hook: the active peer's sid, so the streamer can
                    // synthesize a peer-left for it mid-flight (see stream_one).
                    let active_sid = conn.active.clone();
                    tokio::spawn(async move {
                        match stream_one(out, t, id.clone(), offset, chunk, active_sid, tx2.clone()).await {
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
                    // Block until the peer has acked every byte before we exit —
                    // a torn-down QUIC connection drops un-acked send-buffer bytes
                    // and truncates the last file (no-op on DataChannel, which
                    // already drained in flush()). Surface a drain failure rather
                    // than silently reporting "done" on a partial transfer.
                    if let Err(e) = t.drain_finish().await {
                        eprintln!("warning: transfer may be incomplete — {e}");
                    }
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
    active_sid: Option<String>,
    tx: mpsc::UnboundedSender<Ev>,
) -> Result<()> {
    let (sid, name, size, path) = {
        let out = outgoing.lock().await;
        let o = out.iter().find(|o| o.id == id).ok_or_else(|| anyhow!("unknown transfer {id}"))?;
        (o.sid, o.name.clone(), o.size, o.path.clone())
    };
    if offset > 0 {
        eprintln!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0);
    }
    // #28 deterministic test hook: once we cross this byte offset, synthesize a
    // peer-left for the ACTIVE peer WITHOUT touching the data channel — exactly
    // the "signaling reconnect mid-transfer, channel stays alive" case. The
    // deferred-drop path must keep the link and let the transfer finish on it.
    // Injecting the active sid is critical: a wrong id makes on_peer_left
    // return early (link-not-found) and the test would falsely pass.
    let inject_at: Option<u64> = std::env::var("FILAMENT_TEST_INJECT_PEER_LEFT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let mut injected = false;
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
        if let (false, Some(at), Some(asid)) = (injected, inject_at, active_sid.as_ref()) {
            if sent >= at {
                injected = true;
                eprintln!("[test] injecting synthetic peer-left for active sid at {sent} bytes");
                let _ = tx.send(Ev::PeerLeft(json!({ "id": asid })));
            }
        }
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
    shell_policy: ShellPolicy,
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
    // C30: the convergent session repairs whatever the one-shot emits below
    // lose — room membership, channel subscriptions, the lease. The emits
    // stay as the fast path (and old-server compat); the session is truth.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.channels = devices.iter().map(|(_, s)| channel_of(s)).collect();
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
            sess.room = Some(solo.clone());
            sess.emit(&sio, "join", json!({ "room": solo, "name": display_name(), "uid": my_uid })).await;
            // C29: an interactive up can START empty and pair in-session.
            if devices.is_empty() && !std::io::stdin().is_terminal() {
                bail!("no known devices — run `filament pair` once, or `filament up` in a terminal to pair interactively");
            }
            let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
            sess.emit(&sio, "subscribe", json!({ "channels": chans })).await;
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
            sess.room = Some(room.clone());
            sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            // C12: announce on every known device's presence channel
            if !devices.is_empty() {
                let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
                eprintln!("watching for {} known device(s)", devices.len());
                sess.emit(&sio, "subscribe", json!({ "channels": chans })).await;
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
        deferred_left: HashMap::new(),
        recv_done: false,
    direct_pending: HashMap::new(),
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
    let quiet_window = quiet_exit_window();
    // C30 phase 2: roster reconciliation from sync digests — a missed
    // peer-joined/left self-corrects. Absence must hold for TWO consecutive
    // digests before a drop (one digest can race a join in flight).
    let mut digest_absent: HashMap<String, u8> = HashMap::new();
    let mut digest_alone = false;
    // C30 phase 3: link mini-sync — state pings every ~10s per link.
    let mut last_state_ping = Instant::now();
    // L2 (ssh/TCP tunnel) acceptor: one mux per link, created on the first
    // l2-open seen on that link. OFF unless FILAMENT_L2=1 (opt-in) OR an active
    // `up --shell` policy turns it on (you can't ssh in without the acceptor).
    // The cap gate (shell-bootstrap) is enforced separately. Keyed by peer sid
    // so multiple links stay isolated.
    let l2_enabled = shell_policy.enables_l2()
        || std::env::var("FILAMENT_L2").map(|v| v == "1").unwrap_or(false);
    let mut l2_muxes: HashMap<String, Arc<l2::Mux>> = HashMap::new();
    // web-shell: per-sid resize senders so a `pty-resize` reaches its PTY task.
    let mut pty_resizers: HashMap<u32, tokio::sync::mpsc::UnboundedSender<(u16, u16)>> = HashMap::new();

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

        // C30: converge session state (no-op unless diverged/stale/unconfirmed).
        sess.tick(&sio).await;
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // rung-1: direct attempt timed out → fall back to WebRTC (unchanged).
        for (pid, info, (n, sec)) in conn.expired_direct() {
            conn.maybe_adopt(&info, true).await?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
        }

        // C30 phase 3: state pings — each open link hears our transfer/away
        // truth every ~10s, so one-sided beliefs between PEERS can't persist.
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for (pid, l) in &conn.links {
                if let Some(t) = &l.transport {
                    let mut transfers = serde_json::Map::new();
                    for ((p0, _), inc) in &by_sid {
                        if p0 == pid {
                            transfers.insert(inc.id.clone(), json!(inc.received));
                        }
                    }
                    let _ = t
                        .send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": Value::Object(transfers),
                            "trusted": l.trusted,
                            "away": false,
                        }))
                        .await;
                }
            }
        }

        // G-k completion sweep (top-of-loop): see sweep_completed_streams.
        sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;

        // Gate-18 Mode B: recompute the completion flag AFTER the sweep, every
        // tick (never sticky). When true, a stuck/lost link is DROPPED in
        // on_stuck instead of re-established — see Conn::recv_done. Refreshing it
        // here, where `completed`/`by_sid` were just settled, makes the gate-2/
        // gate-11c fence exact: a mid-transfer link (by_sid non-empty) sees
        // recv_done=false and reconnects unchanged.
        conn.recv_done = recv_transfer_done(completed, keep_open, by_sid.is_empty());

        // Gate-18 Mode B DETERMINISTIC repro hook: simulate the post-completion
        // FLAP that contention triggers in the wild (the sender's departure puts
        // the receiver's link into the C4 reconnect loop). Once everything is on
        // disk, force each surviving link to go stuck repeatedly — reset its
        // attempts (mirroring the real flap's attempts-reset, so MAX_ATTEMPTS
        // can never cap it) and re-inject Ev::Stuck. On the BASELINE (no fix)
        // on_stuck re-establishes → link persists → conn.links never empties →
        // hang to timeout (RC=124). WITH the fix on_stuck drops on recv_done →
        // links empties → no link to churn next tick → quiet-exit fires. Driven
        // at LOOP level (not inside on_stuck) so the A/B tests the fix, not
        // itself.
        if conn.recv_done && std::env::var("FILAMENT_TEST_CHURN_AFTER_COMPLETE").is_ok() {
            let churn: Vec<(String, u32)> = conn
                .links
                .iter()
                .map(|(pid, l)| (pid.clone(), l.generation))
                .collect();
            for (pid, generation) in churn {
                if let Some(l) = conn.links.get_mut(&pid) {
                    l.attempts = 0; // mirror the real flap: cap never accumulates
                    // Tear the data channel down so on_stuck's is_connected()
                    // guard sees a dead link and the Stuck isn't swallowed.
                    if let Some(p) = &l.peer {
                        p.close().await;
                    }
                }
                let _ = conn.tx.send(Ev::Stuck(pid, generation));
            }
        }

        // #28 exit reconciliation: once everything is received and the only links
        // left are ones held open purely for their deferred-drop reap (their
        // sender's signaling left AFTER the transfer finished), there is nothing
        // in flight to protect — exit promptly instead of paying the full
        // FILAMENT_ADOPT_ACTIVE_MS deferral. Restores the pre-#28 prompt exit; an
        // in-progress reconnect keeps `by_sid` non-empty and so is unaffected.
        if completed > 0 && !keep_open && by_sid.is_empty() && pending.is_empty()
            && !conn.links.is_empty() && conn.only_deferred_links()
        {
            eprintln!("done ({completed} file{}).", if completed == 1 { "" } else { "s" });
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // G-k fallback: everything done, nobody attached, no questions
        // outstanding — if that holds quietly for the quiet-exit window (10s
        // default, FILAMENT_QUIET_EXIT_SECS overrides), the peer-left we were
        // counting on for a clean exit never arrived; exit anyway. C30 ph2:
        // ALSO satisfied when the server's digest says the room is empty and
        // no room-independent (channel) link remains — lingering dead links
        // can't block the exit when the server knows nobody's there.
        let digest_says_alone = digest_alone && conn.links.values().all(|l| l.expected_secret.is_none());
        // #28 Mode B: a dead link that keeps FLAPPING — on_stuck reconnect, or a
        // roster/session reconcile re-adopting the gone sender and re-arming
        // `expected_secret` so `digest_says_alone` never holds — must NOT block
        // this fallback once everything is received; `conn.links` may never
        // empty under churn (the RC=124 hang). Surgical: discriminate on link
        // HEALTH, not existence — a churning/reconnecting/dead link (never
        // `Ready`) does not block exit, but a healthy `Ready` link (e.g. a
        // bystander between two human-paced sends, gate 6) STILL does. So this is
        // a no-op for healthy peers, not a behaviour change — only a peer we've
        // lost contact with stops blocking. FILAMENT_TEST_DISABLE_MODEB_DROP
        // restores the old links-gated behaviour so gate 18b proves the A/B
        // (baseline hangs, fix exits) with one binary.
        let no_healthy_link = conn.links.values().all(|l| !matches!(l.presence, Presence::Ready));
        let links_clear = if std::env::var("FILAMENT_TEST_DISABLE_MODEB_DROP").is_err() {
            no_healthy_link
        } else {
            conn.links.is_empty() || digest_says_alone
        };
        if completed > 0 && !keep_open && by_sid.is_empty() && pending.is_empty() && links_clear {
            match last_quiet {
                None => last_quiet = Some(Instant::now()),
                Some(since) if since.elapsed() > quiet_window => {
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
                sess.room = Some(room.clone()); // C30: desire moves; session repairs if the join dies
                sess.touch();
                sess.emit(&sio, "join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await;
            }
            // C30: server confirmed our session digest. Phase 2: reconcile
            // the roster it carries — missed peer-joined/left self-correct.
            Ev::Synced(v) => {
                if let Some(peers) = sess.on_synced(&v) {
                    digest_alone = peers.is_empty();
                    let present: std::collections::HashSet<String> = peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    // unknown in digest → a peer-joined we never received
                    for p in &peers {
                        let id = p["id"].as_str().unwrap_or_default();
                        if !id.is_empty() && !conn.links.contains_key(id) {
                            eprintln!("{}", ui::paint(ui::Tone::Dim, "  (digest: adopting a peer we never heard join)"));
                            conn.maybe_adopt(p, true).await?;
                        }
                    }
                    // known room-sourced link absent ×2 → a peer-left we
                    // never received (channel-introduced links are exempt:
                    // room-independent by design)
                    let mut gone: Vec<String> = Vec::new();
                    for (pid, l) in &conn.links {
                        if l.expected_secret.is_none() && !present.contains(pid) {
                            let c = digest_absent.entry(pid.clone()).or_insert(0);
                            *c += 1;
                            if *c >= 2 {
                                gone.push(pid.clone());
                            }
                        } else {
                            digest_absent.remove(pid);
                        }
                    }
                    for pid in gone {
                        digest_absent.remove(&pid);
                        let name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        conn.drop_link(&pid);
                        ui::say(&conn.roster(&pid, "○", ui::Tone::Dim, "left (digest reconcile) — still listening", &name));
                    }
                }
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
                // C30 (dissolves the C28 belt): a welcome means a fresh sid —
                // everything sid-keyed (subscriptions, lease) died with the
                // old one. Invalidate; the next tick re-asserts everything.
                sess.invalidate();
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own sender/daemon shares these channels
                }
                if let Some((n, sec)) = devices.iter().find(|(_, s)| channel_of(s) == v["channel"].as_str().unwrap_or("")) {
                    eprintln!("known device '{n}' appeared — connecting");
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    // rung-1: known device = both CLIs; try direct QUIC first.
                    let (n, sec) = (n.clone(), sec.clone());
                    conn.start_direct(&pid, &n, &sec).await;
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
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates — start the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    // rung-2: optional server-reflexive candidate for hole-punch.
                    let srflx = data["srflx"].as_str().map(String::from);
                    conn.on_transport_offer(&from, cands, srflx);
                    continue;
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            // rung-1: authenticated direct-QUIC won the race — adopt as a
            // pre-trusted Link, then funnel into the normal ChannelReady handler.
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            Ev::ChannelReady(pid, t) => {
                if let Some(l) = conn.link_mut(&pid) {
                    ui::say(&format!("  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ui::paint(ui::Tone::Bold, &l.name)));
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                    let is_direct = l.direct;
                    let direct_route = l.direct_route;
                    if let Some(p) = l.peer.clone() {
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
                    } else if is_direct {
                        ui::say(&format!("    {}", ui::paint(ui::Tone::Dim, &format!("route: {direct_route}"))));
                    }
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
                // L2 (ssh/TCP tunnel) acceptor. Opt-in (FILAMENT_L2=1). The
                // capability gate is the proof-verified `trusted` flag on this
                // link (placeholder for L1-a caps); localhost-only is enforced in
                // accept_control. A non-trusted or non-loopback open is refused.
                Some("l2-open") | Some("l2-close") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let mux = l2_muxes
                        .entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    match mux.accept_control(&v, trusted).await {
                        l2::OpenVerdict::Accept { sid, host, port, rx } => {
                            tokio::spawn(mux.clone().dial_and_serve(sid, host, port, rx));
                        }
                        l2::OpenVerdict::Deny { sid, err } => {
                            // Log refused dials (threat model: port-scan / SSRF
                            // visibility). The gate observes this line.
                            eprintln!("l2: refused stream {sid:#x}: {err}");
                            let _ = t
                                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": err }))
                                .await;
                        }
                        l2::OpenVerdict::Ignore => {}
                    }
                    // A PTY stream closing frees its resize channel.
                    if v["type"].as_str() == Some("l2-close") {
                        if let Some(sid) = v["sid"].as_u64() {
                            pty_resizers.remove(&(sid as u32));
                        }
                    }
                }
                // Seamless-shell bootstrap (acceptor). Opt-in (FILAMENT_L2=1).
                // DENY-BY-DEFAULT: install the initiator's managed pubkey ONLY
                // when the link is proof-verified (`trusted`) AND the proven
                // device holds the NEW `shell` capability — distinct from
                // `transfer`, so pairing for file transfer never yields a shell.
                // The write happens only here (over the authenticated channel)
                // into a clearly-marked, removable authorized_keys block.
                Some("shell-bootstrap") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Cap lookup keys on the PROVEN petname, not the presence name.
                    let dev = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    // Granted if the device was explicitly `grant`ed shell OR an
                    // active `up --shell[-only]` policy auto-allows it. Trust
                    // (pair-proof) is still required either way.
                    let granted = trusted
                        && dev
                            .as_deref()
                            .map(|n| shell_policy.auto_allows(n) || device_allows(n, "shell"))
                            .unwrap_or(false);
                    if !granted {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        eprintln!("l2: shell bootstrap refused: {who} (no shell cap / untrusted)");
                        let _ = t
                            .send_control(&json!({
                                "type": "shell-bootstrap-deny",
                                "reason": "shell capability not granted"
                            }))
                            .await;
                        continue;
                    }
                    let device = dev.unwrap();
                    let pubkey = v["pubkey"].as_str().unwrap_or_default().to_string();
                    // Basic shape check: an ed25519/rsa/ecdsa pubkey line. Never
                    // install junk.
                    let looks_ok = pubkey.starts_with("ssh-") || pubkey.starts_with("ecdsa-");
                    if pubkey.is_empty() || !looks_ok {
                        let _ = t
                            .send_control(&json!({
                                "type": "shell-bootstrap-deny",
                                "reason": "malformed pubkey"
                            }))
                            .await;
                        continue;
                    }
                    match sshkeys::install_authorized_key(&device, &pubkey) {
                        Ok(()) => {
                            let hostkeys = sshkeys::host_pubkeys();
                            let login = std::env::var("USER").unwrap_or_else(|_| "root".into());
                            eprintln!(
                                "l2: shell granted to '{device}' — installed managed key (filament-managed block)"
                            );
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-ack",
                                    "hostkeys": hostkeys,
                                    "user": login
                                }))
                                .await;
                        }
                        Err(e) => {
                            eprintln!("l2: shell bootstrap install failed for '{device}': {e}");
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "install failed"
                                }))
                                .await;
                        }
                    }
                }
                // web-shell (browser terminal): spawn a login shell in a PTY and
                // bridge it to a sid stream. Same deny-by-default gate as
                // shell-bootstrap — a PTY is a superset of ssh-key access, so it
                // reuses the `shell` cap / --shell policy and requires `trusted`.
                Some("pty-open") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else { continue };
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    if !l2::is_l2_sid(sid) {
                        continue;
                    }
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let dev = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    let granted = trusted
                        && dev
                            .as_deref()
                            .map(|n| shell_policy.auto_allows(n) || device_allows(n, "shell"))
                            .unwrap_or(false);
                    if !granted {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        eprintln!("l2: pty refused: {who} (no shell cap / untrusted)");
                        let _ = t
                            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "shell capability not granted" }))
                            .await;
                        continue;
                    }
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    let mux = l2_muxes
                        .entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    let rx = mux.register_stream(sid).await; // before spawn (race fix)
                    let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<(u16, u16)>();
                    pty_resizers.insert(sid, rtx);
                    eprintln!("l2: pty granted to '{}' — {cols}x{rows}", dev.unwrap_or_default());
                    let _ = t.send_control(&json!({ "type": "pty-open-ack", "sid": sid })).await;
                    tokio::spawn(l2::serve_pty(mux.clone(), sid, cols, rows, shell_argv(), rx, rrx));
                }
                Some("pty-resize") if l2_enabled => {
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    if let Some(tx) = pty_resizers.get(&sid) {
                        let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                        let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                        let _ = tx.send((cols, rows));
                    }
                }
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
                // C30 phase 3: a state ping proves the peer is alive — clear
                // any away-mark (the receiver side has no sender corrections).
                Some("state") => {
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
                            sess.channels.push(channel_of(&sec)); // C30: desire grows; session repairs
                            sess.touch();
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
                            sess.channels.push(channel_of(&ceremony_secret)); // C30
                            sess.touch();
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
                        Some(l) => match &l.peer { Some(p) => p.fingerprints().await, None => None },
                        None => None,
                    };
                    let Some((my_fp, their_fp)) = fps else {
                        eprintln!("pair-proof received before fingerprints known — ignoring");
                        continue;
                    };
                    // #9: pair secrets are symmetric — our own install holds
                    // every secret we do, so a same-host process could prove
                    // "pop2" and tunnel callers into the WRONG machine. Refuse.
                    let hit = if is_self_uid(&conn.my_uid, Some(peer_uid.as_str())) {
                        eprintln!("pair-proof from our own install — refusing (self-connect)");
                        None
                    } else {
                        devices
                            .iter()
                            .find(|(_, s)| proof_for(s, &peer_uid, &peer_uid, &conn.my_uid, &my_fp, &their_fp) == mac)
                    };
                    let ok = if let Some((n, _)) = hit {
                        if let Some(l) = conn.link_mut(&pid) {
                            l.trusted = true;
                            // Record the proven devices.json petname — the cap
                            // store key (the `shell` bootstrap gate looks up caps
                            // under exactly this, not the presence display name).
                            l.verified_name = Some(n.clone());
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
                        sess.channels.push(channel_of(&isec)); // C30
                        sess.touch();
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
                    // Test hook (gate 18 standalone repro): drop the file-end
                    // control frame so a fully-received stream is stranded in
                    // by_sid — mirrors a sender whose PC tears down before the
                    // best-effort file-end is delivered. The G-k completion
                    // sweep must then finalize it on size and quiet-exit.
                    if std::env::var("FILAMENT_TEST_DROP_FILE_END").is_ok() {
                        continue;
                    }
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    if let Some(mut inc) = by_sid.remove(&(pid.clone(), sid)) {
                        inc.file.flush().await?;
                        if to_stdout {
                            completed += 1;
                            continue;
                        }
                        let rename_to = if completed == 0 { output.clone() } else { None };
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await? {
                            completed += 1;
                        }
                    }
                }
                _ => {}
            },
            Ev::Chunk(pid, sid, data) => {
                // L2 streams live in the HIGH half of the sid space — route them
                // to the tunnel mux, never the file-transfer table (the pure
                // high-bit prefix check keeps file send/recv byte-identical).
                if l2_enabled && l2::is_l2_sid(sid) {
                    if let Some(mux) = l2_muxes.get(&pid) {
                        mux.on_frame(sid, data).await;
                    }
                } else if let Some(inc) = by_sid.get_mut(&(pid, sid)) {
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
            // Losing the sender is only an ERROR when nothing completed —
            // after a successful transfer it's just closure (the quiet-exit
            // prints the same `done (N files).` the peer-left path would).
            Ev::Stuck(pid, generation) => {
                if conn.on_stuck(&pid, generation, "stuck while connecting").await? && paired && !keep_open {
                    // G-k: the dropped link may have delivered every byte but
                    // lost its file-end — finalize before deciding it's fatal.
                    sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;
                    if completed == 0 {
                        bail!("lost the sender after {} attempts", MAX_ATTEMPTS);
                    }
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? && paired && !keep_open {
                    sweep_completed_streams(&mut by_sid, &conn, &dir, &output, to_stdout, daemon, &mut completed).await?;
                    if completed == 0 {
                        bail!("lost the sender after {} attempts", MAX_ATTEMPTS);
                    }
                }
            }
            Ev::PcState(pid, s) => {
                // L2: a dead/closed link must abort every tunnel stream it
                // carried so no pump hangs on a peer that's gone (design §3.5).
                if l2_enabled && (s == "failed" || s == "closed" || s == "disconnected") {
                    if let Some(mux) = l2_muxes.remove(&pid) {
                        mux.shutdown_all().await;
                    }
                }
                conn.on_pc_state(&pid, &s).await;
            }
            Ev::PeerLeft(v) => {
                // Test hook (gate 18): peer-left delivery is best-effort in the
                // real world; this simulates the loss deterministically so the
                // quiet-exit fallback (G-k) can be exercised. SIGSTOP can't do
                // it — engine.io's ping timeout reaps a frozen client in ~30s
                // and the legit peer-left wins the race.
                if std::env::var("FILAMENT_TEST_DROP_PEER_LEFT").is_ok() {
                    continue;
                }
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

/// Finalize a fully-received incoming file: flush, rename `.part` → final,
/// clean up the meta sidecar, and (in daemon mode) append to the upload log.
/// Returns true if the file was placed (so the caller bumps `completed`).
/// Shared by the file-end control-frame path and the G-k completion sweep —
/// the two must not drift. `daemon`/`from_name` drive only the daemon log.
async fn finalize_incoming(
    mut inc: IncomingFile,
    dir: &Path,
    rename_to: Option<&str>,
    daemon: bool,
    from_name: &str,
) -> Result<bool> {
    inc.file.flush().await?;
    drop(inc.file);
    let final_path = unique_path(dir, rename_to.unwrap_or(&inc.name));
    if let Err(e) = tokio::fs::rename(&inc.part_path, &final_path).await {
        // C23: a duplicate stream's partial may already be finalized — discard
        // quietly instead of dying.
        ui::say(&ui::paint(ui::Tone::Dim, &format!("  (stream for {} already finalized — duplicate discarded: {e})", inc.name)));
        return Ok(false);
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
    if daemon {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(up_log()) {
            let _ = writeln!(f, "{}  {}  {}  from {}", chrono_now(), inc.name, human(inc.received), from_name);
        }
    }
    Ok(true)
}

/// G-k completion sweep: file-end delivery is best-effort. A stream can
/// receive every expected byte yet have its file-end LOST when the sender's
/// PeerConnection tears down first (observed under load). The bytes are whole
/// (held in `inc.received`; `finalize_incoming` flushes the BufWriter before
/// rename so the on-disk file is complete), but the stream is stranded in
/// `by_sid` with no live link to ever deliver file-end — and that non-empty
/// `by_sid` plus `completed == 0` blocks the quiet-exit while the dead link
/// spins through the reconnect-retry loop to the 120s ceiling. Finalize any
/// fully received stream whose link is gone. `received == size` is exactly the
/// bar the file-end handler itself checks, so this can never claim a genuine
/// partial (received < size stays parked for resume — gate 2) and never
/// touches the offer-stage corruption guard (gate 3). Called both at top-of-
/// loop and right after a link is dropped in the Stuck/GraceExpired handlers,
/// so the bail on `completed == 0` sees the finalized file.
async fn sweep_completed_streams(
    by_sid: &mut HashMap<(String, u32), IncomingFile>,
    conn: &Conn,
    dir: &Path,
    output: &Option<String>,
    to_stdout: bool,
    daemon: bool,
    completed: &mut usize,
) -> Result<()> {
    let done_sids: Vec<(String, u32)> = by_sid
        .iter()
        .filter(|((pid, _), inc)| inc.received == inc.size && !conn.links.contains_key(pid))
        .map(|(k, _)| k.clone())
        .collect();
    for key in done_sids {
        if let Some(mut inc) = by_sid.remove(&key) {
            if to_stdout {
                // Parity with the file-end handler: flush before counting it,
                // since dropping a tokio BufWriter does not async-flush.
                let _ = inc.file.flush().await;
                *completed += 1;
                continue;
            }
            let rename_to = if *completed == 0 { output.clone() } else { None };
            ui::say(&ui::paint(ui::Tone::Dim, &format!("  ({} fully received — sender left before file-end; finalizing)", inc.name)));
            if finalize_incoming(inc, dir, rename_to.as_deref(), daemon, "").await? {
                *completed += 1;
            }
        }
    }
    Ok(())
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
    fn capability_deny_by_default() {
        // GATE 5: deny-by-default. A device with empty caps is refused any gated
        // action; "transfer" is the always-allowed L0 baseline; a v1 record
        // (no caps) reads as ["transfer"]; future caps must be explicitly
        // granted (i.e. agreed under K at re-enrollment), not escalatable.
        let dir = std::env::temp_dir().join(format!("fil-caps-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("devices.json");
        let sec = "a".repeat(64);
        std::fs::write(
            &p,
            serde_json::to_string(&json!([
                {"name": "empty",   "secret": sec, "v": 2, "caps": []},
                {"name": "xfer",    "secret": sec, "v": 2, "caps": ["transfer"]},
                {"name": "execcap", "secret": sec, "v": 2, "caps": ["transfer", "remote-exec"]},
                {"name": "legacy",  "secret": sec}  // v1 record: reads as ["transfer"]
            ]))
            .unwrap(),
        )
        .unwrap();

        // transfer is the L0 baseline — allowed even for empty caps.
        assert!(device_allows_at(&p, "empty", "transfer"), "transfer is the L0 baseline");
        assert!(device_allows_at(&p, "xfer", "transfer"));
        // A v1 record reads as caps:["transfer"] (back-compat, spec §8).
        assert_eq!(device_caps_at(&p, "legacy"), Some(vec!["transfer".to_string()]));
        assert!(device_allows_at(&p, "legacy", "transfer"));
        // Deny-by-default: a gated future cap is REFUSED unless explicitly granted.
        assert!(!device_allows_at(&p, "empty", "remote-exec"), "empty caps must deny remote-exec");
        assert!(!device_allows_at(&p, "xfer", "remote-exec"), "transfer-only must deny remote-exec");
        assert!(!device_allows_at(&p, "legacy", "remote-exec"), "v1 record must deny remote-exec");
        // Only a device explicitly granted the cap (under K, at enrollment) is allowed.
        assert!(device_allows_at(&p, "execcap", "remote-exec"), "explicitly granted cap is allowed");
        // An unknown device grants no GATED cap (but transfer is the universal
        // L0 baseline, so it is allowed regardless — never regresses send/recv).
        assert!(!device_allows_at(&p, "ghost", "remote-exec"));
        assert!(device_allows_at(&p, "ghost", "transfer"), "transfer baseline is universal");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shell_policy_gates_auto_shell() {
        // `up` default: NOTHING auto-shells — a device needs an explicit grant.
        let g = ShellPolicy::Granted;
        assert!(!g.auto_allows("popos"));
        assert!(!g.enables_l2(), "default must not silently enable the L2 acceptor");
        // `up --shell`: every paired device auto-shells, and L2 is on.
        let a = ShellPolicy::All;
        assert!(a.auto_allows("popos") && a.auto_allows("anything"));
        assert!(a.enables_l2());
        // `up --shell-only popos,laptop`: only the listed petnames; others don't.
        let o = ShellPolicy::Only(["popos".to_string(), "laptop".to_string()].into_iter().collect());
        assert!(o.auto_allows("popos") && o.auto_allows("laptop"));
        assert!(!o.auto_allows("stranger"), "shell-only must not auto-shell unlisted devices");
        assert!(o.enables_l2());
    }

    #[test]
    fn forget_and_store_preserve_other_devices_caps() {
        // Regression: forgetting/pairing a device must NOT wipe the `shell`
        // (or any v2) caps of the OTHER devices. The old (name, secret) tuple
        // round-trip rewrote every survivor as bare {name, secret}, silently
        // dropping their grants — a remembered device lost its shell on the
        // next `forget`/`pair`.
        let dir = std::env::temp_dir().join(format!("fil-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Serialize: these tests mutate the process-global FILAMENT_CONFIG_DIR.
        unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", &dir) };
        let p = dir.join("devices.json");
        let sec = "b".repeat(64);
        std::fs::write(
            &p,
            serde_json::to_string(&json!([
                {"name": "shellbox", "secret": sec, "v": 2, "caps": ["transfer", "shell"]},
                {"name": "dupe",     "secret": sec, "v": 2, "caps": ["transfer"]},
            ]))
            .unwrap(),
        )
        .unwrap();

        // Forgetting 'dupe' must leave 'shellbox' with its shell cap intact.
        devices_remove("dupe").unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "forget wiped a survivor's shell cap");
        assert!(device_caps_at(&p, "dupe").is_none(), "dupe should be gone");

        // Storing a NEW pairing must also preserve 'shellbox'’s caps.
        devices_store("newpeer", &sec).unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "store wiped a survivor's shell cap");
        // And re-storing an existing name keeps its caps (only the secret rotates).
        devices_store("shellbox", &"c".repeat(64)).unwrap();
        assert!(device_allows_at(&p, "shellbox", "shell"), "re-store dropped the device's own caps");

        unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn recv_done_drops_only_when_complete() {
        // Gate-18 Mode B: the drop-instead-of-reconnect decision must hold
        // ONLY when the transfer is complete and idle. This is the exact fence
        // that protects gate 2 (kill-resume) and gate 11c (deferred-drop): a
        // mid-transfer link (by_sid non-empty) must always reconnect.
        // complete + idle + not keep_open -> drop the dead link, let quiet-exit
        assert!(recv_transfer_done(1, false, true));
        assert!(recv_transfer_done(3, false, true));
    }

    #[test]
    fn recv_done_false_mid_transfer_protects_resume() {
        // by_sid NON-empty == a stream in flight (an in-progress reconnect or
        // resume). Must NOT drop — gate 2 / gate 11c reconnect paths depend on
        // this returning false so on_stuck re-establishes.
        assert!(!recv_transfer_done(0, false, false)); // nothing done, mid-stream
        assert!(!recv_transfer_done(1, false, false)); // file done but another in flight
        // keep_open (gate 13): a resident receiver never self-drops its links.
        assert!(!recv_transfer_done(1, true, true));
        assert!(!recv_transfer_done(5, true, true));
        // nothing completed yet (still connecting / first stream) -> reconnect.
        assert!(!recv_transfer_done(0, false, true));
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
