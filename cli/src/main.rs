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
/// C4/C6: how long we wait for a vanished peer to rejoin before giving up.
const REJOIN_WINDOW: Duration = Duration::from_secs(120);
/// C3/C4: connection (re)establishment attempts before failing honestly.
const MAX_ATTEMPTS: u32 = 3;

const VERSION: &str = env!("FILAMENT_BUILD_INFO"); // stamped by build.rs

#[derive(Parser)]
#[command(name = "filament", version = VERSION, about = "P2P file transfer between terminals and browsers — no upload, no account")]
struct Cli {
    /// Signaling server (self-hosters: point at your own instance)
    #[arg(long, global = true, env = "FILAMENT_SERVER", default_value = DEFAULT_SERVER)]
    server: String,
    /// Force TURN relay (testing/privacy; hides your IP from the peer)
    #[arg(long, global = true)]
    relay: bool,
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
    },
    /// Update filament to the latest release
    Update {
        /// Check only; don't install
        #[arg(long)]
        check: bool,
    },
    /// Generate shell completions (bash, zsh, fish, elvish, powershell)
    Completions {
        shell: clap_complete::Shell,
    },
    /// Print the man page (roff) to stdout
    #[command(hide = true)]
    Man,
}

// --------------------------------------------------------------- utilities --

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
    format!("cli-{prefix}-{:x}{:x}", std::process::id(), nanos)
}

fn display_name() -> String {
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

fn human(bytes: u64) -> String {
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
}

struct Conn {
    server: String,
    sio: rust_socketio::asynchronous::Client,
    tx: mpsc::UnboundedSender<Ev>,
    my_uid: String,
    my_id: String,
    relay_only: bool,
    to_filter: Option<String>,
    link: Option<Link>,
    attempts: u32,
    next_gen: u32,
    waiting_rejoin: Option<Instant>,
    chunk_size: usize,
}

impl Conn {
    /// Consider a roster entry / peer-joined for adoption. Returns true if a
    /// (re)connection was started.
    async fn maybe_adopt(&mut self, v: &Value) -> Result<bool> {
        let peer_id = v["id"].as_str().unwrap_or_default().to_string();
        let peer_uid = v["uid"].as_str().map(|s| s.to_string());
        let name = v["name"].as_str().unwrap_or("peer").to_string();
        if peer_id.is_empty() || peer_id == self.my_id {
            return Ok(false);
        }
        if let Some(filter) = &self.to_filter {
            if !name.to_lowercase().contains(&filter.to_lowercase()) {
                return Ok(false);
            }
        }
        // Same-role CLI peers never transfer to each other (a receiver binding
        // to another idle receiver wedges both — gate 7). The uid encodes the
        // role: cli-s-* sends, cli-r-* receives. Browsers (random uids) pass.
        if let (Some(peer_uid), Some(my_role)) = (&peer_uid, self.my_uid.get(..6)) {
            if peer_uid.starts_with(my_role) {
                return Ok(false);
            }
        }
        match &self.link {
            Some(l) => {
                // C6: same device, new connection — supersede the stale link.
                if l.uid.is_some() && l.uid == peer_uid && l.peer.id != peer_id {
                    eprintln!("{name} reconnected — superseding old link");
                    self.attempts = 0;
                    self.establish(v.clone()).await?;
                    return Ok(true);
                }
                Ok(false)
            }
            None => {
                self.establish(v.clone()).await?;
                Ok(true)
            }
        }
    }

    async fn establish(&mut self, info: Value) -> Result<()> {
        if let Some(old) = self.link.take() {
            // Fire-and-forget: pc.close() can block on network teardown
            // against a frozen/unreachable peer, and this runs in the event
            // loop — awaiting it inline deadlocks the whole process (found by
            // gate 11). The atomic closed-flag silences the old peer's
            // callbacks synchronously; the actual teardown can take its time
            // off-loop.
            let p = old.peer.clone();
            p.mark_closed();
            tokio::spawn(async move { p.close().await });
        }
        self.waiting_rejoin = None;
        let peer_id = info["id"].as_str().unwrap_or_default().to_string();
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
            peer_id,
            polite,
            cfg.ice_servers,
            self.relay_only,
            self.sio.clone(),
            self.tx.clone(),
            generation,
        )
        .await?;
        self.link = Some(Link { peer, info, name, uid: peer_uid, transport: None, generation });
        Ok(())
    }

    /// C3/C4: watchdog or grace expiry — retry with a fresh connection (and
    /// fresh credentials), up to MAX_ATTEMPTS, then fail honestly.
    async fn on_stuck(&mut self, pid: &str, generation: u32, why: &str) -> Result<()> {
        let Some(l) = &self.link else { return Ok(()) };
        if l.peer.id != pid || l.generation != generation || l.peer.is_connected() {
            return Ok(()); // stale timer from a superseded attempt
        }
        self.attempts += 1;
        if self.attempts >= MAX_ATTEMPTS {
            bail!("connection {why} after {} attempts", self.attempts);
        }
        eprintln!("connection {why} — retrying ({}/{})", self.attempts + 1, MAX_ATTEMPTS);
        let info = l.info.clone();
        self.establish(info).await
    }

    /// C4: transient `disconnected` — nudge ICE from the impolite side and
    /// give it 6 s of grace before treating it as failure.
    async fn on_pc_state(&mut self, s: &str) {
        let Some(l) = &self.link else { return };
        match s {
            "connected" => {
                self.attempts = 0;
            }
            "disconnected" => {
                eprintln!("connection blip — attempting recovery");
                if !l.peer.polite {
                    l.peer.restart_ice().await;
                }
                let tx = self.tx.clone();
                let pid = l.peer.id.clone();
                let generation = l.generation;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(6)).await;
                    let _ = tx.send(Ev::GraceExpired(pid, generation));
                });
            }
            _ => {}
        }
    }

    /// Our peer's socket died. Keep state and wait for a rejoin (their client
    /// auto-rejoins on reconnect); supersede (C6) completes the recovery.
    fn on_peer_left(&mut self, v: &Value) -> bool {
        let Some(l) = &self.link else { return false };
        if v["id"].as_str() != Some(l.peer.id.as_str()) {
            return false;
        }
        self.link = None;
        self.waiting_rejoin = Some(Instant::now());
        true
    }

    fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.link.as_ref().and_then(|l| l.transport.clone())
    }
}

/// Receive the next event; while a rejoin window is open, tick every 2 s so
/// the window can expire even if no events arrive.
async fn next_ev(rx: &mut mpsc::UnboundedReceiver<Ev>, conn: &Conn) -> Result<Option<Ev>> {
    if let Some(since) = conn.waiting_rejoin {
        if since.elapsed() > REJOIN_WINDOW {
            bail!("peer did not come back within {}s (partial state kept for resume)", REJOIN_WINDOW.as_secs());
        }
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
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
    let cli = Cli::parse();
    let server = cli.server.trim_end_matches('/').to_string();
    match cli.cmd {
        Cmd::Send { paths, code, word, room, to, name } => {
            send_cmd(&server, paths, code || word.is_some(), word, room, to, name, cli.relay).await
        }
        Cmd::Recv { code, dir, yes, room, to, keep_open } => {
            recv_cmd(&server, code, dir, yes, room, to, keep_open, cli.relay).await
        }
        Cmd::Update { check } => update_cmd(check).await,
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

async fn update_cmd(check_only: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("filament/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    // Latest cli-v* release via the API (releases/latest may point at a web
    // release tag, so filter explicitly).
    let releases: Value = client
        .get(format!("https://api.github.com/repos/{REPO}/releases?per_page=20"))
        .send()
        .await?
        .json()
        .await?;
    let latest = releases
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|r| r["tag_name"].as_str().is_some_and(|t| t.starts_with("cli-v")))
        })
        .ok_or_else(|| anyhow!("no CLI release found"))?;
    let tag = latest["tag_name"].as_str().unwrap_or_default().to_string();
    let latest_ver = tag.trim_start_matches("cli-v").to_string();
    let current = env!("CARGO_PKG_VERSION");
    if latest_ver == current {
        println!("filament {current} is already the latest");
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

    if use_code {
        let payload = match &word {
            Some(w) => json!({ "keyword": w }),
            None => json!({}),
        };
        sio.emit("pair-create", payload).await.ok();
    } else {
        eprintln!("waiting for a peer in room {room} (same network auto-discovers; or use --code)");
    }

    let mut conn = Conn {
        server: server.to_string(),
        sio: sio.clone(),
        tx: tx.clone(),
        my_uid,
        my_id: String::new(),
        relay_only: relay,
        to_filter: to,
        link: None,
        attempts: 0,
        next_gen: 0,
        waiting_rejoin: None,
        chunk_size: net::MAX_DC_PAYLOAD,
    };
    let mut code_used = !use_code; // without --code any (filtered) peer is fair game
    let outgoing = Arc::new(tokio::sync::Mutex::new(outgoing));
    let started = Instant::now();
    let claim_deadline = Duration::from_secs(600);

    loop {
        // The wait-for-peer deadline only applies while we have no peer (F3).
        let ev = if conn.link.is_none() && conn.waiting_rejoin.is_none() {
            match tokio::time::timeout(claim_deadline.saturating_sub(started.elapsed()), rx.recv()).await {
                Ok(Some(ev)) => Some(ev),
                Ok(None) => bail!("signaling channel closed"),
                Err(_) => bail!("timed out waiting for a peer"),
            }
        } else {
            next_ev(&mut rx, &conn).await?
        };
        let Some(ev) = ev else { continue };

        match ev {
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                if code_used {
                    if let Some(peers) = v["peers"].as_array() {
                        for p in peers {
                            if conn.maybe_adopt(p).await? {
                                break;
                            }
                        }
                    }
                }
            }
            Ev::PairCode(v) => {
                let code = v["code"].as_str().unwrap_or("?");
                let ttl = v["ttl"].as_u64().unwrap_or(600);
                eprintln!("\n  code: {code}\n");
                eprintln!("on the other machine:  filament recv {code}");
                eprintln!("or in a browser:       https://filament.autumated.com (PAIR WITH CODE)");
                eprintln!("one claim only; expires in {} min", ttl / 60);
            }
            Ev::PairError(v) => bail!("pairing failed: {}", v["error"].as_str().unwrap_or("?")),
            Ev::PairUsed(_) => {
                eprintln!("code claimed — connecting...");
                code_used = true;
            }
            Ev::PeerJoined(v) => {
                if code_used {
                    conn.maybe_adopt(&v).await?;
                }
            }
            Ev::Signal(v) => {
                if let Some(l) = &conn.link {
                    if v["from"].as_str() == Some(l.peer.id.as_str()) {
                        // Never fatal: a signal that fails to apply (e.g. a
                        // renegotiation offer landing while our agent is mid-
                        // gather -> "can not be restarted when gathering")
                        // leaves a connection the watchdog/grace machinery
                        // already knows how to recover or replace. Mirrors
                        // the browser's catch-and-log signal queue (#2).
                        if let Err(e) = l.peer.handle_signal(v["data"].clone()).await {
                            eprintln!("signal failed to apply: {e} (recovering)");
                        }
                    }
                }
            }
            Ev::ChannelReady(t) => {
                if let Some(l) = &mut conn.link {
                    eprintln!("connected to {}", l.name);
                    l.transport = Some(t.clone());
                    let p = l.peer.clone();
                    tokio::spawn(async move {
                        // ICE may renominate; retry briefly (mirrors the
                        // browser's _detectRoute attempts) so fast transfers
                        // still get a route line before the process exits.
                        for _ in 0..6 {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                            if let Some(r) = p.route().await {
                                eprintln!("route: {r}");
                                break;
                            }
                        }
                    });
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
            Ev::Control(v) => match v["type"].as_str() {
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
            Ev::Stuck(pid, generation) => conn.on_stuck(&pid, generation, "stuck while connecting").await?,
            Ev::GraceExpired(pid, generation) => conn.on_stuck(&pid, generation, "lost").await?,
            Ev::PcState(s) => conn.on_pc_state(&s).await,
            Ev::PeerLeft(v) => {
                if conn.on_peer_left(&v) {
                    let all_done = outgoing.lock().await.iter().all(|o| o.done);
                    if !all_done {
                        eprintln!("peer disconnected — waiting up to {}s for them to come back", REJOIN_WINDOW.as_secs());
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
    let start = Instant::now();
    let mut last = Instant::now();
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        t.send_frame(sid, &buf[..n]).await?;
        sent += n as u64;
        if last.elapsed() > Duration::from_secs(2) {
            last = Instant::now();
            let rate = (sent - offset) as f64 / start.elapsed().as_secs_f64();
            eprintln!("{name}: {:.0}% ({}/s)", sent as f64 / size.max(1) as f64 * 100.0, human(rate as u64));
        }
    }
    t.send_control(&json!({ "type": "file-end", "id": id, "sid": sid })).await?;
    t.flush().await?;
    let rate = (sent - offset) as f64 / start.elapsed().as_secs_f64().max(0.001);
    eprintln!("{name}: complete ({}, {}/s)", human(size), human(rate as u64));
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
    started: Instant,
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
) -> Result<()> {
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let my_uid = mk_uid("r");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;

    let paired = code.is_some();
    match &code {
        Some(c) => {
            sio.emit("pair-claim", json!({ "code": c.trim().to_lowercase() })).await.ok();
        }
        None => {
            let room = match &room {
                Some(r) => r.clone(),
                None => net::fetch_auto_room(server).await?,
            };
            eprintln!("listening in room {room} (dir: {})", dir.display());
            sio.emit("join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await.ok();
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
        link: None,
        attempts: 0,
        next_gen: 0,
        waiting_rejoin: None,
        chunk_size: net::MAX_DC_PAYLOAD,
    };
    let mut by_sid: HashMap<u32, IncomingFile> = HashMap::new();
    let mut completed = 0usize;
    let mut last_progress = Instant::now();

    loop {
        let Some(ev) = next_ev(&mut rx, &conn).await? else { continue };

        match ev {
            Ev::PairMatched(v) => {
                let room = v["room"].as_str().unwrap_or_default().to_string();
                eprintln!("code accepted — joining sender");
                sio.emit("join", json!({ "room": room, "name": display_name(), "uid": my_uid })).await.ok();
            }
            Ev::PairError(v) => bail!(
                "code rejected: {} (one-time codes burn after a single use)",
                v["error"].as_str().unwrap_or("?")
            ),
            Ev::Welcome(v) => {
                conn.my_id = v["id"].as_str().unwrap_or_default().to_string();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        if conn.maybe_adopt(p).await? {
                            break;
                        }
                    }
                }
            }
            Ev::PeerJoined(v) => {
                let had_partials = !by_sid.is_empty();
                if conn.maybe_adopt(&v).await? && had_partials {
                    // Stale per-link sid routing dies with the old link; the
                    // .part files live on and the sender's resume re-offers.
                    flush_inflight(&mut by_sid).await;
                }
            }
            Ev::Signal(v) => {
                if let Some(l) = &conn.link {
                    if v["from"].as_str() == Some(l.peer.id.as_str()) {
                        // Never fatal: a signal that fails to apply (e.g. a
                        // renegotiation offer landing while our agent is mid-
                        // gather -> "can not be restarted when gathering")
                        // leaves a connection the watchdog/grace machinery
                        // already knows how to recover or replace. Mirrors
                        // the browser's catch-and-log signal queue (#2).
                        if let Err(e) = l.peer.handle_signal(v["data"].clone()).await {
                            eprintln!("signal failed to apply: {e} (recovering)");
                        }
                    }
                }
            }
            Ev::ChannelReady(t) => {
                if let Some(l) = &mut conn.link {
                    eprintln!("peer: {}", l.name);
                    l.transport = Some(t);
                    let p = l.peer.clone();
                    tokio::spawn(async move {
                        // ICE may renominate; retry briefly (mirrors the
                        // browser's _detectRoute attempts) so fast transfers
                        // still get a route line before the process exits.
                        for _ in 0..6 {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                            if let Some(r) = p.route().await {
                                eprintln!("route: {r}");
                                break;
                            }
                        }
                    });
                }
            }
            Ev::Control(v) => match v["type"].as_str() {
                Some("file-offer") => {
                    let Some(t) = conn.transport() else { continue };
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

                    // C14: consent. -y accepts everything; a resume of a
                    // partial we already said yes to auto-accepts; everything
                    // else gets an explicit prompt naming the sender.
                    let sender_name = conn.link.as_ref().map(|l| l.name.clone()).unwrap_or_default();
                    let ok = yes
                        || (is_resume && offset > 0)
                        || prompt_accept(&sender_name, &name, size, paired).await;
                    if !ok {
                        t.send_control(&json!({ "type": "file-decline", "id": id })).await?;
                        continue;
                    }

                    let file = if offset > 0 {
                        eprintln!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0);
                        tokio::fs::OpenOptions::new().append(true).open(&part_path).await?
                    } else {
                        PartMeta { size, head: offer_head }.store(&meta_path)?;
                        tokio::fs::File::create(&part_path).await?
                    };
                    eprintln!("receiving {name} ({})", human(size));
                    by_sid.insert(sid, IncomingFile {
                        id: id.clone(),
                        name,
                        size,
                        received: offset,
                        file: tokio::io::BufWriter::with_capacity(1 << 20, file),
                        part_path,
                        started: Instant::now(),
                    });
                    t.send_control(&json!({ "type": "file-accept", "id": id, "offset": offset })).await?;
                }
                Some("file-end") => {
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    if let Some(mut inc) = by_sid.remove(&sid) {
                        inc.file.flush().await?;
                        drop(inc.file);
                        let final_path = unique_path(&dir, &inc.name);
                        tokio::fs::rename(&inc.part_path, &final_path).await?;
                        let _ = tokio::fs::remove_file(dir.join(format!("{}.part.meta", inc.name))).await;
                        let rate = inc.received as f64 / inc.started.elapsed().as_secs_f64().max(0.001);
                        let ok = inc.received == inc.size;
                        eprintln!(
                            "received {} ({}{}) -> {} ({}/s)",
                            inc.name,
                            human(inc.received),
                            if ok { "" } else { ", SIZE MISMATCH" },
                            final_path.display(),
                            human(rate as u64),
                        );
                        completed += 1;
                    }
                }
                _ => {}
            },
            Ev::Chunk(sid, data) => {
                if let Some(inc) = by_sid.get_mut(&sid) {
                    inc.file.write_all(&data).await?;
                    inc.received += data.len() as u64;
                    if last_progress.elapsed() > Duration::from_secs(2) {
                        last_progress = Instant::now();
                        let rate = inc.received as f64 / inc.started.elapsed().as_secs_f64().max(0.001);
                        eprintln!(
                            "{}: {:.0}% ({}/s)",
                            inc.name,
                            inc.received as f64 / inc.size.max(1) as f64 * 100.0,
                            human(rate as u64)
                        );
                    }
                }
            }
            Ev::Stuck(pid, generation) => conn.on_stuck(&pid, generation, "stuck while connecting").await?,
            Ev::GraceExpired(pid, generation) => conn.on_stuck(&pid, generation, "lost").await?,
            Ev::PcState(s) => conn.on_pc_state(&s).await,
            Ev::PeerLeft(v) => {
                if conn.on_peer_left(&v) {
                    if !by_sid.is_empty() {
                        // Keep partials writable-but-parked; resume comes via
                        // rejoin (C6) or a later re-offer against the .part.
                        eprintln!("sender disconnected mid-transfer — waiting up to {}s for them to come back", REJOIN_WINDOW.as_secs());
                        flush_inflight(&mut by_sid).await;
                    } else if completed > 0 && !keep_open {
                        eprintln!("done ({completed} file{}).", if completed == 1 { "" } else { "s" });
                        let _ = sio.disconnect().await;
                        return Ok(());
                    } else if paired && !keep_open {
                        bail!("sender left before sending anything");
                    } else {
                        conn.waiting_rejoin = None; // open listener: keep going
                        eprintln!("peer left — still listening");
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
async fn flush_inflight(by_sid: &mut HashMap<u32, IncomingFile>) {
    for (_sid, mut inc) in by_sid.drain() {
        let _ = inc.file.flush().await;
        eprintln!("{}: parked at {} for resume", inc.name, human(inc.received));
    }
}

async fn prompt_accept(sender: &str, name: &str, size: u64, paired: bool) -> bool {
    if !std::io::stdin().is_terminal() {
        eprintln!("declining {name} (no tty for confirmation — use -y to auto-accept)");
        return false;
    }
    let sender = if sender.is_empty() { "unknown peer".to_string() } else { sender.to_string() };
    let name = name.to_string();
    let hint = if paired { " [paired]" } else { "" };
    tokio::task::spawn_blocking(move || {
        eprint!("{sender}{hint} offers {name} ({}) — accept? [y/N] ", human(size));
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
    })
    .await
    .unwrap_or(false)
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

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
