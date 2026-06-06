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
// Resume: receivers keep `<name>.part` + `<name>.part.meta`; a re-offered
// file with the same name+size continues from the bytes already on disk —
// and unlike the browser, this survives a full process restart.

mod net;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use net::{Ev, Peer, Transport};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const DEFAULT_SERVER: &str = "https://api.filament.autumated.com";

#[derive(Parser)]
#[command(name = "filament", version, about = "P2P file transfer between terminals and browsers — no upload, no account")]
struct Cli {
    /// Signaling server (self-hosters: point at your own instance)
    #[arg(long, global = true, env = "FILAMENT_SERVER", default_value = DEFAULT_SERVER)]
    server: String,
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
        /// Keep listening after a batch completes
        #[arg(long)]
        keep_open: bool,
    },
}

fn mk_uid(prefix: &str) -> String {
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

#[tokio::main]
async fn main() -> Result<()> {
    // Both ring (webrtc) and aws-lc (reqwest) end up in the dep tree; rustls
    // refuses to guess between two providers, so pick ring explicitly.
    rustls::crypto::ring::default_provider().install_default().ok();
    let cli = Cli::parse();
    let server = cli.server.trim_end_matches('/').to_string();
    match cli.cmd {
        Cmd::Send { paths, code, word, room, name } => {
            send_cmd(&server, paths, code || word.is_some(), word, room, name).await
        }
        Cmd::Recv { code, dir, yes, room, keep_open } => {
            recv_cmd(&server, code, dir, yes, room, keep_open).await
        }
    }
}

// ------------------------------------------------------------------- send --

struct Outgoing {
    id: String,
    sid: u32,
    name: String,
    size: u64,
    path: PathBuf,
    temp: bool, // delete after sending (tar spools, stdin spools)
    done: bool,
}

async fn send_cmd(
    server: &str,
    paths: Vec<String>,
    use_code: bool,
    word: Option<String>,
    room: Option<String>,
    stdin_name: String,
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
            outgoing.push(Outgoing { id, sid, name: stdin_name.clone(), size: n, path: spool, temp: true, done: false });
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
                outgoing.push(Outgoing { id, sid, name: format!("{dirname}.tar"), size, path: spool, temp: true, done: false });
            } else {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone());
                outgoing.push(Outgoing { id, sid, name, size: meta.len(), path, temp: false, done: false });
            }
        }
    }
    for o in &outgoing {
        eprintln!("send: {} ({})", o.name, human(o.size));
    }

    let cfg = net::fetch_config(server).await?;
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

    let mut my_id = String::new();
    let mut peer: Option<Arc<Peer>> = None;
    let mut peer_name = String::new();
    let mut transport: Option<Arc<dyn Transport>> = None;
    let mut code_used = !use_code; // without --code any peer is fair game
    let outgoing = Arc::new(tokio::sync::Mutex::new(outgoing));
    let started = Instant::now();
    let deadline = Duration::from_secs(600);

    loop {
        // The wait-for-peer deadline only applies while we have no peer; once a
        // transfer is running it must never fire.
        let ev = if peer.is_none() {
            tokio::time::timeout(deadline.saturating_sub(started.elapsed()), rx.recv())
                .await
                .map_err(|_| anyhow!("timed out waiting for a peer"))?
                .ok_or_else(|| anyhow!("signaling channel closed"))?
        } else {
            rx.recv().await.ok_or_else(|| anyhow!("signaling channel closed"))?
        };
        match ev {
            Ev::Welcome(v) => {
                my_id = v["id"].as_str().unwrap_or_default().to_string();
                if code_used && peer.is_none() {
                    if let Some(first) = v["peers"].as_array().and_then(|a| a.first()) {
                        let (p, n) = connect_peer(first, &my_uid, &my_id, cfg.ice_servers.clone(), &sio, &tx).await?;
                        peer = Some(p);
                        peer_name = n;
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
                if code_used && peer.is_none() {
                    let (p, n) = connect_peer(&v, &my_uid, &my_id, cfg.ice_servers.clone(), &sio, &tx).await?;
                    peer = Some(p);
                    peer_name = n;
                }
            }
            Ev::Signal(v) => {
                if let Some(p) = &peer {
                    if v["from"].as_str() == Some(p.id.as_str()) {
                        p.handle_signal(v["data"].clone()).await?;
                    }
                }
            }
            Ev::ChannelReady(t) => {
                eprintln!("connected to {peer_name}");
                if let Some(p) = &peer {
                    let p = p.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(1200)).await;
                        if let Some(r) = p.route().await {
                            eprintln!("route: {r}");
                        }
                    });
                }
                for o in outgoing.lock().await.iter() {
                    t.send_control(&json!({
                        "type": "file-offer", "id": o.id, "sid": o.sid,
                        "name": o.name, "size": o.size, "mime": "application/octet-stream",
                    }))
                    .await?;
                }
                transport = Some(t);
            }
            Ev::Control(v) => match v["type"].as_str() {
                Some("file-accept") => {
                    let t = transport.clone().ok_or_else(|| anyhow!("accept before channel"))?;
                    let offset = v["offset"].as_u64().unwrap_or(0);
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    let out = outgoing.clone();
                    let chunk = cfg.chunk_size.min(t.max_payload());
                    let tx2 = tx.clone();
                    tokio::spawn(async move {
                        match stream_one(out, t, id.clone(), offset, chunk).await {
                            Ok(()) => {
                                let _ = tx2.send(Ev::TransferDone(id));
                            }
                            Err(e) => {
                                eprintln!("send failed: {e}");
                                std::process::exit(1);
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
            Ev::PcState(s) => {
                if s == "failed" && !outgoing.lock().await.iter().all(|o| o.done) {
                    bail!("connection failed");
                }
            }
            Ev::PeerLeft(v) => {
                if let Some(p) = &peer {
                    if v["id"].as_str() == Some(p.id.as_str())
                        && !outgoing.lock().await.iter().all(|o| o.done)
                    {
                        bail!("peer left before the transfer finished");
                    }
                    // Receiver got everything and left — the all-done check
                    // below ends us gracefully.
                }
            }
            _ => {}
        }
        // Exit when every transfer reached a terminal state.
        {
            let out = outgoing.lock().await;
            if !out.is_empty() && out.iter().all(|o| o.done) {
                if let Some(t) = &transport {
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

async fn connect_peer(
    v: &Value,
    my_uid: &str,
    my_id: &str,
    ice: Vec<webrtc::ice_transport::ice_server::RTCIceServer>,
    sio: &rust_socketio::asynchronous::Client,
    tx: &mpsc::UnboundedSender<Ev>,
) -> Result<(Arc<Peer>, String)> {
    let peer_id = v["id"].as_str().unwrap_or_default().to_string();
    let peer_uid = v["uid"].as_str().map(|s| s.to_string());
    let name = v["name"].as_str().unwrap_or("peer").to_string();
    let polite = net::polite_role(my_uid, peer_uid.as_deref(), my_id, &peer_id);
    let p = Peer::connect(peer_id, polite, ice, sio.clone(), tx.clone()).await?;
    Ok((p, name))
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
    file: std::io::BufWriter<std::fs::File>,
    part_path: PathBuf,
    started: Instant,
}

async fn recv_cmd(
    server: &str,
    code: Option<String>,
    dir: PathBuf,
    yes: bool,
    room: Option<String>,
    keep_open: bool,
) -> Result<()> {
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let my_uid = mk_uid("r");
    let cfg = net::fetch_config(server).await?;
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

    let auto_accept = yes || paired; // claiming a code IS the consent gesture
    let mut my_id = String::new();
    let mut peer: Option<Arc<Peer>> = None;
    let mut transport: Option<Arc<dyn Transport>> = None;
    let mut by_sid: HashMap<u32, IncomingFile> = HashMap::new();
    let mut completed = 0usize;
    let mut last_progress = Instant::now();

    loop {
        // After a finished batch (nothing in flight), exit unless --keep-open.
        let idle_exit = !keep_open && completed > 0 && by_sid.is_empty();
        let ev = if idle_exit {
            match tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
                Ok(Some(ev)) => ev,
                _ => {
                    eprintln!("done ({completed} file{}).", if completed == 1 { "" } else { "s" });
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
            }
        } else {
            rx.recv().await.ok_or_else(|| anyhow!("signaling channel closed"))?
        };

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
                my_id = v["id"].as_str().unwrap_or_default().to_string();
                if peer.is_none() {
                    if let Some(first) = v["peers"].as_array().and_then(|a| a.first()) {
                        let (p, n) = connect_peer(first, &my_uid, &my_id, cfg.ice_servers.clone(), &sio, &tx).await?;
                        eprintln!("peer: {n}");
                        peer = Some(p);
                    }
                }
            }
            Ev::PeerJoined(v) => {
                if peer.is_none() {
                    let (p, n) = connect_peer(&v, &my_uid, &my_id, cfg.ice_servers.clone(), &sio, &tx).await?;
                    eprintln!("peer: {n}");
                    peer = Some(p);
                }
            }
            Ev::Signal(v) => {
                if let Some(p) = &peer {
                    if v["from"].as_str() == Some(p.id.as_str()) {
                        p.handle_signal(v["data"].clone()).await?;
                    }
                }
            }
            Ev::ChannelReady(t) => {
                transport = Some(t);
                if let Some(p) = &peer {
                    let p = p.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(1200)).await;
                        if let Some(r) = p.route().await {
                            eprintln!("route: {r}");
                        }
                    });
                }
            }
            Ev::Control(v) => match v["type"].as_str() {
                Some("file-offer") => {
                    let t = transport.clone().ok_or_else(|| anyhow!("offer before channel"))?;
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // Never trust a remote name with path separators.
                    let raw = v["name"].as_str().unwrap_or("file.bin");
                    let name = Path::new(raw)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "file.bin".into());
                    let size = v["size"].as_u64().unwrap_or(0);

                    let ok = if auto_accept {
                        true
                    } else {
                        prompt_accept(&name, size).await
                    };
                    if !ok {
                        t.send_control(&json!({ "type": "file-decline", "id": id })).await?;
                        continue;
                    }

                    let part_path = dir.join(format!("{name}.part"));
                    let meta_path = dir.join(format!("{name}.part.meta"));
                    let mut offset = 0u64;
                    if part_path.is_file() {
                        let prior = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
                        let meta_size = std::fs::read_to_string(&meta_path)
                            .ok()
                            .and_then(|s| s.trim().parse::<u64>().ok());
                        if meta_size == Some(size) && prior <= size {
                            offset = prior;
                            eprintln!("{name}: resuming at {} ({:.0}%)", human(offset), offset as f64 / size.max(1) as f64 * 100.0);
                        }
                    }
                    let file = if offset > 0 {
                        std::fs::OpenOptions::new().append(true).open(&part_path)?
                    } else {
                        std::fs::write(&meta_path, size.to_string())?;
                        std::fs::File::create(&part_path)?
                    };
                    eprintln!("receiving {name} ({})", human(size));
                    by_sid.insert(sid, IncomingFile {
                        id: id.clone(),
                        name,
                        size,
                        received: offset,
                        file: std::io::BufWriter::with_capacity(1 << 20, file),
                        part_path,
                        started: Instant::now(),
                    });
                    t.send_control(&json!({ "type": "file-accept", "id": id, "offset": offset })).await?;
                }
                Some("file-end") => {
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    if let Some(mut inc) = by_sid.remove(&sid) {
                        inc.file.flush()?;
                        drop(inc.file);
                        let final_path = unique_path(&dir, &inc.name);
                        std::fs::rename(&inc.part_path, &final_path)?;
                        let _ = std::fs::remove_file(dir.join(format!("{}.part.meta", inc.name)));
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
                    inc.file.write_all(&data)?;
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
            Ev::PcState(s) => {
                if s == "failed" {
                    // Partials stay on disk: a re-offer resumes from them.
                    bail!("connection failed (partial files kept for resume)");
                }
            }
            Ev::PeerLeft(v) => {
                if let Some(p) = &peer {
                    if v["id"].as_str() == Some(p.id.as_str()) {
                        if by_sid.is_empty() && completed > 0 && !keep_open {
                            eprintln!("done ({completed} file{}).", if completed == 1 { "" } else { "s" });
                            let _ = sio.disconnect().await;
                            return Ok(());
                        }
                        if !by_sid.is_empty() {
                            bail!("sender left mid-transfer (partial files kept for resume)");
                        }
                        peer = None;
                        transport = None;
                    }
                }
            }
            _ => {}
        }
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

async fn prompt_accept(name: &str, size: u64) -> bool {
    if !std::io::stdin().is_terminal() {
        eprintln!("declining {name} (no tty for confirmation — use -y to auto-accept)");
        return false;
    }
    let name = name.to_string();
    tokio::task::spawn_blocking(move || {
        eprint!("accept {name} ({})? [y/N] ", human(size));
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
    })
    .await
    .unwrap_or(false)
}
