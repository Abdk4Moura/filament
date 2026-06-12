// L2 — ssh / raw TCP tunnelled over the Filament WebRTC data channel.
//
// Productionizes docs/L2-tunnel-design.md (spike: cli/spike/l2spike.rs). L2
// multiplexes logical TCP streams over the SAME data channel that moves files
// today, reusing the `Transport` trait verbatim — no transport changes.
//
// SCOPE: single-stream (ssh / one forward at a time is the supported case and
// what ships first). Multiple *concurrent heavy* streams over one link need
// per-stream credit flow control (design §4) to stay deadlock-free; that is a
// follow-up — see TODO(credits) below. l2-open-ack is mandatory here (it closes
// the early-frame-drop race and the open/deny ambiguity); the `credit` field it
// will eventually carry is the only piece deferred.
//
// Three surfaces, smallest-primitive-first (each is sugar over the one below):
//   * `filament netcat <peer> <rport>`            stdio  <-> one L2 stream
//   * `filament forward <lport> <peer> <rport>`   local TCP listener; conn=stream
//   * `filament ssh <peer> [args...]`             real ssh -o ProxyCommand=netcat
//
// The ACCEPTOR (the side that dials the localhost target) is NOT a subcommand:
// it lives inside `filament up` / `filament recv`, gated on the existing
// proof-verified `trusted` flag (the capability placeholder) + localhost-only
// dialing (the SSRF defense). See `Mux::on_open` and main.rs's recv loop.

use crate::net::{self, Ev, Peer, Transport};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::AbortHandle;

/// L2 stream ids live in the HIGH half of the u32 sid space (`sid | 0x8000_0000`)
/// so they can NEVER collide with file-transfer sids (which start at 0 and count
/// up). A single link can therefore carry file transfers (low sids) and L2
/// streams (high sids) at once; the read loop in net.rs hands both to `Ev::Chunk`
/// and the dispatcher splits on this bit.
pub const L2_SID_BASE: u32 = 0x8000_0000;

/// Is this a high-half (L2) stream id? The hot-path discriminator the recv loop
/// uses to route an `Ev::Chunk` to the mux vs. the file-transfer logic.
#[inline]
pub fn is_l2_sid(sid: u32) -> bool {
    sid & L2_SID_BASE != 0
}

/// Per-stream pipe item: `Some(bytes)` = data; `None` = clean half-close/EOF
/// (an empty 4-byte data frame). A RST/abort is signalled out-of-band by
/// dropping the whole stream entry (writer wakes on a closed channel) — distinct
/// from `None` so a reset is never mistaken for an orderly EOF.
type PipeItem = Option<Bytes>;
type StreamTx = mpsc::Sender<PipeItem>;

/// Liveness handle for one stream's two pumps. Holding the read-pump's
/// `AbortHandle` is what makes teardown actually work: `socket_to_dc` parks in
/// `rd.read()` and will NOT wake just because we drop its peer channel, so on
/// data-channel death / l2-close we must abort it explicitly (design §3.5).
struct StreamHandle {
    tx: StreamTx,
    read_pump: Option<AbortHandle>,
}

/// H-1 (DoS): per-link cap on concurrently live streams (file + L2 + PTY share
/// the `streams` table). Beyond this an `l2-open`/`pty-open` is refused. A
/// generous bound — interactive use needs only a handful — that still stops a
/// flaky/hostile paired device from spawning unbounded threads/sockets.
pub const MAX_STREAMS_PER_LINK: usize = 8;

/// H-1 (DoS): process-wide cap on concurrently live PTYs across ALL links. Each
/// PTY is a login shell + threads, so this bounds total resource use even if many
/// links each stay under the per-link cap. Refused opens get an `l2-close`.
pub const MAX_PTYS_GLOBAL: usize = 32;

/// Process-wide live-PTY counter (incremented just before a `serve_pty` task is
/// spawned, decremented when it ends — see `PtyGuard`). The acceptor checks it
/// against `MAX_PTYS_GLOBAL` before granting a `pty-open`.
pub static LIVE_PTYS: AtomicUsize = AtomicUsize::new(0);

/// RAII guard that decrements `LIVE_PTYS` on drop, so the global PTY count is
/// freed on EVERY `serve_pty` exit path (shell exit, browser FIN, error return).
pub struct PtyGuard;
impl PtyGuard {
    /// Reserve a global PTY slot if one is free. Returns `None` (and reserves
    /// nothing) when `MAX_PTYS_GLOBAL` live PTYs already exist.
    pub fn try_acquire() -> Option<PtyGuard> {
        // Optimistic CAS loop so the check + increment is atomic across links.
        let mut cur = LIVE_PTYS.load(Ordering::Relaxed);
        loop {
            if cur >= MAX_PTYS_GLOBAL {
                return None;
            }
            match LIVE_PTYS.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Some(PtyGuard),
                Err(actual) => cur = actual,
            }
        }
    }
}
impl Drop for PtyGuard {
    fn drop(&mut self) {
        LIVE_PTYS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The multiplexer: routes inbound control/data frames to per-stream pipes and
/// owns stream-id allocation. Transport-agnostic — it rides above the trait.
pub struct Mux {
    transport: Arc<dyn Transport>,
    streams: Mutex<HashMap<u32, StreamHandle>>,
    next_sid: AtomicU32,
    /// Acceptor only: sids we have seen `l2-open` for and accepted, so a late
    /// duplicate open is ignored. (Initiator allocates, so it can't double-open.)
    accepted: Mutex<HashMap<u32, ()>>,
    /// web-shell: per-sid PTY resize senders. H-1: owning these HERE (rather than
    /// in the main event loop) guarantees they are dropped on EVERY teardown path
    /// — inbound `l2-close` (`on_close`), `serve_pty` exit (`drop_pty`), and
    /// link/mux death (`shutdown_all`) — closing the resizer-map leak.
    resizers: Mutex<HashMap<u32, mpsc::UnboundedSender<(u16, u16)>>>,
}

impl Mux {
    pub fn new(t: Arc<dyn Transport>) -> Arc<Self> {
        Arc::new(Mux {
            transport: t,
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(L2_SID_BASE),
            accepted: Mutex::new(HashMap::new()),
            resizers: Mutex::new(HashMap::new()),
        })
    }

    pub fn transport(&self) -> Arc<dyn Transport> {
        self.transport.clone()
    }

    fn alloc_sid(&self) -> u32 {
        // Wrap inside the high half so a long-lived link never escapes back into
        // the low (file-transfer) range.
        let raw = self.next_sid.fetch_add(1, Ordering::Relaxed);
        raw | L2_SID_BASE
    }

    /// Register a stream's inbound pipe and return the receiver the socket-writer
    /// task drains. The read-pump handle is attached later via `set_read_pump`.
    async fn register(&self, sid: u32) -> mpsc::Receiver<PipeItem> {
        let (tx, rx) = mpsc::channel::<PipeItem>(256);
        self.streams
            .lock()
            .await
            .insert(sid, StreamHandle { tx, read_pump: None });
        rx
    }

    async fn set_read_pump(&self, sid: u32, h: AbortHandle) {
        if let Some(s) = self.streams.lock().await.get_mut(&sid) {
            s.read_pump = Some(h);
        } else {
            // Stream already gone (raced with teardown) — kill the orphan pump.
            h.abort();
        }
    }

    /// Register a stream's inbound pipe (public, for the PTY acceptor which
    /// registers BEFORE spawning the shell — same pre-registration race fix as
    /// l2-open's dial path).
    pub async fn register_stream(&self, sid: u32) -> mpsc::Receiver<PipeItem> {
        self.register(sid).await
    }

    /// Number of currently live streams on this link (file + L2 + PTY share the
    /// table). H-1: the acceptor checks this against `MAX_STREAMS_PER_LINK`
    /// before accepting a new `l2-open`/`pty-open`.
    pub async fn live_streams(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// True if accepting one more stream would exceed `MAX_STREAMS_PER_LINK`.
    pub async fn at_stream_cap(&self) -> bool {
        self.live_streams().await >= MAX_STREAMS_PER_LINK
    }

    /// Drop a stream and abort its read pump. Idempotent. Also drops any PTY
    /// resize sender for this sid (H-1: no resizer outlives its stream).
    async fn drop_stream(&self, sid: u32) {
        self.resizers.lock().await.remove(&sid);
        if let Some(s) = self.streams.lock().await.remove(&sid) {
            if let Some(h) = s.read_pump {
                h.abort();
            }
            // Dropping `s.tx` closes the pipe; the writer pump (dc_to_socket)
            // sees `recv()` return None and shuts the socket down.
        }
    }

    /// Register a PTY's resize sender (acceptor). Stored in the mux so it is freed
    /// on every teardown path with the stream — see `resizers`.
    pub async fn register_resizer(&self, sid: u32, tx: mpsc::UnboundedSender<(u16, u16)>) {
        self.resizers.lock().await.insert(sid, tx);
    }

    /// Deliver a `pty-resize` to the PTY task for `sid`, if it is still live.
    pub async fn resize_pty(&self, sid: u32, cols: u16, rows: u16) {
        if let Some(tx) = self.resizers.lock().await.get(&sid) {
            let _ = tx.send((cols, rows));
        }
    }

    /// Free a PTY's stream + resize sender on `serve_pty` exit (the teardown path
    /// that does NOT come from an inbound `l2-close`). Idempotent.
    pub async fn drop_pty(&self, sid: u32) {
        self.resizers.lock().await.remove(&sid);
        self.streams.lock().await.remove(&sid);
    }

    /// Route an inbound data frame to its stream. Empty payload = clean EOF/FIN.
    pub async fn on_frame(&self, sid: u32, payload: Bytes) {
        let tx = self.streams.lock().await.get(&sid).map(|s| s.tx.clone());
        if let Some(tx) = tx {
            let msg = if payload.is_empty() { None } else { Some(payload) };
            let _ = tx.send(msg).await; // receiver gone => stream already torn down
        }
    }

    /// Inbound l2-close. `err` set = RST/abort (drop, do NOT deliver clean EOF);
    /// no `err` = the peer is done — also a drop (its data direction already
    /// EOF'd via the empty frame). Either way: abort pumps, close the socket.
    async fn on_close(&self, sid: u32, _err: Option<&str>) {
        self.drop_stream(sid).await;
    }

    /// Data-channel died (or a send errored): tear down EVERY live stream so no
    /// pump hangs forever waiting on a peer that will never speak again.
    pub async fn shutdown_all(&self) {
        self.resizers.lock().await.clear(); // H-1: no resizer outlives the mux
        let mut map = self.streams.lock().await;
        for (_, s) in map.drain() {
            if let Some(h) = s.read_pump {
                h.abort();
            }
        }
    }
}

// ----------------------------------------------------------- stream plumbing --

/// Pump local TCP reads -> data-channel frames. On local EOF, send a 4-byte
/// empty frame (clean half-close / FIN). `send_frame` carries the per-link
/// aggregate backpressure, so a slow peer naturally stalls us here. Returns the
/// kind of ending so the caller can pick FIN vs. RST in the trailing l2-close.
///
/// TODO(credits): single-stream only relies on send_frame's per-link
/// backpressure. With >1 concurrent heavy stream this needs a per-stream credit
/// window (design §4) or one slow stream head-of-line-blocks the others.
async fn socket_to_dc(
    transport: Arc<dyn Transport>,
    sid: u32,
    mut rd: tokio::net::tcp::OwnedReadHalf,
) -> Result<()> {
    let cap = transport.max_payload();
    let mut buf = vec![0u8; cap];
    loop {
        let n = rd.read(&mut buf).await?;
        if n == 0 {
            transport.send_frame(sid, &[]).await?; // local FIN -> empty frame
            return Ok(());
        }
        transport.send_frame(sid, &buf[..n]).await?;
    }
}

/// Pump data-channel frames -> local TCP writes. `None` = peer FIN: shutdown the
/// write half so the local app sees a clean EOF, then end. A dropped pipe
/// (channel closed without a `None`) = abort: shutdown anyway and end.
async fn dc_to_socket(
    mut rx: mpsc::Receiver<PipeItem>,
    mut wr: tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    while let Some(item) = rx.recv().await {
        match item {
            Some(bytes) => wr.write_all(&bytes).await?,
            None => {
                let _ = wr.shutdown().await; // clean half-close to local app
                return Ok(());
            }
        }
    }
    let _ = wr.shutdown().await; // pipe dropped (teardown/abort)
    Ok(())
}

/// Wire a connected socket to stream `sid` whose inbound pipe (`rx`) is already
/// registered. Spawns the write pump, stores the read pump's abort handle so
/// teardown can wake it, and runs the read pump to completion. On exit, drops
/// the stream and (optionally) sends a trailing l2-close (FIN or, on read error,
/// RST with `err`).
async fn serve_stream(
    mux: Arc<Mux>,
    sid: u32,
    sock: TcpStream,
    rx: mpsc::Receiver<PipeItem>,
    send_close: bool,
) {
    let _ = sock.set_nodelay(true);
    let (rd, wr) = sock.into_split();
    let writer = tokio::spawn(dc_to_socket(rx, wr));
    let reader = tokio::spawn(socket_to_dc(mux.transport.clone(), sid, rd));
    mux.set_read_pump(sid, reader.abort_handle()).await;

    // Wait for the read pump: Ok = local FIN sent; Err = socket error -> RST;
    // Aborted = teardown already cleaned us up.
    let read_result = reader.await;
    let _ = writer.await;
    // The stream may already be gone (teardown). Remove if still present.
    mux.streams.lock().await.remove(&sid);
    if send_close {
        let close = match read_result {
            Ok(Ok(())) => json!({ "type": "l2-close", "sid": sid }), // clean FIN
            Ok(Err(e)) => json!({ "type": "l2-close", "sid": sid, "err": e.to_string() }),
            Err(_aborted) => return, // teardown owns the close; don't double-send
        };
        let _ = mux.transport.send_control(&close).await;
    }
}

/// web-shell acceptor: spawn a login shell in a PTY and bridge it to stream `sid`.
/// PTY master output -> sid frames; inbound sid frames (`rx`) -> PTY input;
/// `resize_rx` carries (cols, rows) from the browser. The blocking PTY fd reads/
/// writes run on dedicated threads (portable-pty is sync) and funnel into this
/// async task. The shell exiting (reader EOF) OR the browser closing tears it all
/// down and sends a trailing l2-close.
pub async fn serve_pty(
    mux: Arc<Mux>,
    sid: u32,
    cols: u16,
    rows: u16,
    argv: Vec<String>,
    mut rx: mpsc::Receiver<PipeItem>,
    mut resize_rx: mpsc::UnboundedReceiver<(u16, u16)>,
    // H-1: holding the guard for the whole task lifetime frees the global PTY
    // slot on EVERY exit path (early error returns + the normal teardown).
    _pty_guard: PtyGuard,
) {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read as _, Write as _};

    let size = PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 };
    let pair = match native_pty_system().openpty(size) {
        Ok(p) => p,
        Err(e) => {
            mux.drop_pty(sid).await;
            let _ = mux.transport.send_control(&json!({ "type": "l2-close", "sid": sid, "err": format!("pty: {e}") })).await;
            return;
        }
    };
    let mut cmd = CommandBuilder::new(&argv[0]);
    for a in &argv[1..] {
        cmd.arg(a);
    }
    cmd.env("TERM", "xterm-256color");
    if let Ok(home) = std::env::var("HOME") {
        cmd.cwd(home);
    }
    let mut child = match pair.slave.spawn_command(cmd) {
        Ok(c) => c,
        Err(e) => {
            mux.drop_pty(sid).await;
            let _ = mux.transport.send_control(&json!({ "type": "l2-close", "sid": sid, "err": format!("spawn: {e}") })).await;
            return;
        }
    };
    drop(pair.slave); // close our copy of the slave so the shell owns the only one
    let master = pair.master;
    let mut reader = match master.try_clone_reader() {
        Ok(r) => r,
        Err(_) => {
            mux.drop_pty(sid).await;
            return;
        }
    };
    let mut writer = match master.take_writer() {
        Ok(w) => w,
        Err(_) => {
            mux.drop_pty(sid).await;
            return;
        }
    };

    // Blocking PTY-master reads -> async output channel.
    let (otx, mut orx) = mpsc::channel::<Vec<u8>>(128);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break, // shell exited / PTY closed
                Ok(n) => {
                    if otx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    // Async input -> blocking PTY-master writes (dedicated thread).
    let (wtx, wrx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(b) = wrx.recv() {
            if writer.write_all(&b).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let cap = mux.transport.max_payload();
    loop {
        tokio::select! {
            out = orx.recv() => match out {
                Some(bytes) => {
                    for chunk in bytes.chunks(cap) {
                        if mux.transport.send_frame(sid, chunk).await.is_err() {
                            break;
                        }
                    }
                }
                None => break, // shell exited
            },
            inp = rx.recv() => match inp {
                Some(Some(bytes)) => { let _ = wtx.send(bytes.to_vec()); }
                Some(None) | None => break, // browser FIN / pipe dropped
            },
            rs = resize_rx.recv() => {
                if let Some((c, r)) = rs {
                    let _ = master.resize(PtySize { rows: r.max(1), cols: c.max(1), pixel_width: 0, pixel_height: 0 });
                }
            }
        }
    }

    drop(wtx); // stop the writer thread
    let _ = child.kill(); // ensure the shell dies if the browser closed first
    let _ = child.wait();
    mux.drop_pty(sid).await; // H-1: free stream + resize sender on this exit path
    let _ = mux.transport.send_control(&json!({ "type": "l2-close", "sid": sid })).await;
}

// ------------------------------------------------------------- ACCEPTOR side --

/// Decision for an inbound `l2-open`, made synchronously in the event loop
/// BEFORE any await — so the pipe is registered before a data frame for this sid
/// can be processed (closes the early-frame-drop race, design §3.4).
pub enum OpenVerdict {
    /// Accepted: dial this localhost target and relay. Carries the pre-registered
    /// inbound pipe.
    Accept { sid: u32, host: String, port: u16, rx: mpsc::Receiver<PipeItem> },
    /// Refused: send l2-close{err} and forget it.
    Deny { sid: u32, err: &'static str },
    /// Not an l2-open / malformed — ignore.
    Ignore,
}

impl Mux {
    /// Handle an inbound L2 *control* message on the acceptor side. `trusted` is
    /// the proof-verified capability flag for this link (the placeholder gate).
    /// Registers the pipe synchronously for an accepted open, then returns the
    /// verdict for the caller to act on (the dial is async and must NOT block the
    /// event loop). Returns `Ignore` for non-l2 control.
    pub async fn accept_control(&self, v: &Value, trusted: bool) -> OpenVerdict {
        match v["type"].as_str() {
            Some("l2-open") => {
                let Some(sid) = v["sid"].as_u64().map(|s| s as u32) else {
                    return OpenVerdict::Ignore;
                };
                if !is_l2_sid(sid) {
                    return OpenVerdict::Ignore; // not in the high half — not ours
                }
                // Idempotency: a duplicate open for a live sid is ignored.
                {
                    let mut acc = self.accepted.lock().await;
                    if acc.contains_key(&sid) {
                        return OpenVerdict::Ignore;
                    }
                    acc.insert(sid, ());
                }
                // ---- CAPABILITY GATE (placeholder; see TODO below) ----
                // Today: the peer must be a remembered/trusted device (its
                // pair-proof verified on this link, main.rs ~3111). That is the
                // coarse stand-in for L1-a's per-cap model.
                if !trusted {
                    return OpenVerdict::Deny { sid, err: "denied" };
                }
                // TODO(L1-a caps): replace the bare `trusted` check above with the
                // real capability decision once l1-a-pake merges. L1-a gives each
                // device a record {name, secret, caps[]}; here we must require the
                // `forward` cap (and `shell` for port 22) carried/proved in
                // `v["cap"]` and bound to the DTLS fingerprints, deny-by-default.
                // The whole L2 acceptor stays OFF unless FILAMENT_L2=1 (opt-in).

                let host = v["host"].as_str().unwrap_or("127.0.0.1").to_string();
                let port = v["rport"].as_u64().or_else(|| v["port"].as_u64()).unwrap_or(0) as u16;
                if port == 0 {
                    return OpenVerdict::Deny { sid, err: "bad port" };
                }
                // ---- SSRF defense: localhost-only by default ----
                // Stricter than is_private_addr (which ALLOWS LAN/RFC1918): the
                // dial target must resolve to loopback. Non-loopback is refused
                // unless a future per-device allowlist opts in (TODO above).
                if !host_is_loopback(&host) {
                    return OpenVerdict::Deny { sid, err: "non-loopback denied" };
                }
                // H-1 (DoS): cap concurrent streams per link. A flaky/hostile
                // paired device can otherwise flood `l2-open` and exhaust
                // sockets/threads. We drop the `accepted` marker so the same sid
                // can be retried once others free up.
                if self.at_stream_cap().await {
                    self.accepted.lock().await.remove(&sid);
                    return OpenVerdict::Deny { sid, err: "too many streams" };
                }
                let rx = self.register(sid).await; // BEFORE the async dial
                OpenVerdict::Accept { sid, host, port, rx }
            }
            Some("l2-close") => {
                if let Some(sid) = v["sid"].as_u64() {
                    self.on_close(sid as u32, v["err"].as_str()).await;
                }
                OpenVerdict::Ignore
            }
            _ => OpenVerdict::Ignore,
        }
    }

    /// Acceptor: dial the localhost target for an accepted open and relay. Sends
    /// l2-open-ack on success, l2-close{err} on dial failure. Runs as its own
    /// task (the event loop spawns it) so the dial never blocks routing.
    pub async fn dial_and_serve(self: Arc<Self>, sid: u32, host: String, port: u16, rx: mpsc::Receiver<PipeItem>) {
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(sock) => {
                // l2-open-ack is mandatory (design §3.4/O2): it tells the
                // initiator the stream is live. credit-in-ack is the follow-up
                // (TODO(credits)); 0 here means "no per-stream window yet".
                let _ = self
                    .transport
                    .send_control(&json!({ "type": "l2-open-ack", "sid": sid, "credit": 0 }))
                    .await;
                serve_stream(self.clone(), sid, sock, rx, true).await;
                self.accepted.lock().await.remove(&sid);
            }
            Err(e) => {
                self.drop_stream(sid).await;
                self.accepted.lock().await.remove(&sid);
                let _ = self
                    .transport
                    .send_control(&json!({ "type": "l2-close", "sid": sid, "err": e.to_string() }))
                    .await;
            }
        }
    }
}

/// True if `host` is a loopback address/name. We accept the literal "localhost"
/// and any address that parses to a loopback IP. (DNS for arbitrary names is
/// deliberately NOT performed here — the default contract is localhost-only and
/// a name that isn't "localhost" is treated as non-loopback.)
fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

// ------------------------------------------------------------ INITIATOR side --

/// Holds the signaling client + WebRTC peer that back a brought-up link so the
/// CALLER decides their fate. A long-lived consumer (netcat/forward) calls
/// `forget()` to keep the link alive for the process lifetime (byte-identical to
/// the old `std::mem::forget`). A short-lived consumer (the shell bootstrap)
/// calls `close().await` to TEAR THE LINK DOWN before opening a second link to
/// the same device — otherwise the acceptor sees two same-device peers at once
/// and its C6 supersede/adopt logic churns (one link gets dropped mid-use).
pub struct LinkGuard {
    sio: Option<rust_socketio::asynchronous::Client>,
    peer: Option<Arc<Peer>>,
}

impl LinkGuard {
    /// Keep the link alive forever (leaks sio+peer, as the long-lived tunnels
    /// want). Consumes the guard.
    fn forget(mut self) {
        if let Some(sio) = self.sio.take() {
            std::mem::forget(sio);
        }
        if let Some(p) = self.peer.take() {
            std::mem::forget(p);
        }
    }

    /// Cleanly close the link: drop the WebRTC peer connection and disconnect
    /// signaling, so the acceptor reaps this peer promptly. Consumes the guard.
    async fn close(mut self) {
        if let Some(p) = self.peer.take() {
            p.close().await;
        }
        if let Some(sio) = self.sio.take() {
            let _ = sio.disconnect().await;
        }
    }
}

/// Minimal identity-mode link bring-up to a *known* device, mirroring the
/// production send/recv path but stripped to exactly what L2 needs: join a solo
/// room, subscribe to the device's presence channel, dial it when it appears,
/// and prove our identity (pair-proof) so its `up`/`recv` marks us trusted —
/// which is what unlocks the acceptor's capability gate. Returns the ready
/// Transport, the event receiver, and a `LinkGuard` the caller must either
/// `forget()` (keep alive) or `close().await` (tear down).
async fn bring_up_to_known(
    server: &str,
    peer_name: &str,
    relay: bool,
) -> Result<(Arc<dyn Transport>, mpsc::UnboundedReceiver<Ev>, LinkGuard)> {
    let secret = crate::devices_load()
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(peer_name))
        .map(|(_, s)| s)
        .ok_or_else(|| anyhow!("no known device named '{peer_name}' — run `filament pair` first (see `filament devices`)"))?;
    let channel = crate::channel_of(&secret);

    let cfg = net::fetch_config(server).await?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;

    let my_uid = crate::mk_uid("l2");
    // A solo room keeps strangers out; presence-channel subscription is how we
    // actually find the known device (same as `--to` identity mode).
    let solo = format!("l2-{}", crate::fresh_secret());
    sio.emit("join", json!({ "room": solo, "uid": my_uid, "name": crate::display_name() }))
        .await
        .ok();
    // NOTE: subscribe is emitted on Ev::Welcome (below), not here — `welcome` is
    // the proof the socket.io connection is fully established, so the subscribe
    // can't be lost in the connect->emit race that intermittently left the client
    // unsubscribed and "waiting for known device" forever (harness finding).

    let mut my_id: Option<String> = None;
    let mut peer: Option<Arc<Peer>> = None;
    let mut peer_uid: Option<String> = None;
    let mut generation: u32 = 0;
    // Ghost tolerance: the channel can hold DEAD sids (a SIGKILL'd process
    // lingers until the server's ping-timeout) and WRONG peers (our own up
    // subscribes the same pair channel). Locking onto the first known-peer
    // forever was the dominant stall. Instead: one candidate AT A TIME (a
    // parallel race glares — proven, see multicandidate-attempt.patch), a
    // short per-candidate timer, and rotation through everything seen.
    let mut queue: VecDeque<(String, Option<String>)> = VecDeque::new();
    const CANDIDATE_SECS: u64 = 7;
    // Item 3: the L2 initiator races a DIRECT-QUIC dial against WebRTC. On
    // KnownPeer we bind a quinn endpoint + advertise our candidates (mirrors
    // `start_direct` in main.rs); when the peer's transport-offer arrives we
    // consume this endpoint into the race. UNCONDITIONAL here: `bring_up_to_known`
    // only ever serves L2 (netcat/ssh/forward), which always wants direct — and
    // `filament ssh`/`netcat` do NOT set FILAMENT_L2 in their own env, so gating
    // on `direct_enabled()` would kill the direct dial on the live path. main.rs
    // gates because it ALSO serves file transfer; this function never does.
    let mut endpoint: Option<quinn::Endpoint> = None;
    // Candidates gathered once at first bind; re-advertised to each new
    // candidate peer we rotate to (the endpoint accepts from any of them —
    // the QUIC race is pair-secret-authenticated either way).
    let mut direct_cands: Option<Vec<String>> = None;
    // The acceptor re-sends its transport-offer (a late initiator can miss the
    // first). Race only the FIRST offer we get; later re-sends are duplicates.
    let mut direct_racing = false;

    let spawn_timer = |pid: String, g: u32| {
        let tx = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(CANDIDATE_SECS)).await;
            let _ = tx.send(Ev::Stuck(pid, g));
        });
    };

    crate::ui::say(&format!("filament: waiting for known device '{peer_name}'..."));

    loop {
        // One candidate at a time: start the next attempt whenever idle.
        if peer.is_none() {
            if let Some((pid, uid)) = queue.pop_front() {
                let mine = my_id.clone().unwrap_or_default();
                let polite = net::polite_role(&my_uid, uid.as_deref(), &mine, &pid);
                generation += 1;
                spawn_timer(pid.clone(), generation);
                let p = Peer::connect(
                    pid.clone(), polite, cfg.ice_servers.clone(), relay,
                    sio.clone(), tx.clone(), generation,
                )
                .await?;
                peer_uid = uid;
                peer = Some(p);

                // Item 3: also start a DIRECT-QUIC attempt racing the WebRTC
                // dial. Bind once, advertise to whichever candidate is current
                // (mirrors `start_direct`); the peer's own offer drives the
                // race (handled in Ev::Signal below).
                if !direct_racing {
                    if endpoint.is_none() {
                        match crate::direct::bind_endpoint() {
                            Ok((ep, port)) => {
                                direct_cands =
                                    Some(crate::direct::gather_candidates(server, port).await);
                                endpoint = Some(ep);
                                // TRACE — direct-offer detail.
                                crate::ui::trace(&format!("filament: DIRECT-OFFER sent to '{peer_name}' — port {port}"));
                            }
                            Err(e) => {
                                crate::ui::trace(&format!("filament: direct disabled (endpoint bind failed: {e}) — WebRTC only"));
                            }
                        }
                    }
                    if endpoint.is_some() {
                        if let Some(c) = &direct_cands {
                            let offer =
                                json!({ "type": "transport-offer", "v": 1, "addrs": c });
                            sio.emit("signal", json!({ "to": pid, "data": offer })).await.ok();
                        }
                    }
                }
            }
        }
        let Some(ev) = rx.recv().await else { break };
        match ev {
            Ev::Welcome(v) => {
                my_id = v["id"].as_str().map(|s| s.to_string());
                // Subscribe now that the connection is confirmed (see the note
                // at the join site). The server replies with known-peer for every
                // live member already on the channel, so discovery is reliable.
                sio.emit("subscribe", json!({ "channels": [channel.clone()] }))
                    .await
                    .ok();
            }
            Ev::KnownPeer(v) => {
                if v["channel"].as_str() != Some(channel.as_str()) {
                    continue;
                }
                let pid = match v["id"].as_str() {
                    Some(p) => p.to_string(),
                    None => continue,
                };
                if Some(pid.as_str()) == my_id.as_deref() {
                    continue;
                }
                // #9: never dial our OWN install (the up subscribes this pair
                // channel too). Pair secrets are symmetric, so a self-connect
                // can pass the pair-proof and tunnel into the WRONG host's
                // sshd — the local daemon answering as the remote device.
                if crate::is_self_uid(&my_uid, v["uid"].as_str()) {
                    continue;
                }
                // Queue every distinct sid; the loop top rotates through them.
                if peer.as_ref().is_some_and(|p| p.id == pid)
                    || queue.iter().any(|(q, _)| *q == pid)
                {
                    continue;
                }
                queue.push_back((pid, v["uid"].as_str().map(|s| s.to_string())));
            }
            Ev::Signal(v) => {
                let data = v["data"].clone();
                // Item 3: a relayed `transport-offer` carries the peer's direct
                // candidates. Do NOT hand it to the WebRTC `Peer`; instead consume
                // our endpoint and spawn the simultaneous-open + auth race
                // (`race_connect_labeled`, the same primitive `start_direct`
                // drives). The winner posts Ev::DirectReady into THIS loop's tx,
                // so the DirectTransport's reader funnels Chunk/Control/PcState to
                // the rx the caller hands to `pump_initiator`.
                if data["type"].as_str() == Some("transport-offer") {
                    if direct_racing {
                        continue; // already racing the first offer; ignore re-sends
                    }
                    // Bind on-demand if the offer beat our own KnownPeer: on real
                    // WAN the already-running acceptor fires its offer the instant
                    // we appear, which can arrive BEFORE our presence event sets
                    // `endpoint`. The old `if let Some` silently DROPPED it and we
                    // never dialed (the cross-machine stall). We DIAL the peer's
                    // candidates, so we don't need to have sent our own offer first.
                    let ep = endpoint
                        .take()
                        .or_else(|| crate::direct::bind_endpoint().ok().map(|(ep, _)| ep));
                    if let Some(ep) = ep {
                        direct_racing = true;
                        let peer_cands: Vec<String> = data["addrs"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        // DEBUG — resilience/direct internal (racing a direct path).
                        crate::ui::debug(&format!(
                            "filament: got transport-offer ({} cand) — racing direct-quic",
                            peer_cands.len()
                        ));
                        let secret = secret.clone();
                        let pid = v["from"].as_str().unwrap_or_default().to_string();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            if let Some(t) = crate::direct::race_connect_labeled(
                                ep, peer_cands, &secret, pid.clone(), tx.clone(), "direct-quic",
                            )
                            .await
                            {
                                let _ = tx.send(Ev::DirectReady(pid, t, "direct-quic"));
                            }
                            // On None the WebRTC path (Ev::ChannelReady) continues.
                        });
                    }
                    continue;
                }
                // Route by sender: the channel is multi-party (our own up
                // subscribes it too, plus lingering dead sids) — a stray offer
                // applied to the current pc was a reliable glare generator.
                let from = v["from"].as_str().unwrap_or_default();
                let Some(p) = &peer else { continue };
                if p.id != from {
                    continue;
                }
                match p.handle_signal(data).await {
                    Ok(net::SignalOutcome::Handled) => {}
                    Ok(net::SignalOutcome::Glare(offer)) => {
                        // Both sides offered (role confusion). Yield: rebuild
                        // this attempt as a pure responder answering theirs.
                        let old = peer.take().unwrap();
                        let pid = old.id.clone();
                        old.mark_closed();
                        tokio::spawn(async move { old.close().await });
                        generation += 1;
                        spawn_timer(pid.clone(), generation);
                        let p = Peer::connect(
                            pid, true, cfg.ice_servers.clone(), relay,
                            sio.clone(), tx.clone(), generation,
                        )
                        .await?;
                        if let Err(e) = p.handle_signal(offer).await {
                            crate::ui::trace(&format!("filament: signal: {e}"));
                        }
                        peer = Some(p);
                    }
                    Err(e) => crate::ui::trace(&format!("filament: signal: {e}")),
                }
            }
            Ev::DirectReady(_pid, t, route) => {
                // Item 3: the DIRECT-QUIC race won before WebRTC. The acceptor's
                // `adopt_direct` (main.rs) is born `trusted: true` + identity-bound
                // `verified_name` — its pair-secret MAC already proved who we are —
                // so the cap gate is satisfied WITHOUT a pair-proof. We deliberately
                // do NOT replicate the ChannelReady proof here: that MAC is built
                // from the WebRTC DTLS fingerprints, which a direct QUIC link does
                // not have, and the acceptor's direct link (`peer: None`) has none
                // to verify against. (design-l2-direct-ladder.md §NOTE: pre-trust
                // OR pair-proof — we confirmed pre-trust holds for the L2 acceptor.)
                // INFO — tunnel established (with its route label).
                crate::ui::say(&format!("filament: tunnel up to '{peer_name}' (route: {route})"));
                // The WebRTC `peer` is now superfluous; the guard owns it (its
                // teardown/forget semantics are unchanged — no extra teardown).
                let guard = LinkGuard { sio: Some(sio), peer: peer.take() };
                return Ok((t, rx, guard));
            }
            Ev::Stuck(pid, g) => {
                // Per-candidate timer (or the 15s watchdog) fired for the
                // CURRENT attempt: drop it and rotate. The sid goes to the
                // back of the queue — a slow-but-real peer gets retried, a
                // ghost just cycles until the server evicts it.
                if g == generation && peer.as_ref().is_some_and(|p| p.id == pid) {
                    let p = peer.take().unwrap();
                    p.mark_closed();
                    tokio::spawn(async move { p.close().await });
                    crate::ui::debug("filament: candidate unresponsive — rotating");
                    queue.push_back((pid, peer_uid.take()));
                }
            }
            Ev::ChannelReady(pid, t) if peer.as_ref().is_some_and(|p| p.id == pid) => {
                // Prove identity so the peer's up/recv marks this link trusted —
                // the acceptor's capability gate keys on exactly that.
                if let Some(p) = &peer {
                    if let Some((my_fp, their_fp)) = p.fingerprints().await {
                        let mac = crate::proof_for(
                            &secret, &my_uid, &my_uid,
                            peer_uid.as_deref().unwrap_or(""), &my_fp, &their_fp,
                        );
                        t.send_control(&json!({ "type": "pair-proof", "mac": mac })).await?;
                    }
                }
                // Hand sio + peer to the caller via a guard: a long-lived tunnel
                // `forget()`s it (keep alive); the bootstrap `close().await`s it
                // (tear down before the second link).
                crate::ui::say(&format!("filament: tunnel up to '{peer_name}'"));
                let guard = LinkGuard { sio: Some(sio), peer: peer.take() };
                return Ok((t, rx, guard));
            }
            Ev::PcState(pid, s) if s == "failed" || s == "closed" => {
                // Was fatal; now just rotate — the overall command timeout
                // (or the user) bounds how long we keep trying.
                if peer.as_ref().is_some_and(|p| p.id == pid) {
                    let p = peer.take().unwrap();
                    p.mark_closed();
                    tokio::spawn(async move { p.close().await });
                    crate::ui::debug(&format!("filament: connection {s} — rotating"));
                    queue.push_back((pid, peer_uid.take()));
                }
            }
            _ => {}
        }
    }
    Err(anyhow!("signaling ended before a data channel came up"))
}

/// Drive the initiator's inbound event pump: route L2 control/data into the mux
/// and tear everything down on data-channel death. The initiator never accepts
/// inbound opens (it allocates ids); an l2-open-ack unparks nothing today (no
/// credits) but is consumed so the protocol stays honest.
async fn pump_initiator(mut rx: mpsc::UnboundedReceiver<Ev>, mux: Arc<Mux>) {
    while let Some(ev) = rx.recv().await {
        match ev {
            Ev::Control(_pid, v) => match v["type"].as_str() {
                Some("l2-close") => {
                    if let Some(sid) = v["sid"].as_u64() {
                        mux.on_close(sid as u32, v["err"].as_str()).await;
                    }
                }
                Some("l2-open-ack") => { /* TODO(credits): seed the send window */ }
                _ => {}
            },
            Ev::Chunk(_pid, sid, data) if is_l2_sid(sid) => {
                mux.on_frame(sid, data).await;
            }
            Ev::PcState(_, s) if s == "failed" || s == "closed" || s == "disconnected" => {
                crate::ui::debug(&format!("filament: tunnel {s} — closing streams"));
                mux.shutdown_all().await;
            }
            _ => {}
        }
    }
    mux.shutdown_all().await;
}

/// Open one stream to `peer:rport`, sending l2-open and waiting (briefly) until
/// the inbound pipe is wired. Returns the registered receiver. The initiator
/// registers its OWN pipe up front so a server-speaks-first protocol (ssh
/// banner) can't lose bytes.
async fn open_stream(mux: &Arc<Mux>, rport: u16) -> Result<(u32, mpsc::Receiver<PipeItem>)> {
    let sid = mux.alloc_sid();
    let rx = mux.register(sid).await;
    // The dial target is ALWAYS 127.0.0.1 in production (localhost-only is the
    // contract). FILAMENT_L2_DIALHOST is a TEST-ONLY override so the SSRF gate
    // can drive a non-loopback open and observe the acceptor refuse it.
    let host = std::env::var("FILAMENT_L2_DIALHOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    mux.transport
        .send_control(&json!({ "type": "l2-open", "sid": sid, "host": host, "rport": rport }))
        .await?;
    Ok((sid, rx))
}

/// `filament netcat <peer> <rport>`: wire this process's stdio to one L2 stream.
/// This is the ssh ProxyCommand primitive.
pub async fn netcat_cmd(server: &str, peer: &str, rport: u16, relay: bool) -> Result<()> {
    let (t, rx, guard) = bring_up_to_known(server, peer, relay).await?;
    guard.forget(); // long-lived tunnel — keep the link alive for the process
    let mux = Mux::new(t);
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    let (sid, mut rx_pipe) = open_stream(&mux, rport).await?;

    // stdin -> dc
    let t_in = mux.transport();
    let reader = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let cap = t_in.max_payload();
        let mut buf = vec![0u8; cap];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = t_in.send_frame(sid, &[]).await; // local EOF -> FIN
                    break;
                }
                Ok(n) => {
                    if t_in.send_frame(sid, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // dc -> stdout
    let mut stdout = tokio::io::stdout();
    while let Some(item) = rx_pipe.recv().await {
        match item {
            Some(bytes) => {
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            None => break, // peer FIN
        }
    }
    let _ = reader.await;
    mux.drop_stream(sid).await;
    let _ = mux
        .transport()
        .send_control(&json!({ "type": "l2-close", "sid": sid }))
        .await;
    pump.abort();
    Ok(())
}

/// `filament pty <peer>`: open a PTY shell on the peer and bridge it to this
/// process's stdio (the CLI sibling of the browser terminal). No local raw-mode
/// or resize handling yet — primarily a test/diagnostic of the `serve_pty`
/// acceptor; the browser is the polished client.
pub async fn pty_cmd(server: &str, peer: &str, relay: bool) -> Result<()> {
    let (t, rx, guard) = bring_up_to_known(server, peer, relay).await?;
    guard.forget();
    let mux = Mux::new(t);
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    let sid = mux.alloc_sid();
    let mut rx_pipe = mux.register(sid).await;
    let (cols, rows) = (
        std::env::var("COLUMNS").ok().and_then(|s| s.parse().ok()).unwrap_or(80u16),
        std::env::var("LINES").ok().and_then(|s| s.parse().ok()).unwrap_or(24u16),
    );
    mux.transport()
        .send_control(&json!({ "type": "pty-open", "sid": sid, "cols": cols, "rows": rows }))
        .await?;

    let t_in = mux.transport();
    let reader = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let cap = t_in.max_payload();
        let mut buf = vec![0u8; cap];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = t_in.send_frame(sid, &[]).await;
                    break;
                }
                Ok(n) => {
                    if t_in.send_frame(sid, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut stdout = tokio::io::stdout();
    while let Some(item) = rx_pipe.recv().await {
        match item {
            Some(bytes) => {
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            None => break,
        }
    }
    let _ = reader.await;
    mux.drop_stream(sid).await;
    let _ = mux.transport().send_control(&json!({ "type": "l2-close", "sid": sid })).await;
    pump.abort();
    Ok(())
}

/// `filament forward <lport> <peer> <rport>`: local TCP listener; every accepted
/// connection opens a fresh L2 stream to `peer:127.0.0.1:rport`.
pub async fn forward_cmd(server: &str, lport: u16, peer: &str, rport: u16, relay: bool) -> Result<()> {
    let (t, rx, guard) = bring_up_to_known(server, peer, relay).await?;
    guard.forget(); // long-lived listener — keep the link alive for the process
    let mux = Mux::new(t);
    tokio::spawn(pump_initiator(rx, mux.clone()));

    let listener = TcpListener::bind(("127.0.0.1", lport)).await?;
    crate::ui::say(&format!("filament: forwarding 127.0.0.1:{lport} -> {peer}:127.0.0.1:{rport}"));
    // NOTE(scope): concurrent heavy forwards over one link need credit flow
    // control (design §4); single active stream is the supported case today.
    loop {
        let (sock, _) = listener.accept().await?;
        let mux = mux.clone();
        let (sid, rx_pipe) = open_stream(&mux, rport).await?;
        tokio::spawn(async move {
            serve_stream(mux, sid, sock, rx_pipe, true).await;
        });
    }
}

/// Seamless-shell bootstrap (initiator): over the already-authenticated filament
/// channel, hand the acceptor our managed pubkey and fetch its host keys, so a
/// user with ZERO ssh setup gets a no-prompt shell. The exchange is pure control
/// JSON over the transport `bring_up_to_known` returns (no mux needed).
///
/// Returns `Ok(hostkeys)` on grant (the acceptor installed our key); the caller
/// pins the host keys and spawns ssh. Returns `Err` if the acceptor DENIES (the
/// device lacks the `shell` cap) or times out — in which case the caller MUST NOT
/// fall through to a key-less ssh attempt (that would be a muddy auth failure
/// instead of a clear "zero shell" denial).
async fn shell_bootstrap(server: &str, peer: &str, relay: bool) -> Result<(Vec<String>, Option<String>)> {
    // Managed keypair lives under the filament config dir — NEVER ~/.ssh.
    let pubkey = crate::sshkeys::ensure_managed_key()?;

    let (t, mut rx, guard) = bring_up_to_known(server, peer, relay).await?;
    t.send_control(&json!({ "type": "shell-bootstrap", "v": 1, "pubkey": pubkey })).await?;

    // Await the verdict (bounded — a daemon without FILAMENT_L2 / without the cap
    // must not hang us forever). Capture it, then ALWAYS tear this link down
    // BEFORE returning, so the ssh data link (netcat ProxyCommand) is the only
    // boxA peer the acceptor sees — no concurrent same-device supersede churn.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let verdict: Result<(Vec<String>, Option<String>)> = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break Err(anyhow!(
                "shell bootstrap timed out — is '{peer}' running `filament up` with shell access granted?"
            ));
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(Ev::Control(_pid, v))) => match v["type"].as_str() {
                Some("shell-bootstrap-ack") => {
                    let hostkeys: Vec<String> = v["hostkeys"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|k| k.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    // The acceptor reports the account it installed our key into
                    // — authoritative for the ssh login (see ssh_cmd).
                    let user = v["user"].as_str().map(String::from);
                    break Ok((hostkeys, user));
                }
                Some("shell-bootstrap-deny") => {
                    let why = v["reason"].as_str().unwrap_or("shell capability not granted");
                    break Err(anyhow!(
                        "shell refused by '{peer}': {why}. Run `filament grant <this-device> shell` on '{peer}'."
                    ));
                }
                _ => continue,
            },
            Ok(Some(_)) => continue, // other events on this link — ignore
            Ok(None) => break Err(anyhow!("channel closed before shell bootstrap completed")),
            Err(_) => continue, // timeout sliver — loop re-checks the deadline
        }
    };

    // Tear down the bootstrap link before the caller opens the ssh data link.
    drop(t);
    guard.close().await;
    verdict
}

/// `filament ssh <peer> [args...]`: seamless shell over the trusted channel.
///
/// With zero pre-existing ssh setup: bootstrap our managed key + the peer's host
/// key over the authenticated filament channel, pin them, then run ssh pointed
/// EXCLUSIVELY at filament-managed material (-o IdentityFile / IdentitiesOnly /
/// UserKnownHostsFile) with a `filament netcat` ProxyCommand. No prompts, no
/// ~/.ssh, no key copying. The bootstrap is the deny-by-default gate: if the
/// peer lacks the `shell` cap we abort HERE, before invoking ssh.
pub async fn ssh_cmd(server: &str, peer: &str, extra: &[String], relay: bool) -> Result<()> {
    // ssh matches known_hosts by HOST token only (never user@host), so the pin
    // MUST be keyed on the bare host or it is silently inert.
    let host = format!("filament-{peer}");

    // 1) Bootstrap auth material over the trusted channel (deny-by-default gate).
    let (hostkeys, remote_user) = shell_bootstrap(server, peer, relay).await?;
    crate::sshkeys::pin_host_keys(&host, &hostkeys)?;

    // The login account is the one the ACCEPTOR actually installed our key into
    // (reported in the bootstrap-ack) — authoritative over a guess from our local
    // $USER, which is usually wrong cross-machine (agboola@laptop vs root@server).
    // A killed earlier session left "agboola@filament-dovm: Permission denied
    // (publickey)" precisely because of that mismatch. FILAMENT_SSH_USER still
    // overrides for explicit control (`ssh -l user` via extra args also works).
    let login = std::env::var("FILAMENT_SSH_USER")
        .ok()
        .or(remote_user)
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".into());
    // `<login>@filament-<peer>` keeps the destination stable + recognizable.
    let dest_token = format!("{login}@{host}");

    // 2) Build the ProxyCommand: a fresh `filament netcat` link to peer:22 (or a
    // test port via FILAMENT_SSH_PORT, mirroring FILAMENT_L2_DIALHOST).
    let rport: u16 = std::env::var("FILAMENT_SSH_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(22);
    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let mut proxy = format!("{exe} --server {server}");
    if relay {
        proxy.push_str(" --relay");
    }
    proxy.push_str(&format!(" netcat {peer} {rport}"));

    // 3) ssh pointed ONLY at filament-managed key + known_hosts; no prompts.
    let key = crate::sshkeys::managed_key_path();
    let kh = crate::sshkeys::known_hosts_path();
    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o").arg(format!("ProxyCommand={proxy}"))
        .arg("-o").arg(format!("IdentityFile={}", key.display()))
        .arg("-o").arg("IdentitiesOnly=yes")
        .arg("-o").arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o").arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o").arg("StrictHostKeyChecking=accept-new");
    // Split passthrough args into ssh OPTIONS (leading `-…` flags) and the remote
    // COMMAND (everything from the first non-flag token on). The destination is
    // ALWAYS our managed token — in the seamless model `<peer>` IS the host — so
    // the destination must be inserted BETWEEN the options and the command, or
    // ssh would mistake the command (e.g. `hostname`) for the host.
    let mut split = extra.len();
    for (i, a) in extra.iter().enumerate() {
        if !a.starts_with('-') {
            split = i;
            break;
        }
    }
    for a in &extra[..split] {
        cmd.arg(a); // leading ssh flags (e.g. -p, -L, -v)
    }
    cmd.arg(&dest_token); // the destination is the filament peer
    for a in &extra[split..] {
        cmd.arg(a); // remote command + its args
    }
    let status = cmd.status()?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod h1_tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    /// Minimal in-memory Transport: records control messages, discards frames.
    struct MockTransport {
        controls: StdMutex<Vec<Value>>,
    }
    impl MockTransport {
        fn new() -> Arc<Self> {
            Arc::new(MockTransport { controls: StdMutex::new(Vec::new()) })
        }
    }
    #[async_trait]
    impl Transport for MockTransport {
        async fn send_control(&self, msg: &Value) -> Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _payload: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
    }

    fn open_msg(sid: u32) -> Value {
        json!({ "type": "l2-open", "sid": sid, "host": "127.0.0.1", "rport": 9 })
    }

    /// H-1: opening + closing N PTY-style streams (register + resizer, then close)
    /// leaves BOTH the stream table and the resizer map empty on every teardown
    /// path, and the global PTY counter returns to zero.
    #[tokio::test]
    async fn pty_open_close_leaves_maps_empty() {
        let start = LIVE_PTYS.load(Ordering::SeqCst);
        let mux = Mux::new(MockTransport::new());
        let n = 5u32;

        // Path A: inbound l2-close frees stream + resizer.
        for i in 0..n {
            let sid = L2_SID_BASE | (1000 + i);
            let guard = PtyGuard::try_acquire().expect("slot free");
            let _rx = mux.register_stream(sid).await;
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
            assert_eq!(mux.live_streams().await, 1);
            assert_eq!(mux.resizers.lock().await.len(), 1);
            // Inbound l2-close (browser closed).
            mux.on_close(sid, None).await;
            drop(guard); // serve_pty task ending frees the global slot
            assert_eq!(mux.live_streams().await, 0, "stream not freed on l2-close");
            assert_eq!(mux.resizers.lock().await.len(), 0, "resizer leaked on l2-close");
        }

        // Path B: serve_pty exit (drop_pty) frees stream + resizer.
        for i in 0..n {
            let sid = L2_SID_BASE | (2000 + i);
            let guard = PtyGuard::try_acquire().expect("slot free");
            let _rx = mux.register_stream(sid).await;
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
            mux.drop_pty(sid).await; // serve_pty's own exit path
            drop(guard);
            assert_eq!(mux.live_streams().await, 0, "stream not freed on drop_pty");
            assert_eq!(mux.resizers.lock().await.len(), 0, "resizer leaked on drop_pty");
        }

        // Path C: link/mux death (shutdown_all) frees everything.
        let mut guards = Vec::new();
        for i in 0..n {
            let sid = L2_SID_BASE | (3000 + i);
            guards.push(PtyGuard::try_acquire().expect("slot free"));
            let _rx = mux.register_stream(sid).await;
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
        }
        assert_eq!(mux.live_streams().await, n as usize);
        mux.shutdown_all().await;
        drop(guards);
        assert_eq!(mux.live_streams().await, 0, "streams leaked past shutdown_all");
        assert_eq!(mux.resizers.lock().await.len(), 0, "resizers leaked past shutdown_all");

        assert_eq!(LIVE_PTYS.load(Ordering::SeqCst), start, "global PTY count must return to baseline");
    }

    /// H-1: the per-link stream cap refuses opens beyond MAX_STREAMS_PER_LINK with
    /// an `l2-close{err:"too many streams"}`, and does NOT register the stream.
    #[tokio::test]
    async fn per_link_stream_cap_refuses_over_limit() {
        let mux = Mux::new(MockTransport::new());
        // Fill to the cap with accepted opens (they register pipes).
        for i in 0..MAX_STREAMS_PER_LINK as u32 {
            let sid = L2_SID_BASE | (i + 1);
            match mux.accept_control(&open_msg(sid), true).await {
                OpenVerdict::Accept { .. } => {}
                other => panic!("expected Accept under cap, got {:?}", std::mem::discriminant(&other)),
            }
        }
        assert_eq!(mux.live_streams().await, MAX_STREAMS_PER_LINK);
        // One more must be denied with the cap error, leaving the table unchanged.
        let over = L2_SID_BASE | 9999;
        match mux.accept_control(&open_msg(over), true).await {
            OpenVerdict::Deny { sid, err } => {
                assert_eq!(sid, over);
                assert_eq!(err, "too many streams");
            }
            other => panic!("expected Deny over cap, got {:?}", std::mem::discriminant(&other)),
        }
        assert_eq!(mux.live_streams().await, MAX_STREAMS_PER_LINK, "over-cap open must not register");
        // The denied sid is not stuck in `accepted` (can retry once room frees).
        assert!(!mux.accepted.lock().await.contains_key(&over));
    }

    /// H-1: the global PTY guard refuses acquisition once MAX_PTYS_GLOBAL slots
    /// are held, and frees them on drop.
    #[tokio::test]
    async fn global_pty_cap_is_enforced() {
        // Other tests may hold none here, but to be robust we only assert the
        // guard refuses once at-capacity relative to the current baseline.
        let mut held = Vec::new();
        while LIVE_PTYS.load(Ordering::SeqCst) < MAX_PTYS_GLOBAL {
            match PtyGuard::try_acquire() {
                Some(g) => held.push(g),
                None => break,
            }
        }
        assert_eq!(LIVE_PTYS.load(Ordering::SeqCst), MAX_PTYS_GLOBAL);
        assert!(PtyGuard::try_acquire().is_none(), "must refuse at global cap");
        let before = held.len();
        drop(held);
        assert!(LIVE_PTYS.load(Ordering::SeqCst) <= MAX_PTYS_GLOBAL - before.min(1));
    }
}
