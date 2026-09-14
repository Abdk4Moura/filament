// L2, ssh / raw TCP tunnelled over the Filament WebRTC data channel.
//
// Productionizes docs/L2-tunnel-design.md (spike: cli/spike/l2spike.rs). L2
// multiplexes logical TCP streams over the SAME data channel that moves files
// today, reusing the `Transport` trait verbatim, no transport changes.
//
// SCOPE: single-stream (ssh / one forward at a time is the supported case and
// what ships first). Multiple *concurrent heavy* streams over one link need
// per-stream credit flow control (design §4) to stay deadlock-free; that is a
// follow-up, see TODO(credits) below. l2-open-ack is mandatory here (it closes
// the early-frame-drop race and the open/deny ambiguity); the `credit` field it
// will eventually carry is the only piece deferred.
//
// Three surfaces, smallest-primitive-first (each is sugar over the one below):
//   * `filament netcat <peer> <rport>`            stdio  <-> one L2 stream
//   * `filament forward <lport> <peer> <rport>`   local TCP listener; conn=stream
//   * `filament shell --ssh <peer> [args...]`             real ssh -o ProxyCommand=netcat
//
// The ACCEPTOR (the side that dials the localhost target) is NOT a subcommand:
// it lives inside `filament up` / `filament recv`, gated on the existing
// proof-verified `trusted` flag (the capability placeholder) + localhost-only
// dialing (the SSRF defense). See `Mux::on_open` and main.rs's recv loop.

use crate::net::{self, Ev, Peer, Transport};
use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
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

/// Parse a stream id from an inbound control message's `sid` field, REFUSING a
/// value that does not fit in u32 instead of silently truncating it. A bare
/// `as_u64().unwrap_or(0) as u32` cast both defaults a MISSING sid to 0 and
/// WRAPS an oversized one (e.g. `0x1_8000_0000 as u32 == 0x8000_0000`), which
/// would let a peer forge a value that passes `is_l2_sid` yet aliases a live
/// sid. Returns `None` for a missing field OR an out-of-range value; every
/// caller must deny/ignore the open in that case, never default to 0.
pub fn wire_sid(v: &Value) -> Option<u32> {
    u32::try_from(v["sid"].as_u64()?).ok()
}

/// Per-stream pipe item: `Some(bytes)` = data; `None` = clean half-close/EOF
/// (an empty 4-byte data frame). A RST/abort is signalled out-of-band by
/// dropping the whole stream entry (writer wakes on a closed channel), distinct
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
/// generous bound, interactive use needs only a handful, that still stops a
/// flaky/hostile paired device from spawning unbounded threads/sockets.
pub const MAX_STREAMS_PER_LINK: usize = 8;

/// H-1 (DoS): process-wide cap on concurrently live PTYs across ALL links. Each
/// PTY is a login shell + threads, so this bounds total resource use even if many
/// links each stay under the per-link cap. Refused opens get an `l2-close`.
pub const MAX_PTYS_GLOBAL: usize = 32;

/// Process-wide live-PTY counter (incremented just before a PTY session task is
/// spawned, decremented when it ends, see `PtyGuard`). The acceptor checks it
/// against `MAX_PTYS_GLOBAL` before granting a `pty-open`.
pub static LIVE_PTYS: AtomicUsize = AtomicUsize::new(0);

/// RAII guard that decrements `LIVE_PTYS` on drop, so the global PTY count is
/// freed on EVERY PTY session exit path (shell exit, browser FIN, error return).
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
            match LIVE_PTYS.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
            {
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

/// What the acceptor answered to an initiator's open (mount-open / pty-open).
/// One channel per stream id, shared by every verb, so a new open kind inherits
/// the denial path instead of silently starting without one (the lesson of the
/// mount-only `mount_ack_tx`, which left pty with no way to learn why it was
/// refused).
enum OpenOutcome {
    /// The acceptor acked the open. The carried control JSON is the verb's ack
    /// payload (mount-open-ack carries `caps`; pty-open-ack carries nothing).
    Opened(serde_json::Value),
    /// The acceptor closed the stream with an explicit reason (a real refusal).
    Refused(String),
    /// The stream closed with no ack and no reason: we never established that
    /// the peer opened anything.
    ClosedWithoutAck,
}

/// The multiplexer: routes inbound control/data frames to per-stream pipes and
/// owns stream-id allocation. Transport-agnostic, it rides above the trait.
pub struct Mux {
    transport: Arc<dyn Transport>,
    streams: Mutex<HashMap<u32, StreamHandle>>,
    next_sid: AtomicU32,
    /// Acceptor only: sids we have seen `l2-open` for and accepted, so a late
    /// duplicate open is ignored. (Initiator allocates, so it can't double-open.)
    accepted: Mutex<HashMap<u32, ()>>,
    /// web-shell: per-sid PTY resize senders. H-1: owning these HERE (rather than
    /// in the main event loop) guarantees they are dropped on EVERY teardown path:
    /// inbound `l2-close` (`on_close`), the session task exit (`drop_pty`), and
    /// link/mux death (`shutdown_all`), closing the resizer-map leak.
    resizers: Mutex<HashMap<u32, mpsc::UnboundedSender<(u16, u16)>>>,
    /// per-sid oneshot senders delivering the acceptor's answer to an open back
    /// to the caller that issued it (mount-open via `open_mount_stream`, pty-open
    /// via `pty_attach_once`). pump_initiator receives the ack control message
    /// (mount-open-ack / pty-open-ack), resolves the sid, and sends `Opened`;
    /// an inbound l2-close (`on_close`) sends `Refused`/`ClosedWithoutAck`. The
    /// caller awaits the receiver. Shared across verbs and keyed by stream id, so
    /// a denial carries a reason for every open kind instead of just mount.
    open_ack_tx: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<OpenOutcome>>>,
    /// A reason an inbound `l2-close` carried for a stream whose open waiter was
    /// already consumed (i.e. a mid-session close). A revoked peer loses a live
    /// shell/stream this way; the reason must reach the caller as a denial, not
    /// be swallowed into a clean close. Entries for streams that never read them
    /// linger only until link death (`shutdown_all`), bounded and harmless.
    close_err: Mutex<HashMap<u32, String>>,
}

impl Mux {
    pub fn new(t: Arc<dyn Transport>) -> Arc<Self> {
        Arc::new(Mux {
            transport: t,
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            accepted: Mutex::new(HashMap::new()),
            resizers: Mutex::new(HashMap::new()),
            open_ack_tx: Mutex::new(HashMap::new()),
            close_err: Mutex::new(HashMap::new()),
        })
    }

    pub fn transport(&self) -> Arc<dyn Transport> {
        self.transport.clone()
    }

    pub(crate) fn alloc_sid(&self) -> u32 {
        // Mask the counter to the low 30 bits so a long-lived link never escapes
        // into the L2 flag (0x80000000) OR the answerer-role bit (0x40000000).
        // The role bit keeps the two ends' sid spaces DISJOINT: each end allocates
        // with its own bit (opposite the peer's, via the deterministic `polite`
        // role), so a sid this end allocates can never equal one the peer
        // allocated - preventing cross-tunnel frame collisions when both ends open
        // L2 streams on one link (pty + warm-reuse forward, etc.).
        let n = self.next_sid.fetch_add(1, Ordering::Relaxed) & 0x3FFF_FFFF;
        let role = if self.transport.sid_answerer() {
            0x4000_0000
        } else {
            0
        };
        n | L2_SID_BASE | role
    }

    /// Register a stream's inbound pipe and return the receiver the socket-writer
    /// task drains. The read-pump handle is attached later via `set_read_pump`.
    ///
    /// COLLISION-SAFE: the sid is chosen by the PEER, so it can name a sid that
    /// is ALREADY live (its own earlier forward, a pty, a mount, ...). A bare
    /// `insert` would silently DISPLACE the existing `StreamHandle` and drop it;
    /// dropping is NOT closing (the orphaned `read_pump` is dropped WITHOUT
    /// `abort()`, so `socket_to_dc` stays parked in `rd.read()` leaking a
    /// pump+socket, while `streams.len()` stays flat and defeats the H-1 stream
    /// cap, and inbound frames for the sid are redirected to the new stream).
    /// So this REFUSES a sid that is already present and returns `None`; a peer
    /// reusing a live sid is a protocol error and the caller must deny the open.
    /// This is the single structural chokepoint every stream type inherits.
    async fn register(&self, sid: u32) -> Option<mpsc::Receiver<PipeItem>> {
        let mut streams = self.streams.lock().await;
        if streams.contains_key(&sid) {
            return None; // sid already live: refuse, do NOT overwrite/drop
        }
        let (tx, rx) = mpsc::channel::<PipeItem>(256);
        streams.insert(
            sid,
            StreamHandle {
                tx,
                read_pump: None,
            },
        );
        Some(rx)
    }

    async fn set_read_pump(&self, sid: u32, h: AbortHandle) {
        if let Some(s) = self.streams.lock().await.get_mut(&sid) {
            s.read_pump = Some(h);
        } else {
            // Stream already gone (raced with teardown), kill the orphan pump.
            h.abort();
        }
    }

    /// Register a stream's inbound pipe (public, for the PTY/mount acceptors which
    /// register BEFORE spawning the server, same pre-registration race fix as
    /// l2-open's dial path). Returns `None` if the sid is already live (see
    /// `register`): the caller MUST deny the open and must NOT proceed to set up
    /// the stream, or the collision hole re-opens.
    pub async fn register_stream(&self, sid: u32) -> Option<mpsc::Receiver<PipeItem>> {
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
    pub(crate) async fn drop_stream(&self, sid: u32) {
        self.resizers.lock().await.remove(&sid);
        self.open_ack_tx.lock().await.remove(&sid);
        if let Some(s) = self.streams.lock().await.remove(&sid) {
            if let Some(h) = s.read_pump {
                h.abort();
            }
            // Dropping `s.tx` closes the pipe; the writer pump (dc_to_socket)
            // sees `recv()` return None and shuts the socket down.
        }
    }

    /// Register a PTY's resize sender (acceptor). Stored in the mux so it is freed
    /// on every teardown path with the stream, see `resizers`.
    pub async fn register_resizer(&self, sid: u32, tx: mpsc::UnboundedSender<(u16, u16)>) {
        self.resizers.lock().await.insert(sid, tx);
    }

    /// Deliver a `pty-resize` to the PTY task for `sid`, if it is still live.
    pub async fn resize_pty(&self, sid: u32, cols: u16, rows: u16) {
        if let Some(tx) = self.resizers.lock().await.get(&sid) {
            let _ = tx.send((cols, rows));
        }
    }

    /// Free a PTY's stream + resize sender on a session task exit (the teardown path
    /// that does NOT come from an inbound `l2-close`). Idempotent.
    pub async fn drop_pty(&self, sid: u32) {
        self.resizers.lock().await.remove(&sid);
        self.streams.lock().await.remove(&sid);
    }

    /// Route an inbound data frame to its stream. Empty payload = clean EOF/FIN.
    /// Never parks: the send is try_send, so a stalled consumer cannot freeze
    /// the daemon recv loop that calls this (bulk stdin vs a non-reading
    /// child filled the 256-slot pipe and wedged every stream behind it).
    /// A full pipe resets the stream LOUDLY -- l2-close with an explicit
    /// reason, entry dropped -- so the initiator fails fast with a reason
    /// instead of hanging on silently lost bytes or wedging the daemon.
    /// Steady consumers never trip it (they drain continuously); only a
    /// genuinely stalled consumer with a full buffer does.
    pub async fn on_frame(&self, sid: u32, payload: Bytes) {
        let tx = match self.streams.lock().await.get(&sid) {
            Some(s) => s.tx.clone(),
            None => return,
        };
        let msg = if payload.is_empty() {
            None
        } else {
            Some(payload)
        };
        match tx.try_send(msg) {
            Ok(()) => {}
            // receiver gone => stream already torn down (same as before).
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                let _ = self
                    .transport
                    .send_control(&json!({
                        "type": "l2-close",
                        "sid": sid,
                        "err": "stream input flooded (consumer stalled)",
                    }))
                    .await;
                self.drop_stream(sid).await;
            }
        }
    }

    /// Deliver a liveness marker for `sid` when the acceptor's `l2-open-ack` lands.
    /// Warm-reuse verification (`verify_first_frame`) needs proof the held link still
    /// delivers BEFORE it commits the client. A server-speaks-first protocol supplies
    /// that proof itself (sshd's banner), but a CLIENT-speaks-first one (HTTP, most DB
    /// clients) sends no app bytes until the client does - so without this the verify
    /// window expired and a HEALTHY link was wrongly dropped as a zombie, making every
    /// `forward` connection fall to a fresh cold link (the "no extra presence" promise
    /// broke). The ack is an empty `Some`: `on_frame` maps real empty payloads to
    /// `None`/EOF, so `Some(empty)` never occurs organically and is an unambiguous
    /// marker; replaying it writes zero bytes to the client.
    pub async fn on_open_ack(&self, sid: u32) {
        let tx = self.streams.lock().await.get(&sid).map(|s| s.tx.clone());
        if let Some(tx) = tx {
            let _ = tx.send(Some(Bytes::new())).await;
        }
    }

    /// Inbound l2-close. `err` set = RST/abort (drop, do NOT deliver clean EOF);
    /// no `err` = the peer is done, also a drop (its data direction already
    /// EOF'd via the empty frame). Either way: abort pumps, close the socket.
    async fn on_close(&self, sid: u32, err: Option<&str>) {
        // Deliver any pending open waiter its answer: an l2-close is the peer
        // saying NO (authorization, ceiling, stream cap, acceptor off), and the
        // reason it carries must reach the caller as a denial, not as a mystery
        // timeout. #206: the acceptor sends `l2-close{err: ...}` on a refusal;
        // before this, the reason was dropped here and the initiator read a
        // generic channel-closed. A close WITHOUT an err is a different fact
        // (we never established the peer opened anything) and is delivered as
        // `ClosedWithoutAck` so the caller can say that instead of inventing a
        // cause.
        if let Some(tx) = self.open_ack_tx.lock().await.remove(&sid) {
            let outcome = match err {
                Some(reason) => OpenOutcome::Refused(reason.to_string()),
                None => OpenOutcome::ClosedWithoutAck,
            };
            let _ = tx.send(outcome);
        } else if let Some(reason) = err {
            // Mid-session close: the open waiter is already consumed, so record
            // the reason where the caller (the pty IO loop) can read it. A revoked
            // peer loses a live session this way; the reason must surface as a
            // denial, never a clean exit.
            //
            // Why this needs no buffer: this insert happens BEFORE drop_stream,
            // and dropping the stream is what closes the pipe the consumer awaits,
            // so the write happens-before the close the reader keys on, in program
            // order. Do NOT "simplify" this by re-arming the open_ack_tx one-shot
            // here: a one-shot slot can be empty at the instant on_close fires, and
            // a denial delivered into that gap is silently lost. The always-present
            // map, written before the close, cannot lose it.
            self.close_err.lock().await.insert(sid, reason.to_string());
        }
        self.drop_stream(sid).await;
    }

    /// Take the mid-session close reason for a stream, if one was recorded, so the
    /// caller can distinguish "the peer revoked us" from "the shell exited".
    pub async fn take_close_err(&self, sid: u32) -> Option<String> {
        self.close_err.lock().await.remove(&sid)
    }

    /// Data-channel died (or a send errored): tear down EVERY live stream so no
    /// pump hangs forever waiting on a peer that will never speak again.
    pub async fn shutdown_all(&self) {
        self.resizers.lock().await.clear(); // H-1: no resizer outlives the mux
        self.open_ack_tx.lock().await.clear();
        self.close_err.lock().await.clear();
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
async fn socket_to_dc<R: AsyncRead + Unpin>(
    transport: Arc<dyn Transport>,
    sid: u32,
    mut rd: R,
) -> Result<()> {
    let cap = transport.max_payload();
    let mut buf = vec![0u8; cap];
    loop {
        let n = rd.read(&mut buf).await?;
        if n == 0 {
            transport.send_frame(sid, 0, &[]).await?; // local FIN -> empty frame
            return Ok(());
        }
        transport.send_frame(sid, 0, &buf[..n]).await?;
    }
}

/// Pump data-channel frames -> local TCP writes. `None` = peer FIN: shutdown the
/// write half so the local app sees a clean EOF, then end. A dropped pipe
/// (channel closed without a `None`) = abort: shutdown anyway and end.
async fn dc_to_socket<W: AsyncWrite + Unpin>(
    mut rx: mpsc::Receiver<PipeItem>,
    mut wr: W,
    first: Option<PipeItem>,
) -> Result<()> {
    // A warm-reuse verify already pulled the FIRST inbound frame off the wire to
    // confirm the link is live; replay it here so no peer bytes are lost.
    if let Some(item) = first {
        match item {
            Some(bytes) => wr.write_all(&bytes).await?,
            None => {
                let _ = wr.shutdown().await;
                return Ok(());
            }
        }
    }
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
async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    sid: u32,
    sock: S,
    rx: mpsc::Receiver<PipeItem>,
    send_close: bool,
    first: Option<PipeItem>,
    // The peer's device key, for the acceptor's live-stream revocation re-check.
    // `None` for the warm/initiator bridges, which do not gate the peer's
    // liveness.
    idev: Option<[u8; 32]>,
) {
    // Caller sets TCP_NODELAY where applicable (a unix socket has none); split
    // generically so the same plumbing serves a TcpStream OR a local UnixStream
    // (the warm-link reuse path bridges a unix socket to an L2 stream).
    let (rd, wr) = tokio::io::split(sock);
    // `first`: a warm-reuse verify already pulled the first inbound frame off the
    // wire to PROVE the link is live before the client was committed; replay it
    // here so no peer bytes are lost.
    let mut writer = tokio::spawn(dc_to_socket(rx, wr, first));
    let reader_task = tokio::spawn(socket_to_dc(mux.transport.clone(), sid, rd));
    mux.set_read_pump(sid, reader_task.abort_handle()).await;
    let mut reader = Some(reader_task);

    // Half-close semantics: reader-done (client stdin-EOF) is NON-TERMINAL.
    // The reader finishing means the client closed its write-half (stdin-EOF /
    // socket write-half closed). On a Unix socket, closing the write-half sends
    // EOF to the reader (socket_to_dc sees it and sends FIN to daemon transport),
    // but the read-half stays open. The daemon keeps the pty open until the
    // command exits, then dc_to_socket finishes and the socket closes.
    //
    // Writer-done (dc_to_socket done = remote command exited / pty output pipe
    // closed) IS terminal: this is when the command has finished and all output
    // has been delivered. Only then do we send l2-close and tear down.
    //
    // Ticker+transport-dead is also terminal: a dead peer must not hang the
    // bridge. The 2s poll tears down in ~2s (kept short so a dead peer doesn't
    // leave the warm pty hung).
    //
    // read_result: Some = reader finished (Ok=FIN sent); None = we tore down
    // because the peer/link ended (writer-done or transport-dead).
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.tick().await; // consume the immediate tick
    let mut reader_done = false;
    let mut read_result = None;
    // #235-shape: a dedicated recheck ticker at the shared interval, so the
    // revoke bound is not floored by the 2s liveness tick. The tick IS the
    // cadence; the verdict is re-asked directly.
    let mut revoke_ticker = tokio::time::interval(crate::revoke_recheck_interval());
    revoke_ticker.tick().await; // consume the immediate first tick
    let mut revoked_reason: Option<&'static str> = None;
    loop {
        tokio::select! {
            r = async { reader.as_mut().unwrap().await }, if !reader_done => {
                // Client-side finished: record result, disarm the arm, but DO
                // NOT break. The writer (dc_to_socket) is still waiting for the
                // remote command to exit. l2-close is sent only after the writer
                // finishes (command exit), not here.
                read_result = Some(r);
                reader = None;   // disarm - must not re-poll a resolved future
                reader_done = true;
            }
            _ = &mut writer => {
                // Terminal: remote command exited / pty output pipe closed.
                // All output delivered; safe to tear down.
                if let Some(r) = reader.take() { r.abort(); }
                read_result = None;
                break;
            }
            _ = ticker.tick() => {
                if !mux.transport.is_alive() {
                    // Terminal: transport dead. Abort both directions.
                    if let Some(r) = reader.take() { r.abort(); }
                    writer.abort();
                    read_result = None;
                    break;
                }
            }
            _ = revoke_ticker.tick() => {
                // Re-ask the gate. A revoked peer loses the live forward; the
                // denial is a close-with-reason so the client's connection breaks
                // instead of hanging.
                if crate::cert_revoked_for(idev.as_ref()) {
                    crate::ui::critical("l2: peer revoked, closing the live stream");
                    revoked_reason = Some(crate::capability::REVOKED_REASON);
                    if let Some(r) = reader.take() { r.abort(); }
                    writer.abort();
                    read_result = None;
                    break;
                }
            }
        }
    }
    // The stream may already be gone (teardown). Remove if still present.
    mux.streams.lock().await.remove(&sid);
    if send_close {
        let close = if let Some(reason) = revoked_reason {
            json!({ "type": "l2-close", "sid": sid, "err": reason })
        } else {
            match read_result {
                Some(Ok(Ok(()))) => json!({ "type": "l2-close", "sid": sid }), // clean FIN
                Some(Ok(Err(e))) => json!({ "type": "l2-close", "sid": sid, "err": e.to_string() }),
                Some(Err(_aborted)) => return, // teardown owns the close; don't double-send
                // Peer FIN or link death: ack a close so the peer reaps its half (a
                // no-op if the transport is already gone).
                None => json!({ "type": "l2-close", "sid": sid }),
            }
        };
        let _ = mux.transport.send_control(&close).await;
    }
}

// ----------------------------------------------------- PERSISTENT PTY SESSIONS --
//
// Issue #4 (disconnects lose progress): a PTY must OUTLIVE the data channel that
// opened it. A link-bound bridge would tie the shell's lifetime to one link, so a
// dropped channel would kill the shell. The session model below decouples them:
//
//   * A `PtySession` owns the shell (child + master + reader/writer threads) and
//     a long-lived task. It is keyed by a STABLE `session id` chosen by the
//     browser, NOT by the per-link sid (which changes on every reconnect).
//   * While ATTACHED, PTY output is framed to the current link's transport+sid
//     AND mirrored into a bounded ring buffer. While DETACHED (channel dropped),
//     output only accrues in the ring (capped: oldest bytes evicted).
//   * On reconnect the browser re-opens with the SAME session id; the acceptor
//     calls `attach`, which rebinds the new transport+sid and REPLAYS the ring,
//     so the user sees the same shell and its missed output (tmux/mosh-style).
//   * Caps: the ring is bounded (`SESSION_BUFFER_CAP`); a detached session is
//     reaped after `SESSION_DETACHED_IDLE` with no reattach; ANY session is
//     reaped after `SESSION_MAX_LIFETIME` regardless. The shell exiting always
//     ends the session immediately.

/// Bytes of recent PTY output retained while detached, for replay on reattach.
/// 256 KiB covers a full-screen TUI redraw plus a scrollback's worth of context
/// without letting an abandoned-but-not-reaped session hoard memory.
pub const SESSION_BUFFER_CAP: usize = 256 * 1024;

/// Terminal-mode reset emitted to the client right AFTER a reattach replay.
/// A TUI that gets cut off mid-run (link drop, then the app dies before it can
/// emit its own disable) leaves the client terminal stuck in mouse-reporting
/// mode: every trackpad move then spews escape codes onto the shell line, which
/// also wedges readline so Ctrl-U / Alt-Backspace stop parsing. Clearing the
/// mouse modes after the replay heals that; a TUI that is STILL alive re-enables
/// the mouse on its next redraw. Deliberately ONLY mouse modes (X10/normal/
/// button/any-motion + SGR + urxvt ext), never cursor-key or keypad modes, so a
/// reattach never disturbs arrow keys.
pub const PTY_REATTACH_RESET: &[u8] = b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l";

/// Scan a PTY output chunk for DEC private-mode SET/RST sequences that
/// affect mouse tracking. Returns (modes_set, modes_reset) from this chunk.
///
/// CSI `ESC [ ? <num> h` = DECSET (enable); `l` = DECRST (disable).
/// Multiple mode numbers separated by `;` are each evaluated.
fn mouse_mode_changes(data: &[u8]) -> (Vec<u16>, Vec<u16>) {
    let mut sets: Vec<u16> = Vec::new();
    let mut resets: Vec<u16> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'\x1b' || i + 3 >= data.len() || data[i + 1] != b'[' || data[i + 2] != b'?' {
            i += 1;
            continue;
        }
        let start = i + 3;
        let mut j = start;
        while j < data.len() && (data[j].is_ascii_digit() || data[j] == b';') {
            j += 1;
        }
        if j > start && j < data.len() && matches!(data[j], b'h' | b'l') {
            let set = data[j] == b'h';
            let nums: &str = std::str::from_utf8(&data[start..j]).unwrap_or("");
            for part in nums.split(';') {
                if let Ok(n) = part.parse::<u16>() {
                    if matches!(n, 1000 | 1002 | 1003 | 1006 | 1015) {
                        if set {
                            if !sets.contains(&n) {
                                sets.push(n);
                            }
                        } else {
                            if !resets.contains(&n) {
                                resets.push(n);
                            }
                        }
                    }
                }
            }
        }
        i = j + 1;
    }
    (sets, resets)
}

/// A detached session (channel dropped, nobody reattached) is reaped after this.
/// Long enough to ride out a mobile network handoff / tab suspend, short enough
/// that a closed laptop does not leave a root shell alive for hours.
pub const SESSION_DETACHED_IDLE: Duration = Duration::from_secs(180);

/// Hard lifetime cap on ANY persistent PTY session, attached or not. A backstop
/// so a wedged or forgotten session cannot live forever.
pub const SESSION_MAX_LIFETIME: Duration = Duration::from_secs(8 * 3600);

/// Where a session sends its PTY output right now: a link's transport + the sid
/// the browser allocated for THIS attach. `None` = detached (buffer only).
struct OutBind {
    transport: Arc<dyn Transport>,
    sid: u32,
}

/// Commands to a session's task: (re)bind output to a new link, detach, or end.
enum SessionCmd {
    Attach {
        transport: Arc<dyn Transport>,
        sid: u32,
    },
    Detach,
    End,
}

/// Handle to one persistent PTY session, stored in the `PtySessions` map. Cloning
/// is cheap (channels + Arcs); the actual shell lives in the spawned task.
#[derive(Clone)]
pub struct PtySessionHandle {
    /// Bytes typed by the user -> PTY master writer thread.
    input_tx: std::sync::mpsc::Sender<Vec<u8>>,
    /// Window-size changes -> PTY master resize.
    resize_tx: mpsc::UnboundedSender<(u16, u16)>,
    /// Attach/detach control -> the session task.
    cmd_tx: mpsc::UnboundedSender<SessionCmd>,
    /// Set once the task observes the shell exit OR a reap, so a stale handle in
    /// the map is recognized as dead and replaced by a fresh spawn.
    dead: Arc<std::sync::atomic::AtomicBool>,
}

impl PtySessionHandle {
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }
    pub fn feed_input(&self, bytes: Vec<u8>) {
        let _ = self.input_tx.send(bytes);
    }
    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.resize_tx.send((cols, rows));
    }
    /// Rebind output to a new link (transport + sid) and replay the buffer.
    pub fn attach(&self, transport: Arc<dyn Transport>, sid: u32) {
        let _ = self.cmd_tx.send(SessionCmd::Attach { transport, sid });
    }
    /// Drop the current binding; output accrues in the ring until the next attach
    /// or the detached-idle reaper fires.
    pub fn detach(&self) {
        let _ = self.cmd_tx.send(SessionCmd::Detach);
    }
    /// End the session now: kill the shell and tear the task down (the explicit
    /// `pty-close` / user-closed path, NOT a transient channel drop).
    pub fn end(&self) {
        let _ = self.cmd_tx.send(SessionCmd::End);
    }
}

/// Process-wide store of persistent PTY sessions, keyed by the browser-chosen
/// stable session id. Lives for the whole `up`/`recv` process so a session
/// survives any number of link drops/reconnects.
#[derive(Default)]
pub struct PtySessions {
    map: Mutex<HashMap<String, PtySessionHandle>>,
}

impl PtySessions {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Look up a LIVE session by id (a dead/exited one is treated as absent so a
    /// re-open spawns fresh).
    pub async fn get_live(&self, id: &str) -> Option<PtySessionHandle> {
        let mut map = self.map.lock().await;
        match map.get(id) {
            Some(h) if !h.is_dead() => Some(h.clone()),
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    /// Insert a freshly spawned session under `id`.
    pub async fn insert(&self, id: String, h: PtySessionHandle) {
        self.map.lock().await.insert(id, h);
    }

    /// Remove a session by id (the reaper / shell-exit path calls this).
    pub async fn remove(&self, id: &str) {
        self.map.lock().await.remove(id);
    }
}

/// Spawn a brand-new persistent PTY session bound to `(transport, sid)`. Returns
/// a handle to store in `PtySessions`; the shell runs in a detached task that
/// outlives the link. `pty_guard` holds the global PTY slot for the session's
/// whole life. On any failure an `l2-close{err}` is sent on the opening link and
/// `None` is returned (nothing to store).
pub async fn spawn_pty_session(
    sessions: Arc<PtySessions>,
    session_id: String,
    transport: Arc<dyn Transport>,
    sid: u32,
    cols: u16,
    rows: u16,
    term: &str,
    argv: Vec<String>,
    pty_guard: PtyGuard,
    // The peer's device key, for the live session's revocation re-check. `None`
    // (no resolved identity) is treated as not-revoked by `cert_revoked_for`.
    idev: Option<[u8; 32]>,
) -> Option<PtySessionHandle> {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use std::io::{Read as _, Write as _};

    let size = PtySize {
        rows: rows.max(1),
        cols: cols.max(1),
        pixel_width: 0,
        pixel_height: 0,
    };
    let pair = match native_pty_system().openpty(size) {
        Ok(p) => p,
        Err(e) => {
            let _ = transport
                .send_control(
                    &json!({ "type": "l2-close", "sid": sid, "err": format!("pty: {e}") }),
                )
                .await;
            return None;
        }
    };
    let mut cmd = CommandBuilder::new(&argv[0]);
    for a in &argv[1..] {
        cmd.arg(a);
    }
    cmd.env(
        "TERM",
        if term.is_empty() {
            "xterm-256color"
        } else {
            term
        },
    );
    // Advertise 24-bit color. opentui-based TUIs (e.g. opencode) downgrade to a
    // 256-color palette when COLORTERM is unset; the web-shell xterm.js renders
    // truecolor fine, so set this to get full-color output (verified: opencode
    // emits 38;2;R;G;B with this set, 38;5;N without).
    cmd.env("COLORTERM", "truecolor");
    cmd.cwd(crate::platform::Paths::home_dir());
    let mut child = match pair.slave.spawn_command(cmd) {
        Ok(c) => c,
        Err(e) => {
            let _ = transport
                .send_control(
                    &json!({ "type": "l2-close", "sid": sid, "err": format!("spawn: {e}") }),
                )
                .await;
            return None;
        }
    };
    drop(pair.slave); // close our copy so the shell owns the only slave
    let master = pair.master;
    let mut reader = match master.try_clone_reader() {
        Ok(r) => r,
        Err(_) => return None,
    };
    let mut writer = match master.take_writer() {
        Ok(w) => w,
        Err(_) => return None,
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
    let (input_tx, wrx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(b) = wrx.recv() {
            if writer.write_all(&b).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let (resize_tx, mut resize_rx) = mpsc::unbounded_channel::<(u16, u16)>();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SessionCmd>();
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let handle = PtySessionHandle {
        input_tx,
        resize_tx,
        cmd_tx,
        dead: dead.clone(),
    };

    // The long-lived session task: it owns the PTY output, the current binding,
    // the replay ring, and the lifetime/idle caps. It outlives every link.
    let sessions_for_task = sessions.clone();
    let session_id_for_task = session_id.clone();
    tokio::spawn(async move {
        let _guard = pty_guard; // freed when the task ends (any exit path)
        let mut bind: Option<OutBind> = Some(OutBind { transport, sid });
        let mut ring: VecDeque<u8> = VecDeque::new();
        let started = Instant::now();
        let mut detached_since: Option<Instant> = None;
        let mut active_mouse_modes: Vec<u16> = Vec::new();
        // 5s tick to enforce the idle/lifetime caps without busy-waiting.
        let mut reaper = tokio::time::interval(Duration::from_secs(5));
        reaper.tick().await; // consume the immediate first tick
        // #235-shape: a dedicated recheck ticker at the shared interval, so the
        // revoke bound is NOT floored by the 5s reaper. The tick IS the cadence;
        // the verdict is re-asked directly. The denial must reach the initiator
        // as a denial (a reason + nonzero exit), never as a clean shell exit.
        let mut revoke_ticker = tokio::time::interval(crate::revoke_recheck_interval());
        revoke_ticker.tick().await; // consume the immediate first tick
        let mut revoked_reason: Option<&'static str> = None;

        loop {
            tokio::select! {
                out = orx.recv() => match out {
                    Some(bytes) => {
                        let (sets, resets) = mouse_mode_changes(&bytes);
                        for m in sets {
                            if !active_mouse_modes.contains(&m) { active_mouse_modes.push(m); }
                        }
                        active_mouse_modes.retain(|m| !resets.contains(m));
                        push_ring(&mut ring, &bytes, SESSION_BUFFER_CAP);
                        if let Some(b) = &bind {
                            for chunk in bytes.chunks(b.transport.max_payload().max(1)) {
                                if b.transport.send_frame(b.sid, 0, chunk).await.is_err() {
                                    // The link died under us; treat as a detach so
                                    // output keeps buffering for a reattach.
                                    detached_since = Some(Instant::now());
                                    bind = None;
                                    break;
                                }
                            }
                        }
                    }
                    None => break, // shell exited
                },
                cmd = cmd_rx.recv() => match cmd {
                    Some(SessionCmd::Attach { transport, sid }) => {
                        // Replay the buffered output to the freshly attached link
                        // so the user sees the shell exactly as it stands now.
                        let snapshot: Vec<u8> = ring.iter().copied().collect();
                        let mp = transport.max_payload().max(1);
                        let mut ok = true;
                        for chunk in snapshot.chunks(mp) {
                            if transport.send_frame(sid, 0, chunk).await.is_err() {
                                ok = false;
                                break;
                            }
                        }
                        // Heal stuck mouse modes from a cut-off TUI, then
                        // restore any modes the live PTY app had active so
                        // the wheel still scrolls after a reconnect.
                        if ok {
                            // Always flush stuck modes first (safety net)
                            if transport.send_frame(sid, 0, PTY_REATTACH_RESET).await.is_err() {
                                ok = false;
                            }
                            // Re-enable modes the PTY app had on before detach
                            for m in &active_mouse_modes {
                                let seq = format!("\x1b[?{m}h");
                                if ok && transport.send_frame(sid, 0, seq.as_bytes()).await.is_err() {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            bind = Some(OutBind { transport, sid });
                            detached_since = None;
                        } else {
                            detached_since = Some(Instant::now());
                            bind = None;
                        }
                    }
                    Some(SessionCmd::Detach) => {
                        bind = None;
                        detached_since = Some(Instant::now());
                    }
                    Some(SessionCmd::End) => break, // explicit close: kill the shell
                    None => break, // all handles dropped (store removed): tear down
                },
                rs = resize_rx.recv() => {
                    if let Some((c, r)) = rs {
                        let _ = master.resize(PtySize { rows: r.max(1), cols: c.max(1), pixel_width: 0, pixel_height: 0 });
                    }
                }
                _ = reaper.tick() => {
                    let lifetime_up = started.elapsed() >= SESSION_MAX_LIFETIME;
                    let idle_up = detached_since
                        .map(|t| t.elapsed() >= SESSION_DETACHED_IDLE)
                        .unwrap_or(false);
                    if lifetime_up || idle_up {
                        break;
                    }
                }
                _ = revoke_ticker.tick() => {
                    // Re-ask the gate. A revoked peer loses the live shell: tell
                    // the terminal, then close with a reason so the initiator
                    // surfaces a nonzero exit rather than a clean one (#223).
                    if crate::cert_revoked_for(idev.as_ref()) {
                        crate::ui::critical("pty: peer revoked, closing the live session");
                        revoked_reason = Some(crate::capability::REVOKED_REASON);
                        if let Some(b) = &bind {
                            let msg = format!("\r\n[filament: {}]\r\n", crate::capability::REVOKED_REASON);
                            let _ = b.transport.send_frame(b.sid, 0, msg.as_bytes()).await;
                        }
                        break;
                    }
                }
            }
        }

        // Teardown (shell exit, reap, revoke, or store removal): kill the shell,
        // tell the currently-attached link (if any) the session ended, drop from
        // the store.
        let _ = child.kill();
        let _ = child.wait();
        dead.store(true, Ordering::Release);
        if let Some(b) = &bind {
            let close = match revoked_reason {
                Some(reason) => json!({ "type": "l2-close", "sid": b.sid, "err": reason }),
                None => json!({ "type": "l2-close", "sid": b.sid }),
            };
            let _ = b.transport.send_control(&close).await;
        }
        sessions_for_task.remove(&session_id_for_task).await;
    });

    sessions.insert(session_id, handle.clone()).await;
    Some(handle)
}

/// Append `bytes` to the replay ring, evicting from the front so it never exceeds
/// `cap`. A single write larger than `cap` keeps only its trailing `cap` bytes
/// (the most recent screen state is what matters for replay).
fn push_ring(ring: &mut VecDeque<u8>, bytes: &[u8], cap: usize) {
    if bytes.len() >= cap {
        ring.clear();
        ring.extend(&bytes[bytes.len() - cap..]);
        return;
    }
    ring.extend(bytes);
    while ring.len() > cap {
        ring.pop_front();
    }
}

// ------------------------------------------------------------- ACCEPTOR side --

/// Decision for an inbound `l2-open`, made synchronously in the event loop
/// BEFORE any await, so the pipe is registered before a data frame for this sid
/// can be processed (closes the early-frame-drop race, design §3.4).
pub enum OpenVerdict {
    /// Accepted: dial this localhost target and relay. Carries the pre-registered
    /// inbound pipe.
    Accept {
        sid: u32,
        host: String,
        port: u16,
        rx: mpsc::Receiver<PipeItem>,
    },
    /// Refused: send l2-close{err} and forget it.
    Deny { sid: u32, err: &'static str },
    /// Not an l2-open / malformed, ignore.
    Ignore,
}

impl Mux {
    /// Handle an inbound L2 *control* message on the acceptor side. `trusted` is
    /// the proof-verified capability flag for this link (the placeholder gate).
    /// Registers the pipe synchronously for an accepted open, then returns the
    /// verdict for the caller to act on (the dial is async and must NOT block the
    /// event loop). Returns `Ignore` for non-l2 control.
    /// `allow_nonloopback`: the caller (main.rs, where the peer's device name is
    /// known) decided this specific non-loopback target is permitted by the
    /// operator's opt-in `l2-allow.json` allowlist. Loopback is always allowed; a
    /// non-loopback host is refused UNLESS this is set, keeping the SSRF default.
    pub async fn accept_control(
        &self,
        v: &Value,
        trusted: bool,
        allow_nonloopback: bool,
    ) -> OpenVerdict {
        match v["type"].as_str() {
            Some("l2-open") => {
                // Reject a missing OR out-of-range sid (wire_sid never truncates)
                // rather than defaulting/wrapping into a forged is_l2_sid value.
                let Some(sid) = wire_sid(v) else {
                    return OpenVerdict::Ignore;
                };
                if !is_l2_sid(sid) {
                    return OpenVerdict::Ignore; // not in the high half, not ours
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
                let port = v["rport"]
                    .as_u64()
                    .or_else(|| v["port"].as_u64())
                    .unwrap_or(0) as u16;
                if port == 0 {
                    return OpenVerdict::Deny {
                        sid,
                        err: "bad port",
                    };
                }
                // ---- SSRF defense: localhost-only by default ----
                // Stricter than is_private_addr (which ALLOWS LAN/RFC1918): the
                // dial target must resolve to loopback. A non-loopback host is
                // refused UNLESS the caller's opt-in per-device allowlist
                // (l2-allow.json) authorized this exact target (`allow_nonloopback`).
                if !host_is_loopback(&host) && !allow_nonloopback {
                    return OpenVerdict::Deny {
                        sid,
                        err: "non-loopback denied (not in l2-allow.json)",
                    };
                }
                // H-1 (DoS): cap concurrent streams per link. A flaky/hostile
                // paired device can otherwise flood `l2-open` and exhaust
                // sockets/threads. We drop the `accepted` marker so the same sid
                // can be retried once others free up.
                if self.at_stream_cap().await {
                    self.accepted.lock().await.remove(&sid);
                    return OpenVerdict::Deny {
                        sid,
                        err: "too many streams",
                    };
                }
                // Collision-safe register: if the peer named a sid already live
                // on this link (its own forward/pty/mount), REFUSE rather than
                // overwrite. Drop the `accepted` marker so the sid isn't wedged.
                let Some(rx) = self.register(sid).await else {
                    self.accepted.lock().await.remove(&sid);
                    return OpenVerdict::Deny {
                        sid,
                        err: "sid in use",
                    };
                };
                OpenVerdict::Accept {
                    sid,
                    host,
                    port,
                    rx,
                }
            }
            Some("l2-close") => {
                // wire_sid (not `as u32`): a wrapped/oversized close sid must not
                // be truncated into a live sid and tear down the wrong stream.
                if let Some(sid) = wire_sid(v) {
                    self.on_close(sid, v["err"].as_str()).await;
                }
                OpenVerdict::Ignore
            }
            _ => OpenVerdict::Ignore,
        }
    }

    /// Acceptor: dial the localhost target for an accepted open and relay. Sends
    /// l2-open-ack on success, l2-close{err} on dial failure. Runs as its own
    /// task (the event loop spawns it) so the dial never blocks routing.
    pub async fn dial_and_serve(
        self: Arc<Self>,
        sid: u32,
        host: String,
        port: u16,
        rx: mpsc::Receiver<PipeItem>,
        idev: Option<[u8; 32]>,
    ) {
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(sock) => {
                let _ = sock.set_nodelay(true);
                // l2-open-ack is mandatory (design §3.4/O2): it tells the
                // initiator the stream is live. credit-in-ack is the follow-up
                // (TODO(credits)); 0 here means "no per-stream window yet".
                let _ = self
                    .transport
                    .send_control(&json!({ "type": "l2-open-ack", "sid": sid, "credit": 0 }))
                    .await;
                serve_stream(self.clone(), sid, sock, rx, true, None, idev).await;
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
/// deliberately NOT performed here, the default contract is localhost-only and
/// a name that isn't "localhost" is treated as non-loopback.)
fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

// ------------------------------------------------------------ INITIATOR side --

/// Holds the signaling client + WebRTC peer that back a brought-up link so the
/// CALLER decides their fate. A long-lived consumer (netcat/forward) calls
/// `forget()` to keep the link alive for the process lifetime (byte-identical to
/// the old `std::mem::forget`). A short-lived consumer (the shell bootstrap)
/// calls `close().await` to TEAR THE LINK DOWN before opening a second link to
/// the same device, otherwise the acceptor sees two same-device peers at once
/// and its C6 supersede/adopt logic churns (one link gets dropped mid-use).
pub struct LinkGuard {
    sio: Option<filament_signal::Client>,
    peer: Option<Arc<Peer>>,
}

impl LinkGuard {
    /// Keep the link alive forever (leaks sio+peer, as the long-lived tunnels
    /// want). Consumes the guard.
    pub(crate) fn forget(mut self) {
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
/// and prove our identity (pair-proof) so its `up`/`recv` marks us trusted,
/// which is what unlocks the acceptor's capability gate. Returns the ready
/// Transport, the event receiver, and a `LinkGuard` the caller must either
/// `forget()` (keep alive) or `close().await` (tear down).
/// Prove that the peer on this link is the device the caller NAMED.
///
/// Dialing with the fleet secret authenticates the link as "someone in this
/// fleet". Turning that into "this is `expected`" needs the owner-signed
/// certificate, bound to this link, and the device key it names has to resolve to
/// the local record `expected` refers to. Anything else is refused: a same-fleet
/// device answering to the wrong name is exactly the case this exists to stop.
async fn verify_fleet_identity(
    t: &Arc<dyn Transport>,
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    expected: &str,
) -> Result<()> {
    let cb = t
        .channel_binding()
        .ok_or_else(|| anyhow!("cannot verify '{expected}': this link exposes no channel binding"))?;
    let owner = crate::fleet::my_owner_pub()
        .ok_or_else(|| anyhow!("cannot verify '{expected}': this device holds no owner key"))?;
    let hello = crate::fleet::make_hello(&cb, &crate::display_name())?;
    t.send_control(&hello).await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .map_err(|_| anyhow!("'{expected}' never presented a certificate"))?
            .ok_or_else(|| anyhow!("link closed before '{expected}' presented a certificate"))?;
        let Ev::Control(_, v) = &ev else { continue };
        if v["type"].as_str() != Some(crate::fleet::HELLO) {
            continue;
        }
        let proven = crate::fleet::verify_hello(v, &cb, &owner, crate::identity::now_secs())?;
        let name = crate::device_name_for_pub(&proven.device_pub);
        if name.as_deref().map(|n| n.eq_ignore_ascii_case(expected)) != Some(true) {
            bail!(
                "refusing: the device answering as '{expected}' proved a different identity ({}). Nothing was sent.",
                name.as_deref().unwrap_or("unknown device")
            );
        }
        return Ok(());
    }
}

pub(crate) async fn bring_up_to_known(
    server: &str,
    peer_name: &str,
    relay: bool,
    role: &'static str,
) -> Result<(
    Arc<dyn Transport>,
    mpsc::UnboundedReceiver<Ev>,
    LinkGuard,
    crate::diag::Attempt,
)> {
    // A paired device has its own secret. A FLEET sibling is indexed WITHOUT one
    // (design-fleet-automesh.md), so fall back to the fleet secret, which is what
    // the daemon dials such peers with. `fleet_mode` matters at the return sites:
    // that secret proves MEMBERSHIP, not identity, so the certificate has to be
    // checked before the link is handed to the caller.
    let (secret, fleet_mode) = match crate::devices_load()
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(peer_name))
        .map(|(_, s)| s)
    {
        Some(s) => (s, false),
        None => {
            // Ask the daemon to broker a PRIVATE rendezvous before falling back
            // to the fleet secret. Same mechanism `send --to` uses (WORK-STATE
            // 1h), which took sibling send from ~50% to 58/58: the fleet secret
            // below meets the peer on the channel EVERY sibling sits on, and the
            // dial then has to work out which of the answering peers is the
            // target. A brokered secret has exactly two parties on it, so that
            // race does not get safer, it stops existing.
            //
            // Condition mirrors send_cmd's: only a fleet-indexed name, only when
            // this device is in a fleet. A typo must not cost a daemon round
            // trip, and a paired device never reaches here at all.
            //
            // fleet_mode is FALSE for a brokered secret, also matching send_cmd,
            // because the secret travelled over a link the daemon had ALREADY
            // verified by certificate and so identifies the peer by itself. The
            // daemon holds up that end: it brokers only over a link with a
            // Proven identity binding (`warm_link_for`), never on presence, so a
            // stranger on the fleet channel cannot obtain one.
            let brokered = if crate::fleet_indexed_name(peer_name) && crate::fleet::rv().is_some() {
                crate::ctl::try_fleet_rendezvous(peer_name).await
            } else {
                None
            };
            match brokered {
                Some(sec) => {
                    crate::ui::debug(&format!(
                        "fleet: daemon brokered a private rendezvous with '{peer_name}' for {role}"
                    ));
                    (sec, false)
                }
                None => match (crate::fleet_indexed_name(peer_name), crate::fleet::rv()) {
                    (true, Some(rv)) => (rv, true),
                    _ => bail!("no known device named '{peer_name}', run `filament add` first (see `filament devices`)"),
                },
            }
        }
    };
    let channel = crate::channel_of(&secret);

    // Establishment telemetry: a connect span, peer tagged by SHORT HASH (never
    // the petname). The Attempt is returned to the caller so it can record the
    // L2Open round trip and the final `up`. We start in Signaling (socket + the
    // first `welcome`); the loop drives the phase transitions below.
    let mut diag =
        crate::diag::Attempt::new(server, &crate::diag::peer_hash_from_secret(&secret), role);
    // Latch so we record the Presence->Establishing transition exactly once
    // (the loop dequeues a candidate every time `peer` is idle, but the connect
    // lifecycle's "establishing" begins at the FIRST candidate).
    let mut entered_establishing = false;

    let cfg = net::fetch_config(server).await?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let mut sio = net::connect_signaling(server, tx.clone()).await?;

    let my_uid = crate::mk_uid("l2");
    // A solo room keeps strangers out; presence-channel subscription is how we
    // actually find the known device (same as `--to` identity mode).
    let solo = format!("l2-{}", crate::fresh_secret());
    let join_payload =
        json!({ "room": solo, "uid": my_uid.clone(), "name": crate::display_name() });
    sio.emit("join", join_payload.clone()).await.ok();
    // NOTE: subscribe is emitted on Ev::Welcome (below), not here, `welcome` is
    // the proof the socket.io connection is fully established, so the subscribe
    // can't be lost in the connect->emit race that intermittently left the client
    // unsubscribed and "waiting for known device" forever (harness finding).
    //
    // The `join` ABOVE has the SAME connect->emit race: fired the instant
    // `connect_signaling` returns, it can land before the socket.io connection is
    // fully ready and be silently dropped, the server then never runs `_do_join`,
    // never emits `welcome`, and this loop waits for a Welcome that never comes,
    // stranding `filament shell --ssh` in "waiting for known device" (~30% of attempts in
    // the isolated repro). So we RE-EMIT join on the same cadence as the
    // re-subscribe below until Welcome lands (idempotent: a repeat join to the
    // same solo room is a no-op server-side once it took).

    let mut my_id: Option<String> = None;
    let mut peer: Option<Arc<Peer>> = None;
    let mut peer_uid: Option<String> = None;
    let mut peer_present = false;
    let mut generation: u32 = 0;
    // Ghost tolerance: the channel can hold DEAD sids (a SIGKILL'd process
    // lingers until the server's ping-timeout) and WRONG peers (our own up
    // subscribes the same pair channel). Locking onto the first known-peer
    // forever was the dominant stall. Instead: one candidate AT A TIME (a
    // parallel race glares, proven, see multicandidate-attempt.patch), a
    // short per-candidate timer, and rotation through everything seen.
    let mut queue: VecDeque<(String, Option<String>, bool)> = VecDeque::new();
    // Per-candidate establish budget for the INTERACTIVE L2/ssh path: how long a
    // single candidate gets to complete (WebRTC + direct-QUIC race) before it is
    // declared Stuck and we rotate to the next. This is a TIMEOUT, not the
    // connect time: a healthy candidate completes in 1.7-3.3s regardless, so a
    // larger budget never slows a good path, it only stops abandoning a real one
    // too early.
    //
    // It was briefly tightened to 4s chasing Tailscale's sub-5s connect, but 4s
    // is BELOW the time a legitimately slow-but-real ICE needs (~5s, e.g. a
    // cross-NAT path that nominates a srflx/relay pair): the budget fired before
    // the real candidate finished, every rotation got cut at 4s, and the link
    // never came up ("establishment timed out", reproduced live as a consistent
    // pop-os -> do-vm failure that 7s/12s established cleanly). Back to 7s, which
    // clears the real ICE time with margin; field-overridable via
    // FILAMENT_L2_CANDIDATE_SECS.
    let candidate_secs: u64 = std::env::var("FILAMENT_L2_CANDIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(7);
    // Item 3: the L2 initiator races a DIRECT-QUIC dial against WebRTC. On
    // KnownPeer we bind a quinn endpoint + advertise our candidates (mirrors
    // `start_direct` in main.rs); when the peer's transport-offer arrives we
    // consume this endpoint into the race. UNCONDITIONAL here: `bring_up_to_known`
    // only ever serves L2 (netcat/ssh/forward), which always wants direct, and
    // `filament shell --ssh`/`netcat` do NOT set FILAMENT_L2 in their own env, so gating
    // on `direct_enabled()` would kill the direct dial on the live path. main.rs
    // gates because it ALSO serves file transfer; this function never does.
    let mut endpoint: Option<quinn::Endpoint> = None;
    // Candidates gathered once at first bind; re-advertised to each new
    // candidate peer we rotate to (the endpoint accepts from any of them,
    // the QUIC race is pair-secret-authenticated either way).
    let mut direct_cands: Option<(Vec<String>, Option<String>)> = None;
    // The acceptor re-sends its transport-offer (a late initiator can miss the
    // first). Race only the FIRST offer we get; later re-sends are duplicates.
    let mut direct_racing = false;

    let spawn_timer = |pid: String, g: u32| {
        let tx = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(candidate_secs)).await;
            let _ = tx.send(Ev::Stuck(pid, g));
        });
    };

    // Distinct wording for the shell-auth pre-flight so the two sequential
    // bring-ups of `filament shell --ssh` (the bootstrap link, then the netcat data link)
    // do not read as a flap/retry of one connection. "bootstrap" has its own
    // wording; "reconnect" is silent (post-warm resume check — the link was
    // already up; re-reporting it after a clean logout is noise).
    let silent = role.starts_with("reconnect");
    if !silent {
        crate::ui::say(&match role {
            "bootstrap" => format!("filament: authenticating with '{peer_name}'..."),
            _ => format!("\rfilament: waiting for known device '{peer_name}'..."),
        });
    }

    // Presence re-subscribe cadence: while we have NOT yet discovered a candidate
    // (empty queue, no live peer), re-emit the ack'd subscribe every ~2s. This
    // recovers the inverse of the ack-roster race, the acceptor that subscribes
    // AFTER us, whose single async `known-peer` push to us is lost. The `up`
    // acceptor gets this self-healing free from its `sync` tick; the one-shot L2
    // initiator needs it explicitly or a lost push strands it in "presence"
    // forever. Cheap (one emit) and idempotent, and it STOPS the instant a
    // candidate is queued/dialing, so a healthy connect never re-subscribes.
    let mut resubscribe = tokio::time::interval(Duration::from_millis(2000));
    resubscribe.tick().await; // consume the immediate first tick (we just subscribed on Welcome)
    // How many re-join ticks we've waited with NO Welcome. rust_socketio's
    // websocket client occasionally finishes `.connect().await` in a state where
    // it can SEND but silently never DELIVERS inbound events to our handlers: the
    // server receives our `join` (and re-emits `welcome` on every retry, verified
    // in the backend telemetry) but this loop never sees `Ev::Welcome`, so it
    // hangs in "waiting for known device" no matter how many times we re-join the
    // SAME dead socket (the residual ~30% rapid-`ssh` failure). Re-emitting can't
    // fix a socket that won't receive, so after a couple of silent ticks we tear
    // the socket DOWN and dial a FRESH one (reconnect_signaling) on the same `tx`.
    let mut welcome_silent_ticks: u32 = 0;

    // Heartbeat so a slow establish never reads as a silent hang: every 7s while
    // still connecting, emit elapsed progress (skipped for `doctor`, which renders
    // its own per-phase ladder). The overall deadline lives at the call site.
    let connect_started = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(7));
    heartbeat.tick().await; // consume the immediate first tick

    loop {
        // One candidate at a time: start the next attempt whenever idle.
        if peer.is_none() {
            if let Some((pid, uid, candidate_present)) = queue.pop_front() {
                peer_present = candidate_present;
                // A candidate appeared and we are dialing it: presence is done,
                // we are now in the Establishing (WebRTC + direct-QUIC race)
                // phase. Latched so re-dials of later candidates don't re-emit.
                if !entered_establishing {
                    diag.enter(crate::diag::Phase::Establishing);
                    entered_establishing = true;
                }
                let Some(mine) = my_id.clone() else {
                    eprintln!("role election deferred for {pid}: local session ID unavailable");
                    continue;
                };
                let polite = match uid.as_deref() {
                    Some(peer_uid) => net::polite_role(&my_uid, peer_uid, &mine, &pid)?,
                    None => {
                        let source = if peer_present {
                            "presence"
                        } else {
                            "absent-roster"
                        };
                        net::polite_role_legacy(&my_uid, None, &mine, &pid, source, peer_present)?
                    }
                };
                generation += 1;
                spawn_timer(pid.clone(), generation);
                let p = Peer::connect(
                    pid.clone(),
                    my_uid.clone(),
                    polite,
                    cfg.ice_servers.clone(),
                    relay,
                    sio.clone(),
                    tx.clone(),
                    generation,
                )
                .await?;
                peer_uid = uid;
                peer = Some(p);

                // Item 3: also start a DIRECT-QUIC attempt racing the WebRTC
                // dial. Bind once, advertise to whichever candidate is current
                // (mirrors `start_direct`); the peer's own offer drives the
                // race (handled in Ev::Signal below). Gated on
                // `direct_enabled()` — when `FILAMENT_DIRECT=0` (e.g. macOS
                // hyperkit CI), the L2 establish skips direct-quic entirely and
                // uses WebRTC (srflx / relay candidates), exercising the relay
                // fallback path.
                if !direct_racing && crate::direct::direct_enabled() {
                    if endpoint.is_none() {
                        match crate::direct::bind_endpoint() {
                            Ok((ep, port)) => {
                                direct_cands =
                                    Some(crate::direct::gather_candidates(server, port).await);
                                endpoint = Some(ep);
                                // TRACE, direct-offer detail.
                                crate::ui::trace(&format!(
                                    "filament: DIRECT-OFFER sent to '{peer_name}', port {port}"
                                ));
                            }
                            Err(e) => {
                                crate::ui::trace(&format!(
                                    "filament: direct disabled (endpoint bind failed: {e}), WebRTC only"
                                ));
                            }
                        }
                    }
                    if endpoint.is_some() {
                        if let Some((c, server_public)) = &direct_cands {
                            // #237: advertise the address adopted on the server's
                            // say-so (the peer dials it and may have to name it)
                            // and our protocol version (gates the observed-address
                            // exchange on both sides).
                            let mut offer = json!({ "type": "transport-offer", "v": 1, "proto": 2, "addrs": c });
                            if let Some(s) = server_public {
                                offer["server_public"] = json!(s);
                            }
                            sio.emit("signal", json!({ "to": pid, "data": offer }))
                                .await
                                .ok();
                        }
                    }
                }
            }
        }
        let ev = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => ev,
                None => break,
            },
            _ = heartbeat.tick() => {
                if role != "doctor" {
                    crate::ui::say(&format!(
                        "filament: still reaching '{peer_name}'... ({}s)",
                        connect_started.elapsed().as_secs()
                    ));
                }
                continue;
            }
            _ = resubscribe.tick() => {
                if my_id.is_none() {
                    // No Welcome yet. Re-emit the `join` once (it may have raced the
                    // socket-ready and been dropped server-bound); but if the socket
                    // stays silent across a couple of ticks the socket itself is
                    // RECEIVE-dead, so dial a fresh one and re-join on it.
                    welcome_silent_ticks += 1;
                    if welcome_silent_ticks >= 2 {
                        welcome_silent_ticks = 0;
                        if let Ok(fresh) = net::reconnect_signaling(server, tx.clone()).await {
                            let _ = sio.disconnect().await;
                            sio = fresh;
                        }
                    }
                    sio.emit("join", join_payload.clone()).await.ok();
                } else if peer.is_none() && queue.is_empty() {
                    // Welcome landed but no candidate found yet: re-subscribe so a
                    // lost `known-peer` push / a late-appearing acceptor is still
                    // discovered. Stops the instant a candidate is queued/dialing.
                    net::subscribe_with_ack(&sio, vec![channel.clone()], tx.clone()).await;
                }
                continue;
            }
        };
        match ev {
            Ev::Welcome(v) => {
                my_id = v["id"].as_str().map(|s| s.to_string());
                // Signaling is live (socket + welcome); we now subscribe and wait
                // for the known device to appear, that is the Presence phase.
                diag.enter(crate::diag::Phase::Presence);
                // Subscribe now that the connection is confirmed (see the note at
                // the join site). DETERMINISTIC discovery: emit-with-ack and read
                // the roster the server returns synchronously, so a known device
                // already present is found even if its one-shot async `known-peer`
                // push is lost (the dominant presence stall, see
                // `net::subscribe_with_ack`). The periodic re-subscribe below
                // covers the inverse race (the acceptor appearing AFTER us).
                net::subscribe_with_ack(&sio, vec![channel.clone()], tx.clone()).await;
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
                // sshd, the local daemon answering as the remote device.
                if crate::is_self_uid(&my_uid, v["uid"].as_str()) {
                    continue;
                }
                // Queue every distinct sid; the loop top rotates through them.
                if peer.as_ref().is_some_and(|p| p.id == pid)
                    || queue.iter().any(|(q, _, _)| *q == pid)
                {
                    continue;
                }
                queue.push_back((pid, v["uid"].as_str().map(|s| s.to_string()), true));
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
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        // #237: the initiated race only runs the observed-address
                        // exchange when the PEER's offer says it speaks it; the
                        // peer makes the same decision from OUR offer (we always
                        // advertise proto 2), so both ends skip or both run.
                        let peer_proto = data["proto"].as_u64().unwrap_or(1).clamp(1, 255) as u8;
                        let exchange = peer_proto >= 2;
                        // The L2 initiator has no fallback to attribute, and
                        // does not track the peer's claimed server-asserted
                        // address (dial-tracking is unused here, held so the
                        // shared race keeps a single signature).
                        let l2_dialed = Arc::new(AtomicBool::new(false));
                        // DEBUG, resilience/direct internal (racing a direct path).
                        crate::ui::debug(&format!(
                            "filament: got transport-offer ({} cand), racing direct-quic",
                            peer_cands.len()
                        ));
                        let secret = secret.clone();
                        let pid = v["from"].as_str().unwrap_or_default().to_string();
                        let peer_uid_for_race = match peer_uid.clone() {
                            Some(value) => value,
                            None => {
                                eprintln!("direct role election deferred for {pid}: no peer UID");
                                continue;
                            }
                        };
                        let my_uid_for_race = my_uid.clone();
                        let Some(my_id_for_race) = my_id.clone() else {
                            eprintln!(
                                "direct role election deferred for {pid}: local session ID unavailable"
                            );
                            continue;
                        };
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            if let Some(t) = crate::direct::race_connect_labeled(
                                ep,
                                peer_cands,
                                &secret,
                                pid.clone(),
                                my_uid_for_race,
                                peer_uid_for_race,
                                my_id_for_race,
                                tx.clone(),
                                "direct-quic",
                                exchange,
                                None,
                                l2_dialed,
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
                // subscribes it too, plus lingering dead sids), a stray offer
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
                            pid,
                            my_uid.clone(),
                            true,
                            cfg.ice_servers.clone(),
                            relay,
                            sio.clone(),
                            tx.clone(),
                            generation,
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
                // `verified_name`, its pair-secret MAC already proved who we are,
                // so the cap gate is satisfied WITHOUT a pair-proof. We deliberately
                // do NOT replicate the ChannelReady proof here: that MAC is built
                // from the WebRTC DTLS fingerprints, which a direct QUIC link does
                // not have, and the acceptor's direct link (`peer: None`) has none
                // to verify against. (design-l2-direct-ladder.md §NOTE: pre-trust
                // OR pair-proof, we confirmed pre-trust holds for the L2 acceptor.)
                // INFO, tunnel established (with its route label). Silent for the
                // bootstrap pre-flight (internal; the data link reports the route)
                // and for reconnect roles (post-warm resume noise suppression).
                if !role.starts_with("reconnect") && role != "bootstrap" {
                    crate::ui::debug(&format!(
                        "\rfilament: tunnel up to '{peer_name}' (route: {route})"
                    ));
                }
                // Transport is up: the Establishing race is won. Record Ready;
                // the caller records the L2Open round trip and the final `up`.
                diag.enter(crate::diag::Phase::Ready);
                // The WebRTC `peer` is now superfluous; the guard owns it (its
                // teardown/forget semantics are unchanged, no extra teardown).
                let guard = LinkGuard {
                    sio: Some(sio),
                    peer: peer.take(),
                };
                // The fleet secret got us CONNECTED to a fleet member. It does not
                // say WHICH one: every sibling sits on the same channel, so a peer
                // answering to this name merely ASSERTED it. Prove it with the
                // certificate before the caller moves any bytes, or
                // `send --to laptop` could hand the file to whichever fleet device
                // answered first. Fails closed on a transport with no channel
                // binding, because there is nothing to bind the proof to.
                if fleet_mode {
                    verify_fleet_identity(&t, &mut rx, peer_name).await?;
                }
                return Ok((t, rx, guard, diag));
            }
            Ev::Stuck(pid, g) => {
                // Per-candidate timer (or the 15s watchdog) fired for the
                // CURRENT attempt: drop it and rotate. The sid goes to the
                // back of the queue, a slow-but-real peer gets retried, a
                // ghost just cycles until the server evicts it.
                if g == generation && peer.as_ref().is_some_and(|p| p.id == pid) {
                    let p = peer.take().unwrap();
                    p.mark_closed();
                    tokio::spawn(async move { p.close().await });
                    // The per-candidate establish budget fired: this candidate
                    // wedged and we rotate. Record a stall (the "burns the budget
                    // then succeeds on retry" signal we are hunting).
                    diag.stall(crate::diag::Phase::Establishing, candidate_secs * 1000);
                    crate::ui::debug("filament: candidate unresponsive, rotating");
                    queue.push_back((pid, peer_uid.take(), peer_present));
                }
            }
            Ev::ChannelReady(pid, t) if peer.as_ref().is_some_and(|p| p.id == pid) => {
                // Prove identity so the peer's up/recv marks this link trusted,
                // the acceptor's capability gate keys on exactly that.
                if let Some(p) = &peer {
                    if let Some((my_fp, their_fp)) = p.fingerprints().await {
                        let mac = crate::proof_for(
                            &secret,
                            &my_uid,
                            &my_uid,
                            peer_uid.as_deref().unwrap_or(""),
                            &my_fp,
                            &their_fp,
                        );
                        t.send_control(&json!({ "type": "pair-proof", "mac": mac }))
                            .await?;
                    }
                }
                // Hand sio + peer to the caller via a guard: a long-lived tunnel
                // `forget()`s it (keep alive); the bootstrap `close().await`s it
                // (tear down before the second link).
                if !role.starts_with("reconnect") && role != "bootstrap" {
                    crate::ui::say(&format!("filament: tunnel up to '{peer_name}'"));
                }
                // Transport is up via WebRTC: Establishing race won. Record Ready;
                // the caller records the L2Open round trip and the final `up`.
                diag.enter(crate::diag::Phase::Ready);
                let guard = LinkGuard {
                    sio: Some(sio),
                    peer: peer.take(),
                };
                // The fleet secret got us CONNECTED to a fleet member. It does not
                // say WHICH one: every sibling sits on the same channel, so a peer
                // answering to this name merely ASSERTED it. Prove it with the
                // certificate before the caller moves any bytes, or
                // `send --to laptop` could hand the file to whichever fleet device
                // answered first. Fails closed on a transport with no channel
                // binding, because there is nothing to bind the proof to.
                if fleet_mode {
                    verify_fleet_identity(&t, &mut rx, peer_name).await?;
                }
                return Ok((t, rx, guard, diag));
            }
            Ev::PcState(pid, s) if s == "failed" || s == "closed" => {
                // Was fatal; now just rotate, the overall command timeout
                // (or the user) bounds how long we keep trying.
                if peer.as_ref().is_some_and(|p| p.id == pid) {
                    let p = peer.take().unwrap();
                    p.mark_closed();
                    tokio::spawn(async move { p.close().await });
                    crate::ui::debug(&format!("filament: connection {s}, rotating"));
                    queue.push_back((pid, peer_uid.take(), peer_present));
                }
            }
            _ => {}
        }
    }
    diag.fail("signaling ended before a data channel came up");
    Err(anyhow!("signaling ended before a data channel came up"))
}

// ------------------------------------------------------------- DOCTOR PROBE --
//
// `filament doctor <device>` drives this: an "establish then drop" probe that
// runs the EXACT same bring-up as netcat (`bring_up_to_known` with role
// "doctor"), opens one L2 stream so the L2Open round trip is exercised, then
// IMMEDIATELY tears the link down. It never opens a shell or moves payload. The
// point is to surface WHERE establishment is slow or stalls, using the same
// `Attempt` instrumentation (phases + budgets) a real connect uses, so the
// ladder a probe prints matches what a live ssh would have hit.

/// The result of one `establish_probe`: the per-phase ladder (reused verbatim
/// from the `Attempt`), the total span time, and the terminal verdict.
pub struct ProbeOutcome {
    /// Per-phase timings, in completion order (signaling, presence, ...). Each
    /// carries its over-budget flag, computed by `diag::over_budget`.
    pub timings: Vec<crate::diag::PhaseTiming>,
    /// Total establish time, signaling start to link usable.
    pub total_ms: u64,
    /// True iff the link came up. On `false`, `failed_phase` says where it died.
    pub established: bool,
    /// On failure, the phase the bring-up was IN when it gave up.
    pub failed_phase: Option<crate::diag::Phase>,
    /// On failure, the error string.
    pub error: Option<String>,
    /// On success, the path the probe link actually took (interface, address
    /// class, endpoints) - so `filament doctor` shows the route in the same fine
    /// detail as `filament reach`. `None` when the link never came up.
    pub path: Option<crate::net::PathInfo>,
}

/// Establish a link to `peer` exactly as netcat would, then drop it. Returns the
/// per-phase timings + verdict. Reuses `bring_up_to_known` (role "doctor"), so
/// the phases/budgets are identical to a real connect, and cleans up BOTH the
/// link (LinkGuard::close) and the mux (no leaked streams/pumps).
pub async fn establish_probe(server: &str, peer: &str, relay: bool) -> Result<ProbeOutcome> {
    // Overall safety bound so a wedged candidate cannot hang the probe forever
    // (the per-candidate rotation already re-races inside bring_up_to_known; this
    // is the outer wall). Generous: a slow-but-real ICE lands around 5s and we
    // want to OBSERVE that, not abort it prematurely. Overridable for the field.
    let probe_secs: u64 = std::env::var("FILAMENT_DOCTOR_PROBE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30);
    let deadline = std::time::Duration::from_secs(probe_secs);

    match tokio::time::timeout(deadline, bring_up_to_known(server, peer, relay, "doctor")).await {
        Ok(Ok((t, rx, guard, mut diag))) => {
            // The link is up (Ready recorded). Exercise the L2Open round trip the
            // same way netcat does: pump inbound events, open one stream (sends
            // l2-open), record `up`. We do NOT wait on payload; the open is the
            // last establishment rung we care about.
            let mux = Mux::new(t);
            let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

            diag.enter(crate::diag::Phase::L2Open);
            // rport is irrelevant for the timing: the acceptor dials localhost:0
            // and refuses, but the l2-open / l2-close round trip is what we time.
            // Use a benign port and tear the stream down immediately afterwards.
            let probe_rport: u16 = 9; // discard
            let (sid, _rx_pipe) = open_stream(&mux, probe_rport).await?;
            diag.up("tunnel", "datachannel-or-direct");

            // Capture the path BEFORE teardown: the transport (direct) or the
            // guard's webrtc peer (relay) still holds the live endpoints here.
            let path = Some(
                crate::net::describe_path(mux.transport().as_ref(), guard.peer.as_deref()).await,
            );

            // Tear DOWN, no leak: drop the stream, tell the peer, stop the pump,
            // and close the link (peer + signaling), so the acceptor reaps us.
            mux.drop_stream(sid).await;
            let _ = mux
                .transport()
                .send_control(&json!({ "type": "l2-close", "sid": sid }))
                .await;
            mux.shutdown_all().await;
            pump.abort();
            guard.close().await;

            Ok(ProbeOutcome {
                timings: diag.timings().to_vec(),
                total_ms: diag.total_ms(),
                established: true,
                failed_phase: None,
                error: None,
                path,
            })
        }
        Ok(Err(e)) => {
            // bring_up_to_known recorded `fail` on its (now-consumed) Attempt and
            // wrote the partial ladder to the JSONL. Read it back so the verdict
            // can name where it died, the SAME timings a live connect recorded.
            let (timings, failed_phase) = match crate::diag::latest_span_ladder() {
                Some((t, p)) => (t, Some(p)),
                None => (Vec::new(), None),
            };
            Ok(ProbeOutcome {
                timings,
                total_ms: 0,
                established: false,
                failed_phase,
                error: Some(e.to_string()),
                path: None,
            })
        }
        Err(_elapsed) => {
            // The outer wall fired: the bring-up is still running (the Attempt was
            // never returned). Recover whatever ladder it logged so far.
            let (timings, failed_phase) = match crate::diag::latest_span_ladder() {
                Some((t, p)) => (t, Some(p)),
                None => (Vec::new(), None),
            };
            Ok(ProbeOutcome {
                timings,
                total_ms: probe_secs * 1000,
                established: false,
                failed_phase,
                error: Some(format!("establishment timed out after {probe_secs}s")),
                path: None,
            })
        }
    }
}

/// Drive the initiator's inbound event pump: route L2 control/data into the mux
/// and tear everything down on data-channel death. The initiator never accepts
/// inbound opens (it allocates ids); an l2-open-ack is delivered to the stream as a
/// liveness marker so warm-reuse verification passes even for a client-speaks-first
/// protocol (see `Mux::on_open_ack`).
async fn pump_initiator(mut rx: mpsc::UnboundedReceiver<Ev>, mux: Arc<Mux>) {
    while let Some(ev) = rx.recv().await {
        match ev {
            Ev::Control(_pid, v) => match v["type"].as_str() {
                Some("l2-close") => {
                    if let Some(sid) = wire_sid(&v) {
                        mux.on_close(sid, v["err"].as_str()).await;
                    }
                }
                Some("l2-open-ack") => {
                    if let Some(sid) = wire_sid(&v) {
                        mux.on_open_ack(sid).await;
                    }
                }
                Some("mount-open-ack") | Some("pty-open-ack") => {
                    if let Some(sid) = wire_sid(&v) {
                        let mut ack_map = mux.open_ack_tx.lock().await;
                        if let Some(tx) = ack_map.remove(&sid) {
                            let _ = tx.send(OpenOutcome::Opened(v.clone()));
                        }
                    }
                }
                _ => {}
            },
            Ev::Chunk(_pid, sid, _offset, data) if is_l2_sid(sid) => {
                mux.on_frame(sid, data).await;
            }
            Ev::PcState(_, s) if s == "failed" || s == "closed" || s == "disconnected" => {
                crate::ui::debug(&format!("filament: tunnel {s}, closing streams"));
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
async fn open_stream(
    mux: &Arc<Mux>,
    rport: u16,
) -> Result<(u32, mpsc::Receiver<PipeItem>)> {
    let sid = mux.alloc_sid();
    // alloc_sid hands out a fresh sid, so register never collides here; guard
    // anyway so a refusal can never be silently ignored (which would re-open the
    // collision hole if this path ever shared sid space).
    let rx = mux
        .register(sid)
        .await
        .ok_or_else(|| anyhow!("l2 open: sid {sid:#x} already in use"))?;
    // The dial target is ALWAYS 127.0.0.1 in production (localhost-only is the
    // contract). FILAMENT_L2_DIALHOST is a TEST-ONLY override so the SSRF gate
    // can drive a non-loopback open and observe the acceptor refuse it.
    let host = std::env::var("FILAMENT_L2_DIALHOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    mux.transport
        .send_control(&json!({ "type": "l2-open", "sid": sid, "host": host, "rport": rport }))
        .await?;
    Ok((sid, rx))
}

/// How long warm-reuse waits for the first inbound frame proving a held link
/// still delivers, before treating it as a zombie. A healthy link answers in ~1
/// RTT; for ssh that frame is sshd's banner and for pty the shell prompt, both of
/// which the peer sends UNPROMPTED, so the wait overlaps work we needed anyway.
/// Only a black-holed link burns the whole window. Override with
/// FILAMENT_WARM_VERIFY_MS.
#[cfg(unix)]
pub(crate) fn warm_verify_window() -> std::time::Duration {
    let ms = std::env::var("FILAMENT_WARM_VERIFY_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(2500);
    std::time::Duration::from_millis(ms)
}

/// Confirm a just-opened warm stream (`sid` + its inbound `rx`) actually delivers,
/// BEFORE the caller commits the client to it. Waits up to `verify` for the first
/// inbound frame - data OR an l2-close (a real refusal): either proves the link is
/// alive. Returns the frame so the caller can replay it (no bytes lost). `Err` if
/// nothing arrives in time: a ZOMBIE link, up at the QUIC layer but black-holing
/// new streams, so the caller drops it and falls back to a fresh establish rather
/// than handing the client a dead connection (which would stall until ITS own
/// timeout - the 25s ssh ConnectTimeout we measured). Verifying first means the
/// fallback is immediate and the client never sends bytes into a black hole.
#[cfg(unix)]
async fn verify_first_frame(
    mux: &Arc<Mux>,
    sid: u32,
    mut rx: mpsc::Receiver<PipeItem>,
    verify: std::time::Duration,
) -> Result<(PipeItem, mpsc::Receiver<PipeItem>)> {
    match tokio::time::timeout(verify, rx.recv()).await {
        Ok(Some(first)) => Ok((first, rx)),
        Ok(None) => Err(anyhow!("warm stream closed before any frame")),
        Err(_) => {
            // Best-effort tear-down of the half-open sid on the peer, then bail so
            // the caller drops this zombie link and establishes fresh.
            mux.streams.lock().await.remove(&sid);
            let _ = mux
                .transport
                .send_control(&json!({ "type": "l2-close", "sid": sid }))
                .await;
            Err(anyhow!(
                "warm link unresponsive after {}ms (zombie)",
                verify.as_millis()
            ))
        }
    }
}

/// Open an L2 stream over a warm link and CONFIRM the peer responds before the
/// caller commits the client. Returns (sid, first_frame, remaining_rx) once the
/// first inbound frame lands. `Err` on a zombie link (see `verify_first_frame`).
#[cfg(unix)]
pub(crate) async fn open_stream_verified(
    mux: &Arc<Mux>,
    rport: u16,
    verify: std::time::Duration,
) -> Result<(u32, PipeItem, mpsc::Receiver<PipeItem>)> {
    let (sid, rx) = open_stream(mux, rport).await?;
    let (first, rx) = verify_first_frame(mux, sid, rx, verify).await?;
    Ok((sid, first, rx))
}

/// Bridge a verified warm stream to the client `sock`, replaying the already-read
/// `first` frame so no peer bytes are lost.
#[cfg(unix)]
pub(crate) async fn serve_verified_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    sid: u32,
    sock: S,
    first: PipeItem,
    rx: mpsc::Receiver<PipeItem>,
) {
    serve_stream(mux, sid, sock, rx, true, Some(first), None).await;
}

/// Open a mesh-native mount stream to the peer, sending `mount-open` with the
/// encoded root path. Waits for the `mount-open-ack` control message carrying
/// server capabilities, then sends `mount-cap-ack` to confirm the negotiated
/// protocol. Returns sid + inbound pipe + the server's MountCaps.
/// No sshd, no sshfs.
async fn open_mount_stream(
    mux: &Arc<Mux>,
    root: &str,
) -> Result<(u32, mpsc::Receiver<PipeItem>, crate::mount_proto::MountCaps)> {
    let sid = mux.alloc_sid();
    let rx = mux
        .register(sid)
        .await
        .ok_or_else(|| anyhow!("mount open: sid {sid:#x} already in use"))?;
    let (tx, outcome_rx) = tokio::sync::oneshot::channel();
    mux.open_ack_tx.lock().await.insert(sid, tx);
    let encoded = crate::mount_proto::path_encode(std::path::Path::new(root));
    mux.transport
        .send_control(&json!({ "type": "mount-open", "sid": sid, "root": encoded }))
        .await?;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), outcome_rx)
        .await
        .map_err(|_| anyhow::anyhow!("mount-open-ack not received (timed out)"))?
        .map_err(|_| anyhow::anyhow!("mount-open-ack channel closed"))?;
    // #206: an l2-close from the acceptor is a DENIAL (authorization, ceiling,
    // stream cap) carrying a reason. It must surface as a denial, never as a
    // transport-shaped timeout. Silence still means timeout; a refusal is never
    // silent.
    let caps_value = match outcome {
        OpenOutcome::Opened(v) => v.get("caps").cloned().unwrap_or(serde_json::Value::Null),
        OpenOutcome::Refused(reason) => return Err(anyhow!("mount denied by {reason}")),
        OpenOutcome::ClosedWithoutAck => {
            return Err(anyhow!("mount denied by connection closed by the peer"));
        }
    };
    let caps = crate::mount_proto::parse_mount_caps(caps_value)?;
    // Send mount-cap-ack: the client confirms it accepts the server's caps.
    let _ = mux
        .transport
        .send_control(&json!({
            "type": "mount-cap-ack", "sid": sid,
            "binary_frames": caps.protocol_version >= 2
        }))
        .await;
    Ok((sid, rx, caps))
}

/// WARM pty (daemon side): open a PTY on the peer over an EXISTING link's `mux`,
/// sending `pty-open` (vs `open_stream`'s `l2-open`). Returns the sid + inbound
/// pipe; the caller bridges with `serve_opened_stream` and relays `pty-resize` by
/// the sid. `session` keys the peer's persistent PTY so a reconnect reattaches.
/// The remote acceptor serves this exactly as a cold `pty-open`.
async fn open_pty_stream(
    mux: &Arc<Mux>,
    session: &str,
    cols: u16,
    rows: u16,
    term: &str,
    cmd: &str,
) -> Result<(u32, mpsc::Receiver<PipeItem>)> {
    let sid = mux.alloc_sid();
    let rx = mux
        .register(sid)
        .await
        .ok_or_else(|| anyhow!("pty open: sid {sid:#x} already in use"))?;
    let mut ctl = json!({
        "type": "pty-open", "sid": sid, "session": session, "cols": cols, "rows": rows, "term": term
    });
    if !cmd.is_empty() {
        ctl["cmd"] = json!(cmd);
    }
    mux.transport.send_control(&ctl).await?;
    Ok((sid, rx))
}

/// Warm PTY open that CONFIRMS the held link delivers before the caller commits
/// the terminal - the pty twin of `open_stream_verified`. A fresh PTY's shell
/// prompt (or a reattach's replayed buffer) is the first inbound frame and the
/// peer sends it unprompted, so a healthy link costs nothing here; a zombie link
/// yields nothing within `verify` and we `Err` so the caller drops it + falls
/// back to a cold pty instead of handing the user a dead terminal.
#[cfg(unix)]
pub(crate) async fn open_pty_stream_verified(
    mux: &Arc<Mux>,
    session: &str,
    cols: u16,
    rows: u16,
    term: &str,
    cmd: &str,
    verify: std::time::Duration,
) -> Result<(u32, PipeItem, mpsc::Receiver<PipeItem>)> {
    let (sid, rx) = open_pty_stream(mux, session, cols, rows, term, cmd).await?;
    let (first, rx) = verify_first_frame(mux, sid, rx, verify).await?;
    Ok((sid, first, rx))
}

/// Bridge an already-opened L2 stream (`sid` + its inbound `rx`) to a local
/// `stream` (the warm pty client's unix socket), running to completion (stream
/// EOF or peer FIN). The daemon's warm-pty path uses this after a verified open.
#[cfg(unix)]
pub(crate) async fn serve_opened_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    sid: u32,
    stream: S,
    rx: mpsc::Receiver<PipeItem>,
) {
    serve_stream(mux, sid, stream, rx, true, None, None).await;
}

/// Pump this process's stdio over a connected warm-reuse socket: stdin -> sock,
/// sock -> stdout. Exit when the remote half closes (sock read EOF), the same
/// "session over" semantics the cold netcat path has. Its OWN `tokio::io::stdin()`
/// is fine here because netcat is a single-shot ProxyCommand (one process, one
/// attach, no reconnect): the singleton is created once and never handed off.
#[cfg(unix)]
async fn pump_stdio_over(sock: tokio::net::UnixStream) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(sock);
    let writer = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = tokio::io::copy(&mut stdin, &mut wr).await; // local EOF
        let _ = wr.shutdown().await; // half-close so the remote sees our EOF
    });
    let mut stdout = tokio::io::stdout();
    tokio::io::copy(&mut rd, &mut stdout).await?;
    let _ = stdout.flush().await;
    writer.abort();
    Ok(())
}

/// Warm-pty variant of `pump_stdio_over` that draws input from the SHARED,
/// invocation-long stdin reader instead of its own `tokio::io::stdin()`. The pty
/// client can hand off warm->cold on a drop, so both halves MUST consume the one
/// fd0 reader or a stale singleton swallows input after the handoff (see
/// `spawn_stdin_reader`). `pending` preserves an input chunk pulled just as the
/// warm socket died so the cold reattach re-sends it. Returns when the socket's
/// remote half closes (warm session over: a drop OR a clean shell exit).
#[cfg(unix)]
async fn pump_warm_pty_stdio(
    sock: tokio::net::UnixStream,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(sock);
    if let Some(buf) = pending.take() {
        if wr.write_all(&buf).await.is_err() {
            *pending = Some(buf);
            return Ok(());
        }
        let _ = wr.flush().await;
    }
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            r = rd.read(&mut buf) => match r {
                Ok(0) | Err(_) => break, // remote half closed: warm session over
                Ok(n) => { stdout.write_all(&buf[..n]).await?; stdout.flush().await?; }
            },
            chunk = stdin_rx.recv() => match chunk {
                Some(c) if c.is_empty() => { let _ = wr.shutdown().await; } // fd0 EOF
                Some(c) => {
                    if wr.write_all(&c).await.is_err() { *pending = Some(c); break; }
                    let _ = wr.flush().await;
                }
                None => { let _ = wr.shutdown().await; }
            },
        }
    }
    let _ = stdout.flush().await;
    Ok(())
}

/// Pump a one-shot warm pty: stream output to stdout until the command exits.
/// No raw mode, no SIGWINCH, no interactive features. Forwards stdin to match
/// cold path parity (supports `echo hi | filament shell peer -- cat`).
#[cfg(unix)]
async fn pump_warm_pty_one_shot(
    sock: tokio::net::UnixStream,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(sock);
    if let Some(buf) = pending.take() {
        if wr.write_all(&buf).await.is_err() {
            *pending = Some(buf);
            return Ok(());
        }
        let _ = wr.flush().await;
    }
    // For scripted one-shot: on stdin-EOF, shut down the write-half to signal
    // stdin-EOF to the daemon (cat etc. will see stdin EOF and exit), but do
    // NOT let serve_stream tear down the pty session yet. The daemon's
    // socket_to_dc sees the read-EOF and sends an empty frame (FIN) to the
    // daemon transport, which closes the pty stdin. The daemon keeps the pty
    // open until the command exits, then closes the socket (dc_to_socket
    // finishes as the pty output pipe closes), which we see as read-EOF.
    //
    // Key insight: on a Unix socket, closing the write-half sends FIN to the
    // reader, but the reader half stays open. socket_to_dc sees the FIN and
    // returns Ok(()), but the writer (dc_to_socket) is NOT aborted until the
    // daemon's pty output pipe closes. serve_stream's select! picks up the
    // writer finishing AFTER the reader, not before.
    let mut stdin_done = false;
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            r = rd.read(&mut buf) => match r {
                Ok(0) | Err(_) => break, // command exited / link closed
                Ok(n) => {
                    stdout.write_all(&buf[..n]).await?;
                    stdout.flush().await?;
                }
            },
            chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                Some(c) if c.is_empty() => {
                    // stdin-EOF: shut down write-half to signal the daemon.
                    // socket_to_dc sees read-EOF, sends FIN to daemon transport.
                    // Daemon keeps pty open until command exits, then closes socket.
                    let _ = wr.shutdown().await;
                    stdin_done = true;
                }
                Some(c) => {
                    if wr.write_all(&c).await.is_err() { *pending = Some(c); break; }
                    let _ = wr.flush().await;
                }
                None => {
                    // Shared reader gone (only at shutdown) - don't close socket.
                    stdin_done = true;
                }
            },
        }
    }
    let _ = stdout.flush().await;
    Ok(())
}

/// `filament forward <peer> <port>`: wire this process's stdio to a service the peer
/// EXPOSED on its overlay address, over L3 (the overlay-port counterpart of
/// `netcat`; also an ssh ProxyCommand for an overlay-exposed sshd). Goes through the
/// local daemon, which resolves the peer to its verified overlay address and dials
/// it, so it works from a userspace node with no kernel route.
#[cfg(unix)]
pub async fn dial_cmd(peer: &str, port: u16) -> Result<()> {
    match crate::ctl::try_dial(peer, port).await {
        Some(sock) => pump_stdio_over(sock).await,
        None => bail!(
            "could not dial {peer}.mesh:{port} over the overlay (is the daemon up, the peer paired, and the port expose'd on it?)"
        ),
    }
}

#[cfg(not(unix))]
pub async fn dial_cmd(_peer: &str, _port: u16) -> Result<()> {
    bail!("filament forward needs the local daemon's control socket (unix only)")
}

/// `filament netcat <peer> <rport>`: wire this process's stdio to one L2 stream.
/// This is the ssh ProxyCommand primitive.
pub async fn netcat_cmd(server: &str, peer: &str, rport: u16, relay: bool) -> Result<()> {
    // WARM-LINK FAST PATH: if a local `up` daemon already holds a link to `peer`,
    // ride it (no signaling, no establishment, ~1s saved). Skipped under --relay
    // (the user forced a relay path; a warm link may be direct) and self-heals: any
    // miss / no daemon / dead stream falls through to a fresh establish below.
    // Unix-only: the control socket is a unix-domain socket (no-op elsewhere).
    #[cfg(unix)]
    if !relay {
        if let Some(sock) = crate::ctl::try_open(peer, rport).await {
            crate::ui::trace(&format!(
                "filament: reusing warm link to '{peer}' (no establish)"
            ));
            return pump_stdio_over(sock).await;
        }
    }
    // Bound the connect so an unreachable peer fails with a clear message
    // instead of hanging forever. Override with FILAMENT_CONNECT_SECS.
    let connect_secs: u64 = std::env::var("FILAMENT_CONNECT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(45);
    let (t, rx, guard, mut diag) = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_secs),
        bring_up_to_known(server, peer, relay, "init"),
    )
    .await
    {
        Ok(inner) => inner?,
        Err(_) => {
            crate::ui::problem(
                &format!("filament netcat: can't reach '{peer}'"),
                &format!(
                    "couldn't establish a link to '{peer}' in {connect_secs}s - it may be offline or unreachable from here."
                ),
                &[
                    format!(
                        "check it's reachable: {}",
                        crate::ui::paint(crate::ui::Tone::Brand, &format!("filament reach {peer}"))
                    ),
                    format!(
                        "diagnose the connect: {}",
                        crate::ui::paint(
                            crate::ui::Tone::Brand,
                            &format!("filament doctor {peer}")
                        )
                    ),
                ],
            );
            std::process::exit(1);
        }
    };
    guard.forget(); // long-lived tunnel, keep the link alive for the process
    let mux = Mux::new(t);
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    // L2Open round trip: open the stream and wait for the acceptor's l2-open-ack
    // (the stream-is-live confirmation) before declaring the link Up. The ack is
    // consumed by pump_initiator, so we instead wait for the FIRST inbound byte
    // or a bounded grace, the practical "stream usable" signal for stdio netcat.
    diag.enter(crate::diag::Phase::L2Open);
    let (sid, mut rx_pipe) = open_stream(&mux, rport).await?;
    // The link is now usable end to end (the ssh handshake will flow). Record
    // `up` with the route label we can infer (the transport carries no route()
    // for a direct link, so we report the generic tunnel transport here).
    diag.up("tunnel", "datachannel-or-direct");

    // stdin -> dc
    let t_in = mux.transport();
    let reader = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let cap = t_in.max_payload();
        let mut buf = vec![0u8; cap];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = t_in.send_frame(sid, 0, &[]).await; // local EOF -> FIN
                    break;
                }
                Ok(n) => {
                    if t_in.send_frame(sid, 0, &buf[..n]).await.is_err() {
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

/// RAII guard: put the local terminal in raw mode for an interactive PTY and
/// ALWAYS restore cooked mode on drop (normal exit, error, or `?`). Without raw
/// mode the local tty line-buffers + echoes and swallows control keys, so a
/// remote TUI (claude/opencode/vim/htop) can't receive keystrokes or escape
/// sequences and renders unusable.
struct RawGuard {
    active: bool,
}
impl RawGuard {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawGuard { active: true })
    }
}
impl Drop for RawGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = crossterm::terminal::disable_raw_mode();
            crossterm::execute!(std::io::stderr(), crossterm::cursor::Show).ok();
            eprint!("\r\n");
        }
    }
}

/// Why a single PTY attach ended.
enum PtyOutcome {
    /// The remote shell exited (acceptor sent `l2-close` while the link was
    /// healthy) - we are DONE, do not reconnect.
    Exited,
    /// The link died under us (transport not alive) - the remote PTY session may
    /// still be alive on the acceptor; reconnect and REATTACH the same session.
    Dropped,
    /// The acceptor refused the open with an explicit reason (no shell cap,
    /// acceptor off, stream cap, ...). Nonzero, print the reason.
    Refused(String),
    /// The stream closed (or never answered) before we could confirm the peer
    /// opened a shell. Nonzero, with a weaker sentence rather than a confident
    /// wrong one.
    Unconfirmed(String),
}

/// A single, process-lifetime reader of fd0 for the resumable pty client.
///
/// tokio's `io::stdin()` is a GLOBAL singleton backed by an UNCANCELLABLE blocking
/// read thread. The resumable client re-attaches on every link drop (and hands off
/// warm->cold), and the old code spawned a fresh stdin reader per attach then
/// `abort()`ed the previous one. Aborting a task parked in that shared blocking
/// read does NOT stop the read: a stale reader keeps draining fd0 and routing bytes
/// to a DEAD stream, so after a real reattach every keystroke is silently swallowed
/// (observed live: a 30s outage closes QUIC, forces a true reattach, input dies -
/// the read even shows up in strace, it just goes nowhere). Fix: read fd0 exactly
/// ONCE, on a dedicated thread that lives for the whole invocation, and fan chunks
/// to whichever attach is current over an mpsc channel. An empty Vec is the EOF
/// sentinel (matches the `send_frame(sid, &[])` FIN convention). The thread ends on
/// EOF/error; on a clean session exit the process exits right after, reaping it.
pub(crate) fn spawn_stdin_reader() -> tokio::sync::mpsc::UnboundedReceiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(Vec::new()); // EOF sentinel
                    break;
                }
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break; // the client hung up
                    }
                }
            }
        }
    });
    rx
}

/// Send `data` to the peer over one L2 stream, split into transport-sized frames.
/// `Err(())` means a frame was rejected (the link is gone); the caller stashes the
/// unsent input for the next attach so a keystroke typed at the drop is not lost.
async fn send_frames_chunked(
    t: &Arc<dyn Transport>,
    sid: u32,
    data: &[u8],
) -> std::result::Result<(), ()> {
    let cap = t.max_payload().max(1);
    for chunk in data.chunks(cap) {
        if t.send_frame(sid, 0, chunk).await.is_err() {
            return Err(());
        }
    }
    Ok(())
}

/// One attach to the peer's PTY over a freshly-established link: open/reattach the
/// `session_id`, bridge stdio, and return why it ended. Raw mode is owned by the
/// caller (held across reconnects), so this only does size/resize/IO. `stdin_rx`
/// is the shared, invocation-long stdin source (see `spawn_stdin_reader`); `pending`
/// carries input pulled-but-unsent when the previous attach dropped, so a keystroke
/// at the seam survives the reconnect.
#[allow(clippy::too_many_arguments)]
async fn pty_attach_once(
    server: &str,
    peer: &str,
    relay: bool,
    role: &'static str,
    session_id: &str,
    term: &str,
    cmd: &str,
    interactive: bool,
    resume: bool,
    raw: &mut Option<RawGuard>,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
) -> Result<PtyOutcome> {
    // Bound the connect so an unreachable peer fails with a clear message
    // instead of hanging forever. Override with FILAMENT_CONNECT_SECS.
    let connect_secs: u64 = std::env::var("FILAMENT_CONNECT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(45);
    let (t, rx, guard, mut diag) = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_secs),
        bring_up_to_known(server, peer, relay, role),
    )
    .await
    {
        Ok(inner) => inner?,
        Err(_) => {
            bail!("connect timeout: couldn't reach '{peer}' in {connect_secs}s");
        }
    };
    guard.forget();
    let mux = Mux::new(t);
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    diag.enter(crate::diag::Phase::L2Open);
    let sid = mux.alloc_sid();
    let mut rx_pipe = mux
        .register(sid)
        .await
        .ok_or_else(|| anyhow!("pty open: sid {sid:#x} already in use"))?;

    // Register the open waiter BEFORE the pty-open goes out, so an ack/close that
    // races back cannot be lost. Only the FIRST attach needs this: a resume that
    // finds no session is a clean end (the acceptor says "no such session"), not a
    // denial, and exit 0 is correct there.
    let ack_rx = if resume {
        None
    } else {
        let (tx, rx) = tokio::sync::oneshot::channel::<OpenOutcome>();
        mux.open_ack_tx.lock().await.insert(sid, tx);
        Some(rx)
    };

    // Real terminal: query the ACTUAL tty size (crossterm asks the tty via
    // ioctl), NOT the COLUMNS/LINES shell vars which are usually unexported and
    // leave a TUI rendering at a stale size. Fall back to env/defaults for a pipe.
    let (cols, rows) = if interactive {
        crossterm::terminal::size().unwrap_or((80, 24))
    } else {
        (
            std::env::var("COLUMNS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(80u16),
            std::env::var("LINES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(24u16),
        )
    };
    // `session` makes reconnects REATTACH the same shell (acceptor keys it per
    // verified device); a fresh per-invocation id means two `filament shell` runs
    // never collide. `term` is forwarded so the remote matches THIS terminal.
    mux.transport()
        .send_control(&{
            let mut ctl = json!({
                "type": "pty-open", "sid": sid, "session": session_id,
                "cols": cols, "rows": rows, "term": term, "resume": resume,
            });
            if !cmd.is_empty() {
                ctl["cmd"] = json!(cmd);
            }
            ctl
        })
        .await?;
    diag.up("tunnel", "datachannel-or-direct");

    // Exit 0 must mean "the peer told me it opened". Wait (bounded) for the
    // pty-open-ack before committing to the session, so a refusal, a silent
    // close, or a black hole all become nonzero instead of an empty-success.
    // `-- true` stays exit 0: the ack arrives, then the clean l2-close follows.
    if let Some(ack_rx) = ack_rx {
        let outcome = tokio::time::timeout(Duration::from_secs(10), ack_rx).await;
        match outcome {
            Ok(Ok(OpenOutcome::Opened(_))) => {}
            Ok(Ok(OpenOutcome::Refused(reason))) => {
                mux.drop_stream(sid).await;
                pump.abort();
                return Ok(PtyOutcome::Refused(reason));
            }
            Ok(Ok(OpenOutcome::ClosedWithoutAck)) => {
                mux.drop_stream(sid).await;
                pump.abort();
                return Ok(PtyOutcome::Unconfirmed(format!(
                    "could not confirm '{peer}' opened a shell (the connection closed before it answered)"
                )));
            }
            Ok(Err(_)) => {
                mux.drop_stream(sid).await;
                pump.abort();
                return Ok(PtyOutcome::Unconfirmed(format!(
                    "could not confirm '{peer}' opened a shell (the link closed)"
                )));
            }
            Err(_) => {
                mux.drop_stream(sid).await;
                pump.abort();
                return Ok(PtyOutcome::Unconfirmed(format!(
                    "no answer from '{peer}' - it may be unresponsive or running a build that does not ack shell opens"
                )));
            }
        }
    }

    // Enable raw mode LAZILY, AFTER the establishment status lines have printed in
    // cooked mode (so `\n` still does CR+LF and they don't "staircase"). Held in
    // the caller's scope so it persists across reconnects and is restored on exit.
    // On a reconnect raw is already on; the acceptor's buffer replay redraws the
    // screen cleanly anyway.
    if interactive && raw.is_none() {
        *raw = Some(RawGuard::enable()?);
    }

    // Forward terminal resizes to the remote PTY (acceptor handles `pty-resize`).
    #[cfg(unix)]
    let winch = if interactive {
        let t_resize = mux.transport();
        Some(tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sig = match signal(SignalKind::window_change()) {
                Ok(s) => s,
                Err(_) => return,
            };
            while sig.recv().await.is_some() {
                if let Ok((c, r)) = crossterm::terminal::size() {
                    let _ = t_resize
                        .send_control(
                            &json!({ "type": "pty-resize", "sid": sid, "cols": c, "rows": r }),
                        )
                        .await;
                }
            }
        }))
    } else {
        None
    };

    let t_in = mux.transport();
    // Input buffered-but-unsent by the PREVIOUS (dropped) attach goes out first, so
    // a keystroke typed right at the seam survives the reconnect. If this link is
    // already dead, keep it stashed and report a drop so the loop reattaches again.
    if let Some(buf) = pending.take() {
        if send_frames_chunked(&t_in, sid, &buf).await.is_err() {
            *pending = Some(buf);
            #[cfg(unix)]
            if let Some(w) = winch {
                w.abort();
            }
            mux.drop_stream(sid).await;
            pump.abort();
            return Ok(PtyOutcome::Dropped);
        }
    }

    // Stream remote output to stdout AND forward local input, driven by the SHARED
    // stdin reader (see `spawn_stdin_reader`) so reconnects never spawn a second
    // fd0 consumer. End when the pipe closes (shell exit OR link death) - disambiguated
    // by the transport's liveness. A 2s liveness poll is the backstop for a silent
    // black-hole that never closes the pipe.
    let mut stdout = tokio::io::stdout();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.tick().await; // consume the immediate tick
    let mut stdin_done = false; // fd0 hit EOF: stop reading it, keep pumping stdout
    let dropped;
    let mut close_reason: Option<String> = None;
    loop {
        tokio::select! {
            item = rx_pipe.recv() => match item {
                Some(Some(bytes)) => {
                    stdout.write_all(&bytes).await?;
                    stdout.flush().await?;
                }
                // Pipe closed: clean exit (l2-close, link still alive), a mid-session
                // denial (l2-close{err}, the revoke case), or a drop.
                _ => {
                    dropped = !mux.transport().is_alive();
                    close_reason = mux.take_close_err(sid).await;
                    break;
                }
            },
            chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                // Empty Vec = fd0 EOF: send the FIN once, then stop reading stdin but
                // keep draining remote output until the shell actually closes.
                Some(c) if c.is_empty() => { let _ = t_in.send_frame(sid, 0, &[]).await; stdin_done = true; }
                Some(c) => {
                    if send_frames_chunked(&t_in, sid, &c).await.is_err() {
                        // Link died mid-send: stash the input for the next attach and
                        // reconnect rather than lose it.
                        *pending = Some(c);
                        dropped = true;
                        break;
                    }
                }
                None => { stdin_done = true; } // shared reader gone (only at shutdown)
            },
            _ = ticker.tick() => {
                if !mux.transport().is_alive() { dropped = true; break; }
            }
        }
    }

    #[cfg(unix)]
    if let Some(w) = winch {
        w.abort();
    }
    mux.drop_stream(sid).await;
    // Only send our own l2-close on a CLEAN exit. On a drop the link is gone and,
    // crucially, an l2-close would tell the acceptor to END the session we want
    // to reattach - so we stay silent and let it buffer for the reattach.
    if !dropped {
        let _ = mux
            .transport()
            .send_control(&json!({ "type": "l2-close", "sid": sid }))
            .await;
    }
    pump.abort();
    match close_reason {
        // A mid-session denial (revoke): nonzero with the reason, never a clean
        // exit that would carry a `&&` pipeline forward (#223).
        Some(reason) => Ok(PtyOutcome::Refused(reason)),
        None if dropped => Ok(PtyOutcome::Dropped),
        None => Ok(PtyOutcome::Exited),
    }
}

/// Warm fast path for `filament shell`: if the local daemon already holds a link to
/// `peer`, open the PTY over it (via the control socket) and bridge this process's
/// stdio to it - raw mode + SIGWINCH forwarded as a `resize` op. Returns
/// `Some(result)` once it has handled the session (stdio EOF = shell exit or a
/// warm-link drop -> we exit), or `None` when there is no warm link, so the caller
/// falls through to the cold resumable path. Unix-only (the control socket is unix).
#[cfg(unix)]
async fn try_warm_pty(
    peer: &str,
    session: &str,
    term: &str,
    cmd: &str,
    interactive: bool,
    raw: &mut Option<RawGuard>,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
) -> Option<Result<()>> {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    // `Err(Some(reason))` means the DAEMON answered. A `refused:` reason is the
    // PEER's answer relayed back, and it is definitive: returning None here would
    // send the caller down the cold path, which for a fleet peer dies at name
    // resolution and reports "can't reach ... may be offline" for a peer that is
    // demonstrably reachable and simply said no.
    let sock = match crate::ctl::try_pty_reason(peer, session, cols, rows, term, cmd).await {
        Ok(sock) => sock,
        Err(Some(reason)) if reason.starts_with("refused:") => {
            return Some(Err(anyhow!("{}", reason.trim_start_matches("refused:").trim())));
        }
        Err(_) => return None, // no warm path; the cold path is the right answer
    };
    if interactive {
        crate::ui::trace(&format!(
            "filament: reusing warm link to '{peer}' for pty (no establish)"
        ));
        if raw.is_none() {
            match RawGuard::enable() {
                Ok(g) => *raw = Some(g),
                Err(e) => return Some(Err(e)),
            }
        }
        // Forward SIGWINCH as a `resize` control op (a fresh short connection each time).
        let session_owned = session.to_string();
        let winch = tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sig = match signal(SignalKind::window_change()) {
                Ok(s) => s,
                Err(_) => return,
            };
            while sig.recv().await.is_some() {
                if let Ok((c, r)) = crossterm::terminal::size() {
                    crate::ctl::try_resize(&session_owned, c, r).await;
                }
            }
        });
        let r = pump_warm_pty_stdio(sock, stdin_rx, pending).await;
        winch.abort();
        Some(r)
    } else {
        // One-shot (scripted): no raw mode, no SIGWINCH, just stream output.
        crate::ui::trace(&format!(
            "filament: reusing warm link to '{peer}' for one-shot pty"
        ));
        // NOTE: neither the cold path nor this warm path propagates the remote
        // command's exit status - both return Ok(()) regardless. This is a known
        // limitation / future enhancement.
        Some(pump_warm_pty_one_shot(sock, stdin_rx, pending).await)
    }
}

/// `filament shell <peer>`: open a PTY shell on the peer and bridge it to this
/// terminal (the CLI sibling of the browser web-shell). On a real terminal it is
/// a FULL interactive client - real tty size, raw mode, SIGWINCH, $TERM - AND
/// RESUMABLE: a per-invocation random session id lets a dropped link reconnect
/// and reattach the SAME live shell (mosh/tmux-style, the acceptor replays its
/// output buffer), so a flaky link (e.g. a Coder workspace reconnecting every
/// ~90s) no longer loses the session. The session id lives only in THIS process,
/// so a separate `filament shell` run always gets a fresh shell, never this one.
/// A non-tty stdio (a pipe) keeps the plain cooked, non-resuming bridge.
pub async fn pty_cmd(server: &str, peer: &str, relay: bool, cmd: Vec<String>) -> Result<()> {
    let one_shot = cmd.join(" ");
    use std::io::IsTerminal;
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    // Random, per-invocation, in-memory only: distinct runs never collide; only
    // THIS process's reconnects reattach (see the user's "same client" concern).
    let session_id = crate::fresh_secret();
    let term = std::env::var("TERM")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "xterm-256color".into());

    // Raw mode is held for the WHOLE invocation (enabled lazily inside the first
    // attach, AFTER its status lines, so they don't staircase), persists across
    // reconnects, and is restored on every exit path by this guard's Drop.
    let mut raw: Option<RawGuard> = None;

    // ONE fd0 reader for the whole invocation, shared across the warm bridge and
    // every cold reattach. tokio's stdin singleton can't be cancelled, so a
    // per-attach reader leaks and swallows input after a reconnect (see
    // `spawn_stdin_reader`). `pending` carries input pulled just as a link died so
    // the reattach re-sends it instead of losing the keystroke.
    let mut stdin_rx = spawn_stdin_reader();
    let mut pending: Option<Vec<u8>> = None;

    // WARM FAST PATH: if the local `up` daemon already holds a (verified, direct)
    // link to `peer`, open the PTY over it - no signaling, no establishment, ~0.2s
    // instead of seconds. A miss / no daemon / no warm link falls through to the
    // cold resumable path below. Skipped under --relay (the user forced relay; a
    // warm link may be direct) and for non-tty stdio (scripted). Resumability
    // lives on the cold path, where flaky peers (no warm link) need it anyway.
    // Loop state up front so the warm path can hand off INTO the resumable loop
    // instead of returning (the old behavior, which re-logged-in on a warm drop).
    let mut ever_connected = false;
    let mut last_up = std::time::Instant::now();
    let mut backoff = Duration::from_millis(300);
    let mut role: &'static str = "init";
    // Set when a WARM session ended (a drop OR a clean shell exit - the warm bridge
    // can't tell). The first cold attach after that is RESUME-ONLY: a warm drop
    // reattaches the SAME live shell/TUI (seamless, no re-login); a clean warm exit
    // finds no session and the acceptor closes it, so we exit cleanly.
    // TODO: distinguish clean-exit from transport-drop at the warm layer.
    //   Currently the bridge sees an opaque socket close for both cases.
    //
    //   INVESTIGATED 2026-08-30, and the `ctl::session_alive(peer)` probe this
    //   note used to propose DOES NOT WORK. The initiating daemon's warm_ptys
    //   entry is dropped for both outcomes -- its own comment says "Bridge ended
    //   (shell exit / client gone / link drop): drop our entry" -- so the probe
    //   answers "not alive" either way. It would skip the cold path for both,
    //   which breaks the warm-drop reattach this path exists to provide, or for
    //   neither, which changes nothing.
    //
    //   The fact lives on the PEER: does its acceptor still hold the session?
    //   Asking costs a transport establishment, which is the thing being
    //   avoided. So the real fix is a PROTOCOL addition, the acceptor sending an
    //   explicit clean-exit marker before it closes, which the initiator records
    //   so the next attach can tell the two apart locally. Bigger than a ctl op,
    //   and worth knowing before someone builds a probe that cannot answer.
    let mut warm_ended = false;

    #[cfg(unix)]
    if !relay && (interactive || !one_shot.is_empty()) {
        match try_warm_pty(
            peer,
            &session_id,
            &term,
            &one_shot,
            interactive,
            &mut raw,
            &mut stdin_rx,
            &mut pending,
        )
        .await
        {
            Some(Err(e)) => return Err(e),
            Some(Ok(())) => {
                // For one-shot exec: the warm bridge already streamed the command's
                // output and waited for exit. Return immediately - do NOT enter the
                // reconnect/resume loop which would cold-establish redundantly.
                if !one_shot.is_empty() {
                    return Ok(());
                }
                warm_ended = true;
                role = "reconnect";
            }
            None => {} // no warm link -> normal cold path below
        }
    }

    loop {
        // Resume-only after any prior connection (warm or cold). If the session
        // is gone (shell exited cleanly on a prior drop), the acceptor returns
        // "no such session" and we exit cleanly instead of spawning a fresh shell.
        let resume = ever_connected || warm_ended;
        match pty_attach_once(
            server,
            peer,
            relay,
            role,
            &session_id,
            &term,
            &one_shot,
            interactive,
            resume,
            &mut raw,
            &mut stdin_rx,
            &mut pending,
        )
        .await
        {
            Ok(PtyOutcome::Exited) => return Ok(()),
            Ok(PtyOutcome::Refused(reason)) => {
                // The peer is up and said no. Nonzero with the reason; never a
                // false success that would carry a `&&` pipeline forward.
                // The remedy depends on WHICH refusal: a revoked certificate is
                // not repaired by a grant, so the hint must not say "grant".
                let hint = if reason == crate::capability::REVOKED_REASON {
                    format!(
                        "the peer's certificate was revoked; restore it with {}",
                        crate::ui::paint(
                            crate::ui::Tone::Brand,
                            "filament devices restore <this-device>"
                        )
                    )
                } else if reason == crate::capability::CEILING_REASON {
                    // A grant cannot widen an enrolment ceiling, and `filament
                    // grant` says so when you run it. Prescribing it here sent
                    // the owner to a command that refuses, and the refusal named
                    // the real fix. Name it here instead, one step earlier.
                    format!(
                        "shell is outside this device's invitation ceiling, and a grant cannot widen one. Re-invite with shell: {}",
                        crate::ui::paint(
                            crate::ui::Tone::Brand,
                            "filament add --for <this-device> --allow shell"
                        )
                    )
                } else {
                    format!(
                        "grant shell on the peer: {}",
                        crate::ui::paint(
                            crate::ui::Tone::Brand,
                            &format!("filament grant <this-device> shell")
                        )
                    )
                };
                crate::ui::problem(&format!("shell refused by '{peer}'"), &reason, &[hint]);
                std::process::exit(1);
            }
            Ok(PtyOutcome::Unconfirmed(reason)) => {
                // We could not establish that the peer opened a shell. Say the
                // weaker true sentence rather than a confident wrong one.
                crate::ui::problem(
                    &format!("shell could not be confirmed on '{peer}'"),
                    &reason,
                    &[],
                );
                std::process::exit(1);
            }
            Ok(PtyOutcome::Dropped) => {
                // Non-tty (scripted) sessions don't resume; a drop is the end.
                if !interactive {
                    return Ok(());
                }
                ever_connected = true;
                last_up = std::time::Instant::now();
                backoff = Duration::from_millis(300);
                role = "reconnect";
                eprint!("\r\n\x1b[2m[filament: link dropped, reconnecting...]\x1b[0m\r\n");
                continue;
            }
            Err(e) => {
                // A first COLD connect (no warm session) failing is fatal. But if a
                // warm session just ended, a failed reattach should RETRY (the mesh
                // may be mid-repair) until the reaper window, not bail.
                if !ever_connected && !warm_ended {
                    // A REFUSAL is not a reachability failure, and saying it is
                    // sends the user to `ping`/`doctor` to debug a healthy link.
                    // The peer answers an unauthorized open with an l2-close
                    // carrying a reason, which arrives in milliseconds; report
                    // that instead of the connect-timeout copy.
                    let refused = {
                        let msg = e.to_string();
                        (msg.contains("closed the shell request")
                            || msg.contains("refused")
                            || msg.contains("not authorized")
                            || msg.contains("capability")
                            || msg.contains("not in auth key caps"))
                        .then_some(msg)
                    };
                    if let Some(reason) = refused {
                        // Both verbs here used to be invented: `filament pty` and
                        // `filament request`. Neither exists, so the hint sent the
                        // user to a command that would not run. main's
                        // printed_hints_name_verbs_that_exist gate caught it on
                        // merge, which is exactly what that gate is for.
                        //
                        // The real shape: the attempt already queues a consent
                        // request on the PEER, so there is nothing to type here.
                        // What helps is knowing it was queued and how the other
                        // side answers it.
                        crate::ui::problem(
                            &format!("filament shell: '{peer}' refused the shell"),
                            &reason,
                            &[
                                format!(
                                    "on {peer}, approve it: {}",
                                    crate::ui::paint(crate::ui::Tone::Brand, "filament requests")
                                ),
                                format!(
                                    "or on {peer}, grant it outright: {}",
                                    crate::ui::paint(crate::ui::Tone::Brand, "filament grant <this device> shell")
                                ),
                            ],
                        );
                        std::process::exit(1);
                    }
                    let connect_secs: u64 = std::env::var("FILAMENT_CONNECT_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .filter(|n| *n > 0)
                        .unwrap_or(45);
                    crate::ui::problem(
                        &format!("filament shell: can't reach '{peer}'"),
                        &format!(
                            "couldn't establish a link to '{peer}' in {connect_secs}s - it may be offline or unreachable from here."
                        ),
                        &[
                            format!(
                                "check it's reachable: {}",
                                crate::ui::paint(
                                    crate::ui::Tone::Brand,
                                    &format!("filament reach {peer}")
                                )
                            ),
                            format!(
                                "diagnose the connect: {}",
                                crate::ui::paint(
                                    crate::ui::Tone::Brand,
                                    &format!("filament doctor {peer}")
                                )
                            ),
                        ],
                    );
                    std::process::exit(1);
                }
                // A reconnect attempt failed. Keep trying until the acceptor would
                // have reaped the detached session (SESSION_DETACHED_IDLE = 180s);
                // stop a bit under that so we don't reattach into a fresh shell.
                if last_up.elapsed() > Duration::from_secs(150) {
                    eprint!(
                        "\r\n\x1b[2m[filament: session expired, reconnect window passed]\x1b[0m\r\n"
                    );
                    return Ok(());
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
                role = "reconnect";
                continue;
            }
        }
    }
}

/// Build the user-facing message for the case where `filament forward` could
/// not bind its local listener because the requested port is in use. The
/// tunnel itself is healthy; only the local bind failed. We suggest
/// lport+1 with a saturating increment so the suggestion is always a valid
/// u16 (the helper is pure so the unit test below can pin the message shape
/// without touching the network).
fn port_in_use_msg(lport: u16, peer: &str, rport: u16) -> String {
    let suggested = lport.saturating_add(1);
    format!(
        "filament: local port {lport} is already in use, pick another (e.g. filament forward {suggested} {peer} {rport})"
    )
}

/// Bidirectionally copy an accepted local TCP connection and a warm-reuse unix
/// socket (the daemon bridges the unix socket to an L2 stream over its existing
/// link). One copy per direction; either side's EOF ends the pair. Unix-only.
#[cfg(unix)]
async fn bridge_streams(
    mut tcp: TcpStream,
    mut unix: tokio::net::UnixStream,
) -> std::io::Result<()> {
    tokio::io::copy_bidirectional(&mut tcp, &mut unix)
        .await
        .map(|_| ())
}

/// `filament forward <lport> <peer> <rport>`: local TCP listener; every accepted
/// connection opens a fresh L2 stream to `peer:127.0.0.1:rport`.
///
/// WARM-LINK FAST PATH: when a local daemon already holds a link to `peer`, each
/// accepted connection rides it (no establishment) via the control socket. If the
/// daemon can't serve it (no daemon / no warm link / --relay), we fall back to
/// establishing ONE cold link lazily and multiplexing connections over it, the
/// original behavior. The warm path also sidesteps the single-link credit caveat:
/// each connection is an independent stream over the daemon's link.
/// Normalize a device name for self-comparison: lowercase, alphanumerics only, so
/// "pop-os", "popos", and "Pop_OS" all compare equal.
fn norm_device_name(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// True when `peer` names THIS device (its configured name, that name's host part,
/// or the system hostname), so the forward would just loop back to this machine.
fn forward_target_is_self(peer: &str) -> bool {
    let p = norm_device_name(peer);
    if p.is_empty() {
        return false;
    }
    let dn = crate::display_name();
    let host_part = dn.rsplit('@').next().unwrap_or("").to_string();
    // #184: /etc/hostname is UNIX-only; l3::hostname() handles Windows.
    let hostname = crate::l3::hostname();
    [dn.as_str(), host_part.as_str(), hostname.as_str()]
        .iter()
        .any(|c| !c.is_empty() && norm_device_name(c) == p)
}

/// Live per-connection accounting for `forward`, so the user can SEE it working
/// instead of staring at a static "ready" line. Increments on accept, decrements on
/// close (RAII), keeps one updating status line ("N active, M total"), and prints a
/// one-time confirmation on the very first forwarded connection.
struct ForwardActivity {
    active: std::sync::Arc<std::sync::atomic::AtomicU64>,
    total: std::sync::Arc<std::sync::atomic::AtomicU64>,
    first: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// #232/#268: report a peer refusal ONCE. A browser retrying a dead port
    /// would otherwise repeat the same line per connection, and a reason
    /// printed twenty times reads as a storm rather than an explanation.
    refused: std::sync::Arc<std::sync::atomic::AtomicBool>,
    peer: String,
    rport: u16,
}

impl ForwardActivity {
    fn new(peer: &str, rport: u16) -> Self {
        Self {
            active: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            total: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            first: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            refused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            peer: peer.to_string(),
            rport,
        }
    }
    fn line(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        crate::ui::status(&format!(
            "filament: forwarding to {}:{} - {} active, {} total",
            self.peer,
            self.rport,
            self.active.load(Relaxed),
            self.total.load(Relaxed)
        ));
    }
    /// A handle sharing the same counters, for the per-connection tasks.
    fn handle(&self) -> ForwardActivity {
        ForwardActivity {
            active: self.active.clone(),
            total: self.total.clone(),
            first: self.first.clone(),
            refused: self.refused.clone(),
            peer: self.peer.clone(),
            rport: self.rport,
        }
    }

    /// #232/#268: the peer said no, and said why. Surface it.
    ///
    /// Before this, `forward` printed an accept-time line and then nothing: a
    /// refusal reached `Mux::on_close`, which recorded the reason in `close_err`
    /// exactly so a caller could read it, and forward was the one caller that
    /// never did. pty already reads it via `take_close_err`. So this is wiring a
    /// channel that existed, not building one, which is the correction the
    /// reviewer made to my first description of this work.
    fn refused_once(&self, reason: &str) {
        use std::sync::atomic::Ordering::Relaxed;
        if self.refused.swap(true, Relaxed) {
            return;
        }
        crate::ui::critical(&format!(
            "filament: {}:{} refused the connection: {reason}",
            self.peer, self.rport
        ));
    }

    /// Register a newly accepted connection; the returned guard decrements on drop.
    fn begin(&self) -> ConnGuard {
        use std::sync::atomic::Ordering::Relaxed;
        self.total.fetch_add(1, Relaxed);
        self.active.fetch_add(1, Relaxed);
        if !self.first.swap(true, Relaxed) {
            // #232: this used to read "first connection forwarded to X:Y", and it
            // fires on `listener.accept()`, before any l2-open has been sent. On
            // the cold path the peer has not been asked yet; on either path
            // `open_stream` returns as soon as the l2-open frame is WRITTEN, so
            // even that is not proof the peer accepted. The reporter saw
            // "the link is live" printed while curl got an empty reply.
            //
            // Accepting a local connection is true and narrower than the peer
            // forwarding it, so the line now claims only what is known here.
            // Proof of delivery is the first inbound frame, which lives behind
            // `verify_first_frame` on the warm path and behind `serve_stream`'s
            // shared plumbing on the cold one; reporting from there needs an
            // outcome channel that several other callers must NOT inherit, so it
            // is a follow-up rather than a claim made loosely here.
            crate::ui::say(&format!(
                "filament: first connection accepted, opening to {}:{}",
                self.peer, self.rport
            ));
        }
        self.line();
        ConnGuard {
            active: self.active.clone(),
            total: self.total.clone(),
            peer: self.peer.clone(),
            rport: self.rport,
        }
    }
}

struct ConnGuard {
    active: std::sync::Arc<std::sync::atomic::AtomicU64>,
    total: std::sync::Arc<std::sync::atomic::AtomicU64>,
    peer: String,
    rport: u16,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.active.fetch_sub(1, Relaxed);
        crate::ui::status(&format!(
            "filament: forwarding to {}:{} - {} active, {} total",
            self.peer,
            self.rport,
            self.active.load(Relaxed),
            self.total.load(Relaxed)
        ));
    }
}

/// `filament mount <peer> <remote>`: open a mesh-native mount stream to the
/// peer and serve the remote filesystem over the mount protocol. No sshd,
/// no sshfs — the server runs the mount handler on the peer's side of the
/// authenticated mesh stream, and the client drives it via `MountClient`.
///
/// Returns a `MountClient` ready for FUSE or direct operations.
pub async fn mount_cmd(
    server: &str,
    peer: &str,
    relay: bool,
    root: &str,
) -> Result<crate::mount_proto::MountClient> {
    let (t, rx, guard, _diag) = bring_up_to_known(server, peer, relay, "mount").await?;
    guard.forget();
    let mux = Mux::new(t.clone());
    let _pump = tokio::spawn(pump_initiator(rx, mux.clone()));
    let (sid, pipe_rx, caps) = open_mount_stream(&mux, root).await?;
    let client = crate::mount_proto::MountClient::from_mux_v2(t.clone(), sid, pipe_rx, caps);
    Ok(client)
}

pub async fn forward_cmd(
    server: &str,
    lport: u16,
    peer: &str,
    rport: u16,
    relay: bool,
) -> Result<()> {
    // Refuse a forward to THIS device before doing anything: it would just loop back,
    // and the generic "no known device" error hides what actually happened.
    if forward_target_is_self(peer) {
        bail!(
            "filament: '{peer}' is this device - a forward reaches a DIFFERENT machine. \
             Whatever runs on this host's :{rport} is already here as 127.0.0.1:{rport}; \
             point the forward at another peer (see `filament devices`)."
        );
    }
    // Resolve the peer against the paired devices UP FRONT, so an unknown/typo'd
    // target fails immediately with a clear message instead of after a premature
    // "ready" (the warm path used to announce success before ever reaching the peer).
    if !crate::devices_load()
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(peer))
    {
        bail!(
            "filament: no known device named '{peer}'. Add it first with `filament add`, \
             then `filament devices` shows who you can reach."
        );
    }
    // Bind first so a port conflict fails fast, before any network work.
    let listener = match TcpListener::bind(("127.0.0.1", lport)).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            bail!("{}", port_in_use_msg(lport, peer, rport));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            bail!(
                "filament: cannot bind 127.0.0.1:{lport}: permission denied. Local ports below \
                 1024 need root; pick a higher local port (e.g. `filament forward 8{lport:0>3} {peer} {rport}`) \
                 or run with sudo."
            );
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "filament: failed to bind 127.0.0.1:{lport} for forward to {peer}:127.0.0.1:{rport}"
            )));
        }
    };
    crate::ui::say(&format!(
        "filament: forwarding 127.0.0.1:{lport} -> {peer}:127.0.0.1:{rport}"
    ));

    // Ride a local `up` daemon's warm link when one exists (unix control socket):
    // connections are then instant and open NO new presence on the peer (the
    // daemon is the one connected), and the daemon reports its own link state.
    // Probed once, up front.
    #[cfg(unix)]
    let via_daemon = !relay && crate::ctl::daemon_present().await;
    #[cfg(not(unix))]
    let via_daemon = false;
    let warm = via_daemon; // per-connection warm attempts (unix only)

    // Cold link (no daemon): managed by a background task that establishes it,
    // WATCHES its liveness, and reconnects on loss, reporting lost/recovered so a
    // network blip is never silent (the old code held one link and never noticed).
    // Published via a watch channel the accept loop reads. Not started on the warm
    // path (that would create the extra presence we are avoiding).
    let mut cold_rx = if via_daemon {
        // Report the ACTUAL peer link state, not a blanket "ready". The daemon may
        // hold a live warm link (then connections really are instant) or none yet
        // (then it opens on the first connection) - saying "ready, instant" in the
        // second case is what left the user unsure whether it was forwarding.
        match crate::ctl::try_ping(peer).await {
            Some(facts) => {
                let route = facts["route"].as_str().unwrap_or("link");
                crate::ui::say(&format!(
                    "filament: ready - 127.0.0.1:{lport} -> {peer}:{rport} over the daemon's live {route} link (no extra presence on {peer})"
                ));
            }
            None => {
                crate::ui::say(&format!(
                    "filament: listening on 127.0.0.1:{lport} -> {peer}:{rport} via the local daemon; no live link to {peer} yet - it opens on the first connection (check with `filament reach {peer}`)"
                ));
            }
        }
        None
    } else {
        crate::ui::status(&format!("filament: bringing up the link to {peer} ..."));
        let (tx, mut rx) = tokio::sync::watch::channel::<Option<Arc<Mux>>>(None);
        {
            let (server, peer_s) = (server.to_string(), peer.to_string());
            tokio::spawn(async move { manage_cold_link(server, peer_s, relay, tx).await });
        }
        // Wait for the first link so "ready" is honest.
        while rx.borrow().is_none() {
            if rx.changed().await.is_err() {
                bail!(
                    "filament: could not establish the link to {peer}; is it online? check with `filament reach {peer}` (or `filament devices`)"
                );
            }
        }
        crate::ui::say(&format!(
            "filament: ready, listening on 127.0.0.1:{lport} -> {peer}:{rport} (connect to it to forward; run `filament up` here to avoid a separate presence on {peer})"
        ));
        Some(rx)
    };

    let activity = ForwardActivity::new(peer, rport);
    loop {
        // A transient accept error (e.g. EMFILE/ENFILE under fd pressure) must NOT
        // tear down the listener; back off briefly and keep serving.
        let sock = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                crate::ui::status(&format!("filament: accept paused ({e}), retrying..."));
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        // Warm path: bridge this connection straight to the daemon's link. Retried
        // per connection so it is used whenever the daemon holds a warm link.
        #[cfg(unix)]
        if warm {
            if let Some(usock) = crate::ctl::try_open(peer, rport).await {
                let guard = activity.begin();
                tokio::spawn(async move {
                    let _guard = guard; // decrements + refreshes the activity line on close
                    let _ = bridge_streams(sock, usock).await;
                });
                continue;
            }
            // Warm miss (the daemon has no live link to the peer right now): fall
            // through to a cold link instead of dropping the connection. The cold
            // manager is started once, lazily, and self-heals from there.
        }
        // Cold path (also the warm-miss fallback): ensure the managed cold link
        // exists, then serve over the current live link.
        if cold_rx.is_none() {
            crate::ui::debug(&format!(
                "filament: no warm link to {peer}, using a direct link for forwarding"
            ));
            let (tx, rx) = tokio::sync::watch::channel::<Option<Arc<Mux>>>(None);
            let (server, peer_s) = (server.to_string(), peer.to_string());
            tokio::spawn(async move { manage_cold_link(server, peer_s, relay, tx).await });
            cold_rx = Some(rx);
        }
        let rx = cold_rx.clone().unwrap();
        let guard = activity.begin();
        // #232/#268: a handle sharing the same counters, so the spawned task can
        // report a refusal against this forward's once-only flag.
        let act = activity.handle();
        let peer_c = peer.to_string();
        // Serve this connection, retrying across a reconnect: a link that died in
        // the poll window is skipped (is_alive) and open_stream failures re-wait
        // for the manager's fresh link. On give-up the socket is dropped (closed),
        // but the ACCEPT LOOP ALWAYS SURVIVES -- one connection is never allowed to
        // kill the whole forward (the beta.28/29 regression class).
        tokio::spawn(async move {
            let _guard = guard; // decrements + refreshes the activity line on close
            serve_cold_connection(rx, sock, rport, peer_c, Some(act)).await;
        });
    }
}

/// `filament proxy`: a local SOCKS5 proxy that reaches mesh peers by name with NO
/// TUN and NO privilege (Tailscale's userspace-networking model). A SOCKS5 CONNECT
/// to `<peer>.mesh:<port>` opens an L2 stream to that peer's `localhost:<port>` over
/// filament (warm via a local daemon, else a self-healing cold link); any other
/// host is dialed directly, so the proxy is a drop-in that only diverts `.mesh`.
/// Pure userspace: no CAP_NET_ADMIN, no sudo, works in containers.
///
/// When `--http-port` is set, also runs an HTTP CONNECT proxy + PAC file endpoint
/// on that port for browser/OS proxy config (Tailscale parity).
pub async fn proxy_cmd(
    server: &str,
    bind: &str,
    port: u16,
    http_port: u16,
    relay: bool,
) -> Result<()> {
    let listener = match TcpListener::bind((bind, port)).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            bail!("filament: {bind}:{port} is already in use; pick another with --port");
        }
        Err(e) => {
            return Err(
                anyhow::Error::new(e).context(format!("filament: failed to bind {bind}:{port}"))
            );
        }
    };
    crate::ui::say(&format!(
        "filament: SOCKS5 proxy on {bind}:{port} (no TUN, no sudo)"
    ));
    crate::ui::say(&format!(
        "  point apps here; {}.mesh rides the mesh, everything else connects directly",
        "<peer>"
    ));
    crate::ui::say(&format!(
        "  e.g.  curl --socks5-hostname {bind}:{port} http://<peer>.mesh:8080/"
    ));
    #[cfg(unix)]
    if !crate::ctl::daemon_present().await {
        crate::ui::say(&crate::ui::paint(
            crate::ui::Tone::Dim,
            "  note: no local daemon; each .mesh connection brings up its own link. `filament up` makes them instant.",
        ));
    }
    // Per-peer self-healing cold links, started lazily on first use of a peer (only
    // when the warm daemon path misses), mirroring `forward`'s cold manager.
    let cold: Arc<Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<Arc<Mux>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // HTTP CONNECT proxy + PAC file endpoint (optional).
    if http_port > 0 {
        let http_listener = match TcpListener::bind((bind, http_port)).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                bail!(
                    "filament: {bind}:{http_port} is already in use; pick another with --http-port"
                );
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("filament: failed to bind {bind}:{http_port}")));
            }
        };
        crate::ui::say(&format!(
            "filament: HTTP CONNECT proxy on {bind}:{http_port}"
        ));
        crate::ui::say(&format!(
            "  PAC file: http://127.0.0.1:{http_port}/proxy.pac"
        ));
        crate::ui::say(&format!(
            "  e.g.  curl -x http://127.0.0.1:{http_port} https://<peer>.mesh"
        ));
        let cold_http = cold.clone();
        let server_http = server.to_string();
        tokio::spawn(async move {
            loop {
                let sock = match http_listener.accept().await {
                    Ok((s, _)) => s,
                    Err(e) => {
                        crate::ui::status(&format!(
                            "filament: HTTP accept paused ({e}), retrying..."
                        ));
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let (server, cold) = (server_http.clone(), cold_http.clone());
                tokio::spawn(async move {
                    if let Err(e) = handle_http(sock, &server, port, relay, cold).await {
                        crate::ui::debug(&format!("filament: HTTP proxy connection ended: {e}"));
                    }
                });
            }
        });
    }
    loop {
        let sock = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                crate::ui::status(&format!("filament: accept paused ({e}), retrying..."));
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let (server, cold) = (server.to_string(), cold.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_socks(sock, &server, relay, cold).await {
                crate::ui::debug(&format!("filament: proxy connection ended: {e}"));
            }
        });
    }
}

/// Write a minimal SOCKS5 reply (`code` 0x00 = success) with a zero BND.ADDR/PORT.
async fn socks_reply(sock: &mut TcpStream, code: u8) -> std::io::Result<()> {
    sock.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

/// Handle one SOCKS5 client: no-auth handshake, parse the CONNECT target, then
/// route `<peer>.mesh:<port>` over filament (warm-first, cold fallback) or dial any
/// other host directly. Errors here only affect this one connection.
async fn handle_socks(
    mut sock: TcpStream,
    server: &str,
    relay: bool,
    cold: Arc<Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<Arc<Mux>>>>>>,
) -> Result<()> {
    // Greeting: VER, NMETHODS, METHODS...; we only offer no-auth (0x00).
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    if greet[0] != 0x05 {
        bail!("not a SOCKS5 client");
    }
    let mut methods = vec![0u8; greet[1] as usize];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[0x05, 0x00]).await?;

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT.
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("bad SOCKS5 request");
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut d = vec![0u8; len[0] as usize];
            sock.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        _ => {
            socks_reply(&mut sock, 0x08).await?; // address type not supported
            return Ok(());
        }
    };
    let mut pb = [0u8; 2];
    sock.read_exact(&mut pb).await?;
    let dport = u16::from_be_bytes(pb);
    if req[1] != 0x01 {
        socks_reply(&mut sock, 0x07).await?; // only CONNECT
        return Ok(());
    }

    match host.strip_suffix(".mesh") {
        Some(peer) => {
            let peer = peer.to_string();
            // Warm path: ride the local daemon's live mesh link (instant, no extra
            // presence on the peer).
            #[cfg(unix)]
            if crate::ctl::daemon_present().await {
                // PRIMARY: the L2 loopback open reaches the peer's 127.0.0.1:dport
                // over its opt-in acceptor (unchanged semantics).
                if let Some(usock) = crate::ctl::try_open(&peer, dport).await {
                    socks_reply(&mut sock, 0x00).await?;
                    return bridge_streams(sock, usock).await.map_err(Into::into);
                }
                // FALLBACK: reach a service the peer EXPOSED on its OVERLAY address
                // (which the loopback open can't), and the only path on a userspace
                // node. Tried only after the L2 open misses, so nothing that worked
                // before changes; this only adds reachability to expose'd ports.
                if let Some(usock) = crate::ctl::try_dial(&peer, dport).await {
                    socks_reply(&mut sock, 0x00).await?;
                    return bridge_streams(sock, usock).await.map_err(Into::into);
                }
            }
            // Cold fallback (no daemon, or a warm miss): a per-peer self-healing
            // link, reused across connections.
            let rx = {
                let mut map = cold.lock().await;
                if let Some(rx) = map.get(&peer) {
                    rx.clone()
                } else {
                    let (tx, rx) = tokio::sync::watch::channel::<Option<Arc<Mux>>>(None);
                    let (s, pr) = (server.to_string(), peer.clone());
                    tokio::spawn(async move { manage_cold_link(s, pr, relay, tx).await });
                    map.insert(peer.clone(), rx.clone());
                    rx
                }
            };
            socks_reply(&mut sock, 0x00).await?;
            serve_cold_connection(rx, sock, dport, peer, None).await;
            Ok(())
        }
        None => {
            // Not a mesh name: behave like a plain SOCKS5 proxy (dial directly), so
            // the user can set filament as their one proxy and only .mesh is diverted.
            match TcpStream::connect((host.as_str(), dport)).await {
                Ok(mut up) => {
                    let _ = up.set_nodelay(true);
                    socks_reply(&mut sock, 0x00).await?;
                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut up).await;
                    Ok(())
                }
                Err(_) => {
                    socks_reply(&mut sock, 0x05).await?; // connection refused
                    Ok(())
                }
            }
        }
    }
}

/// Handle one HTTP CONNECT client or PAC file request. Reads the HTTP request,
/// routes CONNECT through the mesh, or serves the PAC file for browser config.
async fn handle_http(
    mut sock: TcpStream,
    server: &str,
    socks_port: u16,
    relay: bool,
    cold: Arc<Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<Arc<Mux>>>>>>,
) -> Result<()> {
    // Read the HTTP request line + headers until empty line.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1];
    loop {
        sock.read_exact(&mut tmp).await?;
        buf.push(tmp[0]);
        // Check for \r\n\r\n (end of headers).
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            bail!("HTTP request too large");
        }
    }
    let request = String::from_utf8_lossy(&buf);
    let first_line = request.lines().next().unwrap_or("");

    // Parse: METHOD PATH HTTP/1.x
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTP CONNECT proxy: CONNECT host:port HTTP/1.1
        let host_port = path;
        let (host, dport) = if let Some(colon) = host_port.rfind(':') {
            let h = &host_port[..colon];
            let p: u16 = host_port[colon + 1..].parse().unwrap_or(0);
            (h.to_string(), p)
        } else {
            (host_port.to_string(), 80)
        };

        match host.strip_suffix(".mesh") {
            Some(peer) => {
                let peer = peer.to_string();
                // Warm path: ride the local daemon's live mesh link.
                #[cfg(unix)]
                if crate::ctl::daemon_present().await {
                    if let Some(usock) = crate::ctl::try_open(&peer, dport).await {
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await;
                        return bridge_streams(sock, usock).await.map_err(Into::into);
                    }
                    if let Some(usock) = crate::ctl::try_dial(&peer, dport).await {
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await;
                        return bridge_streams(sock, usock).await.map_err(Into::into);
                    }
                }
                // Cold fallback.
                let rx = {
                    let mut map = cold.lock().await;
                    if let Some(rx) = map.get(&peer) {
                        rx.clone()
                    } else {
                        let (tx, rx) = tokio::sync::watch::channel::<Option<Arc<Mux>>>(None);
                        let (s, pr) = (server.to_string(), peer.clone());
                        tokio::spawn(async move { manage_cold_link(s, pr, relay, tx).await });
                        map.insert(peer.clone(), rx.clone());
                        rx
                    }
                };
                let _ = sock
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                serve_cold_connection(rx, sock, dport, peer, None).await;
                Ok(())
            }
            None => {
                // Not a mesh name: dial directly.
                match TcpStream::connect((host.as_str(), dport)).await {
                    Ok(mut up) => {
                        let _ = up.set_nodelay(true);
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await;
                        let _ = tokio::io::copy_bidirectional(&mut sock, &mut up).await;
                        Ok(())
                    }
                    Err(_) => {
                        let _ = sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        Ok(())
                    }
                }
            }
        }
    } else if path == "/proxy.pac" || path == "/wpad.dat" {
        // Serve PAC file for browser/OS proxy config.
        let pac = format!(
            r#"function FindProxyForURL(url, host) {{
    if (dnsDomainIs(host, ".mesh") || shExpMatch(host, "*.mesh")) {{
        return "SOCKS5 127.0.0.1:{socks_port}; DIRECT";
    }}
    return "DIRECT";
}}
"#
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/x-ns-proxy-autoconfig\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            pac.len(),
            pac
        );
        let _ = sock.write_all(response.as_bytes()).await;
        Ok(())
    } else {
        // Unknown HTTP request: return 404.
        let response = "HTTP/1.1 404 Not Found\r\n\
                         Content-Length: 0\r\n\
                         Connection: close\r\n\
                         \r\n";
        let _ = sock.write_all(response.as_bytes()).await;
        Ok(())
    }
}

/// Serve one accepted forward connection over the managed cold link, tolerant of
/// a link blip: wait for a LIVE mux (skipping a stale dead one still parked in the
/// channel), open a stream, and on a transient open failure re-wait for the
/// manager's reconnected link (bounded). Never propagates errors to the accept
/// loop; on give-up it just drops `sock`.
async fn serve_cold_connection(
    mut rx: tokio::sync::watch::Receiver<Option<Arc<Mux>>>,
    sock: TcpStream,
    rport: u16,
    peer: String,
    // #232/#268: Some for `forward`, whose user is watching a terminal and needs
    // to know the peer refused. None for the proxy paths, which serve many
    // callers and have no single console to narrate to.
    activity: Option<ForwardActivity>,
) {
    let mut tries = 0u32;
    loop {
        // Wait for a live link (a dead mux may still be parked until the manager's
        // ~1s poll republishes; is_alive() skips it so we never open on a corpse).
        let mux = loop {
            let cur = rx.borrow_and_update().clone();
            match cur {
                Some(m) if m.transport().is_alive() => break m,
                _ => {
                    if rx.changed().await.is_err() {
                        return; // manager gone; drop this socket (listener lives on)
                    }
                }
            }
        };
        match open_stream(&mux, rport).await {
            Ok((sid, rx_pipe)) => {
                serve_stream(mux.clone(), sid, sock, rx_pipe, true, None, None).await;
                // The acceptor's `l2-close{err}` landed in `close_err` before the
                // pipe was dropped (on_close orders it that way deliberately), so
                // by the time serve_stream returns the reason is already there if
                // there is one. A clean end leaves None and prints nothing.
                if let (Some(a), Some(reason)) = (&activity, mux.take_close_err(sid).await) {
                    a.refused_once(&reason);
                }
                return;
            }
            Err(_) => {
                tries += 1;
                if tries >= 3 {
                    // #232: the client is staring at an empty reply, so this is
                    // not a debug detail. It was invisible at the default level,
                    // which is why the only thing the user saw was the premature
                    // success line above.
                    crate::ui::critical(&format!(
                        "filament: could not open a stream to {peer} after 3 tries; this connection was dropped (the forward stays up)"
                    ));
                    return; // drop sock; accept loop keeps running
                }
                // The link died between the liveness check and open_stream; loop
                // back to wait for the manager to publish a fresh one.
            }
        }
    }
}

/// Own the cold forward link end to end: establish it, publish it to the accept
/// loop, watch its liveness, and reconnect on loss, narrating each transition so
/// a network blip is visible (mirrors the `up` daemon's lost/recovered UX). Never
/// returns while the watch receiver is live; a send error means the forward
/// command exited, so the manager stops.
async fn manage_cold_link(
    server: String,
    peer: String,
    relay: bool,
    tx: tokio::sync::watch::Sender<Option<Arc<Mux>>>,
) {
    let mut backoff_ms = 500u64;
    let mut had_link = false; // distinguishes first bring-up from a recovery
    loop {
        // (Re)establish. Transient states (retrying / reconnecting) update ONE
        // status line in place via ui::status; only real transitions (recovered)
        // print a permanent line via ui::say, which clears the live status line.
        let mux = match bring_up_to_known(&server, &peer, relay, "init").await {
            Ok((t, rx, guard, mut diag)) => {
                guard.forget();
                diag.up("tunnel", "datachannel-or-direct");
                let m = Mux::new(t);
                tokio::spawn(pump_initiator(rx, m.clone()));
                m
            }
            Err(e) => {
                crate::ui::status(&format!(
                    "filament: reaching {peer} failed ({e}), retrying..."
                ));
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(8000);
                continue;
            }
        };
        backoff_ms = 500;
        if had_link {
            crate::ui::say(&format!("filament: link to {peer} recovered"));
        }
        had_link = true;
        if tx.send(Some(mux.clone())).is_err() {
            return; // forward command gone
        }
        // Watch liveness; a dead transport means the link dropped under us.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if tx.is_closed() {
                return;
            }
            if !mux.transport().is_alive() {
                crate::ui::status(&format!("filament: link to {peer} lost, reconnecting..."));
                let _ = tx.send(None);
                break;
            }
        }
    }
}

/// Seamless-shell bootstrap (initiator): over the already-authenticated filament
/// channel, hand the acceptor our managed pubkey and fetch its host keys, so a
/// user with ZERO ssh setup gets a no-prompt shell. The exchange is pure control
/// JSON over the transport `bring_up_to_known` returns (no mux needed).
///
/// Returns `Ok(hostkeys)` on grant (the acceptor installed our key); the caller
/// pins the host keys and spawns ssh. Returns `Err` if the acceptor DENIES (the
/// device lacks the `shell` cap) or times out, in which case the caller MUST NOT
/// fall through to a key-less ssh attempt (that would be a muddy auth failure
/// instead of a clear "zero shell" denial).
/// Result of installing our managed key on a peer (warm or cold path). `sshd` is
/// the peer's report of whether an sshd is listening on the port `filament shell --ssh`
/// will dial: `Some(true)` reachable, `Some(false)` nothing there (so ssh would
/// fail blindly - caller bails with a clear message), `None` when the peer is an
/// older build that didn't report it (caller proceeds, status unknown).
struct BootstrapInfo {
    hostkeys: Vec<String>,
    user: Option<String>,
    sshd: Option<bool>,
}

async fn shell_bootstrap(
    server: &str,
    peer: &str,
    relay: bool,
    ssh_port: u16,
    cert_only: bool,
) -> Result<BootstrapInfo> {
    // Managed keypair lives under the filament config dir, NEVER ~/.ssh. In
    // cert mode it is NOT generated and NOT offered: `shell --ssh` now
    // authenticates with an ephemeral certificate, so this exchange exists
    // only to learn the peer's host keys and sshd status (the acceptor
    // skips its authorized_keys write on the same flag).
    let pubkey = if cert_only {
        String::new()
    } else {
        crate::sshkeys::ensure_managed_key()?
    };

    // Bound the connect so an unreachable peer fails with a clear, actionable
    // message instead of looping forever (the heartbeat inside reports progress
    // meanwhile). Override with FILAMENT_SSH_CONNECT_SECS.
    let connect_secs: u64 = std::env::var("FILAMENT_SSH_CONNECT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(45);
    let (t, mut rx, guard, mut diag) = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_secs),
        bring_up_to_known(server, peer, relay, "bootstrap"),
    )
    .await
    {
        Ok(inner) => inner?,
        Err(_) => {
            crate::ui::problem(
                &format!("filament shell --ssh: can't reach '{peer}'"),
                &format!(
                    "couldn't establish a link to '{peer}' in {connect_secs}s - it may be offline or unreachable from here."
                ),
                &[
                    format!(
                        "check it's reachable: {}",
                        crate::ui::paint(crate::ui::Tone::Brand, &format!("filament reach {peer}"))
                    ),
                    format!(
                        "diagnose the connect: {}",
                        crate::ui::paint(
                            crate::ui::Tone::Brand,
                            &format!("filament doctor {peer}")
                        )
                    ),
                ],
            );
            std::process::exit(1);
        }
    };
    // The bootstrap rides the bring-up transport directly (pure control JSON, no
    // mux), so the link being usable IS the end of this span. Record `up`; the
    // ssh data link is a SEPARATE netcat span instrumented in its own right.
    diag.up("tunnel", "datachannel-or-direct");
    t.send_control(
        &json!({
            "type": "shell-bootstrap",
            "v": 1,
            "pubkey": pubkey,
            "ssh_port": ssh_port,
            "cert": cert_only
        }),
    )
    .await?;

    // Await the verdict (bounded, a daemon without FILAMENT_L2 / without the cap
    // must not hang us forever). Capture it, then ALWAYS tear this link down
    // BEFORE returning, so the ssh data link (netcat ProxyCommand) is the only
    // boxA peer the acceptor sees, no concurrent same-device supersede churn.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let verdict: Result<BootstrapInfo> = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break Err(anyhow!(
                "shell bootstrap timed out with no answer from '{peer}'. If it is running \
                 `filament up`, the shell acceptor may be off there (`filament up --shell`)."
            ));
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(Ev::Control(_pid, v))) => match v["type"].as_str() {
                // #30: the acceptor challenges us to prove device-key possession
                // before it decides the shell gate. Answer it (shared responder)
                // so our binding is upgraded to Proven; otherwise the acceptor
                // refuses the bootstrap on Inferred ("identity not proven").
                Some("identity-nonce-challenge") => {
                    crate::respond_to_identity_challenge(&t, &v).await;
                    continue;
                }
                // The acceptor SAYS why it refused, in an l2-close `err`. This
                // arm used to fall through to `_ => continue`, so `--ssh` threw
                // that sentence away, spun for the full 20s, and then guessed
                // at a cause: "is '<peer>' running `filament up` with shell
                // access granted?" The plain `filament shell` path surfaces the
                // same message immediately. Same refusal, same wire, two very
                // different errors, and the useless one was on the path a user
                // reaches for when the first attempt fails.
                Some("l2-close") => {
                    if let Some(why) = v["err"].as_str() {
                        break Err(anyhow!("shell refused by '{peer}': {why}"));
                    }
                    continue;
                }
                Some("shell-bootstrap-ack") => {
                    let hostkeys: Vec<String> = v["hostkeys"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|k| k.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    // The acceptor reports the account it installed our key into,
                    // authoritative for the ssh login (see ssh_cmd).
                    let user = v["user"].as_str().map(String::from);
                    // Older acceptors omit `sshd` -> None (unknown, proceed).
                    let sshd = v["sshd"].as_bool();
                    break Ok(BootstrapInfo {
                        hostkeys,
                        user,
                        sshd,
                    });
                }
                Some("shell-bootstrap-deny") => {
                    let why = v["reason"]
                        .as_str()
                        .unwrap_or("shell capability not granted");
                    // Same trap as the non-ssh path: a grant cannot widen an
                    // enrolment ceiling, so do not prescribe one when the
                    // ceiling is the reason.
                    // One reason, one remedy. Appending a grant hint to every
                    // refusal produced "shell serving is off there; run
                    // `filament up --shell` on that device. Run `filament grant
                    // <this-device> shell`" — two instructions, the second
                    // irrelevant to the stated cause. A reason that already
                    // carries its own fix gets no second one bolted on.
                    let fix = if why == crate::capability::CEILING_REASON {
                        format!(
                            " shell is outside this device's invitation ceiling, and a grant cannot widen one. Re-invite with shell: `filament add --for <this-device> --allow shell` on '{peer}'."
                        )
                    } else if why == crate::capability::SHELL_OFF_REASON {
                        String::new()
                    } else {
                        format!(" Run `filament grant <this-device> shell` on '{peer}'.")
                    };
                    break Err(anyhow!("shell refused by '{peer}': {why}.{fix}"));
                }
                _ => continue,
            },
            Ok(Some(_)) => continue, // other events on this link, ignore
            Ok(None) => break Err(anyhow!("channel closed before shell bootstrap completed")),
            Err(_) => continue, // timeout sliver, loop re-checks the deadline
        }
    };

    // Tear down the bootstrap link before the caller opens the ssh data link.
    drop(t);
    guard.close().await;
    verdict
}

/// Install our managed key on `peer`, WARM-first: ask the local `up` daemon to
/// run the `shell-bootstrap` over its already-established link (instant, no cold
/// establish), and fall back to a fresh `shell_bootstrap` on a miss/deny/timeout,
/// under `--relay`, or off-unix. This is what closes the last gap that left
/// `filament shell --ssh` slow while `pty` was already warm: the bootstrap was the only
/// remaining cold establish in the ssh path.
async fn bootstrap_key(
    server: &str,
    peer: &str,
    relay: bool,
    ssh_port: u16,
    cert_only: bool,
) -> Result<BootstrapInfo> {
    #[cfg(unix)]
    if !relay && !cert_only {
        let pubkey = crate::sshkeys::ensure_managed_key()?;
        if let Some(v) = crate::ctl::try_bootstrap(peer, &pubkey, ssh_port).await {
            let hostkeys: Vec<String> = v["hostkeys"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if !hostkeys.is_empty() {
                crate::ui::trace(&format!(
                    "filament: reusing warm link to '{peer}' for ssh bootstrap (no establish)"
                ));
                return Ok(BootstrapInfo {
                    hostkeys,
                    user: v["user"].as_str().map(String::from),
                    sshd: v["sshd"].as_bool(),
                });
            }
        }
    }
    shell_bootstrap(server, peer, relay, ssh_port, cert_only).await
}

/// The login account for the ssh destination: FILAMENT_SSH_USER wins, else the
/// account the ACCEPTOR installed our key into (from the bootstrap-ack, or the
/// cache), else local $USER, else root. The acceptor's report is authoritative
/// over a local $USER guess, which is usually wrong cross-machine (agboola@laptop
/// vs root@server, the "Permission denied (publickey)" mismatch).
fn resolve_login(remote_user: Option<String>) -> String {
    std::env::var("FILAMENT_SSH_USER")
        .ok()
        .or(remote_user)
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".into())
}

/// Spawn the real `ssh`, pointed EXCLUSIVELY at the ephemeral cert identity
/// (fresh key + B-signed cert) + known_hosts, with a `filament netcat`
/// ProxyCommand. Returns ssh's exit code. The cert is acquired FIRST over a
/// fresh L2 link and the flow fails CLOSED without it (clear error, never a
/// managed-key fallback: silently downgrading would make the CA decorative).
/// The destination is always `<login>@filament-<peer>`.
/// Run the ssh session, preferring the resilient L3 overlay. Both paths use
/// the SAME cert identity; L3 just connects to the stable overlay address
/// directly (no ProxyCommand), so the session survives a link repair.
/// Falls back to the L2 tunnel when L3 isn't viable or its connect fails (255).
/// The ephemeral tmpdir dies with the flow: explicit cleanup is belt, Drop
/// is suspenders, and a signal watchdog covers SIGINT/SIGTERM (process::exit
/// and signals both skip Drop).
async fn run_ssh(
    server: &str,
    peer: &str,
    relay: bool,
    host: &str,
    login: &str,
    rport: u16,
    extra: &[String],
    revive: bool,
) -> Result<i32> {
    // Cert identity first: fresh ephemeral key, B-signed cert over an L2
    // link. Fail closed (no managed-key fallback) when keygen, link, or
    // signing fails -- the error names the cause.
    let eph = crate::ssh_ca::EphemeralKey::generate().await
        .map_err(|e| anyhow::anyhow!("ssh cert setup failed (no key fallback): {e}"))?;
    // Aborted on the normal path below (Drop + explicit cleanup already
    // covered everything else); left running only while ssh owns the session.
    let sigwatch = crate::ssh_ca::spawn_cleanup_on_signal(eph.dir().to_path_buf());
    let ident = crate::ssh_ca::acquire_ssh_cert(server, peer, relay, &eph)
        .await
        .map_err(|e| anyhow::anyhow!("ssh cert issuance failed (no key fallback): {e}"))?;
    #[cfg(not(target_os = "linux"))]
    let _ = revive;
    #[cfg(target_os = "linux")]
    if std::env::var("FILAMENT_NO_L3_SSH").as_deref() != Ok("1") {
        if let Some((mesh_host, addr)) = l3_mesh_addr(peer, rport) {
            // The peer IS on the overlay. PREFER L3 (survives link repairs); only
            // fall to L2 when the overlay genuinely can't carry ssh.
            if probe_sshd(addr, std::time::Duration::from_millis(600)) {
                crate::ui::debug(&format!(
                    "ssh over the L3 overlay ({mesh_host}) - survives link repairs"
                ));
                let code = spawn_ssh_direct(login, &mesh_host, extra, &ident)?;
                if code != 255 {
                    sigwatch.abort();
                    return Ok(code);
                }
                crate::ui::say("filament: L3 ssh failed, falling back to the tunnel");
            } else if revive {
                // The route exists but the overlay path looks dead (a lapsed/zombie
                // transport). Kick the revive nudge in the BACKGROUND and fall back to
                // L2 immediately. The user must never wait the revive ceiling for an
                // interactive ssh; the next ssh will find L3 up if the revive worked.
                crate::ui::say(&format!(
                    "filament: L3 overlay to '{peer}' down, falling back to the tunnel; reviving in background"
                ));
                let peer = peer.to_string();
                tokio::spawn(async move {
                    revive_l3(&peer, rport).await;
                });
            }
            // else (revive=false, e.g. the post-255 re-bootstrap retry): don't pay the
            // revive wait twice - go straight to the L2 tunnel below.
        }
    }
    let code = spawn_ssh(server, peer, relay, host, login, rport, extra, &ident)?;
    sigwatch.abort();
    Ok(code)
}

/// ssh directly to a stable overlay host (no ProxyCommand), reusing the managed
/// key + known_hosts the L2 path uses. The overlay address is cryptographically
/// bound to the peer, so accept-new pins the host key on first use.
#[cfg(target_os = "linux")]
fn spawn_ssh_direct(
    login: &str,
    mesh_host: &str,
    extra: &[String],
    ident: &crate::ssh_ca::CertIdentity,
) -> Result<i32> {
    let kh = crate::sshkeys::known_hosts_path();
    let dest_token = format!("{login}@{mesh_host}");
    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o")
        .arg(format!("IdentityFile={}", ident.key_path.display()))
        .arg("-o")
        .arg(format!("CertificateFile={}", ident.cert_path.display()))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=4");
    let mut split = extra.len();
    for (i, a) in extra.iter().enumerate() {
        if !a.starts_with('-') {
            split = i;
            break;
        }
    }
    for a in &extra[..split] {
        cmd.arg(a);
    }
    cmd.arg(&dest_token);
    for a in &extra[split..] {
        cmd.arg(a);
    }
    Ok(cmd.status()?.code().unwrap_or(1))
}

fn spawn_ssh(
    server: &str,
    peer: &str,
    relay: bool,
    host: &str,
    login: &str,
    rport: u16,
    extra: &[String],
    ident: &crate::ssh_ca::CertIdentity,
) -> Result<i32> {
    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let mut proxy = format!("{exe} --server {server}");
    if relay {
        proxy.push_str(" --relay");
    }
    proxy.push_str(&format!(" forward {peer}:{rport} --stdio"));

    let kh = crate::sshkeys::known_hosts_path();
    let dest_token = format!("{login}@{host}");
    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .arg("-o")
        .arg(format!("IdentityFile={}", ident.key_path.display()))
        .arg("-o")
        .arg(format!("CertificateFile={}", ident.cert_path.display()))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        // Bound the ssh-side connect and detect a dead session, so the data link
        // (the filament netcat ProxyCommand) can't hang ssh indefinitely either.
        .arg("-o")
        .arg("ConnectTimeout=25")
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=3");
    // Split passthrough args into ssh OPTIONS (leading flags) and the remote
    // COMMAND (from the first non-flag token on). The destination is ALWAYS our
    // managed token, inserted BETWEEN options and command, or ssh would mistake
    // the command (e.g. `hostname`) for the host.
    let mut split = extra.len();
    for (i, a) in extra.iter().enumerate() {
        if !a.starts_with('-') {
            split = i;
            break;
        }
    }
    for a in &extra[..split] {
        cmd.arg(a);
    }
    cmd.arg(&dest_token);
    for a in &extra[split..] {
        cmd.arg(a);
    }
    Ok(cmd.status()?.code().unwrap_or(1))
}

/// `filament shell --ssh <peer> [args...]`: seamless shell over the trusted channel.
///
/// With zero pre-existing ssh setup: bootstrap our managed key + the peer's host
/// key over the authenticated filament channel, pin them, then run ssh pointed
/// EXCLUSIVELY at filament-managed material (-o IdentityFile / IdentitiesOnly /
/// UserKnownHostsFile) with a `filament netcat` ProxyCommand. No prompts, no
/// ~/.ssh, no key copying. The bootstrap is the deny-by-default gate: if the
/// peer lacks the `shell` cap we abort HERE, before invoking ssh.
/// Resolve `<peer>.mesh` (the MagicDNS /etc/hosts entry) to its overlay socket
/// address. `Some` iff the peer is on the overlay (has a route); the address is the
/// crypto-derived, STABLE overlay IP (only the transport swaps under it on a
/// repair), so it's a valid target to probe/connect across repairs. `None` means
/// the peer isn't on the mesh at all -> the caller goes straight to the L2 tunnel.
/// (Note: unlike the old `l3_ssh_target`, this does NOT probe here - the caller
/// probes and, if the route is present but dead, REVIVES rather than dumping to L2.)
#[cfg(target_os = "linux")]
fn l3_mesh_addr(peer: &str, port: u16) -> Option<(String, std::net::SocketAddr)> {
    use std::net::ToSocketAddrs;
    let name = format!("{}.mesh", crate::l3::sanitize_host(peer));
    let addr = (name.as_str(), port).to_socket_addrs().ok()?.next()?;
    Some((name, addr))
}

/// Quick reachability probe of an sshd over the overlay: a bounded TCP connect.
#[cfg(target_os = "linux")]
fn probe_sshd(addr: std::net::SocketAddr, to: std::time::Duration) -> bool {
    std::net::TcpStream::connect_timeout(&addr, to).is_ok()
}

/// Nudge the daemon to revive the overlay link to `peer`: a warm-open over the
/// control socket triggers the daemon's verify-before-accept, which drops a zombie
/// link so its re-dial / 8s self-heal rebuilds it (add_peer re-installs the SAME
/// stable overlay IP). The opened stream is discarded - the open itself is the
/// nudge. Bounded (ctl's open has no internal timeout).
#[cfg(target_os = "linux")]
async fn revive_l3(peer: &str, rport: u16) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        crate::ctl::try_open(peer, rport),
    )
    .await;
}

/// How long to wait for the overlay to come back after a revive nudge (default 15s;
/// override with FILAMENT_L3_REVIVE_MS). This is a CEILING, not a fixed wait:
/// Info needed to connect to a peer over SSH (or sshfs/rsync). Returned by
/// `ensure_peer_bootstrap` after key installation + host key pinning.
pub(crate) struct PeerSshInfo {
    pub login: String,
    pub host: String,
    pub rport: u16,
    pub key_path: std::path::PathBuf,
    pub known_hosts_path: std::path::PathBuf,
    pub took_fast_path: bool,
}

/// Ensure our managed key is installed on the peer and host keys are pinned.
/// Returns `PeerSshInfo` with everything needed to spawn sshfs/rsync/ssh.
pub(crate) async fn ensure_peer_bootstrap(
    server: &str,
    peer: &str,
    relay: bool,
) -> Result<PeerSshInfo> {
    let peer = peer.strip_suffix(".mesh").unwrap_or(peer);
    let _host = format!("filament-{peer}");
    let rport: u16 = std::env::var("FILAMENT_SSH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);

    // sshfs/rsync still authenticate with the managed key.
    ensure_peer_bootstrap_port(server, peer, relay, rport, false).await
}

/// Ensure our managed key is installed on the peer with a specific port.
pub(crate) async fn ensure_peer_bootstrap_port(
    server: &str,
    peer: &str,
    relay: bool,
    rport: u16,
    cert_only: bool,
) -> Result<PeerSshInfo> {
    let peer = peer.strip_suffix(".mesh").unwrap_or(peer);
    let host = format!("filament-{peer}");

    let cached = if crate::sshkeys::host_pinned(&host) {
        crate::sshkeys::bootstrap_cache_get(peer)
    } else {
        None
    };

    let (login, took_fast_path) = match cached {
        Some(cached_user) => (resolve_login(cached_user), true),
        None => {
            let info = bootstrap_key(server, peer, relay, rport, cert_only).await?;
            ensure_sshd(peer, rport, info.sshd).await;
            crate::sshkeys::pin_host_keys(&host, &info.hostkeys)?;
            crate::sshkeys::bootstrap_cache_put(peer, info.user.as_deref());
            (resolve_login(info.user), false)
        }
    };

    Ok(PeerSshInfo {
        login,
        host,
        rport,
        key_path: crate::sshkeys::managed_key_path(),
        known_hosts_path: crate::sshkeys::known_hosts_path(),
        took_fast_path,
    })
}

/// Invalidate bootstrap cache and re-bootstrap a peer (for retry after exit 255).
pub(crate) async fn rebootstrap_peer(server: &str, peer: &str, relay: bool) -> Result<PeerSshInfo> {
    let peer = peer.strip_suffix(".mesh").unwrap_or(peer);
    let host = format!("filament-{peer}");
    let rport: u16 = std::env::var("FILAMENT_SSH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);

    crate::sshkeys::bootstrap_cache_clear(peer);
    let info = shell_bootstrap(server, peer, relay, rport, false).await?;
    ensure_sshd(peer, rport, info.sshd).await;
    crate::sshkeys::pin_host_keys(&host, &info.hostkeys)?;
    crate::sshkeys::bootstrap_cache_put(peer, info.user.as_deref());

    Ok(PeerSshInfo {
        login: resolve_login(info.user),
        host,
        rport,
        key_path: crate::sshkeys::managed_key_path(),
        known_hosts_path: crate::sshkeys::known_hosts_path(),
        took_fast_path: false,
    })
}

/// Build ssh option args for use with sshfs/rsync (identity, known_hosts, etc).
pub(crate) fn ssh_transport_args(
    info: &PeerSshInfo,
    server: &str,
    peer: &str,
    relay: bool,
) -> Vec<String> {
    let mut args = vec![
        "-o".into(),
        format!("IdentityFile={}", info.key_path.display()),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", info.known_hosts_path.display()),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=4".into(),
    ];
    let exe = std::env::current_exe().unwrap();
    let exe = exe.to_string_lossy();
    let mut proxy = format!("{exe} --server {server}");
    if relay {
        proxy.push_str(" --relay");
    }
    proxy.push_str(&format!(" forward {peer}:{} --stdio", info.rport));
    args.push("-o".into());
    args.push(format!("ProxyCommand={proxy}"));
    args
}

/// Build the L3 direct destination for sshfs/rsync (login@peer.mesh). The mesh
/// overlay (TUN) and its `.mesh` MagicDNS entries are Linux-only, so on other
/// platforms there is no L3 path: return `None` and let the caller fall back to
/// the L2 tunnel (same semantics as "peer isn't on the mesh").
#[cfg(not(target_os = "linux"))]
pub(crate) fn l3_dest(_info: &PeerSshInfo) -> Option<String> {
    None
}

/// Build the L3 direct destination for sshfs/rsync (login@peer.mesh).
#[cfg(target_os = "linux")]
pub(crate) fn l3_dest(info: &PeerSshInfo) -> Option<String> {
    let peer = info.host.strip_prefix("filament-").unwrap_or(&info.host);
    let (mesh_host, addr) = l3_mesh_addr(peer, info.rport)?;

    // Retry with increasing timeouts (like run_ssh does with revive+poll).
    // A single 600ms probe is too aggressive - overlay may be temporarily slow.
    for attempt in 0..3 {
        if probe_sshd(addr, std::time::Duration::from_millis(1000)) {
            return Some(format!("{}@{mesh_host}", info.login));
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    None
}

pub async fn ssh_cmd(server: &str, peer: &str, extra: &[String], relay: bool) -> Result<()> {
    let peer = peer.strip_suffix(".mesh").unwrap_or(peer);

    // CERT MODE: `shell --ssh` authenticates with an ephemeral certificate,
    // so this bootstrap fetches host keys + sshd status only and installs
    // NOTHING into the peer's authorized_keys.
    let rport: u16 = std::env::var("FILAMENT_SSH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);
    let info = ensure_peer_bootstrap_port(server, peer, relay, rport, true).await?;

    let code = run_ssh(
        server,
        peer,
        relay,
        &info.host,
        &info.login,
        info.rport,
        extra,
        true,
    )
    .await?;

    // A cached skip that failed at the ssh layer (connect/auth, exit 255) may mean
    // the device rotated its key/host-key or revoked the cap. Invalidate, run a
    // real bootstrap, and retry ssh ONCE.
    if code == 255 && info.took_fast_path {
        crate::ui::say(&format!("filament: re-authenticating with '{peer}'..."));
        let retry = rebootstrap_peer(server, peer, relay).await?;
        // revive=false: don't pay the L3 revive-wait twice on the same invocation.
        let code = run_ssh(
            server,
            peer,
            relay,
            &retry.host,
            &retry.login,
            retry.rport,
            extra,
            false,
        )
        .await?;
        ssh_failed_hint(peer, code);
        std::process::exit(code);
    }
    ssh_failed_hint(peer, code);
    std::process::exit(code);
}

/// ssh exit 255 is ssh's own connect/session failure (no sshd reachable, timed
/// out, auth) - distinct from a remote command's non-zero exit. In that case point
/// the user at the filament-native shell, which needs no sshd and survives repairs.
fn ssh_failed_hint(peer: &str, code: i32) {
    if code == 255 {
        crate::ui::say(&crate::ui::paint(
            crate::ui::Tone::Dim,
            &format!(
                "  tip: `filament {peer}` opens a filament shell instead (no sshd needed, survives link repairs)"
            ),
        ));
    }
}

/// Confirm an sshd is reachable on `rport` before spawning ssh, so it fails fast
/// with a clear message instead of hanging on a refused/black-holed connection.
/// A beta.20+ peer already `reported` it in the bootstrap ack; for an older peer
/// (`None`) fall back to a quick client-side probe over the warm link, which works
/// regardless of the peer's version. Only a DEFINITE "no sshd" stops us; an
/// inconclusive probe proceeds (never make ssh worse than before).
async fn ensure_sshd(peer: &str, rport: u16, reported: Option<bool>) {
    let sshd = match reported {
        Some(b) => Some(b),
        #[cfg(unix)]
        None => probe_sshd_warm(peer, rport).await,
        #[cfg(not(unix))]
        None => None,
    };
    if sshd != Some(false) {
        return;
    }
    crate::ui::problem(
        &format!("filament shell --ssh: no sshd on '{peer}'"),
        &format!(
            "'{peer}' is reachable, but nothing is listening on localhost:{rport} for ssh. \
             (sshd may be bound to a non-localhost address like the mesh ULA — \
             `filament shell --ssh` connects to localhost:{rport} on the peer.)",
        ),
        &[
            format!("start an sshd on '{peer}' listening on localhost (or all interfaces)"),
            format!(
                "set {} to a different port",
                crate::ui::paint(crate::ui::Tone::Brand, "FILAMENT_SSH_PORT")
            ),
            format!(
                "use {} for a shell that needs no sshd",
                crate::ui::paint(crate::ui::Tone::Brand, &format!("filament shell {peer}"))
            ),
        ],
    );
    std::process::exit(1);
}

/// Client-side "is there an sshd on `peer:rport`" probe over the daemon's WARM
/// link only (fast, never a cold establish, so it can't hang). Opens one L2
/// stream and reads: an immediate EOF means the acceptor's local dial was refused
/// (no listener); any bytes (the SSH banner) mean a listener is there. No warm
/// link or no banner in time -> `None` (unknown, caller proceeds). Works against
/// any peer version, since it relies only on the old l2-open/l2-close path.
#[cfg(unix)]
async fn probe_sshd_warm(peer: &str, rport: u16) -> Option<bool> {
    use tokio::io::AsyncReadExt;
    let mut s = crate::ctl::try_open(peer, rport).await?;
    let mut buf = [0u8; 8];
    match tokio::time::timeout(std::time::Duration::from_secs(3), s.read(&mut buf)).await {
        Ok(Ok(0)) => Some(false),  // refused: stream closed before any byte
        Ok(Ok(_)) => Some(true),   // a listener answered (sshd banner)
        Ok(Err(_)) => Some(false), // stream error: treat as unreachable
        Err(_) => None,            // no banner in time: inconclusive, don't block
    }
}

#[cfg(test)]
mod h1_tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    /// Minimal in-memory Transport: records control messages, discards frames.
    struct MockTransport {
        controls: StdMutex<Vec<Value>>,
        alive: bool,
        idle: u64,
    }
    impl MockTransport {
        fn new() -> Arc<Self> {
            Self::new_with_alive(true)
        }
        fn new_with_alive(alive: bool) -> Arc<Self> {
            Self::new_with_state(alive, u64::MAX)
        }
        fn new_with_state(alive: bool, idle: u64) -> Arc<Self> {
            Arc::new(MockTransport {
                controls: StdMutex::new(Vec::new()),
                alive,
                idle,
            })
        }
    }
    #[async_trait]
    impl Transport for MockTransport {
        async fn send_control(&self, msg: &Value) -> Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _payload: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
        fn idle_ms(&self) -> u64 {
            self.idle
        }
        fn is_dead(&self) -> bool {
            !self.alive
        }
        fn is_alive(&self) -> bool {
            self.alive
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn stall_observation_reports_dead_transport_down() {
        let dead = MockTransport::new_with_alive(false);
        let (transport_up, _flowed, idle_ms) =
            crate::Conn::stall_observation(Some(dead.as_ref()), &[]);
        assert!(!transport_up, "a dead transport must not be observed as up");
        assert_eq!(
            idle_ms,
            u64::MAX,
            "dead transport must not contribute activity"
        );
    }

    #[test]
    fn stall_observation_uses_oldest_live_activity() {
        let primary = MockTransport::new_with_state(true, 9_000);
        let worker = MockTransport::new_with_state(true, 10);
        let workers: Vec<Arc<dyn Transport>> = vec![worker];
        let (transport_up, flowed, idle_ms) =
            crate::Conn::stall_observation(Some(primary.as_ref()), &workers);
        assert!(transport_up);
        assert!(flowed);
        assert_eq!(
            idle_ms, 9_000,
            "a recently active worker must not mask a stalled primary"
        );
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
            let _rx = mux.register_stream(sid).await.expect("fresh sid registers");
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
            assert_eq!(mux.live_streams().await, 1);
            assert_eq!(mux.resizers.lock().await.len(), 1);
            // Inbound l2-close (browser closed).
            mux.on_close(sid, None).await;
            drop(guard); // session task ending frees the global slot
            assert_eq!(mux.live_streams().await, 0, "stream not freed on l2-close");
            assert_eq!(
                mux.resizers.lock().await.len(),
                0,
                "resizer leaked on l2-close"
            );
        }

        // Path B: session task exit (drop_pty) frees stream + resizer.
        for i in 0..n {
            let sid = L2_SID_BASE | (2000 + i);
            let guard = PtyGuard::try_acquire().expect("slot free");
            let _rx = mux.register_stream(sid).await.expect("fresh sid registers");
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
            mux.drop_pty(sid).await; // a session task own exit path
            drop(guard);
            assert_eq!(mux.live_streams().await, 0, "stream not freed on drop_pty");
            assert_eq!(
                mux.resizers.lock().await.len(),
                0,
                "resizer leaked on drop_pty"
            );
        }

        // Path C: link/mux death (shutdown_all) frees everything.
        let mut guards = Vec::new();
        for i in 0..n {
            let sid = L2_SID_BASE | (3000 + i);
            guards.push(PtyGuard::try_acquire().expect("slot free"));
            let _rx = mux.register_stream(sid).await.expect("fresh sid registers");
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
        }
        assert_eq!(mux.live_streams().await, n as usize);
        mux.shutdown_all().await;
        drop(guards);
        assert_eq!(
            mux.live_streams().await,
            0,
            "streams leaked past shutdown_all"
        );
        assert_eq!(
            mux.resizers.lock().await.len(),
            0,
            "resizers leaked past shutdown_all"
        );

        assert_eq!(
            LIVE_PTYS.load(Ordering::SeqCst),
            start,
            "global PTY count must return to baseline"
        );
    }

    /// A full pipe resets LOUDLY instead of parking the caller: 256 queued
    /// frames fill the pipe without blocking, and the 257th drops the entry
    /// plus an l2-close with the flooded reason. The daemon recv loop calls
    /// on_frame inline, so parking there would freeze every stream (bulk
    /// stdin vs a non-reading child did exactly that); steady consumers
    /// drain continuously and never trip this.
    #[tokio::test]
    async fn on_frame_resets_full_pipe_instead_of_parking() {
        let t = MockTransport::new();
        let mux = Mux::new(t.clone());
        let sid = L2_SID_BASE | 77;
        let _rx = mux.register_stream(sid).await.expect("fresh sid registers");
        // Fill the 256-slot pipe with NOBODY reading (stalled consumer).
        for _ in 0..256 {
            mux.on_frame(sid, bytes::Bytes::from_static(b"x")).await;
        }
        assert!(
            mux.streams.lock().await.contains_key(&sid),
            "a full-but-live pipe stays registered"
        );
        // The 257th frame must reset promptly, never park the caller.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            mux.on_frame(sid, bytes::Bytes::from_static(b"y")),
        )
        .await
        .expect("on_frame never parks, even on a full pipe");
        assert!(
            !mux.streams.lock().await.contains_key(&sid),
            "full pipe resets (drops) the stream"
        );
        let controls = t.controls.lock().unwrap();
        assert!(
            controls.iter().any(|v| v.get("type").and_then(|x| x.as_str())
                == Some("l2-close")
                && v.get("sid").and_then(|x| x.as_u64()) == Some(sid as u64)
                && v
                    .get("err")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .contains("flooded")),
            "reset carries an l2-close naming the flood, got: {controls:?}"
        );
    }

    /// H-1: the per-link stream cap refuses opens beyond MAX_STREAMS_PER_LINK with
    /// an `l2-close{err:"too many streams"}`, and does NOT register the stream.
    #[tokio::test]
    async fn per_link_stream_cap_refuses_over_limit() {
        let mux = Mux::new(MockTransport::new());
        // Fill to the cap with accepted opens (they register pipes).
        for i in 0..MAX_STREAMS_PER_LINK as u32 {
            let sid = L2_SID_BASE | (i + 1);
            match mux.accept_control(&open_msg(sid), true, false).await {
                OpenVerdict::Accept { .. } => {}
                other => panic!(
                    "expected Accept under cap, got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        }
        assert_eq!(mux.live_streams().await, MAX_STREAMS_PER_LINK);
        // One more must be denied with the cap error, leaving the table unchanged.
        let over = L2_SID_BASE | 9999;
        match mux.accept_control(&open_msg(over), true, false).await {
            OpenVerdict::Deny { sid, err } => {
                assert_eq!(sid, over);
                assert_eq!(err, "too many streams");
            }
            other => panic!(
                "expected Deny over cap, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert_eq!(
            mux.live_streams().await,
            MAX_STREAMS_PER_LINK,
            "over-cap open must not register"
        );
        // The denied sid is not stuck in `accepted` (can retry once room frees).
        assert!(!mux.accepted.lock().await.contains_key(&over));
    }

    /// SECURITY (sid collision): a second `register` for an ALREADY-LIVE sid must
    /// be REFUSED (return None), NOT silently overwrite the existing StreamHandle.
    /// An overwrite drops the first handle's read pump WITHOUT abort() (leaking a
    /// parked socket) while `streams.len()` stays flat (defeating the H-1 cap) and
    /// redirects the sid's inbound frames to the new stream. The peer chooses the
    /// sid, so this is a peer-triggerable protocol error, and `register` is the
    /// single structural chokepoint that refuses it.
    #[tokio::test]
    async fn register_refuses_duplicate_live_sid() {
        let mux = Mux::new(MockTransport::new());
        let sid = L2_SID_BASE | 42;
        let mut rx1 = mux.register(sid).await.expect("first register succeeds");
        assert_eq!(mux.live_streams().await, 1);

        // Second register for the SAME live sid is refused (no new channel).
        assert!(
            mux.register(sid).await.is_none(),
            "duplicate register on a live sid must be refused, not overwrite"
        );
        // Table unchanged: still exactly one stream for S.
        assert_eq!(
            mux.live_streams().await,
            1,
            "refused register must not change the table"
        );

        // The ORIGINAL handle is intact: an inbound frame for S still reaches rx1,
        // proving its tx was NOT replaced by a second register's fresh channel.
        mux.on_frame(sid, Bytes::from_static(b"hello")).await;
        match rx1.recv().await {
            Some(Some(bytes)) => assert_eq!(&bytes[..], b"hello"),
            other => panic!("original stream channel broken after refused register: {other:?}"),
        }
    }

    /// SECURITY (cross-stream collision): the exact shipped bug. A pty/mount open
    /// registers a stream at sid S through the bare insert (bypassing the l2-open
    /// `accepted` guard); a later `l2-open` naming the SAME S must be DENIED
    /// ("sid in use") rather than displace the pre-existing stream. `register` is
    /// now the chokepoint so every stream type inherits the protection.
    #[tokio::test]
    async fn accept_control_denies_open_on_live_foreign_sid() {
        let mux = Mux::new(MockTransport::new());
        let sid = L2_SID_BASE | 7;
        // A pty/mount claims S via register_stream (a path that never touches the
        // `accepted` map, so the l2-open acceptor cannot see it there).
        let mut rx_orig = mux
            .register_stream(sid)
            .await
            .expect("first claim succeeds");
        assert_eq!(mux.live_streams().await, 1);

        // A peer now opens an l2 forward naming the SAME sid.
        match mux.accept_control(&open_msg(sid), true, false).await {
            OpenVerdict::Deny { sid: dsid, err } => {
                assert_eq!(dsid, sid);
                assert_eq!(err, "sid in use");
            }
            other => panic!(
                "expected Deny on live-sid reuse, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        // Still exactly one stream, and the colliding open left no `accepted` wedge.
        assert_eq!(
            mux.live_streams().await,
            1,
            "collision must not add or replace a stream"
        );
        assert!(
            !mux.accepted.lock().await.contains_key(&sid),
            "denied open must not wedge `accepted`"
        );
        // The surviving stream is the ORIGINAL: an inbound frame still reaches rx_orig.
        mux.on_frame(sid, Bytes::from_static(b"orig")).await;
        match rx_orig.recv().await {
            Some(Some(b)) => assert_eq!(&b[..], b"orig"),
            other => panic!("original stream displaced by colliding open: {other:?}"),
        }
    }

    /// SECURITY (sid truncation): a wire `sid` that does not fit in u32 must be
    /// REJECTED by `wire_sid`, never truncated. `0x1_8000_0000 as u32 ==
    /// 0x8000_0000` would otherwise pass `is_l2_sid` and alias a legit high-half
    /// sid; a missing sid must be rejected too, never defaulted to 0.
    #[test]
    fn wire_sid_rejects_out_of_range_and_missing() {
        // In range: parsed exactly.
        assert_eq!(
            wire_sid(&json!({ "sid": 0x8000_0000u64 })),
            Some(0x8000_0000)
        );
        assert_eq!(wire_sid(&json!({ "sid": 0u64 })), Some(0));
        assert_eq!(wire_sid(&json!({ "sid": u32::MAX as u64 })), Some(u32::MAX));
        // The aliasing attack value: 0x1_8000_0000 must NOT become 0x8000_0000.
        let attack = 0x1_8000_0000u64;
        assert_eq!(
            attack as u32, 0x8000_0000,
            "precondition: a bare cast truncates"
        );
        assert_eq!(
            wire_sid(&json!({ "sid": attack })),
            None,
            "oversized sid must be refused, not wrapped"
        );
        // Just past the boundary is rejected, not wrapped to 0.
        assert_eq!(wire_sid(&json!({ "sid": (u32::MAX as u64) + 1 })), None);
        // Missing sid: rejected, NOT defaulted to 0.
        assert_eq!(wire_sid(&json!({ "type": "l2-open" })), None);
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
        assert!(
            PtyGuard::try_acquire().is_none(),
            "must refuse at global cap"
        );
        let before = held.len();
        drop(held);
        assert!(LIVE_PTYS.load(Ordering::SeqCst) <= MAX_PTYS_GLOBAL - before.min(1));
    }

    // ---- #4: persistent PTY session ----------------------------------------

    /// A Transport that records every frame's payload (per sid) so a test can
    /// observe what a session actually sent / replayed.
    struct CapTransport {
        frames: StdMutex<Vec<(u32, Vec<u8>)>>,
        controls: StdMutex<Vec<Value>>,
    }
    impl CapTransport {
        fn new() -> Arc<Self> {
            Arc::new(CapTransport {
                frames: StdMutex::new(Vec::new()),
                controls: StdMutex::new(Vec::new()),
            })
        }
        /// All bytes ever sent to `sid`, concatenated in order.
        fn bytes_for(&self, sid: u32) -> Vec<u8> {
            self.frames
                .lock()
                .unwrap()
                .iter()
                .filter(|(s, _)| *s == sid)
                .flat_map(|(_, b)| b.clone())
                .collect()
        }
    }
    #[async_trait]
    impl Transport for CapTransport {
        async fn send_control(&self, msg: &Value) -> Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, sid: u32, _offset: u64, payload: &[u8]) -> Result<()> {
            self.frames.lock().unwrap().push((sid, payload.to_vec()));
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
        fn is_dead(&self) -> bool {
            false
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A transport whose liveness we can flip, to prove the daemon bridge tears
    /// down on transport death (not just on a clean FIN) even with an IDLE client.
    struct KillableTransport {
        alive: std::sync::atomic::AtomicBool,
    }
    impl KillableTransport {
        fn new() -> Arc<Self> {
            Arc::new(KillableTransport {
                alive: std::sync::atomic::AtomicBool::new(true),
            })
        }
        fn kill(&self) {
            self.alive.store(false, Ordering::SeqCst);
        }
    }
    #[async_trait]
    impl Transport for KillableTransport {
        async fn send_control(&self, _msg: &Value) -> Result<()> {
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _payload: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }
        fn is_dead(&self) -> bool {
            !self.alive.load(Ordering::SeqCst)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Regression for the warm-pty deadlock: the daemon bridge (`serve_stream`) must
    /// tear down when the PEER TRANSPORT dies even while the local client is IDLE.
    /// The client->peer reader parks on the silent client socket and never notices
    /// the death; awaiting only that reader (the old code) hung the warm bridge - and
    /// the user's warm pty - until they happened to type. The liveness ticker now
    /// catches it: with an idle client and a killed transport, this returns instead
    /// of blocking forever.
    #[tokio::test]
    async fn serve_stream_tears_down_on_transport_death_with_idle_client() {
        let t = KillableTransport::new();
        let mux = Mux::new(t.clone());
        let sid = L2_SID_BASE | 7;
        let rx = mux.register(sid).await.expect("fresh sid registers");
        // A duplex pair: one half is the bridge's "client socket", the other we keep
        // and NEVER write to, so the reader stays parked (the deadlock precondition).
        let (client, server_side) = tokio::io::duplex(1024);
        let bridge = tokio::spawn(serve_stream(
            mux.clone(),
            sid,
            server_side,
            rx,
            true,
            None,
            None,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await; // let the reader park
        t.kill(); // transport dies with no clean FIN and no client input
        let r = tokio::time::timeout(Duration::from_secs(4), bridge).await;
        assert!(
            r.is_ok(),
            "serve_stream deadlocked on an idle client after transport death"
        );
        drop(client);
    }

    /// `push_ring` keeps the buffer bounded by `cap`, evicting the OLDEST bytes,
    /// and a single oversized write keeps only its trailing `cap` bytes.
    #[test]
    fn ring_buffer_is_bounded_and_keeps_newest() {
        let mut ring = VecDeque::new();
        push_ring(&mut ring, b"hello", 8);
        assert_eq!(ring.iter().copied().collect::<Vec<u8>>(), b"hello");
        // "helloworld!!" is 12 bytes; cap 8 keeps the trailing 8: "oworld!!".
        push_ring(&mut ring, b"world!!", 8);
        assert_eq!(ring.len(), 8);
        assert_eq!(ring.iter().copied().collect::<Vec<u8>>(), b"oworld!!");
    }

    /// A single write LARGER than the cap keeps only its trailing `cap` bytes.
    #[test]
    fn ring_buffer_oversized_write_keeps_tail() {
        let mut ring = VecDeque::new();
        push_ring(&mut ring, b"0123456789", 4);
        assert_eq!(ring.iter().copied().collect::<Vec<u8>>(), b"6789");
    }

    /// End-to-end #4: a session spawned over link A, detached (link A drops),
    /// then REATTACHED over link B with the same session id REPLAYS the buffered
    /// output to link B AND the still-running shell keeps working. Uses `cat` as
    /// the "shell" (it echoes stdin), so input typed after reattach comes back on
    /// link B, proving the SAME process survived the reconnect.
    #[tokio::test]
    async fn session_survives_detach_and_reattaches_with_replay() {
        // `cat` echoes its stdin: a deterministic stand-in for a live shell whose
        // process identity we can verify survived the drop.
        if !std::path::Path::new("/bin/cat").exists() {
            return; // environment without /bin/cat: skip rather than fail
        }
        let sessions = PtySessions::new();
        let ta = CapTransport::new();
        let sid_a = L2_SID_BASE | 1;
        let guard = PtyGuard::try_acquire().expect("slot");
        let sess = spawn_pty_session(
            sessions.clone(),
            "sess-x".to_string(),
            ta.clone(),
            sid_a,
            80,
            24,
            "xterm-256color",
            vec!["/bin/cat".to_string()],
            guard,
            None,
        )
        .await
        .expect("spawn");

        // Type a line on link A; cat echoes it back to sid_a.
        sess.feed_input(b"before-drop\n".to_vec());
        // Give the PTY threads + task a moment to echo and buffer.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let a_out = String::from_utf8_lossy(&ta.bytes_for(sid_a)).to_string();
        assert!(
            a_out.contains("before-drop"),
            "link A never saw the echo: {a_out:?}"
        );

        // Link A drops: detach (the shell MUST keep running).
        sess.detach();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!sess.is_dead(), "detach must NOT kill the session");

        // Reconnect: attach link B with the same session, new sid. The buffer
        // (including "before-drop") replays to sid_b.
        let tb = CapTransport::new();
        let sid_b = L2_SID_BASE | 2;
        let live = sessions
            .get_live("sess-x")
            .await
            .expect("session still live for reattach");
        live.attach(tb.clone(), sid_b);
        tokio::time::sleep(Duration::from_millis(150)).await;
        let b_replay = String::from_utf8_lossy(&tb.bytes_for(sid_b)).to_string();
        assert!(
            b_replay.contains("before-drop"),
            "reattach did not replay buffered output: {b_replay:?}"
        );

        // The SAME shell still works: type after reattach, see it on link B.
        live.feed_input(b"after-reconnect\n".to_vec());
        tokio::time::sleep(Duration::from_millis(200)).await;
        let b_out = String::from_utf8_lossy(&tb.bytes_for(sid_b)).to_string();
        assert!(
            b_out.contains("after-reconnect"),
            "post-reattach input did not echo: {b_out:?}"
        );

        // Explicit end kills the shell and removes the session.
        live.end();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            sessions.get_live("sess-x").await.is_none(),
            "ended session must leave the store"
        );
    }

    /// The `port_in_use_msg` helper must surface the conflicting port and a
    /// `filament forward <lport+1> <peer> <rport>` retry hint, so a user
    /// staring at a "port in use" error can recover in one copy-paste.
    #[test]
    fn port_in_use_msg_names_port_and_suggests_forward() {
        let msg = port_in_use_msg(8080, "laptop", 22);
        assert!(
            msg.contains("8080"),
            "message must name the conflicting port: {msg}"
        );
        assert!(
            msg.contains("filament forward"),
            "message must suggest a filament forward retry: {msg}"
        );
        assert!(
            msg.contains("8081"),
            "suggested port should be lport+1: {msg}"
        );
        assert!(
            msg.contains("laptop"),
            "message should reference the peer: {msg}"
        );
        assert!(
            msg.contains("22"),
            "message should reference the rport: {msg}"
        );
    }

    /// The helper's `saturating_add` must not wrap when lport is u16::MAX, so
    /// the user never sees a suggested port of 0 (which would still be valid
    /// for binding but is a confusing retry hint).
    #[test]
    fn port_in_use_msg_saturates_at_u16_max() {
        let msg = port_in_use_msg(u16::MAX, "laptop", 22);
        assert!(
            msg.contains(&format!("{}", u16::MAX)),
            "must name the conflicting port: {msg}"
        );
        // u16::MAX.saturating_add(1) == u16::MAX, NOT 0.
        assert!(
            !msg.contains("0 "),
            "saturating add must not wrap to 0: {msg}"
        );
    }

    // ---- warm-reuse zombie self-heal (the popos pty/ssh hang) ----------------

    /// THE proof for "filament definitively works no matter what": warm-reuse over
    /// a ZOMBIE held link (alive at QUIC, black-holing new streams: NOTHING ever
    /// arrives inbound) must NOT hang. `open_stream_verified` bails within the
    /// window with an `Err`, removes the half-open stream, and sends an `l2-close`
    /// so the peer reaps its half. The caller (handle_warm_open) then drops the
    /// link and rejects, so the client falls through to a fresh establish.
    /// Crucially it verifies BEFORE the client is committed, so the fallback is
    /// instant - never the 25s ssh-ConnectTimeout stall an accepted-then-dead
    /// connection would cause.
    #[cfg(unix)]
    #[tokio::test]
    async fn warm_reuse_zombie_link_self_heals_instead_of_hanging() {
        let t = CapTransport::new();
        let mux = Mux::new(t.clone());

        let verdict = open_stream_verified(&mux, 22, std::time::Duration::from_millis(50)).await;

        assert!(
            verdict.is_err(),
            "a link that delivers no inbound frame must be a zombie Err"
        );
        assert_eq!(
            mux.live_streams().await,
            0,
            "zombie stream must be removed, not leaked"
        );
        let ctrls = t.controls.lock().unwrap();
        assert!(
            ctrls.iter().any(|c| c["type"] == "l2-open"),
            "must have attempted the open"
        );
        assert!(
            ctrls.iter().any(|c| c["type"] == "l2-close"),
            "must send l2-close so the peer reaps its half of the zombie stream"
        );
    }

    /// The flip side, proving the verify costs the happy path NOTHING and never
    /// false-flags a live link: a HEALTHY link that delivers a first frame within
    /// the window returns `Ok` with that frame preserved, and `serve_verified_stream`
    /// replays it to the client byte-for-byte (no peer bytes lost to the probe).
    #[cfg(unix)]
    #[tokio::test]
    async fn warm_reuse_healthy_link_passes_and_replays_first_frame() {
        let t = CapTransport::new();
        let mux = Mux::new(t.clone());

        // Drive open_stream_verified concurrently; as soon as it registers its
        // stream, deliver the peer's first frame (sshd banner / shell prompt).
        let mux2 = mux.clone();
        let h = tokio::spawn(async move {
            open_stream_verified(&mux2, 22, std::time::Duration::from_secs(5)).await
        });
        let sid = loop {
            if let Some(&sid) = mux.streams.lock().await.keys().next() {
                break sid;
            }
            tokio::task::yield_now().await;
        };
        mux.on_frame(sid, Bytes::from_static(b"BANNER")).await;

        let (got_sid, first, rx) = h
            .await
            .expect("task panicked")
            .expect("healthy link must be Ok");
        assert_eq!(got_sid, sid);
        assert_eq!(
            first,
            Some(Bytes::from_static(b"BANNER")),
            "first frame must be preserved for replay"
        );

        // serve_verified_stream replays `first` to the client verbatim.
        let (mut client, srv) = tokio::io::duplex(1024);
        let mux3 = mux.clone();
        let s = tokio::spawn(async move { serve_verified_stream(mux3, sid, srv, first, rx).await });
        let mut buf = [0u8; 6];
        client
            .read_exact(&mut buf)
            .await
            .expect("replayed frame must reach the client");
        assert_eq!(
            &buf, b"BANNER",
            "the verified first frame must be replayed verbatim"
        );

        mux.on_frame(sid, Bytes::new()).await; // peer FIN closes the writer pump
        drop(client); // client EOF closes the reader pump
        s.await.expect("serve task panicked");
    }

    /// The client-speaks-first case (HTTP, most DB clients): the peer sends NO app
    /// bytes until we do, only the `l2-open-ack` confirming its local connect. Warm
    /// verify must pass on that ack - not hang until the window expires and wrongly
    /// drop a healthy link (the bug that sent every warm `forward` to a cold link) -
    /// and replay it as ZERO bytes so the client sees no spurious data before its own
    /// exchange.
    #[cfg(unix)]
    #[tokio::test]
    async fn warm_reuse_client_first_link_passes_on_open_ack() {
        let t = CapTransport::new();
        let mux = Mux::new(t.clone());

        let mux2 = mux.clone();
        let h = tokio::spawn(async move {
            open_stream_verified(&mux2, 80, std::time::Duration::from_secs(5)).await
        });
        let sid = loop {
            if let Some(&sid) = mux.streams.lock().await.keys().next() {
                break sid;
            }
            tokio::task::yield_now().await;
        };
        // Only the acceptor's connect confirmation arrives - no app data yet.
        mux.on_open_ack(sid).await;

        let (got_sid, first, rx) = h
            .await
            .expect("task panicked")
            .expect("open-ack must prove the link live");
        assert_eq!(got_sid, sid);
        assert_eq!(
            first,
            Some(Bytes::new()),
            "the ack is an empty liveness marker"
        );

        // Replaying the empty ack writes nothing; real app data (sent only after the
        // client would have spoken) still reaches the client intact.
        let (mut client, srv) = tokio::io::duplex(1024);
        let mux3 = mux.clone();
        let s = tokio::spawn(async move { serve_verified_stream(mux3, sid, srv, first, rx).await });
        mux.on_frame(sid, Bytes::from_static(b"HTTP/1.1 200 OK"))
            .await;
        let mut buf = [0u8; 15];
        client
            .read_exact(&mut buf)
            .await
            .expect("real data must reach the client after the empty ack");
        assert_eq!(
            &buf, b"HTTP/1.1 200 OK",
            "the empty ack must not corrupt the stream"
        );

        mux.on_frame(sid, Bytes::new()).await;
        drop(client);
        s.await.expect("serve task panicked");
    }
}
