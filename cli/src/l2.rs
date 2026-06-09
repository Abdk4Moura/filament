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
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
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

/// The multiplexer: routes inbound control/data frames to per-stream pipes and
/// owns stream-id allocation. Transport-agnostic — it rides above the trait.
pub struct Mux {
    transport: Arc<dyn Transport>,
    streams: Mutex<HashMap<u32, StreamHandle>>,
    next_sid: AtomicU32,
    /// Acceptor only: sids we have seen `l2-open` for and accepted, so a late
    /// duplicate open is ignored. (Initiator allocates, so it can't double-open.)
    accepted: Mutex<HashMap<u32, ()>>,
}

impl Mux {
    pub fn new(t: Arc<dyn Transport>) -> Arc<Self> {
        Arc::new(Mux {
            transport: t,
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(L2_SID_BASE),
            accepted: Mutex::new(HashMap::new()),
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

    /// Drop a stream and abort its read pump. Idempotent.
    async fn drop_stream(&self, sid: u32) {
        if let Some(s) = self.streams.lock().await.remove(&sid) {
            if let Some(h) = s.read_pump {
                h.abort();
            }
            // Dropping `s.tx` closes the pipe; the writer pump (dc_to_socket)
            // sees `recv()` return None and shuts the socket down.
        }
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

/// Minimal identity-mode link bring-up to a *known* device, mirroring the
/// production send/recv path but stripped to exactly what L2 needs: join a solo
/// room, subscribe to the device's presence channel, dial it when it appears,
/// and prove our identity (pair-proof) so its `up`/`recv` marks us trusted —
/// which is what unlocks the acceptor's capability gate. Returns the ready
/// Transport plus the event receiver so the caller can pump the mux.
async fn bring_up_to_known(
    server: &str,
    peer_name: &str,
    relay: bool,
) -> Result<(Arc<dyn Transport>, mpsc::UnboundedReceiver<Ev>)> {
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
    sio.emit("subscribe", json!({ "channels": [channel.clone()] })).await.ok();

    let mut my_id: Option<String> = None;
    let mut peer: Option<Arc<Peer>> = None;
    let mut peer_uid: Option<String> = None;
    let mut generation: u32 = 0;

    eprintln!("filament: waiting for known device '{peer_name}'...");

    while let Some(ev) = rx.recv().await {
        match ev {
            Ev::Welcome(v) => {
                my_id = v["id"].as_str().map(|s| s.to_string());
            }
            Ev::KnownPeer(v) => {
                if v["channel"].as_str() != Some(channel.as_str()) {
                    continue;
                }
                if peer.is_some() {
                    continue;
                }
                let pid = match v["id"].as_str() {
                    Some(p) => p.to_string(),
                    None => continue,
                };
                peer_uid = v["uid"].as_str().map(|s| s.to_string());
                let mine = my_id.clone().unwrap_or_default();
                let polite = net::polite_role(&my_uid, peer_uid.as_deref(), &mine, &pid);
                generation += 1;
                let p = Peer::connect(
                    pid, polite, cfg.ice_servers.clone(), relay,
                    sio.clone(), tx.clone(), generation,
                )
                .await?;
                peer = Some(p);
            }
            Ev::Signal(v) => {
                if let Some(p) = &peer {
                    if let Err(e) = p.handle_signal(v["data"].clone()).await {
                        eprintln!("filament: signal: {e}");
                    }
                }
            }
            Ev::ChannelReady(_pid, t) => {
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
                // Keep sio + peer alive for the link's lifetime.
                std::mem::forget(sio);
                if let Some(p) = peer.take() {
                    std::mem::forget(p);
                }
                eprintln!("filament: tunnel up to '{peer_name}'");
                return Ok((t, rx));
            }
            Ev::PcState(_, s) if s == "failed" || s == "closed" => {
                return Err(anyhow!("connection {s} before the tunnel came up"));
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
                eprintln!("filament: tunnel {s} — closing streams");
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
    let (t, rx) = bring_up_to_known(server, peer, relay).await?;
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

/// `filament forward <lport> <peer> <rport>`: local TCP listener; every accepted
/// connection opens a fresh L2 stream to `peer:127.0.0.1:rport`.
pub async fn forward_cmd(server: &str, lport: u16, peer: &str, rport: u16, relay: bool) -> Result<()> {
    let (t, rx) = bring_up_to_known(server, peer, relay).await?;
    let mux = Mux::new(t);
    tokio::spawn(pump_initiator(rx, mux.clone()));

    let listener = TcpListener::bind(("127.0.0.1", lport)).await?;
    eprintln!("filament: forwarding 127.0.0.1:{lport} -> {peer}:127.0.0.1:{rport}");
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

/// `filament ssh <peer> [args...]`: run the user's REAL ssh with our `netcat` as
/// the ProxyCommand, so keys / known_hosts / ~/.ssh/config all work unchanged.
/// The ProxyCommand is built from the current executable and carries --server /
/// --relay so the fresh netcat process hits the same backend and peer.
pub fn ssh_cmd(server: &str, peer: &str, extra: &[String], relay: bool) -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let mut proxy = format!("{exe} --server {server}");
    if relay {
        proxy.push_str(" --relay");
    }
    // ssh substitutes %h (the hostname arg) — but we want the FILAMENT peer name,
    // not whatever host token ssh ends up using, so embed `peer` literally.
    proxy.push_str(&format!(" netcat {peer} 22"));

    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o").arg(format!("ProxyCommand={proxy}"));
    for a in extra {
        cmd.arg(a);
    }
    // ssh needs a destination; if the caller didn't pass one, use the peer name
    // (a harmless placeholder host — ProxyCommand carries the real routing).
    if !extra.iter().any(|a| !a.starts_with('-')) {
        cmd.arg(peer);
    }
    let status = cmd.status()?;
    std::process::exit(status.code().unwrap_or(1));
}
