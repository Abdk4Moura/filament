// Networking plumbing: /api config fetch, Socket.IO signaling, the WebRTC
// peer, and the Transport abstraction the transfer logic rides on.
//
// Transport is a trait on purpose: the control protocol (JSON text + sid-framed
// binary) is transport-agnostic. DataChannelTransport is implementation #1;
// a QUIC transport for CLI<->CLI bulk speed slots in later without touching
// the transfer logic.
//
// Resilience parity with the browser (docs/cli-resilience.md):
//   C3 establishment watchdog  -> Peer::connect spawns a 15s timer -> Ev::Stuck
//   C4 transient 'disconnected'-> surfaced as PcState; main loop graces + retries
//   C8a backpressure           -> event-driven via on_buffered_amount_low

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::FutureExt;
use rust_socketio::asynchronous::{Client, ClientBuilder};
use rust_socketio::{Event as SioEvent, Payload};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data::data_channel::DataChannel as RawDataChannel;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// SCTP default max message size is 65535; keep payload + 4-byte header under it.
pub const MAX_DC_PAYLOAD: usize = 60 * 1024;
const HIGH_WATER: usize = 4 * 1024 * 1024;
const LOW_WATER: usize = 1024 * 1024;
pub const WATCHDOG_SECS: u64 = 15;

// ------------------------------------------------------------------ events --

#[derive(Debug)]
pub enum Ev {
    Welcome(Value),
    PeerJoined(Value),
    PeerLeft(Value),
    Signal(Value),
    PairCode(Value),
    PairMatched(Value),
    #[allow(dead_code)] // payload is {code}; senders only need the wake-up
    PairUsed(Value),
    PairError(Value),
    ChannelReady(Arc<dyn Transport>),
    Control(Value),
    Chunk(u32, Bytes),
    PcState(String),
    /// A local outgoing stream finished (sent by the streaming task so the
    /// main loop re-evaluates its all-done exit condition).
    #[allow(dead_code)] // id kept for symmetry with TransferFailed
    TransferDone(String),
    /// A local outgoing stream failed; the transfer stays pending so it can
    /// be re-offered (resume) on the next channel (C10: no process::exit).
    TransferFailed { id: String, err: String },
    /// C3: the establishment watchdog fired for (peer sid, attempt generation).
    Stuck(String, u32),
    /// C4: the 6s disconnected-grace timer expired for (peer sid, generation).
    GraceExpired(String, u32),
}

impl std::fmt::Debug for dyn Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transport")
    }
}

// --------------------------------------------------------------- transport --

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send_control(&self, msg: &Value) -> Result<()>;
    /// Frame and send one chunk: [u32 BE sid][payload]. Applies backpressure.
    async fn send_frame(&self, sid: u32, payload: &[u8]) -> Result<()>;
    /// Resolve once all queued bytes are flushed to the wire.
    async fn flush(&self) -> Result<()>;
    fn max_payload(&self) -> usize;
}

// The channel is DETACHED (SettingEngine::detach_data_channels): webrtc-rs's
// managed read loop has a hardcoded 65535-byte buffer (DATA_CHANNEL_BUFFER_SIZE)
// that an inbound browser frame of 64 KiB + 4 overflows, killing the channel
// (ledger C1). Detaching lets us read with our own 1 MiB buffer, matching the
// `a=max-message-size` we advertise.
const READ_BUF: usize = 1 << 20;

pub struct DataChannelTransport {
    raw: Arc<RawDataChannel>,
    drained: Arc<Notify>,
    dead: Arc<std::sync::atomic::AtomicBool>, // set by the read loop on EOF/error
}

impl DataChannelTransport {
    fn is_dead(&self) -> bool {
        self.dead.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl Transport for DataChannelTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        if self.is_dead() {
            return Err(anyhow!("channel closed"));
        }
        self.raw
            .write_data_channel(&Bytes::from(msg.to_string()), true)
            .await?;
        Ok(())
    }

    async fn send_frame(&self, sid: u32, payload: &[u8]) -> Result<()> {
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&sid.to_be_bytes());
        framed.extend_from_slice(payload);
        // Event-driven backpressure (C8a): park on the buffered-amount-low
        // notification instead of sleep-polling. Re-check after registering
        // to close the notify race. The read loop notifies on death, so a
        // sender parked on a dying channel wakes up and errors out.
        loop {
            if self.is_dead() {
                return Err(anyhow!("channel closed"));
            }
            if self.raw.buffered_amount() <= HIGH_WATER {
                break;
            }
            let notified = self.drained.notified();
            if self.raw.buffered_amount() <= HIGH_WATER {
                break;
            }
            notified.await;
        }
        self.raw
            .write_data_channel(&Bytes::from(framed), false)
            .await?;
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // Tail-drain only; polling is fine for the final few buffers.
        while self.raw.buffered_amount() > 0 {
            if self.is_dead() {
                return Err(anyhow!("channel closed while flushing"));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    fn max_payload(&self) -> usize {
        MAX_DC_PAYLOAD
    }
}

// ------------------------------------------------------------- HTTP config --

#[derive(Clone)]
pub struct ServerConfig {
    pub ice_servers: Vec<RTCIceServer>,
    pub chunk_size: usize,
}

/// C5: callers fetch this fresh before EVERY peer connection — TURN
/// credentials are expiry-stamped HMACs and go stale in long-lived processes.
pub async fn fetch_config(server: &str) -> Result<ServerConfig> {
    let body: Value = http_get_json(&format!("{server}/api/config")).await?;
    let mut ice_servers = Vec::new();
    if let Some(arr) = body["iceServers"].as_array() {
        for s in arr {
            let urls: Vec<String> = match &s["urls"] {
                Value::String(u) => vec![u.clone()],
                Value::Array(us) => us
                    .iter()
                    .filter_map(|u| u.as_str().map(|x| x.to_string()))
                    .collect(),
                _ => continue,
            };
            ice_servers.push(RTCIceServer {
                urls,
                username: s["username"].as_str().unwrap_or_default().to_string(),
                credential: s["credential"].as_str().unwrap_or_default().to_string(),
            });
        }
    }
    let chunk_size = body["chunkSize"].as_u64().unwrap_or(64 * 1024) as usize;
    Ok(ServerConfig {
        ice_servers,
        chunk_size: chunk_size.min(MAX_DC_PAYLOAD),
    })
}

pub async fn fetch_auto_room(server: &str) -> Result<String> {
    let body: Value = http_get_json(&format!("{server}/api/room")).await?;
    body["room"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("no room in /api/room response"))
}

async fn http_get_json(url: &str) -> Result<Value> {
    // rust_socketio already pulls in reqwest; reuse it instead of adding a dep.
    // 3 quick attempts: establish() refetches config per connection attempt
    // (C5), and one blip of the API mustn't kill a transfer in progress.
    let mut last = None;
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        }
        // Explicit timeout: reqwest has none by default, and this is awaited
        // from the event loop — a hung GET must not freeze the process.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        let Ok(client) = client else { continue };
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json().await {
                Ok(v) => return Ok(v),
                Err(e) => last = Some(anyhow!(e)),
            },
            Ok(resp) => last = Some(anyhow!("GET {url} -> {}", resp.status())),
            Err(e) => last = Some(anyhow!(e)),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("GET {url} failed"))).with_context(|| format!("GET {url}"))
}

// ---------------------------------------------------------------- signaling --

pub async fn connect_signaling(server: &str, tx: mpsc::UnboundedSender<Ev>) -> Result<Client> {
    let fwd = |variant: fn(Value) -> Ev, tx: mpsc::UnboundedSender<Ev>| {
        move |payload: Payload, _c: Client| {
            let tx = tx.clone();
            let v = match payload {
                Payload::Text(mut vals) if !vals.is_empty() => Some(vals.remove(0)),
                _ => None,
            };
            async move {
                if let Some(v) = v {
                    let _ = tx.send(variant(v));
                }
            }
            .boxed()
        }
    };

    let sio = ClientBuilder::new(server)
        .reconnect(false)
        .on(SioEvent::Connect, |_p: Payload, _c: Client| async {}.boxed())
        .on("welcome", fwd(Ev::Welcome, tx.clone()))
        .on("peer-joined", fwd(Ev::PeerJoined, tx.clone()))
        .on("peer-left", fwd(Ev::PeerLeft, tx.clone()))
        .on("signal", fwd(Ev::Signal, tx.clone()))
        .on("pair-code", fwd(Ev::PairCode, tx.clone()))
        .on("pair-matched", fwd(Ev::PairMatched, tx.clone()))
        .on("pair-used", fwd(Ev::PairUsed, tx.clone()))
        .on("pair-error", fwd(Ev::PairError, tx.clone()))
        .connect()
        .await
        .with_context(|| format!("socket.io connect to {server}"))?;
    Ok(sio)
}

// --------------------------------------------------------------------- peer --

/// Mirror of webrtc.js politeRole(): prefer stable uids, fall back to sids.
pub fn polite_role(my_uid: &str, peer_uid: Option<&str>, my_id: &str, peer_id: &str) -> bool {
    match peer_uid {
        Some(p) if p != my_uid => my_uid > p,
        _ => my_id > peer_id,
    }
}

pub struct Peer {
    pub id: String,
    pub polite: bool,
    pub pc: Arc<RTCPeerConnection>,
    state: Mutex<PeerSignalState>,
    sio: Client,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

struct PeerSignalState {
    pending_candidates: Vec<RTCIceCandidateInit>,
    has_remote: bool,
}

impl Peer {
    /// Build the RTCPeerConnection, wire callbacks into `tx`, and (if impolite)
    /// create the data channel + offer — exactly the browser's PeerLink dance.
    /// `generation` tags watchdog events so stale timers from torn-down attempts are
    /// ignored by the main loop (C3).
    pub async fn connect(
        peer_id: String,
        polite: bool,
        ice_servers: Vec<RTCIceServer>,
        relay_only: bool,
        sio: Client,
        tx: mpsc::UnboundedSender<Ev>,
        generation: u32,
    ) -> Result<Arc<Peer>> {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut m)?;
        let mut se = SettingEngine::default();
        se.detach_data_channels(); // C1: we run our own read loop (see READ_BUF)
        let api = APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .with_setting_engine(se)
            .build();
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers,
                ice_transport_policy: if relay_only {
                    RTCIceTransportPolicy::Relay
                } else {
                    RTCIceTransportPolicy::All
                },
                ..Default::default()
            })
            .await?,
        );

        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Trickle ICE -> relay each candidate.
        {
            let sio = sio.clone();
            let to = peer_id.clone();
            pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
                let sio = sio.clone();
                let to = to.clone();
                Box::pin(async move {
                    if let Some(c) = c {
                        if let Ok(init) = c.to_json() {
                            let _ = sio
                                .emit(
                                    "signal",
                                    json!({ "to": to, "data": { "type": "candidate", "candidate": init } }),
                                )
                                .await;
                        }
                    }
                })
            }));
        }

        {
            let tx = tx.clone();
            let closed = closed.clone();
            pc.on_peer_connection_state_change(Box::new(move |s| {
                if !closed.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = tx.send(Ev::PcState(s.to_string()));
                }
                Box::pin(async {})
            }));
        }

        if !polite {
            let dc = pc.create_data_channel("filament", None).await?;
            wire_channel(dc, tx.clone(), closed.clone()).await;
            let offer = pc.create_offer(None).await?;
            pc.set_local_description(offer).await?;
            let ld = pc
                .local_description()
                .await
                .ok_or_else(|| anyhow!("no local description"))?;
            sio.emit(
                "signal",
                json!({ "to": peer_id, "data": { "type": "description", "description": advertise_max_message_size(&ld) } }),
            )
            .await
            .ok();
        } else {
            let tx = tx.clone();
            let closed = closed.clone();
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let tx = tx.clone();
                let closed = closed.clone();
                Box::pin(async move {
                    wire_channel(dc, tx, closed).await;
                })
            }));
        }

        // C3: establishment watchdog. ICE only times out once descriptions are
        // exchanged; a lost offer would otherwise mean 'connecting' forever.
        {
            let pc = pc.clone();
            let tx = tx.clone();
            let pid = peer_id.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(WATCHDOG_SECS)).await;
                if !closed.load(std::sync::atomic::Ordering::Relaxed)
                    && pc.connection_state() != RTCPeerConnectionState::Connected
                {
                    let _ = tx.send(Ev::Stuck(pid, generation));
                }
            });
        }

        Ok(Arc::new(Peer {
            id: peer_id,
            polite,
            pc,
            state: Mutex::new(PeerSignalState {
                pending_candidates: Vec::new(),
                has_remote: false,
            }),
            sio,
            closed,
        }))
    }

    pub fn is_connected(&self) -> bool {
        self.pc.connection_state() == RTCPeerConnectionState::Connected
    }

    /// C4: nudge ICE recovery after a transient 'disconnected' (impolite side
    /// only, mirroring the browser).
    pub async fn restart_ice(&self) {
        let _ = self.pc.restart_ice().await;
        // restart_ice marks negotiation needed; drive the new offer ourselves
        // (webrtc-rs has no negotiationneeded auto-loop in this setup).
        if let Ok(offer) = self.pc.create_offer(None).await {
            if self.pc.set_local_description(offer).await.is_ok() {
                if let Some(ld) = self.pc.local_description().await {
                    let _ = self
                        .sio
                        .emit(
                            "signal",
                            json!({ "to": self.id, "data": { "type": "description", "description": advertise_max_message_size(&ld) } }),
                        )
                        .await;
                }
            }
        }
    }

    /// Silence callbacks immediately (synchronous, atomic) so a dying pc
    /// can't spam the event loop (browser fix #3, the CLI flavor).
    pub fn mark_closed(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Tear down. May block on network teardown against an unreachable peer —
    /// callers in the event loop must mark_closed() and spawn this, never
    /// await it inline (gate 11 deadlock).
    pub async fn close(&self) {
        self.mark_closed();
        let _ = self.pc.close().await;
    }

    /// Apply one relayed signal (description or candidate), browser-equivalent
    /// ordering rules: candidates buffer until a remote description lands.
    pub async fn handle_signal(&self, data: Value) -> Result<()> {
        match data["type"].as_str() {
            Some("description") => {
                let desc: RTCSessionDescription =
                    serde_json::from_value(data["description"].clone())
                        .context("parse remote description")?;
                let is_offer = desc.sdp_type.to_string() == "offer";
                self.pc.set_remote_description(desc).await?;
                let pending = {
                    let mut st = self.state.lock().await;
                    st.has_remote = true;
                    std::mem::take(&mut st.pending_candidates)
                };
                for c in pending {
                    if let Err(e) = self.pc.add_ice_candidate(c).await {
                        eprintln!("filament: queued candidate failed: {e}");
                    }
                }
                if is_offer {
                    let answer = self.pc.create_answer(None).await?;
                    self.pc.set_local_description(answer).await?;
                    let ld = self
                        .pc
                        .local_description()
                        .await
                        .ok_or_else(|| anyhow!("no local description"))?;
                    self.sio
                        .emit(
                            "signal",
                            json!({ "to": self.id, "data": { "type": "description", "description": advertise_max_message_size(&ld) } }),
                        )
                        .await
                        .ok();
                }
            }
            Some("candidate") => {
                let init: RTCIceCandidateInit =
                    serde_json::from_value(data["candidate"].clone()).context("parse candidate")?;
                let buffered = {
                    let mut st = self.state.lock().await;
                    if st.has_remote {
                        false
                    } else {
                        st.pending_candidates.push(init.clone());
                        true
                    }
                };
                if !buffered {
                    if let Err(e) = self.pc.add_ice_candidate(init).await {
                        eprintln!("filament: addIceCandidate failed: {e}");
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Which physical path did ICE pick? Same taxonomy as the browser badge.
    /// C2 fix: read the agent's actual selected pair, and classify
    /// local-vs-direct by ADDRESS rather than candidate type — the answering
    /// side often sees its peer as prflx even on the same LAN, and what the
    /// badge promises is "bytes never leave your network", which is an
    /// address property.
    pub async fn route(&self) -> Option<&'static str> {
        let pair = self
            .pc
            .sctp()
            .transport()
            .ice_transport()
            .get_selected_candidate_pair()
            .await?;
        if pair.local.typ == RTCIceCandidateType::Relay
            || pair.remote.typ == RTCIceCandidateType::Relay
        {
            return Some("relayed");
        }
        // Same address on both ends = same machine (loopback via any of its
        // IPs, public included) — bytes never leave the host.
        // "local" when bytes can't leave the machine/network: identical
        // addresses, the remote address being one of THIS host's own
        // addresses (multi-homed same-host pairs select different interfaces
        // nondeterministically), or both ends private.
        let same_host =
            pair.local.address == pair.remote.address || is_own_addr(&pair.remote.address);
        let both_private = is_private_addr(&pair.local.address) && is_private_addr(&pair.remote.address);
        Some(if same_host || both_private { "local" } else { "direct" })
    }
}

/// C1: webrtc-rs never writes `a=max-message-size` into its SDP, so browsers
/// assume the RFC 8841 default of 64K (65536) — and the browser's frame is
/// 64 KiB payload + 4-byte header = 65540, four bytes over, making Chrome's
/// send() throw against a CLI peer. Advertise a roomy limit in the
/// application m-section of every description we relay; datachannel-only SDP
/// has exactly one m-section, so appending is safe. Our own sends stay at
/// 60 KiB regardless.
pub const ADVERTISED_MAX_MESSAGE: u32 = 262144;

fn advertise_max_message_size(desc: &RTCSessionDescription) -> Value {
    let mut sdp = desc.sdp.clone();
    if !sdp.contains("max-message-size") && sdp.contains("m=application") {
        if !sdp.ends_with('\n') {
            sdp.push_str("\r\n");
        }
        sdp.push_str(&format!("a=max-message-size:{ADVERTISED_MAX_MESSAGE}\r\n"));
    }
    json!({ "type": desc.sdp_type.to_string(), "sdp": sdp })
}

/// Is this address one of this host's own? Std-only trick: a UDP socket
/// "connected" to one of our own IPs reports that same IP as its local
/// address (the kernel routes it locally); a genuinely remote IP yields our
/// interface address instead. No packets are sent.
pub fn is_own_addr(addr: &str) -> bool {
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    std::net::UdpSocket::bind(bind)
        .and_then(|s| {
            s.connect((ip, 9))?;
            s.local_addr()
        })
        .map(|la| la.ip() == ip)
        .unwrap_or(false)
}

/// RFC1918/4193 + loopback + link-local — "on your network" for the route badge.
pub fn is_private_addr(addr: &str) -> bool {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                // 100.64/10 (RFC6598 shared/CGNAT): in practice these are
                // overlay networks like Tailscale — bytes stay on your wire.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
        Err(_) => false,
    }
}

async fn wire_channel(
    dc: Arc<RTCDataChannel>,
    tx: mpsc::UnboundedSender<Ev>,
    closed: Arc<std::sync::atomic::AtomicBool>,
) {
    // With detach_data_channels(), on_open still fires but webrtc-rs's
    // managed (65535-byte-buffer) read loop never starts — we detach and run
    // our own with a buffer matching the max-message-size we advertise (C1).
    let dc2 = dc.clone();
    dc.on_open(Box::new(move || {
        let dc2 = dc2.clone();
        let tx = tx.clone();
        let closed = closed.clone();
        Box::pin(async move {
            let raw = match dc2.detach().await {
                Ok(raw) => raw,
                Err(e) => {
                    eprintln!("filament: data channel detach failed: {e}");
                    return;
                }
            };
            let drained = Arc::new(Notify::new());
            let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));

            // C8a: one persistent buffered-amount-low subscription wakes all
            // parked senders.
            raw.set_buffered_amount_low_threshold(LOW_WATER);
            {
                let drained = drained.clone();
                raw.on_buffered_amount_low(Box::new(move || {
                    let drained = drained.clone();
                    Box::pin(async move {
                        drained.notify_waiters();
                    })
                }));
            }

            // Our read loop: text -> Control, binary -> [u32 sid][payload].
            {
                let raw = raw.clone();
                let tx = tx.clone();
                let closed = closed.clone();
                let dead = dead.clone();
                let drained = drained.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; READ_BUF];
                    loop {
                        match raw.read_data_channel(&mut buf).await {
                            Ok((0, _)) | Err(_) => {
                                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                                drained.notify_waiters(); // wake parked senders
                                break;
                            }
                            Ok((n, true)) => {
                                if !closed.load(std::sync::atomic::Ordering::Relaxed) {
                                    if let Ok(v) = serde_json::from_slice::<Value>(&buf[..n]) {
                                        let _ = tx.send(Ev::Control(v));
                                    }
                                }
                            }
                            Ok((n, false)) => {
                                if n >= 4 && !closed.load(std::sync::atomic::Ordering::Relaxed) {
                                    let sid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                                    let _ = tx.send(Ev::Chunk(
                                        sid,
                                        Bytes::copy_from_slice(&buf[4..n]),
                                    ));
                                }
                            }
                        }
                    }
                });
            }

            if !closed.load(std::sync::atomic::Ordering::Relaxed) {
                let transport: Arc<dyn Transport> =
                    Arc::new(DataChannelTransport { raw, drained, dead });
                let _ = tx.send(Ev::ChannelReady(transport));
            }
        })
    }));
}
