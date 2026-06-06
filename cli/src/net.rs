// Networking plumbing: /api config fetch, Socket.IO signaling, the WebRTC
// peer, and the Transport abstraction the transfer logic rides on.
//
// Transport is a trait on purpose: the control protocol (JSON text + sid-framed
// binary) is transport-agnostic. DataChannelTransport is implementation #1;
// a QUIC transport for CLI<->CLI bulk speed slots in later without touching
// the transfer logic.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::FutureExt;
use rust_socketio::asynchronous::{Client, ClientBuilder};
use rust_socketio::{Event as SioEvent, Payload};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// SCTP default max message size is 65535; keep payload + 4-byte header under it.
pub const MAX_DC_PAYLOAD: usize = 60 * 1024;
const HIGH_WATER: usize = 4 * 1024 * 1024;

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
    TransferDone(String),
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

pub struct DataChannelTransport {
    dc: Arc<RTCDataChannel>,
}

#[async_trait]
impl Transport for DataChannelTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        self.dc.send_text(msg.to_string()).await?;
        Ok(())
    }

    async fn send_frame(&self, sid: u32, payload: &[u8]) -> Result<()> {
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&sid.to_be_bytes());
        framed.extend_from_slice(payload);
        while self.dc.buffered_amount().await > HIGH_WATER {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        self.dc.send(&Bytes::from(framed)).await?;
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        while self.dc.buffered_amount().await > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    fn max_payload(&self) -> usize {
        MAX_DC_PAYLOAD
    }
}

// ------------------------------------------------------------- HTTP config --

pub struct ServerConfig {
    pub ice_servers: Vec<RTCIceServer>,
    pub chunk_size: usize,
}

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
    let resp = reqwest::get(url).await.with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("GET {url} -> {}", resp.status()));
    }
    Ok(resp.json().await?)
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
    pub pc: Arc<RTCPeerConnection>,
    state: Mutex<PeerSignalState>,
    sio: Client,
}

struct PeerSignalState {
    pending_candidates: Vec<RTCIceCandidateInit>,
    has_remote: bool,
}

impl Peer {
    /// Build the RTCPeerConnection, wire callbacks into `tx`, and (if impolite)
    /// create the data channel + offer — exactly the browser's PeerLink dance.
    pub async fn connect(
        peer_id: String,
        polite: bool,
        ice_servers: Vec<RTCIceServer>,
        sio: Client,
        tx: mpsc::UnboundedSender<Ev>,
    ) -> Result<Arc<Peer>> {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut m)?;
        let api = APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .build();
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers,
                ..Default::default()
            })
            .await?,
        );

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
            pc.on_peer_connection_state_change(Box::new(move |s| {
                let _ = tx.send(Ev::PcState(s.to_string()));
                Box::pin(async {})
            }));
        }

        if !polite {
            let dc = pc.create_data_channel("filament", None).await?;
            wire_channel(dc, tx.clone());
            let offer = pc.create_offer(None).await?;
            pc.set_local_description(offer).await?;
            let ld = pc
                .local_description()
                .await
                .ok_or_else(|| anyhow!("no local description"))?;
            sio.emit(
                "signal",
                json!({ "to": peer_id, "data": { "type": "description", "description": ld } }),
            )
            .await
            .ok();
        } else {
            let tx = tx.clone();
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                wire_channel(dc, tx.clone());
                Box::pin(async {})
            }));
        }

        Ok(Arc::new(Peer {
            id: peer_id,
            pc,
            state: Mutex::new(PeerSignalState {
                pending_candidates: Vec::new(),
                has_remote: false,
            }),
            sio,
        }))
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
                            json!({ "to": self.id, "data": { "type": "description", "description": ld } }),
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

    /// Which physical path did ICE pick? Mirrors the browser's route badge.
    pub async fn route(&self) -> Option<&'static str> {
        let stats = self.pc.get_stats().await;
        let mut local_type = None;
        let mut remote_type = None;
        for (_k, v) in stats.reports {
            if let webrtc::stats::StatsReportType::CandidatePair(p) = v {
                if p.state == webrtc::ice::candidate::CandidatePairState::Succeeded && p.nominated
                {
                    local_type = Some(p.local_candidate_id.clone());
                    remote_type = Some(p.remote_candidate_id.clone());
                }
            }
        }
        // Candidate ids encode nothing useful by themselves; do a second pass
        // mapping ids -> candidate types.
        if let (Some(lid), Some(rid)) = (local_type, remote_type) {
            let stats = self.pc.get_stats().await;
            let mut lt = String::new();
            let mut rt = String::new();
            for (k, v) in stats.reports {
                match v {
                    webrtc::stats::StatsReportType::LocalCandidate(c) if k == lid => {
                        lt = c.candidate_type.to_string()
                    }
                    webrtc::stats::StatsReportType::RemoteCandidate(c) if k == rid => {
                        rt = c.candidate_type.to_string()
                    }
                    _ => {}
                }
            }
            let route = if lt == "relay" || rt == "relay" {
                "relayed"
            } else if lt == "host" && rt == "host" {
                "local"
            } else {
                "direct"
            };
            return Some(route);
        }
        None
    }
}

fn wire_channel(dc: Arc<RTCDataChannel>, tx: mpsc::UnboundedSender<Ev>) {
    {
        let tx = tx.clone();
        let dc2 = dc.clone();
        dc.on_open(Box::new(move || {
            let transport: Arc<dyn Transport> = Arc::new(DataChannelTransport { dc: dc2.clone() });
            let _ = tx.send(Ev::ChannelReady(transport));
            Box::pin(async {})
        }));
    }
    {
        let tx = tx.clone();
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            if msg.is_string {
                if let Ok(v) = serde_json::from_slice::<Value>(&msg.data) {
                    let _ = tx.send(Ev::Control(v));
                }
            } else if msg.data.len() >= 4 {
                let sid = u32::from_be_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]]);
                let _ = tx.send(Ev::Chunk(sid, msg.data.slice(4..)));
            }
            Box::pin(async {})
        }));
    }
}
