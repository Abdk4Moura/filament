// Filament CLI — protocol spike.
//
// Goal: prove a Rust client can speak Filament's existing wire protocol
// end-to-end against the unmodified backend:
//   1. Socket.IO signaling (join / welcome / peer-joined / signal)
//   2. Perfect-negotiation roles (impolite = lower uid loses, see politeRole)
//   3. webrtc-rs DataChannel labelled "filament"
//   4. Control JSON (file-offer / file-accept / file-end) + [u32 BE sid] framing
//
// Usage:
//   filament recv <server> <room>
//   filament send <server> <room> <file>
//
// Roles are decided exactly like the browser: polite = myUid > peerUid; the
// impolite peer creates the data channel and the offer.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures_util::FutureExt;
use rust_socketio::asynchronous::{Client, ClientBuilder};
use rust_socketio::{Event, Payload};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

// 60 KiB payload + 4-byte sid header stays under SCTP's default 65535-byte
// max message size (the browser sends 64 KiB + 4 and Chrome accepts it, but
// webrtc-rs enforces the limit strictly on send).
const CHUNK: usize = 60 * 1024;
const HIGH_WATER: usize = 4 * 1024 * 1024;

#[derive(Debug)]
enum Ev {
    Welcome(Value),
    PeerJoined(Value),
    Signal(Value),
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    Send,
    Recv,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Mirror of webrtc.js politeRole(): prefer stable uids, fall back to sids.
fn polite_role(my_uid: &str, peer_uid: Option<&str>, my_id: &str, peer_id: &str) -> bool {
    match peer_uid {
        Some(p) if p != my_uid => my_uid > p,
        _ => my_id > peer_id,
    }
}

struct PeerState {
    id: String,
    pc: Arc<RTCPeerConnection>,
    pending_candidates: Vec<RTCIceCandidateInit>,
    has_remote: bool,
}

struct App {
    role: Role,
    file: Option<(String, Vec<u8>)>, // (name, bytes) for the sender
    my_uid: String,
    my_id: Mutex<Option<String>>,
    peer: Mutex<Option<PeerState>>,
    recv_bufs: Mutex<HashMap<u32, Vec<u8>>>, // sid -> bytes
    recv_meta: Mutex<HashMap<u32, (String, u64)>>, // sid -> (name, size)
    done: mpsc::UnboundedSender<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: filament recv <server> <room> | filament send <server> <room> <file>";
    let role = match args.get(1).map(|s| s.as_str()) {
        Some("send") => Role::Send,
        Some("recv") => Role::Recv,
        _ => return Err(anyhow!(usage)),
    };
    let server = args.get(2).ok_or_else(|| anyhow!(usage))?.clone();
    let room = args.get(3).ok_or_else(|| anyhow!(usage))?.clone();
    let file = if role == Role::Send {
        let path = args.get(4).ok_or_else(|| anyhow!(usage))?;
        let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file.bin".into());
        println!("[send] {} ({} bytes) sha256={}", name, bytes.len(), sha256_hex(&bytes));
        Some((name, bytes))
    } else {
        None
    };

    // uid convention from the frontend: any unique string works; politeness
    // compares them lexicographically.
    let suffix = std::process::id();
    let my_uid = match role {
        Role::Send => format!("cli-send-{suffix}"),
        Role::Recv => format!("cli-recv-{suffix}"),
    };
    let name = my_uid.clone();

    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<String>();
    let app = Arc::new(App {
        role,
        file,
        my_uid: my_uid.clone(),
        my_id: Mutex::new(None),
        peer: Mutex::new(None),
        recv_bufs: Mutex::new(HashMap::new()),
        recv_meta: Mutex::new(HashMap::new()),
        done: done_tx,
    });

    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
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

    let join_room = room.clone();
    let join_name = name.clone();
    let join_uid = my_uid.clone();
    let sio = ClientBuilder::new(server.as_str())
        .on(Event::Connect, move |_p: Payload, c: Client| {
            let room = join_room.clone();
            let name = join_name.clone();
            let uid = join_uid.clone();
            async move {
                println!("[sio] connected, joining room {room}");
                let _ = c
                    .emit("join", json!({ "room": room, "name": name, "uid": uid }))
                    .await;
            }
            .boxed()
        })
        .on("welcome", fwd(Ev::Welcome, tx.clone()))
        .on("peer-joined", fwd(Ev::PeerJoined, tx.clone()))
        .on("signal", fwd(Ev::Signal, tx.clone()))
        .connect()
        .await
        .context("socket.io connect")?;

    println!("[sio] handshake ok ({server})");

    loop {
        tokio::select! {
            Some(ev) = rx.recv() => handle_event(&app, &sio, ev).await?,
            Some(msg) = done_rx.recv() => {
                println!("{msg}");
                // Give in-flight SCTP/socket writes a beat to flush.
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let _ = sio.disconnect().await;
                return Ok(());
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(120)) => {
                return Err(anyhow!("spike timed out after 120s"));
            }
        }
    }
}

async fn handle_event(app: &Arc<App>, sio: &Client, ev: Ev) -> Result<()> {
    match ev {
        Ev::Welcome(v) => {
            let my_id = v["id"].as_str().unwrap_or_default().to_string();
            println!("[sio] welcome: my sid={my_id}");
            *app.my_id.lock().await = Some(my_id);
            if let Some(peers) = v["peers"].as_array() {
                for p in peers {
                    setup_peer(app, sio, p).await?;
                }
            }
        }
        Ev::PeerJoined(v) => {
            setup_peer(app, sio, &v).await?;
        }
        Ev::Signal(v) => {
            let from = v["from"].as_str().unwrap_or_default().to_string();
            let data = v["data"].clone();
            handle_signal(app, sio, &from, data).await?;
        }
    }
    Ok(())
}

async fn setup_peer(app: &Arc<App>, sio: &Client, p: &Value) -> Result<()> {
    let peer_id = p["id"].as_str().unwrap_or_default().to_string();
    let peer_uid = p["uid"].as_str().map(|s| s.to_string());
    let peer_name = p["name"].as_str().unwrap_or("?").to_string();
    if peer_id.is_empty() {
        return Ok(());
    }
    if app.peer.lock().await.is_some() {
        println!("[peer] ignoring extra peer {peer_name} (spike handles one)");
        return Ok(());
    }
    let my_id = app.my_id.lock().await.clone().unwrap_or_default();
    let polite = polite_role(&app.my_uid, peer_uid.as_deref(), &my_id, &peer_id);
    println!("[peer] {peer_name} ({peer_id}) — I am {}", if polite { "polite" } else { "impolite" });

    let mut m = MediaEngine::default();
    m.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m)?;
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();
    let pc = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await?,
    );

    // Trickle ICE → relay each candidate as the browser does.
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
        pc.on_peer_connection_state_change(Box::new(move |s| {
            println!("[pc] state: {s}");
            Box::pin(async {})
        }));
    }

    if !polite {
        // Impolite peer owns the channel + offer (same as the browser).
        let dc = pc.create_data_channel("filament", None).await?;
        wire_channel(app, dc).await;
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
        let app2 = app.clone();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let app2 = app2.clone();
            Box::pin(async move {
                wire_channel(&app2, dc).await;
            })
        }));
    }

    *app.peer.lock().await = Some(PeerState {
        id: peer_id,
        pc,
        pending_candidates: Vec::new(),
        has_remote: false,
    });
    Ok(())
}

async fn handle_signal(app: &Arc<App>, sio: &Client, from: &str, data: Value) -> Result<()> {
    let mut guard = app.peer.lock().await;
    let peer = match guard.as_mut() {
        Some(p) if p.id == from => p,
        _ => {
            println!("[signal] from unknown sid {from}, ignoring");
            return Ok(());
        }
    };
    match data["type"].as_str() {
        Some("description") => {
            let desc: RTCSessionDescription = serde_json::from_value(data["description"].clone())
                .context("parse remote description")?;
            let is_offer = desc.sdp_type.to_string() == "offer";
            peer.pc.set_remote_description(desc).await?;
            peer.has_remote = true;
            for c in peer.pending_candidates.drain(..) {
                if let Err(e) = peer.pc.add_ice_candidate(c).await {
                    println!("[ice] queued candidate failed: {e}");
                }
            }
            if is_offer {
                let answer = peer.pc.create_answer(None).await?;
                peer.pc.set_local_description(answer).await?;
                let ld = peer
                    .pc
                    .local_description()
                    .await
                    .ok_or_else(|| anyhow!("no local description"))?;
                sio.emit(
                    "signal",
                    json!({ "to": peer.id, "data": { "type": "description", "description": ld } }),
                )
                .await
                .ok();
            }
        }
        Some("candidate") => {
            let init: RTCIceCandidateInit = serde_json::from_value(data["candidate"].clone())
                .context("parse candidate")?;
            if peer.has_remote {
                if let Err(e) = peer.pc.add_ice_candidate(init).await {
                    println!("[ice] addIceCandidate failed: {e}");
                }
            } else {
                peer.pending_candidates.push(init);
            }
        }
        other => println!("[signal] unknown type {other:?}"),
    }
    Ok(())
}

async fn wire_channel(app: &Arc<App>, dc: Arc<RTCDataChannel>) {
    println!("[dc] channel '{}' wired", dc.label());

    // on_open: the sender offers its file, exactly like sendFiles() in webrtc.js.
    {
        let app = app.clone();
        let dc2 = dc.clone();
        dc.on_open(Box::new(move || {
            let app = app.clone();
            let dc2 = dc2.clone();
            Box::pin(async move {
                println!("[dc] open");
                if app.role == Role::Send {
                    if let Some((name, bytes)) = &app.file {
                        let offer = json!({
                            "type": "file-offer",
                            "id": "t1-cli",
                            "sid": 1,
                            "name": name,
                            "size": bytes.len(),
                            "mime": "application/octet-stream",
                        });
                        let _ = dc2.send_text(offer.to_string()).await;
                        println!("[send] offered {name}");
                    }
                }
            })
        }));
    }

    // on_message: control JSON (text) or [u32 sid][payload] frames (binary).
    {
        let app = app.clone();
        let dc2 = dc.clone();
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let app = app.clone();
            let dc2 = dc2.clone();
            Box::pin(async move {
                if msg.is_string {
                    let text = String::from_utf8_lossy(&msg.data).into_owned();
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    handle_control(&app, &dc2, v).await;
                } else {
                    handle_chunk(&app, &msg.data).await;
                }
            })
        }));
    }
}

async fn handle_control(app: &Arc<App>, dc: &Arc<RTCDataChannel>, v: Value) {
    match v["type"].as_str() {
        Some("file-offer") if app.role == Role::Recv => {
            let sid = v["sid"].as_u64().unwrap_or(0) as u32;
            let name = v["name"].as_str().unwrap_or("file.bin").to_string();
            let size = v["size"].as_u64().unwrap_or(0);
            println!("[recv] offered {name} ({size} bytes), accepting");
            app.recv_bufs.lock().await.insert(sid, Vec::with_capacity(size as usize));
            app.recv_meta.lock().await.insert(sid, (name, size));
            let accept = json!({ "type": "file-accept", "id": v["id"], "offset": 0 });
            let _ = dc.send_text(accept.to_string()).await;
        }
        Some("file-accept") if app.role == Role::Send => {
            let offset = v["offset"].as_u64().unwrap_or(0) as usize;
            println!("[send] accepted at offset {offset}, streaming");
            let app = app.clone();
            let dc = dc.clone();
            let id = v["id"].clone();
            tokio::spawn(async move {
                if let Err(e) = stream_file(&app, &dc, id, offset).await {
                    println!("[send] stream failed: {e}");
                }
            });
        }
        Some("file-end") if app.role == Role::Recv => {
            let sid = v["sid"].as_u64().unwrap_or(0) as u32;
            let bytes = app.recv_bufs.lock().await.remove(&sid).unwrap_or_default();
            let (name, size) = app
                .recv_meta
                .lock()
                .await
                .remove(&sid)
                .unwrap_or(("file.bin".into(), 0));
            let ok = bytes.len() as u64 == size;
            let out = std::env::temp_dir().join(format!("filament-recv-{name}"));
            let _ = std::fs::write(&out, &bytes);
            let _ = app.done.send(format!(
                "[recv] COMPLETE {} bytes (expected {size}, match={ok}) sha256={} -> {}",
                bytes.len(),
                sha256_hex(&bytes),
                out.display()
            ));
        }
        other => println!("[ctrl] unhandled {other:?}"),
    }
}

async fn handle_chunk(app: &Arc<App>, data: &Bytes) {
    if data.len() < 4 {
        return;
    }
    let sid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let mut bufs = app.recv_bufs.lock().await;
    if let Some(buf) = bufs.get_mut(&sid) {
        buf.extend_from_slice(&data[4..]);
        let len = buf.len();
        drop(bufs);
        if len % (CHUNK * 64) < CHUNK {
            println!("[recv] {len} bytes...");
        }
    }
}

async fn stream_file(app: &Arc<App>, dc: &Arc<RTCDataChannel>, id: Value, start: usize) -> Result<()> {
    let (_name, bytes) = app.file.as_ref().ok_or_else(|| anyhow!("no file"))?;
    let sid: u32 = 1;
    let mut offset = start.min(bytes.len());
    while offset < bytes.len() {
        let end = (offset + CHUNK).min(bytes.len());
        let mut framed = Vec::with_capacity(4 + end - offset);
        framed.extend_from_slice(&sid.to_be_bytes());
        framed.extend_from_slice(&bytes[offset..end]);
        // Backpressure: same high-water idea as the browser's bufferedAmount check.
        while dc.buffered_amount().await > HIGH_WATER {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        dc.send(&Bytes::from(framed)).await?;
        offset = end;
    }
    let end_msg = json!({ "type": "file-end", "id": id, "sid": sid });
    dc.send_text(end_msg.to_string()).await?;
    while dc.buffered_amount().await > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let _ = app
        .done
        .send(format!("[send] COMPLETE {} bytes streamed from offset {start}", bytes.len()));
    Ok(())
}
