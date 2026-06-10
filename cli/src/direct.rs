// Rung-1 DIRECT CLI<->CLI transport over QUIC (quinn).
//
// Why this exists: WebRTC/ICE/STUN/TURN is browser machinery — two CLIs are
// full network stacks and, when either end is directly reachable, should dial
// each other with no relay tax. See docs/design-direct-cli-transport.md (the
// doc proposes Noise-over-TCP; we use QUIC instead: TLS encryption + multiplexed
// streams + connection migration for free).
//
// THE WHOLE PATH IS GATED behind `FILAMENT_DIRECT=1` (see `direct_enabled`).
// Flag OFF ⇒ none of this code runs and the shipped WebRTC path is untouched.
//
// It is purely ADDITIVE: `DirectTransport` is a second `impl Transport`, so the
// transfer + L2 logic ride the SAME trait unchanged. On success the orchestrator
// hands back an `Arc<dyn Transport>` the caller injects as `Ev::ChannelReady`,
// exactly like the DataChannel path.
//
// Security (NON-NEGOTIABLE, must match DTLS — see the module's auth section):
// self-signed certs give an encrypted pipe but ZERO authentication. Trust is
// bound to the PAIR SECRET via an RFC-5705 TLS keying-material exporter: both
// peers derive the same session-unique value, HKDF the pair secret into an
// independent transport key, and exchange+verify an HMAC over (keying material ||
// direction). A relay that terminates TLS on each side gets DIFFERENT keying
// material → the MAC fails → reject + tear down. Wrong secret → MAC fails too.
// Constant-time compare. This is the same channel-binding idea as the C20 DTLS
// fingerprint proof, applied to QUIC.

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use quinn::{Endpoint, RecvStream, SendStream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::net::Transport;

/// Opt-in gate. The ENTIRE direct path is dead unless this is set; default
/// behaviour (WebRTC) is byte-for-byte unchanged. CHECKPOINT before promoting.
pub fn direct_enabled() -> bool {
    std::env::var("FILAMENT_DIRECT").map(|v| v == "1").unwrap_or(false)
}

/// Test-only: force the direct race to fail (simulate a blocked direct path)
/// so the fallback gate can assert WebRTC still completes WITH the flag ON.
/// Not a product knob — only the fallback gate sets it.
fn test_block() -> bool {
    std::env::var("FILAMENT_DIRECT_TEST_BLOCK").map(|v| v == "1").unwrap_or(false)
}

/// Total budget for the whole direct attempt before falling back to WebRTC.
pub const DIRECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// ALPN — distinguishes our QUIC app; both ends must agree.
const ALPN: &[u8] = b"filament-direct/1";

/// Max app payload per send_frame. QUIC streams are byte-streams with no
/// datagram cap, but we keep a chunk size comparable to the DataChannel so the
/// transfer pacing/backpressure logic behaves the same.
pub const MAX_DIRECT_PAYLOAD: usize = 256 * 1024;

// =========================================================== crypto helpers ==

/// Raw-bytes HMAC-SHA256 (the in-tree `hmac_sha256` in main.rs returns hex;
/// HKDF needs raw bytes). Same construction, raw output.
fn hmac_sha256_raw(key: &[u8], msg: &[u8]) -> [u8; 32] {
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
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// HKDF-SHA256 to a 32-byte transport key. The pair secret already keys two
/// other primitives (the C20 proof HMAC and the public channel hash); feeding
/// the raw secret into a third is cross-context reuse. Derive an INDEPENDENT
/// key (design doc §Key derivation). Single-block expand (32B ≤ hashlen).
pub fn transport_key(secret: &str) -> [u8; 32] {
    // Extract: PRK = HMAC(salt=0, ikm=secret)
    let prk = hmac_sha256_raw(&[0u8; 32], secret.as_bytes());
    // Expand: T(1) = HMAC(PRK, info || 0x01)
    let mut info = b"filament-direct-transport-v1".to_vec();
    info.push(0x01);
    hmac_sha256_raw(&prk, &info)
}

/// Constant-time equality (no `subtle` dep). XOR-accumulate; the loop runs the
/// full length regardless of where the first difference is.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ====================================================== candidate gathering ==

/// Every local non-loopback interface IP (v4+v6). Std-only: enumerate by
/// "connecting" UDP sockets to public anchors and reading the chosen local
/// addr (no packets sent). This yields the primary routable v4 and v6 source
/// addresses — the ones a peer on the same LAN / overlay can actually reach.
fn local_ips() -> Vec<IpAddr> {
    let mut out = Vec::new();
    // v4 default route source
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
        if s.connect(("8.8.8.8", 9)).is_ok() {
            if let Ok(la) = s.local_addr() {
                let ip = la.ip();
                if !ip.is_loopback() && !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    // v6 default route source
    if let Ok(s) = UdpSocket::bind("[::]:0") {
        if s.connect(("2001:4860:4860::8888", 9)).is_ok() {
            if let Ok(la) = s.local_addr() {
                let ip = la.ip();
                if !ip.is_loopback() && !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    // Loopback last-resort: same-host gates (and CI) dial 127.0.0.1. Real
    // cross-host pairing ignores it (the peer can't reach our loopback).
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    out.push(lo);
    out
}

/// Public IP for cross-NAT reachability: `FILAMENT_PUBLIC_IP` override wins,
/// else a one-line `GET /api/whoami` echo of CF-Connecting-IP (the droplet is
/// behind Cloudflare; the backend reads that header). Best-effort — failure
/// just means we advertise no public candidate.
async fn public_ip(server: &str) -> Option<IpAddr> {
    if let Ok(v) = std::env::var("FILAMENT_PUBLIC_IP") {
        if let Ok(ip) = v.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }
    let url = format!("{server}/api/whoami");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    v["ip"].as_str()?.trim().parse::<IpAddr>().ok()
}

/// Format an addr as a candidate string; v6 gets brackets so `[ip]:port` parses.
fn cand_str(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

/// Test-only: suppress rung-1's public (`whoami`) candidate. `/api/whoami`
/// returns IP only, NO port — so rung-1 advertises `public_ip:local_port`, which
/// is correct ONLY when the NAT preserves the source port (Linux MASQUERADE in
/// the lab happens to). On the very common NAT that does NOT preserve the port,
/// that guessed candidate is wrong and rung-1's public path fails — which is
/// exactly the class rung-2's STUN-learned srflx (real external port) exists to
/// catch. This knob models that NAT class so the cone gate can exercise rung-2 in
/// isolation. NOT a product knob — only the hole-punch gate sets it.
fn suppress_public() -> bool {
    std::env::var("FILAMENT_DIRECT_NO_PUBLIC").map(|v| v == "1").unwrap_or(false)
}

/// Gather all advertisable candidates for our bound endpoint port.
pub async fn gather_candidates(server: &str, port: u16) -> Vec<String> {
    let mut cands: Vec<String> = local_ips().into_iter().map(|ip| cand_str(ip, port)).collect();
    if !suppress_public() {
        if let Some(pip) = public_ip(server).await {
            let s = cand_str(pip, port);
            if !cands.contains(&s) {
                cands.push(s);
            }
        }
    }
    cands
}

// =============================================================== TLS configs ==

/// Client verifier that accepts ANY server cert. This is SAFE here and ONLY
/// here: authentication does NOT come from the PKI — it comes from the
/// keying-material MAC bound to the pair secret (below). A wrong/forged cert
/// still produces a valid encrypted pipe, but the post-handshake MAC fails
/// unless the peer holds the secret. We deliberately skip CA validation.
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Explicit ring provider — we never rely on a process-default crypto provider
/// (webrtc + reqwest both pull rustls into the tree; the default is ambiguous).
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// rung-2 reuses these QUIC configs verbatim — same ALPN, same accept-any-cert +
/// keying-material auth — only the underlying socket differs (a punched one).
pub(crate) fn server_config() -> Result<quinn::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec!["filament-direct".to_string()])
        .context("self-signed cert")?;
    let cert_der = CertificateDer::from(ck.cert.der().clone());
    let key_der = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());

    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("server tls versions")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .context("server single cert")?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .context("quic server config")?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(qsc)))
}

pub(crate) fn client_config() -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("client tls versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider())))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .context("quic client config")?;
    Ok(quinn::ClientConfig::new(Arc::new(qcc)))
}

/// Bind a quinn endpoint on an EPHEMERAL UDP port that BOTH accepts and dials
/// (simultaneous-open over one socket). Returns the endpoint and its port.
pub fn bind_endpoint() -> Result<(Endpoint, u16)> {
    let mut ep = Endpoint::server(server_config()?, "0.0.0.0:0".parse().unwrap())
        .context("bind quinn endpoint")?;
    ep.set_default_client_config(client_config()?);
    let port = ep.local_addr().context("endpoint local addr")?.port();
    Ok((ep, port))
}

// ====================================================== authenticated handshake

/// 32-byte RFC-5705 exporter value — the session-unique channel binding. A
/// MITM relay terminating TLS on each leg gets a DIFFERENT value, so the MAC it
/// would have to forward cannot validate against its own peer's binding.
fn keying_material(conn: &quinn::Connection) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, b"filament-direct-auth", b"")
        .map_err(|e| anyhow!("export_keying_material failed: {e:?}"))?;
    Ok(out)
}

/// Auth tag: HMAC(transport_key, keying_material || who). `who` direction-tags
/// the tag so each side's tag differs and neither can be reflected back.
fn auth_tag(tkey: &[u8; 32], km: &[u8; 32], who: &str) -> [u8; 32] {
    let mut msg = Vec::with_capacity(32 + 16);
    msg.extend_from_slice(km);
    msg.push(b'|');
    msg.extend_from_slice(who.as_bytes());
    hmac_sha256_raw(tkey, &msg)
}

/// Run the mutual confirm-MAC over a fresh bidirectional QUIC stream BEFORE any
/// transfer byte. Both sides SEND their tag and VERIFY the peer's; mismatch ⇒
/// reject. `is_dialer` only decides the two direction tags (so dialer-tag and
/// acceptor-tag are distinct and can't be reflected). On success the stream is
/// returned for reuse as the control/data stream.
async fn authenticate(
    conn: &quinn::Connection,
    tkey: &[u8; 32],
    is_dialer: bool,
) -> Result<(SendStream, RecvStream)> {
    let km = keying_material(conn)?;
    let (my_who, their_who) = if is_dialer { ("dialer", "acceptor") } else { ("acceptor", "dialer") };
    let my_tag = auth_tag(tkey, &km, my_who);
    let their_expected = auth_tag(tkey, &km, their_who);

    // Dialer opens the auth stream; acceptor accepts it. Deterministic so the
    // two sides never both wait.
    let (mut send, mut recv) = if is_dialer {
        conn.open_bi().await.context("open auth stream")?
    } else {
        conn.accept_bi().await.context("accept auth stream")?
    };

    // Exchange tags. 32-byte fixed frame each way; no length prefix needed.
    send.write_all(&my_tag).await.context("write auth tag")?;
    let mut peer_tag = [0u8; 32];
    recv.read_exact(&mut peer_tag).await.context("read auth tag")?;

    if !ct_eq(&peer_tag, &their_expected) {
        // Don't leak which byte differed; the log marker is for the gates.
        bail!("DIRECT-AUTH-FAIL: pair-secret MAC mismatch — rejecting peer");
    }
    Ok((send, recv))
}

// ============================================================= DirectTransport

/// `impl Transport` over an AUTHENTICATED QUIC connection. Control + data ride
/// ONE bidirectional stream, framed exactly like the DataChannel wire:
///   control = a u32-BE length prefix + JSON text  (distinguished by a tag byte)
///   data    = a u32-BE length prefix + [u32-BE sid][payload]
/// We add a 1-byte kind tag (0=control,1=data) + 4-byte length so the reader
/// can demux a byte-stream back into discrete messages (QUIC has no message
/// boundaries the way SCTP/DataChannel does).
pub struct DirectTransport {
    conn: quinn::Connection,
    send: Arc<Mutex<SendStream>>,
    last_activity: Arc<std::sync::atomic::AtomicU64>,
    dead: Arc<std::sync::atomic::AtomicBool>,
}

const KIND_CONTROL: u8 = 0;
const KIND_DATA: u8 = 1;

fn now_ms() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    EPOCH.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
}

impl DirectTransport {
    /// Frame: [1B kind][4B BE len][payload].
    async fn write_framed(&self, kind: u8, payload: &[u8]) -> Result<()> {
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(anyhow!("direct connection closed"));
        }
        let mut hdr = [0u8; 5];
        hdr[0] = kind;
        hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let mut s = self.send.lock().await;
        // QUIC streams apply flow control internally; write_all parks on the
        // peer's receive window — that IS the backpressure (no manual high-water
        // loop needed). A frozen receiver stalls here, so last_activity stops
        // advancing exactly like the DataChannel path's #28 guard.
        if let Err(e) = s.write_all(&hdr).await {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow!("direct write hdr: {e}"));
        }
        if let Err(e) = s.write_all(payload).await {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow!("direct write body: {e}"));
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for DirectTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        let text = msg.to_string();
        self.write_framed(KIND_CONTROL, text.as_bytes()).await
    }

    async fn send_frame(&self, sid: u32, payload: &[u8]) -> Result<()> {
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&sid.to_be_bytes());
        framed.extend_from_slice(payload);
        self.write_framed(KIND_DATA, &framed).await?;
        self.last_activity.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // Per-file flush (called after every `file-end`). QUIC is ordered and
        // reliable, so file N's buffered tail is delivered before file N+1's
        // bytes with no app-layer action — and we MUST NOT `finish()` here or a
        // multi-file send dies after the first file. The real delivery barrier
        // is in `drain_finish()`, run once at teardown.
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(anyhow!("direct connection closed while flushing"));
        }
        Ok(())
    }

    async fn drain_finish(&self) -> Result<()> {
        // THE cross-machine fix. `write_all` only commits bytes to quinn's send
        // buffer; dropping the connection (process exit after `send`) sends
        // CONNECTION_CLOSE immediately and discards anything not yet acked — on a
        // real WAN that truncates the last file's tail (loopback hid it: the
        // buffer drains before close). quinn's documented barrier: `finish()` the
        // stream (this runs ONLY at final teardown, so ending the send half is
        // correct), then await `stopped()`, which resolves `Ok(None)` once the
        // peer has acknowledged receipt of every byte incl. the FIN.
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(()); // connection already gone — nothing left to drain
        }
        let stopped = {
            let mut s = self.send.lock().await;
            let _ = s.finish(); // harmless if already finished/stopped
            s.stopped()
        };
        // A live-but-slow transfer keeps acks flowing, so this waits exactly as
        // long as delivery needs; a dead peer makes quinn error `stopped()`. The
        // outer wall is only a backstop against a silently half-dead peer so we
        // never hang forever (Ctrl-C also escapes).
        match tokio::time::timeout(std::time::Duration::from_secs(180), stopped).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(anyhow!("direct drain: peer dropped before full ack: {e}")),
            Err(_) => Err(anyhow!("direct drain: timed out after 180s awaiting peer ack")),
        }
    }

    fn max_payload(&self) -> usize {
        MAX_DIRECT_PAYLOAD
    }

    fn idle_ms(&self) -> u64 {
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return u64::MAX;
        }
        let _ = &self.conn; // keep the connection alive for the link's lifetime
        now_ms().saturating_sub(self.last_activity.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// Spawn the read loop that demuxes the authenticated stream back into
/// `Ev::Control` / `Ev::Chunk`, attributed to `peer_id` (same as the
/// DataChannel read loop). Mirrors net.rs::wire_channel's reader.
fn spawn_reader(
    peer_id: String,
    mut recv: RecvStream,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
    last_activity: Arc<std::sync::atomic::AtomicU64>,
    dead: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        loop {
            let mut hdr = [0u8; 5];
            if recv.read_exact(&mut hdr).await.is_err() {
                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
            let kind = hdr[0];
            let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
            // Guard against an absurd length (a corrupt/hostile peer); cap well
            // above MAX_DIRECT_PAYLOAD + the 4-byte sid.
            if len > MAX_DIRECT_PAYLOAD + 64 {
                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
            let mut body = vec![0u8; len];
            if recv.read_exact(&mut body).await.is_err() {
                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
            match kind {
                KIND_CONTROL => {
                    if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                        let _ = tx.send(crate::net::Ev::Control(peer_id.clone(), v));
                    }
                }
                KIND_DATA => {
                    if body.len() >= 4 {
                        last_activity.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
                        let sid = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                        let _ = tx.send(crate::net::Ev::Chunk(
                            peer_id.clone(),
                            sid,
                            bytes::Bytes::copy_from_slice(&body[4..]),
                        ));
                    }
                }
                _ => {}
            }
        }
    });
}

/// Build a `DirectTransport` from an authenticated connection + its auth stream
/// (reused as the control/data stream), wiring the reader into `tx`.
fn make_transport(
    peer_id: String,
    conn: quinn::Connection,
    send: SendStream,
    recv: RecvStream,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
) -> Arc<dyn Transport> {
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(now_ms()));
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    spawn_reader(peer_id, recv, tx, last_activity.clone(), dead.clone());
    Arc::new(DirectTransport {
        conn,
        send: Arc::new(Mutex::new(send)),
        last_activity,
        dead,
    })
}

// ============================================================== orchestrator ==

/// The simultaneous-open race: run the acceptor AND dial every peer candidate
/// concurrently; the FIRST connection to pass the pair-secret MAC wins, the
/// rest are dropped. Returns an authenticated `Arc<dyn Transport>` or None
/// (caller then falls back to WebRTC). Bounded by `DIRECT_BUDGET`.
///
/// `endpoint` is the already-bound shared endpoint (so the advertised port is
/// the one we actually listen on). `peer_cands` are the peer's advertised
/// `ip:port` strings. `secret` is the pair secret (known-device only — rung 1).
pub async fn race_connect(
    endpoint: Endpoint,
    peer_cands: Vec<String>,
    secret: &str,
    peer_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
) -> Option<Arc<dyn Transport>> {
    race_connect_labeled(endpoint, peer_cands, secret, peer_id, tx, "direct-quic").await
}

/// Same race, but with the route label parameterized so rung-2 (hole-punch) can
/// reuse this verbatim and emit `route: holepunched`. rung-1 calls the wrapper
/// above with `direct-quic`; nothing else about the race changes.
pub async fn race_connect_labeled(
    endpoint: Endpoint,
    peer_cands: Vec<String>,
    secret: &str,
    peer_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
    route: &str,
) -> Option<Arc<dyn Transport>> {
    // The test-block knob only simulates a blocked rung-1 (direct-quic) path so
    // the WebRTC fallback gate can assert. It must NOT short-circuit rung-2 — a
    // hole-punch race carries a distinct label.
    if route == "direct-quic" && test_block() {
        // Fallback gate: pretend the direct path is unreachable. Drop the
        // endpoint and let the budget expire so WebRTC takes over.
        eprintln!("filament: DIRECT-BLOCKED (test) — forcing WebRTC fallback");
        tokio::time::sleep(DIRECT_BUDGET).await;
        endpoint.close(0u32.into(), b"test-block");
        return None;
    }

    let tkey = transport_key(secret);

    // One future that resolves to an authenticated (conn, send, recv) or errors.
    async fn auth_conn(
        conn: quinn::Connection,
        tkey: [u8; 32],
        is_dialer: bool,
    ) -> Result<(quinn::Connection, SendStream, RecvStream)> {
        let (s, r) = authenticate(&conn, &tkey, is_dialer).await?;
        Ok((conn, s, r))
    }

    let mut futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = Result<(quinn::Connection, SendStream, RecvStream)>> + Send>>> = Vec::new();

    // Acceptor side: accept inbound, then auth as acceptor.
    {
        let ep = endpoint.clone();
        let tkey = tkey;
        futs.push(Box::pin(async move {
            let incoming = ep.accept().await.ok_or_else(|| anyhow!("endpoint closed"))?;
            let conn = incoming.await.context("accept handshake")?;
            auth_conn(conn, tkey, false).await
        }));
    }

    // Dialer side: one future per candidate, auth as dialer.
    for cand in peer_cands {
        let Ok(addr) = cand.parse::<SocketAddr>() else { continue };
        let ep = endpoint.clone();
        let tkey = tkey;
        futs.push(Box::pin(async move {
            let connecting = ep
                .connect(addr, "filament-direct")
                .context("connect")?;
            let conn = connecting.await.context("dial handshake")?;
            auth_conn(conn, tkey, true).await
        }));
    }

    let race = async {
        use futures_util::stream::{FuturesUnordered, StreamExt};
        let mut set: FuturesUnordered<_> = futs.into_iter().collect();
        while let Some(res) = set.next().await {
            match res {
                Ok((conn, send, recv)) => return Some((conn, send, recv)),
                Err(e) => {
                    // Auth failures are the negative-gate signal — make them
                    // greppable. Dial failures (unreachable candidate) are noise.
                    let s = e.to_string();
                    if s.contains("DIRECT-AUTH-FAIL") {
                        eprintln!("filament: {s}");
                    }
                    continue;
                }
            }
        }
        None
    };

    let winner = match tokio::time::timeout(DIRECT_BUDGET, race).await {
        Ok(Some(w)) => w,
        _ => {
            endpoint.close(0u32.into(), b"direct-timeout");
            return None;
        }
    };

    let (conn, send, recv) = winner;
    eprintln!(
        "filament: DIRECT-CONNECT ok (route: {}) peer={} remote={}",
        route,
        peer_id,
        conn.remote_address()
    );
    // Keep the endpoint alive for the connection's lifetime by leaking it into
    // the transport's closure scope: hold it in a task that lives as long as the
    // connection. Simplest: stash it in a detached keepalive future.
    {
        let conn2 = conn.clone();
        tokio::spawn(async move {
            // Hold the endpoint until the connection ends.
            conn2.closed().await;
            drop(endpoint);
        });
    }
    Some(make_transport(peer_id, conn, send, recv, tx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_is_deterministic_and_independent() {
        let a = transport_key("secret-one");
        let b = transport_key("secret-one");
        let c = transport_key("secret-two");
        assert_eq!(a, b, "same secret -> same key");
        assert_ne!(a, c, "different secret -> different key");
        // Not equal to the raw secret bytes (independence sanity).
        assert_ne!(&a[..], b"secret-one\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn auth_tags_directional_and_secret_bound() {
        let k1 = transport_key("right");
        let k2 = transport_key("wrong");
        let km = [7u8; 32];
        let dialer = auth_tag(&k1, &km, "dialer");
        let acceptor = auth_tag(&k1, &km, "acceptor");
        assert_ne!(dialer, acceptor, "direction-tagged tags differ");
        // Wrong secret -> wrong tag (the negative-auth property).
        assert_ne!(auth_tag(&k2, &km, "dialer"), dialer);
    }
}
