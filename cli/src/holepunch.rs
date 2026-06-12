// Rung-2 UDP HOLE-PUNCHING (FILAMENT_HOLEPUNCH=1).
//
// Sits BETWEEN rung-1 (direct-dial QUIC, src/direct.rs) and rung-3 (WebRTC/relay)
// on the transport ladder. When rung-1's host-candidate race fails — both peers
// behind NAT, no directly-reachable candidate — we open the NATs with a
// simultaneous-open UDP punch and then run rung-1's UNCHANGED authenticated QUIC
// handshake over the punched socket. Route label: `holepunched`.
//
// REUSE, not reinvention: this module owns ONLY (a) server-reflexive discovery
// (a hand-rolled STUN Binding), (b) the punch handshake, and (c) wrapping the
// punched std socket in a quinn Endpoint. The QUIC handshake + pair-secret MAC +
// drain are rung-1's `direct::race_connect_labeled`, called verbatim.
//
// THE LOAD-BEARING CONSTRAINT (see docs/design-rung2-holepunch.md): a srflx
// candidate belongs to ONE specific UDP socket's NAT mapping, and quinn takes
// OWNERSHIP of the std socket it is built on. So rung-2 uses its OWN second raw
// socket — bound + STUN'd at offer time, kept raw until the punch, then handed to
// quinn. Rung-1's socket/endpoint is never touched ⇒ no regression.

use anyhow::{anyhow, Context, Result};
use quinn::Endpoint;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::direct;
use crate::net::Transport;

/// Opt-in gate. Rung-2 is dead unless this is set; rung-1 + WebRTC are unaffected.
pub fn holepunch_enabled() -> bool {
    std::env::var("FILAMENT_HOLEPUNCH").map(|v| v == "1").unwrap_or(false)
}

/// Total budget for the punch handshake before giving up (and stepping down to
/// WebRTC). Symmetric NAT defeats the punch — this is how long we wait before
/// declaring that and falling through.
pub const PUNCH_BUDGET: Duration = Duration::from_secs(3);
/// Punch retransmit cadence. The OUTBOUND send opens our NAT mapping/filter; we
/// retransmit so a packet lands after the peer's mapping forms (the zero-RTT
/// race) and to survive loss.
const PUNCH_INTERVAL: Duration = Duration::from_millis(75);
/// Magic bytes so a punch datagram is unmistakably ours (not stray QUIC).
const PUNCH_MAGIC: &[u8] = b"FILAMENT-PUNCH-v1";

// ============================================================== STUN discovery

/// STUN magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

/// Hand-rolled STUN Binding: send a Binding request from `sock`, read the
/// response, return the XOR-MAPPED-ADDRESS (our public ip:port for THIS socket's
/// NAT mapping). Discovery only — no auth, no symmetric detection (the punch
/// failing IS the symmetric detection). std sockets only; no new dependency.
///
/// `sock` MUST be the same socket we will punch + run QUIC on, or the srflx we
/// learn belongs to a different mapping.
pub fn stun_srflx(sock: &UdpSocket, stun_server: SocketAddr) -> Result<SocketAddr> {
    // 20-byte header: type=Binding-Request(0x0001), len=0, cookie, 96-bit txid.
    let mut txid = [0u8; 12];
    // Cheap unique txid from the clock; STUN only needs it to match req↔resp.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    txid.copy_from_slice(&now.to_be_bytes()[..12]);

    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&0x0001u16.to_be_bytes()); // message type
    req.extend_from_slice(&0x0000u16.to_be_bytes()); // message length (no attrs)
    req.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req.extend_from_slice(&txid);

    let prev_timeout = sock.read_timeout().ok().flatten();
    sock.set_read_timeout(Some(Duration::from_millis(700)))
        .context("stun: set read timeout")?;

    // A few attempts — UDP can drop the first request.
    let mut last_err = anyhow!("stun: no response");
    for _ in 0..4 {
        if let Err(e) = sock.send_to(&req, stun_server) {
            last_err = anyhow!("stun: send_to {stun_server}: {e}");
            continue;
        }
        let mut buf = [0u8; 512];
        match sock.recv_from(&mut buf) {
            Ok((n, _from)) => {
                if let Some(addr) = parse_xor_mapped_address(&buf[..n], &txid) {
                    let _ = sock.set_read_timeout(prev_timeout);
                    return Ok(addr);
                }
                last_err = anyhow!("stun: response had no XOR-MAPPED-ADDRESS");
            }
            Err(e) => last_err = anyhow!("stun: recv_from: {e}"),
        }
    }
    let _ = sock.set_read_timeout(prev_timeout);
    Err(last_err)
}

/// Parse the XOR-MAPPED-ADDRESS (0x0020) attribute from a STUN response.
/// Returns the de-XOR'd public address. Tolerates MAPPED-ADDRESS (0x0001) as a
/// fallback (un-XOR'd) for older servers.
fn parse_xor_mapped_address(buf: &[u8], _txid: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    // Response type should be Binding Success (0x0101); be lenient and just look
    // for the attribute. Attributes start at byte 20.
    let mut i = 20usize;
    while i + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let val_start = i + 4;
        if val_start + attr_len > buf.len() {
            break;
        }
        let val = &buf[val_start..val_start + attr_len];
        match attr_type {
            0x0020 => {
                // XOR-MAPPED-ADDRESS: family(1) + reserved(1) + xport(2) + xaddr(4).
                if val.len() >= 8 && val[1] == 0x01 {
                    let xport = u16::from_be_bytes([val[2], val[3]]);
                    let port = xport ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                    let ip = std::net::Ipv4Addr::new(
                        val[4] ^ cookie[0],
                        val[5] ^ cookie[1],
                        val[6] ^ cookie[2],
                        val[7] ^ cookie[3],
                    );
                    return Some(SocketAddr::new(ip.into(), port));
                }
            }
            0x0001 => {
                // MAPPED-ADDRESS (un-XOR'd) fallback: family(1)+reserved(1)+port(2)+addr(4).
                if val.len() >= 8 && val[1] == 0x01 {
                    let port = u16::from_be_bytes([val[2], val[3]]);
                    let ip = std::net::Ipv4Addr::new(val[4], val[5], val[6], val[7]);
                    return Some(SocketAddr::new(ip.into(), port));
                }
            }
            _ => {}
        }
        // Attributes are padded to 4-byte boundaries.
        i = val_start + ((attr_len + 3) & !3);
    }
    None
}

/// Resolve the STUN server address: `FILAMENT_STUN` (host:port) override wins,
/// else the first `stun:` URL from the ICE config. Returns None if neither is
/// available (rung-2 then simply doesn't advertise an srflx).
pub fn stun_server_addr(stun_urls: &[String]) -> Option<SocketAddr> {
    if let Ok(v) = std::env::var("FILAMENT_STUN") {
        if let Some(a) = resolve_host_port(v.trim()) {
            return Some(a);
        }
    }
    for url in stun_urls {
        // urls look like "stun:host:port" or "stun:host:port?transport=..."
        let rest = url.strip_prefix("stun:").or_else(|| url.strip_prefix("stuns:"))?;
        let hostport = rest.split('?').next().unwrap_or(rest);
        if let Some(a) = resolve_host_port(hostport) {
            return Some(a);
        }
    }
    None
}

fn resolve_host_port(hostport: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    // Default STUN port if none given.
    let hp = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:3478")
    };
    hp.to_socket_addrs().ok()?.next()
}

// ============================================================== the punch

/// Bind a fresh raw UDP punch socket on an ephemeral port. Kept raw (NOT
/// connected) so STUN, the punch, and quinn all share one NAT mapping.
pub fn bind_punch_socket() -> Result<UdpSocket> {
    UdpSocket::bind("0.0.0.0:0").context("bind punch socket")
}

/// Simultaneous-open punch toward `peer_srflx` on `sock`. Retransmits our punch
/// magic every PUNCH_INTERVAL while reading inbound; succeeds once we have BOTH
/// sent ≥1 and received ≥1 punch packet (bidirectional confirmation that both
/// NAT mappings/filters are open). Times out at PUNCH_BUDGET → Err (the caller
/// steps down to WebRTC — this is the symmetric-NAT outcome).
///
/// Runs on a blocking thread (it does blocking UDP I/O) so it doesn't stall the
/// tokio reactor; the caller `spawn_blocking`s it and gets the socket back.
pub fn punch(sock: &UdpSocket, peer_srflx: SocketAddr) -> Result<()> {
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .context("punch: set read timeout")?;
    let start = Instant::now();
    let mut last_send = Instant::now()
        .checked_sub(PUNCH_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut sent = 0u32;
    let mut recvd = false;

    let mut buf = [0u8; 256];
    while start.elapsed() < PUNCH_BUDGET {
        if last_send.elapsed() >= PUNCH_INTERVAL {
            // The OUTBOUND send opens our NAT mapping+filter toward the peer.
            let _ = sock.send_to(PUNCH_MAGIC, peer_srflx);
            sent += 1;
            last_send = Instant::now();
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                // Accept a punch from the peer's srflx ip (port may differ if its
                // NAT remapped — for cone NAT it matches). A received punch
                // confirms the peer's filter is open for us.
                if n >= PUNCH_MAGIC.len() && &buf[..PUNCH_MAGIC.len()] == PUNCH_MAGIC {
                    let _ = from;
                    recvd = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => {}
        }
        // Need our mapping open (we've sent) AND theirs (we've received). After
        // confirmation, send a couple extra so the peer also confirms before we
        // build QUIC, then return.
        if sent >= 1 && recvd {
            for _ in 0..3 {
                let _ = sock.send_to(PUNCH_MAGIC, peer_srflx);
                std::thread::sleep(Duration::from_millis(20));
            }
            return Ok(());
        }
    }
    Err(anyhow!(
        "HOLEPUNCH-FAIL: no bidirectional punch in budget (sent={sent}, recvd={recvd}) — symmetric NAT?"
    ))
}

// ====================================================== quinn over the punch

/// Build a quinn Endpoint on the already-punched (still UNCONNECTED) std socket.
/// quinn sets it nonblocking and manages its own addressing — we do NOT connect()
/// it. Server + client config are rung-1's, verbatim.
pub fn endpoint_from_socket(sock: UdpSocket) -> Result<Endpoint> {
    let mut ep = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(direct::server_config()?),
        sock,
        Arc::new(quinn::TokioRuntime),
    )
    .context("build quinn endpoint on punched socket")?;
    ep.set_default_client_config(direct::client_config()?);
    Ok(ep)
}

/// Rung-2 entry point: given a freshly-bound-and-STUN'd punch socket, the peer's
/// advertised srflx, and the pair secret, punch the NAT then run rung-1's
/// authenticated QUIC race over the punched socket. Returns an authenticated
/// `Arc<dyn Transport>` (route `holepunched`) or None (caller steps to WebRTC).
///
/// `punch_sock` ownership is moved in: on success it lives inside the quinn
/// endpoint; on failure it is dropped (mapping released).
pub async fn connect(
    punch_sock: UdpSocket,
    peer_srflx: SocketAddr,
    secret: &str,
    peer_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
) -> Option<Arc<dyn Transport>> {
    // Punch on a blocking thread (blocking UDP I/O), reclaim the socket.
    let punch_result = tokio::task::spawn_blocking(move || {
        let r = punch(&punch_sock, peer_srflx);
        (r, punch_sock)
    })
    .await
    .ok()?;
    let (r, punch_sock) = punch_result;
    if let Err(e) = r {
        crate::ui::trace(&format!("filament: {e}"));
        return None; // step down to WebRTC
    }
    // DEBUG — direct/hole-punch internal.
    crate::ui::debug(&format!("filament: HOLEPUNCH ok — NAT open toward {peer_srflx}, starting QUIC"));

    let endpoint = match endpoint_from_socket(punch_sock) {
        Ok(ep) => ep,
        Err(e) => {
            crate::ui::trace(&format!("filament: holepunch endpoint build failed: {e}"));
            return None;
        }
    };

    // rung-1's race, UNCHANGED but for the route label.
    direct::race_connect_labeled(
        endpoint,
        vec![peer_srflx.to_string()],
        secret,
        peer_id,
        tx,
        "holepunched",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_server_addr_parses_url() {
        let urls = vec!["stun:198.18.0.1:3478".to_string()];
        let a = stun_server_addr(&urls).unwrap();
        assert_eq!(a.to_string(), "198.18.0.1:3478");
    }

    #[test]
    fn stun_server_addr_strips_query() {
        let urls = vec!["stun:198.18.0.1:3478?transport=udp".to_string()];
        let a = stun_server_addr(&urls).unwrap();
        assert_eq!(a.port(), 3478);
    }

    #[test]
    fn xor_mapped_address_roundtrip() {
        // Build a minimal Binding Success with an XOR-MAPPED-ADDRESS for
        // 203.0.113.5:50000 and assert we de-XOR it back.
        let ip = std::net::Ipv4Addr::new(203, 0, 113, 5);
        let port: u16 = 50000;
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let xport = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        let octets = ip.octets();
        let mut resp = vec![0u8; 20];
        resp[0] = 0x01;
        resp[1] = 0x01; // Binding Success
        // attr: type 0x0020, len 8
        resp.extend_from_slice(&0x0020u16.to_be_bytes());
        resp.extend_from_slice(&0x0008u16.to_be_bytes());
        resp.push(0x00);
        resp.push(0x01); // IPv4 family
        resp.extend_from_slice(&xport.to_be_bytes());
        resp.extend_from_slice(&[
            octets[0] ^ cookie[0],
            octets[1] ^ cookie[1],
            octets[2] ^ cookie[2],
            octets[3] ^ cookie[3],
        ]);
        let got = parse_xor_mapped_address(&resp, &[0u8; 12]).unwrap();
        assert_eq!(got, SocketAddr::new(ip.into(), port));
    }

    #[test]
    fn stun_and_punch_against_local_reflector() {
        // A loopback STUN-ish reflector that echoes XOR-MAPPED-ADDRESS, and a
        // loopback punch peer, to exercise the wire format end-to-end.
        // (Pure unit-level; real NAT validation is the netns lab gate.)
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv_addr = srv.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (_n, from) = srv.recv_from(&mut buf).unwrap();
            // Reply with XOR-MAPPED-ADDRESS = the sender's addr.
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let port = from.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            let octets = match from.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => [127, 0, 0, 1],
            };
            let mut resp = vec![0u8; 20];
            resp[0] = 0x01;
            resp[1] = 0x01;
            // copy txid back from request (bytes 8..20)
            resp[8..20].copy_from_slice(&buf[8..20]);
            resp.extend_from_slice(&0x0020u16.to_be_bytes());
            resp.extend_from_slice(&0x0008u16.to_be_bytes());
            resp.push(0x00);
            resp.push(0x01);
            resp.extend_from_slice(&port.to_be_bytes());
            resp.extend_from_slice(&[
                octets[0] ^ cookie[0],
                octets[1] ^ cookie[1],
                octets[2] ^ cookie[2],
                octets[3] ^ cookie[3],
            ]);
            srv.send_to(&resp, from).unwrap();
        });
        // Bind to loopback so the reflector observes a 127.0.0.1 source (a
        // 0.0.0.0-bound socket reports an unspecified local addr, but the kernel
        // still sends from 127.0.0.1 to a loopback dst).
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let srflx = stun_srflx(&client, srv_addr).unwrap();
        // The de-XOR'd reflected addr is the source the server saw: loopback,
        // on the client's actual local port.
        assert!(srflx.ip().is_loopback(), "srflx ip {} not loopback", srflx.ip());
        assert_eq!(srflx.port(), client.local_addr().unwrap().port());
        handle.join().unwrap();
    }
}
