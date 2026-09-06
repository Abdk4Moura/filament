macro_rules! dlog {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-logs")]
        eprintln!($($arg)*);
    };
}
// Rung-1 DIRECT CLI<->CLI transport over QUIC (quinn).
//
// Why this exists: WebRTC/ICE/STUN/TURN is browser machinery, two CLIs are
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
// Security (NON-NEGOTIABLE, must match DTLS, see the module's auth section):
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
use quinn::{Endpoint, ReadError, RecvStream, SendStream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

use crate::net::Transport;

/// Opt-in gate. The ENTIRE direct path is dead unless this is set; default
/// behaviour (WebRTC) is byte-for-byte unchanged. CHECKPOINT before promoting.
///
/// Item 3: `FILAMENT_L2=1` ALSO implies direct. The L2/ssh use-case needs
/// reliable CLI<->CLI and WebRTC is too flaky cross-machine (it gets "stuck
/// while connecting" even over TURN), while direct-QUIC to a reachable peer is
/// rock-solid. A plain `up`/`send` WITHOUT FILAMENT_L2 keeps the WebRTC default
/// byte-for-byte unchanged, the file-transfer hard rule.
pub fn direct_enabled() -> bool {
    // Default ON. Opt out with FILAMENT_DIRECT=0.
    std::env::var("FILAMENT_DIRECT").map(|v| v != "0").unwrap_or(true)
        || std::env::var("FILAMENT_L2").map(|v| v == "1").unwrap_or(false)
}

/// Test-only: force the direct race to fail (simulate a blocked direct path)
/// so the fallback gate can assert WebRTC still completes WITH the flag ON.
/// Not a product knob, only the fallback gate sets it.
fn test_block() -> bool {
    std::env::var("FILAMENT_DIRECT_TEST_BLOCK").map(|v| v == "1").unwrap_or(false)
}

/// Bug 2 PROOF hook (test-only): `FILAMENT_DIRECT_TEST_DIE_AT=<bytes>` forces
/// the FIRST established direct transport's QUIC connection to DIE (structurally
/// error, dead=true) after N cumulative bytes of file data have been written
/// across all send_frame calls. One-shot via process-global latch: only the
/// first transport dies; the re-dial (the ladder's rung-c repair) streams
/// normally and recovers.
static DIED_ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static TOTAL_DIRECT_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn die_after_bytes() -> Option<u64> {
    std::env::var("FILAMENT_DIRECT_TEST_DIE_AT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
}

/// P0 stall-detector PROOF hook (test-only): `FILAMENT_TEST_FREEZE_AFTER_BYTES=N`
/// makes the FIRST direct transport's data path go silently dark after it has
/// written ~N bytes of *file data*, `send_frame` parks forever while the QUIC
/// connection stays UP and CONTROL frames keep flowing. That is the exact
/// "open channel, zero data bytes" black-hole (the Pixel-at-0% hang / a NAT
/// rebind that strands only the data 5-tuple), reproduced deterministically.
///
/// It is ONE-SHOT across the process (a process-global latch): once one
/// transport has frozen, a *fresh* transport built by the correction ladder's
/// in-place repair (rung c) is NOT frozen, so the test proves the stall is
/// both DETECTED and AUTO-RECOVERED on the re-dialled path, not merely detected.
/// Never a product knob; only the data-path-freeze sim sets it. Compiled in ONLY
/// under `--features test-hooks`, stripped from default/release builds.
#[cfg(feature = "test-hooks")]
fn freeze_after_bytes() -> Option<u64> {
    std::env::var("FILAMENT_TEST_FREEZE_AFTER_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
}

/// P1 relay-fallback PROOF hook (test-only): `FILAMENT_TEST_FREEZE_PERSIST=1`
/// makes the data-path freeze PERSISTENT instead of one-shot, EVERY fresh direct
/// transport (including the correction ladder's rung-c re-dials) freezes after the
/// byte threshold. So the direct/in-place-repair ladder can never recover; it
/// EXHAUSTS, and the only way the transfer completes is the rung-(d) escalation
/// to the TURN relay (a WebRTC path that doesn't ride this direct-QUIC freeze).
/// This is how the relay-fallback gate forces the exact "direct can't, relay can"
/// condition deterministically. Only that sim sets it. Compiled in ONLY under
/// `--features test-hooks`, stripped from default/release builds.
#[cfg(feature = "test-hooks")]
fn freeze_persist() -> bool {
    std::env::var("FILAMENT_TEST_FREEZE_PERSIST").map(|v| v == "1").unwrap_or(false)
}

/// P5 (GAP-6) relay->direct UPGRADE PROOF hook (test-only):
/// `FILAMENT_TEST_DIRECT_UNBLOCK_MS=N` LIFTS the persistent direct freeze for any
/// transport born after N ms of process uptime. So the timeline is: early direct
/// transports freeze (the peer falls to relay, rung d), then, once the prober
/// dials a FRESH direct standby after the unblock moment, that late transport is
/// NOT frozen and carries data, letting the prober VERIFY + UPGRADE back to
/// direct. Unset ⇒ no lift (the freeze persists forever, as P1's gate needs).
/// Compiled in ONLY under `--features test-hooks`, stripped from release.
#[cfg(feature = "test-hooks")]
fn direct_unblock_after_ms() -> Option<u64> {
    std::env::var("FILAMENT_TEST_DIRECT_UNBLOCK_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
}

/// P5 (GAP-6) NO-FLAP PROOF hook (test-only): `FILAMENT_TEST_DIRECT_FLAKY=1`
/// makes a post-unblock direct standby CONNECT and move a little data, then
/// RE-FREEZE almost immediately, modelling a flaky direct path that comes up but
/// won't hold. The verify-before-upgrade guard must catch this and DISCARD the
/// standby (stay on relay), never flapping relayed<->direct. With this set, the
/// unblock lift is GRANTED for connection (so the standby forms) but the transport
/// re-freezes after a tiny byte threshold. Compiled in ONLY under
/// `--features test-hooks`, stripped from release.
#[cfg(feature = "test-hooks")]
fn direct_flaky_upgrade() -> bool {
    std::env::var("FILAMENT_TEST_DIRECT_FLAKY").map(|v| v == "1").unwrap_or(false)
}

/// P5 (GAP-6): tiny byte threshold after which a FLAKY post-unblock standby
/// re-freezes (enough to connect + look alive for a beat, far less than the
/// verify window needs to confirm sustained progress).
#[cfg(feature = "test-hooks")]
const FLAKY_REFREEZE_BYTES: u64 = 4_096;

/// Process-global "a transport has already frozen once" latch (see
/// `freeze_after_bytes`). `false` until the first transport freezes; once `true`
/// every later transport streams normally, so rung-c's fresh dial recovers.
/// Test-only, stripped from default/release builds.
#[cfg(feature = "test-hooks")]
static FROZE_ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Total budget for the whole direct attempt before falling back to WebRTC.
pub const DIRECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// ALPN, distinguishes our QUIC app; both ends must agree.
const ALPN: &[u8] = b"filament-direct/1";

/// Max app payload per send_frame on the direct-QUIC path. QUIC streams are
/// byte-streams with no datagram cap, so larger frames just mean fewer
/// send_frame calls and, more importantly, far fewer chunks through the
/// receiver's single event-loop consumer (record_range + seek + write) per
/// byte. 1 MiB keeps that per-chunk overhead ~17x lower than the old 60 KiB.
pub const MAX_DIRECT_PAYLOAD: usize = 1024 * 1024;

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

// ============================================================= CIDR filter ==

/// A single CIDR rule: network IP + prefix length.
struct CidrRule {
    ip: IpAddr,
    prefix_len: u8,
}

fn parse_cidr(s: &str) -> Option<CidrRule> {
    let s = s.trim();
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: IpAddr = ip_str.parse().ok()?;
    let prefix_len: u8 = len_str.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > max {
        return None;
    }
    Some(CidrRule { ip, prefix_len })
}

fn ip_matches_cidr(ip: &IpAddr, rule: &CidrRule) -> bool {
    match (ip, &rule.ip) {
        (IpAddr::V4(a), IpAddr::V4(net)) => {
            let mask = u32::MAX.checked_shl(32 - rule.prefix_len as u32).unwrap_or(0);
            u32::from(*a) & mask == u32::from(*net) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(net)) => {
            let mask = u128::MAX.checked_shl(128 - rule.prefix_len as u32).unwrap_or(0);
            u128::from(*a) & mask == u128::from(*net) & mask
        }
        _ => false,
    }
}

/// Expand a friendly group name into CIDR rules. Groups:
///   tailscale → 100.64.0.0/10  (Tailscale / CGNAT overlay)
///   docker    → 172.17.0.0/16  (docker0 bridge default)
fn expand_group(item: &str) -> Vec<CidrRule> {
    match item.to_ascii_lowercase().as_str() {
        "tailscale" => parse_cidr("100.64.0.0/10").into_iter().collect(),
        "docker" => parse_cidr("172.17.0.0/16").into_iter().collect(),
        _ => vec![],
    }
}

/// Parse one avoid/prefer CSV entry, normalizing both CIDRs and groups.
fn parse_rule_item(item: &str) -> Vec<CidrRule> {
    let item = item.trim();
    if item.is_empty() {
        return vec![];
    }
    // Try as CIDR first
    if let Some(r) = parse_cidr(item) {
        return vec![r];
    }
    // Try as friendly group
    let groups = expand_group(item);
    if !groups.is_empty() {
        return groups;
    }
    // Not a CIDR or group — could be an interface name (not supported yet).
    // Silently ignore; avoid being noisy.
    vec![]
}

fn parse_rule_list(csv: &str) -> Vec<CidrRule> {
    csv.split(',')
        .flat_map(parse_rule_item)
        .collect()
}

/// Read one iface setting, per-peer aware. For the membership store
/// ("interfaces"), returns the raw JSON. For prefer, reads from config.
fn read_iface_setting(key: &str, peer: Option<&str>) -> String {
    if key == "interfaces" {
        return crate::hooks::raw_membership(peer);
    }
    crate::hooks::settings_get_str(key, peer).unwrap_or_default()
}

/// Filter local IPs for candidate gathering using membership (avoid/only store)
/// and arrangement (prefer ordering). Membership decides which IPs are ELIGIBLE;
/// prefer only orders the survivors.
fn filter_local_ips(ips: Vec<IpAddr>, peer: Option<&str>) -> Vec<IpAddr> {
    // --- membership: eligible set from the shared interfaces store ---
    let membership_raw = read_iface_setting("interfaces", peer);
    let (membership_mode, membership_items) = parse_membership(&membership_raw);
    let avoid_rules = if membership_mode == "avoid" {
        parse_rule_list(&membership_items)
    } else {
        vec![]
    };
    let only_rules = if membership_mode == "only" {
        parse_rule_list(&membership_items)
    } else {
        vec![]
    };

    // --- arrangement: prefer ordering (soft by default) ---
    let prefer = read_iface_setting("prefer", peer);
    let prefer_rules = parse_rule_list(&prefer);

    // If no rules at all, pass through unchanged
    if membership_mode.is_empty() && prefer.is_empty() {
        return ips;
    }

    let mut kept: Vec<(IpAddr, u8)> = ips
        .into_iter()
        .filter(|ip| {
            if ip.is_loopback() {
                return true; // never filter loopback
            }
            // Avoid mode: drop matching IPs (deny list)
            for r in &avoid_rules {
                if ip_matches_cidr(ip, r) {
                    return false;
                }
            }
            // Only mode: keep only matching IPs (allow list)
            if !only_rules.is_empty() {
                return only_rules.iter().any(|r| ip_matches_cidr(ip, r));
            }
            true
        })
        .map(|ip| {
            // Prefer: weight 0 for preferred, 1 for fallback
            let weight: u8 = if prefer_rules.iter().any(|r| ip_matches_cidr(&ip, r)) {
                0
            } else {
                1
            };
            (ip, weight)
        })
        .collect();

    if kept.is_empty() {
        crate::hooks::debug("membership filter removed ALL host candidates");
        return vec![];
    }

    kept.sort_by_key(|(_, w)| *w);
    kept.into_iter().map(|(ip, _)| ip).collect()
}

/// Parse the shared interfaces store value (JSON membership) into (mode, items).
/// Returns ("", "") when the store is empty or unparseable.
fn parse_membership(raw: &str) -> (String, String) {
    if raw.is_empty() {
        return (String::new(), String::new());
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        let mode = v["m"].as_str().unwrap_or("").to_string();
        let items = v["i"].as_str().unwrap_or("").to_string();
        return (mode, items);
    }
    (String::new(), String::new())
}

/// Every local non-loopback interface IP (v4+v6). Std-only: enumerate by
/// "connecting" UDP sockets to public anchors and reading the chosen local
/// addr (no packets sent). This yields the primary routable v4 and v6 source
/// addresses, the ones a peer on the same LAN / overlay can actually reach.
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

/// P5 (GAP-6): a stable, sorted snapshot of the local ROUTABLE source addresses
/// (loopback excluded, it never changes and would mask a real handoff). The
/// relay->direct prober polls this each tick: a change (new/removed interface,
/// wifi<->cellular handoff, default-route move) is the strongest portable "a new
/// direct path may exist NOW" signal, and triggers an immediate re-probe. Cheap
/// (two UDP `connect`s, no packets) and dependency-free, no platform netlink.
pub fn local_ip_snapshot() -> Vec<String> {
    let mut v: Vec<String> = local_ips()
        .into_iter()
        .filter(|ip| !ip.is_loopback())
        .map(|ip| ip.to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Public IP for cross-NAT reachability: `FILAMENT_PUBLIC_IP` override wins,
/// else a one-line `GET /api/whoami` echo of CF-Connecting-IP (the droplet is
/// behind Cloudflare; the backend reads that header). Best-effort, failure
/// just means we advertise no public candidate.
/// Our public IP, learned from `{server}/api/whoami`. This sits on the
/// CRITICAL PATH of every connect: `gather_candidates` calls it before the
/// transport-offer can be sent, and the long-lived `up` acceptor pays it on
/// EVERY incoming connect (the initiator waits on that reply). The public IP is
/// STABLE for a box, only the ephemeral UDP port rotates per bind, so the IP is
/// safe to memoize for a short TTL even though the endpoint cache (which keyed on
/// the rotating port) was not. A cache miss/expiry just refetches; the env
/// override always wins and never touches the network.
const PUBIP_TTL: std::time::Duration = std::time::Duration::from_secs(300);

struct PubIpEntry {
    server: String,
    ip: IpAddr,
    at: std::time::Instant,
}

static PUBIP_CACHE: std::sync::OnceLock<Mutex<Option<PubIpEntry>>> = std::sync::OnceLock::new();

/// Our public IP as OBSERVED by an authenticated peer (#237): the peer saw us
/// connect from this address, so it is the only source NOT chosen by the party
/// under suspicion (the signaling server). It SUPERSEDES the `/api/whoami`
/// assertion (the `PUBIP_CACHE` above, including the `warm_public_ip` pre-warm
/// at daemon start): once a peer has seen us, the server's guess is ignored.
/// Empty until a peer has actually connected to us.
static PEER_OBSERVED_IP: std::sync::OnceLock<Mutex<Option<IpAddr>>> = std::sync::OnceLock::new();

/// The address an authenticated peer observed us connecting from, if any.
pub async fn observed_public_ip() -> Option<IpAddr> {
    *PEER_OBSERVED_IP.get_or_init(|| Mutex::new(None)).lock().await
}

async fn record_observed_ip(ip: IpAddr) {
    *PEER_OBSERVED_IP.get_or_init(|| Mutex::new(None)).lock().await = Some(ip);
}

/// Pure freshness test, split out so the TTL/server-match logic is unit-testable
/// without a clock or the network. A cached IP is reusable only for the SAME
/// server and only while younger than the TTL.
fn pubip_fresh(cached_server: &str, age: std::time::Duration, want_server: &str, ttl: std::time::Duration) -> bool {
    cached_server == want_server && age < ttl
}

async fn public_ip(server: &str) -> Option<IpAddr> {
    if let Ok(v) = std::env::var("FILAMENT_PUBLIC_IP") {
        if let Ok(ip) = v.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }
    let cache = PUBIP_CACHE.get_or_init(|| Mutex::new(None));
    // Read the cache under a short-held lock (NEVER across the await below).
    {
        let guard = cache.lock().await;
        if let Some(e) = guard.as_ref() {
            if pubip_fresh(&e.server, e.at.elapsed(), server, PUBIP_TTL) {
                return Some(e.ip);
            }
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
    let ip = v["ip"].as_str()?.trim().parse::<IpAddr>().ok()?;
    // Record for the next connect. A concurrent cold fetch may overwrite this
    // with an identical value, which is harmless (idempotent).
    let mut guard = cache.lock().await;
    *guard = Some(PubIpEntry { server: server.to_string(), ip, at: std::time::Instant::now() });
    Some(ip)
}

/// Pre-resolve and cache our public IP. The `up` acceptor calls this at startup
/// so its FIRST incoming connect answers the transport-offer without an inline
/// `/api/whoami` round trip (subsequent connects already hit the warm cache).
/// Best-effort: a failure leaves the cache empty and the normal lazy path runs.
pub async fn warm_public_ip(server: &str) {
    let _ = public_ip(server).await;
}

/// Format an addr as a candidate string; v6 gets brackets so `[ip]:port` parses.
fn cand_str(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

/// Test-only: suppress rung-1's public (`whoami`) candidate. `/api/whoami`
/// returns IP only, NO port, so rung-1 advertises `public_ip:local_port`, which
/// is correct ONLY when the NAT preserves the source port (Linux MASQUERADE in
/// the lab happens to). On the very common NAT that does NOT preserve the port,
/// that guessed candidate is wrong and rung-1's public path fails, which is
/// exactly the class rung-2's STUN-learned srflx (real external port) exists to
/// catch. This knob models that NAT class so the cone gate can exercise rung-2 in
/// isolation. NOT a product knob, only the hole-punch gate sets it.
fn suppress_public() -> bool {
    std::env::var("FILAMENT_DIRECT_NO_PUBLIC").map(|v| v == "1").unwrap_or(false)
}

/// Test-only: advertise ONLY the server-asserted (`whoami`) public candidate.
/// Uses the SAME single adopted-value computation as the normal path and returns
/// `(vec![the adopted address], Some(it))` when one was adopted. The gate C
/// fixture uses it to make the direct race DIAL a real, unanswerable address
/// (TEST-NET) and fail for real, so the fallback attribution names a candidate
/// that was actually dialed on the wire - not a simulated stand-in. NOT a
/// product knob, only the whoami-candidate gate sets it.
fn only_public() -> bool {
    std::env::var("FILAMENT_DIRECT_ONLY_PUBLIC").map(|v| v == "1").unwrap_or(false)
}

/// Test-only: pin candidates to loopback (`127.0.0.1`). A multi-homed host (a
/// cloud box with eth0/private/docker/tailscale/bridge IPs) advertises many
/// local candidates; the simultaneous-open race can then pick a pair that can't
/// actually carry data, so even a CLEAN same-host transfer is flaky. This knob
/// makes same-host gates deterministic by advertising ONLY loopback. NOT a
/// product knob, only the local sim gates set it.
/// Test-only, compiled in ONLY under `--features test-hooks`; the production
/// twin returns `false` so a default/release build never reads the env and
/// advertises the real candidate set.
#[cfg(feature = "test-hooks")]
fn loopback_only() -> bool {
    std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY").map(|v| v == "1").unwrap_or(false)
}
#[cfg(not(feature = "test-hooks"))]
#[inline]
fn loopback_only() -> bool {
    false
}

/// True exactly when the dial-ahead for candidate `cand` is a dial OF the
/// peer's claimed server-asserted address. The peer's claim comes off the
/// wire untrusted, so this is the ONLY thing that may let the fallback name
/// it: the name and the dialed address must be the SAME socket. A claim that
/// does not parse, or a candidate that does not parse, or two addresses that
/// merely look alike, all yield false - the attribution may only state a fact
/// it established by dialing.
fn dials_claimed(claimed: Option<SocketAddr>, cand: &str) -> bool {
    match (claimed, cand.parse::<SocketAddr>()) {
        (Some(c), Ok(a)) => c == a,
        _ => false,
    }
}

/// Gather all advertisable candidates for our bound endpoint port, and return
/// (cands, adopted_server_public) where the second element is exactly the
/// server-asserted (`whoami`) candidate that was ADOPTED into the set - computed
/// in the SAME place the push decision is made, so there is no second copy of
/// the rule to desynchronize. `Some(s)` means `s` was appended on the server's
/// say-so alone (no peer had observed us, whoami not suppressed, and the answer
/// was not a local address); `None` means no server-chosen address was adopted.
/// The relay fallback carries that value to name it at the decision, so the
/// attribution can never name an address the candidate set did not contain.
/// `peer` is optional — when provided, per-peer avoid/prefer overrides are read.
pub async fn gather_candidates(server: &str, port: u16) -> (Vec<String>, Option<String>) {
    let peer: Option<&str> = None; // per-peer filter not yet wired from callers
    if loopback_only() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        return (vec![cand_str(lo, port)], None);
    }
    let all_local = local_ips();
    let ips = filter_local_ips(all_local.clone(), peer);
    let mut cands: Vec<String> = ips.into_iter().map(|ip| cand_str(ip, port)).collect();
    if cands.is_empty() && !all_local.is_empty() {
        crate::hooks::debug("iface filter removed ALL host candidates; connectivity may fail");
    }
    let mut adopted_server_public: Option<String> = None;
    if !suppress_public() {
        // #237: the peer-observed address (an authenticated peer saw us connect
        // from it) SUPERSEDES the server's whoami assertion, including the
        // warm pre-warm cache. whoami is only a bootstrap hint for FIRST
        // contact, before any peer has observed us; a wrong answer there costs
        // one slow connection instead of a standing downgrade.
        let observed = observed_public_ip().await;
        let pip = match observed {
            Some(ip) => Some(ip),
            None => public_ip(server).await,
        };
        if let Some(pip) = pip {
            let s = cand_str(pip, port);
            if !cands.contains(&s) {
                if observed.is_none() && !all_local.contains(&pip) {
                    // Gate C (#237): the SAME edge that makes this candidate
                    // server-asserted (adopted on the server's say-so, before
                    // any peer observed us, not local) is the one the fallback
                    // uses to NAME it. Carried value first, forecast second -
                    // one computation, one condition.
                    adopted_server_public = Some(s.clone());
                    // Diagnostic detail, demoted to -v. The HEADLINE is the
                    // fallback attribution in `expired_direct` (the moment of
                    // the symptom), not this forecast.
                    crate::hooks::debug(&format!(
                        "public candidate {s} is server-asserted (bootstrap hint) and unverified; the relay fallback will name it if it never answers"
                    ));
                }
                cands.push(s);
            }
        }
    }
    // Test-only (gate C positive): strip everything but the adopted server-
    // asserted candidate so the race DIALS it for real and fails for real.
    if only_public() {
        return match adopted_server_public.as_ref() {
            Some(s) => (vec![s.clone()], adopted_server_public),
            None => (Vec::new(), None),
        };
    }
    (cands, adopted_server_public)
}

// =============================================================== TLS configs ==

/// Client verifier that accepts ANY server cert. This is SAFE here and ONLY
/// here: authentication does NOT come from the PKI, it comes from the
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

/// Explicit ring provider, we never rely on a process-default crypto provider
/// (webrtc + reqwest both pull rustls into the tree; the default is ambiguous).
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// rung-2 reuses these QUIC configs verbatim, same ALPN, same accept-any-cert +
/// keying-material auth, only the underlying socket differs (a punched one).
/// Keep idle direct-QUIC links alive across NAT UDP-mapping timeouts. Residential
/// NAT drops an idle UDP mapping in ~30-120s, but CONTAINER/relay paths (e.g. a
/// Coder workspace behind DERP) evict far faster, observed ~10s: a warm link gone
/// idle for ten seconds is already dead, yet quinn (and is_alive) only notice it
/// at max_idle_timeout, so warm-reuse grabs the zombie and the next ssh/pty hangs.
/// A 7s keepalive sits UNDER that ~10s window, so the mapping is refreshed before
/// it dies (the link stays genuinely alive across idle gaps); max_idle_timeout
/// (must exceed 2x the keepalive) then closes a TRULY dead peer in ~21s so
/// teardown and warm-link liveness checks see it instead of hanging on a zombie.
fn direct_transport_config() -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    tc.keep_alive_interval(Some(std::time::Duration::from_secs(7)));
    if let Ok(idle) = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(21)) {
        tc.max_idle_timeout(Some(idle));
    }
    // 2 Gbps × 1 ms RTT = ~250 KB BDP. Raise all windows well above that so
    // the pipe stays full and the congestion controller can probe beyond the
    // initial slow-start cwnd. 16 MB each is generous both ways.
    tc.stream_receive_window(quinn::VarInt::from_u32(16_777_216));
    tc.receive_window(quinn::VarInt::from_u32(33_554_432));
    tc.send_window(16_777_216_u64);
    // Congestion control: BBR by default (tolerates non-congestion loss).
    // CUBIC can be selected via FILAMENT_CUBIC=1 — it responds more
    // aggressively to policer loss (rate-limit drops), which can hold closer
    // to the link ceiling on policed paths (e.g. DO 2 Gbps VM cap).
    if std::env::var("FILAMENT_CUBIC").map(|v| v == "1").unwrap_or(false) {
        use quinn_proto::congestion::CubicConfig;
        tc.congestion_controller_factory(Arc::new(CubicConfig::default()));
    } else {
        tc.congestion_controller_factory(Arc::new(quinn_proto::congestion::BbrConfig::default()));
    }
    // L3 data plane: enable QUIC unreliable DATAGRAMs (the serve_tun path rides
    // these, not the reliable streams L2 uses, to avoid TCP-over-TCP meltdown).
    // A 1 MiB receive ring absorbs bursts; advertising it lets the peer send to us.
    tc.datagram_receive_buffer_size(Some(1024 * 1024));
    tc.datagram_send_buffer_size(1024 * 1024);
    Arc::new(tc)
}

pub fn server_config() -> Result<quinn::ServerConfig> {
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
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    sc.transport_config(direct_transport_config());
    Ok(sc)
}

pub fn client_config() -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("client tls versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider())))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .context("quic client config")?;
    let mut cc = quinn::ClientConfig::new(Arc::new(qcc));
    cc.transport_config(direct_transport_config());
    Ok(cc)
}

/// Bind a quinn endpoint on an EPHEMERAL UDP port that BOTH accepts and dials
/// (simultaneous-open over one socket). Returns the endpoint and its port.
/// Uses socket2 for large SO_RCVBUF/SO_SNDBUF to reduce UDP packet loss at
/// high throughput (the default ~208KB kernel buffer overflows at ~1.2 Gbps).
pub fn bind_endpoint() -> Result<(Endpoint, u16)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("socket2 UDP socket")?;
    let buf_size: usize = 8 * 1024 * 1024; // 8 MiB
    sock.set_recv_buffer_size(buf_size)
        .or_else(|_| sock.set_recv_buffer_size(4 * 1024 * 1024))
        .or_else(|_| sock.set_recv_buffer_size(1024 * 1024))
        .context("set SO_RCVBUF")?;
    sock.set_send_buffer_size(buf_size)
        .or_else(|_| sock.set_send_buffer_size(4 * 1024 * 1024))
        .or_else(|_| sock.set_send_buffer_size(1024 * 1024))
        .context("set SO_SNDBUF")?;
    sock.bind(&"0.0.0.0:0".parse::<std::net::SocketAddr>().unwrap().into())
        .context("bind socket")?;
    let port = sock.local_addr().context("sock local addr")?.as_socket().unwrap().port();
    let socket: std::net::UdpSocket = sock.into();
    socket.set_nonblocking(true).context("set nonblocking")?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| anyhow::anyhow!("no async runtime found"))?;
    let mut ep = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config()?),
        runtime.wrap_udp_socket(socket)?,
        runtime,
    )?;
    ep.set_default_client_config(client_config()?);
    Ok((ep, port))
}

// ====================================================== authenticated handshake

/// 32-byte RFC-5705 exporter value, the session-unique channel binding. A
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
        bail!("DIRECT-AUTH-FAIL: pair-secret MAC mismatch, rejecting peer");
    }
    Ok((send, recv))
}

// ===================================================== direct-endpoint L3 (serve_tun)

/// serve_tun LISTEN: bind a QUIC server on `bind` and return the FIRST peer that
/// completes the PSK channel-binding auth. No signaling/pairing: the two ends
/// share `secret` out of band (the WireGuard model). The endpoint is kept alive
/// for the connection's lifetime.
///
/// DoS-hardened: each inbound connection is authenticated in its own task under a
/// timeout, so a peer that completes the QUIC handshake but then stalls (or sends
/// a bad tag) neither blocks `accept()` nor tears the listener down. Only a
/// genuinely authenticated peer is returned; everyone else is dropped silently.
pub async fn serve_tun_listen(bind: SocketAddr, secret: &[u8; 32]) -> Result<quinn::Connection> {
    let ep = Endpoint::server(server_config()?, bind).context("bind serve-tun listener")?;
    let secret = *secret;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<quinn::Connection>(1);
    loop {
        tokio::select! {
            // A candidate finished auth: keep it, let the rest of the in-flight
            // handshakes fall away (their tasks end and drop their connections).
            Some(conn) = rx.recv() => {
                keep_endpoint_alive(ep, &conn);
                return Ok(conn);
            }
            incoming = ep.accept() => {
                let Some(incoming) = incoming else {
                    return Err(anyhow!("listener closed before a peer authenticated"));
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let ok = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                        let conn = incoming.await?;
                        authenticate(&conn, &secret, false).await?;
                        Ok::<_, anyhow::Error>(conn)
                    })
                    .await;
                    if let Ok(Ok(conn)) = ok {
                        let _ = tx.send(conn).await;
                    }
                });
            }
        }
    }
}

/// serve_tun CONNECT: dial `peer`, run the PSK auth, return the connection.
/// Retries briefly so the connector can start before, or alongside, the listener
/// (the lab and most setups don't guarantee ordering).
pub async fn serve_tun_connect(peer: SocketAddr, secret: &[u8; 32]) -> Result<quinn::Connection> {
    let mut ep = Endpoint::client("0.0.0.0:0".parse().unwrap()).context("bind serve-tun client")?;
    ep.set_default_client_config(client_config()?);
    let mut last = anyhow!("serve-tun connect: no attempt made");
    for _ in 0..8 {
        let attempt = async {
            let conn = ep.connect(peer, "filament-direct")?.await?;
            authenticate(&conn, secret, true).await?;
            Ok::<_, anyhow::Error>(conn)
        };
        match attempt.await {
            Ok(conn) => {
                keep_endpoint_alive(ep, &conn);
                return Ok(conn);
            }
            Err(e) => {
                last = e;
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            }
        }
    }
    Err(last.context("serve-tun connect failed after retries"))
}

/// Dropping a quinn `Endpoint` closes every connection it owns, so hold it until
/// THIS connection closes (a detached waiter), then let it drop.
fn keep_endpoint_alive(ep: Endpoint, conn: &quinn::Connection) {
    let c = conn.clone();
    let ep_addr = ep.local_addr().ok();
    let conn_id = conn.stable_id();
    tokio::spawn(async move {
        c.closed().await;
        #[cfg(debug_assertions)]
        #[cfg(debug_assertions)]
        eprintln!("[KEEP-EP-DROP] conn_id={conn_id} ep={ep_addr:?} — connection closed, dropping endpoint");
        drop(ep);
    });
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
    /// The deterministic `polite` role for this link (opposite on the two ends);
    /// selects this end's L2 sid half so the two ends never collide.
    answerer: bool,
    /// The endpoint that created this transport. WORKER transports own their
    /// own endpoint (one per worker). The PRIMARY transport does NOT own the
    /// endpoint (it is shared). When the worker transport is dropped (via
    /// drop_link), the endpoint drops, closing all its connections.
    ep: Option<quinn::Endpoint>,
    /// Running count of file-data bytes this transport has written. Only read by
    /// the data-path-freeze PROOF hook (`freeze_after_bytes`); compiled out
    /// entirely unless `--features test-hooks` is set.
    #[cfg(feature = "test-hooks")]
    sent_data: std::sync::atomic::AtomicU64,
    /// PROOF hook: set once THIS transport's data path has gone dark, so EVERY
    /// subsequent `send_frame` on it parks too (a black-holed path stays dark,
    /// not just the one stream that tripped it), faithful to a NAT-rebind that
    /// strands the data 5-tuple. A fresh transport (rung c) has this clear.
    /// Compiled out entirely unless `--features test-hooks` is set.
    #[cfg(feature = "test-hooks")]
    frozen: std::sync::atomic::AtomicBool,
    /// P5 (GAP-6) PROOF hook: process-uptime (ms) at which THIS transport was
    /// born. The relay->direct upgrade gate uses `FILAMENT_TEST_DIRECT_UNBLOCK_MS`
    /// to LIFT the persistent freeze for transports born AFTER that moment, so the
    /// peer first falls to relay (early transports freeze) and then the prober's
    /// DIRECT standby (a late transport) actually carries data, proving the
    /// detect->verify->UPGRADE path. Compiled out unless `--features test-hooks`.
    #[cfg(feature = "test-hooks")]
    born_ms: u64,
}

impl Drop for DirectTransport {
    fn drop(&mut self) {
        let ep_info = self.ep.as_ref().map(|e| format!("ep={:?}", e.local_addr())).unwrap_or_else(|| "ep=None".to_string());
        #[cfg(debug_assertions)]
        #[cfg(debug_assertions)]
        eprintln!("[DROP] DirectTransport stable_id={} answerer={} {ep_info} close_reason={:?}",
            self.conn.stable_id(), self.answerer, self.conn.close_reason());
    }
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
        // --- TRACE ---
        let trace = cfg!(feature = "debug-logs") && std::env::var("FILAMENT_TRACE_THROUGHPUT").is_ok();
        let t_lock_start = if trace { Some(std::time::Instant::now()) } else { None };
        let mut s = self.send.lock().await;
        let lock_us = t_lock_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        let t_hdr_start = if trace { Some(std::time::Instant::now()) } else { None };
        // QUIC streams apply flow control internally; write_all parks on the
        // peer's receive window, that IS the backpressure (no manual high-water
        // loop needed). A frozen receiver stalls here, so last_activity stops
        // advancing exactly like the DataChannel path's #28 guard.
        if let Err(e) = s.write_all(&hdr).await {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow!("direct write hdr: {e}"));
        }
        let hdr_us = t_hdr_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        let t_body_start = if trace { Some(std::time::Instant::now()) } else { None };
        if let Err(e) = s.write_all(payload).await {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow!("direct write body: {e}"));
        }
        let body_us = t_body_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        if trace && lock_us + hdr_us + body_us > 1000 {
            dlog!("[TRACE direct write_framed] lock={}us hdr={}us body={}us payload_len={} kind={}", lock_us, hdr_us, body_us, payload.len(), kind);
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

    async fn send_frame(&self, sid: u32, offset: u64, payload: &[u8]) -> Result<()> {
        // P5 (GAP-6): the relay->direct UPGRADE lift. A transport born AFTER the
        // unblock moment is the prober's DIRECT standby, let it carry data so the
        // verify-before-upgrade can confirm + cut over. In FLAKY mode the lift is
        // granted only for the first few KB (it connects + looks alive for a beat),
        // then it re-freezes, exercising the no-flap guard (verify must DISCARD it).
        #[cfg(feature = "test-hooks")]
        let unblocked = match direct_unblock_after_ms() {
            Some(after) => self.born_ms >= after,
            None => false,
        };
        #[cfg(feature = "test-hooks")]
        if unblocked && !self.frozen.load(std::sync::atomic::Ordering::Relaxed) {
            // Healthy upgrade standby: stream normally (no freeze ever).
            if !direct_flaky_upgrade() {
                let mut framed = Vec::with_capacity(4 + 8 + payload.len());
                framed.extend_from_slice(&sid.to_be_bytes());
                framed.extend_from_slice(&offset.to_be_bytes());
                framed.extend_from_slice(payload);
                self.write_framed(KIND_DATA, &framed).await?;
                self.last_activity.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
                return Ok(());
            }
            // Flaky standby: carry a few KB (so it connects and looks alive for a
            // beat), then re-freeze so the verify window can never confirm.
            let prior = self
                .sent_data
                .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
            if prior + (payload.len() as u64) >= FLAKY_REFREEZE_BYTES {
                self.frozen.store(true, std::sync::atomic::Ordering::Relaxed);
                eprintln!("[test] FLAKY direct standby re-froze at {prior} bytes, verify must discard it");
                loop {
                    if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
                        return Err(anyhow!("direct connection closed (flaky standby discarded)"));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
            let mut framed = Vec::with_capacity(4 + 8 + payload.len());
            framed.extend_from_slice(&sid.to_be_bytes());
            framed.extend_from_slice(&offset.to_be_bytes());
            framed.extend_from_slice(payload);
            self.write_framed(KIND_DATA, &framed).await?;
            self.last_activity.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
        // P0 PROOF hook: black-hole the data path after N bytes on the FIRST
        // transport. We DON'T write and DON'T stamp last_activity, so this
        // transport's idle_ms() climbs while the connection stays up and control
        // frames keep flowing, exactly the stall the bytes-moved watchdog must
        // catch. Parking here (not erroring) mimics a wire that silently drops
        // data: the sender just stops making progress. One-shot via FROZE_ONCE,
        // so the ladder's fresh re-dial (rung c) streams normally and recovers.
        #[cfg(feature = "test-hooks")]
        if let Some(limit) = freeze_after_bytes() {
            // Engage the freeze the first time THIS transport crosses the byte
            // threshold AND no transport has frozen yet (one episode per process).
            if !self.frozen.load(std::sync::atomic::Ordering::Relaxed) {
                let prior = self
                    .sent_data
                    .fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                if freeze_persist() {
                    // Persistent mode (P1 relay-fallback gate): EVERY direct
                    // transport freezes. The FIRST one freezes after `limit` bytes
                    // (so the receiver builds a real .part to resume from); once
                    // that first freeze has happened (FROZE_ONCE latched), every
                    // SUBSEQUENT fresh direct transport, the ladder's rung-c
                    // re-dials, freezes IMMEDIATELY (at byte 0), making zero
                    // progress. So direct can NEVER carry the file forward and the
                    // ladder must exhaust → escalate to relay (rung d). Without the
                    // immediate-freeze, each re-dial would ship another `limit`
                    // bytes, note_progress would reset the episode, and the ladder
                    // would loop on direct forever instead of escalating.
                    let already_froze = FROZE_ONCE.load(std::sync::atomic::Ordering::SeqCst);
                    let cross = prior + (payload.len() as u64) >= limit;
                    if already_froze || cross {
                        FROZE_ONCE.store(true, std::sync::atomic::Ordering::SeqCst);
                        self.frozen.store(true, std::sync::atomic::Ordering::Relaxed);
                        eprintln!("[test] data-path FREEZE engaged at {} bytes, black-holing this transport", prior);
                    }
                } else if prior + (payload.len() as u64) >= limit
                    && !FROZE_ONCE.swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    // One-shot (P0): only the FIRST transport freezes; rung-c's
                    // fresh re-dial streams normally and recovers.
                    self.frozen.store(true, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("[test] data-path FREEZE engaged at {} bytes, black-holing this transport", prior);
                }
            }
            // Once dark, EVERY send_frame on this transport parks, the path
            // stays black-holed until the ladder tears it down (rung c).
            if self.frozen.load(std::sync::atomic::Ordering::Relaxed) {
                loop {
                    if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
                        return Err(anyhow!("direct connection closed (frozen path repaired)"));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
        // --- PROD PATH: scatter-gather without intermediate Vec copy ---
        // Previously this was behind a test-hook guard (dead code in prod), causing
        // an extra 1 MiB alloc+memcpy per chunk. Now we write directly.
        let trace = cfg!(feature = "debug-logs") && std::env::var("FILAMENT_TRACE_THROUGHPUT").is_ok();
        let t_total_start = if trace { Some(std::time::Instant::now()) } else { None };
        let t_lock_start = if trace { Some(std::time::Instant::now()) } else { None };
        let mut s = self.send.lock().await;
        let lock_us = t_lock_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(anyhow!("direct connection closed"));
        }
        let mut hdr = [0u8; 5];
        hdr[0] = KIND_DATA;
        let payload_len = (4 + 8 + payload.len()) as u32;
        hdr[1..5].copy_from_slice(&payload_len.to_be_bytes());
        let t_hdr_start = if trace { Some(std::time::Instant::now()) } else { None };
        if let Err(e) = s.write_all(&hdr).await {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow!("direct write hdr: {e}"));
        }
        let hdr_us = t_hdr_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        let t_sid_start = if trace { Some(std::time::Instant::now()) } else { None };
        if let Err(e) = s.write_all(&sid.to_be_bytes()).await {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow!("direct write sid: {e}"));
        }
        let sid_us = t_sid_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        let t_off_start = if trace { Some(std::time::Instant::now()) } else { None };
        if let Err(e) = s.write_all(&offset.to_be_bytes()).await {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow!("direct write offset: {e}"));
        }
        let off_us = t_off_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        let t_body_start = if trace { Some(std::time::Instant::now()) } else { None };
        if let Err(e) = s.write_all(payload).await {
            self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(anyhow!("direct write body: {e}"));
        }
        let body_us = t_body_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        drop(s);
        let total_us = t_total_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
        if trace {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let c = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if c % 10 == 0 || total_us > 5000 {
                dlog!("[TRACE direct send_frame] sid={} offset={} len={} lock={}us hdr={}us sid={}us off={}us body={}us total={}us", sid, offset, payload.len(), lock_us, hdr_us, sid_us, off_us, body_us, total_us);
            }
        }
        self.last_activity.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
        // Bug 2 PROOF hook: force structural death mid-transfer after N bytes.
        // One-shot: only the first transport dies; the re-dial (rung c) streams
        // normally and recovers. total crosses the threshold AFTER this frame's
        // bytes have been written, so the receiver has a real partial on disk.
        if let Some(limit) = die_after_bytes() {
            let total = TOTAL_DIRECT_BYTES.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed) + payload.len() as u64;
            if total >= limit && !DIED_ONCE.swap(true, std::sync::atomic::Ordering::SeqCst) {
                self.dead.store(true, std::sync::atomic::Ordering::Relaxed);
                eprintln!("[test] DIRECT DEATH at {} total bytes (limit={}), transport killed", total, limit);
                return Err(anyhow!("direct connection killed (test hook DIE_AT) after {} bytes", total));
            }
        }
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // Per-file flush (called after every `file-end`). QUIC is ordered and
        // reliable, so file N's buffered tail is delivered before file N+1's
        // bytes with no app-layer action, and we MUST NOT `finish()` here or a
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
        // CONNECTION_CLOSE immediately and discards anything not yet acked, on a
        // real WAN that truncates the last file's tail (loopback hid it: the
        // buffer drains before close). quinn's documented barrier: `finish()` the
        // stream (this runs ONLY at final teardown, so ending the send half is
        // correct), then await `stopped()`, which resolves `Ok(None)` once the
        // peer has acknowledged receipt of every byte incl. the FIN.
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(()); // connection already gone, nothing left to drain
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

    // --- L3 data plane (serve_tun): IP packets over QUIC unreliable datagrams ---
    // Datagrams, NOT the reliable streams send_frame uses: tunneling a reliable
    // transport over another reliable one collapses under loss (double retransmit).
    // Datagrams are lossy + unordered, like the UDP WireGuard rides, so the inner
    // flow's own congestion control stays in charge.
    fn supports_datagrams(&self) -> bool {
        true
    }
    fn is_dead(&self) -> bool {
        self.dead.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn quic_connection(&self) -> Option<quinn::Connection> {
        // Cloning a quinn::Connection is a handle clone, not a new connection.
        Some(self.conn.clone())
    }
    fn force_close(&self) {
        self.conn.close(0u32.into(), b"dropped");
    }

    async fn open_stream(&self) -> Option<(quinn::SendStream, quinn::RecvStream, quinn::Connection)> {
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        match self.conn.open_bi().await {
            Ok(s) => Some((s.0, s.1, self.conn.clone())),
            Err(_) => None,
        }
    }

    fn send_datagram(&self, packet: &[u8]) -> Result<()> {
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(anyhow!("direct connection closed"));
        }
        self.conn
            .send_datagram(bytes::Bytes::copy_from_slice(packet))
            .map_err(|e| anyhow!("send_datagram: {e}"))
    }

    async fn recv_datagram(&self) -> Result<bytes::Bytes> {
        self.conn
            .read_datagram()
            .await
            .map_err(|e| anyhow!("read_datagram: {e}"))
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    fn channel_binding(&self) -> Option<Vec<u8>> {
        // The same RFC-5705 exporter the pair-secret auth binds to; a relay that
        // terminates TLS on each leg derives a DIFFERENT value, so an announce
        // signed against it cannot be forwarded/replayed across the relay.
        keying_material(&self.conn).ok().map(|km| km.to_vec())
    }

    fn sid_answerer(&self) -> bool {
        self.answerer
    }

    fn idle_ms(&self) -> u64 {
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return u64::MAX;
        }
        let _ = &self.conn; // keep the connection alive for the link's lifetime
        now_ms().saturating_sub(self.last_activity.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn is_alive(&self) -> bool {
        // Our own teardown flag, OR quinn having closed the connection (idle
        // timeout from the keepalive probe, peer close, transport error). With the
        // 15s keepalive + 30s idle timeout, a NAT-dead or departed peer flips this
        // within ~30s, so warm-link reuse skips it and falls back.
        !self.dead.load(std::sync::atomic::Ordering::Relaxed)
            && self.conn.close_reason().is_none()
    }

    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        // The actual UDP 5-tuple this direct link is pinned to (post hole-punch
        // this is the punched peer address, like what `tailscale ping` prints).
        Some(self.conn.remote_address())
    }

    fn rtt_ms(&self) -> Option<u64> {
        // quinn's smoothed RTT estimate, measured continuously from ACKs (kept
        // fresh by the 7s keepalive) - no peer cooperation or round-trip needed.
        Some(self.conn.rtt().as_millis() as u64)
    }

    fn local_ip(&self) -> Option<std::net::IpAddr> {
        // The local address quinn's socket actually sends from for this link.
        // Maps to the outbound interface (tailscale0 / eth0 / docker0) so ping
        // can name the path's local end without guessing.
        self.conn.local_ip()
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
    answerer: bool,
) {
    tokio::spawn(async move {
        let trace = cfg!(feature = "debug-logs") && std::env::var("FILAMENT_TRACE_THROUGHPUT").is_ok();
        let mut last_chunk_time = if trace { Some(std::time::Instant::now()) } else { None };
        let mut chunk_counter: u64 = 0;
        loop {
            let t_hdr_start = if trace { Some(std::time::Instant::now()) } else { None };
            let mut hdr = [0u8; 5];
            if let Err(e) = recv.read_exact(&mut hdr).await {
                // FinishedEarly is the peer cleanly ending their send half
                // (e.g. after the final file chunk). Our WRITE half is still
                // open for delivery-ack — DO NOT mark the transport as dead.
                if matches!(&e, quinn::ReadExactError::FinishedEarly(_)) {
                    break;
                }
                #[cfg(debug_assertions)]
                #[cfg(debug_assertions)]
                eprintln!("[DEAD] spawn_reader: peer={} answerer={answerer} read hdr error: {e:?}", peer_id);
                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
            let kind = hdr[0];
            let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
            // Guard against an absurd length (a corrupt/hostile peer); cap well
            // above MAX_DIRECT_PAYLOAD + the 4-byte sid.
            if len > MAX_DIRECT_PAYLOAD + 64 {
                #[cfg(debug_assertions)]
                #[cfg(debug_assertions)]
                eprintln!("[DEAD] spawn_reader: peer={} absurd len={}", peer_id, len);
                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
            let hdr_us = t_hdr_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
            let t_body_start = if trace { Some(std::time::Instant::now()) } else { None };
            let mut body = vec![0u8; len];
            if let Err(e) = recv.read_exact(&mut body).await {
                // FinishedEarly after a header means clean end-of-stream after
                // the sender's final frame — not a protocol error.
                if matches!(&e, quinn::ReadExactError::FinishedEarly(_)) {
                    break;
                }
                #[cfg(debug_assertions)]
                #[cfg(debug_assertions)]
                eprintln!("[DEAD] spawn_reader: peer={} read body error kind={} err={e:?}", peer_id, kind);
                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
            let body_us = t_body_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
            match kind {
                KIND_CONTROL => {
                    if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                        let _ = tx.send(crate::net::Ev::Control(peer_id.clone(), v));
                    }
                }
                KIND_DATA => {
                    // Frame: [4B sid][8B abs_offset][payload]
                    if body.len() >= 12 {
                        last_activity.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
                        let sid = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                        let offset = u64::from_be_bytes([
                            body[4], body[5], body[6], body[7],
                            body[8], body[9], body[10], body[11],
                        ]);
                        // --- TRACE ---
                        if trace {
                            chunk_counter += 1;
                            let now = std::time::Instant::now();
                            let since_last = last_chunk_time.map(|t| now.duration_since(t).as_micros()).unwrap_or(0);
                            last_chunk_time = Some(now);
                            if chunk_counter % 10 == 0 || since_last > 5000 {
                                dlog!("[TRACE direct recv] chunk={} hdr_read={}us body_read={}us since_last_chunk={}us len={} sid={} offset={}", chunk_counter, hdr_us, body_us, since_last, len, sid, offset);
                            }
                        }
                        // Zero-copy: convert Vec directly to Bytes, then split off the 12-byte prefix.
                        let bytes = bytes::Bytes::from(body);
                        let _ = tx.send(crate::net::Ev::Chunk(
                            peer_id.clone(),
                            sid,
                            Some(offset),
                            bytes.slice(12..),
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
pub fn make_transport(
    peer_id: String,
    conn: quinn::Connection,
    send: SendStream,
    recv: RecvStream,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
    answerer: bool,
    ep: Option<quinn::Endpoint>,
) -> Arc<dyn Transport> {
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(now_ms()));
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    spawn_reader(peer_id, recv, tx, last_activity.clone(), dead.clone(), answerer);
    Arc::new(DirectTransport {
        conn,
        send: Arc::new(Mutex::new(send)),
        last_activity,
        dead,
        answerer,
        ep,
        #[cfg(feature = "test-hooks")]
        sent_data: std::sync::atomic::AtomicU64::new(0),
        #[cfg(feature = "test-hooks")]
        frozen: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "test-hooks")]
        born_ms: now_ms(),
    })
}

/// Mesh reuse: spawn a background task that accepts new incoming QUIC streams
/// on an existing connection. Each accepted stream gets wrapped as a transport
/// and sent as a worker via Ev::DirectWorkersReady — avoiding the 1-RTT
/// handshake for file transfers that re-use the L3 mesh connection.
pub fn spawn_mesh_accept(
    pid: String,
    t: &std::sync::Arc<dyn crate::net::Transport>,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
) {
    if let Some(dt) = t.as_any().downcast_ref::<DirectTransport>() {
        let conn = dt.conn.clone();
        tokio::spawn(async move {
            loop {
                match conn.accept_bi().await {
                    Ok((send, recv)) => {
                        let conn2 = conn.clone();
                        let worker = make_transport(pid.clone(), conn2, send, recv, tx.clone(), true, None);
                        let _ = tx.send(crate::net::Ev::DirectWorkersReady(pid.clone(), vec![worker]));
                    }
                    Err(_) => return,
                }
            }
        });
    }
}

// ========================================================== multi-stream workers ==

/// Dial one direct-QUIC worker connection per port in `ports`.  Each connection
/// gets its OWN endpoint (own UDP socket, own QUIC driver task), letting packet
/// I/O parallelise across cores.  Returns however many completed within the
/// 5-second budget (may be fewer; the caller gracefully degrades).
/// Called by the non-answerer side after receiving the `worker-ports` message.
pub async fn dial_workers(
    ports: Vec<u16>,
    peer_ip: IpAddr,
    tkey: [u8; 32],
    peer_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
    count: usize,
) -> Vec<Arc<dyn Transport>> {
    const WORKER_BUDGET: Duration = Duration::from_secs(5);
    if count == 0 || ports.is_empty() {
        return vec![];
    }
    let mut workers = Vec::with_capacity(count.min(ports.len()));
    let deadline = tokio::time::sleep(WORKER_BUDGET);
    tokio::pin!(deadline);

    use futures_util::stream::StreamExt;
    let mut futs: futures_util::stream::FuturesUnordered<_> = ports
        .into_iter()
        .map(|port| {
            let tkey = tkey;
            Box::pin(async move {
                let (ep, _) = bind_endpoint()?;
                let peer = SocketAddr::new(peer_ip, port);
                let connecting =
                    ep.connect(peer, "filament-direct").context("worker connect")?;
                let conn = connecting.await.context("worker dial handshake")?;
                let (s, r) = authenticate(&conn, &tkey, true).await?;
                // Pass the endpoint to make_transport so its lifetime is
                // bound to the DirectTransport (no detached keepalive task).
                Ok::<_, anyhow::Error>((conn, s, r, ep))
            })
        })
        .collect();

    loop {
        tokio::select! {
            result = futs.next() => {
                match result {
                    Some(Ok((conn, send, recv, ep))) => {
                        workers.push(make_transport(
                            peer_id.clone(), conn, send, recv, tx.clone(), false, Some(ep),
                        ));
                        if workers.len() >= count { break; }
                    }
                    Some(Err(e)) => {
                        crate::hooks::debug(&format!("worker dial: {e}"));
                    }
                    None => break,
                }
            }
            _ = &mut deadline => break,
        }
    }
    workers
}

/// Accept `count` additional direct-QUIC worker connections, one per endpoint,
/// and authenticate each as an acceptor.  Returns however many arrived within
/// the 5-second budget.  Each endpoint in `endpoints` has its own UDP socket,
/// letting the QUIC driver tasks parallelise across cores.
/// Called by the answerer side after the primary transport wins its race.
pub async fn accept_workers(
    endpoints: Vec<Endpoint>,
    tkey: [u8; 32],
    peer_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
    count: usize,
) -> Vec<Arc<dyn Transport>> {
    const WORKER_BUDGET: Duration = Duration::from_secs(5);
    if count == 0 || endpoints.is_empty() {
        return vec![];
    }
    let mut workers = Vec::with_capacity(count.min(endpoints.len()));
    let deadline = tokio::time::sleep(WORKER_BUDGET);
    tokio::pin!(deadline);

    use futures_util::stream::StreamExt;
    let mut futs: futures_util::stream::FuturesUnordered<_> = endpoints
        .into_iter()
        .map(|ep| {
            let tkey = tkey;
            Box::pin(async move {
                match ep.accept().await {
                    Some(incoming) => {
                        let conn = incoming.await.context("worker accept handshake")?;
                        let (s, r) = authenticate(&conn, &tkey, false).await?;
                        // Pass the endpoint to make_transport so its lifetime
                        // is bound to the DirectTransport.
                        Ok::<_, anyhow::Error>((conn, s, r, ep))
                    }
                    None => bail!("worker endpoint closed before connection arrived"),
                }
            })
        })
        .collect();

    loop {
        tokio::select! {
            result = futs.next() => {
                match result {
                    Some(Ok((conn, send, recv, ep))) => {
                        workers.push(make_transport(
                            peer_id.clone(), conn, send, recv, tx.clone(), true, Some(ep),
                        ));
                        if workers.len() >= count { break; }
                    }
                    Some(Err(e)) => {
                        crate::hooks::debug(&format!("worker accept: {e}"));
                    }
                    None => break,
                }
            }
            _ = &mut deadline => break,
        }
    }
    workers
}

// ============================================================== orchestrator ==

fn answerer_for(my_uid: &str, peer_uid: &str, my_id: &str, peer_id: &str) -> Result<bool> {
    crate::net::ensure_ascii_session_id(my_id)?;
    crate::net::ensure_ascii_session_id(peer_id)?;
    crate::net::polite_role(my_uid, peer_uid, my_id, peer_id)
}

fn preferred_connection(is_dialer: bool, answerer: bool) -> bool {
    is_dialer == !answerer
}

/// The simultaneous-open race: run the acceptor AND dial every peer candidate
/// concurrently; the FIRST connection to pass the pair-secret MAC wins, the
/// rest are dropped. Returns an authenticated `Arc<dyn Transport>` or None
/// (caller then falls back to WebRTC). Bounded by `DIRECT_BUDGET`.
///
/// `endpoint` is the already-bound shared endpoint (so the advertised port is
/// the one we actually listen on). `peer_cands` are the peer's advertised
/// `ip:port` strings. `secret` is the pair secret (known-device only, rung 1).
pub async fn race_connect(
    endpoint: Endpoint,
    peer_cands: Vec<String>,
    secret: &str,
    peer_id: String,
    my_uid: String,
    peer_uid: String,
    my_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
    exchange: bool,
    peer_claimed: Option<SocketAddr>,
    server_public_dialed: Arc<AtomicBool>,
) -> Option<Arc<dyn Transport>> {
    race_connect_labeled(endpoint, peer_cands, secret, peer_id, my_uid, peer_uid, my_id, tx, "direct-quic", exchange, peer_claimed, server_public_dialed).await
}

/// Same race, but with the route label parameterized so rung-2 (hole-punch) can
/// reuse this verbatim and emit `route: holepunched`. rung-1 calls the wrapper
/// above with `direct-quic`; nothing else about the race changes.
///
/// `exchange` is the negotiated observed-address exchange agreement: true only
/// when BOTH ends' transport-offers said `proto >= 2`. When either side is an
/// older build the frame is skipped on BOTH sides (byte-identical stream, no
/// hang, no misalignment), it is never read without the peer having agreed to
/// write it.
///
/// `peer_claimed` is the peer's wire-carried `server_public` claim, parsed. It
/// is UNTRUSTED: it only becomes a fact when the dial loop below actually
/// dials that address. `server_public_dialed` is set true exactly then and
/// nowhere else, so the relay fallback can say "dialed and never answered"
/// only about an address it dialed - never about a label that merely appeared
/// on the wire.
pub async fn race_connect_labeled(
    endpoint: Endpoint,
    peer_cands: Vec<String>,
    secret: &str,
    peer_id: String,
    my_uid: String,
    peer_uid: String,
    my_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
    route: &str,
    exchange: bool,
    peer_claimed: Option<SocketAddr>,
    server_public_dialed: Arc<AtomicBool>,
) -> Option<Arc<dyn Transport>> {
    let answerer = match answerer_for(&my_uid, &peer_uid, &my_id, &peer_id) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("direct role election failed for peer {peer_id}: {error}");
            return None;
        }
    };
    // The test-block knob only simulates a blocked rung-1 (direct-quic) path so
    // the WebRTC fallback gate can assert. It must NOT short-circuit rung-2, a
    // hole-punch race carries a distinct label. It returns BEFORE any dial, so
    // `server_public_dialed` stays false and the fallback attribution stays
    // silent - the gate's negative control for "we never got to the candidate".
    if route == "direct-quic" && test_block() {
        // Fallback gate: pretend the direct path is unreachable. Drop the
        // endpoint and let the budget expire so WebRTC takes over.
        eprintln!("filament: DIRECT-BLOCKED (test), forcing WebRTC fallback");
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
        exchange: bool,
    ) -> Result<(quinn::Connection, SendStream, RecvStream, bool)> {
        let (mut s, mut r) = authenticate(&conn, &tkey, is_dialer).await?;
        // #237: after auth, exchange the peer-observed address. The acceptor
        // tells the dialer the source address it saw the dialer connect from;
        // the dialer records it and supersedes the server's whoami assertion.
        // Only when BOTH ends agreed (proto >= 2 in their transport-offers),
        // so a mixed old/new fleet skips the frame on both sides instead of
        // hanging or misaligning the stream.
        exchange_observed_address(&conn, is_dialer, &mut s, &mut r, exchange).await?;
        Ok((conn, s, r, is_dialer))
    }

    /// Post-auth observed-address exchange (see `auth_conn`). The acceptor
    /// writes the dialer's source address (as the acceptor sees it); the dialer
    /// reads it and records it as its peer-observed public address. Framed as a
    /// 2-byte BE length + ASCII IP, read exactly by the dialer before the stream
    /// is handed to `DirectTransport`, so the transport's own framing stays
    /// aligned. Auth failures already dropped the connection, so both sides are
    /// authenticated here; a malformed frame just means no observation recorded.
    /// When `exchange` is false (either side predates #237's exchange) the frame
    /// is skipped on BOTH sides - the stream is byte-identical to the old
    /// protocol, so an old peer links fine and a clear refusal is surfaced by
    /// the caller (on_transport_offer) instead.
    async fn exchange_observed_address(
        conn: &quinn::Connection,
        is_dialer: bool,
        send: &mut SendStream,
        recv: &mut RecvStream,
        exchange: bool,
    ) -> Result<()> {
        if !exchange {
            return Ok(());
        }
        if is_dialer {
            // Defensive: a peer that AGREED to the exchange but never sends the
            // frame must not hang the direct link (a hang and a refusal are
            // indistinguishable to the operator). Time out, skip the exchange,
            // and keep the authenticated connection - the stream is clean on
            // our side, and a conforming peer wrote the frame immediately after
            // auth, so this only ever fires on an inconsistent build.
            let timeout_read = async {
                let mut lenb = [0u8; 2];
                recv.read_exact(&mut lenb).await.context("read observed-address length")?;
                let len = u16::from_be_bytes(lenb) as usize;
                if len > 64 {
                    anyhow::bail!("observed-address frame too long ({len})");
                }
                let mut buf = vec![0u8; len];
                recv.read_exact(&mut buf).await.context("read observed-address")?;
                Ok::<Vec<u8>, anyhow::Error>(buf)
            };
            match tokio::time::timeout(std::time::Duration::from_secs(3), timeout_read).await {
                Ok(Ok(buf)) => {
                    if let Ok(s) = std::str::from_utf8(&buf) {
                        if let Ok(ip) = s.trim().parse::<IpAddr>() {
                            record_observed_ip(ip).await;
                            crate::hooks::trace(&format!("filament: peer observed us from {ip}; supersedes whoami"));
                        }
                    }
                }
                Ok(Err(e)) => {
                    // A malformed frame is not an observation; the connection
                    // still works. Surface it so the operator can see it.
                    crate::hooks::debug(&format!("filament: observed-address exchange failed ({e}); skipping"));
                }
                Err(_) => {
                    crate::hooks::say("filament: peer agreed to the observed-address exchange but never sent the frame; skipping (inconsistent older build)");
                }
            }
        } else {
            let ip = conn.remote_address().ip();
            let b = ip.to_string();
            let bytes = b.as_bytes();
            if bytes.len() > u16::MAX as usize {
                anyhow::bail!("observed-address too long");
            }
            send.write_all(&(bytes.len() as u16).to_be_bytes()).await.context("write observed-address length")?;
            send.write_all(bytes).await.context("write observed-address")?;
        }
        Ok(())
    }

    let mut futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = Result<(quinn::Connection, SendStream, RecvStream, bool)>> + Send>>> = Vec::new();

    // Acceptor side: accept exactly one inbound, then auth as acceptor. The
    // deterministic winner fallback below depends on this bound; an accept
    // loop requires a new selection rule.
    {
        let ep = endpoint.clone();
        let tkey = tkey;
        futs.push(Box::pin(async move {
            let incoming = ep.accept().await.ok_or_else(|| anyhow!("endpoint closed"))?;
            let conn = incoming.await.context("accept handshake")?;
            auth_conn(conn, tkey, false, exchange).await
        }));
    }

    // Dialer side: one future per candidate, auth as dialer.
    for cand in peer_cands {
        let Ok(addr) = cand.parse::<SocketAddr>() else { continue };
        // #237: the fallback attribution ("X never answered") is only honest
        // when the PEER CLAIMED server-asserted address, and only THAT address,
        // was actually dialed. Mark the flag at the candidate that equals the
        // claim (after a successful parse), so a claim that was never in the
        // dial set - or that does not even parse - can never be named by the
        // fallback. The fact and the sentence are tied to the same address.
        if dials_claimed(peer_claimed, &cand) {
            server_public_dialed.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let ep = endpoint.clone();
        let tkey = tkey;
        futs.push(Box::pin(async move {
            let connecting = ep
                .connect(addr, "filament-direct")
                .context("connect")?;
            let conn = connecting.await.context("dial handshake")?;
            auth_conn(conn, tkey, true, exchange).await
        }));
    }

    let race = async {
        use futures_util::stream::{FuturesUnordered, StreamExt};
        let mut set: FuturesUnordered<_> = futs.into_iter().collect();
        let mut fallback = None;
        // Prefer the connection dialed by the non-answerer. If both directions
        // authenticate, both ends see and choose that same connection. If only
        // one direction exists, both ends fall back to that sole connection.
        // The fallback is unique because mutual authentication plus this
        // single accept bounds successful connections to one per direction;
        // changing accept into a loop would require a new winner rule.
        // Give the preferred direction a quarter of the existing direct budget
        // to arrive after a non-preferred auth. This is bounded by a derived
        // transport timeout, not a new magic latency, and only matters when the
        // answerer authenticated its own dial first.
        let preferred_deadline = tokio::time::Instant::now() + DIRECT_BUDGET / 4;
        loop {
            let next = tokio::time::timeout_at(preferred_deadline, set.next()).await;
            let Some(res) = (match next {
                Ok(value) => value,
                Err(_) => return fallback,
            }) else { return fallback };
            match res {
                Ok((conn, send, recv, is_dialer)) => {
                    if preferred_connection(is_dialer, answerer) {
                        return Some((conn, send, recv, is_dialer));
                    }
                    fallback = Some((conn, send, recv, is_dialer));
                }
                Err(e) => {
                    // Auth failures are the negative-gate signal, make them
                    // greppable. Dial failures (unreachable candidate) are noise.
                    let s = e.to_string();
                    if s.contains("DIRECT-AUTH-FAIL") {
                        crate::hooks::trace(&format!("filament: {s}"));
                    }
                    continue;
                }
            }
        }
        
    };

    let winner = match tokio::time::timeout(DIRECT_BUDGET, race).await {
        Ok(Some(w)) => w,
        _ => {
            endpoint.close(0u32.into(), b"direct-timeout");
            return None;
        }
    };

    let (conn, send, recv, _is_dialer) = winner;
    // DEBUG, direct-connect diagnostic (the user-facing route label is the
    // `route:` line emitted in main.rs; this is the internal detail).
    crate::hooks::debug(&format!(
        "filament: DIRECT-CONNECT ok (route: {}) peer={} remote={}",
        route,
        peer_id,
        conn.remote_address()
    ));
    // Keep the endpoint alive for the connection's lifetime by leaking it into
    // the transport's closure scope: hold it in a task that lives as long as the
    // connection.
    let ep_for_transport = endpoint.clone(); // clone: one for the keepalive task,
                                             // one for the DirectTransport
    {
        let conn2 = conn.clone();
        tokio::spawn(async move {
            conn2.closed().await;
            #[cfg(debug_assertions)]
            #[cfg(debug_assertions)]
            eprintln!("[KEEP-EP-DROP] endpoint for primary conn_stable={} ep={:?}",
                conn2.stable_id(), endpoint.local_addr());
            drop(endpoint);
        });
    }
    let conn_id = conn.stable_id();
    #[cfg(debug_assertions)]
    #[cfg(debug_assertions)]
    eprintln!("[PRIMARY-MADE] conn_stable={conn_id} answerer={answerer}");
    Some(make_transport(peer_id, conn, send, recv, tx, answerer, Some(ep_for_transport)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answerer_role_is_opposite_for_both_quic_ends() {
        let a = answerer_for("uid-a", "uid-b", "sid-a", "sid-b").unwrap();
        let b = answerer_for("uid-b", "uid-a", "sid-b", "sid-a").unwrap();
        assert_ne!(a, b, "QUIC ends must allocate opposite sid halves");
    }

    #[test]
    fn answerer_role_rejects_non_ascii_session_id() {
        assert!(answerer_for("uid-a", "uid-b", "sid-😀", "sid-b").is_err());
    }

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
    fn pubip_cache_freshness() {
        use std::time::Duration;
        let ttl = Duration::from_secs(300);
        let server = "https://api.filament.autumated.com";
        // Same server, well within TTL -> reusable.
        assert!(pubip_fresh(server, Duration::from_secs(10), server, ttl));
        // Same server, exactly at the boundary -> expired (strict <).
        assert!(!pubip_fresh(server, ttl, server, ttl));
        // Same server, past TTL -> expired.
        assert!(!pubip_fresh(server, Duration::from_secs(600), server, ttl));
        // Different server, even when fresh -> never reused (avoids serving one
        // deployment's reflexive IP to another).
        assert!(!pubip_fresh("https://other.example.com", Duration::from_secs(1), server, ttl));
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

    #[test]
    fn preferred_connection_matches_on_both_ends() {
        assert!(preferred_connection(true, false));
        assert!(!preferred_connection(true, true));
        assert!(!preferred_connection(false, false));
        assert!(preferred_connection(false, true));
    }

    /// #237 regression: once a peer has observed our address, `gather_candidates`
    /// advertises THAT and does not consult the `/api/whoami` cache (which
    /// `warm_public_ip` pre-warms at daemon start with a server assertion). The
    /// server is unreachable here, so if whoami WERE consulted it would return
    /// None and no public candidate would exist; the observed address being
    /// present proves whoami was bypassed. The carried `adopted_server_public`
    /// must be None (a peer-observed address is NOT server-asserted), so the
    /// relay fallback would not name anything for a connection adopted this way.
    /// #237: the fallback may name a peer's claimed server-asserted address only
    /// when that EXACT address was dialed. `dials_claimed` is the two-value
    /// comparison at the dial site: parse-normalized equality (so a merely
    /// cosmetic difference in the label cannot defeat the claim), and false for
    /// everything that does not prove a dial of the claim - a claim that does
    /// not parse surfaces as `None` and can never match, a candidate that does
    /// not parse is skipped by the dial loop, and an address that merely looks
    /// close is not the dialed one.
    #[test]
    fn claimed_means_dialed_exactly() {
        let claimed = Some("8.8.8.8:53".parse::<SocketAddr>().unwrap());
        assert!(dials_claimed(claimed, "8.8.8.8:53"));
        assert!(dials_claimed(claimed, "8.8.8.8:0053"), "cosmetic port formatting must match");
        assert!(!dials_claimed(claimed, "8.8.8.9:53"), "a look-alike address is not the dialed one");
        assert!(!dials_claimed(None, "8.8.8.8:53"), "an absent/unparseable claim is never a dialed claim");
        assert!(
            !dials_claimed(claimed, "8.8.8.8:notaport"),
            "an unparseable candidate is skipped by the dial loop, never a dial of the claim"
        );
    }
    /// #237 regression: once a peer has observed our address, `gather_candidates`
    /// advertises THAT and does not consult the `/api/whoami` cache (which
    /// `warm_public_ip` pre-warms at daemon start with a server assertion). The
    /// server is unreachable here, so if whoami WERE consulted it would return
    /// None and no public candidate would exist; the observed address being
    /// present proves whoami was bypassed. The carried `adopted_server_public`
    /// must be None (a peer-observed address is NOT server-asserted), so the
    /// relay fallback would not name anything for a connection adopted this way.
    #[test]
    fn peer_observed_address_supersedes_whoami() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            record_observed_ip("192.0.2.55".parse().unwrap()).await;
            let (cands, adopted) = gather_candidates("http://127.0.0.1:1", 4242).await;
            assert!(
                cands.iter().any(|c| c.starts_with("192.0.2.55:4242")),
                "the peer-observed address must be advertised and whoami bypassed, got: {cands:?}"
            );
            assert!(
                adopted.is_none(),
                "a peer-observed address must not be reported as server-asserted, got: {adopted:?}"
            );
        });
    }
}
