//! Kernel-WireGuard L3 carrier for `serve-tun --wireguard` (ADR-0001 data plane).
//!
//! filament owns identity, authentication and reachability; WireGuard moves the
//! bytes. The flow: filament first establishes its normal authenticated
//! (channel-bound) connection, then each side generates a Curve25519 WireGuard
//! keypair and swaps {public key, WG listen-port} over that authenticated stream.
//! With the peer's key and endpoint in hand, a kernel WireGuard interface carries
//! the L3 traffic at kernel speed, instead of the userspace QUIC-datagram pump.
//!
//! Linux-only, and requires the `wireguard` kernel module plus the `wg` and `ip`
//! tools (same iproute2 dependency the kernel TUN backend already relies on).

use anyhow::{anyhow, bail, Context, Result};
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// Generate a WireGuard keypair, returned as (private_b64, public_b64), via `wg`.
/// Can this machine actually run kernel WireGuard right now?
///
/// A RUNTIME check, not a compile-time one. The platform surface gate keeps
/// per-platform branching out of files like this, and it would be the wrong tool
/// anyway: a Linux box without wireguard-tools, without the module, or without
/// CAP_NET_ADMIN cannot do this either. Asking the system is the only answer
/// that is true on the machine it runs on.
///
/// Deliberately quiet and cheap: it creates and immediately removes a probe
/// interface, which is the only way to learn whether the module and the
/// capability are both present without waiting for a real failure mid-session.
pub fn usable() -> bool {
    debug_assert!(WG_DEV.len() <= MAX_IFNAME, "wg device name too long for Linux");
    if Command::new("wg").arg("--version").output().map(|o| !o.status.success()).unwrap_or(true) {
        return false;
    }
    // SHORT ON PURPOSE. Linux caps an interface name at 15 characters, and
    // "filament-wgprobe" is 16, so the probe failed with "Attribute failed
    // policy validation" on every machine and usable() always returned false.
    // That silently disabled the entire feature: no error, no log, just a
    // capability check that could never say yes. The device itself,
    // "filament-wg", is 11 and was always fine, which is why this only showed up
    // when the probe was added.
    const PROBE: &str = "fil-wgprobe";
    let _ = ip(&["link", "del", PROBE]);
    if ip(&["link", "add", PROBE, "type", "wireguard"]).is_err() {
        return false;
    }
    let _ = ip(&["link", "del", PROBE]);
    true
}

pub fn gen_keypair() -> Result<(String, String)> {
    let out = Command::new("wg")
        .arg("genkey")
        .output()
        .context("run `wg genkey` (is wireguard-tools installed?)")?;
    if !out.status.success() {
        bail!("wg genkey failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let privkey = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("spawn `wg pubkey`")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("wg pubkey: no stdin"))?
        .write_all(format!("{privkey}\n").as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("wg pubkey failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((privkey, pubkey))
}

fn ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip").args(args).output().context("exec ip")?;
    if !out.status.success() {
        bail!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Create the WG interface with our private key and an ephemeral listen-port, and
/// return the port the kernel actually chose (advertised to the peer as our endpoint).
pub fn create_iface(dev: &str, privkey: &str) -> Result<u16> {
    let _ = ip(&["link", "del", dev]); // best-effort clear a stale interface
    ip(&["link", "add", dev, "type", "wireguard"]).with_context(|| format!("create wg dev {dev} (is the wireguard module loaded?)"))?;

    // `wg set <dev> private-key <path>`: feed the key on stdin via /dev/stdin so it
    // never lands on disk.
    let mut child = Command::new("wg")
        .args(["set", dev, "private-key", "/dev/stdin", "listen-port", "0"])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawn `wg set private-key`")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("wg set: no stdin"))?
        .write_all(format!("{privkey}\n").as_bytes())?;
    if !child.wait()?.success() {
        let _ = ip(&["link", "del", dev]);
        bail!("wg set private-key failed");
    }

    // Bring the interface up so `wg show listen-port` returns the ephemeral
    // port the kernel actually assigned (down interfaces always report 0).
    ip(&["link", "set", "dev", dev, "up"]).with_context(|| format!("bring {dev} up"))?;

    let out = Command::new("wg").args(["show", dev, "listen-port"]).output().context("wg show listen-port")?;
    if !out.status.success() {
        bail!("wg show listen-port failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    String::from_utf8_lossy(&out.stdout).trim().parse::<u16>().context("parse wg listen-port")
}

/// Attach the peer (key + endpoint + allowed-ips), address the interface, bring it up.
pub fn configure_peer(
    dev: &str,
    peer_pub: &str,
    allowed_ips: &str,
    endpoint: &str,
    addr_cidr: &str,
    mtu: u32,
) -> Result<()> {
    let out = Command::new("wg")
        .args([
            "set", dev, "peer", peer_pub, "allowed-ips", allowed_ips, "endpoint", endpoint,
            "persistent-keepalive", "25",
        ])
        .output()
        .context("wg set peer")?;
    if !out.status.success() {
        bail!("wg set peer: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    ip(&["addr", "add", addr_cidr, "dev", dev]).context("ip addr add on wg dev")?;
    ip(&["link", "set", "dev", dev, "mtu", &mtu.to_string()]).context("ip link set mtu")?;
    ip(&["link", "set", "dev", dev, "up"]).context("ip link set up")?;
    Ok(())
}

/// Remove the WG interface (best-effort; used on teardown).
pub fn teardown(dev: &str) {
    let _ = ip(&["link", "del", dev]);
}

/// The network CIDR that `addr_cidr` (IP/PREFIX) sits in, used as the peer's
/// allowed-ips for a point-to-point overlay (route the whole overlay to the peer).
pub fn network_cidr(addr_cidr: &str) -> Result<String> {
    let (ip_s, pfx_s) = addr_cidr.split_once('/').ok_or_else(|| anyhow!("tun-addr must be IP/PREFIX"))?;
    let pfx: u8 = pfx_s.parse().context("bad prefix in tun-addr")?;
    match ip_s.parse::<IpAddr>().context("bad ip in tun-addr")? {
        IpAddr::V4(v4) => {
            if pfx > 32 { bail!("v4 prefix > 32"); }
            let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx as u32) };
            Ok(format!("{}/{}", std::net::Ipv4Addr::from(u32::from(v4) & mask), pfx))
        }
        IpAddr::V6(v6) => {
            if pfx > 128 { bail!("v6 prefix > 128"); }
            let mask = if pfx == 0 { 0 } else { u128::MAX << (128 - pfx as u32) };
            Ok(format!("{}/{}", std::net::Ipv6Addr::from(u128::from(v6) & mask), pfx))
        }
    }
}

/// Format a WireGuard endpoint (bracket IPv6).
pub fn endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Swap {public key, WG listen-port} with the peer over the authenticated
/// connection. The initiator opens the bi stream; the responder accepts it. Both
/// sides write their line, finish, and read the peer's, so it is symmetric.
/// A key exchange must not wait forever.
///
/// `exchange` rendezvouses on a QUIC bi-stream: one side opens, the other
/// accepts. If both ends ever decide to accept, both block indefinitely, the
/// interface exists with no peer, and nothing is logged because neither side
/// reached success or failure. That is precisely what happened before the role
/// was made deterministic, and a bound turns it into a retryable error instead
/// of a silent hang.
const EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub async fn exchange(
    conn: &quinn::Connection,
    our_pub: &str,
    our_port: u16,
    initiator: bool,
) -> Result<(String, u16)> {
    let (mut send, mut recv) = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        if initiator {
            conn.open_bi().await.context("open wg key-exchange stream")
        } else {
            conn.accept_bi().await.context("accept wg key-exchange stream")
        }
    })
    .await
    .map_err(|_| anyhow!("wg key exchange timed out after {EXCHANGE_TIMEOUT:?}"))??;
    send.write_all(format!("{our_pub} {our_port}\n").as_bytes()).await.context("send wg key-exchange")?;
    send.finish().context("finish wg key-exchange")?;

    let buf = recv.read_to_end(1024).await.context("read peer wg key-exchange")?;
    let line = String::from_utf8(buf).context("wg key-exchange not utf8")?;
    let line = line.trim();
    let (pk, pt) = line.split_once(' ').ok_or_else(|| anyhow!("malformed wg key-exchange: {line:?}"))?;
    let port: u16 = pt.trim().parse().context("parse peer wg listen-port")?;
    if pk.is_empty() {
        bail!("empty peer wg public key");
    }
    Ok((pk.to_string(), port))
}

/// The interface filament manages. One device carries every peer, as WireGuard
/// intends: peers are distinguished by public key and allowed-ips, not by device.
pub const WG_DEV: &str = "filament-wg";

/// Linux refuses an interface name longer than this, and does it with a message
/// that names neither the length nor the field.
const MAX_IFNAME: usize = 15;

/// Bring up a WireGuard tunnel to one direct peer, over the connection filament
/// has already authenticated.
///
/// WHY THIS IS SAFE TO ATTEMPT AND SAFE TO FAIL. The key exchange rides the
/// EXISTING QUIC connection (`exchange`), so it inherits filament's identity and
/// adds no new trust story. Every failure path returns `Err` and the caller
/// keeps using the QUIC datagram plane, so a machine without the module, the
/// tools or the capability simply does not get WireGuard: it never gets a
/// half-configured interface instead of a working one.
///
/// `our_overlay` and `peer_overlay` are the overlay addresses already assigned
/// by the mesh, so WireGuard carries exactly the same addressing and nothing
/// downstream (MagicDNS, routes, the capability gate) has to know which plane a
/// packet took.
/// Which end opens the key-exchange stream.
///
/// Derived from the two overlay addresses, which both ends know and agree on, so
/// the answers are GUARANTEED opposite. The previous version used the
/// transport's answerer flag, which is not guaranteed to differ between the two
/// ends: when both computed "accept", each waited for the other to open and the
/// tunnel silently never formed.
pub fn is_initiator(ours: &str, theirs: &str) -> bool {
    ours < theirs
}

pub async fn establish(
    conn: &quinn::Connection,
    initiator: bool,
    our_overlay: &str,
    peer_overlay: &str,
    peer_underlay: std::net::IpAddr,
    mtu: u32,
) -> Result<()> {
    let (privkey, pubkey) = gen_keypair()?;
    // Create ours FIRST so we have a listen port to advertise. Idempotent: a
    // second peer reuses the interface rather than replacing it.
    let port = match existing_listen_port() {
        Some(p) => p,
        None => create_iface(WG_DEV, &privkey)?,
    };
    let (peer_pub, peer_port) = exchange(conn, &pubkey, port, initiator).await?;
    let allowed = format!("{peer_overlay}/128");
    configure_peer(
        WG_DEV,
        &peer_pub,
        &allowed,
        &endpoint(peer_underlay, peer_port),
        &format!("{our_overlay}/128"),
        mtu,
    )?;
    // Route THIS peer's overlay address down the tunnel. Host-scoped, so a
    // WireGuard peer never captures traffic for a peer that is not on it.
    let _ = ip(&["route", "replace", &allowed, "dev", WG_DEV]);
    Ok(())
}

/// The listen port of an interface we already created, if any.
fn existing_listen_port() -> Option<u16> {
    let out = Command::new("wg").args(["show", WG_DEV, "listen-port"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Peers this process has a tunnel to, or is currently building one for.
///
/// The reconcile runs on a timer, so without this a slow rendezvous would be
/// re-attempted every tick and the two ends would pile up half-open bi-streams
/// against each other. Claim before spawning, release on failure so the next
/// tick retries, keep it on success.
static WG_ATTEMPTED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn attempted() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    WG_ATTEMPTED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// True if this call took the claim for `peer`; false if someone already has it.
pub fn claim_attempt(peer: &str) -> bool {
    attempted()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(peer.to_string())
}

/// Give the claim back so a later tick can retry.
pub fn release_attempt(peer: &str) {
    attempted().lock().unwrap_or_else(|e| e.into_inner()).remove(peer);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both ends must not choose the same role, or they deadlock waiting for
    /// each other and the tunnel forms without a peer.
    #[test]
    fn exactly_one_end_initiates() {
        let a = "fdf1::a";
        let b = "fdf1::b";
        assert!(is_initiator(a, b) != is_initiator(b, a), "roles must be opposite");
        assert!(is_initiator(a, b), "the lower address opens the stream");
    }

    /// The probe name being one character over the Linux limit made usable()
    /// return false on every machine, which disabled WireGuard silently: no
    /// error, no log, just a capability check that could never say yes.
    #[test]
    fn interface_names_fit_within_the_kernel_limit() {
        assert!(WG_DEV.len() <= MAX_IFNAME, "{WG_DEV} is {} chars", WG_DEV.len());
        assert!(
            "fil-wgprobe".len() <= MAX_IFNAME,
            "the probe name must fit too, or usable() silently answers no"
        );
    }
}
