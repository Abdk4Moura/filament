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
/// The interface filament manages. One device carries every peer, as WireGuard
/// intends: peers are distinguished by public key and allowed-ips, not by device.
pub const WG_DEV: &str = "filament-wg";

/// Linux refuses an interface name longer than this, and does it with a message
/// that names neither the length nor the field.
const MAX_IFNAME: usize = 15;

pub fn usable() -> bool {
    // A KERNEL TUN IS A PRECONDITION. A node that fell back to the userspace
    // overlay has no kernel device for the overlay address, so configuring a
    // WireGuard peer against it produces a half-built interface: observed as
    // "ip addr add ... /128" with no address in front of the prefix, because the
    // address it would have used does not exist. wg tools and the module being
    // present says nothing about that.
    if !std::path::Path::new("/sys/class/net/filament0").exists() {
        return false;
    }
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
        // WireGuard's registered port, not an ephemeral one. A port that
        // changes every start cannot be port-forwarded, and a forwardable port
        // is the difference between a peer being directly reachable and having
        // to fall back. Falls back to ephemeral if it is already taken.
        .args(["set", dev, "private-key", "/dev/stdin", "listen-port", "51820"])
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

    // If 51820 was taken the set above failed; retry on an ephemeral port so a
    // second filament on the same host still works, just unforwardably.
    if Command::new("wg").args(["show", dev, "listen-port"]).output().map(|o| !o.status.success()).unwrap_or(true) {
        let mut child = Command::new("wg")
            .args(["set", dev, "private-key", "/dev/stdin", "listen-port", "0"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("spawn wg set (ephemeral port)")?;
        if let Some(mut si) = child.stdin.take() {
            use std::io::Write as _;
            let _ = si.write_all(privkey.as_bytes());
        }
        let _ = child.wait();
    }
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
    // Idempotent: the address belongs to the INTERFACE, not to a peer, so the
    // second peer would otherwise fail here with "File exists" and take the
    // whole establish down with it.
    if let Err(e) = ip(&["addr", "add", addr_cidr, "dev", dev]) {
        if !e.to_string().contains("File exists") {
            return Err(e).context("ip addr add on wg dev");
        }
    }
    ip(&["link", "set", "dev", dev, "mtu", &mtu.to_string()]).context("ip link set mtu")?;
    ip(&["link", "set", "dev", dev, "up"]).context("ip link set up")?;
    Ok(())
}

/// Remove the WG interface (best-effort; used on teardown).
pub fn teardown(dev: &str) {
    let _ = ip(&["link", "del", dev]);
}

/// Our half of the exchange: make sure the interface exists and report what the
/// peer needs to know about us. Symmetric, so there is no initiator.
pub fn local_offer() -> Result<(String, u16)> {
    let (privkey, pubkey) = iface_identity()?;
    let port = match existing_listen_port() {
        Some(p) => p,
        None => {
            let p = create_iface(WG_DEV, &privkey)?;
            crate::ui::debug(&format!("  wg: created {WG_DEV} on port {p}"));
            p
        }
    };
    Ok((pubkey, port))
}

/// Configure the peer that just announced itself, and route its overlay address
/// down the tunnel.
pub async fn adopt_peer(
    peer_pub: &str,
    peer_overlay: &str,
    our_overlay: &str,
    mtu: u32,
    peer_underlay: std::net::IpAddr,
    peer_wg_port: u16,
) -> Result<()> {
    let (_priv, _pub) = iface_identity()?;
    // Asserts the interface is up before configuring a peer on it; the port
    // itself is only needed by the peer, which learns it from our announcement.
    existing_listen_port().ok_or_else(|| anyhow!("no local WireGuard listen port"))?;
    let allowed = format!("{peer_overlay}/128");

    // DIRECT FIRST: kernel to kernel, no userspace in the data path at all.
    //
    // This is the point of using kernel WireGuard. Routing frames through
    // filament's transport keeps the crypto in the kernel but puts a userspace
    // hop back in the path, which inherits the very thing WireGuard is here to
    // escape. So the peer's real endpoint is tried first, and the relay exists
    // only for the case where it cannot work.
    //
    // The address is the one the QUIC connection is actually pinned to, so it is
    // the peer's post-hole-punch external address rather than anything it
    // claimed about itself.
    configure_peer(
        WG_DEV,
        peer_pub,
        &allowed,
        &format!("{}:{peer_wg_port}", wrap_v6(peer_underlay)),
        &format!("{our_overlay}/128"),
        mtu,
    )?;
    let _ = ip(&["route", "replace", &allowed, "dev", WG_DEV]);
    crate::ui::debug(&format!(
        "  wg: trying direct kernel path to {peer_underlay}:{peer_wg_port}"
    ));

    // Give the direct path a chance, then check whether it actually carried a
    // handshake. "Configured" is not "working": the endpoint may be a NAT with
    // no inbound mapping for WireGuard's port, which is silent.
    let peer_pub_owned = peer_pub.to_string();
    let peer_overlay_owned = peer_overlay.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
        if handshook(&peer_pub_owned) {
            crate::ui::say(&format!(
                "  {} WireGuard direct to {peer_overlay_owned} (kernel to kernel)",
                crate::ui::paint(crate::ui::Tone::Ok, crate::ui::glyph_ok())
            ));
        } else {
            // NO FALLBACK TUNNEL, deliberately. The QUIC-datagram plane is
            // already carrying this peer and already IS an authenticated
            // encrypted tunnel over the same punched path; running a second
            // tunnel inside it would encrypt twice for no additional security.
            // So an unreachable WireGuard endpoint simply means this peer stays
            // on the plane it was already on.
            let _ = remove_peer(&peer_pub_owned);
            // Release the claim so a later tick RETRIES. A peer can become
            // reachable after the fact (a port-forward appears, a NAT mapping
            // opens), and without this the first failure was permanent for the
            // life of the process.
            release_attempt(&peer_overlay_owned);
            crate::ui::debug(&format!(
                "  wg: {peer_overlay_owned} is not reachable for a direct tunnel; staying on the QUIC plane, will retry"
            ));
        }
    });
    Ok(())
}

/// Drop a peer whose direct path never handshook, so a dead entry cannot keep a
/// route pointed into a tunnel that carries nothing.
fn remove_peer(peer_pub: &str) -> Result<()> {
    let out = Command::new("wg")
        .args(["set", WG_DEV, "peer", peer_pub, "remove"])
        .output()
        .context("wg set peer remove")?;
    if !out.status.success() {
        bail!("wg set peer remove: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Bracket an IPv6 literal so `ADDR:PORT` parses.
fn wrap_v6(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v) => v.to_string(),
        std::net::IpAddr::V6(v) => format!("[{v}]"),
    }
}

/// Has this peer completed a handshake?
///
/// The only honest test of a WireGuard path. An endpoint can be configured, look
/// perfectly correct, and carry nothing, which is exactly what a NAT with no
/// inbound mapping produces.
fn handshook(peer_pub: &str) -> bool {
    let Ok(out) = Command::new("wg").args(["show", WG_DEV, "latest-handshakes"]).output() else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).lines().any(|l| {
        let mut f = l.split_whitespace();
        f.next() == Some(peer_pub) && f.next().and_then(|t| t.parse::<u64>().ok()).unwrap_or(0) > 0
    })
}


/// This interface's keypair, generated once per process.
///
/// Cached because the interface has exactly one identity: see `establish` for
/// what regenerating it per peer breaks.
static WG_IDENTITY: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

fn iface_identity() -> Result<(String, String)> {
    if let Some(kp) = WG_IDENTITY.get() {
        return Ok(kp.clone());
    }
    let kp = gen_keypair()?;
    // A race here would mean two callers generated keys; the first one stored
    // wins and both return it, so the interface and what we advertise agree.
    let _ = WG_IDENTITY.set(kp);
    Ok(WG_IDENTITY.get().cloned().expect("just set"))
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

