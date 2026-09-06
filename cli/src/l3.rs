//! L3 (serve_tun) manager: one TUN for this node, a route table mapping a peer's
//! overlay IP to its link transport, and the datagram pumps. Lives in the `up`
//! daemon, which owns the QUIC connections the datagrams ride.
//!
//! Data path (symmetric on both ends):
//!   TUN read  -> dest IP -> route lookup -> peer.send_datagram(packet)
//!   peer datagram -> TUN write
//!
//! The daemon's link layer is already a full mesh of authenticated links; L3 just
//! attaches an IP plane to it. Each node's overlay address is derived from its
//! Ed25519 overlay key (see `overlay`); peers learn and TRUST each other's address
//! via a SIGNED `l3-announce` verified against the live link's channel binding
//! (main.rs).
//!
//! Both link kinds carry datagrams. A direct-QUIC link uses real QUIC datagrams.
//! A relay/DataChannel link carries IP packets on a reserved sid
//! (`net::L3_DATAGRAM_SID`), which is reliable and ordered where IP wants
//! neither, so it head-of-line blocks and shares the channel with file transfer.
//! It is still far better than the alternative it replaces, which was no route at
//! all for a pair that cannot go direct. The transport ladder always prefers
//! direct. The SENDER only installs a relayed route when the peer advertised
//! `dg_relay` in its announce: an older peer discards the reserved sid silently,
//! and a route that black-holes is worse than no route.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

use crate::net::Transport;
use crate::overlay::{Announce, Identity};
use crate::tun::{KernelTun, NetstackListener, NetstackStream, NetstackTun, TunDevice};

/// How the overlay's packet endpoint is provided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum L3Mode {
    /// Kernel TUN when it can be created, else the userspace netstack. The default.
    Auto,
    /// Force the kernel TUN; fail if it can't be created.
    Kernel,
    /// Force the userspace smoltcp netstack (zero privilege; containers/CI/no-sudo).
    Userspace,
}

/// A mode-agnostic accepted overlay connection: a kernel `TcpStream` (bound on the
/// overlay IP) or a userspace smoltcp stream. Implements the same async byte-stream
/// traits either way, so `expose`'s splice code is identical in both modes.
pub enum OverlayStream {
    Kernel(tokio::net::TcpStream),
    Netstack(NetstackStream),
}

impl tokio::io::AsyncRead for OverlayStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OverlayStream::Kernel(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            OverlayStream::Netstack(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for OverlayStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            OverlayStream::Kernel(s) => std::pin::Pin::new(s).poll_write(cx, b),
            OverlayStream::Netstack(s) => std::pin::Pin::new(s).poll_write(cx, b),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OverlayStream::Kernel(s) => std::pin::Pin::new(s).poll_flush(cx),
            OverlayStream::Netstack(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OverlayStream::Kernel(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OverlayStream::Netstack(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// A mode-agnostic overlay listener. `accept` yields the next connection and the
/// peer's overlay SOURCE address (the expose allowlist matches on it).
pub enum OverlayListener {
    Kernel(tokio::net::TcpListener),
    Netstack(NetstackListener),
}

impl OverlayListener {
    pub async fn accept(&self) -> Result<(OverlayStream, IpAddr)> {
        match self {
            OverlayListener::Kernel(l) => {
                let (s, src) = l.accept().await?;
                Ok((OverlayStream::Kernel(s), src.ip()))
            }
            OverlayListener::Netstack(nl) => {
                let (s, src) = nl.accept().await?;
                Ok((OverlayStream::Netstack(s), src.as_ipv6().into()))
            }
        }
    }
}

/// The TUN interface name the daemon creates for the overlay.
const IFNAME: &str = "filament0";

/// The overlay interface name, for callers that must name it to the kernel
/// (the subnet-router forwarding rules).
/// The prefixes this machine offers to carry, as configured.
///
/// One reader for every announce path, so a route cannot be forwarded by the
/// kernel but omitted from the wire (or the reverse) because two call sites
/// parsed the same setting differently.
pub fn advertised_prefixes() -> Vec<String> {
    crate::settings::get_str("advertise-routes", None)
        .unwrap_or_default()
        .split(',')
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect()
}

pub fn ifname() -> &'static str {
    IFNAME
}

pub struct L3 {
    tun: Arc<dyn TunDevice>,
    /// overlay dest IP -> the transport that peer's packets ride. Read on the TUN hot
    /// path, written as links come and go. A dual-stack peer has TWO entries here (its
    /// v6 ULA and its v4 address) both pointing at the same transport. The hot path
    /// takes the lock only to clone one Arc.
    routes: Arc<Mutex<RouteTable>>,
    /// pid -> that link's datagram->TUN pump. ONE reader per link (a peer's datagrams
    /// carry both families; the pump just forwards each to the TUN, which demuxes by
    /// dest), aborted when the link is replaced/removed so it is never leaked (fix #2).
    readers: Mutex<HashMap<String, AbortHandle>>,
    /// pid -> every overlay IP that link installed (v6 always; v4 in dual-stack), so a
    /// link drop or re-key (keyed by pid in main.rs) can retract exactly those routes.
    by_pid: Mutex<HashMap<String, Vec<IpAddr>>>,
    /// This node's overlay identity (crypto mode) for signing announces; `None` in
    /// manual/PSK addressing mode (no announce, routes added out of band).
    identity: Option<Identity>,
    /// Subnet prefixes THIS node has installed into the kernel routing table, so
    /// reconciliation can withdraw one that is no longer advertised. Tracked
    /// rather than re-read from the kernel so filament only ever deletes routes
    /// it created, and never a route the operator put there.
    kernel_subnets: Mutex<std::collections::HashSet<String>>,
    /// Whether the policy-routing exit route is currently in force, so it is
    /// installed once and withdrawn exactly once.
    exit_route_installed: Mutex<bool>,
    /// Highest announce sequence ACCEPTED from each peer identity, so a stale
    /// announce cannot roll an address back. Keyed by the announcing PUBKEY,
    /// not by pid: pid is a session artefact, and the signature binds the key.
    ///
    /// Populated only AFTER `Announce::verify` succeeds, so an unauthenticated
    /// message can never poison the map.
    seen_seq: Mutex<HashMap<[u8; 32], u64>>,
    /// MagicDNS: pid -> (petname, v6 overlay addr, optional v4 overlay addr) for
    /// VERIFIED peers, mirrored into a managed block in /etc/hosts so native tools
    /// resolve `<petname>` / `<petname>.mesh` (both AAAA and A records).
    names: Mutex<HashMap<String, (String, Ipv6Addr, Option<Ipv4Addr>)>>,
    /// `Some` when the endpoint is the userspace netstack (no kernel TUN). Held as
    /// the concrete type so `bind`/`dial` can open smoltcp sockets; its presence also
    /// means there is no kernel route to the overlay, so we do NOT write /etc/hosts
    /// (names would resolve but not route) and `add_route` is a no-op.
    netstack: Option<Arc<NetstackTun>>,
}

impl L3 {
    /// Start the overlay. In CRYPTO mode (`identity` set) the endpoint takes this
    /// node's derived `<addr>/128` and the whole overlay prefix routes to it; in
    /// manual mode `cidr` is used verbatim (PSK/lab). `mode` picks the packet
    /// endpoint: Kernel needs CAP_NET_ADMIN; Userspace needs none; Auto tries the
    /// kernel TUN and silently falls back to the userspace netstack if it can't be
    /// created (no cap, no /dev/net/tun, container without `ip`, locked netns).
    /// `FILAMENT_L3_USERSPACE=1` forces Userspace regardless of `mode`.
    pub fn start(cidr: &str, mtu: u32, identity: Option<Identity>, mode: L3Mode) -> Result<Arc<L3>> {
        cidr.split('/')
            .next()
            .and_then(|a| a.parse::<IpAddr>().ok())
            .ok_or_else(|| anyhow!("bad overlay address '{cidr}', want IP/PREFIX"))?;
        let mode = if std::env::var("FILAMENT_L3_USERSPACE").as_deref() == Ok("1") {
            L3Mode::Userspace
        } else {
            mode
        };
        let crypto = identity.is_some();
        // This node's v4 overlay address (crypto mode), derived from its identity key.
        // Passed to the kernel path so the TUN also carries our v4 address + route.
        let my_v4 = identity.as_ref().map(|id| id.addr_v4());
        // Keep the concrete NetstackTun (for bind/dial) AND the dyn handle (for the
        // datagram pumps) when userspace; `None` netstack == kernel TUN.
        let v4_cidr = my_v4.map(|v4| format!("{v4}/32"));
        let open_netstack = || -> Result<(Arc<dyn TunDevice>, Option<Arc<NetstackTun>>)> {
            let ns = Arc::new(NetstackTun::open_dual(
                IFNAME,
                cidr,
                v4_cidr.as_deref(),
                mtu,
            )?);
            Ok((ns.clone() as Arc<dyn TunDevice>, Some(ns)))
        };
        let (tun, netstack): (Arc<dyn TunDevice>, Option<Arc<NetstackTun>>) = match mode {
            L3Mode::Userspace => open_netstack()?,
            L3Mode::Kernel => (open_kernel(cidr, mtu, crypto, my_v4)?, None),
            L3Mode::Auto => match open_kernel(cidr, mtu, crypto, my_v4) {
                Ok(t) => (t, None),
                Err(e) => {
                    crate::ui::say(&format!(
                        "  {} no kernel TUN ({e}); using the userspace overlay (zero privilege)",
                        crate::ui::paint(crate::ui::Tone::Brand, "●")
                    ));
                    open_netstack()?
                }
            },
        };
        let userspace = netstack.is_some();
        let routes: Arc<Mutex<RouteTable>> = Arc::new(Mutex::new(RouteTable::default()));
        let l3 = Arc::new(L3 {
            tun: tun.clone(),
            routes: routes.clone(),
            readers: Mutex::new(HashMap::new()),
            by_pid: Mutex::new(HashMap::new()),
            identity,
            kernel_subnets: Mutex::new(std::collections::HashSet::new()),
            exit_route_installed: Mutex::new(false),
            seen_seq: Mutex::new(HashMap::new()),
            names: Mutex::new(HashMap::new()),
            netstack,
        });
        // Clear any stale MagicDNS block from a previous run - but only in kernel
        // mode; the userspace path never writes /etc/hosts (see `userspace`).
        if !userspace {
            let _ = rewrite_hosts_block(&[]);
        }

        // TUN -> datagram: one reader for the whole node. Each packet's dest IP
        // selects the peer link (cryptokey-routing style). A miss (no route) or a
        // send error is a silent drop, correct for a lossy datagram plane.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(_) => break, // TUN closed -> daemon shutting down
                };
                let Some(dst) = dest_ip(&buf[..n]) else { continue };
                let peer = routes.lock().await.lookup(dst);
                if let Some(t) = peer {
                    let _ = t.send_datagram(&buf[..n]);
                }
            }
        });
        Ok(l3)
    }

    /// This node's overlay address (crypto mode only).
    pub fn my_addr(&self) -> Option<Ipv6Addr> {
        self.identity.as_ref().map(|i| i.addr())
    }

    /// This node's dual-stack IPv4 overlay address (crypto mode only), key-derived
    /// in the reserved 198.18.0.0/15 range.
    pub fn my_addr_v4(&self) -> Option<std::net::Ipv4Addr> {
        self.identity.as_ref().map(|i| i.addr_v4())
    }

    /// True when running on the userspace netstack (no kernel TUN / no privilege).
    /// Callers use this to warn that host firewalling is bypassed and that native
    /// tools need the proxy/dial to reach `<peer>.mesh`.
    pub fn is_userspace(&self) -> bool {
        self.netstack.is_some()
    }

    /// Access the overlay identity (crypto mode only).
    pub fn identity_ref(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Insert a name entry into the MagicDNS table (for self-registration).
    pub async fn names_insert(&self, pid: &str, name: &str, v6: Ipv6Addr, v4: Option<Ipv4Addr>) {
        self.names.lock().await.insert(pid.to_string(), (name.to_string(), v6, v4));
    }

    /// Re-label an existing peer without touching its routes.
    ///
    /// A fleet peer can announce its overlay address BEFORE `fleet-hello` has
    /// established what it is called, and the route must be installed at announce
    /// time (that is what makes the mesh instant). The name is therefore whatever
    /// the link was showing then, which for an unverified fleet link is a
    /// placeholder. Once the certificate names the device, the MagicDNS entry has
    /// to catch up, or the peer is reachable as a nonsense hostname.
    /// Returns true when an entry was actually re-labelled.
    pub async fn rename_peer(&self, pid: &str, name: &str) -> bool {
        let mut names = self.names.lock().await;
        match names.get(pid) {
            Some((current, v6, v4)) if current != name => {
                let (v6, v4) = (*v6, *v4);
                names.insert(pid.to_string(), (name.to_string(), v6, v4));
                true
            }
            _ => false,
        }
    }

    /// Dial `dst:port` over the overlay, in BOTH modes: a kernel `TcpStream`
    /// (routed via filament0) or an in-process smoltcp connection. This is what lets
    /// a node reach a peer's OVERLAY-exposed service (an `expose` bound on the
    /// overlay IP, which an L2 loopback open cannot reach) - and the ONLY way a
    /// userspace node (no kernel route) reaches `<peer>.mesh:port` at all.
    pub async fn dial(&self, dst: Ipv6Addr, port: u16) -> Result<OverlayStream> {
        match &self.netstack {
            Some(ns) => Ok(OverlayStream::Netstack(ns.dial(dst, port).await?)),
            None => {
                let s = tokio::net::TcpStream::connect(std::net::SocketAddr::new(IpAddr::V6(dst), port)).await?;
                Ok(OverlayStream::Kernel(s))
            }
        }
    }

    /// Listen on `port` on this node's overlay address, returning an endpoint that
    /// works in BOTH modes: a kernel `TcpListener` bound to the overlay IP, or a
    /// userspace smoltcp listener. `expose` rides this so it is TUN-free.
    pub async fn bind(&self, port: u16) -> Result<OverlayListener> {
        match &self.netstack {
            Some(ns) => Ok(OverlayListener::Netstack(ns.listen(port).await?)),
            None => {
                let addr = self.my_addr().ok_or_else(|| anyhow!("L3 overlay address not set"))?;
                let l = tokio::net::TcpListener::bind(std::net::SocketAddr::new(IpAddr::V6(addr), port)).await?;
                Ok(OverlayListener::Kernel(l))
            }
        }
    }

    /// True if `addr` is a currently-routed (verified) peer on the overlay. Any
    /// datagram on filament0 already came from a paired peer, so this is the
    /// membership check the expose allowlist builds on.
    pub async fn is_verified_peer(&self, addr: IpAddr) -> bool {
        self.routes.lock().await.contains_host(&addr)
    }

    /// Reverse MagicDNS: the petname of a verified peer by overlay address, so an
    /// `expose --peer` allowlist can match an incoming connection's source.
    pub async fn petname_of(&self, addr: IpAddr) -> Option<String> {
        self.names.lock().await.values().find(|(_n, v6, v4)| {
            matches!(addr, IpAddr::V6(a) if a == *v6)
                || matches!(addr, IpAddr::V4(a) if v4.map_or(false, |v| a == v))
        }).map(|(n, _, _)| n.clone())
    }

    /// Resolve a verified peer's petname to its overlay address (the inverse of
    /// `petname_of`). The daemon uses this so a `dial` targets an address DERIVED
    /// from a paired identity, never one the client asserts.
    pub async fn addr_of(&self, name: &str) -> Option<Ipv6Addr> {
        let name = sanitize_host(name);
        self.names.lock().await.values().find(|(n, _, _)| *n == name).map(|(_, a, _)| *a)
    }

    /// Resolve a verified peer's petname to its v4 overlay address (if dual-stack).
    pub async fn addr_v4_of(&self, name: &str) -> Option<Ipv4Addr> {
        let name = sanitize_host(name);
        self.names.lock().await.values().find(|(n, _, _)| *n == name).and_then(|(_, _, a)| *a)
    }

    /// Build a signed announce of our address bound to link channel-binding `cb`.
    /// `None` in manual mode (no identity to sign with).
    pub fn make_announce(&self, cb: &[u8]) -> Option<Announce> {
        let id = self.identity.as_ref()?;
        // PERSISTED, not an in-process counter. See overlay::next_announce_seq
        // for why: a counter that restarts at zero gets a restarted peer
        // rejected forever by the very check below.
        let seq = crate::overlay::next_announce_seq();
        // CARRY THE ADVERTISED PREFIXES. This used to call `announce`, which
        // hardcodes `routes: Vec::new()`, so a router configured with
        // advertise-routes set up its own forwarding, printed "carrying
        // 10.66.0.0/24 for peers", and then told no one. The receiving half was
        // complete and correct the whole time: it called verify_routes, found an
        // empty set, and installed nothing. Nothing logged an error at either
        // end, because neither end was wrong on its own.
        let routes = advertised_prefixes();
        if routes.is_empty() {
            Some(id.announce(seq, cb))
        } else {
            Some(id.announce_with_routes(seq, cb, routes))
        }
    }

    /// Accept an announce's sequence number, or reject it as stale.
    ///
    /// MUST be called only AFTER `Announce::verify` has passed. Verify proves
    /// address-is-key, channel binding and possession; none of those stop a
    /// GENUINE announce being captured and replayed onto the SAME channel
    /// later, because the binding still matches. This is what stops that.
    ///
    /// The attack it closes: peer P announces address X (seq 3), then moves and
    /// announces Y (seq 5), and `add_peer` retires X and installs Y. An
    /// adversary on the channel replays the captured seq-3 announce; signature
    /// verifies, binding matches, and `add_peer` retires Y and reinstalls X.
    /// That is an address ROLLBACK, and it lands precisely because add_peer is
    /// idempotent for identical content and DESTRUCTIVE for stale content. The
    /// sequence is the only field that distinguishes the two.
    ///
    /// Strictly increasing, not contiguous: the persisted counter may skip
    /// numbers after a crash and that is fine.
    pub async fn accept_seq(&self, pubkey: &[u8; 32], seq: u64) -> bool {
        let mut seen = self.seen_seq.lock().await;
        if !crate::overlay::seq_is_fresh(seen.get(pubkey).copied(), seq) {
            return false;
        }
        seen.insert(*pubkey, seq);
        true
    }

    /// Attach a VERIFIED peer to the overlay: route its overlay addresses (already
    /// checked to match the announcing key + link, see main.rs) to `t`, keyed by
    /// `pid` so a link drop can retract them, and register `petname` for MagicDNS.
    /// `peer_ip` is the v6 ULA (always); `peer_ip_v4` is the peer's v4 address in
    /// dual-stack mode (both derive from the same verified key). Both families point
    /// at ONE transport with ONE datagram pump. Aborts any prior pump for this pid,
    /// so a repair/supersede never leaks the old reader or its connection (fix #2).
    /// Skips links that can't carry datagrams.
    pub async fn add_peer(
        &self,
        pid: &str,
        petname: &str,
        peer_ip: IpAddr,
        peer_ip_v4: Option<IpAddr>,
        t: Arc<dyn Transport>,
    ) {
        if !t.supports_datagrams() {
            return;
        }
        // Every overlay address this peer answers to (v6 always; v4 in dual-stack).
        let mut ips = vec![peer_ip];
        if let Some(v4) = peer_ip_v4 {
            if !ips.contains(&v4) {
                ips.push(v4);
            }
        }
        // Retire any address a prior incarnation of this pid installed that is no
        // longer ours to serve (its overlay IP may have changed across a re-key).
        if let Some(old) = self.by_pid.lock().await.insert(pid.to_string(), ips.clone()) {
            for ip in old {
                if !ips.contains(&ip) {
                    self.retract_route(ip).await;
                }
            }
        }
        // MagicDNS: record <petname> -> v6 addr (+ v4 if dual-stack) and refresh /etc/hosts.
        if let IpAddr::V6(v6) = peer_ip {
            let v4 = peer_ip_v4.and_then(|ip| match ip {
                IpAddr::V4(a) => Some(a),
                _ => None,
            });
            self.names.lock().await.insert(pid.to_string(), (sanitize_host(petname), v6, v4));
            self.refresh_hosts().await;
        }
        // ONE datagram->TUN pump per link (a peer's datagrams carry both families;
        // the pump just forwards each packet to the TUN, which demuxes by dest).
        let tun = self.tun.clone();
        let t_reader = t.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = t_reader.recv_datagram() => match r {
                        Ok(pkt) => { let _ = tun.send(&pkt).await; }
                        Err(_) => break, // link closed
                    },
                    // Wake periodically so a zombie link (alive at QUIC but dead
                    // for datagrams) is noticed even if read_datagram never errors.
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        if !t_reader.is_alive() { break; }
                    }
                }
            }
            // CONTINUITY: on transport death we do NOT retract the routes. The
            // overlay IPs stay in the table pointing at the (now dead) transport,
            // so datagrams merely drop (the inner TCP pauses, like WireGuard) until
            // the peer's repair calls add_peer, which atomically SWAPS in the fresh
            // transport (aborting this finished pump). Retracting here would open a
            // routability gap that can reset a live session across a link repair.
        });
        if let Some(old) = self.readers.lock().await.insert(pid.to_string(), handle.abort_handle()) {
            old.abort(); // stop the superseded pump now
        }
        // Install/replace every route for this peer, all pointing at the fresh transport.
        let mut map = self.routes.lock().await;
        for ip in &ips {
            map.insert_host(*ip, t.clone());
        }
    }

    /// Install the subnet routes a peer is authorized to carry, replacing any it
    /// previously had.
    ///
    /// A RESTATEMENT, matching how the advertisement itself works: whatever the
    /// peer no longer advertises (or is no longer granted) stops being routed.
    /// The alternative, adding without removing, is how a revoked route outlives
    /// its revocation.
    /// Every subnet prefix currently carried, across all peers.
    ///
    /// The kernel table is reconciled against this UNION rather than against one
    /// peer's list, because two peers may advertise overlapping prefixes and a
    /// withdrawal by one must not delete a route the other still provides.
    pub async fn subnet_prefixes(&self) -> Vec<(IpAddr, u8)> {
        self.routes.lock().await.subnets.iter().map(|(n, l, _)| (*n, *l)).collect()
    }

    /// The underlay address of every transport currently carrying a DEFAULT
    /// route, and whether any of them could not report one.
    ///
    /// `Transport::remote_addr` is `None` on a relay link, whose path is an ICE
    /// candidate pair rather than a single UDP 5-tuple. Without an address there
    /// is no carve-out, and without a carve-out the tunnel routes through
    /// itself, so the caller must refuse rather than guess. The bool is that
    /// signal, kept separate from an empty list because "no default routes" and
    /// "a default route we cannot make safe" are opposite situations.
    async fn default_route_underlay(&self) -> (Vec<IpAddr>, bool) {
        let mut addrs = Vec::new();
        let mut unknown = false;
        for (net, len, t) in self.routes.lock().await.subnets.iter() {
            if !crate::exit_route::is_default_route(*net, *len) {
                continue;
            }
            match t.remote_addr() {
                Some(sa) => addrs.push(sa.ip()),
                None => unknown = true,
            }
        }
        (addrs, unknown)
    }

    pub async fn set_peer_subnets(
        &self,
        pid: &str,
        t: &Arc<dyn Transport>,
        cidrs: &[String],
    ) {
        let mut prefixes: Vec<(IpAddr, u8)> = Vec::new();
        for c in cidrs {
            // Parsed here rather than trusted: these strings crossed the wire.
            // A malformed one is dropped, not defaulted, because there is no
            // safe default for "which network is this".
            let Some((net, len)) = c.split_once('/') else { continue };
            let (Ok(net), Ok(len)) = (net.trim().parse::<IpAddr>(), len.trim().parse::<u8>())
            else {
                continue;
            };
            let max = if net.is_ipv4() { 32 } else { 128 };
            if len > max {
                continue;
            }
            prefixes.push((net, len));
        }
        {
            let mut map = self.routes.lock().await;
            map.set_subnets(t, &prefixes);
        }
        let _ = pid; // routes are keyed by transport; pid retracts via remove_by_pid
        self.sync_kernel_subnets().await;
    }

    /// Of the advertised default routes, those whose transport is still alive.
    ///
    /// A default route pointing into a dead tunnel is indistinguishable from
    /// having lost the internet, so a peer that has gone away must stop being an
    /// exit node immediately rather than at the next announce, which by
    /// definition never arrives from a peer that is gone.
    async fn live_default_routes(&self, defaults: &[(IpAddr, u8)]) -> Vec<(IpAddr, u8)> {
        if defaults.is_empty() {
            return Vec::new();
        }
        let table = self.routes.lock().await;
        defaults
            .iter()
            .filter(|(n, l)| {
                table
                    .subnets
                    .iter()
                    .any(|(sn, sl, t)| sn == n && sl == l && t.is_alive())
            })
            .copied()
            .collect()
    }

    /// Every peer on the overlay, with the transport its packets currently ride.
    ///
    /// Returned as a snapshot so a caller can decide about each peer without
    /// holding the route-table lock across an await.
    pub async fn peers_with_transport(&self) -> Vec<(String, IpAddr, Arc<dyn Transport>)> {
        let names = self.names.lock().await.clone();
        let by_pid = self.by_pid.lock().await.clone();
        let table = self.routes.lock().await;
        let mut out = Vec::new();
        for (pid, ips) in by_pid {
            // The v6 ULA is the peer's canonical overlay address; the v4 alias
            // points at the same transport, so one entry per peer is right.
            let Some(v6) = ips.iter().find(|i| i.is_ipv6()).copied() else { continue };
            if let Some(t) = table.hosts.get(&v6) {
                let name = names.get(&pid).map(|(n, _, _)| n.clone()).unwrap_or_else(|| pid.clone());
                out.push((name, v6, t.clone()));
            }
        }
        out
    }

    /// Re-evaluate the routes this node has installed.
    ///
    /// Called on a timer as well as on an inbound announce, because the event
    /// that most needs handling is a peer going SILENT, and a silent peer sends
    /// no announce to trigger anything.
    pub async fn reconcile_routes(&self) {
        self.sync_kernel_subnets().await;
    }

    /// Install or withdraw an accepted DEFAULT route, using policy routing so it
    /// cannot capture the traffic that carries it. See `exit_route`.
    async fn sync_exit_route(&self, defaults: &[(IpAddr, u8)]) {
        if !crate::platform::policy_route::supported() {
            if !defaults.is_empty() {
                crate::ui::say(&format!(
                    "  {} ignoring an exit route: policy routing is implemented for Linux only",
                    crate::ui::paint(crate::ui::Tone::Warn, crate::ui::glyph_warn())
                ));
            }
            return;
        }
        {
            let mut installed = self.exit_route_installed.lock().await;
            if defaults.is_empty() {
                if *installed {
                    if let Err(e) = crate::platform::policy_route::run_plan(&crate::exit_route::teardown_plan())
                    {
                        crate::ui::debug(&format!("  could not withdraw the exit route: {e}"));
                    }
                    *installed = false;
                    crate::ui::say("  exit route withdrawn; traffic uses the ordinary path again");
                }
                return;
            }
            if *installed {
                return; // already in force; nothing changed
            }
            let (mut underlay, unknown) = self.default_route_underlay().await;
            if unknown {
                // A relay link cannot name its own endpoint, so there is no
                // carve-out to make and installing anyway would route the tunnel
                // through itself. Refuse loudly rather than disconnect.
                crate::ui::say(&format!(
                    "  {} not accepting an exit route over a relay link: its underlay address is unknown, so it cannot be excluded from the route it offers",
                    crate::ui::paint(crate::ui::Tone::Warn, crate::ui::glyph_warn())
                ));
                return;
            }
            // The signaling server, or the node cannot renegotiate, cannot be
            // told to stop, and cannot recover on its own.
            underlay.extend(crate::exit_route::signaling_addrs());
            if underlay.is_empty() {
                crate::ui::say(&format!(
                    "  {} not accepting an exit route: no underlay address to exclude",
                    crate::ui::paint(crate::ui::Tone::Warn, crate::ui::glyph_warn())
                ));
                return;
            }
            let gw = crate::platform::policy_route::default_gateway();
            let plan = crate::exit_route::install_plan(ifname(), gw.as_deref(), &underlay);
            match crate::platform::policy_route::run_plan(&plan) {
                Ok(()) => {
                    *installed = true;
                    crate::ui::say(&format!(
                        "  {} exit route active: all traffic via the mesh, except {} excluded address(es)",
                        crate::ui::paint(crate::ui::Tone::Ok, crate::ui::glyph_ok()),
                        underlay.len()
                    ));
                }
                Err(e) => {
                    // Do not leave a half-applied policy in place.
                    let _ = crate::platform::policy_route::run_plan(&crate::exit_route::teardown_plan());
                    crate::ui::say(&format!(
                        "  {} could not install the exit route ({e}); reverted",
                        crate::ui::paint(crate::ui::Tone::Warn, crate::ui::glyph_warn())
                    ));
                }
            }
        }
    }

    /// Make the KERNEL routing table match the prefixes we accepted.
    ///
    /// Without this the whole path is invisible to the operating system: the
    /// advertisement verifies, authorization passes, the prefix lands in the
    /// in-process table, `filament` prints "routes via <peer>", and `ip route`
    /// still shows nothing, so the kernel never hands those packets to the TUN
    /// and every ping fails. The in-process table decides which TRANSPORT a
    /// packet rides once it reaches us; it cannot make the kernel deliver the
    /// packet in the first place. A peer's overlay address needs no such route
    /// because it falls inside the TUN's own prefix. A foreign LAN prefix does
    /// not, which is exactly what a subnet route is.
    ///
    /// Reconciles rather than appends, so a withdrawn prefix is removed.
    async fn sync_kernel_subnets(&self) {
        // Kernel-TUN mode only: in userspace mode there is no OS device to route
        // at, and the route command would fail on every announcement.
        //
        // Asked of the endpoint, not of the filesystem. This was a
        // /sys/class/net/<if> existence check, which is Linux-only: on macOS the
        // path never exists, so the guard would have returned early forever and
        // silently disabled subnet-route RECEPTION on that platform, with no
        // error anywhere. `netstack` is Some exactly when we fell back to
        // userspace, which is the question actually being asked.
        if self.netstack.is_some() {
            return;
        }
        // A DEFAULT ROUTE IS NOT A SUBNET ROUTE. `10.66.0.0/24 dev filament0` is
        // additive; `0.0.0.0/0 dev filament0` captures every packet this machine
        // sends, including the ones carrying the overlay. Installed into the main
        // table it routes the tunnel through the tunnel: the link dies, the route
        // is withdrawn, the link returns, and the machine oscillates, having
        // usually lost the path to the signaling server first, so it cannot even
        // be told to stop.
        //
        // Accepting one safely needs the policy-routing plan in `exit_route`
        // (separate table, rule, and carve-outs for the peer's own endpoint and
        // the signaling server). The carve-out for the PEER needs its underlay
        // address, and `net::Transport` does not expose one, so this refuses
        // loudly instead of installing something that disconnects the machine.
        // Advertising a default route already works; it is accepting one that
        // waits on that accessor.
        let (defaults, subnets): (Vec<_>, Vec<_>) = self
            .subnet_prefixes()
            .await
            .into_iter()
            .partition(|(n, l)| crate::exit_route::is_default_route(*n, *l));
        // LIVENESS APPLIES TO DEFAULT ROUTES ONLY, and the asymmetry is
        // deliberate. A stale subnet route is a nuisance: packets for one prefix
        // go nowhere until the link returns, and links drop and re-establish
        // constantly, so evicting on every transient drop would churn the
        // routing table for no gain. A stale DEFAULT route is a disconnected
        // machine, because it captures everything, so it must not outlive the
        // link that carries it even briefly.
        let live_defaults = self.live_default_routes(&defaults).await;
        self.sync_exit_route(&live_defaults).await;
        let desired: std::collections::HashSet<String> =
            subnets.into_iter().map(|(n, l)| format!("{n}/{l}")).collect();
        let mut installed = self.kernel_subnets.lock().await;
        for cidr in desired.difference(&installed).cloned().collect::<Vec<_>>() {
            match crate::tun::add_route(&cidr, ifname()) {
                Ok(()) => {
                    installed.insert(cidr);
                }
                Err(e) => crate::ui::debug(&format!("  could not install route {cidr}: {e}")),
            }
        }
        for cidr in installed.difference(&desired).cloned().collect::<Vec<_>>() {
            if let Err(e) = crate::tun::del_route(&cidr, ifname()) {
                crate::ui::debug(&format!("  could not withdraw route {cidr}: {e}"));
            }
            installed.remove(&cidr);
        }
    }

    /// Drop the route for a specific overlay IP. The datagram pump is keyed by pid,
    /// not by IP, so it is aborted separately (add_peer supersede / remove_by_pid).
    async fn retract_route(&self, ip: IpAddr) {
        self.routes.lock().await.remove_host(&ip);
    }

    /// Retract every route a link (by pid) installed and abort its pump. NOT called
    /// on a transient link drop (that would break continuity across a repair);
    /// reserved for an explicit device-forget path. Kept for that use.
    #[allow(dead_code)]
    pub async fn remove_by_pid(&self, pid: &str) {
        if let Some(ips) = self.by_pid.lock().await.remove(pid) {
            let mut map = self.routes.lock().await;
            for ip in ips {
                map.remove_host(&ip);
            }
        }
        if let Some(r) = self.readers.lock().await.remove(pid) {
            r.abort();
        }
        if self.names.lock().await.remove(pid).is_some() {
            self.refresh_hosts().await;
        }
    }

    /// Rewrite the managed /etc/hosts block from the current verified names so
    /// native tools resolve `<petname>` and `<petname>.mesh`. Best-effort: a
    /// non-root daemon (or read-only /etc/hosts) just skips it and the overlay
    /// still works by IP.
    /// Refresh the managed /etc/hosts block from the current verified names so
    /// native tools resolve `<petname>` and `<petname>.mesh`. Best-effort: a
    /// non-root daemon (or read-only /etc/hosts) just skips it and the overlay
    /// still works by IP.
    pub async fn refresh_hosts(&self) {
        // Userspace mode has no kernel route to the overlay, so a resolved
        // `<peer>.mesh` would point at an unroutable IP (worse than not resolving);
        // skip /etc/hosts entirely and let dial/proxy resolve names in-process.
        if self.netstack.is_some() {
            return;
        }
        let entries: Vec<(String, Ipv6Addr, Option<Ipv4Addr>)> = self
            .names
            .lock()
            .await
            .values()
            .map(|(n, v6, v4)| (n.clone(), *v6, *v4))
            .collect();
        if let Err(e) = rewrite_hosts_block(&entries) {
            crate::ui::debug(&format!("  MagicDNS: /etc/hosts not updated ({e}); overlay still works by IP"));
        }
    }
}

/// Open the KERNEL TUN end to end: create the device AND install the overlay-prefix
/// route (crypto mode). Both steps can fail in a container (no cap, no /dev/net/tun,
/// no `ip`, locked netns); doing them together lets `L3Mode::Auto` catch ANY failure
/// and fall back to the userspace netstack instead of dropping off the overlay.
#[cfg(l3)]
fn open_kernel(
    cidr: &str,
    mtu: u32,
    crypto: bool,
    addr_v4: Option<std::net::Ipv4Addr>,
) -> Result<Arc<dyn TunDevice>> {
    let tun: Arc<dyn TunDevice> = Arc::new(KernelTun::open(IFNAME, cidr, mtu)?);
    // Route by the device's ACTUAL name: Linux honors `filament0`, but macOS assigns
    // `utunN` (utun devices can't be renamed). Crypto mode scatters /128s across the
    // shared ULA prefix, so route the whole prefix to the TUN (userspace demuxes).
    if crypto {
        let name = tun.name().to_string();
        crate::tun::add_route(&crate::overlay::prefix_cidr(), &name)?;
        // Dual-stack v4 is ADDITIVE and BEST-EFFORT. The v6 ULA is the load-bearing,
        // self-certifying stack; a v4 quirk on any platform must never knock a working
        // overlay off the kernel path (that would force a needless userspace fallback).
        // So assign our v4 address + route the v4 prefix, logging on failure rather
        // than bailing. `add_addr` first so the /32 is local before the /15 is routed.
        if let Some(v4) = addr_v4 {
            if let Err(e) = crate::tun::add_addr(&format!("{v4}/32"), &name) {
                crate::ui::debug(&format!("  L3 v4 address not assigned ({e}); v6 overlay unaffected"));
            } else if let Err(e) = crate::tun::add_route(&crate::overlay::prefix_v4_cidr(), &name) {
                crate::ui::debug(&format!("  L3 v4 route not installed ({e}); v6 overlay unaffected"));
            }
        }
    }
    Ok(tun)
}

const HOSTS_BEGIN: &str = "# BEGIN filament-mesh (managed by filament; edits here are overwritten)";
const HOSTS_END: &str = "# END filament-mesh";

/// Get this machine's hostname for MagicDNS.
pub fn hostname() -> String {
    // #183.1: /etc/hostname is UNIX-only; Windows provides COMPUTERNAME.
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "cli".into())
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "cli".into())
    }
}

/// The OS hosts file for MagicDNS. Unix: /etc/hosts. Windows: the drivers\etc\hosts
/// under %SystemRoot% (default C:\Windows), which the resolver consults like /etc/hosts.
fn hosts_path() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        std::path::PathBuf::from(root).join("System32\\drivers\\etc\\hosts")
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/etc/hosts")
    }
}

/// Replace the filament-mesh managed block in /etc/hosts with `entries`
/// (`<addr> <name>.mesh` per peer, both AAAA and A records). Atomic via
/// temp-file + rename. An empty `entries` removes the block. Names are
/// display-only; routing is always by the cryptographically-verified address.
pub(crate) fn sanitize_host(name: &str) -> String {
    // If name contains @, extract just the hostname part (user@host → host)
    let base = name.split('@').last().unwrap_or(name);
    let s: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '-' })
        .collect();
    s.trim_matches('-').to_string()
}

fn rewrite_hosts_block(entries: &[(String, Ipv6Addr, Option<Ipv4Addr>)]) -> std::io::Result<()> {
    let path = hosts_path();
    let cur = std::fs::read_to_string(&path).unwrap_or_default();
    let out = render_hosts(&cur, entries);
    // Preferred: atomic sibling-temp + rename (crash-safe), which needs write on
    // the hosts DIRECTORY (root/Administrator). Fallback for a non-root daemon that
    // only has a per-file ACL on the hosts file: a single-shot in-place truncating
    // write, which needs write on the file alone. The in-place path writes the whole
    // buffer in one std::fs::write so the corruption window is one syscall.
    let tmp = path.with_extension("filament.tmp");
    match std::fs::write(&tmp, &out).and_then(|()| std::fs::rename(&tmp, &path)) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = std::fs::remove_file(&tmp);
            std::fs::write(&path, out)
        }
    }
}

/// Pure transform: strip any prior filament-mesh block from `current`, then append
/// a fresh one for `entries` (none => block removed). Non-filament lines are kept
/// verbatim, so we never clobber the user's /etc/hosts.
fn render_hosts(current: &str, entries: &[(String, Ipv6Addr, Option<Ipv4Addr>)]) -> String {
    let mut out = String::with_capacity(current.len() + 256);
    let mut in_block = false;
    for line in current.lines() {
        let t = line.trim_start();
        if t.starts_with("# BEGIN filament-mesh") {
            in_block = true;
            continue;
        }
        if in_block {
            if t.starts_with(HOSTS_END) {
                in_block = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    // Dedup exact (name, v6_addr) pairs: the names table is keyed per-link, so a
    // peer that reconnected under several link ids can appear more than once and
    // would otherwise emit duplicate /etc/hosts lines.
    let mut seen = std::collections::HashSet::new();
    let live: Vec<&(String, Ipv6Addr, Option<Ipv4Addr>)> = entries
        .iter()
        .filter(|(n, _, _)| is_safe_mesh_name(n))
        .filter(|(n, v6, _)| seen.insert((n.clone(), *v6)))
        .collect();
    if !live.is_empty() {
        out.push_str(HOSTS_BEGIN);
        out.push('\n');
        for (name, v6, v4) in live {
            // AAAA record: the v6 overlay address (always present).
            // ONLY the namespaced `<name>.mesh` is emitted, never a bare `<name>`:
            // a bare entry could shadow a real hostname (localhost, an internal
            // host, a public domain). Under the reserved `.mesh` suffix a peer
            // name can never collide with real resolution. (Security: DNS-hijack
            // hardening; the petname is the locally-assigned one, but this holds
            // even if a name is ever influenced by the peer.)
            out.push_str(&format!("{v6} {name}.mesh\n"));
            // A record: the v4 overlay address (dual-stack only). Same .mesh
            // suffix so both families resolve to the same name.
            if let Some(v4) = v4 {
                out.push_str(&format!("{v4} {name}.mesh\n"));
            }
        }
        out.push_str(HOSTS_END);
        out.push('\n');
    }
    out
}

/// Reject empty or reserved labels so a mesh name can never map to something
/// load-bearing even under `.mesh` (defense in depth beyond the `.mesh` suffix).
fn is_safe_mesh_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    !matches!(name.to_ascii_lowercase().as_str(), "localhost" | "localhost4" | "localhost6")
}

/// Standalone point-to-point serve_tun (no signaling): open `dev` with `tun_addr`
/// and pump IP packets both ways over an already-authenticated QUIC connection's
/// datagrams. Runs until the link or TUN closes. Backs `filament serve-tun` and
/// the lab's filament-l3 carrier (WireGuard-style known-endpoint overlay).
pub async fn run_point_to_point(
    conn: quinn::Connection,
    dev: &str,
    tun_addr: &str,
    mtu: u32,
) -> Result<()> {
    let tun: Arc<dyn TunDevice> = Arc::new(KernelTun::open(dev, tun_addr, mtu)?);
    // datagram -> TUN (background)
    let c = conn.clone();
    let t = tun.clone();
    let down = tokio::spawn(async move {
        while let Ok(pkt) = c.read_datagram().await {
            let _ = t.send(&pkt).await;
        }
    });
    // TUN -> datagram (this task). Select against conn.closed() so a peer that
    // drops while our TUN is idle ends the pump promptly, instead of parking in
    // tun.recv() forever (the process would otherwise hang holding filament0).
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = conn.closed() => break,
            r = tun.recv(&mut buf) => {
                let n = match r {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(e) => {
                        down.abort();
                        return Err(e);
                    }
                };
                // A too-big packet errors (over the datagram MTU) and is dropped;
                // a closed link ends the pump.
                if conn.send_datagram(bytes::Bytes::copy_from_slice(&buf[..n])).is_err()
                    && conn.close_reason().is_some()
                {
                    break;
                }
            }
        }
    }
    down.abort();
    Ok(())
}

/// Destination IP of a raw IP packet (v4 header dst at [16..20], v6 at [24..40]).
/// `None` for a truncated or non-IP frame.
/// Which advertised prefixes may actually be installed from one peer.
///
/// TWO GATES, both required, and they answer different questions:
///
/// - `accept_routes` is the RECEIVER's decision: "do I take routes from this
///   device at all". Off by default, per peer.
/// - `authorized` is the OWNER's decision, carried by a signed CAP_ROUTE grant
///   naming that exact prefix as its resource.
///
/// Requiring both is not belt-and-braces. The grant says the owner designated
/// this device to carry this prefix; accept-routes says this machine wants to
/// route through it. A device can be legitimately granted a prefix that a given
/// peer still has no business sending its traffic through, and a peer can want
/// routes from a device the owner never authorized. Neither implies the other.
///
/// A verified signature on the advertisement is a THIRD, prior condition handled
/// by the caller (`Announce::verify_routes`): it establishes who said it, which
/// is what makes asking these two questions meaningful at all.
pub(crate) fn installable_routes<F>(
    advertised: &[String],
    accept_routes: bool,
    authorized: F,
) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    if !accept_routes {
        // Cheap and total: no grant can override the receiver declining.
        return Vec::new();
    }
    advertised.iter().filter(|c| authorized(c)).cloned().collect()
}

/// Does `addr` fall inside the prefix `net/len`?
///
/// Pure, so the matching rule is testable without a Transport or a running L3.
/// Families never mix: a v4 destination cannot match a v6 prefix even when the
/// bits would line up, which is the bug you get from comparing octet slices
/// without checking the family first.
fn prefix_contains(net: IpAddr, len: u8, addr: IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            if len > 32 {
                return false;
            }
            if len == 0 {
                return true; // /0 is the default route, and shifting by 32 is UB
            }
            let mask = u32::MAX << (32 - len);
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            if len > 128 {
                return false;
            }
            if len == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - len);
            (u128::from(n) & mask) == (u128::from(a) & mask)
        }
        _ => false,
    }
}

/// Overlay routing table: exact host routes, plus advertised subnet prefixes.
///
/// SPLIT DELIBERATELY. Host routes keep their own `HashMap` and their exact-match
/// fast path completely unchanged, because that path works and carries every
/// transfer today. Prefixes are consulted ONLY on a host miss, so adding subnet
/// routing cannot alter how an existing peer-to-peer packet is routed.
///
/// Precedence is host-before-prefix, then longest prefix. A host route is just a
/// /32 or /128, so "most specific wins" is the single rule; keeping hosts separate
/// is a performance and blast-radius choice, not a semantic one.
#[derive(Default)]
pub(crate) struct RouteTable {
    hosts: HashMap<IpAddr, Arc<dyn Transport>>,
    /// (network, prefix_len, via). Small and read on every packet that misses the
    /// host map, so a linear longest-match scan is the right shape until a node
    /// carries enough prefixes for that to show up in a profile.
    subnets: Vec<(IpAddr, u8, Arc<dyn Transport>)>,
}

impl RouteTable {
    fn lookup(&self, dst: IpAddr) -> Option<Arc<dyn Transport>> {
        if let Some(t) = self.hosts.get(&dst) {
            return Some(t.clone());
        }
        self.subnets
            .iter()
            .filter(|(net, len, _)| prefix_contains(*net, *len, dst))
            .max_by_key(|(_, len, _)| *len)
            .map(|(_, _, t)| t.clone())
    }

    fn insert_host(&mut self, ip: IpAddr, t: Arc<dyn Transport>) {
        self.hosts.insert(ip, t);
    }

    fn remove_host(&mut self, ip: &IpAddr) {
        self.hosts.remove(ip);
    }

    fn contains_host(&self, ip: &IpAddr) -> bool {
        self.hosts.contains_key(ip)
    }

    /// Test-only, and marked so rather than `allow(dead_code)`: an unused method
    /// and a test-only method look identical to the compiler, and this tree has
    /// already been bitten by treating the first as the second.
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.subnets.is_empty()
    }

    /// Total installed routes, hosts plus prefixes. Total rather than hosts-only
    /// because the caller asking is checking for LEAKS, and a leaked prefix counts.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.hosts.len() + self.subnets.len()
    }

    /// Replace every prefix advertised via one peer. Advertisement is a full
    /// restatement, not a delta: a peer that stops advertising a prefix must have
    /// it withdrawn, and diffing deltas is how stale routes survive a retraction.
    fn set_subnets(&mut self, via: &Arc<dyn Transport>, prefixes: &[(IpAddr, u8)]) {
        self.subnets.retain(|(_, _, t)| !Arc::ptr_eq(t, via));
        for (net, len) in prefixes {
            self.subnets.push((*net, *len, via.clone()));
        }
    }
}

fn dest_ip(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::from([pkt[16], pkt[17], pkt[18], pkt[19]])),
        6 if pkt.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::from(a))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{dest_ip, prefix_contains, render_hosts, sanitize_host, RouteTable, Transport};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    #[test]
    fn magicdns_block_roundtrips_without_clobbering() {
        let base = "127.0.0.1 localhost\n::1 localhost\n";
        let a: Ipv6Addr = "fdf1:1af7:c30d:1a1::99aa".parse().unwrap();
        let with = render_hosts(base, &[("other-do".into(), a, None)]);
        // user lines preserved, managed block added with the NAMESPACED name only
        assert!(with.contains("127.0.0.1 localhost"));
        assert!(with.contains(&format!("{a} other-do.mesh")));
        // never a bare hostname (would shadow real names); never `localhost`
        assert!(!with.contains(&format!("{a} other-do.mesh other-do")));
        assert!(!with.lines().any(|l| l.trim() == format!("{a} other-do")));
        assert!(with.contains("# BEGIN filament-mesh"));
        // re-rendering replaces (not stacks) the block, and empty removes it
        let again = render_hosts(&with, &[("other-do".into(), a, None)]);
        assert_eq!(again.matches("# BEGIN filament-mesh").count(), 1);
        let cleared = render_hosts(&again, &[]);
        assert!(!cleared.contains("filament-mesh"));
        assert!(cleared.contains("127.0.0.1 localhost"));
    }

    #[test]
    fn hostnames_are_sanitized() {
        assert_eq!(sanitize_host("other-do"), "other-do");
        assert_eq!(sanitize_host("user@cli"), "cli");  // strips user@ prefix
        assert_eq!(sanitize_host("a b/c"), "a-b-c");
    }

    #[test]
    fn reserved_and_empty_names_are_dropped() {
        use super::is_safe_mesh_name;
        assert!(!is_safe_mesh_name(""));
        assert!(!is_safe_mesh_name("localhost"));
        assert!(!is_safe_mesh_name("LocalHost"));
        assert!(is_safe_mesh_name("other-do"));
        // a peer named "localhost" is skipped entirely (no localhost.mesh either)
        let a: Ipv6Addr = "fdf1:1af7:c30d:1a1::99aa".parse().unwrap();
        assert!(!render_hosts("", &[("localhost".into(), a, None)]).contains("filament-mesh"));
    }

    #[test]
    fn parses_ipv4_dest() {
        // minimal IPv4 header: version/IHL=0x45, dst=10.9.0.2 at bytes 16..20
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&[10, 9, 0, 2]);
        assert_eq!(dest_ip(&p), Some(IpAddr::from([10, 9, 0, 2])));
    }

    #[test]
    fn parses_ipv6_dest() {
        let mut p = [0u8; 40];
        p[0] = 0x60;
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        p[24..40].copy_from_slice(&dst);
        assert_eq!(dest_ip(&p), Some(IpAddr::from(dst)));
    }

    #[test]
    fn rejects_truncated_and_unknown() {
        assert_eq!(dest_ip(&[]), None);
        assert_eq!(dest_ip(&[0x45, 0, 0]), None); // too short for v4
        assert_eq!(dest_ip(&[0x70, 0, 0, 0]), None); // not v4/v6
    }

    // A transport that carries datagrams but never delivers one, so add_peer's pump
    // parks; we only inspect the route/reader bookkeeping it leaves behind.
    #[test]
    fn installing_a_route_needs_the_receiver_and_the_owner_to_agree() {
        let adv = vec!["10.0.0.0/24".to_string(), "192.168.1.0/24".to_string()];
        let granted = |c: &str| c == "10.0.0.0/24";

        // Both gates open: only the granted prefix installs. An advertisement
        // for something ungranted is simply not taken, not an error: a peer may
        // advertise to several receivers with different grants.
        assert_eq!(
            super::installable_routes(&adv, true, granted),
            vec!["10.0.0.0/24".to_string()]
        );

        // Receiver declines: nothing installs, however well granted. The owner's
        // grant does not oblige this machine to route through anyone.
        assert!(super::installable_routes(&adv, false, granted).is_empty());

        // Owner granted nothing: nothing installs, however willing the receiver.
        assert!(super::installable_routes(&adv, true, |_| false).is_empty());

        // Nothing advertised is trivially nothing installed, which is also the
        // shape an older peer and a failed route signature both produce.
        assert!(super::installable_routes(&[], true, |_| true).is_empty());
    }

    #[test]
    fn prefix_matching_is_family_aware_and_handles_the_edges() {
        let v4 = |s: &str| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
        let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());

        assert!(prefix_contains(v4("10.0.0.0"), 24, v4("10.0.0.5")));
        assert!(!prefix_contains(v4("10.0.0.0"), 24, v4("10.0.1.5")));
        assert!(prefix_contains(v4("10.0.0.0"), 8, v4("10.9.9.9")));

        // /0 is the default route. Also the shift that would be UB if written
        // as `<< (32 - 0)`, which is why it is special-cased rather than trusted.
        assert!(prefix_contains(v4("0.0.0.0"), 0, v4("8.8.8.8")));
        assert!(prefix_contains(v6("::"), 0, v6("fd00::1")));

        // A full-length prefix is an exact match.
        assert!(prefix_contains(v4("10.0.0.5"), 32, v4("10.0.0.5")));
        assert!(!prefix_contains(v4("10.0.0.5"), 32, v4("10.0.0.6")));

        // FAMILIES NEVER MIX, even where the bits would line up.
        assert!(!prefix_contains(v4("10.0.0.0"), 24, v6("::a00:5")));
        assert!(!prefix_contains(v6("::"), 0, v4("10.0.0.1")));

        // Nonsense lengths are refused rather than wrapping.
        assert!(!prefix_contains(v4("10.0.0.0"), 33, v4("10.0.0.1")));
        assert!(!prefix_contains(v6("fd00::"), 129, v6("fd00::1")));

        assert!(prefix_contains(v6("fd00::"), 16, v6("fd00::1")));
        assert!(!prefix_contains(v6("fd00::"), 16, v6("fd01::1")));
    }

    #[test]
    fn route_lookup_prefers_host_then_longest_prefix() {
        let v4 = |s: &str| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
        // Distinct Arcs so ptr_eq can tell them apart; the value is irrelevant.
        let a: Arc<dyn Transport> = Arc::new(DgramTransport);
        let b: Arc<dyn Transport> = Arc::new(DgramTransport);
        let c: Arc<dyn Transport> = Arc::new(DgramTransport);

        let mut rt = RouteTable::default();
        rt.set_subnets(&a, &[(v4("10.0.0.0"), 8)]);
        rt.set_subnets(&b, &[(v4("10.1.0.0"), 16)]);
        rt.insert_host(v4("10.1.0.7"), c.clone());

        // Most specific wins: host beats /16 beats /8.
        assert!(Arc::ptr_eq(&rt.lookup(v4("10.1.0.7")).unwrap(), &c), "host route wins");
        assert!(Arc::ptr_eq(&rt.lookup(v4("10.1.0.8")).unwrap(), &b), "longer prefix wins");
        assert!(Arc::ptr_eq(&rt.lookup(v4("10.9.9.9")).unwrap(), &a), "falls back to /8");
        assert!(rt.lookup(v4("192.168.1.1")).is_none(), "no route is None, not a default");

        // Advertisement is a RESTATEMENT: re-advertising without a prefix withdraws
        // it. Diffing deltas instead is how a retracted route survives.
        rt.set_subnets(&a, &[]);
        assert!(rt.lookup(v4("10.9.9.9")).is_none(), "withdrawn prefix must not linger");
        assert!(Arc::ptr_eq(&rt.lookup(v4("10.1.0.8")).unwrap(), &b), "other peers unaffected");

        // Host routes are untouched by subnet churn, which is the whole point of
        // keeping them in a separate map.
        assert!(Arc::ptr_eq(&rt.lookup(v4("10.1.0.7")).unwrap(), &c));
        rt.remove_host(&v4("10.1.0.7"));
        assert!(Arc::ptr_eq(&rt.lookup(v4("10.1.0.7")).unwrap(), &b), "now covered by the /16");
    }

    struct DgramTransport;
    #[async_trait::async_trait]
    impl super::Transport for DgramTransport {
        async fn send_control(&self, _m: &serde_json::Value) -> super::Result<()> {
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _p: &[u8]) -> super::Result<()> {
            Ok(())
        }
        async fn flush(&self) -> super::Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1200
        }
        fn supports_datagrams(&self) -> bool {
            true
        }
        fn is_alive(&self) -> bool {
            true
        }
        fn send_datagram(&self, _p: &[u8]) -> super::Result<()> {
            Ok(())
        }
        async fn recv_datagram(&self) -> super::Result<bytes::Bytes> {
            std::future::pending().await
        }
        fn is_dead(&self) -> bool {
            false
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    // Build an L3 backed by the userspace netstack (no privilege, and refresh_hosts
    // early-returns so the test never touches /etc/hosts). Routing bookkeeping is the
    // same in kernel and userspace mode - it is a RouteTable: exact host routes
    // plus advertised prefixes, consulted in that order.
    fn test_l3() -> std::sync::Arc<super::L3> {
        use super::*;
        let ns = std::sync::Arc::new(NetstackTun::open(IFNAME, "fdf1:1af7:c30d::1/128", 1280).unwrap());
        std::sync::Arc::new(L3 {
            tun: ns.clone() as std::sync::Arc<dyn TunDevice>,
            routes: std::sync::Arc::new(tokio::sync::Mutex::new(RouteTable::default())),
            readers: tokio::sync::Mutex::new(HashMap::new()),
            by_pid: tokio::sync::Mutex::new(HashMap::new()),
            identity: None,
            kernel_subnets: tokio::sync::Mutex::new(std::collections::HashSet::new()),
            exit_route_installed: tokio::sync::Mutex::new(false),
            seen_seq: Mutex::new(HashMap::new()),
            names: tokio::sync::Mutex::new(HashMap::new()),
            netstack: Some(ns),
        })
    }

    #[tokio::test]
    async fn dual_stack_add_peer_routes_both_families_and_retracts() {
        use super::Transport;
        let l3 = test_l3();
        let v6: IpAddr = "fdf1:1af7:c30d::1".parse().unwrap();
        let v4: IpAddr = "198.18.5.6".parse().unwrap();
        let t: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);

        // A verified dual-stack peer installs BOTH families, one pump for the link.
        l3.add_peer("pidA", "alice", v6, Some(v4), t.clone()).await;
        {
            let map = l3.routes.lock().await;
            assert!(map.contains_host(&v6), "v6 route installed");
            assert!(map.contains_host(&v4), "v4 route installed");
        }
        assert_eq!(l3.readers.lock().await.len(), 1, "exactly one pump per link");

        // Re-key: the same link now announces a different v6+v4; the old pair is
        // retracted and only the new pair remains, still one pump.
        let v6b: IpAddr = "fdf1:1af7:c30d::2".parse().unwrap();
        let v4b: IpAddr = "198.18.9.9".parse().unwrap();
        l3.add_peer("pidA", "alice", v6b, Some(v4b), t.clone()).await;
        {
            let map = l3.routes.lock().await;
            assert!(!map.contains_host(&v6) && !map.contains_host(&v4), "stale pair retracted on re-key");
            assert!(map.contains_host(&v6b) && map.contains_host(&v4b), "new pair installed");
            assert_eq!(map.len(), 2, "no leaked routes");
        }
        assert_eq!(l3.readers.lock().await.len(), 1, "still one pump after supersede");

        // Explicit forget drops every route and the pump for that link.
        l3.remove_by_pid("pidA").await;
        assert!(l3.routes.lock().await.is_empty(), "all routes gone");
        assert!(l3.readers.lock().await.is_empty(), "pump aborted");
    }

    #[test]
    fn magicdns_emits_both_a_and_aaaa_records() {
        let base = "127.0.0.1 localhost\n";
        let v6: Ipv6Addr = "fdf1:1af7:c30d:1a1::99aa".parse().unwrap();
        let v4: Ipv4Addr = "198.18.5.6".parse().unwrap();
        let out = render_hosts(base, &[("peer-one".into(), v6, Some(v4))]);
        // Both AAAA (v6) and A (v4) records present
        assert!(out.contains(&format!("{v6} peer-one.mesh")), "AAAA record present");
        assert!(out.contains(&format!("{v4} peer-one.mesh")), "A record present");
        // v6-only peer: no A record emitted
        let v6b: Ipv6Addr = "fdf1:1af7:c30d:2b2::bb".parse().unwrap();
        let out2 = render_hosts(base, &[("v6-only".into(), v6b, None)]);
        assert!(out2.contains(&format!("{v6b} v6-only.mesh")), "AAAA record present");
        assert!(!out2.contains("v6-only.mesh") || out2.lines().filter(|l| l.contains("v6-only.mesh")).count() == 1, "no duplicate A record for v6-only peer");
    }

    #[test]
    fn magicdns_dual_stack_add_peer_registers_v4_in_names() {
        use super::Transport;
        // Use a userspace-backed L3 so refresh_hosts is a no-op (avoids /etc/hosts)
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let l3 = test_l3();
            let v6: IpAddr = "fdf1:1af7:c30d::1".parse().unwrap();
            let v4: IpAddr = "198.18.5.6".parse().unwrap();
            let t: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            l3.add_peer("pidA", "alice", v6, Some(v4), t).await;
            // petname_of matches both v6 and v4
            assert_eq!(l3.petname_of(v6).await.as_deref(), Some("alice"));
            assert_eq!(l3.petname_of(v4).await.as_deref(), Some("alice"));
            // addr_of returns v6; addr_v4_of returns v4
            assert_eq!(l3.addr_of("alice").await, Some("fdf1:1af7:c30d::1".parse().unwrap()));
            assert_eq!(l3.addr_v4_of("alice").await, Some("198.18.5.6".parse().unwrap()));
            // v6-only peer: addr_v4_of returns None
            let v6b: IpAddr = "fdf1:1af7:c30d::2".parse().unwrap();
            let t2: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            l3.add_peer("pidB", "bob", v6b, None, t2).await;
            assert_eq!(l3.addr_v4_of("bob").await, None);
        });
    }

    #[test]
    fn magicdns_same_name_different_peers_both_emitted() {
        use super::Transport;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let l3 = test_l3();
            // Two peers with the same petname "host1" but different addresses
            let v6a: IpAddr = "fdf1:1af7:c30d::aa".parse().unwrap();
            let v4a: IpAddr = "198.18.1.1".parse().unwrap();
            let v6b: IpAddr = "fdf1:1af7:c30d::bb".parse().unwrap();
            let v4b: IpAddr = "198.18.2.2".parse().unwrap();
            let ta: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            let tb: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            // Both registered under same name, different pids
            l3.add_peer("pidA", "host1", v6a, Some(v4a), ta).await;
            l3.add_peer("pidB", "host1", v6b, Some(v4b), tb).await;
            // Both addresses are routable
            assert!(l3.is_verified_peer(v6a).await);
            assert!(l3.is_verified_peer(v6b).await);
            assert!(l3.is_verified_peer(v4a).await);
            assert!(l3.is_verified_peer(v4b).await);
            // petname_of returns one of them (which one is implementation-defined)
            let found = l3.petname_of(v6a).await;
            assert!(found.is_some(), "petname_of must return a result for known peer");
            // render_hosts emits both entries (DNS round-robin)
            let base = "";
            let entries: Vec<(String, std::net::Ipv6Addr, Option<std::net::Ipv4Addr>)> = vec![
                ("host1".into(), "fdf1:1af7:c30d::aa".parse().unwrap(), Some("198.18.1.1".parse().unwrap())),
                ("host1".into(), "fdf1:1af7:c30d::bb".parse().unwrap(), Some("198.18.2.2".parse().unwrap())),
            ];
            let out = render_hosts(base, &entries);
            // Both v6 addresses should appear as host1.mesh
            assert!(out.contains("fdf1:1af7:c30d::aa host1.mesh"));
            assert!(out.contains("fdf1:1af7:c30d::bb host1.mesh"));
            // Both v4 addresses should appear as host1.mesh
            assert!(out.contains("198.18.1.1 host1.mesh"));
            assert!(out.contains("198.18.2.2 host1.mesh"));
        });
    }

    #[test]
    fn magicdns_case_insensitive_collision() {
        // "Host1" and "host1" should collide after sanitization
        use super::Transport;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let l3 = test_l3();
            let v6a: IpAddr = "fdf1:1af7:c30d::aa".parse().unwrap();
            let v6b: IpAddr = "fdf1:1af7:c30d::bb".parse().unwrap();
            let ta: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            let tb: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            // Different case names
            l3.add_peer("pidA", "Host1", v6a, None, ta).await;
            l3.add_peer("pidB", "host1", v6b, None, tb).await;
            // Both are routable
            assert!(l3.is_verified_peer(v6a).await);
            assert!(l3.is_verified_peer(v6b).await);
            // render_hosts deduplicates by (sanitized_name, v6) - different v6 means both emitted
            let entries: Vec<(String, std::net::Ipv6Addr, Option<std::net::Ipv4Addr>)> = vec![
                ("host1".into(), "fdf1:1af7:c30d::aa".parse().unwrap(), None),
                ("host1".into(), "fdf1:1af7:c30d::bb".parse().unwrap(), None),
            ];
            let out = render_hosts("", &entries);
            assert!(out.contains("fdf1:1af7:c30d::aa host1.mesh"));
            assert!(out.contains("fdf1:1af7:c30d::bb host1.mesh"));
        });
    }

    #[tokio::test]
    async fn l3_start_with_ipv4() {
        use super::*;
        let identity = crate::overlay::load_identity().unwrap();
        let expected_v4 = identity.addr_v4();
        let cidr = format!("{}/128", identity.addr());
        let l3 = L3::start(&cidr, 1280, Some(identity), L3Mode::Userspace).unwrap();
        assert!(l3.is_userspace(), "should be userspace mode");
        assert_eq!(l3.my_addr_v4(), Some(expected_v4), "v4 address from identity");
        // The netstack should be dual-stack when v4 is available
        let ns = l3.netstack.as_ref().unwrap();
        assert!(ns.is_dual_stack(), "netstack should be dual-stack with v4 CIDR");
    }
}
