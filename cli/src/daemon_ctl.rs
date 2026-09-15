//! Daemon control-socket and warm-reuse subsystem, lifted out of `main.rs`.
//!
//! Two related jobs the long-lived `up` daemon does on its control socket:
//! mount bookkeeping (`DaemonMounts` plus the mount/unmount/list/health
//! handlers) and warm-link reuse (`warm_link_for` plus the warm
//! open/pty/resize/bootstrap handlers, which ride a link the daemon already
//! holds instead of paying for a cold establish).
//!
//! Every item here already takes its inputs explicitly (`conn: &Conn`,
//! `req: ctl::Req`, `&mut DaemonMounts`, `&mut PendingBootstraps`), so the move
//! is a relocation plus the visibility the crate root needs -- no context
//! struct, no closure capture, no ownership reshaping.
//!
//! cfg discipline: the `not(unix)`/`unix` halves of `handle_warm_req` and every
//! `#[cfg(unix)]` item moved together, attributes included.
use crate::Conn;
use crate::ctl;
use crate::l2;
use crate::mount;
use crate::net::{self, Ev};
use crate::ui;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub(crate) type WarmPtys = std::sync::Arc<std::sync::Mutex<HashMap<String, (String, u32)>>>;

pub(crate) struct DaemonMountEntry {
    local: String,
    pub(crate) peer: String,
    pub(crate) remote: String,
    pid: u32,
    read_only: bool,
    auto_restore: bool,
    created: String,
}

pub(crate) struct DaemonMounts {
    pub(crate) entries: HashMap<String, DaemonMountEntry>,
    pub(crate) children: HashMap<String, tokio::process::Child>,
}

/// Dispatch one warm-reuse control request to the right handler. Warm reuse is
/// unix-only (the control socket is a unix-domain socket); on non-unix `ctl::Req`
/// is uninhabited so this is never reached - it only keeps the event loop portable.
#[cfg(not(unix))]
pub(crate) async fn handle_warm_req(
    _conn: &Conn,
    _l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    _warm_ptys: &WarmPtys,
    _tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    match req {}
}

#[cfg(unix)]
pub(crate) async fn handle_warm_req(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    match &req.kind {
        ctl::ReqKind::Open { .. } => handle_warm_open(conn, l2_muxes, tx, req).await,
        // Dial is handled inline in the daemon loop (it needs the L3 manager);
        // answer defensively if it ever reaches here.
        ctl::ReqKind::Dial { .. } => req.reject("dial not handled here").await,
        ctl::ReqKind::Pty { .. } => handle_warm_pty(conn, l2_muxes, warm_ptys, tx, req).await,
        ctl::ReqKind::Resize { .. } => handle_warm_resize(l2_muxes, warm_ptys, req).await,
        ctl::ReqKind::Ping { .. } => handle_warm_ping(conn, req).await,
        // Bootstrap is dispatched before this (it defers its reply), so it never
        // reaches here; reject defensively so a future caller falls back to cold.
        ctl::ReqKind::Bootstrap { .. } => req.reject("bootstrap not handled here").await,
        // Reconfigure is handled inline in the daemon loop (it mutates loop state),
        // so it never reaches this dispatcher; answer defensively if it ever does.
        ctl::ReqKind::Reconfigure { .. } => req.reply(&json!({ "ok": true, "live": false })).await,
        // ReqKind::Arm is gone: the mint writes armed.json directly (no IPC),
        // and the per-tick arm-gate reads it. See cli/src/armed.rs.
        // ReloadExpose is likewise handled inline in the daemon loop (it owns the
        // Exposer); answer defensively if it ever reaches here.
        ctl::ReqKind::ReloadExpose => {
            req.reply(&json!({ "ok": true, "live": false, "count": 0 }))
                .await
        }
        // Reload is handled inline in the daemon loop (it self-SIGTERMs); answer
        // defensively if it ever reaches here.
        ctl::ReqKind::Reload => req.reply(&json!({ "ok": true, "reloading": false })).await,
        // Mount/Unmount/ListMounts/MountHealth are handled inline in the daemon
        // loop (they need access to DaemonMounts); answer defensively if reached.
        ctl::ReqKind::Mount { .. } => req.reject("mount not handled here").await,
        ctl::ReqKind::Unmount { .. } => req.reject("unmount not handled here").await,
        ctl::ReqKind::ListMounts => req.reject("list-mounts not handled here").await,
        ctl::ReqKind::MountHealth { .. } => req.reject("mount-health not handled here").await,
        ctl::ReqKind::CapStatus => req.reject("cap-status not handled here").await,
        ctl::ReqKind::ListWarm => req.reject("list-warm not handled here").await,
        ctl::ReqKind::FleetRendezvous { .. } => {
            req.reject("fleet-rendezvous not handled here").await
        }
        ctl::ReqKind::ListPending => req.reject("list-pending not handled here").await,
        ctl::ReqKind::ApproveRequest { .. } => req.reject("approve-request not handled here").await,
        ctl::ReqKind::DenyRequest { .. } => req.reject("deny-request not handled here").await,
    }
}

/// Handle a mount request: spawn sshfs directly and track the child process
/// centrally so `handle_unmount` can kill it.
#[cfg(unix)]
pub(crate) async fn handle_mount(
    req: ctl::Req,
    server: &str,
    relay: bool,
    daemon_mounts: &mut DaemonMounts,
    last_mount_check: &mut Instant,
) {
    let ctl::ReqKind::Mount {
        peer,
        remote,
        local,
        read_only,
        auto_restore,
        port,
    } = &req.kind
    else {
        return;
    };
    let peer = peer.clone();
    let remote = remote.clone();
    let local = local.clone();
    let read_only = *read_only;
    let auto_restore = *auto_restore;
    let port = *port;

    // Ensure mount point exists.
    if !Path::new(&local).exists() {
        if let Err(e) = std::fs::create_dir_all(&local) {
            req.reject(&format!("failed to create mount point: {e}"))
                .await;
            return;
        }
        crate::ui::say(&format!("created mount point: {local}"));
    }

    // Check sshfs is available.
    if std::process::Command::new("which")
        .arg("sshfs")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        req.reject("sshfs not found").await;
        return;
    }

    // Bootstrap peer connection info (sshfs authenticates with the managed
    // key: cert mode is `shell --ssh` only).
    let info = match crate::l2::ensure_peer_bootstrap_port(server, &peer, relay, port, false).await {
        Ok(info) => info,
        Err(e) => {
            req.reject(&format!("bootstrap failed: {e}")).await;
            return;
        }
    };
    let peer_name = peer.strip_suffix(".mesh").unwrap_or(&peer);

    // Build the sshfs command args directly.
    let mut args: Vec<String> = Vec::new();

    // Common SSH options.
    args.extend_from_slice(&[
        "-o".into(),
        format!("IdentityFile={}", info.key_path.display()),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", info.known_hosts_path.display()),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=4".into(),
    ]);

    // L3 preferred, L2 fallback.
    let dest = if let Some(d) = crate::l2::l3_dest(&info) {
        d // L3 direct: user@peer.mesh, no ProxyCommand
    } else {
        // L2 fallback: user@filament-peer with ProxyCommand
        let exe = std::env::current_exe().unwrap();
        let exe = exe.to_string_lossy();
        let mut proxy = format!("{exe} --server {server}");
        if relay {
            proxy.push_str(" --relay");
        }
        proxy.push_str(&format!(" forward {peer_name}:{} --stdio", info.rport));
        args.push("-o".into());
        args.push(format!("ProxyCommand={proxy}"));
        format!("{}@{}", info.login, info.host)
    };

    args.push(format!("{dest}:{remote}"));
    args.push(local.clone());
    if read_only {
        args.push("-o".into());
        args.push("ro".into());
    }

    // Spawn sshfs via tokio so we get a Child we can kill later.
    let child = match tokio::process::Command::new("sshfs")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            req.reject(&format!("failed to spawn sshfs: {e}")).await;
            return;
        }
    };

    let pid = child.id().unwrap_or(0);
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mount_id = mount::unique_mount_id();
    let parent_id = mount::find_parent_mount(&local);

    // Record in persistent mount tracking.
    let _ = mount::add_mount(mount::MountEntry {
        id: mount_id.clone(),
        parent_id,
        local: local.clone(),
        peer: peer_name.to_string(),
        remote: remote.clone(),
        pid,
        read_only,
        auto_restore,
        created: now.clone(),
    });

    // Store in daemon in-memory tracking.
    let entry = DaemonMountEntry {
        local: local.clone(),
        peer: peer_name.to_string(),
        remote: remote.clone(),
        pid,
        read_only,
        auto_restore,
        created: now,
    };
    daemon_mounts.entries.insert(local.clone(), entry);
    daemon_mounts.children.insert(local.clone(), child);

    *last_mount_check = Instant::now();
    crate::ui::say(&format!(
        "mounted {peer_name}:{remote} at {local} (id: {mount_id})"
    ));
    req.reply(&json!({ "ok": true })).await;
}

/// Handle an unmount request: kill the sshfs process and remove tracking.
#[cfg(unix)]
pub(crate) async fn handle_unmount(req: ctl::Req, daemon_mounts: &mut DaemonMounts) {
    let ctl::ReqKind::Unmount { target } = &req.kind else {
        return;
    };
    let target = target.clone();

    // Kill the child process if tracked by the daemon.
    if let Some(mut child) = daemon_mounts.children.remove(&target) {
        let _ = child.kill().await;
    }
    daemon_mounts.entries.remove(&target);

    // Also remove from persistent tracking (async-safe, no block_on).
    match mount::unmount_cmd_async(&target).await {
        Ok(()) => req.reply(&json!({ "ok": true })).await,
        Err(e) => req.reject(&format!("unmount failed: {e}")).await,
    }
}

/// Handle a list-mounts request: return all tracked mounts and their status.
#[cfg(unix)]
pub(crate) async fn handle_list_mounts(req: ctl::Req, daemon_mounts: &DaemonMounts) {
    let mounts: Vec<Value> = daemon_mounts
        .entries
        .values()
        .map(|e| {
            let is_alive = mount::is_mount_point(&e.local);
            let status = if is_alive { "healthy" } else { "dead" };
            json!({
                "local": e.local,
                "peer": e.peer,
                "remote": e.remote,
                "read_only": e.read_only,
                "auto_restore": e.auto_restore,
                "created": e.created,
                "status": status,
            })
        })
        .collect();
    req.reply(&json!({ "ok": true, "mounts": mounts })).await;
}

/// Handle a mount-health request: check health of a specific mount.
#[cfg(unix)]
pub(crate) async fn handle_mount_health(req: ctl::Req, daemon_mounts: &DaemonMounts) {
    let ctl::ReqKind::MountHealth { target } = &req.kind else {
        return;
    };
    let target = target.clone();

    // Find the entry by local path or ID.
    let entry = daemon_mounts.entries.get(&target);
    match entry {
        Some(e) => {
            let is_alive = mount::is_mount_point(&e.local);
            let path_exists = Path::new(&e.local).exists();
            let status = if !path_exists {
                "missing"
            } else if !is_alive {
                "dead"
            } else {
                match std::fs::metadata(&e.local) {
                    Ok(_) => "healthy",
                    Err(_) => "stale",
                }
            };
            req.reply(&json!({ "ok": true, "status": status, "local": e.local, "peer": e.peer, "remote": e.remote })).await;
        }
        None => {
            // Not tracked by daemon, but check if it's a live mount anyway.
            if mount::is_mount_point(&target) {
                req.reply(&json!({ "ok": true, "status": "untracked", "local": target }))
                    .await;
            } else {
                req.reject(&format!("no mount found for '{target}'")).await;
            }
        }
    }
}

/// Is something listening on this host's own loopback `port` - i.e. an sshd a
/// `filament shell --ssh` initiator could actually reach? A fast connect probe: a
/// successful connect means a listener (we close it at once); refused/timeout
/// means nothing is there. Reported in the shell-bootstrap ack so the initiator
/// fails fast with a clear message instead of ssh hanging on a dead port.
pub(crate) async fn sshd_listening(port: u16) -> bool {
    // Probe localhost first (covers the common case: sshd bound to localhost or
    // all interfaces). Then also try ::1 for dual-stack daemons that only bind
    // IPv6 localhost.
    let addrs: [(&str, std::net::SocketAddr); 2] = [
        ("127.0.0.1", (std::net::Ipv4Addr::LOCALHOST, port).into()),
        ("[::1]", (std::net::Ipv6Addr::LOCALHOST, port).into()),
    ];
    let rt = tokio::runtime::Handle::current();
    for (_label, addr) in addrs {
        let ok = rt
            .spawn_blocking(move || {
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400))
                    .is_ok()
            })
            .await
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

/// Answer a `filament reach`: report the daemon's warm link to `peer` (route,
/// remote address, RTT, verified name). Synchronous - every fact is local (quinn
/// already measured the RTT/addr; the route is the link's own label/ICE state), so
/// nothing is awaited from the peer and the F8 event-loop rule is not in play. A
/// miss `reject`s so the client falls back to a cold establish-probe.
#[cfg(unix)]
async fn handle_warm_ping(conn: &Conn, req: ctl::Req) {
    let ctl::ReqKind::Ping { peer } = &req.kind else {
        return;
    };
    let peer = peer.clone();
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        req.reject("no warm link").await;
        return;
    };
    // WARM-HOLD: ping succeeded, mark peer as warm (note: we can't call
    // note_warm_use here because conn is &Conn; the warm-hold tick will
    // connect to this peer on the next cycle if it drops)
    let link = conn.link(&pid);
    let direct = link.map(|l| l.direct).unwrap_or(false);
    let route = if direct {
        link.map(|l| l.direct_route.to_string())
            .unwrap_or_else(|| "direct".into())
    } else if let Some(p) = link.and_then(|l| l.peer.clone()) {
        p.route().await.unwrap_or_else(|| "relay".into())
    } else {
        "relay".to_string()
    };
    // Path detail: name the interface the link's local end sits on, classify the
    // remote address, and (for webrtc) report the candidate types + whether the
    // path is relayed. The daemon holds the link AND runs on the same box as the
    // ping client, so it resolves local-ip -> interface locally; ping.rs just
    // renders the fields. This is the data that answers "is it the tailnet?"
    // (e.g. local 100.x on a tailscale0 iface) instead of inferring it.
    let peer_ref = link.and_then(|l| l.peer.clone());
    let path = net::describe_path(t.as_ref(), peer_ref.as_deref())
        .await
        .to_json();
    let reply = json!({
        "ok": true,
        "warm": true,
        "direct": direct,
        "route": route,
        "remote_addr": t.remote_addr().map(|a| a.to_string()),
        "rtt_ms": t.rtt_ms(),
        "verified": link.and_then(|l| l.verified_name.clone()),
        "path": path,
    });
    req.reply(&reply).await;
}

/// Return only links the daemon already holds. This is deliberately passive:
/// devices listing must never establish, ping, or otherwise wake a peer.
#[cfg(unix)]
pub(crate) async fn handle_list_warm(conn: &Conn, req: ctl::Req) {
    let links: Vec<Value> = conn
        .links
        .iter()
        .filter_map(|(pid, link)| {
            let name = link.verified_name.as_deref()?;
            let transport = link.transport.as_ref()?;
            if !link.trusted || !transport.is_alive() {
                return None;
            }
            Some(json!({
                "name": name,
                "warm": true,
                "direct": link.direct,
                "route": if link.direct { link.direct_route } else { "relay" },
                "remote_addr": transport.remote_addr().map(|a| a.to_string()),
                "rtt_ms": transport.rtt_ms(),
                "verified": name,
                "path": Value::Null,
                "pid": pid,
            }))
        })
        .collect();
    req.reply(&json!({ "ok": true, "links": links })).await;
}

#[cfg(unix)]
/// A non-direct (relay/WebRTC) link has no QUIC keepalive, so an idle one may be
/// silently NAT/relay-evicted while `is_alive()`/`is_dead()` still lag (the read
/// loop hasn't seen the EOF yet). Container/DERP paths evict ~10s; reusing such a
/// link would open a stream into a black hole and hang. So past this idle window
/// we refuse to warm-reuse a non-direct link and fall back to a fresh establish
/// (correct, just not free). Direct links are exempt: the 5s keepalive keeps them
/// genuinely alive across idle gaps, and their `idle_ms()` is unreliable here
/// anyway (quinn keepalive frames don't stamp last_activity).
/// The net.rs 5s relay keepalive keeps idle_ms under this gate on healthy links;
/// tripping it means the keepalive stopped, so a fresh establish is the right answer.
const WARM_RELAY_STALE_MS: u64 = 8_000;

#[cfg(unix)]
/// Resolve `peer` (matched case-insensitively on the PROVEN `verified_name`, the
/// same key the L2 cap gate uses) to a warm, trusted, alive link, preferring a
/// direct one. The single resolver for every warm-reuse op (open + pty), so the
/// eligibility rule lives in exactly one place. A miss means the caller falls
/// back to a fresh establish, which is correct.
pub(crate) fn warm_link_for(conn: &Conn, peer: &str) -> Option<(String, Arc<dyn net::Transport>)> {
    conn.links
        .iter()
        .filter(|(_, l)| {
            // Eligibility here is "do I know WHO this link reaches", because the
            // caller is asking to route a request AT that peer. `l.trusted` is a
            // narrower thing: the legacy blanket-trust flag, which a fleet link
            // deliberately never sets (its identity comes from a verified
            // certificate, and `admit_delegated` avoids `trusted` precisely so it
            // cannot leak into the legacy_ok gates). Testing only `trusted` made
            // every fleet sibling ineligible for the warm path, so `shell`/`open`
            // fell through to a cold dial for a peer we hold no secret for and
            // reported it as unreachable while a healthy link sat right there.
            // A Proven identity binding answers the actual question.
            // NOTE: this decides ROUTING, not permission. What the peer may do to
            // us is still decided by the capability gate on the receiving side.
            let identity_known =
                l.trusted || l.identity_binding == crate::capability::BindingStrength::Proven;
            identity_known
                && l.verified_name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case(peer))
                    .unwrap_or(false)
                && l.transport
                    .as_ref()
                    .map(|t| {
                        // Alive, AND (direct OR a relay link that hasn't been idle long
                        // enough to be a silently-evicted zombie).
                        t.is_alive() && (l.direct || t.idle_ms() < WARM_RELAY_STALE_MS)
                    })
                    .unwrap_or(false)
        })
        .max_by_key(|(_, l)| l.direct as u8)
        .map(|(pid, l)| (pid.clone(), l.transport.clone().unwrap()))
}

/// DEBUG: dump every link's warm-reuse eligibility so a miss-despite-a-live-link
/// is diagnosable (visible at `-v` / FILAMENT_LOG=debug only).
#[cfg(unix)]
fn log_warm_miss(conn: &Conn, peer: &str) {
    for (p, l) in conn.links.iter() {
        ui::debug(&format!(
            "warm-miss '{peer}': pid={p} name={:?} verified={:?} trusted={} has_transport={} alive={} direct={}",
            l.name,
            l.verified_name,
            l.trusted,
            l.transport.is_some(),
            l.transport.as_ref().map(|t| t.is_alive()).unwrap_or(false),
            l.direct,
        ));
    }
}

/// Warm-reuse: open a raw L2 stream to `peer:rport` over its existing link and
/// bridge it to the client's unix socket (netcat/ssh/forward fast path).
#[cfg(unix)]
async fn handle_warm_open(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    let ctl::ReqKind::Open { peer, rport } = &req.kind else {
        return;
    };
    let (peer, rport) = (peer.clone(), *rport);
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    // Reuse the SAME per-peer mux the event loop routes inbound L2 frames to.
    let mux = l2_muxes
        .entry(pid.clone())
        .or_insert_with(|| l2::Mux::new(t))
        .clone();
    let tx = tx.clone();
    // SELF-HEALING warm-reuse: VERIFY the held link still delivers BEFORE committing
    // the client. Open the stream and wait for the first inbound frame (sshd's
    // banner - the byte we needed anyway, so a healthy link pays ~1 RTT and nothing
    // extra), then accept. A zombie link (alive at the QUIC layer but black-holing
    // new streams - the popos hang) yields nothing within the window, so we DROP it
    // (the loop re-forms a healthy one, keeping warm-reuse fast) and REJECT, which
    // makes the client's `try_open` return None and fall straight through to a fresh
    // establish. Verifying before accepting is what makes the fallback INSTANT: an
    // accepted-then-dead connection would instead stall the client until ITS own
    // timeout (the 25s ssh ConnectTimeout we measured). Spawned so the verify wait
    // never blocks the event loop (F8).
    tokio::spawn(async move {
        match l2::open_stream_verified(&mux, rport, l2::warm_verify_window()).await {
            Ok((sid, first, rx)) => {
                let sock = req.accept().await;
                l2::serve_verified_stream(mux, sid, sock, first, rx).await;
            }
            Err(e) => {
                ui::debug(&format!(
                    "filament: warm link to '{peer}' is a zombie ({e}); dropping + establishing fresh"
                ));
                let _ = tx.send(Ev::DropLink(pid));
                req.reject("warm link unresponsive; establishing fresh")
                    .await;
            }
        }
    });
}

/// Warm-reuse: open a PTY on `peer` over its existing link and bridge it to the
/// client's stdio socket (the `filament shell` fast path). Records the session->sid
/// so a later `pty-resize` can find it; the entry is dropped when the bridge ends.
#[cfg(unix)]
async fn handle_warm_pty(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    let ctl::ReqKind::Pty {
        peer,
        session,
        cols,
        rows,
        term,
        cmd,
    } = &req.kind
    else {
        return;
    };
    let (peer, session, cols, rows, term, cmd) = (
        peer.clone(),
        session.clone(),
        *cols,
        *rows,
        term.clone(),
        cmd.clone(),
    );
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    let mux = l2_muxes
        .entry(pid.clone())
        .or_insert_with(|| l2::Mux::new(t))
        .clone();
    let warm_ptys = warm_ptys.clone();
    let tx = tx.clone();
    let verify = l2::warm_verify_window();
    // SELF-HEALING warm pty, same shape as handle_warm_open: VERIFY the held link
    // delivers (the shell prompt / replayed buffer, sent unprompted, is the first
    // frame) BEFORE recording the session and accepting the terminal. On a zombie
    // link we DROP it and REJECT, so the client falls straight through to a cold
    // pty rather than getting a dead terminal. Spawned so the verify wait never
    // blocks the event loop (F8).
    tokio::spawn(async move {
        match l2::open_pty_stream_verified(&mux, &session, cols, rows, &term, &cmd, verify).await {
            l2::WarmPtyVerdict::Opened(sid, first, rx_pipe) => {
                if let Ok(mut m) = warm_ptys.lock() {
                    m.insert(session.clone(), (pid, sid));
                }
                let sock = req.accept().await;
                l2::serve_verified_stream(mux, sid, sock, first, rx_pipe).await;
                // Bridge ended (shell exit / client gone / link drop): drop our
                // entry, but only if it is still ours (a reconnect may have
                // replaced it).
                if let Ok(mut m) = warm_ptys.lock() {
                    if m.get(&session).map(|(_, s)| *s == sid).unwrap_or(false) {
                        m.remove(&session);
                    }
                }
            }
            l2::WarmPtyVerdict::Refused(reason) => {
                ui::debug(&format!(
                    "filament: warm pty to '{peer}' refused by the peer ({reason})"
                ));
                req.reject(&format!("refused: {reason}")).await;
            }
            l2::WarmPtyVerdict::LinkDead => {
                ui::debug(&format!(
                    "filament: warm pty link to '{peer}' died; dropping + establishing fresh"
                ));
                let _ = tx.send(Ev::DropLink(pid));
                req.reject("warm link unresponsive; establishing fresh")
                    .await;
            }
            l2::WarmPtyVerdict::Silent => {
                // Clean end, no output: accept and drop at once so the
                // client reads EOF as exit 0 (the cold path's Exited).
                // Nothing is recorded (no live session exists to reattach).
                ui::debug(&format!(
                    "filament: warm pty to '{peer}' exited cleanly with no output"
                ));
                let _sock = req.accept().await;
            }
        }
    });
}

/// Warm-reuse: relay a window-size change to an already-open warm PTY (by session).
#[cfg(unix)]
async fn handle_warm_resize(
    l2_muxes: &HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    req: ctl::Req,
) {
    let ctl::ReqKind::Resize {
        session,
        cols,
        rows,
    } = &req.kind
    else {
        return;
    };
    let (cols, rows) = (*cols, *rows);
    let target = warm_ptys.lock().ok().and_then(|m| m.get(session).cloned());
    if let Some((pid, sid)) = target {
        if let Some(mux) = l2_muxes.get(&pid) {
            let _ = mux
                .transport()
                .send_control(
                    &json!({ "type": "pty-resize", "sid": sid, "cols": cols, "rows": rows }),
                )
                .await;
        }
    }
    req.accept().await; // close the client's short connection cleanly
}

/// Deferred ssh-bootstrap replies, keyed by the peer's link pid. A `Bootstrap`
/// request can't be answered inline: the daemon sends `shell-bootstrap` over the
/// warm link and the peer's `shell-bootstrap-ack` arrives LATER via this same
/// event loop, so blocking here would deadlock. We stash the reply socket (with a
/// deadline) and complete it from the `shell-bootstrap-ack`/`-deny` control arms,
/// or reap it on timeout. A `Vec` per pid handles concurrent ssh to one peer (the
/// ack is identical, so every waiter gets the same answer).
#[cfg(unix)]
pub(crate) type PendingBootstraps =
    HashMap<String, Vec<(tokio::net::UnixStream, std::time::Instant)>>;

/// Warm-reuse the ssh `shell-bootstrap`: install the client's managed `pubkey` on
/// `peer` over the daemon's EXISTING link instead of a fresh cold establish, the
/// big win for `filament shell --ssh` (pty already rode the warm link; the bootstrap was
/// the last cold-establish left). Sends `shell-bootstrap` and STASHES the reply
/// socket; the ack/deny handler completes it. A miss falls the client back to the
/// cold `shell_bootstrap`.
#[cfg(unix)]
pub(crate) async fn handle_warm_bootstrap(
    conn: &Conn,
    pending: &mut PendingBootstraps,
    req: ctl::Req,
) {
    let (peer, pubkey, ssh_port) = match &req.kind {
        ctl::ReqKind::Bootstrap {
            peer,
            pubkey,
            ssh_port,
        } => (peer.clone(), pubkey.clone(), *ssh_port),
        _ => return,
    };
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    if t.send_control(
        &json!({ "type": "shell-bootstrap", "v": 1, "pubkey": pubkey, "ssh_port": ssh_port }),
    )
    .await
    .is_err()
    {
        req.reject("warm link send failed").await;
        return;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    pending.entry(pid).or_default().push((req.sock, deadline));
}

/// Complete every stashed `Bootstrap` waiter for `pid` with `reply`. Called from
/// the `shell-bootstrap-ack`/`-deny` arms; a no-op if none are pending (e.g. the
/// peer re-acked, or the waiter was already reaped).
#[cfg(unix)]
pub(crate) async fn complete_warm_bootstrap(
    pending: &mut PendingBootstraps,
    pid: &str,
    reply: &Value,
) {
    if let Some(waiters) = pending.remove(pid) {
        for (mut sock, _) in waiters {
            ctl::send_reply(&mut sock, reply).await;
        }
    }
}

/// Drop expired bootstrap waiters (peer never answered): closing the socket gives
/// the client an EOF, which it reads as a miss and falls back to the cold path.
#[cfg(unix)]
pub(crate) fn reap_warm_bootstraps(pending: &mut PendingBootstraps) {
    if pending.is_empty() {
        return;
    }
    let now = std::time::Instant::now();
    for waiters in pending.values_mut() {
        waiters.retain(|(_, deadline)| *deadline > now);
    }
    pending.retain(|_, waiters| !waiters.is_empty());
}
