//! The receive command (`filament recv`) and its event loop, lifted out of `main.rs`.
//!
//! One unit, moved without splitting the body: the setup phase that builds the
//! connection, then the single `loop` + `select!` that drives it. Nothing inside was
//! rewritten, so the 13 `tokio::spawn` captures, the borrows that live across the 243
//! awaits, and all 28 in-body cfg regions (`unix`, `l3`, `not(unix)`, `not(l3)`) behave
//! exactly as they did at the crate root.
//!
//! Everything it calls stays where it was and is imported here -- notably the thirty
//! helpers shared with the send path, `daemon_alive` included. Nothing was promoted for
//! this move: a private crate-root item is already visible to a descendant module.
//! `l3` is the single exception to the import story: `mod l3;` is itself `#[cfg(l3)]`, so
//! the module path is gated the same way. The two traits used by method syntax
//! (`anyhow::Context` for `.with_context`, `std::io::IsTerminal` for `.is_terminal`) are
//! imported; the rest travel inside the body's own function-local `use`s.
use crate::dlog;
#[cfg(l3)]
use crate::l3;
#[cfg(l3)]
use crate::{
    AdoptSource, Ceremony, Conn, DaemonMounts, Ev, IncomingFile, MAX_ATTEMPTS, MAX_VERIFY_FAILS,
    PROVEN_CHALLENGE_DEADLINE, PakeInbound, PartMeta, Presence, RecvState, Rung,
    ShellPolicy, TtyGuard, WarmPtys, any_shell_grant, apply_reconfigure, cancelled, channel_of,
    clear_provisional_identity, codeentry, command_arg, config_get,
    consent_token, ctl, daemon_alive, device_allows, device_capability_denied, device_cert_revoked,
    device_name_for_pub, device_set_cap, devices_load, devices_path, devices_remove, devices_store,
    devices_sweep_lapsed, devices_touch, devices_upsert_atomic, direct, direct_ok_for,
    display_name, enqueue_if_requestable, ensure_self_genesis_header, exec_recv, expire_requests,
    expose, finalize_incoming, fleet, fleet_identity_pending, fleet_route_ok, fleet_shaped_link,
    flush_inflight, fresh_secret, handle_auth_key_enroll_response, handle_cert_renew_ack,
    handle_identity_expose, handle_warm_req, human, identity,
    in_binding, interactive_allowed, interactive_requested, is_self_uid,
    issue_proven_challenge_and_hold, issue_signed_bounded_grant, l2, l2_open_allowed,
    l2_target_allowed, link_nonce, load_provisional_identity, load_requests, local_device_cert,
    mark_bounded_cap_source, mark_lapsed_now, maybe_hint_local_wedge, maybe_request_cert_renewal,
    merge_owner_cap_ops, mk_uid, mount, mount_proto, net, next_ev, offer_question, out_binding,
    overlay, owner_pub_for_resources, owner_signed_cap_ops, pair_v2_caps, peer_authz, platform,
    principal_ceiling_for, prompt_line, proof_for, protocol, pwrite_at, quiet_exit_window,
    record_range, regex_lite_code, relay_banner, resolve_peer_identity,
    respond_to_auth_key_enroll_request, respond_to_cert_renew_request,
    respond_to_identity_challenge, safe_create_part, safe_incoming_name, safe_resume_part,
    save_requests, sdnotify, session, settings, shell_argv, shutdown, spawn_session_pumps, sshd,
    sshd_listening, sshkeys, store_provisional_identity, subnet_forward, sweep_completed_streams,
    test_hooks, ui, verify_incoming, with_devices_mut,
};
// Unix-only daemon-control names, gated exactly like their definitions in
// daemon_ctl.rs. Call sites stay byte-identical to the monolith.
#[cfg(unix)]
use crate::{
    PendingBootstraps, complete_warm_bootstrap, handle_list_mounts, handle_list_warm,
    handle_mount, handle_mount_health, handle_unmount, handle_warm_bootstrap,
    reap_warm_bootstraps, warm_link_for,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::mpsc;

pub(crate) async fn recv_cmd(
    server: &str,
    mut code: Option<String>,
    mut dir: PathBuf,
    yes: bool,
    room: Option<String>,
    to: Option<String>,
    keep_open: bool,
    relay: bool,
    remember: Option<String>,
    daemon: bool,
    output: Option<String>,
    mut shell_policy: ShellPolicy,
    // M-1: optional non-root account the web-shell/ssh PTY is dropped to. `None`
    // means the PTY runs as the up-process user (documented root risk).
    mut shell_user: Option<String>,
    no_proxy_fallback: bool,
) -> Result<()> {
    let opened_flow =
        !daemon && interactive_allowed() && (code.is_none() || interactive_requested());
    let to_stdout = output.as_deref() == Some("-");
    // Daemon start: idempotently heal the owner's self genesis cap header.
    // Identities created before this seeding existed have no header; seeding
    // only at `identity init` would grandfather-trap them into permanent
    // Unprovisioned. Healing on every daemon start makes old identities correct
    // on next `up` and new ones born correct. Tautological; widens nothing.
    if daemon {
        if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
            if ensure_self_genesis_header(&crate::settings::config_dir(), &uk) {
                ui::debug("seeded owner self genesis capability header");
            }
        }
    }
    // INTERACTIVE GATE (CLI `recv` only, never the daemon/`up`). With no code,
    // offer: type a code to connect to a specific person, or press Enter on an
    // empty buffer to use the local network (today's default). When the gate is
    // closed we fall straight through to the auto-room default below.
    if !daemon && code.is_none() && interactive_allowed() {
        ui::say(&ui::paint(
            ui::Tone::Dim,
            "  enter a code to connect to a specific person, or press enter to use the local network",
        ));
        match codeentry::run("  receive / code  ", codeentry::Mode::Claim, "", "")? {
            codeentry::Outcome::Submitted(c) => code = Some(c),
            codeentry::Outcome::Empty => { /* fall through to the local-network auto room */ }
            codeentry::Outcome::Cancelled => return Err(cancelled()),
        }
    }
    if opened_flow {
        eprintln!();
        eprintln!("  {}", ui::paint(ui::Tone::Brand, "RECEIVE"));
        eprintln!(
            "  from     {}",
            to.as_deref().unwrap_or(if code.is_some() {
                "holder of this one-time code"
            } else {
                "nearby sender"
            })
        );
        eprintln!(
            "  into     {}",
            if to_stdout {
                "stdout".to_string()
            } else {
                dir.display().to_string()
            }
        );
        eprintln!("  verify   whole-file hash before final placement");
        eprintln!(
            "  consent  {}",
            if yes {
                "accept matching offers"
            } else {
                "ask before each offer"
            }
        );
        let mut replay = vec!["filament".to_string(), "receive".to_string()];
        if let Some(code) = code.as_deref() {
            replay.push(command_arg(code));
        }
        replay.extend(["--dir".to_string(), command_arg(&dir.display().to_string())]);
        if yes {
            replay.push("--yes".to_string());
        }
        eprintln!("  command  {}", replay.join(" "));
        let confirmation = prompt_line("\n  Press Enter to wait, or type cancel: ")?;
        if confirmation.eq_ignore_ascii_case("cancel") {
            bail!("cancelled");
        }
    }
    // L1-a unification: a transfer code and a pairing code now have the SAME
    // shape (`words-NNNN`) and run the SAME ephemeral SPAKE2 ceremony, the verb
    // (`recv` vs `pair`) decides whether the agreed secret is discarded or kept.
    // So `recv` no longer redirects a 4-digit code away (the old width-based
    // hint is obsolete); any well-formed code is a valid claim here.
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let my_uid = mk_uid("r");
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    // P2 (GAP-2): `mut` so the long-lived acceptor's outer reconnect loop can
    // swap in a freshly-dialed signaling client after a drop (see below). The
    // short-lived `recv`/`send` paths never reconnect, they re-invoke fresh,
    // so this is only exercised by the daemon (`up`/`up --dir`).
    let mut sio = net::connect_signaling(server, tx.clone()).await?;

    let mut paired = code.is_some();
    // C24: at most one typed claim in flight, a second typed code while one
    // is pending was silently dropped in live use; now it queues a message.
    let mut claim_in_flight = false;
    // C29: an in-session pairing ceremony (daemon mode): typed code or a
    // minted one, exactly ONE side hands over a fresh secret (creator
    // initiates; a claimer waits 3 s for the creator, then takes over,
    // browsers never initiate). Some(true) = we minted; Some(false) = we
    // claimed; None = no ceremony pending.
    let mut ceremony: Option<bool> = None;
    let mut ceremony_pid: Option<String> = None;
    let mut ceremony_secret = fresh_secret();
    // Receive-side transfer/consent state, grouped out of this function's locals
    // (still a plain local; no handler extraction yet). See `RecvState`.
    let mut st = RecvState {
        by_sid: HashMap::new(),
        verify_fails: HashMap::new(),
        completed: 0usize,
        ever_received: false,
        pending: Default::default(),
        pending_proven: Arc::new(Mutex::new(HashMap::new())),
        question_open: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        question_shown: Instant::now(),
        recv_pending_offers: HashMap::new(),
        recv_cers: HashMap::new(),
        recv_deadlines: HashMap::new(),
    };
    let mut devices = devices_load(); // channel -> identity lookup for proofs
    // C30: the convergent session repairs whatever the one-shot emits below
    // lose, room membership, channel subscriptions, the lease. The emits
    // stay as the fast path (and old-server compat); the session is truth.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.channels = devices.iter().map(|(_, s)| channel_of(s)).collect();
    // Fleet auto-mesh: one more meeting point, where devices certified by the
    // SAME owner key find each other with no pairwise pairing. Presence there
    // authorizes NOTHING; admission runs on the certificate. See cli/src/fleet.rs
    // and docs/design-fleet-automesh.md.
    if let Some(fc) = fleet::channel() {
        if !sess.channels.contains(&fc) {
            sess.channels.push(fc);
        }
    }
    // L1-a: the ephemeral SPAKE2 ceremony for a `recv <code>` claim. The typed
    // code is split CLIENT-SIDE; only the numeric nameplate is sent (pair-claim
    // {nameplate, v:2}). The words feed SPAKE2 and never reach the server. After
    // mutual auth the agreed secret is DISCARDED (transfer never persists it).
    //
    // PER-PEER ceremonies (shared-auto-room fix): the receiver joins the sender's
    // room, which (for a `send --code`) is the sender's AUTO room, shared with any
    // other local peers sitting in it. We therefore CANNOT latch onto the first
    // peer that appears: an unrelated decoy must not be allowed to consume our one
    // ceremony, run it to the budget, and bail the whole receive. Instead we run
    // an INDEPENDENT ephemeral ceremony per candidate peer, each built from the
    // SAME claimed code (words + nameplate). The FIRST peer whose ceremony agrees
    // K and verifies the confirm MAC becomes the authenticated sender; from then
    // on we accept file-offers ONLY from that peer. A peer whose ceremony fails
    // (wrong words) or whose per-peer budget expires is dropped INDIVIDUALLY and
    // never bails the receive. Only an OVERALL deadline with NO peer authenticated
    // fails the whole `recv` (so a genuinely absent/old sender still fails loudly
    // rather than hanging). `recv_code_path` is the "this is a code claim" sentinel
    // (was `recv_cer.is_some()`); `recv_pake_template` mints each per-peer ceremony.
    let recv_code_path = code.is_some();
    let recv_pake_template: Option<(String, String)>; // (words, nameplate)
    // Identity: receiver-generated nonce challenges for introduce path (0x02), single-use, session-scoped, erased after verification, distinct per concurrent session
    // Map peer_id -> (nonce, timestamp, receiver_device_pub)
    let mut identity_nonces: HashMap<String, ([u8; 32], Instant, [u8; 32])> = HashMap::new();
    let mut recv_pending_direct: HashMap<
        String,
        (Vec<String>, Option<String>, Option<String>, u8),
    > = HashMap::new();
    // #161: first-offer hold start times per peer. On the typed-code path the
    // buffered offer is replayed at PAKE confirm, BEFORE DirectReady issues the
    // 0x02 identity challenge, so the first offer always arrives with identity
    // unresolved. The offer is held (re-injected) while identity resolution is
    // pending, bounded by RECV_IDENTITY_HOLD_DEADLINE from first sight so a
    // ceremony that never resolves cannot wedge the transfer.
    let mut recv_identity_hold: HashMap<String, std::time::Instant> = HashMap::new();
    // #161: how long the offer waits for identity to resolve before deciding.
    // Identity resolution normally settles in well under a second on a working
    // link; the window exists so a revoked device's cert (which resolves via
    // the challenge) reaches the gate's absolute Deny before the offer is
    // decided. A peer whose identity does not resolve within the window is
    // decided by the normal gate, which is the documented residual - see
    // PROVEN_CHALLENGE_DEADLINE, which must stay in lockstep with this so the
    // challenge's entry does not expire and let a re-issue clobber the nonce.
    const RECV_IDENTITY_HOLD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);
    let mut recv_pake_done = code.is_none(); // only the code path runs the PAKE
    let recv_pake_budget = Duration::from_secs(
        std::env::var("FILAMENT_PAIR_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
    );
    // Overall bound: once we are matched into the sender's room, SOMEONE must
    // authenticate within this window or the whole `recv` fails loudly. Per-peer
    // budgets only drop individual mis-latch candidates; this is the backstop for
    // a genuinely absent / old sender. Armed on the first candidate channel.
    let mut recv_pake_overall_deadline: Option<Instant> = None;
    // Memory bound: a crowded room cannot blow us up. We mint at most this many
    // concurrent candidate ceremonies; further candidates are ignored (the real
    // sender is, in practice, among the first to share the room with the claimer).
    const RECV_MAX_CANDIDATES: usize = 8;
    // #211: the control socket must be ACCEPTING before "filament up" is printed.
    // A sibling `mint` can race the bind and silently fail to arm otherwise.
    // Create the control channel here (before the banner) and spawn the server
    // with a readiness signal the banner awaits. `ctl_tx` is held for the loop's
    // life so `ctl_rx` stays open (recv pends, never spins) even when we are not
    // the daemon and `serve` was not spawned.
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<ctl::Req>();
    let mut ctl_ready: Option<tokio::sync::oneshot::Receiver<()>> = None;
    #[cfg(unix)]
    {
        if daemon && daemon_alive() == Some(std::process::id()) {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
            ctl_ready = Some(ready_rx);
            let ctl_tx = ctl_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    ctl::serve_at(crate::ctl::control_sock_path(), ctl_tx, Some(ready_tx)).await
                {
                    crate::ui::trace(&format!("filament: control socket disabled: {e}"));
                }
            });
        }
    }
    #[cfg(not(unix))]
    let _ = &ctl_tx;
    match &code {
        Some(c) => {
            // Split the typed code into (nameplate, words); send ONLY the
            // nameplate. The words become the SPAKE2 password held locally.
            let normalized = crate::pake::norm_code(c);
            let (np, pw) = crate::pake::split_code(&normalized);
            if pw.is_empty() || np.is_empty() {
                bail!("that code doesn't look right, expected something like brave-otter-371");
            }
            // Held to mint a fresh per-peer ceremony for each candidate. The words
            // live ONLY here and inside each Ceremony's SPAKE2 state; never sent.
            recv_pake_template = Some((pw.clone(), np.clone()));
            sio.emit("pair-claim", json!({ "nameplate": np, "v": 2 }))
                .await
                .ok();
        }
        None if daemon => {
            recv_pake_template = None; // no code claim, no ephemeral PAKE
            // C19: the daemon joins NO room. Presence-channel subscriptions
            // only, strangers can't see it, probe it, or offer to it.
            // Enrollment rendezvous: subscribe to enroll_channel(owner_pub)
            // when armed (outstanding non-expired auth key). Channel-based
            // (not room) because the server supports 1 room/socket and we
            // need the solo room for known-device discovery.
            let solo = format!("up-{}", fresh_secret());
            sess.room = Some(solo.clone());
            sess.emit(
                &sio,
                "join",
                json!({ "room": solo, "name": display_name(), "uid": my_uid }),
            )
            .await;
            // #211: the banner means SERVING, not "process started". Wait
            // (bounded) for the control socket to accept before announcing up;
            // a sibling `mint` that arms right after this line must not race a
            // socket that is not listening yet.
            if let Some(ready) = ctl_ready.take() {
                let _ = tokio::time::timeout(Duration::from_secs(5), ready).await;
            }
            if crate::armed::is_armed() {
                ui::debug("enrollment armed: ephemeral devices may enroll");
            } else {
                ui::debug("enrollment closed (no armed keys — mint or arm an auth-key to open)");
            }
            let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
            let mut c = chans;
            if crate::armed::is_armed() {
                if let Ok(Some(uk)) =
                    crate::identity::UserKey::load(&crate::platform::PlatformKeyStore)
                {
                    let ek = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
                    if !c.contains(&ek) {
                        c.push(ek);
                    }
                }
            }
            // Fleet auto-mesh: the meeting point for same-owner devices goes in
            // the SAME list, because this is the subscribe the daemon actually
            // emits. (It rebuilds `c` from scratch and then overwrites
            // sess.channels, so anything pushed onto sess.channels before this
            // point is discarded.) Presence here authorizes nothing; admission
            // runs on the certificate. See cli/src/fleet.rs.
            if let Some(fc) = fleet::channel() {
                if !c.contains(&fc) {
                    c.push(fc);
                }
            }
            sess.emit(&sio, "subscribe", json!({ "channels": c })).await;
            sess.channels = c;
            ui::say(&format!(
                "  {} filament up, {} known device{} {} {}",
                ui::paint(ui::Tone::Brand, "●"),
                devices.len(),
                if devices.len() == 1 { "" } else { "s" },
                ui::glyph_arrow(),
                ui::paint(ui::Tone::Bold, &dir.display().to_string()),
            ));
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  trusted devices only · invisible to strangers · Ctrl-C or `filament down` to stop",
            ));
            // C29: this is a SESSION, like a browser tab, pairing and petname
            // management happen right here.
            if std::io::stdin().is_terminal() {
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  type a code to pair a new device · `pair` mints one · `devices` · `forget <name>`",
                ));
            }
        }
        None => {
            recv_pake_template = None; // local-network listen, no ephemeral PAKE
            let room = match &room {
                Some(r) => r.clone(),
                None => net::fetch_auto_room(server).await?,
            };
            // C22: proactive affordance, tell the user what they CAN do,
            // cargo-style gutter, before they have to guess.
            ui::say(&format!(
                "  {} listening, same-network devices appear automatically  {}",
                ui::paint(ui::Tone::Brand, "●"),
                ui::paint(
                    ui::Tone::Dim,
                    &format!("(room {room} · dir {})", dir.display())
                ),
            ));
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  have a code? just type it here (like brave-otter-123) and press Enter",
            ));
            sess.room = Some(room.clone());
            sess.emit(
                &sio,
                "join",
                json!({ "room": room, "name": display_name(), "uid": my_uid }),
            )
            .await;
            // C12: announce on every known device's presence channel
            if !devices.is_empty() {
                let chans: Vec<String> = devices.iter().map(|(_, s)| channel_of(s)).collect();
                ui::say(&format!("watching for {} known device(s)", devices.len()));
                sess.emit(&sio, "subscribe", json!({ "channels": chans }))
                    .await;
            }
        }
    }

    // L2 acceptor posture (computed here so it also gates the direct-QUIC path).
    // OFF unless FILAMENT_L2=1 (opt-in) OR an active `up --shell` policy turns it
    // on (you can't ssh in without the acceptor). See its second use below.
    // L2/shell is ON when: an `--shell`/`--shell-only` policy turns it on, the
    // FILAMENT_L2 opt-in is set, OR any known device has been `grant`ed shell (so
    // `filament grant <dev> shell` works on a plain `up` without restarting with a
    // flag, matching what the grant command tells the user). The per-device gate
    // below still denies every non-granted device, so this never widens access.
    let l2_enabled = shell_policy.enables_l2()
        || std::env::var("FILAMENT_L2")
            .map(|v| v == "1")
            .unwrap_or(false)
        || any_shell_grant();

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid.clone(),
        relay, // relay_only
        to,    // to_filter
        // P3 (GAP-3): the `up`/`up --shell` daemon acceptor is the canonical
        // long-lived / interactive session, so warm redundancy defaults ON for it
        // (a one-shot `recv` keeps daemon=false -> OFF).
        daemon, // warm_standby default
        // rung-1 direct-QUIC: take it when the env gate is set, when this is an
        // L2/ssh acceptor, OR when this is the long-lived `up` daemon. Any acceptor
        // MUST answer the initiator's transport-offer (direct-QUIC over the
        // reachable host candidate, e.g. Tailscale) rather than build a colliding
        // WebRTC peer (glare). For `up --shell` this kills the `filament shell --ssh`
        // "stuck while connecting" failure; for a plain `up` it kills the up<->up
        // glare/supersede churn (two known daemons each racing to be the WebRTC
        // initiator). See `direct_ok_for`. One-shot send/recv/pair (daemon=false)
        // are unaffected and keep their WebRTC default.
        direct_ok_for(daemon, l2_enabled),
    );
    // WARM-HOLD: load configured warm-peers at daemon startup
    if daemon {
        conn.load_warm_peers_config();
    }
    // SIGINT/SIGTERM: route a graceful Ev::Interrupted through the loop AND arm a
    // signal-owned force-exit watchdog. The watchdog is the guarantee: if the
    // event loop is wedged on a stuck peer transport (a WebRTC data-channel write
    // against a frozen/half-open peer, or a send_frame parked on backpressure that
    // never drains), the graceful Interrupted is never processed and the daemon
    // would otherwise ignore the signal until systemd SIGKILLs it ~90s later. The
    // watchdog force-exits within the bounded grace regardless of loop state; a
    // dropped link is an ordinary disconnect to the peer's resilience layer.
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }
    #[cfg(unix)]
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                term.recv().await;
                shutdown::arm_force_exit(130, shutdown::grace());
                let _ = tx.send(Ev::Interrupted);
            }
        });
    }
    // C29: the stdin owner also runs for an INTERACTIVE daemon (a terminal-
    // attached `filament up` is a session); `up --install` under systemd has
    // no tty, so headless daemons stay stdin-free.
    let interactive = !daemon || std::io::stdin().is_terminal();
    let tty_guard = if interactive && std::io::stdin().is_terminal() {
        Some(TtyGuard::raw())
    } else {
        None
    };
    if interactive {
        let tx = tx.clone();
        let q = st.question_open.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 1];
            let mut line = String::new();
            while stdin.read(&mut buf).await.map(|n| n == 1).unwrap_or(false) {
                let c = buf[0] as char;
                if q.load(std::sync::atomic::Ordering::Relaxed)
                    && "yYnN".contains(c)
                    && line.is_empty()
                {
                    ui::answer_echo(c); // raw mode is no-echo; land it cleanly (C23)
                    let _ = tx.send(Ev::StdinLine(c.to_lowercase().to_string()));
                    continue;
                }
                match buf[0] {
                    b'\n' | b'\r' => {
                        eprintln!();
                        let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                        line.clear();
                    }
                    0x7f | 0x08 => {
                        if line.pop().is_some() {
                            eprint!("\x08 \x08");
                        }
                    }
                    _ if !c.is_control() => {
                        eprint!("{c}");
                        line.push(c);
                    }
                    _ => {}
                }
            }
        });
    }
    // L3 (serve_tun mesh): the up daemon opens a TUN and routes IP packets across
    // its peer links when `tun-addr` is set. `auto` (recommended) derives a stable,
    // self-certifying overlay address from this device's Ed25519 overlay key; peers
    // learn+trust it via a signed `l3-announce` (below). A manual CIDR is the
    // advanced/PSK case (no announce). Off otherwise; Linux-only.
    // `l3_seen`: last announce received per pid, replayed once a datagram-capable
    // transport is installed, so a hello that races ahead of the link is not lost
    // (review fix #3).
    #[cfg(l3)]
    let mut l3_seen: HashMap<String, overlay::Announce> = HashMap::new();
    #[cfg(l3)]
    let l3: Option<std::sync::Arc<l3::L3>> = if daemon {
        match settings::get_str("tun-addr", None) {
            Some(setting) => {
                let (cidr, identity) = if setting == "auto" {
                    match overlay::load_identity() {
                        Ok(id) => (format!("{}/128", id.addr()), Some(id)),
                        Err(e) => {
                            ui::say(&ui::paint(ui::Tone::Warn, &format!("  L3 disabled: {e}")));
                            (String::new(), None)
                        }
                    }
                } else {
                    (setting.clone(), None) // manual/PSK address, no crypto announce
                };
                if cidr.is_empty() {
                    None
                } else {
                    // Endpoint selection: `l3-mode` setting (kernel|userspace|auto),
                    // default Auto; FILAMENT_L3_USERSPACE / `up --userspace` force
                    // userspace (handled inside L3::start via the env).
                    let mode = match settings::get_str("l3-mode", None).as_deref() {
                        Some("kernel") => l3::L3Mode::Kernel,
                        Some("userspace") => l3::L3Mode::Userspace,
                        _ => l3::L3Mode::Auto,
                    };
                    match l3::L3::start(&cidr, 1280, identity, mode) {
                        Ok(m) => {
                            let addr = m.my_addr().map(|a| a.to_string()).unwrap_or(cidr);

                            // Subnet router: if this machine offers prefixes, make
                            // the kernel actually carry them. Only in kernel-TUN
                            // mode, because userspace has no kernel route to
                            // forward FROM, and saying "routing" while forwarding
                            // nothing is the failure this whole module is written
                            // against.
                            // Same reader the announce paths use, so what the
                            // kernel is told to forward and what the wire
                            // advertises cannot diverge.
                            let advertised: Vec<String> = crate::l3::advertised_prefixes();
                            if !advertised.is_empty() {
                                if m.is_userspace() {
                                    ui::say(&ui::paint(
                                        ui::Tone::Warn,
                                        &format!(
                                            "  advertise-routes is set ({}) but L3 is in userspace mode; a subnet router needs the kernel TUN, so nothing is being carried",
                                            advertised.join(", ")
                                        ),
                                    ));
                                } else {
                                    let snat = settings::get_bool("route-snat", None);
                                    match subnet_forward::enable(l3::ifname(), &advertised, snat) {
                                        Ok(_applied) => ui::say(&format!(
                                            "  {} carrying {} for peers{}",
                                            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                            advertised.join(", "),
                                            if snat { " (masqueraded)" } else { "" }
                                        )),
                                        // LOUD, not swallowed: a router that cannot
                                        // forward must not look like one that can.
                                        Err(e) => ui::say(&ui::paint(
                                            ui::Tone::Err,
                                            &format!(
                                                "  cannot carry {}: {e}",
                                                advertised.join(", ")
                                            ),
                                        )),
                                    }
                                }
                            }
                            if m.is_userspace() {
                                ui::say(&format!(
                                    "  {} L3 overlay {} (userspace, zero privilege)",
                                    ui::paint(ui::Tone::Brand, "●"),
                                    addr
                                ));
                                ui::say(&ui::paint(
                                    ui::Tone::Warn,
                                    "    host firewall/nftables are NOT enforced here; only mesh membership + the expose allowlist gate access",
                                ));
                                ui::say(
                                    "    native tools reach <peer>.mesh via `filament forward <peer>:<port> --socks` (no kernel route in userspace)",
                                );
                                // Auto-start SOCKS5 proxy when kernel TUN is unavailable.
                                // Opt-out via --no-proxy-fallback or `filament set auto-proxy off`.
                                let auto_proxy =
                                    settings::get_bool("auto-proxy", None) && !no_proxy_fallback;
                                if auto_proxy {
                                    let server = server.to_string();
                                    tokio::spawn(async move {
                                        if let Err(e) =
                                            l2::proxy_cmd(&server, "127.0.0.1", 1080, 0, relay)
                                                .await
                                        {
                                            // Port already in use is expected (user started proxy manually);
                                            // only log unexpected errors.
                                            let msg = e.to_string();
                                            if !msg.contains("already in use") {
                                                ui::debug(&format!("auto-proxy: {e}"));
                                            }
                                        }
                                    });
                                    ui::say(&format!(
                                        "  {} started SOCKS5 proxy on 127.0.0.1:1080 (set your tools' proxy to this)",
                                        ui::paint(ui::Tone::Ok, ui::glyph_ok())
                                    ));
                                    ui::say(&format!(
                                        "    e.g.  curl --socks5-hostname 127.0.0.1:1080 http://<peer>.mesh:8080/"
                                    ));
                                }
                            } else {
                                // Kernel mode is dual-stack: show the v4 address too
                                // (userspace has no v4 endpoint yet, so it is omitted
                                // above to avoid implying a route that does not exist).
                                let v4 = m
                                    .my_addr_v4()
                                    .map(|a| format!(" / {a}"))
                                    .unwrap_or_default();
                                ui::say(&format!(
                                    "  {} L3 overlay {}{} on filament0",
                                    ui::paint(ui::Tone::Brand, "●"),
                                    addr,
                                    v4
                                ));
                                // Show the .mesh name that resolves to this machine.
                                let my_name = l3::hostname();
                                ui::say(&format!(
                                    "    this machine resolves as {}{}",
                                    l3::sanitize_host(&my_name),
                                    ".mesh"
                                ));
                            }
                            // Add this machine's own address to MagicDNS so
                            // `<name>.mesh` resolves locally (not just peers).
                            // Uses the filament device name (from `filament set name`
                            // or hostname if unset), sanitized for DNS.
                            if let Some(id) = m.identity_ref() {
                                let my_name = config_get("name").unwrap_or_else(|| l3::hostname());
                                let v6 = id.addr();
                                let v4 = Some(id.addr_v4());
                                m.names_insert("__self__", &l3::sanitize_host(&my_name), v6, v4)
                                    .await;
                                if !m.is_userspace() {
                                    m.refresh_hosts().await;
                                }
                                // Configure sshd to listen on overlay addresses if enabled.
                                if settings::get_bool("sshd-overlay", None) {
                                    let v6_str = id.addr().to_string();
                                    let v4_str = id.addr_v4().to_string();
                                    if let Err(e) = sshd::configure_sshd_overlay(&v6_str, &v4_str) {
                                        ui::say(&ui::paint(
                                            ui::Tone::Warn,
                                            &format!("  sshd-overlay: {e}"),
                                        ));
                                    }
                                }
                            }
                            Some(m)
                        }
                        Err(e) => {
                            ui::say(&ui::paint(ui::Tone::Warn, &format!("  L3 disabled: {e}")));
                            None
                        }
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };
    // `filament expose`: once the overlay is up, bind the persisted ports on the
    // overlay address and forward each to its local target. Reconciled live on a
    // ReloadExpose control request (expose/unexpose without a restart).
    #[cfg(l3)]
    let exposer: Option<std::sync::Arc<expose::Exposer>> = match l3.as_ref() {
        Some(m) => {
            // POSTURE (user decision): a node that SILENTLY fell back to userspace
            // (Auto, no explicit opt-in) must NOT auto-honor expose.json, because
            // userspace bypasses host firewall/nftables on filament0 - an operator
            // who assumed kernel-mode scoping would silently lose it. Only honor
            // expose in userspace when the user opted in (`--userspace` / the env /
            // `l3-mode=userspace`). Kernel mode always honors it.
            let userspace_opt_in = std::env::var("FILAMENT_L3_USERSPACE").as_deref() == Ok("1")
                || settings::get_str("l3-mode", None).as_deref() == Some("userspace");
            if m.is_userspace() && !userspace_opt_in {
                if !expose::load().is_empty() {
                    ui::say(&ui::paint(
                        ui::Tone::Warn,
                        "  expose.json NOT honored: L3 fell back to userspace (host firewall is bypassed there).",
                    ));
                    ui::say(
                        "    opt in with `filament up --userspace` or `filament set l3-mode userspace` to expose in userspace mode",
                    );
                }
                let ex = expose::Exposer::new(m.clone());
                Some(ex) // held so a later live opt-in via ReloadExpose can still bind
            } else {
                let ex = expose::Exposer::new(m.clone());
                let n = ex.reconcile().await;
                if n > 0 {
                    ui::say(&format!(
                        "  {} exposing {} port{} on the overlay",
                        ui::paint(ui::Tone::Brand, "●"),
                        n,
                        if n == 1 { "" } else { "s" }
                    ));
                }
                Some(ex)
            }
        }
        None => None,
    };
    // G-k: peer-left delivery is best-effort, a browser can close having
    // delivered every byte yet never emit its leave (observed under load,
    // gate 6). Tick the loop on a 2s timeout so a fallback quiet-check can
    // exit cleanly instead of idling to the connect-timeout.
    let mut last_quiet: Option<Instant> = None;
    let quiet_window = quiet_exit_window();
    // C30 phase 2: roster reconciliation from sync digests, a missed
    // peer-joined/left self-corrects. Absence must hold for TWO consecutive
    // digests before a drop (one digest can race a join in flight).
    let mut digest_absent: HashMap<String, u8> = HashMap::new();
    let mut channel_digest_absent: HashMap<String, u8> = HashMap::new();
    let mut digest_alone = false;
    // C30 phase 3: link mini-sync, state pings every ~10s per link.
    let mut last_state_ping = Instant::now();
    // L2 (ssh/TCP tunnel) acceptor: one mux per link, created on the first
    // l2-open seen on that link. `l2_enabled` is computed once above (it also
    // gates the direct-QUIC path); reused here for the mux/cap machinery.
    let mut l2_muxes: HashMap<String, Arc<l2::Mux>> = HashMap::new();
    // Warm-pty session -> (pid, sid), so a `pty-resize` op relays to the right stream.
    let warm_ptys: WarmPtys = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
    // Warm ssh-bootstrap reply sockets awaiting the peer's ack (see PendingBootstraps).
    #[cfg(unix)]
    let mut pending_bootstrap: PendingBootstraps = HashMap::new();
    // Warm-link reuse: ONLY the registered `up` daemon exposes the local control
    // socket (a short-lived `recv`/`send` must never bind it and steal the
    // daemon's path). When a sibling `filament shell --ssh`/`netcat`/`forward` asks to
    // reach a peer we already hold a link to, we open a new L2 stream over that
    // warm link instead of making the sibling establish a fresh one. `ctl_tx`
    // was created (and `serve` spawned, when we are the daemon) before the
    // banner, so a mint racing the bind cannot happen; `ctl_rx` is consumed
    // below.

    // Hold `ctl_tx` for the loop's life so `ctl_rx` stays open (recv pends, never
    // spins) even when `serve` was not spawned (non-unix, or not the daemon).
    // web-shell (#4): persistent PTY sessions, keyed by a stable browser-chosen
    // session id, OUTLIVE the link that opened them. A dropped data channel
    // DETACHES (does not kill) the shell; a reconnect with the same session id
    // reattaches and replays buffered output. Process-wide for the whole loop.
    let pty_sessions = l2::PtySessions::new();
    // Per-link map of the PTY sids currently bound to a session on that link, so
    // a link drop can DETACH exactly those sessions (and a clean l2-close ends
    // the right one). pid -> (sid -> session_id).
    let mut pty_bindings: HashMap<String, HashMap<u32, String>> = HashMap::new();
    // web-shell: per-sid resize senders are now owned by each Mux (l2.rs) so they
    // are freed on every teardown path (H-1: closes the prior pty_resizers leak).
    // Bug 5: surface the single-host mDNS wedge hint once after repeated stuck.
    let mut stuck_while_connecting = 0u32;
    let mut wedge_hint_shown = false;
    let _saw_known_peer: HashSet<String> = HashSet::new();
    // C12 live-pairing: the roster (`devices`) is loaded ONCE at startup, and
    // KnownPeer events only fire for channels we've SUBSCRIBED. A device paired
    // into the shared store by a SEPARATE `filament pair` process AFTER the
    // daemon is up was therefore invisible until restart, it never got a
    // subscription, so its "appeared, connecting" flow never fired and it
    // could not connect (no transfer, no web-shell). We now re-scan the store
    // on a modest cadence and subscribe to any NEW device's channel live; the
    // session digest (which includes `sess.channels`) repairs a lost subscribe
    // on the next tick. Existing channels and live links are untouched.
    let mut known_channels: std::collections::HashSet<String> =
        devices.iter().map(|(_, s)| channel_of(s)).collect();
    known_channels.extend(fleet::channel());
    let mut last_devices_scan = Instant::now();
    // Fleet auto-mesh link state, keyed by peer sid.
    //   pending  dialed off the fleet channel, certificate NOT yet proven. Such a
    //            link is reachable but authorizes nothing, and in particular must
    //            not receive an L3 route (see the l3-announce arm below).
    //   verified fleet-hello checked out against our owner key.
    //   greeted  we already sent ours, so a mutual hello does not ping-pong.
    // L3/fleet binding on a transport with NO RFC-5705 exporter (the relay /
    // DataChannel path). `Announce::verify` and `fleet-hello` are bound to the
    // link so a captured message cannot be replayed onto another one, and
    // direct-QUIC supplies that binding for free. A DataChannel does not, and
    // webrtc-rs exposes no DTLS exporter, so the two ends establish one by
    // challenge instead: each side picks a random nonce and sends it, and the
    // PEER signs against it. Freshly generated per link, so a message captured
    // on one link is useless on the next, which is the property the exporter was
    // providing.
    //   ours[pid]   what WE chose: verify messages arriving from that peer.
    //   theirs[pid] what THEY chose: sign messages we send to them.
    let mut bind_ours: HashMap<String, Vec<u8>> = HashMap::new();
    let mut bind_theirs: HashMap<String, Vec<u8>> = HashMap::new();
    let mut fleet_pending: std::collections::HashSet<String> = Default::default();
    let mut fleet_verified: std::collections::HashSet<String> = Default::default();
    // Offers that arrived while this link's `fleet-hello` was still in flight.
    // Verification is MUTUAL and the two directions are not synchronized: the
    // sender proves US, then offers, and its offer can beat our verification of
    // IT. Deciding then reads `binding=None` on a link that is about to be
    // Proven, and the gate declines a transfer it would have allowed a moment
    // later. Measured as a ~1-in-6 spurious decline between two siblings. The
    // answer is to wait for the identity to settle, not to widen the gate:
    // whether the peer is authorized is exactly what is still being computed.
    let mut fleet_deferred_offers: Vec<(String, serde_json::Value, Instant)> = Vec::new();
    // Brokered meeting places we have joined: channel -> its one-time secret.
    // Kept so a peer arriving on one is proved by that secret, exactly as a
    // paired peer is proved by a pair secret.
    let mut brokered: HashMap<String, String> = HashMap::new();
    // How long an offer may wait for its sender to prove itself before we decide
    // anyway. Bounded on purpose: waiting forever for a hello that never comes
    // would turn a clean decline into the 45s timeout it replaced.
    let fleet_offer_grace = Duration::from_secs(
        std::env::var("FILAMENT_FLEET_OFFER_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8),
    );
    let mut fleet_greeted: std::collections::HashSet<String> = Default::default();

    // Daemon-managed mount state: the daemon holds the sshfs child processes and
    // monitors their health centrally instead of spawning per-mount threads.
    let mut daemon_mounts = DaemonMounts {
        entries: HashMap::new(),
        children: HashMap::new(),
    };
    let mut last_mount_check = Instant::now();

    // WARM-HOLD: periodic check for warm peers that need connections
    let mut last_warm_hold_tick = Instant::now();

    // P2 (GAP-2): outer reconnect / re-announce loop state for the long-lived
    // acceptor. `reconnect(false)` means a severed signaling TCP leaves the
    // socket dead with NO further events, the acceptor zombies and the sender
    // can't rediscover it (the documented `no peer connected` failure that
    // up_supervisor.sh patched from outside the binary). We close it IN-CORE:
    //  - `last_signaling`  : monotonic time of the last inbound signaling event;
    //                        any inbound Ev that originates from the socket bumps
    //                        it (welcome/synced/peer-*/signal/known-peer/...).
    //  - silence watchdog  : if it goes silent past `signaling_silence_ms` (and
    //                        a forced `sync` emit doesn't restore it), the link
    //                        is dead, re-dial. This is the AUTHORITATIVE trigger
    //                        because a hard TCP sever fires no close callback.
    //  - Ev::SignalingDown : the socket.io close/error fast-path accelerant.
    // Only the daemon acceptor self-heals (`signaling_self_heal`); the one-shot
    // recv/send paths re-invoke fresh, so they keep failing fast (unchanged).
    // FILAMENT_TEST_NO_SIGNALING_RECONNECT reverts to the OLD no-outer-loop path
    // so the signaling-drop gate's A/B baseline can prove the acceptor ZOMBIES
    // without the fix (the detector/loop is load-bearing, not incidental).
    let signaling_self_heal = daemon && !test_hooks::no_signaling_reconnect();
    let mut last_signaling = Instant::now();
    let mut signaling_down_since: Option<Instant> = None;
    let mut reconnect_attempt: u32 = 0;
    let mut last_reconnect_try = Instant::now();
    let mut probed_silence = false; // fired one forced sync before declaring down
    let mut last_watchdog = Instant::now();
    // Link self-heal cadence (the multi-minute-outage fix, #3). A transport that
    // died past the QUIC idle timeout lingers in `links` as a zombie and SUPPRESSES
    // the KnownPeer re-dial (start_direct early-returns when a link exists), so the
    // overlay never recovers. We DROP dead links here (so the next KnownPeer
    // re-push re-establishes, single-driver + glare-safe = the model's proven
    // disconnect->recover) but do NOT re-dial ourselves - a timer-based re-dial on
    // BOTH ends caused a supersede storm. The L3 route is intentionally KEPT
    // (continuity), so the re-establish's add_peer swaps the transport under the
    // same overlay IP and the session resumes.
    let mut last_link_health = Instant::now();
    // Periodic liveness observation: refreshes lastSeen for devices with a
    // live link, independent of traffic. Without this an idle-but-connected
    // device would decay against its offline budget and be reaped while alive.
    let mut last_liveness_observe = Instant::now();
    // Periodic sweep: marks lapsed delegated records (deadline passed, no
    // observation revived them). State-only; the gate already denies past the
    // deadline, the sweep is what makes LAPSED visible in `devices`.
    let mut last_sweep = Instant::now();
    let mut last_renewal_check = Instant::now();
    let mut last_route_reconcile = Instant::now();
    let mut last_wg_check = Instant::now();
    // Owner-only roster push: mint + push the mesh roster on membership change,
    // validity refresh, or a newly-established link.
    let mut last_roster_push = Instant::now();

    // systemd Type=notify: announce readiness once the serving loop is about to
    // run, then ping the watchdog below. No-op when not run under systemd.
    if daemon {
        sdnotify::ready();
        sdnotify::status("up - serving");
    }

    // Restore mounts that were marked with auto_restore.
    if let Err(e) = mount::restore_mounts(server, relay).await {
        crate::ui::say(&format!("warning: failed to restore mounts: {e}"));
    }

    loop {
        // systemd liveness watchdog: ping on a throttle (well under WatchdogSec).
        // If this loop WEDGES on an await, the pings stop and systemd restarts us
        // - the backstop for the stall that also freezes the reconnect code.
        if daemon && last_watchdog.elapsed() >= Duration::from_secs(5) {
            sdnotify::watchdog();
            last_watchdog = Instant::now();
        }
        // Shutdown-hang repro hook: once links are live, freeze the event loop
        // forever, faithfully simulating a peer transport whose inline write
        // never returns. The graceful Ev::Interrupted can no longer be processed;
        // only the signal-owned force-exit watchdog can still terminate us. No-op
        // unless FILAMENT_TEST_WEDGE_LOOP is set (test-hooks builds only).
        if test_hooks::wedge_loop_on_shutdown() && !conn.links.is_empty() {
            std::future::pending::<()>().await;
        }
        let ev = tokio::select! {
            biased;
            // Warm-link reuse request from a sibling process. Handle it inline
            // (we own `conn`/`l2_muxes` here), then fall through like a tick. For
            // a non-daemon this branch pends forever (ctl_tx held, serve unspawned).
            req = ctl_rx.recv() => {
                if let Some(req) = req {
                    // Bootstrap defers its reply (awaits the peer's ack via this
                    // loop), so it can't go through the inline handle_warm_req; it
                    // stashes the socket in pending_bootstrap instead.
                    #[cfg(unix)]
                    {
                        // `filament set` live-reconfigure: re-read the changed key
                        // into this loop's live state, then report whether it took
                        // without a restart. Handled here (we own dir/policy/sess).
                        if let ctl::ReqKind::Reconfigure { key } = &req.kind {
                            let key = key.clone();
                            let live = apply_reconfigure(
                                &key, &mut dir, &mut shell_policy, &mut shell_user,
                                l2_enabled, &mut sess, &sio, &my_uid,
                            ).await;
                            req.reply(&json!({ "ok": true, "live": live })).await;
                        } else if matches!(&req.kind, ctl::ReqKind::ReloadExpose) {
                            // `filament expose`/`unexpose`: reconcile overlay
                            // listeners from expose.json. live:true only if L3 is up.
                            let (live, count): (bool, usize) = {
                                #[cfg(l3)]
                                {
                                    match exposer.as_ref() {
                                        Some(ex) => (true, ex.reconcile().await),
                                        None => (false, 0),
                                    }
                                }
                                #[cfg(not(l3))]
                                {
                                    (false, 0)
                                }
                            };
                            req.reply(&json!({ "ok": true, "live": live, "count": count })).await;
                        } else if matches!(&req.kind, ctl::ReqKind::Reload) {
                            // `filament update` reload: only safe when a supervisor
                            // will bring us back (systemd sets INVOCATION_ID). Reply
                            // FIRST (the shutdown closes the ctl socket), then take the
                            // SAME graceful path SIGTERM does - which cleanly closes the
                            // QUIC links so peers re-establish and L3 recovers - by
                            // raising SIGTERM on ourselves. systemd's Restart=always
                            // then starts the new binary with fresh ambient caps: no
                            // manual restart, no sudo. Unsupervised, we decline (exiting
                            // would just leave the node down).
                            let supervised = std::env::var("INVOCATION_ID").is_ok();
                            req.reply(&json!({ "ok": true, "reloading": supervised })).await;
                            if supervised {
                                ui::say("filament: reloading onto the updated binary (graceful restart)");
                                #[cfg(unix)]
                                unsafe { libc::raise(libc::SIGTERM); }
                            }
                        } else if matches!(&req.kind, ctl::ReqKind::Dial { .. }) {
                            // Overlay dial (proxy `.mesh` fallback): resolve the peer
                            // to its VERIFIED overlay address ourselves, dial it over
                            // L3, and bridge the ctl socket to it. Spawned so the
                            // long-lived splice never blocks the event loop.
                            #[cfg(l3)]
                            if let ctl::ReqKind::Dial { peer, port } = &req.kind {
                                let (peer, port) = (peer.clone(), *port);
                                match l3.as_ref() {
                                    Some(m) => {
                                        let m = m.clone();
                                        tokio::spawn(async move {
                                            let Some(addr) = m.addr_of(&peer).await else {
                                                req.reject("unknown overlay peer").await;
                                                return;
                                            };
                                            match m.dial(addr, port).await {
                                                Ok(mut stream) => {
                                                    let mut sock = req.accept().await;
                                                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
                                                }
                                                Err(e) => req.reject(&format!("overlay dial failed: {e}")).await,
                                            }
                                        });
                                    }
                                    None => req.reject("L3 overlay is not up").await,
                                }
                            }
                            #[cfg(not(l3))]
                            req.reject("L3 overlay not supported on this build").await;
                        } else if matches!(&req.kind, ctl::ReqKind::Bootstrap { .. }) {
                            handle_warm_bootstrap(&conn, &mut pending_bootstrap, req).await;
                        } else if matches!(&req.kind, ctl::ReqKind::Mount { .. }) {
                            handle_mount(req, &server, relay, &mut daemon_mounts, &mut last_mount_check).await;
                        } else if matches!(&req.kind, ctl::ReqKind::Unmount { .. }) {
                            handle_unmount(req, &mut daemon_mounts).await;
                        } else if matches!(&req.kind, ctl::ReqKind::ListMounts) {
                            handle_list_mounts(req, &daemon_mounts).await;
                        } else if matches!(&req.kind, ctl::ReqKind::MountHealth { .. }) {
                            handle_mount_health(req, &daemon_mounts).await;
                        } else if matches!(&req.kind, ctl::ReqKind::CapStatus) {
                            let counts = crate::capability::cap_shadow_counts();
                            let action_counts = crate::capability::cap_action_counts();
                            req.reply(&json!({
                                "ok": true,
                                "counts": {
                                    "la_authorized": counts.la_authorized,
                                    "la_denied": counts.la_denied,
                                    "la_no_header": counts.la_no_header,
                                    "ld_authorized": counts.ld_authorized,
                                    "ld_denied": counts.ld_denied,
                                    "ld_no_header": counts.ld_no_header,
                                    "ceiling_denied": counts.ceiling_denied,
                                },
                                "by_action": action_counts,
                                "flip_ready": counts.flip_ready(),
                                "summary": counts.summary(),
                                // #244: the LIVE shell posture. `revoke <dev> shell`
                                // reads this so it can say when the shell it just
                                // revoked is still being handed out by the policy.
                                "shell_policy": shell_policy.label(),
                                "shell_auto": shell_policy.auto_names(),
                            })).await;
                        } else if matches!(&req.kind, ctl::ReqKind::ListWarm) {
                            handle_list_warm(&conn, req).await;
                        } else if let ctl::ReqKind::FleetRendezvous { name } =
                            req.kind.clone()
                        {
                            // Broker a PRIVATE meeting place for a one-shot.
                            //
                            // The reliability problem this solves: a one-shot
                            // `send` joins the fleet channel, where every sibling
                            // is, and has to work out which of them is the target
                            // while they all answer. The daemon does not have that
                            // problem, because it already holds a
                            // certificate-verified link to the peer. So it mints a
                            // single-use secret, hands it over THAT link, and both
                            // ends meet on channel_of(secret) where exactly two
                            // parties exist.
                            //
                            // The secret doubles as the proof, which is why this
                            // reuses the most-tested path in the product rather
                            // than adding one: `send --to` already knows how to
                            // meet a known device on a shared secret. Its
                            // authenticity is inherited from the link it travelled
                            // over, which was verified by certificate.
                            match warm_link_for(&conn, &name) {
                                Some((pid, t)) => {
                                    let secret = fresh_secret();
                                    let sent = t
                                        .send_control(&json!({
                                            "type": "fleet-rendezvous",
                                            "secret": secret,
                                        }))
                                        .await
                                        .is_ok();
                                    if sent {
                                        ui::debug(&format!(
                                            "fleet-rendezvous: brokered for '{name}' over pid={pid}"
                                        ));
                                        req.reply(&json!({ "ok": true, "secret": secret })).await;
                                    } else {
                                        req.reject("could not reach that peer over the warm link").await;
                                    }
                                }
                                None => {
                                    req.reject(&format!("no verified link to '{name}'")).await;
                                }
                            }
                        } else if matches!(&req.kind, ctl::ReqKind::ListPending) {
                            let mut requests = load_requests();
                            expire_requests(&mut requests);
                            req.reply(&json!({
                                "ok": true,
                                "requests": requests,
                            })).await;
                        } else if let ctl::ReqKind::ApproveRequest { id, allow, expires } = &req.kind {
                            let id = *id;
                            let allow = allow.clone();
                            let expires = *expires;
                            let mut requests = load_requests();
                            expire_requests(&mut requests);
                            if let Some(r) = requests.iter_mut().find(|r| r.id == id && r.status == "pending") {
                                let peer = r.peer.clone();
                                let cap = r.capability.clone();
                                if cap != allow {
                                    req.reject(&format!("request {id} is for '{cap}', not '{allow}'")).await;
                                } else if !crate::capability::grant_active(expires, crate::capability::now_secs()) {
                                    req.reject("grant expiry must be in the future").await;
                                } else if let Err(e) = device_set_cap(&peer, &cap, true, Some(expires)) {
                                    req.reject(&format!("grant failed: {e}")).await;
                                } else if let Err(e) = issue_signed_bounded_grant(&peer, &cap, expires).and_then(|signed| {
                                    if signed { mark_bounded_cap_source(&peer, &cap, "signed") } else { Ok(()) }
                                }) {
                                    req.reject(&format!("signed grant failed: {e}")).await;
                                } else {
                                    r.status = "approved".to_string();
                                    r.granted_at = Some(crate::capability::now_secs());
                                    save_requests(&requests);
                                    req.reply(&json!({ "ok": true, "id": id, "peer": peer, "capability": cap, "expires": expires })).await;
                                }
                            } else {
                                req.reject(&format!("request {id} not found or not pending")).await;
                            }
                        } else if let ctl::ReqKind::DenyRequest { id } = &req.kind {
                            let id = *id;
                            let mut requests = load_requests();
                            expire_requests(&mut requests);
                            if let Some(r) = requests.iter_mut().find(|r| r.id == id && r.status == "pending") {
                                r.status = "denied".to_string();
                                save_requests(&requests);
                                req.reply(&json!({ "ok": true, "id": id })).await;
                            } else {
                                req.reject(&format!("request {id} not found or not pending")).await;
                            }
                        } else {
                            // Auto-warm: feed LRU for pty sessions (bounded, no leak).
                            if let ctl::ReqKind::Pty { peer, .. } = &req.kind {
                                conn.note_warm_use(peer);
                            }
                            handle_warm_req(&conn, &mut l2_muxes, &warm_ptys, &tx, req).await;
                        }
                    }
                    #[cfg(not(unix))]
                    handle_warm_req(&conn, &mut l2_muxes, &warm_ptys, &tx, req).await;
                }
                None
            }
            res = tokio::time::timeout(
                Duration::from_secs(2),
                next_ev(&mut rx, &conn, !st.pending.is_empty()),
            ) => match res {
                Ok(res) => res?,
                Err(_) => None, // 2s tick, run the fallback quiet-check below
            },
        };

        // C30: converge session state (no-op unless diverged/stale/unconfirmed).
        sess.tick(&sio).await;

        // L1-a ephemeral PAKE progression (recv code path), PER CANDIDATE PEER.
        // For each candidate's ceremony whose link is up: send our SPAKE2 element,
        // then (once K + both DTLS fingerprints exist) the key-confirmation MAC.
        // Each ceremony is independent, so a decoy peer that never replies just
        // sits until ITS budget expires (dropped below), never blocking the real
        // sender's ceremony. The agreed secret is DISCARDED after auth, never
        // stored. Once one peer authenticates (`recv_pake_done`) we stop driving
        // candidates: the sender is settled.
        if recv_code_path && !recv_pake_done {
            let pids: Vec<String> = st.recv_cers.keys().cloned().collect();
            for pid in pids {
                let send_msg = st
                    .recv_cers
                    .get_mut(&pid)
                    .and_then(|c| c.take_msg_payload());
                if let Some(data) = send_msg {
                    sio.emit("signal", json!({ "to": pid, "data": data }))
                        .await
                        .ok();
                }
                let has_k = st.recv_cers.get(&pid).map(|c| c.has_k()).unwrap_or(false);
                if has_k {
                    let fps = match conn.link(&pid) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    if let Some((my_fp, their_fp)) = fps {
                        let conf = st
                            .recv_cers
                            .get_mut(&pid)
                            .and_then(|c| c.take_confirm_payload(&my_fp, &their_fp));
                        if let Some(data) = conf {
                            sio.emit("signal", json!({ "to": pid, "data": data }))
                                .await
                                .ok();
                        }
                    }
                }
            }
        }
        // Per-peer budgets: a candidate whose ceremony never completes within its
        // own budget is dropped INDIVIDUALLY (an unrelated decoy, or an old peer
        // that won't run v2). Dropping it never bails the receive; the real sender
        // keeps its own live budget. Only relevant before someone authenticates.
        if recv_code_path && !recv_pake_done {
            let now = Instant::now();
            let expired: Vec<String> = st
                .recv_deadlines
                .iter()
                .filter(|(_, dl)| now > **dl)
                .map(|(pid, _)| pid.clone())
                .collect();
            for pid in expired {
                st.recv_deadlines.remove(&pid);
                st.recv_cers.remove(&pid);
                st.recv_pending_offers.remove(&pid);
                ui::debug(&format!(
                    "recv: candidate {pid} did not authenticate in budget, dropped"
                ));
            }
        }
        // Overall deadline: the backstop. Once we are matched into the sender's
        // room a candidate channel arms this; if NO peer authenticates within it,
        // fail the whole `recv` loudly (a genuinely absent / old sender, mirroring
        // the previous single-budget intent and FILAMENT_PAIR_GRACE_SECS) rather
        // than hanging forever.
        if recv_code_path && !recv_pake_done {
            if let Some(dl) = recv_pake_overall_deadline {
                if Instant::now() > dl {
                    bail!(
                        "the other device uses an older version and can't send securely over a code. Update it (or this CLI) so the transfer runs the encrypted handshake. Nothing was received."
                    );
                }
            }
        }

        // P2 (GAP-2): the OUTER RECONNECT / RE-ANNOUNCE loop for the long-lived
        // acceptor. Runs only in the daemon path; the one-shot recv/send paths
        // re-invoke fresh on failure and so never need it.
        if signaling_self_heal {
            // (1) Liveness accounting. Any inbound signaling event proves the
            // socket is alive; a successful `sync` ack (Ev::Synced) is the
            // strongest signal (the server answered). The fast-path close/error
            // callback marks the link down immediately.
            let mut saw_down = false;
            match &ev {
                Some(Ev::SignalingDown(_)) => saw_down = true,
                Some(
                    Ev::Welcome(_)
                    | Ev::Synced(_)
                    | Ev::SignalingAlive
                    | Ev::PeerJoined(_)
                    | Ev::PeerLeft(_)
                    | Ev::Signal(_)
                    | Ev::KnownPeer(_)
                    | Ev::KnownPeerLeft(_)
                    | Ev::PairMatched(_)
                    | Ev::PairOk(_)
                    | Ev::PairCode(_)
                    | Ev::PairUsed(_)
                    | Ev::PairError(_),
                ) => {
                    last_signaling = Instant::now();
                    signaling_down_since = None;
                    probed_silence = false;
                    reconnect_attempt = 0;
                }
                _ => {}
            }

            // (2) Silence watchdog, the AUTHORITATIVE trigger. A hard TCP sever
            // fires no close callback, so we watch the inbound gap. Once it
            // exceeds the threshold, fire ONE forced `sync` (the heartbeat); if
            // the socket is alive the server's `synced` ack lands within a tick
            // and resets the gap. If a second threshold passes with still no
            // event, the socket is dead, declare it down.
            let silence = net::signaling_silence_ms();
            let silent_ms = last_signaling.elapsed().as_millis() as u64;
            if signaling_down_since.is_none() {
                if saw_down {
                    signaling_down_since = Some(Instant::now());
                    last_reconnect_try = Instant::now() - Duration::from_secs(60); // re-dial now
                    // Visible (not just debug): a node dropping off signaling was
                    // previously silent until it bit someone. Surface it + reflect
                    // it in `systemctl status` so it's diagnosable at a glance.
                    ui::say(&ui::paint(
                        ui::Tone::Warn,
                        "signaling link closed, reconnecting...",
                    ));
                    sdnotify::status("signaling down - reconnecting");
                } else if silent_ms >= silence {
                    if !probed_silence {
                        // Heartbeat probe: an ACK'd `sync` round-trip, the only
                        // liveness signal that works for a room-less idle
                        // acceptor. `sess.tick()` can't serve here: it returns
                        // early when there is no room (the `up` case) AND when
                        // the session is already confirmed-fresh, so on a quiet
                        // link it emitted nothing and the watchdog falsely
                        // reconnected every ~30 s, churning presence. The server
                        // acks `sync` unconditionally; the ack wakes the loop as
                        // Ev::SignalingAlive, which resets the gap below.
                        probed_silence = true;
                        net::heartbeat(&sio, sess.heartbeat_payload(), tx.clone()).await;
                    } else if silent_ms >= silence.saturating_mul(2) {
                        signaling_down_since = Some(Instant::now());
                        last_reconnect_try = Instant::now() - Duration::from_secs(60);
                        // Visible: a silent (half-open) signaling link is the exact
                        // way a node falls off presence without anyone noticing.
                        ui::say(&ui::paint(
                            ui::Tone::Warn,
                            &format!("signaling silent for {silent_ms}ms, reconnecting..."),
                        ));
                        sdnotify::status("signaling silent - reconnecting");
                    }
                }
            }

            // (3) Re-dial with backoff + jitter. Idempotent: a fresh `welcome`
            // re-asserts room + channel subscriptions through the C30 session
            // (sess.invalidate forces it next tick). Live DATA links are NOT torn
            // down, they ride independent WebRTC/QUIC transports and keep
            // flowing across the cosmetic signaling reconnect (the #28 contract).
            if let Some(down_at) = signaling_down_since {
                // backoff: 0.5s, 1s, 2s, 4s ... capped at 8s, +/-25% jitter.
                let base = 500u64
                    .saturating_mul(1 << reconnect_attempt.min(4))
                    .min(8_000);
                let jitter = (down_at.elapsed().as_nanos() as u64 % (base / 2 + 1)) as i64
                    - (base as i64 / 4);
                let backoff = Duration::from_millis((base as i64 + jitter).max(100) as u64);
                if last_reconnect_try.elapsed() >= backoff {
                    last_reconnect_try = Instant::now();
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    let _ = sio.disconnect().await; // drop the dead client (no-op if already gone)
                    match net::reconnect_signaling(server, tx.clone()).await {
                        Ok(new_sio) => {
                            sio = new_sio;
                            conn.sio = sio.clone();
                            // C30: a fresh sid voids everything the server held,
                            // re-assert room + channels on the next tick. Re-fire
                            // the fast-path join/subscribe immediately too.
                            sess.invalidate();
                            if let Some(room) = sess.room.clone() {
                                sess.emit(
                                    &sio,
                                    "join",
                                    json!({ "room": room, "name": display_name(), "uid": my_uid }),
                                )
                                .await;
                            }
                            if !sess.channels.is_empty() {
                                let chans = sess.channels.clone();
                                sess.emit(&sio, "subscribe", json!({ "channels": chans }))
                                    .await;
                            }
                            sess.tick(&sio).await;
                            // optimistic: a clean connect proves reachability; let
                            // the welcome confirm it (which resets the counters).
                            last_signaling = Instant::now();
                            signaling_down_since = None;
                            probed_silence = false;
                            // Visible: pairs with the "reconnecting..." line so the
                            // recovery is observable end to end.
                            ui::say(&ui::paint(
                                ui::Tone::Ok,
                                "signaling reconnected, re-announcing presence",
                            ));
                            sdnotify::status("up - serving");
                        }
                        Err(e) => {
                            // DEBUG, resilience internal (signaling reconnect retry).
                            ui::debug(&ui::paint(
                                ui::Tone::Dim,
                                &format!(
                                    "  signaling reconnect failed ({e}), retrying with backoff"
                                ),
                            ));
                        }
                    }
                }
            }
        }

        // Arm-gate: toggle enrollment-channel subscription EVERY loop iteration
        // based on the armed set. Channel-based (not room) because the server
        // supports 1 room/socket. This MUST run at loop top-level, not nested in
        // the signaling-reconnect Ok arm: a stable daemon (signaling never down)
        // would otherwise never subscribe and no ephemeral device could enroll.
        if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
            let ek = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
            let armed = crate::armed::is_armed();
            let subscribed = sess.channels.contains(&ek);
            if armed && !subscribed {
                sess.channels.push(ek.clone());
                let _ = sio.emit("subscribe", json!({ "channels": [ek] })).await;
            } else if !armed && subscribed {
                sess.channels.retain(|c| c != &ek);
                let _ = sio
                    .emit("channel-goodbye", json!({ "channels": [ek] }))
                    .await;
            }
        }

        // Link self-heal (#3): drop links whose transport has DIED so the KnownPeer
        // re-dial (re-pushed on signaling reconnect + periodic sync) can rebuild
        // them. Same action as the on-demand DropLink handler, just proactive; the
        // L3 route is intentionally NOT retracted (continuity), so the re-establish's
        // add_peer swaps the fresh transport under the same overlay IP. We do NOT
        // re-dial here on purpose (single-driver = the model's proven, churn-free
        // recovery; a both-ends timer re-dial storms).
        if daemon && last_link_health.elapsed() >= Duration::from_secs(8) {
            last_link_health = Instant::now();
            let dead: Vec<String> = conn
                .links
                .iter()
                .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| !t.is_alive()))
                .map(|(pid, _)| pid.clone())
                .collect();
            for pid in dead {
                ui::debug(&format!(
                    "filament: link to '{pid}' died, dropping so it can re-connect"
                ));
                conn.drop_link(&pid);
                l2_muxes.remove(&pid);
            }
        }

        // LIVENESS OBSERVATION: a device with a live link is alive regardless of
        // traffic. Refresh lastSeen periodically for linked devices so an idle
        // but connected device never decays against its offline budget. This is
        // a PERIODIC OBSERVATION of link-up state, deliberately not an event
        // fired by message receipt (a traffic-driven refresh would reap healthy
        // quiet devices exactly the way xats reaped chief-ux).
        if daemon && last_liveness_observe.elapsed() >= Duration::from_secs(8) {
            last_liveness_observe = Instant::now();
            let live: Vec<String> = conn
                .links
                .iter()
                .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| t.is_alive()))
                .map(|(_, l)| l.shown().to_string())
                .collect();
            for who in live {
                devices_touch(&who, None, None);
            }
        }

        // SWEEP: mark lapsed delegated records whose effective deadline has
        // passed and which no observation revived. Runs every 30s; keeps the
        // record as evidence (option b, decided deliberately).
        if daemon && last_sweep.elapsed() >= Duration::from_secs(30) {
            last_sweep = Instant::now();
            let lapsed = devices_sweep_lapsed(crate::identity::now_secs());
            if lapsed > 0 {
                ui::say(&format!(
                    "{} {lapsed} device(s) lapsed (offline past their budget)",
                    ui::paint(ui::Tone::Warn, ui::glyph_warn())
                ));
            }
        }

        // WIREGUARD RECONCILE. On a timer, and deliberately NOT on an event.
        //
        // The first version hooked the moment a peer joined the L3 plane, which
        // is when its ANNOUNCE arrives. A link that starts relayed and upgrades
        // to direct upgrades AFTER that, so the hook saw the relay transport and
        // declined forever: the rig showed "DIRECT-CONNECT ok (route:
        // direct-quic)" in the same log as "WireGuard skipped". Reconciling on a
        // tick is order-independent, picks up a link that goes direct later, and
        // is idempotent, which an event hook can only approximate.
        //
        // Each attempt is spawned rather than awaited: the two ends rendezvous
        // on a QUIC bi-stream, so whichever side ticks first waits for the
        // other, and blocking the daemon loop on that would stall everything.
        if daemon
            && last_wg_check.elapsed() >= Duration::from_secs(10)
            && crate::settings::get_str("wireguard", None)
                .map(|v| v == "on" || v == "true")
                .unwrap_or(false)
        {
            last_wg_check = Instant::now();
            if let Some(l3) = l3.as_ref() {
                if crate::wg::usable() {
                    let ours = l3.my_addr().map(|a| a.to_string()).unwrap_or_default();
                    for (who, addr, t) in l3.peers_with_transport().await {
                        // Direct links only: WireGuard needs a real UDP endpoint
                        // to send to, and a relay link has none to name.
                        let Some(sa) = t.remote_addr() else { continue };
                        if t.quic_connection().is_none() {
                            continue;
                        }
                        if !crate::wg::claim_attempt(&addr.to_string()) {
                            continue; // already announced to this peer
                        }
                        let (pubkey, port) = match crate::wg::local_offer() {
                            Ok(v) => v,
                            Err(e) => {
                                crate::wg::release_attempt(&addr.to_string());
                                ui::debug(&format!("  wg: cannot bring up the interface ({e})"));
                                continue;
                            }
                        };
                        let _ = sa;
                        // Straight down the peer's own transport: the control
                        // channel every other filament message uses.
                        let _ = t
                            .send_control(&json!({
                                "type": "wg-key",
                                "pubkey": pubkey,
                                "port": port,
                            }))
                            .await;
                        ui::debug(&format!("  wg: announced our key to {who}"));
                    }
                }
            }
        }

        // ROUTE RECONCILE: re-evaluate installed routes on a timer, not only on
        // an inbound announce. The case that matters most is a peer going
        // SILENT, and a silent peer sends no announce, so an announce-driven
        // reconciler is deaf to exactly the event it most needs to hear. For an
        // exit node that gap is the difference between a stale entry and a
        // machine holding a default route into a tunnel nobody is carrying.
        if daemon && last_route_reconcile.elapsed() >= Duration::from_secs(15) {
            last_route_reconcile = Instant::now();
            if let Some(l3) = l3.as_ref() {
                l3.reconcile_routes().await;
            }
        }

        // RENEWAL: ask a primary to re-sign this device's certificate before it
        // expires. ON A TIMER, not only when a link comes up: a device that
        // stays connected for its whole certificate lifetime would otherwise
        // never re-check and would expire while online, which is exactly the
        // silent death renewal exists to prevent. Found by running it, not by
        // reading it: the link-up trigger alone left a live device dying.
        //
        // Cheap: `maybe_request_cert_renewal` returns immediately unless this
        // device is a fleet member whose certificate is in its last third, so
        // the common case is a few comparisons. It asks every live peer because
        // only a primary can answer and we do not know which one that is.
        if daemon && last_renewal_check.elapsed() >= Duration::from_secs(30) {
            last_renewal_check = Instant::now();
            let live: Vec<String> = conn
                .links
                .iter()
                .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| t.is_alive()))
                .map(|(pid, _)| pid.clone())
                .collect();
            for pid in live {
                maybe_request_cert_renewal(&conn, &pid).await;
            }
        }

        // ROSTER (v1, owner-only): push the mesh roster over live links on a
        // membership change, a validity refresh, or a newly-established link.
        // Runs faster than the sweep so a new link gets the roster promptly.
        if daemon && last_roster_push.elapsed() >= Duration::from_secs(5) {
            last_roster_push = Instant::now();
            conn.roster_maintenance().await;
        }

        // Daemon-managed mount health check: periodically check all tracked
        // mounts and remove dead/stale entries. Runs every 30s, daemon-only.
        if daemon && last_mount_check.elapsed() >= Duration::from_secs(30) {
            last_mount_check = Instant::now();
            let dead_locals: Vec<String> = daemon_mounts
                .entries
                .iter()
                .filter_map(|(local, _entry)| {
                    let is_alive = mount::is_mount_point(local);
                    let path_exists = Path::new(local).exists();
                    if !path_exists {
                        Some(local.clone())
                    } else if !is_alive {
                        Some(local.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for local in dead_locals {
                if let Some(entry) = daemon_mounts.entries.remove(&local) {
                    ui::say(&format!(
                        "mount {local} is gone, removing from daemon tracking (was {}:{})",
                        entry.peer, entry.remote
                    ));
                    // Kill the child process if still tracked.
                    if let Some(mut child) = daemon_mounts.children.remove(&local) {
                        let _ = child.kill().await;
                    }
                    let _ = mount::remove_mount(&local);
                }
            }
        }

        // WARM-HOLD: periodically check for warm peers that need connections.
        // This keeps recently-used and explicitly configured peers connected
        // so `filament reach`/`ssh` is instant. Runs every 10s, daemon-only.
        if daemon && last_warm_hold_tick.elapsed() >= Duration::from_secs(10) {
            last_warm_hold_tick = Instant::now();
            // Warm-all is the DEFAULT (auto-warm setting, opt-out). L3 forces it on:
            // the overlay routes over these links, opting out must not break L3.
            let auto_warm = l3.is_some() || settings::get_bool("auto-warm", None);
            let _ = conn.warm_hold_tick(auto_warm).await;
        }

        // C12 live-pairing: pick up devices paired AFTER we started (a separate
        // `filament pair` writes them into the shared store atomically). Re-read
        // every ~2s, subscribe to any channel we don't already watch, and feed
        // them into `devices` so the KnownPeer handler recognizes them. We never
        // re-subscribe existing channels or touch live links. Daemon-only: a
        // one-shot `recv`/`send` has a fixed roster for its short lifetime.
        if daemon && last_devices_scan.elapsed() >= Duration::from_secs(2) {
            last_devices_scan = Instant::now();
            let mut new_chans: Vec<String> = Vec::new();
            for (n, s) in devices_load() {
                let ch = channel_of(&s);
                if known_channels.insert(ch.clone()) {
                    ui::say(&format!("new device '{n}' paired, now reachable"));
                    devices.push((n, s));
                    new_chans.push(ch);
                }
            }
            if !new_chans.is_empty() {
                // Fast-path emit now; the session digest carries the durable
                // subscription so a dropped emit self-repairs on the next tick.
                for ch in &new_chans {
                    if !sess.channels.contains(ch) {
                        sess.channels.push(ch.clone());
                    }
                }
                sess.emit(&sio, "subscribe", json!({ "channels": new_chans }))
                    .await;
            }
        }
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // Grace expired: decide these offers normally rather than hold them.
        // Re-injected with `__fleet_waited` so the deferral above does not catch
        // them a second time and park them forever.
        {
            let now = Instant::now();
            let due: Vec<_> = fleet_deferred_offers
                .iter()
                .filter(|(_, _, dl)| now > *dl)
                .cloned()
                .collect();
            fleet_deferred_offers.retain(|(_, _, dl)| now <= *dl);
            for (p, mut ov, _) in due {
                ui::debug(&format!(
                    "fleet: offer from {p} waited out its grace unverified; deciding it"
                ));
                ov["__fleet_waited"] = serde_json::Value::Bool(true);
                let _ = tx.send(Ev::Control(p, ov));
            }
        }
        // Drop warm-bootstrap waiters whose peer never acked; the client's read
        // hits EOF and falls back to the cold establish.
        #[cfg(unix)]
        reap_warm_bootstraps(&mut pending_bootstrap);
        // rung-1: direct attempt timed out → fall back to WebRTC (unchanged).
        // Unlike the sender call above, this receiver-side fallback routes
        // through maybe_adopt, so its ESTABLISH caller is indistinguishable
        // from ordinary adoption. Correlate DIRECT-FALLBACK with the following
        // ADOPT for the same peer; that sequence is not sound if peers recover
        // concurrently, so caller attribution alone is insufficient here.
        for (pid, info, (n, sec)) in conn.expired_direct() {
            conn.maybe_adopt(&info, true).await.with_context(|| {
                format!("direct fallback adoption failed for peer {pid} on receive path")
            })?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
        }

        // C30 phase 3: state pings, each open link hears our transfer/away
        // truth every ~10s, so one-sided beliefs between PEERS can't persist.
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for (pid, l) in &conn.links {
                if let Some(t) = &l.transport {
                    let mut transfers = serde_json::Map::new();
                    for ((p0, _), inc) in &st.by_sid {
                        if p0 == pid {
                            transfers.insert(
                                inc.id.clone(),
                                json!(inc.received.load(Ordering::Relaxed)),
                            );
                        }
                    }
                    // BOUNDED: this runs inline in the event loop for EVERY link.
                    // A WebRTC data-channel write against a frozen / half-open peer
                    // can block (write_data_channel().await never returns), which
                    // would starve the whole loop, including the signal-driven
                    // Interrupted handler, the multi-link shutdown hang. The state
                    // ping is best-effort, so cap it and move on.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        t.send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": Value::Object(transfers),
                            "trusted": l.trusted,
                            "away": false,
                        })),
                    )
                    .await;
                }
            }
        }

        // G-k completion sweep (top-of-loop): see sweep_completed_streams.
        sweep_completed_streams(
            &mut st.by_sid,
            &conn,
            &dir,
            &output,
            to_stdout,
            daemon,
            &mut st.completed,
        )
        .await?;

        // Gate-18 Mode B: recompute the completion flag AFTER the sweep, every
        // tick (never sticky). When true, a stuck/lost link is DROPPED in
        // on_stuck instead of re-established, see Conn::recv_done. Refreshing it
        // here, where `completed`/`by_sid` were just settled, makes the gate-2/
        // gate-11c fence exact: a mid-transfer link (by_sid non-empty) sees
        // recv_done=false and reconnects unchanged.
        conn.recv_done =
            protocol::recv_transfer_done(st.completed, keep_open, st.by_sid.is_empty());
        // WARM-HOLD: when a transfer completes, mark the peer as warm so we
        // proactively reconnect if the link drops.
        if st.completed > 0 {
            let warm_peers: Vec<String> = st
                .by_sid
                .keys()
                .filter_map(|(pid, _)| conn.links.get(pid)?.verified_name.clone())
                .collect();
            for name in &warm_peers {
                conn.note_warm_use(name);
            }
        }
        if st.completed > 0 || !st.by_sid.is_empty() {
            st.ever_received = true; // a channel was up; Bug-5 wedge hint no longer applies
        }

        // P0 (GAP-1): bytes-moved STALL watchdog (RECEIVE side). The receiver is
        // the peer that visibly hangs at 0%: when an inbound transfer is in
        // flight (`by_sid` non-empty for a link) but no data byte has arrived
        // past the stall threshold, its transport's idle_ms() climbs. The
        // RECEIVER must also act so a direct-QUIC repair is SYMMETRIC, a fresh
        // authenticated QUIC connection needs both ends to re-dial. We emit
        // Ev::TransferStalled for each such link (liveness-gated), whose handler
        // re-arms this side's direct dial (rung c). The on-disk `.part` is kept,
        // so the resumed stream continues from the saved offset.
        {
            // Per-link: in_flight = this peer has an inbound file mid-transfer
            // (a by_sid entry) OR a stall episode is already open for it (the
            // .part was flushed to disk mid-repair, so by_sid is momentarily
            // empty, detect_stall keeps the episode alive until fresh progress).
            let all_pids: Vec<String> = conn.links.keys().cloned().collect();
            for pid in all_pids {
                let in_flight = st.by_sid.keys().any(|(p, _)| *p == pid);
                if let Some(idle) = conn.detect_stall(&pid, in_flight) {
                    let transport_dead = conn
                        .transport_of(&pid)
                        .map(|t| t.is_dead())
                        .unwrap_or(false);
                    if transport_dead || conn.link_alive(&pid).await {
                        let _ = tx.send(Ev::TransferStalled(pid, idle));
                    } else {
                        conn.note_progress(&pid);
                    }
                }
            }
        }

        // P5 (GAP-6): relay->direct upgrade prober (receive side). The `up` daemon
        // acceptor is the canonical long-lived session, so the prober defaults ON
        // here. Probe for a direct path while serving on relay; verify-before-
        // upgrade cuts over only on a confirmed-stable direct standby.
        conn.tick_upgrade_prober().await;

        // Gate-18 Mode B DETERMINISTIC repro hook: simulate the post-completion
        // FLAP that contention triggers in the wild (the sender's departure puts
        // the receiver's link into the C4 reconnect loop). Once everything is on
        // disk, force each surviving link to go stuck repeatedly, reset its
        // attempts (mirroring the real flap's attempts-reset, so MAX_ATTEMPTS
        // can never cap it) and re-inject Ev::Stuck. On the BASELINE (no fix)
        // on_stuck re-establishes → link persists → conn.links never empties →
        // hang to timeout (RC=124). WITH the fix on_stuck drops on recv_done →
        // links empties → no link to churn next tick → quiet-exit fires. Driven
        // at LOOP level (not inside on_stuck) so the A/B tests the fix, not
        // itself.
        if conn.recv_done && test_hooks::churn_after_complete() {
            let churn: Vec<(String, u32)> = conn
                .links
                .iter()
                .map(|(pid, l)| (pid.clone(), l.generation))
                .collect();
            for (pid, generation) in churn {
                if let Some(l) = conn.links.get_mut(&pid) {
                    l.attempts = 0; // mirror the real flap: cap never accumulates
                    // Tear the data channel down so on_stuck's is_connected()
                    // guard sees a dead link and the Stuck isn't swallowed.
                    if let Some(p) = &l.peer {
                        p.close().await;
                    }
                }
                let _ = conn.tx.send(Ev::Stuck(pid, generation));
            }
        }

        // #28 exit reconciliation: once everything is received and the only links
        // left are ones held open purely for their deferred-drop reap (their
        // sender's signaling left AFTER the transfer finished), there is nothing
        // in flight to protect, exit promptly instead of paying the full
        // FILAMENT_ADOPT_ACTIVE_MS deferral. Restores the pre-#28 prompt exit; an
        // in-progress reconnect keeps `by_sid` non-empty and so is unaffected.
        if st.completed > 0
            && !keep_open
            && st.by_sid.is_empty()
            && st.pending.is_empty()
            && !conn.links.is_empty()
            && conn.only_deferred_links()
        {
            ui::say(&format!(
                "done ({} file{}).",
                st.completed,
                if st.completed == 1 { "" } else { "s" }
            ));
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // Bug 2: the transfer is COMPLETE and the sender's link is fully GONE
        // (dropped via peer-left, or via the grace/Mode-B path when peer-left
        // was lost). With no live link and nothing left to fetch there is
        // nothing to wait for, exit at once instead of holding out the full
        // rejoin window (peer-left case) or the quiet-exit window (lost-peer-left
        // case). Fenced exactly like the exits above: by_sid empty + no pending
        // questions, so a mid-transfer reconnect (which keeps `by_sid`
        // non-empty) is untouched, and --keep-open still lingers by design.
        if st.completed > 0
            && !keep_open
            && st.by_sid.is_empty()
            && st.pending.is_empty()
            && conn.links.is_empty()
        {
            conn.rejoin.waiting_rejoin = None;
            ui::clear_sticky();
            ui::say(&format!(
                "done ({} file{}).",
                st.completed,
                if st.completed == 1 { "" } else { "s" }
            ));
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // G-k fallback: everything done, nobody attached, no questions
        // outstanding, if that holds quietly for the quiet-exit window (10s
        // default, FILAMENT_QUIET_EXIT_SECS overrides), the peer-left we were
        // counting on for a clean exit never arrived; exit anyway. C30 ph2:
        // ALSO satisfied when the server's digest says the room is empty and
        // no room-independent (channel) link remains, lingering dead links
        // can't block the exit when the server knows nobody's there.
        // A fleet link is room-INDEPENDENT, exactly like a pair-channel link, so
        // it must count here too. It can lack a pair secret (WebRTC fallback), and
        // without this a daemon holding only fleet links would read as "alone" and
        // take the quiet-exit path while peers are connected.
        let digest_says_alone = digest_alone
            && conn.links.keys().all(|pid| {
                conn.links
                    .get(pid)
                    .map(|l| l.expected_secret.is_none())
                    .unwrap_or(true)
                    && !fleet_pending.contains(pid)
                    && !fleet_verified.contains(pid)
            });
        // #28 Mode B: a dead link that keeps FLAPPING, on_stuck reconnect, or a
        // roster/session reconcile re-adopting the gone sender and re-arming
        // `expected_secret` so `digest_says_alone` never holds, must NOT block
        // this fallback once everything is received; `conn.links` may never
        // empty under churn (the RC=124 hang). Surgical: discriminate on link
        // HEALTH, not existence, a churning/reconnecting/dead link (never
        // `Ready`) does not block exit, but a healthy `Ready` link (e.g. a
        // bystander between two human-paced sends, gate 6) STILL does. So this is
        // a no-op for healthy peers, not a behaviour change, only a peer we've
        // lost contact with stops blocking. FILAMENT_TEST_DISABLE_MODEB_DROP
        // restores the old links-gated behaviour so gate 18b proves the A/B
        // (baseline hangs, fix exits) with one binary.
        let no_healthy_link = conn
            .links
            .values()
            .all(|l| !matches!(l.presence, Presence::Ready));
        let links_clear = if !test_hooks::disable_modeb_drop() {
            no_healthy_link
        } else {
            conn.links.is_empty() || digest_says_alone
        };
        if st.completed > 0
            && !keep_open
            && st.by_sid.is_empty()
            && st.pending.is_empty()
            && links_clear
        {
            match last_quiet {
                None => last_quiet = Some(Instant::now()),
                Some(since) if since.elapsed() > quiet_window => {
                    ui::say(&ui::paint(
                        ui::Tone::Dim,
                        "  (peer-left never arrived, exiting on quiet)",
                    ));
                    ui::say(&format!(
                        "done ({} file{}).",
                        st.completed,
                        if st.completed == 1 { "" } else { "s" }
                    ));
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
                Some(_) => {}
            }
        } else {
            last_quiet = None;
        }

        let Some(ev) = ev else { continue };

        // C23: questions from links that died (supersede/peer-left) are
        // moot, the sender re-offers on its new link. Purge them so a 'y'
        // can never accept a ghost (the duplicate-stream ENOENT crash).
        if !st.pending.is_empty() {
            let front_id = st.pending.front().map(|(_, v)| v["id"].clone());
            st.pending.retain(|(p, _)| conn.links.contains_key(p));
            if st.pending.front().map(|(_, v)| v["id"].clone()) != front_id {
                ui::clear_sticky();
                if let Some((qpid, qv)) = st.pending.front() {
                    let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                    {
                        let q = offer_question(
                            &s,
                            qv["name"].as_str().unwrap_or("file"),
                            qv["size"].as_u64().unwrap_or(0),
                            paired,
                        );
                        ui::say(&q); // permanent: a new question fronted (C25)
                        ui::sticky(&q);
                        st.question_shown = Instant::now();
                    }
                } else {
                    st.question_open
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        match ev {
            // A warm-reuse open found this held link black-holing new streams
            // (zombie: alive at QUIC, dead for data). Drop it so the proactive
            // re-connect forms a fresh, healthy held link and warm-reuse goes
            // back to instant. Live DATA links are untouched (each ssh/pty op
            // rides its own stream; the dropped link had no working stream).
            Ev::DropLink(pid) => {
                if conn.links.contains_key(&pid) {
                    ui::debug(&format!(
                        "filament: dropping zombie warm link to '{pid}' (black-holed a stream)"
                    ));
                    conn.drop_link(&pid);
                    l2_muxes.remove(&pid);
                    // CONTINUITY: do NOT retract the L3 route here. A dropped link
                    // is almost always followed by a repair (a fresh transport for
                    // the same peer), whose add_peer atomically swaps the route. If
                    // we retracted now, the overlay IP would be briefly unroutable
                    // and a live ssh/L3 session could reset across the repair. The
                    // stale route just drops datagrams (the inner TCP pauses) until
                    // the swap. The cached announce is dropped so the peer's next
                    // announce is treated fresh.
                    #[cfg(l3)]
                    l3_seen.remove(&pid);
                    // Fleet auto-mesh: forget this peer's verification too. A
                    // reconnect gets a NEW sid and must re-prove its certificate
                    // on the new link's binding, so carrying the old sid's verdict
                    // forward would be exactly the stale-trust bug the channel
                    // binding exists to prevent.
                    fleet_pending.remove(&pid);
                    fleet_verified.remove(&pid);
                    fleet_greeted.remove(&pid);
                    // Deferred offers die with the link that carried them. A new
                    // link must re-prove on a NEW binding, so replaying an offer
                    // buffered under the old one is precisely the stale-trust bug
                    // the channel binding exists to prevent.
                    fleet_deferred_offers.retain(|(p, _, _)| p != &pid);
                    // A new link gets a NEW challenge. Carrying the old nonce
                    // forward would let a message captured on the previous link
                    // verify on this one, which is the whole thing the binding
                    // exists to stop.
                    bind_ours.remove(&pid);
                    bind_theirs.remove(&pid);
                }
            }
            Ev::PairMatched(v) => {
                claim_in_flight = false;
                let room = v["room"].as_str().unwrap_or_default().to_string();
                ui::say(&format!(
                    "  {} code accepted, joining sender",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok())
                ));
                sess.room = Some(room.clone()); // C30: desire moves; session repairs if the join dies
                sess.touch();
                sess.emit(
                    &sio,
                    "join",
                    json!({ "room": room, "name": display_name(), "uid": my_uid }),
                )
                .await;
            }
            // C30: server confirmed our session digest. Phase 2: reconcile
            // the roster it carries, missed peer-joined/left self-correct.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    let channel_peers = roster.channel_peers;
                    let channel_present: std::collections::HashSet<String> = channel_peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    // Channel subscriptions are independent of room membership.
                    // Re-adopt missed known-peer pushes and reap known links that
                    // remain absent from two consecutive channel rosters.
                    for p in &channel_peers {
                        if is_self_uid(&conn.my_uid, p["uid"].as_str()) {
                            continue;
                        }
                        if let Some((name, secret)) = devices.iter().find(|(_, s)| {
                            channel_of(s) == p["channel"].as_str().unwrap_or_default()
                        }) {
                            let pid = p["id"].as_str().unwrap_or_default().to_string();
                            let (name, secret) = (name.clone(), secret.clone());
                            conn.start_direct(&pid, &name, &secret).await;
                            // Channel-digest recovery remains intentionally outside
                            // the room give-up suppression scope.
                            conn.maybe_adopt(p, true).await?;
                            if let Some(l) = conn.link_mut(&pid) {
                                l.expected_secret = Some((name, secret));
                            }
                        } else if let Ok(Some(uk)) =
                            crate::identity::UserKey::load(&crate::platform::PlatformKeyStore)
                        {
                            let enroll_channel =
                                crate::ephemeral::enroll_channel(&uk.public_key_bytes());
                            if p["channel"].as_str() == Some(enroll_channel.as_str()) {
                                conn.maybe_adopt(p, true).await?;
                            }
                        }
                    }
                    let mut channel_gone = Vec::new();
                    for (pid, link) in &conn.links {
                        let channel_link = link
                            .expected_secret
                            .as_ref()
                            .map(|(_, secret)| {
                                sess.channels.iter().any(|ch| ch == &channel_of(secret))
                            })
                            .unwrap_or(false);
                        if channel_link && !channel_present.contains(pid) {
                            let count = channel_digest_absent.entry(pid.clone()).or_insert(0);
                            *count += 1;
                            if *count >= 2 {
                                channel_gone.push(pid.clone());
                            }
                        } else {
                            channel_digest_absent.remove(pid);
                        }
                    }
                    for pid in channel_gone {
                        channel_digest_absent.remove(&pid);
                        let name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        conn.drop_link(&pid);
                        ui::say(&conn.roster(
                            &pid,
                            "○",
                            ui::Tone::Dim,
                            "left (channel digest reconcile), still listening",
                            &name,
                        ));
                    }
                    let peers = roster.peers;
                    digest_alone = peers.is_empty();
                    let present: std::collections::HashSet<String> = peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    // unknown in digest → a peer-joined we never received
                    for p in &peers {
                        let id = p["id"].as_str().unwrap_or_default();
                        if !id.is_empty() && !conn.links.contains_key(id) {
                            ui::debug(&ui::paint(
                                ui::Tone::Dim,
                                "  (digest: adopting a peer we never heard join)",
                            ));
                            conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                        }
                    }
                    // known room-sourced link absent ×2 → a peer-left we
                    // never received (channel-introduced links are exempt:
                    // room-independent by design)
                    let mut gone: Vec<String> = Vec::new();
                    for (pid, l) in &conn.links {
                        // "Channel-introduced" is the property that matters here,
                        // and `expected_secret.is_some()` was only ever a PROXY for
                        // it: true while every channel link carried a pair secret.
                        // A fleet link is channel-introduced and secretless, so the
                        // proxy reads it as room-sourced, finds it absent from the
                        // room roster, and reaps it after two digest ticks. Test the
                        // property directly instead of the proxy.
                        let channel_introduced = l.expected_secret.is_some()
                            || fleet_pending.contains(pid)
                            || fleet_verified.contains(pid);
                        if !channel_introduced && !present.contains(pid) {
                            let c = digest_absent.entry(pid.clone()).or_insert(0);
                            *c += 1;
                            if *c >= 2 {
                                gone.push(pid.clone());
                            }
                        } else {
                            digest_absent.remove(pid);
                        }
                    }
                    for pid in gone {
                        digest_absent.remove(&pid);
                        let name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        conn.drop_link(&pid);
                        ui::say(&conn.roster(
                            &pid,
                            "○",
                            ui::Tone::Dim,
                            "left (digest reconcile), still listening",
                            &name,
                        ));
                    }
                }
            }
            // C29: a code minted in-session (`pair` typed into up).
            Ev::PairCode(v) => {
                let c = v["code"].as_str().unwrap_or("?");
                ui::clipboard(c);
                ui::say("");
                ui::say(&format!(
                    "      {}",
                    ui::paint(ui::Tone::Brand, &c.to_uppercase())
                ));
                ui::say("");
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  say it aloud; they type it in the web app or `filament join <code>` / one claim / 10 min",
                ));
            }
            Ev::PairUsed(_) => {
                ui::say(&ui::paint(ui::Tone::Dim, "  code claimed, connecting..."));
            }
            Ev::PairError(v) => {
                let why = v["error"].as_str().unwrap_or("?").to_string();
                // The server distinguishes (additively) a dead creator from a
                // typo'd/expired code, say the actionable thing for each.
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => {
                        "the sender who made that code already left, ask them for a fresh one"
                            .to_string()
                    }
                    _ => format!("{why}, codes burn after one use and expire after 10 min"),
                };
                if code.is_some() && conn.links.is_empty() && st.completed == 0 {
                    // started WITH a code that failed: nothing else to do
                    bail!("code rejected: {hint}");
                }
                // a TYPED claim failing must not kill a listening session
                paired = false;
                claim_in_flight = false;
                ui::say(&format!(
                    "  {} code rejected: {hint}; still listening",
                    ui::paint(ui::Tone::Err, ui::glyph_err()),
                ));
            }
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                // P5 (GAP-6): a fresh welcome (signaling reconnect) may mean the
                // network just changed under us, re-probe relay-committed peers for
                // a direct path immediately instead of waiting out the backoff.
                conn.reprobe_on_network_event();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, true).await?;
                    }
                }
                // C30 (dissolves the C28 belt): a welcome means a fresh sid,
                // everything sid-keyed (subscriptions, lease) died with the
                // old one. Invalidate; the next tick re-asserts everything.
                sess.invalidate();
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own sender/daemon shares these channels
                }
                if let Some((n, sec)) = devices
                    .iter()
                    .find(|(_, s)| channel_of(s) == v["channel"].as_str().unwrap_or(""))
                {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    // WARM-HOLD: a known peer just came online. Under auto-warm, adopt it
                    // into the auto tier NOW (don't wait up to 10s for the tick) and clear
                    // any dormancy/backoff so the reconnect loop owns it from t=0. The
                    // start_direct/maybe_adopt below already dial immediately; this makes
                    // warm-hold RETRY if that first dial fails or the link later drops.
                    // Do NOT add to recent-LRU (that's for ACTUAL use only).
                    let auto_warm = l3.is_some() || settings::get_bool("auto-warm", None);
                    if auto_warm {
                        conn.warm_hold.auto.insert(n.clone());
                    }
                    if conn.warm_hold.should_connect(n) {
                        conn.warm_hold.resume(n);
                        // Pull the next warm tick forward: the event loop wakes at least every
                        // 2s (next_ev timeout, :8957-8960), so a failed eager dial is retried
                        // within ~2s instead of ~10s.
                        last_warm_hold_tick = Instant::now()
                            .checked_sub(Duration::from_secs(10))
                            .unwrap_or_else(Instant::now);
                    }
                    // Only announce a FRESH connect. The server re-pushes the
                    // known-peer roster on every (re)subscribe and C30 sync tick, so
                    // a peer we already hold a link to (or are already dialing) would
                    // otherwise reprint "appeared, connecting" on a loop, reading
                    // like a flap even though `start_direct` below no-ops for an
                    // existing link (start_direct_inner early-return). A real
                    // reconnect removes the link first, so it still announces.
                    let fresh =
                        !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid);
                    // Also re-announce if the existing link's transport is dead
                    let link_dead = conn
                        .links
                        .get(&pid)
                        .and_then(|l| l.transport.as_ref())
                        .map(|t| t.is_dead())
                        .unwrap_or(false);
                    if fresh || link_dead {
                        ui::say(&format!("known device '{n}' appeared, connecting"));
                        devices_touch(n, None, None); // track last_seen; addresses filled on ChannelReady
                    } else {
                        ui::trace(&format!(
                            "known device '{n}' re-announced (link already up)"
                        ));
                    }
                    // rung-1: known device = both CLIs; try direct QUIC first.
                    let (n, sec) = (n.clone(), sec.clone());
                    conn.start_direct(&pid, &n, &sec).await;
                    conn.maybe_adopt(&v, true).await?;
                    if let Some(l) = conn.link_mut(&pid) {
                        l.expected_secret = Some((n.clone(), sec.clone()));
                    }
                } else if let Some(sec) = brokered.get(v["channel"].as_str().unwrap_or("")).cloned()
                {
                    // A peer arrived on a meeting place we were TOLD about over a
                    // certificate-verified link. Exactly one other party is
                    // expected here, and the brokered secret proves it the same
                    // way a pair secret proves a paired device, so this joins the
                    // ordinary known-device path rather than the fleet one.
                    //
                    // That is the whole point of brokering: the one-shot never has
                    // to work out which of several siblings is the target, because
                    // only the target was ever given the address.
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if pid.is_empty() {
                        continue;
                    }
                    let name = v["name"].as_str().unwrap_or("peer").to_string();
                    conn.start_direct(&pid, &name, &sec).await;
                    conn.maybe_adopt(&v, true).await?;
                    if let Some(l) = conn.link_mut(&pid) {
                        l.expected_secret = Some((name, sec));
                    }
                } else if fleet::is_fleet_channel(v["channel"].as_str().unwrap_or("")) {
                    // Fleet auto-mesh: a device is present on our fleet meeting
                    // point. We hold NO pair secret for it, so this is the
                    // secretless presence path (same shape as the enrollment
                    // channel below): dial now, prove identity with the
                    // certificate once the link is up. Until `fleet-hello`
                    // verifies, the link is in `fleet_pending` and authorizes
                    // nothing.
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty() && !fleet_verified.contains(&pid) {
                        fleet_pending.insert(pid.clone());
                    }
                    // Dial direct-QUIC keyed by the fleet secret. It must be
                    // direct, not the WebRTC fallback: only a direct link exposes
                    // an RFC-5705 channel binding, and fleet-hello is bound to it
                    // (net.rs channel_binding() returns None). And both ends are
                    // daemons, so without an explicit dial nobody connects at all
                    // (maybe_adopt only prepares to ACCEPT).
                    // GLARE: both ends see each other on the fleet channel, so
                    // both would dial, collide, and supersede each other forever.
                    // Measured before this guard: 1 verify, 10 drops, never
                    // settling, which reads downstream as "peer unreachable" while
                    // a link is visibly present. Pick ONE dialer deterministically;
                    // both sides run the same comparison and get opposite answers,
                    // so exactly one dials and the other accepts.
                    if conn.my_id < pid {
                        if let Some(rv) = fleet::rv() {
                            conn.start_direct_fleet(&pid, &rv).await;
                        }
                    }
                    conn.maybe_adopt(&v, true).await?;
                } else if let Ok(Some(uk)) =
                    crate::identity::UserKey::load(&crate::platform::PlatformKeyStore)
                {
                    // Enrollment channel: an ephemeral device appeared on
                    // enroll_channel(own_owner_pub). Dial it (channel-presence
                    // path, no room-join) so the auth-key handshake can run.
                    let ek = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
                    if v["channel"].as_str() == Some(&ek) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        if !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid)
                        {
                            ui::debug("enrollment peer appeared on channel, dialing");
                        }
                        conn.maybe_adopt(&v, true).await?;
                    }
                }
            }
            Ev::PeerJoined(v) => {
                let had_partials = !st.by_sid.is_empty();
                if conn.maybe_adopt(&v, true).await? && had_partials {
                    // Stale per-link sid routing dies with the old link; the
                    // .part files live on and the sender's resume re-offers.
                    flush_inflight(&mut st.by_sid).await;
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates, start the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let srflx = data["srflx"].as_str().map(String::from);
                    // #237: peer's server-asserted candidate + protocol version
                    // (see the send-side handler; absent `proto` means older build).
                    let peer_server_public = data["server_public"].as_str().map(String::from);
                    let peer_proto = data["proto"].as_u64().unwrap_or(1).clamp(1, 255) as u8;
                    // If we're on the code path and this peer hasn't authenticated yet,
                    // buffer the transport-offer until PAKE completes. Otherwise
                    // on_transport_offer would find no DirectPending (no secret) and
                    // silently drop the offer, causing the QUIC race to fail.
                    if recv_code_path && !recv_pake_done {
                        recv_pending_direct
                            .insert(from.clone(), (cands, srflx, peer_server_public, peer_proto));
                        ui::debug(&format!("buffering pre-auth transport-offer from {from}"));
                        continue;
                    }
                    if data["probe"].as_bool() == Some(true) {
                        conn.answer_upgrade_probe(&from).await;
                    }
                    // Bug 2: the sender re-dialed after mid-transfer death.
                    // If we don't have a DirectPending, buffer the offer and
                    // replay it once start_direct creates one (same pattern as
                    // Bug 1's pre-PAKE buffer). Without this, on_transport_offer
                    // finds no pending and silently drops the offer.
                    if conn.direct_pending.contains_key(&from) {
                        conn.on_transport_offer(
                            &from,
                            cands,
                            srflx,
                            peer_server_public,
                            peer_proto,
                        );
                    } else {
                        // Also try to re-arm direct proactively: if we still
                        // know this peer's (name,secret), create the pending
                        // now so the buffered offer is replayed immediately.
                        let known = crate::devices_load().into_iter().find(|(n, _)| {
                            conn.links.get(&from).map(|l| l.name == *n).unwrap_or(false)
                        });
                        if let Some((name, secret)) = known {
                            conn.start_direct(&from, &name, &secret).await;
                        }
                        if conn.direct_pending.contains_key(&from) {
                            // Re-arm succeeded — process the offer now.
                            conn.on_transport_offer(
                                &from,
                                cands,
                                srflx,
                                peer_server_public,
                                peer_proto,
                            );
                        } else {
                            conn.buffered_offers.insert(
                                from.clone(),
                                (cands, srflx, peer_server_public, peer_proto),
                            );
                            ui::debug(&format!(
                                "buffering re-dial transport-offer from {from} (no pending yet)"
                            ));
                        }
                    }
                    continue;
                }
                // L1-a: PAKE messages ride the opaque `signal` relay. Route them
                // into THAT `from` peer's own ephemeral ceremony (recv code path).
                // On confirm the secret is agreed; that peer becomes the
                // authenticated sender and we DISCARD the secret. A failed/aborted
                // ceremony drops ONLY that candidate (a decoy / wrong-words peer),
                // it never bails the receive: the real sender's ceremony is
                // independent and still live.
                if recv_code_path
                    && matches!(
                        data["type"].as_str(),
                        Some("pake-msg") | Some("pake-confirm")
                    )
                {
                    // Already authenticated a sender? Ignore stray PAKE traffic
                    // from anyone else, including a late decoy.
                    if recv_pake_done {
                        continue;
                    }
                    // Mint this peer's ceremony on first sight (bounded), or route
                    // into its existing one. If the peer was already dropped (budget
                    // expired) or we are at the candidate cap, ignore its traffic.
                    if !st.recv_cers.contains_key(&from) {
                        if st.recv_cers.len() >= RECV_MAX_CANDIDATES {
                            ui::debug("recv: candidate cap reached, ignoring extra peer's PAKE");
                            continue;
                        }
                        if let Some((pw, np)) = &recv_pake_template {
                            st.recv_cers.insert(
                                from.clone(),
                                Ceremony::new(
                                    pw,
                                    np,
                                    pair_v2_caps(),
                                    crate::identity::IntroScope::Device.to_byte(),
                                ),
                            );
                            st.recv_deadlines
                                .entry(from.clone())
                                .or_insert_with(|| Instant::now() + recv_pake_budget);
                            recv_pake_overall_deadline
                                .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                        }
                    }
                    let fps = match conn.link(&from) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                    // Extract secret first to avoid borrow checker issues with clear() and start_direct
                    let mut secret_opt: Option<String> = None;
                    let mut is_abort = false;
                    let mut abort_why = String::new();
                    if let Some(cer) = st.recv_cers.get_mut(&from) {
                        match cer.on_signal(&data, fp_ref) {
                            PakeInbound::Consumed => {
                                secret_opt = cer.secret().cloned();
                            }
                            PakeInbound::Abort(why) => {
                                is_abort = true;
                                abort_why = why;
                            }
                            PakeInbound::Ignored => {}
                        }
                    }
                    if let Some(sec) = secret_opt {
                        // This peer authenticated. Record it as THE sender
                        recv_pake_done = true;
                        st.recv_cers.clear();
                        st.recv_deadlines.clear();
                        ui::say(&ui::paint(ui::Tone::Dim, "  authenticated, receiving"));
                        // Option A: start the direct-QUIC race. start_direct owns
                        // replacement after all fallible setup and pending registration.
                        let promo = conn.start_direct_promote(&from, &from, &sec).await;
                        conn.bind_active(&from);
                        // A retained link is unannounced here too, and this loop's
                        // ChannelReady arm sends `caps` and the signed L3 announce,
                        // which a peer on a retained link would otherwise never get.
                        conn.rearm_channel_ready(&from, promo);
                        // #161 (WebRTC/relay path): issue the possession challenge
                        // now that this peer authenticated. The direct path resolves
                        // identity at DirectReady (start_direct_promote above); the
                        // WebRTC path has no pair-proof for a fresh code peer (no
                        // stored secret) and no DirectReady, so without this its
                        // identity never resolves and revocation cannot bind. The
                        // helper is idempotent with the DirectReady site.
                        if recv_code_path {
                            if let Some(l) = conn.link_mut(&from) {
                                resolve_peer_identity(l);
                            }
                            let (idev_known, proven) = conn
                                .link(&from)
                                .map(|l| {
                                    (
                                        l.identity_device_pub.is_some(),
                                        l.identity_binding
                                            == crate::capability::BindingStrength::Proven,
                                    )
                                })
                                .unwrap_or((false, false));
                            if !proven && !idev_known {
                                if let Some(t) = conn.transport_of(&from) {
                                    issue_proven_challenge_and_hold(
                                        &conn,
                                        &from,
                                        &t,
                                        &st.pending_proven,
                                        &mut identity_nonces,
                                    )
                                    .await;
                                }
                            }
                        }
                        // Replay any buffered transport-offer that arrived before PAKE
                        // (now that start_direct created a DirectPending with the secret)
                        if let Some((cands, srflx, server_public, proto)) =
                            recv_pending_direct.remove(&from)
                        {
                            conn.on_transport_offer(&from, cands, srflx, server_public, proto);
                        }
                        recv_pending_direct.clear();
                        // Replay any buffered file offers from this peer
                        let buffered = st.recv_pending_offers.remove(&from);
                        st.recv_pending_offers.clear();
                        if let Some(offer) = buffered {
                            let _ = tx.send(Ev::Control(from.clone(), offer));
                        }
                        continue;
                    }
                    if is_abort {
                        st.recv_cers.remove(&from);
                        st.recv_deadlines.remove(&from);
                        st.recv_pending_offers.remove(&from);
                        recv_pending_direct.remove(&from);
                        ui::debug(&format!(
                            "recv: candidate {from} refused ({abort_why}), dropped"
                        ));
                    }
                    continue;
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            // rung-1: authenticated direct-QUIC won the race, adopt as a
            // pre-trusted Link, then funnel into the normal ChannelReady handler.
            Ev::DirectReady(pid, t, route) => {
                let tkey = conn
                    .direct_pending
                    .get(&pid)
                    .map(|p| direct::transport_key(&p.secret.1));
                conn.adopt_direct(&pid, t.clone(), route);
                if let Some(k) = tkey {
                    conn.spawn_direct_workers(&pid, &t, k);
                }
                // #30: Send nonce challenge at link adoption so Proven settles
                // before any gated open. Under authoritative, HOLD ChannelReady
                // until the possession-sig round-trip completes or 3s timeout,
                // so short-session gates never decide on Inferred while a
                // challenge is in flight.
                // Resolve identity from the stored cert first so device_pub is
                // populated at adopt time; otherwise needs_proven is always false
                // and the possession-sig challenge never fires.
                if let Some(l) = conn.link_mut(&pid) {
                    resolve_peer_identity(l);
                }
                let (idev_known, proven) = conn
                    .link(&pid)
                    .map(|l| {
                        (
                            l.identity_device_pub.is_some(),
                            l.identity_binding == crate::capability::BindingStrength::Proven,
                        )
                    })
                    .unwrap_or((false, false));
                // #161: in shadow mode, a typed-code link with NO identity still
                // needs the challenge so revocation can bind: shadow mode never
                // resolves a fresh code peer's identity otherwise (the old code
                // issued the challenge under authoritative only), and the gate
                // would then decide a legacy-trusted offer with
                // cert_revoked_for(None)=false, letting a revoked device push a
                // transfer before its revoked cert resolves.
                let needs_challenge = if crate::capability::cap_authoritative() {
                    idev_known && !proven
                } else {
                    recv_code_path && !idev_known
                };
                if needs_challenge {
                    // Shared issue-and-hold (hold-then-await; see the helper). This
                    // registers the pending_proven hold BEFORE sending, identically to
                    // the ChannelReady site, so the two sites cannot diverge on order.
                    issue_proven_challenge_and_hold(
                        &conn,
                        &pid,
                        &t,
                        &st.pending_proven,
                        &mut identity_nonces,
                    )
                    .await;
                    if crate::capability::cap_authoritative() {
                        ui::say(&format!(
                            "  identity challenge sent to {pid}, holding until Proven or timeout"
                        ));
                        // DirectReady-specific release policy: HOLD ChannelReady (do not
                        // emit it here) and RE-EMIT it when the 3s hold expires, so a
                        // direct link's gates never observe Inferred at all.
                        let hold_t = t.clone();
                        let hold_tx = tx.clone();
                        let hold_pending = st.pending_proven.clone();
                        let hold_pid = pid.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(PROVEN_CHALLENGE_DEADLINE).await;
                            if hold_pending.lock().unwrap().contains_key(&hold_pid) {
                                hold_pending.lock().unwrap().remove(&hold_pid);
                                let _ = hold_tx.send(Ev::ChannelReady(hold_pid, hold_t));
                            }
                        });
                    } else {
                        // #161 shadow mode: the typed-code path already rearmed
                        // ChannelReady at PAKE confirm. Issue the challenge for
                        // identity but do NOT hold the channel; the file-offer
                        // hold re-injects the first offer until identity settles.
                        let _ = tx.send(Ev::ChannelReady(pid, t));
                    }
                } else {
                    let _ = tx.send(Ev::ChannelReady(pid, t));
                }
            }
            Ev::DirectWorkersReady(pid, workers) => {
                if let Some(link) = conn.link_mut(&pid) {
                    link.workers = workers;
                    crate::ui::debug(&format!(
                        "worker transports ready: {pid} {} workers",
                        link.workers.len()
                    ));
                }
            }
            // P5 (GAP-6): relay->direct upgrade standby connected (receiver side).
            // Stash + VERIFY rather than adopt, see the send-loop twin.
            Ev::DirectUpgradeReady(pid, t, route) => {
                conn.stash_upgrade_standby(&pid, t, route);
            }
            Ev::ChannelReady(pid, t) => {
                // #39 (fleet-trust): the WebRTC/relay path's possession challenge is
                // NOT issued here. At ChannelReady on the WebRTC path, verified_name is
                // not set yet (the pair-proof round-trip sets it AFTER the channel opens),
                // so resolve_peer_identity finds no identity, needs_proven is false, and
                // the challenge would be skipped — the live rig caught exactly this. The
                // challenge for the WebRTC/relay path is issued from the pair-proof
                // handler, where verified_name is set and identity first RESOLVES on that
                // path; the DirectReady path issues at adoption (identity already resolved
                // by then). Both go through the now-idempotent issue_proven_challenge_and_hold,
                // which dedupes by a live pending_proven entry so the two sites are
                // order-independent and cannot clobber each other's nonce.
                //
                // #161 EXCEPTION (typed-code path): a fresh code peer has NO stored pair
                // secret, so pair-proof never fires and the #39 rule above would leave its
                // identity permanently unresolved on the WebRTC transport - the direct
                // path resolves it at DirectReady, the WebRTC path would never. Without
                // the challenge its cert never reaches the gate, so revocation cannot
                // bind and a revoked device's first transfer lands. The challenge is
                // issued at PAKE confirm (the peer is authenticated and its responder
                // loop is live), not here: at ChannelReady the sender is not yet ready
                // to answer, and the 3s hold would expire before it is.
                // #161 EXCEPTION (typed-code path, transport-up re-issue): a
                // fresh code peer has NO stored pair secret, so pair-proof never
                // fires and the #39 rule above would leave its identity
                // permanently unresolved on the WebRTC transport. The direct
                // path resolves it at DirectReady; the WebRTC path issues the
                // challenge at PAKE confirm. When that PAKE-confirm challenge
                // was LOST because the WebRTC transport was not yet up (the
                // direct-blocked fallback establishes the data channel AFTER
                // PAKE), this ChannelReady re-issue delivers it now that the
                // transport is genuinely ready. Gated on recv_pake_done so the
                // normal WebRTC path (ChannelReady BEFORE PAKE) never gets an
                // early challenge the sender cannot answer - only the case
                // where the channel arrived after the ceremony.
                if recv_code_path && recv_pake_done {
                    if let Some(l) = conn.link_mut(&pid) {
                        resolve_peer_identity(l);
                    }
                    let (idev_known, proven) = conn
                        .link(&pid)
                        .map(|l| {
                            (
                                l.identity_device_pub.is_some(),
                                l.identity_binding == crate::capability::BindingStrength::Proven,
                            )
                        })
                        .unwrap_or((false, false));
                    if !proven && !idev_known {
                        issue_proven_challenge_and_hold(
                            &conn,
                            &pid,
                            &t,
                            &st.pending_proven,
                            &mut identity_nonces,
                        )
                        .await;
                    }
                }
                // web-shell discovery: tell the peer whether this receiver offers a
                // terminal (l2_enabled = `up --shell` / FILAMENT_L2). The browser
                // shows its per-device shell button ONLY when this is true; the
                // actual pty-open is still gated server-side by the cap/policy.
                let _ = t
                    .send_control(&json!({ "type": "caps", "shell": l2_enabled }))
                    .await;
                // L3 (serve_tun mesh): on a datagram-capable (direct) link, send a
                // SIGNED announce of our overlay address, bound to THIS link's
                // channel binding so it can't be replayed elsewhere. Both ends
                // announce on their own ChannelReady, so each learns the other.
                // Also replay any announce that arrived BEFORE this transport was
                // installed (fix #3), now that the link can carry datagrams.
                // Fleet auto-mesh: this link came off the fleet channel, so there
                // is no pair secret to prove. Present the owner-signed certificate
                // bound to THIS link instead.
                // No exporter on this transport: open the challenge. Our nonce
                // goes out now; anything we SEND waits until theirs arrives.
                if t.channel_binding().is_none() {
                    // Generate ONCE per link, not per ChannelReady. This fires
                    // again on every re-establish and re-announce, and a fresh
                    // nonce here would invalidate the one the peer is already
                    // signing against, which shows up as a permanent
                    // "signature or channel-binding mismatch". The nonce is
                    // dropped with the link, so a genuinely new link still gets a
                    // new one. Re-send the stored value every time, so a peer
                    // that missed the first copy still gets it.
                    let nonce = bind_ours
                        .entry(pid.clone())
                        .or_insert_with(link_nonce)
                        .clone();
                    let _ = t
                        .send_control(&json!({
                            "type": "l3-nonce",
                            "nonce": crate::overlay::b64(&nonce),
                        }))
                        .await;
                }
                // Only for a node that is actually IN a fleet: this fires on every
                // ChannelReady, and a user with no fleet has nothing to diagnose
                // here. It is what made the dial-glare visible, so it stays.
                if fleet::rv().is_some() {
                    ui::debug(&format!(
                        "fleet-hello decision pid={pid}: rv={} pending={} shaped={} verified={} cb={} secret={:?}",
                        fleet::rv().is_some(),
                        fleet_pending.contains(&pid),
                        fleet_shaped_link(&conn, &pid),
                        fleet_verified.contains(&pid),
                        t.channel_binding().is_some(),
                        conn.link(&pid)
                            .and_then(|l| l.expected_secret.as_ref().map(|(n, _)| n.clone())),
                    ));
                }
                if !fleet_verified.contains(&pid)
                    && fleet::rv().is_some()
                    && (fleet_pending.contains(&pid) || fleet_shaped_link(&conn, &pid))
                {
                    // Mark it, so the L3 gate and the drop-cleanup track this link
                    // even when it arrived via warm-hold rather than presence.
                    fleet_pending.insert(pid.clone());
                    if let Some(cb) = out_binding(&t, &pid, &bind_theirs) {
                        match fleet::make_hello(&cb, &display_name()) {
                            Ok(hello) => {
                                fleet_greeted.insert(pid.clone());
                                let _ = t.send_control(&hello).await;
                            }
                            Err(e) => ui::debug(&format!("fleet-hello not sent to {pid}: {e}")),
                        }
                    }
                }
                #[cfg(l3)]
                if let Some(l3) = l3.as_ref() {
                    if let Some(cb) = out_binding(&t, &pid, &bind_theirs) {
                        if let Some(ann) = l3.make_announce(&cb) {
                            let _ = t.send_control(&ann.to_json()).await;
                        }
                    }
                    if let Some(cb) = in_binding(&t, &pid, &bind_ours) {
                        if let Some(pending) = l3_seen.get(&pid) {
                            if let Ok(ip) = pending.verify(&cb) {
                                // Seq check AFTER verify, never before, so an
                                // unauthenticated message cannot poison the
                                // last-seen map. verify() proves the key, the
                                // channel binding and possession; none of those
                                // stop a genuine announce being replayed onto
                                // the SAME channel later.
                                if !fleet_route_ok(&conn, &pid, pending.relay_datagrams) {
                                    ui::debug(&format!(
                                        "  l3-announce from {pid} ignored: relayed link and peer does not advertise relay datagrams"
                                    ));
                                } else if l3.accept_seq(&pending.pubkey, pending.seq).await {
                                    let who =
                                        conn.link(&pid).map(|l| l.shown()).unwrap_or_default();
                                    let v4 = pending.addr_v4();
                                    l3.add_peer(&pid, &who, ip.into(), Some(v4.into()), t.clone())
                                        .await;
                                    // Store overlay addresses for `filament addr <device>`
                                    devices_touch(&who, Some(ip), Some(v4));
                                } else {
                                    ui::debug(&format!(
                                        "  l3-announce from {pid} ignored: stale sequence {}",
                                        pending.seq
                                    ));
                                }
                            }
                        }
                    }
                }
                if let Some(l) = conn.link_mut(&pid) {
                    ui::say(&format!(
                        "  {} {}",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        ui::paint(ui::Tone::Bold, l.shown())
                    ));
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                    let is_direct = l.direct;
                    let direct_route = l.direct_route;
                    if let Some(p) = l.peer.clone() {
                        tokio::spawn(async move {
                            // ICE may renominate; retry briefly (mirrors the
                            // browser's _detectRoute attempts) so fast transfers
                            // still get a route line before the process exits.
                            for _ in 0..6 {
                                tokio::time::sleep(Duration::from_millis(400)).await;
                                if let Some(r) = p.route().await {
                                    // CRITICAL: the route label is the value-prop,
                                    // direct vs relayed. Always shown, even under -q.
                                    ui::debug(&format!(
                                        "    {}",
                                        ui::paint(ui::Tone::Dim, &format!("route: {r}"))
                                    ));
                                    // Relay honesty (§3.3): the quiet `route:` line
                                    // is legible but not loud. When the route is
                                    // actually the TURN relay, print the honest
                                    // one-line banner so the user is never unaware
                                    // they're on a middleman path. CRITICAL.
                                    if r == "relayed" {
                                        ui::critical(&format!("    {}", relay_banner()));
                                    }
                                    break;
                                }
                            }
                        });
                    } else if is_direct {
                        ui::debug(&format!(
                            "    {}",
                            ui::paint(ui::Tone::Dim, &format!("route: {direct_route}"))
                        ));
                    }
                }
                // Warm-reuse readiness: proactively prove our identity to a KNOWN
                // peer on a RELAY/WebRTC link (a DIRECT link is born-verified at
                // adoption, so it skips this). `send_cmd` already does this on its
                // active transfer link (the ChannelReady proof ~5205); the daemon
                // must too, otherwise a passively-held link reaches `✓` but neither
                // end ever sets `verified_name`, so `warm_link_for` rejects it and
                // the FIRST ssh/pty/netcat to an idle paired peer eats a full cold
                // establish. Symmetric by construction: both daemons send, both
                // verify (the `pair-proof` handler below), both can then warm-reuse.
                // No guard, mirroring send_cmd: re-proving on a reconnect is
                // harmless and just refreshes trust.
                let proof_creds = conn.link(&pid).and_then(|l| {
                    if l.direct {
                        return None;
                    }
                    let (_n, sec) = l.expected_secret.clone()?;
                    Some((sec, l.uid.clone().unwrap_or_default(), l.peer.clone()))
                });
                if let Some((sec, uid, peer)) = proof_creds {
                    if let Some((my_fp, their_fp)) = match peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    } {
                        let mac =
                            proof_for(&sec, &conn.my_uid, &conn.my_uid, &uid, &my_fp, &their_fp);
                        let _ = t
                            .send_control(&json!({ "type": "pair-proof", "mac": mac }))
                            .await;
                    }
                }
                // L1-a: on the `recv <code>` path, this peer is a CANDIDATE sender.
                // Mint its own ephemeral ceremony (bounded) and arm its per-peer
                // budget plus the overall backstop. The progression block (top of
                // loop) drives every candidate independently; file-offers are not
                // accepted until ONE peer's ceremony confirms (`recv_pake_done`),
                // and then only from that authenticated peer. A stored pairing
                // secret authenticates that known device, but does not prove it
                // minted this one-time code, so every candidate still runs PAKE.
                if recv_code_path && !recv_pake_done {
                    if st.recv_cers.contains_key(&pid) {
                        // Ceremony already minted (its PAKE traffic arrived first);
                        // just make sure its budgets are armed.
                        st.recv_deadlines
                            .entry(pid.clone())
                            .or_insert_with(|| Instant::now() + recv_pake_budget);
                        recv_pake_overall_deadline
                            .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                    } else if st.recv_cers.len() < RECV_MAX_CANDIDATES {
                        if let Some((pw, np)) = &recv_pake_template {
                            st.recv_cers.insert(
                                pid.clone(),
                                Ceremony::new(
                                    pw,
                                    np,
                                    pair_v2_caps(),
                                    crate::identity::IntroScope::Device.to_byte(),
                                ),
                            );
                            st.recv_deadlines
                                .insert(pid.clone(), Instant::now() + recv_pake_budget);
                            recv_pake_overall_deadline
                                .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                            ui::say(&ui::paint(ui::Tone::Dim, "  authenticating..."));
                        }
                    }
                }
                // C29: an in-session pairing, exactly one side hands over a
                // secret; consent (pair-keep-ack / our store) completes it.
                // Only links that aren't ALREADY known are candidates.
                // "No pair secret" USED to mean "a peer we have never met", which
                // is what makes a link a candidate for the in-session ceremony.
                // Fleet auto-mesh broke that: a sibling whose direct dial fell
                // back to WebRTC also has no pair secret, and it would consume the
                // code the human just typed, handing the ceremony secret to a
                // device we already know and leaving the intended one unpaired.
                // A fleet peer is never a pairing candidate.
                let fresh_link = conn
                    .link(&pid)
                    .map(|l| l.expected_secret.is_none())
                    .unwrap_or(false)
                    && !fleet_pending.contains(&pid)
                    && !fleet_verified.contains(&pid);
                if fresh_link {
                    match ceremony {
                        Some(true) => {
                            // we minted the code, initiate now
                            ceremony = None;
                            ceremony_pid = Some(pid.clone());
                            t.send_control(
                                &json!({ "type": "pair-keep", "secret": ceremony_secret }),
                            )
                            .await
                            .ok();
                        }
                        Some(false) => {
                            // we claimed, give a CLI creator 3 s to initiate
                            // (browsers never do), then take over.
                            let tx = tx.clone();
                            let pid = pid.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(3)).await;
                                let _ =
                                    tx.send(Ev::Control(pid, json!({ "type": "__pair_fallback" })));
                            });
                        }
                        None => {}
                    }
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                // L3 (serve_tun): the peer announced its overlay IP. Route that IP
                // to this link and start pumping its datagrams into our TUN. Only
                // when we run an overlay ourselves; ignored otherwise.
                // Check BEFORE the catch-all guard so announces that race ahead of
                // link creation are cached in l3_seen for replay on ChannelReady.
                // The peer's half of the link challenge (transports with no
                // RFC-5705 exporter). Store it, then send everything that was
                // waiting on a binding: our announce, and our fleet-hello.
                // Fleet policy relayed by a sibling. Only ops the OWNER signed
                // survive `merge_owner_cap_ops`, so a peer can relay policy but
                // never author it.
                Some("fleet-policy") => {
                    if let Some(ops) = v["ops"].as_array() {
                        let n = merge_owner_cap_ops(ops);
                        if n > 0 {
                            ui::debug(&format!("fleet policy from {pid}: {n} new op(s)"));
                        }
                    }
                }
                Some("l3-nonce") => {
                    match v["nonce"].as_str().map(crate::overlay::unb64) {
                        Some(Ok(nonce)) if nonce.len() >= 16 => {
                            bind_theirs.insert(pid.clone(), nonce);
                            if let Some(t) = conn.transport_of(&pid) {
                                if let Some(cb) = out_binding(&t, &pid, &bind_theirs) {
                                    #[cfg(l3)]
                                    if let Some(l3) = l3.as_ref() {
                                        if let Some(ann) = l3.make_announce(&cb) {
                                            let _ = t.send_control(&ann.to_json()).await;
                                        }
                                    }
                                    // Answer EVERY nonce with a fresh hello, even
                                    // one we have already greeted. A repeat nonce
                                    // means the peer could not verify what we sent
                                    // (its challenge had not reached us when we
                                    // signed) and is asking again. Honouring
                                    // `fleet_greeted` here would leave it waiting
                                    // forever for a proof we refuse to re-send.
                                    if !fleet_verified.contains(&pid) {
                                        if let Ok(hello) = fleet::make_hello(&cb, &display_name()) {
                                            fleet_greeted.insert(pid.clone());
                                            let _ = t.send_control(&hello).await;
                                        }
                                    }
                                }
                            }
                        }
                        // A short or malformed nonce is refused rather than used:
                        // a peer that picks a weak challenge would weaken OUR
                        // replay protection, not theirs.
                        _ => ui::debug(&format!(
                            "l3-nonce from {pid} ignored: missing or too short"
                        )),
                    }
                }
                // Fleet auto-mesh: a same-owner device is presenting its
                // certificate. Three things must hold together (fleet.rs): live
                // possession bound to THIS link, a certificate chaining to OUR
                // owner key, and both naming the same device key. Anything less
                // and the link stays unverified, so it never gains a route.
                Some(fleet::HELLO) => {
                    let cb = conn
                        .transport_of(&pid)
                        .and_then(|t| in_binding(&t, &pid, &bind_ours));
                    let owner = fleet::my_owner_pub();
                    match (cb, owner) {
                        (Some(cb), Some(owner)) => {
                            match fleet::verify_hello(&v, &cb, &owner, identity::now_secs()) {
                                Ok(ok) if device_cert_revoked(&ok.device_pub) => {
                                    ui::debug(&format!(
                                        "fleet-hello from {pid} refused: device revoked"
                                    ));
                                    fleet_pending.remove(&pid);
                                    fleet_deferred_offers.retain(|(p, _, _)| p != &pid);
                                    conn.drop_link(&pid);
                                }
                                Ok(ok) => {
                                    let fresh = fleet_verified.insert(pid.clone());
                                    // Identity has settled: replay whatever arrived
                                    // while it had not. This belongs HERE, beside
                                    // the insert, not in the `fresh` branch below:
                                    // the deferral waits on "verified", and a link
                                    // that re-verifies is verified just the same.
                                    {
                                        let replay: Vec<_> = fleet_deferred_offers
                                            .iter()
                                            .filter(|(p, _, _)| p == &pid)
                                            .cloned()
                                            .collect();
                                        fleet_deferred_offers.retain(|(p, _, _)| p != &pid);
                                        for (p, ov, _) in replay {
                                            ui::debug(&format!(
                                                "fleet: replaying offer deferred while {p} was unverified"
                                            ));
                                            let _ = tx.send(Ev::Control(p, ov));
                                        }
                                    }
                                    // Reachability, NOT capability: an empty
                                    // ceiling. The link forms, warm-hold keeps it
                                    // and L3 routes to it, while transfer, shell
                                    // and mount still need their own grant.
                                    // verified_name is the CAP-STORE KEY, so it is
                                    // resolved from the PROVEN certificate key, never
                                    // from the name the peer sent. A peer that could
                                    // name itself could name itself after a device
                                    // that holds grants.
                                    let proven_name = device_name_for_pub(&ok.device_pub);
                                    // The ceiling comes from the RECORD, which is
                                    // what `filament grant` edits. Hardcoding it
                                    // empty made auto-mesh peers ungrantable: the
                                    // grant landed in devices.json and the live
                                    // link kept refusing, so `grant` silently did
                                    // nothing for exactly the devices this feature
                                    // adds. A sibling we hold no record for still
                                    // gets nothing, which is the intended
                                    // reachability-without-capability default.
                                    if let Some(l) = conn.link_mut(&pid) {
                                        l.verified_name = proven_name.clone();
                                        l.admit_fleet(ok.owner_pub, ok.device_pub, ok.cert_expires);
                                    }
                                    // Answer once, so a mutual hello terminates.
                                    if fleet_greeted.insert(pid.clone()) {
                                        if let Some(t) = conn.transport_of(&pid) {
                                            if let Ok(hello) =
                                                fleet::make_hello(&cb, &display_name())
                                            {
                                                let _ = t.send_control(&hello).await;
                                            }
                                        }
                                    }
                                    // Re-announce our overlay address: an announce
                                    // that arrived while this link was unverified
                                    // was DROPPED (below), so without this the
                                    // route would never form.
                                    #[cfg(l3)]
                                    if let Some(l3) = l3.as_ref() {
                                        if let Some(t) = conn.transport_of(&pid) {
                                            if let Some(ann) = l3.make_announce(&cb) {
                                                let _ = t.send_control(&ann.to_json()).await;
                                            }
                                        }
                                    }
                                    // Fleet policy push. Enrollment seeds a device
                                    // once; grants made LATER would never reach it,
                                    // so re-push on every verified hello. The peer
                                    // verifies each op against the owner key it
                                    // already holds, and merging is idempotent, so
                                    // repeating this is cheap and self-healing.
                                    {
                                        let ops = owner_signed_cap_ops();
                                        if !ops.is_empty() {
                                            if let Some(t) = conn.transport_of(&pid) {
                                                let _ = t
                                                    .send_control(&json!({
                                                        "type": "fleet-policy",
                                                        "ops": ops,
                                                    }))
                                                    .await;
                                            }
                                        }
                                    }
                                    if fresh {
                                        // Proven petname when we have one; otherwise
                                        // the claimed display name, presentation only.
                                        let shown =
                                            proven_name.clone().unwrap_or(ok.claimed_name.clone());
                                        // Record the sibling so `filament devices`
                                        // can show the fleet. Deliberately with NO
                                        // pair secret: devices_load() filter-maps on
                                        // `secret`, so this record can never become a
                                        // channel subscription or a dial target. It is
                                        // an INDEX ENTRY, not an authorization, and the
                                        // empty ceiling it carries matches the link's.
                                        if proven_name.is_none() {
                                            if let Some(cert) =
                                                identity::DeviceCert::from_json(&v["cert"])
                                            {
                                                match devices_upsert_atomic(
                                                    &shown,
                                                    None,
                                                    Some(&cert),
                                                    Some(&[]),
                                                    Some(identity::IntroScope::Device.to_byte()),
                                                    None,
                                                    None,
                                                ) {
                                                    Ok(stored) => {
                                                        // Bind the link to the record we
                                                        // just created. Without this the
                                                        // FIRST contact leaves
                                                        // verified_name unset (there was
                                                        // no record when we looked it up),
                                                        // so the daemon cannot resolve
                                                        // this peer by name until some
                                                        // later reconnect happens to
                                                        // re-run the lookup. The name is
                                                        // still the PROVEN one: it came
                                                        // from the certificate we just
                                                        // verified.
                                                        if let Some(l) = conn.link_mut(&pid) {
                                                            l.verified_name = Some(stored.clone());
                                                        }
                                                        ui::debug(&format!(
                                                            "fleet peer indexed as '{stored}'"
                                                        ));
                                                    }
                                                    Err(e) => ui::debug(&format!(
                                                        "fleet peer not indexed: {e}"
                                                    )),
                                                }
                                            }
                                        }
                                        // The overlay route was installed at announce
                                        // time, when this link had no name yet, so its
                                        // MagicDNS entry still reads as the placeholder.
                                        // Correct it now that the certificate has named
                                        // the device.
                                        #[cfg(l3)]
                                        if let Some(l3) = l3.as_ref() {
                                            if l3
                                                .rename_peer(&pid, &l3::sanitize_host(&shown))
                                                .await
                                            {
                                                l3.refresh_hosts().await;
                                            }
                                        }
                                        ui::say(&format!("fleet device '{shown}' joined the mesh"));
                                        // A link to a fleet peer is the only
                                        // chance a joined device gets to reach a
                                        // primary. Ask here rather than on a
                                        // timer: a device that is only
                                        // occasionally connected would otherwise
                                        // tick past its own expiry while offline.
                                        maybe_request_cert_renewal(&conn, &pid).await;
                                    }
                                }
                                Err(e) => {
                                    ui::debug(&format!("fleet-hello from {pid} rejected: {e}"));
                                    fleet_pending.remove(&pid);
                                    fleet_deferred_offers.retain(|(p, _, _)| p != &pid);
                                    conn.drop_link(&pid);
                                }
                            }
                        }
                        _ => ui::debug(&format!(
                            "fleet-hello from {pid} ignored: no channel binding or no owner key"
                        )),
                    }
                }
                // A sibling's daemon brokered a private meeting place for one of
                // its one-shots. Join it, so the one-shot meets exactly us.
                //
                // ONLY from a link whose certificate we already verified. The
                // secret grants a meeting place and, on that place, the ordinary
                // known-device proof, so accepting one from an unverified link
                // would let mere presence on the fleet channel manufacture a
                // trusted-looking peering, which is the one thing this design says
                // presence must never buy.
                Some("fleet-rendezvous") if fleet_verified.contains(&pid) => {
                    match v["secret"].as_str() {
                        Some(sec) if hex::decode(sec).map(|b| b.len()).ok() == Some(32) => {
                            let ch = channel_of(sec);
                            if !sess.channels.contains(&ch) {
                                sess.channels.push(ch.clone());
                                let _ = sio
                                    .emit("subscribe", json!({ "channels": [ch.clone()] }))
                                    .await;
                                brokered.insert(ch, sec.to_string());
                                ui::debug(&format!(
                                    "fleet-rendezvous: joined a brokered channel for {pid}"
                                ));
                            }
                        }
                        _ => ui::debug("fleet-rendezvous: ignored a malformed secret"),
                    }
                }
                #[cfg(l3)]
                Some("l3-announce") if l3.is_some() => {
                    // A fleet link that has not proven its certificate gets NO
                    // overlay route, and its announce is not even cached for
                    // replay. Otherwise mere presence on the meeting point would
                    // buy an IP route, which is the one thing the design says
                    // presence must never buy.
                    if fleet_identity_pending(
                        &conn,
                        &pid,
                        fleet_pending.contains(&pid),
                        fleet_verified.contains(&pid),
                    ) {
                        ui::debug(&format!(
                            "l3-announce from unverified fleet link {pid} ignored"
                        ));
                        continue;
                    }
                    match overlay::Announce::from_json(&v) {
                        Ok(ann) => {
                            l3_seen.insert(pid.clone(), ann.clone());
                            // Try to process immediately if transport is available.
                            if let Some(l3) = l3.as_ref() {
                                match conn.transport_of(&pid).and_then(|t| {
                                    in_binding(&t, &pid, &bind_ours).map(|cb| (t, cb))
                                }) {
                                    Some((t, cb)) => match ann.verify(&cb) {
                                        Ok(ip) => {
                                            // Seq check AFTER verify, never before, so an
                                            // unauthenticated message cannot poison the
                                            // last-seen map. verify() proves address-is-key,
                                            // channel binding and possession; none of those
                                            // stop a GENUINE announce captured on this
                                            // channel from being replayed onto it later,
                                            // which is an address rollback (see accept_seq).
                                            if !l3.accept_seq(&ann.pubkey, ann.seq).await {
                                                ui::debug(&format!(
                                                    "  l3-announce from {pid} ignored: stale sequence {}",
                                                    ann.seq
                                                ));
                                                continue;
                                            }
                                            let who = conn
                                                .link(&pid)
                                                .map(|l| l.shown())
                                                .unwrap_or_default();
                                            // Verify-order fix: overlay key vs pinned cert check happens HERE at overlay establishment,
                                            // not at expose time. Possession-proven key already committed at expose time (provisional).
                                            // On mismatch, tear down with named error, never overwrite anchor.
                                            // Durable trust is written ONLY after this check passes.
                                            {
                                                let p = devices_path();
                                                if let Ok(raw) = std::fs::read_to_string(&p) {
                                                    if let Ok(arr) =
                                                        serde_json::from_str::<Vec<Value>>(&raw)
                                                    {
                                                        if let Err(e) = identity::check_overlay_against_pinned_cert(&arr, &who, &ann.pubkey) {
                                                            ui::say(&ui::paint(ui::Tone::Warn, &format!("  {}", e)));
                                                            // Tear down: do not add peer, do not overwrite anchor, clear provisional
                                                            clear_provisional_identity(&who);
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                            // Promote provisional identity to durable if present and matches overlay key
                                            if let Some(prov_cert) = load_provisional_identity(&who)
                                            {
                                                if let Err(e) = identity::provisional_promote_ok(
                                                    &prov_cert,
                                                    &ann.pubkey,
                                                ) {
                                                    ui::say(&ui::paint(
                                                        ui::Tone::Warn,
                                                        &format!(
                                                            "  {} for device {} - clearing provisional, no anchor written",
                                                            e, who
                                                        ),
                                                    ));
                                                    clear_provisional_identity(&who);
                                                    // Do not add peer, no durable write
                                                    continue;
                                                }
                                                // Check takeover guard and scope-aware anchor before promoting
                                                {
                                                    // For promote, use Device-scope as fixed convention for pair
                                                    let scope = crate::identity::IntroScope::Device
                                                        .to_byte();
                                                    match with_devices_mut(|arr| {
                                                        identity::apply_peer_identity(
                                                            arr, &who, &prov_cert, scope,
                                                        )
                                                        .map_err(|e| anyhow::anyhow!("{}", e))
                                                    }) {
                                                        Ok(_) => {
                                                            // Write durable anchor only after overlay assertion passes
                                                            clear_provisional_identity(&who);
                                                        }
                                                        Err(e) => {
                                                            ui::say(&ui::paint(
                                                                ui::Tone::Warn,
                                                                &format!(
                                                                    "  takeover guard at overlay establishment: {}",
                                                                    e
                                                                ),
                                                            ));
                                                            clear_provisional_identity(&who);
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                            let v4 = ann.addr_v4();
                                            if !fleet_route_ok(&conn, &pid, ann.relay_datagrams) {
                                                ui::debug(&format!(
                                                    "  L3 route for {who} withheld: relayed link and peer does not advertise relay datagrams"
                                                ));
                                                continue;
                                            }
                                            l3.add_peer(
                                                &pid,
                                                &who,
                                                ip.into(),
                                                Some(v4.into()),
                                                t.clone(),
                                            )
                                            .await;
                                            ui::say(&format!(
                                                "  {} L3 peer {who}.mesh ({ip} / {v4})",
                                                ui::paint(ui::Tone::Ok, ui::glyph_ok())
                                            ));
                                            devices_touch(&who, Some(ip), Some(v4));

                                            // Subnet routes, after the peer is on
                                            // the overlay. Three conditions, in
                                            // increasing cost: the advertisement
                                            // must be SIGNED (verify_routes, which
                                            // also covers seq so a withdrawn prefix
                                            // cannot be resurrected), this machine
                                            // must ACCEPT routes from this device,
                                            // and the owner must have GRANTED each
                                            // prefix by name.
                                            let advertised = ann.verify_routes(&cb);
                                            // NO EMPTY-SET SHORTCUT. An announce
                                            // carrying no routes is not "nothing
                                            // to do", it is a WITHDRAWAL, and
                                            // set_peer_subnets is a full
                                            // restatement of what this peer
                                            // carries. Skipping the block left a
                                            // withdrawn route installed forever:
                                            // the operator cleared
                                            // advertise-routes, the peer stopped
                                            // advertising, and the receiver kept
                                            // routing through it. For an exit
                                            // node that is not a stale entry, it
                                            // is a default route pointing into a
                                            // tunnel nobody is carrying, which
                                            // is indistinguishable from the
                                            // machine losing the internet.
                                            {
                                                let accept = crate::settings::get_str(
                                                    "accept-routes",
                                                    Some(&who),
                                                )
                                                .map(|v| v == "on" || v == "true")
                                                .unwrap_or(false);
                                                let config_dir = crate::settings::config_dir();
                                                // The OWNER's public key, which is
                                                // not the same as holding the
                                                // owner's signing key.
                                                //
                                                // FOUND BY RUNNING IT, not by a
                                                // test: `UserKey::load` returns
                                                // None on a JOINED device, because
                                                // a fleet member has no user
                                                // signing key. Deriving the
                                                // resource from it therefore made
                                                // every fleet member refuse every
                                                // route, which is precisely the
                                                // population subnet routes exist
                                                // for. The owner's PUBLIC key is
                                                // carried in the device's own
                                                // certificate, which the owner
                                                // signed, so a joined device knows
                                                // it without holding anything
                                                // secret.
                                                let owner_pk = owner_pub_for_resources();
                                                let idev = conn
                                                    .link(&pid)
                                                    .and_then(|l| l.identity_device_pub);
                                                let iusr = conn
                                                    .link(&pid)
                                                    .and_then(|l| l.identity_user_pub);
                                                // A DELEGATED principal's authority
                                                // is its enrollment ceiling, which
                                                // the owner signed inside the
                                                // invitation and enrollment
                                                // verified. That is the same source
                                                // transfer and mount are authorized
                                                // from, so route reads it too.
                                                //
                                                // Why it is needed at all: no grant
                                                // can bind to a fleet member (a
                                                // CapOp targets the owner user key
                                                // that every member presents, so it
                                                // cannot name one device), which is
                                                // why `grant` refuses outright. With
                                                // only the cap-store path, a router
                                                // that is a fleet member could never
                                                // be authorized by any route at all.
                                                //
                                                // Read the ceiling from the PERSISTED
                                                // record, not from the link's
                                                // principal. Which admission path ran
                                                // decides what the link says: a peer
                                                // that reconnects through fleet-hello
                                                // is admitted by admit_fleet as
                                                // FleetDevice, which carries no caps
                                                // at all, while only a fresh
                                                // enrollment produces Delegated{caps}.
                                                // Matching on Delegated therefore
                                                // worked exactly once per join and
                                                // silently stopped after the first
                                                // reconnect. The stored ceiling is the
                                                // same source `devices` renders and
                                                // `grant` consults, so all three agree
                                                // by construction.
                                                //
                                                // SCOPED, not a bare yes. The ceiling
                                                // entries are `route:<cidr>`, taken
                                                // from the signed invitation, so this
                                                // asks whether the advertised prefix
                                                // is INSIDE one the owner allowed. A
                                                // bare `route` used to authorise every
                                                // prefix a member cared to advertise,
                                                // 0.0.0.0/0 included, which is an exit
                                                // node the owner never agreed to.
                                                let ceiling_routes: Vec<String> =
                                                    principal_ceiling_for(&who)
                                                        .unwrap_or_default()
                                                        .iter()
                                                        .filter_map(|c| {
                                                            c.strip_prefix("route:")
                                                                .map(str::to_string)
                                                        })
                                                        .collect();
                                                let ok = crate::l3::installable_routes(
                                                    &advertised,
                                                    accept,
                                                    |cidr| {
                                                        if crate::capability::cidr_within_any(
                                                            cidr,
                                                            &ceiling_routes,
                                                        ) {
                                                            return true;
                                                        }
                                                        let Some(pk) = owner_pk else {
                                                            return false;
                                                        };
                                                        let Ok(res) =
                                                            crate::capability::route_resource_id(
                                                                &pk, cidr,
                                                            )
                                                        else {
                                                            return false;
                                                        };
                                                        matches!(
                                                            crate::capability::cap_authorize(
                                                                &config_dir,
                                                                &res,
                                                                crate::capability::CAP_ROUTE,
                                                                idev.as_ref(),
                                                                iusr.as_ref(),
                                                                None,
                                                            ),
                                                            crate::capability::CapOutcome::Authorized
                                                        )
                                                    },
                                                );
                                                let declined = advertised.len() - ok.len();
                                                if declined > 0 {
                                                    // Say so rather than silently
                                                    // dropping: an advertisement
                                                    // that vanishes without a word
                                                    // is indistinguishable from one
                                                    // that was never sent.
                                                    ui::debug(&format!(
                                                        "  {declined} of {} route(s) from {who} not installed (accept-routes={accept}, or not granted)",
                                                        advertised.len()
                                                    ));
                                                }
                                                // ALWAYS restate, including the
                                                // empty case. set_peer_subnets is
                                                // a full restatement of what this
                                                // peer carries, so an empty list
                                                // is how a WITHDRAWAL is applied.
                                                // Skipping it left a withdrawn
                                                // route installed forever: the
                                                // operator ran
                                                // `set advertise-routes ''`, the
                                                // peer stopped advertising, and
                                                // the receiver kept routing
                                                // through it. With an exit node
                                                // that is not a stale route, it
                                                // is a machine with a default
                                                // route pointing into a tunnel
                                                // nobody is carrying.
                                                l3.set_peer_subnets(&pid, &t, &ok).await;
                                                if !ok.is_empty() {
                                                    ui::say(&format!(
                                                        "  {} routes via {who}: {}",
                                                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                                        ok.join(", ")
                                                    ));
                                                }
                                            }
                                        }
                                        Err(e) => ui::debug(&ui::paint(
                                            ui::Tone::Warn,
                                            &format!("  L3 announce rejected: {e}"),
                                        )),
                                    },
                                    // Transport not installed yet: kept in l3_seen, replayed on ChannelReady.
                                    None => {}
                                }
                            }
                        }
                        Err(e) => ui::debug(&format!("  L3 malformed announce: {e}")),
                    }
                }
                // #30: respond to identity nonce challenge by producing a
                // possession_sig (0x02) over the peer-provided nonce. The
                // challenger verifies and upgrades our binding to Proven.
                Some("identity-nonce-challenge") => {
                    // #30: shared responder (also used by send_cmd) proves
                    // device-key possession so the challenger upgrades us to Proven.
                    if let Some(t) = conn.transport_of(&pid) {
                        respond_to_identity_challenge(&t, &v).await;
                    }
                }
                // #30: received possession-sig from peer after our challenge.
                // Verify, upgrade binding to Proven so capability gates pass.
                Some("identity-expose") => {
                    if handle_identity_expose(&mut conn, &pid, &v, &mut identity_nonces) {
                        // Release held ChannelReady — Proven settled before timeout.
                        if let Some((held_t, _deadline)) =
                            st.pending_proven.lock().unwrap().remove(&pid)
                        {
                            let _ = tx.send(Ev::ChannelReady(pid, held_t));
                        }
                    }
                }
                Some("worker-ports") => {
                    let pid = v["for"].as_str().unwrap_or_default();
                    ui::trace(&format!(
                        "[T:CLI] worker-ports handler: looking up key={pid}"
                    ));
                    if let Some(tx) = conn.worker_port_tx.remove(pid) {
                        ui::trace(&format!("[T:CLI] worker-ports handler: FOUND key={pid}"));
                        let ports: Vec<u16> = v["ports"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|p| p.as_u64().map(|x| x as u16))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let _ = tx.send(ports);
                    }
                }
                // WireGuard key announcement. Symmetric: whoever hears one
                // configures that peer and answers with its own if it has not
                // already, so two messages converge and neither end waits for
                // the other to move first. This rides the control channel
                // because an out-of-band QUIC stream races with filament's own
                // stream acceptor: the first version opened one and both ends
                // hung after creating their interface.
                Some("wg-key") => {
                    let enabled = crate::settings::get_str("wireguard", None)
                        .map(|x| x == "on" || x == "true")
                        .unwrap_or(false);
                    if enabled && crate::wg::usable() {
                        let peer_pub = v["pubkey"].as_str().unwrap_or_default().to_string();
                        let peer_port = v["port"].as_u64().unwrap_or(0) as u16;
                        let underlay = conn.transport_of(&pid).and_then(|t| t.remote_addr());
                        let peer_overlay =
                            l3.as_ref().map(|l| l.peer_overlay_of(&pid)).unwrap_or(None);
                        let ours = l3
                            .as_ref()
                            .and_then(|l| l.my_addr())
                            .map(|a| a.to_string())
                            .unwrap_or_default();
                        match (underlay, peer_overlay) {
                            (Some(sa), Some(po)) if !peer_pub.is_empty() && peer_port != 0 => {
                                match crate::wg::local_offer() {
                                    Ok((our_pub, our_port)) => {
                                        // The peer's real endpoint and port are
                                        // no longer needed: WireGuard talks to a
                                        // loopback stand-in and filament carries
                                        // the frames, so NAT never sees a
                                        // WireGuard packet.
                                        if let Err(e) = crate::wg::adopt_peer(
                                            &peer_pub,
                                            &po.to_string(),
                                            &ours,
                                            1380,
                                            sa.ip(),
                                            peer_port,
                                        )
                                        .await
                                        {
                                            ui::debug(&format!("  wg: could not adopt peer ({e})"));
                                        } else {
                                            ui::say(&format!(
                                                "  {} WireGuard tunnel to {}",
                                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                                conn.link(&pid)
                                                    .map(|l| l.shown())
                                                    .unwrap_or_default()
                                            ));
                                        }
                                        // Answer once, so the other end can
                                        // adopt us too. claim_attempt makes this
                                        // idempotent across repeats.
                                        if crate::wg::claim_attempt(&po.to_string()) {
                                            if let Some(t) = conn.transport_of(&pid) {
                                                let _ = t
                                                    .send_control(&json!({
                                                        "type": "wg-key",
                                                        "pubkey": our_pub,
                                                        "port": our_port,
                                                    }))
                                                    .await;
                                            }
                                        }
                                    }
                                    Err(e) => ui::debug(&format!("  wg: no local interface ({e})")),
                                }
                            }
                            _ => ui::debug(
                                "  wg: key announcement ignored (no direct endpoint or overlay address yet)",
                            ),
                        }
                    }
                }
                // Certificate renewal. Expiry is the only bound this system has,
                // so renewal is also how removal works: an owner that stops
                // renewing evicts a device without needing to reach it.
                Some("identity-cert-renew-request") => {
                    respond_to_cert_renew_request(&mut conn, pid.clone()).await;
                }
                Some("identity-cert-renew-ack") => {
                    handle_cert_renew_ack(&v).await;
                }
                Some("identity-cert-renew-error") => {
                    // Deliberately quiet and deliberately not fatal. A refusal
                    // may mean "removed", but it may equally mean the peer we
                    // asked is not a primary. Falling out at expiry is the
                    // correct failure direction either way, so we simply keep
                    // the certificate we have and ask again on the next link.
                    ui::debug("  peer declined to renew our certificate");
                }
                // Auth key enrollment (challenge/response flow)
                Some("identity-auth-key-enroll-request") => {
                    respond_to_auth_key_enroll_request(&mut conn, pid.clone(), v.clone()).await;
                }
                Some("identity-auth-key-enroll-response") => {
                    // Daemon receives the enrollment response with possession proofs.
                    // Must have a pending challenge nonce for this peer.
                    handle_auth_key_enroll_response(&mut conn, pid.clone(), v.clone()).await;
                    // A successful join adds a reconnect secret. Refresh the
                    // daemon's live channel set immediately; waiting for restart
                    // would make the persisted ceiling correct but unreachable.
                    devices = devices_load();
                    sess.channels = devices
                        .iter()
                        .map(|(_, secret)| channel_of(secret))
                        .collect();
                    if let Some(fc) = fleet::channel() {
                        if !sess.channels.contains(&fc) {
                            sess.channels.push(fc);
                        }
                    }
                    sess.invalidate();
                }
                Some("depart") => {
                    // Advisory goodbye: a joined device asks to free its slot NOW.
                    // Verify possession of the claimed device_pub, then mark the
                    // record lapsed immediately. Never load-bearing: if this
                    // message never arrives, the offline budget lapses it anyway.
                    let dpub_hex = v["device_pub"].as_str().unwrap_or_default();
                    let msg = v["msg"].as_str().unwrap_or_default();
                    let sig_hex = v["sig"].as_str().unwrap_or_default();
                    if let (Ok(dpub), Ok(sig)) = (hex::decode(dpub_hex), hex::decode(sig_hex)) {
                        if let (Ok(dpub_arr), Ok(sig_arr)) = (
                            dpub.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            sig.as_slice().try_into().map(|a: &[u8; 64]| *a),
                        ) {
                            if crate::identity::verify_possession_sig(
                                &dpub_arr,
                                msg.as_bytes(),
                                &sig_arr,
                            )
                            .is_ok()
                            {
                                if let Some(name) = mark_lapsed_now(&dpub_arr) {
                                    ui::say(&format!(
                                        "{} {name} departed; slot freed immediately",
                                        ui::paint(ui::Tone::Dim, "·")
                                    ));
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t
                                            .send_control(
                                                &json!({"type": "depart-ack", "name": name}),
                                            )
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                }
                // Owner-signed mesh roster push (v1, display-only). Verify
                // against the owner key held in OUR device certificate (the
                // issuer), accept only a newer (epoch, valid_until), store for
                // `devices` to render. The roster NEVER feeds an authorization
                // decision, so a failed receipt (bad sig / wrong owner / replay /
                // expired) is a silent no-op, logged at debug only.
                Some("roster") => {
                    if let Some(cert) = local_device_cert() {
                        match crate::roster::verify_and_store_roster(
                            &v,
                            &cert.user_pub,
                            identity::now_secs(),
                        ) {
                            Ok(true) => ui::debug(&format!(
                                "roster: accepted epoch {} from owner",
                                v["epoch"].as_u64().unwrap_or(0)
                            )),
                            Ok(false) => {}
                            Err(e) => ui::debug(&format!("roster: rejected: {e}")),
                        }
                    }
                }
                _ if !conn.links.contains_key(&pid) => {}
                // Warm-reuse liveness: the acceptor confirmed a stream WE initiated
                // (a warm `open`) is connected end to end. Route it to the mux so
                // verify_first_frame passes even for a client-speaks-first service
                // (HTTP, DB clients) that sends no bytes until we do, instead of the
                // verify window expiring and a HEALTHY link being dropped as a zombie
                // (which made every warm `forward` fall to a cold link). See
                // l2::Mux::on_open_ack.
                Some("l2-open-ack") if l2_enabled => {
                    if let Some(sid) = l2::wire_sid(&v) {
                        if let Some(mux) = l2_muxes.get(&pid) {
                            mux.on_open_ack(sid).await;
                        }
                    }
                }
                // L2 (ssh/TCP tunnel) acceptor. Opt-in (FILAMENT_L2=1). The
                // capability gate is the proof-verified `trusted` flag on this
                // link (placeholder for L1-a caps); localhost-only is enforced in
                // accept_control. A non-trusted or non-loopback open is refused.
                // `l2_enabled` answers "will I ACCEPT inbound stream opens", which
                // is the right gate for `l2-open` and the WRONG one for
                // `l2-close`. A close is the peer answering a stream WE opened, and
                // a node that accepts no inbound opens still opens outbound ones.
                // Gating both on it meant a refusal ("shell capability not
                // granted") was silently discarded by the very client that asked,
                // which then waited out its 2500ms verify window, declared the link
                // a zombie, and fell through to a 45s cold establish that reported
                // "can't reach". The answer had arrived in milliseconds.
                // `l2-open` stays gated; the body already no-ops the authorization
                // check for a close.
                Some("l2-close") | Some("l2-open")
                    if l2_enabled || v["type"].as_str() == Some("l2-close") =>
                {
                    // TODO(diag acceptor): emit a diag::Attempt with role
                    // "acceptor" for this l2-open->l2-open-ack round trip. Deferred
                    // because the acceptor has no per-connect span here: this fires
                    // on an ALREADY-established shared link inside the big up/recv
                    // loop (the link's bring-up lives in the file-transfer/recv
                    // machinery upstream), so a clean span would mean threading an
                    // Attempt through the whole loop. The initiator path (l2.rs) is
                    // fully instrumented and is the side that exhibits the stall.
                    let Some(t) = conn.transport_of(&pid) else {
                        continue;
                    };
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Per-device authorization for a NEW open (an l2-close just
                    // tears a stream down, so it is never gated here). In a blanket
                    // mode any trusted peer may open; in grant-only mode the opening
                    // peer must hold the shell grant itself.
                    let mut l2_deny_reason: Option<String> = None;
                    let authorized = v["type"].as_str() != Some("l2-open") || {
                        let legacy_ok = {
                            let blanket = shell_policy.enables_l2()
                                || std::env::var("FILAMENT_L2")
                                    .map(|x| x == "1")
                                    .unwrap_or(false);
                            let peer_has_shell = conn
                                .link(&pid)
                                .and_then(|l| l.verified_name.as_deref())
                                .map(|n| device_allows(n, "shell"))
                                .unwrap_or(false);
                            l2_open_allowed(blanket, peer_has_shell)
                        };
                        let az = peer_authz(&mut conn, &pid);
                        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_SHELL,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        // Fleet scope for `reach`: a same-owner Proven device may
                        // open an l2 forward WITHOUT a grant ONLY to a port the
                        // owner has explicitly exposed (`expose.json`). A forward to
                        // any other port is reach-all (deliberate) and needs a grant.
                        let reach_port = v["rport"]
                            .as_u64()
                            .or_else(|| v["port"].as_u64())
                            .unwrap_or(0) as u16;
                        let scoped_in_bounds = reach_port != 0
                            && crate::expose::load().iter().any(|b| b.port == reach_port);
                        let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_SHELL,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        let d = crate::capability::cap_gate_effective(
                            legacy_ok,
                            &outcome,
                            crate::capability::CAP_SHELL,
                            "self",
                            idev,
                            iusr,
                            binding,
                            expires,
                            ak_caps,
                            own_user.as_ref(),
                            scoped_in_bounds,
                            has_grant,
                            cert_revoked,
                        );
                        if let crate::capability::GateDecision::Deny {
                            cap_reason: Some(r),
                        } = &d
                        {
                            l2_deny_reason = Some(r.clone());
                        }
                        d.allowed()
                    };
                    if !authorized {
                        // wire_sid (not a wrapping cast) so the l2-close we echo
                        // back names the real sid; 0 only if absent/out-of-range.
                        let sid = l2::wire_sid(&v).unwrap_or(0);
                        let diag = l2_deny_reason
                            .as_deref()
                            .unwrap_or("device not granted shell");
                        ui::say(&format!("l2: refused stream {sid:#x}: {diag}"));
                        let _ = t
                            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "not authorized: device lacks shell grant" }))
                            .await;
                    } else {
                        // Opt-in gateway: if the target is non-loopback, allow it
                        // only when the operator's l2-allow.json lists it for this
                        // device (or "*"). Loopback ignores this (always allowed).
                        let allow_nonloopback = {
                            let host = v["host"].as_str().unwrap_or("127.0.0.1");
                            let port = v["rport"]
                                .as_u64()
                                .or_else(|| v["port"].as_u64())
                                .unwrap_or(0) as u16;
                            let name = conn
                                .link(&pid)
                                .and_then(|l| l.verified_name.clone())
                                .unwrap_or_default();
                            l2_target_allowed(&name, host, port)
                        };
                        let mux = l2_muxes
                            .entry(pid.clone())
                            .or_insert_with(|| l2::Mux::new(t.clone()))
                            .clone();
                        match mux.accept_control(&v, trusted, allow_nonloopback).await {
                            l2::OpenVerdict::Accept {
                                sid,
                                host,
                                port,
                                rx,
                            } => {
                                // The peer's device key, resolved again for the live
                                // stream's revocation re-check (the gate above resolved
                                // the same value for the open decision).
                                let spawn_idev =
                                    conn.link(&pid).and_then(|l| l.identity_device_pub);
                                tokio::spawn(
                                    mux.clone().dial_and_serve(sid, host, port, rx, spawn_idev),
                                );
                            }
                            l2::OpenVerdict::Deny { sid, err } => {
                                // Log refused dials at INFO (visible by default,
                                // suppressed under -q) - a refused SSRF/port-scan or
                                // untrusted/over-cap open is a security event the
                                // operator should see, mirroring the
                                // shell-bootstrap-deny path (`ui::say`). Normal
                                // initiators always dial 127.0.0.1, so this is silent
                                // in normal operation and only fires on an anomaly.
                                ui::say(&format!("l2: refused stream {sid:#x}: {err}"));
                                let _ = t
                                    .send_control(
                                        &json!({ "type": "l2-close", "sid": sid, "err": err }),
                                    )
                                    .await;
                            }
                            l2::OpenVerdict::Ignore => {}
                        }
                    }
                    // A PTY stream closing frees its resize channel, handled by
                    // the mux's `on_close`/`drop_stream` (H-1: resizer is owned by
                    // the mux now, so it can't leak past the stream).
                }
                // Seamless-shell bootstrap (acceptor). Opt-in (FILAMENT_L2=1).
                // DENY-BY-DEFAULT: install the initiator's managed pubkey ONLY
                // when the link is proof-verified (`trusted`) AND the proven
                // device holds the NEW `shell` capability, distinct from
                // `transfer`, so pairing for file transfer never yields a shell.
                // The write happens only here (over the authenticated channel)
                // into a clearly-marked, removable authorized_keys block.
                // Warm-bootstrap (INITIATOR side): the peer answered a
                // `shell-bootstrap` we relayed over its warm link for a `filament
                // ssh`. Complete the stashed reply socket(s) for this pid; the
                // client then pins these host keys and skips the cold establish.
                #[cfg(unix)]
                Some("shell-bootstrap-ack") => {
                    let reply = json!({
                        "ok": true,
                        "hostkeys": v["hostkeys"].clone(),
                        "user": v["user"].clone(),
                        "sshd": v["sshd"].clone(),
                    });
                    complete_warm_bootstrap(&mut pending_bootstrap, &pid, &reply).await;
                }
                #[cfg(unix)]
                Some("shell-bootstrap-deny") => {
                    let reply = json!({
                        "ok": false,
                        "err": v["reason"].as_str().unwrap_or("shell bootstrap denied"),
                    });
                    complete_warm_bootstrap(&mut pending_bootstrap, &pid, &reply).await;
                }
                // #268: an `l2-open` arriving while L2 is OFF used to fall
                // through and be IGNORED. The initiator has already committed a
                // client to that stream, so it waits for an answer that is never
                // coming: measured cross-machine, curl hung for its full 25s
                // timeout while filament printed nothing at either end.
                //
                // `shell-bootstrap` directly below already refuses explicitly in
                // this exact state. The tunnel open, which is the more common
                // path (`forward`, `netcat`, ssh), did not, so the two disagreed
                // about whether "off" is something you say or something you
                // silently do.
                //
                // `on_close` turns this into OpenOutcome::Refused with the reason
                // (#206), so the client gets a clean, immediate, explained close
                // instead of a hang.
                Some("l2-open") if !l2_enabled => {
                    if let (Some(t), Some(sid)) = (conn.transport_of(&pid), v["sid"].as_u64()) {
                        let _ = t
                            .send_control(&json!({
                                "type": "l2-close",
                                "sid": sid,
                                "err": crate::capability::TUNNEL_OFF_REASON,
                            }))
                            .await;
                    }
                    continue;
                }
                // exec-open when serving is off: refuse loudly like l2-open, so
                // the caller errors instead of hanging on a silent drop.
                Some("exec-open") if !l2_enabled => {
                    if let (Some(t), Some(sid)) = (conn.transport_of(&pid), v["sid"].as_u64()) {
                        let _ = t
                            .send_control(&json!({
                                "type": "l2-close",
                                "sid": sid,
                                "err": crate::capability::SHELL_OFF_REASON,
                            }))
                            .await;
                    }
                    continue;
                }
                // NOTE: keep this arm ABOVE the `#[cfg(unix)]` comment block
                // below. That attribute belongs to `shell-bootstrap`, and an
                // outer attribute binds to the NEXT arm regardless of any
                // comments in between: inserting here originally compiled this
                // refusal out on Windows AND silently made the shell-bootstrap
                // deny unconditional there. Found in review, not by the compiler,
                // because both outcomes still build.
                // Shell serving is OFF here. Without this arm the message falls
                // through the match and the acceptor says NOTHING, so the caller
                // can only time out: `filament shell X --ssh` burned its full
                // bootstrap deadline and then guessed, while plain
                // `filament shell X` printed the reason immediately. The refusal
                // exists; only this path failed to send it. Measured across three
                // machines, not inferred.
                #[cfg(unix)]
                Some("shell-bootstrap") if !l2_enabled => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let _ = t
                            .send_control(&json!({
                                "type": "shell-bootstrap-deny",
                                "reason": crate::capability::SHELL_OFF_REASON,
                            }))
                            .await;
                    }
                    continue;
                }
                Some("shell-bootstrap") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else {
                        continue;
                    };
                    // #30 GAP 2 (shell): honor the pending_proven hold. If a
                    // possession-sig challenge is still in flight for this peer
                    // and the binding is not yet Proven, do NOT refuse on
                    // Inferred: the identity-expose that flips us to Proven is a
                    // SEPARATE event this single-consumer loop must process, so
                    // blocking inline would deadlock. Re-inject the bootstrap
                    // shortly and let the loop drain. The hold entry clears on
                    // Proven OR at the 3s deadline, so this self-terminates and
                    // the re-injected bootstrap is then decided for real.
                    if crate::capability::cap_authoritative() {
                        let challenge_in_flight =
                            st.pending_proven.lock().unwrap().contains_key(&pid);
                        let proven = conn
                            .link(&pid)
                            .map(|l| {
                                l.identity_binding == crate::capability::BindingStrength::Proven
                            })
                            .unwrap_or(false);
                        if challenge_in_flight && !proven {
                            let rtx = tx.clone();
                            let rpid = pid.clone();
                            let rv = v.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(80)).await;
                                let _ = rtx.send(Ev::Control(rpid, rv));
                            });
                            continue;
                        }
                    }
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Cap lookup keys on the PROVEN petname, not the presence name.
                    let dev = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    // Granted if the device was explicitly `grant`ed shell OR an
                    // active `up --shell[-only]` policy auto-allows it. Trust
                    // (pair-proof) is still required either way.
                    let legacy_ok = trusted
                        && dev
                            .as_deref()
                            .map(|n| {
                                !device_capability_denied(n, "shell")
                                    && (shell_policy.auto_allows(n) || device_allows(n, "shell"))
                            })
                            .unwrap_or(false);
                    // Capability layer evaluated unconditionally (shadow samples the
                    // legacy-allowed population); legacy stands in shadow, cap gates
                    // under FILAMENT_CAP_AUTHORITATIVE.
                    let granted = {
                        let az = peer_authz(&mut conn, &pid);
                        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_SHELL,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        {
                            let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                                &crate::settings::config_dir(),
                                "self",
                                crate::capability::CAP_SHELL,
                                idev,
                                iusr,
                                ak_caps,
                            );
                            // Deliberate tier: `shell` is never a scoped default, so a
                            // same-owner device gets it ONLY via an explicit grant
                            // (has_grant), never fleet auto-trust (scoped_in_bounds=false).
                            crate::capability::cap_gate_effective(
                                legacy_ok,
                                &outcome,
                                crate::capability::CAP_SHELL,
                                "self",
                                idev,
                                iusr,
                                binding,
                                expires,
                                ak_caps,
                                own_user.as_ref(),
                                false,
                                has_grant,
                                cert_revoked,
                            )
                        }
                    };
                    if !granted.allowed() {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        ui::say(&format!(
                            "l2: shell bootstrap refused: {who}: {}",
                            granted.deny_reason("no shell cap / untrusted")
                        ));
                        enqueue_if_requestable(who, "shell");
                        let _ = t
                            .send_control(&json!({
                                "type": "shell-bootstrap-deny",
                                "reason": "shell capability not granted"
                            }))
                            .await;
                        continue;
                    }
                    let device = dev.unwrap();
                    let pubkey = v["pubkey"].as_str().unwrap_or_default().to_string();
                    // M-3 (authorized_keys injection): a single, well-formed key
                    // line ONLY. validate_pubkey rejects interior newlines / CR /
                    // control chars and multi-line payloads, so a trusted+shell
                    // peer can't inject extra authorized_keys lines. Enforced here
                    // AND again inside install_authorized_key (defense in depth).
                    let pubkey = match sshkeys::validate_pubkey(&pubkey) {
                        Ok(k) => k,
                        Err(e) => {
                            ui::say(&format!(
                                "l2: shell bootstrap refused: malformed pubkey from '{device}': {e}"
                            ));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "malformed pubkey"
                                }))
                                .await;
                            continue;
                        }
                    };
                    match sshkeys::install_authorized_key(&device, &pubkey) {
                        Ok(()) => {
                            let hostkeys = sshkeys::host_pubkeys();
                            let login = std::env::var("USER").unwrap_or_else(|_| "root".into());
                            // Tell the initiator whether an sshd is actually
                            // listening on the port `filament shell --ssh` will dial here,
                            // so it can fail fast with a clear message instead of
                            // spawning ssh into a refused/black-holed connection.
                            let ssh_port = v["ssh_port"]
                                .as_u64()
                                .and_then(|n| u16::try_from(n).ok())
                                .unwrap_or(22);
                            let sshd = sshd_listening(ssh_port).await;
                            ui::say(&format!(
                                "l2: shell granted to '{device}', installed managed key (filament-managed block)"
                            ));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-ack",
                                    "hostkeys": hostkeys,
                                    "user": login,
                                    "sshd": sshd,
                                    "ssh_port": ssh_port
                                }))
                                .await;
                        }
                        Err(e) => {
                            ui::say(&format!(
                                "l2: shell bootstrap install failed for '{device}': {e}"
                            ));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "install failed"
                                }))
                                .await;
                        }
                    }
                }
                // web-shell (browser terminal): spawn a login shell in a PTY and
                // bridge it to a sid stream. Same deny-by-default gate as
                // shell-bootstrap, a PTY is a superset of ssh-key access, so it
                // reuses the `shell` cap / --shell policy and requires `trusted`.
                Some("pty-open") => {
                    let Some(t) = conn.transport_of(&pid) else {
                        continue;
                    };
                    // #219: the acceptor is OFF (plain `up`, no --shell/--shell-only,
                    // no FILAMENT_L2). The peer is visibly up but cannot serve a
                    // shell, and dropping the open silently made `shell` hang with
                    // no output. Say so, so the initiator errors instead of waiting.
                    if !l2_enabled {
                        let sid = l2::wire_sid(&v).unwrap_or(0);
                        let _ = t
                            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "shell serving is off there; run `filament up --shell` on that device" }))
                            .await;
                        continue;
                    }
                    // wire_sid rejects a missing OR out-of-range sid instead of
                    // defaulting to 0 / wrapping into a forged is_l2_sid value.
                    let Some(sid) = l2::wire_sid(&v) else {
                        continue;
                    };
                    if !l2::is_l2_sid(sid) {
                        continue;
                    }
                    // One shared shell gate (same function, same inputs as
                    // exec-open): gather, then the pty entry point. The tells
                    // below stay local; only the verdict is shared.
                    let (dev, gate_inputs) =
                        crate::shell_gate::gather_shell_gate_inputs(&mut conn, &pid, &shell_policy);
                    if let Err(cap_reason) = crate::shell_gate::pty_gate_decision(&gate_inputs) {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        ui::say(&format!(
                            "l2: pty refused: {who}: {}",
                            cap_reason.as_deref().unwrap_or("no shell cap / untrusted")
                        ));
                        enqueue_if_requestable(who, "shell");
                        // Carry the specific cap reason (e.g. CEILING_REASON,
                        // "device revoked") to the peer; the generic string was
                        // produced and then thrown away before it crossed the wire,
                        // so the initiator read an empty success instead of the
                        // refusal. The fallback stays coarse on purpose.
                        let reason = cap_reason.unwrap_or_else(|| "shell capability not granted".to_string());
                        let _ = t
                            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": reason }))
                            .await;
                        continue;
                    }
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    // #4: a stable, client-chosen session id binds reconnects to
                    // the same persistent PTY. DEVICE-SCOPED: prefixed with the
                    // verified device so a client id from device A can never
                    // address device B's session (no cross-device collision or
                    // hijack) - the random per-invocation client id then only
                    // needs to be unique per device. Absent (older client) -> a
                    // per-sid id that never reattaches (old behavior).
                    let session_id = match v["session"]
                        .as_str()
                        .filter(|s| !s.is_empty() && s.len() <= 128)
                    {
                        Some(s) => format!("{}\u{1}{}", dev.as_deref().unwrap_or(&pid), s),
                        None => format!("{pid}:{sid:#x}"),
                    };
                    // $TERM forwarded by the client (so the remote matches the
                    // user's actual terminal); validated + capped, sane default.
                    let term = v["term"]
                        .as_str()
                        .filter(|s| {
                            !s.is_empty()
                                && s.len() <= 64
                                && s.bytes().all(|b| b.is_ascii_graphic())
                        })
                        .unwrap_or("xterm-256color")
                        .to_string();
                    // One-shot command (non-empty when pty one-shot was requested).
                    let pty_cmd = v["cmd"].as_str().unwrap_or("").to_string();
                    // RESUME-ONLY (warm-drop fall-through): the client wants to
                    // REATTACH an existing session and never start a fresh shell, so a
                    // clean warm exit can't turn into a surprise re-login.
                    let resume = v["resume"].as_bool().unwrap_or(false);
                    let mux = l2_muxes
                        .entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    // #4 REATTACH: a live session for this id means a reconnect.
                    // Rebind its output to THIS link+sid and replay its buffer; do
                    // not spawn a new shell. Register the input pump + resizer for
                    // the new sid so typing and SIGWINCH reach the surviving PTY.
                    if let Some(sess) = pty_sessions.get_live(&session_id).await {
                        if mux.at_stream_cap().await {
                            ui::say("l2: pty reattach refused: too many streams on this link");
                            let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                            continue;
                        }
                        // Collision-safe: if this sid is already live (peer reused
                        // a live forward/pty/mount sid) register refuses; deny the
                        // reattach rather than displacing the existing stream.
                        let Some(rx) = mux.register_stream(sid).await else {
                            ui::say(&format!("l2: pty reattach refused: sid {sid:#x} in use"));
                            let _ = t
                                .send_control(
                                    &json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }),
                                )
                                .await;
                            continue;
                        };
                        let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<(u16, u16)>();
                        mux.register_resizer(sid, rtx).await;
                        let _ = t
                            .send_control(&json!({ "type": "pty-open-ack", "sid": sid }))
                            .await;
                        sess.attach(t.clone(), sid);
                        sess.resize(cols, rows);
                        pty_bindings
                            .entry(pid.clone())
                            .or_default()
                            .insert(sid, session_id.clone());
                        spawn_session_pumps(sess.clone(), rx, rrx);
                        ui::say(&format!(
                            "l2: pty REATTACHED to '{}', {cols}x{rows}",
                            dev.unwrap_or_default()
                        ));
                        continue;
                    }
                    // Resume-only + no live session: the client is a warm-drop
                    // fall-through and the session is gone (the shell exited cleanly).
                    // Close instead of spawning a fresh shell, so the client exits
                    // cleanly rather than getting a surprise re-login.
                    if resume {
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no such session" })).await;
                        continue;
                    }
                    // H-1 (DoS): refuse over the per-link stream cap or the global
                    // PTY cap BEFORE spawning a shell. A flaky/hostile paired
                    // device can otherwise flood `pty-open` and exhaust threads.
                    if mux.at_stream_cap().await {
                        ui::say("l2: pty refused: too many streams on this link");
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                        continue;
                    }
                    let Some(pty_guard) = l2::PtyGuard::try_acquire() else {
                        ui::say(&format!(
                            "l2: pty refused: too many PTYs (global cap {})",
                            l2::MAX_PTYS_GLOBAL
                        ));
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                        continue;
                    };
                    // before spawn (race fix). Collision-safe: refuse (don't
                    // displace) if the peer named an already-live sid. `pty_guard`
                    // drops on `continue`, freeing the global PTY slot it reserved.
                    let Some(rx) = mux.register_stream(sid).await else {
                        ui::say(&format!("l2: pty refused: sid {sid:#x} in use"));
                        let _ = t
                            .send_control(
                                &json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }),
                            )
                            .await;
                        continue;
                    };
                    let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<(u16, u16)>();
                    // Resizer is owned by the mux so it is freed on EVERY teardown
                    // path (inbound l2-close, link death), H-1.
                    mux.register_resizer(sid, rtx).await;
                    let _ = t
                        .send_control(&json!({ "type": "pty-open-ack", "sid": sid }))
                        .await;
                    // #4: spawn the PTY as a PERSISTENT session keyed by session_id,
                    // not a link-bound serve_pty. It outlives this link; a drop
                    // detaches it, a reconnect reattaches above.
                    // Resolve the shell and build interactive or one-shot argv.
                    let (shell_argv, _can_use_user) = shell_argv(None, shell_user.as_deref());
                    let host = platform::ShellHost::new(&shell_argv);
                    let argv = if pty_cmd.is_empty() {
                        host.interactive_args()
                    } else {
                        host.exec_cmd_args(&pty_cmd)
                    };
                    // The peer's device key, resolved again for the live session's
                    // revocation re-check (the gate above resolved the same value for
                    // the open decision; this is that same value).
                    let spawn_idev = conn.link(&pid).and_then(|l| l.identity_device_pub);
                    match l2::spawn_pty_session(
                        pty_sessions.clone(),
                        session_id.clone(),
                        t.clone(),
                        sid,
                        cols,
                        rows,
                        &term,
                        argv,
                        pty_guard,
                        spawn_idev,
                    )
                    .await
                    {
                        Some(sess) => {
                            pty_bindings
                                .entry(pid.clone())
                                .or_default()
                                .insert(sid, session_id.clone());
                            spawn_session_pumps(sess, rx, rrx);
                            ui::say(&format!(
                                "l2: pty granted to '{}', {cols}x{rows}",
                                dev.unwrap_or_default()
                            ));
                        }
                        None => {
                            // spawn already sent an l2-close{err}; free the stream.
                            mux.drop_pty(sid).await;
                        }
                    }
                }
                // Remote command execution: parse, shell-gate, direct-spawn
                // and serve. The module sends its own ack/close/refusal
                // replies; the arm only resolves the transport and the mux.
                Some("exec-open") => {
                    let Some(t) = conn.transport_of(&pid) else {
                        continue;
                    };
                    let mux = l2_muxes
                        .entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    exec_recv::handle_exec_open(&mut conn, &pid, t, mux, &v, &shell_policy).await;
                    continue;
                }
                Some("ssh-sign-request") if !l2_enabled => {
                    if let (Some(t), Some(sid)) = (conn.transport_of(&pid), v["sid"].as_u64()) {
                        let _ = t
                            .send_control(&json!({
                                "type": "l2-close",
                                "sid": sid,
                                "err": crate::capability::SHELL_OFF_REASON,
                            }))
                            .await;
                    }
                    continue;
                }
                // SSH certificate signing: parse, shell-gate (third path),
                // clamp, sign, reply. Pure control round trip (no stream);
                // the handler sends its own cert/refusal replies.
                Some("ssh-sign-request") => {
                    let Some(t) = conn.transport_of(&pid) else {
                        continue;
                    };
                    crate::ssh_ca::handle_ssh_sign(&mut conn, &pid, t, &v, &shell_policy).await;
                    continue;
                }
                Some("mount-open") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else {
                        continue;
                    };
                    // wire_sid rejects a missing OR out-of-range sid instead of
                    // defaulting to 0 / wrapping into a forged is_l2_sid value.
                    let Some(sid) = l2::wire_sid(&v) else {
                        continue;
                    };
                    if !l2::is_l2_sid(sid) {
                        continue;
                    }
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Decode the requested root up front: the fleet mount scope
                    // (read-only, within the share root) is decided at the gate.
                    let root_encoded = v["root"].as_str().unwrap_or(".");
                    let root_path = mount_proto::path_decode(root_encoded)
                        .unwrap_or_else(|_| std::path::PathBuf::from("."));
                    let within_share =
                        crate::path_within_canonical(&crate::fleet_share_root(), &root_path);
                    // Capability layer for mount evaluated unconditionally (shadow
                    // samples the legacy-allowed population); legacy (trusted) stands
                    // in shadow, cap gates under FILAMENT_CAP_AUTHORITATIVE.
                    let (authorized, read_only) = {
                        let az = peer_authz(&mut conn, &pid);
                        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_MOUNT,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        // Trust floor: under authoritative, an untrusted link
                        // must never authorize mount (pair-proof vs device-key).
                        let outcome = crate::capability::cap_trust_floor(
                            &outcome,
                            trusted,
                            binding,
                            crate::capability::cap_authoritative(),
                        );
                        // Fleet scope: a same-owner Proven device may mount WITHOUT a
                        // grant ONLY read-only, within the share root (scoped_in_bounds
                        // = within_share). An auto-trusted fleet mount is served
                        // READ-ONLY; an explicit `mount` grant keeps its rw behavior.
                        let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_MOUNT,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        let same_owner = match (iusr, own_user.as_ref()) {
                            (Some(u), Some(o)) => u == o,
                            _ => false,
                        };
                        // #42 HOLD-OUT (advisor call): the mount scoped-DEFAULT is not
                        // shipped in this release. It is not drivable today (filament
                        // mount has no --auth-key, and an OwnerDevice cannot reach
                        // Proven), so its scope enforcement (within_share /
                        // path_within_canonical + the read-only EROFS path) has NEVER
                        // been exercised end-to-end — shipping it would make the first
                        // real user its first test, and publish a capability no path can
                        // reach. Until mount is auth-key-drivable AND rig-verified
                        // (including a write attempt that MUST return EROFS), a fleet
                        // mount requires an EXPLICIT grant (deliberate tier). `within_share`
                        // stays computed so re-enabling #42 is a one-line flip back.
                        let _ = within_share;
                        let mount_scoped_default = false;
                        let read_only = same_owner
                            && binding == crate::capability::BindingStrength::Proven
                            && mount_scoped_default
                            && !has_grant;
                        let d = crate::capability::cap_gate_effective(
                            trusted,
                            &outcome,
                            crate::capability::CAP_MOUNT,
                            "self",
                            idev,
                            iusr,
                            binding,
                            expires,
                            ak_caps,
                            own_user.as_ref(),
                            mount_scoped_default,
                            has_grant,
                            cert_revoked,
                        );
                        (d, read_only)
                    };
                    if !authorized.allowed() {
                        let who = conn
                            .link(&pid)
                            .and_then(|l| l.verified_name.clone())
                            .unwrap_or_else(|| "<unverified>".into());
                        // Operator-side diagnostic in BOTH modes, so a mount refusal
                        // is never invisible on the default (shadow) path and never
                        // reads as a transport failure. The peer-facing string stays a
                        // coarse category and leaks no authz internals.
                        ui::say(&format!(
                            "mount: refused for '{who}': {}",
                            authorized.deny_reason("not authorized (mount capability required)")
                        ));
                        enqueue_if_requestable(&who, "mount");
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "not authorized: mount capability required" })).await;
                        continue;
                    }
                    let mut caps = mount_proto::mount_caps_for_root(&root_path);
                    // A read-only fleet share advertises zero writable size so a
                    // well-behaved client sees it is read-only; the server also
                    // hard-rejects every write with EROFS regardless of the ack.
                    if read_only {
                        caps.max_write_size = 0;
                    }
                    let mux = l2_muxes
                        .entry(pid.clone())
                        .or_insert_with(|| l2::Mux::new(t.clone()))
                        .clone();
                    if mux.at_stream_cap().await {
                        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
                        continue;
                    }
                    // Collision-safe: refuse (don't displace) if the peer named an
                    // already-live sid; otherwise a forward's read pump would be
                    // orphaned and its inbound frames redirected to this mount.
                    let Some(rx) = mux.register_stream(sid).await else {
                        let _ = t
                            .send_control(
                                &json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }),
                            )
                            .await;
                        continue;
                    };
                    let _ = t
                        .send_control(
                            &json!({ "type": "mount-open-ack", "sid": sid, "caps": caps }),
                        )
                        .await;
                    let transport = t.clone();
                    let spawn_sid = sid;
                    let proto_version = caps.protocol_version;
                    // #235: hand the peer's device key down so the live session can re-ask
                    // the gate. Resolved above for the open decision; the same value.
                    let spawn_idev = conn.link(&pid).and_then(|l| l.identity_device_pub);
                    mount_proto::spawn_mount_server(
                        root_path,
                        transport,
                        spawn_sid,
                        rx,
                        proto_version,
                        read_only,
                        spawn_idev,
                    );
                }
                Some("pty-resize") if l2_enabled => {
                    let Some(sid) = l2::wire_sid(&v) else {
                        continue;
                    };
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    // #4: resize the persistent session bound to this sid (not a
                    // link-local serve_pty). Falls back to the mux resizer if the
                    // sid isn't a known session binding (defensive).
                    if let Some(sid_map) = pty_bindings.get(&pid) {
                        if let Some(session_id) = sid_map.get(&sid) {
                            if let Some(sess) = pty_sessions.get_live(session_id).await {
                                sess.resize(cols, rows);
                            }
                        }
                    }
                    if let Some(mux) = l2_muxes.get(&pid) {
                        mux.resize_pty(sid, cols, rows).await;
                    }
                }
                // #4: explicit end of a persistent PTY session (the ✕ / unmount).
                // Distinct from a bare channel drop, which only DETACHES. Kills the
                // shell and removes the session so a later open spawns fresh.
                Some("pty-close") if l2_enabled => {
                    if let Some(session_id) = v["session"].as_str() {
                        if let Some(sess) = pty_sessions.get_live(session_id).await {
                            sess.end(); // kill the shell now
                        }
                        pty_sessions.remove(session_id).await;
                        if let Some(sid_map) = pty_bindings.get_mut(&pid) {
                            sid_map.retain(|_, v| v != session_id);
                        }
                    }
                }
                // Client confirmed the protocol version advertised in mount-open-ack.
                // The server is already running in that version; this control is
                // received and consumed here to prevent it from hitting the catch-all.
                Some("mount-cap-ack") if l2_enabled => {}
                Some("brb") => {
                    // C21: the peer announces a benign absence (mobile file
                    // picker suspends the tab). Hold the line that long.
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.rejoin.away =
                        Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    ui::say(&conn.roster(
                        &pid,
                        "●",
                        ui::Tone::Warn,
                        "away, choosing a file · holding the line",
                        &n,
                    ));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                // C30 phase 3: a state ping proves the peer is alive, clear
                // any away-mark (the receiver side has no sender corrections).
                Some("state") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                Some("pair-keep") => {
                    let sec = v["secret"].as_str().unwrap_or_default().to_string();
                    if sec.len() == 64 {
                        let kept = if let Some(name) = &remember {
                            devices_store(name, &sec)?;
                            ui::say(&format!(
                                "remembered this device as '{name}', future sends auto-accept after proof"
                            ));
                            true
                        } else if ceremony == Some(false) {
                            // C29: we typed their code into this session, the
                            // creator initiated first; that's our ceremony.
                            ceremony = None;
                            let n = conn
                                .link(&pid)
                                .map(|l| l.name.clone())
                                .unwrap_or_else(|| "device".into());
                            devices_store(&n, &sec)?;
                            devices.push((n.clone(), sec.clone()));
                            sess.channels.push(channel_of(&sec)); // C30: desire grows; session repairs
                            sess.touch();
                            sio.emit("subscribe", json!({ "channels": [channel_of(&sec)] }))
                                .await
                                .ok();
                            ui::say(&format!(
                                "  {} {} mutually remembered, rename anytime: filament devices rename {n} <new>",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                            true
                        } else {
                            ui::say(
                                "(sender offered to be remembered; re-run with --remember <name> to keep it)",
                            );
                            false
                        };
                        // C27: answer either way, a declined sender discards
                        // its half instead of waving at a dead meeting point.
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep-ack", "ok": kept }))
                                .await
                                .ok();
                        }
                    }
                }
                // C29: claimer fallback, the creator never initiated
                // (browsers don't); hand over OUR secret instead.
                Some("__pair_fallback") => {
                    if ceremony == Some(false) {
                        ceremony = None;
                        ceremony_pid = Some(pid.clone());
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(
                                &json!({ "type": "pair-keep", "secret": ceremony_secret }),
                            )
                            .await
                            .ok();
                        }
                    }
                }
                // C29: their answer to OUR in-session remember offer.
                Some("pair-keep-ack") => {
                    if ceremony_pid.as_deref() == Some(pid.as_str()) {
                        ceremony_pid = None;
                        let n = conn
                            .link(&pid)
                            .map(|l| l.name.clone())
                            .unwrap_or_else(|| "device".into());
                        if v["ok"].as_bool() == Some(false) {
                            ui::say(&conn.roster(
                                &pid,
                                ui::glyph_err(),
                                ui::Tone::Warn,
                                "declined to be remembered, nothing stored",
                                &n,
                            ));
                        } else {
                            devices_store(&n, &ceremony_secret)?;
                            devices.push((n.clone(), ceremony_secret.clone()));
                            sess.channels.push(channel_of(&ceremony_secret)); // C30
                            sess.touch();
                            sio.emit(
                                "subscribe",
                                json!({ "channels": [channel_of(&ceremony_secret)] }),
                            )
                            .await
                            .ok();
                            ceremony_secret = fresh_secret(); // never reuse across devices
                            ui::say(&format!(
                                "  {} {} mutually remembered, rename anytime: filament devices rename {n} <new>",
                                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                                ui::paint(ui::Tone::Bold, &n),
                            ));
                        }
                    }
                }
                Some("pair-proof") => {
                    let mac = v["mac"].as_str().unwrap_or_default();
                    let peer_uid = conn
                        .link(&pid)
                        .and_then(|l| l.uid.clone())
                        .unwrap_or_default();
                    let fps = match conn.link(&pid) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    let Some((my_fp, their_fp)) = fps else {
                        ui::debug("pair-proof received before fingerprints known, ignoring");
                        continue;
                    };
                    // #9: pair secrets are symmetric, our own install holds
                    // every secret we do, so a same-host process could prove
                    // "pop2" and tunnel callers into the WRONG machine. Refuse.
                    let hit = if is_self_uid(&conn.my_uid, Some(peer_uid.as_str())) {
                        ui::debug("pair-proof from our own install, refusing (self-connect)");
                        None
                    } else {
                        devices.iter().find(|(_, s)| {
                            proof_for(s, &peer_uid, &peer_uid, &conn.my_uid, &my_fp, &their_fp)
                                == mac
                        })
                    };
                    let ok = if let Some((n, _)) = hit {
                        if let Some(l) = conn.link_mut(&pid) {
                            l.trusted = true;
                            l.verified_name = Some(n.clone());
                            resolve_peer_identity(l);
                        }
                        // #39: identity just RESOLVED on the WebRTC/relay path — verified_name
                        // is set above and resolve_peer_identity populated device_pub. This is
                        // the resolution point for NON-direct links (ChannelReady fired before
                        // this); the direct path resolves at DirectReady adoption instead. Issue
                        // the possession challenge here so the link reaches Proven (fleet
                        // auto-trust is Proven-gated), authoritative only. The helper is
                        // idempotent — if DirectReady already challenged this pid the call is a
                        // no-op and does not clobber the in-flight nonce. The transport exists by
                        // construction (this handler was reached by a control message on it).
                        if crate::capability::cap_authoritative() {
                            let needs_proven = conn
                                .link(&pid)
                                .map(|l| {
                                    l.identity_device_pub.is_some()
                                        && l.identity_binding
                                            != crate::capability::BindingStrength::Proven
                                })
                                .unwrap_or(false);
                            if needs_proven {
                                if let Some(t) = conn.transport_of(&pid) {
                                    issue_proven_challenge_and_hold(
                                        &conn,
                                        &pid,
                                        &t,
                                        &st.pending_proven,
                                        &mut identity_nonces,
                                    )
                                    .await;
                                    ui::debug(&format!(
                                        "  identity challenge sent to {pid} at pair-proof (universal expose, WebRTC/relay path)"
                                    ));
                                    let hold_pending = st.pending_proven.clone();
                                    let hold_pid = pid.clone();
                                    tokio::spawn(async move {
                                        tokio::time::sleep(PROVEN_CHALLENGE_DEADLINE).await;
                                        hold_pending.lock().unwrap().remove(&hold_pid);
                                    });
                                }
                            }
                        }
                        ui::say(&format!("identity verified: '{n}' (auto-accepting)"));
                        true
                    } else {
                        // CRITICAL, a security verdict the user must see (-q too).
                        ui::critical(&ui::paint(
                            ui::Tone::Warn,
                            "pair-proof FAILED verification, treating peer as untrusted",
                        ));
                        false
                    };
                    // C27: tell the prover the verdict, a rejected prover
                    // learns we never met and stops claiming acquaintance.
                    if let Some(t) = conn.transport_of(&pid) {
                        t.send_control(&json!({ "type": "pair-proof-ack", "ok": ok }))
                            .await
                            .ok();
                    }
                }
                Some("pair-intro") => {
                    // C19/C20: only a fingerprint-verified known device may
                    // vouch new trust into this store.
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let iname = v["name"].as_str().unwrap_or_default().to_string();
                    let isec = v["secret"].as_str().unwrap_or_default().to_string();
                    let hub = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    if trusted && isec.len() == 64 && !iname.is_empty() {
                        devices_store(&iname, &isec)?;
                        devices.push((iname.clone(), isec.clone()));
                        sess.channels.push(channel_of(&isec)); // C30
                        sess.touch();
                        sio.emit("subscribe", json!({ "channels": [channel_of(&isec)] }))
                            .await
                            .ok();
                        ui::say(&format!(
                            "  {} introduced to '{}' by {}, now a known device",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                            iname,
                            hub
                        ));
                        // For identity layer, after introduction, generate nonce challenge to learn peer's identity (0x02 path)
                        // Challenge carries ONLY {nonce, receiver_device_pub} per correction A
                        // Receiver_device_pub is our own overlay key (always exists, not cert-or-zeros)
                        if let Ok(own_dpub) = crate::overlay::overlay_pubkey_bytes() {
                            if let Some(t) = conn.transport_of(&pid) {
                                use ring::rand::{SecureRandom, SystemRandom};
                                let rng = SystemRandom::new();
                                let mut nonce = [0u8; 32];
                                let _ = rng.fill(&mut nonce);
                                // Store pending nonce for this peer, single-use, session-scoped, distinct per concurrent session
                                identity_nonces
                                    .insert(iname.clone(), (nonce, Instant::now(), own_dpub));
                                let challenge = json!({
                                    "type": "identity-nonce-challenge",
                                    "nonce": hex::encode(nonce),
                                    "receiver_device_pub": hex::encode(own_dpub)
                                });
                                let _ = t.send_control(&challenge).await;
                            }
                        }
                    } else {
                        ui::say(&ui::paint(
                            ui::Tone::Warn,
                            &format!("  ignored pair-intro from unverified peer {hub}"),
                        ));
                    }
                }
                Some("identity-nonce-challenge") => {
                    // Received challenge as sender: peer wants to learn our identity, we must respond with sealed cert + possession sig
                    // Challenge carries ONLY {nonce, receiver_device_pub} per correction A, no scope/caps/user data
                    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                    let recv_dpub_hex = v["receiver_device_pub"].as_str().unwrap_or_default();
                    if let (Ok(nonce_bytes), Ok(recv_dpub_bytes)) =
                        (hex::decode(nonce_hex), hex::decode(recv_dpub_hex))
                    {
                        if nonce_bytes.len() == 32 && recv_dpub_bytes.len() == 32 {
                            let mut nonce_arr = [0u8; 32];
                            nonce_arr.copy_from_slice(&nonce_bytes);
                            let mut recv_dpub_arr = [0u8; 32];
                            recv_dpub_arr.copy_from_slice(&recv_dpub_bytes);
                            // Build possession_msg with 0x02 binding_type, binding_value=nonce, scope own, caps_digest own, cert_hash own, sender=own, receiver=challenger's
                            // For minimal, try to get local device cert for this machine
                            if let Some(local_cert) = local_device_cert() {
                                let scope = crate::identity::IntroScope::User.to_byte(); // User-scope for introduce, from own token
                                let caps = "transfer";
                                let caps_d = crate::identity::caps_digest(caps);
                                let chash = crate::identity::cert_hash(&local_cert);
                                let sender_dpub = local_cert.device_pub;
                                // Possession_msg 8-field: tag, type 0x02, nonce, scope, caps_digest, cert_hash, sender, receiver
                                let msg = crate::identity::possession_msg(
                                    0x02,
                                    &nonce_arr,
                                    scope,
                                    &caps_d,
                                    &chash,
                                    &sender_dpub,
                                    &recv_dpub_arr,
                                );
                                if let Ok(sig) = crate::overlay::overlay_sign_possession(&msg) {
                                    // For introduce path, identity-expose goes over DIRECT A-B DTLS data channel (the introduced pair's OWN transport,
                                    // whose DTLS keys the introducer/hub does NOT know). This is E2E encrypted, so unsealed is actually FINE and BETTER than
                                    // sealing with HKDF(fresh_secret) (which introducer CAN open, since it minted fresh_secret). DTLS gives true A-B E2E,
                                    // introducer is BLIND (cannot read cert), which is stronger. No sealing needed for introduce when sent over direct A-B transport.
                                    // For pair path (0x01), we DO seal via signal path with HKDF(K) because signal goes via server.
                                    let _inner = json!({
                                        "cert": local_cert.to_json(),
                                        "possession_sig": hex::encode(sig)
                                    });
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let payload = json!({
                                            "type": "identity-expose",
                                            "v": 2,
                                            "binding_type": 0x02,
                                            "nonce": hex::encode(nonce_arr),
                                            "cert": local_cert.to_json(),
                                            "possession_sig": hex::encode(sig)
                                        });
                                        let _ = t.send_control(&payload).await;
                                    }
                                }
                            }
                        }
                    }
                }
                Some("identity-expose") => {
                    // Received sealed or unsealed identity-expose for introduce path (0x02)
                    // For PAKE path we already handle sealed with possession in pair_cmd, this is for introduce path
                    // Verify against held nonce, own scope/caps, cert_hash locally rebuilt, etc.
                    // For minimal, if we have pending nonce for this peer, verify and store
                    // This is the receiver side (we generated nonce, now receiving expose)
                    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                    if let Ok(nonce_bytes) = hex::decode(nonce_hex) {
                        if nonce_bytes.len() == 32 {
                            let mut nonce_arr = [0u8; 32];
                            nonce_arr.copy_from_slice(&nonce_bytes);
                            // Check held nonce matches and is single-use
                            if let Some((held_nonce, _ts, _held_recv_dpub)) =
                                identity_nonces.get(&pid)
                            {
                                if held_nonce == &nonce_arr {
                                    // Nonce matches, now verify cert and possession sig
                                    if let Some(cert_json) = v.get("cert") {
                                        if let Some(cert) =
                                            identity::DeviceCert::from_json(cert_json)
                                        {
                                            if cert.verify(identity::now_secs()).is_ok() {
                                                // Verify possession sig
                                                if let Some(sig_hex) =
                                                    v.get("possession_sig").and_then(|x| x.as_str())
                                                {
                                                    if let Ok(sig_bytes) = hex::decode(sig_hex) {
                                                        if sig_bytes.len() == 64 {
                                                            let mut sig_arr = [0u8; 64];
                                                            sig_arr.copy_from_slice(&sig_bytes);
                                                            // Recompute possession_msg with held nonce, own scope/caps, etc.
                                                            let scope =
                                                                crate::identity::IntroScope::User
                                                                    .to_byte(); // from own token, not echoed
                                                            let caps_d =
                                                                crate::identity::caps_digest(
                                                                    "transfer",
                                                                ); // own caps
                                                            let chash =
                                                                crate::identity::cert_hash(&cert);
                                                            if let Ok(own_dpub) =
                                                                crate::overlay::overlay_pubkey_bytes(
                                                                )
                                                            {
                                                                let sender_dpub = cert.device_pub;
                                                                let receiver_dpub = own_dpub; // our own device_pub as receiver
                                                                let msg =
                                                                    crate::identity::possession_msg(
                                                                        0x02,
                                                                        &nonce_arr,
                                                                        scope,
                                                                        &caps_d,
                                                                        &chash,
                                                                        &sender_dpub,
                                                                        &receiver_dpub,
                                                                    );
                                                                if crate::identity::verify_possession_sig(&cert.device_pub, &msg, &sig_arr).is_ok() {
                                                                    // Anti-reflection, narrowed to device_pub (#41). The outer `if let` is kept
                                                                    // only to preserve the if/else-if chain with the enrollment branch below;
                                                                    // the reflection test itself now compares cert.device_pub against own_dpub
                                                                    // (this machine's LOCAL device pubkey, from the enclosing
                                                                    // overlay_pubkey_bytes()), so a same-owner fleet device (different device_pub,
                                                                    // same user key) is admitted instead of refused. This 0x02 path also binds
                                                                    // receiver_dpub in the possession_msg, so device_pub here is defense-in-depth.
                                                                    if let Ok(Some(_own_uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                                                                        if cert.device_pub == own_dpub {
                                                                            // self, refuse
                                                                        } else {
                                                                            // Store as provisional, then promote at overlay after check
                                                                            let _ = store_provisional_identity(&format!("peer-{}", pid), &cert);
                                                                            // Store identity on the link for capability authorization
                                                                            if let Some(l) = conn.link_mut(&pid) {
                                                                                l.identity_device_pub = Some(cert.device_pub);
                                                                                l.identity_user_pub = Some(cert.user_pub);
                                                                                l.identity_binding = crate::capability::BindingStrength::Proven;
                                                                                l.identity_cert_expires = Some(cert.expires);
                                                                            }
                                                                            ui::say(&format!("  {} identity verified for peer {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), pid));
                                                                            // Erase held nonce single-use
                                                                            identity_nonces.remove(&pid);
                    }
                } else if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
                    // Enrollment channel: an ephemeral device is trying to enroll.
                    // Recognize peers on enroll_channel(own_owner_pub) and dial them.
                    let ek = crate::ephemeral::enroll_channel(&uk.public_key_bytes());
                    if v["channel"].as_str() == Some(&ek) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        if !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid) {
                            ui::debug(&format!("enrollment peer appeared on channel, dialing"));
                        }
                        conn.maybe_adopt(&v, true).await?;
                    }
                }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Some("file-offer") => {
                    let Some(t) = conn.transport_of(&pid) else {
                        continue;
                    };
                    // L1-a (shared-room hardened): on the code path, accept bytes
                    // ONLY from the peer whose ephemeral SPAKE2 ceremony confirmed
                    // (the authenticated sender). Anything else, a pre-auth offer, a
                    // decoy / unrelated room peer, or an offer from a DIFFERENT peer
                    // than the one that authenticated, is refused. (Previously this
                    // only gated the single latched peer, so a decoy could slip an
                    // offer past while we were still authenticating; now it cannot.)
                    // If no peer has authenticated yet, the overall watchdog still
                    // fails loudly should the real sender never confirm.
                    if recv_code_path && (!recv_pake_done || !conn.is_bound_active_peer(&pid)) {
                        // A pre-auth offer from a peer we are STILL authenticating
                        // (it has a live ceremony) is buffered, not lost: the offer
                        // and the sender's confirm crossed on the wire. If that peer
                        // wins auth we replay it; if its ceremony is dropped, the
                        // buffered offer dies with it. A confirmed-but-different peer
                        // (a decoy that authenticated nothing) is simply ignored.
                        if !recv_pake_done && st.recv_cers.contains_key(&pid) {
                            st.recv_pending_offers.insert(pid.clone(), v.clone());
                            ui::debug(
                                "buffering a pre-auth file-offer until its ceremony confirms",
                            );
                        } else {
                            ui::debug(
                                "ignoring file-offer from a peer that has not authenticated via ephemeral PAKE",
                            );
                        }
                        continue;
                    }
                    // Same race, one layer over: this peer's `fleet-hello` has
                    // not landed yet, so its link still reads binding=None and
                    // the gate below would decline a peer that is seconds from
                    // being Proven. Buffer rather than decide. Bounded by the
                    // link: `fleet-hello` either verifies (we replay) or is
                    // rejected and the link is dropped (the entry goes with it),
                    // so a peer cannot park offers here indefinitely.
                    // "Could this link still prove itself?" is the question, and
                    // `fleet_pending` alone answers a NARROWER one: "have we already
                    // classified it?". The offer can arrive before ChannelReady has
                    // run for that pid, so the set is still empty and the gate
                    // decides against a peer that is seconds from being Proven,
                    // declining with "not in auth key caps" against the empty
                    // ceiling an unverified fleet link is born with. Measured as the
                    // dominant failure once the active-slot bug was fixed: 3 of 4
                    // remaining failures were this decline, not a timeout.
                    //
                    // `__fleet_waited` marks an offer that has already served its
                    // grace, so a peer that never proves itself is decided normally
                    // instead of deferred forever.
                    // MEASURED, and the wider condition was WORSE. Broadening this
                    // to "any untrusted fleet-shaped link could still verify" took
                    // sibling sends from 11/15 to 3/15: `fleet_shaped_link` is true
                    // for nearly every such link, so offers whose hello had ALREADY
                    // been handled were parked too, waited out the full grace, and
                    // were then declined anyway. `fleet_pending` is the honest
                    // predicate because it means "a hello is actually coming".
                    let already_waited = v["__fleet_waited"].as_bool() == Some(true);
                    if !already_waited
                        && fleet_identity_pending(
                            &conn,
                            &pid,
                            fleet_pending.contains(&pid),
                            fleet_verified.contains(&pid),
                        )
                    {
                        ui::debug(&format!(
                            "deferring file-offer from {pid}: fleet identity still verifying"
                        ));
                        fleet_deferred_offers.push((
                            pid.clone(),
                            v.clone(),
                            Instant::now() + fleet_offer_grace,
                        ));
                        continue;
                    }
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // Never trust a remote name: reduce it to a safe single path
                    // component (basename only, no path separators, no control
                    // bytes). See safe_incoming_name.
                    let raw = v["name"].as_str().unwrap_or("file.bin");
                    let name = safe_incoming_name(raw);
                    let size = v["size"].as_u64().unwrap_or(0);
                    let offer_head = v["head"].as_str().map(|s| s.to_string());
                    // P4 (GAP-5): the sender's whole-file sha256 (absent for an old
                    // peer). Used to verify-on-completion + drive the delivery-ack.
                    let offer_full = v["full"].as_str().map(|s| s.to_string());
                    let is_resume = v["resume"].as_bool().unwrap_or(false);

                    let part_path = dir.join(format!("{name}.part"));
                    let meta_path = dir.join(format!("{name}.part.meta"));
                    // C7: a partial counts only if size matches AND the
                    // content head matches (when both sides have one).
                    let mut offset = 0u64;
                    // P4: the whole-file digest persisted with the partial, so a
                    // resume after a process restart can still verify-on-completion
                    // even if this particular re-offer omits `full`.
                    let mut prior_full: Option<String> = None;
                    if part_path.is_file() {
                        let prior = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
                        match PartMeta::load(&meta_path) {
                            Some(m) if m.size == size && prior <= size => {
                                let head_ok = match (&m.head, &offer_head) {
                                    (Some(a), Some(b)) => a == b,
                                    _ => true, // legacy peer, size-only fallback
                                };
                                if head_ok {
                                    offset = prior;
                                    prior_full = m.full;
                                } else {
                                    // DEBUG, resilience internal (resume mismatch, restart).
                                    ui::debug(&format!(
                                        "{name}: same name+size but different content, restarting from 0"
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }

                    // #30 GAP 2 / #161: hold the offer while identity resolution
                    // is pending. Do NOT decide the offer with an un-resolved
                    // sender.
                    //
                    // #30 (authoritative): if a possession-sig challenge is still
                    // in flight and the binding is not yet Proven, do NOT decide
                    // on Inferred now: the identity-expose that flips us to
                    // Proven is a SEPARATE event this single-consumer loop must
                    // be free to process, so blocking inline would deadlock.
                    //
                    // #161 (both modes, typed-code path): the buffered offer is
                    // replayed at PAKE confirm BEFORE DirectReady issues the 0x02
                    // identity challenge, so the first offer always arrives with
                    // identity unresolved. Revocation is mode-independent (the
                    // #158 absolute Deny fires in both modes), so accepting a
                    // legacy-trusted offer with cert_revoked_for(None)=false lets
                    // a revoked device push a transfer before its stored revoked
                    // cert resolves. Hold the offer while identity is unresolved,
                    // bounded by RECV_IDENTITY_HOLD_DEADLINE from first sight.
                    //
                    // Both self-terminate: the pending_proven entry is removed on
                    // Proven OR its 3s deadline; the #161 hold clears at its own
                    // deadline and the offer below is then decided.
                    //
                    // #161 FAIL-CLOSED EXPIRY: if the hold clears with identity
                    // STILL unresolved on the typed-code path, DENY rather than
                    // proceed. Deciding a legacy-trusted offer with
                    // cert_revoked_for(None)=false would admit a device whose
                    // revocation cannot bind - #156 makes unidentified read as
                    // not-revoked by design, and #161's hold was the only thing
                    // standing between them. The operator is present by
                    // construction (they typed the code), so the cost of denial
                    // is a retry at the terminal, not a lost unattended
                    // transfer. A peer whose ceremony cannot resolve within the
                    // hold is either revoked or on a link the ceremony does not
                    // complete on; both must be refused, not admitted.
                    {
                        let (proven, idev_known, link_ready) = conn
                            .link(&pid)
                            .map(|l| {
                                (
                                    l.identity_binding
                                        == crate::capability::BindingStrength::Proven,
                                    l.identity_device_pub.is_some(),
                                    l.presence == Presence::Ready,
                                )
                            })
                            .unwrap_or((false, false, false));
                        let challenge_in_flight =
                            st.pending_proven.lock().unwrap().contains_key(&pid);
                        let code_hold = recv_code_path && !proven && !idev_known;
                        let hold = if code_hold {
                            if !link_ready {
                                // Transport still establishing (the direct-blocked
                                // fallback brings WebRTC up AFTER PAKE, and the
                                // ChannelReady re-issue delivers the challenge when
                                // it does). Hold without starting the clock.
                                true
                            } else {
                                let deadline = *recv_identity_hold
                                    .entry(pid.clone())
                                    .or_insert_with(std::time::Instant::now);
                                deadline.elapsed() < RECV_IDENTITY_HOLD_DEADLINE
                            }
                        } else {
                            crate::capability::cap_authoritative() && challenge_in_flight && !proven
                        };
                        if hold {
                            let rtx = tx.clone();
                            let rpid = pid.clone();
                            let rv = v.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(80)).await;
                                let _ = rtx.send(Ev::Control(rpid, rv));
                            });
                            continue;
                        }
                        // #161: the hold expires into a DECISION, not a denial.
                        // Revocation binds wherever identity resolves: a revoked
                        // device's cert resolves via the challenge and the gate's
                        // absolute Deny fires. A peer whose identity does NOT
                        // resolve within the hold (a slow fallback link, or a
                        // lost challenge on a transport that came up late) is
                        // decided by the normal gate - consent and grants in
                        // shadow, the capability layer under authoritative. The
                        // residual (a revoked device whose identity ceremony does
                        // not complete on a given path being admitted) is
                        // precondition-bounded and documented in the changelog;
                        // the terminal-outcome model that closes it entirely is
                        // the next iteration, not a 0.8.0 change.
                    }

                    // C14/C22: consent. -y accepts everything; a resume of a
                    // partial we already said yes to auto-accepts; a verified
                    // device auto-accepts; otherwise the question joins the
                    // pending queue and the answer arrives via StdinLine, a
                    // per-process token marks re-enqueued offers so a remote
                    // peer can't forge "already consented".
                    let sender_name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    let link_trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let consented = v["__consent"].as_str() == Some(consent_token());
                    // Legacy (pre-capability) decision, per mode.
                    let legacy_ok = if daemon {
                        link_trusted
                    } else {
                        yes || consented || link_trusted || (is_resume && offset > 0)
                    };
                    // Capability layer evaluated unconditionally (shadow samples the
                    // legacy-allowed population); legacy stands in shadow, cap gates
                    // under FILAMENT_CAP_AUTHORITATIVE.
                    let (ok, xfer_deny_reason, xfer_gate) = {
                        let az = peer_authz(&mut conn, &pid);
                        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
                        let outcome = crate::capability::cap_authorize(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_TRANSFER,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        // Trust floor: under authoritative, an untrusted link
                        // must never authorize transfer (pair-proof vs device-key).
                        let outcome = crate::capability::cap_trust_floor(
                            &outcome,
                            link_trusted,
                            binding,
                            crate::capability::cap_authoritative(),
                        );
                        // Fleet transfer scope, enforced by construction and VERIFIED
                        // here (not hardcoded `true`, which asserted a bound nothing
                        // checked). The offered name is basename-only (see ~14095:
                        // `Path::new(raw).file_name()`, "never trust a remote name with
                        // path separators") and lands in the receiver's OWN drop dir
                        // `dir`, which the sender cannot redirect. Assert the landing
                        // path is within `dir` so a future regression in the sanitizer
                        // or in how `dir` is derived TRIPS the gate (fails closed to
                        // grant-only) instead of silently widening scope. NOTE: this is
                        // a LEXICAL check; a symlink planted at the final `.part` create
                        // could still redirect the write — closed separately by the
                        // plain-file-only (O_NOFOLLOW/O_EXCL) write hardening tracked as
                        // a fleet-trust follow-up.
                        let landing = dir.join(&name);
                        let scoped_in_bounds = crate::path_within(&dir, &landing);
                        let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
                            &crate::settings::config_dir(),
                            "self",
                            crate::capability::CAP_TRANSFER,
                            idev,
                            iusr,
                            ak_caps,
                        );
                        let d = crate::capability::cap_gate_effective(
                            legacy_ok,
                            &outcome,
                            crate::capability::CAP_TRANSFER,
                            "self",
                            idev,
                            iusr,
                            binding,
                            expires,
                            ak_caps,
                            own_user.as_ref(),
                            scoped_in_bounds,
                            has_grant,
                            cert_revoked,
                        );
                        let reason =
                            if let crate::capability::GateDecision::Deny { cap_reason } = &d {
                                cap_reason.clone()
                            } else {
                                None
                            };
                        ui::debug(&format!(
                            "transfer-gate: from={sender_name} allowed={} legacy_ok={legacy_ok} trusted={link_trusted} binding={binding:?} own_user={} has_grant={has_grant} in_bounds={scoped_in_bounds} revoked={cert_revoked} authoritative={} reason={:?}",
                            d.allowed(),
                            own_user.is_some(),
                            crate::capability::cap_authoritative(),
                            reason
                        ));
                        (d.allowed(), reason, d)
                    };
                    // Under authoritative, a capability Deny hard-declines
                    // immediately: no prompt, skip the accept path entirely.
                    if let Some(reason) = crate::capability::transfer_gate_decision(
                        &xfer_gate,
                        crate::capability::cap_authoritative(),
                    ) {
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            &format!("  declined {name} from {sender_name} ({reason})",),
                        ));
                        if daemon {
                            enqueue_if_requestable(&sender_name, "transfer");
                        }
                        t.send_control(&protocol::decline_msg(&id)).await?;
                        continue;
                    }
                    if !ok {
                        if !daemon && std::io::stdin().is_terminal() && xfer_deny_reason.is_none() {
                            st.pending.push_back((pid.clone(), v.clone()));
                            st.question_open
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            if st.pending.len() == 1 {
                                // C25: the question is a PERMANENT line first
                                // (nothing can be asked invisibly), with the
                                // sticky as the live answer tail.
                                let q = offer_question(&sender_name, &name, size, paired);
                                ui::say(&q);
                                ui::sticky(&q);
                                st.question_shown = Instant::now();
                            }
                            continue; // decision arrives later via StdinLine
                        }
                        // #213: surface the REAL gate reason. In shadow mode a
                        // consent denial returns cap_reason None, so xfer_deny_reason
                        // is Some exactly when the gate refused for a real reason
                        // (revocation, ceiling, authoritative) - surface it. The tty
                        // hint is ONLY for the None case: an unanswered consent
                        // prompt on a non-tty, where passing -y genuinely changes the
                        // outcome. Telling a user to pass a flag they already passed,
                        // for a decision no flag can change, is how a green security
                        // property turns unmeasurable.
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            &format!(
                                "  declined {name} from {sender_name} ({})",
                                if daemon {
                                    xfer_deny_reason.as_deref().unwrap_or("unverified peer")
                                } else if let Some(reason) = xfer_deny_reason.as_deref() {
                                    reason
                                } else {
                                    "no tty, use -y to auto-accept"
                                }
                            ),
                        ));
                        t.send_control(&protocol::decline_msg(&id)).await?;
                        continue;
                    }

                    // C23: never run two streams into one .part, a rejoin
                    // can re-offer a file whose first stream is still live;
                    // accepting both corrupted the path and crashed on the
                    // second rename. First stream wins.
                    //
                    // P0 (GAP-1) exception: a STALL repair re-offers the same file
                    // (resume:true) on a FRESH transport while the OLD stream's
                    // by_sid entry may still linger (its data path went dark). If
                    // the existing stream's transport is itself STALLED past the
                    // threshold, the "first stream" is the wedged one, flush it to
                    // its .part and accept the resume on the live link instead of
                    // declining (a decline would mark the SENDER's transfer done
                    // and abort the recovery). A genuinely FLOWING duplicate still
                    // wins as before.
                    let want_part = dir.join(format!("{name}.part"));
                    if !to_stdout {
                        let dup_keys: Vec<(String, u32)> = st
                            .by_sid
                            .iter()
                            .filter(|(_, inc)| inc.part_path == want_part)
                            .map(|(k, _)| k.clone())
                            .collect();
                        if !dup_keys.is_empty() {
                            // Is ANY existing stream for this file still flowing?
                            let any_flowing = dup_keys.iter().any(|(p, _)| {
                                conn.transport_of(p)
                                    .map(|t| t.idle_ms() < net::stall_ms())
                                    .unwrap_or(false)
                            });
                            if any_flowing {
                                // A real concurrent duplicate, first (flowing)
                                // stream wins. Ignore WITHOUT marking the sender
                                // done (a benign skip, not a user decline).
                                ui::say(&ui::paint(
                                    ui::Tone::Dim,
                                    &format!(
                                        "  (duplicate offer for {name} ignored, already receiving it)"
                                    ),
                                ));
                                continue;
                            }
                            // The lingering stream(s) are STALLED, flush their
                            // partials to disk and drop them so the resume below
                            // re-opens the .part from its saved offset.
                            for k in dup_keys {
                                if let Some(inc) = st.by_sid.remove(&k) {
                                    let f = inc.file.clone();
                                    let _ = tokio::task::spawn_blocking(move || {
                                        let _ = f.sync_all();
                                    })
                                    .await;
                                }
                            }
                        }
                    }

                    if to_stdout {
                        // Pipe mode: no part files, no resume, pure stream.
                        // Write through a dup'd stdout fd so dropping the
                        // writer never closes the process's real fd 1; the
                        // /dev/stdout open is the portable-unix way to dup.
                        // (Windows: -o - is not supported yet; see G-e.)
                        #[cfg(unix)]
                        let out = tokio::fs::OpenOptions::new()
                            .write(true)
                            .open("/dev/stdout")
                            .await?;
                        #[cfg(not(unix))]
                        {
                            bail!("-o - (stdout streaming) is not supported on this platform yet");
                        }
                        #[cfg(unix)]
                        {
                            st.by_sid.insert(
                                (pid.clone(), sid),
                                IncomingFile {
                                    id: id.clone(),
                                    name,
                                    size,
                                    received: Arc::new(AtomicU64::new(0)),
                                    ranges: Arc::new(std::sync::Mutex::new(vec![])),
                                    file: Arc::new(out.into_std().await),
                                    part_path: PathBuf::new(),
                                    // Pipe mode streams to a fd we can't re-read, so we
                                    // can't recompute the digest, no verify, no ack
                                    // (the sender's bounded fallback covers it).
                                    full: None,
                                    inflight: Arc::new(AtomicI64::new(0)),
                                    end_seen: Arc::new(AtomicBool::new(false)),
                                    ack_sid: 0,
                                    last_tick: 0,
                                    bar: ui::Progress::new("(stdout)", size),
                                },
                            );
                            t.send_control(&protocol::accept_msg(&id, 0)).await?;
                            continue;
                        }
                    }
                    // P4: the digest to verify against on completion, the current
                    // offer's, else the one persisted with the partial (resume).
                    let effective_full = offer_full.clone().or(prior_full);
                    // A per-file open failure DECLINES this one file (continue),
                    // matching the other offer-accept declines. It must never unwind
                    // the receive loop: that would kill every other in-flight transfer.
                    let file = if offset > 0 {
                        // DEBUG, resilience internal (receiver resuming from offset).
                        ui::debug(&format!(
                            "{name}: resuming at {} ({:.0}%)",
                            human(offset),
                            offset as f64 / size.max(1) as f64 * 100.0
                        ));
                        // Open with write mode (not append) so we can seek to any
                        // position for multi-stream out-of-order writes.
                        // safe_resume_part: RESOLVE_BENEATH on Linux, O_NOFOLLOW +
                        // fstat regular-file check on other Unix. NO O_EXCL (resume).
                        match safe_resume_part(&part_path).await {
                            Ok(f) => f,
                            Err(e) => {
                                ui::debug(&format!(
                                    "{name}: cannot open .part to resume, declining: {e}"
                                ));
                                continue;
                            }
                        }
                    } else {
                        // Restart-from-0: a leftover .part of different content/size
                        // (interrupted transfer, or a common filename from another
                        // peer) must not block the fresh create. safe_create_part uses
                        // O_EXCL to refuse a planted symlink, which EEXISTs on any
                        // leftover .part; that Err used to unwind the whole loop. Remove
                        // the stale partial first (unlinking a symlink drops the link,
                        // not its target); a symlink planted in the gap still trips
                        // O_EXCL and is declined below, not followed.
                        let _ = std::fs::remove_file(&part_path);
                        if let Err(e) = (PartMeta {
                            size,
                            head: offer_head,
                            full: effective_full.clone(),
                        }
                        .store(&meta_path))
                        {
                            ui::debug(&format!("{name}: cannot write .part.meta, declining: {e}"));
                            continue;
                        }
                        match safe_create_part(&part_path).await {
                            Ok(f) => f,
                            Err(e) => {
                                ui::debug(&format!("{name}: cannot create .part, declining: {e}"));
                                continue;
                            }
                        }
                    };
                    let bar = ui::Progress::new(&name, size);
                    let file = Arc::new(file.into_std().await);
                    let received = Arc::new(AtomicU64::new(offset));
                    let ranges = Arc::new(std::sync::Mutex::new(if offset > 0 {
                        vec![(0, offset)]
                    } else {
                        vec![]
                    }));
                    st.by_sid.insert(
                        (pid.clone(), sid),
                        IncomingFile {
                            id: id.clone(),
                            name,
                            size,
                            received,
                            ranges,
                            file,
                            part_path,
                            full: effective_full,
                            inflight: Arc::new(AtomicI64::new(0)),
                            end_seen: Arc::new(AtomicBool::new(false)),
                            ack_sid: 0,
                            last_tick: 0,
                            bar,
                        },
                    );
                    t.send_control(&protocol::accept_msg(&id, offset)).await?;
                }
                Some("file-end") => {
                    // Test hook (gate 18 standalone repro): drop the file-end
                    // control frame so a fully-received stream is stranded in
                    // by_sid, mirrors a sender whose PC tears down before the
                    // best-effort file-end is delivered.
                    if test_hooks::drop_file_end() {
                        continue;
                    }
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // If background writes are still in-flight, defer to
                    // Ev::MaybeComplete from the last finishing writer.
                    let process_now = {
                        match st.by_sid.get_mut(&(pid.clone(), sid)) {
                            None => false, // unknown stream
                            Some(inc) => {
                                inc.ack_sid = sid;
                                if inc.inflight.load(Ordering::Relaxed) > 0 {
                                    inc.end_seen.store(true, Ordering::Relaxed);
                                    false // deferred to MaybeComplete
                                } else {
                                    true // inflight == 0, process now
                                }
                            }
                        }
                    };
                    if !process_now {
                        continue;
                    }
                    // No inflight writes — process inline (fast path).
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    let mut inc = match st.by_sid.remove(&(pid.clone(), sid)) {
                        Some(i) => i,
                        None => continue,
                    };
                    let f = inc.file.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = f.sync_all();
                    })
                    .await;
                    if to_stdout {
                        st.completed += 1;
                        continue;
                    }
                    let id = inc.id.clone();
                    if inc.full.is_some() {
                        let verdict = verify_incoming(&inc).await;
                        match verdict {
                            protocol::VerifyResult::Match => {
                                st.verify_fails.remove(&id);
                                let rename_to = if st.completed == 0 {
                                    output.clone()
                                } else {
                                    None
                                };
                                let from =
                                    conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                                let nm = inc.name.clone();
                                if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from)
                                    .await?
                                {
                                    st.completed += 1;
                                    // BUG-ACKLOSS reproducer: tear the link DOWN at the
                                    // instant the ack is due, so the sender never sees it and
                                    // its transport observes ApplicationClosed(0,""). In
                                    // `=once` mode this fires only the FIRST time, so a daemon
                                    // receiver recovers (delivers) on the re-dial.
                                    //
                                    // RESTORED 2026-08-30. This arm was wired in 12a8db82 and
                                    // was gone by the next commit, with no commit deleting it;
                                    // the else-if chain survived MINUS its first arm, which is
                                    // what a botched conflict resolution looks like. For ~620
                                    // commits `cli/tests/ack-loss-repro.sh` set
                                    // FILAMENT_TEST_PREMATURE_CLOSE=1 and NOTHING READ IT, so
                                    // its "premature" round ran an ordinary transfer and the
                                    // promptness verdict measured the happy path.
                                    // `hooks_that_nothing_calls` now fails if any hook loses
                                    // its last call site again.
                                    if test_hooks::premature_close_after_ack()
                                        && !(test_hooks::premature_close_once()
                                            && test_hooks::premature_already_fired())
                                    {
                                        if test_hooks::premature_close_once() {
                                            test_hooks::premature_mark_fired();
                                        }
                                        ui::say(&ui::paint(
                                            ui::Tone::Warn,
                                            &format!(
                                                "    [test] {nm} PREMATURE-CLOSE at ack (reproducing ack-loss / corpse)"
                                            ),
                                        ));
                                        conn.drop_link(&pid);
                                    } else if test_hooks::suppress_delivery_ack() {
                                        ui::say(&ui::paint(
                                            ui::Tone::Warn,
                                            &format!(
                                                "    [test] {nm} verified but SUPPRESSING delivery-ack"
                                            ),
                                        ));
                                    } else if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t
                                            .send_control(&protocol::delivery_ack_msg(&id, sid))
                                            .await;
                                        let _ = t.flush().await;
                                        ui::say(&ui::paint(
                                            ui::Tone::Dim,
                                            &format!(
                                                "    {nm} verified (whole-file sha256 matched), acked"
                                            ),
                                        ));
                                    }
                                }
                            }
                            protocol::VerifyResult::Mismatch { restart_from_zero } => {
                                let fails = st.verify_fails.entry(id.clone()).or_insert(0);
                                *fails += 1;
                                if *fails > MAX_VERIFY_FAILS {
                                    ui::critical(&ui::paint(
                                        ui::Tone::Err,
                                        &format!(
                                            "  {}: whole-file checksum still wrong after {MAX_VERIFY_FAILS} re-fetches, refusing to accept a corrupt file (partial kept)",
                                            inc.name
                                        ),
                                    ));
                                    st.verify_fails.remove(&id);
                                    continue;
                                }
                                let mut req_offset = inc.received.load(Ordering::Relaxed);
                                if restart_from_zero {
                                    let _ = safe_create_part(&inc.part_path).await;
                                    inc.received.store(0, Ordering::Relaxed);
                                    inc.ranges.lock().unwrap().clear();
                                    req_offset = 0;
                                    ui::debug(&ui::paint(
                                        ui::Tone::Warn,
                                        &format!(
                                            "  {}: received all bytes but whole-file checksum FAILED (corrupt), re-fetching from 0 (attempt {})",
                                            inc.name, *fails
                                        ),
                                    ));
                                } else {
                                    ui::debug(&ui::paint(
                                        ui::Tone::Warn,
                                        &format!(
                                            "  {}: TRUNCATED ({}/{}), checksum can't match yet; re-requesting the rest (attempt {})",
                                            inc.name,
                                            human(req_offset),
                                            human(inc.size),
                                            *fails
                                        ),
                                    ));
                                }
                                let f = inc.file.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    let _ = f.sync_all();
                                })
                                .await;
                                if req_offset == 0 {
                                    if let Ok(f) = safe_resume_part(&inc.part_path).await {
                                        inc.file = Arc::new(f.into_std().await);
                                    }
                                }
                                inc.end_seen.store(false, Ordering::Relaxed);
                                st.by_sid.insert((pid.clone(), sid), inc);
                                if let Some(t) = conn.transport_of(&pid) {
                                    let _ = t
                                        .send_control(&protocol::accept_msg(&id, req_offset))
                                        .await;
                                }
                            }
                        }
                    } else {
                        let rename_to = if st.completed == 0 {
                            output.clone()
                        } else {
                            None
                        };
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await?
                        {
                            st.completed += 1;
                        }
                    }
                }
                _ => {}
            },
            Ev::MaybeComplete(pid, sid) => {
                // A background writer task finished and was the last inflight,
                // and end_seen was already set. Finalize (verify + delv ack).
                let ack_sid = {
                    st.by_sid
                        .get(&(pid.clone(), sid))
                        .map(|inc| inc.ack_sid)
                        .unwrap_or(0)
                };
                if let Some(mut inc) = st.by_sid.remove(&(pid.clone(), sid)) {
                    if to_stdout {
                        st.completed += 1;
                        continue;
                    }
                    let id = inc.id.clone();
                    if inc.full.is_some() {
                        let verdict = verify_incoming(&inc).await;
                        match verdict {
                            protocol::VerifyResult::Match => {
                                st.verify_fails.remove(&id);
                                let rename_to = if st.completed == 0 {
                                    output.clone()
                                } else {
                                    None
                                };
                                let from =
                                    conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                                let nm = inc.name.clone();
                                if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from)
                                    .await?
                                {
                                    st.completed += 1;
                                    // BUG-ACKLOSS reproducer: tear the link DOWN at the
                                    // instant the ack is due, so the sender never sees it and
                                    // its transport observes ApplicationClosed(0,""). In
                                    // `=once` mode this fires only the FIRST time, so a daemon
                                    // receiver recovers (delivers) on the re-dial.
                                    //
                                    // RESTORED 2026-08-30. This arm was wired in 12a8db82 and
                                    // was gone by the next commit, with no commit deleting it;
                                    // the else-if chain survived MINUS its first arm, which is
                                    // what a botched conflict resolution looks like. For ~620
                                    // commits `cli/tests/ack-loss-repro.sh` set
                                    // FILAMENT_TEST_PREMATURE_CLOSE=1 and NOTHING READ IT, so
                                    // its "premature" round ran an ordinary transfer and the
                                    // promptness verdict measured the happy path.
                                    // `hooks_that_nothing_calls` now fails if any hook loses
                                    // its last call site again.
                                    if test_hooks::premature_close_after_ack()
                                        && !(test_hooks::premature_close_once()
                                            && test_hooks::premature_already_fired())
                                    {
                                        if test_hooks::premature_close_once() {
                                            test_hooks::premature_mark_fired();
                                        }
                                        ui::say(&ui::paint(
                                            ui::Tone::Warn,
                                            &format!(
                                                "    [test] {nm} PREMATURE-CLOSE at ack (reproducing ack-loss / corpse)"
                                            ),
                                        ));
                                        conn.drop_link(&pid);
                                    } else if test_hooks::suppress_delivery_ack() {
                                        ui::say(&ui::paint(
                                            ui::Tone::Warn,
                                            &format!(
                                                "    [test] {nm} verified but SUPPRESSING delivery-ack"
                                            ),
                                        ));
                                    } else if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t
                                            .send_control(&protocol::delivery_ack_msg(&id, ack_sid))
                                            .await;
                                        ui::say(&ui::paint(
                                            ui::Tone::Dim,
                                            &format!(
                                                "    {nm} verified (whole-file sha256 matched), acked"
                                            ),
                                        ));
                                    }
                                }
                            }
                            protocol::VerifyResult::Mismatch { restart_from_zero } => {
                                let fails = st.verify_fails.entry(id.clone()).or_insert(0);
                                *fails += 1;
                                if *fails > MAX_VERIFY_FAILS {
                                    ui::critical(&ui::paint(
                                        ui::Tone::Err,
                                        &format!(
                                            "  {}: whole-file checksum still wrong after {MAX_VERIFY_FAILS} re-fetches, refusing to accept a corrupt file (partial kept)",
                                            inc.name
                                        ),
                                    ));
                                    st.verify_fails.remove(&id);
                                    continue;
                                }
                                let mut req_offset = inc.received.load(Ordering::Relaxed);
                                if restart_from_zero {
                                    let _ = safe_create_part(&inc.part_path).await;
                                    if let Ok(f) = safe_resume_part(&inc.part_path).await {
                                        inc.file = Arc::new(f.into_std().await);
                                    }
                                    inc.received.store(0, Ordering::Relaxed);
                                    inc.ranges.lock().unwrap().clear();
                                    req_offset = 0;
                                    ui::debug(&ui::paint(
                                        ui::Tone::Warn,
                                        &format!(
                                            "  {}: received all bytes but whole-file checksum FAILED (corrupt), re-fetching from 0 (attempt {})",
                                            inc.name, *fails
                                        ),
                                    ));
                                } else {
                                    ui::debug(&ui::paint(
                                        ui::Tone::Warn,
                                        &format!(
                                            "  {}: TRUNCATED ({}/{}), checksum can't match yet; re-requesting the rest (attempt {})",
                                            inc.name,
                                            human(req_offset),
                                            human(inc.size),
                                            *fails
                                        ),
                                    ));
                                }
                                let f = inc.file.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    let _ = f.sync_all();
                                })
                                .await;
                                inc.end_seen.store(false, Ordering::Relaxed);
                                st.by_sid.insert((pid.clone(), sid), inc);
                                if let Some(t) = conn.transport_of(&pid) {
                                    let _ = t
                                        .send_control(&protocol::accept_msg(&id, req_offset))
                                        .await;
                                }
                            }
                        }
                    } else {
                        let rename_to = if st.completed == 0 {
                            output.clone()
                        } else {
                            None
                        };
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if finalize_incoming(inc, &dir, rename_to.as_deref(), daemon, &from).await?
                        {
                            st.completed += 1;
                        }
                    }
                }
            }
            Ev::Chunk(pid, sid, offset, data) => {
                // L2 streams live in the HIGH half of the sid space, route them
                // to the tunnel mux, never the file-transfer table (the pure
                // high-bit prefix check keeps file send/recv byte-identical).
                if l2_enabled && l2::is_l2_sid(sid) {
                    if let Some(mux) = l2_muxes.get(&pid) {
                        mux.on_frame(sid, data).await;
                    }
                } else if let Some(inc) = st.by_sid.get_mut(&(pid.clone(), sid)) {
                    // --- TRACE recv path ---
                    let trace = cfg!(feature = "debug-logs")
                        && std::env::var("FILAMENT_TRACE_THROUGHPUT").is_ok();
                    let t_recv_start = if trace {
                        Some(std::time::Instant::now())
                    } else {
                        None
                    };
                    // Determine the write position: absolute offset from the
                    // sender. Both QUIC and DataChannel now frame the offset.
                    // An offsetless frame is impossible under the new scheme.
                    let pos: u64 = match offset {
                        Some(off) => off,
                        None => {
                            dlog!(
                                "[recv] REFUSING offsetless chunk sid={sid}: transport must frame offset"
                            );
                            continue;
                        }
                    };
                    inc.inflight.fetch_add(1, Ordering::Relaxed);
                    let file = Arc::clone(&inc.file);
                    let inflight = Arc::clone(&inc.inflight);
                    let end_seen = Arc::clone(&inc.end_seen);
                    let ranges = Arc::clone(&inc.ranges);
                    let received = Arc::clone(&inc.received);
                    let tx = tx.clone();
                    let pid_c = pid.clone();
                    let data_len = data.len();
                    let trace_inner = trace;
                    tokio::task::spawn_blocking(move || {
                        let t_pwrite = if trace_inner {
                            Some(std::time::Instant::now())
                        } else {
                            None
                        };
                        // `pwrite_at` reports how many iterations the write took;
                        // more than one means a genuine short write. It used to
                        // print that itself, which put terminal output inside the
                        // byte-writing primitive. The primitive returns the fact
                        // now and the decision to report it lives out here.
                        let wrote = pwrite_at(&file, &data, pos);
                        if let Err(_e) = &wrote {
                            // Write failed: do NOT record coverage (leaves the gap).
                            // The whole-file digest will fail and trigger a re-fetch.
                            dlog!("[recv] pwrite_at FAILED at pos={pos} len={data_len}: {e}");
                        } else {
                            if let Ok(iters) = &wrote {
                                if *iters > 1 {
                                    dlog!(
                                        "[recv] short write: {iters} iterations for {data_len} bytes at {pos}"
                                    );
                                }
                            }
                            // Write succeeded: record coverage AFTER bytes landed.
                            let mut r = ranges.lock().unwrap();
                            let (_delta, total) = record_range(&mut *r, pos, data_len);
                            drop(r);
                            // fetch_max, not store: writer tasks run concurrently, so
                            // a task that locked earlier (lower union total) can reach
                            // this line AFTER one that locked later (higher total). The
                            // union total is monotonic, so max() keeps `received` from
                            // regressing to a stale value (which would spuriously trip
                            // the `recvd < size` gate in verify_incoming). Serialized in
                            // the old event-loop path; this race is new to the writer.
                            received.fetch_max(total, Ordering::Relaxed);
                        }
                        let pwrite_us = t_pwrite.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                        if trace_inner && pwrite_us > 1000 {
                            dlog!(
                                "[TRACE recv spawn_blocking] pos={} len={} pwrite={}us",
                                pos,
                                data_len,
                                pwrite_us
                            );
                        }
                        let prev = inflight.fetch_sub(1, Ordering::Relaxed);
                        if prev == 1 && end_seen.load(Ordering::Relaxed) {
                            let _ = tx.send(Ev::MaybeComplete(pid_c, sid));
                        }
                    });
                    let recv_us = t_recv_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                    if trace && recv_us > 500 {
                        dlog!(
                            "[TRACE recv Ev::Chunk] sid={} offset={:?} len={} dispatch={}us",
                            sid,
                            offset,
                            data_len,
                            recv_us
                        );
                    }
                    let r = inc.received.load(Ordering::Relaxed);
                    if r != inc.last_tick {
                        inc.bar.tick(r);
                        inc.last_tick = r;
                    }
                } else {
                    // Chunk arrived for unknown (pid, sid) - log instead of silently dropping.
                    // This happens during transport supersede or stall repair when old chunks
                    // arrive after the by_sid entry was removed.
                    ui::debug(&format!(
                        "  dropping chunk for unknown sid {sid} from {pid} ({} bytes)",
                        data.len()
                    ));
                }
            }
            Ev::StdinLine(line) => {
                let ans = line.to_lowercase();
                if !st.pending.is_empty() {
                    // C22/C25: an open question owns stdin, but ONLY explicit
                    // answers count. An empty line (stray CR, idle Enter) used
                    // to default-decline an offer the user never saw; and any
                    // keypress within 300ms of the question appearing is a
                    // buffered stroke, not a decision.
                    if st.question_shown.elapsed() < Duration::from_millis(300) {
                        continue;
                    }
                    let mut answered = false;
                    if ans == "y" || ans == "yes" {
                        answered = true;
                        let (qpid, mut qv) = st.pending.pop_front().unwrap();
                        ui::clear_sticky();
                        qv["__consent"] = json!(consent_token());
                        let _ = tx.send(Ev::Control(qpid, qv)); // re-enter the offer path, consented
                    } else if ans == "n" || ans == "no" {
                        answered = true;
                        let (qpid, qv) = st.pending.pop_front().unwrap();
                        ui::clear_sticky();
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            &format!("  declined {}", qv["name"].as_str().unwrap_or("file")),
                        ));
                        if let Some(t) = conn.transport_of(&qpid) {
                            t.send_control(&protocol::decline_msg(
                                qv["id"].as_str().unwrap_or_default(),
                            ))
                            .await?;
                        }
                    }
                    // show the next queued question (or re-show on gibberish)
                    if let Some((qpid, qv)) = st.pending.front() {
                        let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                        let q = offer_question(
                            &s,
                            qv["name"].as_str().unwrap_or("file"),
                            qv["size"].as_u64().unwrap_or(0),
                            paired,
                        );
                        if answered {
                            ui::say(&q); // a NEW question fronted, permanent line (C25)
                            st.question_shown = Instant::now();
                        }
                        ui::sticky(&q);
                    } else {
                        st.question_open
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                } else if ans == "devices" {
                    // C29: session commands, `up` is a place you live in.
                    if devices.is_empty() {
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            "  no known devices yet, type a code or `pair` to add one",
                        ));
                    }
                    for (n, s) in &devices {
                        ui::say(&format!(
                            "  {}  {}",
                            ui::paint(ui::Tone::Bold, n),
                            ui::paint(
                                ui::Tone::Dim,
                                &format!("(channel {})", &channel_of(s)[..12])
                            )
                        ));
                    }
                } else if let Some(n) = ans.strip_prefix("forget ") {
                    let n = n.trim();
                    if devices.iter().any(|(dn, _)| dn == n) {
                        devices_remove(n)?;
                        devices.retain(|(dn, _)| dn != n);
                        ui::say(&format!(
                            "  {} forgot '{n}', it can no longer find this machine",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok())
                        ));
                    } else {
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            &format!("  no device named '{n}' (try `devices`)"),
                        ));
                    }
                } else if ans == "pair" || ans == "code" {
                    // C29: mint a code; whoever claims it gets the remember
                    // ceremony on connect (we created it, so WE initiate).
                    if daemon {
                        ceremony = Some(true);
                    }
                    sio.emit("pair-create", json!({})).await.ok();
                } else if regex_lite_code(&line) {
                    if claim_in_flight {
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            "  (a claim is already in flight, wait for it to resolve)",
                        ));
                    } else {
                        ui::say(&format!(
                            "  claiming {}...",
                            ui::paint(ui::Tone::Brand, &line)
                        ));
                        paired = true;
                        claim_in_flight = true;
                        if daemon {
                            ceremony = Some(false); // C29: in a session, pairing means remembering
                        }
                        sio.emit("pair-claim", json!({ "code": line.to_lowercase() }))
                            .await
                            .ok();
                    }
                } else if !line.is_empty() {
                    ui::say(&ui::paint(
                        ui::Tone::Dim,
                        "  (type a code like brave-otter-123 to claim it · `pair` · `devices` · `forget <name>`)",
                    ));
                }
            }
            Ev::Interrupted => {
                flush_inflight(&mut st.by_sid).await;
                // One string served two situations. "partials kept; run the
                // same command to resume" is exactly right for an interrupted
                // transfer and meaningless for a daemon, which has no partials
                // to keep: Ctrl-C out of `filament up` printed a transfer's
                // recovery advice. Observed on two machines. The daemon's own
                // banner already says "Ctrl-C or `filament down` to stop", so
                // say the thing that banner promised.
                if daemon {
                    ui::say(&format!(
                        "  {} stopped serving; `filament up` starts again",
                        ui::paint(ui::Tone::Dim, "·")
                    ));
                } else {
                    ui::say(&format!(
                        "  {} interrupted, partials kept; run the same command to resume",
                        ui::paint(ui::Tone::Warn, "!")
                    ));
                }
                if let Some(g) = &tty_guard {
                    g.restore(); // process::exit skips Drop
                }
                // Best-effort, BOUNDED: a wedged signaling socket must not turn the
                // graceful exit into the very hang the watchdog exists to catch.
                // The signal task already armed a force-exit; cap the disconnect so
                // we exit cleanly on our own well inside that grace.
                let _ = tokio::time::timeout(Duration::from_secs(1), sio.disconnect()).await;
                std::process::exit(130);
            }
            // P0 (GAP-1): the inbound transfer stalled (zero bytes, link alive).
            // The receiver participates in the SYMMETRIC direct-QUIC repair: it
            // re-arms its own direct dial so the fresh authenticated connection
            // can form. The `.part` stays on disk; the sender re-offers
            // resume:true on the new transport, so the file continues from its
            // saved offset (no restart-from-zero). For a WebRTC link the repair
            // is the impolite-side ICE-restart inside correct_stall.
            Ev::TransferStalled(pid, idle_ms) => {
                // DEBUG, resilience internal (inbound stall detection).
                ui::debug(&ui::paint(
                    ui::Tone::Warn,
                    &format!("  inbound stall: {idle_ms}ms with no data from peer, repairing link"),
                ));
                // P0 partial-preservation: flush THIS peer's in-flight partials
                // to their `.part` on disk and release the in-memory handles, so
                // the C23 "already receiving" guard doesn't reject the sender's
                // resume-offer on the FRESH repair link. The `.part` + `.meta`
                // stay on disk; the resume re-opens them from the saved offset
                // (no restart-from-zero). Only this peer's streams are dropped,
                // other links keep flowing.
                let stale: Vec<(String, u32)> = st
                    .by_sid
                    .keys()
                    .filter(|(p, _)| *p == pid)
                    .cloned()
                    .collect();
                for key in stale {
                    if let Some(inc) = st.by_sid.remove(&key) {
                        let f = inc.file.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let _ = f.sync_all();
                        })
                        .await;
                        ui::debug(&format!(
                            "{}: parked at {} for resume",
                            inc.name,
                            human(inc.received.load(Ordering::Relaxed))
                        ));
                    }
                }
                match conn.correct_stall(&pid).await {
                    // Receiver has nothing to re-offer; the sender owns the offer.
                    // Rung (a) is a no-op here, wait for the sender's re-offer.
                    Rung::Resume => {}
                    Rung::Repaired => {}
                    // Rung (d) P1: the receiver re-established over the TURN relay
                    // (relay-only ICE), preserving its `.part`. The sender re-offers
                    // resume:true on the fresh relay link, the file continues from
                    // its saved offset. Nothing to do here.
                    Rung::Relayed => {}
                    // Direct rungs spent AND relay forbidden / already on relay:
                    // failed CLEANLY, partial kept on disk (message already shown).
                    Rung::Exhausted => {}
                }
            }
            // Losing the sender is only an ERROR when nothing completed,
            // after a successful transfer it's just closure (the quiet-exit
            // prints the same `done (N files).` the peer-left path would).
            Ev::Stuck(pid, generation) => {
                // Bug 5: repeated stuck before ANY byte arrived → hint at the
                // single-host mDNS wedge once.
                if !st.ever_received {
                    stuck_while_connecting += 1;
                    if stuck_while_connecting >= 2 {
                        maybe_hint_local_wedge(&mut wedge_hint_shown);
                    }
                }
                if conn
                    .on_stuck(&pid, generation, "stuck while connecting")
                    .await?
                    && paired
                    && !keep_open
                {
                    // G-k: the dropped link may have delivered every byte but
                    // lost its file-end, finalize before deciding it's fatal.
                    sweep_completed_streams(
                        &mut st.by_sid,
                        &conn,
                        &dir,
                        &output,
                        to_stdout,
                        daemon,
                        &mut st.completed,
                    )
                    .await?;
                    if st.completed == 0 {
                        bail!(
                            "lost the sender after {} attempts; the partial is kept, re-run `filament receive <code>` to resume",
                            MAX_ATTEMPTS
                        );
                    }
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? && paired && !keep_open {
                    sweep_completed_streams(
                        &mut st.by_sid,
                        &conn,
                        &dir,
                        &output,
                        to_stdout,
                        daemon,
                        &mut st.completed,
                    )
                    .await?;
                    if st.completed == 0 {
                        bail!(
                            "lost the sender after {} attempts; the partial is kept, re-run `filament receive <code>` to resume",
                            MAX_ATTEMPTS
                        );
                    }
                }
            }
            Ev::PcState(pid, s) => {
                // L2: a dead/closed link must abort every tunnel stream it
                // carried so no pump hangs on a peer that's gone (design §3.5).
                if l2_enabled && (s == "failed" || s == "closed" || s == "disconnected") {
                    if let Some(mux) = l2_muxes.remove(&pid) {
                        mux.shutdown_all().await;
                    }
                    // #4: a genuinely DEAD link (failed/closed) DETACHES its PTY
                    // sessions, it does NOT kill them. The shell keeps running and
                    // buffering output; a reconnect with the same session id
                    // reattaches and replays. We deliberately skip `disconnected`:
                    // that is usually a transient ICE blip the SAME data channel
                    // rides out (no new pty-open follows), so detaching there would
                    // wedge a still-working session. The detached-idle / lifetime
                    // caps in the session task reap a session nobody returns to.
                    if (s == "failed" || s == "closed") && !pty_bindings.is_empty() {
                        if let Some(sid_map) = pty_bindings.remove(&pid) {
                            for session_id in sid_map.values() {
                                if let Some(sess) = pty_sessions.get_live(session_id).await {
                                    sess.detach();
                                }
                            }
                        }
                    }
                }
                conn.on_pc_state(&pid, &s).await;
            }
            Ev::PeerLeft(v) => {
                // Test hook (gate 18): peer-left delivery is best-effort in the
                // real world; this simulates the loss deterministically so the
                // quiet-exit fallback (G-k) can be exercised. SIGSTOP can't do
                // it, engine.io's ping timeout reaps a frozen client in ~30s
                // and the legit peer-left wins the race.
                if test_hooks::drop_peer_left() {
                    continue;
                }
                let gone = v["id"]
                    .as_str()
                    .and_then(|p| conn.link(p))
                    .map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let secs = conn.rejoin.rejoin_window.as_secs();
                    if !st.by_sid.is_empty() {
                        // Keep partials writable-but-parked; resume comes via
                        // rejoin (C6) or a later re-offer against the .part.
                        ui::say(&ui::paint(
                            ui::Tone::Dim,
                            &format!("  sender disconnected mid-transfer, waiting up to {secs}s"),
                        ));
                        flush_inflight(&mut st.by_sid).await;
                    } else if st.completed > 0 && !keep_open {
                        ui::say(&format!(
                            "done ({} file{}).",
                            st.completed,
                            if st.completed == 1 { "" } else { "s" }
                        ));
                        let _ = sio.disconnect().await;
                        return Ok(());
                    } else if paired && !keep_open {
                        // C21: NOT fatal, a phone opening its file picker
                        // suspends the whole tab and drops the socket. Hold
                        // the line; their client rejoins on refocus.
                        let gid = v["id"].as_str().unwrap_or_default();
                        let n = gone.unwrap_or_else(|| "sender".into());
                        ui::say(&conn.roster(
                            gid,
                            "●",
                            ui::Tone::Warn,
                            &format!(
                                "stepped away, holding the line up to {secs}s (Ctrl-C to stop)"
                            ),
                            &n,
                        ));
                    } else {
                        conn.rejoin.waiting_rejoin = None; // open listener: keep going
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => ui::say(&conn.roster(
                                gid,
                                "○",
                                ui::Tone::Dim,
                                "left, still listening",
                                &n,
                            )),
                            None => {
                                ui::say(&ui::paint(ui::Tone::Dim, "  peer left, still listening"))
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
