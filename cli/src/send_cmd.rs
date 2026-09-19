//! The send command (`filament send`) and its single-stream helper.
//!
//! Moved as one unit: `send_cmd` drives the send-side ceremony and the
//! transfer loop, and `stream_one` streams one file for it -- `send_cmd` is its
//! only caller, which is why it lives here and why it stays private rather than
//! being promoted. Neither body contains a cfg attribute, so nothing about the
//! move is conditional. The four spawns in `send_cmd` and the two in
//! `stream_one` keep their captures, and `stream_one` keeps its own
//! function-local `use anyhow::{ Result, anyhow, bail };
use crate::DEFAULT_SERVER;
use crate::MAX_ATTEMPTS;
use crate::PakeInbound;
use crate::REJOIN_WINDOW;
use crate::SendOutcome;
use crate::channel_of;
use crate::codeentry;
use crate::command_arg;
use crate::conn::Conn;
use crate::conn::{AdoptSource, Presence, Rung};
use crate::ctl;
use crate::device_cert_for;
use crate::device_name_for_pub;
use crate::devices_store::devices_load;
use crate::display_name;
use crate::dlog;
use crate::fleet;
use crate::fleet_indexed_name;
use crate::fleet_session;
use crate::head_hash;
use crate::human;
use crate::identity;
use crate::identity_lifecycle::respond_to_identity_challenge;
use crate::interactive_allowed;
use crate::interactive_requested;
use crate::is_self_uid;
use crate::link_nonce;
use crate::load_owner_key;
use crate::maybe_hint_local_wedge;
use crate::mk_uid;
use crate::next_ev;
use crate::pake_ceremony::{Ceremony, pair_v2_caps};
use crate::prompt_line;
use crate::proof_for;
use crate::protocol;
use crate::recv_files::full_hash;
use crate::remember::{self, Ack, Offer, Outcome as RememberOutcome};
use crate::relay_banner;
use crate::relay_forbidden;
use crate::send_outcome;
use crate::session;
use crate::shutdown;
use crate::test_hooks;
use crate::ui;
use anyhow::{Context, Result, anyhow, bail};
use filament_transfer::Outgoing;
use filament_transport::direct;
use filament_transport::net;
use net::{Ev, Transport};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_cmd(
    server: &str,
    mut paths: Vec<String>,
    mut use_code: bool,
    mut word: Option<String>,
    room: Option<String>,
    mut to: Option<String>,
    name: Option<String>,
    relay: bool,
    remember: Option<String>,
) -> Result<()> {
    send_cmd_inner(
        server, paths, use_code, word, room, to, name, relay, remember, false,
    )
    .await
}

/// `filament remember <name>`: the same machinery with nothing to send.
///
/// Deliberately not a second implementation. The remember ceremony is one code
/// path (`crate::remember`) driven from one event loop; the verb is that loop
/// with an empty file list, which is what keeps `remember` and `--remember`
/// from drifting apart the way the two half-mechanisms before them did.
pub(crate) async fn remember_cmd(
    server: &str,
    name: String,
    room: Option<String>,
    relay: bool,
) -> Result<()> {
    send_cmd_inner(
        server,
        Vec::new(),
        false,
        None,
        room,
        Some(name.clone()),
        None,
        relay,
        Some(name),
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_cmd_inner(
    server: &str,
    mut paths: Vec<String>,
    mut use_code: bool,
    mut word: Option<String>,
    room: Option<String>,
    mut to: Option<String>,
    name: Option<String>,
    relay: bool,
    remember: Option<String>,
    remember_only: bool,
) -> Result<()> {
    // `remember` has nothing to send: no picker, no path prompt, no file
    // validation, and never the "mint a code" default. It meets the peer on the
    // same-network room (or --room) and filters by name, exactly as a send
    // without a code does.
    let opened_flow = !remember_only
        && interactive_allowed()
        && (paths.is_empty() || (!use_code && to.is_none()) || interactive_requested());

    // #230: `filament send <file>` with no --to and no --code fell through to
    // local-network discovery and printed a raw room id, while the bare
    // `filament <file>` minted a speakable code. Same intent, two experiences,
    // and the banner documented the code on the verb that lacked it.
    //
    // This defaulting must come AFTER opened_flow, and the first version of the
    // fix did not: setting use_code above the gate made `!use_code` false, so
    // the interactive picker could never open and a TTY user with paired
    // devices lost "send to which device?" entirely. Caught in a flow sweep,
    // not by any gate, because every gate tests a defect and none walks a
    // session.
    //
    // So: ask when we can, and default to a code only when we are not going to
    // ask. Non-interactive keeps the code instead of the room id, which was the
    // actual complaint. Local discovery stays reachable with --room.
    if !remember_only && !opened_flow && !use_code && to.is_none() && room.is_none() {
        use_code = true;
    }
    if paths.is_empty() && !remember_only {
        if !interactive_allowed() {
            bail!(
                "nothing to send in non-interactive mode; pass a file, directory, or '-' for stdin"
            );
        }
        let path = prompt_line("  What do you want to send? ")?;
        if path.is_empty() {
            bail!("cancelled");
        }
        paths.push(path);
    }
    // #188: validate the first path NOW, before asking anything else. The old
    // flow asked local-vs-code first and only then statted the file, so a typo
    // at the prompt cost two questions and a raw syscall error. Validate and
    // re-prompt once instead.
    if !remember_only && !paths.iter().any(|p| p == "-") {
        loop {
            let first = paths.first().cloned().unwrap_or_default();
            if first.is_empty() {
                break;
            }
            match std::fs::metadata(&first) {
                Ok(_) => break,
                Err(_) if interactive_allowed() && paths.len() == 1 => {
                    ui::say(&ui::paint(
                        ui::Tone::Warn,
                        &format!("  no such file or directory: '{first}'"),
                    ));
                    let again = prompt_line("  What do you want to send? ")?;
                    if again.is_empty() {
                        bail!("cancelled");
                    }
                    paths[0] = again;
                }
                Err(e) => bail!("cannot send '{first}': {e}"),
            }
        }
    }
    // #221: --to must name a device we actually know. Falling back to local
    // discovery silently turned a targeted, identity-verified send into a
    // discoverable one, and a mistyped name cost a minute of silence before the
    // timeout. Reject up front, like mount does.
    if let Some(target) = to.as_deref() {
        // A fleet sibling has no pair secret, so `devices_load` skips it, but it IS
        // a valid target: the cold path dials it on the fleet secret and then
        // PROVES its certificate before any bytes move (`verify_fleet_identity`).
        // A fleet sibling is a valid target when our daemon can broker a private
        // rendezvous with it, which needs a daemon to ask. The opt-in flag still
        // lets the old unbrokered path be exercised deliberately; brokering does
        // not need it, because it does not have the reliability problem the flag
        // exists to warn about.
        let known = devices_load()
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(target))
            || (fleet_indexed_name(target)
                && (ctl::daemon_present().await
                    || std::env::var("FILAMENT_FLEET_SEND").as_deref() == Ok("1")));
        if !known {
            if fleet_indexed_name(target) {
                bail!(
                    "send --to '{target}': that is a fleet device, reachable on the mesh but not yet a `send` target. \
                     Use its mesh address ({target}.mesh) for now, or pair with it directly."
                );
            }
            bail!(
                "send --to '{target}': no known device by that name; run `filament devices` to see who you can reach"
            );
        }
    }
    // INTERACTIVE GATE: `send <files>` with no --code/--word/--to and not piping
    // from stdin. First offer to pick a PAIRED DEVICE (arrow-key list); the last
    // item / Esc drops to the code path: Enter = local network, typed words mint a
    // shareable code. Skipped when reading payload from stdin ('-').
    if !use_code && to.is_none() && !paths.iter().any(|p| p == "-") && interactive_allowed() {
        let names: Vec<String> = devices_load().into_iter().map(|(n, _)| n).collect();
        let mut chose_device = false;
        if !names.is_empty() {
            let mut items = names
                .iter()
                .map(|name| {
                    let relation = device_cert_for(name)
                        .and_then(|cert| {
                            load_owner_key().map(|owner| cert.user_pub == owner.public_key_bytes())
                        })
                        .map(|mine| if mine { "MY DEVICE" } else { "EXTERNAL" })
                        .unwrap_or("PAIRED");
                    format!("{name:<20} {relation}")
                })
                .collect::<Vec<_>>();
            items.push("shareable code / local network".into());
            let header = ui::paint(
                ui::Tone::Dim,
                "  send to which device?  (up/down, enter, esc)",
            );
            if let Some(i) = codeentry::pick(&header, &items)? {
                if i < names.len() {
                    ui::say(&format!(
                        "  {} sending to {}",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        names[i]
                    ));
                    to = Some(names[i].clone());
                    chose_device = true;
                }
            }
        }
        if !chose_device {
            // #189: the old local-vs-code question was unanswerable at ask time
            // (you cannot know whether anyone is nearby until you have waited).
            // The full escalation (watch local AND mint a code, whoever arrives
            // first wins) needs the sender reachable in two rendezvous points,
            // which is a transport change - flagged, not pushed through. The
            // non-transport half ships here: there is no question, the sender
            // mints a code immediately and shows it, so `send` is discoverable
            // by `receive <code>` from anywhere and a nearby receiver appears in
            // the room on its own.
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  minting a shareable code (a nearby device can also appear automatically)",
            ));
            use_code = true;
            word = Some(crate::pake::words::mint_words());
        }
    }
    // --name overrides the offered name, but only makes sense for a SINGLE
    // payload (stdin, or one regular file). With multiple paths or a directory
    // there is no single name to override, so warn that it's ignored.
    if name.is_some() && paths.len() > 1 {
        ui::say(&ui::paint(
            ui::Tone::Warn,
            "--name is ignored when sending multiple paths",
        ));
    }
    let single = paths.len() == 1;
    let my_uid = mk_uid("s");
    let mut outgoing: Vec<Outgoing> = Vec::new();
    for (i, p) in paths.iter().enumerate() {
        let sid = (i + 1) as u32;
        let id = format!("{}-{}", my_uid, sid);
        if p == "-" {
            let spool = std::env::temp_dir().join(format!("filament-stdin-{}", std::process::id()));
            let mut f = std::fs::File::create(&spool)?;
            let n = std::io::copy(&mut std::io::stdin().lock(), &mut f)?;
            drop(f);
            let head = head_hash(&spool);
            let full = full_hash(&spool);
            let offered = name
                .clone()
                .filter(|_| single)
                .unwrap_or_else(|| "stdin.bin".into());
            outgoing.push(Outgoing {
                id,
                sid,
                name: offered,
                size: n,
                head,
                full,
                path: spool,
                temp: true,
                accepted_once: false,
                sent: false,
                acked: false,
                declined: false,
                done: false,
                stream_started: None,
                stream_bytes: 0,
            });
        } else {
            let path = PathBuf::from(p);
            let meta = std::fs::metadata(&path).with_context(|| format!("stat {p}"))?;
            if meta.is_dir() {
                if name.is_some() && single {
                    ui::say(&ui::paint(
                        ui::Tone::Warn,
                        "--name is ignored for a directory (it's tarred under the directory name)",
                    ));
                }
                let dirname = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "dir".into());
                let spool = std::env::temp_dir().join(format!(
                    "filament-tar-{}-{}.tar",
                    std::process::id(),
                    i
                ));
                ui::say(&format!("packing {p} -> {dirname}.tar ..."));
                {
                    let f = std::fs::File::create(&spool)?;
                    let mut b = tar::Builder::new(f);
                    b.append_dir_all(&dirname, &path)?;
                    b.finish()?;
                }
                let size = std::fs::metadata(&spool)?.len();
                let head = head_hash(&spool);
                let full = full_hash(&spool);
                outgoing.push(Outgoing {
                    id,
                    sid,
                    name: format!("{dirname}.tar"),
                    size,
                    head,
                    full,
                    path: spool,
                    temp: true,
                    accepted_once: false,
                    sent: false,
                    acked: false,
                    declined: false,
                    done: false,
                    stream_started: None,
                    stream_bytes: 0,
                });
            } else {
                // A single regular file with --name uses the override; otherwise
                // the basename. With multiple files --name was already warned off.
                let offered = name.clone().filter(|_| single).unwrap_or_else(|| {
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| p.clone())
                });
                let head = head_hash(&path);
                let full = full_hash(&path);
                outgoing.push(Outgoing {
                    id,
                    sid,
                    name: offered,
                    size: meta.len(),
                    head,
                    full,
                    path,
                    temp: false,
                    accepted_once: false,
                    sent: false,
                    acked: false,
                    declined: false,
                    done: false,
                    stream_started: None,
                    stream_bytes: 0,
                });
            }
        }
    }
    for o in &outgoing {
        ui::say(&format!("send: {} ({})", o.name, human(o.size)));
    }
    if opened_flow {
        let total = outgoing.iter().map(|item| item.size).sum::<u64>();
        eprintln!();
        eprintln!("  {}", ui::paint(ui::Tone::Brand, "SEND"));
        eprintln!(
            "  files    {} item{} / {}",
            outgoing.len(),
            if outgoing.len() == 1 { "" } else { "s" },
            human(total)
        );
        eprintln!(
            "  to       {}",
            to.as_deref().unwrap_or(if use_code {
                "one-time code"
            } else {
                "nearby receiver"
            })
        );
        eprintln!("  proof    receiver must acknowledge the whole-file hash");
        let mut replay = vec!["filament".to_string(), "send".to_string()];
        replay.extend(paths.iter().map(|path| command_arg(path)));
        if let Some(target) = to.as_deref() {
            replay.extend(["--to".to_string(), command_arg(target)]);
        } else if use_code {
            replay.push("--code".to_string());
        }
        eprintln!("  command  {}", replay.join(" "));
        let confirmation = prompt_line("\n  Press Enter to send, or type cancel: ")?;
        if confirmation.eq_ignore_ascii_case("cancel") {
            bail!("cancelled");
        }
    }

    let room = match room {
        Some(r) => r,
        None => net::fetch_auto_room(server).await?,
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(server, tx.clone()).await?;
    // C30: the convergent session repairs room/channel/lease state the
    // one-shot emits lose (the fast path stays for old servers + latency);
    // under gate L these initial emits are exactly what the shim drops.
    let mut sess = session::Session::new(&display_name(), &my_uid);
    sess.room = Some(room.clone());
    sess.emit(
        &sio,
        "join",
        json!({ "room": room, "name": display_name(), "uid": my_uid }),
    )
    .await;

    // C12: --to matching a remembered device switches to identity mode,
    // subscribe to its presence channel and wait for known-peer.
    // A FLEET sibling has no pair secret, so it is dialed on the fleet secret and
    // met on the fleet channel. That authenticates the link as "someone in this
    // fleet" and NOTHING more, because every sibling shares both. `fleet_target`
    // therefore gates every file-offer on the certificate: without it,
    // `send --to laptop` would hand the file to whichever sibling answered first.
    let mut fleet_target = false;
    // `to` is moved into the peer filter further down; keep the name for the
    // refusal messages, which are emitted long after that move.
    let fleet_target_name: String = to.clone().unwrap_or_default();
    // BROKERED RENDEZVOUS, tried before anything else for a fleet sibling.
    //
    // Our daemon already holds a certificate-verified link to that peer, so it
    // can hand it a one-time secret over that link and tell us the same secret.
    // Both ends then meet on channel_of(secret), where exactly two parties
    // exist, and the secret proves the peer exactly as a pair secret does.
    //
    // This is the answer to the reliability problem rather than another
    // condition on the fleet handshake. A one-shot on the fleet channel has to
    // work out which of several answering siblings is the target while they all
    // race; four attempts to make that race safer each measured WORSE. Here the
    // race does not exist, because only the target was ever told the address.
    //
    // Falls through silently when there is no daemon or no verified link: then
    // the existing paths apply and nothing is lost.
    let brokered_target: Option<(String, String)> = match (to.as_deref(), fleet::rv()) {
        (Some(t), Some(_)) if fleet_indexed_name(t) => match ctl::try_fleet_rendezvous(t).await {
            Some(sec) => {
                ui::debug(&format!(
                    "fleet: daemon brokered a private rendezvous with '{t}'"
                ));
                Some((t.to_string(), sec))
            }
            None => {
                ui::debug(&format!(
                    "fleet: no brokered rendezvous for '{t}'; falling back"
                ));
                None
            }
        },
        _ => None,
    };
    if brokered_target.is_none() && std::env::var("FILAMENT_FLEET_SEND").as_deref() != Ok("1") {
        if let Some(t) = to.as_deref() {
            if fleet_indexed_name(t)
                && !devices_load()
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(t))
            {
                bail!(
                    "send --to '{t}': your daemon has no verified link to it right now, so it \
                     cannot broker a private rendezvous. Start `filament up` on both devices and \
                     retry, or use its mesh address ({t}.mesh)."
                );
            }
        }
    }
    let known_target: Option<(String, String)> = brokered_target.clone().or_else(|| to.as_ref().and_then(|t| {
        devices_load()
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(t))
            .or_else(|| {
                // INCOMPLETE, opt-in only. Everything up to identity proof works
                // and is verified: the sender dials the fleet channel, skips a
                // sibling whose certificate names a different device (measured:
                // it correctly refused to hand a file to `owner` when asked for
                // `laptop`), and reaches the right peer. What is NOT finished is
                // the binding handshake on a transport with no RFC-5705 exporter:
                // the peer's hello can arrive before the sender has established
                // its challenge nonce, and verification then fails closed.
                //
                // Fails closed, so it never misdelivers, but a half-finished
                // feature should not be the default: without the opt-in,
                // `send --to <sibling>` keeps the clear "not yet a send target"
                // message rather than an error that reads like a security alarm.
                // Set FILAMENT_FLEET_SEND=1 to work on it. The former implementation audit is archived in docs/archive/handoffs/WORK-STATE-2026-09-03.md.
                if std::env::var("FILAMENT_FLEET_SEND").as_deref() != Ok("1") {
                    return None;
                }
                // EXPERIMENTAL, and the honest reason is RELIABILITY, not
                // safety. It is correct when it completes and it fails closed:
                // the misdelivery bug (`fleet_proven` was a single bool meaning
                // "some peer proved", read as "THIS peer proved") is fixed, and
                // no measured run has ever delivered to the wrong device.
                //
                // It still does not complete often enough. Measured 2026-08-27,
                // interleaved A/B so the sibling arm and the paired control share
                // one time window, two independent rigs, release build, one inbox
                // per node, zero stale daemons on the channel:
                //
                //     sibling -> sibling   ~50/55   (91%)  with the active-slot fix
                //     sibling -> sibling     8/15   (53%)  before it
                //     device  -> owner      45/45  (100%)  throughout
                //
                // The paired control at 100% across the same windows is what says
                // the gap is specific to the fleet path, not the box or the rig.
                //
                // TWO measurement traps, both of which produced wrong numbers here:
                // stale daemons from previous runs sit on the SAME fleet channel
                // under the SAME owner key and are indistinguishable from real
                // siblings; and running one arm fully before the other lets a bad
                // window land on one arm, which had the SAME binary read 2/8 and
                // 8/8. Any fleet number without a zero-daemon check AND
                // interleaving is void.
                ui::say(&ui::paint(
                    ui::Tone::Warn,
                    "  FILAMENT_FLEET_SEND: experimental. Fails closed and has never misdelivered; it completes about 9 times in 10, and a failure costs a 45s timeout.",
                ));
                let rv = fleet::rv()?;
                fleet_indexed_name(t).then(|| {
                    fleet_target = true;
                    (t.clone(), rv)
                })
            })
    }));
    // Proven identity for a fleet target, PER PEER.
    //
    // This was a single bool, and that was a misdelivery bug: it meant "some peer
    // proved itself" while every read of it meant "THIS peer proved itself". On
    // the fleet channel several siblings are present, so once any one of them
    // verified, the offer guard passed for all of them and the file went to
    // whichever peer the loop reached next. Measured: verified pid=8gNe as
    // 'laptop', then offered to pid=yNDj (the owner), which accepted.
    // The fleet handshake, as ONE object rather than six ad-hoc collections.
    //
    // This used to be `fleet_proven` + `fleet_wrong` + `fleet_bind_ours` +
    // `fleet_rechallenged` + `fleet_deadline`, hand-maintained here and
    // hand-maintained AGAIN in the daemon's receive loop. The two copies drifted
    // and every drift was the same shape: state describing "the peer", stored as
    // one value, on a channel that carries EVERY sibling. Four bugs came out of
    // that, including a misdelivery. `FleetSession` keys all of it by peer id by
    // construction, so the mistake has nowhere to live.
    //
    // The daemon's copy was the one that already got this right (its bindings
    // were per-peer HashMaps), so `fleet_session.rs` follows THAT implementation,
    // not this one.
    let mut fleet_sess = fleet_session::FleetSession::new();
    let fleet_proof_budget = Duration::from_secs(
        std::env::var("FILAMENT_FLEET_PROOF_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12),
    );
    let mut channel_digest_absent: HashMap<String, u8> = HashMap::new();
    // L1-a: `send --code` now mints a v2 nameplate (client-minted words, the
    // server allocates ONLY the numeric nameplate) and runs the SAME ephemeral
    // SPAKE2 ceremony as `pair` before any byte flows, then DISCARDS the secret
    // (transfer = "link with mutual auth, then forget"). The words NEVER cross
    // the server; only the nameplate does. The full `words-nameplate` code is
    // displayed from our own local mint when pair-ok arrives.
    let mut send_words = String::new(); // the SPAKE2 password (only when use_code)
    let mut send_nameplate = String::new();
    if let Some((n, sec)) = &known_target {
        ui::say(&format!(
            "  waiting for known device {}",
            ui::paint(ui::Tone::Bold, n)
        ));
        sess.channels = vec![channel_of(sec)];
        sess.emit(&sio, "subscribe", json!({ "channels": [channel_of(sec)] }))
            .await;
    } else if use_code {
        // The words are the user's chosen phrase (--word) or a fresh mint; the
        // nameplate is ALWAYS machine-minted. `split_chosen_code` keeps both
        // words of a two-word phrase (it only strips a trailing 3-5 digit group).
        send_words = match &word {
            Some(w) => {
                let (words, _np) = crate::pake::split_chosen_code(&crate::pake::norm_code(w));
                if let Err(why) =
                    crate::pake::words::validate_chosen_password(&words, &display_name())
                {
                    bail!("'{w}' is too weak: {why}");
                }
                words
            }
            None => crate::pake::words::mint_words(),
        };
        send_nameplate = crate::pake::words::mint_nameplate();
        sio.emit(
            "pair-create",
            json!({ "nameplate": send_nameplate, "v": 2 }),
        )
        .await
        .ok();
    } else {
        ui::say(&format!(
            "waiting for a peer in room {room} (same network auto-discovers; or use --code)"
        ));
    }
    // Live spinner while nothing is connected yet (tty only; stops at adopt).
    let waiting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let waiting = waiting.clone();
        tokio::spawn(async move {
            while waiting.load(std::sync::atomic::Ordering::Relaxed) {
                ui::status(&format!("  {} waiting...", ui::spinner_frame()));
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
        });
    }

    let mut conn = Conn::for_command(
        server,
        sio.clone(),
        tx.clone(),
        my_uid,
        relay,                    // relay_only
        to,                       // to_filter
        false,                    // warm_standby default (one-shot send)
        direct::direct_enabled(), // direct_ok: env gate only (file transfer keeps WebRTC default)
    );
    if known_target.is_some() {
        conn.to_filter = None; // identity supersedes name matching
    }
    let mut code_used = !use_code && known_target.is_none();
    // L1-a ephemeral PAKE on the transfer path. When `--code` is used, run the
    // SAME SPAKE2 ceremony `pair` runs, then DISCARD the secret (auth only). The
    // file-offers are GATED on the ceremony agreeing a secret (`pake_done`); a
    // local-network send (no code) and a known-device send (already proven via
    // channel_of/proof_for) keep the existing, unchanged path (`pake_done` set
    // true up front so they offer immediately). `send_cer` is the ceremony; it
    // is only ever populated on the code path.
    let mut send_cer: Option<Ceremony> = if use_code {
        Some(Ceremony::new(
            &send_words,
            &send_nameplate,
            pair_v2_caps(),
            crate::identity::IntroScope::Device.to_byte(),
        ))
    } else {
        None
    };
    let mut pake_peer: Option<String> = None;
    // The transfer is allowed to offer once auth is settled: immediately for
    // local / known-device sends; only after the ephemeral PAKE confirms for the
    // code path. The agreed secret is then DISCARDED (never stored).
    let mut pake_done = !use_code;
    // Interop / downgrade: a code-path peer that never runs the v2 ceremony is on
    // an older build. Once the channel is up, give the ceremony a bounded budget;
    // if it doesn't confirm, fail LOUDLY ("update to transfer securely") rather
    // than hang. Mirrors `pair`'s ceremony_deadline.
    let pake_budget = Duration::from_secs(
        std::env::var("FILAMENT_PAIR_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
    );
    let mut pake_deadline: Option<Instant> = None;
    // U5: the remember ceremony's state for this run.
    //
    // `pending_offer` holds the ONE offer we have made and that is not yet
    // answered. Its secret exists only here until an accepting ack arrives:
    // that is what makes "silence is a refusal" true by construction rather
    // than by a timer, because the only write is in `remember::apply_ack`.
    // `remember_outcome` is what we will TELL the operator at exit, and it is
    // set from what actually happened, never from the flag.
    let mut pending_offer: Option<Offer> = None;
    let mut offered_peers: HashSet<String> = HashSet::new();
    let mut remember_outcome: Option<RememberOutcome> = None;
    // How long a remember-only run waits for the peer and its answer before
    // saying, honestly, that nothing was stored.
    let remember_budget = Duration::from_secs(
        std::env::var("FILAMENT_REMEMBER_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
    );
    let remember_deadline = Instant::now() + remember_budget;
    // C30 phase 3: link mini-sync, pings out, divergence corrections in.
    let mut last_state_ping = Instant::now();
    let mut reproved: std::collections::HashSet<String> = Default::default();
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Bounded force-exit guarantee (see the acceptor path): Ctrl-C must
            // exit promptly even if the unwind/peer-drop deadlocks.
            shutdown::arm_force_exit(130, shutdown::grace());
            let _ = tx.send(Ev::Interrupted);
        });
    }
    let outgoing = Arc::new(tokio::sync::Mutex::new(outgoing));
    let started = Instant::now();
    let claim_deadline = Duration::from_secs(600);
    // Bug 6: bound ESTABLISHMENT. netcat/ssh cap how long they hunt for a peer;
    // `send` had no such bound, so an ICE wedge (no candidate pair ever
    // nominates) hung unbounded with the spinner spinning. Cap the time to the
    // FIRST live data channel (ChannelReady); once a channel is up, a long
    // legitimate transfer is never interrupted by this. Overridable / disablable
    // (0 = off) via FILAMENT_SEND_TIMEOUT.
    let establish_deadline = std::env::var("FILAMENT_SEND_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60));
    let mut established = false;
    // Bug 5: count stuck-while-connecting events to hint at the mDNS wedge once.
    let mut stuck_while_connecting = 0u32;
    let mut wedge_hint_shown = false;
    let mut saw_known_peer: HashSet<String> = HashSet::new();
    // P4 (delivery-ack window): when every transfer's bytes have been `sent` but
    // the whole-file `delivery-ack` hasn't landed, we wait up to this bound for
    // the ack. CRITICAL (silent-data-loss fix): elapsing this window does NOT mean
    // "declare done". The bytes draining out of the send buffer proves nothing, a
    // path that black-holes without QUIC noticing drains while NOTHING arrives and
    // no ack comes. So on no-ack we re-probe once (re-send file-end to prompt a
    // possibly-lost ack), and if the ack still never lands we FAIL the send
    // (nonzero, partial kept resumable), never a false "delivered + verified".
    // Overridable via FILAMENT_ACK_TIMEOUT (seconds). The never-hangs property
    // holds: we reach a terminal state in bounded time, just an honest one.
    let ack_wait = std::env::var("FILAMENT_ACK_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(15));
    // After the first window with no ack we re-send file-end and wait this much
    // longer for a (possibly lost) ack before giving up. Short: the ack is a tiny
    // control message, on a healthy link it returns within a round-trip.
    let ack_reprobe = Duration::from_secs(5);
    let mut sent_all_at: Option<Instant> = None;
    let mut ack_reprobed = false; // re-sent file-end once for the no-ack window?
    let mut reprobed_at: Option<Instant> = None;

    loop {
        // Bug 6: no data channel has come up within the establishment window,
        // an ICE wedge or a peer that claimed the code but never connected. Fail
        // honestly instead of spinning forever. A non-zero deadline only; a live
        // channel (established) disarms it so big transfers are never cut off.
        if !established && !establish_deadline.is_zero() && started.elapsed() >= establish_deadline
        {
            ui::clear_sticky();
            bail!(
                "no peer connected within {}s, is a receiver running / the page open? \
                 (set FILAMENT_SEND_TIMEOUT to change or 0 to disable)",
                establish_deadline.as_secs()
            );
        }
        // The wait-for-peer deadline only applies while we have no peer (F3).
        let ev = if conn.active.is_none() && conn.rejoin.waiting_rejoin.is_none() {
            // C30: read in ≤2s slices, a blocking full-deadline read starves
            // the session tick, so a dropped initial subscribe was never
            // repaired and the wait could NEVER succeed (found by gate L's
            // seed-16 choreography: the daemon healed, the sender starved).
            if started.elapsed() >= claim_deadline {
                bail!(
                    "timed out waiting for a peer, is the other device online and on the same server? (--code makes pairing explicit)"
                );
            }
            let slice =
                Duration::from_secs(2).min(claim_deadline.saturating_sub(started.elapsed()));
            match tokio::time::timeout(slice, rx.recv()).await {
                Ok(Some(ev)) => Some(ev),
                Ok(None) => bail!("signaling channel closed"),
                Err(_) => None, // tick
            }
        } else {
            next_ev(&mut rx, &conn, false).await?
        };
        // C30: converge session state every iteration (incl. ticks).
        sess.tick(&sio).await;
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // A fleet peer that has not proved itself within budget stops holding the
        // target slot. Treated as "not the target" rather than as a failure: it
        // may simply be a sibling that never speaks fleet to us (see the paired
        // owner above), and the device we asked for may still be out there.
        if fleet_target {
            let _now = Instant::now();
            for p in fleet_sess.lapsed(Instant::now()) {
                ui::debug(&format!(
                    "fleet: pid={p} did not prove itself within {}s; releasing the slot",
                    fleet_proof_budget.as_secs()
                ));
                if conn.is_active(&p) {
                    conn.active = None;
                }
                conn.drop_link(&p);
                established = false;
            }
        }
        // L1-a ephemeral PAKE progression (code path only). Once the link to our
        // PAKE counterpart is up: send our SPAKE2 element, then (once K + both
        // DTLS fingerprints exist) the key-confirmation MAC. The secret is
        // DISCARDED after auth (`pake_done`), never stored.
        if let (Some(cer), Some(pid)) = (send_cer.as_mut(), pake_peer.clone()) {
            if let Some(data) = cer.take_msg_payload() {
                sio.emit("signal", json!({ "to": pid, "data": data }))
                    .await
                    .ok();
            }
            if cer.has_k() {
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    } {
                        if let Some(data) = cer.take_confirm_payload(&my_fp, &their_fp) {
                            sio.emit("signal", json!({ "to": pid, "data": data }))
                                .await
                                .ok();
                        }
                    }
                }
            }
        }
        // Interop / downgrade: the ephemeral ceremony must confirm within budget
        // once the channel is up, a peer that never runs it is an older build.
        if !pake_done {
            if let Some(dl) = pake_deadline {
                if Instant::now() > dl {
                    ui::clear_sticky();
                    bail!(
                        "the other device uses an older version and can't receive securely over a code. Update it (or this CLI) so the transfer runs the encrypted handshake. Nothing was sent."
                    );
                }
            }
        }
        // rung-1: a direct attempt that timed out without an authenticated QUIC
        // connection falls back to the WebRTC establish (unchanged path).
        // This is the sender-side expired_direct caller: the ESTABLISH caller
        // location is sufficient to distinguish this fallback from adoption.
        // The receiver-side caller below routes through maybe_adopt instead.
        for (pid, info, (n, sec)) in conn.expired_direct() {
            conn.establish_as(info, None).await.with_context(|| {
                format!("direct fallback establish failed for peer {pid} on send path")
            })?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
            if conn.to_filter.is_none() && conn.active.is_none() {
                conn.active = Some(pid.clone());
            }
        }
        // C30 phase 3: tell every link our truth every ~10s (sender side has
        // no receive-partials; the ping mainly carries trusted/away and keeps
        // the peer's away-mark honest).
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for l in conn.links.values() {
                if let Some(t) = &l.transport {
                    let _ = t
                        .send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": {},
                            "trusted": l.trusted,
                            "away": false,
                        }))
                        .await;
                }
            }
        }
        // P0 (GAP-1): bytes-moved STALL watchdog (send side). A transfer is in
        // flight once the active peer accepted an offer that isn't done; if that
        // link then moves zero bytes past the stall threshold (a black-holed data
        // path, the 0% hang) we emit Ev::TransferStalled, which drives the
        // correction ladder below. The control-channel liveness probe gates it so
        // a genuinely DEAD link falls to the C3/C4 path instead.
        if let Some(active) = conn.active.clone() {
            let in_flight = {
                let out = outgoing.lock().await;
                out.iter().any(|o| o.accepted_once && !o.sent)
            };
            if let Some(idle) = conn.detect_stall(&active, in_flight) {
                let transport_dead = conn
                    .transport_of(&active)
                    .map(|t| t.is_dead())
                    .unwrap_or(false);
                // A dead transport can't pass link_alive (write_framed sees
                // dead=true and returns Err), but a structurally dead transport
                // (I/O error, not a vanished peer) IS repairable via the
                // ladder's re-dial rung. Only suppress the stall when the
                // transport is NOT dead AND the control path is silent — which
                // means the peer itself is gone (the C3/C4 establishment path
                // owns that case).
                if transport_dead || conn.link_alive(&active).await {
                    let _ = tx.send(Ev::TransferStalled(active, idle));
                } else {
                    conn.note_progress(&active);
                }
            }
        }
        // P5 (GAP-6): relay->direct upgrade prober (send side). Probe for a direct
        // path while serving on relay; verify-before-upgrade cuts over only when a
        // direct standby is confirmed stable. No-op unless a peer is relay-committed
        // on an eligible session.
        conn.tick_upgrade_prober().await;
        let Some(ev) = ev else { continue };

        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                // P5 (GAP-6): a fresh signaling welcome (reconnect) is a moment a
                // new direct path may have appeared, re-probe immediately for any
                // relay-committed peer rather than waiting out the backoff.
                conn.reprobe_on_network_event();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(p, code_used).await?;
                    }
                }
                // C30 (dissolves the C28 belt): fresh sid = everything
                // sid-keyed is gone; invalidate and let the session re-assert.
                sess.invalidate();
            }
            // C30: server confirmed our session digest. Phase 2: reconcile the
            // roster it carries, so a `welcome` or `peer-joined` we never
            // received self-corrects. Without this the sender waits out the
            // full 600s claim deadline while the peer can see it, which is the
            // one-directional presence failure the macOS smoke job hits: the
            // receiver recovers via this same digest (it already reconciles),
            // the sender never did because it discarded the roster.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(p, code_used, AdoptSource::Digest)
                            .await?;
                    }
                    if let Some((name, secret)) = &known_target {
                        let channel = channel_of(secret);
                        let present: std::collections::HashSet<String> = roster
                            .channel_peers
                            .iter()
                            .filter_map(|p| p["id"].as_str().map(String::from))
                            .collect();
                        let stale: Vec<String> = conn
                            .links
                            .iter()
                            .filter_map(|(pid, link)| {
                                let matches = link
                                    .expected_secret
                                    .as_ref()
                                    .map(|(_, s)| channel_of(s) == channel)
                                    .unwrap_or(false);
                                if matches && !present.contains(pid) {
                                    let count =
                                        channel_digest_absent.entry(pid.clone()).or_insert(0);
                                    *count += 1;
                                    (*count >= 2).then(|| pid.clone())
                                } else {
                                    channel_digest_absent.remove(pid);
                                    None
                                }
                            })
                            .collect();
                        for pid in stale {
                            channel_digest_absent.remove(&pid);
                            conn.drop_link(&pid);
                        }
                        for p in &roster.channel_peers {
                            if p["channel"].as_str() != Some(channel.as_str())
                                || is_self_uid(&conn.my_uid, p["uid"].as_str())
                            {
                                continue;
                            }
                            let pid = p["id"].as_str().unwrap_or_default().to_string();
                            conn.start_direct(&pid, name, secret).await;
                            conn.maybe_adopt_from(p, true, AdoptSource::Digest).await?;
                            if let Some(l) = conn.link_mut(&pid) {
                                l.expected_secret = Some((name.clone(), secret.clone()));
                            }
                        }
                    }
                }
            }
            // L1-a: the server allocated our v2 nameplate. Display the FULL
            // `words-nameplate` code assembled from OUR OWN local mint (the
            // server never echoes any words). The receiver runs the SAME
            // ephemeral SPAKE2 ceremony before any byte flows.
            Ev::PairOk(v) => {
                let ttl = v["ttl"].as_u64().unwrap_or(600);
                let full = format!("{send_words}-{send_nameplate}");
                let site = if server == DEFAULT_SERVER {
                    "https://filament.autumated.com".to_string()
                } else {
                    server.to_string()
                };
                ui::clipboard(&full);
                ui::say("");
                ui::say(&format!(
                    "  code   {}   {}",
                    ui::paint(ui::Tone::Brand, &full),
                    ui::paint(ui::Tone::Dim, "(copied to clipboard)")
                ));
                ui::say(&format!(
                    "         {}",
                    ui::paint(
                        ui::Tone::Dim,
                        &format!(
                            "terminal: filament receive {full}   browser: {} (RECEIVE WITH CODE)",
                            ui::link(&site, &site.replace("https://", ""))
                        )
                    )
                ));
                ui::say(&format!(
                    "         {}",
                    ui::paint(
                        ui::Tone::Dim,
                        &format!(
                            "one claim · expires in {} min · authenticated end-to-end (no key crosses the server)",
                            ttl / 60
                        )
                    )
                ));
                ui::say("");
            }
            // A legacy server (or a v2-stripping one) minted a whole code: it
            // can't run the secure ceremony. Refuse rather than fall back to an
            // unauthenticated transfer (mirrors `pair`'s downgrade-refusal).
            Ev::PairCode(_v) => {
                bail!(
                    "this server returned a legacy transfer code and can't authenticate the transfer. Update the server (or the peer) to transfer securely."
                );
            }
            Ev::PairError(v) => {
                // Nameplate collision on create: re-mint a FRESH nameplate (and
                // fresh words when we minted them) and retry, never reuse a
                // burned code. The ephemeral ceremony restarts with the new pair.
                if use_code && v["error"].as_str() == Some("taken") {
                    if word.is_none() {
                        send_words = crate::pake::words::mint_words();
                    }
                    send_nameplate = crate::pake::words::mint_nameplate();
                    if let Some(cer) = send_cer.as_mut() {
                        cer.restart(&send_words, &send_nameplate);
                    }
                    sio.emit(
                        "pair-create",
                        json!({ "nameplate": send_nameplate, "v": 2 }),
                    )
                    .await
                    .ok();
                    continue;
                }
                bail!("pairing failed: {}", v["error"].as_str().unwrap_or("?"));
            }
            Ev::PairUsed(_) => {
                ui::say("code claimed, connecting...");
                code_used = true;
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, code_used).await?;
            }
            Ev::KnownPeer(v) => {
                if is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own daemon shares this channel
                }
                if let Some((n, sec)) = &known_target {
                    if v["channel"].as_str() == Some(channel_of(sec).as_str()) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        // Liveness-aware: skip only if a healthy link already exists.
                        // If the link is dead or absent, re-establish (reconnect-after-loss).
                        let link_alive = conn
                            .link(&pid)
                            .and_then(|l| l.transport.as_ref())
                            .map(|t| !t.is_dead())
                            .unwrap_or(false);
                        if link_alive {
                            if !saw_known_peer.contains(n) {
                                saw_known_peer.insert(n.clone());
                            }
                            continue;
                        }
                        if !saw_known_peer.contains(n) {
                            ui::say(&format!("known device '{n}' is online, connecting"));
                        }
                        saw_known_peer.insert(n.clone());
                        // rung-1: both ends are CLIs (known device), try direct
                        // QUIC FIRST. start_direct records the pending so the
                        // maybe_adopt->establish below skips the WebRTC offer
                        // until the budget expires (then it falls back).
                        let (n, sec) = (n.clone(), sec.clone());
                        conn.start_direct(&pid, &n, &sec).await;
                        conn.maybe_adopt(&v, true).await?;
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = Some((n.clone(), sec.clone()));
                        }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates, kick off the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    // rung-2: optional server-reflexive candidate for hole-punch.
                    let srflx = data["srflx"].as_str().map(String::from);
                    // #237: the candidate the peer adopted on the server's say-so
                    // alone (the one OUR race will dial and may have to name),
                    // and the peer's protocol version (gates the observed-address
                    // exchange; an offer without `proto` is an older build).
                    let peer_server_public = data["server_public"].as_str().map(String::from);
                    let peer_proto = data["proto"].as_u64().unwrap_or(1).clamp(1, 255) as u8;
                    // P5 (GAP-6): a `probe:true` offer is a relay->direct UPGRADE
                    // probe from the other end. If we're serving this peer on relay
                    // and have no probe of our own yet, ARM one so the symmetric
                    // direct dial can complete (a later re-send of the offer, the
                    // peer re-emits 6x, is consumed by our now-armed pending). The
                    // winner posts DirectUpgradeReady (verify-before-upgrade), never
                    // clobbering the serving relay link.
                    if data["probe"].as_bool() == Some(true) {
                        conn.answer_upgrade_probe(&from).await;
                    }
                    // Bug 2: same buffer-and-replay as the recv-side handler.
                    // The receiver's re-dial transport-offer may arrive before
                    // our DirectPending exists (our start_direct hasn't returned
                    // yet, or PeerLeft dropped the link before the repair).
                    if conn.direct_pending.contains_key(&from) {
                        conn.on_transport_offer(
                            &from,
                            cands,
                            srflx,
                            peer_server_public,
                            peer_proto,
                        );
                    } else {
                        let known = crate::devices_load().into_iter().find(|(n, _)| {
                            conn.links.get(&from).map(|l| l.name == *n).unwrap_or(false)
                        });
                        if let Some((name, secret)) = known {
                            conn.start_direct(&from, &name, &secret).await;
                        }
                        if conn.direct_pending.contains_key(&from) {
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
                        }
                    }
                    continue;
                }
                // L1-a: PAKE messages ride the opaque `signal` relay. Route them
                // OUT of the WebRTC path into the ephemeral ceremony (code path).
                // On confirm the secret is agreed; we record auth done and then
                // DISCARD the secret (transfer never persists it).
                if matches!(
                    data["type"].as_str(),
                    Some("pake-msg") | Some("pake-confirm")
                ) {
                    if let Some(cer) = send_cer.as_mut() {
                        pake_peer.get_or_insert(from.clone());
                        let fps = match conn.link(&from) {
                            Some(l) => match &l.peer {
                                Some(p) => p.fingerprints().await,
                                None => None,
                            },
                            None => None,
                        };
                        let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                        match cer.on_signal(&data, fp_ref) {
                            PakeInbound::Consumed => {
                                if let Some(sec) = cer.secret() {
                                    if !pake_done {
                                        pake_done = true;
                                        ui::say(&ui::paint(
                                            ui::Tone::Dim,
                                            "  authenticated, sending",
                                        ));
                                        // Option A: race direct-quic FIRST; start_direct
                                        // replaces WebRTC only after pending registration.
                                        // If direct wins: transfer rides QUIC (130+ MB/s).
                                        // If direct fails: expired_direct → establish → WebRTC fallback
                                        //   (bounded ~5s gap for NAT-blocked peers, then WebRTC reconnects).
                                        let promo =
                                            conn.start_direct_promote(&from, &from, &sec).await;
                                        if conn.active.is_none() {
                                            conn.active = Some(from.clone());
                                        }
                                        // Offers were deferred pending this confirm, and
                                        // the ChannelReady handler ignores a non-active
                                        // pid, so this must follow the claim above.
                                        conn.rearm_channel_ready(&from, promo);
                                    }
                                }
                            }
                            PakeInbound::Abort(why) => {
                                ui::clear_sticky();
                                bail!(
                                    "transfer REFUSED: {why}. Nothing was sent; ask for a FRESH code."
                                );
                            }
                            PakeInbound::Ignored => {}
                        }
                        continue;
                    }
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                conn.ensure_responder(&from, &data).await?;
                conn.apply_signal(&from, data).await;
            }
            // rung-1: the authenticated direct-QUIC connection won the race.
            // Create the (pre-trusted) Link, then funnel into the SAME ready
            // handler the WebRTC path uses (announce + offers) by re-emitting
            // ChannelReady, the transfer logic rides the trait unchanged.
            Ev::DirectReady(pid, t, route) => {
                let tkey = conn
                    .direct_pending
                    .get(&pid)
                    .map(|p| direct::transport_key(&p.secret.1));
                conn.adopt_direct(&pid, t.clone(), route);
                if let Some(k) = tkey {
                    conn.spawn_direct_workers(&pid, &t, k);
                }
                let _ = tx.send(Ev::ChannelReady(pid, t));
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
            // P5 (GAP-6): a relay->direct upgrade probe's direct standby connected
            // ALONGSIDE the live relay link. Do NOT adopt it (that would clobber the
            // serving relay link); stash it as a warm standby and enter VERIFY. The
            // per-tick prober (judge_upgrade_standby) decides whether to cut over
            // (sustained progress) or discard (no flap).
            Ev::DirectUpgradeReady(pid, t, route) => {
                conn.stash_upgrade_standby(&pid, t, route);
            }
            Ev::ChannelReady(pid, t) => {
                // Already proved itself to be a DIFFERENT sibling. Stay polite,
                // never target: re-running the handshake here is what looped.
                if fleet_target && fleet_sess.is_wrong(&pid) {
                    if conn.is_active(&pid) {
                        conn.active = None;
                    }
                    conn.drop_link(&pid);
                    continue;
                }
                conn.mark_ready(&pid, &t, false);
                // Responder links stop here: connected, polite, idle. Only
                // the active target gets announcements + offers.
                if !conn.is_active(&pid) {
                    continue;
                }
                // Bug 6: a live channel to the active peer disarms the
                // establishment timeout, the rest of the transfer is unbounded.
                established = true;
                waiting.store(false, std::sync::atomic::Ordering::Relaxed);
                // Fleet target: present our certificate and demand theirs before
                // anything is offered. Fails closed, including on a transport with
                // no channel binding, because there is nothing to bind a proof to.
                //
                // Greeting EVERY fleet link rather than only the active one was
                // tried (a receiver cannot verify a sender that never introduced
                // itself) and measured 17/20 and 7/20 across two rigs against a
                // committed baseline of 15/15 and 16/20. Not shipped: it is
                // plausible but unproven, and rig-to-rig variance is larger than
                // the effect. Settle the measurement before revisiting it.
                if fleet_target && !fleet_sess.proved(&pid) {
                    match fleet_sess.greet(&pid, t.channel_binding(), link_nonce, |cb| {
                        fleet::make_hello(cb, &display_name())
                    }) {
                        fleet_session::Action::Send(msg) => {
                            let _ = t.send_control(&msg).await;
                        }
                        fleet_session::Action::Idle => {}
                    }
                }
                if let Some(l) = conn.link(&pid) {
                    ui::say(&format!(
                        "  {} {}",
                        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                        ui::paint(ui::Tone::Bold, l.shown())
                    ));
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
                    // L1-a: on the `--code` path, run the ephemeral SPAKE2
                    // ceremony BEFORE offering any byte. While auth is pending,
                    // mark this peer as our PAKE counterpart, arm the bounded
                    // budget, and DEFER offers. The progression block (top of
                    // loop) drives the ceremony; on confirm the Signal handler
                    // sets `pake_done` and re-emits ChannelReady to fall through
                    // here and offer. The secret is DISCARDED after auth.
                    if use_code && !is_direct && !pake_done {
                        pake_peer.get_or_insert(pid.clone());
                        pake_deadline.get_or_insert_with(|| Instant::now() + pake_budget);
                        ui::say(&ui::paint(ui::Tone::Dim, "  authenticating..."));
                        continue; // offers/remember wait for PAKE confirm
                    }
                    // Same rule for a FLEET target, for the same reason: the link
                    // is authenticated but the PEER is not yet identified, and
                    // every sibling shares the secret that got us here. Presenting
                    // our certificate is not enough; nothing is offered until
                    // THEIRS has verified (the Control arm sets `fleet_proven`,
                    // and a mismatch bails there rather than falling through).
                    if fleet_target && !fleet_sess.proved(&pid) {
                        ui::debug(&format!(
                            "fleet-send: deferring offer to pid={pid} (identity unproven)"
                        ));
                        fleet_sess.arm_deadline(&pid, fleet_proof_budget);
                        ui::say(&ui::paint(ui::Tone::Dim, "  verifying fleet identity..."));
                        continue;
                    }
                    if fleet_target {
                        ui::debug(&format!(
                            "fleet-send: OFFERING to pid={pid} (identity proven)"
                        ));
                    }
                    // C12: prove identity to a known device (their daemon
                    // auto-accepts only after verifying); or hand over a new
                    // pair secret when the user asked to --remember. A DIRECT
                    // link already proved the secret via the QUIC keying-material
                    // MAC (>= the DTLS pair-proof), so it skips this dance.
                    if is_direct {
                        // pre-authenticated; nothing to prove over the channel.
                    } else if let Some((_n, sec)) = &l.expected_secret {
                        if let Some((my_fp, their_fp)) = match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        } {
                            t.send_control(&json!({
                                "type": "pair-proof",
                                "mac": proof_for(sec, &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                            })).await?;
                        } else {
                            ui::say(&ui::paint(
                                ui::Tone::Warn,
                                "no DTLS fingerprints available, skipping identity proof",
                            ));
                        }
                    }
                    // U5: the remember offer rides the SAME gate as a file
                    // offer, and for the same reason. Everything above has
                    // settled who this peer is (PAKE confirmed on the code
                    // path, certificate proven on a fleet link, pre-proven on a
                    // direct one); offering a shared secret before that would
                    // hand it to whoever answered first. One offer per peer.
                    if let Some(rname) = &remember {
                        if pending_offer.is_none() && offered_peers.insert(pid.clone()) {
                            let o = remember::make_offer(rname, &pid);
                            t.send_control(&remember::offer_frame(&o)).await?;
                            pending_offer = Some(o);
                            ui::say(&format!(
                                "  offering to remember {}, and to be remembered by it.",
                                ui::paint(ui::Tone::Bold, rname)
                            ));
                            ui::say(&ui::paint(
                                ui::Tone::Dim,
                                "  waiting for the other side to accept (nothing is stored until it does)...",
                            ));
                        }
                    }
                    // (Re-)offer everything unfinished; resume:true after a
                    // prior accept so receivers continue from their partial.
                    // (The `--code` path offers later, post-PAKE; this is the
                    // local-network / known-device / direct path.)
                    for o in outgoing.lock().await.iter() {
                        if o.done {
                            continue;
                        }
                        let offer = protocol::offer_msg(
                            &o.id,
                            o.sid,
                            &o.name,
                            o.size,
                            o.head.as_deref(),
                            o.full.as_deref(),
                            o.accepted_once,
                        );
                        t.send_control(&offer).await?;
                    }
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                // Fleet target: the peer's certificate. The fleet secret proved
                // it is IN the fleet; this proves WHICH member. The device key it
                // names must resolve to the local record the user typed, or we
                // refuse and send nothing.
                // The fleet handshake, delegated. Both arms of the conversation
                // (their challenge, their certificate) are ONE call into
                // `FleetSession`, which owns the per-peer binding, the per-peer
                // retry budget and the proven/wrong verdict. This block used to
                // be ~150 lines duplicating the daemon's, and every place the two
                // drifted was a bug.
                Some("l3-nonce") | Some(fleet::HELLO)
                    if fleet_target && !fleet_sess.proved(&pid) =>
                {
                    let exporter = conn.transport_of(&pid).and_then(|t| t.channel_binding());
                    let outcome = fleet_sess.on_control(
                        &pid,
                        &v,
                        exporter,
                        fleet::my_owner_pub(),
                        Some(&fleet_target_name),
                        identity::now_secs(),
                        link_nonce,
                        |cb| fleet::make_hello(cb, &display_name()),
                        |pubk| device_name_for_pub(pubk),
                    );
                    match outcome {
                        fleet_session::Outcome::Ignored => {}
                        fleet_session::Outcome::Send(msg) => {
                            if let Some(t) = conn.transport_of(&pid) {
                                let _ = t.send_control(&msg).await;
                            }
                        }
                        fleet_session::Outcome::WrongPeer { proved } => {
                            // Not an attack and not fatal: every fleet member sits
                            // on this channel, so whoever answered first is simply
                            // not the one asked for. Drop it, free the slot, keep
                            // waiting. Bailing here would make `send --to` fail
                            // whenever a sibling answered sooner.
                            ui::debug(&format!(
                                "fleet: '{}' answered for '{fleet_target_name}'; not the target, waiting",
                                proved.as_deref().unwrap_or("an unknown device")
                            ));
                            if conn.is_active(&pid) {
                                conn.active = None;
                            }
                            conn.drop_link(&pid);
                            established = false;
                            continue;
                        }
                        fleet_session::Outcome::Proved { .. } => {
                            ui::debug(&format!(
                                "fleet target '{fleet_target_name}' proved its certificate on pid={pid}"
                            ));
                            // THE PROVEN PEER IS THE TARGET. On a fleet send
                            // identity is the selector: a peer whose certificate
                            // names the device the user asked for IS that device.
                            //
                            // Without this the re-emit below is thrown away one
                            // line into the ChannelReady handler, which opens with
                            // `if !conn.is_active(&pid) { continue }`. Whoever won
                            // the slot first keeps it, and on this channel that is
                            // routinely some OTHER sibling, so the real target
                            // proved itself into a slot it did not own and its
                            // offer was never made. That was the whole "sibling
                            // send is unreliable" symptom.
                            conn.active = Some(pid.clone());
                            // RE-EMIT ChannelReady, exactly as the PAKE path does
                            // on confirm: the offer lives in that handler, which
                            // already ran and deferred while identity was unproven.
                            if let Some(t) = conn.transport_of(&pid) {
                                let _ = tx.send(Ev::ChannelReady(pid.clone(), t));
                            }
                        }
                        fleet_session::Outcome::Refused(e) => bail!(
                            "refusing to send to '{fleet_target_name}': its certificate did not verify ({e})"
                        ),
                    }
                }
                Some("worker-ports") => {
                    let pid = v["for"].as_str().unwrap_or_default();
                    ui::trace(&format!(
                        "[T:SERVE] worker-ports handler: looking up key={pid}"
                    ));
                    if let Some(tx) = conn.worker_port_tx.remove(pid) {
                        ui::trace(&format!("[T:SERVE] worker-ports handler: FOUND key={pid}"));
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
                // #30 GAP 1: a one-shot sender must ANSWER the receiver's
                // identity-nonce-challenge (prove device-key possession) so the
                // receiver can upgrade the sender's binding to Proven and an
                // authoritative cap gate can ALLOW the transfer. Placed before
                // the is_active guard so it fires as soon as the challenge lands.
                Some("identity-nonce-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        respond_to_identity_challenge(&t, &v).await;
                    }
                }
                // Enroller receives the daemon's nonce challenge — build
                // EnrollmentPayload and send the response.
                Some("identity-auth-key-enroll-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                        let verifier_hex = v["verifier_pub"].as_str().unwrap_or_default();
                        if let (Ok(nonce_bytes), Ok(verifier_bytes)) =
                            (hex::decode(nonce_hex), hex::decode(verifier_hex))
                        {
                            if let (Ok(nonce_arr), Ok(verifier_pub)) = (
                                nonce_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                                verifier_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            ) {
                                let device_cert = v
                                    .get("device_cert")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null);
                                if let Some(response) = crate::ephemeral::build_enrollment_response(
                                    &pid,
                                    nonce_arr,
                                    verifier_pub,
                                    &device_cert,
                                ) {
                                    let mut msg =
                                        json!({ "type": "identity-auth-key-enroll-response" });
                                    if let Some(obj) = response.as_object() {
                                        for (k, v) in obj {
                                            msg[k] = v.clone();
                                        }
                                    }
                                    let _ = t.send_control(&msg).await;
                                }
                            }
                        }
                    }
                }
                _ if !conn.is_active(&pid) => {}
                Some("brb") => {
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.rejoin.away =
                        Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    ui::say(&conn.roster(&pid, "●", ui::Tone::Warn, "away, holding the line", &n));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                }
                // C30 phase 3: the peer's periodic truth, correct one-sided
                // beliefs instead of letting them persist.
                Some("state") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid); // a state ping proves they're not frozen
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        ui::say(&conn.roster(&pid, ui::glyph_ok(), ui::Tone::Ok, "back", &n));
                    }
                    // Transfer divergence: I believe it complete; the peer
                    // holds fewer bytes, the END/tail was lost. Re-offer.
                    if let Some(obj) = v["transfers"].as_object() {
                        let mut out = outgoing.lock().await;
                        for o in out.iter_mut() {
                            if let Some(b) = obj.get(&o.id).and_then(|x| x.as_u64()) {
                                if o.done && b < o.size {
                                    o.done = false; // not actually done
                                    // DEBUG, resilience internal (state-divergence re-offer).
                                    ui::debug(&ui::paint(
                                        ui::Tone::Warn,
                                        &format!(
                                            "  state-diverged: {}, peer holds {b}/{}; re-offering",
                                            o.name, o.size
                                        ),
                                    ));
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let offer = protocol::offer_msg(
                                            &o.id,
                                            o.sid,
                                            &o.name,
                                            o.size,
                                            o.head.as_deref(),
                                            o.full.as_deref(),
                                            true,
                                        );
                                        let _ = t.send_control(&offer).await;
                                    }
                                }
                            }
                        }
                    }
                    // Trust divergence: they don't recognize us but we hold a
                    // pair secret for them, re-prove ONCE per link.
                    if v["trusted"].as_bool() == Some(false) && !reproved.contains(&pid) {
                        let proof = match conn.link(&pid) {
                            Some(l) => match &l.expected_secret {
                                Some((_n, sec)) => (match &l.peer {
                                    Some(p) => p.fingerprints().await,
                                    None => None,
                                })
                                .map(|(my_fp, their_fp)| {
                                    proof_for(
                                        sec,
                                        &conn.my_uid,
                                        &conn.my_uid,
                                        l.uid.as_deref().unwrap_or(""),
                                        &my_fp,
                                        &their_fp,
                                    )
                                }),
                                None => None,
                            },
                            None => None,
                        };
                        if let Some(mac) = proof {
                            if let Some(t) = conn.transport_of(&pid) {
                                let _ = t
                                    .send_control(&json!({ "type": "pair-proof", "mac": mac }))
                                    .await;
                                reproved.insert(pid.clone());
                                ui::debug(&ui::paint(
                                    ui::Tone::Dim,
                                    "  state-diverged: re-proving identity",
                                ));
                            }
                        }
                    }
                }
                // C27/U5: the other side answered our remember offer. The
                // record is written HERE, inside `apply_ack`, and the line
                // below is said only because that write returned Ok. The old
                // code printed "mutually remembered" off the `--remember` flag
                // alone while `send` had never stored anything and never even
                // emitted a `pair-keep`: the claim and the effect had no
                // relationship at all. They are now the same statement.
                Some("pair-keep-ack") => {
                    let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    match remember::apply_ack(&mut pending_offer, &pid, &v)? {
                        Ack::Accepted { name, secret } => {
                            // C30: the link can now be re-found on the pair
                            // channel, exactly as a `pair` would leave it.
                            sess.channels.push(channel_of(&secret));
                            sess.touch();
                            sio.emit("subscribe", json!({ "channels": [channel_of(&secret)] }))
                                .await
                                .ok();
                            remember_outcome = Some(RememberOutcome::Remembered(name.clone()));
                            ui::say(&conn.roster(
                                &pid,
                                ui::glyph_ok(),
                                ui::Tone::Ok,
                                &format!("mutually remembered as '{name}', stored"),
                                &n,
                            ));
                        }
                        Ack::Declined => {
                            remember_outcome = Some(RememberOutcome::Declined);
                            ui::say(&conn.roster(
                                &pid,
                                ui::glyph_err(),
                                ui::Tone::Warn,
                                "declined to be remembered, nothing stored",
                                &n,
                            ));
                        }
                        // An ack for an offer we do not hold. Ignored, per the
                        // contract; it must never be applied to a different
                        // outstanding offer.
                        Ack::Unmatched => {
                            ui::debug("pair-keep-ack answered no offer of ours, ignoring");
                        }
                    }
                }
                // U5: either side may offer, so the sending side answers one
                // too. Consent here is our own `--remember <name>` or `--yes`;
                // with neither we refuse and say the flag, and nothing is
                // stored on either end.
                Some("pair-keep") => {
                    let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    let ans = remember::answer_offer(&v, remember.as_deref(), &n)?;
                    match &ans {
                        remember::Answer::Kept { name, secret } => {
                            sess.channels.push(channel_of(secret));
                            sess.touch();
                            sio.emit("subscribe", json!({ "channels": [channel_of(secret)] }))
                                .await
                                .ok();
                            remember_outcome = Some(RememberOutcome::Remembered(name.clone()));
                            ui::say(&conn.roster(
                                &pid,
                                ui::glyph_ok(),
                                ui::Tone::Ok,
                                &format!("mutually remembered as '{name}', stored"),
                                &n,
                            ));
                        }
                        remember::Answer::Refused { why } => ui::say(&ui::paint(ui::Tone::Dim, why)),
                        remember::Answer::Ignored => {}
                    }
                    if let (Some(ok), Some(t)) = (ans.ok(), conn.transport_of(&pid)) {
                        t.send_control(&remember::ack_frame(&v, ok)).await.ok();
                    }
                }
                // C27: their verdict on our identity proof. false = they have
                // no memory of us, stop acting like a known device.
                Some("pair-proof-ack") => {
                    if v["ok"].as_bool() == Some(false) {
                        let n = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = None;
                        }
                        ui::say(&conn.roster(
                            &pid,
                            ui::glyph_err(),
                            ui::Tone::Warn,
                            "doesn't recognize this device, re-pair with --remember",
                            &n,
                        ));
                    }
                }
                Some("file-accept") => {
                    let Some(t) = conn.transport() else { continue };
                    // Build transport list: primary + any parallel QUIC workers.
                    let workers = conn
                        .link(&pid)
                        .map(|l| l.workers.clone())
                        .unwrap_or_default();
                    let mut transports = vec![t];
                    transports.extend(workers);
                    let offset = v["offset"].as_u64().unwrap_or(0);
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    {
                        let mut out = outgoing.lock().await;
                        if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                            o.accepted_once = true;
                        }
                    }
                    let out = outgoing.clone();
                    // Use the transport's OWN max payload, not conn.chunk_size:
                    // chunk_size is pinned to the 60 KiB WebRTC DataChannel limit
                    // (MAX_DC_PAYLOAD), which needlessly throttled the direct-QUIC
                    // path to tiny chunks. On QUIC max_payload() is far larger, so
                    // far fewer chunks pass through the receiver's single event-loop
                    // consumer (record_range + seek + write) per byte.
                    let chunk = transports[0].max_payload();
                    let tx2 = tx.clone();
                    // #28 test hook: the active peer's sid, so the streamer can
                    // synthesize a peer-left for it mid-flight (see stream_one).
                    let active_sid = conn.active.clone();
                    tokio::spawn(async move {
                        match stream_one(
                            out,
                            transports,
                            id.clone(),
                            offset,
                            chunk,
                            active_sid,
                            tx2.clone(),
                        )
                        .await
                        {
                            Ok(()) => {
                                let _ = tx2.send(Ev::TransferDone(id));
                            }
                            Err(e) => {
                                // C10: surface through the loop; the transfer
                                // stays pending and re-offers on reconnect.
                                let _ = tx2.send(Ev::TransferFailed {
                                    id,
                                    err: e.to_string(),
                                });
                            }
                        }
                    });
                }
                Some("file-decline") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        ui::say(&format!("declined: {}", o.name));
                        o.declined = true;
                        o.done = true;
                    }
                }
                // P4 (delivery-ack): the receiver computed the whole-file sha256
                // of every byte it received and it MATCHED our offered digest,
                // the bytes landed INTACT. Only now is the transfer truly `done`
                // (vs the old fire-and-forget where `file-end` alone "completed"
                // it). This closes the loop the runner had to fake above the
                // transport: the sender deterministically KNOWS it landed whole.
                Some("delivery-ack") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        if !o.acked {
                            o.acked = true;
                            o.done = true;
                            // #262: THIS is the instant the bytes are known to be
                            // on the far side, so this is the interval the
                            // throughput line is entitled to divide by. Printing
                            // it at `flush()` measured the send buffer filling.
                            if let Some(t0) = o.stream_started {
                                ui::transfer_summary(
                                    &o.name,
                                    o.stream_bytes,
                                    t0.elapsed().as_secs_f64(),
                                );
                            }
                            ui::say(&ui::paint(
                                ui::Tone::Dim,
                                &format!(
                                    "    {} delivered + verified (whole-file sha256 matched)",
                                    o.name
                                ),
                            ));
                        }
                    }
                }
                _ => {}
            },
            Ev::TransferFailed { id, err } => {
                let out = outgoing.lock().await;
                let name = out
                    .iter()
                    .find(|o| o.id == id)
                    .map(|o| o.name.as_str())
                    .unwrap_or("?");
                // DEBUG, resilience internal (transfer interrupted, will resume).
                ui::debug(&format!(
                    "{name}: interrupted ({err}), will resume on reconnect"
                ));
            }
            // P0 (GAP-1): the bytes-moved watchdog declared this transfer stalled.
            // Drive the least-disruptive correction ladder, preserving the on-disk
            // partial at every rung (C7 resume).
            Ev::TransferStalled(pid, idle_ms) => {
                if !conn.is_active(&pid) {
                    continue; // only the transfer-target peer's stall matters
                }
                // DEBUG, resilience internal (stall detection).
                ui::debug(&ui::paint(
                    ui::Tone::Warn,
                    &format!("  stall detected: {idle_ms}ms with no data, correcting"),
                ));
                match conn.correct_stall(&pid).await {
                    Rung::Resume => {
                        // Rung (a): re-issue every unfinished transfer with
                        // resume:true on the SAME transport. The receiver's
                        // file-accept carries its `.part` offset, so streaming
                        // continues from where it stalled (no restart-from-zero).
                        // If the link has no live transport, Resume is futile.
                        if conn.transport_of(&pid).is_none() {
                            ui::debug(&format!(
                                "  resume skipped: no live transport for {pid}, awaiting next repair cycle"
                            ));
                        } else if let Some(t) = conn.transport_of(&pid) {
                            let out = outgoing.lock().await;
                            for o in out.iter().filter(|o| o.accepted_once && !o.done) {
                                let offer = protocol::offer_msg(
                                    &o.id,
                                    o.sid,
                                    &o.name,
                                    o.size,
                                    o.head.as_deref(),
                                    o.full.as_deref(),
                                    true,
                                );
                                let _ = t.send_control(&offer).await;
                            }
                        }
                    }
                    // Rung (c): the transport was repaired in place inside
                    // correct_stall (fresh direct dial / ICE-restart). The new
                    // transport's ChannelReady re-offers the unfinished transfers
                    // (resume:true), nothing more to do here.
                    Rung::Repaired => {}
                    // Rung (d) P1: correct_stall re-established this transfer over
                    // the TURN relay (relay-only ICE), preserving the partial. The
                    // fresh relay link's ChannelReady re-offers the unfinished
                    // transfers (resume:true) and prints the route, nothing more
                    // to do here.
                    Rung::Relayed => {}
                    // Direct rungs spent AND relay forbidden (--no-relay) or relay
                    // itself stalled: the ladder failed CLEANLY (a kept partial, the
                    // clear cause already shown in correct_stall). PROMPTLY end the
                    // send rather than letting the frozen transfer hang to a timeout,
                    // the hard direct-only promise is "fail clean, fast", never a
                    // hang. The receiver kept its `.part`, so re-running resumes.
                    Rung::Exhausted => {
                        // The hard direct-only promise is "fail clean AND FAST", never
                        // a hang. A signaling socket wedged by the same frozen path can
                        // make `disconnect()` itself block, so BOUND it: a 2s cap keeps
                        // the exit prompt (we're tearing down anyway; the OS reaps the
                        // socket). This only affects the already-failing path, it can
                        // never delay or alter a successful send.
                        let _ =
                            tokio::time::timeout(Duration::from_secs(2), sio.disconnect()).await;
                        if relay_forbidden() {
                            bail!(
                                "couldn't establish a direct path and relay is disabled (--no-relay), partial kept; re-run to resume, or drop --no-relay"
                            );
                        }
                        bail!(
                            "transfer stalled and no usable path remains, partial kept; re-run to resume"
                        );
                    }
                }
            }
            Ev::Interrupted => {
                ui::say(&format!(
                    "  {} interrupted, the receiver keeps its partial; re-run the same command to resume",
                    ui::paint(ui::Tone::Warn, "!")
                ));
                let _ = sio.disconnect().await;
                std::process::exit(130);
            }
            Ev::Stuck(pid, generation) => {
                // Bug 5: if we keep getting stuck BEFORE a channel ever came up,
                // surface the single-host mDNS hint once.
                if !established {
                    stuck_while_connecting += 1;
                    if stuck_while_connecting >= 2 {
                        maybe_hint_local_wedge(&mut wedge_hint_shown);
                    }
                }
                if conn
                    .on_stuck(&pid, generation, "stuck while connecting")
                    .await?
                {
                    bail!(
                        "lost the receiving peer after {} attempts; the partial is kept, re-run the same `filament send` to resume",
                        MAX_ATTEMPTS
                    );
                }
            }
            Ev::GraceExpired(pid, generation) => {
                if conn.on_stuck(&pid, generation, "lost").await? {
                    bail!(
                        "lost the receiving peer after {} attempts; the partial is kept, re-run the same `filament send` to resume",
                        MAX_ATTEMPTS
                    );
                }
            }
            Ev::PcState(pid, s) => conn.on_pc_state(&pid, &s).await,
            Ev::PeerLeft(v) => {
                let gone = v["id"]
                    .as_str()
                    .and_then(|p| conn.link(p))
                    .map(|l| l.name.clone());
                if conn.on_peer_left(&v) {
                    let all_done = outgoing.lock().await.iter().all(|o| o.done);
                    if !all_done {
                        let secs = REJOIN_WINDOW.as_secs();
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => ui::say(&conn.roster(
                                gid,
                                "○",
                                ui::Tone::Dim,
                                &format!("disconnected, waiting up to {secs}s"),
                                &n,
                            )),
                            // DEBUG, resilience internal (peer-disconnect wait).
                            None => ui::debug(&format!(
                                "peer disconnected, waiting up to {secs}s for them to come back"
                            )),
                        }
                    }
                }
            }
            _ => {}
        }
        // P4 (silent-data-loss fix): every transfer's BYTES have left this side
        // (`sent`), but a transfer is only truly `done` once the receiver returns a
        // whole-file-verified `delivery-ack`. Drain the wire first, then WAIT for
        // the ack, bounded by `ack_wait`. If the window elapses with no ack we do
        // NOT declare success (the old bug): we decide via decide_ack_fallback,
        // re-probe ONCE (re-send file-end to prompt a possibly-lost ack), and if
        // the ack still never lands we FAIL the send below (nonzero, partial kept
        // resumable). Only the real `delivery-ack` handler may set `o.done`.
        {
            let all_sent;
            let all_acked;
            let mut do_flush = false;
            let mut do_reprobe = false;
            let mut give_up = false;
            {
                let out = outgoing.lock().await;
                all_sent = !out.is_empty() && out.iter().all(|o| o.sent);
                all_acked = !out.is_empty() && out.iter().all(|o| o.done);
                if all_sent && !all_acked {
                    if sent_all_at.is_none() {
                        sent_all_at = Some(Instant::now());
                        do_flush = true;
                    }
                    let window_elapsed = sent_all_at
                        .map(|t| t.elapsed() >= ack_wait)
                        .unwrap_or(false);
                    let reprobe_elapsed = reprobed_at
                        .map(|t| t.elapsed() >= ack_reprobe)
                        .unwrap_or(false);
                    // Only act once a window has elapsed: the first ack_wait, or
                    // (after a re-probe) the shorter ack_reprobe window.
                    if (!ack_reprobed && window_elapsed) || (ack_reprobed && reprobe_elapsed) {
                        // A live transport attached is the "link alive" signal
                        // (mirrors the browser's data-channel-open check). A
                        // black-hole that QUIC hasn't noticed still reports a
                        // transport, so the re-probe path is what catches it.
                        let link_alive = conn.transport().is_some();
                        match protocol::decide_ack_fallback(link_alive, ack_reprobed) {
                            protocol::AckFallback::Reprobe => do_reprobe = true,
                            protocol::AckFallback::FailUnconfirmed => give_up = true,
                        }
                    }
                }
            }
            if do_flush {
                // Flush (NOT drain_finish) on first reaching the all-sent point:
                // push the wire so the receiver can finish + verify + ack. We do
                // NOT call drain_finish here because on direct-QUIC that ends the
                // send half (`finish()`), which would block a corrupt-case
                // RE-FETCH that needs to stream more bytes. The final exit block
                // does the authoritative drain_finish once the ack lands (no more
                // re-fetch possible by then). On a DataChannel both are just
                // flush(); on QUIC this keeps the stream open for a resume.
                if let Some(t) = conn.transport() {
                    let _ = t.flush().await;
                }
            }
            if do_reprobe {
                // The ack may have been lost on a still-alive link. Re-send file-end
                // for every unacked transfer to prompt the receiver to re-ack, then
                // wait one more (shorter) window. Never completes anything.
                ack_reprobed = true;
                reprobed_at = Some(Instant::now());
                let pending: Vec<(String, u32, String)> = {
                    let out = outgoing.lock().await;
                    out.iter()
                        .filter(|o| !o.done)
                        .map(|o| (o.id.clone(), o.sid, o.name.clone()))
                        .collect()
                };
                if let Some(t) = conn.transport() {
                    for (id, sid, name) in &pending {
                        ui::debug(&format!(
                            "  {name}: no delivery-ack yet, re-probing (re-sending file-end)"
                        ));
                        let _ = t.send_control(&protocol::end_msg(id, *sid)).await;
                    }
                    let _ = t.flush().await;
                }
            }
            if give_up {
                // No delivery-ack after the window + re-probe (or the link is gone).
                // Do NOT claim success: the receiver may have gotten nothing. Fail
                // honestly. The on-disk source is untouched and the outgoing entry
                // is preserved for resume; a fresh `send`/reconnect re-offers it.
                let names: Vec<String> = {
                    let out = outgoing.lock().await;
                    out.iter()
                        .filter(|o| !o.done)
                        .map(|o| o.name.clone())
                        .collect()
                };
                for name in &names {
                    ui::critical(&ui::paint(
                        ui::Tone::Warn,
                        &format!(
                            "  {name}: delivery not confirmed (no whole-file delivery-ack), the receiver may have gotten nothing; NOT marking complete"
                        ),
                    ));
                }
                let _ = sio.disconnect().await;
                bail!(
                    "delivery not confirmed: {} file(s) sent but never delivery-acked by the receiver (treating as unconfirmed, not delivered)",
                    names.len().max(1)
                );
            }
        }
        // Exit when every transfer reached a terminal state (`done` = acked, or the
        // bounded-fallback / un-hashable cases above).
        {
            let out = outgoing.lock().await;
            if !out.is_empty() && out.iter().all(|o| o.done) {
                if let Some(t) = conn.transport() {
                    // Block until the peer has acked every byte before we exit,
                    // a torn-down QUIC connection drops un-acked send-buffer bytes
                    // and truncates the last file (no-op on DataChannel, which
                    // already drained in flush()). Surface a drain failure rather
                    // than silently reporting "done" on a partial transfer.
                    if let Err(e) = t.drain_finish().await {
                        // CRITICAL, a possibly-incomplete delivery; must-see even under -q.
                        ui::critical(&ui::paint(
                            ui::Tone::Warn,
                            &format!("warning: transfer may be incomplete, {e}"),
                        ));
                    }
                }
                for o in out.iter().filter(|o| o.temp) {
                    let _ = std::fs::remove_file(&o.path);
                }
                let completed = out.iter().filter(|o| o.done && !o.declined).count();
                let declined = out.iter().filter(|o| o.declined).count();
                match send_outcome(completed, declined) {
                    SendOutcome::Complete { .. } => ui::say("done."),
                    SendOutcome::Declined {
                        completed: 0,
                        declined,
                    } => {
                        ui::say(&format!("no files delivered ({declined} declined)."));
                    }
                    SendOutcome::Declined {
                        completed,
                        declined,
                    } => {
                        ui::say(&format!(
                            "partial: {completed} delivered, {declined} declined."
                        ));
                    }
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = sio.disconnect().await;
                match send_outcome(completed, declined) {
                    SendOutcome::Complete { .. } => return Ok(()),
                    SendOutcome::Declined {
                        completed,
                        declined,
                    } => bail!("send incomplete: {completed} delivered, {declined} declined"),
                }
            }
        }
    }
}

async fn stream_one(
    outgoing: Arc<tokio::sync::Mutex<Vec<Outgoing>>>,
    transports: Vec<Arc<dyn Transport>>,
    id: String,
    offset: u64,
    chunk: usize,
    active_sid: Option<String>,
    tx: mpsc::UnboundedSender<Ev>,
) -> Result<()> {
    let (sid, name, size, path) = {
        let out = outgoing.lock().await;
        let o = out
            .iter()
            .find(|o| o.id == id)
            .ok_or_else(|| anyhow!("unknown transfer {id}"))?;
        (o.sid, o.name.clone(), o.size, o.path.clone())
    };
    if offset > 0 {
        // DEBUG, resilience internal (transfer resuming from a saved offset).
        ui::debug(&format!(
            "{name}: resuming at {} ({:.0}%)",
            human(offset),
            offset as f64 / size.max(1) as f64 * 100.0
        ));
    }
    // #28 deterministic test hook: once we cross this byte offset, synthesize a
    // peer-left for the ACTIVE peer WITHOUT touching the data channel, exactly
    // the "signaling reconnect mid-transfer, channel stays alive" case. The
    // deferred-drop path must keep the link and let the transfer finish on it.
    // Injecting the active sid is critical: a wrong id makes on_peer_left
    // return early (link-not-found) and the test would falsely pass.
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let inject_at: Option<u64> = test_hooks::inject_peer_left_at();
    let num = transports.len().max(1);
    // Split the remaining bytes [offset, size) into `num` contiguous ranges and
    // stream each over its OWN transport in a CONCURRENT task. The previous
    // round-robin ran on one task and awaited each send_frame, so it stalled on
    // whichever connection's flow-control window filled first and never used the
    // links in parallel. One task per connection lets every link drain at once,
    // which is the actual multi-stream win. The receiver reassembles by absolute
    // offset (positional writes), so range order does not matter.
    let bar = std::sync::Arc::new(tokio::sync::Mutex::new(ui::Progress::new(&name, size)));
    // #262: stamp the real start of the byte stream, so the completion rate can
    // be measured against the `delivery-ack` rather than against `flush()`.
    {
        let mut out = outgoing.lock().await;
        if let Some(o) = out.iter_mut().find(|o| o.id == id) {
            o.stream_started = Some(Instant::now());
            o.stream_bytes = size.saturating_sub(offset);
        }
    }
    let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(offset));
    let injected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let remaining = size.saturating_sub(offset);
    let per = remaining / num as u64;
    let mut handles = Vec::with_capacity(num);
    for i in 0..num {
        let start = offset + i as u64 * per;
        let end = if i == num - 1 { size } else { start + per };
        if start >= end {
            continue;
        }
        let t = transports[i].clone();
        let path = path.clone();
        let bar = bar.clone();
        let progress = progress.clone();
        let injected = injected.clone();
        let tx = tx.clone();
        let active_sid = active_sid.clone();
        handles.push(tokio::spawn(async move {
            let trace =
                cfg!(feature = "debug-logs") && std::env::var("FILAMENT_TRACE_THROUGHPUT").is_ok();
            let mut f = tokio::fs::File::open(&path).await?;
            f.seek(SeekFrom::Start(start)).await?;
            let mut pos = start;
            // Double-buffer with tracing + batching
            let mut buf_a = vec![0u8; chunk];
            let mut buf_b = vec![0u8; chunk];
            let mut using_buf_a = true;
            let mut chunk_idx: u64 = 0;

            // Prime the first read into buf_a.
            let first_want = std::cmp::min(chunk as u64, end - pos) as usize;
            if first_want == 0 {
                return Ok(());
            }
            let t_first_read = if trace {
                Some(std::time::Instant::now())
            } else {
                None
            };
            let mut cur_n = f.read(&mut buf_a[..first_want]).await?;
            let _first_read_us = t_first_read.map(|t| t.elapsed().as_micros()).unwrap_or(0);
            if cur_n == 0 {
                return Ok(());
            }

            while pos < end {
                // Gate 11b only: slow the send so the transfer is still in flight
                // when the reconnect lands. Zero in every build without test
                // hooks, and the no-hook twin returns 0, so the shipped loop is
                // unchanged.
                let stall = test_hooks::transfer_stall_ms();
                if stall > 0 {
                    tokio::time::sleep(Duration::from_millis(stall)).await;
                }
                // Fire the NEXT read (into the alternate buffer) BEFORE sending.
                let next_want = std::cmp::min(chunk as u64, end - (pos + cur_n as u64)) as usize;
                let next_read = if next_want > 0 {
                    let mut f2 = tokio::fs::File::open(&path).await?;
                    f2.seek(SeekFrom::Start(pos + cur_n as u64)).await?;
                    let alt_buf = if using_buf_a {
                        std::mem::replace(&mut buf_b, vec![0u8; chunk])
                    } else {
                        std::mem::replace(&mut buf_a, vec![0u8; chunk])
                    };
                    Some(tokio::spawn(async move {
                        let mut buf = alt_buf;
                        let n = f2.read(&mut buf[..next_want]).await?;
                        Ok::<(Vec<u8>, usize), anyhow::Error>((buf, n))
                    }))
                } else {
                    None
                };

                // Send the current buffer.
                let cur_buf = if using_buf_a {
                    &buf_a[..cur_n]
                } else {
                    &buf_b[..cur_n]
                };
                let t_send_start = if trace {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                t.send_frame(sid, pos, cur_buf).await?;
                let send_us = t_send_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                pos += cur_n as u64;

                let total = progress.fetch_add(cur_n as u64, std::sync::atomic::Ordering::Relaxed)
                    + cur_n as u64;
                // Batch progress ticks
                chunk_idx += 1;
                let should_tick = chunk_idx % 8 == 0 || pos >= end;
                let t_tick_start = if trace && should_tick {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                if should_tick {
                    bar.lock().await.tick(total);
                }
                let tick_us = t_tick_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                if trace && (chunk_idx % 10 == 0 || send_us + tick_us > 5000) {
                    dlog!(
                        "[TRACE stream_one] chunk={} offset={} len={} send_frame={}us tick={}us",
                        chunk_idx,
                        pos - cur_n as u64,
                        cur_n,
                        send_us,
                        tick_us
                    );
                }
                if let (Some(at), Some(asid)) = (inject_at, active_sid.as_ref()) {
                    if total >= at && !injected.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        eprintln!(
                            "[test] injecting synthetic peer-left for active sid at {total} bytes"
                        );
                        let _ = tx.send(Ev::PeerLeft(json!({ "id": asid })));
                    }
                }

                // Collect the next read (it was running while we sent).
                match next_read {
                    Some(handle) => match handle.await {
                        Ok(Ok((buf, n))) => {
                            if using_buf_a {
                                buf_b = buf;
                            } else {
                                buf_a = buf;
                            }
                            using_buf_a = !using_buf_a;
                            cur_n = n;
                            if cur_n == 0 {
                                break;
                            }
                        }
                        Ok(Err(e)) => return Err(e.into()),
                        Err(e) => return Err(anyhow!("read-ahead task panicked: {e}")),
                    },
                    None => break,
                }
            }
            t.flush().await?;
            Ok::<(), anyhow::Error>(())
        }));
    }
    for h in handles {
        h.await.map_err(|e| anyhow!("stream task join: {e}"))??;
    }
    // End frame on primary transport; flush all transports.
    transports[0]
        .send_control(&protocol::end_msg(&id, sid))
        .await?;
    for t in &transports {
        t.flush().await?;
    }
    let mut out = outgoing.lock().await;
    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
        // P4: the bytes + file-end left this side, but the transfer is NOT
        // `done` yet. It is `done` only once the receiver returns a whole-file-
        // verified `delivery-ack` (or the bounded no-ack fallback fires). A peer
        // that has nothing more to send for THIS file is `sent`; the all-done
        // exit waits on `acked`. If this file carries no `full` digest (we
        // couldn't hash it), there's nothing for the receiver to verify-and-ack,
        // so it's done on send, the legacy fire-and-forget behaviour, scoped to
        // exactly the un-hashable case.
        o.sent = true;
        if o.full.is_none() {
            o.acked = true;
            o.done = true;
            // #262: no digest means no `delivery-ack` is coming, so this is the
            // last instant we will ever have. The rate is honest about what it
            // can know here (bytes handed to the transport) and is the only case
            // that still ends its interval at `flush()`.
            let secs = o
                .stream_started
                .map(|t| t.elapsed().as_secs_f64())
                .unwrap_or(0.0);
            ui::transfer_summary(&o.name, o.stream_bytes, secs);
        }
    }
    Ok(())
}
