//! CLI dispatch: `main` parses the options, this decides what runs.
//!
//! Moved out of `main.rs` as one unit -- the `Cli` parse and the `Cmd` match
//! table, arm for arm, in the same order. `Cli`, `Cmd` and `BareTarget` stay
//! defined in the crate root and are imported here; they are private there, which
//! is already visible to this module, so none of them was promoted.
//!
//! The single cfg pair inside the body is the local-mount adapter: the active
//! half calls `mount_fuse_cmd` and the inactive half bails. Both halves travel
//! verbatim, and `mount_fuse_cmd`'s import carries the identical cfg because anyhow::{ Result, anyhow, bail };
use crate::BareTarget;
use crate::Cli;
use crate::Cmd;
use crate::DEFAULT_SERVER;
use crate::DevicesAction;
use crate::FORCE_INTERACTIVE;
use crate::IdAction;
use crate::NO_INTERACTIVE;
use crate::NO_RELAY;
use crate::ShellPolicy;
use crate::UiCapability;
use crate::add_for::add_for_cmd;
use crate::backup;
use crate::cancelled;
use crate::capability_list_summary;
use crate::certified_device_names;
use crate::channel_of;
use crate::classify_bare_token;
use crate::codeentry;
use crate::command_arg;
use crate::config_get;
use crate::config_set;
use crate::conn::owner_pub_for_resources;
use crate::ctl;
use crate::daemon_alive;
use crate::device_caps::{device_set_cap, devices_remove, effective_device_caps};
use crate::device_cert_for;
use crate::device_countdown;
use crate::device_entries;
use crate::device_record_exists;
use crate::devices_info;
use crate::devices_store::{devices_load, devices_path, with_devices_mut};
use crate::doctor;
use crate::down_cmd;
use crate::drop_dir;
use crate::enrollment::enroll_and_send_cmd;
use crate::ephemeral_cmd;
use crate::expose;
use crate::first_screen_actions;
use crate::fleet_certificate_warning;
use crate::fleet_ui;
use crate::format_approval_expiry;
use crate::identity;
use crate::init_experience;
use crate::install_transport_hooks;
use crate::interactive_requested;
use crate::invite_path_for;
use crate::join_cmd;
use crate::l2;
use crate::l3;
use crate::load_owner_key;
use crate::local_device_cert;
use crate::local_device_cert_path;
use crate::membership::{depart_cmd, introduce_cmd};
use crate::mount;
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "mount-macos"),
    all(target_os = "windows", feature = "mount-windows")
))]
use crate::mount_fuse_cmd;
use crate::overlay;
use crate::pair_cmd::pair_cmd;
use crate::pending_request_count;
use crate::platform;
use crate::principal_ceiling_for;
use crate::prompt_line;
use crate::recover_identity;
use crate::recv_cmd::recv_cmd;
use crate::requests_cmd;
use crate::require_known_device;
use crate::reset_cmd;
use crate::resolve_for_kind;
use crate::resolve_mount_plan;
use crate::send_cmd::send_cmd;
use crate::set_device_cert_revoked;
use crate::set_device_revoked;
use crate::settings;
use crate::sshkeys;
use crate::status_cmd;
use crate::token_is_pairing_code;
use crate::tour_cmd;
use crate::ui;
use crate::up_logs::{logs_cmd, up_cmd};
use crate::update_cmd;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser};
use serde_json::{Value, json};
use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) async fn async_main() -> Result<()> {
    // Pick ring explicitly before anything touches TLS. Kept UNCONDITIONAL on
    // purpose: skipping it for local-only commands was tried and measured at
    // exactly zero (6.7ms either way), so the conditional bought nothing and
    // would have put a branch in front of crypto initialisation for free.
    // `filament_signal::connect` also installs it, idempotently, so no call
    // site has to remember.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    // Tell the transport how to reach this host. It no longer reaches sideways
    // into the CLI for terminal output, settings, config paths or interface
    // enumeration; it asks, and these are our answers. Every hook has a safe
    // default, so a library consumer that installs none still gets a working
    // transport with the diagnostics discarded.
    install_transport_hooks();
    // #161 probe scope: mark this process as a live flow so the gate's
    // ordering-window probe fires here (and in the harness) but not in unit
    // tests that construct the window state deliberately.
    crate::capability::set_gate_live();
    // Migrate state from legacy cwd-relative .config/filament (the broken
    // Windows fallback when HOME was unset) to the platform-correct path.
    platform::Paths::migrate_legacy();
    match platform::Paths::repair_sensitive_permissions() {
        Ok(repaired) if repaired > 0 => {
            eprintln!("filament: repaired permissions on {repaired} sensitive config path(s)");
        }
        Ok(_) => {}
        Err(e) => eprintln!("filament: sensitive config permission repair failed: {e}"),
    }
    // Bare-arg comfort dispatch: `filament <path>` sends it with a code;
    // `filament <something-like-a-code>` claims it. Subcommands still win.
    let mut argv: Vec<String> = std::env::args().collect();
    if let Some(first) = argv.get(1) {
        // The real subcommand set, derived from clap so it can NEVER go stale. A
        // hardcoded list drifted (it missed proxy/expose/pair/set/pty/... and the
        // unknown-token branch below then wrongly rejected them). Includes hidden
        // commands + aliases, so every real verb is recognized.
        use clap::CommandFactory;
        let cmd_names: std::collections::HashSet<String> = {
            let c = Cli::command();
            let mut s = std::collections::HashSet::new();
            for sc in c.get_subcommands() {
                s.insert(sc.get_name().to_string());
                s.extend(sc.get_all_aliases().map(str::to_string));
            }
            s
        };
        if !first.starts_with('-') && !cmd_names.contains(first.as_str()) {
            // The router is pure argv transformation: it never escalates
            // privilege, prompts, or mutates capability state. It only decides what
            // a bare token most likely means; the actual command enforces grants.
            let first = first.clone();
            match classify_bare_token(&first, &|t| std::path::Path::new(t).exists(), &|t| {
                devices_load().iter().any(|(n, _)| n == t)
            }) {
                BareTarget::Help => {
                    // `help` / `help <sub>` as an alias for `--help`. clap's built-in
                    // `help` subcommand is not surfaced by `get_subcommands()` on the
                    // un-built command, so it never lands in `cmd_names` and the
                    // unknown-token guard would otherwise reject it. Rewrite it
                    // to the long-help flag: `help` -> `--help`, `help ssh` ->
                    // `ssh --help`.
                    argv.remove(1); // drop the "help" token
                    argv.push("--help".into());
                }
                BareTarget::Send => {
                    // `filament <path>` mints a one-time code so the other side can
                    // claim it without having been paired first.
                    argv.insert(1, "send".into());
                    argv.push("--code".into());
                }
                BareTarget::Add => {
                    // L1-a unification: a `word-word-NNNN` (4-digit) code now drives
                    // the SAME ephemeral SPAKE2 ceremony whether the verb is `pair`
                    // or `recv`; a bare code is ambiguous. We keep routing it to
                    // `pair` (the long-standing bare-code behavior, 4-digit codes
                    // were always pairing codes), so existing muscle memory is
                    // preserved. To RECEIVE a transfer code, run `filament recv
                    // <code>` explicitly (the `send --code` output prints exactly
                    // that hint), or `filament pair <code>` to remember the device.
                    argv.insert(1, "add".into());
                }
                BareTarget::Receive => {
                    // A legacy `word-word-NNN` (2-3 digit) transfer code from an old
                    // sender, receive it (no v2 ceremony; the recv path fails loudly
                    // if the peer can't run the handshake).
                    argv.insert(1, "receive".into());
                }
                BareTarget::Forward { lport, peer, rport } => {
                    // `filament device:port` -> `filament forward device:port`.
                    // The local and remote ports are the same number.
                    argv.remove(1);
                    argv.insert(1, "forward".into());
                    argv.insert(2, format!("{peer}:{rport}"));
                    if lport != rport {
                        argv.insert(3, "--lport".into());
                        argv.insert(4, lport);
                    }
                }
                BareTarget::Reach(dev_port) => {
                    // `filament device.mesh` or `filament device.mesh:port` ->
                    // `filament reach <device>.mesh[:port]`.
                    argv.remove(1);
                    argv.insert(1, "reach".into());
                    argv.insert(2, dev_port);
                }
                BareTarget::Shell => {
                    // Bare device name = shell in. `filament dovm` opens an interactive
                    // PTY. `filament dovm <cmd...>` runs a one-shot command over PTY
                    // (no sshd needed; the PTY protocol handles it).
                    argv.insert(1, "shell".into());
                }
                BareTarget::AmbiguousFileDevice => {
                    // The token is both a file and a known device. Refuse to guess
                    // which the user meant; naming both readings lets them pick.
                    let send_cmd = format!("filament send {first}");
                    let shell_cmd = format!("filament shell {first}");
                    let width = send_cmd.len().max(shell_cmd.len());
                    eprintln!(
                        "{} \"{first}\" is both a file here and a device you know. Say which:",
                        ui::paint(ui::Tone::Err, ui::glyph_err())
                    );
                    eprintln!(
                        "  {}  send the file",
                        ui::paint(ui::Tone::Dim, &format!("{send_cmd:width$}"))
                    );
                    eprintln!(
                        "  {}  open a shell on the device",
                        ui::paint(ui::Tone::Dim, &format!("{shell_cmd:width$}"))
                    );
                    std::process::exit(2);
                }
                BareTarget::Unknown => {
                    // Not a command, path, code, or paired device. Give a filament-native
                    // error with a did-you-mean over BOTH commands and device names,
                    // instead of clap's bare "unrecognized subcommand" (smart errors).
                    // The 0.7.5 rule: a deleted legacy name errors with a did-you-mean.
                    // The levenshtein hint below cannot match the renames (recv->receive
                    // is distance 3, pair->add is 4, identity->id is 8), so map them
                    // explicitly: this audience meets the product afresh and the old
                    // names should teach the new ones, not silently route.
                    let legacy = match first.as_str() {
                        "recv" => Some("receive"),
                        "pair" => Some("add"),
                        "identity" => Some("id"),
                        // 0.8.3: invite was absorbed into add --for <device|person>.
                        // The did-you-mean teaches instead of silently routing.
                        "invite" => Some("add --for"),
                        _ => None,
                    };
                    if let Some(h) = legacy {
                        eprintln!("filament: '{first}' is not a command");
                        eprintln!(
                            "  did you mean '{h}'?  the command was renamed; `filament --help` lists everything"
                        );
                        std::process::exit(2);
                    }
                    let mut cands: Vec<String> = cmd_names.iter().cloned().collect();
                    cands.extend(devices_load().into_iter().map(|(n, _)| n));
                    let hint = cands
                        .iter()
                        .map(|c| (settings::levenshtein(&first, c), c))
                        .filter(|(d, _)| *d <= 2)
                        .min_by_key(|(d, _)| *d)
                        .map(|(_, c)| c.clone());
                    eprintln!("filament: unknown command or device '{first}'");
                    if let Some(h) = hint {
                        eprintln!("  did you mean '{h}'?");
                    }
                    eprintln!(
                        "  see what you can do:  filament  ·  filament --help  ·  filament devices"
                    );
                    std::process::exit(2);
                }
            }
        }
    }
    // Papercut: `devices remove <x>` — `remove` is not a `devices` subcommand.
    // clap's own did-you-mean points at `rename` (nearest by edit distance), but
    // the semantic match for "remove a device" is `forget`. Intercept and say so
    // before clap emits its less-helpful suggestion.
    if argv.get(1).map(String::as_str) == Some("devices")
        && argv.get(2).map(String::as_str) == Some("remove")
    {
        eprintln!("filament: `devices remove` is not a command");
        eprintln!("  did you mean `filament devices forget <name>`?");
        std::process::exit(2);
    }
    if argv.len() == 1 && std::io::stdin().is_terminal() {
        let device_count = devices_load().len();
        let availability = if daemon_alive().is_some() {
            "AVAILABLE"
        } else {
            "PAUSED"
        };
        let header = format!("FILAMENT  /  {device_count} DEVICES  /  {availability}");
        let owner = identity::UserKey::load(&crate::platform::PlatformKeyStore)?.is_some();
        let joined = !owner && local_device_cert().is_some();
        let actions = first_screen_actions(owner, joined, device_count);
        let labels = actions
            .iter()
            .map(|(label, _)| (*label).to_string())
            .collect::<Vec<_>>();
        match codeentry::pick(&header, &labels)? {
            Some(index) => argv.extend(actions[index].1.split_whitespace().map(str::to_string)),
            // #209: Ctrl-C means stop. Answering it with the full
            // status-and-help screen reads as "I picked the first item and got a
            // help page", which is what the owner reported on Windows. Exit
            // quietly, status 0, printing nothing.
            //
            // This arm was mostly unreachable until #203 made cancelling work,
            // so fixing cancel is what turned a bad destination into a live one.
            // Every other `None =>` on a picker deserves the same second look.
            None => return Ok(()),
        }
    }
    // `add <code>` was how you accepted a code until the verbs split by role.
    // Clap answers it with "unexpected argument", which tells someone with the
    // old habit nothing about where the verb went. Name the replacement instead:
    // a removed spelling should point at its successor, once, and then be gone.
    // Global flags precede the verb (`filament --no-interactive add <code>`), so
    // find `add` rather than assuming argv[1], and inspect the token after it.
    if let Some(i) = argv.iter().position(|a| a == "add") {
        if let Some(next) = argv.get(i + 1).cloned() {
            // A code is WORD-WORD-NNNN or WORD-WORD-WORD-NNNN: at least two
            // dashes, and a LAST segment of exactly four digits (the machine
            // assigned connect number).
            //
            // The old rule was "contains a dash and any digit", justified by
            // "a device name may contain dashes but no digits". That held while
            // the name only arrived via --for. `add <name>` is positional now,
            // so the same token is a legitimate name and the loose rule refuses
            // it: `add my-laptop-2` was answered with "run filament join
            // my-laptop-2". Tightened against the format codes actually have.
            //
            //   brave-otter-ruby-3141  3 dashes, last 4 digits  -> code
            //   my-laptop-2            2 dashes, last 1 digit   -> name
            //   macbook-2019           1 dash                   -> name
            let looks_like_code = token_is_pairing_code(&next);
            if looks_like_code {
                bail!(
                    "`add` offers, `join` accepts. To claim that code run:  filament join {next}"
                );
            }
        }
    }
    let cli = Cli::parse_from(argv);
    let ui_caps = UiCapability::from_cli(&cli);
    // Resolve the global output verbosity ONCE, before any worker spawns:
    // FILAMENT_LOG (if set) overrides the -v/-q flags. Default = info.
    ui::init_verbosity(cli.verbose, cli.quiet);
    if let Some(n) = &cli.name_as {
        // single-threaded at this point (before the runtime spawns workers)
        unsafe { std::env::set_var("FILAMENT_NAME", n) };
    }
    // A --color flag overrides the NO_COLOR/TERM env contract (flags win); record
    // it before any output so both stdout (readout) and stderr (caps) honor it.
    if let Some(when) = &cli.color {
        unsafe { std::env::set_var("FILAMENT_COLOR", when) };
    }
    // P1 (GAP-4): record the hard direct-only choice before any worker spawns.
    // Precedence: an explicit --relay/--no-relay flag always wins; otherwise the
    // persistent `relay` setting (always|never|auto) decides.
    let relay = if cli.no_relay {
        NO_RELAY.store(true, std::sync::atomic::Ordering::Relaxed);
        false
    } else if cli.relay {
        true
    } else {
        match settings::get_str("relay", None).as_deref() {
            Some("always") => true,
            Some("never") => {
                NO_RELAY.store(true, std::sync::atomic::Ordering::Relaxed);
                false
            }
            _ => false,
        }
    };
    // Record the global --no-interactive opt-out before any command runs (the
    // gate also honors FILAMENT_NONINTERACTIVE and a non-TTY stdin).
    if cli.interactive && !std::io::stdin().is_terminal() {
        bail!("--interactive requires a terminal; remove it or provide every required option");
    }
    if cli.interactive && (cli.no_interactive || cli.json) {
        bail!("--interactive conflicts with --no-interactive and --json; pick one mode");
    }
    if cli.no_interactive || cli.json {
        NO_INTERACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    if cli.interactive {
        FORCE_INTERACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let server = if cli.server == DEFAULT_SERVER {
        config_get("server").unwrap_or(cli.server.clone())
    } else {
        cli.server.clone()
    };
    let server = server.trim_end_matches('/').to_string();
    // Bare `filament` (no subcommand): a short, state-aware tour of what you'd do
    // next, instead of clap's wall of subcommands. Power users still get --help.
    let Some(cmd) = cli.cmd else {
        return tour_cmd();
    };
    if cli.json
        && !matches!(
            &cmd,
            Cmd::Init { .. }
                | Cmd::Add { .. }
                | Cmd::Join { .. }
                | Cmd::Id { .. }
                | Cmd::Status { .. }
                | Cmd::Set { .. }
                | Cmd::Reach { .. }
                | Cmd::Doctor { .. }
                | Cmd::Addr { .. }
                | Cmd::Devices { action: None, .. }
        )
    {
        bail!(
            "--json is not implemented for this operation; refusing to mix human output with machine data"
        );
    }
    match cmd {
        Cmd::Init {
            name,
            inbox,
            recovery_file,
            recovery_fd,
            background,
            no_background,
        } => {
            let out = init_experience(
                &ui_caps,
                &server,
                relay,
                name,
                inbox,
                recovery_file,
                recovery_fd,
                background,
                no_background,
            )
            .await;
            // Mint the SSH CA key idempotently. Warn-only: init must not
            // fail for an SSH-CA nicety, and signing fails closed later
            // with a clear error until ssh-keygen succeeds.
            if out.is_ok() {
                if let Err(e) = crate::ssh_ca::ensure_ca_key(&crate::settings::config_dir()).await
                {
                    crate::ui::say(&format!(
                        "ssh CA not provisioned ({e}); `shell --ssh` signing will refuse until ssh-keygen succeeds (re-run init)"
                    ));
                }
            }
            out
        }
        Cmd::Send {
            paths,
            code,
            word,
            room,
            to,
            name,
            remember,
            auth_key,
        } => {
            if let Some(ak_path) = auth_key {
                enroll_and_send_cmd(&server, ak_path, to, paths, relay, remember).await
            } else {
                send_cmd(
                    &server,
                    paths,
                    code || word.is_some(),
                    word,
                    room,
                    to,
                    name,
                    relay,
                    remember,
                )
                .await
            }
        }
        Cmd::Receive {
            code,
            dir,
            yes,
            room,
            to,
            keep_open,
            remember,
            output,
            background,
        } => {
            let dir = drop_dir(dir);
            if background {
                // 0.8.5: receive --background was a second name for `up --install`
                // (the same call), created because `up` was hidden. `up` is now
                // visible, so the alias is gone. Teach, do not silently route.
                bail!(
                    "`receive --background` was renamed: the always-on receiver is the daemon. Run `up --install` instead"
                );
            } else {
                recv_cmd(
                    &server,
                    code,
                    dir,
                    yes,
                    room,
                    to,
                    keep_open,
                    relay,
                    remember,
                    false,
                    output,
                    ShellPolicy::Granted,
                    None,
                    false,
                )
                .await
            }
        }
        Cmd::Set {
            key,
            value,
            peer,
            dry_run,
            reset,
            hard,
            ..
        } => {
            settings::run_set(
                key.as_deref(),
                value.as_deref(),
                &peer,
                dry_run,
                reset,
                hard,
                ui_caps.yes,
                ui_caps.json || cli.json,
            )
            .await
        }
        Cmd::Addr { device, v4 } => {
            let json_output = ui_caps.json || cli.json;
            if let Some(name) = device {
                // Show a specific device's info.
                let all = devices_load();
                let entry = all.iter().find(|(n, _)| n == &name);
                if entry.is_none() && !device_record_exists(&name) {
                    bail!("no device named '{name}', see `filament devices`");
                }
                // main's effective_device_caps (it folds in expiry and revocation
                // rather than reading the raw list) with the fleet-safe channel:
                // a fleet sibling has no pair secret and therefore no pair
                // channel, and its overlay address is the thing this command
                // exists to show, so report that and leave the channel empty
                // rather than refusing to answer.
                let caps = effective_device_caps(&name);
                let channel = entry
                    .map(|(_, secret)| channel_of(secret))
                    .unwrap_or_default();
                // Load lastSeen and overlay addresses from the device store.
                let (last_seen, stored_v6, stored_v4) =
                    devices_info(&name).unwrap_or((0, None, None));
                let last_seen_str = if last_seen == 0 {
                    "never".to_string()
                } else {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let ago = now.saturating_sub(last_seen);
                    if ago < 60 {
                        "just now".to_string()
                    } else if ago < 3600 {
                        format!("{}m ago", ago / 60)
                    } else if ago < 86400 {
                        format!("{}h ago", ago / 3600)
                    } else {
                        format!("{}d ago", ago / 86400)
                    }
                };
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "name": name,
                            "channel": channel,
                            "caps": caps,
                            "lastSeen": last_seen,
                            "lastSeenLabel": last_seen_str,
                            "overlayV6": stored_v6,
                            "overlayV4": stored_v4,
                            "mesh": format!("{name}.mesh"),
                        }))?
                    );
                } else {
                    println!("  {}", ui::paint(ui::Tone::Bold, &name));
                    println!("  channel:  {}", &channel[..12.min(channel.len())]);
                    // Show overlay addresses if we have them.
                    if let Some(v6) = &stored_v6 {
                        let v4_str = stored_v4
                            .as_ref()
                            .map(|a| format!(" / {a}"))
                            .unwrap_or_default();
                        println!("  overlay:  {v6}{v4_str}");
                        println!("  mesh:     {name}.mesh");
                    }
                    // "granted" (not "caps") makes clear this is the LOCAL GRANT RECORD
                    // (what THIS machine authorized the peer to do), NOT what the peer offers.
                    println!("  granted:  {}", capability_list_summary(&caps));
                    println!("  last seen: {last_seen_str}");
                }
            } else {
                // Show this machine's address.
                let id = overlay::load_identity()?;
                let my_name = config_get("name").unwrap_or_else(|| l3::hostname());
                let mesh_name = l3::sanitize_host(&my_name);
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "name": mesh_name,
                            "overlayV6": id.addr().to_string(),
                            "overlayV4": id.addr_v4().to_string(),
                            "mesh": format!("{mesh_name}.mesh"),
                        }))?
                    );
                } else if v4 {
                    println!("{}", id.addr_v4());
                } else {
                    println!("  {}", ui::paint(ui::Tone::Bold, &mesh_name));
                    println!("  overlay:  {} (v4) / {} (v6)", id.addr_v4(), id.addr());
                    println!("  mesh:     {mesh_name}.mesh");
                }
            }
            Ok(())
        }
        Cmd::Id { action } => {
            match action.unwrap_or(IdAction::Show) {
                IdAction::Show => {
                    match identity::UserKey::load(&crate::platform::PlatformKeyStore)? {
                        None => {
                            if let Ok(raw) = std::fs::read_to_string(local_device_cert_path()) {
                                if let Ok(record) = serde_json::from_str::<Value>(&raw) {
                                    if let Some(cert) =
                                        identity::DeviceCert::from_json(&record["cert"])
                                    {
                                        let fingerprint = hex::encode(cert.user_pub)
                                            .chars()
                                            .take(8)
                                            .collect::<String>();
                                        if ui_caps.json {
                                            println!(
                                                "{}",
                                                serde_json::to_string_pretty(&json!({
                                                    "configured": true,
                                                    "fingerprint": fingerprint,
                                                    "role": "joined-device",
                                                    "holdsOwnerSigningKey": false,
                                                    "certificateExpires": cert.expires,
                                                }))?
                                            );
                                        } else {
                                            println!(
                                                "  identity:          {}",
                                                ui::paint(ui::Tone::Bold, &fingerprint)
                                            );
                                            println!(
                                                "  role:              joined device (no owner signing key)"
                                            );
                                            // #275: this printed the raw epoch, on the one
                                            // surface where a temporary guest's expiry is the
                                            // most important fact on the screen. Routed through
                                            // `device_countdown`, the same helper `devices`
                                            // renders from, so the two cannot drift and #236's
                                            // wording rules (nothing renews) apply here too.
                                            println!(
                                                "  local certificate: {}  ({})",
                                                device_countdown(
                                                    fleet_ui::devices::DeviceTier::Fleet,
                                                    Some(&cert)
                                                ),
                                                format_approval_expiry(cert.expires)
                                            );
                                        }
                                        return Ok(());
                                    }
                                }
                            }
                            if ui_caps.json {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&json!({ "configured": false }))?
                                );
                            } else {
                                println!(
                                    "no identity yet. Run 'filament init' or 'filament join'."
                                );
                            }
                        }
                        Some(uk) => {
                            let uk_pub = uk.public_key_bytes();
                            let certified = certified_device_names(&uk_pub);
                            if ui_caps.json {
                                let devices = certified
                                    .iter()
                                    .map(|(name, cert)| {
                                        json!({
                                            "name": name,
                                            "devicePub": hex::encode(cert.device_pub),
                                            "expires": cert.expires,
                                        })
                                    })
                                    .collect::<Vec<_>>();
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&json!({
                                        "configured": true,
                                        "fingerprint": uk.fingerprint(),
                                        "publicKey": uk.public_key_hex(),
                                        "role": "owner",
                                        "holdsOwnerSigningKey": true,
                                        "devices": devices,
                                    }))?
                                );
                                return Ok(());
                            }
                            println!(
                                "  user fingerprint: {}",
                                ui::paint(ui::Tone::Bold, &uk.fingerprint())
                            );
                            println!(
                                "  public key:       {}",
                                ui::paint(ui::Tone::Dim, &uk.public_key_hex())
                            );
                            let mut found = 0usize;
                            for (name, cert) in certified {
                                let exp = if identity::now_secs() >= cert.expires {
                                    "EXPIRED".to_string()
                                } else {
                                    format!(
                                        "{}d",
                                        cert.expires.saturating_sub(identity::now_secs()) / 86400
                                    )
                                };
                                println!(
                                    "  {} {}",
                                    ui::paint(ui::Tone::Bold, &name),
                                    ui::paint(ui::Tone::Dim, &format!("(valid {exp})"))
                                );
                                found += 1;
                            }
                            if found == 0 {
                                println!(
                                    "  {}",
                                    ui::paint(
                                        ui::Tone::Warn,
                                        "no certified local device record; run `filament init` or `filament id recover` on a clean device"
                                    )
                                );
                            }
                        }
                    }
                    Ok(())
                }
                IdAction::Recover {
                    words_file,
                    words_fd,
                } => recover_identity(&ui_caps, words_file, words_fd),
            }
        }
        Cmd::Config { key, value } => {
            match (key, value) {
                (Some(k), Some(v)) => {
                    config_set(&k, &v)?;
                    println!("{k} = {v}");
                }
                (Some(k), None) => println!("{}", config_get(&k).unwrap_or_default()),
                (None, _) => {
                    for k in ["name", "server", "dir"] {
                        if let Some(v) = config_get(k) {
                            println!("{k} {v}");
                        }
                    }
                }
            }
            Ok(())
        }
        Cmd::Up {
            install,
            system,
            detach,
            userspace,
            dir,
            shell,
            shell_only,
            shell_program,
            shell_user,
            i_know,
            install_system,
            no_proxy_fallback,
        } => {
            // `--userspace` forces the netstack backend; L3::start reads this env, so
            // set it before the daemon brings L3 up (same process). Safe: single
            // threaded at this point (the daemon's tasks are not spawned yet).
            if userspace {
                unsafe { std::env::set_var("FILAMENT_L3_USERSPACE", "1") };
            }
            // Flags win; otherwise fall back to persistent settings. Per-peer
            // `shell on` overrides fold into the shell-only allowlist so
            // `filament set shell on --peer laptop` unifies with --shell-only.
            let shell = shell || settings::get_bool("shell", None);
            let shell_user = shell_user.or_else(|| settings::get_str("shell-user", None));
            let peer_shell = settings::peers_with("shell", "on");
            let shell_only = match (shell_only, peer_shell.is_empty()) {
                (existing, true) => existing,
                (Some(list), false) => Some(format!("{list},{}", peer_shell.join(","))),
                (None, false) => Some(peer_shell.join(",")),
            };
            // Arm SSH-CA sshd trust when serving shell (best-effort, loud):
            // the daemon needs the CA lines + principals entry before cert
            // logins can land. Never fails the command (no new root rule).
            if shell || shell_only.as_ref().is_some_and(|s| !s.is_empty()) {
                crate::sshd::arm_ssh_ca_for_serving().await;
            }
            up_cmd(
                &server,
                install,
                system,
                detach,
                dir,
                relay,
                shell,
                shell_only,
                shell_program,
                shell_user,
                i_know,
                install_system,
                no_proxy_fallback,
            )
            .await
        }
        Cmd::Status { json } => status_cmd(json || ui_caps.json),
        Cmd::Down => {
            ui_caps.confirm("shut down the daemon")?;
            down_cmd()
        }
        Cmd::Logs { follow, tail } => logs_cmd(follow, tail).await,
        Cmd::Reset => reset_cmd(&ui_caps),
        Cmd::Add {
            who,
            name,
            word,
            for_,
            allow,
            expires,
            out,
            via,
        } => {
            // `filament add laptop` == `filament add --for laptop`. `--for`
            // already accepts a device NAME (that is how --for my-laptop works),
            // so the positional needs no new meaning, only a shorter spelling of
            // the one thing the operator always knows.
            //
            // Naming it twice is a contradiction, not a precedence puzzle, so it
            // is refused rather than silently resolved.
            let for_ = match (who, for_) {
                (Some(w), None) => Some(w),
                (Some(w), Some(f)) => {
                    bail!("you named the invitee twice: `add {w}` and `--for {f}`. Use one.")
                }
                (None, f) => f,
            };
            // `add` OFFERS. Accepting is `join`, which is the only spelling now:
            // `add <code>` was the second one, and per WORK-STATE's no-backward-
            // compat rule (no real users yet, clean breaks everywhere) a second
            // spelling of one action is exactly what that rule exists to remove.
            let code: Option<String> = None;
            // THREE ORTHOGONAL AXES, three spellings, no overlap:
            //   who   --for device|person   (the same question on both transports)
            //   how   --out                 (a file instead of a spoken code)
            //   what  --allow               (the ceiling)
            //
            // `--for` used to reach only the invitation path, so the code path
            // grew `--internal` meaning exactly the same thing. Two spellings of
            // one question is what made this confusing, so `--for` now answers it
            // everywhere and `--internal` is gone.
            if out.is_some() {
                // Delivering as a file is the invitation ceremony, unchanged.
                add_for_cmd(&ui_caps, for_, allow, expires, out).await
            } else if for_.is_some() {
                // Same question, spoken-code transport. Resolving here (rather
                // than inside the ceremony) means a script that omits the answer
                // is refused before anything is minted.
                let (kind, named) = resolve_for_kind(&ui_caps, for_)?;
                // ASK "how", not only "who". The comment above names three
                // orthogonal axes and the guided flow asked exactly one of them,
                // so from the first screen the ONLY reachable delivery was a
                // spoken code, which needs both people present at the same
                // moment. `--out` (a bounded invitation they claim later) was
                // reachable only by knowing to type it.
                //
                // Reported as "why can't I mint a key for a regular device or
                // person": you could, but only from the command line. Third time
                // on this branch that a path existed and its interactive surface
                // did not (see `join` in the no-identity menu, and `ephemeral
                // mint` on the first screen).
                // HOW, resolved ONCE for both modes. `--via` is the flag, the
                // picker below is the prompt, and they are the same question:
                // a script and a person answer it the same way and get the same
                // thing. Before this, HOW was inferred from whether --out
                // happened to be present, and the guided flow never asked at
                // all, so the file path was reachable only by knowing to type a
                // flag nobody was told about.
                let via = match via.as_deref() {
                    Some("code") => Some("code".to_string()),
                    Some("file") => Some("file".to_string()),
                    Some(other) => bail!("--via takes `code` or `file`, not '{other}'"),
                    // --out names a file, so it answers HOW by itself.
                    None if out.is_some() => Some("file".to_string()),
                    // An unattended runner is never present to hear a code read
                    // out, so the question does not arise: it is always a file.
                    None if kind == "runner" => Some("file".to_string()),
                    None if ui_caps.interactive => {
                        let who = if kind == "device" {
                            "that device"
                        } else {
                            "them"
                        };
                        let choices = vec![
                            "Read out a code now         (we are both here)".to_string(),
                            format!("Write a file {who} claims later"),
                        ];
                        match codeentry::pick("HOW SHOULD THEY GET IT", &choices)? {
                            Some(0) => Some("code".to_string()),
                            Some(_) => Some("file".to_string()),
                            None => return Err(cancelled()),
                        }
                    }
                    // --word IS the code transport. It chooses the SPAKE2
                    // password for a spoken code, and means nothing to a file,
                    // so supplying it has already answered this question.
                    //
                    // Defaulting to file regardless broke exactly that: a
                    // scripted `add --for device --word "..."`, which is how the
                    // acceptance rig pairs, silently wrote an invitation file
                    // instead of minting the code the caller had just chosen
                    // words for. Caught by running the pairing, not by tests.
                    None if word.is_some() => Some("code".to_string()),
                    // Otherwise nobody is present to hear a code read out, so
                    // `code` is not a possible answer here, only a slower way to
                    // fail: `add laptop` used to default to code and then bail
                    // with the message for a bare `add`, telling an operator who
                    // HAD named a device that they had named nothing.
                    None => Some("file".to_string()),
                };

                // A runner is not a member: it gets a temporary KEY, which is
                // what `ephemeral mint` was a separate verb for. Same two
                // questions, third answer to the first one.
                if via.as_deref() == Some("file") {
                    let path = out.unwrap_or_else(|| invite_path_for(named.as_deref(), &kind));
                    return add_for_cmd(&ui_caps, Some(kind), allow, expires, Some(path)).await;
                }
                let internal = kind == "device";
                if internal && load_owner_key().is_none() {
                    bail!(
                        "`add --for device` enrols the other side into your mesh, which \
                         needs this machine's owner key. Only the device you ran \
                         `filament init` on holds it: run it there, or use \
                         `--for person` to pair without enrolling."
                    );
                }
                pair_cmd(&server, code, name.or(named), word, relay, internal, allow).await
            } else {
                // No answer given and none required: an ordinary pair, which
                // confers no membership. This is the safe default and the
                // pre-existing behaviour.
                pair_cmd(&server, code, name, word, relay, false, allow).await
            }
        }
        Cmd::Join {
            code,
            invite_file,
            invite_fd,
            name,
            to,
        } => {
            // ONE VERB FOR THE PERSON HOLDING THE THING. They were handed a code
            // or a file; making them know WHICH, and then pick between `join
            // <code>`, `join --invite-file` and `ephemeral enroll
            // --auth-key-file`, puts the most spellings in front of the person
            // with the least information.
            //
            // A PATH is safe as a positional; the invitation MATERIAL is not,
            // and still is not accepted here, because argv lands in `ps` output
            // and shell history. So the test is "does this name a file that
            // exists", not "does this look like a token".
            let (code, invite_file) = match code {
                Some(arg)
                    if invite_file.is_none()
                        && invite_fd.is_none()
                        && std::path::Path::new(&arg).is_file() =>
                {
                    (None, Some(std::path::PathBuf::from(arg)))
                }
                other => (other, invite_file),
            };
            if let Some(code) = code {
                if invite_file.is_some() || invite_fd.is_some() {
                    bail!("give a code or an invitation file, not both");
                }
                // Same ceremony `add <code>` runs: accepting a code confers no
                // membership by itself, the offering side decides that.
                pair_cmd(&server, Some(code), name, None, relay, false, Vec::new()).await
            } else {
                join_cmd(&ui_caps, &server, relay, invite_file, invite_fd, name, to).await
            }
        }
        Cmd::Depart => depart_cmd(&server, relay).await,
        Cmd::Devices { action, json, caps } => {
            if let Some(selector) = caps {
                if action.is_some() {
                    bail!("--caps is a view; it takes a device name, not a subcommand");
                }
                let name = (!selector.is_empty()).then_some(selector.as_str());
                return crate::device_perms::devices_caps_cmd(name, json || ui_caps.json);
            }
            match action {
                None => {
                    let all = devices_load();
                    if json || ui_caps.json {
                        let arr: Vec<Value> = all
                            .iter()
                            .map(|(n, s)| {
                                let (last_seen, v6, v4) =
                                    devices_info(n).unwrap_or((0, None, None));
                                let addr = v6.clone().or_else(|| v4.clone()).unwrap_or_default();
                                let mesh = format!("{n}.mesh");
                                json!({
                                    "name": n,
                                    "channel": channel_of(s),
                                    "caps": effective_device_caps(n),
                                    "lastSeen": last_seen,
                                    "address": addr,
                                    "mesh": mesh,
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&arr)?);
                    } else {
                        let warm = ctl::try_list_warm().await;
                        let pending = ctl::try_list_pending().await;
                        let now = identity::now_secs();
                        // Honest roster heading: show the epoch and when it was
                        // received, never "current"; and distinguish an expired
                        // roster (stale in both directions) from one never seen.
                        let roster_heading = match crate::roster::roster_staleness(now) {
                            crate::roster::RosterStaleness::Fresh { epoch, received_at } => {
                                let ago = now.saturating_sub(received_at);
                                let ago = if ago < 60 { "just now".to_string() } else if ago < 3600 { format!("{}m ago", ago / 60) } else { format!("{}h ago", ago / 3600) };
                                Some(format!("MESH  /  your owner's other devices (epoch {epoch}, received {ago})"))
                            }
                            crate::roster::RosterStaleness::Expired => Some(
                                "MESH  /  your owner's other devices (roster expired; reconnect to the owner to refresh)".to_string(),
                            ),
                            crate::roster::RosterStaleness::None => None,
                        };
                        let rendered = fleet_ui::devices::render_devices(
                            &device_entries(warm.as_ref()),
                            pending_request_count(pending.as_ref()),
                            roster_heading,
                        );
                        println!("{rendered}");
                    }
                }
                Some(DevicesAction::Forget { name }) => {
                    let had = device_record_exists(&name);
                    if !had {
                        bail!("no device named '{name}', see `filament devices`");
                    }
                    // advisor's anti-theatre point: deleting the record also
                    // discards any revocation on it, and the copy must say so.
                    // Otherwise a revoked device that is forgotten looks like a
                    // first-time peer again, and typing its code (its own or a
                    // fresh mint) reads as ordinary pairing with nothing
                    // signalling the revocation was just undone.
                    let was_revoked = std::fs::read_to_string(devices_path())
                        .ok()
                        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default()
                        .iter()
                        .any(|d| {
                            d["name"].as_str() == Some(name.as_str())
                                && d["certRevoked"].as_bool() == Some(true)
                        });
                    devices_remove(&name)?;
                    if was_revoked {
                        println!(
                            "forgot '{name}' and its revocation; it can now be added or joined again (if it still holds its key)"
                        );
                    } else {
                        println!(
                            "forgot '{name}', it can no longer find or auto-connect to this machine"
                        );
                    }
                    println!(
                        "(their side still holds its half; it will hear \"never met you\" on the next proof)"
                    );
                }
                Some(DevicesAction::Rename { old, new }) => {
                    // Rename in place on the raw record so caps/v2 fields ride
                    // along (remove+store dropped the renamed device's caps).
                    with_devices_mut(|arr| {
                        if !arr.iter().any(|d| d["name"].as_str() == Some(old.as_str())) {
                            bail!("no device named '{old}', see `filament devices`");
                        }
                        if arr.iter().any(|d| d["name"].as_str() == Some(new.as_str())) {
                            bail!("'{new}' already exists, forget it first or pick another name");
                        }
                        for d in arr.iter_mut() {
                            if d["name"].as_str() == Some(old.as_str()) {
                                d["name"] = json!(new);
                            }
                        }
                        Ok(())
                    })?;
                    println!(
                        "renamed '{old}' -> '{new}' (local alias only, the secret, and the other side, are unchanged)"
                    );
                }
                Some(DevicesAction::Vouch { a, b }) => {
                    introduce_cmd(&server, &a, &b, relay).await?;
                }
                Some(DevicesAction::Revoke { name }) => {
                    if !device_record_exists(&name) {
                        bail!("no device named '{name}', see `filament devices`");
                    }
                    ui_caps.confirm(&format!("durably revoke {name} (it will stop being recognized and cannot rejoin until restored)"))?;
                    set_device_revoked(&name, true)?;
                    println!(
                        "revoked '{name}'; it is denied on reconnect and a fresh invitation cannot revive it (only `filament devices restore {name}` can)"
                    );
                }
                Some(DevicesAction::Restore { name }) => {
                    if !device_record_exists(&name) {
                        bail!("no device named '{name}', see `filament devices`");
                    }
                    set_device_revoked(&name, false)?;
                    println!("restored '{name}'; it is recognized again under its prior record");
                }
            }
            Ok(())
        }
        Cmd::Update { check, beta } => update_cmd(check, beta).await,
        Cmd::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "filament",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        Cmd::Man { page } => {
            if let Some(p) = page {
                if p == "routing" {
                    println!("{}", include_str!("../docs/filament-routing.md"));
                    return Ok(());
                }
                // Unknown page: print clear message instead of falling through to roff
                if std::io::stdout().is_terminal() {
                    eprintln!("no manual page '{p}'; available: routing");
                    eprintln!(
                        "try `filament man` for the full help, or `filament man routing` for the connection model."
                    );
                } else {
                    // Piped: still emit roff for backward compatibility
                    use clap::CommandFactory;
                    clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
                }
                return Ok(());
            }
            // Bare `filament man`: readable on TTY, roff when piped
            if std::io::stdout().is_terminal() {
                use clap::CommandFactory;
                Cli::command().print_long_help()?;
            } else {
                use clap::CommandFactory;
                clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
            }
            Ok(())
        }
        Cmd::Shell { peer, ssh, args } => {
            let opened_flow = ui_caps.interactive && (peer.is_none() || interactive_requested());
            let peer = match peer {
                Some(peer) => peer,
                None if ui_caps.interactive => {
                    let devices = devices_load();
                    if devices.is_empty() {
                        bail!("no devices are connected; start with `filament add`");
                    }
                    let labels = devices
                        .iter()
                        .map(|(name, _)| name.clone())
                        .collect::<Vec<_>>();
                    let selected = codeentry::pick("OPEN A TERMINAL ON", &labels)?
                        .ok_or_else(|| anyhow!("cancelled"))?;
                    devices[selected].0.clone()
                }
                None => {
                    bail!("shell needs a device in non-interactive mode: filament shell <device>")
                }
            };
            require_known_device(&peer)?;
            // #219: a device whose invitation ceiling excludes shell can never
            // serve one, and the denial was surfacing as a silent hang (the
            // acceptor's l2-close is only sent when the acceptor is ON). Say so
            // before opening anything, matching the #206 mount pre-check.
            if let Some(caps) = principal_ceiling_for(&peer) {
                if !caps.iter().any(|c| c == "shell") {
                    bail!(
                        "shell denied by {peer}: this device's invitation ceiling ({}) does not include shell",
                        caps.join(", ")
                    );
                }
            }
            if opened_flow {
                eprintln!();
                eprintln!("  {}", ui::paint(ui::Tone::Brand, "REMOTE TERMINAL"));
                eprintln!("  device   {peer}");
                eprintln!(
                    "  channel  {}",
                    if ssh {
                        "SSH over Filament"
                    } else {
                        "native encrypted PTY"
                    }
                );
                eprintln!("  access   the remote device enforces its shell grant and OS account");
                eprintln!(
                    "  command  filament shell {}{}",
                    command_arg(&peer),
                    if ssh { " --ssh" } else { "" }
                );
                let confirmation = prompt_line("\n  Press Enter to open it, or type cancel: ")?;
                if confirmation.eq_ignore_ascii_case("cancel") {
                    bail!("cancelled");
                }
            }
            if ssh {
                l2::ssh_cmd(&server, &peer, &args, relay).await
            } else {
                l2::pty_cmd(&server, &peer, relay, args).await
            }
        }
        Cmd::Exec {
            peer,
            shell,
            tty,
            cwd,
            env,
            argv,
        } => {
            let peer = match peer {
                Some(peer) => peer,
                None if ui_caps.interactive => {
                    let devices = devices_load();
                    if devices.is_empty() {
                        bail!("no devices are connected; start with `filament add`");
                    }
                    let labels = devices
                        .iter()
                        .map(|(name, _)| name.clone())
                        .collect::<Vec<_>>();
                    let selected = codeentry::pick("RUN COMMAND ON", &labels)?
                        .ok_or_else(|| anyhow!("cancelled"))?;
                    devices[selected].0.clone()
                }
                None => {
                    bail!(
                        "exec needs a device in non-interactive mode: filament exec <device> -- <cmd>"
                    )
                }
            };
            require_known_device(&peer)?;
            // Same ceiling pre-check as a shell: exec rides the shell grant,
            // so a device whose invitation ceiling excludes shell can never
            // serve one. Say so before opening anything, like #219 did.
            if let Some(caps) = principal_ceiling_for(&peer) {
                if !caps.iter().any(|c| c == "shell") {
                    bail!(
                        "exec denied by {peer}: this device's invitation ceiling ({}) does not include shell",
                        caps.join(", ")
                    );
                }
            }
            if argv.is_empty() {
                bail!("exec needs a command: filament exec <device> -- <cmd>");
            }
            // --shell wraps here, visibly, on the initiator side: the receiver
            // never invokes a shell on its own.
            let final_argv = crate::exec_send::build_argv(&argv, shell);
            let mut pairs = Vec::new();
            for e in &env {
                pairs.push(crate::exec_send::parse_env_pair(e)?);
            }
            let opts = crate::exec_send::ExecOpts {
                argv: final_argv,
                tty,
                cwd,
                env: pairs,
            };
            // The remote status becomes our own exit code (backup.rs precedent).
            // Refusals and link failures bail with the reason instead.
            match crate::exec_send::exec_cmd(&server, &peer, relay, opts).await? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Cmd::Reach { dev, until_direct, timeout, json, socks } => {
            if socks {
                bail!(
                    "`reach --socks` moved to `forward --socks`: reach now probes only. Run `filament forward <device>:<port> --socks`"
                );
            }
            let json = json || ui_caps.json;
            match dev {
                Some(d) if d.contains(':') => bail!(
                    "`reach <device>:<port>` moved to `forward <device>:<port>`: reach probes only, forward tunnels. Run `filament forward {d}`"
                ),
                Some(d) => {
                    require_known_device(&d)?;
                    // A mesh sibling is a known NAME (via the owner's roster) but
                    // carries no channel, so there is nothing to probe. Say so
                    // honestly instead of reporting "may be offline" (#240/#241
                    // shape) about a device this side has never contacted.
                    let roster_only = crate::roster::roster_device_names().iter().any(|n| n == &d)
                        && !devices_load().iter().any(|(n, _)| n == &d);
                    if roster_only {
                        // Human narration goes through ui::, not println!: this is
                        // stderr for a person, and println! would put it on stdout
                        // where a script parsing `reach` output would collect it.
                        ui::say(&format!(
                            "{} {}",
                            ui::paint(ui::Tone::Dim, "filament reach →"),
                            ui::paint(ui::Tone::Brand, &d)
                        ));
                        ui::say(&format!(
                            "  {} {}",
                            ui::paint(ui::Tone::Brand, ui::glyph_mesh()),
                            ui::paint(
                                ui::Tone::Dim,
                                "in your mesh via the owner's roster; sibling connections are not in this release"
                            )
                        ));
                        return Ok(());
                    }
                    if until_direct {
                        crate::ping::reach_until_direct(&d, timeout, json, relay).await
                    } else {
                        crate::ping::ping_cmd(&server, &d, 1, json, relay).await
                    }
                }
                None => bail!(
                    "reach needs a device to probe: `filament reach <device>`. To tunnel a port use `filament forward <device>:<port>`."
                ),
            }
        }
        Cmd::Forward {
            target,
            lport,
            stdio,
            socks,
            port,
            bind,
            http_port,
        } => {
            let (peer, rport) = match target.split_once(':') {
                Some((p, r)) => (
                    p.to_string(),
                    r.parse().map_err(|_| {
                        anyhow!("invalid port in '{target}'; expected <device>:<port>")
                    })?,
                ),
                None => bail!("forward needs <device>:<port>, e.g. `filament forward laptop:5432`"),
            };
            if stdio {
                // #202: the netcat shape - pipe stdio to the peer's port (the
                // ssh ProxyCommand contract). `forward` owns the role; --stdio
                // is the second plumbing.
                require_known_device(&peer)?;
                l2::netcat_cmd(&server, &peer, rport, relay).await
            } else if socks {
                l2::proxy_cmd(&server, &bind, port, http_port, relay).await
            } else {
                require_known_device(&peer)?;
                let lport = lport.unwrap_or(rport);
                l2::forward_cmd(&server, lport, &peer, rport, relay).await
            }
        }
        Cmd::Netcat { peer, rport } => {
            // Hidden one-release alias for the netcat shape, now forward --stdio.
            require_known_device(&peer)?;
            l2::netcat_cmd(&server, &peer, rport, relay).await
        }
        Cmd::Expose {
            port,
            to,
            peer,
            list,
            off,
        } => {
            if off {
                if let Some(p) = port {
                    ui_caps.confirm("unexpose a port")?;
                    expose::unexpose_cmd(p).await
                } else {
                    bail!("expose --off requires a port number");
                }
            } else {
                expose::expose_cmd(port, to, peer, list).await
            }
        }
        Cmd::Doctor {
            device,
            watch,
            repeat,
            json,
        } => {
            if let Some(d) = &device {
                require_known_device(d)?;
            }
            doctor::doctor_cmd(&server, device, watch, repeat, json || ui_caps.json, relay).await
        }
        Cmd::Grant {
            device,
            capability,
            tag,
        } => {
            // The owner key resolves the RESOURCE, so it is needed before the
            // capability name is final: `route:10.0.0.0/24` names an owner-bound
            // resource, while `shell` names "self".
            let spec = capability;
            let config_dir = crate::settings::config_dir();
            let mut store = crate::capability::load_cap_store(&config_dir);

            if let Some(ref t) = tag {
                // Grant to tag
                // The tag path SIGNS the CapOp below with the owner keypair, so
                // unlike the device path it genuinely needs the signing key, not
                // just the public half. Keep requiring a full identity here.
                let Some(user_key) = load_owner_key() else {
                    bail!("identity not initialized");
                };
                let pk = user_key.public_key_bytes();
                let g = crate::capability::parse_grant_spec(&spec, &pk)?;
                let (capability, resource) = (g.action.clone(), g.resource.clone());
                let target_bytes = crate::capability::make_tag_target(&pk, t);
                let ver = crate::capability::hlc_next(0, crate::capability::now_ms());
                let mut op = crate::capability::CapOp {
                    op: crate::capability::CapOpKind::Grant,
                    grantor: pk,
                    target_kind: 0x03,
                    target: target_bytes,
                    resource: resource.clone(),
                    permissions: vec![capability.clone()],
                    expires: crate::capability::now_secs().saturating_add(90 * 24 * 3600),
                    issued_at: crate::capability::now_secs(),
                    version: ver,
                    sig: [0u8; 64],
                };
                op.sig = crate::capability::sign_cap_op(&op, user_key.keypair());
                store.push(op.to_json());
                let _ = crate::capability::save_and_list_revoked(&store, &config_dir)
                    .context("save cap store")?;
                println!("granted '{capability}' to tag '{t}'.");
                return Ok(());
            }
            // Device path. The owner PUBLIC key is needed up front for the same
            // reason as the tag path: it resolves a `route:CIDR` spec to its
            // owner-bound resource id.
            //
            // The SIGNING key, deliberately. Naming the resource would only need
            // the public half, but the grant below is issued as an owner-signed
            // CapOp, and a joined device cannot mint one. That restriction is the
            // security model rather than an oversight: if a fleet member could
            // sign its own route authorization, any member could authorize any
            // prefix for itself and the capability would gate nothing.
            //
            // Verification is the asymmetric half and needs only the public key,
            // which is why enforcement uses owner_pub_for_resources() and this
            // does not. What WAS wrong here is the diagnosis printed on failure:
            // a joined device has an identity, so "Run `filament init` first" is
            // both false and unactionable. See the error below.
            let owner_pk = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore)
                .ok()
                .flatten()
                .map(|k| k.public_key_bytes());
            let (capability, cap_resource, cap_nonce) = match owner_pk {
                Some(pk) => {
                    let g = crate::capability::parse_grant_spec(&spec, &pk)?;
                    (g.action, g.resource, g.nonce)
                }
                None => {
                    // No identity: only the legacy self-scoped verbs are possible.
                    if spec.contains(':') {
                        // Distinguish "no identity at all" from "an identity that
                        // cannot sign". Telling a joined device to run `init` is
                        // wrong twice over: it already has an identity, and init
                        // is not what would make this work.
                        if owner_pub_for_resources().is_some() {
                            bail!(
                                "'{spec}' must be granted by the fleet owner. This is a joined device, \
                                 which holds no owner signing key and so cannot issue an owner-signed \
                                 grant. Run this on the owner's machine:\n  filament grant {device} {spec}"
                            );
                        }
                        bail!(
                            "'{spec}' names a resource, which needs an identity to bind it to. Run `filament init` first."
                        );
                    }
                    (
                        crate::capability::canonical_capability(&spec)?,
                        "self".to_string(),
                        crate::capability::self_resource_nonce(),
                    )
                }
            };

            // A delegated device's authority comes from its enrollment ceiling,
            // which enforcement reads from its fleet certificate; a grant targets
            // a key the device never presents, so it cannot bind. Refuse rather
            // than report a success enforcement will not honour.
            if let Some(ceiling) = principal_ceiling_for(&device) {
                // A ceiling records an ACTION and nothing else. It has no
                // resource dimension, so it cannot express WHICH prefix a router
                // may advertise: `route` in a ceiling means "may carry routes",
                // not "may carry 10.66.0.0/24". A resource-scoped grant is
                // therefore strictly NARROWER than the ceiling entry, not
                // redundant with it, and refusing it as redundant left the
                // prefix permanently unauthorized: the ceiling satisfied this
                // check while enforcement, which asks about the prefix-bound
                // resource id, still found nothing and declined every route.
                // Only a bare, self-scoped grant can be genuinely redundant.
                let resource_scoped = cap_resource != "self";
                if !resource_scoped && ceiling.iter().any(|c| c == &capability) {
                    bail!(
                        "'{capability}' is already granted to '{device}' by its invitation ceiling; no grant is needed"
                    );
                }
                bail!(
                    "{capability} is outside {device}'s invitation ceiling ({}). A grant cannot widen a ceiling. Re-invite with {capability} in the invitation:\n  filament add --for {device} --allow {capability} --yes",
                    ceiling.join(", ")
                );
            }
            device_set_cap(&device, &capability, true, None)?;
            // If identity layer is active, also issue an owner-signed CapOp
            if let Ok(Some(user_key)) =
                crate::identity::UserKey::load(&crate::platform::PlatformKeyStore)
            {
                let config_dir = crate::settings::config_dir();
                let mut store = crate::capability::load_cap_store(&config_dir);
                let pk = user_key.public_key_bytes();

                // Ensure a genesis header exists for the resource being granted.
                // Keyed by the RESOURCE, so a route prefix gets its own header
                // rather than riding on "self": each prefix is a distinct
                // resource with its own succession, which is what lets one
                // prefix be revoked without touching another.
                let has_header = store.iter().any(|e| {
                    e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                        && e["resource"].as_str() == Some(cap_resource.as_str())
                });
                if !has_header {
                    let pk = user_key.public_key_bytes();
                    // The nonce must match the one the resource id was derived
                    // from, or the header does not describe the resource it is
                    // filed under.
                    let nonce = cap_nonce;
                    let resource = cap_resource.clone();
                    let mut hdr = crate::capability::CapHeader {
                        resource,
                        epoch: 0,
                        owner_pub: pk,
                        nonce,
                        floors: vec![],
                        issued_at: crate::capability::now_secs(),
                        prev_owner_pub: None,
                        prev_header_hash: None,
                        sig: [0u8; 64],
                    };
                    hdr.sig = crate::capability::sign_cap_header(&hdr, &user_key.keypair());
                    let mut hdr_json = hdr.to_json();
                    // The header's signature is over the self-certifying resource id
                    // (SHA-256(owner_pub||nonce)), but the STORED header has resource="self".
                    // This signature is decorative: cap_authorize/evaluate never calls
                    // verify_genesis/verify_sig on the stored header (those run only on
                    // the grant-creation path, not the authorize path). Consistent with
                    // Cmd::Grant which does the same. The header is trusted local state
                    // in the owner's own caps.json, not a cross-verified object.
                    hdr_json["resource"] = serde_json::json!(cap_resource.clone());
                    store.push(hdr_json);
                }

                // Create CapOp: target the peer's real user_pub from their
                // stored device cert (not SHA-256 of the device name, which
                // never matches evaluate()'s principal_user_pub comparison).
                // Requires the peer to have a certified identity (paired +
                // identity-expose completed).
                let Some(peer_cert) = device_cert_for(&device) else {
                    return Err(anyhow!(
                        "peer identity for '{device}' is not available. Pair with the peer first so their identity can be certified; the grant requires a known user key to target"
                    ));
                };
                if peer_cert.verify(crate::identity::now_secs()).is_err() {
                    return Err(anyhow!(
                        "peer identity cert for '{device}' is expired; re-pair to refresh it"
                    ));
                }
                let target_arr = peer_cert.user_pub;

                // Version must EXCEED any existing grant for this target, the
                // same monotonic ratchet `revoke` respects. This was
                // hlc_next(0, ..), which ignores what is already in the store,
                // so a regrant could be minted below the floor. That could not
                // fail while the op was pushed straight in; through
                // apply_cap_op it would be refused, which is the point.
                let existing_ver = store
                    .iter()
                    .filter(|e| {
                        e.get("type").and_then(|v| v.as_str()) == Some("cap_grant")
                            && e["grantor"].as_str() == Some(hex::encode(pk).as_str())
                            && e["resource"].as_str() == Some("self")
                            && e["target"].as_str() == Some(hex::encode(target_arr).as_str())
                    })
                    .filter_map(|e| e["version"].as_u64())
                    .max()
                    .unwrap_or(0);
                let v = crate::capability::hlc_next(existing_ver, crate::capability::now_ms());
                let mut op = crate::capability::CapOp {
                    op: crate::capability::CapOpKind::Grant,
                    grantor: pk,
                    target_kind: 0x00, // User
                    target: target_arr,
                    resource: cap_resource.clone(),
                    permissions: vec![capability.clone()],
                    expires: crate::capability::now_secs().saturating_add(90 * 24 * 3600),
                    issued_at: crate::capability::now_secs(),
                    version: v,
                    sig: [0u8; 64],
                };
                op.sig = crate::capability::sign_cap_op(&op, &user_key.keypair());
                // ONE VALIDATED OP-CREATION PATH. `revoke` already went through
                // apply_cap_op; `grant` pushed its JSON straight into the store
                // and then called update_ratchet by hand, patching the single
                // consequence somebody had been bitten by. The TODO that asked
                // for this is now discharged.
                //
                // What grant was skipping: signature verification against the
                // header's owner_pub, the resource header existing at all, and
                // the version FLOOR. apply_cap_op does the push and the ratchet
                // itself, so both are removed here rather than duplicated.
                let hdr = store
                    .iter()
                    .find(|e| {
                        e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                            && e["resource"].as_str() == Some("self")
                    })
                    .and_then(crate::capability::CapHeader::from_json)
                    .ok_or_else(|| {
                        anyhow!("capability store has no header for 'self'; re-run the grant")
                    })?;
                crate::capability::apply_cap_op(&mut store, &hdr, &op, crate::capability::now_secs())
                    .context("the grant was refused by the capability store, so it did NOT take. Nothing was written")?;
                // save_and_list_revoked: persist THEN reconcile (reconciliation
                // is a property of the write). GATED on authoritative: in shadow
                // only REPORT what would be removed.
                let revoked = crate::capability::save_and_list_revoked(&store, &config_dir)
                    .context("save cap store")?;
                {
                    let authoritative = crate::capability::cap_authoritative();
                    let ak_path = sshkeys::authorized_keys_path();
                    let ak_content = std::fs::read_to_string(&ak_path).unwrap_or_default();
                    // Emit per-device shadow logs for actual-block devices.
                    for device in &revoked {
                        if sshkeys::has_block(&ak_content, device) && !authoritative {
                            ui::critical(&format!(
                                "CAP-SHADOW RECONCILE: WOULD remove shell key for '{device}' (cap store denies shell); NOT removing in shadow"
                            ));
                        }
                    }
                    let new_ak = crate::capability::reconcile_shell_keys(
                        &revoked,
                        &ak_content,
                        authoritative,
                    );
                    if new_ak != ak_content {
                        if let Err(e) = crate::platform::SecretFile::write_str(&ak_path, &new_ak) {
                            eprintln!("shell-key reconcile: failed to write authorized_keys: {e}");
                        }
                    }
                }
            }
            if capability == "shell" {
                crate::sshd::arm_ssh_ca_for_serving().await;
            }
            println!(
                "granted '{capability}' to '{device}'. {}",
                if capability == "shell" {
                    "OWNER-EQUIVALENT: they can act as you through `filament shell --ssh` (their key is installed on first connect)."
                } else {
                    ""
                }
            );
            Ok(())
        }
        Cmd::Revoke {
            device,
            capability,
            certificate,
        } => {
            if certificate {
                if capability.is_some() {
                    bail!("choose either a capability or --certificate, not both");
                }
                ui_caps.confirm(&format!("revoke fleet certificate from {device}"))?;
                let cert = device_cert_for(&device)
                    .ok_or_else(|| anyhow!(
                            // #244: this used to end here, so an operator revoking a
                            // vouched device got an error and no route. A record with no
                            // certificate is removed by forgetting it, and nothing else
                            // said so.
                            "device '{device}' has no stored fleet certificate, so there is nothing to revoke.\n  It was paired by secret rather than certified (see `filament devices`).\n  To remove its access: filament devices forget {device}"
                        ))?;
                let owner = load_owner_key().ok_or_else(|| anyhow!("no local user identity"))?;
                if cert.user_pub != owner.public_key_bytes() {
                    bail!("device '{device}' certificate is not chained to this user identity");
                }
                set_device_cert_revoked(&device, true)?;
                println!(
                    "revoked fleet certificate from '{device}'; the device is denied by the local capability gate"
                );
                return Ok(());
            }
            let capability = capability
                .ok_or_else(|| anyhow!("capability is required unless --certificate is set"))?;
            let capability = crate::capability::canonical_capability(&capability)?;
            // A delegated device's authority comes from its enrollment ceiling, not
            // a grant, so revoking a capability from it cannot bind. Name the thing
            // that does work: revoking the certificate.
            if let Some(ceiling) = principal_ceiling_for(&device) {
                if ceiling.iter().any(|c| c == &capability) {
                    bail!(
                        "'{capability}' cannot be revoked from {device}: its access comes from the enrollment ceiling on its fleet certificate, not from a grant. Revoke the certificate:\n  filament revoke {device} --certificate"
                    );
                }
                bail!(
                    "'{capability}' is not granted to {device} (its invitation ceiling is {}); nothing to revoke",
                    ceiling.join(", ")
                );
            }
            ui_caps.confirm(&format!("revoke {capability} from {device}"))?;
            device_set_cap(&device, &capability, false, None)?;
            // Mirror the grant path: also emit an owner-signed Revoke cap_op so
            // the AUTHORITATIVE capability gate actually denies. The legacy
            // device_set_cap(false) only clears devices.json; it leaves the cap
            // store granting, so under FILAMENT_CAP_AUTHORITATIVE the gate keeps
            // ALLOWing and a re-connect re-installs the shell key (revocation was
            // a no-op at the gate). apply_cap_op removes the matching grant, so
            // evaluate() then denies and devices_with_shell_revoked lists this
            // device; save_and_list_revoked + reconcile_shell_keys then strips
            // its managed authorized_keys block under authoritative.
            if let Ok(Some(user_key)) =
                crate::identity::UserKey::load(&crate::platform::PlatformKeyStore)
            {
                let config_dir = crate::settings::config_dir();
                let mut store = crate::capability::load_cap_store(&config_dir);
                let pk = user_key.public_key_bytes();
                let header = store
                    .iter()
                    .find(|e| {
                        e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                            && e["resource"].as_str() == Some("self")
                    })
                    .and_then(crate::capability::CapHeader::from_json);
                // A revoke only bites if there is a header AND the peer has a
                // certified identity to target (same requirement as grant).
                if let (Some(hdr), Some(peer_cert)) = (header, device_cert_for(&device)) {
                    let target_arr = peer_cert.user_pub;
                    // Version MUST exceed the existing grant's version (monotonic
                    // ratchet), else apply_cap_op refuses.
                    let existing_ver = store
                        .iter()
                        .filter(|e| {
                            e.get("type").and_then(|v| v.as_str()) == Some("cap_grant")
                                && e["grantor"].as_str() == Some(hex::encode(pk).as_str())
                                && e["resource"].as_str() == Some("self")
                                && e["target"].as_str() == Some(hex::encode(target_arr).as_str())
                        })
                        .filter_map(|e| e["version"].as_u64())
                        .max()
                        .unwrap_or(0);
                    let v = crate::capability::hlc_next(existing_ver, crate::capability::now_ms());
                    let now = crate::capability::now_secs();
                    let mut op = crate::capability::CapOp {
                        op: crate::capability::CapOpKind::Revoke,
                        grantor: pk,
                        target_kind: 0x00, // User
                        target: target_arr,
                        resource: "self".to_string(),
                        permissions: vec![capability.clone()],
                        expires: now.saturating_add(90 * 24 * 3600),
                        issued_at: now,
                        version: v,
                        sig: [0u8; 64],
                    };
                    op.sig = crate::capability::sign_cap_op(&op, user_key.keypair());
                    match crate::capability::apply_cap_op(&mut store, &hdr, &op, now) {
                        Ok(()) => {
                            let revoked =
                                crate::capability::save_and_list_revoked(&store, &config_dir)
                                    .unwrap_or_default();
                            let authoritative = crate::capability::cap_authoritative();
                            let ak_path = sshkeys::authorized_keys_path();
                            let ak_content = std::fs::read_to_string(&ak_path).unwrap_or_default();
                            for d in &revoked {
                                if sshkeys::has_block(&ak_content, d) && authoritative {
                                    eprintln!(
                                        "shell-key reconcile (revoke): removing managed key for '{d}' (cap store denies shell)"
                                    );
                                }
                            }
                            let new_ak = crate::capability::reconcile_shell_keys(
                                &revoked,
                                &ak_content,
                                authoritative,
                            );
                            if new_ak != ak_content {
                                if let Err(e) =
                                    crate::platform::SecretFile::write_str(&ak_path, &new_ak)
                                {
                                    eprintln!(
                                        "shell-key reconcile (revoke): failed to write authorized_keys: {e}"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "revoke: owner-signed cap_op not applied ({e}); legacy revoke still took effect"
                            );
                        }
                    }
                }
            }
            if capability == "shell" {
                sshkeys::remove_authorized_key(&device)?;
                println!(
                    "revoked 'shell' from '{device}' and removed its filament-managed authorized_keys block."
                );
            } else {
                println!("revoked '{capability}' from '{device}'.");
            }
            if let Some(warning) = fleet_certificate_warning(&device) {
                eprintln!("{warning}");
            }
            // #244: revoking the `shell` CAP does nothing while `up --shell` is
            // serving, because that policy auto-allows without consulting a
            // per-device capability at all. The operator ran the security verb,
            // saw success, and lost nothing. Say so, and name what does work.
            //
            // Asked of the RUNNING daemon, not derived from settings: `--shell`
            // is a launch flag that never lands in the settings file, so a local
            // guess would be confidently wrong in exactly the case that matters.
            // When no daemon answers we say NOTHING rather than guess: silence
            // here means "not known", and inventing a reassurance would repeat
            // the defect one layer up.
            if capability == "shell" {
                if let Some(st) = crate::ctl::try_cap_status().await {
                    let policy = st["shell_policy"].as_str().unwrap_or("");
                    let auto = st["shell_auto"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str()).any(|n| n == device))
                        .unwrap_or(false);
                    if policy == "all" || (policy == "only" && auto) {
                        let how = if policy == "all" {
                            "`up --shell` is serving, which auto-allows every paired device"
                                .to_string()
                        } else {
                            format!("`up --shell-only` is serving and lists {device}")
                        };
                        ui::caution(
                            &format!("{device} still has shell access"),
                            Some(&format!(
                                "the grant is revoked, but {how}, so this revoke changed nothing for it."
                            )),
                            &[
                                format!(
                                    "restart the daemon without it, or scope it: filament up --shell-only <others>"
                                ),
                                format!(
                                    "or remove the device entirely: filament devices forget {device}"
                                ),
                            ],
                        );
                    }
                }
            }
            Ok(())
        }
        Cmd::Mount {
            peer,
            remote,
            local,
            read_write,
            options,
            foreground,
            save_auto,
            list,
            check,
            save_profile,
            apply_profile,
            profiles,
            delete_profile,
            off,
        } => {
            if let Some(path) = off {
                ui_caps.confirm(&format!("unmount {path}"))?;
                mount::unmount_cmd(&path)
            } else if let Some(name) = save_profile {
                mount::save_profile_cmd(&name)
            } else if let Some(name) = apply_profile {
                mount::apply_profile_cmd(&name, &server, relay).await
            } else if profiles {
                mount::profiles_cmd()
            } else if let Some(name) = delete_profile {
                mount::delete_profile_cmd(&name)
            } else if list {
                mount::list_cmd()
            } else if let Some(path) = check {
                mount::check_cmd(&path)
            } else {
                if options.is_some() || foreground || save_auto {
                    bail!(
                        "--options, --foreground, and --save-auto belong to the retired sshfs path and are not supported by mesh-native mount"
                    );
                }
                let plan = resolve_mount_plan(&ui_caps, peer, remote, local, read_write)?;
                require_known_device(&plan.peer)?;
                let client = l2::mount_cmd(&server, &plan.peer, relay, &plan.remote).await?;
                #[cfg(any(
                    target_os = "linux",
                    all(target_os = "macos", feature = "mount-macos"),
                    all(target_os = "windows", feature = "mount-windows")
                ))]
                {
                    return mount_fuse_cmd(client, &plan).await;
                }
                #[cfg(not(any(
                    target_os = "linux",
                    all(target_os = "macos", feature = "mount-macos"),
                    all(target_os = "windows", feature = "mount-windows")
                )))]
                {
                    let _ = client;
                    bail!("local mount adapter is not available on this platform")
                }
            }
        }
        Cmd::Requests { action } => requests_cmd(action).await,
        Cmd::Ephemeral { action } => ephemeral_cmd(&server, action, relay).await,
        Cmd::Backup {
            peer,
            source,
            dest,
            exclude,
            dry_run,
            delete,
            options,
        } => {
            require_known_device(&peer)?;
            backup::backup_cmd(
                &server, &peer, &source, &dest, exclude, dry_run, delete, options, relay,
            )
            .await
        }
    }
}
