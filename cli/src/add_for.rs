//! `filament add --for`: the invitation and approval path.
//!
//! `add_for_cmd` is the handler `Cmd::Add` reaches when the caller names who the
//! addition is for -- it mints a capability for that subject, writes or prints
//! the invitation, and reports uptake. `report_invitation_uptake` is a member
//! rather than an import because this command is its only caller.
//!
//! Nothing here is promoted out of the crate root: every helper this needs
//! (`daemon_alive`, `mint_capability`, `parse_mint_ttl`, `invite_path_for`,
//! `resolve_for_kind`, `format_approval_expiry`, `write_owner_only_file`,
//! `prompt_line`) is private at the root and therefore already visible to this
//! module. There are no cfg branches, no spawns and no awaits in these bodies.
//! `add_for_cmd` keeps its own function-local `use base64::Engine`,
//! `use std::io::Write as _` and `use crossterm::{execute, terminal}`, which is
//! why no trait is imported at module level.
use crate::{
    UiCapability, Zeroizing, cancelled, codeentry, daemon_alive, devices_path, display_name,
    fmt_short_duration, format_approval_expiry, identity, invite_path_for, mint_capability,
    parse_mint_ttl, prompt_line, resolve_for_kind, ui, write_owner_only_file,
};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Report who, if anyone, joined through the invitation that carries `ttl_abs`
/// as its absolute expiry (#275). Polls briefly, because the joiner's "joined"
/// line and the daemon's write to the device store are separate events and the
/// owner presses Enter between them.
fn report_invitation_uptake(ttl_abs: u64) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let joined: Vec<(String, Vec<String>)> = std::fs::read_to_string(devices_path())
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
            .unwrap_or_default()
            .into_iter()
            .filter(|d| d["principalExpires"].as_u64() == Some(ttl_abs))
            .filter_map(|d| {
                let name = d["name"].as_str()?.to_string();
                let caps = d["principalCeiling"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                Some((name, caps))
            })
            .collect();
        if !joined.is_empty() {
            for (name, caps) in joined {
                ui::say(&format!(
                    "{} '{name}' joined, may {}, access ends {}",
                    ui::glyph_ok(),
                    if caps.is_empty() {
                        "nothing".to_string()
                    } else {
                        caps.join(" and ")
                    },
                    format_approval_expiry(ttl_abs)
                ));
            }
            return;
        }
        if Instant::now() >= deadline {
            // Deliberately not "waiting" or "pending": we do not know that
            // anyone ever scanned it. State only what is checkable.
            ui::say(&format!(
                "  no one has joined on this invitation yet; it stays usable until {}. `filament devices` will show them when they do.",
                format_approval_expiry(ttl_abs)
            ));
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub(crate) async fn add_for_cmd(
    caps: &UiCapability,
    for_: Option<String>,
    allow: Vec<String>,
    expires: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    use base64::Engine;
    // The Some("") -> "ask me" normalisation now lives in resolve_for_kind, so
    // both callers get it. Doing it here as well is what let the other caller
    // look correct while it was not.
    // #187: `--for` reads like a name. A bare word that is not the literal
    // device/person is a DEVICE NAME: select device-kind and pre-fill the
    // invitation so the owner can name the invitee up front. The literals
    // keep working for scripts.
    let (kind, _invitee_name) = resolve_for_kind(caps, for_)?;
    // The ergonomic gap behind "I want to shell into my own devices": shell has
    // to be in the invitation ceiling, because a grant cannot widen one later
    // (#226, which now refuses honestly instead of pretending). So the only way
    // to get it was `--allow shell`, a flag you had to already know about, on a
    // path the interactive flow never mentioned. Ask instead.
    //
    // Offered only for a device you control, only when the user did not pass
    // --allow, and only interactively. A person gets transfer and is not asked,
    // because owner-equivalent access to a stranger should stay a deliberate
    // flag rather than a menu item one keypress away.
    let mut interactive_shell = false;
    // Prefixes pulled out of `--allow route:<cidr>`; empty for every other kind
    // of invitation, which keeps those tokens byte-identical v2.
    let mut route_prefixes: Vec<String> = Vec::new();
    if allow.is_empty() && kind == "device" && caps.interactive {
        let choices = vec![
            "Send files, and mount my folders".to_string(),
            "...and open a terminal here  (OWNER-EQUIVALENT)".to_string(),
        ];
        match codeentry::pick("WHAT THIS DEVICE MAY DO", &choices)? {
            Some(1) => interactive_shell = true,
            Some(_) => {}
            None => return Err(cancelled()),
        }
    }
    let mut ceiling = if allow.is_empty() {
        if kind == "runner" {
            // A runner moves bytes and nothing else by default. Widening it is
            // --allow, deliberately, the same as for anyone else.
            vec!["transfer".to_string()]
        } else if kind == "device" {
            let mut c = vec!["transfer".to_string(), "mount".to_string()];
            if interactive_shell {
                c.push("shell".to_string());
            }
            c
        } else {
            vec!["transfer".to_string()]
        }
    } else {
        // `route:10.0.0.0/24` carries its scope in the flag. Split the prefixes
        // out here so they can travel in the SIGNED ceiling: a bare `route` is
        // refused at mint, because a ceiling that cannot say which prefix is not
        // a scope at all, and it previously authorised every prefix a member
        // chose to advertise, 0.0.0.0/0 included.
        let mut caps = Vec::new();
        for entry in allow {
            match entry.split_once(':') {
                Some((name, cidr))
                    if mint_capability(name).ok().as_deref()
                        == Some(crate::capability::CAP_ROUTE) =>
                {
                    caps.push(crate::capability::CAP_ROUTE.to_string());
                    for one in cidr.split(',').map(str::trim).filter(|c| !c.is_empty()) {
                        route_prefixes.push(one.to_string());
                    }
                }
                _ => caps.push(mint_capability(&entry)?),
            }
        }
        caps
    };
    ceiling.sort();
    ceiling.dedup();
    let ttl_text = expires.unwrap_or_else(|| {
        if kind == "device" {
            "30d".to_string()
        } else {
            "1h".to_string()
        }
    });
    let ttl = parse_mint_ttl(&ttl_text)?;
    if ttl == 0 || ttl > 30 * 24 * 3600 {
        bail!("invitations must expire between 1 second and 30 days");
    }
    if ceiling
        .iter()
        .any(|capability| capability == "shell" || capability == "all-ports")
    {
        caps.confirm("include deliberate remote authority in this invitation ceiling")?;
    }
    if !caps.interactive && out.is_none() {
        // They already said who. Do not re-explain --for; name the one missing
        // piece, with a filename derived from what they actually typed so the
        // suggestion is copy-pasteable rather than a template.
        // Defensive: both call sites now supply a path (a bare `add laptop`
        // defaults to filament-invite-laptop.txt and says so), so this cannot
        // fire today. Kept because add_for_cmd is a function and a future caller
        // could pass None, and written as lines because the continued literal it
        // replaced dragged its source indentation into the output.
        let suggested = invite_path_for(_invitee_name.as_deref(), &kind);
        let who = _invitee_name
            .clone()
            .unwrap_or_else(|| format!("--for {kind}"));
        bail!(
            "{}",
            [
                "a script has to say where the invitation goes (it holds a credential):"
                    .to_string(),
                String::new(),
                format!("  filament add {who} --out {}", suggested.display()),
                String::new(),
                format!(
                    "  Then on that machine:  filament join {}",
                    suggested.display()
                ),
            ]
            .join("\n")
        );
    }
    let owner_key = crate::identity_flow::ensure_user_key(caps.json)?;
    let mut enroll_seed = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut enroll_seed)
        .map_err(|_| anyhow!("failed to generate invitation possession key"))?;
    // #186: the v2 invitation is a compact binary token (base64url) with a
    // self-contained signature, not hex-inside-JSON-inside-base64. ~530 chars
    // became ~210, and the QR fits a normal terminal.
    let ttl_abs = identity::now_secs().saturating_add(ttl);
    // AN INVITATION IS AN AUTH KEY WITH DIFFERENT CONFIG. The two were separate
    // artifacts in separate formats reached by separate verbs, and the fields
    // say otherwise: enroll_pub, caps, expires, reuse, ephemeral and sig are the
    // same in both, and Invitation already CARRIES the `ephemeral` flag that
    // is the whole difference. It was hardcoded `false` here, so the only way to
    // get the ephemeral variant was a different command writing a different file
    // format that a different claim verb could read.
    //
    // So `runner` is not a third artifact. It is this one, minted ephemeral:
    // removed on disconnect, no persistent record, which is exactly what an
    // unattended CI box should leave behind.
    let ephemeral = kind == "runner";
    let inv = crate::ephemeral::Invitation::mint(
        owner_key.keypair(),
        enroll_seed,
        ceiling.clone(),
        ttl_abs,
        30 * 24 * 3600,
        crate::ephemeral::Reuse::Once,
        ephemeral,
        display_name(),
        route_prefixes.clone(),
    )?;
    enroll_seed.fill(0);
    let token = Zeroizing::new(format!(
        "filament-invite:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(inv.to_token())
    ));
    // #205/#211: arming is a FILE WRITE, not IPC. The mint records the key in
    // armed.json directly; the daemon's per-tick arm-gate reads it. No socket,
    // no bind race, no platform branch, no control channel. The only thing the
    // mint cannot guarantee is that a RECEIVER is actually running to pick the
    // key up - check that, and offer to start one.
    crate::armed::arm(hex::encode(inv.enroll_pub), inv.expires);
    // #207: a minted code that nothing can claim is not an invitation, it is a
    // lie with a QR on it. The receiver is what claims; if none is running,
    // say so before printing and offer to start one.
    if caps.interactive && daemon_alive().is_none() {
        use std::io::Write as _;
        eprint!(
            "  the always-on receiver is not running.\n  Start it now so this invitation can be claimed? [y/N] "
        );
        let _ = std::io::stderr().flush();
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans).ok();
        if matches!(ans.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            let exe = std::env::current_exe()?;
            let _ = std::process::Command::new(&exe)
                .arg("up")
                .arg("--install")
                .spawn();
            ui::say(&format!(
                "  {} receiver starting ({})",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                exe.display()
            ));
        }
    }

    if let Some(path) = out.as_deref() {
        write_owner_only_file(path, token.as_str())?;
    } else {
        use crossterm::{execute, terminal};
        let mut err = std::io::stderr();
        execute!(
            err,
            terminal::EnterAlternateScreen,
            terminal::Clear(terminal::ClearType::All)
        )?;
        eprintln!("  {}", ui::paint(ui::Tone::Brand, "JOIN INVITATION"));
        eprintln!("  kind     {kind}");
        eprintln!("  ceiling  {}", ceiling.join(", "));
        eprintln!(
            "  budget   {} (the key allows up to {})",
            fmt_short_duration(inv.max_offline),
            fmt_short_duration(inv.max_offline)
        );
        eprintln!("  expires  {ttl_text}");
        eprintln!();
        eprintln!("  Whoever captures this can join until it is used or expires.");
        // The token is printed ONCE, on its own line. qr_or_text's fallback
        // embeds the text, which would double it here; so render the QR only
        // when it fits and let the note stand alone otherwise (the other QR
        // callers rely on the fallback embedding the text, so the helper is
        // not changed - this call site prints the token separately).
        if ui::qr_fits(token.as_str(), 8) {
            eprintln!("{}", ui::qr(token.as_str()));
        } else {
            eprintln!(
                "  (the QR needs {} rows and this window has {}; the top would be cut off - the code is below)",
                ui::qr_rows(token.as_str()).unwrap_or(0),
                crossterm::terminal::size()
                    .map(|(_, h)| h as usize)
                    .unwrap_or(0)
            );
        }
        eprintln!("{}", token.as_str());
        eprintln!("  keep this window open so the QR stays on screen; the other device scans it");
        let result = prompt_line("\n  Press Enter after the other device has captured it: ");
        let _ = execute!(err, terminal::LeaveAlternateScreen);
        result?;
        // #275: this surface used to say nothing at all once the QR came down.
        // The owner picked the duration and the ceiling, someone joined under
        // them, and the one screen that knew what was offered never confirmed
        // what was taken; you had to run `filament devices` to find out.
        //
        // The mint process cannot observe the enrollment directly, because the
        // joiner talks to the running daemon and not to us. So match on the
        // invitation's absolute expiry, which the daemon copies verbatim into
        // `principalExpires`: a delegated record carrying THIS ttl_abs was
        // enrolled by THIS invitation.
        //
        // Says nothing rather than something reassuring when no record appears.
        // A claim of success we cannot support is worse than silence, which is
        // the failure this issue is about in the first place.
        report_invitation_uptake(ttl_abs);
    }
    if caps.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "kind": kind,
                "ceiling": ceiling,
                "maxOffline": inv.max_offline,
                "expires": inv.expires,
                "writtenTo": out,
                "invitationSecretPrinted": false,
            }))?
        );
    } else if let Some(path) = out {
        ui::say(&format!(
            "  {} invitation written to {}",
            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
            path.display()
        ));
        ui::say(&ui::paint(
            ui::Tone::Warn,
            "  Anyone who reads that file can join until it is used or expires.",
        ));
    }
    // Non-interactive (--out or a pipe): no offer was printed above. Warn that a
    // receiver must be running to claim, which is the one thing the file write
    // cannot guarantee.
    if !caps.interactive && daemon_alive().is_none() {
        ui::say(&ui::paint(
            ui::Tone::Warn,
            "  note: the always-on receiver is not running; start `filament up --install` before anyone claims this invitation.",
        ));
    }
    Ok(())
}
