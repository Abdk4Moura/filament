//! Creating an identity, joining, and the certificate and principal state behind them.
//!
//! `init_experience` walks a new device through minting its identity and showing the
//! recovery phrase, `confirm_recovery_phrase` is the check inside that flow,
//! `join_cmd` claims a code, `local_device_cert` and `principal_from_records` read
//! the resulting local state, and `open_enrollment` is the fleet side of joining.
//!
//! Six scattered blocks. NO member is definition-gated: the `#[cfg(l3)]` inside
//! init_experience is a statement attribute and travels with the body, and
//! dispatch.rs imports init_experience unconditionally. The only gate is on the `l3`
//! module import, because anyhow::{ Result, bail };
use crate::UiCapability;
use crate::capability_list_summary;
use crate::certify_local_device;
use crate::config_set;
use crate::conn::Conn;
use crate::default_drop_dir;
use crate::device_view::device_cert_for;
use crate::devices_store::devices_path;
use crate::display_name;
use crate::enrollment::enroll_cmd;
use crate::fleet_support::ensure_self_genesis_header;
use crate::fmt_short_duration;
use crate::format_approval_expiry;
use crate::identity;
#[cfg(l3)]
use crate::l3;
use crate::local_device_cert_path;
use crate::net::Transport;
use crate::parse_invitation;
use crate::prompt_line;
use crate::read_owner_only_fd;
use crate::read_owner_only_file;
use crate::settings;
use crate::ui;
use crate::up_logs::up_cmd;
use crate::write_owner_only_fd;
use crate::write_owner_only_file;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Resolve the persisted principal record for a device cert. Returns
/// `(kind, not_after, max_offline, last_seen)`. A missing or malformed record
/// FAILS CLOSED as a ceiling-less delegated principal (denies everything), so
/// a half-persisted record can never silently become an owner.
pub(crate) fn principal_from_records(
    records: &[Value],
    cert: &identity::DeviceCert,
    own_user_pub: Option<&[u8; 32]>,
) -> (
    crate::capability::PrincipalKind,
    Option<u64>,
    Option<u64>,
    Option<u64>,
) {
    let record = records.iter().find(|record| {
        identity::DeviceCert::from_json(&record["deviceCert"])
            .map(|stored| stored.device_pub == cert.device_pub)
            .unwrap_or(false)
    });
    if let Some(record) = record {
        if record["principalKind"].is_null() {
            return (
                crate::capability::PrincipalKind::OwnerDevice,
                None,
                None,
                None,
            );
        }
        if record["principalKind"].as_str() == Some("delegated") {
            let caps = record["principalCeiling"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let expires = record["principalExpires"].as_u64().unwrap_or(0);
            let max_offline = record["principalMaxOffline"].as_u64();
            let last_seen = record["lastSeen"].as_u64();
            return (
                crate::capability::PrincipalKind::Delegated { caps },
                Some(expires),
                max_offline,
                last_seen,
            );
        }
        return (
            crate::capability::PrincipalKind::Delegated { caps: Vec::new() },
            Some(0),
            None,
            None,
        );
    }
    let is_same_owner = own_user_pub
        .map(|owner| *owner == cert.user_pub)
        .unwrap_or(false);
    if is_same_owner {
        return (
            crate::capability::PrincipalKind::Delegated { caps: Vec::new() },
            Some(0),
            None,
            None,
        );
    }
    (
        crate::capability::PrincipalKind::OwnerDevice,
        None,
        None,
        None,
    )
}

pub(crate) fn local_device_cert() -> Option<identity::DeviceCert> {
    if let (Ok(raw), Ok(overlay_pub)) = (
        std::fs::read_to_string(local_device_cert_path()),
        crate::overlay::overlay_pubkey_bytes(),
    ) {
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            if let Some(cert) = identity::DeviceCert::from_json(&value["cert"]) {
                if cert.device_pub == overlay_pub && cert.verify(identity::now_secs()).is_ok() {
                    return Some(cert);
                }
            }
        }
    }
    // Try display name first
    if let Some(cert) = device_cert_for(&display_name()) {
        if cert.verify(identity::now_secs()).is_ok() {
            return Some(cert);
        }
    }
    // Fallback: find any cert whose device_pub matches overlay key
    if let Ok(overlay_pub) = crate::overlay::overlay_pubkey_bytes() {
        let p = devices_path();
        if let Ok(raw) = std::fs::read_to_string(&p) {
            if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                for d in arr {
                    if let Some(cert) = identity::DeviceCert::from_json(&d["deviceCert"]) {
                        if cert.device_pub == overlay_pub
                            && cert.verify(identity::now_secs()).is_ok()
                        {
                            return Some(cert);
                        }
                    }
                }
            }
        }
    }
    // Final fallback: MINT the self-cert on demand from the user key + overlay key.
    // `identity init` creates the user key but no stored self device-cert, so without
    // this local_device_cert() is None, pairing never runs identity-expose (it is gated
    // on this fn), the peer stays secret-only (binding Inferred), and under authoritative
    // the #21 proven-gate denies EVERY peer. Minting here (deterministic in user_pub and
    // device_pub; only the timestamps vary) makes the Proven-binding path reachable for
    // freshly-onboarded and already-onboarded identities alike, without a peer-store entry.
    if let (Ok(Some(uk)), Ok(overlay_pub)) = (
        identity::UserKey::load(&crate::platform::PlatformKeyStore),
        crate::overlay::overlay_pubkey_bytes(),
    ) {
        if let Ok(cert) = identity::DeviceCert::certify(
            &uk,
            overlay_pub,
            identity::now_secs(),
            identity::CERT_TTL_SECS,
        ) {
            return Some(cert);
        }
    }
    None
}

fn confirm_recovery_phrase(words: &[&str], phrase: &str) -> Result<()> {
    use crossterm::{execute, terminal};
    let mut err = std::io::stderr();
    execute!(
        err,
        terminal::EnterAlternateScreen,
        terminal::Clear(terminal::ClearType::All)
    )?;
    let result = (|| -> Result<()> {
        eprintln!(
            "{}",
            ui::paint(ui::Tone::Brand, "  FILAMENT / YOUR WAY BACK")
        );
        eprintln!();
        eprintln!("  Anyone with these words can become you.");
        eprintln!("  Write them somewhere offline. Filament cannot reset them.");
        eprintln!();
        for (row, chunk) in words.chunks(4).enumerate() {
            let cells = chunk
                .iter()
                .enumerate()
                .map(|(column, word)| format!("{:>2}  {:<10}", row * 4 + column + 1, word))
                .collect::<Vec<_>>()
                .join("   ");
            eprintln!("     {cells}");
        }
        eprintln!();
        let qr = prompt_line("  Enter to check your copy, or type QR for a scannable export: ")?;
        if qr.eq_ignore_ascii_case("qr") {
            eprintln!();
            eprintln!("  Anyone who captures this QR can become you.");
            eprintln!(
                "{}",
                ui::qr_or_text(&format!("filament-recovery:v1:{phrase}"), 2)
            );
            let _ = prompt_line("  Press Enter after saving it somewhere you control: ")?;
        }
        let fourth = prompt_line("  Word 4:  ")?;
        if fourth != words[3] {
            bail!("word 4 did not match; identity was not created");
        }
        let eleventh = prompt_line("  Word 11: ")?;
        if eleventh != words[10] {
            bail!("word 11 did not match; identity was not created");
        }
        Ok(())
    })();
    let _ = execute!(err, terminal::LeaveAlternateScreen);
    result
}

pub(crate) async fn init_experience(
    caps: &UiCapability,
    server: &str,
    relay: bool,
    name: Option<String>,
    inbox: Option<PathBuf>,
    recovery_file: Option<PathBuf>,
    recovery_fd: Option<i32>,
    background: bool,
    no_background: bool,
) -> Result<()> {
    let store = crate::platform::PlatformKeyStore;
    if caps.json && background {
        bail!(
            "init --json cannot install a service without mixing service output; run `filament up --install` separately"
        );
    }
    if let Some(existing) = identity::UserKey::load(&store)? {
        bail!(
            "this device already has identity {}; see `filament id`",
            existing.fingerprint()
        );
    }
    // Non-interactive init names EVERYTHING it needs in one message, so a
    // script learns the full contract in one round trip instead of two
    // (--recovery-file, then --yes, then --name).
    if !caps.interactive {
        let mut missing: Vec<&str> = Vec::new();
        if recovery_file.is_none() && recovery_fd.is_none() {
            missing.push("--recovery-file <path> (or --recovery-fd <fd>)");
        }
        if !caps.yes {
            missing.push("--yes");
        }
        if name.is_none() {
            missing.push("--name <device>");
        }
        if !missing.is_empty() {
            bail!("non-interactive init needs: {}", missing.join(", "));
        }
    }

    let device_name = match name {
        Some(name) => name,
        None if caps.interactive => {
            let suggested = l3::hostname();
            let entered = prompt_line(&format!("  Name this device [{suggested}]: "))?;
            if entered.is_empty() {
                suggested
            } else {
                entered
            }
        }
        None => bail!("non-interactive init requires --name <device>"),
    };
    let inbox = inbox.unwrap_or_else(default_drop_dir);
    let pending = identity::PendingIdentity::generate()?;
    let phrase = Zeroizing::new(pending.mnemonic().to_string());
    let words = pending.mnemonic().words().collect::<Vec<_>>();

    if let Some(path) = recovery_file.as_deref() {
        write_owner_only_file(path, phrase.as_str())?;
    } else if let Some(fd) = recovery_fd {
        write_owner_only_fd(fd, phrase.as_str())?;
    } else {
        confirm_recovery_phrase(&words, phrase.as_str())?;
    }

    let user_key = pending.commit(&store)?;
    config_set("name", &device_name)?;
    config_set("dir", &inbox.display().to_string())?;
    std::fs::create_dir_all(&inbox)?;
    certify_local_device(&user_key, &device_name)?;
    ensure_self_genesis_header(&crate::settings::config_dir(), &user_key);
    let start_background = if no_background {
        false
    } else if background {
        true
    } else if caps.interactive {
        // `-y` means "answer this prompt with its default", and the default is Y.
        // Without it `filament init --yes` BLOCKED on a real terminal: the
        // identity was written, then it sat on "Stay available in the
        // background? [Y/n]:" forever, because this arm never consulted
        // `caps.yes`. Every other confirmation goes through
        // `UiCapability::confirm`, which starts `if self.yes { return Ok(()); }`.
        // This one called `prompt_line` directly and so escaped that contract.
        //
        // Invisible to every non-TTY check: piped, redirected and scripted runs
        // all take the `else` branch and exit 0, so a build, a pipe and CI all
        // said the first-run command was fine while it hung in a terminal.
        //
        // The check belongs INSIDE the interactive arm, not ahead of it. A
        // non-TTY never saw this prompt, so there is no default for `-y` to
        // supply and its answer must stay no. Hoisting it out flipped
        // `init --yes` from a pipe to "install a service", which is how the
        // capability harness (two piped `init --yes` at setup) started hanging
        // on macOS and Windows.
        caps.yes
            || !prompt_line("  Stay available in the background? [Y/n]: ")?
                .eq_ignore_ascii_case("n")
    } else {
        false
    };
    if start_background {
        up_cmd(
            server,
            true,
            false,
            false,
            Some(inbox.clone()),
            relay,
            false,
            None,
            None,
            None,
            false,
            false,
            false,
        )
        .await
        .context("install always-on receive service")?;
    }

    if caps.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "identity": user_key.fingerprint(),
                "device": device_name,
                "inbox": inbox,
                "recoveryExported": true,
                "background": start_background,
            }))?
        );
        return Ok(());
    }
    // L3 is default-on (`tun-addr` defaults to "auto"), and a non-root daemon
    // needs CAP_NET_ADMIN to open the tunnel device. Ask for the one-time grant
    // HERE, at init, because this is the moment there is a terminal to answer a
    // sudo prompt; the daemon has none. Declining is not fatal: the overlay
    // falls back to the userspace netstack, which needs no privilege.
    #[cfg(l3)]
    if !settings::get_str("tun-addr", None)
        .unwrap_or_default()
        .is_empty()
        && settings::get_str("l3-mode", None).as_deref() != Some("userspace")
        && caps.interactive
    {
        crate::tun::ensure_net_admin_for_l3();
    }
    ui::say(&format!(
        "  {} identity created",
        ui::paint(ui::Tone::Ok, ui::glyph_ok())
    ));
    ui::say(&format!(
        "  {} this device: {}",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        ui::paint(ui::Tone::Bold, &device_name)
    ));
    ui::say(&format!(
        "  {} inbox: {}",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        inbox.display()
    ));
    ui::say("");
    ui::say("  Least privilege by default");
    ui::say("  + paired devices may send into this inbox");
    ui::say("  - remote shell is off");
    ui::say("  - remote writing is off");
    ui::say("  - local ports are private");
    ui::say("");
    if start_background {
        ui::say(&format!(
            "  {} available in the background",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
    } else {
        ui::say(&ui::paint(
            ui::Tone::Dim,
            "  Stay available: filament up --install",
        ));
    }
    Ok(())
}

pub(crate) async fn join_cmd(
    caps: &UiCapability,
    server: &str,
    relay: bool,
    invite_file: Option<PathBuf>,
    invite_fd: Option<i32>,
    name: Option<String>,
    to: Option<String>,
) -> Result<()> {
    if identity::UserKey::load(&crate::platform::PlatformKeyStore)?.is_some() {
        bail!("this device already has an identity; join starts from a clean Filament identity");
    }
    if local_device_cert_path().exists() {
        bail!("this device has already joined an identity; reset it before joining another");
    }
    let invitation = Zeroizing::new(if let Some(path) = invite_file.as_deref() {
        read_owner_only_file(path)?
    } else if let Some(fd) = invite_fd {
        read_owner_only_fd(fd)?
    } else if caps.interactive {
        use crossterm::{execute, terminal};
        let mut err = std::io::stderr();
        execute!(
            err,
            terminal::EnterAlternateScreen,
            terminal::Clear(terminal::ClearType::All)
        )?;
        eprintln!("  Paste the invitation. It is cleared from this terminal after reading.");
        let result = prompt_line("\n  invitation: ");
        let _ = execute!(err, terminal::LeaveAlternateScreen);
        result?
    } else {
        bail!(
            "non-interactive join requires a code (`join <code>`), --invite-file <path>, or --invite-fd <fd>"
        );
    });
    let inv = parse_invitation(invitation.as_str())?;
    if inv.expires <= identity::now_secs() {
        bail!("this invitation has expired");
    }
    let owner_name = to.or_else(|| Some(inv.owner_name.clone()));
    let name_given = name.is_some();
    let mut proposed_name = name.unwrap_or_else(l3::hostname);
    if caps.interactive {
        // #183.3: join is the other first-run path; let the joined device name
        // itself the way init does. The review below shows the chosen name,
        // which is the name the owner sees in the device list.
        if !name_given {
            let answer = prompt_line(&format!("  name this device [{}]: ", proposed_name))?;
            let trimmed = answer.trim();
            if !trimmed.is_empty() {
                proposed_name = trimmed.to_string();
            }
        }
        eprintln!();
        eprintln!("  {}", ui::paint(ui::Tone::Brand, "JOIN"));
        eprintln!("  as       {proposed_name}");
        eprintln!(
            "  owner    {}",
            owner_name.as_deref().unwrap_or("invitation issuer")
        );
        eprintln!("  ceiling  {}", capability_list_summary(&inv.caps));
        eprintln!(
            "  budget   {} (key allows up to {})",
            fmt_short_duration(inv.max_offline),
            fmt_short_duration(inv.max_offline)
        );
        // #183.2: a raw epoch on the one screen where a person decides whether
        // to accept a grant is illegible; the mint side already formats it.
        eprintln!("  expires  {}", format_approval_expiry(inv.expires));
        eprintln!(
            "  proof    the ceiling and budget are persisted and reloaded before reconnect authorization"
        );
        let confirmation = prompt_line("\n  Press Enter to join, or type cancel: ")?;
        if confirmation.eq_ignore_ascii_case("cancel") {
            bail!("cancelled");
        }
    }
    enroll_cmd(
        server,
        inv,
        owner_name,
        relay,
        Some(&proposed_name),
        caps.json,
    )
    .await
}

/// Register a pending enrollment and send the request over a freshly-ready link.
///
/// Both enrollment commands opened their `ChannelReady` arm with exactly this,
/// and differed only in whether they printed a line afterwards. Two copies of a
/// ceremony step is how the two halves drift apart: one gets a fix, the other
/// keeps the bug, which this file has already recorded happening between `mount`
/// and `pty`.
pub(crate) async fn open_enrollment(
    conn: &mut Conn,
    pid: &str,
    t: &Arc<dyn Transport>,
    enroll_seed: [u8; 32],
    device_pub: [u8; 32],
    ak: &filament_cap::ephemeral::Invitation,
) {
    // SAME THREE STEPS the invitation path already performs (mark ready,
    // register pending, send the request), and now the same credential on the
    // wire. This branch used to send `auth_key` (an AuthKey JSON) and register
    // through `register_enrollment_legacy`, purely because `ephemeral mint`
    // wrote a different artifact than `add --for` did. The daemon carried a
    // reader for each. One credential means one of everything.
    conn.mark_ready(pid, t, true);
    crate::ephemeral::register_enrollment(pid.to_string(), enroll_seed, device_pub, ak.clone());
    let payload = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ak.to_payload())
    };
    let _ = t
        .send_control(&json!({
            "type": "identity-auth-key-enroll-request",
            "auth_key_v2": payload,
            "device_pub": hex::encode(device_pub),
        }))
        .await;
}
