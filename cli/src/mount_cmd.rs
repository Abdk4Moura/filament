//! Mount planning, the mount implementation, and `filament reset`.
//!
//! `resolve_mount_plan` turns `mount <device> <dir>` into a plan, `mount_fuse_cmd`
//! carries it out through the platform mount adapter, and `reset_cmd` wipes this
//! machine's filament state.
//!
//! CFG, handled explicitly because anyhow::{ Result, anyhow, bail };
use crate::MountPlan;
use crate::UiCapability;
use crate::codeentry;
use crate::command_arg;
use crate::daemon_alive;
use crate::default_mount_point;
use crate::device_view::device_cert_for;
use crate::devices_store::devices_load;
use crate::interactive_requested;
use crate::load_owner_key;
use crate::mount_proto;
use crate::principal_ceiling_for;
use crate::prompt_line;
use crate::reset_remove;
use crate::ui;
#[cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos")))]
use crate::unmount_fuse;
use anyhow::{Context, Result, anyhow, bail};
use std::time::Duration;

pub(crate) fn reset_cmd(ui_caps: &UiCapability) -> Result<()> {
    // 1. Refuse while the daemon runs: reset yanks the keys and device store out
    //    from under a live acceptor. Make the user stop it explicitly.
    if let Some(pid) = daemon_alive() {
        bail!(
            "the filament daemon is running (pid {pid}); run `filament down` first, then `filament reset`"
        );
    }

    // 2. Confirm (destructive). ui_caps.confirm honors the global -y/--yes and
    //    REFUSES from a non-TTY without it, exactly the required behavior.
    ui_caps.confirm(
        "wipe ALL local filament state (identity, devices, caps, managed ssh keys) on this machine",
    )?;

    let cfg = crate::settings::config_dir();
    let mut wiped: Vec<String> = Vec::new();

    // 3. Strip the managed authorized_keys blocks BEFORE devices.json is gone,
    //    so we know every petname whose block filament may have installed. Only
    //    the delimited `# BEGIN/END filament-managed <device>` blocks are removed;
    //    everything else in authorized_keys is preserved verbatim.
    let ak_path = crate::sshkeys::authorized_keys_path();
    if let Ok(existing) = std::fs::read_to_string(&ak_path) {
        let mut content = existing.clone();
        let mut stripped: Vec<String> = Vec::new();
        for (name, _) in devices_load() {
            if crate::sshkeys::has_block(&content, &name) {
                content = crate::sshkeys::strip_block(&content, &name);
                stripped.push(name);
            }
        }
        if content != existing {
            // Best-effort restrictive write (owner-only), same as the installer.
            if crate::platform::SecretFile::write_str(&ak_path, &content).is_ok() {
                wiped.push(format!(
                    "managed authorized_keys blocks: {}  ({})",
                    stripped.join(", "),
                    ak_path.display()
                ));
            } else {
                ui::say(&ui::paint(
                    ui::Tone::Warn,
                    &format!(
                        "  could not rewrite {} — leaving it untouched",
                        ak_path.display()
                    ),
                ));
            }
        }
    }

    // 4. Remove filament's own state files. Each is filament-authored; a missing
    //    file is a silent no-op. Explicit list (NOT a blanket rmdir of the config
    //    dir) so a mis-set FILAMENT_CONFIG_DIR can never take out unrelated files.
    reset_remove(
        &cfg.join("identity.ed25519"),
        "user identity key",
        &mut wiped,
    );
    reset_remove(
        &cfg.join("identity/device-cert.json"),
        "local device certificate",
        &mut wiped,
    );
    reset_remove(&cfg.join("overlay.ed25519"), "overlay key", &mut wiped);
    reset_remove(
        &cfg.join("devices.json"),
        "paired-device store (device certs)",
        &mut wiped,
    );
    reset_remove(&cfg.join("caps.json"), "capability store", &mut wiped);
    reset_remove(
        &cfg.join("requests.json"),
        "pending consent requests",
        &mut wiped,
    );
    reset_remove(
        &cfg.join("expose.json"),
        "exposed-service records",
        &mut wiped,
    );
    reset_remove(&cfg.join("mounts.json"), "mount records", &mut wiped);
    reset_remove(
        &cfg.join("l2-allow.json"),
        "L2 forward allowlist",
        &mut wiped,
    );
    reset_remove(
        &cfg.join("signaling-dns.json"),
        "signaling DNS cache",
        &mut wiped,
    );
    reset_remove(&cfg.join("peerconf"), "per-peer settings", &mut wiped);
    reset_remove(&cfg.join("config"), "global settings", &mut wiped);
    reset_remove(&cfg.join("diag.jsonl"), "diagnostics log", &mut wiped);
    reset_remove(
        &cfg.join("mount-profiles"),
        "saved mount profiles",
        &mut wiped,
    );
    // Managed ssh material (private key, known_hosts pins, bootstrap cache) lives
    // under {config}/ssh — filament-authored, distinct from the user's ~/.ssh.
    reset_remove(
        &cfg.join("ssh"),
        "managed ssh material (key, known_hosts, cache)",
        &mut wiped,
    );

    // 5. Invalidate the in-process cap-store read cache so a same-process reader
    //    can't serve the just-deleted store from memory.
    crate::capability::invalidate_cap_cache();

    if wiped.is_empty() {
        ui::say("  nothing to wipe / no local filament state found");
    } else {
        ui::say(&format!(
            "  {} wiped local filament state:",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
        for line in &wiped {
            ui::say(&format!("    - {line}"));
        }
        ui::say("  this machine is now a clean slate (`filament init` to start over)");
    }
    Ok(())
}

pub(crate) fn resolve_mount_plan(
    caps: &UiCapability,
    mut peer: Option<String>,
    mut remote: Option<String>,
    local: Option<String>,
    mut read_write: bool,
) -> Result<MountPlan> {
    let opened_flow =
        caps.interactive && (peer.is_none() || remote.is_none() || interactive_requested());
    if remote.is_none() {
        let (device, path) = match peer.as_deref().and_then(|raw| raw.split_once(':')) {
            Some((device, path)) if !device.is_empty() && !path.is_empty() => {
                (device.to_string(), path.to_string())
            }
            _ => (String::new(), String::new()),
        };
        if !device.is_empty() && !path.is_empty() {
            peer = Some(device);
            remote = Some(path);
        }
    }
    if peer.is_none() {
        if !caps.interactive {
            bail!(
                "mount needs a device in non-interactive mode: filament mount <device> <remote> [local]"
            );
        }
        let devices = devices_load();
        if devices.is_empty() {
            bail!("no devices are connected; start with `filament add`");
        }
        let labels = devices
            .iter()
            .map(|(name, _)| {
                let relation = device_cert_for(name)
                    .and_then(|cert| {
                        load_owner_key().map(|owner| cert.user_pub == owner.public_key_bytes())
                    })
                    .map(|mine| if mine { "MY DEVICE" } else { "EXTERNAL" })
                    .unwrap_or("PAIRED");
                format!("{name:<20} {relation}")
            })
            .collect::<Vec<_>>();
        let selected =
            codeentry::pick("MOUNT FILES FROM", &labels)?.ok_or_else(|| anyhow!("cancelled"))?;
        peer = Some(devices[selected].0.clone());
    }
    let peer = peer.unwrap();
    // #206: a joined device knows its own ceiling (it printed it at join). If
    // the ceiling excludes mount, say so BEFORE opening a stream, instead of
    // letting the peer's denial come back as a ten-second transport timeout.
    // The device's ceiling lives on its record; a peer with no delegated
    // ceiling (an owner device or a plain pair) is not restricted here.
    if let Some(caps) = principal_ceiling_for(&peer) {
        if !caps.iter().any(|c| c == "mount") {
            bail!(
                "mount denied by {peer}: this device's invitation ceiling ({}) does not include mount",
                caps.join(", ")
            );
        }
    }
    let remote = match remote {
        Some(remote) => remote,
        None if caps.interactive => {
            let entered = prompt_line(&format!("  Shared path on {peer} [.]: "))?;
            if entered.is_empty() {
                ".".to_string()
            } else {
                entered
            }
        }
        None => bail!("mount needs a remote path in non-interactive mode"),
    };
    let suggested = default_mount_point(&peer, &remote);
    let local = match local {
        Some(local) => local,
        None if caps.interactive && opened_flow => {
            let entered = prompt_line(&format!("  Mount here [{suggested}]: "))?;
            if entered.is_empty() {
                suggested
            } else {
                entered
            }
        }
        None => suggested,
    };
    if caps.interactive && opened_flow && !read_write {
        let access = prompt_line("  Access [read only] (type WRITE for read and write): ")?;
        read_write = access == "WRITE";
    }
    let plan = MountPlan {
        peer,
        remote,
        local,
        read_only: !read_write,
    };
    if caps.interactive && opened_flow {
        eprintln!();
        eprintln!("  {}", ui::paint(ui::Tone::Brand, "MOUNT"));
        eprintln!("  source   {}:{}", plan.peer, plan.remote);
        eprintln!("  local    {}", plan.local);
        eprintln!(
            "  access   {}",
            if plan.read_only {
                "read only"
            } else {
                "read and write"
            }
        );
        eprintln!();
        eprintln!("  The remote device still enforces its configured share root and grant.");
        eprintln!(
            "  command  filament mount {} {} {}{}",
            command_arg(&plan.peer),
            command_arg(&plan.remote),
            command_arg(&plan.local),
            if plan.read_only { "" } else { " --read-write" }
        );
        let confirmation = prompt_line("\n  Press Enter to mount, or type cancel: ")?;
        if confirmation.eq_ignore_ascii_case("cancel") {
            bail!("cancelled");
        }
    }
    Ok(plan)
}

/// Present the connected `client` as a local FUSE mount at `local`.
///
/// Before touching the filesystem we run a connection-honesty probe: one
/// GetAttr on the mount root under a timeout. An untrusted or refused peer
/// (the acceptor replies l2-close, which EOFs the stream) surfaces here as one
/// clean pre-mount error, instead of a cryptic failure on the first `ls` after
/// the kernel has already accepted the mount. On any failure we leave no stale
/// mountpoint behind (the #22 contract).
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "mount-macos"),
    all(target_os = "windows", feature = "mount-windows")
))]
pub(crate) async fn mount_fuse_cmd(
    mut client: crate::mount_proto::MountClient,
    plan: &MountPlan,
) -> Result<()> {
    use crate::mount_proto::{MountOp, MountResult};

    let peer = &plan.peer;
    let remote = &plan.remote;
    let local = &plan.local;
    client.set_read_only(plan.read_only);
    // 1. Probe the link before we mount anything.
    let root_enc = mount_proto::path_encode(std::path::Path::new("."));
    let probe = tokio::time::timeout(
        Duration::from_secs(10),
        client.call(MountOp::GetAttr { path: root_enc }),
    )
    .await;
    match probe {
        Ok(Ok(resp)) => match resp.result {
            MountResult::Ok(_) => {}
            MountResult::Err(e) => {
                bail!("mount refused by {peer}: {} (remote path {remote})", e.msg)
            }
        },
        Ok(Err(e)) => bail!(
            "mount to {peer} failed before it started: {e} \
             (peer may be untrusted or the link dropped; nothing was mounted)"
        ),
        Err(_) => bail!(
            "mount to {peer} timed out waiting for the remote filesystem \
             (no response in 10s; nothing was mounted)"
        ),
    }

    // 2. Create the mountpoint. Track whether WE created it so a failed mount
    //    cleans up after itself and never leaves a stale empty dir.
    let mnt = std::path::PathBuf::from(local);
    let created_dir = !mnt.exists();
    if created_dir {
        std::fs::create_dir_all(&mnt)
            .with_context(|| format!("failed to create mount point {local}"))?;
    }

    ui::say(&format!(
        "  {} mesh-native mount: {peer}:{remote} -> {local} ({}, FUSE)",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        if plan.read_only {
            "read only"
        } else {
            "read and write"
        }
    ));
    ui::say(&format!(
        "  {} mounted. unmount with `filament mount --off {local}` or ctrl-c",
        ui::paint(ui::Tone::Ok, ui::glyph_ok())
    ));

    // 3. Run the blocking FUSE session on a dedicated thread so the tokio mux
    //    pump keeps draining the transport. ctrl-c triggers an unmount, which
    //    makes the blocking session loop return.
    let mnt_run = mnt.clone();
    #[cfg(target_os = "linux")]
    let session =
        tokio::task::spawn_blocking(move || crate::mount_fuse::run_mount(client, &mnt_run));
    #[cfg(all(target_os = "windows", feature = "mount-windows"))]
    let session =
        tokio::task::spawn_blocking(move || crate::mount_winfsp::run_mount(client, &mnt_run));

    let result: Result<()> = tokio::select! {
        joined = session => {
            match joined {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(anyhow::anyhow!("mount session panicked: {e}")),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            ui::say("\n  unmounting...");
            let _ = unmount_fuse(local);
            Ok(())
        }
    };

    // 4. On any error, remove the mountpoint we created (leave a pre-existing
    //    dir alone). A clean unmount leaves the empty dir in place, matching the
    //    legacy behaviour.
    if result.is_err() && created_dir {
        let _ = unmount_fuse(local);
        let _ = std::fs::remove_dir(&mnt);
    }
    result
}
