use anyhow::{bail, Result};

pub async fn backup_cmd(
    server: &str,
    peer: &str,
    source: &str,
    dest: &str,
    excludes: Vec<String>,
    dry_run: bool,
    delete: bool,
    extra_opts: Option<String>,
    relay: bool,
) -> Result<()> {
    // Check rsync is available.
    if std::process::Command::new("which")
        .arg("rsync")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        crate::ui::problem(
            "rsync not found",
            "rsync is required for `filament backup` but is not installed.",
            &[
                "apt install rsync          # Debian/Ubuntu".to_string(),
                "brew install rsync         # macOS".to_string(),
                "pacman -S rsync            # Arch".to_string(),
            ],
        );
        std::process::exit(1);
    }

    let info = crate::l2::ensure_peer_bootstrap(server, peer, relay).await?;

    // Build rsync command. Use -e to specify the remote shell.
    // For L3 direct: rsync -e "ssh <opts>" source login@peer.mesh:dest
    // For L2 fallback: rsync -e "ssh <opts> -o ProxyCommand=..." source login@filament-peer:dest
    let mut cmd = std::process::Command::new("rsync");
    cmd.arg("-avz");

    if dry_run {
        cmd.arg("--dry-run");
    }
    if delete {
        cmd.arg("--delete");
    }
    for pattern in &excludes {
        cmd.arg("--exclude").arg(pattern);
    }

    // Build the ssh command for rsync -e.
    let peer_name = peer.strip_suffix(".mesh").unwrap_or(peer);
    let mut ssh_cmd = std::process::Command::new("ssh");
    ssh_cmd
        .arg("-o").arg(format!("IdentityFile={}", info.key_path.display()))
        .arg("-o").arg("IdentitiesOnly=yes")
        .arg("-o").arg(format!("UserKnownHostsFile={}", info.known_hosts_path.display()))
        .arg("-o").arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o").arg("StrictHostKeyChecking=accept-new")
        .arg("-o").arg("ConnectTimeout=10")
        .arg("-o").arg("ServerAliveInterval=15")
        .arg("-o").arg("ServerAliveCountMax=4");

    let dest_token;
    if let Some(dest) = crate::l2::l3_dest(&info) {
        crate::ui::debug("backing up over the L3 overlay (survives link repairs)");
        // dest is "login@peer.mesh", use it directly.
        dest_token = dest;
    } else {
        // L2 fallback: add ProxyCommand.
        let exe = std::env::current_exe()?;
        let exe = exe.to_string_lossy();
        let mut proxy = format!("{exe} --server {server}");
        if relay {
            proxy.push_str(" --relay");
        }
        proxy.push_str(&format!(" forward {peer_name}:{} --stdio", info.rport));
        ssh_cmd.arg("-o").arg(format!("ProxyCommand={proxy}"));
        dest_token = format!("{}@{}", info.login, info.host);
    }

    // Use the ssh command string as the -e argument.
    // We need to reconstruct it as a single string for rsync -e.
    let ssh_args: Vec<String> = ssh_cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let ssh_cmd_str = format!("ssh {}", ssh_args.join(" "));
    cmd.arg("-e").arg(&ssh_cmd_str);

    if let Some(opts) = &extra_opts {
        for opt in opts.split_whitespace() {
            cmd.arg(opt);
        }
    }

    // source is local, dest is remote.
    cmd.arg(source);
    cmd.arg(format!("{dest_token}:{dest}"));

    crate::ui::say(&format!("backing up {source} -> {peer}:{dest}"));
    let status = cmd.status();
    match status {
        Ok(s) if s.success() => {
            crate::ui::say("backup complete");
            Ok(())
        }
        Ok(s) => {
            let code = s.code().unwrap_or(1);
            if code == 255 && info.took_fast_path {
                // Retry with fresh bootstrap.
                crate::ui::say(&format!("filament: re-authenticating with '{peer}'..."));
                let retry = crate::l2::rebootstrap_peer(server, peer, relay, false).await?;
                let mut cmd = std::process::Command::new("rsync");
                cmd.arg("-avz");
                if dry_run { cmd.arg("--dry-run"); }
                if delete { cmd.arg("--delete"); }
                for pattern in &excludes {
                    cmd.arg("--exclude").arg(pattern);
                }
                let mut ssh_cmd = std::process::Command::new("ssh");
                ssh_cmd
                    .arg("-o").arg(format!("IdentityFile={}", retry.key_path.display()))
                    .arg("-o").arg("IdentitiesOnly=yes")
                    .arg("-o").arg(format!("UserKnownHostsFile={}", retry.known_hosts_path.display()))
                    .arg("-o").arg("GlobalKnownHostsFile=/dev/null")
                    .arg("-o").arg("StrictHostKeyChecking=accept-new")
                    .arg("-o").arg("ConnectTimeout=10")
                    .arg("-o").arg("ServerAliveInterval=15")
                    .arg("-o").arg("ServerAliveCountMax=4");
                let dest_token;
                if let Some(d) = crate::l2::l3_dest(&retry) {
                    dest_token = d;
                } else {
                    let exe = std::env::current_exe()?;
                    let exe = exe.to_string_lossy();
                    let mut proxy = format!("{exe} --server {server}");
                    if relay { proxy.push_str(" --relay"); }
                    proxy.push_str(&format!(" forward {peer_name}:{} --stdio", retry.rport));
                    ssh_cmd.arg("-o").arg(format!("ProxyCommand={proxy}"));
                    dest_token = format!("{}@{}", retry.login, retry.host);
                }
                let ssh_args: Vec<String> = ssh_cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
                cmd.arg("-e").arg(format!("ssh {}", ssh_args.join(" ")));
                if let Some(opts) = &extra_opts {
                    for opt in opts.split_whitespace() { cmd.arg(opt); }
                }
                cmd.arg(source).arg(format!("{dest_token}:{dest}"));
                let s = cmd.status()?;
                std::process::exit(s.code().unwrap_or(1));
            }
            bail!("rsync exited with code {code}");
        }
        Err(e) => {
            bail!("failed to run rsync: {e}");
        }
    }
}
