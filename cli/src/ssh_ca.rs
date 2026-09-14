//! B-side SSH certificate signer (`filament shell --ssh` via local CA).
//!
//! The daemon holds a permanent CA key (0600 beside the identity key) and
//! signs initiators' ephemeral ed25519 keys with `ssh-keygen -s`, pinning
//! every flag the contract requires. Fail-closed throughout: no key, bad
//! perms, nonzero ssh-keygen, missing cert output, garbage ttl, or a pubkey
//! already signed for another device all refuse with a clear error -- never
//! a cert, never an authorized_keys fallback.
//!

use anyhow::{bail, Result};

/// Hard max certificate lifetime: 24h, per contract. The setting clamps here.
pub(crate) const CERT_TTL_HARD_MAX_SECS: u64 = 86_400;
/// Default lifetime when unset: 1h (mirrors the setting default).
pub(crate) const CERT_TTL_DEFAULT_SECS: u64 = 3_600;
/// Skew allowance subtracted from validity start (late clocks, slow links).
pub(crate) const CERT_SKEW_SECS: u64 = 300;

/// Parse a ttl value (plain seconds or `30m`/`1h`/`1d` durations) and clamp
/// to the hard max. Zero, negative (unparseable), and garbage refuse --
/// signing with a guessed lifetime would over-grant against operator intent.
pub(crate) fn parse_ttl_secs(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if let Ok(secs) = trimmed.parse::<u64>() {
        if secs == 0 {
            bail!("ssh cert ttl must be greater than zero");
        }
        return Ok(secs.min(CERT_TTL_HARD_MAX_SECS));
    }
    let secs = crate::parse_duration_secs(trimmed)?;
    Ok(secs.min(CERT_TTL_HARD_MAX_SECS))
}

/// Resolve the configured ttl through the settings registry (default 1h).
/// Garbage refuses (fail closed); the hard max applies after parsing.
pub(crate) fn resolve_cert_ttl_secs() -> Result<u64> {
    let Some(setting) = crate::settings::find("ssh.cert_ttl") else {
        return Ok(CERT_TTL_DEFAULT_SECS);
    };
    let (raw, _) = crate::settings::resolve(setting, None);
    parse_ttl_secs(&raw)
}

/// Effective validity: min(grant expiry if known, requested ttl, setting).
/// Requested 0 refuses (meaningless); the setting side is already clamped.
pub(crate) fn clamp_validity_secs(
    grant_expiry_secs: Option<u64>,
    requested_secs: u64,
    setting_secs: u64,
) -> Result<u64> {
    if requested_secs == 0 {
        bail!("ssh cert ttl must be greater than zero");
    }
    let mut out = requested_secs.min(setting_secs);
    if let Some(g) = grant_expiry_secs {
        out = out.min(g);
    }
    if out == 0 {
        bail!("ssh cert expires immediately under the clamp; refusing");
    }
    Ok(out)
}

/// Absolute `-V` interval for ssh-keygen from a ttl: `AFTER:BEFORE` with a
/// skew allowance on the start. Absolute timestamps (universally accepted),
/// never relative suffixes.
pub(crate) fn validity_interval(now_secs: u64, ttl_secs: u64) -> String {
    format!("{}:{}", stamp(now_secs.saturating_sub(CERT_SKEW_SECS)), stamp(now_secs + ttl_secs))
}

fn stamp(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|d| d.format("%Y%m%d%H%M%S").to_string())
        .unwrap_or_else(|| "19700101000000".to_string())
}

/// Check the CA key file: must exist and (unix) be exactly 0600. A group- or
/// world-readable CA key refuses -- fail closed, never sign anyway.
pub(crate) fn check_ca_key(path: &std::path::Path) -> Result<()> {
    if !path.is_file() {
        bail!("ssh CA key not found at {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "ssh CA key at {} has permissions {:o}, need 0600",
                path.display(),
                mode
            );
        }
    }
    Ok(())
}

/// Refuse anything but a bare ed25519 pubkey (options prefixes, other types,
/// and empty input all fail closed: ssh-keygen would happily sign them).
pub(crate) fn check_ephemeral_pubkey(text: &str) -> Result<()> {
    if text.starts_with("ssh-ed25519 ") && text.trim().split_whitespace().count() >= 2 {
        Ok(())
    } else {
        bail!("only bare ed25519 ephemeral keys are signed");
    }
}

/// Exact pinned ssh-keygen argv: `-I` device id only, `-n` daemon user only,
/// absolute `-V` interval, monotonic `-z` serial, `-O clear` + `-O permit-pty`
/// and nothing else. No shell involved (direct spawn by the caller).
pub(crate) fn build_sign_argv(
    ca_path: &std::path::Path,
    pubkey_file: &std::path::Path,
    key_id: &str,
    principal: &str,
    validity: &str,
    serial: u64,
) -> Vec<String> {
    vec![
        "-s".to_string(),
        ca_path.to_string_lossy().into_owned(),
        "-I".to_string(),
        key_id.to_string(),
        "-n".to_string(),
        principal.to_string(),
        "-V".to_string(),
        validity.to_string(),
        "-z".to_string(),
        serial.to_string(),
        "-O".to_string(),
        "clear".to_string(),
        "-O".to_string(),
        "permit-pty".to_string(),
        pubkey_file.to_string_lossy().into_owned(),
    ]
}

/// One issued-cert record: binds a pubkey to the device it was signed for,
/// so the same key is never re-signed for someone else.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct IssuedCert {
    pub pubkey: String,
    pub device_id: String,
    pub serial: u64,
}

/// Next monotonic serial: one past the max on record (starts at 1).
pub(crate) fn next_serial(records: &[IssuedCert]) -> u64 {
    records.iter().map(|r| r.serial).max().unwrap_or(0) + 1
}

/// Refuse a pubkey already signed for a DIFFERENT device id (key sharing
/// across devices). Same device re-issue is allowed (new serial).
pub(crate) fn refuse_resign(records: &[IssuedCert], pubkey: &str, device_id: &str) -> Result<()> {
    if let Some(r) = records.iter().find(|r| r.pubkey == pubkey) {
        if r.device_id != device_id {
            bail!("ephemeral key already signed for a different device; refusing re-sign");
        }
    }
    Ok(())
}

/// Sidecar path for the issued-cert record (config dir).
pub(crate) fn issued_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("ssh_ca_issued.json")
}

/// Load the record (missing file = no issuances yet, not an error).
pub(crate) fn load_issued(config_dir: &std::path::Path) -> Vec<IssuedCert> {
    let p = issued_path(config_dir);
    let Ok(raw) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

/// Append one issuance (best-effort persist; a lost record only loses the
/// re-sign check for old keys, never grants anything).
pub(crate) fn record_issuance(config_dir: &std::path::Path, rec: &IssuedCert) {
    let mut v = load_issued(config_dir);
    v.push(rec.clone());
    let _ = std::fs::write(issued_path(config_dir), serde_json::to_string(&v).unwrap_or_default());
}

/// Issuance log line fields (who, principal, serial, expiry), per contract.
pub(crate) fn format_issuance(device_id: &str, principal: &str, serial: u64, valid_before: &str) -> String {
    format!("ssh-ca: signed for '{device_id}' principal '{principal}' serial {serial} expiry {valid_before}")
}

/// CA private-key path: beside the managed keys in the ssh dir (which is
/// 0700 by construction). Operator-provisioned or minted at init; never
/// temp-copied, always passed by path.
pub(crate) fn ca_key_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("ssh").join("ssh_ca")
}

/// Mint the CA key idempotently (0700 dir, 0600 key, 0644 pub): exists →
/// return as-is (perm problems fail closed later at sign time); missing →
/// ssh-keygen, deleting a half-created key on failure. ssh-keygen itself
/// missing refuses (the caller warns and continues: init must not fail
/// for an SSH-CA nicety, and signing fails closed with a clear error).
pub(crate) fn ensure_ca_key_with(
    config_dir: &std::path::Path,
    keygen_bin: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let key = ca_key_path(config_dir);
    if key.exists() {
        return Ok(key);
    }
    if let Some(dir) = key.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let created = !key.exists();
    let status = std::process::Command::new(keygen_bin)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "filament-ca", "-f"])
        .arg(&key)
        .stdin(std::process::Stdio::null())
        .status()
        .map_err(|e| anyhow::anyhow!("CA mint failed to run ssh-keygen: {e}"))?;
    if !status.success() {
        if created {
            let _ = std::fs::remove_file(&key);
            let _ = std::fs::remove_file(key.with_extension("pub"));
        }
        bail!("ssh-keygen refused to mint the CA key");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

/// Mint with the real ssh-keygen.
pub(crate) fn ensure_ca_key(config_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    ensure_ca_key_with(config_dir, std::path::Path::new("ssh-keygen"))
}

/// Pure core: the daemon serving user is the shell-user setting when set,
/// else the daemon process user, else root. Never anything the initiator
/// sent: the principal is B's decision alone (contract pins `-n`).
pub(crate) fn daemon_username_from(
    shell_user: Option<&str>,
    env_user: Option<&str>,
) -> String {
    shell_user
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| env_user.filter(|s| !s.is_empty()).map(str::to_string))
        .unwrap_or_else(|| "root".to_string())
}

/// Resolve the serving user for signing (thin wrapper over the pure core).
pub(crate) fn daemon_username() -> String {
    let su = crate::settings::get_str("shell-user", None);
    daemon_username_from(su.as_deref(), std::env::var("USER").ok().as_deref())
}

/// A validated `ssh-sign-request`: asserted device id, ephemeral pubkey,
/// requested ttl. Semantic checks (ed25519 shape, ttl range) run in sign()
/// so every layer fails closed independently; parse only enforces shape.
pub(crate) struct SignRequest {
    pub(crate) device_id: String,
    pub(crate) ephemeral_pubkey: String,
    pub(crate) ttl_secs: u64,
}

pub(crate) fn parse_sign_request(v: &serde_json::Value) -> Option<SignRequest> {
    let device_id = v.get("device_id")?.as_str()?;
    if device_id.is_empty() || device_id.len() > 128 {
        return None;
    }
    let ephemeral_pubkey = v.get("ephemeral_pubkey")?.as_str()?;
    if ephemeral_pubkey.is_empty() || ephemeral_pubkey.len() > 4096 {
        return None;
    }
    let ttl_secs = v.get("ttl_secs")?.as_u64()?;
    Some(SignRequest { device_id: device_id.to_string(), ephemeral_pubkey: ephemeral_pubkey.to_string(), ttl_secs })
}

/// Handle one `ssh-sign-request` past the l2_enabled guard: validate, gate
/// through the shared shell gate (third path), clamp, sign, reply. Sends
/// its own replies (cert or l2-close refusal) and returns; the hook arm
/// only looks up the transport and continues.
pub(crate) async fn handle_ssh_sign(
    conn: &mut crate::conn::Conn,
    pid: &str,
    t: std::sync::Arc<dyn crate::net::Transport>,
    v: &serde_json::Value,
    shell_policy: &crate::ShellPolicy,
) {
    let deny = |t: &std::sync::Arc<dyn crate::net::Transport>, sid: u32, reason: &str| {
        let t = t.clone();
        let reason = reason.to_string();
        async move {
            let _ = t
                .send_control(&serde_json::json!({ "type": "l2-close", "sid": sid, "err": reason }))
                .await;
        }
    };
    let Some(req) = parse_sign_request(v) else {
        return;
    };
    let Some(sid) = crate::l2::wire_sid(v) else {
        return;
    };
    // Gate first (same function, same inputs as pty/exec): no grant, no cert.
    let (dev, inputs) = crate::shell_gate::gather_shell_gate_inputs(conn, pid, shell_policy);
    if let Err(cap_reason) = crate::shell_gate::ssh_gate_decision(&inputs) {
        let reason = cap_reason.unwrap_or_else(|| "shell capability not granted".to_string());
        crate::ui::say(&format!("l2: ssh-sign refused: {reason}"));
        deny(&t, sid, &reason).await;
        return;
    }
    // -I always carries the LINK-verified name, never the asserted one: a
    // lying id would poison audit, so on mismatch the verified name wins
    // and the attempt is logged loudly (the spoof fails closed: the cert
    // labels the true peer, never the claimed one). Unverified links have
    // no name to certify, so they refuse.
    let verified = dev.clone().unwrap_or_default();
    if verified.is_empty() {
        let reason = "ssh-sign refused: link peer is unverified";
        crate::ui::say(&format!("l2: {reason}"));
        deny(&t, sid, reason).await;
        return;
    }
    if verified != req.device_id {
        crate::ui::say(&format!(
            "l2: ssh-sign id mismatch (asserted '{}', verified '{}'): certifying verified",
            req.device_id, verified
        ));
    }
    let config_dir = crate::settings::config_dir();
    let ca_path = ca_key_path(&config_dir);
    if let Err(e) = check_ca_key(&ca_path) {
        let reason = format!("ssh-sign refused: {e}");
        deny(&t, sid, &reason).await;
        return;
    }
    let setting_ttl = match resolve_cert_ttl_secs() {
        Ok(s) => s,
        Err(e) => {
            let reason = format!("ssh-sign refused: bad ssh.cert_ttl: {e}");
            deny(&t, sid, &reason).await;
            return;
        }
    };
    let grant_expiry = conn.link(pid).and_then(|l| l.identity_cert_expires);
    let ttl = match clamp_validity_secs(grant_expiry, req.ttl_secs, setting_ttl) {
        Ok(s) => s,
        Err(e) => {
            let reason = format!("ssh-sign refused: {e}");
            deny(&t, sid, &reason).await;
            return;
        }
    };
    let records = load_issued(&config_dir);
    if let Err(e) = refuse_resign(&records, &req.ephemeral_pubkey, &verified) {
        let reason = format!("ssh-sign refused: {e}");
        deny(&t, sid, &reason).await;
        return;
    }
    let serial = next_serial(&records);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let validity = validity_interval(now, ttl);
    let principal = daemon_username();
    let workdir = std::env::temp_dir().join(format!(
        "fil-ssh-sign-{}-{}",
        std::process::id(),
        serial
    ));
    if std::fs::create_dir_all(&workdir).is_err() {
        deny(&t, sid, "ssh-sign refused: cannot stage signing").await;
        return;
    }
    let cert = match sign(
        std::path::Path::new("ssh-keygen"),
        &ca_path,
        &req.ephemeral_pubkey,
        &verified,
        &principal,
        &validity,
        serial,
        &workdir,
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&workdir);
            let reason = format!("ssh-sign refused: {e}");
            deny(&t, sid, &reason).await;
            return;
        }
    };
    let _ = std::fs::remove_dir_all(&workdir);
    record_issuance(
        &config_dir,
        &IssuedCert { pubkey: req.ephemeral_pubkey.clone(), device_id: verified.clone(), serial },
    );
    let valid_before = validity.rsplit(':').next().unwrap_or("");
    crate::ui::say(&format!(
        "l2: {}",
        format_issuance(&verified, &principal, serial, valid_before)
    ));
    let _ = t
        .send_control(&serde_json::json!({ "type": "ssh-sign-response", "sid": sid, "cert": cert }))
        .await;
}

/// This device's asserted id for sign requests: the configured name (env
/// override wins, same resolution as everywhere else).
pub(crate) fn local_device_id() -> String {
    crate::settings::get_str("name", None).unwrap_or_else(|| "unknown".to_string())
}

/// Identity files for one cert-authenticated ssh invocation (both under the
/// ephemeral tmpdir, removed with it).
pub(crate) struct CertIdentity {
    pub key_path: std::path::PathBuf,
    pub cert_path: std::path::PathBuf,
}

/// Full client side: bring up a link, request the cert, write it next to
/// the ephemeral key. Fail closed (clear error, no managed-key fallback):
/// silently downgrading would make the CA a decoration an attacker defeats
/// by blocking sign responses.
pub(crate) async fn acquire_ssh_cert(
    server: &str,
    peer: &str,
    relay: bool,
    eph: &EphemeralKey,
) -> Result<CertIdentity> {
    let ttl = resolve_cert_ttl_secs()?;
    let device_id = local_device_id();
    let inner = crate::l2::bring_up_to_known(server, peer, relay, "ssh-sign");
    let (t, mut rx, guard, _diag) =
        match tokio::time::timeout(std::time::Duration::from_secs(45), inner).await {
            Ok(inner) => inner?,
            Err(_) => {
                anyhow::bail!("connect timeout: couldn't reach '{peer}' in 45s");
            }
        };
    guard.forget();
    let mux = crate::l2::Mux::new(t.clone());
    let sid = mux.alloc_sid();
    let cert = request_cert(&t, &mut rx, sid, &device_id, eph.pubkey_text(), ttl).await?;
    let cert_path = eph.dir().join("key-cert.pub");
    std::fs::write(&cert_path, format!("{cert}\n"))?;
    Ok(CertIdentity { key_path: eph.private_path(), cert_path })
}

/// Request a certificate over an established link: send the open, wait
/// bounded (10s, like exec's ack) for the cert, a refusal, or silence.
/// Pure control round trip (no stream registered); the sid only correlates.
pub(crate) async fn request_cert(
    t: &std::sync::Arc<dyn crate::net::Transport>,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::net::Ev>,
    sid: u32,
    device_id: &str,
    pubkey: &str,
    ttl_secs: u64,
) -> Result<String> {
    t.send_control(&serde_json::json!({
        "type": "ssh-sign-request",
        "sid": sid,
        "device_id": device_id,
        "ephemeral_pubkey": pubkey,
        "ttl_secs": ttl_secs,
    }))
    .await?;
    let cert: Result<String, String> = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let ev = match rx.recv().await {
                Some(ev) => ev,
                None => break Err("peer closed the sign stream before answering".to_string()),
            };
            match ev {
                crate::net::Ev::Control(_pid, v) => {
                    let is_ours = v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64);
                    match v.get("type").and_then(|x| x.as_str()) {
                        Some("ssh-sign-response") if is_ours => {
                            match v.get("cert").and_then(|c| c.as_str()) {
                                Some(c) if !c.is_empty() => break Ok(c.to_string()),
                                _ => break Err("peer answered without a cert".to_string()),
                            }
                        }
                        Some("l2-close") if is_ours => {
                            break Err(v
                                .get("err")
                                .and_then(|e| e.as_str())
                                .unwrap_or("closed")
                                .to_string());
                        }
                        _ => {}
                    }
                }
                crate::net::Ev::Chunk(_pid, got, _offset, data) => {
                    // No streams in this exchange, but never let a frame sit
                    // unread: feed the mux like every other pump does.
                    let _ = (got, data);
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "no answer to ssh-sign-request - peer may run a build without SSH CA"
        )
    })?;
    cert.map_err(|reason| anyhow::anyhow!("ssh sign refused by peer: {reason}"))
}

/// Ephemeral client key: a fresh ed25519 keypair in a 0700 tmpdir, unique
/// per invocation. Removal is a scope guard with three triggers, because no
/// single one covers every exit: Drop covers returns/unwinds, an explicit
/// `cleanup()` covers `process::exit` (which skips Drop) on the normal
/// path, and `spawn_cleanup_on_signal` covers SIGINT/SIGTERM. All three are
/// idempotent (double remove is ignored), so overlap is harmless.
pub(crate) struct EphemeralKey {
    dir: std::path::PathBuf,
    pubkey: String,
}

impl EphemeralKey {
    /// Generate with the real ssh-keygen.
    pub(crate) fn generate() -> Result<Self> {
        Self::generate_with(std::path::Path::new("ssh-keygen"))
    }

    /// Generate with an injectable keygen binary (tests pass a stub).
    pub(crate) fn generate_with(keygen_bin: &std::path::Path) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "fil-ssh-ephemeral-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let cleanup_on_err = || {
            let _ = std::fs::remove_dir_all(&dir);
        };
        let key = dir.join("key");
        let status = std::process::Command::new(keygen_bin)
            .args([
                "-q",
                "-t",
                "ed25519",
                "-f",
                &key.to_string_lossy(),
                "-N",
                "",
                "-C",
                "filament-ephemeral",
            ])
            .stdin(std::process::Stdio::null())
            .status()
            .map_err(|e| anyhow::anyhow!("ephemeral keygen failed to run: {e}"));
        let status = match status {
            Ok(s) => s,
            Err(e) => {
                cleanup_on_err();
                return Err(e);
            }
        };
        if !status.success() {
            cleanup_on_err();
            bail!(
                "ephemeral keygen refused (exit {})",
                status.code().unwrap_or(-1)
            );
        }
        let pubkey = std::fs::read_to_string(dir.join("key.pub")).map_err(|_| {
            cleanup_on_err();
            anyhow::anyhow!("ephemeral keygen wrote no pubkey; refusing")
        })?;
        Ok(Self { dir, pubkey: pubkey.trim().to_string() })
    }

    pub(crate) fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    pub(crate) fn private_path(&self) -> std::path::PathBuf {
        self.dir.join("key")
    }

    pub(crate) fn pubkey_text(&self) -> &str {
        &self.pubkey
    }

    /// Idempotent removal (all three guard triggers funnel here).
    pub(crate) fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Signal watchdog: remove the ephemeral dir on SIGINT/SIGTERM, then exit
/// with the conventional code. Subscribing replaces the default disposition
/// (the process would otherwise survive the signal), so exiting here is
/// required, not optional. The caller aborts the handle on the normal path.
/// Unix watches INT+TERM; other platforms watch Ctrl-C.
pub(crate) fn spawn_cleanup_on_signal(dir: std::path::PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut interrupt = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut terminate = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let code = tokio::select! {
                _ = interrupt.recv() => 130,
                _ = terminate.recv() => 143,
            };
            let _ = std::fs::remove_dir_all(&dir);
            std::process::exit(code);
        }
        #[cfg(not(unix))]
        {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = std::fs::remove_dir_all(&dir);
                std::process::exit(130);
            }
        }
    })
}

/// Sign: write the pubkey to the workdir, run ssh-keygen, read back the
/// `<pubkey>-cert.pub` it writes. Nonzero exit, missing output, or any IO
/// failure refuses with a clear error -- never a cert, never a fallback.
/// `keygen_bin` is injectable so tests pass a stub instead of the real tool.
pub(crate) fn sign(
    keygen_bin: &std::path::Path,
    ca_path: &std::path::Path,
    pubkey_text: &str,
    key_id: &str,
    principal: &str,
    validity: &str,
    serial: u64,
    workdir: &std::path::Path,
) -> Result<String> {
    check_ephemeral_pubkey(pubkey_text)?;
    let pub_file = workdir.join("key.pub");
    std::fs::write(&pub_file, pubkey_text)?;
    let argv = build_sign_argv(ca_path, &pub_file, key_id, principal, validity, serial);
    let status = std::process::Command::new(keygen_bin)
        .args(&argv)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| anyhow::anyhow!("ssh-keygen failed to run: {e}"))?;
    if !status.status.success() {
        bail!(
            "ssh-keygen refused to sign (exit {}): {}",
            status.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    let cert_file = workdir.join("key-cert.pub");
    std::fs::read_to_string(&cert_file)
        .map(|s| s.trim().to_string())
        .map_err(|_| anyhow::anyhow!("ssh-keygen exited 0 but wrote no cert; refusing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_parses_seconds_and_durations_then_clamps() {
        assert_eq!(parse_ttl_secs("3600").unwrap(), 3600);
        assert_eq!(parse_ttl_secs("30m").unwrap(), 1800);
        assert_eq!(parse_ttl_secs("1h").unwrap(), 3600);
        assert_eq!(parse_ttl_secs("48h").unwrap(), 86_400);
        assert!(parse_ttl_secs("0").is_err());
        assert!(parse_ttl_secs("soon").is_err());
        assert!(parse_ttl_secs("").is_err());
    }

    #[test]
    fn clamp_takes_min_and_rejects_zero() {
        assert_eq!(clamp_validity_secs(None, 60, 3600).unwrap(), 60);
        assert_eq!(clamp_validity_secs(Some(30), 3600, 3600).unwrap(), 30);
        assert_eq!(clamp_validity_secs(None, 99_999, 3600).unwrap(), 3600);
        assert!(clamp_validity_secs(None, 0, 3600).is_err());
    }

    #[test]
    fn validity_is_absolute_with_skew() {
        // 2026-09-13T21:20:00Z == 1789334400: start backs off 5m skew.
        assert_eq!(
            validity_interval(1789334400, 3600),
            "20260913211500:20260913222000"
        );
    }

    #[test]
    fn sign_argv_pins_everything() {
        let argv = build_sign_argv(
            std::path::Path::new("/ca"),
            std::path::Path::new("/w/key.pub"),
            "boxA",
            "daemon",
            "20260914000000:20260914010000",
            7,
        );
        assert_eq!(
            argv,
            vec![
                "-s", "/ca", "-I", "boxA", "-n", "daemon", "-V",
                "20260914000000:20260914010000", "-z", "7", "-O", "clear",
                "-O", "permit-pty", "/w/key.pub"
            ]
        );
        assert!(!argv.iter().any(|a| a.contains(' ') && !a.contains('/')),
            "no joined/shell-quoted values: {argv:?}");
    }

    #[test]
    fn ephemeral_accepts_only_bare_ed25519() {
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAAC3xyz box").is_ok());
        assert!(check_ephemeral_pubkey("ssh-rsa AAAAB3xyz box").is_err());
        assert!(check_ephemeral_pubkey("no-touch-cert-request ssh-ed25519 AAAAC3xyz").is_err());
        assert!(check_ephemeral_pubkey("").is_err());
    }

    #[test]
    fn serials_monotonic_and_resign_bound_to_device() {
        let recs = vec![
            IssuedCert { pubkey: "k1".into(), device_id: "a".into(), serial: 4 },
            IssuedCert { pubkey: "k2".into(), device_id: "b".into(), serial: 9 },
        ];
        assert_eq!(next_serial(&recs), 10);
        assert_eq!(next_serial(&[]), 1);
        assert!(refuse_resign(&recs, "k1", "a").is_ok());
        assert!(refuse_resign(&recs, "k3", "zzz").is_ok());
        assert!(refuse_resign(&recs, "k1", "EVIL").is_err());
    }

    #[test]
    fn issuance_line_carries_contract_fields() {
        let line = format_issuance("boxA", "daemon", 7, "20260914010000");
        for field in ["boxA", "daemon", "7", "20260914010000"] {
            assert!(line.contains(field), "missing {field}: {line}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ca_key_requires_0600() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let strict = dir.join("ca");
        let loose = dir.join("ca-loose");
        let missing = dir.join("ca-missing");
        std::fs::write(&strict, "x").unwrap();
        std::fs::write(&loose, "x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&strict, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_ca_key(&strict).is_ok());
        assert!(check_ca_key(&loose).is_err());
        assert!(check_ca_key(&missing).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_sign_request_accepts_shape_rejects_garbage() {
        let good = serde_json::json!({
            "type": "ssh-sign-request", "sid": 1,
            "device_id": "boxA",
            "ephemeral_pubkey": "ssh-ed25519 AAAAC3xyz",
            "ttl_secs": 3600u64,
        });
        let req = parse_sign_request(&good).expect("parses");
        assert_eq!(req.device_id, "boxA");
        assert_eq!(req.ttl_secs, 3600);
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"device_id": "", "ephemeral_pubkey": "k", "ttl_secs": 1u64}),
            serde_json::json!({"device_id": "a", "ephemeral_pubkey": "", "ttl_secs": 1u64}),
            serde_json::json!({"device_id": "a", "ephemeral_pubkey": "k"}),
            serde_json::json!({"device_id": "a", "ephemeral_pubkey": "k", "ttl_secs": "soon"}),
        ] {
            assert!(parse_sign_request(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn daemon_username_prefers_setting_then_env() {
        assert_eq!(daemon_username_from(Some("svc"), Some("bob")), "svc");
        assert_eq!(daemon_username_from(None, Some("bob")), "bob");
        assert_eq!(daemon_username_from(Some(""), Some("bob")), "bob");
        assert_eq!(daemon_username_from(None, None), "root");
    }

    #[cfg(unix)]
    #[test]
    fn ca_mint_is_idempotent_and_needs_keygen() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-mint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Missing keygen binary refuses without creating anything.
        assert!(ensure_ca_key_with(&dir, std::path::Path::new("/bin/false")).is_err());
        assert!(!ca_key_path(&dir).exists());
        // Stub that behaves like ssh-keygen -f (writes key + pub).
        let stub = dir.join("stub-keygen");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &stub,
            "#!/bin/sh\nf=\"\";prev=\"\";for a in \"$@\";do if [ \"$prev\" = \"-f\" ];then f=\"$a\";fi;prev=\"$a\";done\necho PRIVATE > \"$f\"\necho PUBLIC > \"$f.pub\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key = ensure_ca_key_with(&dir, &stub).expect("stub mints");
        assert_eq!(key, ca_key_path(&dir));
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "minted CA key must be 0600");
        let mode = std::fs::metadata(dir.join("ssh")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "ssh dir must be 0700");
        // Second run returns the same key without touching it.
        let again = ensure_ca_key_with(&dir, std::path::Path::new("/bin/false")).expect("idempotent");
        assert_eq!(again, key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_key_is_0700_fresh_and_cleaned() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-stub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub-keygen");
        std::fs::write(
            &stub,
            "#!/bin/sh\nf=\"\";prev=\"\";for a in \"$@\";do if [ \"$prev\" = \"-f\" ];then f=\"$a\";fi;prev=\"$a\";done\necho PRIVATE > \"$f\"\necho 'ssh-ed25519 AAAAC3test stub' > \"$f.pub\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key = EphemeralKey::generate_with(&stub).expect("stub keygen succeeds");
        assert_eq!(key.pubkey_text(), "ssh-ed25519 AAAAC3test stub");
        let mode = std::fs::metadata(key.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "ephemeral tmpdir must be 0700");
        assert!(key.private_path().is_file());
        let path = key.dir().to_path_buf();
        drop(key);
        assert!(!path.exists(), "scope guard removes the tmpdir on drop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_keygen_failure_is_an_error() {
        assert!(EphemeralKey::generate_with(std::path::Path::new("/bin/false")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sign_refuses_on_nonzero_and_missing_output() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0bW9Oq68v6Kz4pGk3Bn2K8R8m4t stunt";
        // Nonzero exit refuses with the stderr attached.
        let e = sign(
            std::path::Path::new("/bin/false"),
            std::path::Path::new("/ca"),
            key, "boxA", "daemon", "V", 1, &dir,
        )
        .unwrap_err();
        assert!(e.to_string().contains("refused to sign"), "{e}");
        // Zero exit but no cert file refuses too (never an empty cert).
        let e = sign(
            std::path::Path::new("/bin/true"),
            std::path::Path::new("/ca"),
            key, "boxA", "daemon", "V", 1, &dir,
        )
        .unwrap_err();
        assert!(e.to_string().contains("wrote no cert"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
