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

/// Effective validity: min(grant remaining if known, requested ttl, setting).
/// All three are durations-from-now, so they compare directly. Requested 0
/// refuses (meaningless); the setting side is already clamped.
pub(crate) fn clamp_validity_secs(
    grant_remaining_secs: Option<u64>,
    requested_secs: u64,
    setting_secs: u64,
) -> Result<u64> {
    if requested_secs == 0 {
        bail!("ssh cert ttl must be greater than zero");
    }
    let mut out = requested_secs.min(setting_secs);
    if let Some(g) = grant_remaining_secs {
        out = out.min(g);
    }
    if out == 0 {
        bail!("ssh cert expires immediately under the clamp; refusing");
    }
    Ok(out)
}

/// Relative `-V` interval for ssh-keygen from a ttl: `-5m:+<ttl>s`. Pure
/// relative form, so there is NOTHING timezone-dependent anywhere in the
/// path (no timestamps rendered, nothing to shift under TZ=Asia/Lagos).
/// Verified live against ssh-keygen (seconds suffix accepted, validity
/// window correct); the skew allowance absorbs clock drift and slow links.
pub(crate) fn validity_interval(ttl_secs: u64) -> String {
    format!("-{}m:+{}s", CERT_SKEW_SECS / 60, ttl_secs)
}

/// Grant-expiry bound (relative seconds) from both stores: the legacy
/// device capExpires.shell for the name, plus fleet cap_grant ops for the
/// peer's user key. Most restrictive wins; absent everywhere means
/// unexpiring (None). Expired clamps to 0 via saturating_sub, which the
/// validity clamp then refuses. `now_secs` is a parameter (not read) so
/// tests pin time instead of racing it.
pub(crate) fn grant_expiry_secs(
    config_dir: &std::path::Path,
    device_name: &str,
    user_pub: Option<[u8; 32]>,
    now_secs: u64,
) -> Option<u64> {
    let mut best: Option<u64> = None;
    let mut consider = |exp: u64| {
        best = Some(best.map_or(exp, |b: u64| b.min(exp)));
    };
    if let Ok(raw) = std::fs::read_to_string(config_dir.join("devices.json")) {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&raw) {
            if let Some(d) = arr.iter().find(|d| d["name"].as_str() == Some(device_name)) {
                if let Some(e) = d["capExpires"]["shell"].as_u64() {
                    consider(e);
                }
            }
        }
    }
    if let Some(up) = user_pub {
        let key = hex::encode(up);
        for e in crate::capability::load_cap_store(config_dir).iter().filter(|e| {
            e["type"].as_str() == Some("cap_grant")
                && e["resource"].as_str() == Some("self")
                && e["permissions"].as_array().is_some_and(|p| {
                    p.iter().any(|c| c.as_str() == Some("shell"))
                })
                && e["target"].as_str() == Some(&key)
        }) {
            if let Some(x) = e["expires"].as_u64() {
                consider(x);
            }
        }
    }
    best.map(|e| e.saturating_sub(now_secs))
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

/// Refuse anything but a bare ed25519 pubkey, strictly: no newlines/CR
/// (log injection + multi-key smuggling), exactly 2-3 whitespace fields
/// (type, base64, optional comment), and the base64 must decode to the
/// ssh-ed25519 wire prefix (4-byte length 11 + "ssh-ed25519"). A textual
/// prefix match alone would bless `ssh-ed25519AAA...` garbage or a valid
/// prefix on non-key bytes; ssh-keygen would happily sign either.
pub(crate) fn check_ephemeral_pubkey(text: &str) -> Result<()> {
    if text.bytes().any(|b| b == b'\n' || b == b'\r') {
        bail!("ephemeral pubkey must be a single line");
    }
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() < 2 || fields.len() > 3 {
        bail!("ephemeral pubkey must have 2-3 fields");
    }
    if fields[0] != "ssh-ed25519" {
        bail!("only bare ed25519 ephemeral keys are signed");
    }
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(fields[1])
        .map_err(|_| anyhow::anyhow!("ephemeral pubkey is not valid base64"))?;
    if raw.len() < 15 || &raw[0..4] != &[0, 0, 0, 11] || &raw[4..15] != b"ssh-ed25519" {
        bail!("ephemeral pubkey does not decode to an ssh-ed25519 key");
    }
    Ok(())
}

/// Exact pinned ssh-keygen argv: `-I` device id only, `-n` daemon user only
/// (single principal: commas/whitespace would certify extra names, so they
/// refuse here at the tool boundary, not just at the caller), absolute `-V`
/// interval, monotonic `-z` serial, `-O clear` + `-O permit-pty` and nothing
/// else. No shell involved (direct spawn by the caller).
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
/// so the same key is never re-signed for someone else. Carries its expiry
/// so dead entries prune instead of accumulating forever.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct IssuedCert {
    pub pubkey: String,
    pub device_id: String,
    pub serial: u64,
    pub expires: u64,
}

/// Next monotonic serial: one past the max on record (starts at 1). The
/// counter additionally persists in its own file (below); the record max is
/// the fallback when that file is absent.
pub(crate) fn next_serial(records: &[IssuedCert]) -> u64 {
    records.iter().map(|r| r.serial).max().unwrap_or(0) + 1
}

/// Serial counter path (separate small file, not the record).
pub(crate) fn serial_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("ssh_ca_serial")
}

/// Read the persisted serial, falling back to the record max. Garbage reads
/// as absent (fail closed downstream: a lost counter restarts at record
/// max + 1, never at zero over live serials).
pub(crate) fn read_serial(config_dir: &std::path::Path, records: &[IssuedCert]) -> u64 {
    std::fs::read_to_string(serial_path(config_dir))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or_else(|| next_serial(records))
}

/// Persist the NEXT serial atomically (temp + rename). Errors fail closed:
/// a serial that cannot be persisted must not be issued (a crash between
/// issue and persist would otherwise repeat it). No lock needed: issuance
/// runs inline in the daemon's single recv loop, so two signs cannot
/// interleave the read-increment-write.
pub(crate) fn write_serial(config_dir: &std::path::Path, next: u64) -> Result<()> {
    let path = serial_path(config_dir);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, next.to_string())?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
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

/// Load the record (missing file = no issuances yet, not an error),
/// pruning expired entries so the ledger does not accumulate dead rows.
/// `now_secs` is a parameter (not read) so tests pin time.
pub(crate) fn load_issued(config_dir: &std::path::Path, now_secs: u64) -> Vec<IssuedCert> {
    let p = issued_path(config_dir);
    let Ok(raw) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    let mut v: Vec<IssuedCert> = serde_json::from_str(&raw).unwrap_or_default();
    let before = v.len();
    v.retain(|r| r.expires > now_secs);
    if v.len() != before {
        let _ = std::fs::write(&p, serde_json::to_string(&v).unwrap_or_default());
    }
    v
}

/// Append one issuance, atomically (temp + rename). Errors fail closed at
/// the call site: an unrecorded cert must not ship, or the re-sign check
/// would go blind for it.
pub(crate) fn record_issuance(
    config_dir: &std::path::Path,
    rec: &IssuedCert,
    now_secs: u64,
) -> Result<()> {
    let mut v = load_issued(config_dir, now_secs);
    v.push(rec.clone());
    let text =
        serde_json::to_string(&v).map_err(|e| anyhow::anyhow!("issuance record unserializable: {e}"))?;
    let path = issued_path(config_dir);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Issuance log line fields (who, principal, serial, expiry), per contract.
pub(crate) fn format_issuance(device_id: &str, principal: &str, serial: u64, valid_before: &str) -> String {
    format!("ssh-ca: signed for '{device_id}' principal '{principal}' serial {serial} expiry {valid_before}")
}

/// Secure tempdir: random-suffixed, create_dir (fail-if-exists, NOT
/// create_dir_all), 0700 on unix. Retries on collision; a persistent
/// collision fails instead of reusing (reusing a predictable dir would let
/// another user pre-place symlinks). Used for both the client ephemeral dir
/// and the daemon staging dir.
pub(crate) fn secure_tempdir(prefix: &str) -> Result<std::path::PathBuf> {
    let base = std::env::temp_dir();
    for attempt in 0..10u32 {
        let dir = base.join(format!(
            "fil-{prefix}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            attempt
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
                }
                return Ok(dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("could not create a fresh tempdir for {prefix}")
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
pub(crate) async fn ensure_ca_key_with(
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
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(keygen_bin)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "filament-ca", "-f"])
            .arg(&key)
            .stdin(std::process::Stdio::null())
            .status(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("CA mint timed out running ssh-keygen"))?
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
pub(crate) async fn ensure_ca_key(config_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    ensure_ca_key_with(config_dir, std::path::Path::new("ssh-keygen")).await
}

/// Pure core: the daemon serving user is the shell-user setting when set,
/// else the daemon process user. Never anything the initiator sent: the
/// principal is B's decision alone (contract pins `-n`). Deliberately NO
/// root fallback: certifying root when the serving user is undeterminable
/// would mint a root login out of confusion (resolve_login's root fallback
/// is for the initiator's login GUESS, a harmless hint; a principal is a
/// security boundary, so unknown means refuse, not root).
pub(crate) fn daemon_username_from(
    shell_user: Option<&str>,
    env_user: Option<&str>,
) -> Option<String> {
    shell_user
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| env_user.filter(|s| !s.is_empty()).map(str::to_string))
}

/// Resolve the serving user for signing (thin wrapper over the pure core).
pub(crate) fn daemon_username() -> Option<String> {
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
    // Refusals are GENERIC on the wire: every deny looks identical out
    // there, so a refused peer cannot oracle which check failed. The detail
    // goes to the local log only (the malformed-frame case below is the
    // deliberate exception: it names itself so misconfigured peers can
    // tell a malformed request from a denied one).
    let refuse = |t: &std::sync::Arc<dyn crate::net::Transport>, sid: u32, detail: String| {
        let t = t.clone();
        async move {
            crate::ui::say(&format!("l2: ssh-sign refused: {detail}"));
            let _ = t
                .send_control(&serde_json::json!({ "type": "l2-close", "sid": sid, "err": "ssh-sign refused" }))
                .await;
        }
    };
    // Malformed requests are refused LOUDLY (not silently dropped): a peer
    // that cannot form the frame learns it immediately instead of timing
    // out. Only a missing sid stays silent (nothing to correlate the reply
    // to). Non-L2 sids are malformed here too: the exchange mints proper
    // L2 sids, so anything else is a foreign or forged frame.
    let Some(sid) = crate::l2::wire_sid(v) else {
        return;
    };
    let good_sid = crate::l2::is_l2_sid(sid);
    let Some(req) = parse_sign_request(v) else {
        if good_sid {
            let _ = t
                .send_control(&serde_json::json!({ "type": "l2-close", "sid": sid, "err": "malformed ssh-sign-request" }))
                .await;
        }
        return;
    };
    if !good_sid {
        let _ = t
            .send_control(&serde_json::json!({ "type": "l2-close", "sid": sid, "err": "malformed ssh-sign-request" }))
            .await;
        return;
    }
    // Gate first (same function, same inputs as pty/exec): no grant, no cert.
    let (dev, inputs) = crate::shell_gate::gather_shell_gate_inputs(conn, pid, shell_policy);
    if let Err(cap_reason) = crate::shell_gate::ssh_gate_decision(&inputs) {
        refuse(
            &t,
            sid,
            cap_reason.unwrap_or_else(|| "shell capability not granted".to_string()),
        )
        .await;
        return;
    }
    // -I always carries the LINK-verified name, never the asserted one: a
    // lying id would poison audit, so on mismatch the verified name wins
    // and the attempt is logged loudly (the spoof fails closed: the cert
    // labels the true peer, never the claimed one). Unverified links have
    // no name to certify, so they refuse.
    let verified = dev.clone().unwrap_or_default();
    if verified.is_empty() {
        refuse(&t, sid, "link peer is unverified".to_string()).await;
        return;
    }
    if verified != req.device_id {
        // {:?}-escaped: the asserted id is attacker-controlled (log
        // injection via newlines/ANSI), the verified name decides.
        crate::ui::say(&format!(
            "l2: ssh-sign id mismatch (asserted {:?}, verified '{}'): certifying verified",
            req.device_id, verified
        ));
    }
    let config_dir = crate::settings::config_dir();
    let ca_path = ca_key_path(&config_dir);
    if let Err(e) = check_ca_key(&ca_path) {
        refuse(&t, sid, format!("CA key: {e}")).await;
        return;
    }
    let setting_ttl = match resolve_cert_ttl_secs() {
        Ok(s) => s,
        Err(e) => {
            refuse(&t, sid, format!("bad ssh.cert_ttl: {e}")).await;
            return;
        }
    };
    let peer_user = {
        let az = crate::peer_authz(conn, pid);
        let (_, iusr, _, _, _, _) = az.parts();
        iusr.copied()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let grant_remaining = grant_expiry_secs(&config_dir, &verified, peer_user, now);
    let ttl = match clamp_validity_secs(grant_remaining, req.ttl_secs, setting_ttl) {
        Ok(s) => s,
        Err(e) => {
            refuse(&t, sid, format!("validity: {e}")).await;
            return;
        }
    };
    let records = load_issued(&config_dir, now);
    if let Err(e) = refuse_resign(&records, &req.ephemeral_pubkey, &verified) {
        refuse(&t, sid, format!("re-sign check: {e}")).await;
        return;
    }
    // Persist the serial BEFORE signing (atomic, fail closed): a crash
    // between issue and persist must never repeat a serial.
    let serial = read_serial(&config_dir, &records);
    if let Err(e) = write_serial(&config_dir, serial.saturating_add(1)) {
        refuse(&t, sid, format!("serial ledger unwritable: {e}")).await;
        return;
    }
    let validity = validity_interval(ttl);
    let Some(principal) = daemon_username() else {
        refuse(&t, sid, "cannot determine serving user".to_string()).await;
        return;
    };
    let workdir = match secure_tempdir("ssh-sign") {
        Ok(d) => d,
        Err(_) => {
            refuse(&t, sid, "cannot stage signing".to_string()).await;
            return;
        }
    };
    let cert = match sign(
        std::path::Path::new("ssh-keygen"),
        &ca_path,
        &req.ephemeral_pubkey,
        &verified,
        &principal,
        &validity,
        serial,
        &workdir,
    )
    .await {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&workdir);
            refuse(&t, sid, format!("signing failed: {e}")).await;
            return;
        }
    };
    let _ = std::fs::remove_dir_all(&workdir);
    // Record the issuance (fail closed: an unrecorded cert must not ship,
    // or the re-sign check would go blind for it).
    if record_issuance(
        &config_dir,
        &IssuedCert {
            pubkey: req.ephemeral_pubkey.clone(),
            device_id: verified.clone(),
            serial,
            expires: now.saturating_add(ttl),
        },
        now,
    )
    .is_err()
    {
        refuse(&t, sid, "issuance ledger unwritable".to_string()).await;
        return;
    }
    crate::ui::say(&format!(
        "l2: {}",
        format_issuance(&verified, &principal, serial, &(now + ttl).to_string())
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
    pub(crate) async fn generate() -> Result<Self> {
        Self::generate_with(std::path::Path::new("ssh-keygen")).await
    }

    /// Generate with an injectable keygen binary (tests pass a stub).
    pub(crate) async fn generate_with(keygen_bin: &std::path::Path) -> Result<Self> {
        let dir = secure_tempdir("ssh-ephemeral")?;
        let cleanup_on_err = || {
            let _ = std::fs::remove_dir_all(&dir);
        };
        let key = dir.join("key");
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::process::Command::new(keygen_bin)
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
                .status(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ephemeral keygen timed out"))?
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
pub(crate) async fn sign(
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
    if principal.bytes().any(|b| b == b',' || b.is_ascii_whitespace()) || principal.is_empty() {
        bail!("principal must be a single name");
    }
    let pub_file = workdir.join("key.pub");
    std::fs::write(&pub_file, pubkey_text)?;
    let argv = build_sign_argv(ca_path, &pub_file, key_id, principal, validity, serial);
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(keygen_bin)
            .args(&argv)
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("ssh-keygen timed out; refusing"))?
    .map_err(|e| anyhow::anyhow!("ssh-keygen failed to run: {e}"))?;
    if !status.status.success() {
        bail!(
            "ssh-keygen refused to sign (exit {}): {}",
            status.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    let cert_file = workdir.join("key-cert.pub");
    let cert = std::fs::read_to_string(&cert_file)
        .map(|s| s.trim().to_string())
        .map_err(|_| anyhow::anyhow!("ssh-keygen exited 0 but wrote no cert; refusing"))?;
    // Certs are public material, but a multi-user box should not offer them
    // for harvesting: lock the file down, fail closed if that fails.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cert_file, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("cannot lock down cert file: {e}"))?;
    }
    Ok(cert)
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
    fn validity_is_relative_with_skew() {
        // Pure relative form: no timestamps rendered, nothing TZ-dependent.
        assert_eq!(validity_interval(3600), "-5m:+3600s");
        assert_eq!(validity_interval(60), "-5m:+60s");
    }

    #[test]
    fn grant_expiry_reads_both_stores_most_restrictive_wins() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-exp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = 1_800_000_000u64;
        // Absent everywhere: unexpiring.
        assert_eq!(grant_expiry_secs(&dir, "boxA", None, now), None);
        // Legacy device store: 10-minute shell grant.
        std::fs::write(
            dir.join("devices.json"),
            r#"[{"name":"boxA","secret":"x","caps":["shell"],"capExpires":{"shell":1800000600}}]"#,
        )
        .unwrap();
        let got = grant_expiry_secs(&dir, "boxA", None, now).expect("legacy expiry");
        assert!(got <= 600 && got >= 590, "10-min grant clamps ttl, got {got}");
        // Fleet cap store with a tighter 5-minute shell grant for the peer key.
        let upub = [0x77u8; 32];
        std::fs::write(
            dir.join("caps.json"),
            format!(
                r#"[{{"type":"cap_grant","resource":"self","permissions":["shell"],"target":"{}","expires":{}}}]"#,
                hex::encode(upub),
                now + 300
            ),
        )
        .unwrap();
        let got = grant_expiry_secs(&dir, "boxA", Some(upub), now).expect("fleet expiry");
        assert!(got <= 300 && got >= 290, "tighter fleet grant wins, got {got}");
        // Expired clamps to zero (the validity clamp then refuses).
        std::fs::write(
            dir.join("devices.json"),
            r#"[{"name":"boxA","secret":"x","caps":["shell"],"capExpires":{"shell":1799999999}}]"#,
        )
        .unwrap();
        let _ = std::fs::remove_file(dir.join("caps.json"));
        assert_eq!(grant_expiry_secs(&dir, "boxA", None, now), Some(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relative_validity_accepted_under_foreign_tz() {
        // ssh-keygen must accept the relative -V under a non-UTC zone (the
        // old absolute stamps shifted with TZ). Nothing in this tree reads
        // localtime, so the set_var window below cannot disturb other tests.
        let prior = std::env::var("TZ").ok();
        unsafe { std::env::set_var("TZ", "Asia/Lagos") };
        let dir =
            std::env::temp_dir().join(format!("fil-sshca-tz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = (|| -> anyhow::Result<()> {
            std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-f"])
                .arg(dir.join("ca"))
                .args(["-N", ""])
                .status()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            // ssh-keygen refuses a 0644 signing key (and so does the
            // product's own check_ca_key): tighten the fixture like the
            // real mint path does.
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    dir.join("ca"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-f"])
                .arg(dir.join("key"))
                .args(["-N", ""])
                .status()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let out = std::process::Command::new("ssh-keygen")
                .args([
                    "-q", "-s", &dir.join("ca").to_string_lossy(), "-I", "t",
                    "-n", "root", "-V", &validity_interval(3600), "-z", "1",
                ])
                .arg(dir.join("key.pub"))
                .output()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            assert!(
                out.status.success(),
                "relative -V must be accepted: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let out = std::process::Command::new("ssh-keygen")
                .args(["-L", "-f"])
                .arg(dir.join("key-cert.pub"))
                .output()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(text.contains("Valid: from"), "cert carries a window: {text}");
            Ok(())
        })();
        match prior {
            Some(v) => unsafe { std::env::set_var("TZ", v) },
            None => unsafe { std::env::remove_var("TZ") },
        }
        let _ = std::fs::remove_dir_all(&dir);
        r.unwrap();
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
    fn secure_tempdir_is_unique_and_private() {
        let a = secure_tempdir("probe").expect("creates");
        let b = secure_tempdir("probe").expect("creates again");
        assert_ne!(a, b, "same prefix must still yield distinct dirs");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for d in [&a, &b] {
                let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "tmpdir must be 0700");
            }
        }
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn ephemeral_accepts_only_bare_ed25519() {
        // Real ed25519 body (decodes to the ssh-ed25519 wire prefix).
        let good = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIILzAe0+efgsfT1oeQP5UeMfhXaoRd/jKUNU9Ol2oub5 stunt";
        assert!(check_ephemeral_pubkey(good).is_ok());
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIILzAe0+efgsfT1oeQP5UeMfhXaoRd/jKUNU9Ol2oub5").is_ok());
        assert!(check_ephemeral_pubkey("ssh-rsa AAAAB3xyz box").is_err());
        assert!(check_ephemeral_pubkey("no-touch-cert-request ssh-ed25519 AAAAC3xyz").is_err());
        assert!(check_ephemeral_pubkey("").is_err());
        // Smuggling shapes: interior newline/CR, single field, four fields.
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAAC3xyz\nssh-ed25519 AAAAC3xyz").is_err());
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAAC3xyz\r").is_err());
        assert!(check_ephemeral_pubkey("ssh-ed25519").is_err());
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAA b c d").is_err());
        // Valid prefix on non-key bytes, and non-base64 body.
        assert!(check_ephemeral_pubkey("ssh-ed25519 !!!not-base64!!!").is_err());
        assert!(check_ephemeral_pubkey("ssh-ed25519 c3NoLXJzYQ==").is_err());
    }

    #[test]
    fn serials_monotonic_and_resign_bound_to_device() {
        let recs = vec![
            IssuedCert { pubkey: "k1".into(), device_id: "a".into(), serial: 4, expires: 9_999_999_999 },
            IssuedCert { pubkey: "k2".into(), device_id: "b".into(), serial: 9, expires: 9_999_999_999 },
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
        assert_eq!(daemon_username_from(Some("svc"), Some("bob")), Some("svc".to_string()));
        assert_eq!(daemon_username_from(None, Some("bob")), Some("bob".to_string()));
        assert_eq!(daemon_username_from(Some(""), Some("bob")), Some("bob".to_string()));
        assert_eq!(daemon_username_from(None, None), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ca_mint_is_idempotent_and_needs_keygen() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-mint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Missing keygen binary refuses without creating anything.
        assert!(ensure_ca_key_with(&dir, std::path::Path::new("/bin/false")).await.is_err());
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
        let key = ensure_ca_key_with(&dir, &stub).await.expect("stub mints");
        assert_eq!(key, ca_key_path(&dir));
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "minted CA key must be 0600");
        let mode = std::fs::metadata(dir.join("ssh")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "ssh dir must be 0700");
        // Second run returns the same key without touching it.
        let again = ensure_ca_key_with(&dir, std::path::Path::new("/bin/false")).await.expect("idempotent");
        assert_eq!(again, key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ledger_persists_serial_prunes_dead_and_roundtrips() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = 1_800_000_000u64;
        // Absent serial falls back to record max + 1 (fresh store: 1).
        assert_eq!(read_serial(&dir, &[]), 1);
        write_serial(&dir, 41).expect("serial persists");
        assert_eq!(read_serial(&dir, &[]), 41);
        // Garbage reads as absent (fail closed downstream, never zero).
        std::fs::write(serial_path(&dir), "bogus").unwrap();
        assert_eq!(read_serial(&dir, &[]), 1);
        // Record round trip; expired rows prune on load.
        record_issuance(
            &dir,
            &IssuedCert { pubkey: "k".into(), device_id: "a".into(), serial: 41, expires: now + 100 },
            now,
        )
        .expect("record persists");
        record_issuance(
            &dir,
            &IssuedCert { pubkey: "old".into(), device_id: "a".into(), serial: 40, expires: now - 1 },
            now,
        )
        .expect("record persists");
        let v = load_issued(&dir, now);
        assert_eq!(v.len(), 1, "expired rows prune");
        assert_eq!(v[0].serial, 41);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ephemeral_key_is_0700_fresh_and_cleaned() {
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
        let key = EphemeralKey::generate_with(&stub).await.expect("stub keygen succeeds");
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
    #[tokio::test]
    async fn ephemeral_keygen_failure_is_an_error() {
        assert!(EphemeralKey::generate_with(std::path::Path::new("/bin/false")).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sign_refuses_on_nonzero_and_missing_output() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIILzAe0+efgsfT1oeQP5UeMfhXaoRd/jKUNU9Ol2oub5 stunt";
        // Nonzero exit refuses with the stderr attached.
        let e = sign(
            std::path::Path::new("/bin/false"),
            std::path::Path::new("/ca"),
            key, "boxA", "daemon", "V", 1, &dir,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("refused to sign"), "{e}");
        // Zero exit but no cert file refuses too (never an empty cert).
        let e = sign(
            std::path::Path::new("/bin/true"),
            std::path::Path::new("/ca"),
            key, "boxA", "daemon", "V", 1, &dir,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("wrote no cert"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
