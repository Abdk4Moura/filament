//! `filament exec` receiver: parse the open frame, enforce the shell gate,
//! direct-spawn the command, and serve its stdio until it exits.
//!
//! This is the `exec-open` counterpart to the `pty-open` acceptor in recv_cmd.rs:
//! same four steps (enabled check lives in the hook arm, then sid validation,
//! shell gate, spawn+serve), same refusal verdicts, same `l2-close{err}` replies
//! so the initiator errors instead of hanging. Differences from a shell are
//! deliberate and total: NO login shell and no shell at all on the default path
//! (argv[] spawns directly), NO persistent session (each open serves once and
//! exits on child death -- there is nothing to reattach to), and stdout/stderr
//! travel on SEPARATE stream channels announced in the ack.
//!
//! Wire contract (CONTRACT.md, "Exec streams"): `exec-open` carries argv[]
//! EXACTLY, cwd, env and tty; `{type:"exec-close", sid, status}` carries the raw
//! exit code, or 128+signal on signal death; exec is allowed exactly where a
//! shell is allowed (--shell-only scoping included, same refusal verdict).

use crate::conn::Conn;
use crate::l2;
use crate::net::Transport;
use anyhow::Result;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Bounds that keep a hostile or buggy initiator from turning an open frame
/// into unbounded allocation. Generous on purpose: real commands (long rsync
/// lines, big --env blobs) must fit comfortably; only absurd frames refuse.
const MAX_ARGV: usize = 128;
const MAX_ARG_LEN: usize = 32 * 1024;
const MAX_ENV_PAIRS: usize = 64;
const MAX_ENV_VAL_LEN: usize = 32 * 1024;
const MAX_NAME_LEN: usize = 128;

/// A validated `exec-open` request: argv[] verbatim plus the execution context.
pub(crate) struct ExecOpen {
    pub(crate) argv: Vec<String>,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) tty: bool,
}

/// Parse and validate an `exec-open` frame. Returns None (caller ignores the
/// frame, like every other malformed open) when argv[] is missing, not an
/// array, empty, over-long, or holds a non-string -- never defaulting or
/// truncating into something executable. Malformed env entries are DROPPED
/// individually (an odd entry must not kill an otherwise good open); a
/// missing/invalid cwd or tty falls back to the default.
pub(crate) fn parse_exec_open(v: &Value) -> Option<ExecOpen> {
    let arr = v.get("argv")?.as_array()?;
    if arr.is_empty() || arr.len() > MAX_ARGV {
        return None;
    }
    let mut argv = Vec::with_capacity(arr.len());
    for a in arr {
        let s = a.as_str()?;
        if s.len() > MAX_ARG_LEN {
            return None;
        }
        argv.push(s.to_string());
    }
    let cwd = v
        .get("cwd")
        .and_then(|c| c.as_str())
        .filter(|c| !c.is_empty() && c.len() <= 4096)
        .map(PathBuf::from);
    let mut env = Vec::new();
    if let Some(obj) = v.get("env").and_then(|e| e.as_array()) {
        for pair in obj.iter().take(MAX_ENV_PAIRS + 1) {
            let Some(s) = pair.as_str() else { continue };
            let Some((k, val)) = s.split_once('=') else {
                continue;
            };
            if k.is_empty()
                || k.len() > MAX_NAME_LEN
                || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || val.len() > MAX_ENV_VAL_LEN
            {
                continue;
            }
            env.push((k.to_string(), val.to_string()));
            if env.len() >= MAX_ENV_PAIRS {
                break;
            }
        }
    }
    let tty = v.get("tty").and_then(|t| t.as_bool()).unwrap_or(false);
    Some(ExecOpen {
        argv,
        cwd,
        env,
        tty,
    })
}

/// Resolve `program` the way the DAEMON would: an absolute or relative path
/// (anything containing a separator) is used as-is; a bare name is looked up
/// in the daemon process's own PATH. Returns None when unresolvable, so the
/// caller refuses instead of spawning something surprising. Must run BEFORE
/// any env_clear, which removes PATH from the child's environment.
pub(crate) fn resolve_in_path(program: &str) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    if program.contains('/') || program.contains('\\') {
        return Some(PathBuf::from(program));
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.is_file()
        && p.metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &std::path::Path) -> bool {
    p.is_file()
}

/// Pure exit-status mapping, split out so it is unit-testable without spawning:
/// a clean exit keeps its raw code, signal death becomes 128+signal (the shell
/// convention: 137 SIGKILL, 143 SIGTERM), and no information at all becomes
/// None -- in which case the close payload OMITS status rather than inventing
/// a code, because the contract forbids rendering that as success.
pub(crate) fn status_code(code: Option<i32>, signal: Option<i32>) -> Option<i32> {
    match (code, signal) {
        (Some(c), _) => Some(c),
        (None, Some(s)) => Some(128 + s),
        (None, None) => None,
    }
}

/// Extract the reportable status from a waited child.
pub(crate) fn exit_status_code(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status_code(status.code(), status.signal())
    }
    #[cfg(not(unix))]
    {
        status_code(status.code(), None)
    }
}

/// The shell-gate DECISION, factored pure so the matrix is unit-testable: None
/// for the capability layer means shadow mode (legacy stands in); Some means
/// authoritative (the cap verdict decides). Mirrors the pty-open tiers exactly
/// so exec can never be MORE permissive than a shell.
pub(crate) fn gate_decision(
    trusted: bool,
    legacy_ok: bool,
    cap_allowed: Option<bool>,
) -> Result<(), &'static str> {
    if !trusted {
        return Err("denied");
    }
    match cap_allowed {
        Some(true) => Ok(()),
        Some(false) => Err("shell capability not granted"),
        None => {
            if legacy_ok {
                Ok(())
            } else {
                Err("shell capability not granted")
            }
        }
    }
}

/// Build the child's environment: env_clear PLUS the allowlist. TERM, LANG and
/// LC_* pass through from the daemon's own environment; explicit `--env` pairs
/// are layered on top (explicit wins on collision). Everything else -- notably
/// secrets, tokens, and proxy config -- stays on the daemon side of the link.
fn build_env(explicit: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in std::env::vars_os() {
        let Some(ks) = k.to_str() else { continue };
        if ks == "TERM" || ks == "LANG" || ks.starts_with("LC_") {
            if let Some(vs) = v.to_str() {
                out.push((ks.to_string(), vs.to_string()));
            }
        }
    }
    for (k, v) in explicit {
        if let Some(slot) = out.iter_mut().find(|(ek, _)| ek == k) {
            slot.1 = v.clone();
        } else {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

async fn send_frames_chunked(t: &Arc<dyn Transport>, sid: u32, data: &[u8]) -> Result<()> {
    let cap = t.max_payload().max(1);
    for chunk in data.chunks(cap) {
        t.send_frame(sid, 0, chunk)
            .await
            .map_err(|_| anyhow::anyhow!("send frame failed"))?;
    }
    Ok(())
}

/// Authorize an exec open: the shell gate, evaluated exactly like pty-open (the
/// same inputs, the same tiers, the same refusal reasons). Returns the label
/// for user-visible messages on allow, or the wire refusal reason on deny.
/// Side-effecting tells (ui::say, enqueue) stay with the caller, next to the
/// send_control that carries the verdict -- same split as the pty-open arm.
pub(crate) async fn authorize_exec(
    conn: &mut Conn,
    pid: &str,
    shell_policy: &crate::ShellPolicy,
) -> Result<String, String> {
    let trusted = conn.link(pid).map(|l| l.trusted).unwrap_or(false);
    let dev = conn.link(pid).and_then(|l| l.verified_name.clone());
    let legacy_ok = trusted
        && dev
            .as_deref()
            .map(|n| {
                !crate::device_capability_denied(n, "shell")
                    && (shell_policy.auto_allows(n) || crate::device_allows(n, "shell"))
            })
            .unwrap_or(false);
    // Capability layer evaluated unconditionally (shadow samples the
    // legacy-allowed population); legacy stands in shadow, cap gates under
    // FILAMENT_CAP_AUTHORITATIVE -- the same block pty-open runs.
    let az = crate::peer_authz(conn, pid);
    let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
    let outcome = crate::capability::cap_authorize(
        &crate::settings::config_dir(),
        "self",
        crate::capability::CAP_SHELL,
        idev,
        iusr,
        ak_caps,
    );
    let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
        &crate::settings::config_dir(),
        "self",
        crate::capability::CAP_SHELL,
        idev,
        iusr,
        ak_caps,
    );
    let granted = crate::capability::cap_gate_effective(
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
    );
    let cap_allowed = if crate::capability::cap_authoritative() {
        Some(granted.allowed())
    } else {
        None
    };
    match gate_decision(trusted, legacy_ok, cap_allowed) {
        Ok(()) => Ok(dev.unwrap_or_else(|| pid.to_string())),
        Err(_) => Err(granted
            .deny_reason("shell capability not granted")
            .to_string()),
    }
}

/// Serve one accepted exec open: spawn argv[] directly (NO shell, NO login
/// shell -- that path does not exist here), pump stdout and stderr to their
/// separate stream channels, feed stdin from the registered pipe, and on child
/// exit send the exec-close payload and clean up. One-shot by design: unlike a
/// PTY session there is nothing persistent, so there is nothing to reattach.
pub(crate) async fn serve_exec(
    t: Arc<dyn Transport>,
    mux: Arc<l2::Mux>,
    sid: u32,
    err_sid: u32,
    req: ExecOpen,
    stdin_rx: mpsc::Receiver<Option<bytes::Bytes>>,
) {
    let program = match resolve_in_path(&req.argv[0]) {
        Some(p) => p,
        None => {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "argv[0] not found on daemon PATH" }))
                .await;
            return;
        }
    };
    // tty/pty is a later slice: refuse loudly rather than silently serving
    // pipes to an initiator that is showing a terminal (wrong rendering, and
    // the user would blame the remote command, not the missing pty).
    if req.tty {
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "tty not supported in this build" }))
            .await;
        return;
    }
    let cwd = req.cwd.unwrap_or_else(crate::platform::Paths::home_dir);
    if !cwd.is_dir() {
        // Fail closed: a requested directory that does not exist refuses
        // rather than silently running somewhere else.
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "cwd does not exist" }))
            .await;
        return;
    }
    let mut child = match tokio::process::Command::new(&program)
        .args(&req.argv[1..])
        .current_dir(&cwd)
        .env_clear()
        .envs(build_env(&req.env))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            let _ = t
                .send_control(
                    &json!({ "type": "l2-close", "sid": sid, "err": format!("spawn failed: {e}") }),
                )
                .await;
            return;
        }
    };
    let _ = t
        .send_control(&json!({ "type": "exec-open-ack", "sid": sid, "out": sid, "err": err_sid }))
        .await;
    let mut stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no stdout pipe" }))
                .await;
            return;
        }
    };
    let mut stderr = match child.stderr.take() {
        Some(s) => s,
        None => {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no stderr pipe" }))
                .await;
            return;
        }
    };
    let mut stdin = match child.stdin.take() {
        Some(s) => s,
        None => {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no stdin pipe" }))
                .await;
            return;
        }
    };
    let mut stdin_rx = stdin_rx;
    let t_out = t.clone();
    let out_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send_frames_chunked(&t_out, sid, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let t_err = t.clone();
    let err_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send_frames_chunked(&t_err, err_sid, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    // stdin: chunks in, EOF shuts the child's write-half (it may still produce
    // output -- EOF is non-terminal, same rule as the pty pumps). Channel
    // death (link gone) kills the child: nobody is left to report to, and an
    // orphaned child outliving its link is a resource leak with a trust tail.
    loop {
        tokio::select! {
            status = child.wait() => {
                let _ = out_task.await;
                let _ = err_task.await;
                let mut close = json!({ "type": "exec-close", "sid": sid });
                if let Ok(status) = status {
                    if let Some(code) = exit_status_code(&status) {
                        close["status"] = json!(code);
                    }
                }
                let _ = t.send_control(&close).await;
                mux.drop_stream(sid).await;
                mux.drop_stream(err_sid).await;
                return;
            }
            chunk = stdin_rx.recv() => {
                // on_frame maps a real empty payload to inner None (stdin
                // EOF) and reserves Some(empty) as a liveness marker, so:
                // inner None shuts the child's write-half but keeps waiting
                // for its output and exit -- EOF is non-terminal, same rule
                // as the pty pumps. Outer None is channel death (link gone):
                // kill the child rather than orphaning it with a trust tail
                // past its link's death.
                match chunk {
                    Some(Some(bytes)) => {
                        if stdin.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    Some(None) => {
                        let _ = stdin.shutdown().await;
                    }
                    None => {
                        let _ = child.kill().await;
                        mux.drop_stream(sid).await;
                        mux.drop_stream(err_sid).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Handle one `exec-open` frame past the l2_enabled guard: validate, gate,
/// register, ack, serve. Sends its own replies (ack/close/deny) and returns;
/// the hook arm only looks up the transport and continues.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_exec_open(
    conn: &mut Conn,
    pid: &str,
    t: Arc<dyn Transport>,
    mux: Arc<l2::Mux>,
    v: &Value,
    shell_policy: &crate::ShellPolicy,
) {
    let Some(req) = parse_exec_open(v) else {
        return;
    };
    let Some(sid) = l2::wire_sid(v) else {
        return;
    };
    if !l2::is_l2_sid(sid) {
        return;
    }
    if let Err(reason) = authorize_exec(conn, pid, shell_policy).await {
        crate::ui::say(&format!("l2: exec refused: {reason}"));
        crate::enqueue_if_requestable(&pid.to_string(), "shell");
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": reason }))
            .await;
        return;
    };
    // H-1 (DoS): refuse over the per-link stream cap BEFORE spawning, same as
    // pty-open -- a hostile paired device must not flood exec opens.
    if mux.at_stream_cap().await {
        crate::ui::say("l2: exec refused: too many streams on this link");
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }))
            .await;
        return;
    }
    // Collision-safe: refuse (don't displace) an already-live sid.
    let Some(stdin_rx) = mux.register_stream(sid).await else {
        crate::ui::say(&format!("l2: exec refused: sid {sid:#x} in use"));
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }))
            .await;
        return;
    };
    // Second channel for stderr, named in the ack. Allocated from the
    // answerer-role sid space, so it cannot collide with initiator sids by
    // construction (same argument as alloc_sid's own docs).
    let err_sid = mux.alloc_sid();
    serve_exec(t, mux, sid, err_sid, req, stdin_rx).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_argv_exact() {
        let v = json!({
            "type": "exec-open", "sid": 1,
            "argv": ["rsync", "-a", "my dir/with spaces", "--exclude='*.tmp'", "*.log"],
            "cwd": "/tmp", "env": ["FOO=bar"], "tty": false,
        });
        let req = parse_exec_open(&v).expect("valid frame parses");
        assert_eq!(
            req.argv,
            vec![
                "rsync",
                "-a",
                "my dir/with spaces",
                "--exclude='*.tmp'",
                "*.log"
            ]
        );
        assert_eq!(req.cwd, Some(PathBuf::from("/tmp")));
        assert_eq!(req.env, vec![("FOO".to_string(), "bar".to_string())]);
        assert!(!req.tty);
    }

    #[test]
    fn parse_rejects_bad_argv() {
        for bad in [
            json!({"type": "exec-open", "sid": 1}),
            json!({"type": "exec-open", "sid": 1, "argv": []}),
            json!({"type": "exec-open", "sid": 1, "argv": "ls -la"}),
            json!({"type": "exec-open", "sid": 1, "argv": [42]}),
        ] {
            assert!(parse_exec_open(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn parse_drops_malformed_env_and_applies_defaults() {
        let v = json!({
            "type": "exec-open", "sid": 1,
            "argv": ["true"],
            "env": ["OK=1", "NOEQUALS", "=nokey", "BAD KEY=x"],
        });
        let req = parse_exec_open(&v).expect("parses");
        assert_eq!(req.env, vec![("OK".to_string(), "1".to_string())]);
        assert!(req.cwd.is_none());
        assert!(!req.tty);
    }

    #[test]
    fn parse_rejects_absurd_frames() {
        let many: Vec<Value> = (0..200).map(|i| json!(format!("a{i}"))).collect();
        assert!(parse_exec_open(&json!({"argv": many})).is_none());
        let big = "x".repeat(40 * 1024);
        assert!(parse_exec_open(&json!({"argv": ["ok", big]})).is_none());
    }

    #[test]
    fn status_mapping_is_shell_convention() {
        assert_eq!(status_code(Some(0), None), Some(0));
        assert_eq!(status_code(Some(1), None), Some(1));
        assert_eq!(status_code(None, Some(9)), Some(137));
        assert_eq!(status_code(None, Some(15)), Some(143));
        assert_eq!(status_code(None, None), None);
    }

    #[test]
    fn gate_matrix_matches_shell_tiers() {
        // untrusted is always denied, regardless of anything else
        assert!(gate_decision(false, true, None).is_err());
        assert!(gate_decision(false, false, Some(true)).is_err());
        // shadow: legacy decides
        assert!(gate_decision(true, true, None).is_ok());
        assert!(gate_decision(true, false, None).is_err());
        // authoritative: cap decides
        assert!(gate_decision(true, false, Some(true)).is_ok());
        assert!(gate_decision(true, true, Some(false)).is_err());
    }

    #[test]
    fn resolve_absolute_passthrough_and_missing() {
        assert_eq!(
            resolve_in_path("/bin/true"),
            Some(PathBuf::from("/bin/true"))
        );
        assert_eq!(
            resolve_in_path("definitely-not-a-filament-binary-xyz"),
            None
        );
        assert_eq!(resolve_in_path(""), None);
    }

    #[cfg(unix)]
    #[test]
    fn live_spawn_reports_real_exit_code() {
        let Some(sh) = resolve_in_path("sh") else {
            return;
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let status = rt.block_on(async {
            tokio::process::Command::new(&sh)
                .arg("-c")
                .arg("exit 41")
                .status()
                .await
                .unwrap()
        });
        assert_eq!(exit_status_code(&status), Some(41));
    }
}
