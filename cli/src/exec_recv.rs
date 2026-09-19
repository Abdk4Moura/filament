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
    /// Initiator-allocated stderr sid, announced in the open so BOTH ends use
    /// one value (same discipline as `sid` itself -- the initiator registers
    /// the pipe before the open goes out, so stderr racing the ack finds it).
    pub(crate) err_sid: u32,
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
    // Fail closed on a missing/forged stderr sid: defaulting to 0 would alias
    // a live stream, and allocating a second value the initiator never
    // listens on silently drops stderr (both observed live). Same
    // no-truncation discipline as `wire_sid`, plus the L2-half check.
    let err_sid = u32::try_from(v.get("err_sid")?.as_u64()?).ok()?;
    if !crate::l2::is_l2_sid(err_sid) {
        return None;
    }
    Some(ExecOpen {
        argv,
        cwd,
        env,
        tty,
        err_sid,
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
        if let Some(p) = resolve_bare_in(&dir, program) {
            return Some(p);
        }
    }
    None
}

/// Candidate spellings of a bare program name in one directory: the name
/// itself, plus (Windows only) each PATHEXT suffix in order. Pure so the
/// ordering is unit-testable on every platform; only used on Windows
/// (allowed dead elsewhere so the unix build stays warning-neutral).
#[cfg_attr(not(windows), allow(dead_code))]
fn pathext_candidates(program: &str, exts: &str) -> Vec<String> {
    let mut out = vec![program.to_string()];
    for ext in exts.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        out.push(format!("{program}{ext}"));
    }
    out
}

/// Resolve a bare name inside one PATH directory. Unix: the name itself.
/// Windows: the name itself, then PATHEXT suffixes (.EXE etc.) so `rsync`
/// finds `rsync.exe` -- still a direct spawn of the resolved path, never a
/// shell lookup, so argv exactness is unaffected.
#[cfg(windows)]
fn resolve_bare_in(dir: &std::path::Path, program: &str) -> Option<PathBuf> {
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    for name in pathext_candidates(program, &exts) {
        let candidate = dir.join(&name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Resolve a bare name inside one PATH directory (non-Windows): the name
/// itself, unchanged from the original loop.
#[cfg(not(windows))]
fn resolve_bare_in(dir: &std::path::Path, program: &str) -> Option<PathBuf> {
    let candidate = dir.join(program);
    if is_executable(&candidate) {
        return Some(candidate);
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

/// Authorize an exec open through the shared shell gate (same function, same
/// inputs as pty-open; no exec-local decision logic). Returns the label for
/// user-visible messages on allow, or the wire refusal reason on deny.
/// Side-effecting tells (ui::say, enqueue) stay with the caller, next to the
/// send_control that carries the verdict -- same split as the pty-open arm.
pub(crate) async fn authorize_exec(
    conn: &mut Conn,
    pid: &str,
    shell_policy: &crate::ShellPolicy,
) -> Result<String, String> {
    let (dev, inputs) = crate::shell_gate::gather_shell_gate_inputs(
        conn,
        pid,
        shell_policy,
        crate::capability::CAP_SHELL,
    );
    crate::shell_gate::exec_gate_decision(&inputs)
        .map(|()| dev.unwrap_or_else(|| pid.to_string()))
        .map_err(|r| r.unwrap_or_else(|| "shell capability not granted".to_string()))
}

/// Serve one accepted exec open: spawn argv[] directly (NO shell, NO login
/// shell -- that path does not exist here), pump stdout and stderr to their
/// separate stream channels, feed stdin from the registered pipe, and on child
/// exit send the exec-close payload and clean up. One-shot by design: unlike a
/// PTY session there is nothing persistent, so there is nothing to reattach.
/// Session-scoped authz snapshot for mid-session revoke re-checks: the
/// verified device name (None when unverified, meaning nothing store-bound
/// to re-check), its identity device key for cert-revoke checks, and whether
/// the serving policy auto-allows it (static for the session). Resolved once
/// in handle_exec_open; the ticker below re-reads the STORE each tick.
pub(crate) struct ExecSessionAuthz {
    pub(crate) dev_name: Option<String>,
    pub(crate) idev: Option<[u8; 32]>,
    pub(crate) policy_allows: bool,
    /// True when this session was admitted via its enrolment ceiling rather
    /// than an explicit grant: a narrowed ceiling must end it on the next
    /// tick, exactly like a revocation.
    pub(crate) admitted_via_ceiling: bool,
}

pub(crate) async fn serve_exec(
    t: Arc<dyn Transport>,
    mux: Arc<l2::Mux>,
    sid: u32,
    req: ExecOpen,
    stdin_rx: mpsc::Receiver<Option<bytes::Bytes>>,
    authz: ExecSessionAuthz,
) {
    // stderr rides the initiator-allocated `err_sid` from the open frame
    // (same value the initiator registered before sending): allocating a
    // second sid here would name a stream nobody listens on.
    let err_sid = req.err_sid;
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
        Some(s) => Some(s),
        None => {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no stdin pipe" }))
                .await;
            return;
        }
    };
    let mut stdin_rx = stdin_rx;
    // Pump tasks report bytes SENT: the close carries both counts so the
    // initiator can drain stragglers deterministically (a fast-exiting child
    // can beat its own tail frames -- close travels control, bytes travel
    // frames -- and breaking on close would truncate output, observed live
    // as a missing 8 KiB tail with rc=0).
    let t_out = t.clone();
    let out_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut sent: u64 = 0;
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send_frames_chunked(&t_out, sid, &buf[..n]).await.is_err() {
                        break;
                    }
                    sent += n as u64;
                }
            }
        }
        sent
    });
    let t_err = t.clone();
    let err_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut sent: u64 = 0;
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
                    sent += n as u64;
                }
            }
        }
        sent
    });
    // Revoke re-check (pty precedent): a dedicated ticker at the shared
    // interval re-asks the gate while the child runs. A peer revoked
    // mid-session -- certificate OR shell grant -- loses the live exec.
    let mut revoke_ticker = tokio::time::interval(crate::revoke_recheck_interval());
    revoke_ticker.tick().await; // consume the immediate first tick
    // stdin: chunks in, EOF shuts the child's write-half (it may still produce
    // output -- EOF is non-terminal, same rule as the pty pumps). Channel
    // death (link gone) kills the child: nobody is left to report to, and an
    // orphaned child outliving its link is a resource leak with a trust tail.
    loop {
        tokio::select! {
            status = child.wait() => {
                let out_bytes = out_task.await.unwrap_or(0);
                let err_bytes = err_task.await.unwrap_or(0);
                let mut close = json!({ "type": "exec-close", "sid": sid, "out_bytes": out_bytes, "err_bytes": err_bytes });
                if let Ok(status) = status {
                    if let Some(code) = exit_status_code(&status) {
                        close["status"] = json!(code);
                    }
                }
                if let Err(e) = t.send_control(&close).await {
                    // The close is the only other way the initiator learns the session finished,
                    // so when it cannot be delivered the streams have to END on the wire instead.
                    // An EMPTY payload is the mux's pipe-end sentinel (`on_frame` maps it to
                    // None), which is the same mechanism stdin EOF uses, and the initiator's
                    // closed-pipe arm reads it as a terminal end without an exit status rather
                    // than waiting forever for a frame that will never be actioned.
                    // A close that never arrives leaves the initiator in a select with nothing
                    // left to select: this file already documents that hazard class a few lines
                    // above, for a different early break ("hanging the initiator"). The old
                    // `let _ =` made a LOST close indistinguishable from a delivered one, so the
                    // acceptor believed it had reported the exit while the initiator never heard
                    // it and the only artifact was silence. Say so instead.
                    crate::ui::say(&format!(
                        "filament: could not deliver exec-close for sid {sid}: {e}; the initiator will not learn the exit status"
                    ));
                }
                // THE END OF THE STREAM IS SIGNALLED UNCONDITIONALLY, and that is the correction
                // this fix carries: the sentinel was inside the error branch, so it fired only
                // when the close send FAILED. The observed run is the case where the send
                // returns Ok and the frame is still not acted on downstream, which left the
                // initiator waiting with nothing to observe -- the `fs.out`/`fs.done` evidence
                // from the gate, and the reason commit 5 did not remove the hang.
                //
                // An EMPTY payload is the mux's pipe-end convention (`on_frame` maps it to
                // None, and `exec_send` already uses it for stdin EOF), so these two frames are
                // how a stream's end reaches its reader whether or not the status frame made
                // it. Sent after the close attempt so the normal path still exits on the STATUS.
                let _ = t.send_frame(sid, 0, &[]).await;
                let _ = t.send_frame(err_sid, 0, &[]).await;
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
                        if let Some(s) = stdin.as_mut() {
                            if s.write_all(&bytes).await.is_err() {
                                // Write error (child gone or pipe broken): treat
                                // as EOF -- drop the write end and CONTINUE.
                                // break here would skip child.wait() AND the
                                // exec-close, hanging the initiator (yes |
                                // exec -- head -1). Only child.wait() (exit)
                                // or channel death (link gone) ends the loop.
                                stdin.take();
                            }
                        }
                    }
                    Some(None) => {
                        // EOF: CLOSE (drop) the write end. shutdown() is a
                        // socket operation and silently no-ops on a pipe --
                        // observed live: the daemon still held the write fd
                        // open after shutdown(), the child starved forever
                        // in pipe_wait_readable. EOF stays non-terminal: the
                        // loop keeps waiting for output and exit.
                        stdin.take();
                    }
                    None => {
                        let _ = child.kill().await;
                        mux.drop_stream(sid).await;
                        mux.drop_stream(err_sid).await;
                        return;
                    }
                }
            }
            _ = revoke_ticker.tick() => {
                // Re-ask the gate. Cert revoke is re-read from the store
                // each tick; the shell grant is re-read the same way (the
                // policy half is static per session). Either way the peer
                // loses the live exec: kill the child and close with the
                // revoked reason, so the initiator surfaces nonzero with a
                // reason instead of hanging or rendering a clean exit.
                let cert_gone = crate::cert_revoked_for(authz.idev.as_ref());
                let grant_gone = match authz.dev_name.as_deref() {
                    Some(n) => {
                        crate::device_capability_denied(n, "shell")
                            || !(authz.policy_allows || crate::device_allows(n, "shell"))
                    }
                    None => false,
                };
                // A ceiling narrowed under a ceiling-admitted session ends
                // it (re-read fresh; grant-admitted sessions ignore this).
                let ceiling_gone = authz.admitted_via_ceiling
                    && !crate::identity_state::ceiling_covers_action(
                        authz.idev.as_ref(),
                        crate::capability::CAP_SHELL,
                    );
                // A lapsed deadline (cert expiry, absolute stop, offline
                // budget) ends it too; unresolvable identity is no opinion.
                let lapsed =
                    matches!(crate::identity_state::peer_liveness_alive(authz.idev.as_ref()), Some(false));
                if cert_gone || grant_gone || ceiling_gone || lapsed {
                    crate::ui::critical("exec: peer access revoked, closing live session");
                    let _ = child.kill().await;
                    let _ = t
                        .send_control(&json!({
                            "type": "l2-close",
                            "sid": sid,
                            "err": crate::capability::REVOKED_REASON,
                        }))
                        .await;
                    mux.drop_stream(sid).await;
                    mux.drop_stream(err_sid).await;
                    return;
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
    parked: &mut Vec<crate::recv_cmd::ParkedOpen>,
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
        // Settle-then-evaluate: the verdict above may rest on stale
        // (unproven) identity. Park for re-drive on proof when the deny
        // is attributable to it; otherwise the live verdict stands.
        if crate::recv_cmd::park_on_deny(
            parked,
            conn,
            pid,
            crate::recv_cmd::ParkKind::Exec,
            &t,
            sid,
            v,
            &reason,
        )
        .await
        {
            return;
        }
        crate::ui::say(&format!("l2: exec refused: {reason}"));
        // Enqueue under the verified petname (like pty-open's `who`), never
        // the raw pid: the queue is keyed by name, and "<unverified>" is a
        // no-op by design.
        let who = conn.link(pid).and_then(|l| l.verified_name.clone());
        crate::enqueue_if_requestable(who.as_deref().unwrap_or("<unverified>"), "shell");
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
    // Serve DETACHED: awaiting the session inline would park the daemon's
    // single recv loop for its whole lifetime, so no inbound data frame
    // could ever be dispatched while a session runs (stdin starves, the
    // child never exits, every later open hangs behind the parked loop --
    // observed live as hung stdin sessions wedging the acceptor). The pty
    // path spawns its session pumps for exactly this reason; validation,
    // gating and registration above already ran in-hook, so the detached
    // task owns only owned values from here. The revoke ticker needs the
    // same authz context, resolved once here (re-reads the store per tick).
    let dev_name = conn.link(pid).and_then(|l| l.verified_name.clone());
    let policy_allows = dev_name
        .as_deref()
        .map(|n| shell_policy.auto_allows(n))
        .unwrap_or(false);
    let idev = {
        let az = crate::peer_authz(conn, pid);
        let (idev, _, _, _, _, _) = az.parts();
        idev.copied()
    };
    let covered =
        crate::identity_state::ceiling_covers_action(idev.as_ref(), crate::capability::CAP_SHELL);
    let (_, has_grant_now) = crate::capability::cap_fleet_inputs(
        &crate::settings::config_dir(),
        "self",
        crate::capability::CAP_SHELL,
        idev.as_ref(),
        None,
        None,
    );
    let authz = ExecSessionAuthz {
        dev_name,
        idev,
        policy_allows,
        admitted_via_ceiling: covered && !has_grant_now,
    };
    tokio::spawn(serve_exec(t, mux, sid, req, stdin_rx, authz));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_argv_exact() {
        let v = json!({
            "type": "exec-open", "sid": 1, "err_sid": 2147483649u64,
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
        assert_eq!(req.err_sid, 2147483649);
    }

    #[test]
    fn parse_rejects_missing_or_forged_err_sid() {
        let base = json!({"type": "exec-open", "sid": 1, "argv": ["true"]});
        assert!(parse_exec_open(&base).is_none());
        let mut low = base.clone();
        low["err_sid"] = json!(7u64);
        assert!(parse_exec_open(&low).is_none());
        let mut big = base.clone();
        big["err_sid"] = json!(0x1_8000_0000u64);
        assert!(parse_exec_open(&big).is_none());
        let mut ok = base.clone();
        ok["err_sid"] = json!(2147483649u64);
        assert!(parse_exec_open(&ok).is_some());
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
            "type": "exec-open", "sid": 1, "err_sid": 2147483649u64,
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
    fn pathext_candidates_bare_first_then_suffixes_in_order() {
        assert_eq!(
            pathext_candidates("rsync", ".COM;.EXE;.BAT;.CMD"),
            vec!["rsync", "rsync.COM", "rsync.EXE", "rsync.BAT", "rsync.CMD"]
        );
        assert_eq!(pathext_candidates("rsync", ""), vec!["rsync"]);
        assert_eq!(
            pathext_candidates("run", " .EXE ; ; .BAT "),
            vec!["run", "run.EXE", "run.BAT"]
        );
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
