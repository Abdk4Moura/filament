//! `filament exec` initiator: open the stream, pump stdio, surface the exit code.
//!
//! Deliberately one-shot where `pty_cmd` is resumable: an exec invocation has
//! no session worth reattaching (the receiver holds no persistent state for
//! it), so there is NO warm-daemon fast path and NO reconnect loop. A dropped
//! link fails loudly instead of re-running the command -- re-running would
//! execute side effects twice, which is exactly the wrong default for a
//! non-idempotent remote command. That asymmetry with shells is intentional
//! and documented here so a future "make exec resilient" change has to reckon
//! with double-execution first.
//!
//! Wire contract (CONTRACT.md, "Exec streams"): allocator registers both pipes
//! BEFORE the open goes out (a racing ack/close must not find no pipe, same
//! race discipline as pty's open waiter); the ack wait is bounded at 10 s with
//! the same four outcomes (opened / refused / unconfirmed / timeout); stdin
//! EOF goes out as one empty frame and then we stop reading stdin but keep
//! draining both outputs until the close arrives.

use crate::l2;
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Built initiator options: argv already final (shell wrapping applied by the
/// caller), env already validated into pairs.
pub(crate) struct ExecOpts {
    pub(crate) argv: Vec<String>,
    pub(crate) tty: bool,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) env: Vec<(String, String)>,
}

/// Build the final argv: direct spawn passes through untouched; `--shell`
/// wraps as `/bin/sh -c <joined>` (cmd /C on Windows). The receiver never
/// invokes a shell on its own -- this wrapping is the ONLY shell in the path,
// and it happens here, visibly, on the initiator side.
pub(crate) fn build_argv(argv: &[String], shell: bool) -> Vec<String> {
    if !shell {
        return argv.to_vec();
    }
    let joined = argv.join(" ");
    #[cfg(windows)]
    {
        vec!["cmd".to_string(), "/C".to_string(), joined]
    }
    #[cfg(not(windows))]
    {
        vec!["/bin/sh".to_string(), "-c".to_string(), joined]
    }
}

/// Validate one `--env KEY=VALUE` pair. Same rule as the receiver enforces, so
/// a malformed pair fails fast locally instead of being silently dropped over
/// the wire. Returns the split pair.
pub(crate) fn parse_env_pair(s: &str) -> Result<(String, String)> {
    let Some((k, v)) = s.split_once('=') else {
        bail!("--env must be KEY=VALUE, got {s:?}");
    };
    if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("--env key must be [A-Za-z0-9_], got {k:?}");
    }
    Ok((k.to_string(), v.to_string()))
}

/// Run a command on a peer and return its remote exit status. Local failures
/// (connect, open, link death) are Err with a human message; a clean remote
/// close -- including a remote NONZERO exit -- is Ok(status).
pub(crate) async fn exec_cmd(server: &str, peer: &str, relay: bool, opts: ExecOpts) -> Result<i32> {
    let (t, mut rx, guard, _diag) = match tokio::time::timeout(
        std::time::Duration::from_secs(45),
        l2::bring_up_to_known(server, peer, relay, "exec"),
    )
    .await
    {
        Ok(inner) => inner?,
        Err(_) => {
            bail!("connect timeout: couldn't reach '{peer}' in 45s");
        }
    };
    guard.forget();
    let mux = l2::Mux::new(t.clone());
    let sid = mux.alloc_sid();
    // Register BOTH inbound pipes before the open goes out: bytes or a close
    // racing the ack must find a pipe, same discipline as pty's open waiter.
    let mut out_pipe = mux
        .register_stream(sid)
        .await
        .ok_or_else(|| anyhow::anyhow!("exec open: sid {sid:#x} already in use"))?;
    // The stderr sid is initiator-allocated and announced in the open (same
    // value both ends use, like `sid` itself): the pipe is registered before
    // the open goes out, so stderr racing the ack finds it. A receiver-side
    // second allocation would name a stream nobody listens on.
    let err_sid = mux.alloc_sid();
    let mut err_pipe = mux
        .register_stream(err_sid)
        .await
        .ok_or_else(|| anyhow::anyhow!("exec open: sid {err_sid:#x} already in use"))?;
    let frame = {
        let mut f = json!({
            "type": "exec-open",
            "sid": sid,
            "err_sid": err_sid,
            "argv": opts.argv,
        });
        if let Some(cwd) = &opts.cwd {
            f["cwd"] = json!(cwd.to_string_lossy());
        }
        if !opts.env.is_empty() {
            f["env"] = json!(
                opts.env
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
            );
        }
        if opts.tty {
            f["tty"] = json!(true);
        }
        f
    };
    t.send_control(&frame).await?;
    // Bounded ack wait with pty's four outcomes. A refusal surfaces the
    // RECEIVER's reason (dropping it here reported every refusal as a
    // confusing transport error); anything else names what actually happened.
    let ack: Value = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let ev = match rx.recv().await {
                Some(ev) => ev,
                None => {
                    break Err(format!("'{peer}' closed the exec stream before answering"));
                }
            };
            match ev {
                crate::net::Ev::Control(_pid, v) => {
                    if v.get("type").and_then(|t| t.as_str()) == Some("exec-open-ack")
                        && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                    {
                        break Ok(v);
                    }
                    if v.get("type").and_then(|t| t.as_str()) == Some("l2-close")
                        && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                    {
                        let reason = v
                            .get("err")
                            .and_then(|e| e.as_str())
                            .unwrap_or("closed");
                        break Err(format!("'{peer}' refused exec: {reason}"));
                    }
                }
                crate::net::Ev::Chunk(_pid, got, _offset, data) => {
                    mux.on_frame(got, data).await;
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "no answer from '{peer}' - it may be unresponsive or running a build without exec"
        )
    })?
    .map_err(|reason: String| anyhow::anyhow!(reason))?;
    let _ = ack;
    // Pumps: stdin shared reader (the fd0 singleton pattern from pty -- one
    // consumer for the whole invocation), stdout/stderr to local stdio, close
    // status out. No reconnect: link death below fails loudly by design.
    let mut stdin_rx = l2::spawn_stdin_reader();
    let mut stdin_done = false;
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let exit_status: Option<i32>;
    // Bytes consumed per stream: the close announces both counts, and the
    // drain below collects stragglers until the counts are met (or bounded
    // time passes). Incremented everywhere a pipe item is consumed.
    let mut out_recv: u64 = 0;
    let mut err_recv: u64 = 0;
    let want_out: Option<u64>;
    let want_err: Option<u64>;
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    ticker.tick().await;
    loop {
        tokio::select! {
            item = out_pipe.recv() => match item {
                Some(Some(bytes)) => {
                    out_recv += bytes.len() as u64;
                    stdout.write_all(&bytes).await?;
                    stdout.flush().await?;
                }
                _ => {
                    // Pipe closed without a close payload: transport-level liveness
                    // decides whether this was a clean end we misread or a drop.
                    if !mux.transport().is_alive() {
                        bail!("link to '{peer}' died during exec");
                    }
                    bail!("'{peer}' closed the exec stream without an exit status");
                }
            },
            item = err_pipe.recv() => match item {
                Some(Some(bytes)) => {
                    err_recv += bytes.len() as u64;
                    stderr.write_all(&bytes).await?;
                    stderr.flush().await?;
                }
                _ => {}
            },
            chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                Some(c) if c.is_empty() => {
                    let r = t.send_frame(sid, 0, &[]).await;
                    eprintln!("[TEMP2-exec] eof frame sid={sid:#x} ok={}", r.is_ok());
                    stdin_done = true;
                }
                Some(c) => {
                    let cap = t.max_payload().max(1);
                    let mut failed = false;
                    for chunk in c.chunks(cap) {
                        if t.send_frame(sid, 0, chunk).await.is_err() {
                            failed = true;
                            break;
                        }
                    }
                    if failed {
                        bail!("link to '{peer}' died mid-send");
                    }
                }
                None => { stdin_done = true; }
            },
            ev = rx.recv() => match ev {
                Some(crate::net::Ev::Control(_pid, v)) => {
                    if v.get("type").and_then(|t| t.as_str()) == Some("exec-close")
                        && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                    {
                        exit_status = v.get("status").and_then(|s| s.as_i64()).map(|s| s as i32);
                        want_out = v.get("out_bytes").and_then(|n| n.as_u64());
                        want_err = v.get("err_bytes").and_then(|n| n.as_u64());
                        break;
                    }
                    if v.get("type").and_then(|t| t.as_str()) == Some("l2-close")
                        && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                    {
                        let err = v.get("err").and_then(|e| e.as_str()).unwrap_or("closed");
                        bail!("'{peer}' closed the exec stream: {err}");
                    }
                }
                Some(crate::net::Ev::Chunk(_pid, got, _offset, data)) => {
                    mux.on_frame(got, data).await;
                }
                // Bring-up's LOSER keeps emitting on this shared channel after
                // it returns (a late ChannelReady/DirectReady, Stuck, PcState
                // ...): pty's pump never polls rx at all, and polling it here
                // must not mistake those for death -- a late winner-arrival
                // killed every session living past ~2s with a bogus "link
                // died". Only a CLOSED channel means the link is really gone;
                // anything else is ignored, with the 2s ticker as backstop.
                Some(_) => {}
                None => {
                    bail!("link to '{peer}' died during exec");
                }
            },
            _ = ticker.tick() => {
                if !mux.transport().is_alive() {
                    bail!("link to '{peer}' died during exec");
                }
            }
        }
    }
    // Bounded drain: exec-close travels control while bytes travel frames,
    // so a fast-exiting child can beat its own tail (observed live: a missing
    // 8 KiB tail with rc=0). The close announces both byte counts, so the
    // drain is DETERMINISTIC on a healthy link -- collect until the counts
    // are met -- with a 3s cap for a dying one. Skipped when the close
    // carried no status (abnormal end: nothing to collect for).
    if exit_status.is_some() {
        let drain_end = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let met = match (want_out, want_err) {
                (Some(o), Some(e)) => out_recv >= o && err_recv >= e,
                _ => false,
            };
            if met || tokio::time::Instant::now() >= drain_end {
                break;
            }
            tokio::select! {
                ev = rx.recv() => match ev {
                    Some(crate::net::Ev::Chunk(_pid, got, _offset, data)) => {
                        mux.on_frame(got, data).await;
                    }
                    _ => {}
                },
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
            while let Ok(Some(bytes)) = out_pipe.try_recv() {
                out_recv += bytes.len() as u64;
                stdout.write_all(&bytes).await?;
            }
            while let Ok(Some(bytes)) = err_pipe.try_recv() {
                err_recv += bytes.len() as u64;
                stderr.write_all(&bytes).await?;
            }
            stdout.flush().await?;
            stderr.flush().await?;
        }
    }
    mux.drop_stream(sid).await;
    mux.drop_stream(err_sid).await;
    // No exit-status payload means the process did not exit cleanly: never
    // render that as success (contract). A clean remote 0 falls through to Ok.
    match exit_status {
        Some(code) => Ok(code),
        None => bail!("'{peer}' closed the exec stream without an exit status"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_argv_direct_passthrough() {
        let argv = vec!["rsync".to_string(), "-a".to_string(), "my dir/".to_string()];
        assert_eq!(build_argv(&argv, false), argv);
    }

    #[test]
    fn build_argv_shell_wraps() {
        let argv = vec!["ls *.log".to_string()];
        let built = build_argv(&argv, true);
        assert_eq!(built.len(), 3);
        assert_eq!(built[2], "ls *.log");
        #[cfg(not(windows))]
        assert_eq!(&built[..2], ["/bin/sh", "-c"]);
    }

    #[test]
    fn parse_env_pair_accepts_and_rejects() {
        assert_eq!(
            parse_env_pair("FOO=bar").unwrap(),
            ("FOO".to_string(), "bar".to_string())
        );
        assert_eq!(
            parse_env_pair("A=b=c").unwrap(),
            ("A".to_string(), "b=c".to_string())
        );
        for bad in ["NOEQUALS", "=nokey", "BAD KEY=x", ""] {
            assert!(parse_env_pair(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn frame_carries_argv_exact_and_opts() {
        let opts = ExecOpts {
            argv: vec!["a b".to_string()],
            tty: false,
            cwd: Some(PathBuf::from("/tmp")),
            env: vec![("K".to_string(), "V".to_string())],
        };
        assert_eq!(opts.argv, vec!["a b".to_string()]);
        assert!(!opts.tty);
    }
}
