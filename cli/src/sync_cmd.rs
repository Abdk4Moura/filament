//! `filament sync <local-dir> <device>:<remote-dir>`: rsync-shaped delta
//! transfer between paired devices. The sender walks the tree into a manifest
//! (whole-file sha256 plus per-chunk sha256), the receiver answers with what it
//! lacks, and only those chunks cross. Every landed file is verified by the same
//! whole-file digest `send`/`receive` use (`recv_files::full_hash`) before it is
//! renamed into place, and the receiver admits the stream through the same
//! transfer gate a `file-offer` from a paired device passes (`CAP_TRANSFER`).
//!
//! Wire: one L2 stream, opened like `exec-open`. Both directions carry
//! `[u32 BE len][payload]` records; JSON records steer, raw records carry chunk
//! bytes. The receiver never trusts a path: every relative path is reduced by
//! `safe_relpath` and bounded to its root, which itself must lie inside the
//! daemon's drop directory.
use crate::conn::Conn;
use crate::l2;
use crate::net::{Ev, Transport};
use crate::ui;
use anyhow::{Result, bail};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Delta granularity. Wire frames are cut to the transport's payload underneath.
pub(crate) const SYNC_CHUNK: u64 = 256 * 1024;
const MAX_RECORD: usize = 64 << 20;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Entry {
    pub p: String,
    pub size: u64,
    pub mtime: u64,
    pub full: String,
    pub chunks: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Need {
    pub p: String,
    pub new: bool,
    pub chunks: Vec<u32>,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub(crate) struct Plan {
    pub need: Vec<Need>,
    pub same: Vec<String>,
    pub extra: Vec<String>,
}

/// A relative path that cannot leave its root: no absolute, no `..`, no `.`,
/// no control bytes, no backslash. `None` means refuse.
pub(crate) fn safe_relpath(s: &str) -> Option<PathBuf> {
    if s.is_empty() || s.len() > 4096 || s.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }
    // Textual, not `Path::components()`: that normalizes an interior `.` away,
    // and a path the peer spelled with one is a path we refuse, not tidy.
    let mut out = PathBuf::new();
    for seg in s.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        out.push(seg);
    }
    Some(out)
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whole-file digest and per-chunk digests in one pass.
pub(crate) fn hash_file(path: &Path) -> std::io::Result<(String, Vec<String>)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut whole = Sha256::new();
    let mut chunks = Vec::new();
    let mut buf = vec![0u8; SYNC_CHUNK as usize];
    loop {
        let mut n = 0;
        while n < buf.len() {
            let k = f.read(&mut buf[n..])?;
            if k == 0 {
                break;
            }
            n += k;
        }
        if n == 0 {
            break;
        }
        whole.update(&buf[..n]);
        chunks.push(hex(&Sha256::digest(&buf[..n])));
        if n < buf.len() {
            break;
        }
    }
    Ok((hex(&whole.finalize()), chunks))
}

/// Walk `root` without following symlinks. Returns the manifest (sorted by path)
/// and the entries skipped with a reason (symlinks, non-regular files).
pub(crate) fn walk_manifest(root: &Path) -> Result<(Vec<Entry>, Vec<(String, String)>)> {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for e in std::fs::read_dir(root.join(&rel))? {
            let e = e?;
            let r = rel.join(e.file_name());
            let rs = r.to_string_lossy().into_owned();
            let md = e.metadata()?; // does not follow symlinks
            if md.file_type().is_symlink() {
                skipped.push((rs, "symlink".into()));
            } else if md.is_dir() {
                stack.push(r);
            } else if !md.is_file() {
                skipped.push((rs, "not a regular file".into()));
            } else if safe_relpath(&rs).is_none() || !crate::path_within(root, &root.join(&r)) {
                skipped.push((rs, "path escapes the directory".into()));
            } else {
                let (full, chunks) = hash_file(&e.path())?;
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                out.push(Entry { p: rs, size: md.len(), mtime, full, chunks });
            }
        }
    }
    out.sort_by(|a, b| a.p.cmp(&b.p));
    skipped.sort();
    Ok((out, skipped))
}

/// What `remote` lacks relative to `local`: per differing file the chunk indices
/// whose digest differs or that the remote does not have; equal digests are
/// `same`; remote files absent from `local` are `extra`.
pub(crate) fn diff(local: &[Entry], remote: &[Entry]) -> Plan {
    let have: BTreeMap<&str, &Entry> = remote.iter().map(|e| (e.p.as_str(), e)).collect();
    let mut plan = Plan::default();
    for l in local {
        match have.get(l.p.as_str()) {
            Some(r) if r.full == l.full && r.size == l.size => plan.same.push(l.p.clone()),
            other => {
                let rc: &[String] = other.map(|r| r.chunks.as_slice()).unwrap_or(&[]);
                let chunks = (l.chunks.iter().enumerate())
                    .filter(|(i, h)| rc.get(*i) != Some(h))
                    .map(|(i, _)| i as u32)
                    .collect();
                plan.need.push(Need { p: l.p.clone(), new: other.is_none(), chunks });
            }
        }
    }
    let want: BTreeSet<&str> = local.iter().map(|e| e.p.as_str()).collect();
    plan.extra = (remote.iter().filter(|e| !want.contains(e.p.as_str())))
        .map(|e| e.p.clone())
        .collect();
    plan
}

// ------------------------------------------------------------- records ------

#[derive(Default)]
struct Records(Vec<u8>);

impl Records {
    fn next(&mut self) -> Result<Option<Vec<u8>>> {
        if self.0.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as usize;
        if n > MAX_RECORD {
            bail!("sync record too large ({n} bytes)");
        }
        if self.0.len() < 4 + n {
            return Ok(None);
        }
        let rec = self.0[4..4 + n].to_vec();
        self.0.drain(..4 + n);
        Ok(Some(rec))
    }
}

async fn send_rec(t: &Arc<dyn Transport>, sid: u32, payload: &[u8]) -> Result<()> {
    let mut v = (payload.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(payload);
    for c in v.chunks(t.max_payload().max(1)) {
        t.send_frame(sid, 0, c).await?;
    }
    Ok(())
}

async fn send_json(t: &Arc<dyn Transport>, sid: u32, v: &Value) -> Result<()> {
    send_rec(t, sid, &serde_json::to_vec(v)?).await
}

/// One inbound record from the stream pipe. `rx` is the initiator's link event
/// channel (None on the receiver, whose daemon loop routes frames for it):
/// frames are handed to the mux, an `l2-close` for our sid ends the stream.
async fn next_rec(
    pipe: &mut mpsc::Receiver<Option<Bytes>>,
    mut rx: Option<&mut mpsc::UnboundedReceiver<Ev>>,
    mux: &l2::Mux,
    sid: u32,
    recs: &mut Records,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(r) = recs.next()? {
            return Ok(r);
        }
        tokio::select! {
            item = pipe.recv() => match item {
                Some(Some(b)) => recs.0.extend_from_slice(&b),
                _ => bail!("the peer closed the sync stream"),
            },
            ev = async { match rx.as_deref_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => match ev {
                Some(Ev::Control(_, v)) => {
                    if v["type"].as_str() == Some("l2-close") && v["sid"].as_u64() == Some(sid as u64) {
                        bail!("{}", v["err"].as_str().unwrap_or("closed"));
                    }
                }
                Some(Ev::Chunk(_, got, _, data)) => mux.on_frame(got, data).await,
                Some(_) => {}
                None => bail!("the link died during sync"),
            },
            _ = tokio::time::sleep_until(deadline) => bail!("timed out waiting for the peer"),
        }
    }
}

async fn next_json(
    pipe: &mut mpsc::Receiver<Option<Bytes>>,
    rx: Option<&mut mpsc::UnboundedReceiver<Ev>>,
    mux: &l2::Mux,
    sid: u32,
    recs: &mut Records,
    timeout: Duration,
) -> Result<Value> {
    Ok(serde_json::from_slice(&next_rec(pipe, rx, mux, sid, recs, timeout).await?)?)
}

// ------------------------------------------------------------ initiator -----

pub(crate) struct SyncOpts {
    pub delete: bool,
    pub dry_run: bool,
    pub json: bool,
}

/// Exit codes per docs/agent-output-audit.md: 3 unknown device, 4 denied,
/// 5 unreachable, 7 partial, 1 anything else.
struct Fail(i32, &'static str, String);
impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.2)
    }
}
impl std::fmt::Debug for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.2)
    }
}
impl std::error::Error for Fail {}
fn fail(exit: i32, code: &'static str, msg: impl Into<String>) -> anyhow::Error {
    Fail(exit, code, msg.into()).into()
}

struct Report {
    json: bool,
    moved: u64,
    counts: BTreeMap<&'static str, u64>,
}
impl Report {
    fn line(&mut self, state: &'static str, p: &str, bytes: u64, reason: Option<&str>) {
        *self.counts.entry(state).or_insert(0) += 1;
        self.moved += bytes;
        if self.json {
            let mut d = json!({ "file": p, "state": state, "bytes": bytes });
            if let Some(r) = reason {
                d["reason"] = json!(r);
            }
            println!("{}", json!({ "ok": true, "verb": "sync", "data": d }));
        } else {
            let tail = match (reason, bytes) {
                (Some(r), _) => format!(": {r}  {p}"),
                (None, 0) => format!("  {p}"),
                (None, b) => format!("  {p}  ({})", crate::human(b)),
            };
            ui::say(&format!("  {state}{tail}"));
        }
    }
}

/// Run the verb end to end and return the process exit code. Prints its own
/// lines (human via `ui::`, machine via one JSONL envelope per file plus a
/// final one), so the dispatch arm only has to exit.
pub(crate) async fn run(
    server: &str,
    local: &Path,
    peer: &str,
    remote_dir: &str,
    relay: bool,
    opts: SyncOpts,
) -> i32 {
    let mut rep = Report { json: opts.json, moved: 0, counts: BTreeMap::new() };
    match sync_inner(server, local, peer, remote_dir, relay, &opts, &mut rep).await {
        Ok(total) => {
            let partial = rep.counts.get("failed").copied().unwrap_or(0) > 0;
            let exit = if partial { 7 } else { 0 };
            if opts.json {
                let mut d = json!({ "moved": rep.moved, "total": total, "dry_run": opts.dry_run, "exit": exit });
                for (k, v) in &rep.counts {
                    d[k] = json!(v);
                }
                println!("{}", json!({ "ok": !partial, "verb": "sync", "data": d }));
            } else {
                let c = |k: &str| rep.counts.get(k).copied().unwrap_or(0);
                ui::say(&format!(
                    "  {} {} of {} moved{}: {} sent, {} updated, {} same, {} skipped{}{}",
                    if partial { ui::glyph_warn() } else { ui::glyph_ok() },
                    crate::human(rep.moved),
                    crate::human(total),
                    if opts.dry_run { " (dry run, nothing moved)" } else { "" },
                    c("sent") + c("would send"),
                    c("updated") + c("would update"),
                    c("same"),
                    c("skipped"),
                    if c("deleted") + c("would delete") > 0 {
                        format!(", {} deleted", c("deleted") + c("would delete"))
                    } else {
                        String::new()
                    },
                    if partial { format!(", {} FAILED", c("failed")) } else { String::new() },
                ));
            }
            exit
        }
        Err(e) => {
            let (exit, code) = match e.downcast_ref::<Fail>() {
                Some(Fail(x, c, _)) => (*x, *c),
                None => (1, "error"),
            };
            if opts.json {
                println!(
                    "{}",
                    json!({ "ok": false, "verb": "sync", "error": { "code": code, "exit": exit, "message": e.to_string() } })
                );
            } else {
                ui::problem("sync failed", &e.to_string(), &[]);
            }
            exit
        }
    }
}

async fn sync_inner(
    server: &str,
    local: &Path,
    peer: &str,
    remote_dir: &str,
    relay: bool,
    opts: &SyncOpts,
    rep: &mut Report,
) -> Result<u64> {
    let local = local
        .canonicalize()
        .map_err(|e| fail(2, "usage", format!("{}: {e}", local.display())))?;
    if !local.is_dir() {
        return Err(fail(2, "usage", format!("{} is not a directory", local.display())));
    }
    crate::identity_state::require_known_device(peer)
        .map_err(|e| fail(3, "unknown_device", e.to_string()))?;
    let (files, skipped) = walk_manifest(&local)?;
    let total: u64 = files.iter().map(|e| e.size).sum();

    let (t, mut rx, guard, _diag) = match tokio::time::timeout(
        Duration::from_secs(45),
        l2::bring_up_to_known(server, peer, relay, "sync"),
    )
    .await
    {
        Ok(Ok(x)) => x,
        Ok(Err(e)) if e.to_string().contains("no known device") => {
            return Err(fail(3, "unknown_device", e.to_string()));
        }
        Ok(Err(e)) => return Err(fail(5, "unreachable", e.to_string())),
        Err(_) => return Err(fail(5, "unreachable", format!("couldn't reach '{peer}' in 45s"))),
    };
    guard.forget();
    let mux = l2::Mux::new(t.clone());
    let sid = mux.alloc_sid();
    let mut pipe = mux
        .register_stream(sid)
        .await
        .ok_or_else(|| fail(1, "error", format!("sid {sid:#x} already in use")))?;
    t.send_control(&json!({
        "type": "sync-open", "sid": sid, "root": remote_dir,
        "delete": opts.delete, "dry_run": opts.dry_run,
    }))
    .await?;
    // Ack wait, exec's four outcomes: ack, refusal with the receiver's reason,
    // stream closed, silence.
    let ack = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match rx.recv().await {
                Some(Ev::Control(_, v)) if v["sid"].as_u64() == Some(sid as u64) => {
                    match v["type"].as_str() {
                        Some("sync-open-ack") => break Ok(()),
                        Some("l2-close") => {
                            break Err(v["err"].as_str().unwrap_or("closed").to_string());
                        }
                        _ => {}
                    }
                }
                Some(Ev::Chunk(_, got, _, data)) => mux.on_frame(got, data).await,
                Some(_) => {}
                None => break Err("closed the link before answering".into()),
            }
        }
    })
    .await
    .map_err(|_| fail(5, "unreachable", format!("no answer from '{peer}' (is `filament up` running there?)")))?;
    if let Err(reason) = ack {
        return Err(fail(4, "denied", format!("'{peer}' refused sync: {reason}")));
    }
    let mut recs = Records::default();
    send_json(&t, sid, &json!({ "type": "manifest", "files": files })).await?;
    let plan: Plan = serde_json::from_value(
        next_json(&mut pipe, Some(&mut rx), &mux, sid, &mut recs, Duration::from_secs(300)).await?,
    )?;

    for (p, why) in &skipped {
        rep.line("skipped", p, 0, Some(why));
    }
    for p in &plan.same {
        rep.line("same", p, 0, None);
    }
    let by_path: BTreeMap<&str, &Entry> = files.iter().map(|e| (e.p.as_str(), e)).collect();
    for n in &plan.need {
        let Some(e) = by_path.get(n.p.as_str()) else { continue };
        let bytes: u64 = (n.chunks.iter())
            .map(|&i| (e.size - (i as u64 * SYNC_CHUNK)).min(SYNC_CHUNK))
            .sum();
        let state = match (opts.dry_run, n.new) {
            (true, true) => "would send",
            (true, false) => "would update",
            (false, true) => "sent",
            (false, false) => "updated",
        };
        if opts.dry_run {
            rep.line(state, &n.p, bytes, None);
            continue;
        }
        send_json(&t, sid, &json!({ "type": "file", "p": e.p, "size": e.size, "full": e.full, "mtime": e.mtime })).await?;
        let mut f = std::fs::File::open(local.join(&e.p))?;
        let mut buf = vec![0u8; SYNC_CHUNK as usize];
        for &i in &n.chunks {
            use std::io::{Read, Seek};
            f.seek(std::io::SeekFrom::Start(i as u64 * SYNC_CHUNK))?;
            let mut got = 0;
            while got < buf.len() {
                let k = f.read(&mut buf[got..])?;
                if k == 0 {
                    break;
                }
                got += k;
            }
            send_json(&t, sid, &json!({ "type": "chunk", "idx": i })).await?;
            send_rec(&t, sid, &buf[..got]).await?;
        }
        send_json(&t, sid, &json!({ "type": "file-end" })).await?;
        let ack = next_json(&mut pipe, Some(&mut rx), &mux, sid, &mut recs, Duration::from_secs(300)).await?;
        if ack["ok"].as_bool() == Some(true) {
            rep.line(state, &n.p, bytes, None);
        } else {
            rep.line("failed", &n.p, bytes, Some(ack["err"].as_str().unwrap_or("receiver refused the file")));
        }
    }
    if opts.delete && !plan.extra.is_empty() {
        if opts.dry_run {
            for p in &plan.extra {
                rep.line("would delete", p, 0, None);
            }
        } else {
            send_json(&t, sid, &json!({ "type": "delete", "paths": plan.extra })).await?;
            let ack = next_json(&mut pipe, Some(&mut rx), &mux, sid, &mut recs, Duration::from_secs(120)).await?;
            for p in ack["paths"].as_array().into_iter().flatten().filter_map(|v| v.as_str()) {
                rep.line("deleted", p, 0, None);
            }
        }
    }
    send_json(&t, sid, &json!({ "type": "done" })).await?;
    let _ = t.flush().await;
    mux.drop_stream(sid).await;
    Ok(total)
}

// ------------------------------------------------------------- receiver -----

/// The same decision a `file-offer` from this peer gets in daemon mode: the
/// transfer capability under the trust floor, legacy trust in shadow, an
/// authoritative deny hard-refusing. Returns the verified petname on allow.
fn authorize_sync(conn: &mut Conn, pid: &str, in_bounds: bool) -> Result<String, String> {
    use crate::capability as cap;
    let trusted = conn.link(pid).map(|l| l.trusted).unwrap_or(false);
    let who = conn
        .link(pid)
        .and_then(|l| l.verified_name.clone())
        .unwrap_or_else(|| "<unverified>".into());
    let az = crate::peer_authz(conn, pid);
    let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
    let cfg = crate::settings::config_dir();
    let outcome = cap::cap_authorize(&cfg, "self", cap::CAP_TRANSFER, idev, iusr, ak_caps);
    let outcome = cap::cap_trust_floor(&outcome, trusted, binding, cap::cap_authoritative());
    let (own_user, has_grant) =
        cap::cap_fleet_inputs(&cfg, "self", cap::CAP_TRANSFER, idev, iusr, ak_caps);
    let d = cap::cap_gate_effective(
        trusted, &outcome, cap::CAP_TRANSFER, "self", idev, iusr, binding, expires, ak_caps,
        own_user.as_ref(), in_bounds, has_grant, cert_revoked,
    );
    if let Some(reason) = cap::transfer_gate_decision(&d, cap::cap_authoritative()) {
        return Err(reason);
    }
    if !d.allowed() {
        return Err(d.deny_reason("unverified peer: pair first").to_string());
    }
    Ok(who)
}

/// Bound the requested root to the drop directory: relative, or absolute under
/// it; every existing ancestor canonical-within before anything is created,
/// and the result canonical-within after. With `create` false (a dry run) a
/// missing root is returned as is and nothing touches the disk.
pub(crate) fn resolve_root(drop_dir: &Path, req: &str, create: bool) -> Result<PathBuf, String> {
    let outside = || "remote dir is outside this device's drop directory".to_string();
    let rel = match req.trim() {
        "" | "." => PathBuf::new(),
        r if Path::new(r).is_absolute() => {
            let inside = Path::new(r).strip_prefix(drop_dir).map_err(|_| outside())?;
            if inside.as_os_str().is_empty() {
                PathBuf::new()
            } else {
                safe_relpath(&inside.to_string_lossy()).ok_or_else(outside)?
            }
        }
        r => safe_relpath(r).ok_or_else(outside)?,
    };
    let target = drop_dir.join(&rel);
    if !crate::path_within(drop_dir, &target) {
        return Err(outside());
    }
    let mut probe = target.clone();
    while !probe.exists() {
        probe = probe.parent().map(Path::to_path_buf).ok_or_else(outside)?;
    }
    if !crate::path_within_canonical(drop_dir, &probe) {
        return Err(outside());
    }
    if !create && !target.exists() {
        return Ok(target);
    }
    std::fs::create_dir_all(&target).map_err(|e| format!("cannot create remote dir: {e}"))?;
    if !crate::path_within_canonical(drop_dir, &target) {
        return Err(outside());
    }
    target.canonicalize().map_err(|e| e.to_string())
}

pub(crate) async fn handle_sync_open(
    conn: &mut Conn,
    pid: &str,
    t: Arc<dyn Transport>,
    mux: Arc<l2::Mux>,
    v: &Value,
    drop_dir: &Path,
) {
    let Some(sid) = l2::wire_sid(v) else { return };
    if !l2::is_l2_sid(sid) {
        return;
    }
    let refuse = |err: String| {
        let t = t.clone();
        async move {
            ui::say(&format!("sync: refused: {err}"));
            let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": err })).await;
        }
    };
    // Bounds first, so an out-of-root request never widens to a grant-only
    // decision it would have failed anyway, and the gate sees the real scope.
    let dry_run = v["dry_run"].as_bool() == Some(true);
    let root = match resolve_root(drop_dir, v["root"].as_str().unwrap_or(""), !dry_run) {
        Ok(r) => r,
        Err(e) => return refuse(e).await,
    };
    let who = match authorize_sync(conn, pid, true) {
        Ok(w) => w,
        Err(reason) => {
            let name = conn.link(pid).and_then(|l| l.verified_name.clone());
            crate::enqueue_if_requestable(name.as_deref().unwrap_or("<unverified>"), "transfer");
            return refuse(format!("not authorized: {reason}")).await;
        }
    };
    if mux.at_stream_cap().await {
        return refuse("too many streams".into()).await;
    }
    let Some(pipe) = mux.register_stream(sid).await else {
        return refuse("sid in use".into()).await;
    };
    let delete = v["delete"].as_bool() == Some(true);
    let _ = t.send_control(&json!({ "type": "sync-open-ack", "sid": sid })).await;
    ui::say(&format!("sync: '{who}' -> {}{}", root.display(), if dry_run { " (dry run)" } else { "" }));
    tokio::spawn(async move {
        if let Err(e) = serve_sync(&t, &mux, sid, &root, delete, dry_run, pipe).await {
            ui::say(&format!("sync: ended: {e}"));
            let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": e.to_string() })).await;
        }
        mux.drop_stream(sid).await;
    });
}

async fn serve_sync(
    t: &Arc<dyn Transport>,
    mux: &l2::Mux,
    sid: u32,
    root: &Path,
    delete: bool,
    dry_run: bool,
    mut pipe: mpsc::Receiver<Option<Bytes>>,
) -> Result<()> {
    let wait = Duration::from_secs(300);
    let mut recs = Records::default();
    let mut m = next_json(&mut pipe, None, mux, sid, &mut recs, wait).await?;
    if m["type"].as_str() != Some("manifest") {
        bail!("expected a manifest");
    }
    let files: Vec<Entry> = serde_json::from_value(m["files"].take())?;
    if files.iter().any(|e| safe_relpath(&e.p).is_none()) {
        bail!("manifest names an unsafe path");
    }
    let r = root.to_path_buf();
    let (have, _) = if r.is_dir() {
        tokio::task::spawn_blocking(move || walk_manifest(&r)).await??
    } else {
        (Vec::new(), Vec::new())
    };
    let plan = diff(&files, &have);
    send_json(t, sid, &serde_json::to_value(&plan)?).await?;
    loop {
        let m = next_json(&mut pipe, None, mux, sid, &mut recs, wait).await?;
        match m["type"].as_str() {
            Some("done") => return Ok(()),
            Some("file") if !dry_run => {
                let p = m["p"].as_str().unwrap_or("").to_string();
                let res = receive_file(t, mux, sid, root, &m, &mut pipe, &mut recs).await;
                let ack = match res {
                    Ok(()) => json!({ "type": "file-ack", "p": p, "ok": true }),
                    Err(e) => json!({ "type": "file-ack", "p": p, "ok": false, "err": e.to_string() }),
                };
                send_json(t, sid, &ack).await?;
            }
            Some("delete") if delete && !dry_run => {
                let mut gone = Vec::new();
                for p in m["paths"].as_array().into_iter().flatten().filter_map(|v| v.as_str()) {
                    let Some(rel) = safe_relpath(p) else { continue };
                    let target = root.join(rel);
                    let is_file = std::fs::symlink_metadata(&target).map(|md| md.is_file()).unwrap_or(false);
                    if crate::path_within(root, &target) && is_file && std::fs::remove_file(&target).is_ok() {
                        gone.push(p.to_string());
                    }
                }
                send_json(t, sid, &json!({ "type": "deleted", "paths": gone })).await?;
            }
            other => bail!("unexpected sync record {other:?}"),
        }
    }
}

/// Land one file: copy the existing target (if any) to `.part`, write the
/// chunks that arrive at their positions, truncate to size, verify the whole
/// digest, rename into place. Any failure leaves the target untouched.
async fn receive_file(
    t: &Arc<dyn Transport>,
    mux: &l2::Mux,
    sid: u32,
    root: &Path,
    m: &Value,
    pipe: &mut mpsc::Receiver<Option<Bytes>>,
    recs: &mut Records,
) -> Result<()> {
    let _ = t;
    let wait = Duration::from_secs(300);
    let rel = safe_relpath(m["p"].as_str().unwrap_or("")).ok_or_else(|| anyhow::anyhow!("unsafe path"))?;
    let size = m["size"].as_u64().unwrap_or(0);
    let full = m["full"].as_str().unwrap_or("").to_string();
    let target = root.join(&rel);
    if !crate::path_within(root, &target) {
        bail!("path escapes the remote dir");
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let part = target.with_file_name(format!(
        "{}.part",
        target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    ));
    if std::fs::symlink_metadata(&part).is_ok() {
        std::fs::remove_file(&part)?;
    }
    match std::fs::symlink_metadata(&target) {
        Ok(md) if md.is_file() => {
            std::fs::copy(&target, &part)?;
        }
        Ok(_) => bail!("destination exists and is not a regular file"),
        Err(_) => {}
    }
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&part)?;
    loop {
        let h = next_json(pipe, None, mux, sid, recs, wait).await?;
        match h["type"].as_str() {
            Some("file-end") => break,
            Some("chunk") => {
                let idx = h["idx"].as_u64().unwrap_or(u64::MAX);
                let data = next_rec(pipe, None, mux, sid, recs, wait).await?;
                let pos = idx.checked_mul(SYNC_CHUNK).filter(|p| *p < size.max(1)).ok_or_else(|| anyhow::anyhow!("chunk index out of range"))?;
                if data.len() as u64 > SYNC_CHUNK || pos + data.len() as u64 > size {
                    bail!("chunk overruns the file");
                }
                filament_transfer::pwrite_at(&f, &data, pos)?;
            }
            other => bail!("unexpected record inside a file: {other:?}"),
        }
    }
    f.set_len(size)?;
    f.sync_all()?;
    drop(f);
    let p2 = part.clone();
    let got = tokio::task::spawn_blocking(move || crate::recv_files::full_hash(&p2)).await?;
    if got.as_deref() != Some(full.as_str()) {
        let _ = std::fs::remove_file(&part);
        bail!("content hash mismatch after transfer");
    }
    std::fs::rename(&part, &target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fil-sync-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn relpaths_that_could_escape_are_refused() {
        for bad in ["", "/etc/passwd", "../x", "a/../../b", "./a", "a/./b", "a/", "a//b", "a\\b", "a\0b"] {
            assert!(safe_relpath(bad).is_none(), "{bad:?}");
        }
        assert_eq!(safe_relpath("a/b/c.txt").unwrap(), PathBuf::from("a/b/c.txt"));
    }

    #[test]
    fn chunk_hashes_cover_the_file_and_agree_with_the_whole_digest() {
        let d = tmp("hash");
        let p = d.join("f");
        let data: Vec<u8> = (0..(SYNC_CHUNK as usize * 2 + 17)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        let (full, chunks) = hash_file(&p).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(Some(full), crate::recv_files::full_hash(&p));
        assert_eq!(hash_file(&d.join({ std::fs::write(d.join("e"), b"").unwrap(); "e" })).unwrap().1.len(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn walk_skips_symlinks_and_diff_names_only_changed_chunks() {
        let d = tmp("walk");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        let big: Vec<u8> = vec![7u8; SYNC_CHUNK as usize * 3];
        std::fs::write(d.join("big"), &big).unwrap();
        std::fs::write(d.join("sub/small"), b"hello").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", d.join("link")).unwrap();
        let (local, skipped) = walk_manifest(&d).unwrap();
        assert_eq!(local.iter().map(|e| e.p.as_str()).collect::<Vec<_>>(), ["big", "sub/small"]);
        #[cfg(unix)]
        assert_eq!(skipped, vec![("link".to_string(), "symlink".to_string())]);

        // Remote: identical small, big with the MIDDLE chunk changed, plus a stray.
        let r = tmp("walk-remote");
        std::fs::create_dir_all(r.join("sub")).unwrap();
        let mut rb = big.clone();
        rb[SYNC_CHUNK as usize + 5] = 0;
        std::fs::write(r.join("big"), &rb).unwrap();
        std::fs::write(r.join("sub/small"), b"hello").unwrap();
        std::fs::write(r.join("stray"), b"x").unwrap();
        let (remote, _) = walk_manifest(&r).unwrap();
        let plan = diff(&local, &remote);
        assert_eq!(plan.same, vec!["sub/small".to_string()]);
        assert_eq!(plan.need, vec![Need { p: "big".into(), new: false, chunks: vec![1] }]);
        assert_eq!(plan.extra, vec!["stray".to_string()]);
        // Empty remote: everything is new, every chunk needed.
        let plan = diff(&local, &[]);
        assert_eq!(plan.need.len(), 2);
        assert!(plan.need.iter().all(|n| n.new));
        assert_eq!(plan.need[0].chunks, vec![0, 1, 2]);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn remote_root_is_bounded_to_the_drop_dir() {
        let d = tmp("root");
        assert_eq!(resolve_root(&d, "dry", false).unwrap(), d.join("dry"));
        assert!(!d.join("dry").exists(), "a dry run creates nothing");
        assert_eq!(resolve_root(&d, "inbox/photos", true).unwrap(), d.join("inbox/photos").canonicalize().unwrap());
        assert_eq!(resolve_root(&d, "", true).unwrap(), d.canonicalize().unwrap());
        assert_eq!(resolve_root(&d, &d.join("abs").to_string_lossy(), true).unwrap(), d.join("abs").canonicalize().unwrap());
        for bad in ["../out", "/etc", "a/../../b"] {
            assert!(resolve_root(&d, bad, true).is_err(), "{bad}");
            assert!(resolve_root(&d, bad, false).is_err(), "{bad}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/tmp", d.join("esc")).unwrap();
            assert!(resolve_root(&d, "esc/x", true).is_err(), "symlink escape must be refused");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn records_reassemble_across_frame_boundaries() {
        let mut r = Records::default();
        let mut wire = (5u32).to_be_bytes().to_vec();
        wire.extend_from_slice(b"hello");
        wire.extend_from_slice(&(0u32).to_be_bytes());
        r.0.extend_from_slice(&wire[..3]);
        assert!(r.next().unwrap().is_none());
        r.0.extend_from_slice(&wire[3..7]);
        assert!(r.next().unwrap().is_none());
        r.0.extend_from_slice(&wire[7..]);
        assert_eq!(r.next().unwrap().unwrap(), b"hello");
        assert_eq!(r.next().unwrap().unwrap(), b"");
        assert!(r.next().unwrap().is_none());
    }
}
