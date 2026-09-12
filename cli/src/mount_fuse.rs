// Unix FUSE client adapter for the mesh-native mount protocol (Linux FUSE and
// macOS macFUSE).
//
// This is the `MountHost` piece from docs/design-cross-platform-capabilities.md:
// the mesh serves a uniform SFTP-like file protocol (see mount_proto.rs), and
// this adapter presents that protocol as a real local filesystem via FUSE. The
// server needs no FUSE; only the client mount does. macOS reuses this same crate
// (macFUSE) and Windows gets a WinFsp/ProjFS adapter in a later round.
//
// Design notes:
//   * The wire protocol is PATH-based; FUSE is INODE-based. `InodeMap` is the
//     client-side bridge: a stable u64 inode per path (root = 1), allocated on
//     first lookup/readdir and reused so the kernel's inode cache stays coherent.
//   * Server file handles pass straight through as FUSE file handles.
//   * fuser 0.17's `Filesystem` methods take `&self`, but `MountClient::call_sync`
//     needs `&mut` (it owns the framing buffer + id counter), so the client lives
//     behind a `Mutex`. fuser runs a single event-loop thread by default, so this
//     never contends.
//   * `call_sync` blocks the calling thread on a tokio mpsc, so the whole FUSE
//     session runs inside `spawn_blocking` while the mux pump tasks keep draining
//     the transport on the tokio runtime.

#![cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos")))]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    Config, FileAttr, FileType, Filesystem, Generation, MountOption, OpenFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
    TimeOrNow,
};
use fuser::{Errno, FileHandle, FopenFlags, INodeNo};
use serde_json::Value;

use crate::mount_proto::{FileKind, FileStat, MountClient, MountOp, MountResult};

const EIO: i32 = 5;
const TTL: Duration = Duration::from_secs(1);

/// Maps stable FUSE inode numbers to protocol paths (relative to the mount root)
/// and back. Root is inode 1, path ".". New inodes are handed out monotonically
/// and cached both ways so repeated lookups of the same path are stable.
///
/// When `case_sensitive` is false (e.g. macOS mounting a case-preserving but
/// case-insensitive filesystem) the reverse lookup key is lowercased so that
/// "File" and "file" resolve to the same inode. This is an ASCII-centric
/// approximation; full Unicode case folding is left to a future normalization
/// pass.
struct InodeMap {
    fwd: HashMap<u64, PathBuf>,
    rev: HashMap<Vec<u8>, u64>,
    next: u64,
    case_sensitive: bool,
}

impl InodeMap {
    fn new(case_sensitive: bool) -> Self {
        let mut fwd = HashMap::new();
        let mut rev = HashMap::new();
        fwd.insert(1, PathBuf::from("."));
        rev.insert(Self::normalize(Path::new(".")), 1);
        InodeMap { fwd, rev, next: 2, case_sensitive }
    }

    fn normalize(path: &Path) -> Vec<u8> {
        let mut bytes = path.as_os_str().as_bytes().to_vec();
        // Preserve undecodable bytes; Unicode folding cannot define their case.
        for byte in &mut bytes {
            if byte.is_ascii_uppercase() {
                *byte = byte.to_ascii_lowercase();
            }
        }
        bytes
    }

    fn key(&self, path: &Path) -> Vec<u8> {
        if self.case_sensitive {
            path.as_os_str().as_bytes().to_vec()
        } else {
            Self::normalize(path)
        }
    }

    fn path(&self, ino: u64) -> Option<PathBuf> {
        self.fwd.get(&ino).cloned()
    }

    fn intern(&mut self, path: PathBuf) -> u64 {
        let key = self.key(&path);
        if let Some(&i) = self.rev.get(&key) {
            return i;
        }
        let i = self.next;
        self.next += 1;
        self.fwd.insert(i, path);
        self.rev.insert(key, i);
        i
    }

    fn forget(&mut self, path: &Path) {
        let key = self.key(path);
        if let Some(i) = self.rev.remove(&key) {
            self.fwd.remove(&i);
        }
    }
}

/// A cached directory listing, captured on the first `readdir` for an open dir
/// handle and served across the paginated readdir calls the kernel makes.
struct CachedDir {
    // (child inode, kind, name) triples, in listing order.
    entries: Vec<(u64, FileType, OsString)>,
}

pub struct FilamentFs {
    client: Mutex<MountClient>,
    inodes: Mutex<InodeMap>,
    // Keyed by the server file handle returned from opendir.
    dirs: Mutex<HashMap<u64, CachedDir>>,
}

impl FilamentFs {
    pub fn new(client: MountClient) -> Self {
        // The mount protocol is v2+. A v1 client reaching here is a programming
        // error; fail fast rather than silently return empty data.
        assert!(client.binary_frames, "FilamentFs requires a v2 MountClient");
        let case_sensitive = client.caps.case_sensitive;
        FilamentFs {
            client: Mutex::new(client),
            inodes: Mutex::new(InodeMap::new(case_sensitive)),
            dirs: Mutex::new(HashMap::new()),
        }
    }

    /// Issue one protocol op and unwrap the result to either the ok `Value` or a
    /// POSIX errno the FUSE reply can carry. A dead channel maps to EIO.
    fn call(&self, op: MountOp) -> Result<Value, i32> {
        self.call_data(op, None).map(|(v, _)| v)
    }

    /// Issue one protocol op with an optional binary data payload (for Write)
    /// and collect any binary payload from the response (for Read).
    fn call_data(&self, op: MountOp, data: Option<&[u8]>) -> Result<(Value, Option<Vec<u8>>), i32> {
        let mut c = self.client.lock().unwrap();
        match c.call_sync_binary(op, data) {
            Ok((resp, bin)) => match resp.result {
                MountResult::Ok(v) => Ok((v, bin.map(|b| b.to_vec()))),
                MountResult::Err(e) => Err(e.code),
            },
            Err(_) => Err(EIO),
        }
    }

    fn path_of(&self, ino: u64) -> Result<PathBuf, i32> {
        self.inodes
            .lock()
            .unwrap()
            .path(ino)
            .ok_or(libc::ENOENT)
    }

    fn supports_fifo(&self) -> bool {
        self.client.lock().unwrap().caps.supports_fifo
    }
}

/// Join a child name onto a parent path, keeping the root as "." rather than
/// "./name" so the encoded wire path and the inode-map key stay canonical.
fn child_path(parent: &Path, name: &OsStr) -> PathBuf {
    if parent == Path::new(".") {
        PathBuf::from(name)
    } else {
        parent.join(name)
    }
}

fn encode(path: &Path) -> String {
    crate::mount_proto::path_encode(path)
}

fn kind_to_fuse(stat: &FileStat, supports_fifo: bool) -> FileType {
    match stat.kind {
        Some(FileKind::Dir) => FileType::Directory,
        Some(FileKind::Symlink) => FileType::Symlink,
        _ => {
            // No explicit kind: fall back to the mode type bits.
            match stat.mode & 0o170000 {
                0o040000 => FileType::Directory,
                0o120000 => FileType::Symlink,
                0o010000 => {
                    if supports_fifo { FileType::NamedPipe } else { FileType::RegularFile }
                }
                0o140000 => FileType::Socket,
                0o020000 => FileType::CharDevice,
                0o060000 => FileType::BlockDevice,
                _ => FileType::RegularFile,
            }
        }
    }
}

/// Build a fuser `FileAttr` from the protocol `FileStat`, stamping the given
/// stable inode. Times we cannot represent collapse to mtime (v1 carries mtime
/// only, per the spec's best-effort metadata rule).
fn to_attr(ino: u64, stat: &FileStat, supports_fifo: bool) -> FileAttr {
    let mtime = UNIX_EPOCH + Duration::from_secs(stat.mtime);
    FileAttr {
        ino: INodeNo(ino),
        size: stat.size,
        blocks: stat.blocks,
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime: mtime,
        kind: kind_to_fuse(stat, supports_fifo),
        perm: (stat.mode & 0o7777) as u16,
        nlink: stat.nlink.max(1),
        uid: stat.uid,
        gid: stat.gid,
        rdev: 0,
        blksize: stat.blksize,
        flags: 0,
    }
}

fn parse_stat(v: &Value) -> Result<FileStat, i32> {
    serde_json::from_value(v.clone()).map_err(|_| EIO)
}

impl Filesystem for FilamentFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let parent_path = match self.path_of(parent.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        let path = child_path(&parent_path, name);
        match self.call(MountOp::GetAttr { path: encode(&path) }) {
            Ok(v) => match parse_stat(&v) {
                Ok(stat) => {
                    let ino = self.inodes.lock().unwrap().intern(path);
                    reply.entry(&TTL, &to_attr(ino, &stat, self.supports_fifo()), Generation(0));
                }
                Err(e) => reply.error(Errno::from_i32(e)),
            },
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let path = match self.path_of(ino.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        match self.call(MountOp::GetAttr { path: encode(&path) }) {
            Ok(v) => match parse_stat(&v) {
                Ok(stat) => reply.attr(&TTL, &to_attr(ino.0, &stat, self.supports_fifo())),
                Err(e) => reply.error(Errno::from_i32(e)),
            },
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let path = match self.path_of(ino.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        // v1 honours the one setattr that changes bytes: truncate. mode/uid/gid/
        // timestamps are acked best-effort (the spec's honest-metadata rule); we
        // re-stat and return the server's truth rather than fake the requested
        // values.
        if let Some(sz) = size {
            if let Err(e) = self.call(MountOp::Truncate { path: encode(&path), size: sz }) {
                return reply.error(Errno::from_i32(e));
            }
        }
        match self.call(MountOp::GetAttr { path: encode(&path) }) {
            Ok(v) => match parse_stat(&v) {
                Ok(stat) => reply.attr(&TTL, &to_attr(ino.0, &stat, self.supports_fifo())),
                Err(e) => reply.error(Errno::from_i32(e)),
            },
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let path = match self.path_of(ino.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        match self.call(MountOp::ReadLink { path: encode(&path) }) {
            // The server returns the target as an encoded raw-byte path; the link
            // body handed to the kernel is exactly those bytes.
            Ok(Value::String(enc)) => match crate::mount_proto::path_decode(&enc) {
                Ok(target) => reply.data(target.as_os_str().as_bytes()),
                Err(_) => reply.error(Errno::from_i32(EIO)),
            },
            Ok(_) => reply.error(Errno::from_i32(EIO)),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let path = match self.path_of(ino.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        match self.call(MountOp::Open { path: encode(&path), flags: flags.0 }) {
            Ok(v) => {
                let fh = v["fh"].as_u64().unwrap_or(0);
                reply.opened(FileHandle(fh), FopenFlags::empty());
            }
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let max_read = self.client.lock().unwrap().caps.max_read_size;
        let size = size.min(max_read);
        match self.call_data(MountOp::Read { fh: fh.0, offset, size }, None) {
            Ok((_v, Some(bytes))) => reply.data(&bytes),
            Ok((_, None)) => reply.data(&[]),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        // The kernel may hand us a buffer larger than the server advertised.
        // Split it into cap-sized chunks so each frame fits through every
        // transport path (direct-quic, relay, WebRTC DataChannel).
        let max_write = self.client.lock().unwrap().caps.max_write_size;
        let mut written: u32 = 0;
        for chunk in data.chunks(max_write as usize) {
            match self.call_data(
                MountOp::Write {
                    fh: fh.0,
                    offset: offset + written as u64,
                    size: chunk.len() as u32,
                },
                Some(chunk),
            ) {
                Ok((v, _)) => written += v["size"].as_u64().unwrap_or(0) as u32,
                Err(e) => return reply.error(Errno::from_i32(e)),
            }
        }
        reply.written(written);
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        // No client-side write buffering: writes are already synchronous round
        // trips to the server, so there is nothing to flush here.
        reply.ok();
    }

    fn fsync(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, datasync: bool, reply: ReplyEmpty) {
        match self.call(MountOp::FSync { fh: fh.0, datasync }) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let _ = self.call(MountOp::Release { fh: fh.0 });
        reply.ok();
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let path = match self.path_of(ino.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        // The server serves ReadDir off an open handle, so a dir opens like a file.
        match self.call(MountOp::Open { path: encode(&path), flags: flags.0 }) {
            Ok(v) => {
                let fh = v["fh"].as_u64().unwrap_or(0);
                reply.opened(FileHandle(fh), FopenFlags::empty());
            }
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        // Populate the cache once (offset 0), then paginate from it. The server
        // returns the whole listing in one ReadDir, so caching keeps readdir
        // stable across the kernel's paginated calls.
        if offset == 0 {
            let dir_path = match self.path_of(ino.0) {
                Ok(p) => p,
                Err(e) => return reply.error(Errno::from_i32(e)),
            };
            let listing = match self.call(MountOp::ReadDir { fh: fh.0, offset: 0 }) {
                Ok(v) => v,
                Err(e) => return reply.error(Errno::from_i32(e)),
            };
            let parent_ino = {
                let inodes = self.inodes.lock().unwrap();
                dir_path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .and_then(|p| {
                        let key = inodes.key(p);
                        inodes.rev.get(&key).copied()
                    })
                    .unwrap_or(1)
            };
            let mut entries: Vec<(u64, FileType, OsString)> = Vec::new();
            entries.push((ino.0, FileType::Directory, OsString::from(".")));
            entries.push((parent_ino, FileType::Directory, OsString::from("..")));
            if let Some(arr) = listing.as_array() {
                let mut inodes = self.inodes.lock().unwrap();
                for e in arr {
                    let name_enc = e["name"].as_str().unwrap_or("");
                    // Names are raw bytes on the wire; decode to an OsString and
                    // never lossy-convert (spec rule 2). Skip anything undecodable.
                    let name_os = match crate::mount_proto::path_decode(name_enc) {
                        Ok(p) => match p.file_name() {
                            Some(n) => n.to_os_string(),
                            None => continue,
                        },
                        Err(_) => continue,
                    };
                    let stat: FileStat = match serde_json::from_value(e["stat"].clone()) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let child = child_path(&dir_path, &name_os);
                    let child_ino = inodes.intern(child);
                    entries.push((child_ino, kind_to_fuse(&stat, self.supports_fifo()), name_os));
                }
            }
            self.dirs.lock().unwrap().insert(fh.0, CachedDir { entries });
        }

        let dirs = self.dirs.lock().unwrap();
        if let Some(cached) = dirs.get(&fh.0) {
            for (idx, (child_ino, kind, name)) in
                cached.entries.iter().enumerate().skip(offset as usize)
            {
                // The offset we hand back is the index of the NEXT entry, so a
                // resumed readdir continues correctly.
                let next = (idx + 1) as u64;
                if reply.add(INodeNo(*child_ino), next, *kind, name) {
                    break; // kernel buffer full; the rest comes on the next call
                }
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.dirs.lock().unwrap().remove(&fh.0);
        let _ = self.call(MountOp::Release { fh: fh.0 });
        reply.ok();
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.path_of(parent.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        let path = child_path(&parent_path, name);
        let fh = match self.call(MountOp::Create { path: encode(&path), mode, flags }) {
            Ok(v) => v["fh"].as_u64().unwrap_or(0),
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        match self.call(MountOp::GetAttr { path: encode(&path) }) {
            Ok(v) => match parse_stat(&v) {
                Ok(stat) => {
                    let ino = self.inodes.lock().unwrap().intern(path);
                    reply.created(
                        &TTL,
                        &to_attr(ino, &stat, self.supports_fifo()),
                        Generation(0),
                        FileHandle(fh),
                        FopenFlags::empty(),
                    );
                }
                Err(e) => reply.error(Errno::from_i32(e)),
            },
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_path = match self.path_of(parent.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        let path = child_path(&parent_path, name);
        if let Err(e) = self.call(MountOp::MkDir { path: encode(&path), mode }) {
            return reply.error(Errno::from_i32(e));
        }
        match self.call(MountOp::GetAttr { path: encode(&path) }) {
            Ok(v) => match parse_stat(&v) {
                Ok(stat) => {
                    let ino = self.inodes.lock().unwrap().intern(path);
                    reply.entry(&TTL, &to_attr(ino, &stat, self.supports_fifo()), Generation(0));
                }
                Err(e) => reply.error(Errno::from_i32(e)),
            },
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.path_of(parent.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        let path = child_path(&parent_path, name);
        match self.call(MountOp::Unlink { path: encode(&path) }) {
            Ok(_) => {
                self.inodes.lock().unwrap().forget(&path);
                reply.ok();
            }
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.path_of(parent.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        let path = child_path(&parent_path, name);
        match self.call(MountOp::RmDir { path: encode(&path) }) {
            Ok(_) => {
                self.inodes.lock().unwrap().forget(&path);
                reply.ok();
            }
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let from_parent = match self.path_of(parent.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        let to_parent = match self.path_of(newparent.0) {
            Ok(p) => p,
            Err(e) => return reply.error(Errno::from_i32(e)),
        };
        let from = child_path(&from_parent, name);
        let to = child_path(&to_parent, newname);
        match self.call(MountOp::Rename { from: encode(&from), to: encode(&to) }) {
            Ok(_) => {
                // Drop the stale inode bindings; the kernel re-looks-up as needed.
                let mut inodes = self.inodes.lock().unwrap();
                inodes.forget(&from);
                inodes.forget(&to);
                reply.ok();
            }
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }
}

/// Mount the protocol served by `client` at `mountpoint` via FUSE. Blocks the
/// calling thread running the FUSE session loop until the filesystem is
/// unmounted (by `fusermount -u`, `umount`, or the kernel on teardown). Because
/// `MountClient::call_sync` blocks on the tokio mpsc, callers must run this on a
/// dedicated blocking thread (`spawn_blocking`) so the mux pump keeps draining.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices_store::upsert_peer_record;
    use crate::identity;
    use crate::identity_flow::principal_from_records;
    use serde_json::json;
    use std::os::unix::ffi::OsStringExt;
    #[test]
    fn inodemap_case_sensitive_distinct_keys() {
        let mut map = InodeMap::new(true);
        let a = map.intern(PathBuf::from("File.txt"));
        let b = map.intern(PathBuf::from("file.txt"));
        assert_ne!(a, b, "case-sensitive map treats File and file as distinct");
    }

    #[test]
    fn inodemap_case_insensitive_merges_keys() {
        let mut map = InodeMap::new(false);
        let a = map.intern(PathBuf::from("File.txt"));
        let b = map.intern(PathBuf::from("file.txt"));
        assert_eq!(a, b, "case-insensitive map merges File and file");
    }

    #[test]
    fn inodemap_case_insensitive_forget_by_other_case() {
        let mut map = InodeMap::new(false);
        let _ = map.intern(PathBuf::from("Foo"));
        map.forget(Path::new("foo"));
        assert!(map.path(2).is_none());
    }

    #[test]
    fn inodemap_non_utf8_names_do_not_collide() {
        let mut map = InodeMap::new(true);
        let a = PathBuf::from(std::ffi::OsString::from_vec(b"name-\xff".to_vec()));
        let b = PathBuf::from(std::ffi::OsString::from_vec(b"name-\xfe".to_vec()));
        assert_ne!(map.intern(a), map.intern(b));
    }

    #[test]
    fn inodemap_non_utf8_name_round_trips() {
        let mut map = InodeMap::new(true);
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"name-\xff".to_vec()));
        let ino = map.intern(path.clone());
        assert_eq!(map.intern(path), ino);
    }

    #[test]
    fn kind_to_fuse_fifo_when_supported() {
        let stat = FileStat { ino: 1, kind: None, mode: 0o010644, size: 0, blocks: 0, mtime: 0, nlink: 1, uid: 0, gid: 0, blksize: 512 };
        assert_eq!(kind_to_fuse(&stat, true), FileType::NamedPipe);
    }

    #[test]
    fn kind_to_fuse_fifo_mapped_to_regular_when_not_supported() {
        let stat = FileStat { ino: 1, kind: None, mode: 0o010644, size: 0, blocks: 0, mtime: 0, nlink: 1, uid: 0, gid: 0, blksize: 512 };
        assert_eq!(kind_to_fuse(&stat, false), FileType::RegularFile);
    }

    /// #23: the atomicity-relevant invariant — upsert_peer_record puts secret AND cert
    /// into ONE record, so the single write that persists it can never yield
    /// new-secret + old-cert. Drives the real merge fn across two generations against an
    /// in-memory store (no file, no env — deterministic). A non-atomic write path (the
    /// old pair flow: write secret, then separately write cert) is exactly what this
    /// forbids: it would leave secretB paired with certA (dpub_a), a wrong-userPub state.
    #[test]
    fn upsert_peer_record_writes_secret_and_cert_together() {
        // Hand-crafted certs (from_json only parses fields — no signature check — so this
        // structural test needs no UserKey/disk/env and is fully deterministic).
        let mk_cert = |dpub: u8| -> identity::DeviceCert {
            identity::DeviceCert::from_json(&serde_json::json!({
                "devicePub": hex::encode([dpub; 32]),
                "userPub": hex::encode([0x11u8; 32]),
                "expires": 9_999_999_999u64,
                "issued": 1u64,
                "sig": hex::encode([0u8; 64]),
            }))
            .unwrap()
        };
        let cert_a = mk_cert(0xa1);
        let cert_b = mk_cert(0xb2);

        let mut arr: Vec<Value> = vec![];

        // Generation A: secretA + certA land together.
        upsert_peer_record(
            &mut arr,
            "bob",
            Some("secretA"),
            Some(&cert_a),
            None,
            None,
            None,
            None,
        );
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["secret"].as_str(), Some("secretA"));
        let stored_a = identity::DeviceCert::from_json(&arr[0]["deviceCert"]).unwrap();
        assert_eq!(
            stored_a.device_pub, [0xa1u8; 32],
            "gen A: cert must be certA"
        );

        // Generation B: secretB + certB — the update that a non-atomic path could tear.
        upsert_peer_record(
            &mut arr,
            "bob",
            Some("secretB"),
            Some(&cert_b),
            None,
            None,
            None,
            None,
        );
        assert_eq!(arr.len(), 1, "same name updates in place, not duplicated");
        // The invariant: secret and cert are BOTH gen-B in the SAME record.
        assert_eq!(
            arr[0]["secret"].as_str(),
            Some("secretB"),
            "secret must be gen B"
        );
        let stored_b = identity::DeviceCert::from_json(&arr[0]["deviceCert"]).unwrap();
        assert_eq!(
            stored_b.device_pub, [0xb2u8; 32],
            "cert must be gen B — never torn to certA"
        );
        assert_ne!(
            stored_b.device_pub, [0xa1u8; 32],
            "new secret must not retain the old-gen cert"
        );
    }

    #[test]
    fn missing_same_owner_record_fails_closed() {
        let cert = identity::DeviceCert::from_json(&json!({
            "devicePub": hex::encode([0xddu8; 32]),
            "userPub": hex::encode([0x11u8; 32]),
            "expires": 9_999_999_999u64,
            "issued": 1u64,
            "sig": hex::encode([0u8; 64]),
        }))
        .unwrap();
        let (principal, expires, _max_offline, _last_seen) =
            principal_from_records(&[], &cert, Some(&cert.user_pub));
        assert_eq!(
            principal,
            crate::capability::PrincipalKind::Delegated { caps: Vec::new() }
        );
        assert_eq!(expires, Some(0));
    }
}

pub fn run_mount(client: MountClient, mountpoint: &Path) -> anyhow::Result<()> {
    let max_read = client.caps.max_read_size;
    let fs = FilamentFs::new(client);
    let mut cfg = Config::default();
    // FSName labels the mount in /proc/mounts. max_read matches the server's
    // advertised cap so the kernel never requests a single read larger than
    // one transport frame. We deliberately omit AutoUnmount (it needs
    // allow_other and a fuse.conf tweak); teardown is driven explicitly by the
    // caller via fusermount -u / ctrl-c.
    cfg.mount_options = vec![
        MountOption::FSName("filament".into()),
        MountOption::CUSTOM(format!("max_read={max_read}")),
    ];
    // macOS-specific mount options for macFUSE.
    #[cfg(target_os = "macos")]
    {
        cfg.mount_options.extend([
            MountOption::CUSTOM("volname=Filament".into()),
            MountOption::CUSTOM("local".into()),
            MountOption::CUSTOM("noappledouble".into()),
            MountOption::CUSTOM("daemon_timeout=60".into()),
        ]);
    }
    fuser::mount2(fs, mountpoint, &cfg)?;
    Ok(())
}
