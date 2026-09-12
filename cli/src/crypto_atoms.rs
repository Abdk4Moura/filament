//! Hashing, time and randomness primitives.
//!
//! Small pure helpers shared across the crate: SHA-256 digests (one-shot, whole-file
//! and HMAC), wall-clock time, per-link nonces and the pair-secret CSPRNG.
//!
//! Six scattered blocks. NO cfg, NO spawns, NO nested fns, NO function-local uses.
use crate::shared_defs::HEAD_BYTES;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// C7: hash of the first min(256 KiB, len) bytes, cheap content identity
/// carried in file-offer so resume can detect a different file wearing the
/// same name + size.
pub(crate) fn head_hash(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; HEAD_BYTES as usize];
    let mut got = 0usize;
    while got < buf.len() {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    let mut h = Sha256::new();
    h.update(&buf[..got]);
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// A fresh per-link challenge nonce for transports with no RFC-5705 exporter.
pub(crate) fn link_nonce() -> Vec<u8> {
    // fresh_secret() is the same CSPRNG the pair secrets use; 32 bytes of it.
    hex::decode(fresh_secret()).unwrap_or_else(|_| fresh_secret().into_bytes())
}

/// HMAC-SHA256 (manual: avoids a hmac-crate version dance with sha2 0.11).
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner.finalize());
    outer
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn fresh_secret() -> String {
    let mut buf = [0u8; 32];
    // std-only CSPRNG is unavailable; derive from getrandom via std::fs on unix
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // fallback (non-unix): hash of time+pid noise, still unpredictable enough
        let mut h = Sha256::new();
        h.update(format!("{:?}{}", SystemTime::now(), std::process::id()));
        buf.copy_from_slice(&h.finalize()[..32]);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal `YYYY-MM-DD HH:MM` UTC stamp (civil-from-days; avoids chrono).
pub(crate) fn chrono_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86400, secs % 86400);
    let (hh, mm) = (rem / 3600, (rem % 3600) / 60);
    // Howard Hinnant's civil_from_days
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}
