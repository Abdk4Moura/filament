//! SPIKE (throwaway) — shared SPAKE2 core compiled to BOTH native and wasm32.
//!
//! Purpose: prove ONE Rust SPAKE2 implementation runs identically on the CLI
//! (native) and in the browser (wasm32), so browser<->CLI pairing shares a
//! single codebase. We export a tiny C-ABI usable from a wasm host with no
//! wasm-bindgen (keeps the spike dependency-light; production would use
//! wasm-bindgen for ergonomics).
//!
//! To make cross-target agreement REPRODUCIBLE in a headless harness we accept
//! a caller-supplied 32-byte seed for the SPAKE2 scalar RNG. Production uses
//! OsRng (already available via getrandom-js on wasm) — the seed path exists
//! ONLY for the deterministic interop demo.

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

// A tiny deterministic CSPRNG (ChaCha-free: SHA256 counter stream) so the
// spike has zero extra deps and runs identically on both targets.
struct SeedRng {
    state: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    buf_pos: usize,
}
impl SeedRng {
    fn from_seed(seed: [u8; 32]) -> Self {
        SeedRng { state: seed, counter: 0, buf: [0u8; 32], buf_pos: 32 }
    }
    fn refill(&mut self) {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(self.state);
        h.update(self.counter.to_le_bytes());
        self.buf.copy_from_slice(&h.finalize());
        self.counter += 1;
        self.buf_pos = 0;
    }
}
impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest.iter_mut() {
            if self.buf_pos >= 32 { self.refill(); }
            *d = self.buf[self.buf_pos];
            self.buf_pos += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for SeedRng {}
impl SeedableRng for SeedRng {
    type Seed = [u8; 32];
    fn from_seed(seed: [u8; 32]) -> Self { SeedRng::from_seed(seed) }
}

fn identity(nameplate: &[u8]) -> Vec<u8> {
    let mut v = b"filament-pair-pake-v1:".to_vec();
    v.extend_from_slice(nameplate);
    v
}

/// Start a symmetric SPAKE2 with a deterministic seed. Writes the outbound
/// SPAKE2 message into `out_msg` (must be >= 33 bytes) and returns its length,
/// plus the opaque session state needed to finish.
pub fn start(seed: [u8; 32], password: &[u8], nameplate: &[u8]) -> (Spake2<Ed25519Group>, Vec<u8>) {
    let rng = SeedRng::from_seed(seed);
    Spake2::<Ed25519Group>::start_symmetric_with_rng(
        &Password::new(password),
        &Identity::new(&identity(nameplate)),
        rng,
    )
}

/// Finish: consume peer's message, return the derived 32-byte pinned secret
/// (HKDF(K)) hex, or empty string on failure.
pub fn finish_to_secret(state: Spake2<Ed25519Group>, peer_msg: &[u8]) -> Option<String> {
    let k = state.finish(peer_msg).ok()?;
    let hk = Hkdf::<Sha256>::new(None, &k);
    let mut out = [0u8; 32];
    hk.expand(b"filament-pair-pake-v1:pinned-secret", &mut out).ok()?;
    Some(hex::encode(out))
}

// ----------------------- C-ABI for the wasm host ----------------------------
// One self-contained call that does start+finish for ONE side, given the
// peer's already-known message. The interop harness calls this twice (once per
// side, native vs wasm) feeding each the OTHER's message.
//
// Layout of the in/out buffer (caller-allocated, 256 bytes):
//   [0..32)   seed
//   [32..64)  reserved
//   in:  peer_msg at [64..64+peer_len)
//   out: result written from [0..) as: msg_len(u32 LE) | msg(33) | secret_hex(64)
//
// For the demo we split into two calls via the higher-level wrappers below;
// this raw export is what the wasm host imports.

use std::sync::Mutex;
static PENDING: Mutex<Vec<(u32, Spake2<Ed25519Group>)>> = Mutex::new(Vec::new());

/// wasm export: begin. Returns a handle (u32) and writes the 33-byte outbound
/// message to `msg_out`. seed/password/nameplate passed as pointers+lens.
#[no_mangle]
pub extern "C" fn pake_begin(
    seed_ptr: *const u8,
    pw_ptr: *const u8, pw_len: usize,
    np_ptr: *const u8, np_len: usize,
    msg_out: *mut u8,
) -> u32 {
    let seed = unsafe { std::slice::from_raw_parts(seed_ptr, 32) };
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    let pw = unsafe { std::slice::from_raw_parts(pw_ptr, pw_len) };
    let np = unsafe { std::slice::from_raw_parts(np_ptr, np_len) };
    let (state, msg) = start(s, pw, np);
    unsafe { std::ptr::copy_nonoverlapping(msg.as_ptr(), msg_out, msg.len()); }
    let mut g = PENDING.lock().unwrap();
    let handle = g.len() as u32;
    g.push((handle, state));
    handle
}

/// wasm export: finish. Consumes peer's 33-byte message, writes 64-byte hex
/// secret to `secret_out`. Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn pake_finish(handle: u32, peer_ptr: *const u8, peer_len: usize, secret_out: *mut u8) -> u32 {
    let peer = unsafe { std::slice::from_raw_parts(peer_ptr, peer_len) };
    let mut g = PENDING.lock().unwrap();
    let pos = match g.iter().position(|(h, _)| *h == handle) { Some(p) => p, None => return 0 };
    let (_, state) = g.remove(pos);
    drop(g);
    match finish_to_secret(state, peer) {
        Some(hexs) => { unsafe { std::ptr::copy_nonoverlapping(hexs.as_ptr(), secret_out, 64); } 1 }
        None => 0,
    }
}

/// Scratch buffers so the wasm host can pass data without its own allocator.
#[no_mangle]
pub extern "C" fn scratch() -> *mut u8 {
    static mut BUF: [u8; 1024] = [0u8; 1024];
    unsafe { core::ptr::addr_of_mut!(BUF) as *mut u8 }
}

// re-export rand_core trait deps
pub use rand_core;
