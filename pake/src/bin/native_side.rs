//! Native helper for the WASM<->native interop gate (gate 4). Mirrors the
//! browser's `PakeSession` so a Node harness can run one side in WASM and the
//! other natively and assert they derive the SAME secret + mutually confirm.
//!
//! Production OsRng (no seeding) — agreement, not determinism, is the assertion.
//!
//! Protocol (one process, one SPAKE2 session):
//!   argv: native_side <password> <nameplate> <my_fp> <their_fp> <caps_csv>
//!   1. prints its own SPAKE2 element hex on the FIRST stdout line, then flushes
//!   2. reads the peer's element hex from ONE stdin line
//!   3. prints "<secret_hex> <our_confirm_hex> <expect_peer_confirm_hex>"
//!
//! The harness pipes the two sides' messages across and compares secrets.

use std::io::{BufRead, Write};

use filament_pake::{canonical_caps, confirm_mac, confirm_dirs, finish, our_confirm, secret_from_k, sort_fps, start};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let password = a[1].as_bytes();
    let nameplate = a[2].as_bytes();
    let my_fp = &a[3];
    let their_fp = &a[4];
    let caps = canonical_caps(&a[5].split(',').map(String::from).collect::<Vec<_>>());

    let (state, msg) = start(password, nameplate);
    // Phase 1: emit our element, flush so the harness can route it.
    let mut out = std::io::stdout();
    writeln!(out, "{}", hex::encode(&msg)).unwrap();
    out.flush().unwrap();

    // Phase 2: read the peer's element.
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    let peer = hex::decode(line.trim()).expect("peer msg hex");

    let k = finish(state, &peer).expect("finish");
    let secret = secret_from_k(&k);
    let our = our_confirm(&k, my_fp, their_fp, &caps);
    // Also emit the MAC we EXPECT from the peer (for the harness to cross-check).
    let (lo, hi) = sort_fps(my_fp, their_fp);
    let (_send, expect_dir) = confirm_dirs(my_fp, lo);
    let expect = confirm_mac(&k, expect_dir, lo, hi, &caps);
    writeln!(out, "{} {} {}", secret, hex::encode(&our), hex::encode(&expect)).unwrap();
    out.flush().unwrap();
}
