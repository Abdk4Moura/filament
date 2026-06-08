//! SPIKE native helper for the WASM<->native interop harness.
//! Usage:
//!   native_side begin  <seedhex32> <password> <nameplate>   -> prints msg hex
//!   native_side full   <seedhex32> <password> <nameplate> <peer_msg_hex>
//!        -> prints "<own_msg_hex> <pinned_secret_hex>"
use pake_core::{start, finish_to_secret};
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a[1].as_str();
    let seed_v = hex::decode(&a[2]).unwrap();
    let mut seed = [0u8; 32]; seed.copy_from_slice(&seed_v);
    let pw = a[3].as_bytes();
    let np = a[4].as_bytes();
    match mode {
        "full" => {
            let (state, msg) = start(seed, pw, np);
            let peer = hex::decode(&a[5]).unwrap();
            let secret = finish_to_secret(state, &peer).expect("finish failed");
            println!("{} {}", hex::encode(msg), secret);
        }
        "begin" => {
            let (_state, msg) = start(seed, pw, np);
            println!("{}", hex::encode(msg));
        }
        _ => panic!("bad mode"),
    }
}
