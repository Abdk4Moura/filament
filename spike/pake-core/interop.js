// SPIKE — WASM<->native SPAKE2 interop harness (item 2: the make/break).
//
// Proves the SAME Rust SPAKE2, compiled to wasm32, agrees on the SAME pinned
// secret with the native build. The WASM side plays peer B (browser); the
// native binary plays peer A (CLI). Both run start_symmetric over the SAME
// password+nameplate and exchange messages; secrets must MATCH.
//
// We use a deterministic seed so the run is reproducible in CI and so we do
// NOT need to wire getrandom-js into the bare Node host (production browser
// path uses OsRng/crypto.getRandomValues; this is a harness-only shortcut).
//
// Run: node interop.js
const fs = require('fs');
const { execFileSync } = require('child_process');
const path = require('path');

const WASM = path.join(__dirname, 'target/wasm32-unknown-unknown/release/pake_core.wasm');
const NATIVE = path.join(__dirname, 'target/debug/native_side');

const PASSWORD = 'brave-otter';   // the spoken words (never sent to server)
const NAMEPLATE = '314';          // server-routed
const SEED_A = '11'.repeat(32);   // native side seed
const SEED_B = '22'.repeat(32);   // wasm side seed

function hexToBytes(h){ return Uint8Array.from(Buffer.from(h,'hex')); }
function bytesToHex(b){ return Buffer.from(b).toString('hex'); }

async function loadWasm(){
  const bytes = fs.readFileSync(WASM);
  // Stubs for the wasm-bindgen describe/throw imports; the seeded path never
  // calls getrandom-js so these are never actually invoked.
  const imports = {
    __wbindgen_placeholder__: {
      __wbindgen_describe: () => {},
      __wbg___wbindgen_throw_1506f2235d1bdba0: (p,l) => { throw new Error('wasm throw'); },
    },
    __wbindgen_externref_xform__: {
      __wbindgen_externref_table_set_null: () => {},
      __wbindgen_externref_table_grow: () => 0,
    },
  };
  // tolerate extra/renamed imports
  const mod = await WebAssembly.compile(bytes);
  for (const imp of WebAssembly.Module.imports(mod)) {
    imports[imp.module] = imports[imp.module] || {};
    if (!(imp.name in imports[imp.module])) imports[imp.module][imp.name] = () => 0;
  }
  const inst = await WebAssembly.instantiate(mod, imports);
  return inst.exports;
}

function wasmWrite(ex, offset, bytes){
  new Uint8Array(ex.memory.buffer, offset, bytes.length).set(bytes);
}
function wasmRead(ex, offset, len){
  return new Uint8Array(ex.memory.buffer.slice(offset, offset+len));
}

async function main(){
  const ex = await loadWasm();
  const base = ex.scratch();            // 1024-byte scratch region in wasm
  const SEED = base, PW = base+64, NP = base+96, MSG = base+160, PEER = base+256, SEC = base+320;

  // --- WASM side (peer B): begin ---
  wasmWrite(ex, SEED, hexToBytes(SEED_B));
  wasmWrite(ex, PW, Buffer.from(PASSWORD));
  wasmWrite(ex, NP, Buffer.from(NAMEPLATE));
  const handle = ex.pake_begin(SEED, PW, PASSWORD.length, NP, NAMEPLATE.length, MSG);
  const wasmMsg = wasmRead(ex, MSG, 33);
  console.log('[wasm] B begin -> msg', bytesToHex(wasmMsg).slice(0,24)+'...');

  // --- Native side (peer A): full (begin + finish using wasm's msg) ---
  const out = execFileSync(NATIVE, ['full', SEED_A, PASSWORD, NAMEPLATE, bytesToHex(wasmMsg)])
                .toString().trim().split(' ');
  const nativeMsg = out[0], nativeSecret = out[1];
  console.log('[native] A full -> msg', nativeMsg.slice(0,24)+'...  secret', nativeSecret.slice(0,16)+'...');

  // --- WASM side: finish using native's msg ---
  wasmWrite(ex, PEER, hexToBytes(nativeMsg));
  const ok = ex.pake_finish(handle, PEER, 33, SEC);
  if (!ok){ console.log('GATE:interop FAILED — wasm finish errored'); process.exit(1); }
  const wasmSecret = Buffer.from(wasmRead(ex, SEC, 64)).toString('latin1');
  console.log('[wasm] B finish -> secret', wasmSecret.slice(0,16)+'...');

  const match = wasmSecret === nativeSecret;
  console.log('\n[gate:browser<->cli interop] secrets match =', match);
  if (!match){
    console.log('  native:', nativeSecret);
    console.log('  wasm  :', wasmSecret);
    process.exit(1);
  }

  // Negative: wasm side with a WRONG password must NOT match native.
  wasmWrite(ex, PW, Buffer.from('tidy-walrus'));
  const h2 = ex.pake_begin(SEED, PW, 'tidy-walrus'.length, NP, NAMEPLATE.length, MSG);
  const wm2 = wasmRead(ex, MSG, 33);
  const out2 = execFileSync(NATIVE, ['full', SEED_A, PASSWORD, NAMEPLATE, bytesToHex(wm2)])
                 .toString().trim().split(' ');
  wasmWrite(ex, PEER, hexToBytes(out2[0]));
  ex.pake_finish(h2, PEER, 33, SEC);
  const wasmSecret2 = Buffer.from(wasmRead(ex, SEC, 64)).toString('latin1');
  const wrongMatches = wasmSecret2 === out2[1];
  console.log('[gate:interop wrong-pw] secrets match (must be false) =', wrongMatches);
  if (wrongMatches){ process.exit(1); }

  console.log('\n=== WASM<->NATIVE INTEROP PROVEN ===');
}
main().catch(e => { console.error(e); process.exit(1); });
