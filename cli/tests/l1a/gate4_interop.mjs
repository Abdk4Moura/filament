// GATE 4 (browser<->CLI interop): the COMMITTED browser WASM and the NATIVE
// CLI crate derive the SAME pinned secret and mutually pass key confirmation,
// from the same spoken code. Deterministic (no network): one side runs in WASM
// (Node), the other in the native `native_side` helper.
//
// Run: node gate4_interop.mjs
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const PAKE_DIR = '/root/wt-l1a/frontend/src/pake'
const NATIVE = '/root/wt-l1a/pake/target/release/native_side'

// Load the committed wasm-bindgen module (the artifact the browser ships).
const mod = await import(join(PAKE_DIR, 'filament_pake.js'))
const wasmBytes = readFileSync(join(PAKE_DIR, 'filament_pake_bg.wasm'))
await mod.default({ module_or_path: wasmBytes })
const { PakeSession, canonicalCaps } = mod

const enc = (s) => new TextEncoder().encode(s)
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('')
const fromHex = (s) => new Uint8Array(s.match(/.{2}/g).map((h) => parseInt(h, 16)))

// Distinct, realistic fingerprint strings (uppercased a=fingerprint values).
const FP_WASM = 'SHA-256 AA:BB:CC:DD:EE:FF:00:11'
const FP_NATIVE = 'SHA-256 99:88:77:66:55:44:33:22'
const PASSWORD = 'brave-otter-ruby'
const NAMEPLATE = '3141'
const CAPS = 'transfer'

// WASM side starts and emits its element.
const wasm = new PakeSession(enc(PASSWORD), enc(NAMEPLATE))
const wasmMsg = wasm.message()

// Drive the native side: it prints its element, we feed it the WASM element,
// it prints "<secret> <our_confirm> <expect_peer_confirm>".
const native = spawn(NATIVE, [PASSWORD, NAMEPLATE, FP_NATIVE, FP_WASM, CAPS])
let nativeOut = ''
native.stdout.on('data', (d) => (nativeOut += d))
native.stderr.on('data', (d) => process.stderr.write(d))

const done = new Promise((res, rej) => {
  native.on('close', (code) => (code === 0 ? res() : rej(new Error('native exit ' + code))))
})

// Read the native element (first line), then send it the WASM element.
await new Promise((res) => {
  const iv = setInterval(() => {
    if (nativeOut.includes('\n')) { clearInterval(iv); res() }
  }, 10)
})
const nativeMsg = fromHex(nativeOut.split('\n')[0].trim())
native.stdin.write(hex(wasmMsg) + '\n')
native.stdin.end()

// WASM finishes on the native element, derives its secret + confirm MAC.
if (!wasm.finish(nativeMsg)) { console.error('GATE4 FAIL: wasm finish failed'); process.exit(1) }
const wasmSecret = wasm.secret()
const wasmConfirm = wasm.ourConfirm(FP_WASM, FP_NATIVE, canonicalCaps([CAPS]))

await done
const [nativeSecret, nativeConfirmHex, nativeExpectHex] = nativeOut.split('\n')[1].trim().split(' ')

console.log('wasm   secret:', wasmSecret)
console.log('native secret:', nativeSecret)

let ok = true
if (wasmSecret !== nativeSecret) { console.log('  !! secrets differ'); ok = false }

// Cross-verify confirmation MACs: WASM verifies native's, native's expected ==
// wasm's sent.
const nativeConfirm = fromHex(nativeConfirmHex)
if (!wasm.verifyPeerConfirm(FP_WASM, FP_NATIVE, canonicalCaps([CAPS]), nativeConfirm)) {
  console.log('  !! wasm could NOT verify native confirm MAC'); ok = false
} else {
  console.log('wasm verified native confirm MAC: OK')
}
if (hex(wasmConfirm) !== nativeExpectHex) {
  console.log('  !! native expected != wasm sent confirm MAC'); ok = false
} else {
  console.log('native expected == wasm sent confirm MAC: OK')
}

console.log(ok ? 'GATE4 PASS: WASM and native derive the same secret + mutually confirm' : 'GATE4 FAIL')
process.exit(ok ? 0 : 1)
