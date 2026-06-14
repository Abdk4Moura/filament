// GATE 8 (byte-identity): the browser's channelOf/proofFor (devices.js) and the
// CLI's channel_of/proof_for (cli/src/main.rs) MUST produce byte-identical
// output, or browsers and CLIs silently stop recognizing each other as known
// devices. Both are pinned here to the SAME external vectors the Rust unit test
// `tests::proof_matches_browser` asserts (computed with openssl: e.g.
//   printf 'filament-proof2:u1|u1|u2|FPA|FPB' | openssl dgst -sha256 -hmac s3cret
// and  printf 'filament-pair:topsecret' | openssl dgst -sha256).
//
// Run: node cli/tests/l1a/gate8_byte_identity.mjs
// Pure (no network, no WASM, no browser): devices.js's channelOf/proofFor use
// only WebCrypto (global `crypto.subtle` on Node >= 20) and TextEncoder.
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
// repo root is three levels up: cli/tests/l1a -> cli/tests -> cli -> <root>
const DEVICES = join(here, '..', '..', '..', 'frontend', 'src', 'lib', 'devices.js')
const { channelOf, proofFor } = await import(DEVICES)

// The SAME vectors pinned in cli/src/main.rs tests::proof_matches_browser.
const PROOF_WANT = 'f98c3b6b7a70ebdf4b200680e83383881bdb1a11476283507359c55ef03a8474'
const CHANNEL_WANT = '1e32e46e93691c29d9c0305545a10c86a00ae9f3c43d4eea3c7423c1528f9b5d'

let ok = true
const check = (label, got, want) => {
  if (got !== want) {
    console.log(`  !! ${label}: got ${got} want ${want}`)
    ok = false
  } else {
    console.log(`  ${label}: OK`)
  }
}

// proofFor must order-normalize uids and fingerprints — feed BOTH orderings and
// require the same digest (exactly the CLI's proof_for contract).
check('proofFor (u2,u1 / FPB,FPA)', await proofFor('s3cret', 'u1', 'u2', 'u1', 'FPB', 'FPA'), PROOF_WANT)
check('proofFor (u1,u2 / FPA,FPB)', await proofFor('s3cret', 'u1', 'u1', 'u2', 'FPA', 'FPB'), PROOF_WANT)
check('channelOf (topsecret)', await channelOf('topsecret'), CHANNEL_WANT)

console.log(ok
  ? 'GATE8 PASS: browser channelOf/proofFor == CLI channel_of/proof_for (byte-identical)'
  : 'GATE8 FAIL: browser/CLI device-identity primitives DIVERGED')
process.exit(ok ? 0 : 1)
