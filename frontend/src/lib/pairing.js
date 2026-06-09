// L1-a (PAKE v2) — the browser half of secure first-pairing.
//
// Mirrors the CLI `pair_cmd` exactly, using the SHARED Rust→WASM SPAKE2 core
// (src/pake). The server only ever sees the numeric nameplate; the password
// (words) is minted/typed CLIENT-SIDE and never transmitted. A strong key K is
// agreed over the opaque `signal` relay BEFORE the pinned secret exists; the
// 32-byte device secret is HKDF(K) — agreed, never sent. A key-confirmation MAC
// folds the SORTED DTLS fingerprints + caps so a server that substitutes a DTLS
// cert (or rewrites caps) is detected and the pairing aborts.
//
// Downgrade-refusal (spec §6.1): a v2 pairing NEVER sends or stores a pair-keep
// secret over the DataChannel; a received pair-keep means the peer is v1 → the
// caller refuses with "update to pair securely".

import initPake, { PakeSession, canonicalCaps, normCode, splitCode } from '../pake/filament_pake.js'
import pakeWasmUrl from '../pake/filament_pake_bg.wasm?url'

let _ready = null
/// Initialize the WASM module once (idempotent). Vite serves the .wasm via ?url.
export async function pakeReady() {
  if (!_ready) _ready = initPake({ module_or_path: pakeWasmUrl })
  return _ready
}

const utf8 = (s) => new TextEncoder().encode(s)

// The caps v2 first-pairing agrees on. "transfer" is the L0 baseline (always
// allowed); deny-by-default future caps are NOT granted at enrollment. BOTH
// sides MAC the identical canonical string (spec §8 / gate 5).
export const PAIR_V2_CAPS = ['transfer']

/// A single v2 pairing attempt with one peer. Drives:
///   start → (send our element over signal) → finish on peer's element →
///   once K AND both fingerprints known → send confirm MAC → verify peer's →
///   on success: derive the pinned secret (HKDF(K)).
///
/// `sendSignal(data)` relays an opaque payload to the peer via the server.
/// `getFingerprints()` returns {mine, theirs} once SDP is exchanged (or null).
export class PakePairing {
  constructor({ nameplate, password, caps = PAIR_V2_CAPS, sendSignal, getFingerprints }) {
    this.nameplate = nameplate
    this.password = password
    this.caps = caps
    this.capsCanon = canonicalCaps(caps)
    this.sendSignal = sendSignal
    this.getFingerprints = getFingerprints
    this.session = new PakeSession(utf8(password), utf8(nameplate))
    this.sentMsg = false
    this.sentConfirm = false
    this.haveK = false
    this.secret = null // set ONLY after confirmation passes
    this.aborted = null // abort reason if the pairing was refused
    this._pendingConfirmMac = null // a confirm that arrived before fingerprints
  }

  /// Send our SPAKE2 element (idempotent). Call once the peer sid is known.
  sendOurMessage() {
    if (this.sentMsg) return
    const msg = this.session.message()
    this.sendSignal({ type: 'pake-msg', v: 2, msg: b64(msg) })
    this.sentMsg = true
  }

  /// Try to send our key-confirmation MAC once K + both fingerprints exist.
  tryConfirm() {
    if (this.sentConfirm || !this.haveK || this.secret || this.aborted) return
    const fps = this.getFingerprints()
    if (!fps) return
    const mac = this.session.ourConfirm(fps.mine, fps.theirs, this.capsCanon)
    if (!mac) return
    this.sendSignal({ type: 'pake-confirm', v: 2, mac: b64(mac), caps: this.caps })
    this.sentConfirm = true
    // A confirm from the peer may have arrived first — process it now.
    if (this._pendingConfirmMac) this._verify(this._pendingConfirmMac)
  }

  /// Handle an inbound opaque signal. Returns true if it was a PAKE message
  /// (and thus consumed); false if it should fall through to WebRTC.
  onSignal(data) {
    if (data?.type === 'pake-msg') {
      if (!this.haveK) {
        const peer = b64d(data.msg)
        if (!this.session.finish(peer)) {
          this.aborted = 'malformed key-exchange message'
          return true
        }
        this.haveK = true
        this.tryConfirm()
      }
      return true
    }
    if (data?.type === 'pake-confirm') {
      const mac = b64d(data.mac)
      if (!this.haveK) {
        // Out-of-order: stash until K is derived (shouldn't happen — msg
        // precedes confirm by per-sender ordering — but be safe).
        this._pendingConfirmMac = mac
        return true
      }
      this._verify(mac)
      return true
    }
    return false
  }

  _verify(mac) {
    const fps = this.getFingerprints()
    if (!fps) {
      // Can't verify without fingerprints; stash and retry on tryConfirm.
      this._pendingConfirmMac = mac
      return
    }
    if (this.session.verifyPeerConfirm(fps.mine, fps.theirs, this.capsCanon, mac)) {
      // CONFIRMED. Derive the pinned secret from K — agreed, never transmitted.
      this.secret = this.session.secret()
    } else {
      this.aborted = 'key confirmation failed — wrong code or tampering (a server cannot forge this)'
    }
  }
}

// Minimal base64 helpers for the opaque 33-byte element / 32-byte MAC payloads.
function b64(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}
function b64d(str) {
  const s = atob(str)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

/// Parse a typed spoken code into {nameplate, password} the SAME way the CLI
/// does (shared WASM normCode/splitCode), so K agrees.
export function parseSpokenCode(typed) {
  const normalized = normCode(typed)
  const [nameplate, password] = splitCode(normalized)
  return { nameplate, password, normalized }
}
