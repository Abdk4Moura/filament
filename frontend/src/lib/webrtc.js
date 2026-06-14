// PeerLink: one live connection to one remote peer.
//
// Owns an RTCPeerConnection + a single RTCDataChannel and moves files across it
// in chunks. The server never sees a byte, it only relayed the SDP/ICE that
// got us here. Control messages are JSON strings; file chunks are ArrayBuffers.
//
// Transfer lifecycle (both directions surfaced to the UI via onTransfer):
//   offered      -> receiver has been told a file is coming, not yet accepted
//   transferring -> bytes are moving (progress 0..1)
//   complete     -> done; a receive transfer also carries { url, blob }
//   declined     -> receiver said no
//   failed       -> connection/transfer error
import { log } from './log.js'

const rlog = log.scope('rtc')

const CTRL = {
  OFFER: 'file-offer',
  ACCEPT: 'file-accept',
  DECLINE: 'file-decline',
  END: 'file-end',
  BRB: 'brb', // C21: "I'm stepping away (file picker / tab hidden), hold the line"
  BACK: 'back',
  PAIR_KEEP: 'pair-keep', // C12: here's a secret, remember me as a known device
  PAIR_KEEP_ACK: 'pair-keep-ack', // C27: the human's answer, sender keeps only confirmed secrets
  PAIR_PROOF: 'pair-proof', // C20: HMAC proof I hold a secret you remembered
  PAIR_PROOF_ACK: 'pair-proof-ack', // C27: verifier's verdict, a rejected prover stops claiming acquaintance
  STATE: 'state', // C30 ph3: periodic link truth {transfers, trusted, away}, divergence repair
  DELIVERY_ACK: 'delivery-ack', // P4: receiver verified the WHOLE file (sha256 matched), sender marks done only on this
}

// P4: bound the whole-file re-fetch so a genuinely-corrupt payload fails CLEANLY
// instead of looping forever; the partial is kept, the transfer stays resumable.
const MAX_VERIFY_FAILS = 2
// P4: if a CLI peer is too old to send a delivery-ack, accept on size+drain after
// this window so a send never hangs against an ack-less receiver (interop).
const ACK_FALLBACK_MS = 30000

// P4 test shims, INERT unless a `?test=` query flag (persisted to localStorage)
// is set, so they ship in the bundle with zero effect on real users. They exist
// only to drive the deterministic browser↔CLI integrity e2e:
//   ?test=fixedid    -> mint a deterministic transfer id so the CLI's
//                       FILAMENT_TEST_CORRUPT_RECV=<id> hook can target it.
//   ?test=trunconce  -> on the RECEIVER, drop the final chunk before file-end
//                       exactly once, inducing a truncated receive so the
//                       whole-file verify + re-request path is exercised live.
//   ?test=freeze     -> P0: after FREEZE_AFTER_BYTES on a transfer, make
//                       _streamFile's channel.send a no-op for THAT transfer
//                       once (one-shot) while the channel stays open, a
//                       faithful NAT-rebind black-hole that drives the in-flight
//                       stall watchdog + correction ladder. Mirrors the Rust
//                       client's FILAMENT_TEST_FREEZE_AFTER_BYTES. Inert for
//                       real users (TEST.freeze is false).
//   ?test=freezepersist -> P5: like ?test=freeze but PERSISTENT, EVERY
//                       _streamFile run (not just the first) black-holes after
//                       FREEZE_AFTER_BYTES, so a relayOnly link rebuilt on stall
//                       (P1) STAYS the carrying path: the relay is a one-way
//                       trapdoor we then escape. Lifted for any send begun after
//                       `?healafter=<ms>` (the network "heals") so the P5 upgrade
//                       prober's re-probe can re-detect a direct route and the
//                       verify-before-commit path runs live. Mirrors the Rust
//                       FILAMENT_TEST_FREEZE_PERSIST + FILAMENT_TEST_DIRECT_UNBLOCK_MS.
//                       Inert for real users.
function _testFlags() {
  try {
    const q = new URLSearchParams(window.location.search).get('test')
    if (q != null) localStorage.setItem('filamentTest', q)
    return (q ?? localStorage.getItem('filamentTest') ?? '').split(',').filter(Boolean)
  } catch {
    return []
  }
}
const TEST = (() => {
  const f = _testFlags()
  return {
    fixedId: f.includes('fixedid'),
    truncOnce: f.includes('trunconce'),
    freeze: f.includes('freeze'),
    freezePersist: f.includes('freezepersist'),
  }
})()
// P5 test knob: ms after page load before the persistent freeze "heals" (the
// network recovers and a direct path becomes possible). Mirrors the Rust
// FILAMENT_TEST_DIRECT_UNBLOCK_MS. Only meaningful with ?test=freezepersist.
const HEAL_AFTER_MS = (() => {
  try {
    const v = parseInt(new URLSearchParams(window.location.search).get('healafter') || '', 10)
    return Number.isFinite(v) && v >= 0 ? v : Infinity
  } catch {
    return Infinity
  }
})()
const _bootAt = (() => {
  try {
    return performance.now()
  } catch {
    return Date.now()
  }
})()

// P0 test knob: bytes a frozen transfer is allowed to send before the data path
// goes dark (mirrors FILAMENT_TEST_FREEZE_AFTER_BYTES). Overridable via
// ?freezeafter=<bytes>; defaults to a value a multi-chunk file crosses quickly.
const FREEZE_AFTER_BYTES = (() => {
  try {
    const v = parseInt(new URLSearchParams(window.location.search).get('freezeafter') || '', 10)
    return Number.isFinite(v) && v > 0 ? v : 700000
  } catch {
    return 700000
  }
})()

// P0 (GAP-1): the in-flight STALL watchdog. We tick every STALL_TICK_MS and, if
// a transfer is `transferring` over an OPEN channel yet no bytes have moved (and
// the SCTP send buffer isn't draining) for >= STALL_MS, the data path has gone
// dark (NAT-rebind black-hole / path death) even though the channel reports
// `open` and the pc stays `connected`. Mirrors the Rust client's idle_ms()
// watchdog (STALL_MS_DEFAULT=6000, cli/src/net.rs:55). The threshold is on TIME
// SINCE THE LAST BYTE, never throughput, so a slow-but-moving link never trips.
const STALL_TICK_MS = 2000
// Override STALL_MS via ?stallms=<ms> for the A/B baseline (huge => the watchdog
// is effectively off and a freeze must HANG), mirroring FILAMENT_STALL_MS.
const STALL_MS = (() => {
  try {
    const v = parseInt(new URLSearchParams(window.location.search).get('stallms') || '', 10)
    return Number.isFinite(v) && v > 0 ? v : 6000
  } catch {
    return 6000
  }
})()
// Ladder ceiling (mirror Rust STALL_MAX_REPAIRS' intent): rungs a→c, then fail
// clean through _failActive (paused/resumable, never silently dead).
const MAX_STALL_ATTEMPTS = 3

// P5 (GAP-6): the relay→direct UPGRADE prober. P1 makes a stalled direct path
// fall to the TURN relay, but that's a ONE-WAY TRAPDOOR: once on relay the link
// STAYS on relay even after the network heals and direct would work again. P5
// fixes that: while serving on relay, periodically restartIce() on the SAME PC
// (the data channel SURVIVES an ICE restart, non-disruptive) and re-detect the
// route; if a direct candidate-pair wins re-nomination AND holds (verify-before-
// commit), commit to direct and release the relay. "Relay is a way-station, not
// a destination." Mirrors the Rust upgrade prober (cli/src/net.rs).
//
// Cadence: eager FIRST probe (the cause is often a transient hiccup that heals in
// seconds), then each failed probe backs off toward a calm STEADY cap so a
// symmetric-NAT peer that will NEVER get direct isn't hammered (CPU/battery).
const UPGRADE_FIRST_MS = (() => {
  try {
    const v = parseInt(new URLSearchParams(window.location.search).get('upgradefirstms') || '', 10)
    return Number.isFinite(v) && v > 0 ? v : 5000
  } catch {
    return 5000
  }
})()
const UPGRADE_STEADY_MS = (() => {
  try {
    const v = parseInt(new URLSearchParams(window.location.search).get('upgradesteadyms') || '', 10)
    return Number.isFinite(v) && v > 0 ? v : 25000
  } catch {
    return 25000
  }
})()
// VERIFY-before-commit window: once re-detection reports a non-relay route, it
// must READ non-relay AND keep moving bytes continuously for this long before we
// cut over. Prevents thrash on a flaky direct path that wins re-nomination then
// immediately re-stalls (the mandatory no-flap guard).
const UPGRADE_VERIFY_MS = (() => {
  try {
    const v = parseInt(new URLSearchParams(window.location.search).get('upgradeverifyms') || '', 10)
    return Number.isFinite(v) && v > 0 ? v : 2500
  } catch {
    return 2500
  }
})()

let _tid = 0
const nextTransferId = () =>
  TEST.fixedId ? `webtest-${++_tid}` : `t${++_tid}_${Math.random().toString(36).slice(2, 7)}`

// Content identity for resume (docs/cli-resilience.md C7): sha256 over the
// first 256 KiB, carried in file-offer. Disk-based receivers (the CLI) use it
// to reject a different file wearing the same name + size before offsetting
// into it. Returns null where crypto.subtle is unavailable (insecure origins);
// receivers then fall back to size-only matching.
const HEAD_BYTES = 256 * 1024
async function headHash(file) {
  try {
    const buf = await file.slice(0, Math.min(HEAD_BYTES, file.size)).arrayBuffer()
    const digest = await crypto.subtle.digest('SHA-256', buf)
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
  } catch {
    return null
  }
}

// P4 (whole-file integrity): hex sha256 over the WHOLE file, carried in the
// file-offer alongside `head`. The receiver recomputes it over every byte it
// received and only declares the transfer done (and acks it) on a match, so a
// silently-truncated/corrupt receive (the 7 KB stub class) is caught. Wire-
// compatible with the Rust client's offer `full` field. Web Crypto has no
// incremental digest, so we hash the whole buffer for the common case and fall
// back to slice-accumulation above a threshold to bound peak memory. Returns
// null where crypto.subtle is unavailable (insecure origin), receivers then
// degrade to size-only acceptance, exactly like headHash.
const FULL_DIRECT_MAX = 64 * 1024 * 1024 // hash in one shot below this
const FULL_SLICE = 8 * 1024 * 1024 // slice size above it
async function fullHash(file) {
  try {
    if (!crypto?.subtle) return null
    let bytes
    if (file.size <= FULL_DIRECT_MAX) {
      bytes = new Uint8Array(await file.arrayBuffer())
    } else {
      // Web Crypto can't update incrementally; concatenate slices into one
      // buffer (bounded read pressure, we never hold two full copies of a
      // slice). Peak is the file size in one contiguous buffer, which the
      // single-shot path would also need, so this only caps per-read memory.
      bytes = new Uint8Array(file.size)
      let off = 0
      while (off < file.size) {
        const end = Math.min(off + FULL_SLICE, file.size)
        const part = new Uint8Array(await file.slice(off, end).arrayBuffer())
        bytes.set(part, off)
        off = end
      }
    }
    const digest = await crypto.subtle.digest('SHA-256', bytes)
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
  } catch {
    return null
  }
}

// P4: hex sha256 over an assembled Blob (the received bytes), to compare against
// the offered `full`. Same null-on-insecure-origin degradation as fullHash.
async function blobHash(blob) {
  try {
    if (!crypto?.subtle) return null
    const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer())
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
  } catch {
    return null
  }
}

// Deterministic negotiation roles (#1, hardened in #8/#10): prefer the stable
// per-tab uid, it survives reconnects, so both sides always compare the SAME
// pair even when one of them holds a stale sid. Fall back to sids, then to
// polite (wait for the offer) when we know nothing yet.
export function politeRole({ myUid, peerUid, myId, peerId }) {
  if (myUid && peerUid && myUid !== peerUid) return myUid > peerUid
  if (myId && peerId) return myId > peerId
  return true
}

export class PeerLink {
  /**
   * @param {object}  o
   * @param {string}  o.id          remote peer id
   * @param {string}  o.name        remote display name
   * @param {Array}   o.iceServers  RTCIceServer[]
   * @param {number}  o.chunkSize
   * @param {boolean} o.initiator   true if WE create the offer + data channel
   * @param {(data:any)=>void}      o.sendSignal  relay signaling to this peer
   * @param {(status:string)=>void} o.onStatus    'connecting'|'ready'|'failed'
   * @param {(t:object)=>void}      o.onTransfer  transfer state changed
   */
  constructor({ id, name, iceServers, relayOnly, chunkSize, polite, peerUid, stores, sendSignal, onStatus, onTransfer, onRoute, onChannelOpen, onStuck, onStall, watchdogMs, onPairKeep, onPairKeepAck, onPairProof, onPairProofAck, onPeerStateDiverged, onPtyData, onPtyClose, onPtyReady, onCaps }) {
    this.id = id
    this.name = name
    this.chunkSize = chunkSize || 64 * 1024
    this.sendSignal = sendSignal
    this.onStatus = onStatus || (() => {})
    this.onTransfer = onTransfer || (() => {})
    this.onRoute = onRoute || (() => {})
    this.onChannelOpen = onChannelOpen || (() => {})
    // P0: escalation hook fired at rung (c) when an in-flight stall persists past
    // the in-place repair ladder. P1 wires this to the relay-preferred rebuild +
    // the amber UI; until then it's a no-op (the ladder still fails clean via
    // _failActive on exhaustion, partials preserved).
    this.onStall = onStall || (() => {})
    this.onPairKeep = onPairKeep || (() => {}) // C12: peer handed us a pair secret
    this.onPairKeepAck = onPairKeepAck || (() => {}) // C27: peer answered our remember offer
    this.onPairProof = onPairProof || (() => {}) // C20: peer claims to be a known device
    this.onPairProofAck = onPairProofAck || (() => {}) // C27: peer judged our proof
    this.onPeerStateDiverged = onPeerStateDiverged || (() => {}) // C30 ph3: one-sided belief detected
    // web-shell: the Terminal component reassigns these directly on the link.
    this.onPtyData = onPtyData || (() => {}) // raw PTY bytes (Uint8Array) from the peer
    this.onPtyClose = onPtyClose || (() => {}) // shell exited / stream closed
    this.onPtyReady = onPtyReady || (() => {}) // pty-open-ack arrived
    this.onCaps = onCaps || (() => {}) // peer announced capabilities (e.g. shell)
    this.peerShell = false // does the peer offer a web-shell? (set by a 'caps' msg)
    this._ptySid = null
    this._ptySession = null // stable PTY session id, reused across reconnects (#4)
    this.route = null // 'local' | 'direct' | 'relayed'

    // Resume support: a stable per-tab identity for the remote peer, plus
    // hook-owned stores that OUTLIVE this link, partial receive buffers and
    // unfinished outgoing files survive a drop and resume on the next link.
    this.peerUid = peerUid || null
    this.stores = stores || { partials: new Map(), outgoing: new Map() }

    // Perfect negotiation (docs/resilience.md RED-1): exactly one peer per pair
    // is "impolite" and owns the offer; the polite peer yields on a glare.
    this.polite = polite
    this._makingOffer = false
    this._ignoreOffer = false
    this._signalQ = Promise.resolve() // per-peer FIFO: an offer lands before its candidates
    this._pendingCandidates = [] // candidates that arrived before the remote description

    this.transfers = new Map() // id -> transfer state (mirrored to the UI)
    this._outgoingFiles = new Map() // id -> { file, sid } streaming on THIS link
    this._incomingBySid = new Map() // sid -> transferId (chunk routing, #4)
    this._nextSid = 1 // channel-local stream id assigned per transfer
    this._drainWaiters = [] // backpressure waiters fed by one shared onbufferedamountlow
    this._closed = false // guards late callbacks after teardown (#3)
    this._dcTimer = null // grace timer for transient 'disconnected' (#6)

    // P0 (GAP-1): in-flight bytes-moved liveness. `_bytesMoved` counts FILE
    // bytes sent + received on this link (PTY bytes excluded, file-transfer
    // liveness only). The watchdog compares it (and the SCTP send buffer level)
    // against the last tick's snapshot to tell "data wedged, link alive" (→ the
    // correction ladder) from a slow-but-moving link (→ no action).
    this._bytesMoved = 0
    this._lastMovedSnapshot = 0
    this._lastBuffered = 0
    this._stallIdleMs = 0 // accumulated no-progress time across ticks
    this._stallEpisode = null // {rung, at} latch: prevents re-entering a rung mid-convergence (mirrors Rust repair_in_flight)
    this._stallTimer = null // the watchdog interval (armed on channel open)

    // P5 (GAP-6): the relay→direct upgrade prober. Armed when the route becomes
    // 'relayed', disarmed when it's 'direct'/'local'. `_upgradeTimer` is the
    // backoff timer; `_upgradeDelay` is the current (doubling) cadence;
    // `_upgradeVerify` is the in-progress verify latch {since, bytesAt}.
    this._upgradeTimer = null
    this._upgradeDelay = UPGRADE_FIRST_MS
    this._upgradeVerify = null
    this._upgrading = false // re-entrancy guard while a probe/verify is mid-flight

    // P1 (GAP-4): when this link is rebuilt relay-preferred after a chronically
    // stalled direct/STUN path, force EVERY ICE candidate through the TURN relay
    // (`iceTransportPolicy:'relay'`), the same auto-relay the Rust client takes
    // at ladder exhaustion. The amber RELAY UI then lights itself off the normal
    // `_detectRoute()`→onRoute('relayed') path; P5 later upgrades back to direct.
    this.relayOnly = !!relayOnly
    this.pc = new RTCPeerConnection({
      iceServers,
      ...(this.relayOnly ? { iceTransportPolicy: 'relay' } : {}),
    })
    this.pc.onicecandidate = (e) => {
      if (e.candidate) {
        rlog.trace('ice candidate', this.id.slice(-6), e.candidate.candidate)
        this.sendSignal({ type: 'candidate', candidate: e.candidate })
      }
    }
    // All (re)negotiation funnels through here, we never hand-roll offers.
    // Explicit createOffer (not the no-arg setLocalDescription()) for older
    // Safari, where the implicit form throws and silently kills the handshake.
    this.pc.onnegotiationneeded = async () => {
      try {
        this._makingOffer = true
        const offer = await this.pc.createOffer()
        await this.pc.setLocalDescription(offer)
        this.sendSignal({ type: 'description', description: this.pc.localDescription })
      } catch (err) {
        rlog.error('negotiation failed', this.id.slice(-6), err)
      } finally {
        this._makingOffer = false
      }
    }
    this.pc.ondatachannel = (e) => this._setChannel(e.channel)
    this.pc.onconnectionstatechange = () => {
      const s = this.pc.connectionState
      rlog.trace('connectionState', this.id.slice(-6), s)
      if (s === 'connected') {
        clearTimeout(this._dcTimer)
        clearTimeout(this._watchdog) // established, watchdog stands down (#8)
        this.onStatus('ready')
        this._detectRoute() // which physical path did ICE actually pick?
      } else if (s === 'disconnected') {
        rlog.debug('peer disconnected, attempting recovery', this.id.slice(-6))
        // Usually a transient blip (#6): show 'connecting' (or keep 'away' if
        // they announced the absence), nudge an ICE restart from the impolite
        // side, and only fail if it doesn't recover in time.
        this.onStatus((this._awayUntil || 0) > Date.now() ? 'away' : 'connecting')
        if (!this.polite) {
          try {
            rlog.debug('restarting ICE (repair)', this.id.slice(-6))
            this.pc.restartIce()
          } catch {}
        }
        clearTimeout(this._dcTimer)
        // Dynamic grace (#12/C21): 6s mid-transfer (fail fast, resume covers
        // it); a peer that declared `brb` gets its announced window; 45s for
        // an unannounced idle drop (mobile pickers suspend the whole tab).
        const midTransfer = [...this.transfers.values()].some((t) => t.status === 'transferring')
        const awayMs = Math.max(0, (this._awayUntil || 0) - Date.now())
        const grace = midTransfer ? 6000 : awayMs > 0 ? awayMs + 15000 : 45000
        this._dcTimer = setTimeout(() => {
          if (this.pc.connectionState !== 'connected') {
            this.onStatus('failed')
            this._failActive()
          }
        }, grace)
      } else if (s === 'failed') {
        clearTimeout(this._dcTimer)
        this.onStatus('failed')
        this._failActive()
      } else if (s === 'connecting' || s === 'new') {
        this.onStatus('connecting')
      }
    }

    // The impolite peer owns the data channel; creating it triggers the first
    // negotiationneeded → offer. The polite peer just answers.
    if (!polite) this._setChannel(this.pc.createDataChannel('filament'))

    // Establishment watchdog (#8): if signaling is lost (offer to a dead sid,
    // peer suspended, swallowed SDP error), the connection would otherwise sit
    // at 'connecting' FOREVER, ICE only times out once descriptions exchange.
    // Let the hook tear down and retry instead of hanging.
    this.onStuck = onStuck || null
    this._watchdog = setTimeout(() => {
      if (!this._closed && this.pc.connectionState !== 'connected') this.onStuck?.()
    }, watchdogMs || 15000)
  }

  // --------------------------------------------------------------- signaling
  // Relayed signals are processed STRICTLY IN ORDER per peer (docs/resilience.md
  // RED-2): otherwise an offer and the candidates that follow it race, and a
  // candidate applied before the remote description is set gets dropped.
  enqueueSignal(data) {
    this._signalQ = this._signalQ
      .then(() => this._handleSignal(data))
      .catch((err) => rlog.error('signal handling failed', this.id.slice(-6), err))
    return this._signalQ
  }

  async _handleSignal(data) {
    if (data.type === 'description') {
      const description = data.description
      const collision =
        description.type === 'offer' && (this._makingOffer || this.pc.signalingState !== 'stable')
      this._ignoreOffer = !this.polite && collision
      if (this._ignoreOffer) return // impolite peer keeps its own offer
      await this.pc.setRemoteDescription(description) // polite peer rolls back implicitly on a glare
      await this._flushCandidates()
      if (description.type === 'offer') {
        const answer = await this.pc.createAnswer() // explicit, for older Safari
        await this.pc.setLocalDescription(answer)
        this.sendSignal({ type: 'description', description: this.pc.localDescription })
      }
    } else if (data.type === 'candidate') {
      // Hold candidates until there's a remote description to attach them to.
      if (!this.pc.remoteDescription) {
        this._pendingCandidates.push(data.candidate)
        return
      }
      try {
        await this.pc.addIceCandidate(data.candidate)
      } catch (err) {
        if (!this._ignoreOffer) rlog.warn('addIceCandidate failed', this.id.slice(-6), err)
      }
    }
  }

  async _flushCandidates() {
    const pending = this._pendingCandidates
    this._pendingCandidates = []
    for (const c of pending) {
      try {
        await this.pc.addIceCandidate(c)
      } catch (err) {
        rlog.warn('queued candidate failed', this.id.slice(-6), err)
      }
    }
  }

  // Inspect the ICE stats to learn which path the connection actually took:
  //   local   (host↔host, i.e. straight across the LAN, never hit the internet)
  //   direct  (peer-to-peer over the internet, NAT-traversed, no relay)
  //   relayed (falling back through a TURN relay)
  // ICE renominates occasionally, so we poll a few times after connecting.
  // PURE read of the currently-selected candidate-pair route (no commit, no UI,
  // no prober side-effects). Returns 'local'|'direct'|'relayed', or null when no
  // pair is selected yet / getStats is unsupported. Shared by _detectRoute (the
  // committing path) and the P5 prober's verify (which must NOT commit until the
  // path is verified, see _beginUpgradeVerify).
  async _measureRoute() {
    if (this._closed) return null
    try {
      const stats = await this.pc.getStats()
      const cands = {}
      let selected = null
      let transportSelectedId = null
      stats.forEach((r) => {
        if (r.type === 'local-candidate' || r.type === 'remote-candidate') cands[r.id] = r
        if (r.type === 'transport' && r.selectedCandidatePairId) transportSelectedId = r.selectedCandidatePairId
      })
      stats.forEach((r) => {
        if (r.type !== 'candidate-pair') return
        if (r.id === transportSelectedId || (!transportSelectedId && r.state === 'succeeded' && (r.nominated || r.selected)))
          selected = r
      })
      if (!selected) return null
      const lt = cands[selected.localCandidateId]?.candidateType
      const rt = cands[selected.remoteCandidateId]?.candidateType
      if (lt === 'relay' || rt === 'relay') return 'relayed'
      if (lt === 'host' && rt === 'host') return 'local'
      return 'direct'
    } catch {
      return null // getStats unsupported
    }
  }

  async _detectRoute(attempt = 0) {
    if (this._closed) return null
    const route = await this._measureRoute()
    if (this._closed) return null
    if (!route) {
      if (attempt < 5) setTimeout(() => this._detectRoute(attempt + 1), 400)
      return null
    }
    if (route !== this.route) {
      this.route = route
      this.onRoute(route)
    }
    // P5: arm the upgrade prober whenever we're serving on relay; disarm it the
    // moment we're on a direct/local path (nothing to upgrade away from). This
    // runs on the initial connect detection AND every prober re-poll, so a route
    // that drops back to relay re-arms automatically.
    if (route === 'relayed') this._armUpgradeProber()
    else this._disarmUpgradeProber()
    return route
  }

  // ---------------------------------------------------- P5 relay→direct upgrade
  // Begin probing for a direct path while serving on relay. Idempotent. The
  // schedule is: first probe at UPGRADE_FIRST_MS (eager, the cause is often a
  // transient hiccup), then each failed probe doubles toward UPGRADE_STEADY_MS.
  _armUpgradeProber() {
    if (this._closed || this._upgradeTimer) return
    rlog.debug('upgrade prober armed (on relay, probing for a direct path)', this.id.slice(-6))
    this._upgradeDelay = UPGRADE_FIRST_MS
    this._scheduleUpgradeProbe(this._upgradeDelay)
  }

  _disarmUpgradeProber() {
    if (this._upgradeTimer) {
      clearTimeout(this._upgradeTimer)
      this._upgradeTimer = null
    }
    this._upgradeVerify = null
    this._upgrading = false
    this._upgradeDelay = UPGRADE_FIRST_MS
  }

  _scheduleUpgradeProbe(delay) {
    if (this._closed) return
    clearTimeout(this._upgradeTimer)
    this._upgradeTimer = setTimeout(() => this._upgradeProbe(), delay)
  }

  // Re-probe NOW: collapse the backoff so the next probe fires immediately. The
  // hook calls this from its visibility/online effect on a network change, the
  // browser analog of the Rust client's iface-change re-probe trigger.
  probeUpgradeNow() {
    if (this._closed || this.route !== 'relayed') return
    this._upgradeDelay = UPGRADE_FIRST_MS // a fresh path may exist, reset the cadence
    if (this._upgrading) return // a probe is already in flight; let it run
    rlog.debug('upgrade re-probe now (network change)', this.id.slice(-6))
    this._scheduleUpgradeProbe(0)
  }

  // One upgrade attempt: restartIce() on the live PC (the data channel survives,
  // so this is non-disruptive), let ICE re-nominate, then re-detect the route. A
  // non-relay re-detection enters the verify-before-commit window; anything else
  // backs off and re-schedules.
  async _upgradeProbe() {
    this._upgradeTimer = null
    if (this._closed || this.route !== 'relayed') return this._disarmUpgradeProber()
    // Kill-switch (browser analog of FILAMENT_UPGRADE_PROBE=0): the user opted out
    // of the prober entirely. Leave the link on relay; never re-schedule.
    try {
      if (localStorage.getItem('filamentUpgradeProbe') === '0') {
        rlog.debug('upgrade prober disabled (filamentUpgradeProbe=0), staying on relay', this.id.slice(-6))
        return
      }
    } catch {}
    // Shared-ICE-restart guard: the P0 stall ladder also drives restartIce. They
    // must never both fire at once (glare / churn). If a stall episode is open or
    // we're not cleanly connected, skip this probe and back off.
    if (this.pc.connectionState !== 'connected' || this._stallEpisode) {
      rlog.debug('upgrade probe skipped (not connected or stall episode open)', this.id.slice(-6))
      return this._backoffUpgrade()
    }
    // Only the IMPOLITE side drives restartIce (consistent with C4 + the P0
    // ladder rung a), restarting from both sides glares.
    this._upgrading = true
    if (!this.polite) {
      try {
        rlog.debug('upgrade probe: restartIce to find a direct path', this.id.slice(-6))
        this.pc.restartIce()
      } catch {}
    } else {
      rlog.debug('upgrade probe: re-detecting route (polite: no restartIce)', this.id.slice(-6))
    }
    // Give ICE a moment to re-nominate, then MEASURE (not commit) the route. We
    // deliberately use _measureRoute, not _detectRoute: a relay→direct flip must
    // pass verify-before-commit first, so we must NOT fire onRoute / clear the
    // amber UI here. Only _commitUpgrade does that, after the path holds.
    await new Promise((r) => setTimeout(r, 1200))
    this._upgrading = false
    if (this._closed || this.route !== 'relayed') return
    const route = await this._measureRoute()
    if (this._closed || this.route !== 'relayed') return
    // A non-relay measurement enters the verify window; anything else backs off.
    if (route && route !== 'relayed') {
      this._beginUpgradeVerify(route)
    } else {
      this._upgradeVerify = null
      this._backoffUpgrade()
    }
  }

  // Verify-before-commit (mirrors Rust judge_upgrade_standby): a direct path that
  // wins re-nomination must keep moving data for UPGRADE_VERIFY_MS before we cut
  // over. Reuses the P0 _bytesMoved counter as the "data path holds" signal. We
  // sample on a short heartbeat; if the route reverts to relay OR bytes stop
  // before the window closes, DISCARD and back off, no flap.
  _beginUpgradeVerify(route) {
    rlog.debug('direct path detected, verifying it holds before committing', this.id.slice(-6))
    const start = Date.now()
    const verify = { route, bytesAt: this._bytesMoved, lastBytes: this._bytesMoved, lastSeen: start }
    this._upgradeVerify = verify
    const VERIFY_TICK = 500
    // During the verify window we want some traffic to move so a flaky path
    // reveals itself. _checkStall already nudges real transfers; if the link is
    // otherwise idle we can't distinguish hold-vs-flaky, so an idle link that
    // simply READS non-relay across the whole window is accepted (a connected
    // direct candidate-pair is itself evidence; the no-flap risk is only when a
    // transfer is in flight, and then _bytesMoved advances).
    const tick = async () => {
      if (this._closed || this._upgradeVerify !== verify) return
      if (this.route !== 'relayed') return // someone else committed; stop
      const re = await this._measureRoute() // MEASURE only, commit happens below
      if (this._closed || this._upgradeVerify !== verify) return
      const hasInflight = [...this.transfers.values()].some(
        (t) => t.status === 'transferring' && (t.progress ?? 0) < 1,
      )
      const moved = this._bytesMoved !== verify.lastBytes
      if (moved) {
        verify.lastBytes = this._bytesMoved
        verify.lastSeen = Date.now()
      }
      // REGRESSED: route fell back to relay, OR a transfer is in flight yet bytes
      // have stalled past a tick-of-grace → discard, stay on relay, back off.
      const idleTooLong = hasInflight && Date.now() - verify.lastSeen >= UPGRADE_VERIFY_MS
      if ((re && re === 'relayed') || idleTooLong) {
        rlog.debug('direct path connected but did not hold, staying on relay (no flap)', this.id.slice(-6))
        this._upgradeVerify = null
        this._backoffUpgrade()
        return
      }
      // HELD long enough → commit.
      if (Date.now() - start >= UPGRADE_VERIFY_MS) {
        this._commitUpgrade(verify.route)
        return
      }
      this._upgradeTimer = setTimeout(tick, VERIFY_TICK)
    }
    this._upgradeTimer = setTimeout(tick, VERIFY_TICK)
  }

  // Commit the upgrade: the direct path held. Set the route, fire onRoute (which
  // AUTO-CLEARS the amber RELAY UI, no new UI needed), log the one value-prop
  // line, and disarm the prober (we're a destination now, not a way-station).
  _commitUpgrade(route) {
    if (this._closed) return
    this.route = route
    this.onRoute(route)
    rlog.info('upgraded to direct, relay released', this.id.slice(-6), route)
    this._disarmUpgradeProber()
  }

  // A probe (or a failed verify) didn't yield a held direct path: double the
  // cadence toward the steady cap and re-schedule, so a peer that will never get
  // direct isn't hammered.
  _backoffUpgrade() {
    this._upgrading = false
    this._upgradeDelay = Math.min(this._upgradeDelay * 2, UPGRADE_STEADY_MS)
    if (this.route === 'relayed' && !this._closed) this._scheduleUpgradeProbe(this._upgradeDelay)
  }

  // ------------------------------------------------------------- data channel
  _setChannel(channel) {
    this.channel = channel
    channel.binaryType = 'arraybuffer'
    channel.bufferedAmountLowThreshold = this.chunkSize
    channel.onopen = () => {
      clearTimeout(this._watchdog) // established, watchdog stands down (#8)
      this.onStatus('ready')
      this.onChannelOpen() // the hook re-offers any paused sends to this peer
      // C30 ph3: tell this peer our truth every ~10s, transfers we hold,
      // whether we verified them, whether our tab is hidden. One-sided
      // beliefs (lost END, lost proof, stale away) self-correct.
      clearInterval(this._stateTimer)
      this._stateTimer = setInterval(() => this._sendState(), 10000)
      // P0: arm the in-flight stall watchdog alongside the state ticker. It is
      // disjoint from the establishment _watchdog (which only runs pre-connected)
      // and from C4's _dcTimer (which only arms on 'disconnected'): during a
      // black-hole the pc stays 'connected' and the channel 'open', so only this
      // detector runs. Reset the baseline so the first tick starts clean.
      this._lastMovedSnapshot = this._bytesMoved
      this._lastBuffered = this.channel?.bufferedAmount || 0
      this._stallIdleMs = 0
      this._stallEpisode = null
      clearInterval(this._stallTimer)
      this._stallTimer = setInterval(() => this._checkStall(), STALL_TICK_MS)
    }
    channel.onmessage = (e) => this._onMessage(e.data)
    // One persistent drain handler feeds ALL concurrent senders, never
    // clobbered by a per-transfer assignment (#4).
    channel.onbufferedamountlow = () => {
      const waiters = this._drainWaiters
      this._drainWaiters = []
      waiters.forEach((r) => r())
    }
  }

  _onMessage(data) {
    if (typeof data === 'string') return this._onControl(JSON.parse(data))
    // Binary chunk: first 4 bytes are the stream id, the rest is payload (#4).
    if (data.byteLength < 4) return
    const sid = new DataView(data).getUint32(0)
    // web-shell: PTY bytes for the open terminal stream (empty frame = closed).
    if (sid === this._ptySid) {
      const payload = data.slice(4)
      if (payload.byteLength === 0) { this.onPtyClose(); this._ptySid = null }
      else this.onPtyData(new Uint8Array(payload))
      return
    }
    const id = this._incomingBySid.get(sid)
    const entry = id && this.stores.partials.get(id)
    if (!entry) return
    const payload = data.slice(4)
    entry.buffers.push(payload)
    entry.received += payload.byteLength
    this._bytesMoved += payload.byteLength // P0: inbound file bytes = data path alive (PTY excluded, handled above)
    this._update(this.transfers.get(id), { progress: entry.size ? entry.received / entry.size : 0 })
  }

  // C21: declared absences make waits informed: the peer holds the line for
  // the announced ttl instead of failing on the picker-induced disconnect.
  sendBrb(ttl = 120) {
    this._control({ type: CTRL.BRB, ttl })
  }
  sendBack() {
    this._control({ type: CTRL.BACK })
  }

  // C20: prove to the peer that we hold a secret they remembered. The mac is
  // computed by the hook (it owns the device store and our uid).
  sendPairProof(mac) {
    this._control({ type: CTRL.PAIR_PROOF, mac })
  }

  // C27: answer a remember offer, the sender discards its half on false.
  sendPairKeepAck(ok) {
    this._control({ type: CTRL.PAIR_KEEP_ACK, ok: !!ok })
  }

  // C27: judge a received proof: false tells a stale prover we never met.
  sendPairProofAck(ok) {
    this._control({ type: CTRL.PAIR_PROOF_ACK, ok: !!ok })
  }

  /// Both DTLS fingerprints of THIS link, parsed like the CLI does
  /// (a=fingerprint: value, trimmed, uppercased), the proof binds to them.
  fingerprints() {
    const grab = (desc) => {
      const line = (desc?.sdp || '').split(/\r?\n/).find((l) => l.startsWith('a=fingerprint:'))
      return line ? line.slice('a=fingerprint:'.length).trim().toUpperCase() : null
    }
    const mine = grab(this.pc.localDescription)
    const theirs = grab(this.pc.remoteDescription)
    return mine && theirs ? { mine, theirs } : null
  }

  // ---- web-shell (PTY over the data channel) -------------------------------
  // The browser allocates a HIGH-HALF sid (top bit set) so the CLI acceptor's
  // is_l2_sid router delivers our input frames to the PTY mux (the low range is
  // file transfer). Output rides the same sid; _onMessage routes it to onPtyData.
  // web-shell: open (or REATTACH to) a PTY. `session` is a stable id chosen by
  // the terminal that survives a reconnect; passing the same one after a dropped
  // channel tells the CLI to rebind the still-running PTY and replay its buffered
  // output instead of spawning a fresh shell (issue #4). Each open allocates a
  // NEW per-link sid (the old link is gone), but the `session` is what binds the
  // two opens to the same remote PTY.
  openPty(cols, rows, session) {
    this._ptySid = (0x80000000 | (this._nextSid++)) >>> 0
    this._ptySession = session || null
    this._control({ type: 'pty-open', sid: this._ptySid, cols, rows, session: this._ptySession })
    return this._ptySid
  }
  sendPtyInput(u8) {
    if (this._ptySid == null || this.channel?.readyState !== 'open') return
    const framed = new Uint8Array(4 + u8.byteLength)
    new DataView(framed.buffer).setUint32(0, this._ptySid)
    framed.set(u8, 4)
    this.channel.send(framed)
  }
  resizePty(cols, rows) {
    if (this._ptySid != null) this._control({ type: 'pty-resize', sid: this._ptySid, cols, rows })
  }
  // Explicitly END the remote PTY session (the ✕ / unmount). Carries the stable
  // session id so the CLI kills the right persistent shell. Distinct from a bare
  // channel drop, which the CLI treats as a DETACH (the shell keeps running for a
  // reattach). Sending both the session-scoped close and the per-link l2-close
  // covers a CLI that has the session AND frees the per-link stream bookkeeping.
  closePty() {
    if (this._ptySid == null && this._ptySession == null) return
    if (this._ptySession) this._control({ type: 'pty-close', session: this._ptySession })
    if (this._ptySid != null) this._control({ type: 'l2-close', sid: this._ptySid })
    this._ptySid = null
    this._ptySession = null
  }

  _onControl(msg) {
    switch (msg.type) {
      case 'caps':
        this.peerShell = !!msg.shell
        this.onCaps({ shell: this.peerShell })
        return
      case 'pty-open-ack':
        this.onPtyReady()
        return
      case 'l2-close':
        if (msg.sid === this._ptySid) { this.onPtyClose(); this._ptySid = null }
        return
      case CTRL.BRB:
        this._awayUntil = Date.now() + Math.min(msg.ttl || 120, 300) * 1000
        this.onStatus('away') // surfaced on the peer tile (C21 UX)
        return
      case CTRL.BACK:
        this._awayUntil = 0
        this.onStatus(this.pc.connectionState === 'connected' ? 'ready' : 'connecting')
        return
      default:
        if (this._awayUntil) {
          this._awayUntil = 0 // any real traffic means they're back
          this.onStatus(this.pc.connectionState === 'connected' ? 'ready' : 'connecting')
        }
    }
    switch (msg.type) {
      case CTRL.OFFER: {
        const t = this._track({
          id: msg.id, peerId: this.id, peerName: this.name, direction: 'receive',
          name: msg.name, size: msg.size, mime: msg.mime, progress: 0, status: 'offered',
        })
        t._sid = msg.sid
        // P4: stash the offered whole-file digest on the transfer so accept can
        // copy it onto the partial; verified at file-end.
        t._full = msg.full || null
        // Resume: if we already hold partial bytes for this transfer (the link
        // dropped mid-receive), accept automatically from where we left off,
        // the user already said yes once.
        const partial = msg.resume && this.stores.partials.get(msg.id)
        if (partial) {
          // P4: a re-offer may carry the digest the first offer did (or update
          // it); keep the partial verifiable across a resume.
          if (msg.full) partial.full = msg.full
          this._incomingBySid.set(msg.sid, msg.id)
          this._update(t, { status: 'transferring', progress: t.size ? partial.received / t.size : 0 })
          this._control({ type: CTRL.ACCEPT, id: msg.id, offset: partial.received })
        } else {
          this.onTransfer(t)
        }
        break
      }
      case CTRL.ACCEPT:
        this._streamFile(msg.id, msg.offset || 0)
        break
      case CTRL.DECLINE: {
        const t = this.transfers.get(msg.id)
        this._outgoingFiles.delete(msg.id)
        this.stores.outgoing.delete(msg.id)
        if (t) this._update(t, { status: 'declined' })
        break
      }
      case CTRL.END: {
        const id = this._incomingBySid.get(msg.sid)
        const entry = id && this.stores.partials.get(id)
        if (!entry) return
        // P4: whole-file verify happens here. If the offer carried `full`,
        // recompute sha256 over the received bytes and only finalize + ack on a
        // match; on a mismatch keep the partial and re-request, bounded by
        // MAX_VERIFY_FAILS. No digest (old/insecure peer) -> legacy accept.
        this._finishReceive(id, entry, msg.sid)
        break
      }
      case CTRL.PAIR_KEEP:
        // C12: the peer minted a pair secret and asked us to remember them.
        // C27: the hook asks the HUMAN before storing, never automatic.
        if (typeof msg.secret === 'string' && /^[0-9a-f]{64}$/.test(msg.secret)) this.onPairKeep(msg.secret)
        break
      case CTRL.PAIR_KEEP_ACK:
        this.onPairKeepAck(!!msg.ok)
        break
      case CTRL.PAIR_PROOF:
        if (typeof msg.mac === 'string') this.onPairProof(msg.mac)
        break
      case CTRL.PAIR_PROOF_ACK:
        this.onPairProofAck(!!msg.ok)
        break
      case CTRL.STATE: {
        // (the first switch's default already cleared any away-mark, a
        // state ping is proof of life.) Corrections:
        const tr = msg.transfers || {}
        for (const [id, bytes] of Object.entries(tr)) {
          const t = this.transfers.get(id)
          // I believe this send is COMPLETE; the peer holds fewer bytes,
          // the tail/END was lost. Re-offer with resume.
          if (t && t.direction === 'send' && t.status === 'complete' && bytes < t.size) {
            this.onPeerStateDiverged('transfer')
            this.resumeSend(id)
          }
        }
        // They say they don't recognize us; the hook may hold a secret for
        // them, let it re-prove. Report ONCE per link: the re-prove is
        // one-shot, and a genuinely asymmetric peer (no secret for us) would
        // otherwise repeat trusted:false on every 10s ping forever (observed
        // live). Aligning the signal with the action keeps the monitor honest.
        if (msg.trusted === false && !this._trustReported) {
          this._trustReported = true
          this.onPeerStateDiverged('trust')
        }
        break
      }
      case CTRL.DELIVERY_ACK: {
        // P4: the receiver verified the WHOLE file (sha256 matched). Only NOW is
        // an outgoing send truly done (vs the old fire-and-forget on file-end).
        const t = this.transfers.get(msg.id)
        if (!t || t.direction !== 'send') break
        if (this._ackTimers?.has(msg.id)) {
          clearTimeout(this._ackTimers.get(msg.id))
          this._ackTimers.delete(msg.id)
        }
        if (t.status === 'complete') break // already accepted (e.g. via fallback)
        this._outgoingFiles.delete(msg.id)
        this.stores.outgoing.delete(msg.id)
        this._update(t, { status: 'complete', progress: 1 })
        rlog.info('delivery-ack received, send verified + complete', msg.id)
        break
      }
    }
  }

  // P4 (whole-file integrity + delivery-ack, RECEIVER side). Called at file-end.
  // - no offered digest -> finalize as before (interop with old/insecure peers).
  // - digest present + MATCH -> finalize AND send delivery-ack.
  // - digest present + MISMATCH -> keep the partial, log a checksum-fail, and
  //   re-request: a short receive (buffered < size) resumes from where we are;
  //   a full-size-but-wrong-hash receive (corrupt body) restarts from 0 (the
  //   buffers are poisoned). Bounded by MAX_VERIFY_FAILS, then fail CLEAN
  //   (paused/resumable, partial kept), never an infinite loop.
  async _finishReceive(id, entry, sid) {
    const t = this.transfers.get(id)
    const finalize = (blob) => {
      this._incomingBySid.delete(sid)
      this.stores.partials.delete(id)
      this._update(t, { status: 'complete', progress: 1, blob, url: URL.createObjectURL(blob) })
    }
    if (!entry.full) {
      // Legacy: no whole-file digest offered, accept on size, no ack.
      finalize(new Blob(entry.buffers, { type: entry.mime || 'application/octet-stream' }))
      return
    }
    // Test shim (?test=trunconce): drop the tail ONCE to simulate a lost final
    // chunk, so the whole-file mismatch + re-request path runs against a CLI
    // sender. Inert in production (TEST.truncOnce is false).
    if (TEST.truncOnce && !entry._truncated && entry.buffers.length > 1) {
      entry._truncated = true
      const dropped = entry.buffers.pop()
      entry.received -= dropped.byteLength
      rlog.debug('[test] dropped final chunk to simulate truncation', id)
    }
    const blob = new Blob(entry.buffers, { type: entry.mime || 'application/octet-stream' })
    const got = await blobHash(blob)
    // Insecure origin on our side (can't hash): degrade to size-only acceptance
    // rather than rejecting forever, matches headHash's null-degrade contract.
    if (got == null) {
      rlog.debug('no crypto.subtle, accepting received file on size (no whole-file verify)', id)
      finalize(blob)
      return
    }
    if (got === entry.full) {
      // INTACT: finalize, then tell the sender it landed whole (delivery-ack).
      entry.verifyFails = 0
      finalize(blob)
      rlog.info('whole-file sha256 matched, finalizing + acking', id)
      this._control({ type: CTRL.DELIVERY_ACK, id, sid, v: 1 })
      return
    }
    // MISMATCH: do NOT finalize. Keep the partial, bound the re-request.
    entry.verifyFails = (entry.verifyFails || 0) + 1
    const truncated = entry.received < (entry.size || 0)
    rlog.debug(
      `whole-file checksum FAILED (${truncated ? 'truncated ' + entry.received + '/' + entry.size : 'corrupt'}), attempt ${entry.verifyFails}`,
      id,
    )
    if (entry.verifyFails > MAX_VERIFY_FAILS) {
      // Give up CLEANLY: keep the partial on the store (resumable), mark paused,
      // do not finalize, do not ack. No silent bad file, no hang.
      rlog.warn(`whole-file checksum still wrong after ${MAX_VERIFY_FAILS} re-fetches, refusing corrupt file (partial kept)`, id)
      this._incomingBySid.delete(sid)
      this._update(t, { status: 'paused' })
      return
    }
    // Re-request: truncated -> resume from current offset; corrupt (full size,
    // wrong hash) -> the buffers are poisoned, restart from 0.
    let offset = entry.received
    if (!truncated) {
      entry.buffers = []
      entry.received = 0
      offset = 0
    }
    // Keep the stream routable so resumed chunks land in the same partial, and
    // ask the sender to (re)stream from offset.
    this._incomingBySid.set(sid, id)
    this._update(t, { status: 'transferring', progress: entry.size ? offset / entry.size : 0 })
    this._control({ type: CTRL.ACCEPT, id, offset })
  }

  // ------------------------------------------------------------- send / accept
  // Queue files to a peer. Each becomes an 'offered' transfer the receiver must
  // accept before bytes flow. Each gets a stream id so multiple can run at once,
  // and the File is kept in the hook-owned store so a drop can resume later.
  sendFiles(fileList) {
    const ids = []
    for (const file of fileList) {
      const id = nextTransferId()
      const sid = this._nextSid++
      this._outgoingFiles.set(id, { file, sid })
      this.stores.outgoing.set(id, {
        file, name: file.name, size: file.size, mime: file.type, peerUid: this.peerUid,
      })
      const t = this._track({
        id, peerId: this.id, peerName: this.name, direction: 'send',
        name: file.name, size: file.size, mime: file.type, progress: 0, status: 'offered',
      })
      t._sid = sid
      this.onTransfer(t)
      // The offer ships once the hashes resolve: head (C7 resume) AND the
      // whole-file digest (P4 integrity). Order across concurrent offers
      // doesn't matter, ids are independent.
      Promise.all([headHash(file), fullHash(file)]).then(([head, full]) =>
        this._control({ type: CTRL.OFFER, id, sid, name: file.name, size: file.size, mime: file.type, ...(head ? { head } : {}), ...(full ? { full } : {}) })
      )
      ids.push(id)
    }
    return ids
  }

  // Re-offer an unfinished outgoing transfer on this (new) link after a drop.
  resumeSend(id) {
    const entry = this.stores.outgoing.get(id)
    if (!entry || this._outgoingFiles.has(id)) return
    const sid = this._nextSid++
    this._outgoingFiles.set(id, { file: entry.file, sid })
    const t = this._track({
      id, peerId: this.id, peerName: this.name, direction: 'send',
      name: entry.name, size: entry.size, mime: entry.mime, progress: 0, status: 'offered',
    })
    t._sid = sid
    this.onTransfer(t)
    Promise.all([headHash(entry.file), fullHash(entry.file)]).then(([head, full]) =>
      this._control({ type: CTRL.OFFER, id, sid, name: entry.name, size: entry.size, mime: entry.mime, resume: true, ...(head ? { head } : {}), ...(full ? { full } : {}) })
    )
  }

  // Receiver accepts an offered incoming transfer (fresh, from byte 0).
  acceptTransfer(id) {
    const t = this.transfers.get(id)
    if (!t || t.direction !== 'receive') return
    this.stores.partials.set(id, { received: 0, buffers: [], size: t.size, mime: t.mime, name: t.name, full: t._full || null })
    this._incomingBySid.set(t._sid, id)
    this._update(t, { status: 'transferring' })
    this._control({ type: CTRL.ACCEPT, id, offset: 0 })
  }

  declineTransfer(id) {
    const t = this.transfers.get(id)
    if (!t || t.direction !== 'receive') return
    this.stores.partials.delete(id)
    this._update(t, { status: 'declined' })
    this._control({ type: CTRL.DECLINE, id })
  }

  async _streamFile(id, startOffset = 0) {
    const entry = this._outgoingFiles.get(id)
    const t = this.transfers.get(id)
    if (!entry || !t) return
    const { file, sid } = entry
    this._update(t, { status: 'transferring', progress: file.size ? startOffset / file.size : 0 })
    let offset = Math.max(0, Math.min(startOffset, file.size))
    let sentThisRun = 0 // P0 freeze shim: bytes pushed since this _streamFile call began
    while (offset < file.size) {
      if (this._closed || this.channel?.readyState !== 'open') return // dropped mid-transfer
      const buf = await file.slice(offset, offset + this.chunkSize).arrayBuffer()
      // Backpressure: park without clobbering other senders (#4).
      if (this.channel.bufferedAmount > this.chunkSize * 16) {
        await new Promise((res) => this._drainWaiters.push(res))
        if (this._closed || this.channel?.readyState !== 'open') return
      }
      // Frame: [uint32 sid][payload]
      const framed = new Uint8Array(4 + buf.byteLength)
      new DataView(framed.buffer).setUint32(0, sid)
      framed.set(new Uint8Array(buf), 4)
      // P0 test shim (?test=freeze): after FREEZE_AFTER_BYTES on THIS transfer,
      // make the data-path send a no-op ONCE (one-shot per transfer) while the
      // channel stays open, a faithful NAT-rebind black-hole. The control path
      // keeps flowing, the channel stays 'open', the pc stays 'connected'; only
      // the bytes-moved watchdog can catch this. Inert in production.
      if (TEST.freeze && !this._frozenIds?.has(id) && sentThisRun + buf.byteLength > FREEZE_AFTER_BYTES) {
        ;(this._frozenIds ||= new Set()).add(id) // one-shot: rung (a)/(b)'s re-stream sends normally
        rlog.debug('[test] data-path FREEZE engaged, dropping chunks (channel stays open)', id, 'after', sentThisRun)
        return // park the sender loop without advancing offset; the partial is preserved
      }
      // P5 test shim (?test=freezepersist): a PERSISTENT freeze, EVERY run of
      // this loop black-holes after FREEZE_AFTER_BYTES (not just the first), so a
      // direct path can never carry the transfer and the link stays trapped on the
      // relay P1 rebuilds it onto. It LIFTS once HEAL_AFTER_MS has elapsed since
      // boot ("the network heals"), letting the P5 upgrade prober's re-probe
      // re-detect a usable direct route. relayOnly links are exempt (the relay
      // path must keep carrying bytes, only DIRECT is frozen). Inert in prod.
      if (TEST.freezePersist && !this.relayOnly && sentThisRun + buf.byteLength > FREEZE_AFTER_BYTES) {
        const now = (() => { try { return performance.now() } catch { return Date.now() } })()
        if (now - _bootAt < HEAL_AFTER_MS) {
          rlog.debug('[test] PERSISTENT data-path FREEZE engaged (direct dark, not yet healed)', id, 'after', sentThisRun)
          // Re-arm the sender shortly so it resumes (and re-freezes), this keeps
          // the transferring transfer "in flight" so the stall watchdog + the P5
          // verify both have live signal once the heal lifts.
          setTimeout(() => { if (!this._closed && this.channel?.readyState === 'open') this._streamFile(id, offset) }, 500)
          return
        }
        // Healed. Fall through and send normally.
      }
      this.channel.send(framed)
      offset += buf.byteLength
      sentThisRun += buf.byteLength
      this._bytesMoved += buf.byteLength // P0: outbound file bytes handed to SCTP = progress
      this._update(t, { progress: Math.min(offset / file.size, 1) })
    }
    this._control({ type: CTRL.END, id, sid })
    // Don't declare 'complete' while bytes still sit in the SCTP buffer: the
    // user reads 'complete' as permission to close the tab, and closing then
    // truncates the receiver's tail (caught by CLI gate 6, ledger F5).
    while (!this._closed && this.channel?.readyState === 'open' && this.channel.bufferedAmount > 0) {
      await new Promise((res) => setTimeout(res, 50))
    }
    if (this._closed) return
    // P4: do NOT declare complete here anymore. A send is "done" only when the
    // receiver delivery-acks the whole-file sha256 (see CTRL.DELIVERY_ACK).
    // Bounded fallback for interop with a peer too old to ack (or one that
    // offered no digest): after the buffer drains, accept on size+drain in
    // ACK_FALLBACK_MS if no ack arrives, preserves the never-hangs property.
    this._ackTimers ||= new Map()
    if (this._ackTimers.has(id)) clearTimeout(this._ackTimers.get(id))
    this._ackTimers.set(id, setTimeout(() => {
      this._ackTimers.delete(id)
      const cur = this.transfers.get(id)
      if (!cur || cur.status === 'complete') return
      rlog.debug('no delivery-ack, accepting on drain', id)
      this._outgoingFiles.delete(id)
      this.stores.outgoing.delete(id)
      this._update(cur, { status: 'complete', progress: 1 })
    }, ACK_FALLBACK_MS))
  }

  // ------------------------------------------------------------------ helpers
  _control(obj) {
    try {
      this.channel?.send(JSON.stringify(obj))
    } catch {}
  }
  _track(t) {
    this.transfers.set(t.id, t)
    return t
  }
  _update(t, patch) {
    if (!t) return
    Object.assign(t, patch)
    this.onTransfer({ ...t })
  }

  // When the link drops, in-flight transfers become 'paused' if they can resume
  // (we still hold the File / the partial bytes, kept in the hook-owned stores,
  // which deliberately survive this link), else 'failed' (#5 + resume).
  _failActive() {
    // P0: the in-flight watchdog is meaningless once we've torn the link's
    // transfers down, disarm it and clear the episode so a fresh link starts
    // clean (close() also clears it; this covers a mid-life link drop).
    clearInterval(this._stallTimer)
    this._stallTimer = null
    this._stallEpisode = null
    this._stallIdleMs = 0
    this._disarmUpgradeProber() // P5: the upgrade prober dies with the link's transfers
    for (const t of this.transfers.values()) {
      if (t.status !== 'transferring' && t.status !== 'offered') continue
      const resumable =
        (t.direction === 'send' && this.stores.outgoing.has(t.id)) ||
        (t.direction === 'receive' && this.stores.partials.has(t.id))
      this._update(t, { status: resumable ? 'paused' : 'failed' })
    }
    this._incomingBySid.clear() // sid routing dies with the link; partials survive
    this._outgoingFiles.clear() // per-link send state; the Files survive in stores
    // P4: drop pending ack-fallback timers, the send is no longer 'complete' on
    // this link (it becomes 'paused' above and re-offers on the next link).
    if (this._ackTimers) {
      for (const tm of this._ackTimers.values()) clearTimeout(tm)
      this._ackTimers.clear()
    }
    const waiters = this._drainWaiters
    this._drainWaiters = []
    waiters.forEach((r) => r()) // unblock parked sender loops so they exit
  }

  _sendState() {
    const transfers = {}
    for (const t of this.transfers.values()) {
      if (t.direction !== 'receive') continue
      const p = this.stores.partials.get(t.id)
      transfers[t.id] = t.status === 'complete' ? t.size : p ? p.received : 0
    }
    this._control({
      type: CTRL.STATE, v: 1, transfers,
      trusted: !!this._verified, // set by the hook on proof-ok
      away: typeof document !== 'undefined' && document.visibilityState === 'hidden',
    })
  }

  // -------------------------------------------------------------- P0 stall (GAP-1)
  // Application-layer "no bytes moved in N seconds while the channel is OPEN"
  // detector. Mirrors the Rust client's idle_ms() watchdog: the threshold is on
  // TIME SINCE THE LAST BYTE, never throughput, so a slow-but-moving link never
  // trips. Runs every STALL_TICK_MS from channel.onopen; disarmed in close() /
  // _failActive(). Composition is deliberate (none double-fires):
  //   - establishment _watchdog: disjoint (it only runs pre-'connected'; this
  //     requires the channel 'open');
  //   - C4 _dcTimer: only arms on 'disconnected'. During a black-hole the state
  //     stays 'connected', so only this runs; rung (a)'s connectionState guard
  //     prevents colliding restartIce calls if a real 'disconnected' happens.
  _checkStall() {
    // A genuine drop is C4's job, this detector is for an OPEN-but-dark channel.
    if (this._closed || this.channel?.readyState !== 'open') return
    // An idle link must never trip: nothing with bytes STILL TO MOVE -> reset the
    // baseline. A transfer at progress 1 has handed every byte off and is in its
    // legitimate no-wire-bytes tail (SCTP drain + whole-file verify + delivery-ack,
    // P4), counting it would false-trip on a clean transfer, so we require
    // progress < 1 (an outstanding byte) to treat the link as stall-eligible.
    const transferring = [...this.transfers.values()].some(
      (t) => t.status === 'transferring' && (t.progress ?? 0) < 1,
    )
    if (!transferring) {
      this._lastMovedSnapshot = this._bytesMoved
      this._lastBuffered = this.channel.bufferedAmount
      this._stallIdleMs = 0
      this._stallEpisode = null
      return
    }
    // C21 announced-absence grace: a peer that said `brb` (or whose tab is hidden)
    // gets its window, don't trip while they're legitimately away.
    if ((this._awayUntil || 0) > Date.now()) {
      this._lastMovedSnapshot = this._bytesMoved
      this._lastBuffered = this.channel.bufferedAmount
      this._stallIdleMs = 0
      return
    }
    // PROGRESS check. Either application-level bytes advanced, OR the SCTP send
    // buffer drained (bytes left for the wire), the latter prevents a false
    // positive on a slow-but-moving link whose chunks sit briefly buffered.
    const buffered = this.channel.bufferedAmount
    if (this._bytesMoved !== this._lastMovedSnapshot || buffered < this._lastBuffered) {
      this._lastMovedSnapshot = this._bytesMoved
      this._lastBuffered = buffered
      this._stallIdleMs = 0
      // A moved byte clears any open episode (the link recovered), mirrors the
      // Rust note_progress(): a future stall may climb the ladder fresh.
      if (this._stallEpisode) {
        rlog.info('stall corrected, bytes moving again', this.id.slice(-6), 'rung', this._stallEpisode.rung)
        this._stallEpisode = null
      }
      return
    }
    // No progress this tick, accumulate idle time.
    this._lastBuffered = buffered
    this._stallIdleMs += STALL_TICK_MS
    if (this._stallIdleMs < STALL_MS) return
    // The _stallEpisode latch gates re-entry: while a rung is mid-convergence
    // (we gave it ~one STALL_MS grace) we wait rather than re-firing the ladder.
    const now = Date.now()
    if (this._stallEpisode && now - this._stallEpisode.at < STALL_MS) return
    rlog.debug('stall detected', this.id.slice(-6), 'idleMs', this._stallIdleMs)
    this._correctStall()
  }

  // Least-disruptive-first correction ladder (mirrors Rust correct_stall):
  //   (a) liveness ping + (impolite, connected) restartIce, cheapest in-place;
  //   (b) re-offer/resume unfinished transfers (receiver auto-resumes; the
  //       receiver instead re-acks at its current offset to nudge the sender);
  //   (c) escalate to onStall (P1: relay-preferred rebuild), callback may be a
  //       no-op for now.
  // Bounded at MAX_STALL_ATTEMPTS; on exhaustion -> onStatus('failed') +
  // _failActive (transfers become paused/resumable, NEVER silently dead).
  _correctStall() {
    const now = Date.now()
    const rung = this._stallEpisode?.rung
    // RUNG (a): liveness probe + in-place ICE repair.
    if (!rung) {
      try {
        // A control send over the reliable channel: success ⇒ the transport
        // itself is up (data path dark, link alive). A throw ⇒ truly dead. Let
        // C4 / _failActive own it.
        this.channel.send(JSON.stringify({ type: 'ping', v: 1, reason: 'stall-probe' }))
      } catch {
        rlog.debug('stall: control send threw: link is dead, deferring to C4', this.id.slice(-6))
        return
      }
      // Only nudge ICE while CONNECTED and from the IMPOLITE side: C4 owns the
      // ICE-restart while 'disconnected', and restarting from both sides at once
      // glares. The guard also stops a double-fire if a real 'disconnected' lands
      // mid-stall (C4 then takes over).
      if (this.pc.connectionState === 'connected' && !this.polite) {
        try {
          this.pc.restartIce()
          rlog.info('stall corrected attempt (rung a), liveness ping + restartIce', this.id.slice(-6))
        } catch {}
      } else {
        rlog.info('stall corrected attempt (rung a), liveness ping (no ICE restart: polite/not-connected)', this.id.slice(-6))
      }
      this._stallEpisode = { rung: 'a', at: now }
      return
    }
    // RUNG (b): still stalled after rung (a)'s grace, re-issue every unfinished
    // transfer so the data path re-flows from the partial.
    if (rung === 'a') {
      let nudged = 0
      for (const t of this.transfers.values()) {
        if (t.status !== 'transferring') continue
        if (t.direction === 'send') {
          // Re-offer with resume:true; the receiver auto-resumes from its partial.
          // Clear the per-link send state so resumeSend re-arms a fresh stream.
          this._outgoingFiles.delete(t.id)
          this.resumeSend(t.id)
          nudged++
        } else if (t.direction === 'receive') {
          // Receiver side: re-send a resume accept at the current offset to nudge
          // the sender to (re)stream from where we are, never restart from 0.
          const partial = this.stores.partials.get(t.id)
          this._control({ type: CTRL.ACCEPT, id: t.id, offset: partial ? partial.received : 0 })
          nudged++
        }
      }
      rlog.info('stall correction (rung b), re-offered/resumed unfinished transfers', this.id.slice(-6), 'count', nudged)
      this._stallEpisode = { rung: 'b', at: now }
      return
    }
    // RUNG (c): still stalled, escalate to the hook (P1 implements the
    // relay-preferred rebuild). The callback may be a no-op for now.
    if (rung === 'b') {
      rlog.info('stall correction (rung c), escalating to onStall', this.id.slice(-6))
      try {
        this.onStall?.({ reason: 'persistent', route: this.route })
      } catch (err) {
        rlog.warn('onStall hook threw', this.id.slice(-6), err)
      }
      this._stallEpisode = { rung: 'c', at: now }
      return
    }
    // EXHAUSTED (rungs a→c spent, MAX_STALL_ATTEMPTS): no rung recovered. Fail
    // CLEAN, transfers become paused/resumable via _failActive, never silently
    // dead; the partials are preserved for the next link.
    rlog.warn('stall correction exhausted, failing clean (partials preserved)', this.id.slice(-6))
    this.onStatus('failed')
    this._failActive()
  }

  close() {
    clearInterval(this._stateTimer)
    clearInterval(this._stallTimer) // P0: disarm the in-flight stall watchdog
    this._disarmUpgradeProber() // P5: disarm the relay→direct upgrade prober
    if (this._closed) return
    this._closed = true
    clearTimeout(this._dcTimer)
    clearTimeout(this._watchdog)
    this._failActive() // flush 'failed' to the UI before we go silent
    // Silence late async callbacks (detectRoute timers, channel events) so they
    // can't resurrect a removed peer in the hook (#3).
    this.onStatus = () => {}
    this.onRoute = () => {}
    this.onTransfer = () => {}
    try { this.channel?.close() } catch {}
    try { this.pc.close() } catch {}
  }
}
