// PeerLink: one live connection to one remote peer.
//
// Owns an RTCPeerConnection + a single RTCDataChannel and moves files across it
// in chunks. The server never sees a byte — it only relayed the SDP/ICE that
// got us here. Control messages are JSON strings; file chunks are ArrayBuffers.
//
// Transfer lifecycle (both directions surfaced to the UI via onTransfer):
//   offered      -> receiver has been told a file is coming, not yet accepted
//   transferring -> bytes are moving (progress 0..1)
//   complete     -> done; a receive transfer also carries { url, blob }
//   declined     -> receiver said no
//   failed       -> connection/transfer error

const CTRL = {
  OFFER: 'file-offer',
  ACCEPT: 'file-accept',
  DECLINE: 'file-decline',
  END: 'file-end',
  BRB: 'brb', // C21: "I'm stepping away (file picker / tab hidden), hold the line"
  BACK: 'back',
  PAIR_KEEP: 'pair-keep', // C12: here's a secret — remember me as a known device
  PAIR_KEEP_ACK: 'pair-keep-ack', // C27: the human's answer — sender keeps only confirmed secrets
  PAIR_PROOF: 'pair-proof', // C20: HMAC proof I hold a secret you remembered
  PAIR_PROOF_ACK: 'pair-proof-ack', // C27: verifier's verdict — a rejected prover stops claiming acquaintance
  STATE: 'state', // C30 ph3: periodic link truth {transfers, trusted, away} — divergence repair
}

let _tid = 0
const nextTransferId = () => `t${++_tid}_${Math.random().toString(36).slice(2, 7)}`

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

// Deterministic negotiation roles (#1, hardened in #8/#10): prefer the stable
// per-tab uid — it survives reconnects, so both sides always compare the SAME
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
  constructor({ id, name, iceServers, chunkSize, polite, peerUid, stores, sendSignal, onStatus, onTransfer, onRoute, onChannelOpen, onStuck, watchdogMs, onPairKeep, onPairKeepAck, onPairProof, onPairProofAck, onPeerStateDiverged, onPtyData, onPtyClose, onPtyReady, onCaps }) {
    this.id = id
    this.name = name
    this.chunkSize = chunkSize || 64 * 1024
    this.sendSignal = sendSignal
    this.onStatus = onStatus || (() => {})
    this.onTransfer = onTransfer || (() => {})
    this.onRoute = onRoute || (() => {})
    this.onChannelOpen = onChannelOpen || (() => {})
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
    this.route = null // 'local' | 'direct' | 'relayed'

    // Resume support: a stable per-tab identity for the remote peer, plus
    // hook-owned stores that OUTLIVE this link — partial receive buffers and
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

    this.pc = new RTCPeerConnection({ iceServers })
    this.pc.onicecandidate = (e) => {
      if (e.candidate) this.sendSignal({ type: 'candidate', candidate: e.candidate })
    }
    // All (re)negotiation funnels through here — we never hand-roll offers.
    // Explicit createOffer (not the no-arg setLocalDescription()) for older
    // Safari, where the implicit form throws and silently kills the handshake.
    this.pc.onnegotiationneeded = async () => {
      try {
        this._makingOffer = true
        const offer = await this.pc.createOffer()
        await this.pc.setLocalDescription(offer)
        this.sendSignal({ type: 'description', description: this.pc.localDescription })
      } catch (err) {
        console.error('negotiation failed', err)
      } finally {
        this._makingOffer = false
      }
    }
    this.pc.ondatachannel = (e) => this._setChannel(e.channel)
    this.pc.onconnectionstatechange = () => {
      const s = this.pc.connectionState
      if (s === 'connected') {
        clearTimeout(this._dcTimer)
        clearTimeout(this._watchdog) // established — watchdog stands down (#8)
        this.onStatus('ready')
        this._detectRoute() // which physical path did ICE actually pick?
      } else if (s === 'disconnected') {
        // Usually a transient blip (#6): show 'connecting' (or keep 'away' if
        // they announced the absence), nudge an ICE restart from the impolite
        // side, and only fail if it doesn't recover in time.
        this.onStatus((this._awayUntil || 0) > Date.now() ? 'away' : 'connecting')
        if (!this.polite) {
          try {
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
    // at 'connecting' FOREVER — ICE only times out once descriptions exchange.
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
      .catch((err) => console.error('signal handling failed', err))
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
        if (!this._ignoreOffer) console.error('addIceCandidate failed', err)
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
        console.error('queued candidate failed', err)
      }
    }
  }

  // Inspect the ICE stats to learn which path the connection actually took:
  //   local   — host↔host, i.e. straight across the LAN (never hit the internet)
  //   direct  — peer-to-peer over the internet (NAT-traversed, no relay)
  //   relayed — falling back through a TURN relay
  // ICE renominates occasionally, so we poll a few times after connecting.
  async _detectRoute(attempt = 0) {
    if (this._closed) return
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
      if (!selected) {
        if (attempt < 5) setTimeout(() => this._detectRoute(attempt + 1), 400)
        return
      }
      const lt = cands[selected.localCandidateId]?.candidateType
      const rt = cands[selected.remoteCandidateId]?.candidateType
      let route = 'direct'
      if (lt === 'relay' || rt === 'relay') route = 'relayed'
      else if (lt === 'host' && rt === 'host') route = 'local'
      if (route !== this.route) {
        this.route = route
        this.onRoute(route)
      }
    } catch {
      /* getStats unsupported — leave route null */
    }
  }

  // ------------------------------------------------------------- data channel
  _setChannel(channel) {
    this.channel = channel
    channel.binaryType = 'arraybuffer'
    channel.bufferedAmountLowThreshold = this.chunkSize
    channel.onopen = () => {
      clearTimeout(this._watchdog) // established — watchdog stands down (#8)
      this.onStatus('ready')
      this.onChannelOpen() // the hook re-offers any paused sends to this peer
      // C30 ph3: tell this peer our truth every ~10s — transfers we hold,
      // whether we verified them, whether our tab is hidden. One-sided
      // beliefs (lost END, lost proof, stale away) self-correct.
      clearInterval(this._stateTimer)
      this._stateTimer = setInterval(() => this._sendState(), 10000)
    }
    channel.onmessage = (e) => this._onMessage(e.data)
    // One persistent drain handler feeds ALL concurrent senders — never
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
    this._update(this.transfers.get(id), { progress: entry.size ? entry.received / entry.size : 0 })
  }

  // C21: declared absences make waits informed — the peer holds the line for
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

  // C27: answer a remember offer — the sender discards its half on false.
  sendPairKeepAck(ok) {
    this._control({ type: CTRL.PAIR_KEEP_ACK, ok: !!ok })
  }

  // C27: judge a received proof — false tells a stale prover we never met.
  sendPairProofAck(ok) {
    this._control({ type: CTRL.PAIR_PROOF_ACK, ok: !!ok })
  }

  /// Both DTLS fingerprints of THIS link, parsed like the CLI does
  /// (a=fingerprint: value, trimmed, uppercased) — the proof binds to them.
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
  openPty(cols, rows) {
    this._ptySid = (0x80000000 | (this._nextSid++)) >>> 0
    this._control({ type: 'pty-open', sid: this._ptySid, cols, rows })
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
  closePty() {
    if (this._ptySid == null) return
    this._control({ type: 'l2-close', sid: this._ptySid })
    this._ptySid = null
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
        // Resume: if we already hold partial bytes for this transfer (the link
        // dropped mid-receive), accept automatically from where we left off —
        // the user already said yes once.
        const partial = msg.resume && this.stores.partials.get(msg.id)
        if (partial) {
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
        this._incomingBySid.delete(msg.sid)
        this.stores.partials.delete(id)
        const blob = new Blob(entry.buffers, { type: entry.mime || 'application/octet-stream' })
        this._update(this.transfers.get(id), {
          status: 'complete', progress: 1, blob, url: URL.createObjectURL(blob),
        })
        break
      }
      case CTRL.PAIR_KEEP:
        // C12: the peer minted a pair secret and asked us to remember them.
        // C27: the hook asks the HUMAN before storing — never automatic.
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
        // (the first switch's default already cleared any away-mark — a
        // state ping is proof of life.) Corrections:
        const tr = msg.transfers || {}
        for (const [id, bytes] of Object.entries(tr)) {
          const t = this.transfers.get(id)
          // I believe this send is COMPLETE; the peer holds fewer bytes —
          // the tail/END was lost. Re-offer with resume.
          if (t && t.direction === 'send' && t.status === 'complete' && bytes < t.size) {
            this.onPeerStateDiverged('transfer')
            this.resumeSend(id)
          }
        }
        // They say they don't recognize us; the hook may hold a secret for
        // them — let it re-prove. Report ONCE per link: the re-prove is
        // one-shot, and a genuinely asymmetric peer (no secret for us) would
        // otherwise repeat trusted:false on every 10s ping forever (observed
        // live). Aligning the signal with the action keeps the monitor honest.
        if (msg.trusted === false && !this._trustReported) {
          this._trustReported = true
          this.onPeerStateDiverged('trust')
        }
        break
      }
    }
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
      // The offer ships once the head hash resolves (C7); order across
      // concurrent offers doesn't matter — ids are independent.
      headHash(file).then((head) =>
        this._control({ type: CTRL.OFFER, id, sid, name: file.name, size: file.size, mime: file.type, ...(head ? { head } : {}) })
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
    headHash(entry.file).then((head) =>
      this._control({ type: CTRL.OFFER, id, sid, name: entry.name, size: entry.size, mime: entry.mime, resume: true, ...(head ? { head } : {}) })
    )
  }

  // Receiver accepts an offered incoming transfer (fresh, from byte 0).
  acceptTransfer(id) {
    const t = this.transfers.get(id)
    if (!t || t.direction !== 'receive') return
    this.stores.partials.set(id, { received: 0, buffers: [], size: t.size, mime: t.mime, name: t.name })
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
      this.channel.send(framed)
      offset += buf.byteLength
      this._update(t, { progress: Math.min(offset / file.size, 1) })
    }
    this._control({ type: CTRL.END, id, sid })
    // Don't declare 'complete' while bytes still sit in the SCTP buffer: the
    // user reads 'complete' as permission to close the tab, and closing then
    // truncates the receiver's tail (caught by CLI gate 6 — ledger F5).
    while (!this._closed && this.channel?.readyState === 'open' && this.channel.bufferedAmount > 0) {
      await new Promise((res) => setTimeout(res, 50))
    }
    this._outgoingFiles.delete(id)
    this.stores.outgoing.delete(id)
    this._update(t, { status: 'complete', progress: 1 })
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
  // (we still hold the File / the partial bytes — kept in the hook-owned stores,
  // which deliberately survive this link), else 'failed' (#5 + resume).
  _failActive() {
    for (const t of this.transfers.values()) {
      if (t.status !== 'transferring' && t.status !== 'offered') continue
      const resumable =
        (t.direction === 'send' && this.stores.outgoing.has(t.id)) ||
        (t.direction === 'receive' && this.stores.partials.has(t.id))
      this._update(t, { status: resumable ? 'paused' : 'failed' })
    }
    this._incomingBySid.clear() // sid routing dies with the link; partials survive
    this._outgoingFiles.clear() // per-link send state; the Files survive in stores
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

  close() {
    clearInterval(this._stateTimer)
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
