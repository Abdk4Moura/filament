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
}

let _tid = 0
const nextTransferId = () => `t${++_tid}_${Math.random().toString(36).slice(2, 7)}`

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
  constructor({ id, name, iceServers, chunkSize, initiator, sendSignal, onStatus, onTransfer, onRoute }) {
    this.id = id
    this.name = name
    this.chunkSize = chunkSize || 64 * 1024
    this.sendSignal = sendSignal
    this.onStatus = onStatus || (() => {})
    this.onTransfer = onTransfer || (() => {})
    this.onRoute = onRoute || (() => {})
    this.route = null // 'local' | 'direct' | 'relayed'

    this.transfers = new Map() // id -> transfer state (mirrored to the UI)
    this._outgoingFiles = new Map() // id -> File awaiting accept
    this._incoming = null // { id, name, size, mime, received, buffers }

    this.pc = new RTCPeerConnection({ iceServers })
    this.pc.onicecandidate = (e) => {
      if (e.candidate) this.sendSignal({ type: 'candidate', candidate: e.candidate })
    }
    this.pc.onconnectionstatechange = () => {
      const s = this.pc.connectionState
      if (s === 'connected') {
        this.onStatus('ready')
        this._detectRoute() // which physical path did ICE actually pick?
      } else if (s === 'failed' || s === 'disconnected' || s === 'closed') {
        this.onStatus('failed')
      } else {
        this.onStatus('connecting')
      }
    }

    if (initiator) {
      this._setChannel(this.pc.createDataChannel('filament'))
      this._makeOffer()
    } else {
      this.pc.ondatachannel = (e) => this._setChannel(e.channel)
    }
  }

  // --------------------------------------------------------------- signaling
  async _makeOffer() {
    const offer = await this.pc.createOffer()
    await this.pc.setLocalDescription(offer)
    this.sendSignal({ type: 'offer', sdp: offer })
  }

  // Called by the hook when a relayed `signal` for this peer arrives.
  async accept(data) {
    try {
      if (data.type === 'offer') {
        await this.pc.setRemoteDescription(new RTCSessionDescription(data.sdp))
        const answer = await this.pc.createAnswer()
        await this.pc.setLocalDescription(answer)
        this.sendSignal({ type: 'answer', sdp: answer })
      } else if (data.type === 'answer') {
        await this.pc.setRemoteDescription(new RTCSessionDescription(data.sdp))
      } else if (data.type === 'candidate') {
        await this.pc.addIceCandidate(new RTCIceCandidate(data.candidate))
      }
    } catch (err) {
      console.error('signal handling failed', err)
    }
  }

  // Inspect the ICE stats to learn which path the connection actually took:
  //   local   — host↔host, i.e. straight across the LAN (never hit the internet)
  //   direct  — peer-to-peer over the internet (NAT-traversed, no relay)
  //   relayed — falling back through a TURN relay
  // ICE renominates occasionally, so we poll a few times after connecting.
  async _detectRoute(attempt = 0) {
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
    channel.onopen = () => this.onStatus('ready')
    channel.onmessage = (e) => this._onMessage(e.data)
  }

  _onMessage(data) {
    if (typeof data === 'string') return this._onControl(JSON.parse(data))
    // binary chunk for the in-flight incoming transfer
    if (!this._incoming) return
    this._incoming.buffers.push(data)
    this._incoming.received += data.byteLength
    const t = this.transfers.get(this._incoming.id)
    this._update(t, { progress: this._incoming.received / this._incoming.size })
  }

  _onControl(msg) {
    switch (msg.type) {
      case CTRL.OFFER: {
        const t = this._track({
          id: msg.id, peerId: this.id, peerName: this.name, direction: 'receive',
          name: msg.name, size: msg.size, mime: msg.mime, progress: 0, status: 'offered',
        })
        this.onTransfer(t)
        break
      }
      case CTRL.ACCEPT:
        this._streamFile(msg.id)
        break
      case CTRL.DECLINE: {
        const t = this.transfers.get(msg.id)
        this._outgoingFiles.delete(msg.id)
        if (t) this._update(t, { status: 'declined' })
        break
      }
      case CTRL.END: {
        const inc = this._incoming
        if (!inc || inc.id !== msg.id) return
        const blob = new Blob(inc.buffers, { type: inc.mime || 'application/octet-stream' })
        this._incoming = null
        const t = this.transfers.get(msg.id)
        this._update(t, { status: 'complete', progress: 1, blob, url: URL.createObjectURL(blob) })
        break
      }
    }
  }

  // ------------------------------------------------------------- send / accept
  // Queue files to a peer. Each becomes an 'offered' transfer the receiver must
  // accept before bytes flow.
  sendFiles(fileList) {
    const ids = []
    for (const file of fileList) {
      const id = nextTransferId()
      this._outgoingFiles.set(id, file)
      const t = this._track({
        id, peerId: this.id, peerName: this.name, direction: 'send',
        name: file.name, size: file.size, mime: file.type, progress: 0, status: 'offered',
      })
      this.onTransfer(t)
      this._control({ type: CTRL.OFFER, id, name: file.name, size: file.size, mime: file.type })
      ids.push(id)
    }
    return ids
  }

  // Receiver accepts an offered incoming transfer.
  acceptTransfer(id) {
    const t = this.transfers.get(id)
    if (!t || t.direction !== 'receive') return
    this._incoming = { id, name: t.name, size: t.size, mime: t.mime, received: 0, buffers: [] }
    this._update(t, { status: 'transferring' })
    this._control({ type: CTRL.ACCEPT, id })
  }

  declineTransfer(id) {
    const t = this.transfers.get(id)
    if (!t || t.direction !== 'receive') return
    this._update(t, { status: 'declined' })
    this._control({ type: CTRL.DECLINE, id })
  }

  async _streamFile(id) {
    const file = this._outgoingFiles.get(id)
    const t = this.transfers.get(id)
    if (!file || !t) return
    this._update(t, { status: 'transferring' })
    let offset = 0
    while (offset < file.size) {
      const slice = file.slice(offset, offset + this.chunkSize)
      const buf = await slice.arrayBuffer()
      // Backpressure: wait if the send buffer is filling up.
      if (this.channel.bufferedAmount > this.chunkSize * 16) {
        await new Promise((res) => (this.channel.onbufferedamountlow = res))
      }
      this.channel.send(buf)
      offset += buf.byteLength
      this._update(t, { progress: Math.min(offset / file.size, 1) })
    }
    this._control({ type: CTRL.END, id })
    this._outgoingFiles.delete(id)
    this._update(t, { status: 'complete', progress: 1 })
  }

  // ------------------------------------------------------------------ helpers
  _control(obj) {
    this.channel?.send(JSON.stringify(obj))
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

  close() {
    try { this.channel?.close() } catch {}
    try { this.pc.close() } catch {}
  }
}
