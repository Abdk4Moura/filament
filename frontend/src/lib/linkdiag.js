// linkdiag: link-diagnostics / telemetry capture for root-causing terminal
// "blips" on a real 5G/CGNAT mobile network. This is a debugger-grade TIMELINE,
// distinct from tel.js (which beacons a small set of lifecycle events to the
// server). linkdiag holds a rolling, in-memory ring of richly-timestamped link
// events that the user can EXPORT after a blip (download / copy / send) and hand
// back for analysis.
//
// Design:
//   - One process-wide ring (RING_MAX entries, ~10 min at the cadences below).
//   - Each entry is { t (epoch ms), m (monotonic ms since capture start), k
//     (kind), uid (which peer, last 6), shell (bool: is this the PTY link),
//     ...fields }. Compact on purpose: deltas, not full getStats dumps.
//   - Capture is gated: default ON (lightweight) but suppressible, and the
//     periodic getStats poll only runs while a link is connected.
//   - The PeerLink installs a per-link sampler (record + poll) via attach().
//
// What it answers (the three primary suspects):
//   1. CGNAT symmetric NAT forcing TURN relay: the route + selected candidate
//      pair (local/remote candidate types) is recorded on connect and ON CHANGE.
//   2. Periodic NAT rebinds: a candidate-pair id change mid-session is the
//      smoking gun, recorded as a 'pair' event whenever the selected pair id
//      moves.
//   3. Radio-idle on screen-off/background: visibility / online-offline /
//      connection-change / pagehide-pageshow are recorded, plus the getStats
//      snapshot shows whether consent + bytes keep advancing across the gap.

// Ring capacity. At ~2.5s getStats snapshots that's ~20 min of pure snapshots,
// but ICE churn + env events share the ring, so ~500 covers roughly the last
// 10 min of an active session, which is the post-blip window we care about.
const RING_MAX = 500

// getStats poll cadence while a link is connected (~2-3s per the brief).
const POLL_MS = 2500

// Monotonic clock base (performance.now is immune to wall-clock jumps, which a
// mobile radio sleep can cause). Both a wall (t) and monotonic (m) stamp are
// recorded so a blip can be correlated either way.
const _t0wall = Date.now()
const _t0mono = (() => {
  try {
    return performance.now()
  } catch {
    return 0
  }
})()
function nowMono() {
  try {
    return Math.round(performance.now() - _t0mono)
  } catch {
    return Date.now() - _t0wall
  }
}

// ---- the ring -------------------------------------------------------------
const ring = []
let dropped = 0 // count of entries evicted (so the export header is honest)
let enabled = true // default-on; flip via setEnabled / ?diag=0
const listeners = new Set() // live-status subscribers (the UI panel)

// Whether capture is on. Honors a ?diag=0 opt-out and a localStorage override,
// otherwise default-on (lightweight). ?diag=1 is the explicit opt-in the brief
// asks for; it is also accepted (and is the default), so the user can simply
// add ?diag=1 to turn the panel on and know capture is running.
function _resolveEnabled() {
  try {
    const q = new URLSearchParams(window.location.search).get('diag')
    if (q === '0') return false
    if (q === '1') return true
    const ls = localStorage.getItem('filamentDiag')
    if (ls === '0') return false
    if (ls === '1') return true
  } catch {}
  return true
}
enabled = _resolveEnabled()

export function setEnabled(on) {
  enabled = !!on
  try {
    localStorage.setItem('filamentDiag', on ? '1' : '0')
  } catch {}
  record('diag', { enabled }) // a marker in the timeline itself
}
export function isEnabled() {
  return enabled
}

// Subscribe to live updates (the panel re-renders its compact status on each
// record). Returns an unsubscribe. Kept cheap: we notify with the latest entry,
// the subscriber pulls whatever summary it wants.
export function subscribe(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

// The one entry point. `k` is the kind (a short tag); `fields` is the compact
// payload. `meta` carries link identity { uid, shell } so every entry is tagged
// with which peer/link it came from and whether it is the shell (PTY) link.
export function record(k, fields = {}, meta = {}) {
  if (!enabled) return
  const e = {
    t: Date.now(),
    m: nowMono(),
    k,
    ...(meta.uid ? { uid: String(meta.uid).slice(-6) } : {}),
    ...(meta.shell ? { shell: true } : {}),
    ...fields,
  }
  ring.push(e)
  if (ring.length > RING_MAX) {
    ring.shift()
    dropped++
  }
  for (const fn of listeners) {
    try {
      fn(e)
    } catch {}
  }
  return e
}

// ---- export ---------------------------------------------------------------
// A clean, self-contained JSON the user can hand back. Header has the userAgent,
// screen size, the capture window, and the current network snapshot so a reader
// has the environment without digging. The timeline is the ring (oldest first).
export function snapshot() {
  let conn = null
  try {
    const c = navigator.connection
    if (c) conn = { effectiveType: c.effectiveType, downlink: c.downlink, rtt: c.rtt, type: c.type, saveData: c.saveData }
  } catch {}
  const first = ring[0]
  const last = ring[ring.length - 1]
  return {
    kind: 'filament-linkdiag',
    v: 1,
    header: {
      generatedAt: new Date().toISOString(),
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
      screen: typeof window !== 'undefined' ? { w: window.screen?.width, h: window.screen?.height, dpr: window.devicePixelRatio } : null,
      visibility: typeof document !== 'undefined' ? document.visibilityState : null,
      online: typeof navigator !== 'undefined' ? navigator.onLine : null,
      connection: conn,
      capture: {
        ringMax: RING_MAX,
        pollMs: POLL_MS,
        count: ring.length,
        dropped,
        firstWall: first ? first.t : null,
        lastWall: last ? last.t : null,
        spanMs: first && last ? last.m - first.m : 0,
      },
    },
    timeline: ring.slice(),
  }
}

export function exportJson() {
  return JSON.stringify(snapshot(), null, 2)
}

// A one-line current status for the live panel: route, RTT, the last event, and
// how many entries are buffered.
export function liveStatus() {
  // Walk back for the most recent route + rtt we recorded.
  let route = null
  let rtt = null
  for (let i = ring.length - 1; i >= 0; i--) {
    const e = ring[i]
    if (route == null && (e.k === 'route' || e.k === 'pair') && e.route) route = e.route
    if (rtt == null && typeof e.rttMs === 'number') rtt = e.rttMs
    if (route != null && rtt != null) break
  }
  const last = ring[ring.length - 1]
  return {
    enabled,
    route,
    rttMs: rtt,
    count: ring.length,
    dropped,
    last: last ? { k: last.k, t: last.t } : null,
  }
}

// ---- per-link sampler (installed by PeerLink) -----------------------------
// attach() wires a getStats poll for ONE link. It returns a small controller the
// link drives on its own lifecycle: start() on channel-open / connected, stop()
// on close / fail. The poll computes COMPACT deltas (advancing? yes/no) rather
// than dumping every counter, and records a 'pair' event whenever the selected
// candidate-pair id changes (the NAT-rebind smoking gun).
//
// `getMeta()` returns { uid, shell } at sample time (shell can flip when a PTY
// opens on the link). `getPc()` returns the live RTCPeerConnection (may be
// replaced across a rebuild, so we read it each tick).
export function attach({ getPc, getMeta }) {
  let timer = null
  let lastPairId = null
  let prev = null // last snapshot's raw counters, for delta computation

  const sample = async () => {
    const pc = getPc?.()
    if (!pc) return
    let stats
    try {
      stats = await pc.getStats()
    } catch {
      return
    }
    const meta = getMeta?.() || {}
    // Find the selected candidate pair via the transport's selectedCandidatePairId
    // (the authoritative source), falling back to a succeeded+nominated pair.
    const cands = {}
    let transportSelectedId = null
    let dataChannelState = null
    stats.forEach((r) => {
      if (r.type === 'local-candidate' || r.type === 'remote-candidate') cands[r.id] = r
      if (r.type === 'transport' && r.selectedCandidatePairId) transportSelectedId = r.selectedCandidatePairId
      if (r.type === 'data-channel') dataChannelState = r.state
    })
    let pair = null
    stats.forEach((r) => {
      if (r.type !== 'candidate-pair') return
      if (r.id === transportSelectedId || (!transportSelectedId && r.state === 'succeeded' && (r.nominated || r.selected))) pair = r
    })
    if (!pair) return // no selected pair yet

    const local = cands[pair.localCandidateId]
    const remote = cands[pair.remoteCandidateId]
    const lt = local?.candidateType
    const rt = remote?.candidateType
    const route = lt === 'relay' || rt === 'relay' ? 'relayed' : lt === 'host' && rt === 'host' ? 'local' : 'direct'

    // CANDIDATE-PAIR CHANGE: the smoking gun for a NAT rebind. Record the full
    // pair description (local/remote types, protocol, network type) on first
    // sight and whenever the selected pair id moves.
    if (pair.id !== lastPairId) {
      lastPairId = pair.id
      record(
        'pair',
        {
          route,
          relayed: route === 'relayed',
          localType: lt || null,
          remoteType: rt || null,
          protocol: local?.protocol || pair.protocol || null,
          relayProtocol: local?.relayProtocol || null,
          networkType: local?.networkType || null,
        },
        meta,
      )
      prev = null // reset deltas across a pair change so advancing? is honest
    }

    // PERIODIC COMPACT SNAPSHOT: RTT, bitrates, whether bytes/packets and ICE
    // consent are ADVANCING (deltas), retransmits, and the data-channel state.
    const rttMs = typeof pair.currentRoundTripTime === 'number' ? Math.round(pair.currentRoundTripTime * 1000) : null
    const cur = {
      bytesSent: pair.bytesSent ?? 0,
      bytesReceived: pair.bytesReceived ?? 0,
      packetsSent: pair.packetsSent ?? 0,
      packetsReceived: pair.packetsReceived ?? 0,
      requestsSent: pair.requestsSent ?? 0,
      responsesReceived: pair.responsesReceived ?? 0,
      consentRequestsSent: pair.consentRequestsSent ?? 0,
      retransmits: pair.retransmissionsSent ?? pair.retransmissionsReceived ?? 0,
    }
    const adv = (a, b) => (b > a ? 1 : b < a ? -1 : 0) // 1 advancing, 0 flat, -1 reset
    const snap = {
      route,
      rttMs,
      outKbps: typeof pair.availableOutgoingBitrate === 'number' ? Math.round(pair.availableOutgoingBitrate / 1000) : null,
      inKbps: typeof pair.availableIncomingBitrate === 'number' ? Math.round(pair.availableIncomingBitrate / 1000) : null,
      dc: dataChannelState,
    }
    if (prev) {
      // Deltas (compact: how much, plus a coarse advancing flag for consent).
      snap.dSent = cur.bytesSent - prev.bytesSent
      snap.dRecv = cur.bytesReceived - prev.bytesReceived
      snap.dPktS = cur.packetsSent - prev.packetsSent
      snap.dPktR = cur.packetsReceived - prev.packetsReceived
      snap.dResp = cur.responsesReceived - prev.responsesReceived // ICE consent: must climb on a live link
      snap.dReq = cur.requestsSent - prev.requestsSent
      snap.dConsent = cur.consentRequestsSent - prev.consentRequestsSent
      snap.dRetx = cur.retransmits - prev.retransmits
      snap.consentAdv = adv(prev.responsesReceived, cur.responsesReceived) // the key liveness signal
    }
    prev = cur
    record('stat', snap, meta)
  }

  return {
    start() {
      if (timer || !enabled) return
      timer = setInterval(sample, POLL_MS)
      sample() // eager first sample so connect shows up immediately
    },
    stop() {
      if (timer) {
        clearInterval(timer)
        timer = null
      }
      prev = null
    },
    // Force an immediate sample (e.g. right after a route detect / restartIce).
    sampleNow: sample,
  }
}

// ---- environment / network taps (installed once) --------------------------
// These are global, not per-link: they correlate a blip with a radio-idle, a
// background, or a network switch. Installed once from the hook bootstrap.
let envInstalled = false
export function installEnv() {
  if (envInstalled || typeof window === 'undefined') return
  envInstalled = true

  const conn = navigator.connection
  const connFields = () => {
    try {
      return conn ? { effectiveType: conn.effectiveType, downlink: conn.downlink, rtt: conn.rtt, type: conn.type } : {}
    } catch {
      return {}
    }
  }
  // Start-of-capture environment baseline.
  record('env', { what: 'start', online: navigator.onLine, visibility: document.visibilityState, ...connFields() })

  let hiddenAt = 0
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      hiddenAt = Date.now()
      record('vis', { state: 'hidden' })
    } else {
      record('vis', { state: 'visible', hiddenMs: hiddenAt ? Date.now() - hiddenAt : 0 })
    }
  })
  window.addEventListener('online', () => record('net', { state: 'online', ...connFields() }))
  window.addEventListener('offline', () => record('net', { state: 'offline' }))
  conn?.addEventListener?.('change', () => record('conn', connFields()))
  window.addEventListener('pagehide', (e) => record('pagehide', { persisted: !!e.persisted }))
  window.addEventListener('pageshow', (e) => record('pageshow', { persisted: !!e.persisted }))
}
