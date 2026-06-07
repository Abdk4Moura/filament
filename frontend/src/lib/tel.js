// Debugger-grade client telemetry (C24). Connection lifecycle ONLY — never
// file names, never contents. Events queue locally and flush via
// navigator.sendBeacon (survives page-hide/unload, exactly the moments we
// most need to observe) with a fetch-keepalive fallback.
//
// What it answers, per the live bug reports:
//   - when did this tab's session open / hide / refocus / die
//   - was the tab FROZEN (heartbeat gap) and for how long
//   - socket connect/disconnect/reconnect, with sid transitions
//   - pair-create round-trip (clicked -> code received, or never: the
//     zombie-socket smoking gun)
//   - per-peer status transitions with dwell times (connecting -> ready in
//     800ms, or connecting -> failed after 21s of lingering)
import { api } from './api.js'

const Q = []
let session = Math.random().toString(36).slice(2, 10)
let seq = 0

export function tel(ev, data = {}) {
  Q.push({ ev, s: session, n: seq++, t: Date.now(), ...data })
  if (Q.length >= 20) flush()
}

export function flush() {
  if (!Q.length) return
  const body = JSON.stringify(Q.splice(0, 50))
  try {
    if (navigator.sendBeacon && navigator.sendBeacon(api('/api/telemetry'), body)) return
  } catch {}
  fetch(api('/api/telemetry'), { method: 'POST', body, keepalive: true }).catch(() => {})
}

// ---- automatic lifecycle instrumentation (installed once) ----
let installed = false
export function installTel(uid) {
  if (installed) return
  installed = true
  tel('session-open', { uid, ua: navigator.userAgent.slice(0, 80), vis: document.visibilityState })

  // freeze detector: a 1s heartbeat; a gap means the tab was suspended —
  // the prime suspect for stale create-code and dead emits.
  let last = Date.now()
  setInterval(() => {
    const now = Date.now()
    if (now - last > 5000) tel('frozen', { gapMs: now - last })
    last = now
  }, 1000)

  let hiddenAt = 0
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      hiddenAt = Date.now()
      tel('hidden', {})
      flush() // beacon NOW; we may be about to die
    } else {
      tel('visible', { hiddenMs: hiddenAt ? Date.now() - hiddenAt : 0 })
      flush()
    }
  })
  window.addEventListener('pagehide', () => {
    tel('pagehide', {})
    flush()
  })
  setInterval(flush, 10000)
}

/// Track one peer's status dwell times: call on every transition.
const dwell = new Map() // peerId -> { status, since }
export function telPeer(id, status, extra = {}) {
  const prev = dwell.get(id)
  if (prev && prev.status === status) return
  if (prev) tel('peer-status', { peer: id.slice(-6), from: prev.status, to: status, dwellMs: Date.now() - prev.since, ...extra })
  else tel('peer-status', { peer: id.slice(-6), to: status, ...extra })
  dwell.set(id, { status, since: Date.now() })
  if (status === 'failed') flush() // the lingering-then-unreachable case
}
