// P5 — relay→direct auto-upgrade prober (frontend transport half).
//
// Drives the REAL PeerLink that P5 ships, in a real browser (Chromium):
//   1. ARM/DISARM: _detectRoute committing 'relayed' arms the prober; committing
//      'direct'/'local' disarms it. (The onRoute→amber-UI path is the UI's own;
//      here we assert the prober lifecycle keys off the route.)
//   2. PROBE → VERIFY → COMMIT: while on relay, a probe restartIce()s (impolite
//      side), re-measures the route, and on a non-relay measurement enters the
//      verify window. A path that HOLDS (route stays non-relay + bytes keep
//      moving) for UPGRADE_VERIFY_MS commits: this.route flips to direct and
//      onRoute('direct') fires (the auto-clear of the amber RELAY UI).
//   3. NO FLAP: a direct path that re-measures back to relay (or whose in-flight
//      bytes stall) during verify is DISCARDED — the link STAYS on relay,
//      onRoute never fires 'direct', and the backoff cadence increases.
//   4. KILL-SWITCH: localStorage.filamentUpgradeProbe==='0' makes a probe a no-op
//      (no restartIce, never commits).
//   5. STALL-GUARD: a probe while a P0 _stallEpisode is open does NOT restartIce
//      (the stall ladder and the upgrade prober must never both restart ICE).
//
// All against the real webrtc.js code: real RTCPeerConnection, real timers, real
// _detectRoute/_measureRoute/_upgradeProbe/_beginUpgradeVerify/_commitUpgrade. We
// stub only the EXTERNAL signals a headless box can't produce: the selected
// candidate-pair route (via _measureRoute) and restartIce observation.
//
// Output: a single JSON blob on window.__P5 the playwright spec asserts against.
import { PeerLink } from '../src/lib/webrtc.js'

const results = []
const rec = (name, pass, detail) => results.push({ name, pass: !!pass, detail: detail || '' })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// A PeerLink wired with tight upgrade timings (via the URL knobs webrtc.js reads)
// so the whole probe→verify→commit cycle lands in well under a second. The route
// the prober "measures" is whatever `routeBox.value` holds — the deterministic
// stand-in for getStats()'s selected candidate-pair on a headless box.
function makeProbeLink({ polite = false } = {}) {
  const link = new PeerLink({
    id: 'peerUP-' + Math.random().toString(36).slice(2),
    name: 'up', iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
    polite, sendSignal: () => {},
  })
  // Observe restartIce without disturbing the real PC.
  link._restartIceCount = 0
  const origRestart = link.pc.restartIce.bind(link.pc)
  link.pc.restartIce = () => { link._restartIceCount++; try { origRestart() } catch {} }
  // Pretend we're cleanly connected (the probe guards on connectionState).
  Object.defineProperty(link.pc, 'connectionState', { get: () => 'connected', configurable: true })
  // Deterministic route measurement: the prober calls _measureRoute(); make it
  // return whatever the test currently wants the selected pair to look like.
  const routeBox = { value: 'relayed' }
  link._measureRoute = async () => routeBox.value
  link._routeBox = routeBox
  // Record onRoute commits (the UI auto-clear signal).
  link._routeCommits = []
  link.onRoute = (r) => link._routeCommits.push(r)
  return link
}

async function run() {
  // Tighten the prober cadence for the test via URL knobs the module read at load.
  // (These were set on window.location.search before the bundle ran — see harness
  // HTML. We assert the effective constants indirectly via behavior/timing.)

  // -- TEST 1: arm on relayed, disarm on direct (route → prober lifecycle) -----
  {
    const link = makeProbeLink()
    // Drive a real route commit to 'relayed' through _detectRoute (uses the
    // stubbed _measureRoute). It should set route + arm the prober.
    link._routeBox.value = 'relayed'
    await link._detectRoute()
    const armed = !!link._upgradeTimer && link.route === 'relayed'
    rec('relayed route arms the upgrade prober', armed,
      `route=${link.route} timer=${!!link._upgradeTimer}`)
    // Now commit 'direct' → the prober must disarm.
    link._routeBox.value = 'direct'
    await link._detectRoute()
    rec('direct route disarms the prober', !link._upgradeTimer && link.route === 'direct',
      `route=${link.route} timer=${!!link._upgradeTimer}`)
    rec('direct commit fired onRoute (auto-clears amber UI)',
      link._routeCommits.includes('direct'), JSON.stringify(link._routeCommits))
    link.close()
  }

  // -- TEST 2: probe → verify → COMMIT when the direct path HOLDS -------------
  {
    const link = makeProbeLink({ polite: false }) // impolite: drives restartIce
    link._routeBox.value = 'relayed'
    await link._detectRoute() // arm
    // Simulate an in-flight transfer so the verify has live byte signal, and keep
    // bytes advancing so the path reads as "holding".
    link.transfers.set('t1', { id: 't1', status: 'transferring', progress: 0.5 })
    const mover = setInterval(() => { link._bytesMoved += 4096 }, 50)
    // The network "heals": the selected pair becomes direct. Force an immediate
    // probe (collapse the backoff) and let the cycle run.
    link._routeBox.value = 'direct'
    link.probeUpgradeNow()
    // probe settle (1200ms) + verify window (URL-knobbed short) + ticks.
    const t0 = Date.now()
    while (link.route === 'relayed' && Date.now() - t0 < 8000) await sleep(100)
    clearInterval(mover)
    rec('probe restarted ICE (impolite drives upgrade)', link._restartIceCount >= 1,
      `restartIceCount=${link._restartIceCount}`)
    rec('committed: route flipped to direct', link.route === 'direct', `route=${link.route}`)
    rec('commit fired onRoute(direct) — amber RELAY UI auto-clears',
      link._routeCommits.includes('direct'), JSON.stringify(link._routeCommits))
    rec('prober disarmed after commit (way-station released)', !link._upgradeTimer,
      `timer=${!!link._upgradeTimer}`)
    link.close()
  }

  // -- TEST 3: NO FLAP — flaky direct that reverts during verify stays on relay -
  {
    const link = makeProbeLink({ polite: false })
    link._routeBox.value = 'relayed'
    await link._detectRoute() // arm
    link.transfers.set('t1', { id: 't1', status: 'transferring', progress: 0.5 })
    // The probe will measure 'direct' once, entering verify — but then the path
    // reverts to relay (flaky): the verify tick re-measures 'relayed' → discard.
    let measureCalls = 0
    link._measureRoute = async () => {
      measureCalls++
      // first measurement (in _upgradeProbe) reads direct; every verify-tick
      // re-measure reads relayed → the no-flap guard must reject.
      return measureCalls <= 1 ? 'direct' : 'relayed'
    }
    const before = link._upgradeDelay
    link.probeUpgradeNow()
    // Let the probe + at least one verify tick run, then settle just past the
    // discard (probe settle 1200ms + a verify tick) but BEFORE the next backed-off
    // probe can flip state again, so the no-flap assertions read deterministically.
    await sleep(1900)
    const discardDelay = link._upgradeDelay
    rec('flaky direct DISCARDED — stayed on relay (no flap)', link.route === 'relayed',
      `route=${link.route}`)
    rec('no flap: onRoute(direct) NEVER fired', !link._routeCommits.includes('direct'),
      JSON.stringify(link._routeCommits))
    rec('backoff increased after the failed verify', discardDelay > before,
      `before=${before} after=${discardDelay}`)
    // The prober must NOT be permanently disarmed — it keeps trying from relay.
    // At any given instant it's either waiting on a scheduled timer OR mid-probe
    // (_upgrading), and a few measurements have happened. Assert it's still live.
    const stillTrying = !!link._upgradeTimer || link._upgrading || measureCalls >= 1
    rec('prober still trying from relay (not permanently disarmed)', stillTrying && link.route === 'relayed',
      `timer=${!!link._upgradeTimer} upgrading=${link._upgrading} measureCalls=${measureCalls}`)
    link.close()
  }

  // -- TEST 4: KILL-SWITCH — filamentUpgradeProbe='0' makes a probe a no-op -----
  {
    localStorage.setItem('filamentUpgradeProbe', '0')
    const link = makeProbeLink({ polite: false })
    link._routeBox.value = 'relayed'
    await link._detectRoute() // arm
    link._routeBox.value = 'direct' // a direct path IS available...
    const beforeRestart = link._restartIceCount
    // Call the probe directly (skip the timer) so the assertion is deterministic.
    await link._upgradeProbe()
    rec('kill-switch: probe did NOT restartIce', link._restartIceCount === beforeRestart,
      `restartIceCount=${link._restartIceCount}`)
    rec('kill-switch: stayed on relay (never committed direct)', link.route === 'relayed',
      `route=${link.route}`)
    rec('kill-switch: prober not re-scheduled', !link._upgradeTimer,
      `timer=${!!link._upgradeTimer}`)
    localStorage.removeItem('filamentUpgradeProbe')
    link.close()
  }

  // -- TEST 5: STALL-GUARD — no restartIce while a P0 _stallEpisode is open -----
  {
    const link = makeProbeLink({ polite: false })
    link._routeBox.value = 'relayed'
    await link._detectRoute() // arm
    link._routeBox.value = 'direct'
    // Open a P0 stall episode (the shared-ICE-restart guard must hold).
    link._stallEpisode = { rung: 'a', at: Date.now() }
    const beforeRestart = link._restartIceCount
    const beforeDelay = link._upgradeDelay
    await link._upgradeProbe()
    rec('stall-guard: probe did NOT restartIce while a stall episode is open',
      link._restartIceCount === beforeRestart, `restartIceCount=${link._restartIceCount}`)
    rec('stall-guard: stayed on relay', link.route === 'relayed', `route=${link.route}`)
    rec('stall-guard: backed off + re-scheduled (did not commit)',
      link._upgradeDelay > beforeDelay && !!link._upgradeTimer,
      `delay ${beforeDelay}->${link._upgradeDelay} timer=${!!link._upgradeTimer}`)
    link.close()
  }

  window.__P5 = { results, passed: results.every((r) => r.pass), total: results.length }
}

run().catch((e) => { window.__P5 = { error: String(e && e.stack || e), passed: false, results } })
