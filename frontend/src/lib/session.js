// session.js — the convergent session (C30).
//
// The cure for the lost-emit disease class (docs/design-c30-convergent-session.md):
// session state is no longer held in N edge-triggered belts (rejoin belt #14,
// subscribeKnown's ack-retry + 45s reconcile, pair-create lease refresh, …).
// Instead ONE level-triggered loop keeps a single `desired` snapshot converged
// with what the server has confirmed.
//
//   desired   = { room, name, uid, channels: Set<hex> }   — edited ONLY by app actions
//   confirmed = { snapshot, at }                           — edited ONLY by sync acks
//
// Every 5s (and on kick(): socket-up, tab-visible) — if the socket is up AND
// (digest(desired) != digest(confirmed) OR confirmed is stale > 30s) — we emit
// ONE idempotent `sync { full desired state }`. The server ensures membership,
// subscriptions, and lease refresh, then acks with its resulting digest; the
// ack stamps `confirmed`. No emit is load-bearing — only convergence is.
//
// Loss shim (gate L): the module silently drops a configurable fraction of its
// OWN emits so any code path that secretly depends on a single emit arriving
// fails in CI by construction. Per the design doc the BROWSER reads this from a
// query param (`?telLoss=0.3&telSeed=...`) — it cannot read process env at
// runtime the way the CLI does. (The pinned protocol names env vars
// FILAMENT_TEST_EMIT_LOSS/FILAMENT_TEST_EMIT_SEED for the CLI flavor; the
// browser-specific mechanism is the query param. See shared notes.)

const TICK_MS = 5000 // loop cadence
const STALE_MS = 30000 // re-sync even if unchanged once confirmed is older than this
const ACK_MS = 4000 // an ack not seen within this window counts as missed

// Stable digest of a desired snapshot. Channels are SORTED before serializing —
// a Set's iteration order is insertion order, so an unsorted digest would
// spuriously differ across re-derivations of the same set.
function digest(s) {
  const chans = [...(s.channels || [])].sort().join(',')
  return `${s.room || ''}|${s.name || ''}|${s.uid || ''}|${chans}`
}

// Seeded PRNG (mulberry32) — deterministic given telSeed, so a lossy run is
// reproducible. Returns floats in [0,1).
function mulberry32(seed) {
  let a = seed >>> 0
  return function () {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// Read the loss config from the URL (browser-only mechanism). Absent/0 → no shim.
function readLossConfig() {
  try {
    const q = new URLSearchParams(window.location.search)
    const loss = parseFloat(q.get('telLoss') || '0')
    if (!(loss > 0)) return { loss: 0, rng: null }
    const seed = parseInt(q.get('telSeed') || '1', 10) || 1
    return { loss: Math.min(1, loss), rng: mulberry32(seed) }
  } catch {
    return { loss: 0, rng: null }
  }
}

// createSession(sig, tel) → { setRoom, setChannels, kick, stop, desired }
//
// sig: signaling client. Must expose `sync(state, onAck)` and a `connected`
//      getter (true when session-state emits can land).
// tel: telemetry fn (ev, data) — kept LOW volume: we only emit when state
//      actually changed or an ack was missed.
export function createSession(sig, tel = () => {}) {
  const desired = { room: null, name: null, uid: null, channels: new Set() }
  let confirmed = { snapshot: null, at: 0 }

  // In-flight guard: 5s tick + kick(socket-up) + kick(visible) all funnel
  // through one emit. While a sync is outstanding (<ACK_MS, not yet acked) we
  // must NOT fire a second — confirmed hasn't updated yet so the digest still
  // differs. This replaces the old debounce; the digest check kills the
  // boot-storm but only with this guard.
  let pendingSince = 0 // 0 = nothing outstanding
  let pendingDigest = null // digest of the snapshot we're awaiting an ack for

  const { loss, rng } = readLossConfig()
  const shouldDrop = () => loss > 0 && rng && rng() < loss

  function maybeSync(now) {
    if (!sig?.connected) return
    // An outstanding sync still inside its ack window: leave it be (the loop
    // retries naturally once the window lapses).
    if (pendingSince && now - pendingSince < ACK_MS) return
    if (pendingSince && now - pendingSince >= ACK_MS) {
      // The ack never came (lost emit, lost ack, or a shim-dropped emit).
      // Report it once, then fall through to re-emit.
      tel('sync-ack', { missed: true })
      pendingSince = 0
      pendingDigest = null
    }

    const dDesired = digest(desired)
    const dConfirmed = confirmed.snapshot ? digest(confirmed.snapshot) : null
    const changed = dDesired !== dConfirmed
    const stale = now - confirmed.at >= STALE_MS
    if (!changed && !stale) return

    // Snapshot desired AT EMIT — channels sorted — and apply it on the ack.
    // The ack callback must not read live `desired`; it may have mutated.
    const snapshot = {
      room: desired.room,
      name: desired.name,
      uid: desired.uid,
      channels: new Set(desired.channels),
    }
    const wire = {
      v: 1,
      room: snapshot.room,
      name: snapshot.name,
      uid: snapshot.uid,
      channels: [...snapshot.channels].sort(),
    }

    pendingSince = now
    pendingDigest = digest(snapshot)
    // Keep tel volume low (spec: only when state changed or an ack was missed).
    // The 30s staleness re-sync is a heartbeat, neither — don't log it.
    if (changed) tel('sync', { changed })

    // Loss shim: drop our OWN emit silently — confirmed stays stale, the loop
    // retries on the next tick, and the missed-ack path fires above.
    if (shouldDrop()) return

    sig.sync(wire, () => {
      // Stale ack guard: only the ack for the snapshot we're awaiting counts.
      if (pendingDigest !== digest(snapshot)) return
      confirmed = { snapshot, at: Date.now() }
      pendingSince = 0
      pendingDigest = null
    })
  }

  // kick(): callers fire this on socket-up and tab-visible for an immediate
  // raise (the immediate-raise semantics the old subscribeKnown had).
  function kick() {
    maybeSync(Date.now())
  }

  const timer = setInterval(() => maybeSync(Date.now()), TICK_MS)

  return {
    // Pure data edit — room membership. kick() to raise immediately.
    setRoom(room, name, uid) {
      desired.room = room
      desired.name = name
      desired.uid = uid
    },
    // Pure data edit — known-device presence channels (64-hex strings).
    setChannels(hexArray) {
      desired.channels = new Set(hexArray || [])
    },
    kick,
    // Invalidate the confirmed snapshot. `confirmed` is implicitly bound to a
    // specific sid's server-side state; a reconnect gives a FRESH sid that the
    // server dropped from its room + subscriptions, so the old confirmation is
    // void. Callers invalidate on every socket-up (then kick): without this, a
    // reconnect within the 30s staleness window would find desired==confirmed
    // and emit nothing — leaving the fresh sid a roomless ghost (#14) with
    // unraised channels (C28) until the staleness timer trips. This is exactly
    // the one re-assert per socket-up the old rejoin belt did.
    invalidate() {
      confirmed = { snapshot: null, at: 0 }
      pendingSince = 0
      pendingDigest = null
    },
    // Teardown — clears the loop timer (HMR/unmount leak otherwise).
    stop() {
      clearInterval(timer)
    },
    // Exposed for tests/inspection — do not mutate directly.
    desired,
  }
}
