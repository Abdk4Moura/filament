// RESILIENCE layer — stall handling (keeping an OPEN-but-dark link alive).
//
// First seam of the resilience layer (docs/archive/plans/consolidation-GOAL-2026-06-16.md §4). Resilience OWNS
// the timers and the mutable episode/idle state — unlike PROTOCOL it is NOT pure
// overall — but the POLICY pieces that don't need a clock are split out here so
// they are directly node-testable. This module currently holds the ladder SHAPE;
// the detection reducer (idle/away/progress/accumulate/grace → correct) and the
// timer-owning StallController are the next slice (they need the freeze-shim
// browser gate / netns lab to verify under real fault, per §6).
//
// The ladder mirrors the Rust `correct_stall` rungs (cli/src/...): least
// disruptive first, bounded, then fail CLEAN (transfers paused/resumable, never
// silently dead).

// The correction rungs, least-disruptive first:
//   'a' liveness ping + (impolite, connected) restartIce — cheapest, in place
//   'b' re-offer/resume unfinished transfers so the data path re-flows
//   'c' escalate to the onStall hook (P1 relay-preferred rebuild)
export const STALL_LADDER = ['a', 'b', 'c']

// Given the rung of the CURRENT in-flight episode (undefined when none is open),
// return the rung to execute NOW. No episode → start at 'a'; 'a' → 'b'; 'b' →
// 'c'; 'c' (ladder spent) → 'fail'. Pure; the caller runs the rung's mechanics
// and latches the new episode.
export function nextStallRung(currentRung) {
  if (!currentRung) return STALL_LADDER[0]
  const i = STALL_LADDER.indexOf(currentRung)
  // Unknown/last rung → ladder exhausted.
  return i >= 0 && i + 1 < STALL_LADDER.length ? STALL_LADDER[i + 1] : 'fail'
}

// ---- the stall DETECTOR (pure reducer) ---------------------------------------
// The watchdog decision extracted 1:1 from webrtc.js `_checkStall`. PeerLink owns
// the STALL_TICK_MS timer and the mutable counters; each tick it hands the
// current counters + this tick's observations to stallTick and applies the
// returned next counters, then runs the ladder iff action === 'correct'.
//
// The detector fires only on an OPEN-but-DARK channel carrying an unfinished
// transfer: no app bytes moved AND the SCTP send buffer not draining for
// >= stallMs. An idle link, an announced-absence ("brb") peer, and any progress
// all reset the idle clock (idle/progress also clear the episode latch; the away
// grace keeps it). Mirrors the Rust client's idle_ms() watchdog.
//
//   state: { idleMs, episode, lastMoved, lastBuffered }   the prior counters
//   obs:   { transferring, awayActive, bytesMoved, buffered, stallMs, tickMs, now }
// Returns:
//   { state: {...next counters}, action: 'none' | 'correct', recovered }
//   recovered is the rung that was open when bytes resumed (for the
//   "stall corrected" log), else null.
export function stallTick(s, o) {
  // Idle: nothing with bytes still to move — reset baseline AND clear any episode.
  if (!o.transferring) {
    return { state: { idleMs: 0, episode: null, lastMoved: o.bytesMoved, lastBuffered: o.buffered }, action: 'none', recovered: null }
  }
  // Announced-absence grace ("brb"/hidden tab): reset baseline + idle, but KEEP
  // the episode latch — they are legitimately away, not stalled.
  if (o.awayActive) {
    return { state: { idleMs: 0, episode: s.episode, lastMoved: o.bytesMoved, lastBuffered: o.buffered }, action: 'none', recovered: null }
  }
  // Progress: app bytes advanced OR the SCTP buffer drained (bytes left for the
  // wire) — reset baseline and clear (reporting) any open episode: link recovered.
  const progressed = o.bytesMoved !== s.lastMoved || o.buffered < s.lastBuffered
  if (progressed) {
    return {
      state: { idleMs: 0, episode: null, lastMoved: o.bytesMoved, lastBuffered: o.buffered },
      action: 'none',
      recovered: s.episode ? s.episode.rung : null,
    }
  }
  // No progress this tick: keep the moved-snapshot, refresh buffered, accumulate.
  const idleMs = s.idleMs + o.tickMs
  const state = { idleMs, episode: s.episode, lastMoved: s.lastMoved, lastBuffered: o.buffered }
  if (idleMs < o.stallMs) return { state, action: 'none', recovered: null }     // still under threshold
  // Over threshold but a rung is mid-convergence (within its ~one-stallMs grace)
  // → wait rather than re-firing the ladder.
  if (s.episode && (o.now - s.episode.at) < o.stallMs) return { state, action: 'none', recovered: null }
  // Stalled past grace → run the correction ladder.
  return { state, action: 'correct', recovered: null }
}
