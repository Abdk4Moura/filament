//! RESILIENCE: keeping a hostile link alive (the Rust mirror of the JS
//! `net/resilience` layer). This module holds the timer-free POLICY of the stall
//! correction ladder; `Conn::correct_stall` in `main.rs` owns the state + I/O
//! (the repair/escalate side effects) and calls in here to classify each tick.
//!
//! Discipline (docs/archive/plans/consolidation-GOAL-2026-06-16.md §3): if it has a timer/retry/reconnect it is
//! RESILIENCE, but the *decision* of which rung to take is pure, so it lives here
//! and is unit-tested directly. Mirrors `frontend/src/net/resilience/stall.js`
//! (`nextStallRung`) + `net/app/recovery.js` (`decideStallEscalation`).

/// Which correction action the stall ladder should take this tick. Pure
/// classification of `Conn::correct_stall`'s nested branches; the caller performs
/// the matching side effect and maps it to the public `Rung`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StallAction {
    /// attempt 0 + a warm relay standby is eligible → instant relay failover.
    WarmCutover,
    /// attempt 0 → re-offer unfinished transfers on the SAME transport (rung a).
    Resume,
    /// 0 < attempt < max → repair the transport IN PLACE (rung c).
    Repair,
    /// attempt >= max, relay permitted → re-establish over the TURN relay (rung d).
    RelayEscalate,
    /// attempt >= max but `--no-relay` → fail clean (partial kept).
    ExhaustedRelayForbidden,
    /// attempt >= max and already on relay → fail clean (no harder rung).
    ExhaustedAlreadyRelay,
}

/// Decide the stall-correction action for this attempt. Pure.
///
/// `attempt` is the 0-based count BEFORE this one (rung a is attempt 0). The
/// warm-cutover early-return guard (an episode already cut over) is handled by the
/// caller before this is reached.
///
///   attempt          0-based correction attempt for this episode
///   max_repairs      STALL_MAX_REPAIRS (the in-place-repair ceiling)
///   warm_eligible    a warm relay standby exists and may be used (long-lived
///                    session, relay permitted, not already on relay, not yet cut over)
///   relay_forbidden  the `--no-relay` hard direct-only promise
///   already_relayed  this link is ALREADY the relay (relay_only)
pub fn decide_stall_action(
    attempt: u32,
    max_repairs: u32,
    warm_eligible: bool,
    relay_forbidden: bool,
    already_relayed: bool,
) -> StallAction {
    if attempt == 0 {
        return if warm_eligible { StallAction::WarmCutover } else { StallAction::Resume };
    }
    if attempt >= max_repairs {
        if relay_forbidden {
            return StallAction::ExhaustedRelayForbidden;
        }
        if already_relayed {
            return StallAction::ExhaustedAlreadyRelay;
        }
        return StallAction::RelayEscalate;
    }
    StallAction::Repair
}

// ============================================================================
// LIVENESS state machine: the data-flow phase of ONE link carrying an in-flight
// transfer, as seen by the bytes-moved stall watchdog.
//
// Why a machine: the watchdog's job is "no data for too long -> correct", but
// "too long" is NOT one number. A link that is still ESTABLISHING (TURN alloc +
// ICE + DTLS/SCTP + first chunk, which over a high-RTT relay routinely takes
// 10-30 s) has not earned the tight flowing-transfer threshold yet; charging it
// that threshold tore the link down and rebuilt it, and the rebuild re-exceeded
// the threshold -> an infinite repair loop that delivered ZERO bytes (the exact
// hang the watchdog exists to prevent). The fix is to make the timeout a
// property OF THE PHASE: this enum names the phases, and `classify` is the ONLY
// place a phase is paired with a clock, so "judge an establishing link by the
// flowing threshold" is unrepresentable.
//
// The phases and their allowed transitions (driven each watchdog tick by the
// observation `LiveObs` = in-flight? transport-up? first-byte-flowed? idle-ms):
//
//        no transfer in flight
//   ┌───────────────────────────────► Idle ◄───────────────────────────┐
//   │                                   │ transfer starts               │
//   │                                   ▼                               │
//   │                 (no transport yet, OR transport up but            │ transfer
//   │                  no first DATA byte) & idle < GRACE               │ ends /
//   │            ┌────────────────► Establishing ─────────┐            │ completes
//   │ first byte │                      │ idle ≥ GRACE     │ first byte │
//   │  + idle    │                      ▼                  │  flows     │
//   │  < STALL   │                   Stalled ◄─────────────┘            │
//   │            │                      │ (caller runs the ladder:      │
//   │            │                      │  decide_stall_action)         │
//   │            │   idle < STALL       ▼                               │
//   └─────────── Flowing ◄──── (repair re-establishes; the fresh        │
//                   │   ▲       transport has no first byte, so it       │
//                   │   │       re-enters Establishing -> GRACE again,   │
//                   └───┘       which is what BREAKS the repair loop)    │
//              idle ≥ STALL → Stalled ──────────────────────────────────┘
//
// Establishing can ONLY be judged by GRACE; Flowing/Stalled by STALL. There is
// no path that judges a not-yet-flowed link by STALL. After a repair, the new
// transport reports flowed=false, so the machine re-enters Establishing and the
// generous grace applies again, structurally preventing the loop.

/// The data-flow phase of one link carrying an in-flight transfer.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Liveness {
    /// No transfer in flight on this link, nothing for the watchdog to judge.
    Idle,
    /// A transfer is in flight but the link has not moved its first DATA byte yet
    /// (no transport, or a transport that has not yet delivered a chunk). Judged
    /// ONLY against the establishment grace, NEVER the flowing-stall threshold.
    Establishing,
    /// A data byte moved within the flowing-stall window. Healthy.
    Flowing,
    /// No progress past this phase's threshold: the watchdog must drive the
    /// correction ladder (`decide_stall_action`).
    Stalled,
}

/// One watchdog-tick observation of a link. The ONLY inputs the phase depends on.
#[derive(Debug, Clone, Copy)]
pub struct LiveObs {
    /// A transfer is in flight on this link (something to watch).
    pub in_flight: bool,
    /// A transport (data channel / QUIC) exists for this link.
    pub transport_up: bool,
    /// The transport exposes a tracked idle clock for current activity.
    pub flowed: bool,
    /// Ms since the last tracked data byte (`u64::MAX` if unavailable).
    pub idle_ms: u64,
    /// Before-first-byte establishment grace (`net::establish_grace_ms`).
    pub grace_ms: u64,
    /// Flowing-transfer no-progress threshold (`net::stall_ms`).
    pub stall_ms: u64,
}

/// The no-progress timeout a phase is judged against. The SINGLE place a phase
/// maps to its clock: an untracked link gets the grace, a tracked one the
/// tight threshold. Centralizing this is what makes the wrong-threshold bug
/// unrepresentable, callers ask `classify`, they never pick a threshold.
pub fn phase_threshold(flowed: bool, grace_ms: u64, stall_ms: u64) -> u64 {
    if flowed {
        stall_ms
    } else {
        grace_ms
    }
}

/// Classify a link's liveness phase from this tick's observation. Pure and
/// memoryless: the phase is a function of the observation, so there is no stored
/// state that can drift into an illegal combination.
pub fn classify(o: &LiveObs) -> Liveness {
    if !o.in_flight {
        return Liveness::Idle;
    }
    // No transport at all yet: ESTABLISHING, unconditionally. There is no
    // transport-open clock for the bytes watchdog to measure, and a link that
    // never gets a transport is the ESTABLISHMENT watchdog's job (C3 / Ev::Stuck),
    // not this one. Firing the correction ladder here would repair a link that
    // has nothing to repair.
    if !o.transport_up {
        return Liveness::Establishing;
    }
    // Transport up but no tracked activity clock: ESTABLISHING, judged against
    // the grace. Such a link can NEVER be Flowing.
    if !o.flowed {
        let grace = phase_threshold(false, o.grace_ms, o.stall_ms);
        return if o.idle_ms >= grace {
            Liveness::Stalled
        } else {
            Liveness::Establishing
        };
    }
    // A tracked activity clock is available: judged against the tight threshold.
    let thr = phase_threshold(true, o.grace_ms, o.stall_ms);
    if o.idle_ms >= thr {
        Liveness::Stalled
    } else {
        Liveness::Flowing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAX: u32 = 5;

    #[test]
    fn attempt0_warm_eligible_cuts_over() {
        assert_eq!(decide_stall_action(0, MAX, true, false, false), StallAction::WarmCutover);
    }

    #[test]
    fn attempt0_not_warm_resumes() {
        assert_eq!(decide_stall_action(0, MAX, false, false, false), StallAction::Resume);
    }

    #[test]
    fn middle_attempts_repair_in_place() {
        for a in 1..MAX {
            assert_eq!(decide_stall_action(a, MAX, false, false, false), StallAction::Repair);
        }
    }

    #[test]
    fn exhausted_escalates_to_relay_when_permitted() {
        assert_eq!(decide_stall_action(MAX, MAX, false, false, false), StallAction::RelayEscalate);
        assert_eq!(decide_stall_action(MAX + 3, MAX, false, false, false), StallAction::RelayEscalate);
    }

    #[test]
    fn exhausted_with_no_relay_fails_clean() {
        assert_eq!(decide_stall_action(MAX, MAX, false, true, false), StallAction::ExhaustedRelayForbidden);
    }

    #[test]
    fn exhausted_already_on_relay_fails_clean() {
        assert_eq!(decide_stall_action(MAX, MAX, false, false, true), StallAction::ExhaustedAlreadyRelay);
    }

    #[test]
    fn no_relay_takes_priority_over_already_relayed_at_exhaustion() {
        // Mirrors correct_stall: the relay_forbidden branch is checked first.
        assert_eq!(decide_stall_action(MAX, MAX, false, true, true), StallAction::ExhaustedRelayForbidden);
    }

    #[test]
    fn warm_cutover_only_on_first_attempt() {
        // A warm-eligible link past attempt 0 repairs/escalates, never re-cuts-over.
        assert_eq!(decide_stall_action(1, MAX, true, false, false), StallAction::Repair);
        assert_eq!(decide_stall_action(MAX, MAX, true, false, false), StallAction::RelayEscalate);
    }

    // ---- LIVENESS state machine -------------------------------------------
    const GRACE: u64 = 45_000;
    const STALL: u64 = 6_000;

    fn obs(in_flight: bool, transport_up: bool, flowed: bool, idle_ms: u64) -> LiveObs {
        LiveObs { in_flight, transport_up, flowed, idle_ms, grace_ms: GRACE, stall_ms: STALL }
    }

    #[test]
    fn no_transfer_is_idle_regardless_of_anything() {
        // !in_flight short-circuits before any threshold is consulted.
        assert_eq!(classify(&obs(false, true, true, u64::MAX)), Liveness::Idle);
        assert_eq!(classify(&obs(false, false, false, 0)), Liveness::Idle);
    }

    #[test]
    fn no_transport_is_always_establishing() {
        // No transport at all: the ESTABLISHMENT watchdog (C3 / Ev::Stuck) owns
        // "never connects", not the bytes watchdog. So this is Establishing
        // regardless of idle, the bytes watchdog must never declare a link with
        // nothing to repair Stalled (firing the ladder would repair nothing).
        for idle in [0u64, STALL + 1, GRACE, u64::MAX] {
            assert_eq!(classify(&obs(true, false, false, idle)), Liveness::Establishing);
        }
    }

    #[test]
    fn pre_first_byte_is_judged_by_grace_not_stall() {
        // THE REGRESSION: a transport that is up but has not delivered its first
        // byte, idle PAST the flowing threshold but WITHIN the grace, MUST be
        // Establishing, never Stalled. The old code declared this Stalled and
        // looped the repair forever, delivering zero bytes.
        let o = obs(true, true, /*flowed*/ false, STALL + 1);
        assert_eq!(classify(&o), Liveness::Establishing);
        // ...and is only Stalled once the (much larger) grace elapses.
        assert_eq!(classify(&obs(true, true, false, GRACE - 1)), Liveness::Establishing);
        assert_eq!(classify(&obs(true, true, false, GRACE)), Liveness::Stalled);
    }

    #[test]
    fn flowing_link_uses_the_tight_threshold() {
        // Once a byte has flowed, the tight STALL threshold applies.
        assert_eq!(classify(&obs(true, true, true, 0)), Liveness::Flowing);
        assert_eq!(classify(&obs(true, true, true, STALL - 1)), Liveness::Flowing);
        assert_eq!(classify(&obs(true, true, true, STALL)), Liveness::Stalled);
    }

    #[test]
    fn dead_transport_idle_max_is_stalled_when_flowed() {
        // A flowed transport reporting idle == u64::MAX (dead) is Stalled.
        assert_eq!(classify(&obs(true, true, true, u64::MAX)), Liveness::Stalled);
        // ...and a not-yet-flowed dead transport is Stalled too (idle >= grace).
        assert_eq!(classify(&obs(true, true, false, u64::MAX)), Liveness::Stalled);
    }

    #[test]
    fn phase_threshold_is_grace_before_first_byte_stall_after() {
        assert_eq!(phase_threshold(false, GRACE, STALL), GRACE);
        assert_eq!(phase_threshold(true, GRACE, STALL), STALL);
    }

    #[test]
    fn repair_re_enters_establishing_grace_breaking_the_loop() {
        // The loop-breaker, as a state sequence: a flowing link stalls; the repair
        // brings up a FRESH transport (flowed=false), which the machine judges by
        // GRACE again (Establishing), not STALL, so a high-RTT relay re-establish
        // that takes > STALL but < GRACE is NOT re-declared Stalled.
        assert_eq!(classify(&obs(true, true, true, STALL)), Liveness::Stalled); // stalls
        // fresh transport after repair, mid-establish over a slow relay:
        assert_eq!(classify(&obs(true, true, false, STALL * 3)), Liveness::Establishing);
        // first byte over the new path -> back to Flowing:
        assert_eq!(classify(&obs(true, true, true, 0)), Liveness::Flowing);
    }

    #[test]
    fn grace_never_below_stall_via_classify_inputs() {
        // Even if a caller passed a grace smaller than stall (misconfig), a
        // not-yet-flowed link is judged by whatever grace was given, net::
        // establish_grace_ms() enforces grace >= stall, so this documents the
        // contract the classifier relies on.
        let weird = LiveObs { in_flight: true, transport_up: true, flowed: false, idle_ms: 5_000, grace_ms: 1_000, stall_ms: 6_000 };
        // idle 5000 >= grace 1000 -> Stalled (classifier honors the inputs).
        assert_eq!(classify(&weird), Liveness::Stalled);
    }
}
