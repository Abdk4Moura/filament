//! CONNECTION STATE: the peer-link table and its per-link record, presence, the
//! resilience / warm-hold bookkeeping, the pure decisions over them, and `Conn`
//! itself -- the orchestration state every command's event loop manipulates.
//!
//! Lifted out of `main.rs` in two slices: 1a moved the state types and their
//! pure helpers, 1b moved `Conn`, `impl Conn` and the owner/principal helpers
//! that sit with them. The command surface deliberately stayed behind:
//! `send_cmd`, `recv_cmd`, `pair_cmd`, `async_main`'s dispatch and the daemon ctl
//! handlers are all still in `main.rs`, which is the only reader of the
//! `pub(crate)` items here.
//!
//! Layout mirrors the state it belongs to, not a new abstraction:
//!   Link / Presence / Rung / StallState / DirectPending   per-link and per-attempt state
//!   ResilienceState / RejoinState / WarmHold / WarmBackoff   bookkeeping bags
//!   Conn + impl Conn                                      the link table and its policy
//!   promotion, adoption, principal, liveness decisions      pure helpers over the above
//!
//! BACK-EDGES -- what a future peer-loop carve still owes. This module calls
//! back into `main.rs` for host- or config-bound helpers (see
//! docs/design-libfilament.md, "the rule for what may leave"):
//! `devices_load`, `load_owner_key`, `local_device_cert_path`,
//! `resolve_peer_identity`, `peer_entry`, `is_self_uid`, `rejoin_unwarned`,
//! `relay_banner`, `relay_forbidden`, and the FLEET/REJOIN/WARM constants.
//! They belong to the CLI until they are injected rather than imported.
use crate::direct;
use crate::holepunch;
use crate::net::{self, Ev, Peer, Transport};
use crate::resilience;
use crate::settings;
use crate::test_hooks;
use crate::ui;
use crate::{
    FLEET_LINK_NAME, MAX_ATTEMPTS, REJOIN_WINDOW, STALL_MAX_REPAIRS, VERIFY_PROBE_SID,
    devices_load, is_self_uid, load_owner_key, local_device_cert_path, peer_entry, rejoin_unwarned,
    relay_banner, relay_forbidden, resolve_peer_identity,
};
use crate::{fleet, identity};
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// Why a direct attempt is being started. A bool pair gave four states, three
/// meaningful and one nonsense (`probe && promote` = "a test dial that tears
/// down a serving link", exactly what the guard exists to prevent), with
/// nothing rejecting it. Every expensive defect this week was a boolean-ish
/// value legal in the type system and wrong in the domain: a hardcoded
/// `answerer: true`, `has_flowed() -> true`, `expected_secret: None`. This
/// makes the meaningless combination unrepresentable instead of merely
/// unreachable-by-convention.
/// What a promotion did to the serving WebRTC link.
///
/// Carried rather than inferred at the call site, because the two outcomes need
/// opposite follow-ups and getting it wrong is silent both ways:
///
///   Replaced  the link was torn down and a successor is coming; announcing the
///             old transport would advertise something already gone.
///   Retained  direct was disabled, or setup failed before registering a
///             pending, so the ORIGINAL link is still live and NOTHING else
///             will announce it. That silence is the macOS wedge.
///
/// The `#[must_use]` is the point, and so is taking this by value in
/// `rearm_channel_ready`: it keeps re-announcement unreachable from a `Normal`
/// or `Probe` start_direct, both of which register a pending WITHOUT dropping,
/// where re-announcing would advertise a transport with a live direct race
/// pending against it. Same argument that made `DirectIntent` an enum rather
/// than two bools.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use = "a promotion that RETAINED the link leaves its transport \
              unannounced, and nothing else will announce it. Pass this to \
              `rearm_channel_ready`, or explain in a comment why this command \
              does not need the retained link announced."]
pub(crate) enum Promotion {
    Replaced,
    Retained,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DirectIntent {
    /// Never disturb a live link.
    Normal,
    /// Upgrade probe: bypass the live-link guard, but never drop.
    Probe,
    /// Option A: the ONLY intent permitted to replace a serving link.
    Promote,
    /// Fleet auto-mesh: dial a same-owner device using the FLEET rendezvous
    /// secret as the transport MAC key. Behaves like `Normal` for teardown, but
    /// the resulting link is born UNPRIVILEGED: the fleet secret is shared by
    /// the whole fleet, so it proves MEMBERSHIP, not identity, and definitely
    /// not owner-equivalence. Identity arrives only with a verified
    /// `fleet-hello` (see cli/src/fleet.rs).
    Fleet,
}

/// #246: a link is dead only when nothing is serving AND its WebRTC peer is
/// not still making progress. `peer_live` is `Peer::is_live` (anything but
/// Failed/Closed); `transport_dead` and `workers_all_dead` describe the direct
/// transports. A WebRTC link that just finished `establish` is
/// (peer_live=true, transport dead, workers empty) and therefore alive: it has
/// no transport or workers YET, but its ICE agent is working. Named as a
/// function so the decision is one expression, unit-testable, and stable
/// across call sites.
pub(crate) fn link_dead_for(peer_live: bool, transport_dead: bool, workers_all_dead: bool) -> bool {
    !peer_live && transport_dead && workers_all_dead
}

/// #246: a link counts as live when any transport serves, any worker serves,
/// or the WebRTC peer is still making progress. The peer clause is what lets a
/// Normal re-dial yield to an establish that is still underway instead of
/// arming a fresh direct attempt (whose fallback timer would then tear the
/// establish down).
pub(crate) fn link_has_live_for(peer_live: bool, primary_ok: bool, workers_ok: bool) -> bool {
    peer_live || primary_ok || workers_ok
}

pub(crate) struct Link {
    /// WebRTC peer connection. `None` for a rung-1 direct link (no ICE/DTLS
    /// negotiation, it rides authenticated QUIC), so every WebRTC-only call
    /// site (`handle_signal`, `fingerprints`, `restart_ice`, the watchdog's
    /// `is_connected`) is reachable only when this is `Some`.
    pub(crate) peer: Option<Arc<Peer>>,
    pub(crate) info: Value, // {id,name,uid} as last seen, enough to re-establish
    pub(crate) name: String,
    pub(crate) uid: Option<String>,
    pub(crate) transport: Option<Arc<dyn Transport>>,
    pub(crate) generation: u32,
    pub(crate) attempts: u32,
    /// C12: proof-verified known device (per link, not global)
    pub(crate) trusted: bool,
    /// (name, secret) hypothesis to prove/verify on this link
    pub(crate) expected_secret: Option<(String, String)>,
    /// The devices.json PETNAME this link proved as (the cap-store key). Set on a
    /// verified `pair-proof` (WebRTC) or at birth for a direct link (already
    /// identity-bound). `None` until proven. Capability lookups (e.g. the `shell`
    /// gate) MUST key on this, NOT on `name` (a presence display string that may
    /// not match a stored record).
    pub(crate) verified_name: Option<String>,
    /// C26: what the status roster shows for this peer
    pub(crate) presence: Presence,
    /// rung-1 (FILAMENT_DIRECT): this link's transport is an authenticated direct
    /// QUIC connection, its pair-secret MAC already proved identity, so the
    /// post-channel DTLS pair-proof is skipped and the link is born trusted.
    pub(crate) direct: bool,
    /// Route label for a direct link (no WebRTC `route()` to query): `direct-quic`
    /// for rung-1, `holepunched` for rung-2. Ignored for WebRTC links.
    pub(crate) direct_route: &'static str,
    /// Parallel QUIC transports for multi-stream file transfer
    /// (`FILAMENT_DIRECT_STREAMS` > 1). Empty when striping is disabled
    /// or when the link uses a non-QUIC transport.
    pub(crate) workers: Vec<Arc<dyn Transport>>,
    /// When this link was established (for the warm-hold pair-proof grace).
    /// `warm_hold_tick` skips re-establish for a live link within this window,
    /// preventing churn while pair-proof verification completes.
    pub(crate) established_at: Option<Instant>,
    /// Identity cert device_pub (set when identity-expose is verified).
    pub(crate) identity_device_pub: Option<[u8; 32]>,
    /// Identity cert user_pub (set when identity-expose is verified).
    pub(crate) identity_user_pub: Option<[u8; 32]>,
    /// Binding strength of the identity fields (set alongside them).
    pub(crate) identity_binding: crate::capability::BindingStrength,
    /// Identity cert expiry (unix seconds). None = no cert resolved.
    pub(crate) identity_cert_expires: Option<u64>,
    /// Principal kind: OwnerDevice or Delegated { caps }. A Delegated
    /// principal CANNOT exist without its ceiling — the compiler enforces it.
    pub(crate) principal_kind: crate::capability::PrincipalKind,
}

impl Link {
    /// The name to SHOW for this peer. A known device proves into its local
    /// petname (`verified_name`); show that, so one device reads consistently as
    /// (e.g.) `dovm` everywhere instead of flipping between the petname and the
    /// peer's broadcast display name (`name`, e.g. `Abdul's server`). The
    /// broadcast name is the fallback only for an unverified / unknown peer.
    pub(crate) fn shown(&self) -> &str {
        self.verified_name.as_deref().unwrap_or(&self.name)
    }

    /// Admit this link as a delegated (auth-key-enrolled) principal.
    /// Ensures caps are structurally tied to the Proven identity — a Delegated
    /// principal CANNOT exist without its ceiling.
    ///
    /// PERSISTENCE INVARIANT: a delegated device record writes its certificate,
    /// reconnect secret, principal kind, capability ceiling, and expiry in one
    /// atomic devices.json update. `resolve_peer_identity` restores the ceiling
    /// and clamps the certificate expiry before any owner-derived authorization.
    /// A same-owner certificate with no matching record fails closed as a
    /// delegated principal with an empty ceiling and expiry zero.
    /// Admit a same-owner FLEET device: identity proven, no ceiling, not owner.
    ///
    /// Deliberately NOT `admit_delegated`. That pins an auth-key ceiling, and the
    /// ceiling check is unconditional and purely restrictive, so the empty
    /// ceiling a sibling starts with denied everything before the fleet policy
    /// was consulted. `trusted` stays false here for the same reason it does
    /// there: binding=Proven is what authorizes, and `trusted` leaks into the
    /// legacy_ok gates.
    pub(crate) fn admit_fleet(&mut self, owner_pub: [u8; 32], device_pub: [u8; 32], expires: u64) {
        self.identity_user_pub = Some(owner_pub);
        self.identity_device_pub = Some(device_pub);
        self.identity_binding = crate::capability::BindingStrength::Proven;
        self.identity_cert_expires = Some(expires);
        self.principal_kind = crate::capability::PrincipalKind::FleetDevice;
    }

    pub(crate) fn admit_delegated(
        &mut self,
        owner_pub: [u8; 32],
        device_pub: [u8; 32],
        expires: u64,
        caps: Vec<String>,
    ) {
        // A delegated principal acts UNDER the owner's user identity (the auth
        // key issuer), so it presents user_pub = owner_pub. evaluate()'s owner
        // shortcut then authorizes, but ONLY after the auth-key caps ceiling
        // (checked first) has passed — so a transfer-only key gets transfer and
        // is denied shell/mount. This is the delegation grant.
        self.identity_user_pub = Some(owner_pub);
        self.identity_device_pub = Some(device_pub);
        self.identity_binding = crate::capability::BindingStrength::Proven;
        self.identity_cert_expires = Some(expires);
        self.principal_kind = crate::capability::PrincipalKind::Delegated { caps };
        // NOTE: deliberately do NOT set self.trusted. binding=Proven satisfies
        // cap_trust_floor under authoritative mode, and the auth-key caps ceiling
        // (auth_key_caps ∩ owner_effective) bounds the principal. Setting trusted
        // would leak into legacy_ok for gates that read it directly (e.g. mount),
        // handing an ephemeral borrower an unbounded, un-ceilinged grant.
    }
}

/// C26: per-peer presence for the static status roster.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Presence {
    Connecting,
    Ready,
    Away,
    Reconnecting,
}

fn presence_glyph(p: Presence) -> (&'static str, ui::Tone, &'static str) {
    match p {
        Presence::Ready => (ui::glyph_ok(), ui::Tone::Ok, ""),
        Presence::Away => ("●", ui::Tone::Warn, "away"),
        Presence::Reconnecting => ("◌", ui::Tone::Warn, "reconnecting..."),
        Presence::Connecting => ("◌", ui::Tone::Dim, "connecting..."),
    }
}

/// C18: browsers are mesh peers, they connect to EVERY room member. The CLI
/// must answer every offer politely or unanswered browsers wedge at
/// "connecting" (and their retry storms degrade the whole room). So: a links
/// MAP, every peer answered; SEND still aims transfers at one `active`
/// target; RECV accepts from any link, gated per-link by consent/trust.
const MAX_LINKS: usize = 16;

/// RESILIENCE state, split out of the `Conn` god-struct so the stall/relay/
/// warm-standby/upgrade-probe bookkeeping is one named bag, not mixed in with
/// signaling + protocol state. The pure decisions live in `resilience.rs`.
#[derive(Default)]
pub(crate) struct ResilienceState {
    /// P0 (GAP-1): per-peer stall-repair bookkeeping for the bytes-moved
    /// watchdog. Tracks how many correction-ladder repairs we've already run for
    /// the current stall episode (bounded by MAX_ATTEMPTS) and whether a repair
    /// is in flight, so a single stall can't re-fire the ladder every tick while
    /// a repair is converging. Reset once the link starts flowing again.
    pub(crate) stall_repairs: HashMap<String, StallState>,
    /// P1 (GAP-4): peers this session has COMMITTED to the relay route after the
    /// direct ladder exhausted (rung d). Once a pid is in here, we stop dialing /
    /// answering direct-QUIC for it (the direct path is what just failed and would
    /// only re-freeze, racing the relay link); all (re)establishment for it goes
    /// over relay-only WebRTC. Survives link drops (keyed by pid, not stored on the
    /// Link), so a re-establish never bounces back to the known-bad direct path.
    pub(crate) relay_committed: std::collections::HashSet<String>,
    /// P3 (GAP-3): the WARM-REDUNDANCY selectivity gate. TRUE only for long-lived
    /// / interactive sessions (the `up`/`up --shell` daemon acceptor; a transfer
    /// flagged interactive via `FILAMENT_WARM_STANDBY=1` standing in for a tunnel),
    /// the sessions §2.4 says a mid-session drop is intolerable for. When set,
    /// `correct_stall` keeps the relay path as a pre-designated WARM standby and
    /// CUTS OVER to it on the FIRST stall (rung b) instead of grinding through the
    /// slow direct-repair rung (c)'s up-to-MAX_ATTEMPTS cold re-dials, so the
    /// failover is near-instant rather than a perceptible gap. FALSE for one-shot
    /// file `send` (the 90% case): the on-disk partial + C7 resume make the cold
    /// repair ladder correct and bounded, and a warm standby isn't worth a second
    /// socket / NAT mapping / keepalive for a single transfer (the honest cost
    /// tradeoff, §2.4 / §6). Defaulted by session kind at construction, overridable
    /// by `net::warm_standby_override()` (`FILAMENT_WARM_STANDBY`).
    pub(crate) warm_standby: bool,
    /// P3: per-peer warm-standby bookkeeping, peers whose relay standby has
    /// already been cut over to in the current stall episode, so a flapping relay
    /// path can't re-fire the instant cutover every tick (it falls through to the
    /// bounded relay-stalled `Exhausted` honesty instead). Cleared by
    /// `note_progress` once bytes move again.
    pub(crate) warm_cutover: std::collections::HashSet<String>,
    /// P5 (GAP-6): per-peer relay->direct UPGRADE-PROBE bookkeeping. Present only
    /// for peers currently committed to relay (`relay_committed`) on a session
    /// where the prober is eligible (warm_standby/daemon, relay permitted). Drives
    /// the backoff schedule (probe soon, then steady cadence) and the
    /// verify-before-upgrade window for a connected direct standby. Removed on a
    /// successful upgrade (cutover) or when the peer leaves.
    pub(crate) upgrade_probe: HashMap<String, UpgradeProbe>,
    /// P5: a snapshot of the local interface set (sorted IP strings) at the last
    /// probe schedule. A change (new/removed interface, wifi<->cellular,
    /// default-route move surfacing a new local IP) is the "walked home onto wifi"
    /// signal, we re-probe IMMEDIATELY. Polled cheaply each tick (no platform
    /// netlink dependency); the portable best-effort trigger the plan asks for.
    pub(crate) iface_snapshot: Vec<String>,
}

/// ORCHESTRATION: peer-absence / rejoin-grace bookkeeping, split out of the Conn
/// god-struct. Tracks the reconnect window we hold open for a vanished peer and a
/// peer's declared absence (C21 `brb`).
pub(crate) struct RejoinState {
    /// when set, we are holding a reconnect window open for a vanished peer.
    pub(crate) waiting_rejoin: Option<Instant>,
    /// How long the current rejoin window runs (set when it opens; depends on
    /// whether the peer declared `brb`).
    pub(crate) rejoin_window: Duration,
    /// (peer sid, until), the peer told us it's stepping away (C21).
    pub(crate) away: Option<(String, Instant)>,
}

/// WARM-HOLD state: keeps connections alive to recently-used and explicitly
/// configured peers so `filament reach`/`ssh` is instant.
///
/// Design:
/// - EXPLICIT peers: from `filament set warm-peers dovm,popos` (always connected)
/// - RECENT peers: LRU of last 5 peers used for send/ssh/ping (auto-connected)
/// - RECONNECT: exponential backoff (1s, 2s, 4s, 8s, 16s, 30s cap) on drop
/// - DORMANT: go dormant after 5 failed attempts; resume on peer presence
const WARM_RECENT_CAP: usize = 5;
const WARM_MAX_BACKOFF: Duration = Duration::from_secs(30);
const WARM_DORMANT_THRESHOLD: u32 = 5;
/// A dormant peer is retried this often (instead of never). Presence re-announce
/// still resumes it immediately; this is the floor for a peer whose announces we
/// keep missing.
const WARM_DORMANT_RETRY: Duration = Duration::from_secs(300);

/// Auto-warm size guard: warm at most this many roster peers (see `warm-max`).
/// Must stay under MAX_LINKS (16) so warm-all can never starve on-demand,
/// inbound, or upgrade-probe links of link-table slots.
fn warm_max() -> usize {
    settings::get_str("warm-max", None)
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(12)
        .min(MAX_LINKS - 2)
}

#[derive(Default)]
pub(crate) struct WarmHold {
    /// Explicitly configured peers (from `warm-peers` setting)
    pub(crate) configured: std::collections::HashSet<String>,
    /// AUTO-WARM tier: ALL online paired peers (from the live roster), synced each
    /// warm_hold_tick. ON by default (`auto-warm` setting); also forced on while the
    /// L3 overlay is up (L3 needs live links to route). Bounded by `warm-max`
    /// (Change 4), not by the recent LRU cap.
    pub(crate) auto: std::collections::HashSet<String>,
    /// Recently-used peers in LRU order (most recent at back, capped at 5)
    recent: std::collections::VecDeque<String>,
    /// Per-peer last-use timestamp
    pub(crate) last_use: HashMap<String, Instant>,
    /// Per-peer reconnect backoff state
    backoff: HashMap<String, WarmBackoff>,
}

#[derive(Clone)]
struct WarmBackoff {
    /// Current backoff duration
    duration: Duration,
    /// Number of consecutive failures
    failures: u32,
    /// When we last tried to connect
    last_attempt: Option<Instant>,
    /// True if we've given up (dormant) after too many failures
    dormant: bool,
}

impl Default for WarmBackoff {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(1),
            failures: 0,
            last_attempt: None,
            dormant: false,
        }
    }
}

impl WarmHold {
    /// Record that a peer was just used (transfer, ssh, ping)
    pub(crate) fn note_use(&mut self, peer: &str) {
        let peer = peer.to_string();
        self.last_use.insert(peer.clone(), Instant::now());
        // Move to back of LRU (most recent)
        self.recent.retain(|p| p != &peer);
        self.recent.push_back(peer.clone());
        // Trim to cap
        while self.recent.len() > WARM_RECENT_CAP {
            self.recent.pop_front();
        }
        // Clear dormant flag and reset backoff on use
        if let Some(b) = self.backoff.get_mut(&peer) {
            b.dormant = false;
            b.failures = 0;
            b.duration = Duration::from_secs(1);
        }
    }

    /// Mark a connection attempt failed (exponential backoff)
    pub(crate) fn note_failure(&mut self, peer: &str) {
        let b = self.backoff.entry(peer.to_string()).or_default();
        b.failures += 1;
        b.last_attempt = Some(Instant::now());
        // Exponential backoff with cap
        b.duration = (b.duration * 2).min(WARM_MAX_BACKOFF);
        // Go dormant after too many failures
        if b.failures >= WARM_DORMANT_THRESHOLD {
            b.dormant = true;
        }
    }

    /// Mark a connection succeeded (reset backoff)
    pub(crate) fn note_success(&mut self, peer: &str) {
        if let Some(b) = self.backoff.get_mut(peer) {
            b.failures = 0;
            b.duration = Duration::from_secs(1);
            b.dormant = false;
        }
    }

    /// Check if a peer should be connected (configured OR auto OR recently used, not dormant)
    pub(crate) fn should_connect(&self, peer: &str) -> bool {
        if self.configured.contains(peer) {
            return true;
        }
        if self.auto.contains(peer) {
            return true;
        }
        if self.recent.contains(&peer.to_string()) {
            // Check if dormant
            if let Some(b) = self.backoff.get(peer) {
                return !b.dormant;
            }
            return true;
        }
        false
    }

    /// Get all peers that should be connected
    pub(crate) fn peers_to_connect(&self) -> Vec<String> {
        let mut peers: Vec<String> = self.configured.iter().cloned().collect();
        // Add auto-warm peers (all online paired peers)
        for p in &self.auto {
            if !peers.contains(p) {
                peers.push(p.clone());
            }
        }
        // Add recent peers (capped at 5, not dormant)
        for p in &self.recent {
            if !peers.contains(p) {
                if let Some(b) = self.backoff.get(p) {
                    if !b.dormant {
                        peers.push(p.clone());
                    }
                } else {
                    peers.push(p.clone());
                }
            }
        }
        peers
    }

    /// Check if a peer is dormant (too many failures)
    fn is_dormant(&self, peer: &str) -> bool {
        self.backoff.get(peer).map(|b| b.dormant).unwrap_or(false)
    }

    /// Is this peer due for a (re)connect attempt this tick? Dormant peers get one
    /// probe per WARM_DORMANT_RETRY; non-dormant peers honor their exponential
    /// backoff window (duration since last_attempt).
    pub(crate) fn due(&self, peer: &str) -> bool {
        match self.backoff.get(peer) {
            None => true,
            Some(b) => {
                let since = b.last_attempt.map(|t| t.elapsed());
                if b.dormant {
                    since.map_or(true, |d| d >= WARM_DORMANT_RETRY)
                } else {
                    since.map_or(true, |d| d >= b.duration)
                }
            }
        }
    }

    /// Resume a dormant peer (e.g., when it reappears in signaling presence)
    pub(crate) fn resume(&mut self, peer: &str) {
        if let Some(b) = self.backoff.get_mut(peer) {
            b.dormant = false;
            b.failures = 0;
            b.duration = Duration::from_secs(1);
        }
    }
}

#[cfg(test)]
mod warm_hold_tests {
    use super::*;

    #[test]
    fn should_connect_configured() {
        let mut wh = WarmHold::default();
        wh.configured.insert("dovm".into());
        assert!(wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn should_connect_l3() {
        let mut wh = WarmHold::default();
        wh.auto.insert("dovm".into());
        assert!(wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn should_connect_recent_not_dormant() {
        let mut wh = WarmHold::default();
        wh.note_use("dovm");
        assert!(wh.should_connect("dovm"));
    }

    #[test]
    fn should_connect_false_for_dormant() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(!wh.should_connect("dovm"));
    }

    #[test]
    fn should_connect_false_for_unknown() {
        let wh = WarmHold::default();
        assert!(!wh.should_connect("unknown"));
    }

    #[test]
    fn recent_lru_caps_at_5() {
        let mut wh = WarmHold::default();
        for i in 0..7 {
            wh.note_use(&format!("peer{i}"));
        }
        // Should only have last 5: peer2, peer3, peer4, peer5, peer6
        assert_eq!(wh.recent.len(), WARM_RECENT_CAP);
        assert!(!wh.recent.contains(&"peer0".to_string()));
        assert!(!wh.recent.contains(&"peer1".to_string()));
        assert!(wh.recent.contains(&"peer2".to_string()));
        assert!(wh.recent.contains(&"peer6".to_string()));
    }

    #[test]
    fn recent_evicts_oldest() {
        let mut wh = WarmHold::default();
        wh.note_use("a");
        wh.note_use("b");
        wh.note_use("c");
        wh.note_use("d");
        wh.note_use("e");
        // All 5 present
        assert_eq!(wh.recent.len(), 5);
        // Add 6th - "a" should be evicted
        wh.note_use("f");
        assert_eq!(wh.recent.len(), 5);
        assert!(!wh.recent.contains(&"a".to_string()));
        assert!(wh.recent.contains(&"f".to_string()));
    }

    #[test]
    fn auto_set_is_unbounded() {
        let mut wh = WarmHold::default();
        // Add 10 peers to auto set
        for i in 0..10 {
            wh.auto.insert(format!("peer{i}"));
        }
        // All 10 should be in peers_to_connect
        let peers = wh.peers_to_connect();
        for i in 0..10 {
            assert!(peers.contains(&format!("peer{i}")), "peer{i} missing");
        }
    }

    #[test]
    fn auto_disabled_clears_set() {
        let mut wh = WarmHold::default();
        wh.auto.insert("dovm".into());
        wh.auto.insert("popos".into());
        assert!(wh.should_connect("dovm"));
        // Simulate auto-warm disabled
        wh.auto.clear();
        assert!(!wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn note_failure_backoff_doubling() {
        let mut wh = WarmHold::default();
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(2));
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(4));
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(8));
    }

    #[test]
    fn note_failure_caps_at_30s() {
        let mut wh = WarmHold::default();
        for _ in 0..10 {
            wh.note_failure("dovm");
        }
        assert_eq!(wh.backoff["dovm"].duration, WARM_MAX_BACKOFF);
    }

    #[test]
    fn note_failure_dormant_after_threshold() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.backoff["dovm"].dormant);
        assert!(wh.is_dormant("dovm"));
    }

    #[test]
    fn note_use_clears_backoff() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        wh.note_use("dovm");
        assert!(!wh.is_dormant("dovm"));
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(1));
        assert_eq!(wh.backoff["dovm"].failures, 0);
    }

    #[test]
    fn resume_clears_dormant() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        wh.resume("dovm");
        assert!(!wh.is_dormant("dovm"));
    }

    /// CI GUARDRAIL: warm peers should be instantly connectable.
    /// This is a LOGICAL test (no network) - verifies the warm-hold state
    /// machine would allow instant connection for a warm peer.
    #[test]
    fn warm_peer_allows_instant_connection() {
        let mut wh = WarmHold::default();
        // Simulate a warm peer (configured + auto)
        wh.configured.insert("dovm".into());
        wh.auto.insert("dovm".into());
        wh.note_use("dovm");
        // All paths should return true
        assert!(wh.should_connect("dovm"));
        assert!(!wh.is_dormant("dovm"));
        // Peer is in warm sets
        assert!(wh.configured.contains("dovm"));
        assert!(wh.auto.contains("dovm"));
    }

    #[test]
    fn due_respects_backoff_window() {
        let mut wh = WarmHold::default();
        // No backoff entry -> always due
        assert!(wh.due("unknown"));
        // After one failure, not due until backoff window passes
        wh.note_failure("dovm");
        assert!(!wh.due("dovm")); // 1s window, just failed
    }

    #[test]
    fn dormant_peer_retries_after_interval() {
        let mut wh = WarmHold::default();
        // Make peer dormant
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        // Not due immediately
        assert!(!wh.due("dovm"));
        // After WARM_DORMANT_RETRY, would be due (can't easily test Instant::elapsed
        // without injecting time, so just verify the dormant flag is set)
        assert!(wh.backoff["dovm"].dormant);
    }
}

/// Why a roster entry is being adopted. Contact is the safe default for new
/// call sites; Digest is reserved for roster reconciliation, which must not
/// undo an exhausted give-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdoptSource {
    Contact,
    Digest,
}

pub(crate) fn match_adoption_source(
    suppressed: &mut HashSet<String>,
    peer_id: &str,
    source: AdoptSource,
) -> bool {
    match source {
        AdoptSource::Contact => {
            suppressed.remove(peer_id);
            true
        }
        AdoptSource::Digest => !suppressed.contains(peer_id),
    }
}

pub(crate) fn active_binding_matches(
    binding: &(String, Option<String>),
    peer_id: &str,
    peer_uid: Option<&str>,
) -> bool {
    binding.0 == peer_id
        || binding
            .1
            .as_deref()
            .zip(peer_uid)
            .is_some_and(|(bound, candidate)| bound == candidate)
}

/// P0: one peer's stall-repair episode state.
#[derive(Default)]
pub(crate) struct StallState {
    /// Repairs attempted in the current episode (rung a is the first).
    pub(crate) attempts: u32,
    /// `true` between firing the ladder and the next observed byte of progress,
    /// so the per-tick watchdog doesn't re-arm while a repair is converging.
    pub(crate) pending: bool,
    /// P1 (GAP-4): `true` once this episode escalated to relay (rung d) and a
    /// FRESH relay WebRTC link is establishing (no transport yet). The new link
    /// isn't tracked by `direct_pending`, so without this latch `detect_stall`
    /// would keep seeing the (transport-less) link idle and re-fire the ladder
    /// into a premature `Exhausted` before relay even connects. Cleared by
    /// `note_progress` on the first byte over the relay path.
    pub(crate) relayed: bool,
}

/// P5 (GAP-6): one peer's relay->direct UPGRADE-PROBE state. Lifecycle:
///   IDLE  : armed (relay-committed); `next_at` is when the next probe fires,
///            `attempt` drives the exponential backoff (first_ms → steady_ms).
///   PROBING: a direct dial is in flight (a `DirectPending{probe:true}` exists);
///            we don't re-fire until it resolves (win → VERIFYING, or expiry →
///            back to IDLE with a longer backoff).
///   VERIFYING: a direct standby CONNECTED (`standby` set). It must move data
///            CONTINUOUSLY for `verify_ms` before we cut over; `verify_started`
///            marks when it connected. If it goes idle past `verify_idle_ms` or
///            never reaches `verify_ms` of sustained progress, it is DISCARDED
///            and we go back to IDLE (stay on relay, the no-flap guard).
pub(crate) struct UpgradeProbe {
    /// failed-probe count; each failure backs the cadence off toward steady_ms.
    pub(crate) attempt: u32,
    /// when the next probe may fire (None ⇒ probe ASAP, e.g. just armed or a
    /// network-change re-probe).
    pub(crate) next_at: Option<Instant>,
    /// the connected-but-unverified direct standby transport (VERIFYING state).
    pub(crate) standby: Option<Arc<dyn Transport>>,
    /// the route label of the standby (`direct-quic` / `holepunched`).
    pub(crate) standby_route: &'static str,
    /// when the standby connected, the start of the verify window.
    pub(crate) verify_started: Option<Instant>,
    /// the standby's `idle_ms()` floor observed so far in the verify window, used
    /// to require SUSTAINED progress (it must keep moving, not just connect).
    pub(crate) verify_last_idle: u64,
}

impl UpgradeProbe {
    pub(crate) fn armed() -> Self {
        UpgradeProbe {
            attempt: 0,
            next_at: None, // first probe is scheduled by the prober tick
            standby: None,
            standby_route: "direct-quic",
            verify_started: None,
            verify_last_idle: u64::MAX,
        }
    }
}

/// P0: which correction rung the stall ladder took (see `Conn::correct_stall`).
#[derive(Debug, PartialEq)]
pub(crate) enum Rung {
    /// (a) re-offer unfinished transfers on the SAME transport (resume:true).
    Resume,
    /// (c) the transport was repaired in place (fresh direct dial / ICE-restart).
    Repaired,
    /// (d) P1: direct rungs a→c spent → the link was RE-ESTABLISHED over the TURN
    /// relay (relay-only ICE), preserving the on-disk partial. The fresh relay
    /// transport's ChannelReady re-offers the unfinished transfers (resume:true)
    /// and prints the honest relay banner.
    Relayed,
    /// rungs a→d unavailable: direct rungs spent AND relay is forbidden
    /// (`--no-relay`) or we were already on relay. The caller FAILS CLEANLY, a
    /// kept partial, a clear error, never a hang.
    Exhausted,
}

/// rung-1: state for one in-flight direct-QUIC attempt.
pub(crate) struct DirectPending {
    /// (name, secret) for the known device, gates the attempt and keys the MAC.
    pub(crate) secret: (String, String),
    /// This dial used the FLEET rendezvous secret, so the link it produces must
    /// NOT be born trusted / owner-equivalent. See `DirectIntent::Fleet`.
    pub(crate) fleet: bool,
    /// budget deadline; on expiry with no DirectReady we fall back to WebRTC.
    pub(crate) deadline: Instant,
    /// set once the peer's transport-offer arrived and we spawned the racer, so
    /// a duplicate offer doesn't spawn a second race.
    pub(crate) racing: bool,
    /// kept alive so the bound UDP port stays ours until the race consumes it.
    pub(crate) endpoint: Option<quinn::Endpoint>,
    /// rung-2 (FILAMENT_HOLEPUNCH): a SECOND raw UDP socket, already STUN'd, kept
    /// raw (not connected) so its NAT mapping is the one we punch + run QUIC on.
    /// Consumed by the chained ladder in `on_transport_offer` only if rung-1
    /// fails. None when hole-punch is off or STUN discovery failed.
    pub(crate) punch_sock: Option<std::net::UdpSocket>,
    /// rung-2: our advertised srflx (logged at offer time; kept for diagnostics).
    #[allow(dead_code)]
    pub(crate) my_srflx: Option<std::net::SocketAddr>,
    /// #237: the server-asserted (whoami) public candidate the PEER advertised in
    /// its transport-offer, when the peer adopted one (None when the peer had
    /// already observed OUR address, suppressed whoami, or was answered a local
    /// address). This is the candidate OUR race actually dialed, so it is the one
    /// the relay-fallback attribution may honestly name as "never answered".
    pub(crate) peer_server_public: Option<String>,
    /// #237: set true at the dial site exactly when the race dialed THE PEER'S
    /// CLAIMED server-asserted address (see `dials_claimed`), never for a dial
    /// of any other candidate and never for a knob that skips the dials. The
    /// attribution says "dialed and never answered" only when this is true, so
    /// the sentence is bound to the address it names.
    pub(crate) server_public_dialed: Arc<AtomicBool>,
    /// P5 (GAP-6): this is a relay->direct UPGRADE probe, a direct dial run
    /// ALONGSIDE a live relay link (not the cold establishment path). When the
    /// race wins, `on_transport_offer` posts `Ev::DirectUpgradeReady` (verify-
    /// before-upgrade) instead of `Ev::DirectReady` (which would clobber the
    /// serving relay link). When the budget expires with no winner, `expired_direct`
    /// just DROPS the pending (no WebRTC fallback, the relay link is still serving)
    /// and the prober schedules the next backoff.
    pub(crate) probe: bool,
}

pub(crate) struct Conn {
    pub(crate) server: String,
    pub(crate) sio: filament_signal::Client,
    pub(crate) tx: mpsc::UnboundedSender<Ev>,
    pub(crate) my_uid: String,
    pub(crate) my_id: String,
    pub(crate) relay_only: bool,
    pub(crate) to_filter: Option<String>,
    pub(crate) links: HashMap<String, Link>,
    pub(crate) roster: HashMap<String, Value>, // sid -> {id,name,uid} from welcome/peer-joined
    /// Peer IDs whose exhausted stall ladder deliberately gave up. Contact
    /// clears these; digest reconciliation skips them.
    pub(crate) suppressed_digest_adoptions: HashSet<String>,
    pub(crate) active: Option<String>, // the transfer-target sid (send side)
    /// A code-claimed receive is bound to the peer that completed PAKE. The sid
    /// may change on signaling reconnect, so retain its install uid as well.
    pub(crate) active_binding: Option<(String, Option<String>)>,
    pub(crate) next_gen: u32,
    /// Peer-absence / rejoin-grace state (the reconnect window + declared brb).
    pub(crate) rejoin: RejoinState,
    pub(crate) chunk_size: usize,
    /// #28 (deferred drop): sids that got a peer-left while their data channel
    /// was still FLOWING. The signaling socket left the room, but the WebRTC
    /// link is independent and may be a cosmetic reconnect mid-transfer. We do
    /// NOT drop immediately (that kills a live transfer) and do NOT drop never
    /// (a hard-killed peer reads flowing for a beat and would strand the
    /// sender). Instead we stash the original peer-left payload here and
    /// re-check on every main-loop tick: once the link goes idle past the
    /// flowing threshold (or its channel is dead), we re-inject the stored
    /// peer-left so the normal handler runs verbatim, now dropping it. A live
    /// reconnect never goes idle (the transfer completes on it), so its entry
    /// is reaped harmlessly once done. Cleared in drop_link so a supersede of a
    /// deferred sid can't leave a stale blocker.
    pub(crate) deferred_left: HashMap<String, Value>,
    /// Gate-18 Mode B: set TRUE by the recv loop, each tick, exactly when the
    /// transfer is COMPLETE and nothing is in flight (`completed>0 &&
    /// by_sid.is_empty() && !keep_open`). When it holds, `on_stuck` DROPS a
    /// stuck/lost link instead of re-establishing it: there is nothing left to
    /// fetch, so reconnect attempts are pointless and a sender that departs
    /// AFTER delivering every byte would otherwise FLAP the link forever
    /// (establish → connect → die → Stuck → establish ...), each cycle resetting
    /// `attempts` (so MAX_ATTEMPTS never caps it) and re-arming `expected_secret`
    /// (so `digest_says_alone` never holds), `conn.links` never empties and the
    /// quiet-exit never fires → RC=124 hang. Dropping the link empties
    /// `conn.links` and lets the quiet-exit fire. Recomputed PER TICK (never
    /// sticky) so a mid-transfer link (`by_sid` non-empty) always reconnects
    /// normally, kill-resume (gate 2) and the #28 deferred-drop (gate 11c)
    /// reconnect paths are untouched. Defaults false, so the send-side and
    /// connecting-phase `on_stuck` callers are unaffected.
    pub(crate) recv_done: bool,
    /// rung-1 (FILAMENT_DIRECT): in-flight direct-QUIC attempts, keyed by peer
    /// sid. While an attempt is pending we do NOT establish WebRTC for that peer
    /// (sequential, per the design review, avoids two transports racing to
    /// ChannelReady). On deadline expiry with no DirectReady the entry is
    /// dropped and the normal WebRTC `establish` runs; the fallback is unchanged.
    pub(crate) direct_pending: HashMap<String, DirectPending>,
    /// Bug 2: transport-offers that arrived before the receiver's DirectPending
    /// was created (peer's re-dial after a mid-transfer death). Same class as Bug
    /// 1 (pre-PAKE offers): buffered here and replayed once `start_direct` creates
    /// the pending. pid → (candidates, srflx).
    pub(crate) buffered_offers: HashMap<String, (Vec<String>, Option<String>, Option<String>, u8)>,
    /// RESILIENCE bookkeeping (stall/relay/warm/upgrade); see ResilienceState.
    pub(crate) resil: ResilienceState,
    /// Is the rung-1 direct-QUIC path allowed for THIS session? Normally this is
    /// just `direct::direct_enabled()` (the FILAMENT_DIRECT/FILAMENT_L2 env gate),
    /// but ANY long-lived acceptor must ALSO take it even when those env vars are
    /// unset: the L2/ssh ACCEPTOR (`up --shell`) AND the plain `up` daemon. An
    /// acceptor that doesn't silently drops the initiator's `transport-offer` AND
    /// builds its own WebRTC peer dialing back, colliding with the initiator's
    /// offer (GLARE), which for `up --shell` stalls at "stuck while connecting" and
    /// for a plain `up` (two mutually-known daemons) loops the supersede churn and
    /// never settles to one link. Answering the direct dial instead is sequential,
    /// authenticated, and rides the reachable host candidate (e.g. the Tailscale
    /// link), so it neither glares nor depends on cross-NAT ICE. Set via
    /// `direct_ok_for`; `start_direct_inner` gates on this instead of the bare env
    /// check. One-shot send/recv/pair keep the bare `direct_enabled()` default.
    pub(crate) direct_ok: bool,
    /// Local transport for same-machine peers.
    pub(crate) local_port: Option<u16>,
    pub(crate) local_listener: Option<Arc<tokio::net::TcpListener>>,
    /// Shared direct-QUIC endpoint, cloned from the originating Endpoint so that
    /// worker connections for multi-stream transfers can be dialled (sender side)
    /// or accepted (receiver side) without racing the winner's keepalive closure.
    /// Set once in `start_direct_inner`; `None` when direct is not in use, or
    /// when multi-streaming is disabled (`direct_streams() == 1`).
    pub(crate) direct_endpoint: Option<quinn::Endpoint>,
    /// WARM-HOLD: keeps connections alive to recently-used and explicitly
    /// configured peers so `filament reach`/`ssh` is instant. Tracked per-peer
    /// with LRU eviction and exponential backoff on failures.
    pub(crate) warm_hold: WarmHold,
    /// Oneshot senders for per-endpoint worker port negotiation, keyed by pid.
    /// The dialer-side `spawn_direct_workers` stores a sender here; the
    /// `worker-ports` control message handler delivers the acceptor's port list
    /// through it. Removed by the receiver on delivery (one-shot).
    pub(crate) worker_port_tx: HashMap<String, oneshot::Sender<Vec<u16>>>,
    /// Owner-only roster push bookkeeping: the (epoch, valid_until) last pushed
    /// and the live links it reached, so a re-push fires only on a membership
    /// change (new epoch), a validity refresh (new valid_until), or a new link.
    pub(crate) roster_pushed: Option<(u64, u64, HashSet<String>)>,
}

/// What principal a relay->direct upgrade's rebuilt Link should carry.
///
/// Extracted as a PURE fn so the invariant is testable: `Conn::for_command`
/// needs a live socket.io client, so the calling method cannot be unit-tested,
/// and before this the only check on the rule was reading it.
///
/// The rule: carry the pre-upgrade principal. `adopt_direct_transport` used to
/// hardcode `(true, OwnerDevice)`, so an upgrade PROMOTED any link to
/// owner-equivalence, the escalation `adopt_direct` fail-safes against and whose
/// comment records a REVOKED device delivering a file. `None` keeps the old
/// default, since it means the link vanished and that is a separate question.
/// The owner public key that names this machine's resources.
///
/// Prefers the local user key (an owner device holds one), and falls back to the
/// `user_pub` inside this device's own certificate (a joined device does not).
/// Both are the SAME key: a device certificate is signed by the owner, and
/// carries the owner's public half. Using only the first is a bug that silently
/// disables capability resources on every fleet member.
pub(crate) fn owner_pub_for_resources() -> Option<[u8; 32]> {
    if let Ok(Some(k)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        return Some(k.public_key_bytes());
    }
    let raw = std::fs::read_to_string(local_device_cert_path()).ok()?;
    let record: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let cert = crate::identity::DeviceCert::from_json(&record["cert"])?;
    Some(cert.user_pub)
}

pub(crate) fn upgrade_principal(
    carried: &Option<(bool, crate::capability::PrincipalKind)>,
) -> (bool, crate::capability::PrincipalKind) {
    match carried {
        Some((trusted, kind)) => (*trusted, kind.clone()),
        None => (true, crate::capability::PrincipalKind::OwnerDevice),
    }
}

impl Conn {
    /// Single constructor for the `pair`/`send`/`recv` command event loops, which
    /// built the identical ~17-field `Conn` literal three times (the only
    /// per-command differences are `relay_only`, `to_filter`, and the
    /// warm-standby default). Everything else is the fixed fresh-session state.
    /// `warm_standby_default` is the per-session-kind default that the
    /// `FILAMENT_WARM_STANDBY` override (via `net::warm_standby_override`) can
    /// still force either way. NOTE: the long-lived `up` daemon loop keeps its
    /// own literal on purpose, it is a different (non-command) session.
    pub(crate) fn for_command(
        server: &str,
        sio: filament_signal::Client,
        tx: mpsc::UnboundedSender<Ev>,
        my_uid: String,
        relay_only: bool,
        to_filter: Option<String>,
        warm_standby_default: bool,
        direct_ok: bool,
    ) -> Self {
        Conn {
            server: server.to_string(),
            sio,
            tx,
            my_uid,
            my_id: String::new(),
            relay_only,
            to_filter,
            links: HashMap::new(),
            roster: HashMap::new(),
            suppressed_digest_adoptions: HashSet::new(),
            active: None,
            active_binding: None,
            next_gen: 0,
            rejoin: RejoinState {
                waiting_rejoin: None,
                rejoin_window: REJOIN_WINDOW,
                away: None,
            },
            chunk_size: net::MAX_DC_PAYLOAD,
            deferred_left: HashMap::new(),
            recv_done: false,
            direct_pending: HashMap::new(),
            buffered_offers: HashMap::new(),
            resil: ResilienceState {
                stall_repairs: HashMap::new(),
                relay_committed: std::collections::HashSet::new(),
                warm_standby: net::warm_standby_override().unwrap_or(warm_standby_default),
                warm_cutover: std::collections::HashSet::new(),
                upgrade_probe: HashMap::new(),
                iface_snapshot: Vec::new(),
            },
            direct_ok,
            local_port: None,
            local_listener: None,
            direct_endpoint: None,
            warm_hold: WarmHold::default(),
            worker_port_tx: HashMap::new(),
            roster_pushed: None,
        }
    }

    pub(crate) fn link(&self, pid: &str) -> Option<&Link> {
        self.links.get(pid)
    }
    pub(crate) fn link_mut(&mut self, pid: &str) -> Option<&mut Link> {
        self.links.get_mut(pid)
    }
    fn active_link(&self) -> Option<&Link> {
        self.active.as_ref().and_then(|a| self.links.get(a))
    }
    pub(crate) fn is_active(&self, pid: &str) -> bool {
        self.active.as_deref() == Some(pid)
    }
    pub(crate) fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.active_link().and_then(|l| l.transport.clone())
    }
    pub(crate) fn transport_of(&self, pid: &str) -> Option<Arc<dyn Transport>> {
        self.links.get(pid).and_then(|l| l.transport.clone())
    }

    /// Owner-only: mint the current roster and push it to every live link whose
    /// view is stale (membership changed = new epoch, validity refreshed = new
    /// valid_until, or a newly-established link). A push that fails is dropped
    /// silently here; the next tick re-tries because `roster_pushed` still holds
    /// the old mark, so a lost push is not a fact we swallow.
    pub(crate) async fn roster_maintenance(&mut self) {
        let Some(owner) = load_owner_key() else {
            return;
        };
        let now = identity::now_secs();
        let Ok((blob, _changed)) = crate::roster::mint_roster(&owner, now) else {
            return;
        };
        let epoch = blob["epoch"].as_u64().unwrap_or(0);
        let until = blob["valid_until"].as_u64().unwrap_or(0);
        let live: HashSet<String> = self
            .links
            .iter()
            .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| t.is_alive()))
            .map(|(pid, _)| pid.clone())
            .collect();
        let should_push = match &self.roster_pushed {
            None => true,
            Some((e, u, pids)) => *e != epoch || *u != until || *pids != live,
        };
        if !should_push {
            return;
        }
        let mut msg = blob.clone();
        msg["type"] = json!("roster");
        let mut pushed_to: HashSet<String> = HashSet::new();
        for pid in &live {
            if let Some(t) = self.transport_of(pid) {
                if t.send_control(&msg).await.is_ok() {
                    pushed_to.insert(pid.clone());
                }
            }
        }
        if pushed_to.len() != live.len() {
            // A failed push is a fact worth surfacing: a spoke that missed it
            // stays stale until the next successful push. Re-tried next tick.
            let missed = live.len() - pushed_to.len();
            ui::say(&format!(
                "  {} roster push did not reach {missed} device(s); will retry",
                ui::paint(ui::Tone::Warn, ui::glyph_warn())
            ));
        }
        self.roster_pushed = Some((epoch, until, pushed_to));
    }

    /// #28: is the link keyed by `pid` actively moving transfer bytes right now?
    /// The data channel is independent of the signaling socket, so when a
    /// same-uid reconnect arrives as a new sid, superseding must NOT tear down
    /// an old link that's still flowing. A frozen-alive peer (gate 11's
    /// SIGSTOP'd receiver) stops stamping activity, so it reads as not-flowing
    /// and the supersede proceeds as before. Threshold is overridable for
    /// deterministic gating (FILAMENT_ADOPT_ACTIVE_MS); the 3 s default sits
    /// well above a healthy sub-100 ms inter-frame gap so a transient ICE blip
    /// can't masquerade as idle and let a spurious supersede through.
    fn link_flowing(&self, pid: &str) -> bool {
        let threshold = std::env::var("FILAMENT_ADOPT_ACTIVE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3000);
        self.transport_of(pid)
            .map(|t| t.idle_ms() < threshold)
            .unwrap_or(false)
    }

    /// Attach a freshly-opened channel to its link and mark the peer Ready.
    ///
    /// Every `Ev::ChannelReady` arm opened with these same few lines, copied
    /// eight times with three different formattings. The tails genuinely differ
    /// per command, but this prologue never did, and a prologue that is retyped
    /// per call site is one that can drift per call site.
    ///
    /// `claim_active` asks for the peer to become the target if no target exists
    /// yet. Attaching the transport happens FIRST either way: claiming the slot
    /// while the link has no transport hands the caller a target it cannot send
    /// to. Returns true if this peer is now the active one.
    pub(crate) fn mark_ready(
        &mut self,
        pid: &str,
        t: &Arc<dyn Transport>,
        claim_active: bool,
    ) -> bool {
        if let Some(l) = self.link_mut(pid) {
            l.transport = Some(t.clone());
            l.presence = Presence::Ready;
        }
        if claim_active && self.active.is_none() {
            self.active = Some(pid.to_string());
        }
        self.active.as_deref() == Some(pid)
    }

    /// May this peer become the TRANSFER TARGET? (Filters gate targeting,
    /// never answering, every peer still gets a polite link.)
    fn targetable(&self, name: &str, peer_uid: Option<&str>) -> bool {
        if let Some(filter) = &self.to_filter {
            if !name.to_lowercase().contains(&filter.to_lowercase()) {
                return false;
            }
        }
        // Same-role CLI peers never transfer to each other (gate 7).
        if let (Some(pu), Some(my_role)) = (peer_uid, self.my_uid.get(..6)) {
            if pu.starts_with(my_role) {
                return false;
            }
        }
        true
    }

    fn adoption_allowed(&mut self, peer_id: &str, source: AdoptSource) -> bool {
        match_adoption_source(&mut self.suppressed_digest_adoptions, peer_id, source)
    }

    pub(crate) fn bind_active(&mut self, peer_id: &str) {
        let uid = self
            .links
            .get(peer_id)
            .and_then(|link| link.uid.clone())
            .or_else(|| {
                self.roster
                    .get(peer_id)
                    .and_then(|peer| peer["uid"].as_str().map(String::from))
            });
        self.active_binding = Some((peer_id.to_string(), uid));
        self.active = Some(peer_id.to_string());
        self.rejoin.waiting_rejoin = None;
    }

    pub(crate) fn is_bound_active_peer(&self, peer_id: &str) -> bool {
        let uid = self
            .links
            .get(peer_id)
            .and_then(|link| link.uid.as_deref())
            .or_else(|| {
                self.roster
                    .get(peer_id)
                    .and_then(|peer| peer["uid"].as_str())
            });
        self.active_binding
            .as_ref()
            .is_some_and(|binding| active_binding_matches(binding, peer_id, uid))
    }

    /// Track a roster entry and (re)connect to it. `want_active` marks it as
    /// the intended transfer target if it passes the target filters and no
    /// target exists yet. Returns true if this peer is (now) the active one.
    pub(crate) async fn maybe_adopt(&mut self, v: &Value, want_active: bool) -> Result<bool> {
        self.maybe_adopt_from(v, want_active, AdoptSource::Contact)
            .await
    }

    pub(crate) async fn maybe_adopt_from(
        &mut self,
        v: &Value,
        want_active: bool,
        source: AdoptSource,
    ) -> Result<bool> {
        let peer_id = v["id"].as_str().unwrap_or_default().to_string();
        let peer_uid = v["uid"].as_str().map(|s| s.to_string());
        let name = v["name"].as_str().unwrap_or("peer").to_string();
        if peer_id.is_empty() || peer_id == self.my_id {
            return Ok(false);
        }
        if !self.adoption_allowed(&peer_id, source) {
            return Ok(false);
        }
        // NOTE: same-install peers (our own daemon) are filtered at the
        // KnownPeer call sites, NOT here, room discovery must keep working
        // between two processes of one machine (loopback self-send is the
        // first thing every new user tries).
        self.roster.insert(peer_id.clone(), v.clone());
        ui::debug(&format!(
            "filament: ADOPT peer={peer_id} source={source:?} want_active={want_active}"
        ));

        // C6: same device on a NEW sid, supersede the stale link.
        let stale: Option<String> = self
            .links
            .iter()
            .find(|(sid, l)| l.uid.is_some() && l.uid == peer_uid && **sid != peer_id)
            .map(|(sid, _)| sid.clone());
        if let Some(old_sid) = stale {
            // #28: the same device reconnected its signaling socket (fresh sid).
            // If its existing data channel is still flowing, the reconnect is
            // cosmetic, superseding would tear down an active transfer. Keep the
            // old link; once it goes idle a later roster/presence event supersedes.
            if self.link_flowing(&old_sid) {
                // Observable so a gate can assert the keep happened (true
                // positive), not merely that no supersede line appeared.
                ui::debug(&format!("{name} reconnected, keeping active link"));
                return Ok(self.is_active(&old_sid));
            }
            ui::debug(&format!("{name} reconnected, superseding old link"));
            let was_active = self.is_active(&old_sid);
            let secret = self
                .links
                .get(&old_sid)
                .and_then(|l| l.expected_secret.clone());
            self.drop_link(&old_sid);
            self.establish_as(v.clone(), None).await?;
            if let Some(l) = self.links.get_mut(&peer_id) {
                l.expected_secret = secret;
            }
            if was_active {
                self.active = Some(peer_id.clone());
            }
            return Ok(self.is_active(&peer_id));
        }

        if !self.links.contains_key(&peer_id) {
            if self.links.len() >= MAX_LINKS {
                return Ok(false);
            }
            self.establish_as(v.clone(), None).await?;
        }
        // #28: a deferred-active slot is claimable. When the active link got a
        // peer-left but is still flowing, we keep `active` pointing at it (so a
        // same-uid reconnect's supersede still sees it active, and the live
        // transfer's offer/exit machinery is undisturbed). But a DIFFERENT-uid
        // replacement (gate 2: hard-killed receiver, fresh recv) must still be
        // able to take over, otherwise the deferred link squats the slot until
        // the reap, and the replacement (whose ChannelReady already fired) never
        // gets promoted or offered the file. Treating a deferred active as
        // "claimable" promotes the replacement at peer-joined, before its
        // ChannelReady, so the offer goes out on the same baseline path.
        let active_deferred = self
            .active
            .as_ref()
            .is_some_and(|a| self.deferred_left.contains_key(a));
        let binding_allows = self
            .active_binding
            .as_ref()
            .is_none_or(|binding| active_binding_matches(binding, &peer_id, peer_uid.as_deref()));
        if want_active && !binding_allows {
            ui::debug("filament: ADOPT refused: peer is not the authenticated code sender");
        }
        if want_active
            && binding_allows
            && (self.active.is_none() || active_deferred)
            && self.targetable(&name, peer_uid.as_deref())
        {
            // Claiming the slot from a deferred link: discharge that link now
            // (it left the room and is being replaced) so reap doesn't later
            // re-inject a stale peer-left against the slot the new peer holds.
            if active_deferred {
                if let Some(old) = self.active.clone() {
                    if old != peer_id {
                        self.drop_link(&old);
                    }
                }
            }
            self.active = Some(peer_id.clone());
            if let Some(binding) = self.active_binding.as_mut() {
                binding.0 = peer_id.clone();
            }
            self.rejoin.waiting_rejoin = None;
        }
        Ok(self.is_active(&peer_id))
    }

    /// A link is "live" if its primary transport or any worker is still alive,
    /// or its WebRTC peer is still making progress (#246). Restored: the
    /// pending-only guard made it briefly dead, but promotion intent needs it
    /// back. Every caller EXCEPT a deliberate promotion must leave a live link
    /// alone, which is what warm-hold depends on.
    fn has_live_transport(&self, pid: &str) -> bool {
        self.links
            .get(pid)
            .map(|l| {
                // #246: a link mid-establish (peer present, ICE still working
                // toward Connected) is making progress even before any
                // transport/worker exists. Counting it as live is what lets a
                // Normal re-dial yield to the in-flight establish instead of
                // arming a fresh direct attempt whose 5s fallback timer then
                // tears that establish down at the moment it is about to win.
                let peer_live = l.peer.as_ref().map(|p| p.is_live()).unwrap_or(false);
                let primary_ok = l.transport.as_ref().map(|t| !t.is_dead()).unwrap_or(false);
                let workers_ok = l.workers.iter().any(|w| !w.is_dead());
                link_has_live_for(peer_live, primary_ok, workers_ok)
            })
            .unwrap_or(false)
    }

    /// Re-emit `ChannelReady` for a link that ALREADY holds a live transport.
    ///
    /// The `--code` path DEFERS every offer until the PAKE confirms. The offer
    /// site says so, and states who is supposed to wake it:
    ///
    ///     // ...on confirm the Signal handler sets `pake_done` and re-emits
    ///     // ChannelReady to fall through here and offer.
    ///     if use_code && !is_direct && !pake_done {
    ///         continue; // offers/remember wait for PAKE confirm
    ///     }
    ///
    /// The Signal handler sets `pake_done`. It has never re-emitted anything.
    /// What actually woke the loop was the Option A teardown: dropping the link
    /// forced a rebuild, and the rebuilt link's FRESH `ChannelReady` fell through
    /// the (now satisfied) guard and carried the offer. A destroy-and-rebuild
    /// cycle was standing in for an event dispatch.
    ///
    /// That is why removing the unconditional teardown wedged macOS. With direct
    /// disabled there was nothing to promote, so nothing dropped, so nothing was
    /// rebuilt, so no second `ChannelReady` ever arrived. The sender sat on a
    /// healthy authenticated link and never attempted a byte, which is exactly
    /// what the #78 artifact shows: `authenticated, sending`, then 15 minutes of
    /// nothing but 30s backend syncs.
    ///
    /// So this honours the contract the comment already documents. It mirrors
    /// the direct-upgrade re-emit in `adopt_direct_transport`, which does the
    /// same thing for the same reason: a transport that becomes usable without a
    /// fresh channel-open still has to tell the loop.
    ///
    /// No-op when the link is gone or its transport is dead, so it is safe to
    /// call unconditionally after a promotion attempt: if the promotion DID
    /// happen the link was replaced and the new transport will announce itself.
    pub(crate) fn rearm_channel_ready(&self, pid: &str, outcome: Promotion) {
        if outcome == Promotion::Replaced {
            return; // the replacement transport announces itself
        }
        let Some(l) = self.links.get(pid) else { return };
        let Some(t) = l.transport.as_ref() else {
            return;
        };
        if t.is_dead() {
            return;
        }
        let _ = self.tx.send(Ev::ChannelReady(pid.to_string(), t.clone()));
    }

    /// `#[track_caller]` so a teardown NAMES the path that ordered it. There are
    /// 17 call sites, and a link that dies 40ms after authenticating leaves a
    /// `timed out waiting for a peer` whose guard cannot distinguish "no peer
    /// ever arrived" from "the peer's link died". Two of us built root-cause
    /// narratives out of that ambiguity before noticing the instrument was
    /// missing. This is that instrument: no runtime cost, and it cannot drift
    /// from the call sites the way a manual audit does.
    #[track_caller]
    pub(crate) fn drop_link(&mut self, pid: &str) {
        ui::debug(&format!(
            "  drop_link({pid}) ordered by {}",
            std::panic::Location::caller()
        ));
        // #28: dropping a link also discharges any deferred peer-left for it,
        // so a supersede (maybe_adopt) of a deferred same-uid sid can't leave a
        // stale entry blocking adoption. Invariant: deferred_left only ever
        // holds sids that are still live links.
        self.deferred_left.remove(pid);
        self.buffered_offers.remove(pid);
        if let Some(old) = self.links.remove(pid) {
            // Never await close in the event loop (F8): mark + spawn. A direct
            // link has no WebRTC peer; dropping the Link drops its QUIC transport
            // (the keepalive task observes conn.closed() and tears down).
            if let Some(p) = old.peer.clone() {
                p.mark_closed();
                tokio::spawn(async move { p.close().await });
            }
        }
        if self.is_active(pid) {
            self.active = None;
        }
    }

    // --- WARM-HOLD: proactive connection management ---

    /// Record that a peer was just used (transfer, ssh, ping). This updates the
    /// LRU and marks the peer as warm so the daemon proactively connects/reconnects.
    pub(crate) fn note_warm_use(&mut self, peer: &str) {
        self.warm_hold.note_use(peer);
    }

    /// Load configured warm-peers from settings. Called at daemon startup and
    /// at the top of each warm_hold_tick to stay in sync with runtime changes.
    pub(crate) fn load_warm_peers_config(&mut self) {
        if let Some(setting) = settings::get_str("warm-peers", None) {
            self.warm_hold.configured.clear();
            for p in setting.split(',') {
                let p = p.trim().to_string();
                if !p.is_empty() {
                    self.warm_hold.configured.insert(p);
                }
            }
        }
    }

    /// Check for warm peers that need connections and establish them.
    /// Called periodically from the daemon event loop. Returns the list of
    /// peers we attempted to connect to.
    ///
    /// `auto_warm`: sync the auto tier (ALL online paired peers) from the roster.
    /// Default ON (`auto-warm` setting); forced on while L3 is up. When off, the
    /// auto tier is cleared and only configured + recent peers stay warm.
    pub(crate) async fn warm_hold_tick(&mut self, auto_warm: bool) -> Vec<String> {
        // Reload configured peers from settings to stay in sync
        self.load_warm_peers_config();
        if auto_warm {
            let mut online: Vec<(String, Option<Instant>)> = self
                .roster
                .values()
                .filter_map(|v| v["name"].as_str())
                .map(|s| (s.to_string(), self.warm_hold.last_use.get(s).copied()))
                .collect();
            // Change 4 size guard: over warm-max, keep the most recently USED peers
            // warm (never-used peers rank last; name tie-break keeps it deterministic).
            let cap = warm_max();
            if online.len() > cap {
                online.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                online.truncate(cap);
            }
            let current: std::collections::HashSet<String> =
                online.into_iter().map(|(n, _)| n).collect();
            for name in &current {
                if !self.warm_hold.auto.contains(name) {
                    self.warm_hold.auto.insert(name.clone());
                    ui::debug(&format!("warm-hold: auto-warming peer '{name}'"));
                }
            }
            // Drop peers that went offline (or fell over the warm-max recency cut)
            self.warm_hold.auto.retain(|name| current.contains(name));
        } else {
            if !self.warm_hold.auto.is_empty() {
                ui::debug("warm-hold: auto-warm off, clearing auto tier");
                self.warm_hold.auto.clear();
            }
        }
        let mut connected = Vec::new();
        let peers = self.warm_hold.peers_to_connect();
        for peer in peers {
            // Skip re-establish if a link to this pid exists AND is alive AND
            // (verified OR within the pair-proof grace window).  Dead links and
            // alive-but-unverified-past-grace (stuck) links still re-establish.
            // The grace prevents churn during the normal pair-proof verification
            // window while ensuring stuck links are eventually replaced.
            const WARM_PAIR_PROOF_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
            let skip = self.links.iter().any(|(_, l)| {
                // Match by name (peers_to_connect returns names, not IDs)
                l.name.eq_ignore_ascii_case(&peer)
                    // Link is alive: transport alive, OR WebRTC peer exists, OR direct link exists
                    && (l.transport.as_ref().map(|t| t.is_alive()).unwrap_or(false)
                        || l.peer.is_some()
                        || l.direct)
                    && (
                        l.verified_name.is_some()                    // verified: warm-usable, skip
                        || l.established_at                          // within grace: pair-proof expected
                            .map(|t| t.elapsed() < WARM_PAIR_PROOF_GRACE)
                            .unwrap_or(false)
                    )
            });
            if skip {
                ui::debug(&format!(
                    "warm-hold: skip '{peer}' (link alive, within grace)"
                ));
                continue;
            } else {
                ui::debug(&format!(
                    "warm-hold: will establish '{peer}' (no alive link found)"
                ));
            }
            // Honor per-peer backoff; a dormant peer still gets one probe per
            // WARM_DORMANT_RETRY so an online-but-unlucky peer cannot stay cold forever.
            if !self.warm_hold.due(&peer) {
                continue;
            }
            // Find peer info from roster
            if let Some(info) = self.roster.values().find(|v| {
                v["name"]
                    .as_str()
                    .map(|n| n.eq_ignore_ascii_case(&peer))
                    .unwrap_or(false)
                    || v["id"]
                        .as_str()
                        .map(|id| id.eq_ignore_ascii_case(&peer))
                        .unwrap_or(false)
            }) {
                let info = info.clone();
                let _peer_id = info["id"].as_str().unwrap_or_default().to_string();
                // Try to establish connection
                match self.establish_as(info, None).await {
                    Ok(()) => {
                        self.warm_hold.note_success(&peer);
                        ui::debug(&format!("warm-hold: established connection to '{peer}'"));
                        connected.push(peer);
                    }
                    Err(e) => {
                        self.warm_hold.note_failure(&peer);
                        ui::debug(&format!("warm-hold: failed to connect to '{peer}': {e}"));
                    }
                }
            }
        }
        connected
    }

    /// Resume a dormant warm peer (e.g., when it reappears in signaling presence)
    fn resume_warm_peer(&mut self, peer: &str) {
        self.warm_hold.resume(peer);
    }

    /// `force_polite: Some(true)` builds a pure responder link (no local offer)
    /// regardless of uid comparison, required when the link exists to ANSWER
    /// an incoming offer (ensure_responder / glare rebuild). The uid-based role
    /// can come out impolite there (especially on the bare `{id}` roster-miss
    /// fallback, which compares sids), making the "responder" offer too: glare.
    #[track_caller]
    pub(crate) fn establish_as(
        &mut self,
        info: Value,
        force_polite: Option<bool>,
    ) -> impl std::future::Future<Output = Result<()>> + '_ {
        let caller = std::panic::Location::caller();
        async move { self.establish_as_inner(info, force_polite, caller).await }
    }

    async fn establish_as_inner(
        &mut self,
        info: Value,
        force_polite: Option<bool>,
        caller: &'static std::panic::Location<'static>,
    ) -> Result<()> {
        let peer_id = info["id"].as_str().unwrap_or_default().to_string();
        // rung-1: a direct-QUIC attempt owns this peer until its budget expires.
        // Suppress the WebRTC offer so the path stays SEQUENTIAL (no two
        // transports racing to ChannelReady). `expired_direct` removes the
        // pending before calling us for the fallback, so this never blocks it.
        if self.direct_pending.contains_key(&peer_id) {
            return Ok(());
        }
        // P1 (GAP-4): once a peer is committed to relay, a live link already
        // carries (or is converging on) the relay route. Re-establish events
        // (KnownPeer re-announce, expired_direct fallback, a watchdog tick) must
        // NOT tear it down and rebuild mid-handshake, that thrash is exactly why
        // the relay link got "stuck while connecting". A genuinely failed link is
        // removed by the normal drop path (on_pc_state/GraceExpired) FIRST, so when
        // no link is present here we DO proceed to (re)build the relay link.
        if self.resil.relay_committed.contains(&peer_id) && self.links.contains_key(&peer_id) {
            return Ok(());
        }
        // Build the replacement BEFORE destroying what we have. The drop used to
        // happen here, ahead of `fetch_config` and the peer construction below,
        // both of which are fallible and one of which is a network round trip to
        // the signaling server. On any error this returned Err with the link
        // already gone, and three call sites discard that Err, so a transient
        // failure silently converted a working link into no link at all. That is
        // the fallback path: `expired_direct` -> `establish` is what Option A
        // promises when a direct race loses, so a fallback that can destroy
        // without rebuilding is worse than no fast path.
        //
        // Carry the pair-secret forward too. `expected_secret` is what binds the
        // post-channel pair-proof to the SAME device, and the designed fallback
        // at the expiry site saves and restores it by hand. Any other path that
        // rebuilt a link, including roster adoption, silently produced a link
        // with `expected_secret: None`: no re-dial of direct, and no device
        // binding. Preserving it here fixes every rebuild path at once instead
        // of asking each caller to remember.
        let carried_secret = self
            .links
            .get(&peer_id)
            .and_then(|l| l.expected_secret.clone());
        let peer_uid = info["uid"].as_str().map(|s| s.to_string());
        let peer_present = self.roster.contains_key(&peer_id);
        let name = info["name"].as_str().unwrap_or("peer").to_string();
        // C5: fresh ICE config (TURN creds are expiry-stamped HMACs) for
        // every attempt, not just the first.
        let mut cfg = net::fetch_config(&self.server).await?;
        self.chunk_size = cfg.chunk_size;
        let polite = match force_polite {
            Some(value) => value,
            None => match peer_uid.as_deref() {
                Some(peer_uid) => net::polite_role(&self.my_uid, peer_uid, &self.my_id, &peer_id)?,
                None => {
                    let source = if peer_present {
                        "presence"
                    } else {
                        "absent-roster"
                    };
                    net::polite_role_legacy(
                        &self.my_uid,
                        None,
                        &self.my_id,
                        &peer_id,
                        source,
                        peer_present,
                    )?
                }
            },
        };
        self.next_gen += 1;
        let generation = self.next_gen;
        // P1 relay-fallback gate (test-only): FILAMENT_TEST_WEBRTC_RELAY_ONLY=1
        // models a peer with NO direct WebRTC path (hard NAT), every WebRTC link
        // is relay-only, so when the direct-QUIC ladder freezes/exhausts the
        // transfer can ONLY complete over the TURN relay. Faithful to the real
        // "direct can't, relay can" condition the auto-fallback exists for; never a
        // product knob. OR'd with the real relay_only (set by --relay or by an
        // auto escalate_to_relay).
        let relay_ice = self.relay_only || test_hooks::webrtc_relay_only();
        // P1 (GAP-4): --no-relay is a HARD direct-only promise, never traverse a
        // relay. Strip TURN servers from the ICE config so no relay candidate can
        // ever be gathered. A peer reachable ONLY via relay then simply fails to
        // connect, honestly, by the user's own choice, instead of silently using
        // a middleman. (The ICE policy is left as-is: a relay-only policy with no
        // relay servers has no candidates and fails cleanly, which is the point.)
        if relay_forbidden() {
            cfg.ice_servers.retain(|s| net::is_stun_only(s));
        }
        let peer = Peer::connect(
            peer_id.clone(),
            self.my_uid.clone(),
            polite,
            cfg.ice_servers,
            relay_ice,
            self.sio.clone(),
            self.tx.clone(),
            generation,
        )
        .await?;
        // Everything fallible is done: NOW replace. Until this point the old link
        // was still serving, so an early return above leaves it untouched.
        self.drop_link(&peer_id);
        self.links.insert(
            peer_id.clone(),
            Link {
                peer: Some(peer),
                info,
                name,
                uid: peer_uid,
                transport: None,
                workers: vec![],
                generation,
                attempts: 0,
                trusted: false,
                expected_secret: carried_secret,
                verified_name: None,
                presence: Presence::Connecting,
                direct: false,
                direct_route: "direct-quic", // unused for WebRTC links (peer.is_some())
                established_at: Some(Instant::now()),
                identity_device_pub: None,
                identity_user_pub: None,
                identity_binding: crate::capability::BindingStrength::None,
                identity_cert_expires: None,
                principal_kind: crate::capability::PrincipalKind::OwnerDevice,
            },
        );
        ui::debug(&format!(
            "filament: ESTABLISH peer={peer_id} caller={caller}"
        ));
        Ok(())
    }

    // --- rung-1 direct-QUIC path (FILAMENT_DIRECT) ---------------------------
    //
    // Sequential by design: when both peers are CLIs and a pair secret is known,
    // try a direct authenticated QUIC connection FIRST and only fall back to the
    // WebRTC `establish` above if no authenticated connection lands within the
    // budget. The whole thing is gated on `direct::direct_enabled()`, so with the
    // flag OFF none of this runs and the WebRTC path is byte-for-byte unchanged.

    /// Begin a direct attempt against `pid`: bind a quinn endpoint, advertise our
    /// candidates via a relayed `transport-offer`, and stash the pending state.
    /// No Link is created yet, it is born (with `peer: None`, pre-trusted) only
    /// when an authenticated connection wins (Ev::DirectReady). Idempotent per
    /// peer (a second call while pending is a no-op). The peer's own
    /// transport-offer (Ev::TransportOffer) drives the race.
    pub(crate) async fn start_direct(&mut self, pid: &str, name: &str, secret: &str) {
        self.start_direct_inner(pid, name, secret, DirectIntent::Normal)
            .await
    }

    /// Dial a same-owner device met on the fleet channel. There is no pair
    /// secret for such a peer, so the fleet rendezvous secret keys the MAC. The
    /// display name is deliberately one no petname can be, because it must never
    /// key into the capability store; `adopt_direct` leaves `verified_name`
    /// unset for fleet links regardless.
    pub(crate) async fn start_direct_fleet(&mut self, pid: &str, secret: &str) {
        self.start_direct_inner(pid, FLEET_LINK_NAME, secret, DirectIntent::Fleet)
            .await
    }

    /// Option A: replace the serving WebRTC link with direct after PAKE. This
    /// is the ONLY caller permitted to tear down a live link, and the teardown
    /// happens inside `start_direct_inner` AFTER `direct_pending` is registered,
    /// so a failure anywhere in setup leaves WebRTC serving and the fallback
    /// reaper has an attempt to expire.
    pub(crate) async fn start_direct_promote(
        &mut self,
        pid: &str,
        name: &str,
        secret: &str,
    ) -> Promotion {
        self.start_direct_inner(pid, name, secret, DirectIntent::Promote)
            .await;
        // The promotion drops the link ONLY after registering a pending (the
        // insert and the drop are straight-line, nothing returns between them),
        // so the link's continued existence is an exact witness of which
        // outcome happened and does not need threading out of the early returns.
        if self.links.contains_key(pid) {
            Promotion::Retained
        } else {
            Promotion::Replaced
        }
    }

    /// P5 (GAP-6): arm a relay->direct UPGRADE probe, a direct dial run
    /// ALONGSIDE the live relay link. Bypasses the `relay_committed` /
    /// already-linked early-returns of `start_direct` (the whole POINT is to dial
    /// direct while a relay link serves), and marks the `DirectPending` as a
    /// probe so the winner posts `Ev::DirectUpgradeReady` (verify-before-upgrade)
    /// rather than clobbering the serving relay link. A no-op if a probe is
    /// already in flight for this peer.
    async fn start_upgrade_probe(&mut self, pid: &str, name: &str, secret: &str) {
        // A probe already in flight (its own DirectPending), don't double-dial.
        if self.direct_pending.contains_key(pid) {
            return;
        }
        self.start_direct_inner(pid, name, secret, DirectIntent::Probe)
            .await
    }

    /// Ensure we have a TCP listener for local connections.
    async fn ensure_local_listener(&mut self) -> u16 {
        if let Some(p) = self.local_port {
            return p;
        }
        let (listener, port) = crate::local::listen_local().await.unwrap();
        self.local_listener = Some(Arc::new(listener));
        self.local_port = Some(port);
        port
    }

    /// `promote`: this call is REPLACING a serving WebRTC link with direct
    /// (Option A after PAKE). Only then may a live link be torn down, and only
    /// after `direct_pending` is registered so the fallback reaper has an
    /// attempt to expire. Every other caller (known-peer appeared, warm-hold,
    /// re-dial) must leave a healthy link alone: dropping it there is what broke
    /// `warm_all_makes_first_contact_warm`, because warm-hold's whole job is to
    /// have a link already up when first contact arrives.
    async fn start_direct_inner(
        &mut self,
        pid: &str,
        name: &str,
        secret: &str,
        intent: DirectIntent,
    ) {
        let probe = intent == DirectIntent::Probe;
        // Gate on the per-session flag, not the bare env check: the L2/ssh
        // acceptor (`up --shell`) sets `direct_ok` true even with the env unset,
        // so it answers the initiator's transport-offer (rung-1 direct-QUIC over
        // the reachable host candidate) instead of building a colliding WebRTC
        // peer that glares with the initiator's offer.
        if !self.direct_ok {
            return;
        }
        if !probe && self.resil.relay_committed.contains(pid) {
            // P1: this peer escalated to relay, never re-dial direct (it would
            // only re-freeze and race the relay link). If a link already exists
            // (the relay link that escalate_to_relay built, possibly still
            // converging), DON'T rebuild it, repeated KnownPeer/`appeared` events
            // would otherwise tear it down and re-establish mid-handshake, so it
            // never connects ("stuck while connecting"). Only (re)establish over
            // relay when there is no link at all to carry the session.
            // P5 (GAP-6): a `probe` deliberately bypasses this guard, it dials
            // direct ALONGSIDE the serving relay link (warm direct standby) and
            // never touches `links`, so it cannot disturb the relay path.
            if !self.links.contains_key(pid) {
                let info = json!({ "id": pid, "name": name });
                if let Err(e) = self.establish_as(info, None).await {
                    ui::debug(&format!("  re-establish for {pid} failed: {e}"));
                }
            }
            return;
        }
        // A probe expects a relay link to be present (it's the one we'd upgrade
        // AWAY from); only the cold path bails when a link already exists.
        // #246: a link without a transport and without workers is NOT
        // necessarily dead. A WebRTC link that just finished `establish` has
        // exactly that shape: peer present, ICE gathering, presence
        // Connecting. Judging it dead here is what destroyed the in-flight
        // ICE agent about a second into the relay fallback, on every 5s direct
        // retry, forever. A link is dead only when BOTH nothing is serving AND
        // its peer has reached a terminal state (Failed/Closed) or is absent.
        let link_dead = self
            .links
            .get(pid)
            .map(|l| {
                let peer_live = l.peer.as_ref().map(|p| p.is_live()).unwrap_or(false);
                link_dead_for(
                    peer_live,
                    l.transport.as_ref().map(|t| t.is_dead()).unwrap_or(true),
                    l.workers.iter().all(|w| w.is_dead()),
                )
            })
            .unwrap_or(false);
        if link_dead {
            // The link is already dead, so destroying it loses nothing. Its
            // PENDING is a different matter, see `supersede`.
            self.drop_link(pid);
        }
        // A stale pending must not BLOCK a fresh attempt, but REMOVING it here
        // would disarm the fallback, and the two are not the same thing.
        //
        // `expired_direct` reaps a pending in order to fire the WebRTC
        // re-establish, so a pending removed now and not replaced is a recovery
        // trigger that can never fire. `bind_endpoint` is ~24 lines below and
        // returns ~100 lines BEFORE the re-insert, so a box where bind fails
        // (which is exactly a box where the previous attempt died and left a
        // dead link, so the two conditions co-occur by construction rather than
        // by coincidence) ends with no link, no pending, and nothing armed.
        //
        // That is the same destroy-without-a-successor shape as the teardown
        // bug this file already fixed, one level up: not the link this time,
        // the recovery trigger. The rule is identical. Do not remove the
        // pending until you are certain you can replace it.
        //
        // So the decision to supersede is made WITHOUT mutating. The insert
        // below replaces the entry, and that is the first point at which we are
        // certain a replacement exists. A promotion supersedes for its own
        // reason: any pending started before PAKE completed was dialled without
        // the shared secret and cannot authenticate, so letting it block the
        // promotion is how Option A silently never runs.
        let supersede = link_dead || intent == DirectIntent::Promote;
        if self.direct_pending.contains_key(pid) && !supersede {
            return; // already trying
        }
        // A live link is a REASON TO STOP for everyone except a deliberate
        // promotion. Promotion is the one caller that intends to replace it.
        // #246: `has_live_transport` now counts a mid-establish WebRTC peer as
        // live, so a Normal re-dial YIELDS to an establish that is still
        // making progress instead of arming a fresh direct attempt whose own
        // 5s fallback timer would then re-enter `establish` at the same cursor
        // and swap the still-establishing link. That is the livelock relocated
        // rather than removed, which is why both gates are needed. Promote
        // bypasses on purpose (it is the one caller that intends to displace a
        // live link, and its teardown is the designed Option A), and Probe
        // bypasses on purpose (it dials ALONGSIDE the serving relay link and
        // never touches `links`, so it cannot disturb an establish it did not
        // create).
        if intent == DirectIntent::Normal && self.has_live_transport(pid) {
            return; // already linked via a live transport
        }

        // Check if target is same-machine peer (local transport).
        let peer_uid = self.roster.get(pid).and_then(|info| info["uid"].as_str());
        let is_local = is_self_uid(&self.my_uid, peer_uid);

        let (ep, port) = if is_local {
            // For local peers, we don't need a QUIC endpoint.
            (None, 0u16)
        } else {
            match direct::bind_endpoint() {
                Ok(v) => {
                    // Clone for multi-stream worker connections before the
                    // original is consumed by the race in on_transport_offer.
                    if net::direct_streams() > 1 {
                        self.direct_endpoint = Some(v.0.clone());
                    }
                    (Some(v.0), v.1)
                }
                Err(e) => {
                    // Keep the existing WebRTC link: direct_pending is not
                    // registered yet, so the fallback reaper has nothing to
                    // expire. The caller must retain a working path on failure.
                    ui::debug(&format!(
                        "filament: direct disabled (endpoint bind failed: {e}); WebRTC retained"
                    ));
                    return;
                }
            }
        };
        // #1 (parallelism): gather the host/public candidates (incl. the
        // /api/whoami HTTP) and the rung-2 STUN srflx CONCURRENTLY. Both are
        // independent network round-trips that must finish before the
        // transport-offer can go out, and the initiator's "establishing" phase
        // waits on exactly that offer, so overlapping them shaves a round-trip off
        // every cold connect. Both borrow &self immutably, so join! is sound.
        //
        // rung-2 (FILAMENT_HOLEPUNCH): bind a SECOND raw socket and STUN it so we
        // can advertise a server-reflexive candidate. This socket is kept RAW
        // (not handed to quinn), its NAT mapping is the one we'll punch + run
        // QUIC on if rung-1's host-candidate race fails. STUN failure is graceful:
        // no srflx is advertised and rung-2 simply won't fire for this peer.

        // #237: gather_candidates is the ONE computation of both the candidate
        // set and the server-asserted address adopted into it (Some exactly
        // when a server-chosen address was pushed and no peer had observed us
        // yet). The offer carries that value to the peer so the PEER's race can
        // dial it and, if it never answers, name it at ITS fallback decision.
        // No second copy of the rule exists to desynchronize.
        let (cands, server_public, srflx) = if is_local {
            // For local peers, ensure we have a listener and return TCP candidate.
            if self.local_port.is_none() {
                let (listener, port) = crate::local::listen_local().await.unwrap();
                self.local_listener = Some(Arc::new(listener));
                self.local_port = Some(port);
            }
            let cands = vec![format!(
                "{{\"type\":\"tcp-localhost\",\"port\":{}}}",
                self.local_port.unwrap()
            )];
            (cands, None, None)
        } else {
            let srflx_fut = async {
                if holepunch::holepunch_enabled() {
                    self.gather_srflx().await
                } else {
                    None
                }
            };
            let ((cands, server_public), srflx) =
                tokio::join!(direct::gather_candidates(&self.server, port), srflx_fut);
            (cands, server_public, srflx)
        };

        let (punch_sock, my_srflx) = match srflx {
            Some((sock, srflx)) => (Some(sock), Some(srflx)),
            None => (None, None),
        };

        // transport-offer rides the OPAQUE signaling relay (same channel as ICE
        // signals); the server cannot read or forge it without failing the MAC.
        let mut offer = json!({ "type": "transport-offer", "v": 1, "proto": 2, "addrs": cands });
        if let Some(s) = my_srflx {
            offer["srflx"] = json!(s.to_string());
        }
        // #237: the candidate this offer adopts on the server's say-so alone.
        // The peer dials it; if it never answers, the peer's fallback can name
        // exactly this address instead of claiming a cause it never dialed.
        if let Some(s) = server_public {
            // Test-only (gate C-negative/mismatch): advertise a server_public
            // label that is NOT the dialed candidate, modelling a peer (or
            // adversarially-mislabeled offer) whose claimed address is not in
            // its addrs. The peer that dials THIS offer's addrs must NOT name
            // this label on fallback - it never dialed 8.8.8.8:53.
            let tag = if std::env::var("FILAMENT_DIRECT_SERVER_PUBLIC_MISMATCH")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                "8.8.8.8:53".to_string()
            } else {
                s
            };
            offer["server_public"] = json!(tag);
        }
        // P5 (GAP-6): tag a probe offer so the PEER races it as an upgrade probe
        // too, its winning side then posts Ev::DirectUpgradeReady (verify-before-
        // upgrade) instead of clobbering ITS serving relay link. Both ends must
        // treat the new direct path as a standby until verified, or one end would
        // tear down its relay link unilaterally.
        if probe {
            offer["probe"] = json!(true);
        }
        let _ = self
            .sio
            .emit("signal", json!({ "to": pid, "data": offer.clone() }))
            .await;
        // TRACE, direct-offer / signaling detail.
        ui::trace(&format!(
            "filament: {} sent to {name} ({pid}), port {} srflx {}",
            if probe {
                "UPGRADE-PROBE-OFFER"
            } else {
                "DIRECT-OFFER"
            },
            port,
            my_srflx
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into())
        ));
        // Re-send the offer periodically. The L2 initiator (netcat/ssh) subscribes
        // to the channel AFTER us, so on a late join it can miss BOTH our single
        // fire-once offer AND its own KnownPeer for us (presence delivery is racy),
        // the cross-machine stall. Re-emitting lets it catch a later offer and
        // dial our (reachable) candidates; the initiator only races the FIRST
        // offer it gets, so the extra emits are harmless once linked.
        {
            let sio = self.sio.clone();
            let pid_c = pid.to_string();
            tokio::spawn(async move {
                for _ in 0..6 {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                    let _ = sio
                        .emit("signal", json!({ "to": pid_c, "data": offer.clone() }))
                        .await;
                }
            });
        }
        // The WebRTC fallback reaper (`expired_direct`) fires at this deadline.
        // rung-1's race always burns the full DIRECT_BUDGET when it can't win
        // (its acceptor future never self-completes), so with hole-punch enabled
        // the deadline MUST cover the WHOLE ladder, rung-1 budget + punch budget
        // + QUIC handshake slack, or the reaper would race WebRTC against an
        // in-flight punch and the route would be a coin flip. Flag-gated, so
        // rung-1-only timing is byte-identical.
        let deadline = if holepunch::holepunch_enabled() {
            Instant::now()
                + direct::DIRECT_BUDGET
                + holepunch::PUNCH_BUDGET
                + Duration::from_secs(3)
        } else {
            Instant::now() + direct::DIRECT_BUDGET
        };
        self.direct_pending.insert(
            pid.to_string(),
            DirectPending {
                fleet: intent == DirectIntent::Fleet,
                secret: (name.to_string(), secret.to_string()),
                deadline,
                racing: false,
                endpoint: ep,
                punch_sock,
                my_srflx,
                // #237: the peer's server-asserted candidate arrives with its transport-offer
                // (on_transport_offer fills it); at insert time no offer has
                // arrived yet. The per-address dial gate starts false and flips
                // only when the race dials exactly the claimed address.
                peer_server_public: None,
                server_public_dialed: Arc::new(AtomicBool::new(false)),
                probe,
            },
        );
        // Replace the serving WebRTC link only after all fallible setup has
        // completed and the fallback reaper has a pending attempt to expire.
        // Upgrade probes retain their serving relay link by design.
        if intent == DirectIntent::Promote {
            self.drop_link(pid);
        }
        // Bug 2: replay any transport-offers that were buffered while we had
        // no DirectPending (the sender re-dialed after a mid-transfer death).
        if let Some((cands, srflx, server_public, proto)) = self.buffered_offers.remove(pid) {
            ui::debug(&format!("replaying buffered transport-offer from {pid}"));
            self.on_transport_offer(pid, cands, srflx, server_public, proto);
        }
    }

    /// rung-2: bind a raw punch socket and discover its srflx via STUN against
    /// the ICE config's STUN server. Returns (raw socket, srflx) or None.
    async fn gather_srflx(&self) -> Option<(std::net::UdpSocket, std::net::SocketAddr)> {
        let cfg = net::fetch_config(&self.server).await.ok()?;
        let stun_urls: Vec<String> = cfg
            .ice_servers
            .iter()
            .flat_map(|s| s.urls.iter().cloned())
            .collect();
        // #3 (parallelism): race ALL configured STUN servers so a slow/dead one
        // never stalls gathering (the offer the initiator waits on).
        let stun_addrs = holepunch::stun_server_addrs(&stun_urls);
        if stun_addrs.is_empty() {
            return None;
        }
        let sock = holepunch::bind_punch_socket().ok()?;
        // STUN is blocking UDP I/O, run it off the reactor.
        tokio::task::spawn_blocking(move || {
            holepunch::stun_srflx_any(&sock, &stun_addrs).map(|srflx| (sock, srflx))
        })
        .await
        .ok()?
        .ok()
    }

    /// The peer advertised its candidates. If we have a matching pending attempt
    /// and haven't started the race yet, consume the endpoint and spawn the
    /// simultaneous-open + auth race; the winner posts Ev::DirectReady (or, for an
    /// upgrade probe, Ev::DirectUpgradeReady, verify-before-upgrade).
    /// `peer_server_public`/`peer_proto` come from the peer's transport-offer
    /// (#237): the server-asserted candidate the peer adopted (which OUR race
    /// will dial) and the protocol version that gates the observed-address
    /// exchange.
    pub(crate) fn on_transport_offer(
        &mut self,
        pid: &str,
        peer_cands: Vec<String>,
        peer_srflx: Option<String>,
        peer_server_public: Option<String>,
        peer_proto: u8,
    ) {
        let Some(p) = self.direct_pending.get_mut(pid) else {
            return;
        };
        if p.racing {
            return;
        }
        let Some(ep) = p.endpoint.take() else { return };
        // #237: record what the peer advertised on the server's say-so, BEFORE the
        // race consumes the endpoint. The claim is WIRE DATA and untrusted:
        // it only becomes a fact when the race dials that exact address (the
        // dial site sets server_public_dialed, nothing else can).
        let peer_name = p.secret.0.clone();
        // An unparseable claim can never be dialed (there is no such address);
        // passing None keeps it silent, which is the safe direction.
        let peer_claimed = peer_server_public
            .as_deref()
            .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
        let server_public_dialed = p.server_public_dialed.clone();
        p.peer_server_public = peer_server_public;
        // #237 (mixed-fleet): a peer running an older build (no `proto` >= 2 in
        // its offer) gets a clear sentence instead of a hang or a mismatch. The
        // observed-address exchange is skipped on BOTH sides (the race below is
        // told `exchange=false`, so the stream stays byte-identical to the old
        // protocol and the direct link still forms). A refusal without a
        // sentence is just a support mystery; this is the sentence.
        if peer_proto < 2 {
            crate::ui::say(&format!(
                "peer {peer_name} is running an older build without the direct address exchange; link still works, address supersession skipped"
            ));
        }
        p.racing = true;
        let secret = p.secret.1.clone();
        // P5 (GAP-6): is THIS the upgrade-probe pending? Then the winner posts
        // DirectUpgradeReady (verify-before-upgrade) so the serving relay link is
        // never clobbered. A cold pending posts DirectReady as before.
        let is_probe = p.probe;
        // rung-2: hand the punch socket + peer's srflx to the chained ladder.
        let punch_sock = p.punch_sock.take();
        let peer_srflx_addr = peer_srflx
            .as_deref()
            .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
        let tx = self.tx.clone();
        let pid_s = pid.to_string();
        // #237: the observed-address exchange runs only when BOTH ends agreed
        // (our build is proto 2, so the negotiator is the peer's advertised
        // version). The peer computes the same boolean from OUR offer, so both
        // sides skip or both sides run - never one of each.
        let exchange = peer_proto >= 2;
        let peer_uid = self
            .roster
            .get(pid)
            .and_then(|info| info["uid"].as_str())
            .map(str::to_owned);
        let Some(peer_uid) = peer_uid else {
            eprintln!("direct role election deferred for {pid}: no peer UID");
            return;
        };
        let my_uid = self.my_uid.clone();
        let my_id = self.my_id.clone();
        let mk = move |pid: String, t: Arc<dyn Transport>, route: &'static str| {
            if is_probe {
                Ev::DirectUpgradeReady(pid, t, route)
            } else {
                Ev::DirectReady(pid, t, route)
            }
        };
        tokio::spawn(async move {
            // Check for TCP localhost candidate (same-machine peer).
            for cand in &peer_cands {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(cand) {
                    if v["type"] == "tcp-localhost" {
                        if let Some(port) = v["port"].as_u64() {
                            let addr = format!("127.0.0.1:{port}");
                            ui::trace(&format!("filament: trying TCP localhost to {addr}"));
                            match crate::local::LocalTransport::connect(&addr).await {
                                Ok(t) => {
                                    let _ = tx.send(mk(pid_s, Arc::new(t), "local-tcp"));
                                    return;
                                }
                                Err(e) => {
                                    ui::trace(&format!("filament: TCP localhost failed: {e}"));
                                }
                            }
                        }
                    }
                }
            }
            // rung-1: direct-dial QUIC over host candidates. The answerer role is
            // derived inside the race from both endpoint identity tuples, so the
            // connector and offer-receiver cannot drift via caller literals.
            if let Some(t) = direct::race_connect(
                ep,
                peer_cands,
                &secret,
                pid_s.clone(),
                my_uid.clone(),
                peer_uid.clone(),
                my_id.clone(),
                tx.clone(),
                exchange,
                peer_claimed,
                server_public_dialed.clone(),
            )
            .await
            {
                let _ = tx.send(mk(pid_s, t, "direct-quic"));
                return;
            }
            // rung-2: UDP hole-punch, then rung-1's QUIC race over the punched
            // socket. Only fires with the flag on, a punch socket bound, and a
            // peer srflx to punch toward. On failure (e.g. symmetric NAT) we fall
            // through to the WebRTC step-down via the per-tick reaper.
            if holepunch::holepunch_enabled() {
                if let (Some(sock), Some(peer_srflx)) = (punch_sock, peer_srflx_addr) {
                    // TRACE, direct/hole-punch detail.
                    ui::trace(&format!(
                        "filament: rung-1 failed, attempting hole-punch to {peer_srflx}"
                    ));
                    if let Some(t) = holepunch::connect(
                        sock,
                        peer_srflx,
                        &secret,
                        pid_s.clone(),
                        my_uid.clone(),
                        peer_uid.clone(),
                        my_id.clone(),
                        tx.clone(),
                        exchange,
                        // The punched race dials ONLY the srflx, never the
                        // claimed server-asserted address, so it cannot set the
                        // flag that would let the fallback name that address.
                        None,
                        server_public_dialed.clone(),
                    )
                    .await
                    {
                        let _ = tx.send(mk(pid_s, t, "holepunched"));
                        return;
                    }
                }
            }
            // On None the per-tick reaper handles the WebRTC fallback at deadline.
        });
    }

    /// P5 (GAP-6): a relay-committed peer received an UPGRADE-PROBE transport-
    /// offer (`probe:true`) from the other end while we have no probe pending of
    /// our own yet. ARM a matching upgrade probe so the symmetric direct dial can
    /// complete (both ends must offer their candidates for the QUIC simultaneous-
    /// open race). Only fires for a peer we are actually serving on relay
    /// (`relay_committed` + a live link) and only when the prober is enabled and
    /// relay isn't forbidden, otherwise the probe offer is ignored.
    pub(crate) async fn answer_upgrade_probe(&mut self, pid: &str) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        if !self.resil.relay_committed.contains(pid) || !self.links.contains_key(pid) {
            return;
        }
        if self.direct_pending.contains_key(pid) {
            return; // our own probe is already in flight, its race will consume the offer
        }
        let known = self.links.get(pid).and_then(|l| l.expected_secret.clone());
        if let Some((name, secret)) = known {
            self.start_upgrade_probe(pid, &name, &secret).await;
        }
    }

    /// Create the Link for a direct connection that won the race. `peer: None`
    /// (no WebRTC), `direct: true`, `trusted: true` (the pair-secret MAC already
    /// proved identity, at least as strong as the DTLS pair-proof it replaces).
    pub(crate) fn adopt_direct(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let pend = self.direct_pending.remove(pid);
        // Read the fleet flag BEFORE the secret moves out of the pending.
        //
        // FAIL SAFE WITH NO PENDING. Only the DIALER holds a `DirectPending`, so
        // `unwrap_or(false)` meant the ACCEPTING side of a fleet dial was born
        // `trusted: true` + OwnerDevice, which is the exact escalation the Fleet
        // intent exists to prevent, reachable by anyone holding the fleet secret.
        // It was caught live: a device whose transfer grant had been REVOKED still
        // delivered a file, because the acceptor had granted it owner-equivalence
        // at link birth.
        //
        // With no pending we cannot see which secret authenticated the MAC, so we
        // infer from what we know: a peer we hold a PAIR secret for is a paired
        // device (only it could have produced that MAC); anything else, while we
        // have a fleet secret at all, is treated as a fleet link and stays
        // untrusted until `fleet-hello` names it.
        let fleet = match pend.as_ref() {
            Some(p) => p.fleet,
            None => {
                let claimed = self
                    .roster
                    .get(pid)
                    .and_then(|v| v["name"].as_str().map(str::to_string))
                    .unwrap_or_default();
                let paired = !claimed.is_empty()
                    && devices_load()
                        .iter()
                        .any(|(n, _)| n.eq_ignore_ascii_case(&claimed));
                fleet::rv().is_some() && !paired
            }
        };
        let (name, secret) = match pend {
            Some(p) => p.secret,
            None => ("peer".to_string(), String::new()),
        };
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": name }));
        let uid = info["uid"].as_str().map(|s| s.to_string());
        let expected_secret = if secret.is_empty() {
            None
        } else {
            Some((name.clone(), secret))
        };
        self.next_gen += 1;
        let generation = self.next_gen;
        // If a Link already exists for this pid (e.g. from a stall-watchdog
        // repair re-dial), UPDATE its transport + workers in place instead of
        // full-insert replacing the old Link (which would drop the primary
        // transport Arc → quinn ApplicationClosed → primary death at K>1).
        // Workers stay intact; only the primary transport is swapped.
        let _existing_generation = self.links.get(pid).map(|l| l.generation).unwrap_or(0);
        if let Some(existing) = self.links.get_mut(pid) {
            if existing
                .transport
                .as_ref()
                .map(|t2| t2.is_dead())
                .unwrap_or(true)
            {
                existing.transport = Some(t);
            }
            existing.direct = true;
            existing.direct_route = route;
            existing.generation = generation;
            existing.attempts = 0;
            existing.trusted = true;
            if let Some((n, _)) = &expected_secret {
                existing.verified_name = Some(n.clone());
            }
            resolve_peer_identity(existing);
            if expected_secret.is_some() {
                existing.expected_secret = expected_secret;
            }
        } else {
            // Mesh reuse: spawn accept loop before t moves into Link.
            direct::spawn_mesh_accept(pid.to_string(), &t, self.tx.clone());
            self.links.insert(
                pid.to_string(),
                Link {
                    peer: None,
                    info,
                    name,
                    uid,
                    transport: Some(t),
                    workers: vec![],
                    generation,
                    attempts: 0,
                    // A direct link is normally born identity-bound: its PAIR-secret
                    // MAC already proved who it is. A FLEET link is not. Its MAC was
                    // keyed by a secret the whole fleet shares, which proves only
                    // that the peer is in the fleet. So it is born untrusted, with no
                    // petname and no owner-equivalence, until a verified fleet-hello
                    // names it.
                    trusted: !fleet,
                    verified_name: if fleet {
                        None
                    } else {
                        expected_secret.as_ref().map(|(n, _)| n.clone())
                    },
                    expected_secret,
                    presence: Presence::Ready,
                    direct: true,
                    direct_route: route,
                    established_at: Some(Instant::now()),
                    identity_device_pub: None,
                    identity_user_pub: None,
                    identity_binding: crate::capability::BindingStrength::None,
                    identity_cert_expires: None,
                    principal_kind: if fleet {
                        crate::capability::PrincipalKind::Delegated { caps: Vec::new() }
                    } else {
                        crate::capability::PrincipalKind::OwnerDevice
                    },
                },
            );
        }
    }

    /// Spawn K-1 parallel QUIC worker transports in a background task after
    /// the primary direct connection wins.  The non-answerer side dials; the
    /// answerer side accepts.  Each worker gets its OWN quinn::Endpoint (own
    /// UDP socket, own driver task) so packet I/O parallelises across cores.
    /// Workers arrive asynchronously via `Ev::DirectWorkersReady` and are
    /// populated on the Link.  File send (`stream_one`) gracefully degrades
    /// to fewer streams if workers are not yet ready.
    pub(crate) fn spawn_direct_workers(
        &mut self,
        pid: &str,
        primary: &Arc<dyn Transport>,
        tkey: [u8; 32],
    ) {
        let k = net::direct_streams();
        if k <= 1 {
            return;
        }
        let peer_uid = self.roster.get(pid).and_then(|i| i["uid"].as_str());
        let peer_present = self.roster.contains_key(pid);
        let answerer = match peer_uid {
            Some(peer_uid) => match net::polite_role(&self.my_uid, peer_uid, &self.my_id, pid) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("direct worker role election failed for {pid}: {error}");
                    return;
                }
            },
            None => {
                let source = if peer_present {
                    "presence"
                } else {
                    "absent-roster"
                };
                match net::polite_role_legacy(
                    &self.my_uid,
                    None,
                    &self.my_id,
                    pid,
                    source,
                    peer_present,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("worker role election failed for peer {pid}: {error}");
                        return;
                    }
                }
            }
        };
        let count = k - 1;
        let pid = pid.to_string();
        let tx = self.tx.clone();
        let primary = primary.clone();

        if answerer {
            // ACCEPTOR: create independent QUIC endpoints (one per worker),
            // send their ports to the dialer, then accept incoming connections.
            let mut endpoints = Vec::with_capacity(count);
            let mut ports = Vec::with_capacity(count);
            for _ in 0..count {
                if let Ok((ep, port)) = direct::bind_endpoint() {
                    endpoints.push(ep);
                    ports.push(port);
                }
            }
            if endpoints.is_empty() {
                return;
            }
            let offer = json!({ "type": "worker-ports", "v": 1, "ports": ports, "for": &pid });
            let p = primary.clone();
            tokio::spawn(async move {
                let _ = p.send_control(&offer).await;
            });
            tokio::spawn(async move {
                let workers =
                    direct::accept_workers(endpoints, tkey, pid.clone(), tx.clone(), count).await;
                if !workers.is_empty() {
                    let _ = tx.send(net::Ev::DirectWorkersReady(pid, workers));
                }
            });
        } else {
            // DIALER: wait for the acceptor's worker ports, then connect to each.
            let peer_ip = match primary.remote_addr().map(|a| a.ip()) {
                Some(ip) => ip,
                None => return,
            };
            let (port_tx, port_rx) = tokio::sync::oneshot::channel();
            self.worker_port_tx.insert(pid.clone(), port_tx);
            tokio::spawn(async move {
                let ports =
                    match tokio::time::timeout(std::time::Duration::from_secs(5), port_rx).await {
                        Ok(Ok(p)) => p,
                        _ => return,
                    };
                let workers =
                    direct::dial_workers(ports, peer_ip, tkey, pid.clone(), tx.clone(), count)
                        .await;
                if !workers.is_empty() {
                    let _ = tx.send(net::Ev::DirectWorkersReady(pid, workers));
                }
            });
        }
    }

    /// Per-tick: a direct attempt whose budget expired without an authenticated
    /// connection falls back to the WebRTC `establish` (unchanged). Returns the
    /// list of (pid, info) to establish, caller awaits establish outside the
    /// borrow. Also drops any pending whose Link already exists.
    pub(crate) fn expired_direct(&mut self) -> Vec<(String, Value, (String, String))> {
        let now = Instant::now();
        let mut fell_back = Vec::new();
        // P5 (GAP-6): an UPGRADE-PROBE pending whose budget expired with no winner
        // must NOT fall back to WebRTC, the relay link is still serving and the
        // whole point of the probe was to find a DIRECT path. Just DROP it and let
        // the prober's backoff schedule the next attempt (mark_probe_failed). The
        // cold (non-probe) pendings keep their existing WebRTC-fallback behavior.
        let expired_probes: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(_, p)| p.probe && now >= p.deadline)
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired_probes {
            self.direct_pending.remove(&pid);
            // DEBUG, resilience internal (upgrade probe found no path).
            ui::debug(&format!(
                "filament: UPGRADE-PROBE for {pid} found no direct path in budget, staying on relay"
            ));
            self.mark_probe_failed(&pid);
        }
        let expired: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| !p.probe && now >= p.deadline && !self.links.contains_key(*pid))
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired {
            if let Some(p) = self.direct_pending.remove(&pid) {
                let info = self
                    .roster
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| json!({ "id": pid, "name": p.secret.0 }));
                // Gate C (#237): the fallback is now ATTRIBUTED - and only when the
                // attribution is TRUE. The decision to use the relay names the
                // peer's claimed server-asserted public candidate only when the
                // race actually DIALED THAT EXACT ADDRESS (the dial site set
                // server_public_dialed; nothing else can). The claim is wire
                // data and untrusted: absent a dial of the named address,
                // "never answered" would blame a sentence rather than a fact -
                // whether the claim was never in the candidate set, never
                // parsed, or the budget went to other dials. All of those stay
                // silent at default verbosity: the infinite negative run stays
                // quiet, and a fallback with an unrelated cause - or a lying
                // label - never names a cause it has not established.
                let attributed = p
                    .peer_server_public
                    .as_ref()
                    .filter(|_| p.server_public_dialed.load(Ordering::Relaxed));
                match attributed {
                    Some(sp) => crate::ui::say(&format!(
                        "falling back to relay: the public address from the server ({sp}) never answered"
                    )),
                    None => {
                        // DEBUG, resilience internal (direct→WebRTC fallback).
                        ui::debug(&format!(
                            "filament: DIRECT-FALLBACK for {}, no authenticated QUIC in budget, using WebRTC",
                            p.secret.0
                        ))
                    }
                }
                fell_back.push((pid, info, p.secret));
            }
        }
        // Drop pendings whose link landed by another route (cleanup). P5 (GAP-6):
        // EXCLUDE upgrade probes, a probe pending ALWAYS coexists with the serving
        // relay link (that's the point), so this cleanup must not reap it before its
        // race runs; a probe is reaped only by its own deadline (above) or by the
        // upgrade cutover consuming it.
        let linked: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| !p.probe && self.links.contains_key(*pid))
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in linked {
            self.direct_pending.remove(&pid);
        }
        fell_back
    }

    /// C3/C4: watchdog or grace expiry, retry that LINK with fresh config,
    /// up to MAX_ATTEMPTS, then drop it. Returns true when the exhausted link
    /// was the active transfer target (send decides whether that is fatal).
    pub(crate) async fn on_stuck(&mut self, pid: &str, generation: u32, why: &str) -> Result<bool> {
        // C21: don't burn retry attempts against a peer that told us it's
        // away, re-dialing a suspended tab is wasted attrition.
        if self.is_away(pid) {
            return Ok(false);
        }
        let Some(l) = self.links.get(pid) else {
            return Ok(false);
        };
        // rung-1: a direct link has no WebRTC watchdog (no Peer::connect timer),
        // so on_stuck can't fire for it; defensively no-op if it ever does.
        if l.direct {
            return Ok(false);
        }
        if l.generation != generation || l.peer.as_ref().map(|p| p.is_connected()).unwrap_or(true) {
            return Ok(false); // stale timer from a superseded attempt
        }
        // Gate-18 Mode B: the transfer is COMPLETE (recv_done; recomputed per
        // tick by the recv loop, so this can only be true with by_sid empty and
        // !keep_open) and this link just went stuck/lost. Reconnecting would
        // fetch nothing and merely FLAP the link, resetting attempts and
        // re-arming expected_secret each cycle, so conn.links never empties and
        // the quiet-exit can't fire (RC=124 hang under contention). DROP it
        // instead: links empties, quiet-exit fires. Fenced to complete-only, so
        // a mid-transfer link (recv_done=false) reconnects normally (gate 2/11c).
        // FILAMENT_TEST_DISABLE_MODEB_DROP reverts to the old reconnect-always
        // behaviour so the gate proves A/B with ONE binary: baseline (toggle set)
        // hangs to RC=124 under the churn hook; fix (toggle unset) exits cleanly.
        if self.recv_done && !test_hooks::disable_modeb_drop() {
            let was_active = self.is_active(pid);
            ui::debug(&ui::paint(
                ui::Tone::Dim,
                &format!(
                    "dropping peer (connection {why} after completion, nothing left to fetch)"
                ),
            ));
            self.drop_link(pid);
            return Ok(was_active);
        }
        let attempts = l.attempts + 1;
        if attempts >= MAX_ATTEMPTS {
            let was_active = self.is_active(pid);
            ui::debug(&format!(
                "filament: STALL-LADDER-EXHAUSTED peer={pid} attempts={attempts} reason={why}"
            ));
            ui::debug(&ui::paint(
                ui::Tone::Dim,
                &format!("dropping peer (connection {why} after {attempts} attempts)"),
            ));
            self.suppressed_digest_adoptions.insert(pid.to_string());
            self.drop_link(pid);
            return Ok(was_active);
        }
        // DEBUG, resilience internal (link retry).
        ui::debug(&format!(
            "connection {why}, retrying ({}/{})",
            attempts + 1,
            MAX_ATTEMPTS
        ));
        let info = l.info.clone();
        let secret = l.expected_secret.clone();
        // C26: a link that was ever up is *re*connecting; one that never
        // connected is still just connecting, keeps "recovered" honest.
        let prev = match l.presence {
            Presence::Connecting => Presence::Connecting,
            _ => Presence::Reconnecting,
        };
        let was_active = self.is_active(pid);
        // Add exponential backoff between retries to avoid burning through attempts instantly.
        let backoff = std::cmp::min(
            Duration::from_secs(2u64.pow(attempts - 1)),
            Duration::from_secs(10),
        );
        tokio::time::sleep(backoff).await;
        self.establish_as(info, None).await?;
        if let Some(nl) = self.links.get_mut(pid) {
            nl.attempts = attempts;
            nl.expected_secret = secret;
            nl.presence = prev;
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        Ok(false)
    }

    // --- P0 (GAP-1): the bytes-moved STALL watchdog + correction ladder ------
    //
    // The single byte-flow primitive `Transport::idle_ms()` already exists
    // (net.rs) and is stamped at the unambiguous "a data byte moved" point on
    // both send and receive. #28 wired it ONLY to the supersede decision; this
    // is the second consumer the audit calls the core gap: a watchdog that
    // declares an OPEN, ALIVE link bad when an in-flight transfer moves zero
    // bytes, the "stuck at 0%" hang, and drives the least-disruptive
    // correction. Run from the main event loop's tick (no new concurrency: F8).

    /// Build the detector's transport observation without treating presence or
    /// an idle sentinel as proof of liveness. Dead transports are excluded from
    /// the activity sample, and the maximum idle age prevents a worker from
    /// masking a stalled primary.
    pub(crate) fn stall_observation(
        transport: Option<&dyn Transport>,
        workers: &[Arc<dyn Transport>],
    ) -> (bool, bool, u64) {
        let mut transport_up = false;
        let mut flowed = false;
        let mut idle_ms: Option<u64> = None;

        let mut observe = |t: &dyn Transport| {
            if !t.is_alive() {
                return;
            }
            transport_up = true;
            if let Some(idle) = t.idle_ms_tracked() {
                flowed = true;
                idle_ms = Some(idle_ms.map_or(idle, |current| current.max(idle)));
            }
        };
        if let Some(t) = transport {
            observe(t);
        }
        for worker in workers {
            observe(worker.as_ref());
        }

        (transport_up, flowed, idle_ms.unwrap_or(u64::MAX))
    }

    /// Per-tick check: if a transfer is in flight (`in_flight`) on a link whose
    /// `idle_ms()` has crossed the stall threshold, return its (pid, idle_ms) so
    /// the loop can emit `Ev::TransferStalled`. Returns `None` for a flowing or
    /// idle-but-empty link. Resetting bookkeeping on observed progress lives in
    /// `note_progress`, so a slow-but-MOVING link (which keeps advancing
    /// idle_ms's baseline) never trips, the threshold is on time-since-last-byte,
    /// never on throughput.
    pub(crate) fn detect_stall(&mut self, pid: &str, in_flight: bool) -> Option<u64> {
        let in_episode = self
            .resil
            .stall_repairs
            .get(pid)
            .map(|s| s.pending)
            .unwrap_or(false);
        // The liveness PHASE is the single source of truth (resilience::classify):
        // it pairs each phase with its own clock, so an ESTABLISHING link (no first
        // byte yet) is judged by the generous grace and a FLOWING one by the tight
        // stall threshold. This makes "judge a still-establishing link by the 6 s
        // flowing threshold" - the high-RTT relay repair loop - unrepresentable.
        // See docs/transfer-state-machine.md.
        // Aggregate across primary + worker transports: during multi-stream
        // transfers data rides the workers, so the primary can appear idle.
        // Do not infer liveness from presence or idle sentinels.
        let link = self.links.get(pid);
        let transport = link.and_then(|l| l.transport.as_ref());
        let workers: Vec<Arc<dyn Transport>> = link.map(|l| l.workers.clone()).unwrap_or_default();
        let (transport_up, flowed, idle_ms) =
            Self::stall_observation(transport.map(|t| t.as_ref()), &workers);
        #[cfg(debug_assertions)]
        eprintln!(
            "[STALL] pid={pid} in_flight={in_flight} transport_up={transport_up} flowed={flowed} idle_ms={idle_ms} workers={} cluster={:?}",
            workers.len(),
            transport
                .map(|t| t.idle_ms())
                .into_iter()
                .chain(workers.iter().map(|w| w.idle_ms()))
                .collect::<Vec<_>>()
        );
        let obs = resilience::LiveObs {
            in_flight,
            transport_up,
            flowed,
            idle_ms,
            grace_ms: net::establish_grace_ms(),
            stall_ms: net::stall_ms(),
        };
        match resilience::classify(&obs) {
            resilience::Liveness::Flowing => {
                self.note_progress(pid);
                None
            }
            resilience::Liveness::Establishing => {
                // During an active repair cycle (new transport not yet
                // established), the episode must survive so the next stall
                // picks up at the correct rung instead of restarting from
                // Resume (which fails because the link was dropped).
                let in_repair = self
                    .resil
                    .stall_repairs
                    .get(pid)
                    .map(|s| s.pending)
                    .unwrap_or(false);
                if !in_repair {
                    self.note_progress(pid);
                }
                None
            }
            // Nothing in flight: drop stray bookkeeping.
            resilience::Liveness::Idle => {
                self.resil.stall_repairs.remove(pid);
                None
            }
            // No progress past the phase threshold. Open a new episode, or (if one
            // is already open) re-fire the ladder UNLESS a repair is converging -
            // re-emitting every tick would thrash while the replacement transport
            // is still establishing.
            resilience::Liveness::Stalled => {
                if in_episode && self.repair_in_flight(pid) {
                    None
                } else {
                    Some(obs.idle_ms)
                }
            }
        }
    }

    /// Is a repair for this peer's stall episode currently converging (a re-dial
    /// in flight or the ladder mid-step)? Used to avoid re-firing every tick.
    fn repair_in_flight(&self, pid: &str) -> bool {
        // A direct re-dial is pending, OR the ladder just acted and we're waiting
        // on the next observation. We treat `direct_pending` as the convergence
        // signal for rung (c)'s fresh dial. P1: a relay escalation (rung d) builds
        // a fresh WebRTC link NOT tracked by `direct_pending`, so the per-episode
        // `relayed` latch is its convergence signal, both keep the watchdog from
        // re-firing while the replacement transport is still establishing.
        if self.direct_pending.contains_key(pid) {
            return true;
        }
        self.resil
            .stall_repairs
            .get(pid)
            .map(|s| s.relayed)
            .unwrap_or(false)
    }

    /// Clear a peer's stall episode, called when bytes are observed moving
    /// again (the link recovered) or nothing is in flight.
    pub(crate) fn note_progress(&mut self, pid: &str) {
        self.resil.stall_repairs.remove(pid);
        // P3: a fresh byte means the (warm-cut-over) path is healthy again, let a
        // FUTURE episode warm-cut-over once more if it too stalls.
        self.resil.warm_cutover.remove(pid);
    }

    /// P0 liveness cross-check: is the link's CONTROL path still answering? A
    /// black-holed *data* path (the case we recover) still carries reliable,
    /// ordered control frames, so a successful control send distinguishes
    /// "data wedged, link alive" (→ correction ladder) from "link dead" (→ the
    /// established C3/C4 establishment-retry path, which already handles it).
    /// We send a cheap `ping` control frame; success ⇒ alive. We do NOT await a
    /// pong (F8: the event loop must never block on something a remote controls),
    /// a send that returns Ok over a reliable channel is sufficient evidence
    /// the transport itself is up; a dead transport errors or is flagged dead and
    /// returns Err here.
    pub(crate) async fn link_alive(&self, pid: &str) -> bool {
        match self.transport_of(pid) {
            Some(t) => t
                .send_control(&json!({ "type": "ping", "v": 1, "reason": "stall-probe" }))
                .await
                .is_ok(),
            None => false,
        }
    }

    /// Decide the correction RUNG for the current stall episode and (for rung c)
    /// repair the transport in place WITHOUT tearing the session down. Returns:
    ///   `Rung::Resume`: rung (a): caller re-offers unfinished transfers with
    ///                     resume:true on the SAME transport (cheapest).
    ///   `Rung::Repaired`: rung (c): the transport was repaired in place
    ///                     (direct: fresh QUIC dial of the known device;
    ///                     WebRTC: restart_ice), caller re-offers once it's back.
    ///   `Rung::Relayed`, rung (b)/(d): re-established over the TURN relay. P3
    ///                     reaches this on the FIRST stall for a warm-standby
    ///                     (interactive) session, instant failover to the
    ///                     pre-designated warm alternate; P1 reaches it at the
    ///                     ladder ceiling for a one-shot transfer.
    ///   `Rung::Exhausted`: rungs a→c spent (MAX_ATTEMPTS) AND relay unavailable
    ///                     (forbidden / already on relay), fail clean, kept partial.
    /// Bounds the episode by MAX_ATTEMPTS, reusing the same ceiling as on_stuck.
    pub(crate) async fn correct_stall(&mut self, pid: &str) -> Rung {
        // P3 (GAP-3): once this episode has CUT OVER to the warm relay standby, a
        // SECOND Ev::TransferStalled that was already QUEUED before the cutover ran
        // (the loops emit one per tick while the stall holds) must NOT re-enter the
        // ladder and run a COLD in-place repair on top of the converging cutover,
        // that tore the fresh relay link down ("ICE Agent can not be restarted when
        // gathering"). Swallow it as a no-op (`Repaired` is the benign "in flight,
        // nothing to do" for both handlers). This guard is keyed on `warm_cutover`,
        // which is ONLY ever set on the warm path, so the COLD ladder (P0/P1) is
        // byte-for-byte unchanged and still climbs rung a→c→d normally. Cleared by
        // `note_progress` when the relay path moves a byte.
        if self.resil.warm_cutover.contains(pid) {
            return Rung::Repaired;
        }
        // Check transport dead BEFORE the mutable borrow so the borrow-split
        // is unambiguous. When the transport is structurally dead (I/O error,
        // not a vanished peer), rung (a) Resume (re-offer on the same transport)
        // is guaranteed wasted — send_frame checks the dead flag and errors
        // immediately. Skip ahead to rung (c) Repair (re-dial direct QUIC) on
        // the first ladder tick, collapsing a wasted stall cycle.
        let dead_on_entry = self.transport_of(pid).map(|t| t.is_dead()).unwrap_or(false);
        let st = self.resil.stall_repairs.entry(pid.to_string()).or_default();
        st.pending = true;
        if dead_on_entry && st.attempts == 0 {
            st.attempts = 1;
        }
        let attempt = st.attempts;
        st.attempts += 1;

        // P3 (GAP-3): WARM-REDUNDANCY instant failover (rung b). For a long-lived
        // / interactive session (`warm_standby`), the relay is a PRE-DESIGNATED
        // WARM standby kept ready alongside the primary direct path. On the FIRST
        // detected stall we CUT OVER to it IMMEDIATELY rather than grinding through
        // the slow direct-repair rungs, rung (a)'s resume-and-wait-another-stall,
        // then rung (c)'s up-to-MAX_ATTEMPTS cold re-dials, each of which costs a
        // full stall threshold before it gives up. Those rungs are correct for a
        // one-shot file (the on-disk partial makes a cold repair fine), but for an
        // interactive session every one of those windows is a visible, intolerable
        // gap. Cutting straight to the warm relay collapses N×stall_ms of cold
        // re-establish into a single relay cutover (rung d's machinery, but reached
        // on stall #1 instead of stall #~6), preserving the on-disk partial / PTY
        // stream / tunnel state via the same C7 resume seam.
        //
        // Gated tightly so we never pay this on the wrong session:
        //   - `warm_standby` (session-kind selectivity) must be on;
        //   - relay must be PERMITTED (`--no-relay` keeps the hard direct-only
        //     promise → fall through to the normal ladder, which fails clean);
        //   - we must not be ON relay already (`relay_only`), then relay is the
        //     PRIMARY that stalled, so there's no warmer alternate; fall through to
        //     the ladder, which lands on the honest "still stalled on relay" exit;
        //   - we cut over at most ONCE per episode (`warm_cutover`), a flapping
        //     relay can't re-fire instant cutover every tick; the second stall on
        //     the relay path falls through to the bounded relay-stalled honesty.
        let warm_eligible = self.resil.warm_standby
            && !relay_forbidden()
            && !self.relay_only
            && !self.resil.warm_cutover.contains(pid);
        // The ladder DECISION (which rung) is pure and lives in resilience.rs; this
        // method owns the state mutation + the rung's side effect.
        match resilience::decide_stall_action(
            attempt,
            STALL_MAX_REPAIRS,
            warm_eligible,
            relay_forbidden(),
            self.relay_only,
        ) {
            resilience::StallAction::WarmCutover => {
                // P3 (GAP-3) WARM-REDUNDANCY instant failover (rung b): cut straight
                // to the pre-designated warm relay standby instead of grinding the
                // slow direct-repair rungs (intolerable for an interactive session).
                // DEBUG, resilience internal; visible at -v / FILAMENT_LOG=debug.
                ui::debug(&ui::paint(
                    ui::Tone::Warn,
                    "  transfer stalled, cutting over to the warm relay standby (instant failover)",
                ));
                self.resil.warm_cutover.insert(pid.to_string());
                // Latch the episode as relaying so detect_stall waits for the fresh
                // relay path to move a byte (clearing the episode) instead of
                // re-firing the ladder while the cutover converges.
                if let Some(st) = self.resil.stall_repairs.get_mut(pid) {
                    st.relayed = true;
                }
                self.escalate_to_relay(pid).await;
                Rung::Relayed
            }
            resilience::StallAction::Resume => {
                // Rung (a): cheapest, re-issue on the same transport. The caller
                // owns `outgoing` and does the actual re-offer; we just classify.
                // DEBUG, resilience internal (rung (a) resume on the same link).
                ui::debug(&ui::paint(
                    ui::Tone::Warn,
                    "  transfer stalled, resuming on the same link",
                ));
                Rung::Resume
            }
            resilience::StallAction::ExhaustedRelayForbidden => {
                // The hard direct-only promise: never silently fall to a relay.
                // CRITICAL, a clean fatal path-decision the user must see (-q too).
                ui::critical(&ui::paint(
                    ui::Tone::Warn,
                    "  couldn't establish a direct path; relay disabled (--no-relay), \
                    partial kept on disk. Re-run to resume, or drop --no-relay to \
                     allow relay fallback.",
                ));
                Rung::Exhausted
            }
            resilience::StallAction::ExhaustedAlreadyRelay => {
                // We already re-established over relay and it ALSO stalled: no harder
                // rung. Stop honestly with the partial preserved.
                // CRITICAL, a terminal honesty line the user must see (-q too).
                ui::critical(&ui::paint(
                    ui::Tone::Warn,
                    "  transfer still stalled on the relay route, partial kept on disk. \
                     Re-run to resume.",
                ));
                Rung::Exhausted
            }
            resilience::StallAction::RelayEscalate => {
                // Rung (d): re-establish over the TURN relay, preserving the on-disk
                // partial (C7 resume). Bounded: one escalation per episode.
                // CRITICAL, P1's value-prop: the never-flaky promise kicking in.
                ui::critical(&ui::paint(
                    ui::Tone::Warn,
                    "  direct paths exhausted, falling back to the TURN relay",
                ));
                if let Some(st) = self.resil.stall_repairs.get_mut(pid) {
                    st.relayed = true;
                }
                self.escalate_to_relay(pid).await;
                Rung::Relayed
            }
            resilience::StallAction::Repair => {
                // Rung (c): repair the transport IN PLACE under the live session.
                // DEBUG, resilience internal (in-place repair).
                ui::debug(&ui::paint(
                    ui::Tone::Warn,
                    &format!(
                        "  transfer stalled, repairing the link in place (attempt {}/{})",
                        attempt, STALL_MAX_REPAIRS
                    ),
                ));
                self.repair_link_in_place(pid).await;
                Rung::Repaired
            }
        }
    }

    /// Rung (c): rebuild a path under the LIVE session, preserving the on-disk
    /// partial (C7 resume re-offers from the saved offset on the new transport).
    /// - direct-QUIC link: drop the wedged transport and re-arm the known-device
    ///   direct dial (`start_direct`), which re-advertises candidates; the peer's
    ///   matching re-dial (it runs the same watchdog) completes a FRESH
    ///   authenticated QUIC connection → `Ev::DirectReady` → `adopt_direct` swaps
    ///   in the new transport → ChannelReady re-offers the unfinished transfers.
    /// - WebRTC link: `restart_ice()`, keeps the RTCPeerConnection + DTLS keys;
    ///   only ICE re-gathers, so transfers resume on the same channel once ICE
    ///   re-converges (no re-key, the preferred repair when available).
    async fn repair_link_in_place(&mut self, pid: &str) {
        let Some(l) = self.links.get(pid) else { return };
        if l.direct {
            // Fresh QUIC dial of the known device. Pull the (name,secret) the
            // link was born with so the re-dial re-authenticates to the SAME pair
            // secret (session identity is stable across the swap; only the wire
            // keys rotate, documented in §2.5).
            let known = l.expected_secret.clone();
            let info = l.info.clone();
            let was_active = self.is_active(pid);
            self.drop_link(pid); // tears down the wedged transport (frees the port)
            if let Some((name, secret)) = known {
                self.start_direct(pid, &name, &secret).await;
                if was_active {
                    // start_direct creates no Link yet; keep the slot pointed here
                    // so adopt_direct's ChannelReady re-offers to the right target.
                    self.active = Some(pid.to_string());
                }
            } else {
                // No stored secret to re-dial direct, fall back to a WebRTC
                // re-establish under the session (still preserves the partial).
                // This IS the fallback: swallowing its failure is how a lost
                // direct race became a transfer with no link and no diagnostic.
                if let Err(e) = self.establish_as(info, None).await {
                    ui::debug(&format!("  WebRTC fallback for {pid} failed: {e}"));
                }
                if was_active {
                    self.active = Some(pid.to_string());
                }
            }
        } else if let Some(p) = l.peer.clone() {
            // WebRTC: ICE-restart in place, no teardown, no re-key.
            p.restart_ice().await;
        }
    }

    /// Rung (d), P1 (GAP-4): the direct/in-place ladder is exhausted, so
    /// RE-ESTABLISH this transfer over the TURN relay (relay-only ICE), the
    /// automatic version of the manual `--relay` the Pixel delivery and the runner
    /// both had to perform by hand. The on-disk partial is preserved at the seam:
    /// we re-establish a fresh WebRTC link with `RTCIceTransportPolicy::Relay`, and
    /// its ChannelReady re-offers the unfinished transfers with `resume:true` from
    /// the saved `.part` offset (no restart-from-zero, C7). Flipping the
    /// connection-wide `relay_only` flag also makes any subsequent repair on this
    /// session relay-only, so we don't bounce back to a known-bad direct path.
    /// Session identity (the pair secret / verified petname) is stable across the
    /// swap, only the wire keys rotate (§2.5). Bounded: one escalation per stall
    /// episode (the caller returns `Rung::Relayed` and the `stall_repairs` counter
    /// is already at the ceiling, so the ladder can't re-fire until progress
    /// resumes and resets it).
    async fn escalate_to_relay(&mut self, pid: &str) {
        // Latch the whole connection onto relay-only ICE: the re-establish below
        // and every later (re)establish for this session now forces TURN.
        self.relay_only = true;
        // Commit THIS peer to relay: stop dialing/answering direct-QUIC for it, so
        // the known-bad direct path can't keep winning the race and re-freezing
        // while the relay link tries to form (the exact thrash the sim exposed).
        self.resil.relay_committed.insert(pid.to_string());
        let Some(l) = self.links.get(pid) else { return };
        let info = l.info.clone();
        let known = l.expected_secret.clone();
        let was_active = self.is_active(pid);
        // Tear down the wedged (direct) transport, then re-establish over WebRTC
        // relay-only. We deliberately do NOT re-arm the direct-QUIC dial here even
        // if a secret is known: direct is what just failed, and relay is a WebRTC
        // path, so we go straight to `establish` (relay-only ICE).
        self.drop_link(pid);
        // Clear any stray pending direct attempt so `establish` (which early-
        // returns while a direct attempt owns the peer, to keep the ladder
        // sequential) is never suppressed for the relay re-establish.
        self.direct_pending.remove(pid);
        // Carry the proven identity into the fresh relay link so the post-channel
        // pair-proof still binds to the same device (set after establish creates
        // the Link below).
        if let Err(e) = self.establish_as(info, None).await {
            ui::debug(&format!("  relay-only re-establish for {pid} failed: {e}"));
        }
        if let (Some(l), Some(ks)) = (self.links.get_mut(pid), known) {
            l.expected_secret = Some(ks);
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        // Honest, loud: the user must know this session is now on a relay.
        // CRITICAL, the value-prop path label; shown even under -q.
        ui::critical(&format!("  {}", relay_banner()));
        // P5 (GAP-6): ARM the relay->direct upgrade prober for this peer. Relay is
        // a way-station, not a destination: while we serve on relay we keep probing
        // for a direct path and upgrade back the moment one is confirmed stable.
        // Eligibility mirrors warm redundancy (long-lived/interactive sessions +
        // the daemon, a one-shot send that already completed doesn't need it) and
        // requires relay to be PERMITTED. The kill switch (`FILAMENT_UPGRADE_PROBE=0`)
        // and `--no-relay` both make this a no-op.
        if self.upgrade_eligible() {
            self.resil
                .upgrade_probe
                .entry(pid.to_string())
                .or_insert_with(UpgradeProbe::armed);
            ui::say(&ui::paint(
                ui::Tone::Dim,
                "  on relay, will keep trying for a direct path and upgrade automatically",
            ));
        }
    }

    /// P5 (GAP-6): is this session eligible to run the relay->direct prober?
    /// Selective like P3's warm redundancy: ON for long-lived / interactive
    /// sessions (the `up`/`up --shell` daemon acceptor; a transfer flagged
    /// interactive via `FILAMENT_WARM_STANDBY=1`). Gated off by the kill switch
    /// and by `--no-relay` (which never reaches relay anyway).
    fn upgrade_eligible(&self) -> bool {
        self.resil.warm_standby && net::upgrade_prober_enabled() && !relay_forbidden()
    }

    /// P5 (GAP-6): a portable network-change-ish event fired (a signaling
    /// reconnect / fresh welcome). Re-probe every relay-committed peer IMMEDIATELY
    /// (reset its backoff to fire now), unless it's already mid-verify on a standby.
    /// Cheap and idempotent, the prober tick does the actual dialing.
    pub(crate) fn reprobe_on_network_event(&mut self) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        for up in self.resil.upgrade_probe.values_mut() {
            if up.standby.is_none() {
                up.next_at = Some(Instant::now());
            }
        }
    }

    /// P5 (GAP-6): record a failed/expired probe and back the cadence off toward
    /// the steady cadence (exponential, capped at steady_ms). Also clears any
    /// stale standby/verify state so the next probe starts clean.
    fn mark_probe_failed(&mut self, pid: &str) {
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else {
            return;
        };
        up.attempt = up.attempt.saturating_add(1);
        up.standby = None;
        up.verify_started = None;
        up.verify_last_idle = u64::MAX;
        // Backoff: first failure → first_ms; then double toward steady_ms (cap).
        let first = net::upgrade_first_ms();
        let steady = net::upgrade_steady_ms();
        let backoff = first.saturating_mul(1u64 << up.attempt.min(8)).min(steady);
        up.next_at = Some(Instant::now() + Duration::from_millis(backoff));
    }

    /// P5 (GAP-6): the per-tick prober. Run from each live-session event loop's
    /// tick (no new concurrency, F8). For every peer currently committed to relay
    /// with an armed `UpgradeProbe`: (1) if a direct standby is mid-VERIFY, judge
    /// it (cut over if it has sustained progress for verify_ms; discard + back off
    /// if it regressed); (2) else if a probe is due (`next_at`), fire a fresh
    /// direct dial ALONGSIDE the relay link (warm direct standby) without
    /// disturbing it. Also detects a local interface change (`iface_snapshot`) and
    /// re-probes IMMEDIATELY, the "walked home onto wifi" trigger.
    pub(crate) async fn tick_upgrade_prober(&mut self) {
        if !net::upgrade_prober_enabled() || relay_forbidden() {
            return;
        }
        if self.resil.upgrade_probe.is_empty() {
            return;
        }
        // Network-change trigger: a change to the local interface set is the
        // strongest "a new direct path may exist NOW" signal we can read without a
        // platform netlink dependency. On change, reset every armed probe's
        // backoff to fire immediately (catches the wifi/cellular handoff instantly).
        let snap = direct::local_ip_snapshot();
        if snap != self.resil.iface_snapshot {
            if !self.resil.iface_snapshot.is_empty() {
                // DEBUG, resilience internal (upgrade-probe trigger).
                ui::debug(&ui::paint(
                    ui::Tone::Dim,
                    "  network changed, re-probing for a direct path now",
                ));
                for up in self.resil.upgrade_probe.values_mut() {
                    if up.standby.is_none() {
                        up.next_at = Some(Instant::now()); // fire ASAP
                    }
                }
            }
            self.resil.iface_snapshot = snap;
        }

        let now = Instant::now();
        let pids: Vec<String> = self.resil.upgrade_probe.keys().cloned().collect();
        for pid in pids {
            // A peer that is no longer relay-committed (already upgraded or gone)
            // shouldn't be probed; drop its entry.
            if !self.resil.relay_committed.contains(&pid) || !self.links.contains_key(&pid) {
                self.resil.upgrade_probe.remove(&pid);
                self.direct_pending.remove(&pid);
                continue;
            }
            // VERIFYING: a standby connected, judge it before scheduling anything.
            let verifying = self
                .resil
                .upgrade_probe
                .get(&pid)
                .map(|u| u.standby.is_some())
                .unwrap_or(false);
            if verifying {
                self.judge_upgrade_standby(&pid).await;
                continue;
            }
            // PROBING: a direct dial is in flight (its DirectPending), wait for it
            // to win (→ DirectUpgradeReady) or expire (→ expired_direct backoff).
            if self.direct_pending.contains_key(&pid) {
                continue;
            }
            // IDLE: schedule / fire the next probe per the backoff.
            let due = match self.resil.upgrade_probe.get(&pid).and_then(|u| u.next_at) {
                None => true,          // armed but unscheduled → schedule first probe
                Some(at) => now >= at, // due
            };
            if let Some(up) = self.resil.upgrade_probe.get_mut(&pid) {
                if up.next_at.is_none() {
                    // First scheduling after arming: probe after first_ms.
                    up.next_at = Some(now + Duration::from_millis(net::upgrade_first_ms()));
                    continue;
                }
            }
            if !due {
                continue;
            }
            // Fire a probe: dial direct ALONGSIDE the relay link.
            let known = self.links.get(&pid).and_then(|l| l.expected_secret.clone());
            let Some((name, secret)) = known else {
                // No stored secret to authenticate a direct dial, can't probe;
                // disarm so we don't spin.
                self.resil.upgrade_probe.remove(&pid);
                continue;
            };
            // DEBUG, resilience internal (upgrade probe attempt).
            ui::debug(&ui::paint(
                ui::Tone::Dim,
                "  probing for a direct path (alongside the relay)...",
            ));
            // Pre-set the NEXT backoff deadline so a probe that silently makes no
            // progress still re-schedules (expired_direct also calls
            // mark_probe_failed on budget expiry; whichever fires first wins).
            self.start_upgrade_probe(&pid, &name, &secret).await;
        }
    }

    /// P5 (GAP-6): VERIFY-before-upgrade. A direct standby has connected for
    /// `pid`. Decide whether it is STABLE enough to cut over to:
    ///   - if it has been moving data (idle_ms stays low) CONTINUOUSLY for
    ///     `verify_ms`, perform the upgrade (clear relay_committed/relay_only, cut
    ///     over to the direct transport, tear down relay, re-offer transfers);
    ///   - if it goes idle past `verify_idle_ms` before that, DISCARD it and stay
    ///     on relay (back off), the mandatory no-flap guard against a flaky direct
    ///     path that connects then immediately re-stalls.
    /// We drive a tiny VERIFY heartbeat over the standby (a control ping) so a
    /// healthy path keeps stamping its `idle_ms()` low even before the session's
    /// real transfer bytes are re-routed onto it.
    pub(crate) async fn judge_upgrade_standby(&mut self, pid: &str) {
        let verify_ms = net::upgrade_verify_ms();
        let verify_idle_ms = net::upgrade_verify_idle_ms();
        // Heartbeat the standby with a real DATA frame (reserved verify sid) so a
        // healthy path advances its activity clock (`idle_ms()` stays low) while a
        // stalled/flaky standby, which black-holes the DATA path, not the control
        // path, either errors here or lets idle climb. A control ping would wrongly
        // pass on a flaky standby (whose control path stays alive), so we MUST probe
        // the data path. The peer drops the unknown-sid chunk harmlessly but stamps
        // its inbound activity, so its side's idle drops too (symmetric verify).
        let standby = self
            .resil
            .upgrade_probe
            .get(pid)
            .and_then(|u| u.standby.clone());
        let Some(standby) = standby else { return };
        // BOUND the heartbeat (F8: never block the event loop on something a remote
        // / a wedged path controls). A flaky standby's data path black-holes, the
        // send_frame would park forever, so a timeout reads as "didn't hold".
        let beat_ok = matches!(
            tokio::time::timeout(
                Duration::from_millis(500),
                standby.send_frame(VERIFY_PROBE_SID, 0, b"upgrade-verify"),
            )
            .await,
            Ok(Ok(()))
        );
        let idle = standby.idle_ms();
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else {
            return;
        };
        let started = match up.verify_started {
            Some(t) => t,
            None => {
                up.verify_started = Some(Instant::now());
                up.verify_last_idle = idle;
                return;
            }
        };
        // Regressed: control send failed OR the path went idle past the guard.
        // Discard the standby, stay on relay, back off (the no-flap guard).
        if !beat_ok || idle >= verify_idle_ms {
            // DEBUG, resilience internal (no-flap guard rejecting a standby).
            ui::debug(&ui::paint(
                ui::Tone::Warn,
                "  direct path connected but didn't hold, staying on relay (no flap)",
            ));
            self.direct_pending.remove(pid);
            self.mark_probe_failed(pid);
            return;
        }
        up.verify_last_idle = up.verify_last_idle.min(idle);
        // Sustained: moved data continuously for the whole verify window → upgrade.
        if started.elapsed() >= Duration::from_millis(verify_ms) {
            let t = standby;
            let route = self
                .resil
                .upgrade_probe
                .get(pid)
                .map(|u| u.standby_route)
                .unwrap_or("direct-quic");
            self.perform_upgrade(pid, t, route).await;
        }
    }

    /// P5 (GAP-6): the upgrade cutover. The direct standby is CONFIRMED stable,
    /// commit it as the session's transport, preserving the session (the same
    /// cutover seam P1/P3 use): clear `relay_committed` + `relay_only` so direct
    /// may win again, swap the verified direct transport into the link (the relay
    /// link/transport is dropped), and re-offer any unfinished transfers
    /// (resume:true) on the new direct path. Honest + loud, mirroring the relay
    /// banner: the user is told they're back on a direct path.
    async fn perform_upgrade(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let was_active = self.is_active(pid);
        let known = self.links.get(pid).and_then(|l| l.expected_secret.clone());
        // CARRY the pre-upgrade principal across the swap. `drop_link` below
        // destroys the old link, and `adopt_direct_transport` rebuilt it with a
        // hardcoded `trusted: true` + OwnerDevice, so a relay->direct upgrade
        // PROMOTED whatever the link was into owner-equivalence.
        //
        // That is the same escalation `adopt_direct` fail-safes against a
        // thousand lines up, where the comment records it being caught live: "a
        // device whose transfer grant had been REVOKED still delivered a file,
        // because the acceptor had granted it owner-equivalence at link birth."
        // The fix landed there and not in this sibling.
        //
        // It also contradicts this function's own contract, which says it reuses
        // the known identity so only the wire path changes.
        let carried = self
            .links
            .get(pid)
            .map(|l| (l.trusted, l.principal_kind.clone()));
        // Clear the relay commitment FIRST so the new direct link isn't treated as
        // a known-bad path and so a future stall can escalate cleanly again.
        self.resil.relay_committed.remove(pid);
        self.relay_only = false;
        self.resil.upgrade_probe.remove(pid);
        self.direct_pending.remove(pid);
        // Swap the verified direct transport into the link, dropping the relay
        // link/transport (drop_link tears down the WebRTC peer). adopt the new
        // transport via the same direct-link shape adopt_direct builds, but reusing
        // the existing identity so the session is preserved across the swap.
        self.drop_link(pid);
        self.adopt_direct_transport(pid, t.clone(), route, known, carried);
        if was_active {
            self.active = Some(pid.to_string());
        }
        // CRITICAL, P5's value-prop line: relay released, back on a direct path.
        ui::critical(&ui::paint(
            ui::Tone::Ok,
            &format!("  upgraded back to a direct path (route: {route}), relay released"),
        ));
        // Re-offer unfinished transfers on the new direct transport (resume:true);
        // the ChannelReady re-emit drives the same path for the send loop.
        let _ = self.tx.send(Ev::ChannelReady(pid.to_string(), t));
    }

    /// P5 (GAP-6): build the post-upgrade DIRECT link from a verified standby
    /// transport, reusing the known identity (so the session/petname is stable
    /// across the relay->direct swap, only the wire path changes). Mirrors
    /// `adopt_direct` but takes an already-connected transport and a carried
    /// (name,secret) instead of consuming a `DirectPending`.
    fn adopt_direct_transport(
        &mut self,
        pid: &str,
        t: Arc<dyn Transport>,
        route: &'static str,
        known: Option<(String, String)>,
        // (trusted, principal_kind) carried from the pre-upgrade link. None only
        // if the link vanished, where the previous defaults are kept so this
        // change stays scoped to the escalation it fixes.
        carried: Option<(bool, crate::capability::PrincipalKind)>,
    ) {
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": known.as_ref().map(|(n, _)| n.clone()).unwrap_or_else(|| "peer".into()) }));
        let name = known
            .as_ref()
            .map(|(n, _)| n.clone())
            .or_else(|| info["name"].as_str().map(String::from))
            .unwrap_or_else(|| "peer".into());
        let uid = info["uid"].as_str().map(|s| s.to_string());
        self.next_gen += 1;
        let generation = self.next_gen;
        self.links.insert(
            pid.to_string(),
            Link {
                peer: None,
                info,
                name,
                uid,
                transport: Some(t),
                workers: vec![],
                generation,
                attempts: 0,
                trusted: upgrade_principal(&carried).0,
                verified_name: known.as_ref().map(|(n, _)| n.clone()),
                expected_secret: known,
                presence: Presence::Ready,
                direct: true,
                direct_route: route,
                established_at: Some(Instant::now()),
                identity_device_pub: None,
                identity_user_pub: None,
                identity_binding: crate::capability::BindingStrength::None,
                identity_cert_expires: None,
                principal_kind: upgrade_principal(&carried).1,
            },
        );
    }

    /// P5 (GAP-6): a relay->direct upgrade probe's direct standby CONNECTED. Stash
    /// it on the peer's `UpgradeProbe` and START the verify window. Crucially, do
    /// NOT touch `links`, the relay link keeps serving until the standby is proven
    /// stable. If we have no armed probe for this peer (it upgraded/left while the
    /// race was in flight), just drop the transport (it closes on drop). Idempotent:
    /// a second DirectUpgradeReady for an already-stashed standby is ignored.
    pub(crate) fn stash_upgrade_standby(
        &mut self,
        pid: &str,
        t: Arc<dyn Transport>,
        route: &'static str,
    ) {
        // Consume any probe DirectPending so expired_direct doesn't reap/backoff it
        // out from under the verify (the race already won).
        self.direct_pending.remove(pid);
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else {
            // No armed probe, the transport is unowned; dropping it tears it down.
            return;
        };
        if up.standby.is_some() {
            return; // already verifying a standby; ignore the duplicate.
        }
        up.standby = Some(t);
        up.standby_route = route;
        up.verify_started = None; // judge_upgrade_standby stamps it on first look
        up.verify_last_idle = u64::MAX;
        // DEBUG, resilience internal (upgrade verify window opening).
        ui::debug(&ui::paint(
            ui::Tone::Dim,
            "  direct path connected, verifying it holds before upgrading...",
        ));
    }

    /// C4: transient `disconnected`, nudge ICE from the impolite side and
    /// give it grace before treating it as failure. C21: a peer that said
    /// `brb` gets its declared window instead of the 6 s blip grace, and no
    /// scary message.
    pub(crate) async fn on_pc_state(&mut self, pid: &str, s: &str) {
        let away = self.is_away(pid);
        let Some(l) = self.links.get_mut(pid) else {
            return;
        };
        // C26: collect the announcement, print after the borrow ends so the
        // roster can read every link.
        let mut announce: Option<(&'static str, ui::Tone, &'static str)> = None;
        match s {
            "connected" => {
                if l.presence == Presence::Reconnecting {
                    announce = Some((ui::glyph_ok(), ui::Tone::Ok, "recovered"));
                }
                l.presence = Presence::Ready;
                l.attempts = 0;
            }
            "disconnected" => {
                let grace = if away {
                    l.presence = Presence::Away;
                    if let Some((_, until)) = &self.rejoin.away {
                        until.duration_since(Instant::now()) + Duration::from_secs(15)
                    } else {
                        Duration::from_secs(6)
                    }
                } else {
                    l.presence = Presence::Reconnecting;
                    announce = Some(("◌", ui::Tone::Warn, "reconnecting..."));
                    Duration::from_secs(6)
                };
                if let Some(p) = &l.peer {
                    if !p.polite && !away {
                        p.restart_ice().await;
                    }
                }
                let tx = self.tx.clone();
                let pid = pid.to_string();
                let generation = l.generation;
                tokio::spawn(async move {
                    tokio::time::sleep(grace).await;
                    let _ = tx.send(Ev::GraceExpired(pid, generation));
                });
            }
            _ => {}
        }
        if let Some((mark, tone, note)) = announce {
            ui::say(&self.roster(pid, mark, tone, note, "peer"));
        }
    }

    /// A peer's socket died. Drop its link; if it was the active target, open
    /// the rejoin window (their client auto-rejoins; C6 supersede completes
    /// the recovery). Returns true if the ACTIVE peer left.
    ///
    /// #28 DEFERRED DROP: peer-left fires when a sid LEAVES THE ROOM, but the
    /// WebRTC data channel is independent and may still be flowing, either a
    /// cosmetic signaling reconnect mid-transfer (keep it!) or a hard-killed
    /// peer whose channel reads flowing for a beat before DTLS notices (must
    /// still drop, or the sender strands). We can't tell the two apart at this
    /// instant, so we DEFER: stash the payload and re-check each tick
    /// (`reap_deferred`). If it goes idle/dead it gets re-injected here with a
    /// force marker and dropped then; if it keeps flowing the transfer
    /// completes on the live channel and the idle link is reaped harmlessly.
    /// The roster entry is removed immediately (the sid truly left); only the
    /// LINK drop is deferred.
    pub(crate) fn on_peer_left(&mut self, v: &Value) -> bool {
        let Some(pid_val) = v["id"].as_str() else {
            return false;
        };
        let pid = pid_val.to_string();
        self.roster.remove(&pid);
        if !self.links.contains_key(&pid) {
            return false;
        }
        // Delegated (ephemeral) devices are removed immediately on disconnect —
        // not deferred, not rejoinable. They must re-enroll on reconnect.
        if matches!(
            self.link(&pid).map(|l| &l.principal_kind),
            Some(crate::capability::PrincipalKind::Delegated { .. })
        ) {
            let name = self.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
            self.drop_link(&pid);
            ui::debug(&format!(
                "ephemeral device {name} disconnected, enrollment revoked"
            ));
            return false;
        }
        // Defer the drop while the data channel is still moving bytes, unless
        // this is the force re-injection from reap_deferred (the link has since
        // gone idle/dead and must drop now). FILAMENT_TEST_NO_DEFER reverts to
        // the old unconditional-drop behaviour so an A/B repro can prove the
        // deferral is what saves the live transfer (baseline must FAIL).
        let forced = v["__fil_force_drop"].as_bool() == Some(true);
        let defer_disabled = test_hooks::no_defer();
        if !forced && !defer_disabled && self.link_flowing(&pid) {
            // Idempotent: first peer-left for this sid records the original
            // payload; a duplicate is swallowed (no double-defer, no drop).
            self.deferred_left
                .entry(pid.clone())
                .or_insert_with(|| v.clone());
            let name = self
                .link(&pid)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| "peer".into());
            // DEBUG, resilience internal (deferred drop while channel flowing).
            ui::debug(&format!(
                "{name} signaling left, data channel still flowing, deferring drop"
            ));
            return false;
        }
        let was_active = self.is_active(&pid);
        self.drop_link(&pid);
        if was_active {
            // C21: informed waits, a peer that declared `brb` gets its
            // promised window (plus slack); an unannounced vanish gets the
            // short default. Their client auto-rejoins; C6 supersede or a
            // fresh adopt completes the recovery.
            self.rejoin.rejoin_window = match &self.rejoin.away {
                Some((apid, until)) if *apid == pid && *until > Instant::now() => {
                    until.duration_since(Instant::now()) + Duration::from_secs(15)
                }
                _ => rejoin_unwarned(),
            };
            self.rejoin.waiting_rejoin = Some(Instant::now());
        }
        was_active
    }

    /// #28: re-check every deferred peer-left. Called on every main-loop tick
    /// (idempotent, cheap). A deferred sid is discharged when it is no longer
    /// flowing, its data channel went idle past the threshold OR died
    /// (idle_ms == u64::MAX). We then re-inject the ORIGINAL peer-left payload
    /// (flagged force) so the normal Ev::PeerLeft handler runs verbatim, same
    /// loop-side flush/messaging/rejoin behaviour as a non-deferred leave, with
    /// the link now correctly dropped. A sid that vanished from `links` (e.g. a
    /// supersede dropped it; drop_link already cleared its entry, but belt-and-
    /// braces) is forgotten silently. A still-flowing sid is left to keep
    /// flowing, the reconnect case, where the transfer completes on the live
    /// channel and the all-done exit reaps it.
    pub(crate) fn reap_deferred(&mut self) {
        if self.deferred_left.is_empty() {
            return;
        }
        let ready: Vec<(String, Value)> = self
            .deferred_left
            .iter()
            .filter(|(sid, _)| !self.links.contains_key(*sid) || !self.link_flowing(sid))
            .map(|(sid, v)| (sid.clone(), v.clone()))
            .collect();
        for (sid, mut payload) in ready {
            self.deferred_left.remove(&sid);
            if !self.links.contains_key(&sid) {
                continue; // link already gone (superseded); nothing to drop
            }
            // Force the drop this time (the channel is now idle/dead).
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("__fil_force_drop".into(), Value::Bool(true));
            }
            let name = self
                .link(&sid)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| "peer".into());
            // DEBUG, resilience internal (deferred-leave reap).
            ui::debug(&format!(
                "{name} link went idle after deferred leave, dropping now"
            ));
            // Re-inject so the loop's own peer-left branch handles partials,
            // messaging and the rejoin window exactly as a fresh leave would.
            let _ = self.tx.send(Ev::PeerLeft(payload));
        }
    }

    /// #28 exit reconciliation: true when every remaining link is one we're only
    /// holding open for its deferred-drop reap (vacuously true with no links). A
    /// link in `deferred_left` is a peer whose signaling already left; once all
    /// transfers are complete it protects nothing, so it must not delay exit by
    /// the full deferral window.
    pub(crate) fn only_deferred_links(&self) -> bool {
        self.links
            .keys()
            .all(|k| self.deferred_left.contains_key(k))
    }

    /// C21: any traffic from a peer cancels its declared absence.
    pub(crate) fn note_alive(&mut self, pid: &str) {
        if matches!(&self.rejoin.away, Some((apid, _)) if apid == pid) {
            self.rejoin.away = None;
        }
    }

    /// C26: set a link's roster presence; returns its name for the announce.
    pub(crate) fn link_presence(&mut self, pid: &str, p: Presence) -> String {
        match self.links.get_mut(pid) {
            Some(l) => {
                l.presence = p;
                l.name.clone()
            }
            None => String::new(),
        }
    }

    pub(crate) fn is_away(&self, pid: &str) -> bool {
        matches!(&self.rejoin.away, Some((apid, until)) if apid == pid && *until > Instant::now())
    }

    /// C26: one static colored status line showing EVERY peer, the changed
    /// one carrying the note, `✓ daring-wombat   ● deft-gibbon  away...`.
    /// `fallback_name` covers a peer already dropped from the map (peer-left).
    pub(crate) fn roster(
        &self,
        pid: &str,
        mark: &str,
        tone: ui::Tone,
        note: &str,
        fallback_name: &str,
    ) -> String {
        let mut links: Vec<(&String, &Link)> = self.links.iter().collect();
        links.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        let mut parts = Vec::new();
        let mut seen = false;
        for (id, l) in links {
            if id == pid {
                seen = true;
                parts.push(peer_entry(l.shown(), mark, tone, note));
            } else {
                let (m, t, n) = presence_glyph(l.presence);
                parts.push(peer_entry(l.shown(), m, t, n));
            }
        }
        if !seen {
            parts.push(peer_entry(fallback_name, mark, tone, note));
        }
        format!("  {}", parts.join("   "))
    }

    /// #7 for the CLI: an offer from a roster peer we haven't linked yet
    /// creates a polite responder link. Stray signals from unknowns drop.
    /// Apply a relayed signal to `from`'s link. Never fatal (F6): the
    /// watchdog/grace machinery owns failed negotiations. On polite-side
    /// glare (webrtc-rs can't roll back out of have-local-offer) the link is
    /// rebuilt as a pure responder and the colliding offer re-applied.
    pub(crate) async fn apply_signal(&mut self, from: &str, data: Value) {
        let peer = match self.link(from).and_then(|l| l.peer.clone()) {
            Some(p) => p,
            None => return,
        };
        match peer.handle_signal(data).await {
            Ok(net::SignalOutcome::Handled) => {}
            Ok(net::SignalOutcome::Glare(offer)) => {
                self.drop_link(from);
                if let Err(e) = self.ensure_responder(from, &offer).await {
                    ui::trace(&format!("signal: glare rebuild failed: {e} (recovering)"));
                    return;
                }
                if let Some(p) = self.link(from).and_then(|l| l.peer.clone()) {
                    if let Err(e) = p.handle_signal(offer).await {
                        ui::trace(&format!("signal failed to apply: {e} (recovering)"));
                    }
                }
            }
            Err(e) => ui::trace(&format!("signal failed to apply: {e} (recovering)")),
        }
    }

    pub(crate) async fn ensure_responder(&mut self, from: &str, data: &Value) -> Result<()> {
        if let Some(uid) = data["uid"].as_str() {
            net::ensure_ascii_uid(uid)?;
            if let Some(info) = self.roster.get_mut(from) {
                info["uid"] = json!(uid);
            } else {
                self.roster
                    .insert(from.to_string(), json!({ "id": from, "uid": uid }));
            }
        }
        if self.links.contains_key(from) {
            return Ok(());
        }
        if data["type"].as_str() == Some("description")
            && data["description"]["type"].as_str() == Some("offer")
        {
            // Answer a WebRTC offer from a channel-peer EVEN IF we never got its
            // known-peer. The existing-member known-peer notification is
            // unreliable on prod (proven via the signaling harness: the NEW
            // joiner is reliably notified, but the EXISTING member often is NOT),
            // which left the acceptor ignoring a valid initiator's offer and
            // looking like "stuck connecting". One-sided discovery is now enough:
            // whoever discovers drives, the other answers. SAFE: trust still
            // gates entirely on the pair-proof MAC (an attacker without the
            // secret fails it and is never trusted), we only answer the offer
            // and let the proof decide. A later known-peer refreshes name/uid.
            let info = self
                .roster
                .get(from)
                .cloned()
                .unwrap_or_else(|| json!({ "id": from }));
            if self.links.len() < MAX_LINKS {
                // Forced responder: this link exists to answer THEIR offer.
                self.establish_as(info, Some(true)).await?;
            }
        }
        Ok(())
    }
}
