//! C30: the convergent session — the CLI's half of "no emit is ever
//! load-bearing; only convergence is" (docs/design-c30-convergent-session.md).
//!
//! Each command loop owns a `Session` describing the DESIRED signaling state
//! (room, identity, presence channels) and calls `tick()` every loop
//! iteration (the loops already tick every ≤2 s). The session re-emits one
//! idempotent `sync` whenever the server's last-confirmed digest disagrees
//! with desire or has gone stale — so a join or subscribe that died in a
//! half-open socket is repaired within a tick instead of becoming a roomless
//! ghost / invisible device / zombie lease (the C24/C28/#14 disease class).
//!
//! The loss shim lives here on purpose: ALL session-state emits flow through
//! `lossy_emit`, so gate L (`FILAMENT_TEST_EMIT_LOSS` + `_SEED`) adversarially
//! drops them and the suite proves convergence survives.

use rust_socketio::asynchronous::Client;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// At most one sync per this interval unless desire changed.
const SYNC_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// A confirmed digest older than this is re-asserted even if unchanged.
const CONFIRM_TTL: Duration = Duration::from_secs(30);

pub struct Session {
    pub room: Option<String>,
    pub name: String,
    pub uid: String,
    pub channels: Vec<String>,
    /// digest of the last server-confirmed state + when
    confirmed: Option<(String, Instant)>,
    last_attempt: Option<Instant>,
    rng: u64, // loss-shim PRNG state (deterministic under _SEED)
    loss: f64,
}

impl Session {
    pub fn new(name: &str, uid: &str) -> Self {
        let loss = std::env::var("FILAMENT_TEST_EMIT_LOSS")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|l| (0.0..1.0).contains(l))
            .unwrap_or(0.0);
        let seed = std::env::var("FILAMENT_TEST_EMIT_SEED")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0xF11A_C30D);
        Session {
            room: None,
            name: name.to_string(),
            uid: uid.to_string(),
            channels: Vec::new(),
            confirmed: None,
            last_attempt: None,
            rng: seed | 1,
            loss,
        }
    }

    /// What we want the server to hold for us, as a comparable string.
    fn desired_digest(&self) -> String {
        let mut chans = self.channels.clone();
        chans.sort();
        format!("{}|{}", self.room.as_deref().unwrap_or(""), chans.join(","))
    }

    /// The server confirmed our state (Ev::Synced) — record its digest.
    /// The digest we store is OUR desire at confirm time: the server applies
    /// what we sent, so a later desire change diffs against it correctly.
    /// Phase 2: the digest may carry the server's roster (`peers`) — the
    /// loops reconcile against it (missed peer-joined/left self-correct).
    pub fn on_synced(&mut self, v: &Value) -> Option<Vec<Value>> {
        if v["ok"].as_bool() != Some(true) {
            return None; // error digests carry no roster (server contract)
        }
        self.confirmed = Some((self.desired_digest(), Instant::now()));
        v["peers"].as_array().cloned()
    }

    /// Any local change to desire invalidates confirmation timing so the next
    /// tick syncs immediately.
    pub fn touch(&mut self) {
        self.last_attempt = None;
    }

    /// A fresh sid (welcome after reconnect) voids everything the server held
    /// for the old one — even if desire is unchanged, it must be re-asserted.
    /// (Without this, a fast reconnect inside CONFIRM_TTL looks "confirmed"
    /// while the new sid is roomless and unsubscribed — the browser track hit
    /// the identical hole.)
    pub fn invalidate(&mut self) {
        self.confirmed = None;
        self.last_attempt = None;
    }

    /// xorshift64* — deterministic, no rand crate; gate L replays by seed.
    fn roll(&mut self) -> f64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// All session-state emits go through here so the loss shim covers them —
    /// including the commands' INITIAL join/subscribe fast-path emits (public
    /// for that reason). Under gate L the shim drops a deterministic fraction;
    /// the tick loop is what must repair the damage.
    pub async fn emit(&mut self, sio: &Client, event: &str, payload: Value) {
        if self.loss > 0.0 && self.roll() < self.loss {
            return; // gate L: this emit "died in a half-open socket"
        }
        let _ = sio.emit(event, payload).await;
    }

    /// Called every loop iteration; cheap no-op most ticks.
    pub async fn tick(&mut self, sio: &Client) {
        let Some(room) = self.room.clone() else { return };
        let now = Instant::now();
        let due = match (&self.confirmed, &self.last_attempt) {
            // never confirmed: retry on the attempt cadence
            (None, Some(at)) => now.duration_since(*at) >= SYNC_MIN_INTERVAL,
            (None, None) => true,
            (Some((digest, at)), _) => {
                let stale = now.duration_since(*at) >= CONFIRM_TTL;
                let diverged = *digest != self.desired_digest();
                (stale || diverged)
                    && self
                        .last_attempt
                        .map(|a| now.duration_since(a) >= SYNC_MIN_INTERVAL)
                        .unwrap_or(true)
            }
        };
        if !due {
            return;
        }
        self.last_attempt = Some(now);
        let payload = json!({
            "v": 1,
            "room": room,
            "name": self.name,
            "uid": self.uid,
            "channels": self.channels,
        });
        self.emit(sio, "sync", payload).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_orders_channels() {
        let mut s = Session::new("n", "u");
        s.room = Some("r".into());
        s.channels = vec!["b".into(), "a".into()];
        let d1 = s.desired_digest();
        s.channels = vec!["a".into(), "b".into()];
        assert_eq!(d1, s.desired_digest());
    }

    #[test]
    fn loss_shim_deterministic() {
        // (no env manipulation — edition 2024 makes set/remove_var unsafe;
        // the default seed path is what's under test)
        let mut a = Session::new("n", "u");
        let mut b = Session::new("n", "u");
        let ra: Vec<u64> = (0..8).map(|_| (a.roll() * 1e9) as u64).collect();
        let rb: Vec<u64> = (0..8).map(|_| (b.roll() * 1e9) as u64).collect();
        assert_eq!(ra, rb, "same seed must replay the same drop pattern");
    }
}
