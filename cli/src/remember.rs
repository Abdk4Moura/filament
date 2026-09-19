//! The remember ceremony: `pair-keep` v2 (`CONTRACT.md`, *Remember offer and
//! accept*).
//!
//! ONE implementation of "promote this session to a remembered relationship",
//! called by every surface that offers it: the `remember` verb, `send
//! --remember`, and the accepting half inside `receive` / `up`.
//!
//! Why this module exists at all. Before it there were two half-mechanisms and
//! the flag that names the feature was on the half that does not do it:
//!
//!   * `send --remember` ran the SPAKE2 ceremony, DISCARDED the agreed secret
//!     by design, never called `devices_store*`, and emitted no `pair-keep`
//!     anywhere. All it did was listen for `pair-keep-ack` and print "mutually
//!     remembered" off the flag alone. On the code path no peer ever sends that
//!     ack unprompted, so the flag was a silent no-op; the one way to reach the
//!     print was a peer that acked an offer we never made, and then the line
//!     was a lie, because nothing had been written.
//!   * The ceremony that DOES store lives in `recv_cmd`, armed only from the
//!     interactive REPL inside a running `receive` / `up`.
//!
//! The rules this module enforces, all of them from the contract:
//!
//!   * **Remembering is mutual or it does not happen.** The offerer writes
//!     NOTHING until `pair-keep-ack {ok:true}` arrives. There is no path here
//!     that stores on the strength of a flag.
//!   * **Silence is not consent.** An offer that is never answered is never
//!     stored, which falls out of the rule above: no ack, no call to
//!     [`apply_ack`], no write.
//!   * **An ack must echo the `offer_id` it answers.** An ack naming an offer
//!     we do not hold is ignored rather than applied to whatever is
//!     outstanding. A v:1 ack carries no `offer_id` and answers the single
//!     outstanding offer, which is the legacy behaviour the contract keeps.
//!   * **`pair-keep` carries no grant and no role.** The record written here is
//!     the secret and the petname, nothing else.

use crate::policy::assume_yes;
use crate::{devices_store, display_name, fresh_secret};
use anyhow::Result;
use serde_json::{Value, json};

/// The wire version this module speaks. v:1 frames keep their old meaning.
pub(crate) const V2: u64 = 2;

/// A pair secret is 32 bytes, hex: any other length is not one.
const SECRET_HEX_LEN: usize = 64;

/// An offer we have made and that has not been answered yet.
///
/// Held by the offering side ONLY. Its presence means "a secret exists in
/// memory that is not on disk and must not reach disk until the other side
/// says yes"; dropping it without an accepting ack is how silence becomes a
/// refusal.
#[derive(Clone, Debug)]
pub(crate) struct Offer {
    pub offer_id: String,
    pub secret: String,
    /// The LOCAL petname we will file them under if they accept (C12: a name is
    /// a local alias for a secret, never something the peer can set).
    pub name: String,
    /// The peer this offer went to, so a stray ack from a third link cannot
    /// answer it.
    pub peer: String,
}

/// Mint an offer for `peer`, to be filed locally as `name`.
pub(crate) fn make_offer(name: &str, peer: &str) -> Offer {
    Offer {
        // 16 hex of fresh CSPRNG output, per the contract's "fresh 16-hex nonce".
        offer_id: fresh_secret()[..16].to_string(),
        secret: fresh_secret(),
        name: name.to_string(),
        peer: peer.to_string(),
    }
}

/// The frame that carries an offer. `name` is OUR proposed display name for
/// ourselves: a suggestion the other side may file us under, never
/// authoritative.
pub(crate) fn offer_frame(o: &Offer) -> Value {
    json!({
        "type": "pair-keep",
        "v": V2,
        "offer_id": o.offer_id,
        "secret": o.secret,
        "name": display_name(),
    })
}

/// What an inbound `pair-keep-ack` did to our outstanding offer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Ack {
    /// They said yes and the record is now on disk under `name`.
    Accepted { name: String, secret: String },
    /// They said no. Nothing was written; the secret is gone.
    Declined,
    /// It answered no offer of ours (wrong `offer_id`, wrong peer, or we hold
    /// no offer at all). Ignored, per the contract.
    Unmatched,
}

/// Apply an ack to our outstanding offer.
///
/// THIS IS THE ONLY PLACE THE OFFERING SIDE WRITES. Anything that prints "you
/// are now remembered" must be downstream of an `Accepted` returned here, which
/// is what makes the claim and the effect impossible to separate again.
pub(crate) fn apply_ack(pending: &mut Option<Offer>, peer: &str, v: &Value) -> Result<Ack> {
    let Some(o) = pending.as_ref() else {
        return Ok(Ack::Unmatched);
    };
    if o.peer != peer {
        return Ok(Ack::Unmatched);
    }
    // A v:2 ack MUST echo the offer_id. A v:1 ack has none and answers the one
    // outstanding offer (legacy).
    if let Some(id) = v["offer_id"].as_str() {
        if id != o.offer_id {
            return Ok(Ack::Unmatched);
        }
    }
    if v["ok"].as_bool() == Some(false) {
        *pending = None;
        return Ok(Ack::Declined);
    }
    let (name, secret) = (o.name.clone(), o.secret.clone());
    // Write BEFORE clearing the offer: if the store fails the offer stays
    // outstanding and the caller reports the failure rather than a success.
    devices_store(&name, &secret)?;
    *pending = None;
    Ok(Ack::Accepted { name, secret })
}

/// What we did with an inbound `pair-keep`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Consent existed, the record is on disk under `name`.
    Kept { name: String, secret: String },
    /// No consent. Nothing written; `why` says what the operator can do.
    Refused { why: String },
    /// Not an offer we can act on (no usable secret). No ack is owed.
    Ignored,
}

impl Answer {
    /// The `ok` this answer acks with, if it acks at all.
    pub(crate) fn ok(&self) -> Option<bool> {
        match self {
            Answer::Kept { .. } => Some(true),
            Answer::Refused { .. } => Some(false),
            Answer::Ignored => None,
        }
    }
}

/// The ack for an offer, echoing its `offer_id` so the offerer can match it.
pub(crate) fn ack_frame(offer: &Value, ok: bool) -> Value {
    let mut f = json!({ "type": "pair-keep-ack", "ok": ok });
    if let Some(id) = offer["offer_id"].as_str() {
        f["offer_id"] = json!(id);
        f["v"] = json!(V2);
    }
    f
}

/// Answer an inbound `pair-keep`: decide consent, store on consent, and say
/// what happened.
///
/// Consent on this side is `--remember <name>` (the operator named them, which
/// is the consent) or the global `--yes` (the scripted form of accepting, per
/// the design's non-interactive contract). With neither we refuse and name the
/// flag: the user did not say no, the user was never asked, and widening a
/// relationship on silence is the exact defect C12/C27 cured.
///
/// It deliberately does NOT open a prompt. This runs inside the receive event
/// loop, which also drives the transfer; a blocking single-key read there would
/// stall every in-flight file behind a question. Refusing and naming the flag is
/// what this path already did before v2, so nothing regressed by not asking.
pub(crate) fn answer_offer(offer: &Value, remember: Option<&str>, peer_name: &str) -> Result<Answer> {
    let sec = offer["secret"].as_str().unwrap_or_default().to_string();
    if sec.len() != SECRET_HEX_LEN {
        return Ok(Answer::Ignored);
    }
    let name = match remember {
        Some(n) => n.to_string(),
        None => {
            if !assume_yes() {
                return Ok(Answer::Refused {
                    why: format!(
                        "{peer_name} offered to be remembered; nothing was stored. Re-run with --remember <name> (or --yes) to accept"
                    ),
                });
            }
            // --yes accepts, and the petname falls back to the offerer's
            // proposal, then to the link's display name. The proposal is a
            // suggestion: it is sanitized here and stays local.
            petname(offer["name"].as_str(), peer_name)
        }
    };
    devices_store(&name, &sec)?;
    Ok(Answer::Kept { name, secret: sec })
}

/// A local petname from the offerer's proposal, falling back to the link name.
///
/// The proposal is peer-controlled text that becomes a filename-ish key in
/// `devices.json` and an argument people paste into `--to`, so it is reduced to
/// the characters a device name is allowed to have rather than trusted.
fn petname(proposed: Option<&str>, fallback: &str) -> String {
    let cleaned: String = proposed
        .unwrap_or("")
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(40)
        .collect();
    if cleaned.is_empty() {
        let fb: String = fallback
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .take(40)
            .collect();
        if fb.is_empty() { "device".to_string() } else { fb }
    } else {
        cleaned
    }
}

/// What a run's remember ceremony actually did, for the one line said at exit.
///
/// Every variant is set from an OBSERVED event: a stored record, a refusing
/// ack, a deadline with no answer, or a peer that never arrived. There is no
/// variant that can be reached from the presence of `--remember` alone, which
/// is the property the old code lacked.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Stored, on disk, under this local name.
    Remembered(String),
    /// They answered no. Nothing stored on either side.
    Declined,
    /// The session ended with the offer outstanding. Silence is a refusal, so
    /// nothing was stored.
    Unanswered,
    /// No peer was ever reached, so no offer was even made.
    NoPeer,
}

impl Outcome {
    /// True when a durable record exists because of this run.
    pub(crate) fn stored(&self) -> bool {
        matches!(self, Outcome::Remembered(_))
    }

    /// The honest line. Nothing here claims a write that did not happen.
    pub(crate) fn line(&self) -> String {
        match self {
            Outcome::Remembered(n) => format!(
                "remembered as '{n}'. it is in `filament devices` and survives a restart; find each other with no code"
            ),
            Outcome::Declined => {
                "not remembered: the other side declined. nothing was stored here or there".into()
            }
            Outcome::Unanswered => {
                "not remembered: the other side never answered, so nothing was stored (it needs --remember <name> or --yes)".into()
            }
            Outcome::NoPeer => {
                "not remembered: no peer was reached, so nothing was offered and nothing was stored".into()
            }
        }
    }
}
