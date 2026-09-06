//! Ephemeral devices and auth keys — pre-authorized self-enrollment.
//!
//! Two enrollment doors, one trust root:
//!   1. Interactive pairing (PAKE): people and persistent devices
//!   2. Auth key: programmatic and ephemeral, pre-authorized delegation
//!
//! Both root in the same user key. The auth key is the user key pre-authorizing
//! the second door with a scope and a clock on it.
//!
//! This module is the PURE, host-independent half of the ephemeral layer: the
//! AuthKey / EnrollmentPayload objects, the normalize/intersect helpers, and the
//! process-local burn / nonce / armed state (with their accessors). The one
//! piece that stays in the CLI is the pending-enrollment glue
//! (register_enrollment / build_enrollment_response), because
//! build_enrollment_response reads a DeviceCert (filament-id), which this crate
//! deliberately does not depend on. Those two share a static (PENDING_ENROLLS)
//! and therefore stay together in the CLI.
//!
//! Design: docs/design-ephemeral-auth-keys.md

use anyhow::{anyhow, bail, Result};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum TTL an auth key may be minted with (30 days).
const MAX_TTL_SECS: u64 = 30 * 24 * 3600;

/// Maximum enrollemnts per minute per enroll_pub (rate-limit, independent of burn).
const ENROLL_RATE_LIMIT: u32 = 5;

/// Maximum length for a canonical cap or tag string (cap truncation → collision defense).
const MAX_CAP_LEN: usize = 65535;

// ---------------------------------------------------------------------------
// AuthKey — owner-signed delegation token (no bearer secret)
// ---------------------------------------------------------------------------

/// Controls how many times an auth key may be used to enroll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reuse {
    Once,
    N(u32),
    Reusable,
}

impl Reuse {
    /// Commit both discriminant and count to canonical bytes.
    /// Once = (0, 0), N(n) = (1, n), Reusable = (2, u32::MAX).
    fn to_canonical(&self) -> (u32, u32) {
        match self {
            Reuse::Once => (0, 0),
            Reuse::N(n) => (1, *n),
            Reuse::Reusable => (2, u32::MAX),
        }
    }
}

/// Normalize a slice of capability strings: lowercase, sort, deduplicate.
pub fn normalize_caps(caps: &[String]) -> Vec<String> {
    let mut v: Vec<String> = caps.iter().map(|s| s.to_lowercase()).collect();
    v.sort();
    v.dedup();
    v
}

/// An owner-signed delegation token that authorizes a device to self-enroll
/// as a delegated principal. Carries an enroll PUBLIC key (no bearer secret).
///
/// Caps are NORMALIZED at construction and deserialization (lowercase, sorted,
/// deduped), so signature commitments are case-consistent and mesh-ban
/// comparisons (`c == "mesh"`) are sound.
#[derive(Debug, Clone)]
pub struct AuthKey {
    /// Owner's Ed25519 public key (the issuer, must match a trusted user_pub).
    pub issuer: [u8; 32],
    /// Public key of the enrollment keypair that the enrolled device must
    /// prove possession of. NOT a bearer secret — verifier learns only a
    /// public key, nothing replayable.
    pub enroll_pub: [u8; 32],
    /// Semantic capability actions — a CEILING, not a floor (see delegated
    /// principal). Normalized: sorted, deduplicated, lowercase.
    pub caps: Vec<String>,
    /// Which peer(s) may enroll this key. Empty = Any.
    pub audience: Vec<[u8; 32]>,
    /// Absolute expiry (unix seconds).
    pub expires: u64,
    /// How many times this key may be used.
    pub reuse: Reuse,
    /// Whether the enrolled device is ephemeral (removed on disconnect; no
    /// durable record written). `false` = persist the enrolled device.
    pub ephemeral: bool,
    /// The signed CEILING on how long the device may be offline before it
    /// stops being recognized, in seconds. Local owner policy may tighten it
    /// (never loosen) at enrollment or later; the effective budget is
    /// `min(signed_max_offline, local_policy)`, mirroring how caps work. Only
    /// meaningful when `ephemeral` is false.
    pub max_offline: u64,
    /// Human-readable tag for the use case ("ci", "gpu-borrower", etc.).
    pub tag: String,
    /// Ed25519 signature by the owner's user key over the canonical bytes.
    pub sig: [u8; 64],
    /// Wire version. 1 = legacy (max_offline absent from canonical bytes),
    /// 2 = current. Drives which canonical bytes the signature must cover so
    /// legacy keys still verify and new keys cannot be mistaken for them.
    version: u8,
}

/// Canonical bytes that the signature covers — deterministic, no ambiguity.
/// Uses u32 length prefixes to prevent truncation-based canonical collisions.
/// v2 appends `max_offline` after the ephemeral byte and prefixes a v2 tag, so
/// the v1 byte stream is byte-identical for legacy keys.
fn auth_key_canonical_bytes(k: &AuthKey) -> Vec<u8> {
    let mut b = Vec::new();
    if k.version >= 2 {
        b.extend_from_slice(b"filament-auth-key-v2");
    } else {
        b.extend_from_slice(b"filament-auth-key-v1");
    }
    b.extend_from_slice(&k.issuer);
    b.extend_from_slice(&k.enroll_pub);
    // caps (already normalized: sorted, deduped, lowercase)
    // COUNT PREFIX before loop — prevents caps/audience boundary forgery.
    b.extend_from_slice(&(k.caps.len() as u32).to_le_bytes());
    for c in &k.caps {
        b.extend_from_slice(&(c.len() as u32).to_le_bytes());
        b.extend_from_slice(c.as_bytes());
    }
    // audience sorted
    let mut aud = k.audience.clone();
    aud.sort();
    b.extend_from_slice(&(aud.len() as u32).to_le_bytes());
    for a in &aud {
        b.extend_from_slice(a);
    }
    b.extend_from_slice(&k.expires.to_le_bytes());
    let (disc, count) = k.reuse.to_canonical();
    b.extend_from_slice(&disc.to_le_bytes());
    b.extend_from_slice(&count.to_le_bytes());
    b.push(if k.ephemeral { 1 } else { 0 });
    if k.version >= 2 {
        b.extend_from_slice(&k.max_offline.to_le_bytes());
    }
    b.extend_from_slice(&(k.tag.len() as u32).to_le_bytes());
    b.extend_from_slice(k.tag.as_bytes());
    b
}

impl AuthKey {
    /// Mint a new auth key signed by the owner's user key.
    /// Caps are normalized (lowercase, sorted, deduped) at construction.
    /// ttl_secs is capped at MAX_TTL_SECS (30 days).
    /// Rejects caps or tag exceeding MAX_CAP_LEN.
    pub fn mint(
        owner_uk: &Ed25519KeyPair,
        enroll_pub: [u8; 32],
        caps: Vec<String>,
        audience: Vec<[u8; 32]>,
        ttl_secs: u64,
        reuse: Reuse,
        tag: String,
    ) -> Result<Self> {
        Self::mint_with_bounds(owner_uk, enroll_pub, caps, audience, ttl_secs, reuse, tag, MAX_TTL_SECS, true)
    }

    /// Like `mint`, but with an explicit signed `max_offline` CEILING (seconds)
    /// and the persistence choice. Local policy may only tighten the budget, and
    /// nothing may exceed the signed ceiling. `ephemeral: false` is the
    /// persistent form (a durable, budget-governed device).
    pub fn mint_with_bounds(
        owner_uk: &Ed25519KeyPair,
        enroll_pub: [u8; 32],
        caps: Vec<String>,
        audience: Vec<[u8; 32]>,
        ttl_secs: u64,
        reuse: Reuse,
        tag: String,
        max_offline: u64,
        ephemeral: bool,
    ) -> Result<Self> {
        let caps: Vec<String> = caps
            .iter()
            .map(|cap| super::capability::canonical_capability(cap))
            .collect::<Result<_>>()?;
        if tag.len() > MAX_CAP_LEN {
            bail!("tag too long (max {} bytes)", MAX_CAP_LEN);
        }
        if caps.iter().any(|c| c.len() > MAX_CAP_LEN) {
            bail!("cap too long (max {} bytes)", MAX_CAP_LEN);
        }
        // Refuse HERE, where there is still a caller to tell. The token encoder
        // used to swallow this and emit an empty ceiling, so `add --allow route`
        // produced a valid, signed invitation that granted nothing, and the
        // failure only surfaced much later as "route is outside <device>'s
        // invitation ceiling ()" on a machine that had done everything right.
        inv_caps_to_bitmask(&caps)?;
        let now = now_secs();
        let mut k = AuthKey {
            issuer: owner_uk.public_key().as_ref().try_into().map_err(|_| anyhow!("bad owner pub"))?,
            enroll_pub,
            caps: normalize_caps(&caps),
            audience,
            expires: now.saturating_add(ttl_secs.min(MAX_TTL_SECS)),
            reuse,
            ephemeral,
            max_offline: max_offline.min(MAX_TTL_SECS),
            tag,
            sig: [0u8; 64],
            version: 2,
        };
        let canonical = auth_key_canonical_bytes(&k);
        let sig = owner_uk.sign(&canonical);
        let sig_bytes: [u8; 64] = sig.as_ref().try_into().map_err(|_| anyhow!("bad sig"))?;
        k.sig = sig_bytes;
        Ok(k)
    }

    /// Verify signature + expiry only.
    /// Private — callers use verify_against_owner for the genesis-forgery guard.
    fn verify_sig_and_expiry(&self) -> Result<()> {
        if now_secs() >= self.expires {
            bail!("auth key expired");
        }
        let canonical = auth_key_canonical_bytes(self);
        let pubkey = UnparsedPublicKey::new(&ED25519, &self.issuer);
        pubkey
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("auth key signature invalid"))
    }

    /// Full verification: audience allowed, sig valid, not expired,
    /// issuer equals trusted owner_pub (genesis-forgery rule), mesh refused.
    pub fn verify_against_owner(&self, owner_pub: &[u8; 32], verifier_pub: &[u8; 32]) -> Result<()> {
        // Audience check FIRST — don't verify sig if this verifier is excluded.
        if !self.audience_allows(verifier_pub) {
            bail!("auth key not authorized for this peer");
        }
        // Caps normalization invariant — cheap hardening at point of use.
        if self.caps != normalize_caps(&self.caps) {
            bail!("auth key caps not normalized");
        }
        self.verify_sig_and_expiry()?;
        if self.issuer != *owner_pub {
            bail!("auth key issuer does not match trusted owner");
        }
        // Mesh refusal: caps are normalized (lowercase), so "mesh" catches all case variants.
        if self.caps.iter().any(|c| c == "mesh") {
            bail!("auth keys must not carry mesh capability");
        }
        Ok(())
    }

    /// Returns true if audience is empty (Any) or this peer is named.
    pub fn audience_allows(&self, peer_pub: &[u8; 32]) -> bool {
        self.audience.is_empty() || self.audience.contains(peer_pub)
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "issuer": hex::encode(self.issuer),
            "enroll_pub": hex::encode(self.enroll_pub),
            "caps": self.caps,
            "audience": self.audience.iter().map(hex::encode).collect::<Vec<_>>(),
            "expires": self.expires,
            "reuse": self.reuse,
            "ephemeral": self.ephemeral,
            "tag": self.tag,
            "sig": hex::encode(self.sig),
        });
        // v2 keys carry the signed max_offline ceiling; v1 keys serialize in
        // their original shape so a legacy key round-trips as v1 and verifies.
        if self.version >= 2 {
            if let serde_json::Value::Object(map) = &mut json {
                map.insert("max_offline".to_string(), serde_json::json!(self.max_offline));
            }
        }
        json
    }

    /// SAFE deserialization: uses try_into() (no panics on wrong-length hex).
    /// Caps are normalized at parse time.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let issuer: [u8; 32] = hex::decode(v.get("issuer")?.as_str()?).ok()?.try_into().ok()?;
        let enroll_pub: [u8; 32] = hex::decode(v.get("enroll_pub")?.as_str()?).ok()?.try_into().ok()?;
        let caps: Vec<String> = v.get("caps")?.as_array()?
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect();
        let caps = normalize_caps(&caps);
        let audience: Vec<[u8; 32]> = {
            let raw = v.get("audience")?.as_array()?;
            let mut out = Vec::with_capacity(raw.len());
            for x in raw {
                let b = hex::decode(x.as_str()?).ok()?;
                out.push(b.try_into().ok()?);
            }
            out
        };
        let expires = v.get("expires")?.as_u64()?;
        let reuse = match v.get("reuse")?.as_str()? {
            "Once" => Reuse::Once,
            "Reusable" => Reuse::Reusable,
            s if s.starts_with("N(") => {
                let n: u32 = s[2..s.len()-1].parse().ok()?;
                Reuse::N(n)
            }
            _ => return None,
        };
        let ephemeral = v.get("ephemeral")?.as_bool()?;
        let max_offline = v.get("max_offline").and_then(|m| m.as_u64()).unwrap_or(MAX_TTL_SECS);
        let tag = v.get("tag")?.as_str()?.to_string();
        let sig: [u8; 64] = hex::decode(v.get("sig")?.as_str()?).ok()?.try_into().ok()?;
        // Legacy keys have no max_offline field: they were signed over the v1
        // canonical bytes, so the version stays 1 and max_offline is not verified
        // (it is an owner-side policy default, never a signed commitment).
        let version = if v.get("max_offline").is_some() { 2 } else { 1 };
        Some(AuthKey { issuer, enroll_pub, caps, audience, expires, reuse, ephemeral, max_offline, tag, sig, version })
    }
}

/// Compact invitation token (v2 wire format, #186).
///
/// The 0.8.0 invitation token was hex-inside-JSON inside base64: ~530 bytes
/// for ~116 bytes of real content, which rendered a QR too wide for a normal
/// terminal. This is a self-contained binary replacement with a NEW signature
/// domain: the owner's Ed25519 signature covers the token bytes before the
/// trailing sig, so verification needs only the owner's public key. The owner
/// is selected by an 8-byte fingerprint; the full issuer is supplied by the
/// verifying daemon after the fingerprint matches. No tag, audience, or JSON.
///
/// TWO WIRE ARTIFACTS, ONE STRUCT (the verifier must never learn the seed):
/// - TOKEN (owner -> joiner, off-band): fields + SEED(32) + sig. The joiner
///   derives the public key from the seed, verifies the sig over
///   (fields + pub), then proves possession by signing with the seed.
/// - PAYLOAD (joiner -> daemon): fields + PUB(32) + sig, NO seed. The daemon
///   verifies the sig over (fields + pub) and learns only the public key.
///
/// Shared field region: version(1) | issuer_fp(8) | caps(1) | expires_min(4 LE)
/// | max_offline_s(4 LE) | reuse(1) | ephemeral(1) | owner_name_len(2 LE) |
/// owner_name(N) | key(32) | sig(64). `sig` covers the signed prefix, which is
/// the field region with the PUBLIC key where `key` sits (the seed is never in
/// the signed domain, so the payload needs no seed to verify).
#[derive(Clone)]
pub struct Invitation {
    pub issuer_fp: [u8; 8],
    pub caps: Vec<String>,
    pub expires: u64,
    pub max_offline: u64,
    pub reuse: Reuse,
    pub ephemeral: bool,
    /// The PUBLIC half. Always present, always in the signed domain: derived
    /// from the seed at mint and at token parse; parsed directly from the
    /// payload on the verifier side.
    pub enroll_pub: [u8; 32],
    /// The SEED. Present in the TOKEN only; NEVER serialized into the payload,
    /// so the verifier cannot replay possession. Zeroed on drop.
    pub enroll_private_key: [u8; 32],
    pub owner_name: String,
    /// Prefixes a `route` ceiling is limited to, as normalised CIDR strings.
    ///
    /// EMPTY MEANS NO ROUTING AUTHORITY, never "any prefix". A ceiling records
    /// an action and, before this, nothing else: `route` in a ceiling therefore
    /// authorised ANY prefix the member advertised, including 0.0.0.0/0, which
    /// is an exit node the owner never agreed to. The prefixes travel inside the
    /// signed domain, so a member cannot widen its own grant.
    ///
    /// Always encoded, as a count that is zero when there are none, so the
    /// format has one shape and one parser.
    pub routes: Vec<String>,
    pub sig: [u8; 64],
}

/// The invitation wire format tag.
///
/// A TAG, not a version to maintain. There is exactly one format and exactly one
/// parser: an invitation is a short-lived credential (minutes to days), so the
/// cost of carrying a second encoding forever is real and the benefit is not.
/// A byte that does not match is refused rather than guessed at.
const INV_FORMAT: u8 = 0x03;

const INV_CAP_TRANSFER: u8 = 1 << 0;
const INV_CAP_MOUNT: u8 = 1 << 1;
const INV_CAP_SHELL: u8 = 1 << 2;
const INV_CAP_WRITE: u8 = 1 << 3;
const INV_CAP_ALL_PORTS: u8 = 1 << 4;
// Bit 5. A capability that is grantable but NOT encodable here cannot be put in
// an invitation ceiling, and since a grant may never widen a ceiling, no joined
// device could ever legitimately hold it. Adding a capability to
// CANONICAL_CAPABILITIES therefore obliges adding a bit here; the round-trip
// test below fails if that is forgotten.
const INV_CAP_ROUTE: u8 = 1 << 5;
const INV_REUSE_REUSABLE: u8 = 255;

fn inv_caps_to_bitmask(caps: &[String]) -> Result<u8> {
    let mut mask = 0u8;
    for c in caps {
        mask |= match c.as_str() {
            "transfer" => INV_CAP_TRANSFER,
            "mount" => INV_CAP_MOUNT,
            "shell" => INV_CAP_SHELL,
            "write" => INV_CAP_WRITE,
            "all-ports" => INV_CAP_ALL_PORTS,
            "route" => INV_CAP_ROUTE,
            other => bail!("cannot encode capability '{other}' in a v2 invitation"),
        };
    }
    Ok(mask)
}

fn inv_caps_from_bitmask(mask: u8) -> Vec<String> {
    let mut out = Vec::new();
    if mask & INV_CAP_TRANSFER != 0 { out.push("transfer".into()); }
    if mask & INV_CAP_MOUNT != 0 { out.push("mount".into()); }
    if mask & INV_CAP_SHELL != 0 { out.push("shell".into()); }
    if mask & INV_CAP_WRITE != 0 { out.push("write".into()); }
    if mask & INV_CAP_ALL_PORTS != 0 { out.push("all-ports".into()); }
    if mask & INV_CAP_ROUTE != 0 { out.push("route".into()); }
    out
}

/// Deterministic 8-byte fingerprint of a public key; selects the owner.
pub fn issuer_fingerprint(pubkey: &[u8; 32]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pubkey);
    let d = h.finalize();
    let mut fp = [0u8; 8];
    fp.copy_from_slice(&d[..8]);
    fp
}

/// #186: the enrollment rendezvous channel is derived from an 8-byte issuer
/// fingerprint, so a compact invitation (which carries only the fingerprint)
/// can subscribe without the full owner key. The daemon derives the same
/// channel from its own key. A channel is a rendezvous point, not an
/// authorization; the enrollment response validates the signature.
pub fn enroll_channel_fp(fp: &[u8; 8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"filament-enroll-v1");
    h.update(fp);
    hex::encode(h.finalize().as_slice())
}

fn inv_reuse_to_byte(r: &Reuse) -> u8 {
    match r {
        Reuse::Once => 0,
        Reuse::N(n) => (*n as u8).min(250),
        Reuse::Reusable => INV_REUSE_REUSABLE,
    }
}

fn inv_reuse_from_byte(b: u8) -> Reuse {
    match b {
        0 => Reuse::Once,
        255 => Reuse::Reusable,
        n => Reuse::N(n as u32),
    }
}

/// Derive an Ed25519 public key from a seed.
fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed)
        .expect("32-byte seed is always a valid Ed25519 seed");
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(kp.public_key().as_ref());
    pubkey
}

/// Fixed field region (everything before the variable owner name): version,
/// issuer fp, caps, expiry, budget, reuse, ephemeral, name length.

/// Encode the route prefixes of a v3 invitation.
///
/// `count | (family, prefix_len, addr)*`, with family as the address byte width
/// so a reader never has to guess. Fixed-width and self-describing, because this
/// sits inside the SIGNED domain and a length the reader can disagree about is
/// a signature-confusion bug waiting to happen.
fn inv_routes_encode(routes: &[String]) -> Vec<u8> {
    let mut b = vec![routes.len() as u8];
    for cidr in routes {
        let Some((net, len)) = cidr.split_once('/') else { continue };
        let Ok(len) = len.parse::<u8>() else { continue };
        match net.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(a)) => {
                b.push(4);
                b.push(len);
                b.extend_from_slice(&a.octets());
            }
            Ok(std::net::IpAddr::V6(a)) => {
                b.push(16);
                b.push(len);
                b.extend_from_slice(&a.octets());
            }
            Err(_) => continue,
        }
    }
    b
}

/// Decode route prefixes, returning them and how many bytes were consumed.
/// `None` on any malformed input: a partially-read route list would change the
/// offset of the key and signature that follow.
fn inv_routes_decode(raw: &[u8]) -> Option<(Vec<String>, usize)> {
    let count = *raw.first()? as usize;
    let mut off = 1;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let width = *raw.get(off)? as usize;
        let len = *raw.get(off + 1)?;
        off += 2;
        let bytes = raw.get(off..off + width)?;
        off += width;
        let ip = match width {
            4 => std::net::IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
            16 => std::net::IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
            _ => return None,
        };
        out.push(format!("{ip}/{len}"));
    }
    Some((out, off))
}

fn inv_field_fixed_len() -> usize {
    1 + 8 + 1 + 4 + 4 + 1 + 1 + 2
}

impl Invitation {
    /// Mint a compact invitation. `enroll_private_key` is the SEED the joiner
    /// must possess; the public half is derived from it and is what the
    /// signature binds and the verifier learns. `owner_uk` signs the signed
    /// prefix (fields + derived public key).
    pub fn mint(
        owner_uk: &Ed25519KeyPair,
        enroll_private_key: [u8; 32],
        caps: Vec<String>,
        expires: u64,
        max_offline: u64,
        reuse: Reuse,
        ephemeral: bool,
        owner_name: String,
        routes: Vec<String>,
    ) -> Result<Self> {
        let caps = caps.iter().map(|c| super::capability::canonical_capability(c)).collect::<Result<Vec<_>>>()?;
        // A route ceiling MUST name its prefixes, and prefixes without the
        // capability are meaningless. Before this, `route` in a ceiling carried
        // no scope at all, so it authorised every prefix the member chose to
        // advertise, up to and including 0.0.0.0/0: an exit node the owner never
        // agreed to. Refusing both halves here is what makes the scope real,
        // because a ceiling that can be minted unscoped is not a scope.
        let wants_route = caps.iter().any(|c| c == super::capability::CAP_ROUTE);
        if wants_route && routes.is_empty() {
            bail!(
                "a 'route' invitation must name the prefixes it allows, e.g. --allow route:10.0.0.0/24"
            );
        }
        if !routes.is_empty() && !wants_route {
            bail!("route prefixes were given without the 'route' capability");
        }
        // Normalised so the signed bytes are canonical: 10.0.0.5/24 and
        // 10.0.0.0/24 must not be two different signed ceilings.
        let routes = routes
            .iter()
            .map(|r| super::capability::normalize_cidr(r))
            .collect::<Result<Vec<_>>>()?;
        let owner_pub: [u8; 32] = owner_uk.public_key().as_ref().try_into().map_err(|_| anyhow!("bad owner pub"))?;
        let enroll_pub = pubkey_from_seed(&enroll_private_key);
        let mut t = Invitation {
            issuer_fp: issuer_fingerprint(&owner_pub),
            caps,
            expires,
            max_offline,
            reuse,
            ephemeral,
            enroll_pub,
            enroll_private_key,
            owner_name,
            routes,
            sig: [0u8; 64],
        };
        let prefix = t.signed_prefix();
        let sig = owner_uk.sign(&prefix);
        t.sig.copy_from_slice(sig.as_ref());
        Ok(t)
    }

    /// The bytes the signature covers: fields + the PUBLIC key. The seed is
    /// NOT in the signed domain, so a payload carrying only the public half can
    /// be verified without ever seeing the seed.
    fn signed_prefix(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(INV_FORMAT);
        b.extend_from_slice(&self.issuer_fp);
        // `.unwrap_or(0)` here silently turned an unencodable capability into an
        // EMPTY ceiling: the invitation still minted, still signed, still
        // delivered, and conferred nothing. That is the worst available failure
        // mode for a security artifact, because everything downstream reports
        // success. mint_with_bounds now rejects unencodable caps up front, so
        // this cannot be reached with bad data; expect() states the invariant
        // rather than hiding its violation.
        let mask = inv_caps_to_bitmask(&self.caps)
            .expect("caps were validated as encodable at mint");
        b.push(mask);
        b.extend_from_slice(&(self.expires as u32).to_le_bytes());
        b.extend_from_slice(&(self.max_offline as u32).to_le_bytes());
        b.push(inv_reuse_to_byte(&self.reuse));
        b.push(if self.ephemeral { 1 } else { 0 });
        b.extend_from_slice(&(self.owner_name.len() as u16).to_le_bytes());
        b.extend_from_slice(self.owner_name.as_bytes());
        b.extend_from_slice(&inv_routes_encode(&self.routes));
        b.extend_from_slice(&self.enroll_pub);
        b
    }

    /// The TOKEN: the artifact handed to the joiner. Fields + SEED + sig.
    /// The joiner derives the public key from the seed and verifies the sig.
    pub fn to_token(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(INV_FORMAT);
        b.extend_from_slice(&self.issuer_fp);
        // `.unwrap_or(0)` here silently turned an unencodable capability into an
        // EMPTY ceiling: the invitation still minted, still signed, still
        // delivered, and conferred nothing. That is the worst available failure
        // mode for a security artifact, because everything downstream reports
        // success. mint_with_bounds now rejects unencodable caps up front, so
        // this cannot be reached with bad data; expect() states the invariant
        // rather than hiding its violation.
        let mask = inv_caps_to_bitmask(&self.caps)
            .expect("caps were validated as encodable at mint");
        b.push(mask);
        b.extend_from_slice(&(self.expires as u32).to_le_bytes());
        b.extend_from_slice(&(self.max_offline as u32).to_le_bytes());
        b.push(inv_reuse_to_byte(&self.reuse));
        b.push(if self.ephemeral { 1 } else { 0 });
        b.extend_from_slice(&(self.owner_name.len() as u16).to_le_bytes());
        b.extend_from_slice(self.owner_name.as_bytes());
        b.extend_from_slice(&inv_routes_encode(&self.routes));
        b.extend_from_slice(&self.enroll_private_key);
        b.extend_from_slice(&self.sig);
        b
    }

    /// The PAYLOAD: what the joiner sends to the verifier. Fields + PUB + sig.
    /// No seed crosses the wire; the verifier learns only the public key.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(INV_FORMAT);
        b.extend_from_slice(&self.issuer_fp);
        // `.unwrap_or(0)` here silently turned an unencodable capability into an
        // EMPTY ceiling: the invitation still minted, still signed, still
        // delivered, and conferred nothing. That is the worst available failure
        // mode for a security artifact, because everything downstream reports
        // success. mint_with_bounds now rejects unencodable caps up front, so
        // this cannot be reached with bad data; expect() states the invariant
        // rather than hiding its violation.
        let mask = inv_caps_to_bitmask(&self.caps)
            .expect("caps were validated as encodable at mint");
        b.push(mask);
        b.extend_from_slice(&(self.expires as u32).to_le_bytes());
        b.extend_from_slice(&(self.max_offline as u32).to_le_bytes());
        b.push(inv_reuse_to_byte(&self.reuse));
        b.push(if self.ephemeral { 1 } else { 0 });
        b.extend_from_slice(&(self.owner_name.len() as u16).to_le_bytes());
        b.extend_from_slice(self.owner_name.as_bytes());
        b.extend_from_slice(&inv_routes_encode(&self.routes));
        b.extend_from_slice(&self.enroll_pub);
        b.extend_from_slice(&self.sig);
        b
    }

    /// Parse a TOKEN (fields + seed + sig). Derives the public key from the
    /// seed and verifies the signature; returns None on any failure.
    pub fn from_token(raw: &[u8]) -> Option<Self> {
        let fixed = inv_field_fixed_len();
        if raw.len() < fixed + 32 + 64 {
            return None;
        }
        if raw[0] != INV_FORMAT {
            return None;
        }
        let name_len = u16::from_le_bytes(raw[fixed - 2..fixed].try_into().ok()?) as usize;
        let after_name = fixed + name_len;
        // Always present, zero-length when there are no routes. ONE shape, so
        // there is no second parse path to keep in step with the first.
        let (routes, routes_len) = inv_routes_decode(raw.get(after_name..)?)?;
        let key_off = after_name + routes_len;
        // Exact, not "at least": a trailing byte would mean the reader and the
        // signer disagree about where the signed region ends.
        if key_off + 32 + 64 != raw.len() {
            return None;
        }
        let mut enroll_private_key = [0u8; 32];
        enroll_private_key.copy_from_slice(&raw[key_off..key_off + 32]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&raw[key_off + 32..]);
        let t = Invitation {
            issuer_fp: raw[1..9].try_into().ok()?,
            caps: inv_caps_from_bitmask(raw[9]),
            expires: u32::from_le_bytes(raw[10..14].try_into().ok()?) as u64,
            max_offline: u32::from_le_bytes(raw[14..18].try_into().ok()?) as u64,
            reuse: inv_reuse_from_byte(raw[18]),
            ephemeral: raw[19] == 1,
            enroll_pub: pubkey_from_seed(&enroll_private_key),
            enroll_private_key,
            owner_name: String::from_utf8(raw[fixed..after_name].to_vec()).ok()?,
            routes,
            sig,
        };
        Some(t)
    }

    /// Parse a PAYLOAD (fields + pub + sig). The verifier learns only the
    /// public key; no seed is present. Verifies the signature.
    pub fn from_payload(raw: &[u8]) -> Option<Self> {
        let fixed = inv_field_fixed_len();
        if raw.len() < fixed + 32 + 64 {
            return None;
        }
        if raw[0] != INV_FORMAT {
            return None;
        }
        let name_len = u16::from_le_bytes(raw[fixed - 2..fixed].try_into().ok()?) as usize;
        let after_name = fixed + name_len;
        // Always present, zero-length when there are no routes. ONE shape, so
        // there is no second parse path to keep in step with the first.
        let (routes, routes_len) = inv_routes_decode(raw.get(after_name..)?)?;
        let key_off = after_name + routes_len;
        // Exact, not "at least": a trailing byte would mean the reader and the
        // signer disagree about where the signed region ends.
        if key_off + 32 + 64 != raw.len() {
            return None;
        }
        let t = Invitation {
            issuer_fp: raw[1..9].try_into().ok()?,
            caps: inv_caps_from_bitmask(raw[9]),
            expires: u32::from_le_bytes(raw[10..14].try_into().ok()?) as u64,
            max_offline: u32::from_le_bytes(raw[14..18].try_into().ok()?) as u64,
            reuse: inv_reuse_from_byte(raw[18]),
            ephemeral: raw[19] == 1,
            enroll_pub: raw[key_off..key_off + 32].try_into().ok()?,
            enroll_private_key: [0u8; 32],
            owner_name: String::from_utf8(raw[fixed..after_name].to_vec()).ok()?,
            routes,
            sig: raw[key_off + 32..].try_into().ok()?,
        };
        Some(t)
    }

    /// The fingerprint selects the owner; the signature binds. Verify both
    /// against the given owner public key.
    pub fn verify_against_owner(&self, owner_pub: &[u8; 32]) -> bool {
        if self.issuer_fp != issuer_fingerprint(owner_pub) {
            return false;
        }
        let prefix = self.signed_prefix();
        let pubkey = UnparsedPublicKey::new(&ED25519, owner_pub);
        pubkey.verify(&prefix, &self.sig).is_ok()
    }

    /// Reconstruct a full AuthKey for the verifying owner (its own issuer),
    /// for the daemon's principal registration. The signature is the compact
    /// token's (a different domain than the legacy canonical); nothing re-verifies
    /// it after enrollment, so this is for carrying the ceiling forward.
    pub fn to_auth_key(&self, owner_pub: &[u8; 32]) -> AuthKey {
        let kind_tag = if self.caps.iter().any(|c| c == "mount") { "join-device" } else { "join-person" };
        // Carry the route SCOPE into the caps themselves: `route:10.0.0.0/24`
        // rather than a bare `route`. The prefixes arrived inside the signed
        // invitation, and this is the one conversion between the invitation and
        // everything downstream, so scoping here means the ceiling that gets
        // stored, displayed and enforced all say which prefix without any of
        // them needing a second field to look up.
        let caps = self
            .caps
            .iter()
            .flat_map(|c| {
                if c == super::capability::CAP_ROUTE {
                    self.routes.iter().map(|r| format!("route:{r}")).collect::<Vec<_>>()
                } else {
                    vec![c.clone()]
                }
            })
            .collect();
        AuthKey {
            issuer: *owner_pub,
            enroll_pub: self.enroll_pub,
            caps,
            audience: Vec::new(),
            expires: self.expires,
            reuse: self.reuse.clone(),
            ephemeral: self.ephemeral,
            max_offline: self.max_offline,
            tag: kind_tag.to_string(),
            sig: self.sig,
            version: 2,
        }
    }
}

impl serde::Serialize for Reuse {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Reuse::Once => s.serialize_str("Once"),
            Reuse::N(n) => s.serialize_str(&format!("N({})", n)),
            Reuse::Reusable => s.serialize_str("Reusable"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Reuse {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "Once" => Ok(Reuse::Once),
            "Reusable" => Ok(Reuse::Reusable),
            s if s.starts_with("N(") && s.ends_with(')') => {
                let n: u32 = s[2..s.len()-1].parse().map_err(serde::de::Error::custom)?;
                Ok(Reuse::N(n))
            }
            _ => Err(serde::de::Error::custom(format!("invalid Reuse: {}", s))),
        }
    }
}

// ---------------------------------------------------------------------------
// Enrollment payload — what the enrolling machine presents to a verifying peer
// ---------------------------------------------------------------------------

/// The enrollment payload carried over the wire. The machine generates its own
/// device keypair and presents the auth key + device_pub + possession proofs.
///
/// NONCE IS NOT ON THE WIRE. The verifier always knows the challenge it issued;
/// keeping it on the wire enables replay attacks. The verifier passes its held
/// nonce to verify() directly.
pub enum EnrollmentPrincipal {
    /// #186 compact-invitation join: the verifier checks the 8-byte owner
    /// fingerprint + the compact signature, then reconstructs the full AuthKey
    /// under its own issuer.
    Compact(Invitation),
    /// Legacy mint/enroll path (hidden): a full AuthKey with its own issuer.
    Legacy(AuthKey),
}

pub struct EnrollmentPayload {
    pub principal: EnrollmentPrincipal,
    pub device_pub: [u8; 32],
    /// Possession proof: sign(possession_msg(nonce, device_pub, verifier_pub))
    /// with enroll_priv (proves holder possesses auth key's private half).
    pub enroll_possession_sig: [u8; 64],
    /// Possession proof: same message signed with device_priv (proves holder
    /// possesses the device key it claims).
    pub device_possession_sig: [u8; 64],
}

/// Possession message: binds the enrollment to a specific nonce, device,
/// AND verifier, so a payload captured for peer A cannot be presented to peer B.
pub fn enrollment_possession_msg(nonce: &[u8; 32], device_pub: &[u8; 32], verifier_pub: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"filament-auth-key-enroll-v1");
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(device_pub);
    msg.extend_from_slice(verifier_pub);
    msg
}

impl EnrollmentPayload {
    /// Build payload: sign possession messages with both keys.
    /// verifier_pub binds this payload to a specific verifier.
    pub fn build(
        principal: EnrollmentPrincipal,
        device_pub: [u8; 32],
        enroll_keypair: &Ed25519KeyPair,
        device_keypair: &Ed25519KeyPair,
        nonce: [u8; 32],
        verifier_pub: [u8; 32],
    ) -> Self {
        let msg = enrollment_possession_msg(&nonce, &device_pub, &verifier_pub);
        let enroll_sig = enroll_keypair.sign(&msg);
        let device_sig = device_keypair.sign(&msg);
        let mut es = [0u8; 64];
        es.copy_from_slice(enroll_sig.as_ref());
        let mut ds = [0u8; 64];
        ds.copy_from_slice(device_sig.as_ref());
        EnrollmentPayload {
            principal,
            device_pub,
            enroll_possession_sig: es,
            device_possession_sig: ds,
        }
    }

    /// Verify the enrollment payload against a trusted owner.
    /// `verifier_nonce` is the nonce THIS verifier issued — never trust the
    /// payload's own claim. `verifier_pub` binds to this specific verifier.
    /// Returns (enroll_pub, device_pub, verified_auth_key) on success.
    pub fn verify(
        &self,
        owner_pub: &[u8; 32],
        verifier_nonce: &[u8; 32],
        verifier_pub: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], AuthKey)> {
        // 1. Verify the principal under the trusted owner. Compact: the 8-byte
        //    fingerprint selects the owner, the Ed25519 signature binds.
        //    Legacy: the auth key's signature + issuer equality.
        let enroll_pub = match &self.principal {
            EnrollmentPrincipal::Compact(inv) => {
                if !inv.verify_against_owner(owner_pub) {
                    bail!("invitation signature or fingerprint invalid");
                }
                if now_secs() >= inv.expires {
                    bail!("invitation expired");
                }
                inv.enroll_pub
            }
            EnrollmentPrincipal::Legacy(ak) => {
                ak.verify_against_owner(owner_pub, verifier_pub)?;
                ak.enroll_pub
            }
        };
        let ak = match &self.principal {
            EnrollmentPrincipal::Compact(inv) => inv.to_auth_key(owner_pub),
            EnrollmentPrincipal::Legacy(ak) => ak.clone(),
        };

        // 2. Build possession message from VERIFIER's held nonce, NOT payload bytes
        let msg = enrollment_possession_msg(verifier_nonce, &self.device_pub, verifier_pub);

        // 3. Verify enroll possession
        let enroll_pkey = UnparsedPublicKey::new(&ED25519, &enroll_pub);
        enroll_pkey
            .verify(&msg, &self.enroll_possession_sig)
            .map_err(|_| anyhow!("enroll possession proof invalid"))?;

        // 4. Verify device possession
        let device_pkey = UnparsedPublicKey::new(&ED25519, &self.device_pub);
        device_pkey
            .verify(&msg, &self.device_possession_sig)
            .map_err(|_| anyhow!("device possession proof invalid"))?;

        Ok((enroll_pub, self.device_pub, ak))
    }

    pub fn to_json(&self) -> serde_json::Value {
        use base64::Engine;
        match &self.principal {
            EnrollmentPrincipal::Compact(inv) => serde_json::json!({
                "inv_v2": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(inv.to_payload()),
                "device_pub": hex::encode(self.device_pub),
                "enroll_possession_sig": hex::encode(self.enroll_possession_sig),
                "device_possession_sig": hex::encode(self.device_possession_sig),
            }),
            EnrollmentPrincipal::Legacy(ak) => serde_json::json!({
                "auth_key": ak.to_json(),
                "device_pub": hex::encode(self.device_pub),
                "enroll_possession_sig": hex::encode(self.enroll_possession_sig),
                "device_possession_sig": hex::encode(self.device_possession_sig),
            }),
        }
    }

    /// SAFE deserialization: uses try_into() (no panics on wrong-length hex).
    /// Nonce is NOT in the JSON — the verifier supplies its own.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        use base64::Engine;
        // ONE ACCEPTED SHAPE. This used to fall back to a Legacy principal read
        // from an `auth_key` field. The producer of that shape was `ephemeral
        // mint`, which no longer exists, so nothing could legitimately send it,
        // and an enrolment parser that still accepts it is a second way to
        // become a principal kept alive past its reason.
        //
        // Closing the request handler alone was NOT enough: the daemon reaches
        // this function on the RESPONSE path, so the shape stayed reachable
        // through a different door. Both are shut here.
        let b64 = v.get("inv_v2").and_then(|x| x.as_str())?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).ok()?;
        let principal = EnrollmentPrincipal::Compact(Invitation::from_payload(&bytes)?);
        let device_pub: [u8; 32] = hex::decode(v.get("device_pub")?.as_str()?).ok()?.try_into().ok()?;
        let enroll_possession_sig: [u8; 64] = hex::decode(v.get("enroll_possession_sig")?.as_str()?).ok()?.try_into().ok()?;
        let device_possession_sig: [u8; 64] = hex::decode(v.get("device_possession_sig")?.as_str()?).ok()?.try_into().ok()?;
        Some(EnrollmentPayload {
            principal,
            device_pub,
            enroll_possession_sig,
            device_possession_sig,
        })
    }
}

// ---------------------------------------------------------------------------
// Burn / rate-limit state — per-peer, per-enroll_pub
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ---- Burn store (enroll_pub-keyed, PERMANENT — must survive process lifetime for single-use) ----

struct BurnEntry {
    burn_count: u32,       // never reset (reuse guard)
    window_count: u32,     // reset every 60s (rate limit on successful burns)
    window_start_secs: u64,
}

struct BurnState {
    map: HashMap<[u8; 32], BurnEntry>,
}

static BURN: OnceLock<Mutex<BurnState>> = OnceLock::new();

fn burn_state() -> &'static Mutex<BurnState> {
    BURN.get_or_init(|| Mutex::new(BurnState { map: HashMap::new() }))
}

// ---- Flood store (pid-keyed, TTL-sweepable — SEPARATE from burn so entries can be evicted) ----

struct FloodEntry {
    attempt_count: u32,
    window_start_secs: u64,
}

struct FloodState {
    map: HashMap<String, FloodEntry>,
}

static FLOOD: OnceLock<Mutex<FloodState>> = OnceLock::new();

fn flood_state() -> &'static Mutex<FloodState> {
    FLOOD.get_or_init(|| Mutex::new(FloodState { map: HashMap::new() }))
}

/// Rate-limit check: pre-flight anti-flood KEYED BY TRANSPORT PID.
/// Separate map from burn store so expired entries can be swept without
/// destroying permanent single-use burn state.
pub fn check_rate_limit(pid: &str) -> Result<()> {
    let now_secs = now_secs();
    let mut state = flood_state().lock().unwrap();
    // Sweep expired flood entries
    state.map.retain(|_, e| now_secs.saturating_sub(e.window_start_secs) < 120);
    let entry = state.map.entry(pid.to_string()).or_insert(FloodEntry {
        attempt_count: 0,
        window_start_secs: now_secs,
    });
    let elapsed = now_secs.saturating_sub(entry.window_start_secs);
    if elapsed >= 60 {
        entry.attempt_count = 0;
        entry.window_start_secs = now_secs;
    }
    if entry.attempt_count >= ENROLL_RATE_LIMIT {
        bail!("too many enrollment attempts (max {}/min)", ENROLL_RATE_LIMIT);
    }
    entry.attempt_count += 1;
    Ok(())
}

/// Consume one use of an auth key identified by `enroll_pub`.
/// Rate-limited: max 5 enrollments/min per enroll_pub per peer.
/// Burn is process-local: a daemon restart clears all burn state.
/// NEVER reset burn_count (reuse guard) — rate-limit window is independent.
pub fn burn_auth_key(enroll_pub: &[u8; 32], reuse: &Reuse) -> Result<()> {
    burn_auth_key_at(enroll_pub, reuse, now_secs())
}

/// Like burn_auth_key but takes an explicit now so tests can advance time
/// without sleeping.
pub(crate) fn burn_auth_key_at(enroll_pub: &[u8; 32], reuse: &Reuse, now_secs: u64) -> Result<()> {
    let mut state = burn_state().lock().unwrap();
    let entry = state.map.entry(*enroll_pub).or_insert(BurnEntry {
        burn_count: 0,
        window_count: 0,
        window_start_secs: now_secs,
    });

    let elapsed = now_secs.saturating_sub(entry.window_start_secs);
    if elapsed >= 60 {
        entry.window_count = 0;
        entry.window_start_secs = now_secs;
    }
    if entry.window_count >= ENROLL_RATE_LIMIT {
        bail!("auth key rate-limited (max {} enrollments/min)", ENROLL_RATE_LIMIT);
    }

    match reuse {
        Reuse::Once => {
            if entry.burn_count > 0 {
                bail!("auth key already used (single-use)");
            }
        }
        Reuse::N(max) => {
            if entry.burn_count >= *max {
                bail!("auth key exhausted ({} uses)", max);
            }
        }
        Reuse::Reusable => {}
    }

    entry.burn_count += 1;
    entry.window_count += 1;

    // Burn: a consumed key is left in the armed file until its expiry, when the
    // file-backed store's is_armed() prunes it. Enrollment still requires the
    // signed invitation, so a burned key lingering in the set is harmless and a
    // per-key immediate disarm (which needs this crate to know the store path,
    // which it must not) is a refinement the CLI may add later.
    Ok(())
}

// ---------------------------------------------------------------------------
// Delegated principal — auth-key-enrolled devices have ceiling = caps ∩ owner
// ---------------------------------------------------------------------------

/// A delegated principal's effective capabilities are the INTERSECTION of the
/// owner's effective caps at this peer AND the auth key's caps. Both sides are
/// normalized (lowercase) so mixed-case owner caps are correctly intersected.
///
/// Invariants (property-testable):
///   effective(delegated) ⊆ auth_key_caps  (the ceiling)
///   effective(delegated) ⊆ effective(owner)  (no escalation)
pub fn delegated_effective_caps(
    owner_effective: &[String],
    auth_key_caps: &[String],
) -> Vec<String> {
    let owner_set: std::collections::HashSet<String> =
        owner_effective.iter().map(|s| s.to_lowercase()).collect();
    let mut result: Vec<String> = auth_key_caps
        .iter()
        .filter(|c| owner_set.contains(c.as_str()))
        .cloned()
        .collect();
    result.sort();
    result.dedup();
    result
}

// ---------------------------------------------------------------------------
// Enrollment nonce store — challenge/response anti-replay
// ---------------------------------------------------------------------------

use std::time::Instant as StdInstant;

const ENROLL_NONCE_TTL_SECS: u64 = 60;

struct NonceEntry {
    nonce: [u8; 32],
    deadline: StdInstant,
}

struct NonceStore {
    // peer_id → list of pending nonces (one enrollment attempt at a time expected)
    pending: HashMap<String, Vec<NonceEntry>>,
}

static NONCE_STORE: OnceLock<Mutex<NonceStore>> = OnceLock::new();

fn nonce_store() -> &'static Mutex<NonceStore> {
    NONCE_STORE.get_or_init(|| Mutex::new(NonceStore { pending: HashMap::new() }))
}

/// Generate a fresh CSPRNG nonce for the given peer, store it, return the nonce.
/// Rate-limited: called once per attempt (by check_rate_limit), single outstanding
/// nonce per peer (replaced on each new request). Sweeps expired entries on insert.
/// Propagates CSPRNG fill error — never issues a zero-filled nonce.
pub fn generate_nonce(peer_id: &str) -> Result<[u8; 32]> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce).map_err(|e| anyhow!("CSPRNG failure: {}", e))?;
    // Nonce must be non-zero after fill
    if nonce == [0u8; 32] {
        bail!("CSPRNG returned zero nonce");
    }
    let mut store = nonce_store().lock().unwrap();
    // Sweep expired entries across ALL peers
    let now = StdInstant::now();
    store.pending.retain(|_, entries| {
        entries.iter().any(|e| e.deadline > now)
    });
    // Single outstanding nonce per peer — replace
    store.pending.insert(peer_id.to_string(), vec![NonceEntry {
        nonce,
        deadline: now + std::time::Duration::from_secs(ENROLL_NONCE_TTL_SECS),
    }]);
    Ok(nonce)
}

/// Consume the outstanding nonce for a peer and return it.
/// Since we maintain a single outstanding nonce per peer (replaced on each
/// new request), this simply takes it. Errors if none found or expired.
pub fn consume_latest_nonce(peer_id: &str) -> Result<[u8; 32]> {
    let mut store = nonce_store().lock().unwrap();
    let entries = match store.pending.get_mut(peer_id) {
        Some(v) => v,
        None => bail!("no enrollment nonce for peer"),
    };
    let now = StdInstant::now();
    entries.retain(|e| e.deadline > now);
    if entries.is_empty() {
        store.pending.remove(peer_id);
        bail!("enrollment nonce expired or already consumed");
    }
    let nonce = entries.remove(0).nonce;
    if entries.is_empty() {
        store.pending.remove(peer_id);
    }
    Ok(nonce)
}

// Remove consume_nonce (peer_id, nonce) — no longer needed since single-outstanding.

// ---------------------------------------------------------------------------
// Arm-gate: armed set for enrollment room membership
//
// REMOVED from here. The armed set was an in-memory OnceLock, which meant the
// only way a mint could tell the daemon "an invitation is outstanding" was
// inter-process communication, and IPC is the one thing with no portable form
// (#205 Windows had no socket, #211 the socket was a bind race, and a daemon
// restart silently disarmed every outstanding invitation). It is now a
// file-backed store in the CLI (cli/src/armed.rs): the mint writes armed.json
// directly, the daemon's per-tick arm-gate reads it. This crate stays pure.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Derive a network-independent enrollment rendezvous channel from the owner's
/// public key. Both the `up` daemon and the enroller join this channel so they
/// can rendezvous cross-network (same model as channel_of for pairing secrets).
pub fn enroll_channel(owner_pub: &[u8; 32]) -> String {
    // #186: the channel is derived from an 8-byte fingerprint of the owner key
    // so a compact invitation (which carries only the fp) can subscribe
    // without the full key. The daemon passes its full key here and derives
    // the same channel.
    enroll_channel_fp(&issuer_fingerprint(owner_pub))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::KeyPair;

    fn gen_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed).unwrap();
        Ed25519KeyPair::from_seed_unchecked(&seed).unwrap()
    }

    fn owner_pub(owner: &Ed25519KeyPair) -> [u8; 32] {
        owner.public_key().as_ref().try_into().unwrap()
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn mint_v2(owner: &Ed25519KeyPair) -> Invitation {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed).unwrap();
        Invitation::mint(
            owner,
            seed,
            vec!["transfer".into(), "mount".into()],
            1_800_000_000,
            30 * 24 * 3600,
            Reuse::Once,
            false,
            "alice".into(),
            Vec::new(),
        )
        .unwrap()
    }

    // ── #186 invitation v2: two-artifact property ───────────────────────
    // The token (owner -> joiner) carries the possession seed; the payload
    // (joiner -> verifier) carries only the public half. The verifier must
    // never learn anything replayable.

    #[test]
    fn v2_payload_does_not_contain_the_seed() {
        let owner = gen_keypair();
        let inv = mint_v2(&owner);
        let payload = inv.to_payload();
        let token = inv.to_token();
        // An intercepted payload reveals nothing replayable: the seed that
        // proves possession must not appear anywhere in it.
        assert!(
            !find_subslice(&payload, &inv.enroll_private_key),
            "payload must not contain the possession seed"
        );
        // And the token (which the joiner legitimately holds) does carry it.
        assert!(
            find_subslice(&token, &inv.enroll_private_key),
            "token carries the seed for the joiner"
        );
    }

    #[test]
    fn v2_payload_cannot_be_replayed_by_an_interceptor() {
        let owner = gen_keypair();
        let inv = mint_v2(&owner);
        let payload = inv.to_payload();
        let parsed = Invitation::from_payload(&payload).unwrap();
        // The verifier learns only the public key. A possession proof signed
        // with ANY seed other than the joiner's fails verification against it,
        // so an interceptor of the payload (or the verifier itself) cannot
        // impersonate the joiner.
        let rng = SystemRandom::new();
        let mut forge_seed = [0u8; 32];
        rng.fill(&mut forge_seed).unwrap();
        while forge_seed == inv.enroll_private_key {
            rng.fill(&mut forge_seed).unwrap();
        }
        let forge_kp = Ed25519KeyPair::from_seed_unchecked(&forge_seed).unwrap();
        let challenge = b"possession-challenge";
        let forge_sig = forge_kp.sign(challenge);
        let verifier = UnparsedPublicKey::new(&ED25519, &parsed.enroll_pub);
        assert!(
            verifier.verify(challenge, forge_sig.as_ref()).is_err(),
            "a forged possession proof must fail against the payload's public key"
        );
    }

    #[test]
    fn v2_token_roundtrips_to_a_verifiable_payload() {
        let owner = gen_keypair();
        let inv = mint_v2(&owner);
        let token = inv.to_token();
        let parsed = Invitation::from_token(&token).unwrap();
        // The joiner derives the public half from the seed; it must match the
        // minted value.
        assert_eq!(parsed.enroll_pub, inv.enroll_pub, "derived pub matches minted pub");
        assert_eq!(parsed.caps, inv.caps);
        assert_eq!(parsed.issuer_fp, inv.issuer_fp);
        let payload = parsed.to_payload();
        let wire = Invitation::from_payload(&payload).unwrap();
        // The daemon verifies the owner signature over (fields + pub) and
        // learns only the pub.
        assert!(
            wire.verify_against_owner(&owner_pub(&owner)),
            "daemon verifies the owner signature"
        );
        assert_eq!(wire.enroll_pub, inv.enroll_pub);
    }

    #[test]
    fn v2_tampered_payload_fails_owner_verification() {
        let owner = gen_keypair();
        let inv = mint_v2(&owner);
        // Flip a byte in the signed field region (expiry), not the sig.
        let mut payload = inv.to_payload();
        let flip = payload.len() - 64 - 32 - 4;
        payload[flip] ^= 0x01;
        let wire = Invitation::from_payload(&payload).unwrap();
        assert!(
            !wire.verify_against_owner(&owner_pub(&owner)),
            "a tampered payload must fail the owner signature"
        );
        // Tampering the signature itself also fails.
        let mut payload2 = inv.to_payload();
        let last = payload2.len() - 1;
        payload2[last] ^= 0x01;
        let wire2 = Invitation::from_payload(&payload2).unwrap();
        assert!(
            !wire2.verify_against_owner(&owner_pub(&owner)),
            "a tampered signature must fail the owner signature"
        );
    }

    // ── Finding 1: Replay ──────────────────────────────────────────────

    #[test]
    fn replay_payload_rejected_with_wrong_nonce() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let rng = SystemRandom::new();
        let mut nonce1 = [0u8; 32];
        rng.fill(&mut nonce1).unwrap();
        let mut nonce2 = [0u8; 32];
        rng.fill(&mut nonce2).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(EnrollmentPrincipal::Legacy(ak), device_pub, &enroll_kp, &device_kp, nonce1, verifier_pub);
        let op = owner_pub(&owner);

        // Correct nonce passes
        assert!(payload.verify(&op, &nonce1, &verifier_pub).is_ok());
        // Replayed with wrong nonce fails
        assert!(payload.verify(&op, &nonce2, &verifier_pub).is_err());
        // Nonce is not on the wire (JSON roundtrip has no nonce field)
        let json = payload.to_json();
        assert!(json.get("nonce").is_none());
    }

    #[test]
    fn replay_payload_verifier_bound() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let verifier_a: [u8; 32] = [0xAA; 32];
        let verifier_b: [u8; 32] = [0xBB; 32];
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(EnrollmentPrincipal::Legacy(ak), device_pub, &enroll_kp, &device_kp, nonce, verifier_a);
        let op = owner_pub(&owner);

        assert!(payload.verify(&op, &nonce, &verifier_a).is_ok());
        // Same payload presented to verifier B fails
        assert!(payload.verify(&op, &nonce, &verifier_b).is_err());
    }

    // ── Finding 2: Mesh case-bypass ────────────────────────────────────

    #[test]
    fn mesh_rejected_at_mint() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        assert!(AuthKey::mint(&owner, enroll_pub, vec!["mesh".into()], vec![], 3600, Reuse::Once, "test".into()).is_err());
    }

    #[test]
    fn mesh_case_bypass_rejected_at_mint() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        assert!(AuthKey::mint(&owner, enroll_pub, vec!["MESH".into()], vec![], 3600, Reuse::Once, "test".into()).is_err());
    }

    #[test]
    fn mesh_refused_when_parsed_from_json() {
        // Construct JSON with "MESH" (mixed or upper case) — from_json must normalize
        let ak_json = serde_json::json!({
            "issuer": hex::encode([0u8; 32]),
            "enroll_pub": hex::encode([0u8; 32]),
            "caps": ["MESH"],
            "audience": [],
            "expires": now_secs() + 3600,
            "reuse": "Once",
            "ephemeral": true,
            "tag": "test",
            "sig": hex::encode([0u8; 64])
        });
        let parsed = AuthKey::from_json(&ak_json).unwrap();
        assert_eq!(parsed.caps, vec!["mesh"]); // normalized at parse
    }

    // ── Finding 3: Burn reset ──────────────────────────────────────────

    #[test]
    fn burn_once_not_undone_by_rate_window_reset() {
        let kp = gen_keypair();
        let enroll_pub: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();

        // Use once at t=0
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::Once, 0).is_ok());
        // Still at t=0: second use fails (single-use consumed)
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::Once, 0).is_err());

        // Manually reset window to simulate rate-window expiry at t=120
        {
            let mut state = burn_state().lock().unwrap();
            if let Some(entry) = state.map.get_mut(&enroll_pub) {
                entry.window_count = 0;
                entry.window_start_secs = 120;
            }
        }
        // At t=120, window is fresh — but burn_count is still 1, so Reuse::Once still fails
        assert!(
            burn_auth_key_at(&enroll_pub, &Reuse::Once, 120).is_err(),
            "burn must not reset with rate-limit window"
        );
    }

    #[test]
    fn burn_n_count_enforced() {
        let kp = gen_keypair();
        let enroll_pub: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::N(3), 0).is_ok());
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::N(3), 1).is_ok());
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::N(3), 2).is_ok());
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::N(3), 3).is_err());
    }

    // ── Finding 4: Pre-auth panic ──────────────────────────────────────

    #[test]
    fn from_json_no_panic_on_wrong_length_hex() {
        // AuthKey: short issuer
        let ak_json = serde_json::json!({
            "issuer": "aa",
            "enroll_pub": hex::encode([0u8; 32]),
            "caps": ["shell"],
            "audience": [],
            "expires": now_secs() + 3600,
            "reuse": "Once",
            "ephemeral": true,
            "tag": "test",
            "sig": hex::encode([0u8; 64])
        });
        assert!(AuthKey::from_json(&ak_json).is_none());

        // AuthKey: short sig
        let ak_json2 = serde_json::json!({
            "issuer": hex::encode([0u8; 32]),
            "enroll_pub": hex::encode([0u8; 32]),
            "caps": ["shell"],
            "audience": [],
            "expires": now_secs() + 3600,
            "reuse": "Once",
            "ephemeral": true,
            "tag": "test",
            "sig": "aa"
        });
        assert!(AuthKey::from_json(&ak_json2).is_none());

        // AuthKey: short audience element
        let ak_json3 = serde_json::json!({
            "issuer": hex::encode([0u8; 32]),
            "enroll_pub": hex::encode([0u8; 32]),
            "caps": ["shell"],
            "audience": ["aa"],
            "expires": now_secs() + 3600,
            "reuse": "Once",
            "ephemeral": true,
            "tag": "test",
            "sig": hex::encode([0u8; 64])
        });
        assert!(AuthKey::from_json(&ak_json3).is_none());

        // EnrollmentPayload: short device_pub
        let pl_json = serde_json::json!({
            "auth_key": {
                "issuer": hex::encode([0u8; 32]),
                "enroll_pub": hex::encode([0u8; 32]),
                "caps": ["shell"],
                "audience": [],
                "expires": now_secs() + 3600,
                "reuse": "Once",
                "ephemeral": true,
                "tag": "test",
                "sig": hex::encode([0u8; 64])
            },
            "device_pub": "aa",
            "enroll_possession_sig": hex::encode([0u8; 64]),
            "device_possession_sig": hex::encode([0u8; 64])
        });
        assert!(EnrollmentPayload::from_json(&pl_json).is_none());

        // EnrollmentPayload: short possession sig
        let pl_json2 = serde_json::json!({
            "auth_key": {
                "issuer": hex::encode([0u8; 32]),
                "enroll_pub": hex::encode([0u8; 32]),
                "caps": ["shell"],
                "audience": [],
                "expires": now_secs() + 3600,
                "reuse": "Once",
                "ephemeral": true,
                "tag": "test",
                "sig": hex::encode([0u8; 64])
            },
            "device_pub": hex::encode([0u8; 32]),
            "enroll_possession_sig": "aa",
            "device_possession_sig": hex::encode([0u8; 64])
        });
        assert!(EnrollmentPayload::from_json(&pl_json2).is_none());
    }

    // ── Finding 5: Canonical collision (length-prefix truncation) ──────

    #[test]
    fn canonical_bytes_uses_u32_prefixes() {
        // Verify that a cap longer than 255 bytes still gets a full u32 prefix
        let long_cap = vec!["x".repeat(500)];
        let short_cap = vec![] as Vec<String>;
        let b1 = {
            let ak = AuthKey {
                issuer: [0u8; 32], enroll_pub: [0u8; 32],
                caps: long_cap, audience: vec![],
                expires: 0, reuse: Reuse::Once, ephemeral: true,
                max_offline: 0, tag: String::new(), sig: [0u8; 64], version: 1,
            };
            auth_key_canonical_bytes(&ak)
        };
        let b2 = {
            let ak = AuthKey {
                issuer: [0u8; 32], enroll_pub: [0u8; 32],
                caps: short_cap, audience: vec![],
                expires: 0, reuse: Reuse::Once, ephemeral: true,
                max_offline: 0, tag: String::new(), sig: [0u8; 64], version: 1,
            };
            auth_key_canonical_bytes(&ak)
        };
        assert_ne!(b1, b2, "different caps must not collide canonical bytes");
    }

    #[test]
    fn max_cap_len_rejected_at_mint() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        // Cap exceeding MAX_CAP_LEN (65535)
        let mega_cap = "x".repeat(MAX_CAP_LEN + 1);
        assert!(AuthKey::mint(&owner, enroll_pub, vec![mega_cap], vec![], 3600, Reuse::Once, "test".into()).is_err());
        // Tag exceeding MAX_CAP_LEN
        let mega_tag = "y".repeat(MAX_CAP_LEN + 1);
        assert!(AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, mega_tag).is_err());
    }

    #[test]
    fn canonical_bytes_caps_count_prefix_prevents_boundary_forgery() {
        // Key A: caps=["shell"], audience=[]
        // Key B: caps=[], audience=[0..repeat "shell" bytes]
        // Without a caps count prefix, the bare sequence (len,"shell") from A's caps
        // could collide with B's audience data. With count prefix they MUST differ.
        let a = {
            let ak = AuthKey {
                issuer: [1u8; 32], enroll_pub: [0u8; 32],
                caps: vec!["shell".into()],
                audience: vec![],
                expires: 0, reuse: Reuse::Once, ephemeral: true,
                max_offline: 0, tag: String::new(), sig: [0u8; 64], version: 1,
            };
            auth_key_canonical_bytes(&ak)
        };
        // Construct an audience whose raw bytes mirror "shell" but embedded
        // in the audience loop (no length prefix per entry — audience entries are 32B keys)
        // We need a 32-byte key; there's no direct way to match "shell".
        // Instead: generic property — changing caps count changes bytes.
        let b_empty_caps = {
            let ak = AuthKey {
                issuer: [1u8; 32], enroll_pub: [0u8; 32],
                caps: vec![],
                audience: vec![],
                expires: 0, reuse: Reuse::Once, ephemeral: true,
                max_offline: 0, tag: String::new(), sig: [0u8; 64], version: 1,
            };
            auth_key_canonical_bytes(&ak)
        };
        // caps count differs (1 vs 0) → bytes MUST differ
        assert_ne!(a, b_empty_caps, "caps count prefix must make canonical bytes differ");
    }

    #[test]
    fn reuse_n_count_committed_to_signature() {
        // N(1) and N(999) must produce different canonical bytes → different sigs.
        // Mint two keys that differ ONLY in reuse count; verify sigs differ.
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();

        // Use explicit construction to set reuse directly (not through mint which uses wall clock)
        let make = |n: u32| -> AuthKey {
            let now = now_secs();
            let mut ak = AuthKey {
                issuer: owner.public_key().as_ref().try_into().unwrap(),
                enroll_pub,
                caps: vec!["shell".into()],
                audience: vec![],
                expires: now + 3600,
                reuse: Reuse::N(n),
                ephemeral: true,
                max_offline: 0,
                tag: "test".into(),
                sig: [0u8; 64],
                version: 1,
            };
            let canonical = auth_key_canonical_bytes(&ak);
            let sig = owner.sign(&canonical);
            ak.sig = sig.as_ref().try_into().unwrap();
            ak
        };

        let ak1 = make(1);
        let ak3 = make(3);

        // Canonical bytes MUST differ (different reuse count)
        assert_ne!(
            auth_key_canonical_bytes(&ak1),
            auth_key_canonical_bytes(&ak3),
            "N(1) and N(3) must not share canonical bytes"
        );

        // Sigs MUST differ (signature commits to count)
        assert_ne!(ak1.sig, ak3.sig, "N(1) sig must not verify N(3)");
    }

    #[test]
    fn caps_not_normalized_rejected_by_verify_against_owner() {
        // Cheap hardening: verify_against_owner rejects when caps != normalize_caps(&self.caps)
        // Construct an AuthKey with non-normalized caps (not sorted, uppercase)
        let ak = AuthKey {
            issuer: [0u8; 32], enroll_pub: [0u8; 32],
            caps: vec!["SHELL".into(), "transfer".into()],
            audience: vec![],
            expires: now_secs() + 3600,
            reuse: Reuse::Once, ephemeral: true,
            max_offline: 0,
            tag: "test".into(), sig: [0u8; 64],
            version: 1,
        };
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let err = ak.verify_against_owner(&[0u8; 32], &verifier_pub).unwrap_err().to_string();
        assert!(err.contains("not normalized"), "non-normalized caps must be rejected");
    }

    // ── Finding 6: Audience ─────────────────────────────────────────────

    #[test]
    fn audience_enforced_by_verify_against_owner() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let named_peer = [0xAA; 32];
        let other_peer = [0xBB; 32];
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![named_peer], 3600, Reuse::Once, "test".into()).unwrap();
        let op = owner_pub(&owner);
        assert!(ak.verify_against_owner(&op, &named_peer).is_ok());
        assert!(ak.verify_against_owner(&op, &other_peer).is_err(),
            "audience-bound key must be rejected at unauthorized peer");
    }

    #[test]
    fn audience_checked_before_sig() {
        // Audience rejection should happen before signature verification.
        // Even with invalid sig, audience mismatch should produce "not authorized for this peer".
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let named_peer = [0xAA; 32];
        let other_peer = [0xBB; 32];
        let mut ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![named_peer], 3600, Reuse::Once, "test".into()).unwrap();
        // Corrupt sig so we can tell which check fired first
        ak.sig = [0u8; 64];
        let op = owner_pub(&owner);
        let err = ak.verify_against_owner(&op, &other_peer).unwrap_err().to_string();
        assert!(err.contains("not authorized for this peer"),
            "audience rejection must come before sig error: got '{err}'");
    }

    // ── General tests ──────────────────────────────────────────────────

    #[test]
    fn auth_key_mint_verify_roundtrip() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into(), "transfer".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let op = owner_pub(&owner);
        assert!(ak.verify_against_owner(&op, &verifier_pub).is_ok());
    }

    #[test]
    fn auth_key_expired_fails() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let mut ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        ak.expires = 0;
        let op = owner_pub(&owner);
        assert!(ak.verify_against_owner(&op, &verifier_pub).is_err());
    }

    #[test]
    fn auth_key_wrong_owner_fails() {
        let owner = gen_keypair();
        let other = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let other_pub = owner_pub(&other);
        assert!(ak.verify_against_owner(&other_pub, &verifier_pub).is_err());
    }

    #[test]
    fn auth_key_caps_normalized_at_mint() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["TRANSFER".into(), "shell".into(), "TRANSFER".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        assert_eq!(ak.caps, vec!["shell", "transfer"]);
    }

    #[test]
    fn auth_key_ttl_capped() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let now = now_secs();
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 90 * 24 * 3600, Reuse::Once, "test".into()).unwrap();
        assert!(ak.expires <= now + MAX_TTL_SECS);
    }

    #[test]
    fn audience_allows_empty_is_any() {
        let ak = AuthKey {
            issuer: [0u8; 32], enroll_pub: [0u8; 32], caps: vec![], audience: vec![],
            expires: now_secs() + 3600, reuse: Reuse::Once, ephemeral: true,
            max_offline: 0,
            tag: "test".into(), sig: [0u8; 64],
            version: 1,
        };
        assert!(ak.audience_allows(&[1u8; 32]));
    }

    #[test]
    fn audience_allows_named_peer() {
        let peer = [0xAA; 32];
        let ak = AuthKey {
            issuer: [0u8; 32], enroll_pub: [0u8; 32], caps: vec![], audience: vec![peer],
            expires: now_secs() + 3600, reuse: Reuse::Once, ephemeral: true,
            max_offline: 0,
            tag: "test".into(), sig: [0u8; 64],
            version: 1,
        };
        assert!(ak.audience_allows(&peer));
        assert!(!ak.audience_allows(&[0xBB; 32]));
    }

    #[test]
    fn enrollment_payload_roundtrip() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(EnrollmentPrincipal::Legacy(ak), device_pub, &enroll_kp, &device_kp, nonce, verifier_pub);
        let op = owner_pub(&owner);
        let (ep, dp, _ak) = payload.verify(&op, &nonce, &verifier_pub).unwrap();
        assert_eq!(ep, enroll_pub);
        assert_eq!(dp, device_pub);
    }

    #[test]
    fn enrollment_wrong_enroll_key_fails() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let wrong_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(EnrollmentPrincipal::Legacy(ak), device_pub, &wrong_kp, &device_kp, nonce, verifier_pub);
        let op = owner_pub(&owner);
        assert!(payload.verify(&op, &nonce, &verifier_pub).is_err());
    }

    #[test]
    fn delegated_effective_intersection() {
        let owner = vec!["shell".into(), "transfer".into(), "mount".into()];
        let ak_caps = vec!["shell".into(), "deploy".into()];
        assert_eq!(delegated_effective_caps(&owner, &ak_caps), vec!["shell"]);
    }

    #[test]
    fn delegated_never_above_auth_key() {
        let owner = vec!["shell".into(), "transfer".into(), "mount".into()];
        let ak_caps = vec!["shell".into()];
        let eff = delegated_effective_caps(&owner, &ak_caps);
        assert!(eff.iter().all(|c| ak_caps.contains(c)));
    }

    #[test]
    fn delegated_never_above_owner() {
        let owner = vec!["shell".into()];
        let ak_caps = vec!["shell".into(), "transfer".into()];
        let eff = delegated_effective_caps(&owner, &ak_caps);
        assert!(eff.iter().all(|c| owner.contains(c)));
    }

    #[test]
    fn delegated_mixed_case_owner() {
        let owner = vec!["Shell".into(), "TRANSFER".into()];
        let ak_caps = vec!["shell".into()];
        assert_eq!(delegated_effective_caps(&owner, &ak_caps), vec!["shell"]);
    }

    #[test]
    fn auth_key_json_roundtrip() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into(), "transfer".into()], vec![[0xAA; 32]], 3600, Reuse::N(5), "ci".into()).unwrap();
        let json = ak.to_json();
        let round = AuthKey::from_json(&json).unwrap();
        assert_eq!(ak.issuer, round.issuer);
        assert_eq!(ak.enroll_pub, round.enroll_pub);
        assert_eq!(ak.caps, round.caps);
        assert_eq!(ak.audience, round.audience);
        assert_eq!(ak.expires, round.expires);
        assert_eq!(ak.reuse, round.reuse);
        assert_eq!(ak.ephemeral, round.ephemeral);
        assert_eq!(ak.max_offline, round.max_offline);
        assert_eq!(ak.tag, round.tag);
        assert_eq!(ak.sig, round.sig);
        // A freshly minted v2 key must verify against its own signature.
        assert!(round.verify_sig_and_expiry().is_ok());
    }

    #[test]
    fn max_offline_ceiling_signed_and_roundtrips() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint_with_bounds(&owner, enroll_pub, vec!["transfer".into()], vec![], 3600, Reuse::Once, "join".into(), 3 * 86400, false).unwrap();
        assert_eq!(ak.max_offline, 3 * 86400);
        assert!(!ak.ephemeral);
        let round = AuthKey::from_json(&ak.to_json()).unwrap();
        assert_eq!(round.max_offline, 3 * 86400);
        assert!(!round.ephemeral);
        // The ceiling is committed to the signature: flipping it must break verify.
        let mut forged = ak.clone();
        forged.max_offline = 10 * 86400;
        assert!(forged.verify_sig_and_expiry().is_err(), "tampered max_offline must fail signature");
        // Local tightening never exceeds the signed ceiling.
        assert_eq!(ak.max_offline.min(7 * 86400), 3 * 86400, "min(ceiling, tighter policy) must stay at the ceiling when tighter is larger");
        assert_eq!(ak.max_offline.min(1 * 86400), 1 * 86400, "a tighter policy may lower the budget");
    }

    #[test]
    fn legacy_v1_key_without_max_offline_still_verifies() {
        // A key signed over the v1 canonical bytes (no max_offline) must parse,
        // verify against the v1 canonical, and default its ceiling to the 30d cap.
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let now = now_secs();
        let mut k = AuthKey {
            issuer: owner.public_key().as_ref().try_into().unwrap(),
            enroll_pub,
            caps: vec!["transfer".into()],
            audience: vec![],
            expires: now + 3600,
            reuse: Reuse::Once,
            ephemeral: true,
            max_offline: MAX_TTL_SECS,
            tag: "old".into(),
            sig: [0u8; 64],
            version: 1,
        };
        let canonical = auth_key_canonical_bytes(&k);
        k.sig = owner.sign(&canonical).as_ref().try_into().unwrap();
        let json = k.to_json();
        assert!(json.get("max_offline").is_none(), "v1 keys serialize without max_offline");
        let legacy = AuthKey::from_json(&json).expect("legacy key without max_offline must parse");
        assert_eq!(legacy.max_offline, MAX_TTL_SECS, "legacy key defaults its ceiling to the 30d cap");
        assert!(legacy.verify_sig_and_expiry().is_ok(), "legacy v1 key must verify against v1 canonical bytes");
    }

    #[test]
    fn enroll_channel_deterministic() {
        let owner = [0xAA; 32];
        let c1 = enroll_channel(&owner);
        let c2 = enroll_channel(&owner);
        assert_eq!(c1, c2, "enroll_channel must be deterministic");
        assert_eq!(c1.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn enrollment_payload_json_roundtrip() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        // Round-trips the SURVIVING shape. It used to build a Legacy principal,
        // and from_json now refuses that: nothing produces it since `ephemeral
        // mint` was collapsed into `add --for runner`, and an enrolment parser
        // that still accepted it was a second way to become a principal.
        let _ = enroll_pub;
        let inv = mint_v2(&owner);
        let payload = EnrollmentPayload::build(EnrollmentPrincipal::Compact(inv), device_pub, &enroll_kp, &device_kp, nonce, verifier_pub);
        let json = payload.to_json();
        let round = EnrollmentPayload::from_json(&json)
            .expect("the one accepted shape must round-trip through JSON");
        assert_eq!(payload.device_pub, round.device_pub);
        assert_eq!(payload.enroll_possession_sig, round.enroll_possession_sig);
        assert_eq!(payload.device_possession_sig, round.device_possession_sig);
    }
}


#[cfg(test)]
mod invitation_ceiling_codec_tests {
    use super::*;

    /// Every capability that can be GRANTED must survive a trip through the v2
    /// invitation bitmask, because a grant may never widen a ceiling: a
    /// capability missing from this codec can never legitimately reach a joined
    /// device at all. `route` was absent, and because the encoder fell back to
    /// an empty mask instead of failing, the whole ceiling silently vanished.
    #[test]
    fn every_canonical_capability_survives_the_invitation_bitmask() {
        for cap in crate::capability::CANONICAL_CAPABILITIES {
            let mask = inv_caps_to_bitmask(std::slice::from_ref(&cap.to_string()))
                .unwrap_or_else(|e| panic!("'{cap}' cannot be encoded in an invitation: {e}"));
            assert_ne!(mask, 0, "'{cap}' encoded to an EMPTY ceiling");
            assert_eq!(
                inv_caps_from_bitmask(mask),
                vec![cap.to_string()],
                "'{cap}' did not survive the bitmask round trip"
            );
        }
    }

    /// A multi-capability ceiling must not lose members.
    #[test]
    fn a_mixed_ceiling_round_trips_without_loss() {
        let ceiling: Vec<String> =
            ["transfer", "mount", "route"].iter().map(|s| s.to_string()).collect();
        let mask = inv_caps_to_bitmask(&ceiling).expect("encodable");
        let mut back = inv_caps_from_bitmask(mask);
        back.sort();
        let mut want = ceiling.clone();
        want.sort();
        assert_eq!(back, want);
    }

    /// An unencodable capability must be a LOUD failure at mint, never a
    /// quietly-empty ceiling on a signed artifact.
    #[test]
    fn an_unencodable_capability_is_refused_not_silently_dropped() {
        let err = inv_caps_to_bitmask(&["not-a-real-capability".to_string()]);
        assert!(err.is_err(), "an unknown capability must not encode to a mask");
    }
}

#[cfg(test)]
mod route_ceiling_tests {
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};

    fn owner() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }
    fn seed() -> [u8; 32] {
        let rng = SystemRandom::new();
        let mut s = [0u8; 32];
        rng.fill(&mut s).unwrap();
        s
    }
    fn mint(caps: Vec<String>, routes: Vec<String>) -> Result<Invitation> {
        Invitation::mint(
            &owner(), seed(), caps, 1_800_000_000, 86400,
            Reuse::Once, false, "alice".into(), routes,
        )
    }

    /// The whole point: a ceiling that cannot say WHICH prefix is not a scope,
    /// and previously authorised every prefix a member chose, 0.0.0.0/0 included.
    #[test]
    fn a_route_ceiling_without_prefixes_is_refused_at_mint() {
        let err = match mint(vec!["route".into()], vec![]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an unscoped route ceiling must not mint"),
        };
        assert!(err.contains("must name the prefixes"), "got: {err}");
    }

    #[test]
    fn prefixes_without_the_capability_are_refused() {
        assert!(matches!(mint(vec!["transfer".into()], vec!["10.0.0.0/8".into()]), Err(_)));
    }

    /// The prefixes must survive the round trip, or the scope is decorative.
    #[test]
    fn prefixes_survive_the_token_and_payload_round_trip() {
        let inv = mint(vec!["route".into()], vec!["10.66.0.0/24".into(), "192.168.0.0/16".into()])
            .unwrap();
        let back = Invitation::from_token(&inv.to_token()).expect("token parses");
        assert_eq!(back.routes, inv.routes);
        let payload = Invitation::from_payload(&inv.to_payload()).expect("payload parses");
        assert_eq!(payload.routes, inv.routes);
    }

    /// Host bits must not create two different signed ceilings for one network.
    #[test]
    fn prefixes_are_normalised_before_signing() {
        let inv = mint(vec!["route".into()], vec!["10.66.0.5/24".into()]).unwrap();
        assert_eq!(inv.routes, vec!["10.66.0.0/24".to_string()]);
    }

    /// The prefixes are inside the SIGNED domain: widening them must invalidate
    /// the signature, or a member could grant itself an exit node.
    #[test]
    fn widening_the_prefixes_breaks_the_signature() {
        let o = owner();
        let owner_pub: [u8; 32] = o.public_key().as_ref().try_into().unwrap();
        let inv = Invitation::mint(
            &o, seed(), vec!["route".into()], 1_800_000_000, 86400,
            Reuse::Once, false, "alice".into(), vec!["10.66.0.0/24".into()],
        )
        .unwrap();
        assert!(inv.verify_against_owner(&owner_pub), "honest invitation verifies");

        let mut tampered = inv.clone();
        tampered.routes = vec!["0.0.0.0/0".to_string()];
        assert!(
            !tampered.verify_against_owner(&owner_pub),
            "a member must not be able to widen its own ceiling to a default route"
        );
    }

    /// to_auth_key is the one conversion into everything downstream, so the
    /// scope has to survive it or enforcement sees a bare `route` again.
    #[test]
    fn the_auth_key_carries_the_scope_not_a_bare_route() {
        let o = owner();
        let owner_pub: [u8; 32] = o.public_key().as_ref().try_into().unwrap();
        let inv = Invitation::mint(
            &o, seed(), vec!["route".into()], 1_800_000_000, 86400,
            Reuse::Once, false, "alice".into(), vec!["10.66.0.0/24".into()],
        )
        .unwrap();
        let ak = inv.to_auth_key(&owner_pub);
        assert!(ak.caps.contains(&"route:10.66.0.0/24".to_string()), "caps: {:?}", ak.caps);
        assert!(!ak.caps.contains(&"route".to_string()), "a bare route would be unscoped");
    }
}
