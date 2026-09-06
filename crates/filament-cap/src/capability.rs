//! Capability/grant layer: two owner-signed objects + monotonic store.
//!
//! CapOp: an owner-signed grant/revoke/modify.  CapHeader: the owner-signed
//! resource header (self-certifying resource id, hash-chained succession,
//! fork detection).  Ownership is derived from the header, never a grant.
//!
//! This module is the PURE, host-independent half of the capability layer:
//! the signed objects, the single authorization fn (`evaluate`), the monotonic
//! store-mutation logic, the restrictive composers, preview/self-lockout, and
//! the crypto primitives. The host-bound orchestration (store file I/O, the env
//! mode flag `cap_authoritative`, the observability counters, and the glue gates
//! `cap_authorize` / `cap_gate_effective`) lives in the CLI and calls into this
//! module; nothing here calls back, so there is no cycle.
//!
//! ## LIMIT — WireGuard / serve-tun mesh (accepted posture)
//!
//! The WG mesh is a COARSER trust tier. Mesh-join (filament serve-tun) grants
//! L3 IP reach to raw TCP services bound on the overlay address (SSH, exposed
//! ports). These services are NOT constrained by L2 capability gates (l2-open,
//! mount-open, pty-open) because the WG data path is L3 IP, not L2 control-plane
//! streams over QUIC/WebRTC.
//!
//! Everything reachable by WG peers with ONLY L3 IP: SSH daemon on overlay
//! address, any port exposed via `filament expose`. Everything else (forward,
//! netcat, proxy, file transfer, mount, PTY) requires an L2 control channel
//! that a WG-only peer lacks.
//!
//! Mesh-join is therefore a weighty grant at the transport layer. A peer
//! with WG access can reach SSH and exposed ports regardless of capability
//! grants. This is the stated boundary — the WG PSK IS the authorization
//! for SSH and exposed-port reach on the overlay.
use anyhow::{anyhow, bail, Result};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde_json::Value;

/// The only capability names understood by the enforcement layer.
///
/// Keep this list in the capability crate so command and UX layers cannot
/// silently grow names that the gates do not enforce.
pub const CAP_SHELL: &str = "shell";
pub const CAP_TRANSFER: &str = "transfer";
pub const CAP_MOUNT: &str = "mount";
/// Advertise a subnet route. Unlike the others this is meaningless without its
/// RESOURCE: `route` alone authorizes nothing, because the whole question is
/// *which prefix*. See `route_resource_id`.
pub const CAP_ROUTE: &str = "route";

/// The wire reason a live session is closed with when the peer's certificate is
/// revoked mid-session (#235/#235-shape). The initiator keys its remedy on this
/// exact string, so it must be one shared value, never a substring sniff.
pub const REVOKED_REASON: &str = "access revoked";

pub const CANONICAL_CAPABILITIES: &[&str] = &[CAP_SHELL, CAP_TRANSFER, CAP_MOUNT, CAP_ROUTE];

/// Scoped-default actions classified by the fleet gate.
pub const SCOPED_DEFAULT_ACTIONS: &[&str] = &[CAP_TRANSFER, CAP_MOUNT];

// Known residual: gate action parameters remain `&str`, so a future call site
// can still pass an unregistered literal. A typed Action newtype is a follow-up
// hardening task; current predicates and tests cover the declared vocabulary.

/// Split a grant spec into (action, resource) for the cap store.
///
/// `shell` -> ("shell", "self"): the capability acts on the owner's own machine,
/// which is the only resource those verbs have ever had.
///
/// `route:10.0.0.0/24` -> ("route", <owner-bound resource id>): the prefix IS the
/// resource, so the capability name alone cannot express the grant. Carried in
/// the capability argument rather than behind a new flag, so the whole grant is
/// one token and `grant <device> route:10.0.0.0/24` reads as one thing.
///
/// Refuses a route with no prefix, and a non-route with one. Both are the same
/// mistake in opposite directions: a resource that does not match the action's
/// arity, which would otherwise store a grant that can never be matched at
/// enforcement time and so silently authorize nothing.
pub struct GrantSpec {
    pub action: String,
    pub resource: String,
    /// The nonce the resource id was derived from. Returned rather than
    /// recomputed by the caller: the genesis header must be filed under the same
    /// (owner_pub, nonce) the id came from, and a second parse in a second place
    /// is how two implementations of one rule drift apart.
    pub nonce: [u8; 32],
}

pub fn parse_grant_spec(spec: &str, owner_pub: &[u8; 32]) -> Result<GrantSpec> {
    let (name, rest) = match spec.split_once(':') {
        Some((n, r)) => (n, Some(r)),
        None => (spec, None),
    };
    let action = canonical_capability(name)?;
    if action == CAP_ROUTE {
        let Some(cidr) = rest.map(str::trim).filter(|c| !c.is_empty()) else {
            anyhow::bail!(
                "'route' authorizes a specific prefix, so it needs one: try 'route:10.0.0.0/24'"
            );
        };
        let normalized = normalize_cidr(cidr)?;
        let nonce = route_resource_nonce(&normalized);
        Ok(GrantSpec {
            action,
            resource: make_resource_id(owner_pub, &nonce),
            nonce,
        })
    } else {
        if rest.is_some() {
            anyhow::bail!("'{action}' applies to the device itself and takes no ':' resource");
        }
        Ok(GrantSpec {
            action,
            resource: "self".to_string(),
            nonce: self_resource_nonce(),
        })
    }
}

/// Normalize and validate a capability name at an API boundary.
pub fn canonical_capability(name: &str) -> Result<String> {
    let normalized = name.trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "send" | "inbox") {
        bail!("capability '{normalized}' is not currently grantable; use 'transfer', which covers both directions")
    }
    if CANONICAL_CAPABILITIES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        bail!("unknown capability '{name}' (valid: {})", CANONICAL_CAPABILITIES.join(", "))
    }
}

/// Hybrid logical clock: version = max(wall_clock_ms, last_seen + 1).
pub fn hlc_next(last_seen: u64, now_ms: u64) -> u64 {
    std::cmp::max(now_ms, last_seen.saturating_add(1))
}

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Maximum clock skew for ratchet far-future clamp (seconds).
pub const MAX_SKEW_SECS: u64 = 300;

/// Domain constant for the deterministic "self" resource nonce.
/// Survives cold-key restore: the key survives, so the resource id does too.
pub const SELF_RESOURCE_DOMAIN: &[u8] = b"filament-self-resource-v1";

pub fn self_resource_nonce() -> [u8; 32] {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SELF_RESOURCE_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn self_resource_id(owner_pub: &[u8; 32]) -> String {
    make_resource_id(owner_pub, &self_resource_nonce())
}

/// Domain constant for route-resource nonces. Separate from SELF so a route id
/// can never collide with the self id, and so the two namespaces can evolve
/// independently.
pub const ROUTE_RESOURCE_DOMAIN: &[u8] = b"filament-route-resource-v1";

/// Deterministic nonce for a CIDR, so the same prefix always names the same
/// resource. Deterministic rather than random because a grant made today must
/// still match the advertisement that arrives tomorrow, on a device that never
/// saw the grant being minted.
fn route_resource_nonce(normalized_cidr: &str) -> [u8; 32] {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ROUTE_RESOURCE_DOMAIN);
    h.update(normalized_cidr.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Canonical text for a CIDR, so one prefix has exactly one resource id.
///
/// NOT a caller convention, because a caller that forgets is an authorization
/// bypass rather than a cosmetic slip: `10.0.0.0/24 ` with a trailing space, or
/// `10.0.0.5/24` with host bits set, would otherwise hash to a DIFFERENT
/// resource than the one the owner granted, and the grant would silently not
/// apply. Host bits are masked off, text is trimmed, v6 is lowercased by
/// `Ipv6Addr`'s own Display.

/// Is `candidate` contained within any of `allowed`?
///
/// CONTAINMENT, not equality, and the direction matters more than anything else
/// in this file. A ceiling of `10.0.0.0/8` permits advertising `10.66.0.0/24`,
/// because the narrower prefix carries strictly less traffic. The reverse must
/// be refused: a ceiling of `10.66.0.0/24` must NOT permit `10.0.0.0/8`, and a
/// ceiling of anything must not permit `0.0.0.0/0`. Getting that backwards would
/// let a member widen its own grant into an exit node, which is the exact hole
/// this scoping exists to close.
///
/// Family-crossing never matches: a v4 ceiling cannot authorise a v6 prefix.
pub fn cidr_within_any(candidate: &str, allowed: &[String]) -> bool {
    let Some((c_net, c_len)) = parse_cidr(candidate) else { return false };
    allowed.iter().any(|a| {
        let Some((a_net, a_len)) = parse_cidr(a) else { return false };
        // The candidate must be at least as SPECIFIC as the allowance, and sit
        // inside it. `c_len >= a_len` is what refuses widening.
        c_len >= a_len && same_family(&c_net, &a_net) && masked_eq(&c_net, &a_net, a_len)
    })
}

fn parse_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let (net, len) = s.trim().split_once('/')?;
    let net: std::net::IpAddr = net.trim().parse().ok()?;
    let len: u8 = len.trim().parse().ok()?;
    let max = if net.is_ipv4() { 32 } else { 128 };
    if len > max { return None; }
    Some((net, len))
}

fn same_family(a: &std::net::IpAddr, b: &std::net::IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}

/// Compare the first `len` bits of two addresses of the same family.
fn masked_eq(a: &std::net::IpAddr, b: &std::net::IpAddr, len: u8) -> bool {
    // A zero-length prefix matches everything in its family, and shifting by the
    // full width is undefined, so it is handled before any shift happens.
    if len == 0 {
        return true;
    }
    match (a, b) {
        (std::net::IpAddr::V4(x), std::net::IpAddr::V4(y)) => {
            let mask = u32::MAX << (32 - len);
            (u32::from(*x) & mask) == (u32::from(*y) & mask)
        }
        (std::net::IpAddr::V6(x), std::net::IpAddr::V6(y)) => {
            let mask = u128::MAX << (128 - len);
            (u128::from(*x) & mask) == (u128::from(*y) & mask)
        }
        _ => false,
    }
}

pub fn normalize_cidr(cidr: &str) -> Result<String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let t = cidr.trim();
    let (addr, len) = t
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("'{t}' is not a CIDR: expected ADDRESS/LENGTH"))?;
    let len: u8 = len
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("'{t}': prefix length is not a number"))?;
    let ip: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("'{t}': '{addr}' is not an IP address"))?;
    match ip {
        IpAddr::V4(a) => {
            if len > 32 {
                anyhow::bail!("'{t}': /{len} is not valid for IPv4 (max 32)");
            }
            let bits = u32::from(a);
            let masked = if len == 0 { 0 } else { bits & (u32::MAX << (32 - len)) };
            Ok(format!("{}/{len}", Ipv4Addr::from(masked)))
        }
        IpAddr::V6(a) => {
            if len > 128 {
                anyhow::bail!("'{t}': /{len} is not valid for IPv6 (max 128)");
            }
            let bits = u128::from(a);
            let masked = if len == 0 { 0 } else { bits & (u128::MAX << (128 - len)) };
            Ok(format!("{}/{len}", Ipv6Addr::from(masked)))
        }
    }
}

/// Resource id for "the owner's authority over this prefix".
///
/// THE POINT: an overlay address is self-certifying because it derives from the
/// peer's key, so an announce proves it. A prefix derives from nothing, so
/// advertising one is an unbacked claim. Binding the prefix to the OWNER's key
/// here is what makes it checkable: the grant says the owner designated this
/// device to carry this prefix, and `CapOp::verify` already refuses any op whose
/// grantor is not the resource owner.
pub fn route_resource_id(owner_pub: &[u8; 32], cidr: &str) -> Result<String> {
    let normalized = normalize_cidr(cidr)?;
    Ok(make_resource_id(owner_pub, &route_resource_nonce(&normalized)))
}

/// Self-certifying resource id: hex(SHA-256(owner_pub || nonce)).
/// Only a genesis whose owner_pub+nonce hash to this id is accepted.
pub fn make_resource_id(owner_pub: &[u8; 32], nonce: &[u8; 32]) -> String {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(owner_pub);
    h.update(nonce);
    hex::encode(h.finalize())
}

/// Hash a header for chain linking: SHA-256(canonical_for_signing).
pub fn hash_header(header: &CapHeader) -> [u8; 32] {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&header.canonical_for_signing());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// ---------------------------------------------------------------------------
// CapOp  (domain b"filament/capability-op/v1")
// ---------------------------------------------------------------------------

const CAPOP_SIGN_DOMAIN: &[u8] = b"filament/capability-op/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOpKind {
    Grant = 0x00,
    Revoke = 0x01,
    Modify = 0x02,
}

impl CapOpKind {
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(CapOpKind::Grant),
            0x01 => Some(CapOpKind::Revoke),
            0x02 => Some(CapOpKind::Modify),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapTarget {
    User([u8; 32]),
    Device([u8; 32]),
    /// SHA-256(owner_pub || tag_id) — scoped to owner. 0x02 (Group) is reserved.
    Tag([u8; 32]),
}

impl CapTarget {
    pub fn kind_byte(&self) -> u8 {
        match self {
            CapTarget::User(_) => 0x00,
            CapTarget::Device(_) => 0x01,
            CapTarget::Tag(_) => 0x03,
        }
    }

    pub fn target_bytes(&self) -> [u8; 32] {
        match self {
            CapTarget::User(b) | CapTarget::Device(b) | CapTarget::Tag(b) => *b,
        }
    }

    #[allow(dead_code)]
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(33);
        v.push(self.kind_byte());
        v.extend_from_slice(&self.target_bytes());
        v
    }
}

/// 0x02 (Group) is reserved for future use.
/// SHA-256(owner_pub || tag_id) → 32-byte tag target.
pub fn make_tag_target(owner_pub: &[u8; 32], tag_id: &str) -> [u8; 32] {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(owner_pub);
    h.update(tag_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[derive(Debug, Clone)]
pub struct CapOp {
    pub op: CapOpKind,
    pub grantor: [u8; 32],
    pub target_kind: u8,
    pub target: [u8; 32],
    pub resource: String,
    pub permissions: Vec<String>,
    pub expires: u64,
    pub issued_at: u64,
    pub version: u64,
    pub sig: [u8; 64],
}

impl CapOp {
    fn lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
        buf.extend_from_slice(field);
    }

    pub fn canonical_for_signing(&self) -> Vec<u8> {
        let mut perms_blob = Vec::new();
        perms_blob.extend_from_slice(&(self.permissions.len() as u32).to_le_bytes());
        for p in &self.permissions {
            Self::lp(&mut perms_blob, p.as_bytes());
        }

        let mut target_blob = Vec::with_capacity(33);
        target_blob.push(self.target_kind);
        target_blob.extend_from_slice(&self.target);

        let mut v = Vec::new();
        v.extend_from_slice(CAPOP_SIGN_DOMAIN);
        Self::lp(&mut v, &[self.op.to_byte()]);
        Self::lp(&mut v, &self.grantor);
        Self::lp(&mut v, &target_blob);
        Self::lp(&mut v, self.resource.as_bytes());
        Self::lp(&mut v, &perms_blob);
        Self::lp(&mut v, &self.expires.to_le_bytes());
        Self::lp(&mut v, &self.issued_at.to_le_bytes());
        Self::lp(&mut v, &self.version.to_le_bytes());
        v
    }

    pub fn verify(&self, owner_pub: &[u8; 32], now: u64) -> Result<()> {
        if self.grantor != *owner_pub {
            bail!("capability op grantor != resource owner");
        }
        if now >= self.expires {
            bail!("capability op expired");
        }
        let canonical = self.canonical_for_signing();
        let peer_pub = UnparsedPublicKey::new(&ED25519, &self.grantor);
        peer_pub
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("capability op signature invalid"))
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "op": self.op.to_byte(),
            "grantor": hex::encode(self.grantor),
            "targetKind": self.target_kind,
            "target": hex::encode(self.target),
            "resource": self.resource,
            "permissions": self.permissions,
            "expires": self.expires,
            "issued_at": self.issued_at,
            "version": self.version,
            "sig": hex::encode(self.sig),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let op_byte = v["op"].as_u64()? as u8;
        let op = CapOpKind::from_byte(op_byte)?;
        let grantor = {
            let b = hex::decode(v["grantor"].as_str()?).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        };
        let target = {
            let b = hex::decode(v["target"].as_str()?).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        };
        let target_kind = v["targetKind"].as_u64()? as u8;
        let sig = {
            let b = hex::decode(v["sig"].as_str()?).ok()?;
            if b.len() != 64 { return None; }
            let mut a = [0u8; 64]; a.copy_from_slice(&b); a
        };
        let perms: Vec<String> = v["permissions"]
            .as_array()?
            .iter()
            .map(|x| x.as_str().map(|s| s.to_string()))
            .collect::<Option<Vec<_>>>()?;
        Some(CapOp {
            op,
            grantor,
            target_kind,
            target,
            resource: v["resource"].as_str()?.to_string(),
            permissions: perms,
            expires: v["expires"].as_u64()?,
            issued_at: v["issued_at"].as_u64()?,
            version: v["version"].as_u64()?,
            sig,
        })
    }
}

pub fn sign_cap_op(op: &CapOp, keypair: &Ed25519KeyPair) -> [u8; 64] {
    let sig = keypair.sign(&op.canonical_for_signing());
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ---------------------------------------------------------------------------
// evaluate() -- the single pure authorization fn
// ---------------------------------------------------------------------------

/// The outcome of an authorization check.
pub enum Decision {
    Authorized,
    Denied(String),
}

/// The outcome of a capability query at a gate. Unlike `Decision`, it separates an
/// ABSENT header (the resource is UNPROVISIONED) from a header that EXISTS and
/// refused (`Denied`, a real disagreement). Absent means "provision this node";
/// denied means "the grants disagree". Conflating them floods the shadow log and
/// makes the flip criterion unsatisfiable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapOutcome {
    Authorized,
    Denied(String),
    Unprovisioned,
}

/// Single pure authorization fn. Both enforcement and preview call this, so
/// preview cannot diverge from enforcement.
///
/// Returns `Authorized` if:
/// - `principal_user_pub == header.owner_pub` (derived owner, always allowed)
/// - OR a non-expired grant exists where `grantor == header.owner_pub` and
///   target matches (Device→principal_device_pub, User→principal_user_pub)
///   and `action` is listed in permissions.
///
/// Expiry uses `eval_time = max(now, ratchet_for(header.owner_pub))`. If the
/// per-owner ratchet is uninitialized, grants are DENIED (fail-closed).

/// Resolve a Tag-targeted grant: find tag bindings, verify signatures,
/// check if any binding's subject matches the principal.
fn resolve_tag_match(
    store: &[Value],
    grantor: &[u8; 32],
    tag_hash: [u8; 32],
    principal_user_pub: &[u8; 32],
    principal_device_pub: &[u8; 32],
    eval_time: u64,
) -> bool {
    let bindings = find_tag_bindings(store, grantor, tag_hash);
    bindings.iter().any(|b| {
        grant_active(b.expires, eval_time)
            && ((b.subject_kind == 0x00 && &b.subject == principal_user_pub)
                || (b.subject_kind == 0x01 && &b.subject == principal_device_pub))
    })
}

/// The single expiry decision point shared by signed and legacy grants.
pub fn grant_active(expires: u64, now: u64) -> bool {
    now < expires
}

pub fn evaluate(
    store: &[Value],
    header: &CapHeader,
    principal_device_pub: &[u8; 32],
    principal_user_pub: &[u8; 32],
    resource: &str,
    action: &str,
    now: u64,
    auth_key_caps: Option<&[String]>,
) -> Decision {
    // === Delegated-principal ceiling (check 1 of 2) ===================
    // If auth_key_caps is present, the action must be within the auth key's
    // stated caps. Even if the principal is the owner (user_pub matches header
    // owner_pub), a delegated principal never inherits full owner rights — it
    // gets the intersection. This check runs BEFORE the owner shortcut below,
    // which is exactly what makes the delegated owner-shortcut safe.
    //
    // DEFENSE-IN-DEPTH — do NOT "tidy" this away as redundant. The SAME ceiling
    // is enforced a second time, independently, at the top of
    // `cap_gate_effective` in the CLI (cli/src/capability.rs). That second check
    // does NOT trust this one's result. Each check is sufficient on its own and
    // both are retained DELIBERATELY: after the crate split, each is invisible
    // from the other side of the boundary, and removing either re-opens the
    // delegated-owner escalation. See the mirror comment on cap_gate_effective.
    // (Shared with evaluate_grants_only via auth_key_ceiling_denied so the two
    // in-crate copies cannot diverge; the CLI copy stays independent by design.)
    if let Some(denied) = auth_key_ceiling_denied(action, auth_key_caps) {
        return denied;
    }

    // Owner is always authorized (derived, outside cap list)
    if principal_user_pub == &header.owner_pub {
        return Decision::Authorized;
    }

    // Lazy-loaded ratchet: None means uninitialized (fail-closed for grants)
    let ratchet = ratchet_for(store, &header.owner_pub);
    if ratchet.is_none() {
        return Decision::Denied("ratchet uninitialized".into());
    }
    let eval_time = std::cmp::max(now, ratchet.unwrap());

    if scan_grants_authorizes(
        store, header, principal_device_pub, principal_user_pub, resource, action, eval_time,
    ) {
        Decision::Authorized
    } else {
        Decision::Denied("not authorized".into())
    }
}

/// Scan explicit owner-signed grants (User/Device/Tag targets) for one that
/// authorizes `action` on `resource` for this principal at `eval_time`. This is
/// the grant-matching core WITHOUT the owner shortcut, shared by `evaluate` (which
/// applies the owner shortcut first) and `evaluate_grants_only` (which never does),
/// so the two can never diverge on how a grant is matched.
fn scan_grants_authorizes(
    store: &[Value],
    header: &CapHeader,
    principal_device_pub: &[u8; 32],
    principal_user_pub: &[u8; 32],
    resource: &str,
    action: &str,
    eval_time: u64,
) -> bool {
    for entry in store {
        if entry.get("type").and_then(|v| v.as_str()) != Some("cap_grant") {
            continue;
        }
        if entry["grantor"].as_str() != Some(hex::encode(header.owner_pub).as_str()) {
            continue;
        }
        if entry["resource"].as_str() != Some(resource) {
            continue;
        }

        let target_kind = entry["targetKind"].as_u64().unwrap_or(0) as u8;
        let target_matches = match target_kind {
            0x00 => {
                let t = hex::decode(entry["target"].as_str().unwrap_or("")).unwrap_or_default();
                t.len() == 32 && t.as_slice() == principal_user_pub
            }
            0x01 => {
                let t = hex::decode(entry["target"].as_str().unwrap_or("")).unwrap_or_default();
                t.len() == 32 && t.as_slice() == principal_device_pub
            }
            0x02 => continue, // reserved (Group) — 0x03 (Tag) is the active kind
            0x03 => {
                let t = hex::decode(entry["target"].as_str().unwrap_or("")).unwrap_or_default();
                if t.len() != 32 { false }
                else {
                    let mut hash = [0u8; 32]; hash.copy_from_slice(&t);
                    resolve_tag_match(store, &header.owner_pub, hash, principal_user_pub, principal_device_pub, eval_time)
                }
            }
            _ => continue,
        };
        if !target_matches {
            continue;
        }

        // Check expiry: on expired grant, continue scanning (it must not
        // shadow a second matching grant that is still valid)
        let expires = entry["expires"].as_u64().unwrap_or(0);
        if !grant_active(expires, eval_time) {
            continue;
        }

        // Check action is in permissions
        if let Some(perms) = entry["permissions"].as_array() {
            if perms.iter().any(|p| p.as_str() == Some(action)) {
                return true;
            }
        }
    }
    false
}

/// The delegated-principal ceiling, factored out so `evaluate` and
/// `evaluate_grants_only` cannot DIVERGE on it (they already share the grant match
/// via `scan_grants_authorizes`; this removes the last mirror between them). If
/// `auth_key_caps` is present, the action must be within the auth key's stated
/// caps — even the owner shortcut does not bypass it, which is what makes a
/// delegated owner-shortcut safe. Returns `Some(Denied)` when the ceiling refuses,
/// `None` when it passes or is not applicable.
///
/// DEFENSE-IN-DEPTH: a THIRD, deliberately INDEPENDENT copy of this ceiling lives
/// at `cap_gate_effective` in the CLI (across the crate boundary), which does not
/// trust this one's result — see the notes there. That copy is intentional
/// redundancy (it is the ONLY ceiling enforcement in shadow mode) and is NOT part
/// of this de-duplication.
fn auth_key_ceiling_denied(action: &str, auth_key_caps: Option<&[String]>) -> Option<Decision> {
    if let Some(caps) = auth_key_caps {
        let action_lc = action.to_lowercase();
        if !caps.iter().any(|c| c.to_lowercase() == action_lc) {
            return Some(Decision::Denied("not in auth key caps".into()));
        }
    }
    None
}

/// Gate-facing authorization that NEVER applies the owner shortcut. A remote peer
/// whose device cert merely chains to the owner user key (same `user_pub`) is a
/// FLEET MEMBER, not the local primary: it must not inherit blanket owner
/// authority just for sharing the user pubkey. Only an explicit owner-signed grant
/// (or fleet auto-trust, layered above this at the gate) authorizes. This is the
/// finding-#24 class fixed at the UX/gate layer.
///
/// For a principal that is NOT the owner, this is identical to `evaluate` (the
/// owner shortcut never fires there anyway); it differs only for a same-owner peer,
/// which is exactly the fleet case the gate must scope.
pub fn evaluate_grants_only(
    store: &[Value],
    header: &CapHeader,
    principal_device_pub: &[u8; 32],
    principal_user_pub: &[u8; 32],
    resource: &str,
    action: &str,
    now: u64,
    auth_key_caps: Option<&[String]>,
) -> Decision {
    // Delegated-principal ceiling — SHARED with evaluate via auth_key_ceiling_denied
    // (no longer a mirror; the two cannot diverge on it).
    if let Some(denied) = auth_key_ceiling_denied(action, auth_key_caps) {
        return denied;
    }
    let ratchet = ratchet_for(store, &header.owner_pub);
    if ratchet.is_none() {
        return Decision::Denied("ratchet uninitialized".into());
    }
    let eval_time = std::cmp::max(now, ratchet.unwrap());
    if scan_grants_authorizes(
        store, header, principal_device_pub, principal_user_pub, resource, action, eval_time,
    ) {
        Decision::Authorized
    } else {
        Decision::Denied("not authorized".into())
    }
}

/// The scoped-default action set a same-owner Proven fleet device may exercise
/// with NO explicit grant — each bounded to a scope the GATE enforces:
///   - `transfer` → into the designated inbox directory (not arbitrary paths)
///   - `mount`    → READ-ONLY, of the explicit share root (never home)
/// Deliberate-tier actions (`shell`, write-mount, reach-all-ports, mount of a
/// broader root) are NEVER in this set and always require an explicit grant.
/// (Note: the l2-open port-forward gate labels its cap action `shell`; the gate
/// there passes `scoped_in_bounds` computed from `expose.json` directly rather
/// than routing port reach through this classifier — see cap_gate_effective callers.)
pub fn is_scoped_default_action(action: &str) -> bool {
    SCOPED_DEFAULT_ACTIONS.contains(&action)
}

/// Deliberate capability classified by the grant-only gate.
pub fn is_deliberate_capability(action: &str) -> bool {
    // ROUTE IS DELIBERATE, NOT SCOPED-DEFAULT, and that is a security choice
    // rather than caution. A scoped default is auto-granted to any proven
    // same-owner device (`fleet_auto_trust`), which is right for transfer and
    // mount: those act on the OWNER'S OWN resources, and the blast radius is the
    // owner's own data.
    //
    // Advertising a route is not that shape. It is a claim about the world
    // ("traffic for 10.0.0.0/24 should come to me") that nothing in the peer's
    // key can substantiate, and believing it silently redirects other peers'
    // traffic. Auto-granting it would mean one compromised laptop in the fleet
    // can become the path to anything, which is the exact failure the
    // accept-routes default exists to prevent. Same tier as shell, for the same
    // reason: high blast radius, never implied by membership.
    action == CAP_SHELL || action == CAP_ROUTE
}

/// True when an action is classified by one of the capability gate predicates.
pub fn is_enforced_capability(action: &str) -> bool {
    is_scoped_default_action(action) || is_deliberate_capability(action)
}

/// Same-owner fleet auto-trust decision, PROVEN-GATED. Grants a scoped default to
/// a peer whose device cert chains to MY user key (`same_owner`) ONLY when the
/// link binding proves device-key possession (`Proven`, never `Inferred`/`None`)
/// AND the action is within its bounded scope (`scoped_in_bounds`, computed at the
/// gate). It NEVER authorizes the deliberate tier (callers pass
/// `scoped_in_bounds = false` there) and is unreachable on a non-Proven binding.
pub fn fleet_auto_trust(
    same_owner: bool,
    binding: BindingStrength,
    scoped_in_bounds: bool,
    cert_not_revoked: bool,
) -> bool {
    same_owner && binding == BindingStrength::Proven && scoped_in_bounds && cert_not_revoked
}

// ---------------------------------------------------------------------------
// Tag store objects  (owner-signed, verified at resolution time)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TagBindingObj {
    pub tag_ref: [u8; 32],  // SHA-256(owner_pub || tag_id)
    pub subject_kind: u8,   // 0x00=user, 0x01=device
    pub subject: [u8; 32],
    pub owner_pub: [u8; 32],
    pub version: u64,
    pub issued_at: u64,
    pub expires: u64,
    pub sig: [u8; 64],
}

impl TagBindingObj {
    pub fn canonical_for_signing(&self) -> Vec<u8> {
        fn lp(buf: &mut Vec<u8>, f: &[u8]) {
            buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
            buf.extend_from_slice(f);
        }
        let mut v = Vec::new();
        v.extend_from_slice(b"filament/tag-binding/v1");
        lp(&mut v, &self.tag_ref);
        lp(&mut v, &[self.subject_kind]);
        lp(&mut v, &self.subject);
        lp(&mut v, &self.owner_pub);
        lp(&mut v, &self.version.to_le_bytes());
        lp(&mut v, &self.issued_at.to_le_bytes());
        lp(&mut v, &self.expires.to_le_bytes());
        v
    }

    pub fn verify(&self) -> Result<()> {
        if now_secs() >= self.expires {
            bail!("tag binding expired");
        }
        let canonical = self.canonical_for_signing();
        let peer_pub = UnparsedPublicKey::new(&ED25519, &self.owner_pub);
        peer_pub
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("tag binding signature invalid"))
    }
}

/// Find tag bindings for (owner_pub, tag_hash) that are not expired and sig-valid.
fn find_tag_bindings(store: &[Value], owner: &[u8; 32], tag_hash: [u8; 32]) -> Vec<TagBindingObj> {
    store.iter().filter_map(|e| {
        if e.get("type").and_then(|v| v.as_str()) != Some("cap_tag_binding") { return None; }
        let b = TagBindingObj {
            tag_ref: { let b = hex::decode(e["tag_ref"].as_str()?).ok()?; let mut a = [0u8;32]; a.copy_from_slice(&b); a },
            subject_kind: e["subject_kind"].as_u64()? as u8,
            subject: { let b = hex::decode(e["subject"].as_str()?).ok()?; let mut a = [0u8;32]; a.copy_from_slice(&b); a },
            owner_pub: { let b = hex::decode(e["owner_pub"].as_str()?).ok()?; let mut a = [0u8;32]; a.copy_from_slice(&b); a },
            version: e["version"].as_u64()?,
            issued_at: e["issued_at"].as_u64()?,
            expires: e["expires"].as_u64()?,
            sig: { let b = hex::decode(e["sig"].as_str()?).ok()?; let mut a = [0u8;64]; a.copy_from_slice(&b); a },
        };
        if b.tag_ref != tag_hash { return None; }
        if b.owner_pub != *owner { return None; }
        if b.verify().is_err() { return None; }
        Some(b)
    }).collect()
}

/// Apply a tag binding with monotonic version check (anti-rollback).
pub fn apply_tag_binding(store: &mut Vec<Value>, binding: &TagBindingObj) -> Result<()> {
    binding.verify()?;
    let owner_hex = hex::encode(binding.owner_pub);
    let tag_hex = hex::encode(binding.tag_ref);

    for entry in store.iter_mut() {
        if entry.get("type").and_then(|v| v.as_str()) != Some("cap_tag_binding") { continue; }
        if entry["owner_pub"].as_str() != Some(&owner_hex) { continue; }
        if entry["tag_ref"].as_str() != Some(&tag_hex) { continue; }
        if entry["subject_kind"].as_u64() != Some(binding.subject_kind as u64) { continue; }
        if entry["subject"].as_str() != Some(hex::encode(binding.subject).as_str()) { continue; }
        let existing_ver = entry["version"].as_u64().unwrap_or(0);
        if existing_ver >= binding.version {
            bail!("tag binding version rollback: existing {} >= new {}",
                existing_ver, binding.version);
        }
        *entry = binding.to_json();
        return Ok(());
    }
    store.push(binding.to_json());
    Ok(())
}

impl TagBindingObj {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "type": "cap_tag_binding",
            "tag_ref": hex::encode(self.tag_ref),
            "subject_kind": self.subject_kind,
            "subject": hex::encode(self.subject),
            "owner_pub": hex::encode(self.owner_pub),
            "version": self.version,
            "issued_at": self.issued_at,
            "expires": self.expires,
            "sig": hex::encode(self.sig),
        })
    }
}

// ---------------------------------------------------------------------------
// CapHeader  (domain b"filament/capability-header/v1")
// ---------------------------------------------------------------------------

const CAPHEADER_SIGN_DOMAIN: &[u8] = b"filament/capability-header/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapFloor {
    pub target_kind: u8,
    pub target: [u8; 32],
    pub min_version: u64,
}

impl CapFloor {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(33);
        v.push(self.target_kind);
        v.extend_from_slice(&self.target);
        v
    }
}

#[derive(Debug, Clone)]
pub struct CapHeader {
    pub resource: String,
    pub epoch: u64,
    pub owner_pub: [u8; 32],
    pub nonce: [u8; 32],
    pub floors: Vec<CapFloor>,
    pub issued_at: u64,
    pub prev_owner_pub: Option<[u8; 32]>,
    /// None for genesis; for succession, SHA-256(canonical(predecessor)).
    pub prev_header_hash: Option<[u8; 32]>,
    pub sig: [u8; 64],
}

impl CapHeader {
    fn lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
        buf.extend_from_slice(field);
    }

    pub fn canonical_for_signing(&self) -> Vec<u8> {
        // Floors blob
        let mut floors_blob = Vec::new();
        floors_blob.extend_from_slice(&(self.floors.len() as u32).to_le_bytes());
        for f in &self.floors {
            Self::lp(&mut floors_blob, &f.encode());
            Self::lp(&mut floors_blob, &f.min_version.to_le_bytes());
        }

        // prev_owner_pub
        let mut prev_blob = Vec::with_capacity(33);
        match &self.prev_owner_pub {
            None => {
                prev_blob.push(0x00);
                prev_blob.extend_from_slice(&[0u8; 32]);
            }
            Some(pk) => {
                prev_blob.push(0x01);
                prev_blob.extend_from_slice(pk);
            }
        }

        // prev_header_hash
        let mut phh_blob = Vec::with_capacity(33);
        match &self.prev_header_hash {
            None => {
                phh_blob.push(0x00);
                phh_blob.extend_from_slice(&[0u8; 32]);
            }
            Some(h) => {
                phh_blob.push(0x01);
                phh_blob.extend_from_slice(h);
            }
        }

        let mut v = Vec::new();
        v.extend_from_slice(CAPHEADER_SIGN_DOMAIN);
        Self::lp(&mut v, self.resource.as_bytes());
        Self::lp(&mut v, &self.epoch.to_le_bytes());
        Self::lp(&mut v, &self.owner_pub);
        Self::lp(&mut v, &self.nonce);
        Self::lp(&mut v, &floors_blob);
        Self::lp(&mut v, &self.issued_at.to_le_bytes());
        Self::lp(&mut v, &prev_blob);
        Self::lp(&mut v, &phh_blob);
        v
    }

    /// Verify a header's signature under the expected signer pubkey.
    fn verify_sig(&self, signer: &[u8; 32]) -> Result<()> {
        let canonical = self.canonical_for_signing();
        let peer_pub = UnparsedPublicKey::new(&ED25519, signer);
        peer_pub
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("capability header signature invalid"))
    }

    /// Verify a genesis header: self-signed, resource id is self-certifying,
    /// prev_owner_pub=None, prev_header_hash=None, epoch=0.
    pub fn verify_genesis(&self) -> Result<()> {
        if self.epoch != 0 {
            bail!("genesis header must have epoch=0");
        }
        if self.prev_owner_pub.is_some() {
            bail!("genesis header must have prev_owner_pub=None");
        }
        if self.prev_header_hash.is_some() {
            bail!("genesis header must have prev_header_hash=None");
        }
        // Self-certifying resource id
        let expected_id = make_resource_id(&self.owner_pub, &self.nonce);
        if self.resource != expected_id {
            bail!(
                "genesis resource id mismatch: stored '{}' != computed '{}' from owner_pub+nonce",
                self.resource,
                expected_id
            );
        }
        self.verify_sig(&self.owner_pub)
    }

    /// Verify a succession header against its predecessor.
    /// - Signed by predecessor's owner_pub
    /// - prev_header_hash == SHA-256(canonical(predecessor))
    /// - epoch > predecessor's epoch
    /// - prev_owner_pub == predecessor's owner_pub
    pub fn verify_succession(&self, predecessor: &CapHeader) -> Result<()> {
        if self.prev_owner_pub.is_none() {
            bail!("succession header must have prev_owner_pub set");
        }
        if self.prev_header_hash.is_none() {
            bail!("succession header must have prev_header_hash set");
        }
        if self.prev_owner_pub != Some(predecessor.owner_pub) {
            bail!("succession prev_owner_pub must equal predecessor's owner_pub");
        }
        let pred_hash = hash_header(predecessor);
        if self.prev_header_hash != Some(pred_hash) {
            bail!("succession prev_header_hash does not match predecessor hash");
        }
        if self.epoch <= predecessor.epoch {
            bail!(
                "epoch not strictly forward: new {} <= predecessor {}",
                self.epoch,
                predecessor.epoch
            );
        }
        self.verify_sig(&predecessor.owner_pub)
    }

    pub fn to_json(&self) -> Value {
        let floors: Vec<Value> = self
            .floors
            .iter()
            .map(|f| {
                serde_json::json!({
                    "targetKind": f.target_kind,
                    "target": hex::encode(f.target),
                    "min_version": f.min_version,
                })
            })
            .collect();
        serde_json::json!({
            "type": "cap_header",
            "resource": self.resource,
            "epoch": self.epoch,
            "owner_pub": hex::encode(self.owner_pub),
            "nonce": hex::encode(self.nonce),
            "floors": floors,
            "issued_at": self.issued_at,
            "prev_owner_pub": self.prev_owner_pub.map(hex::encode),
            "prev_header_hash": self.prev_header_hash.map(hex::encode),
            "sig": hex::encode(self.sig),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let owner_pub = {
            let b = hex::decode(v["owner_pub"].as_str()?).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        };
        let nonce = {
            let b = hex::decode(v["nonce"].as_str()?).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        };
        let prev_owner_pub = v["prev_owner_pub"].as_str().and_then(|s| {
            let b = hex::decode(s).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Some(a)
        });
        let prev_header_hash = v["prev_header_hash"].as_str().and_then(|s| {
            let b = hex::decode(s).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Some(a)
        });
        let sig = {
            let b = hex::decode(v["sig"].as_str()?).ok()?;
            if b.len() != 64 { return None; }
            let mut a = [0u8; 64]; a.copy_from_slice(&b); a
        };
        let floors: Vec<CapFloor> = v["floors"]
            .as_array()?
            .iter()
            .map(|f| {
                let tk = f["targetKind"].as_u64()? as u8;
                let t = {
                    let b = hex::decode(f["target"].as_str()?).ok()?;
                    if b.len() != 32 { return None; }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                };
                let mv = f["min_version"].as_u64()?;
                Some(CapFloor {
                    target_kind: tk,
                    target: t,
                    min_version: mv,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(CapHeader {
            resource: v["resource"].as_str()?.to_string(),
            epoch: v["epoch"].as_u64()?,
            owner_pub,
            nonce,
            floors,
            issued_at: v["issued_at"].as_u64()?,
            prev_owner_pub,
            prev_header_hash,
            sig,
        })
    }

    /// Find the floor min_version for a given target in this header.
    pub fn floor_for(&self, target_kind: u8, target: &[u8; 32]) -> u64 {
        self.floors
            .iter()
            .find(|f| f.target_kind == target_kind && &f.target == target)
            .map(|f| f.min_version)
            .unwrap_or(0)
    }
}

pub fn sign_cap_header(header: &CapHeader, keypair: &Ed25519KeyPair) -> [u8; 64] {
    let sig = keypair.sign(&header.canonical_for_signing());
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ---------------------------------------------------------------------------
// Per-owner freshness ratchet
// ---------------------------------------------------------------------------

/// Read the ratchet for `owner_pub`. Returns `None` if uninitialized.
fn ratchet_for(store: &[Value], owner_pub: &[u8; 32]) -> Option<u64> {
    let owner_hex = hex::encode(owner_pub);
    store
        .iter()
        .find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("cap_ratchet")
                && e["owner_pub"].as_str() == Some(owner_hex.as_str())
        })
        .and_then(|e| e["max_issued_at"].as_u64())
}

/// Update the per-owner ratchet. Clamps `issued_at` to `local_clock + MAX_SKEW_SECS`;
/// far-future values are rejected. On success, stores `max(existing, issued_at)`.
pub fn update_ratchet(store: &mut Vec<Value>, owner_pub: &[u8; 32], issued_at: u64) -> Result<()> {
    let local_now = now_secs();
    let max_allowed = local_now.saturating_add(MAX_SKEW_SECS);
    if issued_at > max_allowed {
        bail!(
            "far-future issued_at {} rejected (local clock {} + skew {})",
            issued_at,
            local_now,
            MAX_SKEW_SECS
        );
    }

    let owner_hex = hex::encode(owner_pub);
    for e in store.iter_mut() {
        if e.get("type").and_then(|v| v.as_str()) == Some("cap_ratchet")
            && e["owner_pub"].as_str() == Some(owner_hex.as_str())
        {
            let existing = e["max_issued_at"].as_u64().unwrap_or(0);
            e["max_issued_at"] = Value::from(std::cmp::max(existing, issued_at));
            return Ok(());
        }
    }
    store.push(serde_json::json!({
        "type": "cap_ratchet",
        "owner_pub": owner_hex,
        "max_issued_at": issued_at,
    }));
    Ok(())
}

// ---------------------------------------------------------------------------
// Restrictive composers + gate decision types
// ---------------------------------------------------------------------------

/// The effective gate decision with an optional capability denial reason so
/// the operator-facing diagnostic can say what actually happened instead of
/// repeating the legacy assertion.
pub enum GateDecision {
    Allow,
    Deny { cap_reason: Option<String> },
}

impl GateDecision {
    pub fn allowed(&self) -> bool {
        matches!(self, GateDecision::Allow)
    }

    /// Operator-facing denial reason: the real cap reason when present
    /// (authoritative), else `legacy`.
    pub fn deny_reason<'a>(&'a self, legacy: &'a str) -> &'a str {
        match self {
            GateDecision::Deny { cap_reason: Some(r) } => r,
            _ => legacy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingStrength {
    None,
    Proven,
    Inferred,
}

/// A delegated principal CANNOT exist without its caps ceiling — the compiler
/// enforces what convention previously did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalKind {
    OwnerDevice,
    Delegated { caps: Vec<String> },
    /// A same-owner FLEET device: identity proven by an owner-signed certificate
    /// bound to the link, but NOT this machine's owner principal.
    ///
    /// Distinct from both neighbours on purpose:
    ///   - not `Delegated`, because that carries an auth-key CEILING, and the
    ///     ceiling check is unconditional and purely restrictive. A fleet sibling
    ///     is not an auth-key borrower, and giving it an empty ceiling denied
    ///     everything before the fleet policy in `cap_gate_effective` was ever
    ///     consulted. (Delegated also means "ephemeral, drop on disconnect",
    ///     which a persistent sibling is not.)
    ///   - not `OwnerDevice`, so nothing reads it as the local primary.
    ///
    /// It carries no ceiling, which is safe precisely because
    /// `cap_gate_effective` DISCARDS the owner shortcut for a same-owner peer and
    /// recomputes from fleet policy: a scoped default within bounds plus Proven
    /// is auto-authorized, and everything else stays grant-only.
    FleetDevice,
}

impl PrincipalKind {
    /// Extract auth_key_caps for evaluate. Delegated always has caps; OwnerDevice has None.
    pub fn auth_key_caps(&self) -> Option<&[String]> {
        match self {
            PrincipalKind::OwnerDevice => None,
            // No ceiling: the fleet policy in `cap_gate_effective` decides.
            PrincipalKind::FleetDevice => None,
            PrincipalKind::Delegated { caps } => Some(caps),
        }
    }
}

/// Purely restrictive: under authoritative, downgrades Authorized→Denied when
/// binding is not Proven. Denied/Unprovisioned pass through; shadow passes through.
pub fn cap_authorize_proven(
    outcome: &CapOutcome,
    binding: BindingStrength,
    authoritative: bool,
) -> CapOutcome {
    if !authoritative || binding == BindingStrength::Proven {
        return outcome.clone();
    }
    match outcome {
        CapOutcome::Authorized => CapOutcome::Denied("identity not proven".into()),
        _ => outcome.clone(),
    }
}

/// Purely restrictive: under authoritative, downgrades Authorized→Denied when
/// the cert is expired or expiry is unknown (None = fail-closed).
pub fn cap_authorize_expired(
    outcome: &CapOutcome,
    cert_expires: Option<u64>,
    authoritative: bool,
) -> CapOutcome {
    if !authoritative {
        return outcome.clone();
    }
    let expired = match cert_expires {
        None => true,
        Some(exp) => now_secs() >= exp,
    };
    if expired {
        match outcome {
            CapOutcome::Authorized => CapOutcome::Denied("cert expired".into()),
            _ => outcome.clone(),
        }
    } else {
        outcome.clone()
    }
}

/// Trust floor: under authoritative, an untrusted OR unbound link must never
/// authorize. Floor passes if the session is link-trusted (pair-proof completed)
/// OR the identity is Proven (delegated-by-enrollment / possession-proven).
/// Purely restrictive — downgrades Authorized→Denied only; Denied/Unprov
/// pass through. Shadow always passes through. Only needed at gates whose
/// legacy check is trust-based (transfer, mount).
pub fn cap_trust_floor(
    outcome: &CapOutcome,
    trusted: bool,
    binding: BindingStrength,
    authoritative: bool,
) -> CapOutcome {
    if !authoritative || trusted || binding == BindingStrength::Proven {
        return outcome.clone();
    }
    match outcome {
        CapOutcome::Authorized => CapOutcome::Denied("session not trusted".into()),
        _ => outcome.clone(),
    }
}

/// Transfer-gate decision: under authoritative, a Deny from the capability
/// layer returns `Some(reason)` and the caller must hard-decline immediately
/// (no accept prompt, send decline wire with `reason`). In shadow, returns
/// `None` and the legacy accept/consent path still decides (report-only).
pub fn transfer_gate_decision(gate: &GateDecision, authoritative: bool) -> Option<String> {
    match gate {
        GateDecision::Allow => None,
        GateDecision::Deny { cap_reason } if authoritative => {
            Some(cap_reason.clone().unwrap_or_else(|| "capability denied".into()))
        }
        _ => None, // shadow, or legacy-only deny without cap reason
    }
}

// ---------------------------------------------------------------------------
// Observability count shapes (constructed by the CLI's glue counters)
// ---------------------------------------------------------------------------

/// Per-action shadow count for a single action.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionCounts {
    pub action: String,
    pub la_authorized: u64,
    pub la_denied: u64,
    pub la_no_header: u64,
    pub ld_authorized: u64,
    pub ld_denied: u64,
    pub ld_no_header: u64,
}

/// Shadow counts, bucketed by legacy outcome and cap outcome.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct ShadowCounts {
    pub la_authorized: u64,
    pub la_denied: u64,
    pub la_no_header: u64,
    pub ld_authorized: u64,
    pub ld_denied: u64,
    pub ld_no_header: u64,
    /// Auth-key ceiling denials (both modes, outside flip criterion).
    pub ceiling_denied: u64,
}

impl ShadowCounts {
    /// The FLIP CRITERION, in code (not just prose): flip to authoritative only when
    /// a real sample of legacy-ALLOWED opens has been seen (`la_authorized > 0`), NO
    /// header disagreed (`la_denied == 0`), and every reachable resource EXERCISED in
    /// the window was provisioned (`la_no_header == 0`).
    ///
    /// This boolean guards BREAKAGE (access the flip would remove). It deliberately
    /// does NOT read `ld_authorized`, the WIDENING count (opens legacy refused that
    /// cap authorizes, which the flip will newly ALLOW), because some widening is the
    /// intended point of the migration and a hard zero would forbid it. Widening is
    /// instead a MANDATORY REVIEW gate: the commit that sets the flag MUST cite
    /// `ld_authorized` alongside the `la_*` numbers, and if it is nonzero, enumerate
    /// which opens will be newly permitted and why. A number written down gets looked
    /// at; a number labeled "informational" does not.
    ///
    /// Caveat: `la_no_header == 0` proves every resource EXERCISED during the window
    /// was provisioned, not that every resource is. Today all gates pass "self" (one
    /// resource) so the claim is tight; when resources multiply this silently becomes
    /// a sampled claim, the biased-sample problem one level up. Revisit then.
    pub fn flip_ready(&self) -> bool {
        self.la_authorized > 0 && self.la_denied == 0 && self.la_no_header == 0
    }

    /// One-line operator summary of both populations plus flip-readiness.
    pub fn summary(&self) -> String {
        format!(
            "legacy-allowed ok={} deny={} no-header={} | WIDENING(newly-allowed-on-flip)={} legacy-denied[deny={} no-header={}] | flip_ready={}",
            self.la_authorized,
            self.la_denied,
            self.la_no_header,
            self.ld_authorized,
            self.ld_denied,
            self.ld_no_header,
            self.flip_ready(),
        )
    }
}

// ---------------------------------------------------------------------------
// Preview + self-lockout
// ---------------------------------------------------------------------------

/// A single authorization query for preview enumeration.
pub struct AuthQuery {
    pub principal_device_pub: [u8; 32],
    pub principal_user_pub: [u8; 32],
    pub action: String,
}

pub struct PreviewEntry {
    pub query: AuthQuery,
    pub authorized: bool,
}

/// Preview the effect of applying `ops` to a cloned store: compute
/// evaluate() for each query against the post-apply state. Same
/// evaluate() fn, so preview cannot diverge from enforcement.
pub fn preview(
    store: &[Value],
    header: &CapHeader,
    ops: &[CapOp],
    queries: &[AuthQuery],
    now: u64,
) -> Vec<PreviewEntry> {
    let mut cloned_store = store.to_vec();
    for op in ops {
        let _ = apply_cap_op(&mut cloned_store, header, op, now);
    }
    queries
        .iter()
        .map(|q| {
            let d = evaluate(
                &cloned_store,
                header,
                &q.principal_device_pub,
                &q.principal_user_pub,
                &header.resource,
                &q.action,
                now,
                None,
            );
            PreviewEntry {
                query: AuthQuery {
                    principal_device_pub: q.principal_device_pub,
                    principal_user_pub: q.principal_user_pub,
                    action: q.action.clone(),
                },
                authorized: matches!(d, Decision::Authorized),
            }
        })
        .collect()
}

/// Check whether applying an op self-locks out the admin: if a principal
/// held Authorized on an action before but is Denied after, return a
/// warning. The caller surfaces this toward the owner; it does NOT refuse
/// the op.
pub fn check_self_lockout(
    store: &[Value],
    header: &CapHeader,
    op: &CapOp,
    principals: &[(String, [u8; 32], [u8; 32])],
    admin_actions: &[&str],
    now: u64,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut after_store = store.to_vec();
    if apply_cap_op(&mut after_store, header, op, now).is_err() {
        return warnings;
    }
    for (label, dev_pub, user_pub) in principals {
        for action in admin_actions {
            let before = evaluate(store, header, dev_pub, user_pub, &header.resource, action, now, None);
            let after = evaluate(&after_store, header, dev_pub, user_pub, &header.resource, action, now, None);
            if matches!(before, Decision::Authorized) && matches!(after, Decision::Denied(_)) {
                warnings.push(format!(
                    "self-lockout WARNING: {} would lose '{}' on resource '{}'",
                    label, action, header.resource
                ));
            }
        }
    }
    warnings
}

// ---------------------------------------------------------------------------
// Store fns
// ---------------------------------------------------------------------------

fn find_header_idx(store: &[Value], resource: &str) -> Option<usize> {
    store
        .iter()
        .position(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                      && e["resource"].as_str() == Some(resource))
}

/// Apply a resource header.  Genesis must be self-certifying (resource id =
/// hex(SHA-256(owner_pub||nonce))).  Succession must hash-chain to the
/// predecessor and be signed by it.  Equal-epoch forks freeze the chain.
pub fn apply_header(store: &mut Vec<Value>, new_header: &CapHeader) -> Result<()> {
    let existing_idx = find_header_idx(store, &new_header.resource);

    if existing_idx.is_none() {
        // Genesis: first header for this resource
        new_header.verify_genesis()?;
        store.push(new_header.to_json());
        update_ratchet(store, &new_header.owner_pub, new_header.issued_at)?;
        return Ok(());
    }

    let current = CapHeader::from_json(&store[existing_idx.unwrap()])
        .ok_or_else(|| anyhow!("stored header is corrupt"))?;

    // Fork detection: same epoch, same predecessor -> must be identical, else fork
    if new_header.epoch == current.epoch {
        if new_header.prev_header_hash == current.prev_header_hash {
            let new_hash = hash_header(new_header);
            let cur_hash = hash_header(&current);
            if new_hash != cur_hash {
                // Equal-epoch fork: freeze, do not accept either
                store[existing_idx.unwrap()]["frozen"] = Value::from(true);
                bail!(
                    "equal-epoch fork detected at epoch {} for resource '{}': successor frozen",
                    new_header.epoch,
                    new_header.resource
                );
            }
            // Identical header: replay is non-forward
            bail!(
                "non-forward epoch: new epoch {} == current epoch {}",
                new_header.epoch,
                current.epoch
            );
        }
        bail!(
            "non-forward epoch: new epoch {} == current epoch {}",
            new_header.epoch,
            current.epoch
        );
    }

    // Check chain is not frozen
    if store[existing_idx.unwrap()].get("frozen").and_then(|v| v.as_bool()).unwrap_or(false) {
        bail!(
            "succession frozen for resource '{}' (fork detected)",
            new_header.resource
        );
    }

    // Verify hash-chained succession
    new_header.verify_succession(&current)?;

    store[existing_idx.unwrap()] = new_header.to_json();
    update_ratchet(store, &new_header.owner_pub, new_header.issued_at)?;
    Ok(())
}

/// Apply a verified capability op to the store.
pub fn apply_cap_op(
    store: &mut Vec<Value>,
    header: &CapHeader,
    op: &CapOp,
    now: u64,
) -> Result<()> {
    op.verify(&header.owner_pub, now)?;

    if find_header_idx(store, &header.resource).is_none() {
        bail!("cannot apply cap op: no header for resource '{}' in store", &header.resource);
    }

    let floor = header.floor_for(op.target_kind, &op.target);
    if op.version < floor {
        bail!(
            "cap op version {} below floor {} for target {}/{}",
            op.version,
            floor,
            op.target_kind,
            hex::encode(op.target)
        );
    }

    let grantor_hex = hex::encode(op.grantor);
    let target_hex = hex::encode(op.target);

    let mut found_idx = None;
    for (i, entry) in store.iter().enumerate() {
        if entry.get("type").and_then(|v| v.as_str()) != Some("cap_grant") {
            continue;
        }
        if entry["grantor"].as_str() == Some(&grantor_hex)
            && entry["resource"].as_str() == Some(op.resource.as_str())
            && entry["targetKind"].as_u64() == Some(op.target_kind as u64)
            && entry["target"].as_str() == Some(target_hex.as_str())
        {
            let existing_version = entry["version"].as_u64().unwrap_or(0);
            if existing_version >= op.version {
                bail!(
                    "monotonic version refusal: existing {} >= new {}",
                    existing_version,
                    op.version
                );
            }
            found_idx = Some(i);
            break;
        }
    }

    if op.op == CapOpKind::Revoke || op.permissions.is_empty() {
        if let Some(idx) = found_idx {
            store.remove(idx);
        }
        return Ok(());
    }

    let mut json_entry = op.to_json();
    json_entry["type"] = Value::from("cap_grant");

    if let Some(idx) = found_idx {
        if let Some(ma) = store[idx].get("max_issued_at").and_then(|v| v.as_u64()) {
            let new_ma = std::cmp::max(ma, op.issued_at);
            json_entry["max_issued_at"] = Value::from(new_ma);
        } else {
            json_entry["max_issued_at"] = Value::from(op.issued_at);
        }
        store[idx] = json_entry;
    } else {
        json_entry["max_issued_at"] = Value::from(op.issued_at);
        store.push(json_entry);
    }
    update_ratchet(store, &op.grantor, op.issued_at)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (the pure subset; store-I/O / counter / DeviceCert tests stay in cli)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn grant_spec_arity_is_enforced_in_both_directions() {
        let owner = [3u8; 32];

        // Ordinary capabilities act on "self" and take no resource.
        let g = parse_grant_spec("shell", &owner).unwrap();
        assert_eq!((g.action.as_str(), g.resource.as_str()), ("shell", "self"));
        let g = parse_grant_spec(" Transfer ", &owner).unwrap();
        assert_eq!((g.action.as_str(), g.resource.as_str()), ("transfer", "self"));

        // A route carries its prefix, and the resource is the owner-bound id.
        let g = parse_grant_spec("route:10.0.0.0/24", &owner).unwrap();
        assert_eq!(g.action, "route");
        let r = g.resource.clone();
        assert_eq!(r, route_resource_id(&owner, "10.0.0.0/24").unwrap());
        // The returned nonce must be the one the id came from, or the genesis
        // header would be filed under a resource it does not describe.
        assert_eq!(make_resource_id(&owner, &g.nonce), r);

        // Spelling still does not matter, because the id normalizes.
        let g2 = parse_grant_spec("route: 10.0.0.5/24 ", &owner).unwrap();
        assert_eq!(r, g2.resource);

        // BOTH arity mistakes are refused. A route with no prefix would store a
        // grant that matches nothing; a non-route with one would store a resource
        // enforcement never asks about. Either way the grant silently authorizes
        // nothing, which is worse than an error because it looks like it worked.
        assert!(parse_grant_spec("route", &owner).is_err(), "route needs a prefix");
        assert!(parse_grant_spec("route:", &owner).is_err(), "empty prefix is not a prefix");
        assert!(parse_grant_spec("shell:10.0.0.0/24", &owner).is_err(), "shell takes no resource");

        // And a malformed prefix is refused rather than hashed into a resource
        // that can never match.
        assert!(parse_grant_spec("route:not-a-cidr", &owner).is_err());
        assert!(parse_grant_spec("route:10.0.0.0/33", &owner).is_err());
    }

    #[test]
    fn cidr_normalization_closes_the_bypasses_it_exists_for() {
        // Host bits set. `10.0.0.5/24` and `10.0.0.0/24` are the SAME prefix, and
        // if they hashed differently a grant would silently not apply to the
        // advertisement it was written for.
        assert_eq!(normalize_cidr("10.0.0.5/24").unwrap(), "10.0.0.0/24");
        assert_eq!(normalize_cidr("10.0.0.0/24").unwrap(), "10.0.0.0/24");

        // Whitespace, which is the cheapest bypass of a text-keyed resource.
        assert_eq!(normalize_cidr("  10.0.0.0/24  ").unwrap(), "10.0.0.0/24");
        assert_eq!(normalize_cidr("10.0.0.0 / 24").unwrap(), "10.0.0.0/24");

        // v6 casing, normalized by Ipv6Addr's own Display.
        assert_eq!(normalize_cidr("FD00::1/16").unwrap(), "fd00::/16");

        // /0 is legal and means everything; the mask must not be a UB shift.
        assert_eq!(normalize_cidr("1.2.3.4/0").unwrap(), "0.0.0.0/0");
        assert_eq!(normalize_cidr("fd00::1/0").unwrap(), "::/0");

        // Refusals, rather than a resource id for nonsense.
        assert!(normalize_cidr("10.0.0.0/33").is_err(), "over-long v4");
        assert!(normalize_cidr("fd00::/129").is_err(), "over-long v6");
        assert!(normalize_cidr("10.0.0.0").is_err(), "no length");
        assert!(normalize_cidr("not-an-ip/24").is_err(), "not an address");
    }

    #[test]
    fn route_resource_binds_prefix_to_owner_and_ignores_spelling() {
        let owner = [7u8; 32];
        let other = [8u8; 32];

        // Same prefix spelled differently is ONE resource. This is the property
        // the whole grant depends on: the id computed when the owner grants must
        // equal the id computed when an advertisement is checked, on a different
        // machine that never saw the grant being minted.
        let a = route_resource_id(&owner, "10.0.0.0/24").unwrap();
        let b = route_resource_id(&owner, " 10.0.0.5/24 ").unwrap();
        assert_eq!(a, b, "spelling must not change the resource");

        // Different prefix is a different resource, so a grant for one LAN does
        // not authorize another.
        let c = route_resource_id(&owner, "10.0.1.0/24").unwrap();
        assert_ne!(a, c, "different prefix, different resource");

        // Different length is a different resource: /8 is not /24.
        let d = route_resource_id(&owner, "10.0.0.0/8").unwrap();
        assert_ne!(a, d, "different length, different resource");

        // BOUND TO THE OWNER. Another owner granting the same prefix produces a
        // different id, so one owner's grant cannot be replayed into another's
        // store; CapOp::verify separately refuses a grantor that is not the
        // resource owner.
        let e = route_resource_id(&other, "10.0.0.0/24").unwrap();
        assert_ne!(a, e, "resource must be owner-bound");

        // And it never collides with the self resource.
        assert_ne!(a, self_resource_id(&owner), "route id must not collide with self id");
    }

    #[test]
    fn route_is_a_canonical_capability() {
        assert!(CANONICAL_CAPABILITIES.contains(&CAP_ROUTE));
        assert_eq!(canonical_capability(" Route ").unwrap(), CAP_ROUTE);
    }

    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

    #[test]
    fn canonical_capabilities_reject_unknown_names() {
        for capability in CANONICAL_CAPABILITIES {
            assert_eq!(canonical_capability(capability).unwrap(), *capability);
        }
        assert!(canonical_capability("all-ports").is_err());
        assert!(canonical_capability("typo").is_err());
        let send_err = canonical_capability("send").unwrap_err().to_string();
        assert!(send_err.contains("not currently grantable"));
        assert!(send_err.contains("covers both directions"));
        assert!(canonical_capability("inbox").is_err());
    }

    #[test]
    fn canonical_capabilities_normalize_case_and_whitespace() {
        assert_eq!(canonical_capability(" SHELL ").unwrap(), "shell");
    }

    #[test]
    fn gated_actions_are_canonical_and_canonical_actions_are_gated() {
        for capability in CANONICAL_CAPABILITIES {
            // This checks grantable vocabulary against declared classification, not enforcement.
            // The CLI behavioral authorization test covers the latter for shell.
            assert!(is_enforced_capability(capability), "canonical capability '{capability}' is not classified");
        }
    }

    fn make_owner() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn owner_pub(keypair: &Ed25519KeyPair) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(keypair.public_key().as_ref());
        buf
    }

    fn make_genesis_header(
        owner: &Ed25519KeyPair,
        nonce: &[u8; 32],
        floors: &[CapFloor],
    ) -> CapHeader {
        let pk = owner_pub(owner);
        let resource = make_resource_id(&pk, nonce);
        let mut h = CapHeader {
            resource,
            epoch: 0,
            owner_pub: pk,
            nonce: *nonce,
            floors: floors.to_vec(),
            issued_at: now_secs(),
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        h.sig = sign_cap_header(&h, owner);
        h
    }

    fn make_succession_header(
        prev_owner: &Ed25519KeyPair,
        predecessor: &CapHeader,
        new_owner: &Ed25519KeyPair,
        epoch: u64,
        nonce: &[u8; 32],
        floors: &[CapFloor],
    ) -> CapHeader {
        let pred_hash = hash_header(predecessor);
        let mut h = CapHeader {
            resource: predecessor.resource.clone(),
            epoch,
            owner_pub: owner_pub(new_owner),
            nonce: *nonce,
            floors: floors.to_vec(),
            issued_at: now_secs(),
            prev_owner_pub: Some(predecessor.owner_pub),
            prev_header_hash: Some(pred_hash),
            sig: [0u8; 64],
        };
        h.sig = sign_cap_header(&h, prev_owner);
        h
    }

    fn make_grant(
        owner: &Ed25519KeyPair,
        target: CapTarget,
        resource: &str,
        permissions: &[&str],
        version: u64,
        ttl_secs: u64,
    ) -> CapOp {
        let grantor = owner_pub(owner);
        let issued_at = now_secs();
        let target_kind = target.kind_byte();
        let target_bytes = target.target_bytes();
        let mut op = CapOp {
            op: CapOpKind::Grant,
            grantor,
            target_kind,
            target: target_bytes,
            resource: resource.to_string(),
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
            expires: issued_at.saturating_add(ttl_secs),
            issued_at,
            version,
            sig: [0u8; 64],
        };
        op.sig = sign_cap_op(&op, owner);
        op
    }

    fn make_revoke(
        owner: &Ed25519KeyPair,
        target: CapTarget,
        resource: &str,
        version: u64,
        ttl_secs: u64,
    ) -> CapOp {
        let grantor = owner_pub(owner);
        let issued_at = now_secs();
        let target_kind = target.kind_byte();
        let target_bytes = target.target_bytes();
        let mut op = CapOp {
            op: CapOpKind::Revoke,
            grantor,
            target_kind,
            target: target_bytes,
            resource: resource.to_string(),
            permissions: vec![],
            expires: issued_at.saturating_add(ttl_secs),
            issued_at,
            version,
            sig: [0u8; 64],
        };
        op.sig = sign_cap_op(&op, owner);
        op
    }

    fn init_store(header: &CapHeader) -> Vec<Value> {
        let mut s = vec![];
        apply_header(&mut s, header).unwrap();
        s
    }

    // -- CapOp tests -------------------------------------------------------

    #[test]
    fn honest_grant_verifies_and_applies() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh", "shell"], v1, 86400);

        grant.verify(&pk, now_secs()).unwrap();

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        let grants: Vec<_> = store.iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant"))
            .collect();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0]["resource"].as_str().unwrap(), header.resource);
        assert_eq!(grants[0]["version"].as_u64().unwrap(), v1);
    }

    #[test]
    fn tampered_permission_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.permissions = vec!["admin".to_string()];
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn tampered_target_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xaa; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.target = [0xbb; 32];
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn tampered_resource_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.resource = "admin".to_string();
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn tampered_expires_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.expires = now_secs() + 999999;
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn tampered_version_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.version = v1.saturating_add(1000);
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn wrong_owner_sig_refused() {
        let alice = make_owner();
        let bob = make_owner();
        let alice_pub = owner_pub(&alice);
        let bob_pub = owner_pub(&bob);
        assert_ne!(alice_pub, bob_pub);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&alice, &nonce, &[]);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&alice, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&alice_pub, now_secs()).is_ok());
        assert!(grant.verify(&bob_pub, now_secs()).is_err());
    }

    #[test]
    fn expired_grant_refused() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let issued_at = now_secs().saturating_sub(86401);
        let target_kind = target.kind_byte();
        let target_bytes = target.target_bytes();
        let mut op = CapOp {
            op: CapOpKind::Grant,
            grantor: pk,
            target_kind,
            target: target_bytes,
            resource: "shell".to_string(),
            permissions: vec!["ssh".to_string()],
            expires: issued_at.saturating_add(86400),
            issued_at,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        op.sig = sign_cap_op(&op, &owner);
        assert!(op.verify(&pk, now_secs()).is_err());
    }

    // -- Monotonic / rollback -----------------------------------------------

    #[test]
    fn rollback_lower_version_rejected() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let seed = now_ms();
        let v5 = hlc_next(hlc_next(hlc_next(hlc_next(hlc_next(0, seed), seed), seed), seed), seed);
        let v3 = hlc_next(hlc_next(hlc_next(0, seed), seed), seed);

        let grant_v5 = make_grant(&owner, target, &header.resource, &["ssh", "shell"], v5, 86400);
        let grant_v3 = make_grant(&owner, target, &header.resource, &["ssh"], v3, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_v5, now_secs()).unwrap();
        let res = apply_cap_op(&mut store, &header, &grant_v3, now_secs());
        assert!(res.is_err(), "rollback v5 -> v3 must be rejected");
    }

    #[test]
    fn revoke_removes_grant() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let revoke = make_revoke(&owner, target, &header.resource, v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &revoke, now_secs()).unwrap();
        let grants: Vec<_> = store.iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant"))
            .collect();
        assert_eq!(grants.len(), 0, "revoke must remove grant");
    }

    #[test]
    fn empty_permissions_removes_grant() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let empty_grant = make_grant(&owner, target, &header.resource, &[], v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &empty_grant, now_secs()).unwrap();
        let grants: Vec<_> = store.iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant"))
            .collect();
        assert_eq!(grants.len(), 0);
    }

    #[test]
    fn rollback_guard_red_without_fix() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);
        let v3 = hlc_next(v2, seed);
        let v4 = hlc_next(v3, seed);
        let v5 = hlc_next(v4, seed);

        let grant_v5 = make_grant(&owner, target, &header.resource, &["ssh", "shell"], v5, 86400);
        let grant_v3 = make_grant(&owner, target, &header.resource, &["ssh"], v3, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_v5, now_secs()).unwrap();

        let pk = owner_pub(&owner);
        assert!(grant_v3.verify(&pk, now_secs()).is_ok());

        let res = apply_cap_op(&mut store, &header, &grant_v3, now_secs());
        assert!(res.is_err(), "rollback v5->v3 must be REFUSED; if green, guard is broken");
    }

    // -- Floor --------------------------------------------------------------

    #[test]
    fn floor_rejects_first_seen_op_below_min_version() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let seed = now_ms();
        let floor_ver = hlc_next(hlc_next(hlc_next(0, seed), seed), seed);
        let low_ver = hlc_next(0, seed);

        let header = make_genesis_header(
            &owner,
            &nonce,
            &[CapFloor {
                target_kind: target.kind_byte(),
                target: target.target_bytes(),
                min_version: floor_ver,
            }],
        );

        let grant_low = make_grant(&owner, target, &header.resource, &["ssh"], low_ver, 86400);
        let mut store = init_store(&header);
        let res = apply_cap_op(&mut store, &header, &grant_low, now_secs());
        assert!(res.is_err(), "op below floor must be rejected");

        let v = hlc_next(floor_ver, seed);
        let grant_ok = make_grant(&owner, target, &header.resource, &["ssh"], v, 86400);
        apply_cap_op(&mut store, &header, &grant_ok, now_secs()).unwrap();
    }

    // -- Genesis self-certifying resource id ---------------------------------

    #[test]
    fn genesis_id_forgery_rejected() {
        let alice = make_owner();
        let mallory = make_owner();
        let nonce = [0xaa; 32];

        // Alice creates a valid genesis
        let alice_genesis = make_genesis_header(&alice, &nonce, &[]);
        alice_genesis.verify_genesis().unwrap();

        // Mallory tries to create a genesis with the SAME resource id (alice's)
        // by computing her own nonce... but make_resource_id binds owner_pub too.
        // Any genesis with owner_pub=mallory will produce a different resource id.
        let mallory_pk = owner_pub(&mallory);
        let mallory_id = make_resource_id(&mallory_pk, &nonce);
        assert_ne!(mallory_id, alice_genesis.resource,
            "different owner must produce different resource id");

        // Mallory cannot produce a genesis for Alice's resource id because
        // sha256(mallory_pub||nonce) != sha256(alice_pub||nonce)
        // And she cannot change owner_pub without changing the resource id.
        // verify_genesis enforces resource_id == sha256(owner_pub||nonce).
        let mut bogus = CapHeader {
            resource: alice_genesis.resource.clone(),
            epoch: 0,
            owner_pub: mallory_pk,
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        bogus.sig = sign_cap_header(&bogus, &mallory);
        assert!(bogus.verify_genesis().is_err(),
            "genesis with mismatched owner_pub+nonce must be rejected");
    }

    // -- Succession hash-chained ---------------------------------------------

    #[test]
    fn succession_alice_to_bob_applies_bobs_ops() {
        let alice = make_owner();
        let bob = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let genesis = make_genesis_header(&alice, &nonce, &[]);
        let mut store = init_store(&genesis);

        let v1 = hlc_next(0, now_ms());
        let grant_alice = make_grant(&alice, target, &genesis.resource, &["ssh"], v1, 86400);
        apply_cap_op(&mut store, &genesis, &grant_alice, now_secs()).unwrap();

        let succ = make_succession_header(&alice, &genesis, &bob, 1, &nonce, &[]);
        succ.verify_succession(&genesis).unwrap();
        apply_header(&mut store, &succ).unwrap();

        let v2 = hlc_next(v1, now_ms());
        let grant_bob = make_grant(&bob, target, &genesis.resource, &["shell"], v2, 86400);
        apply_cap_op(&mut store, &succ, &grant_bob, now_secs()).unwrap();

        let v3 = hlc_next(v2, now_ms());
        let grant_alice2 = make_grant(&alice, target, &genesis.resource, &["admin"], v3, 86400);
        assert!(apply_cap_op(&mut store, &succ, &grant_alice2, now_secs()).is_err());
    }

    #[test]
    fn succession_not_signed_by_prev_owner_rejected() {
        let alice = make_owner();
        let bob = make_owner();
        let mallory = make_owner();
        let nonce = [0x01; 32];
        let genesis = make_genesis_header(&alice, &nonce, &[]);
        let mut store = init_store(&genesis);

        let pred_hash = hash_header(&genesis);
        let mut bogus = CapHeader {
            resource: genesis.resource.clone(),
            epoch: 1,
            owner_pub: owner_pub(&bob),
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(genesis.owner_pub),
            prev_header_hash: Some(pred_hash),
            sig: [0u8; 64],
        };
        bogus.sig = sign_cap_header(&bogus, &mallory);
        let res = apply_header(&mut store, &bogus);
        assert!(res.is_err(), "succession not signed by prev owner must be rejected");
    }

    #[test]
    fn non_forward_epoch_rejected() {
        let alice = make_owner();
        let bob = make_owner();
        let nonce = [0x01; 32];
        let genesis = make_genesis_header(&alice, &nonce, &[]);
        let mut store = init_store(&genesis);

        let succ1 = make_succession_header(&alice, &genesis, &bob, 1, &nonce, &[]);
        apply_header(&mut store, &succ1).unwrap();

        // Replay epoch 1
        let res = apply_header(&mut store, &succ1);
        assert!(res.is_err(), "non-forward epoch must be rejected");
    }

    #[test]
    fn succession_prev_header_hash_consistency() {
        let alice = make_owner();
        let bob = make_owner();
        let nonce = [0x01; 32];
        let genesis = make_genesis_header(&alice, &nonce, &[]);
        let mut store = init_store(&genesis);

        let succ1 = make_succession_header(&alice, &genesis, &bob, 1, &nonce, &[]);
        apply_header(&mut store, &succ1).unwrap();

        // Try to submit a header whose prev_header_hash is hash(genesis) not hash(succ1)
        let gen_hash = hash_header(&genesis);
        let mut gap = CapHeader {
            resource: genesis.resource.clone(),
            epoch: 2,
            owner_pub: owner_pub(&bob),
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(succ1.owner_pub),
            prev_header_hash: Some(gen_hash), // points to genesis, not succ1
            sig: [0u8; 64],
        };
        gap.sig = sign_cap_header(&gap, &bob);
        let res = apply_header(&mut store, &gap);
        assert!(res.is_err(), "chain gap: prev_header_hash must match stored predecessor");
    }

    // -- Equal-epoch fork ---------------------------------------------------

    #[test]
    fn equal_epoch_fork_frozen() {
        let alice = make_owner();
        let bob = make_owner();
        let carol = make_owner();
        let nonce = [0x01; 32];
        let genesis = make_genesis_header(&alice, &nonce, &[]);

        // Two valid but different successors at epoch 1 from genesis
        let pred_hash = hash_header(&genesis);

        let mut fork_a = CapHeader {
            resource: genesis.resource.clone(),
            epoch: 1,
            owner_pub: owner_pub(&bob),
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(genesis.owner_pub),
            prev_header_hash: Some(pred_hash),
            sig: [0u8; 64],
        };
        fork_a.sig = sign_cap_header(&fork_a, &alice);

        let mut fork_b = CapHeader {
            resource: genesis.resource.clone(),
            epoch: 1,
            owner_pub: owner_pub(&carol),
            nonce,
            floors: vec![],
            issued_at: now_secs() + 1,
            prev_owner_pub: Some(genesis.owner_pub),
            prev_header_hash: Some(pred_hash),
            sig: [0u8; 64],
        };
        fork_b.sig = sign_cap_header(&fork_b, &alice);

        // Both are valid against genesis
        fork_a.verify_succession(&genesis).unwrap();
        fork_b.verify_succession(&genesis).unwrap();

        // Apply the first one -- ok
        let mut store = init_store(&genesis);
        apply_header(&mut store, &fork_a).unwrap();

        // Apply the second one at same epoch -- FORK, freeze
        let res = apply_header(&mut store, &fork_b);
        assert!(res.is_err(), "equal-epoch fork must be rejected");

        // Chain must be frozen now
        let stored = store.iter()
            .find(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                     && e["resource"].as_str() == Some(genesis.resource.as_str()))
            .unwrap();
        assert!(stored.get("frozen").and_then(|v| v.as_bool()).unwrap_or(false),
            "chain must be frozen after fork detection");

        // Any succession after freeze is rejected
        let succ2 = make_succession_header(&alice, &fork_a, &bob, 2, &nonce, &[]);
        let res2 = apply_header(&mut store, &succ2);
        assert!(res2.is_err(), "succession after freeze must be rejected");
    }

    // -- Domain separation ---------------------------------------------------

    #[test]
    fn domain_separation_three_way() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0x11; 32]);
        let v1 = hlc_next(0, now_ms());
        let header = make_genesis_header(&owner, &nonce, &[]);
        let op = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);

        let op_canon = op.canonical_for_signing();
        let header_canon = header.canonical_for_signing();

        let op_domain: &[u8] = b"filament/capability-op/v1";
        let header_domain: &[u8] = b"filament/capability-header/v1";
        let cert_domain: &[u8] = b"filament/identity-device-cert/v1";

        assert_ne!(op_domain, header_domain);
        assert_ne!(op_domain, cert_domain);
        assert_ne!(header_domain, cert_domain);

        assert!(op_canon.starts_with(op_domain));
        assert!(!op_canon.starts_with(header_domain));
        assert!(!op_canon.starts_with(cert_domain));

        assert!(header_canon.starts_with(header_domain));
        assert!(!header_canon.starts_with(op_domain));
        assert!(!header_canon.starts_with(cert_domain));

        let op_len = (op_domain.len() as u32).to_le_bytes();
        let header_len = (header_domain.len() as u32).to_le_bytes();
        let cert_len = (cert_domain.len() as u32).to_le_bytes();
        assert_ne!(op_len, header_len);
        assert_ne!(header_len, cert_len);
    }

    // -- Canonical injectivity ----------------------------------------------

    #[test]
    fn canonical_injectivity() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let target = CapTarget::Device([0x11; 32]);
        let seed = now_ms();

        let op1 = make_grant(&owner, target, &header.resource, &["ssh"], hlc_next(0, seed), 86400);
        let op2 = make_grant(&owner, target, &header.resource, &["ssh"], hlc_next(hlc_next(0, seed), seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op2.canonical_for_signing());

        let op3 = make_grant(&owner, target, &header.resource, &["ssh", "shell"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op3.canonical_for_signing());

        let target2 = CapTarget::Device([0x22; 32]);
        let op4 = make_grant(&owner, target2, &header.resource, &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op4.canonical_for_signing());

        let op5 = make_grant(&owner, target, "admin", &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op5.canonical_for_signing());

        let op_user = make_grant(&owner, CapTarget::User([0x11; 32]), &header.resource, &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op_user.canonical_for_signing());
    }

    // -- JSON roundtrip -----------------------------------------------------

    #[test]
    fn grant_json_roundtrip() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let target = CapTarget::Device([0x42; 32]);
        let v = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["send", "receive"], v, 86400);

        let j = grant.to_json();
        let grant2 = CapOp::from_json(&j).unwrap();
        assert_eq!(grant.grantor, grant2.grantor);
        assert_eq!(grant.target, grant2.target);
        assert_eq!(grant.resource, grant2.resource);
        assert_eq!(grant.permissions, grant2.permissions);
        assert_eq!(grant.expires, grant2.expires);
        assert_eq!(grant.issued_at, grant2.issued_at);
        assert_eq!(grant.version, grant2.version);
        assert_eq!(grant.sig, grant2.sig);

        let pk = owner_pub(&owner);
        grant2.verify(&pk, now_secs()).unwrap();
    }

    #[test]
    fn header_json_roundtrip() {
        let owner = make_owner();
        let nonce = [0xab; 32];
        let header = make_genesis_header(
            &owner,
            &nonce,
            &[CapFloor {
                target_kind: CapTarget::Device([0xaa; 32]).kind_byte(),
                target: [0xaa; 32],
                min_version: 123,
            }],
        );
        let j = header.to_json();
        let header2 = CapHeader::from_json(&j).unwrap();
        assert_eq!(header.resource, header2.resource);
        assert_eq!(header.epoch, header2.epoch);
        assert_eq!(header.owner_pub, header2.owner_pub);
        assert_eq!(header.nonce, header2.nonce);
        assert_eq!(header.floors.len(), header2.floors.len());
        assert_eq!(header.issued_at, header2.issued_at);
        assert_eq!(header.prev_owner_pub, header2.prev_owner_pub);
        assert_eq!(header.sig, header2.sig);
        header2.verify_genesis().unwrap();
    }

    // -- Multi-resource -----------------------------------------------------

    #[test]
    fn cross_resource_independent_keys() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);
        let v1 = hlc_next(0, now_ms());
        let grant_shell = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let grant_transfer = make_grant(&owner, target, "transfer", &["send"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_shell, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &grant_transfer, now_secs()).unwrap();
        let grant_count = store.iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant"))
            .count();
        assert_eq!(grant_count, 2); // shell + transfer
    }

    // -- HLC ----------------------------------------------------------------

    #[test]
    fn hlc_seeds_from_wall_clock_not_zero() {
        let v = hlc_next(0, now_ms());
        assert!(v > 0);
        let v2 = hlc_next(v, now_ms());
        assert!(v2 > v);
    }

    // -- B1 evaluate() authorization ----------------------------------------

    #[test]
    fn evaluate_owner_authorized() {
        let alice = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&alice, &nonce, &[]);
        let store = init_store(&header);

        let device_pub = [0xff; 32];
        let user_pub = owner_pub(&alice);

        let d = evaluate(&store, &header, &device_pub, &user_pub, &header.resource, "ssh", now_secs(), None);
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("owner must be authorized, got: {}", reason),
        }
    }

    #[test]
    fn evaluate_granted_action_ok() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh", "shell"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principal_user = [0xaa; 32]; // different user, not the owner
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs(), None);
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("granted action must be authorized, got: {}", reason),
        }
    }

    #[test]
    fn evaluate_ungranted_denied() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principal_user = [0xaa; 32];
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "admin", now_secs(), None);
        match d {
            Decision::Denied(_) => {},
            Decision::Authorized => panic!("ungranted action must be denied"),
        }
    }

    #[test]
    fn evaluate_expired_denied() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let issued_at = now_secs().saturating_sub(86401);
        let mut grant = CapOp {
            op: CapOpKind::Grant,
            grantor: pk,
            target_kind: target.kind_byte(),
            target: target.target_bytes(),
            resource: header.resource.clone(),
            permissions: vec!["ssh".to_string()],
            expires: issued_at.saturating_add(86400),
            issued_at,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        grant.sig = sign_cap_op(&grant, &owner);

        let mut store = init_store(&header);
        // Grant expired, but apply_cap_op doesn't check expiry — that's evaluate's job
        // We need to apply a non-expired op first so ratchet is initialized
        let v = hlc_next(0, now_ms());
        let fresh = make_grant(&owner, target, &header.resource, &["ssh"], v, 86400);
        apply_cap_op(&mut store, &header, &fresh, now_secs()).unwrap();

        let principal_user = [0xaa; 32];
        // fresh grant covers "ssh", expired grant is not there — test evaluates against stored grants
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs(), None);
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("non-expired grant must be authorized, got: {}", reason),
        }

        // Now test with an expired grant
        let mut expired_store = init_store(&header);
        // Store the expired grant directly (bypassing apply_cap_op's monotonicity)
        let mut expired_entry = grant.to_json();
        expired_entry["type"] = Value::from("cap_grant");
        expired_store.push(expired_entry);

        // evaluate should see the grant but consider it expired
        let d2 = evaluate(&expired_store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs(), None);
        match d2 {
            Decision::Denied(reason) => assert!(reason.contains("not authorized"), "expired-only store must be denied: {}", reason),
            Decision::Authorized => panic!("expired grant must be denied"),
        }
    }

    #[test]
    fn evaluate_expired_grant_does_not_shadow_valid_grant() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let device_target = CapTarget::Device([0xcc; 32]);
        let user_pub = [0xaa; 32];
        let user_target = CapTarget::User(user_pub);
        let header = make_genesis_header(&owner, &nonce, &[]);

        // Expired Device grant (will be skipped)
        let expired_issued = now_secs().saturating_sub(86401);
        let mut expired_grant = CapOp {
            op: CapOpKind::Grant,
            grantor: owner_pub(&owner),
            target_kind: device_target.kind_byte(),
            target: device_target.target_bytes(),
            resource: header.resource.clone(),
            permissions: vec!["ssh".to_string()],
            expires: expired_issued.saturating_add(86400),
            issued_at: expired_issued,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        expired_grant.sig = sign_cap_op(&expired_grant, &owner);

        // Valid User grant
        let v = hlc_next(0, now_ms());
        let user_grant = make_grant(&owner, user_target, &header.resource, &["ssh"], v, 86400);

        let mut store = init_store(&header);
        // Push expired grant first
        let mut expired_entry = expired_grant.to_json();
        expired_entry["type"] = Value::from("cap_grant");
        store.push(expired_entry);
        // Then valid User grant via apply_cap_op
        apply_cap_op(&mut store, &header, &user_grant, now_secs()).unwrap();

        // A principal with device=0xcc and user=0xaa matches BOTH grants.
        // The expired Device grant must NOT shadow the valid User grant.
        let d = evaluate(&store, &header, &[0xcc; 32], &user_pub, &header.resource, "ssh", now_secs(), None);
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("valid User grant must authorize despite expired Device grant: {}", reason),
        }
    }

    #[test]
    fn evaluate_wrong_target_denied() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principal_user = [0xaa; 32];
        // Wrong device pubkey
        let d = evaluate(&store, &header, &[0xdd; 32], &principal_user, &header.resource, "ssh", now_secs(), None);
        match d {
            Decision::Denied(_) => {},
            Decision::Authorized => panic!("wrong target device must be denied"),
        }
    }

    #[test]
    fn evaluate_user_grant_matches_device() {
        // target_kind=User: a device chaining to that user_pub is authorized
        let owner = make_owner();
        let nonce = [0x01; 32];
        let principal_user_pub = [0xaa; 32];
        let target = CapTarget::User(principal_user_pub);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        // Any device pubkey works when target_kind=User and principal_user_pub matches
        let d = evaluate(&store, &header, &[0x11; 32], &principal_user_pub, &header.resource, "ssh", now_secs(), None);
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("User grant must authorize device chaining to that user, got: {}", reason),
        }

        // Wrong user_pub must be denied even with correct device
        let d2 = evaluate(&store, &header, &[0x11; 32], &[0xbb; 32], &header.resource, "ssh", now_secs(), None);
        match d2 {
            Decision::Denied(_) => {},
            Decision::Authorized => panic!("wrong user must be denied"),
        }
    }

    #[test]
    fn evaluate_ratchet_uninitialized_denies() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        // Store has the header (via init_store which calls apply_header → update_ratchet)
        // So ratchet IS initialized. To test uninitialized, construct a store without the ratchet.
        let mut store: Vec<Value> = vec![];
        // Manually add header without ratchet
        let mut hdr_json = header.to_json();
        hdr_json["type"] = Value::from("cap_header");
        store.push(hdr_json);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let mut grant_json = grant.to_json();
        grant_json["type"] = Value::from("cap_grant");
        store.push(grant_json);

        let principal_user = [0xaa; 32];
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs(), None);
        match d {
            Decision::Denied(reason) => assert!(reason.contains("ratchet"), "must fail on uninitialized ratchet: {}", reason),
            Decision::Authorized => panic!("uninitialized ratchet must deny grants"),
        }

        // But owner is still authorized even with uninitialized ratchet
        let owner_pubkey = owner_pub(&owner);
        let d2 = evaluate(&store, &header, &[0x00; 32], &owner_pubkey, &header.resource, "ssh", now_secs(), None);
        match d2 {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("owner must be authorized even without ratchet, got: {}", reason),
        }
    }

    #[test]
    fn evaluate_clock_set_back_uses_ratchet() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        // Create a grant with a future issued_at (within skew) to advance ratchet
        let future_issued = now_secs() + 100;
        let future_expires = future_issued + 86400;
        let mut grant = CapOp {
            op: CapOpKind::Grant,
            grantor: owner_pub(&owner),
            target_kind: target.kind_byte(),
            target: target.target_bytes(),
            resource: header.resource.clone(),
            permissions: vec!["ssh".to_string()],
            expires: future_expires,
            issued_at: future_issued,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        grant.sig = sign_cap_op(&grant, &owner);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        // Now test with `now` set behind the ratchet (clock went backwards)
        let clock_back_now = future_issued.saturating_sub(50);
        let principal_user = [0xaa; 32];
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", clock_back_now, None);
        // eval_time = max(clock_back_now, ratchet) = ratchet (future_issued)
        // grant.expires = future_issued + 86400
        // eval_time (future_issued) < grant.expires (future_issued + 86400) -> authorized
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("clock set back must still authorize via ratchet, got: {}", reason),
        }
    }

    // -- B2 per-owner ratchet -----------------------------------------------

    #[test]
    fn ratchet_per_owner_isolation() {
        let alice = make_owner();
        let bob = make_owner();
        let nonce_a = [0x01; 32];
        let nonce_b = [0x02; 32];
        let target = CapTarget::Device([0xcc; 32]);

        let header_a = make_genesis_header(&alice, &nonce_a, &[]);
        let header_b = make_genesis_header(&bob, &nonce_b, &[]);

        let mut store = init_store(&header_a);
        // Use a combined store with both headers and ratchets
        // Bob's future issued_at must NOT expire Alice's grants

        // Bob issues a grant with a far-future issued_at (but within skew)
        let future_issued = now_secs() + 100;
        let mut bob_grant = CapOp {
            op: CapOpKind::Grant,
            grantor: owner_pub(&bob),
            target_kind: target.kind_byte(),
            target: [0xdd; 32],
            resource: header_b.resource.clone(),
            permissions: vec!["ssh".to_string()],
            expires: future_issued + 86400,
            issued_at: future_issued,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        bob_grant.sig = sign_cap_op(&bob_grant, &bob);

        // Initialize Bob's header and apply his grant
        apply_header(&mut store, &header_b).unwrap();
        apply_cap_op(&mut store, &header_b, &bob_grant, now_secs()).unwrap();

        // Alice's grant with now-ish issued_at
        let v1 = hlc_next(0, now_ms());
        let alice_grant = make_grant(&alice, target, &header_a.resource, &["ssh"], v1, 86400);
        apply_cap_op(&mut store, &header_a, &alice_grant, now_secs()).unwrap();

        // Bob's ratchet is at future_issued. Alice's ratchet should be her own.
        // evaluate Alice's grant: ratchet_for(Alice's owner) != future_issued
        let principal_user = [0xaa; 32];
        let d = evaluate(&store, &header_a, &[0xcc; 32], &principal_user, &header_a.resource, "ssh", now_secs(), None);
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("Bob's ratchet must not expire Alice's grant: {}", reason),
        }
    }

    #[test]
    fn ratchet_far_future_clamp() {
        let owner = make_owner();
        let far_future = now_secs() + MAX_SKEW_SECS + 1;
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let mut store = init_store(&header);
        let res = update_ratchet(&mut store, &owner_pub(&owner), far_future);
        assert!(res.is_err(), "far-future issued_at must be rejected");
    }

    /// The flip criterion is code, not prose: a clean legacy-ALLOWED sample with
    /// everything provisioned is ready; a bare zero total, a real disagreement, or
    /// any unprovisioned resource each block the flip. Pure (no global atomics), so
    /// it is not subject to the parallel-test interference the process-global
    /// counters would have.
    #[test]
    fn shadow_flip_criterion() {
        let ready = ShadowCounts { la_authorized: 5, la_denied: 0, la_no_header: 0, ld_authorized: 2, ld_denied: 3, ld_no_header: 0, ceiling_denied: 0 };
        assert!(ready.flip_ready(), "clean legacy-allowed sample, all provisioned, must be flip-ready");
        let empty = ShadowCounts { la_authorized: 0, la_denied: 0, la_no_header: 0, ld_authorized: 0, ld_denied: 0, ld_no_header: 0, ceiling_denied: 0 };
        assert!(!empty.flip_ready(), "no sample yet: a bare zero total must NOT pass");
        let disagree = ShadowCounts { la_authorized: 10, la_denied: 1, la_no_header: 0, ld_authorized: 0, ld_denied: 0, ld_no_header: 0, ceiling_denied: 0 };
        assert!(!disagree.flip_ready(), "a real header disagreement must block the flip");
        let unprov = ShadowCounts { la_authorized: 10, la_denied: 0, la_no_header: 4, ld_authorized: 0, ld_denied: 0, ld_no_header: 0, ceiling_denied: 0 };
        assert!(!unprov.flip_ready(), "an unprovisioned resource must block the flip (absent != clean)");
        assert!(disagree.summary().contains("flip_ready=false"));
    }

    /// Grant must initialize the per-owner ratchet so evaluate() never hits
    /// "ratchet uninitialized". The grant command in main.rs constructs CapOp
    /// and CapHeader JSON directly (not via apply_cap_op / apply_header), so
    /// it must explicitly call update_ratchet. Without it, a freshly-granted
    /// resource always denies.
    #[test]
    fn grant_initializes_ratchet() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let nonce = [0x01; 32];
        // A DIFFERENT principal, not the owner, so evaluate() must scan grants.
        let principal = make_owner();
        let principal_pub = owner_pub(&principal);
        let target = CapTarget::Device(principal_pub);

        // Simulate the grant-command path: push header + grant JSON directly
        // without apply_header / apply_cap_op (so no ratchet side-effect).
        let mut store = Vec::new();
        let header = make_genesis_header(&owner, &nonce, &[]);
        let header_json = header.to_json();
        store.push(header_json);

        let v1 = hlc_next(0, now_ms());
        let mut grant = make_grant(&owner, target, &header.resource, &["shell"], v1, 86400);
        grant.sig = sign_cap_op(&grant, &owner);
        let mut grant_json = grant.to_json();
        grant_json["type"] = serde_json::Value::from("cap_grant");
        store.push(grant_json);

        // Before update_ratchet: evaluate must deny ("ratchet uninitialized")
        match evaluate(&store, &header, &target.target_bytes(), &principal_pub, &header.resource, "shell", now_secs(), None) {
            Decision::Denied(reason) => assert!(reason.contains("ratchet uninitialized")),
            Decision::Authorized => panic!("evaluate must refuse before ratchet is initialized"),
        }
        // After update_ratchet: evaluate must authorize
        update_ratchet(&mut store, &pk, grant.issued_at).unwrap();
        match evaluate(&store, &header, &target.target_bytes(), &principal_pub, &header.resource, "shell", now_secs(), None) {
            Decision::Authorized => {}
            Decision::Denied(reason) => panic!("evaluate must authorize after ratchet init, got: {reason}"),
        }
    }

    /// Grant must target the peer's real user_pub, not SHA-256 of the device
    /// name. evaluate() matches User-target grants against principal_user_pub
    /// (an Ed25519 key), so a name hash never matches.
    #[test]
    fn grant_target_user_pub_not_name_hash() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        // A different principal (the grantee) with a real user_pub
        let principal = make_owner();
        let principal_pub = owner_pub(&principal);

        // The name-hash approach (old bug): SHA-256("root@do-vm") never matches
        use sha2_pake::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"root@do-vm");
        let name_hash = h.finalize();
        let mut name_hash_arr = [0u8; 32];
        name_hash_arr.copy_from_slice(&name_hash);
        assert_ne!(&name_hash_arr[..], &principal_pub[..],
            "SHA-256(device_name) must not equal the user_pub");

        // The correct approach: target = principal_pub (the real user key)
        let target = CapTarget::User(principal_pub);
        let mut store = init_store(&header);
        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["shell"], v1, 86400);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        // evaluate() with the principal's user_pub must authorize
        match evaluate(&store, &header, &principal_pub, &principal_pub, &header.resource, "shell", now_secs(), None) {
            Decision::Authorized => {}
            Decision::Denied(reason) => panic!("grant targeting real user_pub must authorize, got: {reason}"),
        }
        // evaluate() with a WRONG user_pub must deny
        let wrong_pub = [0xbb; 32];
        assert_ne!(&wrong_pub[..], &principal_pub[..]);
        match evaluate(&store, &header, &wrong_pub, &wrong_pub, &header.resource, "shell", now_secs(), None) {
            Decision::Authorized => panic!("wrong user_pub must NOT authorize"),
            Decision::Denied(_) => {}
        }
    }

    // -- B4 preview + self-lockout ------------------------------------------

    #[test]
    fn preview_matches_enforcement() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);
        let v1 = hlc_next(0, now_ms());
        let principal_user = [0xaa; 32];

        // Store with one grant
        let mut store = init_store(&header);
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        // Preview applying a revoke of that grant
        let v2 = hlc_next(v1, now_ms());
        let revoke = make_revoke(&owner, target, &header.resource, v2, 86400);
        let revoke2 = revoke.clone();

        let queries = vec![
            AuthQuery {
                principal_device_pub: [0xcc; 32],
                principal_user_pub: principal_user,
                action: "ssh".to_string(),
            },
        ];

        let preview_results = preview(&store, &header, &[revoke2], &queries, now_secs());
        assert!(!preview_results[0].authorized, "preview of revoke must show Denied");

        // Apply revoke for real and evaluate — must match preview
        apply_cap_op(&mut store, &header, &revoke, now_secs()).unwrap();
        let real_d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs(), None);
        assert!(matches!(real_d, Decision::Denied(_)), "real enforcement must match preview");

        // No-op preview: should show Authorized (preview doesn't mutate store)
        let mut store2 = init_store(&header);
        apply_cap_op(&mut store2, &header, &grant, now_secs()).unwrap();
        let preview_current = preview(&store2, &header, &[], &queries, now_secs());
        assert!(preview_current[0].authorized, "preview of no-op must show Authorized for existing grant");
    }

    #[test]
    fn self_lockout_warns_on_admin_loss() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let v2 = hlc_next(v1, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["admin", "ssh"], v1, 86400);
        let narrow = make_grant(&owner, target, &header.resource, &["ssh"], v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principals = vec![(
            "bob".to_string(),
            [0xcc; 32],
            [0xaa; 32],
        )];

        // Narrowing from ["admin","ssh"] to ["ssh"] loses "admin"
        let warnings = check_self_lockout(
            &store, &header, &narrow, &principals, &["admin", "ssh", "shell"], now_secs(),
        );
        assert!(!warnings.is_empty(), "must warn when admin action is lost");
        assert!(warnings[0].contains("admin"), "warning must mention the lost action");
    }

    #[test]
    fn self_lockout_no_warn_on_gain() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let v2 = hlc_next(v1, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let expand = make_grant(&owner, target, &header.resource, &["ssh", "admin"], v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principals = vec![("bob".to_string(), [0xcc; 32], [0xaa; 32])];

        // Expanding grants must NOT warn (no loss)
        let warnings = check_self_lockout(
            &store, &header, &expand, &principals, &["admin"], now_secs(),
        );
        assert!(warnings.is_empty(), "must not warn when gaining access");
    }

    /// Transfer gate: under authoritative + Deny → hard-decline (Some(reason));
    /// under shadow + Deny → fall through (None, legacy consent path decides).
    #[test]
    fn transfer_gate_hard_decline_under_authoritative() {
        // Deny with a cap reason
        let deny = GateDecision::Deny {
            cap_reason: Some("not authorized".into()),
        };
        // Under authoritative: hard-decline with the real reason
        let r_auth = transfer_gate_decision(&deny, true);
        assert_eq!(r_auth, Some("not authorized".into()),
            "authoritative: must return Some(reason) to hard-decline");

        // Under shadow: fall through to legacy consent (None)
        let r_shadow = transfer_gate_decision(&deny, false);
        assert!(r_shadow.is_none(), "shadow: must fall through");

        // Deny with no reason string (structurally fail-closed)
        let deny_noreason = GateDecision::Deny { cap_reason: None };
        let r_noreason = transfer_gate_decision(&deny_noreason, true);
        assert_eq!(r_noreason, Some("capability denied".into()),
            "authoritative Deny without cap_reason must still hard-decline (fail-closed)");

        // Allow always returns None
        assert!(transfer_gate_decision(&GateDecision::Allow, true).is_none());
        assert!(transfer_gate_decision(&GateDecision::Allow, false).is_none());
    }

    #[test]
    fn cap_authorize_proven_purely_restrictive() {
        // All arms: (Authorized/Denied/Unprovisioned) × (Proven/Inferred/None) × (auth/shadow)
        let auth = CapOutcome::Authorized;
        let deny = CapOutcome::Denied("no grant".into());
        let unprov = CapOutcome::Unprovisioned;

        // Authorized + Proven + authoritative → passes through
        assert_eq!(cap_authorize_proven(&auth, BindingStrength::Proven, true), CapOutcome::Authorized);
        // Authorized + Inferred + authoritative → downgraded
        assert!(matches!(cap_authorize_proven(&auth, BindingStrength::Inferred, true), CapOutcome::Denied(_)));
        // Authorized + None + authoritative → downgraded
        assert!(matches!(cap_authorize_proven(&auth, BindingStrength::None, true), CapOutcome::Denied(_)));
        // Authorized + Inferred + shadow → passes through (no downgrade)
        assert_eq!(cap_authorize_proven(&auth, BindingStrength::Inferred, false), CapOutcome::Authorized);
        // Denied + Inferred + authoritative → stays Denied (no laundering)
        assert_eq!(cap_authorize_proven(&deny, BindingStrength::Inferred, true), deny);
        // Unprovisioned + Inferred + authoritative → stays Unprovisioned
        assert_eq!(cap_authorize_proven(&unprov, BindingStrength::Inferred, true), unprov);
    }

    #[test]
    fn cap_authorize_expired_purely_restrictive() {
        let auth = CapOutcome::Authorized;
        let deny = CapOutcome::Denied("no grant".into());

        let future = now_secs() + 86400;
        let past = now_secs().saturating_sub(86400);

        // Authorized + valid cert + authoritative → passes
        assert_eq!(cap_authorize_expired(&auth, Some(future), true), CapOutcome::Authorized);
        // Authorized + expired cert + authoritative → downgraded
        assert!(matches!(cap_authorize_expired(&auth, Some(past), true), CapOutcome::Denied(_)));
        // Authorized + None expiry + authoritative → downgraded (fail-closed)
        assert!(matches!(cap_authorize_expired(&auth, None, true), CapOutcome::Denied(_)));
        // Authorized + expired + shadow → passes through
        assert_eq!(cap_authorize_expired(&auth, Some(past), false), CapOutcome::Authorized);
        // Denied + expired + authoritative → stays Denied
        assert_eq!(cap_authorize_expired(&deny, Some(past), true), deny);
    }

    #[test]
    fn cap_authorize_proven_expired_composed() {
        let auth = CapOutcome::Authorized;
        let future = now_secs() + 86400;
        let past = now_secs().saturating_sub(86400);

        // Proven + valid → passes
        let r = cap_authorize_proven(&auth, BindingStrength::Proven, true);
        assert_eq!(cap_authorize_expired(&r, Some(future), true), CapOutcome::Authorized);

        // Inferred + valid → denied (proven gate wins)
        let r2 = cap_authorize_proven(&auth, BindingStrength::Inferred, true);
        assert!(matches!(r2, CapOutcome::Denied(_)));

        // Proven + expired → denied (expiry gate wins)
        let r3 = cap_authorize_proven(&auth, BindingStrength::Proven, true);
        assert!(matches!(cap_authorize_expired(&r3, Some(past), true), CapOutcome::Denied(_)));
    }

    #[test]
    fn cap_trust_floor_purely_restrictive() {
        let auth = CapOutcome::Authorized;
        let deny = CapOutcome::Denied("no grant".into());
        let inferred = BindingStrength::Inferred;

        // Authoritative + untrusted + Inferred + Authorized → Denied
        assert!(matches!(cap_trust_floor(&auth, false, inferred, true), CapOutcome::Denied(_)));
        // Authoritative + trusted + Inferred + Authorized → passes through
        assert_eq!(cap_trust_floor(&auth, true, inferred, true), CapOutcome::Authorized);
        // Shadow + untrusted + Inferred + Authorized → passes through
        assert_eq!(cap_trust_floor(&auth, false, inferred, false), CapOutcome::Authorized);
        // Proven binding alone passes the floor even without link.trusted
        assert_eq!(cap_trust_floor(&auth, false, BindingStrength::Proven, true), CapOutcome::Authorized);
        // Denied + untrusted + authoritative → stays Denied
        assert_eq!(cap_trust_floor(&deny, false, inferred, true), deny);
    }

    // ----------------------------------------------------------------------
    // Fleet auto-trust (same-owner Proven-gated scoped defaults)
    // ----------------------------------------------------------------------

    /// The scoped-default classifier: transfer/mount are auto-grantable
    /// to a same-owner Proven device; the deliberate tier is not.
    #[test]
    fn is_scoped_default_action_classifies_tiers() {
        assert!(is_scoped_default_action("transfer"));
        assert!(is_scoped_default_action("mount"));
        // Deliberate tier and unknowns are never auto.
        assert!(!is_scoped_default_action("shell"));
        assert!(!is_scoped_default_action("write-mount"));
        assert!(!is_scoped_default_action("anything-else"));
    }

    /// The Proven-gate is the load-bearing rule: fleet auto-trust fires for a
    /// same-owner device ONLY on Proven AND in-scope, and NEVER on Inferred/None,
    /// out-of-scope, or a different owner.
    #[test]
    fn fleet_auto_trust_matrix() {
        // same-owner Proven + in-scope → auto-trust
        assert!(fleet_auto_trust(true, BindingStrength::Proven, true, true));
        // same-owner Proven + OUT of scope → no auto-trust (deliberate/out-of-bounds)
        assert!(!fleet_auto_trust(true, BindingStrength::Proven, false, true));
        // same-owner INFERRED + in-scope → NOTHING (the Proven gate)
        assert!(!fleet_auto_trust(true, BindingStrength::Inferred, true, true));
        // same-owner None + in-scope → NOTHING
        assert!(!fleet_auto_trust(true, BindingStrength::None, true, true));
        // DIFFERENT owner + Proven + in-scope → deny-by-default (not my fleet)
        assert!(!fleet_auto_trust(false, BindingStrength::Proven, true, true));
        // A local revocation must disable automatic fleet trust independently.
        assert!(!fleet_auto_trust(true, BindingStrength::Proven, true, false));
    }

    /// `evaluate_grants_only` must NOT apply the owner shortcut: a peer that
    /// merely shares the owner user key gets NOTHING without an explicit grant,
    /// where `evaluate` (with the shortcut) would authorize everything. This is
    /// the finding-#24 fix that lets the gate deny the deliberate tier to a
    /// same-owner device that has no grant.
    #[test]
    fn evaluate_grants_only_ignores_owner_shortcut() {
        let owner = make_owner();
        let owner_pk = owner_pub(&owner);
        let nonce = [7u8; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut store = init_store(&header);
        let resource = header.resource.clone();
        let dev = [0xdd; 32];
        let now = now_secs();

        // Baseline: evaluate() applies the owner shortcut → same-owner authorized
        // for a deliberate action even with no grant.
        assert!(matches!(
            evaluate(&store, &header, &dev, &owner_pk, &resource, "shell", now, None),
            Decision::Authorized
        ), "evaluate owner shortcut authorizes same-owner");

        // evaluate_grants_only: same-owner, no grant → DENIED (shortcut skipped).
        assert!(matches!(
            evaluate_grants_only(&store, &header, &dev, &owner_pk, &resource, "shell", now, None),
            Decision::Denied(_)
        ), "grants-only must not apply the owner shortcut");

        // With an explicit device grant for transfer, grants-only authorizes
        // transfer for that device but still NOT shell.
        let grant = make_grant(&owner, CapTarget::Device(dev), &resource, &["transfer"], hlc_next(0, now_ms()), 86_400);
        apply_cap_op(&mut store, &header, &grant, now).unwrap();
        assert!(matches!(
            evaluate_grants_only(&store, &header, &dev, &owner_pk, &resource, "transfer", now, None),
            Decision::Authorized
        ), "explicit device grant authorizes transfer under grants-only");
        assert!(matches!(
            evaluate_grants_only(&store, &header, &dev, &owner_pk, &resource, "shell", now, None),
            Decision::Denied(_)
        ), "no shell grant → grants-only denies shell for same-owner device");
    }
}

#[cfg(test)]
mod route_scope_tests {
    use super::cidr_within_any;

    fn allow(v: &[&str]) -> Vec<String> { v.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn a_narrower_prefix_is_inside_a_wider_allowance() {
        assert!(cidr_within_any("10.66.0.0/24", &allow(&["10.0.0.0/8"])));
        assert!(cidr_within_any("10.0.0.0/8", &allow(&["10.0.0.0/8"])), "exact match");
    }

    /// The hole this scoping exists to close: a member must not be able to widen
    /// its own grant, and least of all into a default route.
    #[test]
    fn a_wider_prefix_is_refused() {
        assert!(!cidr_within_any("10.0.0.0/8", &allow(&["10.66.0.0/24"])));
        assert!(!cidr_within_any("0.0.0.0/0", &allow(&["10.66.0.0/24"])));
        assert!(!cidr_within_any("0.0.0.0/0", &allow(&["10.0.0.0/8"])));
    }

    /// An exit node is legitimate only when the owner said 0.0.0.0/0.
    #[test]
    fn a_default_route_needs_a_default_route_allowance() {
        assert!(cidr_within_any("0.0.0.0/0", &allow(&["0.0.0.0/0"])));
        assert!(cidr_within_any("10.66.0.0/24", &allow(&["0.0.0.0/0"])), "0/0 allows anything v4");
    }

    #[test]
    fn a_different_network_is_refused() {
        assert!(!cidr_within_any("192.168.1.0/24", &allow(&["10.0.0.0/8"])));
    }

    #[test]
    fn families_do_not_cross() {
        assert!(!cidr_within_any("fd00::/8", &allow(&["0.0.0.0/0"])));
        assert!(!cidr_within_any("10.0.0.0/8", &allow(&["::/0"])));
        assert!(cidr_within_any("fd00:1::/32", &allow(&["fd00::/8"])));
    }

    #[test]
    fn an_empty_allowance_permits_nothing() {
        assert!(!cidr_within_any("10.0.0.0/24", &[]));
    }

    #[test]
    fn malformed_input_is_refused_not_guessed_at() {
        assert!(!cidr_within_any("not-a-cidr", &allow(&["10.0.0.0/8"])));
        assert!(!cidr_within_any("10.0.0.0/33", &allow(&["10.0.0.0/8"])));
        assert!(!cidr_within_any("10.0.0.0/24", &allow(&["garbage"])));
    }
}
