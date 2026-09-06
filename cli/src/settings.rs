//! Typed, discoverable persistent settings: the backing for `filament set`,
//! `filament get`, and `filament unset`.
//!
//! Design follows the evidence on world-class CLI config surfaces (clig.dev,
//! the 12-factor CLI doc, and how git/gh/aws actually behave), chosen over the
//! Tailscale `set --flag` model after its own maintainers documented that the
//! flag model "tries to safely do a bad job" at being both declarative and
//! imperative (tailscale/tailscale#15460):
//!
//!  - `key value` is the canonical surface (git/gh/npm/aws lineage): it scales
//!    without flag explosion and stays compatible with the legacy
//!    `filament config <key> <value>` file (`key value` lines).
//!  - `set` is strictly imperative and PARTIAL: it touches only the key you
//!    name, never resetting anything you did not mention (the exact Tailscale
//!    bug, designed out here).
//!  - Resolution precedence is a fixed ladder, surfaced via provenance like
//!    git's `--show-origin` / aws's TYPE/LOCATION:
//!        env  >  per-peer override  >  global config  >  built-in default
//!  - Humans first, machines second: a TTY gets an aligned, colored table; a
//!    pipe gets tab-separated `key<TAB>value<TAB>scope` rows with no color and
//!    no borders; `--json` gives the complete structured view either way.
//!  - Values go to stdout, all messaging/confirmation to stderr, so
//!    `$(filament get drop-dir)` is exactly the value.
//!
//! Storage: global settings live in the existing `config` file (one `key value`
//! line each, so name/server/dir stay byte-compatible with the old `config`
//! command and its readers). Per-peer overrides live alongside in `peerconf`
//! (JSON: `{ "<device>": { "<key>": "<value>" } }`).

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::ui;

// --------------------------------------------------------------- registry --

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Bool,
    Str,
    Path,
    Enum(&'static [&'static str]),
    /// Comma-separated list; each item is validated by the setting's own
    /// parse fn (e.g. interface name, CIDR, or friendly group).
    List,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ScopeKind {
    /// Global only (a single machine-wide value).
    GlobalOnly,
    /// Global default, optionally overridden per known device via `--peer`.
    GlobalOrPeer,
}

pub struct Setting {
    /// Canonical name (what the readout prints, what `--peer` keys on).
    pub key: &'static str,
    /// Accepted alternate spellings (for input + did-you-mean).
    pub aliases: &'static [&'static str],
    /// On-disk key (legacy-compatible: drop-dir stores as `dir`).
    pub store: &'static str,
    pub kind: Kind,
    /// Built-in default rendered value (some keys compute it; see `effective_default`).
    pub default: &'static str,
    pub scope: ScopeKind,
    /// Environment variable that overrides everything (highest precedence).
    pub env: Option<&'static str>,
    /// True when the running `up` daemon must restart to pick the change up.
    pub daemon: bool,
    pub help: &'static str,
}

const RELAY_VALS: &[&str] = &["auto", "always", "never"];
const L3_MODE_VALS: &[&str] = &["auto", "kernel", "userspace"];

pub fn registry() -> &'static [Setting] {
    static R: &[Setting] = &[
        Setting {
            key: "name",
            aliases: &[],
            store: "name",
            kind: Kind::Str,
            default: "",
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_NAME"),
            daemon: true,
            help: "Display name other devices see (default: your platform username@hostname)",
        },
        Setting {
            key: "server",
            aliases: &["signaling"],
            store: "server",
            kind: Kind::Str,
            default: crate::DEFAULT_SERVER,
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_SERVER"),
            daemon: true,
            help: "Signaling server URL",
        },
        Setting {
            key: "drop-dir",
            aliases: &["dir"],
            store: "dir",
            kind: Kind::Path,
            default: "~/Filament",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "Where received files are saved",
        },
        Setting {
            key: "relay",
            aliases: &[],
            store: "relay",
            kind: Kind::Enum(RELAY_VALS),
            default: "auto",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: true,
            help: "Relay policy: auto (direct, fall back to relay), always (force TURN), never (direct-only). Per-peer: filament set relay never --peer dovm",
        },
        Setting {
            key: "shell-program",
            aliases: &[],
            store: "shell-program",
            kind: Kind::Str,
            default: "",
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_SHELL"),
            daemon: true,
            help: "Shell program for PTY sessions (e.g. \"bash -l\", \"pwsh -NoLogo\"). Args allowed. Overrides platform default.",
        },
        Setting {
            key: "prefer",
            aliases: &["via"],
            store: "prefer",
            kind: Kind::List,
            default: "",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: false,
            help: "Interfaces to prefer, in order: interface name (wl1, eth0), friendly group (wifi, ethernet), or CIDR (100.64.0.0/10). Non-preferred interfaces are still used as fallback.",
        },
        Setting {
            key: "avoid",
            aliases: &["exclude"],
            store: "interfaces",
            kind: Kind::List,
            default: "",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: false,
            help: "Deny-list (open set): interfaces or subnets never to use. Complements only/include — setting either replaces the membership config.",
        },
        Setting {
            key: "only",
            aliases: &["include"],
            store: "interfaces",
            kind: Kind::List,
            default: "",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: false,
            help: "Allow-list (closed set): only these interfaces or subnets are eligible. Complements avoid — setting either replaces the membership config.",
        },
        // Subnet routing. Two settings because advertising and accepting are
        // different trust decisions made by different people: the router's owner
        // decides what to offer, and each peer's owner decides whether to believe
        // it. Collapsing them into one flag would make believing automatic.
        Setting {
            key: "advertise-routes",
            aliases: &["advertise"],
            store: "advertise-routes",
            kind: Kind::List,
            default: "",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "CIDRs this machine can reach and offers to carry for peers (a subnet router). Reaching a LAN needs this on the machine that sits on it; peers additionally need accept-routes for this device.",
        },
        Setting {
            key: "route-snat",
            aliases: &["masquerade"],
            kind: Kind::Bool,
            store: "route-snat",
            // ON by default: a LAN host replying to an overlay address it has no
            // route for is the common case, and without masquerading the reply is
            // simply lost. Off is correct only when the LAN routes back to the
            // overlay, which is the rarer, deliberate setup.
            default: "on",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "Masquerade forwarded subnet traffic as this machine, so LAN hosts can reply without a route back to the overlay. Turn off only if the LAN already routes to your overlay range.",
        },
        Setting {
            key: "wireguard",
            aliases: &["wg"],
            store: "wireguard",
            kind: Kind::Bool,
            // OFF by default because it changes the DATA PLANE. The QUIC
            // datagram path is what every gate measures and what works without
            // privilege; WireGuard needs the module, the tools and
            // CAP_NET_ADMIN, and silently switching the plane a user's traffic
            // rides on is not something a default should do.
            default: "off",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "Carry overlay traffic to DIRECT peers over kernel WireGuard instead of QUIC datagrams. Linux only, needs wireguard-tools and CAP_NET_ADMIN; falls back to the QUIC path per peer when unavailable.",
        },
        Setting {
            key: "accept-routes",
            aliases: &["accept"],
            store: "accept-routes",
            kind: Kind::Bool,
            // DEFAULT OFF, and this is the security property, not a preference.
            // An overlay ADDRESS is self-certifying: it derives from the peer's
            // key, so an announce proves it. A PREFIX does not derive from any
            // key, so "I can reach 10.0.0.0/24" is an unbacked claim, and any
            // peer could otherwise claim to be the path to your bank. Off until
            // a human says otherwise, per device.
            default: "off",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: true,
            help: "Install subnet routes advertised by a device. OFF by default: a prefix is a claim about what someone can reach, and unlike an overlay address it is not provable from their key. Scope it per device with --peer.",
        },
        Setting {
            key: "auto-extract",
            aliases: &["extract", "unzip"],
            store: "auto-extract",
            kind: Kind::Bool,
            default: "off",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: true,
            help: "Unpack received .tar/.tar.gz archives into the drop dir (off by default)",
        },
        Setting {
            key: "shell",
            aliases: &[],
            store: "shell",
            kind: Kind::Bool,
            default: "off",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: true,
            help: "Accept seamless `filament ssh` from paired devices (per-peer with --peer)",
        },
        Setting {
            key: "shell-user",
            aliases: &[],
            store: "shell-user",
            kind: Kind::Str,
            default: "",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "Drop the ssh/web-shell PTY to this non-root account (runuser)",
        },
        Setting {
            key: "sshd-overlay",
            aliases: &[],
            store: "sshd-overlay",
            kind: Kind::Bool,
            default: "off",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "Add L3 overlay addresses to sshd ListenAddress for L3 mounts",
        },
        Setting {
            key: "tun-addr",
            aliases: &["overlay"],
            store: "tun-addr",
            kind: Kind::Str,
            // DEFAULT-ON (2026-08-25). "auto" derives the address from the
            // overlay key, so a fresh install has an IP plane to its paired
            // devices without a second command. `filament init` asks for the
            // one-time CAP_NET_ADMIN grant so the common case is a real kernel
            // route; an unprivileged box still falls back to the userspace
            // netstack. Set to "" to turn L3 off.
            default: "auto",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "L3 overlay address as IP/PREFIX (e.g. 10.9.0.1/24), \"auto\" to derive it from your key, empty = L3 off",
        },
        Setting {
            key: "l3-mode",
            aliases: &[],
            store: "l3-mode",
            kind: Kind::Enum(L3_MODE_VALS),
            default: "auto",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "L3 backend: auto (kernel TUN when privileged, else userspace netstack), kernel (require the TUN), userspace (zero-privilege netstack; host firewall NOT enforced, expose honored)",
        },
        Setting {
            key: "warm-peers",
            aliases: &[],
            store: "warm-peers",
            kind: Kind::List,
            default: "",
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_WARM_PEERS"),
            daemon: true,
            help: "Peers to keep connected (comma-separated names). These stay warm for instant ssh/ping. Recently-used peers are also kept warm automatically (last 5).",
        },
        Setting {
            key: "auto-warm",
            aliases: &["warm-all"],
            store: "auto-warm",
            kind: Kind::Bool,
            default: "on",
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_AUTO_WARM"),
            daemon: true,
            help: "Keep a live link to every online paired peer so ssh/pty/ping are instant (Tailscale-style). Turn off to connect on demand only. Capped by warm-max.",
        },
        Setting {
            key: "warm-max",
            aliases: &[],
            store: "warm-max",
            kind: Kind::Str,
            default: "12",
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_WARM_MAX"),
            daemon: true,
            help: "Auto-warm at most this many online peers (most recently used win). Others stay discoverable via signaling and connect on demand.",
        },
        Setting {
            key: "auto-proxy",
            aliases: &[],
            store: "auto-proxy",
            kind: Kind::Bool,
            default: "on",
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_AUTO_PROXY"),
            daemon: true,
            help: "When kernel TUN is unavailable, auto-start a SOCKS5 proxy on port 1080 so native tools reach <peer>.mesh. Turn off with `filament set auto-proxy off`.",
        },
        Setting {
            key: "verbosity",
            aliases: &[],
            store: "verbosity",
            kind: Kind::Str,
            default: "info",
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_LOG"),
            daemon: false,
            help: "Default verbosity level: quiet (errors only), info (progress + results), debug (-v equivalent, route/tunnel), trace (-vv equivalent, ICE/per-frame). CLI flags override.",
        },
    ];
    R
}

/// Resolve a key (canonical or alias) to its `Setting`.
pub fn find(name: &str) -> Option<&'static Setting> {
    let n = name.trim();
    registry()
        .iter()
        .find(|s| s.key == n || s.aliases.contains(&n))
}

/// Closest known key name (canonical or alias) within edit-distance 2.
pub fn did_you_mean(name: &str) -> Option<&'static str> {
    let mut best: Option<(&'static str, usize)> = None;
    for s in registry() {
        for cand in std::iter::once(s.key).chain(s.aliases.iter().copied()) {
            let d = levenshtein(name, cand);
            if d <= 2 && best.map(|(_, bd)| d < bd).unwrap_or(true) {
                best = Some((s.key, d)); // suggest the canonical name
            }
        }
    }
    best.map(|(k, _)| k)
}

pub(crate) fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

// ------------------------------------------------------------------ store --

pub(crate) fn config_dir() -> PathBuf {
    crate::platform::Paths::config_dir()
}

fn global_path() -> PathBuf {
    config_dir().join("config")
}

fn peer_path() -> PathBuf {
    config_dir().join("peerconf")
}

fn global_get(store: &str) -> Option<String> {
    std::fs::read_to_string(global_path()).ok()?.lines().find_map(|l| {
        let (k, v) = l.split_once(char::is_whitespace)?;
        (k == store && !v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

fn global_put(store: &str, value: &str) -> Result<()> {
    let p = global_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut lines: Vec<String> = std::fs::read_to_string(&p)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(store))
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{store} {value}"));
    // Atomic write: temp file + rename (same as devices.json fix)
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, lines.join("\n") + "\n")?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

fn global_remove(store: &str) -> Result<bool> {
    let p = global_path();
    let Ok(raw) = std::fs::read_to_string(&p) else { return Ok(false) };
    let kept: Vec<&str> = raw
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(store))
        .collect();
    let removed = kept.len() != raw.lines().count();
    if removed {
        std::fs::write(&p, kept.join("\n") + if kept.is_empty() { "" } else { "\n" })?;
    }
    Ok(removed)
}

fn peer_load() -> serde_json::Map<String, Value> {
    std::fs::read_to_string(peer_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn peer_save(m: &serde_json::Map<String, Value>) -> Result<()> {
    crate::platform::SecretFile::write_str(&peer_path(), &serde_json::to_string_pretty(&Value::Object(m.clone()))?)?;
    Ok(())
}

fn peer_get(device: &str, store: &str) -> Option<String> {
    peer_load()
        .get(device)?
        .get(store)?
        .as_str()
        .map(|s| s.to_string())
}

// ------------------------------------------------------------- resolution --

#[derive(Clone)]
pub enum Origin {
    Env(&'static str),
    Peer(String),
    Global,
    Default,
}

impl Origin {
    fn label(&self) -> String {
        match self {
            Origin::Env(v) => format!("env:{v}"),
            Origin::Peer(d) => format!("peer:{d}"),
            Origin::Global => "config".into(),
            Origin::Default => "default".into(),
        }
    }
}

fn effective_default(s: &Setting) -> String {
    match s.key {
        "name" => crate::default_display_name(),
        "drop-dir" => crate::default_drop_dir().display().to_string(),
        _ => s.default.to_string(),
    }
}

/// Resolve the effective value of a setting and where it came from.
/// `peer` is consulted only for `GlobalOrPeer` settings.
pub fn resolve(s: &Setting, peer: Option<&str>) -> (String, Origin) {
    if let Some(ev) = s.env {
        if let Ok(v) = std::env::var(ev) {
            if !v.is_empty() {
                return (v, Origin::Env(ev));
            }
        }
    }
    if let Some(p) = peer {
        if s.scope == ScopeKind::GlobalOrPeer {
            if let Some(v) = peer_get(p, s.store) {
                return (decode_membership(s, v), Origin::Peer(p.to_string()));
            }
        }
    }
    if let Some(v) = global_get(s.store) {
        return (decode_membership(s, v), Origin::Global);
    }
    (effective_default(s), Origin::Default)
}

/// Decode the shared "interfaces" store or "prefer" store (JSON) into the
/// view appropriate for the requested key.
fn decode_store_value(s: &Setting, raw: String) -> String {
    if s.store == "interfaces" {
        if let Ok(obj) = serde_json::from_str::<Value>(&raw) {
            let mode = obj["m"].as_str().unwrap_or("");
            let items = obj["i"].as_str().unwrap_or("");
            let want_mode = match s.key {
                "avoid" | "exclude" => "avoid",
                "only" | "include" => "only",
                _ => "avoid",
            };
            if mode == want_mode { return items.to_string(); }
        }
        return String::new();
    }
    if s.store == "prefer" {
        if let Ok(obj) = serde_json::from_str::<Value>(&raw) {
            if let Some(order) = obj["o"].as_str() {
                return order.to_string();
            }
        }
    }
    raw
}

fn decode_membership(s: &Setting, raw: String) -> String {
    decode_store_value(s, raw)
}

// -- typed convenience for behavioral consumers (up/recv/relay wiring) ------

/// Effective boolean for a Bool key, peer-aware (peer override > global > default).
pub fn get_bool(key: &str, peer: Option<&str>) -> bool {
    let Some(s) = find(key) else { return false };
    truthy(&resolve(s, peer).0)
}

/// Effective string for a key, or None when it resolves to the empty default.
/// Read the prefer strength (soft|hard) from the raw store, or "soft" if unset.
pub fn prefer_strength(peer: Option<&str>) -> &'static str {
    let raw = if let Some(p) = peer {
        peer_get(p, "prefer").unwrap_or_default()
    } else {
        global_get("prefer").unwrap_or_default()
    };
    if let Ok(obj) = serde_json::from_str::<Value>(&raw) {
        if obj["s"].as_str() == Some("hard") {
            return "hard";
        }
    }
    "soft"
}

/// Read the RAW store value (no decode) for the interfaces membership config.
/// Returns the JSON string or empty so the filter can parse mode+items directly.
pub fn raw_membership(peer: Option<&str>) -> String {
    if let Some(p) = peer {
        if let Some(v) = peer_get(p, "interfaces") {
            return v;
        }
    }
    global_get("interfaces").unwrap_or_default()
}

/// Effective string for a key, or None when it resolves to the empty default.
pub fn get_str(key: &str, peer: Option<&str>) -> Option<String> {
    let s = find(key)?;
    let (v, origin) = resolve(s, peer);
    match origin {
        Origin::Default if v.is_empty() => None,
        _ => Some(v),
    }
}

/// Devices that have a per-peer override of `key` set to a truthy/eq value.
/// For Bool keys, `want` is "on"; used to fold per-peer shell into shell-only.
pub fn peers_with(key: &str, want: &str) -> Vec<String> {
    let Some(s) = find(key) else { return Vec::new() };
    let mut out = Vec::new();
    for (dev, kv) in peer_load() {
        if let Some(v) = kv.get(s.store).and_then(|v| v.as_str()) {
            if v == want {
                out.push(dev);
            }
        }
    }
    out.sort();
    out
}

fn truthy(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "on" | "true" | "yes" | "1")
}

// ------------------------------------------------------ validate / canon --

/// Canonicalize + validate a raw input value for a setting; returns the form
/// to persist, or a human error explaining what was expected.
fn canonicalize(s: &Setting, raw: &str) -> Result<String> {
    let raw = raw.trim();
    match s.kind {
        Kind::Bool => match raw.to_ascii_lowercase().as_str() {
            "on" | "true" | "yes" | "1" => Ok("on".into()),
            "off" | "false" | "no" | "0" => Ok("off".into()),
            _ => bail!("'{}' expects on/off (also true/false, yes/no, 1/0)", s.key),
        },
        Kind::Enum(vals) => {
            let lc = raw.to_ascii_lowercase();
            if vals.contains(&lc.as_str()) {
                Ok(lc)
            } else {
                bail!("'{}' expects one of: {}", s.key, vals.join(", "))
            }
        }
        Kind::Path => {
            if raw.is_empty() {
                bail!("'{}' needs a path", s.key);
            }
            let expanded = expand_tilde(raw);
            // Validate writability without surprising side effects: the dir
            // itself, or its nearest existing ancestor, must be writable.
            let probe = if expanded.exists() {
                expanded.clone()
            } else {
                expanded
                    .ancestors()
                    .find(|a| a.exists())
                    .map(|a| a.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("/"))
            };
            let writable = std::fs::metadata(&probe)
                .map(|m| !m.permissions().readonly())
                .unwrap_or(false);
            if !writable {
                bail!("{} is not writable (or its parent does not exist)", probe.display());
            }
            Ok(raw.to_string()) // store as given (keep ~ portable)
        }
        Kind::Str => {
            if s.key == "server" && !(raw.starts_with("http://") || raw.starts_with("https://")) {
                bail!("server must be an http(s) URL, e.g. https://api.example.com");
            }
            Ok(raw.to_string())
        }
        Kind::List => {
            // An EMPTY list is how a list setting is cleared, and clearing is
            // not an edge case: `advertise-routes ''` is how a subnet router or
            // exit node WITHDRAWS what it offers. Refusing it meant a node could
            // start carrying traffic for its peers and had no way to stop short
            // of editing config by hand.
            Ok(raw.to_string())
        }
    }
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        // #184: route through Paths::home_dir() (USERPROFILE on Windows);
        // a bare HOME read is unset on Windows and leaves the literal "~".
        let home = crate::platform::Paths::home_dir();
        if home != Path::new(".") {
            return home.join(rest);
        }
    }
    PathBuf::from(p)
}

// ------------------------------------------------------------- mutations --

pub struct Change {
    pub key: &'static str,
    pub old: String,
    pub new: String,
    pub scope: String, // "global" or "peer:<device>"
    pub daemon: bool,
}

fn require_peer_known(device: &str) -> Result<()> {
    if crate::devices_load().iter().any(|(n, _)| n == device) {
        Ok(())
    } else {
        bail!("no device named '{device}' (see `filament devices`)")
    }
}

/// Set one key (strictly imperative + partial: only this key changes).
pub fn set(key: &str, value: &str, peer: Option<&str>) -> Result<Change> {
    let s = lookup(key)?;
    if let Some(p) = peer {
        if s.scope == ScopeKind::GlobalOnly {
            bail!("'{}' is global-only; drop --peer", s.key);
        }
        require_peer_known(p)?;
    }
    let new = canonicalize(s, value)?;
    let scope_str = peer.map(|p| format!("peer:{p}")).unwrap_or_else(|| "global".into());
    let old = resolve(s, peer).0;
    match peer {
        Some(p) => {
            let mut m = peer_load();
            let entry = m.entry(p.to_string()).or_insert_with(|| json!({}));
            if let Some(obj) = entry.as_object_mut() {
                obj.insert(s.store.to_string(), json!(new));
            }
            peer_save(&m)?;
        }
        None => global_put(s.store, &new)?,
    }
    Ok(Change { key: s.key, old, new, scope: scope_str, daemon: s.daemon })
}

/// Remove an override (revert to the next layer down: global, then default).
pub fn unset(key: &str, peer: Option<&str>) -> Result<Change> {
    let s = lookup(key)?;
    let before = resolve(s, peer).0;
    let scope_str = peer.map(|p| format!("peer:{p}")).unwrap_or_else(|| "global".into());
    match peer {
        Some(p) => {
            let mut m = peer_load();
            if let Some(obj) = m.get_mut(p).and_then(|e| e.as_object_mut()) {
                obj.remove(s.store);
                if obj.is_empty() {
                    m.remove(p);
                }
            }
            peer_save(&m)?;
        }
        None => {
            global_remove(s.store)?;
        }
    }
    let after = resolve(s, peer).0;
    Ok(Change { key: s.key, old: before, new: after, scope: scope_str, daemon: s.daemon })
}

fn lookup(key: &str) -> Result<&'static Setting> {
    find(key).ok_or_else(|| match did_you_mean(key) {
        Some(s) => anyhow::anyhow!("unknown key '{key}' - did you mean '{s}'? (`filament set` lists all)"),
        None => anyhow::anyhow!("unknown key '{key}' (`filament set` lists all keys)"),
    })
}

// ----------------------------------------------------------- CLI handlers --

/// `filament get <key> [--show-origin] [--default <v>] [--json] [--peer <d>]`
pub fn run_get(
    key: &str,
    peer: Option<&str>,
    show_origin: bool,
    default: Option<&str>,
    json_out: bool,
) -> Result<()> {
    let s = lookup(key)?;
    if peer.is_some() && s.scope == ScopeKind::GlobalOnly {
        bail!("'{}' is global-only; drop --peer", s.key);
    }
    let (mut value, origin) = resolve(s, peer);
    if value.is_empty() {
        if let Some(d) = default {
            value = d.to_string();
        } else {
            // Empty effective value (e.g. unset name fallback failed) → exit 1.
            std::process::exit(1);
        }
    }
    if json_out {
        println!(
            "{}",
            json!({ "key": s.key, "value": value, "origin": origin.label(), "default": effective_default(s), "help": s.help })
        );
    } else if show_origin {
        let color = ui::stdout_color();
        println!(
            "{}  {}",
            value,
            ui::paint_when(color, ui::Tone::Dim, &format!("({})", origin.label()))
        );
    } else {
        // Bare value: $(filament get drop-dir) is exactly the value.
        println!("{value}");
    }
    Ok(())
}

/// Tell a running daemon a key changed and print whether it applied live. On a
/// daemon that doesn't answer (or a non-unix host), fall back to the restart hint.
async fn announce_to_daemon(key: &str, color: bool) {
    #[cfg(unix)]
    {
        match crate::ctl::try_reconfigure(key).await {
            Some(v) if v["live"].as_bool() == Some(true) => {
                eprintln!("  {}", ui::paint_when(color, ui::Tone::Ok, "applied to the running daemon"));
                return;
            }
            _ => {}
        }
    }
    eprintln!("  {}", ui::paint_when(color, ui::Tone::Dim, "takes effect on next `filament up`"));
}

/// `filament unset <key> [--peer a,b]`. `peers` empty = clear the global value;
/// one or more = remove each device's per-peer override.
pub async fn run_unset(key: &str, peers: &[String]) -> Result<()> {
    let s = lookup(key)?;
    let color = ui::stdout_color();
    let targets: Vec<Option<&str>> = if peers.is_empty() {
        vec![None]
    } else {
        peers.iter().map(|p| Some(p.as_str())).collect()
    };
    let mut touched_daemon = false;
    for tgt in targets {
        let c = unset(key, tgt)?;
        eprintln!(
            "{} {} reset to default: {} ({})",
            ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()),
            c.key,
            c.new,
            c.scope
        );
        touched_daemon = c.daemon;
    }
    if touched_daemon && crate::daemon_running() {
        announce_to_daemon(s.key, color).await;
    }
    Ok(())
}

/// `filament set` with key+value, or no args (readout), or --reset.
/// `peers` empty = global; one or more = a per-peer override applied to each.
#[allow(clippy::too_many_arguments)]
pub async fn run_set(
    key: Option<&str>,
    value: Option<&str>,
    peers: &[String],
    dry_run: bool,
    reset: bool,
    hard: bool,
    yes: bool,
    json_out: bool,
) -> Result<()> {
    if reset {
        return run_reset(dry_run, yes);
    }
    match (key, value) {
        (None, _) => readout(json_out),
        (Some(k), None) => {
            // `set <key>` with no value.
            let s = lookup(k)?;
            let tty = std::io::stdout().is_terminal();
            if json_out {
                let aff = build_affordance(s);
                crate::interact::render_json_steer(&aff);
            } else if tty {
                render_missing_interactive(s);
            } else {
                let aff = build_affordance(s);
                crate::interact::render_steer(&aff);
            }
            Ok(())
        }
        (Some(k), Some(v)) => {
            let s = lookup(k)?;
            if !peers.is_empty() && s.scope == ScopeKind::GlobalOnly {
                bail!("'{}' is global-only; drop --peer", s.key);
            }
            // Validate the value once (fail fast before writing anything), and
            // every target device, so a typo in peer 2 never half-applies peer 1.
            let raw = canonicalize(s, v)?;
            // Membership refactor: avoid/only share one store. Encode as JSON
            // so the file carries the mode alongside the items.
            let new = if s.store == "interfaces" {
                let mode = match s.key {
                    "avoid" => "avoid",
                    "only" | "include" => "only",
                    _ => "avoid",
                };
                json!({"m": mode, "i": raw}).to_string()
            } else if s.store == "prefer" {
                let strength = if hard { "hard" } else { "soft" };
                json!({"o": raw, "s": strength}).to_string()
            } else {
                raw
            };
            for p in peers {
                require_peer_known(p)?;
            }
            // Targets: no --peer = the single global scope; else one per device.
            let targets: Vec<Option<&str>> = if peers.is_empty() {
                vec![None]
            } else {
                peers.iter().map(|p| Some(p.as_str())).collect()
            };
            let color = ui::stdout_color();
            let mut touched_daemon = false;
            for tgt in targets {
                if dry_run {
                    let old = resolve(s, tgt).0;
                    let scope_str = tgt.map(|p| format!("peer:{p}")).unwrap_or_else(|| "global".into());
                    eprintln!(
                        "would set {} {} {} ({}) {}",
                        s.key,
                        ui::paint_when(color, ui::Tone::Dim, &old),
                        ui::paint_when(color, ui::Tone::Dim, ui::glyph_arrow()),
                        scope_str,
                        new
                    );
                    continue;
                }
                let c = set(k, v, tgt)?;
                if c.old == c.new {
                    eprintln!("{} already {} ({})", c.key, c.new, c.scope);
                } else {
                    eprintln!(
                        "{} {}: {} {} {} ({})",
                        ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()),
                        c.key,
                        ui::paint_when(color, ui::Tone::Dim, &c.old),
                        ui::glyph_arrow(),
                        c.new,
                        c.scope
                    );
                }
                touched_daemon = c.daemon;
            }
            // One reconfigure ping covers all peers (it re-reads the whole key).
            if !dry_run && touched_daemon && crate::daemon_running() {
                announce_to_daemon(s.key, color).await;
            }
            // Enabling the L3 overlay needs CAP_NET_ADMIN for a non-root daemon;
            // grant it now (one sudo prompt) so `up` just works, no separate step.
            // BUT the userspace backend needs no privilege, so don't prompt for a
            // setcap the user explicitly opted out of (l3-mode=userspace or the env).
            #[cfg(l3)]
            if !dry_run && s.key == "tun-addr" && !new.is_empty() {
                let userspace = std::env::var("FILAMENT_L3_USERSPACE").as_deref() == Ok("1")
                    || get_str("l3-mode", None).as_deref() == Some("userspace");
                if !userspace {
                    crate::tun::ensure_net_admin_for_l3();
                }
            }
            Ok(())
        }
    }
}

fn run_reset(dry_run: bool, yes: bool) -> Result<()> {
    let color = ui::stdout_color();
    // Gather what would change so dry-run and the prompt are honest.
    let mut changes: Vec<String> = Vec::new();
    for s in registry() {
        let (cur, origin) = resolve(s, None);
        if !matches!(origin, Origin::Default) {
            changes.push(format!("  {} {} {} {}", s.key, cur, ui::glyph_arrow(), effective_default(s)));
        }
    }
    let peers = peer_load();
    if changes.is_empty() && peers.is_empty() {
        eprintln!("nothing to reset (all settings are at their defaults)");
        return Ok(());
    }
    if dry_run {
        eprintln!("would reset to defaults:");
        for c in &changes {
            eprintln!("{c}");
        }
        if !peers.is_empty() {
            eprintln!("  and clear per-peer overrides for: {}", peers.keys().cloned().collect::<Vec<_>>().join(", "));
        }
        return Ok(());
    }
    // Destructive: confirm at a TTY, require --yes in a pipe (never hang).
    if !yes {
        if std::io::stdin().is_terminal() {
            eprint!("reset ALL settings to defaults? this clears global + per-peer overrides [y/N] ");
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).ok();
            if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                eprintln!("aborted");
                return Ok(());
            }
        } else {
            bail!("refusing to reset without --yes (non-interactive)");
        }
    }
    for s in registry() {
        global_remove(s.store)?;
    }
    let _ = std::fs::remove_file(peer_path());
    eprintln!("{} reset all settings to defaults", ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()));
    Ok(())
}

/// No-args readout. TTY: aligned colored table. Pipe: tab-separated rows.
/// `--json`: complete structured array (global rows + per-peer overrides).
/// Build an Affordance when `filament set <key>` is given without a value.
/// Renders interactively (TTY), as steer (non-TTY), or as JSON (--json).
fn render_missing_interactive(s: &Setting) {
    let (cur_val, origin) = resolve(s, None);
    let subtitle = if cur_val.is_empty() {
        format!("(currently unset) [{}]", origin.label())
    } else {
        format!("currently: {}  [{}]", cur_val, origin.label())
    };
    match s.kind {
        Kind::List => {
            let is_membership = s.key == "avoid" || s.key == "only" || s.key == "include";
            let aff = build_affordance_with_current(s, &cur_val);
            let opts = aff.options.unwrap_or_default();

            if is_membership {
                // Membership (avoid/only): multi-select checklist
                match crate::interact::interactive_checklist(&aff.command, &subtitle, &opts) {
                    Some(chosen) => {
                        if chosen.is_empty() {
                            eprintln!("{} cancelled (nothing selected)", s.key);
                        } else {
                            let _ = set(s.key, &chosen, None);
                            let color = ui::stdout_color();
                            eprintln!("{} {}: {} {} {} (global)", ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()), s.key, ui::paint_when(color, ui::Tone::Dim, &cur_val), ui::glyph_arrow(), chosen);
                        }
                    }
                    None => eprintln!("{} cancelled", s.key),
                }
            } else {
                // Arrangement (prefer): reorderable list
                match crate::interact::interactive_reorder(&aff.command, &subtitle, &opts, crate::interact::Strength::Soft) {
                    Some((ordered, strength)) => {
                        let _ = set(s.key, &ordered, None);
                        let color = ui::stdout_color();
                        let s_label = if strength == crate::interact::Strength::Hard { " (hard)" } else { "" };
                        eprintln!("{} {}: {} {} {}{s_label} (global)", ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()), s.key, ui::paint_when(color, ui::Tone::Dim, &cur_val), ui::glyph_arrow(), ordered);
                    }
                    None => eprintln!("{} cancelled", s.key),
                }
            }
        }
        _ => {
            // Non-List: show current value + help
            let color = ui::stdout_color();
            println!("{} {} = {}  ({})", s.key, ui::paint_when(color, ui::Tone::Dim, &origin.label()), cur_val, s.help);
            match s.kind {
                Kind::Bool => println!("  on / off  (example: filament set {} on)", s.key),
                Kind::Enum(vals) => println!("  values: {}  (example: filament set {} {})", vals.join(" / "), s.key, vals[0]),
                Kind::Str | Kind::Path => println!("  example: filament set {} <value>", s.key),
                _ => {}
            }
            println!();
            println!("{}", ui::paint_when(color, ui::Tone::Dim, "set: filament set <key> <value> [--peer <peer>]"));
        }
    }
}



// `render_missing_steer` / `render_missing_json` lived here. They were exact
// duplicates of the inline json/plain branches of `set <key>` with no value, so
// the nudge always DID render and these were leftovers, not a disconnected
// affordance. Deleted after checking the branch that supersedes them.
fn build_affordance(s: &Setting) -> crate::interact::Affordance {
    let (cur_val, _) = resolve(s, None);
    build_affordance_with_current(s, &cur_val)
}

fn build_affordance_with_current(s: &Setting, cur_val: &str) -> crate::interact::Affordance {
    let command = format!("set {}", s.key);
    let (needs, example) = match s.kind {
        Kind::Bool => ("on / off".into(), format!("filament set {} on", s.key)),
        Kind::Enum(vals) => (vals.join(" / "), format!("filament set {} {}", s.key, vals[0])),
        Kind::List => ("interface name, group, or CIDR".into(), format!("filament set {} wl1", s.key)),
        Kind::Str => ("a value".into(), format!("filament set {} <value>", s.key)),
        Kind::Path => ("a path".into(), format!("filament set {} ~/Downloads", s.key)),
    };

    let options = if matches!(s.kind, Kind::List) {
        let ifaces = crate::interact::enumerate_interfaces();
        if ifaces.is_empty() {
            None
        } else {
            // Split current value into parts for preselection
            let current_parts: Vec<&str> = cur_val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            Some(ifaces.iter().map(|i| {
                let ips: Vec<String> = i.ips.iter().map(|ip| ip.to_string()).collect();
                let is_checked = current_parts.iter().any(|p| *p == i.name);
                crate::interact::OptionEntry {
                    label: i.name.clone(),
                    detail: ips.join(", "),
                    group: i.group.clone(),
                    checked: is_checked,
                }
            }).collect())
        }
    } else {
        None
    };

    crate::interact::Affordance { command, needs, example, options, options_label: "interfaces".into() }
}

// Remove old functions
/// When avoid and prefer overlap, the latest set wins. Remove the overlapping
/// items from the OTHER key so the two lists stay consistent.
fn fix_overlap(key: &str, value: &str, peer: Option<&str>, color: bool) {
    let parts: Vec<&str> = value.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return;
    }
    let other_key = if key == "avoid" { "prefer" } else if key == "prefer" { "avoid" } else { return };
    if let Some(other_s) = find(other_key) {
        let (other_val, _) = resolve(other_s, peer);
        if !other_val.is_empty() {
            let mut other_parts: Vec<&str> = other_val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            let original_len = other_parts.len();
            other_parts.retain(|p| !parts.contains(p));
            if other_parts.len() < original_len {
                if other_parts.is_empty() {
                    // All items removed — clear the key entirely
                    let _ = global_remove(other_key);
                } else {
                    let new_val = other_parts.join(",");
                    let _ = set(other_key, &new_val, peer);
                }
                let removed: Vec<&&str> = parts.iter().filter(|p| other_val.split(',').any(|o| o.trim() == **p)).collect();
                let removed_str: Vec<&str> = removed.iter().map(|r| **r).collect();
                let msg = format!("removed {} from {}", removed_str.join(","), other_key);
                if color {
                    eprintln!("  {}", ui::paint_when(color, ui::Tone::Dim, &msg));
                } else {
                    eprintln!("  {msg}");
                }
            }
        }
    }
}

fn readout(json_out: bool) -> Result<()> {
    let peers = peer_load();

    if json_out {
        let mut rows: Vec<Value> = Vec::new();
        for s in registry() {
            let (v, o) = resolve(s, None);
            rows.push(json!({
                "key": s.key, "value": v, "scope": "global",
                "origin": o.label(), "default": effective_default(s), "daemon": s.daemon, "help": s.help,
            }));
        }
        for (dev, kv) in &peers {
            if let Some(obj) = kv.as_object() {
                for (store, val) in obj {
                    if let Some(s) = registry().iter().find(|s| s.store == store) {
                        rows.push(json!({
                            "key": s.key, "value": val, "scope": format!("peer:{dev}"),
                            "origin": format!("peer:{dev}"), "default": effective_default(s), "daemon": s.daemon,
                        }));
                    }
                }
            }
        }
        println!("{}", serde_json::to_string_pretty(&json!(rows))?);
        return Ok(());
    }

    // Human surface: aligned table with provenance, no borders.
    let color = ui::stdout_color();
    let tty = std::io::stdout().is_terminal();

    if !tty {
        // Non-TTY default: plain TSV (not JSON). Scripts parse this.
        for s in registry() {
            let (v, _) = resolve(s, None);
            let val = if v.is_empty() { "(none)".to_string() } else { v };
            println!("{}\t{}\tglobal\t{}", s.key, val, short_help(s));
        }
        for (dev, kv) in &peers {
            if let Some(obj) = kv.as_object() {
                for (store, val) in obj {
                    if let Some(s) = registry().iter().find(|r| r.store == store) {
                        println!("{}\t{}\tpeer:{dev}\t{}", s.key, val.as_str().unwrap_or_default(), short_help(s));
                    }
                }
            }
        }
        return Ok(());
    }

    // TTY: aligned table with WHAT IT DOES column.
    // Build rows: (key, value, where_label, help, is_default, is_peer_child, peer_name)
    let mut rows: Vec<(String, String, String, String, bool, bool, String)> = Vec::new();
    let mut peer_rows: Vec<(String, String, String, String, bool, bool, String)> = Vec::new();

    for s in registry() {
        let (v, o) = resolve(s, None);
        let is_default = v.is_empty();
        let val = if is_default { "(none)".into() } else { v };
        let where_ = match o {
            Origin::Default => "default".into(),
            Origin::Global => "config".into(),
            Origin::Env(v) => format!("env:{v}"),
            Origin::Peer(d) => format!("peer:{d}"),
        };
        let help = setting_help_line(s);
        rows.push((s.key.into(), val, where_, help, is_default, false, String::new()));

        // Collect per-peer overrides for this setting
        for (dev, kv) in &peers {
            if let Some(obj) = kv.as_object() {
                if let Some(pv) = obj.get(s.store) {
                    let pval = pv.as_str().unwrap_or_default().to_string();
                    peer_rows.push((
                        s.key.into(),
                        pval,
                        "peer".into(),
                        String::new(),
                        false,
                        true,
                        dev.clone(),
                    ));
                }
            }
        }
    }

    let w0 = rows.iter().map(|r| r.0.len() + if r.5 { 6 } else { 0 }).max().unwrap_or(7).max(7);
    let w1 = rows.iter().chain(&peer_rows).map(|r| r.1.len()).max().unwrap_or(5).max(5);
    let w2 = rows.iter().map(|r| r.2.len()).max().unwrap_or(7).max(7);
    let header = format!(
        "{:w0$}  {:w1$}  {:w2$}  WHAT IT DOES",
        "SETTING", "VALUE", "WHERE",
        w0 = w0, w1 = w1, w2 = w2
    );
    println!("{}", ui::paint_when(color, ui::Tone::Dim, &header));

    for (k, v, wh, help, is_default, _is_child, _pn) in &rows {
        let line = format!("{k:w0$}  {v:w1$}  {wh:w2$}  {help}", w0 = w0, w1 = w1, w2 = w2);
        if *is_default {
            println!("{}", ui::paint_when(color, ui::Tone::Dim, &line));
        } else {
            println!("{line}");
        }
        // Print peer overrides grouped under this key
        let key = k;
        for (_pk, pv, _pwh, _ph, _pd, _pc, pn) in peer_rows.iter().filter(|r| r.0 == *key) {
            let indent = "   |- ";
            let label = "peer";
            let child = format!("{indent}{pn:wpad$}  {pv:w1$}  {label:w2$}",
                wpad = w0.saturating_sub(6), w1 = w1, w2 = w2);
            println!("{child}");
        }
    }
    println!();
    println!(
        "{}",
        ui::paint_when(color, ui::Tone::Dim, "edit: filament set <key>   change: filament set <key> <value> [--peer <peer>]   reset: filament unset <key>")
    );
    Ok(())
}

/// First sentence of help text, truncated to ~50 chars. Enums get their
/// options appended inline.
fn short_help(s: &Setting) -> String {
    let base = s.help.split(". ").next().unwrap_or(s.help);
    let base = base.trim();
    let mut out = if base.len() > 55 {
        format!("{}…", &base[..52])
    } else {
        base.to_string()
    };
    if let Kind::Enum(vals) = s.kind {
        out.push_str(&format!(" {}", vals.join("/")));
    }
    out
}

/// Like short_help but also appends enum options when present.
fn setting_help_line(s: &Setting) -> String {
    short_help(s)
}

// --------------------------------------------------------------- extract --

/// Extract a received tar/tar.gz archive into `into`, hardened against zip-slip,
/// symlink/hardlink escapes, and tar bombs. Returns the number of files written.
/// Only ever called for recognized archive extensions, opt-in via `auto-extract`.
pub fn extract_archive(path: &Path, into: &Path) -> Result<usize> {
    let max_files: usize = std::env::var("FILAMENT_MAX_EXTRACT_FILES").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let max_bytes: u64 = std::env::var("FILAMENT_MAX_EXTRACT_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(20 * 1024 * 1024 * 1024);

    let f = std::fs::File::open(path)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let gz = name.ends_with(".tar.gz") || name.ends_with(".tgz");
    let reader: Box<dyn std::io::Read> = if gz {
        Box::new(flate2::read::GzDecoder::new(f))
    } else {
        Box::new(f)
    };
    let mut ar = tar::Archive::new(reader);
    ar.set_overwrite(false); // never clobber existing files
    ar.set_preserve_permissions(false);

    std::fs::create_dir_all(into)?;
    let mut written = 0usize;
    let mut total = 0u64;
    let mut skipped = 0usize;
    for entry in ar.entries()? {
        let mut e = entry?;
        let et = e.header().entry_type();
        // Strict: an auto-unpack never creates links (a link is the classic
        // escape vector). Users who need them can extract by hand.
        if et.is_symlink() || et.is_hard_link() {
            skipped += 1;
            continue;
        }
        total = total.saturating_add(e.header().size().unwrap_or(0));
        if written > max_files || total > max_bytes {
            bail!("archive exceeds extract limits ({written} files / {total} bytes); extract it manually");
        }
        // unpack_in refuses to write outside `into` (returns Ok(false) on a
        // crafted `..`/absolute path); that is our zip-slip guard.
        match e.unpack_in(into) {
            Ok(true) => written += 1,
            Ok(false) => skipped += 1,
            Err(_) => skipped += 1,
        }
    }
    let _ = skipped;
    Ok(written)
}

#[cfg(test)]
mod tests {

    /// Clearing a list is how a node WITHDRAWS what it offers. `set
    /// advertise-routes ''` is the documented way to stop being a subnet router
    /// or exit node, and it used to fail with "needs a comma-separated list",
    /// so a node could start carrying its peers' traffic and had no supported
    /// way to stop.
    #[test]
    fn an_empty_list_clears_the_setting_rather_than_failing() {
        let spec = lookup("advertise-routes").expect("advertise-routes is a registered key");
        assert_eq!(canonicalize(spec, "").ok().as_deref(), Some(""));
        assert_eq!(canonicalize(spec, "10.0.0.0/8").ok().as_deref(), Some("10.0.0.0/8"));
    }
    use super::*;

    // FILAMENT_CONFIG_DIR is process-global, so config-dir tests must not run
    // concurrently (cargo tests are multithreaded by default). Serialize them.
    static CFG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_tmp_cfg<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CFG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("fil-set-test-{}-{:x}", std::process::id(), rand_tag()));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: the lock above makes this the only thread touching the env/dir.
        unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", &dir) };
        let r = f();
        unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
        r
    }
    fn rand_tag() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn find_resolves_aliases_and_did_you_mean() {
        assert_eq!(find("dir").unwrap().key, "drop-dir");
        assert_eq!(find("unzip").unwrap().key, "auto-extract");
        assert_eq!(did_you_mean("rely"), Some("relay"));
        assert_eq!(did_you_mean("dropdir"), Some("drop-dir"));
        assert!(find("nonsense").is_none());
    }

    #[test]
    fn bool_canonicalization_is_forgiving_then_strict() {
        let s = find("auto-extract").unwrap();
        assert_eq!(canonicalize(s, "YES").unwrap(), "on");
        assert_eq!(canonicalize(s, "0").unwrap(), "off");
        assert!(canonicalize(s, "maybe").is_err());
    }

    #[test]
    fn enum_validates_against_allowed_set() {
        let s = find("relay").unwrap();
        assert_eq!(canonicalize(s, "Always").unwrap(), "always");
        assert!(canonicalize(s, "sometimes").is_err());
    }

    #[test]
    fn precedence_env_over_peer_over_global_over_default() {
        with_tmp_cfg(|| {
            let s = find("shell").unwrap();
            // default
            assert!(matches!(resolve(s, None).1, Origin::Default));
            assert_eq!(resolve(s, None).0, "off");
            // global wins over default
            global_put("shell", "on").unwrap();
            assert!(matches!(resolve(s, None).1, Origin::Global));
            assert_eq!(resolve(s, None).0, "on");
        });
    }

    #[test]
    fn peer_override_beats_global_and_is_scoped() {
        with_tmp_cfg(|| {
            // a known device is required for set --peer; write devices.json
            let devs = config_dir().join("devices.json");
            std::fs::write(&devs, r#"[{"name":"laptop","secret":"x"}]"#).unwrap();
            global_put("auto-extract", "off").unwrap();
            set("auto-extract", "on", Some("laptop")).unwrap();
            assert!(get_bool("auto-extract", Some("laptop")));
            assert!(!get_bool("auto-extract", Some("phone"))); // falls to global off
            assert!(!get_bool("auto-extract", None));
            assert_eq!(peers_with("auto-extract", "on"), vec!["laptop".to_string()]);
        });
    }

    #[test]
    fn global_only_rejects_peer_scope() {
        with_tmp_cfg(|| {
            let devs = config_dir().join("devices.json");
            std::fs::write(&devs, r#"[{"name":"laptop","secret":"x"}]"#).unwrap();
            assert!(set("server", "https://x", Some("laptop")).is_err());
        });
    }

    #[test]
    fn unset_reverts_to_lower_layer() {
        with_tmp_cfg(|| {
            global_put("relay", "always").unwrap();
            assert_eq!(resolve(find("relay").unwrap(), None).0, "always");
            unset("relay", None).unwrap();
            let (v, o) = resolve(find("relay").unwrap(), None);
            assert_eq!(v, "auto");
            assert!(matches!(o, Origin::Default));
        });
    }

    // Hand-built USTAR record so the archive genuinely contains a `..` entry
    // (the tar crate's Builder refuses to write one, so it can't construct the
    // attack we must defend against).
    fn raw_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut h = [0u8; 512];
        let nb = name.as_bytes();
        h[..nb.len()].copy_from_slice(nb);
        h[100..107].copy_from_slice(b"0000644"); // mode
        h[108..115].copy_from_slice(b"0000000"); // uid
        h[116..123].copy_from_slice(b"0000000"); // gid
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes()); // size
        h[136..147].copy_from_slice(b"00000000000"); // mtime
        h[156] = b'0'; // typeflag = regular
        h[257..262].copy_from_slice(b"ustar");
        h[263..265].copy_from_slice(b"00");
        for b in h.iter_mut().take(156).skip(148) {
            *b = b' '; // checksum field is spaces while summing
        }
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
        h[154] = 0;
        h[155] = b' ';
        let mut out = h.to_vec();
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat(0u8).take(pad));
        out
    }

    #[test]
    fn extract_blocks_traversal() {
        with_tmp_cfg(|| {
            let src = config_dir().join("payload.tar");
            let mut bytes = Vec::new();
            bytes.extend(raw_entry("bundle/ok.txt", b"hello")); // the dir-send shape
            bytes.extend(raw_entry("../escape.txt", b"pwned")); // zip-slip attempt
            bytes.extend(std::iter::repeat(0u8).take(1024)); // tar EOF
            std::fs::write(&src, &bytes).unwrap();

            let into = config_dir().join("out");
            let n = extract_archive(&src, &into).unwrap();
            assert_eq!(n, 1, "only the safe entry is written");
            assert!(into.join("bundle/ok.txt").exists());
            assert!(!config_dir().join("escape.txt").exists(), "traversal blocked");
        });
    }

    #[test]
    fn avoid_resolve_matches_what_was_set() {
        with_tmp_cfg(|| {
            let devs = config_dir().join("devices.json");
            std::fs::write(&devs, r#"[{"name":"laptop","secret":"x"}]"#).unwrap();

            // Low-level set writes raw; the membership JSON wrapping happens in run_set.
            // Here we write the JSON directly so resolve can decode it.
            global_put("interfaces", r#"{"m":"avoid","i":"tailscale0,lo"}"#).unwrap();
            let resolved = resolve(find("avoid").unwrap(), None).0;
            assert_eq!(resolved, "tailscale0,lo");
        });
    }

    #[test]
    fn fix_overlap_removes_from_other_key() {
        with_tmp_cfg(|| {
            let devs = config_dir().join("devices.json");
            std::fs::write(&devs, r#"[{"name":"laptop","secret":"x"}]"#).unwrap();

            // Set prefer, then fix_overlap for avoid: items in avoid are removed from prefer
            set("prefer", "wl1,tailscale0", None).unwrap();
            set("avoid", "wl1", None).unwrap();
            fix_overlap("avoid", "wl1", None, false);
            assert_eq!(resolve(find("prefer").unwrap(), None).0, "tailscale0",
                "wl1 removed from prefer, tailscale0 kept");
        });
    }

    #[test]
    fn fix_overlap_clears_other_when_all_removed() {
        with_tmp_cfg(|| {
            let devs = config_dir().join("devices.json");
            std::fs::write(&devs, r#"[{"name":"laptop","secret":"x"}]"#).unwrap();

            set("avoid", "wl1", None).unwrap();
            set("prefer", "wl1", None).unwrap();
            fix_overlap("prefer", "wl1", None, false);
            assert_eq!(resolve(find("avoid").unwrap(), None).0, "",
                "avoid cleared when prefer claims the only item");
        });
    }
}
