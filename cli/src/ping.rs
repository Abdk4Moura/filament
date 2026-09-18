// `filament reach <peer>`: show the live link to a known device, including route, RTT, and
// whether ssh/pty will be instant. Mirrors `tailscale ping` and elevates it with
// two things Tailscale has no concept of: WARM vs COLD (is a link already held by
// the local `up` daemon, so ssh/pty is instant?) and VERIFIED identity (paired +
// proof-verified, not merely reachable). A warm direct link reports quinn's RTT
// and the real remote IP:port; with no live link it reports the cold establish
// cost (what ssh/pty would actually pay) instead of a fake latency.
//
// Every probe renders through one shape, `probe_line`: `pong via <where> <n> ms`.
// `reach` prints it once; `reach --until-direct` prints it once a second until the
// daemon's link to the peer is no longer relayed.
//
// Color is restrained: one accent (Brand mint = warm), amber only for the relay
// caveat, green for a good pong, red for unreachable, dim for metadata.

use crate::ui::{self, Tone};
use anyhow::{bail, Result};
use serde_json::{json, Value};

/// What ONE probe observed. Every field is read off the link the daemon holds
/// (quinn's RTT and 5-tuple, the link's own route label, the selected ICE pair),
/// never inferred: `relayed` in particular is the link's state, so a direct line
/// can never be reported for a path that is actually turning through a relay.
#[derive(Debug, Clone, PartialEq)]
pub enum Probe {
    /// A link the local `up` daemon already holds.
    Warm {
        relayed: bool,
        route: String,
        addr: Option<String>,
        rtt_ms: Option<u64>,
    },
    /// No held link. `--until-direct` watches the daemon's state and never
    /// establishes a link of its own, so this is what a miss looks like.
    NoLink,
}

impl Probe {
    /// Did this probe see a live path with no relay in it?
    pub fn is_direct(&self) -> bool {
        matches!(self, Probe::Warm { relayed: false, .. })
    }
}

/// The one-line result shape, uncoloured. `reach` and `reach --until-direct`
/// both render through this, so the two read identically and one unit test
/// covers both.
pub fn probe_line(p: &Probe) -> String {
    match p {
        Probe::Warm {
            relayed,
            route,
            addr,
            rtt_ms,
        } => {
            let via = match (relayed, addr) {
                (true, Some(a)) => format!("relay({a})"),
                (true, None) => "relay".to_string(),
                (false, Some(a)) => format!("{a} ({route})"),
                (false, None) => route.clone(),
            };
            match rtt_ms {
                Some(ms) => format!("pong via {via} {ms} ms"),
                None => format!("pong via {via}"),
            }
        }
        Probe::NoLink => "no warm link to this peer".to_string(),
    }
}

/// Tone for a probe line: green for a direct pong, amber for a relayed one,
/// red when nothing answered.
fn probe_tone(p: &Probe) -> Tone {
    match p {
        Probe::Warm { relayed: false, .. } => Tone::Ok,
        Probe::Warm { relayed: true, .. } => Tone::Warn,
        Probe::NoLink => Tone::Err,
    }
}

/// Read a warm daemon reply into a `Probe`. `relayed` is the link's own state
/// (its route label, or the ICE pair's relayed flag), not a guess from the
/// address.
fn probe_from_warm(v: &Value) -> Probe {
    let route = v["route"].as_str().unwrap_or("?").to_string();
    let path = &v["path"];
    Probe::Warm {
        relayed: is_relay(&route) || path["relay"].as_bool().unwrap_or(false),
        route,
        addr: path["remote"]
            .as_str()
            .or_else(|| v["remote_addr"].as_str())
            .map(str::to_string),
        rtt_ms: v["rtt_ms"].as_u64(),
    }
}

/// The per-probe `--json` envelope for this verb: one object per probe, so a
/// script watching `--until-direct` reads a line per second and the exit code.
fn probe_envelope(p: &Probe) -> Value {
    let (ok, route, direct, rtt, addr) = match p {
        Probe::Warm { relayed, route, addr, rtt_ms } => {
            (true, json!(route), !*relayed, json!(rtt_ms), json!(addr))
        }
        Probe::NoLink => (false, Value::Null, false, Value::Null, Value::Null),
    };
    json!({
        "ok": ok,
        "verb": "reach",
        "data": { "route": route, "direct": direct, "rtt_ms": rtt, "addr": addr },
    })
}

pub async fn ping_cmd(server: &str, peer: &str, count: u32, json_out: bool, relay: bool) -> Result<()> {
    let count = count.max(1);

    // Warm path: ask a local `up` daemon about its held link. Synchronous and
    // exact (quinn already measured RTT/addr). A miss → None → cold probe below.
    #[cfg(unix)]
    let warm = if relay { None } else { crate::ctl::try_ping(peer).await };
    #[cfg(not(unix))]
    let warm: Option<Value> = None;

    if json_out {
        return ping_json(server, peer, relay, warm).await;
    }

    ui::say(&format!(
        "{} {}",
        ui::paint(Tone::Dim, "filament reach →"),
        ui::paint(Tone::Brand, peer)
    ));

    match warm {
        Some(mut v) => {
            for i in 0..count {
                if i > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    // Re-sample so repeated pings show live RTT drift (quinn keeps
                    // it fresh via the keepalive); keep the prior facts on a miss.
                    #[cfg(unix)]
                    if let Some(nv) = crate::ctl::try_ping(peer).await {
                        v = nv;
                    }
                }
                print_warm_line(&v);
            }
            print_warm_verdict(peer, &v);
        }
        None => print_cold(server, peer, relay).await,
    }
    Ok(())
}

/// `reach <device> --until-direct`: print one line per probe and stop as soon as
/// the daemon's link to the peer stops being relayed (exit 0), or at the timeout
/// (exit 5). It WATCHES the local `up` daemon's link rather than establishing one
/// of its own, so a second of waiting costs one unix-socket round trip and the
/// "direct" it reports is the link ssh/pty would actually ride.
pub async fn reach_until_direct(
    peer: &str,
    timeout_s: u64,
    json_out: bool,
    relay: bool,
) -> Result<()> {
    if relay {
        bail!("`--relay` forces the relay path, so it cannot be combined with `--until-direct`");
    }
    // Portable: `ctl::daemon_present` is the adapter (false where the platform
    // has no control socket), so the same error covers "not running" and
    // "cannot run here" without a platform branch in this file.
    if !crate::ctl::daemon_present().await {
        bail!("no local `filament up` daemon: `--until-direct` watches the daemon's link to {peer}. Start `filament up` first.");
    }
    if !json_out {
        ui::say(&format!(
            "{} {} {}",
            ui::paint(Tone::Dim, "filament reach →"),
            ui::paint(Tone::Brand, peer),
            ui::paint(Tone::Dim, &format!("(until direct, {timeout_s}s)"))
        ));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);
    let mut saw_link = false;
    loop {
        let p = match crate::ctl::try_ping(peer).await {
            Some(v) => probe_from_warm(&v),
            None => Probe::NoLink,
        };
        emit_probe(&p, json_out);
        if p.is_direct() {
            return Ok(());
        }
        saw_link |= matches!(p, Probe::Warm { .. });
        if std::time::Instant::now() >= deadline {
            break;
        }
        // Ctrl-C ends the watch here, between lines, so no half-written
        // line and no orphaned probe.
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            _ = tokio::signal::ctrl_c() => std::process::exit(130),
        }
    }
    if !json_out {
        let verdict = if saw_link {
            format!("still on relay after {timeout_s}s")
        } else {
            format!("no link to {peer} after {timeout_s}s")
        };
        ui::critical(&format!("  {}", ui::paint(Tone::Warn, &verdict)));
    }
    std::process::exit(5)

}

/// One probe, for whichever audience asked: the envelope on stdout under
/// `--json`, the one-line shape otherwise. A route label is must-see output
/// (docs/ui/OUTPUT.md), so it goes through `ui::critical`.
fn emit_probe(p: &Probe, json_out: bool) {
    if json_out {
        println!("{}", probe_envelope(p));
    } else {
        ui::critical(&format!("  {}", ui::paint(probe_tone(p), &probe_line(p))));
    }
}

/// A relay/TURN path (no direct line of sight), the only case we tint amber.
fn is_relay(route: &str) -> bool {
    matches!(route, "relay" | "relayed")
}

/// Compact the doctor's address class for the one-line ping ("private (RFC1918)"
/// → "private", "CGNAT (100.64/10)" → "CGNAT"). Doctor keeps the full form.
fn short_class(class: &str) -> &str {
    class.split(" (").next().unwrap_or(class)
}

fn fmt_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

/// One result line for a held (warm) link: the shared `probe_line` shape, then
/// the detail only `reach` shows - the local network INTERFACE, the remote
/// address class, the verified name, and the warm badge. So you can see exactly
/// which route the link takes (e.g. `tailscale0 · CGNAT` means the tailnet,
/// stated as data, not guessed). A relay/TURN path has no line of sight, so it
/// reads "relay" with the encrypted caveat instead of an interface.
fn print_warm_line(v: &Value) {
    let p = probe_from_warm(v);
    let verified = v["verified"].as_str();
    let path = &v["path"];

    let mut line = format!("  {}", ui::paint(probe_tone(&p), &probe_line(&p)));

    if p.is_direct() {
        // Interface · class, the heart of "show the path". When the interface
        // is a VPN/tailscale tunnel, tint it mint so the tunnel is obvious.
        if let Some(iface) = path["iface"].as_str() {
            let vpn = path["vpn"].as_bool().unwrap_or(false);
            let iface_tone = if vpn { Tone::Brand } else { Tone::Dim };
            line.push_str(&format!("   {}", ui::paint(iface_tone, iface)));
            if let Some(class) = path["class"].as_str() {
                line.push_str(&format!(" {} {}", ui::paint(Tone::Dim, "·"), ui::paint(Tone::Dim, short_class(class))));
            }
        } else if let Some(class) = path["class"].as_str() {
            line.push_str(&format!("   {}", ui::paint(Tone::Dim, short_class(class))));
        }
    } else {
        line.push_str(&format!("  {}", ui::paint(Tone::Dim, "(encrypted, not direct)")));
    }

    if let Some(name) = verified {
        line.push_str(&format!("   {}", ui::paint(Tone::Ok, &format!("✓ {name}"))));
    }
    line.push_str(&format!("   {}", ui::paint(Tone::Brand, "⚡ warm")));
    ui::critical(&line);
}

fn print_warm_verdict(peer: &str, v: &Value) {
    let route = v["route"].as_str().unwrap_or("?");
    if is_relay(route) {
        ui::say(&format!("  {}", ui::paint(Tone::Warn, "⚠ on relay, no direct path · still end-to-end encrypted")));
        ui::say(&format!("  {}", ui::paint(Tone::Dim, &format!("─ ssh/pty to {peer} will be instant, over the relay"))));
    } else {
        ui::say(&format!("  {}", ui::paint(Tone::Dim, &format!("─ ssh/pty to {peer} will be instant (warm direct link)"))));
    }
}

/// No live link held locally: measure what a fresh connect would cost (the honest
/// number (that IS what ssh/pty would pay), via the same establish-then-drop
/// probe `filament doctor` uses.
async fn print_cold(server: &str, peer: &str, relay: bool) {
    match crate::l2::establish_probe(server, peer, relay).await {
        Ok(o) if o.established => {
            ui::critical(&format!(
                "  {}   {}",
                ui::paint(Tone::Warn, "○ cold"),
                ui::paint(Tone::Dim, &format!("no warm link · would connect in ~{}", fmt_ms(o.total_ms)))
            ));
            ui::say(&format!(
                "  {}",
                ui::paint(Tone::Dim, &format!("─ ssh/pty to {peer} would establish a fresh link; run `filament up` to keep it warm"))
            ));
        }
        Ok(o) => {
            let phase = o.failed_phase.map(|p| p.label()).unwrap_or("establishing");
            ui::critical(&format!(
                "  {}   {}",
                ui::paint(Tone::Err, "✗ unreachable"),
                ui::paint(Tone::Dim, &format!("gave up at the {phase} phase (~{})", fmt_ms(o.total_ms)))
            ));
            ui::say(&format!(
                "  {}",
                ui::paint(Tone::Dim, &format!("─ {peer} may be offline, or not running `filament up` / `--shell`"))
            ));
        }
        Err(e) => {
            ui::critical(&format!(
                "  {}   {}",
                ui::paint(Tone::Err, "✗ unreachable"),
                ui::paint(Tone::Dim, &e.to_string())
            ));
        }
    }
}

/// Machine-readable output: the warm facts verbatim, or the cold probe result.
async fn ping_json(server: &str, peer: &str, relay: bool, warm: Option<Value>) -> Result<()> {
    let out = if let Some(v) = warm {
        v
    } else {
        match crate::l2::establish_probe(server, peer, relay).await {
            Ok(o) => json!({
                "ok": true,
                "warm": false,
                "established": o.established,
                "total_ms": o.total_ms,
                "failed_phase": o.failed_phase.map(|p| p.label()),
            }),
            Err(e) => json!({ "ok": false, "warm": false, "error": e.to_string() }),
        }
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warm(relayed: bool, route: &str, addr: Option<&str>, rtt: Option<u64>) -> Probe {
        Probe::Warm { relayed, route: route.into(), addr: addr.map(str::to_string), rtt_ms: rtt }
    }

    #[test]
    fn probe_line_renders_direct_relay_and_the_no_answer_cases() {
        assert_eq!(
            probe_line(&warm(false, "direct-quic", Some("203.0.113.7:41641"), Some(9))),
            "pong via 203.0.113.7:41641 (direct-quic) 9 ms"
        );
        // No address on the link: the route label still carries the answer.
        assert_eq!(probe_line(&warm(false, "holepunched", None, Some(12))), "pong via holepunched 12 ms");
        assert_eq!(
            probe_line(&warm(true, "relay", Some("198.51.100.4:3478"), Some(41))),
            "pong via relay(198.51.100.4:3478) 41 ms"
        );
        // A webrtc link labels its route by interface; `relayed` is the link's
        // own ICE state, and it is what decides the word "relay".
        assert_eq!(probe_line(&warm(true, "direct over eth0", None, None)), "pong via relay");
        assert_eq!(probe_line(&Probe::NoLink), "no warm link to this peer");
    }

    #[test]
    fn only_a_warm_unrelayed_link_counts_as_direct() {
        assert!(warm(false, "direct-quic", None, Some(1)).is_direct());
        assert!(!warm(true, "direct over eth0", None, Some(1)).is_direct());
        assert!(!Probe::NoLink.is_direct());
    }

    #[test]
    fn a_warm_reply_becomes_a_probe_with_the_links_own_facts() {
        let v = json!({
            "ok": true, "warm": true, "direct": true, "route": "direct-quic",
            "remote_addr": "203.0.113.7:41641", "rtt_ms": 9,
            "path": { "remote": "203.0.113.7:41641", "relay": false },
        });
        let p = probe_from_warm(&v);
        assert_eq!(probe_line(&p), "pong via 203.0.113.7:41641 (direct-quic) 9 ms");
        assert_eq!(
            probe_envelope(&p),
            json!({"ok": true, "verb": "reach", "data": {
                "route": "direct-quic", "direct": true, "rtt_ms": 9, "addr": "203.0.113.7:41641"}})
        );
        // A relayed ICE pair is relayed even though its route label is not the
        // word "relay": the flag comes from the path, never from the label.
        let r = json!({ "ok": true, "warm": true, "direct": false, "route": "direct over eth0",
                        "rtt_ms": 41, "path": { "remote": "198.51.100.4:3478", "relay": true } });
        let p = probe_from_warm(&r);
        assert!(!p.is_direct());
        assert_eq!(probe_line(&p), "pong via relay(198.51.100.4:3478) 41 ms");
        assert_eq!(probe_envelope(&p)["data"]["direct"], json!(false));
    }
}
