// `filament doctor`: an on-demand local probe that shows WHERE SSH/L2 connect
// establishment is slow or stalls. Two modes:
//
//   * `filament doctor <device>`  -> run the establish-then-drop probe
//     (l2::establish_probe) and print the per-phase ladder + a one-line verdict.
//     `--repeat N` / `--watch` run it many times and print a distribution (the
//     key tool for the intermittent "fails on the first try" case). `--json`
//     emits the timings + verdict for scripting.
//
//   * `filament doctor`           -> environment preflight + history: signaling
//     reachability (timed GET /api/config), one STUN binding (srflx + class),
//     local interfaces (flagging a tailscale/vpn confounder), and a digest of
//     the local diag.jsonl (diag::summarize). `--json` emits the whole report.
//
// It reuses the SAME diag phases/budgets a real connect records (over_budget,
// budget_ms), so a probe ladder matches what a live `filament ssh` would hit.
// It is purely additive: it changes no wire framing or control messages.

use crate::diag::{self, Phase};
use crate::ui::{self, Tone};
use anyhow::Result;
use serde_json::{json, Value};

/// How many history spans the no-arg report digests by default.
const HISTORY_LIMIT: usize = 20;

/// `--watch` with no explicit `--repeat` runs this many probes (a sensible
/// bounded default; the intermittent case usually shows within a handful).
const WATCH_DEFAULT_REPEAT: u32 = 5;

/// Entry point from main's dispatch. `device` None => preflight+history; Some =>
/// probe. `watch`/`repeat`/`json` shape the probe mode.
pub async fn doctor_cmd(
    server: &str,
    device: Option<String>,
    watch: bool,
    repeat: Option<u32>,
    json_out: bool,
    relay: bool,
) -> Result<()> {
    match device {
        Some(dev) => probe_mode(server, &dev, watch, repeat, json_out, relay).await,
        None => preflight_mode(server, json_out).await,
    }
}

// ============================================================== probe (device) =

async fn probe_mode(
    server: &str,
    device: &str,
    watch: bool,
    repeat: Option<u32>,
    json_out: bool,
    relay: bool,
) -> Result<()> {
    // Resolve the run count: --repeat wins; else --watch => WATCH_DEFAULT_REPEAT;
    // else a single probe.
    let runs = repeat.filter(|n| *n > 0).unwrap_or(if watch { WATCH_DEFAULT_REPEAT } else { 1 });

    if runs == 1 {
        let outcome = crate::l2::establish_probe(server, device, relay).await?;
        if json_out {
            println!("{}", single_json(device, &outcome).to_string());
        } else {
            print_ladder(device, &outcome);
        }
        return Ok(());
    }

    // Repeat: collect outcomes, then print (or emit) a distribution summary.
    let mut outcomes = Vec::with_capacity(runs as usize);
    for i in 0..runs {
        if !json_out {
            ui::say(&format!("filament doctor: probe {}/{} to '{device}'...", i + 1, runs));
        }
        let outcome = crate::l2::establish_probe(server, device, relay).await?;
        if !json_out {
            // A compact per-run line so the user sees progress, with its verdict.
            let v = verdict(&outcome);
            let tone = if outcome.established && v.healthy { Tone::Ok } else { Tone::Warn };
            ui::say(&format!(
                "  run {}: {}",
                i + 1,
                ui::paint(tone, &v.line)
            ));
        }
        outcomes.push(outcome);
    }

    if json_out {
        println!("{}", repeat_json(device, &outcomes).to_string());
    } else {
        print_distribution(device, &outcomes);
    }
    Ok(())
}

/// A computed verdict for one probe: the headline phase + a human line.
struct Verdict {
    healthy: bool,
    /// The phase named as slow/stalled, if any.
    culprit: Option<Phase>,
    line: String,
}

/// Decide the verdict for one outcome. PURE (no IO): testable. Healthy means it
/// established with no phase over budget; otherwise name the worst phase (the
/// first over-budget phase, or the failed phase).
fn verdict(o: &crate::l2::ProbeOutcome) -> Verdict {
    if !o.established {
        let where_ = o
            .failed_phase
            .map(|p| format!(" on the {} phase", p.label()))
            .unwrap_or_default();
        let why = o.error.clone().unwrap_or_else(|| "establishment failed".into());
        return Verdict {
            healthy: false,
            culprit: o.failed_phase,
            line: format!("establishment FAILED{where_}: {why}"),
        };
    }
    // Established: is any phase over budget? Pick the FIRST over-budget phase as
    // the headline culprit (it is the earliest place the connect ran slow).
    let over = o.timings.iter().find(|t| t.over_budget);
    match over {
        Some(t) => Verdict {
            healthy: false,
            culprit: Some(t.phase),
            line: format!(
                "established but the {} phase ran over budget ({} > budget {})",
                t.phase.label(),
                fmt_ms(t.dur_ms),
                fmt_ms(diag::budget_ms(t.phase)),
            ),
        },
        None => Verdict {
            healthy: true,
            culprit: None,
            line: format!("healthy (total {})", fmt_ms(o.total_ms)),
        },
    }
}

/// Render one probe's phase ladder + verdict to stdout (the house style: an
/// aligned, colored listing like `filament devices`).
fn print_ladder(device: &str, o: &crate::l2::ProbeOutcome) {
    println!();
    println!("{}", ui::paint(Tone::Bold, &format!("filament doctor: probe to '{device}'")));
    println!();
    // Column widths: phase label (longest is "establishing" = 12) + time.
    for t in &o.timings {
        let status = if t.over_budget {
            ui::paint(Tone::Err, &format!("STALL  (budget {})", fmt_ms(diag::budget_ms(t.phase))))
        } else {
            ui::paint(Tone::Ok, "ok")
        };
        println!("  {:<13} {:>6}  {}", t.phase.label(), fmt_ms(t.dur_ms), status);
    }
    // If it never established, show the phase it died in as a failed rung.
    if !o.established {
        if let Some(p) = o.failed_phase {
            // Only add a rung if it isn't already the last recorded phase.
            let already = o.timings.last().map(|t| t.phase == p).unwrap_or(false);
            if !already {
                println!("  {:<13} {:>6}  {}", p.label(), "-", ui::paint(Tone::Err, "FAILED"));
            }
        }
    }
    // The path the link actually took: same fine detail as `filament ping` so the
    // diagnosis names the interface + endpoints, not just the timings.
    if let Some(p) = &o.path {
        println!("  {:<13} {:>6}  {}", "path", "", fmt_path(p));
    }
    println!();
    let v = verdict(o);
    let tone = if v.healthy { Tone::Ok } else { Tone::Err };
    println!("  {} {}", ui::paint(Tone::Bold, "verdict:"), ui::paint(tone, &v.line));
    println!();
}

/// Render a `PathInfo` to one elegant line: interface · class, the endpoints
/// (direct shows `→remote`; a webrtc pair shows `local ↔ remote` plus the
/// candidate types), or the relay caveat. A VPN/tailscale interface is tinted
/// mint so the tunnel is obvious. Doctor keeps the full class form.
fn fmt_path(p: &crate::net::PathInfo) -> String {
    if p.relay {
        return format!(
            "{}   {}",
            ui::paint(Tone::Warn, "relay · TURN"),
            ui::paint(Tone::Dim, "(encrypted, no direct 5-tuple)")
        );
    }
    let mut s = String::new();
    if let Some(iface) = &p.iface {
        let tone = if p.vpn { Tone::Brand } else { Tone::Dim };
        s.push_str(&ui::paint(tone, iface));
        if let Some(c) = &p.class {
            s.push_str(&format!(" {} {}", ui::paint(Tone::Dim, "·"), ui::paint(Tone::Dim, c)));
        }
    } else if let Some(c) = &p.class {
        s.push_str(&ui::paint(Tone::Dim, c));
    }
    let addrs = match (&p.local, &p.remote, p.cand.is_some()) {
        (Some(l), Some(r), true) => format!("{l} \u{2194} {r}"),
        (_, Some(r), _) => format!("\u{2192}{r}"),
        _ => String::new(),
    };
    if !addrs.is_empty() {
        s.push_str(&format!("  {}", ui::paint(Tone::Dim, &addrs)));
    }
    if let Some(c) = &p.cand {
        s.push_str(&format!("  {}", ui::paint(Tone::Dim, &format!("({c})"))));
    }
    s
}

/// Render the distribution across N probes: per-phase min/median/max, the stall
/// rate per phase, and the overall established rate.
fn print_distribution(device: &str, outcomes: &[crate::l2::ProbeOutcome]) {
    let n = outcomes.len();
    println!();
    println!(
        "{}",
        ui::paint(Tone::Bold, &format!("filament doctor: {n} probes to '{device}'"))
    );
    println!();

    let established = outcomes.iter().filter(|o| o.established).count();
    let est_tone = if established == n { Tone::Ok } else { Tone::Warn };
    println!(
        "  established: {}",
        ui::paint(est_tone, &format!("{established} of {n}"))
    );
    println!();

    // Per-phase distribution across all probes that recorded that phase.
    println!("  {:<13} {:>7} {:>7} {:>7}   {}", "phase", "min", "median", "max", "over budget");
    for phase in PHASES {
        let mut durs: Vec<u64> = outcomes
            .iter()
            .flat_map(|o| o.timings.iter())
            .filter(|t| t.phase == *phase)
            .map(|t| t.dur_ms)
            .collect();
        if durs.is_empty() {
            continue;
        }
        durs.sort_unstable();
        let over = outcomes
            .iter()
            .flat_map(|o| o.timings.iter())
            .filter(|t| t.phase == *phase && t.over_budget)
            .count();
        let seen = durs.len();
        let over_str = format!("{over} of {seen} over budget");
        let over_tone = if over == 0 { Tone::Ok } else { Tone::Warn };
        println!(
            "  {:<13} {:>7} {:>7} {:>7}   {}",
            phase.label(),
            fmt_ms(durs[0]),
            fmt_ms(median(&durs)),
            fmt_ms(durs[seen - 1]),
            ui::paint(over_tone, &over_str),
        );
    }
    println!();

    // The headline: how often did it stall ANYWHERE (over budget or failed)?
    let unhealthy = outcomes.iter().filter(|o| !verdict(o).healthy).count();
    let line = if unhealthy == 0 {
        ui::paint(Tone::Ok, &format!("all {n} probes healthy"))
    } else {
        ui::paint(
            Tone::Warn,
            &format!("{unhealthy} of {n} probes stalled or failed (the intermittent case)"),
        )
    };
    println!("  {} {line}", ui::paint(Tone::Bold, "verdict:"));
    println!();
}

/// The phases in ladder order (for the distribution table). Up is the steady
/// state, never a bring-up rung, so it is excluded.
const PHASES: &[Phase] = &[
    Phase::Signaling,
    Phase::Presence,
    Phase::Establishing,
    Phase::Ready,
    Phase::L2Open,
];

fn single_json(device: &str, o: &crate::l2::ProbeOutcome) -> Value {
    let v = verdict(o);
    json!({
        "kind": "filament-doctor-probe",
        "device": device,
        "established": o.established,
        "total_ms": o.total_ms,
        "phases": o.timings.iter().map(timing_json).collect::<Vec<_>>(),
        "failed_phase": o.failed_phase.map(|p| p.label()),
        "error": o.error,
        "path": o.path.as_ref().map(|p| p.to_json()),
        "verdict": {
            "healthy": v.healthy,
            "culprit": v.culprit.map(|p| p.label()),
            "text": v.line,
        },
    })
}

fn repeat_json(device: &str, outcomes: &[crate::l2::ProbeOutcome]) -> Value {
    let n = outcomes.len();
    let established = outcomes.iter().filter(|o| o.established).count();
    let mut phases = Vec::new();
    for phase in PHASES {
        let mut durs: Vec<u64> = outcomes
            .iter()
            .flat_map(|o| o.timings.iter())
            .filter(|t| t.phase == *phase)
            .map(|t| t.dur_ms)
            .collect();
        if durs.is_empty() {
            continue;
        }
        durs.sort_unstable();
        let over = outcomes
            .iter()
            .flat_map(|o| o.timings.iter())
            .filter(|t| t.phase == *phase && t.over_budget)
            .count();
        phases.push(json!({
            "phase": phase.label(),
            "min_ms": durs[0],
            "median_ms": median(&durs),
            "max_ms": durs[durs.len() - 1],
            "seen": durs.len(),
            "over_budget": over,
        }));
    }
    let unhealthy = outcomes.iter().filter(|o| !verdict(o).healthy).count();
    json!({
        "kind": "filament-doctor-repeat",
        "device": device,
        "runs": n,
        "established": established,
        "unhealthy": unhealthy,
        "phases": phases,
        "runs_detail": outcomes.iter().map(|o| single_json(device, o)).collect::<Vec<_>>(),
    })
}

fn timing_json(t: &diag::PhaseTiming) -> Value {
    json!({
        "phase": t.phase.label(),
        "dur_ms": t.dur_ms,
        "over_budget": t.over_budget,
        "budget_ms": diag::budget_ms(t.phase),
    })
}

// ===================================================== preflight (no device) ==

async fn preflight_mode(server: &str, json_out: bool) -> Result<()> {
    // #2 (parallelism): the signaling reachability probe and the STUN probe are
    // independent network round-trips; run them CONCURRENTLY so the preflight's
    // wall-clock is the slower of the two, not their sum (on a slow link that is
    // ~2.7s + ~0.9s sequential -> ~2.7s).
    let (sig, ice) = tokio::join!(check_signaling(server), check_stun(server));
    let ifaces = list_interfaces();
    let history = diag::summarize(HISTORY_LIMIT);
    // Local file read (fast, no IO worth joining): sshd CA trust presence.
    let sshca = crate::sshd::check_sshd_ca();

    if json_out {
        println!("{}", preflight_json(server, &sig, &ice, &ifaces, &history, &sshca).to_string());
        return Ok(());
    }

    println!();
    println!("{}", ui::paint(Tone::Bold, "filament doctor: environment preflight"));
    println!();

    // Signaling.
    match &sig {
        Ok(ms) => println!(
            "  {:<13} {}  {}",
            "signaling",
            ui::paint(Tone::Ok, "reachable"),
            ui::paint(Tone::Dim, &format!("{server} ({} round trip)", fmt_ms(*ms))),
        ),
        Err(e) => println!(
            "  {:<13} {}  {}",
            "signaling",
            ui::paint(Tone::Err, "UNREACHABLE"),
            ui::paint(Tone::Dim, &format!("{server}: {e}")),
        ),
    }

    // ICE / STUN.
    match &ice {
        IceResult::Ok { srflx, class, ms } => println!(
            "  {:<13} {}  {}",
            "ice/stun",
            ui::paint(Tone::Ok, "works"),
            ui::paint(Tone::Dim, &format!("srflx {srflx} ({class}, {} round trip)", fmt_ms(*ms))),
        ),
        IceResult::NoServer => println!(
            "  {:<13} {}  {}",
            "ice/stun",
            ui::paint(Tone::Warn, "no STUN server"),
            ui::paint(Tone::Dim, "config advertises no stun: url; direct path limited"),
        ),
        IceResult::Failed(e) => println!(
            "  {:<13} {}  {}",
            "ice/stun",
            ui::paint(Tone::Warn, "FAILED"),
            ui::paint(Tone::Dim, &format!("no srflx learned: {e}")),
        ),
    }

    // SSH CA trust (sshd side of `shell --ssh`). Human-facing row, so
    // ui::say (not bare println!: the print ratchet counts those).
    match &sshca {
        Ok(()) => ui::say(&format!(
            "  {:<13} {}  {}",
            "sshd-ca",
            ui::paint(Tone::Ok, "trusted CA configured"),
            ui::paint(Tone::Dim, "TrustedUserCAKeys + principals present"),
        )),
        Err(e) => ui::say(&format!(
            "  {:<13} {}  {}",
            "sshd-ca",
            ui::paint(Tone::Warn, "unconfigured"),
            ui::paint(Tone::Dim, e),
        )),
    }

    // Interfaces.
    println!("  {:<13} {}", "interfaces", iface_summary(&ifaces));
    if ifaces.iter().any(|i| i.vpn) {
        let mut names: Vec<&str> = ifaces.iter().filter(|i| i.vpn).map(|i| i.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        println!(
            "  {:<13} {}",
            "",
            ui::paint(
                Tone::Warn,
                &format!("vpn/tailscale interface present ({}): a common direct-path confounder", names.join(", "))
            ),
        );
    }

    // History.
    println!();
    println!("{}", ui::paint(Tone::Bold, "history (recent connect spans)"));
    println!();
    print_history(&history);
    println!();
    Ok(())
}

fn print_history(h: &diag::Summary) {
    if h.considered == 0 {
        println!("  {}", ui::paint(Tone::Dim, "no recorded connect attempts yet (run `filament doctor <device>` or connect once)"));
        return;
    }
    println!("  attempts     {}", h.considered);
    println!("  succeeded    {}", ui::paint(Tone::Ok, &format!("{} of {}", h.ups, h.considered)));
    if h.fails > 0 {
        println!("  failed       {}", ui::paint(Tone::Warn, &format!("{} of {}", h.fails, h.considered)));
    }
    if let Some(m) = h.median_total_ms {
        println!("  median total {}", fmt_ms(m));
    }
    match &h.worst_phase {
        Some((p, c)) => println!(
            "  worst phase  {}",
            ui::paint(Tone::Warn, &format!("{} (over budget in {} of {} spans)", p.label(), c, h.considered)),
        ),
        None => println!("  worst phase  {}", ui::paint(Tone::Ok, "none over budget")),
    }
    let stall_tone = if h.spans_with_stall == 0 { Tone::Ok } else { Tone::Warn };
    println!(
        "  stall rate   {}",
        ui::paint(stall_tone, &format!("{} of {} spans stalled", h.spans_with_stall, h.considered)),
    );
}

/// Timed GET {server}/api/config (reuses net::http_get_json). Returns the round
/// trip in ms on success.
async fn check_signaling(server: &str) -> std::result::Result<u64, String> {
    let url = format!("{server}/api/config");
    let start = std::time::Instant::now();
    match crate::net::http_get_json(&url).await {
        Ok(_) => Ok(start.elapsed().as_millis() as u64),
        Err(e) => Err(e.to_string()),
    }
}

enum IceResult {
    Ok { srflx: String, class: String, ms: u64 },
    NoServer,
    Failed(String),
}

/// One STUN binding to learn the srflx address: fetch the config's iceServers,
/// pick a stun: url, bind a UDP socket, send a Binding request, classify the
/// reflexive address. Reuses holepunch::{stun_srflx, stun_server_addr}.
async fn check_stun(server: &str) -> IceResult {
    // Pull the stun urls from the live config (the same source a connect uses).
    let cfg = match crate::net::fetch_config(server).await {
        Ok(c) => c,
        Err(e) => return IceResult::Failed(format!("config fetch: {e}")),
    };
    let mut stun_urls: Vec<String> = Vec::new();
    for s in &cfg.ice_servers {
        for u in &s.urls {
            if u.starts_with("stun:") || u.starts_with("stuns:") {
                stun_urls.push(u.clone());
            }
        }
    }
    // Resolve a STUN server to an IPv4 address. The hand-rolled STUN parser
    // (holepunch::stun_srflx) reads the IPv4 XOR-MAPPED-ADDRESS family, and the
    // srflx ADDRESS CLASS (public / RFC1918 / CGNAT) is the IPv4 direct-path
    // signal the report cares about; an IPv6 server answers with a v6 srflx the
    // parser rejects. So prefer a v4 resolution; fall back to whatever resolves.
    let Some(stun_addr) = resolve_stun_v4(&stun_urls).or_else(|| crate::holepunch::stun_server_addr(&stun_urls)) else {
        return IceResult::NoServer;
    };
    // Bind an ephemeral UDP socket and time the binding. stun_srflx is blocking
    // (std UdpSocket), so run it on a blocking thread to keep the runtime clean.
    let start = std::time::Instant::now();
    let res = tokio::task::spawn_blocking(move || {
        // Bind a socket of the SAME family as the STUN server, or send_to fails
        // with "address family not supported" (an IPv4 0.0.0.0 socket cannot
        // reach an IPv6 stun: url, which some configs advertise first).
        let bind = if stun_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = std::net::UdpSocket::bind(bind).map_err(|e| e.to_string())?;
        crate::holepunch::stun_srflx(&sock, stun_addr).map_err(|e| e.to_string())
    })
    .await;
    match res {
        Ok(Ok(srflx)) => {
            let ms = start.elapsed().as_millis() as u64;
            IceResult::Ok { srflx: srflx.to_string(), class: address_class(&srflx), ms }
        }
        Ok(Err(e)) => IceResult::Failed(e),
        Err(e) => IceResult::Failed(e.to_string()),
    }
}

/// Resolve the first `stun:`/`stuns:` url to an IPv4 socket address. Honors a
/// `FILAMENT_STUN` override (host:port) first, mirroring stun_server_addr. Used
/// so the doctor's binding learns an IPv4 srflx (the parser + class are v4).
fn resolve_stun_v4(stun_urls: &[String]) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let mut hostports: Vec<String> = Vec::new();
    if let Ok(v) = std::env::var("FILAMENT_STUN") {
        hostports.push(v.trim().to_string());
    }
    for url in stun_urls {
        if let Some(rest) = url.strip_prefix("stun:").or_else(|| url.strip_prefix("stuns:")) {
            hostports.push(rest.split('?').next().unwrap_or(rest).to_string());
        }
    }
    for hp in hostports {
        let hp = if hp.contains(':') { hp } else { format!("{hp}:3478") };
        if let Ok(addrs) = hp.to_socket_addrs() {
            if let Some(v4) = addrs.filter(|a| a.is_ipv4()).next() {
                return Some(v4);
            }
        }
    }
    None
}

/// A coarse class for a reflexive address: public, private (RFC1918/CGNAT), or
/// loopback. A private/CGNAT srflx hints at carrier-grade NAT (the direct-path
/// confounder the doctor wants to surface).
fn address_class(addr: &std::net::SocketAddr) -> String {
    let ip = addr.ip();
    if ip.is_loopback() {
        return "loopback".into();
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_private() {
                "private (RFC1918)".into()
            } else if is_cgnat(v4) {
                "CGNAT (100.64/10)".into()
            } else {
                "public".into()
            }
        }
        std::net::IpAddr::V6(_) => "ipv6".into(),
    }
}

/// RFC 6598 carrier-grade NAT range 100.64.0.0/10.
fn is_cgnat(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// Coarse class for a bare IP. `filament ping`/`doctor` path display reuses the
/// doctor's taxonomy so "public"/"private (RFC1918)"/"CGNAT (100.64/10)" read
/// identically everywhere. (Tailscale hands out CGNAT addresses, so a local end
/// in 100.64/10 on a `tailscale0` interface is the tailnet, stated as data.)
pub(crate) fn ip_class(ip: std::net::IpAddr) -> String {
    address_class(&std::net::SocketAddr::new(ip, 0))
}

/// Map a local IP (the near end of a selected path) to the interface it belongs
/// to, plus whether that interface is a VPN/tailscale tunnel. `None` when the IP
/// isn't among local interfaces or `ip` is unavailable, the caller then just
/// omits the interface name rather than guessing one.
pub(crate) fn iface_for_ip(ip: std::net::IpAddr) -> Option<(String, bool)> {
    list_interfaces()
        .into_iter()
        .find(|i| i.ip == ip)
        .map(|i| (i.name, i.vpn))
}

struct Iface {
    name: String,
    ip: std::net::IpAddr,
    vpn: bool,
}

/// List local interface IPs, flagging tailscale/vpn interfaces (a common
/// direct-path confounder). Uses `ip -o addr` (Linux) and falls back to parsing
/// minimally; on no tool, returns empty (the report just says "unknown").
fn list_interfaces() -> Vec<Iface> {
    let mut out = Vec::new();
    // `ip -o addr show` is universal on the Linux hosts this runs on. One line
    // per address: "<idx>: <ifname> <family> <addr>/<prefix> ...".
    let Ok(o) = std::process::Command::new("ip").args(["-o", "addr", "show"]).output() else {
        return out;
    };
    let text = String::from_utf8_lossy(&o.stdout);
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // f[1]=ifname, f[2]=family (inet/inet6), f[3]=addr/prefix
        if f.len() < 4 {
            continue;
        }
        let name = f[1].to_string();
        if name == "lo" {
            continue;
        }
        let addr_part = f[3].split('/').next().unwrap_or("");
        let Ok(ip) = addr_part.parse::<std::net::IpAddr>() else { continue };
        // Skip link-local addresses (fe80::/10): noise that never carries a
        // connect. We keep global IPv6 + all IPv4 (including RFC1918/CGNAT, which
        // are exactly the direct-path signal the report wants).
        if is_link_local(&ip) {
            continue;
        }
        let vpn = is_vpn_iface(&name);
        out.push(Iface { name, ip, vpn });
    }
    out
}

/// Link-local addresses (IPv6 fe80::/10, IPv4 169.254/16) never carry a connect;
/// the report drops them to stay readable.
fn is_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Heuristic: interface names that denote a VPN / tailscale tunnel.
fn is_vpn_iface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("tailscale")
        || n.starts_with("ts")
        || n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("wg")
        || n.starts_with("zt") // zerotier
}

fn iface_summary(ifaces: &[Iface]) -> String {
    if ifaces.is_empty() {
        return ui::paint(Tone::Dim, "unknown (no `ip` tool)");
    }
    let parts: Vec<String> = ifaces
        .iter()
        .map(|i| {
            let s = format!("{}={}", i.name, i.ip);
            if i.vpn {
                ui::paint(Tone::Warn, &s)
            } else {
                s
            }
        })
        .collect();
    parts.join("  ")
}

fn preflight_json(
    server: &str,
    sig: &std::result::Result<u64, String>,
    ice: &IceResult,
    ifaces: &[Iface],
    history: &diag::Summary,
    sshca: &std::result::Result<(), String>,
) -> Value {
    let sig_json = match sig {
        Ok(ms) => json!({ "reachable": true, "round_trip_ms": ms }),
        Err(e) => json!({ "reachable": false, "error": e }),
    };
    let ice_json = match ice {
        IceResult::Ok { srflx, class, ms } => json!({ "works": true, "srflx": srflx, "class": class, "round_trip_ms": ms }),
        IceResult::NoServer => json!({ "works": false, "reason": "no stun server in config" }),
        IceResult::Failed(e) => json!({ "works": false, "error": e }),
    };
    let sshca_json = match sshca {
        Ok(()) => json!({ "configured": true }),
        Err(e) => json!({ "configured": false, "detail": e }),
    };
    json!({
        "kind": "filament-doctor-preflight",
        "server": server,
        "signaling": sig_json,
        "ice": ice_json,
        "interfaces": ifaces.iter().map(|i| json!({ "name": i.name, "ip": i.ip.to_string(), "vpn": i.vpn })).collect::<Vec<_>>(),
        "sshd_ca": sshca_json,
        "history": {
            "considered": history.considered,
            "ups": history.ups,
            "fails": history.fails,
            "median_total_ms": history.median_total_ms,
            "worst_phase": history.worst_phase.map(|(p, c)| json!({ "phase": p.label(), "count": c })),
            "spans_with_stall": history.spans_with_stall,
        },
    })
}

// ----------------------------------------------------------------- helpers ----

/// Format ms as a compact "X.Ys" (seconds, one decimal) for the ladder/report.
fn fmt_ms(ms: u64) -> String {
    format!("{:.1}s", ms as f64 / 1000.0)
}

/// Median of a SORTED slice (lower-middle for even length). Mirrors
/// diag::median's contract; kept local so doctor owns its own number-crunching.
fn median(sorted: &[u64]) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[(sorted.len() - 1) / 2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::PhaseTiming;
    use crate::l2::ProbeOutcome;

    fn t(phase: Phase, dur_ms: u64) -> PhaseTiming {
        PhaseTiming { phase, dur_ms, over_budget: diag::over_budget(phase, dur_ms) }
    }

    #[test]
    fn verdict_healthy_when_all_under_budget() {
        let o = ProbeOutcome {
            timings: vec![t(Phase::Signaling, 300), t(Phase::Presence, 700), t(Phase::Establishing, 1500)],
            total_ms: 2500,
            established: true,
            failed_phase: None,
            error: None,
            path: None,
        };
        let v = verdict(&o);
        assert!(v.healthy);
        assert!(v.culprit.is_none());
        assert!(v.line.contains("healthy"));
        assert!(v.line.contains("2.5s"));
    }

    #[test]
    fn verdict_names_first_over_budget_phase() {
        // Establishing budget is 3000ms; 4100 is over. Presence is fine.
        let o = ProbeOutcome {
            timings: vec![t(Phase::Signaling, 300), t(Phase::Presence, 700), t(Phase::Establishing, 4100)],
            total_ms: 5100,
            established: true,
            failed_phase: None,
            error: None,
            path: None,
        };
        let v = verdict(&o);
        assert!(!v.healthy);
        assert_eq!(v.culprit, Some(Phase::Establishing));
        assert!(v.line.contains("establishing"));
    }

    #[test]
    fn verdict_reports_failure_phase() {
        let o = ProbeOutcome {
            timings: vec![t(Phase::Signaling, 300)],
            total_ms: 0,
            established: false,
            failed_phase: Some(Phase::Establishing),
            error: Some("establishment timed out after 30s".into()),
            path: None,
        };
        let v = verdict(&o);
        assert!(!v.healthy);
        assert_eq!(v.culprit, Some(Phase::Establishing));
        assert!(v.line.contains("FAILED"));
        assert!(v.line.contains("establishing"));
    }

    #[test]
    fn address_class_buckets() {
        let pub_addr: std::net::SocketAddr = "8.8.8.8:1".parse().unwrap();
        let priv_addr: std::net::SocketAddr = "192.168.1.5:1".parse().unwrap();
        let cgnat_addr: std::net::SocketAddr = "100.107.184.100:1".parse().unwrap();
        let lo_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(address_class(&pub_addr), "public");
        assert_eq!(address_class(&priv_addr), "private (RFC1918)");
        assert_eq!(address_class(&cgnat_addr), "CGNAT (100.64/10)");
        assert_eq!(address_class(&lo_addr), "loopback");
    }

    #[test]
    fn vpn_iface_detection() {
        assert!(is_vpn_iface("tailscale0"));
        assert!(is_vpn_iface("wg0"));
        assert!(is_vpn_iface("tun0"));
        assert!(!is_vpn_iface("eth0"));
        assert!(!is_vpn_iface("enp0s3"));
    }

    #[test]
    fn fmt_ms_is_one_decimal_seconds() {
        assert_eq!(fmt_ms(0), "0.0s");
        assert_eq!(fmt_ms(1500), "1.5s");
        assert_eq!(fmt_ms(4100), "4.1s");
    }

    #[test]
    fn median_lower_middle() {
        assert_eq!(median(&[]), 0);
        assert_eq!(median(&[5]), 5);
        assert_eq!(median(&[1, 2, 3]), 2);
        assert_eq!(median(&[1, 2, 3, 4]), 2);
    }
}
