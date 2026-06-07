// The output layer — every styled byte goes through here, nowhere else.
//
// Capability detection happens ONCE; everything degrades in order:
//   truecolor -> ansi-256 -> mono;  unicode -> ascii;  tty -> plain pipe mode
// Pipe mode emits zero ANSI, zero \r redraws, zero spinners: appendable lines
// only, so logs and scripts stay clean. NO_COLOR and TERM=dumb are honored.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

pub struct Caps {
    pub tty: bool,
    pub color: bool,
    pub truecolor: bool,
    pub unicode: bool,
}

pub fn caps() -> &'static Caps {
    static C: OnceLock<Caps> = OnceLock::new();
    C.get_or_init(|| {
        let tty = std::io::stderr().is_terminal();
        let term = std::env::var("TERM").unwrap_or_default();
        let color = tty
            && std::env::var_os("NO_COLOR").is_none()
            && term != "dumb"
            && std::env::var("FILAMENT_COLOR").as_deref() != Ok("never");
        let truecolor = color
            && std::env::var("COLORTERM")
                .map(|v| v.contains("truecolor") || v.contains("24bit"))
                .unwrap_or(false);
        let unicode = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_CTYPE"))
            .or_else(|_| std::env::var("LANG"))
            .map(|v| v.to_uppercase().contains("UTF"))
            .unwrap_or(cfg!(windows)); // Windows Terminal is UTF-16 native
        Caps { tty, color, truecolor, unicode }
    })
}

// ------------------------------------------------------------------ paint --

pub enum Tone {
    /// the brand: filament green (#7CF6C8)
    Brand,
    Ok,
    Err,
    Warn,
    Dim,
    Bold,
}

pub fn paint(tone: Tone, s: &str) -> String {
    let c = caps();
    if !c.color {
        return s.to_string();
    }
    let code = match tone {
        Tone::Brand if c.truecolor => "\x1b[1;38;2;124;246;200m".to_string(),
        Tone::Brand => "\x1b[1;92m".to_string(),
        Tone::Ok => "\x1b[32m".to_string(),
        Tone::Err => "\x1b[31m".to_string(),
        Tone::Warn => "\x1b[33m".to_string(),
        Tone::Dim => "\x1b[2m".to_string(),
        Tone::Bold => "\x1b[1m".to_string(),
    };
    format!("{code}{s}\x1b[0m")
}

pub fn glyph_ok() -> &'static str {
    if caps().unicode { "✓" } else { "ok" }
}
#[allow(dead_code)] // part of the glyph set; error paths adopt it next
pub fn glyph_err() -> &'static str {
    if caps().unicode { "✗" } else { "x" }
}
pub fn glyph_arrow() -> &'static str {
    if caps().unicode { "→" } else { "->" }
}

/// OSC 8 hyperlink (clickable in modern terminals); plain text elsewhere.
pub fn link(url: &str, text: &str) -> String {
    if caps().color {
        format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
    } else {
        text.to_string()
    }
}

/// OSC 52: put `s` on the terminal's clipboard (silently unsupported in some
/// terminals; harmless there). Only on a tty.
pub fn clipboard(s: &str) {
    use base64_mini::enc;
    if caps().tty {
        eprint!("\x1b]52;c;{}\x07", enc(s.as_bytes()));
    }
}

mod base64_mini {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    pub fn enc(d: &[u8]) -> String {
        let mut out = String::with_capacity(d.len().div_ceil(3) * 4);
        for ch in d.chunks(3) {
            let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
            let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if ch.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if ch.len() > 2 { T[n as usize & 63] as char } else { '=' });
        }
        out
    }
}

// ----------------------------------------------------------------- status --
// One living line on stderr, redrawn in place on a tty; on a pipe, nothing
// until a final say()/done() line. Spinner frames are braille.

static LIVE: AtomicBool = AtomicBool::new(false);

fn clear_live() {
    if LIVE.swap(false, Ordering::Relaxed) && caps().tty {
        eprint!("\r\x1b[2K");
    }
}

// Sticky status (C22): an open question or countdown survives interleaved
// say() lines — async events (route detection, peer chatter) print ABOVE it
// and the sticky line is repainted, instead of clobbering a half-typed
// prompt (observed live: "accept? [y/N]     route: direct").
static STICKY: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn paint_live(line: &str) {
    clear_live();
    eprint!("{line}");
    let _ = std::io::stderr().flush();
    LIVE.store(true, Ordering::Relaxed);
}

/// Permanent line (survives in scrollback); repaints any sticky line below.
pub fn say(line: &str) {
    clear_live();
    eprintln!("{line}");
    if let Ok(s) = STICKY.lock() {
        if let Some(st) = s.as_ref() {
            if caps().tty {
                paint_live(st);
            }
        }
    }
}

/// Transient line: replaced by the next say()/status()/bar tick. No-op noise
/// on pipes (suppressed entirely).
pub fn status(line: &str) {
    if !caps().tty {
        return;
    }
    paint_live(line);
}

/// A status line that survives interleaved say()s until cleared — for open
/// questions and countdowns.
pub fn sticky(line: &str) {
    if let Ok(mut s) = STICKY.lock() {
        *s = Some(line.to_string());
    }
    status(line);
}

pub fn clear_sticky() {
    let had = STICKY.lock().map(|mut s| s.take().is_some()).unwrap_or(false);
    if had && caps().tty {
        clear_live();
    }
}

pub fn spinner_frame() -> char {
    const U: [char; 8] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];
    const A: [char; 4] = ['|', '/', '-', '\\'];
    let t = (Instant::now().elapsed().as_millis() / 80) as usize; // monotonic-ish
    if caps().unicode { U[t % 8] } else { A[t % 4] }
}

// ------------------------------------------------------------- progress bar --

pub struct Progress {
    label: String,
    total: u64,
    started: Instant,
    rate_ema: f64,
    last_draw: Instant,
    last_bytes: u64,
}

impl Progress {
    pub fn new(label: &str, total: u64) -> Progress {
        Progress {
            label: label.to_string(),
            total,
            started: Instant::now(),
            rate_ema: 0.0,
            last_draw: Instant::now() - std::time::Duration::from_secs(1),
            last_bytes: 0,
        }
    }

    /// Thin filament-style bar: done in brand green (━), boundary ╸, rest dim.
    pub fn tick(&mut self, bytes: u64) {
        let now = Instant::now();
        if now.duration_since(self.last_draw).as_millis() < 100 {
            return;
        }
        let dt = now.duration_since(self.last_draw).as_secs_f64();
        let inst = (bytes.saturating_sub(self.last_bytes)) as f64 / dt.max(0.001);
        // EMA so the rate reads steady instead of jittering every frame
        self.rate_ema = if self.rate_ema == 0.0 { inst } else { 0.85 * self.rate_ema + 0.15 * inst };
        self.last_draw = now;
        self.last_bytes = bytes;
        if !caps().tty {
            return;
        }
        let frac = (bytes as f64 / self.total.max(1) as f64).min(1.0);
        let width = 22usize;
        let filled = (frac * width as f64) as usize;
        let bar = if caps().unicode {
            let done = "━".repeat(filled.min(width));
            let edge = if filled < width { "╸" } else { "" };
            let rest = "─".repeat(width - filled - if filled < width { 1 } else { 0 });
            format!("{}{}{}", paint(Tone::Brand, &done), paint(Tone::Brand, edge), paint(Tone::Dim, &rest))
        } else {
            let done = "=".repeat(filled.min(width));
            let rest = "-".repeat(width - filled);
            format!("{done}{rest}")
        };
        let eta = if self.rate_ema > 1.0 && bytes < self.total {
            let s = ((self.total - bytes) as f64 / self.rate_ema) as u64;
            format!("{}:{:02}", s / 60, s % 60)
        } else {
            "-:--".into()
        };
        status(&format!(
            "  {}  {}  {}  {}  {}",
            self.label,
            bar,
            paint(Tone::Bold, &format!("{:>3.0}%", frac * 100.0)),
            paint(Tone::Dim, &format!("{}/s", crate::human(self.rate_ema as u64))),
            paint(Tone::Dim, &eta),
        ));
    }

    /// Final summary line; rings the bell (opt-in via tty) for long transfers.
    pub fn done(&self, bytes: u64) {
        let secs = self.started.elapsed().as_secs_f64().max(0.001);
        let rate = bytes as f64 / secs;
        say(&format!(
            "  {} {}  {}",
            paint(Tone::Ok, glyph_ok()),
            self.label,
            paint(Tone::Dim, &format!("{} · {}/s", crate::human(bytes), crate::human(rate as u64))),
        ));
        if caps().tty && secs > 30.0 {
            eprint!("\x07");
        }
    }
}

// --------------------------------------------------------------------- QR --

/// Render a QR code in half-height blocks (2 modules per char row). Empty
/// string when unicode is unavailable.
pub fn qr(url: &str) -> String {
    if !caps().unicode {
        return String::new();
    }
    let Ok(code) = qrcode::QrCode::new(url.as_bytes()) else {
        return String::new();
    };
    let w = code.width();
    let get = |x: i32, y: i32| -> bool {
        if x < 0 || y < 0 || x >= w as i32 || y >= w as i32 {
            false
        } else {
            code[(x as usize, y as usize)] == qrcode::Color::Dark
        }
    };
    let mut out = String::new();
    let q = 2; // quiet zone
    let mut y = -q;
    while y < w as i32 + q {
        out.push_str("         ");
        for x in -q..w as i32 + q {
            out.push(match (get(x, y), get(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    out
}
