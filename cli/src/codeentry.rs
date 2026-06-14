// Interactive, steered, color-coded code entry — the CLI sibling of the
// browser's CodeInput / CustomCodeEntry. When `pair`/`recv`/`send` run WITHOUT
// a code (or with a malformed one) AND we're allowed to be interactive (see the
// gate in main.rs), we drop into a browser-like live entry:
//
//   * auto-inserts dashes (space -> '-'), refuses bad characters entirely,
//   * judges the code instantly with color (red / amber / green),
//   * steers the user (REPL-like: won't submit an incomplete code).
//
// DESIGN: the crossterm event loop is kept THIN. ALL formatting + judging lives
// in PURE functions (`format_buffer`, `judge`) so they're unit-testable with no
// TTY. The judging uses the SHARED `filament_pake` split/normalize functions and
// the crate's `password_word_tokens`, so the CLI's verdict matches the browser
// and the actual PAKE parse byte-for-byte.

use crate::ui;
use std::io::Write;

/// Which side of the ceremony we're judging for. CREATE = the user is minting a
/// code for someone else (pair creator / `send --code`); CLAIM = the user is
/// typing a code somebody read them (`pair <code>` / `recv <code>`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Create,
    Claim,
}

/// How "done" the current buffer is. Drives the color of the steer line and
/// whether Enter is allowed to submit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    /// nothing typed yet — dim hint
    Empty,
    /// content, but not a submittable code — amber, keep steering
    Incomplete,
    /// a complete, submittable code — green, Enter submits
    Ready,
}

/// The pure verdict for a buffer: a level (color), a one-line steer message, and
/// an optional preview of the resolved code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judgment {
    pub level: Level,
    pub steer: String,
    pub preview: Option<String>,
}

/// Normalize a raw buffer the way the browser's CodeInput `format` does, but
/// toward the SPAKE2-normalized lower-case form (so what the user sees IS what
/// gets hashed). Pure + total:
///   * lowercase,
///   * map space (and any whitespace) -> '-',
///   * collapse runs of '-' to a single '-',
///   * strip leading '-',
///   * KEEP only [a-z0-9-]; everything else is dropped (bad chars never enter).
///
/// We intentionally do NOT strip a trailing '-' here — the user may be mid-type
/// between words, and a visible trailing dash is correct feedback. `judge`
/// tolerates it via the shared split.
pub fn format_buffer(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let mapped = if ch.is_whitespace() { '-' } else { ch.to_ascii_lowercase() };
        if mapped == '-' {
            // collapse runs; drop a leading dash entirely
            if prev_dash || out.is_empty() {
                continue;
            }
            out.push('-');
            prev_dash = true;
        } else if mapped.is_ascii_lowercase() || mapped.is_ascii_digit() {
            out.push(mapped);
            prev_dash = false;
        }
        // anything else (punctuation, symbols, non-ascii) is simply not inserted
    }
    out
}

/// Is `s` a 3-5 ASCII-digit nameplate (the minted-code suffix shape)?
fn is_nameplate(s: &str) -> bool {
    (3..=5).contains(&s.len()) && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Judge a buffer for the given mode. PURE — uses the shared pake split/normalize
/// and the crate strength floor, so it agrees with the browser and the real parse.
///
/// `auto_nameplate` is the stable machine-minted number shown (dimmed) in the
/// CREATE preview — mint it ONCE per session (like the browser's autoNpRef) and
/// pass it in, so the preview doesn't reshuffle on every keystroke.
pub fn judge(buf: &str, mode: Mode, auto_nameplate: &str) -> Judgment {
    let normalized = filament_pake::norm_code(buf);
    let trimmed = normalized.trim_matches('-');

    if trimmed.is_empty() {
        let steer = match mode {
            Mode::Claim => "type the code they read you, e.g. brave-otter-3141".to_string(),
            Mode::Create => "type two words, easier to say and harder to guess".to_string(),
        };
        return Judgment { level: Level::Empty, steer, preview: None };
    }

    match mode {
        Mode::Claim => {
            // Claim side: the shared `split_code` peels the TRAILING dash-group as
            // the nameplate; everything before it is the password (words).
            let (np, pw) = filament_pake::split_code(trimmed);
            let has_words = !pw.is_empty();
            let np_ok = is_nameplate(&np);
            if np_ok && has_words {
                return Judgment {
                    level: Level::Ready,
                    steer: "✓ ready, press enter".to_string(),
                    preview: Some(format!("{pw} · {np}")),
                };
            }
            // A bare number, no words (e.g. "3141"): split_code returns np=whole,
            // pw empty.
            if !has_words {
                return Judgment {
                    level: Level::Incomplete,
                    steer: "add the words before the number".to_string(),
                    preview: None,
                };
            }
            // Words present but the trailing group isn't a 3-5 digit nameplate.
            Judgment {
                level: Level::Incomplete,
                steer: "keep going, a full code ends in a 3-5 digit number".to_string(),
                preview: None,
            }
        }
        Mode::Create => {
            // Create side: keep ALL words as the password; the nameplate is always
            // machine-minted. `split_chosen_code` only strips a trailing 3-5 digit
            // group, so "gigantic-element" keeps both words.
            let (words, _np) = filament_pake::split_chosen_code(trimmed);
            if crate::password_word_tokens(&words) < 2 {
                return Judgment {
                    level: Level::Incomplete,
                    steer: "add another word, easier to say and harder to guess".to_string(),
                    preview: None,
                };
            }
            Judgment {
                level: Level::Ready,
                steer: format!("✓ {words}, press enter to create"),
                // the auto-nameplate rides along dimmed in the preview
                preview: Some(format!("{words}-{auto_nameplate}")),
            }
        }
    }
}

/// The OUTCOME of one interactive entry session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The user submitted a Ready buffer. For CREATE this is the words-only
    /// password (no nameplate); for CLAIM it's the normalized full code.
    Submitted(String),
    /// The user pressed Enter on an EMPTY buffer (a deliberate "use the default"
    /// — auto-mint for create, local-network for recv/send).
    Empty,
    /// Esc / Ctrl-C — the user backed out entirely.
    Cancelled,
}

// --------------------------------------------------------------------------
// The thin crossterm event loop. Everything above is pure + tested; this part
// only wires keystrokes -> format_buffer/judge and paints.
// --------------------------------------------------------------------------

/// RAII guard: enables raw mode on construction and ALWAYS restores the terminal
/// on drop (success, cancel, error, OR panic). This is the one thing we must
/// never get wrong — a leaked raw mode wedges the user's shell.
struct RawGuard {
    active: bool,
}

impl RawGuard {
    fn enable() -> std::io::Result<RawGuard> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawGuard { active: true })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        if self.active {
            // Best-effort restore; never panic in drop.
            let _ = crossterm::terminal::disable_raw_mode();
            // Move to a fresh line and show the cursor so the prompt that follows
            // starts clean.
            let mut err = std::io::stderr();
            let _ = crossterm::execute!(err, crossterm::cursor::Show);
            let _ = write!(err, "\r\n");
            let _ = err.flush();
        }
    }
}

/// ANSI color for a level, respecting the existing ui caps/no-color story.
fn level_color(level: Level) -> Option<&'static str> {
    if !ui::caps().color {
        return None;
    }
    Some(match level {
        Level::Empty => "\x1b[2m",       // dim
        Level::Incomplete => "\x1b[33m", // amber/yellow
        Level::Ready => "\x1b[32m",      // green
    })
}

/// Render the entry on a SINGLE line, redrawn in place. We deliberately avoid
/// save/restore-cursor (`\x1b[s`/`\x1b[u`) and newlines: some shells ignore SCO
/// save/restore, which made the entry walk down a line per keystroke on those
/// terminals. A single line cleared with CR + erase-line (`\r\x1b[2K`) redraws
/// consistently on every terminal.
fn render(prompt: &str, buf: &str, j: &Judgment) {
    let mut err = std::io::stderr();
    let reset = if ui::caps().color { "\x1b[0m" } else { "" };
    let color = level_color(j.level).unwrap_or("");
    let preview = match &j.preview {
        Some(p) => {
            if ui::caps().color { format!("  \x1b[2m{p}{reset}") } else { format!("  {p}") }
        }
        None => String::new(),
    };
    // Clear the whole line, then draw: prompt+buffer, a gap, the colored steer
    // plus optional dim preview.
    let _ = write!(err, "\r\x1b[2K{prompt}{buf}   {color}{}{reset}{preview}", j.steer);
    // Put the caret back right after the typed buffer (browser-like), so typing
    // continues at the end of the code rather than after the steer text.
    let col = prompt.chars().count() + buf.chars().count();
    let _ = write!(err, "\r");
    if col > 0 {
        let _ = write!(err, "\x1b[{col}C");
    }
    let _ = err.flush();
}

/// Drive the live, steered entry. Returns the user's outcome. The terminal is
/// ALWAYS restored before returning (RawGuard). `prefill` seeds the buffer (used
/// for the malformed-arg "fix it" path). Pass the SAME `auto_nameplate` you'll
/// use to actually mint, so the preview is honest.
pub fn run(prompt: &str, mode: Mode, prefill: &str, auto_nameplate: &str) -> std::io::Result<Outcome> {
    use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    let _guard = RawGuard::enable()?;

    let mut buf = format_buffer(prefill);
    // Initial paint.
    {
        let j = judge(&buf, mode, auto_nameplate);
        render(prompt, &buf, &j);
    }

    loop {
        let ev = event::read()?;
        let Event::Key(KeyEvent { code, modifiers, kind, .. }) = ev else { continue };
        // Only react to presses (Windows sends Release/Repeat too).
        if kind == KeyEventKind::Release {
            continue;
        }
        match code {
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(Outcome::Cancelled);
            }
            KeyCode::Char('d') if modifiers.contains(KeyModifiers::CONTROL) => {
                // Ctrl-D on empty = cancel (EOF-like); otherwise ignore.
                if buf.is_empty() {
                    return Ok(Outcome::Cancelled);
                }
            }
            KeyCode::Esc => return Ok(Outcome::Cancelled),
            KeyCode::Enter => {
                let j = judge(&buf, mode, auto_nameplate);
                match j.level {
                    Level::Ready => {
                        let result = match mode {
                            // CREATE submits the words-only password (no nameplate);
                            // the caller mints the nameplate.
                            Mode::Create => {
                                let (words, _np) = filament_pake::split_chosen_code(
                                    &filament_pake::norm_code(&buf),
                                );
                                words
                            }
                            // CLAIM submits the normalized full code.
                            Mode::Claim => filament_pake::norm_code(&buf),
                        };
                        return Ok(Outcome::Submitted(result));
                    }
                    Level::Empty => return Ok(Outcome::Empty),
                    // Incomplete: refuse to submit, keep steering (REPL-like).
                    Level::Incomplete => { /* fall through, redraw */ }
                }
            }
            KeyCode::Backspace => {
                buf.pop();
                buf = format_buffer(&buf);
            }
            KeyCode::Char(c) => {
                // Run the new char through the filter by appending then
                // re-formatting; bad chars are simply not inserted.
                let mut candidate = buf.clone();
                candidate.push(c);
                buf = format_buffer(&candidate);
            }
            _ => {}
        }
        let j = judge(&buf, mode, auto_nameplate);
        render(prompt, &buf, &j);
    }
}

// -------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_lowercases_and_keeps_valid() {
        assert_eq!(format_buffer("Brave-Otter-3141"), "brave-otter-3141");
        assert_eq!(format_buffer("ABC123"), "abc123");
    }

    #[test]
    fn format_maps_space_to_dash() {
        assert_eq!(format_buffer("gigantic element"), "gigantic-element");
        assert_eq!(format_buffer("brave otter ruby"), "brave-otter-ruby");
    }

    #[test]
    fn format_collapses_dashes_and_strips_leading() {
        assert_eq!(format_buffer("brave---otter"), "brave-otter");
        assert_eq!(format_buffer("---brave"), "brave");
        assert_eq!(format_buffer("  leading"), "leading");
        // multiple spaces collapse too
        assert_eq!(format_buffer("a   b"), "a-b");
    }

    #[test]
    fn format_rejects_bad_chars_entirely() {
        // '!', '@', '/', emoji etc. never enter the buffer.
        assert_eq!(format_buffer("brave!otter"), "braveotter");
        assert_eq!(format_buffer("a@b/c"), "abc");
        assert_eq!(format_buffer("café"), "caf"); // non-ascii 'é' dropped
        assert_eq!(format_buffer("UP!!!"), "up");
    }

    #[test]
    fn format_keeps_trailing_dash_midtype() {
        // mid-type between words — trailing dash is honest feedback
        assert_eq!(format_buffer("brave-"), "brave-");
    }

    const NP: &str = "1234";

    // ---- CLAIM judgments ----

    #[test]
    fn claim_empty_is_dim_hint() {
        let j = judge("", Mode::Claim, NP);
        assert_eq!(j.level, Level::Empty);
        assert!(j.steer.contains("brave-otter-3141"));
        assert_eq!(j.preview, None);
    }

    #[test]
    fn claim_words_without_nameplate_is_amber() {
        let j = judge("brave-otter", Mode::Claim, NP);
        assert_eq!(j.level, Level::Incomplete);
        assert!(j.steer.contains("3-5 digit"));
    }

    #[test]
    fn claim_bare_number_steers_to_add_words() {
        let j = judge("3141", Mode::Claim, NP);
        assert_eq!(j.level, Level::Incomplete);
        assert!(j.steer.contains("add the words"));
    }

    #[test]
    fn claim_full_code_is_ready_with_preview() {
        let j = judge("brave-otter-3141", Mode::Claim, NP);
        assert_eq!(j.level, Level::Ready);
        assert!(j.steer.contains("ready"));
        assert_eq!(j.preview.as_deref(), Some("brave-otter · 3141"));
    }

    #[test]
    fn claim_three_word_code_is_ready() {
        let j = judge("brave-otter-ruby-314", Mode::Claim, NP);
        assert_eq!(j.level, Level::Ready);
        assert_eq!(j.preview.as_deref(), Some("brave-otter-ruby · 314"));
    }

    #[test]
    fn claim_short_trailing_group_not_nameplate() {
        // a 2-digit trailing group is NOT a 3-5 digit nameplate
        let j = judge("brave-otter-31", Mode::Claim, NP);
        assert_eq!(j.level, Level::Incomplete);
    }

    #[test]
    fn claim_tolerates_messy_input() {
        // upper case + spaces + bad chars all normalize
        let j = judge("BRAVE  OTTER!! 3141", Mode::Claim, NP);
        assert_eq!(j.level, Level::Ready);
    }

    // ---- CREATE judgments ----

    #[test]
    fn create_empty_is_dim_hint() {
        let j = judge("", Mode::Create, NP);
        assert_eq!(j.level, Level::Empty);
    }

    #[test]
    fn create_single_word_is_amber() {
        let j = judge("gigantic", Mode::Create, NP);
        assert_eq!(j.level, Level::Incomplete);
        assert!(j.steer.contains("add another word"));
    }

    #[test]
    fn create_two_words_is_ready_with_auto_nameplate() {
        let j = judge("gigantic-element", Mode::Create, NP);
        assert_eq!(j.level, Level::Ready);
        assert!(j.steer.contains("gigantic-element"));
        assert_eq!(j.preview.as_deref(), Some("gigantic-element-1234"));
    }

    #[test]
    fn create_strips_user_typed_number_from_password() {
        // a user-typed 3-5 digit trailing group is dropped from the password
        // (the nameplate is always machine-minted)
        let j = judge("gigantic-element-999", Mode::Create, NP);
        assert_eq!(j.level, Level::Ready);
        assert_eq!(j.preview.as_deref(), Some("gigantic-element-1234"));
    }

    #[test]
    fn create_space_separated_words_ready() {
        let j = judge("brave otter", Mode::Create, NP);
        assert_eq!(j.level, Level::Ready);
    }

    #[test]
    fn create_single_word_plus_number_still_amber() {
        // "cat-12345" -> split_chosen strips 12345, leaves "cat" = 1 token
        let j = judge("cat-12345", Mode::Create, NP);
        assert_eq!(j.level, Level::Incomplete);
    }
}
