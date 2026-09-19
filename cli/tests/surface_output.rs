//! Ratchet on bare print macros. See docs/ui/OUTPUT.md.
//!
//! Human-facing output goes through `ui::say` / `ui::critical` / `ui::trace`,
//! which apply the verbosity gate, colour capability and glyph fallbacks.
//! `println!` is for stdout, machine-readable output that must NOT be gated.
//! `eprintln!` for human text is always wrong: it looks like UI, and under `-q`
//! it is the one thing still shouting.
//!
//! A wall would be useless here. There are 338 existing sites and a test that
//! is red on day one gets deleted, so this is a RATCHET: each file has a budget
//! and the number may only go down. Converting calls and lowering the budget in
//! the same commit is the intended way to pay it off.
//!
//! Concrete defect this guards, from the invitation screen: its body printed
//! with `eprintln!` and its footer with `ui::say`, so under `-q` the user got
//! the footer and not the invitation.

use std::collections::BTreeMap;
use std::path::Path;

/// Bare print macros allowed per file, relative to `cli/src/`.
/// LOWER THESE. Raising one needs a comment saying why, and "it was easier"
/// is not a why.
fn budget() -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        // main.rs was 154 before the 2026-09-12 decomposition (26,261 -> 1,845
        // lines); its prints moved with their code. Sum 337 -> 328.
        ("main.rs", 1),
        ("dispatch.rs", 65),
        ("identity_flow.rs", 20),
        ("add_for.rs", 12),
        ("mount_cmd.rs", 8),
        ("recv_cmd.rs", 8),
        ("update_cmd.rs", 8),
        ("send_cmd.rs", 7),
        ("conn.rs", 4),
        ("up_logs.rs", 4),
        ("runtime_support.rs", 3),
        ("devices_store.rs", 1),
        ("enrollment.rs", 1),
        ("pair_cmd.rs", 1),
        ("recv_files.rs", 1),
        ("status_cmd.rs", 1),
        ("mount.rs", 47),
        ("doctor.rs", 44),
        ("settings.rs", 37),
        ("direct.rs", 14),
        // reach now renders every human line through ui:: (the route label is
        // must-see, so ui::critical); the two left are the --json envelopes.
        ("ping.rs", 2),
        ("tun/linux.rs", 11),
        ("interact.rs", 5),
        // ui.rs is the emitter of last resort; these ARE the implementation.
        ("ui.rs", 4),
        ("l2.rs", 3),
        ("net.rs", 3),
        ("capability.rs", 2),
        ("tun/macos.rs", 1),
        ("tun/windows.rs", 1),
    ])
}

/// Count `eprintln!` and `println!`, ignoring `writeln!`-style macros and any
/// `::println!` path form. Deliberately textual: the point is to notice new
/// calls appearing, not to be a parser.
fn count(src: &str) -> usize {
    // Comments are prose about the code, not calls in it. A comment saying
    // "use ui::say, not println!" counted as two bare prints and pushed main.rs
    // over budget, which is the ratchet measuring the wrong thing: the docs it
    // exists to enforce cannot be quoted in the code it guards.
    //
    // Stripping comment lines only ever LOWERS a count, so no budget can turn
    // red from this; the slack is reported by the existing under-budget notice
    // and paid off by lowering the numbers, which this commit does.
    let src: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let src = src.as_str();
    let mut n = 0;
    for (i, _) in src.match_indices("println!") {
        // Skip when preceded by a word char or a colon: that is the tail of
        // `eprintln!` (counted separately below) or a path form like
        // `std::println!`. This must stay identical to the rule that produced
        // the seeded budgets, or the ratchet is red the day it lands.
        match src[..i].chars().next_back() {
            Some(c) if c.is_alphanumeric() || c == '_' || c == ':' => continue,
            _ => n += 1,
        }
    }
    n + src.matches("eprintln!").count()
}

fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, usize>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, root, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            let src = std::fs::read_to_string(&path).unwrap_or_default();
            let n = count(&src);
            if n > 0 {
                out.insert(rel, n);
            }
        }
    }
}

#[test]
fn bare_print_macros_do_not_grow() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = BTreeMap::new();
    walk(&root, &root, &mut found);
    let budget = budget();

    let mut over = Vec::new();
    let mut under = Vec::new();
    for (file, &n) in &found {
        let allowed = budget.get(file.as_str()).copied().unwrap_or(0);
        if n > allowed {
            over.push(format!(
                "  {file}: {n} bare print macros, budget {allowed}. \
                 Use ui::say / ui::critical / ui::trace for human output; \
                 println! only for stdout a script consumes."
            ));
        } else if n < allowed {
            under.push(format!("  {file}: {n}, budget {allowed} — lower it"));
        }
    }
    for file in budget.keys() {
        if !found.contains_key(*file) {
            under.push(format!("  {file}: 0 now — drop it from the budget"));
        }
    }

    assert!(
        over.is_empty(),
        "new bare print macros (see docs/ui/OUTPUT.md):\n{}",
        over.join("\n")
    );
    // Progress is not a failure, but it should not go unrecorded either: a
    // budget left above the real count silently re-opens the room it was
    // meant to close.
    if !under.is_empty() {
        eprintln!("budgets that can be lowered:\n{}", under.join("\n"));
    }
}
