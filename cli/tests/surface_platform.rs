//! Ratchet on platform-conditional code outside `platform/`. See
//! docs/architecture/PLATFORM.md.
//!
//! The rule: platform differences live in `platform/`; everything else calls a
//! portable function. We had that structure and routed around it. At the time
//! this landed there were 254 platform-conditional blocks in cli/src and only
//! 40 were in `platform/`; main.rs alone had 97.
//!
//! That is not tidiness. #204 (daemon_alive read /proc inline, constant-false on
//! Windows, three features silently dead), #215 (detach_up's Windows arm
//! computes the log path and discards it) and #205 (ctl.rs unix-only, so bounded
//! invitations cannot be claimed when minted on Windows) are all the same
//! mistake: a platform fact written where it was needed, tested on the platform
//! the author had, wrong elsewhere for an unknown number of releases.
//!
//! A ratchet, not a wall: 214 sites are grandfathered and the number may only go
//! down. A test that is red on day one gets deleted rather than paid.
//!
//! `platform/` is exempt. That is what it is for.

use std::collections::BTreeMap;
use std::path::Path;

/// Platform-conditional blocks allowed per file, relative to `cli/src/`.
/// LOWER THESE. Raising one needs a comment saying why, and "it was easier
/// here" is not a why.
fn budget() -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        // Where every bug listed above came from. Pay this down first: process
        // liveness and daemon control, then the ctl channel, then path
        // stragglers.
        //
        // main.rs was 92 before the 2026-09-12 decomposition. The total grows
        // 209 -> 252, and that growth is honest, not sloppiness: a cfg-gated
        // item moved into a child module now carries its attribute at up to
        // three sites (definition + import + crate-root re-export) where the
        // monolith needed one. New-module entries below mirror that.
        ("main.rs", 30),
        ("recv_cmd.rs", 25),
        ("daemon_ctl.rs", 19),
        ("tests.rs", 13),
        ("recv_files.rs", 10),
        ("runtime_support.rs", 7),
        ("exec_recv.rs", 5),
        ("file_io.rs", 5),
        ("install_service.rs", 5),
        ("update_cmd.rs", 5),
        ("mount_cmd.rs", 4),
        ("dispatch.rs", 3),
        ("exec_send.rs", 3),
        ("shell_support.rs", 3),
        ("up_logs.rs", 2),
        ("conn.rs", 1),
        // Largely irreducible: path encoding genuinely differs across platforms
        // and flattening it loses data. Not a target.
        ("mount_proto.rs", 47),
        ("l2.rs", 39),
        // Should approach zero as the armed set stops needing IPC at all.
        ("ctl.rs", 6),
        ("tun/mod.rs", 6),
        ("sdnotify.rs", 5),
        ("l3.rs", 4),
        ("ping.rs", 3),
        ("mount.rs", 2),
        ("mount_fuse.rs", 2),
        ("expose.rs", 1),
        ("mount_winfsp.rs", 1),
        ("settings.rs", 1),
    ])
}

/// Count `cfg(...)` attributes whose condition mentions a platform. Balances
/// parens so `cfg(all(unix, feature = "x"))` counts once, and deliberately
/// textual: the job is to notice new ones appearing, not to be a parser.
///
/// Must stay identical to the rule that produced the seeded budgets. Two
/// nearly-identical rules would make this red on arrival, which is the same
/// class of mistake the file exists to catch.
fn count(src: &str) -> usize {
    const KEYS: [&str; 4] = ["windows", "unix", "target_os", "target_family"];
    let bytes = src.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while let Some(rel) = src[i..].find("cfg(") {
        let start = i + rel;
        let mut j = start + 4;
        let mut depth = 1usize;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        if KEYS.iter().any(|k| src[start..j].contains(k)) {
            n += 1;
        }
        i = start + 4;
    }
    n
}

fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, usize>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, root, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if rel.starts_with("platform/") {
                continue; // the designated home
            }
            let n = count(&std::fs::read_to_string(&path).unwrap_or_default());
            if n > 0 {
                out.insert(rel, n);
            }
        }
    }
}

#[test]
fn platform_conditionals_outside_the_adapter_do_not_grow() {
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
                "  {file}: {n} platform-conditional blocks, budget {allowed}. \
                 Put the branch in platform/ and call a portable function; \
                 write BOTH arms in the same commit (see docs/architecture/PLATFORM.md)."
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
        "platform branching grew outside platform/:\n{}",
        over.join("\n")
    );
    // Progress recorded, not enforced: a budget left above the real count
    // silently re-opens the room it was meant to close.
    if !under.is_empty() {
        eprintln!("platform budgets that can be lowered:\n{}", under.join("\n"));
    }
}
