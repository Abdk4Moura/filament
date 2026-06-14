// Stamp the binary with commit + date for `filament --version`.
// CI can override via FILAMENT_BUILD_SHA / FILAMENT_BUILD_DATE.
use std::path::Path;
use std::process::Command;

/// Run a git command from the crate dir and return trimmed stdout on success.
fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Emit a `rerun-if-changed` for a path if it actually exists. Cargo only
/// re-runs the build script when a WATCHED, EXISTING file changes, so we resolve
/// the real on-disk paths (which differ for plain clones, worktrees, and packed
/// refs) instead of hard-coding `../.git/...`.
fn watch_if_exists(path: &str) {
    if !path.is_empty() && Path::new(path).exists() {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn main() {
    let sha = std::env::var("FILAMENT_BUILD_SHA")
        .ok()
        .or_else(|| git(&["rev-parse", "--short", "HEAD"]));
    let date = std::env::var("FILAMENT_BUILD_DATE").ok().or_else(|| {
        Command::new("date")
            .args(["-u", "+%Y-%m-%d"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    });
    println!(
        "cargo:rustc-env=FILAMENT_BUILD_INFO={} ({} {})",
        env!("CARGO_PKG_VERSION"),
        sha.unwrap_or_else(|| "dev".into()),
        date.unwrap_or_else(|| "unstamped".into()),
    );

    // Re-stamp whenever HEAD moves (new commit, checkout, branch switch), not
    // just when the env overrides change. We ask git for the real paths so this
    // works in plain checkouts, linked worktrees, and packed-ref repos alike.
    //
    //   * HEAD itself: changes on checkout / branch switch (per-worktree).
    //   * The ref HEAD points at (e.g. refs/heads/<branch>): changes on commit.
    //   * packed-refs: the fallback when the branch ref is packed (loose file
    //     absent), so a commit that updates a packed ref still re-triggers.
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        watch_if_exists(&head);
    }
    // The loose file backing the currently checked-out ref, if any.
    if let Some(symref) = git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(ref_path) = git(&["rev-parse", "--git-path", &symref]) {
            watch_if_exists(&ref_path);
        }
    }
    // packed-refs lives in the common dir; covers the packed-ref case.
    if let Some(packed) = git(&["rev-parse", "--git-path", "packed-refs"]) {
        watch_if_exists(&packed);
    }

    println!("cargo:rerun-if-env-changed=FILAMENT_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=FILAMENT_BUILD_DATE");
}
