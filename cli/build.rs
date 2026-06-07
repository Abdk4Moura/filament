// Stamp the binary with commit + date for `filament --version`.
// CI can override via FILAMENT_BUILD_SHA / FILAMENT_BUILD_DATE.
use std::process::Command;

fn main() {
    let sha = std::env::var("FILAMENT_BUILD_SHA").ok().or_else(|| {
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    });
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
    // re-stamp on every new commit, not just env changes
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs/heads/main");
    println!("cargo:rerun-if-env-changed=FILAMENT_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=FILAMENT_BUILD_DATE");
}
