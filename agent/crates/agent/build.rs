//! Stamps the binary with its build identity so the self-updater (and the HUD)
//! can tell one build from the next. In CI these come from the workflow
//! (`NETSCOPE_BUILD_ID` = the run number, monotonic; `NETSCOPE_BUILD_SHA` = the
//! commit); locally they fall back to `0` ("dev" — updates disabled) and the
//! short git SHA. The numeric id is the comparison key: a published build whose
//! id is higher than the running one is an available update.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=NETSCOPE_BUILD_ID");
    println!("cargo:rerun-if-env-changed=NETSCOPE_BUILD_SHA");

    let id = std::env::var("NETSCOPE_BUILD_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "0".into());

    let sha = std::env::var("NETSCOPE_BUILD_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(git_short_sha)
        .unwrap_or_else(|| "dev".into());

    println!("cargo:rustc-env=NETSCOPE_BUILD_ID={}", id.trim());
    println!("cargo:rustc-env=NETSCOPE_BUILD_SHA={}", sha.trim());
}

fn git_short_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
