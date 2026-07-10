//! # Self-update (the Windows product path)
//!
//! The product ships as one `netscope.exe`. Rather than ask the user to re-download
//! it, the agent checks a rolling **`latest`** GitHub release (published by CI on
//! every push to `main`) and — *with the user's click* — replaces itself in place.
//!
//! Shape of it:
//!   - each build is stamped with a monotonic `build` id (`build.rs`);
//!   - CI publishes `latest.json` (a manifest) + `netscope.exe` to the `latest`
//!     release. The manifest's `build` is the comparison key;
//!   - on launch the agent fetches the manifest (HTTPS, from the known repo) and,
//!     if `manifest.build > our build`, marks an update *available* — it does not
//!     apply anything;
//!   - the HUD surfaces the banner; `POST /update/apply` (loopback only) downloads
//!     the exe, verifies its SHA-256 against the manifest, and self-replaces.
//!
//! Trust posture (see `docs/threat-model.md`): the fetch is HTTPS from a fixed
//! repo URL (transport authenticity), the download is integrity-checked against
//! the manifest's hash, apply is loopback-only (a remote paired client cannot push
//! a binary onto your machine), and a `dev` build (id 0) or `NETSCOPE_NO_UPDATE`
//! disables it entirely — both the background poll *and* a manual
//! `/update/check` or `/update/apply` hit. This is integrity + locality, not
//! code-signing — stated plainly rather than implied.
//!
//! ## This is the single-exe product's updater — the desktop app has its own
//!
//! The Tauri desktop shell (`frontend/src-tauri`) always sets
//! `NETSCOPE_NO_UPDATE` on its bundled sidecar. It has to: this self-replace
//! path only ever touches the currently-running exe, which for the desktop
//! product is the sidecar, not the installed shell — updating just the
//! sidecar would leave the shell (and its own copy of the sidecar inside the
//! installer) stale, and worse, would fetch the *single-exe browser build's*
//! manifest (a different product, published by a different CI job with an
//! unrelated build-id sequence) and self-replace the sidecar with it. The
//! desktop app instead updates as a whole — shell, sidecar, and all — through
//! Tauri's own signed updater plugin (`frontend/src-tauri/src/main.rs`).

use std::io::Read;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The rolling manifest the updater reads. Overridable at runtime with
/// `NETSCOPE_UPDATE_MANIFEST_URL` (forks / testing).
const DEFAULT_MANIFEST_URL: &str =
    "https://github.com/duncanheck/NETSCOPE-v1.0/releases/download/latest/latest.json";

/// This build's identity, stamped by `build.rs`.
#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub id: u64,
    pub sha: String,
}

impl BuildInfo {
    pub fn current() -> Self {
        BuildInfo {
            id: env!("NETSCOPE_BUILD_ID").parse().unwrap_or(0),
            sha: env!("NETSCOPE_BUILD_SHA").to_string(),
        }
    }
    /// A `0` id means an unstamped local build — never self-updates.
    pub fn is_dev(&self) -> bool {
        self.id == 0
    }
}

/// The CI-published manifest describing the latest available build.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub build: u64,
    #[serde(default)]
    pub sha: String,
    #[serde(default)]
    pub built_at: String,
    pub exe_url: String,
    /// Lowercase hex SHA-256 of the exe asset.
    pub sha256: String,
    #[serde(default)]
    pub notes: Option<String>,
}

/// What the HUD reads from `GET /update/status`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateStatus {
    pub current_build: u64,
    pub current_sha: String,
    /// True for an unstamped local build — the UI then hides the updater.
    pub dev: bool,
    /// True once a check has completed (success or failure).
    pub checked: bool,
    pub available: bool,
    pub latest_build: Option<u64>,
    pub latest_sha: Option<String>,
    pub latest_built_at: Option<String>,
    pub notes: Option<String>,
    /// Set when the last check failed (offline, etc.) — surfaced, not fatal.
    pub error: Option<String>,
}

/// Holds the build identity, the last-known status, and the manifest to apply.
pub struct Updater {
    build: BuildInfo,
    manifest_url: String,
    status: Mutex<UpdateStatus>,
    pending: Mutex<Option<Manifest>>,
}

impl Updater {
    pub fn new(build: BuildInfo) -> Self {
        let manifest_url = std::env::var("NETSCOPE_UPDATE_MANIFEST_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MANIFEST_URL.to_string());
        let status = UpdateStatus {
            current_build: build.id,
            current_sha: build.sha.clone(),
            dev: build.is_dev(),
            ..Default::default()
        };
        Updater {
            build,
            manifest_url,
            status: Mutex::new(status),
            pending: Mutex::new(None),
        }
    }

    pub fn status(&self) -> UpdateStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn is_dev(&self) -> bool {
        self.build.is_dev()
    }

    /// Blocking check (call from `spawn_blocking`): fetch + parse the manifest and
    /// record whether an update is available. Never panics — a failure is recorded
    /// in `status.error` and the agent runs on.
    ///
    /// `NETSCOPE_NO_UPDATE` short-circuits this even on a manual `/update/check`
    /// hit, not just the background poll — the variable means "don't update,"
    /// full stop. This matters beyond the standalone product: a sidecar embedded
    /// in another shell (the Tauri desktop app sets this) has no business running
    /// this self-replace path at all, since the shell owns updating the whole
    /// installed app through its own mechanism.
    pub fn check(&self) {
        if self.build.is_dev() || updates_disabled() {
            let mut s = self.status.lock().unwrap();
            s.checked = true;
            return;
        }
        let result = fetch_text(&self.manifest_url)
            .and_then(|body| serde_json::from_str::<Manifest>(&body).map_err(|e| e.to_string()));

        let mut s = self.status.lock().unwrap();
        s.checked = true;
        match result {
            Ok(manifest) => {
                let available = is_newer(self.build.id, manifest.build);
                s.available = available;
                s.latest_build = Some(manifest.build);
                s.latest_sha = Some(manifest.sha.clone());
                s.latest_built_at =
                    (!manifest.built_at.is_empty()).then(|| manifest.built_at.clone());
                s.notes = manifest.notes.clone();
                s.error = None;
                *self.pending.lock().unwrap() = available.then_some(manifest);
            }
            Err(e) => {
                s.error = Some(e);
            }
        }
    }

    /// Blocking apply (call from `spawn_blocking`): download the pending exe,
    /// verify its hash, and replace the running binary. Returns a message for the
    /// UI; on success the user restarts to run the new build.
    pub fn apply(&self) -> Result<String, String> {
        if updates_disabled() {
            return Err("updates disabled (NETSCOPE_NO_UPDATE)".into());
        }
        let manifest = self
            .pending
            .lock()
            .unwrap()
            .clone()
            .ok_or("no update available to apply")?;

        let bytes = fetch_bytes(&manifest.exe_url)?;
        let got = hex_sha256(&bytes);
        if !got.eq_ignore_ascii_case(&manifest.sha256) {
            return Err(format!(
                "downloaded exe failed integrity check (expected {}, got {got})",
                manifest.sha256
            ));
        }
        replace_self(&bytes)?;
        Ok(format!(
            "updated to build {} — restart NETSCOPE to finish",
            manifest.build
        ))
    }
}

/// An available update is simply a higher build id than the one running.
fn is_newer(current: u64, manifest_build: u64) -> bool {
    manifest_build > current
}

fn updates_disabled() -> bool {
    std::env::var_os("NETSCOPE_NO_UPDATE").is_some()
}

/// Lowercase hex SHA-256 of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

/// Write the new exe next to the current one (same volume, so the swap is a
/// rename) and replace the running binary in place. Windows-safe via `self_replace`.
fn replace_self(bytes: &[u8]) -> Result<String, String> {
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = current
        .parent()
        .ok_or("current exe has no parent directory")?;
    let tmp = dir.join(format!(".netscope-update-{}.exe.tmp", std::process::id()));

    std::fs::write(&tmp, bytes).map_err(|e| format!("writing update: {e}"))?;
    let result = self_replace::self_replace(&tmp).map_err(|e| format!("replacing binary: {e}"));
    // self_replace consumes the temp on success; clean up on failure regardless.
    let _ = std::fs::remove_file(&tmp);
    result.map(|()| "replaced".into())
}

fn fetch_text(url: &str) -> Result<String, String> {
    ureq::get(url)
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url).call().map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_only_when_manifest_build_is_higher() {
        assert!(is_newer(5, 6));
        assert!(!is_newer(6, 6));
        assert!(!is_newer(7, 6));
        assert!(is_newer(0, 1)); // a stamped build is newer than dev(0)
    }

    #[test]
    fn hex_sha256_is_lowercase_and_64_chars() {
        let h = hex_sha256(b"netscope");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Known vector for "abc".
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn manifest_parses_and_ignores_unknown_fields() {
        let json = r#"{
            "build": 42, "sha": "abc1234", "built_at": "2026-06-16T00:00:00Z",
            "exe_url": "https://example/netscope.exe", "sha256": "DEADBEEF",
            "notes": "fix things", "future_field": true
        }"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.build, 42);
        assert_eq!(m.exe_url, "https://example/netscope.exe");
        assert_eq!(m.notes.as_deref(), Some("fix things"));
    }

    #[test]
    fn dev_build_reports_dev_and_never_available() {
        let u = Updater::new(BuildInfo {
            id: 0,
            sha: "dev".into(),
        });
        u.check(); // no network for a dev build
        let s = u.status();
        assert!(s.dev && s.checked && !s.available);
    }

    #[test]
    fn no_update_env_var_disables_check_and_apply() {
        // A stamped (non-dev) build would normally hit the network on check();
        // NETSCOPE_NO_UPDATE must short-circuit that too, not just the
        // background poll loop — this is what makes it safe for a sidecar
        // embedded in another shell (the Tauri desktop app) to set it and
        // trust that neither endpoint does anything.
        std::env::set_var("NETSCOPE_NO_UPDATE", "1");
        let u = Updater::new(BuildInfo {
            id: 5,
            sha: "abc1234".into(),
        });
        u.check();
        let s = u.status();
        assert!(
            s.checked && !s.available && s.error.is_none(),
            "no network hit"
        );
        assert_eq!(
            u.apply().unwrap_err(),
            "updates disabled (NETSCOPE_NO_UPDATE)"
        );
        std::env::remove_var("NETSCOPE_NO_UPDATE");
    }
}
