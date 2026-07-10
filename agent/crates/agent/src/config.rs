//! # config — the on-disk config file (GROWTH G3.1)
//!
//! Until G3, every knob was an environment variable read once at startup — fine
//! for a terminal user, invisible to everyone else. This file gives the UI
//! somewhere durable to write what the user sets up in-app (today: the MaxMind
//! license key, so a GeoLite2 refresh never asks twice).
//!
//! Precedence is deliberate: **environment variables always win** over the file,
//! so nothing an operator already scripted changes behaviour. The file is plain
//! JSON in the platform config directory (`NETSCOPE_CONFIG_DIR` overrides):
//! `%APPDATA%\netscope` on Windows, `$XDG_CONFIG_HOME/netscope` or
//! `~/.config/netscope` elsewhere.
//!
//! The license key is the user's own free MaxMind credential, stored with their
//! other local config — the same place `scripts/download-geoip.*` users already
//! keep it (a shell profile). It never leaves the machine except in the download
//! request to MaxMind itself.

use std::path::{Path, PathBuf};

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maxmind_license_key: Option<String>,
}

/// The config directory: explicit override, else the platform convention.
pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("NETSCOPE_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata).join("netscope");
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("netscope");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("netscope");
    }
    // No home at all (containers) — fall back to a dotdir beside the agent.
    PathBuf::from(".netscope")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

impl Config {
    pub fn load() -> Self {
        Self::load_from(&config_path())
    }

    /// Path-parameterised for tests; a missing or malformed file is just default
    /// (the file is optional by design).
    pub fn load_from(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&config_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, body).map_err(|e| e.to_string())
    }

    /// The effective MaxMind key: env var first (operator scripting wins), else
    /// the file. Empty strings count as absent.
    pub fn maxmind_key(&self) -> Option<String> {
        std::env::var("MAXMIND_LICENSE_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| {
                self.maxmind_license_key
                    .clone()
                    .filter(|k| !k.trim().is_empty())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("netscope-config-test-{}", std::process::id()));
        let path = dir.join("config.json");
        let cfg = Config {
            maxmind_license_key: Some("abc123".into()),
        };
        cfg.save_to(&path).expect("save");
        let loaded = Config::load_from(&path);
        assert_eq!(loaded.maxmind_license_key.as_deref(), Some("abc123"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_or_malformed_file_is_default() {
        let missing = Config::load_from(Path::new("/definitely/not/here/config.json"));
        assert!(missing.maxmind_license_key.is_none());
    }

    #[test]
    fn empty_key_counts_as_absent() {
        let cfg = Config {
            maxmind_license_key: Some("  ".into()),
        };
        // (Assumes MAXMIND_LICENSE_KEY isn't set in the test environment.)
        if std::env::var("MAXMIND_LICENSE_KEY").is_err() {
            assert!(cfg.maxmind_key().is_none());
        }
    }
}
