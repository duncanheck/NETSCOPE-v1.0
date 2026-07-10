//! # setup — in-app enablement downloads (GROWTH G3.2)
//!
//! The Rust twin of `scripts/download-geoip.*` and `scripts/download-threatfeeds.*`,
//! so the System panel can enable geo/ASN enrichment and threat feeds with a paste
//! and a click — no terminal, no restart. The scripts stay for CLI users and CI;
//! this module exists so a non-technical user never needs them.
//!
//! Same licensing posture as the scripts (PITFALLS A4): NETSCOPE downloads with
//! the *user's own* free MaxMind key and never redistributes the databases; the
//! threat feeds are fetched fresh from their public sources rather than bundled.
//! Everything here is blocking I/O — callers run it on `spawn_blocking`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Both GeoLite2 editions the enricher needs (`enrich::geo` requires the pair).
pub const GEOIP_EDITIONS: [&str; 2] = ["GeoLite2-City", "GeoLite2-ASN"];

/// The same free feeds as `scripts/download-threatfeeds.sh`, name-for-name, so
/// either path produces the identical `ThreatDb::load_dir` layout.
pub const THREAT_FEEDS: [(&str, &str); 4] = [
    (
        "stevenblack.hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        "urlhaus.hosts",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
    ),
    (
        "feodo.ips",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    ),
    (
        "firehol_level1.ips",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    ),
];

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Where threat feeds live: the same resolution the startup loader uses.
pub fn threat_dir() -> PathBuf {
    std::env::var("NETSCOPE_THREAT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("threatfeeds"))
}

/// Download + extract both GeoLite2 editions into `dest` with the user's key.
/// MaxMind ships each as a tar.gz with the `.mmdb` in a dated subdirectory; we
/// stream-extract just that file, writing via a temp name so a failed download
/// can never leave a half-written `.mmdb` where the loader would find it.
pub fn download_geoip(license_key: &str, dest: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    for edition in GEOIP_EDITIONS {
        let url = format!(
            "https://download.maxmind.com/app/geoip_download?edition_id={edition}&license_key={license_key}&suffix=tar.gz"
        );
        let resp = ureq::get(&url)
            .timeout(DOWNLOAD_TIMEOUT)
            .call()
            .map_err(|e| match e {
                // MaxMind answers a bad/expired key with 401/403 — say so plainly
                // instead of leaking the keyed URL in a generic error.
                ureq::Error::Status(401 | 403, _) => {
                    "MaxMind refused the license key — check it and try again".to_string()
                }
                ureq::Error::Status(code, _) => format!("{edition}: MaxMind answered HTTP {code}"),
                ureq::Error::Transport(t) => format!("{edition}: download failed: {t}"),
            })?;
        extract_mmdb(resp.into_reader(), &dest.join(format!("{edition}.mmdb")))
            .map_err(|e| format!("{edition}: {e}"))?;
        tracing::info!(edition, dest = %dest.display(), "geolite2 database installed");
    }
    Ok(())
}

fn extract_mmdb(reader: impl Read, dest: &Path) -> Result<(), String> {
    let gz = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(gz);
    for entry in archive
        .entries()
        .map_err(|e| format!("read archive: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("read archive entry: {e}"))?;
        let is_mmdb = entry
            .path()
            .ok()
            .is_some_and(|p| p.extension().is_some_and(|ext| ext == "mmdb"));
        if !is_mmdb {
            continue;
        }
        let tmp = dest.with_extension("mmdb.part");
        let mut out =
            std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        std::io::copy(&mut entry, &mut out).map_err(|e| format!("write: {e}"))?;
        drop(out);
        std::fs::rename(&tmp, dest).map_err(|e| format!("finalize {}: {e}", dest.display()))?;
        return Ok(());
    }
    Err("archive contained no .mmdb file".into())
}

/// What the threat-feed fetch achieved. Partial success is success — one feed
/// down shouldn't zero the intel (mirrors the script's skip-not-fail behaviour).
pub struct ThreatFetch {
    pub fetched: Vec<String>,
    pub skipped: Vec<String>,
}

pub fn download_threatfeeds(dest: &Path) -> Result<ThreatFetch, String> {
    std::fs::create_dir_all(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let mut fetched = Vec::new();
    let mut skipped = Vec::new();
    for (name, url) in THREAT_FEEDS {
        match fetch_to(url, &dest.join(name)) {
            Ok(()) => fetched.push(name.to_string()),
            Err(e) => {
                tracing::warn!(feed = name, error = %e, "threat feed skipped");
                skipped.push(name.to_string());
            }
        }
    }
    if fetched.is_empty() {
        return Err("every feed download failed — check the network and try again".into());
    }
    Ok(ThreatFetch { fetched, skipped })
}

fn fetch_to(url: &str, dest: &Path) -> Result<(), String> {
    let resp = ureq::get(url)
        .timeout(DOWNLOAD_TIMEOUT)
        .call()
        .map_err(|e| e.to_string())?;
    let tmp = dest.with_extension("part");
    let mut out =
        std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    std::io::copy(&mut resp.into_reader(), &mut out).map_err(|e| format!("write: {e}"))?;
    drop(out);
    std::fs::rename(&tmp, dest).map_err(|e| format!("finalize {}: {e}", dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny in-memory tar.gz containing a dated subdir + .mmdb, like MaxMind's.
    fn fake_maxmind_archive(mmdb_bytes: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(mmdb_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "GeoLite2-City_20260101/GeoLite2-City.mmdb",
                    mmdb_bytes,
                )
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn extracts_the_mmdb_from_a_dated_subdirectory() {
        let dir = std::env::temp_dir().join(format!("netscope-setup-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("GeoLite2-City.mmdb");
        let archive = fake_maxmind_archive(b"mmdb-payload");
        extract_mmdb(archive.as_slice(), &dest).expect("extract");
        assert_eq!(std::fs::read(&dest).unwrap(), b"mmdb-payload");
        // No stray .part file left behind.
        assert!(!dir.join("GeoLite2-City.mmdb.part").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_without_mmdb_is_an_error() {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(5);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "README.txt", &b"hello"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        let archive = gz.finish().unwrap();

        let dest =
            std::env::temp_dir().join(format!("netscope-setup-nommdb-{}.mmdb", std::process::id()));
        let err = extract_mmdb(archive.as_slice(), &dest).unwrap_err();
        assert!(err.contains("no .mmdb"), "unexpected error: {err}");
        assert!(!dest.exists());
    }

    #[test]
    fn feed_names_match_the_shell_script() {
        // ThreatDb::load_dir keys behaviour off the .hosts/.ips extensions; keep
        // the in-app path byte-identical to the script's layout.
        let names: Vec<&str> = THREAT_FEEDS.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                "stevenblack.hosts",
                "urlhaus.hosts",
                "feodo.ips",
                "firehol_level1.ips"
            ]
        );
    }
}
