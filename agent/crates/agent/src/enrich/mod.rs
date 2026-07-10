//! # enrich — the A4 enrichment pipeline
//!
//! Turns a raw captured [`Flow`] (name = IP, no org/geo/flags) into an enriched
//! one: reverse-DNS name, GeoLite2 ASN + city, a refined category, and security
//! flags. It implements the capture engine's [`Enrich`] trait, so it slots in
//! ahead of the diff (see `capture` for why that's the natural place).
//!
//! The async part is reverse-DNS (a bounded, timed-out pool — [`dns`]); geo/ASN is
//! a synchronous local-file lookup ([`geo`], optional and license-aware);
//! classification and flags are pure functions — the policy lives in
//! `netscope_narrator::classify`, shared with the D3 eval so the thing we measure
//! is the thing we ship. Local addresses are never sent to geo/DNS (classified
//! `Local` in capture, PITFALLS A4).

mod dns;
mod geo;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use netscope_narrator::classify;
use netscope_protocol::{Category, Flow};

use crate::capture::Enrich;
use dns::DnsResolver;
use geo::GeoDb;

/// Where the GeoLite2 files live — re-exported for the setup control plane
/// (G3.2), which downloads into the same directory the loader reads.
pub fn geoip_dir() -> PathBuf {
    GeoDb::dir()
}

pub struct Enricher {
    /// `None` when the GeoLite2 databases aren't present (geo disabled). Behind
    /// a lock so the G3.2 in-app download can hot-swap it without a restart —
    /// reads are a brief shared lock on the 250 ms capture path; the only write
    /// is a reload.
    geo: RwLock<Option<GeoDb>>,
    dns: DnsResolver,
    /// User-supplied tracker keywords (G4.2) from `NETSCOPE_TRACKER_KEYWORDS`
    /// (a file, one lowercase substring per line, `#` comments). Extends the
    /// curated built-ins; the eval still grades the built-ins only.
    extra_trackers: Vec<String>,
}

impl Enricher {
    /// Build the enricher on the given Tokio runtime (reverse-DNS spawns there).
    pub fn new(handle: tokio::runtime::Handle) -> Arc<Self> {
        let geo = GeoDb::load();
        if geo.is_some() {
            tracing::info!("geoip enabled (GeoLite2 .mmdb found)");
        } else {
            tracing::info!(
                "geoip disabled — no GeoLite2 .mmdb. Enable it from the UI's System \
                 panel (paste a free MaxMind key), or set NETSCOPE_GEOIP_DIR / run \
                 scripts/download-geoip; ASN/location will be empty until then"
            );
        }
        let extra_trackers = load_extra_trackers();
        if !extra_trackers.is_empty() {
            tracing::info!(
                keywords = extra_trackers.len(),
                "extra tracker keywords loaded (NETSCOPE_TRACKER_KEYWORDS)"
            );
        }
        Arc::new(Self {
            geo: RwLock::new(geo),
            dns: DnsResolver::new(handle),
            extra_trackers,
        })
    }

    /// Re-open the GeoLite2 databases (G3.2: called after an in-app download so
    /// enrichment turns on without restarting the agent). Returns whether geo is
    /// now enabled.
    pub fn reload_geo(&self) -> bool {
        let fresh = GeoDb::load();
        let enabled = fresh.is_some();
        *self.geo.write().unwrap() = fresh;
        if enabled {
            tracing::info!("geoip enabled (hot reload)");
        } else {
            tracing::warn!("geoip reload found no usable GeoLite2 .mmdb pair");
        }
        enabled
    }

    pub fn geo_enabled(&self) -> bool {
        self.geo.read().unwrap().is_some()
    }
}

impl Enrich for Enricher {
    fn enrich(&self, flow: &mut Flow) {
        // Local addresses are never geo/DNS-resolved (PITFALLS A4) — they only get
        // their security flags (a plaintext local DNS query is still plaintext).
        if flow.category == Category::Local {
            flow.flags = classify::security_flags(flow);
            return;
        }

        let Ok(ip) = flow.ip.parse::<IpAddr>() else {
            return;
        };

        if let Some(geo) = self.geo.read().unwrap().as_ref() {
            if flow.asn.is_none() {
                flow.asn = geo.asn(ip);
            }
            if flow.location.is_none() {
                flow.location = geo.city(ip);
            }
        }

        // Reverse DNS: a cache hit names the flow now; a miss is requested async
        // and named on a later poll. A cached absence keeps the IP as the name.
        match self.dns.lookup(ip) {
            Some(Some(name)) => flow.name = name,
            Some(None) => {}
            None => self.dns.request(ip),
        }

        flow.category = classify::category_with(flow, &self.extra_trackers);
        flow.flags = classify::security_flags(flow);
    }
}

/// Read `NETSCOPE_TRACKER_KEYWORDS` (G4.2): one substring per line, lowercased,
/// `#`-prefixed lines and blanks ignored. Missing/unreadable → empty (feature
/// off), matching the config philosophy: optional data is optional.
fn load_extra_trackers() -> Vec<String> {
    let Some(path) = std::env::var_os("NETSCOPE_TRACKER_KEYWORDS") else {
        return Vec::new();
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        tracing::warn!(path = %PathBuf::from(&path).display(), "tracker keyword file unreadable — ignored");
        return Vec::new();
    };
    body.lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}
