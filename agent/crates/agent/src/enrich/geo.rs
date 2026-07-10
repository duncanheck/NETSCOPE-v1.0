//! GeoLite2 city + ASN lookups (A4) via local `.mmdb` files (`maxminddb`).
//!
//! ## License-aware: we ship a downloader, not the database
//!
//! The GeoLite2 databases are MaxMind's and their license forbids redistribution,
//! so NETSCOPE never bundles them (PITFALLS A4). Instead the agent looks for the
//! `.mmdb` files at runtime — `NETSCOPE_GEOIP_DIR`, else a `geoip/` directory next
//! to the working directory — and enables geo/ASN enrichment only if both are
//! present. Absent, geo is silently disabled and flows keep `asn`/`location` of
//! `None`. The downloader (which needs the user's own MaxMind license key) is
//! `scripts/download-geoip.*`; see the README.

use std::net::IpAddr;
use std::path::PathBuf;

use maxminddb::{geoip2, Reader};
use netscope_protocol::{AsnInfo, GeoLocation};

pub struct GeoDb {
    city: Reader<Vec<u8>>,
    asn: Reader<Vec<u8>>,
}

impl GeoDb {
    /// Open the databases if both are present; otherwise `None` (geo disabled).
    pub fn load() -> Option<Self> {
        let dir = Self::dir();
        let city = Reader::open_readfile(dir.join("GeoLite2-City.mmdb")).ok()?;
        let asn = Reader::open_readfile(dir.join("GeoLite2-ASN.mmdb")).ok()?;
        Some(Self { city, asn })
    }

    /// Where the `.mmdb` files live (and where the in-app downloader writes,
    /// G3.2): an explicit override, else `./geoip`. Returned even when the
    /// directory doesn't exist yet — the downloader creates it.
    pub fn dir() -> PathBuf {
        std::env::var("NETSCOPE_GEOIP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("geoip"))
    }

    pub fn asn(&self, ip: IpAddr) -> Option<AsnInfo> {
        let rec: geoip2::Asn = self.asn.lookup(ip).ok()?;
        Some(AsnInfo {
            number: rec.autonomous_system_number?,
            org: rec.autonomous_system_organization?.to_string(),
        })
    }

    pub fn city(&self, ip: IpAddr) -> Option<GeoLocation> {
        let rec: geoip2::City = self.city.lookup(ip).ok()?;
        let city = rec
            .city
            .and_then(|c| c.names)
            .and_then(|n| n.get("en").map(|s| s.to_string()));
        let country = rec
            .country
            .and_then(|c| c.names)
            .and_then(|n| n.get("en").map(|s| s.to_string()));
        let (lat, lon) = rec
            .location
            .map(|l| (l.latitude, l.longitude))
            .unwrap_or((None, None));
        // If nothing resolved, report no location rather than an empty husk.
        if city.is_none() && country.is_none() && lat.is_none() && lon.is_none() {
            return None;
        }
        Some(GeoLocation {
            city,
            country,
            lat,
            lon,
        })
    }
}
