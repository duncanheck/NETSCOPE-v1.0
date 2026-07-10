//! # E2 — threat-intelligence feeds
//!
//! E1/E3 let you block by *heuristic* (category, plaintext). E2 lets you block by
//! *reputation*: free, downloadable blocklists of known-bad domains and IPs. The
//! agent loads whatever feed files are present and flags any flow whose host or
//! remote IP appears on one — a `threat` signal the policy can act on.
//!
//! **Free and ship-the-downloader, not the data** (the GeoLite2 pattern, A4): the
//! repo carries `scripts/download-threatfeeds.*`, which fetches free lists
//! (StevenBlack hosts, abuse.ch URLhaus / Feodo, FireHOL) into a local dir; the
//! agent reads that dir. Nothing is bundled, nothing is paid for, and the feeds
//! stay fresh.
//!
//! Matching is cheap: a domain `HashSet` walked over the host's suffixes
//! (`a.b.evil.com` → `b.evil.com` → `evil.com`, O(labels)), an exact-IP `HashSet`,
//! and a small CIDR list. (A longest-prefix trie is the scale path once feeds grow
//! to millions of CIDRs — noted, not needed yet.)

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use netscope_protocol::Flow;

/// A loaded set of threat feeds: known-bad domains and IPs/CIDRs.
#[derive(Debug, Clone, Default)]
pub struct ThreatDb {
    domains: HashSet<String>,
    ips: HashSet<IpAddr>,
    cidrs: Vec<(IpAddr, u8)>,
    /// Feed file names that were loaded, for display.
    sources: Vec<String>,
}

/// Why a flow matched a feed — surfaced as the block reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatHit {
    /// The host (or a parent domain) is on a domain blocklist.
    Domain(String),
    /// The remote IP is on an IP/CIDR blocklist.
    Ip,
}

impl ThreatDb {
    /// Total entries across all feeds.
    pub fn len(&self) -> usize {
        self.domains.len() + self.ips.len() + self.cidrs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The feed files that were loaded.
    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// Does this flow match any feed? Checks the host's domain suffixes, then the
    /// remote IP (exact, then CIDRs).
    pub fn matches(&self, flow: &Flow) -> Option<ThreatHit> {
        if let Some(d) = self.match_host(&flow.name) {
            return Some(ThreatHit::Domain(d));
        }
        if self.match_ip(&flow.ip) {
            return Some(ThreatHit::Ip);
        }
        None
    }

    fn match_host(&self, host: &str) -> Option<String> {
        if self.domains.is_empty() {
            return None;
        }
        let host = host.trim().trim_end_matches('.').to_lowercase();
        // Walk progressively shorter suffixes: a.b.c → b.c → c.
        let mut rest = host.as_str();
        loop {
            if self.domains.contains(rest) {
                return Some(rest.to_string());
            }
            match rest.split_once('.') {
                Some((_, tail)) => rest = tail,
                None => return None,
            }
        }
    }

    fn match_ip(&self, ip: &str) -> bool {
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return false;
        };
        if self.ips.contains(&ip) {
            return true;
        }
        self.cidrs
            .iter()
            .any(|(net, prefix)| cidr_contains(*net, *prefix, ip))
    }

    /// Load every recognized feed file from `dir`. Dispatched by extension:
    /// `.hosts` (a hosts file), `.domains` (one domain per line), `.ips` /
    /// `.netset` / `.txt` (one IP or CIDR per line). Missing dir → an empty db
    /// (the feature is simply off until the user runs the downloader).
    pub fn load_dir(dir: impl AsRef<Path>) -> std::io::Result<ThreatDb> {
        let mut db = ThreatDb::default();
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Ok(db);
        }
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            let kind = match ext.as_str() {
                "hosts" => FeedKind::Hosts,
                "domains" => FeedKind::Domains,
                "ips" | "netset" | "txt" => FeedKind::Ips,
                _ => continue,
            };
            let text = std::fs::read_to_string(&path)?;
            db.load_text(kind, &text);
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                db.sources.push(name.to_string());
            }
        }
        Ok(db)
    }

    /// Load one feed's text in the given format. Comments (`#`, `!`) and blanks are
    /// ignored.
    pub fn load_text(&mut self, kind: FeedKind, text: &str) {
        for raw in text.lines() {
            let line = strip_comment(raw);
            if line.is_empty() {
                continue;
            }
            match kind {
                FeedKind::Hosts => {
                    // `0.0.0.0 ads.example.com` — take the domain (2nd token), skip
                    // the localhost mappings a hosts file always starts with.
                    if let Some(domain) = line.split_whitespace().nth(1) {
                        let d = domain.trim_end_matches('.').to_lowercase();
                        if is_plausible_domain(&d) {
                            self.domains.insert(d);
                        }
                    }
                }
                FeedKind::Domains => {
                    let d = line.trim_end_matches('.').to_lowercase();
                    if is_plausible_domain(&d) {
                        self.domains.insert(d);
                    }
                }
                FeedKind::Ips => self.add_ip_spec(line),
            }
        }
    }

    fn add_ip_spec(&mut self, spec: &str) {
        let spec = spec.split_whitespace().next().unwrap_or(spec);
        match spec.split_once('/') {
            None => {
                if let Ok(ip) = spec.parse::<IpAddr>() {
                    self.ips.insert(ip);
                }
            }
            Some((addr, prefix)) => {
                if let (Ok(ip), Ok(p)) = (addr.parse::<IpAddr>(), prefix.parse::<u8>()) {
                    let max = if ip.is_ipv4() { 32 } else { 128 };
                    if p <= max {
                        self.cidrs.push((ip, p));
                    }
                }
            }
        }
    }
}

/// Feed file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedKind {
    /// A hosts file: `0.0.0.0 domain` per line.
    Hosts,
    /// One domain per line.
    Domains,
    /// One IP or CIDR per line.
    Ips,
}

/// The remote IPs of every flow that matches a feed — the block targets a "block
/// known-bad" rule would add.
pub fn threat_targets(db: &ThreatDb, flows: &[Flow]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for flow in flows {
        if db.matches(flow).is_some() && !out.contains(&flow.ip) {
            out.push(flow.ip.clone());
        }
    }
    out
}

fn strip_comment(line: &str) -> &str {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with('!') {
        return "";
    }
    line
}

/// A coarse sanity check so a stray token or a bare TLD can't poison the set.
fn is_plausible_domain(d: &str) -> bool {
    d.contains('.') && d.len() >= 4 && d != "localhost" && d.parse::<IpAddr>().is_err()
}

fn cidr_contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_protocol::{Category, L4Proto};

    fn flow(host: &str, ip: &str) -> Flow {
        Flow {
            id: "t".into(),
            name: host.into(),
            category: Category::Service,
            asn: None,
            location: None,
            process: None,
            port: 443,
            protocol: L4Proto::Tcp,
            encrypted: true,
            ip: ip.into(),
            activity: 0.0,
            alive: true,
            flags: Vec::new(),
        }
    }

    fn db_with(hosts: &str, domains: &str, ips: &str) -> ThreatDb {
        let mut db = ThreatDb::default();
        db.load_text(FeedKind::Hosts, hosts);
        db.load_text(FeedKind::Domains, domains);
        db.load_text(FeedKind::Ips, ips);
        db
    }

    #[test]
    fn hosts_file_parses_domains_and_skips_localhost() {
        let db = db_with(
            "# header\n127.0.0.1 localhost\n0.0.0.0 ads.evil.com\n0.0.0.0 tracker.bad.net\n",
            "",
            "",
        );
        assert!(db.match_host("ads.evil.com").is_some());
        assert!(db.match_host("tracker.bad.net").is_some());
        assert!(db.match_host("localhost").is_none());
    }

    #[test]
    fn domain_match_walks_suffixes() {
        let db = db_with("", "evil.com\n", "");
        // A subdomain of a blocked domain matches.
        assert_eq!(db.match_host("a.b.evil.com"), Some("evil.com".to_string()));
        assert_eq!(db.match_host("evil.com"), Some("evil.com".to_string()));
        // An unrelated domain does not, and a bare TLD never matches.
        assert!(db.match_host("notevil.com").is_none());
        assert!(db.match_host("good.org").is_none());
    }

    #[test]
    fn ip_and_cidr_matching() {
        let db = db_with(
            "",
            "",
            "# feed\n198.51.100.5\n203.0.113.0/24\n2001:db8::/32\n",
        );
        assert!(db.match_ip("198.51.100.5")); // exact
        assert!(db.match_ip("203.0.113.77")); // in cidr
        assert!(!db.match_ip("203.0.114.1")); // outside
        assert!(db.match_ip("2001:db8::dead")); // v6 cidr
        assert!(!db.match_ip("8.8.8.8"));
    }

    #[test]
    fn matches_reports_host_then_ip() {
        let db = db_with("", "evil.com\n", "198.51.100.5\n");
        assert_eq!(
            db.matches(&flow("x.evil.com", "1.2.3.4")),
            Some(ThreatHit::Domain("evil.com".into()))
        );
        assert_eq!(
            db.matches(&flow("clean.example.com", "198.51.100.5")),
            Some(ThreatHit::Ip)
        );
        assert!(db.matches(&flow("clean.example.com", "8.8.8.8")).is_none());
    }

    #[test]
    fn threat_targets_dedupes_matched_ips() {
        let db = db_with("", "evil.com\n", "");
        let flows = vec![
            flow("a.evil.com", "93.184.216.34"),
            flow("b.evil.com", "93.184.216.34"), // same ip
            flow("good.com", "8.8.8.8"),
        ];
        assert_eq!(
            threat_targets(&db, &flows),
            vec!["93.184.216.34".to_string()]
        );
    }

    #[test]
    fn garbage_lines_are_ignored() {
        let db = db_with(
            "0.0.0.0\n!comment\n",
            "com\nlocalhost\n1.2.3.4\n",
            "not-an-ip\n10.0.0.0/40\n",
        );
        // bare TLD, localhost, an IP-as-domain, and bad ip specs all rejected.
        assert!(db.is_empty());
    }

    #[test]
    fn load_dir_reads_recognized_extensions() {
        let dir = std::env::temp_dir().join(format!("netscope-threat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ads.hosts"), "0.0.0.0 ads.evil.com\n").unwrap();
        std::fs::write(dir.join("malware.ips"), "198.51.100.9\n").unwrap();
        std::fs::write(dir.join("readme.md"), "ignored\n").unwrap();
        let db = ThreatDb::load_dir(&dir).unwrap();
        assert!(db.match_host("ads.evil.com").is_some());
        assert!(db.match_ip("198.51.100.9"));
        assert_eq!(db.sources().len(), 2); // the .md is skipped
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_dir_is_an_empty_db_not_an_error() {
        let db = ThreatDb::load_dir("/no/such/netscope/dir").unwrap();
        assert!(db.is_empty());
    }
}
