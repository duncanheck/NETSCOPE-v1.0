//! # netscope-narrator — D1: the scrubbing pipeline
//!
//! The AI layer (Track D) sends a *description* of your traffic to an LLM so it
//! can explain it. That description leaves your machine, so it must carry enough
//! to be explainable — the destination's org, category, coarse geo, port — and
//! **none** of the identifiers that describe *you*: local IPs and ports, the
//! connection 5-tuple, process paths (which embed your username), LAN hostnames.
//!
//! [`scrub_session`] is that boundary, and it is the *only* thing the rest of
//! Track D is allowed to feed an API. It is a pure function with no I/O, so the
//! privacy policy is reviewable and testable in one place (see `docs/scrubbing.md`
//! for the contract and the threat model).
//!
//! ## What is dropped (never sent)
//! - the connection `id` (the local↔remote 5-tuple, including your local IP/port);
//! - any **local-scope** endpoint — RFC1918 / loopback / link-local / CGNAT
//!   (tailnet) / IPv6 ULA / unparseable — is reduced to `scope: "local"` with no
//!   host, org, or geo;
//! - the raw **remote IP** (the destination org + hostname + coarse geo describe
//!   it without the literal address);
//! - the process **path** and **pid** (only the bare process *name* survives).
//!
//! ## What is kept (the explainable surface)
//! - for remote flows: public hostname (when resolved), org + ASN, country + city,
//!   port, protocol, encrypted flag, security flags, category;
//! - the process name (e.g. `firefox`), and safe per-session aggregate counts.

use serde::Serialize;

use netscope_protocol::{Category, Flow, L4Proto, SecurityFlag};

pub mod classify;
pub mod eval;
mod explain;
pub use explain::{
    explain, explain_node, explain_node_rules, explain_rules, provider_statuses, Explanation,
    Provider, ProviderConfig, ProviderStatus, PROMPT_VERSION,
};

/// A redacted, API-safe view of one flow. Optional fields are omitted entirely
/// when empty, so the serialized prompt stays compact.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScrubbedFlow {
    /// Stable per-session reference (`flow-1`, `flow-2`, …) so the model can talk
    /// about a flow without ever seeing its 5-tuple.
    pub handle: String,
    pub scope: Scope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    pub port: u16,
    pub protocol: L4Proto,
    pub encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    pub category: Category,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<SecurityFlag>,
}

/// Whether the destination is out on the internet or on your own local/tailnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Remote,
    Local,
}

/// Safe, non-identifying aggregate counts for a session — useful for the D3
/// briefing without exposing any single flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct SessionTotals {
    pub flows: usize,
    pub remote: usize,
    pub local: usize,
    pub encrypted: usize,
    pub plaintext: usize,
    pub trackers: usize,
}

/// The complete API-safe payload for a session.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScrubbedSession {
    pub flows: Vec<ScrubbedFlow>,
    pub totals: SessionTotals,
}

/// Redact a session's flows into the API-safe [`ScrubbedSession`]. The single
/// privacy boundary for Track D — nothing downstream may call an API on anything
/// but this output.
pub fn scrub_session(flows: &[Flow]) -> ScrubbedSession {
    let scrubbed: Vec<ScrubbedFlow> = flows
        .iter()
        .enumerate()
        .map(|(i, f)| scrub_flow(f, i))
        .collect();

    let totals = SessionTotals {
        flows: scrubbed.len(),
        remote: scrubbed.iter().filter(|f| f.scope == Scope::Remote).count(),
        local: scrubbed.iter().filter(|f| f.scope == Scope::Local).count(),
        encrypted: scrubbed.iter().filter(|f| f.encrypted).count(),
        plaintext: scrubbed.iter().filter(|f| !f.encrypted).count(),
        // A flow counts as a tracker by category or by the A4 security flag —
        // they usually agree, but either is enough.
        trackers: scrubbed
            .iter()
            .filter(|f| f.category == Category::Tracker || f.flags.contains(&SecurityFlag::Tracker))
            .count(),
    };

    ScrubbedSession {
        flows: scrubbed,
        totals,
    }
}

fn scrub_flow(flow: &Flow, index: usize) -> ScrubbedFlow {
    // Local by either the enrichment category *or* the raw IP — defense in depth,
    // so a misclassified-but-private address is still redacted.
    let scope = if flow.category == Category::Local || classify_ip(&flow.ip) == IpScope::Local {
        Scope::Local
    } else {
        Scope::Remote
    };
    let remote = scope == Scope::Remote;

    ScrubbedFlow {
        handle: format!("flow-{}", index + 1),
        scope,
        host: remote.then(|| public_host(&flow.name)).flatten(),
        org: remote
            .then(|| flow.asn.as_ref().map(|a| a.org.clone()))
            .flatten(),
        asn: remote
            .then(|| flow.asn.as_ref().map(|a| a.number))
            .flatten(),
        country: remote
            .then(|| flow.location.as_ref().and_then(|l| l.country.clone()))
            .flatten(),
        city: remote
            .then(|| flow.location.as_ref().and_then(|l| l.city.clone()))
            .flatten(),
        port: flow.port,
        protocol: flow.protocol,
        encrypted: flow.encrypted,
        // Name only — the path embeds the user's home directory / username.
        process: flow.process.as_ref().map(|p| p.name.clone()),
        category: flow.category,
        flags: flow.flags.clone(),
    }
}

/// Keep a display name only if it is a real hostname — never a bare IP literal
/// (we redact raw addresses) and never empty.
fn public_host(name: &str) -> Option<String> {
    if name.is_empty() || name.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(name.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpScope {
    Local,
    Public,
}

/// Classify an address as local (must be redacted) or public. Anything we can't
/// parse fails *safe* to local.
fn classify_ip(ip: &str) -> IpScope {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn is_cgnat(v4: &Ipv4Addr) -> bool {
        // 100.64.0.0/10 — carrier-grade NAT, and the Tailscale tailnet range.
        let o = v4.octets();
        o[0] == 100 && (64..=127).contains(&o[1])
    }
    fn is_v6_link_local(v6: &Ipv6Addr) -> bool {
        (v6.segments()[0] & 0xffc0) == 0xfe80
    }
    fn is_v6_ula(v6: &Ipv6Addr) -> bool {
        (v6.segments()[0] & 0xfe00) == 0xfc00
    }

    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || is_cgnat(&v4)
            {
                IpScope::Local
            } else {
                IpScope::Public
            }
        }
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback() || v6.is_unspecified() || is_v6_link_local(&v6) || is_v6_ula(&v6) {
                IpScope::Local
            } else {
                IpScope::Public
            }
        }
        Err(_) => IpScope::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_protocol::{AsnInfo, GeoLocation, ProcessInfo};

    fn remote_flow() -> Flow {
        Flow {
            id: "tcp:192.168.1.50:54000->93.184.216.34:443".into(),
            name: "edgecast.example.com".into(),
            category: Category::Service,
            asn: Some(AsnInfo {
                number: 15133,
                org: "Edgecast Inc.".into(),
            }),
            location: Some(GeoLocation {
                city: Some("Los Angeles".into()),
                country: Some("US".into()),
                lat: Some(34.05),
                lon: Some(-118.24),
            }),
            process: Some(ProcessInfo {
                pid: 4242,
                name: "firefox".into(),
                path: Some("/home/alice/.local/bin/firefox".into()),
            }),
            port: 443,
            protocol: L4Proto::Tcp,
            encrypted: true,
            ip: "93.184.216.34".into(),
            activity: 0.7,
            alive: true,
            flags: vec![SecurityFlag::Tracker],
        }
    }

    fn local_flow() -> Flow {
        Flow {
            id: "tcp:192.168.1.50:51000->192.168.1.10:22".into(),
            name: "nas.local".into(),
            category: Category::Local,
            asn: None,
            location: None,
            process: Some(ProcessInfo {
                pid: 99,
                name: "ssh".into(),
                path: Some("/home/alice/bin/ssh".into()),
            }),
            port: 22,
            protocol: L4Proto::Tcp,
            encrypted: true,
            ip: "192.168.1.10".into(),
            activity: 0.1,
            alive: true,
            flags: vec![],
        }
    }

    #[test]
    fn scrubbed_output_leaks_no_local_identifiers() {
        let session = scrub_session(&[remote_flow(), local_flow()]);
        let json = serde_json::to_string(&session).unwrap();

        for needle in [
            "192.168.1.50", // local IP
            "54000",        // local port
            "51000",        // local port
            "192.168.1.10", // LAN device IP
            "nas.local",    // LAN hostname
            "/home/alice",  // process path / home dir
            "alice",        // username
            "4242",         // pid
            "tcp:192.168",  // 5-tuple id
        ] {
            assert!(
                !json.contains(needle),
                "scrubbed output leaked `{needle}`: {json}"
            );
        }
    }

    #[test]
    fn remote_flow_keeps_the_explainable_surface() {
        let s = scrub_session(&[remote_flow()]);
        let f = &s.flows[0];
        assert_eq!(f.handle, "flow-1");
        assert_eq!(f.scope, Scope::Remote);
        assert_eq!(f.host.as_deref(), Some("edgecast.example.com"));
        assert_eq!(f.org.as_deref(), Some("Edgecast Inc."));
        assert_eq!(f.asn, Some(15133));
        assert_eq!(f.country.as_deref(), Some("US"));
        assert_eq!(f.city.as_deref(), Some("Los Angeles"));
        assert_eq!(f.process.as_deref(), Some("firefox")); // name, not path
        assert_eq!(f.port, 443);
        assert_eq!(f.flags, vec![SecurityFlag::Tracker]);
    }

    #[test]
    fn local_flow_is_reduced_to_scope_only() {
        let s = scrub_session(&[local_flow()]);
        let f = &s.flows[0];
        assert_eq!(f.scope, Scope::Local);
        assert!(f.host.is_none());
        assert!(f.org.is_none());
        assert!(f.asn.is_none());
        assert!(f.country.is_none() && f.city.is_none());
        // Process name still survives (it's not a local-network identifier).
        assert_eq!(f.process.as_deref(), Some("ssh"));
    }

    #[test]
    fn a_public_ip_with_no_hostname_emits_no_host() {
        let mut flow = remote_flow();
        flow.name = "93.184.216.34".into(); // unresolved — name is the IP
        let s = scrub_session(&[flow]);
        assert_eq!(s.flows[0].scope, Scope::Remote);
        assert!(
            s.flows[0].host.is_none(),
            "a bare IP must not be emitted as host"
        );
        // and the raw IP is nowhere in the payload
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("93.184.216.34"));
    }

    #[test]
    fn totals_are_computed_over_the_session() {
        let s = scrub_session(&[remote_flow(), local_flow()]);
        assert_eq!(s.totals.flows, 2);
        assert_eq!(s.totals.remote, 1);
        assert_eq!(s.totals.local, 1);
        assert_eq!(s.totals.encrypted, 2);
        assert_eq!(s.totals.trackers, 1);
    }

    #[test]
    fn ip_classifier_covers_the_local_ranges() {
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.5",
            "172.16.9.9",
            "169.254.1.1",     // link-local
            "100.101.102.103", // CGNAT / tailnet
            "0.0.0.0",
            "::1",
            "fe80::1",      // v6 link-local
            "fc00::1",      // v6 ULA
            "fd12:3456::1", // v6 ULA
            "not-an-ip",    // fails safe to local
        ] {
            assert_eq!(
                classify_ip(local),
                IpScope::Local,
                "{local} should be local"
            );
        }
        for public in [
            "93.184.216.34",
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
        ] {
            assert_eq!(
                classify_ip(public),
                IpScope::Public,
                "{public} should be public"
            );
        }
    }
}
