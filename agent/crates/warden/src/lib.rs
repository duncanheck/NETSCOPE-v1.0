//! # netscope-warden — E1: the block-policy engine
//!
//! The Warden (Track E) turns NETSCOPE from sight into action. **E1 is the brain
//! only — pure logic, no privilege, no firewall, no network.** It answers one
//! question: given the flows on screen and a set of rules, *which would be
//! blocked, and why* — a [`dry_run`] the UI can preview before anything is ever
//! enforced.
//!
//! The decision is a pure function with fixed, tested precedence (see
//! [`evaluate`]):
//!
//! 1. **Protected** destinations are *never* blocked — loopback, link-local, RFC1918
//!    / CGNAT / ULA (your LAN and tailnet), the unspecified address. This is a hard
//!    floor the policy cannot override, so a rule can never cut you off from your own
//!    network or lock the host out. (Gateway/DNS detection is runtime — Track E4.)
//! 2. The **allowlist** wins next: an explicit "never block this org/host/CIDR" is
//!    the user's escape hatch over any deny rule.
//! 3. Then **deny rules** match (category / security flag / org / CIDR).
//! 4. Otherwise **default-allow** — nothing is blocked unless a rule says so.
//!
//! Because the classifier has honest false positives (the D3 eval flagged a real BI
//! tool as a tracker), nothing here auto-acts: E1 only *previews*. Enforcement
//! (E3+) is generated, opt-in, and reversible.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use netscope_protocol::{Category, Flow, SecurityFlag};

pub mod generate;
pub mod threat;
pub use generate::{all_backends, default_backend, generate, Firewall, GeneratedRuleset};
pub use threat::{threat_targets, FeedKind, ThreatDb, ThreatHit};

/// A deny rule — a flow is a block candidate if any deny rule matches it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum Rule {
    /// Block flows of this category (e.g. `tracker`).
    Category(Category),
    /// Block flows carrying this A4 security flag (e.g. `plaintext`).
    Flag(SecurityFlag),
    /// Block flows whose resolved org contains this text (case-insensitive).
    Org(String),
    /// Block flows whose remote IP falls in this CIDR (`1.2.3.0/24`, `2001:db8::/32`,
    /// or a bare address = a single host).
    Cidr(String),
    /// Block flows whose host/IP is on a loaded threat feed (E2). Matches only when
    /// a [`ThreatDb`] is supplied to [`evaluate_with`].
    Threat,
}

/// An allowlist matcher — if any matches a flow, it is never blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum Allow {
    /// Allow flows whose org contains this text (case-insensitive).
    Org(String),
    /// Allow flows whose host contains this text (so `github.com` allows
    /// `api.github.com`).
    Host(String),
    /// Allow flows whose remote IP falls in this CIDR.
    Cidr(String),
}

/// A block policy: an allowlist (wins) plus deny rules. Serializable so it can be
/// configured from the UI, an env var, or a file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub allow: Vec<Allow>,
    #[serde(default)]
    pub deny: Vec<Rule>,
}

/// What the policy decided for one flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Allow,
}

/// A decision plus a human-readable reason (every decision is explainable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
}

impl Decision {
    fn allow(reason: impl Into<String>) -> Self {
        Decision {
            action: Action::Allow,
            reason: reason.into(),
        }
    }
    fn block(reason: impl Into<String>) -> Self {
        Decision {
            action: Action::Block,
            reason: reason.into(),
        }
    }
    pub fn is_block(&self) -> bool {
        self.action == Action::Block
    }
}

/// Evaluate the policy for a single flow, applying the fixed precedence above.
/// (No threat feed — a `Rule::Threat` never matches; use [`evaluate_with`].)
pub fn evaluate(policy: &Policy, flow: &Flow) -> Decision {
    evaluate_with(policy, flow, None)
}

/// Evaluate with an optional threat feed ([`ThreatDb`]) so `Rule::Threat` can match
/// flows on a blocklist. Precedence is unchanged: protected floor > allowlist >
/// deny > default-allow.
pub fn evaluate_with(policy: &Policy, flow: &Flow, threats: Option<&ThreatDb>) -> Decision {
    // 1. Protected — a hard floor the policy cannot override.
    if is_protected(flow) {
        return Decision::allow("protected (local/loopback)");
    }
    // 2. Allowlist wins over any deny rule.
    if let Some(a) = policy.allow.iter().find(|a| a.matches(flow)) {
        return Decision::allow(format!("allowlisted ({a})"));
    }
    // 3. Deny rules.
    if let Some(r) = policy.deny.iter().find(|r| r.matches(flow, threats)) {
        return Decision::block(format!("rule: {}", r.reason(flow, threats)));
    }
    // 4. Default-allow.
    Decision::allow("no matching rule")
}

/// One row of a [`Plan`] — a flow that *would* be blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanEntry {
    pub flow_id: String,
    pub host: String,
    pub ip: String,
    pub reason: String,
}

/// The preview: what *would* be blocked under this policy, and the deduplicated set
/// of remote IPs a firewall set would contain. Nothing is enforced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// Every flow the policy would block, with the reason.
    pub blocks: Vec<PlanEntry>,
    /// Deduplicated remote IPs to block — the future firewall-set membership (E3).
    pub targets: Vec<String>,
    /// How many flows were considered.
    pub considered: usize,
}

/// Run the policy over a set of flows and produce the preview. Pure — no I/O.
/// (No threat feed; see [`dry_run_with`].)
pub fn dry_run(policy: &Policy, flows: &[Flow]) -> Plan {
    dry_run_with(policy, flows, None)
}

/// Run the policy with an optional threat feed and produce the preview.
pub fn dry_run_with(policy: &Policy, flows: &[Flow], threats: Option<&ThreatDb>) -> Plan {
    let mut blocks = Vec::new();
    let mut targets: Vec<String> = Vec::new();

    for flow in flows {
        let decision = evaluate_with(policy, flow, threats);
        if decision.is_block() {
            if !targets.contains(&flow.ip) {
                targets.push(flow.ip.clone());
            }
            blocks.push(PlanEntry {
                flow_id: flow.id.clone(),
                host: flow.name.clone(),
                ip: flow.ip.clone(),
                reason: decision.reason,
            });
        }
    }

    Plan {
        blocks,
        targets,
        considered: flows.len(),
    }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

impl Rule {
    fn matches(&self, flow: &Flow, threats: Option<&ThreatDb>) -> bool {
        match self {
            Rule::Category(c) => flow.category == *c,
            Rule::Flag(f) => flow.flags.contains(f),
            Rule::Org(s) => org_contains(flow, s),
            Rule::Cidr(spec) => cidr_contains(spec, &flow.ip),
            Rule::Threat => threats.is_some_and(|db| db.matches(flow).is_some()),
        }
    }

    /// The "why" for a block, more specific than `Display` for `Threat` (which names
    /// the matched feed signal).
    fn reason(&self, flow: &Flow, threats: Option<&ThreatDb>) -> String {
        match (self, threats.and_then(|db| db.matches(flow))) {
            (Rule::Threat, Some(ThreatHit::Domain(d))) => format!("threat feed (host {d})"),
            (Rule::Threat, Some(ThreatHit::Ip)) => "threat feed (IP)".to_string(),
            _ => self.to_string(),
        }
    }
}

impl Allow {
    fn matches(&self, flow: &Flow) -> bool {
        match self {
            Allow::Org(s) => org_contains(flow, s),
            Allow::Host(s) => flow.name.to_lowercase().contains(&s.to_lowercase()),
            Allow::Cidr(spec) => cidr_contains(spec, &flow.ip),
        }
    }
}

fn org_contains(flow: &Flow, needle: &str) -> bool {
    flow.asn
        .as_ref()
        .map(|a| a.org.to_lowercase().contains(&needle.to_lowercase()))
        .unwrap_or(false)
}

/// A destination that must never be blocked: a local-scope address, or a flow the
/// enrichment already classified `Local`. Defense in depth — both the category and
/// the raw IP are checked, and an unparseable address fails *safe* (protected).
fn is_protected(flow: &Flow) -> bool {
    if flow.category == Category::Local {
        return true;
    }
    match flow.ip.parse::<IpAddr>() {
        Ok(ip) => is_local_scope(ip),
        Err(_) => true,
    }
}

/// The never-block floor as a plain predicate on an address: true for loopback /
/// private / link-local / CGNAT(tailnet) / ULA / unspecified / broadcast. This is
/// the single source of truth the **enforcer** (E4) also applies, so a protected
/// address can never reach a firewall set even if something upstream asks for it.
pub fn is_protected_addr(ip: IpAddr) -> bool {
    is_local_scope(ip)
}

/// True for loopback / private / link-local / CGNAT(tailnet) / ULA / unspecified.
fn is_local_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 CGNAT/tailnet
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 ULA
        }
    }
}

/// Whether `ip` falls within the CIDR `spec`. A bare address is treated as a single
/// host (`/32` or `/128`). Returns false on a malformed spec or a family mismatch —
/// a bad rule simply never matches (it cannot accidentally block everything).
pub fn cidr_contains(spec: &str, ip: &str) -> bool {
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    let (addr_str, prefix_str) = match spec.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (spec, None),
    };
    let Ok(net) = addr_str.trim().parse::<IpAddr>() else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let prefix = parse_prefix(prefix_str, 32);
            let Some(prefix) = prefix else { return false };
            let mask = v4_mask(prefix);
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let prefix = parse_prefix(prefix_str, 128);
            let Some(prefix) = prefix else { return false };
            let mask = v6_mask(prefix);
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        // Family mismatch — a v4 rule never matches a v6 flow, and vice versa.
        _ => false,
    }
}

fn parse_prefix(prefix: Option<&str>, max: u8) -> Option<u8> {
    match prefix {
        None => Some(max),
        Some(p) => p.trim().parse::<u8>().ok().filter(|&n| n <= max),
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

// ---------------------------------------------------------------------------
// Display (the "why" strings)
// ---------------------------------------------------------------------------

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::Category(c) => write!(f, "category {c:?}"),
            Rule::Flag(s) => write!(f, "flag {s:?}"),
            Rule::Org(s) => write!(f, "org contains '{s}'"),
            Rule::Cidr(s) => write!(f, "in {s}"),
            Rule::Threat => write!(f, "on a threat feed"),
        }
    }
}

impl fmt::Display for Allow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Allow::Org(s) => write!(f, "org '{s}'"),
            Allow::Host(s) => write!(f, "host '{s}'"),
            Allow::Cidr(s) => write!(f, "{s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_protocol::{AsnInfo, L4Proto};

    fn flow(id: &str, host: &str, ip: &str, cat: Category, org: Option<&str>) -> Flow {
        let mut flags = Vec::new();
        if cat == Category::Tracker {
            flags.push(SecurityFlag::Tracker);
        }
        Flow {
            id: id.into(),
            name: host.into(),
            category: cat,
            asn: org.map(|o| AsnInfo {
                number: 1,
                org: o.into(),
            }),
            location: None,
            process: None,
            port: 443,
            protocol: L4Proto::Tcp,
            encrypted: true,
            ip: ip.into(),
            activity: 0.5,
            alive: true,
            flags,
        }
    }

    fn plaintext(mut f: Flow) -> Flow {
        f.encrypted = false;
        f.flags.push(SecurityFlag::Plaintext);
        f
    }

    #[test]
    fn threat_rule_matches_only_with_a_loaded_feed() {
        let mut db = ThreatDb::default();
        db.load_text(FeedKind::Domains, "evil.com\n");
        let policy = Policy {
            deny: vec![Rule::Threat],
            ..Default::default()
        };
        let bad = flow(
            "a",
            "x.evil.com",
            "93.184.216.34",
            Category::Service,
            Some("X"),
        );
        let good = flow(
            "b",
            "api.github.com",
            "140.82.121.6",
            Category::Service,
            Some("GitHub"),
        );

        // No feed → a threat rule matches nothing.
        assert!(!evaluate(&policy, &bad).is_block());
        // With the feed → the flagged flow is blocked, with a feed-specific reason.
        let d = evaluate_with(&policy, &bad, Some(&db));
        assert!(d.is_block());
        assert!(d.reason.contains("threat feed") && d.reason.contains("evil.com"));
        assert!(!evaluate_with(&policy, &good, Some(&db)).is_block());
    }

    #[test]
    fn threat_rule_respects_the_protected_floor_and_allowlist() {
        let mut db = ThreatDb::default();
        db.load_text(FeedKind::Ips, "10.0.0.5\n"); // a local IP on a feed (contrived)
        let policy = Policy {
            deny: vec![Rule::Threat],
            ..Default::default()
        };
        // Local is protected even if a feed lists it.
        let local = flow("a", "nas.local", "10.0.0.5", Category::Local, None);
        assert!(!evaluate_with(&policy, &local, Some(&db)).is_block());
    }

    #[test]
    fn category_rule_blocks_matching_flows() {
        let policy = Policy {
            deny: vec![Rule::Category(Category::Tracker)],
            ..Default::default()
        };
        let tracker = flow(
            "a",
            "ads.example.com",
            "93.184.216.34",
            Category::Tracker,
            Some("Ad Co"),
        );
        let service = flow(
            "b",
            "api.github.com",
            "140.82.121.6",
            Category::Service,
            Some("GitHub"),
        );
        assert!(evaluate(&policy, &tracker).is_block());
        assert!(!evaluate(&policy, &service).is_block());
    }

    #[test]
    fn flag_rule_blocks_plaintext() {
        let policy = Policy {
            deny: vec![Rule::Flag(SecurityFlag::Plaintext)],
            ..Default::default()
        };
        let f = plaintext(flow(
            "a",
            "mirror.example.com",
            "198.51.100.7",
            Category::Service,
            Some("X"),
        ));
        assert!(evaluate(&policy, &f).is_block());
    }

    #[test]
    fn allowlist_beats_deny() {
        let policy = Policy {
            allow: vec![Allow::Host("github.com".into())],
            deny: vec![Rule::Category(Category::Service)],
        };
        let f = flow(
            "a",
            "api.github.com",
            "140.82.121.6",
            Category::Service,
            Some("GitHub"),
        );
        let d = evaluate(&policy, &f);
        assert!(
            !d.is_block(),
            "allowlisted host must not be blocked: {}",
            d.reason
        );
        assert!(d.reason.contains("allowlisted"));
    }

    #[test]
    fn protected_local_is_never_blocked() {
        // Even a deny-everything policy can't touch a local destination.
        let policy = Policy {
            deny: vec![
                Rule::Category(Category::Service),
                Rule::Category(Category::Local),
                Rule::Cidr("0.0.0.0/0".into()),
            ],
            ..Default::default()
        };
        for (ip, cat) in [
            ("192.168.1.10", Category::Local),
            ("127.0.0.1", Category::Service),
            ("100.101.102.103", Category::Service), // tailnet
            ("10.0.0.5", Category::Service),
            ("::1", Category::Service),
        ] {
            let f = flow("p", "x", ip, cat, None);
            assert!(!evaluate(&policy, &f).is_block(), "{ip} must be protected");
        }
    }

    #[test]
    fn org_rule_is_case_insensitive() {
        let policy = Policy {
            deny: vec![Rule::Org("doubleclick".into())],
            ..Default::default()
        };
        let f = flow(
            "a",
            "x",
            "93.184.216.34",
            Category::Tracker,
            Some("DoubleClick LLC"),
        );
        assert!(evaluate(&policy, &f).is_block());
    }

    #[test]
    fn cidr_rule_matches_within_range_only() {
        let policy = Policy {
            deny: vec![Rule::Cidr("93.184.216.0/24".into())],
            ..Default::default()
        };
        let inside = flow("a", "x", "93.184.216.34", Category::Service, Some("X"));
        let outside = flow("b", "y", "93.184.217.1", Category::Service, Some("Y"));
        assert!(evaluate(&policy, &inside).is_block());
        assert!(!evaluate(&policy, &outside).is_block());
    }

    #[test]
    fn cidr_contains_handles_v4_v6_and_garbage() {
        assert!(cidr_contains("10.0.0.0/8", "10.5.6.7")); // (but 10.x is also protected upstream)
        assert!(cidr_contains("93.184.216.34", "93.184.216.34")); // bare = /32
        assert!(!cidr_contains("93.184.216.0/24", "8.8.8.8"));
        assert!(cidr_contains("2001:db8::/32", "2001:db8::1"));
        assert!(!cidr_contains("2001:db8::/32", "2001:dead::1"));
        assert!(!cidr_contains("93.184.216.0/24", "2001:db8::1")); // family mismatch
        assert!(!cidr_contains("not-a-cidr", "1.2.3.4")); // garbage never matches
        assert!(!cidr_contains("1.2.3.0/99", "1.2.3.4")); // bad prefix
    }

    #[test]
    fn dry_run_dedupes_targets_and_explains() {
        let policy = Policy {
            deny: vec![Rule::Category(Category::Tracker)],
            ..Default::default()
        };
        let flows = vec![
            flow(
                "a",
                "ads1.example.com",
                "93.184.216.34",
                Category::Tracker,
                Some("Ad Co"),
            ),
            flow(
                "b",
                "ads2.example.com",
                "93.184.216.34",
                Category::Tracker,
                Some("Ad Co"),
            ), // same ip
            flow(
                "c",
                "api.github.com",
                "140.82.121.6",
                Category::Service,
                Some("GitHub"),
            ),
            flow("d", "192.168.1.5", "192.168.1.5", Category::Local, None), // protected
        ];
        let plan = dry_run(&policy, &flows);
        assert_eq!(plan.considered, 4);
        assert_eq!(plan.blocks.len(), 2); // both tracker flows
        assert_eq!(plan.targets, vec!["93.184.216.34".to_string()]); // deduped
        assert!(plan.blocks.iter().all(|b| b.reason.contains("category")));
    }

    #[test]
    fn default_policy_blocks_nothing() {
        let policy = Policy::default();
        let f = flow(
            "a",
            "ads.example.com",
            "93.184.216.34",
            Category::Tracker,
            Some("Ad Co"),
        );
        assert!(!evaluate(&policy, &f).is_block());
    }

    #[test]
    fn policy_round_trips_through_json() {
        let policy = Policy {
            allow: vec![
                Allow::Org("github".into()),
                Allow::Cidr("1.1.1.1/32".into()),
            ],
            deny: vec![
                Rule::Category(Category::Tracker),
                Rule::Flag(SecurityFlag::Plaintext),
                Rule::Org("doubleclick".into()),
            ],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
        // The wire shape is the tagged form the UI sends.
        assert!(json.contains(r#"{"type":"category","value":"tracker"}"#));
        assert!(json.contains(r#"{"type":"flag","value":"plaintext"}"#));
    }
}
