//! Classification and security flags (A4). Pure functions of a flow's resolved
//! org/hostname and its port — so the policy *is* the tests. Classification refines
//! the A2 `Unknown` into service / CDN / tracker; the flags are the per-flow
//! security/privacy callouts the UI surfaces.
//!
//! The keyword lists are deliberately small and honest — a curated heuristic, not
//! a comprehensive blocklist. Matching is case-insensitive substring on the
//! resolved org *and* the reverse-DNS hostname, so either signal can classify.

use netscope_protocol::{Category, Flow, SecurityFlag};

/// Org/hostname fragments that mark tracker / telemetry / ad endpoints.
const TRACKER_KEYWORDS: &[&str] = &[
    "doubleclick",
    "adsystem",
    "adservice",
    "admetrics",
    "scorecardresearch",
    "criteo",
    "taboola",
    "outbrain",
    "appnexus",
    "pubmatic",
    "rubiconproject",
    "moatads",
    "quantserve",
    "chartbeat",
    "mixpanel",
    "segment.io",
    "amplitude",
    "appsflyer",
    "adjust.com",
    "branch.io",
    "bugsnag",
    "crashlytics",
    "google-analytics",
    "googletagmanager",
    "analytics",
    "telemetry",
    "metric",
];

/// Org/hostname fragments that mark content-delivery networks.
const CDN_KEYWORDS: &[&str] = &[
    "akamai",
    "cloudflare",
    "fastly",
    "cloudfront",
    "edgecast",
    "stackpath",
    "bunnycdn",
    "limelight",
    "edgio",
    "gcore",
    "jsdelivr",
    "cdn",
];

fn matches_any(org: Option<&str>, name: &str, keywords: &[&str]) -> bool {
    let org = org.unwrap_or("");
    keywords.iter().any(|k| org.contains(k) || name.contains(k))
}

/// Refine a flow's category from its resolved org and hostname. Local flows keep
/// their `Local` category (set in capture, before enrichment); everything else is
/// tracker > CDN > service (has an org) > unknown (couldn't attribute it).
pub fn category(flow: &Flow) -> Category {
    category_with(flow, &[])
}

/// [`category`] with user-supplied extra tracker keywords (GROWTH G4.2: a
/// pluggable list to lift recall beyond the curated built-ins — the eval grades
/// the built-ins only, so published numbers stay comparable). Extras must be
/// lowercase; they extend, never replace, and still lose to `Local`.
pub fn category_with(flow: &Flow, extra_trackers: &[String]) -> Category {
    if flow.category == Category::Local {
        return Category::Local;
    }
    let org = flow.asn.as_ref().map(|a| a.org.to_lowercase());
    let name = flow.name.to_lowercase();
    let org_ref = org.as_deref();

    let extra_hit = || {
        let org = org_ref.unwrap_or("");
        extra_trackers
            .iter()
            .any(|k| !k.is_empty() && (org.contains(k.as_str()) || name.contains(k.as_str())))
    };

    if matches_any(org_ref, &name, TRACKER_KEYWORDS) || extra_hit() {
        Category::Tracker
    } else if matches_any(org_ref, &name, CDN_KEYWORDS) {
        Category::Cdn
    } else if flow.asn.is_some() {
        Category::Service
    } else {
        Category::Unknown
    }
}

/// Per-flow security/privacy callouts. Computed after `category`, so the tracker
/// flag agrees with the category.
pub fn security_flags(flow: &Flow) -> Vec<SecurityFlag> {
    let mut flags = Vec::new();
    if !flow.encrypted {
        flags.push(SecurityFlag::Plaintext);
    }
    // "Can't attribute this destination" — only meaningful for remote flows.
    if flow.asn.is_none() && flow.category != Category::Local {
        flags.push(SecurityFlag::UnresolvedOrg);
    }
    if flow.category == Category::Tracker {
        flags.push(SecurityFlag::Tracker);
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_protocol::{AsnInfo, L4Proto};

    fn flow(name: &str, org: Option<&str>, encrypted: bool, category: Category) -> Flow {
        Flow {
            id: "t".into(),
            name: name.into(),
            category,
            asn: org.map(|o| AsnInfo {
                number: 1,
                org: o.into(),
            }),
            location: None,
            process: None,
            port: if encrypted { 443 } else { 80 },
            protocol: L4Proto::Tcp,
            encrypted,
            ip: "1.2.3.4".into(),
            activity: 0.5,
            alive: true,
            flags: Vec::new(),
        }
    }

    #[test]
    fn tracker_org_classifies_tracker() {
        let f = flow("x", Some("DoubleClick LLC"), true, Category::Unknown);
        assert_eq!(category(&f), Category::Tracker);
    }

    #[test]
    fn tracker_hostname_classifies_tracker() {
        let f = flow("telemetry.example.com", None, true, Category::Unknown);
        assert_eq!(category(&f), Category::Tracker);
    }

    #[test]
    fn cdn_org_classifies_cdn() {
        let f = flow("x", Some("Akamai Technologies"), true, Category::Unknown);
        assert_eq!(category(&f), Category::Cdn);
    }

    #[test]
    fn org_without_keyword_is_service() {
        let f = flow(
            "api.github.com",
            Some("GitHub, Inc."),
            true,
            Category::Unknown,
        );
        assert_eq!(category(&f), Category::Service);
    }

    #[test]
    fn no_org_is_unknown() {
        let f = flow("203.0.113.7", None, true, Category::Unknown);
        assert_eq!(category(&f), Category::Unknown);
    }

    #[test]
    fn local_stays_local() {
        let f = flow("192.168.1.1", None, false, Category::Local);
        assert_eq!(category(&f), Category::Local);
    }

    #[test]
    fn plaintext_and_unresolved_flags() {
        let f = flow("203.0.113.7", None, false, Category::Unknown);
        let flags = security_flags(&f);
        assert!(flags.contains(&SecurityFlag::Plaintext));
        assert!(flags.contains(&SecurityFlag::UnresolvedOrg));
    }

    #[test]
    fn encrypted_attributed_flow_has_no_flags() {
        let f = flow("api.github.com", Some("GitHub"), true, Category::Service);
        assert!(security_flags(&f).is_empty());
    }

    #[test]
    fn local_flow_is_not_unresolved_but_may_be_plaintext() {
        let f = flow("192.168.1.1", None, false, Category::Local);
        let flags = security_flags(&f);
        assert!(flags.contains(&SecurityFlag::Plaintext));
        assert!(!flags.contains(&SecurityFlag::UnresolvedOrg));
    }

    #[test]
    fn extra_keyword_catches_what_the_builtins_miss() {
        // connect.facebook.net is the eval's named miss (docs/eval.md) — no
        // built-in keyword matches it, so it classifies Service. A user-supplied
        // keyword flips it to Tracker.
        let f = flow(
            "connect.facebook.net",
            Some("Meta Platforms"),
            true,
            Category::Unknown,
        );
        assert_eq!(category(&f), Category::Service);
        assert_eq!(
            category_with(&f, &["facebook".to_string()]),
            Category::Tracker
        );
    }

    #[test]
    fn extra_keywords_extend_but_never_reclassify_local() {
        let f = flow("192.168.1.1", None, false, Category::Local);
        assert_eq!(category_with(&f, &["192.168".to_string()]), Category::Local);
        // Empty extras behave exactly like the plain function.
        let g = flow(
            "api.github.com",
            Some("GitHub, Inc."),
            true,
            Category::Unknown,
        );
        assert_eq!(category_with(&g, &[]), category(&g));
        // Empty strings in the list never match everything.
        assert_eq!(category_with(&g, &[String::new()]), Category::Service);
    }
}
