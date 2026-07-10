//! # D3 — the classification eval
//!
//! Every explanation NETSCOPE produces rests on one thing: the classification of
//! each flow (tracker / CDN / service) and its security flags. An LLM narrating on
//! top can only be as right as that substrate. So the honest measure of "when are
//! the explanations wrong" is: **how often is the classifier wrong**, on a labeled
//! set of real-world endpoints — run through the *same* [`crate::classify`] policy
//! the product ships.
//!
//! The dataset below is small and deliberately includes cases the curated keyword
//! heuristic *gets wrong* (Facebook/LinkedIn/gstatic carry no keyword; a BI tool
//! named "analytics" trips a false positive). The point of an eval is to surface
//! those, not to hide them — the number in the README is the real one, failures
//! included. The eval is offline and deterministic (no model, no network), so it
//! runs in CI; the LLM-narration layer is evaluated manually against this same
//! substrate.

use netscope_protocol::{AsnInfo, Category, Flow, L4Proto, SecurityFlag};

use crate::classify;

/// One labeled endpoint: the inputs the classifier sees, plus the ground-truth
/// category a human would assign.
#[derive(Debug, Clone, Copy)]
pub struct Labeled {
    pub host: &'static str,
    pub org: Option<&'static str>,
    pub encrypted: bool,
    pub expected: Category,
    /// Whether a human would call this a tracker (drives the precision/recall pair;
    /// usually equals `expected == Tracker`).
    pub is_tracker: bool,
}

/// A single misclassification, for the report.
#[derive(Debug, Clone)]
pub struct Failure {
    pub host: String,
    pub expected: Category,
    pub got: Category,
}

/// Eval results over the dataset. The fields are the honest, reproducible numbers.
#[derive(Debug, Clone)]
pub struct EvalReport {
    pub total: usize,
    pub category_correct: usize,
    pub tracker_tp: usize,
    pub tracker_fp: usize,
    pub tracker_fn: usize,
    pub plaintext_correct: usize,
    pub failures: Vec<Failure>,
}

impl EvalReport {
    pub fn category_accuracy(&self) -> f64 {
        ratio(self.category_correct, self.total)
    }
    pub fn tracker_precision(&self) -> f64 {
        ratio(self.tracker_tp, self.tracker_tp + self.tracker_fp)
    }
    pub fn tracker_recall(&self) -> f64 {
        ratio(self.tracker_tp, self.tracker_tp + self.tracker_fn)
    }
    pub fn plaintext_accuracy(&self) -> f64 {
        ratio(self.plaintext_correct, self.total)
    }
}

fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        1.0
    } else {
        num as f64 / den as f64
    }
}

fn flow_of(label: &Labeled) -> Flow {
    Flow {
        id: "eval".into(),
        name: label.host.into(),
        // Local labels arrive pre-classified (as capture does); remote start Unknown.
        category: if label.expected == Category::Local {
            Category::Local
        } else {
            Category::Unknown
        },
        asn: label.org.map(|o| AsnInfo {
            number: 0,
            org: o.into(),
        }),
        location: None,
        process: None,
        port: if label.encrypted { 443 } else { 80 },
        protocol: L4Proto::Tcp,
        encrypted: label.encrypted,
        ip: "203.0.113.1".into(),
        activity: 0.0,
        alive: true,
        flags: Vec::new(),
    }
}

/// Run the classifier over `dataset` and tally the metrics.
pub fn run(dataset: &[Labeled]) -> EvalReport {
    let mut r = EvalReport {
        total: dataset.len(),
        category_correct: 0,
        tracker_tp: 0,
        tracker_fp: 0,
        tracker_fn: 0,
        plaintext_correct: 0,
        failures: Vec::new(),
    };

    for label in dataset {
        let mut flow = flow_of(label);
        let got = classify::category(&flow);
        flow.category = got;
        let flags = classify::security_flags(&flow);

        if got == label.expected {
            r.category_correct += 1;
        } else {
            r.failures.push(Failure {
                host: label.host.to_string(),
                expected: label.expected,
                got,
            });
        }

        let predicted_tracker = flags.contains(&SecurityFlag::Tracker);
        match (label.is_tracker, predicted_tracker) {
            (true, true) => r.tracker_tp += 1,
            (false, true) => r.tracker_fp += 1,
            (true, false) => r.tracker_fn += 1,
            (false, false) => {}
        }

        // Plaintext is a pure function of the encrypted flag — the flag should be
        // present exactly when the flow is *not* encrypted, so this should be exact.
        let predicted_plaintext = flags.contains(&SecurityFlag::Plaintext);
        if predicted_plaintext != label.encrypted {
            r.plaintext_correct += 1;
        }
    }
    r
}

/// Run against the bundled [`DATASET`].
pub fn run_default() -> EvalReport {
    run(DATASET)
}

/// The labeled set. ~40 real-world-shaped endpoints across trackers, CDNs,
/// services, unknown, and local — including the cases the heuristic misses.
pub const DATASET: &[Labeled] = &[
    // --- Trackers the keywords catch ---
    t("google-analytics.com", Some("Google LLC")),
    t("www.googletagmanager.com", Some("Google LLC")),
    t("stats.g.doubleclick.net", Some("Google LLC")),
    t("sb.scorecardresearch.com", Some("comScore Inc")),
    t("api.amplitude.com", Some("Amplitude Inc")),
    t("api2.branch.io", Some("Branch Metrics")),
    t("api.mixpanel.com", Some("Mixpanel Inc")),
    t("ib.adnxs.com", Some("AppNexus")), // org "AppNexus" → "appnexus" keyword
    t("analytics.tiktok.com", Some("TikTok")),
    t("incoming.telemetry.mozilla.org", Some("Mozilla")),
    // --- Trackers the keyword heuristic MISSES (honest false negatives) ---
    fn_tracker("connect.facebook.net", Some("Facebook Inc")),
    fn_tracker("graph.facebook.com", Some("Facebook Inc")),
    fn_tracker("pixel.tapad.com", Some("Tapad Inc")),
    fn_tracker("t.co", Some("Twitter Inc")),
    // --- A false positive: a legitimate BI/service whose name trips "analytics" ---
    Labeled {
        host: "app.acme-analytics-suite.com",
        org: Some("Acme Software"),
        encrypted: true,
        expected: Category::Service, // it's the user's own BI tool, not a tracker
        is_tracker: false,
    },
    // --- CDNs the keywords catch ---
    c("cloudflare.com", Some("Cloudflare Inc")),
    c("e1.akamai.net", Some("Akamai Technologies")),
    c("dualstack.fastly.net", Some("Fastly Inc")),
    c("d111abcdef.cloudfront.net", Some("Amazon.com")),
    c("cdn.jsdelivr.net", Some("jsDelivr")),
    c("assets.bunnycdn.com", Some("BunnyWay")),
    // --- CDNs the heuristic MISSES (honest false negatives) ---
    fn_cdn("fonts.gstatic.com", Some("Google LLC")),
    fn_cdn("static.licdn.com", Some("LinkedIn")),
    // --- Plain services ---
    s("api.github.com", Some("GitHub Inc")),
    s("api.stripe.com", Some("Stripe Inc")),
    s("api.openai.com", Some("OpenAI")),
    s("wss-primary.slack.com", Some("Slack Technologies")),
    s("registry.npmjs.org", Some("npm Inc")),
    s("login.microsoftonline.com", Some("Microsoft")),
    s("gateway.discord.gg", Some("Discord Inc")),
    s("s3.us-east-1.amazonaws.com", Some("Amazon.com")),
    // A plaintext service — category Service, plaintext flag must fire.
    Labeled {
        host: "mirror.archlinux.org",
        org: Some("Arch Linux"),
        encrypted: false,
        expected: Category::Service,
        is_tracker: false,
    },
    // --- Unattributable (no org) → Unknown ---
    Labeled {
        host: "198.51.100.23",
        org: None,
        encrypted: true,
        expected: Category::Unknown,
        is_tracker: false,
    },
    Labeled {
        host: "203.0.113.200",
        org: None,
        encrypted: false,
        expected: Category::Unknown,
        is_tracker: false,
    },
    // --- Local network ---
    Labeled {
        host: "192.168.1.10",
        org: None,
        encrypted: false,
        expected: Category::Local,
        is_tracker: false,
    },
    Labeled {
        host: "10.0.0.42",
        org: None,
        encrypted: true,
        expected: Category::Local,
        is_tracker: false,
    },
];

// Builders keep the dataset terse and readable.
const fn t(host: &'static str, org: Option<&'static str>) -> Labeled {
    Labeled {
        host,
        org,
        encrypted: true,
        expected: Category::Tracker,
        is_tracker: true,
    }
}
const fn c(host: &'static str, org: Option<&'static str>) -> Labeled {
    Labeled {
        host,
        org,
        encrypted: true,
        expected: Category::Cdn,
        is_tracker: false,
    }
}
const fn s(host: &'static str, org: Option<&'static str>) -> Labeled {
    Labeled {
        host,
        org,
        encrypted: true,
        expected: Category::Service,
        is_tracker: false,
    }
}
/// A real tracker the heuristic can't catch — labeled Tracker so it counts against
/// recall, even though the classifier will (honestly) call it Service.
const fn fn_tracker(host: &'static str, org: Option<&'static str>) -> Labeled {
    Labeled {
        host,
        org,
        encrypted: true,
        expected: Category::Tracker,
        is_tracker: true,
    }
}
/// A real CDN the heuristic can't catch — labeled Cdn so it counts as a miss.
const fn fn_cdn(host: &'static str, org: Option<&'static str>) -> Labeled {
    Labeled {
        host,
        org,
        encrypted: true,
        expected: Category::Cdn,
        is_tracker: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_eval_reports_honest_metrics() {
        let r = run_default();

        println!("\n=== NETSCOPE classification eval (n={}) ===", r.total);
        println!(
            "category accuracy : {:.1}%  ({}/{} correct)",
            r.category_accuracy() * 100.0,
            r.category_correct,
            r.total
        );
        println!(
            "tracker precision : {:.1}%   recall : {:.1}%   (tp={} fp={} fn={})",
            r.tracker_precision() * 100.0,
            r.tracker_recall() * 100.0,
            r.tracker_tp,
            r.tracker_fp,
            r.tracker_fn
        );
        println!("plaintext accuracy: {:.1}%", r.plaintext_accuracy() * 100.0);
        if !r.failures.is_empty() {
            println!("misclassified:");
            for f in &r.failures {
                println!(
                    "  {:<32} expected {:?}, got {:?}",
                    f.host, f.expected, f.got
                );
            }
        }

        // Plaintext detection is a pure port/flag function — it must be exact.
        assert_eq!(
            r.plaintext_correct, r.total,
            "plaintext detection must be exact"
        );
        // Conservative floors so CI is stable; the README carries the real numbers.
        assert!(r.category_accuracy() >= 0.70, "category accuracy regressed");
        assert!(r.tracker_recall() >= 0.60, "tracker recall regressed");
        assert!(r.tracker_precision() >= 0.80, "tracker precision regressed");
    }
}
