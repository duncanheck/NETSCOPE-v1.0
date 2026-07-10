//! # D2 — structured explain, with selectable providers
//!
//! Turns a [`ScrubbedSession`](crate::ScrubbedSession) into a plain-language
//! explanation. Three providers, chosen by the user (NETSCOPE is free to run with
//! no API key at all):
//!
//! - **Built-in** — a deterministic, offline rules summary. No network, always
//!   available, nothing leaves the machine.
//! - **Ollama** — a *local* Llama (or any Ollama model) on `localhost:11434`.
//!   Free, private, runs on your own hardware.
//! - **Claude** — Anthropic's API (needs `ANTHROPIC_API_KEY`).
//!
//! Every provider is fed **only** `scrub_session` output — the privacy boundary
//! holds regardless of which one runs. The built-in and Ollama providers keep
//! everything local; only Claude sends the scrubbed summary off the machine, which
//! the UI states plainly.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ScrubbedSession;
use netscope_protocol::{Category, L4Proto};

/// Versioned in-repo prompt — bump when the wording changes so explanations are
/// traceable to a prompt revision.
pub const PROMPT_VERSION: u32 = 1;

const SYSTEM_PROMPT: &str = "\
You are NETSCOPE's network explainer. You receive a privacy-scrubbed JSON summary \
of the outbound network connections from a user's computer. Each flow lists a \
destination by host/org/category and coarse geo; trackers and plaintext (\
unencrypted) connections are flagged. No local identifiers are present.\n\n\
Explain, in plain language, what this machine appears to be talking to and surface \
anything notable: trackers/telemetry, plaintext connections, and unfamiliar or \
unexpected destinations. Keep it short — a two or three sentence overview, then a \
few bullet points. Ground every statement in the data provided; do not invent \
destinations, owners, or behaviour that isn't in the JSON.";

/// Focused prompt for explaining a *single* selected endpoint (D2, per-node).
const NODE_SYSTEM_PROMPT: &str = "\
You are NETSCOPE's endpoint explainer. You receive a privacy-scrubbed JSON \
description of ONE outbound network connection from a user's computer: its \
destination host/org/category, coarse geo, port, protocol, the owning process \
name, and any tracker/plaintext flags. No local identifiers are present.\n\n\
In 2–4 sentences explain: who owns this destination, what an endpoint like this is \
typically used for, and whether the user should be concerned (tracker/telemetry, \
plaintext/unencrypted, or an unexpected destination). Ground every statement in the \
data; if the host or org is unknown, say so plainly rather than guessing. Do not \
invent owners, locations, or behaviour that isn't in the JSON.";

/// Which explainer to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// Offline, deterministic rules — no network.
    Rules,
    /// A local Ollama model (Llama by default).
    Ollama,
    /// Anthropic's Claude API.
    Anthropic,
}

/// Endpoints/models for the network providers, resolved from the environment.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub ollama_url: String,
    pub ollama_model: String,
    pub anthropic_key: Option<String>,
    pub anthropic_model: String,
}

impl ProviderConfig {
    pub fn from_env() -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
        ProviderConfig {
            ollama_url: env("OLLAMA_URL").unwrap_or_else(|| "http://localhost:11434".into()),
            ollama_model: env("OLLAMA_MODEL").unwrap_or_else(|| "llama3.2".into()),
            anthropic_key: env("ANTHROPIC_API_KEY"),
            // Default to the latest Claude per the API guidance; override with env.
            anthropic_model: env("ANTHROPIC_MODEL").unwrap_or_else(|| "claude-opus-4-8".into()),
        }
    }
}

/// One provider's availability, for the selection menu.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderStatus {
    pub id: Provider,
    pub label: String,
    pub available: bool,
    pub detail: String,
    /// Whether using this provider sends the scrubbed summary off the machine.
    pub local: bool,
    /// For local-model providers (Ollama): the models actually installed on this
    /// machine, detected at probe time. Empty for the others. The first is the
    /// default; the UI lets the user pick any of them.
    #[serde(default)]
    pub models: Vec<String>,
}

/// The result handed back to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct Explanation {
    pub provider: Provider,
    pub prompt_version: u32,
    pub text: String,
}

/// Report each provider's availability (built-in always; Ollama by detecting the
/// models actually installed locally; Claude by key presence) so the menu can
/// disable what isn't ready and offer the user's own local models.
pub fn provider_statuses(cfg: &ProviderConfig) -> Vec<ProviderStatus> {
    // Probe Ollama once: the list of installed models doubles as the reachability
    // check and as the menu's options. A reachable daemon with zero models pulled
    // is "reachable but unusable" — say so plainly.
    let reachable = ollama_reachable(cfg);
    let models = if reachable {
        ollama_models(cfg)
    } else {
        Vec::new()
    };
    let ollama_detail = if !reachable {
        format!("Start Ollama at {} to enable", cfg.ollama_url)
    } else if models.is_empty() {
        "Reachable, but no models installed — run e.g. `ollama pull llama3.2`".into()
    } else {
        format!(
            "{} model{} installed · {}",
            models.len(),
            if models.len() == 1 { "" } else { "s" },
            cfg.ollama_url
        )
    };

    vec![
        ProviderStatus {
            id: Provider::Rules,
            label: "Built-in (offline)".into(),
            available: true,
            detail: "Deterministic summary — nothing leaves your machine".into(),
            local: true,
            models: Vec::new(),
        },
        ProviderStatus {
            id: Provider::Ollama,
            label: "Local model (Ollama)".into(),
            available: reachable && !models.is_empty(),
            detail: ollama_detail,
            local: true,
            models,
        },
        ProviderStatus {
            id: Provider::Anthropic,
            label: "Claude (Anthropic API)".into(),
            available: cfg.anthropic_key.is_some(),
            detail: if cfg.anthropic_key.is_some() {
                format!(
                    "{} · sends the scrubbed summary to Anthropic",
                    cfg.anthropic_model
                )
            } else {
                "Set ANTHROPIC_API_KEY to enable".into()
            },
            local: false,
            models: Vec::new(),
        },
    ]
}

/// Run the chosen provider on a scrubbed session. Blocking — call from a
/// `spawn_blocking` task. The built-in path never touches the network.
pub fn explain(
    provider: Provider,
    cfg: &ProviderConfig,
    session: &ScrubbedSession,
) -> Result<Explanation, String> {
    let text = match provider {
        Provider::Rules => explain_rules(session),
        Provider::Ollama => explain_ollama(cfg, SYSTEM_PROMPT, session)?,
        Provider::Anthropic => explain_anthropic(cfg, SYSTEM_PROMPT, session)?,
    };
    Ok(Explanation {
        provider,
        prompt_version: PROMPT_VERSION,
        text,
    })
}

/// Explain a *single* selected endpoint (D2, per-node). `session` must hold exactly
/// the one scrubbed flow; the providers run with the focused [`NODE_SYSTEM_PROMPT`].
/// Same privacy boundary — the input is still `scrub_session` output.
pub fn explain_node(
    provider: Provider,
    cfg: &ProviderConfig,
    session: &ScrubbedSession,
) -> Result<Explanation, String> {
    let flow = session
        .flows
        .first()
        .ok_or("no flow to explain (it may have closed)")?;
    let text = match provider {
        Provider::Rules => explain_node_rules(flow),
        Provider::Ollama => explain_ollama(cfg, NODE_SYSTEM_PROMPT, session)?,
        Provider::Anthropic => explain_anthropic(cfg, NODE_SYSTEM_PROMPT, session)?,
    };
    Ok(Explanation {
        provider,
        prompt_version: PROMPT_VERSION,
        text,
    })
}

/// Deterministic, offline one-endpoint summary — the per-node analogue of
/// [`explain_rules`]. Built straight from the scrubbed fields, no network.
pub fn explain_node_rules(f: &crate::ScrubbedFlow) -> String {
    use crate::Scope;
    if f.scope == Scope::Local {
        return format!(
            "A connection to a device on your local network ({}/:{}), {}. Local traffic stays on your LAN/tailnet and isn't sent to the internet.",
            proto_label(f.protocol),
            f.port,
            if f.encrypted { "encrypted" } else { "unencrypted" },
        );
    }

    let who = match (&f.host, &f.org) {
        (Some(h), Some(o)) => format!("{h} — run by {o}"),
        (Some(h), None) => h.clone(),
        (None, Some(o)) => format!("an endpoint at {o}"),
        (None, None) => "an unidentified remote endpoint".to_string(),
    };
    let asn = f.asn.map(|n| format!(" (AS{n})")).unwrap_or_default();
    let place = match (&f.city, &f.country) {
        (Some(c), Some(cc)) => format!(", served from {c}, {cc}"),
        (None, Some(cc)) => format!(", served from {cc}"),
        _ => String::new(),
    };
    let proc = f
        .process
        .as_deref()
        .map(|p| format!(" The connection is owned by {p}."))
        .unwrap_or_default();

    let mut out = format!(
        "{who}{asn}{place}. Classified as {} traffic on {}/:{}, {}.{proc}",
        category_label(f.category),
        proto_label(f.protocol),
        f.port,
        if f.encrypted {
            "encrypted"
        } else {
            "PLAINTEXT — readable in transit"
        },
    );

    let mut notes: Vec<&str> = Vec::new();
    for flag in &f.flags {
        notes.push(match flag {
            netscope_protocol::SecurityFlag::Tracker => "flagged as a tracker / telemetry endpoint",
            netscope_protocol::SecurityFlag::Plaintext => "sends data unencrypted",
            netscope_protocol::SecurityFlag::UnresolvedOrg => "the owning organisation is unknown",
        });
    }
    if !notes.is_empty() {
        out.push_str(" Notable: ");
        out.push_str(&notes.join("; "));
        out.push('.');
    }
    out
}

fn category_label(c: Category) -> &'static str {
    match c {
        Category::Service => "a service",
        Category::Cdn => "CDN / content-delivery",
        Category::Tracker => "tracker / telemetry",
        Category::Local => "local-network",
        Category::Unknown => "uncategorised",
    }
}

fn proto_label(p: L4Proto) -> &'static str {
    match p {
        L4Proto::Tcp => "TCP",
        L4Proto::Udp => "UDP",
    }
}

/// The prompt body sent to an LLM provider: the system prompt plus the scrubbed
/// session as pretty JSON.
fn user_content(session: &ScrubbedSession) -> String {
    let json = serde_json::to_string_pretty(session).unwrap_or_else(|_| "{}".into());
    format!("Here is the scrubbed session:\n\n```json\n{json}\n```")
}

/// Deterministic, offline explanation built straight from the aggregates and
/// flags — no model, no network. Also the fallback when an LLM is unavailable.
pub fn explain_rules(session: &ScrubbedSession) -> String {
    let t = &session.totals;
    let mut out = String::new();

    if t.flows == 0 {
        return "No active outbound connections were captured.".into();
    }

    out.push_str(&format!(
        "Your machine has {} active connection{} — {} to remote services and {} on your local network. {} of {} remote flow{} are encrypted.",
        t.flows,
        plural(t.flows),
        t.remote,
        t.local,
        t.encrypted.min(t.remote),
        t.remote,
        plural(t.remote),
    ));

    let mut bullets: Vec<String> = Vec::new();

    if t.trackers > 0 {
        bullets.push(format!(
            "{} flow{} classified as trackers / telemetry.",
            t.trackers,
            plural(t.trackers)
        ));
    }
    if t.plaintext > 0 {
        bullets.push(format!(
            "{} plaintext (unencrypted) connection{} — data may be readable in transit.",
            t.plaintext,
            plural(t.plaintext)
        ));
    }

    // Name the most common destination orgs (already scrubbed; remote only).
    let mut orgs: Vec<&str> = session
        .flows
        .iter()
        .filter_map(|f| f.org.as_deref())
        .collect();
    orgs.sort_unstable();
    orgs.dedup();
    if !orgs.is_empty() {
        let shown: Vec<&str> = orgs.into_iter().take(5).collect();
        bullets.push(format!("Talking to: {}.", shown.join(", ")));
    }

    if bullets.is_empty() {
        out.push_str(" Nothing notable stands out — no trackers or plaintext flows.");
    } else {
        out.push('\n');
        for b in bullets {
            out.push_str(&format!("\n• {b}"));
        }
    }
    out
}

fn explain_ollama(
    cfg: &ProviderConfig,
    system: &str,
    session: &ScrubbedSession,
) -> Result<String, String> {
    let url = format!("{}/api/chat", cfg.ollama_url.trim_end_matches('/'));
    let payload = serde_json::json!({
        "model": cfg.ollama_model,
        "stream": false,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content(session)},
        ],
    });
    let body = post_json(&url, &[], &payload, Duration::from_secs(120))?;
    body.pointer("/message/content")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "Ollama returned no content".to_string())
}

fn explain_anthropic(
    cfg: &ProviderConfig,
    system: &str,
    session: &ScrubbedSession,
) -> Result<String, String> {
    let key = cfg
        .anthropic_key
        .as_deref()
        .ok_or("ANTHROPIC_API_KEY is not set")?;
    let payload = serde_json::json!({
        "model": cfg.anthropic_model,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": user_content(session)}],
    });
    let headers = [("x-api-key", key), ("anthropic-version", "2023-06-01")];
    let body = post_json(
        "https://api.anthropic.com/v1/messages",
        &headers,
        &payload,
        Duration::from_secs(120),
    )?;

    // A safety refusal returns HTTP 200 with stop_reason "refusal" — surface it
    // rather than reading an empty content array.
    if body.pointer("/stop_reason").and_then(|v| v.as_str()) == Some("refusal") {
        return Err("Claude declined to explain this session.".into());
    }
    body.pointer("/content/0/text")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "Claude returned no text".to_string())
}

/// POST JSON and parse the JSON response, surfacing a useful error on non-2xx.
fn post_json(
    url: &str,
    headers: &[(&str, &str)],
    payload: &serde_json::Value,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let body = serde_json::to_string(payload).map_err(|e| e.to_string())?;
    let mut req = ureq::post(url)
        .timeout(timeout)
        .set("content-type", "application/json");
    for (k, v) in headers {
        req = req.set(k, v);
    }
    match req.send_string(&body) {
        Ok(resp) => {
            let text = resp.into_string().map_err(|e| e.to_string())?;
            serde_json::from_str(&text).map_err(|e| e.to_string())
        }
        Err(ureq::Error::Status(code, resp)) => {
            let detail = resp.into_string().unwrap_or_default();
            Err(format!("provider returned HTTP {code}: {}", detail.trim()))
        }
        Err(e) => Err(format!("could not reach provider: {e}")),
    }
}

fn ollama_reachable(cfg: &ProviderConfig) -> bool {
    let url = format!("{}/api/tags", cfg.ollama_url.trim_end_matches('/'));
    ureq::get(&url)
        .timeout(Duration::from_millis(800))
        .call()
        .is_ok()
}

/// The models installed in the local Ollama, newest-typical first. `GET /api/tags`
/// returns `{"models":[{"name":"llama3.2:latest", ...}, ...]}`; we surface the
/// names. Best-effort: any failure yields an empty list (the provider is then
/// reported unavailable rather than erroring).
pub fn ollama_models(cfg: &ProviderConfig) -> Vec<String> {
    let url = format!("{}/api/tags", cfg.ollama_url.trim_end_matches('/'));
    let Ok(resp) = ureq::get(&url).timeout(Duration::from_millis(1500)).call() else {
        return Vec::new();
    };
    let Ok(text) = resp.into_string() else {
        return Vec::new();
    };
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(body) => parse_model_names(&body),
        Err(_) => Vec::new(),
    }
}

/// Extract installed model names from an Ollama `/api/tags` body, sorted and
/// deduped. Split out from the network call so it can be tested directly.
fn parse_model_names(body: &serde_json::Value) -> Vec<String> {
    let mut names: Vec<String> = body
        .get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(str::to_string))
                .filter(|s| !s.trim().is_empty())
                .collect()
        })
        .unwrap_or_default();
    names.sort_unstable();
    names.dedup();
    names
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrub_session;
    use netscope_protocol::{
        AsnInfo, Category, Flow, GeoLocation, L4Proto, ProcessInfo, SecurityFlag,
    };

    fn flow(id: &str, ip: &str, org: Option<&str>, cat: Category, enc: bool) -> Flow {
        Flow {
            id: id.into(),
            name: "host.example.com".into(),
            category: cat,
            asn: org.map(|o| AsnInfo {
                number: 1,
                org: o.into(),
            }),
            location: Some(GeoLocation {
                city: Some("LA".into()),
                country: Some("US".into()),
                lat: None,
                lon: None,
            }),
            process: Some(ProcessInfo {
                pid: 1,
                name: "firefox".into(),
                path: None,
            }),
            port: 443,
            protocol: L4Proto::Tcp,
            encrypted: enc,
            ip: ip.into(),
            activity: 0.5,
            alive: true,
            flags: if cat == Category::Tracker {
                vec![SecurityFlag::Tracker]
            } else if !enc {
                vec![SecurityFlag::Plaintext]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn rules_summarize_counts_and_orgs() {
        let session = scrub_session(&[
            flow("a", "93.184.216.34", Some("Edgecast"), Category::Cdn, true),
            flow("b", "8.8.8.8", Some("Google"), Category::Tracker, true),
            flow("c", "1.2.3.4", Some("Acme"), Category::Service, false),
            flow("d", "192.168.1.2", None, Category::Local, true),
        ]);
        let text = explain_rules(&session);
        assert!(text.contains("4 active connection"));
        assert!(text.contains("tracker"));
        assert!(text.contains("plaintext"));
        assert!(text.contains("Edgecast") || text.contains("Google") || text.contains("Acme"));
    }

    #[test]
    fn rules_handle_empty_session() {
        let session = scrub_session(&[]);
        assert!(explain_rules(&session).contains("No active outbound"));
    }

    #[test]
    fn rules_explain_runs_through_explain_entrypoint_offline() {
        let session = scrub_session(&[flow(
            "a",
            "93.184.216.34",
            Some("Edgecast"),
            Category::Service,
            true,
        )]);
        let cfg = ProviderConfig::from_env();
        let out = explain(Provider::Rules, &cfg, &session).unwrap();
        assert_eq!(out.provider, Provider::Rules);
        assert_eq!(out.prompt_version, PROMPT_VERSION);
        assert!(!out.text.is_empty());
    }

    #[test]
    fn user_content_carries_no_local_identifiers() {
        // The prompt body is built from scrubbed data — double-check nothing leaks.
        let session = scrub_session(&[flow(
            "tcp:192.168.1.50:54000->93.184.216.34:443",
            "93.184.216.34",
            Some("Edgecast"),
            Category::Service,
            true,
        )]);
        let body = user_content(&session);
        assert!(!body.contains("192.168.1.50"));
        assert!(!body.contains("54000"));
    }

    #[test]
    fn parses_and_sorts_installed_ollama_models() {
        let body = serde_json::json!({
            "models": [
                {"name": "llama3.2:latest", "size": 1},
                {"name": "qwen2.5:7b"},
                {"name": ""},          // ignored
                {"size": 2},            // no name — ignored
                {"name": "llama3.2:latest"} // duplicate — deduped
            ]
        });
        assert_eq!(
            parse_model_names(&body),
            vec!["llama3.2:latest".to_string(), "qwen2.5:7b".to_string()]
        );
        // A missing/garbage body yields no models rather than erroring.
        assert!(parse_model_names(&serde_json::json!({})).is_empty());
        assert!(parse_model_names(&serde_json::json!({"models": "nope"})).is_empty());
    }

    #[test]
    fn anthropic_requires_a_key() {
        let cfg = ProviderConfig {
            ollama_url: "http://localhost:11434".into(),
            ollama_model: "llama3.2".into(),
            anthropic_key: None,
            anthropic_model: "claude-opus-4-8".into(),
        };
        let session = scrub_session(&[]);
        assert!(explain_anthropic(&cfg, SYSTEM_PROMPT, &session).is_err());
    }

    #[test]
    fn node_rules_describe_a_single_remote_endpoint() {
        let session = scrub_session(&[flow(
            "a",
            "93.184.216.34",
            Some("Edgecast"),
            Category::Tracker,
            false,
        )]);
        let out = explain_node(Provider::Rules, &ProviderConfig::from_env(), &session).unwrap();
        assert_eq!(out.provider, Provider::Rules);
        assert!(out.text.contains("Edgecast"));
        assert!(out.text.contains("tracker") || out.text.contains("telemetry"));
        assert!(out.text.contains("PLAINTEXT"));
    }

    #[test]
    fn node_rules_redact_a_local_endpoint() {
        let session = scrub_session(&[flow("b", "192.168.1.10", None, Category::Local, true)]);
        let out = explain_node(Provider::Rules, &ProviderConfig::from_env(), &session).unwrap();
        assert!(out.text.contains("local network"));
        // No raw LAN address leaks into the per-node summary.
        assert!(!out.text.contains("192.168.1.10"));
    }

    #[test]
    fn node_explain_errors_on_empty_session() {
        let session = scrub_session(&[]);
        assert!(explain_node(Provider::Rules, &ProviderConfig::from_env(), &session).is_err());
    }
}
