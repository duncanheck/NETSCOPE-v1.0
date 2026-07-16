//! # netscope-agent
//!
//! Captures the host's connection state by polling the OS connection tables
//! (~250 ms) and serves it over the versioned wire protocol. On connect a client
//! receives `hello`, then a `snapshot` of the current world, then a `delta` per
//! capture generation plus a `heartbeat` per tick — one batched payload per
//! event, never per-item (PITFALLS A1).
//!
//! The HTTP layer is `axum`: the WebSocket feed lives at `/ws`, and — in the
//! `bundled-ui` build — the compiled frontend is embedded and served from `/` on
//! the same port, so the product is a single executable that opens in a browser.
//!
//! The capture loop (A2) is metadata-only by deliberate choice — no Npcap. The
//! platform-specific table read lives behind [`capture::ConnectionSource`]
//! (Linux + Windows); this binary is the transport that fans the result out.

mod auth;
mod capture;
mod config;
#[cfg(any(unix, windows))]
mod enforce;
mod enrich;
mod history;
mod setup;
mod update;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use netscope_protocol::{
    AgentInfo, ClientMessage, Delta, Encoding, Frame, Heartbeat, Hello, ResyncRequest, Snapshot,
    WireMessage, PROTOCOL_VERSION,
};
use netscope_ring::{CrossbeamRing, Ring};
use tokio::net::TcpListener;
use tokio::sync::{watch, Notify};
use tokio::time::interval;

use auth::AuthState;
use capture::{CaptureEngine, CaptureUpdate, DeltaParts, Enrich};
use enrich::Enricher;
use netscope_narrator::{
    explain, explain_node, provider_statuses, scrub_session, Provider, ProviderConfig,
};
use netscope_warden::{
    default_backend, dry_run_with, generate, threat_targets, Firewall, Policy, ThreatDb,
};
use update::{BuildInfo, Updater};

const BIND_ADDR: &str = "127.0.0.1:8787";
/// Connection-table poll cadence. ~250 ms is the documented v1 trade: frequent
/// enough to feel live, coarse enough that sub-250 ms flows slip through — the
/// limitation the Npcap path removes (ARCHITECTURE.md / PITFALLS A2).
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Heartbeat cadence — a steady liveness pulse independent of capture activity.
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(1000);
/// Capacity of the capture→protocol ring (ROADMAP A3). The path moves ~4
/// updates/sec, so this is generous headroom; a full ring drops the newest
/// update, which the client heals via generation-gap resync. We ship the
/// verified `CrossbeamRing`; the hand-built `AtomicSpsc` is the benchmarked,
/// swap-in-ready alternative (see `docs/ringbuffer.md`).
const RING_CAPACITY: usize = 256;

/// Shared with each request: the latest-world watch receiver and the pairing/token
/// auth state (C2). Cheap to clone — `rx` is a watch receiver, the rest `Arc`s.
#[derive(Clone)]
struct AppState {
    rx: watch::Receiver<Arc<CaptureUpdate>>,
    auth: Arc<AuthState>,
    update: Arc<Updater>,
    /// Loaded threat feeds (E2). Behind a lock so the G3.2 in-app download can
    /// hot-swap a fresh load without a restart; handlers clone the inner `Arc`
    /// out and drop the lock immediately.
    threats: Arc<std::sync::RwLock<Arc<ThreatDb>>>,
    /// The enrichment pipeline — held concretely so the G3.2 setup path can
    /// hot-reload the GeoLite2 databases after an in-app download.
    enricher: Arc<Enricher>,
    /// Packet-capture state (G5), decided once at startup; shown verbatim in
    /// /setup/status and the System panel.
    pcap_status: Arc<str>,
}

impl AppState {
    /// The current threat DB (E2), lock released before returning.
    fn threats(&self) -> Arc<ThreatDb> {
        self.threats.read().unwrap().clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netscope_agent=info".into()),
        )
        .init();

    // Capture → protocol → clients, in two stages:
    //   1. the capture thread (producer) hands each update to the consumer over a
    //      bounded SPSC *ring* (A3) — never blocking the OS-table poll;
    //   2. a coordinator task (the single consumer) drains the ring and republishes
    //      on a *watch* channel, which fans the latest value out to every client.
    let ring: Arc<dyn Ring<CaptureUpdate>> = Arc::new(CrossbeamRing::new(RING_CAPACITY));
    let notify = Arc::new(Notify::new());
    let (tx, rx) = watch::channel(Arc::new(CaptureUpdate::default()));
    // The enrichment pipeline (A4) spawns reverse-DNS lookups on this runtime.
    // Held concretely (not as `dyn Enrich`) so the setup control plane (G3.2)
    // can hot-reload the GeoLite2 databases on it.
    let enricher = Enricher::new(tokio::runtime::Handle::current());
    // Packet capture (G5): the opt-in pcap/Npcap augmentation. `None` (the
    // default) leaves the polling path exactly as measured; the status string
    // is surfaced verbatim in /setup/status and the System panel.
    let (pkt_observer, pcap_status) = capture::packet_observer_from_env();
    spawn_capture_loop(
        Arc::clone(&ring),
        Arc::clone(&notify),
        Arc::clone(&enricher) as Arc<dyn Enrich>,
        pkt_observer,
    );
    // Opt-in flow history (G4.1): only when NETSCOPE_HISTORY_DIR is set does
    // anything touch disk — the ephemeral default stands (threat-model.md).
    let flow_history = history::HistoryLog::from_env();
    tokio::spawn(run_coordinator(ring, notify, tx, flow_history));

    // C2 auth. Loopback clients stay token-free (the existing trust boundary);
    // a remote client (C3) must pair for a token. We mint the first code now so
    // it's printed alongside the listen banner and ready for a phone to redeem.
    let auth = Arc::new(AuthState::new());

    // Self-update (Windows product). A stamped build checks the rolling `latest`
    // release on launch; a dev build (id 0) or `NETSCOPE_NO_UPDATE` skips it.
    let build = BuildInfo::current();
    let updater = Arc::new(Updater::new(build.clone()));
    if !updater.is_dev() && std::env::var_os("NETSCOPE_NO_UPDATE").is_none() {
        let u = Arc::clone(&updater);
        tokio::spawn(async move {
            // Check at startup, then poll on a slow cadence so a long-running app
            // notices a newly published build without a restart. Blocking HTTPS runs
            // off the async runtime; the result lands in the status the HUD reads.
            // Never fatal.
            loop {
                let u2 = Arc::clone(&u);
                let _ = tokio::task::spawn_blocking(move || u2.check()).await;
                tokio::time::sleep(Duration::from_secs(6 * 60 * 60)).await;
            }
        });
    }

    // Threat feeds (E2). Load whatever is in NETSCOPE_THREAT_DIR (default
    // ./threatfeeds) — fetched either in-app from the System panel (G3.2) or via
    // scripts/download-threatfeeds.*; absent → empty, so the feature is simply
    // off until the user opts in.
    let initial_threats = Arc::new(ThreatDb::load_dir(setup::threat_dir()).unwrap_or_default());
    if !initial_threats.is_empty() {
        tracing::info!(
            entries = initial_threats.len(),
            feeds = initial_threats.sources().len(),
            "loaded threat feeds"
        );
    }
    let threats = Arc::new(std::sync::RwLock::new(initial_threats));

    let app = Router::new()
        .route("/ws", get(ws_handler))
        // Control plane (C2): pairing/token lifecycle over HTTP, deliberately kept
        // out of the streaming wire protocol (which stays a pure data plane).
        .route(
            "/pair/code",
            get(pair_code_handler).post(rotate_code_handler),
        )
        .route("/pair", post(pair_handler))
        .route("/auth/revoke", post(revoke_handler))
        // Self-update control plane: status is read-only; apply is loopback-only.
        .route("/update/status", get(update_status_handler))
        .route("/update/check", post(update_check_handler))
        .route("/update/apply", post(update_apply_handler))
        // Narrator (D2): list AI providers and explain the current session. Both
        // loopback-only — explain may send the scrubbed summary to a cloud API.
        .route("/narrator/providers", get(narrator_providers_handler))
        .route("/narrator/explain", post(narrator_explain_handler))
        // Warden: preview a block policy (E1) and generate a native firewall
        // ruleset from it (E3). Loopback-only and read-only — the agent never
        // applies anything; the user reviews and runs the generated rules.
        .route("/warden/preview", post(warden_preview_handler))
        .route("/warden/generate", post(warden_generate_handler))
        // Threat feeds (E2): which loaded blocklists, and which current flows hit them.
        .route("/warden/threats", get(warden_threats_handler))
        // Enforcement (E4): apply/list/clear via the privileged helper, if one is
        // configured. Loopback-only; absent an enforcer, /apply explains it's
        // generate-only. The helper re-checks the never-block floor itself.
        .route("/warden/apply", post(warden_apply_handler))
        .route("/warden/blocked", get(warden_blocked_handler))
        .route("/warden/unblock", post(warden_unblock_handler))
        // Real-time proof (not just the enforcer's belief) that blocking is
        // actually happening: re-reads the OS firewall itself and flags drift.
        .route("/warden/verify", get(warden_verify_handler))
        // Setup (G3.2): enable geo/ASN and threat feeds from inside the UI — the
        // agent downloads with the user's own key and hot-reloads, no restart.
        // Loopback-only: setup changes what the agent does, so it's host-only.
        .route("/setup/status", get(setup_status_handler))
        .route("/setup/geoip", post(setup_geoip_handler))
        .route("/setup/threats", post(setup_threats_handler))
        .fallback(static_handler)
        // CORS for the desktop shell (tauri.localhost) and loopback dev origins —
        // local origins only; see `cors_local`.
        .layer(axum::middleware::from_fn(cors_local))
        .with_state(AppState {
            rx,
            auth: Arc::clone(&auth),
            update: Arc::clone(&updater),
            threats: Arc::clone(&threats),
            enricher: Arc::clone(&enricher),
            pcap_status: pcap_status.into(),
        });

    // Default loopback (NETSCOPE_BIND overrides — set it to your tailnet IP for
    // the C3 remote path). Binding beyond loopback is the moment the feed could
    // leave the host, so it is opt-in and announced loudly; the C2 token gate on
    // non-loopback peers is what makes it safe.
    let bind = std::env::var("NETSCOPE_BIND").unwrap_or_else(|_| BIND_ADDR.to_string());
    let listener = TcpListener::bind(&bind).await?;
    let local = listener.local_addr()?;
    let code = auth.current_code();
    tracing::info!(
        addr = %local,
        version = PROTOCOL_VERSION,
        build = build.id,
        sha = %build.sha,
        ui = cfg!(feature = "bundled-ui"),
        "netscope-agent listening"
    );
    if !local.ip().is_loopback() {
        tracing::warn!(
            addr = %local,
            "binding beyond loopback — remote peers must present a pairing token (C2); \
             ensure this is a private interface (e.g. a Tailscale IP), not a public one"
        );
    }
    println!(
        "\n  Pair a remote device — code  {}  (valid {}s, single-use)\n",
        code.code, code.expires_in_secs
    );
    #[cfg(feature = "bundled-ui")]
    {
        // The product build: announce the UI it serves and open it. Uses the
        // resolved bind so a NETSCOPE_BIND override (C3) prints the right URL.
        let url = format!("http://{local}");
        println!("\n  NETSCOPE is running — open  {url}  in your browser\n");
        // Only auto-open when serving locally; a tailnet bind is opened from the
        // remote device, not the host. The desktop shell (Tauri) sets
        // NETSCOPE_NO_OPEN — it *is* the window, so no browser should pop.
        if local.ip().is_loopback() && std::env::var_os("NETSCOPE_NO_OPEN").is_none() {
            open_browser(&url);
        }
    }

    serve(listener, app).await?;
    Ok(())
}

/// Accept loop with a **bounded handshake**. We drive hyper directly (rather than
/// `axum::serve`) for one reason: to set an HTTP header-read timeout. The auth and
/// origin gates in [`ws_handler`] only run *after* the request line + headers are
/// read, so without this bound a peer that connects and then stalls — sending
/// headers a byte at a time, or nothing at all — pins a connection open before any
/// gate can refuse it (a slowloris on the accept). Harmless while the agent was
/// loopback-only; the C3 remote path makes it reachable, so we close it here. The
/// timeout covers only the header phase — an upgraded WebSocket is never affected.
///
/// The peer `SocketAddr` is injected as a `ConnectInfo` request extension exactly
/// as axum's connect-info make-service would, so the C2 loopback-vs-remote
/// distinction keeps working.
async fn serve(listener: TcpListener, app: Router) -> Result<(), Box<dyn std::error::Error>> {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder;
    use tower::Service;

    /// Max time from connect to a fully-read request head. Generous for any honest
    /// client (headers arrive in one segment); fatal only to a staller.
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    };
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                // A transient accept error must not tear down the listener.
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
        };

        let app = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = hyper::service::service_fn(move |mut req| {
                // Mirror axum's connect-info make-service: hand handlers the peer.
                req.extensions_mut()
                    .insert(axum::extract::ConnectInfo(peer));
                app.clone().call(req)
            });
            let mut builder = Builder::new(TokioExecutor::new());
            // `header_read_timeout` needs a timer wired to the runtime to arm it.
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(HANDSHAKE_TIMEOUT);
            if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
                tracing::debug!(%peer, error = %e, "connection closed");
            }
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// WebSocket feed
// ---------------------------------------------------------------------------

/// Upgrade `/ws` to a WebSocket. Two gates run before the upgrade:
///
/// 1. **Origin** (CSWSH, landed in A2). The agent streams sensitive connection
///    metadata, and a localhost service is reachable from browser JS on *any*
///    site the user visits, so a browser `Origin` is allowed only if loopback;
///    a request with no `Origin` (native client) passes this gate.
/// 2. **Token** (C2). Loopback is the existing trust boundary — local native
///    already owns the machine — so a loopback peer connects token-free,
///    preserving the local default. A **remote** peer must present a valid
///    pairing token via `Sec-WebSocket-Protocol: auth.<token>` (the only header a
///    browser can set on the WS handshake; never a query string — PITFALLS C2).
async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    if let Some(origin) = headers.get("origin") {
        let host = headers.get("host").and_then(|h| h.to_str().ok());
        let allowed = origin
            .to_str()
            .map(|o| origin_allowed(o, host))
            .unwrap_or(false);
        if !allowed {
            tracing::warn!(?origin, "rejected non-local WebSocket origin");
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }

    if !peer.ip().is_loopback() {
        let authed = headers
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            .and_then(extract_auth_token)
            .is_some_and(|t| state.auth.validate(t));
        if !authed {
            tracing::warn!(%peer, "rejected unauthenticated remote WebSocket");
            return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
        }
    }

    // Content-encoding negotiation (A5): a client offering `netscope.msgpack`
    // gets MessagePack (binary frames), otherwise JSON (text). We echo the chosen
    // subprotocol so the client knows which dialect to decode.
    let encoding = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(Encoding::negotiate)
        .unwrap_or(Encoding::Json);
    ws.protocols([encoding.subprotocol()])
        .on_upgrade(move |socket| serve_client(socket, state.rx, encoding))
}

/// Pull the bearer token out of a `Sec-WebSocket-Protocol` value — a
/// comma-separated list where the credential rides as `auth.<token>`.
fn extract_auth_token(header: &str) -> Option<&str> {
    header
        .split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("auth."))
        .filter(|t| !t.is_empty())
}

// ---------------------------------------------------------------------------
// Pairing + token control plane (C2)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct PairCodeResponse {
    code: String,
    expires_in_secs: u64,
}

#[derive(serde::Deserialize)]
struct PairRequest {
    code: String,
}

#[derive(serde::Serialize)]
struct PairResponse {
    token: String,
}

#[derive(serde::Serialize)]
struct RevokeResponse {
    revoked: usize,
}

/// `GET /pair/code` — loopback only. The pairing code is shown only on the agent
/// host (the trusted local UI displays it for the user to type into a remote
/// device), so a remote caller is refused rather than handed the secret.
async fn pair_code_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            "pairing code is shown on the agent host only",
        )
            .into_response();
    }
    let c = state.auth.current_code();
    Json(PairCodeResponse {
        code: c.code,
        expires_in_secs: c.expires_in_secs,
    })
    .into_response()
}

/// `POST /pair/code` — loopback only. Force a fresh code (the "show a new code"
/// control), invalidating any prior one.
async fn rotate_code_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            "pairing code is shown on the agent host only",
        )
            .into_response();
    }
    let c = state.auth.rotate_code();
    Json(PairCodeResponse {
        code: c.code,
        expires_in_secs: c.expires_in_secs,
    })
    .into_response()
}

/// `POST /pair` — exchange a pairing code for a token. Open to any peer because
/// the remote device redeems here (over TLS, via the C3 tunnel); the code itself
/// is the secret, and it is short-lived, single-use, and attempt-capped.
async fn pair_handler(State(state): State<AppState>, Json(req): Json<PairRequest>) -> Response {
    match state.auth.redeem(&req.code) {
        Some(token) => Json(PairResponse { token }).into_response(),
        None => (StatusCode::UNAUTHORIZED, "invalid or expired pairing code").into_response(),
    }
}

/// `POST /auth/revoke` — loopback only. The "de-authorize all devices" control;
/// drops every issued token so previously-paired devices must re-pair.
async fn revoke_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "revocation is a local control").into_response();
    }
    let revoked = state.auth.revoke_all();
    Json(RevokeResponse { revoked }).into_response()
}

// ---------------------------------------------------------------------------
// Self-update control plane
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct ApplyResponse {
    ok: bool,
    message: String,
}

/// `GET /update/status` — the build identity and whether a newer build is
/// available. Read-only and non-sensitive (version info), so unrestricted.
async fn update_status_handler(State(state): State<AppState>) -> Response {
    Json(state.update.status()).into_response()
}

/// `POST /update/check` — loopback only. Re-run the manifest check on demand (the
/// HUD's "check now") and return the fresh status, so the user can see the updater
/// work rather than waiting for the next background poll.
async fn update_check_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "updates check from the host only").into_response();
    }
    let updater = Arc::clone(&state.update);
    let _ = tokio::task::spawn_blocking(move || updater.check()).await;
    Json(state.update.status()).into_response()
}

// ---------------------------------------------------------------------------
// Narrator control plane (D2)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct ProvidersResponse {
    providers: Vec<netscope_narrator::ProviderStatus>,
}

#[derive(serde::Deserialize)]
struct ExplainRequest {
    provider: Provider,
    /// Optional model override — for Ollama, one of the locally-installed models
    /// the provider menu detected. Ignored by the offline and Claude providers.
    #[serde(default)]
    model: Option<String>,
    /// Optional flow id: when set, explain just that one selected endpoint (D2,
    /// per-node) instead of the whole session.
    #[serde(default)]
    flow_id: Option<String>,
}

#[derive(serde::Serialize)]
struct ExplainError {
    ok: bool,
    error: String,
}

// ---------------------------------------------------------------------------
// Warden control plane (E1 — preview only)
// ---------------------------------------------------------------------------

/// `POST /warden/preview` — loopback only. Given a block policy, return what it
/// *would* block among the current flows. Pure preview — nothing is enforced (the
/// firewall generator and enforcer are E3/E4), so this is safe and unprivileged.
async fn warden_preview_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(policy): Json<Policy>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "the warden is a local control").into_response();
    }
    let threats = state.threats();
    let plan = dry_run_with(&policy, &state.rx.borrow().flows, Some(&threats));
    Json(plan).into_response()
}

#[derive(serde::Deserialize)]
struct GenerateRequest {
    policy: Policy,
    /// Firewall backend; defaults to the agent host's OS when omitted.
    #[serde(default)]
    backend: Option<Firewall>,
}

/// `POST /warden/generate` — loopback only. Run the policy over the current flows
/// (E1) and render a native, namespaced, reversible firewall ruleset (E3) the user
/// applies by hand. Still no enforcement here — only generation.
async fn warden_generate_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<GenerateRequest>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "the warden is a local control").into_response();
    }
    let threats = state.threats();
    let plan = dry_run_with(&req.policy, &state.rx.borrow().flows, Some(&threats));
    let backend = req.backend.unwrap_or_else(default_backend);
    Json(generate(backend, &plan.targets)).into_response()
}

#[derive(serde::Serialize)]
struct ThreatsResponse {
    /// Number of distinct indicators loaded across all feeds.
    indicators: usize,
    /// Human-readable list of the feeds that were loaded (filenames).
    sources: Vec<String>,
    /// IPs among the *current* flows that match a loaded threat indicator.
    matches: Vec<String>,
}

/// `GET /warden/threats` — loopback only. Report the loaded threat feeds and which
/// of the current flows match a known-bad indicator. Pure read — no enforcement.
async fn warden_threats_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "the warden is a local control").into_response();
    }
    let threats = state.threats();
    let matches = threat_targets(&threats, &state.rx.borrow().flows);
    Json(ThreatsResponse {
        indicators: threats.len(),
        sources: threats.sources().to_vec(),
        matches,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Setup control plane (GROWTH G3.2) — in-app enablement
// ---------------------------------------------------------------------------
// The zero-knowledge path: what previously required a terminal (running the
// downloader scripts, restarting the agent) is a paste + click in the System
// panel. All loopback-only — setup changes agent behaviour, so it's host-only,
// like every other control here. Downloads run on `spawn_blocking` (ureq is a
// blocking client, same pattern as the updater).

#[derive(serde::Serialize)]
struct SetupStatusResponse {
    /// Whether geo/ASN enrichment is live right now (dbs loaded).
    geo_enabled: bool,
    geoip_dir: String,
    threat_dir: String,
    threat_indicators: usize,
    /// A MaxMind key is known (env or config) — a geoip refresh won't ask again.
    has_maxmind_key: bool,
    config_path: String,
    /// Packet-capture state (G5): "active (dev)", "off — …", "unavailable: …",
    /// or "not built — …". Decided at startup.
    packet_capture: String,
}

/// `GET /setup/status` — loopback only. What's enabled and where data lives, so
/// the System panel can offer the right action instead of a shell command.
async fn setup_status_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "setup is a local control").into_response();
    }
    Json(SetupStatusResponse {
        geo_enabled: state.enricher.geo_enabled(),
        geoip_dir: enrich::geoip_dir().display().to_string(),
        threat_dir: setup::threat_dir().display().to_string(),
        threat_indicators: state.threats().len(),
        has_maxmind_key: config::Config::load().maxmind_key().is_some(),
        config_path: config::config_path().display().to_string(),
        packet_capture: state.pcap_status.to_string(),
    })
    .into_response()
}

#[derive(serde::Deserialize)]
struct GeoipSetupRequest {
    /// The user's own free MaxMind key. Omitted/empty → reuse the stored one
    /// (env or config), so "refresh databases" never asks twice.
    #[serde(default)]
    license_key: Option<String>,
}

#[derive(serde::Serialize)]
struct GeoipSetupResponse {
    ok: bool,
    geo_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `POST /setup/geoip` — loopback only. Download both GeoLite2 editions with the
/// user's key, hot-reload the enricher, and persist the key to the config file
/// (G3.1) so future refreshes are one click. The key goes only to MaxMind.
async fn setup_geoip_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<GeoipSetupRequest>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "setup is a local control").into_response();
    }
    let provided = req
        .license_key
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());
    let key = provided
        .clone()
        .or_else(|| config::Config::load().maxmind_key());
    let Some(key) = key else {
        return (
            StatusCode::BAD_REQUEST,
            Json(GeoipSetupResponse {
                ok: false,
                geo_enabled: state.enricher.geo_enabled(),
                error: Some(
                    "a MaxMind license key is required — free at \
                     maxmind.com/en/geolite2/signup"
                        .into(),
                ),
            }),
        )
            .into_response();
    };

    let dest = enrich::geoip_dir();
    let dl = tokio::task::spawn_blocking(move || setup::download_geoip(&key, &dest)).await;
    let result = match dl {
        Ok(r) => r,
        Err(e) => Err(format!("download task failed: {e}")),
    };

    match result {
        Ok(()) => {
            let enabled = state.enricher.reload_geo();
            // Persist a key the user typed (never re-persist an env-provided
            // one) so the next refresh is one click. Best-effort: a read-only
            // config dir shouldn't fail the enablement that just worked.
            if let Some(k) = provided {
                let mut cfg = config::Config::load();
                cfg.maxmind_license_key = Some(k);
                if let Err(e) = cfg.save() {
                    tracing::warn!(error = %e, "couldn't persist MaxMind key to config");
                }
            }
            Json(GeoipSetupResponse {
                ok: enabled,
                geo_enabled: enabled,
                error: (!enabled).then(|| "downloaded, but the databases failed to load".into()),
            })
            .into_response()
        }
        Err(error) => Json(GeoipSetupResponse {
            ok: false,
            geo_enabled: state.enricher.geo_enabled(),
            error: Some(error),
        })
        .into_response(),
    }
}

#[derive(serde::Serialize)]
struct ThreatsSetupResponse {
    ok: bool,
    indicators: usize,
    sources: Vec<String>,
    fetched: Vec<String>,
    skipped: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `POST /setup/threats` — loopback only. Fetch the free feeds and hot-swap the
/// loaded `ThreatDb`, so "known-bad lists" lights up without a restart. Partial
/// success is success (a feed being down shouldn't zero the intel).
async fn setup_threats_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "setup is a local control").into_response();
    }
    let dest = setup::threat_dir();
    let dl = {
        let dest = dest.clone();
        tokio::task::spawn_blocking(move || setup::download_threatfeeds(&dest)).await
    };
    let result = match dl {
        Ok(r) => r,
        Err(e) => Err(format!("download task failed: {e}")),
    };

    match result {
        Ok(fetch) => {
            let db = Arc::new(ThreatDb::load_dir(&dest).unwrap_or_default());
            tracing::info!(
                entries = db.len(),
                feeds = db.sources().len(),
                "threat feeds loaded (in-app setup)"
            );
            let response = ThreatsSetupResponse {
                ok: !db.is_empty(),
                indicators: db.len(),
                sources: db.sources().to_vec(),
                fetched: fetch.fetched,
                skipped: fetch.skipped,
                error: None,
            };
            *state.threats.write().unwrap() = db;
            Json(response).into_response()
        }
        Err(error) => {
            let current = state.threats();
            Json(ThreatsSetupResponse {
                ok: false,
                indicators: current.len(),
                sources: current.sources().to_vec(),
                fetched: Vec::new(),
                skipped: Vec::new(),
                error: Some(error),
            })
            .into_response()
        }
    }
}

// --- Enforcement (E4) -------------------------------------------------------
// The agent holds no privilege; it asks the configured enforcer helper and the
// helper does the work (and re-checks the never-block floor). These run on a
// blocking task because the socket round-trip is synchronous.

/// What to ask the enforcer to do.
enum EnforceAction {
    Apply {
        add: Vec<std::net::IpAddr>,
        remove: Vec<std::net::IpAddr>,
    },
    List,
    Clear,
    /// Live proof, not the enforcer's in-memory belief (see `Enforcer::verify`).
    Verify,
}

/// The result of trying, distinguishing "no enforcer configured" (the common,
/// generate-only case) from a real failure.
enum EnforceOutcome {
    Done(netscope_enforcer::proto::Response),
    Failed(String),
    NotConfigured,
}

#[cfg(any(unix, windows))]
fn enforce_blocking(action: EnforceAction) -> EnforceOutcome {
    let Some(enforcer) = enforce::Enforcer::from_env() else {
        return EnforceOutcome::NotConfigured;
    };
    let result = match action {
        EnforceAction::Apply { add, remove } => enforcer.apply(add, remove),
        EnforceAction::List => enforcer.list(),
        EnforceAction::Clear => enforcer.clear(),
        EnforceAction::Verify => enforcer.verify(),
    };
    match result {
        Ok(resp) => EnforceOutcome::Done(resp),
        Err(e) => EnforceOutcome::Failed(e),
    }
}

#[cfg(not(any(unix, windows)))]
fn enforce_blocking(_action: EnforceAction) -> EnforceOutcome {
    EnforceOutcome::NotConfigured
}

fn enforce_response(outcome: EnforceOutcome) -> Response {
    match outcome {
        EnforceOutcome::Done(resp) => Json(resp).into_response(),
        EnforceOutcome::Failed(error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "ok": false, "error": error })),
        )
            .into_response(),
        EnforceOutcome::NotConfigured => {
            let hint = if cfg!(windows) {
                "enforcement not configured — install the netscope-enforcer service \
                 (packaging/install-enforcer.ps1, elevated). NETSCOPE stays generate-only (E3)."
            } else {
                "enforcement not configured — run netscope-enforcer and set \
                 NETSCOPE_ENFORCER_SOCKET (Linux). NETSCOPE stays generate-only (E3)."
            };
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "ok": false, "error": hint })),
            )
                .into_response()
        }
    }
}

/// `POST /warden/apply` — loopback only. Compute the policy's block targets (E1/E2)
/// and ask the enforcer to apply them. The enforcer re-validates and refuses any
/// protected address itself.
async fn warden_apply_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(policy): Json<Policy>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "the warden is a local control").into_response();
    }
    let threats = state.threats();
    let plan = dry_run_with(&policy, &state.rx.borrow().flows, Some(&threats));
    let add: Vec<std::net::IpAddr> = plan.targets.iter().filter_map(|s| s.parse().ok()).collect();
    let outcome = tokio::task::spawn_blocking(move || {
        enforce_blocking(EnforceAction::Apply {
            add,
            remove: Vec::new(),
        })
    })
    .await
    .unwrap_or(EnforceOutcome::Failed("enforce task failed".into()));
    enforce_response(outcome)
}

/// `GET /warden/blocked` — loopback only. The addresses the enforcer currently blocks.
async fn warden_blocked_handler(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "the warden is a local control").into_response();
    }
    let outcome = tokio::task::spawn_blocking(|| enforce_blocking(EnforceAction::List))
        .await
        .unwrap_or(EnforceOutcome::Failed("enforce task failed".into()));
    enforce_response(outcome)
}

/// `GET /warden/verify` — loopback only. Asks the enforcer to re-read the *actual*
/// OS firewall state (not its in-memory mirror) and compare it to what it expects
/// to be there — the "is the Warden really operating correctly, right now" check.
/// Same NotConfigured(503)/Failed(502) shape as `/warden/blocked`, so the UI can
/// tell "not installed" apart from "installed but not responding/erroring".
async fn warden_verify_handler(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "the warden is a local control").into_response();
    }
    let outcome = tokio::task::spawn_blocking(|| enforce_blocking(EnforceAction::Verify))
        .await
        .unwrap_or(EnforceOutcome::Failed("enforce task failed".into()));
    enforce_response(outcome)
}

#[derive(serde::Deserialize, Default)]
struct UnblockRequest {
    /// Specific addresses to unblock; empty (or `{}`) means "unblock everything".
    #[serde(default)]
    ips: Vec<String>,
}

/// `POST /warden/unblock` — loopback only. With `{ "ips": [...] }`, removes just
/// those blocks (the per-row unblock); with `{}`, clears every active block.
async fn warden_unblock_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<UnblockRequest>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "the warden is a local control").into_response();
    }
    let action = if req.ips.is_empty() {
        EnforceAction::Clear
    } else {
        let remove: Vec<std::net::IpAddr> = req.ips.iter().filter_map(|s| s.parse().ok()).collect();
        EnforceAction::Apply {
            add: Vec::new(),
            remove,
        }
    };
    let outcome = tokio::task::spawn_blocking(move || enforce_blocking(action))
        .await
        .unwrap_or(EnforceOutcome::Failed("enforce task failed".into()));
    enforce_response(outcome)
}

/// `GET /narrator/providers` — loopback only. The AI providers for the menu and
/// whether each is ready (Ollama reachability is probed, so this blocks briefly).
async fn narrator_providers_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(_state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "narrator is a local control").into_response();
    }
    let providers = tokio::task::spawn_blocking(|| provider_statuses(&ProviderConfig::from_env()))
        .await
        .unwrap_or_default();
    Json(ProvidersResponse { providers }).into_response()
}

/// `POST /narrator/explain` — loopback only. Scrub the current world (D1) and run
/// the chosen provider on it (D2). Loopback-gated because the Claude provider
/// sends the scrubbed summary off the machine.
async fn narrator_explain_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<ExplainRequest>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "narrator is a local control").into_response();
    }
    // Scrub the current flows (D1) — the only thing any provider ever sees. A
    // `flow_id` narrows that to the single selected endpoint (per-node explain);
    // the scrub boundary is identical, just over one flow. The watch::Ref is dropped
    // at the end of this block, before any `.await`.
    let per_node = req.flow_id.is_some();
    let session = {
        let world = state.rx.borrow();
        match req.flow_id.as_deref() {
            Some(id) => match world.flows.iter().find(|f| f.id == id) {
                Some(flow) => scrub_session(std::slice::from_ref(flow)),
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(ExplainError {
                            ok: false,
                            error: "that connection has closed".into(),
                        }),
                    )
                        .into_response();
                }
            },
            None => scrub_session(&world.flows),
        }
    };
    let mut cfg = ProviderConfig::from_env();
    // Honor a user-picked local model (one Ollama detected); ignored otherwise.
    if let Some(model) = req.model.filter(|m| !m.trim().is_empty()) {
        cfg.ollama_model = model;
    }
    let result = tokio::task::spawn_blocking(move || {
        if per_node {
            explain_node(req.provider, &cfg, &session)
        } else {
            explain(req.provider, &cfg, &session)
        }
    })
    .await;
    match result {
        Ok(Ok(explanation)) => Json(explanation).into_response(),
        Ok(Err(error)) => (
            StatusCode::BAD_GATEWAY,
            Json(ExplainError { ok: false, error }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ExplainError {
                ok: false,
                error: format!("explain task failed: {e}"),
            }),
        )
            .into_response(),
    }
}

/// `POST /update/apply` — loopback only. Download the pending build, verify its
/// hash, and replace this binary in place; the user then restarts. A remote paired
/// client must never be able to push a binary onto your machine, hence loopback.
async fn update_apply_handler(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "updates apply from the host only").into_response();
    }
    let updater = Arc::clone(&state.update);
    let result = tokio::task::spawn_blocking(move || updater.apply()).await;
    match result {
        Ok(Ok(message)) => Json(ApplyResponse { ok: true, message }).into_response(),
        Ok(Err(message)) => {
            tracing::warn!(error = %message, "self-update failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApplyResponse { ok: false, message }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApplyResponse {
                ok: false,
                message: format!("update task failed: {e}"),
            }),
        )
            .into_response(),
    }
}

/// One client session: `hello` → `snapshot` → (`delta` per capture generation +
/// `heartbeat` per tick) until the socket drops. Each session owns its own
/// monotonic `seq`, contiguous across *every* frame — so the client can detect a
/// gap by seq alone. The socket is split so the session can also *read*: a client
/// `resync` request (C4) is answered with a fresh snapshot.
async fn serve_client(
    socket: WebSocket,
    mut rx: watch::Receiver<Arc<CaptureUpdate>>,
    encoding: Encoding,
) {
    use futures_util::StreamExt;

    let (mut tx, mut rx_ws) = socket.split();
    let mut seq: u64 = 0;
    let started = Instant::now();

    // hello{version} — the first frame, carrying the protocol version.
    let hello = WireMessage::Hello(Hello {
        version: PROTOCOL_VERSION,
        agent: AgentInfo {
            name: "netscope-agent".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            platform: std::env::consts::OS.into(),
        },
    });
    if send(&mut tx, &hello, &mut seq, encoding).await.is_err() {
        return;
    }

    // snapshot — the current world wholesale, the baseline deltas build on.
    let mut last_gen = {
        let update = rx.borrow_and_update().clone();
        let snap = WireMessage::Snapshot(Snapshot {
            seq,
            flows: update.flows.clone(),
        });
        if send(&mut tx, &snap, &mut seq, encoding).await.is_err() {
            return;
        }
        update.generation
    };

    let mut ticker = interval(HEARTBEAT_INTERVAL);
    ticker.tick().await; // the first tick fires immediately; skip it
    let mut tick: u64 = 0;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                tick += 1;
                let beat = WireMessage::Heartbeat(Heartbeat {
                    seq,
                    tick,
                    uptime_ms: started.elapsed().as_millis() as u64,
                });
                if send(&mut tx, &beat, &mut seq, encoding).await.is_err() {
                    break;
                }
            }
            changed = rx.changed() => {
                if changed.is_err() {
                    break; // capture pipeline ended
                }
                let update = rx.borrow_and_update().clone();
                let msg = if update.generation == last_gen + 1 {
                    WireMessage::Delta(delta_from_parts(seq, &update.delta))
                } else {
                    // Coalesced past a generation — re-snapshot rather than apply a
                    // non-consecutive delta (the C4 gap-then-resync discipline).
                    WireMessage::Snapshot(Snapshot { seq, flows: update.flows.clone() })
                };
                last_gen = update.generation;
                if send(&mut tx, &msg, &mut seq, encoding).await.is_err() {
                    break;
                }
            }
            incoming = rx_ws.next() => {
                // A `resync` is the only client→agent message; answer with the
                // current world wholesale, which rebases the client's mirror and
                // closes its detected gap (C4). Decoded per frame type (text=JSON,
                // binary=MessagePack); unknown / malformed messages are ignored.
                let req = match incoming {
                    Some(Ok(Message::Text(text))) => decode_client(&text),
                    Some(Ok(Message::Binary(bytes))) => decode_client_bin(&bytes),
                    // Close frame, stream end, or a transport error end the session.
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    // Ping/Pong: nothing to do (axum answers pings itself).
                    Some(Ok(_)) => None,
                };
                if let Some(req) = req {
                    last_gen = resync(&mut tx, &mut rx, &mut seq, encoding, req).await;
                    if last_gen == GEN_SESSION_ENDED { break; }
                }
            }
        }
    }
}

/// Sentinel `last_gen` meaning "send failed — end the session".
const GEN_SESSION_ENDED: u64 = u64::MAX;

/// Answer a client `resync` with the current world wholesale; returns the new
/// `last_gen`, or [`GEN_SESSION_ENDED`] if the send failed.
async fn resync(
    tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    rx: &mut watch::Receiver<Arc<CaptureUpdate>>,
    seq: &mut u64,
    encoding: Encoding,
    req: ResyncRequest,
) -> u64 {
    let update = rx.borrow_and_update().clone();
    tracing::debug!(client_last_seq = req.last_seq, "client-driven resync");
    let snap = WireMessage::Snapshot(Snapshot {
        seq: *seq,
        flows: update.flows.clone(),
    });
    if send(tx, &snap, seq, encoding).await.is_err() {
        GEN_SESSION_ENDED
    } else {
        update.generation
    }
}

fn decode_client(text: &str) -> Option<ResyncRequest> {
    match netscope_protocol::decode_json::<ClientMessage>(text) {
        Ok(ClientMessage::Resync(req)) => Some(req),
        Err(_) => None,
    }
}

fn decode_client_bin(bytes: &[u8]) -> Option<ResyncRequest> {
    match netscope_protocol::decode_msgpack::<ClientMessage>(bytes) {
        Ok(ClientMessage::Resync(req)) => Some(req),
        Err(_) => None,
    }
}

/// Serialize and send one frame in the session's negotiated [`Encoding`],
/// advancing `seq`. A closed socket surfaces here as a send error and ends the
/// session.
async fn send(
    tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg: &WireMessage,
    seq: &mut u64,
    encoding: Encoding,
) -> Result<(), ()> {
    use futures_util::SinkExt;
    let frame = match encoding.encode(msg).map_err(|_| ())? {
        Frame::Text(t) => Message::Text(t),
        Frame::Binary(b) => Message::Binary(b),
    };
    tx.send(frame).await.map_err(|_| ())?;
    *seq += 1;
    Ok(())
}

/// Stamp a [`DeltaParts`] from the capture loop with this session's `seq`.
fn delta_from_parts(seq: u64, parts: &DeltaParts) -> Delta {
    Delta {
        seq,
        adds: parts.adds.clone(),
        updates: parts.updates.clone(),
        removes: parts.removes.clone(),
    }
}

/// Decide whether a browser `Origin` may open the feed, given the request's
/// `Host`. Two allow rules, both narrow:
///
///   - **same-origin** — the page was served *by this agent* (the `Origin`
///     authority equals the `Host`). This is the C3 path: over the tailnet the
///     agent serves its own UI, so the legitimate page's origin is the tailnet
///     address, not loopback — the A2 loopback-only rule would wrongly refuse it.
///   - **loopback** — any loopback `Origin` host, covering local dev where the
///     Vite server (`:5173`) talks cross-origin to the agent (`:8787`), both
///     on-machine.
///
/// A hostile third-party page is neither same-origin nor loopback, so the CSWSH
/// vector A2 closed stays closed. (Token auth still gates non-loopback *peers*
/// regardless — this is the browser-vector layer.)
fn origin_allowed(origin: &str, host: Option<&str>) -> bool {
    let authority = origin.split_once("://").map_or(origin, |(_, r)| r);
    if let Some(h) = host {
        if authority.eq_ignore_ascii_case(h) {
            return true;
        }
    }
    origin_is_local(origin)
}

/// True when an `Origin` header names a loopback host (any scheme/port). Handles
/// bracketed IPv6 literals (`http://[::1]:5173`) and the reserved `.localhost` TLD
/// (RFC 6761), which is how a native WebView shell identifies itself — Tauri serves
/// the bundled UI from `tauri.localhost`, so the desktop app's `Origin` is
/// `http(s)://tauri.localhost`, not a numeric loopback address.
///
/// Allowing `*.localhost` is safe: the TLD is reserved for loopback and cannot be a
/// real public site, and `Origin` is a forbidden header that page JavaScript cannot
/// set — so only the genuine on-machine WebView (or a loopback page) ever presents
/// one. It is strictly a suffix on the *host*, so `localhost.evil.com` stays refused.
fn origin_is_local(origin: &str) -> bool {
    let rest = origin.split_once("://").map_or(origin, |(_, r)| r);
    let host = if let Some(v6) = rest.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        rest.split(['/', ':']).next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1") || host.ends_with(".localhost")
}

/// CORS for the loopback HTTP control plane. The native desktop shell loads the UI
/// from `tauri.localhost` and `fetch`es the agent at `127.0.0.1:8787` — a
/// *cross-origin* request the WebView blocks (and preflights) unless the agent opts
/// in. We echo `Access-Control-Allow-Origin` **only** for origins that pass
/// [`origin_is_local`] (the same loopback / `.localhost` set the WebSocket handshake
/// trusts), and answer the preflight for them. A public page's origin is never
/// echoed, so it still cannot read a response; the handlers remain loopback-gated by
/// peer IP regardless, so this widens nothing a remote attacker can reach.
async fn cors_local(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let origin = req
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| origin_is_local(o))
        .map(str::to_string);

    if req.method() == axum::http::Method::OPTIONS {
        // Preflight — answer locally-originated OPTIONS without touching a handler.
        let mut resp = StatusCode::NO_CONTENT.into_response();
        if let Some(o) = &origin {
            put_cors_headers(resp.headers_mut(), o, true);
        }
        return resp;
    }

    let mut resp = next.run(req).await;
    if let Some(o) = &origin {
        put_cors_headers(resp.headers_mut(), o, false);
    }
    resp
}

fn put_cors_headers(headers: &mut axum::http::HeaderMap, origin: &str, preflight: bool) {
    use axum::http::header;
    if let Ok(v) = header::HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    headers.insert(header::VARY, header::HeaderValue::from_static("Origin"));
    if preflight {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            header::HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            header::HeaderValue::from_static("content-type"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            header::HeaderValue::from_static("600"),
        );
    }
}

// ---------------------------------------------------------------------------
// Static UI (bundled-ui build only)
// ---------------------------------------------------------------------------

#[cfg(feature = "bundled-ui")]
#[derive(rust_embed::Embed)]
#[folder = "../../../frontend/dist"]
struct Assets;

/// Serve the embedded frontend. Unknown paths fall back to `index.html` (the SPA
/// entry), so a deep link still loads the app.
#[cfg(feature = "bundled-ui")]
async fn static_handler(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    let file = Assets::get(path).or_else(|| Assets::get("index.html"));
    match file {
        Some(content) => {
            let mime = content.metadata.mimetype();
            ([(axum::http::header::CONTENT_TYPE, mime)], content.data).into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Best-effort browser launch for the product build — no dependency, just the
/// platform's "open this URL" command. Failure is ignored; the URL is also printed.
#[cfg(feature = "bundled-ui")]
fn open_browser(url: &str) {
    let _ = url;
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

/// Without the bundled UI, the root explains where the dev UI lives.
#[cfg(not(feature = "bundled-ui"))]
async fn static_handler() -> Response {
    (
        axum::http::StatusCode::OK,
        "netscope-agent: WebSocket feed at /ws. The UI is not bundled in this build \
         — run the Vite dev server (frontend/), or build with --features bundled-ui.",
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Capture pipeline (producer thread + coordinator task)
// ---------------------------------------------------------------------------

/// Run the blocking capture engine on a dedicated thread (the ring's single
/// producer), polling every [`POLL_INTERVAL`] and pushing each non-empty
/// [`CaptureUpdate`] into the ring, then waking the coordinator. A poll error is
/// logged and the previous world is held — a transient read hiccup must not tear
/// down the stream.
fn spawn_capture_loop(
    ring: Arc<dyn Ring<CaptureUpdate>>,
    notify: Arc<Notify>,
    enricher: Arc<dyn Enrich>,
    observer: Option<Box<dyn capture::packet::PacketObserve>>,
) {
    std::thread::Builder::new()
        .name("netscope-capture".into())
        .spawn(move || {
            let mut engine = match CaptureEngine::new(enricher) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error = %e, "capture engine failed to start");
                    return;
                }
            };
            if let Some(obs) = observer {
                engine.set_observer(obs);
            }
            tracing::info!(
                interval_ms = POLL_INTERVAL.as_millis(),
                ring_capacity = ring.capacity(),
                "capture loop started"
            );
            loop {
                match engine.poll() {
                    // Only an actual change is worth publishing — an idle poll
                    // returns an empty delta, which we drop so clients aren't woken
                    // (and the wire isn't filled) with no-op frames.
                    Ok(update) if !update.delta.is_empty() => {
                        tracing::debug!(
                            gen = update.generation,
                            adds = update.delta.adds.len(),
                            updates = update.delta.updates.len(),
                            removes = update.delta.removes.len(),
                            flows = update.flows.len(),
                            "capture delta"
                        );
                        // Never blocks: a full ring drops the newest update and
                        // counts it; the client heals the gap with a resync.
                        if ring.push(update).is_some() {
                            tracing::warn!(
                                dropped = ring.dropped(),
                                "capture ring full — dropped update (client will resync)"
                            );
                        }
                        notify.notify_one();
                    }
                    Ok(_) => {} // no change this poll
                    Err(e) => tracing::warn!(error = %e, "capture poll failed — holding world"),
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        })
        .expect("spawn capture thread");
}

/// The ring's single consumer. Drains every available [`CaptureUpdate`] and
/// republishes the latest on the watch channel for client fan-out, then parks on
/// the notify until the producer signals more. Draining fully before awaiting
/// (and `Notify`'s stored permit) means a push that races the await is not lost.
async fn run_coordinator(
    ring: Arc<dyn Ring<CaptureUpdate>>,
    notify: Arc<Notify>,
    tx: watch::Sender<Arc<CaptureUpdate>>,
    flow_history: Option<Arc<history::HistoryLog>>,
) {
    loop {
        while let Some(update) = ring.pop() {
            // Opt-in history (G4.1) records lifecycle events before publish —
            // adds/removes only, so the 4-updates/sec churn never hits disk.
            if let Some(h) = &flow_history {
                h.record(&update);
            }
            // watch keeps only the latest; a lagging client coalesces and, on a
            // generation gap, re-requests a snapshot (C4). Send errors mean every
            // client is gone for now — harmless, the next update overwrites.
            let _ = tx.send(Arc::new(update));
        }
        notify.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_auth_token, origin_allowed, origin_is_local};

    #[test]
    fn same_origin_is_allowed_even_when_not_loopback() {
        // The C3 tailnet path: the agent serves its own UI, so the page's origin
        // is the tailnet address and matches the request Host.
        assert!(origin_allowed(
            "http://100.101.102.103:8787",
            Some("100.101.102.103:8787"),
        ));
        assert!(origin_allowed(
            "https://my-box.ts.net",
            Some("my-box.ts.net")
        ));
    }

    #[test]
    fn cross_origin_remote_is_refused() {
        // A hostile page on the tailnet host is neither same-origin nor loopback.
        assert!(!origin_allowed(
            "https://evil.com",
            Some("100.101.102.103:8787"),
        ));
        // Origin host matches but port differs → not same-origin, not loopback.
        assert!(!origin_allowed(
            "http://100.101.102.103:9999",
            Some("100.101.102.103:8787"),
        ));
    }

    #[test]
    fn loopback_dev_origin_allowed_against_any_host() {
        // Vite dev (:5173) → agent (:8787): cross-origin but both loopback.
        assert!(origin_allowed(
            "http://localhost:5173",
            Some("127.0.0.1:8787")
        ));
        assert!(origin_allowed("http://127.0.0.1:5173", None));
    }

    #[test]
    fn extracts_bearer_token_from_subprotocol_list() {
        assert_eq!(extract_auth_token("netscope, auth.abc123"), Some("abc123"));
        assert_eq!(extract_auth_token("auth.xYz_-09"), Some("xYz_-09"));
        // Order-independent and whitespace-tolerant.
        assert_eq!(extract_auth_token("auth.tok ,netscope"), Some("tok"));
    }

    #[test]
    fn rejects_subprotocols_without_a_token() {
        assert_eq!(extract_auth_token("netscope"), None);
        assert_eq!(extract_auth_token("auth."), None); // empty token
        assert_eq!(extract_auth_token(""), None);
    }

    #[test]
    fn loopback_origins_are_allowed() {
        assert!(origin_is_local("http://localhost:5173"));
        assert!(origin_is_local("http://127.0.0.1:8787"));
        assert!(origin_is_local("https://localhost"));
        assert!(origin_is_local("http://[::1]:5173"));
    }

    #[test]
    fn tauri_desktop_origin_is_allowed() {
        // The native desktop shell (WebView2 / webkit2gtk) serves the bundled UI
        // from the reserved `.localhost` TLD and connects to the loopback agent, so
        // its Origin is tauri.localhost — equivalent in trust to a loopback page.
        assert!(origin_is_local("http://tauri.localhost"));
        assert!(origin_is_local("https://tauri.localhost"));
        assert!(origin_allowed(
            "http://tauri.localhost",
            Some("127.0.0.1:8787")
        ));
        assert!(origin_allowed("https://tauri.localhost", None));
    }

    #[test]
    fn remote_origins_are_rejected() {
        assert!(!origin_is_local("https://evil.com"));
        assert!(!origin_is_local("http://localhost.evil.com"));
        assert!(!origin_is_local("https://127.0.0.1.evil.com"));
        assert!(!origin_is_local("https://attacker.io:443"));
        assert!(!origin_is_local("null"));
        // The `.localhost` rule is a host *suffix*, so it can't be tricked by a
        // public name that merely contains "localhost".
        assert!(!origin_is_local("https://tauri.localhost.evil.com"));
        assert!(!origin_is_local("https://notlocalhost"));
    }
}
