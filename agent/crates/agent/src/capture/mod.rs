//! # capture — the connection-table polling loop (ROADMAP A2)
//!
//! Metadata-only v1: a background poll of the OS connection tables (~250 ms),
//! diffed snapshot-to-snapshot into add/update/remove [`Flow`] events. This is
//! the deliberate non-Npcap path — every later milestone works either way, and
//! A2 is where the fork landed (see ARCHITECTURE.md "Capture: metadata-only
//! polling, no packet capture"). The documented cost is that flows shorter than
//! one poll interval (a DNS lookup, a quick fetch) are missed; that limitation is
//! inherent to polling and is exactly what the Npcap upgrade removes.
//!
//! **The fork has since been taken — as an opt-in augmentation, not a
//! replacement (GROWTH G5).** With the `pcap` cargo feature and
//! `NETSCOPE_PCAP=1`, a packet observer ([`packet`], [`pcap`]) merges into each
//! poll: byte-true activity for table-confirmed flows, and synthesized
//! packet-only flows for conversations the table never showed. The default
//! build and default run remain exactly this polling path, so the measured
//! <1%-CPU claim keeps describing what ships.
//!
//! ## Shape
//!
//! The platform-specific work — reading the socket table and attributing each
//! socket to a process — lives behind [`ConnectionSource`], implemented per OS
//! ([`linux`] today; a Windows `GetExtendedTcpTable` source slots in behind the
//! same trait later). Everything above the trait — the snapshot diffing, the UDP
//! TTL lifecycle, classification — is platform-agnostic and unit-tested, so the
//! interesting engineering is verifiable without an OS in the loop.
//!
//! ## Pitfalls handled here (PITFALLS A2)
//!
//! - **PID reuse:** process identity is keyed on `(pid, start_time)`, never pid
//!   alone — resolved in the platform source so a recycled pid can't inherit a
//!   dead process's name.
//! - **UDP is stateless:** UDP "connections" are bound sockets, not
//!   conversations. They get their own TTL-based lifecycle ([`UDP_TTL`]) separate
//!   from TCP state transitions, so brief table flutter doesn't churn the view.
//! - **Access denied:** `process` is `Option` end to end; a socket owned by a
//!   process we can't introspect renders as a protected process, never a crash.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use netscope_protocol::{Category, Flow, L4Proto, ProcessInfo};

#[cfg(target_os = "linux")]
mod linux;

pub mod packet;
#[cfg(feature = "pcap")]
pub mod pcap;

#[cfg(windows)]
mod windows;

use packet::{FlowTraffic, PacketObserve};

/// How long a UDP flow survives in the view after it stops appearing in the
/// table. TCP flows are removed the moment they leave the table (their state
/// machine drives lifetime); UDP has no such state, so it expires on a timer.
const UDP_TTL: Duration = Duration::from_secs(5);

/// How long a packet-only flow (seen on the wire, never in the table — shorter
/// than a poll interval, or invisible to the platform's table like Windows UDP)
/// lingers after its last packet. Short by design: these are glimpses, not
/// table-confirmed conversations.
const PKT_TTL: Duration = Duration::from_secs(3);

/// TCP connection state, as far as A2 cares: we only distinguish "carrying
/// traffic" (Established) from everything else, to drive a coarse activity read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established,
    /// SYN_SENT / SYN_RECV / FIN_WAIT / TIME_WAIT / … — handshaking or tearing down.
    Other,
}

/// One row of the OS connection table, already attributed to its owning process
/// by the platform source. The 5-tuple plus protocol is the stable identity the
/// engine diffs on.
#[derive(Debug, Clone)]
pub struct RawConn {
    pub protocol: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// `Some` for TCP, `None` for UDP (which has no connection state).
    pub tcp_state: Option<TcpState>,
    /// `None` when the owning process can't be introspected (PITFALLS A2).
    pub process: Option<ProcessInfo>,
}

/// The platform-specific socket-table reader. The single OS-dependent seam: a
/// Linux procfs reader today, a Windows iphlpapi reader later, both producing the
/// same [`RawConn`] rows.
pub trait ConnectionSource: Send {
    /// Read the current connection table. A poll failure is surfaced rather than
    /// swallowed — the caller logs it and keeps the previous world intact.
    fn poll(&mut self) -> std::io::Result<Vec<RawConn>>;
}

/// The change between two consecutive captures, in protocol terms.
#[derive(Debug, Clone, Default)]
pub struct DeltaParts {
    pub adds: Vec<Flow>,
    pub updates: Vec<Flow>,
    pub removes: Vec<String>,
}

impl DeltaParts {
    pub fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.updates.is_empty() && self.removes.is_empty()
    }
}

/// One published capture: the full current world (the source of a `snapshot`)
/// plus the delta from the previous generation (the source of a `delta`). The
/// monotonic `generation` lets a client that coalesced several updates detect the
/// skip and re-snapshot instead of misapplying a non-consecutive delta — the same
/// gap-then-resync discipline C4 formalizes, here between capture and transport.
#[derive(Debug, Clone, Default)]
pub struct CaptureUpdate {
    pub generation: u64,
    pub flows: Vec<Flow>,
    pub delta: DeltaParts,
}

/// Build the connection source for the host platform. On a platform without a
/// reader yet, capture is inert (empty polls) rather than a build break — the
/// heartbeat spine still runs and the HUD shows zero flows.
pub fn new_source() -> std::io::Result<Box<dyn ConnectionSource>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::ProcfsSource::new()))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(windows::IpHelperSource::new()))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        tracing::warn!(
            os = std::env::consts::OS,
            "no connection-table reader for this platform yet — capture is inert"
        );
        Ok(Box::new(UnsupportedSource))
    }
}

/// Stand-in source for platforms without a reader yet: always empty.
#[cfg(not(any(target_os = "linux", windows)))]
struct UnsupportedSource;

#[cfg(not(any(target_os = "linux", windows)))]
impl ConnectionSource for UnsupportedSource {
    fn poll(&mut self) -> std::io::Result<Vec<RawConn>> {
        Ok(Vec::new())
    }
}

/// The A4 enrichment seam: fills a freshly-built [`Flow`] with reverse-DNS name,
/// geo/ASN, refined category, and security flags. Kept a trait so the capture
/// engine stays platform- and enrichment-agnostic (and tests use a no-op), and so
/// enrichment runs *before* the diff — when an async lookup later lands in the
/// enricher's cache, the next poll's enriched flow differs from the previous one
/// and the diff emits the update naturally (no separate re-publish path).
pub trait Enrich: Send + Sync {
    fn enrich(&self, flow: &mut Flow);
}

/// Enrichment that does nothing — used by the engine tests (the real binary always
/// wires the A4 [`Enricher`](crate::enrich::Enricher)).
#[cfg(test)]
pub struct NoEnrich;
#[cfg(test)]
impl Enrich for NoEnrich {
    fn enrich(&self, _flow: &mut Flow) {}
}

/// The platform-agnostic capture loop: polls a [`ConnectionSource`], turns rows
/// into [`Flow`]s, and diffs against the previous world to produce a
/// [`CaptureUpdate`]. All of the interesting lifecycle logic is here and tested.
pub struct CaptureEngine {
    source: Box<dyn ConnectionSource>,
    enricher: Arc<dyn Enrich>,
    /// Optional packet-level observation (G5, the pcap/Npcap path): byte-true
    /// activity and sub-poll-interval flows merged into each poll. `None` keeps
    /// the pure table-polling behaviour byte-for-byte.
    observer: Option<Box<dyn PacketObserve>>,
    /// Last emitted world, keyed by `Flow.id`.
    prev: HashMap<String, Flow>,
    /// Last time each UDP flow was seen in the table — drives TTL expiry.
    udp_seen: HashMap<String, Instant>,
    /// Packet-only flows (never table-confirmed) and their last packet time —
    /// drives PKT_TTL expiry. An id graduates out of here the moment the table
    /// sees it (the table then owns its lifecycle).
    pkt_seen: HashMap<String, Instant>,
    generation: u64,
}

impl CaptureEngine {
    pub fn new(enricher: Arc<dyn Enrich>) -> std::io::Result<Self> {
        Ok(Self::with_source(new_source()?, enricher))
    }

    pub fn with_source(source: Box<dyn ConnectionSource>, enricher: Arc<dyn Enrich>) -> Self {
        Self {
            source,
            enricher,
            observer: None,
            prev: HashMap::new(),
            udp_seen: HashMap::new(),
            pkt_seen: HashMap::new(),
            generation: 0,
        }
    }

    /// Attach packet-level observation (G5). Called once at startup when the
    /// pcap path is built in, enabled, and the device opened.
    pub fn set_observer(&mut self, observer: Box<dyn PacketObserve>) {
        self.observer = Some(observer);
    }

    /// Poll once and diff. Uses [`Instant::now`] for UDP TTL; the time-injecting
    /// variant [`poll_at`] backs the deterministic tests.
    pub fn poll(&mut self) -> std::io::Result<CaptureUpdate> {
        self.poll_at(Instant::now())
    }

    fn poll_at(&mut self, now: Instant) -> std::io::Result<CaptureUpdate> {
        let rows = self.source.poll()?;

        // Build this poll's world from the table rows.
        let mut current: HashMap<String, Flow> = HashMap::new();
        for row in rows {
            // Only outbound conversations: skip listeners and unconnected
            // sockets (a zero remote address). UDP sockets with no peer are
            // bound-but-idle and would otherwise read as phantom flows.
            if row.remote.ip().is_unspecified() || row.remote.port() == 0 {
                continue;
            }
            let mut flow = flow_from_raw(&row);
            // Enrich before diffing: a later async lookup landing in the enricher's
            // cache changes the next poll's flow, which the diff then emits.
            self.enricher.enrich(&mut flow);
            if row.protocol == L4Proto::Udp {
                self.udp_seen.insert(flow.id.clone(), now);
            }
            // De-dup: a 5-tuple should be unique, but keep the first deterministically.
            current.entry(flow.id.clone()).or_insert(flow);
        }

        // Carry forward UDP flows that have dropped out of the table but are
        // still within their TTL — UDP has no close to observe, so we expire on
        // a timer instead of trusting a single absent poll.
        for (id, flow) in &self.prev {
            if flow.protocol != L4Proto::Udp || current.contains_key(id) {
                continue;
            }
            let fresh = self
                .udp_seen
                .get(id)
                .is_some_and(|seen| now.duration_since(*seen) < UDP_TTL);
            if fresh {
                current.insert(id.clone(), flow.clone());
            }
        }

        // Merge packet observation (G5), when attached. Two effects:
        //  1. a table-confirmed flow that moved bytes this window gets a
        //     byte-true activity instead of the coarse state placeholder;
        //  2. a conversation the table never showed (shorter than the poll
        //     interval, or invisible to the platform table — Windows UDP) is
        //     synthesized so it appears in the organism at all.
        // Any id the table shows this poll graduates out of packet-only status
        // — from here the table owns its lifecycle (a table drop closes it;
        // PKT_TTL no longer applies).
        self.pkt_seen.retain(|id, _| !current.contains_key(id));
        let traffic = self
            .observer
            .as_mut()
            .map(|o| o.drain())
            .unwrap_or_default();
        for t in traffic {
            let id = traffic_id(&t);
            match current.get_mut(&id) {
                Some(flow) => {
                    let act = activity_from_bytes(t.bytes);
                    if act > flow.activity {
                        flow.activity = act;
                    }
                }
                None => {
                    let mut flow = flow_from_traffic(&t);
                    self.enricher.enrich(&mut flow);
                    self.pkt_seen.insert(id.clone(), now);
                    current.insert(id, flow);
                }
            }
        }
        // Packet-only flows linger briefly after their last packet (mirroring
        // the UDP TTL pattern), then expire.
        for (id, flow) in &self.prev {
            if current.contains_key(id) {
                continue;
            }
            let fresh = self
                .pkt_seen
                .get(id)
                .is_some_and(|seen| now.duration_since(*seen) < PKT_TTL);
            if fresh {
                current.insert(id.clone(), flow.clone());
            }
        }

        // Diff previous → current.
        let mut delta = DeltaParts::default();
        for (id, flow) in &current {
            match self.prev.get(id) {
                None => delta.adds.push(flow.clone()),
                Some(old) if old != flow => delta.updates.push(flow.clone()),
                Some(_) => {}
            }
        }
        for id in self.prev.keys() {
            if !current.contains_key(id) {
                delta.removes.push(id.clone());
                self.udp_seen.remove(id);
                self.pkt_seen.remove(id);
            }
        }

        self.prev = current.clone();
        // Generation advances only on real change, so the sequence of *published*
        // updates is gap-free: a client applying consecutive deltas never sees a
        // phantom jump on an idle poll. An unchanged poll returns the standing
        // generation with an empty delta, which the transport simply doesn't send.
        if !delta.is_empty() {
            self.generation += 1;
        }

        let mut flows: Vec<Flow> = current.into_values().collect();
        // Stable ordering so a snapshot is deterministic for tests and diffs.
        flows.sort_by(|a, b| a.id.cmp(&b.id));

        Ok(CaptureUpdate {
            generation: self.generation,
            flows,
            delta,
        })
    }
}

/// Turn one attributed table row into a [`Flow`]. Enrichment (reverse-DNS name,
/// ASN, geo, tracker/CDN classification) is A4 and deliberately absent here — the
/// fields it fills are left `None`/`Unknown`. The one classification A2 *does*
/// make is local-vs-remote, because RFC1918/loopback/link-local addresses must be
/// tagged before they could ever reach a geo lookup (PITFALLS A4).
fn flow_from_raw(row: &RawConn) -> Flow {
    let remote_ip = row.remote.ip();
    let port = row.remote.port();
    let category = if is_local(&remote_ip) {
        Category::Local
    } else {
        Category::Unknown
    };

    Flow {
        id: flow_id(row),
        name: remote_ip.to_string(), // reverse-DNS resolved in A4
        category,
        asn: None,      // A4
        location: None, // A4
        process: row.process.clone(),
        port,
        protocol: row.protocol,
        encrypted: is_encrypted_port(port),
        ip: remote_ip.to_string(),
        activity: activity_of(row),
        alive: true,
        flags: Vec::new(), // populated by the enricher (A4)
    }
}

/// Stable per-flow identity = protocol + full 5-tuple. Two polls of the same live
/// connection produce the same id, so it shows up as an `update`, not a
/// remove+add churn pair.
fn flow_id(row: &RawConn) -> String {
    let proto = match row.protocol {
        L4Proto::Tcp => "tcp",
        L4Proto::Udp => "udp",
    };
    format!("{proto}-{}-{}", row.local, row.remote)
}

/// Coarse activity stand-in. Real per-flow byte-rate needs packet capture or
/// netlink socket-stat counters; metadata polling can't see bytes, so A2 keys a
/// placeholder off connection state. Established TCP and live UDP read as active;
/// half-open/closing TCP reads as faint. When the packet observer (G5) is
/// attached, flows that actually moved bytes get [`activity_from_bytes`] instead.
fn activity_of(row: &RawConn) -> f32 {
    match (row.protocol, row.tcp_state) {
        (L4Proto::Tcp, Some(TcpState::Established)) => 0.6,
        (L4Proto::Tcp, _) => 0.15,
        (L4Proto::Udp, _) => 0.3,
    }
}

/// Byte-true activity (G5): log-scaled bytes-per-window so a keystroke-sized
/// trickle reads faint and a download saturates. ~1 KB/window ≈ 0.5,
/// ~2 MB/window (a fast transfer per 250 ms poll) pegs at 1.0.
fn activity_from_bytes(bytes: u64) -> f32 {
    let scale = (2_000_000f32).ln_1p();
    ((bytes as f32).ln_1p() / scale).clamp(0.15, 1.0)
}

/// The same identity scheme as [`flow_id`], from observed traffic — so a flow
/// glimpsed on the wire and later confirmed by the table is one node, not two.
fn traffic_id(t: &FlowTraffic) -> String {
    let proto = match t.protocol {
        L4Proto::Tcp => "tcp",
        L4Proto::Udp => "udp",
    };
    format!("{proto}-{}-{}", t.local, t.remote)
}

/// Synthesize a flow from packet observation alone (G5): a conversation the
/// table never confirmed. No process attribution — packets don't carry pids;
/// if the table catches the socket on a later poll, the table's row (same id)
/// takes over and fills it in.
fn flow_from_traffic(t: &FlowTraffic) -> Flow {
    let row = RawConn {
        protocol: t.protocol,
        local: t.local,
        remote: t.remote,
        tcp_state: None,
        process: None,
    };
    let mut flow = flow_from_raw(&row);
    flow.activity = activity_from_bytes(t.bytes);
    flow
}

/// Build the packet observer from the environment (G5). Three honest states:
/// the feature isn't compiled in; it is but `NETSCOPE_PCAP` isn't set (off, the
/// default — capture needs elevated privilege and a measured CPU cost); or it's
/// requested and the device open succeeded/failed. The returned string is the
/// user-facing status the System panel shows verbatim.
pub fn packet_observer_from_env() -> (Option<Box<dyn PacketObserve>>, String) {
    let enabled = std::env::var_os("NETSCOPE_PCAP").is_some_and(|v| !v.is_empty() && v != "0");
    if !enabled {
        return (
            None,
            "off — set NETSCOPE_PCAP=1 (needs capture privilege)".into(),
        );
    }
    #[cfg(feature = "pcap")]
    {
        match pcap::PcapObserver::start() {
            Ok((obs, device)) => {
                tracing::info!(device, "packet capture active (G5)");
                (Some(Box::new(obs)), format!("active ({device})"))
            }
            Err(e) => {
                tracing::warn!(error = %e, "packet capture unavailable — table polling only");
                (None, format!("unavailable: {e}"))
            }
        }
    }
    #[cfg(not(feature = "pcap"))]
    {
        tracing::warn!(
            "NETSCOPE_PCAP is set but this build lacks the `pcap` feature — \
             rebuild with `--features pcap` (needs libpcap / the Npcap SDK)"
        );
        (None, "not built — rebuild with --features pcap".into())
    }
}

/// Known-encrypted destination ports. A coarse heuristic, not a guarantee — a
/// plaintext service can squat on 443 — but it's the v1 read the plaintext-flag
/// art-direction keys on; deep inspection is out of scope for metadata polling.
fn is_encrypted_port(port: u16) -> bool {
    matches!(port, 443 | 853 | 993 | 995 | 465 | 990 | 5223 | 8443 | 22)
}

/// RFC1918 / loopback / link-local / ULA — the "local network" category. Computed
/// here, before enrichment, because these addresses must never reach a geo lookup
/// (PITFALLS A4) and read as one category in the organism.
fn is_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local() || a.is_broadcast(),
        IpAddr::V6(a) => {
            let seg = a.segments();
            a.is_loopback()
                || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (seg[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A scripted source: each `poll` returns the next queued batch (or empty).
    struct ScriptSource {
        batches: std::collections::VecDeque<Vec<RawConn>>,
    }
    impl ScriptSource {
        fn new(batches: Vec<Vec<RawConn>>) -> Self {
            Self {
                batches: batches.into(),
            }
        }
    }
    impl ConnectionSource for ScriptSource {
        fn poll(&mut self) -> std::io::Result<Vec<RawConn>> {
            Ok(self.batches.pop_front().unwrap_or_default())
        }
    }

    fn tcp(remote_ip: [u8; 4], port: u16, state: TcpState) -> RawConn {
        RawConn {
            protocol: L4Proto::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50000),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(remote_ip)), port),
            tcp_state: Some(state),
            process: None,
        }
    }
    fn udp(remote_ip: [u8; 4], port: u16) -> RawConn {
        RawConn {
            protocol: L4Proto::Udp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50001),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(remote_ip)), port),
            tcp_state: None,
            process: None,
        }
    }

    #[test]
    fn first_poll_is_all_adds() {
        let src = ScriptSource::new(vec![vec![
            tcp([1, 1, 1, 1], 443, TcpState::Established),
            tcp([8, 8, 8, 8], 80, TcpState::Other),
        ]]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        let u = eng.poll().unwrap();
        assert_eq!(u.generation, 1);
        assert_eq!(u.delta.adds.len(), 2);
        assert!(u.delta.updates.is_empty() && u.delta.removes.is_empty());
        assert_eq!(u.flows.len(), 2);
    }

    #[test]
    fn unchanged_flow_produces_no_delta() {
        let conn = tcp([1, 1, 1, 1], 443, TcpState::Established);
        let src = ScriptSource::new(vec![vec![conn.clone()], vec![conn]]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        eng.poll().unwrap();
        let u = eng.poll().unwrap();
        assert!(u.delta.is_empty(), "a stable connection must not churn");
    }

    #[test]
    fn state_change_is_an_update_not_a_churn() {
        let src = ScriptSource::new(vec![
            vec![tcp([1, 1, 1, 1], 443, TcpState::Other)], // connecting
            vec![tcp([1, 1, 1, 1], 443, TcpState::Established)], // now live
        ]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        eng.poll().unwrap();
        let u = eng.poll().unwrap();
        assert_eq!(u.delta.updates.len(), 1);
        assert!(u.delta.adds.is_empty() && u.delta.removes.is_empty());
        assert!(u.delta.updates[0].activity > 0.5);
    }

    #[test]
    fn closed_tcp_is_removed_immediately() {
        let src = ScriptSource::new(vec![
            vec![tcp([1, 1, 1, 1], 443, TcpState::Established)],
            vec![], // gone
        ]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        let first = eng.poll().unwrap();
        let id = first.flows[0].id.clone();
        let u = eng.poll().unwrap();
        assert_eq!(u.delta.removes, vec![id]);
        assert!(u.flows.is_empty());
    }

    #[test]
    fn udp_survives_one_absent_poll_then_expires() {
        let src = ScriptSource::new(vec![
            vec![udp([9, 9, 9, 9], 53)],
            vec![], // absent — within TTL, must persist
            vec![], // absent — past TTL, must expire
        ]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));

        let t0 = Instant::now();
        let first = eng.poll_at(t0).unwrap();
        assert_eq!(first.flows.len(), 1);
        let id = first.flows[0].id.clone();

        // 1s later: still inside the 5s TTL → carried forward, no remove.
        let second = eng.poll_at(t0 + Duration::from_secs(1)).unwrap();
        assert!(
            second.delta.removes.is_empty(),
            "UDP must not expire on one absent poll"
        );
        assert_eq!(second.flows.len(), 1);

        // 6s later: past TTL → removed.
        let third = eng.poll_at(t0 + Duration::from_secs(6)).unwrap();
        assert_eq!(third.delta.removes, vec![id]);
        assert!(third.flows.is_empty());
    }

    #[test]
    fn listeners_and_unconnected_sockets_are_skipped() {
        let mut listener = tcp([0, 0, 0, 0], 0, TcpState::Other);
        listener.remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let src = ScriptSource::new(vec![vec![
            listener,
            tcp([1, 1, 1, 1], 443, TcpState::Established),
        ]]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        let u = eng.poll().unwrap();
        assert_eq!(u.flows.len(), 1, "only the outbound conversation survives");
    }

    #[test]
    fn private_and_loopback_addresses_are_local() {
        assert!(is_local(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_local(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(is_local(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_local(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_local(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_local(&IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(is_local(&IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(!is_local(&IpAddr::V6("2606:4700::1111".parse().unwrap())));
    }

    #[test]
    fn local_flow_is_categorized_local_and_skips_enrichment() {
        let src = ScriptSource::new(vec![vec![udp([192, 168, 1, 1], 53)]]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        let u = eng.poll().unwrap();
        let f = &u.flows[0];
        assert_eq!(f.category, Category::Local);
        assert!(f.asn.is_none() && f.location.is_none());
    }

    // --- G5: packet observation merged into the poll -------------------------

    /// A scripted observer: each `drain` returns the next queued batch.
    struct ScriptObserver {
        batches: std::collections::VecDeque<Vec<FlowTraffic>>,
    }
    impl ScriptObserver {
        fn new(batches: Vec<Vec<FlowTraffic>>) -> Box<Self> {
            Box::new(Self {
                batches: batches.into(),
            })
        }
    }
    impl PacketObserve for ScriptObserver {
        fn drain(&mut self) -> Vec<FlowTraffic> {
            self.batches.pop_front().unwrap_or_default()
        }
    }

    fn traffic(remote_ip: [u8; 4], port: u16, bytes: u64) -> FlowTraffic {
        FlowTraffic {
            protocol: L4Proto::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50000),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(remote_ip)), port),
            packets: 4,
            bytes,
        }
    }

    #[test]
    fn packet_only_flow_appears_then_expires_after_pkt_ttl() {
        let src = ScriptSource::new(vec![vec![], vec![], vec![]]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        eng.set_observer(ScriptObserver::new(vec![
            vec![traffic([1, 1, 1, 1], 443, 5_000)], // a sub-poll-interval burst
        ]));

        let t0 = Instant::now();
        let first = eng.poll_at(t0).unwrap();
        assert_eq!(first.delta.adds.len(), 1, "the table missed it; we didn't");
        let id = first.flows[0].id.clone();
        assert!(first.flows[0].process.is_none(), "packets carry no pid");

        // Within PKT_TTL: lingers.
        let second = eng.poll_at(t0 + Duration::from_secs(1)).unwrap();
        assert!(second.delta.removes.is_empty());
        assert_eq!(second.flows.len(), 1);

        // Past PKT_TTL: expires.
        let third = eng.poll_at(t0 + Duration::from_secs(4)).unwrap();
        assert_eq!(third.delta.removes, vec![id]);
        assert!(third.flows.is_empty());
    }

    #[test]
    fn bytes_lift_a_table_flows_activity() {
        let conn = tcp([1, 1, 1, 1], 443, TcpState::Established); // placeholder 0.6
        let src = ScriptSource::new(vec![vec![conn.clone()], vec![conn]]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        eng.set_observer(ScriptObserver::new(vec![
            vec![],
            vec![traffic([1, 1, 1, 1], 443, 2_000_000)], // a fast transfer window
        ]));

        eng.poll().unwrap();
        let u = eng.poll().unwrap();
        assert_eq!(u.delta.updates.len(), 1, "byte-true activity is an update");
        assert!(u.delta.updates[0].activity > 0.95);
    }

    #[test]
    fn table_takeover_is_an_update_and_table_owns_the_lifecycle() {
        // Poll 1: packets only. Poll 2: the table catches the same 5-tuple
        // (same id → update, not remove+add churn). Poll 3: table drops it →
        // removed immediately, PKT_TTL no longer applies.
        let src = ScriptSource::new(vec![
            vec![],
            vec![tcp([1, 1, 1, 1], 443, TcpState::Established)],
            vec![],
        ]);
        let mut eng = CaptureEngine::with_source(Box::new(src), Arc::new(NoEnrich));
        eng.set_observer(ScriptObserver::new(vec![
            vec![traffic([1, 1, 1, 1], 443, 800)],
            vec![],
            vec![],
        ]));

        let t0 = Instant::now();
        let first = eng.poll_at(t0).unwrap();
        assert_eq!(first.delta.adds.len(), 1);
        let id = first.flows[0].id.clone();

        let second = eng.poll_at(t0 + Duration::from_millis(250)).unwrap();
        assert!(second.delta.adds.is_empty(), "same id — no churn");
        assert_eq!(second.delta.updates.len(), 1);
        assert_eq!(second.delta.updates[0].id, id);

        let third = eng.poll_at(t0 + Duration::from_millis(500)).unwrap();
        assert_eq!(
            third.delta.removes,
            vec![id],
            "once table-confirmed, a table drop closes it — no packet lingering"
        );
    }

    #[test]
    fn activity_from_bytes_is_log_scaled_and_clamped() {
        assert!(activity_from_bytes(0) <= 0.16);
        let kb = activity_from_bytes(1_000);
        let mb = activity_from_bytes(2_000_000);
        assert!(kb > 0.4 && kb < 0.6, "1 KB window ≈ half: {kb}");
        assert!((mb - 1.0).abs() < 0.01, "2 MB window pegs: {mb}");
        assert_eq!(activity_from_bytes(u64::MAX), 1.0);
    }
}
