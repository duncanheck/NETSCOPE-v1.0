//! # netscope-protocol
//!
//! The single source of truth for every message that crosses the
//! agent ↔ frontend boundary. The TypeScript types in
//! `frontend/src/protocol/generated/` are produced *from* the structs in this
//! crate via `ts-rs`, so the two languages cannot silently disagree
//! (see PITFALLS A5). Regenerate with:
//!
//! ```bash
//! cargo test -p netscope-protocol export_bindings
//! ```
//!
//! ## Versioning & sequencing
//!
//! Every message carries a `seq`, and the protocol carries a [`PROTOCOL_VERSION`],
//! from v1 — so the resync milestone (C4) is not a retrofit. Unknown fields are
//! ignored (forward compatibility); a breaking change is a major version bump
//! negotiated in [`Hello`].

use serde::{Deserialize, Serialize};
use ts_rs::TS;

mod codec;
pub use codec::{
    decode_json, decode_msgpack, is_compatible, Encoding, Frame, ProtocolError, SUBPROTOCOL_JSON,
    SUBPROTOCOL_MSGPACK,
};

/// Wire protocol version — the protocol *major*. Additive changes ride the
/// unknown-fields rule and never bump it; a breaking change bumps it, and an old
/// peer disconnects (see [`is_compatible`]). The client compares this against the
/// value carried in [`Hello`].
pub const PROTOCOL_VERSION: u32 = 1;

/// Where the generated TypeScript lands, relative to the repo root.
/// (ts-rs resolves the `export_to` attribute paths below relative to this
/// crate's `src/`, hence the `../../../../` they carry.)
pub const TS_EXPORT_DIR: &str = "frontend/src/protocol/generated/";

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// The top-level frame. A tagged union discriminated on `type`; this generates a
/// discriminated union on the TypeScript side.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "lowercase")]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub enum WireMessage {
    /// First frame the agent sends on connect.
    Hello(Hello),
    /// Full state; wholesale-replaces the client mirror (sent on connect / resync).
    Snapshot(Snapshot),
    /// Incremental change since the previous `seq`.
    Delta(Delta),
    /// One batched payload per tick — the batching pattern all high-frequency
    /// data follows (PITFALLS A1: never per-item events).
    Heartbeat(Heartbeat),
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct Hello {
    /// The protocol version this agent speaks ([`PROTOCOL_VERSION`]).
    pub version: u32,
    pub agent: AgentInfo,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct AgentInfo {
    pub name: String,
    pub version: String,
    /// `windows` / `linux` / `macos` — the OS the agent is capturing on.
    pub platform: String,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct Heartbeat {
    /// Emitted as a JS `number` (not bigint): JSON carries it as a number, and a
    /// session never approaches 2^53 ticks. Same for `tick`/`uptime_ms` below.
    #[ts(type = "number")]
    pub seq: u64,
    /// Monotonic tick counter since the agent started.
    #[ts(type = "number")]
    pub tick: u64,
    /// Agent uptime in milliseconds, for a liveness read on the client.
    #[ts(type = "number")]
    pub uptime_ms: u64,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct Snapshot {
    #[ts(type = "number")]
    pub seq: u64,
    pub flows: Vec<Flow>,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct Delta {
    #[ts(type = "number")]
    pub seq: u64,
    pub adds: Vec<Flow>,
    pub updates: Vec<Flow>,
    /// IDs of flows that have closed/expired.
    pub removes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Client → agent (the C4 control direction)
//
// A separate envelope from `WireMessage` (which is agent → client) so the two
// directions version independently. Same tagged-union shape and the same
// forward-compat rule: an unknown `type` is ignored by the receiver.
// ---------------------------------------------------------------------------

/// Messages the client sends back to the agent.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "lowercase")]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub enum ClientMessage {
    /// The client detected a sequence gap and wants the world wholesale to
    /// rebuild its mirror (C4). The agent always answers with a fresh `snapshot`.
    Resync(ResyncRequest),
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct ResyncRequest {
    /// The last `seq` the client successfully applied — diagnostics only; the
    /// agent replies with a full snapshot regardless of this value.
    #[ts(type = "number")]
    pub last_seq: u64,
}

// ---------------------------------------------------------------------------
// Data model (carried straight over from the prototype — SALVAGE.md)
//
// This is the per-endpoint record shape the real capture loop (A2) will emit.
// It is locked in now, in Pass 1, so the frontend and the mock fixture share it
// even before the agent produces real flows.
// ---------------------------------------------------------------------------

/// How a flow is classified for art-direction and security read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub enum Category {
    /// Content-delivery / general service traffic — the default cool blue-green.
    Service,
    /// Known tracker / telemetry org — rendered amber.
    Tracker,
    /// Content delivery network.
    Cdn,
    /// RFC1918 / loopback / link-local — the "local network" category
    /// (classified before enrichment, never sent to geo lookup — PITFALLS A4).
    Local,
    /// Not yet classified.
    Unknown,
}

/// Layer-4 protocol. TCP carries connection state; UDP entries are stateless
/// bound sockets with their own TTL-based lifecycle (PITFALLS A2).
/// `Hash` so a (proto, local, remote) tuple can key the G5 packet aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub enum L4Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct GeoLocation {
    pub city: Option<String>,
    pub country: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct AsnInfo {
    pub number: u32,
    pub org: String,
}

/// Owning process. `Option`-typed end to end because some elevated/system
/// processes deny their info even without admin — the UI renders
/// "protected process" rather than crashing or blanking (PITFALLS A2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

/// A per-flow security/privacy callout produced by the A4 enrichment pass. The
/// policy that sets these lives agent-side (testable Rust), and the set is
/// open-ended — unknown variants are ignored by older clients (forward-compat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub enum SecurityFlag {
    /// The destination port/protocol is not known-encrypted — data may be in clear.
    Plaintext,
    /// No owning org/ASN could be resolved — a destination we can't attribute.
    UnresolvedOrg,
    /// Classified as a tracker / telemetry endpoint.
    Tracker,
}

/// A single endpoint conversation. Mirrors the prototype's data model exactly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../../frontend/src/protocol/generated/")]
pub struct Flow {
    /// Stable identity for delta application: keyed on the connection 5-tuple.
    pub id: String,
    /// Display name (resolved hostname or IP).
    pub name: String,
    pub category: Category,
    pub asn: Option<AsnInfo>,
    pub location: Option<GeoLocation>,
    pub process: Option<ProcessInfo>,
    pub port: u16,
    pub protocol: L4Proto,
    /// True when the destination port / protocol is known-encrypted (e.g. 443).
    pub encrypted: bool,
    pub ip: String,
    /// 0.0–1.0 traffic intensity, drives tendril thickness and pulse rate.
    pub activity: f32,
    /// False once the connection has closed but is lingering in the view.
    pub alive: bool,
    /// Security/privacy callouts (A4 enrichment); empty until/unless any apply.
    #[serde(default)]
    pub flags: Vec<SecurityFlag>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_round_trips_through_wire_message() {
        let msg = WireMessage::Heartbeat(Heartbeat {
            seq: 7,
            tick: 3,
            uptime_ms: 1234,
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"heartbeat\""));
        let back: WireMessage = serde_json::from_str(&json).unwrap();
        matches!(back, WireMessage::Heartbeat(_));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // Forward-compatibility rule: a newer agent adding a field must not
        // break an older client's deserialization.
        let json = r#"{"type":"heartbeat","seq":1,"tick":1,"uptime_ms":1,"future_field":42}"#;
        let parsed: WireMessage = serde_json::from_str(json).unwrap();
        matches!(parsed, WireMessage::Heartbeat(_));
    }

    #[test]
    fn resync_round_trips_through_client_message() {
        let msg = ClientMessage::Resync(ResyncRequest { last_seq: 42 });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"resync\""));
        assert!(json.contains("\"last_seq\":42"));
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        let ClientMessage::Resync(req) = back;
        assert_eq!(req.last_seq, 42);
    }

    #[test]
    fn unknown_client_message_fields_are_ignored() {
        let json = r#"{"type":"resync","last_seq":7,"future_field":true}"#;
        let parsed: ClientMessage = serde_json::from_str(json).unwrap();
        let ClientMessage::Resync(req) = parsed;
        assert_eq!(req.last_seq, 7);
    }

    // -------------------------------------------------------------------------
    // Conformance — the protocol contract, enforced so contributors can't regress
    // it (the whole point of a single-source-of-truth, multi-client protocol).
    // -------------------------------------------------------------------------

    /// A representative flow with every optional field populated — the
    /// worst/realistic case for both round-trip and size measurement.
    fn sample_flow(i: usize) -> Flow {
        Flow {
            id: format!("tcp:10.0.0.{i}:54321->93.184.216.34:443"),
            name: format!("host-{i}.example.com"),
            category: Category::Service,
            asn: Some(AsnInfo {
                number: 15133,
                org: "Edgecast Inc.".into(),
            }),
            location: Some(GeoLocation {
                city: Some("Los Angeles".into()),
                country: Some("US".into()),
                lat: Some(34.0522),
                lon: Some(-118.2437),
            }),
            process: Some(ProcessInfo {
                pid: 4242,
                name: "firefox".into(),
                path: Some("/usr/lib/firefox/firefox".into()),
            }),
            port: 443,
            protocol: L4Proto::Tcp,
            encrypted: true,
            ip: "93.184.216.34".into(),
            activity: 0.73,
            alive: true,
            flags: vec![SecurityFlag::Tracker],
        }
    }

    fn sample_snapshot(n: usize) -> WireMessage {
        WireMessage::Snapshot(Snapshot {
            seq: 1,
            flows: (0..n).map(sample_flow).collect(),
        })
    }

    /// Every agent→client variant must survive a round trip in **both** dialects
    /// and come back equal — the guarantee a second-language client relies on.
    #[test]
    fn every_message_round_trips_in_both_encodings() {
        let messages = vec![
            WireMessage::Hello(Hello {
                version: PROTOCOL_VERSION,
                agent: AgentInfo {
                    name: "netscope-agent".into(),
                    version: "0.1.0".into(),
                    platform: "linux".into(),
                },
            }),
            sample_snapshot(3),
            WireMessage::Delta(Delta {
                seq: 9,
                adds: vec![sample_flow(0)],
                updates: vec![sample_flow(1)],
                removes: vec!["udp:0.0.0.0:5353".into()],
            }),
            WireMessage::Heartbeat(Heartbeat {
                seq: 5,
                tick: 5,
                uptime_ms: 5000,
            }),
        ];

        for msg in &messages {
            for enc in [Encoding::Json, Encoding::MessagePack] {
                let back: WireMessage = match enc.encode(msg).unwrap() {
                    Frame::Text(t) => decode_json(&t).unwrap(),
                    Frame::Binary(b) => decode_msgpack(&b).unwrap(),
                };
                assert_eq!(&back, msg, "round trip failed for {enc:?}");
            }
        }
    }

    #[test]
    fn client_message_round_trips_in_both_encodings() {
        let msg = ClientMessage::Resync(ResyncRequest { last_seq: 999 });
        // JSON
        let Frame::Text(t) = Encoding::Json.encode(&msg).unwrap() else {
            panic!("json should be a text frame")
        };
        assert_eq!(decode_json::<ClientMessage>(&t).unwrap(), msg);
        // MessagePack
        let Frame::Binary(b) = Encoding::MessagePack.encode(&msg).unwrap() else {
            panic!("msgpack should be a binary frame")
        };
        assert_eq!(decode_msgpack::<ClientMessage>(&b).unwrap(), msg);
    }

    /// The forward-compat rule holds for **MessagePack too**, not just JSON: an
    /// unknown field added by a newer peer is ignored by an older one.
    /// The forward-compat rule holds for **MessagePack too**, not just JSON: an
    /// unknown field added by a newer peer is ignored by an older one. We build
    /// the extended frame by round-tripping a `serde_json::Value` (which carries
    /// the extra key) through the same struct-map MessagePack serializer.
    #[test]
    fn msgpack_ignores_unknown_fields() {
        let json = r#"{"type":"heartbeat","seq":1,"tick":1,"uptime_ms":1,"future_field":42}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut bytes = Vec::new();
        let mut ser = rmp_serde::Serializer::new(&mut bytes).with_struct_map();
        serde::Serialize::serialize(&value, &mut ser).unwrap();

        let parsed: WireMessage = decode_msgpack(&bytes).unwrap();
        assert!(matches!(parsed, WireMessage::Heartbeat(_)));
    }

    /// Records the JSON-vs-MessagePack size win on a realistic snapshot so the
    /// claim in `docs/protocol.md` stays honest and reproducible. Run with
    /// `cargo test -p netscope-protocol wire_size -- --nocapture` to see the table.
    #[test]
    fn wire_size_messagepack_is_smaller() {
        for n in [1usize, 50, 300] {
            let snap = sample_snapshot(n);
            let Frame::Text(json) = Encoding::Json.encode(&snap).unwrap() else {
                unreachable!()
            };
            let Frame::Binary(mp) = Encoding::MessagePack.encode(&snap).unwrap() else {
                unreachable!()
            };
            let (j, m) = (json.len(), mp.len());
            let pct = 100.0 * (1.0 - m as f64 / j as f64);
            println!("snapshot n={n:>3}: json={j:>7}B  msgpack={m:>7}B  ({pct:.1}% smaller)");
            assert!(m < j, "messagepack should be smaller for n={n}");
        }
    }
}
