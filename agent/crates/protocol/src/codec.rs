//! # Wire framing — version compatibility + content encoding (A5)
//!
//! The message *types* live in [`crate`]; this module is how they cross the wire
//! and how the two ends agree on a dialect. Two concerns:
//!
//! - **Version compatibility.** [`PROTOCOL_VERSION`](crate::PROTOCOL_VERSION) is
//!   the protocol *major*. Additive (minor) changes ride the unknown-fields rule
//!   and do not bump it, so [`is_compatible`] is an exact-major check; a breaking
//!   change bumps the major and an old peer disconnects.
//! - **Content encoding.** JSON is the default — debuggable, readable in browser
//!   devtools, the right call for a project people read to learn the protocol.
//!   MessagePack is opt-in for bandwidth (remote/mobile over constrained links).
//!   The dialect is negotiated once at the WebSocket handshake and the *frame
//!   type* carries it thereafter: JSON on text frames, MessagePack on binary —
//!   so a receiver never has to sniff.
//!
//! Both dialects encode the **same logical shape** (MessagePack uses named struct
//! fields via `with_struct_map`), so they are interchangeable and share the
//! forward-compatibility guarantee: unknown fields are ignored in either.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::PROTOCOL_VERSION;

/// Subprotocol token for the default JSON dialect (echoed by the server).
pub const SUBPROTOCOL_JSON: &str = "netscope";
/// Subprotocol token a client offers to request the MessagePack dialect.
pub const SUBPROTOCOL_MSGPACK: &str = "netscope.msgpack";

/// Whether a peer speaking `peer_version` is compatible with this build.
///
/// The version is the protocol *major*: additive changes ride the unknown-fields
/// rule and never bump it, so compatibility is an exact-major match. A future
/// `2` is intentionally incompatible with a `1` client, which disconnects rather
/// than misread a reshaped stream.
pub fn is_compatible(peer_version: u32) -> bool {
    peer_version == PROTOCOL_VERSION
}

/// The negotiated content encoding for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// UTF-8 JSON on WebSocket text frames. The default.
    Json,
    /// MessagePack on WebSocket binary frames. Opt-in.
    MessagePack,
}

impl Encoding {
    /// Pick the encoding from a client's `Sec-WebSocket-Protocol` offer (a
    /// comma-separated list). A client advertising [`SUBPROTOCOL_MSGPACK`] gets
    /// MessagePack; everyone else — including older clients that send no
    /// subprotocol — gets JSON. New encodings can be added here without breaking
    /// any existing client (the heart of why this is the *scalable* seam).
    pub fn negotiate(offered: &str) -> Encoding {
        let wants_msgpack = offered
            .split(',')
            .map(str::trim)
            .any(|p| p == SUBPROTOCOL_MSGPACK);
        if wants_msgpack {
            Encoding::MessagePack
        } else {
            Encoding::Json
        }
    }

    /// The subprotocol token the server echoes so the client knows what was chosen.
    pub fn subprotocol(self) -> &'static str {
        match self {
            Encoding::Json => SUBPROTOCOL_JSON,
            Encoding::MessagePack => SUBPROTOCOL_MSGPACK,
        }
    }

    /// Encode a message into a transport [`Frame`] in this encoding.
    pub fn encode<T: Serialize>(self, msg: &T) -> Result<Frame, ProtocolError> {
        match self {
            Encoding::Json => Ok(Frame::Text(serde_json::to_string(msg)?)),
            Encoding::MessagePack => Ok(Frame::Binary(to_msgpack(msg)?)),
        }
    }
}

/// A transport-agnostic encoded frame. The variant mirrors the WebSocket frame
/// type the caller should send, so the encoding is self-describing on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Text(String),
    Binary(Vec<u8>),
}

/// Decode a JSON (text-frame) payload.
pub fn decode_json<T: DeserializeOwned>(text: &str) -> Result<T, ProtocolError> {
    Ok(serde_json::from_str(text)?)
}

/// Decode a MessagePack (binary-frame) payload.
pub fn decode_msgpack<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    Ok(rmp_serde::from_slice(bytes)?)
}

/// MessagePack with **named struct fields** (a map, not a positional array).
/// Required for serde's internally-tagged enums (our `type`-discriminated
/// envelopes) to round-trip, and it preserves the JSON shape field-for-field so
/// the dialects stay interchangeable and forward-compatible.
fn to_msgpack<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    let mut ser = rmp_serde::Serializer::new(&mut buf).with_struct_map();
    msg.serialize(&mut ser)?;
    Ok(buf)
}

/// Encode/decode failure on either dialect.
#[derive(Debug)]
pub enum ProtocolError {
    Json(serde_json::Error),
    MessagePackEncode(rmp_serde::encode::Error),
    MessagePackDecode(rmp_serde::decode::Error),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Json(e) => write!(f, "json: {e}"),
            ProtocolError::MessagePackEncode(e) => write!(f, "messagepack encode: {e}"),
            ProtocolError::MessagePackDecode(e) => write!(f, "messagepack decode: {e}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<serde_json::Error> for ProtocolError {
    fn from(e: serde_json::Error) -> Self {
        ProtocolError::Json(e)
    }
}
impl From<rmp_serde::encode::Error> for ProtocolError {
    fn from(e: rmp_serde::encode::Error) -> Self {
        ProtocolError::MessagePackEncode(e)
    }
}
impl From<rmp_serde::decode::Error> for ProtocolError {
    fn from(e: rmp_serde::decode::Error) -> Self {
        ProtocolError::MessagePackDecode(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_is_exact_major() {
        assert!(is_compatible(PROTOCOL_VERSION));
        assert!(!is_compatible(PROTOCOL_VERSION + 1));
        assert!(!is_compatible(0));
    }

    #[test]
    fn negotiation_prefers_msgpack_only_when_offered() {
        assert_eq!(Encoding::negotiate("netscope"), Encoding::Json);
        assert_eq!(Encoding::negotiate(""), Encoding::Json);
        assert_eq!(Encoding::negotiate("auth.tok, netscope"), Encoding::Json);
        assert_eq!(
            Encoding::negotiate("netscope, netscope.msgpack, auth.tok"),
            Encoding::MessagePack
        );
        assert_eq!(
            Encoding::negotiate("netscope.msgpack"),
            Encoding::MessagePack
        );
        // A near-miss must not match.
        assert_eq!(Encoding::negotiate("netscope.msgpackx"), Encoding::Json);
    }

    #[test]
    fn subprotocol_round_trips_through_negotiation() {
        for enc in [Encoding::Json, Encoding::MessagePack] {
            assert_eq!(Encoding::negotiate(enc.subprotocol()), enc);
        }
    }

    #[test]
    fn json_uses_text_and_msgpack_uses_binary_frames() {
        use crate::Heartbeat;
        let hb = Heartbeat {
            seq: 1,
            tick: 2,
            uptime_ms: 3,
        };
        assert!(matches!(
            Encoding::Json.encode(&hb).unwrap(),
            Frame::Text(_)
        ));
        assert!(matches!(
            Encoding::MessagePack.encode(&hb).unwrap(),
            Frame::Binary(_)
        ));
    }
}
