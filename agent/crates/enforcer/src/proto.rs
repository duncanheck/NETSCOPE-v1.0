//! The enforcer's local IPC: length-prefixed JSON over a stream (a Unix socket in
//! production). One request, one response. Deliberately tiny — the whole vocabulary
//! is "add/remove/list/clear addresses in my set", nothing else, so the privileged
//! surface stays auditable.

use std::io::{self, Read, Write};
use std::net::IpAddr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Protocol version, bumped on a breaking change to the message shapes.
pub const PROTOCOL_VERSION: u32 = 1;

/// A frame can't exceed this — a hostile or buggy peer can't make us allocate
/// unbounded memory. 1 MiB is far more than any real request.
pub const MAX_FRAME: usize = 1 << 20;

/// Agent → enforcer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness/version handshake.
    Ping,
    /// Block `add` and unblock `remove` (both optional). The enforcer applies its
    /// never-block floor first, so protected addresses are silently refused.
    Apply {
        #[serde(default)]
        add: Vec<IpAddr>,
        #[serde(default)]
        remove: Vec<IpAddr>,
    },
    /// The set of currently-blocked addresses.
    List,
    /// Remove every block (tear the set down).
    Clear,
}

/// Enforcer → agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Pong {
        version: u32,
    },
    /// What actually changed. `rejected` are addresses refused by the never-block
    /// floor (loopback/LAN/etc.) — surfaced so the caller can explain the no-op.
    Applied {
        added: Vec<IpAddr>,
        removed: Vec<IpAddr>,
        rejected: Vec<IpAddr>,
        blocked_total: usize,
    },
    Blocked {
        blocked: Vec<IpAddr>,
    },
    Cleared {
        removed: usize,
    },
    Error {
        message: String,
    },
}

/// Write one length-prefixed JSON frame.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::other("message exceeds MAX_FRAME"));
    }
    let len = (body.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one length-prefixed JSON frame. `Ok(None)` on a clean EOF before any byte
/// (the peer hung up), so a read loop can end gracefully.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::other("frame length exceeds MAX_FRAME"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let msg = serde_json::from_slice(&body).map_err(io::Error::other)?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_request_and_response() {
        let req = Request::Apply {
            add: vec!["8.8.8.8".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            remove: vec![],
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &req).unwrap();
        let got: Option<Request> = read_msg(&mut buf.as_slice()).unwrap();
        assert_eq!(got, Some(req));

        let resp = Response::Applied {
            added: vec!["8.8.8.8".parse().unwrap()],
            removed: vec![],
            rejected: vec!["127.0.0.1".parse().unwrap()],
            blocked_total: 1,
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &resp).unwrap();
        let got: Option<Response> = read_msg(&mut buf.as_slice()).unwrap();
        assert_eq!(got, Some(resp));
    }

    #[test]
    fn clean_eof_is_none_not_error() {
        let empty: &[u8] = &[];
        let got: Option<Request> = read_msg(&mut { empty }).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn oversized_frame_is_refused() {
        // A length prefix claiming > MAX_FRAME must error, not allocate.
        let mut framed = ((MAX_FRAME as u32) + 1).to_be_bytes().to_vec();
        framed.push(0);
        let r: io::Result<Option<Request>> = read_msg(&mut framed.as_slice());
        assert!(r.is_err());
    }

    #[test]
    fn request_tag_is_stable_json() {
        // The wire shape is part of the contract; pin it.
        let j = serde_json::to_string(&Request::List).unwrap();
        assert_eq!(j, r#"{"op":"list"}"#);
    }
}
