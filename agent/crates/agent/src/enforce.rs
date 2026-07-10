//! The agent's client to the privileged enforcer (E4) — Unix socket on Linux,
//! named pipe on Windows.
//!
//! Opt-in either way; the agent holds no privilege — it just asks the helper over
//! the authenticated channel, and the helper re-checks everything (including the
//! never-block floor) on its side.
//!
//! - **Linux**: only when `NETSCOPE_ENFORCER_SOCKET` is set does the agent ever
//!   reach for enforcement; otherwise NETSCOPE stays generate-only (E3).
//! - **Windows**: the opt-in is *installing the service* (it owns the well-known
//!   pipe `\\.\pipe\netscope-enforcer`). The agent probes for that pipe and uses
//!   it when present, so the desktop product lights up enforcement the moment the
//!   service is installed — no env var to plumb through the shell. Set
//!   `NETSCOPE_ENFORCER_PIPE` to a different name to override, or to `off`/`0`
//!   to disable entirely.

use std::net::IpAddr;
#[cfg(unix)]
use std::time::Duration;

use netscope_enforcer::proto::{read_msg, write_msg, Request, Response};

/// A handle to the configured enforcer channel.
pub struct Enforcer {
    endpoint: String,
}

impl Enforcer {
    #[cfg(unix)]
    /// Present only when `NETSCOPE_ENFORCER_SOCKET` is configured.
    pub fn from_env() -> Option<Self> {
        std::env::var("NETSCOPE_ENFORCER_SOCKET")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|endpoint| Enforcer { endpoint })
    }

    #[cfg(windows)]
    /// Present when the enforcer pipe is configured, or when the well-known pipe
    /// exists (the installed-service auto-detect).
    pub fn from_env() -> Option<Self> {
        match std::env::var("NETSCOPE_ENFORCER_PIPE") {
            Ok(v) => {
                let v = v.trim().to_string();
                if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("off") {
                    return None;
                }
                Some(Enforcer { endpoint: v })
            }
            Err(_) => {
                let default = netscope_enforcer::DEFAULT_PIPE;
                netscope_enforcer::winpipe::pipe_exists(default).then(|| Enforcer {
                    endpoint: default.to_string(),
                })
            }
        }
    }

    #[cfg(unix)]
    fn connect(&self) -> Result<std::os::unix::net::UnixStream, String> {
        let conn = std::os::unix::net::UnixStream::connect(&self.endpoint)
            .map_err(|e| format!("cannot reach enforcer at {}: {e}", self.endpoint))?;
        let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = conn.set_write_timeout(Some(Duration::from_secs(5)));
        Ok(conn)
    }

    #[cfg(windows)]
    fn connect(&self) -> Result<std::fs::File, String> {
        // Named-pipe reads/writes have no per-handle timeout knob like sockets; the
        // helper is local and serves each frame immediately, and `client_connect`
        // already bounds the busy-wait. The 5 s socket timeouts on Unix guard the
        // same failure mode (a hung helper), which here surfaces as a pipe error.
        netscope_enforcer::winpipe::client_connect(&self.endpoint)
            .map_err(|e| format!("cannot reach enforcer at {}: {e}", self.endpoint))
    }

    fn round_trip(&self, req: &Request) -> Result<Response, String> {
        let mut conn = self.connect()?;
        write_msg(&mut conn, req).map_err(|e| format!("sending to enforcer: {e}"))?;
        read_msg::<_, Response>(&mut conn)
            .map_err(|e| format!("reading from enforcer: {e}"))?
            .ok_or_else(|| "enforcer closed without replying".to_string())
    }

    pub fn apply(&self, add: Vec<IpAddr>, remove: Vec<IpAddr>) -> Result<Response, String> {
        self.round_trip(&Request::Apply { add, remove })
    }

    pub fn list(&self) -> Result<Response, String> {
        self.round_trip(&Request::List)
    }

    pub fn clear(&self) -> Result<Response, String> {
        self.round_trip(&Request::Clear)
    }
}
