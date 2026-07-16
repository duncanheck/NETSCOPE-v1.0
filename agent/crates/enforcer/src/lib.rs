//! # E4 — the enforcer (privilege-separated apply)
//!
//! E1–E3 are zero-privilege: decide, match, and *generate* a firewall ruleset the
//! user applies by hand. E4 is the one privileged piece — a small helper that holds
//! `CAP_NET_ADMIN` and does *only* "add/remove an address in my own `inet netscope`
//! set", on request from the unprivileged agent over an authenticated local socket.
//!
//! The design is defensive on purpose, because it's the project's one elevated
//! surface:
//!
//! - **Least privilege.** It needs only `CAP_NET_ADMIN`, not root (the shipped
//!   systemd unit drops everything else). It owns one table and refuses to touch
//!   anything outside it.
//! - **Authenticated peer, not "loopback == trusted".** A Unix socket gives us the
//!   connecting process' real UID via `SO_PEERCRED`; only an allowed UID (or root)
//!   is served (see [`is_authorized`]).
//! - **The never-block floor lives *here*, not just in the agent.** Even if the
//!   agent (or a stolen C2 token that can reach it) asks to block loopback, the LAN,
//!   or the tailnet, the enforcer drops those addresses itself — reusing the exact
//!   predicate the warden uses ([`netscope_warden::is_protected_addr`]). A bug or a
//!   compromise upstream still can't cut the user off their own network.
//! - **Bounded + audited.** The block set is capped, and every change is logged.
//!
//! The agent talks to it only when explicitly configured (a socket path); absent
//! that, NETSCOPE stays generate-only, exactly as before.

pub mod apply;
pub mod proto;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::OnceLock;

pub use apply::{Applier, MockApplier, NftApplier};
pub use proto::{Request, Response, PROTOCOL_VERSION};

// The Windows E4 follow-up, landed: the same enforcer core behind a named pipe
// (peer authenticated by process-token SID) driving Windows Firewall rules in a
// namespaced group. See `winpipe` / `apply_windows`.
#[cfg(windows)]
pub mod apply_windows;
#[cfg(windows)]
pub mod winpipe;
#[cfg(windows)]
pub use apply_windows::WfwApplier;
#[cfg(windows)]
pub use winpipe::{serve_windows, AllowedSids, DEFAULT_PIPE};

use netscope_warden::is_protected_addr;

/// Who may drive the enforcer, checked against the connecting peer's UID.
#[derive(Debug, Clone)]
pub enum AllowedPeers {
    /// Any local peer (tests, or an explicitly trusted single-user host). Never the
    /// production default.
    Any,
    /// Only root (UID 0).
    RootOnly,
    /// Root, or this specific UID (the desktop user the helper was installed for).
    Uid(u32),
}

/// Is a peer with `peer_uid` allowed under `policy`? Root is always allowed (it can
/// edit nftables anyway); otherwise the UID must match the configured one.
pub fn is_authorized(policy: &AllowedPeers, peer_uid: u32) -> bool {
    match policy {
        AllowedPeers::Any => true,
        AllowedPeers::RootOnly => peer_uid == 0,
        AllowedPeers::Uid(uid) => peer_uid == 0 || peer_uid == *uid,
    }
}

/// A hard cap on the block set, so a runaway caller can't grow the kernel set
/// without bound. Generous for real use (feeds match a handful of live flows).
pub const DEFAULT_MAX_BLOCKED: usize = 4096;

/// The enforcer: owns the authoritative view of what's blocked and drives an
/// [`Applier`] to mirror it into the kernel. Generic over the applier so the logic
/// is tested with a mock and run with `nft`.
pub struct Enforcer<A: Applier> {
    applier: A,
    blocked: Mutex<BTreeSet<IpAddr>>,
    max_blocked: usize,
}

impl<A: Applier> Enforcer<A> {
    /// Create an enforcer and ensure the firewall structure exists.
    pub fn new(applier: A, max_blocked: usize) -> Result<Self, String> {
        applier.ensure()?;
        Ok(Enforcer {
            applier,
            blocked: Mutex::new(BTreeSet::new()),
            max_blocked,
        })
    }

    /// Current block set (sorted).
    pub fn blocked(&self) -> Vec<IpAddr> {
        self.blocked.lock().unwrap().iter().copied().collect()
    }

    /// Handle one request, applying any change to the kernel. This is the whole
    /// behaviour of the helper; the socket loop just feeds it.
    pub fn handle(&self, req: Request) -> Response {
        match req {
            Request::Ping => Response::Pong {
                version: PROTOCOL_VERSION,
            },
            Request::List => Response::Blocked {
                blocked: self.blocked(),
            },
            Request::Clear => match self.applier.clear() {
                Ok(()) => {
                    let mut set = self.blocked.lock().unwrap();
                    let n = set.len();
                    set.clear();
                    // Recreate the empty structure so a later Apply has somewhere to go.
                    let _ = self.applier.ensure();
                    audit(&format!("clear: removed {n}"));
                    Response::Cleared { removed: n }
                }
                Err(e) => err(format!("clear failed: {e}")),
            },
            Request::Apply { add, remove } => self.apply(add, remove),
            Request::Verify => match self.applier.verify() {
                Ok(live) => {
                    let expected = self.blocked();
                    let live_set: BTreeSet<IpAddr> = live.iter().copied().collect();
                    let expected_set: BTreeSet<IpAddr> = expected.iter().copied().collect();
                    let in_sync = live_set == expected_set;
                    if !in_sync {
                        // Drift is exactly the case this exists to catch — always
                        // audited, not just a UI-side concern.
                        audit(&format!(
                            "verify: DRIFT — live {} expected {}",
                            live_set.len(),
                            expected_set.len()
                        ));
                    }
                    Response::Verified {
                        live,
                        expected,
                        in_sync,
                    }
                }
                Err(e) => err(format!("verify failed: {e}")),
            },
        }
    }

    fn apply(&self, add: Vec<IpAddr>, remove: Vec<IpAddr>) -> Response {
        let mut set = self.blocked.lock().unwrap();

        // The never-block floor: refuse protected addresses outright. This is the
        // load-bearing safety check — it lives here so it holds even if the agent
        // is wrong or hostile.
        let mut rejected = Vec::new();
        let mut to_add = Vec::new();
        for ip in add {
            if is_protected_addr(ip) {
                rejected.push(ip);
            } else if !set.contains(&ip) {
                to_add.push(ip);
            }
        }

        // Enforce the cap (count only genuinely-new additions).
        if set.len() + to_add.len() > self.max_blocked {
            return err(format!(
                "block set cap reached ({}); refusing {} new",
                self.max_blocked,
                to_add.len()
            ));
        }

        let to_remove: Vec<IpAddr> = remove.into_iter().filter(|ip| set.contains(ip)).collect();

        if !to_add.is_empty() {
            if let Err(e) = self.applier.add(&to_add) {
                return err(format!("add failed: {e}"));
            }
            for ip in &to_add {
                set.insert(*ip);
            }
        }
        if !to_remove.is_empty() {
            if let Err(e) = self.applier.remove(&to_remove) {
                return err(format!("remove failed: {e}"));
            }
            for ip in &to_remove {
                set.remove(ip);
            }
        }

        audit(&format!(
            "apply: +{} -{} rejected {} total {}",
            to_add.len(),
            to_remove.len(),
            rejected.len(),
            set.len()
        ));

        Response::Applied {
            added: to_add,
            removed: to_remove,
            rejected,
            blocked_total: set.len(),
        }
    }
}

fn err(message: String) -> Response {
    audit(&format!("error: {message}"));
    Response::Error { message }
}

/// An optional audit-log file (used on Windows, where a service has no journald to
/// capture stderr). Set once at startup; every audit line is appended there too.
static AUDIT_LOG: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Route audit lines to a file as well as stderr (call once, before serving).
pub fn set_audit_log(path: std::path::PathBuf) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = AUDIT_LOG.set(path);
}

/// One audit line per change, to stderr — captured by journald under the shipped
/// systemd unit (and mirrored to the configured file on Windows, where a service
/// has no attached stderr). Every mutation of the privileged set is recorded.
pub(crate) fn audit(line: &str) {
    eprintln!("[netscope-enforcer] {line}");
    if let Some(path) = AUDIT_LOG.get() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = writeln!(f, "{ts} {line}");
        }
    }
}

// --- The socket server (Unix-only; the privileged channel) --------------------
#[cfg(unix)]
mod server;
#[cfg(unix)]
pub use server::serve;

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn authorization_matrix() {
        assert!(is_authorized(&AllowedPeers::Any, 1000));
        assert!(is_authorized(&AllowedPeers::RootOnly, 0));
        assert!(!is_authorized(&AllowedPeers::RootOnly, 1000));
        assert!(is_authorized(&AllowedPeers::Uid(1000), 1000));
        assert!(is_authorized(&AllowedPeers::Uid(1000), 0)); // root always
        assert!(!is_authorized(&AllowedPeers::Uid(1000), 1001));
    }

    #[test]
    fn never_block_floor_rejects_protected_even_when_asked() {
        let e = Enforcer::new(MockApplier::default(), DEFAULT_MAX_BLOCKED).unwrap();
        let resp = e.handle(Request::Apply {
            add: vec![
                ip("8.8.8.8"),       // public — accepted
                ip("127.0.0.1"),     // loopback — rejected
                ip("10.0.0.5"),      // private — rejected
                ip("192.168.1.20"),  // private — rejected
                ip("100.100.0.1"),   // CGNAT/tailnet — rejected
                ip("fd00::1"),       // ULA — rejected
                ip("2001:4860::64"), // public v6 — accepted
            ],
            remove: vec![],
        });
        match resp {
            Response::Applied {
                added,
                rejected,
                blocked_total,
                ..
            } => {
                assert_eq!(added, vec![ip("8.8.8.8"), ip("2001:4860::64")]);
                assert_eq!(rejected.len(), 5);
                assert_eq!(blocked_total, 2);
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        // The mock kernel set holds only the two public addresses.
        assert_eq!(e.blocked(), vec![ip("8.8.8.8"), ip("2001:4860::64")]);
    }

    #[test]
    fn apply_is_idempotent_and_remove_works() {
        let e = Enforcer::new(MockApplier::default(), DEFAULT_MAX_BLOCKED).unwrap();
        e.handle(Request::Apply {
            add: vec![ip("8.8.8.8")],
            remove: vec![],
        });
        // Re-adding the same address adds nothing.
        let resp = e.handle(Request::Apply {
            add: vec![ip("8.8.8.8")],
            remove: vec![],
        });
        if let Response::Applied { added, .. } = resp {
            assert!(added.is_empty());
        } else {
            panic!("expected Applied");
        }
        // Removing it empties the set.
        e.handle(Request::Apply {
            add: vec![],
            remove: vec![ip("8.8.8.8")],
        });
        assert!(e.blocked().is_empty());
    }

    #[test]
    fn cap_is_enforced() {
        let e = Enforcer::new(MockApplier::default(), 2).unwrap();
        let resp = e.handle(Request::Apply {
            add: vec![ip("8.8.8.8"), ip("9.9.9.9"), ip("1.1.1.1")],
            remove: vec![],
        });
        assert!(matches!(resp, Response::Error { .. }));
        assert!(e.blocked().is_empty(), "nothing applied when the cap trips");
    }

    #[test]
    fn clear_removes_all() {
        let e = Enforcer::new(MockApplier::default(), DEFAULT_MAX_BLOCKED).unwrap();
        e.handle(Request::Apply {
            add: vec![ip("8.8.8.8"), ip("9.9.9.9")],
            remove: vec![],
        });
        let resp = e.handle(Request::Clear);
        assert!(matches!(resp, Response::Cleared { removed: 2 }));
        assert!(e.blocked().is_empty());
    }

    #[test]
    fn ping_reports_version() {
        let e = Enforcer::new(MockApplier::default(), DEFAULT_MAX_BLOCKED).unwrap();
        assert_eq!(
            e.handle(Request::Ping),
            Response::Pong {
                version: PROTOCOL_VERSION
            }
        );
    }

    #[test]
    fn verify_reports_in_sync_when_applier_matches() {
        let e = Enforcer::new(MockApplier::default(), DEFAULT_MAX_BLOCKED).unwrap();
        e.handle(Request::Apply {
            add: vec![ip("8.8.8.8")],
            remove: vec![],
        });
        match e.handle(Request::Verify) {
            Response::Verified {
                in_sync,
                live,
                expected,
            } => {
                assert!(in_sync);
                assert_eq!(live, vec![ip("8.8.8.8")]);
                assert_eq!(expected, vec![ip("8.8.8.8")]);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn verify_detects_drift_when_os_state_diverges() {
        let e = Enforcer::new(MockApplier::default(), DEFAULT_MAX_BLOCKED).unwrap();
        e.handle(Request::Apply {
            add: vec![ip("8.8.8.8"), ip("9.9.9.9")],
            remove: vec![],
        });
        // Simulate an external change the enforcer's own bookkeeping never saw —
        // someone hand-edited the firewall, or a resync silently failed. Only the
        // OS-side mirror the applier reads back changes; `blocked()` (what the
        // enforcer *believes*) is untouched.
        e.applier.set.lock().unwrap().remove(&ip("9.9.9.9"));
        match e.handle(Request::Verify) {
            Response::Verified {
                in_sync,
                live,
                expected,
            } => {
                assert!(!in_sync);
                assert_eq!(live, vec![ip("8.8.8.8")]);
                assert_eq!(expected, vec![ip("8.8.8.8"), ip("9.9.9.9")]);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
