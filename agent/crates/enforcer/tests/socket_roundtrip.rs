//! End-to-end over a real Unix socket: spin up the enforcer's serve loop with a
//! mock applier, then drive it as the agent would. Verifies the framing, the accept
//! path, and the never-block floor across the actual IPC boundary — no privilege and
//! no `nft` needed, so it runs anywhere Unix.

#![cfg(unix)]

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;

use netscope_enforcer::proto::{read_msg, write_msg, Request, Response};
use netscope_enforcer::{serve, AllowedPeers, Enforcer, MockApplier, DEFAULT_MAX_BLOCKED};

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

#[test]
fn agent_drives_the_enforcer_over_a_socket() {
    let dir = std::env::temp_dir().join(format!("netscope-enf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("enforcer.sock");

    let listener = UnixListener::bind(&sock).unwrap();
    let enforcer = Arc::new(Enforcer::new(MockApplier::default(), DEFAULT_MAX_BLOCKED).unwrap());
    // AllowedPeers::Any so the test's own UID is accepted without configuration.
    thread::spawn(move || serve(listener, enforcer, AllowedPeers::Any));

    let mut conn = UnixStream::connect(&sock).unwrap();

    // Ping → Pong.
    write_msg(&mut conn, &Request::Ping).unwrap();
    let resp: Response = read_msg(&mut conn).unwrap().unwrap();
    assert!(matches!(resp, Response::Pong { .. }));

    // Apply a public + a protected address; only the public one is blocked.
    write_msg(
        &mut conn,
        &Request::Apply {
            add: vec![ip("8.8.8.8"), ip("127.0.0.1")],
            remove: vec![],
        },
    )
    .unwrap();
    let resp: Response = read_msg(&mut conn).unwrap().unwrap();
    match resp {
        Response::Applied {
            added,
            rejected,
            blocked_total,
            ..
        } => {
            assert_eq!(added, vec![ip("8.8.8.8")]);
            assert_eq!(rejected, vec![ip("127.0.0.1")]);
            assert_eq!(blocked_total, 1);
        }
        other => panic!("expected Applied, got {other:?}"),
    }

    // List reflects it.
    write_msg(&mut conn, &Request::List).unwrap();
    let resp: Response = read_msg(&mut conn).unwrap().unwrap();
    assert_eq!(
        resp,
        Response::Blocked {
            blocked: vec![ip("8.8.8.8")]
        }
    );

    std::fs::remove_dir_all(&dir).ok();
}
