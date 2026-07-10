//! The privileged channel: a Unix-domain socket. Each accepted connection's real
//! UID comes from the kernel (`SO_PEERCRED`, via [`UnixStream::peer_cred`]) — not
//! from anything the peer can forge — and is checked against the [`AllowedPeers`]
//! policy before a single request is served. One connection may carry many
//! request/response pairs until the peer hangs up.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use crate::proto::{read_msg, write_msg, Request, Response};
use crate::{is_authorized, AllowedPeers, Applier, Enforcer};

/// The connecting process' real UID, straight from the kernel via `SO_PEERCRED` —
/// not forgeable by the peer. (Replaces the still-unstable `UnixStream::peer_cred`.)
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid socket fd, a correctly-sized out buffer, and a matching length;
    // the return code is checked.
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Serve requests on `listener` forever. Connections are handled one at a time —
/// the workload is tiny and serializing keeps the privileged path simple to reason
/// about (no concurrent mutation of the set).
pub fn serve<A: Applier>(
    listener: UnixListener,
    enforcer: Arc<Enforcer<A>>,
    allow: AllowedPeers,
) -> ! {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle_conn(stream, &enforcer, &allow) {
                    eprintln!("[netscope-enforcer] connection error: {e}");
                }
            }
            Err(e) => eprintln!("[netscope-enforcer] accept error: {e}"),
        }
    }
    unreachable!("UnixListener::incoming is infinite")
}

fn handle_conn<A: Applier>(
    mut stream: UnixStream,
    enforcer: &Enforcer<A>,
    allow: &AllowedPeers,
) -> std::io::Result<()> {
    // Authenticate the peer by its real UID before doing anything.
    let uid = match peer_uid(&stream) {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("[netscope-enforcer] no peer credentials, refusing: {e}");
            let _ = write_msg(
                &mut stream,
                &Response::Error {
                    message: "peer credentials unavailable".into(),
                },
            );
            return Ok(());
        }
    };
    if !is_authorized(allow, uid) {
        eprintln!("[netscope-enforcer] refused connection from uid {uid}");
        let _ = write_msg(
            &mut stream,
            &Response::Error {
                message: "not authorized".into(),
            },
        );
        return Ok(());
    }

    // Serve requests until the peer closes the connection.
    let mut reader = stream.try_clone()?;
    while let Some(req) = read_msg::<_, Request>(&mut reader)? {
        let resp = enforcer.handle(req);
        write_msg(&mut stream, &resp)?;
    }
    Ok(())
}
