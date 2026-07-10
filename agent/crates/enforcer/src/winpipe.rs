//! The privileged channel on Windows: a **named pipe**. The mirror of the Unix
//! socket server, with the same trust posture translated to Win32:
//!
//! - The peer is authenticated by the **user SID of its process token**, read via
//!   `GetNamedPipeClientProcessId` → `OpenProcessToken` → `GetTokenInformation`
//!   — kernel-reported, not forgeable by the peer (the `SO_PEERCRED` analog).
//! - Belt and braces, the pipe itself carries a **DACL** that only SYSTEM,
//!   Administrators, and the configured desktop user can even connect through
//!   (`PIPE_REJECT_REMOTE_CLIENTS` shuts the network path off entirely). The
//!   explicit SID check is still the load-bearing gate.
//! - One connection at a time, many request/response frames per connection —
//!   identical to the Unix loop, over the same length-prefixed JSON protocol.
//!
//! This module also carries the **client** half (used by the agent): connect to
//! the pipe as an ordinary file handle, with the documented busy-retry dance, and
//! a cheap existence probe so the agent can auto-detect an installed enforcer.

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, WaitNamedPipeW,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::proto::{read_msg, write_msg, Request, Response};
use crate::{audit, Applier, Enforcer};

/// The well-known pipe name the desktop product looks for. Installing the service
/// under this name is the opt-in that lights enforcement up in the agent.
pub const DEFAULT_PIPE: &str = r"\\.\pipe\netscope-enforcer";

/// The local SYSTEM SID — services and the OS itself, the "root is always allowed"
/// analog on Windows.
const SYSTEM_SID: &str = "S-1-5-18";

/// Who may drive the enforcer, matched against the connecting process token's user
/// SID. SYSTEM is always allowed; the configured SID is the desktop user the
/// helper was installed for. No SID configured ⇒ SYSTEM only.
#[derive(Debug, Clone)]
pub struct AllowedSids {
    allowed: Vec<String>,
}

impl AllowedSids {
    pub fn new(user_sid: Option<String>) -> Self {
        let mut allowed = vec![SYSTEM_SID.to_string()];
        if let Some(sid) = user_sid {
            let sid = sid.trim().to_string();
            if !sid.is_empty() {
                allowed.push(sid);
            }
        }
        AllowedSids { allowed }
    }

    pub fn contains(&self, sid: &str) -> bool {
        self.allowed.iter().any(|s| s.eq_ignore_ascii_case(sid))
    }

    /// The SDDL for the pipe's DACL: SYSTEM + Administrators get full control, the
    /// configured user gets read/write (enough to connect and talk). `D:P` makes it
    /// protected — nothing inherited, nothing wider than what's spelled out here.
    fn sddl(&self) -> String {
        let mut s = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        for sid in self.allowed.iter().filter(|s| *s != SYSTEM_SID) {
            s.push_str(&format!("(A;;GRGW;;;{sid})"));
        }
        s
    }
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_err(context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("{context}: {}", io::Error::last_os_error()),
    )
}

/// A security descriptor parsed from SDDL, kept alive for the server's lifetime.
struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
}

impl PipeSecurity {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl_w = wide(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid NUL-terminated wide string in, descriptor out; checked.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bad SDDL: {e}")))?;
        }
        Ok(PipeSecurity { descriptor })
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.0.is_null() {
            // SAFETY: descriptor was allocated by the SDDL conversion with LocalAlloc.
            unsafe {
                let _ = LocalFree(HLOCAL(self.descriptor.0));
            }
        }
    }
}

/// Create one listening pipe instance. `first` asserts FIRST_PIPE_INSTANCE so a
/// squatter holding our name is detected at startup instead of silently splitting
/// clients between two owners.
fn create_instance(name_w: &[u16], sa: &SECURITY_ATTRIBUTES, first: bool) -> io::Result<HANDLE> {
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: valid wide name, a live SECURITY_ATTRIBUTES; the handle is checked.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            Some(sa as *const _),
        )
    };
    if handle.is_invalid() {
        return Err(last_err("CreateNamedPipeW"));
    }
    Ok(handle)
}

/// The user SID (as a string) of the process on the other end of the pipe —
/// kernel-reported, the Windows `SO_PEERCRED`.
fn client_sid(pipe: HANDLE) -> io::Result<String> {
    let mut pid = 0u32;
    // SAFETY: live pipe handle with a connected client; out param checked.
    unsafe {
        GetNamedPipeClientProcessId(pipe, &mut pid)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("client pid: {e}")))?;
    }

    // SAFETY: standard token-user query sequence; every handle is closed below and
    // every return code checked.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("open client: {e}")))?;

        let mut token = HANDLE::default();
        let token_res = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        let _ = CloseHandle(process);
        token_res.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("client token: {e}")))?;

        // Two-call pattern: size, then data.
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        if len == 0 {
            let _ = CloseHandle(token);
            return Err(io::Error::new(io::ErrorKind::Other, "token user size query failed"));
        }
        let mut buf = vec![0u8; len as usize];
        let info_res = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            len,
            &mut len,
        );
        let _ = CloseHandle(token);
        info_res.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("token user: {e}")))?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str = PWSTR::null();
        ConvertSidToStringSidW(token_user.User.Sid, &mut sid_str)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sid to string: {e}")))?;
        let sid = sid_str
            .to_string()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("sid utf16: {e}")))?;
        let _ = LocalFree(HLOCAL(sid_str.0 as *mut _));
        Ok(sid)
    }
}

/// Serve requests on the named pipe forever. Connections are handled one at a
/// time (same reasoning as the Unix server: tiny workload, no concurrent mutation
/// of the privileged set), but the **next** instance is created before the current
/// connection is served, so there is always a listening instance and clients never
/// see a not-found gap.
pub fn serve_windows<A: Applier>(
    pipe_name: &str,
    enforcer: Arc<Enforcer<A>>,
    allow: AllowedSids,
) -> io::Result<()> {
    let name_w = wide(pipe_name);
    let security = PipeSecurity::from_sddl(&allow.sddl())?;
    let sa = security.attributes();

    let mut next = create_instance(&name_w, &sa, true)?;
    audit(&format!("listening on {pipe_name} (allow={:?})", allow.allowed));
    loop {
        let pipe = next;
        // Block until a client connects. ERROR_PIPE_CONNECTED means one raced in
        // between create and connect — already connected, fine.
        // SAFETY: live pipe handle; the error path is handled.
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(e) = connected {
            if e.code() != ERROR_PIPE_CONNECTED.into() {
                // SAFETY: handle is live and owned here.
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                audit(&format!("connect error: {e}"));
                next = create_instance(&name_w, &sa, false)?;
                continue;
            }
        }
        // Keep an instance listening before we go serve this one.
        next = create_instance(&name_w, &sa, false)?;

        // Hand the connected instance to an owned File: Read/Write over the pipe,
        // and closing it disconnects the client.
        // SAFETY: `pipe` is a valid, owned handle; File takes ownership.
        let mut stream = unsafe { File::from_raw_handle(pipe.0 as _) };

        // Authenticate before serving a single frame.
        match client_sid(pipe) {
            Ok(sid) if allow.contains(&sid) => {
                if let Err(e) = serve_conn(&mut stream, &enforcer) {
                    audit(&format!("connection error: {e}"));
                }
            }
            Ok(sid) => {
                audit(&format!("refused connection from {sid}"));
                let _ = write_msg(
                    &mut stream,
                    &Response::Error {
                        message: "not authorized".into(),
                    },
                );
            }
            Err(e) => {
                audit(&format!("no peer credentials, refusing: {e}"));
                let _ = write_msg(
                    &mut stream,
                    &Response::Error {
                        message: "peer credentials unavailable".into(),
                    },
                );
            }
        }
    }
}

fn serve_conn<A: Applier>(stream: &mut File, enforcer: &Enforcer<A>) -> io::Result<()> {
    while let Some(req) = read_msg::<_, Request>(stream)? {
        let resp = enforcer.handle(req);
        write_msg(stream, &resp)?;
    }
    Ok(())
}

// --- The client half (used by the agent) --------------------------------------

/// Does an enforcer pipe exist right now? A cheap probe (no connection is
/// consumed) so the agent can distinguish "not installed" from "failed".
pub fn pipe_exists(pipe_name: &str) -> bool {
    let name_w = wide(pipe_name);
    // SAFETY: valid wide string; only the result is inspected. A ~zero timeout
    // checks existence: any failure other than file-not-found (busy, timeout)
    // still means an instance exists.
    let ok = unsafe { WaitNamedPipeW(PCWSTR(name_w.as_ptr()), 1) };
    if ok.as_bool() {
        return true;
    }
    io::Error::last_os_error().raw_os_error()
        != Some(windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.0 as i32)
}

/// Connect to the enforcer pipe as a byte stream, retrying briefly while all
/// instances are busy (the documented named-pipe dance).
pub fn client_connect(pipe_name: &str) -> io::Result<File> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
        {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "enforcer pipe busy",
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_sids_always_include_system() {
        let a = AllowedSids::new(None);
        assert!(a.contains("S-1-5-18"));
        assert!(!a.contains("S-1-5-21-1-2-3-1001"));

        let a = AllowedSids::new(Some("S-1-5-21-1-2-3-1001".into()));
        assert!(a.contains("S-1-5-18"));
        assert!(a.contains("S-1-5-21-1-2-3-1001"));
        assert!(a.contains("s-1-5-21-1-2-3-1001")); // case-insensitive
        assert!(!a.contains("S-1-5-21-1-2-3-1002"));
    }

    #[test]
    fn sddl_grants_only_the_configured_user() {
        let a = AllowedSids::new(Some("S-1-5-21-9-9-9-500".into()));
        let sddl = a.sddl();
        assert!(sddl.starts_with("D:P"));
        assert!(sddl.contains("(A;;GA;;;SY)"));
        assert!(sddl.contains("(A;;GA;;;BA)"));
        assert!(sddl.contains("(A;;GRGW;;;S-1-5-21-9-9-9-500)"));

        // No user configured: SYSTEM/Admins only, no extra ACE.
        let sddl = AllowedSids::new(None).sddl();
        assert_eq!(sddl, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    }

    #[test]
    fn sddl_parses_into_a_real_descriptor() {
        // The conversion API itself validates the SDDL — a syntax error here would
        // fail service startup, so pin it.
        let a = AllowedSids::new(Some("S-1-5-21-1-2-3-1001".into()));
        assert!(PipeSecurity::from_sddl(&a.sddl()).is_ok());
    }

    /// End-to-end over a real named pipe: serve on a random name, connect as a
    /// client (same process ⇒ same SID via the real token query), apply/list/clear.
    #[test]
    fn pipe_roundtrip_with_real_auth() {
        use crate::{MockApplier, DEFAULT_MAX_BLOCKED};

        let name = format!(
            r"\\.\pipe\netscope-enforcer-test-{}",
            std::process::id()
        );
        let enforcer = Arc::new(Enforcer::new(MockApplier::default(), DEFAULT_MAX_BLOCKED).unwrap());

        // Our own SID must be allowed for the loopback test to pass auth.
        let me = current_user_sid().expect("own sid");
        let allow = AllowedSids::new(Some(me));

        let server_name = name.clone();
        let server_enforcer = enforcer.clone();
        std::thread::spawn(move || {
            let _ = serve_windows(&server_name, server_enforcer, allow);
        });

        // Wait for the pipe to appear.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pipe_exists(&name) {
            assert!(Instant::now() < deadline, "pipe never appeared");
            std::thread::sleep(Duration::from_millis(20));
        }

        let mut conn = client_connect(&name).expect("connect");
        write_msg(
            &mut conn,
            &Request::Apply {
                add: vec!["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()],
                remove: vec![],
            },
        )
        .unwrap();
        let resp: Option<Response> = read_msg(&mut conn).unwrap();
        match resp.expect("reply") {
            Response::Applied {
                added,
                rejected,
                blocked_total,
                ..
            } => {
                assert_eq!(added, vec!["8.8.8.8".parse::<std::net::IpAddr>().unwrap()]);
                assert_eq!(rejected.len(), 1, "loopback refused by the floor");
                assert_eq!(blocked_total, 1);
            }
            other => panic!("expected Applied, got {other:?}"),
        }

        // Same connection, next frame: list then clear.
        write_msg(&mut conn, &Request::List).unwrap();
        let resp: Option<Response> = read_msg(&mut conn).unwrap();
        assert!(matches!(resp, Some(Response::Blocked { blocked }) if blocked.len() == 1));

        write_msg(&mut conn, &Request::Clear).unwrap();
        let resp: Option<Response> = read_msg(&mut conn).unwrap();
        assert!(matches!(resp, Some(Response::Cleared { removed: 1 })));
    }

    /// The current process' token user SID — test helper mirroring `client_sid`.
    fn current_user_sid() -> io::Result<String> {
        // SAFETY: same token-query sequence as client_sid, on our own process.
        unsafe {
            let process = windows::Win32::System::Threading::GetCurrentProcess();
            let mut token = HANDLE::default();
            OpenProcessToken(process, TOKEN_QUERY, &mut token)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
            let mut len = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let res = GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                len,
                &mut len,
            );
            let _ = CloseHandle(token);
            res.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut sid_str = PWSTR::null();
            ConvertSidToStringSidW(token_user.User.Sid, &mut sid_str)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
            let sid = sid_str
                .to_string()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
            let _ = LocalFree(HLOCAL(sid_str.0 as *mut _));
            Ok(sid)
        }
    }
}
