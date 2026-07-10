//! `netscope-enforcer` — the privileged helper daemon (E4).
//!
//! Runs as a dedicated service with only `CAP_NET_ADMIN` (see the shipped systemd
//! unit), listens on a Unix socket, and applies block/unblock requests from the
//! agent into its own `inet netscope` nftables table. Configured entirely by env:
//!
//! - `NETSCOPE_ENFORCER_SOCKET`: socket path (default `/run/netscope/enforcer.sock`)
//! - `NETSCOPE_ENFORCER_ALLOW_UID`: UID permitted to drive it; unset ⇒ root only
//! - `NETSCOPE_ENFORCER_MAX_BLOCKED`: block-set cap (default 4096)
//! - `NETSCOPE_ENFORCER_DRY_RUN=1`: validate nft scripts (`nft -c`) without applying,
//!   so the daemon can run unprivileged for a smoke test
//! - `NETSCOPE_ENFORCER_MOCK=1`: keep blocks in memory only (tests/demos)

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;

    use netscope_enforcer::apply::{Applier, MockApplier, NftApplier};
    use netscope_enforcer::{serve, AllowedPeers, Enforcer, DEFAULT_MAX_BLOCKED};

    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());

    let socket_path =
        env("NETSCOPE_ENFORCER_SOCKET").unwrap_or_else(|| "/run/netscope/enforcer.sock".into());
    let allow = match env("NETSCOPE_ENFORCER_ALLOW_UID").and_then(|s| s.parse::<u32>().ok()) {
        Some(uid) => AllowedPeers::Uid(uid),
        None => AllowedPeers::RootOnly,
    };
    let max_blocked = env("NETSCOPE_ENFORCER_MAX_BLOCKED")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_BLOCKED);
    let dry_run = env("NETSCOPE_ENFORCER_DRY_RUN").is_some();
    // A test affordance: keep blocks in memory only, never touching nft — lets the
    // whole agent→enforcer path be exercised without privilege.
    let mock = env("NETSCOPE_ENFORCER_MOCK").is_some();

    // Ensure the socket's parent directory exists (systemd's RuntimeDirectory does
    // this in production; do it ourselves for ad-hoc runs).
    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // A stale socket from a previous run would make bind() fail.
    let _ = std::fs::remove_file(&socket_path);

    let applier: Box<dyn Applier> = if mock {
        Box::new(MockApplier::default())
    } else if dry_run {
        Box::new(NftApplier::checking())
    } else {
        Box::new(NftApplier::new())
    };
    let enforcer = match Enforcer::new(applier, max_blocked) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("[netscope-enforcer] could not initialise firewall: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[netscope-enforcer] cannot bind {socket_path}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    // The socket is reachable by the unprivileged agent; the SO_PEERCRED check is
    // what authorizes, not the file mode. 0o666 keeps it connectable across users.
    let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666));

    eprintln!(
        "[netscope-enforcer] listening on {socket_path} (allow={allow:?}, cap={max_blocked}, dry_run={dry_run}, mock={mock})"
    );
    serve(listener, enforcer, allow);
}

// --- Windows: the E4 follow-up, landed --------------------------------------
//
// The same enforcer core behind a **named pipe** (`\\.\pipe\netscope-enforcer`),
// authenticated by the connecting process token's user SID, applying blocks as
// Windows Firewall rules in the namespaced "NETSCOPE Warden" group. Two ways in:
//
//   netscope-enforcer.exe                 console mode (elevated shell) — testing
//   netscope-enforcer.exe --service       under the SCM (installed by
//                                         packaging/install-enforcer.ps1)
//
// Configuration, by env var or flag (flags win; both work for a service because
// ImagePath arguments arrive in argv):
//
// - NETSCOPE_ENFORCER_PIPE      / --pipe <name>        (default \\.\pipe\netscope-enforcer)
// - NETSCOPE_ENFORCER_ALLOW_SID / --allow-sid <SID>    user allowed to drive it;
//                                                      unset ⇒ SYSTEM only
// - NETSCOPE_ENFORCER_MAX_BLOCKED / --max-blocked <n>  block-set cap (default 4096)
// - NETSCOPE_ENFORCER_DRY_RUN=1 / --dry-run            validate cmdlets with -WhatIf,
//                                                      no privilege, no change
// - NETSCOPE_ENFORCER_MOCK=1    / --mock               in-memory only (tests/demos)
// - NETSCOPE_ENFORCER_LOG       / --log <path>         audit-log file (service mode
//                                                      defaults to %ProgramData%\netscope\enforcer.log)

#[cfg(windows)]
#[derive(Clone, Debug)]
struct WinConfig {
    pipe: String,
    allow_sid: Option<String>,
    max_blocked: usize,
    dry_run: bool,
    mock: bool,
    log: Option<std::path::PathBuf>,
    service: bool,
}

#[cfg(windows)]
fn win_config() -> WinConfig {
    use netscope_enforcer::{DEFAULT_MAX_BLOCKED, DEFAULT_PIPE};

    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
    let mut cfg = WinConfig {
        pipe: env("NETSCOPE_ENFORCER_PIPE").unwrap_or_else(|| DEFAULT_PIPE.to_string()),
        allow_sid: env("NETSCOPE_ENFORCER_ALLOW_SID"),
        max_blocked: env("NETSCOPE_ENFORCER_MAX_BLOCKED")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_BLOCKED),
        dry_run: env("NETSCOPE_ENFORCER_DRY_RUN").is_some(),
        mock: env("NETSCOPE_ENFORCER_MOCK").is_some(),
        log: env("NETSCOPE_ENFORCER_LOG").map(Into::into),
        service: false,
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match args[i].as_str() {
            "--service" => cfg.service = true,
            "--dry-run" => cfg.dry_run = true,
            "--mock" => cfg.mock = true,
            "--pipe" => {
                if let Some(v) = take(&mut i) {
                    cfg.pipe = v;
                }
            }
            "--allow-sid" => cfg.allow_sid = take(&mut i),
            "--max-blocked" => {
                if let Some(n) = take(&mut i).and_then(|v| v.parse().ok()) {
                    cfg.max_blocked = n;
                }
            }
            "--log" => cfg.log = take(&mut i).map(Into::into),
            other => eprintln!("[netscope-enforcer] ignoring unknown argument {other}"),
        }
        i += 1;
    }
    cfg
}

/// Build the enforcer from config and serve the pipe. Shared by console and
/// service mode; only returns on a fatal setup/serve error.
#[cfg(windows)]
fn win_serve(cfg: &WinConfig) -> Result<(), String> {
    use std::sync::Arc;

    use netscope_enforcer::apply::{Applier, MockApplier};
    use netscope_enforcer::{serve_windows, AllowedSids, Enforcer, WfwApplier};

    if let Some(log) = &cfg.log {
        netscope_enforcer::set_audit_log(log.clone());
    }

    let applier: Box<dyn Applier> = if cfg.mock {
        Box::new(MockApplier::default())
    } else if cfg.dry_run {
        Box::new(WfwApplier::checking())
    } else {
        Box::new(WfwApplier::new())
    };
    let enforcer = Enforcer::new(applier, cfg.max_blocked)
        .map_err(|e| format!("could not initialise firewall: {e}"))?;
    let enforcer = Arc::new(enforcer);

    // Publish the handle so the service Stop control can clear blocks (fail-open:
    // NETSCOPE-managed blocks live only while the enforcer runs — a stopped
    // service must not leave orphaned rules nothing can list or undo).
    win_service::set_running(enforcer.clone());

    eprintln!(
        "[netscope-enforcer] listening on {} (allow={:?}, cap={}, dry_run={}, mock={})",
        cfg.pipe, cfg.allow_sid, cfg.max_blocked, cfg.dry_run, cfg.mock
    );
    serve_windows(&cfg.pipe, enforcer, AllowedSids::new(cfg.allow_sid.clone()))
        .map_err(|e| format!("pipe server failed: {e}"))
}

#[cfg(windows)]
mod win_service {
    //! SCM integration: the thinnest possible wrapper so the service is exactly
    //! the console daemon plus a Stop handler.

    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    use netscope_enforcer::apply::Applier;
    use netscope_enforcer::{Enforcer, Request};
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const SERVICE_NAME: &str = "netscope-enforcer";

    /// The live enforcer, for the Stop handler's fail-open clear. Boxed applier
    /// because the daemon picks its backend at runtime.
    #[allow(clippy::type_complexity)]
    static RUNNING: OnceLock<Mutex<Option<Arc<Enforcer<Box<dyn Applier>>>>>> = OnceLock::new();

    pub fn set_running(e: Arc<Enforcer<Box<dyn Applier>>>) {
        let cell = RUNNING.get_or_init(|| Mutex::new(None));
        *cell.lock().unwrap() = Some(e);
    }

    fn clear_on_stop() {
        if let Some(cell) = RUNNING.get() {
            if let Some(e) = cell.lock().unwrap().take() {
                let _ = e.handle(Request::Clear);
            }
        }
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_launch_args: Vec<std::ffi::OsString>) {
        if let Err(e) = run_service() {
            eprintln!("[netscope-enforcer] service error: {e}");
        }
    }

    fn run_service() -> windows_service::Result<()> {
        let status_handle = service_control_handler::register(SERVICE_NAME, |control| {
            match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    // Fail-open: drop every block, report stopped, and exit. The
                    // serve loop blocks in ConnectNamedPipe, so a clean process
                    // exit is the honest way out of a minimal helper.
                    clear_on_stop();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        })?;

        let running = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        };
        status_handle.set_service_status(running.clone())?;

        // The Stop handler above runs on an SCM thread; when it fires we clear and
        // then exit the whole process from here by watching for the cleared state.
        let cfg = super::win_config();
        let serve_result = std::thread::spawn(move || super::win_serve(&cfg));

        // Wait until either the server dies or Stop cleared the enforcer handle.
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let stopped = RUNNING
                .get()
                .map(|c| c.lock().unwrap().is_none())
                .unwrap_or(false);
            if stopped || serve_result.is_finished() {
                break;
            }
        }

        status_handle.set_service_status(ServiceStatus {
            current_state: ServiceState::Stopped,
            ..running
        })?;
        std::process::exit(0);
    }

    pub fn dispatch() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let cfg = win_config();
    if cfg.service {
        if let Err(e) = win_service::dispatch() {
            eprintln!("[netscope-enforcer] cannot start as a service: {e}");
            return std::process::ExitCode::FAILURE;
        }
        return std::process::ExitCode::SUCCESS;
    }
    // Console mode: same daemon, foreground (run from an elevated shell, or use
    // --dry-run / --mock without privilege).
    match win_serve(&cfg) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[netscope-enforcer] {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("netscope-enforcer supports Linux (Unix socket) and Windows (named pipe) only");
}
