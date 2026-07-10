// NETSCOPE desktop shell.
//
// A thin native window over the existing web UI. On launch it starts the capture
// agent as a **sidecar** (a bundled binary next to the app), so the WebSocket feed
// is live before the window connects to it — exactly the same feed the browser
// build uses (the UI is compiled with VITE_AGENT_URL=ws://127.0.0.1:8787/ws, so it
// reaches the agent regardless of where the page itself is served from).
//
// It also lives in the **system tray**: closing the window hides it rather than
// quitting, so NETSCOPE keeps monitoring in the background. Left-click the tray icon
// to toggle the window; the tray menu shows/hides it or quits for real. Quitting —
// from the menu or a true exit — terminates the agent so no capture process lingers.
//
// Why a sidecar and not in-process: it keeps the agent a single, separately-built,
// separately-testable binary (the same one shipped headless), and preserves the
// architecture's deliberate WebSocket spine — the same agent can drive this native
// window *and* a phone over the tailnet (C3). The shell adds a window; it changes
// nothing about how data flows.

// No console window on Windows release builds — this is a GUI app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use std::time::Duration;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, WindowEvent};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;

/// Holds the agent child so it can be terminated when the app quits — we don't want
/// a stray capture process lingering after exit.
struct Agent(Mutex<Option<CommandChild>>);

/// Show + focus the main window (creating nothing — it always exists).
fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Hide the main window to the tray.
fn hide_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
}

/// Toggle window visibility (the tray left-click behaviour).
fn toggle_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
        } else {
            let _ = w.show();
            let _ = w.set_focus();
        }
    }
}

/// Kill the agent sidecar if it's still running. Idempotent — a second call is a
/// no-op, so it's safe from both the tray "Quit" and the exit event.
fn kill_agent(app: &AppHandle) {
    if let Some(agent) = app.try_state::<Agent>() {
        if let Some(child) = agent.0.lock().unwrap().take() {
            let _ = child.kill();
        }
    }
}

/// True when the main window is not something the user is currently looking
/// at — hidden to the tray, or minimized. Restarting to apply an update is
/// invisible in this state (the tray icon just blinks out and back); it would
/// be a jarring interruption otherwise, so the update loop only fires here.
fn is_backgrounded(app: &AppHandle) -> bool {
    match app.get_webview_window("main") {
        Some(w) => !w.is_visible().unwrap_or(true) || w.is_minimized().unwrap_or(false),
        None => true,
    }
}

/// Auto-update loop (fluid, Chrome/Slack-style — no button, no banner, no HUD
/// involvement). Checks a signed manifest on a fixed cadence; if a newer build
/// is available *and* the window isn't currently in view, downloads, installs,
/// and restarts straight into it. If the window *is* in view when a check
/// lands, the update is simply deferred to the next cycle — never applied out
/// from under someone looking at the scene.
///
/// This mirrors the single-exe product's own updater in spirit (signed/
/// integrity-checked artifact, opt-out via `NETSCOPE_NO_UPDATE`, never applied
/// silently behind a remote control surface) but drives the *whole installed
/// app* — shell, sidecar, and all — through Tauri's updater plugin, rather
/// than the agent's self-replace path (which only ever touched its own exe,
/// the wrong binary to update here).
///
/// Note: this exercises Tauri's Windows NSIS updater codepath, which cannot be
/// run or observed from this Linux dev/CI environment — it's built on the
/// documented `check` → `download_and_install` → `restart` sequence Tauri
/// ships as the canonical pattern, but real-machine verification on Windows is
/// the one step that has to happen outside this session.
async fn run_updater_loop(app: AppHandle) {
    if std::env::var_os("NETSCOPE_NO_UPDATE").is_some() {
        return;
    }
    // A short grace period before the first check, so it never competes with
    // the sidecar/window spinning up; then a slow, steady cadence — matching
    // the agent's own background-poll interval philosophy.
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
        if is_backgrounded(&app) {
            if let Err(e) = try_update(&app).await {
                eprintln!("[updater] check failed (will retry next cycle): {e}");
            }
        }
        tokio::time::sleep(Duration::from_secs(6 * 60 * 60)).await;
    }
}

async fn try_update(app: &AppHandle) -> tauri_plugin_updater::Result<()> {
    let Some(update) = app.updater()?.check().await? else {
        return Ok(());
    };
    eprintln!("[updater] update found — downloading in the background");
    update
        .download_and_install(
            |_chunk_len, _total_len| {},
            || eprintln!("[updater] download complete — installing"),
        )
        .await?;
    // The window may have come back into view during the download; honour
    // that rather than yanking it away with a restart mid-install-cycle.
    if is_backgrounded(app) {
        eprintln!("[updater] restarting into the updated build");
        kill_agent(app);
        app.request_restart();
    } else {
        // Not applied this cycle. The running process is still the old build,
        // so the next cycle's `check()` reports the same update again (a
        // harmless re-download, not a re-install) and retries the
        // background-check — it converges the first time the app is hidden.
        eprintln!("[updater] installed on disk — will apply once the window is hidden again");
    }
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // Spawn the bundled agent. NETSCOPE_NO_OPEN tells it not to pop a
            // browser (the Tauri window is the UI); it binds loopback:8787 as usual.
            // NETSCOPE_NO_UPDATE disables the agent's *own* self-updater — the
            // desktop product updates as a whole (shell + sidecar together)
            // through the Tauri updater below, so the agent's standalone
            // self-replace path (which would only ever touch its own exe,
            // never the installed shell) would just be a redundant, confusing
            // second update mechanism if left enabled.
            // NETSCOPE_PCAP=1 turns on the G5 packet-capture augmentation (this
            // sidecar is built with `--features pcap`, so the capability is
            // compiled in — see .github/workflows/desktop-build.yml). It needs
            // the Npcap driver installed on the host and capture privilege; when
            // either is missing it fails soft (packet_observer_from_env) and the
            // System panel reports why, falling back to table-only polling.
            let (mut rx, child) = app
                .shell()
                .sidecar("netscope-agent")?
                .env("NETSCOPE_NO_OPEN", "1")
                .env("NETSCOPE_NO_UPDATE", "1")
                .env("NETSCOPE_PCAP", "1")
                .spawn()?;

            app.manage(Agent(Mutex::new(Some(child))));

            // Auto-update (fluid, no banner/button — see `run_updater_loop`).
            tauri::async_runtime::spawn(run_updater_loop(app.handle().clone()));

            // Drain the agent's stdio so its pipes never fill and stall it. Lines
            // are forwarded to the desktop process' stderr for troubleshooting.
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                            eprint!("[agent] {}", String::from_utf8_lossy(&bytes));
                        }
                        CommandEvent::Terminated(payload) => {
                            eprintln!("[agent] exited: {:?}", payload.code);
                        }
                        _ => {}
                    }
                }
            });

            // --- System tray: keep NETSCOPE alive in the background ---
            let show = MenuItem::with_id(app, "show", "Show NETSCOPE", true, None::<&str>)?;
            let hide = MenuItem::with_id(app, "hide", "Hide to tray", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &hide, &sep, &quit])?;

            let mut tray = TrayIconBuilder::with_id("netscope")
                .menu(&menu)
                .tooltip("NETSCOPE — live network monitor")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main(app),
                    "hide" => hide_main(app),
                    "quit" => {
                        kill_agent(app);
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle_main(tray.app_handle());
                    }
                });
            // Reuse the app icon for the tray when one is configured.
            if let Some(icon) = app.default_window_icon().cloned() {
                tray = tray.icon(icon);
            }
            tray.build(app)?;

            Ok(())
        })
        // Closing the window hides it to the tray instead of quitting, so capture
        // keeps running. "Quit" (tray) is the only true exit.
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building the NETSCOPE desktop shell")
        .run(|app, event| {
            // Belt-and-braces: kill the agent on any real exit path.
            if let RunEvent::ExitRequested { .. } = event {
                kill_agent(app);
            }
        });
}
