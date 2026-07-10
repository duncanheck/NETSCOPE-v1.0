# Desktop auto-update

The desktop app (the Tauri shell + NSIS installer) updates itself the way a
normal consumer app does: no banner, no button, no manual "check for updates."
It checks a signed manifest in the background, downloads and installs
silently, and restarts into the new build at a moment nobody's looking —
closer to Chrome or Slack than to the single-exe browser build's updater
panel.

## Why this isn't the same mechanism as the single-exe build

NETSCOPE already had a self-updater (`agent/crates/agent/src/update.rs`): a
stamped build checks a rolling manifest and, on click, downloads a new exe and
`self_replace`s the currently-running binary. That path only ever replaces
*its own running exe* — for the single-exe browser product, that's the whole
product. For the desktop app, the running exe the agent would replace is the
**sidecar** (`netscope-agent.exe` bundled inside the installer), not the
installed shell (`netscope-desktop.exe`, the thing Windows' Add/Remove
Programs actually tracks). Updating just the sidecar would leave the shell
stale, and the shell's own copy of the sidecar (re-bundled on every install)
would immediately overwrite it back on the next reinstall anyway.

Worse, before this was fixed, the desktop CI build (`desktop-build.yml`)
stamped the sidecar with a real build id from *its own* GitHub Actions
run-number sequence — a different, unrelated counter from the single-exe
build's (`windows-build.yml`) run-number sequence, since each workflow counts
its own runs independently. The sidecar's self-updater would fetch the
**single-exe build's** manifest (same hardcoded URL, since it's the same
agent binary/code) and compare its own build id against it — two numbers
from unrelated sequences, compared as if they meant the same thing. A "check
now" click in the desktop app's HUD could report a bogus "update available,"
and clicking through would download the single-exe `bundled-ui` build and
`self_replace` the sidecar with it. That bug is now closed two ways: the
sidecar is no longer stamped by `desktop-build.yml` (so it reports as a `dev`
build, hiding the legacy HUD banner entirely), and `NETSCOPE_NO_UPDATE` — set
explicitly when the shell spawns the sidecar — now disables the agent's
`/update/check` and `/update/apply` endpoints outright, not just its
background poll loop, so even a stray manual hit can't do anything.

The desktop app instead updates as a whole — shell, sidecar, and installer
payload together — through Tauri's own updater plugin
(`tauri-plugin-updater`), which is built for exactly this: a signed manifest,
a real installer swap, one call to restart.

## The flow

1. **Check.** ~30s after launch, then every 6 hours, `run_updater_loop`
   (`frontend/src-tauri/src/main.rs`) asks the updater plugin to check
   `plugins.updater.endpoints` in `tauri.conf.json` — a `desktop-latest`
   rolling GitHub pre-release. But only if the window isn't currently in
   view (hidden to the tray, or minimized) — a check itself is harmless, but
   there's no reason to even start one while someone's actively watching the
   scene.
2. **Download + install.** If the manifest's version is newer than the
   running build, `download_and_install` fetches the signed installer and
   runs it — silently (`plugins.updater.windows.installMode: "quiet"`).
3. **Restart, deferred to a safe moment.** If the window is *still* hidden
   after the install finishes, `AppHandle::request_restart()` exits and
   relaunches immediately — invisible from the outside; the tray icon blinks
   out and back. If the window came back into view during the download, the
   restart is skipped for this cycle; the *next* check (the process hasn't
   restarted, so it's still running the old build) reports the same update
   again and retries. It converges the first time the window is hidden —
   worst case, a harmless redundant download every 6 hours until then.

No JS is involved — this is pure Rust in the shell, so it works identically
whether or not the window has ever been opened, and it never touches the
shared web HUD (which stays exclusively the single-exe build's territory).

## Signing

Every desktop build is signed with a dedicated minisign keypair — real
artifact signing, not just an integrity hash (the single-exe path is
SHA-256-only; see `ARCHITECTURE.md`'s open-decisions table). The public key
lives in `tauri.conf.json` (`plugins.updater.pubkey`); the private key is a
CI secret, never committed.

**One-time repo setup**, required before the desktop-latest channel can
publish anything (builds still succeed without it — see below — they just
don't produce a signed manifest, so nothing auto-updates yet):

1. Add two repository secrets (Settings → Secrets and variables → Actions):
   - `TAURI_UPDATER_PRIVATE_KEY`
   - `TAURI_UPDATER_PRIVATE_KEY_PASSWORD`
2. That's it — `desktop-build.yml` picks them up automatically on the next
   push to `main` and starts publishing `desktop-latest`.

If you ever need to rotate the key: generate a new one with
`pnpm tauri signer generate -w <path>` from `frontend/`, update
`plugins.updater.pubkey` in `tauri.conf.json` to the new public key, and
replace both secrets. Existing installs won't be able to verify a build
signed with the new key against their embedded old public key — treat a key
rotation like a breaking change and communicate it (e.g. a pinned release
note), since silently-orphaned installs would need a fresh manual download.

**Without the secrets configured**, `desktop-build.yml` still builds and
uploads the installer as a build artifact (unsigned) exactly as before; the
`publish desktop update manifest` and `publish rolling desktop release` steps
are skipped (gated on the secret being present), so no broken/unsigned
manifest is ever published. `createUpdaterArtifacts: true` in
`tauri.conf.json` is what makes the bundler *attempt* to sign — if that turns
out to require the key to even build (rather than degrading gracefully), the
first sign of it will be a clear failure in that CI step, not a silent bad
state; this is one of the pieces that could only be confirmed by actually
running the workflow.

## What's honestly unverified

This was built and compile-checked (`cargo check`/`clippy`, with the
project's Linux Tauri build deps installed) entirely from a Linux
environment with no Windows runtime available. What that means concretely:

- The Rust code compiles clean and follows Tauri's documented
  `check` → `download_and_install` → `request_restart` pattern, but the
  actual Windows NSIS silent-install-and-relaunch sequence has never been
  observed running.
- Whether an unsigned `createUpdaterArtifacts: true` build hard-fails or
  degrades gracefully (see above) is inferred, not confirmed.
- The "restart only when hidden" gate is straightforward logic
  (`WebviewWindow::is_visible`/`is_minimized`), but its *feel* — whether the
  tray-icon blink is as unobtrusive in practice as intended — needs a real
  install to judge.

The first real desktop-build.yml run on Windows CI (once the two secrets are
added) is the actual verification step for all of this.
