# Changelog

Notable changes to NETSCOPE, starting from the run-up to `v1.0.0`. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioned entries
begin at `v1.0.0`, the project's first tagged release.

## Unreleased

### Fixed
- **Auto-update was silently dead.** The repo's trunk branch is `latest`, not `main` —
  both `desktop-build.yml` and `windows-build.yml` only published their update manifest
  `if: github.ref == 'refs/heads/main'`, so a push to `latest` never published an
  update. Both workflows now trigger on and publish from `latest`.
- **Npcap packet capture was compiled out of the Tauri desktop build.** The bundled
  sidecar agent built without `--features pcap` and without the Npcap SDK on the CI
  runner, so `NETSCOPE_PCAP=1` was a no-op regardless of what was installed on the
  host. `desktop-build.yml` now fetches the Npcap SDK and builds with `--features
  pcap`; the Tauri shell sets `NETSCOPE_PCAP=1` by default when it spawns the sidecar.

### Added
- **The Windows enforcer (Warden E4, Windows).** The privilege-separated apply
  helper now ships for Windows too: a real Windows service (`netscope-enforcer`)
  behind a local named pipe, each connection authenticated by the client process
  token's user SID (the `SO_PEERCRED` analog), applying blocks as Windows Firewall
  rules in its own namespaced "NETSCOPE Warden" group. The never-block floor and
  the set cap live in the service; every change is audited to
  `%ProgramData%\netscope\enforcer.log`; rules are cleared on service stop
  (fail-open). Installed by `packaging/install-enforcer.ps1` (elevated); the agent
  auto-detects the well-known pipe, so the block panel's enforcement section
  lights up with no configuration.
- **The desktop app is now the headline Windows build**, and it bundles the
  enforcer: `netscope-enforcer.exe` plus its install/uninstall scripts ship in the
  app folder, so enforcement is one elevated script away from any desktop install.
- `SECURITY.md`, `CONTRIBUTING.md`, issue/PR templates, and this changelog.

### Changed
- **Unencrypted endpoints no longer render as washed-out grey spheres.** A
  plaintext endpoint keeps its category colour and instead wears an amber hazard
  signal — a rotating beacon band sweeping the shell plus a hot pulsing rim — so
  "unencrypted" reads as *at risk*, not *uninteresting*. The legend explains the
  beacon, and the `local` / `unknown` category hues moved off grey (steel blue /
  soft violet) so no node in the organism reads as a dead grey ball.
- **HUD visual refresh.** Deeper glass panels (layered gradients, stronger blur,
  soft shadows), cooler border palette that reserves the teal accent for meaning,
  thin quiet scrollbars, refined buttons with focus rings, and consistent radii
  across panels, tooltips, and overlays.
