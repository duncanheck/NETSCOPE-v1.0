# Manual test plan — Windows desktop build (the main build)

The checklist for validating a Windows desktop release by hand: the Tauri shell,
the bundled agent, the new plaintext-endpoint visual, the refreshed HUD, and the
Windows Warden enforcer (E4). Written for a clean-ish Windows 10/11 machine.

## What you need installed

| What | Why | Notes |
|---|---|---|
| **Rust (rustup, MSVC)** + **VS 2022 Build Tools (C++ workload)** | build the agent/enforcer/shell locally | `winget install Rustlang.Rustup Microsoft.VisualStudio.2022.BuildTools` (add the *Desktop development with C++* workload) |
| **Node 22 + pnpm 10** | frontend + Tauri CLI | already required by the repo |
| **WebView2 runtime** | the Tauri window | preinstalled on Win 11; the NSIS installer bootstraps it otherwise |
| **Npcap driver** (optional) | G5 packet capture | [npcap.com](https://npcap.com/#download), tick *WinPcap API-compatible Mode* |
| **NSIS** (optional) | only if building the installer locally | Tauri downloads it automatically during `pnpm tauri:build` |

Build the pieces:

```powershell
cd agent
cargo build --release -p netscope-agent -p netscope-enforcer   # add --features pcap if you have the Npcap SDK
cd ..\frontend
Copy-Item ..\agent\target\release\netscope-agent.exe    src-tauri\binaries\netscope-agent-x86_64-pc-windows-msvc.exe
Copy-Item ..\agent\target\release\netscope-enforcer.exe src-tauri\binaries\netscope-enforcer-x86_64-pc-windows-msvc.exe
pnpm install
pnpm tauri:build          # installer lands in src-tauri\target\release\bundle\nsis\
```

## 1. Desktop shell basics

- [ ] Run the NSIS installer; NETSCOPE appears in the Start menu with its icon.
- [ ] Launch it: a native window opens (no console, no browser), the organism
      appears within ~2 s and live connections populate the HUD list.
- [ ] Close the window → it hides to the **tray** (capture keeps running: hover
      the tray icon, tooltip present). Left-click the tray icon → window toggles.
- [ ] Tray menu → **Quit** → the window closes AND `netscope-agent.exe` is gone
      from Task Manager (nothing lingers).
- [ ] Reboot-free reinstall: run the installer again over itself — app still works.

## 2. The plaintext (unencrypted) endpoint visual — no more grey spheres

Generate plaintext traffic: `curl http://neverssl.com` (or visit
`http://neverssl.com` in a browser) while NETSCOPE is running.

- [ ] The endpoint's node keeps its **category colour** (it must NOT wash out to
      grey) and wears an **amber beacon**: a bright band slowly circling the
      sphere plus a warm pulsing rim.
- [ ] The bottom legend shows the pulsing **"amber beacon = unencrypted"** key.
- [ ] The HUD list row shows the amber `plaintext` tag; the inspector's
      *encryption* row reads `plaintext` in amber.
- [ ] No node anywhere reads as a flat grey ball: `local` endpoints are steel
      blue, `unknown` endpoints are soft violet (check the legend swatches match
      the scene).
- [ ] The exposure score drops and the amber "N plaintext" chip appears.

## 3. HUD refresh

- [ ] Panels look like deep glass: gradient surface, blur, soft shadow, cool
      blue-grey borders (teal reserved for accents), 14 px corners.
- [ ] Scrollbars in the connection list are thin and quiet, not stock chrome.
- [ ] Buttons glow subtly on hover; keyboard focus (Tab) draws a visible ring.
- [ ] Drag panels by the title bar, resize from the corner, collapse (—),
      reset (⟲) — all still work and persist across an app restart.
- [ ] `C` cinematic mode, `P` perf overlay, `?` help — all still toggle.

## 4. The Windows enforcer (Warden E4)

Setup: in an **elevated** PowerShell (the desktop bundle keeps the script in the
app's `resources\` folder; from a source checkout use `packaging\` instead, with
`-ExePath` pointing at the built exe):

```powershell
& "$env:LOCALAPPDATA\NETSCOPE\resources\install-enforcer.ps1"
```

- [ ] Script reports the service **Running**, your account SID authorized.
- [ ] `Get-Service netscope-enforcer` → Running; startup type Automatic.
- [ ] Restart NETSCOPE → System panel's **enforcement** row flips to
      `enforcer ready`; the block panel gains the **enforcement** section.

Blocking flow (use a disposable target — e.g. tick **plaintext** after loading
`http://neverssl.com`):

- [ ] **Preview** first: the block panel lists what would be cut and why.
- [ ] **Apply** requires the confirm step (never one-click).
- [ ] After apply: "N blocks active" appears; the blocked list shows the IPs;
      `Get-NetFirewallRule -Group 'NETSCOPE Warden'` shows the rules; reloading
      the plaintext site now fails.
- [ ] **Unblock** one row → rule updates, site loads again. **Unblock all** → the
      group is empty.
- [ ] Per-flow: select a node → inspector → **block this endpoint** → it appears
      in the blocked list; unblock from there.
- [ ] Never-block floor: try blocking a LAN flow (e.g. your router/printer) — the
      enforcer must refuse it (refusal surfaces in the panel), and
      `192.168.x.x`/`10.x` never appears in the firewall group.
- [ ] Audit: `%ProgramData%\netscope\enforcer.log` records every apply/unblock.
- [ ] Fail-open: `Stop-Service netscope-enforcer` → the firewall group empties
      (`Get-NetFirewallRule -Group 'NETSCOPE Warden'` → nothing); NETSCOPE's
      enforcement section degrades to "off" gracefully.
- [ ] Auth: from a *different* Windows account (or with the service reinstalled
      with `-User someoneelse`), NETSCOPE's apply must be refused ("not
      authorized" in the panel / a 502 from `/warden/apply`).
- [ ] Uninstall: `.\uninstall-enforcer.ps1` (elevated) → service gone, group
      empty, NETSCOPE back to generate-only.

## 5. Regression sweep (unchanged features)

- [ ] Threat feeds: System panel → *download free threat feeds* → known-bad
      toggle activates with an indicator count.
- [ ] GeoLite2: paste a MaxMind key in the System panel → geo/ASN enrich live.
- [ ] Pairing: from a phone on the same tailnet, redeem the pairing code and
      watch remotely; remote clients can *view* but `/warden/apply` refuses them.
- [ ] Npcap installed → System panel `packet capture: active (<device>)`; without
      it, `unavailable: …` and the app still works.
- [ ] Exports (⤓ csv / ⤓ json), narrator explain (offline rules at minimum),
      layouts + relationship edges + focus drill-down.

## Known limitations to keep in mind while testing

- Windows capture is TCP-only without Npcap (no UDP/QUIC/DNS nodes).
- Enforcement is IP-based: a CDN-fronted tracker may come back on a new IP.
- An open TCP connection can outlive its block until it next sends packets
  (reactive socket-kill is E5, not built).
- The enforcer service runs as LocalSystem; its safety comes from the narrow
  vocabulary (add/remove/list/clear in one group) + service-side floor + audit.
