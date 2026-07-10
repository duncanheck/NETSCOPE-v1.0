# NETSCOPE

*A live, beautiful map of where your machine is actually talking — built on a
rigorous systems core.*

[![CI](https://github.com/duncanheck/NETSCOPEv1/actions/workflows/ci.yml/badge.svg)](https://github.com/duncanheck/NETSCOPEv1/actions/workflows/ci.yml)
[![Desktop build (Tauri)](https://github.com/duncanheck/NETSCOPEv1/actions/workflows/desktop-build.yml/badge.svg)](https://github.com/duncanheck/NETSCOPEv1/actions/workflows/desktop-build.yml)
[![Windows build](https://github.com/duncanheck/NETSCOPEv1/actions/workflows/windows-build.yml/badge.svg)](https://github.com/duncanheck/NETSCOPEv1/actions/workflows/windows-build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

<!--
Demo GIF: drop docs/media/demo.gif (see docs/media/README.md for spec), then swap
the line below in for this comment block:
![NETSCOPE demo](docs/media/demo.gif)
-->
🎥 **Demo GIF coming shortly** — recording in progress.

NETSCOPE watches the network connections leaving your computer and renders them as
a deep-sea bioluminescent organism: every endpoint a softly pulsing node, every
active flow a luminous tendril reaching out from a central core that is *you*.
Under the visualization sits a real systems project — a Rust agent that captures
connection state with **measured** overhead, attributes every flow to its owning
process, enriches it (reverse-DNS, geo/ASN, tracker & security flags), and streams
it over a versioned, self-describing wire protocol.

## Try it in 60 seconds

1. Download the **desktop installer** from the latest
   [desktop-build](../../actions/workflows/desktop-build.yml) run (Artifacts) or a
   tagged [Release](../../releases).
2. Run it, then launch **NETSCOPE** from the Start menu.
3. Your machine's live connections appear as the organism. No terminal, no config.

Prefer a single portable `.exe` with nothing to install, or want packet capture /
remote viewing / firewall generation? See [Run it](#run-it) below — same agent, more
knobs.

## The thesis

A beautiful demo on top of a rigorous core. The visualizer proves
rendering/performance engineering; the Rust agent proves systems engineering; the
remote path proves distributed thinking; the writeups prove the thinking itself.
Most portfolios have one half. This has both — and the load-bearing claims are
either tested in CI or measured by a script you can re-run.

## Status

Four tracks run interleaved. Where a milestone landed, it links to the artifact
that proves it.

**Track A — the agent (systems depth)**

| | Milestone | State |
|---|---|---|
| A1 | End-to-end spine (agent ↔ frontend over the transport) | ✅ |
| A2 | Capture loop — connection-table polling, process-attributed (Linux + Windows) | ✅ |
| A3 | The capture→protocol **SPSC ring** + benchmark ([`docs/ringbuffer.md`](docs/ringbuffer.md)) | ✅ |
| A4 | Enrichment — reverse-DNS, GeoLite2, tracker/CDN classification, security flags | ✅ |
| A5 | Versioned wire protocol — JSON/MessagePack negotiation, enforced compat ([`docs/protocol.md`](docs/protocol.md)) | ✅ |
| A6 | Overhead benchmark ([table below](#agent-overhead)) | ✅ |

**Track B — the organism (rendering showcase)**

| | Milestone | State |
|---|---|---|
| B1 | Frontend skeleton (Vite + React + TS + R3F + Zustand) | ✅ |
| B2 | Deep-ocean environment (half-res fBm + capability gate) | ✅ |
| B3 | Organism nodes (instanced, vertex-displaced, fresnel) | ✅ |
| B4 | Tendrils (GPU ribbons, traffic motes) | ✅ |
| B5 | Performance pass + writeup + worker force layout ([`docs/performance.md`](docs/performance.md)) | ✅ |
| B6 | True bloom (EffectComposer / UnrealBloomPass, capability-gated) | ✅ |

**Track C — the bridge (distributed)** — C1 transport abstraction ✅ (mock and
WebSocket are indistinguishable to the UI), C2 pairing/token auth ✅, C3 Tailscale
reachability ✅ ([watch from your phone](#watch-from-your-phone-c2--c3--the-remote-path)),
C4 reconnect (exponential backoff) + client-driven resync ✅. C5 relay ⬜.
**Track D — the narrator (AI layer)** — D1 scrubbing pipeline ✅ (a pure, tested
redaction boundary, [`docs/scrubbing.md`](docs/scrubbing.md)); D2 structured explain
✅ — pick your AI in the HUD: **built-in offline rules**, a **local model via
Ollama** (free, private — the menu auto-detects the models you've already pulled
and lets you pick one), or **Claude** (`ANTHROPIC_API_KEY`); every provider sees
only scrubbed data. D3 eval ✅ — the classification the narrator rests on is
measured on a labeled set: **83.3 % category accuracy, 71.4 % tracker recall, 100 %
plaintext detection**, failures and all ([`docs/eval.md`](docs/eval.md)).

**Track E — the Warden (sight into action)** — turn NETSCOPE from a viewer into a
control: block trackers, plaintext exfil, and known-bad endpoints via the OS's own
firewall, free and opt-in. E1 block-policy engine + dry-run ✅ (zero privilege, fixed
precedence with a protected floor), E2 free threat-intel feeds ✅ (a license-aware
downloader + host/IP matching), E3 native firewall generator ✅ (nftables/netsh/pf,
injection-proof), E4 the privilege-separated enforcer ✅ (**Linux and Windows** — a
hardened `CAP_NET_ADMIN` helper over an `SO_PEERCRED`-authenticated Unix socket, and
a Windows service over a SID-authenticated named pipe editing its own Windows
Firewall group; both hold the never-block floor themselves), E6 the blocking UX ✅
(preview→confirm apply, live blocked list, per-flow block, audit log). E5 reactive
socket-kill ⬜. Spec: [`planning/WARDEN.md`](planning/WARDEN.md).

**Packaging** — beyond the single-exe browser build, a **Tauri desktop app** (native
window + system tray, agent bundled as a sidecar; [run it](#on-windows--the-native-desktop-app-tauri))
and **self-update** (the Windows product checks a rolling release and applies
integrity-checked, notify-then-apply binary swaps) both ship.

The full plan, with the skill each milestone forces, is
[`planning/ROADMAP.md`](planning/ROADMAP.md).

## Run it

### On Windows — the desktop app (the main build)

**This is the build most people should run.** A native app —
[Tauri](https://tauri.app) shell, WebView2 window — with the capture agent bundled
as a sidecar and an installer that adds a Start-menu entry and app icon. No
console, no browser tab, no `localhost` URL.

1. Download the installer from the latest **desktop-build** run (Actions tab →
   *Artifacts*) or a tagged [Release](../../releases).
2. Run it, then launch **NETSCOPE** from the Start menu. The agent starts in the
   background; the organism appears in the window.

It lives in the **system tray**: closing the window hides it (capture keeps
running), left-clicking the tray icon toggles the window, and the tray menu
shows/hides it or **Quit**s — which also stops the agent so nothing lingers. That
makes it a proper always-on background monitor.

**It updates itself, fluidly.** No banner, no button — a background check every
few hours downloads and installs a signed update silently, restarting only at a
moment the window isn't in view. Details, signing setup, and honest caveats in
[`docs/desktop-update.md`](docs/desktop-update.md).

Nothing about the data path changes — the UI still talks to the agent over the same
loopback WebSocket the browser build uses, so the phone-pairing path (C2 + C3) keeps
working. The shell only swaps the browser for a native window. Built on a real Windows
runner ([`desktop-build.yml`](.github/workflows/desktop-build.yml)). Build it locally
with `cd frontend && pnpm install && pnpm tauri:build` (needs the
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) — WebView2 on Windows,
webkit2gtk on Linux); `pnpm tauri:dev` runs it against the Vite dev server.

**Packet capture (G5) is on by default in this build.** The bundled sidecar is
compiled with the `pcap` feature and launched with `NETSCOPE_PCAP=1`, so it tries
to open a capture device on startup — but the [Npcap](https://npcap.com/#download)
driver is a separate, one-time **system install** this app can't do for you (it's a
kernel driver, not something a CI build or an NSIS installer script can silently
provision). Install Npcap first (check "Install Npcap in WinPcap API-compatible
Mode" during its setup), then launch NETSCOPE — the System panel's "packet capture"
row reads `active (<device>)` once it's working, or the specific reason (no driver,
no permission, etc.) when it isn't. Without Npcap installed, the app still runs
fine on the table-polling path alone (System panel shows `unavailable: ...`).

**Blocking is one script away (Warden E4, Windows).** The app folder ships the
privilege-separated enforcer service and its installer. To turn the Warden's
preview into actual blocks, in an **elevated** PowerShell run
`& "$env:LOCALAPPDATA\NETSCOPE\resources\install-enforcer.ps1"`. That registers
the `netscope-enforcer` Windows service:
it listens on an authenticated local named pipe (only *your* account and SYSTEM
may drive it), edits **only its own** `NETSCOPE Warden` Windows Firewall group,
holds the never-block floor itself (loopback / LAN / tailnet can never be cut),
audits every change to `%ProgramData%\netscope\enforcer.log`, and clears its
rules when stopped. NETSCOPE detects the service automatically — the block
panel's enforcement section lights up. Remove it any time with
`.\uninstall-enforcer.ps1`. Without the service, NETSCOPE stays generate-only.

### On Windows — the single-exe build (portable alternative)

Prefer a single portable binary with nothing to install? NETSCOPE also ships as a
**self-contained `netscope.exe`**: the React UI is compiled and embedded into the
Rust agent, so there's no installer and no separate web server.

1. Download `netscope.exe` from the **[latest](../../releases/tag/latest)** rolling
   build, the latest **windows-build** run (Actions tab → *Artifacts*), or a tagged
   [Release](../../releases).
2. Double-click it. A console shows status, your browser opens to
   `http://127.0.0.1:8787`, and your machine's live TCP connections appear as the
   organism. Close the console to stop.

**It keeps itself current.** Every push to `main` publishes a new rolling build to
the `latest` release. The agent checks on launch and then every few hours, and the
HUD's **updater panel** shows the running build and the last check so you can see it
working — with a **check now** button to re-check on demand. When a newer build
exists, one click downloads the new exe, verifies its SHA-256, and swaps the binary
in place; you just restart. No reinstalling. Updates are **notify-then-apply** (never
silent), the download is integrity-checked over HTTPS, and *applying* is loopback-only
— a remote paired device can't push a binary onto your machine. Opt out with
`NETSCOPE_NO_UPDATE=1`; local `cargo run` builds (unstamped) never check. The
mechanics and trust posture are in [`docs/threat-model.md`](docs/threat-model.md).

It binds to **loopback only** and the WebSocket handshake rejects non-local origins
([`docs/threat-model.md`](docs/threat-model.md)); no admin rights needed. The
binary is built and smoke-checked on a real Windows runner
([`windows-build.yml`](.github/workflows/windows-build.yml)).

> **Windows capture is TCP-only in v1** — the Windows owner-PID UDP table has no
> remote address, so QUIC/HTTP-3 and DNS don't appear. Sub-250 ms connections are
> missed too (inherent to polling; the documented Npcap path removes both).

### From source (development)

```bash
# Agent — captures connections, serves the WS feed at ws://127.0.0.1:8787/ws
cd agent && cargo run -p netscope-agent

# Frontend — mock feed by default; toggle to the live agent in the HUD
cd frontend && pnpm install && pnpm dev        # http://localhost:5173
```

Build the single-exe product locally: `cd frontend && VITE_TRANSPORT=websocket
pnpm build`, then `cargo run -p netscope-agent --features bundled-ui`.

**Optional — geo/ASN enrichment.** Reverse-DNS, classification, and security flags
work out of the box. City + ASN need MaxMind's GeoLite2 databases, which their
license forbids redistributing — so NETSCOPE downloads them with *your* free key,
never bundles them. The easy path (G3.2): open the **System panel** in the UI,
paste a free [license key](https://www.maxmind.com/en/geolite2/signup), click
**enable** — the agent downloads both databases and turns enrichment on live, no
restart. The key is saved to the agent's config file
(`~/.config/netscope/config.json`, `%APPDATA%\netscope` on Windows;
`NETSCOPE_CONFIG_DIR` overrides) so a refresh never asks twice. The terminal path
still works and env vars always win:

```bash
MAXMIND_LICENSE_KEY=xxxxx ./scripts/download-geoip.sh   # or .ps1 on Windows
```

Files land in `./geoip` (override with `NETSCOPE_GEOIP_DIR`); absent them the agent
runs fine with `asn`/`location` empty.

**Optional — reputation blocking (Warden E2).** The Warden can flag flows whose host
or remote IP is on a free, public threat feed. Same pattern: NETSCOPE ships the
*downloader*, not the data, since feeds carry their own licenses and update
constantly. The easy path: the System panel's **download free threat feeds**
button fetches and hot-loads them in one click. The terminal path:

```bash
./scripts/download-threatfeeds.sh   # or .ps1 on Windows
```

Either fetches StevenBlack hosts (ads/malware, MIT), abuse.ch URLhaus + Feodo (CC0), and
FireHOL level-1 (public) into `./threatfeeds` (override with `NETSCOPE_THREAT_DIR`). The
HUD's block panel then offers a **known-bad lists** toggle, and `GET /warden/threats`
(loopback) reports what's loaded. Absent any feed, the toggle is simply off.

**Optional — actual enforcement (Warden E4).** By default the Warden only
*generates* firewall rules you apply by hand — zero privilege. To have NETSCOPE apply
them, run the privilege-separated `netscope-enforcer` helper for your OS:

- **Windows** — a service driving Windows Firewall (its own namespaced
  `NETSCOPE Warden` rule group), authenticated per-connection by the client
  process token's **SID** over a local named pipe. Install it elevated with
  [`packaging/install-enforcer.ps1`](packaging/install-enforcer.ps1) (the desktop
  app bundles both the exe and the script in its install folder); the agent
  auto-detects the service's well-known pipe. Blocks are audited to
  `%ProgramData%\netscope\enforcer.log` and cleared when the service stops.
- **Linux** — a hardened systemd service holding only `CAP_NET_ADMIN` that edits
  its own `inet netscope` nftables table and authenticates the agent by UID
  (`SO_PEERCRED`) over a Unix socket. Install it from
  [`packaging/netscope-enforcer.service`](packaging/netscope-enforcer.service), then
  point the agent at it with `NETSCOPE_ENFORCER_SOCKET=/run/netscope/enforcer.sock`.

Both **enforce the never-block floor themselves** (loopback / LAN / tailnet can
never be cut, even by a hostile request). The HUD's block panel then gains an
**enforcement** section (preview → confirm apply, a live blocked list with one-click
unblock / unblock-all, a per-endpoint block toggle in the flow inspector, and a
persistent audit log); the selected flow can be blocked directly. Without a helper,
the UI shows enforcement as off and NETSCOPE stays generate-only. The trust model is
in [`docs/threat-model.md`](docs/threat-model.md).

**Optional — packet capture (G5, the Npcap fork).** The polling capture misses
connections shorter than one ~250 ms tick and can only estimate activity from
connection state. The pcap path fixes both — as an opt-in augmentation, never a
replacement. Build with the feature, then ask for it:

```bash
cargo build -p netscope-agent --features pcap    # needs libpcap-dev (Linux/macOS build hosts) / the Npcap SDK (Windows)
NETSCOPE_PCAP=1 ./target/debug/netscope-agent    # needs capture privilege (root/CAP_NET_RAW; Npcap driver on Windows)
```

Sub-tick flows now appear (process shown once the table confirms them; packets
carry no pid), and activity is byte-true instead of a state guess.
`NETSCOPE_PCAP_DEVICE` picks a specific interface. Capture is headers-only by
construction — snaplen 96, kernel-filtered to `tcp or udp`, aggregated to
per-conversation packet/byte counters; payload never reaches the process (see
the packet-capture section of [`docs/threat-model.md`](docs/threat-model.md)).
The System panel shows the live state (`active (eth0)` / off / unavailable).
Default builds and default runs stay on the polling path, so the measured
overhead numbers above keep describing what ships.

**Optional — the pro layer (G4).** For security folk and tooling: **⤓ csv / ⤓
json** in the connections panel export the current (filtered) view; set
`NETSCOPE_HISTORY_DIR=/some/dir` to opt into a rotated JSONL log of connection
open/close events (off by default — the agent writes nothing to disk otherwise;
see the "Data at rest" section of
[`docs/threat-model.md`](docs/threat-model.md)); point
`NETSCOPE_TRACKER_KEYWORDS` at a file of extra tracker substrings (one per line)
to extend the curated classifier; and consume the live feed from your own
scripts — [`docs/protocol.md`](docs/protocol.md) now has a "consume this from
your own tooling" guide.

**Customizable HUD.** The overlay panels are floating windows: **drag** by the title
bar to move anywhere, **drag the bottom-right corner** to resize, and use the header
buttons to **collapse** (—) or **reset** (⟲). Position, size, and collapsed state are
remembered across reloads, and a panel is always clamped back into view, so the HUD
never has to cover the organism.

**Cinematic mode.** Press **`C`** (or the ⛶ button, bottom-right) for a full-screen,
pure-visual presentation — every panel and overlay hidden, the browser full-screen,
just the deep-sea organism. `Esc` or `C` again returns the HUD. For screenshots,
ambient display, or watching the traffic breathe.

**Explore the graph.** Position is meaningful, not a fixed blob per category. The
**Settings** panel's *arrangement* switches the layout live — *clustered* (the
original by-category layout), *relaxed* (the worker force sim), or **group by
process / org (ASN) / country**, which clusters nodes by that shared dimension and
pulls the clusters apart. Turn on **relationship edges** to draw luminous links
between endpoints that share a process, org or country — the host→endpoint star plus
the real relationships between endpoints. **Double-click a node** (or *explore
connections* in the inspector) to **focus** it: the camera flies in, its relatives
stay lit while the rest of the organism dims, and a breadcrumb (⌂ host › process ›
node) walks you back out (or press **Esc**).

**Settings, in the UI.** What used to be terminal flags now lives in the **Settings**
panel and applies live: layout/arrangement, relationship edges, bloom (was `?bloom=`),
GPU tier (`?renderTier=`), wire encoding (`?encoding=` / `VITE_WIRE_ENCODING`), the
perf overlay (the **`P`** key still toggles it), and the synthetic stress count
(`?nodes=N`). All of it is persisted across reloads; the old URL params still work as
the initial seed. A read-only **System** panel surfaces the agent capabilities that
are configured outside the UI — geo/ASN enrichment, threat feeds, the firewall
enforcer, AI narrators, the running build — each with the one line you'd need to turn
it on.

**Useful knobs:** `pnpm test` (force-sim + relationship unit tests) · everything above
is in the **Settings** / **System** panels.

**Regenerate protocol types** after changing the Rust schema:
`cd agent && cargo test -p netscope-protocol export_bindings` writes
`frontend/src/protocol/generated/`; `cd ../frontend && pnpm typecheck` fails on drift.

## Watch from your phone (C2 + C3 — the remote path)

The agent binds **loopback only by default** and never leaves your machine. To
watch your desktop's traffic from another device, two pieces combine:

**Pairing + auth (C2).** A loopback client connects token-free (you already own
the machine); a **remote** client must authenticate. On start the agent prints a
six-digit **pairing code** (single-use, 60 s). On the remote device, open the UI
and enter the code in *pair a device* — it exchanges the code for a token
(`POST /pair`) that rides every WebSocket handshake as a subprotocol (never a
query string). `POST /auth/revoke` (loopback-only) de-authorizes every device.
The full model — token storage, brute-force/interception limits, what a stolen
token grants — is in [`docs/threat-model.md`](docs/threat-model.md).

**Reachability (C3) — via Tailscale, no relay code.** Put both devices on a
[tailnet](https://tailscale.com), then pick one path:

```bash
# Option A — direct bind to your tailnet IP. The agent serves its own UI, so the
# phone loads http://<tailnet-ip>:8787 and connects same-origin (no mixed-content
# wall). Remote peers are non-loopback, so the C2 token is enforced.
NETSCOPE_BIND=<your-tailnet-ip>:8787 netscope-agent       # built with --features bundled-ui

# Option B — `tailscale serve` proxies HTTPS → the loopback agent, giving you wss
# on a stable <host>.ts.net name (no cert wrangling). Here the tailnet itself is
# the auth boundary (only your devices can reach it); the agent sees loopback.
tailscale serve --bg 8787
```

Why same-origin matters (PITFALLS C3): a page served over HTTPS can't open a plain
`ws://` socket, so we **serve the UI from the agent** — page and feed share an
origin and the mixed-content wall never appears. The agent's `Origin` check was
widened from loopback-only to *loopback or same-origin* to allow exactly this and
nothing more (a hostile third-party page is still refused). The two options' trust
models are compared in the threat-model doc.

## Agent overhead

**Target:** under **1% of one core** sustained at idle, low single digits under
normal use. Measured by a pinned, self-contained benchmark
([`scripts/overhead-bench.sh`](scripts/overhead-bench.sh)) so the numbers are
reproducible, not anecdotal — a local TCP sink + load generators create the
connections, and a sampler reads CPU (`/proc/<pid>/stat`) and RSS over a fixed
window.

| Scenario | ~connections | CPU (% of 1 core) | Peak RSS |
|---|---|---|---|
| **idle** (ambient) | ~1 | **0.9 %** | 5 MB |
| **browse** (~85 held, light churn) | ~85 | **2.3 %** | 7 MB |
| **churn** (torrent-level open/close) | ~1500 (mostly `TIME_WAIT`) | **15.8 %** | 39 MB |

*Intel Xeon @ 2.80 GHz · 4 cores · Linux 6.18 · 87 host processes · agent 0.1.0
release · 15 s window, one draining client.* The cost is dominated by the 250 ms
poll's `/proc/*/fd`→PID sweep, which scales with the host's **process count**, not
connections; churn is a deliberate worst case. The optimization that follows
(resolve PIDs only for *new* sockets) is recorded in ARCHITECTURE.md.

## Repository layout

```
NETSCOPE/
├── README.md            ← the thesis + how to run it (you are here)
├── ARCHITECTURE.md      ← decisions + reasoning, by subsystem
├── planning/            ← ROADMAP · PITFALLS · SALVAGE · RESOURCES
├── docs/                ← per-milestone deep-dives, written as each lands
│   ├── protocol.md        the wire protocol (A5)
│   ├── ringbuffer.md      the SPSC ring + benchmark numbers (A3)
│   ├── performance.md     frame budget + force-layout methodology (B5)
│   └── threat-model.md    loopback exposure + the C2/C3 remote path
├── scripts/             ← overhead-bench.sh · download-geoip.{sh,ps1} · download-threatfeeds.{sh,ps1}
├── agent/               ← the Rust systems core (Cargo workspace)
│   └── crates/
│       ├── protocol/      netscope-protocol — wire types, single source of truth
│       ├── ring/          netscope-ring — the bounded SPSC ring + criterion bench
│       └── agent/         netscope-agent — capture · enrich · axum WS+UI server
└── frontend/            ← the visualizer (Vite + React + TS + R3F + Zustand)
    └── src/
        ├── transport/     the Connection interface (mock | websocket)
        ├── protocol/      TS types GENERATED from the Rust protocol crate
        ├── store/         Zustand delta-mirror
        └── scene/         the R3F organism (ocean · nodes · tendrils · force/)
```

## Support

NETSCOPE is free, open source, and donation-funded. If it showed you something
about your machine you didn't know, you can
[buy me a coffee](https://buymeacoffee.com/duncanhecker) — it funds the
consumer-facing work in [`planning/GROWTH.md`](planning/GROWTH.md).

## License

MIT — see [`LICENSE`](LICENSE). NETSCOPE never bundles the GeoLite2 databases
(MaxMind's, non-redistributable); it ships a downloader for your own key.
