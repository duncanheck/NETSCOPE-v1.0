# NETSCOPE v2 — RESOURCES.md

*Mapped to roadmap milestones. Links marked ✓ were verified June 2026; the rest are canonical project documentation pages I’m confident in — verify on first use.*

## Systems / Rust (Track A)

- **Rust Atomics and Locks** — Mara Bos (O’Reilly, 2023). The book for A3. Free official online edition: <https://marabos.nl/atomics/> ✓ Chapters 1–4 cover threads, atomics, and memory ordering — exactly the ring-buffer prerequisite.
- **crossbeam** — docs.rs/crossbeam — channels + lock-free utilities; the Phase-1 baseline to benchmark against.
- **criterion** — docs.rs/criterion — the standard Rust benchmarking harness for the A3/A6 numbers.
- **netstat2** — docs.rs/netstat2 — cross-platform socket-table enumeration (A2).
- **sysinfo** — docs.rs/sysinfo — PID → process name/path (A2).
- **tokio** — tokio.rs — async runtime for the enrichment pipeline (A4); their tutorial is the best async-Rust on-ramp.
- **maxminddb** — docs.rs/maxminddb — GeoLite2 reader (A4).
- **MaxMind GeoLite2** — dev.maxmind.com — database downloads + license terms (A4; note redistribution restrictions — ship a downloader).
- **Npcap** — npcap.com — Windows packet-capture driver docs (the v2 capture fork).
- **Tauri** — tauri.app — IPC, events, packaging (A1).
- **serde** — serde.rs — serialization for the wire protocol (A5).

## Rendering / GLSL (Track B)

- **The Book of Shaders** — thebookofshaders.com — GLSL fundamentals; the noise and fBm chapters are directly what the ocean shader does (B2).
- **Inigo Quilez articles** — iquilezles.org/articles/ — canonical references for noise, fBm, and domain warping (B2/B3); see in particular his fbm and warp write-ups.
- **Three.js docs + examples** — threejs.org — instancing, EffectComposer/UnrealBloomPass (B5/B6); the examples source is the best practical reference.
- **react-three-fiber docs** — docs.pmnd.rs — R3F patterns, performance pitfalls (B1).
- **Zustand** — github.com/pmndrs/zustand — store for the delta-mirror state (B1).
- **MDN WebGL** — developer.mozilla.org — fundamentals when Three’s abstraction needs piercing.

## Distributed / Networking (Track C)

- **“How NAT traversal works”** — Tailscale blog, David Anderson: <https://tailscale.com/blog/how-nat-traversal-works> ✓ The definitive explainer — covers the full bag of tricks (UDP-first design, STUN/ICE-style techniques) and the relay fallback (TURN-style) for networks that can’t be traversed. Read before C2/C3.
- **“How Tailscale works”** — <https://tailscale.com/blog/how-tailscale-works> ✓ Explains the STUN/ICE-based approach plus their DERP (Designated Encrypted Relay for Packets) fallback servers — the same agent-relay-fallback shape as our C5.
- **Tailscale NAT-traversal improvements series (2025)** — parts 1–3 on the Tailscale blog ✓ — current state of the art; most traffic flows direct peer-to-peer over WireGuard, with DERP relays used to initiate connections and as fallback.
- **Tailscale docs** — tailscale.com/kb — setup for C3.
- **MDN WebSocket API** — developer.mozilla.org — the C1 transport.
- **Cloudflare Workers / Durable Objects** — developers.cloudflare.com — the C5 relay platform, free tier.

## AI layer (Track D)

- **Anthropic docs** — docs.claude.com — API reference, prompting guidance, tool use (D2/D3).
- **Ollama** — ollama.com / github.com/ollama/ollama — the local-model runtime (D2). The
  `GET /api/tags` endpoint lists installed models (used to auto-detect them in the menu);
  `POST /api/chat` runs them. Free, private, on your own hardware.

## Warden — enforcement (Track E)

- **nftables wiki** — wiki.nftables.org — sets (interval/`ipv4_addr`/`ipv6_addr`),
  `inet` tables, `nft -f`/`nft -c` (E3 generation + E4 apply). The `nft -c` check mode
  validates syntax without privilege.
- **netsh advfirewall / pf** — Microsoft Learn + OpenBSD pf FAQ — the Windows and
  macOS firewall backends the generator targets (E3).
- **StevenBlack/hosts**, **abuse.ch** (URLhaus, Feodo), **FireHOL blocklist-ipsets** —
  the free, redistributable threat feeds the downloader fetches (E2); check each
  feed's licence (MIT / CC0 / public).
- **systemd hardening** — `systemd.exec(5)` / `systemd.resource-control(5)` —
  `AmbientCapabilities=CAP_NET_ADMIN`, `NoNewPrivileges`, `ProtectSystem`,
  `SystemCallFilter` for the least-privilege enforcer unit (E4).
- **SO_PEERCRED** — `unix(7)` — authenticate the connecting peer's real UID over a
  Unix socket (E4), instead of trusting "loopback".

## Packaging — desktop shell & self-update

- **Tauri 2** — v2.tauri.app — native shell, the shell plugin (sidecar/`externalBin`),
  the tray-icon API, and the NSIS bundler. WebView2 (Windows) / WebKitGTK (Linux).
- **self_replace** — docs.rs/self_replace — in-place replacement of the running
  binary for the updater; **sha2** / **ureq** — integrity hashing + the HTTPS fetch.

## Reading order suggestion

1. Tauri quickstart (before A1) → 2. tokio tutorial (before A4) → 3. Bos ch. 1–4 (alongside A3 Phase 2) → 4. Book of Shaders noise chapters + IQ’s fbm/warp articles (before B2/B3) → 5. Tailscale NAT post (before C2).