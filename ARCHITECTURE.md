# NETSCOPE — ARCHITECTURE.md

*Decisions and the reasoning behind them, organized by subsystem. Milestone tags
(A2, B5, …) point at where each landed; the per-milestone deep-dives live in
`docs/`. The "decisions I'd revisit" section at the end is part of the showcase —
kept honest as the project grows.*

## Shape of the system

Two processes, one interface between them:

```
   netscope-agent (Rust, native)                          frontend (browser / R3F)
   ┌───────────────────────────────────┐                 ┌──────────────────────┐
   │  capture thread ──[SPSC ring]──►   │   hello /       │  transport (mock |   │
   │  coordinator ──[watch]──► axum     │ ── snapshot ──► │   websocket)         │
   │     /ws  (WebSocket feed)          │     + delta     │     │                │
   │     /    (embedded UI, prod)       │ ◄── resync ──── │  Zustand delta-mirror│
   │  enrich (geo · dns · classify)     │                 │     │ → organism      │
   └───────────────────────────────────┘                 └──────────────────────┘
```

The agent is the systems core: it captures OS connection state, attributes each
flow to its owning process, enriches it (geo, ASN, reverse-DNS,
tracker/security), and serializes it onto a versioned wire protocol. The frontend
is the rendering core: it mirrors the agent's state and draws it as a
bioluminescent organism. The seam is a single `Connection` interface (`connect`,
`onSnapshot`, `onDelta`, `send`, `state`) with interchangeable **mock** and
**WebSocket** implementations — the frontend cannot tell which is behind it, and
that indistinguishability is the test (C1).

---

# The agent

## Capture — metadata-only polling, behind a trait (A2)

A background thread reads the OS connection tables every ~250 ms and diffs each
snapshot into add/update/remove `Flow` events. The A2 fork (poll vs fold Npcap in
now) is **resolved in favour of polling.** The price is explicit, not hidden:
**flows shorter than one poll interval are missed.** Two things polling buys that
packet capture doesn't get for free — **process attribution** (the socket table
names the owner) and **zero driver/elevation** (it just reads the OS). Npcap is the
documented v2 upgrade and slots in behind the same protocol.

The only genuinely OS-dependent work — reading the socket table and attributing
sockets to processes — lives behind one trait, `capture::ConnectionSource`:

- **Linux** (`capture/linux.rs`) reads `/proc/net/{tcp,tcp6,udp,udp6}` and joins it
  against an `inode → pid` map swept from `/proc/*/fd`.
- **Windows** (`capture/windows.rs`) reads the TCP tables via `GetExtendedTcpTable`
  (the `OWNER_PID` variants) and resolves PIDs via
  `OpenProcess`/`QueryFullProcessImageNameW`. It is **TCP-only**: the owner-PID UDP
  table has no remote address, so UDP can't be a conversation — an honest,
  documented gap. It can't be *run* from the Linux dev box, so it's held to
  `cargo check`/`clippy` for the MSVC target plus a build on a real Windows runner.

Everything above the trait — the diffing engine, the UDP TTL lifecycle,
local-vs-remote classification — is platform-agnostic and unit-tested without an OS
in the loop. Three PITFALLS-A2 prefires are code, not intentions:

- **PID reuse** → identity cached on `(pid, start_time)`; a recycled pid whose start
  time differs misses the cache and re-resolves, so it can't inherit a dead
  process's name.
- **UDP is stateless** → UDP sockets have no close to observe, so they expire on a
  5 s TTL (separate lifecycle from TCP state); TCP flows leave the instant they
  leave the table.
- **Access denied** → `process` is `Option` end to end; an unintrospectable socket
  renders as a protected process, never a crash.

## The pipeline — ring for 1→1, watch for 1→N (A3)

The capture→protocol hand-off is a bounded **SPSC ring** (crate `netscope-ring`).
The capture thread (producer) pushes; one coordinator task (consumer) drains it and
republishes the latest on a `tokio::sync::watch` channel, which fans out to every
client session. Each tool does what it's good at: the ring never blocks the
OS-table poll; `watch` coalesces for slow clients, who re-snapshot on a detected
generation gap.

- **Two implementations behind one `Ring` trait.** `CrossbeamRing` (over
  `crossbeam::queue::ArrayQueue`) and a hand-built lock-free `AtomicSpsc` (a Lamport
  ring with cached cursors and documented Acquire/Release). Both pass one
  conformance suite, including a 1,000,000-item cross-thread transfer — the swap is
  one line (the PITFALLS A3 prefire).
- **Drop-newest, not drop-oldest.** Drop-oldest would need the producer to write the
  consumer's `head` cursor, breaking the lock-free proof. Drop-newest is sound, and
  costless because every payload is a full snapshot, so a drop is just a generation
  gap the client heals (C4). The drop count is telemetry.
- **Ship the verified library; keep the hand-built ring as the studied artifact.**
  `AtomicSpsc` *wins* the microbenchmarks (~1.75× uncontended), but the path moves
  ~4 updates/sec, so the ring is never the bottleneck. We ship `CrossbeamRing` —
  measure first, then ship the boring correct thing where the clever thing buys
  nothing. Full treatment + numbers: [`docs/ringbuffer.md`](docs/ringbuffer.md).

## Enrichment — async, behind the engine's `Enrich` trait (A4)

The fields capture leaves empty — name, ASN, geo, refined category, security flags
— are filled by an enricher that runs on each raw flow *before* the engine diffs
it. That ordering is the trick: reverse-DNS is async, so a name isn't ready the
poll an IP first appears; when the lookup later lands in the cache, the *next*
poll's flow differs and the existing diff emits it. No separate "enrichment ready,
re-publish" path — the 250 ms poll + diff already is one.

- **DNS never blocks the capture thread.** `lookup` is a sync cache read; a miss is
  handed to a bounded (semaphore of 8), timed-out (2 s) reverse lookup on the Tokio
  runtime. The cache remembers **absences** (most IPs have no PTR), evicts to stay
  bounded, and an in-flight set dedupes repeated polls (PITFALLS A4).
- **Geo/ASN is local, synchronous, optional.** GeoLite2 `.mmdb` lookups are a
  mmap'd read (microseconds), so they run inline. They're **off unless the databases
  are present** — we never bundle them (MaxMind's license forbids redistribution),
  so the agent ships a downloader (`scripts/download-geoip.*`) and degrades to
  `asn`/`location` of `None`.
- **Classification and flags are pure functions — the policy is the tests.**
  Tracker/CDN classification is case-insensitive keyword matching on the resolved
  org *and* hostname (a curated heuristic, honestly incomplete); flags
  (`plaintext`, `unresolved_org`, `tracker`) are derived likewise. Local addresses
  never reach geo/DNS.

## Wire protocol & schema — one source of truth (A5)

The protocol types are defined **once**, in the `netscope-protocol` crate, and the
TypeScript types are **generated from them** via `ts-rs` (committed under
`frontend/src/protocol/generated/`; CI fails the build on drift). This kills the
classic two-language lie structurally rather than by discipline.

- **Version + sequence from v1.** Every message carries a protocol `version` and a
  monotonic `seq`, even when only heartbeats existed — so the C4 resync (apply
  deltas idempotently on `seq`, re-request a snapshot on a gap) is never a retrofit.
- **Forward-compatible by rule.** Unknown fields are ignored; a breaking change is a
  major version bump negotiated in `hello`. New fields are additive: `Flow` gained
  `flags: Vec<SecurityFlag>` with `#[serde(default)]`, and old/new peers stay
  compatible. Spec: [`docs/protocol.md`](docs/protocol.md).
- **Two encodings, negotiated.** JSON (text, the debuggable default) and **MessagePack**
  (binary, ~20 % smaller, opt-in via the `netscope.msgpack` subprotocol) both ship;
  `rmp-serde`'s `with_struct_map` keeps the same logical shape so the dialects are
  interchangeable, and the choice is negotiated on the handshake. Verified
  interoperable Rust↔JS, with forward-compat round-trips locked behind conformance
  tests in both encodings.

## Serving & packaging — the agent serves the UI; a native shell wraps it

The HTTP layer is `axum`: the WebSocket feed lives at `/ws`, and — in the
`--features bundled-ui` build — the compiled frontend is embedded (`rust-embed`)
and served from `/` on the same port. One self-contained `netscope.exe`, opened in
the browser. This realizes the ROADMAP-A1 "desktop shell" as *agent-serves-browser*
over loopback HTTP, which also keeps the frontend identical to the future tailnet
path and dodges the C3 mixed-content friction (UI and feed are same-origin; the
bundled UI derives its WS URL from `window.location`).

**A native desktop app now exists too — a thin Tauri shell.** For users who'd
rather have a real app window than a browser tab, `frontend/src-tauri/` is a Tauri 2
shell that shows the *same* React/Three.js UI in a native window (WebView2 on
Windows), bundles the agent as a **sidecar** it launches on startup
(`NETSCOPE_NO_OPEN` stops the agent popping a browser), and lives in the **system
tray** (close-to-tray, left-click toggle, Quit terminates the sidecar) so it's a
proper always-on monitor. It changes nothing about the data path: the UI is built
with `VITE_AGENT_URL=ws://127.0.0.1:8787/ws` and talks to the sidecar over the same
WebSocket the browser build uses — so the tailnet/phone path (C2+C3) keeps working,
and the deliberate "WebSocket spine, not Tauri IPC" choice is what makes one agent
drive both the native window and a remote device. The shell is a standalone crate,
kept out of the agent workspace so the headless agent never pulls webview deps.
Built on a real Windows runner into an NSIS installer (`desktop-build.yml`).

**The single-exe browser build keeps itself current.** A stamped build (CI sets a
monotonic build id) checks a rolling `latest` GitHub release on launch and then on a
slow poll; if a newer build is published the HUD's updater panel offers a one-click
apply that downloads the new exe, **verifies its SHA-256** against the manifest, and
self-replaces in place (`self_replace`) — notify-then-apply, integrity-gated,
loopback-only to apply. A dev build (id 0) or `NETSCOPE_NO_UPDATE` opts out. This is
integrity + locality, not artifact signing — stated plainly; see
[`docs/threat-model.md`](docs/threat-model.md).

**The desktop app updates itself differently — automatically, and signed.** The
mechanism above only ever replaces *its own running exe*; for the desktop product
that exe is the sidecar, not the installed shell, and it would compare itself
against the *browser build's* manifest — a different product with an unrelated CI
run-number sequence. Rather than adapt that path, the sidecar's self-updater is
explicitly disabled (`NETSCOPE_NO_UPDATE=1`, set when the shell spawns it — and
now enforced at the endpoint level too, not just the background-poll loop, so a
stray manual hit can't do it either), and the whole installed app — shell,
sidecar, and all — updates through Tauri's own updater plugin instead
(`frontend/src-tauri/src/main.rs`). It's genuinely fluid: no banner, no button.
A background loop checks a signed manifest (`desktop-latest`, published by
`desktop-build.yml` on every push to `main`) every few hours; when a newer
version is found it downloads and installs silently, then restarts into it —
but only at a moment the window isn't in view (hidden to the tray, or
minimized), so it never yanks the scene away from someone looking at it. Each
release is signed with a dedicated minisign keypair (`TAURI_SIGNING_PRIVATE_KEY`
in CI) and verified against the public key embedded in `tauri.conf.json` — real
artifact signing, not just an integrity hash, which is the "graduation step" the
single-exe path below still has on its list.

**Security at the seam (pre-C2 defense-in-depth):** the agent binds loopback only,
the WS handshake validates `Origin` (loopback browser origins or origin-less native
clients; everything else 403 — closing cross-site WebSocket hijacking), and the
handshake has a timeout (anti-slowloris). Full token auth is C2; see
[`docs/threat-model.md`](docs/threat-model.md).

**Built on Windows CI, not cross-compiled.** `windows-build.yml` runs on
`windows-latest` (MSVC): builds the frontend, then `cargo build --release
--features bundled-ui`, uploads `netscope.exe`, and attaches it to a Release on a
`v*` tag — so the Windows-only code is compiled and smoke-checked on the OS it
targets.

## Overhead — measured, with a finding (A6)

`scripts/overhead-bench.sh` runs three pinned scenarios (idle / browse / churn)
against a local TCP sink and samples the agent's CPU and RSS, so the README table
is reproducible (PITFALLS A6). The target (<1% of one core at idle) is met (~0.9%;
browse ~2%). The benchmark located the **dominant cost, and it isn't connection
count**: the per-poll `build_inode_pid_map` sweep over *every* process's
`/proc/*/fd`, which scales with the host's process count. The optimization that
follows — resolve only *new* inodes (cache the map, refresh incrementally), and gate
the poll when no client is connected — is **recorded, not built**: A6 is a
measurement milestone, so it's a documented finding, not scope creep.

---

# The frontend — the organism

## Transport abstraction (C1)

The app talks to exactly one `Connection` interface and cannot tell which
implementation is behind it. The mock churn generator (salvaged from the prototype,
kept permanently as a fixture) and the WebSocket transport both implement it, so
frontend work never blocks on the agent, and "works on mock" means "works on live."
A small Zustand store mirrors the agent's world via snapshot + delta, applying
deltas idempotently on `seq` and flagging a gap as `needsResync` (the seam C4
fills).

## The render pipeline — owned loop, half-res ocean, measured capability (B2)

The deep-ocean background is a domain-warped fBm (Ashima simplex), the frame's
heaviest fragment program. It renders to a **half-resolution** target and is
composited up — a quarter of the fragment work, invisibly soft for a murky volume.
That means three sequenced passes (ocean → target, composite → screen, main scene →
screen on top), so a component **takes over R3F's render loop** (a `useFrame` with
non-zero priority disables auto-render) rather than pulling in the `postprocessing`
library for one background pass.

Octave count, RT scale, and particle density are chosen by a **startup GPU
micro-benchmark** (`scene/capability.ts`), never by user-agent string — a phone can
outrun a laptop, so the UA is a lie. `prefers-reduced-motion` freezes drift, and the
chosen tier shows in the HUD so the gate is visible.

## Nodes and tendrils — instanced, GPU-driven (B3, B4)

- **Organism nodes** are one `InstancedMesh` of icospheres: a 3D-simplex vertex
  displacement wobbles each membrane, a fresnel rim lights its silhouette, and
  colour/activity/phase/exposed/selection ride as per-instance attributes. Node
  count costs one draw call (plus one for the additive glow halos), not N. Picking
  is R3F's raycast against the **undisplaced** spheres — displacement is shader-only,
  so the hit area stays the clean sphere (PITFALLS B3). Click-to-select is shared
  with the HUD list + a detail inspector.
- **Tendrils** are one instanced ribbon. The base geometry is a flat strip carrying
  only its along-parameter and cross-side; the swaying center→node curve and the
  camera-facing width are computed *entirely in the vertex shader* (PITFALLS B4
  prefire — no per-frame CPU ribbon rebuild), with traffic reading as gaussian motes
  travelling core→endpoint. The 3D-noise sway is shared with the node displacement
  via one `shaders/noise.ts` chunk.

## Layout & performance — flat budget, opt-in worker sim (B5)

The performance work is front-loaded into the architecture, so the budget is
**flat in node count**: every layer is one instanced/full-screen draw (~9 total),
and the default layout is **deterministic** (category clustering + id hash) with all
motion in shaders — so there is no per-frame CPU layout, and the prototype's O(n²)
force-sim trap (SALVAGE #1) never applied.

The force sim *does* ship, but properly: a **Web Worker** runs it off the render
thread (`scene/force/`), repulsion uses a uniform spatial grid (O(n·k)), and it's
stability-first (bounded/damped/clamped/NaN-guarded, seeded from the deterministic
layout) with real unit tests (`vitest`, in CI). It's behind `?layout=force`, so the
verified default is never at risk from code that can't be visually verified in CI.
Measurement is in-app: a perf overlay (`P`) reads frame time/draws/tris from the
renderer, and `?nodes=N` seeds the mock at a fixed count for the 50/150/300
scenarios. Methodology + budget: [`docs/performance.md`](docs/performance.md).

---

# The bridge — remote access (C2–C4)

The agent is loopback-only by default; the bridge is what lets a phone on your
tailnet watch your desktop, safely.

- **Pairing + token auth (C2).** A loopback client connects token-free (you already
  own the machine); a **remote** client must authenticate. The agent mints a
  six-digit, single-use, 60 s, attempt-capped pairing code; a device exchanges it
  (`POST /pair`) for a 256-bit token presented on every WS handshake as the
  `Sec-WebSocket-Protocol: auth.<token>` value (never a query string). Tokens are
  stored agent-side as SHA-256 hashes, client-side in memory only; `revoke_all`
  de-authorizes every device. Pairing/revocation is a plain-HTTP control plane,
  deliberately outside the versioned wire protocol.
- **Tailscale reachability (C3).** `NETSCOPE_BIND=<tailnet-ip>:8787` opts into the
  remote path (logged loudly; the C2 token gates every non-loopback peer). The
  `Origin` check is widened from loopback-only to **loopback or same-origin**
  (`origin_allowed`) so the agent's own served page is admitted and nothing else. No
  relay code — the tailnet *is* the transport.
- **Reconnect + resync (C4).** Reconnection uses exponential backoff with equal
  jitter (500 ms → 15 s, reset on a clean open). Resync is client-driven: a
  `ClientMessage::Resync` envelope asks for a fresh snapshot; gap detection runs on
  the *global* seq line (heartbeats consume seq too), delta application is idempotent
  (`seq ≤ lastApplied` discarded), a snapshot wholesale-replaces. The handshake is
  bounded by a header-read timeout (a manual hyper-util accept loop, not
  `axum::serve`) so the C3-exposed listener can't be held open by a slowloris.

Full trust tables (both paths): [`docs/threat-model.md`](docs/threat-model.md).

# The narrator — the AI layer (D1–D3)

An optional plain-language explanation of your traffic, built privacy-first.

- **The scrub boundary (D1).** `netscope-narrator::scrub_session` is a pure, tested
  redaction function — the single thing any provider is ever fed. It drops the
  5-tuple id, local IPs/ports, raw remote IPs, LAN hostnames, and process
  paths/pids; keeps the explainable surface (public host, org+ASN, coarse geo, port,
  flags) and the process name. Local-vs-remote fails safe (an unparseable address is
  treated as local). [`docs/scrubbing.md`](docs/scrubbing.md).
- **Selectable providers (D2), free by default.** A menu picks the explainer: a
  deterministic **offline rules** summary (always available, nothing leaves the
  machine), a **local model via Ollama** (`localhost:11434` — and the menu
  *auto-detects the models you've already pulled* via `/api/tags` and lets you pick
  one), or **Claude** (the only one that sends the scrubbed summary off-machine,
  stated plainly). Endpoints are loopback-only.
- **Honest eval (D3).** The classification the narration rests on is measured on a
  labeled set — **83.3 % category accuracy, 71.4 % tracker recall, 100 % plaintext**,
  failures named, in CI. The classifier is one source of truth shared by the live
  path and the eval. [`docs/eval.md`](docs/eval.md).

# The Warden — sight into action (E1–E6)

Track E turns NETSCOPE from a viewer into a control: block trackers, plaintext
exfil, and known-bad endpoints, free and out-of-band, with privilege isolated to one
tiny component.

- **Policy engine + dry-run (E1).** `netscope-warden` is a pure decision function
  with fixed, tested precedence — **protected floor > allowlist > deny rules >
  default-allow** — and a per-decision "why". It only ever *decides*; it holds no
  privilege. The protected floor (loopback/RFC1918/link-local/CGNAT-tailnet/ULA) can
  never be blocked.
- **Threat feeds (E2).** A license-aware downloader (`scripts/download-threatfeeds.*`)
  fetches free public blocklists (StevenBlack/abuse.ch/FireHOL) into `threatfeeds/`;
  a `ThreatDb` matches a flow's host (suffix-walk) or IP (exact + CIDR) and feeds a
  `threat` deny rule. Ship the downloader, not the data (the GeoLite2 pattern).
- **Firewall generator (E3).** Renders a policy's block targets into a native,
  namespaced, reversible ruleset (`inet netscope` nftables / grouped netsh / a pf
  anchor) the user applies by hand — **injection-proof by construction** (only
  strings that parse as an IP/CIDR reach the output) and validated by the firewall's
  own parser.
- **The enforcer (E4, Linux).** The project's one privileged piece:
  `netscope-enforcer`, a daemon that does *only* add/remove an address in its own
  `inet netscope` set, over a Unix socket. It authenticates the peer by UID
  (`SO_PEERCRED`, not "loopback == trusted"), **re-applies the never-block floor
  itself** (reusing the warden's `is_protected_addr`, so a buggy/compromised agent
  can't cut you off your own network), caps the set, and audits every change. Shipped
  as a hardened systemd unit (a dedicated user with only `CAP_NET_ADMIN`). The agent
  reaches it only when `NETSCOPE_ENFORCER_SOCKET` is set; otherwise generate-only.
- **The blocking UX (E6).** The HUD gains preview → confirm apply (never silent), a
  live blocked list with one-click per-row unblock and unblock-all, a per-flow block
  action in the inspector, a "N blocks active" count, and a persistent audit log.
  Enforcement availability is detected at runtime (the agent answers `503` when no
  enforcer is configured) so the UI degrades gracefully to generate-only.

E5 (reactive socket teardown) and a Windows enforcer service are the queued
follow-ups. Full spec + pitfalls: [`planning/WARDEN.md`](planning/WARDEN.md); the
enforcer's threat model: [`docs/threat-model.md`](docs/threat-model.md).

# Decisions inherited from the prototype

Made for the `netscope-neural` prototype and carried into v2 (full account in
[`planning/SALVAGE.md`](planning/SALVAGE.md)): connection-table polling for capture
v1; the transport abstraction; the per-endpoint data model (the schema the real
agent emits, with the mock retained as a fixture); and the ribbon/particle/nebula
rendering techniques, re-art-directed to the deep sea.

# Open decisions

| Decision | Where | Notes |
|---|---|---|
| Public relay (share beyond your own devices) | C5 | Deferred by design; Cloudflare Workers/DO drafted in ROADMAP. |
| Windows enforcement | E4 | Linux enforcer ships; a LocalSystem service is the follow-up. |
| Reactive socket teardown | E5 | Queued — kill the open connection so a block bites within one poll. |
| Artifact signing for the single-exe self-update | packaging | Today is integrity + locality (SHA-256); Authenticode is the graduation step. The desktop app's own updater is already past this — minisign-signed via Tauri's updater plugin — so this row is specific to the single-exe path. |

*Resolved since first draft:* JSON **and** MessagePack ship (A5, negotiated);
pairing/token auth ships (C2); the Tauri native shell ships (below).

# Decisions I'd revisit

- **Heartbeat/feed over WebSocket instead of Tauri IPC** — right for building the
  distributed spine first; it paid off when the **Tauri shell landed** (the same
  agent over the same WS drives both the native window and a remote phone — a native
  IPC would have forked that path). The shell adds a window; the data path is
  unchanged.
- **`watch` fan-out for the 1→N hop** — correct as the client fan-out; the A3 ring
  backs the 1→1 capture→coordinator hop, which is what each is for.
- **Hand-owned render loop for the ocean composite** — the right machinery for one
  pass; folds into `EffectComposer` when B6's bloom lands.
- **Re-sweeping `/proc/*/fd` every poll** — the A6 finding; cache the inode→pid map
  and resolve only new sockets, and gate the poll when no client is connected.
