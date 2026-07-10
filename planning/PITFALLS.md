# NETSCOPE v2 — PITFALLS.md

*Anticipated failure points and prefire fixes, written before any code. Organized by roadmap milestone. Update as reality disagrees.*

## Track A — Agent

**A1 (Tauri skeleton)**

- *Pitfall:* WSL2 vs native Windows confusion. Tauri building a Windows app needs Windows toolchains (MSVC, WebView2); building from WSL2 produces a Linux binary that can’t read Windows connection tables.
  *Prefire:* develop the agent natively on Windows (PowerShell + rustup MSVC toolchain) from day one. Keep WSL2 for other projects.
- *Pitfall:* event flooding over Tauri IPC — naive per-connection events will hammer the bridge.
  *Prefire:* the heartbeat milestone already establishes the pattern: one batched payload per tick, never per-item events.

**A2 (capture loop)**

- *Pitfall:* PID reuse — Windows recycles PIDs fast; a cached PID→process mapping can mislabel a new process with a dead one’s name.
  *Prefire:* cache key = (PID, process start time), not PID alone; expire entries when the connection closes.
- *Pitfall:* polling misses short-lived connections (<250ms) entirely — DNS lookups, quick HTTP requests.
  *Prefire:* accept and *document* it as a v1 limitation (it’s inherent to polling); listing it honestly in ARCHITECTURE.md is part of the showcase. Npcap path eliminates it.
- *Pitfall:* UDP “connections” are stateless — the table shows bound sockets, not real conversations; naive diffing will show phantom persistent flows.
  *Prefire:* treat UDP entries with their own lifecycle rules (TTL-based expiry) separate from TCP state transitions.
- *Pitfall:* access denied on some process info for elevated/system processes even without admin.
  *Prefire:* design the schema with `process: Option<ProcessInfo>` from the start; UI renders “protected process” instead of crashing or blank.

**A3 (ring buffer)**

- *Pitfall:* building the lock-free version first, drowning, stalling the project.
  *Prefire:* the roadmap already orders it crossbeam-first; the hand-built SPSC is a swap behind the same interface. Define that interface (trait) on day one so the swap is mechanical.
- *Pitfall:* benchmark lies — measuring throughput with empty payloads or in debug builds.
  *Prefire:* criterion, release builds only, realistic flow-event payloads, documented machine spec. State methodology in ringbuffer.md before recording numbers.
- *Pitfall:* buffer-full policy unconsidered until it happens.
  *Prefire:* decide now: drop-oldest with a counted metric (capture must never block). The drop counter itself becomes interesting telemetry.

**A4 (enrichment)**

- *Pitfall:* blocking DNS lookups stall the async runtime.
  *Prefire:* dedicated lookup task pool with timeouts (1–2s) and negative-result caching; PTR records frequently don’t exist — cache the *absence*.
- *Pitfall:* GeoLite2 licensing — redistributing the .mmdb violates MaxMind terms.
  *Prefire:* first-run downloader with the user’s own license key; document in README. Already noted in RESOURCES.
- *Pitfall:* private/loopback/link-local IPs sent to geo lookup produce garbage.
  *Prefire:* classify RFC1918/loopback/link-local before enrichment; render as “local network” category.

**A5 (protocol)**

- *Pitfall:* schema drift between Rust structs and TS types — the classic two-language lie.
  *Prefire:* single source of truth: define schema once and generate the other side (e.g., serde structs + a TS type generation step), or at minimum a shared JSON-schema file with CI validation.
- *Pitfall:* unbounded delta growth when a client lags.
  *Prefire:* sequence numbers from day one + “if gap detected, request snapshot” rule — already in C4, but the protocol must carry seq from v1 or retrofitting hurts.

**A6 (benchmark)**

- *Pitfall:* unreproducible numbers (“it was fast on my machine that day”).
  *Prefire:* scripted load scenarios (idle / browse-sim / churn-sim), pinned in repo; results table includes hardware, OS build, agent version.

## Track B — Organism

**B1 (skeleton)**

- *Pitfall:* mock and live transports drifting apart so “works on mock” stops meaning anything.
  *Prefire:* both implement the same TS interface; CI runs the frontend against recorded real-session fixtures once the agent exists.
- *Pitfall:* R3F re-render storms — putting per-frame data in React state kills framerate.
  *Prefire:* rule from day one: per-frame values flow through refs/zustand-transient or directly to three objects in `useFrame`; React state only for UI-rate changes (selection, toggles).

**B2 (ocean environment)**

- *Pitfall:* mobile GPU cost of fBm+warp per pixel.
  *Prefire:* already half-res RT; add a capability gate (octaves 5→3, or static-with-slow-scroll fallback) keyed on a startup micro-benchmark, not user-agent sniffing.

**B3 (organism nodes)**

- *Pitfall:* per-node draw calls explode with mesh nodes (we lose the sprite cheapness).
  *Prefire:* InstancedMesh from the first commit of B3, with per-instance attributes (phase, activity, color) driving the displacement shader — don’t write the single-mesh version first.
- *Pitfall:* vertex displacement breaks raycast picking (hit area no longer matches displaced surface).
  *Prefire:* pick against undisplaced bounding spheres (slightly enlarged); displacement is cosmetic, picking is logical.

**B4 (tendrils)**

- *Pitfall:* per-frame CPU ribbon rebuild scales linearly with node count (known debt #2).
  *Prefire:* B4 ships the GPU path directly: endpoints + sway params as attributes, path math in the vertex shader. The CPU version already exists in the prototype as reference.

**B5 (performance pass)**

- *Pitfall:* optimizing without baselines.
  *Prefire:* record profiler traces at 50/150/300 nodes *before* B5 work begins; the doc shows before/after.

## Track C — Bridge

**C2 (auth)**

- *Pitfall:* tokens in localStorage / logged URLs.
  *Prefire:* token in memory + OS keychain via Tauri on desktop; never in query strings; threat-model doc reviews storage explicitly.
- *Pitfall:* pairing code interception on hostile networks.
  *Prefire:* short-lived codes (60s), single-use, exchanged only over TLS; document residual risk honestly.

**C3 (Tailscale)**

- *Pitfall:* mixed-content/cert friction — browser frontend on HTTPS connecting to plain `ws://` tailnet IP gets blocked.
  *Prefire:* either serve the frontend from the agent itself on the tailnet (same origin), or use Tailscale’s HTTPS cert provisioning for the agent endpoint. Decide in C1, not after the first blocked connection.

**C4 (resync)**

- *Pitfall:* duplicate or out-of-order deltas after reconnect corrupting the mirror.
  *Prefire:* idempotent delta application keyed on seq; client discards seq ≤ last-applied; snapshot wholesale-replaces state.

## Track D — Narrator

- *Pitfall:* scrubbing policy as vibes instead of code.
  *Prefire:* redaction is a pure function with unit tests (input flow → scrubbed flow); the tests *are* the policy spec.
- *Pitfall:* eval set too small/cherry-picked to mean anything.
  *Prefire:* fixed labeled set (~50 connections) committed before measuring; report the honest number even if mediocre — the honesty is the showcase.

## Track E — Warden (the full prefire set lives in [`WARDEN.md`](WARDEN.md))

- *Pitfall:* auto-blocking on a heuristic with known false positives cuts the user's
  own service.
  *Prefire:* never auto-block; default-off; a mandatory preview before any apply; the
  allowlist and a protected floor (loopback/LAN/tailnet) **always** win; everything
  reversible (one-click unblock + unblock-all).
- *Pitfall:* a generated/applied rule injects shell or firewall syntax, or locks the
  user out (blocking loopback/DNS/the default route).
  *Prefire:* only strings that parse as an IP/CIDR ever reach output (the firewall's
  own parser is the second gate); generate into an own namespaced table that never
  touches the user's rules; outbound-to-specific-IPs only.
- *Pitfall:* the privileged enforcer becomes a general firewall-editing oracle, or
  trusts "loopback == trusted".
  *Prefire:* it owns one table and refuses everything else; authenticates the peer by
  UID (`SO_PEERCRED`); **re-enforces the never-block floor itself** so a buggy/stolen
  agent still can't cut the user off; least privilege (`CAP_NET_ADMIN` only, a
  hardened systemd unit); set-size cap; every change audited. Threat-model addendum in
  [`docs/threat-model.md`](../docs/threat-model.md).
- *Pitfall:* a threat feed isn't redistributable, or goes stale and blocks a now-clean
  IP.
  *Prefire:* ship a downloader, not the data (the GeoLite2 pattern); the allowlist and
  floor override; matching is cheap (host suffix-walk + IP/CIDR).

## Packaging — desktop shell & self-update

- *Pitfall:* a native rewrite throws away the WebGL/Three.js organism and the remote
  path.
  *Prefire:* a thin **Tauri** shell wraps the existing UI in a native window and
  bundles the agent as a sidecar; the UI still talks to the agent over the same
  WebSocket, so the phone path (C2+C3) keeps working. A standalone crate, kept out of
  the agent workspace so the headless agent never pulls webview deps.
- *Pitfall:* a self-updater that runs an attacker's binary, or swaps silently.
  *Prefire:* fetch over HTTPS from a fixed repo URL; **verify SHA-256** before the
  swap; notify-then-apply (never silent); apply is loopback-only (a remote paired
  device can't push a binary); dev builds and `NETSCOPE_NO_UPDATE` opt out. Honest
  residual risk: this is integrity + locality, not artifact signing — documented in
  [`docs/threat-model.md`](../docs/threat-model.md).

## Cross-cutting

- *Pitfall:* docs written retroactively (they won’t be).
  *Prefire:* each milestone’s PR/commit includes its doc update; roadmap already states this rule.
- *Pitfall:* scope creep from the backlog file.
  *Prefire:* backlog items enter only between milestones, never mid-milestone.