# NETSCOPE v2 — ROADMAP.md

*Deep-sea bioluminescence visual identity + systems-depth showcase. Each milestone
names the skill it forces and the artifact that proves it.*

## The thesis

A beautiful demo on top of a rigorous core. The visualizer proves
rendering/performance engineering; the Rust agent proves systems engineering; the
remote path proves distributed thinking; the writeups prove the thinking itself.
Most portfolios have one half. This has both.

## Progress

`✅ landed · 🟡 partial · ⬜ planned`

| Track | Milestones |
|---|---|
| **A — Agent** | A1 ✅ A2 ✅ A3 ✅ A4 ✅ A5 ✅ A6 ✅ |
| **B — Organism** | B1 ✅ B2 ✅ B3 ✅ B4 ✅ B5 ✅ B6 ✅ |
| **C — Bridge** | C1 ✅ C2 ✅ C3 ✅ C4 ✅ · C5 ⬜ |
| **D — Narrator** | D1 ✅ D2 ✅ D3 ✅ |
| **E — Warden** | E1 ✅ E2 ✅ E3 ✅ E4 ✅ (Linux) E6 ✅ · E5 ⬜ |

Tracks A and B are complete; the bridge (C), narrator (D), and most of the Warden
(E) have landed. Two product layers sit on top of the core, both shipped:

- **Desktop app** — a Tauri native-window shell (WebView2) with a system tray and the
  agent bundled as a sidecar, built into a Windows installer (`desktop-build.yml`).
  Optional; the single-exe browser build still ships alongside it.
- **Self-update** — the Windows product checks a rolling `latest` release and applies
  integrity-checked (SHA-256), notify-then-apply, in-place binary swaps.

Landed milestones link to their proof; details live in
[`ARCHITECTURE.md`](../ARCHITECTURE.md), [`WARDEN.md`](WARDEN.md), and `docs/`.

---

## Track A — The Agent (systems depth)

**A1. End-to-end spine. ✅** Agent ↔ frontend proven end to end. Realized over the
WebSocket transport (not Tauri IPC) so it builds the C1 spine every later milestone
rides — see ARCHITECTURE.md for the reasoning.
*Skill:* the Rust/JS boundary, transport-first design.

**A2. Capture loop — connection-table polling. ✅** ~250 ms poll, snapshot diffing,
process attribution, behind a `ConnectionSource` trait (**Linux** `/proc/net/*` +
**Windows** `GetExtendedTcpTable`, both shipped). Metadata-only v1; Npcap is the
documented v2 upgrade. PID-reuse, UDP-TTL, and protected-process prefires are code.
*Skill:* OS API work, snapshot diffing. *Artifact:* the live `connections` panel.

**A3. The capture→protocol ring — done properly. ✅** Bounded SPSC ring
(`netscope-ring`): a shipped `CrossbeamRing` and a hand-built lock-free `AtomicSpsc`
behind one trait, both passing a 1M-item cross-thread conformance test, benchmarked
with `criterion`.
*Skill:* atomics, memory ordering, benchmark methodology. *Artifact:*
[`docs/ringbuffer.md`](../docs/ringbuffer.md) — the strongest systems piece.

**A4. Enrichment pipeline. ✅** Reverse-DNS (bounded/timed-out async pool, negative
cache), GeoLite2 city+ASN (optional, license-aware downloader), tracker/CDN
classification, per-flow security flags — as the engine's `Enrich` trait so async
results emit via the next poll's diff.
*Skill:* async Rust, cache design, license-aware data handling.

**A5. Versioned wire protocol. ✅** Schema defined once in Rust and generated to TS
(`ts-rs`); version + monotonic `seq` from v1. The version is now the protocol
*major* with an enforced `is_compatible` (exact-major) check — the client
disconnects on a mismatch, both sides (`codec.rs` / `isCompatibleVersion`). Content
negotiation lands: JSON (text, the debuggable default) ↔ **MessagePack** (binary,
opt-in via the `netscope.msgpack` subprotocol), measured at a steady ~20 % smaller
and verified interoperable Rust↔JS end-to-end. The forward-compat rules (unknown
fields/types ignored in *both* encodings, round-trip in both, exact-major compat)
are locked behind conformance tests so contributors can't regress them, and
`docs/protocol.md` is the full catalogue + a "how to extend the protocol" guide —
the scalability move for an open-source protocol.
*Skill:* protocol design, forward-compatibility. *Artifact:*
[`docs/protocol.md`](../docs/protocol.md).

**A6. Overhead benchmark. ✅** CPU/RSS at idle / browse / churn via a pinned,
self-contained harness (`scripts/overhead-bench.sh`); target (<1% of one core idle)
met; the dominant cost located and an optimization path recorded.
*Skill:* measurement discipline. *Artifact:* the table in the README.

## Track B — The Organism (rendering showcase)

**B1. Project skeleton. ✅** Vite + React + TS + R3F + Zustand; the mock-feed module
implementing the same `Connection` interface the live transport does.

**B2. Deep-ocean environment. ✅** Domain-warped fBm water column on a half-res
target, 3 parallax marine-snow layers, capability tier chosen by a startup GPU
micro-benchmark (not UA sniffing), tier surfaced in the HUD.

**B3. Organism nodes. ✅** One `InstancedMesh` of vertex-displaced, fresnel-shaded
cells; biolum palette (amber trackers, pale plaintext); picking against undisplaced
spheres; orbit camera; click-to-select synced with the HUD + detail inspector.
*Skill:* vertex displacement, fresnel shading.

**B4. Tendrils. ✅** One instanced GPU ribbon from a host core to each node — sway,
width, and traffic motes all computed in the vertex/fragment shaders (debt #2
retired up front).

**B5. Performance pass + writeup. ✅** Flat ~9-draw budget documented; worker-offloaded
force layout with a uniform spatial grid ships opt-in (`?layout=force`),
unit-tested in CI (debt #1 retired); in-app perf overlay (`P`) + `?nodes=N` stress
mode.
*Artifact:* [`docs/performance.md`](../docs/performance.md).

**B6. True bloom. ✅** `EffectComposer` + `UnrealBloomPass` on the HIGH tier; the
ocean composite folds into the same pipeline rather than adding a second render
owner — DeepOcean draws the combined frame (ocean + scene) into one full-res
**HalfFloat** target, then blooms it to screen (`CopyShader` final blit, not
`OutputPass`, so the base image keeps the direct-path look and bloom is purely
additive). The threshold (0.75) sits above the ocean's murk, so only the emissive
organism — node cores, fresnel rims, traffic motes, which exceed 1.0 — glows.
**Capability-gated**: a weak/mobile GPU measures slow → LOW tier → the extra
passes are skipped and the original direct path runs unchanged; `?bloom=on|off`
forces it for testing, and the tier label in the HUD shows the state.

## Track C — The Bridge (distributed slice)

**C1. Transport abstraction. ✅** `Connection` interface with mock + WebSocket
implementations the frontend can't tell apart. The bundled product already serves
the UI same-origin over loopback, which clears C3's mixed-content hurdle.

**C2. Pairing + auth. ✅** A loopback peer connects token-free (the A2 trust
boundary); a **remote** peer must authenticate. The agent mints a six-digit,
single-use, 60 s, attempt-capped pairing code; a device exchanges it for a 256-bit
token (`POST /pair`) presented on every WS handshake as the
`Sec-WebSocket-Protocol: auth.<token>` value (never a query string — PITFALLS C2).
Tokens are stored agent-side as SHA-256 hashes, held client-side in memory only;
`revoke_all` de-authorizes every device. Pairing/revocation is a plain-HTTP
control plane, deliberately outside the versioned wire protocol. Unit-tested both
sides.
*Artifact:* [`docs/threat-model.md`](../docs/threat-model.md) — real threat tables.

**C3. Tailscale reachability. ✅** Phone → tailnet IP → agent, no relay code. Binds
loopback by default; `NETSCOPE_BIND=<tailnet-ip>:8787` opts into the remote path
(logged loudly; C2's token gates every non-loopback peer). The mixed-content wall
(PITFALLS C3) is resolved as C1 anticipated — the agent serves its own UI, so page
and feed are same-origin and `ws://` is never blocked; the A2 `Origin` check was
widened from loopback-only to **loopback or same-origin** (`origin_allowed`) to
admit exactly the served page, nothing more. A `tailscale serve` HTTPS path is
documented with its different trust boundary (tailnet membership vs. C2 token). A
*pair a device* panel is the remote entry point.
*Artifact:* the C3 section of [`docs/threat-model.md`](../docs/threat-model.md)
(two-path trust table) + the README "watch from your phone" runbook.

**C4. Reconnection + resync. ✅** Reconnect uses **exponential backoff with equal
jitter** (500 ms → 15 s cap, reset on a clean open) so a down agent isn't hammered
and many clients don't retry in lockstep. The resync half is now **client-driven**:
a new `ClientMessage::Resync` (a separate client→agent envelope, same forward-compat
rule as `WireMessage`) lets the client ask for a fresh snapshot; the agent splits
the socket and answers any resync with the current world wholesale. Gap detection
was corrected to run on the **global** seq line (every frame), not just deltas —
heartbeats consume seq between deltas, so the old delta-only check fired spuriously
on every delta; now a jump is a real lost frame. Delta application stays idempotent
(discard `seq ≤ lastApplied`); a snapshot wholesale-replaces and clears the flag
(PITFALLS C4). Unit-tested both sides (backoff bounds, false-positive fix, single
resync per gap, idempotent replay) and verified end-to-end over a live socket.

**C5 (later). Public relay. ⬜** Cloudflare Workers/Durable Objects rooms — built
only when sharing beyond your own devices matters.

## Track D — The Narrator (AI layer, done carefully)

**D1. Scrubbing pipeline. ✅** A pure, testable redaction function in its own crate
(`netscope-narrator::scrub_session`) — the single boundary nothing in Track D may
call an API around. Drops the 5-tuple id, local IPs/ports, raw remote IPs, LAN
hostnames, and process paths/pids/usernames; keeps the explainable destination
surface (public host, org+ASN, coarse geo, port, flags) and the process name. Local
vs. remote is fail-safe (category *or* a `classify_ip` that covers RFC1918,
loopback, link-local, CGNAT/tailnet, IPv6 ULA, and unparseable). Tests prove a
sensitive flow serializes with none of its local identifiers.
*Artifact:* [`docs/scrubbing.md`](../docs/scrubbing.md) — the privacy contract.
**D2. Structured explain. ✅** Explains the (scrubbed) session behind a
**selectable provider** menu, so NETSCOPE is free to run with no API key: a
deterministic offline **built-in** rules summary (always available, nothing leaves
the machine), a **local Llama via Ollama** (`localhost:11434`, free + private), and
**Claude** (`ANTHROPIC_API_KEY`, the only one that sends data off-machine — stated
plainly in the UI). The prompt is versioned in-repo (`PROMPT_VERSION`); the rules
explainer is the always-on local fallback. Every provider is fed *only*
`scrub_session` output. Endpoints `GET /narrator/providers` + `POST
/narrator/explain` are loopback-only. Tested (rules summary, prompt body carries no
local identifiers, key-required) and verified end-to-end against rules and an Ollama
stub. *Also QoL:* a connection search/filter box in the HUD.
**D3. Session briefing + eval. ✅** Any provider summarizes a session (D2); the eval
answers *when is that wrong* by measuring the classification the narration rests on.
The classification policy moved into `netscope-narrator::classify` (one source of
truth, shared by the live capture path and the eval — the thing measured is the
thing shipped). `netscope-narrator::eval` runs a 36-endpoint labeled set through it,
**including cases the keyword heuristic can't catch**, and reports the real numbers:
**83.3 % category accuracy, tracker precision 90.9 % / recall 71.4 %, 100 %
plaintext** — failures named, in CI. The LLM layer narrates on the same substrate,
so its accuracy is bounded by (and graded against) this set.
*Artifact:* [`docs/eval.md`](../docs/eval.md) — the honest number and where it's wrong.

## Track E — The Warden (sight into action)

Turning NETSCOPE from a viewer into a control: block trackers, plaintext exfil, and
known-bad endpoints via the OS's own firewall — free, out-of-band, opt-in, with
privilege isolated to one tiny component. Full spec + prefires:
[`WARDEN.md`](WARDEN.md).

**E1. Block-policy engine + dry-run. ✅** A pure decision function, fixed/tested
precedence (protected floor > allowlist > deny > default-allow), zero privilege.
**E2. Threat-intel feeds. ✅** Free public blocklists via a license-aware downloader;
host suffix-walk + IP/CIDR matching feeding a `threat` deny rule.
**E3. Firewall generator. ✅** Native, namespaced, reversible nftables/netsh/pf,
injection-proof by construction, validated by the firewall's own parser.
**E4. The enforcer (Linux). ✅** A hardened `CAP_NET_ADMIN` helper over an
`SO_PEERCRED`-authenticated socket that holds the never-block floor itself.
**E6. The blocking UX. ✅** Preview → confirm apply, a live blocked list with
one-click unblock, per-flow block, and a persistent audit log; degrades to
generate-only when no enforcer is configured.
**E5. Reactive socket teardown. ⬜** Kill the open connection so a block bites within
one poll. *(A Windows enforcer service is the E4 follow-up.)*

## Packaging — desktop app & self-update

Two shipped product layers on top of the core (details in
[`ARCHITECTURE.md`](../ARCHITECTURE.md)):

- **Tauri desktop shell.** The web UI in a native window (WebView2), the agent
  bundled as a sidecar, a system tray (close-to-tray, toggle, quit), built into a
  Windows NSIS installer on a real Windows runner. The single-exe browser build
  ships alongside it; nothing about the data path changes.
- **Self-update (single-exe).** A stamped build checks a rolling `latest` release on
  launch and on a slow poll; the HUD's updater panel applies an integrity-checked
  (SHA-256), notify-then-apply, loopback-only in-place binary swap. Opt out with
  `NETSCOPE_NO_UPDATE`.
- **Auto-update (desktop app).** A different mechanism for a different failure mode:
  the single-exe path above only ever replaces its own running exe, the wrong binary
  for an installed app (the sidecar, not the shell) — so the desktop shell instead
  updates through Tauri's signed updater plugin, silently, on a background cadence,
  applying (download → install → restart) only when the window isn't in view. The
  sidecar's own self-updater is explicitly disabled inside the shell
  (`NETSCOPE_NO_UPDATE=1`). See `docs/desktop-update.md`.

---

## Where we are vs. the plan

The suggested interleaving was: A1 → B1 → A2 → B2/B3 → A3 → A4/A5 → C1/C2 → B4/B5 →
A6 → C3/C4 → D1–D3 → B6. **Every planned milestone is done** — the agent (A1–A6),
the organism (B1–B6), the bridge (C1–C4), and the narrator (D1–D3) — with only **C5
(the public relay)** deferred by design, to be built when sharing beyond your own
devices actually matters. From here it's depth on what exists: a real tracker list
to lift the eval's recall, the Npcap capture upgrade, and the C5 relay if/when it's
warranted. The largest *new* direction is **Track E — the Warden** (turning sight into action:
block trackers, plaintext exfil, and known-bad endpoints via the OS's own firewall —
free, out-of-band, opt-in), specced in [`WARDEN.md`](WARDEN.md). **E1 (the
zero-privilege block-policy engine + dry-run), E2 (free threat-intel feeds — a
license-aware downloader + suffix/CIDR matching feeding a `threat` deny rule), E3
(the native firewall generator — nftables/netsh/pf, injection-proof, validated by
`nft --check`), E4 (the privilege-separated enforcer — a hardened
`CAP_NET_ADMIN` helper over an `SO_PEERCRED`-authenticated socket, holding the
never-block floor itself; Linux), and E6 (the blocking UX — preview→confirm apply,
a live blocked list with one-click unblock, per-flow block, and a persistent audit
log; degrades to generate-only when no enforcer is configured) have landed**; E5
(reactive socket-kill) is queued, and a Windows enforcer service is the E4 follow-up.

## Documentation set (the meta-move)

[`ARCHITECTURE.md`](../ARCHITECTURE.md) (decisions by subsystem),
[`docs/protocol.md`](../docs/protocol.md), [`docs/ringbuffer.md`](../docs/ringbuffer.md),
[`docs/performance.md`](../docs/performance.md), [`docs/threat-model.md`](../docs/threat-model.md),
[`docs/desktop-update.md`](../docs/desktop-update.md).
Each written *when its milestone lands*, never retroactively.
