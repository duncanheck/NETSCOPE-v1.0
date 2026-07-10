# NETSCOPE — SALVAGE.md

*What carries from the prototype (netscope-neural.html) into v2, what gets reworked, what dies.*

## Carries straight over

**The data model.** The endpoint record shape — `{name, category, asn, location, process, port, encrypted, ip, activity, alive}` — is exactly the schema the real Rust agent will emit per flow. The mock churn generator is retained permanently as a **test fixture**: v2 develops against simulated traffic with the same schema, so frontend work never blocks on the agent.

**Ribbon filament system.** Billboarded ribbon geometry (camera-facing strip built from a curve, per-vertex `aT`/`aSide` attributes) + the pulse fragment shader (gaussian pulses traveling on `fract(time*speed)`, soft cross-section falloff, depth fade). Renderer-agnostic — in the bioluminescence direction these become *tendrils*; the geometry technique and shader structure are identical, only the art direction changes.

**Wavy-path generator.** The two-axis perpendicular sine displacement (endpoint-pinned, sine envelope, activity-scaled amplitude) is the basis for tendril drift. Will be upgraded to noise-driven motion but the frame (axis basis construction + envelope + temporal phase per node) survives.

**Force-layout core.** Repulsion + category anchor springs + center clamp + velocity damping. Known debt: O(n²) pairwise pass — fine to ~150 nodes, needs a spatial grid or Barnes-Hut beyond that. Structure survives; inner loop gets replaced when scale demands.

**Interaction skeleton.** Custom orbit (azimuth/polar/dolly with smoothing), pinch zoom, drag-vs-tap discrimination, raycast selection against glow sprites, slide-in detail panel, label toggles. All transferable as-is.

**Claude explain flow.** Prompt template (connection metadata → 3-4 sentence plain-language verdict), API call shape, and the local rule-based fallback so the button always answers. v2 wraps this behind the scrubbing pipeline (see ROADMAP — AI layer).

**Label-as-annotation system.** Canvas-texture HUD tags (accent marker, divider, name, colored underline, mono sub-line) rendered to sprites with proximity-based opacity. The *system* (offscreen canvas → texture → distance-faded sprite) carries; visual styling will be re-art-directed to the biolum palette.

**Architecture decisions (all of them).** Tauri + Rust agent; connection-table polling v1 with Npcap as the v2 capture upgrade; transport abstraction (one `Connection` interface, localhost/Tailscale/relay swappable); agent/relay/client split; pairing + token auth from day one; delta protocol at fixed tick rate; SQLite session history. None of this was prototype-specific. **Update (shipped):** the **v1-vs-Npcap call resolved in favour of polling** (process attribution + zero elevation; Npcap stays the documented v2 fork); the transport landed as *agent-serves-browser* over WebSocket (not Tauri IPC) — and the **Tauri native shell did land**, but as a thin window + tray + agent-sidecar *over that same WebSocket*, so the distributed spine was never forked. Pairing/token auth shipped (C2).

## Salvage with rework

**Nebula shader.** Keep as a module: Ashima simplex + 5-octave fBm + two-level domain warp, sampled along the camera ray, rendered to a half-res render target. For biolum: re-art-direct to deep-ocean (near-black blue-greens, darker overall, light attenuating downward like depth) and likely add a slow vertical drift to read as water column rather than sky.

**Particle field.** The 3-layer vertex-shader drift system survives, re-cast as *marine snow* — slower fall bias, sparser, finer. Same uniforms/structure.

**Sprite node system.** Glow+core sprites demote from being *the* node to being the bloom accent on top of actual organism geometry (pulsing membrane volumes — the new modeling work in v2).

## Leave behind

- Globe code and lat/lon positioning (cut in the graph-only pivot).
- Single-file HTML structure. v2 is a real project: Vite + React + TypeScript + react-three-fiber, modules, version control from commit one.
- Straight-line shared-infra links — re-imagined in biolum language (faint symbiotic threads) rather than `LineSegments`.
- The CDN-script Three.js r128 pin — v2 uses current Three via npm.

## Honest debt list (so v2 doesn’t inherit it silently)

*Status appended as each was addressed in v2.*

1. Force sim is O(n²) per frame on the main thread → move to a Web Worker, add spatial partitioning. — **Retired (B5):** a worker-offloaded sim with a uniform spatial grid (O(n·k)), unit-tested, behind `?layout=force`; the default layout is deterministic (no per-frame CPU layout).
1. Ribbon rebuild is per-frame per-node CPU work → acceptable at 22 nodes; at 200+, move path math into the vertex shader. — **Retired (B4):** tendrils are one instanced GPU ribbon; sway/width/motes all computed in the vertex/fragment shader, no CPU rebuild.
1. No state management — globals everywhere → Zustand store with the delta-mirror pattern. — **Retired (B1/C1):** Zustand delta-mirror; a separate render store for selection.
1. Raycasting sprites is imprecise at small sizes → switch to an ID-based picking pass or larger invisible hit proxies. — **Addressed (B3):** picking raycasts the *undisplaced* instanced spheres (displacement is shader-only), so the hit area is the clean sphere.
1. Labels allocate one canvas+texture per node → fine at this count; atlas them if endpoint counts grow. — Unchanged; still fine at current counts.