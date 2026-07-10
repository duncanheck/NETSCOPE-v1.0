# docs/performance.md — Frame budget + rendering performance

*Status: **landed** (milestone B5) — the architecture, the instrumentation, and
the worker-offloaded force layout. The frame-time **numbers** are captured on real
hardware by the in-app overlay (they can't be measured in the headless CI/dev
container that produced the code); the table below is filled by running the
documented scenarios, and the method is pinned so the numbers are reproducible
rather than "fast on my machine that day" (PITFALLS B5).*

## The budget, by construction

NETSCOPE was built GPU-first, so the frame cost is dominated by fragment work, not
by per-object CPU overhead. The draw-call count is **flat in node count** — every
layer is one instanced (or full-screen) draw:

| Layer | Draws | Notes |
|---|---|---|
| Deep-ocean background | 2 | fBm→half-res target, then composite (B2) |
| Marine snow | 3 | three parallax `Points` layers (B2) |
| Tendrils | 1 | one instanced ribbon, all connections (B4) |
| Host core | 1 | single mesh |
| Organism nodes | 1 | one `InstancedMesh` of all endpoints (B3) |
| Glow halos | 1 | one instanced additive layer (B3) |
| **Total** | **~9** | **independent of the number of connections** |

50 endpoints and 300 endpoints issue the *same* ~9 draw calls. That is the whole
point of the instancing decisions (PITFALLS B3): node count scales the *instance*
count inside one draw, not the number of draws.

### Why there's no per-frame CPU layout in the default

The prototype's O(n²) force layout ran on the main thread every frame — honest debt
#1. The default NETSCOPE layout avoids it entirely: node positions are
**deterministic** (category clustering + id hash, computed once), and all motion —
membrane wobble, tendril sway, traffic motes, pulse — lives in **vertex/fragment
shaders**, driven by a single `uTime` uniform. So the per-frame CPU cost of the
scene is essentially: advance a few uniforms, and (only when the world changes, at
≤ a few Hz) rewrite instance attributes. Per-frame data never touches React state
(PITFALLS B1).

### The half-res quality/cost trade

The ocean's fBm+domain-warp is the heaviest fragment program, so it renders to a
**half-resolution** target and is bilinearly upscaled — a quarter of the fragment
work, invisibly soft for a murky volume (see ARCHITECTURE.md "B2"). Octave count,
RT scale, and particle density are chosen by a **startup GPU micro-benchmark**
(`scene/capability.ts`), not user-agent sniffing, so a weak GPU drops to a cheaper
tier automatically.

### Bloom, folded into the same pipeline (B6)

True bloom (`EffectComposer` + `UnrealBloomPass`) is the one effect that lands on
*top* of this budget — so it folds into the existing manual loop rather than adding
a second render owner. On the **HIGH tier** DeepOcean draws the combined frame
(ocean composite + scene) into one full-res **HalfFloat** target, then a three-pass
composer (`TexturePass → UnrealBloomPass → CopyShader`) blooms it to screen. The
extra cost is the bloom's mip blurs — flat in node count, like everything else
here — and it is **gated to HIGH**: the same micro-benchmark that drops a weak GPU
to LOW also drops bloom, where the original direct composite-to-screen path runs
unchanged. `CopyShader` (not `OutputPass`) does the final blit so the base image is
byte-identical to the no-bloom path and the glow is purely additive. `?bloom=on|off`
forces it either way for A/B comparison.

## The worker-offloaded force layout (SALVAGE debt #1, retired)

B5 also ships the force simulation the deterministic layout had deferred — as an
**opt-in** mode (`?layout=force`), so the verified default is untouched:

- **It runs in a Web Worker**, off the render thread (`scene/force/forceWorker.ts`).
  The main thread sends the node set on change and reads back streamed positions;
  the render loop is never blocked by the sim.
- **Repulsion is O(n·k), not O(n²)** — a uniform spatial grid
  (`scene/force/sim.ts`) so each node only tests neighbours in adjacent cells.
- **It is stability-first and unit-tested** (`sim.test.ts`, run in CI via
  `pnpm test`): bounded forces, velocity-damped integration with a speed clamp,
  positions clamped to a sphere, NaN-guarded, and seeded from the deterministic
  layout so it starts at the known-good arrangement and only relaxes. The tests
  assert it springs to anchors, repels coincident nodes, stays finite/bounded from
  random starts, recovers an injected NaN, and settles to a steady state.

This is the credibility point as much as any number: the O(n²) trap was avoided by
design, and the force sim that *does* ship is offloaded, partitioned, and proven
sound by tests — not hand-waved.

## Methodology (pin this before recording numbers)

- **Instrument:** the in-app perf overlay — press **`P`** — reads frame time, FPS,
  draw calls, triangles, node count, and GPU tier straight from the renderer
  (`scene/PerfProbe.tsx` counts *all* passes by disabling three's per-call reset).
- **Scenarios:** the mock fixture seeds a fixed, synthetic node set via
  **`?nodes=N`** — record at **N = 50, 150, 300**. Use the mock (deterministic,
  reproducible), not live capture (uncontrolled count).
- **Surfaces:** a desktop GPU and a phone (the capability gate behaves differently
  on each — record the tier it chose).
- **Record:** median frame time over ~10 s steady-state per scenario, plus the
  hardware (GPU/SoC), browser, and build (`git rev-parse --short HEAD`).
- **Default vs force layout:** record both (`?nodes=N` and `?nodes=N&layout=force`)
  — the force sim adds per-frame instance-matrix rewrites + the worker, so the
  delta is the cost of organic motion.

## Results

*Reproduce: `cd frontend && pnpm dev`, open `http://localhost:5173/?nodes=150`,
press `P`, read the steady-state frame time. Fill one row per scenario per device.*

| Device / GPU | Browser | Build | N | Layout | Tier | Frame (ms) | FPS | Draws |
|---|---|---|---|---|---|---|---|---|
| _e.g. M2 MacBook Air_ | | | 50 | default | | | | ~9 |
| | | | 150 | default | | | | ~9 |
| | | | 300 | default | | | | ~9 |
| | | | 150 | force | | | | ~9 |
| _phone_ | | | 150 | default | | | | ~9 |

> These rows are intentionally blank: they must be filled from a real GPU, which
> the build/test environment doesn't have. The instrument and scenarios above make
> them a five-minute capture, and the ~9-draw budget is structural (verified by the
> code, not the GPU).

## Reproduce the force-sim correctness checks

```bash
cd frontend
pnpm test            # force-sim unit tests (grid, springs, stability, NaN guard)
pnpm dev             # then open /?nodes=300&layout=force to watch it relax
```
