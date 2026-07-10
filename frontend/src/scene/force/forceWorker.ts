// The force-layout Web Worker (ROADMAP B5). It runs the simulation off the render
// thread: the main thread sends the node set (ids + per-node anchors + seed
// positions) on change, the worker steps the sim on a timer and posts the live
// positions back. Carrying a `gen` (generation) on both directions lets the main
// thread ignore positions that belong to a stale node set (after an add/remove),
// so an in-flight tick can never be mapped onto the wrong ids.

import { ForceSim, DEFAULT_PARAMS, type SimParams } from "./sim";

interface SetMessage {
  type: "set";
  gen: number;
  ids: string[];
  anchors: Float32Array;
  seeds: Float32Array;
  /** Sim tuning for this node set (e.g. a wider bounding sphere for big worlds). */
  params?: SimParams;
}
/** Switching to a static layout (`category`) stops the sim without tearing down
 *  the worker — continuity (`known`) is kept for when a dynamic mode resumes. */
interface StopMessage {
  type: "stop";
}
type WorkerMessage = SetMessage | StopMessage;

const TICK_MS = 33; // ~30 Hz; the renderer interpolates between these.
// Convergence: once the largest per-tick move stays below this (squared) for a run
// of ticks, the layout has settled — stop posting so the main thread stops rewriting
// instance buffers every frame. Any new `set` (world/mode change) resumes it.
const REST_EPS2 = 1e-4; // ≈0.01 world units of movement
const REST_TICKS = 12; // ~0.4s of stillness before idling

let sim: ForceSim | null = null;
let gen = 0;
let timer: ReturnType<typeof setInterval> | null = null;
// Last simulated position per id, so a changed node set keeps continuity.
const known = new Map<string, [number, number, number]>();
let ids: string[] = [];
// Convergence tracking: the previous posted frame, and how long we've been still.
let lastPosted: Float32Array | null = null;
let stillTicks = 0;

function halt(): void {
  sim = null;
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

self.onmessage = (e: MessageEvent<WorkerMessage>) => {
  const msg = e.data;
  if (msg.type === "stop") {
    halt();
    return;
  }
  if (msg.type !== "set") return;

  gen = msg.gen;
  ids = msg.ids;
  const n = ids.length;

  if (n === 0) {
    halt();
    return;
  }

  const positions = new Float32Array(n * 3);
  for (let i = 0; i < n; i++) {
    const prev = known.get(ids[i]);
    if (prev) {
      positions[i * 3] = prev[0];
      positions[i * 3 + 1] = prev[1];
      positions[i * 3 + 2] = prev[2];
    } else {
      // New node: start at its seed (the deterministic position).
      positions[i * 3] = msg.seeds[i * 3];
      positions[i * 3 + 1] = msg.seeds[i * 3 + 1];
      positions[i * 3 + 2] = msg.seeds[i * 3 + 2];
    }
  }

  sim = new ForceSim(positions, msg.anchors, msg.params ?? DEFAULT_PARAMS);
  // A new node set / mode is fresh motion — reset convergence and ensure we're ticking.
  lastPosted = null;
  stillTicks = 0;
  if (!timer) timer = setInterval(tick, TICK_MS);
};

function tick(): void {
  if (!sim) return;
  sim.step(TICK_MS / 1000);
  const p = sim.positions;
  for (let i = 0; i < ids.length; i++) {
    known.set(ids[i], [p[i * 3], p[i * 3 + 1], p[i * 3 + 2]]);
  }
  // Post a copy (the worker keeps its own buffer to keep stepping).
  const copy = p.slice();
  self.postMessage({ gen, positions: copy });

  // Convergence check: largest squared move since the last post. Once it stays
  // negligible for REST_TICKS, the layout has settled — idle the timer so we stop
  // posting (and the renderer stops re-uploading). Resumes on the next `set`.
  if (lastPosted && lastPosted.length === copy.length) {
    let maxD2 = 0;
    for (let i = 0; i < copy.length; i += 3) {
      const dx = copy[i] - lastPosted[i];
      const dy = copy[i + 1] - lastPosted[i + 1];
      const dz = copy[i + 2] - lastPosted[i + 2];
      const d2 = dx * dx + dy * dy + dz * dz;
      if (d2 > maxD2) maxD2 = d2;
    }
    if (maxD2 < REST_EPS2) {
      if (++stillTicks >= REST_TICKS && timer) {
        clearInterval(timer);
        timer = null;
      }
    } else {
      stillTicks = 0;
    }
  }
  lastPosted = copy;
}
