// Force-layout manager (ROADMAP B5, extended for graph exploration). A small
// singleton that owns the Web Worker, feeds it the node set + per-node anchors when
// the world or the layout mode changes, and holds the latest positions for the
// renderer to read. `getPosition` returns the live simulated position when a dynamic
// layout is active, or the deterministic position for the current mode otherwise.
//
// Modes:
//   category — the original static clustering (no sim, no worker).
//   force    — relax the category clustering with repulsion + anchor springs.
//   process / org / country — cluster (and separate) by that dimension, springing
//                             each node toward its *group* anchor.
//
// The worker only ever sees anchors + seeds; it doesn't know what a "mode" means, so
// all the semantics stay here and the sim (sim.ts) stays a pure black box.

import * as THREE from "three";
import type { Flow } from "../../protocol";
import type { LayoutMode } from "../../store/useViewStore";
import { anchorFor, nodePosition, groupAnchor, groupedPosition, HOST_CENTER } from "../layout";
import { DEFAULT_PARAMS, type SimParams } from "./sim";
import { groupKey } from "../relationships";

interface PositionsMessage {
  gen: number;
  positions: Float32Array;
}

/** Dynamic (sim-driven) layouts. `category` is static and needs no worker. */
export function isDynamic(mode: LayoutMode): boolean {
  return mode !== "category";
}

/** Scale the layout outward as the world grows so a busy network (150–200 nodes)
 *  reads as separable regions instead of a dense clump. 1× at small counts, easing
 *  up to ~1.9× — paired with the camera's wider zoom-out range. */
function spreadFor(n: number): number {
  return THREE.MathUtils.clamp(Math.sqrt(n / 26), 1, 1.9);
}

/** The anchor a flow springs toward under `mode`. */
function anchorForMode(flow: Flow, mode: LayoutMode): THREE.Vector3 {
  if (mode === "category" || mode === "force") return anchorFor(flow.category);
  return groupAnchor(groupKey(flow, mode));
}

/** The deterministic (no-sim) position for a flow under `mode`. */
function seedForMode(flow: Flow, mode: LayoutMode): THREE.Vector3 {
  if (mode === "category" || mode === "force") return nodePosition(flow.id, flow.category);
  return groupedPosition(flow.id, groupKey(flow, mode));
}

class ForceLayout {
  private worker: Worker | null = null;
  private gen = 0;
  /** Positions for the current generation, indexed by `indexOf`. */
  private positions: Float32Array | null = null;
  private indexOf = new Map<string, number>();
  /** Last known live position per id, snapshotted at each re-push so existing nodes
   *  hold their place while the worker recomputes the new set — without it they'd
   *  flash back to their deterministic seed for a frame or two on every add/remove. */
  private lastById = new Map<string, [number, number, number]>();
  /** The mode the worker is currently simulating — guards against mapping a stale
   *  mode's positions onto a freshly-switched layout. */
  private workerMode: LayoutMode = "category";
  /** Outward scale for the current node count (de-clumps large worlds). Public so
   *  the camera can frame the spread. */
  spreadFactor = 1;
  /** Bumped whenever the live positions change (a worker reply) or the world/mode is
   *  re-pushed. The renderer reads it to skip the per-frame instance rewrite on
   *  frames where nothing moved — so once a dynamic layout settles (the worker goes
   *  quiet), the scene stops re-uploading instance buffers entirely. */
  version = 0;

  private ensureWorker(): Worker {
    if (!this.worker) {
      this.worker = new Worker(new URL("./forceWorker.ts", import.meta.url), {
        type: "module",
      });
      this.worker.onmessage = (e: MessageEvent<PositionsMessage>) => {
        if (e.data.gen === this.gen) {
          this.positions = e.data.positions;
          this.version++;
        }
      };
    }
    return this.worker;
  }

  /** Push the current world + mode to the worker (called when flows or mode change). */
  update(flows: Map<string, Flow>, mode: LayoutMode): void {
    this.workerMode = mode;
    this.version++; // a re-push is a change the renderer must pick up

    // Snapshot the current live positions by id so getPosition can hold existing
    // nodes in place during the gap before the worker replies (no seed flash). Only
    // the current set is kept, so this stays bounded to the node count.
    const snap = new Map<string, [number, number, number]>();
    if (this.positions) {
      const p = this.positions;
      for (const [id, i] of this.indexOf) {
        if (i * 3 + 2 < p.length) snap.set(id, [p[i * 3], p[i * 3 + 1], p[i * 3 + 2]]);
      }
    }
    this.lastById = snap;

    const list = [...flows.values()].sort((a, b) => a.id.localeCompare(b.id));
    const n = list.length;
    // Recompute the spread first — it scales the static layout too (read in
    // getPosition), so it must be set even when there's no worker.
    this.spreadFactor = spreadFor(n);
    const sp = this.spreadFactor;

    if (!isDynamic(mode)) {
      // Static layout: stop the sim, drop positions; the renderer reads seeds.
      this.positions = null;
      this.worker?.postMessage({ type: "stop" });
      return;
    }

    const ids: string[] = new Array(n);
    const anchors = new Float32Array(n * 3);
    const seeds = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      const f = list[i];
      ids[i] = f.id;
      const a = anchorForMode(f, mode);
      anchors[i * 3] = HOST_CENTER.x + (a.x - HOST_CENTER.x) * sp;
      anchors[i * 3 + 1] = HOST_CENTER.y + (a.y - HOST_CENTER.y) * sp;
      anchors[i * 3 + 2] = HOST_CENTER.z + (a.z - HOST_CENTER.z) * sp;
      const s = seedForMode(f, mode);
      seeds[i * 3] = HOST_CENTER.x + (s.x - HOST_CENTER.x) * sp;
      seeds[i * 3 + 1] = HOST_CENTER.y + (s.y - HOST_CENTER.y) * sp;
      seeds[i * 3 + 2] = HOST_CENTER.z + (s.z - HOST_CENTER.z) * sp;
    }

    this.gen++;
    this.indexOf = new Map(ids.map((id, i) => [id, i]));
    this.positions = null; // until the worker replies for this generation
    // Grow the bounding sphere with the spread so the clamp doesn't squash it back.
    const params: SimParams = {
      ...DEFAULT_PARAMS,
      boundsRadius: DEFAULT_PARAMS.boundsRadius * sp,
    };
    this.ensureWorker().postMessage({ type: "set", gen: this.gen, ids, anchors, seeds, params });
  }

  /** Live position for a flow under `mode`, or the (spread-scaled) deterministic one
   *  if the sim isn't active/ready. `mode` is passed by the caller (from the store)
   *  so a switch can never map positions simulated for one mode onto another. */
  getPosition(flow: Flow, mode: LayoutMode, out: THREE.Vector3): THREE.Vector3 {
    if (isDynamic(mode) && mode === this.workerMode && this.positions) {
      const i = this.indexOf.get(flow.id);
      if (i !== undefined && i * 3 + 2 < this.positions.length) {
        return out.set(
          this.positions[i * 3],
          this.positions[i * 3 + 1],
          this.positions[i * 3 + 2],
        );
      }
    }
    // Worker not ready yet (just re-pushed): hold the last known live position so an
    // existing node doesn't flash to its seed. Genuinely new nodes fall through.
    if (isDynamic(mode)) {
      const last = this.lastById.get(flow.id);
      if (last) return out.set(last[0], last[1], last[2]);
    }
    const s = seedForMode(flow, mode);
    const sp = this.spreadFactor;
    return out.set(
      HOST_CENTER.x + (s.x - HOST_CENTER.x) * sp,
      HOST_CENTER.y + (s.y - HOST_CENTER.y) * sp,
      HOST_CENTER.z + (s.z - HOST_CENTER.z) * sp,
    );
  }

  dispose(): void {
    this.worker?.terminate();
    this.worker = null;
  }
}

export const forceLayout = new ForceLayout();
