// Node layout (B3). Each flow gets a stable 3D position derived from its id and
// category: categories cluster around anchors, and a hash of the id scatters nodes
// on a small sphere around their anchor. Deterministic, so a node keeps its place
// across re-renders and a new flow simply appears where it belongs.
//
// This is deliberately NOT a force-directed simulation. The prototype's O(n²)
// per-frame force layout is honest debt (SALVAGE #1); B3 keeps the GPU work the
// star and defers a worker-offloaded force sim to B5. Clustering + hash scatter
// reads as organic without any per-frame CPU cost.

import * as THREE from "three";
import type { Category } from "../protocol";

// Where each category congregates in the water column. They ring the host core at
// the centre (0, 0.5, 0) — which is kept clear so tendrils radiate outward to each
// cluster (B4) rather than starting inside a node clump.
const ANCHORS: Record<Category, THREE.Vector3> = {
  service: new THREE.Vector3(0, 1.0, 5.5),
  cdn: new THREE.Vector3(5.5, 1.5, -2),
  tracker: new THREE.Vector3(-5.5, 1.0, 2),
  local: new THREE.Vector3(0, -4.0, -3.5),
  unknown: new THREE.Vector3(3.0, 4.0, -4.0),
};
const CLUSTER_RADIUS = 2.4;

/** The host machine — the centre every tendril begins from (B4). */
export const HOST_CENTER = new THREE.Vector3(0, 0.5, 0);

/** Cheap, stable string hash → unsigned 32-bit. */
function hash(str: string): number {
  let h = 2166136261 >>> 0; // FNV-1a
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** The category cluster anchor — the force sim (B5) springs nodes toward these. */
export function anchorFor(category: Category): THREE.Vector3 {
  return ANCHORS[category] ?? ANCHORS.unknown;
}

/** Scatter a point inside a sphere of `radius` around `anchor`, deterministically
 *  from `seed`. Shared by the category and group-by layouts so both read organic. */
function scatter(anchor: THREE.Vector3, seed: string, radius: number): THREE.Vector3 {
  const h = hash(seed);
  // Three independent unit values from the hash for a point on a sphere.
  const u = ((h & 0x3ff) / 0x3ff) * 2 - 1; // [-1,1]
  const theta = (((h >>> 10) & 0x3ff) / 0x3ff) * Math.PI * 2;
  const r = radius * Math.cbrt(((h >>> 20) & 0xfff) / 0xfff); // fill volume
  const rho = Math.sqrt(1 - u * u);
  return new THREE.Vector3(
    anchor.x + r * rho * Math.cos(theta),
    anchor.y + r * u,
    anchor.z + r * rho * Math.sin(theta),
  );
}

/** A deterministic position for a flow, clustered by category. */
export function nodePosition(id: string, category: Category): THREE.Vector3 {
  return scatter(ANCHORS[category] ?? ANCHORS.unknown, id, CLUSTER_RADIUS);
}

// --- Group-by layout --------------------------------------------------------
// Instead of five fixed category blobs, the group-by modes place each *value* of
// the chosen dimension (a process, an org, a country) at its own anchor on a shell
// around the host core, then scatter the value's members around it. The anchor is a
// stable hash of the value → a point on the sphere, so a given process always lands
// in the same place and the force sim's repulsion spreads the groups apart cleanly.

const GROUP_SHELL_RADIUS = 6.5;

/** Deterministic anchor for a group value, on a shell around the host core. */
export function groupAnchor(value: string): THREE.Vector3 {
  const h = hash(value || "∅");
  const y = ((h & 0xffff) / 0xffff) * 2 - 1; // latitude in [-1,1]
  const rho = Math.sqrt(Math.max(0, 1 - y * y));
  const theta = (((h >>> 16) & 0xffff) / 0xffff) * Math.PI * 2;
  return new THREE.Vector3(
    HOST_CENTER.x + GROUP_SHELL_RADIUS * rho * Math.cos(theta),
    HOST_CENTER.y + GROUP_SHELL_RADIUS * y * 0.55, // flatten vertically — readable
    HOST_CENTER.z + GROUP_SHELL_RADIUS * rho * Math.sin(theta),
  );
}

/** A deterministic position for a flow clustered under a group value. */
export function groupedPosition(id: string, value: string): THREE.Vector3 {
  return scatter(groupAnchor(value), id, CLUSTER_RADIUS * 0.8);
}

/** A stable per-node phase offset (0..2π) so wobble/pulse decorrelate. */
export function nodePhase(id: string): number {
  return (hash(id + "phase") / 0xffffffff) * Math.PI * 2;
}
