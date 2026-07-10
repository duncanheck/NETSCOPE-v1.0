// Force-directed layout core (ROADMAP B5). A small, dependency-free simulation
// over flat Float32Arrays so it can run in a Web Worker and be unit-tested without
// a browser. This is the SALVAGE-#1 remediation: the prototype's O(n²) per-frame
// force layout on the main thread becomes an O(n·k) sim (repulsion via a uniform
// spatial grid) running off the render thread (see forceWorker.ts).
//
// Stability is the priority — this runs unseen on the user's machine. Forces are
// bounded, integration is velocity-damped with a speed clamp, positions are
// clamped to a sphere, and every value is NaN-guarded, so the worst case is a
// gently-drifting layout, never an explosion. Seeded from the deterministic
// clustering, it starts at the known-good layout and only relaxes from there.

export interface SimParams {
  /** Repulsion strength between nearby nodes. */
  repulsion: number;
  /** Radius within which repulsion acts (also the spatial-grid cell size). */
  repulsionRadius: number;
  /** Spring constant pulling each node toward its category anchor. */
  anchorSpring: number;
  /** Per-step velocity retention (< 1). */
  damping: number;
  /** Max speed, so a transient large force can't fling a node away. */
  maxSpeed: number;
  /** Hard clamp on distance from origin. */
  boundsRadius: number;
}

export const DEFAULT_PARAMS: SimParams = {
  repulsion: 1.1,
  repulsionRadius: 2.6,
  anchorSpring: 2.4,
  damping: 0.9,
  maxSpeed: 6,
  boundsRadius: 13,
};

const SUBSTEP = 1 / 60; // integrate at a fixed dt regardless of tick rate

export class ForceSim {
  readonly count: number;
  /** xyz per node — the live layout, read by the renderer. */
  readonly positions: Float32Array;
  private readonly velocities: Float32Array;
  /** xyz per node — the category anchor each node springs toward. */
  private readonly anchors: Float32Array;
  private readonly params: SimParams;

  // Uniform spatial grid, rebuilt each step: cellKey → node indices.
  private grid = new Map<number, number[]>();

  constructor(
    positions: Float32Array,
    anchors: Float32Array,
    params: SimParams = DEFAULT_PARAMS,
  ) {
    this.count = positions.length / 3;
    this.positions = positions;
    this.anchors = anchors;
    this.velocities = new Float32Array(positions.length);
    this.params = params;
  }

  /** Advance the simulation by `dt` seconds (split into fixed substeps). */
  step(dt: number): void {
    // Cap dt so a stall (backgrounded tab) can't integrate a huge jump.
    let remaining = Math.min(dt, 0.1);
    while (remaining > 1e-4) {
      this.substep(Math.min(SUBSTEP, remaining));
      remaining -= SUBSTEP;
    }
  }

  private substep(dt: number): void {
    const { repulsion, repulsionRadius, anchorSpring, damping, maxSpeed, boundsRadius } =
      this.params;
    const pos = this.positions;
    const vel = this.velocities;
    const anc = this.anchors;
    const n = this.count;

    this.buildGrid();
    const r2 = repulsionRadius * repulsionRadius;

    for (let i = 0; i < n; i++) {
      const ix = i * 3;
      let fx = 0;
      let fy = 0;
      let fz = 0;

      // Repulsion from neighbours in the 27 surrounding grid cells.
      this.forEachNeighbour(i, (j) => {
        const jx = j * 3;
        const dx = pos[ix] - pos[jx];
        const dy = pos[ix + 1] - pos[jx + 1];
        const dz = pos[ix + 2] - pos[jx + 2];
        const d2 = dx * dx + dy * dy + dz * dz;
        if (d2 > 0 && d2 < r2) {
          // Inverse-square, with the radius bounding the magnitude (no singularity
          // blow-up because d2 is the denominator and we cap via maxSpeed anyway).
          const inv = 1 / Math.max(d2, 0.05);
          const f = repulsion * inv;
          const d = Math.sqrt(d2);
          fx += (dx / d) * f;
          fy += (dy / d) * f;
          fz += (dz / d) * f;
        }
      });

      // Spring toward the category anchor.
      fx += (anc[ix] - pos[ix]) * anchorSpring;
      fy += (anc[ix + 1] - pos[ix + 1]) * anchorSpring;
      fz += (anc[ix + 2] - pos[ix + 2]) * anchorSpring;

      // Semi-implicit Euler with damping.
      let vx = (vel[ix] + fx * dt) * damping;
      let vy = (vel[ix + 1] + fy * dt) * damping;
      let vz = (vel[ix + 2] + fz * dt) * damping;

      // Speed clamp.
      const sp = Math.sqrt(vx * vx + vy * vy + vz * vz);
      if (sp > maxSpeed) {
        const s = maxSpeed / sp;
        vx *= s;
        vy *= s;
        vz *= s;
      }

      let px = pos[ix] + vx * dt;
      let py = pos[ix + 1] + vy * dt;
      let pz = pos[ix + 2] + vz * dt;

      // Clamp to the bounding sphere.
      const dist = Math.sqrt(px * px + py * py + pz * pz);
      if (dist > boundsRadius) {
        const s = boundsRadius / dist;
        px *= s;
        py *= s;
        pz *= s;
        vx *= 0.5;
        vy *= 0.5;
        vz *= 0.5;
      }

      // NaN guard — never let a bad value persist into the layout.
      if (!Number.isFinite(px) || !Number.isFinite(py) || !Number.isFinite(pz)) {
        px = anc[ix];
        py = anc[ix + 1];
        pz = anc[ix + 2];
        vx = vy = vz = 0;
      }

      vel[ix] = vx;
      vel[ix + 1] = vy;
      vel[ix + 2] = vz;
      pos[ix] = px;
      pos[ix + 1] = py;
      pos[ix + 2] = pz;
    }
  }

  // --- spatial grid ---------------------------------------------------------

  private cellKey(cx: number, cy: number, cz: number): number {
    // Cantor-ish hash of three signed cell coords into one number. Cells are
    // small integers; this is collision-free for the ranges we use.
    const ox = cx + 512;
    const oy = cy + 512;
    const oz = cz + 512;
    return (ox * 1024 + oy) * 1024 + oz;
  }

  private buildGrid(): void {
    const cell = this.params.repulsionRadius;
    this.grid.clear();
    const pos = this.positions;
    for (let i = 0; i < this.count; i++) {
      const cx = Math.floor(pos[i * 3] / cell);
      const cy = Math.floor(pos[i * 3 + 1] / cell);
      const cz = Math.floor(pos[i * 3 + 2] / cell);
      const key = this.cellKey(cx, cy, cz);
      const bucket = this.grid.get(key);
      if (bucket) bucket.push(i);
      else this.grid.set(key, [i]);
    }
  }

  private forEachNeighbour(i: number, fn: (j: number) => void): void {
    const cell = this.params.repulsionRadius;
    const pos = this.positions;
    const cx = Math.floor(pos[i * 3] / cell);
    const cy = Math.floor(pos[i * 3 + 1] / cell);
    const cz = Math.floor(pos[i * 3 + 2] / cell);
    for (let dx = -1; dx <= 1; dx++) {
      for (let dy = -1; dy <= 1; dy++) {
        for (let dz = -1; dz <= 1; dz++) {
          const bucket = this.grid.get(this.cellKey(cx + dx, cy + dy, cz + dz));
          if (!bucket) continue;
          for (const j of bucket) {
            if (j !== i) fn(j);
          }
        }
      }
    }
  }
}
