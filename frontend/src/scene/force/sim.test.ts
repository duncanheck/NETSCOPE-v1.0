import { describe, it, expect } from "vitest";
import { ForceSim, DEFAULT_PARAMS } from "./sim";

// Build a sim with n nodes, all sharing one anchor at the origin unless given.
function makeSim(positions: number[], anchors?: number[]) {
  const pos = new Float32Array(positions);
  const anc = new Float32Array(anchors ?? new Array(positions.length).fill(0));
  return new ForceSim(pos, anc);
}

function dist(p: Float32Array, i: number, j: number): number {
  const dx = p[i * 3] - p[j * 3];
  const dy = p[i * 3 + 1] - p[j * 3 + 1];
  const dz = p[i * 3 + 2] - p[j * 3 + 2];
  return Math.sqrt(dx * dx + dy * dy + dz * dz);
}

describe("ForceSim", () => {
  it("springs a lone node toward its anchor", () => {
    const sim = makeSim([5, 5, 5], [0, 0, 0]);
    const start = Math.hypot(5, 5, 5);
    for (let i = 0; i < 800; i++) sim.step(1 / 60);
    const d = Math.hypot(sim.positions[0], sim.positions[1], sim.positions[2]);
    expect(d).toBeLessThan(1.0); // settled close to the anchor
    expect(d).toBeLessThan(start * 0.2); // and well in from where it started
  });

  it("repels two coincident nodes apart", () => {
    // Two nodes almost on top of each other, same anchor.
    const sim = makeSim([0.01, 0, 0, -0.01, 0, 0], [0, 0, 0, 0, 0, 0]);
    for (let i = 0; i < 400; i++) sim.step(1 / 60);
    expect(dist(sim.positions, 0, 1)).toBeGreaterThan(0.3); // pushed apart
  });

  it("stays finite and bounded from random initial positions", () => {
    const n = 120;
    const pos: number[] = [];
    const anc: number[] = [];
    for (let i = 0; i < n; i++) {
      pos.push((Math.random() * 2 - 1) * 8, (Math.random() * 2 - 1) * 8, (Math.random() * 2 - 1) * 8);
      // a couple of distinct anchors
      const a = i % 2 === 0 ? [3, 0, 0] : [-3, 0, 0];
      anc.push(a[0], a[1], a[2]);
    }
    const sim = makeSim(pos, anc);
    for (let i = 0; i < 300; i++) sim.step(1 / 60);
    for (let i = 0; i < pos.length; i++) {
      expect(Number.isFinite(sim.positions[i])).toBe(true);
    }
    for (let i = 0; i < n; i++) {
      const r = Math.hypot(sim.positions[i * 3], sim.positions[i * 3 + 1], sim.positions[i * 3 + 2]);
      expect(r).toBeLessThanOrEqual(DEFAULT_PARAMS.boundsRadius + 0.01);
    }
  });

  it("recovers a NaN position to a finite value", () => {
    const sim = makeSim([0, 0, 0, NaN, NaN, NaN], [0, 0, 0, 1, 1, 1]);
    sim.step(1 / 60);
    expect(Number.isFinite(sim.positions[3])).toBe(true);
    expect(Number.isFinite(sim.positions[4])).toBe(true);
    expect(Number.isFinite(sim.positions[5])).toBe(true);
  });

  it("settles to a steady state (low velocity) and stops drifting", () => {
    const sim = makeSim([2, 0, 0, -2, 0, 0, 0, 2, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0]);
    for (let i = 0; i < 600; i++) sim.step(1 / 60);
    const snap = Float32Array.from(sim.positions);
    for (let i = 0; i < 60; i++) sim.step(1 / 60);
    // After settling, one more second of stepping barely moves anything.
    let moved = 0;
    for (let i = 0; i < snap.length; i++) moved += Math.abs(sim.positions[i] - snap[i]);
    expect(moved).toBeLessThan(0.5);
  });
});
