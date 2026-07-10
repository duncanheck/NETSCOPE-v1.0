// Render performance stats (ROADMAP B5). A plain mutable singleton updated every
// frame by PerfProbe (no React state — per-frame writes must not re-render), read
// at a low rate by the PerfHud overlay. This is the measurement instrument the
// performance.md numbers are captured with.

export interface PerfStats {
  /** Exponential moving average of frame time, milliseconds. */
  frameMs: number;
  fps: number;
  /** Draw calls and triangles for the whole frame (all passes). */
  drawCalls: number;
  triangles: number;
}

export const perfStats: PerfStats = {
  frameMs: 16.7,
  fps: 60,
  drawCalls: 0,
  triangles: 0,
};
