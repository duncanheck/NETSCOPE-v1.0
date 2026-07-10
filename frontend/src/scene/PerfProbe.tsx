// In-canvas performance probe (B5). Samples frame time and the renderer's
// draw-call / triangle counters into the `perfStats` singleton each frame.
//
// DeepOcean takes over the render loop (a priority-1 useFrame), so to count ALL
// passes — ocean + composite + main scene — we disable three's automatic per-call
// reset and reset the counters ourselves: this probe runs at priority 0 (before
// DeepOcean renders), so on each frame it reads the totals accumulated by the
// previous frame's renders, then clears them for the frame about to be drawn.

import { useEffect } from "react";
import { useFrame, useThree } from "@react-three/fiber";

import { perfStats } from "./perf";

export function PerfProbe() {
  const gl = useThree((s) => s.gl);

  useEffect(() => {
    gl.info.autoReset = false;
    return () => {
      gl.info.autoReset = true;
    };
  }, [gl]);

  useFrame((_, delta) => {
    const ms = delta * 1000;
    // EMA so the readout is steady rather than jittery.
    perfStats.frameMs += (ms - perfStats.frameMs) * 0.1;
    perfStats.fps = perfStats.frameMs > 0 ? 1000 / perfStats.frameMs : 0;
    perfStats.drawCalls = gl.info.render.calls;
    perfStats.triangles = gl.info.render.triangles;
    gl.info.reset();
  }, 0);

  return null;
}
