// Performance overlay (B5). A compact top-right readout of frame time, FPS, draw
// calls, triangles, node count and the GPU tier — the numbers the performance.md
// budget is captured from. Toggle with the `p` key; hidden by default so it never
// obscures the organism unless you're measuring.

import { useEffect, useState } from "react";
import { perfStats } from "../scene/perf";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { useRenderStore } from "../scene/useRenderStore";
import { useViewStore } from "../store/useViewStore";
import { useFloatingPanel } from "./useFloatingPanel";

export function PerfHud() {
  // Visibility lives in the view store so the Settings panel checkbox and the `P`
  // key are the same switch.
  const open = useViewStore((s) => s.perfOpen);
  const togglePerf = useViewStore((s) => s.togglePerf);
  const [, tick] = useState(0);
  const nodes = useNetscopeStore((s) => s.flows.size);
  const tier = useRenderStore((s) => s.tier);
  const { ref, panelProps, handleProps } = useFloatingPanel({
    storageKey: "netscope.perf",
    // Bottom-right, clear of the Settings/System panels in the top-right.
    defaultPos: { x: window.innerWidth - 168, y: Math.max(16, window.innerHeight - 200) },
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Ignore the shortcut while typing in a field (filter box, pairing code…).
      const el = e.target as HTMLElement | null;
      if (el && el.closest("input, textarea, select")) return;
      if (e.key === "p" || e.key === "P") togglePerf();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [togglePerf]);

  // Re-render a few times a second to refresh the readout (not per frame).
  useEffect(() => {
    if (!open) return;
    const id = setInterval(() => tick((n) => n + 1), 333);
    return () => clearInterval(id);
  }, [open]);

  if (!open) return null;

  const fpsColor = perfStats.fps >= 55 ? "#3fd6c4" : perfStats.fps >= 30 ? "#ffb347" : "#ff6b6b";

  return (
    <div className="perf" ref={ref} {...panelProps}>
      <div className="perf__drag" {...handleProps} title="drag to move" />
      <div className="perf__row">
        <span>fps</span>
        <span style={{ color: fpsColor }}>{perfStats.fps.toFixed(0)}</span>
      </div>
      <div className="perf__row">
        <span>frame</span>
        <span>{perfStats.frameMs.toFixed(2)} ms</span>
      </div>
      <div className="perf__row">
        <span>draws</span>
        <span>{perfStats.drawCalls}</span>
      </div>
      <div className="perf__row">
        <span>tris</span>
        <span>{perfStats.triangles.toLocaleString()}</span>
      </div>
      <div className="perf__row">
        <span>nodes</span>
        <span>{nodes}</span>
      </div>
      <div className="perf__row">
        <span>tier</span>
        <span>{tier ? tier.label.split(" ")[0] : "—"}</span>
      </div>
      <div className="perf__hint">press P to hide</div>
    </div>
  );
}
