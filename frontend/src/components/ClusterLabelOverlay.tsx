// DOM overlay for the cluster labels. Sits above the canvas and draws a small pill
// at each group's projected centroid (name + member count). Positions are produced
// by the in-canvas projector (ClusterLabels) and read from the render store. The
// pills are pointer-transparent so they never intercept clicks/orbit on the scene.

import { useRenderStore } from "../scene/useRenderStore";

export function ClusterLabelOverlay() {
  const labels = useRenderStore((s) => s.clusterLabels);
  if (labels.length === 0) return null;

  return (
    <div className="clusters" aria-hidden>
      {labels.map((l) => (
        <div className="cluster" key={l.id} style={{ left: l.x, top: l.y }}>
          <span className="cluster__name">{l.name}</span>
          <span className="cluster__count">{l.count}</span>
        </div>
      ))}
    </div>
  );
}
