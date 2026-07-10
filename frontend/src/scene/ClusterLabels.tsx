// Cluster labels (graph-exploration legibility). The group-by layouts pull nodes
// into clusters by process / org / country, but a cluster is just a glowing blob
// until it's named. This component runs inside the Canvas, averages each group's
// live node positions into a centroid, projects it to screen space, and publishes
// the result to the render store; the DOM overlay (ClusterLabelOverlay) draws the
// pills on top of the canvas.
//
// It is throttled (~15 Hz) and capped to the busiest groups, so even a churny world
// only nudges a handful of DOM nodes a few times a second — never per frame. Labels
// only exist for the dynamic layouts; the static category layout is covered by the
// always-on legend, so we clear them there.

import { useMemo, useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

import type { Flow } from "../protocol";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { useViewStore } from "../store/useViewStore";
import { useRenderStore, type ClusterLabel } from "./useRenderStore";
import { forceLayout } from "./force/forceLayout";
import { groupKey, relationLabel, type RelationKey } from "./relationships";

const THROTTLE = 4; // update every Nth frame (~15 Hz at 60 fps)
const MAX_LABELS = 14;

export function ClusterLabels() {
  const flows = useNetscopeStore((s) => s.flows);
  const layout = useViewStore((s) => s.layout);
  const setClusterLabels = useRenderStore((s) => s.setClusterLabels);
  const camera = useThree((s) => s.camera);
  const size = useThree((s) => s.size);

  const frame = useRef(0);
  const lastCount = useRef(0);
  const tmp = useMemo(() => new THREE.Vector3(), []);
  // Reused across frames so the ~15 Hz projection allocates no per-group garbage.
  const groups = useMemo(
    () => new Map<string, { x: number; y: number; z: number; n: number; sample: Flow }>(),
    [],
  );

  useFrame(() => {
    frame.current = (frame.current + 1) % THROTTLE;
    if (frame.current !== 0) return;

    // Static category layout: the legend names the categories, so no floating labels.
    if (layout === "category") {
      if (lastCount.current !== 0) {
        setClusterLabels([]);
        lastCount.current = 0;
      }
      return;
    }

    // What dimension to name clusters by. `force` still clusters by category.
    const key: RelationKey =
      layout === "process" || layout === "org" || layout === "country" ? layout : "category";

    // Accumulate each group's centroid (running sum) + a sample member for the label.
    // Plain-number accumulation into a reused map — no Vector3 churn per node/group.
    groups.clear();
    for (const f of flows.values()) {
      const k = groupKey(f, key);
      forceLayout.getPosition(f, layout, tmp);
      const g = groups.get(k);
      if (g) {
        g.x += tmp.x;
        g.y += tmp.y;
        g.z += tmp.z;
        g.n += 1;
      } else {
        groups.set(k, { x: tmp.x, y: tmp.y, z: tmp.z, n: 1, sample: f });
      }
    }

    camera.updateMatrixWorld();
    const labels: ClusterLabel[] = [];
    for (const [id, g] of groups) {
      tmp.set(g.x / g.n, g.y / g.n, g.z / g.n).project(camera);
      if (tmp.z > 1) continue; // behind the camera / beyond far plane
      labels.push({
        id,
        name: relationLabel(g.sample, key),
        count: g.n,
        x: (tmp.x * 0.5 + 0.5) * size.width,
        y: (-tmp.y * 0.5 + 0.5) * size.height,
      });
    }
    // Busiest groups win the on-screen budget.
    labels.sort((a, b) => b.count - a.count);
    const top = labels.slice(0, MAX_LABELS);
    // Don't churn the store with empty arrays once we've already cleared.
    if (top.length === 0 && lastCount.current === 0) return;
    lastCount.current = top.length;
    setClusterLabels(top);
  });

  return null;
}
