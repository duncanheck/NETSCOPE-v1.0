// A tiny store for render-side state, kept separate from the netscope data store
// (which mirrors the agent's world). This holds what the renderer learns/owns at
// runtime — the chosen GPU capability tier, and the selected/hovered node — so the
// HUD and the scene can share selection without the data store knowing about it.
//
// Selection lives here (not in the data store) because it's a view concern and
// changes at UI rate; the 3D scene and the HUD's connection list both read and
// write it, which is how clicking a node highlights its row and vice-versa.

import { create } from "zustand";
import type { RenderTier } from "./capability";

/** A projected group label: where a cluster's centroid lands on screen + what it is.
 *  Produced by the in-canvas projector (ClusterLabels), consumed by the DOM overlay. */
export interface ClusterLabel {
  id: string;
  name: string;
  count: number;
  x: number;
  y: number;
}

interface RenderState {
  tier: RenderTier | null;
  setTier: (tier: RenderTier) => void;

  /** Flow id of the selected node, or null. */
  selectedId: string | null;
  /** Flow id under the cursor, or null. */
  hoveredId: string | null;
  /** Flow id the view is "focused" on (drill-down): the camera flies to it, its
   *  relatives stay lit and everything else dims. Independent of selection so the
   *  inspector can stay open while focus drives the scene. */
  focusId: string | null;
  select: (id: string | null) => void;
  hover: (id: string | null) => void;
  /** Focus a node (also selects it so the inspector follows), or clear with null. */
  setFocus: (id: string | null) => void;

  /** Free-text filter (the connection-list search box). Shared with the scene so a
   *  query isolates the matching nodes in 3D, not just the list. */
  filter: string;
  setFilter: (q: string) => void;

  /** Screen-projected cluster labels for the active group-by layout (empty in the
   *  static category layout, where the legend covers the categories). */
  clusterLabels: ClusterLabel[];
  setClusterLabels: (labels: ClusterLabel[]) => void;
}

export const useRenderStore = create<RenderState>((set) => ({
  tier: null,
  setTier: (tier) => set({ tier }),

  selectedId: null,
  hoveredId: null,
  focusId: null,
  filter: "",
  setFilter: (filter) => set({ filter }),
  clusterLabels: [],
  setClusterLabels: (clusterLabels) => set({ clusterLabels }),
  // Clicking the already-selected node clears it (toggle).
  select: (id) => set((s) => ({ selectedId: s.selectedId === id ? null : id })),
  hover: (id) => set({ hoveredId: id }),
  setFocus: (id) =>
    set((s) => {
      const focusId = s.focusId === id ? null : id;
      // Focusing implies selecting; clearing focus leaves selection untouched.
      return focusId ? { focusId, selectedId: focusId } : { focusId };
    }),
}));
