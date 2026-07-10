// The view-settings store. Everything the user used to set from the terminal — the
// layout mode (`?layout=force`), bloom (`?bloom=`), render tier (`?renderTier=`),
// wire encoding (`?encoding=` / VITE_WIRE_ENCODING), the synthetic stress count
// (`?nodes=N`) and the perf overlay (the `P` key) — now lives here, exposed through
// the Settings panel, applied live, and persisted across reloads.
//
// It is the single source of truth for view config. Imperative, non-React consumers
// (the mock churn engine, the wire codec, the capability gate) read it through
// `useViewStore.getState()` rather than re-parsing the URL, so there is one place a
// setting is decided. The legacy URL params still work — they *seed* the initial
// state — so existing links and docs keep functioning.

import { create } from "zustand";
import type { RelationKey } from "../scene/relationships";

/** How nodes are positioned. `category` is the original static clustering; `force`
 *  relaxes that with the worker sim; the rest cluster (and separate) by a meaningful
 *  dimension via the same sim. */
export type LayoutMode = "category" | "force" | "process" | "org" | "country";

/** Tri-state override for a measured/auto default (bloom, tier). */
export type AutoToggle = "auto" | "on" | "off";
export type TierPref = "auto" | "high" | "low";
export type EncodingPref = "json" | "msgpack";

export interface ViewState {
  layout: LayoutMode;
  /** Draw relationship edges between nodes sharing a key. */
  showEdges: boolean;
  /** Which dimension defines a relationship edge. */
  edgeBy: RelationKey;
  bloom: AutoToggle;
  tier: TierPref;
  encoding: EncodingPref;
  perfOpen: boolean;
  /** Synthetic node count for stress profiling (0 = off, real/seed feed). */
  stressNodes: number;
  /** Cinematic mode: hide all HUD/panels/overlays, just the organism. Session-
   *  only (a moment, not a saved preference) — never persisted. */
  immersive: boolean;

  setLayout: (m: LayoutMode) => void;
  setShowEdges: (v: boolean) => void;
  setEdgeBy: (k: RelationKey) => void;
  setBloom: (v: AutoToggle) => void;
  setTier: (v: TierPref) => void;
  setEncoding: (v: EncodingPref) => void;
  setPerfOpen: (v: boolean) => void;
  togglePerf: () => void;
  setStressNodes: (n: number) => void;
  setImmersive: (v: boolean) => void;
  toggleImmersive: () => void;
  reset: () => void;
}

const STORAGE_KEY = "netscope.view";

function param(name: string): string | null {
  if (typeof window === "undefined") return null;
  return new URLSearchParams(window.location.search).get(name);
}

/** Defaults seeded from the legacy URL params / env so old links keep working. */
function seeded(): Pick<
  ViewState,
  "layout" | "showEdges" | "edgeBy" | "bloom" | "tier" | "encoding" | "perfOpen" | "stressNodes"
> {
  const layoutParam = param("layout");
  const layout: LayoutMode =
    layoutParam === "force" ||
    layoutParam === "process" ||
    layoutParam === "org" ||
    layoutParam === "country"
      ? layoutParam
      : "category";

  const nodes = Number(param("nodes"));
  const stressNodes = Number.isFinite(nodes) && nodes > 0 ? Math.min(Math.floor(nodes), 1000) : 0;

  const encParam = param("encoding");
  const encoding: EncodingPref =
    encParam === "msgpack"
      ? "msgpack"
      : encParam === "json"
        ? "json"
        : import.meta.env.VITE_WIRE_ENCODING === "msgpack"
          ? "msgpack"
          : "json";

  const bloomParam = param("bloom");
  const bloom: AutoToggle = bloomParam === "on" ? "on" : bloomParam === "off" ? "off" : "auto";

  const tierParam = param("renderTier");
  const tier: TierPref = tierParam === "high" ? "high" : tierParam === "low" ? "low" : "auto";

  return { layout, showEdges: false, edgeBy: "process", bloom, tier, encoding, perfOpen: false, stressNodes };
}

type Persisted = Partial<ReturnType<typeof seeded>>;

function load(): Persisted | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Persisted) : null;
  } catch {
    return null;
  }
}

function persist(state: ViewState): void {
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        layout: state.layout,
        showEdges: state.showEdges,
        edgeBy: state.edgeBy,
        bloom: state.bloom,
        tier: state.tier,
        encoding: state.encoding,
        // perfOpen + stressNodes are session/profiling concerns — not persisted.
      }),
    );
  } catch {
    /* private mode / quota — non-fatal, settings just won't persist. */
  }
}

const initial = { ...seeded(), ...(load() ?? {}), immersive: false };

export const useViewStore = create<ViewState>((set, get) => {
  const update = <K extends keyof ViewState>(patch: Pick<ViewState, K>) => {
    set(patch);
    persist(get());
  };
  return {
    ...initial,

    setLayout: (layout) => update({ layout }),
    setShowEdges: (showEdges) => update({ showEdges }),
    setEdgeBy: (edgeBy) => update({ edgeBy }),
    setBloom: (bloom) => update({ bloom }),
    setTier: (tier) => update({ tier }),
    setEncoding: (encoding) => update({ encoding }),
    setPerfOpen: (perfOpen) => set({ perfOpen }),
    togglePerf: () => set((s) => ({ perfOpen: !s.perfOpen })),
    setStressNodes: (stressNodes) =>
      set({ stressNodes: Math.max(0, Math.min(Math.floor(stressNodes) || 0, 1000)) }),
    setImmersive: (immersive) => set({ immersive }),
    toggleImmersive: () => set((s) => ({ immersive: !s.immersive })),

    reset: () => {
      const fresh = seeded();
      set(fresh);
      persist({ ...get(), ...fresh });
    },
  };
});
