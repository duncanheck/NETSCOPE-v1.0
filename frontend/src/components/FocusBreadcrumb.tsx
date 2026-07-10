// The focus breadcrumb. When a node is focused (double-click a node, or "explore"
// in the inspector) the scene dims everything outside that node's relationship and
// the camera flies in; this top-centre bar shows the drill-down path —
// ⌂ host › <process|org> › <node> — and is the way back out. Each crumb to the left
// steps the focus out; Esc or the ✕ clears it entirely.

import { useEffect } from "react";
import { useRenderStore } from "../scene/useRenderStore";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { focusRelation } from "../scene/relationships";

const KEY_LABEL: Record<string, string> = {
  process: "process",
  org: "org",
  country: "country",
  category: "category",
};

export function FocusBreadcrumb() {
  const focusId = useRenderStore((s) => s.focusId);
  const setFocus = useRenderStore((s) => s.setFocus);
  const flow = useNetscopeStore((s) => (focusId ? s.flows.get(focusId) : undefined));

  // Esc exits focus — but not while typing in a field.
  useEffect(() => {
    if (!focusId) return;
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      if (el && el.closest("input, textarea, select")) return;
      if (e.key === "Escape") setFocus(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [focusId, setFocus]);

  // The focused flow may have closed/churned out — clear focus so the camera eases
  // home rather than dangling on a vanished node.
  useEffect(() => {
    if (focusId && !flow) setFocus(null);
  }, [focusId, flow, setFocus]);

  if (!focusId || !flow) return null;

  const rel = focusRelation(flow);
  const groupLabel = rel.value ?? "unattributed";

  return (
    <div className="breadcrumb" role="navigation" aria-label="focus path">
      <button className="breadcrumb__crumb breadcrumb__home" onClick={() => setFocus(null)} title="back to the whole organism">
        ⌂ host
      </button>
      <span className="breadcrumb__sep">›</span>
      <span className="breadcrumb__crumb breadcrumb__group" title={KEY_LABEL[rel.key]}>
        <span className="breadcrumb__tag">{KEY_LABEL[rel.key]}</span>
        {groupLabel}
      </span>
      <span className="breadcrumb__sep">›</span>
      <span className="breadcrumb__crumb breadcrumb__node">{flow.name}</span>
      <button className="breadcrumb__exit" onClick={() => setFocus(null)} title="exit focus (Esc)" aria-label="exit focus">
        ✕
      </button>
    </div>
  );
}
