// Hover tooltip. Hovering a node (in the 3D scene or the connection list — both feed
// the shared hoveredId) shows a compact identity card at the cursor: name, category,
// owning process, and security posture. It lets you sweep the organism and read what
// each cell is without clicking through every one — the difference between a pretty
// demo and something you can actually explore.
//
// Position is updated imperatively on mousemove (no React re-render per move); the
// card only re-renders when the hovered flow changes.

import { useEffect, useLayoutEffect, useRef } from "react";
import { useRenderStore } from "../scene/useRenderStore";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { CATEGORY_HEX } from "../scene/palette";

export function HoverTooltip() {
  const hoveredId = useRenderStore((s) => s.hoveredId);
  const flow = useNetscopeStore((s) => (hoveredId ? s.flows.get(hoveredId) : undefined));
  const ref = useRef<HTMLDivElement>(null);
  const pos = useRef({ x: 0, y: 0 });
  // Only show the card when the cursor is over the 3D canvas. Hovering a connection
  // *list* row also sets hoveredId (to highlight the node), but the row already shows
  // the details — a tooltip popping over the list would just cover it.
  const overCanvas = useRef(false);

  const reposition = (el: HTMLDivElement) => {
    el.style.visibility = overCanvas.current ? "visible" : "hidden";
    const x = Math.min(pos.current.x + 16, window.innerWidth - el.offsetWidth - 8);
    const y = Math.min(pos.current.y + 16, window.innerHeight - el.offsetHeight - 8);
    el.style.transform = `translate(${x}px, ${y}px)`;
  };

  // Track the cursor + whether it's over the canvas; reposition imperatively.
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      pos.current = { x: e.clientX, y: e.clientY };
      overCanvas.current = (e.target as HTMLElement | null)?.tagName === "CANVAS";
      if (ref.current) reposition(ref.current);
    };
    window.addEventListener("mousemove", onMove);
    return () => window.removeEventListener("mousemove", onMove);
  }, []);

  // Snap to the last cursor position / canvas state the moment the card appears.
  useLayoutEffect(() => {
    if (ref.current) reposition(ref.current);
  }, [flow?.id]);

  if (!flow) return null;

  const place = flow.location
    ? [flow.location.city, flow.location.country].filter(Boolean).join(", ")
    : flow.category === "local"
      ? "local network"
      : "";

  return (
    <div className="tooltip" ref={ref} aria-hidden>
      <div className="tooltip__head">
        <span className="flow__dot" style={{ background: CATEGORY_HEX[flow.category] }} />
        <span className="tooltip__name">{flow.name}</span>
      </div>
      <div className="tooltip__meta">
        {flow.category} · {flow.protocol.toUpperCase()}:{flow.port} ·{" "}
        {flow.encrypted ? (
          <span className="flow__lock">🔒 encrypted</span>
        ) : (
          <span className="flow__plain">plaintext</span>
        )}
      </div>
      <div className="tooltip__sub">
        {flow.process ? flow.process.name : "protected"}
        {flow.asn ? ` · ${flow.asn.org}` : ""}
        {place ? ` · ${place}` : ""}
      </div>
    </div>
  );
}
