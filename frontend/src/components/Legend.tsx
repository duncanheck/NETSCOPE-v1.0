// A compact, always-on legend so the visualization is self-explanatory: what the
// node colours mean (the category palette, shared with the scene + HUD), the
// severity channel (warm rim = risk, G1.3), and, when relationship edges are on,
// what a link represents. Bottom-centre, unobtrusive, and pointer-transparent so
// it never gets in the way of the organism.

import { useViewStore } from "../store/useViewStore";
import { CATEGORY_HEX, SEVERITY_HEX, EXPOSED_HEX } from "../scene/palette";

const CATEGORIES: { key: string; label: string; color: string }[] = (
  ["service", "cdn", "tracker", "local", "unknown"] as const
).map((key) => ({ key, label: key, color: CATEGORY_HEX[key] }));

// Mirrors EDGE_COLOR in scene/relationships.ts (kept as hex for the DOM legend).
const EDGE_COLOR: Record<string, string> = {
  process: "#7ad7c4",
  org: "#5ec8ff",
  country: "#b79cff",
};

export function Legend() {
  const showEdges = useViewStore((s) => s.showEdges);
  const edgeBy = useViewStore((s) => s.edgeBy);

  return (
    <div className="legend" aria-hidden>
      {CATEGORIES.map((c) => (
        <span className="legend__item" key={c.key}>
          <span className="legend__dot" style={{ background: c.color }} />
          {c.label}
        </span>
      ))}
      {/* G1.3: severity is its own channel — colour says what a node is, the warm
          rim says whether to worry about it. */}
      <span className="legend__item">
        <span className="legend__dot" style={{ background: SEVERITY_HEX }} />
        warm rim = risk
      </span>
      {/* Plaintext endpoints wear an amber beacon (they keep their category hue). */}
      <span className="legend__item">
        <span className="legend__dot legend__dot--beacon" style={{ background: EXPOSED_HEX }} />
        amber beacon = unencrypted
      </span>
      {showEdges && (
        <span className="legend__item legend__item--edge">
          <span className="legend__line" style={{ background: EDGE_COLOR[edgeBy] }} />
          {edgeBy} link
        </span>
      )}
    </div>
  );
}
