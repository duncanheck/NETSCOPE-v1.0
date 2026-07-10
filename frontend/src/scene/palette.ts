// The bioluminescent palette, keyed by category (ROADMAP B3) — the single source
// of truth for node/tendril/UI colour. Previously this map was declared
// independently in five files (Legend, Hud, HoverTooltip, OrganismNodes,
// TendrilField) and had already drifted (`unknown` was #9fb0c0 in one of them);
// GROWTH G1.1 collapses them here so the scene and the DOM UI can never disagree.
//
// Category answers *what is this* (service, cdn, tracker…). The severity channel
// (G1.3) answers *should I worry* — a separate warm warning colour so risk never
// has to be inferred from category hue alone.

import * as THREE from "three";
import type { Category } from "../protocol";

/** Hex strings for the DOM UI (legend, HUD list, tooltips, detail panel).
 *  Deliberately no grey: every category owns a real bioluminescent hue, so a node
 *  never reads as a dead grey sphere. `local` is a calm steel-blue, `unknown` a
 *  soft violet ("unidentified", not "uninteresting"). */
export const CATEGORY_HEX: Record<Category, string> = {
  service: "#3fd6c4",
  cdn: "#5ec8ff",
  tracker: "#ffb347",
  local: "#6f9bd6",
  unknown: "#a08ff2",
};

/** THREE.Color instances for the scene's instanced attributes. */
export const CATEGORY_COLOR: Record<Category, THREE.Color> = Object.fromEntries(
  (Object.entries(CATEGORY_HEX) as [Category, string][]).map(([k, v]) => [k, new THREE.Color(v)]),
) as Record<Category, THREE.Color>;

/** The severity/warning hue (G1.3): warm rim on flagged nodes, DOM accents. */
export const SEVERITY_HEX = "#ff6a4d";

/** The exposed/plaintext hue: the amber beacon an unencrypted endpoint wears in
 *  the scene (it replaced the old washed-out grey), mirrored in the DOM legend. */
export const EXPOSED_HEX = "#ffb347";
