// Help / shortcuts overlay. The interactions (orbit, focus on double-click, the
// filter, the panels) aren't discoverable on their own, so a persistent "?" affords
// a quick reference. Toggle with the button or the `?` key; close with either, the
// ✕, or a click on the backdrop. Kept deliberately small — a cheat sheet, not a
// manual.

import { useEffect, useState } from "react";

const SHORTCUTS: { keys: string; what: string }[] = [
  { keys: "drag", what: "orbit the organism" },
  { keys: "scroll", what: "zoom in / out" },
  { keys: "click", what: "inspect a node & reveal its links" },
  { keys: "double-click", what: "focus a node + its connections" },
  { keys: "Esc", what: "exit focus" },
  { keys: "search / chip", what: "isolate matching nodes (list + scene)" },
  { keys: "Settings", what: "layout, relationship edges, bloom, GPU tier" },
  { keys: "P", what: "performance overlay" },
  { keys: "C", what: "cinematic mode — full-screen, pure visual" },
  { keys: "?", what: "this help" },
];

export function HelpOverlay() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      if (el && el.closest("input, textarea, select")) return;
      if (e.key === "?") setOpen((o) => !o);
      else if (e.key === "Escape" && open) setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <>
      <button
        className="help-btn"
        onClick={() => setOpen((o) => !o)}
        title="help &amp; shortcuts (?)"
        aria-label="help and shortcuts"
      >
        ?
      </button>
      {open && (
        <div className="help-scrim" onClick={() => setOpen(false)}>
          <div className="help" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="help">
            <div className="help__head">
              <span>NETSCOPE — controls</span>
              <button className="help__close" onClick={() => setOpen(false)} aria-label="close help">
                ✕
              </button>
            </div>
            <dl className="help__grid">
              {SHORTCUTS.map((s) => (
                <div className="help__row" key={s.keys}>
                  <dt>{s.keys}</dt>
                  <dd>{s.what}</dd>
                </div>
              ))}
            </dl>
            <div className="help__foot">
              Each node is an endpoint your machine is talking to · colour = category ·
              a warm rim marks risk (trackers, plaintext, unattributable) · an amber
              beacon sweeps unencrypted endpoints · tendrils
              reach from the host core (you). The HUD's exposure score grades the whole
              session 0–100 — the formula is published in the code and it inherits the
              classifier's measured accuracy (docs/eval.md).
            </div>
          </div>
        </div>
      )}
    </>
  );
}
