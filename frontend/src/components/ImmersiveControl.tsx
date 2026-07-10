// Cinematic mode. A pure-visual, full-screen presentation of the organism: every
// HUD panel, legend, and overlay is hidden (App.tsx does the hiding), the browser
// goes full-screen, and only the deep-sea scene remains. For screenshots, ambient
// display, or just watching the traffic breathe.
//
// This component owns the *controls*: a corner button to enter, the `C` keybind to
// toggle, `Esc` to leave, a brief auto-fading hint on entry, and — importantly —
// syncing our state back if the user exits full-screen by other means (F11, the
// browser's own Esc), so the chrome always returns when full-screen does.

import { useEffect, useRef, useState } from "react";
import { useViewStore } from "../store/useViewStore";

function enterFullscreen() {
  const el = document.documentElement;
  el.requestFullscreen?.().catch(() => {
    /* denied (iframe without allowfullscreen, user gesture rules) — the chrome
       still hides; full-screen is a bonus, not a requirement. */
  });
}

function exitFullscreen() {
  if (document.fullscreenElement) document.exitFullscreen?.().catch(() => {});
}

export function ImmersiveControl() {
  const immersive = useViewStore((s) => s.immersive);
  const setImmersive = useViewStore((s) => s.setImmersive);
  const toggleImmersive = useViewStore((s) => s.toggleImmersive);
  const [hint, setHint] = useState(false);
  const hintTimer = useRef<number | undefined>(undefined);

  // `C` toggles, `Esc` exits — the same input-guarded pattern as the help overlay.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      if (el && el.closest("input, textarea, select")) return;
      if (e.key === "c" || e.key === "C") toggleImmersive();
      else if (e.key === "Escape" && useViewStore.getState().immersive) setImmersive(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleImmersive, setImmersive]);

  // Drive full-screen + the entry hint off the state, and reconcile if full-screen
  // is dropped externally (so we never sit chrome-less in a windowed page).
  useEffect(() => {
    if (immersive) {
      enterFullscreen();
      setHint(true);
      window.clearTimeout(hintTimer.current);
      hintTimer.current = window.setTimeout(() => setHint(false), 2600);
    } else {
      exitFullscreen();
      setHint(false);
    }
    return () => window.clearTimeout(hintTimer.current);
  }, [immersive]);

  useEffect(() => {
    const onFsChange = () => {
      // User left full-screen by their own means while immersive → restore chrome.
      if (!document.fullscreenElement && useViewStore.getState().immersive) {
        setImmersive(false);
      }
    };
    document.addEventListener("fullscreenchange", onFsChange);
    return () => document.removeEventListener("fullscreenchange", onFsChange);
  }, [setImmersive]);

  if (immersive) {
    // In cinematic mode the only chrome is a whisper-quiet exit affordance that
    // fades after entry and reappears on hover, so it never intrudes on a shot.
    return (
      <>
        <button
          className="cinematic-exit"
          onClick={() => setImmersive(false)}
          title="exit cinematic mode (Esc)"
          aria-label="exit cinematic mode"
        >
          ✕
        </button>
        {hint && <div className="cinematic-hint">cinematic mode · press Esc or C to exit</div>}
      </>
    );
  }

  return (
    <button
      className="cinematic-btn"
      onClick={() => setImmersive(true)}
      title="cinematic mode — full-screen, pure visual (C)"
      aria-label="enter cinematic mode"
    >
      ⛶
    </button>
  );
}
