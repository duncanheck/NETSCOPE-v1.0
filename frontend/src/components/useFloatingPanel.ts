// A small hook that turns any overlay into a user-customizable floating panel:
// drag it anywhere by a handle, resize it (CSS `resize`), collapse it to its
// header, and have all of that — position, size, collapsed — remembered across
// reloads in localStorage. Position is clamped to the viewport on load and on
// window resize so a panel can never get stranded off-screen.
//
// It is deliberately transport-agnostic and store-free: it owns only window
// geometry, so the HUD and the perf overlay (and anything later) can share it.

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

export interface PanelGeometry {
  x: number;
  y: number;
  /** Persisted user resize, in px; undefined means "let CSS decide". */
  w?: number;
  h?: number;
  collapsed: boolean;
}

interface Options {
  /** localStorage key; distinct per panel. */
  storageKey: string;
  /** Initial corner if nothing is stored yet. */
  defaultPos: { x: number; y: number };
}

const MARGIN = 8; // keep at least this many px on-screen when clamping.

function load(key: string): Partial<PanelGeometry> | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as Partial<PanelGeometry>) : null;
  } catch {
    return null;
  }
}

function save(key: string, geo: PanelGeometry) {
  try {
    localStorage.setItem(key, JSON.stringify(geo));
  } catch {
    /* private mode / quota — non-fatal, panel just won't persist. */
  }
}

/** Clamp a top-left position so the panel stays mostly within the viewport. */
function clamp(x: number, y: number, el: HTMLElement | null) {
  const w = el?.offsetWidth ?? 280;
  const h = el?.offsetHeight ?? 80;
  const maxX = Math.max(MARGIN, window.innerWidth - w - MARGIN);
  const maxY = Math.max(MARGIN, window.innerHeight - h - MARGIN);
  return {
    x: Math.min(Math.max(x, MARGIN), maxX),
    y: Math.min(Math.max(y, MARGIN), maxY),
  };
}

export function useFloatingPanel({ storageKey, defaultPos }: Options) {
  const ref = useRef<HTMLDivElement | null>(null);
  const stored = useRef<Partial<PanelGeometry> | null>(load(storageKey));
  const [pos, setPos] = useState({
    x: stored.current?.x ?? defaultPos.x,
    y: stored.current?.y ?? defaultPos.y,
  });
  const [collapsed, setCollapsed] = useState(stored.current?.collapsed ?? false);
  const drag = useRef<{ dx: number; dy: number } | null>(null);

  // Restore a persisted user resize before paint, then clamp into view.
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (stored.current?.w) el.style.width = `${stored.current.w}px`;
    if (stored.current?.h && !collapsed) el.style.height = `${stored.current.h}px`;
    setPos((p) => clamp(p.x, p.y, el));
    // Run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const persist = useCallback(
    (next: Partial<PanelGeometry>) => {
      const el = ref.current;
      save(storageKey, {
        x: next.x ?? pos.x,
        y: next.y ?? pos.y,
        w: el && el.style.width ? el.offsetWidth : stored.current?.w,
        h: el && el.style.height ? el.offsetHeight : stored.current?.h,
        collapsed: next.collapsed ?? collapsed,
      });
    },
    [storageKey, pos.x, pos.y, collapsed],
  );

  // Persist user resizes (CSS `resize`) without re-rendering on every pixel.
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    let raf = 0;
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => persist({}));
    });
    ro.observe(el);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [persist]);

  // Re-clamp when the window shrinks so the panel never hides off-edge.
  useEffect(() => {
    const onResize = () => setPos((p) => clamp(p.x, p.y, ref.current));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const onPointerMove = useCallback((e: PointerEvent) => {
    if (!drag.current) return;
    const next = clamp(e.clientX - drag.current.dx, e.clientY - drag.current.dy, ref.current);
    setPos(next);
  }, []);

  const onPointerUp = useCallback(() => {
    drag.current = null;
    window.removeEventListener("pointermove", onPointerMove);
    window.removeEventListener("pointerup", onPointerUp);
    persist({});
  }, [onPointerMove, persist]);

  /** Spread onto the drag handle (e.g. the title bar). */
  const handleProps = {
    onPointerDown: (e: React.PointerEvent) => {
      // Ignore drags that start on an interactive control in the handle.
      if ((e.target as HTMLElement).closest("button, input, select, a, textarea")) return;
      const el = ref.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      drag.current = { dx: e.clientX - rect.left, dy: e.clientY - rect.top };
      window.addEventListener("pointermove", onPointerMove);
      window.addEventListener("pointerup", onPointerUp);
    },
    style: { cursor: "grab" as const, touchAction: "none" as const },
  };

  const toggleCollapsed = useCallback(() => {
    setCollapsed((c) => {
      const next = !c;
      const el = ref.current;
      // Collapsing frees the manual height; expanding restores it.
      if (el) {
        if (next) el.style.height = "";
        else if (stored.current?.h) el.style.height = `${stored.current.h}px`;
      }
      persist({ collapsed: next });
      return next;
    });
  }, [persist]);

  /** Forget the saved geometry and snap back to the default corner. */
  const reset = useCallback(() => {
    try {
      localStorage.removeItem(storageKey);
    } catch {
      /* ignore */
    }
    stored.current = null;
    const el = ref.current;
    if (el) {
      el.style.width = "";
      el.style.height = "";
    }
    setCollapsed(false);
    setPos(clamp(defaultPos.x, defaultPos.y, el));
  }, [storageKey, defaultPos.x, defaultPos.y]);

  return {
    ref,
    /** Spread onto the panel root. */
    panelProps: { style: { left: pos.x, top: pos.y } as React.CSSProperties },
    handleProps,
    collapsed,
    toggleCollapsed,
    reset,
  };
}
