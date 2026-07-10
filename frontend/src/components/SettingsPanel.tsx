// The Settings panel — every view knob that used to be a terminal flag, gathered
// into one floating window and applied live. Layout mode (was `?layout=`),
// relationship edges, bloom (`?bloom=`), GPU tier (`?renderTier=`), wire encoding
// (`?encoding=`), the perf overlay (the `P` key) and the synthetic stress count
// (`?nodes=N`) all live in the view store; this just binds controls to it.
//
// A couple of knobs need the transport to reconnect to take effect (encoding is
// negotiated on the WebSocket handshake; the stress count is read when the mock feed
// is built) — those reattach the connection on change so the user never has to.

import { useState } from "react";
import { useViewStore, type LayoutMode } from "../store/useViewStore";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { defaultTransportKind } from "../transport";
import { useFloatingPanel } from "./useFloatingPanel";
import type { RelationKey } from "../scene/relationships";

const LAYOUTS: { value: LayoutMode; label: string }[] = [
  { value: "category", label: "clustered · by category" },
  { value: "force", label: "relaxed · force sim" },
  { value: "process", label: "group · by process" },
  { value: "org", label: "group · by org (ASN)" },
  { value: "country", label: "group · by country" },
];

const RELATIONS: { value: RelationKey; label: string }[] = [
  { value: "process", label: "process" },
  { value: "org", label: "org (ASN)" },
  { value: "country", label: "country" },
];

export function SettingsPanel() {
  const v = useViewStore();
  const attach = useNetscopeStore((s) => s.attach);
  const transportKind = useNetscopeStore((s) => s.transportKind);
  const paired = useNetscopeStore((s) => s.paired);
  const [stressDraft, setStressDraft] = useState(String(v.stressNodes || ""));

  const { ref, panelProps, handleProps, collapsed, toggleCollapsed, reset } = useFloatingPanel({
    storageKey: "netscope.settings",
    // Top-right, clear of the tall main HUD on the left.
    defaultPos: { x: Math.max(16, window.innerWidth - 336), y: 16 },
  });

  // Encoding is negotiated on connect: reconnect to apply (skip for a paired remote,
  // which would need the pairing token we deliberately don't persist).
  const onEncoding = (encoding: "json" | "msgpack") => {
    v.setEncoding(encoding);
    if (transportKind === "websocket" && !paired) attach("websocket");
  };

  // The stress count is read when the mock feed is constructed, so (re)attach to
  // apply it. defaultTransportKind() reads the freshly-set count: >0 forces the mock
  // fixture, 0 returns to the configured feed (real agent in the product build).
  const applyStress = () => {
    const n = Number(stressDraft);
    v.setStressNodes(Number.isFinite(n) ? n : 0);
    attach(defaultTransportKind());
  };

  return (
    <div className={`hud settings${collapsed ? " hud--collapsed" : ""}`} ref={ref} {...panelProps}>
      <div className="hud__bar" {...handleProps}>
        <div>
          <div className="hud__title hud__title--sm">SETTINGS</div>
          {!collapsed && <div className="hud__sub">view · layout · render</div>}
        </div>
        <div className="hud__chrome">
          <button className="hud__chrome-btn" onClick={reset} title="reset panel" aria-label="reset panel">
            ⟲
          </button>
          <button
            className="hud__chrome-btn"
            onClick={toggleCollapsed}
            title={collapsed ? "expand" : "collapse"}
            aria-label={collapsed ? "expand panel" : "collapse panel"}
          >
            {collapsed ? "▢" : "—"}
          </button>
        </div>
      </div>

      {collapsed ? null : (
        <div className="hud__body">
          <div className="settings__group">layout</div>

          <label className="settings__row">
            <span>arrangement</span>
            <select
              className="settings__select"
              value={v.layout}
              onChange={(e) => v.setLayout(e.target.value as LayoutMode)}
            >
              {LAYOUTS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <div className="settings__hint">
            Group modes cluster nodes by a shared dimension and pull the clusters
            apart, so position means something — not one blob per category.
          </div>

          <label className="settings__row settings__row--check">
            <input
              type="checkbox"
              checked={v.showEdges}
              onChange={(e) => v.setShowEdges(e.target.checked)}
            />
            <span>relationship edges</span>
          </label>
          <label className="settings__row">
            <span>link nodes by</span>
            <select
              className="settings__select"
              value={v.edgeBy}
              disabled={!v.showEdges}
              onChange={(e) => v.setEdgeBy(e.target.value as RelationKey)}
            >
              {RELATIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>

          <div className="settings__group">render</div>

          <label className="settings__row">
            <span>bloom</span>
            <select
              className="settings__select"
              value={v.bloom}
              onChange={(e) => v.setBloom(e.target.value as "auto" | "on" | "off")}
            >
              <option value="auto">auto (by GPU)</option>
              <option value="on">on</option>
              <option value="off">off</option>
            </select>
          </label>

          <label className="settings__row">
            <span>GPU tier</span>
            <select
              className="settings__select"
              value={v.tier}
              onChange={(e) => v.setTier(e.target.value as "auto" | "high" | "low")}
            >
              <option value="auto">auto (measured)</option>
              <option value="high">high</option>
              <option value="low">low</option>
            </select>
          </label>

          <label className="settings__row settings__row--check">
            <input
              type="checkbox"
              checked={v.perfOpen}
              onChange={(e) => v.setPerfOpen(e.target.checked)}
            />
            <span>performance overlay (P)</span>
          </label>

          <div className="settings__group">data</div>

          <label className="settings__row">
            <span>wire encoding</span>
            <select
              className="settings__select"
              value={v.encoding}
              onChange={(e) => onEncoding(e.target.value as "json" | "msgpack")}
            >
              <option value="json">JSON (readable)</option>
              <option value="msgpack">MessagePack (smaller)</option>
            </select>
          </label>
          {transportKind === "websocket" && paired && (
            <div className="settings__hint">Re-pair the device to change encoding.</div>
          )}

          <label className="settings__row">
            <span>stress nodes</span>
            <span className="settings__stress">
              <input
                className="settings__num"
                type="number"
                min={0}
                max={1000}
                inputMode="numeric"
                placeholder="0"
                value={stressDraft}
                onChange={(e) => setStressDraft(e.target.value)}
              />
              <button className="hud__btn settings__apply" onClick={applyStress}>
                apply
              </button>
            </span>
          </label>
          <div className="settings__hint">
            Synthetic flows for profiling (uses the mock feed). 0 = real / seed feed.
          </div>

          <button className="hud__btn" onClick={() => v.reset()}>
            reset settings to defaults
          </button>
        </div>
      )}
    </div>
  );
}
