// The System panel — the agent's capability board, and (G3.2) the place to turn
// capabilities ON. It answers at a glance: where is the agent, is geo/ASN
// enrichment on, are threat feeds loaded, is the firewall enforcer wired up,
// which AI narrators are available, and what build is running. Geo and threat
// feeds are enableable right here — paste a free MaxMind key / one click — with
// the agent downloading and hot-reloading, no terminal, no restart. Capabilities
// that still need out-of-band setup (enforcer, cloud narrator) keep their
// one-line hint.

import { useCallback, useEffect, useState } from "react";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { useWardenStore } from "../store/useWardenStore";
import { useRenderStore } from "../scene/useRenderStore";
import { useFloatingPanel } from "./useFloatingPanel";
import {
  defaultAgentHttpBase,
  fetchProviders,
  fetchUpdateStatus,
  setupGeoip,
  setupStatus,
  setupThreats,
  threatStatus,
  type ProviderStatus,
  type SetupStatus,
  type ThreatStatus,
  type UpdateStatus,
} from "../transport";

type StatusKind = "ok" | "warn" | "off";

function Row({
  label,
  kind,
  value,
  hint,
}: {
  label: string;
  kind: StatusKind;
  value: string;
  hint?: string;
}) {
  return (
    <div className="sys__row">
      <div className="sys__line">
        <span className={`sys__dot sys__dot--${kind}`} />
        <span className="sys__label">{label}</span>
        <span className="sys__value">{value}</span>
      </div>
      {hint && <div className="sys__hint">{hint}</div>}
    </div>
  );
}

export function SystemPanel() {
  const transportKind = useNetscopeStore((s) => s.transportKind);
  const agent = useNetscopeStore((s) => s.agent);
  const connectionState = useNetscopeStore((s) => s.connectionState);
  const tier = useRenderStore((s) => s.tier);
  // True when geo/ASN enrichment is producing data (a proxy for the GeoLite2 dbs +
  // resolver being present — there's no dedicated endpoint, but enriched flows prove it).
  const geoActive = useNetscopeStore((s) => {
    for (const f of s.flows.values()) if (f.asn || f.location) return true;
    return false;
  });
  const enforcer = useWardenStore((s) => s.available);
  const refreshWarden = useWardenStore((s) => s.refresh);

  const [providers, setProviders] = useState<ProviderStatus[] | null>(null);
  const [threats, setThreats] = useState<ThreatStatus | null>(null);
  const [update, setUpdate] = useState<UpdateStatus | null>(null);
  const [setup, setSetup] = useState<SetupStatus | null>(null);

  const live = transportKind === "websocket";

  const { ref, panelProps, handleProps, collapsed, toggleCollapsed, reset } = useFloatingPanel({
    storageKey: "netscope.system",
    // Top-right, stacked clear under the (tall) Settings panel and the main HUD.
    defaultPos: { x: Math.max(16, window.innerWidth - 336), y: 488 },
  });

  // Re-read setup + threat state after an in-app enablement succeeds.
  const refreshSetup = useCallback(() => {
    const base = defaultAgentHttpBase();
    void setupStatus(base).then(setSetup);
    void threatStatus(base).then(setThreats);
  }, []);

  useEffect(() => {
    if (!live) return;
    const base = defaultAgentHttpBase();
    let alive = true;
    void fetchProviders(base).then((p) => alive && setProviders(p));
    void threatStatus(base).then((t) => alive && setThreats(t));
    void fetchUpdateStatus(base).then((u) => alive && setUpdate(u));
    void setupStatus(base).then((s) => alive && setSetup(s));
    void refreshWarden();
    return () => {
      alive = false;
    };
  }, [live, refreshWarden]);

  const aiReady = providers?.filter((p) => p.available) ?? [];

  return (
    <div className={`hud system${collapsed ? " hud--collapsed" : ""}`} ref={ref} {...panelProps}>
      <div className="hud__bar" {...handleProps}>
        <div>
          <div className="hud__title hud__title--sm">SYSTEM</div>
          {!collapsed && <div className="hud__sub">agent capabilities &amp; data sources</div>}
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
          {!live ? (
            <div className="sys__notice">
              Mock feed — no agent attached. Switch to the websocket transport to read
              live capabilities.
            </div>
          ) : (
            <>
              <Row
                label="agent"
                kind={connectionState === "open" ? "ok" : "warn"}
                value={
                  agent ? `${agent.name} v${agent.version} · ${agent.platform}` : connectionState
                }
              />
              <Row label="origin" kind="ok" value={defaultAgentHttpBase()} />
              <Row label="gpu tier" kind="ok" value={tier ? tier.label.split(" · ")[0] : "probing…"} />

              <Row
                label="geo / ASN"
                kind={setup?.geo_enabled || geoActive ? "ok" : "off"}
                value={setup?.geo_enabled || geoActive ? "enriching" : "not loaded"}
              />
              {setup && !setup.geo_enabled && !geoActive && (
                <GeoSetup hasKey={setup.has_maxmind_key} onDone={refreshSetup} />
              )}

              <Row
                label="threat feeds"
                kind={threats && threats.indicators > 0 ? "ok" : "off"}
                value={
                  threats && threats.indicators > 0
                    ? `${threats.indicators.toLocaleString()} · ${threats.sources.length} feed${threats.sources.length === 1 ? "" : "s"}`
                    : "none"
                }
              />
              {threats && threats.indicators === 0 && <ThreatSetup onDone={refreshSetup} />}

              {/* G5: packet capture — deep-capture state, decided at agent
                  startup. "active" = sub-250ms flows + byte-true activity. */}
              {setup && (
                <Row
                  label="packet capture"
                  kind={
                    setup.packet_capture.startsWith("active")
                      ? "ok"
                      : setup.packet_capture.startsWith("off")
                        ? "off"
                        : "warn"
                  }
                  value={setup.packet_capture}
                  hint={
                    setup.packet_capture.startsWith("active")
                      ? undefined
                      : "Catches connections shorter than a poll tick and shows real byte rates. Needs a pcap-enabled build, capture privilege, and NETSCOPE_PCAP=1."
                  }
                />
              )}

              <Row
                label="enforcement"
                kind={enforcer ? "ok" : "off"}
                value={enforcer ? "enforcer ready" : "generate-only"}
                hint={
                  enforcer
                    ? undefined
                    : "Windows: run packaging/install-enforcer.ps1 as admin (auto-detected). Linux: run netscope-enforcer and set NETSCOPE_ENFORCER_SOCKET."
                }
              />

              <Row
                label="AI narrator"
                kind={aiReady.length > 0 ? "ok" : "warn"}
                value={
                  aiReady.length > 0
                    ? aiReady.map((p) => p.label).join(", ")
                    : providers
                      ? "rules only"
                      : "…"
                }
                hint={
                  providers && !providers.find((p) => p.id === "anthropic")?.available
                    ? "Set ANTHROPIC_API_KEY for Claude, or pull an Ollama model for a local one."
                    : undefined
                }
              />

              <Row
                label="build"
                kind={update?.dev ? "warn" : "ok"}
                value={
                  update
                    ? update.dev
                      ? "dev (unstamped)"
                      : `#${update.current_build}${update.current_sha ? ` · ${update.current_sha.slice(0, 7)}` : ""}`
                    : "—"
                }
                hint={
                  update?.available ? "An update is available — see the updater in the main HUD." : undefined
                }
              />
            </>
          )}
        </div>
      )}
    </div>
  );
}

// G3.2 — enable geo/ASN from inside the app. Paste a free MaxMind key (or one
// click if a key is already stored): the agent downloads both GeoLite2 editions
// with it and hot-reloads the enricher. The key goes only to MaxMind; the
// databases stay on this machine (their license forbids redistribution, which is
// why NETSCOPE downloads rather than bundles — PITFALLS A4).
function GeoSetup({ hasKey, onDone }: { hasKey: boolean; onDone: () => void }) {
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy || (!hasKey && key.trim() === "")) return;
    setBusy(true);
    setError(null);
    const res = await setupGeoip(defaultAgentHttpBase(), key.trim() || undefined);
    setBusy(false);
    if (res.ok) onDone();
    else setError(res.error ?? "enable failed");
  };

  return (
    <form className="setup" onSubmit={submit}>
      {!hasKey && (
        <input
          className="setup__input"
          type="text"
          placeholder="free MaxMind license key"
          aria-label="MaxMind license key"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          disabled={busy}
        />
      )}
      <button
        className="hud__btn setup__btn"
        type="submit"
        disabled={busy || (!hasKey && key.trim() === "")}
      >
        {busy ? "downloading…" : hasKey ? "enable with saved key" : "enable"}
      </button>
      <div className="sys__hint">
        Shows city + network owner for each connection. Free key:
        maxmind.com/en/geolite2/signup — the key goes only to MaxMind, the
        databases stay on this machine.
      </div>
      {error && <div className="setup__err">⚠ {error}</div>}
    </form>
  );
}

// G3.2 — enable threat feeds with one click: the agent fetches the free public
// blocklists (StevenBlack, abuse.ch, FireHOL) and hot-swaps them in, lighting up
// the Warden's "known-bad lists" without a restart.
function ThreatSetup({ onDone }: { onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    const res = await setupThreats(defaultAgentHttpBase());
    setBusy(false);
    if (res.ok) onDone();
    else setError(res.error ?? "download failed");
  };

  return (
    <div className="setup">
      <button className="hud__btn setup__btn" onClick={run} disabled={busy}>
        {busy ? "downloading…" : "download free threat feeds"}
      </button>
      <div className="sys__hint">
        Flags connections to known-bad hosts (ads/malware/botnet lists — all free,
        fetched fresh). Enables the Warden's "known-bad lists" rule.
      </div>
      {error && <div className="setup__err">⚠ {error}</div>}
    </div>
  );
}
