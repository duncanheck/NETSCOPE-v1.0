// Setup client (GROWTH G3.2) — the zero-knowledge enablement path. The System
// panel uses these to turn on geo/ASN enrichment (paste a free MaxMind key) and
// threat feeds (one click) from inside the UI: the agent downloads with the
// user's own key, hot-reloads, and answers with the new state — no terminal, no
// restart. All endpoints are loopback-only on the agent side.

/** Mirrors the agent's `GET /setup/status`. */
export interface SetupStatus {
  geo_enabled: boolean;
  geoip_dir: string;
  threat_dir: string;
  threat_indicators: number;
  /** A MaxMind key is already stored (env or config) — refresh won't ask again. */
  has_maxmind_key: boolean;
  config_path: string;
  /**
   * Packet capture state (G5): "active (dev)", "off — …", "unavailable: …",
   * or "not built — …". Decided at agent startup; shown verbatim.
   */
  packet_capture: string;
}

export async function setupStatus(agentHttpBase: string): Promise<SetupStatus | null> {
  try {
    const res = await fetch(new URL("/setup/status", agentHttpBase));
    if (!res.ok) return null;
    return (await res.json()) as SetupStatus;
  } catch {
    return null;
  }
}

export interface GeoipSetupResult {
  ok: boolean;
  geo_enabled: boolean;
  error?: string;
}

/**
 * Enable geo/ASN: the agent downloads both GeoLite2 editions with `licenseKey`
 * (or its stored key when omitted) and hot-reloads the enricher.
 */
export async function setupGeoip(
  agentHttpBase: string,
  licenseKey?: string,
): Promise<GeoipSetupResult> {
  try {
    const res = await fetch(new URL("/setup/geoip", agentHttpBase), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(licenseKey ? { license_key: licenseKey } : {}),
    });
    const body = (await res.json()) as GeoipSetupResult;
    return body;
  } catch {
    return { ok: false, geo_enabled: false, error: "agent unreachable" };
  }
}

export interface ThreatsSetupResult {
  ok: boolean;
  indicators: number;
  sources: string[];
  fetched: string[];
  skipped: string[];
  error?: string;
}

/** Enable threat feeds: the agent fetches the free feeds and hot-swaps the DB. */
export async function setupThreats(agentHttpBase: string): Promise<ThreatsSetupResult> {
  try {
    const res = await fetch(new URL("/setup/threats", agentHttpBase), { method: "POST" });
    return (await res.json()) as ThreatsSetupResult;
  } catch {
    return {
      ok: false,
      indicators: 0,
      sources: [],
      fetched: [],
      skipped: [],
      error: "agent unreachable",
    };
  }
}
