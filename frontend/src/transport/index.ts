// Transport selection. The app asks for a Connection and gets one without
// knowing which; the choice is config (env var or runtime toggle), never woven
// into call sites.

import type { Connection } from "./Connection";
import { MockConnection } from "./MockConnection";
import { WebSocketConnection } from "./WebSocketConnection";
import { useViewStore } from "../store/useViewStore";

export type { Connection, TransportState, Unsubscribe } from "./Connection";
export { MockConnection } from "./MockConnection";
export { WebSocketConnection } from "./WebSocketConnection";
export { redeemPairingCode, PairingError } from "./auth";
export { wireEncoding, wireSubprotocols, decodeFrame } from "./wire";
export type { WireEncoding } from "./wire";
export { fetchUpdateStatus, checkForUpdate, applyUpdate } from "./update";
export type { UpdateStatus, ApplyResult } from "./update";
export { fetchProviders, explainSession, explainFlow } from "./narrator";
export type { ProviderId, ProviderStatus, Explanation, ExplainResult } from "./narrator";
export {
  previewBlocks,
  generateRules,
  threatStatus,
  fetchBlocked,
  applyPolicy,
  blockIp,
  unblockAll,
  verifyEnforcement,
} from "./warden";
export type {
  Policy,
  Rule,
  Allow,
  Plan,
  PlanEntry,
  Firewall,
  GeneratedRuleset,
  ThreatStatus,
  BlockedState,
  EnforceResult,
  VerifyState,
  VerifyResult,
} from "./warden";
export { setupStatus, setupGeoip, setupThreats } from "./setup";
export type { SetupStatus, GeoipSetupResult, ThreatsSetupResult } from "./setup";

export type TransportKind = "mock" | "websocket";

/** The transport the app boots with, from VITE_TRANSPORT (default: mock). The
 *  bundled product build is compiled with VITE_TRANSPORT=websocket so it talks to
 *  the agent that served it; the dev build defaults to the mock feed. */
export function defaultTransportKind(): TransportKind {
  // Stress mode (synthetic nodes) always uses the mock fixture, even in the bundled
  // build — there's nothing real to capture.
  if (useViewStore.getState().stressNodes > 0) return "mock";
  return import.meta.env.VITE_TRANSPORT === "websocket" ? "websocket" : "mock";
}

/** The agent WebSocket URL. An explicit VITE_AGENT_URL wins; otherwise it is
 *  derived from where the page is served — same host:port when the agent serves
 *  the bundled UI, or :8787 when running the Vite dev server on :5173. */
function defaultAgentUrl(): string {
  const explicit = import.meta.env.VITE_AGENT_URL;
  if (explicit) return explicit;
  if (typeof window !== "undefined" && window.location) {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const host =
      window.location.port === "5173"
        ? `${window.location.hostname}:8787` // Vite dev → agent's port
        : window.location.host; // served by the agent → same origin
    return `${proto}://${host}/ws`;
  }
  return "ws://127.0.0.1:8787/ws";
}

/** The agent's HTTP origin (for the C2 `/pair` control plane) — the `ws(s)://…/ws`
 *  feed URL mapped back to `http(s)://…`. */
export function defaultAgentHttpBase(): string {
  const ws = defaultAgentUrl();
  return ws.replace(/^ws(s?):\/\//, "http$1://").replace(/\/ws$/, "");
}

/** Build the boot transport. `token` is the C2 pairing token for the remote path;
 *  null (the default, and the loopback case) presents no credential. */
export function createConnection(
  kind: TransportKind,
  token: string | null = null,
): Connection {
  if (kind === "websocket") {
    return new WebSocketConnection(defaultAgentUrl(), token);
  }
  return new MockConnection();
}
