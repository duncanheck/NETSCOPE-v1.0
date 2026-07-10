// Warden client (E1 — preview only). Sends a block policy to the agent and gets
// back what it *would* block among the current flows. Nothing is enforced yet —
// the firewall generator and the privileged enforcer are later milestones (E3/E4).
// This is a safe, read-only preview, served same-origin from the agent.

/** A deny rule. Mirrors `netscope_warden::Rule` (tagged on `type`). */
export type Rule =
  | { type: "category"; value: string }
  | { type: "flag"; value: string }
  | { type: "org"; value: string }
  | { type: "cidr"; value: string }
  | { type: "threat" };

/** An allowlist matcher. Mirrors `netscope_warden::Allow`. */
export type Allow =
  | { type: "org"; value: string }
  | { type: "host"; value: string }
  | { type: "cidr"; value: string };

export interface Policy {
  allow: Allow[];
  deny: Rule[];
}

export interface PlanEntry {
  flow_id: string;
  host: string;
  ip: string;
  reason: string;
}

export interface Plan {
  blocks: PlanEntry[];
  /** Deduplicated remote IPs a firewall set would contain (the future E3 output). */
  targets: string[];
  considered: number;
}

/** Preview what `policy` would block among the agent's current flows. */
export async function previewBlocks(
  agentHttpBase: string,
  policy: Policy,
): Promise<Plan | null> {
  try {
    const res = await fetch(new URL("/warden/preview", agentHttpBase), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(policy),
    });
    if (!res.ok) return null;
    return (await res.json()) as Plan;
  } catch {
    return null;
  }
}

/** Loaded threat-feed status (E2). Mirrors the agent's `/warden/threats`. */
export interface ThreatStatus {
  /** Distinct indicators loaded across all feeds. */
  indicators: number;
  /** Loaded feed filenames. */
  sources: string[];
  /** Remote IPs among the current flows that match a known-bad indicator. */
  matches: string[];
}

/** Report which threat feeds are loaded and which current flows match them.
 *  The "known-bad lists" toggle is only meaningful when `indicators > 0`. */
export async function threatStatus(
  agentHttpBase: string,
): Promise<ThreatStatus | null> {
  try {
    const res = await fetch(new URL("/warden/threats", agentHttpBase));
    if (!res.ok) return null;
    return (await res.json()) as ThreatStatus;
  } catch {
    return null;
  }
}

/** A firewall backend (E3). */
export type Firewall = "nftables" | "netsh" | "pf";

/** A generated native ruleset. Mirrors `netscope_warden::GeneratedRuleset`. */
export interface GeneratedRuleset {
  backend: Firewall;
  filename: string;
  apply: string;
  remove: string;
  target_count: number;
  rules: string;
}

/** Generate a native firewall ruleset (E3) from `policy` for `backend`. The agent
 *  only renders it — applying is up to the user (a privileged enforcer is E4). */
export async function generateRules(
  agentHttpBase: string,
  policy: Policy,
  backend: Firewall,
): Promise<GeneratedRuleset | null> {
  try {
    const res = await fetch(new URL("/warden/generate", agentHttpBase), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policy, backend }),
    });
    if (!res.ok) return null;
    return (await res.json()) as GeneratedRuleset;
  } catch {
    return null;
  }
}

// --- Enforcement (E4/E6) ----------------------------------------------------
// Actual blocking goes through the privileged enforcer, which the agent reaches
// only when configured. These helpers distinguish three outcomes the UI must show
// distinctly: enforced, *not configured* (generate-only — the common case), and a
// real failure.

/** The enforcer's view of what's currently blocked. `available` is false when no
 *  enforcer is configured (the agent answers 503) — the UI then stays generate-only. */
export interface BlockedState {
  available: boolean;
  blocked: string[];
}

/** Outcome of an apply/unblock attempt, mapped from the enforcer's response. */
export interface EnforceResult {
  /** True only when the enforcer actually ran. */
  ok: boolean;
  /** False when no enforcer is configured (generate-only) — distinct from an error. */
  configured: boolean;
  added: string[];
  removed: string[];
  /** Addresses the enforcer's never-block floor refused (loopback/LAN/etc.). */
  rejected: string[];
  blockedTotal: number | null;
  error: string | null;
}

/** Read the enforcer's current block set, and whether enforcement is available. */
export async function fetchBlocked(agentHttpBase: string): Promise<BlockedState> {
  try {
    const res = await fetch(new URL("/warden/blocked", agentHttpBase));
    if (res.status === 503) return { available: false, blocked: [] };
    if (!res.ok) return { available: false, blocked: [] };
    const body = (await res.json()) as { status?: string; blocked?: string[] };
    return { available: true, blocked: body.blocked ?? [] };
  } catch {
    return { available: false, blocked: [] };
  }
}

function toEnforceResult(status: number, body: unknown): EnforceResult {
  const b = (body ?? {}) as Record<string, unknown>;
  if (status === 503) {
    return {
      ok: false,
      configured: false,
      added: [],
      removed: [],
      rejected: [],
      blockedTotal: null,
      error: typeof b.error === "string" ? b.error : "enforcement not configured",
    };
  }
  if (b.status === "applied" || b.status === "cleared") {
    return {
      ok: true,
      configured: true,
      added: Array.isArray(b.added) ? (b.added as string[]) : [],
      // `applied` carries a removed[] array; `cleared` carries a removed count.
      removed: Array.isArray(b.removed) ? (b.removed as string[]) : [],
      rejected: Array.isArray(b.rejected) ? (b.rejected as string[]) : [],
      blockedTotal:
        typeof b.blocked_total === "number"
          ? b.blocked_total
          : b.status === "cleared"
            ? 0
            : null,
      error: null,
    };
  }
  return {
    ok: false,
    configured: true,
    added: [],
    removed: [],
    rejected: [],
    blockedTotal: null,
    error: typeof b.error === "string" ? b.error : typeof b.message === "string" ? (b.message as string) : "enforce failed",
  };
}

/** Apply `policy` through the enforcer — block the IPs it would match among the
 *  current flows. The enforcer re-checks the never-block floor itself. */
export async function applyPolicy(agentHttpBase: string, policy: Policy): Promise<EnforceResult> {
  try {
    const res = await fetch(new URL("/warden/apply", agentHttpBase), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(policy),
    });
    const body = await res.json().catch(() => null);
    return toEnforceResult(res.status, body);
  } catch (e) {
    return {
      ok: false,
      configured: true,
      added: [],
      removed: [],
      rejected: [],
      blockedTotal: null,
      error: `could not reach the agent: ${String(e)}`,
    };
  }
}

/** Block a single endpoint by IP (a `/32` or `/128` deny) — the per-flow action. */
export function blockIp(agentHttpBase: string, ip: string): Promise<EnforceResult> {
  const suffix = ip.includes(":") ? "/128" : "/32";
  return applyPolicy(agentHttpBase, { allow: [], deny: [{ type: "cidr", value: `${ip}${suffix}` }] });
}

/** Unblock specific addresses, or — with no `ips` — remove every active block. */
export async function unblockAll(agentHttpBase: string, ips: string[] = []): Promise<EnforceResult> {
  try {
    const res = await fetch(new URL("/warden/unblock", agentHttpBase), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ips }),
    });
    const body = await res.json().catch(() => null);
    return toEnforceResult(res.status, body);
  } catch (e) {
    return {
      ok: false,
      configured: true,
      added: [],
      removed: [],
      rejected: [],
      blockedTotal: null,
      error: `could not reach the agent: ${String(e)}`,
    };
  }
}
