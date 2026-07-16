// E6 enforcement state, shared between the Warden panel and the per-flow block
// button. It owns: whether enforcement is available (an enforcer is configured),
// the current blocked set, and a client-side **audit log** of what the user blocked
// or unblocked and when. The audit log persists across reloads (localStorage) so the
// record survives a refresh; the enforcer keeps its own authoritative server-side log.
//
// Everything here is explicit and reversible: nothing blocks without a user action,
// and "unblock all" is always one click away.

import { create } from "zustand";
import {
  applyPolicy,
  blockIp,
  defaultAgentHttpBase,
  fetchBlocked,
  unblockAll,
  verifyEnforcement,
  type EnforceResult,
  type Policy,
  type VerifyState,
} from "../transport";

export interface AuditEntry {
  ts: number;
  action: "block" | "unblock" | "apply";
  detail: string;
  ok: boolean;
}

const AUDIT_KEY = "netscope.warden.audit";
const AUDIT_MAX = 50;

function loadAudit(): AuditEntry[] {
  try {
    const raw = localStorage.getItem(AUDIT_KEY);
    return raw ? (JSON.parse(raw) as AuditEntry[]) : [];
  } catch {
    return [];
  }
}

function saveAudit(entries: AuditEntry[]) {
  try {
    localStorage.setItem(AUDIT_KEY, JSON.stringify(entries.slice(0, AUDIT_MAX)));
  } catch {
    /* private mode / quota — non-fatal */
  }
}

/** The result of a live `/warden/verify` check — real-time proof the firewall is
 *  actually enforcing what the enforcer believes it applied, not just that the
 *  enforcer process responds. See `transport/warden.ts`'s `VerifyResult`. */
export interface Health {
  state: VerifyState;
  live: string[];
  expected: string[];
  checkedAt: number;
  error: string | null;
}

interface WardenState {
  /** null until first probed; false ⇒ generate-only (no enforcer). */
  available: boolean | null;
  blocked: string[];
  audit: AuditEntry[];
  busy: boolean;
  /** The last enforce attempt, for surfacing rejected/errors inline. */
  last: EnforceResult | null;
  /** null until first verified. */
  health: Health | null;

  refresh: () => Promise<void>;
  verify: () => Promise<void>;
  apply: (policy: Policy, label: string) => Promise<void>;
  block: (ip: string) => Promise<void>;
  /** Unblock one address (the per-row action), or all when omitted. */
  unblock: (ip?: string) => Promise<void>;
  clearAudit: () => void;
}

function record(get: () => WardenState, set: (p: Partial<WardenState>) => void, entry: AuditEntry) {
  const audit = [entry, ...get().audit].slice(0, AUDIT_MAX);
  saveAudit(audit);
  set({ audit });
}

export const useWardenStore = create<WardenState>((set, get) => ({
  available: null,
  blocked: [],
  audit: loadAudit(),
  busy: false,
  last: null,
  health: null,

  refresh: async () => {
    const state = await fetchBlocked(defaultAgentHttpBase());
    set({ available: state.available, blocked: state.blocked });
  },

  verify: async () => {
    const res = await verifyEnforcement(defaultAgentHttpBase());
    const prev = get().health;
    // Drift is the one transition worth an audit entry of its own — everything
    // else here is a read, not an action, so it doesn't belong in the log.
    if (res.state === "drift" && prev?.state !== "drift") {
      record(get, set, {
        ts: Date.now(),
        action: "apply",
        detail: `⚠ drift detected — firewall shows ${res.live.length}, expected ${res.expected.length}`,
        ok: false,
      });
    }
    set({
      health: { state: res.state, live: res.live, expected: res.expected, checkedAt: Date.now(), error: res.error },
      available: res.state === "not_configured" ? false : res.state === "unreachable" ? get().available : true,
    });
  },

  apply: async (policy, label) => {
    set({ busy: true });
    const res = await applyPolicy(defaultAgentHttpBase(), policy);
    set({ busy: false, last: res, available: res.configured ? true : get().available });
    if (res.ok) {
      record(get, set, {
        ts: Date.now(),
        action: "apply",
        detail: `${label}: blocked ${res.added.length}${res.rejected.length ? `, ${res.rejected.length} protected refused` : ""}`,
        ok: true,
      });
      await get().refresh();
    } else if (res.configured) {
      record(get, set, { ts: Date.now(), action: "apply", detail: res.error ?? "failed", ok: false });
    }
  },

  block: async (ip) => {
    set({ busy: true });
    const res = await blockIp(defaultAgentHttpBase(), ip);
    set({ busy: false, last: res, available: res.configured ? true : get().available });
    if (res.ok) {
      const ok = res.added.length > 0;
      record(get, set, {
        ts: Date.now(),
        action: "block",
        detail: ok ? `blocked ${ip}` : `${ip} refused (protected / already blocked)`,
        ok,
      });
      await get().refresh();
    } else if (res.configured) {
      record(get, set, { ts: Date.now(), action: "block", detail: res.error ?? "failed", ok: false });
    }
  },

  unblock: async (ip?: string) => {
    set({ busy: true });
    const res = await unblockAll(defaultAgentHttpBase(), ip ? [ip] : []);
    set({ busy: false, last: res });
    if (res.ok) {
      record(get, set, {
        ts: Date.now(),
        action: "unblock",
        detail: ip ? `unblocked ${ip}` : "unblocked all",
        ok: true,
      });
      await get().refresh();
    }
  },

  clearAudit: () => {
    saveAudit([]);
    set({ audit: [] });
  },
}));
