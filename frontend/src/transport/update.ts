// Self-update client (the Windows product). The bundled UI is served by the agent
// same-origin, so it reads the agent's update status and, on the user's click,
// asks it to apply. The agent does the work (download + integrity check + in-place
// swap); the UI just surfaces the banner and the result. Notify-then-apply: no
// surprise swaps.

/** Mirrors the agent's `update::UpdateStatus`. */
export interface UpdateStatus {
  current_build: number;
  current_sha: string;
  /** True for an unstamped local/dev build — the UI hides the updater. */
  dev: boolean;
  checked: boolean;
  available: boolean;
  latest_build: number | null;
  latest_sha: string | null;
  latest_built_at: string | null;
  notes: string | null;
  error: string | null;
}

export interface ApplyResult {
  ok: boolean;
  message: string;
}

/** Read the agent's update status, or null if it can't be reached/parsed. */
export async function fetchUpdateStatus(agentHttpBase: string): Promise<UpdateStatus | null> {
  try {
    const res = await fetch(new URL("/update/status", agentHttpBase));
    if (!res.ok) return null;
    return (await res.json()) as UpdateStatus;
  } catch {
    return null;
  }
}

/** Trigger an on-demand manifest check ("check now") and return the fresh status. */
export async function checkForUpdate(agentHttpBase: string): Promise<UpdateStatus | null> {
  try {
    const res = await fetch(new URL("/update/check", agentHttpBase), { method: "POST" });
    if (!res.ok) return null;
    return (await res.json()) as UpdateStatus;
  } catch {
    return null;
  }
}

/** Ask the agent to download + verify + self-replace. The user restarts after. */
export async function applyUpdate(agentHttpBase: string): Promise<ApplyResult> {
  try {
    const res = await fetch(new URL("/update/apply", agentHttpBase), { method: "POST" });
    const body = (await res.json().catch(() => null)) as ApplyResult | null;
    if (body && typeof body.ok === "boolean") return body;
    return { ok: res.ok, message: res.ok ? "update applied" : `update failed (HTTP ${res.status})` };
  } catch (e) {
    return { ok: false, message: `could not reach the agent: ${String(e)}` };
  }
}
