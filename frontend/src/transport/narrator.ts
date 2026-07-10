// D2 narrator client. The bundled UI is served by the agent same-origin, so it
// reads the available AI providers and asks the agent to explain the current
// session with the chosen one. The agent scrubs (D1) before anything is sent to a
// provider; the built-in and Ollama providers stay on the machine, Claude does not.

export type ProviderId = "rules" | "ollama" | "anthropic";

export interface ProviderStatus {
  id: ProviderId;
  label: string;
  available: boolean;
  detail: string;
  /** True when using this provider keeps the scrubbed summary on the machine. */
  local: boolean;
  /** For local providers (Ollama): the models detected installed on this machine. */
  models: string[];
}

export interface Explanation {
  provider: ProviderId;
  prompt_version: number;
  text: string;
}

/** List the AI providers and whether each is ready (for the menu). */
export async function fetchProviders(agentHttpBase: string): Promise<ProviderStatus[]> {
  try {
    const res = await fetch(new URL("/narrator/providers", agentHttpBase));
    if (!res.ok) return [];
    const body = (await res.json()) as { providers?: ProviderStatus[] };
    return body.providers ?? [];
  } catch {
    return [];
  }
}

export type ExplainResult =
  | { ok: true; explanation: Explanation }
  | { ok: false; error: string };

/** POST a scrub + explain request and normalize the result. `flowId` narrows it to
 *  a single selected endpoint (per-node explain); omit it for the whole session. */
async function postExplain(
  agentHttpBase: string,
  body: Record<string, unknown>,
): Promise<ExplainResult> {
  try {
    const res = await fetch(new URL("/narrator/explain", agentHttpBase), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const parsed = (await res.json().catch(() => null)) as
      | (Explanation & { error?: undefined })
      | { error: string }
      | null;
    if (res.ok && parsed && "text" in parsed) {
      return { ok: true, explanation: parsed as Explanation };
    }
    const error =
      parsed && "error" in parsed && parsed.error
        ? parsed.error
        : `explain failed (HTTP ${res.status})`;
    return { ok: false, error };
  } catch (e) {
    return { ok: false, error: `could not reach the agent: ${String(e)}` };
  }
}

/** Ask the agent to scrub + explain the current session with `provider`. An
 *  optional `model` picks one of the locally-installed models (Ollama). */
export async function explainSession(
  agentHttpBase: string,
  provider: ProviderId,
  model?: string,
): Promise<ExplainResult> {
  return postExplain(agentHttpBase, model ? { provider, model } : { provider });
}

/** Explain a single selected endpoint (per-node, D2). Same providers + privacy
 *  scrub, narrowed to the one flow. */
export async function explainFlow(
  agentHttpBase: string,
  provider: ProviderId,
  flowId: string,
  model?: string,
): Promise<ExplainResult> {
  return postExplain(
    agentHttpBase,
    model ? { provider, model, flow_id: flowId } : { provider, flow_id: flowId },
  );
}
