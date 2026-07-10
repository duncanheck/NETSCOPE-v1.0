// C2 — pairing + token auth, client side.
//
// The agent gates the *remote* path (C3) on a bearer token: a device pairs once
// (exchanging a short-lived code shown on the agent host for a token) and then
// presents the token on every WebSocket handshake. Loopback clients need none —
// that's the existing local trust boundary (see the agent's `ws_handler`).
//
// Token handling rules, straight from PITFALLS C2:
//   - the token rides the `Sec-WebSocket-Protocol` header (the only header a
//     browser can set on a WS handshake), never a query string that would land
//     in logs;
//   - it is held in memory only — never localStorage/sessionStorage. The threat
//     the token defends against is a hostile script reading the network feed; a
//     token such a script could read back from storage would defeat the point.
//     Desktop builds graduate to the OS keychain (Tauri); this web client
//     re-pairs each session.

// The handshake subprotocols (token + encoding) live in `wire.ts`; the token's
// base64url alphabet is RFC 6455 subprotocol-safe, so it rides `auth.<token>`.

/** Thrown when a pairing exchange fails; `status` is the agent's HTTP status. */
export class PairingError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "PairingError";
  }
}

/**
 * Exchange a pairing code for a token at `POST {agentHttpBase}/pair`. The token
 * is returned to the caller to hold in memory (never persisted here). In
 * deployment this call rides TLS via the C3 tunnel; the code is the secret and
 * it is short-lived, single-use, and attempt-capped agent-side.
 */
export async function redeemPairingCode(
  agentHttpBase: string,
  code: string,
): Promise<string> {
  let res: Response;
  try {
    res = await fetch(new URL("/pair", agentHttpBase), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code }),
    });
  } catch (cause) {
    throw new PairingError(`could not reach the agent to pair: ${String(cause)}`, 0);
  }
  if (!res.ok) {
    throw new PairingError(
      res.status === 401
        ? "pairing code is invalid or has expired"
        : `pairing failed (HTTP ${res.status})`,
      res.status,
    );
  }
  const body: unknown = await res.json().catch(() => null);
  const token = (body as { token?: unknown } | null)?.token;
  if (typeof token !== "string" || token.length === 0) {
    throw new PairingError("agent did not return a token", res.status);
  }
  return token;
}
