import { afterEach, describe, expect, it, vi } from "vitest";

import { applyPolicy, blockIp, fetchBlocked, unblockAll, verifyEnforcement } from "./warden";

const BASE = "http://127.0.0.1:8787";

function stubFetch(impl: (url: URL, init: RequestInit) => Response) {
  const fetchMock = vi.fn((input: string | URL, init?: RequestInit) =>
    Promise.resolve(impl(new URL(input.toString()), init ?? {})),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("warden enforcement transport", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("fetchBlocked reports available + the set on 200", async () => {
    stubFetch(
      () =>
        new Response(JSON.stringify({ status: "blocked", blocked: ["8.8.8.8", "1.1.1.1"] }), {
          status: 200,
        }),
    );
    const state = await fetchBlocked(BASE);
    expect(state).toEqual({ available: true, blocked: ["8.8.8.8", "1.1.1.1"] });
  });

  it("fetchBlocked treats 503 as 'not configured' (generate-only), not an error", async () => {
    stubFetch(() => new Response(JSON.stringify({ ok: false, error: "not configured" }), { status: 503 }));
    const state = await fetchBlocked(BASE);
    expect(state).toEqual({ available: false, blocked: [] });
  });

  it("applyPolicy maps an 'applied' response, surfacing rejected (floor) addresses", async () => {
    const fetchMock = stubFetch(
      () =>
        new Response(
          JSON.stringify({
            status: "applied",
            added: ["8.8.8.8"],
            removed: [],
            rejected: ["127.0.0.1"],
            blocked_total: 1,
          }),
          { status: 200 },
        ),
    );
    const res = await applyPolicy(BASE, { allow: [], deny: [{ type: "category", value: "tracker" }] });
    expect(res.ok).toBe(true);
    expect(res.configured).toBe(true);
    expect(res.added).toEqual(["8.8.8.8"]);
    expect(res.rejected).toEqual(["127.0.0.1"]);
    expect(res.blockedTotal).toBe(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url.toString()).toBe("http://127.0.0.1:8787/warden/apply");
    expect(init?.method).toBe("POST");
  });

  it("applyPolicy marks configured=false on a 503", async () => {
    stubFetch(() => new Response(JSON.stringify({ ok: false, error: "no enforcer" }), { status: 503 }));
    const res = await applyPolicy(BASE, { allow: [], deny: [] });
    expect(res.ok).toBe(false);
    expect(res.configured).toBe(false);
    expect(res.error).toBe("no enforcer");
  });

  it("blockIp sends a /32 cidr deny for a v4 address", async () => {
    const fetchMock = stubFetch(
      () =>
        new Response(JSON.stringify({ status: "applied", added: ["9.9.9.9"], removed: [], rejected: [], blocked_total: 1 }), {
          status: 200,
        }),
    );
    await blockIp(BASE, "9.9.9.9");
    const body = JSON.parse(fetchMock.mock.calls[0][1]?.body as string);
    expect(body).toEqual({ allow: [], deny: [{ type: "cidr", value: "9.9.9.9/32" }] });
  });

  it("blockIp uses /128 for a v6 address", async () => {
    const fetchMock = stubFetch(
      () => new Response(JSON.stringify({ status: "applied", added: [], removed: [], rejected: [], blocked_total: 0 }), { status: 200 }),
    );
    await blockIp(BASE, "2001:db8::1");
    const body = JSON.parse(fetchMock.mock.calls[0][1]?.body as string);
    expect(body.deny[0].value).toBe("2001:db8::1/128");
  });

  it("unblockAll posts an ip list (empty = clear all)", async () => {
    const fetchMock = stubFetch(
      () => new Response(JSON.stringify({ status: "cleared", removed: 3 }), { status: 200 }),
    );
    const res = await unblockAll(BASE);
    expect(res.ok).toBe(true);
    expect(res.blockedTotal).toBe(0);
    expect(JSON.parse(fetchMock.mock.calls[0][1]?.body as string)).toEqual({ ips: [] });

    await unblockAll(BASE, ["8.8.8.8"]);
    expect(JSON.parse(fetchMock.mock.calls[1][1]?.body as string)).toEqual({ ips: ["8.8.8.8"] });
  });

  it("verifyEnforcement reports 'ok' when the firewall matches what's expected", async () => {
    stubFetch(
      () =>
        new Response(
          JSON.stringify({ status: "verified", live: ["8.8.8.8"], expected: ["8.8.8.8"], in_sync: true }),
          { status: 200 },
        ),
    );
    const res = await verifyEnforcement(BASE);
    expect(res).toEqual({ state: "ok", live: ["8.8.8.8"], expected: ["8.8.8.8"], error: null });
  });

  it("verifyEnforcement reports 'drift' when the firewall disagrees with the enforcer's belief", async () => {
    stubFetch(
      () =>
        new Response(
          JSON.stringify({ status: "verified", live: ["8.8.8.8"], expected: ["8.8.8.8", "9.9.9.9"], in_sync: false }),
          { status: 200 },
        ),
    );
    const res = await verifyEnforcement(BASE);
    expect(res.state).toBe("drift");
    expect(res.live).toEqual(["8.8.8.8"]);
    expect(res.expected).toEqual(["8.8.8.8", "9.9.9.9"]);
  });

  it("verifyEnforcement reports 'not_configured' on 503, distinct from 'unreachable'", async () => {
    stubFetch(() => new Response(JSON.stringify({ ok: false, error: "not configured" }), { status: 503 }));
    const res = await verifyEnforcement(BASE);
    expect(res.state).toBe("not_configured");
  });

  it("verifyEnforcement reports 'unreachable' on a non-503 error status, with the error surfaced", async () => {
    stubFetch(
      () => new Response(JSON.stringify({ ok: false, error: "cannot reach enforcer at ..." }), { status: 502 }),
    );
    const res = await verifyEnforcement(BASE);
    expect(res.state).toBe("unreachable");
    expect(res.error).toBe("cannot reach enforcer at ...");
  });

  it("verifyEnforcement reports 'unreachable' when the agent itself can't be reached", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("network down"))),
    );
    const res = await verifyEnforcement(BASE);
    expect(res.state).toBe("unreachable");
    expect(res.error).toContain("network down");
  });
});
