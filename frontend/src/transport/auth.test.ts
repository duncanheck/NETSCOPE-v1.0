import { afterEach, describe, expect, it, vi } from "vitest";

import { PairingError, redeemPairingCode } from "./auth";

describe("redeemPairingCode", () => {
  afterEach(() => vi.unstubAllGlobals());

  function stubFetch(impl: (url: URL, init: RequestInit) => Response) {
    const fetchMock = vi.fn((input: string | URL, init?: RequestInit) =>
      Promise.resolve(impl(new URL(input.toString()), init ?? {})),
    );
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("POSTs the code to /pair and returns the token", async () => {
    const fetchMock = stubFetch(
      () => new Response(JSON.stringify({ token: "tok-123" }), { status: 200 }),
    );
    const token = await redeemPairingCode("http://127.0.0.1:8787", "482913");

    expect(token).toBe("tok-123");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url.toString()).toBe("http://127.0.0.1:8787/pair");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(init?.body as string)).toEqual({ code: "482913" });
  });

  it("raises a PairingError on a 401 (bad/expired code)", async () => {
    stubFetch(() => new Response("nope", { status: 401 }));
    await expect(redeemPairingCode("http://127.0.0.1:8787", "000000")).rejects.toMatchObject({
      name: "PairingError",
      status: 401,
    });
  });

  it("raises when the agent returns no token", async () => {
    stubFetch(() => new Response(JSON.stringify({}), { status: 200 }));
    await expect(redeemPairingCode("http://127.0.0.1:8787", "000000")).rejects.toBeInstanceOf(
      PairingError,
    );
  });

  it("wraps a network failure as a PairingError with status 0", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("offline"))),
    );
    await expect(redeemPairingCode("http://127.0.0.1:8787", "000000")).rejects.toMatchObject({
      name: "PairingError",
      status: 0,
    });
  });
});
