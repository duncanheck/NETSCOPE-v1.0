import { afterEach, describe, expect, it, vi } from "vitest";

import { setupGeoip, setupStatus, setupThreats } from "./setup";

const BASE = "http://127.0.0.1:8787";

function stubFetch(impl: (url: URL, init: RequestInit) => Response) {
  const fetchMock = vi.fn((input: string | URL, init?: RequestInit) =>
    Promise.resolve(impl(new URL(input.toString()), init ?? {})),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("setup transport (G3.2)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("setupStatus returns the agent's state on 200", async () => {
    stubFetch(
      () =>
        new Response(
          JSON.stringify({
            geo_enabled: false,
            geoip_dir: "geoip",
            threat_dir: "threatfeeds",
            threat_indicators: 0,
            has_maxmind_key: false,
            config_path: "/home/u/.config/netscope/config.json",
            packet_capture: "off — set NETSCOPE_PCAP=1 (needs capture privilege)",
          }),
          { status: 200 },
        ),
    );
    const status = await setupStatus(BASE);
    expect(status?.geo_enabled).toBe(false);
    expect(status?.has_maxmind_key).toBe(false);
  });

  it("setupStatus is null when the agent is unreachable or refuses", async () => {
    stubFetch(() => new Response("setup is a local control", { status: 403 }));
    expect(await setupStatus(BASE)).toBeNull();
  });

  it("setupGeoip posts the key and surfaces success", async () => {
    const fetchMock = stubFetch(
      () => new Response(JSON.stringify({ ok: true, geo_enabled: true }), { status: 200 }),
    );
    const res = await setupGeoip(BASE, "abc123");
    expect(res.ok).toBe(true);
    expect(res.geo_enabled).toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url.toString()).toBe("http://127.0.0.1:8787/setup/geoip");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(init?.body as string)).toEqual({ license_key: "abc123" });
  });

  it("setupGeoip omits the key field when reusing the stored key", async () => {
    const fetchMock = stubFetch(
      () => new Response(JSON.stringify({ ok: true, geo_enabled: true }), { status: 200 }),
    );
    await setupGeoip(BASE);
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init?.body as string)).toEqual({});
  });

  it("setupGeoip surfaces the agent's error body (e.g. a refused key)", async () => {
    stubFetch(
      () =>
        new Response(
          JSON.stringify({
            ok: false,
            geo_enabled: false,
            error: "MaxMind refused the license key — check it and try again",
          }),
          { status: 200 },
        ),
    );
    const res = await setupGeoip(BASE, "bad");
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/refused the license key/);
  });

  it("setupGeoip fails soft when the agent is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new TypeError("network down"))),
    );
    const res = await setupGeoip(BASE, "abc");
    expect(res.ok).toBe(false);
    expect(res.error).toBe("agent unreachable");
  });

  it("setupThreats reports fetched + skipped feeds and the new indicator count", async () => {
    stubFetch(
      () =>
        new Response(
          JSON.stringify({
            ok: true,
            indicators: 150000,
            sources: ["stevenblack.hosts", "feodo.ips"],
            fetched: ["stevenblack.hosts", "feodo.ips"],
            skipped: ["urlhaus.hosts", "firehol_level1.ips"],
          }),
          { status: 200 },
        ),
    );
    const res = await setupThreats(BASE);
    expect(res.ok).toBe(true);
    expect(res.indicators).toBe(150000);
    expect(res.skipped).toHaveLength(2);
  });
});
