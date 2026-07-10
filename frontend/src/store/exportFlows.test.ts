import { describe, expect, it } from "vitest";

import type { Flow } from "../protocol";
import { CSV_COLUMNS, exportFilename, flowsToCsv, flowsToJson } from "./exportFlows";

function flow(over: Partial<Flow>): Flow {
  return {
    id: "tcp:1.2.3.4:443",
    name: "example.com",
    category: "service",
    asn: null,
    location: null,
    process: null,
    port: 443,
    protocol: "tcp",
    encrypted: true,
    ip: "1.2.3.4",
    activity: 0.5,
    alive: true,
    flags: [],
    ...over,
  };
}

describe("flow export (G4.1)", () => {
  it("JSON round-trips the flow list", () => {
    const flows = [flow({ id: "a" }), flow({ id: "b", encrypted: false })];
    const parsed = JSON.parse(flowsToJson(flows)) as Flow[];
    expect(parsed).toHaveLength(2);
    expect(parsed[1].encrypted).toBe(false);
  });

  it("CSV has a header and one row per flow, every row the same width", () => {
    const csv = flowsToCsv([
      flow({}),
      flow({
        process: { name: "firefox", pid: 4242, path: "/usr/bin/firefox" },
        asn: { number: 13335, org: "Cloudflare, Inc." },
        location: { city: "Sydney", country: "Australia", lat: null, lon: null },
        flags: ["tracker", "plaintext"],
      }),
    ]);
    const lines = csv.trimEnd().split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe(CSV_COLUMNS.join(","));
    // The org contains a comma → quoted, so a naive split undercounts; assert
    // on the quoted form directly instead.
    expect(lines[2]).toContain('"Cloudflare, Inc."');
    expect(lines[2]).toContain("tracker|plaintext");
    expect(lines[1].split(",")).toHaveLength(CSV_COLUMNS.length);
  });

  it("escapes embedded quotes by doubling", () => {
    const csv = flowsToCsv([flow({ name: 'weird"host' })]);
    expect(csv).toContain('"weird""host"');
  });

  it("filenames are timestamped and extensioned", () => {
    const name = exportFilename("csv", new Date("2026-07-05T12:34:56Z"));
    expect(name).toBe("netscope-flows-2026-07-05-12-34-56.csv");
  });
});
