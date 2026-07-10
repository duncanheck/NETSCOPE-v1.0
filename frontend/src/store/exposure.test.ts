// The exposure score's formula is a published contract (GROWTH G1.2): these tests
// pin the weights, the grade boundaries, the alive/non-local filter, and the
// severity ladder so a tweak to any of them is a deliberate, visible change.

import { describe, expect, it } from "vitest";

import type { Flow } from "../protocol";
import {
  appendSample,
  exposureScore,
  gradeOf,
  pruneTrend,
  severityOf,
  TREND_SAMPLE_MS,
  TREND_WINDOW_MS,
} from "./exposure";

function flow(over: Partial<Flow>): Flow {
  return {
    id: over.id ?? "t:1.2.3.4:443",
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

describe("exposureScore", () => {
  it("scores an empty world 100 / protected", () => {
    const e = exposureScore([]);
    expect(e.score).toBe(100);
    expect(e.grade).toBe("protected");
    expect(e.considered).toBe(0);
  });

  it("scores an all-clean session 100", () => {
    const e = exposureScore([flow({ id: "a" }), flow({ id: "b" })]);
    expect(e.score).toBe(100);
    expect(e.grade).toBe("protected");
  });

  it("ignores local and dead flows", () => {
    const e = exposureScore([
      flow({ id: "a" }),
      flow({ id: "local", category: "local", encrypted: false }),
      flow({ id: "dead", alive: false, encrypted: false, flags: ["tracker"] }),
    ]);
    expect(e.considered).toBe(1);
    expect(e.score).toBe(100);
  });

  it("moves the grade for a single tracker among many clean flows (presence penalty)", () => {
    const clean = Array.from({ length: 99 }, (_, i) => flow({ id: `c${i}` }));
    const e = exposureScore([...clean, flow({ id: "trk", category: "tracker", flags: ["tracker"] })]);
    // ratio: 70 × (0.5 × 1/100) = 0.35 → presence 15 → 100 − 15.35 → 85.
    expect(e.score).toBe(85);
    expect(e.grade).toBe("guarded");
    expect(e.trackers).toBe(1);
  });

  it("applies the documented weights exactly", () => {
    // 4 flows: 1 tracker (encrypted), 1 plaintext service, 2 clean.
    // ratio = 70 × (0.5×1 + 0.35×1)/4 = 14.875; presence = 15 + 10 = 25.
    // score = round(100 − 39.875) = 60 → exposed.
    const e = exposureScore([
      flow({ id: "trk", category: "tracker", flags: ["tracker"] }),
      flow({ id: "plain", encrypted: false }),
      flow({ id: "c1" }),
      flow({ id: "c2" }),
    ]);
    expect(e.score).toBe(60);
    expect(e.grade).toBe("exposed");
  });

  it("bottoms out (clamped) on an all-tracker plaintext session", () => {
    const e = exposureScore([
      flow({ id: "a", category: "tracker", encrypted: false, flags: ["tracker", "plaintext"] }),
      flow({ id: "b", category: "tracker", encrypted: false, flags: ["tracker", "plaintext"] }),
    ]);
    // ratio = 70 × (0.5 + 0.35) = 59.5; presence = 25 → round(15.5) = 16 → at risk.
    expect(e.score).toBe(16);
    expect(e.grade).toBe("at risk");
  });

  it("counts unresolved_org with the lightest weight", () => {
    const e = exposureScore([flow({ id: "u", flags: ["unresolved_org"] })]);
    // ratio = 70 × 0.15 = 10.5; presence = 5 → round(84.5) = 85 (banker's-free).
    expect(e.score).toBe(85);
    expect(e.unresolved).toBe(1);
  });
});

describe("gradeOf boundaries", () => {
  it("maps the documented thresholds", () => {
    expect(gradeOf(90)).toBe("protected");
    expect(gradeOf(89)).toBe("guarded");
    expect(gradeOf(70)).toBe("guarded");
    expect(gradeOf(69)).toBe("exposed");
    expect(gradeOf(40)).toBe("exposed");
    expect(gradeOf(39)).toBe("at risk");
  });
});

describe("severityOf", () => {
  it("grades worst-first: tracker∧plaintext > tracker > plaintext > unresolved > clean", () => {
    const both = severityOf(
      flow({ category: "tracker", encrypted: false, flags: ["tracker", "plaintext"] }),
    );
    const tracker = severityOf(flow({ category: "tracker", flags: ["tracker"] }));
    const plain = severityOf(flow({ encrypted: false }));
    const unres = severityOf(flow({ flags: ["unresolved_org"] }));
    const clean = severityOf(flow({}));
    expect(both).toBe(1.0);
    expect(both).toBeGreaterThan(tracker);
    expect(tracker).toBeGreaterThan(plain);
    expect(plain).toBeGreaterThan(unres);
    expect(unres).toBeGreaterThan(clean);
    expect(clean).toBe(0);
  });

  it("never flags local flows", () => {
    expect(severityOf(flow({ category: "local", encrypted: false }))).toBe(0);
  });
});

describe("trend window", () => {
  const t0 = 1_000_000_000;

  it("prunes samples older than the window", () => {
    const samples = [
      { ts: t0 - TREND_WINDOW_MS - 1, score: 50 },
      { ts: t0 - 1000, score: 80 },
    ];
    expect(pruneTrend(samples, t0)).toEqual([{ ts: t0 - 1000, score: 80 }]);
  });

  it("rate-limits appends to one per sample interval", () => {
    let s = appendSample([], 90, t0);
    s = appendSample(s, 80, t0 + TREND_SAMPLE_MS - 1); // too soon — dropped
    expect(s).toHaveLength(1);
    s = appendSample(s, 80, t0 + TREND_SAMPLE_MS); // due — kept
    expect(s).toHaveLength(2);
    expect(s[1].score).toBe(80);
  });
});
