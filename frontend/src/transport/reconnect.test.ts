import { describe, expect, it, vi } from "vitest";

import { reconnectDelay } from "./WebSocketConnection";

describe("reconnectDelay (C4 exponential backoff)", () => {
  it("stays within the equal-jitter band [exp/2, exp] for each attempt", () => {
    const base = 1000;
    const max = 16_000;
    for (let attempt = 0; attempt < 8; attempt++) {
      const exp = Math.min(max, base * 2 ** attempt);
      for (let i = 0; i < 50; i++) {
        const d = reconnectDelay(attempt, base, max);
        expect(d).toBeGreaterThanOrEqual(exp / 2);
        expect(d).toBeLessThanOrEqual(exp);
      }
    }
  });

  it("grows exponentially then saturates at the ceiling", () => {
    const rnd = vi.spyOn(Math, "random").mockReturnValue(1); // top of the jitter band
    try {
      expect(reconnectDelay(0, 1000, 8000)).toBe(1000);
      expect(reconnectDelay(1, 1000, 8000)).toBe(2000);
      expect(reconnectDelay(2, 1000, 8000)).toBe(4000);
      expect(reconnectDelay(3, 1000, 8000)).toBe(8000); // capped
      expect(reconnectDelay(9, 1000, 8000)).toBe(8000); // stays capped
    } finally {
      rnd.mockRestore();
    }
  });

  it("jitters down to half the exponential term", () => {
    const rnd = vi.spyOn(Math, "random").mockReturnValue(0); // bottom of the band
    try {
      expect(reconnectDelay(2, 1000, 8000)).toBe(2000); // 4000 / 2
    } finally {
      rnd.mockRestore();
    }
  });
});
