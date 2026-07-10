// Tests for the relationship/grouping core (the graph-exploration layer). Pure
// functions over Flow records — no browser — like the force-sim tests.

import { describe, it, expect } from "vitest";
import type { Flow } from "../protocol";
import {
  relationValue,
  groupKey,
  computeEdges,
  focusRelation,
  focusStateFor,
  isRelated,
  flowMatches,
  EDGE_MAX,
} from "./relationships";

function flow(over: Partial<Flow> & { id: string }): Flow {
  return {
    name: over.id,
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

describe("relationValue", () => {
  it("reads each dimension, and null when absent", () => {
    const f = flow({
      id: "a",
      process: { pid: 1, name: "chrome", path: null },
      asn: { number: 15169, org: "Google" },
      location: { city: "MV", country: "US", lat: 0, lon: 0 },
      category: "cdn",
    });
    expect(relationValue(f, "process")).toBe("chrome");
    expect(relationValue(f, "org")).toBe("Google");
    expect(relationValue(f, "country")).toBe("US");
    expect(relationValue(f, "category")).toBe("cdn");

    const bare = flow({ id: "b" });
    expect(relationValue(bare, "process")).toBeNull();
    expect(relationValue(bare, "org")).toBeNull();
    expect(relationValue(bare, "country")).toBeNull();
    // category is always present
    expect(relationValue(bare, "category")).toBe("service");
  });

  it("treats an empty country string as null", () => {
    const f = flow({ id: "a", location: { city: "", country: "", lat: 0, lon: 0 } });
    expect(relationValue(f, "country")).toBeNull();
  });
});

describe("groupKey", () => {
  it("collapses nulls into one stable bucket per key", () => {
    const a = flow({ id: "a" });
    const b = flow({ id: "b" });
    expect(groupKey(a, "process")).toBe(groupKey(b, "process"));
    // distinct keys don't collide
    expect(groupKey(a, "process")).not.toBe(groupKey(a, "org"));
  });
});

describe("computeEdges", () => {
  it("stars each group to its busiest member and skips singletons + nulls", () => {
    const flows = [
      flow({ id: "hub", process: { pid: 1, name: "chrome", path: null }, activity: 0.9 }),
      flow({ id: "leaf1", process: { pid: 2, name: "chrome", path: null }, activity: 0.2 }),
      flow({ id: "leaf2", process: { pid: 3, name: "chrome", path: null }, activity: 0.1 }),
      flow({ id: "solo", process: { pid: 4, name: "code", path: null }, activity: 0.5 }),
      flow({ id: "noproc", activity: 0.5 }), // null process → ignored
    ];
    const edges = computeEdges(flows, "process");
    // 3-member group → 2 edges, all anchored on the busiest ("hub"); solo + null none.
    expect(edges).toHaveLength(2);
    expect(edges.every((e) => e.aId === "hub")).toBe(true);
    expect(new Set(edges.map((e) => e.bId))).toEqual(new Set(["leaf1", "leaf2"]));
    expect(edges.every((e) => e.key === "process" && e.value === "chrome")).toBe(true);
  });

  it("never exceeds the instanced-buffer cap", () => {
    const flows = Array.from({ length: EDGE_MAX + 50 }, (_, i) =>
      flow({ id: `n${i}`, asn: { number: 1, org: "BigCo" }, activity: i / 1000 }),
    );
    const edges = computeEdges(flows, "org");
    expect(edges.length).toBeLessThanOrEqual(EDGE_MAX);
  });

  it("is deterministic for tied activity (hub broken by id)", () => {
    const flows = [
      flow({ id: "z", asn: { number: 1, org: "Co" }, activity: 0.5 }),
      flow({ id: "a", asn: { number: 1, org: "Co" }, activity: 0.5 }),
    ];
    const edges = computeEdges(flows, "org");
    expect(edges).toHaveLength(1);
    expect(edges[0].aId).toBe("a"); // lexicographically smallest wins the tie
    expect(edges[0].bId).toBe("z");
  });
});

describe("flowMatches", () => {
  it("matches across text fields, case-insensitively, and empty matches all", () => {
    const f = flow({
      id: "a",
      name: "api.github.com",
      process: { pid: 1, name: "Code", path: null },
      asn: { number: 36459, org: "GitHub" },
      category: "service",
      port: 443,
    });
    expect(flowMatches(f, "")).toBe(true);
    expect(flowMatches(f, "github")).toBe(true); // host + org
    expect(flowMatches(f, "CODE")).toBe(true); // process, case-insensitive
    expect(flowMatches(f, "443")).toBe(true); // port
    expect(flowMatches(f, "tracker")).toBe(false);
  });

  it("matches the category, so a 'tracker' chip isolates trackers", () => {
    expect(flowMatches(flow({ id: "a", category: "tracker" }), "tracker")).toBe(true);
    expect(flowMatches(flow({ id: "b", category: "service" }), "tracker")).toBe(false);
  });

  it("recognises the encrypted/plaintext shortcuts (no text field for posture)", () => {
    const enc = flow({ id: "a", encrypted: true });
    const plain = flow({ id: "b", encrypted: false });
    expect(flowMatches(plain, "plaintext")).toBe(true);
    expect(flowMatches(plain, "unencrypted")).toBe(true);
    expect(flowMatches(enc, "plaintext")).toBe(false);
    expect(flowMatches(enc, "encrypted")).toBe(true);
    expect(flowMatches(plain, "encrypted")).toBe(false);
  });
});

describe("focus", () => {
  it("prefers process, then org, then category", () => {
    expect(focusRelation(flow({ id: "a", process: { pid: 1, name: "p", path: null } })).key).toBe(
      "process",
    );
    expect(focusRelation(flow({ id: "a", asn: { number: 1, org: "O" } })).key).toBe("org");
    expect(focusRelation(flow({ id: "a", category: "tracker" })).key).toBe("category");
  });

  it("relates the focused node and its group siblings, dims the rest", () => {
    const focusFlow = flow({ id: "a", process: { pid: 1, name: "chrome", path: null } });
    const focus = focusStateFor(focusFlow);
    const sibling = flow({ id: "b", process: { pid: 2, name: "chrome", path: null } });
    const other = flow({ id: "c", process: { pid: 3, name: "code", path: null } });

    expect(isRelated(focusFlow, focus)).toBe(true);
    expect(isRelated(sibling, focus)).toBe(true);
    expect(isRelated(other, focus)).toBe(false);
    // No focus → everything is "related" (nothing dims).
    expect(isRelated(other, null)).toBe(true);
  });

  it("only matches the focused node itself when its value is null", () => {
    const bare = flow({ id: "a" }); // no process/org → focuses on category
    const focus = focusStateFor(bare);
    // category is non-null, so same-category siblings still relate
    expect(focus?.key).toBe("category");
    expect(isRelated(flow({ id: "b", category: "service" }), focus)).toBe(true);
    expect(isRelated(flow({ id: "c", category: "tracker" }), focus)).toBe(false);
  });
});
