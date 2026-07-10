// Mock churn generator — carried over from the prototype (SALVAGE.md) and kept
// permanently as a test fixture. It produces `Flow` records in the real wire
// schema and mutates them over time (connections open, change activity, and
// close), so the frontend develops against lifelike traffic without the agent.
//
// It is pure simulation: a snapshot of the current world plus a step() that
// returns the delta since the last step. The MockConnection drives it on a tick.

import type { Flow, Category, L4Proto, SecurityFlag } from "../protocol";
import { useViewStore } from "../store/useViewStore";

type Seed = {
  name: string;
  category: Category;
  org: string;
  asn: number;
  port: number;
  protocol: L4Proto;
  encrypted: boolean;
  city: string;
  country: string;
  lat: number;
  lon: number;
  process: string;
};

// A small cast of plausible endpoints spanning the categories the art-direction
// keys on (service / tracker / cdn / local).
const SEEDS: Seed[] = [
  { name: "lb-edge.cloudfront.net", category: "cdn", org: "Amazon", asn: 16509, port: 443, protocol: "tcp", encrypted: true, city: "Ashburn", country: "US", lat: 39.04, lon: -77.49, process: "chrome.exe" },
  { name: "telemetry.analytics-svc.com", category: "tracker", org: "AdMetrics Inc", asn: 13335, port: 443, protocol: "tcp", encrypted: true, city: "San Francisco", country: "US", lat: 37.77, lon: -122.42, process: "chrome.exe" },
  { name: "api.github.com", category: "service", org: "GitHub", asn: 36459, port: 443, protocol: "tcp", encrypted: true, city: "Seattle", country: "US", lat: 47.61, lon: -122.33, process: "Code.exe" },
  { name: "registry.npmjs.org", category: "service", org: "Cloudflare", asn: 13335, port: 443, protocol: "tcp", encrypted: true, city: "London", country: "GB", lat: 51.51, lon: -0.13, process: "node.exe" },
  { name: "fonts.gstatic.com", category: "cdn", org: "Google", asn: 15169, port: 443, protocol: "tcp", encrypted: true, city: "Mountain View", country: "US", lat: 37.42, lon: -122.08, process: "chrome.exe" },
  { name: "192.168.1.1", category: "local", org: "Local network", asn: 0, port: 53, protocol: "udp", encrypted: false, city: "", country: "", lat: 0, lon: 0, process: "svchost.exe" },
  { name: "beacon.metrics-collect.io", category: "tracker", org: "DataHarvest", asn: 14618, port: 80, protocol: "tcp", encrypted: false, city: "Dublin", country: "IE", lat: 53.35, lon: -6.26, process: "chrome.exe" },
  { name: "steamcdn-a.akamaihd.net", category: "cdn", org: "Akamai", asn: 20940, port: 443, protocol: "tcp", encrypted: true, city: "Frankfurt", country: "DE", lat: 50.11, lon: 8.68, process: "steam.exe" },
];

export interface ChurnDelta {
  adds: Flow[];
  updates: Flow[];
  removes: string[];
}

// --- Stress mode (B5) -------------------------------------------------------
// `?nodes=N` seeds the mock with N synthetic flows (fixed count, drifting
// activity) so the renderer can be profiled at the documented 50/150/300 scales.

const STRESS_CATEGORIES: Category[] = ["service", "cdn", "tracker", "local", "unknown"];

/** The synthetic stress count comes from the view store (set in the Settings panel,
 *  seeded from `?nodes=N`); a fresh ChurnEngine reads it on construction, so the
 *  panel applies the new count by reconnecting the mock transport. */
function stressCount(): number {
  return useViewStore.getState().stressNodes;
}

function syntheticFlow(i: number): Flow {
  const category = STRESS_CATEGORIES[i % STRESS_CATEGORIES.length];
  const isLocal = category === "local";
  const encrypted = i % 4 !== 0;
  const flags: SecurityFlag[] = [];
  if (!encrypted) flags.push("plaintext");
  if (category === "tracker") flags.push("tracker");
  return {
    id: `stress-${i}`,
    name: `node-${i}.synthetic`,
    category,
    asn: isLocal ? null : { number: 64500 + (i % 1000), org: `Synthetic Org ${i % 50}` },
    location: null,
    process: { pid: 1000 + i, name: `proc-${i % 24}.exe`, path: null },
    port: encrypted ? 443 : 80,
    protocol: "tcp",
    encrypted,
    ip: `10.${(i >> 8) & 255}.${i & 255}.1`,
    activity: 0.1 + Math.random() * 0.7,
    alive: true,
    flags,
  };
}

let nextId = 1;

function flowFromSeed(seed: Seed): Flow {
  const isLocal = seed.category === "local";
  // Mirror the agent's A4 flag policy so the mock exercises the same UI paths.
  const flags: SecurityFlag[] = [];
  if (!seed.encrypted) flags.push("plaintext");
  if (seed.category === "tracker") flags.push("tracker");
  return {
    id: `mock-${nextId++}`,
    name: seed.name,
    category: seed.category,
    asn: isLocal ? null : { number: seed.asn, org: seed.org },
    location: isLocal ? null : { city: seed.city, country: seed.country, lat: seed.lat, lon: seed.lon },
    process: { pid: 1000 + Math.floor(Math.random() * 8000), name: seed.process, path: null },
    port: seed.port,
    protocol: seed.protocol,
    encrypted: seed.encrypted,
    ip: isLocal ? seed.name : randomPublicIp(),
    activity: 0.1 + Math.random() * 0.4,
    alive: true,
    flags,
  };
}

function randomPublicIp(): string {
  const oct = () => 1 + Math.floor(Math.random() * 254);
  return `${oct()}.${oct()}.${oct()}.${oct()}`;
}

/**
 * The simulated world. Construct it, read {@link snapshot}, then call
 * {@link step} on a tick to advance and receive the change since last step.
 */
export class ChurnEngine {
  private flows = new Map<string, Flow>();
  /** Stress mode (B5): a fixed, large synthetic node set for the perf scenarios. */
  private stress = false;

  constructor(initial = 5) {
    const stress = stressCount();
    if (stress > 0) {
      this.stress = true;
      for (let i = 0; i < stress; i++) {
        const f = syntheticFlow(i);
        this.flows.set(f.id, f);
      }
      return;
    }
    for (let i = 0; i < Math.min(initial, SEEDS.length); i++) {
      const f = flowFromSeed(SEEDS[i]);
      this.flows.set(f.id, f);
    }
  }

  snapshot(): Flow[] {
    return [...this.flows.values()].map((f) => ({ ...f }));
  }

  /** Advance one tick; returns adds/updates/removes since the previous call. */
  step(): ChurnDelta {
    const adds: Flow[] = [];
    const updates: Flow[] = [];
    const removes: string[] = [];

    // Drift activity on every live flow (this is the common case).
    for (const flow of this.flows.values()) {
      if (!flow.alive) continue;
      const drift = (Math.random() - 0.5) * 0.3;
      const activity = clamp01(flow.activity + drift);
      if (Math.abs(activity - flow.activity) > 0.001) {
        flow.activity = activity;
        updates.push({ ...flow });
      }
    }

    // Stress mode holds a fixed node count — only activity drifts (above).
    if (this.stress) return { adds, updates, removes };

    // Occasionally open a new connection from the seed pool.
    if (this.flows.size < SEEDS.length && Math.random() < 0.25) {
      const used = new Set([...this.flows.values()].map((f) => f.name));
      const candidate = SEEDS.find((s) => !used.has(s.name));
      if (candidate) {
        const f = flowFromSeed(candidate);
        this.flows.set(f.id, f);
        adds.push({ ...f });
      }
    }

    // Occasionally close one (it lingers as !alive for a beat, then is removed).
    if (this.flows.size > 3 && Math.random() < 0.15) {
      const live = [...this.flows.values()].filter((f) => f.alive);
      const victim = live[Math.floor(Math.random() * live.length)];
      if (victim) {
        victim.alive = false;
        victim.activity = 0;
        updates.push({ ...victim });
      }
    }
    for (const flow of [...this.flows.values()]) {
      if (!flow.alive && Math.random() < 0.5) {
        this.flows.delete(flow.id);
        removes.push(flow.id);
      }
    }

    return { adds, updates, removes };
  }
}

function clamp01(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}
