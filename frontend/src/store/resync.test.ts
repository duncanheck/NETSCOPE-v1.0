import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Delta, Flow, Heartbeat, Snapshot } from "../protocol";
import { PROTOCOL_VERSION } from "../protocol";

// A fake Connection we can drive frame-by-frame, recording resync requests. Held
// via vi.hoisted so the vi.mock factory can reach it.
const h = vi.hoisted(() => ({ conn: null as FakeConn | null }));

class FakeConn {
  kind = "websocket" as const;
  resyncCalls: number[] = [];
  private cb: Record<string, ((m: unknown) => void) | undefined> = {};
  state() {
    return "open" as const;
  }
  connect() {}
  close() {}
  send() {}
  requestResync(lastSeq: number) {
    this.resyncCalls.push(lastSeq);
  }
  onHello(cb: (m: unknown) => void) {
    cb({ version: PROTOCOL_VERSION, agent: { name: "x", version: "0", platform: "test" } });
    return () => {};
  }
  onSnapshot(cb: (m: unknown) => void) {
    this.cb.snapshot = cb;
    return () => {};
  }
  onDelta(cb: (m: unknown) => void) {
    this.cb.delta = cb;
    return () => {};
  }
  onHeartbeat(cb: (m: unknown) => void) {
    this.cb.heartbeat = cb;
    return () => {};
  }
  onStateChange() {
    return () => {};
  }
  snapshot(s: Snapshot) {
    this.cb.snapshot?.(s);
  }
  delta(d: Delta) {
    this.cb.delta?.(d);
  }
  heartbeat(hbSeq: number) {
    const hb: Heartbeat = { seq: hbSeq, tick: hbSeq, uptime_ms: hbSeq * 1000 };
    this.cb.heartbeat?.(hb);
  }
}

vi.mock("../transport", () => ({
  createConnection: () => h.conn,
  defaultAgentHttpBase: () => "http://localhost:8787",
  redeemPairingCode: () => Promise.resolve("token"),
}));

import { useNetscopeStore } from "./useNetscopeStore";

const flow = (id: string): Flow => ({
  id,
  name: id,
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
});

describe("store sequence handling (C4)", () => {
  let conn: FakeConn;
  beforeEach(() => {
    useNetscopeStore.getState().detach();
    conn = new FakeConn();
    h.conn = conn;
    useNetscopeStore.getState().attach("websocket");
  });

  it("does NOT resync when heartbeats sit between deltas (the false-positive fix)", () => {
    conn.snapshot({ seq: 1, flows: [] });
    conn.heartbeat(2);
    conn.delta({ seq: 3, adds: [flow("a")], updates: [], removes: [] });
    conn.heartbeat(4);
    conn.delta({ seq: 5, adds: [flow("b")], updates: [], removes: [] });

    const s = useNetscopeStore.getState();
    expect(s.needsResync).toBe(false);
    expect(conn.resyncCalls).toEqual([]);
    expect(s.flows.size).toBe(2);
    expect(s.lastSeq).toBe(5);
  });

  it("requests one resync on a real gap, then heals on the snapshot", () => {
    conn.snapshot({ seq: 1, flows: [] });
    conn.heartbeat(2);
    conn.delta({ seq: 3, adds: [flow("a")], updates: [], removes: [] });
    // A frame is lost: next seq jumps 4 -> 7.
    conn.delta({ seq: 7, adds: [flow("b")], updates: [], removes: [] });

    let s = useNetscopeStore.getState();
    expect(s.needsResync).toBe(true);
    expect(conn.resyncCalls).toEqual([3]); // last applied seq before the gap

    // Further gapped frames must not spam more requests in the same episode.
    conn.heartbeat(9);
    expect(conn.resyncCalls).toEqual([3]);

    // The agent's fresh snapshot rebases and clears the flag.
    conn.snapshot({ seq: 10, flows: [flow("a"), flow("b"), flow("c")] });
    s = useNetscopeStore.getState();
    expect(s.needsResync).toBe(false);
    expect(s.lastSeq).toBe(10);
    expect(s.lastAppliedSeq).toBe(10);
    expect(s.flows.size).toBe(3);
  });

  it("discards already-applied deltas (idempotent)", () => {
    conn.snapshot({ seq: 1, flows: [] });
    conn.delta({ seq: 2, adds: [flow("a")], updates: [], removes: [] });
    conn.delta({ seq: 2, adds: [flow("dup")], updates: [], removes: [] }); // replayed
    const s = useNetscopeStore.getState();
    expect(s.flows.has("dup")).toBe(false);
    expect(s.flows.size).toBe(1);
  });
});
