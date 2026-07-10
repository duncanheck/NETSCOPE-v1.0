// The delta-mirror store (Zustand). It holds a mirror of the agent's state,
// updated from snapshots and deltas, plus connection/heartbeat status for the HUD.
//
// Sequence handling is built in from the start (PITFALLS A5 / ROADMAP C4): deltas
// are applied idempotently keyed on `seq`, anything stale is discarded, and a
// detected gap flips `needsResync` — the seam C4 fills with a snapshot re-request.
//
// Note (PITFALLS B1): everything here updates at UI rate (≤ a few Hz), so React
// state is appropriate. Per-frame values (force-sim positions) will flow through
// refs/transient updates instead — they never live in this store.

import { create } from "zustand";
import type { Connection, TransportKind, TransportState } from "../transport";
import { createConnection, defaultAgentHttpBase, redeemPairingCode } from "../transport";
import type { AgentInfo, Delta, Flow, Heartbeat, Snapshot } from "../protocol";
import { isCompatibleVersion } from "../protocol";

interface NetscopeState {
  transportKind: TransportKind;
  connectionState: TransportState;
  agent: AgentInfo | null;
  protocolVersionMismatch: boolean;

  lastHeartbeat: Heartbeat | null;
  heartbeatCount: number;

  /** The mirrored world, keyed by Flow.id. */
  flows: Map<string, Flow>;
  /** Highest delta seq applied to the mirror — the idempotency cursor. */
  lastAppliedSeq: number;
  /** Highest seq seen on *any* frame (snapshot/delta/heartbeat). The session's
   *  seq is contiguous across every frame, so a jump here is a real gap — tracked
   *  separately from `lastAppliedSeq`, which only deltas advance (C4). */
  lastSeq: number;
  needsResync: boolean;

  /** C2/C3 pairing: true once a remote pairing token is in use this session;
   *  `pairError` carries the last failure for the UI. The token itself is never
   *  stored here (or anywhere persistent) — it lives only inside the live
   *  Connection (PITFALLS C2). */
  paired: boolean;
  pairError: string | null;
  pairing: boolean;

  // actions
  /** Connect via `kind`. `token` is the C2 pairing token for the remote path;
   *  omit it for the loopback default, which the agent serves token-free. */
  attach: (kind: TransportKind, token?: string | null) => void;
  detach: () => void;
  /** Redeem a pairing code (C2) and reconnect the WebSocket transport with the
   *  resulting token — the C3 remote-device entry point. */
  pair: (code: string) => Promise<void>;
}

// The live Connection lives outside the store — it is imperative, not state.
let activeConnection: Connection | null = null;
let unsubscribers: Array<() => void> = [];

function teardown(): void {
  for (const u of unsubscribers) u();
  unsubscribers = [];
  activeConnection?.close();
  activeConnection = null;
}

export const useNetscopeStore = create<NetscopeState>((set, get) => ({
  transportKind: "mock",
  connectionState: "idle",
  agent: null,
  protocolVersionMismatch: false,

  lastHeartbeat: null,
  heartbeatCount: 0,

  flows: new Map(),
  lastAppliedSeq: -1,
  lastSeq: -1,
  needsResync: false,

  paired: false,
  pairError: null,
  pairing: false,

  attach: (kind, token = null) => {
    teardown();
    const conn = createConnection(kind, token);
    activeConnection = conn;
    set({
      transportKind: kind,
      connectionState: conn.state(),
      agent: null,
      protocolVersionMismatch: false,
      lastHeartbeat: null,
      heartbeatCount: 0,
      flows: new Map(),
      lastAppliedSeq: -1,
      lastSeq: -1,
      needsResync: false,
    });

    // Gap detection runs on the *global* seq line (every frame), since heartbeats
    // sit between deltas and the agent's seq is contiguous across all of them. A
    // jump means a frame was lost → ask for a fresh snapshot, but only once per
    // gap episode (the flag clears when the snapshot lands).
    const noteSeq = (seq: number) => {
      const { lastSeq, needsResync } = get();
      if (lastSeq >= 0 && seq > lastSeq + 1 && !needsResync) {
        set({ needsResync: true });
        conn.requestResync(get().lastAppliedSeq);
      }
      if (seq > get().lastSeq) set({ lastSeq: seq });
    };

    unsubscribers.push(
      conn.onStateChange((connectionState) => set({ connectionState })),

      conn.onHello((hello) => {
        const compatible = isCompatibleVersion(hello.version);
        set({ agent: hello.agent, protocolVersionMismatch: !compatible });
        // Enforce the version contract (A5): an incompatible major means the
        // stream is reshaped in ways we can't safely apply, so we disconnect
        // (and don't auto-retry into the same mismatch) rather than misread it.
        if (!compatible) conn.close();
      }),

      conn.onSnapshot((snap: Snapshot) => {
        // A snapshot wholesale-replaces the mirror and rebases both cursors — it
        // is the recovery, so it clears any pending resync rather than gap-checking.
        const flows = new Map<string, Flow>();
        for (const f of snap.flows) flows.set(f.id, f);
        set({ flows, lastAppliedSeq: snap.seq, lastSeq: snap.seq, needsResync: false });
      }),

      conn.onDelta((delta: Delta) => {
        const { lastAppliedSeq } = get();
        // Idempotent + ordered: discard anything already applied.
        if (delta.seq <= lastAppliedSeq) return;
        noteSeq(delta.seq);
        const flows = new Map(get().flows);
        for (const f of delta.adds) flows.set(f.id, f);
        for (const f of delta.updates) flows.set(f.id, f);
        for (const id of delta.removes) flows.delete(id);
        set({ flows, lastAppliedSeq: delta.seq });
      }),

      conn.onHeartbeat((hb: Heartbeat) => {
        noteSeq(hb.seq);
        set((s) => ({ lastHeartbeat: hb, heartbeatCount: s.heartbeatCount + 1 }));
      }),
    );

    conn.connect();
  },

  detach: () => {
    teardown();
    set({ connectionState: "closed" });
  },

  pair: async (code) => {
    set({ pairing: true, pairError: null });
    try {
      const token = await redeemPairingCode(defaultAgentHttpBase(), code.trim());
      // Reconnect over WebSocket carrying the token; the Connection holds it for
      // the session (including across reconnects) — we never persist it here.
      set({ paired: true, pairing: false });
      get().attach("websocket", token);
    } catch (e) {
      set({
        paired: false,
        pairing: false,
        pairError: e instanceof Error ? e.message : String(e),
      });
    }
  },
}));
