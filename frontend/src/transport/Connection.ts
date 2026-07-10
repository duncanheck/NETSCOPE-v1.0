// The transport abstraction (ROADMAP C1). The frontend talks to exactly this
// interface and cannot tell which implementation is behind it — mock feed or live
// WebSocket. That indistinguishability is the test: if the UI behaves the same
// against both, the boundary is honest.

import type { Hello, Snapshot, Delta, Heartbeat } from "../protocol";

export type TransportState =
  | "idle"
  | "connecting"
  | "open"
  | "closed"
  | "error";

/** Call to stop receiving a subscribed event. */
export type Unsubscribe = () => void;

export interface Connection {
  /** Which implementation this is — for diagnostics/HUD only, never for logic. */
  readonly kind: "mock" | "websocket";

  /** Current transport state. */
  state(): TransportState;

  /** Begin connecting. Idempotent: calling while open is a no-op. */
  connect(): void;

  /** Tear down the transport. */
  close(): void;

  /** Send a client→agent message (control messages land here). */
  send(data: unknown): void;

  /** Ask the agent for a fresh snapshot after a detected sequence gap (C4).
   *  `lastSeq` is the last seq the client applied — diagnostics for the agent. */
  requestResync(lastSeq: number): void;

  onHello(cb: (msg: Hello) => void): Unsubscribe;
  onSnapshot(cb: (msg: Snapshot) => void): Unsubscribe;
  onDelta(cb: (msg: Delta) => void): Unsubscribe;
  onHeartbeat(cb: (msg: Heartbeat) => void): Unsubscribe;
  onStateChange(cb: (state: TransportState) => void): Unsubscribe;
}

/**
 * Minimal typed event hub shared by both transport implementations, so the
 * subscribe/emit plumbing is written once. Not exported beyond the transport
 * layer.
 */
export class Emitter<T> {
  private listeners = new Set<(value: T) => void>();
  on(cb: (value: T) => void): Unsubscribe {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }
  emit(value: T): void {
    for (const cb of this.listeners) cb(value);
  }
  clear(): void {
    this.listeners.clear();
  }
}
