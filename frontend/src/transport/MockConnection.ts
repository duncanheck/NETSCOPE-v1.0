// The mock transport. Drives the salvaged churn engine on a tick and emits the
// same messages the live agent does — hello, then heartbeat + delta per tick,
// with a snapshot up front. Implements the exact `Connection` interface the
// WebSocket transport does, so the rest of the app can't tell them apart.

import type { Hello, Snapshot, Delta, Heartbeat } from "../protocol";
import { PROTOCOL_VERSION } from "../protocol";
import { ChurnEngine } from "../mock/churn";
import { Connection, Emitter, TransportState, Unsubscribe } from "./Connection";

const TICK_MS = 1000;

export class MockConnection implements Connection {
  readonly kind = "mock" as const;

  private _state: TransportState = "idle";
  private timer: ReturnType<typeof setInterval> | null = null;
  private engine = new ChurnEngine();
  private seq = 0;
  private tick = 0;
  private startedAt = 0;

  private hello = new Emitter<Hello>();
  private snapshot = new Emitter<Snapshot>();
  private delta = new Emitter<Delta>();
  private heartbeat = new Emitter<Heartbeat>();
  private stateChange = new Emitter<TransportState>();

  state(): TransportState {
    return this._state;
  }

  connect(): void {
    if (this._state === "open" || this._state === "connecting") return;
    this.setState("connecting");

    // Simulate a brief connect latency, then go live.
    setTimeout(() => {
      this.startedAt = Date.now();
      this.setState("open");

      this.hello.emit({
        version: PROTOCOL_VERSION,
        agent: { name: "mock-feed", version: "0.1.0", platform: "mock" },
      });
      this.snapshot.emit({ seq: this.seq++, flows: this.engine.snapshot() });

      this.timer = setInterval(() => this.onTick(), TICK_MS);
    }, 120);
  }

  private onTick(): void {
    this.tick++;
    this.heartbeat.emit({
      seq: this.seq++,
      tick: this.tick,
      uptime_ms: Date.now() - this.startedAt,
    });
    const change = this.engine.step();
    if (change.adds.length || change.updates.length || change.removes.length) {
      this.delta.emit({ seq: this.seq++, ...change });
    }
  }

  close(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.setState("closed");
  }

  send(_data: unknown): void {
    // Generic passthrough; the only control message is resync, handled below.
  }

  requestResync(_lastSeq: number): void {
    // Mirror the agent: answer a resync with a fresh snapshot on the same seq
    // line, so the resync path behaves identically against the mock (the C1 test).
    if (this._state !== "open") return;
    this.snapshot.emit({ seq: this.seq++, flows: this.engine.snapshot() });
  }

  onHello(cb: (msg: Hello) => void): Unsubscribe {
    return this.hello.on(cb);
  }
  onSnapshot(cb: (msg: Snapshot) => void): Unsubscribe {
    return this.snapshot.on(cb);
  }
  onDelta(cb: (msg: Delta) => void): Unsubscribe {
    return this.delta.on(cb);
  }
  onHeartbeat(cb: (msg: Heartbeat) => void): Unsubscribe {
    return this.heartbeat.on(cb);
  }
  onStateChange(cb: (state: TransportState) => void): Unsubscribe {
    return this.stateChange.on(cb);
  }

  private setState(next: TransportState): void {
    this._state = next;
    this.stateChange.emit(next);
  }
}
