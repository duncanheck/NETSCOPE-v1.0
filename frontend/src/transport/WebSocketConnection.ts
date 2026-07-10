// The live transport. Connects to the Rust agent's WebSocket, parses each frame
// into a WireMessage, and fans it out to typed subscribers. Reconnection uses
// exponential backoff with jitter (C4); the resync half — re-requesting a
// snapshot after a sequence gap — is driven by the store via `requestResync`.

import { asWireMessage, resyncRequest } from "../protocol";
import type { Hello, Snapshot, Delta, Heartbeat } from "../protocol";
import { decodeFrame, wireEncoding, wireSubprotocols, type WireEncoding } from "./wire";
import { Connection, Emitter, TransportState, Unsubscribe } from "./Connection";

/** First retry delay; each subsequent attempt doubles up to {@link MAX_RETRY_MS}. */
const BASE_RETRY_MS = 500;
/** Backoff ceiling — a long-down agent is retried at most this often. */
const MAX_RETRY_MS = 15_000;

/**
 * Reconnect delay for the Nth consecutive failed attempt (0-based), with
 * *equal jitter*: half the exponential term plus a random half. The exponential
 * part avoids hammering a down agent; the jitter spreads reconnects so many
 * clients don't retry in lockstep (thundering herd). Exported for testing.
 */
export function reconnectDelay(
  attempt: number,
  baseMs = BASE_RETRY_MS,
  maxMs = MAX_RETRY_MS,
): number {
  const exp = Math.min(maxMs, baseMs * 2 ** attempt);
  return Math.round(exp / 2 + Math.random() * (exp / 2));
}

export class WebSocketConnection implements Connection {
  readonly kind = "websocket" as const;

  private ws: WebSocket | null = null;
  private _state: TransportState = "idle";
  private closedByUser = false;
  private retry: ReturnType<typeof setTimeout> | null = null;
  /** Consecutive failed-connect count; drives the backoff, reset on a clean open. */
  private attempt = 0;

  private hello = new Emitter<Hello>();
  private snapshot = new Emitter<Snapshot>();
  private delta = new Emitter<Delta>();
  private heartbeat = new Emitter<Heartbeat>();
  private stateChange = new Emitter<TransportState>();

  // `token` is the C2 pairing token for the remote path; null for loopback,
  // where the agent requires none. It is presented as a WS subprotocol, not a
  // query string (PITFALLS C2). `encoding` (A5) is the content dialect to request.
  private readonly encoding: WireEncoding = wireEncoding();
  constructor(
    private readonly url: string,
    private readonly token: string | null = null,
  ) {}

  state(): TransportState {
    return this._state;
  }

  connect(): void {
    if (this._state === "open" || this._state === "connecting") return;
    this.closedByUser = false;
    this.open();
  }

  private open(): void {
    this.setState("connecting");
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.url, wireSubprotocols(this.token, this.encoding));
    } catch {
      this.scheduleRetry();
      return;
    }
    // Receive MessagePack binary frames as ArrayBuffer (not Blob) so decoding is
    // synchronous; harmless for the JSON dialect.
    ws.binaryType = "arraybuffer";
    this.ws = ws;

    ws.onopen = () => {
      this.attempt = 0; // a clean connection resets the backoff
      this.setState("open");
    };
    ws.onmessage = (ev) => this.handleMessage(ev.data);
    ws.onerror = () => this.setState("error");
    ws.onclose = () => {
      this.ws = null;
      if (this.closedByUser) {
        this.setState("closed");
      } else {
        this.scheduleRetry();
      }
    };
  }

  private handleMessage(data: unknown): void {
    // Decode by frame type: string → JSON, ArrayBuffer → MessagePack (A5).
    const parsed = decodeFrame(data);
    if (parsed === null) return;
    const msg = asWireMessage(parsed);
    if (!msg) return;
    switch (msg.type) {
      case "hello":
        this.hello.emit(msg);
        break;
      case "snapshot":
        this.snapshot.emit(msg);
        break;
      case "delta":
        this.delta.emit(msg);
        break;
      case "heartbeat":
        this.heartbeat.emit(msg);
        break;
    }
  }

  private scheduleRetry(): void {
    this.setState("closed");
    if (this.retry) clearTimeout(this.retry);
    const delay = reconnectDelay(this.attempt++);
    this.retry = setTimeout(() => {
      if (!this.closedByUser) this.open();
    }, delay);
  }

  close(): void {
    this.closedByUser = true;
    if (this.retry) {
      clearTimeout(this.retry);
      this.retry = null;
    }
    this.ws?.close();
    this.ws = null;
    this.setState("closed");
  }

  send(data: unknown): void {
    if (this.ws && this._state === "open") {
      this.ws.send(typeof data === "string" ? data : JSON.stringify(data));
    }
  }

  requestResync(lastSeq: number): void {
    // Best-effort: if the socket isn't open the request is dropped — but a
    // reconnect always re-sends `hello` + a fresh `snapshot`, so the gap heals
    // either way.
    this.send(resyncRequest(lastSeq));
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
    if (next === this._state) return;
    this._state = next;
    this.stateChange.emit(next);
  }
}
