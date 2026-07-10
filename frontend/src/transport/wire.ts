// Wire framing on the client (A5): which content encoding to request, the
// subprotocols that carry that request + the auth token, and how to decode an
// incoming frame by its type. The agent mirrors this in `netscope-protocol`.
//
// JSON is the default — you can read every frame in devtools, which is the right
// call for a protocol people read to learn the project. MessagePack is opt-in for
// bandwidth (~20% smaller on a full snapshot; see docs/protocol.md) and rides
// binary frames, so the frame type alone tells the decoder which dialect it is.

import { decode as decodeMsgpack } from "@msgpack/msgpack";
import { useViewStore } from "../store/useViewStore";

export const NETSCOPE_SUBPROTOCOL = "netscope";
export const MSGPACK_SUBPROTOCOL = "netscope.msgpack";

export type WireEncoding = "json" | "msgpack";

/** The encoding to request. The view store is the source of truth (set from the
 *  Settings panel, persisted, and seeded from `?encoding=` / `VITE_WIRE_ENCODING`),
 *  so a change here means reconnecting the transport to re-negotiate. */
export function wireEncoding(): WireEncoding {
  return useViewStore.getState().encoding;
}

/**
 * The subprotocols to offer on the handshake: always `netscope`; plus
 * `netscope.msgpack` when requesting MessagePack (the agent negotiates on its
 * presence and echoes the chosen one); plus `auth.<token>` for the remote path
 * (C2). A browser only accepts the server's chosen subprotocol if it was offered,
 * so `netscope` is always present.
 */
export function wireSubprotocols(token: string | null, encoding: WireEncoding): string[] {
  const protocols = [NETSCOPE_SUBPROTOCOL];
  if (encoding === "msgpack") protocols.push(MSGPACK_SUBPROTOCOL);
  if (token) protocols.push(`auth.${token}`);
  return protocols;
}

/**
 * Decode an incoming WebSocket frame to a parsed JS value by frame type: a string
 * is JSON, an ArrayBuffer is MessagePack. Returns null on a malformed frame (the
 * caller drops it) so one bad frame never tears down the stream.
 */
export function decodeFrame(data: unknown): unknown {
  if (typeof data === "string") {
    try {
      return JSON.parse(data);
    } catch {
      return null;
    }
  }
  if (data instanceof ArrayBuffer) {
    try {
      return decodeMsgpack(new Uint8Array(data));
    } catch {
      return null;
    }
  }
  return null;
}
