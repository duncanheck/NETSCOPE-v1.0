import { encode as encodeMsgpack } from "@msgpack/msgpack";
import { describe, expect, it } from "vitest";

import { decodeFrame, wireSubprotocols } from "./wire";

describe("wireSubprotocols (A5 handshake)", () => {
  it("offers just netscope for JSON without a token (loopback)", () => {
    expect(wireSubprotocols(null, "json")).toEqual(["netscope"]);
  });

  it("adds netscope.msgpack when requesting MessagePack", () => {
    expect(wireSubprotocols(null, "msgpack")).toEqual(["netscope", "netscope.msgpack"]);
  });

  it("appends the auth token last, after the encoding protocols", () => {
    expect(wireSubprotocols("tok123", "msgpack")).toEqual([
      "netscope",
      "netscope.msgpack",
      "auth.tok123",
    ]);
  });
});

describe("decodeFrame (A5 by frame type)", () => {
  it("decodes a JSON string frame", () => {
    const msg = { type: "heartbeat", seq: 1, tick: 2, uptime_ms: 3 };
    expect(decodeFrame(JSON.stringify(msg))).toEqual(msg);
  });

  it("decodes a MessagePack ArrayBuffer frame to the same value", () => {
    const msg = { type: "delta", seq: 9, adds: [], updates: [], removes: ["x"] };
    const bytes = encodeMsgpack(msg);
    // Pass an ArrayBuffer, as the WebSocket does with binaryType=arraybuffer.
    const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    expect(decodeFrame(buf as ArrayBuffer)).toEqual(msg);
  });

  it("returns null on a malformed frame (one bad frame never kills the stream)", () => {
    expect(decodeFrame("{not json")).toBeNull();
    expect(decodeFrame(new Uint8Array([0xff, 0x00, 0x12]).buffer)).toBeNull();
    expect(decodeFrame(42)).toBeNull();
  });
});
