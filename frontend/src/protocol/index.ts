// Barrel for the wire protocol types. The files under ./generated/ are produced
// FROM the Rust `netscope-protocol` crate via ts-rs — never hand-edited. Regenerate
// with `pnpm gen:protocol`. This module re-exports them and adds a couple of
// runtime helpers (the generated files are types only).

export type { WireMessage } from "./generated/WireMessage";
export type { Hello } from "./generated/Hello";
export type { AgentInfo } from "./generated/AgentInfo";
export type { Heartbeat } from "./generated/Heartbeat";
export type { Snapshot } from "./generated/Snapshot";
export type { Delta } from "./generated/Delta";
export type { Flow } from "./generated/Flow";
export type { Category } from "./generated/Category";
export type { SecurityFlag } from "./generated/SecurityFlag";
export type { L4Proto } from "./generated/L4Proto";
export type { GeoLocation } from "./generated/GeoLocation";
export type { AsnInfo } from "./generated/AsnInfo";
export type { ProcessInfo } from "./generated/ProcessInfo";
export type { ClientMessage } from "./generated/ClientMessage";
export type { ResyncRequest } from "./generated/ResyncRequest";

import type { WireMessage } from "./generated/WireMessage";
import type { ClientMessage } from "./generated/ClientMessage";

/** Build the one client→agent message: a request for a fresh snapshot (C4). */
export function resyncRequest(lastSeq: number): ClientMessage {
  return { type: "resync", last_seq: lastSeq };
}

/**
 * The protocol version this client speaks. Must match `PROTOCOL_VERSION` in the
 * Rust crate; the client compares it against the value in `hello` and warns on a
 * major mismatch.
 */
export const PROTOCOL_VERSION = 1 as const;

/**
 * Whether an agent speaking `version` is compatible with this client. Mirrors the
 * Rust `is_compatible`: the version is the protocol *major*, so compatibility is
 * an exact match — additive changes ride the unknown-fields rule and never bump
 * it. The client disconnects on an incompatible major rather than misread the
 * stream.
 */
export function isCompatibleVersion(version: number): boolean {
  return version === PROTOCOL_VERSION;
}

/** Narrow an unknown parsed JSON value to a {@link WireMessage} by its tag. */
export function asWireMessage(value: unknown): WireMessage | null {
  if (typeof value !== "object" || value === null) return null;
  const tag = (value as { type?: unknown }).type;
  if (tag === "hello" || tag === "snapshot" || tag === "delta" || tag === "heartbeat") {
    return value as WireMessage;
  }
  return null;
}
