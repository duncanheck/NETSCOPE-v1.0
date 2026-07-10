# docs/protocol.md — The NETSCOPE wire protocol

*Status: **landed (A5).** This is the complete contract between the agent and any
client. The Rust crate `netscope-protocol` is the single source of truth; the
TypeScript types are generated from it, and the rules below are enforced by
conformance tests (`cargo test -p netscope-protocol`) so they can't silently rot.
Read this in three minutes and you can write a second client in any language.*

## Principles

- **One source of truth.** Every message is a Rust type in `netscope-protocol`.
  The TS types in `frontend/src/protocol/generated/` are produced from it via
  `ts-rs` — the two languages cannot disagree (regenerate with `pnpm gen:protocol`;
  `pnpm typecheck` fails on drift).
- **Forward-compatible by construction.** Unknown fields and unknown message
  `type`s are ignored, in both directions and both encodings. Additive changes are
  therefore non-breaking and need no version bump.
- **Self-describing on the wire.** The dialect (JSON vs MessagePack) is carried by
  the WebSocket frame type, so a receiver never has to sniff.

## Transport & framing

The feed is a WebSocket at `/ws`. Two content encodings, negotiated once at the
handshake via `Sec-WebSocket-Protocol` and fixed for the session:

| Dialect | Frame type | Subprotocol offered | When |
|---|---|---|---|
| **JSON** (default) | text | `netscope` | always — debuggable, readable in devtools |
| **MessagePack** | binary | `netscope.msgpack` | opt-in, for bandwidth |

The client offers `netscope` (always), `netscope.msgpack` (to request binary), and
`auth.<token>` (the C2 remote-path credential). The agent picks MessagePack iff
`netscope.msgpack` was offered, and **echoes the chosen subprotocol** so the client
knows which to decode. An older client that offers nothing gets JSON — adding a
future encoding here breaks no one, which is the point.

Request it in the frontend with `?encoding=msgpack` or `VITE_WIRE_ENCODING=msgpack`.

### Why MessagePack, measured

Both dialects encode the **same logical shape** (MessagePack uses named struct
fields, so it round-trips the `type`-tagged envelopes and stays forward-compatible).
Measured on representative snapshots (`cargo test -p netscope-protocol wire_size --
--nocapture`):

| Snapshot | JSON | MessagePack | Smaller |
|---|---|---|---|
| 1 flow | 446 B | 352 B | 21.1 % |
| 50 flows | 20.6 kB | 16.4 kB | 20.5 % |
| 300 flows | 123.7 kB | 98.5 kB | 20.4 % |

A steady ~20 % — meaningful for a phone watching a busy desktop over a tailnet
(C3), modest enough that JSON stays the readable default. The *negotiation seam*
is the durable win: a better encoding can drop in later without touching any
existing client.

## Versioning & compatibility

`PROTOCOL_VERSION` (a `u32`, currently `1`) is the protocol **major**. The `hello`
frame carries it; the client checks it with `is_compatible` (exact-major match)
and **disconnects** on a mismatch rather than misread a reshaped stream — enforced
in both `codec::is_compatible` (Rust) and `isCompatibleVersion` (TS), and the
client closes without auto-retrying into the same mismatch.

- **Additive (minor) changes never bump the major** — they ride the unknown-fields
  rule.
- **A breaking change bumps the major**, and an old peer cleanly disconnects.

## Message catalogue

### Agent → client (`WireMessage`, tagged on `type`)

**`hello { version, agent }`** — first frame on connect.

| Field | Type | Meaning |
|---|---|---|
| `version` | u32 | the agent's `PROTOCOL_VERSION` |
| `agent` | `{ name, version, platform }` | agent name, package version, OS (`linux`/`windows`/`macos`) |

**`snapshot { seq, flows }`** — full state; wholesale-replaces the client mirror.
Sent on connect, on a generation gap, and in answer to `resync`.

| Field | Type | Meaning |
|---|---|---|
| `seq` | u64 | sequence number of this frame |
| `flows` | `Flow[]` | the entire current world |

**`delta { seq, adds, updates, removes }`** — incremental change.

| Field | Type | Meaning |
|---|---|---|
| `seq` | u64 | sequence number of this frame |
| `adds` | `Flow[]` | flows that appeared |
| `updates` | `Flow[]` | flows whose state changed |
| `removes` | `string[]` | ids of flows that closed/expired |

**`heartbeat { seq, tick, uptime_ms }`** — one batched liveness payload per tick
(the batching rule all high-frequency data follows — PITFALLS A1).

| Field | Type | Meaning |
|---|---|---|
| `seq` | u64 | sequence number of this frame |
| `tick` | u64 | monotonic tick counter since the agent started |
| `uptime_ms` | u64 | agent uptime, milliseconds |

### Client → agent (`ClientMessage`, a separate envelope)

Kept distinct from `WireMessage` so the two directions version independently.

**`resync { last_seq }`** — the client detected a sequence gap and wants the world
wholesale. The agent answers with a fresh `snapshot` regardless of `last_seq`
(diagnostics only). The client sends this as JSON text even on a MessagePack
session; the agent decodes incoming frames by type, so either works.

### The `Flow` record

The per-endpoint shape carried by `snapshot`/`delta` (locked since Pass 1):

| Field | Type | Notes |
|---|---|---|
| `id` | string | stable identity, keyed on the connection 5-tuple |
| `name` | string | resolved hostname or IP |
| `category` | `service\|tracker\|cdn\|local\|unknown` | art-direction + security read |
| `asn` | `{ number, org }` \| null | owning org (GeoLite2 ASN) |
| `location` | `{ city, country, lat, lon }` \| null | GeoLite2 city; all sub-fields optional |
| `process` | `{ pid, name, path? }` \| null | null = protected/elevated process (PITFALLS A2) |
| `port` | u16 | destination port |
| `protocol` | `tcp\|udp` | L4 |
| `encrypted` | bool | destination port/proto is known-encrypted |
| `ip` | string | remote IP |
| `activity` | f32 | 0.0–1.0 traffic intensity (drives the visuals) |
| `alive` | bool | false once closed but lingering in the view |
| `flags` | `SecurityFlag[]` | `plaintext` \| `unresolved_org` \| `tracker`; empty unless any apply |

## Sequencing rules (enforced + tested)

1. **Unknown fields and unknown `type`s are ignored**, in both directions and both
   encodings (`unknown_fields_are_ignored`, `msgpack_ignores_unknown_fields`).
2. **A breaking change bumps the major**, negotiated in `hello`; the client
   disconnects on an incompatible major (`compatibility_is_exact_major`).
3. **`seq` is monotonic and contiguous across *every* frame** (`snapshot`, `delta`,
   `heartbeat`) — heartbeats sit between deltas and consume seq, so gap detection
   runs on the global seq line, not delta-to-delta. The client discards any `delta`
   with `seq ≤ last-applied` (idempotency), and on a gap sends `resync` and heals
   on the snapshot (C4). The numbering exists from v1 so resync was never a retrofit.
4. **Every message round-trips byte-for-byte in both dialects**
   (`every_message_round_trips_in_both_encodings`).

## Extending the protocol (a contributor guide)

The whole point of the single-source-of-truth + conformance-test design is that
the protocol scales to more contributors and more clients without drift. To change it:

- **Add a field to an existing message** → add it to the Rust struct (make it
  `Option` or `#[serde(default)]` so old senders/receivers stay valid),
  `pnpm gen:protocol`, done. *No version bump* — the unknown-fields rule makes it
  non-breaking, and the round-trip tests prove it.
- **Add a new message** → add a variant to `WireMessage` (or `ClientMessage`) and a
  struct, regenerate. Old clients ignore the unknown `type`. *No version bump.*
- **Add a new content encoding** → extend `Encoding`/`negotiate` with a new
  subprotocol token. Existing clients never offer it, so they're unaffected.
- **A breaking reshape** (rename/remove a field, change a type) → bump
  `PROTOCOL_VERSION`. Old clients then disconnect cleanly instead of misreading.

After any change, `cargo test -p netscope-protocol` and `cd frontend && pnpm
typecheck` are the guardrails: the first enforces the wire rules, the second fails
if the generated TS drifted from the Rust.

## Consuming the feed from your own tooling (G4.3)

The protocol isn't just the visualizer's — it's a documented local integration
surface. Everything the organism renders, your script can read:

- **The stream**: connect a WebSocket to `ws://127.0.0.1:8787/ws` (loopback needs
  no token; a remote peer pairs first — C2). You'll receive `hello`, then a full
  `snapshot`, then `delta`s and `heartbeat`s — JSON by default, so `websocat` or
  ~ten lines of Python is a working consumer. Apply deltas keyed on `flow.id`,
  honour `seq` gaps by sending a `resync` (C4), ignore message types and fields
  you don't recognize (the forward-compat rule above guarantees that's safe).
- **Point-in-time reads**: `GET /warden/threats` (loaded feeds + current matches),
  `GET /setup/status` (capability state), `GET /update/status` (build identity) —
  all loopback-only, all plain JSON.
- **Files**: the HUD exports the current view as CSV/JSON, and the opt-in history
  log (`NETSCOPE_HISTORY_DIR`, G4.1) appends lifecycle events as JSONL — one
  `{"ts","event":"open","flow":{…}}` per new connection, one
  `{"ts","event":"close","id":…}` per ended one — trivially consumable by `jq`,
  a SIEM shipper, or a notebook.

The compatibility contract is the same one the frontend lives by: exact-major
version match, unknown fields/types ignored, `seq` monotonic per connection.
