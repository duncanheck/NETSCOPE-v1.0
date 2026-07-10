# docs/ringbuffer.md — The capture→protocol ring buffer

*Status: **landed** (milestone A3). The crate is `agent/crates/ring`
(`netscope-ring`); the benchmark is `benches/ring.rs`; numbers below are
reproducible with `cargo bench -p netscope-ring`.*

Flow updates cross from the capture thread to the protocol layer through a
bounded **SPSC** (single-producer, single-consumer) ring. This is the seam the A2
`watch` channel stood in for; A3 makes it real, behind a trait, and measures a
hand-built lock-free implementation against a `crossbeam` baseline.

## Where it sits

```
 capture thread            netscope-ring (SPSC)        coordinator task        clients
 (producer) ───push()──►  ┌────────────────────┐  ──pop()──►  (consumer) ──watch──► N sessions
                          │  bounded ring buf   │             republish latest
 OS-table poll, 250ms     └────────────────────┘             on a watch channel
```

The ring is the **1→1** cross-thread hand-off (capture thread → one coordinator).
The existing `watch` channel remains the **1→N** latest-value fan-out to client
sessions. Splitting them keeps each tool doing what it's good at: the ring never
blocks the capture poll; `watch` coalesces for slow clients, which re-snapshot on
a generation gap (C4).

## The interface (so the swap is mechanical)

One trait, `Ring<T>`, with `push` (returns the item back if the ring was full),
`pop`, `capacity`, `len`, and `dropped`. Two implementations behind it:

- **`CrossbeamRing`** — Phase 1, **shipped**. A thin wrapper over
  `crossbeam::queue::ArrayQueue` (a bounded lock-free MPMC queue): more general
  than we need, but correct, fast, and battle-tested.
- **`AtomicSpsc`** — Phase 2, the **hand-built** lock-free ring. Raw atomics with
  deliberately chosen memory orderings — the systems artifact this doc is about.

The agent ships `CrossbeamRing` (see "Which one ships" below). `AtomicSpsc` passes
the identical conformance suite — FIFO order, drop accounting, and a 1,000,000-item
cross-thread transfer asserting every value arrives exactly once, in order — so the
swap is one line.

## Buffer-full policy: drop-newest, counted, never block

The capture pipeline must never block — a stalled producer would back-pressure the
OS-table poll. So a full ring does not wait; it drops and increments a counter
(`dropped()`), which surfaces as telemetry.

**This revises the A3 plan, which said *drop-oldest*.** Drop-oldest would mean the
producer reclaiming the consumer's slot, i.e. a second writer to the consumer's
`head` cursor — which breaks the single-writer-per-field invariant the lock-free
proof rests on. We drop the **newest** (the item being pushed) instead, because
that is the only choice a sound single-writer-per-slot ring allows, **and it costs
nothing here:** every `CaptureUpdate` carries a full snapshot and a monotonic
generation, so a dropped update is just a generation gap, which the client already
heals by re-requesting a snapshot (C4). We trade the (here irrelevant) "keep
freshest" property of drop-oldest for a ring that is provably sound. The decision
is recorded honestly rather than the prefire followed blindly.

## Memory ordering (the hand-built ring)

A Lamport ring: producer owns `tail`, consumer owns `head`, **one writer per
field**. Each side reads its own cursor `Relaxed`, publishes it `Release`, and
reads the *other* side's cursor `Acquire`:

| Step | Op | Ordering | Why |
|---|---|---|---|
| producer | `tail.load` (own) | `Relaxed` | no other thread writes `tail` |
| producer | `head.load` (partner) | `Acquire` | pairs with consumer's `head` release → the consumer's read of the slot *happens-before* we overwrite it |
| producer | slot write, then `tail.store` | `Release` | publishes the slot write so the consumer's `Acquire` load of `tail` sees it (no torn read) |
| consumer | `head.load` (own) | `Relaxed` | no other thread writes `head` |
| consumer | `tail.load` (partner) | `Acquire` | pairs with producer's `tail` release → the slot write *happens-before* our read |
| consumer | slot read, then `head.store` | `Release` | publishes the freed slot so the producer's `Acquire` load of `head` sees it |

`head` and `tail` are `CachePadded` so the two cursors never share a cache line
(false sharing).

## The cached cursor — diagnosis then fix

The naive Lamport ring above loads the **partner's** cursor on *every* operation
(producer `Acquire`-loads `head` each push; consumer `Acquire`-loads `tail` each
pop). That cursor lives on the other core, so every operation pays a
cache-coherence transfer. Uncontended that's free; under two-thread contention it
dominates — and the naive ring measurably **lost** to crossbeam despite cheaper
atomics (Table 2, "atomic_spsc (naive)").

The fix is the standard one: each side keeps a private, non-atomic **cache** of the
partner's cursor and consults the real atomic only when the cache says it must
(producer: when the cache reports full; consumer: when it reports empty). The cache
is always *conservative* — it can lag the real cursor but never run ahead of it — so
it may report full/empty spuriously (cured by one reload) but can never permit an
overwrite of a live slot or a read of an unwritten one. Most operations then touch
only the local core's cache line. This is the version that ships in `AtomicSpsc`.

## Methodology

- **Machine:** Intel Xeon @ 2.80 GHz, 4 vCPU, 16 GB; Ubuntu 24.04.4 (kernel
  6.18.5); `rustc` 1.94.1. A **shared cloud VM** — so absolute numbers, and the
  two-thread numbers especially, carry real run-to-run noise; treat them as
  indicative and reproduce locally for precision.
- **Release builds**, via `criterion` (debug atomics are meaningless — PITFALLS A3).
- **Payload:** a 384-byte record (seq + 47 words), representative of a small
  delta's memory traffic. Deliberately heap-free — re-allocating a `Vec` per
  iteration would measure the allocator, not the ring.
- **Two scenarios:** `roundtrip_1t` (one thread, push-then-pop — isolates
  per-op cost, no cross-core traffic) and `throughput_2t` (a real producer thread
  and a consumer thread move 200k items, producer retries on full so the transfer
  is lossless — the steady-state hand-off the capture path actually runs).

## Results

**Table 1 — `roundtrip_1t` (uncontended, per operation).** Median of 100 samples.

| Implementation | time / op | throughput |
|---|---|---|
| `CrossbeamRing`      | 73.4 ns | 13.6 Melem/s |
| `AtomicSpsc` (cached) | **41.8 ns** | **23.9 Melem/s** |

The specialized SPSC is ~1.75× the throughput of the general MPMC queue: its
hot path is two plain loads and one release store, versus crossbeam's per-slot
CAS.

**Table 2 — `throughput_2t` (two threads, 200k items).** Median; the shared VM
makes crossbeam's two-thread figure the noisiest cell here (observed 12–20
Melem/s across runs).

| Implementation | time (200k) | throughput |
|---|---|---|
| `CrossbeamRing`        | 15.3 ms | 13.1 Melem/s |
| `AtomicSpsc` (naive)   | 14.7 ms | 13.6 Melem/s |
| `AtomicSpsc` (cached)  | **10.2 ms** | **19.5 Melem/s** |

The robust, repeatable findings: the cached cursor lifts the hand-built ring's
contended throughput **~1.4×** over the naive version (13.6 → 19.5 Melem/s) and
brings it from *behind* crossbeam to *ahead of* it. The naive→cached delta is the
clean signal; the exact margin over crossbeam under contention swims in VM noise,
so the honest claim is "competitive with, and usually ahead of, crossbeam," not a
precise multiple.

## Which one ships, and why not the faster one

The agent ships **`CrossbeamRing`**. The hand-built ring wins the microbenchmarks,
but the capture→protocol path moves about **four updates per second** — the ring is
nowhere near a bottleneck, and at that rate its throughput is irrelevant. Shipping
hand-rolled `unsafe` lock-free code in the running binary, where a verified library
performs identically *for our load*, would be buying risk for nothing. So the
verified library ships; the hand-built ring stands as the benchmarked, fully-tested,
swap-in-ready artifact — and as the writeup you're reading. That ordering — measure,
then ship the boring correct thing where the clever thing buys nothing — is the
point of the milestone as much as the atomics are.

## Reproduce

```bash
cd agent
cargo test  -p netscope-ring     # conformance, incl. the 1M-item threaded check
cargo bench -p netscope-ring     # Tables 1 & 2 (release; ~30s)
```
