//! Criterion benchmark: the hand-built [`AtomicSpsc`] against the [`CrossbeamRing`]
//! baseline. Methodology is documented in `docs/ringbuffer.md`; the short version:
//!
//! - **Release build** (criterion runs benches in release) — debug atomics are
//!   meaningless (PITFALLS A3).
//! - **Realistic payload** — not an empty `u64`. [`Payload`] is a 384-byte record
//!   (seq + 47 words), representative of the per-hand-off memory traffic of a small
//!   delta. It is heap-free on purpose: re-allocating a `Vec` each iteration would
//!   measure the allocator, not the ring.
//! - **Two scenarios** — uncontended single-thread round-trip (raw op cost), and
//!   the one that matters: sustained two-thread producer→consumer throughput.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use netscope_ring::{AtomicSpsc, CrossbeamRing, Ring};

/// A stand-in for a captured delta: a 384-byte record (seq + 47 words). It is
/// deliberately heap-free — re-allocating a `Vec` every iteration would turn this
/// into an allocator benchmark and swamp the ring cost we're trying to measure.
/// 384 B is representative of the per-hand-off memory traffic (a small delta),
/// so the move through the ring copies real bytes across the core boundary.
#[derive(Clone, Copy)]
struct Payload {
    seq: u64,
    words: [u64; 47],
}

impl Payload {
    fn new(seq: u64) -> Self {
        Self {
            seq,
            words: [seq; 47],
        }
    }
}

const CAPACITY: usize = 256;

/// Uncontended cost of one `push` immediately followed by one `pop`, on a single
/// thread. Isolates per-operation overhead with no cross-core traffic.
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip_1t");
    group.throughput(Throughput::Elements(1));

    group.bench_function("crossbeam", |b| {
        let ring = CrossbeamRing::new(CAPACITY);
        let mut seq = 0u64;
        b.iter(|| {
            seq += 1;
            ring.push(black_box(Payload::new(seq)));
            black_box(ring.pop());
        });
    });

    group.bench_function("atomic_spsc", |b| {
        let ring = AtomicSpsc::new(CAPACITY);
        let mut seq = 0u64;
        b.iter(|| {
            seq += 1;
            ring.push(black_box(Payload::new(seq)));
            black_box(ring.pop());
        });
    });

    group.finish();
}

/// Sustained throughput moving `N` payloads across a real thread boundary: one
/// producer thread, the benchmark thread as consumer. The producer retries on a
/// full ring (lossless), so this measures steady-state hand-off cost under
/// contention — the scenario the capture→protocol path actually runs.
fn bench_throughput_2t(c: &mut Criterion) {
    const N: u64 = 200_000;
    let mut group = c.benchmark_group("throughput_2t");
    group.throughput(Throughput::Elements(N));

    group.bench_function("crossbeam", |b| {
        b.iter_custom(|iters| {
            transfer::<CrossbeamRing<Payload>>(iters, N, || CrossbeamRing::new(CAPACITY))
        })
    });

    group.bench_function("atomic_spsc", |b| {
        b.iter_custom(|iters| {
            transfer::<AtomicSpsc<Payload>>(iters, N, || AtomicSpsc::new(CAPACITY))
        })
    });

    group.finish();
}

/// Run `iters` rounds of "move `n` payloads producer→consumer", returning the
/// total elapsed time criterion needs. The ring is rebuilt per round so state
/// never carries over.
fn transfer<R>(iters: u64, n: u64, make: impl Fn() -> R) -> Duration
where
    R: Ring<Payload> + 'static,
{
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let ring = Arc::new(make());
        let start = Instant::now();

        let producer = {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                for i in 0..n {
                    let mut item = Payload::new(i);
                    // Retry on full so the transfer is lossless and we measure
                    // hand-off, not drops.
                    while let Some(returned) = ring.push(item) {
                        item = returned;
                        std::hint::spin_loop();
                    }
                }
            })
        };

        let mut got = 0u64;
        while got < n {
            if let Some(p) = ring.pop() {
                // Touch the payload so the consumer genuinely reads what it moved.
                black_box(p.seq.wrapping_add(p.words[0]));
                got += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        producer.join().unwrap();
        total += start.elapsed();
    }
    total
}

criterion_group!(benches, bench_roundtrip, bench_throughput_2t);
criterion_main!(benches);
