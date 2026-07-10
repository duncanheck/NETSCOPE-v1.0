//! # netscope-ring
//!
//! The bounded SPSC handoff between the capture thread (producer) and the
//! protocol layer (consumer) — ROADMAP A3. One trait, [`Ring`], with two
//! implementations behind it so the swap is mechanical (the PITFALLS A3 prefire):
//!
//! - [`CrossbeamRing`] — Phase 1, the **shipped** baseline. A thin wrapper over
//!   `crossbeam::queue::ArrayQueue`: correct, fast, and verified library code.
//! - [`AtomicSpsc`] — Phase 2, the **hand-built** lock-free ring. Raw
//!   `AtomicUsize` head/tail with explicitly chosen memory orderings — the
//!   systems-skill artifact, benchmarked against the baseline in
//!   `benches/ring.rs` and written up in `docs/ringbuffer.md`.
//!
//! ## Buffer-full policy: drop-newest, counted, never block
//!
//! The capture pipeline must never block (a stalled producer would back-pressure
//! the OS-table poll). So a full ring does not wait: it **drops** and counts the
//! drop ([`Ring::dropped`]) as telemetry. We drop the *newest* item (the one
//! being pushed) rather than the oldest, because that is the only choice that
//! keeps a lock-free single-writer-per-slot ring sound — and it costs nothing in
//! correctness here, since every payload carries a full snapshot and the
//! protocol's generation-gap resync heals any drop. See `docs/ringbuffer.md` for
//! the full argument.

mod crossbeam_ring;
mod spsc;

pub use crossbeam_ring::CrossbeamRing;
pub use spsc::AtomicSpsc;

/// A bounded single-producer/single-consumer handoff. Never blocks; a full ring
/// drops the pushed item and counts it.
///
/// ## Contract
///
/// At most one thread may call [`push`](Ring::push) (the producer) and at most
/// one thread may call [`pop`](Ring::pop) (the consumer), concurrently with each
/// other. Calling `push` from two threads at once (or `pop` from two) is a
/// contract violation; [`CrossbeamRing`] happens to tolerate it (it wraps an
/// MPMC queue), [`AtomicSpsc`] does not.
pub trait Ring<T>: Send + Sync {
    /// Push an item. Returns `None` if it was stored, or `Some(item)` if the ring
    /// was full and the item was dropped (and the drop counter incremented).
    fn push(&self, item: T) -> Option<T>;

    /// Pop the oldest item, or `None` if the ring is empty.
    fn pop(&self) -> Option<T>;

    /// Maximum number of live items the ring can hold.
    fn capacity(&self) -> usize;

    /// Approximate current occupancy.
    fn len(&self) -> usize;

    /// Cumulative count of items dropped because the ring was full — telemetry.
    fn dropped(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod conformance {
    //! One suite, run against both implementations, so they are held to the same
    //! observable behaviour — FIFO order, drop accounting, and lossless transfer
    //! under real cross-thread concurrency (the SPSC soundness check).

    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn fifo_order_preserved<R: Ring<u64>>(ring: R) {
        assert!(ring.is_empty());
        for i in 0..3 {
            assert_eq!(ring.push(i), None);
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop(), Some(0));
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), None);
    }

    fn full_ring_drops_newest_and_counts<R: Ring<u64>>(ring: R) {
        let cap = ring.capacity();
        for i in 0..cap as u64 {
            assert_eq!(ring.push(i), None);
        }
        // Full now — the next push is dropped and returned.
        assert_eq!(ring.push(999), Some(999));
        assert_eq!(ring.dropped(), 1);
        // The stored items are intact and in order; the newest was the one lost.
        assert_eq!(ring.pop(), Some(0));
    }

    /// The soundness test: a real producer thread and consumer thread move a
    /// million items through a small ring. The producer retries on full (so the
    /// transfer is lossless), and the consumer must observe every value exactly
    /// once, in order. A torn read or a missed/duplicated slot fails this.
    fn lossless_in_order_under_threads<R: Ring<u64> + 'static>(ring: R) {
        const N: u64 = 1_000_000;
        let ring = Arc::new(ring);
        let producer = {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                for i in 0..N {
                    while ring.push(i).is_some() {
                        std::hint::spin_loop(); // full — let the consumer catch up
                    }
                }
            })
        };

        let mut expected = 0u64;
        while expected < N {
            if let Some(v) = ring.pop() {
                assert_eq!(v, expected, "out-of-order or lost item");
                expected += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        producer.join().unwrap();
        // Note: `dropped()` is expected to be > 0 here — every time the ring was
        // full, push returned the item and the producer re-pushed it, and each
        // full-push is a counted drop event. Losslessness is proven by the fact
        // that the consumer saw every value 0..N exactly once, in order, above.
        assert!(ring.is_empty());
    }

    #[test]
    fn crossbeam_fifo() {
        fifo_order_preserved(CrossbeamRing::new(8));
    }
    #[test]
    fn crossbeam_drops() {
        full_ring_drops_newest_and_counts(CrossbeamRing::new(8));
    }
    #[test]
    fn crossbeam_threaded() {
        lossless_in_order_under_threads(CrossbeamRing::new(64));
    }

    #[test]
    fn spsc_fifo() {
        fifo_order_preserved(AtomicSpsc::new(8));
    }
    #[test]
    fn spsc_drops() {
        full_ring_drops_newest_and_counts(AtomicSpsc::new(8));
    }
    #[test]
    fn spsc_threaded() {
        lossless_in_order_under_threads(AtomicSpsc::new(64));
    }
}
