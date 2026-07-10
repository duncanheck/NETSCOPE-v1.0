//! Phase-2 ring: a hand-built lock-free single-producer/single-consumer queue.
//!
//! This is the A3 systems artifact — where the project earns its atomics and
//! memory-ordering credibility (Bos, *Rust Atomics and Locks*, ch. 1–4). It is a
//! Lamport bounded ring (power-of-two slots, producer-owned `tail`, consumer-owned
//! `head`, one writer per field) with the **cached-cursor** optimization that
//! makes it competitive under cross-core contention.
//!
//! ## Why it's safe (the SPSC contract + the orderings)
//!
//! Only the producer writes `tail`; only the consumer writes `head`. Each side
//! reads its own index `Relaxed` and publishes it `Release`; it reads the *other*
//! side's index `Acquire`:
//!
//! - **Producer** writes the slot, then `tail.store(Release)`. **Consumer** does
//!   `tail.load(Acquire)` before reading that slot — release→acquire on `tail`
//!   makes the slot write *happen-before* the slot read (no torn read).
//! - **Consumer** finishes the slot, then `head.store(Release)`. **Producer** does
//!   `head.load(Acquire)` before overwriting a slot — release→acquire on `head`
//!   makes the slot read *happen-before* the next write (no write over a live read).
//!
//! ## The cached cursor (why the naive version is slow under contention)
//!
//! A naive Lamport ring loads the *partner's* cursor on every operation: the
//! producer `Acquire`-loads `head` each push, the consumer `Acquire`-loads `tail`
//! each pop. That line lives on the other core, so every op pays a cache-coherence
//! transfer — which (measured in `docs/ringbuffer.md`) dominates and makes the
//! naive ring *lose* to crossbeam despite cheaper atomics.
//!
//! The fix: each side keeps a private, non-atomic **cache** of the partner cursor
//! and consults the real atomic only when the cache says it must (producer: when
//! the cache says full; consumer: when the cache says empty). The cache is always
//! a *conservative* view — it can lag behind the real cursor but never run ahead
//! of it — so it may report "full"/"empty" spuriously (cured by one real reload)
//! but can never permit an overwrite of a live slot or a read of an unwritten one.
//! Most operations then touch only the producer's or consumer's own cache line.
//!
//! ## Why drop-*newest* (and why that's fine here)
//!
//! When full, the producer cannot reclaim a slot — that's the consumer's job, and
//! a second writer to `head` would break the proof above — so a full ring drops the
//! incoming item, counted as telemetry. For NETSCOPE that is costless: every
//! payload carries a full snapshot and a monotonic generation, so a dropped update
//! is just a generation gap the client already heals with a snapshot re-request.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crossbeam::utils::CachePadded;

use crate::Ring;

pub struct AtomicSpsc<T> {
    /// Ring storage; each slot is written by the producer and read by the
    /// consumer, ordered by the `tail`/`head` release→acquire pairs.
    buf: Box<[UnsafeCell<MaybeUninit<T>>]>,
    /// `capacity - 1`; indices mask into the buffer (capacity is a power of two).
    mask: usize,
    capacity: usize,
    /// Consumer's read cursor (monotonic, wrapping). Only the consumer writes it.
    head: CachePadded<AtomicUsize>,
    /// Producer's write cursor (monotonic, wrapping). Only the producer writes it.
    tail: CachePadded<AtomicUsize>,
    /// Producer-private cache of `head` — read without touching the consumer's
    /// cache line until the cache says the ring is full.
    cached_head: CachePadded<UnsafeCell<usize>>,
    /// Consumer-private cache of `tail` — symmetric.
    cached_tail: CachePadded<UnsafeCell<usize>>,
    dropped: AtomicU64,
}

// SAFETY: the SPSC contract (one producer thread, one consumer thread) plus the
// release/acquire discipline means no two threads touch the same slot or atomic
// field without a happens-before edge. `cached_head` is producer-only and
// `cached_tail` is consumer-only, so each `UnsafeCell` has a single accessing
// thread. `T: Send` lets values move across the producer/consumer boundary.
unsafe impl<T: Send> Send for AtomicSpsc<T> {}
unsafe impl<T: Send> Sync for AtomicSpsc<T> {}

impl<T> AtomicSpsc<T> {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two().max(2);
        let buf = (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            buf,
            mask: capacity - 1,
            capacity,
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
            cached_head: CachePadded::new(UnsafeCell::new(0)),
            cached_tail: CachePadded::new(UnsafeCell::new(0)),
            dropped: AtomicU64::new(0),
        }
    }
}

impl<T: Send> Ring<T> for AtomicSpsc<T> {
    fn push(&self, item: T) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed); // we are the only writer
                                                      // SAFETY: producer-only access to the head cache.
        let cached_head = unsafe { &mut *self.cached_head.get() };

        if tail.wrapping_sub(*cached_head) == self.capacity {
            // Cache says full — pay the cross-core read once to confirm.
            *cached_head = self.head.load(Ordering::Acquire);
            if tail.wrapping_sub(*cached_head) == self.capacity {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Some(item);
            }
        }
        // SAFETY: the slot at `tail & mask` is free (the consumer has read past it,
        // observed via the Acquire load of `head` cached above), so no live value
        // or concurrent reader is there. Initialise it, then publish with Release.
        unsafe {
            (*self.buf[tail & self.mask].get()).write(item);
        }
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        None
    }

    fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed); // we are the only writer
                                                      // SAFETY: consumer-only access to the tail cache.
        let cached_tail = unsafe { &mut *self.cached_tail.get() };

        if head == *cached_tail {
            // Cache says empty — pay the cross-core read once to confirm.
            *cached_tail = self.tail.load(Ordering::Acquire);
            if head == *cached_tail {
                return None;
            }
        }
        // SAFETY: `head != cached_tail <= tail`, and the Acquire load of `tail`
        // means the slot at `head & mask` was fully written and published. Read it
        // out (moving the value), then publish the freed slot with Release.
        let item = unsafe { (*self.buf[head & self.mask].get()).assume_init_read() };
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(item)
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl<T> Drop for AtomicSpsc<T> {
    fn drop(&mut self) {
        // Drop the items still live between head and tail; the rest are uninit.
        let mut head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        while head != tail {
            // SAFETY: every index in [head, tail) holds an initialised value.
            unsafe {
                (*self.buf[head & self.mask].get()).assume_init_drop();
            }
            head = head.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_rounds_up_to_power_of_two() {
        assert_eq!(AtomicSpsc::<u64>::new(5).capacity(), 8);
        assert_eq!(AtomicSpsc::<u64>::new(64).capacity(), 64);
        assert_eq!(AtomicSpsc::<u64>::new(0).capacity(), 2); // floor
    }

    #[test]
    fn drops_remaining_items_on_drop() {
        use std::sync::Arc;
        // If Drop forgot the live slots, these Arc strong counts would leak.
        let a = Arc::new(());
        let ring = AtomicSpsc::new(4);
        for _ in 0..3 {
            ring.push(Arc::clone(&a));
        }
        assert_eq!(Arc::strong_count(&a), 4);
        drop(ring);
        assert_eq!(Arc::strong_count(&a), 1, "Drop must release live slots");
    }
}
