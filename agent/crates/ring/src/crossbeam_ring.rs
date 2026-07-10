//! Phase-1 ring: the shipped baseline, a thin wrapper over crossbeam's
//! `ArrayQueue` (a bounded lock-free MPMC queue). It is more general than we need
//! — we only ever have one producer and one consumer — but it is correct, fast,
//! and already battle-tested, which is exactly what "ship it first" wants. The
//! hand-built [`AtomicSpsc`](super::AtomicSpsc) is measured against this.

use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam::queue::ArrayQueue;

use crate::Ring;

pub struct CrossbeamRing<T> {
    queue: ArrayQueue<T>,
    dropped: AtomicU64,
}

impl<T> CrossbeamRing<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity.max(1)),
            dropped: AtomicU64::new(0),
        }
    }
}

impl<T: Send> Ring<T> for CrossbeamRing<T> {
    fn push(&self, item: T) -> Option<T> {
        // `push` returns the item back on a full queue — that is our drop-newest.
        match self.queue.push(item) {
            Ok(()) => None,
            Err(item) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Some(item)
            }
        }
    }

    fn pop(&self) -> Option<T> {
        self.queue.pop()
    }

    fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}
