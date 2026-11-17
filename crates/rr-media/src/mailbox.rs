//! Single-slot "latest value wins" hand-off between pipeline stages
//! (blueprint v2 §4.3, §8.2). Never a queue: if the consumer is busy, a
//! newer value replaces the waiting one and a drop counter goes up.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// A one-value mailbox shared by a producer and a consumer thread. It also
/// keeps one spare value so buffers circulate instead of being reallocated
/// per frame.
#[derive(Debug)]
pub struct Mailbox<T> {
    slot: Mutex<Slot<T>>,
}

#[derive(Debug)]
struct Slot<T> {
    value: Option<T>,
    spare: Option<T>,
    dropped: u64,
}

impl<T> Default for Mailbox<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Mailbox<T> {
    /// An empty mailbox.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slot: Mutex::new(Slot {
                value: None,
                spare: None,
                dropped: 0,
            }),
        }
    }

    // Every critical section is a few moves; a panic cannot leave the slot
    // half updated, so poisoning is ignored.
    fn lock(&self) -> MutexGuard<'_, Slot<T>> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores `value`. If an unconsumed value was waiting, it is counted as
    /// dropped and returned, so the producer can reuse its buffer.
    pub fn put(&self, value: T) -> Option<T> {
        let mut slot = self.lock();
        let replaced = slot.value.replace(value);
        if replaced.is_some() {
            slot.dropped = slot.dropped.saturating_add(1);
        }
        replaced
    }

    /// Takes the waiting value, if any.
    pub fn take(&self) -> Option<T> {
        self.lock().value.take()
    }

    /// Gives a consumed value back for the producer to reuse.
    pub fn recycle(&self, value: T) {
        self.lock().spare = Some(value);
    }

    /// A recycled value, if one is available.
    pub fn spare(&self) -> Option<T> {
        self.lock().spare.take()
    }

    /// Values replaced before the consumer took them.
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_value_wins_and_drops_are_counted() {
        let mailbox = Mailbox::new();
        assert_eq!(mailbox.put(1), None);
        assert_eq!(mailbox.put(2), Some(1));
        assert_eq!(mailbox.dropped(), 1);
        assert_eq!(mailbox.take(), Some(2));
        assert_eq!(mailbox.take(), None);
        assert_eq!(mailbox.put(3), None);
        assert_eq!(mailbox.dropped(), 1);
    }

    #[test]
    fn spare_buffers_circulate() {
        let mailbox: Mailbox<Vec<u8>> = Mailbox::new();
        assert!(mailbox.spare().is_none());
        mailbox.recycle(Vec::with_capacity(64));
        assert!(mailbox.spare().is_some_and(|buf| buf.capacity() >= 64));
        assert!(mailbox.spare().is_none());
    }
}
