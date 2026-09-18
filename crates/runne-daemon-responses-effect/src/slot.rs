use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// A reservation for one active response stream.
pub struct StreamSlot {
    count: Arc<AtomicUsize>,
    held: bool,
}

impl StreamSlot {
    /// Atomically reserves a stream slot below the hard cap.
    pub fn reserve(count: Arc<AtomicUsize>) -> Option<Self> {
        let mut current = count.load(Ordering::Acquire);
        loop {
            if current >= 64 {
                return None;
            }
            match count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self { count, held: true }),
                Err(next) => current = next,
            }
        }
    }

    /// Transfers release ownership to the stream lifecycle.
    pub const fn keep(&mut self) {
        self.held = false;
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        if self.held {
            self.count.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
