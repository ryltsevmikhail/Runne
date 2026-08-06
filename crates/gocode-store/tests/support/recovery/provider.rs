use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct CountingProvider {
    simulated_dispatches: AtomicUsize,
}

impl CountingProvider {
    pub(crate) fn new() -> Self {
        Self {
            simulated_dispatches: AtomicUsize::new(0),
        }
    }

    pub(crate) fn simulate_dispatch(&self) {
        self.simulated_dispatches.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn assert_count(&self, expected: usize) {
        assert_eq!(self.simulated_dispatches.load(Ordering::SeqCst), expected);
    }
}
