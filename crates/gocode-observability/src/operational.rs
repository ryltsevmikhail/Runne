//! Per-launch bounded recovery observation registry.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
};

use gocode_application::provider::{
    ProviderRecoveryObservation, ProviderRecoveryObservationAvailability, ProviderRecoveryObserver,
    ProviderRecoveryObserverError,
};

/// Maximum number of recovery observations retained between snapshots.
pub const RECOVERY_OBSERVATION_CHANNEL_CAPACITY_V1: usize = 64;

struct RecoveryDrainState {
    receiver: Receiver<()>,
    observed_count: u64,
}

struct RecoveryObservationState {
    dropped_event_count: AtomicU64,
    drop_counter_saturated: AtomicBool,
    permanent_unavailable: AtomicBool,
    closed: AtomicBool,
}

impl RecoveryObservationState {
    fn observe(&self, sender: &SyncSender<()>) -> Result<(), ProviderRecoveryObserverError> {
        if self.closed.load(Ordering::Acquire) {
            self.increment_drop_saturating();
            self.permanent_unavailable.store(true, Ordering::Release);
            return Err(ProviderRecoveryObserverError::Unavailable);
        }

        match sender.try_send(()) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(())) => {
                self.increment_drop_saturating();
                Err(ProviderRecoveryObserverError::Unavailable)
            }
            Err(TrySendError::Disconnected(())) => {
                self.increment_drop_saturating();
                self.permanent_unavailable.store(true, Ordering::Release);
                Err(ProviderRecoveryObserverError::Unavailable)
            }
        }
    }

    fn increment_drop_saturating(&self) {
        let mut current = self.dropped_event_count.load(Ordering::Acquire);
        loop {
            if current == u64::MAX {
                self.drop_counter_saturated.store(true, Ordering::Release);
                return;
            }

            match self.dropped_event_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if current == u64::MAX - 1 {
                        self.drop_counter_saturated.store(true, Ordering::Release);
                    }
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn drop_snapshot(&self) -> (u64, bool) {
        let dropped_event_count = self.dropped_event_count.load(Ordering::Acquire);
        let flag_set = self.drop_counter_saturated.load(Ordering::Acquire);
        let drop_counter_saturated = dropped_event_count == u64::MAX;
        if drop_counter_saturated && !flag_set {
            self.drop_counter_saturated.store(true, Ordering::Release);
        }
        (dropped_event_count, drop_counter_saturated)
    }
}

/// Per-launch query registry for recovered terminal output observations.
pub struct RecoveryObservationRegistry {
    sender: SyncSender<()>,
    state: Arc<RecoveryObservationState>,
    drain: Mutex<RecoveryDrainState>,
}

/// Cloneable, nonblocking producer for recovery observations.
#[derive(Clone)]
pub struct RecoveryObservationObserver {
    sender: SyncSender<()>,
    state: Arc<RecoveryObservationState>,
}

impl RecoveryObservationRegistry {
    /// Creates a query registry and its producer observer for one runtime launch.
    #[must_use]
    pub fn new() -> (Self, RecoveryObservationObserver) {
        let (sender, receiver) = sync_channel(RECOVERY_OBSERVATION_CHANNEL_CAPACITY_V1);
        let state = Arc::new(RecoveryObservationState {
            dropped_event_count: AtomicU64::new(0),
            drop_counter_saturated: AtomicBool::new(false),
            permanent_unavailable: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        let registry = Self {
            sender: sender.clone(),
            state: Arc::clone(&state),
            drain: Mutex::new(RecoveryDrainState {
                receiver,
                observed_count: 0,
            }),
        };
        let observer = RecoveryObservationObserver { sender, state };
        (registry, observer)
    }

    /// Permanently makes this launch's recovery observation pipeline unavailable.
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::Release);
        self.state
            .permanent_unavailable
            .store(true, Ordering::Release);
    }

    /// Returns the safe application-internal recovery snapshot.
    #[must_use]
    pub fn snapshot_recovery_observation(&self) -> ProviderRecoveryObservation {
        if self.state.permanent_unavailable.load(Ordering::Acquire) {
            return self.unavailable_snapshot();
        }

        let mut drain = match self.drain.try_lock() {
            Ok(drain) => drain,
            Err(_) => return self.unavailable_snapshot(),
        };
        loop {
            match drain.receiver.try_recv() {
                Ok(()) => match drain.observed_count.checked_add(1) {
                    Some(count) => drain.observed_count = count,
                    None => {
                        self.state
                            .permanent_unavailable
                            .store(true, Ordering::Release);
                        drop(drain);
                        return self.unavailable_snapshot();
                    }
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.state
                        .permanent_unavailable
                        .store(true, Ordering::Release);
                    drop(drain);
                    return self.unavailable_snapshot();
                }
            }
        }

        if self.state.permanent_unavailable.load(Ordering::Acquire) {
            drop(drain);
            return self.unavailable_snapshot();
        }

        let (dropped_event_count, drop_counter_saturated) = self.state.drop_snapshot();
        let availability = if dropped_event_count == 0 {
            ProviderRecoveryObservationAvailability::Complete
        } else {
            ProviderRecoveryObservationAvailability::Truncated
        };
        let observed_count = drain.observed_count;
        drop(drain);
        self.observation(
            availability,
            Some(observed_count),
            dropped_event_count,
            drop_counter_saturated,
        )
    }

    fn unavailable_snapshot(&self) -> ProviderRecoveryObservation {
        let (dropped_event_count, drop_counter_saturated) = self.state.drop_snapshot();
        self.observation(
            ProviderRecoveryObservationAvailability::Unavailable,
            None,
            dropped_event_count,
            drop_counter_saturated,
        )
    }

    fn observation(
        &self,
        availability: ProviderRecoveryObservationAvailability,
        observed_count: Option<u64>,
        dropped_event_count: u64,
        drop_counter_saturated: bool,
    ) -> ProviderRecoveryObservation {
        match ProviderRecoveryObservation::new(
            availability,
            observed_count,
            dropped_event_count,
            drop_counter_saturated,
        ) {
            Ok(observation) => observation,
            Err(_) => unreachable!(),
        }
    }

    #[cfg(test)]
    fn set_observed_count_for_test(&self, observed_count: u64) {
        self.drain.lock().unwrap().observed_count = observed_count;
    }

    #[cfg(test)]
    fn set_drop_count_for_test(&self, dropped_event_count: u64) {
        self.state
            .dropped_event_count
            .store(dropped_event_count, Ordering::Release);
        self.state
            .drop_counter_saturated
            .store(dropped_event_count == u64::MAX, Ordering::Release);
    }
}

impl ProviderRecoveryObserver for RecoveryObservationObserver {
    fn observe_recovered_terminal_output(&self) -> Result<(), ProviderRecoveryObserverError> {
        self.state.observe(&self.sender)
    }
}

impl ProviderRecoveryObserver for RecoveryObservationRegistry {
    fn observe_recovered_terminal_output(&self) -> Result<(), ProviderRecoveryObserverError> {
        self.state.observe(&self.sender)
    }
}

#[cfg(test)]
mod tests;
