//! Admission gate — controls ingress into the runtime via a semaphore.
//!
//! Three states: Accepting → Draining → Closed.
//! `drain()` transitions to `Draining` and blocks until all outstanding
//! reservations are released. `close()` is final.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// ── AdmissionState ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionState {
    Accepting = 0,
    Draining = 1,
    Closed = 2,
}

// ── AdmissionGate ───────────────────────────────────────────────────────────

/// Controls ingress into the runtime. Shared between [`RuntimeHandle`] clones
/// via `Arc`. Consulted by the supervisor during shutdown.
pub(crate) struct AdmissionGate {
    state: AtomicU8,
    reservation_capacity: usize,
    active_reservations: Arc<Semaphore>,
}

impl AdmissionGate {
    /// Create a new gate in `Accepting` state with the given capacity.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            state: AtomicU8::new(AdmissionState::Accepting as u8),
            reservation_capacity: capacity,
            active_reservations: Arc::new(Semaphore::new(capacity)),
        }
    }

    /// Return the current admission state.
    pub(crate) fn state(&self) -> AdmissionState {
        match self.state.load(Ordering::Acquire) {
            0 => AdmissionState::Accepting,
            1 => AdmissionState::Draining,
            _ => AdmissionState::Closed,
        }
    }

    /// Try to acquire an admission reservation.
    ///
    /// Returns `None` if the gate is not `Accepting` or if no permits are
    /// available. The reservation is released on drop.
    ///
    /// Uses a double-checked pattern: first check state eagerly, then try
    /// to acquire, then re-check state. If the state changed between check
    /// and acquire, the permit is released and `None` is returned.
    pub(crate) fn try_reserve(&self) -> Option<AdmissionReservation> {
        if self.state() != AdmissionState::Accepting {
            return None;
        }
        let permit = self.active_reservations.clone().try_acquire_owned().ok()?;
        if self.state() != AdmissionState::Accepting {
            drop(permit);
            return None;
        }
        Some(AdmissionReservation(permit))
    }

    /// Drain the gate: transition to `Draining`, then wait for all
    /// outstanding reservations to be released.
    ///
    /// After this completes, no new reservations can be made.
    pub(crate) async fn drain(&self) {
        self.state
            .store(AdmissionState::Draining as u8, Ordering::Release);

        // Acquire all `reservation_capacity` permits one at a time.
        // Initially, some are available (unused). The rest are held by
        // existing `AdmissionReservation`s — we block until they are
        // released and acquire those too.
        let mut held = Vec::with_capacity(self.reservation_capacity);
        for _ in 0..self.reservation_capacity {
            held.push(self.active_reservations.clone().acquire_owned().await);
        }
        // Permits held until drain() returns — blocks new reservations
    }

    /// Close the gate permanently. Must be called after `drain()`.
    pub(crate) fn close(&self) {
        self.state
            .store(AdmissionState::Closed as u8, Ordering::Release);
    }
}

// ── AdmissionReservation ────────────────────────────────────────────────────

/// Holds one admission permit. Dropping releases it.
pub(crate) struct AdmissionReservation(OwnedSemaphorePermit);
