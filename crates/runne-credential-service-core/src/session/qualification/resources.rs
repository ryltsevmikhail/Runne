use std::sync::{Arc, Mutex, MutexGuard};

const MAX_LEASES: usize = 8;
const MAX_RESERVED_BYTES: usize = 2_129_968;
const MAX_VERIFICATIONS: usize = 2;

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum QualificationResourceError {
    Capacity,
}

/// Shared scalar-only accounting for disabled qualification work.
#[derive(Clone)]
pub struct QualificationResourceBudget {
    state: Arc<Mutex<Usage>>,
}

struct Usage {
    leases: usize,
    bytes: usize,
    verifications: usize,
}

/// Non-clone lease released exactly once by its `Drop` implementation.
pub struct QualificationReservationLease {
    budget: QualificationResourceBudget,
    bytes: usize,
}

/// Non-clone verifier permit released exactly once by its `Drop` implementation.
pub struct QualificationVerificationPermit {
    budget: QualificationResourceBudget,
}

impl QualificationResourceBudget {
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test() -> Self {
        Self {
            state: Arc::new(Mutex::new(Usage {
                leases: 0,
                bytes: 0,
                verifications: 0,
            })),
        }
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn try_acquire_reservation_for_test(
        &self,
        bytes: usize,
    ) -> Result<QualificationReservationLease, QualificationResourceError> {
        self.try_acquire_reservation(bytes)
            .map_err(|()| QualificationResourceError::Capacity)
    }

    pub(super) fn try_acquire_reservation(
        &self,
        bytes: usize,
    ) -> Result<QualificationReservationLease, ()> {
        let mut state = self.lock();
        let Some(next_bytes) = state.bytes.checked_add(bytes) else {
            return Err(());
        };
        if bytes == 0 || state.leases == MAX_LEASES || next_bytes > MAX_RESERVED_BYTES {
            return Err(());
        }
        state.leases += 1;
        state.bytes = next_bytes;
        drop(state);
        Ok(QualificationReservationLease {
            budget: self.clone(),
            bytes,
        })
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn try_acquire_verification_permit_for_test(
        &self,
    ) -> Result<QualificationVerificationPermit, QualificationResourceError> {
        self.try_acquire_verification_permit()
            .map_err(|()| QualificationResourceError::Capacity)
    }

    pub(super) fn try_acquire_verification_permit(
        &self,
    ) -> Result<QualificationVerificationPermit, ()> {
        let mut state = self.lock();
        if state.verifications == MAX_VERIFICATIONS {
            return Err(());
        }
        state.verifications += 1;
        drop(state);
        Ok(QualificationVerificationPermit {
            budget: self.clone(),
        })
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn usage_for_test(&self) -> (usize, usize, usize) {
        let state = self.lock();
        (state.leases, state.bytes, state.verifications)
    }

    fn lock(&self) -> MutexGuard<'_, Usage> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for QualificationReservationLease {
    fn drop(&mut self) {
        let mut state = self.budget.lock();
        debug_assert!(state.leases > 0 && state.bytes >= self.bytes);
        state.leases -= 1;
        state.bytes -= self.bytes;
    }
}

impl Drop for QualificationVerificationPermit {
    fn drop(&mut self) {
        let mut state = self.budget.lock();
        debug_assert!(state.verifications > 0);
        state.verifications -= 1;
    }
}
