use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::CredentialServiceEpoch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CredentialServiceRejoinRequest {
    id: u64,
    epoch: CredentialServiceEpoch,
}

impl CredentialServiceRejoinRequest {
    pub(crate) const fn epoch(self) -> CredentialServiceEpoch {
        self.epoch
    }
}

#[derive(Clone, Copy)]
struct ActiveRejoin {
    request: CredentialServiceRejoinRequest,
    dispatched: bool,
}

struct RejoinState {
    next_id: u64,
    active: Option<ActiveRejoin>,
    last_epoch: Option<CredentialServiceEpoch>,
    completion: Option<(u64, bool)>,
}

pub(super) struct CredentialServiceRejoinCoordinator {
    state: Mutex<RejoinState>,
    completed: Condvar,
}

impl CredentialServiceRejoinCoordinator {
    pub(super) const fn new() -> Self {
        Self {
            state: Mutex::new(RejoinState {
                next_id: 0,
                active: None,
                last_epoch: None,
                completion: None,
            }),
            completed: Condvar::new(),
        }
    }

    pub(super) fn queue(
        &self,
        epoch: CredentialServiceEpoch,
    ) -> Result<CredentialServiceRejoinRequest, ProviderCredentialEnrollmentHostError> {
        let mut state = self.lock()?;
        if let Some(active) = state.active {
            return (active.request.epoch == epoch)
                .then_some(active.request)
                .ok_or(ProviderCredentialEnrollmentHostError::Conflict);
        }
        if state.last_epoch == Some(epoch) {
            return Err(ProviderCredentialEnrollmentHostError::Conflict);
        }
        let id = state
            .next_id
            .checked_add(1)
            .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        let request = CredentialServiceRejoinRequest { id, epoch };
        state.next_id = id;
        state.active = Some(ActiveRejoin {
            request,
            dispatched: false,
        });
        state.last_epoch = Some(epoch);
        state.completion = None;
        Ok(request)
    }

    pub(super) fn take(
        &self,
    ) -> Result<Option<CredentialServiceRejoinRequest>, ProviderCredentialEnrollmentHostError> {
        let mut state = self.lock()?;
        let Some(active) = state.active.as_mut() else {
            return Ok(None);
        };
        if active.dispatched {
            return Ok(None);
        }
        active.dispatched = true;
        Ok(Some(active.request))
    }

    pub(super) fn complete(
        &self,
        request: CredentialServiceRejoinRequest,
        succeeded: bool,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let mut state = self.lock()?;
        let Some(active) = state.active else {
            return Err(ProviderCredentialEnrollmentHostError::Conflict);
        };
        if active.request != request || !active.dispatched {
            return Err(ProviderCredentialEnrollmentHostError::Conflict);
        }
        state.active = None;
        state.completion = Some((request.id, succeeded));
        self.completed.notify_all();
        Ok(())
    }

    pub(super) fn wait(&self, request: CredentialServiceRejoinRequest, timeout: Duration) -> bool {
        let Ok(mut state) = self.lock() else {
            return false;
        };
        let deadline = Instant::now().checked_add(timeout);
        loop {
            if let Some((id, succeeded)) = state.completion
                && id == request.id
            {
                return succeeded;
            }
            if state.active.map(|active| active.request) != Some(request) {
                return false;
            }
            let Some(remaining) =
                deadline.and_then(|value| value.checked_duration_since(Instant::now()))
            else {
                state.active = None;
                state.completion = Some((request.id, false));
                self.completed.notify_all();
                return false;
            };
            let Ok((next, result)) = self.completed.wait_timeout(state, remaining) else {
                return false;
            };
            state = next;
            if result.timed_out() {
                state.active = None;
                state.completion = Some((request.id, false));
                self.completed.notify_all();
                return false;
            }
        }
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, RejoinState>, ProviderCredentialEnrollmentHostError> {
        self.state
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_epoch_is_dispatched_once_and_completion_wakes_waiter() {
        let coordinator = CredentialServiceRejoinCoordinator::new();
        let first_epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
        let second_epoch = CredentialServiceEpoch::from_bytes([2; 16]).unwrap();
        let ticket = coordinator.queue(first_epoch).unwrap();
        assert_eq!(coordinator.queue(first_epoch).unwrap(), ticket);
        assert_eq!(
            coordinator.queue(second_epoch),
            Err(ProviderCredentialEnrollmentHostError::Conflict)
        );
        assert_eq!(coordinator.take().unwrap(), Some(ticket));
        assert_eq!(coordinator.take().unwrap(), None);
        coordinator.complete(ticket, true).unwrap();
        assert!(coordinator.wait(ticket, Duration::ZERO));
        assert!(coordinator.queue(first_epoch).is_err());
        assert!(coordinator.queue(second_epoch).is_ok());
    }

    #[test]
    fn timed_out_attempt_cannot_complete_late() {
        let coordinator = CredentialServiceRejoinCoordinator::new();
        let epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
        let ticket = coordinator.queue(epoch).unwrap();
        assert_eq!(coordinator.take().unwrap(), Some(ticket));
        assert!(!coordinator.wait(ticket, Duration::ZERO));
        assert!(coordinator.complete(ticket, true).is_err());
    }
}
