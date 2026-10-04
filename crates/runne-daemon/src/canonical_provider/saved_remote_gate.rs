use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Per-service bounds for detached local recovery work and duplicate attempts.
pub(crate) struct SavedRemoteBlockingGate {
    scans: Arc<Semaphore>,
    candidates: Arc<Semaphore>,
    in_flight: Mutex<HashMap<[u8; 16], Weak<SavedRemoteAttemptGuard>>>,
    authorization_in_flight: Mutex<HashSet<[u8; 16]>>,
}

pub(crate) struct SavedRemoteAttemptGuard;

/// Keeps both the attempt slot and a non-queueing authorization slot alive
/// until native credential authorization has actually returned.
pub(crate) struct SavedRemoteAuthorizationGuard {
    gate: Weak<SavedRemoteBlockingGate>,
    attempt: [u8; 16],
    _attempt_guard: Arc<SavedRemoteAttemptGuard>,
}

impl SavedRemoteBlockingGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            scans: Arc::new(Semaphore::new(1)),
            candidates: Arc::new(Semaphore::new(4)),
            in_flight: Mutex::new(HashMap::new()),
            authorization_in_flight: Mutex::new(HashSet::new()),
        })
    }

    pub(crate) fn reserve_scan(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.scans).try_acquire_owned().ok()
    }

    pub(crate) fn reserve_candidate(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.candidates).try_acquire_owned().ok()
    }

    pub(crate) fn reserve_attempt(
        self: &Arc<Self>,
        attempt: runne_provider::DispatchAttemptId,
    ) -> Option<Arc<SavedRemoteAttemptGuard>> {
        let key = *attempt.as_bytes();
        let mut active = self.in_flight.lock().ok()?;
        active.retain(|_, guard| guard.strong_count() > 0);
        if active
            .get(&key)
            .is_some_and(|guard| guard.strong_count() > 0)
        {
            return None;
        }
        let guard = Arc::new(SavedRemoteAttemptGuard);
        active.insert(key, Arc::downgrade(&guard));
        Some(guard)
    }

    pub(crate) fn retain_authorization(
        self: &Arc<Self>,
        attempt: runne_provider::DispatchAttemptId,
    ) -> Option<Arc<SavedRemoteAuthorizationGuard>> {
        let key = *attempt.as_bytes();
        let attempt_guard = {
            let active = self.in_flight.lock().ok()?;
            active.get(&key)?.upgrade()?
        };
        self.reserve_authorization_with_guard(key, attempt_guard)
    }

    fn reserve_authorization_with_guard(
        self: &Arc<Self>,
        key: [u8; 16],
        attempt_guard: Arc<SavedRemoteAttemptGuard>,
    ) -> Option<Arc<SavedRemoteAuthorizationGuard>> {
        let mut active = self.authorization_in_flight.lock().ok()?;
        if !active.insert(key) {
            return None;
        }
        Some(Arc::new(SavedRemoteAuthorizationGuard {
            gate: Arc::downgrade(self),
            attempt: key,
            _attempt_guard: attempt_guard,
        }))
    }
}

impl Drop for SavedRemoteAuthorizationGuard {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.upgrade()
            && let Ok(mut active) = gate.authorization_in_flight.lock()
        {
            active.remove(&self.attempt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SavedRemoteBlockingGate;
    use std::sync::mpsc;

    #[test]
    fn timed_out_native_authorization_keeps_attempt_and_one_worker_slot_until_return() {
        let gate = SavedRemoteBlockingGate::new();
        let attempt = runne_provider::DispatchAttemptId::from_bytes([0x91; 16]);
        let attempt_guard = gate.reserve_attempt(attempt).expect("first owner");
        let auth_guard = gate
            .retain_authorization(attempt)
            .expect("authorization retains attempt");
        let worker_permit = gate.reserve_candidate().expect("one bounded worker");
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _auth_guard = auth_guard;
            let _worker_permit = worker_permit;
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.recv().unwrap();
        drop(attempt_guard);

        assert!(gate.reserve_attempt(attempt).is_none());
        assert!(gate.retain_authorization(attempt).is_none());
        let other_permits: Vec<_> = (0..3)
            .map(|_| gate.reserve_candidate().expect("other IDs can progress"))
            .collect();
        assert!(gate.reserve_candidate().is_none());
        drop(other_permits);

        release_tx.send(()).unwrap();
        worker.join().unwrap();
        let next_owner = gate
            .reserve_attempt(attempt)
            .expect("slot released on return");
        let next_auth = gate
            .retain_authorization(attempt)
            .expect("authorization can run again after completion");
        drop(next_auth);
        drop(next_owner);
    }
}
