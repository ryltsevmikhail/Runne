use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use super::reap_guard::ExactWriterCleanup;
#[path = "reaper_registry/worker.rs"]
mod worker;
#[cfg(test)]
use worker::matching_entries;
use worker::{AttemptKind, attempt_entry, eligible_entries, maintenance_loop};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(in crate::provider_credential_enrollment) struct ReaperOperationId(String);

impl ReaperOperationId {
    pub(in crate::provider_credential_enrollment) fn new(value: &str) -> Option<Self> {
        (!value.is_empty() && value.len() <= 128).then(|| Self(value.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialWriterReaperState {
    Pending,
    Reaped,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialWriterReaperLastError {
    InitialReap,
    OuterRetry,
    Maintenance,
    Shutdown,
    Panic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialWriterReaperSnapshot {
    operation: ReaperOperationId,
    state: CredentialWriterReaperState,
    owner_retained: bool,
    attempts: u64,
    last_error: Option<CredentialWriterReaperLastError>,
}

impl CredentialWriterReaperSnapshot {
    #[must_use]
    pub const fn operation_id(&self) -> &str {
        self.operation.0.as_str()
    }

    #[cfg(test)]
    pub(in crate::provider_credential_enrollment) const fn operation(&self) -> &ReaperOperationId {
        &self.operation
    }

    #[must_use]
    pub const fn state(&self) -> CredentialWriterReaperState {
        self.state
    }

    #[must_use]
    pub const fn owner_retained(&self) -> bool {
        self.owner_retained
    }

    #[must_use]
    pub const fn attempts(&self) -> u64 {
        self.attempts
    }

    #[must_use]
    pub const fn last_error(&self) -> Option<CredentialWriterReaperLastError> {
        self.last_error
    }
}

struct EntryStatus {
    state: CredentialWriterReaperState,
    owner_retained: bool,
    eligible: bool,
    attempts: u64,
    last_error: Option<CredentialWriterReaperLastError>,
}

struct ReaperEntry<C> {
    operation: ReaperOperationId,
    owner: Mutex<Option<C>>,
    status: Mutex<EntryStatus>,
}

struct RegistryState<C> {
    entries: Vec<Arc<ReaperEntry<C>>>,
    stopping: bool,
}

struct RegistryCore<C> {
    state: Mutex<RegistryState<C>>,
    wake: Condvar,
    cadence: Duration,
}

pub struct CredentialWriterReaperRegistry<C: ExactWriterCleanup + Send + 'static> {
    core: Arc<RegistryCore<C>>,
    maintenance: Mutex<Option<JoinHandle<()>>>,
}

impl<C: ExactWriterCleanup + Send + 'static> CredentialWriterReaperRegistry<C> {
    pub fn start(cadence: Duration) -> Result<Arc<Self>, std::io::Error> {
        let core = Arc::new(RegistryCore {
            state: Mutex::new(RegistryState {
                entries: Vec::new(),
                stopping: false,
            }),
            wake: Condvar::new(),
            cadence,
        });
        let worker_core = Arc::clone(&core);
        let maintenance = std::thread::Builder::new()
            .name("runne-writer-reaper-maintenance".into())
            .spawn(move || maintenance_loop(&worker_core))?;
        Ok(Arc::new(Self {
            core,
            maintenance: Mutex::new(Some(maintenance)),
        }))
    }

    pub(in crate::provider_credential_enrollment) fn retain_after_initial_failure(
        &self,
        operation: ReaperOperationId,
        owner: C,
    ) {
        let entry = Arc::new(ReaperEntry {
            operation,
            owner: Mutex::new(Some(owner)),
            status: Mutex::new(EntryStatus {
                state: CredentialWriterReaperState::Pending,
                owner_retained: true,
                eligible: false,
                attempts: 0,
                last_error: Some(CredentialWriterReaperLastError::InitialReap),
            }),
        });
        let stopping = {
            let mut state = recover_lock(&self.core.state);
            let stopping = state.stopping;
            state.entries.push(Arc::clone(&entry));
            stopping
        };
        if stopping {
            attempt_entry(&entry, AttemptKind::Shutdown);
        }
    }

    #[cfg(test)]
    pub(in crate::provider_credential_enrollment) fn retry_after_outer_stop(
        &self,
        operation: &ReaperOperationId,
    ) -> bool {
        let entries = matching_entries(&self.core, operation, false);
        for entry in &entries {
            attempt_entry(entry, AttemptKind::OuterRetry);
            let mut status = recover_lock(&entry.status);
            status.eligible = status.owner_retained;
        }
        self.operation_reaped(operation)
    }

    pub fn retry_all_after_outer_stop(&self) -> bool {
        let stopping = recover_lock(&self.core.state).stopping;
        let entries = eligible_entries(&self.core, true);
        for entry in &entries {
            attempt_entry(
                entry,
                if stopping {
                    AttemptKind::Shutdown
                } else {
                    AttemptKind::OuterRetry
                },
            );
            let mut status = recover_lock(&entry.status);
            status.eligible = status.owner_retained && !stopping;
        }
        self.snapshot().iter().all(|entry| !entry.owner_retained)
    }

    pub fn accepts_writer(&self) -> bool {
        let state = recover_lock(&self.core.state);
        !state.stopping
            && state
                .entries
                .iter()
                .all(|entry| !recover_lock(&entry.status).owner_retained)
    }

    pub fn snapshot(&self) -> Vec<CredentialWriterReaperSnapshot> {
        let entries = recover_lock(&self.core.state).entries.clone();
        entries
            .iter()
            .map(|entry| {
                let status = recover_lock(&entry.status);
                CredentialWriterReaperSnapshot {
                    operation: entry.operation.clone(),
                    state: status.state,
                    owner_retained: status.owner_retained,
                    attempts: status.attempts,
                    last_error: status.last_error,
                }
            })
            .collect()
    }

    #[cfg(test)]
    pub(in crate::provider_credential_enrollment) fn maintenance_is_owned(&self) -> bool {
        recover_lock(&self.maintenance).is_some()
    }

    pub fn shutdown(&self) -> bool {
        {
            let mut state = recover_lock(&self.core.state);
            state.stopping = true;
            drop(state);
            self.core.wake.notify_all();
        }
        let worker = recover_lock(&self.maintenance).take();
        if let Some(worker) = worker {
            let _ = worker.join();
        }
        self.snapshot().iter().all(|entry| !entry.owner_retained)
    }

    #[cfg(test)]
    fn operation_reaped(&self, operation: &ReaperOperationId) -> bool {
        self.snapshot()
            .iter()
            .filter(|entry| entry.operation() == operation)
            .all(|entry| !entry.owner_retained())
    }
}

impl<C: ExactWriterCleanup + Send + 'static> Drop for CredentialWriterReaperRegistry<C> {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn recover_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
