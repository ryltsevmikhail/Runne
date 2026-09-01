use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use super::reap_guard::{ExactWriterCleanup, RetainedWriterCleanup};
use super::reaper_registry::{
    CredentialWriterReaperLastError, CredentialWriterReaperRegistry, CredentialWriterReaperState,
    ReaperOperationId,
};
use runne_platform_desktop::ProtectedBundledRuntimeError;

#[test]
fn live_exact_child_is_pending_then_archived_reaped_by_bounded_maintenance() {
    let child = Arc::new(Mutex::new(
        std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("child"),
    ));
    let registry =
        CredentialWriterReaperRegistry::start(Duration::from_millis(20)).expect("registry worker");
    let operation = ReaperOperationId::new("live-child").expect("operation");
    let retained = RetainedWriterCleanup::new(
        TimedChildReap::new(Arc::clone(&child)),
        operation.clone(),
        Arc::clone(&registry),
    );

    let started = Instant::now();
    assert!(retained.finish().is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_pending_owner(&registry, &operation);
    assert!(!registry.retry_after_outer_stop(&operation));
    let snapshot = registry.snapshot();
    assert_eq!(snapshot[0].state(), CredentialWriterReaperState::Failed);
    assert_eq!(
        snapshot[0].last_error(),
        Some(CredentialWriterReaperLastError::OuterRetry)
    );
    assert!(snapshot[0].owner_retained());

    child.lock().expect("child").kill().expect("kill child");
    wait_for_state(&registry, &operation, CredentialWriterReaperState::Reaped);
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert!(!snapshot[0].owner_retained());
    assert!(registry.shutdown());
}

#[test]
fn persistent_wait_error_is_observable_without_spinning_or_dropping_owner() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let registry =
        CredentialWriterReaperRegistry::start(Duration::from_millis(30)).expect("registry worker");
    let operation = ReaperOperationId::new("persistent-error").expect("operation");
    let retained = RetainedWriterCleanup::new(
        PersistentError::new(Arc::clone(&attempts), Arc::clone(&dropped)),
        operation.clone(),
        Arc::clone(&registry),
    );

    assert!(retained.finish().is_err());
    assert!(!registry.retry_after_outer_stop(&operation));
    std::thread::sleep(Duration::from_millis(125));
    let snapshot = registry.snapshot();
    assert_eq!(snapshot[0].state(), CredentialWriterReaperState::Failed);
    assert!(snapshot[0].owner_retained());
    assert!(snapshot[0].last_error().is_some());
    assert!(attempts.load(Ordering::SeqCst) <= 8, "bounded cadence");
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(registry.maintenance_is_owned());

    assert!(!registry.shutdown());
    assert!(!registry.maintenance_is_owned());
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(registry);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn shutdown_joins_within_bound_and_preserves_failed_owner_through_teardown() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let registry =
        CredentialWriterReaperRegistry::start(Duration::from_secs(10)).expect("registry worker");
    let operation = ReaperOperationId::new("shutdown-pending").expect("operation");
    let retained = RetainedWriterCleanup::new(
        SlowPersistentError::new(Arc::clone(&dropped)),
        operation.clone(),
        Arc::clone(&registry),
    );
    assert!(retained.finish().is_err());

    let started = Instant::now();
    assert!(!registry.shutdown());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_pending_or_failed_owner(&registry, &operation);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(registry);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn already_exited_writer_reaps_directly_and_registry_stays_empty() {
    let registry =
        CredentialWriterReaperRegistry::start(Duration::from_millis(20)).expect("registry worker");
    let operation = ReaperOperationId::new("already-exited").expect("operation");
    let retained = RetainedWriterCleanup::new(AlreadyReaped, operation, Arc::clone(&registry));

    retained.finish().expect("direct reap");
    assert!(registry.snapshot().is_empty());
    assert!(registry.shutdown());
}

fn assert_pending_owner<C: ExactWriterCleanup + Send + 'static>(
    registry: &CredentialWriterReaperRegistry<C>,
    operation: &ReaperOperationId,
) {
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].operation(), operation);
    assert_eq!(snapshot[0].state(), CredentialWriterReaperState::Pending);
    assert!(snapshot[0].owner_retained());
}

fn assert_pending_or_failed_owner<C: ExactWriterCleanup + Send + 'static>(
    registry: &CredentialWriterReaperRegistry<C>,
    operation: &ReaperOperationId,
) {
    let snapshot = registry.snapshot();
    assert_eq!(snapshot[0].operation(), operation);
    assert!(matches!(
        snapshot[0].state(),
        CredentialWriterReaperState::Pending | CredentialWriterReaperState::Failed
    ));
    assert!(snapshot[0].owner_retained());
}

fn wait_for_state<C: ExactWriterCleanup + Send + 'static>(
    registry: &CredentialWriterReaperRegistry<C>,
    operation: &ReaperOperationId,
    state: CredentialWriterReaperState,
) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if registry
            .snapshot()
            .iter()
            .any(|value| value.operation() == operation && value.state() == state)
        {
            return;
        }
        assert!(Instant::now() < deadline, "registry state timeout");
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct TimedChildReap {
    child: Arc<Mutex<std::process::Child>>,
}

impl TimedChildReap {
    const fn new(child: Arc<Mutex<std::process::Child>>) -> Self {
        Self { child }
    }

    fn wait(&self, timeout: Duration) -> Result<(), ProtectedBundledRuntimeError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self
                .child
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?
                .try_wait()
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?
                .is_some()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl ExactWriterCleanup for TimedChildReap {
    type Error = ProtectedBundledRuntimeError;

    fn finish_exact(&mut self) -> Result<(), Self::Error> {
        self.wait(Duration::from_millis(20))
    }

    fn abort_exact(&mut self) -> Result<(), Self::Error> {
        self.finish_exact()
    }

    fn maintain_exact(&mut self) -> Result<(), Self::Error> {
        self.wait(Duration::from_millis(10))
    }
}

struct PersistentError {
    attempts: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl PersistentError {
    const fn new(attempts: Arc<AtomicUsize>, dropped: Arc<AtomicUsize>) -> Self {
        Self { attempts, dropped }
    }
}

impl ExactWriterCleanup for PersistentError {
    type Error = ProtectedBundledRuntimeError;

    fn finish_exact(&mut self) -> Result<(), Self::Error> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(ProtectedBundledRuntimeError::ShutdownIncomplete)
    }

    fn abort_exact(&mut self) -> Result<(), Self::Error> {
        self.finish_exact()
    }
}

impl Drop for PersistentError {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

struct SlowPersistentError {
    dropped: Arc<AtomicUsize>,
}

impl SlowPersistentError {
    const fn new(dropped: Arc<AtomicUsize>) -> Self {
        Self { dropped }
    }
}

impl ExactWriterCleanup for SlowPersistentError {
    type Error = ProtectedBundledRuntimeError;

    fn finish_exact(&mut self) -> Result<(), Self::Error> {
        std::thread::sleep(Duration::from_millis(30));
        Err(ProtectedBundledRuntimeError::ShutdownIncomplete)
    }

    fn abort_exact(&mut self) -> Result<(), Self::Error> {
        self.finish_exact()
    }
}

impl Drop for SlowPersistentError {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

struct AlreadyReaped;

impl ExactWriterCleanup for AlreadyReaped {
    type Error = ProtectedBundledRuntimeError;

    fn finish_exact(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn abort_exact(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
