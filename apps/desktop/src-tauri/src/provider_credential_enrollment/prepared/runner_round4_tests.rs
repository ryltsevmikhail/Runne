use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use super::{ProtectedWriterCleanup, RecoverableWriterHandoff};
use crate::bundled_runtime::test_only_live_enrollment_runtime;
use crate::provider_credential_enrollment::prepared::reap_guard::RetainedWriterCleanup;
use crate::provider_credential_enrollment::prepared::reaper_registry::{
    CredentialWriterReaperRegistry, ReaperOperationId,
};
use runne_platform_desktop::ProtectedBundledRuntimeError;

#[tokio::test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "retained owners deliberately span outer stop and reap"
)]
async fn poisoned_supervisor_retains_post_ack_reap_until_outer_stop() {
    let directory = tempfile::tempdir().expect("runtime directory");
    let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
    let daemon_pid = fixture.owned_process_id().expect("owned daemon pid");
    let mut runtime = test_only_live_enrollment_runtime(directory.path(), fixture).await;
    let (lease, cleanup) = runtime.take_lease_with_cleanup();
    let supervisor = runtime.supervisor_handle();
    poison(&supervisor);

    let reaped = Arc::new(AtomicUsize::new(0));
    let reap_attempts = Arc::new(AtomicUsize::new(0));
    let handoff =
        DaemonLifetimeWriter::spawn(daemon_pid, Arc::clone(&reaped), Arc::clone(&reap_attempts));
    let recovery = CredentialWriterReaperRegistry::start(Duration::from_millis(20)).unwrap();
    let operation = ReaperOperationId::new("poisoned-supervisor").unwrap();
    let retained = RetainedWriterCleanup::new(
        ProtectedWriterCleanup::new(handoff, lease.supervisor_handle()),
        operation.clone(),
        Arc::clone(&recovery),
    );

    assert!(retained.abort().is_err(), "abort error remains fail-closed");
    assert_eq!(reap_attempts.load(Ordering::SeqCst), 1);
    assert!(
        recovery.snapshot()[0].owner_retained(),
        "timed-out reap owner must be retained"
    );

    cleanup.abort().await;
    assert!(
        recovery.retry_after_outer_stop(&operation),
        "retry after outer stop must reap"
    );
    assert!(!recovery.snapshot()[0].owner_retained());
    assert_eq!(reaped.load(Ordering::SeqCst), 1);
    assert_eq!(reap_attempts.load(Ordering::SeqCst), 2);
    assert!(runtime.cleanup_completed());
    assert!(recovery.shutdown());
    drop(runtime);
}

#[tokio::test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "registry handles remain retained through explicit cleanup"
)]
async fn production_runtime_lease_and_cleanup_share_the_managed_reaper_registry() {
    let directory = tempfile::tempdir().expect("runtime directory");
    let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
    let mut runtime = test_only_live_enrollment_runtime(directory.path(), fixture).await;
    let runtime_reapers = runtime.writer_reaper_registry();
    let (lease, cleanup) = runtime.take_lease_with_cleanup();
    let lease_reapers = lease.writer_reaper_registry();
    let cleanup_reapers = cleanup.writer_reaper_registry();

    assert!(Arc::ptr_eq(&runtime_reapers, &lease_reapers));
    assert!(Arc::ptr_eq(&runtime_reapers, &cleanup_reapers));
    assert!(runtime.writer_reaper_snapshot().is_empty());
    cleanup.abort().await;
    assert!(runtime_reapers.shutdown());
    drop(lease);
    drop(runtime);
}

fn poison(supervisor: &Arc<Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>>) {
    let owned = Arc::clone(supervisor);
    let panic = std::panic::catch_unwind(move || {
        let _guard = owned.lock().expect("production supervisor lock");
        panic!("deliberately poison production supervisor mutex");
    });
    assert!(panic.is_err());
    assert!(supervisor.is_poisoned());
}

#[tokio::test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "runtime and reaper ownership intentionally spans child cleanup"
)]
async fn failed_platform_handoff_blocks_next_writer_until_registry_reaps_child() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
    let mut runtime = test_only_live_enrollment_runtime(directory.path(), fixture).await;
    let (lease, cleanup) = runtime.take_lease_with_cleanup();
    let reapers = lease.writer_reaper_registry();
    let operation = ReaperOperationId::new("failed-platform-handoff").unwrap();
    let (mut child, error) = runne_platform_desktop::test_only_failed_writer_handoff();
    super::retain_failed_handoff(error, &operation, &reapers, |handoff| {
        ProtectedWriterCleanup::new(handoff, lease.supervisor_handle())
    });
    let retained = reapers.snapshot();
    let accepts_before_reap = reapers.accepts_writer();
    // Clean up the real child even if the retention assertion below detects a mutation.
    child.kill().unwrap();
    let reaped = reapers.retry_after_outer_stop(&operation);
    let wait = child.wait();
    let accepts_after_reap = reapers.accepts_writer();
    cleanup.abort().await;
    assert!(reapers.shutdown());
    assert_eq!(retained.len(), 1, "failed handoff must remain addressable");
    assert!(retained[0].owner_retained());
    assert!(
        !accepts_before_reap,
        "unreaped owner fences the next writer"
    );
    assert!(reaped);
    assert!(
        wait.is_err(),
        "registry, not Child, must consume the wait status"
    );
    assert!(accepts_after_reap);
}

struct DaemonLifetimeWriter {
    child: std::process::Child,
    reaped: Arc<AtomicUsize>,
    attempts: Arc<AtomicUsize>,
}

impl DaemonLifetimeWriter {
    fn spawn(daemon_pid: u32, reaped: Arc<AtomicUsize>, attempts: Arc<AtomicUsize>) -> Self {
        let script = format!("while kill -0 {daemon_pid} 2>/dev/null; do sleep 0.01; done");
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .spawn()
            .expect("writer lifetime child");
        Self {
            child,
            reaped,
            attempts,
        }
    }
}

impl RecoverableWriterHandoff for DaemonLifetimeWriter {
    type Error = ProtectedBundledRuntimeError;

    fn reap_exact_writer(&mut self) -> Result<(), Self::Error> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if self
                .child
                .try_wait()
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?
                .is_some()
            {
                self.reaped.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ProtectedBundledRuntimeError::ShutdownIncomplete);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for DaemonLifetimeWriter {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
