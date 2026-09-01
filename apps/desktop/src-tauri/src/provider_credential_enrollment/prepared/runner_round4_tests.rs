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
