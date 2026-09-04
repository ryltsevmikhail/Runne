#![allow(
    clippy::significant_drop_tightening,
    reason = "tests assert lease retention across explicit cleanup and reap boundaries"
)]
use super::super::reaper_registry::CredentialWriterReaperRegistry;
use super::super::runner::RecoverableWriterHandoff;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn recovery_owner_completes_outer_cleanup_before_reporting_pre_handoff_error() {
    let directory = tempfile::tempdir().unwrap();
    let updater =
        crate::updater_status::enrollment::test_only_expired_enrollment_updater(directory.path())
            .await;
    let mut runtime = crate::bundled_runtime::test_only_live_enrollment_runtime(
        directory.path(),
        runne_platform_desktop::test_only_ready_v3_enrollment_supervisor(),
    )
    .await;
    let (lease, cleanup) = runtime.take_lease_with_cleanup();
    let result = super::owner::spawn_cleanup_owner(Arc::new(RecoveryResources {
        runtime: Arc::new(lease),
        updater: Arc::new(updater.lease),
        installed: updater.confirmed,
    }))
    .unwrap()
    .await
    .unwrap();
    assert!(matches!(result, Err(RecoveryRunError::StaleInstalled)));
    let cleaned = runtime.cleanup_completed();
    cleanup.abort().await;
    assert!(runtime.writer_reaper_registry().shutdown());
    assert!(
        cleaned,
        "owner returned before stopping/degrading the runtime"
    );
    assert!(runtime.operation_available());
}

struct PendingWriter(Arc<AtomicBool>);

impl RecoverableWriterHandoff for PendingWriter {
    type Error = runne_platform_desktop::ProtectedBundledRuntimeError;
    fn reap_exact_writer(&mut self) -> Result<(), Self::Error> {
        self.0
            .load(Ordering::SeqCst)
            .then_some(())
            .ok_or(Self::Error::ShutdownIncomplete)
    }
}

#[tokio::test]
async fn recovery_reaper_retains_operation_fence_until_exact_reap() {
    let directory = tempfile::tempdir().unwrap();
    let updater =
        crate::updater_status::enrollment::test_only_current_enrollment_updater(directory.path())
            .await;
    let mut runtime = crate::bundled_runtime::test_only_live_enrollment_runtime(
        directory.path(),
        runne_platform_desktop::test_only_ready_v3_enrollment_supervisor(),
    )
    .await;
    let (lease, cleanup) = runtime.take_lease_with_cleanup();
    let supervisor = lease.supervisor_handle();
    let resources = RecoveryResources {
        runtime: Arc::new(lease),
        updater: Arc::new(updater.lease),
        installed: updater.confirmed,
    };
    let registry =
        CredentialWriterReaperRegistry::start(std::time::Duration::from_hours(1)).unwrap();
    let operation = ReaperOperationId::new("recovery-retained-lease").unwrap();
    let reaped = Arc::new(AtomicBool::new(false));
    let retained = RetainedWriterCleanup::new(
        ProtectedWriterCleanup::with_recovery_resources(
            PendingWriter(Arc::clone(&reaped)),
            supervisor,
            Arc::new(resources),
        ),
        operation.clone(),
        Arc::clone(&registry),
    );
    assert!(!runtime.operation_available());
    assert!(retained.finish().is_err());
    assert!(!runtime.operation_available());
    assert!(registry.snapshot()[0].owner_retained());
    reaped.store(true, Ordering::SeqCst);
    assert!(registry.retry_after_outer_stop(&operation));
    assert!(runtime.operation_available());
    assert!(!registry.snapshot()[0].owner_retained());
    cleanup.abort().await;
    assert!(registry.shutdown());
    assert!(runtime.writer_reaper_registry().shutdown());
}

#[tokio::test]
async fn pair_reaper_retains_operation_fence_until_exact_reap() {
    let directory = tempfile::tempdir().unwrap();
    let updater =
        crate::updater_status::enrollment::test_only_current_enrollment_updater(directory.path())
            .await;
    let mut runtime = crate::bundled_runtime::test_only_live_enrollment_runtime(
        directory.path(),
        runne_platform_desktop::test_only_ready_v3_enrollment_supervisor(),
    )
    .await;
    let (lease, cleanup) = runtime.take_lease_with_cleanup();
    let supervisor = lease.supervisor_handle();
    let resources = RecoveryResources {
        runtime: Arc::new(lease),
        updater: Arc::new(updater.lease),
        installed: updater.confirmed,
    };
    let registry =
        CredentialWriterReaperRegistry::start(std::time::Duration::from_hours(1)).unwrap();
    let operation = ReaperOperationId::new("recovery-retained-lease").unwrap();
    let reaped = Arc::new(AtomicBool::new(false));
    let retained = RetainedWriterCleanup::new(
        super::super::runner::pair_cleanup(
            PendingWriter(Arc::clone(&reaped)),
            supervisor,
            Arc::new(resources),
        ),
        operation.clone(),
        Arc::clone(&registry),
    );
    assert!(!runtime.operation_available());
    assert!(retained.finish().is_err());
    assert!(!runtime.operation_available());
    assert!(registry.snapshot()[0].owner_retained());
    reaped.store(true, Ordering::SeqCst);
    assert!(registry.retry_after_outer_stop(&operation));
    assert!(runtime.operation_available());
    assert!(!registry.snapshot()[0].owner_retained());
    cleanup.abort().await;
    assert!(registry.shutdown());
    assert!(runtime.writer_reaper_registry().shutdown());
}

#[tokio::test]
async fn recovery_runner_revalidates_installed_tuple_before_recovery_request() {
    let directory = tempfile::tempdir().unwrap();
    let updater =
        crate::updater_status::enrollment::test_only_expired_enrollment_updater(directory.path())
            .await;
    let mut runtime = crate::bundled_runtime::test_only_live_enrollment_runtime(
        directory.path(),
        runne_platform_desktop::test_only_ready_v3_enrollment_supervisor(),
    )
    .await;
    let (lease, cleanup) = runtime.take_lease_with_cleanup();
    let resources = RecoveryResources {
        runtime: Arc::new(lease),
        updater: Arc::new(updater.lease),
        installed: updater.confirmed,
    };
    let result = run_recovery([9; 16], Arc::new(resources));
    assert!(matches!(result, Err(RecoveryRunError::StaleInstalled)));
    cleanup.abort().await;
    assert!(runtime.writer_reaper_registry().shutdown());
}
