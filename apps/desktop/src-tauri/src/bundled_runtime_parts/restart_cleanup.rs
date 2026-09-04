use super::{AppCoreError, RuntimeAvailability};

pub(super) async fn complete_monitor_restart<F: Future<Output = ()>>(
    availability: Result<RuntimeAvailability, AppCoreError>,
    operation: tokio::sync::OwnedMutexGuard<()>,
    cleanup: impl FnOnce() -> F,
) {
    // Cleanup acquires updater admission before reacquiring this runtime fence.
    // Never await it while holding the monitor's operation permit.
    drop(operation);
    if matches!(availability, Ok(RuntimeAvailability::Live)) {
        cleanup().await;
    }
}

#[cfg(test)]
#[allow(
    clippy::significant_drop_tightening,
    reason = "permit is moved into the tested handoff, which must release it"
)]
mod tests {
    use super::*;
    use crate::bundled_runtime::RuntimeOperationFence;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn restarted_client_runs_cleanup_after_releasing_monitor_fence() {
        let fence = RuntimeOperationFence::new();
        let permit = fence.enter().await.unwrap();
        let ran = AtomicBool::new(false);
        complete_monitor_restart(Ok(RuntimeAvailability::Live), permit, || async {
            let _permit = tokio::time::timeout(Duration::from_secs(1), fence.enter())
                .await
                .expect("monitor must release fence before cleanup")
                .unwrap();
            ran.store(true, Ordering::SeqCst);
        })
        .await;
        assert!(
            ran.load(Ordering::SeqCst),
            "successful restart must reconcile cleanup"
        );
    }

    #[tokio::test]
    async fn unsuccessful_restart_does_not_start_cleanup() {
        for availability in [
            Err(AppCoreError::RuntimeUnavailable),
            Ok(RuntimeAvailability::ResyncRequired),
        ] {
            let fence = RuntimeOperationFence::new();
            let permit = fence.enter().await.unwrap();
            complete_monitor_restart(availability, permit, || async {
                panic!("non-live client must not start cleanup");
            })
            .await;
            assert!(fence.enter().await.is_some());
        }
    }
}
