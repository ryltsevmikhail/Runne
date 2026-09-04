use super::{Arc, RecoveryResources, RecoveryRunError};

pub(super) fn spawn_cleanup_owner(
    resources: Arc<RecoveryResources>,
) -> Result<tokio::sync::oneshot::Receiver<Result<(), RecoveryRunError>>, RecoveryRunError> {
    let cleanup = resources.runtime.cleanup_handle();
    let worker_resources = Arc::clone(&resources);
    let (result, _watcher) = crate::provider_credential_enrollment::dispatch::post_fence::spawn_pre_fence_enrollment_owner(
        move || super::scheduler::run(worker_resources),
        move || async move {
            cleanup.abort().await;
            drop(resources);
        },
        || RecoveryRunError::Transport,
    )?;
    Ok(result)
}
