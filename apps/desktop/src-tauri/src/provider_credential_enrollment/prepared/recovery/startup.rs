use super::{Arc, RecoveryResources, RecoveryRunError};
use crate::bundled_runtime::NativeCredentialEnrollmentLease;
use crate::updater_status::enrollment::NativeInstalledEnrollmentLease;

trait StartupSteps {
    async fn discover(&mut self) -> Result<Option<Vec<[u8; 16]>>, RecoveryRunError>;
    async fn first(&mut self, operation: [u8; 16]) -> Result<(), RecoveryRunError>;
    async fn drain(&mut self) -> Result<(), RecoveryRunError>;
}

async fn run<S: StartupSteps>(steps: &mut S) -> Result<(), RecoveryRunError> {
    let Some(pending) = steps.discover().await? else {
        return Ok(());
    };
    let Some(operation) = pending.first().copied() else {
        return Ok(());
    };
    if operation == [0; 16] {
        return Err(RecoveryRunError::InvalidOperation);
    }
    steps.first(operation).await?;
    steps.drain().await
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "leases move to watcher cleanup and must outlive failed worker cleanup"
)]
pub(in crate::provider_credential_enrollment::prepared) async fn reconcile(
    lifecycle: &crate::RuntimeLifecycleManager,
    status_store: &crate::UpdateStatusStore,
) -> Result<(), ()> {
    if lifecycle.runtime_mode != runne_app_core::RuntimeMode::Bundled {
        return Ok(());
    }
    // Unsupported installations keep cleanup pending. Verification errors propagate.
    let Some(updater) = status_store.prepare_startup_native_enrollment().await? else {
        return Ok(());
    };
    let runtime = lifecycle
        .acquire_credential_enrollment_lease()
        .await
        .map_err(|_| ())?;
    let runtime = Arc::new(runtime);
    let updater = Arc::new(updater);
    let cleanup = runtime.cleanup_handle();
    let steps = NativeStartup {
        runtime: Arc::clone(&runtime),
        updater: Arc::clone(&updater),
        recovered: None,
    };
    let (result, _watcher) = crate::provider_credential_enrollment::dispatch::post_fence::spawn_pre_fence_enrollment_owner(
        move || async move { run(&mut { steps }).await },
        move || async move { cleanup.abort().await; drop((runtime, updater)); },
        || RecoveryRunError::Transport,
    ).map_err(|_| ())?;
    result.await.map_err(|_| ())?.map_err(|_| ())
}

struct NativeStartup {
    runtime: Arc<NativeCredentialEnrollmentLease>,
    updater: Arc<NativeInstalledEnrollmentLease>,
    recovered: Option<Arc<RecoveryResources>>,
}

impl StartupSteps for NativeStartup {
    async fn discover(&mut self) -> Result<Option<Vec<[u8; 16]>>, RecoveryRunError> {
        let runtime = Arc::clone(&self.runtime);
        tauri::async_runtime::spawn_blocking(move || {
            runtime
                .supervisor_handle()
                .lock()
                .map_err(|_| RecoveryRunError::Transport)?
                .discover_startup_credential_cleanup()
                .map_err(|_| RecoveryRunError::Transport)
        })
        .await
        .map_err(|_| RecoveryRunError::Transport)?
    }

    async fn first(&mut self, operation: [u8; 16]) -> Result<(), RecoveryRunError> {
        let updater = Arc::clone(&self.updater);
        let prepared = tauri::async_runtime::spawn_blocking(move || updater.prepare_confirmation())
            .await
            .map_err(|_| RecoveryRunError::Transport)?
            .map_err(|()| RecoveryRunError::StaleInstalled)?;
        let installed = self
            .runtime
            .confirm(prepared)
            .await
            .map_err(|_| RecoveryRunError::StaleInstalled)?;
        let resources = Arc::new(RecoveryResources {
            runtime: Arc::clone(&self.runtime),
            updater: Arc::clone(&self.updater),
            installed,
        });
        let resources = super::preparation::prepare_startup(resources).await?;
        let worker = Arc::clone(&resources);
        tauri::async_runtime::spawn_blocking(move || super::run_recovery(operation, worker))
            .await
            .map_err(|_| RecoveryRunError::Transport)??;
        self.recovered = Some(resources);
        Ok(())
    }

    async fn drain(&mut self) -> Result<(), RecoveryRunError> {
        super::scheduler::run(
            self.recovered
                .take()
                .ok_or(RecoveryRunError::NonCompleted)?,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
