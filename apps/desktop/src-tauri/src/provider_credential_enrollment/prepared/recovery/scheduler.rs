use super::{Arc, RecoveryResources, RecoveryRunError};

trait CleanupSteps {
    async fn discover(&mut self) -> Result<Vec<[u8; 16]>, RecoveryRunError>;
    async fn recover(&mut self, operation: [u8; 16]) -> Result<(), RecoveryRunError>;
}

async fn drain<S: CleanupSteps>(steps: &mut S) -> Result<(), RecoveryRunError> {
    let mut completed = Vec::new();
    loop {
        let pending = steps.discover().await?;
        let Some(operation) = pending.first().copied() else {
            return Ok(());
        };
        if operation == [0; 16] {
            return Err(RecoveryRunError::InvalidOperation);
        }
        if completed.len() == 64 || completed.contains(&operation) {
            return Err(RecoveryRunError::NonCompleted);
        }
        steps.recover(operation).await?;
        completed.push(operation);
    }
}

pub(super) async fn run(resources: Arc<RecoveryResources>) -> Result<(), RecoveryRunError> {
    drain(&mut NativeCleanup { resources }).await
}

struct NativeCleanup {
    resources: Arc<RecoveryResources>,
}

impl CleanupSteps for NativeCleanup {
    async fn discover(&mut self) -> Result<Vec<[u8; 16]>, RecoveryRunError> {
        let resources = Arc::clone(&self.resources);
        tauri::async_runtime::spawn_blocking(move || {
            resources
                .updater
                .revalidate_confirmed(&resources.installed)
                .map_err(|()| RecoveryRunError::StaleInstalled)?;
            if resources
                .runtime
                .writer_reaper_registry()
                .snapshot()
                .iter()
                .any(super::super::reaper_registry::CredentialWriterReaperSnapshot::owner_retained)
            {
                return Err(RecoveryRunError::ReapPending);
            }
            Ok::<_, RecoveryRunError>(())
        })
        .await
        .map_err(|_| RecoveryRunError::Transport)??;
        runne_platform_desktop::ProtectedBundledRuntimeSupervisor::discover_prepared_credential_cleanup_with_rejoin(
            self.resources.runtime.supervisor_handle(),
        ).await.map_err(|_| RecoveryRunError::Transport)
    }

    async fn recover(&mut self, operation: [u8; 16]) -> Result<(), RecoveryRunError> {
        self.resources = super::preparation::prepare_next(Arc::clone(&self.resources)).await?;
        let resources = Arc::clone(&self.resources);
        tauri::async_runtime::spawn_blocking(move || super::run_recovery(operation, resources))
            .await
            .map_err(|_| RecoveryRunError::Transport)??;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
