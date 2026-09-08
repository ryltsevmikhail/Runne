use super::{Arc, RecoveryResources, RecoveryRunError};
use runne_platform_desktop::ConfirmedInstalledNativeEnrollment;

trait Preparation {
    type Output;
    fn revalidate(&self) -> Result<(), RecoveryRunError>;
    async fn renew(&mut self) -> Result<(), RecoveryRunError>;
    async fn confirm(&mut self) -> Result<(), RecoveryRunError>;
    async fn round(&mut self) -> Result<(), RecoveryRunError>;
    async fn transition(&mut self) -> Result<(), RecoveryRunError>;
    async fn register(&mut self) -> Result<(), RecoveryRunError>;
    fn finish(self) -> Result<Self::Output, RecoveryRunError>;
}

async fn prepare_first<P: Preparation>(mut preparation: P) -> Result<P::Output, RecoveryRunError> {
    preparation.revalidate()?;
    preparation.confirm().await?;
    preparation.transition().await?;
    preparation.register().await?;
    preparation.finish()
}

pub(super) async fn prepare_startup(
    resources: Arc<RecoveryResources>,
) -> Result<Arc<RecoveryResources>, RecoveryRunError> {
    Box::pin(prepare_first(NativePreparation {
        resources,
        confirmed: None,
    }))
    .await
}

async fn prepare<P: Preparation>(mut preparation: P) -> Result<P::Output, RecoveryRunError> {
    preparation.revalidate()?;
    preparation.renew().await?;
    preparation.confirm().await?;
    preparation.round().await?;
    preparation.register().await?;
    preparation.finish()
}

pub(super) async fn prepare_next(
    resources: Arc<RecoveryResources>,
) -> Result<Arc<RecoveryResources>, RecoveryRunError> {
    prepare(NativePreparation {
        resources,
        confirmed: None,
    })
    .await
}

struct NativePreparation {
    resources: Arc<RecoveryResources>,
    confirmed: Option<ConfirmedInstalledNativeEnrollment>,
}

impl Preparation for NativePreparation {
    type Output = Arc<RecoveryResources>;

    async fn transition(&mut self) -> Result<(), RecoveryRunError> {
        let confirmed = self
            .confirmed
            .take()
            .ok_or(RecoveryRunError::StaleInstalled)?;
        let confirmed = self
            .resources
            .runtime
            .transition_and_install(confirmed)
            .await
            .map_err(|_| RecoveryRunError::Transport)?;
        self.resources
            .updater
            .revalidate_confirmed(&confirmed)
            .map_err(|()| RecoveryRunError::StaleInstalled)?;
        self.confirmed = Some(confirmed);
        Ok(())
    }

    fn revalidate(&self) -> Result<(), RecoveryRunError> {
        if self
            .resources
            .runtime
            .writer_reaper_registry()
            .snapshot()
            .iter()
            .any(super::super::reaper_registry::CredentialWriterReaperSnapshot::owner_retained)
        {
            return Err(RecoveryRunError::ReapPending);
        }
        self.resources
            .updater
            .revalidate_confirmed(&self.resources.installed)
            .map_err(|()| RecoveryRunError::StaleInstalled)
    }

    async fn renew(&mut self) -> Result<(), RecoveryRunError> {
        self.resources
            .runtime
            .renew_and_install()
            .await
            .map_err(|_| RecoveryRunError::Transport)
    }

    async fn confirm(&mut self) -> Result<(), RecoveryRunError> {
        let updater = Arc::clone(&self.resources.updater);
        let prepared = tauri::async_runtime::spawn_blocking(move || updater.prepare_confirmation())
            .await
            .map_err(|_| RecoveryRunError::Transport)?
            .map_err(|()| RecoveryRunError::StaleInstalled)?;
        let confirmed = self
            .resources
            .runtime
            .confirm(prepared)
            .await
            .map_err(|_| RecoveryRunError::StaleInstalled)?;
        self.resources
            .updater
            .revalidate_confirmed(&confirmed)
            .map_err(|()| RecoveryRunError::StaleInstalled)?;
        self.confirmed = Some(confirmed);
        Ok(())
    }

    async fn round(&mut self) -> Result<(), RecoveryRunError> {
        runne_platform_desktop::ProtectedBundledRuntimeSupervisor::begin_next_protected_credential_round_with_rejoin(
            self.resources.runtime.supervisor_handle(),
        ).await.map_err(|_| RecoveryRunError::Transport)
    }

    async fn register(&mut self) -> Result<(), RecoveryRunError> {
        self.resources
            .runtime
            .register_credential_service_session(
                self.confirmed
                    .as_ref()
                    .ok_or(RecoveryRunError::StaleInstalled)?,
            )
            .await
            .map_err(|_| RecoveryRunError::Transport)
    }

    fn finish(self) -> Result<Self::Output, RecoveryRunError> {
        Ok(Arc::new(RecoveryResources {
            runtime: Arc::clone(&self.resources.runtime),
            updater: Arc::clone(&self.resources.updater),
            installed: self.confirmed.ok_or(RecoveryRunError::StaleInstalled)?,
        }))
    }
}

#[cfg(test)]
mod tests;
