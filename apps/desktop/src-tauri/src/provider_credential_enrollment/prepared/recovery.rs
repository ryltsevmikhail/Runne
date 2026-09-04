use super::reap_guard::RetainedWriterCleanup;
use super::reaper_registry::ReaperOperationId;
use super::runner::{ProtectedWriterCleanup, terminal_is_success};
use crate::bundled_runtime::NativeCredentialEnrollmentLease;
use crate::updater_status::enrollment::NativeInstalledEnrollmentLease;
use runne_api::ProviderCredentialOperationSnapshotV2;
use runne_platform_desktop::{ConfirmedInstalledNativeEnrollment, CredentialWriterHandoffMode};
use std::sync::Arc;
mod owner;
mod preparation;
mod scheduler;
pub(super) mod startup;

/// Retained until exact writer reap, including deferred reap after an error.
pub(in crate::provider_credential_enrollment) struct RecoveryResources {
    pub(super) runtime: Arc<NativeCredentialEnrollmentLease>,
    pub(super) updater: Arc<NativeInstalledEnrollmentLease>,
    pub(super) installed: ConfirmedInstalledNativeEnrollment,
}

impl RecoveryResources {
    /// Continues inside the Pair owner; receiver cancellation cannot cancel cleanup.
    pub(in crate::provider_credential_enrollment) async fn finish_cleanup(
        self: Arc<Self>,
    ) -> Result<(), super::PreparedCredentialEnrollmentError> {
        owner::spawn_cleanup_owner(self)
            .map_err(|_| super::PreparedCredentialEnrollmentError)?
            .await
            .map_err(|_| super::PreparedCredentialEnrollmentError)?
            .map_err(|_| super::PreparedCredentialEnrollmentError)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RecoveryRunError {
    InvalidOperation,
    StaleInstalled,
    Transport,
    NonCompleted,
    ReapPending,
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "leases move into the reap owner and must outlive terminal exchange"
)]
pub(super) fn run_recovery(
    operation: [u8; 16],
    resources: Arc<RecoveryResources>,
) -> Result<ProviderCredentialOperationSnapshotV2, RecoveryRunError> {
    if operation == [0; 16] {
        return Err(RecoveryRunError::InvalidOperation);
    }
    resources
        .updater
        .revalidate_confirmed(&resources.installed)
        .map_err(|()| RecoveryRunError::StaleInstalled)?;
    let reaper_operation = ReaperOperationId::new(&format!("recovery-{}", uuid::Uuid::now_v7()))
        .ok_or(RecoveryRunError::InvalidOperation)?;
    let supervisor = resources.runtime.supervisor_handle();
    let reapers = resources.runtime.writer_reaper_registry();
    let recovery = supervisor
        .lock()
        .map_err(|_| RecoveryRunError::Transport)?
        .begin_protected_credential_recovery(operation)
        .map_err(|_| RecoveryRunError::Transport)?;
    let handoff = tauri::async_runtime::block_on(
        runne_platform_desktop::ProtectedBundledRuntimeSupervisor::run_credential_writer_handoff_with_rejoin(
            Arc::clone(&supervisor),
            &resources.installed,
            CredentialWriterHandoffMode::ControlOnly,
        ),
    )
        .map_err(|error| {
            if let (_, Some(handoff)) = error.into_parts() {
                reapers.retain_after_initial_failure(
                    reaper_operation.clone(),
                    ProtectedWriterCleanup::with_recovery_resources(
                        handoff,
                        Arc::clone(&supervisor),
                        Arc::clone(&resources),
                    ),
                );
            }
            RecoveryRunError::Transport
        })?;
    let retained = RetainedWriterCleanup::new(
        ProtectedWriterCleanup::with_recovery_resources(
            handoff,
            Arc::clone(&supervisor),
            resources,
        ),
        reaper_operation,
        reapers,
    );
    let result = tauri::async_runtime::block_on(
        runne_platform_desktop::ProtectedBundledRuntimeSupervisor::finish_protected_credential_recovery_with_rejoin(
            Arc::clone(&supervisor), recovery,
        ),
    )
        .map_err(|_| RecoveryRunError::Transport)
        .and_then(|snapshot| {
            if terminal_is_success(snapshot.state()) {
                Ok(snapshot)
            } else {
                Err(RecoveryRunError::NonCompleted)
            }
        });
    let reaped = if result.is_ok() {
        retained.finish()
    } else {
        retained.abort()
    };
    reaped.map_err(|_| RecoveryRunError::ReapPending)?;
    result
}

#[cfg(test)]
mod tests;
