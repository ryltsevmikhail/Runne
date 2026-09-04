use super::{
    PreparedProtectedCredentialRecovery, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeSupervisor, ProtectedCredentialRecoveryBootstrap, read_frame,
};
use crate::protected_runtime::PreparedCredentialServiceRejoin;
use crate::protected_runtime::control_response::{
    ControlSteps, NativeRegistration, RejoinRegistration, Response, run,
};
use runne_api::ProviderCredentialOperationSnapshotV2;
use std::sync::{Arc, Mutex};
#[cfg(all(test, feature = "test-support"))]
mod tests;

struct Terminal<R> {
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    recovery: Option<PreparedProtectedCredentialRecovery>,
    rejoin: Option<PreparedCredentialServiceRejoin>,
    registration: R,
}

fn validate(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    bootstrap: &ProtectedCredentialRecoveryBootstrap,
) -> Result<(), ProtectedBundledRuntimeError> {
    let process = supervisor.recovery_process()?;
    if process.graceful_requested || &process.recovery_bootstrap()? != bootstrap {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    Ok(())
}

impl<R: RejoinRegistration> ControlSteps for Terminal<R> {
    type Output = ProviderCredentialOperationSnapshotV2;

    async fn read(&mut self) -> Result<Response<Self::Output>, ProtectedBundledRuntimeError> {
        let mut recovery = self
            .recovery
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let handle = Arc::clone(&self.supervisor);
        let (recovery, rejoin, response) = tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&mut supervisor, &recovery.bootstrap)?;
            let process = supervisor.recovery_process()?;
            let frame = read_frame(&mut process.channel)?;
            let (rejoin, response) =
                if let Ok(snapshot) = recovery.codec.decode_daemon_terminal(&frame) {
                    process.record_enrollment_terminal()?;
                    (None, Response::Complete(snapshot))
                } else {
                    (
                        Some(supervisor.prepare_received_credential_service_rejoin(&frame)?),
                        Response::Rejoin,
                    )
                };
            drop(supervisor);
            Ok::<_, ProtectedBundledRuntimeError>((recovery, rejoin, response))
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
        self.recovery = Some(recovery);
        self.rejoin = rejoin;
        Ok(response)
    }

    async fn rejoin(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        let prepared = self
            .rejoin
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let registered = self.registration.register(prepared).await?;
        let bootstrap = self
            .recovery
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?
            .bootstrap
            .clone();
        let handle = Arc::clone(&self.supervisor);
        tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&mut supervisor, &bootstrap)?;
            supervisor.confirm_credential_service_rejoin(registered)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// Reads cleanup terminal evidence while servicing one authenticated service rejoin.
    /// Caller retains operation/updater leases and the non-cancellable writer cleanup owner.
    ///
    /// # Errors
    /// Rejects changed launch/broker state or invalid terminal/registration evidence.
    pub async fn finish_protected_credential_recovery_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
        recovery: PreparedProtectedCredentialRecovery,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProtectedBundledRuntimeError> {
        finish(supervisor, recovery, NativeRegistration).await
    }
}

async fn finish<R: RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    recovery: PreparedProtectedCredentialRecovery,
    registration: R,
) -> Result<ProviderCredentialOperationSnapshotV2, ProtectedBundledRuntimeError> {
    let bootstrap = recovery.bootstrap.clone();
    let result = run(Terminal {
        supervisor: Arc::clone(&supervisor),
        recovery: Some(recovery),
        rejoin: None,
        registration,
    })
    .await;
    if result.is_err() {
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut supervisor) = supervisor.lock()
                && let Some(process) = supervisor.process.as_mut()
                && process
                    .recovery_bootstrap()
                    .is_ok_and(|current| current == bootstrap)
            {
                process.fence_ambiguous_transition();
            }
        })
        .await;
    }
    result
}
