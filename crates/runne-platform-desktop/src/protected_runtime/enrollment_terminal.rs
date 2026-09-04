use super::control_response::{
    ControlSteps, NativeRegistration, RejoinRegistration, Response, run,
};
use super::{
    BundledRuntimeLifecycleState, PreparedCredentialServiceRejoin,
    PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeSupervisor, read_frame,
    relay_ack_allowed, write_frame,
};
use runne_api::{ProtectedCredentialRecoveryBootstrap, ProviderCredentialOperationStateV2};
use std::sync::{Arc, Mutex};
mod control_only;
pub(super) mod relay;
#[cfg(feature = "test-support")]
mod test_support;
#[cfg(feature = "test-support")]
pub use test_support::test_only_pair_terminal;

pub(super) fn accept(
    process: &mut ProtectedBundledRuntimeProcess,
    enrollment: &mut PreparedProtectedCredentialEnrollment,
    frame: &[u8],
) -> Result<(), ProtectedBundledRuntimeError> {
    accept_after(process, enrollment, frame, 2)
}

fn accept_after(
    process: &mut ProtectedBundledRuntimeProcess,
    enrollment: &mut PreparedProtectedCredentialEnrollment,
    frame: &[u8],
    previous_sequence: u64,
) -> Result<(), ProtectedBundledRuntimeError> {
    let terminal = enrollment
        .codec
        .decode_daemon_snapshot(frame, previous_sequence)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    if !matches!(
        terminal.state(),
        ProviderCredentialOperationStateV2::Completed
            | ProviderCredentialOperationStateV2::Failed
            | ProviderCredentialOperationStateV2::Expired
            | ProviderCredentialOperationStateV2::Cancelled
            | ProviderCredentialOperationStateV2::Tombstoned
    ) {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    if terminal.operation_handle() != enrollment.snapshot.operation_handle()
        || terminal.operation_kind() != enrollment.snapshot.operation_kind()
        || terminal.provider_id() != enrollment.snapshot.provider_id()
    {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    process.record_enrollment_terminal()?;
    enrollment.snapshot = terminal;
    enrollment.relay = None;
    enrollment.relay_taken = true;
    enrollment.terminal = true;
    Ok(())
}

async fn finish<R: RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    enrollment: PreparedProtectedCredentialEnrollment,
    relay: &[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES],
    registration: R,
) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
    let handle = Arc::clone(&supervisor);
    let relay = Box::new(*relay);
    let (enrollment, bootstrap) = tokio::task::spawn_blocking(move || {
        let mut supervisor = handle
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let bootstrap = supervisor
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?
            .recovery_bootstrap()?;
        validate(&supervisor, &bootstrap)?;
        if !relay_ack_allowed(
            enrollment.relay_taken,
            enrollment.terminal,
            enrollment.relay.as_ref(),
            relay.as_ref(),
        ) {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let ack = enrollment
            .codec
            .encode_desktop_relay_ack(relay.as_ref(), 2)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let process = supervisor
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        if let Err(error) = write_frame(&mut process.channel, &ack) {
            process.fence_ambiguous_transition();
            return Err(error);
        }
        drop(supervisor);
        Ok((enrollment, bootstrap))
    })
    .await
    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
    receive_phase(
        supervisor,
        enrollment,
        bootstrap,
        Stage::Terminal,
        registration,
    )
    .await
}

#[derive(Clone, Copy)]
enum Stage {
    Relay,
    Terminal,
    ControlOnlyTerminal,
}

async fn receive_phase<R: RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    enrollment: PreparedProtectedCredentialEnrollment,
    bootstrap: ProtectedCredentialRecoveryBootstrap,
    stage: Stage,
    registration: R,
) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
    let result = run(Terminal {
        supervisor: Arc::clone(&supervisor),
        enrollment: Some(enrollment),
        bootstrap: bootstrap.clone(),
        rejoin: None,
        registration,
        stage,
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

fn validate(
    supervisor: &ProtectedBundledRuntimeSupervisor,
    bootstrap: &ProtectedCredentialRecoveryBootstrap,
) -> Result<(), ProtectedBundledRuntimeError> {
    if supervisor.state != BundledRuntimeLifecycleState::Ready
        || supervisor.pending_profile.is_some()
    {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    }
    let process = supervisor
        .process
        .as_ref()
        .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
    if process.graceful_requested || &process.recovery_bootstrap()? != bootstrap {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    Ok(())
}

struct Terminal<R> {
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    enrollment: Option<PreparedProtectedCredentialEnrollment>,
    bootstrap: ProtectedCredentialRecoveryBootstrap,
    rejoin: Option<PreparedCredentialServiceRejoin>,
    registration: R,
    stage: Stage,
}

impl<R: RejoinRegistration> ControlSteps for Terminal<R> {
    type Output = PreparedProtectedCredentialEnrollment;
    async fn read(&mut self) -> Result<Response<Self::Output>, ProtectedBundledRuntimeError> {
        let mut enrollment = self
            .enrollment
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let bootstrap = self.bootstrap.clone();
        let stage = self.stage;
        let handle = Arc::clone(&self.supervisor);
        let (retained, rejoin, response) = tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&supervisor, &bootstrap)?;
            let process = supervisor
                .process
                .as_mut()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            let frame = read_frame(&mut process.channel)?;
            let accepted = match stage {
                Stage::Relay => relay::accept(&mut enrollment, &frame),
                Stage::Terminal => accept(process, &mut enrollment, &frame),
                Stage::ControlOnlyTerminal => accept_after(process, &mut enrollment, &frame, 1),
            };
            let outcome = if accepted.is_ok() {
                (None, None, Response::Complete(enrollment))
            } else {
                let rejoin = supervisor.prepare_received_credential_service_rejoin(&frame)?;
                (Some(enrollment), Some(rejoin), Response::Rejoin)
            };
            drop(supervisor);
            Ok::<_, ProtectedBundledRuntimeError>(outcome)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
        self.enrollment = retained;
        self.rejoin = rejoin;
        Ok(response)
    }
    async fn rejoin(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        let prepared = self
            .rejoin
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let registered = self.registration.register(prepared).await?;
        let bootstrap = self.bootstrap.clone();
        let handle = Arc::clone(&self.supervisor);
        tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&supervisor, &bootstrap)?;
            supervisor.confirm_credential_service_rejoin(registered)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// Sends one relay acknowledgement, then receives terminal evidence with bounded rejoin.
    /// Caller must retain native leases and non-cancellable writer cleanup ownership.
    ///
    /// # Errors
    /// Rejects unconsumed relay, changed launch, invalid terminal or registration evidence.
    pub async fn finish_protected_credential_enrollment_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
        enrollment: PreparedProtectedCredentialEnrollment,
        relay: &[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES],
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        finish(supervisor, enrollment, relay, NativeRegistration).await
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
