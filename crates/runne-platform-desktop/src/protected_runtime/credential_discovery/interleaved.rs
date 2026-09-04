use super::super::{
    BundledRuntimeLifecycleState, PreparedCredentialServiceRejoin,
    ProtectedBundledRuntimeSupervisor,
};
use super::ProtectedBundledRuntimeError;
use runne_api::{ProtectedCredentialDiscoveryCodec, ProtectedCredentialEnrollmentOwnedLaunchV3};
use std::sync::{Arc, Mutex};

use super::super::control_response::{
    ControlSteps, NativeRegistration, RejoinRegistration, Response, run,
};

struct Reader {
    codec: ProtectedCredentialDiscoveryCodec,
    owned: ProtectedCredentialEnrollmentOwnedLaunchV3,
    rejoin: Option<PreparedCredentialServiceRejoin>,
}

struct NativeDiscovery<R> {
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    reader: Option<Reader>,
    registration: R,
}

fn validate(
    supervisor: &ProtectedBundledRuntimeSupervisor,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
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
    let (current, facts) = process.v3_enrollment_facts()?;
    if &current != owned
        || process.graceful_requested
        || facts.terminal_session != Some(*owned.session_id())
    {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    Ok(())
}

impl<R: RejoinRegistration> ControlSteps for NativeDiscovery<R> {
    type Output = Vec<[u8; 16]>;
    async fn read(&mut self) -> Result<Response<Self::Output>, ProtectedBundledRuntimeError> {
        let mut reader = self
            .reader
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let supervisor = Arc::clone(&self.supervisor);
        let (reader, response) = tokio::task::spawn_blocking(move || {
            let mut supervisor = supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&supervisor, &reader.owned)?;
            let process = supervisor
                .process
                .as_mut()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            let frame = super::read_frame(&mut process.channel)?;
            let response = if let Ok(ids) = reader.codec.decode_response(&frame) {
                Response::Complete(ids)
            } else {
                reader.rejoin =
                    Some(supervisor.prepare_received_credential_service_rejoin(&frame)?);
                Response::Rejoin
            };
            drop(supervisor);
            Ok::<_, ProtectedBundledRuntimeError>((reader, response))
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
        self.reader = Some(reader);
        Ok(response)
    }

    async fn rejoin(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        let reader = self
            .reader
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let prepared = reader
            .rejoin
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        // The blocking read released the supervisor mutex before this XPC await.
        let registered = self.registration.register(prepared).await?;
        let owned = reader.owned.clone();
        let supervisor = Arc::clone(&self.supervisor);
        tokio::task::spawn_blocking(move || {
            let mut supervisor = supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&supervisor, &owned)?;
            supervisor.confirm_credential_service_rejoin(registered)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// Reads terminal cleanup metadata, servicing at most one authenticated rejoin.
    /// The caller must retain the exclusive native operation/updater leases and
    /// a non-cancellable cleanup owner throughout this future.
    ///
    /// # Errors
    /// Rejects stale state or malformed/extra rejoin; fences the exact ambiguous launch.
    pub async fn discover_prepared_credential_cleanup_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
    ) -> Result<Vec<[u8; 16]>, ProtectedBundledRuntimeError> {
        discover(supervisor, NativeRegistration).await
    }
}

async fn discover<R: RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    registration: R,
) -> Result<Vec<[u8; 16]>, ProtectedBundledRuntimeError> {
    let handle = Arc::clone(&supervisor);
    let reader = tokio::task::spawn_blocking(move || {
        let mut supervisor = handle
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let owned = supervisor
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?
            .v3_enrollment_facts()?
            .0;
        validate(&supervisor, &owned)?;
        let process = supervisor
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let mut codec = ProtectedCredentialDiscoveryCodec::new(&process.keys, &owned);
        let nonce = super::random_nonce().ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let request = codec
            .encode_request(nonce)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        if let Err(error) = super::write_frame(&mut process.channel, &request) {
            process.fence_ambiguous_transition();
            return Err(error);
        }
        drop(supervisor);
        Ok(Reader {
            codec,
            owned,
            rejoin: None,
        })
    })
    .await
    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
    let owned = reader.owned.clone();
    let result = run(NativeDiscovery {
        supervisor: Arc::clone(&supervisor),
        reader: Some(reader),
        registration,
    })
    .await;
    if result.is_err() {
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut supervisor) = supervisor.lock()
                && let Some(process) = supervisor.process.as_mut()
                && process
                    .v3_enrollment_facts()
                    .is_ok_and(|(current, _)| current == owned)
            {
                process.fence_ambiguous_transition();
            }
        })
        .await;
    }
    result
}

#[cfg(feature = "test-support")]
mod test_support;
#[cfg(feature = "test-support")]
pub(in crate::protected_runtime) use test_support::{prepare, reap};
#[cfg(feature = "test-support")]
pub use test_support::{
    test_only_crossed_discovery, test_only_crossed_renewal, test_only_crossed_round,
};
