use super::control_response::{
    ControlSteps, NativeRegistration, RejoinRegistration, Response, run,
};
use super::{
    BundledRuntimeLifecycleState, BundledRuntimeStopDisposition, PreparedCredentialServiceRejoin,
    ProtectedBundledRuntimeError, ProtectedBundledRuntimeSupervisor, ProtectedProcessActivation,
    read_frame, write_frame,
};
use runne_api::{
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProtectedCredentialEnrollmentShutdownV3,
};
use std::sync::{Arc, Mutex};

async fn request<R: RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    owned: ProtectedCredentialEnrollmentOwnedLaunchV3,
    registration: R,
) -> Result<(), ProtectedBundledRuntimeError> {
    let handle = Arc::clone(&supervisor);
    let expected = owned.clone();
    tokio::task::spawn_blocking(move || {
        let mut supervisor = handle
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        validate(&supervisor, &expected)?;
        let process = supervisor
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(expected);
        shutdown.sign(&process.keys);
        let frame = shutdown
            .encode_frame()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        if let Err(error) = write_frame(&mut process.channel, &frame) {
            process.fence_ambiguous_transition();
            return Err(error);
        }
        drop(supervisor);
        Ok(())
    })
    .await
    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
    let result = run(Shutdown {
        supervisor: Arc::clone(&supervisor),
        owned: owned.clone(),
        rejoin: None,
        registration,
    })
    .await;
    if result.is_err() {
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut supervisor) = supervisor.lock()
                && let Some(process) = supervisor.process.as_mut()
                && matches!(&process.activation, ProtectedProcessActivation::V3 {owned: current, ..} if current == &owned) {
                    process.fence_ambiguous_transition();
                }
        }).await;
    }
    result
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
    if process.graceful_requested
        || !matches!(&process.activation, ProtectedProcessActivation::V3 {owned: current, ..} if current == owned)
    {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    Ok(())
}

struct Shutdown<R> {
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    owned: ProtectedCredentialEnrollmentOwnedLaunchV3,
    rejoin: Option<PreparedCredentialServiceRejoin>,
    registration: R,
}

impl<R: RejoinRegistration> ControlSteps for Shutdown<R> {
    type Output = ();
    async fn read(&mut self) -> Result<Response<()>, ProtectedBundledRuntimeError> {
        let handle = Arc::clone(&self.supervisor);
        let owned = self.owned.clone();
        let (rejoin, response) = tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&supervisor, &owned)?;
            let process = supervisor
                .process
                .as_mut()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            let frame = read_frame(&mut process.channel)?;
            let result = if process
                .activation
                .verify_v3_shutdown_ack(&frame, &process.keys)
                .is_ok_and(|graceful| graceful)
            {
                process.graceful_requested = true;
                process.graceful_acknowledged = true;
                (None, Response::Complete(()))
            } else {
                (
                    Some(supervisor.prepare_received_credential_service_rejoin(&frame)?),
                    Response::Rejoin,
                )
            };
            drop(supervisor);
            Ok::<_, ProtectedBundledRuntimeError>(result)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
        self.rejoin = rejoin;
        Ok(response)
    }
    async fn rejoin(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        let prepared = self
            .rejoin
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let registered = self.registration.register(prepared).await?;
        let handle = Arc::clone(&self.supervisor);
        let owned = self.owned.clone();
        tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
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
    /// Stops the exact owned runtime, servicing one V3 service rejoin before shutdown ACK.
    /// Caller must hold the exclusive shutdown operation fence throughout.
    ///
    /// # Errors
    /// Rejects changed ownership or an incomplete exact-child termination.
    pub async fn stop_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
    ) -> Result<BundledRuntimeStopDisposition, ProtectedBundledRuntimeError> {
        let owned = {
            let supervisor = supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            let owned = supervisor.process.as_ref().and_then(|process| {
                if supervisor.state == BundledRuntimeLifecycleState::Ready
                    && supervisor.pending_profile.is_none()
                    && !process.graceful_requested
                    && let ProtectedProcessActivation::V3 { owned, .. } = &process.activation
                {
                    return Some(owned.clone());
                }
                None
            });
            drop(supervisor);
            owned
        };
        if let Some(owned) = owned.as_ref() {
            let _ = request(Arc::clone(&supervisor), owned.clone(), NativeRegistration).await;
        }
        tokio::task::spawn_blocking(move || {
            let mut supervisor = supervisor.lock().map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            if let Some(expected) = owned {
                let process = supervisor.process.as_ref().ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
                if !matches!(&process.activation, ProtectedProcessActivation::V3 {owned, ..} if owned == &expected) {
                    return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
                }
            }
            supervisor.stop()
        }).await.map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;

/// Runs the production shutdown exchange with a protocol-only service port.
/// Does not invoke XPC, Keychain, or native writer effects.
///
/// # Errors
/// Rejects invalid registration or shutdown acknowledgement.
#[cfg(feature = "test-support")]
pub async fn test_only_crossed_shutdown(
    fixture: super::TestOnlyReadyV3EnrollmentSupervisor,
    channel: std::os::unix::net::UnixStream,
    tamper_ack: bool,
) -> Result<bool, ProtectedBundledRuntimeError> {
    let owned = fixture
        .owned_launch()
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    let (supervisor, registration) =
        super::credential_discovery::prepare(fixture, channel, tamper_ack)?;
    let result = request(Arc::clone(&supervisor), owned, registration).await;
    super::credential_discovery::reap(&supervisor);
    result?;
    let guard = supervisor
        .lock()
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    let acknowledged = guard
        .process
        .as_ref()
        .is_some_and(|process| process.graceful_acknowledged);
    drop(guard);
    Ok(acknowledged)
}
