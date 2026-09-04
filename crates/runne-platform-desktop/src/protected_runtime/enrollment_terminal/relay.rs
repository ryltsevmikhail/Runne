use super::{
    Arc, Mutex, PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeSupervisor, RejoinRegistration,
};

async fn receive<R: RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    enrollment: PreparedProtectedCredentialEnrollment,
    registration: R,
) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
    require_pending(&enrollment)?;
    let bootstrap = {
        let guard = supervisor
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let bootstrap = guard
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?
            .recovery_bootstrap()?;
        super::validate(&guard, &bootstrap)?;
        drop(guard);
        bootstrap
    };
    super::receive_phase(
        supervisor,
        enrollment,
        bootstrap,
        super::Stage::Relay,
        registration,
    )
    .await
}

const fn require_pending(
    enrollment: &PreparedProtectedCredentialEnrollment,
) -> Result<(), ProtectedBundledRuntimeError> {
    if enrollment.relay.is_some() || enrollment.relay_taken || enrollment.terminal {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    }
    Ok(())
}

pub(in crate::protected_runtime) fn accept(
    enrollment: &mut PreparedProtectedCredentialEnrollment,
    frame: &[u8],
) -> Result<(), ProtectedBundledRuntimeError> {
    require_pending(enrollment)?;
    let relay = enrollment
        .codec
        .decode_daemon_relay(frame, 1)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    enrollment.relay = Some(
        relay
            .try_into()
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?,
    );
    enrollment.relay_taken = false;
    Ok(())
}

impl ProtectedBundledRuntimeSupervisor {
    /// Receives a one-use Pair relay, servicing at most one authenticated rejoin.
    /// Caller must retain native leases and non-cancellable writer cleanup ownership.
    ///
    /// # Errors
    /// Rejects consumed relay, changed bootstrap, malformed relay or invalid service evidence.
    pub async fn receive_credential_secret_relay_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
        enrollment: PreparedProtectedCredentialEnrollment,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        receive(supervisor, enrollment, super::NativeRegistration).await
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
