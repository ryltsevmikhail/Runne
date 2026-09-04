use super::super::{
    PreparedCredentialServiceRejoin,
    control_response::{ControlSteps, NativeRegistration, RejoinRegistration, Response, run},
};
use super::{
    BundledRuntimeLifecycleState, EnrollmentBrokerFacts, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeSupervisor, ProtectedCredentialEnrollmentOwnedLaunchV3,
    ProtectedProcessActivation, random_nonce, read_frame, write_frame,
};
use runne_api::ProtectedCredentialRoundCodec;
use std::sync::{Arc, Mutex};

struct Reader {
    codec: ProtectedCredentialRoundCodec,
    owned: ProtectedCredentialEnrollmentOwnedLaunchV3,
    rejoin: Option<PreparedCredentialServiceRejoin>,
}

struct NativeRound<R> {
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
    if process.graceful_requested
        || process.enrollment_broker_facts.is_some()
        || !matches!(&process.activation, ProtectedProcessActivation::V3 { owned: current, .. } if current == owned)
    {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    Ok(())
}

impl<R: RejoinRegistration> ControlSteps for NativeRound<R> {
    type Output = ();

    async fn read(&mut self) -> Result<Response<()>, ProtectedBundledRuntimeError> {
        let mut reader = self
            .reader
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let handle = Arc::clone(&self.supervisor);
        let (reader, response) = tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&supervisor, &reader.owned)?;
            let process = supervisor
                .process
                .as_mut()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            let frame = read_frame(&mut process.channel)?;
            let response = if let Ok(facts) = reader.codec.decode_offer(&frame) {
                let accept = reader
                    .codec
                    .encode_accept()
                    .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
                write_frame(&mut process.channel, &accept)?;
                process.enrollment_broker_facts = Some(EnrollmentBrokerFacts::new(
                    facts.channel_binding(),
                    facts.publication_key(),
                ));
                supervisor.credential_service_rejoin = None;
                Response::Complete(())
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
        let registered = self.registration.register(prepared).await?;
        let owned = reader.owned.clone();
        let handle = Arc::clone(&self.supervisor);
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
    /// Opens the next round after renewal, servicing at most one authenticated rejoin.
    /// Caller retains native runtime/updater leases and a non-cancellable cleanup owner.
    /// Service registration must follow before enrollment/recovery starts.
    ///
    /// # Errors
    /// Rejects stale or unrenewed sessions and fences an ambiguous exact launch.
    pub async fn begin_next_protected_credential_round_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        begin(supervisor, NativeRegistration).await
    }
}

pub(in crate::protected_runtime) async fn begin<R: RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    registration: R,
) -> Result<(), ProtectedBundledRuntimeError> {
    let handle = Arc::clone(&supervisor);
    let reader = tokio::task::spawn_blocking(move || {
        let mut supervisor = handle
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        if supervisor.state != BundledRuntimeLifecycleState::Ready
            || supervisor.pending_profile.is_some()
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = supervisor
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let (owned, facts) = process.v3_enrollment_facts()?;
        if process.graceful_requested
            || facts.terminal_session.is_none()
            || facts.terminal_session == Some(*owned.session_id())
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let mut codec = ProtectedCredentialRoundCodec::new(&process.keys, &owned);
        let nonce = random_nonce().ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let request = codec
            .encode_request(nonce)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        process.enrollment_broker_facts = None;
        if let Err(error) = write_frame(&mut process.channel, &request) {
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
    let result = run(NativeRound {
        supervisor: Arc::clone(&supervisor),
        reader: Some(reader),
        registration,
    })
    .await;
    if result.is_err() {
        let _ = tokio::task::spawn_blocking(move || {
                if let Ok(mut supervisor) = supervisor.lock()
                    && let Some(process) = supervisor.process.as_mut()
                    && matches!(&process.activation, ProtectedProcessActivation::V3 { owned: current, .. } if current == &owned)
                {
                    process.fence_ambiguous_transition();
                }
            }).await;
    }
    result
}
