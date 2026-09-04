use super::{
    BundledRuntimeLifecycleState, PreparedCredentialServiceRejoin, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeSupervisor, ProtectedProcessActivation,
    control_response::{ControlSteps, NativeRegistration, RejoinRegistration, Response, run},
    random_nonce, read_frame, write_frame,
};
use runne_api::{
    ProtectedCredentialEnrollmentRenewRequestV3, ProtectedCredentialEnrollmentRenewTicketV3,
};
use std::sync::{Arc, Mutex};

type Clock = Arc<dyn Fn() -> Result<u64, ProtectedBundledRuntimeError> + Send + Sync>;

struct Reader {
    request: ProtectedCredentialEnrollmentRenewRequestV3,
    rejoin: Option<PreparedCredentialServiceRejoin>,
}

struct NativeRenewal<R> {
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    reader: Option<Reader>,
    clock: Clock,
    registration: R,
}

fn validate(
    supervisor: &ProtectedBundledRuntimeSupervisor,
    renewal: &ProtectedCredentialEnrollmentRenewRequestV3,
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
        || process.renewal_sequence.checked_add(1) != Some(renewal.sequence())
        || !matches!(&process.activation, ProtectedProcessActivation::V3 { owned, .. } if owned == renewal.owned_launch())
    {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    Ok(())
}

impl<R: RejoinRegistration> ControlSteps for NativeRenewal<R> {
    type Output = ();

    async fn read(&mut self) -> Result<Response<()>, ProtectedBundledRuntimeError> {
        let mut reader = self
            .reader
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let handle = Arc::clone(&self.supervisor);
        let clock = Arc::clone(&self.clock);
        let (reader, response) = tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&supervisor, &reader.request)?;
            let process = supervisor
                .process
                .as_mut()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            let frame = read_frame(&mut process.channel)?;
            let response = if let Ok(ticket) =
                ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(&frame)
            {
                let now = clock()?;
                let ProtectedProcessActivation::V3 {
                    request,
                    ready,
                    owned,
                } = &mut process.activation
                else {
                    return Err(ProtectedBundledRuntimeError::InvalidState);
                };
                let profile = ProtectedBundledRuntimeProfile::from_renewal_v3(
                    ready,
                    request,
                    owned,
                    &reader.request,
                    &ticket,
                    now,
                    process.renewal_sequence,
                    &process.keys,
                )?;
                *owned = profile
                    .enrollment_owned_launch()
                    .cloned()
                    .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
                process.renewal_sequence = reader.request.sequence();
                supervisor.backoff.record_disconnected();
                supervisor.state = BundledRuntimeLifecycleState::Handshaking;
                supervisor.pending_profile = Some(profile);
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
        let reader = self
            .reader
            .take()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let handle = Arc::clone(&self.supervisor);
        let reader = tokio::task::spawn_blocking(move || {
            let mut supervisor = handle
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            validate(&supervisor, &reader.request)?;
            supervisor.confirm_credential_service_rejoin(registered)?;
            drop(supervisor);
            Ok::<_, ProtectedBundledRuntimeError>(reader)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
        self.reader = Some(reader);
        Ok(())
    }
}

async fn queue_with_clock(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    clock: impl Fn() -> Result<u64, ProtectedBundledRuntimeError> + Send + Sync + 'static,
) -> Result<(), ProtectedBundledRuntimeError> {
    queue_with_registration(supervisor, clock, NativeRegistration).await
}

pub(super) async fn queue_with_registration<R: RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    clock: impl Fn() -> Result<u64, ProtectedBundledRuntimeError> + Send + Sync + 'static,
    registration: R,
) -> Result<(), ProtectedBundledRuntimeError> {
    let handle = Arc::clone(&supervisor);
    let request = tokio::task::spawn_blocking(move || {
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
        let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
            supervisor.queue_renewal_profile()?;
            return Ok(None);
        };
        if process.graceful_requested {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let sequence = process
            .renewal_sequence
            .checked_add(1)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let nonce = random_nonce().ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let mut request =
            ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), sequence, nonce)?;
        request.sign(&process.keys);
        let frame = request
            .encode_frame()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        if let Err(error) = write_frame(&mut process.channel, &frame) {
            process.fence_ambiguous_v3_renewal();
            return Err(error);
        }
        drop(supervisor);
        Ok(Some(request))
    })
    .await
    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)??;
    let Some(request) = request else {
        return Ok(());
    };
    let owned = request.owned_launch().clone();
    let result = run(NativeRenewal {
        supervisor: Arc::clone(&supervisor),
        reader: Some(Reader {
            request,
            rejoin: None,
        }),
        clock: Arc::new(clock),
        registration,
    })
    .await;
    if result.is_err() {
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut supervisor) = supervisor.lock()
                && let Some(process) = supervisor.process.as_mut()
                && matches!(&process.activation, ProtectedProcessActivation::V3 { owned: current, .. } if current == &owned)
            { process.fence_ambiguous_v3_renewal(); }
        }).await;
    }
    result
}

impl ProtectedBundledRuntimeSupervisor {
    /// Queues renewal while servicing at most one authenticated V3 service rejoin.
    /// Caller retains its exclusive operation fence and cleanup ownership throughout.
    ///
    /// # Errors
    /// Rejects stale/expired tickets and fences an ambiguous exact launch.
    pub async fn queue_renewal_profile_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        queue_with_clock(supervisor, || {
            crate::MacOsContinuousClock::now_millis()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)
        })
        .await
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;
