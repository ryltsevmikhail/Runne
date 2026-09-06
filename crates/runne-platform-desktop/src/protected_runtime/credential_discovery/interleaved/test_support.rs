//! Explicit protocol-only harness. Never connects XPC or accesses Keychain.
use super::{
    Arc, Mutex, PreparedCredentialServiceRejoin, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeSupervisor, ProtectedCredentialEnrollmentOwnedLaunchV3,
    RejoinRegistration, discover,
};
use crate::protected_runtime::{
    EnrollmentBrokerFacts, RegisteredCredentialServiceSession, TestOnlyReadyV3EnrollmentSupervisor,
    credential_service_session::{test_rejoin_context, unix_millis},
};
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceDesktopPort, CredentialServiceDesktopReply,
    CredentialServiceDesktopRequest, CredentialServicePortError, CredentialServicePortFuture,
};
use runne_provider::{
    CredentialServiceEpoch, CredentialServiceIngressRequest, CredentialServiceProtocolCodec,
    CredentialServiceReply, CredentialServiceRequest,
};

struct WireService {
    supervisor: std::sync::Weak<Mutex<ProtectedBundledRuntimeSupervisor>>,
    owned: ProtectedCredentialEnrollmentOwnedLaunchV3,
    tamper: bool,
    parent_expiry: u64,
}

impl WireService {
    fn require_unlocked(&self) -> Result<(), CredentialServicePortError> {
        let supervisor = self
            .supervisor
            .upgrade()
            .ok_or(CredentialServicePortError::Rejected)?;
        let _guard = supervisor
            .try_lock()
            .map_err(|_| CredentialServicePortError::Rejected)?;
        Ok(())
    }
}

impl CredentialServiceDesktopPort for WireService {
    fn challenge(
        &self,
        request: CredentialServiceDesktopRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        Box::pin(async move {
            self.require_unlocked()?;
            if !matches!(
                request.with_bytes(CredentialServiceProtocolCodec::decode_desktop_request),
                Ok(CredentialServiceIngressRequest::RegistrationChallenge)
            ) {
                return Err(CredentialServicePortError::Rejected);
            }
            let reply = CredentialServiceProtocolCodec::encode_reply(
                CredentialServiceRequest::RegistrationChallenge.context(),
                CredentialServiceReply::RegistrationChallenge {
                    epoch: CredentialServiceEpoch::from_bytes([21; 16]).unwrap(),
                    nonce: [22; 16],
                },
            )
            .map_err(|_| CredentialServicePortError::Rejected)?;
            CredentialServiceDesktopReply::from_zeroizing(reply.into_transport_bytes())
        })
    }

    fn register(
        &self,
        request: CredentialServiceDesktopRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        Box::pin(async move {
            self.require_unlocked()?;
            let now = unix_millis().map_err(|_| CredentialServicePortError::Rejected)?;
            let registration = request.with_bytes(|bytes| {
                runne_api::CredentialServiceSessionAuthenticator::accept_registration_install_with_policy(bytes, now, |binding| {
                    let enrollment = self.owned.enrollment_binding();
                    if binding.protected_session_id() != self.owned.session_id()
                        || binding.daemon_authority_generation() != self.owned.launch_generation()
                        || binding.runtime_generation() != self.owned.launch_generation()
                        || binding.supervisor_generation() != enrollment.desktop_supervisor_generation()
                        || binding.installation_owner() != enrollment.installation_identity_digest()
                        || binding.release_binding() != enrollment.release_tuple_digest()
                        || binding.installed_generation() != 1 || binding.join_attempt() != 2
                        || binding.service_epoch() != &[21; 16] || binding.challenge_nonce() != &[22; 16]
                        || binding.expires_at_unix_millis() != self.parent_expiry
                    { return Err(runne_api::CredentialServiceRegistrationError::BindingMismatch); }
                    Ok(())
                })
            }).map_err(|_| CredentialServicePortError::Rejected)?;
            let (_, ack) = registration
                .complete(now)
                .map_err(|_| CredentialServicePortError::Rejected)?;
            let mut bytes = ack.into_bytes();
            if self.tamper {
                *bytes.last_mut().unwrap() ^= 1;
            }
            CredentialServiceDesktopReply::from_zeroizing(zeroize::Zeroizing::new(bytes))
        })
    }
}

pub(in crate::protected_runtime) struct WireRegistration(WireService);
impl RejoinRegistration for WireRegistration {
    async fn register(
        &self,
        prepared: PreparedCredentialServiceRejoin,
    ) -> Result<RegisteredCredentialServiceSession, ProtectedBundledRuntimeError> {
        prepared.register_with_port(&self.0).await
    }
}

/// Runs the production discovery reader with a protocol-only service port.
/// No XPC endpoint, native effect, or production qualification is involved.
///
/// # Errors
/// Rejects invalid transcript, service acknowledgement, or retained launch state.
pub async fn test_only_crossed_discovery(
    fixture: TestOnlyReadyV3EnrollmentSupervisor,
    channel: std::os::unix::net::UnixStream,
    tamper_ack: bool,
) -> Result<Vec<[u8; 16]>, ProtectedBundledRuntimeError> {
    let (supervisor, registration) = prepare(fixture, channel, tamper_ack)?;
    let result = discover(Arc::clone(&supervisor), registration).await;
    reap(&supervisor);
    result
}

/// Runs the production renewal reader with a protocol-only registration port.
/// Returns the queued session and sequence; never connects XPC or Keychain.
///
/// # Errors
/// Rejects invalid registration or renewal evidence.
pub async fn test_only_crossed_renewal(
    fixture: TestOnlyReadyV3EnrollmentSupervisor,
    channel: std::os::unix::net::UnixStream,
    tamper_ack: bool,
) -> Result<([u8; 16], u64), ProtectedBundledRuntimeError> {
    let (supervisor, registration) = prepare(fixture, channel, tamper_ack)?;
    let result = crate::protected_runtime::renewal_interleaved::queue_with_registration(
        Arc::clone(&supervisor),
        || Ok(100),
        registration,
    )
    .await;
    reap(&supervisor);
    result?;
    let guard = supervisor
        .lock()
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    if guard.state != crate::protected_runtime::BundledRuntimeLifecycleState::Handshaking
        || guard.pending_profile.is_none()
    {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    }
    let process = guard
        .process
        .as_ref()
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    let crate::protected_runtime::ProtectedProcessActivation::V3 { owned, .. } =
        &process.activation
    else {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    };
    let observed = (*owned.session_id(), process.renewal_sequence);
    drop(guard);
    Ok(observed)
}

/// Runs the real round reader against the protocol-only service port.
///
/// # Errors
/// Rejects invalid registration or broker offer; no XPC or Keychain is used.
pub async fn test_only_crossed_round(
    fixture: TestOnlyReadyV3EnrollmentSupervisor,
    channel: std::os::unix::net::UnixStream,
    tamper_ack: bool,
) -> Result<([u8; 32], [u8; 32]), ProtectedBundledRuntimeError> {
    let (supervisor, registration) = prepare(fixture, channel, tamper_ack)?;
    {
        let mut guard = supervisor
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        // Fixture represents a renewed session after the previous terminal round.
        guard
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?
            .enrollment_broker_facts
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?
            .terminal_session = Some([77; 16]);
    }
    let result =
        crate::protected_runtime::credential_round::begin(Arc::clone(&supervisor), registration)
            .await;
    reap(&supervisor);
    result?;
    let guard = supervisor
        .lock()
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    let facts = guard
        .process
        .as_ref()
        .and_then(|p| p.enrollment_broker_facts)
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    let cleared = guard.credential_service_rejoin.is_none();
    drop(guard);
    if facts.terminal_session.is_some() || !cleared {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    }
    Ok((facts.binding(), facts.publication_public_key()))
}

pub(in crate::protected_runtime) fn prepare(
    fixture: TestOnlyReadyV3EnrollmentSupervisor,
    channel: std::os::unix::net::UnixStream,
    tamper_ack: bool,
) -> Result<
    (
        Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
        WireRegistration,
    ),
    ProtectedBundledRuntimeError,
> {
    let parent_expiry = fixture.credential_service_parent_expiry();
    let mut supervisor = fixture.into_supervisor();
    let process = supervisor
        .process
        .as_mut()
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    let crate::protected_runtime::ProtectedProcessActivation::V3 { owned, .. } =
        &process.activation
    else {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    };
    let owned = owned.clone();
    let mut facts = EnrollmentBrokerFacts::new([31; 32], [32; 32]);
    facts.terminal_session = Some(*owned.session_id());
    process.enrollment_broker_facts = Some(facts);
    process.channel = channel;
    supervisor.credential_service_rejoin = Some(test_rejoin_context(parent_expiry));
    let supervisor = Arc::new(Mutex::new(supervisor));
    let registration = WireRegistration(WireService {
        supervisor: Arc::downgrade(&supervisor),
        owned,
        tamper: tamper_ack,
        parent_expiry,
    });
    Ok((supervisor, registration))
}

pub(in crate::protected_runtime) fn reap(
    supervisor: &Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
) {
    if let Ok(mut supervisor) = supervisor.lock()
        && let Some(process) = supervisor.process.as_mut()
    {
        let _ = process.child.kill();
        let _ = process.child.wait();
    }
}
